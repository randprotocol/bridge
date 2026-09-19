//! The rotation tool against the shared vectors and the real contract.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use bridge_codec::{Attestation, Payload};
use bridge_daemons::config::{EvmConfig, EvmKind, Finality};
use bridge_daemons::crypto::GuardianKey;
use bridge_daemons::governance::{rotation_body, sign_rotation, verify_rotation};
use bridge_daemons::submit::evm::EvmSubmitter;
use bridge_daemons::submit::Outcome;
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/attestations.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn vector(v: &Value, name: &str) -> Vec<u8> {
    unhex(
        &v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("{name}"))["attestation"],
    )
}

fn keys(v: &Value) -> Vec<GuardianKey> {
    v["guardians"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| GuardianKey::from_hex(g["secret"].as_str().unwrap()).unwrap())
        .collect()
}

/// Build the rotation the vector describes with this tool, sign it with the
/// fixture's first five guardians: the bytes must be the vector's.
#[test]
fn reproduces_the_shared_rotation_vector_byte_for_byte() {
    let v = vectors();
    let expected = vector(&v, "upgrade_set1_ok");
    let decoded = Attestation::decode(&expected).unwrap();
    let Payload::GuardianSetUpgrade(upgrade) = Payload::decode(&decoded.body.payload).unwrap()
    else {
        panic!()
    };

    let guardians = keys(&v);
    let current: Vec<[u8; 20]> = guardians.iter().map(|k| k.address()).collect();
    let body = rotation_body(
        0,
        &upgrade.keys,
        decoded.body.timestamp,
        decoded.body.nonce,
        decoded.body.sequence,
    )
    .unwrap();
    assert_eq!(body, decoded.body);

    let signer_count = decoded.signatures.len();
    let attestation = sign_rotation(&body, 0, &current, &guardians[..signer_count]).unwrap();
    assert_eq!(hex::encode(attestation.encode()), hex::encode(&expected));

    // Six signers still yield exactly a quorum, lowest indices first — and
    // the order the keys are handed over in does not matter.
    let mut shuffled: Vec<GuardianKey> = keys(&v);
    shuffled.reverse();
    let from_six = sign_rotation(&body, 0, &current, &shuffled).unwrap();
    assert_eq!(
        from_six
            .signatures
            .iter()
            .map(|s| s.index)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );

    let checked = verify_rotation(&expected, 0, &current).unwrap();
    assert_eq!((checked.new_index, checked.new_keys), (1, upgrade.keys));
}

#[test]
fn refuses_what_the_verifiers_refuse() {
    let v = vectors();
    let guardians = keys(&v);
    let current: Vec<[u8; 20]> = guardians.iter().map(|k| k.address()).collect();
    let new_keys: Vec<[u8; 20]> = (1..=6u8).map(|i| [i; 20]).collect();
    let body = rotation_body(0, &new_keys, 1_800_000_000, 0, 1).unwrap();

    // Short of a quorum; a stranger's key; a repeated signer.
    assert!(sign_rotation(&body, 0, &current, &guardians[..4]).is_err());
    let stranger = GuardianKey::from_hex(&"11".repeat(32)).unwrap();
    assert!(sign_rotation(&body, 0, &current, &[stranger]).is_err());
    let twice: Vec<GuardianKey> = [0usize, 0, 1, 2, 3, 4]
        .iter()
        .map(|&i| keys(&v).remove(i))
        .collect();
    assert!(sign_rotation(&body, 0, &current, &twice).is_err());

    // Bad new sets.
    assert!(rotation_body(0, &[], 0, 0, 1).is_err());
    assert!(rotation_body(0, &[[0u8; 20]], 0, 0, 1).is_err());
    assert!(rotation_body(0, &[[7u8; 20], [7u8; 20]], 0, 0, 1).is_err());

    // A good rotation presented against the wrong current index or set.
    let good = sign_rotation(&body, 0, &current, &guardians)
        .unwrap()
        .encode();
    assert!(verify_rotation(&good, 1, &current).is_err());
    let mut other = current.clone();
    other.swap(0, 1);
    assert!(verify_rotation(&good, 0, &other).is_err());

    // The vectors' own negatives for rotations are refused here too.
    let name = "upgrade_signed_by_superseded_set";
    assert!(verify_rotation(&vector(&v, name), 1, &current).is_err(), "{name}");
    // A transfer is not a rotation.
    assert!(verify_rotation(&vector(&v, "transfer_eth_usdt_6dp_ok"), 0, &current).is_err());
}

// ---- the real contract, on anvil ---------------------------------------------

const DEPLOYER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const DEPLOYER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const SUBMITTER_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

struct Anvil(Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "{:?} failed: {}",
        cmd,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn rotates_the_real_ethereum_endpoint_on_anvil() {
    if !(have("anvil") && have("forge") && have("cast")) {
        eprintln!("skipped: Foundry is not installed");
        return;
    }
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let rpc = format!("http://127.0.0.1:{port}");
    let _anvil = Anvil(
        Command::new("anvil")
            .args(["--port", &port.to_string(), "--silent"])
            .spawn()
            .expect("anvil"),
    );
    for _ in 0..50 {
        if Command::new("cast")
            .args(["chain-id", "--rpc-url", &rpc])
            .stderr(Stdio::null())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let old: Vec<GuardianKey> = (1..=6u8)
        .map(|i| GuardianKey::from_hex(&format!("{:064x}", i)).unwrap())
        .collect();
    let new: Vec<GuardianKey> = (101..=106u8)
        .map(|i| GuardianKey::from_hex(&format!("{:064x}", i)).unwrap())
        .collect();
    let list = |ks: &[GuardianKey]| {
        format!(
            "[{}]",
            ks.iter()
                .map(|k| format!("0x{}", hex::encode(k.address())))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let evm_root = concat!(env!("CARGO_MANIFEST_DIR"), "/../evm");
    let out = run(Command::new("forge").args([
        "create",
        "--root",
        evm_root,
        "--rpc-url",
        &rpc,
        "--private-key",
        DEPLOYER_KEY,
        "--broadcast",
        "src/EthereumRandBridge.sol:EthereumRandBridge",
        "--constructor-args",
        DEPLOYER,
        DEPLOYER,
        &format!("0x{}", "aa".repeat(32)),
        &list(&old),
    ]));
    let bridge = out
        .lines()
        .find_map(|l| l.strip_prefix("Deployed to: "))
        .unwrap()
        .trim()
        .to_string();

    let current: Vec<[u8; 20]> = old.iter().map(|k| k.address()).collect();
    let new_keys: Vec<[u8; 20]> = new.iter().map(|k| k.address()).collect();
    let body = rotation_body(0, &new_keys, 1_800_000_000, 0, 1).unwrap();
    // Guardians 1..=5 sign; guardian 0 sits this one out.
    let attestation = sign_rotation(&body, 0, &current, &old[1..])
        .unwrap()
        .encode();
    let checked = verify_rotation(&attestation, 0, &current).unwrap();
    assert_eq!(checked.signer_indices, vec![1, 2, 3, 4, 5]);

    let cfg = EvmConfig {
        name: "anvil".into(),
        chain: 2,
        kind: EvmKind::Evm,
        rpc: rpc.clone(),
        contract: bridge.clone(),
        finality: Finality::Tag("latest".into()),
        start_block: 0,
        max_log_range: 1,
    };
    let submitter = EvmSubmitter::new(&cfg, SUBMITTER_KEY).unwrap();
    let outcome = submitter
        .guardian_set_upgrade(&attestation, &checked.digest)
        .await
        .unwrap();
    assert!(matches!(outcome, Outcome::Submitted(_)), "{outcome:?}");

    let index = run(Command::new("cast").args([
        "call",
        "--rpc-url",
        &rpc,
        &bridge,
        "currentGuardianSetIndex()(uint32)",
    ]));
    assert_eq!(index.trim(), "1");
    let set1 = run(Command::new("cast").args([
        "call",
        "--rpc-url",
        &rpc,
        &bridge,
        "guardianSet(uint32)((address[],uint256))",
        "1",
    ]))
    .to_lowercase();
    for key in &new_keys {
        assert!(
            set1.contains(&hex::encode(key)),
            "set 1 holds every new key"
        );
    }
    // The old set now carries an expiry (the 86,400 s grace for transfers).
    let set0 = run(Command::new("cast").args([
        "call",
        "--rpc-url",
        &rpc,
        &bridge,
        "guardianSet(uint32)((address[],uint256))",
        "0",
    ]));
    assert!(
        !set0.trim_end().ends_with(", 0)"),
        "set 0 has an expiration: {set0}"
    );

    // Submitting it again is a no-op: the digest is consumed.
    assert_eq!(
        submitter
            .guardian_set_upgrade(&attestation, &checked.digest)
            .await
            .unwrap(),
        Outcome::AlreadyDone
    );
}
