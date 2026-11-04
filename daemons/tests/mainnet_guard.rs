//! BR-601: on a public Rand chain a guardian's multi-provider quorum (BR-4), peer check (BR-502)
//! and caps (BRG-1) are required, not opt-in. `Config::mainnet_guardian_gaps` lists what a config
//! lacks; `rand-guardian` refuses to start on a non-empty list (tests/daemons.rs). Provider URLs
//! that carry API keys come from the environment through `${NAME}` placeholders.

use std::collections::{BTreeMap, BTreeSet};

use bridge_daemons::config::{is_public_rand_chain, Config, FIRST_PUBLIC_RAND_CHAIN_ID};

const CONTRACT: &str = "0x1111111111111111111111111111111111111111";

/// A guardian config on chain 21 with every BR-601 control in place.
fn hardened() -> String {
    format!(
        r#"
data_dir = "./data"
[rand]
rpc = "http://127.0.0.1:8545"
rpcs = ["http://127.0.0.1:8645"]
rpc_quorum = 2
chain_id = 21
emitter = "{emitter}"

[[evm]]
name = "ethereum"
chain = 2
kind = "evm"
rpc = "https://one.example"
rpcs = ["https://two.example", "https://three.example"]
rpc_quorum = 2
contract = "{CONTRACT}"
finality = "finalized"

[solana]
rpc = "https://sol-one.example"
rpcs = ["https://sol-two.example"]
program = "FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu"

[guardian]
listen = "127.0.0.1:7071"
peers = ["http://127.0.0.1:7172"]

[guardian.limits]
per_transfer = 10000000000
per_window = 100000000000
"#,
        emitter = "aa".repeat(32)
    )
}

fn load_with(text: &str, env: &[(&str, &str)]) -> anyhow::Result<Config> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.toml");
    std::fs::write(&path, text).unwrap();
    let env: BTreeMap<String, String> = env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    Config::load_with(&path, |name| env.get(name).cloned())
}

fn gaps(text: &str) -> Vec<String> {
    load_with(text, &[]).unwrap().mainnet_guardian_gaps()
}

fn has(gaps: &[String], needle: &str) -> bool {
    gaps.iter().any(|g| g.contains(needle))
}

#[test]
fn public_chains_are_14_and_up_and_an_unnamed_chain_counts_as_public() {
    // BRG-901: chains 14-19 bind the chain id, 20 onward the genesis; both are public. Ids below
    // 14 are devnets and retired testnets. A config that names no chain is not exempt: nothing
    // then ties it to a test chain (the node's id is compared only when one is configured).
    assert_eq!(FIRST_PUBLIC_RAND_CHAIN_ID, 14);
    for id in [14, 19, 20, 21, 22, 1_000] {
        assert!(is_public_rand_chain(Some(id)), "{id}");
    }
    for id in [0, 5, 7, 13] {
        assert!(!is_public_rand_chain(Some(id)), "{id}");
    }
    assert!(is_public_rand_chain(None));
}

#[test]
fn a_hardened_config_has_no_gaps() {
    assert_eq!(gaps(&hardened()), Vec::<String>::new());
}

#[test]
fn one_provider_on_any_watched_chain_is_a_gap() {
    let text = hardened().replace("rpcs = [\"https://two.example\", \"https://three.example\"]\nrpc_quorum = 2\n", "");
    let g = gaps(&text);
    assert!(has(&g, "evm.ethereum") && has(&g, "BR-4"), "{g:?}");
    assert_eq!(g.len(), 1, "{g:?}");

    let text = hardened().replace("rpcs = [\"http://127.0.0.1:8645\"]\nrpc_quorum = 2\n", "");
    let g = gaps(&text);
    assert!(has(&g, "rand:"), "{g:?}");

    let text = hardened().replace("rpcs = [\"https://sol-two.example\"]\n", "");
    let g = gaps(&text);
    assert!(has(&g, "solana:"), "{g:?}");

    // A repeated provider is one provider.
    let text = hardened().replace("[\"https://sol-two.example\"]", "[\"https://SOL-ONE.example/\"]");
    assert!(has(&gaps(&text), "solana:"));
}

#[test]
fn a_quorum_of_one_over_several_providers_is_a_gap() {
    let text = hardened().replace(
        "rpcs = [\"https://two.example\", \"https://three.example\"]\nrpc_quorum = 2",
        "rpcs = [\"https://two.example\", \"https://three.example\"]\nrpc_quorum = 1",
    );
    let g = gaps(&text);
    assert!(has(&g, "evm.ethereum") && has(&g, "rpc_quorum 1"), "{g:?}");
}

#[test]
fn no_peers_is_a_gap() {
    let g = gaps(&hardened().replace("peers = [\"http://127.0.0.1:7172\"]\n", ""));
    assert!(has(&g, "guardian.peers") && has(&g, "BR-502"), "{g:?}");
    assert_eq!(g.len(), 1, "{g:?}");
}

#[test]
fn no_limits_is_a_gap() {
    let text = hardened();
    let cut = text.find("[guardian.limits]").unwrap();
    let g = gaps(&text[..cut]);
    assert!(has(&g, "[guardian.limits]") && has(&g, "BRG-1"), "{g:?}");
    assert_eq!(g.len(), 1, "{g:?}");
}

#[test]
fn no_guardian_section_is_a_gap() {
    let text = hardened();
    let cut = text.find("[guardian]").unwrap();
    assert!(has(&gaps(&text[..cut]), "[guardian]"));
}

#[test]
fn placeholders_are_filled_from_the_environment() {
    let text = hardened().replace("https://three.example", "https://three.example/v2/${TEST_KEY}");
    let config = load_with(&text, &[("TEST_KEY", "s3cret")]).unwrap();
    assert!(config.evm[0].rpcs.contains(&"https://three.example/v2/s3cret".to_string()));
    assert!(config.unresolved.is_empty());
    assert_eq!(config.mainnet_guardian_gaps(), Vec::<String>::new());

    // Unset (or empty), the placeholder stays as written and is a gap naming the variable, never
    // its value; the file still loads, so --pause-signing works without the provider secrets.
    for env in [&[][..], &[("TEST_KEY", "")][..]] {
        let config = load_with(&text, env).unwrap();
        assert_eq!(config.unresolved_vars(), BTreeSet::from(["TEST_KEY".to_string()]));
        let g = config.mainnet_guardian_gaps();
        assert!(has(&g, "TEST_KEY") && has(&g, "evm.ethereum.rpcs"), "{g:?}");
    }

    // An unresolved provider does not count toward the quorum.
    let text = hardened().replace("\"http://127.0.0.1:8645\"", "\"${RAND_TWO}\"");
    let g = load_with(&text, &[]).unwrap().mainnet_guardian_gaps();
    assert!(has(&g, "RAND_TWO") && has(&g, "rand: 1 provider"), "{g:?}");

    // Peers take placeholders too.
    let text = hardened().replace("\"http://127.0.0.1:7172\"", "\"${PEER}\"");
    let g = load_with(&text, &[]).unwrap().mainnet_guardian_gaps();
    assert!(has(&g, "PEER") && has(&g, "guardian.peers"), "{g:?}");
    let config = load_with(&text, &[("PEER", "http://10.0.0.2:7071")]).unwrap();
    assert_eq!(config.guardian.unwrap().peers, vec!["http://10.0.0.2:7071".to_string()]);

    // A malformed placeholder is a load error.
    for bad in ["https://x.example/${KEY", "https://x.example/${}", "https://x.example/${9X}", "https://x.example/${A-B}"] {
        let err = load_with(&hardened().replace("https://three.example", bad), &[]).unwrap_err();
        assert!(format!("{err:#}").contains("placeholder"), "{bad}: {err:#}");
    }
}

/// The variables the repository's mainnet guardian configs leave to each host's environment.
const MAINNET_VARS: [&str; 5] = [
    "GUARDIAN_RPC_BSC",
    "GUARDIAN_RPC_ETHEREUM",
    "GUARDIAN_RPC_RAND",
    "GUARDIAN_RPC_SOLANA",
    "GUARDIAN_RPC_TRON",
];

fn mainnet_guardian(i: usize, env: &BTreeMap<String, String>) -> Config {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("mainnet/guardian-{i}.toml"));
    Config::load_with(&path, |name| env.get(name).cloned()).unwrap_or_else(|e| panic!("guardian-{i}: {e:#}"))
}

#[test]
fn every_mainnet_guardian_config_passes_the_guard_once_its_environment_is_set() {
    let env: BTreeMap<String, String> = MAINNET_VARS
        .iter()
        .map(|v| (v.to_string(), format!("https://{}.provider.example/key", v.to_lowercase())))
        .collect();
    for i in 1..=8 {
        let config = mainnet_guardian(i, &env);
        assert!(is_public_rand_chain(config.rand.chain_id), "guardian-{i}");
        assert_eq!(config.mainnet_guardian_gaps(), Vec::<String>::new(), "guardian-{i}");
        // Every watched chain at a quorum of 2 over at least 2 providers, and the peers are the
        // other guardians, never this one.
        let guardian = config.guardian.as_ref().unwrap();
        assert!(!guardian.peers.is_empty(), "guardian-{i}");
        let own = format!("http://127.0.0.1:717{i}");
        assert!(!guardian.peers.contains(&own), "guardian-{i} lists itself");
        assert!(
            !guardian.peers.iter().any(|p| p.ends_with(&guardian.listen)),
            "guardian-{i} lists its own listen address"
        );
    }
}

#[test]
fn without_their_environment_the_mainnet_configs_name_exactly_the_missing_variables() {
    let empty = BTreeMap::new();
    let expected: BTreeSet<String> = MAINNET_VARS.iter().map(|v| v.to_string()).collect();
    for i in 1..=8 {
        let config = mainnet_guardian(i, &empty);
        assert_eq!(config.unresolved_vars(), expected, "guardian-{i}");
        let g = config.mainnet_guardian_gaps();
        for v in MAINNET_VARS {
            assert!(has(&g, v), "guardian-{i}: {v} not reported in {g:?}");
        }
    }
}
