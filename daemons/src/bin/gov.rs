//! `rand-bridge-gov`: guardian-set rotation, as a deliberate command-line act.
//!
//!   rotate       build the rotation, sign it with keys of the CURRENT set
//!                (from environment variables), re-verify it, write the hex
//!   verify       check any rotation attestation against the current set
//!   submit-evm   send it to an Ethereum-style endpoint (anyone may)
//!   submit-tron  send it to the Tron endpoint
//!   pause, pq-unpause, pq-list, pq-register
//!                the Rand-only governance messages (spec/PQ-COSIGNATURE.md §8);
//!                on a chain cut with binding_domain (20 onward) they bind the
//!                genesis hash: --genesis <hex> or --rand-rpc <url> (BRG-901)
//!   pq-rotate-pq, pq-rotate-pause, pq-cancel-rotation, pq-rotate-submit
//!                rotate the post-quantum guardian set or the pause key on Rand
//!                (BRG-14): build the genesis-bound message, sign it (a PQ
//!                quorum of the current set, and each new key's proof of
//!                possession), check it, submit it (docs/pq-rotation.md)
//!
//! The same attestation goes to every chain: the three EVM-family endpoints,
//! Solana (`rand-bridge-cli guardian-set-upgrade`) and Rand (a `BridgeAttest`
//! carrying payload 2), so all five stay on one set index. A superseded set
//! keeps verifying TRANSFERS for 86,400 s; leave a day between a rotation
//! away from exposed keys and any custody.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use bridge_daemons::config::{address20, EvmConfig, EvmKind, Finality};
use bridge_daemons::crypto::GuardianKey;
use bridge_daemons::governance::{rotation_body, sign_rotation, verify_rotation};
use bridge_daemons::submit::evm::EvmSubmitter;
use bridge_daemons::submit::tron::TronSubmitter;
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct CurrentSet {
    /// The CURRENT guardian set's index (0 for the launch set).
    #[arg(long)]
    current_index: u32,
    /// The CURRENT set's addresses, comma-separated, in index order.
    #[arg(long, value_delimiter = ',')]
    current_guardians: Vec<String>,
}

/// Which form a Rand governance message takes (BRG-901, `pq_gov`): a chain cut
/// without `binding_domain` (14-19) signs the chain-id layouts; every later
/// chain binds its genesis hash under the `…-2` tags, so the hash is needed —
/// given, or read from a node that is first checked to serve the chain.
#[derive(Args)]
struct BindingArgs {
    /// The chain's 32-byte genesis hash, hex (chain 20 onward; refused for chains 14-19).
    #[arg(long)]
    genesis: Option<String>,
    /// A Rand node to read the genesis hash from (`rand_getGenesisHash`), after checking
    /// that it serves --rand-chain-id. With --genesis too, the two must agree.
    #[arg(long)]
    rand_rpc: Option<String>,
}

impl BindingArgs {
    async fn resolve(&self, rand_chain_id: u64) -> Result<bridge_daemons::pq_gov::BindingDomain> {
        use bridge_daemons::sources::rand;
        let given = self
            .genesis
            .as_deref()
            .map(bridge_daemons::config::hex32)
            .transpose()
            .context("--genesis")?;
        let mut read = None;
        if let Some(url) = &self.rand_rpc {
            let rpc = bridge_daemons::rpc::JsonRpc::new(url);
            let served = rand::chain_id(&rpc)
                .await
                .context("the node at --rand-rpc did not answer rand_chainId")?;
            if served != rand_chain_id {
                bail!("--rand-chain-id is {rand_chain_id} but the node at --rand-rpc serves chain {served}");
            }
            // A chain-id chain needs no hash; do not read one it would then refuse.
            if !bridge_daemons::pq_gov::CHAIN_ID_BINDING_CHAIN_IDS.contains(&rand_chain_id) {
                let g = rand::genesis_hash(&rpc).await?;
                if let Some(given) = given {
                    if given != g {
                        bail!(
                            "--genesis {} is not the genesis hash the node at --rand-rpc serves ({})",
                            hex::encode(given),
                            hex::encode(g)
                        );
                    }
                }
                read = Some(g);
            }
        }
        bridge_daemons::pq_gov::binding_domain_for(rand_chain_id, given.or(read))
    }
}

#[derive(Args)]
struct PqQuorumArgs {
    #[arg(long)]
    rand_chain_id: u64,
    #[command(flatten)]
    binding: BindingArgs,
    /// The ledger's current nonce for this message kind (`list_nonce` or `pause_nonce`).
    #[arg(long)]
    nonce: u64,
    /// `{"pq_guardians": ["<hex>", …]}` — the chain's PQ guardian set.
    #[arg(long)]
    pq_guardians_file: PathBuf,
    /// Environment variables holding 32-byte PQ seeds (a quorum or more), comma-separated.
    #[arg(long, value_delimiter = ',')]
    seed_envs: Vec<String>,
    /// Where to write `[{"index", "signature"}]`.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct BackingArgs {
    /// Bridge chain id of the coin: 2 Ethereum, 3 BSC, 4 Tron, 5 Solana.
    #[arg(long)]
    chain: u16,
    /// The coin's 32-byte wire form, hex (docs/architecture.md §10.1).
    #[arg(long)]
    token: String,
    /// The coin's decimals on its own chain.
    #[arg(long)]
    decimals: u8,
}

impl BackingArgs {
    fn backing(&self) -> Result<bridge_daemons::pq_gov::Backing> {
        if !(2..=5).contains(&self.chain) {
            bail!("--chain must be 2, 3, 4 or 5");
        }
        Ok(bridge_daemons::pq_gov::Backing {
            chain: self.chain,
            token: bridge_daemons::config::hex32(&self.token)?,
            decimals: self.decimals,
        })
    }
}

fn pq_guardians(path: &PathBuf) -> Result<Vec<Vec<u8>>> {
    let file: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    file["pq_guardians"]
        .as_array()
        .ok_or_else(|| anyhow!("no pq_guardians array"))?
        .iter()
        .map(|k| hex::decode(k.as_str().unwrap_or_default()).context("pq_guardians entry"))
        .collect()
}

/// Signs `message` with the quorum the arguments name and writes pq.json.
fn sign_governance(
    what: &str,
    binding: &bridge_daemons::pq_gov::BindingDomain,
    message: &[u8],
    args: &PqQuorumArgs,
) -> Result<()> {
    let guardians = pq_guardians(&args.pq_guardians_file)?;
    let signers = args
        .seed_envs
        .iter()
        .map(|v| bridge_daemons::pq::PqKey::from_seed_hex(&take_env(v)?))
        .collect::<Result<Vec<_>>>()?;
    let quorum = bridge_daemons::pq_gov::sign_quorum(message, &guardians, &signers)?;
    std::fs::write(&args.out, serde_json::to_vec(&quorum)?)
        .with_context(|| format!("writing {}", args.out.display()))?;
    println!("{what}");
    println!("binding    {}", binding.describe());
    println!(
        "message    0x{}  ({} bytes)",
        hex::encode(message),
        message.len()
    );
    println!(
        "signed by  PQ guardians {:?} -> {}",
        quorum.iter().map(|s| s.index).collect::<Vec<_>>(),
        args.out.display()
    );
    Ok(())
}

/// What a PQ rotation is signed over and by whom (BRG-14).
#[derive(Args)]
struct RotateArgs {
    #[arg(long)]
    rand_chain_id: u64,
    #[command(flatten)]
    binding: BindingArgs,
    /// The bridge's current `rotation_nonce` (rand_getBridgeState). With --rand-rpc it is
    /// checked against the node, and so is --pq-guardians-file.
    #[arg(long)]
    nonce: u64,
    /// `{"pq_guardians": ["<hex>", …]}` — the CURRENT PQ guardian set.
    #[arg(long)]
    pq_guardians_file: PathBuf,
    /// Environment variables holding 32-byte seeds of CURRENT PQ guardians, comma-separated:
    /// each signs the quorum. Any number, a quorum across every run.
    #[arg(long, value_delimiter = ',')]
    seed_envs: Vec<String>,
    /// Environment variables holding seeds of NEW keys, comma-separated: each signs its proof of
    /// possession (bridge.rotation.needs_possession).
    #[arg(long, value_delimiter = ',')]
    possession_seed_envs: Vec<String>,
    /// Where to append the quorum's `index:signature` lines.
    #[arg(long)]
    out: PathBuf,
    /// Where to append the possession `index:signature` lines.
    #[arg(long)]
    possession_out: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    Rotate {
        #[command(flatten)]
        current: CurrentSet,
        /// The NEW set's addresses, comma-separated, in the order they will be indexed.
        #[arg(long, value_delimiter = ',')]
        new_guardians: Vec<String>,
        /// Environment variables holding keys of the CURRENT set (a quorum or more), comma-separated.
        #[arg(long, value_delimiter = ',')]
        signer_envs: Vec<String>,
        /// Body timestamp (unix seconds). Advisory, but part of the digest: fix it to reproduce the bytes.
        #[arg(long)]
        timestamp: Option<u32>,
        #[arg(long, default_value_t = 0)]
        nonce: u32,
        /// Governance sequence. Advisory; use the new set index by convention.
        #[arg(long)]
        sequence: Option<u64>,
        /// Where to write the attestation as hex.
        #[arg(long)]
        out: PathBuf,
    },
    Verify {
        #[command(flatten)]
        current: CurrentSet,
        /// A file holding the attestation as hex.
        #[arg(long)]
        attestation_file: PathBuf,
    },
    /// Dilithium2 co-signatures over an attestation, for its submission to Rand
    /// (`spec/PQ-COSIGNATURE.md`): a rotation needs them like any other BridgeAttest.
    /// Writes `[{"index", "signature"}]`, what `rand bridge-mint --pq @file` reads.
    Cosign {
        #[arg(long)]
        attestation_file: PathBuf,
        /// The Rand chain id the co-signatures name.
        #[arg(long)]
        rand_chain_id: u64,
        /// The chain's `pq_guardians` as a JSON file: `{"pq_guardians": ["<hex>", …]}`.
        #[arg(long)]
        pq_guardians_file: PathBuf,
        /// Environment variables holding 32-byte PQ seeds (a quorum or more), comma-separated.
        #[arg(long, value_delimiter = ',')]
        seed_envs: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Rand-only: a PQ guardian quorum over `ListBacking` (spec/PQ-COSIGNATURE.md §8).
    PqList {
        #[command(flatten)]
        quorum: PqQuorumArgs,
        /// The bridged token's registry index on Rand.
        #[arg(long)]
        token_index: u32,
        #[command(flatten)]
        backing: BackingArgs,
    },
    /// Rand-only: a PQ guardian quorum over `RegisterBridgedToken` (a new token + its first backing).
    PqRegister {
        #[command(flatten)]
        quorum: PqQuorumArgs,
        #[arg(long)]
        name: String,
        #[arg(long)]
        symbol: String,
        /// 32-byte salt, hex.
        #[arg(long)]
        salt: String,
        #[command(flatten)]
        backing: BackingArgs,
    },
    /// Rand-only: a PQ guardian quorum to UNPAUSE minting.
    PqUnpause {
        #[command(flatten)]
        quorum: PqQuorumArgs,
    },
    /// Rand-only: the single pause key's signature to PAUSE minting. It cannot unpause.
    Pause {
        #[arg(long)]
        rand_chain_id: u64,
        #[command(flatten)]
        binding: BindingArgs,
        /// The ledger's current `pause_nonce` (rand_getBridgeState).
        #[arg(long)]
        nonce: u64,
        #[arg(long, default_value = "RAND_BRIDGE_PAUSE_KEY_SEED")]
        seed_env: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Rand-only (BRG-14): sign the rotation of the whole PQ guardian set.
    PqRotatePq {
        #[command(flatten)]
        rotate: RotateArgs,
        /// `{"pq_guardians": ["<hex>", …]}` — the NEW set, in index order.
        #[arg(long)]
        new_pq_guardians_file: PathBuf,
    },
    /// Rand-only (BRG-14): sign the rotation of the pause key.
    PqRotatePause {
        #[command(flatten)]
        rotate: RotateArgs,
        /// The new pause key: Dilithium2 public key hex, or `@file` holding it.
        #[arg(long)]
        new_pause_key: String,
    },
    /// Rand-only (BRG-14): the current pause key's signature dropping a pending rotation.
    PqCancelRotation {
        #[arg(long)]
        rand_chain_id: u64,
        #[command(flatten)]
        binding: BindingArgs,
        /// The bridge's current `rotation_nonce`.
        #[arg(long)]
        nonce: u64,
        #[arg(long, value_parser = ["pq", "pause"])]
        kind: String,
        #[arg(long, default_value = "RAND_BRIDGE_PAUSE_KEY_SEED")]
        seed_env: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Rand-only (BRG-14): check the collected lines against what the node serves, then submit
    /// the rotation through `rand-node bridge-gov rotate-pq|rotate-pause submit`.
    PqRotateSubmit {
        #[arg(long, value_parser = ["pq", "pause"])]
        kind: String,
        /// For --kind pq: the NEW set, `{"pq_guardians": [...]}`.
        #[arg(long)]
        new_pq_guardians_file: Option<PathBuf>,
        /// For --kind pause: the new pause key, hex or `@file`.
        #[arg(long)]
        new_pause_key: Option<String>,
        /// The quorum lines (`index:signature`), as pq-rotate-* wrote them.
        #[arg(long)]
        quorum: PathBuf,
        /// The possession lines, on a chain that requires them.
        #[arg(long)]
        possession: Option<PathBuf>,
        /// The Rand node to read the chain from and submit to.
        #[arg(long)]
        rand_rpc: String,
        /// The fullnode's `rand-node` binary, which encodes and sends the action.
        #[arg(long, default_value = "rand-node")]
        rand_node: PathBuf,
        /// Check everything and print the command, but do not run it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print the Dilithium2 public key a seed derives (and its sha256 prefix), never the seed.
    PqPublicKey {
        #[arg(long)]
        seed_env: String,
    },
    SubmitEvm {
        #[arg(long)]
        rpc: String,
        /// The endpoint contract, 0x + 40 hex.
        #[arg(long)]
        contract: String,
        #[arg(long)]
        attestation_file: PathBuf,
        /// Environment variable with the key that pays gas (any funded key).
        #[arg(long, default_value = "RELAYER_EVM_KEY")]
        key_env: String,
    },
    SubmitTron {
        /// The API origin, e.g. https://api.trongrid.io
        #[arg(long)]
        api: String,
        /// The endpoint contract in EVM form, 0x + 40 hex.
        #[arg(long)]
        contract: String,
        #[arg(long)]
        attestation_file: PathBuf,
        #[arg(long, default_value = "RELAYER_TRON_KEY")]
        key_env: String,
        #[arg(long, default_value_t = 300_000_000)]
        fee_limit: u64,
    },
}

/// A Dilithium2 public key from hex or `@file`.
fn pq_key_arg(arg: &str) -> Result<Vec<u8>> {
    let text = match arg.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?,
        None => arg.to_string(),
    };
    let key = hex::decode(text.trim().trim_start_matches("0x")).context("the key is not hex")?;
    if key.len() != bridge_daemons::pq::PUBLIC_KEY_LEN {
        bail!("a Dilithium2 public key is {} bytes, got {}", bridge_daemons::pq::PUBLIC_KEY_LEN, key.len());
    }
    Ok(key)
}

/// What a rotation reads from the node: `rand_getBridgeState` as served.
struct RotationView {
    chain_id: u64,
    binding: bridge_daemons::pq_gov::BindingDomain,
    nonce: u64,
    guardians: usize,
    pq_guardians: Vec<Vec<u8>>,
    pause_key: Option<Vec<u8>>,
    needs_possession: bool,
}

async fn rotation_view(url: &str) -> Result<RotationView> {
    use bridge_daemons::sources::rand;
    let rpc = bridge_daemons::rpc::JsonRpc::new(url);
    let chain_id = rand::chain_id(&rpc).await.context("rand_chainId")?;
    let genesis = if bridge_daemons::pq_gov::CHAIN_ID_BINDING_CHAIN_IDS.contains(&chain_id) {
        None
    } else {
        Some(rand::genesis_hash(&rpc).await?)
    };
    let binding = bridge_daemons::pq_gov::binding_domain_for(chain_id, genesis)?;
    let state = rpc.call("rand_getBridgeState", serde_json::json!([])).await?;
    if state["enabled"].as_bool() != Some(true) {
        bail!("the node serves no bridge");
    }
    if state["rules_v2"].is_null() {
        bail!("this chain has no bridge rules v2: it has no rotations");
    }
    let hexes = |v: &serde_json::Value| -> Result<Vec<Vec<u8>>> {
        v.as_array()
            .ok_or_else(|| anyhow!("not an array"))?
            .iter()
            .map(|k| hex::decode(k.as_str().unwrap_or_default()).context("not hex"))
            .collect()
    };
    Ok(RotationView {
        chain_id,
        binding,
        nonce: state["rotation_nonce"]
            .as_u64()
            .ok_or_else(|| anyhow!("the node serves no rotation_nonce"))?,
        guardians: state["guardians"].as_array().map_or(0, |g| g.len()),
        pq_guardians: hexes(&state["pq_guardians"]).context("pq_guardians")?,
        pause_key: match state["pause_key"].as_str() {
            Some(k) => Some(hex::decode(k).context("pause_key")?),
            None => None,
        },
        needs_possession: state["rotation_rules"]["needs_possession"].as_bool() == Some(true),
    })
}

/// Appends `lines` to `path`, one per line.
fn append_lines(path: &PathBuf, lines: &[String]) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    for l in lines {
        writeln!(f, "{l}")?;
    }
    f.sync_all()?;
    Ok(())
}

/// Signs a rotation message: the current-set seeds for the quorum, the new
/// keys' seeds for possession; every line is checked before it is written.
async fn sign_rotation_message(what: &str, args: &RotateArgs, new_keys: &[Vec<u8>], pause: bool) -> Result<()> {
    use bridge_daemons::pq_gov;
    let current = pq_guardians(&args.pq_guardians_file)?;
    if let Some(url) = &args.binding.rand_rpc {
        let v = rotation_view(url).await?;
        if v.nonce != args.nonce {
            bail!("--nonce is {} but the node's rotation_nonce is {}", args.nonce, v.nonce);
        }
        if v.pq_guardians != current {
            bail!("--pq-guardians-file is not the PQ guardian set the node serves");
        }
    }
    let binding = args.binding.resolve(args.rand_chain_id).await?;
    let message = if pause {
        pq_gov::rotate_pause_message_in(&binding, args.rand_chain_id, args.nonce, &new_keys[0])?
    } else {
        pq_gov::rotate_pq_message_in(&binding, args.rand_chain_id, args.nonce, new_keys)?
    };
    if args.seed_envs.is_empty() && args.possession_seed_envs.is_empty() {
        bail!("--seed-envs and --possession-seed-envs name no key");
    }
    let mut quorum = Vec::new();
    for var in &args.seed_envs {
        let key = bridge_daemons::pq::PqKey::from_seed_hex(&take_env(var)?)?;
        let index = current
            .iter()
            .position(|k| *k == key.public_key())
            .ok_or_else(|| anyhow!("{var} is not the seed of a key in the current PQ guardian set"))?;
        quorum.push(pq_gov::signature_line(index as u8, &key.sign_raw(&message)));
    }
    let mut possession = Vec::new();
    for var in &args.possession_seed_envs {
        let key = bridge_daemons::pq::PqKey::from_seed_hex(&take_env(var)?)?;
        let index = new_keys
            .iter()
            .position(|k| *k == key.public_key())
            .ok_or_else(|| anyhow!("{var} is not the seed of a new key"))?;
        possession.push(pq_gov::signature_line(index as u8, &key.sign_raw(&message)));
    }
    if !quorum.is_empty() {
        append_lines(&args.out, &quorum)?;
    }
    if !possession.is_empty() {
        let out = args
            .possession_out
            .as_ref()
            .ok_or_else(|| anyhow!("--possession-seed-envs needs --possession-out"))?;
        append_lines(out, &possession)?;
    }
    let collected = if args.out.exists() {
        pq_gov::parse_signature_lines(&std::fs::read_to_string(&args.out)?)?.len()
    } else {
        0
    };
    println!("{what}");
    println!("binding    {}", binding.describe());
    println!("rotation_nonce {}", args.nonce);
    println!("message    0x{}  ({} bytes)", hex::encode(&message), message.len());
    println!(
        "quorum     {} line(s) in {} — the current set of {} needs {}",
        collected,
        args.out.display(),
        current.len(),
        bridge_daemons::pq::quorum(current.len())
    );
    if !possession.is_empty() {
        println!("possession {} line(s) appended", possession.len());
    }
    Ok(())
}

fn addresses(list: &[String]) -> Result<Vec<[u8; 20]>> {
    list.iter()
        .map(|a| address20(a.trim()).with_context(|| format!("address {a}")))
        .collect()
}

fn take_env(name: &str) -> Result<String> {
    let value = std::env::var(name).map_err(|_| anyhow!("{name} is not set"))?;
    std::env::remove_var(name);
    Ok(value)
}

fn read_attestation(path: &PathBuf) -> Result<Vec<u8>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    hex::decode(text.trim().trim_start_matches("0x")).context("attestation is not hex")
}

fn endpoint(name: &str, kind: EvmKind, rpc: &str, contract: &str) -> EvmConfig {
    EvmConfig {
        name: name.into(),
        chain: 2, // unused by a submitter
        kind,
        rpc: rpc.into(),
        contract: contract.into(),
        finality: Finality::Tag("latest".into()),
        start_block: 0,
        max_log_range: 1,
        rpcs: Vec::new(),
        rpc_quorum: None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    match Cli::parse().command {
        Command::Rotate {
            current,
            new_guardians,
            signer_envs,
            timestamp,
            nonce,
            sequence,
            out,
        } => {
            let current_set = addresses(&current.current_guardians)?;
            let new_keys = addresses(&new_guardians)?;
            if signer_envs.is_empty() {
                bail!("--signer-envs names no key");
            }
            let signers = signer_envs
                .iter()
                .map(|v| GuardianKey::from_hex(&take_env(v)?))
                .collect::<Result<Vec<_>>>()?;
            let timestamp = match timestamp {
                Some(t) => t,
                None => std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs() as u32,
            };
            let body = rotation_body(
                current.current_index,
                &new_keys,
                timestamp,
                nonce,
                sequence.unwrap_or(u64::from(current.current_index) + 1),
            )?;
            let attestation =
                sign_rotation(&body, current.current_index, &current_set, &signers)?.encode();
            let checked = verify_rotation(&attestation, current.current_index, &current_set)?;
            std::fs::write(&out, hex::encode(&attestation))
                .with_context(|| format!("writing {}", out.display()))?;

            println!(
                "rotation   set {} -> set {}",
                current.current_index, checked.new_index
            );
            println!(
                "signed by  guardians {:?} of the current set",
                checked.signer_indices
            );
            for (i, key) in checked.new_keys.iter().enumerate() {
                println!("new [{i}]    0x{}", hex::encode(key));
            }
            println!("digest     0x{}", hex::encode(checked.digest));
            println!(
                "timestamp  {timestamp} (pass --timestamp {timestamp} to reproduce these bytes)"
            );
            println!("bytes      {} -> {}", attestation.len(), out.display());
            println!();
            println!("Submit the SAME file to every chain:");
            println!("  rand-bridge-gov submit-evm  --rpc <ETH RPC> --contract <endpoint> --attestation-file {}", out.display());
            println!("  rand-bridge-gov submit-evm  --rpc <BSC RPC> --contract <endpoint> --attestation-file {}", out.display());
            println!("  rand-bridge-gov submit-tron --api https://api.trongrid.io --contract <endpoint, EVM form> --attestation-file {}", out.display());
            println!(
                "  rand-bridge-cli guardian-set-upgrade --program <PROGRAM> --attestation-file {}",
                out.display()
            );
            println!(
                "  Rand (after the bridged chain is cut): a BridgeAttest carrying this attestation"
            );
        }
        Command::Verify {
            current,
            attestation_file,
        } => {
            let checked = verify_rotation(
                &read_attestation(&attestation_file)?,
                current.current_index,
                &addresses(&current.current_guardians)?,
            )?;
            println!(
                "valid: set {} -> set {}, signed by {:?}, digest 0x{}",
                current.current_index,
                checked.new_index,
                checked.signer_indices,
                hex::encode(checked.digest)
            );
            for (i, key) in checked.new_keys.iter().enumerate() {
                println!("new [{i}]  0x{}", hex::encode(key));
            }
        }
        Command::Cosign {
            attestation_file,
            rand_chain_id,
            pq_guardians_file,
            seed_envs,
            out,
        } => {
            use bridge_daemons::pq;
            let attestation = read_attestation(&attestation_file)?;
            let mu = bridge_daemons::crypto::digest(
                bridge_codec::Attestation::body_bytes(&attestation)
                    .map_err(|e| anyhow!("{e:?}"))?,
            );
            let file: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&pq_guardians_file)?)?;
            let pq_guardians: Vec<Vec<u8>> = file["pq_guardians"]
                .as_array()
                .ok_or_else(|| anyhow!("no pq_guardians array"))?
                .iter()
                .map(|k| hex::decode(k.as_str().unwrap_or_default()).context("pq_guardians entry"))
                .collect::<Result<_>>()?;
            let mut found = Vec::new();
            for var in &seed_envs {
                let key = pq::PqKey::from_seed_hex(&take_env(var)?)?;
                let index = pq_guardians
                    .iter()
                    .position(|k| *k == key.public_key())
                    .ok_or_else(|| anyhow!("{var} is not the seed of any key in pq_guardians"))?;
                found.push((index as u8, key.sign(rand_chain_id, &mu)));
            }
            let quorum =
                pq::assemble(&found, &pq_guardians, rand_chain_id, &mu).ok_or_else(|| {
                    anyhow!(
                        "{} co-signers, but {} keys need {}",
                        found.len(),
                        pq_guardians.len(),
                        pq::quorum(pq_guardians.len())
                    )
                })?;
            pq::check(&quorum, &pq_guardians, rand_chain_id, &mu)
                .map_err(|e| anyhow!("self-check failed: {e:?}"))?;
            std::fs::write(&out, serde_json::to_vec(&quorum)?)?;
            println!(
                "co-signed mu 0x{} for Rand chain {rand_chain_id} by PQ guardians {:?} -> {}",
                hex::encode(mu),
                quorum.iter().map(|s| s.index).collect::<Vec<_>>(),
                out.display()
            );
        }
        Command::PqList {
            quorum,
            token_index,
            backing,
        } => {
            let b = backing.backing()?;
            let binding = quorum.binding.resolve(quorum.rand_chain_id).await?;
            let m = bridge_daemons::pq_gov::list_message_in(
                &binding,
                quorum.rand_chain_id,
                quorum.nonce,
                token_index,
                &b,
            );
            sign_governance(&format!("ListBacking: token {token_index} += chain {} coin 0x{} ({} decimals), list_nonce {}", b.chain, hex::encode(b.token), b.decimals, quorum.nonce), &binding, &m, &quorum)?;
        }
        Command::PqRegister {
            quorum,
            name,
            symbol,
            salt,
            backing,
        } => {
            let b = backing.backing()?;
            let binding = quorum.binding.resolve(quorum.rand_chain_id).await?;
            let m = bridge_daemons::pq_gov::register_message_in(
                &binding,
                quorum.rand_chain_id,
                quorum.nonce,
                &name,
                &symbol,
                &bridge_daemons::config::hex32(&salt)?,
                &b,
            )?;
            sign_governance(&format!("RegisterBridgedToken: {name} ({symbol}), first backing chain {} coin 0x{} ({} decimals), list_nonce {}", b.chain, hex::encode(b.token), b.decimals, quorum.nonce), &binding, &m, &quorum)?;
        }
        Command::PqUnpause { quorum } => {
            let binding = quorum.binding.resolve(quorum.rand_chain_id).await?;
            let m = bridge_daemons::pq_gov::unpause_message_in(
                &binding,
                quorum.rand_chain_id,
                quorum.nonce,
            );
            sign_governance(
                &format!(
                    "UNPAUSE minting on Rand chain {}, pause_nonce {}",
                    quorum.rand_chain_id, quorum.nonce
                ),
                &binding,
                &m,
                &quorum,
            )?;
        }
        Command::Pause {
            rand_chain_id,
            binding,
            nonce,
            seed_env,
            out,
        } => {
            let key = bridge_daemons::pq::PqKey::from_seed_hex(&take_env(&seed_env)?)?;
            let binding = binding.resolve(rand_chain_id).await?;
            let m = bridge_daemons::pq_gov::pause_message_in(&binding, rand_chain_id, nonce);
            std::fs::write(&out, hex::encode(key.sign_raw(&m)))
                .with_context(|| format!("writing {}", out.display()))?;
            println!("PAUSE minting on Rand chain {rand_chain_id}, pause_nonce {nonce}");
            println!("binding    {}", binding.describe());
            println!("message    0x{}", hex::encode(&m));
            println!("signature  -> {}", out.display());
        }
        Command::PqRotatePq {
            rotate,
            new_pq_guardians_file,
        } => {
            let new = pq_guardians(&new_pq_guardians_file)?;
            sign_rotation_message(
                &format!("ROTATE the PQ guardian set on Rand chain {} to {} keys", rotate.rand_chain_id, new.len()),
                &rotate,
                &new,
                false,
            )
            .await?;
        }
        Command::PqRotatePause {
            rotate,
            new_pause_key,
        } => {
            let new = vec![pq_key_arg(&new_pause_key)?];
            sign_rotation_message(
                &format!("ROTATE the pause key on Rand chain {}", rotate.rand_chain_id),
                &rotate,
                &new,
                true,
            )
            .await?;
        }
        Command::PqCancelRotation {
            rand_chain_id,
            binding,
            nonce,
            kind,
            seed_env,
            out,
        } => {
            use bridge_daemons::pq_gov::{cancel_rotation_message_in, signature_line, RotationKind};
            let key = bridge_daemons::pq::PqKey::from_seed_hex(&take_env(&seed_env)?)?;
            let kind = if kind == "pause" { RotationKind::PauseKey } else { RotationKind::PqGuardians };
            let binding = binding.resolve(rand_chain_id).await?;
            let m = cancel_rotation_message_in(&binding, rand_chain_id, nonce, kind);
            std::fs::write(&out, signature_line(0, &key.sign_raw(&m)) + "\n")
                .with_context(|| format!("writing {}", out.display()))?;
            println!("CANCEL the pending {kind:?} rotation on Rand chain {rand_chain_id}, rotation_nonce {nonce}");
            println!("binding    {}", binding.describe());
            println!("message    0x{}", hex::encode(&m));
            println!("signature  -> {}", out.display());
        }
        Command::PqRotateSubmit {
            kind,
            new_pq_guardians_file,
            new_pause_key,
            quorum,
            possession,
            rand_rpc,
            rand_node,
            dry_run,
        } => {
            use bridge_daemons::pq_gov;
            let v = rotation_view(&rand_rpc).await?;
            let pause = kind == "pause";
            let new = if pause {
                vec![pq_key_arg(new_pause_key.as_deref().ok_or_else(|| anyhow!("--kind pause needs --new-pause-key"))?)?]
            } else {
                pq_guardians(new_pq_guardians_file.as_ref().ok_or_else(|| anyhow!("--kind pq needs --new-pq-guardians-file"))?)?
            };
            // The ledger's shape rules, before anything is sent.
            if pause {
                if v.pq_guardians.contains(&new[0]) {
                    bail!("the new pause key is a PQ guardian's key");
                }
            } else {
                if new.len() != v.guardians {
                    bail!("the new PQ set has {} keys, the guardian set {}", new.len(), v.guardians);
                }
                if v.pause_key.as_ref().is_some_and(|p| new.contains(p)) {
                    bail!("the new PQ set contains the pause key");
                }
            }
            let message = if pause {
                pq_gov::rotate_pause_message_in(&v.binding, v.chain_id, v.nonce, &new[0])?
            } else {
                pq_gov::rotate_pq_message_in(&v.binding, v.chain_id, v.nonce, &new)?
            };
            let lines = pq_gov::parse_signature_lines(&std::fs::read_to_string(&quorum).with_context(|| format!("reading {}", quorum.display()))?)?;
            // Exactly a quorum, lowest indices first, as the ledger counts it.
            let need = bridge_daemons::pq::quorum(v.pq_guardians.len());
            // Lines that verify under the key at their index, then the lowest `need` of them:
            // a bad line does not push a good one out.
            let lines: Vec<_> = lines
                .into_iter()
                .filter(|(i, sig)| {
                    v.pq_guardians
                        .get(usize::from(*i))
                        .is_some_and(|k| bridge_daemons::pq::verify_raw(k, &message, sig))
                })
                .take(need)
                .collect();
            pq_gov::check_quorum_lines(&lines, &v.pq_guardians, &message)
                .context("the quorum lines do not hold for this chain's current set, rotation_nonce and binding")?;
            match (&possession, v.needs_possession) {
                (Some(p), true) => {
                    let lines = pq_gov::parse_signature_lines(&std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?)?;
                    pq_gov::check_possession_lines(&lines, &new, &message)?;
                }
                (None, true) => bail!("this chain requires a proof of possession: pass --possession"),
                (Some(_), false) => bail!("this chain does not take a proof of possession: drop --possession"),
                (None, false) => {}
            }
            // The quorum file handed on holds exactly the lines checked.
            let checked = quorum.with_extension("checked");
            std::fs::write(&checked, lines.iter().map(|(i, s)| pq_gov::signature_line(*i, s) + "\n").collect::<String>())?;
            let mut cmd = std::process::Command::new(&rand_node);
            cmd.args(["bridge-gov", if pause { "rotate-pause" } else { "rotate-pq" }, "submit"]);
            for k in &new {
                cmd.args(["--new-key", &hex::encode(k)]);
            }
            cmd.arg("--quorum").arg(format!("@{}", checked.display()));
            if let Some(p) = &possession {
                cmd.arg("--possession").arg(format!("@{}", p.display()));
            }
            cmd.args(["--rpc", &rand_rpc]);
            println!(
                "checked    {} rotation on Rand chain {}, rotation_nonce {}, {} quorum line(s){}",
                if pause { "pause-key" } else { "PQ guardian" },
                v.chain_id,
                v.nonce,
                lines.len(),
                if possession.is_some() { ", possession" } else { "" }
            );
            println!("binding    {}", v.binding.describe());
            if dry_run {
                println!("would run  {} bridge-gov {} submit --new-key … --quorum @{} --rpc {}", rand_node.display(), if pause { "rotate-pause" } else { "rotate-pq" }, checked.display(), rand_rpc);
                return Ok(());
            }
            let status = cmd.status().with_context(|| format!("running {}", rand_node.display()))?;
            if !status.success() {
                bail!("{} exited with {status}", rand_node.display());
            }
        }
        Command::PqPublicKey { seed_env } => {
            use sha2::{Digest, Sha256};
            let key = bridge_daemons::pq::PqKey::from_seed_hex(&take_env(&seed_env)?)?;
            let public = key.public_key();
            println!("{}", hex::encode(&public));
            eprintln!(
                "sha256 prefix {}",
                &hex::encode(Sha256::digest(&public))[..8]
            );
        }
        Command::SubmitEvm {
            rpc,
            contract,
            attestation_file,
            key_env,
        } => {
            let attestation = read_attestation(&attestation_file)?;
            let digest = bridge_daemons::crypto::digest(
                bridge_codec::Attestation::body_bytes(&attestation)
                    .map_err(|e| anyhow!("{e:?}"))?,
            );
            let submitter = EvmSubmitter::new(
                &endpoint("evm", EvmKind::Evm, &rpc, &contract),
                &take_env(&key_env)?,
            )?;
            println!(
                "{:?}",
                submitter
                    .guardian_set_upgrade(&attestation, &digest)
                    .await?
            );
        }
        Command::SubmitTron {
            api,
            contract,
            attestation_file,
            key_env,
            fee_limit,
        } => {
            let attestation = read_attestation(&attestation_file)?;
            let digest = bridge_daemons::crypto::digest(
                bridge_codec::Attestation::body_bytes(&attestation)
                    .map_err(|e| anyhow!("{e:?}"))?,
            );
            let submitter = TronSubmitter::new(
                &endpoint("tron", EvmKind::Tron, &api, &contract),
                &take_env(&key_env)?,
                fee_limit,
            )?;
            println!(
                "{:?}",
                submitter
                    .guardian_set_upgrade(&attestation, &digest)
                    .await?
            );
        }
    }
    Ok(())
}
