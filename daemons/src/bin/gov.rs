//! `rand-bridge-gov`: guardian-set rotation, as a deliberate command-line act.
//!
//!   rotate       build the rotation, sign it with keys of the CURRENT set
//!                (from environment variables), re-verify it, write the hex
//!   verify       check any rotation attestation against the current set
//!   submit-evm   send it to an Ethereum-style endpoint (anyone may)
//!   submit-tron  send it to the Tron endpoint
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
