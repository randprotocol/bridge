//! One TOML file configures either daemon; each reads the sections it needs.
//! Secrets are never in the file: a section names the *environment variable*
//! that holds its key.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

use crate::message::Emitters;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Cursors, signatures and relayer progress live here.
    pub data_dir: PathBuf,
    /// Seconds between polls of every source.
    #[serde(default = "default_poll_secs")]
    pub poll_secs: u64,
    pub rand: RandConfig,
    /// Ethereum, BSC and Tron endpoints (Tron through its `/jsonrpc` API).
    #[serde(default)]
    pub evm: Vec<EvmConfig>,
    pub solana: Option<SolanaConfig>,
    pub guardian: Option<GuardianConfig>,
    pub relayer: Option<RelayerConfig>,
    /// The policy `rand-bridge-audit --governance` holds the endpoints to
    /// (BR-3). Optional: absent, the defaults below apply.
    pub governance: Option<GovernanceConfig>,
}

fn default_poll_secs() -> u64 {
    10
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RandConfig {
    pub rpc: String,
    /// The 32-byte Rand burn emitter (genesis `bridge.emitter`), hex.
    pub emitter: String,
    /// First burn sequence to look at on a fresh data dir.
    #[serde(default)]
    pub start_sequence: u64,
    /// The Rand chain's `chain_id`. Required by a guardian that co-signs
    /// (`spec/PQ-COSIGNATURE.md`): it is part of what the co-signature is
    /// over, and the guardian must know it without trusting an RPC node.
    pub chain_id: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvmKind {
    /// Ethereum, BSC, anvil: standard JSON-RPC, EIP-1559 transactions.
    Evm,
    /// Tron: logs over `<api>/jsonrpc`, transactions over `<api>/wallet/*`.
    Tron,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmConfig {
    /// A label for logs and cursor files, e.g. `sepolia`.
    pub name: String,
    /// Bridge chain id: 2 Ethereum, 3 BSC, 4 Tron.
    pub chain: u16,
    pub kind: EvmKind,
    /// JSON-RPC URL (for Tron: the API origin, e.g. `https://nile.trongrid.io`).
    pub rpc: String,
    /// The endpoint contract, `0x` + 40 hex (Tron: the EVM form of the address).
    pub contract: String,
    /// `"finalized"`, `"safe"`, or a number of confirmations behind `latest`.
    pub finality: Finality,
    /// First block to scan on a fresh data dir: the deployment block.
    #[serde(default)]
    pub start_block: u64,
    /// Widest `eth_getLogs` range to ask for.
    #[serde(default = "default_log_range")]
    pub max_log_range: u64,
}

fn default_log_range() -> u64 {
    2_000
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum Finality {
    Tag(String),
    Confirmations(u64),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolanaConfig {
    #[serde(default = "default_solana_name")]
    pub name: String,
    pub rpc: String,
    /// The bridge program id, base58.
    pub program: String,
    #[serde(default)]
    pub start_sequence: u64,
}

fn default_solana_name() -> String {
    "solana".into()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianConfig {
    /// Where the signature API listens, e.g. `127.0.0.1:7071`.
    pub listen: String,
    /// Environment variable holding this guardian's secp256k1 key.
    #[serde(default = "default_guardian_key_env")]
    pub key_env: String,
    /// Environment variable holding this guardian's 32-byte Dilithium2 seed.
    /// When it is set the guardian co-signs every message addressed to Rand.
    #[serde(default = "default_guardian_pq_env")]
    pub pq_seed_env: String,
}

fn default_guardian_pq_env() -> String {
    "GUARDIAN_PQ_SEED".into()
}

fn default_guardian_key_env() -> String {
    "GUARDIAN_KEY".into()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayerConfig {
    /// Every guardian's API origin.
    pub guardians: Vec<String>,
    /// The guardian set to assemble under, used when the Rand node does not
    /// serve `rand_getBridgeState` (a rehearsal without a Rand chain).
    #[serde(default)]
    pub guardian_set_index: u32,
    #[serde(default)]
    pub guardian_addresses: Vec<String>,
    /// Environment variable with the EVM-family submitter key (one key for
    /// every EVM chain; Tron may name its own).
    #[serde(default = "default_evm_key_env")]
    pub evm_key_env: String,
    #[serde(default = "default_tron_key_env")]
    pub tron_key_env: String,
    /// Tron `fee_limit` for a release, in sun.
    #[serde(default = "default_tron_fee_limit")]
    pub tron_fee_limit: u64,
    /// Smallest relayer fee (attested, 8-decimal units) worth a release. 0
    /// relays everything.
    #[serde(default)]
    pub min_relayer_fee: u64,
    /// `rand-bridge-cli` binary for Solana releases; its signer comes from
    /// `SOL_KEYPAIR` / `SOL_PRIVATE_KEY` in the relayer's own environment.
    pub solana_cli: Option<PathBuf>,
    /// `rand` wallet binary for mints on Rand, and the wallet it pays from.
    pub rand_cli: Option<PathBuf>,
    #[serde(default)]
    pub rand_cli_args: Vec<String>,
    /// `recipient_hash (64 hex) -> rand1… address`, one JSON object. A lock
    /// names only the hash; sealing the deposit note needs the address, so
    /// whoever wants a deposit relayed registers it here (or through the
    /// relayer's `POST /v1/recipients`).
    pub recipients_file: Option<PathBuf>,
    /// Where the recipient registration API listens; unset disables it.
    pub listen: Option<String>,
}

fn default_evm_key_env() -> String {
    "RELAYER_EVM_KEY".into()
}

fn default_tron_key_env() -> String {
    "RELAYER_TRON_KEY".into()
}

fn default_tron_fee_limit() -> u64 {
    150_000_000
}

/// What `rand-bridge-audit --governance` requires of every endpoint's admin.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GovernanceConfig {
    /// Least timelock delay the admin must impose, in seconds (48 h).
    #[serde(default = "default_min_delay_secs")]
    pub min_delay_secs: u64,
    /// Least number of signers a multisig must require.
    #[serde(default = "default_min_threshold")]
    pub min_threshold: u32,
    /// The Squads v4 multisig whose vault must be the Solana admin and
    /// upgrade authority, base58. Unset, the Solana rules fail.
    pub solana_multisig: Option<String>,
    /// Which of that multisig's vaults.
    #[serde(default)]
    pub solana_vault_index: u8,
    /// Per bridge chain (2, 3, 4): the block the admin timelock was deployed
    /// at, where the audit starts reading its `RoleGranted` / `RoleRevoked`
    /// logs. A chain without one fails the role rules.
    #[serde(default)]
    pub timelock_deploy_block: BTreeMap<String, u64>,
    /// Per bridge chain (2, 3, 4): the admin multisig, the only account that
    /// may hold the timelock's proposer, executor and canceller roles
    /// (`0x…`; Tron also `T…`).
    #[serde(default)]
    pub admin_multisig: BTreeMap<String, String>,
}

/// The floors under any `[governance]` policy: the deploy script refuses a
/// delay under 24 h, and a "multisig" of one is a key.
pub const MIN_DELAY_FLOOR_SECS: u64 = 86_400;
pub const MIN_THRESHOLD_FLOOR: u32 = 2;

impl GovernanceConfig {
    pub fn deploy_block(&self, chain: u16) -> Option<u64> {
        self.timelock_deploy_block.get(&chain.to_string()).copied()
    }

    /// The configured admin multisig of `chain`, as 20 bytes.
    pub fn admin_multisig20(&self, chain: u16) -> Result<Option<[u8; 20]>> {
        self.admin_multisig
            .get(&chain.to_string())
            .map(|a| evm_or_tron_address(chain, a))
            .transpose()
    }

    fn validate(&self) -> Result<()> {
        if self.min_delay_secs < MIN_DELAY_FLOOR_SECS {
            bail!(
                "governance.min_delay_secs must be at least {MIN_DELAY_FLOOR_SECS} (24 h), got {}",
                self.min_delay_secs
            );
        }
        if self.min_threshold < MIN_THRESHOLD_FLOOR {
            bail!(
                "governance.min_threshold must be at least {MIN_THRESHOLD_FLOOR}, got {}",
                self.min_threshold
            );
        }
        if let Some(ms) = &self.solana_multisig {
            pubkey32(ms).context("governance.solana_multisig")?;
        }
        let chain = |key: &str, table: &str| -> Result<u16> {
            match key.parse::<u16>() {
                Ok(c @ 2..=4) => Ok(c),
                _ => {
                    bail!("governance.{table}: key {key:?} is not an EVM bridge chain (2, 3 or 4)")
                }
            }
        };
        for key in self.timelock_deploy_block.keys() {
            chain(key, "timelock_deploy_block")?;
        }
        for (key, address) in &self.admin_multisig {
            let c = chain(key, "admin_multisig")?;
            evm_or_tron_address(c, address)
                .with_context(|| format!("governance.admin_multisig.{key}"))?;
        }
        Ok(())
    }
}

/// `0x` + 40 hex on any EVM chain; on Tron (4) also the `T…` base58check form.
fn evm_or_tron_address(chain: u16, s: &str) -> Result<[u8; 20]> {
    if s.starts_with("0x") {
        return address20(s);
    }
    if chain == 4 {
        return tron_address20(s);
    }
    bail!("expected 0x + 40 hex, got {s:?}")
}

/// A `T…` Tron address: base58check of `0x41 ‖ 20 bytes`.
pub fn tron_address20(s: &str) -> Result<[u8; 20]> {
    use sha2::{Digest, Sha256};
    let raw = bs58::decode(s)
        .into_vec()
        .map_err(|_| anyhow!("not base58"))?;
    if raw.len() != 25 || raw[0] != 0x41 {
        bail!("not a Tron address");
    }
    let check = Sha256::digest(Sha256::digest(&raw[..21]));
    if check[..4] != raw[21..] {
        bail!("Tron address checksum mismatch");
    }
    Ok(raw[1..21].try_into().expect("20"))
}

fn default_min_delay_secs() -> u64 {
    172_800
}

fn default_min_threshold() -> u32 {
    2
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        GovernanceConfig {
            min_delay_secs: default_min_delay_secs(),
            min_threshold: default_min_threshold(),
            solana_multisig: None,
            solana_vault_index: 0,
            timelock_deploy_block: BTreeMap::new(),
            admin_multisig: BTreeMap::new(),
        }
    }
}

impl Config {
    /// The `[governance]` section, or its defaults when there is none.
    pub fn governance_policy(&self) -> GovernanceConfig {
        self.governance.clone().unwrap_or_default()
    }

    pub fn load(path: &Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        hex32(&self.rand.emitter).context("rand.emitter")?;
        let mut chains = Vec::new();
        for e in &self.evm {
            if !matches!(e.chain, 2..=4) {
                bail!(
                    "evm.{}: chain must be 2 (Ethereum), 3 (BSC) or 4 (Tron)",
                    e.name
                );
            }
            if chains.contains(&e.chain) {
                bail!("evm.{}: chain {} configured twice", e.name, e.chain);
            }
            chains.push(e.chain);
            address20(&e.contract).with_context(|| format!("evm.{}.contract", e.name))?;
            if let Finality::Tag(t) = &e.finality {
                if t != "finalized" && t != "safe" && t != "latest" {
                    bail!("evm.{}: finality must be \"finalized\", \"safe\", \"latest\" or a confirmation count", e.name);
                }
            }
        }
        if let Some(s) = &self.solana {
            pubkey32(&s.program).context("solana.program")?;
        }
        if let Some(g) = &self.governance {
            g.validate()?;
        }
        Ok(())
    }

    /// The emitter table the signing policy checks against.
    pub fn emitters(&self) -> Result<Emitters> {
        let mut endpoints = Vec::new();
        for e in &self.evm {
            let mut word = [0u8; 32];
            word[12..].copy_from_slice(&address20(&e.contract)?);
            endpoints.push((e.chain, word));
        }
        if let Some(s) = &self.solana {
            endpoints.push((bridge_codec::CHAIN_SOLANA, pubkey32(&s.program)?));
        }
        Ok(Emitters {
            rand: hex32(&self.rand.emitter)?,
            endpoints,
        })
    }
}

pub fn hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim_start_matches("0x")).map_err(|_| anyhow!("not hex"))?;
    bytes.try_into().map_err(|_| anyhow!("expected 32 bytes"))
}

pub fn address20(s: &str) -> Result<[u8; 20]> {
    let bytes = hex::decode(s.trim_start_matches("0x")).map_err(|_| anyhow!("not hex"))?;
    bytes.try_into().map_err(|_| anyhow!("expected 20 bytes"))
}

pub fn pubkey32(s: &str) -> Result<[u8; 32]> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|_| anyhow!("not base58"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected a 32-byte pubkey"))
}
