//! `rand-bridge-audit`: the custody reconciliation.
//!
//! For each approved backing (`docs/architecture.md` §10.1) it reads, from the
//! endpoint that holds it, the custody counter, the accrued protocol fees and
//! the token balance the endpoint really has, and — once the Rand node serves
//! per-backing `locked` — what Rand says is outstanding. Two invariants:
//!
//!   balance  >= custody + accrued fees     (the endpoint is solvent)
//!   custody  == locked on Rand             (every zUSD unit is backed, per coin)
//!
//! The second holds exactly only when no message is in flight; a lock that
//! is attested but not yet minted (or a burn not yet released) shows up as a
//! difference, which is reported rather than hidden. Exits non-zero when an
//! endpoint is insolvent.
//!
//! `--governance` instead checks who controls each endpoint (BR-3): the admin
//! behind a timelock and a multisig, the pauser a separate multisig, the
//! Solana upgrade authority the admin's Squads vault. Read-only; exits
//! non-zero when any rule does not pass. The rules live in
//! `bridge_daemons::gov_audit`.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use bridge_daemons::config::{address20, pubkey32, Config, EvmConfig, EvmKind, GovernanceConfig};
use bridge_daemons::gov_audit::{self, EvmReads, Flavor, Rule, SolanaReads, Status};
use bridge_daemons::rpc::{hex_data, JsonRpc};
use bridge_daemons::sources::solana::find_program_address;
use bridge_daemons::submit::selector;
use clap::Parser;
use serde_json::json;

#[derive(Parser)]
struct Cli {
    /// Any daemon config: the [rand], [[evm]] and [solana] sections are used.
    #[arg(long, env = "RAND_BRIDGE_CONFIG")]
    config: PathBuf,
    /// The bridged token on Rand: a registry index, 64 hex, or `rpl1…`.
    #[arg(long, default_value = "1")]
    token: String,
    /// Check governance (BR-3) instead of custody: admin, pauser, timelock,
    /// multisig and upgrade authority on every endpoint.
    #[arg(long)]
    governance: bool,
}

/// The approved backings: (bridge chain, symbol, token, decimals).
const EVM_TOKENS: &[(u16, &str, &str, u32)] = &[
    (2, "USDT", "dac17f958d2ee523a2206206994597c13d831ec7", 6),
    (2, "USDC", "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6),
    (3, "USDT", "55d398326f99059ff775485246999027b3197955", 18),
    (3, "USDC", "8ac76a51cc950d9822d68b83fe1ad97b32cd580d", 18),
    (4, "USDT", "a614f803b6fd780986a42c78ec9c7f77e6ded13c", 6),
];
const SOLANA_TOKENS: &[(&str, &str, u32)] = &[
    ("USDT", "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", 6),
    ("USDC", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", 6),
];

struct Row {
    chain: u16,
    symbol: &'static str,
    token_word: [u8; 32],
    decimals: u32,
    enabled: bool,
    custody: u128,
    fees: u128,
    balance: u128,
}

fn word_u128(bytes: &[u8]) -> Result<u128> {
    if bytes.len() < 32 || bytes[..16].iter().any(|b| *b != 0) {
        return Err(anyhow!("value does not fit a u128"));
    }
    Ok(u128::from_be_bytes(bytes[16..32].try_into().expect("16")))
}

async fn eth_call(rpc: &JsonRpc, to: &[u8; 20], data: Vec<u8>) -> Result<Vec<u8>> {
    let result = rpc
        .call("eth_call", json!([{ "to": format!("0x{}", hex::encode(to)), "data": format!("0x{}", hex::encode(data)) }, "latest"]))
        .await?;
    hex_data(&result)
}

fn call_with_address(signature: &str, address: &[u8; 20]) -> Vec<u8> {
    let mut data = selector(signature).to_vec();
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(address);
    data
}

async fn evm_rows(config: &Config) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for endpoint in &config.evm {
        let url = match endpoint.kind {
            EvmKind::Evm => endpoint.rpc.clone(),
            EvmKind::Tron => format!("{}/jsonrpc", endpoint.rpc.trim_end_matches('/')),
        };
        let rpc = JsonRpc::new(&url);
        let bridge = address20(&endpoint.contract)?;
        for (chain, symbol, token, decimals) in EVM_TOKENS.iter().filter(|t| t.0 == endpoint.chain)
        {
            let token20 = address20(token)?;
            let custody = word_u128(
                &eth_call(
                    &rpc,
                    &bridge,
                    call_with_address("custody(address)", &token20),
                )
                .await?,
            )
            .with_context(|| format!("{} custody", endpoint.name))?;
            let fees = word_u128(
                &eth_call(
                    &rpc,
                    &bridge,
                    call_with_address("accruedFees(address)", &token20),
                )
                .await?,
            )?;
            let balance = word_u128(
                &eth_call(
                    &rpc,
                    &token20,
                    call_with_address("balanceOf(address)", &bridge),
                )
                .await?,
            )?;
            // tokenConfig(address) -> (enabled, decimals, ...): the first word.
            let cfg = eth_call(
                &rpc,
                &bridge,
                call_with_address("tokenConfig(address)", &token20),
            )
            .await
            .unwrap_or_default();
            let enabled = cfg.get(31) == Some(&1);
            let mut token_word = [0u8; 32];
            token_word[12..].copy_from_slice(&token20);
            rows.push(Row {
                chain: *chain,
                symbol,
                token_word,
                decimals: *decimals,
                enabled,
                custody,
                fees,
                balance,
            });
        }
    }
    Ok(rows)
}

async fn solana_account(rpc: &JsonRpc, key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    let result = rpc
        .call("getAccountInfo", json!([bs58::encode(key).into_string(), { "encoding": "base64", "commitment": "finalized" }]))
        .await?;
    match result["value"]["data"][0].as_str() {
        Some(data) => Ok(Some(
            base64::engine::general_purpose::STANDARD.decode(data)?,
        )),
        None => Ok(None),
    }
}

async fn solana_rows(config: &Config) -> Result<Vec<Row>> {
    let Some(sol) = &config.solana else {
        return Ok(Vec::new());
    };
    let rpc = JsonRpc::new(&sol.rpc);
    let program = pubkey32(&sol.program)?;
    let le64 = |d: &[u8], at: usize| -> Result<u128> {
        Ok(u128::from(u64::from_le_bytes(
            d.get(at..at + 8)
                .ok_or_else(|| anyhow!("account too short"))?
                .try_into()
                .expect("8"),
        )))
    };
    let mut rows = Vec::new();
    for (symbol, mint, decimals) in SOLANA_TOKENS {
        let mint32 = pubkey32(mint)?;
        let (registry_key, _) = find_program_address(&[b"token", &mint32], &program)?;
        let (custody_key, _) = find_program_address(&[b"custody", &mint32], &program)?;
        // TokenRegistry: tag, mint, enabled, decimals, 4 x u64, custody, accrued_fees.
        let (enabled, custody, fees) = match solana_account(&rpc, &registry_key).await? {
            Some(d) => (d.get(33) == Some(&1), le64(&d, 67)?, le64(&d, 75)?),
            None => (false, 0, 0),
        };
        // SPL token account: mint (32), owner (32), amount (u64 LE).
        let balance = match solana_account(&rpc, &custody_key).await? {
            Some(d) => le64(&d, 64)?,
            None => 0,
        };
        rows.push(Row {
            chain: 5,
            symbol,
            token_word: mint32,
            decimals: *decimals,
            enabled,
            custody,
            fees,
            balance,
        });
    }
    Ok(rows)
}

/// What Rand says is outstanding: `(chain, token word) -> locked` in attested
/// 8-decimal units, and the token's total supply.
struct RandSide {
    locked: Vec<(u16, [u8; 32], u128)>,
    total_supply: Option<u128>,
}

fn amount(v: &serde_json::Value) -> Option<u128> {
    match v {
        v if v.is_string() => v.as_str()?.parse().ok(),
        v => v.as_u64().map(u128::from),
    }
}

fn backing_rows(rows: &[serde_json::Value]) -> Option<Vec<(u16, [u8; 32], u128)>> {
    rows.iter()
        .map(|a| {
            let chain = a["chain"].as_u64()? as u16;
            let token: [u8; 32] = hex::decode(a["token"].as_str()?).ok()?.try_into().ok()?;
            Some((chain, token, amount(&a["locked"])?))
        })
        .collect()
}

/// `rand_getTokenSupply [token]` is the source of truth (total supply and the
/// per-backing `locked`); a node that predates it may still serve the backing
/// rows in `rand_getBridgeState.assets`.
async fn rand_side(config: &Config, token: &str) -> Option<RandSide> {
    let rpc = JsonRpc::new(&config.rand.rpc);
    let param = token
        .parse::<u64>()
        .map(|i| json!(i))
        .unwrap_or_else(|_| json!(token));
    if let Ok(v) = rpc.call("rand_getTokenSupply", json!([param])).await {
        if let Some(rows) = v["backings"].as_array() {
            return Some(RandSide {
                locked: backing_rows(rows)?,
                total_supply: amount(&v["total_supply"]),
            });
        }
    }
    let state = rpc.call("rand_getBridgeState", json!([])).await.ok()?;
    Some(RandSide {
        locked: backing_rows(state["assets"].as_array()?)?,
        total_supply: None,
    })
}

/// Native units -> the 8-decimal units Rand counts in.
fn attested(native: u128, decimals: u32) -> u128 {
    if decimals > 8 {
        native / 10u128.pow(decimals - 8)
    } else {
        native * 10u128.pow(8 - decimals)
    }
}

// ---- --governance ------------------------------------------------------------

async fn eth_get_code(rpc: &JsonRpc, address: &[u8; 20]) -> Result<Vec<u8>> {
    let result = rpc
        .call(
            "eth_getCode",
            json!([format!("0x{}", hex::encode(address)), "latest"]),
        )
        .await?;
    hex_data(&result)
}

/// `eth_call` whose failure is data: a revert is how a non-timelock answers.
async fn try_call(rpc: &JsonRpc, to: &[u8; 20], signature: &str) -> Result<Vec<u8>, String> {
    eth_call(rpc, to, selector(signature).to_vec())
        .await
        .map_err(|e| format!("{e:#}"))
}

fn word_to_address(w: &[u8]) -> Option<[u8; 20]> {
    (w.len() == 32).then(|| w[12..].try_into().expect("20"))
}

/// Tron `wallet/getaccount`: how many signatures the account needs, or
/// `None` when the API is not served (or the account does not exist).
async fn tron_signers(api: &str, address: &[u8; 20]) -> Option<u32> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .ok()?;
    let account: serde_json::Value = http
        .post(format!("{}/wallet/getaccount", api.trim_end_matches('/')))
        .json(&json!({ "address": format!("41{}", hex::encode(address)) }))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    gov_audit::tron_min_signers(&account)
}

async fn evm_governance(endpoint: &EvmConfig, policy: &GovernanceConfig) -> Result<Vec<Rule>> {
    let (url, flavor) = match endpoint.kind {
        EvmKind::Evm => (endpoint.rpc.clone(), Flavor::Evm),
        EvmKind::Tron => (
            format!("{}/jsonrpc", endpoint.rpc.trim_end_matches('/')),
            Flavor::Tron,
        ),
    };
    let rpc = JsonRpc::new(&url);
    let bridge = address20(&endpoint.contract)?;
    let admin = eth_call(&rpc, &bridge, selector("admin()").to_vec())
        .await
        .context("admin()")?;
    let pauser = eth_call(&rpc, &bridge, selector("pauser()").to_vec())
        .await
        .context("pauser()")?;
    let pending_admin = eth_call(&rpc, &bridge, selector("pendingAdmin()").to_vec())
        .await
        .context("pendingAdmin()")?;
    let admin20 = word_to_address(&admin).ok_or_else(|| anyhow!("admin(): not an address"))?;
    let pauser20 = word_to_address(&pauser).ok_or_else(|| anyhow!("pauser(): not an address"))?;
    let admin_code = eth_get_code(&rpc, &admin20)
        .await
        .context("eth_getCode(admin)")?;
    let pauser_code = eth_get_code(&rpc, &pauser20)
        .await
        .context("eth_getCode(pauser)")?;
    // An account without code answers any call with empty data; only ask a contract.
    let min_delay = if admin_code.is_empty() {
        Ok(Vec::new())
    } else {
        try_call(&rpc, &admin20, "getMinDelay()").await
    };
    let (pauser_threshold, tron_pauser_signers) = match flavor {
        Flavor::Evm if !pauser_code.is_empty() => {
            (try_call(&rpc, &pauser20, "getThreshold()").await, None)
        }
        Flavor::Evm => (Ok(Vec::new()), None),
        Flavor::Tron => (
            Err("not asked on Tron".into()),
            if pauser_code.is_empty() {
                tron_signers(&endpoint.rpc, &pauser20).await
            } else {
                None
            },
        ),
    };
    let reads = EvmReads {
        admin,
        admin_code,
        min_delay,
        pauser,
        pauser_code,
        pauser_threshold,
        pending_admin,
        tron_pauser_signers,
    };
    Ok(gov_audit::evm_rules(&reads, flavor, policy))
}

/// `getAccountInfo`, with the owner, optionally only a prefix of the data.
async fn solana_account_owned(
    rpc: &JsonRpc,
    key: &[u8; 32],
    prefix: Option<usize>,
) -> Result<Option<(String, Vec<u8>)>> {
    let mut opts = json!({ "encoding": "base64", "commitment": "finalized" });
    if let Some(len) = prefix {
        opts["dataSlice"] = json!({ "offset": 0, "length": len });
    }
    let result = rpc
        .call(
            "getAccountInfo",
            json!([bs58::encode(key).into_string(), opts]),
        )
        .await?;
    let value = &result["value"];
    let (Some(owner), Some(data)) = (value["owner"].as_str(), value["data"][0].as_str()) else {
        return Ok(None);
    };
    Ok(Some((
        owner.to_string(),
        base64::engine::general_purpose::STANDARD.decode(data)?,
    )))
}

async fn solana_governance(
    sol: &bridge_daemons::config::SolanaConfig,
    policy: &GovernanceConfig,
) -> Result<Vec<Rule>> {
    let rpc = JsonRpc::new(&sol.rpc);
    let program = pubkey32(&sol.program)?;
    let (config_key, _) = find_program_address(&[b"config"], &program)?;
    let (owner, data) = solana_account_owned(&rpc, &config_key, Some(97))
        .await?
        .ok_or_else(|| {
            anyhow!(
                "config PDA {} not found",
                bs58::encode(config_key).into_string()
            )
        })?;
    if owner != sol.program {
        bail!("config PDA is owned by {owner}, not the bridge program");
    }
    let config = gov_audit::decode_bridge_config(&data)?;

    let loader = gov_audit::BPF_LOADER_UPGRADEABLE;
    let (owner, data) = solana_account_owned(&rpc, &program, Some(36))
        .await?
        .ok_or_else(|| anyhow!("program account not found"))?;
    let upgrade_authority = if owner != loader {
        None // not under the upgradeable loader: it cannot be upgraded
    } else {
        let programdata = gov_audit::decode_program_account(&data)?;
        let (owner, data) = solana_account_owned(&rpc, &programdata, Some(45))
            .await?
            .ok_or_else(|| anyhow!("ProgramData account not found"))?;
        if owner != loader {
            bail!("ProgramData is owned by {owner}");
        }
        gov_audit::decode_programdata_authority(&data)?
    };

    let multisig = policy
        .solana_multisig
        .as_deref()
        .map(pubkey32)
        .transpose()?;
    let vault = multisig
        .map(|ms| gov_audit::squads_vault(&ms, policy.solana_vault_index))
        .transpose()?;
    let multisig_state = match multisig {
        None => Err("no [governance].solana_multisig configured".to_string()),
        Some(ms) => {
            let shown = bs58::encode(ms).into_string();
            match solana_account_owned(&rpc, &ms, None).await? {
                None => Err(format!("multisig {shown} not found")),
                Some((owner, _)) if owner != gov_audit::SQUADS_V4 => {
                    Err(format!("{shown} is owned by {owner}, not Squads v4"))
                }
                Some((_, data)) => {
                    gov_audit::decode_squads_multisig(&data).map_err(|e| format!("{shown}: {e:#}"))
                }
            }
        }
    };
    let reads = SolanaReads {
        config,
        upgrade_authority,
        multisig,
        vault,
        multisig_state,
    };
    Ok(gov_audit::solana_rules(&reads, policy))
}

fn render_governance(title: &str, rules: &[Rule]) -> String {
    let mut out = format!("== {title} ==\n");
    out.push_str(&format!(
        "  {:<50} {:<8} {}\n",
        "rule", "status", "observed"
    ));
    for r in rules {
        out.push_str(&format!(
            "  {:<50} {:<8} {}\n",
            r.name,
            r.status.label(),
            r.observed
        ));
    }
    out
}

fn unreadable(e: anyhow::Error) -> Vec<Rule> {
    vec![Rule {
        name: "endpoint readable".into(),
        status: Status::Fail,
        observed: format!("{e:#}"),
    }]
}

async fn governance(config: &Config) -> Result<()> {
    let policy = config.governance_policy();
    println!(
        "governance policy: min_delay_secs = {}, min_threshold = {}, solana_multisig = {}, solana_vault_index = {}\n",
        policy.min_delay_secs,
        policy.min_threshold,
        policy.solana_multisig.as_deref().unwrap_or("(unset)"),
        policy.solana_vault_index
    );
    let mut failed = 0;
    let mut endpoints_failing = 0;
    for endpoint in &config.evm {
        let rules = evm_governance(endpoint, &policy)
            .await
            .unwrap_or_else(unreadable);
        let contract = match endpoint.kind {
            EvmKind::Evm => endpoint.contract.clone(),
            EvmKind::Tron => gov_audit::tron_base58(&address20(&endpoint.contract)?),
        };
        let title = format!("{} (chain {}) {contract}", endpoint.name, endpoint.chain);
        print!("{}", render_governance(&title, &rules));
        println!();
        let n = gov_audit::failures(&rules);
        failed += n;
        endpoints_failing += usize::from(n > 0);
    }
    if let Some(sol) = &config.solana {
        let rules = solana_governance(sol, &policy)
            .await
            .unwrap_or_else(unreadable);
        let title = format!("{} (chain 5) {}", sol.name, sol.program);
        print!("{}", render_governance(&title, &rules));
        println!();
        let n = gov_audit::failures(&rules);
        failed += n;
        endpoints_failing += usize::from(n > 0);
    }
    if failed > 0 {
        return Err(anyhow!(
            "governance: {failed} rule(s) not passed on {endpoints_failing} endpoint(s)"
        ));
    }
    println!("governance: every rule passed");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    if cli.governance {
        return governance(&config).await;
    }
    let mut rows = evm_rows(&config).await?;
    rows.extend(solana_rows(&config).await?);
    let rand = rand_side(&config, &cli.token).await;
    let locked = rand.as_ref().map(|r| &r.locked);

    println!(
        "{:<5} {:<5} {:<8} {:>24} {:>18} {:>24} {:>20}  verdict",
        "chain",
        "coin",
        "enabled",
        "custody",
        "accrued fees",
        "balance held",
        "locked on Rand (8dp)"
    );
    let mut insolvent = false;
    for r in &rows {
        let on_rand = locked.as_ref().and_then(|l| {
            l.iter()
                .find(|(c, t, _)| *c == r.chain && *t == r.token_word)
                .map(|(_, _, v)| *v)
        });
        let solvent = r.balance >= r.custody + r.fees;
        insolvent |= !solvent;
        let verdict = match (solvent, on_rand) {
            (false, _) => "INSOLVENT: balance < custody + fees".to_string(),
            (true, None) => "solvent; Rand side not available".to_string(),
            (true, Some(l)) if l == attested(r.custody, r.decimals) => {
                "solvent; custody == locked".to_string()
            }
            (true, Some(l)) => format!(
                "solvent; custody - locked = {} (8dp; in-flight messages?)",
                attested(r.custody, r.decimals) as i128 - l as i128
            ),
        };
        println!(
            "{:<5} {:<5} {:<8} {:>24} {:>18} {:>24} {:>20}  {}",
            r.chain,
            r.symbol,
            r.enabled,
            r.custody,
            r.fees,
            r.balance,
            on_rand
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".into()),
            verdict
        );
    }
    if let Some(rand) = &rand {
        let sum: u128 = rand.locked.iter().map(|(_, _, v)| v).sum();
        match rand.total_supply {
            Some(total) if total == sum => {
                println!("Rand: total supply {total} == sum of locked (8dp)")
            }
            Some(total) => {
                println!("Rand: TOTAL SUPPLY {total} != SUM OF LOCKED {sum} — the ledger invariant is broken");
                insolvent = true;
            }
            None => {
                println!("Rand: sum of locked {sum} (8dp); total supply not served by this node")
            }
        }
        let custody_8dp: u128 = rows.iter().map(|r| attested(r.custody, r.decimals)).sum();
        println!(
            "Endpoints: total custody {custody_8dp} (8dp); custody - locked = {}",
            custody_8dp as i128 - sum as i128
        );
    }
    if insolvent {
        return Err(anyhow!("at least one endpoint holds less than it owes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape `rand_getTokenSupply` serves (fullnode a2c9896: amounts are decimal strings).
    #[test]
    fn renders_a_governance_table() {
        use bridge_daemons::gov_audit::{Rule, Status};
        let rules = vec![
            Rule {
                name: "admin has code".into(),
                status: Status::Fail,
                observed: "0xe49b… has no code (a key)".into(),
            },
            Rule {
                name: "no pendingAdmin".into(),
                status: Status::Pass,
                observed: "none".into(),
            },
            Rule {
                name: "pauser is a contract".into(),
                status: Status::Unknown,
                observed: "?".into(),
            },
        ];
        let text = render_governance("ethereum (chain 2) 0xd6eb", &rules);
        assert!(text.starts_with("== ethereum (chain 2) 0xd6eb =="));
        assert!(text.contains("admin has code"));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 5, "title, header, one line per rule:\n{text}");
        assert!(
            lines[2].contains("FAIL") && lines[3].contains("PASS") && lines[4].contains("UNKNOWN")
        );
    }

    #[test]
    fn reads_the_token_supply_rows() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"total_supply":"150000000","backings":[
                {"chain":2,"token":"000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7","decimals":6,"locked":"100000000","mint_cap_per_day":"10000000000000","minted_today":"100000000","mint_day":20716},
                {"chain":5,"token":"c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61","decimals":6,"locked":50000000}]}"#,
        )
        .unwrap();
        let rows = backing_rows(v["backings"].as_array().unwrap()).expect("rows");
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].0, rows[0].2), (2, 100_000_000));
        assert_eq!(
            (rows[1].0, rows[1].2),
            (5, 50_000_000),
            "a number is read like a decimal string"
        );
        assert_eq!(amount(&v["total_supply"]), Some(150_000_000));
        assert_eq!(rows.iter().map(|r| r.2).sum::<u128>(), 150_000_000);
        // 1 USDT (6 decimals) in custody is 100_000_000 on Rand; 1 BSC-USD (18) likewise.
        assert_eq!(attested(1_000_000, 6), 100_000_000);
        assert_eq!(attested(1_000_000_000_000_000_000, 18), 100_000_000);
    }
}
