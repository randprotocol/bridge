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

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use bridge_daemons::config::{address20, pubkey32, Config, EvmKind};
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

/// `(chain, token word) -> locked`, in attested 8-decimal units, when the
/// Rand node serves per-backing rows.
async fn rand_locked(config: &Config) -> Option<Vec<(u16, [u8; 32], u128)>> {
    let state = JsonRpc::new(&config.rand.rpc)
        .call("rand_getBridgeState", json!([]))
        .await
        .ok()?;
    let assets = state["assets"].as_array()?;
    let mut out = Vec::new();
    for a in assets {
        let chain = a["chain"].as_u64()? as u16;
        let token: [u8; 32] = hex::decode(a["token"].as_str()?).ok()?.try_into().ok()?;
        let locked = match &a["locked"] {
            v if v.is_string() => v.as_str()?.parse().ok()?,
            v => u128::from(v.as_u64()?),
        };
        out.push((chain, token, locked));
    }
    Some(out)
}

/// Native units -> the 8-decimal units Rand counts in.
fn attested(native: u128, decimals: u32) -> u128 {
    if decimals > 8 {
        native / 10u128.pow(decimals - 8)
    } else {
        native * 10u128.pow(8 - decimals)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    let mut rows = evm_rows(&config).await?;
    rows.extend(solana_rows(&config).await?);
    let locked = rand_locked(&config).await;

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
    if insolvent {
        return Err(anyhow!("at least one endpoint holds less than it owes"));
    }
    Ok(())
}
