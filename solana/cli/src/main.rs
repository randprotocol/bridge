//! `rand-bridge-cli`: deploy-time administration of the Rand bridge's
//! Solana program from the command line.
//!
//! `initialize` is the step `solana program deploy` cannot do — it installs
//! the admin, the pauser, the Rand emitter and guardian set 0, and must be
//! signed by the program's upgrade authority. The other commands are the
//! admin/pauser instructions, plus `show` to read the bridge's state.
//!
//! Signing key: `--keypair <file>` / `SOL_KEYPAIR`, or an inline secret in
//! `SOL_PRIVATE_KEY` (see `keys.rs`). `deploy/sol.sh` drives this.

mod keys;

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use rand_bridge::instruction as ix;
use rand_bridge::state::{config_pda, guardian_pda, BridgeAccount, Config, GuardianSetAccount};
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature};
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;

#[derive(Parser)]
#[command(name = "rand-bridge-cli", version, about)]
struct Cli {
    /// JSON-RPC endpoint.
    #[arg(
        long,
        env = "SOL_RPC_URL",
        default_value = "https://api.devnet.solana.com",
        global = true
    )]
    rpc_url: String,
    /// Signer keypair file (solana-keygen JSON). Alternatively set SOL_PRIVATE_KEY.
    #[arg(long, env = keys::KEYPAIR_ENV, global = true)]
    keypair: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct ProgramArg {
    /// The deployed bridge program id.
    #[arg(long, env = "SOL_PROGRAM_ID")]
    program: Pubkey,
}

#[derive(Subcommand)]
enum Command {
    /// Print the signer's public key.
    Address,
    /// Write the signer to a solana-keygen JSON file (mode 0600), for
    /// `solana program deploy`.
    ExportKeypair {
        #[arg(long)]
        out: PathBuf,
    },
    /// One-shot setup after `solana program deploy`: config + guardian set 0.
    /// Must be signed by the program's upgrade authority.
    Initialize {
        #[command(flatten)]
        program: ProgramArg,
        /// The admin (a multisig in production).
        #[arg(long, env = "SOL_ADMIN")]
        admin: Pubkey,
        /// The pauser; defaults to the admin.
        #[arg(long, env = "SOL_PAUSER")]
        pauser: Option<Pubkey>,
        /// The 32-byte Rand burn emitter from genesis, 0x + 64 hex.
        #[arg(long, env = "RAND_EMITTER")]
        rand_emitter: String,
        /// Guardian set 0, comma-separated 0x + 40 hex addresses in index order.
        #[arg(long, env = "GUARDIANS", value_delimiter = ',')]
        guardians: Vec<String>,
    },
    /// Whitelist a mint and set its release caps (native units, 0 = unlimited).
    SetToken {
        #[command(flatten)]
        program: ProgramArg,
        #[arg(long)]
        mint: Pubkey,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        enabled: bool,
        #[arg(long, default_value_t = 0)]
        per_transfer_cap: u64,
        #[arg(long, default_value_t = 0)]
        daily_cap: u64,
    },
    /// Halt locks and releases (pauser or admin).
    Pause {
        #[command(flatten)]
        program: ProgramArg,
    },
    /// Resume locks and releases (admin).
    Unpause {
        #[command(flatten)]
        program: ProgramArg,
    },
    /// Start an admin handover (admin); `--to 11111111111111111111111111111111` (the zero pubkey) cancels.
    TransferAdmin {
        #[command(flatten)]
        program: ProgramArg,
        #[arg(long)]
        to: Pubkey,
    },
    /// Finish an admin handover (the pending admin).
    AcceptAdmin {
        #[command(flatten)]
        program: ProgramArg,
    },
    /// Set the protocol fee in basis points, at most 100 (admin).
    SetProtocolFee {
        #[command(flatten)]
        program: ProgramArg,
        #[arg(long)]
        bps: u16,
    },
    /// Pay accrued protocol fees of a mint to a token account (admin).
    WithdrawFees {
        #[command(flatten)]
        program: ProgramArg,
        #[arg(long)]
        mint: Pubkey,
        /// The destination token account (not a wallet) for the mint.
        #[arg(long)]
        to: Pubkey,
        /// Amount in the mint's own units.
        #[arg(long)]
        amount: u64,
    },
    /// Print the bridge's config and current guardian set as JSON.
    Show {
        #[command(flatten)]
        program: ProgramArg,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let secret = std::env::var(keys::SECRET_ENV).ok();
    let signer = || keys::load_keypair(cli.keypair.as_deref(), secret.as_deref());

    match cli.command {
        Command::Address => {
            println!("{}", signer()?.pubkey());
        }
        Command::ExportKeypair { out } => {
            let kp = signer()?;
            keys::write_keypair_file(&kp, &out)?;
            eprintln!("wrote {} ({})", out.display(), kp.pubkey());
        }
        Command::Initialize {
            program,
            admin,
            pauser,
            rand_emitter,
            guardians,
        } => {
            let kp = signer()?;
            let emitter = parse_hex32(&rand_emitter).context("--rand-emitter")?;
            let guardians = parse_guardians(&guardians)?;
            let pauser = pauser.unwrap_or(admin);
            let instruction = ix::initialize(
                &program.program,
                &kp.pubkey(),
                &admin,
                &pauser,
                emitter,
                guardians,
            );
            let sig = send(&cli.rpc_url, &kp, instruction)?;
            println!("initialized {} in {sig}", program.program);
            println!(
                "emitter wire form for bridge.emitters[\"5\"]: 0x{}",
                hex::encode(program.program.to_bytes())
            );
        }
        Command::SetToken {
            program,
            mint,
            enabled,
            per_transfer_cap,
            daily_cap,
        } => {
            let kp = signer()?;
            let instruction = ix::set_token(
                &program.program,
                &kp.pubkey(),
                &mint,
                enabled,
                per_transfer_cap,
                daily_cap,
            );
            let sig = send(&cli.rpc_url, &kp, instruction)?;
            println!("set-token {mint} enabled={enabled} in {sig}");
        }
        Command::Pause { program } => {
            let kp = signer()?;
            let sig = send(&cli.rpc_url, &kp, ix::pause(&program.program, &kp.pubkey()))?;
            println!("paused in {sig}");
        }
        Command::Unpause { program } => {
            let kp = signer()?;
            let sig = send(
                &cli.rpc_url,
                &kp,
                ix::unpause(&program.program, &kp.pubkey()),
            )?;
            println!("unpaused in {sig}");
        }
        Command::TransferAdmin { program, to } => {
            let kp = signer()?;
            let sig = send(
                &cli.rpc_url,
                &kp,
                ix::transfer_admin(&program.program, &kp.pubkey(), &to),
            )?;
            println!("admin transfer to {to} pending in {sig}");
        }
        Command::AcceptAdmin { program } => {
            let kp = signer()?;
            let sig = send(
                &cli.rpc_url,
                &kp,
                ix::accept_admin(&program.program, &kp.pubkey()),
            )?;
            println!("admin accepted in {sig}");
        }
        Command::SetProtocolFee { program, bps } => {
            let kp = signer()?;
            let sig = send(
                &cli.rpc_url,
                &kp,
                ix::set_protocol_fee(&program.program, &kp.pubkey(), bps),
            )?;
            println!("protocol fee {bps} bps in {sig}");
        }
        Command::WithdrawFees {
            program,
            mint,
            to,
            amount,
        } => {
            let kp = signer()?;
            let sig = send(
                &cli.rpc_url,
                &kp,
                ix::withdraw_fees(&program.program, &kp.pubkey(), &mint, &to, amount),
            )?;
            println!("withdrew {amount} of {mint} in fees to {to} in {sig}");
        }
        Command::Show { program } => {
            let client = client(&cli.rpc_url);
            let program = program.program;
            let config_key = config_pda(&program).0;
            let data = client.get_account_data(&config_key).with_context(|| {
                format!("no config at {config_key}; is the program initialized?")
            })?;
            let config = Config::load(&data).map_err(|e| anyhow!("config account: {e}"))?;
            let set_key = guardian_pda(&program, config.current_guardian_set).0;
            let set_data = client
                .get_account_data(&set_key)
                .context("guardian set account")?;
            let set = GuardianSetAccount::load(&set_data)
                .map_err(|e| anyhow!("guardian set account: {e}"))?;
            let out = serde_json::json!({
                "program": program.to_string(),
                "program_hex": format!("0x{}", hex::encode(program.to_bytes())),
                "admin": config.admin.to_string(),
                "pending_admin": config.pending_admin.to_string(),
                "pauser": config.pauser.to_string(),
                "paused": config.paused,
                "protocol_fee_bps": config.protocol_fee_bps,
                "rand_emitter": format!("0x{}", hex::encode(config.rand_emitter)),
                "current_guardian_set": config.current_guardian_set,
                "guardians": set.keys.iter().map(|k| format!("0x{}", hex::encode(k))).collect::<Vec<_>>(),
                "guardian_set_expiration": set.expiration_time,
                "sequence": config.sequence,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}

fn client(url: &str) -> RpcClient {
    RpcClient::new_with_commitment(url.to_string(), CommitmentConfig::confirmed())
}

fn send(url: &str, payer: &Keypair, instruction: Instruction) -> Result<Signature> {
    let client = client(url);
    let blockhash = client
        .get_latest_blockhash()
        .context("get_latest_blockhash")?;
    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );
    client
        .send_and_confirm_transaction(&tx)
        .map_err(|e| anyhow!("transaction failed: {e}"))
}

/// `0x` + 64 hex (the prefix is optional) into 32 bytes.
pub fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(s.trim().trim_start_matches("0x")).context("not hex")?;
    raw.try_into()
        .map_err(|v: Vec<u8>| anyhow!("expected 32 bytes, got {}", v.len()))
}

/// Guardian addresses: `0x` + 40 hex each, in index order.
pub fn parse_guardians(list: &[String]) -> Result<Vec<[u8; 20]>> {
    let mut out = Vec::with_capacity(list.len());
    for (i, g) in list
        .iter()
        .map(|g| g.trim())
        .filter(|g| !g.is_empty())
        .enumerate()
    {
        let raw = hex::decode(g.trim_start_matches("0x"))
            .with_context(|| format!("guardian {i} is not hex"))?;
        let key: [u8; 20] = raw
            .try_into()
            .map_err(|v: Vec<u8>| anyhow!("guardian {i}: expected 20 bytes, got {}", v.len()))?;
        out.push(key);
    }
    if out.is_empty() {
        bail!("no guardians given");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_guardian_parsing() {
        assert_eq!(
            parse_hex32(&format!("0x{}", "11".repeat(32))).unwrap(),
            [0x11; 32]
        );
        assert!(parse_hex32("0x1234").is_err());
        let g = parse_guardians(&[format!("0x{}", "aa".repeat(20)), "bb".repeat(20)]).unwrap();
        assert_eq!(g, vec![[0xaa; 20], [0xbb; 20]]);
        assert!(parse_guardians(&["0x12".into()]).is_err());
        assert!(parse_guardians(&[]).is_err());
    }

    #[test]
    fn initialize_builds_the_programs_own_instruction() {
        let program = rand_bridge::id();
        let payer = Keypair::new();
        let admin = Pubkey::new_unique();
        let built = ix::initialize(
            &program,
            &payer.pubkey(),
            &admin,
            &admin,
            [7; 32],
            vec![[1; 20]],
        );
        assert_eq!(built.program_id, program);
        assert_eq!(built.accounts[1].pubkey, config_pda(&program).0);
    }
}
