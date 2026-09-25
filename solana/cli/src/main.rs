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
mod upgrade_authority;

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
    /// Lock tokens from the signer's associated token account for a Rand recipient. The
    /// message account is derived from the bridge's current sequence, so a lock that loses a
    /// race to another fails and can simply be re-run.
    Lock {
        #[command(flatten)]
        program: ProgramArg,
        #[arg(long)]
        mint: Pubkey,
        /// Native units of the mint.
        #[arg(long)]
        amount: u64,
        /// The 32-byte `recipient_hash` of the recipient's shielded Rand address, hex.
        #[arg(long)]
        rand_recipient: String,
        #[arg(long, default_value_t = 0)]
        relayer_fee: u64,
        #[arg(long, default_value_t = 0)]
        nonce: u32,
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
    /// Submit a guardian-signed Rand burn attestation: pays the recipient and
    /// this signer (the relayer) out of custody. Anyone may run it.
    Release {
        #[command(flatten)]
        program: ProgramArg,
        /// A file holding the encoded attestation as hex.
        #[arg(long)]
        attestation_file: PathBuf,
        /// Compute unit limit: one secp256k1 recovery per signature costs
        /// about 25k, and the default 200k leaves a quorum of five little room.
        #[arg(long, default_value_t = 400_000)]
        compute_units: u32,
    },
    /// Submit a guardian-set rotation (payload 2) signed by the current set.
    /// Anyone may run it; allowed while paused.
    GuardianSetUpgrade {
        #[command(flatten)]
        program: ProgramArg,
        /// A file holding the encoded attestation as hex (from `rand-bridge-gov rotate`).
        #[arg(long)]
        attestation_file: PathBuf,
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
    /// BR-3: hand the program's upgrade authority to a new key (a Squads
    /// vault, in production), via the BPF Upgradeable Loader's unchecked
    /// `SetAuthority` (the new authority, a PDA, cannot co-sign offline).
    /// Signed by the *current* upgrade authority. Refuses without `--yes`.
    SetUpgradeAuthority {
        #[command(flatten)]
        program: ProgramArg,
        /// The new upgrade authority.
        #[arg(long)]
        new: Pubkey,
        /// Repeated so a typo cannot silently hand authority to the wrong key.
        #[arg(long)]
        confirm_new: Pubkey,
        /// Actually send the transaction; otherwise only print what would happen.
        #[arg(long)]
        yes: bool,
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
        Command::Lock {
            program,
            mint,
            amount,
            rand_recipient,
            relayer_fee,
            nonce,
        } => {
            let kp = signer()?;
            let recipient: [u8; 32] = hex::decode(rand_recipient.trim_start_matches("0x"))
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| anyhow!("--rand-recipient must be 32 bytes of hex"))?;
            let data = client(&cli.rpc_url)
                .get_account_data(&config_pda(&program.program).0)
                .context("config account")?;
            let config = Config::load(&data).map_err(|e| anyhow!("config account: {e}"))?;
            let instruction = ix::lock(
                &program.program,
                &kp.pubkey(),
                &ix::associated_token_address(&kp.pubkey(), &mint),
                &mint,
                config.sequence,
                amount,
                recipient,
                relayer_fee,
                nonce,
            );
            let sig = send(&cli.rpc_url, &kp, instruction)?;
            println!("locked {amount} of {mint} as sequence {} in {sig}", config.sequence);
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
        Command::Release {
            program,
            attestation_file,
            compute_units,
        } => {
            let kp = signer()?;
            let text = std::fs::read_to_string(&attestation_file)
                .with_context(|| format!("reading {}", attestation_file.display()))?;
            let bytes = hex::decode(text.trim().trim_start_matches("0x"))
                .context("attestation is not hex")?;
            let attestation = bridge_codec::Attestation::decode(&bytes)
                .map_err(|e| anyhow!("undecodable attestation: {e:?}"))?;
            let bridge_codec::Payload::Transfer(transfer) =
                bridge_codec::Payload::decode(&attestation.body.payload)
                    .map_err(|e| anyhow!("undecodable payload: {e:?}"))?
            else {
                return Err(anyhow!("not a transfer attestation"));
            };
            let body = bridge_codec::Attestation::body_bytes(&bytes)
                .map_err(|e| anyhow!("undecodable attestation: {e:?}"))?;
            let digest = rand_bridge::attestation::digest(body);
            let mint = Pubkey::new_from_array(transfer.token_address);
            let recipient = Pubkey::new_from_array(transfer.to);

            // The token accounts go first, in a transaction of their own: a
            // five-signature release already fills most of the 1,232 bytes.
            let client = client(&cli.rpc_url);
            let missing: Vec<Instruction> = [recipient, kp.pubkey()]
                .iter()
                .filter(|wallet| {
                    client
                        .get_account(&ix::associated_token_address(wallet, &mint))
                        .is_err()
                })
                .map(|wallet| ix::create_ata_idempotent(&kp.pubkey(), wallet, &mint))
                .collect();
            if !missing.is_empty() {
                let sig = send_all(&cli.rpc_url, &kp, &missing)?;
                eprintln!("created {} token account(s) in {sig}", missing.len());
            }

            let mut budget = vec![2u8]; // ComputeBudgetInstruction::SetComputeUnitLimit
            budget.extend_from_slice(&compute_units.to_le_bytes());
            let budget = Instruction {
                program_id: "ComputeBudget111111111111111111111111111111"
                    .parse()
                    .expect("a pubkey"),
                accounts: vec![],
                data: budget,
            };
            let release = ix::release(
                &program.program,
                &kp.pubkey(),
                &mint,
                attestation.guardian_set_index,
                &recipient,
                &digest,
                bytes,
            );
            let sig = send_all(&cli.rpc_url, &kp, &[budget, release])?;
            println!("{sig}");
        }
        Command::GuardianSetUpgrade {
            program,
            attestation_file,
        } => {
            let kp = signer()?;
            let text = std::fs::read_to_string(&attestation_file)
                .with_context(|| format!("reading {}", attestation_file.display()))?;
            let bytes = hex::decode(text.trim().trim_start_matches("0x"))
                .context("attestation is not hex")?;
            let attestation = bridge_codec::Attestation::decode(&bytes)
                .map_err(|e| anyhow!("undecodable attestation: {e:?}"))?;
            let bridge_codec::Payload::GuardianSetUpgrade(upgrade) =
                bridge_codec::Payload::decode(&attestation.body.payload)
                    .map_err(|e| anyhow!("undecodable payload: {e:?}"))?
            else {
                return Err(anyhow!("not a guardian-set upgrade attestation"));
            };
            let body = bridge_codec::Attestation::body_bytes(&bytes)
                .map_err(|e| anyhow!("undecodable attestation: {e:?}"))?;
            let digest = rand_bridge::attestation::digest(body);

            // One recovery per signature, plus the new set's account.
            let mut budget = vec![2u8]; // ComputeBudgetInstruction::SetComputeUnitLimit
            budget.extend_from_slice(&400_000u32.to_le_bytes());
            let budget = Instruction {
                program_id: "ComputeBudget111111111111111111111111111111"
                    .parse()
                    .expect("a pubkey"),
                accounts: vec![],
                data: budget,
            };
            let upgrade_ix = ix::guardian_set_upgrade(
                &program.program,
                &kp.pubkey(),
                attestation.guardian_set_index,
                upgrade.new_index,
                &digest,
                bytes,
            );
            let sig = send_all(&cli.rpc_url, &kp, &[budget, upgrade_ix])?;
            println!("{sig}");
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
            let program_data = upgrade_authority::program_data_address(&program);
            let upgrade_authority = match client.get_account_data(&program_data) {
                Ok(data) => match upgrade_authority::decode_program_data(&data) {
                    Ok((_, Some(a))) => a.to_string(),
                    Ok((_, None)) => "immutable".to_string(),
                    Err(e) => format!("unreadable: {e}"),
                },
                Err(_) => {
                    "unknown (no ProgramData account; not an upgradeable deployment?)".to_string()
                }
            };
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
                "program_data": program_data.to_string(),
                "upgrade_authority": upgrade_authority,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::SetUpgradeAuthority {
            program,
            new,
            confirm_new,
            yes,
        } => {
            let program = program.program;
            if new != confirm_new {
                bail!("--new and --confirm-new must match ({new} != {confirm_new})");
            }
            if new == Pubkey::default() {
                bail!("--new must not be the zero pubkey");
            }

            let kp = signer()?;
            let client = client(&cli.rpc_url);
            let program_data = upgrade_authority::program_data_address(&program);
            let data = client.get_account_data(&program_data).with_context(|| {
                format!("no ProgramData account at {program_data}; is {program} deployed under the upgradeable loader?")
            })?;
            let (_, current_authority) = upgrade_authority::decode_program_data(&data)?;
            let current_authority = current_authority.ok_or_else(|| {
                anyhow!("{program} is already immutable: its upgrade authority is None")
            })?;

            if current_authority != kp.pubkey() {
                bail!(
                    "signer {} is not the current upgrade authority ({current_authority})",
                    kp.pubkey()
                );
            }
            if new == current_authority {
                bail!("--new ({new}) is already the current upgrade authority");
            }

            let instruction =
                upgrade_authority::build_set_upgrade_authority(&program, &current_authority, &new);

            println!("program:            {program}");
            println!("program data:       {program_data}");
            println!("current authority:  {current_authority}");
            println!("new authority:      {new}");
            println!(
                "instruction:        program_id={} accounts=[{}] data=0x{}",
                instruction.program_id,
                instruction
                    .accounts
                    .iter()
                    .map(|m| format!(
                        "{}{}{}",
                        m.pubkey,
                        if m.is_signer { " (signer)" } else { "" },
                        if m.is_writable { " (writable)" } else { "" },
                    ))
                    .collect::<Vec<_>>()
                    .join(", "),
                hex::encode(&instruction.data),
            );

            if !yes {
                bail!("refusing to send without --yes; re-run with --yes to submit");
            }

            let sig = send(&cli.rpc_url, &kp, instruction)?;
            println!("sent in {sig}");

            let data = client
                .get_account_data(&program_data)
                .context("re-reading ProgramData after the transaction")?;
            let (_, after) = upgrade_authority::decode_program_data(&data)?;
            if after != Some(new) {
                bail!(
                    "upgrade authority is {after:?} after the transaction, expected {new}; the cluster may not have finished confirming"
                );
            }
            println!("upgrade authority is now {new}");
        }
    }
    Ok(())
}

fn client(url: &str) -> RpcClient {
    RpcClient::new_with_commitment(url.to_string(), CommitmentConfig::confirmed())
}

fn send(url: &str, payer: &Keypair, instruction: Instruction) -> Result<Signature> {
    send_all(url, payer, &[instruction])
}

fn send_all(url: &str, payer: &Keypair, instructions: &[Instruction]) -> Result<Signature> {
    let client = client(url);
    let blockhash = client
        .get_latest_blockhash()
        .context("get_latest_blockhash")?;
    let tx = Transaction::new_signed_with_payer(
        instructions,
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
