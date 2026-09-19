//! Destinations reached through an existing tool rather than re-implemented:
//!
//! - Solana, through `rand-bridge-cli release` (the CLI already owns the
//!   program's instruction builders, the RPC client and the signer);
//! - Rand, through the wallet's `rand bridge-mint`, because minting a deposit
//!   means sealing a note and proving a fee bundle, which is the wallet's job.
//!
//! The attestation travels in a private temp file, never on a command line
//! (it is not secret, but it can exceed what an argv comfortably holds). Keys
//! are the tools' own business: each reads its signer from its environment.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use bridge_codec::Attestation;
use tokio::process::Command;

use super::Outcome;

/// stderr fragments that mean "someone got there first".
const ALREADY: &[&str] = &[
    "already consumed",
    "AlreadyConsumed",
    "custom program error: 0x14",
];

async fn run(mut command: Command, what: &str) -> Result<Outcome> {
    let output = command
        .output()
        .await
        .with_context(|| format!("starting {what}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        return Ok(Outcome::Submitted(
            stdout.lines().last().unwrap_or_default().trim().to_string(),
        ));
    }
    if ALREADY
        .iter()
        .any(|needle| stderr.contains(needle) || stdout.contains(needle))
    {
        return Ok(Outcome::AlreadyDone);
    }
    bail!(
        "{what} failed: {}",
        stderr.lines().last().unwrap_or("no output").trim()
    )
}

fn write_attestation(dir: &Path, attestation: &Attestation, digest: &[u8; 32]) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.hex", hex::encode(digest)));
    std::fs::write(&path, hex::encode(attestation.encode()))?;
    Ok(path)
}

pub struct SolanaSubmitter {
    pub cli: PathBuf,
    pub rpc: String,
    pub program: String,
    pub scratch: PathBuf,
}

impl SolanaSubmitter {
    pub async fn release(&self, attestation: &Attestation, digest: &[u8; 32]) -> Result<Outcome> {
        let file = write_attestation(&self.scratch, attestation, digest)?;
        let mut command = Command::new(&self.cli);
        command
            .arg("release")
            .arg("--program")
            .arg(&self.program)
            .arg("--attestation-file")
            .arg(&file)
            .env("SOL_RPC_URL", &self.rpc);
        let outcome = run(command, "rand-bridge-cli release").await;
        let _ = std::fs::remove_file(&file);
        outcome
    }
}

pub struct RandSubmitter {
    pub cli: PathBuf,
    pub extra_args: Vec<String>,
    pub scratch: PathBuf,
}

impl RandSubmitter {
    /// `to` is the recipient's full shielded address: the lock names only
    /// its hash, and the chain refuses a mint whose address does not hash
    /// to it, so a wrong entry in the recipients table cannot misdirect
    /// funds — it can only fail.
    pub async fn mint(
        &self,
        attestation: &Attestation,
        digest: &[u8; 32],
        to: &str,
        pq: Option<&[crate::pq::PqSignature]>,
    ) -> Result<Outcome> {
        let file = write_attestation(&self.scratch, attestation, digest)?;
        let pq_file = match pq {
            Some(list) => {
                let path = self
                    .scratch
                    .join(format!("{}.pq.json", hex::encode(digest)));
                std::fs::write(&path, serde_json::to_vec(list)?)?;
                Some(path)
            }
            None => None,
        };
        let mut command = Command::new(&self.cli);
        command
            .args(&self.extra_args)
            .arg("bridge-mint")
            .arg(format!("@{}", file.display()))
            .arg("--to")
            .arg(to);
        if let Some(path) = &pq_file {
            command.arg("--pq").arg(format!("@{}", path.display()));
        }
        let outcome = run(command, "rand bridge-mint").await;
        let _ = std::fs::remove_file(&file);
        if let Some(path) = &pq_file {
            let _ = std::fs::remove_file(path);
        }
        outcome
    }
}
