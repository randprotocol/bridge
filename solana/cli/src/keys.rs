//! Loading the signing keypair from the environment.
//!
//! Three forms are accepted, so the same variable works whether the key
//! came from `solana-keygen`, a wallet export, or a secrets manager:
//!
//! - a path to a `solana-keygen` JSON file (`SOL_KEYPAIR`);
//! - `SOL_PRIVATE_KEY` holding the JSON array of 64 bytes that file
//!   contains, inline;
//! - `SOL_PRIVATE_KEY` holding a base58 string: the 64-byte secret key
//!   (Phantom / Solflare export) or a 32-byte seed.
//!
//! The key is never printed and never passed to a subprocess on a command
//! line; `export-keypair` writes it to a mode-0600 file for tools that can
//! only read a file (`solana program deploy`).

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use solana_sdk::signature::{keypair_from_seed, read_keypair_file, Keypair};

/// The environment variable holding an inline secret.
pub const SECRET_ENV: &str = "SOL_PRIVATE_KEY";
/// The environment variable holding a keypair file path.
pub const KEYPAIR_ENV: &str = "SOL_KEYPAIR";

/// Loads the signer: a keypair file if `path` is given, otherwise the
/// inline `secret`.
pub fn load_keypair(path: Option<&Path>, secret: Option<&str>) -> Result<Keypair> {
    if let Some(path) = path {
        return read_keypair_file(path)
            .map_err(|e| anyhow!("cannot read keypair file {}: {e}", path.display()));
    }
    let secret = secret
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow!("no signer: set {KEYPAIR_ENV} to a keypair file or {SECRET_ENV} to a secret")
        })?;
    parse_secret(secret)
}

/// Parses an inline secret in any of the accepted forms.
pub fn parse_secret(secret: &str) -> Result<Keypair> {
    let bytes: Vec<u8> = if secret.starts_with('[') {
        serde_json::from_str(secret)
            .context("SOL_PRIVATE_KEY looks like JSON but is not a byte array")?
    } else {
        bs58::decode(secret)
            .into_vec()
            .context("SOL_PRIVATE_KEY is neither a JSON byte array nor base58")?
    };
    keypair_from_bytes(&bytes)
}

fn keypair_from_bytes(bytes: &[u8]) -> Result<Keypair> {
    match bytes.len() {
        64 => Keypair::try_from(bytes).map_err(|e| anyhow!("invalid 64-byte secret key: {e}")),
        32 => keypair_from_seed(bytes).map_err(|e| anyhow!("invalid 32-byte seed: {e}")),
        n => bail!("a Solana secret is 64 bytes (or a 32-byte seed), got {n}"),
    }
}

/// The `solana-keygen` file form of `keypair`: a JSON array of its 64
/// secret-key bytes.
pub fn keypair_json(keypair: &Keypair) -> String {
    serde_json::to_string(&keypair.to_bytes().to_vec()).expect("a byte vec serializes")
}

/// Writes `keypair` as a `solana-keygen` file readable only by its owner.
pub fn write_keypair_file(keypair: &Keypair, path: &Path) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    f.write_all(keypair_json(keypair).as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signer::Signer;

    #[test]
    fn json_array_base58_and_seed_all_load_the_same_key() {
        let kp = Keypair::new();
        let json = keypair_json(&kp);
        assert_eq!(parse_secret(&json).unwrap().pubkey(), kp.pubkey());

        let b58 = bs58::encode(kp.to_bytes()).into_string();
        assert_eq!(parse_secret(&b58).unwrap().pubkey(), kp.pubkey());

        let seed = bs58::encode(&kp.to_bytes()[..32]).into_string();
        assert_eq!(parse_secret(&seed).unwrap().pubkey(), kp.pubkey());
    }

    #[test]
    fn a_keypair_file_round_trips_and_is_private() {
        let kp = Keypair::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.json");
        write_keypair_file(&kp, &path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            load_keypair(Some(&path), None).unwrap().pubkey(),
            kp.pubkey()
        );
        // The file wins over an inline secret when both are given.
        let other = keypair_json(&Keypair::new());
        assert_eq!(
            load_keypair(Some(&path), Some(&other)).unwrap().pubkey(),
            kp.pubkey()
        );
    }

    #[test]
    fn bad_secrets_are_refused() {
        assert!(parse_secret("not base58 !!").is_err());
        assert!(parse_secret("[1,2,3]").is_err());
        assert!(load_keypair(None, None).is_err());
        assert!(load_keypair(None, Some("   ")).is_err());
    }
}
