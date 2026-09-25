//! The pure half of `rand-bridge-audit --governance` (BR-3,
//! `docs/superpowers/specs/2026-09-25-br3-governance-design.md`, item 6):
//! account decoders and the rule tables. The binary does the reading; every
//! decision about PASS or FAIL is made here, from bytes, so it is tested
//! without a network.
//!
//! The rules, per endpoint:
//! - EVM / Tron: `admin()` has code; it answers `getMinDelay() >= min_delay_secs`;
//!   `pauser() != admin()`; the pauser is a Safe with `getThreshold() >=
//!   min_threshold` (EVM) or a contract / multi-signature account (Tron);
//!   `pendingAdmin()` is zero.
//! - Solana: `Config::admin` is the configured Squads v4 vault; that
//!   multisig's `threshold >= min_threshold` and `time_lock >= min_delay_secs`;
//!   the program's upgrade authority is the same vault; `pauser != admin`.

use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};

use crate::config::{pubkey32, GovernanceConfig};
use crate::sources::solana::find_program_address;

/// The Squads v4 program.
pub const SQUADS_V4: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";
/// The upgradeable BPF loader, owner of a program and its ProgramData.
pub const BPF_LOADER_UPGRADEABLE: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    /// Could not be decided from what the RPC serves; counts as a failure.
    Unknown,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub name: String,
    pub status: Status,
    pub observed: String,
}

fn rule(name: impl Into<String>, pass: bool, observed: impl Into<String>) -> Rule {
    Rule {
        name: name.into(),
        status: if pass { Status::Pass } else { Status::Fail },
        observed: observed.into(),
    }
}

/// Rules that did not pass (FAIL or UNKNOWN).
pub fn failures(rules: &[Rule]) -> usize {
    rules.iter().filter(|r| r.status != Status::Pass).count()
}

// ---- Solana decoders ---------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SquadsMember {
    pub key: [u8; 32],
    /// Bit 0 initiate, bit 1 vote, bit 2 execute.
    pub permissions: u8,
}

/// Squads v4 `state/multisig.rs::Multisig`, field for field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SquadsMultisig {
    pub create_key: [u8; 32],
    pub config_authority: [u8; 32],
    pub threshold: u16,
    pub time_lock: u32,
    pub transaction_index: u64,
    pub stale_transaction_index: u64,
    pub rent_collector: Option<[u8; 32]>,
    pub bump: u8,
    pub members: Vec<SquadsMember>,
}

/// Anchor's account discriminator: `sha256("account:Multisig")[..8]`.
fn multisig_discriminator() -> [u8; 8] {
    Sha256::digest(b"account:Multisig")[..8]
        .try_into()
        .expect("8")
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let out = self
            .data
            .get(self.at..self.at + n)
            .ok_or_else(|| anyhow!("account too short at byte {}", self.at))?;
        self.at += n;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn key(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("32"))
    }
    fn le<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("N"))
    }
}

/// A Squads v4 `Multisig` account: the 8-byte Anchor discriminator, then the
/// Borsh encoding (an `Option` is one tag byte, then the value if `Some`).
pub fn decode_squads_multisig(data: &[u8]) -> Result<SquadsMultisig> {
    let mut r = Reader { data, at: 0 };
    if r.take(8)? != multisig_discriminator() {
        bail!("not a Squads v4 Multisig account (discriminator)");
    }
    let create_key = r.key()?;
    let config_authority = r.key()?;
    let threshold = u16::from_le_bytes(r.le()?);
    let time_lock = u32::from_le_bytes(r.le()?);
    let transaction_index = u64::from_le_bytes(r.le()?);
    let stale_transaction_index = u64::from_le_bytes(r.le()?);
    let rent_collector = match r.u8()? {
        0 => None,
        1 => Some(r.key()?),
        t => bail!("bad Option tag {t} for rent_collector"),
    };
    let bump = r.u8()?;
    let n = u32::from_le_bytes(r.le()?) as usize;
    if n > (data.len() / 33) {
        bail!("member count {n} does not fit the account");
    }
    let mut members = Vec::with_capacity(n);
    for _ in 0..n {
        members.push(SquadsMember {
            key: r.key()?,
            permissions: r.u8()?,
        });
    }
    Ok(SquadsMultisig {
        create_key,
        config_authority,
        threshold,
        time_lock,
        transaction_index,
        stale_transaction_index,
        rent_collector,
        bump,
        members,
    })
}

/// The multisig PDA: `["multisig", "multisig", create_key]` under Squads.
pub fn squads_multisig_pda(create_key: &[u8; 32]) -> Result<([u8; 32], u8)> {
    find_program_address(
        &[b"multisig", b"multisig", create_key],
        &pubkey32(SQUADS_V4)?,
    )
}

/// A vault: `["multisig", multisig, "vault", [index]]` under Squads.
pub fn squads_vault(multisig: &[u8; 32], index: u8) -> Result<[u8; 32]> {
    Ok(find_program_address(
        &[b"multisig", multisig, b"vault", &[index]],
        &pubkey32(SQUADS_V4)?,
    )?
    .0)
}

/// `UpgradeableLoaderState::Program { programdata_address }`: u32 tag 2, key.
pub fn decode_program_account(data: &[u8]) -> Result<[u8; 32]> {
    let mut r = Reader { data, at: 0 };
    if u32::from_le_bytes(r.le()?) != 2 {
        bail!("not an upgradeable Program account");
    }
    r.key()
}

/// `UpgradeableLoaderState::ProgramData { slot, upgrade_authority_address }`:
/// u32 tag 3, u64 slot, `Option<Pubkey>` (bincode: one tag byte). `None` is
/// an immutable program.
pub fn decode_programdata_authority(data: &[u8]) -> Result<Option<[u8; 32]>> {
    let mut r = Reader { data, at: 0 };
    if u32::from_le_bytes(r.le()?) != 3 {
        bail!("not a ProgramData account");
    }
    r.take(8)?;
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(r.key()?)),
        t => bail!("bad Option tag {t} for the upgrade authority"),
    }
}

/// The three keys of the bridge's `Config` (tag 1, then admin, pending_admin, pauser).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeConfigKeys {
    pub admin: [u8; 32],
    pub pending_admin: [u8; 32],
    pub pauser: [u8; 32],
}

pub fn decode_bridge_config(data: &[u8]) -> Result<BridgeConfigKeys> {
    let mut r = Reader { data, at: 0 };
    if r.u8()? != 1 {
        bail!("not the bridge Config account (discriminator)");
    }
    Ok(BridgeConfigKeys {
        admin: r.key()?,
        pending_admin: r.key()?,
        pauser: r.key()?,
    })
}

fn b58(key: &[u8; 32]) -> String {
    bs58::encode(key).into_string()
}

// ---- EVM and Tron --------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    Evm,
    Tron,
}

/// What the binary read, raw: return data of each `eth_call` and
/// `eth_getCode`. `Err` carries the RPC's error (a revert, usually).
#[derive(Clone, Debug)]
pub struct EvmReads {
    pub admin: Vec<u8>,
    pub admin_code: Vec<u8>,
    /// `admin.getMinDelay()`.
    pub min_delay: Result<Vec<u8>, String>,
    pub pauser: Vec<u8>,
    pub pauser_code: Vec<u8>,
    /// `pauser.getThreshold()` (EVM only).
    pub pauser_threshold: Result<Vec<u8>, String>,
    pub pending_admin: Vec<u8>,
    /// Tron: signatures the pauser account needs (`wallet/getaccount`);
    /// `None` when the RPC does not serve it.
    pub tron_pauser_signers: Option<u32>,
}

fn word_address(w: &[u8]) -> Option<[u8; 20]> {
    if w.len() != 32 || w[..12].iter().any(|b| *b != 0) {
        return None;
    }
    w[12..].try_into().ok()
}

/// A uint256 return word, saturated to u128.
fn word_uint(w: &[u8]) -> Option<u128> {
    if w.len() != 32 {
        return None;
    }
    if w[..16].iter().any(|b| *b != 0) {
        return Some(u128::MAX);
    }
    Some(u128::from_be_bytes(w[16..].try_into().ok()?))
}

/// `T…` form of a Tron address (base58check of `0x41 ‖ address`).
pub fn tron_base58(address: &[u8; 20]) -> String {
    let mut raw = vec![0x41];
    raw.extend_from_slice(address);
    let check = Sha256::digest(Sha256::digest(&raw));
    raw.extend_from_slice(&check[..4]);
    bs58::encode(raw).into_string()
}

fn show(address: &[u8; 20], flavor: Flavor) -> String {
    match flavor {
        Flavor::Evm => format!("0x{}", hex::encode(address)),
        Flavor::Tron => tron_base58(address),
    }
}

fn call_error(r: &Result<Vec<u8>, String>) -> String {
    match r {
        Ok(v) if v.is_empty() => "empty return".into(),
        Ok(v) => format!("{} bytes returned", v.len()),
        Err(e) => format!("reverted: {}", e.chars().take(80).collect::<String>()),
    }
}

pub fn evm_rules(reads: &EvmReads, flavor: Flavor, policy: &GovernanceConfig) -> Vec<Rule> {
    let mut rules = Vec::new();
    let admin = word_address(&reads.admin);
    let pauser = word_address(&reads.pauser);
    let shown = |a: Option<[u8; 20]>| {
        a.map(|a| show(&a, flavor))
            .unwrap_or_else(|| "unreadable".into())
    };

    // 1. The admin is a contract.
    rules.push(if admin.is_none() {
        rule("admin has code", false, "admin(): unreadable")
    } else if reads.admin_code.is_empty() {
        rule(
            "admin has code",
            false,
            format!("{} has no code (a key)", shown(admin)),
        )
    } else {
        rule(
            "admin has code",
            true,
            format!("{} ({} bytes)", shown(admin), reads.admin_code.len()),
        )
    });

    // 2. The admin is a timelock with a long enough delay.
    let name = format!("admin getMinDelay() >= {} s", policy.min_delay_secs);
    rules.push(
        match reads.min_delay.as_ref().ok().and_then(|w| word_uint(w)) {
            Some(d) => rule(
                name,
                d >= u128::from(policy.min_delay_secs),
                format!("getMinDelay() = {d} s"),
            ),
            None => rule(
                name,
                false,
                format!(
                    "admin is not a timelock (getMinDelay(): {})",
                    call_error(&reads.min_delay)
                ),
            ),
        },
    );

    // 3. The pauser is someone else.
    rules.push(match (admin, pauser) {
        (Some(a), Some(p)) if a != p => {
            rule("pauser != admin", true, format!("pauser {}", shown(pauser)))
        }
        (Some(_), Some(_)) => rule(
            "pauser != admin",
            false,
            format!("pauser == admin == {}", shown(admin)),
        ),
        _ => rule("pauser != admin", false, "admin() or pauser(): unreadable"),
    });

    // 4. The pauser is a multisig.
    rules.push(match flavor {
        Flavor::Evm => {
            let name = format!(
                "pauser is a Safe, getThreshold() >= {}",
                policy.min_threshold
            );
            if reads.pauser_code.is_empty() {
                rule(
                    name,
                    false,
                    format!("pauser {} has no code (a key)", shown(pauser)),
                )
            } else {
                match reads
                    .pauser_threshold
                    .as_ref()
                    .ok()
                    .and_then(|w| word_uint(w))
                {
                    Some(t) => rule(
                        name,
                        t >= u128::from(policy.min_threshold),
                        format!("getThreshold() = {t}"),
                    ),
                    None => rule(
                        name,
                        false,
                        format!(
                            "pauser is not a Safe (getThreshold(): {})",
                            call_error(&reads.pauser_threshold)
                        ),
                    ),
                }
            }
        }
        Flavor::Tron => {
            let name = "pauser is a contract or a multi-signature account";
            if !reads.pauser_code.is_empty() {
                rule(
                    name,
                    true,
                    format!("contract ({} bytes)", reads.pauser_code.len()),
                )
            } else {
                match reads.tron_pauser_signers {
                    Some(n) => rule(
                        name,
                        n >= policy.min_threshold,
                        format!(
                            "{} is an account needing {n} signature(s), policy {}",
                            shown(pauser),
                            policy.min_threshold
                        ),
                    ),
                    None => Rule {
                        name: name.into(),
                        status: Status::Unknown,
                        observed: format!(
                            "{} has no code; its permissions are not readable (wallet/getaccount)",
                            shown(pauser)
                        ),
                    },
                }
            }
        }
    });

    // 5. No admin transfer in flight.
    rules.push(match word_address(&reads.pending_admin) {
        Some(p) if p == [0u8; 20] => rule("no pendingAdmin", true, "none"),
        Some(p) => rule(
            "no pendingAdmin",
            false,
            format!("pendingAdmin = {}", show(&p, flavor)),
        ),
        None => rule("no pendingAdmin", false, "pendingAdmin(): unreadable"),
    });
    rules
}

/// The fewest signatures that can act for a Tron account, over its owner
/// and active permissions (from `wallet/getaccount`). `None` when the
/// response is not an account (`{}`: it does not exist).
pub fn tron_min_signers(account: &serde_json::Value) -> Option<u32> {
    let obj = account.as_object()?;
    if obj.is_empty() {
        return None;
    }
    let mut permissions: Vec<&serde_json::Value> = Vec::new();
    if let Some(owner) = obj.get("owner_permission") {
        permissions.push(owner);
    }
    if let Some(active) = obj.get("active_permission").and_then(|a| a.as_array()) {
        permissions.extend(active.iter());
    }
    if permissions.is_empty() {
        // No permissions configured: the account's own key alone.
        return Some(1);
    }
    let needed = |p: &serde_json::Value| -> Option<u32> {
        let threshold = p["threshold"].as_u64().unwrap_or(1);
        let mut weights: Vec<u64> = p["keys"]
            .as_array()?
            .iter()
            .map(|k| k["weight"].as_u64().unwrap_or(0))
            .collect();
        weights.sort_unstable_by(|a, b| b.cmp(a));
        let mut sum = 0u64;
        for (i, w) in weights.iter().enumerate() {
            sum = sum.saturating_add(*w);
            if sum >= threshold {
                return Some(i as u32 + 1);
            }
        }
        None // the permission cannot be satisfied at all
    };
    Some(
        permissions
            .into_iter()
            .filter_map(needed)
            .min()
            .unwrap_or(u32::MAX),
    )
}

// ---- Solana ---------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SolanaReads {
    pub config: BridgeConfigKeys,
    /// `None`: the program is immutable.
    pub upgrade_authority: Option<[u8; 32]>,
    /// `[governance].solana_multisig`, and its vault.
    pub multisig: Option<[u8; 32]>,
    pub vault: Option<[u8; 32]>,
    /// The decoded multisig, or why there is none.
    pub multisig_state: Result<SquadsMultisig, String>,
}

pub fn solana_rules(reads: &SolanaReads, policy: &GovernanceConfig) -> Vec<Rule> {
    let admin = &reads.config.admin;
    let mut rules = Vec::new();
    rules.push(match reads.vault {
        None => rule(
            "admin is the Squads vault",
            false,
            format!(
                "admin {} (no [governance].solana_multisig configured)",
                b58(admin)
            ),
        ),
        Some(v) if v == *admin => rule(
            "admin is the Squads vault",
            true,
            format!("vault {}", b58(&v)),
        ),
        Some(v) => rule(
            "admin is the Squads vault",
            false,
            format!("admin {} != vault {}", b58(admin), b58(&v)),
        ),
    });
    let name = format!("multisig threshold >= {}", policy.min_threshold);
    rules.push(match &reads.multisig_state {
        Ok(ms) => rule(
            name,
            u32::from(ms.threshold) >= policy.min_threshold
                && usize::from(ms.threshold) <= ms.members.len(),
            format!("threshold {} of {} members", ms.threshold, ms.members.len()),
        ),
        Err(e) => rule(name, false, e.clone()),
    });
    let name = format!("multisig time_lock >= {} s", policy.min_delay_secs);
    rules.push(match &reads.multisig_state {
        Ok(ms) => rule(
            name,
            u64::from(ms.time_lock) >= policy.min_delay_secs,
            format!("time_lock {} s", ms.time_lock),
        ),
        Err(e) => rule(name, false, e.clone()),
    });
    rules.push(match (reads.upgrade_authority, reads.vault) {
        (None, _) => rule(
            "upgrade authority is the vault",
            false,
            "immutable (no upgrade authority)",
        ),
        (Some(a), Some(v)) if a == v => rule(
            "upgrade authority is the vault",
            true,
            b58(&a),
        ),
        (Some(a), _) => rule(
            "upgrade authority is the vault",
            false,
            format!("upgrade authority {}", b58(&a)),
        ),
    });
    rules.push(if reads.config.pauser != *admin {
        rule(
            "pauser != admin",
            true,
            format!("pauser {}", b58(&reads.config.pauser)),
        )
    } else {
        rule(
            "pauser != admin",
            false,
            format!("pauser == admin == {}", b58(admin)),
        )
    });
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(s: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .unwrap()
    }
    fn pk(s: &str) -> [u8; 32] {
        crate::config::pubkey32(s).unwrap()
    }
    fn word(addr: &[u8; 20]) -> Vec<u8> {
        let mut w = vec![0u8; 12];
        w.extend_from_slice(addr);
        w
    }
    fn uint(v: u64) -> Vec<u8> {
        let mut w = vec![0u8; 24];
        w.extend_from_slice(&v.to_be_bytes());
        w
    }
    fn policy() -> GovernanceConfig {
        GovernanceConfig::default()
    }
    fn statuses(rules: &[Rule]) -> Vec<Status> {
        rules.iter().map(|r| r.status).collect()
    }

    /// Mainnet Squads v4 multisig `5qprF75BYaQvgYq1dVUgAEkUczW5DhiuNn7ahiYu6FR6`,
    /// `getAccountInfo` (base64) from api.mainnet-beta.solana.com on 2026-09-25,
    /// slot ~450190962. Its `rent_collector` is `Some`.
    const MS_5QPR: &str = include_str!(
        "../tests/fixtures/squads-v4-multisig-5qprF75BYaQvgYq1dVUgAEkUczW5DhiuNn7ahiYu6FR6.b64"
    );
    /// Mainnet Squads v4 multisig `tr8rgazUrZzgdkfc6Q622nVJHMMzh29trdBE2uBHb4u`,
    /// same source and time. Its `rent_collector` is `None`.
    const MS_TR8R: &str = include_str!(
        "../tests/fixtures/squads-v4-multisig-tr8rgazUrZzgdkfc6Q622nVJHMMzh29trdBE2uBHb4u.b64"
    );

    #[test]
    fn decodes_a_mainnet_squads_multisig_with_a_rent_collector() {
        let ms = decode_squads_multisig(&b64(MS_5QPR)).unwrap();
        assert_eq!(ms.threshold, 2);
        assert_eq!(ms.time_lock, 0);
        assert!(ms.rent_collector.is_some());
        assert_eq!(ms.members.len(), 4);
        assert!(ms.members.len() >= usize::from(ms.threshold) && ms.threshold >= 1);
        assert!(ms.stale_transaction_index <= ms.transaction_index);
        assert!(ms.members.iter().all(|m| m.permissions & !0b111 == 0));
        // The account is the multisig PDA of its own create_key and bump.
        let (pda, bump) = squads_multisig_pda(&ms.create_key).unwrap();
        assert_eq!(pda, pk("5qprF75BYaQvgYq1dVUgAEkUczW5DhiuNn7ahiYu6FR6"));
        assert_eq!(bump, ms.bump);
    }

    #[test]
    fn decodes_a_mainnet_squads_multisig_without_a_rent_collector() {
        let ms = decode_squads_multisig(&b64(MS_TR8R)).unwrap();
        assert_eq!((ms.threshold, ms.time_lock), (3, 0));
        assert!(ms.rent_collector.is_none());
        assert_eq!(ms.members.len(), 4);
        assert!(ms.members.len() >= usize::from(ms.threshold));
        let (pda, bump) = squads_multisig_pda(&ms.create_key).unwrap();
        assert_eq!(pda, pk("tr8rgazUrZzgdkfc6Q622nVJHMMzh29trdBE2uBHb4u"));
        assert_eq!(bump, ms.bump);
    }

    #[test]
    fn refuses_what_is_not_a_squads_multisig() {
        let mut data = b64(MS_5QPR);
        data[0] ^= 1;
        assert!(
            decode_squads_multisig(&data).is_err(),
            "wrong discriminator"
        );
        let data = b64(MS_5QPR);
        assert!(decode_squads_multisig(&data[..100]).is_err(), "truncated");
    }

    #[test]
    fn derives_the_squads_vault_pda() {
        // PDA ["multisig", ms, "vault", [i]] under the Squads program, recomputed
        // independently here from the definition.
        let ms = pk("5qprF75BYaQvgYq1dVUgAEkUczW5DhiuNn7ahiYu6FR6");
        let squads = pk(SQUADS_V4);
        for i in [0u8, 1, 7] {
            let (want, _) = crate::sources::solana::find_program_address(
                &[b"multisig", &ms, b"vault", &[i]],
                &squads,
            )
            .unwrap();
            assert_eq!(squads_vault(&ms, i).unwrap(), want);
        }
        assert_ne!(squads_vault(&ms, 0).unwrap(), squads_vault(&ms, 1).unwrap());
    }

    #[test]
    fn decodes_the_bridge_program_and_its_programdata_authority() {
        // FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu and its ProgramData's
        // first 45 bytes, mainnet 2026-09-25.
        let program = b64("AgAAAGUljqd6oxwmtda9iiupePQrMgoyUDPTMmECjJxNCZ6y");
        assert_eq!(
            decode_program_account(&program).unwrap(),
            pk("7oqPp2bqrw2b54qwBJLnRUmDvmBHWwGNfSCGvNFU7cRw")
        );
        let pd = b64("AwAAAC44uRoAAAAAAb//vu5FITDjWSsybP6WhtCmtF3mimPP1gBEbdoHCOxk");
        assert_eq!(
            decode_programdata_authority(&pd).unwrap(),
            Some(pk("DvV45t4mfWKJvUXvFLoEuYgRqzmL1m6DaHbn8ZLw77kX"))
        );
        // Immutable: the Option is None.
        let mut immutable = pd[..12].to_vec();
        immutable.push(0);
        assert_eq!(decode_programdata_authority(&immutable).unwrap(), None);
        assert!(
            decode_programdata_authority(&program).is_err(),
            "a Program is not ProgramData"
        );
        assert!(decode_program_account(&pd).is_err());
    }

    #[test]
    fn decodes_the_bridge_config_keys() {
        let (admin, pending, pauser) = ([1u8; 32], [0u8; 32], [3u8; 32]);
        let mut data = vec![1u8];
        data.extend_from_slice(&admin);
        data.extend_from_slice(&pending);
        data.extend_from_slice(&pauser);
        data.extend_from_slice(&[0u8; 60]);
        let keys = decode_bridge_config(&data).unwrap();
        assert_eq!(
            (keys.admin, keys.pending_admin, keys.pauser),
            (admin, pending, pauser)
        );
        data[0] = 2;
        assert!(
            decode_bridge_config(&data).is_err(),
            "a GuardianSet is not a Config"
        );
    }

    const EOA: [u8; 20] = hex_literal("e49bd2571a549e8797be649229f62891fe300d0e");
    const TIMELOCK: [u8; 20] = hex_literal("1111111111111111111111111111111111111111");
    const SAFE: [u8; 20] = hex_literal("2222222222222222222222222222222222222222");

    const fn hex_literal(s: &str) -> [u8; 20] {
        let b = s.as_bytes();
        let mut out = [0u8; 20];
        let mut i = 0;
        while i < 20 {
            let hi = (b[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            out[i] = hi << 4 | lo;
            i += 1;
        }
        out
    }

    /// The Ethereum / BSC bridge today: admin = pauser = one EOA.
    fn eoa_reads() -> EvmReads {
        EvmReads {
            admin: word(&EOA),
            admin_code: vec![],
            // getMinDelay() on an EOA: the call succeeds with no return data.
            min_delay: Ok(vec![]),
            pauser: word(&EOA),
            pauser_code: vec![],
            pauser_threshold: Ok(vec![]),
            pending_admin: word(&[0u8; 20]),
            tron_pauser_signers: None,
        }
    }

    fn compliant_reads() -> EvmReads {
        EvmReads {
            admin: word(&TIMELOCK),
            admin_code: vec![0x60; 100],
            min_delay: Ok(uint(172_800)),
            pauser: word(&SAFE),
            pauser_code: vec![0x60; 50],
            pauser_threshold: Ok(uint(2)),
            pending_admin: word(&[0u8; 20]),
            tron_pauser_signers: None,
        }
    }

    #[test]
    fn the_eoa_state_fails_every_admin_and_pauser_rule() {
        let rules = evm_rules(&eoa_reads(), Flavor::Evm, &policy());
        use Status::*;
        assert_eq!(rules.len(), 5);
        // admin has code, admin is a timelock, pauser != admin, pauser is a Safe
        // fail; no transfer is in flight today, so "no pending admin" passes.
        assert_eq!(
            statuses(&rules),
            vec![Fail, Fail, Fail, Fail, Pass],
            "{rules:#?}"
        );
        assert!(rules[1].observed.contains("not a timelock"));
        assert!(rules[3].observed.contains("no code"));
        assert_eq!(failures(&rules), 4);
    }

    #[test]
    fn the_compliant_state_passes_every_evm_rule() {
        let rules = evm_rules(&compliant_reads(), Flavor::Evm, &policy());
        assert_eq!(statuses(&rules), vec![Status::Pass; 5], "{rules:#?}");
        assert_eq!(failures(&rules), 0);
    }

    #[test]
    fn each_evm_rule_fails_on_its_own() {
        let p = policy();
        let with = |f: &dyn Fn(&mut EvmReads)| {
            let mut r = compliant_reads();
            f(&mut r);
            statuses(&evm_rules(&r, Flavor::Evm, &p))
        };
        use Status::*;
        assert_eq!(with(&|r| r.admin_code.clear())[0], Fail);
        assert_eq!(with(&|r| r.min_delay = Ok(uint(172_799)))[1], Fail);
        assert_eq!(
            with(&|r| r.min_delay = Err("execution reverted".into()))[1],
            Fail
        );
        assert_eq!(with(&|r| r.pauser = word(&TIMELOCK))[2], Fail);
        assert_eq!(with(&|r| r.pauser_threshold = Ok(uint(1)))[3], Fail);
        assert_eq!(
            with(&|r| r.pauser_threshold = Err("execution reverted".into()))[3],
            Fail
        );
        assert_eq!(with(&|r| r.pauser_threshold = Ok(vec![]))[3], Fail);
        assert_eq!(with(&|r| r.pending_admin = word(&EOA))[4], Fail);
        // A stricter policy.
        let strict = GovernanceConfig {
            min_threshold: 3,
            min_delay_secs: 200_000,
            ..policy()
        };
        assert_eq!(
            statuses(&evm_rules(&compliant_reads(), Flavor::Evm, &strict)),
            vec![Pass, Fail, Pass, Fail, Pass]
        );
    }

    #[test]
    fn tron_accepts_a_contract_or_a_multisignature_pauser() {
        use Status::*;
        let p = policy();
        let mut r = compliant_reads();
        r.pauser_threshold = Err("not asked on Tron".into());
        assert_eq!(
            statuses(&evm_rules(&r, Flavor::Tron, &p))[3],
            Pass,
            "a contract"
        );
        r.pauser_code.clear();
        r.tron_pauser_signers = Some(2);
        assert_eq!(
            statuses(&evm_rules(&r, Flavor::Tron, &p))[3],
            Pass,
            "2-of-n account"
        );
        r.tron_pauser_signers = Some(1);
        assert_eq!(
            statuses(&evm_rules(&r, Flavor::Tron, &p))[3],
            Fail,
            "a single key"
        );
        r.tron_pauser_signers = None;
        let rules = evm_rules(&r, Flavor::Tron, &p);
        assert_eq!(
            rules[3].status, Unknown,
            "the RPC does not serve wallet/getaccount"
        );
        assert_eq!(failures(&rules), 1, "UNKNOWN counts as a failure");
        let mut eoa = eoa_reads();
        eoa.tron_pauser_signers = Some(1);
        assert_eq!(failures(&evm_rules(&eoa, Flavor::Tron, &p)), 4);
    }

    #[test]
    fn counts_the_signatures_a_tron_account_needs() {
        // The live Tron admin/pauser account, wallet/getaccount, 2026-09-25 (abridged).
        let single: serde_json::Value = serde_json::from_str(r#"{
            "address": "41e49bd2571a549e8797be649229f62891fe300d0e",
            "owner_permission": {"permission_name": "owner","threshold": 1,"keys": [{"address": "41e49bd2571a549e8797be649229f62891fe300d0e","weight": 1}]},
            "active_permission": [{"type": "Active","id": 2,"permission_name": "active","threshold": 1,"keys": [{"address": "41e49bd2571a549e8797be649229f62891fe300d0e","weight": 1}]}]}"#).unwrap();
        assert_eq!(tron_min_signers(&single), Some(1));
        let multi: serde_json::Value = serde_json::from_str(r#"{
            "owner_permission": {"threshold": 3,"keys": [{"address":"41aa","weight": 1},{"address":"41bb","weight": 1},{"address":"41cc","weight": 1},{"address":"41dd","weight": 1}]},
            "active_permission": [{"threshold": 2,"keys": [{"address":"41aa","weight": 1},{"address":"41bb","weight": 1}]}]}"#).unwrap();
        assert_eq!(
            tron_min_signers(&multi),
            Some(2),
            "the weakest permission decides"
        );
        let heavy: serde_json::Value = serde_json::from_str(r#"{
            "owner_permission": {"threshold": 3,"keys": [{"address":"41aa","weight": 3},{"address":"41bb","weight": 1},{"address":"41cc","weight": 1}]}}"#).unwrap();
        assert_eq!(
            tron_min_signers(&heavy),
            Some(1),
            "one key carries the whole threshold"
        );
        // An account with no permissions set is controlled by its own key.
        let bare: serde_json::Value =
            serde_json::from_str(r#"{"address":"41aa","balance":1}"#).unwrap();
        assert_eq!(tron_min_signers(&bare), Some(1));
        assert_eq!(
            tron_min_signers(&serde_json::json!({})),
            None,
            "no such account"
        );
    }

    #[test]
    fn prints_tron_addresses_in_base58() {
        assert_eq!(
            tron_base58(&hex_literal("0992df85dcce77ded2c0387f1fa9cf98ac859700")),
            "TAqq2i8KfYpACPUc9f5e2gAjdSgXqmPpkU"
        );
    }

    fn today_solana() -> SolanaReads {
        SolanaReads {
            config: BridgeConfigKeys {
                admin: pk("HLc2AjnRTGvH4ZK6YjPmizJ3m8wGJr5qJ3T38rkdN2P2"),
                pending_admin: [0u8; 32],
                pauser: pk("8bYjGxCUK4aUJmDr1D5i2fV1fPzhQEU2wtkTAeF2jwES"),
            },
            upgrade_authority: Some(pk("DvV45t4mfWKJvUXvFLoEuYgRqzmL1m6DaHbn8ZLw77kX")),
            multisig: None,
            vault: None,
            multisig_state: Err("no [governance].solana_multisig configured".into()),
        }
    }

    fn compliant_solana() -> SolanaReads {
        let ms_key = pk("5qprF75BYaQvgYq1dVUgAEkUczW5DhiuNn7ahiYu6FR6");
        let vault = squads_vault(&ms_key, 0).unwrap();
        let mut ms = decode_squads_multisig(&b64(MS_5QPR)).unwrap();
        ms.time_lock = 172_800;
        SolanaReads {
            config: BridgeConfigKeys {
                admin: vault,
                pending_admin: [0u8; 32],
                pauser: pk("8bYjGxCUK4aUJmDr1D5i2fV1fPzhQEU2wtkTAeF2jwES"),
            },
            upgrade_authority: Some(vault),
            multisig: Some(ms_key),
            vault: Some(vault),
            multisig_state: Ok(ms),
        }
    }

    #[test]
    fn the_solana_state_today_fails_the_squads_rules() {
        let rules = solana_rules(&today_solana(), &policy());
        use Status::*;
        // admin is the vault, threshold, time lock, upgrade authority, pauser != admin
        assert_eq!(
            statuses(&rules),
            vec![Fail, Fail, Fail, Fail, Pass],
            "{rules:#?}"
        );
        // Even with a multisig configured, the admin and authority are single keys.
        let mut r = today_solana();
        r.multisig = compliant_solana().multisig;
        r.vault = compliant_solana().vault;
        r.multisig_state = compliant_solana().multisig_state;
        assert_eq!(
            statuses(&solana_rules(&r, &policy())),
            vec![Fail, Pass, Pass, Fail, Pass]
        );
    }

    #[test]
    fn the_compliant_solana_state_passes() {
        let rules = solana_rules(&compliant_solana(), &policy());
        assert_eq!(statuses(&rules), vec![Status::Pass; 5], "{rules:#?}");
        use Status::*;
        let mut r = compliant_solana();
        r.multisig_state.as_mut().unwrap().time_lock = 3600;
        assert_eq!(
            statuses(&solana_rules(&r, &policy())),
            vec![Pass, Pass, Fail, Pass, Pass]
        );
        let mut r = compliant_solana();
        r.multisig_state.as_mut().unwrap().threshold = 1;
        assert_eq!(
            statuses(&solana_rules(&r, &policy())),
            vec![Pass, Fail, Pass, Pass, Pass]
        );
        let mut r = compliant_solana();
        r.upgrade_authority = None;
        assert_eq!(
            statuses(&solana_rules(&r, &policy()))[3],
            Fail,
            "immutable is not the vault"
        );
        let mut r = compliant_solana();
        r.config.pauser = r.config.admin;
        assert_eq!(statuses(&solana_rules(&r, &policy()))[4], Fail);
    }
}
