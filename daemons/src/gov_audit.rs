//! The pure half of `rand-bridge-audit --governance` (BR-3,
//! `docs/superpowers/specs/2026-09-25-br3-governance-design.md`, item 6):
//! account decoders and the rule tables. The binary does the reading; every
//! decision about PASS or FAIL is made here, from bytes, so it is tested
//! without a network.
//!
//! The rules, per endpoint (a PASS on every row means no single key can
//! change the endpoint's configuration or code; custody itself is still
//! released by the guardian quorum, whose keys are BR-4's concern):
//! - EVM / Tron admin: has code; is not an EIP-1967 proxy; its code hashes to
//!   the pinned OZ v5.0.2 `TimelockController` (the forge build on EVM, the
//!   tronbox build on Tron); `getMinDelay() >= min_delay_secs`; its
//!   `RoleGranted` / `RoleRevoked` logs start with the constructor's
//!   self-grant of DEFAULT_ADMIN, and from them PROPOSER, EXECUTOR and
//!   CANCELLER are held by the configured admin multisig only, DEFAULT_ADMIN by
//!   the timelock only; the admin multisig is a Safe (slot 0 a canonical
//!   singleton, no module, `getThreshold() >= min_threshold`, at least that
//!   many owners) on EVM, or a Tron account needing that many signatures.
//! - EVM / Tron pauser: `!= admin`, `!=` the admin multisig; a Safe as above
//!   (EVM) or a contract / multi-signature account (Tron).
//!   `pendingAdmin()` is zero.
//! - Solana: `Config::admin` is the configured Squads v4 vault; no
//!   `pending_admin`; the multisig is autonomous (`config_authority` default),
//!   `threshold >= min_threshold`, `time_lock >= min_delay_secs`; the program's
//!   upgrade authority is the same vault; `pauser != admin`.
//! - Every bridge chain (2, 3, 4, 5) is configured.

use anyhow::{anyhow, bail, Result};
use std::collections::{BTreeMap, BTreeSet};

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
    /// The rule does not apply to this chain; not a failure.
    Exempt,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Unknown => "UNKNOWN",
            Status::Exempt => "EXEMPT",
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
    rules
        .iter()
        .filter(|r| matches!(r.status, Status::Fail | Status::Unknown))
        .count()
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

pub fn keccak(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256};
    Keccak256::digest(data).into()
}

/// `keccak256` of the runtime code of OpenZeppelin Contracts v5.0.2
/// `TimelockController` (tag v5.0.2, commit
/// dbb6104ce834628e473d2173bbc9d47f81a9eec3), as this repo's `evm/` Foundry
/// default profile builds it: solc 0.8.20+commit.a1b79de6, optimizer on,
/// 200 runs, evm_version paris, bytecode_hash ipfs (the default), source at
/// `lib/openzeppelin-contracts/contracts/governance/TimelockController.sol`,
/// remappings `@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/`,
/// `forge-std/=lib/forge-std/src/`, `openzeppelin-contracts/=lib/openzeppelin-contracts/`
/// (all three listed explicitly in `evm/foundry.toml`, with
/// `auto_detect_remappings = false`, so a new directory under `lib/` cannot
/// change them). The trailing
/// CBOR metadata hashes the settings, remappings included: a build with other
/// remappings or another profile (e.g. `fork`, cancun) gives another hash, and
/// then the deployed timelock fails this rule. The contract has no immutables,
/// so its deployed code is this exact byte string.
///
/// Produced 2026-09-25 by a throwaway `forge build` of a fresh v5.0.2 clone
/// under the scratchpad with evm/foundry.toml's default profile, and checked
/// byte-identical to `evm/out/TimelockController.sol/TimelockController.json`
/// on branch feat/br3-evm (23aea91). The runtime code is
/// `tests/fixtures/oz-v5.0.2-TimelockController.runtime.hex`; the ignored test
/// `the_pinned_timelock_hash_matches_the_repo_build` rechecks it against evm/out.
pub const TIMELOCK_RUNTIME_KECCAK: [u8; 32] = [
    0x0d, 0x2b, 0xd8, 0xc8, 0xc0, 0x35, 0x57, 0xdf, 0xa0, 0xcf, 0x0c, 0x98, 0xe0, 0x3a, 0x94, 0xe3,
    0x7f, 0x30, 0x96, 0xa2, 0x3c, 0xdb, 0xfd, 0xa0, 0x3a, 0xb5, 0x54, 0x1f, 0x4f, 0xd0, 0xba, 0xc3,
];

/// `keccak256` of the runtime code of the same OZ v5.0.2 `TimelockController`
/// as tronbox builds it for Tron: the vendored, unmodified copy under
/// `tron/contracts/governance/openzeppelin/` compiled by `npm run compile` in
/// `tron/` (tronbox 4.x, Tron's solc 0.8.20 fork, optimizer on, 200 runs,
/// evmVersion paris, per `tron/tronbox.js`), i.e. `deployedBytecode` of
/// `tron/build/contracts/TimelockController.json`. Tron's solc writes a
/// `tron` (not `ipfs`) key into the CBOR metadata, hence a hash different from
/// the EVM pin. The contract has no immutables, so a timelock deployed by
/// `deploy/tron-ops.js deploy-timelock` has exactly this runtime code, which
/// the Tron JSON-RPC `eth_getCode` returns (checked 2026-09-25: for the live
/// bridge `TAqq2i8KfYpACPUc9f5e2gAjdSgXqmPpkU` it returns the same 12110 bytes
/// as `wallet/getcontractinfo`'s `runtimecode`, and those match a fresh
/// tronbox build of `TronRandBridge` byte for byte outside its immutables,
/// metadata hash included).
///
/// Produced 2026-09-25 by `npm run compile` in `tron/` of branch
/// feat/br3-governance, twice from a clean `build/` with the same result. The
/// code is `tests/fixtures/oz-v5.0.2-TimelockController.tronbox.runtime.hex`;
/// the ignored test `the_pinned_tron_timelock_hash_matches_the_tronbox_build`
/// rechecks it against `tron/build`. `deploy/tron-ops.js` pins the same value.
pub const TRON_TIMELOCK_RUNTIME_KECCAK: [u8; 32] = [
    0xfc, 0xb7, 0xfa, 0x62, 0xda, 0xf4, 0x0b, 0x05, 0x60, 0x72, 0x9b, 0xeb, 0x39, 0xf3, 0xca, 0x1d,
    0x92, 0x24, 0xed, 0x0b, 0xba, 0x6c, 0x07, 0x9b, 0x6f, 0xd2, 0xca, 0xb2, 0x5f, 0xc5, 0x5d, 0x5b,
];

/// The Safe singletons (mastercopies) a genuine Safe proxy points at, in its
/// storage slot 0: the "canonical" deployment of v1.3.0 `GnosisSafe` and
/// `GnosisSafeL2` and of v1.4.1 `Safe` and `SafeL2`, from
/// github.com/safe-global/safe-deployments `src/assets/v1.3.0/gnosis_safe.json`,
/// `gnosis_safe_l2.json`, `src/assets/v1.4.1/safe.json`, `safe_l2.json` (main
/// at 7b1fb6d, read 2026-09-25; each lists its canonical address for chains 1
/// and 56). `evm/script/Governance.s.sol` `isCanonicalSafeSingleton` pins the
/// same six, which include the two v1.3.0 "eip155" deployments listed in the
/// same v1.3.0 files for chains 1 and 56 (codeHash equal to the canonical
/// ones', there and by `cast codehash` on Ethereum and BSC). Anything else
/// answering `getThreshold()` is not trusted as a Safe.
pub const CANONICAL_SAFE_SINGLETONS: [(&str, [u8; 20]); 6] = [
    (
        "v1.3.0",
        [
            0xd9, 0xdb, 0x27, 0x0c, 0x1b, 0x5e, 0x3b, 0xd1, 0x61, 0xe8, 0xc8, 0x50, 0x3c, 0x55,
            0xce, 0xab, 0xee, 0x70, 0x95, 0x52,
        ],
    ),
    (
        "v1.3.0 (eip155)",
        [
            0x69, 0xf4, 0xd1, 0x78, 0x8e, 0x39, 0xc8, 0x78, 0x93, 0xc9, 0x80, 0xc0, 0x6e, 0xdf,
            0x4b, 0x7f, 0x68, 0x6e, 0x29, 0x38,
        ],
    ),
    (
        "v1.3.0 L2",
        [
            0x3e, 0x5c, 0x63, 0x64, 0x4e, 0x68, 0x35, 0x49, 0x05, 0x5b, 0x9b, 0xe8, 0x65, 0x3d,
            0xe2, 0x6e, 0x0b, 0x4c, 0xd3, 0x6e,
        ],
    ),
    (
        "v1.3.0 L2 (eip155)",
        [
            0xfb, 0x1b, 0xff, 0xc9, 0xd7, 0x39, 0xb8, 0xd5, 0x20, 0xda, 0xf3, 0x7d, 0xf6, 0x66,
            0xda, 0x4c, 0x68, 0x71, 0x91, 0xea,
        ],
    ),
    (
        "v1.4.1",
        [
            0x41, 0x67, 0x5c, 0x09, 0x9f, 0x32, 0x34, 0x1b, 0xf8, 0x4b, 0xfc, 0x53, 0x82, 0xaf,
            0x53, 0x4d, 0xf5, 0xc7, 0x46, 0x1a,
        ],
    ),
    (
        "v1.4.1 L2",
        [
            0x29, 0xfc, 0xb4, 0x3b, 0x46, 0x53, 0x1b, 0xca, 0x00, 0x3d, 0xdc, 0x8f, 0xcb, 0x67,
            0xff, 0xe9, 0x19, 0x00, 0xc7, 0x62,
        ],
    ),
];

/// `keccak256` of the Safe proxy runtime code: a Safe is a proxy with exactly
/// this code (no immutables, so every proxy of a version is identical). Read
/// 2026-09-25 with `cast codehash` on Ethereum mainnet: v1.3.0
/// `GnosisSafeProxy` 0xd55fc3fcdb59c38237948bda9f14add783619f76,
/// 0x11da15f4b1831a5119830902b14db9bf47a4fb59,
/// 0xbf4673efcc7ad7680052d7d96a63d52338f5b2ed (equal to keccak256 of the
/// v1.3.0 ProxyFactory 0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2
/// `proxyRuntimeCode()` on Ethereum and BSC); v1.4.1 `SafeProxy`
/// 0xc0468813ee19f271768f1b53b128ae5b1e0a70c3,
/// 0x43703dd614c5ba3e87ec8211c56b64af14f3bd7b (a suffix of the v1.4.1
/// SafeProxyFactory 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67
/// `proxyCreationCode()` on Ethereum and BSC). safe-deployments records only
/// the factories' code hashes. The runtimes are
/// `tests/fixtures/safe-v1.3.0-GnosisSafeProxy.runtime.hex` and
/// `safe-v1.4.1-SafeProxy.runtime.hex`; `evm/script/Governance.s.sol`
/// `isSafeProxyCodehash` pins the same two.
pub const SAFE_PROXY_CODEHASHES: [(&str, [u8; 32]); 2] = [
    (
        "v1.3.0 GnosisSafeProxy",
        [
            0xb8, 0x9c, 0x1b, 0x3b, 0xdf, 0x2c, 0xf8, 0x82, 0x78, 0x18, 0x64, 0x6b, 0xce, 0x9a,
            0x8f, 0x6e, 0x37, 0x28, 0x85, 0xf8, 0xc5, 0x5e, 0x5c, 0x07, 0xac, 0xbd, 0x30, 0x7c,
            0xb1, 0x33, 0xb0, 0x00,
        ],
    ),
    (
        "v1.4.1 SafeProxy",
        [
            0xd7, 0xd4, 0x08, 0xeb, 0xcd, 0x99, 0xb2, 0xb7, 0x0b, 0xe4, 0x3e, 0x20, 0x25, 0x3d,
            0x6d, 0x92, 0xa8, 0xea, 0x8f, 0xab, 0x29, 0xbd, 0x3b, 0xe7, 0xf5, 0x5b, 0x10, 0x03,
            0x23, 0x31, 0xfb, 0x4c,
        ],
    ),
];

/// Safe's FallbackManager slot, `keccak256("fallback_manager.handler.address")`.
/// A handler equal to the Safe itself is refused (GS400: it gives unsanctioned
/// access to the Safe's internal methods).
pub const SAFE_FALLBACK_HANDLER_SLOT: &str =
    "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5";

/// Safe's ModuleManager list sentinel: `getModulesPaginated(SENTINEL, n)` is
/// the first page.
pub const SAFE_MODULES_SENTINEL: [u8; 20] = {
    let mut a = [0u8; 20];
    a[19] = 1;
    a
};

/// What the binary read from a would-be Safe (EVM): its storage slot 0 and three views.
#[derive(Clone, Debug)]
pub struct SafeReads {
    pub singleton_slot: Result<Vec<u8>, String>,
    /// Storage at `SAFE_FALLBACK_HANDLER_SLOT`.
    pub fallback_handler_slot: Result<Vec<u8>, String>,
    pub threshold: Result<Vec<u8>, String>,
    pub owners: Result<Vec<u8>, String>,
    pub modules: Result<Vec<u8>, String>,
}

impl SafeReads {
    /// Not asked: a Tron account, or an address without code.
    pub fn not_asked(why: &str) -> Self {
        SafeReads {
            singleton_slot: Err(why.into()),
            fallback_handler_slot: Err(why.into()),
            threshold: Err(why.into()),
            owners: Err(why.into()),
            modules: Err(why.into()),
        }
    }
}

/// The `address[]` a call returns as its first value, when the return has
/// `head_words` head words (1 for `getOwners()`, 2 for
/// `getModulesPaginated(address,uint256)`'s `(address[], address)`): exactly
/// the encoding solc produces, the offset pointing right past the head and
/// nothing after the items. `None` for anything else.
fn decode_address_array_in(ret: &[u8], head_words: usize) -> Option<Vec<[u8; 20]>> {
    let word = |i: usize| ret.get(i..i.checked_add(32)?);
    let offset = usize::try_from(word_uint(word(0)?)?).ok()?;
    if offset != 32 * head_words {
        return None;
    }
    let len = usize::try_from(word_uint(word(offset)?)?).ok()?;
    if len > ret.len() / 32 || ret.len() != offset + 32 * (len + 1) {
        return None;
    }
    (0..len)
        .map(|i| word(offset + 32 * (i + 1)).and_then(word_address))
        .collect()
}

/// `getOwners()` return data -> the owners.
pub fn decode_owners(ret: &[u8]) -> Option<Vec<[u8; 20]>> {
    decode_address_array_in(ret, 1)
}

/// `getModulesPaginated(SENTINEL, n)` return data -> the page of modules.
pub fn decode_modules_page(ret: &[u8]) -> Option<Vec<[u8; 20]>> {
    let modules = decode_address_array_in(ret, 2)?;
    word_address(ret.get(32..64)?)?; // `next` is an address
    Some(modules)
}

/// EIP-1967 `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`.
pub const EIP1967_IMPLEMENTATION_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
/// EIP-1967 `bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1)`.
pub const EIP1967_ADMIN_SLOT: &str =
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";

/// An OpenZeppelin AccessControl role id: `DEFAULT_ADMIN_ROLE` is zero, the
/// others `keccak256(name)`.
pub fn role_id(name: &str) -> [u8; 32] {
    if name == "DEFAULT_ADMIN_ROLE" {
        [0u8; 32]
    } else {
        keccak(name.as_bytes())
    }
}

pub fn role_granted_topic() -> [u8; 32] {
    keccak(b"RoleGranted(bytes32,address,address)")
}

pub fn role_revoked_topic() -> [u8; 32] {
    keccak(b"RoleRevoked(bytes32,address,address)")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleEvent {
    pub granted: bool,
    pub role: [u8; 32],
    pub account: [u8; 20],
}

pub type RoleHolders = BTreeMap<[u8; 32], BTreeSet<[u8; 20]>>;

/// The holders of every role after `events`, applied in order. OZ emits
/// `RoleGranted` / `RoleRevoked` only on a change, but folding is idempotent
/// either way.
pub fn fold_roles(events: &[RoleEvent]) -> RoleHolders {
    let mut holders = RoleHolders::new();
    for e in events {
        let set = holders.entry(e.role).or_default();
        if e.granted {
            set.insert(e.account);
        } else {
            set.remove(&e.account);
        }
    }
    holders
}

fn hex32(v: &serde_json::Value) -> Result<[u8; 32]> {
    let s = v.as_str().ok_or_else(|| anyhow!("expected hex, got {v}"))?;
    hex::decode(s.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("expected 32 bytes of hex, got {s}"))
}

fn hex_u64(v: &serde_json::Value) -> Result<u64> {
    let s = v
        .as_str()
        .ok_or_else(|| anyhow!("expected a hex quantity, got {v}"))?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|_| anyhow!("bad quantity {s}"))
}

/// `eth_getLogs` entries (topic0 RoleGranted or RoleRevoked) -> events in
/// chain order (block, then log index). Anything else is an error: the
/// caller asked only for these two topics.
///
/// A log the node marks `removed: true` (reorged out) is skipped. A log whose
/// `address` is not `timelock` is an error: the filter asked for the
/// timelock's logs only, so an RPC that serves others is not trusted.
pub fn role_events_from_logs(
    logs: &[serde_json::Value],
    timelock: &[u8; 20],
) -> Result<Vec<RoleEvent>> {
    let (granted, revoked) = (role_granted_topic(), role_revoked_topic());
    let mut keyed = Vec::with_capacity(logs.len());
    for log in logs {
        if log["removed"].as_bool() == Some(true) {
            continue;
        }
        let from: Option<[u8; 20]> = log["address"]
            .as_str()
            .and_then(|a| hex::decode(a.trim_start_matches("0x")).ok())
            .and_then(|b| b.try_into().ok());
        if from != Some(*timelock) {
            bail!(
                "a role log from {} is not the timelock's (0x{}): {log}",
                log["address"],
                hex::encode(timelock)
            );
        }
        let topics = log["topics"]
            .as_array()
            .filter(|t| t.len() == 4)
            .ok_or_else(|| anyhow!("a role event has 4 topics: {log}"))?;
        let topic0 = hex32(&topics[0])?;
        let is_grant = if topic0 == granted {
            true
        } else if topic0 == revoked {
            false
        } else {
            bail!("not a RoleGranted/RoleRevoked log: {log}");
        };
        let account = word_address(&hex32(&topics[2])?)
            .ok_or_else(|| anyhow!("account topic is not an address: {log}"))?;
        keyed.push((
            hex_u64(&log["blockNumber"])?,
            hex_u64(&log["logIndex"])?,
            RoleEvent {
                granted: is_grant,
                role: hex32(&topics[1])?,
                account,
            },
        ));
    }
    keyed.sort_by_key(|(block, index, _)| (*block, *index));
    Ok(keyed.into_iter().map(|(_, _, e)| e).collect())
}

/// What the binary read, raw: return data of each `eth_call`,
/// `eth_getCode` and `eth_getStorageAt`. `Err` carries the RPC's error (a
/// revert, usually).
#[derive(Clone, Debug)]
pub struct EvmReads {
    pub admin: Vec<u8>,
    pub admin_code: Vec<u8>,
    /// The admin's EIP-1967 (implementation, admin) slots.
    pub proxy_slots: Result<(Vec<u8>, Vec<u8>), String>,
    /// `admin.getMinDelay()`.
    pub min_delay: Result<Vec<u8>, String>,
    /// The admin's RoleGranted / RoleRevoked history, in chain order, or the
    /// status and reason it could not be read (not configured: FAIL; the RPC
    /// refused the range: UNKNOWN).
    pub roles: Result<Vec<RoleEvent>, (Status, String)>,
    /// `[governance].admin_multisig` for this chain.
    pub admin_multisig: Option<[u8; 20]>,
    pub admin_multisig_code: Vec<u8>,
    /// The admin multisig's Safe reads (EVM only).
    pub admin_multisig_safe: SafeReads,
    /// Tron: signatures the admin multisig account needs; `None` unknown.
    pub tron_admin_multisig_signers: Option<u32>,
    pub pauser: Vec<u8>,
    pub pauser_code: Vec<u8>,
    /// The pauser's Safe reads (EVM only).
    pub pauser_safe: SafeReads,
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

/// A uint256 return word whose high 16 bytes are zero. Anything else (short,
/// long, or larger than a u128) is not the answer of the function asked.
fn word_uint(w: &[u8]) -> Option<u128> {
    if w.len() != 32 || w[..16].iter().any(|b| *b != 0) {
        return None;
    }
    Some(u128::from_be_bytes(w[16..].try_into().ok()?))
}

fn is_zero_word(w: &[u8]) -> bool {
    w.len() == 32 && w.iter().all(|b| *b == 0)
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
        Ok(v) if v.len() == 32 => format!("0x{} is not a u128", hex::encode(v)),
        Ok(v) => format!("{} bytes returned", v.len()),
        Err(e) => format!("reverted: {}", e.chars().take(80).collect::<String>()),
    }
}

/// A Safe (EVM) or a native multi-signature account (Tron) that needs at
/// least `policy.min_threshold` signatures. On EVM a Safe is: code; slot 0 a
/// canonical singleton (`CANONICAL_SAFE_SINGLETONS`); no enabled module (a
/// module executes without any owner signature); `getThreshold() >=
/// min_threshold`; `getOwners().length >= getThreshold()`.
#[allow(clippy::too_many_arguments)]
fn multisig_rule(
    name: String,
    who: &str,
    address: Option<[u8; 20]>,
    code: &[u8],
    safe: &SafeReads,
    tron_signers: Option<u32>,
    flavor: Flavor,
    policy: &GovernanceConfig,
) -> Rule {
    match flavor {
        Flavor::Evm => {
            if code.is_empty() {
                return rule(name, false, format!("{who} has no code (a key)"));
            }
            let code_hash = keccak(code);
            let Some((proxy, _)) = SAFE_PROXY_CODEHASHES.iter().find(|(_, h)| *h == code_hash)
            else {
                return rule(
                    name,
                    false,
                    format!(
                        "{who} is not a Safe proxy (keccak256(code) = 0x{})",
                        hex::encode(code_hash)
                    ),
                );
            };
            let singleton = match &safe.singleton_slot {
                Ok(w) => match word_address(w)
                    .and_then(|a| CANONICAL_SAFE_SINGLETONS.iter().find(|(_, s)| *s == a))
                {
                    Some((version, _)) => *version,
                    None => {
                        return rule(
                            name,
                            false,
                            format!(
                                "{who} is not a canonical Safe (slot 0 = 0x{})",
                                hex::encode(w)
                            ),
                        )
                    }
                },
                Err(e) => return rule(name, false, format!("{who} slot 0 unreadable: {e}")),
            };
            match (&safe.fallback_handler_slot, address) {
                (Ok(w), Some(me)) if word_address(w) == Some(me) => {
                    return rule(
                        name,
                        false,
                        format!("{who}: Safe fallback handler is the Safe itself (GS400)"),
                    )
                }
                (Ok(w), Some(_)) if word_address(w).is_some() => {}
                (Ok(w), _) => {
                    return rule(
                        name,
                        false,
                        format!(
                            "{who} fallback handler slot 0x{} unreadable",
                            hex::encode(w)
                        ),
                    )
                }
                (Err(e), _) => {
                    return rule(name, false, format!("{who} fallback handler slot: {e}"))
                }
            }
            let Some(t) = safe.threshold.as_ref().ok().and_then(|w| word_uint(w)) else {
                return rule(
                    name,
                    false,
                    format!(
                        "{who} is not a Safe (getThreshold(): {})",
                        call_error(&safe.threshold)
                    ),
                );
            };
            let Some(owners) = safe.owners.as_ref().ok().and_then(|r| decode_owners(r)) else {
                return rule(
                    name,
                    false,
                    format!(
                        "{who} is not a Safe (getOwners(): {})",
                        call_error(&safe.owners)
                    ),
                );
            };
            let Some(modules) = safe
                .modules
                .as_ref()
                .ok()
                .and_then(|r| decode_modules_page(r))
            else {
                return rule(
                    name,
                    false,
                    format!(
                        "{who} is not a Safe (getModulesPaginated(0x1, 10): {})",
                        call_error(&safe.modules)
                    ),
                );
            };
            if !modules.is_empty() {
                let listed: Vec<String> = modules
                    .iter()
                    .map(|m| format!("0x{}", hex::encode(m)))
                    .collect();
                return rule(
                    name,
                    false,
                    format!(
                        "{who}: Safe has modules: a module acts without signatures ({})",
                        listed.join(", ")
                    ),
                );
            }
            if (owners.len() as u128) < t {
                return rule(
                    name,
                    false,
                    format!(
                        "{who} getThreshold() = {t} but only {} owner(s)",
                        owners.len()
                    ),
                );
            }
            rule(
                name,
                t >= u128::from(policy.min_threshold),
                format!(
                    "{who} {proxy} -> {singleton}, getThreshold() = {t} of {} owners, no modules",
                    owners.len()
                ),
            )
        }
        Flavor::Tron => {
            if !code.is_empty() {
                return rule(
                    name,
                    false,
                    format!("{who} is a contract, not a multi-signature account"),
                );
            }
            signers_rule(name, who, tron_signers, policy)
        }
    }
}

fn signers_rule(name: String, who: &str, signers: Option<u32>, policy: &GovernanceConfig) -> Rule {
    match signers {
        Some(n) => rule(
            name,
            n >= policy.min_threshold,
            format!("{who} is an account needing {n} signature(s)"),
        ),
        None => Rule {
            name,
            status: Status::Unknown,
            observed: format!(
                "{who}: permissions not readable or not understood (wallet/getaccount)"
            ),
        },
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
    let admin_has_code = admin.is_some() && !reads.admin_code.is_empty();
    let no_code = || format!("admin {} has no code", shown(admin));

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

    // 2. It is not a proxy that could be pointed at other code.
    let name = "admin is not an EIP-1967 proxy";
    rules.push(if !admin_has_code {
        rule(name, false, no_code())
    } else {
        match &reads.proxy_slots {
            Ok((implementation, admin_slot)) => rule(
                name,
                is_zero_word(implementation) && is_zero_word(admin_slot),
                format!(
                    "implementation slot 0x{}, admin slot 0x{}",
                    hex::encode(implementation),
                    hex::encode(admin_slot)
                ),
            ),
            Err(e) => rule(name, false, format!("eth_getStorageAt: {e}")),
        }
    });

    // 3. Its code is the pinned OZ v5.0.2 TimelockController (the forge build
    //    on EVM, the tronbox build on Tron).
    let name = "admin code is OZ v5.0.2 TimelockController";
    let pinned = match flavor {
        Flavor::Evm => TIMELOCK_RUNTIME_KECCAK,
        Flavor::Tron => TRON_TIMELOCK_RUNTIME_KECCAK,
    };
    rules.push(if !admin_has_code {
        rule(name, false, no_code())
    } else {
        let hash = keccak(&reads.admin_code);
        rule(
            name,
            hash == pinned,
            format!("keccak256(code) = 0x{}", hex::encode(hash)),
        )
    });

    // 4. With a long enough delay.
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

    // 5. The role history read is the timelock's whole history: OZ v5's
    //    constructor first grants DEFAULT_ADMIN_ROLE to the timelock itself, so
    //    that must be the earliest event. Otherwise the deploy block is after the
    //    deployment (earlier grants unseen) or the timelock was not freshly
    //    deployed.
    let name = "role history starts at the timelock constructor";
    rules.push(match (&reads.roles, admin) {
        (Err((status, why)), _) => Rule {
            name: name.into(),
            status: *status,
            observed: why.clone(),
        },
        (Ok(_), None) => rule(name, false, "admin(): unreadable"),
        (Ok(events), Some(timelock)) => {
            match events.first() {
                Some(e) if e.granted && e.role == [0u8; 32] && e.account == timelock => rule(
                    name,
                    true,
                    format!(
                        "first event RoleGranted(DEFAULT_ADMIN_ROLE, {})",
                        show(&timelock, flavor)
                    ),
                ),
                first => rule(
                    name,
                    false,
                    format!(
                    "deploy block too late or timelock not freshly deployed (first role event: {})",
                    match first {
                        None => "none".to_string(),
                        Some(e) => format!(
                            "{} 0x{}.. {}",
                            if e.granted { "RoleGranted" } else { "RoleRevoked" },
                            hex::encode(&e.role[..4]),
                            show(&e.account, flavor)
                        ),
                    }
                ),
                ),
            }
        }
    });

    // 6-9. Who holds the timelock's roles.
    let ms = reads.admin_multisig;
    for role in [
        "PROPOSER_ROLE",
        "EXECUTOR_ROLE",
        "CANCELLER_ROLE",
        "DEFAULT_ADMIN_ROLE",
    ] {
        let (expected, expected_name) = if role == "DEFAULT_ADMIN_ROLE" {
            (admin, "the timelock itself")
        } else {
            (ms, "the admin multisig")
        };
        let name = format!("{role} held by {expected_name} only");
        rules.push(match (&reads.roles, expected) {
            (_, None) if role != "DEFAULT_ADMIN_ROLE" => rule(
                name,
                false,
                "no [governance].admin_multisig configured for this chain",
            ),
            (Err((status, why)), _) => Rule {
                name,
                status: *status,
                observed: why.clone(),
            },
            (Ok(events), Some(expected)) => {
                let holders: Vec<[u8; 20]> = fold_roles(events)
                    .remove(&role_id(role))
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                let listed = if holders.is_empty() {
                    "no holder".to_string()
                } else {
                    holders
                        .iter()
                        .map(|h| show(h, flavor))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                rule(name, holders == [expected], format!("held by {listed}"))
            }
            (Ok(_), None) => rule(name, false, "admin(): unreadable"),
        });
    }

    // 10. The admin multisig is one.
    let name = format!(
        "admin multisig needs >= {} signatures",
        policy.min_threshold
    );
    rules.push(match ms {
        None => rule(
            name,
            false,
            "no [governance].admin_multisig configured for this chain",
        ),
        Some(ms) => multisig_rule(
            name,
            &format!("admin multisig {}", show(&ms, flavor)),
            Some(ms),
            &reads.admin_multisig_code,
            &reads.admin_multisig_safe,
            reads.tron_admin_multisig_signers,
            flavor,
            policy,
        ),
    });

    // 11. The pauser is someone else.
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

    // 12. ... and not the admin multisig: one set of signers would both pause
    //     and drive the timelock.
    let name = "pauser != admin multisig";
    rules.push(match (pauser, ms) {
        (_, None) => rule(
            name,
            false,
            "no [governance].admin_multisig configured for this chain",
        ),
        (None, _) => rule(name, false, "pauser(): unreadable"),
        (Some(p), Some(m)) if p == m => rule(
            name,
            false,
            format!("pauser == admin multisig == {}", show(&m, flavor)),
        ),
        (Some(p), Some(_)) => rule(name, true, format!("pauser {}", show(&p, flavor))),
    });

    // 13. The pauser is a multisig.
    rules.push(match flavor {
        Flavor::Evm => multisig_rule(
            format!(
                "pauser is a Safe, getThreshold() >= {}",
                policy.min_threshold
            ),
            &format!("pauser {}", shown(pauser)),
            pauser,
            &reads.pauser_code,
            &reads.pauser_safe,
            None,
            flavor,
            policy,
        ),
        Flavor::Tron => {
            let name = "pauser is a contract or a multi-signature account".to_string();
            if !reads.pauser_code.is_empty() {
                rule(
                    name,
                    true,
                    format!("contract ({} bytes)", reads.pauser_code.len()),
                )
            } else {
                signers_rule(name, &shown(pauser), reads.tron_pauser_signers, policy)
            }
        }
    });

    // 14. No admin transfer in flight.
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

/// With `--governance` every bridge chain must be audited: a FAIL row for
/// each of 2, 3, 4 (`[[evm]]`) and 5 (`[solana]`) that is not configured.
pub fn endpoint_coverage(evm_chains: &[u16], solana: bool) -> Vec<Rule> {
    let mut rules = Vec::new();
    for chain in [2u16, 3, 4] {
        if !evm_chains.contains(&chain) {
            rules.push(rule(
                format!("chain {chain} not configured"),
                false,
                "no [[evm]] endpoint for it",
            ));
        }
    }
    if !solana {
        rules.push(rule("chain 5 not configured", false, "no [solana] section"));
    }
    rules
}

/// The fewest signatures that can act for a Tron account, over its owner
/// and active permissions (from `wallet/getaccount`). `None` when the
/// response is not an account (`{}`: it does not exist) or has a shape this
/// does not understand; the caller reports that as UNKNOWN.
pub fn tron_min_signers(account: &serde_json::Value) -> Option<u32> {
    let obj = account.as_object()?;
    obj.get("address")?.as_str()?;
    let mut permissions: Vec<&serde_json::Value> = Vec::new();
    if let Some(owner) = obj.get("owner_permission") {
        permissions.push(owner);
    }
    if let Some(active) = obj.get("active_permission") {
        permissions.extend(active.as_array()?.iter());
    }
    if permissions.is_empty() {
        // No permissions configured: the account's own key alone.
        return Some(1);
    }
    let needed = |p: &serde_json::Value| -> Option<u32> {
        let threshold = p.get("threshold")?.as_u64()?;
        let mut weights = p
            .get("keys")?
            .as_array()?
            .iter()
            .map(|k| k.get("weight")?.as_u64())
            .collect::<Option<Vec<u64>>>()?;
        weights.sort_unstable_by(|a, b| b.cmp(a));
        let mut sum = 0u64;
        for (i, w) in weights.iter().enumerate() {
            sum = sum.saturating_add(*w);
            if sum >= threshold {
                return Some(i as u32 + 1);
            }
        }
        None // cannot be satisfied: not a shape we can reason about
    };
    permissions
        .into_iter()
        .map(needed)
        .collect::<Option<Vec<u32>>>()?
        .into_iter()
        .min()
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
    let name = "admin is the Squads vault";
    rules.push(match reads.vault {
        None => rule(
            name,
            false,
            format!(
                "admin {} (no [governance].solana_multisig configured)",
                b58(admin)
            ),
        ),
        Some(v) if v == *admin => rule(name, true, format!("vault {}", b58(&v))),
        Some(v) => rule(
            name,
            false,
            format!("admin {} != vault {}", b58(admin), b58(&v)),
        ),
    });
    let pending = &reads.config.pending_admin;
    rules.push(if *pending == [0u8; 32] {
        rule("no pending_admin", true, "none")
    } else {
        rule(
            "no pending_admin",
            false,
            format!("pending_admin = {}", b58(pending)),
        )
    });
    // A "controlled" multisig: its config_authority alone can change members,
    // threshold and time_lock without a vote (Squads v4 multisig_config.rs).
    let name = "multisig is autonomous (config_authority == default)";
    rules.push(match &reads.multisig_state {
        Ok(ms) if ms.config_authority == [0u8; 32] => {
            rule(name, true, "config_authority = default")
        }
        Ok(ms) => rule(
            name,
            false,
            format!(
                "controlled by config_authority {}",
                b58(&ms.config_authority)
            ),
        ),
        Err(e) => rule(name, false, e.clone()),
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
    let name = "upgrade authority is the vault";
    rules.push(match (reads.upgrade_authority, reads.vault) {
        (None, _) => rule(name, false, "immutable (no upgrade authority)"),
        (Some(a), Some(v)) if a == v => rule(name, true, b58(&a)),
        (Some(a), _) => rule(name, false, format!("upgrade authority {}", b58(&a))),
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
    const ADMIN_SAFE: [u8; 20] = hex_literal("3333333333333333333333333333333333333333");
    const DEPLOYER: [u8; 20] = hex_literal("4444444444444444444444444444444444444444");

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

    /// OZ v5.0.2 `TimelockController` runtime code, built as the
    /// `TIMELOCK_RUNTIME_KECCAK` doc comment says.
    fn timelock_code() -> Vec<u8> {
        hex::decode(
            include_str!("../tests/fixtures/oz-v5.0.2-TimelockController.runtime.hex")
                .trim()
                .trim_start_matches("0x"),
        )
        .unwrap()
    }

    fn grant(role: &str, account: [u8; 20]) -> RoleEvent {
        RoleEvent {
            granted: true,
            role: role_id(role),
            account,
        }
    }
    fn revoke(role: &str, account: [u8; 20]) -> RoleEvent {
        RoleEvent {
            granted: false,
            role: role_id(role),
            account,
        }
    }

    /// What OZ v5's constructor emits with `admin = address(0)`,
    /// proposers = executors = [ADMIN_SAFE].
    fn constructor_events() -> Vec<RoleEvent> {
        vec![
            grant("DEFAULT_ADMIN_ROLE", TIMELOCK),
            grant("PROPOSER_ROLE", ADMIN_SAFE),
            grant("CANCELLER_ROLE", ADMIN_SAFE),
            grant("EXECUTOR_ROLE", ADMIN_SAFE),
        ]
    }

    const SAFE_130: [u8; 20] = hex_literal("d9db270c1b5e3bd161e8c8503c55ceabee709552");
    const SAFE_130_L2: [u8; 20] = hex_literal("3e5c63644e683549055b9be8653de26e0b4cd36e");
    const SAFE_141: [u8; 20] = hex_literal("41675c099f32341bf84bfc5382af534df5c7461a");
    const SAFE_141_L2: [u8; 20] = hex_literal("29fcb43b46531bca003ddc8fcb67ffe91900c762");
    const SENTINEL: [u8; 20] = hex_literal("0000000000000000000000000000000000000001");

    fn addr(i: u64) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[12..].copy_from_slice(&i.to_be_bytes());
        a
    }

    /// ABI `address[]` as the only return value (`getOwners()`).
    fn abi_owners(n: u64) -> Vec<u8> {
        let mut out = uint(0x20);
        out.extend(uint(n));
        for i in 0..n {
            out.extend(word(&addr(0x5afe_0000 + i)));
        }
        out
    }

    /// ABI `(address[], address)` (`getModulesPaginated(SENTINEL, 10)`).
    fn abi_modules(n: u64) -> Vec<u8> {
        let mut out = uint(0x40);
        out.extend(word(&SENTINEL));
        out.extend(uint(n));
        for i in 0..n {
            out.extend(word(&addr(0x3d_0000 + i)));
        }
        out
    }

    /// Safe proxy runtimes read from Ethereum mainnet (see SAFE_PROXY_CODEHASHES).
    fn proxy_130() -> Vec<u8> {
        hex::decode(
            include_str!("../tests/fixtures/safe-v1.3.0-GnosisSafeProxy.runtime.hex").trim(),
        )
        .unwrap()
    }
    fn proxy_141() -> Vec<u8> {
        hex::decode(include_str!("../tests/fixtures/safe-v1.4.1-SafeProxy.runtime.hex").trim())
            .unwrap()
    }
    const SAFE_130_EIP155: [u8; 20] = hex_literal("69f4d1788e39c87893c980c06edf4b7f686e2938");
    const SAFE_130_L2_EIP155: [u8; 20] = hex_literal("fb1bffc9d739b8d520daf37df666da4c687191ea");

    /// Canned reads of a Safe proxy: slot 0 = `singleton`, a fallback handler set elsewhere.
    fn safe(singleton: [u8; 20], threshold: u64, owners: u64, modules: u64) -> SafeReads {
        SafeReads {
            singleton_slot: Ok(word(&singleton)),
            fallback_handler_slot: Ok(word(&DEPLOYER)),
            threshold: Ok(uint(threshold)),
            owners: Ok(abi_owners(owners)),
            modules: Ok(abi_modules(modules)),
        }
    }

    /// The Ethereum / BSC bridge today: admin = pauser = one EOA; no
    /// [governance] tables configured.
    fn eoa_reads() -> EvmReads {
        EvmReads {
            admin: word(&EOA),
            admin_code: vec![],
            proxy_slots: Ok((vec![0; 32], vec![0; 32])),
            // getMinDelay() on an EOA: the call succeeds with no return data.
            min_delay: Ok(vec![]),
            roles: Err((
                Status::Fail,
                "no [governance].timelock_deploy_block for chain 2".into(),
            )),
            admin_multisig: None,
            admin_multisig_code: vec![],
            admin_multisig_safe: SafeReads::not_asked("no admin multisig configured"),
            tron_admin_multisig_signers: None,
            pauser: word(&EOA),
            pauser_code: vec![],
            pauser_safe: SafeReads::not_asked("no code"),
            pending_admin: word(&[0u8; 20]),
            tron_pauser_signers: None,
        }
    }

    fn compliant_reads() -> EvmReads {
        EvmReads {
            admin: word(&TIMELOCK),
            admin_code: timelock_code(),
            proxy_slots: Ok((vec![0; 32], vec![0; 32])),
            min_delay: Ok(uint(172_800)),
            roles: Ok(constructor_events()),
            admin_multisig: Some(ADMIN_SAFE),
            admin_multisig_code: proxy_130(),
            admin_multisig_safe: safe(SAFE_130_L2, 3, 5, 0),
            tron_admin_multisig_signers: None,
            pauser: word(&SAFE),
            pauser_code: proxy_141(),
            pauser_safe: safe(SAFE_141, 2, 5, 0),
            pending_admin: word(&[0u8; 20]),
            tron_pauser_signers: None,
        }
    }

    const N_EVM: usize = 14;
    // Row indices.
    const NO_PROXY: usize = 1;
    const CODE_HASH: usize = 2;
    const MIN_DELAY: usize = 3;
    const HISTORY: usize = 4;
    const PROPOSERS: usize = 5;
    const EXECUTORS: usize = 6;
    const CANCELLERS: usize = 7;
    const ADMINS: usize = 8;
    const ADMIN_MS: usize = 9;
    const PAUSER_NE: usize = 10;
    const PAUSER_NE_MS: usize = 11;
    const PAUSER_MS: usize = 12;
    const PENDING: usize = 13;

    #[test]
    fn the_pinned_timelock_hash_is_the_fixture_s() {
        assert_eq!(keccak(&timelock_code()), TIMELOCK_RUNTIME_KECCAK);
        assert_eq!(
            hex::encode(TIMELOCK_RUNTIME_KECCAK),
            "0d2bd8c8c03557dfa0cf0c98e03a94e37f3096a23cdbfda03ab5541f4fd0bac3"
        );
    }

    /// After the EVM workstream merges, the repo's own build must give the
    /// same hash: `forge build` in evm/, then `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn the_pinned_timelock_hash_matches_the_repo_build() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../evm/out/TimelockController.sol/TimelockController.json"
        );
        let Ok(text) = std::fs::read_to_string(path) else {
            eprintln!("{path} not built; nothing to compare");
            return;
        };
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        let code = hex::decode(
            json["deployedBytecode"]["object"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        assert_eq!(
            keccak(&code),
            TIMELOCK_RUNTIME_KECCAK,
            "evm/ builds a different TimelockController"
        );
    }

    #[test]
    fn role_ids_are_the_oz_constants() {
        assert_eq!(role_id("DEFAULT_ADMIN_ROLE"), [0u8; 32]);
        assert_eq!(
            hex::encode(role_id("PROPOSER_ROLE")),
            "b09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1"
        );
        assert_eq!(
            hex::encode(role_id("EXECUTOR_ROLE")),
            "d8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63"
        );
        assert_eq!(
            hex::encode(role_id("CANCELLER_ROLE")),
            "fd643c72710c63c0180259aba6b2d05451e3591a24e58b62239378085726f783"
        );
    }

    #[test]
    fn folds_grants_and_revokes_in_order() {
        let events = vec![
            grant("PROPOSER_ROLE", ADMIN_SAFE),
            grant("PROPOSER_ROLE", EOA),
            revoke("PROPOSER_ROLE", ADMIN_SAFE),
            grant("PROPOSER_ROLE", ADMIN_SAFE),
            revoke("PROPOSER_ROLE", EOA),
            revoke("EXECUTOR_ROLE", EOA), // revoking what was never granted
        ];
        let holders = fold_roles(&events);
        let proposers: Vec<[u8; 20]> = holders[&role_id("PROPOSER_ROLE")].iter().copied().collect();
        assert_eq!(proposers, vec![ADMIN_SAFE]);
        assert!(holders
            .get(&role_id("EXECUTOR_ROLE"))
            .map_or(true, |s| s.is_empty()));
    }

    #[test]
    fn reads_role_events_from_logs_in_chain_order() {
        let granted = format!(
            "0x{}",
            hex::encode(keccak(b"RoleGranted(bytes32,address,address)"))
        );
        let revoked = format!(
            "0x{}",
            hex::encode(keccak(b"RoleRevoked(bytes32,address,address)"))
        );
        let proposer = format!("0x{}", hex::encode(role_id("PROPOSER_ROLE")));
        let topic = |a: &[u8; 20]| format!("0x{}{}", "00".repeat(12), hex::encode(a));
        let at = format!("0x{}", hex::encode(TIMELOCK));
        // Served out of order: the revoke (block 11) after the grant (block 10, index 3).
        let logs: Vec<serde_json::Value> = vec![
            serde_json::json!({"address": at, "topics": [revoked, proposer, topic(&EOA), topic(&TIMELOCK)], "blockNumber": "0xb", "logIndex": "0x0", "data": "0x"}),
            serde_json::json!({"address": at, "topics": [granted, proposer, topic(&EOA), topic(&DEPLOYER)], "blockNumber": "0xa", "logIndex": "0x3", "data": "0x"}),
            serde_json::json!({"address": at, "topics": [granted, proposer, topic(&ADMIN_SAFE), topic(&DEPLOYER)], "blockNumber": "0xa", "logIndex": "0x1", "data": "0x"}),
        ];
        let events = role_events_from_logs(&logs, &TIMELOCK).unwrap();
        assert_eq!(
            events,
            vec![
                grant("PROPOSER_ROLE", ADMIN_SAFE),
                grant("PROPOSER_ROLE", EOA),
                revoke("PROPOSER_ROLE", EOA)
            ]
        );
        let mut bad = logs.clone();
        bad[0]["topics"][0] = serde_json::json!(format!("0x{}", "ab".repeat(32)));
        assert!(
            role_events_from_logs(&bad, &TIMELOCK).is_err(),
            "not a role event"
        );
        let mut bad = logs;
        bad[1]["topics"][2] = serde_json::json!(format!("0x{}", "ff".repeat(32)));
        assert!(
            role_events_from_logs(&bad, &TIMELOCK).is_err(),
            "not an address topic"
        );
    }

    #[test]
    fn the_eoa_state_fails_every_admin_and_pauser_rule() {
        let rules = evm_rules(&eoa_reads(), Flavor::Evm, &policy());
        assert_eq!(rules.len(), N_EVM);
        let mut want = vec![Status::Fail; N_EVM];
        // No transfer is in flight today: "no pendingAdmin" is true.
        want[PENDING] = Status::Pass;
        assert_eq!(statuses(&rules), want, "{rules:#?}");
        assert!(rules[MIN_DELAY].observed.contains("not a timelock"));
        assert!(rules[PAUSER_MS].observed.contains("no code"));
        assert_eq!(failures(&rules), N_EVM - 1);
    }

    #[test]
    fn the_compliant_state_passes_every_evm_rule() {
        let rules = evm_rules(&compliant_reads(), Flavor::Evm, &policy());
        assert_eq!(statuses(&rules), vec![Status::Pass; N_EVM], "{rules:#?}");
        assert_eq!(failures(&rules), 0);
    }

    fn only_fails(reads: &EvmReads, flavor: Flavor, index: usize) -> Vec<Rule> {
        let rules = evm_rules(reads, flavor, &policy());
        for (i, r) in rules.iter().enumerate() {
            let want_ok = i != index;
            assert_eq!(
                r.status != Status::Fail && r.status != Status::Unknown,
                want_ok,
                "row {i} ({}) when breaking row {index}: {rules:#?}",
                r.name
            );
        }
        rules
    }

    #[test]
    fn each_evm_rule_fails_on_its_own() {
        let with = |f: &dyn Fn(&mut EvmReads), index: usize| {
            let mut r = compliant_reads();
            f(&mut r);
            only_fails(&r, Flavor::Evm, index)
        };
        with(&|r| r.proxy_slots = Ok((uint(1), vec![0; 32])), NO_PROXY);
        with(&|r| r.proxy_slots = Ok((vec![0; 32], uint(1))), NO_PROXY);
        with(&|r| r.proxy_slots = Err("refused".into()), NO_PROXY);
        with(&|r| r.admin_code[100] ^= 1, CODE_HASH);
        with(&|r| r.min_delay = Ok(uint(172_799)), MIN_DELAY);
        with(
            &|r| r.min_delay = Err("execution reverted".into()),
            MIN_DELAY,
        );
        // An oversized word is not a delay: a non-timelock answering garbage.
        let rules = with(
            &|r| {
                let mut w = vec![0xff; 16];
                w.extend_from_slice(&[0; 16]);
                r.min_delay = Ok(w);
            },
            MIN_DELAY,
        );
        assert!(rules[MIN_DELAY].observed.contains("not a timelock"));
        // An extra EOA proposer: one key can schedule.
        with(
            &|r| r.roles.as_mut().unwrap().push(grant("PROPOSER_ROLE", EOA)),
            PROPOSERS,
        );
        // Open executor role (address 0).
        with(
            &|r| {
                r.roles
                    .as_mut()
                    .unwrap()
                    .push(grant("EXECUTOR_ROLE", [0; 20]))
            },
            EXECUTORS,
        );
        with(
            &|r| r.roles.as_mut().unwrap().push(grant("CANCELLER_ROLE", EOA)),
            CANCELLERS,
        );
        // No canceller at all: the multisig was revoked.
        with(
            &|r| {
                r.roles
                    .as_mut()
                    .unwrap()
                    .push(revoke("CANCELLER_ROLE", ADMIN_SAFE))
            },
            CANCELLERS,
        );
        // The deployer kept DEFAULT_ADMIN_ROLE (constructor `admin` != 0).
        with(
            &|r| {
                r.roles
                    .as_mut()
                    .unwrap()
                    .push(grant("DEFAULT_ADMIN_ROLE", DEPLOYER))
            },
            ADMINS,
        );
        with(&|r| r.admin_multisig_code.clear(), ADMIN_MS);
        with(&|r| r.admin_multisig_safe.threshold = Ok(uint(1)), ADMIN_MS);
        with(
            &|r| r.admin_multisig_safe.threshold = Err("execution reverted".into()),
            ADMIN_MS,
        );
        with(&|r| r.pauser = word(&TIMELOCK), PAUSER_NE);
        // The pauser is the admin multisig: one Safe both pauses and drives the timelock.
        with(&|r| r.pauser = word(&ADMIN_SAFE), PAUSER_NE_MS);
        with(&|r| r.pauser_safe.threshold = Ok(uint(1)), PAUSER_MS);
        with(
            &|r| r.pauser_safe.threshold = Err("execution reverted".into()),
            PAUSER_MS,
        );
        with(&|r| r.pauser_safe.threshold = Ok(vec![]), PAUSER_MS);
        with(&|r| r.pending_admin = word(&EOA), PENDING);
    }

    #[test]
    fn the_canonical_safe_singletons_are_the_six_pinned() {
        let got: Vec<[u8; 20]> = CANONICAL_SAFE_SINGLETONS.iter().map(|(_, a)| *a).collect();
        assert_eq!(
            got,
            vec![
                SAFE_130,
                SAFE_130_EIP155,
                SAFE_130_L2,
                SAFE_130_L2_EIP155,
                SAFE_141,
                SAFE_141_L2
            ]
        );
    }

    #[test]
    fn the_safe_proxy_pins_are_the_mainnet_runtimes() {
        assert_eq!(
            hex::encode(keccak(&proxy_130())),
            "b89c1b3bdf2cf8827818646bce9a8f6e372885f8c55e5c07acbd307cb133b000"
        );
        assert_eq!(
            hex::encode(keccak(&proxy_141())),
            "d7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c"
        );
        let pins: Vec<[u8; 32]> = SAFE_PROXY_CODEHASHES.iter().map(|(_, h)| *h).collect();
        assert_eq!(pins, vec![keccak(&proxy_130()), keccak(&proxy_141())]);
        assert_eq!(
            SAFE_FALLBACK_HANDLER_SLOT,
            format!(
                "0x{}",
                hex::encode(keccak(b"fallback_manager.handler.address"))
            )
        );
        assert_eq!(
            SAFE_FALLBACK_HANDLER_SLOT,
            "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5"
        );
    }

    /// Right slot 0, right answers, other code: not a Safe (e.g. evm/test/mocks/FakeSafe.sol).
    #[test]
    fn a_look_alike_with_other_code_is_not_a_safe() {
        let mut r = compliant_reads();
        r.admin_multisig_code = vec![0x60; 40];
        let rules = only_fails(&r, Flavor::Evm, ADMIN_MS);
        assert!(
            rules[ADMIN_MS].observed.contains("not a Safe proxy"),
            "{rules:#?}"
        );
        let mut r = compliant_reads();
        r.pauser_code[5] ^= 1;
        only_fails(&r, Flavor::Evm, PAUSER_MS);
        // Either proxy version passes for either role.
        let mut r = compliant_reads();
        std::mem::swap(&mut r.admin_multisig_code, &mut r.pauser_code);
        assert_eq!(failures(&evm_rules(&r, Flavor::Evm, &policy())), 0);
    }

    /// GS400: a Safe that is its own fallback handler exposes its internal methods.
    #[test]
    fn a_safe_that_is_its_own_fallback_handler_fails() {
        let mut r = compliant_reads();
        r.admin_multisig_safe.fallback_handler_slot = Ok(word(&ADMIN_SAFE));
        let rules = only_fails(&r, Flavor::Evm, ADMIN_MS);
        assert!(rules[ADMIN_MS].observed.contains("GS400"), "{rules:#?}");
        let mut r = compliant_reads();
        r.pauser_safe.fallback_handler_slot = Ok(word(&SAFE));
        only_fails(&r, Flavor::Evm, PAUSER_MS);
        let mut r = compliant_reads();
        r.pauser_safe.fallback_handler_slot = Err("refused".into());
        only_fails(&r, Flavor::Evm, PAUSER_MS);
        // No handler at all is fine.
        let mut r = compliant_reads();
        r.admin_multisig_safe.fallback_handler_slot = Ok(vec![0; 32]);
        assert_eq!(failures(&evm_rules(&r, Flavor::Evm, &policy())), 0);
    }

    #[test]
    fn decodes_abi_address_arrays() {
        assert_eq!(decode_owners(&abi_owners(0)), Some(vec![]));
        assert_eq!(
            decode_owners(&abi_owners(3)),
            Some(vec![
                addr(0x5afe_0000),
                addr(0x5afe_0001),
                addr(0x5afe_0002)
            ])
        );
        assert_eq!(decode_modules_page(&abi_modules(0)), Some(vec![]));
        assert_eq!(
            decode_modules_page(&abi_modules(2)),
            Some(vec![addr(0x3d_0000), addr(0x3d_0001)])
        );
        // The two shapes are not interchangeable.
        assert_eq!(decode_owners(&abi_modules(0)), None);
        assert_eq!(decode_modules_page(&abi_owners(0)), None);
        // Not an array: empty, a bare word (a zero word is not an empty list),
        // a length past the data, trailing bytes, a dirty address word.
        assert_eq!(decode_owners(&[]), None);
        assert_eq!(decode_owners(&uint(3)), None);
        assert_eq!(decode_modules_page(&uint(0)), None);
        let mut short = abi_owners(3);
        short.truncate(short.len() - 32);
        assert_eq!(decode_owners(&short), None);
        let mut long = abi_owners(1);
        long.extend(uint(0));
        assert_eq!(decode_owners(&long), None);
        let mut dirty = abi_owners(1);
        dirty[64] = 1;
        assert_eq!(decode_owners(&dirty), None);
        let mut far = abi_owners(1);
        far[..32].copy_from_slice(&uint(u64::MAX));
        assert_eq!(decode_owners(&far), None);
    }

    #[test]
    fn each_safe_check_fails_on_its_own() {
        let admin = |f: &dyn Fn(&mut SafeReads)| {
            let mut r = compliant_reads();
            f(&mut r.admin_multisig_safe);
            only_fails(&r, Flavor::Evm, ADMIN_MS)
        };
        let pauser = |f: &dyn Fn(&mut SafeReads)| {
            let mut r = compliant_reads();
            f(&mut r.pauser_safe);
            only_fails(&r, Flavor::Evm, PAUSER_MS)
        };
        for check in [admin, pauser] {
            // A module is enabled: it executes without any owner signature.
            let rules = check(&|s| s.modules = Ok(abi_modules(1)));
            assert!(rules.iter().any(|r| r
                .observed
                .contains("Safe has modules: a module acts without signatures")));
            // Slot 0 is not a canonical singleton: a look-alike answering the same views.
            let rules = check(&|s| s.singleton_slot = Ok(word(&DEPLOYER)));
            assert!(rules
                .iter()
                .any(|r| r.observed.contains("not a canonical Safe")));
            check(&|s| s.singleton_slot = Ok(vec![0; 32]));
            check(&|s| s.singleton_slot = Err("refused".into()));
            // More signatures required than there are owners.
            check(&|s| s.owners = Ok(abi_owners(1)));
            check(&|s| s.owners = Err("execution reverted".into()));
            check(&|s| s.modules = Err("execution reverted".into()));
            check(&|s| s.modules = Ok(uint(0)));
        }
        // Each canonical singleton passes.
        for singleton in [
            SAFE_130,
            SAFE_130_EIP155,
            SAFE_130_L2,
            SAFE_130_L2_EIP155,
            SAFE_141,
            SAFE_141_L2,
        ] {
            let mut r = compliant_reads();
            r.admin_multisig_safe = safe(singleton, 2, 2, 0);
            r.pauser_safe = safe(singleton, 2, 3, 0);
            assert_eq!(failures(&evm_rules(&r, Flavor::Evm, &policy())), 0);
        }
    }

    #[test]
    fn the_role_history_must_start_at_the_timelock_constructor() {
        // A deploy block after the constructor: the first grants are missing.
        let mut r = compliant_reads();
        r.roles.as_mut().unwrap().remove(0);
        let rules = evm_rules(&r, Flavor::Evm, &policy());
        assert_eq!(rules[HISTORY].status, Status::Fail, "{rules:#?}");
        assert!(rules[HISTORY]
            .observed
            .contains("deploy block too late or timelock not freshly deployed"));
        // The constructor's self-grant is there but not first.
        let mut r = compliant_reads();
        r.roles.as_mut().unwrap().swap(0, 1);
        only_fails(&r, Flavor::Evm, HISTORY);
        // No event at all.
        let mut r = compliant_reads();
        r.roles = Ok(vec![]);
        assert_eq!(
            evm_rules(&r, Flavor::Evm, &policy())[HISTORY].status,
            Status::Fail
        );
        // The first grant of DEFAULT_ADMIN_ROLE to someone else: not this timelock's constructor.
        let mut r = compliant_reads();
        r.roles.as_mut().unwrap()[0] = grant("DEFAULT_ADMIN_ROLE", DEPLOYER);
        r.roles
            .as_mut()
            .unwrap()
            .push(grant("DEFAULT_ADMIN_ROLE", TIMELOCK));
        r.roles
            .as_mut()
            .unwrap()
            .push(revoke("DEFAULT_ADMIN_ROLE", DEPLOYER));
        only_fails(&r, Flavor::Evm, HISTORY);
    }

    #[test]
    fn tron_pins_the_tronbox_timelock_build() {
        assert_eq!(keccak(&tron_timelock_code()), TRON_TIMELOCK_RUNTIME_KECCAK);
        assert_eq!(
            hex::encode(TRON_TIMELOCK_RUNTIME_KECCAK),
            "fcb7fa62daf40b0560729beb39f3ca1d9224ed0bba6c079b6fd2cab25fc55d5b"
        );
        let rules = evm_rules(&tron_compliant(), Flavor::Tron, &policy());
        assert_eq!(rules[CODE_HASH].status, Status::Pass, "{rules:#?}");
        assert_eq!(failures(&rules), 0, "{rules:#?}");
        // The forge build is not the Tron timelock, nor is any other code.
        let mut r = tron_compliant();
        r.admin_code = timelock_code();
        only_fails(&r, Flavor::Tron, CODE_HASH);
        let mut r = tron_compliant();
        r.admin_code[200] ^= 1;
        only_fails(&r, Flavor::Tron, CODE_HASH);
        // ... and the tronbox build is not the EVM one.
        let mut r = compliant_reads();
        r.admin_code = tron_timelock_code();
        only_fails(&r, Flavor::Evm, CODE_HASH);
    }

    /// After `npm run compile` in tron/, the build must give the pinned hash:
    /// `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn the_pinned_tron_timelock_hash_matches_the_tronbox_build() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tron/build/contracts/TimelockController.json"
        );
        let Ok(text) = std::fs::read_to_string(path) else {
            eprintln!("{path} not built; nothing to compare");
            return;
        };
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        let code = hex::decode(
            json["deployedBytecode"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        assert_eq!(
            keccak(&code),
            TRON_TIMELOCK_RUNTIME_KECCAK,
            "tron/ builds a different TimelockController"
        );
    }

    #[test]
    fn role_logs_that_were_removed_or_are_not_the_timelock_s_are_not_trusted() {
        let granted = format!("0x{}", hex::encode(role_granted_topic()));
        let proposer = format!("0x{}", hex::encode(role_id("PROPOSER_ROLE")));
        let topic = |a: &[u8; 20]| format!("0x{}{}", "00".repeat(12), hex::encode(a));
        let at = format!("0x{}", hex::encode(TIMELOCK));
        let log = |account: &[u8; 20], index: &str| {
            serde_json::json!({"address": at, "topics": [granted, proposer, topic(account), topic(&DEPLOYER)],
                "blockNumber": "0xa", "logIndex": index, "data": "0x", "removed": false})
        };
        let mut reorged = log(&EOA, "0x2");
        reorged["removed"] = serde_json::json!(true);
        let logs = vec![log(&ADMIN_SAFE, "0x1"), reorged];
        assert_eq!(
            role_events_from_logs(&logs, &TIMELOCK).unwrap(),
            vec![grant("PROPOSER_ROLE", ADMIN_SAFE)],
            "a removed (reorged-out) log is skipped"
        );
        let mut foreign = log(&EOA, "0x2");
        foreign["address"] = serde_json::json!(format!("0x{}", hex::encode(DEPLOYER)));
        let err = role_events_from_logs(&[log(&ADMIN_SAFE, "0x1"), foreign], &TIMELOCK)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not the timelock"), "{err}");
        let mut upper = log(&ADMIN_SAFE, "0x1");
        upper["address"] = serde_json::json!(format!("0x{}", hex::encode_upper(TIMELOCK)));
        assert_eq!(role_events_from_logs(&[upper], &TIMELOCK).unwrap().len(), 1);
        let mut missing = log(&ADMIN_SAFE, "0x1");
        missing.as_object_mut().unwrap().remove("address");
        assert!(role_events_from_logs(&[missing], &TIMELOCK).is_err());
    }

    #[test]
    fn the_role_rules_recover_from_a_revoke() {
        let mut r = compliant_reads();
        let roles = r.roles.as_mut().unwrap();
        roles.push(grant("DEFAULT_ADMIN_ROLE", DEPLOYER));
        roles.push(grant("PROPOSER_ROLE", EOA));
        roles.push(revoke("PROPOSER_ROLE", EOA));
        roles.push(revoke("DEFAULT_ADMIN_ROLE", DEPLOYER));
        assert_eq!(failures(&evm_rules(&r, Flavor::Evm, &policy())), 0);
    }

    #[test]
    fn the_role_rules_need_their_config_and_their_logs() {
        use Status::*;
        let mut r = compliant_reads();
        r.admin_multisig = None;
        let rules = evm_rules(&r, Flavor::Evm, &policy());
        for i in [PROPOSERS, EXECUTORS, CANCELLERS, ADMIN_MS] {
            assert_eq!(rules[i].status, Fail, "{rules:#?}");
            assert!(
                rules[i].observed.contains("admin_multisig"),
                "{}",
                rules[i].observed
            );
        }
        let mut r = compliant_reads();
        r.roles = Err((
            Unknown,
            "eth_getLogs refused; use an archive-capable RPC".into(),
        ));
        let rules = evm_rules(&r, Flavor::Evm, &policy());
        for i in [HISTORY, PROPOSERS, EXECUTORS, CANCELLERS, ADMINS] {
            assert_eq!(rules[i].status, Unknown);
            assert!(rules[i].observed.contains("archive-capable RPC"));
        }
        assert_eq!(failures(&rules), 5, "UNKNOWN counts as a failure");
    }

    #[test]
    fn a_stricter_policy_is_applied() {
        use Status::*;
        let strict = GovernanceConfig {
            min_threshold: 3,
            min_delay_secs: 200_000,
            ..policy()
        };
        let rules = evm_rules(&compliant_reads(), Flavor::Evm, &strict);
        let fails: Vec<usize> = (0..N_EVM).filter(|i| rules[*i].status == Fail).collect();
        // The delay (172800) and the pauser Safe (2) fall short; the admin Safe (3) does not.
        assert_eq!(fails, vec![MIN_DELAY, PAUSER_MS]);
    }

    /// OZ v5.0.2 `TimelockController` runtime code as tronbox builds it, per the
    /// `TRON_TIMELOCK_RUNTIME_KECCAK` doc comment.
    fn tron_timelock_code() -> Vec<u8> {
        hex::decode(
            include_str!("../tests/fixtures/oz-v5.0.2-TimelockController.tronbox.runtime.hex")
                .trim()
                .trim_start_matches("0x"),
        )
        .unwrap()
    }

    fn tron_compliant() -> EvmReads {
        let mut r = compliant_reads();
        r.admin_code = tron_timelock_code();
        r.admin_multisig_code.clear();
        r.admin_multisig_safe = SafeReads::not_asked("not asked on Tron");
        r.tron_admin_multisig_signers = Some(3);
        r.pauser_safe = SafeReads::not_asked("not asked on Tron");
        r
    }

    #[test]
    fn tron_runs_every_rule() {
        let rules = evm_rules(&tron_compliant(), Flavor::Tron, &policy());
        assert_eq!(failures(&rules), 0, "{rules:#?}");
        assert!(rules.iter().all(|r| r.status == Status::Pass), "{rules:#?}");
        // The admin multisig is a native multi-signature account.
        let mut r = tron_compliant();
        r.tron_admin_multisig_signers = Some(1);
        only_fails(&r, Flavor::Tron, ADMIN_MS);
        let mut r = tron_compliant();
        r.tron_admin_multisig_signers = None;
        let rules = only_fails(&r, Flavor::Tron, ADMIN_MS);
        assert_eq!(rules[ADMIN_MS].status, Status::Unknown);
        let mut r = tron_compliant();
        r.admin_multisig_code = vec![0x60; 10];
        only_fails(&r, Flavor::Tron, ADMIN_MS);
        // The other admin rules still apply on Tron.
        let mut r = tron_compliant();
        r.proxy_slots = Ok((uint(1), vec![0; 32]));
        only_fails(&r, Flavor::Tron, NO_PROXY);
    }

    #[test]
    fn tron_accepts_a_contract_or_a_multisignature_pauser() {
        use Status::*;
        let p = policy();
        let mut r = tron_compliant();
        assert_eq!(
            statuses(&evm_rules(&r, Flavor::Tron, &p))[PAUSER_MS],
            Pass,
            "a contract"
        );
        r.pauser_code.clear();
        r.tron_pauser_signers = Some(2);
        assert_eq!(
            statuses(&evm_rules(&r, Flavor::Tron, &p))[PAUSER_MS],
            Pass,
            "2-of-n account"
        );
        r.tron_pauser_signers = Some(1);
        assert_eq!(
            statuses(&evm_rules(&r, Flavor::Tron, &p))[PAUSER_MS],
            Fail,
            "a single key"
        );
        r.tron_pauser_signers = None;
        let rules = evm_rules(&r, Flavor::Tron, &p);
        assert_eq!(
            rules[PAUSER_MS].status, Unknown,
            "the RPC does not serve wallet/getaccount"
        );
        assert_eq!(failures(&rules), 1, "UNKNOWN counts as a failure");
        let mut eoa = eoa_reads();
        eoa.tron_pauser_signers = Some(1);
        eoa.tron_admin_multisig_signers = None;
        let rules = evm_rules(&eoa, Flavor::Tron, &p);
        assert_eq!(rules[CODE_HASH].status, Fail);
        assert_eq!(failures(&rules), N_EVM - 1, "all but no-pendingAdmin");
    }

    #[test]
    fn counts_the_signatures_a_tron_account_needs() {
        let parse = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap();
        // The live Tron admin/pauser account, wallet/getaccount, 2026-09-25 (abridged).
        let single = parse(
            r#"{
            "address": "41e49bd2571a549e8797be649229f62891fe300d0e",
            "owner_permission": {"permission_name": "owner","threshold": 1,"keys": [{"address": "41e49bd2571a549e8797be649229f62891fe300d0e","weight": 1}]},
            "active_permission": [{"type": "Active","id": 2,"permission_name": "active","threshold": 1,"keys": [{"address": "41e49bd2571a549e8797be649229f62891fe300d0e","weight": 1}]}]}"#,
        );
        assert_eq!(tron_min_signers(&single), Some(1));
        let multi = parse(
            r#"{"address":"41aa",
            "owner_permission": {"threshold": 3,"keys": [{"address":"41aa","weight": 1},{"address":"41bb","weight": 1},{"address":"41cc","weight": 1},{"address":"41dd","weight": 1}]},
            "active_permission": [{"threshold": 2,"keys": [{"address":"41aa","weight": 1},{"address":"41bb","weight": 1}]}]}"#,
        );
        assert_eq!(
            tron_min_signers(&multi),
            Some(2),
            "the weakest permission decides"
        );
        let heavy = parse(
            r#"{"address":"41aa",
            "owner_permission": {"threshold": 3,"keys": [{"address":"41aa","weight": 3},{"address":"41bb","weight": 1},{"address":"41cc","weight": 1}]}}"#,
        );
        assert_eq!(
            tron_min_signers(&heavy),
            Some(1),
            "one key carries the whole threshold"
        );
        // An account with no permissions set is controlled by its own key.
        assert_eq!(
            tron_min_signers(&parse(r#"{"address":"41aa","balance":1}"#)),
            Some(1)
        );
        assert_eq!(
            tron_min_signers(&serde_json::json!({})),
            None,
            "no such account"
        );
        // Shapes we do not understand are UNKNOWN, never a pass.
        for odd in [
            r#"{"address":"41aa","owner_permission": {"keys": [{"address":"41aa","weight": 1}]}}"#,
            r#"{"address":"41aa","owner_permission": {"threshold": 2,"keys": "41aa"}}"#,
            r#"{"address":"41aa","owner_permission": {"threshold": 2,"keys": [{"address":"41aa","weight": "2"}]}}"#,
            r#"{"address":"41aa","owner_permission": {"threshold": 5,"keys": [{"address":"41aa","weight": 1}]}}"#,
            r#"{"address":"41aa","owner_permission": {"threshold": 2,"keys": [{"address":"41aa","weight": 1},{"address":"41bb","weight": 1}]},"active_permission": {"threshold": 1}}"#,
            r#"{"address":"41aa","owner_permission": {"threshold": 2,"keys": [{"address":"41aa","weight": 1},{"address":"41bb","weight": 1}]},"active_permission": [{"threshold": 1}]}"#,
            r#"[1]"#,
        ] {
            assert_eq!(tron_min_signers(&parse(odd)), None, "{odd}");
        }
    }

    #[test]
    fn prints_tron_addresses_in_base58() {
        assert_eq!(
            tron_base58(&hex_literal("0992df85dcce77ded2c0387f1fa9cf98ac859700")),
            "TAqq2i8KfYpACPUc9f5e2gAjdSgXqmPpkU"
        );
    }

    #[test]
    fn every_bridge_chain_must_be_configured() {
        assert!(endpoint_coverage(&[2, 3, 4], true).is_empty());
        let rules = endpoint_coverage(&[3], false);
        let names: Vec<&str> = rules.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "chain 2 not configured",
                "chain 4 not configured",
                "chain 5 not configured"
            ]
        );
        assert!(rules.iter().all(|r| r.status == Status::Fail));
    }

    // Solana rows.
    const SOL_ADMIN_VAULT: usize = 0;
    const SOL_PENDING: usize = 1;
    const SOL_AUTONOMOUS: usize = 2;
    const SOL_THRESHOLD: usize = 3;
    const SOL_TIME_LOCK: usize = 4;
    const SOL_UPGRADE: usize = 5;
    const SOL_PAUSER: usize = 6;
    const N_SOL: usize = 7;

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
        assert_eq!(ms.config_authority, [0u8; 32], "the fixture is autonomous");
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

    fn sol_fails(r: &SolanaReads) -> Vec<usize> {
        let rules = solana_rules(r, &policy());
        assert_eq!(rules.len(), N_SOL);
        (0..N_SOL)
            .filter(|i| rules[*i].status != Status::Pass)
            .collect()
    }

    #[test]
    fn the_solana_state_today_fails_the_squads_rules() {
        assert_eq!(
            sol_fails(&today_solana()),
            vec![
                SOL_ADMIN_VAULT,
                SOL_AUTONOMOUS,
                SOL_THRESHOLD,
                SOL_TIME_LOCK,
                SOL_UPGRADE
            ]
        );
        // Even with a multisig configured, the admin and authority are single keys.
        let mut r = today_solana();
        r.multisig = compliant_solana().multisig;
        r.vault = compliant_solana().vault;
        r.multisig_state = compliant_solana().multisig_state;
        assert_eq!(sol_fails(&r), vec![SOL_ADMIN_VAULT, SOL_UPGRADE]);
    }

    #[test]
    fn the_compliant_solana_state_passes() {
        assert_eq!(sol_fails(&compliant_solana()), Vec::<usize>::new());
        let mut r = compliant_solana();
        r.multisig_state.as_mut().unwrap().time_lock = 3600;
        assert_eq!(sol_fails(&r), vec![SOL_TIME_LOCK]);
        let mut r = compliant_solana();
        r.multisig_state.as_mut().unwrap().threshold = 1;
        assert_eq!(sol_fails(&r), vec![SOL_THRESHOLD]);
        let mut r = compliant_solana();
        r.upgrade_authority = None;
        assert_eq!(
            sol_fails(&r),
            vec![SOL_UPGRADE],
            "immutable is not the vault"
        );
        let mut r = compliant_solana();
        r.config.pauser = r.config.admin;
        assert_eq!(sol_fails(&r), vec![SOL_PAUSER]);
    }

    #[test]
    fn a_controlled_squads_multisig_fails() {
        // One config_authority key can change members, threshold and time_lock
        // without a vote (Squads v4 instructions/multisig_config.rs).
        let mut r = compliant_solana();
        r.multisig_state.as_mut().unwrap().config_authority =
            pk("DvV45t4mfWKJvUXvFLoEuYgRqzmL1m6DaHbn8ZLw77kX");
        assert_eq!(sol_fails(&r), vec![SOL_AUTONOMOUS]);
        let rules = solana_rules(&r, &policy());
        assert!(rules[SOL_AUTONOMOUS].observed.contains("DvV45t4m"));
    }

    #[test]
    fn a_pending_solana_admin_fails() {
        let mut r = compliant_solana();
        r.config.pending_admin = pk("DvV45t4mfWKJvUXvFLoEuYgRqzmL1m6DaHbn8ZLw77kX");
        assert_eq!(sol_fails(&r), vec![SOL_PENDING]);
    }
}
