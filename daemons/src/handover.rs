//! Where each endpoint stands in the governance handover (BR-3), and the
//! next step: `rand-bridge-audit --handover`. Read-only.
//!
//! The handover on Ethereum, BSC and Tron (`docs/governance.md` §4) moves the
//! bridge's admin from a key to a timelock in five steps: deploy the timelock,
//! set the pauser, `transferAdmin(timelock)` (the timelock becomes
//! `pendingAdmin`), then the admin multisig schedules `acceptAdmin()` on the
//! timelock and, after its delay, executes it. On Solana the admin moves to a
//! Squads vault in two steps and the upgrade authority follows.
//!
//! `rand-bridge-audit --governance` says whether the end state holds. This
//! says which step an endpoint is at while it does not. A stage of
//! [`Stage::Complete`] here is not a governance PASS: it means the admin
//! moved; the audit judges what it moved to.

use sha3::{Digest, Keccak256};

/// `acceptAdmin()`.
pub const ACCEPT_ADMIN: [u8; 4] = [0x0e, 0x18, 0xb6, 0x81];

fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// The timelock's id of `target.call(data)` with value 0 and no predecessor:
/// OZ `hashOperation` = `keccak256(abi.encode(target, 0, data, 0, salt))`.
pub fn operation_id(target: &[u8; 20], data: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    let mut enc = Vec::with_capacity(32 * 7 + data.len());
    enc.extend_from_slice(&[0u8; 12]);
    enc.extend_from_slice(target);
    enc.extend_from_slice(&[0u8; 32]); // value
    let mut offset = [0u8; 32];
    offset[31] = 0xa0; // five head words
    enc.extend_from_slice(&offset);
    enc.extend_from_slice(&[0u8; 32]); // predecessor
    enc.extend_from_slice(salt);
    let mut len = [0u8; 32];
    len[24..].copy_from_slice(&(data.len() as u64).to_be_bytes());
    enc.extend_from_slice(&len);
    enc.extend_from_slice(data);
    enc.resize(enc.len() + (32 - data.len() % 32) % 32, 0);
    keccak(&enc)
}

/// A timelock operation, from `getTimestamp(id)` and the chain's clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Never scheduled under this id, or cancelled.
    Unset,
    /// Scheduled; executable from `ready_at` (unix seconds).
    Waiting { ready_at: u64 },
    /// Scheduled and executable since `ready_at`.
    Ready { ready_at: u64 },
    /// Executed.
    Done,
}

/// OZ `TimelockController`: timestamp 0 is unset, 1 is done, anything else is
/// when the operation becomes ready.
pub fn operation(timestamp: u128, now: u64) -> Operation {
    match timestamp {
        0 => Operation::Unset,
        1 => Operation::Done,
        t if t > u128::from(now) => Operation::Waiting { ready_at: u64::try_from(t).unwrap_or(u64::MAX) },
        t => Operation::Ready { ready_at: t as u64 },
    }
}

/// What was read from one EVM or Tron endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmHandover {
    pub admin: [u8; 20],
    pub admin_has_code: bool,
    /// Zero when no transfer is under way.
    pub pending_admin: [u8; 20],
    pub pending_has_code: bool,
    /// The `acceptAdmin()` operation on the pending admin, when that is a contract that
    /// answered `getTimestamp`; `None` when it was not asked or did not answer.
    pub accept: Option<Operation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// The admin is a key and no transfer is under way.
    NotStarted,
    /// `transferAdmin` ran: a contract is `pendingAdmin`; the accept is not scheduled.
    Transferred,
    /// The accept is scheduled and waiting out the delay.
    Scheduled,
    /// The accept is executable now. Until it is executed the old key is still admin.
    Executable,
    /// The admin is a contract and nothing is pending.
    Complete,
    /// A state the handover does not pass through; the text says what.
    Unexpected,
}

impl Stage {
    pub fn label(self) -> &'static str {
        match self {
            Stage::NotStarted => "NOT STARTED",
            Stage::Transferred => "TRANSFERRED, ACCEPT NOT SCHEDULED",
            Stage::Scheduled => "ACCEPT SCHEDULED, WAITING",
            Stage::Executable => "ACCEPT EXECUTABLE NOW",
            Stage::Complete => "ADMIN MOVED",
            Stage::Unexpected => "UNEXPECTED",
        }
    }
}

/// The stage of an EVM or Tron endpoint, and what to do next. `tron`: which
/// commands the text names.
pub fn evm_stage(r: &EvmHandover, tron: bool) -> (Stage, String) {
    let pending = r.pending_admin != [0u8; 20];
    let (schedule, execute) = if tron {
        (
            "node deploy/tron-ops.js timelock-schedule-accept <timelock> --from <admin multisig account>",
            "node deploy/tron-ops.js timelock-execute-accept <timelock> --from <admin multisig account>",
        )
    } else {
        (
            "the admin Safe signs deploy/governance/<chainid>-schedule-accept.json (Governance.s.sol acceptProposal())",
            "the admin Safe signs deploy/governance/<chainid>-execute-accept.json",
        )
    };
    match (r.admin_has_code, pending, r.pending_has_code, r.accept) {
        (true, false, _, _) => (
            Stage::Complete,
            "the admin is a contract and nothing is pending. Run --governance: it judges whether that \
             contract is the pinned timelock under a multisig."
                .into(),
        ),
        (false, false, _, _) => (
            Stage::NotStarted,
            "the admin is a single key. Next: docs/governance.md §4 steps 1-3 (deploy the timelock, set the \
             pauser, transferAdmin to the timelock)."
                .into(),
        ),
        (_, true, false, _) => (
            Stage::Unexpected,
            "pendingAdmin is an account without code, so a key could accept the admin role. Unless that is \
             intended, the current admin cancels with transferAdmin(0)."
                .into(),
        ),
        (true, true, true, _) => (
            Stage::Unexpected,
            "the admin is already a contract and a further transfer is pending. Check that it was announced."
                .into(),
        ),
        (false, true, true, Some(Operation::Unset)) => (
            Stage::Transferred,
            format!(
                "the timelock is pendingAdmin; acceptAdmin() is not scheduled under this salt. The single key \
                 is still admin. Next (step 4): {schedule}."
            ),
        ),
        (false, true, true, Some(Operation::Waiting { ready_at })) => (
            Stage::Scheduled,
            format!(
                "acceptAdmin() is scheduled and executable from unix time {ready_at}. The single key is still \
                 admin until then. Next (step 5), after that time: {execute}."
            ),
        ),
        (false, true, true, Some(Operation::Ready { ready_at })) => (
            Stage::Executable,
            format!(
                "acceptAdmin() has been executable since unix time {ready_at} and has not been executed. The \
                 single key is still admin. Next (step 5): {execute}."
            ),
        ),
        (false, true, true, Some(Operation::Done)) => (
            Stage::Unexpected,
            "the timelock reports acceptAdmin() executed, yet it is still only pendingAdmin: a second \
             transferAdmin followed the accept, or this is another salt's operation. Read the bridge's \
             AdminTransferStarted / AdminTransferred events."
                .into(),
        ),
        (false, true, true, None) => (
            Stage::Unexpected,
            "pendingAdmin is a contract that did not answer getTimestamp: it may not be a timelock. \
             handover() and transfer-admin refuse such a target; check how it got there."
                .into(),
        ),
    }
}

/// What was read from the Solana program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaHandover {
    pub admin: [u8; 32],
    /// The default key when no transfer is under way.
    pub pending_admin: [u8; 32],
    /// `None`: the program is not upgradeable.
    pub upgrade_authority: Option<[u8; 32]>,
    /// The Squads vault of `[governance].solana_multisig`, when configured.
    pub vault: Option<[u8; 32]>,
}

pub fn solana_stage(r: &SolanaHandover) -> (Stage, String) {
    let Some(vault) = r.vault else {
        return (
            Stage::NotStarted,
            "no [governance].solana_multisig is configured, so there is no vault to hand over to. Create \
             the Squads v4 multisig (docs/governance.md §2) and set it."
                .into(),
        );
    };
    let pending = r.pending_admin != [0u8; 32];
    let authority_moved = r.upgrade_authority.is_none_or(|a| a == vault);
    if r.admin == vault && !pending {
        return if authority_moved {
            (
                Stage::Complete,
                "the admin and the upgrade authority are the Squads vault. Run --governance: it judges the \
                 multisig's threshold, time lock and config authority."
                    .into(),
            )
        } else {
            (
                Stage::Transferred,
                "the admin is the Squads vault; the upgrade authority is still another key, which can \
                 replace the program. Next: rand-bridge-cli set-upgrade-authority (docs/governance.md §4, \
                 Solana step 2; irreversible)."
                    .into(),
            )
        };
    }
    if r.admin != vault && authority_moved && r.upgrade_authority.is_some() {
        return (
            Stage::Unexpected,
            "the upgrade authority is the vault but the admin is not: set-upgrade-authority refuses that \
             order. Check how it got there."
                .into(),
        );
    }
    if pending && r.pending_admin == vault {
        return (
            Stage::Scheduled,
            "transfer-admin ran: the vault is pending_admin and a single key is still admin. Next: the \
             Squads members approve and, after the time lock, execute the AcceptAdmin vault transaction \
             (rand-bridge-cli --as <vault> accept-admin prints it)."
                .into(),
        );
    }
    if pending {
        return (
            Stage::Unexpected,
            "pending_admin is set to a key that is not the configured vault. Unless that is intended, the \
             admin starts the transfer again with the vault."
                .into(),
        );
    }
    (
        Stage::NotStarted,
        "the admin is a single key. Next: rand-bridge-cli transfer-admin --to <Squads vault> \
         (docs/governance.md §4, Solana step 1)."
            .into(),
    )
}
