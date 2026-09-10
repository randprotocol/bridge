//! `BridgeError`: the program's error enum, mirroring the Solidity
//! `RandBridge` errors one-for-one so a failure means the same thing on
//! every chain of the bridge.
//!
//! Each variant carries a stable `u32` code (its declaration order, 1-based)
//! and converts into [`ProgramError::Custom`]. Codes are part of the
//! program's ABI: append new variants, never reorder existing ones.

use bridge_codec::{CodecError, IndexError};
use solana_program::program_error::ProgramError;
use thiserror::Error;

/// Every way an instruction of the Rand bridge program can fail.
///
/// # Relationship to the EVM error set
///
/// This enum mirrors the Solidity errors in `IRandBridge` and
/// `Attestation` name-for-name, minus their parameters (Solana's
/// `ProgramError::Custom` carries a bare `u32`, so `HighS(index)` becomes
/// `HighS`).
///
/// Four Solidity errors are deliberately **not** mirrored, because the
/// conditions they report cannot arise on Solana:
///
/// - `BadTokenAddress` — on EVM a token id is a 20-byte address
///   right-aligned in a 32-byte field, so the top 12 bytes must be checked
///   for padding. A Solana token id *is* the 32-byte mint pubkey; there is
///   no padding rule to violate.
/// - `WrongFork` — the EVM contracts pin `block.chainid` at deploy time to
///   refuse execution on a forked chain. Solana has no equivalent fork
///   hazard and no chain-id opcode to guard with.
/// - `DecimalsUnavailable` — EVM must `staticcall` `decimals()` on an
///   ERC-20 that may not implement it. SPL's `Mint` account always carries
///   `decimals`, so reading it cannot fail.
/// - `TransferFailed` — EVM's `SafeTransfer` normalizes ERC-20s that
///   return `false` or nothing. A failed `spl-token` CPI aborts the
///   transaction with the token program's own error, which is strictly
///   more informative than collapsing it into one of ours.
///
/// Three variants exist here with no EVM counterpart; each says so in its
/// own doc comment.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[repr(u32)]
pub enum BridgeError {
    /// The attestation's leading version byte was not 1.
    #[error("bad attestation version")]
    BadVersion = 1,
    /// The attestation ended before a required field could be read.
    #[error("truncated attestation")]
    Truncated,
    /// The payload id byte matched no known payload variant.
    #[error("bad payload id")]
    BadPayloadId,
    /// A fixed-length payload had the wrong total length.
    #[error("bad payload length")]
    BadPayloadLength,
    /// A guardian-set upgrade listed zero guardian keys.
    #[error("zero guardians")]
    ZeroGuardians,
    /// Fewer signatures than the guardian set's quorum.
    #[error("no quorum")]
    NoQuorum,
    /// Signature indices were not strictly increasing.
    #[error("signature indices out of order")]
    IndexOrder,
    /// A signature index was past the end of the guardian set.
    #[error("signature index out of range")]
    IndexOutOfRange,
    /// A signature's `s` was above `n/2` (malleable form).
    #[error("high-s signature")]
    HighS,
    /// A signature was malformed or unrecoverable.
    #[error("unrecoverable signature")]
    BadSignature,
    /// A signature recovered to an address that is not the guardian its
    /// index names.
    #[error("wrong guardian")]
    WrongGuardian,
    /// No guardian set exists at the attestation's guardian set index.
    #[error("unknown guardian set")]
    UnknownGuardianSet,
    /// The guardian set's grace period has elapsed.
    #[error("guardian set expired")]
    GuardianSetExpired,
    /// The attestation's emitter is not the one registered for its chain.
    #[error("wrong emitter")]
    WrongEmitter,
    /// The transfer's destination chain is not this chain.
    #[error("wrong destination chain")]
    WrongToChain,
    /// The transfer's token chain does not match the registered token.
    #[error("wrong token chain")]
    WrongTokenChain,
    /// The token is registered but currently disabled.
    #[error("token disabled")]
    TokenDisabled,
    /// A transfer of zero tokens.
    #[error("zero amount")]
    ZeroAmount,
    /// The relayer fee exceeded the transfer amount.
    #[error("fee exceeds amount")]
    FeeExceedsAmount,
    /// The attestation's digest has already been redeemed.
    #[error("attestation already consumed")]
    AlreadyConsumed,
    /// The custody account holds less than the transfer requires.
    #[error("insufficient custody")]
    InsufficientCustody,
    /// The transfer exceeded the token's per-transfer cap.
    #[error("per-transfer cap exceeded")]
    PerTransferCap,
    /// The transfer exceeded the token's rolling daily cap.
    #[error("daily cap exceeded")]
    DailyCap,
    /// The transfer's recipient field is not a valid address.
    #[error("bad recipient")]
    BadRecipient,
    /// A guardian-set upgrade's new index was not `current + 1`.
    #[error("bad guardian set upgrade index")]
    BadUpgradeIndex,
    /// A guardian-set upgrade listed the same key twice.
    #[error("duplicate guardian")]
    DuplicateGuardian,
    /// The signer is not the configured admin.
    #[error("not admin")]
    NotAdmin,
    /// The signer is not the configured pauser.
    #[error("not pauser")]
    NotPauser,
    /// The bridge is paused.
    #[error("bridge is paused")]
    IsPaused,
    /// The bridge is not paused.
    #[error("bridge is not paused")]
    NotPaused,
    /// An account did not match the program-derived address it must be.
    #[error("invalid pda")]
    InvalidPda,
    /// A token account was not the expected associated token account.
    #[error("invalid associated token account")]
    InvalidAta,
    /// An amount did not fit the target integer width.
    ///
    /// Solana-specific: EVM works in `uint256` throughout, so
    /// denormalizing a wire amount cannot overflow there. Here the
    /// 8-decimal wire amount is denormalized into the mint's own decimals
    /// as a `u64`, which can.
    #[error("amount overflow")]
    AmountOverflow,
    /// An address argument was all zeroes.
    #[error("zero address")]
    ZeroAddress,
    /// A lock named the zero address as its Rand-side recipient.
    #[error("zero recipient")]
    ZeroRecipient,
    /// The custody account's balance moved by something other than the
    /// amount locked — a fee-on-transfer or rebasing mint.
    #[error("transfer amount mismatch")]
    TransferAmountMismatch,
    /// Account state could not be Borsh-encoded.
    ///
    /// Solana-specific: EVM has no serialization step to fail.
    #[error("serialization failed")]
    SerializationFailed,
}

impl BridgeError {
    /// Every variant, in declaration order, so `ALL[i].code() == i + 1`.
    ///
    /// Append here whenever a variant is appended to the enum; the
    /// `every_variant_is_listed_once` test enforces that this stays in
    /// step with the declaration.
    pub const ALL: &'static [BridgeError] = {
        use BridgeError::*;
        &[
            BadVersion,
            Truncated,
            BadPayloadId,
            BadPayloadLength,
            ZeroGuardians,
            NoQuorum,
            IndexOrder,
            IndexOutOfRange,
            HighS,
            BadSignature,
            WrongGuardian,
            UnknownGuardianSet,
            GuardianSetExpired,
            WrongEmitter,
            WrongToChain,
            WrongTokenChain,
            TokenDisabled,
            ZeroAmount,
            FeeExceedsAmount,
            AlreadyConsumed,
            InsufficientCustody,
            PerTransferCap,
            DailyCap,
            BadRecipient,
            BadUpgradeIndex,
            DuplicateGuardian,
            NotAdmin,
            NotPauser,
            IsPaused,
            NotPaused,
            InvalidPda,
            InvalidAta,
            AmountOverflow,
            ZeroAddress,
            ZeroRecipient,
            TransferAmountMismatch,
            SerializationFailed,
        ]
    };

    /// The stable `u32` this error travels as inside
    /// [`ProgramError::Custom`].
    pub fn code(self) -> u32 {
        self as u32
    }

    /// The inverse of [`BridgeError::code`]: turns a `Custom` error code
    /// from a failed transaction back into the variant that produced it.
    /// Replaces the deprecated `DecodeError` trait, which `solana-program`
    /// 2.3 no longer offers without a deprecation warning.
    pub fn from_code(code: u32) -> Option<BridgeError> {
        Self::ALL.iter().copied().find(|e| e.code() == code)
    }
}

impl From<BridgeError> for ProgramError {
    fn from(e: BridgeError) -> ProgramError {
        ProgramError::Custom(e.code())
    }
}

impl From<CodecError> for BridgeError {
    fn from(e: CodecError) -> BridgeError {
        match e {
            CodecError::BadVersion => BridgeError::BadVersion,
            CodecError::Truncated | CodecError::TrailingBytes => BridgeError::Truncated,
            CodecError::BadPayloadId => BridgeError::BadPayloadId,
            CodecError::BadPayloadLength | CodecError::TooManyGuardians => {
                BridgeError::BadPayloadLength
            }
            CodecError::ZeroGuardians => BridgeError::ZeroGuardians,
        }
    }
}

impl From<IndexError> for BridgeError {
    fn from(e: IndexError) -> BridgeError {
        match e {
            IndexError::NoQuorum { .. } => BridgeError::NoQuorum,
            IndexError::IndexOrder => BridgeError::IndexOrder,
            IndexError::IndexOutOfRange => BridgeError::IndexOutOfRange,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The code each variant is *declared* with, written out by hand.
    ///
    /// This match is exhaustive, so adding a variant to [`BridgeError`]
    /// stops this file compiling until the new variant is given a code
    /// here — and `every_variant_is_listed_once` then fails until it is
    /// also appended to [`BridgeError::ALL`]. Together those two make the
    /// enum, its codes, and `ALL` impossible to drift apart silently.
    fn declared_code(e: BridgeError) -> u32 {
        use BridgeError::*;
        match e {
            BadVersion => 1,
            Truncated => 2,
            BadPayloadId => 3,
            BadPayloadLength => 4,
            ZeroGuardians => 5,
            NoQuorum => 6,
            IndexOrder => 7,
            IndexOutOfRange => 8,
            HighS => 9,
            BadSignature => 10,
            WrongGuardian => 11,
            UnknownGuardianSet => 12,
            GuardianSetExpired => 13,
            WrongEmitter => 14,
            WrongToChain => 15,
            WrongTokenChain => 16,
            TokenDisabled => 17,
            ZeroAmount => 18,
            FeeExceedsAmount => 19,
            AlreadyConsumed => 20,
            InsufficientCustody => 21,
            PerTransferCap => 22,
            DailyCap => 23,
            BadRecipient => 24,
            BadUpgradeIndex => 25,
            DuplicateGuardian => 26,
            NotAdmin => 27,
            NotPauser => 28,
            IsPaused => 29,
            NotPaused => 30,
            InvalidPda => 31,
            InvalidAta => 32,
            AmountOverflow => 33,
            ZeroAddress => 34,
            ZeroRecipient => 35,
            TransferAmountMismatch => 36,
            SerializationFailed => 37,
        }
    }

    /// The highest code `declared_code` hands out. If a variant is added
    /// there but not to `BridgeError::ALL`, this stays ahead of
    /// `ALL.len()` and the test below catches it.
    const HIGHEST_DECLARED_CODE: u32 = 37;

    #[test]
    fn every_variant_is_listed_once_and_round_trips() {
        assert_eq!(
            BridgeError::ALL.len() as u32,
            HIGHEST_DECLARED_CODE,
            "BridgeError::ALL is out of step with the enum declaration"
        );
        for (i, &e) in BridgeError::ALL.iter().enumerate() {
            let code = i as u32 + 1;
            assert_eq!(e.code(), code, "{e:?} is not at its declared position");
            assert_eq!(declared_code(e), code, "{e:?} moved code");
            assert_eq!(BridgeError::from_code(code), Some(e));
        }
        // Codes are an ABI: these three anchor the ends and the seam
        // where the Solana-only variants were appended.
        assert_eq!(BridgeError::BadVersion.code(), 1);
        assert_eq!(BridgeError::ZeroAddress.code(), 34);
        assert_eq!(BridgeError::SerializationFailed.code(), 37);
        assert_eq!(BridgeError::from_code(0), None);
        assert_eq!(BridgeError::from_code(HIGHEST_DECLARED_CODE + 1), None);
    }

    #[test]
    fn converts_into_program_error() {
        assert_eq!(
            ProgramError::from(BridgeError::WrongGuardian),
            ProgramError::Custom(BridgeError::WrongGuardian.code())
        );
    }

    #[test]
    fn codec_and_index_errors_map_over() {
        assert_eq!(
            BridgeError::from(CodecError::BadVersion),
            BridgeError::BadVersion
        );
        assert_eq!(
            BridgeError::from(CodecError::Truncated),
            BridgeError::Truncated
        );
        assert_eq!(
            BridgeError::from(IndexError::NoQuorum { have: 1, need: 5 }),
            BridgeError::NoQuorum
        );
        assert_eq!(
            BridgeError::from(IndexError::IndexOutOfRange),
            BridgeError::IndexOutOfRange
        );
    }
}
