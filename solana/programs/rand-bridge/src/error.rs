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
    #[error("amount overflow")]
    AmountOverflow,
    /// An address argument was all zeroes.
    #[error("zero address")]
    ZeroAddress,
}

impl BridgeError {
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
        use BridgeError::*;
        const ALL: &[BridgeError] = &[
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
        ];
        ALL.iter().copied().find(|e| e.code() == code)
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

    #[test]
    fn codes_are_stable_and_round_trip() {
        assert_eq!(BridgeError::BadVersion.code(), 1);
        assert_eq!(BridgeError::Truncated.code(), 2);
        assert_eq!(BridgeError::ZeroAddress.code(), 34);
        for code in 1..=34u32 {
            let e = BridgeError::from_code(code).expect("every code decodes");
            assert_eq!(e.code(), code);
        }
        assert_eq!(BridgeError::from_code(0), None);
        assert_eq!(BridgeError::from_code(35), None);
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
