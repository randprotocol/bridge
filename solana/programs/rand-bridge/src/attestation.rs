//! Guardian attestation verification.
//!
//! This is the Solana half of a three-chain verifier: it must accept and
//! reject exactly what the Rust reference (`randprotocol-core::bridge::verify`)
//! and the Solidity `RandBridge` do, vector for vector. The wire format
//! comes from `bridge-codec`; the hashing and the ECDSA recovery come from
//! the `keccak` and `secp256k1_recover` syscalls, which `solana-program`
//! also implements natively off-chain so this module is testable without
//! the SBF toolchain.
//!
//! Digest `mu = keccak256(keccak256(body_bytes))`; a guardian's address is
//! the last 20 bytes of `keccak256(uncompressed_pubkey[1..])`, i.e. of the
//! 64 bytes `secp256k1_recover` returns.

use bridge_codec::{check_indices, is_low_s, Attestation, Signature};
use solana_program::keccak;
use solana_program::secp256k1_recover::secp256k1_recover;

use crate::error::BridgeError;
use crate::state::GuardianSetAccount;

/// The attestation digest `mu = keccak256(keccak256(body_bytes))`.
pub fn digest(body: &[u8]) -> [u8; 32] {
    let inner = keccak::hashv(&[body]);
    keccak::hashv(&[inner.as_ref()]).to_bytes()
}

/// Recovers the guardian address that produced `sig` over `digest`, or
/// `None` if the recovery id is out of range or the signature is
/// unrecoverable.
///
/// Note that this does *not* check low-s: [`verify`] rejects a high-s
/// signature before it gets here, so that a malleated signature is reported
/// as [`BridgeError::HighS`] rather than as a recovery failure.
pub fn recover_guardian(digest: &[u8; 32], sig: &Signature) -> Option<[u8; 20]> {
    if sig.v > 1 {
        return None;
    }
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(&sig.r);
    rs[32..].copy_from_slice(&sig.s);
    let pubkey = secp256k1_recover(digest, sig.v, &rs).ok()?;
    let hash = keccak::hashv(&[pubkey.to_bytes().as_ref()]).to_bytes();
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Some(address)
}

/// Full envelope check: decode, guardian-set expiry, the index/quorum rule,
/// then per signature low-s, recovery, and identity. Returns the decoded
/// attestation and its digest.
///
/// The order of the checks is part of the cross-chain contract: the same
/// malformed attestation must produce the same error on Rand, on Ethereum,
/// and here.
pub fn verify(
    bytes: &[u8],
    set: &GuardianSetAccount,
    now: u64,
) -> Result<(Attestation, [u8; 32]), BridgeError> {
    let att = Attestation::decode(bytes)?;
    if set.expiration_time != 0 && now > set.expiration_time {
        return Err(BridgeError::GuardianSetExpired);
    }
    check_indices(&att.signatures, set.keys.len())?;
    let d = digest(&att.body.encode());
    for sig in &att.signatures {
        if !is_low_s(&sig.s) {
            return Err(BridgeError::HighS);
        }
        let recovered = recover_guardian(&d, sig).ok_or(BridgeError::BadSignature)?;
        if recovered != set.keys[sig.index as usize] {
            return Err(BridgeError::WrongGuardian);
        }
    }
    Ok((att, d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge_codec::{Body, Payload, Transfer, GOVERNANCE_EMITTER};

    #[test]
    fn keccak_known_answer_and_double_hash() {
        assert_eq!(
            hex_lower(&keccak::hashv(&[b""]).to_bytes()),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        let once = keccak::hashv(&[b"abc"]).to_bytes();
        assert_eq!(digest(b"abc"), keccak::hashv(&[once.as_ref()]).to_bytes());
    }

    /// The governance emitter is pinned as a literal in `bridge-codec`,
    /// which has no hash function of its own; this is the Solana-side
    /// check that the literal really is the hash of the string.
    #[test]
    fn governance_emitter_matches_the_string() {
        assert_eq!(
            keccak::hashv(&[b"rand-bridge-governance"]).to_bytes(),
            GOVERNANCE_EMITTER
        );
    }

    #[test]
    fn recover_rejects_out_of_range_recovery_id() {
        let sig = Signature {
            index: 0,
            r: [1u8; 32],
            s: [2u8; 32],
            v: 2,
        };
        assert_eq!(recover_guardian(&[3u8; 32], &sig), None);
    }

    #[test]
    fn decode_failures_surface_before_anything_else() {
        let set = GuardianSetAccount {
            index: 0,
            keys: vec![[0u8; 20]],
            // An expired set: the decode error must still win, because
            // decoding happens first.
            expiration_time: 1,
        };
        assert_eq!(
            verify(&[2, 0, 0, 0, 0, 0], &set, 1_000).unwrap_err(),
            BridgeError::BadVersion
        );
        assert_eq!(
            verify(&[1, 0, 0, 0, 0, 1, 0], &set, 1_000).unwrap_err(),
            BridgeError::Truncated
        );
    }

    /// Expiry is checked before the index rule: an attestation that is
    /// both under-signed and against an expired set reports the expiry.
    #[test]
    fn expiry_precedes_the_index_rule() {
        let body = Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain: 1,
            emitter_address: [1u8; 32],
            sequence: 0,
            consistency_level: 1,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(1),
                token_address: [2u8; 32],
                token_chain: 2,
                to: [3u8; 32],
                to_chain: 5,
                fee: [0u8; 32],
            })
            .encode(),
        };
        let att = Attestation {
            guardian_set_index: 0,
            signatures: vec![],
            body,
        };
        let keys = vec![[0u8; 20]; 6];
        let live = GuardianSetAccount {
            index: 0,
            keys: keys.clone(),
            expiration_time: 0,
        };
        let expired = GuardianSetAccount {
            index: 0,
            keys,
            expiration_time: 999,
        };
        let bytes = att.encode();
        assert_eq!(
            verify(&bytes, &live, 1_000).unwrap_err(),
            BridgeError::NoQuorum
        );
        assert_eq!(
            verify(&bytes, &expired, 1_000).unwrap_err(),
            BridgeError::GuardianSetExpired
        );
        // A set whose expiry is exactly `now` is still live: the rule is
        // `now > expires_at`.
        let boundary = GuardianSetAccount {
            expiration_time: 1_000,
            ..expired
        };
        assert_eq!(
            verify(&bytes, &boundary, 1_000).unwrap_err(),
            BridgeError::NoQuorum
        );
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
