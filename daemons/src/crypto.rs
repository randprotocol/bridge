//! The guardian's signature: secp256k1 over `mu = keccak256(keccak256(body))`,
//! low-s, recovery id 0 or 1 (spec/ATTESTATION.md §3.3). Everything here is
//! pinned against the shared vectors in `tests/vectors.rs`.

use anyhow::{anyhow, bail, Result};
use bridge_codec::{is_low_s, Signature};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// `mu`: what a guardian signs and what every verifier recovers against.
pub fn digest(body: &[u8]) -> [u8; 32] {
    keccak256(&keccak256(body))
}

/// The 20-byte guardian address of a public key: the low 20 bytes of the
/// keccak of its uncompressed form, like an Ethereum address.
pub fn address_of(key: &VerifyingKey) -> [u8; 20] {
    let point = key.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    hash[12..].try_into().expect("20 bytes")
}

/// A guardian's signing key. Never printed, never serialised.
pub struct GuardianKey {
    key: SigningKey,
    address: [u8; 20],
}

impl GuardianKey {
    /// `0x` + 64 hex, or 64 hex.
    pub fn from_hex(secret: &str) -> Result<GuardianKey> {
        let bytes = hex::decode(secret.trim().trim_start_matches("0x"))
            .map_err(|_| anyhow!("guardian key is not hex"))?;
        if bytes.len() != 32 {
            bail!("guardian key must be 32 bytes");
        }
        let key = SigningKey::from_slice(&bytes)
            .map_err(|_| anyhow!("guardian key is not a valid scalar"))?;
        let address = address_of(key.verifying_key());
        Ok(GuardianKey { key, address })
    }

    pub fn address(&self) -> [u8; 20] {
        self.address
    }

    /// Signs `mu`. k256 normalises to low-s itself and adjusts the recovery
    /// id with it; both are asserted rather than assumed, because a high-s
    /// signature is refused by every verifier.
    pub fn sign(&self, mu: &[u8; 32]) -> Result<RawSignature> {
        let raw = sign_recoverable(&self.key, mu)?;
        if recover(mu, &raw)? != self.address {
            bail!("own signature does not recover to own address");
        }
        Ok(raw)
    }
}

/// A low-s recoverable signature over a 32-byte prehash, recovery id 0 or 1.
/// k256 normalises `s` itself; both properties are asserted rather than
/// assumed, because every verifier (and EIP-2) refuses the alternative.
pub fn sign_recoverable(key: &SigningKey, prehash: &[u8; 32]) -> Result<RawSignature> {
    let (sig, recid) = key
        .sign_prehash_recoverable(prehash)
        .map_err(|e| anyhow!("signing failed: {e}"))?;
    let (sig, recid) = match sig.normalize_s() {
        Some(low) => (
            low,
            RecoveryId::from_byte(recid.to_byte() ^ 1).expect("0 or 1"),
        ),
        None => (sig, recid),
    };
    let bytes = sig.to_bytes();
    let raw = RawSignature {
        r: bytes[..32].try_into().expect("32"),
        s: bytes[32..].try_into().expect("32"),
        v: recid.to_byte(),
    };
    if raw.v > 1 || !is_low_s(&raw.s) {
        bail!("produced a signature no verifier would accept");
    }
    Ok(raw)
}

/// `r || s || v` without a guardian index: the index depends on the set an
/// attestation is assembled under, the signature does not (`mu` covers the
/// body only), so one signature serves every set its key belongs to.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RawSignature {
    #[serde(with = "hex32")]
    pub r: [u8; 32],
    #[serde(with = "hex32")]
    pub s: [u8; 32],
    pub v: u8,
}

impl RawSignature {
    pub fn indexed(&self, index: u8) -> Signature {
        Signature {
            index,
            r: self.r,
            s: self.s,
            v: self.v,
        }
    }
}

/// The guardian address a signature over `mu` recovers to, under exactly the
/// rules the on-chain verifiers apply.
pub fn recover(mu: &[u8; 32], sig: &RawSignature) -> Result<[u8; 20]> {
    if sig.v > 1 {
        bail!("recovery id {} is not 0 or 1", sig.v);
    }
    if !is_low_s(&sig.s) {
        bail!("high-s signature");
    }
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&sig.r);
    bytes[32..].copy_from_slice(&sig.s);
    let parsed = K256Signature::from_slice(&bytes).map_err(|_| anyhow!("malformed signature"))?;
    let recid = RecoveryId::from_byte(sig.v).expect("checked above");
    let key = VerifyingKey::recover_from_prehash(mu, &parsed, recid)
        .map_err(|_| anyhow!("unrecoverable signature"))?;
    Ok(address_of(&key))
}

pub mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}
