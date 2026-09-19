//! A bridge message as a daemon sees it, and the guardian's signing policy.
//!
//! A guardian signs a body only if the chain it is addressed to would accept
//! it (bridge issue #3): a signature over a body some verifier refuses is at
//! best wasted and at worst a transfer stuck half way. The rules mirror
//! `docs/architecture.md` §11; they are re-checked on-chain, so an omission
//! here costs liveness, never safety.

use anyhow::{bail, Result};
use bridge_codec::{
    Body, Payload, CHAIN_BSC, CHAIN_ETHEREUM, CHAIN_RAND, CHAIN_SOLANA, CHAIN_TRON,
};
use serde::{Deserialize, Serialize};

use crate::crypto;

/// One outbound message read off a chain at that chain's consistency level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observed {
    pub emitter_chain: u16,
    pub sequence: u64,
    /// The wire body, byte for byte what gets hashed.
    #[serde(with = "hex_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "crypto::hex32")]
    pub digest: [u8; 32],
}

impl Observed {
    pub fn new(body: Vec<u8>) -> Result<Observed> {
        let decoded =
            Body::decode(&body).map_err(|e| anyhow::anyhow!("undecodable body: {e:?}"))?;
        // Canonical or nothing: the digest is over the wire bytes, and a body
        // that does not re-encode to itself would hash differently on the
        // verifiers that re-encode (Solana).
        if decoded.encode() != body {
            bail!("body is not canonically encoded");
        }
        Ok(Observed {
            emitter_chain: decoded.emitter_chain,
            sequence: decoded.sequence,
            digest: crypto::digest(&body),
            body,
        })
    }

    pub fn decoded(&self) -> Body {
        Body::decode(&self.body).expect("checked in new")
    }

    /// Where this message is going: the payload's `to_chain`.
    pub fn to_chain(&self) -> Option<u16> {
        match Payload::decode(&self.decoded().payload) {
            Ok(Payload::Transfer(t)) => Some(t.to_chain),
            _ => None,
        }
    }
}

/// The emitters a deployment recognises: the Rand burn emitter and one
/// endpoint per source chain.
#[derive(Clone, Debug, Default)]
pub struct Emitters {
    pub rand: [u8; 32],
    /// `(bridge chain id, 32-byte emitter)` for chains 2..=5.
    pub endpoints: Vec<(u16, [u8; 32])>,
}

impl Emitters {
    fn endpoint(&self, chain: u16) -> Option<&[u8; 32]> {
        self.endpoints
            .iter()
            .find(|(c, _)| *c == chain)
            .map(|(_, e)| e)
    }
}

fn is_evm_family(chain: u16) -> bool {
    matches!(chain, CHAIN_ETHEREUM | CHAIN_BSC | CHAIN_TRON)
}

fn is_endpoint_chain(chain: u16) -> bool {
    is_evm_family(chain) || chain == CHAIN_SOLANA
}

/// Left-padded 20-byte form: the upper 12 bytes must be zero.
fn is_evm_padded(word: &[u8; 32]) -> bool {
    word[..12].iter().all(|b| *b == 0)
}

/// Whether a guardian should sign `body`. Transfers only: a guardian-set
/// rotation is a governance act, signed by a separate, deliberate procedure
/// and never by a daemon watching a chain.
pub fn check_signable(body: &Body, emitters: &Emitters) -> Result<()> {
    let transfer = match Payload::decode(&body.payload) {
        Ok(Payload::Transfer(t)) => t,
        Ok(Payload::GuardianSetUpgrade(_)) => bail!("rotations are not signed by the daemon"),
        Err(e) => bail!("undecodable payload: {e:?}"),
    };
    let Some(amount) = transfer.amount_u128() else {
        bail!("amount above u128")
    };
    let Some(fee) = transfer.fee_u128() else {
        bail!("fee above u128")
    };
    if amount == 0 {
        bail!("zero amount");
    }
    if amount > u128::from(u64::MAX) {
        bail!("amount above u64: a Rand note could not hold it");
    }
    if fee > amount {
        bail!("fee exceeds amount");
    }
    if transfer.to == [0u8; 32] {
        bail!("zero recipient");
    }

    if body.emitter_chain == CHAIN_RAND {
        // A burn on Rand, released on the token's home chain.
        if body.emitter_address != emitters.rand {
            bail!("not the Rand burn emitter");
        }
        if !is_endpoint_chain(transfer.to_chain) {
            bail!("burn addressed to chain {}", transfer.to_chain);
        }
        if transfer.token_chain != transfer.to_chain {
            bail!("a bridged token is released on its home chain only");
        }
        if is_evm_family(transfer.to_chain)
            && !(is_evm_padded(&transfer.to) && is_evm_padded(&transfer.token_address))
        {
            bail!("EVM-family address with a non-zero upper 12 bytes");
        }
        Ok(())
    } else {
        // A lock on a source chain, minted on Rand.
        if !is_endpoint_chain(body.emitter_chain) {
            bail!("unknown emitter chain {}", body.emitter_chain);
        }
        match emitters.endpoint(body.emitter_chain) {
            Some(e) if *e == body.emitter_address => {}
            _ => bail!("not the registered emitter of chain {}", body.emitter_chain),
        }
        if transfer.to_chain != CHAIN_RAND {
            bail!("lock addressed to chain {}, not Rand", transfer.to_chain);
        }
        if transfer.token_chain != body.emitter_chain {
            bail!("an endpoint locks its own chain's tokens only");
        }
        if is_evm_family(body.emitter_chain) && !is_evm_padded(&transfer.token_address) {
            bail!("EVM-family token address with a non-zero upper 12 bytes");
        }
        Ok(())
    }
}

pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}
