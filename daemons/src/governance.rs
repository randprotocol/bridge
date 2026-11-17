//! Guardian-set rotation: the one governance message the deployed endpoints
//! understand (`spec/ATTESTATION.md` §3.6, payload 2).
//!
//! A rotation is a deliberate act by people, not something a daemon does on
//! seeing an event, so it lives in its own tool (`rand-bridge-gov`). The
//! rules it builds to, and re-checks before printing anything, are the ones
//! every verifier enforces: signed by the CURRENT set, from the governance
//! emitter on chain 1, `new_index == current + 1`, unique non-zero keys. It
//! also holds a set to [`MAX_GUARDIANS`], which only Solana enforces: the EVM
//! endpoints accept 255 keys and take the same attestation first.
//! The body's timestamp, nonce and sequence are advisory — no verifier reads
//! them — but they are part of the digest, so one rotation is one byte string
//! and the same attestation is submitted to every chain.

use anyhow::{anyhow, bail, Result};
use bridge_codec::{
    quorum, Attestation, Body, GuardianSetUpgrade, Payload, CHAIN_RAND, GOVERNANCE_EMITTER,
};

use crate::crypto::{self, GuardianKey};

/// The largest set a rotation may name: the Solana program's `MAX_GUARDIANS`.
/// An endpoint on EVM or Tron would accept more, and Solana would refuse the
/// same attestation. The relayer then stamps burns with a set Solana does not
/// have, so Solana's releases stop until a program upgrade. Held here because
/// this tool is the one step every chain's rotation passes through.
pub const MAX_GUARDIANS: usize = 10;

/// The body of a rotation to `new_keys` as set `current_index + 1`.
pub fn rotation_body(
    current_index: u32,
    new_keys: &[[u8; 20]],
    timestamp: u32,
    nonce: u32,
    sequence: u64,
) -> Result<Body> {
    check_new_keys(new_keys)?;
    let new_index = current_index
        .checked_add(1)
        .ok_or_else(|| anyhow!("guardian set index overflow"))?;
    Ok(Body {
        timestamp,
        nonce,
        emitter_chain: CHAIN_RAND,
        emitter_address: GOVERNANCE_EMITTER,
        sequence,
        // Advisory like the rest; 0 is what the shared rotation vector carries.
        consistency_level: 0,
        payload: Payload::GuardianSetUpgrade(GuardianSetUpgrade {
            new_index,
            keys: new_keys.to_vec(),
        })
        .encode(),
    })
}

fn check_new_keys(keys: &[[u8; 20]]) -> Result<()> {
    if keys.is_empty() || keys.len() > MAX_GUARDIANS {
        bail!(
            "a guardian set has between 1 and {MAX_GUARDIANS} keys (Solana's bound), got {}",
            keys.len()
        );
    }
    for (i, key) in keys.iter().enumerate() {
        if *key == [0u8; 20] {
            bail!("new guardian {i} is the zero address");
        }
        if keys[..i].contains(key) {
            bail!("new guardian {i} repeats an earlier key");
        }
    }
    Ok(())
}

/// Signs `body` with `signers` (keys of the CURRENT set, any order) and
/// assembles the attestation under `current_index`, exactly a quorum, lowest
/// indices first. Refuses a key that is not in `current_set`.
pub fn sign_rotation(
    body: &Body,
    current_index: u32,
    current_set: &[[u8; 20]],
    signers: &[GuardianKey],
) -> Result<Attestation> {
    let mu = crypto::digest(&body.encode());
    let mut indexed = Vec::new();
    for key in signers {
        let index = current_set
            .iter()
            .position(|k| *k == key.address())
            .ok_or_else(|| {
                anyhow!(
                    "signer 0x{} is not in the current guardian set",
                    hex::encode(key.address())
                )
            })?;
        if indexed.iter().any(|(i, _)| *i == index) {
            bail!("guardian {index} was given twice");
        }
        indexed.push((index, key.sign(&mu)?));
    }
    let need = quorum(current_set.len());
    if indexed.len() < need {
        bail!(
            "{} signers, but the current set of {} needs {need}",
            indexed.len(),
            current_set.len()
        );
    }
    indexed.sort_by_key(|(i, _)| *i);
    let attestation = Attestation {
        guardian_set_index: current_index,
        signatures: indexed
            .into_iter()
            .take(need)
            .map(|(i, s)| s.indexed(i as u8))
            .collect(),
        body: body.clone(),
    };
    verify_rotation(&attestation.encode(), current_index, current_set)?;
    Ok(attestation)
}

/// What a verified rotation says.
#[derive(Debug, PartialEq, Eq)]
pub struct Rotation {
    pub digest: [u8; 32],
    pub new_index: u32,
    pub new_keys: Vec<[u8; 20]>,
    pub signer_indices: Vec<u8>,
}

/// Every rule an endpoint applies to a rotation, applied to the bytes that
/// are about to be submitted: run it on the tool's own output, and on any
/// rotation someone else hands you.
pub fn verify_rotation(
    attestation: &[u8],
    current_index: u32,
    current_set: &[[u8; 20]],
) -> Result<Rotation> {
    let decoded =
        Attestation::decode(attestation).map_err(|e| anyhow!("undecodable attestation: {e:?}"))?;
    if decoded.encode() != attestation {
        bail!("attestation is not canonically encoded");
    }
    if decoded.guardian_set_index != current_index {
        bail!(
            "signed by set {}, but a rotation must be signed by the current set {current_index}",
            decoded.guardian_set_index
        );
    }
    if decoded.body.emitter_chain != CHAIN_RAND
        || decoded.body.emitter_address != GOVERNANCE_EMITTER
    {
        bail!("not from the governance emitter");
    }
    let Ok(Payload::GuardianSetUpgrade(upgrade)) = Payload::decode(&decoded.body.payload) else {
        bail!("not a guardian-set upgrade payload");
    };
    if upgrade.new_index != current_index + 1 {
        bail!("new index {} is not current + 1", upgrade.new_index);
    }
    check_new_keys(&upgrade.keys)?;

    let digest = check_signatures(attestation, &decoded, current_set)?;
    Ok(Rotation {
        digest,
        new_index: upgrade.new_index,
        new_keys: upgrade.keys,
        signer_indices: decoded.signatures.iter().map(|s| s.index).collect(),
    })
}

/// The signature rules every verifier applies, on the bytes as given: a quorum of the set
/// (`bridge_codec::check_indices`: indices in range, strictly ascending, at least
/// `n * 2 / 3 + 1` of them), each recovering to the guardian at its index. Returns the digest.
fn check_signatures(
    attestation: &[u8],
    decoded: &Attestation,
    current_set: &[[u8; 20]],
) -> Result<[u8; 32]> {
    bridge_codec::check_indices(&decoded.signatures, current_set.len())
        .map_err(|e| anyhow!("signatures: {e:?}"))?;
    let body_bytes = Attestation::body_bytes(attestation).map_err(|e| anyhow!("{e:?}"))?;
    let digest = crypto::digest(body_bytes);
    for sig in &decoded.signatures {
        let raw = crypto::RawSignature {
            r: sig.r,
            s: sig.s,
            v: sig.v,
        };
        let recovered = crypto::recover(&digest, &raw)?;
        if recovered != current_set[usize::from(sig.index)] {
            bail!(
                "signature {} does not recover to guardian {}",
                sig.index,
                sig.index
            );
        }
    }
    Ok(digest)
}

/// An attestation in words, for the person about to sign something over it (BR-1002): every
/// field of the envelope and the body, and the payload decoded. Says so when it cannot decode.
pub fn describe(attestation: &[u8]) -> Result<String> {
    use std::fmt::Write;
    let a = Attestation::decode(attestation).map_err(|e| anyhow!("undecodable attestation: {e:?}"))?;
    let body_bytes = Attestation::body_bytes(attestation).map_err(|e| anyhow!("{e:?}"))?;
    let mut t = String::new();
    let _ = writeln!(t, "attestation   {} bytes, digest 0x{}", attestation.len(), hex::encode(crypto::digest(body_bytes)));
    let _ = writeln!(
        t,
        "signed by     guardian set {}, {} signature(s), indices {:?}",
        a.guardian_set_index,
        a.signatures.len(),
        a.signatures.iter().map(|s| s.index).collect::<Vec<_>>()
    );
    let b = &a.body;
    let _ = writeln!(t, "timestamp     {}", b.timestamp);
    let _ = writeln!(t, "nonce         {}", b.nonce);
    let _ = writeln!(t, "emitter       chain {} address 0x{}", b.emitter_chain, hex::encode(b.emitter_address));
    let _ = writeln!(t, "sequence      {}", b.sequence);
    let _ = writeln!(t, "consistency   {}", b.consistency_level);
    match Payload::decode(&b.payload) {
        Ok(Payload::GuardianSetUpgrade(u)) => {
            let _ = writeln!(t, "payload       GUARDIAN-SET UPGRADE to set {} with {} key(s)", u.new_index, u.keys.len());
            for (i, k) in u.keys.iter().enumerate() {
                let _ = writeln!(t, "  new [{i}]     0x{}", hex::encode(k));
            }
        }
        Ok(Payload::Transfer(x)) => {
            let _ = writeln!(t, "payload       TRANSFER");
            let amount = |v: Option<u128>| v.map(|n| n.to_string()).unwrap_or_else(|| "above u128".into());
            let _ = writeln!(t, "  amount      {} (8-decimal units), fee {}", amount(x.amount_u128()), amount(x.fee_u128()));
            let _ = writeln!(t, "  token       chain {} address 0x{}", x.token_chain, hex::encode(x.token_address));
            let _ = writeln!(t, "  recipient   chain {} address 0x{}", x.to_chain, hex::encode(x.to));
        }
        Err(e) => {
            let _ = writeln!(t, "payload       UNDECODABLE ({e:?}): 0x{}", hex::encode(&b.payload));
        }
    }
    Ok(t)
}

/// What `verify_for_cosign` found the attestation to be.
#[derive(Debug, PartialEq, Eq)]
pub enum Cosignable {
    Rotation(Rotation),
    /// A deposit: a transfer from a source chain to Rand, carrying the current set's quorum.
    Deposit { digest: [u8; 32], signer_indices: Vec<u8> },
}

impl Cosignable {
    pub fn digest(&self) -> [u8; 32] {
        match self {
            Cosignable::Rotation(r) => r.digest,
            Cosignable::Deposit { digest, .. } => *digest,
        }
    }
}

/// What must hold before a post-quantum key signs over an attestation by hand (BR-1002). A
/// rotation passes every rule of [`verify_rotation`]. Anything else must be a canonical
/// attestation of a transfer to Rand from another chain that already carries a quorum of the
/// current set's signatures, each recovering to its guardian — what Rand itself would check of
/// the classical half. An unsigned body, a body signed by another set, a release, a payload
/// that does not decode: all refused.
pub fn verify_for_cosign(
    attestation: &[u8],
    current_index: u32,
    current_set: &[[u8; 20]],
) -> Result<Cosignable> {
    let decoded =
        Attestation::decode(attestation).map_err(|e| anyhow!("undecodable attestation: {e:?}"))?;
    match Payload::decode(&decoded.body.payload) {
        Ok(Payload::GuardianSetUpgrade(_)) => {
            verify_rotation(attestation, current_index, current_set).map(Cosignable::Rotation)
        }
        Ok(Payload::Transfer(transfer)) => {
            if decoded.encode() != attestation {
                bail!("attestation is not canonically encoded");
            }
            if decoded.guardian_set_index != current_index {
                bail!(
                    "signed by set {}, not the current set {current_index}",
                    decoded.guardian_set_index
                );
            }
            if decoded.body.emitter_chain == CHAIN_RAND || transfer.to_chain != CHAIN_RAND {
                bail!(
                    "a transfer from chain {} to chain {}: only a deposit to Rand is co-signed",
                    decoded.body.emitter_chain,
                    transfer.to_chain
                );
            }
            if transfer.amount_u128() == Some(0) {
                bail!("zero amount");
            }
            let digest = check_signatures(attestation, &decoded, current_set)?;
            Ok(Cosignable::Deposit {
                digest,
                signer_indices: decoded.signatures.iter().map(|s| s.index).collect(),
            })
        }
        Err(e) => bail!("the payload is neither a rotation nor a transfer: {e:?}"),
    }
}

/// `submitGuardianSetUpgrade(bytes)` calldata for the EVM-family endpoints.
pub fn upgrade_calldata(attestation: &[u8]) -> Vec<u8> {
    let mut data = crate::submit::selector("submitGuardianSetUpgrade(bytes)").to_vec();
    data.extend_from_slice(&crate::submit::abi_encode_bytes(attestation));
    data
}
