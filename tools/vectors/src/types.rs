//! The JSON schema written to `vectors/attestations.json` and
//! `crates/shrugg-core/src/bridge/vectors.json`. Field order on every
//! struct is the serialization order (`serde_json::to_string_pretty`
//! preserves struct-declaration order), so this order IS the file's byte
//! layout; keep it in sync with the brief's schema.

use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Serialize)]
pub struct GuardianEntry {
    pub secret: String,
    pub address: String,
}

#[derive(Serialize)]
pub struct SetEntry {
    pub index: u32,
    pub keys: Vec<String>,
    pub expires_at: u64,
}

#[derive(Serialize)]
pub struct BodyJson {
    pub timestamp: u32,
    pub nonce: u32,
    pub emitter_chain: u16,
    pub emitter_address: String,
    pub sequence: u64,
    pub consistency_level: u8,
}

/// The human-readable mirror of a [`shrugg_core::bridge::Payload`]. Picked
/// by `serde(untagged)` based on which fields are present, so a transfer
/// serializes as `{id, amount, token_address, token_chain, to, to_chain,
/// fee}` and an upgrade as `{id, new_index, keys}`.
#[derive(Serialize)]
#[serde(untagged)]
pub enum PayloadJson {
    Transfer {
        id: u8,
        amount: String,
        token_address: String,
        token_chain: u16,
        to: String,
        to_chain: u16,
        fee: String,
    },
    Upgrade {
        id: u8,
        new_index: u32,
        keys: Vec<String>,
    },
}

#[derive(Serialize)]
pub struct Vector {
    pub name: String,
    pub attestation: String,
    pub digest: String,
    pub verifier_chain: u16,
    pub guardian_set_index: u32,
    pub sets: Vec<SetEntry>,
    pub current_set: u32,
    pub expect: String,
    pub body: BodyJson,
    pub payload: PayloadJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_of: Option<String>,
}

#[derive(Serialize)]
pub struct VectorsFile {
    pub guardians: Vec<GuardianEntry>,
    pub governance_emitter: String,
    pub rand_emitter: String,
    pub emitters: BTreeMap<String, String>,
    pub now: u64,
    pub vectors: Vec<Vector>,
}
