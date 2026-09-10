//! `rand_bridge`: the Solana side of the Rand token bridge.
//!
//! Guardians attest to Rand-side burns; this program verifies a quorum of
//! guardian signatures over an attestation and releases SPL tokens from
//! custody, and mirrors the reverse direction by locking tokens and posting
//! a message body for the guardians to sign.
//!
//! The attestation wire format lives in the dependency-free `bridge-codec`
//! crate, shared byte-for-byte with the Solidity contracts and the Rand
//! fullnode.

#[cfg(not(feature = "no-entrypoint"))]
pub mod entrypoint;

pub mod attestation;
pub mod error;
pub mod instruction;
pub mod processor;
pub mod state;
