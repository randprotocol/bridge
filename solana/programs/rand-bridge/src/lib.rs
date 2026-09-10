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

// The program's on-chain address, as `id()` / `check_id()` / `ID`.
//
// A vanity key with no known secret: base58 `RandBr1dge` followed by
// `1`s, which decodes to a valid 32-byte pubkey. A real deployment
// re-declares this with its own keypair before `cargo build-sbf`; the
// tests and the PDA derivations only need *a* fixed id, and a readable
// one keeps the derived addresses reproducible.
solana_program::declare_id!("RandBr1dge111111111111111111111111111111111");

pub mod attestation;
pub mod error;
pub mod instruction;
pub mod processor;
pub mod state;
