//! The off-chain half of the Rand bridge (bridge issue #3).
//!
//! - `rand-guardian`: watches the four source endpoints and Rand's burn log,
//!   waits out each chain's consistency level, checks every message against
//!   the signing policy, signs `mu = keccak256(keccak256(body))`, and serves
//!   its signatures over HTTP. One per guardian, each on its own host.
//! - `rand-relayer`: watches the same sources, collects a quorum of guardian
//!   signatures, assembles the attestation and submits it to the chain the
//!   message is addressed to. Permissionless: anyone may run one.

pub mod api;
pub mod config;
pub mod crypto;
pub mod governance;
pub mod guardian;
pub mod message;
pub mod pq;
pub mod pq_gov;
pub mod relayer;
pub mod rpc;
pub mod sources;
pub mod store;
pub mod submit;
