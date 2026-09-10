//! The program's instruction set.
//!
//! Deliberately empty for now: the instruction encoding lands with the
//! processor, in the task that implements `Initialize`, `SetToken`,
//! `Lock`, `Release`, `GuardianSetUpgrade`, `Pause`, `Unpause`,
//! `TransferAdmin`, and `AcceptAdmin`.

/// A decoded instruction for the bridge program. No variants yet; the
/// processor rejects every instruction until they land.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeInstruction {}
