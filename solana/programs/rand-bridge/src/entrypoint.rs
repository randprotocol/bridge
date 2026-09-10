//! The BPF entrypoint, compiled out under the `no-entrypoint` feature so
//! other programs can depend on this crate as a library — and so
//! `solana-program-test`, which links the processor natively, does not
//! collide with it.

use solana_program::entrypoint;

use crate::processor::process_instruction;

entrypoint!(process_instruction);
