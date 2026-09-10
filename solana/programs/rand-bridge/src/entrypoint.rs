//! The BPF entrypoint, compiled out under the `no-entrypoint` feature so
//! other programs can depend on this crate as a library.

use solana_program::entrypoint;

use crate::processor::process_instruction;

entrypoint!(process_instruction);
