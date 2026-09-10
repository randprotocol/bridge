# `rand_bridge` (Solana)

The Solana endpoint of the Rand token bridge: a native `solana-program`
crate (no Anchor) that locks SPL tokens into custody and releases them
against guardian-signed attestations from Rand.

```
programs/rand-bridge/src/
  lib.rs           crate root and `declare_id!`
  entrypoint.rs    the BPF entrypoint (off under `no-entrypoint`)
  instruction.rs   `BridgeInstruction` + client-side builders
  processor.rs     the rules of design Section 5.1
  state.rs         accounts and PDA derivations
  attestation.rs   digest, secp256k1 recovery, quorum
  error.rs         `BridgeError`, mirroring the Solidity error set
programs/rand-bridge/tests/
  attestation.rs   the shared vectors against the verifier
  bridge.rs        end-to-end `solana-program-test` coverage
```

## Testing

```
cargo test -p rand-bridge
cargo clippy --all-targets
```

`solana-program-test` compiles the program **natively** and runs it
against a real bank, the real SPL token program and real sysvars, so the
whole suite runs without the Solana toolchain installed.

## Deploying

Building the deployable `.so` needs the Solana CLI, which is *not*
installed on the machine this crate was developed on — `cargo build-sbf`
is unavailable here and has never been run against this source:

```
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
cargo build-sbf --manifest-path programs/rand-bridge/Cargo.toml
solana program deploy target/deploy/rand_bridge.so
```

`lib.rs` pins a placeholder program id
(`RandBr1dge111111111111111111111111111111111`), a readable vanity key
with no known secret. A real deployment generates its own keypair and
re-declares it before `cargo build-sbf`, because every PDA in the program
is derived from the program id.

## Compute budget

A release recovers one secp256k1 signature per guardian (about 25k
compute units each), so a five-of-six quorum costs roughly 125k units on
top of the CPIs. Clients should prepend a
`ComputeBudgetInstruction::set_compute_unit_limit` rather than rely on
the 200k default.
