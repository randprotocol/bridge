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

`deploy/sol.sh [devnet|testnet|mainnet-beta]` (repo root) does every step
below from the command line — program keypair, `declare_id!` rewrite,
`cargo build-sbf`, `solana program deploy`, `Initialize` — with the
deployer key loaded from `deploy/.env` (`SOL_KEYPAIR` or
`SOL_PRIVATE_KEY`). `cli/` is `rand-bridge-cli`, the client it uses for
`Initialize` and the admin instructions (`set-token`, `pause`, `unpause`,
`transfer-admin`, `accept-admin`, `show`).

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

### `Initialize` must be signed by the upgrade authority

`Initialize` installs the admin, the pauser, the Rand emitter and
guardian set 0. It is the one instruction with no config to check a role
against, so it authenticates against the program's own ProgramData
account under the upgradeable loader: the payer must be the address the
loader records as `upgrade_authority_address`, or the instruction fails
with `NotAdmin`. Without that, anyone watching the mempool could run it
first on a freshly deployed program and own the bridge.

The upgrade authority could replace the program wholesale in any case, so
binding deployment to it grants no new power. It does mean the ordering
matters:

```
solana program deploy target/deploy/rand_bridge.so     # you are the authority
rand-bridge-cli initialize --program <PROGRAM_ID> --admin <ADMIN> \
  --rand-emitter 0x<64 hex> --guardians 0x<40 hex>,...   # signed by that same key
solana program set-upgrade-authority <PROGRAM_ID> --new-upgrade-authority <MULTISIG>
```

If the authority is handed to a multisig **before** `Initialize`, then the
multisig — not the original deployer — is the only signer the program will
accept, and the initialization transaction has to go through it. A program
whose upgrade authority has been removed entirely (made immutable) can
never be initialized at all, so freeze it only after the bridge is live.

## Two locks in the same slot

`Lock` publishes its message into a PDA derived from the config's current
`sequence`, and the client has to pass that account in. Two locks built
against the same config therefore name the same message PDA: the first to
land consumes that sequence, and the second fails with `InvalidPda`
because the account it passed no longer matches `msg_pda(program_id,
config.sequence)`.

This is a race, not a rejection of the transfer — nothing was locked and
nothing was lost. Clients should treat `InvalidPda` on a `Lock` as
retryable: re-read the config account, re-derive the message PDA from the
new `sequence`, and resubmit.

## Compute budget

A release recovers one secp256k1 signature per guardian (about 25k
compute units each), so a five-of-six quorum costs roughly 125k units on
top of the CPIs. Clients should prepend a
`ComputeBudgetInstruction::set_compute_unit_limit` rather than rely on
the 200k default.
