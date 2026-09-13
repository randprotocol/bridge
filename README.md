# Rand Bridge

The Rand bridge lets a user lock USDT or USDC on Ethereum, BNB Smart Chain, Tron, or Solana and
receive the same amount, 1:1, as a bridged asset on the Rand fullnode. A holder of a bridged
asset on Rand burns it and receives the locked tokens back on the asset's home chain. Every
chain — the four source chains and Rand itself — verifies the same attestation format
(`spec/ATTESTATION.md`) against the same guardian set: a 6-key secp256k1 guardian set with a
5-of-6 quorum. Guardians observe a lock or burn event, sign a digest over it once it clears the emitting
chain's consistency level, and any relayer can submit the resulting attestation to the
destination chain's verifier; the guardians are not the Rand validator set (which signs with
Dilithium2, unusable on-chain elsewhere) and are neither bonded nor slashable — a valid quorum
signature is the sole authorization a verifier requires.

Value flows one direction only: source chain to Rand, then Rand back to that same source chain.
There are no wrapped tokens on source chains and no lock-and-mint between two source chains — a
source contract releases only tokens whose home chain is itself, and Rand mints only against a
registered source-chain emitter. This pass ships the four custody contracts, the shared
attestation verifier and wire format, and the Rand fullnode's minting/burning ledger extension;
it does not ship the guardian or relayer daemons that would run the format end to end (see
Status below).

## Layout

| path | contents |
|---|---|
| `evm/` | Foundry project: `Attestation` verifier library, `RandBridgeBase` plus the Ethereum and BSC bridge contracts, deploy script, tests |
| `tron/` | TronBox project that compiles/deploys the same EVM source as the Tron endpoint (`TronRandBridge`); see `tron/README.md` |
| `solana/` | Native `solana-program` workspace, `programs/rand-bridge`: state, attestation verifier, instruction processing |
| `tools/vectors/` | Rust generator for the shared attestation test vectors consumed by every verifier |
| `vectors/attestations.json` | The generated vectors themselves (checked into this repo; a byte-identical copy lives in the fullnode) |
| `spec/ATTESTATION.md` | The attestation wire-format reference: envelope, body, payloads, digest, quorum, chain-id registry, plus a worked example |
| `docs/architecture.md` | End-to-end architecture: endpoints, guardians, attestation, the fullnode's bridge code, vectors, deployment |
| `docs/superpowers/` | Design spec and implementation plan this repo was built from |

The Rand fullnode itself (`bridge-codec` and `shrugg-core::bridge` crates, transaction kinds,
RPC, wallet CLI) lives in the separate `../fullnode` repository, on `main` (merged in `543d72b`).
Enabling the bridge is a hard fork: a chain whose genesis has no `bridge` section is byte-identical
to a pre-bridge node, and activation is bundled into the next chain cut-over rather than deployed
node by node.

## Build and test

```sh
# EVM contracts (Ethereum + BSC; Tron shares the same source, see tron/README.md)
cd evm && forge install foundry-rs/forge-std && forge test -vv

# Solana program
cd solana && cargo test

# Shared attestation vectors — regenerate, or verify the two copies match
cd tools/vectors && cargo run --release            # regenerate vectors/attestations.json and the fullnode's copy
cd tools/vectors && cargo run --release -- --check  # verify the two copies are byte-identical

# Rand fullnode (separate repo)
cd ../fullnode && cargo test --release
```

## Deployment order

1. **Fullnode genesis first.** Build the Rand genesis with a `bridge` section (`emitter`,
   `guardians`, and as much of the `emitters` map as is already known) via
   `shrugg-node genesis --bridge bridge.json`. The six guardian keys and the Rand-side emitter
   value it fixes here are the values every source-chain contract's constructor must be given
   next — the chains have to agree on one guardian set and one Rand emitter before any of them
   can accept an attestation from the other.
2. **Deploy the source-chain contracts** with that same guardian set and Rand emitter address
   passed to their constructors (`script/Deploy.s.sol` reads `CHAIN`, `ADMIN`, `PAUSER`,
   `RAND_EMITTER`, `GUARDIANS`, `EXPECTED_CHAIN_ID` from the environment for Ethereum/BSC; Tron
   deployment follows the separate steps in `tron/README.md`; Solana needs the Solana CLI toolchain
   for `cargo build-sbf`, which is not installed in this environment, so its program is built and
   tested but not deployed by this pass).
3. **Register each deployed contract's address back into the Rand genesis** `bridge.emitters` map
   (keyed by bridge chain id: 2 Ethereum, 3 BSC, 4 Tron, 5 Solana), left-padded to 32 bytes, before
   the chain launches. A source chain whose contract address is missing from `emitters` can be
   deployed and can accept locks, but `BridgeAttest` transactions carrying its `emitter_chain`
   cannot mint on Rand — the emitter table is the other half of the trust binding, alongside the
   guardian signatures, so it must be in genesis, not added after the fact on a live chain.

Tron's steps (mirroring `evm/src/` into `tron/contracts/`, `tronbox compile`, `tronbox migrate`,
whitelisting tokens, registering the emitter) are detailed in `tron/README.md`; nothing under
`tron/` has actually been deployed by this pass, since no Tron toolchain is installed here.

## Approved tokens

Two tokens are approved for bridging at launch, USDT and USDC, on each of the four source chains.
These are the only addresses the endpoints whitelist; the 32-byte wire forms and the Rand asset
ids for each row are in `docs/architecture.md` §10.1.

| chain | USDT | USDC |
|---|---|---|
| Ethereum (2) | `0xdAC17F958D2ee523a2206206994597C13D831ec7` · 6 dp | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` · 6 dp |
| BNB Smart Chain (3) | `0x55d398326f99059fF775485246999027B3197955` · 18 dp, Binance-Peg | `0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d` · 18 dp, Binance-Peg |
| Tron (4) | `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` · 6 dp | `TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8` · 6 dp, issuer discontinued |
| Solana (5) | `Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB` · 6 dp | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` · 6 dp |

Circle stopped issuing and redeeming USDC on Tron (minting ended February 2024, redemption
February 2025); the row is listed because the launch policy is both tokens on every chain, but it
should be capped tightly or left disabled until that policy is revisited. Verify every address
against the issuer and the chain's explorer before whitelisting it.

## Security notes

- The guardian set is the trust root on every chain. Deployment must place the six keys with
  distinct operators and hardware; no host may hold five.
- Custody counters bound the loss on each chain to what is actually held there, whatever an
  attestation says.
- Guardian upgrades cannot skip indices and old sets expire after a day, limiting the window in
  which a leaked old key set matters.
- The Rand recipient field has no checksum (base58 of 32 raw bytes). Wallets must verify the
  32-byte round trip before calling lock; the contracts can only reject zero.
- Attestations are ECDSA and therefore not post-quantum. The Rand-side verifier is the natural
  place to add ML-DSA later since Rand already verifies Dilithium.

## Status

This pass delivers the wire format, the four source-chain custody contracts, the Rand fullnode's
minting/burning ledger extension, and the shared test vectors that exercise all of it —
everything needed to build the off-chain pieces against a fixed target. It does not include the
guardian daemon or the relayer daemon: nothing runs this format end to end yet, and nothing here
has watched a real chain, signed a real digest, or moved real funds. It does not include shielded
notes — Rand mints a transparent, per-account bridged balance keyed by `(home chain, token)`
rather than into a shielded commitment tree, which is the same public boundary the design
describes but leaves the in-pool step to future shielded-balance work. None of this has been
audited. Treat every contract, program, and ledger change here as a reviewed but unaudited
implementation of the design in `docs/superpowers/specs/2026-09-10-rand-bridge-design.md`, not as
something ready to hold real value.
