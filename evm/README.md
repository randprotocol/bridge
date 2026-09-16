# Rand Bridge — EVM contracts

Foundry project for the Rand bridge's EVM-side contracts. The `Attestation`
library (`src/lib/Attestation.sol`) decodes and verifies the Wormhole-shaped
attestation wire format that is shared byte-for-byte with the Rand fullnode
(`crates/bridge-codec`, `crates/randprotocol-core::bridge`) and the Solana program.

## Setup

`lib/` (including `lib/forge-std`) is vendored, not a git submodule, and is
excluded from version control via `.gitignore`. After cloning this repo, run:

```sh
cd evm
forge install foundry-rs/forge-std
```

(or simply re-run `forge build` / `forge test`, which will report a missing
remapping if `lib/forge-std` is absent).

## Build & test

```sh
forge build
forge test -vv
```

Vector-based tests (`test/Vectors.t.sol`) read the shared fixture at
`../vectors/attestations.json`, granted read access via `fs_permissions` in
`foundry.toml`.
