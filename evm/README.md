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
# BR-3 governance (script/Governance.s.sol, test/Governance.t.sol): OpenZeppelin
# Contracts pinned to v5.0.2 = commit dbb6104ce834628e473d2173bbc9d47f81a9eec3, unmodified.
git clone --depth 1 --branch v5.0.2 https://github.com/OpenZeppelin/openzeppelin-contracts.git \
    lib/openzeppelin-contracts
git -C lib/openzeppelin-contracts rev-parse HEAD   # must print dbb6104c...
```

`foundry.toml` remaps `@openzeppelin/contracts/` to `lib/openzeppelin-contracts/contracts/`.

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
