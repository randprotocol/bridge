# Deploying the Rand bridge endpoints

One script per chain, driven from the command line, each signing with a private key loaded from
`deploy/.env` (git-ignored) or the environment. No script ever puts a key on a command line: the
EVM scripts hand it to `forge` through `DEPLOYER_PRIVATE_KEY` in the environment, TronBox reads
`TRON_PRIVATE_KEY` from its own process environment, and the Solana script writes an inline
secret to a mode-0600 temp file that is deleted on exit.

| script | chain | signs with | tool it drives |
|---|---|---|---|
| `deploy/eth.sh [mainnet\|sepolia]` | Ethereum (bridge chain 2) | `ETH_PRIVATE_KEY` | `forge script evm/script/Deploy.s.sol` |
| `deploy/bnb.sh [mainnet\|testnet]` | BNB Smart Chain (3) | `BSC_PRIVATE_KEY` | same |
| `deploy/trx.sh [nile\|shasta\|mainnet]` | Tron (4) | `TRON_PRIVATE_KEY` | `tronbox migrate` (installed locally into `tron/node_modules`) |
| `deploy/sol.sh [devnet\|testnet\|mainnet-beta\|localnet]` | Solana (5) | `SOL_KEYPAIR` file or `SOL_PRIVATE_KEY` | `cargo build-sbf`, `solana program deploy`, then `rand-bridge-cli initialize` |

Every script accepts `--dry-run` (simulate / compile only) and `--yes` (skip the prompt; mainnets
otherwise require the network name to be typed back). On success each one prints the deployed
address, the **32-byte emitter wire form** that goes into the Rand genesis `bridge.emitters` table,
and appends a record to `deploy/deployments/<network>.json`.

## 1. Fill in `deploy/.env`

```sh
cp deploy/.env.example deploy/.env && chmod 600 deploy/.env
```

The constructor arguments (`ADMIN`, `PAUSER`, `RAND_EMITTER`, `GUARDIANS`) must be the same on
every chain, and `RAND_EMITTER` and `GUARDIANS` must be the values the Rand genesis `bridge`
section carries: the chains have to agree on one guardian set and one Rand emitter before any of
them can accept an attestation from the others (`README.md`, Deployment order).

## 2. Rehearse locally

```sh
anvil --port 18545 &
ANVIL_RPC_URL=http://127.0.0.1:18545 deploy/evm.sh anvil --yes
```

This runs the whole Ethereum path (chain-id check, signing from the environment, broadcast,
address extraction, deployment record) against a throwaway node.

## 3. Deploy

```sh
deploy/eth.sh sepolia            # then: deploy/eth.sh mainnet --verify
deploy/bnb.sh testnet            # then: deploy/bnb.sh mainnet --verify
deploy/trx.sh nile               # then: deploy/trx.sh mainnet
deploy/sol.sh devnet             # then: deploy/sol.sh mainnet-beta
```

`sol.sh` generates the program-id keypair under `deploy/keys/` (git-ignored) the first time, rewrites
`declare_id!` in `solana/programs/rand-bridge/src/lib.rs` to match (commit that), builds with
`cargo build-sbf`, deploys with the deployer as upgrade authority, and runs `Initialize`, which the
program only accepts from the upgrade authority. Hand the authority to a multisig afterwards:

```sh
solana program set-upgrade-authority <PROGRAM_ID> --new-upgrade-authority <MULTISIG> --url <RPC>
```

## 4. After deploying

1. Put each printed emitter wire form into the Rand genesis `bridge.emitters` map under its bridge
   chain id (2, 3, 4, 5). The table is part of the genesis hash, so this happens before the chain
   is cut, never on a live chain (`docs/architecture.md` §8.4, §10).
2. Whitelist the approved tokens with their caps (`docs/architecture.md` §10.1): `setToken` on the
   EVM/Tron endpoints (from the admin), `rand-bridge-cli set-token --program ... --mint ...` on
   Solana (signed by the admin).
3. Verify the EVM sources on the explorer if `--verify` was not used.

## Tooling

- Ethereum/BSC: Foundry (`forge`, `cast`) and `jq`.
- Tron: Node.js and npm; `deploy/trx.sh` installs TronBox into `tron/node_modules` on first use.
- Solana: the Solana CLI (agave) for `cargo build-sbf`, `solana`, `solana-keygen`:
  `sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"`.
- `rand-bridge-cli` (`solana/cli`) is built by `cargo` as part of `sol.sh` and is also useful on
  its own: `initialize`, `set-token`, `pause`, `unpause`, `transfer-admin`, `accept-admin`, `show`,
  `address`, `export-keypair`.
