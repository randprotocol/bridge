# Tron deployment: `TronRandBridge`

This directory holds the [TronBox](https://developers.tron.network/docs/tron-box) project used
to deploy the Rand bridge's Tron endpoint, `TronRandBridge` (bridge chain id **4**). The contract
source lives in `evm/src/` and is shared byte-for-byte with the Ethereum and BSC endpoints (see
`evm/src/TronRandBridge.sol` and `evm/src/RandBridgeBase.sol`); this directory only adds the
TronBox build/deploy wiring around that source. Design background: `docs/superpowers/specs/2026-09-10-rand-bridge-design.md`
Section 5.4.

> **This pass does not deploy anything.** No Tron toolchain (`tronbox`, a funded Shasta/Nile/
> mainnet key, etc.) is installed on the build machine that produced this repository. Everything
> below is instructions and configuration for whoever runs the actual deployment, not a record of
> a deployment that happened.

## 1. Get the contract sources into `contracts/`

TronBox compiles whatever it finds under `tron/contracts/` (a sibling of this README), not
`evm/src/`. Before running `tronbox compile`, mirror the Foundry sources in:

```
rsync -a ../evm/src/ contracts/
```

Run that from inside `tron/`. `tron/contracts/` is git-ignored in this repo (see `tron/.gitignore`)
precisely because it is a generated copy of `evm/src/` -- re-run the `rsync` any time `evm/src/`
changes, rather than editing anything under `tron/contracts/` directly.

The one exception is `tron/contracts/governance/`: the vendored OpenZeppelin v5.0.2
`TimelockController` (BR-3, see its README), which is tracked and must survive the mirror. Use
`rsync -a --delete --exclude governance/ ../evm/src/ contracts/` (what `npm run sync` does) whenever
`--delete` is in play. `node deploy/tron-ops.js deploy-timelock` deploys it from
`build/contracts/TimelockController.json`.

## 2. Install TronBox and build

```
npm i -g tronbox
tronbox compile
tronbox migrate --network nile
```

- `tronbox compile` uses the `compilers.solc` settings in `tronbox.js`: solc `0.8.20`, optimizer
  on with 200 runs, and `evmVersion: "paris"` -- the same target `evm/foundry.toml` pins, chosen
  because the TVM does not support the `PUSH0` opcode that later EVM versions (Shanghai onward)
  emit.
- `tronbox migrate --network nile` runs the migrations in `tron/migrations/` against the Nile
  testnet. Swap `--network shasta` or `--network mainnet` for the other networks configured in
  `tronbox.js`. Each network reads its private key from an environment variable
  (`PRIVATE_KEY_SHASTA`, `PRIVATE_KEY_NILE`, `PRIVATE_KEY_MAINNET`) rather than a config file, so
  it never ends up committed.
- The deploy migration (`tron/migrations/2_deploy.js`) additionally requires `ADMIN`, `PAUSER`,
  `RAND_EMITTER`, and `GUARDIANS` in the environment -- see the doc comment at the top of that
  file. It fails loudly (throws before attempting any transaction) if any of them is missing. For
  example:

  ```
  PRIVATE_KEY_NILE=<funded testnet key> \
  ADMIN=TXYZ...                          # multisig, base58 or hex
  PAUSER=TXYZ...                         # pause quorum, base58 or hex
  RAND_EMITTER=0x...                     # 32-byte hex, from Rand genesis bridge.emitter
  GUARDIANS=0xaaa...,0xbbb...,0xccc...   # guardian set 0, in index order
  tronbox migrate --network nile
  ```

## 3. Address conversion: Tron base58check <-> the 32-byte attestation encoding

Tron wallet/contract addresses are usually shown as base58check strings starting with `T`
(e.g. `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`). Underneath, a Tron address is a 21-byte value: a
fixed `0x41` version/network prefix followed by the same 20 bytes an Ethereum address would use.
So converting between the two representations is:

```
base58check "T..."  --base58check-decode-->  0x41 || <20 bytes>
0x41 || <20 bytes>   --drop the 0x41 byte-->  <20 bytes>          (the EVM-style address)
<20 bytes>           --left-pad to 32-->      0x000...0 || <20 bytes>   (Section 3's bytes32 encoding)
```

This is exactly the same 20-byte value `TronRandBridge` uses on-chain as a Solidity `address`,
and the same value `Attestation.sol`'s `token_address` / `to` fields carry left-padded to 32
bytes (Section 3.5/3.6) -- Tron needs no separate address space or translation table in the
attestation format, only the base58check <-> hex conversion at the edges (when a human reads or
types a Tron address, or when a contract call needs the `41`-prefixed form TronWeb expects).
`tron/migrations/2_deploy.js` does exactly this conversion with `tronWeb.address.toHex` for the
constructor's `admin`/`pauser`/`guardians` arguments.

**Worked example** -- the well-known Tron USDT contract:

```
base58check:  TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
Tron hex:     41a614f803b6fd780986a42c78ec9c7f77e6ded13c     (0x41 prefix + 20 bytes)
EVM address:    a614f803b6fd780986a42c78ec9c7f77e6ded13c     (drop the 0x41 prefix)
attestation:  0x000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c   (left-padded to 32 bytes)
```

That last value is what `token_address` (Section 3.6, payload id 1) and, for a Tron recipient,
`to` (Section 3.2/5.1) carry over the wire; guardians and every other chain's verifier compare it
against `bytes32(uint256(uint160(token)))`, which is the same left-padding `RandBridgeBase._releaseToken`
and `_recipient` do (`evm/src/RandBridgeBase.sol`).

## 4. Mainnet token addresses

| token | base58check | hex (`41`-prefixed) |
|---|---|---|
| USDT | `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` | `41a614f803b6fd780986a42c78ec9c7f77e6ded13c` |
| USDC | `TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8` | `413487b63d30b5b2c87fb7ffa8bcfade38eaac1abe` |

These are the addresses `setToken` should whitelist on a mainnet deployment (Section 5.1). Verify
each against TronScan / the issuer before whitelisting -- this table is a reference for humans
running the deployment, not something the migration reads.
Both carry 6 decimals. Note that Circle discontinued USDC on Tron (minting ended February 2024,
redemption February 2025); see `docs/architecture.md` §10.1 for the launch policy on that row.

## 5. `block.chainid` is not relied on

`RandBridgeBase` pins `DEPLOY_CHAIN_ID = block.chainid` at construction and, on Ethereum and BSC,
`_checkFork()` reverts `lock`/`release` if `block.chainid` ever changes underneath the contract
(a guard against replaying contract state onto a forked chain). `TronRandBridge` overrides
`_checkFork()` to a no-op (`evm/src/TronRandBridge.sol`) because the TVM does not offer a chain id
this contract can depend on the way the EVM's `CHAINID` opcode does: Tron nodes historically
returned `0` (or an inconsistent value depending on node/version) for `block.chainid`, so treating
it as a stable, forkable identity per Section 5.4's fork-guard reasoning would either always
revert or never actually guard against anything. This is not a loss of the property the guard is
for -- Tron does not have the light/heavy client-driven optimistic-rollup-style forking history
the guard defends against on EVM chains -- it is a deliberate no-op documented at both the
contract (`TronRandBridge._checkFork`) and spec (Section 5.4) level so it is never mistaken for an
oversight.

## 6. Post-deploy steps

Once `tronbox migrate` returns a deployed address, before the bridge should be trusted with real
funds:

1. **Whitelist tokens.** As `ADMIN`, call `setToken` for each token this endpoint should custody,
   with its release caps (Section 5.1; `0` means unlimited):

   ```
   setToken(<USDT hex address>, true, <perTransferCap>, <dailyCap>)
   setToken(<USDC hex address>, true, <perTransferCap>, <dailyCap>)
   ```

   Use the hex (EVM-style, 20-byte) form from Section 3/4 above, not the base58check string --
   `setToken`'s `token` parameter is a Solidity `address`, and TronBox/TronWeb will accept either
   representation for a call argument, but the on-chain value stored is always the 20-byte form.

2. **Set the pauser**, if it was not already supplied to the constructor or needs rotating:

   ```
   setPauser(<pause quorum address>)
   ```

3. **Register this contract as the chain-4 emitter in the Rand genesis.** The Rand fullnode's
   `bridge.emitters` map (`docs/superpowers/specs/2026-09-10-rand-bridge-design.md` Section 6.1)
   is keyed by bridge chain id and holds the 32-byte, left-padded encoding of the registered
   source-chain contract address -- exactly the conversion in Section 3 above, applied to this
   deployment's own address rather than a token's:

   ```json
   "bridge": {
     "emitters": {
       "4": "0x000000000000000000000000<this contract's 20-byte EVM-style address>"
     }
   }
   ```

   Until this entry exists, `BridgeAttest` transactions whose `emitter_chain == 4` cannot mint on
   Rand (Section 6.2) even if `TronRandBridge` itself is deployed and working -- the emitter table
   is the other half of the trust binding, alongside the guardian signatures.

## 7. Not deployed by this repo

To repeat the note at the top of this file: no Tron toolchain is installed on the machine this
pass ran on, so nothing here has been compiled with `tronbox`, deployed to Shasta/Nile/mainnet, or
otherwise executed against a live Tron node. `tronbox.js` and `tron/migrations/*.js` are checked
for basic JS validity (`node --check`) but not run. Treat every address, cap, and network endpoint
above as configuration to review, not as a record of what already happened.
