# Mainnet launch runbook

Decisions taken 2026-09-19: launch on mainnet directly; the six guardian keys are generated and
held by their operators, who hand over **addresses only**; `ADMIN` / `PAUSER` to be supplied;
the endpoints are deployed **together with the Rand chain cut that enables the bridge**, because
`RAND_EMITTER` is immutable in every endpoint and must equal that genesis' `bridge.emitter`.

The endpoints cannot be upgraded. A wrong constructor argument means a redeploy, a new address,
and therefore a new Rand genesis.

## 0. Known risk carried into a full launch

Stated once, so it is on the record next to the decision:

- No external audit (issue #4). Three internal passes; the third found a fund-freezing bug.
- The Tron endpoint has never run on a real TVM. Two assumptions are untested there: that
  `ecrecover` yields the address form the guardian set stores, and the Tron-USDT `transfer`
  fix (`docs/audit/2026-09-19-reaudit.md` H-1). If the first is wrong every Tron release reverts
  with custody intact but stuck; a one-hour Nile run settles both for free.
- The daemons' Tron, Solana and Rand submission paths have not run against a live chain.
- Open lows: issues #5 and #6.

Cheapest mitigation that keeps "mainnet directly": whitelist with small caps first
(`setToken(token, true, perTransferCap, dailyCap)`), run one real round trip per chain, then raise
the caps. Caps bound what a bug or a compromised quorum can take per day.

## 1. Inputs (all must exist before anything is broadcast)

| input | who | where it goes |
|---|---|---|
| Six guardian addresses, one operator and host each, index order fixed | operators | `GUARDIANS` in `deploy/.env.mainnet`; Rand genesis `bridge.guardians` |
| `ADMIN`, `PAUSER` (EVM form) and `SOL_ADMIN`, `SOL_PAUSER` — multisigs | you | `deploy/.env.mainnet` |
| `RAND_EMITTER` (32 bytes) | chosen at the chain cut | `deploy/.env.mainnet`; Rand genesis `bridge.emitter` |
| Deployer keys, funded: ~0.03 ETH, 0.01 BNB, 500 TRX, 2.5 SOL (`docs/deployment-costs.md`) | you | `ETH_/BSC_/TRON_PRIVATE_KEY`, `SOL_KEYPAIR` in `deploy/.env.mainnet` (mode 600) or the environment — never in chat, never in argv |
| Mainnet RPC URLs (a paid provider for the daemons) | you | `deploy/.env.mainnet`, daemon configs |

None of the testnet values may be reused: an attestation does not name its network
(`spec/ATTESTATION.md` §3.5). The scripts refuse a mainnet deploy with fewer than six guardians,
without `PAUSER`, or with a guardian key / emitter that appears in a testnet deployment record.

## 2. Order

1. `DEPLOY_ENV_FILE=deploy/.env.mainnet deploy/eth.sh mainnet --dry-run`, then the same for
   `bnb.sh mainnet`, `trx.sh mainnet`, `sol.sh mainnet-beta`. All four must pass.
2. Deploy for real (each asks for the network name to be typed back):
   `deploy/eth.sh mainnet --verify`, `deploy/bnb.sh mainnet --verify`, `deploy/trx.sh mainnet`,
   `deploy/sol.sh mainnet-beta`. Commit the `declare_id!` change `sol.sh` makes, and the four
   records under `deploy/deployments/`.
3. Put the four printed **emitter wire forms** into the Rand genesis `bridge.emitters` (`"2"`,
   `"3"`, `"4"`, `"5"`), with `bridge.emitter = RAND_EMITTER` and the six guardians. Cut the chain
   (fullnode `142e1f7` or later, so a burn costs `BRIDGE_BURN_FEE`).
4. Solana: `solana program set-upgrade-authority <PROGRAM> --new-upgrade-authority <MULTISIG>`.
5. Whitelist tokens from the admin, addresses from `docs/architecture.md` §10.1 re-checked against
   the issuers' pages: USDT and USDC on Ethereum, BSC and Solana; **USDT only on Tron** (Tron USDC
   is discontinued). Start with small caps.
6. Start the six guardians (`daemons/`, one per operator) with `finality = "finalized"` /
   15 / 19 and the deployment blocks as `start_block`; start at least one relayer with funded gas
   keys and a Rand wallet holding RAND for mints. On Tron, stake TRX for energy or require a
   relayer fee that covers ~30–45 TRX per release.
7. One round trip per chain with a few dollars: lock → mint on Rand → burn → release. Check
   `custody`, `accruedFees` and the recipient's balance against the expected 10 bps. Then raise caps.

## 3. After launch

- Keep the pauser reachable: pausing is the only brake on a compromised quorum, and a rotated-away
  guardian set stays valid for transfers for 24 hours.
- Guardian-set rotation has no tooling yet; it is a governance message signed by the current set
  (`spec/ATTESTATION.md` §3.6) and must be built before the first rotation is needed.
- `withdrawFees` / `withdraw-fees` collects the 10 bps; it can never reach custody.
