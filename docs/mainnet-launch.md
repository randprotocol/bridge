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

## 4. Addendum (2026-09-19, evening): what changed after the deployment

The runbook above was written before the endpoints were deployed the same day. The launch now
runs in this order; each step that signs or broadcasts needs the owner's explicit go-ahead.

1. **Rotate the guardian set on the four endpoints** (set 0 → set 1): `rand-bridge-gov rotate`
   (signed by five of the current six), `verify`, then the SAME file to `submit-evm` (Ethereum, BSC),
   `submit-tron`, and `rand-bridge-cli guardian-set-upgrade` (Solana). The file is a bearer
   instrument — anyone holding it can apply it — so it is produced when the rotation is meant to
   happen, not before.
2. **Wait 86,400 s**: the superseded set keeps verifying transfers for a day.
3. **Chain 14 is cut** (fullnode `feat/rpl`: transaction binding, per-backing mint cap and pause,
   forward timestamp bound, Dilithium2 co-signature, fresh validator keys). Its genesis carries the
   `bridge` section of `docs/mainnet-deployment.md` — `guardians` = set 0, `pq_guardians` = the
   set-1 operators' Dilithium2 keys, the pause key — and **no token**.
4. **Rotate Rand**: the same rotation file plus `rand-bridge-gov cosign` →
   `rand bridge-rotate @rotation.hex --pq @pq.json`, so all five chains are on set 1.
5. **Deploy zUSD by transaction** from the faucet-funded deployer: one `RegisterBridgedToken`
   (zUSD + its first backing, `list_nonce` 0) and six `ListBacking` (`list_nonce` 1..6), each
   authorised by a PQ guardian quorum over the fixed layouts of `spec/PQ-COSIGNATURE.md` §8:

   ```sh
   G="--rand-chain-id 14 --pq-guardians-file ~/.rand-bridge/mainnet-pq-set1/public.json \
      --seed-envs NEW_GUARDIAN1_PQ_SEED,NEW_GUARDIAN2_PQ_SEED,NEW_GUARDIAN3_PQ_SEED,NEW_GUARDIAN4_PQ_SEED,NEW_GUARDIAN5_PQ_SEED"
   rand-bridge-gov pq-register $G --nonce 0 --name "Shielded USD" --symbol zUSD \
       --salt 27e77272ee77a47a6b66a62f3452dac66e681c79be6750d5e236e99f0d1e1d60 \
       --chain 2 --decimals 6  --token 000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7 --out zusd-0-register.json
   rand-bridge-gov pq-list $G --nonce 1 --token-index 1 --chain 2 --decimals 6  --token 000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 --out zusd-1.json   # Ethereum USDC
   rand-bridge-gov pq-list $G --nonce 2 --token-index 1 --chain 3 --decimals 18 --token 00000000000000000000000055d398326f99059ff775485246999027b3197955 --out zusd-2.json   # BSC USDT
   rand-bridge-gov pq-list $G --nonce 3 --token-index 1 --chain 3 --decimals 18 --token 0000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d --out zusd-3.json   # BSC USDC
   rand-bridge-gov pq-list $G --nonce 4 --token-index 1 --chain 4 --decimals 6  --token 000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c --out zusd-4.json   # Tron USDT
   rand-bridge-gov pq-list $G --nonce 5 --token-index 1 --chain 5 --decimals 6  --token ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264 --out zusd-5.json   # Solana USDT
   rand-bridge-gov pq-list $G --nonce 6 --token-index 1 --chain 5 --decimals 6  --token c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61 --out zusd-6.json   # Solana USDC
   ```

   Nonces are the ledger's `list_nonce` at the time (read `rand_getBridgeState`); a quorum for one
   message authorises no other. The token is named **"Shielded USD"**, symbol `zUSD`; the salt is
   `keccak256("rand-zusd-shielded-usd-chain-14")`; chain 14 lists no token in genesis, so the
   registration takes index 1 (RAND is 0). `--decimals` is the *backing's* source decimals — zUSD
   itself has 8 on Rand and is not in the message. The wallet then carries each file:
   `rand token register-bridged --name "Shielded USD" --symbol zUSD --salt … --chain 2 --token … --decimals 6 --pq @zusd-0-register.json`,
   `rand token list-backing --asset 1 --chain … --token … --decimals … --pq @zusd-N.json`,
   and for the brake `rand bridge-pause --sig @pause.sig` / `rand bridge-unpause --pq @unpause.json`.
6. **Only then `setToken`** on the endpoints, small caps first (list on Rand FIRST, whitelist
   SECOND — the other order strands a lock behind `UnlistedToken`), start the guardians
   (`GUARDIAN{i}_PQ_SEED` mapped from `NEW_GUARDIAN{i}_PQ_SEED`, `rand.chain_id = 14`) and a relayer,
   one round trip per chain from the tester wallets, `rand-bridge-audit`, then raise the caps after
   the external audit. An emergency stop on Rand is `rand-bridge-gov pause` (the single pause key);
   resuming takes `pq-unpause` (a guardian quorum).
