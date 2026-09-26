# AGENTS.md

Guidance for agents working in this repository. The README is the user-facing overview;
`docs/architecture.md` is the normative end-to-end design; this file is the durable project
memory: review state, load-bearing invariants, and traps. The sibling repo
(`../fullnode`, package `randprotocol`) has its own AGENTS.md with the fullnode memory —
read it before touching anything there, it is worked on by many sessions in parallel.

## State as of 2026-09-26 — bridge on Rand chain 15

- Chain 14 stopped 13:04 UTC; chain 15 (genesis `cc30e085…b6b8`, fullnode dd2ccbe) carries the bridge:
  guardian set 1 at index 1, burn sequence 7, `pq_guardians` = the droplets' pq-next keys + laptop
  `pq-next-{7,8}.seed`, 10 zUSD carried over (locked Tron USDT 9 / Sol USDT 1). All daemons moved with
  `daemons/mainnet/cut-chain15.sh`; `chain_id = 15` everywhere; relayer CLI `~/rand-node-a/bin-dd2ccbe/rand`,
  300 RAND on chain 15. Audit clean on 15. Before the cut the tester's 26 zUSD were burned and released.

## State as of 2026-09-26 — BR-3 on Tron: timelock deployed, handover proposed

- User go in the bridge session: Tron steps 0–3 of `docs/governance.md` §4 ran on mainnet. Timelock
  `TKmds8i5UPQDaV3YghCVJUMomHeQzJzV7k` (pinned code, 48 h, deploy block 86582871), `pauser()` =
  `TCimv6…LG58`, `pendingAdmin()` = the timelock; `admin()` is still `TWoyj…9mh` until the accept.
  Tx table in `docs/mainnet-deployment.md`. EVM, BSC and Solana BR-3 steps not run.
- The Tron multisig accounts and signers are children of ONE xpub (`TRON_MSIG_XPUB`,
  `TRON_ADMIN_MULTISIG`, `TRON_PAUSE_MULTISIG`, `TRON_MSIG_SIGNER_1..5` in `~/.zshrc`) — user ruled
  this fine for now; the multisig is nominal until the signers are separate people/devices.
- `/0` and `/1` are multi-signature since 2026-09-26 (admin 3/5 + 3/5, pause 3/5 + 2/5, signers /2–/6).
  The user pasted the xprv into the bridge session to sign those updates: that one secret controls
  every signer, so the Tron multisigs are one key until the signers are re-keyed on separate devices.
  acceptAdmin scheduled 2026-09-26 12:41 UTC (op 0x41295d32…9a75); `timelock-execute-accept` from
  2026-09-28 12:41 UTC, 3 signers. Admin multisig holds ~45 TRX for it.

## State as of 2026-09-25 — guardian set 1: eight guardians, six on droplets

- **Set 0 → set 1 rotated on all five chains** (user go, 2026-09-25). Set 1 has 8 keys, quorum 6:
  indices 0–5 run on droplets `rand-guardian-1..6`, 6–7 on the laptop. Tx table in
  `docs/mainnet-deployment.md`, operation in `docs/guardian-hosts.md`. Each droplet runs its own
  chain-14 node (no shared Rand RPC, since a lying RPC would get a release signed) and holds the
  chain-14 PQ seed at its own index. The PQ set itself is unchanged until the chain-15 cut.
  Set 0 stays valid for transfers until about 2026-09-26 03:35 UTC.
- **Droplet IPs are NOT in this repo (it is public):** `~/.rand-bridge/mainnet-set1/hosts.txt`.
  The relayer reaches droplet guardians through `daemons/mainnet/guardian-tunnels.sh`
  (127.0.0.1:7171-7176). Start the relayer with `daemons/mainnet/run-relayer.sh`. Before 09-25
  it had been running since 09-24 **without EVM/Tron keys** (releases there were skipped).
- **publicnode log windows:** BSC is about 1 h, Ethereum about 1 day. The set-0 guardians and the
  relayer were stuck on Ethereum/BSC from about 09-21 to 09-25 (403s). Nothing was missed, because
  `sequence()` stayed at 2. Moving a cursor forward is safe only after that check.
- BR-4 is still open: one DO account, one laptop SSH key reaches every droplet (lock-down deferred by the user to before mainnet beta, `tunnel` user already prepared, see `docs/guardian-hosts.md`), and the laptop holds
  all six chain-14 PQ seeds. BR-3 (multisig signers) is on hold until the user decides who holds the Ledgers.

## State as of 2026-09-20 — LIVE: whitelisted, first mainnet round trip passed

- **Rand chain 14 carries the bridge** (genesis `1cff3b7d…c7ff`, fullnode build `b3c594c` = `a2c9896`
  + deploy-only commits; `feat/rpl` + `feat/bridge-hardening` landed linearly). Genesis has guardian
  **set 0** and `pq_guardians` = the set-1 operators' Dilithium2 keys; the daemons file a
  co-signature under whichever PQ-list position it verifies at, so this works unrotated. zUSD
  ("Shielded USD", index 1, 8 dp) was registered by transaction and its seven backings listed with
  PQ quorums signed here (`~/.rand-bridge/mainnet-zusd/zusd-{0-register,1..6}.json`). The 09-19
  launch blocker (redirected `BridgeBurn`) is fixed in chain 14 — `zusd_e2e` phase 5 pins it.
- **`setToken` is done on all four endpoints**, all seven tokens, caps 100 per transfer / 1,000 per
  day (native units). Raise only after the external audit (issue #4).
- **Round 1 passed on every chain** (1 USDT lock → mint → zUSD transfer → burn → release 0.999):
  tx table in `docs/mainnet-deployment.md`. First live run of the Tron log facade + submitter, the
  Solana and Rand subprocess submitters; on a real TVM `ecrecover` yields the stored address form
  and the USDT `transfer`-returns-false fix (H-1) holds. `rand-bridge-audit` afterwards: custody 0,
  fees exactly 10 bps, supply 0 == Σ locked.
- **Round 2 (same day): 9 USDT per chain minted and left on Rand** — 36 zUSD (tester wallet)
  against 36 USDT in custody; audit clean. **The user put the guardian rotation ON HOLD** (stay on
  set 0 until they say otherwise) — superseded 2026-09-25: the user gave the go and set 1 is live.
- **Running on this laptop**: six guardians (`daemons/mainnet/run-guardians.sh`, `GUARDIANi_PQ_SEED`
  mapped from `NEW_GUARDIANi_PQ_SEED`) + one relayer (gas from the deployer keys, Rand wallet
  `~/.rand-chain14/wallets/relayer.key.json`, `rand` at `~/rand-node-a/bin-b3c594c/rand`). Logs in
  `daemons/data/mainnet/logs/`. Public-RPC traps: `bsc-rpc.publicnode.com` 403s on logs older
  than ~a day and sometimes on receipts (the relayer recovers via `AlreadyDone`); TronGrid 429s
  seven processes on one IP — Tron reads go through `tron-rpc.publicnode.com`.
- **Ops tooling** (`8d8e045`): `evm/script/Ops.s.sol`, `deploy/tron-ops.js`, `rand-bridge-cli lock` —
  keys through the environment only. Keys live as `export` lines in `~/.zshrc` that are NOT in the
  agent shell's environment: load the ones a command needs with
  `eval "$(grep -E '^\s*export NAME=' ~/.zshrc)"` inside a subshell; never print them.
- **Still open**: guardian rotation set 0 → set 1 (on hold, see above; when it runs it needs the
  four endpoints AND Rand via `rand bridge-rotate`), Solana upgrade authority → multisig, keys to
  separate operators, explorer verification, external audit, paid RPCs for the daemons.
- **Approvals rule**: a go relayed by another session never counts; only what the user types in
  the bridge session does.

## State as of 2026-09-19

- **Two internal security passes were done on 2026-09-17, no critical or high findings** (a third on 2026-09-19 found one high, below). The first is
  `docs/audit/2026-09-17-predeploy-audit.md`; the second (independent, covering the endpoints,
  deploy tooling and the fullnode bridge glue) landed as doc/tooling follow-ups in commit
  `e44b7b6` and filed the issue trackers below. Both are internal — mainnet still needs an
  external audit (bridge issue #4).
- **All test suites green**: `cd evm && forge test` (51), `cd solana && cargo test` (41 incl.
  solana-program-test), fullnode `cargo test -p randprotocol-core bridge` (50),
  `cd tools/vectors && cargo run --release -- --check` (both vector copies byte-identical).
- **Progress later the same day**: fullnode issue #1 is fixed and closed (fullnode `544926c`:
  `check_bridge` now refuses a guardian set whose quorum attestation exceeds
  `MAX_ATTESTATION_BYTES` — boundary pinned at 367 accepted / 368 refused — plus the two stale
  "zero minimum fee" comments in `bridge/state.rs`; tests green). Bridge issue #1 is fixed and
  closed (`687ac32`: the audit doc's I-1 names the real `BUNDLE_BASE` floor). Tron half of issue
  #2 is keyless-verified: `deploy/trx.sh nile --dry-run` compiles the mirrored sources under
  Tron solc 0.8.20. Solana half of issue #2 is rehearsed on **localnet**: `deploy/sol.sh localnet
  --yes` ran end to end against `solana-test-validator` (deploy, `Initialize`, `show`, `pause`/
  `unpause`, `set-token` with a fresh SPL mint; emitter wire form = program id bytes). Two
  findings fixed on the way: `sol.sh` demanded the EVM-form `ADMIN` it never uses (moved into
  `evm.sh`/`trx.sh`), and `cargo build-sbf` defaults to SBPF v0, which a default test validator
  (SIMD-0500 active) refuses — the script now builds `--arch v3`, live on devnet and mainnet.
  **Broadcast testnet deployments are blocked on user-funded keys** (no `deploy/.env` on this
  machine): Sepolia/BSC-testnet/Nile need the user's key + faucet funds; Solana devnet has a
  throwaway deployer ready at `deploy/keys/solana-devnet-deployer.keypair.json` (git-ignored,
  pubkey `7kNdfwrnwMnsgwMfTS4Sp19N9MXSK37MqyjvnV6udD4y`, 0 SOL) — the RPC airdrop is
  rate-limited from this IP; fund it at faucet.solana.com, then
  `SOL_KEYPAIR=deploy/keys/solana-devnet-deployer.keypair.json SOL_ADMIN=<that pubkey>
  RAND_EMITTER=... GUARDIANS=... deploy/sol.sh devnet`.
- **Third pass, 2026-09-19** (`docs/audit/2026-09-19-reaudit.md`): one **high, fixed** — Tron
  mainnet USDT's `transfer` moves funds and returns `false`, which `SafeTransfer` rejected, so a
  lock would have been a one-way door; `release` now pays through `_push` (return data ignored,
  the bridge's balance must fall by exactly the amount). Also fixed: release to `address(this)`,
  `DecimalsChanged`, `TooManyGuardians` (> 255), and the deploy-tooling lows (keys un-exported,
  genesis-block/genesis-hash network identification on Tron/Solana, mainnet gates, anchored
  TronBox address, root `.gitignore`, record-before-verify, pinned forge-std). Medium, documented:
  **an attestation does not name its network — never share a guardian key or `RAND_EMITTER`
  between testnet and mainnet** (spec §3.5; `check_network_separation` enforces it against the
  deployment records). Open lows O-1..O-5 in that doc (Solana `n >= 9` needs v0 tx + ALT, no
  on-chain set-size bound, no Solana `SetPauser`, `Lock` sequence griefing, sub-unit dust).
  Suites: forge 43, solana 40, fullnode bridge 50, vectors OK. Licence is now GPL-3.0-only
  (`7343e2c`), matching the fullnode.
- **Fees added 2026-09-19**: 10 bps on release on EVM/Tron and Solana (forge 51, solana 41 tests;
  the legacy tests run fee-free via `setProtocolFee(0)` in their setup); a first cut that also
  skimmed locks (`3ad92f1`) was reverted the same day on the user's ruling that deposits are free.
  The RAND side is fullnode `142e1f7` on `origin/main` (fast-forwarded from branch
  `bridge-burn-fee`): `BRIDGE_BURN_FEE = 10 * BUNDLE_BASE`, wallet default, docs, pinned tests.
  Core bridge/gas tests, the wallet flow (4 tests, 889 s) and the cluster's
  `bridge_mint_deposits_a_note_and_a_burn_spends_it` (real proofs) are green; the 21 node-lib
  aggregation tests could not run (no `RECURSION_FIXTURES` cache on this machine — unrelated to
  the fee). The shared checkout's *local* `main` is still at `a941774`: it held another
  session's 145-file uncommitted diff, so git refused the fast-forward; that session must
  `git pull --rebase`. With aggregation on, the proposer keeps only `BUNDLE_BASE` and the rest
  becomes the aggregator's share (`ledger/mod.rs` ~1078) — revisit if the bridge
  chain enables aggregation. It ships with the chain cut that first carries a `bridge` section.
- **LAUNCH BLOCKER (2026-09-19, open): a Rand `BridgeBurn` can be redirected** — a transaction has
  no signature and a bundle proof does not commit to its action, so any gossip peer can rewrite
  `to` / `relayer_fee` and steal the release (`docs/audit/2026-09-19-reaudit.md` §5). Fix is in the
  fullnode (action-binding public words, session `fullnode-fc`, branch `rpl`, ships with chain 14).
  **Do not call `setToken` on any mainnet endpoint until that session reports the fix reviewed and
  the "redirected BridgeBurn copy is refused" case passing.** The Rand side is also becoming ONE
  pooled token, zUSD, with seven backings and per-backing `locked` counters (== endpoint custody);
  bridged-asset transfers and per-asset supply do not exist on fullnode main yet.
- **Design review of 2026-09-18 and the plan that follows:** `docs/bridging-architecture-review-notes.md`
  (option C: own bridge + Dilithium2 co-signature + verifier threshold + Rand-side limits + S3 id;
  nothing in it touches a deployed endpoint, but it is all consensus work that belongs in the
  chain-14 genesis or needs a custody-carrying migration later).
- **MAINNET ENDPOINTS ARE DEPLOYED (2026-09-19)** — addresses, tx hashes and the matching Rand
  genesis `bridge` section are in `docs/mainnet-deployment.md`. Ethereum and BSC
  `0xd6EBD21C3dF90c9175EBdc8d6b377a9361604892`, Tron `TAqq2i8KfYpACPUc9f5e2gAjdSgXqmPpkU`, Solana
  `FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu` (`declare_id!` now names it — do not let a
  localnet/devnet rehearsal overwrite it in a commit). `RAND_EMITTER =
  keccak256("rand-bridge-mainnet-burn-emitter")`. **No token is whitelisted and no Rand chain
  carries the bridge yet**, so nothing can move. Still to do: Solana upgrade authority → multisig,
  `setToken` (USDT only on Tron; small caps first), the Rand chain cut, guardians + relayer
  running, explorer verification of the EVM sources. All six guardian keys, the admin keys and
  the deployer keys are currently held on one machine — the 5-of-6 is nominal until the
  keys move to separate operators (rotation tooling does not exist yet). The program keypair is
  `deploy/keys/solana-mainnet-beta-program.keypair.json` (git-ignored).
- **Testnet deployment is configured and blocked only on faucet funds** (2026-09-19):
  `deploy/.env` (mode 600, git-ignored) holds one EVM key for Sepolia + BSC testnet
  (`0x278071824AD2051b8503d62Aa9c6e5eC12CE0B8D`, also `ADMIN` and `PAUSER`), a Tron key
  (`TYToFBuiEEPFasMc7NBxF54KRkQX7o79nh`), the Solana devnet deployer below, six **testnet-only**
  guardian keys (`deploy/keys/testnet-guardians.json`) and `RAND_EMITTER =
  keccak256("rand-bridge-testnet-burn-emitter")`. All four `--dry-run`s pass from it; every
  address held 0 on every network when last checked. Mainnet uses `DEPLOY_ENV_FILE` with fresh
  guardian keys and emitter. Costs and what gets deployed: `docs/deployment-costs.md` (~$540 to
  fund a mainnet deployment; testnets free).
- **Daemons built 2026-09-19** (`daemons/`, `1f020fb`): `rand-guardian` + `rand-relayer`; signing
  and assembly reproduce the shared ok vectors byte for byte; a lock and a release run against the
  real `EthereumRandBridge` on anvil (`cargo test` in `daemons/`, needs Foundry). Untested paths:
  Tron log facade + submitter, Solana (`rand-bridge-cli release`) and Rand (`rand bridge-mint`)
  subprocess submitters. No rotation tooling. Real USDT/USDC fork tests:
  `FOUNDRY_PROFILE=fork ETH_FORK_URL=… BSC_FORK_URL=… forge test --match-contract ForkTokensTest`.
- **Issue trackers** (created 2026-09-17, both were empty before):
  - `randprotocol/bridge` #1 stale fee-floor claim in the audit doc (closed, `687ac32`) ·
    #2 testnet round trips (Tron dry-run + Solana localnet done; broadcasts blocked on keys) ·
    #3 guardian + relayer daemons (built 2026-09-19 in `daemons/`; vectors + anvil e2e green; Tron/Solana/Rand submit paths untested) · #5 Solana open lows O-1..O-4 · #6 sub-unit dust (O-5) · #4 external-audit gate
  - `randprotocol/fullnode` #1 genesis `check_bridge` guardian-count bound (closed, `544926c`) ·
    #2 no forward bound on block timestamps · #3 deposit-note commitment front-running ·
    #4 mempool re-check gaps
- **Key commits**: `13dc315` (S3 + RAND-rename rewrite of all docs, deploy scripts, first audit),
  `e44b7b6` (second-pass follow-ups: `deploy/evm.sh` key handling, spec advisory-fields note,
  README/architecture security notes).

## Load-bearing invariants (do not regress)

Parity across all verifiers is the security property; change these everywhere or nowhere
(`docs/architecture.md` §11 is the normative list):

- `mu = keccak256(keccak256(body))` over the exact wire body; low-s only; recovery id 0 or 1;
  quorum `n*2/3 + 1`; signature indices strictly increasing and each `< n`.
- A rotation is signed by the **current** set (grace window covers transfers only), carries
  `new_index == current + 1`, unique non-zero keys; a superseded set expires after 86,400 s.
  A rotation's body `sequence`/`nonce`/`consistency_level` are **advisory** — no verifier
  checks them (spec/ATTESTATION.md §3.6).
- Emitter binding on `(emitter_chain, emitter_address)`; the governance emitter
  (`keccak256("rand-bridge-governance")`, pinned literal everywhere) is distinct from the Rand
  burn emitter. EVM-family addresses are left-padded 20-byte; the upper 12 bytes are checked on
  the way out of Rand and into an endpoint.
- `fee <= amount`; zero attested/denormalized amounts refused; attested amount `<= u64::MAX`
  (a Rand note's amount is a `u64`) on every lock and mint.
- Effects before interactions on every release; custody counters bound releases to what the
  endpoint actually holds; locks measure the received balance delta (fee-on-transfer rejected),
  and EVM/Tron releases measure the paid delta and **ignore the token's return value** (Tron USDT
  returns `false` from a successful `transfer`).
- **Fees (user ruling 2026-09-19, `docs/architecture.md` §3.5): a deposit is free — no stablecoin,
  no RAND; only unbridging pays.** On the burn: `gas::BRIDGE_BURN_FEE` = 0.01 RAND (the
  `BridgeBurn` floor; `BridgeAttest` stays at `BUNDLE_BASE`, paid by the relayer). On the release:
  10 bps of the token (default, cap 100), an endpoint-side skim that is never in the attestation,
  taken from the gross amount **before** the relayer fee (`relayer = min(fee, amount - protocol
  fee)`, so it can neither be dodged nor brick a release). Locks must never skim. Fees live in
  `accruedFees` / `accrued_fees`, outside custody; `withdrawFees` can never reach custody. Same
  arithmetic on EVM and Solana — change both or neither.
- Guardian keys and the Rand emitter are per network: nothing in an attestation names testnet or
  mainnet.
- Guardian-set size is bounded by transport, not on-chain: Solana's 1,232-byte transaction caps
  releases at `n <= 10` (rotations at `n <= 11`); the fullnode's 16 KiB attestation cap admits
  ~253. Governance keeps `n` small (launch: 6) by policy.

## Verified fullnode facts (main, post-S3, post-RAND-rename)

- Bridged holdings are **shielded notes** (no per-account balances); the asset registry maps
  `blake3("rand-bridge-asset" || chain BE || token)` to a dense `u32` index (0 = RAND). Mints are
  **gross** (relayer fee is record-only on Rand, paid only on source-chain release). Deposit
  `to` is the 32-byte `recipient_hash` of the recipient's full shielded address (chain 12; chain
  11's `ReceiverId` form, resolved via `Ledger::resolve_pk`, was reverted at fullnode `17db41d`).
- `Action` bincode tags: `BridgeAttest = 7`, `BridgeBurn = 8` (Bond/Unbond/Withdraw took 4-6).
- Fee floors: `BridgeAttest = BUNDLE_BASE`, `BridgeBurn = BRIDGE_BURN_FEE` = 0.01 RAND (fullnode
  `142e1f7`; covers the base for both of the burn's bundles).
- RPC: `rand_getBridgeState`, `rand_getAssets` (no param, registry rows), `rand_getBridgeBurn`,
  `rand_bridgeAssetId`. `rand_getAssetBalance` is **removed** (method-not-found).
- Storage CFs: `bridge_spent`, `bridge_burns`, `meta["bridge_state"]`; no `bridge_balances`.
- `BridgeBurn` = `{ asset_bundle, asset: u32, amount: u64, relayer_fee: u64, to_chain, to }`;
  burn checks: asset match, `burn == amount`, zero asset-bundle fee, disjoint
  nullifiers/commitments, zk proof last; `check_burn` screens the recipient (zero / EVM padding).

## Repo workflow traps

- **HEAD moves mid-task.** Parallel sessions work in this checkout; commits appeared under a
  running audit before. Re-check `git status` / `git log main` before trusting any earlier file
  read; if a doc seems to contradict your notes, re-read it.
- **Never put a key in argv.** `cast wallet address` only accepts a key as an argument (no env,
  no stdin) — `deploy/evm.sh` deliberately does not derive the deployer (Deploy.s.sol logs it);
  `DEPLOYER_ADDRESS` (non-secret) enables the pre-flight balance line. All deploy scripts pass
  keys through the environment only.
- Commit messages with heredoc quoting broke once; write the message to a file and
  `git commit -F`.
- Toolchains on this machine: foundry + cargo present; Solana CLI (agave 4.2.2, platform-tools
  v1.54, `spl-token`) at `~/.local/share/solana/install/active_release/bin` — **not on PATH by
  default**, export it first; **no Tron toolchain installed globally** (TronBox installs locally
  into `tron/node_modules` via `deploy/trx.sh --dry-run`). Solana program is tested natively via
  solana-program-test; the Tron endpoint is exercised only under EVM semantics.
- **Build the Solana program with `cargo build-sbf --arch v3`.** The v0 default deploys on
  devnet/mainnet today but a default `solana-test-validator` refuses it (SIMD-0500 active
  locally, pending on the public clusters). `deploy/sol.sh` does this; a localnet rehearsal
  rewrites `declare_id!` to a throwaway id and writes `deploy/deployments/solana-localnet.json` —
  revert both afterwards, they are not deployment records.
- `solana/programs/rand-bridge` depends on `bridge-codec` **by path** into `../fullnode` — the
  fullnode checkout must sit beside this repo or nothing builds.
