# AGENTS.md

Guidance for agents working in this repository. The README is the user-facing overview;
`docs/architecture.md` is the normative end-to-end design; this file is the durable project
memory: review state, load-bearing invariants, and traps. The sibling repo
(`../fullnode`, package `randprotocol`) has its own AGENTS.md with the fullnode memory —
read it before touching anything there, it is worked on by many sessions in parallel.

## State as of 2026-09-17

- **Two internal security passes are done, no critical or high findings.** The first is
  `docs/audit/2026-09-17-predeploy-audit.md`; the second (independent, covering the endpoints,
  deploy tooling and the fullnode bridge glue) landed as doc/tooling follow-ups in commit
  `e44b7b6` and filed the issue trackers below. Both are internal — mainnet still needs an
  external audit (bridge issue #4).
- **All test suites green**: `cd evm && forge test` (38), `cd solana && cargo test` (35 incl.
  solana-program-test), fullnode `cargo test -p randprotocol-core bridge` (51),
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
- **Issue trackers** (created 2026-09-17, both were empty before):
  - `randprotocol/bridge` #1 stale fee-floor claim in the audit doc (fixed, uncommitted) ·
    #2 testnet round trips (Tron dry-run done; broadcasts blocked on keys) ·
    #3 guardian + relayer daemons (not started) · #4 external-audit gate
  - `randprotocol/fullnode` #1 genesis `check_bridge` guardian-count bound (fixed, uncommitted) ·
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
  endpoint actually holds; locks measure the received balance delta (fee-on-transfer rejected).
- Guardian-set size is bounded by transport, not on-chain: Solana's 1,232-byte transaction caps
  releases at `n <= 10` (rotations at `n <= 11`); the fullnode's 16 KiB attestation cap admits
  ~253. Governance keeps `n` small (launch: 6) by policy.

## Verified fullnode facts (main, post-S3, post-RAND-rename)

- Bridged holdings are **shielded notes** (no per-account balances); the asset registry maps
  `blake3("rand-bridge-asset" || chain BE || token)` to a dense `u32` index (0 = RAND). Mints are
  **gross** (relayer fee is record-only on Rand, paid only on source-chain release). Deposit
  `to` is a `ReceiverId` resolved via `Ledger::resolve_pk`.
- `Action` bincode tags: `BridgeAttest = 7`, `BridgeBurn = 8` (Bond/Unbond/Withdraw took 4-6).
- Fee floors: `BridgeAttest = BUNDLE_BASE`, `BridgeBurn = 2 * BUNDLE_BASE` (two bundles).
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
