# Governance of the bridge endpoints (BR-3)

What this closes: security-report finding **BR-3** (High), "multisig and timelock on the source
contracts; Solana upgrade authority". Design and rationale:
`docs/superpowers/specs/2026-09-25-br3-governance-design.md`.

**None of the on-chain steps below has been run.** They move control of live custody and are
irreversible once a timelock or multisig accepts. Run them in the order given, one chain at a time,
and check each with the audit (§5) before the next.

## 1. The end state

| Chain | Admin | Pauser | Can change code |
|---|---|---|---|
| Ethereum, BSC | OZ v5.0.2 `TimelockController`, 48 h, driven by the **admin Safe** | the **pause Safe** | no (the bridge is not upgradeable) |
| Tron | the same timelock (Tron copy), driven by a **Tron multi-signature account** | a second Tron multi-signature account | no |
| Solana | the **vault of an autonomous Squads v4 multisig** with a 48 h time lock | the existing single key `8bYj…jwES` (no `SetPauser` instruction exists; see §8) | the program's upgrade authority = the same vault |

Rules the audit enforces (`rand-bridge-audit --governance`, §5):

- the admin is not a proxy, its code is exactly the pinned timelock (EVM:
  `0x0d2bd8c8c03557dfa0cf0c98e03a94e37f3096a23cdbfda03ab5541f4fd0bac3`, the forge build; Tron:
  `0xfcb7fa62daf40b0560729beb39f3ca1d9224ed0bba6c079b6fd2cab25fc55d5b`, the tronbox build), its
  delay is at least 48 h, its role history starts at its constructor (so the configured deploy
  block is right), the only proposer, executor and canceller is the admin multisig, and only the
  timelock administers itself;
- the admin multisig and the pauser are multisigs with a threshold of at least 2 — on EVM a
  genuine Safe proxy (its code is the v1.3.0 `GnosisSafeProxy` or v1.4.1 `SafeProxy` runtime)
  whose singleton (storage slot 0) is a canonical v1.3.0 or v1.4.1 Safe (or its L2 variant, or a
  v1.3.0 eip155 deployment), whose fallback handler is not the Safe itself, with **no module
  enabled** (a module executes without any owner signature) and at least as many owners as its
  threshold; on Tron a multi-signature account — and the pauser is neither the admin
  nor the admin multisig;
- on Solana the admin and the upgrade authority are the vault of a Squads multisig with no
  `config_authority`, a threshold of at least 2 and a time lock of at least 48 h.

A PASS on every rule means **no single key can change an endpoint's configuration or code**. It
does not mean no single party controls the funds: releases from custody are authorised by the
guardian quorum, whose keys are not yet distributed (BR-4, §8). The audit prints that caveat on
every run.

Recommended thresholds: admin 3 of 5, pause 2 of 5, **each signer a different person on a
different device**. That last clause is where BR-4 is closed for the endpoints: a multisig whose
keys sit in one shell profile is still one key.

## 2. What the operator provides

- the owners of the admin and pause multisigs on each chain (5 addresses each is the
  recommendation), created beforehand: Safes on Ethereum and BSC at safe.global (v1.3.0 or v1.4.1,
  **no modules, no recovery or spending-limit add-ons**: the handover and the audit refuse a Safe
  with any module; a Safe of any other version, v1.5.0 included, is refused until its proxy code
  hash and singleton are added to both pins, `Governance.s.sol` `isSafeProxyCodehash` /
  `isCanonicalSafeSingleton` and `gov_audit.rs` `SAFE_PROXY_CODEHASHES` /
  `CANONICAL_SAFE_SINGLETONS`), native multi-signature accounts on Tron (active permission with the threshold,
  whose `operations` allow TriggerSmartContract), one Squads v4 multisig on Solana created
  **without** a config authority and with a time lock of at least 172800 s;
- **if the Safe web app offers only a newer version**, create the Safes at v1.4.1 explicitly with
  the Protocol Kit (`@safe-global/protocol-kit`): `Safe.init({ provider, signer, predictedSafe: {
  safeAccountConfig: { owners, threshold }, safeDeploymentConfig: { safeVersion: '1.4.1' } } })`,
  then `createSafeDeploymentTransaction()` and send it from any funded key; it deploys through the
  canonical v1.4.1 SafeProxyFactory `0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67` with the
  canonical v1.4.1 singleton (`Safe` `0x41675C09…461a` or `SafeL2` `0x29fcB43b…C762`, both
  accepted) and the v1.4.1 CompatibilityFallbackHandler. The Safe CLI (`safe-creator`, with `--safe-contract` /
  `--proxy-factory` set to those v1.4.1 addresses) works too. Check the result with
  `cast codehash <safe>` (= `0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c`)
  and `cast storage <safe> 0` (the singleton) before the handover, which re-checks both;
- gas: a few dollars on Ethereum, cents on BSC, ~100 TRX on Tron, and SOL in the Squads vault
  (the admin pays rent when a token is listed);
- the current admin keys (EVM `0xe49B…0d0e`, Solana admin `HLc2…dN2P2`, the Solana upgrade
  authority `DvV4…77kX`).

## 3. Rehearse first

- EVM: `forge test --match-contract Governance` (default profile), and the fork tests against the
  live bridges: `ETH_FORK_URL=… BSC_FORK_URL=… forge test --match-contract GovernanceTest --match-test test_fork`
  (two tests; "2 skipped" means the URLs were not set).
- Tron: run the whole §4 Tron sequence on **Nile** against a Nile deployment of the bridge.
- Safe: import both generated batch files into the admin Safe's Transaction Builder and check that
  they decode (importing signs nothing).

## 4. The handover

### Ethereum and BSC (per chain)

```bash
cd evm
# 1. the timelock (any funded deployer key)
ADMIN_MULTISIG=<admin Safe> forge script script/Governance.s.sol:Governance \
  --sig "deployTimelock()" --rpc-url $RPC --account deployer --broadcast
#    RECORD the block the timelock was deployed in (broadcast/…/run-latest.json, or the
#    explorer): it is [governance].timelock_deploy_block for this chain in §5.
# 2+3. pauser, then the admin handover — signed by the CURRENT admin
BRIDGE=0xd6EBD21C3dF90c9175EBdc8d6b377a9361604892 TIMELOCK=<timelock> \
ADMIN_MULTISIG=<admin Safe> PAUSE_MULTISIG=<pause Safe> \
  forge script script/Governance.s.sol:Governance --sig "handover()" --rpc-url $RPC \
  --sender 0xe49Bd2571A549e8797bE649229F62891Fe300d0e --account bridge-admin --broadcast
# 4+5. the Safe batches (nothing is sent)
BRIDGE=0xd6EBD21C3dF90c9175EBdc8d6b377a9361604892 TIMELOCK=<timelock> CHAIN_ID=<1|56> \
  forge script script/Governance.s.sol:Governance --sig "acceptProposal()" --rpc-url $RPC
```

Then: the admin Safe signs `deploy/governance/<chainid>-schedule-accept.json`; after 48 h it signs
`<chainid>-execute-accept.json`. Only then is `admin()` the timelock. Until the execute, the EOA is
still admin and can cancel with `transferAdmin(address(0))`.

Without `--broadcast` every step is a dry run. `handover()` refuses a timelock that is not the pinned
code, has a delay under 24 h, has an open executor, gives the sender any role (admin, proposer,
executor or canceller), or lacks the admin Safe as proposer and executor; a pause multisig that is
the sender, the timelock or the admin Safe; and an admin or pause multisig that is not a Safe
(slot 0 a canonical v1.3.0/v1.4.1 singleton, no module, threshold at least 2, at least that many
owners).

### Tron

```bash
# 0. build the timelock (tronbox; this also mirrors evm/src into tron/contracts)
(cd tron && npm run compile)
# 1. the timelock
OPS_PRIVATE_KEY=… node deploy/tron-ops.js deploy-timelock <admin multisig account> --yes
#    RECORD the block of the deploy transaction: [governance].timelock_deploy_block for chain 4.
# 2. the pauser, 3. the admin handover — signed by the CURRENT admin
OPS_PRIVATE_KEY=<current admin> node deploy/tron-ops.js set-pauser <pause multisig account> --yes
OPS_PRIVATE_KEY=<current admin> node deploy/tron-ops.js transfer-admin <timelock> \
  --admin-multisig <admin multisig account> --yes
# 4. schedule the acceptance (unsigned, for the admin multisig)
node deploy/tron-ops.js timelock-schedule-accept <timelock> --from <admin multisig account>
#   → deploy/governance/tron-schedule-accept.json: the multisig's signers sign it within 23 h
# 5. after 48 h:
node deploy/tron-ops.js timelock-execute-accept <timelock> --from <admin multisig account>
#   refuses unless the operation is pending, and prints when it becomes ready
```

Each command prints the transaction it built; the signing ones refuse without `--yes`.
`transfer-admin` first checks the timelock as `handover()` does on EVM: its runtime code hashes
to the pinned tronbox build (so step 0 must have run on this checkout), its delay is at least 24 h,
the admin multisig proposes and executes, the zero address does not execute, and the signer holds
none of its roles; and the pauser must already be neither the signer nor the admin multisig.

### Solana — upgrade authority last

```bash
export SOL_RPC_URL=https://api.mainnet-beta.solana.com SOL_PROGRAM_ID=FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu
# 1. the admin, two-step: start it with the current admin key …
rand-bridge-cli --keypair <admin HLc2…> transfer-admin --to <Squads vault>
# … and finish it FROM THE SQUADS MULTISIG: print the AcceptAdmin instruction with the vault as
#    the signing admin (nothing is signed or sent) …
rand-bridge-cli --as <Squads vault> accept-admin
#    … import it into a Squads vault transaction; the members approve, and after the 48 h time
#    lock it executes, signed by the vault.
rand-bridge-cli show                       # admin must now be the vault, pending_admin the default
# 2. the upgrade authority, one step and irreversible:
rand-bridge-cli --keypair <deployer DvV4…> set-upgrade-authority \
  --new <Squads vault> --confirm-new <Squads vault> --squads-multisig <multisig> --vault-index 0 --yes
```

`set-upgrade-authority` refuses unless `--new` equals `--confirm-new`, is the vault of the
(mandatory) `--squads-multisig`, is off the Ed25519 curve, and differs from the current authority;
unless that multisig is owned by Squads v4, has no `config_authority`, a threshold of at least 2
(and no more than its members) and a time lock of at least 172800 s; and unless the bridge's admin
is already that vault with no `pending_admin` — it is the last step by construction. It re-reads
the ProgramData account afterwards and fails unless the vault holds it. Until it runs a mistake
anywhere else is still recoverable by the old keys.

## 5. Verify

Fill the `[governance]` section (`daemons/config.example.toml` documents it: the per-chain
timelock deploy block recorded in §4 and admin multisig, the Squads multisig, the policy) and run:

```bash
rand-bridge-audit --config daemons/mainnet/relayer.toml --governance
```

It exits non-zero unless every rule passes on every chain, so while the handover is under way
(one chain at a time) the exit status stays non-zero: after each chain, **check that chain's section
of the output is all PASS** before starting the next. Today it fails everywhere, which is the
correct reading of the current state. The role check reads `RoleGranted`/`RoleRevoked` logs from the
timelock's deployment block, so on BSC it needs an RPC that serves logs that old (a keyed one); a
deploy block after the real one fails the "role history starts at the timelock constructor" rule.

## 6. After the handover: operating through the delay

Every admin action now takes a proposal, 48 h, and an execution:

- **Ethereum, BSC**: the admin Safe calls `timelock.schedule(bridge, 0, <call data>, 0, salt,
  172800)` and, after the delay, `timelock.execute(bridge, 0, <call data>, 0, salt)` (Transaction
  Builder, contract interaction with the TimelockController ABI). The pause Safe calls
  `bridge.pause()` directly.
- **Tron**: `node deploy/tron-ops.js timelock-schedule <timelock> --from <admin multisig> --call
  <setToken|unpause|setProtocolFee|withdrawFees|setPauser|transferAdmin> --args a,b,…`, then
  `timelock-execute` with the same arguments after the delay (it refuses unless the operation is
  pending); `node deploy/tron-ops.js pause --from <pause multisig>`. Each writes an unsigned
  transaction under `deploy/governance/` for the account's signers. Use a fresh `--salt` to
  repeat an operation already done.
- **Solana**: `rand-bridge-cli --as <Squads vault> <accept-admin|unpause|set-token|set-protocol-fee|withdraw-fees|transfer-admin> …`
  prints the instruction (program id, accounts with signer/writable flags, data in base58 and
  base64) for a Squads vault transaction; nothing is signed or sent. The vault pays rent for
  `set-token`, so it must hold SOL. Pausing stays with the single key `8bYj…jwES`.

## 7. Watch the delay

The 48 h protects no one unless someone watches it: a compromised or colluding multisig quorum can
schedule anything, and the delay only gives the others time to see it and react (cancel, pause,
warn users, move nothing through the bridge). Set up an alert, to more than one person, on:

- **Ethereum, BSC, Tron — the timelock** (logs of the timelock address):
  `CallScheduled(bytes32,uint256,address,uint256,bytes,bytes32,uint256)`
  `0x4cf4410cc57040e44862ef0f45f3dd5a5e02db8eb8add648d4b0e236f1d07dca` — the one that matters:
  decode `target` and `data`, and alert on anything not announced; also
  `CallExecuted` `0xc2617efa69bab66782fa219543714338489c4e9e178271560a91b82c3f612b58`,
  `Cancelled` `0xbaa1eb22f2a492ba1a5fea61b8df4d27c6c8b5f3971e63bb58fa14ff72eedb70`,
  `MinDelayChange` `0x11c24f4ead16507c69ac467fbd5e4eed5fb5c699626d2cc6d66421df253886d5` and
  `RoleGranted`/`RoleRevoked`. On Tron the same topics appear in the JSON-RPC `eth_getLogs` of the
  timelock (hex address, `41` dropped).
- **The Safes** (admin and pause, each chain): `ExecutionSuccess`, and above all any change of
  who or what can act for them — `AddedOwner`, `RemovedOwner`, `ChangedThreshold`,
  `EnabledModule(address)` `0xecdf3a3effea5783a3c4c2140e677577666428d44ed9d474a0b3a4c9943f8440`,
  `ChangedFallbackHandler(address)`
  `0x5ac6c46c93c8d0e53714ba3b53db3e7c046da994313d7ed0d192028bc7c228b0`, `ChangedGuard`. A
  module, a fallback handler or a threshold drop takes effect immediately, without the timelock.
- **The bridge** (each chain): `Paused`, `Unpaused`, `AdminTransferStarted`, `AdminTransferred`,
  `PauserSet`, `TokenConfigured`, `ProtocolFeeSet`, `FeesWithdrawn`.
- **Tron multi-signature accounts**: permission updates of the admin and pause accounts
  (`AccountPermissionUpdateContract` transactions they sign), which change the signers at once.
- **Solana — the Squads multisig**: its `transaction_index` (a new vault or config transaction)
  and every `Proposal` account created under it (Squads program
  `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`, PDA `["multisig", multisig, "transaction",
  index, "proposal"]`); alert on each new proposal and read what its vault transaction does. Also
  the bridge program's ProgramData account (its `slot` changes on an upgrade) and the bridge
  `Config` account (admin, pending_admin, pauser, paused).

Re-running `rand-bridge-audit --governance` daily catches drift in the roles, the multisigs and the
upgrade authority, but not a scheduled operation: that needs the event alert above.

## 8. What this does not close

- **BR-4 (custody).** The six guardian ECDSA keys, their six Dilithium keys and the Rand pause key
  still live on one machine. Closing it means each guardian key running on a host its own operator
  controls, and the pause key held apart from all of them. The code prerequisite, rotation of the
  PQ set and the pause key under the PQ quorum, is fullnode's genesis-gated rules v2 (chain 15).
  No code in this repository can do that move; it is people and machines.
- **The Solana pauser** stays a single key. It can only pause; the timelocked admin unpauses. A
  `SetPauser` instruction would need a program upgrade, which after §4 goes through the Squads
  time lock like any other.
- **Custody.** The governance audit passing means no single key can change an endpoint's
  configuration or code. Releases are still authorised by the guardian quorum (above).
- **Bytecode verification of the live EVM bridge** must use the remappings of its deploy commit
  (`681f2e8`): this change lists remappings explicitly, which changes a fresh build's metadata.
