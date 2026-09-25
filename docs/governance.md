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
| Solana | the **vault of an autonomous Squads v4 multisig** with a 48 h time lock | the existing single key `8bYj…jwES` (no `SetPauser` instruction exists; see §6) | the program's upgrade authority = the same vault |

Rules the audit enforces (`rand-bridge-audit --governance`, §5):

- the admin is not a proxy, its code is exactly the pinned timelock
  (`0x0d2bd8c8c03557dfa0cf0c98e03a94e37f3096a23cdbfda03ab5541f4fd0bac3`, EVM), its delay is at
  least 48 h, the only proposer, executor and canceller is the admin multisig, and only the timelock
  administers itself;
- the admin multisig and the pauser are multisigs with a threshold of at least 2, and the pauser is
  not the admin;
- on Solana the admin and the upgrade authority are the vault of a Squads multisig with no
  `config_authority`, a threshold of at least 2 and a time lock of at least 48 h.

Recommended thresholds: admin 3 of 5, pause 2 of 5, **each signer a different person on a
different device**. That last clause is where BR-4 is closed for the endpoints: a multisig whose
keys sit in one shell profile is still one key.

## 2. What the operator provides

- the owners of the admin and pause multisigs on each chain (5 addresses each is the
  recommendation), created beforehand: Safes on Ethereum and BSC at safe.global, native
  multi-signature accounts on Tron (active permission with the threshold, whose `operations` allow
  TriggerSmartContract), one Squads v4 multisig on Solana created **without** a config authority;
- gas: a few dollars on Ethereum, cents on BSC, ~100 TRX on Tron, and SOL in the Squads vault
  (the admin pays rent when a token is listed);
- the current admin keys (EVM `0xe49B…0d0e`, Solana admin `HLc2…dN2P2`, the Solana upgrade
  authority `DvV4…77kX`).

## 3. Rehearse first

- EVM: `forge test --match-contract Governance` (default profile), and the fork tests against the
  live bridges: `ETH_FORK_URL=… BSC_FORK_URL=… forge test --match-contract GovernanceFork`.
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
# 2+3. pauser, then the admin handover — signed by the CURRENT admin
BRIDGE=0xd6EBD21C3dF90c9175EBdc8d6b377a9361604892 TIMELOCK=<timelock> \
ADMIN_MULTISIG=<admin Safe> PAUSE_MULTISIG=<pause Safe> \
  forge script script/Governance.s.sol:Governance --sig "handover()" --rpc-url $RPC \
  --sender 0xe49Bd2571A549e8797bE649229F62891Fe300d0e --account bridge-admin --broadcast
# 4+5. the Safe batches (nothing is sent)
BRIDGE=0xd6EB…4892 TIMELOCK=<timelock> CHAIN_ID=<1|56> \
  forge script script/Governance.s.sol:Governance --sig "acceptProposal()" --rpc-url $RPC
```

Then: the admin Safe signs `deploy/governance/<chainid>-schedule-accept.json`; after 48 h it signs
`<chainid>-execute-accept.json`. Only then is `admin()` the timelock. Until the execute, the EOA is
still admin and can cancel with `transferAdmin(address(0))`.

Without `--broadcast` every step is a dry run. `handover()` refuses a timelock that is not the pinned
code, has an open executor, gives the sender any role, or lacks the admin Safe as proposer and
executor; and a pause multisig that is the sender, the admin Safe, or not a contract.

### Tron

```bash
OPS_PRIVATE_KEY=… node deploy/tron-ops.js deploy-timelock <admin multisig account> --yes
OPS_PRIVATE_KEY=<current admin> node deploy/tron-ops.js set-pauser <pause multisig account> --yes
OPS_PRIVATE_KEY=<current admin> node deploy/tron-ops.js transfer-admin <timelock> --yes
node deploy/tron-ops.js timelock-schedule-accept <timelock> --from <admin multisig account>
#   → deploy/governance/tron-schedule-accept.json: the multisig's signers sign it within 23 h
# after 48 h:
node deploy/tron-ops.js timelock-execute-accept <timelock> --from <admin multisig account>
#   refuses unless the operation is pending, and prints when it becomes ready
```

Each command prints the transaction it built; the signing ones refuse without `--yes`.

### Solana — upgrade authority last

```bash
export SOL_RPC_URL=https://api.mainnet-beta.solana.com SOL_PROGRAM_ID=FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu
# 1. the admin, two-step: start it with the current admin key …
rand-bridge-cli --keypair <admin HLc2…> transfer-admin --to <Squads vault>
# … and finish it FROM THE SQUADS MULTISIG (a vault transaction carrying the program's
#    AcceptAdmin instruction, signed by the vault), subject to its 48 h time lock.
rand-bridge-cli show                       # admin must now be the vault
# 2. the upgrade authority, one step and irreversible:
rand-bridge-cli --keypair <deployer DvV4…> set-upgrade-authority \
  --new <Squads vault> --confirm-new <Squads vault> --squads-multisig <multisig> --vault-index 0 --yes
```

`set-upgrade-authority` refuses unless `--new` equals `--confirm-new`, is the vault of
`--squads-multisig`, is off the Ed25519 curve, and differs from the current authority; it re-reads
the ProgramData account afterwards and fails unless the vault holds it. Do this last: until then a
mistake anywhere else is still recoverable by the old keys.

## 5. Verify

Fill the `[governance]` section (`daemons/config.example.toml` documents it: the per-chain
timelock deploy block and admin multisig, the Squads multisig, the policy) and run:

```bash
rand-bridge-audit --config daemons/mainnet/relayer.toml --governance
```

It exits non-zero unless every rule passes on every chain. Today it fails everywhere, which is the
correct reading of the current state. The role check reads `RoleGranted`/`RoleRevoked` logs from the
timelock's deployment block, so on BSC it needs an RPC that serves logs that old (a keyed one).

## 6. What this does not close

- **BR-4 (custody).** The six guardian ECDSA keys, their six Dilithium keys and the Rand pause key
  still live on one machine. Closing it means each guardian key running on a host its own operator
  controls, and the pause key held apart from all of them. The code prerequisite, rotation of the
  PQ set and the pause key under the PQ quorum, is fullnode's genesis-gated rules v2 (chain 15).
  No code in this repository can do that move; it is people and machines.
- **The Solana pauser** stays a single key. It can only pause; the timelocked admin unpauses. A
  `SetPauser` instruction would need a program upgrade, which after §4 goes through the Squads
  time lock like any other.
- **Bytecode verification of the live EVM bridge** must use the remappings of its deploy commit
  (`681f2e8`): this change lists remappings explicitly, which changes a fresh build's metadata.
