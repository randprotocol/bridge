# BR-3: multisig and timelock over the bridge endpoints

Date: 2026-09-25. Finding: BR-3 (High) in `Rand_Security_Fixes_Report_2026-09-24.pdf`, "multisig and
timelock on the source contracts; Solana upgrade authority", still open after v0.5.6. Companion
finding BR-4 (key custody) is operational and is addressed only by the runbook in §6.

## What is true today (read on-chain 2026-09-25)

| Chain | Admin | Pauser | Upgradeable |
|---|---|---|---|
| Ethereum, BSC `0xd6EB…4892` | EOA `0xe49B…0d0e` | the same EOA | no (constructor-only) |
| Tron `TAqq…pKU` | the same key, Tron form | the same key | no |
| Solana `FGA3…vycu` | `HLc2…dN2P2` (one key) | `8bYj…jwES` (one key) | yes, upgrade authority = deployer `DvV4…77kX` |

One key can list a worthless token, raise the fee to its 1% cap, withdraw fees, unpause, and on
Solana replace the program outright. BR-3 asks that no single key can do any of that, and that
anything the admin can do is visible for a fixed delay before it takes effect.

## Design

The endpoints already hand the admin role over in two steps (`transferAdmin` then `acceptAdmin`
by the new admin, on every chain), and the new admin may be any address that can sign. So the fix
needs **no bridge redeploy and no program upgrade**: new admin holders are deployed beside the
bridge and the role is handed to them.

### EVM (Ethereum, BSC) and Tron

- **Admin → `TimelockController`** (OpenZeppelin v5, vendored, unmodified) with
  `minDelay = 172 800 s` (48 h; the script refuses anything under 24 h), proposers and executors
  = the **admin multisig**, canceller = the admin multisig (OZ grants it to proposers), and no
  timelock admin (`admin = address(0)`), so the delay can only be changed through the delay
  itself.
- **Admin multisig**: a Safe on Ethereum and BSC (the canonical Safe deployments), a native
  Tron multi-signature account (active permission, threshold) on Tron. Threshold at least 3 of 5
  distinct keyholders is the recommended policy; the audit enforces at least 2 (§5).
- **Pauser → a separate multisig** (a second Safe / Tron account), threshold lower (2 of 5
  recommended), **not** behind the timelock: pausing must stay fast. The pauser can only pause;
  `unpause` is admin-only, so after a pause the bridge restarts only through the 48 h timelock.
  That is the intended cost: a false-positive pause costs up to 48 h of downtime, a compromised
  pauser can only stop the bridge, never move funds.
- **Handover, per chain** (the EOA stays admin until the timelock accepts, and can cancel with
  `transferAdmin(address(0))` until then):
  1. deploy the timelock;
  2. EOA: `setPauser(pauseMultisig)`;
  3. EOA: `transferAdmin(timelock)`;
  4. admin multisig: `timelock.schedule(bridge, 0, acceptAdmin(), 0, salt, minDelay)`;
  5. after the delay, admin multisig: `timelock.execute(…)` — `admin()` is now the timelock.

### Solana

- **Admin → a Squads v4 vault** whose multisig has `threshold ≥ 2` and `time_lock ≥ 172 800 s`.
  The program checks only that the admin account signed and equals `Config::admin`; a Squads
  vault PDA signs through Squads' `invoke_signed`, so `AcceptAdmin`, `SetToken` (the admin also
  pays rent there: the vault must hold SOL), `Unpause`, `SetProtocolFee`, `WithdrawFees` and
  `GuardianSetUpgrade` all work unchanged.
- **Upgrade authority → the same admin vault**, via `bpf_loader_upgradeable::set_upgrade_authority`
  from `rand-bridge-cli set-upgrade-authority` (the Solana CLI is not a dependency of this repo).
  Making the program immutable instead was considered and rejected: it forbids a fix for a bug in
  the release path.
- **Pauser stays a single key.** The Solana program has no `SetPauser` instruction; adding one is
  a program upgrade on mainnet, which this change avoids. The pauser `8bYj…` is already distinct
  from the admin and can only pause. Residual risk: its theft allows repeated pauses, each undone
  by the timelocked admin. Recorded, not fixed here.

### Why not a timelock inside the bridge contracts

It would need a redeploy on four chains, a new guardian-signed emitter binding on Rand and a
custody migration. The external timelock gives the same property today.

## Components (all in this repository)

1. **`evm/lib/openzeppelin-contracts`** (v5.0.2, pinned), and a copy of `TimelockController` and
   its imports under `tron/contracts/governance/` for tronbox (same solc 0.8.20).
2. **`evm/script/Governance.s.sol`**: `deployTimelock()` (env `ADMIN_MULTISIG`, `MIN_DELAY`),
   `handover()` (env `BRIDGE`, `TIMELOCK`, `PAUSE_MULTISIG`; broadcast by the current admin), and
   `acceptProposal()`, which writes a Safe Transaction Builder batch JSON (schedule, and later
   execute) under `deploy/governance/`.
3. **`evm/test/Governance.t.sol`**: the whole handover against a locally deployed bridge, and
   what the end state refuses (§4); a fork variant against the live Ethereum and BSC bridges
   (`ETH_FORK_URL` / `BSC_FORK_URL`, skipped when unset), pranking the current admin.
4. **`deploy/tron-ops.js`**: `deploy-timelock`, `set-pauser`, `transfer-admin`,
   `timelock-schedule-accept`, `timelock-execute-accept`, each printing the transaction before it
   signs and refusing to sign without `--yes`.
5. **`rand-bridge-cli set-upgrade-authority --new <pubkey>`**, and `transfer-admin` already
   exists; `show` prints the current upgrade authority.
6. **`rand-bridge-audit --governance`**: reads each endpoint and fails (non-zero exit) unless
   - EVM/Tron: `admin()` has code and answers `getMinDelay() ≥ min_delay_secs`; `pauser() ≠
     admin()`; `pauser()` has code (EVM) and, when it is a Safe, `getThreshold() ≥ min_threshold`;
     no `pendingAdmin` outstanding;
   - Solana: `Config::admin` is the vault of the configured Squads multisig (PDA
     `["multisig", ms, "vault", index]` under `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`), that
     multisig's `threshold ≥ min_threshold` and `time_lock ≥ min_delay_secs`, and the program's
     upgrade authority is the same vault;
   - policy from an optional `[governance]` config section (`min_delay_secs = 172800`,
     `min_threshold = 2`, `solana_multisig`, `solana_vault_index = 0`).
7. **`docs/governance.md`**: the runbook (§6) and the end state per chain.

## Tests (red first)

EVM (`forge test --match-contract Governance`):
- after the handover `admin()` is the timelock and `pauser()` the pause multisig;
- the old EOA can no longer `setToken`, `setProtocolFee`, `withdrawFees`, `unpause`,
  `transferAdmin`;
- `execute` before `minDelay` reverts; after it succeeds; a non-proposer cannot `schedule`;
- the admin multisig can `cancel` a scheduled operation, which then cannot execute;
- the pause multisig pauses immediately; `unpause` works only through the timelock after the delay;
- until acceptance the EOA is still admin and `transferAdmin(address(0))` cancels the handover;
- `deployTimelock` refuses `MIN_DELAY < 86400`;
- fork variant: the same handover against the live bytecode and storage.

Solana: a unit test of the CLI's instruction builder (program id, ProgramData PDA, current and new
authority, the loader's `SetAuthority` encoding), and the program's existing admin tests unchanged.

Audit: unit tests of the Squads multisig account decoder against a captured mainnet account, the
vault PDA derivation, and the pass/fail table for each rule.

## §6 Runbook and BR-4

The runbook orders the handover so the bridge is never without a working admin: Solana upgrade
authority last. It needs, from the operator: the owners and thresholds of the admin and pause
multisigs on each chain (distinct keyholders — this is where BR-4 is actually closed for the
endpoints), gas on each chain, and the current admin keys. **Every on-chain step is irreversible
once the timelock accepts, and is run by the operator, not by this change.**

BR-4 (guardian keys, the Rand pause key and the endpoint admin on one laptop) is closed only when
each guardian key runs on a host its own operator controls; the code prerequisite (rotation under
the PQ quorum) is on fullnode's genesis-gated rules v2. The runbook lists the steps; this change
does not and cannot perform them.

## Out of scope

A `SetPauser` instruction on Solana (a program upgrade); a timelock inside the bridge contracts;
guardian-set rotation; moving keys between machines.
