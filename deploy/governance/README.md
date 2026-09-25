# BR-3 governance artefacts

Unsigned proposals for the admin multisigs, one file per step, written by the tools and
committed only after review:

- `<chainid>-schedule-accept.json`, `<chainid>-execute-accept.json` — Safe Transaction Builder
  batches from `evm/script/Governance.s.sol` `acceptProposal()` (Ethereum `1`, BSC `56`): the
  admin Safe calls `timelock.schedule(bridge, 0, acceptAdmin(), 0, salt, minDelay)`, then after
  `minDelay` `timelock.execute(...)` with the same arguments.
- `tron-<name>.json` — unsigned Tron transactions from `deploy/tron-ops.js`:
  `tron-schedule-accept.json` / `tron-execute-accept.json` (`timelock-schedule-accept` /
  `timelock-execute-accept`) and, after the handover, `tron-schedule-<call>.json` /
  `tron-execute-<call>.json` (`timelock-schedule` / `timelock-execute --call <call>`), for the
  signers of the Tron admin multi-signature account; `tron-pause.json` (`pause`) for the signers
  of the pause account.

Solana has no files here: `rand-bridge-cli --as <vault> <admin command>` prints the instruction
for a Squads vault transaction.

Design: `docs/superpowers/specs/2026-09-25-br3-governance-design.md`.
