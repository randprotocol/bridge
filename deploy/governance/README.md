# BR-3 governance artefacts

Unsigned proposals for the admin multisigs, one file per step, written by the tools and
committed only after review:

- `<chainid>-schedule-accept.json`, `<chainid>-execute-accept.json` — Safe Transaction Builder
  batches from `evm/script/Governance.s.sol` `acceptProposal()` (Ethereum `1`, BSC `56`): the
  admin Safe calls `timelock.schedule(bridge, 0, acceptAdmin(), 0, salt, minDelay)`, then after
  `minDelay` `timelock.execute(...)` with the same arguments.
- `tron-<name>.json` — unsigned Tron transactions from `deploy/tron-ops.js`
  `timelock-schedule-accept` / `timelock-execute-accept`, for the signers of the Tron admin
  multi-signature account.

Design: `docs/superpowers/specs/2026-09-25-br3-governance-design.md`.
