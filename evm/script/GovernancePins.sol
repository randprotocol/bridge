// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

/// Pins for the BR-3 governance handover (`script/Governance.s.sol`), in one place.
library GovernancePins {
    /// keccak256 of the runtime code of OpenZeppelin Contracts v5.0.2
    /// (commit dbb6104ce834628e473d2173bbc9d47f81a9eec3, unmodified) `TimelockController`, as
    /// this project compiles it: solc 0.8.20, optimizer on with 200 runs, evm_version paris
    /// (the default profile in `evm/foundry.toml`, including its explicit remappings, which
    /// are part of the CBOR metadata and therefore of this hash). The contract has no
    /// immutables, so this is also the `extcodehash` of every timelock `deployTimelock()`
    /// deploys; `rand-bridge-audit --governance` pins the same value.
    ///
    /// Compiled under the `fork` profile (evm_version cancun) the hash differs, and the
    /// handover refuses: run the governance script and its tests in the default profile.
    bytes32 internal constant TIMELOCK_RUNTIME_CODEHASH =
        0x0d2bd8c8c03557dfa0cf0c98e03a94e37f3096a23cdbfda03ab5541f4fd0bac3;
}
