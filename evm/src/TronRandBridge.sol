// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {RandBridgeBase} from "./RandBridgeBase.sol";
import {Attestation} from "./lib/Attestation.sol";

/// @title TronRandBridge
/// @notice The Rand bridge endpoint on Tron: bridge chain id 4, and
/// `consistency_level = 19` (Tron's solidification depth).
///
/// Tron addresses are the same 20 bytes as Ethereum's once the base58check
/// `0x41` prefix is dropped, so the 32-byte encodings in Section 3 need no
/// translation. The one behavioural difference is the fork guard: the TVM
/// does not offer a chain id this contract can depend on, so
/// [RandBridgeBase._checkFork] is overridden to a no-op (Section 5.4).
contract TronRandBridge is RandBridgeBase {
    constructor(address admin_, address pauser_, bytes32 randEmitter_, address[] memory guardians)
        RandBridgeBase(admin_, pauser_, randEmitter_, guardians)
    {}

    function _chainId() internal pure override returns (uint16) {
        return Attestation.CHAIN_TRON;
    }

    function _consistencyLevel() internal pure override returns (uint8) {
        return 19;
    }

    /// No-op: see the contract-level note.
    function _checkFork() internal view override {}
}
