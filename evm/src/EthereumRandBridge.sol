// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {RandBridgeBase} from "./RandBridgeBase.sol";
import {Attestation} from "./lib/Attestation.sol";

/// @title EthereumRandBridge
/// @notice The Rand bridge endpoint on Ethereum: bridge chain id 2, and
/// messages published asking guardians to wait for finality
/// (`consistency_level = 1`). All behaviour lives in
/// [RandBridgeBase]; the fork guard is active here.
contract EthereumRandBridge is RandBridgeBase {
    constructor(address admin_, address pauser_, bytes32 randEmitter_, address[] memory guardians)
        RandBridgeBase(admin_, pauser_, randEmitter_, guardians)
    {}

    function _chainId() internal pure override returns (uint16) {
        return Attestation.CHAIN_ETHEREUM;
    }

    function _consistencyLevel() internal pure override returns (uint8) {
        return 1;
    }
}
