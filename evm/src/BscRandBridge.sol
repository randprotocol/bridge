// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {RandBridgeBase} from "./RandBridgeBase.sol";
import {Attestation} from "./lib/Attestation.sol";

/// @title BscRandBridge
/// @notice The Rand bridge endpoint on BNB Smart Chain: bridge chain id
/// 3, and `consistency_level = 15` (BSC reorgs deeper than Ethereum, so
/// guardians are asked to wait 15 blocks). BSC's USDT and USDC carry 18
/// decimals, so this deployment exercises the truncating half of
/// Section 3.7's normalisation for real.
contract BscRandBridge is RandBridgeBase {
    constructor(address admin_, address pauser_, bytes32 randEmitter_, address[] memory guardians)
        RandBridgeBase(admin_, pauser_, randEmitter_, guardians)
    {}

    function _chainId() internal pure override returns (uint16) {
        return Attestation.CHAIN_BSC;
    }

    function _consistencyLevel() internal pure override returns (uint8) {
        return 15;
    }
}
