// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {IRandBridge} from "../src/interfaces/IRandBridge.sol";
import {EthereumRandBridge} from "../src/EthereumRandBridge.sol";
import {BscRandBridge} from "../src/BscRandBridge.sol";
import {TronRandBridge} from "../src/TronRandBridge.sol";

/// @notice Deploys one Rand bridge endpoint, chosen by the `CHAIN`
/// environment variable.
///
/// ```
/// CHAIN=ethereum \
/// ADMIN=0x...            # multisig that owns the token whitelist
/// PAUSER=0x...           # pause quorum (optional; defaults to none)
/// RAND_EMITTER=0x...     # 32-byte Rand burn emitter from genesis
/// GUARDIANS=0xa,0xb,...  # guardian set 0, in index order
/// forge script script/Deploy.s.sol:Deploy --rpc-url $RPC --broadcast
/// ```
///
/// Tron is compiled here but deployed with TronBox from the Foundry
/// artifact (Section 5.4); running this script with `CHAIN=tron` against
/// an EVM node is only useful for dry runs.
contract Deploy is Script {
    function run() external returns (address bridge) {
        string memory chain = vm.envString("CHAIN");
        address admin = vm.envAddress("ADMIN");
        address pauser = vm.envOr("PAUSER", address(0));
        bytes32 randEmitter = vm.envBytes32("RAND_EMITTER");
        address[] memory guardians = vm.envAddress("GUARDIANS", ",");

        console2.log("chain        ", chain);
        console2.log("admin        ", admin);
        console2.log("pauser       ", pauser);
        console2.log("guardians    ", guardians.length);

        vm.startBroadcast();
        bytes32 which = keccak256(bytes(chain));
        if (which == keccak256("ethereum")) {
            bridge = address(new EthereumRandBridge(admin, pauser, randEmitter, guardians));
        } else if (which == keccak256("bsc")) {
            bridge = address(new BscRandBridge(admin, pauser, randEmitter, guardians));
        } else if (which == keccak256("tron")) {
            bridge = address(new TronRandBridge(admin, pauser, randEmitter, guardians));
        } else {
            revert("Deploy: CHAIN must be one of ethereum, bsc, tron");
        }
        vm.stopBroadcast();

        console2.log("bridge       ", bridge);
        console2.log("bridge chain ", IRandBridge(bridge).chainId());
    }
}
