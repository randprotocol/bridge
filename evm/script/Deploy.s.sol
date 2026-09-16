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
/// DEPLOYER_PRIVATE_KEY=0x...  # optional: sign with this key (see below)
/// forge script script/Deploy.s.sol:Deploy --rpc-url $RPC --broadcast
/// ```
///
/// The deployer key is taken from `DEPLOYER_PRIVATE_KEY` when that
/// variable is set, so the key stays in the environment rather than on
/// the command line where `ps` and shell history could see it. Leave it
/// unset to sign with whatever `forge script` was given instead
/// (`--private-key`, `--account`, `--ledger`, ...). `deploy/evm.sh` is
/// the wrapper that loads the key from `deploy/.env` and runs this.
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

        // `DEPLOY_CHAIN_ID` is baked in at construction and guards every
        // lock and release afterwards, so deploying the wrong contract for
        // the connected network would produce a bridge that can never
        // move value. Mainnet ids are the default; set `EXPECTED_CHAIN_ID`
        // for a testnet (Sepolia 11155111, BSC testnet 97, ...).
        uint256 expected = vm.envOr("EXPECTED_CHAIN_ID", uint256(0));

        uint256 deployerKey = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0));
        if (deployerKey != 0) {
            console2.log("deployer     ", vm.addr(deployerKey));
            vm.startBroadcast(deployerKey);
        } else {
            vm.startBroadcast();
        }
        bytes32 which = keccak256(bytes(chain));
        if (which == keccak256("ethereum")) {
            _requireChainId(expected == 0 ? 1 : expected);
            bridge = address(new EthereumRandBridge(admin, pauser, randEmitter, guardians));
        } else if (which == keccak256("bsc")) {
            _requireChainId(expected == 0 ? 56 : expected);
            bridge = address(new BscRandBridge(admin, pauser, randEmitter, guardians));
        } else if (which == keccak256("tron")) {
            // The TVM has no chain id this script can rely on, which is
            // why `TronRandBridge` drops the fork guard too.
            bridge = address(new TronRandBridge(admin, pauser, randEmitter, guardians));
        } else {
            revert("Deploy: CHAIN must be one of ethereum, bsc, tron");
        }
        vm.stopBroadcast();

        console2.log("bridge       ", bridge);
        console2.log("bridge chain ", IRandBridge(bridge).chainId());
    }

    function _requireChainId(uint256 expected) internal view {
        if (block.chainid != expected) {
            revert(
                string.concat(
                    "Deploy: connected to chain id ",
                    vm.toString(block.chainid),
                    " but CHAIN expects ",
                    vm.toString(expected),
                    " (set EXPECTED_CHAIN_ID for a testnet)"
                )
            );
        }
    }
}
