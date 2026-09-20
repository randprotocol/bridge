// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {IRandBridge} from "../src/interfaces/IRandBridge.sol";

/// @notice Post-deployment operations on an EVM endpoint, signed by a key
/// taken from the `OPS_PRIVATE_KEY` environment variable — never from the
/// command line (`cast send` only takes a key in argv).
///
/// ```
/// OPS_PRIVATE_KEY=0x... forge script script/Ops.s.sol:Ops --rpc-url $RPC --broadcast \
///     --sig "fund(address,uint256)" <to> <wei>
///     --sig "setToken(address,address,uint256,uint256)" <bridge> <token> <perTransferCap> <dailyCap>
///     --sig "lock(address,address,uint256,bytes32,uint256,uint32)" <bridge> <token> <amount> <recipientHash> <relayerFee> <nonce>
/// ```
contract Ops is Script {
    function fund(address payable to, uint256 amount) external {
        vm.startBroadcast(vm.envUint("OPS_PRIVATE_KEY"));
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
        vm.stopBroadcast();
    }

    /// Whitelists `token` from the admin key; caps are in the token's own units, 0 = unlimited.
    function setToken(address bridge, address token, uint256 perTransferCap, uint256 dailyCap) external {
        vm.startBroadcast(vm.envUint("OPS_PRIVATE_KEY"));
        IRandBridge(bridge).setToken(token, true, perTransferCap, dailyCap);
        vm.stopBroadcast();
        IRandBridge.TokenConfig memory c = IRandBridge(bridge).tokenConfig(token);
        console2.log("enabled", c.enabled);
    }

    /// Approves exactly `amount` and locks it. The approve goes through a raw call: mainnet
    /// USDT's `approve` returns nothing.
    function lock(address bridge, address token, uint256 amount, bytes32 randRecipient, uint256 relayerFee, uint32 nonce)
        external
    {
        vm.startBroadcast(vm.envUint("OPS_PRIVATE_KEY"));
        (bool ok,) = token.call(abi.encodeWithSignature("approve(address,uint256)", bridge, amount));
        require(ok, "approve failed");
        IRandBridge(bridge).lock(token, amount, randRecipient, relayerFee, nonce);
        vm.stopBroadcast();
    }
}
