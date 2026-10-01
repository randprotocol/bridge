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
///     --sig "pause(address)" <bridge>
///     --sig "setProtocolFee(address,uint16)" <bridge> <bps>
///     --sig "replay(address,bytes)" <bridge> <calldata of an earlier transaction to that endpoint's ABI>
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

    /// Stops lock and release (the pauser or the admin may; only the admin unpauses).
    function pause(address bridge) external {
        vm.startBroadcast(vm.envUint("OPS_PRIVATE_KEY"));
        IRandBridge(bridge).pause();
        vm.stopBroadcast();
    }

    /// Sends `data` to `bridge` as is: the calldata of an earlier `release` or
    /// `submitGuardianSetUpgrade`, replayed onto another endpoint (the consume step after a
    /// redeploy). Any funded key may send it.
    function replay(address bridge, bytes calldata data) external {
        vm.startBroadcast(vm.envUint("OPS_PRIVATE_KEY"));
        (bool ok, bytes memory ret) = bridge.call(data);
        vm.stopBroadcast();
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    /// Sets the endpoint's release skim (admin only, at most 100 bps). 0 from Rand chain 20 on,
    /// where the bridge fee is taken in zUSD on Rand instead.
    function setProtocolFee(address bridge, uint16 bps) external {
        vm.startBroadcast(vm.envUint("OPS_PRIVATE_KEY"));
        IRandBridge(bridge).setProtocolFee(bps);
        vm.stopBroadcast();
        console2.log("protocolFeeBps", IRandBridge(bridge).protocolFeeBps());
    }
}
