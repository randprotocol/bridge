// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @title SafeTransfer
/// @notice ERC20 `transfer`/`transferFrom` that tolerates the tokens the
/// standard does not describe:
///
/// - tokens that return nothing at all (mainnet USDT is the canonical
///   example: its `transfer` has no return value, so a `bool`-typed
///   Solidity call against it reverts on ABI decoding);
/// - tokens that return `false` instead of reverting.
///
/// A call is accepted only when the low-level call itself succeeded *and*
/// the return data is either empty or decodes to `true`. Anything else
/// (a revert, `false`, or a short/garbage return) reverts
/// [TransferFailed], so a silent failure can never be mistaken for a
/// payout.
///
/// No allowance or balance bookkeeping lives here; `RandBridgeBase`
/// measures the balance delta itself on lock, which is what actually
/// catches fee-on-transfer tokens.
library SafeTransfer {
    error TransferFailed();

    function safeTransfer(address token, address to, uint256 value) internal {
        _call(token, abi.encodeWithSelector(0xa9059cbb, to, value)); // transfer(address,uint256)
    }

    function safeTransferFrom(address token, address from, address to, uint256 value) internal {
        _call(token, abi.encodeWithSelector(0x23b872dd, from, to, value)); // transferFrom(address,address,uint256)
    }

    function _call(address token, bytes memory data) private {
        (bool success, bytes memory ret) = token.call(data);
        if (!success) revert TransferFailed();
        if (ret.length == 0) return; // USDT-style: no return value
        if (ret.length != 32 || abi.decode(ret, (bool)) == false) revert TransferFailed();
    }
}
