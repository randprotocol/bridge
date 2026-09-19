// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

/// @title SafeTransfer
/// @notice ERC20 `transferFrom` that tolerates the tokens the
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
/// [transferUnchecked] is the one exception: it ignores the return data
/// entirely, for the caller that measures the balance delta itself. Tron
/// mainnet USDT's `transfer` moves the funds and then returns `false`
/// (its `transferFrom` returns `true`), so a payout that trusted the
/// return value could be locked into but never released from.
///
/// No allowance or balance bookkeeping lives here; `RandBridgeBase`
/// measures the balance delta itself on lock and on release, which is
/// what actually catches fee-on-transfer tokens and silent failures.
library SafeTransfer {
    error TransferFailed();

    /// `transfer` whose return data is ignored. The call must still succeed
    /// against a target with code; the caller MUST check the balance delta.
    function transferUnchecked(address token, address to, uint256 value) internal {
        if (token.code.length == 0) revert TransferFailed();
        (bool success,) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value)); // transfer(address,uint256)
        if (!success) revert TransferFailed();
    }

    function safeTransferFrom(address token, address from, address to, uint256 value) internal {
        _call(token, abi.encodeWithSelector(0x23b872dd, from, to, value)); // transferFrom(address,address,uint256)
    }

    function _call(address token, bytes memory data) private {
        // A call to an address with no code succeeds and returns nothing,
        // which the empty-return rule below would read as a successful
        // transfer. A whitelisted token can lose its code after the fact
        // (SELFDESTRUCT still applies on Tron), so a codeless target must
        // be a hard failure rather than a transfer that paid nobody.
        if (token.code.length == 0) revert TransferFailed();

        (bool success, bytes memory ret) = token.call(data);
        if (!success) revert TransferFailed();
        if (ret.length == 0) return; // USDT-style: no return value
        if (ret.length != 32 || abi.decode(ret, (bool)) == false) revert TransferFailed();
    }
}
