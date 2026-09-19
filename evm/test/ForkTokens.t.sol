// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

import {RandBridgeTest} from "./RandBridge.t.sol";
import {RandBridgeBase} from "../src/RandBridgeBase.sol";
import {EthereumRandBridge} from "../src/EthereumRandBridge.sol";
import {BscRandBridge} from "../src/BscRandBridge.sol";

interface IToken {
    function balanceOf(address) external view returns (uint256);
    function decimals() external view returns (uint8);
}

/// The bridge against the *real* USDT and USDC contracts, on a fork of
/// Ethereum and of BNB Smart Chain: a lock, then a release with a relayer
/// fee and the 10 bps protocol fee, then a fee withdrawal. These are the
/// tokens the launch policy names (`docs/architecture.md` §10.1), and each
/// has its own quirks — Ethereum USDT returns nothing from `transfer` /
/// `transferFrom` / `approve`, USDC sits behind a proxy with a blacklist,
/// the BSC pegs have 18 decimals — which a mock only imitates.
///
/// Skipped unless a fork URL is given:
///
///   FOUNDRY_PROFILE=fork ETH_FORK_URL=... BSC_FORK_URL=... forge test --match-contract ForkTokensTest
///
/// (the `fork` profile runs a Cancun EVM: the live token implementations use
/// opcodes the deployment profile's `paris` does not have).
///
/// Tron and Solana cannot be forked here; Tron USDT's `transfer`-returns-false
/// shape is covered by `test_release_tron_usdt_style_transfer_returns_false`.
contract ForkTokensTest is RandBridgeTest {
    address constant ETH_USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant ETH_USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant BSC_USDT = 0x55d398326f99059fF775485246999027B3197955;
    address constant BSC_USDC = 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d;

    address treasury = address(0x7EA5);

    function test_fork_ethereum_usdt_and_usdc() public {
        string memory url = vm.envOr("ETH_FORK_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        RandBridgeBase b = new EthereumRandBridge(admin, pauser, randEmitter, guardians);
        _roundTrip(b, ETH_USDT, 2, 6);
        _roundTrip(b, ETH_USDC, 2, 6);
    }

    function test_fork_bsc_usdt_and_usdc() public {
        string memory url = vm.envOr("BSC_FORK_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(url);
        RandBridgeBase b = new BscRandBridge(admin, pauser, randEmitter, guardians);
        _roundTrip(b, BSC_USDT, 3, 18);
        _roundTrip(b, BSC_USDC, 3, 18);
    }

    /// Lock 100 tokens, release 40 of them with a 1-token relayer fee.
    function _roundTrip(RandBridgeBase b, address token, uint16 chain, uint8 decimals) internal {
        bridge = EthereumRandBridge(address(b)); // the helpers sign for `bridge`
        assertEq(IToken(token).decimals(), decimals, "decimals as documented");
        uint256 unit = 10 ** uint256(decimals);

        vm.prank(admin);
        b.setToken(token, true, 0, 0);

        deal(token, user, 100 * unit);
        vm.startPrank(user);
        // Ethereum USDT's `approve` returns nothing: a typed call would
        // revert on decoding, so it goes out low-level, as a wallet's would.
        (bool ok,) = token.call(abi.encodeWithSignature("approve(address,uint256)", address(b), 100 * unit));
        assertTrue(ok, "approve");
        b.lock(token, 100 * unit, keccak256("rand-recipient"), 0, 0);
        vm.stopPrank();

        assertEq(b.custody(token), 100 * unit, "a deposit is free: the whole amount is in custody");
        assertEq(b.accruedFees(token), 0);
        assertEq(IToken(token).balanceOf(address(b)), 100 * unit);

        // 40 tokens at 8 decimals, 1 of them the relayer's.
        uint256 recipientBefore = IToken(token).balanceOf(recipient);
        uint256 relayerBefore = IToken(token).balanceOf(relayer);
        bytes memory att =
            _fromRand(_transferPayload(40 * 1e8, _word(token), chain, _word(recipient), chain, 1 * 1e8));
        vm.prank(relayer);
        b.release(att);

        uint256 protocolFee = 40 * unit * 10 / 10_000; // 10 bps
        assertEq(IToken(token).balanceOf(relayer) - relayerBefore, 1 * unit, "relayer fee");
        assertEq(IToken(token).balanceOf(recipient) - recipientBefore, 39 * unit - protocolFee, "recipient");
        assertEq(b.accruedFees(token), protocolFee);
        assertEq(b.custody(token), 60 * unit);
        assertEq(IToken(token).balanceOf(address(b)), 60 * unit + protocolFee, "custody + fees, nothing else");

        vm.prank(admin);
        b.withdrawFees(token, treasury, protocolFee);
        assertEq(IToken(token).balanceOf(treasury), protocolFee);
        assertEq(IToken(token).balanceOf(address(b)), b.custody(token), "only custody is left");

        // The same attestation cannot pay twice.
        vm.expectRevert();
        b.release(att);
    }
}
