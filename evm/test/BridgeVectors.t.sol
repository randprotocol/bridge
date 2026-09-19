// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {IRandBridge} from "../src/interfaces/IRandBridge.sol";
import {EthereumRandBridge} from "../src/EthereumRandBridge.sol";
import {VectorLoader} from "./utils/VectorLoader.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// Replays the Ethereum-side cases of the shared cross-language fixture
/// `vectors/attestations.json` (the same file the Rust fullnode and the
/// Solana program verify against) through a real `EthereumRandBridge`
/// deployed with the fixture's own guardian set and Rand emitter.
///
/// Only vectors whose `verifier_chain` is 2 belong here: they are the
/// Rand-burn releases addressed to the Ethereum endpoint. Everything else
/// in the file is verified by `Vectors.t.sol` (signature-level rules) or
/// by the fullnode/Solana verifiers.
///
/// The fixture's `payload.token_address` values for chains 2..4 are
/// left-padded 20-byte contract addresses (Section 3.5), which is exactly
/// what `RandBridgeBase._releaseToken` requires; a `MockERC20` is etched
/// at each one so the release has something real to pay out.
contract BridgeVectorsTest is Test {
    uint256 constant MAX_VECTORS = 64;

    EthereumRandBridge bridge;
    string json;

    address admin = address(0xA11CE);
    address pauser = address(0xB0B);
    address user = address(0xBEEF);
    address relayer = address(0xF00D);

    uint256 okChecked;
    uint256 errorsChecked;

    function setUp() public {
        json = VectorLoader.readFile(vm);

        bridge = new EthereumRandBridge(admin, pauser, _randEmitter(), _fixtureGuardians());
        // The shared vectors pin which attestations are accepted, with
        // exact amounts; the protocol fee has its own tests.
        vm.prank(admin);
        bridge.setProtocolFee(0);

        // The fixture's attestations are timestamped just before its
        // `now`; guardian set 0 is current, so only the clock's rough
        // position matters, but keep it honest anyway.
        vm.warp(vm.parseJsonUint(json, ".now"));
    }

    function test_shared_vectors_release_on_ethereum() public {
        uint256 n = VectorLoader.vectorCount(vm, json, MAX_VECTORS);
        assertGt(n, 0, "expected at least one vector in attestations.json");

        for (uint256 i = 0; i < n; i++) {
            if (_verifierChain(i) != 2) continue;
            _checkVector(i);
        }

        assertGt(okChecked, 0, "expected at least one verifier_chain 2 `ok` vector");
        assertGt(errorsChecked, 0, "expected at least one verifier_chain 2 failure vector");
        emit log_named_uint("ethereum vectors released", okChecked);
        emit log_named_uint("ethereum vectors rejected", errorsChecked);
    }

    /// The fixture's governance pair, run through a real contract: apply
    /// `upgrade_set1_ok` (signed by set 0, which is current), then present
    /// `upgrade_signed_by_superseded_set` — the same shape of message, from
    /// the same governance emitter, signed by set 0 while set 0 is still
    /// inside its grace window but no longer current.
    ///
    /// Both are `verifier_chain` 1 vectors, so the release loop above skips
    /// them; `submitGuardianSetUpgrade` is chain-agnostic (it binds on the
    /// governance emitter, not on `to_chain`), so the rule is checkable
    /// here against the shared fixture rather than only against the
    /// locally-built attestations of `RandBridge.t.sol`.
    function test_shared_vectors_reject_an_upgrade_from_a_superseded_set() public {
        (bool foundFirst, uint256 first) = _findVector("upgrade_set1_ok");
        (bool foundStale, uint256 stale) = _findVector("upgrade_signed_by_superseded_set");
        assertTrue(foundFirst, "upgrade_set1_ok missing from the fixture");
        assertTrue(foundStale, "upgrade_signed_by_superseded_set missing from the fixture");

        bridge.submitGuardianSetUpgrade(VectorLoader.loadVector(vm, json, first).attestation);
        assertEq(bridge.currentGuardianSetIndex(), 1, "fixture upgrade rotated the set");
        assertGt(bridge.guardianSet(0).expirationTime, block.timestamp, "set 0 is still inside its grace window");

        VectorLoader.Vector memory v = VectorLoader.loadVector(vm, json, stale);
        assertEq(v.guardianSetIndex, 0, "the stale vector must claim the superseded set");
        (bool ok, bytes memory ret) = address(bridge).call(
            abi.encodeWithSelector(IRandBridge.submitGuardianSetUpgrade.selector, v.attestation)
        );
        assertFalse(ok, string.concat(v.name, ": expected submitGuardianSetUpgrade() to revert"));
        require(ret.length >= 4, "BridgeVectorsTest: revert data too short to contain a selector");
        bytes4 got;
        assembly {
            got := mload(add(ret, 32))
        }
        assertTrue(got == IRandBridge.GuardianSetExpired.selector, string.concat(v.name, ": wrong revert selector"));
        assertEq(bridge.currentGuardianSetIndex(), 1, "no rotation happened");
    }

    function _checkVector(uint256 i) internal {
        VectorLoader.Vector memory v = VectorLoader.loadVector(vm, json, i);

        address token = _prepareToken(i);
        uint256 amount = _denorm(_payloadUint(i, "amount"));
        uint256 fee = _denorm(_payloadUint(i, "fee"));
        address to = address(uint160(uint256(_payloadWord(i, "to"))));

        if (VectorLoader.stringEq(v.expect, "ok")) {
            _fundCustody(token, amount);
            uint256 toBefore = MockERC20(token).balanceOf(to);
            uint256 relayerBefore = MockERC20(token).balanceOf(relayer);

            vm.prank(relayer);
            bridge.release(v.attestation);

            assertTrue(bridge.consumed(v.digest), string.concat(v.name, ": digest not consumed"));
            assertEq(
                MockERC20(token).balanceOf(to) - toBefore, amount - fee, string.concat(v.name, ": recipient payout")
            );
            assertEq(MockERC20(token).balanceOf(relayer) - relayerBefore, fee, string.concat(v.name, ": relayer fee"));
            okChecked++;
            return;
        }

        if (VectorLoader.stringEq(v.expect, "replay")) {
            // The vector this one replays is itself an `ok` vector on this
            // chain, so the loop has usually released it already. Submit it
            // only if it has not been: releasing it twice here would revert
            // with the very error the assertion below is meant to prove.
            (bool found, uint256 j) = _findVector(vm.parseJsonString(json, string.concat(_base(i), ".replay_of")));
            assertTrue(found, string.concat(v.name, ": replay_of vector not found"));
            VectorLoader.Vector memory original = VectorLoader.loadVector(vm, json, j);
            if (!bridge.consumed(original.digest)) {
                address originalToken = _prepareToken(j);
                _fundCustody(originalToken, _denorm(_payloadUint(j, "amount")));
                vm.prank(relayer);
                bridge.release(original.attestation);
            }
            assertTrue(bridge.consumed(original.digest), string.concat(v.name, ": original was never released"));

            _expectRevert(v, IRandBridge.AlreadyConsumed.selector);
            return;
        }
        if (VectorLoader.stringEq(v.expect, "wrong_emitter")) {
            _expectRevert(v, IRandBridge.WrongEmitter.selector);
            return;
        }
        if (VectorLoader.stringEq(v.expect, "wrong_to_chain")) {
            _expectRevert(v, IRandBridge.WrongToChain.selector);
            return;
        }
        if (VectorLoader.stringEq(v.expect, "wrong_token_chain")) {
            _expectRevert(v, IRandBridge.WrongTokenChain.selector);
            return;
        }
        if (VectorLoader.stringEq(v.expect, "fee_exceeds_amount")) {
            _expectRevert(v, IRandBridge.FeeExceedsAmount.selector);
            return;
        }
        // Any other `expect` code is a rule this contract does not own
        // (`amount_overflow` is Rand's u128 bound, for instance).
    }

    /// A low-level call (rather than `vm.expectRevert`) so the failure
    /// message can name the vector, exactly as `Vectors.t.sol` does.
    function _expectRevert(VectorLoader.Vector memory v, bytes4 selector) internal {
        vm.prank(relayer);
        (bool ok, bytes memory ret) =
            address(bridge).call(abi.encodeWithSelector(IRandBridge.release.selector, v.attestation));
        assertFalse(ok, string.concat(v.name, ": expected release() to revert"));
        require(ret.length >= 4, "BridgeVectorsTest: revert data too short to contain a selector");
        bytes4 got;
        assembly {
            got := mload(add(ret, 32))
        }
        assertTrue(got == selector, string.concat(v.name, ": wrong revert selector"));
        errorsChecked++;
    }

    // ------------------------------------------------------------------
    // fixture plumbing
    // ------------------------------------------------------------------

    function _base(uint256 i) internal pure returns (string memory) {
        return string.concat(".vectors[", vm.toString(i), "]");
    }

    function _verifierChain(uint256 i) internal view returns (uint256) {
        return vm.parseJsonUint(json, string.concat(_base(i), ".verifier_chain"));
    }

    /// Amounts and fees are decimal strings in the fixture (they are u256
    /// on the wire and would not survive a JSON number).
    function _payloadUint(uint256 i, string memory field) internal view returns (uint256) {
        return vm.parseUint(vm.parseJsonString(json, string.concat(_base(i), ".payload.", field)));
    }

    function _payloadWord(uint256 i, string memory field) internal view returns (bytes32) {
        return VectorLoader.hexToBytes32(vm.parseJsonString(json, string.concat(_base(i), ".payload.", field)));
    }

    function _findVector(string memory name) internal view returns (bool, uint256) {
        uint256 n = VectorLoader.vectorCount(vm, json, MAX_VECTORS);
        for (uint256 i = 0; i < n; i++) {
            if (VectorLoader.stringEq(vm.parseJsonString(json, string.concat(_base(i), ".name")), name)) {
                return (true, i);
            }
        }
        return (false, 0);
    }

    function _randEmitter() internal view returns (bytes32) {
        return VectorLoader.hexToBytes32(vm.parseJsonString(json, ".rand_emitter"));
    }

    function _fixtureGuardians() internal view returns (address[] memory keys) {
        uint256 n = 0;
        while (vm.keyExistsJson(json, string.concat(".guardians[", vm.toString(n), "]"))) {
            n++;
        }
        keys = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            keys[i] = VectorLoader.hexToAddress(
                vm.parseJsonString(json, string.concat(".guardians[", vm.toString(i), "].address"))
            );
        }
    }

    /// The fixture's tokens are 6-decimal USDT stand-ins. Etches a
    /// `MockERC20` at the payload's token address (low 20 bytes) if there
    /// isn't one yet, and whitelists it.
    function _prepareToken(uint256 i) internal returns (address token) {
        token = address(uint160(uint256(_payloadWord(i, "token_address"))));
        if (token.code.length == 0) {
            deployCodeTo("MockERC20.sol:MockERC20", abi.encode("USDT", "USDT", uint8(6)), token);
        }
        if (!bridge.tokenConfig(token).enabled) {
            vm.prank(admin);
            bridge.setToken(token, true, 0, 0);
        }
    }

    /// Custody is only ever created by a lock, so fund it the honest way.
    ///
    /// Tops up only the shortfall, and does nothing when custody already
    /// covers `units`, so a token is funded once across the whole pass
    /// however many vectors name it.
    function _fundCustody(address token, uint256 units) internal {
        if (units == 0 || bridge.custody(token) >= units) return;
        uint256 missing = units - bridge.custody(token);
        MockERC20(token).mint(user, missing);
        vm.startPrank(user);
        MockERC20(token).approve(address(bridge), missing);
        bridge.lock(token, missing, keccak256("rand-recipient"), 0, 0);
        vm.stopPrank();
    }

    function _denorm(uint256 attested) internal pure returns (uint256) {
        return attested / 100; // 8 attested decimals -> 6 token decimals
    }
}
