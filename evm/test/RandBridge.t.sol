// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {Attestation} from "../src/lib/Attestation.sol";
import {SafeTransfer} from "../src/lib/SafeTransfer.sol";
import {IRandBridge} from "../src/interfaces/IRandBridge.sol";
import {EthereumRandBridge} from "../src/EthereumRandBridge.sol";
import {BscRandBridge} from "../src/BscRandBridge.sol";
import {TronRandBridge} from "../src/TronRandBridge.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// Unit tests for `RandBridgeBase` through `EthereumRandBridge` (chain id
/// 2), covering every rule in design Section 5.1: normalisation on lock,
/// denormalisation plus custody/caps on release, emitter and chain
/// binding, replay, guardian rotation and its grace period, the pause and
/// admin roles, and the fork guard (present on Ethereum/BSC, disabled on
/// Tron).
///
/// Attestations are built here rather than read from the shared fixture
/// (see `BridgeVectors.t.sol` for that): six guardians with private keys
/// 1..6, five signatures per message (quorum for n = 6 is 6*2/3 + 1 = 5).
contract RandBridgeTest is Test {
    // Mirrors of the events asserted below. Solidity 0.8.20 cannot `emit`
    // an event through a qualified interface name, so they are redeclared
    // here; the ABI-level signatures are what `vm.expectEmit` compares.
    event MessagePublished(uint64 indexed sequence, uint32 nonce, uint8 consistencyLevel, bytes payload);
    event Locked(
        address indexed token,
        address indexed from,
        bytes32 indexed randRecipient,
        uint256 locked,
        uint256 attested,
        uint64 sequence
    );
    event Released(address indexed token, address indexed to, uint256 amount, uint256 fee, bytes32 digest);
    event TokenConfigured(address indexed token, bool enabled, uint256 perTransferCap, uint256 dailyCap);
    event GuardianSetUpgraded(uint32 indexed index, address[] keys);
    event Paused(address by);
    event Unpaused(address by);
    event AdminTransferStarted(address indexed to);
    event AdminTransferred(address indexed to);
    event PauserSet(address indexed pauser);

    EthereumRandBridge bridge;

    MockERC20 t6; // 6 decimals, the Ethereum USDT shape
    MockERC20 t8; // 8 decimals, so token units == attested units
    MockERC20 t18; // 18 decimals, the BSC shape

    address admin = address(0xA11CE);
    address pauser = address(0xB0B);
    address user = address(0xBEEF);
    address relayer = address(0xF00D);
    address recipient = address(0xCAFE);

    bytes32 randEmitter = keccak256("rand-emitter-test");

    uint256[] guardianKeys; // private keys of guardian set 0
    address[] guardians; // addresses of guardian set 0
    uint256[] newGuardianKeys; // private keys of guardian set 1
    address[] newGuardians;

    /// Body sequence counter, so every attestation built here has a
    /// distinct digest.
    uint64 nextSeq;

    function setUp() public {
        for (uint256 i = 1; i <= 6; i++) {
            guardianKeys.push(i);
            guardians.push(vm.addr(i));
            newGuardianKeys.push(100 + i);
            newGuardians.push(vm.addr(100 + i));
        }

        bridge = new EthereumRandBridge(admin, pauser, randEmitter, guardians);

        t6 = new MockERC20("USD Tether", "USDT", 6);
        t8 = new MockERC20("Eight", "EIGHT", 8);
        t18 = new MockERC20("Wrapped", "WRAP", 18);

        vm.startPrank(admin);
        bridge.setToken(address(t6), true, 0, 0);
        bridge.setToken(address(t8), true, 0, 0);
        bridge.setToken(address(t18), true, 0, 0);
        vm.stopPrank();

        _fund(t6, 1_000_000_000);
        _fund(t8, 1_000_000_000);
        _fund(t18, 1_000_000 ether);

        // A realistic timestamp: `block.timestamp` feeds the daily window
        // and the guardian grace period.
        vm.warp(1_800_000_000);
    }

    function _fund(MockERC20 token, uint256 amount) internal {
        token.mint(user, amount);
        vm.prank(user);
        token.approve(address(bridge), type(uint256).max);
    }

    // ------------------------------------------------------------------
    // attestation construction
    // ------------------------------------------------------------------

    function _bodyBytes(uint16 emitterChain, bytes32 emitter, uint64 seq, uint8 consistency, bytes memory payload)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(uint32(block.timestamp), uint32(0), emitterChain, emitter, seq, consistency, payload);
    }

    /// Signs `body` with `signers`, assigning guardian index `i` to
    /// `signers[i]` (so `signers` must be a prefix of the guardian set,
    /// keeping the wire's strictly-increasing index rule satisfied).
    function _attestWith(uint32 setIndex, uint256[] memory signers, bytes memory body)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 digest = keccak256(abi.encodePacked(keccak256(body)));
        bytes memory sigs;
        for (uint8 i = 0; i < signers.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(signers[i], digest);
            sigs = abi.encodePacked(sigs, i, r, s, v - 27);
        }
        return abi.encodePacked(uint8(1), setIndex, uint8(signers.length), sigs, body);
    }

    function _quorumOf(uint256[] memory keys) internal pure returns (uint256[] memory out) {
        out = new uint256[](5);
        for (uint256 i = 0; i < 5; i++) {
            out[i] = keys[i];
        }
    }

    function _transferPayload(uint256 amount, bytes32 token, uint16 tokenChain, bytes32 to, uint16 toChain, uint256 fee)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(uint8(1), amount, token, tokenChain, to, toChain, fee);
    }

    /// The common release payload: token on this chain, to this chain, to
    /// `recipient`.
    function _releasePayload(address token, uint256 amount, uint256 fee) internal view returns (bytes memory) {
        return _transferPayload(amount, _word(token), 2, _word(recipient), 2, fee);
    }

    function _word(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    /// A full attestation from the Rand burn emitter, signed by set 0.
    function _fromRand(bytes memory payload) internal returns (bytes memory) {
        return _attestWith(0, _quorumOf(guardianKeys), _bodyBytes(1, randEmitter, nextSeq++, 1, payload));
    }

    function _digestOf(bytes memory attestation) internal pure returns (bytes32) {
        // envelope header (6) + 66 bytes per signature, then the body.
        uint256 nSigs = uint256(uint8(attestation[5]));
        uint256 start = 6 + 66 * nSigs;
        bytes memory body = new bytes(attestation.length - start);
        for (uint256 i = 0; i < body.length; i++) {
            body[i] = attestation[start + i];
        }
        return keccak256(abi.encodePacked(keccak256(body)));
    }

    function _upgradePayload(uint32 newIndex, address[] memory keys) internal pure returns (bytes memory p) {
        p = abi.encodePacked(uint8(2), newIndex, uint8(keys.length));
        for (uint256 i = 0; i < keys.length; i++) {
            p = abi.encodePacked(p, bytes20(keys[i]));
        }
    }

    function _governance(uint32 newIndex, address[] memory keys) internal returns (bytes memory) {
        return _governanceBy(0, guardianKeys, newIndex, keys);
    }

    /// A governance upgrade claiming guardian set `setIndex` and signed by
    /// a quorum of `signers`, so a test can present a rotation signed by a
    /// set other than the current one.
    function _governanceBy(uint32 setIndex, uint256[] memory signers, uint32 newIndex, address[] memory keys)
        internal
        returns (bytes memory)
    {
        return _attestWith(
            setIndex,
            _quorumOf(signers),
            _bodyBytes(1, Attestation.GOVERNANCE_EMITTER, nextSeq++, 0, _upgradePayload(newIndex, keys))
        );
    }

    // ------------------------------------------------------------------
    // lock
    // ------------------------------------------------------------------

    function test_lock_pulls_normalised_amount_6dp() public {
        uint256 userBefore = t6.balanceOf(user);

        vm.prank(user);
        uint64 seq = bridge.lock(address(t6), 1_234_567, keccak256("rand-recipient"), 0, 7);

        assertEq(seq, 0, "first sequence is 0");
        assertEq(bridge.sequence(), 1, "sequence incremented after use");
        assertEq(t6.balanceOf(user), userBefore - 1_234_567, "pulled exactly `locked`");
        assertEq(t6.balanceOf(address(bridge)), 1_234_567, "custody balance");
        assertEq(bridge.custody(address(t6)), 1_234_567, "custody counter");

        (uint256 locked, uint256 attested) = bridge.normalize(1_234_567, 6);
        assertEq(locked, 1_234_567, "6dp locks the full amount");
        assertEq(attested, 123_456_700, "6dp scales up by 10^2");
        assertEq(bridge.denormalize(attested, 6), 1_234_567, "round trip");
    }

    function test_lock_truncates_18dp() public {
        uint256 amount = 1 ether + 123;

        vm.prank(user);
        bridge.lock(address(t18), amount, keccak256("rand-recipient"), 0, 0);

        assertEq(bridge.custody(address(t18)), 1 ether, "dust below 10^10 is not locked");
        assertEq(t18.balanceOf(address(bridge)), 1 ether, "only `locked` was pulled");

        (uint256 locked, uint256 attested) = bridge.normalize(amount, 18);
        assertEq(locked, 1 ether, "locked is truncated to attestable units");
        assertEq(attested, 1e8, "1e18 wei is 1.0 at 8 decimals");
    }

    function test_lock_rejects_zero_recipient_disabled_token_fee_gt_amount_paused_dust() public {
        vm.expectRevert(IRandBridge.ZeroRecipient.selector);
        vm.prank(user);
        bridge.lock(address(t6), 1000, bytes32(0), 0, 0);

        MockERC20 stranger = new MockERC20("Stranger", "STR", 6);
        stranger.mint(user, 1000);
        vm.expectRevert(IRandBridge.TokenDisabled.selector);
        vm.prank(user);
        bridge.lock(address(stranger), 1000, keccak256("r"), 0, 0);

        vm.expectRevert(IRandBridge.FeeExceedsAmount.selector);
        vm.prank(user);
        bridge.lock(address(t6), 1000, keccak256("r"), 1001, 0);

        // 18 decimals, amount 1 wei: `attested` truncates to zero, so no
        // attestation could ever cover it.
        vm.expectRevert(IRandBridge.ZeroAmount.selector);
        vm.prank(user);
        bridge.lock(address(t18), 1, keccak256("r"), 0, 0);

        vm.prank(pauser);
        bridge.pause();
        vm.expectRevert(IRandBridge.IsPaused.selector);
        vm.prank(user);
        bridge.lock(address(t6), 1000, keccak256("r"), 0, 0);
    }

    /// Rand holds a bridged amount in a note whose amount field is a
    /// `u64`, and refuses an attestation above that at admission time
    /// (`BridgeError::AmountTooLarge`). A lock the endpoint accepted but
    /// Rand can never mint would leave the tokens in custody with no
    /// burn that could ever release them, so the endpoint refuses first.
    function test_lock_rejects_attested_amount_above_u64() public {
        uint256 max = uint256(type(uint64).max);
        t8.mint(user, max + 1);

        // 8 decimals: attested == amount, so the bound is exact.
        vm.expectRevert(IRandBridge.AmountTooLarge.selector);
        vm.prank(user);
        bridge.lock(address(t8), max + 1, keccak256("r"), 0, 0);

        vm.prank(user);
        bridge.lock(address(t8), max, keccak256("r"), 0, 0);
        assertEq(bridge.custody(address(t8)), max, "u64::MAX itself is attestable");

        // 6 decimals scale up by 100 on the way to the wire, so the bound
        // is hit at a hundredth of the native amount.
        uint256 native = max / 100 + 1;
        t6.mint(user, native);
        vm.expectRevert(IRandBridge.AmountTooLarge.selector);
        vm.prank(user);
        bridge.lock(address(t6), native, keccak256("r"), 0, 0);
    }

    function test_lock_rejects_fee_on_transfer_token() public {
        t6.setFee(100); // 1%

        vm.expectRevert(IRandBridge.TransferAmountMismatch.selector);
        vm.prank(user);
        bridge.lock(address(t6), 1_000_000, keccak256("r"), 0, 0);

        assertEq(bridge.custody(address(t6)), 0, "nothing custodied");
    }

    function test_lock_emits_payload_matching_encodeTransfer() public {
        bytes32 randRecipient = keccak256("rand-recipient");

        bytes memory expected = Attestation.encodeTransfer(
            Attestation.Transfer({
                amount: 123_456_700,
                tokenAddress: _word(address(t6)),
                tokenChain: 2,
                to: randRecipient,
                toChain: 1,
                fee: 100_000 // 1000 units at 6dp -> 1e5 at 8dp
            })
        );

        vm.expectEmit(true, false, false, true, address(bridge));
        emit MessagePublished(0, 42, 1, expected);
        vm.expectEmit(true, true, true, true, address(bridge));
        emit Locked(address(t6), user, randRecipient, 1_234_567, 123_456_700, 0);

        vm.prank(user);
        bridge.lock(address(t6), 1_234_567, randRecipient, 1000, 42);
    }

    // ------------------------------------------------------------------
    // release
    // ------------------------------------------------------------------

    function _lock8(uint256 amount) internal {
        vm.prank(user);
        bridge.lock(address(t8), amount, keccak256("rand-recipient"), 0, 0);
    }

    function test_release_pays_recipient_and_relayer() public {
        _lock8(1000);

        bytes memory att = _fromRand(_releasePayload(address(t8), 1000, 10));
        bytes32 digest = _digestOf(att);

        vm.expectEmit(true, true, false, true, address(bridge));
        emit Released(address(t8), recipient, 1000, 10, digest);

        vm.prank(relayer);
        bridge.release(att);

        assertEq(t8.balanceOf(recipient), 990, "recipient gets amount - fee");
        assertEq(t8.balanceOf(relayer), 10, "submitter gets the relayer fee");
        assertEq(bridge.custody(address(t8)), 0, "custody drained");
        assertTrue(bridge.consumed(digest), "digest consumed");
    }

    function test_release_rejects_replay_wrong_emitter_wrong_chain_wrong_token_chain_bad_recipient() public {
        _lock8(5000);

        // Wrong emitter address on the right chain.
        bytes memory att = _attestWith(
            0,
            _quorumOf(guardianKeys),
            _bodyBytes(1, keccak256("not-the-rand-emitter"), nextSeq++, 1, _releasePayload(address(t8), 1000, 0))
        );
        vm.expectRevert(IRandBridge.WrongEmitter.selector);
        bridge.release(att);

        // Right emitter address on the wrong chain (cross-chain confusion).
        att = _attestWith(
            0, _quorumOf(guardianKeys), _bodyBytes(2, randEmitter, nextSeq++, 1, _releasePayload(address(t8), 1000, 0))
        );
        vm.expectRevert(IRandBridge.WrongEmitter.selector);
        bridge.release(att);

        // to_chain 3 (BSC) submitted to the Ethereum endpoint.
        att = _fromRand(_transferPayload(1000, _word(address(t8)), 2, _word(recipient), 3, 0));
        vm.expectRevert(IRandBridge.WrongToChain.selector);
        bridge.release(att);

        // token_chain 3: this endpoint only custodies its own chain's tokens.
        att = _fromRand(_transferPayload(1000, _word(address(t8)), 3, _word(recipient), 2, 0));
        vm.expectRevert(IRandBridge.WrongTokenChain.selector);
        bridge.release(att);

        // Recipient with dirty upper bytes: not an EVM address.
        bytes32 dirty = bytes32(uint256(uint160(recipient)) | (uint256(1) << 200));
        att = _fromRand(_transferPayload(1000, _word(address(t8)), 2, dirty, 2, 0));
        vm.expectRevert(IRandBridge.BadRecipient.selector);
        bridge.release(att);

        // Paused releases are refused.
        att = _fromRand(_releasePayload(address(t8), 1000, 0));
        vm.prank(pauser);
        bridge.pause();
        vm.expectRevert(IRandBridge.IsPaused.selector);
        bridge.release(att);
        vm.prank(admin);
        bridge.unpause();

        // Replay: the same attestation twice.
        bridge.release(att);
        vm.expectRevert(IRandBridge.AlreadyConsumed.selector);
        bridge.release(att);
    }

    function test_release_rejects_bad_token_address() public {
        _lock8(1000);

        // A `token_address` with anything above its low 20 bytes is not
        // an address on this chain, even though the low 20 bytes name a
        // whitelisted, funded token.
        bytes32 dirty = bytes32(uint256(uint160(address(t8))) | (uint256(1) << 248));
        bytes memory att = _fromRand(_transferPayload(1000, dirty, 2, _word(recipient), 2, 0));

        vm.expectRevert(IRandBridge.BadTokenAddress.selector);
        bridge.release(att);

        assertEq(bridge.custody(address(t8)), 1000, "custody untouched");
        assertEq(t8.balanceOf(recipient), 0, "nothing paid out");
    }

    function test_release_rejects_codeless_token() public {
        _lock8(1000);
        bytes memory att = _fromRand(_releasePayload(address(t8), 1000, 10));
        bytes32 digest = _digestOf(att);

        // The token loses its code after being whitelisted (SELFDESTRUCT
        // is still live on Tron). A call to a codeless address succeeds
        // and returns nothing, so without an explicit check `release`
        // would burn the digest and decrement custody while paying
        // nobody.
        vm.etch(address(t8), "");

        vm.expectRevert(SafeTransfer.TransferFailed.selector);
        vm.prank(relayer);
        bridge.release(att);

        assertFalse(bridge.consumed(digest), "digest must not be consumed");
        assertEq(bridge.custody(address(t8)), 1000, "custody untouched");
    }

    function test_release_rejects_dust_below_one_token_unit() public {
        vm.prank(user);
        bridge.lock(address(t6), 1_000_000, keccak256("rand-recipient"), 0, 0);

        // 99 attested units is less than one unit of a 6-decimal token,
        // so denormalising it yields zero: refuse rather than consume the
        // digest for a payout of nothing.
        bytes memory att = _fromRand(_transferPayload(99, _word(address(t6)), 2, _word(recipient), 2, 0));
        bytes32 digest = _digestOf(att);

        vm.expectRevert(IRandBridge.ZeroAmount.selector);
        bridge.release(att);
        assertFalse(bridge.consumed(digest), "digest must not be consumed");
    }

    function test_release_custody_counter_bounds_loss() public {
        _lock8(1000);

        bytes memory att = _fromRand(_releasePayload(address(t8), 2000, 0));
        vm.expectRevert(IRandBridge.InsufficientCustody.selector);
        bridge.release(att);

        assertEq(bridge.custody(address(t8)), 1000, "custody untouched");
        assertEq(t8.balanceOf(recipient), 0, "nothing paid out");
    }

    function test_release_caps() public {
        _lock8(5000);

        vm.prank(admin);
        bridge.setToken(address(t8), true, 500, 0);

        bytes memory att = _fromRand(_releasePayload(address(t8), 1000, 0));
        vm.expectRevert(IRandBridge.PerTransferCap.selector);
        bridge.release(att);

        vm.prank(admin);
        bridge.setToken(address(t8), true, 0, 900);

        bridge.release(_fromRand(_releasePayload(address(t8), 500, 0)));
        assertEq(t8.balanceOf(recipient), 500, "first release inside the daily cap");

        att = _fromRand(_releasePayload(address(t8), 500, 0));
        vm.expectRevert(IRandBridge.DailyCap.selector);
        bridge.release(att);

        // The window is `block.timestamp / 1 days`, so a day later the
        // allowance is fresh again.
        vm.warp(block.timestamp + 1 days);
        bridge.release(_fromRand(_releasePayload(address(t8), 500, 0)));
        assertEq(t8.balanceOf(recipient), 1000, "second day releases again");
    }

    function test_release_usdt_style_no_return_token() public {
        t8.setNoReturn(true);

        _lock8(1000); // transferFrom with no return value
        assertEq(bridge.custody(address(t8)), 1000, "lock accepted the empty return");

        bridge.release(_fromRand(_releasePayload(address(t8), 1000, 10)));

        assertEq(t8.balanceOf(recipient), 990, "recipient paid");
        assertEq(t8.balanceOf(address(this)), 10, "submitter paid the fee");
    }

    // ------------------------------------------------------------------
    // guardian rotation
    // ------------------------------------------------------------------

    function test_guardian_upgrade_and_grace() public {
        _lock8(5000);

        // Indices cannot be skipped.
        vm.expectRevert(IRandBridge.BadUpgradeIndex.selector);
        bridge.submitGuardianSetUpgrade(_governance(2, newGuardians));

        // A zero key or a duplicate is refused.
        address[] memory bad = new address[](2);
        bad[0] = newGuardians[0];
        bad[1] = address(0);
        vm.expectRevert(IRandBridge.ZeroAddress.selector);
        bridge.submitGuardianSetUpgrade(_governance(1, bad));
        bad[1] = newGuardians[0];
        vm.expectRevert(IRandBridge.DuplicateGuardian.selector);
        bridge.submitGuardianSetUpgrade(_governance(1, bad));

        // Governance messages must come from the governance emitter, not
        // the burn emitter.
        bytes memory impostor = _attestWith(
            0, _quorumOf(guardianKeys), _bodyBytes(1, randEmitter, nextSeq++, 0, _upgradePayload(1, newGuardians))
        );
        vm.expectRevert(IRandBridge.WrongEmitter.selector);
        bridge.submitGuardianSetUpgrade(impostor);

        vm.expectEmit(true, false, false, true, address(bridge));
        emit GuardianSetUpgraded(1, newGuardians);
        bridge.submitGuardianSetUpgrade(_governance(1, newGuardians));

        assertEq(bridge.currentGuardianSetIndex(), 1, "index advanced");
        assertEq(bridge.guardianSet(1).keys, newGuardians, "new keys stored");
        assertEq(bridge.guardianSet(1).expirationTime, 0, "current set never expires");
        assertEq(
            bridge.guardianSet(0).expirationTime,
            block.timestamp + Attestation.GUARDIAN_GRACE,
            "old set expires after the grace period"
        );

        // The new set works immediately.
        bytes memory byNew = _attestWith(
            1,
            _quorumOf(newGuardianKeys),
            _bodyBytes(1, randEmitter, nextSeq++, 1, _releasePayload(address(t8), 100, 0))
        );
        bridge.release(byNew);
        assertEq(t8.balanceOf(recipient), 100, "release signed by set 1");

        // The old set still works at the last second of the grace period.
        bytes memory byOldInGrace = _fromRand(_releasePayload(address(t8), 100, 0));
        vm.warp(bridge.guardianSet(0).expirationTime);
        bridge.release(byOldInGrace);
        assertEq(t8.balanceOf(recipient), 200, "release signed by the expiring set 0");

        // ... and not one second later.
        bytes memory byOldExpired = _fromRand(_releasePayload(address(t8), 100, 0));
        vm.warp(block.timestamp + 1);
        vm.expectRevert(IRandBridge.GuardianSetExpired.selector);
        bridge.release(byOldExpired);

        // An index nobody has ever seen.
        bytes memory unknownSet = _attestWith(
            9,
            _quorumOf(newGuardianKeys),
            _bodyBytes(1, randEmitter, nextSeq++, 1, _releasePayload(address(t8), 100, 0))
        );
        vm.expectRevert(IRandBridge.UnknownGuardianSet.selector);
        bridge.release(unknownSet);
    }

    /// Design Section 3.4/3.6: the grace window covers transfer payloads
    /// only. A rotation must be signed by the *current* set, so a
    /// superseded set — the one a rotation may be running away from —
    /// cannot rotate the bridge again while its grace period runs.
    function test_guardian_upgrade_must_be_signed_by_the_current_set() public {
        bridge.submitGuardianSetUpgrade(_governance(1, newGuardians));
        assertEq(bridge.currentGuardianSetIndex(), 1, "rotated to set 1");
        assertGt(bridge.guardianSet(0).expirationTime, block.timestamp, "set 0 is still inside its grace window");

        address[] memory thirdSet = new address[](6);
        for (uint256 i = 0; i < 6; i++) {
            thirdSet[i] = vm.addr(200 + i + 1);
        }

        // Signed by the superseded set 0: refused even though set 0 would
        // still be accepted for a release.
        vm.expectRevert(IRandBridge.GuardianSetExpired.selector);
        bridge.submitGuardianSetUpgrade(_governanceBy(0, guardianKeys, 2, thirdSet));
        assertEq(bridge.currentGuardianSetIndex(), 1, "no rotation happened");

        // Set 0 really is still good for value movement in the same block.
        _lock8(5000);
        bytes memory byOld = _fromRand(_releasePayload(address(t8), 100, 0));
        bridge.release(byOld);
        assertEq(t8.balanceOf(recipient), 100, "the superseded set still releases inside grace");

        // The same upgrade signed by the current set 1 goes through.
        bridge.submitGuardianSetUpgrade(_governanceBy(1, newGuardianKeys, 2, thirdSet));
        assertEq(bridge.currentGuardianSetIndex(), 2, "rotated to set 2");
        assertEq(bridge.guardianSet(2).keys, thirdSet, "set 2 keys stored");
    }

    function test_guardian_upgrade_works_while_paused() public {
        vm.prank(pauser);
        bridge.pause();

        // Pausing stops value movement, not the ability to rotate away
        // from a compromised guardian set.
        bridge.submitGuardianSetUpgrade(_governance(1, newGuardians));

        assertEq(bridge.currentGuardianSetIndex(), 1, "rotated while paused");
        assertTrue(bridge.paused(), "still paused");
    }

    // ------------------------------------------------------------------
    // roles
    // ------------------------------------------------------------------

    function test_pause_roles_and_admin_two_step() public {
        // Only the pauser or the admin may pause.
        vm.expectRevert(IRandBridge.NotPauser.selector);
        vm.prank(user);
        bridge.pause();

        vm.expectEmit(false, false, false, true, address(bridge));
        emit Paused(pauser);
        vm.prank(pauser);
        bridge.pause();
        assertTrue(bridge.paused(), "paused");

        vm.expectRevert(IRandBridge.IsPaused.selector);
        vm.prank(admin);
        bridge.pause();

        // The pauser cannot unpause: that is the admin's job.
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        vm.prank(pauser);
        bridge.unpause();

        vm.expectEmit(false, false, false, true, address(bridge));
        emit Unpaused(admin);
        vm.prank(admin);
        bridge.unpause();
        assertFalse(bridge.paused(), "unpaused");

        vm.expectRevert(IRandBridge.NotPaused.selector);
        vm.prank(admin);
        bridge.unpause();

        // The admin can also pause directly.
        vm.prank(admin);
        bridge.pause();
        vm.prank(admin);
        bridge.unpause();

        // Token config and the pauser slot are admin-only.
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        bridge.setToken(address(t6), false, 0, 0);
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        bridge.setPauser(user);

        vm.expectEmit(true, false, false, false, address(bridge));
        emit PauserSet(user);
        vm.prank(admin);
        bridge.setPauser(user);
        vm.prank(user);
        bridge.pause();
        vm.prank(admin);
        bridge.unpause();

        // Two-step admin transfer.
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        bridge.transferAdmin(user);

        // Handing the transfer to the zero address cancels it.
        vm.prank(admin);
        bridge.transferAdmin(user);
        assertEq(bridge.pendingAdmin(), user, "transfer pending");
        vm.expectEmit(true, false, false, false, address(bridge));
        emit AdminTransferStarted(address(0));
        vm.prank(admin);
        bridge.transferAdmin(address(0));
        assertEq(bridge.pendingAdmin(), address(0), "transfer cancelled");
        vm.expectRevert(IRandBridge.NotAdmin.selector);
        vm.prank(user);
        bridge.acceptAdmin();

        vm.expectEmit(true, false, false, false, address(bridge));
        emit AdminTransferStarted(relayer);
        vm.prank(admin);
        bridge.transferAdmin(relayer);
        assertEq(bridge.admin(), admin, "admin unchanged until accepted");

        vm.expectRevert(IRandBridge.NotAdmin.selector);
        vm.prank(user);
        bridge.acceptAdmin();

        vm.expectEmit(true, false, false, false, address(bridge));
        emit AdminTransferred(relayer);
        vm.prank(relayer);
        bridge.acceptAdmin();
        assertEq(bridge.admin(), relayer, "admin transferred");
        assertEq(bridge.pendingAdmin(), address(0), "pending cleared");

        vm.expectRevert(IRandBridge.NotAdmin.selector);
        vm.prank(admin);
        bridge.setPauser(user);
    }

    function test_setToken_records_decimals_and_caps() public {
        vm.expectEmit(true, false, false, true, address(bridge));
        emit TokenConfigured(address(t18), true, 5 ether, 50 ether);
        vm.prank(admin);
        bridge.setToken(address(t18), true, 5 ether, 50 ether);

        IRandBridge.TokenConfig memory cfg = bridge.tokenConfig(address(t18));
        assertTrue(cfg.enabled, "enabled");
        assertEq(cfg.decimals, 18, "decimals read from the token");
        assertEq(cfg.perTransferCap, 5 ether, "per-transfer cap");
        assertEq(cfg.dailyCap, 50 ether, "daily cap");

        // A contract without `decimals()` cannot be configured.
        vm.expectRevert(IRandBridge.DecimalsUnavailable.selector);
        vm.prank(admin);
        bridge.setToken(address(bridge), true, 0, 0);

        vm.expectRevert(IRandBridge.ZeroAddress.selector);
        vm.prank(admin);
        bridge.setToken(address(0), true, 0, 0);
    }

    function test_setToken_can_disable_a_token_that_stopped_answering() public {
        vm.etch(address(t6), "");

        // Disabling must never depend on the token answering: that is
        // precisely when the admin needs the switch.
        vm.prank(admin);
        bridge.setToken(address(t6), false, 0, 0);
        assertFalse(bridge.tokenConfig(address(t6)).enabled, "disabled");
        assertEq(bridge.tokenConfig(address(t6)).decimals, 6, "stored decimals kept");

        // Re-enabling still requires a live `decimals()`.
        vm.expectRevert(IRandBridge.DecimalsUnavailable.selector);
        vm.prank(admin);
        bridge.setToken(address(t6), true, 0, 0);
    }

    // ------------------------------------------------------------------
    // chain constants and the fork guard
    // ------------------------------------------------------------------

    function test_fork_guard_eth_and_not_tron() public {
        TronRandBridge tron = new TronRandBridge(admin, pauser, randEmitter, guardians);
        vm.prank(admin);
        tron.setToken(address(t6), true, 0, 0);
        vm.prank(user);
        t6.approve(address(tron), type(uint256).max);

        bytes memory att = _fromRand(_releasePayload(address(t8), 1000, 0));

        vm.chainId(999);

        vm.expectRevert(IRandBridge.WrongFork.selector);
        vm.prank(user);
        bridge.lock(address(t6), 1_000_000, keccak256("r"), 0, 0);

        vm.expectRevert(IRandBridge.WrongFork.selector);
        bridge.release(att);

        // Tron's TVM does not carry a reliable chain id, so the guard is
        // overridden away there.
        vm.prank(user);
        tron.lock(address(t6), 1_000_000, keccak256("r"), 0, 0);
        assertEq(tron.custody(address(t6)), 1_000_000, "Tron locks regardless of chain id");
    }

    function test_bsc_and_tron_constants() public {
        BscRandBridge bsc = new BscRandBridge(admin, pauser, randEmitter, guardians);
        TronRandBridge tron = new TronRandBridge(admin, pauser, randEmitter, guardians);

        assertEq(bridge.chainId(), 2, "Ethereum chain id");
        assertEq(bridge.consistencyLevel(), 1, "Ethereum consistency level");
        assertEq(bsc.chainId(), 3, "BSC chain id");
        assertEq(bsc.consistencyLevel(), 15, "BSC consistency level");
        assertEq(tron.chainId(), 4, "Tron chain id");
        assertEq(tron.consistencyLevel(), 19, "Tron consistency level");

        assertEq(bridge.randEmitter(), randEmitter, "emitter registered for chain 1");
        assertEq(bridge.guardianSet(0).keys, guardians, "initial guardian set");
    }

    function test_constructor_rejects_zero_admin_emitter_and_empty_guardians() public {
        vm.expectRevert(IRandBridge.ZeroAddress.selector);
        new EthereumRandBridge(address(0), pauser, randEmitter, guardians);

        vm.expectRevert(IRandBridge.ZeroAddress.selector);
        new EthereumRandBridge(admin, pauser, bytes32(0), guardians);

        address[] memory none = new address[](0);
        vm.expectRevert(IRandBridge.ZeroAddress.selector);
        new EthereumRandBridge(admin, pauser, randEmitter, none);

        address[] memory dup = new address[](2);
        dup[0] = guardians[0];
        dup[1] = guardians[0];
        vm.expectRevert(IRandBridge.DuplicateGuardian.selector);
        new EthereumRandBridge(admin, pauser, randEmitter, dup);
    }
}
