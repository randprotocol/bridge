// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {Attestation} from "../src/lib/Attestation.sol";
import {AttestationHarness} from "./utils/AttestationHarness.sol";

/// Unit tests for the `Attestation` library, exercised through
/// `AttestationHarness` so revert paths can be asserted independently
/// within a single test function (see the harness's doc comment).
contract AttestationTest is Test {
    AttestationHarness harness;

    // Hand-derived big-endian byte values, cross-checked independently in
    // Python (pycryptodome keccak) rather than by re-deriving them from the
    // library under test. Mirrors the fullnode's own
    // `envelope_round_trips_and_body_bytes_are_the_tail` fixture: guardian
    // set index 9, one signature (index 0, r = 32*0x01, s = 32*0x02, v =
    // 1), body timestamp=1 nonce=2 emitter_chain=3 emitter_address =
    // 32*0x04, sequence=5, consistency_level=6, payload = [1,2,3].
    bytes32 constant FIXTURE_R = 0x0101010101010101010101010101010101010101010101010101010101010101;
    bytes32 constant FIXTURE_S = 0x0202020202020202020202020202020202020202020202020202020202020202;
    bytes32 constant FIXTURE_EMITTER_ADDR = 0x0404040404040404040404040404040404040404040404040404040404040404;
    bytes32 constant FIXTURE_DIGEST = 0x911b7eea47ae544c31bfe550c3a67e49c6dfc0cb26bd7bb557140a7c064bcaa1;

    uint256 constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 constant SECP256K1_HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    function setUp() public {
        harness = new AttestationHarness();
    }

    function _fixtureAttestation() internal pure returns (bytes memory) {
        bytes memory body = abi.encodePacked(
            uint32(1), // timestamp
            uint32(2), // nonce
            uint16(3), // emitter_chain
            FIXTURE_EMITTER_ADDR,
            uint64(5), // sequence
            uint8(6), // consistency_level
            uint8(1),
            uint8(2),
            uint8(3) // payload = [1,2,3]
        );
        return abi.encodePacked(
            uint8(1), // version
            uint32(9), // guardian_set_index
            uint8(1), // n_sigs
            uint8(0), // sig[0].index
            FIXTURE_R,
            FIXTURE_S,
            uint8(1), // sig[0].v
            body
        );
    }

    function test_parse_layout() public view {
        Attestation.Parsed memory p = harness.parse(_fixtureAttestation());

        assertEq(p.guardianSetIndex, 9, "guardianSetIndex");
        assertEq(p.signatures.length, 1, "n sigs");
        assertEq(p.signatures[0].index, 0, "sig index");
        assertEq(p.signatures[0].r, FIXTURE_R, "sig r");
        assertEq(p.signatures[0].s, FIXTURE_S, "sig s");
        assertEq(p.signatures[0].v, 1, "sig v");
        assertEq(p.timestamp, 1, "timestamp");
        assertEq(p.nonce, 2, "nonce");
        assertEq(p.emitterChain, 3, "emitterChain");
        assertEq(p.emitterAddress, FIXTURE_EMITTER_ADDR, "emitterAddress");
        assertEq(p.sequence, 5, "sequence");
        assertEq(p.consistencyLevel, 6, "consistencyLevel");
        assertEq(p.payload.length, 3, "payload len");
        assertEq(uint8(p.payload[0]), 1, "payload[0]");
        assertEq(uint8(p.payload[1]), 2, "payload[1]");
        assertEq(uint8(p.payload[2]), 3, "payload[2]");
        assertEq(p.digest, FIXTURE_DIGEST, "digest = keccak256(keccak256(body))");
    }

    /// Pins `Attestation.GOVERNANCE_EMITTER` to the string it's derived
    /// from, mirroring the Rust twin
    /// (`randprotocol_core::bridge::tests::governance_emitter_matches_string`)
    /// and the brief's pinned value
    /// `0xb86dc29d182146831be319f8cdd0be86ace823413a477458bf67ffb151b2b55f`.
    function test_governance_emitter_matches_string() public pure {
        assertEq(keccak256("rand-bridge-governance"), Attestation.GOVERNANCE_EMITTER);
    }

    function test_quorum_values() public view {
        assertEq(harness.quorum(6), 5);
        assertEq(harness.quorum(4), 3);
        assertEq(harness.quorum(1), 1);
    }

    function test_rejects_bad_version_and_truncation() public {
        // version byte = 2, everything else zero: BadVersion, checked
        // before any other field is read.
        vm.expectRevert(Attestation.BadVersion.selector);
        harness.parse(hex"020000000000");

        // version = 1, guardian_set_index = 0, n_sigs = 1, but only one
        // more byte follows where a 66-byte signature is required.
        vm.expectRevert(Attestation.Truncated.selector);
        harness.parse(hex"01000000000100");
    }

    function test_transfer_payload_exact_length() public {
        vm.expectRevert(Attestation.BadPayloadLength.selector);
        harness.parseTransfer(new bytes(132));

        vm.expectRevert(Attestation.BadPayloadLength.selector);
        harness.parseTransfer(new bytes(134));
    }

    function test_transfer_payload_bad_id_reverts() public {
        bytes memory payload = new bytes(133);
        payload[0] = 0x09; // not the transfer id (1)
        vm.expectRevert(Attestation.BadPayloadId.selector);
        harness.parseTransfer(payload);
    }

    function test_encode_transfer_round_trips_through_parse_transfer() public view {
        Attestation.Transfer memory t = Attestation.Transfer({
            amount: 100_000_000,
            tokenAddress: bytes32(uint256(0xAA)),
            tokenChain: 2,
            to: bytes32(uint256(0xBB)),
            toChain: 1,
            fee: 1_000
        });
        bytes memory encoded = harness.encodeTransfer(t);
        assertEq(encoded.length, 133, "transfer payload length");

        Attestation.Transfer memory decoded = harness.parseTransfer(encoded);
        assertEq(decoded.amount, t.amount, "amount");
        assertEq(decoded.tokenAddress, t.tokenAddress, "tokenAddress");
        assertEq(decoded.tokenChain, t.tokenChain, "tokenChain");
        assertEq(decoded.to, t.to, "to");
        assertEq(decoded.toChain, t.toChain, "toChain");
        assertEq(decoded.fee, t.fee, "fee");
    }

    function test_guardian_upgrade_round_trips() public view {
        address key0 = address(0x1111111111111111111111111111111111111A);
        address key1 = address(0x2222222222222222222222222222222222222B);
        bytes memory payload = abi.encodePacked(uint8(2), uint32(7), uint8(2), key0, key1);
        assertEq(payload.length, 46, "id(1)+newIndex(4)+n(1)+2*key(20) = 46");

        Attestation.GuardianUpgrade memory g = harness.parseGuardianUpgrade(payload);
        assertEq(g.newIndex, 7, "newIndex");
        assertEq(g.keys.length, 2, "keys length");
        assertEq(g.keys[0], key0, "keys[0]");
        assertEq(g.keys[1], key1, "keys[1]");
    }

    function test_guardian_upgrade_zero_guardians_reverts() public {
        // id(1) + newIndex(4) + n(1) = 0, no keys.
        bytes memory payload = abi.encodePacked(uint8(2), uint32(7), uint8(0));
        vm.expectRevert(Attestation.ZeroGuardians.selector);
        harness.parseGuardianUpgrade(payload);
    }

    function test_guardian_upgrade_trailing_byte_reverts() public {
        address key0 = address(0x1111111111111111111111111111111111111A);
        // n = 1 but one extra trailing byte beyond the single 20-byte key.
        bytes memory payload = abi.encodePacked(uint8(2), uint32(7), uint8(1), key0, uint8(0xFF));
        vm.expectRevert(Attestation.BadPayloadLength.selector);
        harness.parseGuardianUpgrade(payload);
    }

    function test_guardian_upgrade_bad_id_reverts() public {
        address key0 = address(0x1111111111111111111111111111111111111A);
        bytes memory payload = abi.encodePacked(uint8(9), uint32(7), uint8(1), key0); // not the upgrade id (2)
        vm.expectRevert(Attestation.BadPayloadId.selector);
        harness.parseGuardianUpgrade(payload);
    }

    /// Signs `digest` with private key `pk`, tags the signature with
    /// guardian `index`, and normalizes it to low-s (flipping `v`
    /// accordingly) so the fixture matches the wire format's requirement
    /// regardless of whatever form `vm.sign` happens to return.
    function _sign(uint256 pk, bytes32 digest, uint8 index) internal pure returns (Attestation.Signature memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        uint256 sVal = uint256(s);
        if (sVal > SECP256K1_HALF_N) {
            sVal = SECP256K1_N - sVal;
            s = bytes32(sVal);
            v = v == 27 ? 28 : 27;
        }
        sig = Attestation.Signature({index: index, r: r, s: s, v: v - 27});
    }

    function test_verify_signatures_with_vm_sign() public {
        uint256 n = 6;
        address[] memory keys = new address[](n);
        uint256[] memory pks = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            pks[i] = i + 1;
            keys[i] = vm.addr(pks[i]);
        }
        bytes32 digest = keccak256("attestation-digest-fixture");

        Attestation.Signature[] memory five = new Attestation.Signature[](5);
        for (uint256 i = 0; i < 5; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            five[i] = _sign(pks[i], digest, uint8(i)); // safe: loop bound is a literal 5
        }

        // 5 of 6 signatures is exactly quorum(6) = 5: passes.
        harness.verifySignatures(digest, five, keys);

        // 4 signatures: below quorum.
        Attestation.Signature[] memory four = new Attestation.Signature[](4);
        for (uint256 i = 0; i < 4; i++) {
            four[i] = _copySig(five[i]);
        }
        vm.expectRevert(abi.encodeWithSelector(Attestation.NoQuorum.selector, uint256(4), uint256(5)));
        harness.verifySignatures(digest, four, keys);

        // Duplicate index: [0, 0, 2, 3, 4] is not strictly increasing.
        Attestation.Signature[] memory dup = _cloneFive(five);
        dup[1].index = 0;
        vm.expectRevert(Attestation.IndexOrder.selector);
        harness.verifySignatures(digest, dup, keys);

        // Index 6 is out of range for a 6-key guardian set (valid: 0..5).
        Attestation.Signature[] memory outOfRange = _cloneFive(five);
        outOfRange[4].index = 6;
        vm.expectRevert(Attestation.IndexOutOfRange.selector);
        harness.verifySignatures(digest, outOfRange, keys);

        // Signature at index 2 was produced by a key outside the guardian
        // set: recovers to an address that isn't keys[2].
        Attestation.Signature[] memory forged = _cloneFive(five);
        forged[2] = _sign(uint256(0xDEAD), digest, 2);
        vm.expectRevert(abi.encodeWithSelector(Attestation.WrongGuardian.selector, uint8(2)));
        harness.verifySignatures(digest, forged, keys);

        // High-s signature at index 0.
        Attestation.Signature[] memory highS = _cloneFive(five);
        highS[0].s = bytes32(type(uint256).max);
        vm.expectRevert(abi.encodeWithSelector(Attestation.HighS.selector, uint8(0)));
        harness.verifySignatures(digest, highS, keys);
    }

    /// Deep-copies `sigs` into a fresh array. `out[i] = sigs[i]` alone
    /// would NOT do this: structs are reference types in Solidity, so a
    /// plain memory-to-memory struct assignment makes `out[i]` alias the
    /// very same struct instance as `sigs[i]` rather than copying its
    /// fields — mutating the "clone" would then also mutate the
    /// original. Constructing a new struct value per element (via
    /// `_copySig`) avoids that.
    function _cloneFive(Attestation.Signature[] memory sigs) internal pure returns (Attestation.Signature[] memory out) {
        out = new Attestation.Signature[](sigs.length);
        for (uint256 i = 0; i < sigs.length; i++) {
            out[i] = _copySig(sigs[i]);
        }
    }

    function _copySig(Attestation.Signature memory sig) internal pure returns (Attestation.Signature memory) {
        return Attestation.Signature({index: sig.index, r: sig.r, s: sig.s, v: sig.v});
    }
}
