// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {Attestation} from "../src/lib/Attestation.sol";
import {AttestationHarness} from "./utils/AttestationHarness.sol";
import {VectorLoader} from "./utils/VectorLoader.sol";

/// Cross-checks every signature-level vector from the shared
/// `vectors/attestations.json` fixture (generated once and shared with the
/// Rust fullnode and the Solana program) against the `Attestation` library.
///
/// Only the `expect` codes that are this library's concern are asserted
/// here: `ok`, `no_quorum`, `index_order`, `index_out_of_range`,
/// `bad_signature`, `high_s`, `wrong_guardian`, `bad_version`,
/// `bad_payload`. `set_expired`, `unknown_set` and `stale_governance_set`
/// are guardian-set *resolution* concerns that belong to the bridge
/// contract (Task D2), not this pure library, so they're skipped here
/// (mirrors the fullnode's own `randprotocol-core::bridge` vector test).
/// Ledger-level checks (`wrong_emitter`, `wrong_to_chain`,
/// `wrong_token_chain`, `fee_exceeds_amount`, `amount_overflow`, `replay`)
/// are also out of scope for this library.
contract VectorsTest is Test {
    AttestationHarness harness;
    string json;

    uint256 constant MAX_VECTORS = 64;

    // Per-`expect` counters, asserted at the end so a silently-empty vector
    // file (or a typo in an `expect` string) can't make this test pass
    // having checked nothing.
    uint256 okCount;
    uint256 noQuorumCount;
    uint256 indexOrderCount;
    uint256 indexOutOfRangeCount;
    uint256 badSignatureCount;
    uint256 highSCount;
    uint256 wrongGuardianCount;
    uint256 badVersionCount;
    uint256 badPayloadCount;

    function setUp() public {
        harness = new AttestationHarness();
        json = VectorLoader.readFile(vm);
    }

    function test_shared_vectors_match_attestation_library() public {
        uint256 n = VectorLoader.vectorCount(vm, json, MAX_VECTORS);
        assertGt(n, 0, "expected at least one vector in attestations.json");

        for (uint256 i = 0; i < n; i++) {
            VectorLoader.Vector memory v = VectorLoader.loadVector(vm, json, i);
            _checkVector(v);
        }

        uint256 total = okCount + noQuorumCount + indexOrderCount + indexOutOfRangeCount + badSignatureCount
            + highSCount + wrongGuardianCount + badVersionCount + badPayloadCount;
        assertGe(total, 20, "expected at least 20 signature-level vectors checked");
        assertGt(okCount, 0, "expected at least one ok vector");
        assertGt(noQuorumCount, 0, "expected at least one no_quorum vector");
        assertGt(indexOrderCount, 0, "expected at least one index_order vector");
        assertGt(indexOutOfRangeCount, 0, "expected at least one index_out_of_range vector");
        assertGt(badSignatureCount, 0, "expected at least one bad_signature vector");
        assertGt(highSCount, 0, "expected at least one high_s vector");
        assertGt(wrongGuardianCount, 0, "expected at least one wrong_guardian vector");
        assertGt(badVersionCount, 0, "expected at least one bad_version vector");
        assertGt(badPayloadCount, 0, "expected at least one bad_payload vector");

        emit log_named_uint("vectors checked", total);
    }

    function _checkVector(VectorLoader.Vector memory v) internal {
        if (VectorLoader.stringEq(v.expect, "bad_version")) {
            badVersionCount++;
            (bool ok, bytes memory ret) =
                address(harness).call(abi.encodeWithSelector(AttestationHarness.parse.selector, v.attestation));
            assertFalse(ok, string.concat(v.name, ": expected parse() to revert"));
            assertTrue(
                _selectorOf(ret) == Attestation.BadVersion.selector,
                string.concat(v.name, ": expected BadVersion")
            );
            return;
        }

        if (!_isSignatureLevel(v.expect)) {
            return; // set_expired / unknown_set / ledger-level: not this library's concern
        }

        // Every remaining target `expect` requires `parse` itself to
        // succeed (the envelope is well-formed; only the signatures, or
        // the payload contents, are wrong).
        Attestation.Parsed memory p = harness.parse(v.attestation);

        if (VectorLoader.stringEq(v.expect, "bad_payload")) {
            badPayloadCount++;
            (bool ok, bytes memory ret) = address(harness).call(
                abi.encodeWithSelector(AttestationHarness.parseTransfer.selector, p.payload)
            );
            assertFalse(ok, string.concat(v.name, ": expected parseTransfer() to revert"));
            bytes4 got = _selectorOf(ret);
            assertTrue(
                got == Attestation.BadPayloadLength.selector || got == Attestation.BadPayloadId.selector,
                string.concat(v.name, ": expected BadPayloadLength or BadPayloadId")
            );
            return;
        }

        (bool found, VectorLoader.GuardianSet memory set) = VectorLoader.findSet(v.sets, v.guardianSetIndex);
        if (!found) {
            return; // per brief: skip vectors whose own guardian set is absent
        }

        if (VectorLoader.stringEq(v.expect, "ok")) {
            okCount++;
            assertEq(p.digest, v.digest, string.concat(v.name, ": digest mismatch"));
            harness.verifySignatures(p.digest, p.signatures, set.keys);
            return;
        }
        if (VectorLoader.stringEq(v.expect, "no_quorum")) {
            noQuorumCount++;
            _expectVerifyRevertSelector(p, set.keys, Attestation.NoQuorum.selector, v.name);
            return;
        }
        if (VectorLoader.stringEq(v.expect, "index_order")) {
            indexOrderCount++;
            _expectVerifyRevertSelector(p, set.keys, Attestation.IndexOrder.selector, v.name);
            return;
        }
        if (VectorLoader.stringEq(v.expect, "index_out_of_range")) {
            indexOutOfRangeCount++;
            _expectVerifyRevertSelector(p, set.keys, Attestation.IndexOutOfRange.selector, v.name);
            return;
        }
        if (VectorLoader.stringEq(v.expect, "bad_signature")) {
            badSignatureCount++;
            // The vector zeroes signature 0's `r`, so `ecrecover` returns
            // address(0) and the library must reject it as BadSignature
            // rather than compare that zero against a guardian key.
            _expectVerifyRevert(
                p, set.keys, abi.encodeWithSelector(Attestation.BadSignature.selector, uint8(0)), v.name
            );
            return;
        }
        if (VectorLoader.stringEq(v.expect, "high_s")) {
            highSCount++;
            _expectVerifyRevertSelector(p, set.keys, Attestation.HighS.selector, v.name);
            return;
        }
        if (VectorLoader.stringEq(v.expect, "wrong_guardian")) {
            wrongGuardianCount++;
            _expectVerifyRevertSelector(p, set.keys, Attestation.WrongGuardian.selector, v.name);
            return;
        }
    }

    function _isSignatureLevel(string memory expect) internal pure returns (bool) {
        return VectorLoader.stringEq(expect, "ok") || VectorLoader.stringEq(expect, "no_quorum")
            || VectorLoader.stringEq(expect, "index_order") || VectorLoader.stringEq(expect, "index_out_of_range")
            || VectorLoader.stringEq(expect, "bad_signature") || VectorLoader.stringEq(expect, "high_s")
            || VectorLoader.stringEq(expect, "wrong_guardian") || VectorLoader.stringEq(expect, "bad_payload");
    }

    /// Like `_expectVerifyRevertSelector`, but compares the whole revert
    /// payload, so an error carrying arguments (`BadSignature(uint8)`) is
    /// checked down to the offending signature index.
    function _expectVerifyRevert(
        Attestation.Parsed memory p,
        address[] memory keys,
        bytes memory expected,
        string memory name
    ) internal {
        (bool ok, bytes memory ret) = address(harness).call(
            abi.encodeWithSelector(AttestationHarness.verifySignatures.selector, p.digest, p.signatures, keys)
        );
        assertFalse(ok, string.concat(name, ": expected verifySignatures() to revert"));
        assertEq(ret, expected, string.concat(name, ": wrong revert payload"));
    }

    function _expectVerifyRevertSelector(
        Attestation.Parsed memory p,
        address[] memory keys,
        bytes4 selector,
        string memory name
    ) internal {
        (bool ok, bytes memory ret) = address(harness).call(
            abi.encodeWithSelector(AttestationHarness.verifySignatures.selector, p.digest, p.signatures, keys)
        );
        assertFalse(ok, string.concat(name, ": expected verifySignatures() to revert"));
        assertTrue(_selectorOf(ret) == selector, string.concat(name, ": wrong revert selector"));
    }

    function _selectorOf(bytes memory ret) internal pure returns (bytes4 sel) {
        require(ret.length >= 4, "VectorsTest: revert data too short to contain a selector");
        assembly {
            sel := mload(add(ret, 32))
        }
    }
}
