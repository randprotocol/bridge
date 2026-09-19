// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

import {Attestation} from "../../src/lib/Attestation.sol";

/// @notice Thin external wrapper around the internal, pure `Attestation`
/// library functions.
///
/// `Attestation`'s functions are `internal`, so a test contract that calls
/// them directly does so via a plain JUMP, not a CALL: there is no sub-call
/// for `vm.expectRevert` to intercept, and a revert there aborts the whole
/// test function, making it impossible to assert several independent
/// revert scenarios in one test. Routing every call through this harness
/// turns each into a genuine external call/sub-call, so `vm.expectRevert`
/// scopes correctly and the test can keep going afterwards.
contract AttestationHarness {
    function parse(bytes calldata data) external pure returns (Attestation.Parsed memory) {
        return Attestation.parse(data);
    }

    function quorum(uint256 n) external pure returns (uint256) {
        return Attestation.quorum(n);
    }

    function verifySignatures(bytes32 digest, Attestation.Signature[] memory sigs, address[] memory keys)
        external
        pure
    {
        Attestation.verifySignatures(digest, sigs, keys);
    }

    function parseTransfer(bytes calldata payload) external pure returns (Attestation.Transfer memory) {
        return Attestation.parseTransfer(payload);
    }

    function parseGuardianUpgrade(bytes calldata payload) external pure returns (Attestation.GuardianUpgrade memory) {
        return Attestation.parseGuardianUpgrade(payload);
    }

    function encodeTransfer(Attestation.Transfer memory t) external pure returns (bytes memory) {
        return Attestation.encodeTransfer(t);
    }
}
