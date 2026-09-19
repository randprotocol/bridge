// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

import {Vm} from "forge-std/Vm.sol";

/// @notice Reads the shared cross-language test fixture
/// `vectors/attestations.json` and decodes it into Solidity structs.
///
/// Hex-ish string fields in the fixture (digests, addresses, keys, the
/// attestation bytes) may or may not carry a leading `0x`, so every hex
/// value is decoded through this library's own `hexToBytes` rather than
/// `vm.parseJsonBytes*`/`vm.parseJsonAddress`, which assume a `0x` prefix.
library VectorLoader {
    struct GuardianSet {
        uint32 index;
        address[] keys;
        uint64 expiresAt;
    }

    struct Vector {
        string name;
        bytes attestation;
        bytes32 digest;
        uint32 guardianSetIndex;
        GuardianSet[] sets;
        string expect;
    }

    /// Reads the whole vectors file as a raw JSON string.
    function readFile(Vm vm) internal view returns (string memory) {
        return vm.readFile("../vectors/attestations.json");
    }

    /// Counts `.vectors[]` entries by probing indices with `vm.keyExistsJson`
    /// until one is missing, capped at `maxVectors` as a sanity bound.
    function vectorCount(Vm vm, string memory json, uint256 maxVectors) internal view returns (uint256) {
        uint256 i = 0;
        while (i < maxVectors && vm.keyExistsJson(json, string.concat(".vectors[", vm.toString(i), "]"))) {
            i++;
        }
        return i;
    }

    /// Decodes `.vectors[i]` into a `Vector`, including every guardian set
    /// listed under its `sets[]` (not just the one matching
    /// `guardian_set_index`), so callers can resolve the right set
    /// themselves and skip vectors whose set is absent.
    function loadVector(Vm vm, string memory json, uint256 i) internal view returns (Vector memory v) {
        string memory base = string.concat(".vectors[", vm.toString(i), "]");

        v.name = vm.parseJsonString(json, string.concat(base, ".name"));
        v.attestation = hexToBytes(vm.parseJsonString(json, string.concat(base, ".attestation")));
        v.digest = hexToBytes32(vm.parseJsonString(json, string.concat(base, ".digest")));
        v.guardianSetIndex = uint32(vm.parseJsonUint(json, string.concat(base, ".guardian_set_index")));
        v.expect = vm.parseJsonString(json, string.concat(base, ".expect"));

        v.sets = _loadSets(vm, json, string.concat(base, ".sets"));
    }

    /// Split out of `loadVector` to keep each function's local-variable
    /// count low enough for the legacy (non-IR) codegen pipeline (the
    /// combined version hit "stack too deep").
    function _loadSets(Vm vm, string memory json, string memory setsBase)
        private
        view
        returns (GuardianSet[] memory sets)
    {
        uint256 nSets = 0;
        while (vm.keyExistsJson(json, string.concat(setsBase, "[", vm.toString(nSets), "]"))) {
            nSets++;
        }
        sets = new GuardianSet[](nSets);
        for (uint256 s = 0; s < nSets; s++) {
            string memory setBase = string.concat(setsBase, "[", vm.toString(s), "]");
            sets[s].index = uint32(vm.parseJsonUint(json, string.concat(setBase, ".index")));
            sets[s].expiresAt = uint64(vm.parseJsonUint(json, string.concat(setBase, ".expires_at")));
            sets[s].keys = _loadKeys(vm, json, string.concat(setBase, ".keys"));
        }
    }

    function _loadKeys(Vm vm, string memory json, string memory keysBase)
        private
        view
        returns (address[] memory keys)
    {
        uint256 nKeys = 0;
        while (vm.keyExistsJson(json, string.concat(keysBase, "[", vm.toString(nKeys), "]"))) {
            nKeys++;
        }
        keys = new address[](nKeys);
        for (uint256 k = 0; k < nKeys; k++) {
            string memory keyHex = vm.parseJsonString(json, string.concat(keysBase, "[", vm.toString(k), "]"));
            keys[k] = hexToAddress(keyHex);
        }
    }

    /// Finds the guardian set with `index == setIndex` among `sets`, if
    /// any.
    function findSet(GuardianSet[] memory sets, uint32 setIndex) internal pure returns (bool found, GuardianSet memory set) {
        for (uint256 i = 0; i < sets.length; i++) {
            if (sets[i].index == setIndex) {
                return (true, sets[i]);
            }
        }
        return (false, set);
    }

    function stringEq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    /// Decodes a hex string into bytes, tolerating an optional leading
    /// `0x`/`0X` prefix.
    function hexToBytes(string memory s) internal pure returns (bytes memory out) {
        bytes memory raw = bytes(s);
        uint256 start = 0;
        if (raw.length >= 2 && raw[0] == "0" && (raw[1] == "x" || raw[1] == "X")) {
            start = 2;
        }
        uint256 hexLen = raw.length - start;
        require(hexLen % 2 == 0, "VectorLoader: odd hex length");
        out = new bytes(hexLen / 2);
        for (uint256 i = 0; i < out.length; i++) {
            uint8 hi = _nibble(raw[start + 2 * i]);
            uint8 lo = _nibble(raw[start + 2 * i + 1]);
            out[i] = bytes1((hi << 4) | lo);
        }
    }

    function hexToBytes32(string memory s) internal pure returns (bytes32 result) {
        bytes memory b = hexToBytes(s);
        require(b.length == 32, "VectorLoader: expected 32-byte hex value");
        assembly {
            result := mload(add(b, 32))
        }
    }

    function hexToAddress(string memory s) internal pure returns (address addr) {
        bytes memory b = hexToBytes(s);
        require(b.length == 20, "VectorLoader: expected 20-byte hex value");
        assembly {
            addr := shr(96, mload(add(b, 32)))
        }
    }

    function _nibble(bytes1 c) private pure returns (uint8) {
        uint8 ch = uint8(c);
        if (ch >= 0x30 && ch <= 0x39) return ch - 0x30; // '0'-'9'
        if (ch >= 0x61 && ch <= 0x66) return ch - 0x61 + 10; // 'a'-'f'
        if (ch >= 0x41 && ch <= 0x46) return ch - 0x41 + 10; // 'A'-'F'
        revert("VectorLoader: bad hex digit");
    }
}
