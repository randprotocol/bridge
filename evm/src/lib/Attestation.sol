// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @title Attestation
/// @notice Decodes and verifies the Rand bridge's Wormhole-shaped
/// attestation wire format. This is a pure library: no storage, no
/// external calls other than `ecrecover`.
///
/// The wire format is defined once, in Rust, by
/// `fullnode/crates/bridge-codec` (envelope/body/payload byte layouts) and
/// `fullnode/crates/shrugg-core::bridge` (digest, guardian address
/// derivation, quorum/index/low-s rules); every layout and rule below
/// mirrors that crate byte-for-byte and rule-for-rule so a Rand-signed
/// attestation verifies identically on every chain.
///
/// Layout (all integers big-endian):
///   version (1) || guardian_set_index (4) || n_sigs (1) ||
///   signature * n_sigs || body
/// signature = index (1) || r (32) || s (32) || v (1)                = 66 bytes
/// body      = timestamp (4) || nonce (4) || emitter_chain (2) ||
///             emitter_address (32) || sequence (8) ||
///             consistency_level (1) || payload (..)                 = 51 + len(payload) bytes
///
/// `mu = keccak256(keccak256(body))` is the value every guardian
/// signature is over. Guardian addresses are the last 20 bytes of
/// `keccak256(uncompressed_pubkey[1..])`, i.e. a standard Ethereum
/// address, so `ecrecover` output can be compared to them directly.
library Attestation {
    uint16 constant CHAIN_RAND = 1;
    uint16 constant CHAIN_ETHEREUM = 2;
    uint16 constant CHAIN_BSC = 3;
    uint16 constant CHAIN_TRON = 4;
    uint16 constant CHAIN_SOLANA = 5;

    /// `keccak256("rand-bridge-governance")`, pinned as a literal (see
    /// `GovernanceEmitterTest` for the assertion that ties this to the
    /// string, and `bridge-codec::GOVERNANCE_EMITTER` for the Rust twin).
    bytes32 constant GOVERNANCE_EMITTER = 0xb86dc29d182146831be319f8cdd0be86ace823413a477458bf67ffb151b2b55f;

    /// Guardian grace period after a guardian-set upgrade, in seconds.
    uint256 constant GUARDIAN_GRACE = 86400;

    /// `n / 2` for the secp256k1 curve order `n`, used to enforce the
    /// low-s signature malleability rule: a valid guardian signature must
    /// have `s <= SECP256K1_HALF_N`.
    uint256 constant SECP256K1_HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    uint8 constant VERSION = 1;
    uint256 constant TRANSFER_PAYLOAD_LEN = 133;
    uint8 constant TRANSFER_ID = 1;
    uint8 constant GUARDIAN_SET_UPGRADE_ID = 2;

    /// Fixed length, in bytes, of an encoded [Signature]: index (1) + r
    /// (32) + s (32) + v (1).
    uint256 constant SIGNATURE_LEN = 66;
    /// Fixed length, in bytes, of the [Body] header (everything but the
    /// trailing payload): timestamp (4) + nonce (4) + emitter_chain (2) +
    /// emitter_address (32) + sequence (8) + consistency_level (1).
    uint256 constant BODY_HEADER_LEN = 51;
    /// Length, in bytes, of the attestation envelope header: version (1) +
    /// guardian_set_index (4) + n_sigs (1).
    uint256 constant ENVELOPE_HEADER_LEN = 6;

    struct Signature {
        uint8 index;
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    struct Parsed {
        uint32 guardianSetIndex;
        Signature[] signatures;
        uint32 timestamp;
        uint32 nonce;
        uint16 emitterChain;
        bytes32 emitterAddress;
        uint64 sequence;
        uint8 consistencyLevel;
        bytes payload;
        bytes32 digest;
    }

    struct Transfer {
        uint256 amount;
        bytes32 tokenAddress;
        uint16 tokenChain;
        bytes32 to;
        uint16 toChain;
        uint256 fee;
    }

    struct GuardianUpgrade {
        uint32 newIndex;
        address[] keys;
    }

    error BadVersion();
    error Truncated();
    error BadPayloadId();
    error BadPayloadLength();
    error NoQuorum(uint256 have, uint256 need);
    error IndexOrder();
    error IndexOutOfRange();
    error HighS(uint8 index);
    error BadSignature(uint8 index);
    error WrongGuardian(uint8 index);

    /// Decodes the attestation envelope, computing `digest = mu =
    /// keccak256(keccak256(body))` over the body bytes as they appear on
    /// the wire. Does not validate signatures, guardian indices, or the
    /// payload's own contents — see [verifySignatures] and
    /// [parseTransfer]/[parseGuardianUpgrade] for those.
    function parse(bytes calldata data) internal pure returns (Parsed memory p) {
        uint256 pos = 0;

        uint8 version = uint8(_readBe(data, pos, 1));
        pos += 1;
        if (version != VERSION) revert BadVersion();

        p.guardianSetIndex = uint32(_readBe(data, pos, 4));
        pos += 4;

        uint8 nSigs = uint8(_readBe(data, pos, 1));
        pos += 1;

        p.signatures = new Signature[](nSigs);
        for (uint256 i = 0; i < nSigs; i++) {
            uint8 index = uint8(_readBe(data, pos, 1));
            pos += 1;
            bytes32 r = bytes32(_readBe(data, pos, 32));
            pos += 32;
            bytes32 s = bytes32(_readBe(data, pos, 32));
            pos += 32;
            uint8 v = uint8(_readBe(data, pos, 1));
            pos += 1;
            p.signatures[i] = Signature({index: index, r: r, s: s, v: v});
        }

        uint256 bodyStart = pos;
        if (data.length < bodyStart + BODY_HEADER_LEN) revert Truncated();

        p.timestamp = uint32(_readBe(data, pos, 4));
        pos += 4;
        p.nonce = uint32(_readBe(data, pos, 4));
        pos += 4;
        p.emitterChain = uint16(_readBe(data, pos, 2));
        pos += 2;
        p.emitterAddress = bytes32(_readBe(data, pos, 32));
        pos += 32;
        p.sequence = uint64(_readBe(data, pos, 8));
        pos += 8;
        p.consistencyLevel = uint8(_readBe(data, pos, 1));
        pos += 1;

        p.payload = data[pos:];

        bytes32 inner = keccak256(data[bodyStart:]);
        p.digest = keccak256(abi.encodePacked(inner));
    }

    /// Guardian quorum size for a guardian set of `n` keys.
    function quorum(uint256 n) internal pure returns (uint256) {
        return n * 2 / 3 + 1;
    }

    /// Validates `sigs` against `digest` and the guardian set `keys`,
    /// reverting on the first failure found. Mirrors
    /// `shrugg_core::bridge::verify`'s two-pass structure exactly:
    ///
    /// 1. `check_indices`: every `sigs[i].index < keys.length`, indices
    ///    strictly increasing, and `sigs.length >= quorum(keys.length)` —
    ///    checked only after the full index/order pass, so an
    ///    out-of-range or out-of-order index is reported even when there
    ///    aren't enough signatures for quorum.
    /// 2. Low-s, then recovery, then guardian-address match, per
    ///    signature — in that order, matching `recover_address`'s
    ///    behavior of also rejecting recovery id `v > 1`.
    function verifySignatures(bytes32 digest, Signature[] memory sigs, address[] memory keys) internal pure {
        uint256 n = keys.length;

        bool havePrev = false;
        uint8 prevIndex;
        for (uint256 i = 0; i < sigs.length; i++) {
            uint8 idx = sigs[i].index;
            if (idx >= n) revert IndexOutOfRange();
            if (havePrev && idx <= prevIndex) revert IndexOrder();
            prevIndex = idx;
            havePrev = true;
        }

        uint256 need = quorum(n);
        if (sigs.length < need) revert NoQuorum(sigs.length, need);

        for (uint256 i = 0; i < sigs.length; i++) {
            Signature memory sig = sigs[i];
            if (uint256(sig.s) > SECP256K1_HALF_N) revert HighS(sig.index);
            if (sig.v > 1) revert BadSignature(sig.index);
            address recovered = ecrecover(digest, sig.v + 27, sig.r, sig.s);
            if (recovered == address(0)) revert BadSignature(sig.index);
            if (recovered != keys[sig.index]) revert WrongGuardian(sig.index);
        }
    }

    /// Decodes a [Transfer] payload: `id (1) = 1 || amount (32) ||
    /// token_address (32) || token_chain (2) || to (32) || to_chain (2) ||
    /// fee (32)`, total length exactly [TRANSFER_PAYLOAD_LEN].
    function parseTransfer(bytes memory payload) internal pure returns (Transfer memory t) {
        if (payload.length != TRANSFER_PAYLOAD_LEN) revert BadPayloadLength();
        if (uint8(payload[0]) != TRANSFER_ID) revert BadPayloadId();

        t.amount = _readBeMem(payload, 1, 32);
        t.tokenAddress = bytes32(_readBeMem(payload, 33, 32));
        t.tokenChain = uint16(_readBeMem(payload, 65, 2));
        t.to = bytes32(_readBeMem(payload, 67, 32));
        t.toChain = uint16(_readBeMem(payload, 99, 2));
        t.fee = _readBeMem(payload, 101, 32);
    }

    /// Decodes a [GuardianUpgrade] payload: `id (1) = 2 || new_index (4)
    /// || n (1) || keys (20 * n)`.
    function parseGuardianUpgrade(bytes memory payload) internal pure returns (GuardianUpgrade memory g) {
        if (payload.length < ENVELOPE_HEADER_LEN) revert Truncated();
        if (uint8(payload[0]) != GUARDIAN_SET_UPGRADE_ID) revert BadPayloadId();

        g.newIndex = uint32(_readBeMem(payload, 1, 4));
        uint8 n = uint8(_readBeMem(payload, 5, 1));

        uint256 expectedLen = ENVELOPE_HEADER_LEN + uint256(n) * 20;
        if (payload.length != expectedLen) revert BadPayloadLength();

        address[] memory keys = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            keys[i] = address(uint160(_readBeMem(payload, ENVELOPE_HEADER_LEN + i * 20, 20)));
        }
        g.keys = keys;
    }

    /// Encodes a [Transfer] the same way `bridge-codec::Transfer::encode`
    /// does, for use by `lock()`/governance flows that need to build a
    /// payload to attest to.
    function encodeTransfer(Transfer memory t) internal pure returns (bytes memory) {
        return abi.encodePacked(TRANSFER_ID, t.amount, t.tokenAddress, t.tokenChain, t.to, t.toChain, t.fee);
    }

    /// Reads a `width`-byte (`width <= 32`) big-endian unsigned integer
    /// from calldata `d` at byte offset `pos`, reverting `Truncated` if
    /// fewer than `width` bytes remain. Uses `calldataload` directly
    /// (rather than slicing `d[pos:pos+32]`, which would revert on its
    /// own if `pos + 32 > d.length`): reading calldata past its end
    /// yields zero bytes without reverting, and those zero bytes are
    /// discarded by the right-shift, so this is exactly as safe as a
    /// bounds-checked read while staying correct up to the very last byte
    /// of `d`.
    function _readBe(bytes calldata d, uint256 pos, uint256 width) private pure returns (uint256 value) {
        if (pos + width > d.length) revert Truncated();
        uint256 shift = 256 - width * 8;
        assembly {
            let word := calldataload(add(d.offset, pos))
            value := shr(shift, word)
        }
    }

    /// Reads a `width`-byte (`width <= 32`) big-endian unsigned integer
    /// from memory `d` at byte offset `pos`. Callers are expected to have
    /// already validated `d`'s total length (`parseTransfer` and
    /// `parseGuardianUpgrade` both check length before calling this), so
    /// `pos + width` is always within `d`'s Solidity-padded allocation
    /// (every `bytes memory` is padded to a 32-byte boundary).
    function _readBeMem(bytes memory d, uint256 pos, uint256 width) private pure returns (uint256 value) {
        uint256 shift = 256 - width * 8;
        assembly {
            let word := mload(add(add(d, 32), pos))
            value := shr(shift, word)
        }
    }
}
