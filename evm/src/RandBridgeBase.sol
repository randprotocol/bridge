// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

import {Attestation} from "./lib/Attestation.sol";
import {SafeTransfer} from "./lib/SafeTransfer.sol";
import {IRandBridge} from "./interfaces/IRandBridge.sol";

interface IERC20Metadata {
    function decimals() external view returns (uint8);
    function balanceOf(address account) external view returns (uint256);
}

/// @title RandBridgeBase
/// @notice Every rule of design Section 5.1, shared by the Ethereum, BSC
/// and Tron endpoints. Concrete contracts only pin their bridge chain id
/// and consistency level (and, for Tron, drop the fork guard).
///
/// The endpoint is a lock/release custodian, never a minter:
///
/// - `lock` pulls a token into custody, normalises the amount to the
///   attestation's 8 decimals (Section 3.7) and publishes a transfer
///   message for the guardians;
/// - `release` verifies a guardian-signed Rand burn attestation and pays
///   the token back out of custody.
///
/// The trust root is the guardian set. Three independent bounds sit
/// underneath it: the per-token whitelist, the per-token custody counter
/// (an attestation can never move more of a token than this endpoint
/// actually holds — paper `thm:custodysoundness`), and the release caps.
///
/// @dev All state-changing paths follow checks-effects-interactions: the
/// digest is marked consumed and custody/window counters are updated
/// *before* any token call, so a token with a callback in its transfer
/// hook cannot re-enter into a second release of the same attestation.
abstract contract RandBridgeBase is IRandBridge {
    using SafeTransfer for address;

    /// The largest `decimals()` this contract will accept for a token.
    /// `10 ** (decimals - 8)` has to fit in a uint256, and no real token
    /// is anywhere near this; the bound just keeps `setToken` from
    /// whitelisting a token whose every transfer would overflow.
    uint8 internal constant MAX_DECIMALS = 36;

    /// The largest attested (8-decimal) amount a single lock may publish:
    /// `u64::MAX`, the width of a Rand note's amount field. Rand rejects
    /// anything above it (`BridgeError::AmountTooLarge`), so the endpoint
    /// must too, or the locked tokens could never be minted or released.
    uint256 internal constant MAX_ATTESTED_AMOUNT = type(uint64).max;

    /// `block.chainid` at deployment. Section 5.4's fork guard: a replay
    /// of this contract's state onto a forked chain cannot move tokens.
    uint256 public immutable DEPLOY_CHAIN_ID;

    /// The one registered emitter (Section 3.8): chain 1, the Rand burn
    /// emitter. Governance messages come from
    /// `Attestation.GOVERNANCE_EMITTER` on the same chain instead.
    ///
    /// Named in mixedCase because `IRandBridge` specifies the getter as
    /// `randEmitter()`.
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    bytes32 public immutable override randEmitter;

    address public admin;
    address public pendingAdmin;
    address public pauser;
    bool public paused;

    uint32 public override currentGuardianSetIndex;
    mapping(uint32 => GuardianSet) internal _guardianSets;

    mapping(address => TokenConfig) internal _tokenConfigs;
    mapping(address => uint256) public override custody;
    mapping(bytes32 => bool) public override consumed;

    /// Sequence of the next message this emitter publishes; starts at 0.
    uint64 public override sequence;

    constructor(address admin_, address pauser_, bytes32 randEmitter_, address[] memory guardians) {
        if (admin_ == address(0) || randEmitter_ == bytes32(0) || guardians.length == 0) revert ZeroAddress();
        _checkKeys(guardians);

        DEPLOY_CHAIN_ID = block.chainid;
        randEmitter = randEmitter_;
        admin = admin_;
        pauser = pauser_;
        _guardianSets[0].keys = guardians;

        emit AdminTransferred(admin_);
        emit PauserSet(pauser_);
        emit GuardianSetUpgraded(0, guardians);
    }

    // ------------------------------------------------------------------
    // chain constants
    // ------------------------------------------------------------------

    /// The bridge-network chain id of this endpoint (Section 3.5), not
    /// `block.chainid`.
    function _chainId() internal pure virtual returns (uint16);

    /// The confirmation depth this emitter asks guardians to wait for.
    function _consistencyLevel() internal pure virtual returns (uint8);

    function chainId() external pure override returns (uint16) {
        return _chainId();
    }

    function consistencyLevel() external pure returns (uint8) {
        return _consistencyLevel();
    }

    /// Reverts if the chain forked under us. Overridden to a no-op on
    /// Tron, whose TVM does not carry a dependable chain id.
    function _checkFork() internal view virtual {
        if (block.chainid != DEPLOY_CHAIN_ID) revert WrongFork();
    }

    // ------------------------------------------------------------------
    // views
    // ------------------------------------------------------------------

    function guardianSet(uint32 index) external view override returns (GuardianSet memory) {
        return _guardianSets[index];
    }

    function tokenConfig(address token) external view override returns (TokenConfig memory) {
        return _tokenConfigs[token];
    }

    /// Section 3.7. `locked` is what the user actually parts with (the
    /// remainder below one attestable unit stays with them); `attested`
    /// is the 8-decimal value the guardians sign.
    function normalize(uint256 amount, uint8 decimals)
        external
        pure
        override
        returns (uint256 locked, uint256 attested)
    {
        return _normalize(amount, decimals);
    }

    function denormalize(uint256 attested, uint8 decimals) external pure override returns (uint256) {
        return _denormalize(attested, decimals);
    }

    function _normalize(uint256 amount, uint8 decimals) internal pure returns (uint256 locked, uint256 attested) {
        if (decimals > 8) {
            uint256 scale = 10 ** (uint256(decimals) - 8);
            attested = amount / scale;
            locked = attested * scale;
        } else {
            attested = amount * 10 ** (8 - uint256(decimals));
            locked = amount;
        }
    }

    function _denormalize(uint256 attested, uint8 decimals) internal pure returns (uint256) {
        if (decimals > 8) {
            return attested * 10 ** (uint256(decimals) - 8);
        }
        return attested / 10 ** (8 - uint256(decimals));
    }

    // ------------------------------------------------------------------
    // lock
    // ------------------------------------------------------------------

    /// Section 5.1's lock: pull `locked` units into custody and publish a
    /// transfer message addressed to Rand (`to_chain = 1`).
    ///
    /// `randRecipient` is the 32-byte recipient hash Rand's wallet prints
    /// for a shielded address (`blake3("rand-shielded-recipient", pk ||
    /// kem_ek)`); the endpoint can only reject zero. `relayerFee` is
    /// quoted in the token's own units, like `amount`, and is normalised
    /// the same way, so it can round down to zero for an 18-decimal
    /// token — always `<= amount`, which is what the payload requires.
    /// Rand mints the gross `amount` and pays the fee to nobody (the
    /// submitter has no identity on a shielded chain), so it is carried
    /// for the record only; front ends should pass 0.
    function lock(address token, uint256 amount, bytes32 randRecipient, uint256 relayerFee, uint32 nonce)
        external
        override
        returns (uint64)
    {
        _checkFork();
        if (paused) revert IsPaused();

        TokenConfig storage cfg = _tokenConfigs[token];
        if (!cfg.enabled) revert TokenDisabled();
        if (randRecipient == bytes32(0)) revert ZeroRecipient();
        if (relayerFee > amount) revert FeeExceedsAmount();

        (uint256 locked, uint256 attested) = _normalize(amount, cfg.decimals);
        if (attested == 0) revert ZeroAmount();
        // Rand keeps a bridged holding in a note whose amount is a `u64`
        // and refuses a larger attestation at admission; a lock it could
        // never mint would sit in custody with no burn able to release it.
        if (attested > MAX_ATTESTED_AMOUNT) revert AmountTooLarge();
        (, uint256 attestedFee) = _normalize(relayerFee, cfg.decimals);

        _pull(token, msg.sender, locked);
        custody[token] += locked;

        uint64 seq = sequence;
        bytes memory payload = Attestation.encodeTransfer(
            Attestation.Transfer({
                amount: attested,
                tokenAddress: bytes32(uint256(uint160(token))),
                tokenChain: _chainId(),
                to: randRecipient,
                toChain: Attestation.CHAIN_RAND,
                fee: attestedFee
            })
        );
        emit MessagePublished(seq, nonce, _consistencyLevel(), payload);
        emit Locked(token, msg.sender, randRecipient, locked, attested, seq);

        sequence = seq + 1;
        return seq;
    }

    /// Pulls exactly `amount` of `token` from `from` into custody.
    ///
    /// The balance delta is measured rather than trusted: a
    /// fee-on-transfer token would credit this contract less than the
    /// attestation is about to promise, so it is rejected outright rather
    /// than mis-accounted (design Section 5.1, lock step 3).
    function _pull(address token, address from, uint256 amount) private {
        uint256 balanceBefore = IERC20Metadata(token).balanceOf(address(this));
        token.safeTransferFrom(from, address(this), amount);
        uint256 balanceAfter = IERC20Metadata(token).balanceOf(address(this));
        if (balanceAfter < balanceBefore || balanceAfter - balanceBefore != amount) {
            revert TransferAmountMismatch();
        }
    }

    // ------------------------------------------------------------------
    // release
    // ------------------------------------------------------------------

    /// Section 5.1's release: verify a Rand burn attestation and pay it
    /// out of custody. Anyone may submit; the submitter collects the
    /// payload's relayer fee.
    function release(bytes calldata attestation) external override {
        _checkFork();
        if (paused) revert IsPaused();

        Attestation.Parsed memory p = _verify(attestation);
        if (p.emitterChain != Attestation.CHAIN_RAND || p.emitterAddress != randEmitter) revert WrongEmitter();

        Attestation.Transfer memory t = Attestation.parseTransfer(p.payload);
        if (t.toChain != _chainId()) revert WrongToChain();
        if (t.tokenChain != _chainId()) revert WrongTokenChain();
        // `fee <= amount` is Section 3.6's rule on the payload itself, so
        // it is checked here, before anything about this chain's
        // configuration; Section 5.1 lists it later only because it
        // groups it with the denormalisation it precedes.
        if (t.fee > t.amount) revert FeeExceedsAmount();

        address token = _releaseToken(t.tokenAddress);
        TokenConfig storage cfg = _tokenConfigs[token];
        if (!cfg.enabled) revert TokenDisabled();
        address to = _recipient(t.to);

        uint256 amount = _denormalize(t.amount, cfg.decimals);
        uint256 fee = _denormalize(t.fee, cfg.decimals);
        // Attested dust below one unit of this token: paying it out would
        // move nothing while burning the digest, so refuse it instead and
        // leave the burn re-submittable if the token is ever
        // re-configured.
        if (amount == 0) revert ZeroAmount();

        if (custody[token] < amount) revert InsufficientCustody();
        if (cfg.perTransferCap != 0 && amount > cfg.perTransferCap) revert PerTransferCap();
        uint256 window = block.timestamp / 1 days;
        uint256 windowUsed = cfg.windowStart == window ? cfg.windowUsed : 0;
        if (cfg.dailyCap != 0 && windowUsed + amount > cfg.dailyCap) revert DailyCap();

        // Effects before interactions: the digest can never be replayed,
        // not even from inside the token's own transfer.
        consumed[p.digest] = true;
        custody[token] -= amount;
        cfg.windowStart = window;
        cfg.windowUsed = windowUsed + amount;

        emit Released(token, to, amount, fee, p.digest);

        if (fee != 0) {
            _push(token, msg.sender, fee);
        }
        if (amount - fee != 0) {
            _push(token, to, amount - fee);
        }
    }

    /// Pays exactly `amount` of `token` out of custody.
    ///
    /// The mirror of [_pull]: the balance delta is measured and the return
    /// value is not consulted. Tron mainnet USDT's `transfer` moves the
    /// funds and returns `false`, so trusting the return value would make
    /// a lock of it a one-way door; a token that returns `false` (or
    /// anything else) without moving exactly `amount` is caught here
    /// instead, and the whole release reverts with its digest unspent.
    function _push(address token, address to, uint256 amount) private {
        // A whitelisted token can lose its code after the fact; name that
        // failure rather than let `balanceOf` revert without data.
        if (token.code.length == 0) revert SafeTransfer.TransferFailed();
        uint256 balanceBefore = IERC20Metadata(token).balanceOf(address(this));
        token.transferUnchecked(to, amount);
        uint256 balanceAfter = IERC20Metadata(token).balanceOf(address(this));
        if (balanceAfter > balanceBefore || balanceBefore - balanceAfter != amount) {
            revert TransferAmountMismatch();
        }
    }

    /// The token a release payload names. On an EVM/TVM chain a
    /// `token_address` is a left-padded 20-byte contract address
    /// (Section 3.5), so anything in the upper 12 bytes means the payload
    /// names an asset from a different address space and two distinct
    /// 32-byte asset ids could otherwise collapse onto one local token.
    function _releaseToken(bytes32 tokenAddress) internal pure returns (address) {
        if (uint256(tokenAddress) >> 160 != 0) revert BadTokenAddress();
        return address(uint160(uint256(tokenAddress)));
    }

    /// A recipient on this chain must be a left-padded 20-byte address:
    /// anything in the upper 12 bytes means the payload was built for a
    /// different address space (Section 5.2).
    function _recipient(bytes32 to) internal view returns (address) {
        if (uint256(to) >> 160 != 0) revert BadRecipient();
        address addr = address(uint160(uint256(to)));
        if (addr == address(0)) revert ZeroRecipient();
        // Paying the bridge itself would draw custody down while the
        // tokens stayed here, outside the counter, for good.
        if (addr == address(this)) revert BadRecipient();
        return addr;
    }

    // ------------------------------------------------------------------
    // guardian sets
    // ------------------------------------------------------------------

    /// Parses `attestation` and validates everything that does not depend
    /// on the payload: version and envelope, the guardian set's existence
    /// and grace period (Section 3.4), quorum and signatures, and that
    /// the digest has not already been used. Callers check the payload's
    /// own semantics and then mark the digest consumed.
    function _verify(bytes calldata attestation) internal view returns (Attestation.Parsed memory p) {
        p = Attestation.parse(attestation);

        GuardianSet storage set = _guardianSets[p.guardianSetIndex];
        if (set.keys.length == 0) revert UnknownGuardianSet();
        if (p.guardianSetIndex != currentGuardianSetIndex) {
            if (set.expirationTime == 0 || block.timestamp > set.expirationTime) revert GuardianSetExpired();
        }

        Attestation.verifySignatures(p.digest, p.signatures, set.keys);
        if (consumed[p.digest]) revert AlreadyConsumed();
    }

    /// Section 5.1's guardian upgrade. Signed by the *current* set and
    /// carried by the governance emitter, so a burn message can never be
    /// mistaken for a rotation. Indices cannot be skipped or reapplied,
    /// and the superseded set stays usable for one grace period so
    /// in-flight attestations are not stranded.
    ///
    /// Deliberately not gated on `paused` or on `_checkFork()`: pausing
    /// and the fork guard stop value movement (lock and release), and
    /// neither should stand between guardians and rotating away from a
    /// compromised set.
    function submitGuardianSetUpgrade(bytes calldata attestation) external override {
        Attestation.Parsed memory p = _verify(attestation);
        // The grace window `_verify` allows exists so in-flight *transfers*
        // signed by a just-superseded set are not stranded. A rotation gets
        // no such latitude: it must be signed by the set it replaces, or a
        // set the guardians have already rotated away from — possibly
        // because it was compromised — could rotate the bridge again for a
        // whole day. Parity with the fullnode and the Solana program.
        if (p.guardianSetIndex != currentGuardianSetIndex) revert GuardianSetExpired();
        if (p.emitterChain != Attestation.CHAIN_RAND || p.emitterAddress != Attestation.GOVERNANCE_EMITTER) {
            revert WrongEmitter();
        }

        Attestation.GuardianUpgrade memory g = Attestation.parseGuardianUpgrade(p.payload);
        uint32 current = currentGuardianSetIndex;
        if (g.newIndex != current + 1) revert BadUpgradeIndex();
        _checkKeys(g.keys);

        consumed[p.digest] = true;
        _guardianSets[current].expirationTime = block.timestamp + Attestation.GUARDIAN_GRACE;
        _guardianSets[g.newIndex].keys = g.keys;
        currentGuardianSetIndex = g.newIndex;

        emit GuardianSetUpgraded(g.newIndex, g.keys);
    }

    /// A guardian set must be non-empty, hold no zero address (which
    /// `ecrecover` returns on a malformed signature) and no duplicate
    /// (which would let one key count twice towards quorum).
    function _checkKeys(address[] memory keys) internal pure {
        if (keys.length == 0) revert ZeroAddress();
        // Signature and key counts are one byte on the wire: a larger set
        // could be installed here but never reach quorum or be rotated.
        if (keys.length > 255) revert TooManyGuardians();
        for (uint256 i = 0; i < keys.length; i++) {
            if (keys[i] == address(0)) revert ZeroAddress();
            for (uint256 j = i + 1; j < keys.length; j++) {
                if (keys[i] == keys[j]) revert DuplicateGuardian();
            }
        }
    }

    // ------------------------------------------------------------------
    // roles and configuration
    // ------------------------------------------------------------------

    modifier onlyAdmin() {
        _requireAdmin();
        _;
    }

    function _requireAdmin() internal view {
        if (msg.sender != admin) revert NotAdmin();
    }

    /// Whitelists `token` and sets its release caps (native units, 0 =
    /// unlimited), capturing `decimals()` so neither `lock` nor `release`
    /// depends on the token answering later. Re-calling refreshes all
    /// three; the daily window counter is deliberately left alone so
    /// re-configuring a cap cannot reset the day's usage.
    function setToken(address token, bool enabled, uint256 perTransferCap, uint256 dailyCap)
        external
        override
        onlyAdmin
    {
        if (token == address(0)) revert ZeroAddress();

        TokenConfig storage cfg = _tokenConfigs[token];
        cfg.enabled = enabled;
        // Only read `decimals()` when whitelisting. Disabling a token
        // must always be possible, including for a token that has stopped
        // answering (or lost its code entirely) — that is exactly when
        // the admin most needs to switch it off. The stored decimals stay
        // as they were, so re-enabling refreshes them.
        if (enabled) {
            uint8 d = _decimalsOf(token);
            // Custody is counted in native units: rescaling it under an
            // upgradeable token whose decimals moved would misprice every
            // outstanding note, so that needs a deliberate migration.
            if (custody[token] != 0 && d != cfg.decimals) revert DecimalsChanged();
            cfg.decimals = d;
        }
        cfg.perTransferCap = perTransferCap;
        cfg.dailyCap = dailyCap;

        emit TokenConfigured(token, enabled, perTransferCap, dailyCap);
    }

    /// `decimals()` is not part of ERC20 proper, so read it defensively:
    /// a token that does not answer with a usable value cannot be
    /// whitelisted at all (rather than silently defaulting to 18 and
    /// mis-scaling every transfer).
    function _decimalsOf(address token) internal view returns (uint8) {
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(IERC20Metadata.decimals.selector));
        if (!ok || ret.length < 32) revert DecimalsUnavailable();
        uint256 decimals = abi.decode(ret, (uint256));
        if (decimals > MAX_DECIMALS) revert DecimalsUnavailable();
        // casting to 'uint8' is safe because of the bound just above
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint8(decimals);
    }

    function setPauser(address pauser_) external override onlyAdmin {
        pauser = pauser_;
        emit PauserSet(pauser_);
    }

    /// The pause quorum, or the admin. Stops both lock and release.
    function pause() external override {
        if (msg.sender != pauser && msg.sender != admin) revert NotPauser();
        if (paused) revert IsPaused();
        paused = true;
        emit Paused(msg.sender);
    }

    /// Admin only: the pauser can stop the bridge but not restart it.
    function unpause() external override onlyAdmin {
        if (!paused) revert NotPaused();
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// Starts a transfer, or — with `to == address(0)` — cancels the one
    /// in flight.
    function transferAdmin(address to) external override onlyAdmin {
        pendingAdmin = to;
        emit AdminTransferStarted(to);
    }

    /// Second half of the two-step transfer: the new admin proves it can
    /// transact before it owns anything.
    function acceptAdmin() external override {
        // The zero check matters here rather than in `transferAdmin`: with
        // no transfer in flight there is nothing to accept.
        if (pendingAdmin == address(0) || msg.sender != pendingAdmin) revert NotAdmin();
        admin = msg.sender;
        pendingAdmin = address(0);
        emit AdminTransferred(msg.sender);
    }
}
