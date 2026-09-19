// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

/// @title IRandBridge
/// @notice The external surface every EVM/TVM Rand bridge endpoint shares
/// (`EthereumRandBridge`, `BscRandBridge`, `TronRandBridge`), as specified
/// by Section 5 of the Rand bridge design.
///
/// Events, errors and structs live here so relayers, guardians and tests
/// can bind against one artifact regardless of which chain's deployment
/// they are talking to.
interface IRandBridge {
    /// A message for the guardians. Guardians rebuild the Section 3.2
    /// body from this event plus the block timestamp, the emitter chain
    /// id constant and the contract address.
    event MessagePublished(uint64 indexed sequence, uint32 nonce, uint8 consistencyLevel, bytes payload);
    /// `locked` is in the token's own units (what custody grew by),
    /// `attested` the 8-decimal value the guardians will sign over.
    event Locked(
        address indexed token,
        address indexed from,
        bytes32 indexed randRecipient,
        uint256 locked,
        uint256 attested,
        uint64 sequence
    );
    /// `amount` and `fee` are denormalised token units; `amount` includes
    /// `fee` (the recipient receives `amount - fee`).
    event Released(address indexed token, address indexed to, uint256 amount, uint256 fee, bytes32 digest);
    event TokenConfigured(address indexed token, bool enabled, uint256 perTransferCap, uint256 dailyCap);
    event GuardianSetUpgraded(uint32 indexed index, address[] keys);
    event Paused(address by);
    event Unpaused(address by);
    event AdminTransferStarted(address indexed to);
    event AdminTransferred(address indexed to);
    event PauserSet(address indexed pauser);

    /// Caps are in the token's native units and apply to releases only; 0
    /// means unlimited. `windowStart` is a day index
    /// (`block.timestamp / 1 days`) and `windowUsed` the units released in
    /// that day.
    struct TokenConfig {
        bool enabled;
        uint8 decimals;
        uint256 perTransferCap;
        uint256 dailyCap;
        uint256 windowStart;
        uint256 windowUsed;
    }

    /// `expirationTime == 0` means "not superseded"; a superseded set is
    /// usable until `expirationTime` (Section 3.4's 86400 s grace).
    struct GuardianSet {
        address[] keys;
        uint256 expirationTime;
    }

    error NotAdmin();
    error NotPauser();
    error IsPaused();
    error NotPaused();
    error TokenDisabled();
    error ZeroRecipient();
    error FeeExceedsAmount();
    error ZeroAmount();
    /// A lock's attested amount would not fit the `u64` a Rand note holds,
    /// so Rand could never mint it (`BridgeError::AmountTooLarge` there).
    error AmountTooLarge();
    error TransferAmountMismatch();
    error WrongEmitter();
    error WrongToChain();
    error WrongTokenChain();
    error AlreadyConsumed();
    error InsufficientCustody();
    error PerTransferCap();
    error DailyCap();
    error BadRecipient();
    /// A release payload's `token_address` is not a left-padded 20-byte
    /// address on this chain.
    error BadTokenAddress();
    error UnknownGuardianSet();
    error GuardianSetExpired();
    error BadUpgradeIndex();
    error DuplicateGuardian();
    error WrongFork();
    error ZeroAddress();
    /// `setToken` could not read a usable `decimals()` from the token.
    error DecimalsUnavailable();
    /// `setToken` found different `decimals()` while custody is outstanding.
    error DecimalsChanged();
    /// A guardian set larger than an attestation's one-byte counts can carry.
    error TooManyGuardians();

    function lock(address token, uint256 amount, bytes32 randRecipient, uint256 relayerFee, uint32 nonce)
        external
        returns (uint64 sequence);
    function release(bytes calldata attestation) external;
    function submitGuardianSetUpgrade(bytes calldata attestation) external;
    function setToken(address token, bool enabled, uint256 perTransferCap, uint256 dailyCap) external;
    function setPauser(address pauser) external;
    function pause() external;
    function unpause() external;
    function transferAdmin(address to) external;
    function acceptAdmin() external;
    function chainId() external view returns (uint16);
    function randEmitter() external view returns (bytes32);
    function currentGuardianSetIndex() external view returns (uint32);
    function guardianSet(uint32 index) external view returns (GuardianSet memory);
    function custody(address token) external view returns (uint256);
    function consumed(bytes32 digest) external view returns (bool);
    function tokenConfig(address token) external view returns (TokenConfig memory);
    function sequence() external view returns (uint64);
    function normalize(uint256 amount, uint8 decimals) external pure returns (uint256 locked, uint256 attested);
    function denormalize(uint256 attested, uint8 decimals) external pure returns (uint256);
}
