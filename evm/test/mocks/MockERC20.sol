// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

/// @notice Minimal ERC20 for the bridge tests, with the two real-world
/// deviations the bridge has to cope with:
///
/// - `setNoReturn(true)`: `transfer`/`transferFrom` return **no** data at
///   all, the way mainnet USDT does. `SafeTransfer` must accept this.
/// - `setFee(bps)`: fee-on-transfer, i.e. the recipient is credited less
///   than the sender was debited. `lock()` must reject this
///   (`TransferAmountMismatch`) rather than mis-account custody.
///
/// Decimals are a constructor argument so the same mock covers the 6dp
/// (USDT on Ethereum), 8dp (attested-units) and 18dp (BSC) paths.
contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// When true, `transfer`/`transferFrom` return zero-length data.
    bool public noReturn;
    /// When true, `transfer` moves the funds and then returns `false`
    /// (Tron mainnet USDT); `transferFrom` still returns `true`.
    bool public transferReturnsFalse;
    /// When true, `transfer` returns `false` and moves nothing.
    bool public silentFail;
    /// Fee taken from every transfer, in basis points of the amount.
    uint256 public feeBps;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory name_, string memory symbol_, uint8 decimals_) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
    }

    function setDecimals(uint8 d) external {
        decimals = d;
    }

    function setNoReturn(bool on) external {
        noReturn = on;
    }

    function setTransferReturnsFalse(bool on) external {
        transferReturnsFalse = on;
    }

    function setSilentFail(bool on) external {
        silentFail = on;
    }

    function setFee(uint256 bps) external {
        require(bps <= 10_000, "MockERC20: fee too high");
        feeBps = bps;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (silentFail) return false;
        _move(msg.sender, to, amount);
        _maybeReturnNothing();
        return !transferReturnsFalse;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (from != msg.sender) {
            uint256 allowed = allowance[from][msg.sender];
            require(allowed >= amount, "MockERC20: allowance");
            if (allowed != type(uint256).max) {
                allowance[from][msg.sender] = allowed - amount;
            }
        }
        _move(from, to, amount);
        _maybeReturnNothing();
        return true;
    }

    function _move(address from, address to, uint256 amount) private {
        uint256 bal = balanceOf[from];
        require(bal >= amount, "MockERC20: balance");
        balanceOf[from] = bal - amount;

        uint256 fee = amount * feeBps / 10_000;
        uint256 credited = amount - fee;
        balanceOf[to] += credited;
        if (fee != 0) {
            totalSupply -= fee; // burnt, so the mock stays solvent
        }
        emit Transfer(from, to, credited);
    }

    /// Returns from the *enclosing external call* with empty return data,
    /// after the state change above has already been applied — exactly
    /// what a USDT-style token looks like to a caller.
    function _maybeReturnNothing() private view {
        if (noReturn) {
            assembly {
                return(0, 0)
            }
        }
    }
}
