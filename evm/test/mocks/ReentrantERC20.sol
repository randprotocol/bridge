// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

/// @notice A malicious 8-decimal ERC20 for the reentrancy tests: once
/// armed, its next `transfer` or `transferFrom` moves the funds and then
/// calls `target` with `reentry` from inside the token call, the way a
/// token with a transfer hook (ERC-777, or an upgraded token) could.
///
/// The inner call's result is recorded and swallowed, so the outer call
/// goes on and a test can assert what the bridge did with the reentry.
contract ReentrantERC20 {
    uint8 public constant decimals = 8;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public target;
    bytes public reentry;
    bool public armed;

    /// Set once the hook has fired; `innerOk`/`innerRevert` are the inner
    /// call's outcome.
    bool public reentered;
    bool public innerOk;
    bytes public innerRevert;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    /// Lets the token itself be the depositor of a re-entered `lock`.
    function selfApprove(address spender) external {
        allowance[address(this)][spender] = type(uint256).max;
    }

    /// One shot: the next token call re-enters `target` with `data`.
    function arm(address target_, bytes calldata data) external {
        target = target_;
        reentry = data;
        armed = true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        _hook();
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "ReentrantERC20: allowance");
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        _move(from, to, amount);
        _hook();
        return true;
    }

    function _move(address from, address to, uint256 amount) private {
        require(balanceOf[from] >= amount, "ReentrantERC20: balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }

    function _hook() private {
        if (!armed) return;
        armed = false;
        reentered = true;
        (innerOk, innerRevert) = target.call(reentry);
    }
}
