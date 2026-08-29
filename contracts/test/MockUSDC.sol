// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

/// S-28 测试替身：最小 ERC-20（6 decimals 对齐真实 USDC），仅测试用。
/// 只实现 BatchSettler 依赖的最小面：transfer / transferFrom / balanceOf /
/// approve-allowance / mint / 黑名单。
/// 失败语义：返回 `false`（让 BatchSettler 走 `TokenTransferFailed` 包装路径）。
/// 注：真实 USDC 在黑名单/余额不足时是 **revert**（reason 冒泡，不进包装）——两种
/// token 形态 BatchSettler 都安全（false → 包装错误；revert → 原样冒泡，状态同回滚）。
contract MockUSDC {
    string public constant name = "USD Coin";
    string public constant symbol = "USDC";
    uint8 public constant decimals = 6;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    /// 真实 USDC 语义：黑名单账户的收付都会 revert。
    mapping(address => bool) public blacklisted;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

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
        return _move(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        if (a < amount) return false;
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        return _move(from, to, amount);
    }

    /// 测试钩子：模拟黑名单冻结（收付均失败）。
    function setBlacklist(address who, bool on) external {
        blacklisted[who] = on;
    }

    function _move(address from, address to, uint256 amount) internal returns (bool) {
        if (blacklisted[from] || blacklisted[to]) return false;
        if (balanceOf[from] < amount) return false;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
