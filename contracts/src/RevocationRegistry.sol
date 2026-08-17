// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

import {DSA} from "./DSA.sol";

/// @title RevocationRegistry —— 撤销锚点（TECH_SPEC §7）
/// @notice 仅委托 owner 可撤销。聚合器（S-10）在快路径先查 `isRevoked` 拒绝已撤销委托
///         （Contract 模式）；撤销根进电路（S-09）后，ZK 模式同样受此锚点约束。
/// @dev S-06 最小可跑版：owner 来源从 DSA.ownerOf 读取（不再重复存一份，避免两处状态
///      漂移）。撤销事件 S-11 对接聚合器撤销根。
contract RevocationRegistry {
    event Revoked(bytes32 indexed delegationHash, address indexed by);

    error NotOwner();
    error NotRegistered(bytes32 delegationHash);

    /// DSA 注册表（撤销前必须已注册）。
    DSA public immutable dsa;

    mapping(bytes32 => bool) public revoked;

    constructor(DSA _dsa) {
        dsa = _dsa;
    }

    /// 仅 owner：撤销一张已注册委托。
    function revoke(bytes32 delegationHash) external {
        address owner = dsa.ownerOf(delegationHash);
        if (owner == address(0)) revert NotRegistered(delegationHash);
        if (msg.sender != owner) revert NotOwner();
        revoked[delegationHash] = true;
        emit Revoked(delegationHash, msg.sender);
    }

    /// TECH_SPEC §7：委托是否已撤销。
    function isRevoked(bytes32 delegationHash) external view returns (bool) {
        return revoked[delegationHash];
    }
}
