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

    /// 撤销时刻（P2-3 §6.20.2/§6.23）：delegation_hash -> 首次撤销的 block.timestamp。
    /// kind3（已撤销消费）守卫的时间下界锚（`revokedAt(dh) + ACCEPT_MARGIN <= acceptedAt`）。
    /// 粘性语义：只在本委托第一次 revoke 时写（重复 revoke 幂等不重写）——撤销不可解除，
    /// 「最早可观察撤销时刻」才是诚实下界（写晚 = 守卫偏松放过罚、写早 = 假阳性），锚定
    /// 首次即两侧都不偏。零值 = 未撤销（与 `revoked` 布尔同语义）。
    mapping(bytes32 => uint64) public revokedAt;

    constructor(DSA _dsa) {
        dsa = _dsa;
    }

    /// 仅 owner：撤销一张已注册委托。幂等（重复撤销不 revert、时刻锚不重写）。
    function revoke(bytes32 delegationHash) external {
        address owner = dsa.ownerOf(delegationHash);
        if (owner == address(0)) revert NotRegistered(delegationHash);
        if (msg.sender != owner) revert NotOwner();
        revoked[delegationHash] = true;
        if (revokedAt[delegationHash] == 0) {
            revokedAt[delegationHash] = uint64(block.timestamp);
        }
        emit Revoked(delegationHash, msg.sender);
    }

    /// TECH_SPEC §7：委托是否已撤销。
    function isRevoked(bytes32 delegationHash) external view returns (bool) {
        return revoked[delegationHash];
    }
}
