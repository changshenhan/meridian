// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

/// @notice meridian-core `intent_hash` 的 Solidity 镜像（S-11 欺诈证明重算用）。
///         「链上与链下同一 intent_hash」交叉实现契约（TECH_SPEC §7 / §11 E-03）：
///         改任一侧，另一侧的重算立即失配。与 core/src/dsa.rs::intent_hash 的字节序列
///         逐字节对齐（前缀 "INTv1\0" + 各字段 u64 小端），golden vector 锁常量
///         （contracts/test/IntentHelper.t.sol）。
library IntentHelper {
    /// u64 小端编码（core 侧 push_u64 相同语义）。
    function u64LE(uint64 v) internal pure returns (bytes memory) {
        bytes memory b = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            b[i] = bytes1(uint8(v >> (8 * i)));
        }
        return b;
    }

    /// 重算 intent_hash：`sha256("INTv1\0" ‖ agent(20) ‖ delegationHash(32) ‖
    /// recipient(20) ‖ amount_le(8) ‖ category(32) ‖ spendNonce_le(8) ‖ memoTag(1)
    /// ‖ expiresAt_le(8))`；memo 空 → tag 0x00，非空（须 32B）→ tag 0x01 + memo(32)。
    function computeIntentHash(
        bytes20 agent,
        bytes32 delegationHash,
        bytes20 recipient,
        uint64 amount,
        bytes32 category,
        uint64 spendNonce,
        bytes memory memo,
        uint64 expiresAt
    ) internal pure returns (bytes32) {
        require(memo.length == 0 || memo.length == 32, "memo: empty or 32B");
        bytes memory pre = bytes.concat(
            hex"494e547631", // "INTv1"
            bytes1(0x00), // "\0" —— 前缀共 6 字节
            agent,
            delegationHash,
            recipient,
            u64LE(amount),
            category,
            u64LE(spendNonce),
            memo.length == 0 ? bytes1(0x00) : bytes1(0x01),
            memo,
            u64LE(expiresAt)
        );
        return sha256(pre);
    }
}
