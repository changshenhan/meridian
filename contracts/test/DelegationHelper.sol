// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

/// @notice mist-core `canonical_delegation` 的 Solidity 镜像（forge 测试 / alloy 冒烟共用）。
///         两侧 `sha256` 必须一致——这是 TECH_SPEC §7 "链上与链下同一 delegation_hash" 的
///         交叉实现契约：改任何一侧，另一侧的 sha256 校验立即失配（§11 E-03）。
///         与 core/src/dsa.rs::sample_delegation 的字段定序逐字节对齐。
library DelegationHelper {
    /// u64 小端编码（core 侧 push_u64 相同语义）。
    function u64LE(uint64 v) internal pure returns (bytes memory) {
        bytes memory b = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            b[i] = bytes1(uint8(v >> (8 * i)));
        }
        return b;
    }

    /// u32 小端编码（core 侧 push_u32 相同语义）。
    function u32LE(uint32 v) internal pure returns (bytes memory) {
        bytes memory b = new bytes(4);
        for (uint256 i = 0; i < 4; i++) {
            b[i] = bytes1(uint8(v >> (8 * i)));
        }
        return b;
    }

    /// 固定委托，唯一可变位是 owner。返回规范字节 + delegation_hash。
    function buildDelegation(address owner)
        internal
        pure
        returns (bytes memory abiBytes, bytes32 delegationHash)
    {
        abiBytes = bytes.concat(
            hex"4453417631", // "DSAv1"
            bytes1(0x00), // "\0" —— 前缀共 6 字节
            hex"0101010101010101010101010101010101010101", // agent（20 字节）
            abi.encodePacked(owner), // owner（20 字节）
            u64LE(1), // nonce
            u64LE(1000), // max_per_spend
            u64LE(60), // window_secs
            u64LE(10_000), // max_per_window
            u64LE(100_000), // total_cap
            u32LE(0), // categories_len（空白名单）
            u64LE(0), // not_before
            u64LE(type(uint64).max), // expires_at
            bytes1(0x01) // version
        );
        delegationHash = sha256(abiBytes);
    }
}
