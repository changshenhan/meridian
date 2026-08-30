// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

import {BatchSettler} from "../src/BatchSettler.sol";
import {IntentHelper} from "../src/IntentHelper.sol";
import {Merkle} from "../src/Merkle.sol";

/// @notice S-11 测试助手：在 Solidity 内镜像 aggregator/src/merkle.rs 的 merkle_root +
///         inclusion-proof 生成器，供 forge 测试构造欺诈证明（等价于 Rust 证明生成器）。
///         已知向量测试（Merkle.t.sol）+ 端到端挑战测试锁定与 Rust 侧逐字节一致。
contract ChallengeTestHelper {
    /// 与 BatchSettler.IntentProof 前 8 个字段对齐的意图明文（测试构造用）。
    struct IntentFields {
        bytes20 agent;
        bytes32 delegationHash;
        bytes20 recipient;
        uint64 amount;
        bytes32 category;
        uint64 spendNonce;
        bytes memo;
        uint64 expiresAt;
    }

    /// 承诺格包含位置（与聚合器证明生成器输出对齐）。
    struct ProofBundle {
        uint64 seq;
        uint256 leafIndex;
        uint256 acceptedCount;
        bytes32[] siblings;
    }

    function intentHash(IntentFields memory i) internal pure returns (bytes32) {
        return IntentHelper.computeIntentHash(
            i.agent,
            i.delegationHash,
            i.recipient,
            i.amount,
            i.category,
            i.spendNonce,
            i.memo,
            i.expiresAt
        );
    }

    function leaf(uint64 seq, bytes32 ih) internal pure returns (bytes32) {
        return Merkle.leaf(seq, ih);
    }

    /// 镜像 merkle.rs::merkle_root：2 的幂补齐 + EMPTY_LEAF + sha256(left‖right)。
    function merkleRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        uint256 n = leaves.length;
        if (n == 0) return Merkle.EMPTY_LEAF;
        uint256 size = 1;
        while (size < n) size <<= 1;
        bytes32[] memory layer = new bytes32[](size);
        for (uint256 i = 0; i < n; i++) {
            layer[i] = leaves[i];
        }
        for (uint256 i = n; i < size; i++) {
            layer[i] = Merkle.EMPTY_LEAF;
        }
        while (size > 1) {
            bytes32[] memory next = new bytes32[](size / 2);
            for (uint256 i = 0; i < size / 2; i++) {
                next[i] = sha256(abi.encodePacked(layer[2 * i], layer[2 * i + 1]));
            }
            layer = next;
            size /= 2;
        }
        return layer[0];
    }

    /// 镜像聚合器 inclusion-proof 生成器：返回 (acceptedCount, siblings[从底层向上])。
    function proofFor(bytes32[] memory leaves, uint256 index)
        internal
        pure
        returns (uint256, bytes32[] memory)
    {
        uint256 n = leaves.length;
        require(index < n, "idx");
        uint256 size = 1;
        while (size < n) size <<= 1;
        bytes32[] memory layer = new bytes32[](size);
        for (uint256 i = 0; i < n; i++) {
            layer[i] = leaves[i];
        }
        for (uint256 i = n; i < size; i++) {
            layer[i] = Merkle.EMPTY_LEAF;
        }
        uint256 depth = 0;
        for (uint256 s = size; s > 1; s >>= 1) {
            depth++;
        }
        bytes32[] memory siblings = new bytes32[](depth);
        uint256 idx = index;
        for (uint256 d = 0; d < depth; d++) {
            siblings[d] = layer[idx ^ 1];
            bytes32[] memory next = new bytes32[](layer.length / 2);
            for (uint256 i = 0; i < layer.length / 2; i++) {
                next[i] = sha256(abi.encodePacked(layer[2 * i], layer[2 * i + 1]));
            }
            layer = next;
            idx /= 2;
        }
        return (n, siblings);
    }

    /// 从意图明文 + 证明位置构造 BatchSettler.IntentProof。
    function toIntentProof(IntentFields memory i, ProofBundle memory pb)
        internal
        pure
        returns (BatchSettler.IntentProof memory)
    {
        return BatchSettler.IntentProof({
            agent: i.agent,
            delegationHash: i.delegationHash,
            recipient: i.recipient,
            amount: i.amount,
            category: i.category,
            spendNonce: i.spendNonce,
            memo: i.memo,
            expiresAt: i.expiresAt,
            seq: pb.seq,
            leafIndex: pb.leafIndex,
            acceptedCount: pb.acceptedCount,
            siblings: pb.siblings
        });
    }
}
