// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

/// @notice sha256 Merkle 包含验证器（S-11 欺诈证明用），与 aggregator/src/merkle.rs
///         逐字节对齐：叶子 = sha256(seq_le(8) ‖ intent_hash(32))，补齐到 2 的幂，
///         空叶 = sha256("")，内部 = sha256(left‖right)。已知向量测试锁常量
///         （contracts/test/Merkle.t.sol）。
library Merkle {
    /// 空叶子 / 补齐叶子（sha256("")）。与 aggregator::merkle::EMPTY_LEAF 相同常量。
    bytes32 constant EMPTY_LEAF =
        0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;

    /// 叶子 = sha256(seq_le(8) ‖ intent_hash(32)) —— seq 小端，与 merkle.rs::leaf 同构。
    function leaf(uint64 seq, bytes32 intentHash) internal pure returns (bytes32) {
        bytes memory b = new bytes(40);
        for (uint256 i = 0; i < 8; i++) {
            b[i] = bytes1(uint8(seq >> (8 * i)));
        }
        for (uint256 i = 0; i < 32; i++) {
            b[8 + i] = intentHash[i];
        }
        return sha256(b);
    }

    /// next_power_of_two（空输入按 1）。
    function nextPowerOfTwo(uint256 n) internal pure returns (uint256) {
        if (n == 0) return 1;
        uint256 p = 1;
        while (p < n) p <<= 1;
        return p;
    }

    /// 树深 = log2(next_power_of_two(n))；n<=1 → 0。
    function treeDepth(uint256 n) internal pure returns (uint256) {
        uint256 d = 0;
        for (uint256 s = nextPowerOfTwo(n); s > 1; s >>= 1) {
            d++;
        }
        return d;
    }

    /// 从 (leafHash, index, acceptedCount, siblings) 重推根。index/siblings 与 acceptedCount
    /// 不匹配 → 根不匹配 commitmentRoot（自校验）。siblings 顺序从底层向上。
    function computeRoot(
        bytes32 leafHash,
        uint256 index,
        uint256 acceptedCount,
        bytes32[] memory siblings
    ) internal pure returns (bytes32) {
        require(index < acceptedCount, "leafIndex out of bounds");
        require(siblings.length == treeDepth(acceptedCount), "wrong depth");
        bytes32 h = leafHash;
        for (uint256 i = 0; i < siblings.length; i++) {
            bytes32 s = siblings[i];
            h = ((index >> i) & 1) == 0
                ? sha256(abi.encodePacked(h, s))
                : sha256(abi.encodePacked(s, h));
        }
        return h;
    }
}
