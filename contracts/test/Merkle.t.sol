// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Merkle} from "../src/Merkle.sol";
import {ChallengeTestHelper} from "./ChallengeTestHelper.sol";
import {MerkleHarness} from "./InternalHarnesses.sol";

/// S-11a：Merkle.sol 与 aggregator/src/merkle.rs 的交叉实现已知向量。
/// golden hex 由 Rust（print_s11_golden 临时工具）计算并锁定 → sha256 预编译对齐。
contract MerkleTest is Test, ChallengeTestHelper {
    bytes32 internal constant IH1 =
        bytes32(0x436c7472c924c77210d885041a2b154dfc97ad1faf7a9f746eb40503d67e10cd);
    bytes32 internal constant IH2 =
        bytes32(0x980b9e9cf12d59d3f407fbf7f83d5c25fe9c1a0fe3630dbac5f437ac665ad590);
    bytes32 internal constant IH3 =
        bytes32(0xd8575145993fe54bf47e777a961486782838afe5f5b00ae692bc8fb68a3aefe1);
    bytes32 internal constant L1 =
        bytes32(0x6cff56c3eaf2eace39593437ac4cb566a870d11436e120c47d8c6ec5a2cba64d);
    bytes32 internal constant L2 =
        bytes32(0x6e2d5cc1c1df48e5272f1769cc82991cd2cf6189385517f84fd98923dfb8e437);
    bytes32 internal constant L3 =
        bytes32(0xad9bbfd4fbd224a117f0a6af939187f1cd3a1e0246d9f344b6e8a3cfad0237c7);
    bytes32 internal constant ROOT =
        bytes32(0x7ed38000e72f87c2c0a205f55e885010e01746c8a6a085d5f9e6237399258757);

    function test_empty_leaf_constant_matches_rust() public pure {
        assertEq(Merkle.EMPTY_LEAF, bytes32(0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855));
    }

    function test_leaf_golden_vectors() public pure {
        assertEq(leaf(1, IH1), L1);
        assertEq(leaf(2, IH2), L2);
        assertEq(leaf(3, IH3), L3);
    }

    function test_merkle_root_golden_vector() public pure {
        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = L1;
        leaves[1] = L2;
        leaves[2] = L3;
        assertEq(merkleRoot(leaves), ROOT);
    }

    /// computeRoot 沿完整路径重推根 == 已知根（索引 1，3 叶 → 深度 2）。
    function test_compute_root_matches_known_root() public pure {
        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = L1;
        leaves[1] = L2;
        leaves[2] = L3;
        (uint256 accepted, bytes32[] memory siblings) = proofFor(leaves, 1);
        assertEq(accepted, 3);
        assertEq(siblings.length, 2);
        assertEq(Merkle.computeRoot(L2, 1, 3, siblings), ROOT);
    }

    function test_tree_depth() public pure {
        assertEq(Merkle.treeDepth(1), 0);
        assertEq(Merkle.treeDepth(2), 1);
        assertEq(Merkle.treeDepth(3), 2);
        assertEq(Merkle.treeDepth(4), 2);
        assertEq(Merkle.treeDepth(100_000), 17);
    }

    function test_compute_root_rejects_out_of_bounds_index() public {
        MerkleHarness h = new MerkleHarness();
        bytes32[] memory siblings = new bytes32[](0);
        vm.expectRevert("leafIndex out of bounds");
        h.computeRoot(L1, 5, 1, siblings);
    }

    function test_compute_root_rejects_wrong_depth() public {
        MerkleHarness h = new MerkleHarness();
        bytes32[] memory siblings = new bytes32[](1);
        vm.expectRevert("wrong depth");
        h.computeRoot(L1, 0, 1, siblings);
    }
}
