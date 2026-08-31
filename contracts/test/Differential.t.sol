// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntentHelper} from "../src/IntentHelper.sol";
import {Merkle} from "../src/Merkle.sol";
import {BatchSettler} from "../src/BatchSettler.sol";

/// S-57 跨实现差分 fuzz（审计四步路径 ③，TECH_SPEC §8.3）。
///
/// fixture `test/fixtures/differential.json` 由 `contracts/rust-smoke/src/bin/difffuzz.rs`
/// （splitmix64 固定种子）调用 **Rust 生产实现**（core::dsa / aggregator::merkle /
/// aggregator::lattice）生成；verify.sh 步 8b 重生成 `cmp` 做漂移闸。本测试只做
/// 「Rust golden ⇄ Solidity 镜像」逐条比对——期望值不在这里产生，不在测试里重写
/// Rust 语义（S-11a 的单 golden 是定点抽查，这里是批量差分）。
///
/// 覆盖五条交叉实现契约（S-11 深度审计逐行核对过的面）：
///  1. `IntentHelper.computeIntentHash` ↔ `core::dsa::intent_hash`（64 向量）
///  2. `DSA.sha256(delegationABI)` + owner 切片 [26:46] ↔ `delegation_hash`（32 向量）
///  3. `Merkle.leaf` / 补齐根 / `Merkle.computeRoot` 重推 ↔ `aggregator::merkle`（8 叶 + 10 树 + 10 证明）
///  4. `nettingRoot = keccak256(abi.encode(net))` ↔ `abi_encode_net`（16 向量，编码字节级比对）
///  5. `Merkle.acceptanceLeaf` ↔ `merkle::acceptance_leaf`（8 向量，P2-3 §6.23 接受锚叶）
contract DifferentialTest is Test {
    string internal fixture;

    function setUp() public {
        fixture = vm.readFile("test/fixtures/differential.json");
    }

    // ---- 内部工具（不做语义重写，只做字节搬运） -------------------------------

    /// bytes[off:off+32] 装载为 word（fixture 的叶子/兄弟/编码都是扁平 hex）。
    function _word(bytes memory b, uint256 off) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 0x20), off))
        }
    }

    /// 扁平叶子数组重算补齐根（镜像 Merkle.sol 文档语义：补齐到 2 的幂 + EMPTY_LEAF，
    /// 逐层 sha256(left‖right)）。树根面的第三锚——与 Rust golden、computeRoot 重推
    /// 三方必须同值。
    function _paddedRoot(bytes memory flat, uint256 n) internal pure returns (bytes32) {
        if (n == 0) return Merkle.EMPTY_LEAF;
        uint256 p = 1;
        while (p < n) p <<= 1;
        bytes32[] memory layer = new bytes32[](p);
        for (uint256 i; i < p; i++) {
            layer[i] = i < n ? _word(flat, 32 * i) : Merkle.EMPTY_LEAF;
        }
        while (layer.length > 1) {
            bytes32[] memory next = new bytes32[](layer.length / 2);
            for (uint256 i; i < next.length; i++) {
                next[i] = sha256(abi.encodePacked(layer[2 * i], layer[2 * i + 1]));
            }
            layer = next;
        }
        return layer[0];
    }

    // ---- 面 1：intent_hash ---------------------------------------------------

    function test_intent_hash_differential() public {
        // 注意：agent/recipient 走 address 解析——`bytes(string)` 是 ASCII 字节不是
        // hex 解码（本测试首跑在此翻过车，差分闸当场咬住）。
        address[] memory agents = vm.parseJsonAddressArray(fixture, ".intents.agent");
        bytes[] memory dhs = vm.parseJsonBytesArray(fixture, ".intents.delegationHash");
        address[] memory recipients = vm.parseJsonAddressArray(fixture, ".intents.recipient");
        uint256[] memory amounts = vm.parseJsonUintArray(fixture, ".intents.amount");
        bytes[] memory categories = vm.parseJsonBytesArray(fixture, ".intents.category");
        uint256[] memory nonces = vm.parseJsonUintArray(fixture, ".intents.spendNonce");
        bytes[] memory memos = vm.parseJsonBytesArray(fixture, ".intents.memo");
        uint256[] memory expiries = vm.parseJsonUintArray(fixture, ".intents.expiresAt");
        bytes32[] memory hashes = vm.parseJsonBytes32Array(fixture, ".intents.hash");

        assertEq(agents.length, hashes.length, "fixture column count mismatch");
        for (uint256 i; i < hashes.length; i++) {
            bytes32 got = IntentHelper.computeIntentHash(
                bytes20(uint160(agents[i])),
                bytes32(dhs[i]),
                bytes20(uint160(recipients[i])),
                uint64(amounts[i]),
                bytes32(categories[i]),
                uint64(nonces[i]),
                memos[i],
                uint64(expiries[i])
            );
            if (got != hashes[i]) {
                emit log_named_uint("intent_hash mismatch @ index", i);
                emit log_named_bytes32("solidity", got);
                emit log_named_bytes32("rust golden", hashes[i]);
            }
            assertEq(got, hashes[i]);
        }
    }

    // ---- 面 2：delegation_hash + owner 切片 -----------------------------------

    function test_delegation_hash_and_owner_slice_differential() public {
        bytes[] memory abis = vm.parseJsonBytesArray(fixture, ".delegations.abi");
        bytes32[] memory hashes = vm.parseJsonBytes32Array(fixture, ".delegations.hash");
        address[] memory owners = vm.parseJsonAddressArray(fixture, ".delegations.owner");

        assertEq(abis.length, hashes.length, "fixture column count mismatch");
        for (uint256 i; i < hashes.length; i++) {
            // DSA.registerDelegation 同款：dh = sha256(delegationABI)。
            bytes32 got = sha256(abis[i]);
            assertEq(got, hashes[i], "delegation_hash mismatch");

            // owner 锚：DSA.sol 从 [26:46] 读 owner（前缀 6 + agent 20）。bytes memory
            // 不支持切片，用 word 装载（字节 26 是 word 的最高位字节 → 右移 96 bit 取
            // 高 20B，与 [26:46] 等价）。
            assertEq(
                address(uint160(uint256(_word(abis[i], 26)) >> 96)),
                owners[i],
                "owner slice [26:46] mismatch"
            );
        }
    }

    // ---- 面 3：Merkle 叶 / 补齐根 / 包含证明重推 / 树深 -------------------------

    function test_merkle_leaf_differential() public {
        uint256[] memory seqs = vm.parseJsonUintArray(fixture, ".merkleLeaves.seq");
        bytes32[] memory ihs = vm.parseJsonBytes32Array(fixture, ".merkleLeaves.intentHash");
        bytes32[] memory expect = vm.parseJsonBytes32Array(fixture, ".merkleLeaves.leaf");
        for (uint256 i; i < expect.length; i++) {
            assertEq(Merkle.leaf(uint64(seqs[i]), ihs[i]), expect[i], "leaf mismatch");
        }
    }

    function test_merkle_padded_root_differential() public {
        uint256[] memory counts = vm.parseJsonUintArray(fixture, ".merkleTrees.count");
        bytes[] memory flats = vm.parseJsonBytesArray(fixture, ".merkleTrees.leaves");
        bytes32[] memory roots = vm.parseJsonBytes32Array(fixture, ".merkleTrees.root");
        assertEq(counts.length, roots.length, "fixture column count mismatch");
        for (uint256 i; i < roots.length; i++) {
            bytes32 recomputed = _paddedRoot(flats[i], counts[i]);
            assertEq(recomputed, roots[i], "padded root mismatch (non-power-of-two padding)");
        }
    }

    function test_merkle_inclusion_proof_differential() public {
        uint256[] memory counts = vm.parseJsonUintArray(fixture, ".merkleProofs.count");
        uint256[] memory indexes = vm.parseJsonUintArray(fixture, ".merkleProofs.index");
        bytes32[] memory leaves = vm.parseJsonBytes32Array(fixture, ".merkleProofs.leaf");
        bytes[] memory siblings = vm.parseJsonBytesArray(fixture, ".merkleProofs.siblings");
        bytes32[] memory roots = vm.parseJsonBytes32Array(fixture, ".merkleProofs.root");

        assertEq(counts.length, roots.length, "fixture column count mismatch");
        for (uint256 i; i < roots.length; i++) {
            uint256 depth = Merkle.treeDepth(counts[i]);
            assertEq(siblings[i].length / 32, depth, "sibling depth != treeDepth(count)");
            bytes32[] memory sibs = new bytes32[](depth);
            for (uint256 j; j < depth; j++) {
                sibs[j] = _word(siblings[i], 32 * j);
            }
            // 生产函数本体（欺诈证明链上验证路径，非测试替身）。
            bytes32 got = Merkle.computeRoot(leaves[i], indexes[i], counts[i], sibs);
            assertEq(got, roots[i], "computeRoot rederive mismatch");
            // 补齐根面（test_merkle_padded_root_differential）用同一批树的 Rust golden，
            // 三方（Rust merkle_root / 链上重推 / 测试镜像）已在该用例锁定同值。
        }
    }

    function test_merkle_tree_depth_differential() public {
        uint256[] memory counts = vm.parseJsonUintArray(fixture, ".merkleDepths.count");
        uint256[] memory expect = vm.parseJsonUintArray(fixture, ".merkleDepths.expect");
        for (uint256 i; i < counts.length; i++) {
            assertEq(Merkle.treeDepth(counts[i]), expect[i], "treeDepth mismatch");
        }
    }

    function test_merkle_empty_root_constant() public {
        bytes32 golden = vm.parseJsonBytes32(fixture, ".merkleEmptyRoot");
        // sha256("") 的 32B —— Rust EMPTY_LEAF 与 Solidity 常量同源。
        assertEq(Merkle.EMPTY_LEAF, golden, "EMPTY_LEAF constant drift");
        assertEq(Merkle.EMPTY_LEAF, sha256(hex""), "sha256 of empty string");
    }

    // ---- 面 4：nettingRoot = keccak256(abi.encode(net)) ------------------------

    function test_netting_root_differential() public {
        uint256[] memory counts = vm.parseJsonUintArray(fixture, ".netCases.count");
        address[] memory recipients = vm.parseJsonAddressArray(fixture, ".netCases.recipient");
        uint256[] memory amounts = vm.parseJsonUintArray(fixture, ".netCases.amount");
        bytes[] memory encodings = vm.parseJsonBytesArray(fixture, ".netCases.encoding");
        bytes32[] memory roots = vm.parseJsonBytes32Array(fixture, ".netCases.root");

        assertEq(counts.length, roots.length, "fixture column count mismatch");
        uint256 cursor;
        for (uint256 i; i < counts.length; i++) {
            BatchSettler.NetInstruction[] memory net = new BatchSettler.NetInstruction[](counts[i]);
            for (uint256 j; j < counts[i]; j++) {
                net[j] = BatchSettler.NetInstruction({
                    recipient: recipients[cursor + j], amount: amounts[cursor + j]
                });
            }
            cursor += counts[i];

            // 编码字节级比对（比根更强：根失配可定位到编码层）。
            assertEq(
                keccak256(abi.encode(net)),
                keccak256(encodings[i]),
                "abi.encode(net) encoding mismatch"
            );
            // 合约权威定义（BatchSettler.settle 的 WrongNettingRoot 闸）。
            assertEq(keccak256(abi.encode(net)), roots[i], "nettingRoot mismatch");
        }
        assertEq(cursor, recipients.length, "flat net columns not fully consumed");
    }

    // ---- 面 5：acceptanceLeaf（接受锚叶，P2-3 §6.23）---------------------------

    function test_acceptance_leaf_differential() public {
        uint256[] memory seqs = vm.parseJsonUintArray(fixture, ".acceptanceLeaves.seq");
        uint256[] memory acceptedAts =
            vm.parseJsonUintArray(fixture, ".acceptanceLeaves.acceptedAt");
        bytes32[] memory expect = vm.parseJsonBytes32Array(fixture, ".acceptanceLeaves.leaf");
        assertEq(seqs.length, expect.length, "fixture column count mismatch");
        for (uint256 i; i < expect.length; i++) {
            // kind3/kind4 守卫的叶原像（acceptanceInclusion 闸的叶面）：0/0 与
            // MAX/MAX 边界对在 fixture 里（未锚哨兵 0 恰是要逐字节锁死的分支）。
            assertEq(
                Merkle.acceptanceLeaf(uint64(seqs[i]), uint64(acceptedAts[i])),
                expect[i],
                "acceptance leaf mismatch"
            );
        }
    }
}
