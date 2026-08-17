// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IntentHelper} from "../src/IntentHelper.sol";
import {IntentHelperHarness} from "./InternalHarnesses.sol";

/// S-11a：IntentHelper.computeIntentHash 与 core/src/dsa.rs::intent_hash 的交叉实现黄金向量。
/// golden hex 由 Rust（aggregator/examples/print_s11_golden.rs 临时工具）计算并锁定；
/// 任一侧字节序/前缀/字段序变化 → 立即失配（§11 E-03 交叉实现契约）。
contract IntentHelperTest is Test {
    bytes20 internal constant AGENT = bytes20(0x1111111111111111111111111111111111111111);
    bytes32 internal constant DELEGATION_HASH = bytes32(0x2222222222222222222222222222222222222222222222222222222222222222);
    bytes32 internal constant CATEGORY = bytes32(0x4444444444444444444444444444444444444444444444444444444444444444);

    function test_compute_intent_hash_golden_none_memo() public pure {
        bytes32 h = IntentHelper.computeIntentHash(
            AGENT,
            DELEGATION_HASH,
            bytes20(0x3333333333333333333333333333333333333333),
            42,
            CATEGORY,
            7,
            new bytes(0),
            type(uint64).max
        );
        assertEq(h, bytes32(0x436c7472c924c77210d885041a2b154dfc97ad1faf7a9f746eb40503d67e10cd));
    }

    function test_compute_intent_hash_golden_recipient_35_amount_100() public pure {
        bytes32 h = IntentHelper.computeIntentHash(
            AGENT,
            DELEGATION_HASH,
            bytes20(0x3535353535353535353535353535353535353535),
            100,
            CATEGORY,
            7,
            new bytes(0),
            type(uint64).max
        );
        assertEq(h, bytes32(0x980b9e9cf12d59d3f407fbf7f83d5c25fe9c1a0fe3630dbac5f437ac665ad590));
    }

    function test_compute_intent_hash_golden_recipient_36_amount_7() public pure {
        bytes32 h = IntentHelper.computeIntentHash(
            AGENT,
            DELEGATION_HASH,
            bytes20(0x3636363636363636363636363636363636363636),
            7,
            CATEGORY,
            7,
            new bytes(0),
            type(uint64).max
        );
        assertEq(h, bytes32(0xd8575145993fe54bf47e777a961486782838afe5f5b00ae692bc8fb68a3aefe1));
    }

    /// memo Some(32B) 与 None 必须产生不同哈希（memo 参与 preimage）。
    function test_memo_changes_hash() public pure {
        bytes memory memo32 = new bytes(32);
        memo32[0] = 0xAA;
        bytes32 withMemo = IntentHelper.computeIntentHash(
            AGENT, DELEGATION_HASH, bytes20(uint160(0x33)), 42, CATEGORY, 7, memo32, type(uint64).max
        );
        bytes32 withoutMemo = IntentHelper.computeIntentHash(
            AGENT, DELEGATION_HASH, bytes20(uint160(0x33)), 42, CATEGORY, 7, new bytes(0), type(uint64).max
        );
        assertTrue(withMemo != withoutMemo);
    }

    /// memo 长度非法（非 0 非 32）→ require 拒绝（经 external 包装帧，expectRevert 可捕获）。
    function test_bad_memo_length_reverts() public {
        IntentHelperHarness h = new IntentHelperHarness();
        vm.expectRevert("memo: empty or 32B");
        h.computeIntentHash(
            AGENT, DELEGATION_HASH, bytes20(uint160(0x33)), 42, CATEGORY, 7, new bytes(5), type(uint64).max
        );
    }
}
