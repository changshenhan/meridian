// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OperatorRegistry} from "../src/OperatorRegistry.sol";
import {BatchSettler} from "../src/BatchSettler.sol";
import {DSA} from "../src/DSA.sol";
import {RevocationRegistry} from "../src/RevocationRegistry.sol";

/// S-64（TECH_SPEC §6.21）：P2-4 OperatorRegistry —— append-only 金额调度 + 运营者名册
/// （§6.17 决策 D 实施砖）。BatchSettler 逐字节不动，只作名册绑定实证 / 快照源。
contract OperatorRegistryTest is Test {
    OperatorRegistry internal registry;
    address internal registrar = makeAddr("registrar");
    address internal operator = makeAddr("operator");
    address internal other = makeAddr("other");

    /// 调度量（非零基线，测试内按需覆盖）。
    uint256 internal constant BOND = 1 ether;
    uint256 internal constant CHALLENGE_BOND = 0.1 ether;

    function setUp() public {
        registry = new OperatorRegistry(registrar);
    }

    function deploySettler(address operator, uint256 challengeBond)
        internal
        returns (BatchSettler)
    {
        // P2-3：BatchSettler 构造器增两 immutable 锚（DSA + RevocationRegistry），部署序
        // 与 ChallengeTestHelper.deployAnchoredSettler / deploy.rs 同款（本套件未继承助手）。
        DSA dsa = new DSA();
        RevocationRegistry revocations = new RevocationRegistry(dsa);
        return new BatchSettler(operator, address(0), challengeBond, dsa, revocations);
    }
}

/// 金额调度：append-only（旧值永不改写）+ 零金额构造性拒绝 + registrar 写面。
contract OperatorRegistryScheduleTest is OperatorRegistryTest {
    function test_constructor_zero_registrar_reverts() public {
        vm.expectRevert(OperatorRegistry.ZeroRegistrar.selector);
        new OperatorRegistry(address(0));
    }

    function test_append_schedule_success_and_readback() public {
        vm.expectEmit();
        emit OperatorRegistry.ScheduleAppended(0, BOND, CHALLENGE_BOND);
        vm.prank(registrar);
        registry.appendSchedule(BOND, CHALLENGE_BOND);
        assertEq(registry.scheduleCount(), 1);
        assertEq(registry.registrar(), registrar);
        OperatorRegistry.ScheduleEntry memory e = registry.currentSchedule();
        assertEq(e.bond, BOND);
        assertEq(e.challengeBond, CHALLENGE_BOND);
        assertEq(e.writtenAt, block.timestamp);
    }

    function test_append_schedule_history_is_immutable() public {
        // 决策 D：旧值永不改写，新值追加生效——历史条目读数逐字不变，当刻值切换。
        vm.startPrank(registrar);
        registry.appendSchedule(BOND, CHALLENGE_BOND);
        vm.warp(block.timestamp + 100);
        registry.appendSchedule(2 ether, 0.37 ether);
        vm.stopPrank();
        assertEq(registry.scheduleCount(), 2);
        // 自动 getter 对数组元素返回元组（非 struct）。
        (uint256 bond0, uint256 cb0, uint64 at0) = registry.schedule(0);
        assertEq(bond0, BOND);
        assertEq(cb0, CHALLENGE_BOND);
        assertEq(at0, 1); // 追加时刻不随后续追加漂移
        OperatorRegistry.ScheduleEntry memory e1 = registry.currentSchedule();
        assertEq(e1.bond, 2 ether);
        assertEq(e1.challengeBond, 0.37 ether);
        assertEq(e1.writtenAt, block.timestamp);
    }

    function test_append_non_registrar_reverts() public {
        vm.expectRevert(OperatorRegistry.NotRegistrar.selector);
        vm.prank(other);
        registry.appendSchedule(BOND, CHALLENGE_BOND);
    }

    function test_append_zero_bond_reverts() public {
        vm.expectRevert(OperatorRegistry.ZeroScheduleAmount.selector);
        vm.prank(registrar);
        registry.appendSchedule(0, CHALLENGE_BOND);
    }

    function test_append_zero_challenge_bond_reverts() public {
        // 零押金 = 复活垃圾挑战面（S-50 ZeroChallengeBond 同语义，构造性挡在调度层）。
        vm.expectRevert(OperatorRegistry.ZeroScheduleAmount.selector);
        vm.prank(registrar);
        registry.appendSchedule(BOND, 0);
    }

    function test_current_schedule_empty_reverts() public {
        // 部署流程不该在无调度时部署（§6.21.2）。
        vm.expectRevert(OperatorRegistry.ScheduleEmpty.selector);
        registry.currentSchedule();
    }
}

/// 运营者名册：self-registration 绑定实证（调用者必须 = settler.operator()）+
/// 固化值快照 + 同 operator 多实例（决策 D 换金额路径 = 重部署）。
contract OperatorRegistryRosterTest is OperatorRegistryTest {
    function test_register_success_and_snapshot() public {
        BatchSettler settler = deploySettler(operator, CHALLENGE_BOND);
        vm.expectEmit();
        emit OperatorRegistry.OperatorRegistered(operator, address(settler), CHALLENGE_BOND);
        vm.prank(operator);
        registry.registerOperator(address(settler));
        assertTrue(registry.isSettlerListed(address(settler)));
        assertEq(registry.operatorCount(), 1);
        assertEq(registry.settlerCount(operator), 1);
        (address op0, address st0, address asset0, uint256 cb0, uint64 at0) = registry.operators(0);
        assertEq(op0, operator);
        assertEq(st0, address(settler));
        assertEq(asset0, address(0)); // S-28 哨兵：原生 ETH 模式原样快照
        assertEq(cb0, CHALLENGE_BOND);
        assertEq(at0, block.timestamp);
    }

    function test_register_by_non_operator_reverts() public {
        BatchSettler settler = deploySettler(operator, CHALLENGE_BOND);
        // 非 operator 发起：链上归属读数 != 调用者 → 拒绝（名册不可伪造的根）。
        vm.expectRevert(
            abi.encodeWithSelector(
                OperatorRegistry.NotSettlerOperator.selector, address(settler), other, operator
            )
        );
        vm.prank(other);
        registry.registerOperator(address(settler));
        assertFalse(registry.isSettlerListed(address(settler)));
    }

    function test_register_eoa_settler_reverts() public {
        // EOA（无代码）接口调用 revert 气泡——名册只收真实 BatchSettler 实例。
        vm.expectRevert();
        vm.prank(operator);
        registry.registerOperator(operator);
    }

    function test_register_same_settler_twice_reverts() public {
        BatchSettler settler = deploySettler(operator, CHALLENGE_BOND);
        vm.startPrank(operator);
        registry.registerOperator(address(settler));
        vm.expectRevert(
            abi.encodeWithSelector(OperatorRegistry.SettlerAlreadyListed.selector, address(settler))
        );
        registry.registerOperator(address(settler));
        vm.stopPrank();
        assertEq(registry.operatorCount(), 1);
    }

    /// 决策 D 全链流（§6.21.3 演练的合约侧镜像）：v1 调度 → 实例1（读 v1）→ v2 调度 →
    /// 实例2（读 v2）——两实例各持其部署版本，v1 实例不受 v2 影响（不来自 setter）。
    function test_schedule_versions_freeze_into_separate_instances() public {
        vm.startPrank(registrar);
        registry.appendSchedule(BOND, CHALLENGE_BOND);
        vm.stopPrank();
        BatchSettler s1 = deploySettler(operator, registry.currentSchedule().challengeBond);

        vm.prank(registrar);
        registry.appendSchedule(2 ether, 0.37 ether);
        BatchSettler s2 = deploySettler(operator, registry.currentSchedule().challengeBond);

        // 部署后回读交叉核对（S-50「单一事实源在链上」口径）。
        assertEq(s1.challengeBond(), CHALLENGE_BOND);
        assertEq(s2.challengeBond(), 0.37 ether);

        vm.startPrank(operator);
        registry.registerOperator(address(s1));
        registry.registerOperator(address(s2));
        vm.stopPrank();
        assertEq(registry.operatorCount(), 2);
        assertEq(registry.settlerCount(operator), 2);
        (,,, uint256 cb0,) = registry.operators(0);
        (,,, uint256 cb1,) = registry.operators(1);
        assertEq(cb0, CHALLENGE_BOND);
        assertEq(cb1, 0.37 ether);
        // 调度历史不被名册动作触碰。
        assertEq(registry.scheduleCount(), 2);
        (, uint256 sched0Cb,) = registry.schedule(0);
        assertEq(sched0Cb, CHALLENGE_BOND);
    }
}
