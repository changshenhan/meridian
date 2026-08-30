// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DSA} from "../src/DSA.sol";
import {DelegationHelper} from "./DelegationHelper.sol";

/// S-06b：DSA 注册逻辑。签名由 vm.sign 在测试内确定性产生（k256 同款曲线）。
contract DSATest is Test {
    DSA internal dsa;
    uint256 internal ownerPk;
    address internal owner;
    bytes internal abiBytes;
    bytes32 internal dh;

    /// secp256k1 群阶（低位 s 判据用）。
    uint256 internal constant SECP256K1N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function setUp() public {
        dsa = new DSA();
        ownerPk = 0xA11CE;
        owner = vm.addr(ownerPk);
        (abiBytes, dh) = DelegationHelper.buildDelegation(owner);
    }

    /// owner 对 `delegation_hash` 的紧凑 r||s 签名（64 字节，低位 s 由 vm.sign 保证）。
    function signOwner(bytes32 hash) internal view returns (bytes memory) {
        (, bytes32 r, bytes32 s) = vm.sign(ownerPk, hash);
        return abi.encodePacked(r, s);
    }

    function test_register_success() public {
        vm.expectEmit();
        emit DSA.DelegationRegistered(dh, owner);
        dsa.registerDelegation(abiBytes, signOwner(dh));
        assertTrue(dsa.isRegistered(dh));
        assertEq(dsa.ownerOf(dh), owner);
    }

    function test_register_duplicate_reverts() public {
        dsa.registerDelegation(abiBytes, signOwner(dh));
        vm.expectRevert(abi.encodeWithSelector(DSA.AlreadyRegistered.selector, dh));
        dsa.registerDelegation(abiBytes, signOwner(dh));
    }

    function test_register_wrong_key_reverts() public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBEEF, dh);
        vm.expectRevert(DSA.BadOwnerSignature.selector);
        dsa.registerDelegation(abiBytes, abi.encodePacked(r, s));
    }

    function test_register_high_s_reverts() public {
        (, bytes32 r, bytes32 s) = vm.sign(ownerPk, dh);
        // 翻转成保证高位 s 的签名（ecrecover 同 v 下也有效），合约必须在 ecrecover 前拒绝。
        uint256 sHigh = uint256(s) > SECP256K1N / 2 ? uint256(s) : (SECP256K1N - uint256(s));
        vm.expectRevert(DSA.HighS.selector);
        dsa.registerDelegation(abiBytes, abi.encodePacked(r, bytes32(sHigh)));
    }

    function test_register_tampered_abi_reverts() public {
        // 篡改非 owner 区域（长度不变，不影响 [26:46]）→ sha256 变化 → 原签名失配。
        bytes memory tampered = abiBytes;
        tampered[50] ^= 0x01;
        vm.expectRevert(DSA.BadOwnerSignature.selector);
        dsa.registerDelegation(tampered, signOwner(dh));
    }

    function test_register_short_abi_reverts() public {
        vm.expectRevert(DSA.MalformedABI.selector);
        dsa.registerDelegation(new bytes(45), signOwner(dh));
    }

    function test_register_bad_sig_length_reverts() public {
        vm.expectRevert(DSA.BadOwnerSignature.selector);
        dsa.registerDelegation(abiBytes, hex"1234");
    }
}

/// S-62（TECH_SPEC §6.19）：委托→运营者绑定面——owner 私钥一次性写入、不可改绑、
/// 零地址构造性禁止。聚合器摄取绑定闸（§6.19.2）的链上事实源。
contract DSABindingTest is Test {
    DSA internal dsa;
    uint256 internal ownerPk;
    address internal owner;
    bytes internal abiBytes;
    bytes32 internal dh;
    address internal operator = makeAddr("operator");
    address internal other = makeAddr("other");

    function setUp() public {
        dsa = new DSA();
        ownerPk = 0xA11CE;
        owner = vm.addr(ownerPk);
        (abiBytes, dh) = DelegationHelper.buildDelegation(owner);
        dsa.registerDelegation(abiBytes, signOwner(dh));
    }

    function signOwner(bytes32 hash) internal view returns (bytes memory) {
        (, bytes32 r, bytes32 s) = vm.sign(ownerPk, hash);
        return abi.encodePacked(r, s);
    }

    function test_bind_success_and_readback() public {
        vm.expectEmit();
        emit DSA.OperatorBound(dh, owner, operator);
        vm.prank(owner);
        dsa.bindOperator(dh, operator);
        assertEq(dsa.operatorOf(dh), operator);
        // owner 登记不受绑定影响（两映射并列，S-62 独立映射不进哈希 preimage）。
        assertEq(dsa.ownerOf(dh), owner);
        assertTrue(dsa.isRegistered(dh));
    }

    function test_bind_unbound_reads_zero() public {
        // 未绑定的已注册委托读数 = 零地址（fail-open 语义的事实源，§6.19.2）。
        assertEq(dsa.operatorOf(dh), address(0));
    }

    function test_bind_unknown_delegation_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(DSA.NotRegistered.selector, bytes32(uint256(1))));
        vm.prank(owner);
        dsa.bindOperator(bytes32(uint256(1)), operator);
    }

    function test_bind_non_owner_reverts() public {
        // 注册是许可面（任何持有 owner 签名者可发），绑定不是——选型权钉在 owner 私钥。
        vm.expectRevert(DSA.NotDelegationOwner.selector);
        vm.prank(other);
        dsa.bindOperator(dh, operator);
    }

    function test_bind_zero_operator_reverts() public {
        // 零地址 = 读协议的「未绑定」：绑定为零会伪装 fail-open 放行语义（§6.19.1）。
        vm.expectRevert(DSA.ZeroOperator.selector);
        vm.prank(owner);
        dsa.bindOperator(dh, address(0));
    }

    function test_rebind_reverts() public {
        vm.startPrank(owner);
        dsa.bindOperator(dh, operator);
        vm.expectRevert(abi.encodeWithSelector(DSA.AlreadyBound.selector, dh));
        dsa.bindOperator(dh, makeAddr("operator2"));
        vm.stopPrank();
        // 不可改绑（§6.17.4）：失败路径后读数仍是首绑运营者。
        assertEq(dsa.operatorOf(dh), operator);
    }

    function test_bind_owner_self_is_allowed() public {
        // owner 可绑定自身（单实体形态合法：owner 兼运营者，v1 形态）。
        vm.prank(owner);
        dsa.bindOperator(dh, owner);
        assertEq(dsa.operatorOf(dh), owner);
    }
}
