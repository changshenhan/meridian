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
