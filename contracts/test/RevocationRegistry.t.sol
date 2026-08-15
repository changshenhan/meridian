// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DSA} from "../src/DSA.sol";
import {RevocationRegistry} from "../src/RevocationRegistry.sol";
import {DelegationHelper} from "./DelegationHelper.sol";

/// S-06b：撤销逻辑 —— 仅 owner 可撤销；未注册不可撤销。
contract RevocationRegistryTest is Test {
    DSA internal dsa;
    RevocationRegistry internal reg;
    uint256 internal ownerPk;
    address internal owner;

    function setUp() public {
        dsa = new DSA();
        reg = new RevocationRegistry(dsa);
        ownerPk = 0xA11CE;
        owner = vm.addr(ownerPk);
        (bytes memory abiBytes, bytes32 dh) = DelegationHelper.buildDelegation(owner);
        (, bytes32 r, bytes32 s) = vm.sign(ownerPk, dh);
        dsa.registerDelegation(abiBytes, abi.encodePacked(r, s));
    }

    function test_revoke_as_owner() public {
        bytes32 dh = _registeredHash();
        vm.prank(owner); // 撤销必须由 owner 发起
        vm.expectEmit();
        emit RevocationRegistry.Revoked(dh, owner);
        reg.revoke(dh);
        assertTrue(reg.isRevoked(dh));
    }

    function test_revoke_non_owner_reverts() public {
        bytes32 dh = _registeredHash();
        vm.prank(address(0xBEEF));
        vm.expectRevert(RevocationRegistry.NotOwner.selector);
        reg.revoke(dh);
    }

    function test_revoke_unregistered_reverts() public {
        bytes32 unknown = keccak256("not-registered");
        vm.expectRevert(abi.encodeWithSelector(RevocationRegistry.NotRegistered.selector, unknown));
        reg.revoke(unknown);
    }

    function _registeredHash() internal view returns (bytes32 dh) {
        (, dh) = DelegationHelper.buildDelegation(owner);
    }
}
