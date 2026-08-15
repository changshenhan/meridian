// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BatchSettler} from "../src/BatchSettler.sol";

/// S-06b：乐观批量结算 —— commit（债券）→ settle（nettingRoot 占位锚定）→ challenge（窗口）。
contract BatchSettlerTest is Test {
    BatchSettler internal bs;
    uint256 internal constant EPOCH = 1;

    function setUp() public {
        bs = new BatchSettler();
    }

    function _net() internal pure returns (BatchSettler.NetInstruction[] memory n) {
        n = new BatchSettler.NetInstruction[](2);
        n[0] = BatchSettler.NetInstruction({recipient: address(0xA1), amount: 100});
        n[1] = BatchSettler.NetInstruction({recipient: address(0xA2), amount: 200});
    }

    function test_commit_records_bond() public {
        bytes32 root = keccak256("epoch-1");
        vm.expectEmit();
        emit BatchSettler.Commit(EPOCH, root, 1 ether);
        bs.commit{value: 1 ether}(EPOCH, root);

        (bytes32 commitmentRoot, uint256 bondedAmount, , , bool committed, , ) = bs.epochs(EPOCH);
        assertEq(commitmentRoot, root);
        assertEq(bondedAmount, 1 ether);
        assertTrue(committed);
    }

    function test_commit_twice_reverts() public {
        bs.commit(EPOCH, keccak256("a"));
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochAlreadyCommitted.selector, EPOCH));
        bs.commit(EPOCH, keccak256("b"));
    }

    function test_settle_matches_netting_root() public {
        bs.commit(EPOCH, keccak256("epoch-1"));
        BatchSettler.NetInstruction[] memory n = _net();
        bytes32 nettingRoot = keccak256(abi.encode(n));

        vm.expectEmit();
        emit BatchSettler.Settled(EPOCH, nettingRoot, 2);
        bs.settle(EPOCH, n, nettingRoot);
    }

    function test_settle_wrong_root_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"));
        vm.expectRevert(BatchSettler.WrongNettingRoot.selector);
        bs.settle(EPOCH, _net(), keccak256("wrong"));
    }

    function test_settle_unknown_epoch_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochUnknown.selector, 999));
        bs.settle(999, _net(), keccak256("x"));
    }

    function test_settle_twice_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"));
        BatchSettler.NetInstruction[] memory n = _net();
        bytes32 nettingRoot = keccak256(abi.encode(n));
        bs.settle(EPOCH, n, nettingRoot);

        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochAlreadySettled.selector, EPOCH));
        bs.settle(EPOCH, n, nettingRoot);
    }

    function test_challenge_within_window() public {
        bs.commit(EPOCH, keccak256("epoch-1"));
        BatchSettler.NetInstruction[] memory n = _net();
        bs.settle(EPOCH, n, keccak256(abi.encode(n)));

        bytes memory fraud = "fake fraud proof";
        vm.expectEmit();
        emit BatchSettler.Challenge(EPOCH, address(this), keccak256(fraud));
        bs.challenge(EPOCH, fraud);
    }

    function test_challenge_after_window_reverts() public {
        bs.commit(EPOCH, keccak256("epoch-1"));
        BatchSettler.NetInstruction[] memory n = _net();
        bs.settle(EPOCH, n, keccak256(abi.encode(n)));

        vm.warp(block.timestamp + bs.CHALLENGE_WINDOW() + 1);
        vm.expectRevert(BatchSettler.ChallengeWindowClosed.selector);
        bs.challenge(EPOCH, "too late");
    }

    function test_challenge_unknown_epoch_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(BatchSettler.EpochUnknown.selector, 777));
        bs.challenge(777, "x");
    }
}
