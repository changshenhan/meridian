// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

import {IntentHelper} from "../src/IntentHelper.sol";
import {Merkle} from "../src/Merkle.sol";

/// @notice external 包装帧：`IntentHelper.computeIntentHash` / `Merkle.computeRoot` 是 internal
///         library 调用，revert 发生在测试自身帧内（深度低于 cheatcode 调用深度），forge 的
///         `vm.expectRevert` 无法捕获。包装成一次独立 external 调用后，revert 在合约帧边界
///         产生，expectRevert 正常生效。仅测试用，不进 src。
contract IntentHelperHarness {
    function computeIntentHash(
        bytes20 agent,
        bytes32 delegationHash,
        bytes20 recipient,
        uint64 amount,
        bytes32 category,
        uint64 spendNonce,
        bytes calldata memo,
        uint64 expiresAt
    ) external pure returns (bytes32) {
        return IntentHelper.computeIntentHash(
            agent, delegationHash, recipient, amount, category, spendNonce, memo, expiresAt
        );
    }
}

contract MerkleHarness {
    function computeRoot(
        bytes32 leafHash,
        uint256 index,
        uint256 acceptedCount,
        bytes32[] calldata siblings
    ) external pure returns (bytes32) {
        return Merkle.computeRoot(leafHash, index, acceptedCount, siblings);
    }
}
