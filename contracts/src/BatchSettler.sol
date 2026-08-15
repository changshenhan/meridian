// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title BatchSettler —— 乐观批量结算（TECH_SPEC §6.4-6.5, §7）
/// @notice 结算节奏（§6.3）：运营者把 epoch 承诺根上链（commit，质押债券）→ 确定性重排后
///         提交净额指令（settle，nettingRoot 锚定）→ 挑战窗口内任何人可对 commit≠settle
///         发起挑战。
/// @dev S-06 最小可跑版：
///      · nettingRoot = 链式 keccak(abi.encode(net[])) **占位**（公开可重推、可验证），
///        真实 Merkle 根在 S-10。
///      · challenge 只标记状态 + 留 fraudProof 哈希，**不罚没/不回滚**（欺诈证明 + 债券
///        罚没在 S-11）。
///      · 债券（msg.value）S-06 只记录，不参与罚没。
contract BatchSettler {
    struct NetInstruction {
        address recipient;
        uint256 amount;
    }

    struct Epoch {
        bytes32 commitmentRoot;
        uint256 bondedAmount;
        uint64 settledAt;
        bytes32 nettingRoot;
        bool committed;
        bool settled;
        bool challenged;
    }

    event Commit(uint256 indexed epochId, bytes32 commitmentRoot, uint64 bondedAmount);
    event Settled(uint256 indexed epochId, bytes32 nettingRoot, uint64 netCount);
    event Challenge(uint256 indexed epochId, address indexed challenger, bytes32 fraudProofHash);

    error EpochAlreadyCommitted(uint256 epochId);
    error EpochAlreadySettled(uint256 epochId);
    error EpochAlreadyChallenged(uint256 epochId);
    error EpochUnknown(uint256 epochId);
    error WrongNettingRoot();
    error ChallengeWindowClosed();

    /// 挑战窗口：settle 后 6 小时内可挑战（TECH_SPEC §6.5）。
    uint256 public constant CHALLENGE_WINDOW = 6 hours;

    mapping(uint256 => Epoch) public epochs;

    /// 运营者提交承诺根并质押债券（msg.value）。同一 epoch 只允许一次。
    function commit(uint256 epochId, bytes32 commitmentRoot) external payable {
        Epoch storage ep = epochs[epochId];
        if (ep.committed) revert EpochAlreadyCommitted(epochId);
        ep.committed = true;
        ep.commitmentRoot = commitmentRoot;
        ep.bondedAmount = msg.value;
        emit Commit(epochId, commitmentRoot, uint64(msg.value));
    }

    /// 结算：`nettingRoot` 必须与 `net[]` 的链式 keccak 一致（S-06 占位，S-10 换 Merkle）。
    function settle(
        uint256 epochId,
        NetInstruction[] calldata net,
        bytes32 nettingRoot
    ) external {
        Epoch storage ep = epochs[epochId];
        if (!ep.committed) revert EpochUnknown(epochId);
        if (ep.settled) revert EpochAlreadySettled(epochId);
        if (nettingRoot != keccak256(abi.encode(net))) revert WrongNettingRoot();

        ep.settled = true;
        ep.nettingRoot = nettingRoot;
        ep.settledAt = uint64(block.timestamp);
        emit Settled(epochId, nettingRoot, uint64(net.length));
    }

    /// 挑战（S-06 占位）：settle 后窗口内任何人可标记欺诈；债券罚没 + 回滚在 S-11。
    function challenge(uint256 epochId, bytes calldata fraudProof) external {
        Epoch storage ep = epochs[epochId];
        if (!ep.settled) revert EpochUnknown(epochId);
        if (block.timestamp > uint256(ep.settledAt) + CHALLENGE_WINDOW) revert ChallengeWindowClosed();
        if (ep.challenged) revert EpochAlreadyChallenged(epochId);

        ep.challenged = true;
        emit Challenge(epochId, msg.sender, keccak256(fraudProof));
    }
}
