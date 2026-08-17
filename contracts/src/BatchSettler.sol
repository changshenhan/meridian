// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IntentHelper} from "./IntentHelper.sol";
import {Merkle} from "./Merkle.sol";

/// @title BatchSettler —— 乐观批量结算（TECH_SPEC §6.4-6.5, §7）
/// @notice 结算节奏（§6.3）：运营者把 epoch 承诺根上链（commit，质押债券）→ 确定性重排后
///         提交净额指令（settle，nettingRoot 锚定，同笔携带结算资金）→ 挑战窗口内任何人可
///         对 commit≠settle 发起欺诈证明（challenge）→ 窗口过后收款人逐条领取（claim）。
/// @dev S-11 生产化（MASTER_PLAN S-11）：
///      · commit/settle 仅 operator —— 无守卫时任何人可拿自洽 net[] 结算已提交 epoch →
///        挑战成功 → 运营者债券被罚没（griefing，无对手方获利）。
///      · settle 存 net[] + 结算资金（msg.value ≥ Σnet，原生 ETH）；claim 延迟到挑战窗口后
///        （用户决策：延迟 claim）。挑战与 claim 严格时间分离 → 挑战成功时无任何 claim 已付，
///        settlementFunded（= Σnet）全额退运营者。
///      · challenge 完整验证欺诈证明（漏单 kind=1 / 低付 kind=2，sha256 包含证明）→
///        债券罚没给挑战者、退款给运营者、整 epoch voided（后续 claim 拒绝）。
///      · USDC/ERC-20 是 Phase 2 缝（TECH_SPEC §7 已写 USDC；S-11 按用户决策用原生 ETH）。
contract BatchSettler {
    struct NetInstruction {
        address recipient;
        uint256 amount;
    }

    struct Epoch {
        bytes32 commitmentRoot;
        bytes32 revocationRoot;
        uint256 bondedAmount;
        uint256 settlementFunded;
        uint64 settledAt;
        bytes32 nettingRoot;
        NetInstruction[] net;
        mapping(uint256 => bool) claimed;
        bool committed;
        bool settled;
        bool challenged;
        bool voided;
    }

    /// 欺诈证明中的一条已提交意图（明文 + 承诺格包含位置）。
    struct IntentProof {
        bytes20 agent;
        bytes32 delegationHash;
        bytes20 recipient;
        uint64 amount;
        bytes32 category;
        uint64 spendNonce;
        bytes memo;
        uint64 expiresAt;
        uint64 seq;
        uint256 leafIndex;
        uint256 acceptedCount;
        bytes32[] siblings;
    }

    /// 欺诈证明：kind 1 = 漏单（一条已提交意图，其收款人不在 net[]）；kind 2 = 低付
    /// （同一收款人的已提交意图子集，uint256 和 > net[targetNetIndex].amount）。
    /// sound：sha256 原像绑定 + 承诺格包含性；单调子集无需完备性。两个防假阳性硬守卫：
    /// 同笔意图重复计入（DuplicateIntent）+ 跨收款人子集（BadFraudKind）。
    struct FraudProof {
        uint8 kind;
        uint256 targetNetIndex; // kind 2 用
        IntentProof[] intents;
    }

    event Commit(
        uint256 indexed epochId,
        bytes32 commitmentRoot,
        bytes32 revocationRoot,
        uint256 bondedAmount
    );
    event Settled(uint256 indexed epochId, bytes32 nettingRoot, uint64 netCount);
    event ChallengeSucceeded(uint256 indexed epochId, address indexed challenger, uint8 kind);
    event Claimed(uint256 indexed epochId, address indexed recipient, uint256 amount);

    error EpochAlreadyCommitted(uint256 epochId);
    error EpochAlreadySettled(uint256 epochId);
    error EpochAlreadyChallenged(uint256 epochId);
    error EpochUnknown(uint256 epochId);
    error EpochVoided(uint256 epochId);
    error WrongNettingRoot();
    error ChallengeWindowClosed();
    error ChallengeWindowOpen();
    error AlreadyClaimed(uint256 epochId, uint256 netIndex);
    error NetIndexOutOfBounds(uint256 epochId, uint256 netIndex);
    error TooManyIntents();
    error DuplicateIntent();
    error BadInclusionProof();
    error NotFraud();
    error InsufficientSettlementFunding();
    error BadFraudKind();
    error NotOperator();

    /// 挑战窗口：settle 后 6 小时内可挑战（TECH_SPEC §6.5）。
    uint256 public constant CHALLENGE_WINDOW = 6 hours;
    /// 单次挑战最多携带的意图数（gas 上界：epoch_capacity=100k → 树深 17，每意图 ~19 次
    /// sha256 预编译；32 意图 ≈ 500-600k gas，块内可行）。
    uint256 public constant MAX_INTENTS_PER_CHALLENGE = 32;

    /// 唯一结算运营者：commit/settle 的唯一合法调用者（S-11 防 griefing）。
    address public immutable operator;

    mapping(uint256 => Epoch) public epochs;

    constructor(address operator_) {
        operator = operator_;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    /// 运营者提交承诺根 + 撤销根并质押债券（msg.value）。同一 epoch 只允许一次。
    function commit(uint256 epochId, bytes32 commitmentRoot, bytes32 revocationRoot)
        external
        payable
        onlyOperator
    {
        Epoch storage ep = epochs[epochId];
        if (ep.committed) revert EpochAlreadyCommitted(epochId);
        ep.committed = true;
        ep.commitmentRoot = commitmentRoot;
        ep.revocationRoot = revocationRoot;
        ep.bondedAmount = msg.value;
        emit Commit(epochId, commitmentRoot, revocationRoot, msg.value);
    }

    /// 结算：nettingRoot 必须与 net[] 的链式 keccak 一致（S-10 对齐，逐字节）。
    /// 同笔必须携带 ≥ Σnet 的结算资金（原生 ETH，deferred-claim 的资金源）。存 net[] 供
    /// claim 与漏单检查。挑战成功时 settlementFunded（= Σnet）全额退运营者；多付部分留在
    /// 合同（运营者超额充值，视作捐赠，不参与退款）。
    function settle(uint256 epochId, NetInstruction[] calldata net, bytes32 nettingRoot)
        external
        payable
        onlyOperator
    {
        Epoch storage ep = epochs[epochId];
        if (!ep.committed) revert EpochUnknown(epochId);
        if (ep.settled) revert EpochAlreadySettled(epochId);
        if (nettingRoot != keccak256(abi.encode(net))) revert WrongNettingRoot();
        uint256 total = _sumNet(net);
        if (msg.value < total) revert InsufficientSettlementFunding();

        ep.settled = true;
        ep.nettingRoot = nettingRoot;
        ep.settledAt = uint64(block.timestamp);
        ep.settlementFunded = total;
        for (uint256 i = 0; i < net.length; i++) {
            ep.net.push(net[i]);
        }
        emit Settled(epochId, nettingRoot, uint64(net.length));
    }

    /// 延迟领取：窗口（挑战期）过后，收款人（或其代理人）逐条领取净额。整 epoch voided 后拒绝。
    function claim(uint256 epochId, uint256 netIndex) external {
        Epoch storage ep = epochs[epochId];
        if (!ep.settled) revert EpochUnknown(epochId);
        if (ep.voided) revert EpochVoided(epochId);
        if (block.timestamp <= uint256(ep.settledAt) + CHALLENGE_WINDOW) revert ChallengeWindowOpen();
        if (netIndex >= ep.net.length) revert NetIndexOutOfBounds(epochId, netIndex);
        if (ep.claimed[netIndex]) revert AlreadyClaimed(epochId, netIndex);

        ep.claimed[netIndex] = true;
        NetInstruction memory ni = ep.net[netIndex];
        (bool ok, ) = payable(ni.recipient).call{value: ni.amount}("");
        require(ok, "claim transfer failed");
        emit Claimed(epochId, ni.recipient, ni.amount);
    }

    /// 挑战：窗口内任何人可对 commit≠settle 发起欺诈证明。验证通过 → 债券罚没给挑战者、
    /// settlementFunded 退运营者、整 epoch voided。验证失败 → 回滚（挑战者吃 gas，v1 反垃圾）。
    function challenge(uint256 epochId, FraudProof calldata fp) external {
        Epoch storage ep = epochs[epochId];
        if (!ep.settled) revert EpochUnknown(epochId);
        if (ep.challenged || ep.voided) revert EpochAlreadyChallenged(epochId);
        if (block.timestamp > uint256(ep.settledAt) + CHALLENGE_WINDOW) revert ChallengeWindowClosed();
        if (fp.intents.length == 0 || fp.intents.length > MAX_INTENTS_PER_CHALLENGE) {
            revert TooManyIntents();
        }

        if (fp.kind == 1) {
            // 漏单：一条已提交意图，其收款人不在 net[] 中。
            if (fp.intents.length != 1) revert BadFraudKind();
            bytes32 ih = _intentHash(fp.intents[0]);
            _verifyInclusion(ep, fp.intents[0], ih);
            address recipient = address(fp.intents[0].recipient);
            (bool found, ) = _indexOfRecipient(ep, recipient);
            if (found) revert NotFraud();
        } else if (fp.kind == 2) {
            // 低付：同一收款人的已提交意图子集，uint256 和 > net[target].amount。
            if (fp.targetNetIndex >= ep.net.length) {
                revert NetIndexOutOfBounds(epochId, fp.targetNetIndex);
            }
            address targetRecipient = ep.net[fp.targetNetIndex].recipient;
            uint256 sum;
            bytes32[] memory hashes = new bytes32[](fp.intents.length);
            for (uint256 i = 0; i < fp.intents.length; i++) {
                IntentProof calldata ip = fp.intents[i];
                // 防假阳性 #2：跨收款人子集禁止（只与目标行比较）。
                if (address(ip.recipient) != targetRecipient) revert BadFraudKind();
                bytes32 ih = _intentHash(ip);
                // 防假阳性 #1：同笔意图重复计入禁止。
                for (uint256 j = 0; j < i; j++) {
                    if (ih == hashes[j]) revert DuplicateIntent();
                }
                hashes[i] = ih;
                _verifyInclusion(ep, ip, ih);
                sum += ip.amount;
            }
            if (sum <= ep.net[fp.targetNetIndex].amount) revert NotFraud();
        } else {
            revert BadFraudKind();
        }

        // CEI：先改状态，再外部调用。
        ep.challenged = true;
        ep.voided = true;
        uint256 bond = ep.bondedAmount;
        uint256 refund = ep.settlementFunded;
        ep.bondedAmount = 0;
        ep.settlementFunded = 0;
        (bool okBond, ) = payable(msg.sender).call{value: bond}("");
        require(okBond, "bond transfer failed");
        if (refund > 0) {
            (bool okRefund, ) = payable(operator).call{value: refund}("");
            require(okRefund, "refund transfer failed");
        }
        emit ChallengeSucceeded(epochId, msg.sender, fp.kind);
    }

    function _sumNet(NetInstruction[] calldata net) internal pure returns (uint256 total) {
        for (uint256 i = 0; i < net.length; i++) {
            total += net[i].amount;
        }
    }

    function _indexOfRecipient(Epoch storage ep, address recipient)
        internal
        view
        returns (bool found, uint256)
    {
        for (uint256 i = 0; i < ep.net.length; i++) {
            if (ep.net[i].recipient == recipient) return (true, i);
        }
        return (false, 0);
    }

    function _intentHash(IntentProof calldata ip) internal pure returns (bytes32) {
        return IntentHelper.computeIntentHash(
            ip.agent,
            ip.delegationHash,
            ip.recipient,
            ip.amount,
            ip.category,
            ip.spendNonce,
            ip.memo,
            ip.expiresAt
        );
    }

    function _verifyInclusion(Epoch storage ep, IntentProof calldata ip, bytes32 ih) internal view {
        if (ip.leafIndex >= ip.acceptedCount) revert BadInclusionProof();
        if (ip.siblings.length != Merkle.treeDepth(ip.acceptedCount)) revert BadInclusionProof();
        bytes32 leafHash = Merkle.leaf(ip.seq, ih);
        if (
            Merkle.computeRoot(leafHash, ip.leafIndex, ip.acceptedCount, ip.siblings)
                != ep.commitmentRoot
        ) {
            revert BadInclusionProof();
        }
    }
}
