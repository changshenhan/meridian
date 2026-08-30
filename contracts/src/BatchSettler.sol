// SPDX-License-Identifier: Elastic-2.0
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
///      · S-38 挑战押金（TECH_SPEC §6.5）：challenge 变 payable，随笔押金 CHALLENGE_BOND
///        （原生 ETH，与 asset 无关）。押金入场前 4 类 revert（未结算 / 已挑战 / 窗口外 /
///        金额不等，零押金风险）；入场后任何实质验证失败不再 revert —— 发 ChallengeRejected
///        事件、押金全额销毁（address(0)，任何一方不可取回）、epoch 状态一字不动（仍可再
///        挑战）。押金从不停留为合约状态（成功退回 / 失败销毁，本笔交易内结清），不扩大资金面。
///      · S-28 资产参数化：`asset` 构造参数，`address(0)` = 原生 ETH（v2 行为逐字节保留），
///        `asset = USDC/ERC-20` 时结算资金（settle `transferFrom`）/ claim / void 退款走 token，
///        债券恒为原生 ETH（惩罚质押与结算资产分离）。token 模式强制 `msg.value == 0`。
///        欺诈证明机制单一实现，不因资产模式分叉（TECH_SPEC §7）。

/// S-28：最小 ERC-20 接口（结算资产路径；仅依赖 transfer/transferFrom 的返回值检查，
///       与 USDC 的非标准 `transferAndCall` 等扩展无关）。
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

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
    /// S-38：欺诈证明被驳回（押金没收销毁，epoch 状态不变）。reason 见 RejectReason。
    event ChallengeRejected(uint256 indexed epochId, address indexed challenger, uint8 reason);
    event Claimed(uint256 indexed epochId, address indexed recipient, uint256 amount);

    /// S-38：欺诈证明驳回原因码（押金入场后不再 revert，改为本枚举随事件上报）。
    enum RejectReason {
        None,                // 占位（0 值不随事件使用 = 验证通过）
        NotFraud,            // 证明自洽但不构成欺诈（漏单收款人在 net[] / 低付子集和不超行额）
        BadInclusionProof,   // 叶索引越界 / 兄弟深度不匹配 / 根不匹配（含伪造意图）
        DuplicateIntent,     // 低付子集同笔意图重复计入（防假阳性 #1）
        BadFraudKind,        // kind 非法 / kind1 意图数 != 1 / 跨收款人子集（防假阳性 #2）
        TooManyIntents,      // 意图数为 0 或超出 gas 上界
        NetIndexOutOfBounds  // kind2 目标行越界
    }

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
    error InsufficientSettlementFunding();
    error NotOperator();
    // S-38：挑战押金金额不等（msg.value != CHALLENGE_BOND，押金入场前 revert）。
    error WrongChallengeBond();
    // S-28 资产参数化。
    error TokenTransferFailed();
    error EthValueInTokenMode();

    /// 挑战窗口：settle 后 6 小时内可挑战（TECH_SPEC §6.5）。
    uint256 public constant CHALLENGE_WINDOW = 6 hours;
    /// 单次挑战最多携带的意图数（gas 上界：epoch_capacity=100k → 树深 17，每意图 ~19 次
    /// sha256 预编译；32 意图 ≈ 500-600k gas，块内可行）。
    uint256 public constant MAX_INTENTS_PER_CHALLENGE = 32;
    /// S-38 挑战押金（原生 ETH，与 asset 无关）：垃圾挑战的押金成本（此前只靠 gas，见
    /// TECH_SPEC §6.5）。固定常量；金额动态化随 Phase 2 多运营者一起定。
    uint256 public constant CHALLENGE_BOND = 0.1 ether;

    /// 唯一结算运营者：commit/settle 的唯一合法调用者（S-11 防 griefing）。
    address public immutable operator;
    /// S-28 结算资产：`address(0)` = 原生 ETH（v2 行为）；否则为 ERC-20（如 USDC）。
    /// 债券（commit 的 `msg.value`）恒为原生 ETH，与结算资产无关。
    address public immutable asset;

    mapping(uint256 => Epoch) public epochs;

    constructor(address operator_, address asset_) {
        operator = operator_;
        asset = asset_;
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
        // S-28 结算资金来源：ETH 模式 = msg.value；token 模式 = 从运营者 transferFrom 拉款
        //（需事先 approve），且禁止 ETH 随单进入（防卡死）。失败整笔回滚，无中间态。
        if (asset == address(0)) {
            if (msg.value < total) revert InsufficientSettlementFunding();
        } else {
            if (msg.value != 0) revert EthValueInTokenMode();
            if (!IERC20(asset).transferFrom(msg.sender, address(this), total)) {
                revert TokenTransferFailed();
            }
        }

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
        if (block.timestamp <= uint256(ep.settledAt) + CHALLENGE_WINDOW) {
            revert ChallengeWindowOpen();
        }
        if (netIndex >= ep.net.length) revert NetIndexOutOfBounds(epochId, netIndex);
        if (ep.claimed[netIndex]) revert AlreadyClaimed(epochId, netIndex);

        ep.claimed[netIndex] = true;
        NetInstruction memory ni = ep.net[netIndex];
        if (asset == address(0)) {
            (bool ok,) = payable(ni.recipient).call{value: ni.amount}("");
            require(ok, "claim transfer failed");
        } else {
            if (!IERC20(asset).transfer(ni.recipient, ni.amount)) revert TokenTransferFailed();
        }
        emit Claimed(epochId, ni.recipient, ni.amount);
    }

    /// 挑战（S-38 押金制，TECH_SPEC §6.5）：窗口内任何人可对 commit≠settle 发起欺诈证明，
    /// 随笔押金 CHALLENGE_BOND（原生 ETH，token 模式下债券/押金仍为 ETH）。
    /// 押金入场前 revert（无押金风险）：epoch 未结算 / 已成功挑战或 voided / 窗口关闭 /
    /// msg.value != CHALLENGE_BOND。押金入场后"驳回即没收"：任何实质验证失败不再 revert，
    /// 发 ChallengeRejected + 押金全额销毁（address(0)）、epoch 状态一字不动（仍可再挑战）。
    /// 验证通过 → 押金退回 + 运营者债券罚没给挑战者、settlementFunded 退运营者、整 epoch voided。
    function challenge(uint256 epochId, FraudProof calldata fp) external payable {
        Epoch storage ep = epochs[epochId];
        if (!ep.settled) revert EpochUnknown(epochId);
        if (ep.challenged || ep.voided) revert EpochAlreadyChallenged(epochId);
        if (block.timestamp > uint256(ep.settledAt) + CHALLENGE_WINDOW) {
            revert ChallengeWindowClosed();
        }
        if (msg.value != CHALLENGE_BOND) revert WrongChallengeBond();

        RejectReason reason = _verifyFraud(ep, fp);
        if (reason != RejectReason.None) {
            // CEI：事件（状态）先行，再外部调用。销毁目标 address(0) 无代码，无重入面。
            emit ChallengeRejected(epochId, msg.sender, uint8(reason));
            (bool okBurn,) = payable(address(0)).call{value: CHALLENGE_BOND}("");
            require(okBurn, "bond burn failed");
            return;
        }

        // CEI：先改状态，再外部调用。押金退回 + 运营者债券一笔给挑战者。
        ep.challenged = true;
        ep.voided = true;
        uint256 bond = ep.bondedAmount;
        uint256 refund = ep.settlementFunded;
        ep.bondedAmount = 0;
        ep.settlementFunded = 0;
        (bool okPayout,) = payable(msg.sender).call{value: CHALLENGE_BOND + bond}("");
        require(okPayout, "bond transfer failed");
        if (refund > 0) {
            // S-28：settlementFunded 退款按结算资产原路退回（ETH 或 token）。
            if (asset == address(0)) {
                (bool okRefund,) = payable(operator).call{value: refund}("");
                require(okRefund, "refund transfer failed");
            } else {
                if (!IERC20(asset).transfer(operator, refund)) revert TokenTransferFailed();
            }
        }
        emit ChallengeSucceeded(epochId, msg.sender, fp.kind);
    }

    /// 欺诈证明实质验证（S-38：不再 revert，失败返回原因码；None = 欺诈成立）。判定逻辑与
    /// 押金制之前逐字等价，仅把 revert 换成原因码返回。
    function _verifyFraud(Epoch storage ep, FraudProof calldata fp)
        internal
        view
        returns (RejectReason)
    {
        if (fp.intents.length == 0 || fp.intents.length > MAX_INTENTS_PER_CHALLENGE) {
            return RejectReason.TooManyIntents;
        }
        if (fp.kind == 1) {
            // 漏单：一条已提交意图，其收款人不在 net[] 中。
            if (fp.intents.length != 1) return RejectReason.BadFraudKind;
            bytes32 ih = _intentHash(fp.intents[0]);
            if (!_verifyInclusion(ep, fp.intents[0], ih)) return RejectReason.BadInclusionProof;
            address recipient = address(fp.intents[0].recipient);
            (bool found,) = _indexOfRecipient(ep, recipient);
            if (found) return RejectReason.NotFraud;
        } else if (fp.kind == 2) {
            // 低付：同一收款人的已提交意图子集，uint256 和 > net[target].amount。
            if (fp.targetNetIndex >= ep.net.length) return RejectReason.NetIndexOutOfBounds;
            address targetRecipient = ep.net[fp.targetNetIndex].recipient;
            uint256 sum;
            bytes32[] memory hashes = new bytes32[](fp.intents.length);
            for (uint256 i = 0; i < fp.intents.length; i++) {
                IntentProof calldata ip = fp.intents[i];
                // 防假阳性 #2：跨收款人子集禁止（只与目标行比较）。
                if (address(ip.recipient) != targetRecipient) return RejectReason.BadFraudKind;
                bytes32 ih = _intentHash(ip);
                // 防假阳性 #1：同笔意图重复计入禁止。
                for (uint256 j = 0; j < i; j++) {
                    if (ih == hashes[j]) return RejectReason.DuplicateIntent;
                }
                hashes[i] = ih;
                if (!_verifyInclusion(ep, ip, ih)) return RejectReason.BadInclusionProof;
                sum += ip.amount;
            }
            if (sum <= ep.net[fp.targetNetIndex].amount) return RejectReason.NotFraud;
        } else {
            return RejectReason.BadFraudKind;
        }
        return RejectReason.None;
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

    /// 包含性验证（S-38：bool 化，失败由 `_verifyFraud` 归入 BadInclusionProof 原因码）。
    function _verifyInclusion(Epoch storage ep, IntentProof calldata ip, bytes32 ih)
        internal
        view
        returns (bool)
    {
        if (ip.leafIndex >= ip.acceptedCount) return false;
        if (ip.siblings.length != Merkle.treeDepth(ip.acceptedCount)) return false;
        bytes32 leafHash = Merkle.leaf(ip.seq, ih);
        return Merkle.computeRoot(leafHash, ip.leafIndex, ip.acceptedCount, ip.siblings)
            == ep.commitmentRoot;
    }
}
