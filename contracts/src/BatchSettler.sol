// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

import {DSA} from "./DSA.sol";
import {IntentHelper} from "./IntentHelper.sol";
import {Merkle} from "./Merkle.sol";
import {RevocationRegistry} from "./RevocationRegistry.sol";

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
///      · S-38/S-50 挑战押金（TECH_SPEC §6.5）：challenge 变 payable，随笔押金 challengeBond
///        （原生 ETH，与 asset 无关；S-50 起为部署期构造参数 immutable，`== 0` 构造即
///        revert，不做运行时 setter）。押金入场前 4 类 revert（未结算 / 已挑战 / 窗口外 /
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
        /// 平行接受树根（P2-3 §6.20.2/§6.23）：与承诺树同叶集同序（seq 升序），叶 =
        /// `Merkle.acceptanceLeaf(seq, acceptedAt)`。单独锚定「意图何时被接受」，
        /// 与撤销根同款「不并入承诺树」（不破坏承诺叶索引，S-11 决策）。
        bytes32 acceptanceRoot;
        /// 运营者声明的密封时刻（§6.23.1 定夺 5）：观测面字段——与 `committedAt` 的有序窗
        /// 核对在离线比对器做，**不进合约判定**（判定面 require 它会对自派时钟超前链钟的
        /// 诚实运营者构成可用性陷阱，而对回填逃逸方向无约束力）。
        uint64 sealedAt;
        /// commit 时刻（链上写定）：观测面上界锚（sealedAt ≤ committedAt 由离线比对器核对）。
        uint64 committedAt;
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

    /// 欺诈证明中的一条已提交意图（明文 + 承诺格包含位置 + 接受锚包含位置）。
    struct IntentProof {
        bytes20 agent;
        bytes32 delegationHash;
        bytes20 recipient;
        uint64 amount;
        bytes32 category;
        uint64 spendNonce;
        bytes memo;
        uint64 expiresAt;
        /// 接受时刻锚（P2-3 §6.23）：聚合器自派时钟的入口快照，链上由平行接受树承诺。
        /// kind1/kind2 不消费（向后兼容的证据形状）；kind3/kind4 的时间守卫输入。
        uint64 acceptedAt;
        uint64 seq;
        uint256 leafIndex;
        uint256 acceptedCount;
        /// 承诺树兄弟路径（自底层向上）。
        bytes32[] siblings;
        /// 接受树兄弟路径（P2-3 §6.23.1 定夺 6）：两树同叶序 ⇒ 同 `leafIndex` /
        /// `acceptedCount` / 同深度，仅叶规范与根不同。
        bytes32[] acceptanceSiblings;
    }

    /// 欺诈证明：kind 1 = 漏单（一条已提交意图，其收款人不在 net[]）；kind 2 = 低付
    /// （同一收款人的已提交意图子集，uint256 和 > net[targetNetIndex].amount）；
    /// kind 3 = 已撤销消费（一条已提交意图，其委托在 acceptedAt − margin 之前已撤销，
    /// P2-3 §6.20.2）；kind 4 = 跨分片消费（委托绑在他方运营者名下且 boundAt + margin
    /// ≤ acceptedAt 仍被本账本接受）。kind1/kind2 单调子集无需完备性；kind3/kind4 均
    /// 单意图（BadFraudKind 计数闸，kind1 同款）。
    struct FraudProof {
        uint8 kind;
        uint256 targetNetIndex; // kind 2 用
        IntentProof[] intents;
    }

    event Commit(
        uint256 indexed epochId,
        bytes32 commitmentRoot,
        bytes32 revocationRoot,
        bytes32 acceptanceRoot,
        uint64 sealedAt,
        uint256 bondedAmount
    );
    event Settled(uint256 indexed epochId, bytes32 nettingRoot, uint64 netCount);
    event ChallengeSucceeded(uint256 indexed epochId, address indexed challenger, uint8 kind);
    /// 审计加固：结算资金 push 退款失败后的运营者拉取（withdrawRefund）。
    event RefundWithdrawn(uint256 indexed epochId, uint256 amount);
    /// S-38：欺诈证明被驳回（押金没收销毁，epoch 状态不变）。reason 见 RejectReason。
    event ChallengeRejected(uint256 indexed epochId, address indexed challenger, uint8 reason);
    event Claimed(uint256 indexed epochId, address indexed recipient, uint256 amount);

    /// S-38：欺诈证明驳回原因码（押金入场后不再 revert，改为本枚举随事件上报）。
    enum RejectReason {
        None, // 占位（0 值不随事件使用 = 验证通过）
        NotFraud, // 证明自洽但不构成欺诈（漏单收款人在 net[] / 低付子集和不超行额）
        BadInclusionProof, // 叶索引越界 / 兄弟深度不匹配 / 根不匹配（含伪造意图）
        DuplicateIntent, // 低付子集同笔意图重复计入（防假阳性 #1）
        BadFraudKind, // kind 非法 / kind1 意图数 != 1 / 跨收款人子集（防假阳性 #2）
        TooManyIntents, // 意图数为 0 或超出 gas 上界
        NetIndexOutOfBounds // kind2 目标行越界
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
    // S-38：挑战押金金额不等（msg.value != challengeBond，押金入场前 revert）。
    error WrongChallengeBond();
    // S-50：押金金额为 0 的部署（等于静默回退到 S-38 之前的垃圾挑战面），构造期挡下。
    error ZeroChallengeBond();
    // 审计加固：operator 零地址 = commit/settle 恒 NotOperator（自 DoS）。asset 的零地址是
    // 合法哨兵（= 原生 ETH 模式，S-28），不做零检查。
    error ZeroOperator();
    // S-28 资产参数化。
    error TokenTransferFailed();
    error EthValueInTokenMode();
    // 审计加固：结算资金拉取兜底（挑战成功时退款 push 失败的留存量，仅 voided epoch 可取）。
    error EpochNotVoided(uint256 epochId);
    error NothingToRefund(uint256 epochId);
    // P2-3 §6.23.1 定夺 7：kind3/kind4 守卫要读 DSA（boundAt/operatorOf）与
    // RevocationRegistry（revokedAt）的事件时刻锚——缺依赖 = 守卫静默失效面伪装，构造期拒。
    error ZeroAnchor();
    // 部署配置错误：注册表自身也指向 DSA（RevocationRegistry.dsa），两指针失配 = 撤销
    // 时刻锚与运营者绑定锚取自两套注册面，构造期暴露。
    error DsaMismatch();

    /// 挑战窗口：settle 后 6 小时内可挑战（TECH_SPEC §6.5）。
    uint256 public constant CHALLENGE_WINDOW = 6 hours;
    /// 单次挑战最多携带的意图数（gas 上界：epoch_capacity=100k → 树深 17，每意图 ~19 次
    /// sha256 预编译；32 意图 ≈ 500-600k gas，块内可行）。
    uint256 public constant MAX_INTENTS_PER_CHALLENGE = 32;
    /// S-50 挑战押金（原生 ETH，与 asset 无关）：垃圾挑战的押金成本（此前只靠 gas，见
    /// TECH_SPEC §6.5）。部署期构造参数（immutable），逐部署按 gas 价格/债券规模定夺；
    /// 不做运行时 setter——改运行时金额需引入 admin 信任面（抬价 = 审查欺诈证明、降零 =
    /// 复活垃圾挑战），比金额过时严重得多。`== 0` 构造即 revert（`ZeroChallengeBond`）。
    uint256 public immutable challengeBond;

    /// P2-3 §6.20.2/§6.23.1 定夺 3：接受时刻余量（秒，协议常量，无 setter，Rust/合约两侧
    /// 同值）。覆盖运营者自身 RPC 读陈旧 / 撤销观察滞后——kind3/kind4 守卫要求「事件时刻 +
    /// margin ≤ acceptedAt」，太小时正常传播期内的诚实接受被罚（假阳性回归），太大时过失
    /// 免罚窗口变宽。300s ≈ 2 个数量级于本地同步传播（S-59 实测 ~0s）、~18× 于链上事件
    /// 路径（块时 + 轮询 ~17s），同时 << CHALLENGE_WINDOW（6h）。推定缺省非实测标定，
    /// 重定夺走重部署（immutable）。
    uint256 public constant ACCEPT_MARGIN = 300;

    /// 唯一结算运营者：commit/settle 的唯一合法调用者（S-11 防 griefing）。
    address public immutable operator;
    /// S-28 结算资产：`address(0)` = 原生 ETH（v2 行为）；否则为 ERC-20（如 USDC）。
    /// 债券（commit 的 `msg.value`）恒为原生 ETH，与结算资产无关。
    address public immutable asset;
    /// P2-3：kind4 守卫的运营者绑定锚（`DSA.boundAt` / `DSA.operatorOf`）。
    DSA public immutable dsa;
    /// P2-3：kind3 守卫的撤销时刻锚（`RevocationRegistry.revokedAt`）。
    RevocationRegistry public immutable revocations;

    /// 存储本体（S-66 读面拆分：不再 public 自动 getter——Epoch 13 字段后，自动 getter
    /// 的 13 元组返回在 legacy codegen（forge coverage 关优化编译）恒爆栈：13 个隐式
    /// 返回槽恒活跃，最小 13 元组函数亦不可编译，与函数体无关 → 读面拆分为
    /// [`epochs`]（9 静态字段）+ [`epochStatus`]（4 状态位）。内部引用经 epochsById。
    mapping(uint256 => Epoch) internal epochsById;

    constructor(
        address operator_,
        address asset_,
        uint256 challengeBond_,
        DSA dsa_,
        RevocationRegistry revocations_
    ) {
        if (operator_ == address(0)) revert ZeroOperator();
        operator = operator_;
        // slither-disable-next-line missing-zero-check（故意：asset=address(0) 是合法哨兵，= 原生 ETH 模式，S-28）
        asset = asset_;
        if (challengeBond_ == 0) revert ZeroChallengeBond();
        challengeBond = challengeBond_;
        if (dsa_ == DSA(address(0)) || revocations_ == RevocationRegistry(address(0))) {
            revert ZeroAnchor();
        }
        // 交叉核对：注册表自身也指向 DSA，两指针必须同一注册面（部署配置错误构造期暴露）。
        if (revocations_.dsa() != dsa_) revert DsaMismatch();
        dsa = dsa_;
        revocations = revocations_;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    /// 运营者提交承诺根 + 撤销根 + 接受锚根并质押债券（msg.value）。同一 epoch 只允许一次。
    /// `sealedAt` 是运营者声明的密封时刻（观测面，定夺 5——不进判定面，无 require）；
    /// `committedAt` 由本合约以 `block.timestamp` 写定。
    function commit(
        uint256 epochId,
        bytes32 commitmentRoot,
        bytes32 revocationRoot,
        bytes32 acceptanceRoot,
        uint64 sealedAt
    ) external payable onlyOperator {
        Epoch storage ep = epochsById[epochId];
        if (ep.committed) revert EpochAlreadyCommitted(epochId);
        ep.committed = true;
        ep.commitmentRoot = commitmentRoot;
        ep.revocationRoot = revocationRoot;
        ep.acceptanceRoot = acceptanceRoot;
        ep.sealedAt = sealedAt;
        ep.committedAt = uint64(block.timestamp);
        ep.bondedAmount = msg.value;
        emit Commit(epochId, commitmentRoot, revocationRoot, acceptanceRoot, sealedAt, msg.value);
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
        Epoch storage ep = epochsById[epochId];
        if (!ep.committed) revert EpochUnknown(epochId);
        if (ep.settled) revert EpochAlreadySettled(epochId);
        if (nettingRoot != keccak256(abi.encode(net))) revert WrongNettingRoot();
        uint256 total = _sumNet(net);
        // S-28 结算资金来源：ETH 模式 = msg.value；token 模式 = 从运营者 transferFrom 拉款
        //（需事先 approve），且禁止 ETH 随单进入（防卡死）。
        if (asset == address(0)) {
            if (msg.value < total) revert InsufficientSettlementFunding();
        } else {
            if (msg.value != 0) revert EthValueInTokenMode();
        }
        // 审计加固（CEI）：先写全部状态再拉外部资金，杜绝 asset 回调（ERC777 类）重入
        // settle 二次结算的理论缝——尽管重入者只能是运营者自己选的 asset，仍按
        // checks-effects-interactions 收口，不给审计留 Finding。失败整笔回滚，无中间态。
        ep.settled = true;
        ep.nettingRoot = nettingRoot;
        ep.settledAt = uint64(block.timestamp);
        ep.settlementFunded = total;
        for (uint256 i = 0; i < net.length; i++) {
            ep.net.push(net[i]);
        }
        if (asset != address(0)) {
            if (!IERC20(asset).transferFrom(msg.sender, address(this), total)) {
                revert TokenTransferFailed();
            }
        }
        emit Settled(epochId, nettingRoot, uint64(net.length));
    }

    /// 延迟领取：窗口（挑战期）过后，收款人（或其代理人）逐条领取净额。整 epoch voided 后拒绝。
    function claim(uint256 epochId, uint256 netIndex) external {
        Epoch storage ep = epochsById[epochId];
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
    /// 随笔押金 challengeBond（原生 ETH，token 模式下债券/押金仍为 ETH）。
    /// 押金入场前 revert（无押金风险）：epoch 未结算 / 已成功挑战或 voided / 窗口关闭 /
    /// msg.value != challengeBond。押金入场后"驳回即没收"：任何实质验证失败不再 revert，
    /// 发 ChallengeRejected + 押金全额销毁（address(0)）、epoch 状态一字不动（仍可再挑战）。
    /// 验证通过 → 押金退回 + 运营者债券罚没给挑战者、settlementFunded 退运营者、整 epoch
    /// voided。退款推送失败不阻断挑战（资金留合约，运营者经 withdrawRefund 拉取兜底）——
    /// 防恶意运营者以 revert 地址 / token 黑名单审查欺诈证明。
    function challenge(uint256 epochId, FraudProof calldata fp) external payable {
        Epoch storage ep = epochsById[epochId];
        if (!ep.settled) revert EpochUnknown(epochId);
        if (ep.challenged || ep.voided) revert EpochAlreadyChallenged(epochId);
        if (block.timestamp > uint256(ep.settledAt) + CHALLENGE_WINDOW) {
            revert ChallengeWindowClosed();
        }
        if (msg.value != challengeBond) revert WrongChallengeBond();

        RejectReason reason = _verifyFraud(ep, fp);
        if (reason != RejectReason.None) {
            // CEI：事件（状态）先行，再外部调用。销毁目标 address(0) 无代码，无重入面。
            emit ChallengeRejected(epochId, msg.sender, uint8(reason));
            // require 的失败边结构不可达（S-58 覆盖扫描唯一豁免边，TECH_SPEC §8.3）：
            // ETH 向无代码地址推送不可能失败，无测试可达路径。保留 require 只为
            // 显式声明资金面不变量，绝不作为可达校验依赖。
            (bool okBurn,) = payable(address(0)).call{value: challengeBond}("");
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
        (bool okPayout,) = payable(msg.sender).call{value: challengeBond + bond}("");
        require(okPayout, "bond transfer failed");
        if (refund > 0) {
            // S-28：settlementFunded 退款按结算资产原路退回（ETH 或 token）。
            // 审计加固：退款失败**绝不阻断挑战本身**——挑战整体原子回滚意味着恶意运营者
            // 只要把 operator 地址做成收 ETH 即 revert 的合约（或让自身进 token 黑名单），
            // 就能审查一切欺诈证明（epoch 永不 voided，债券机制对其失效）。退款推送失败时
            // 资金留在合约并记回 settlementFunded，运营者可经 withdrawRefund 拉取兜底。
            // 失败回记账的 reentrancy-eth 定性（审计留档）：回记账是贷记方向（记回运营者
            // 应得资金），且外呼期间重入面已闭合——challenged/voided 先行、settlementFunded
            // 已清零，重入 challenge/claim/withdrawRefund 均被前置守卫拒绝。
            if (asset == address(0)) {
                (bool okRefund,) = payable(operator).call{value: refund}("");
                // slither-disable-next-line reentrancy-eth
                if (!okRefund) ep.settlementFunded = refund;
            } else {
                bool pushed = false;
                try IERC20(asset).transfer(operator, refund) returns (bool ok) {
                    pushed = ok;
                } catch {
                    pushed = false; // 真实 USDC 黑名单是 revert 冒泡（catch 吸收，不阻断挑战）
                }
                // slither-disable-next-line reentrancy-eth
                if (!pushed) ep.settlementFunded = refund;
            }
        }
        emit ChallengeSucceeded(epochId, msg.sender, fp.kind);
    }

    /// 审计加固：结算资金拉取兜底 —— 挑战成功时退款 push 失败（运营者合约不收 ETH /
    /// token 黑名单 revert）而留在合约的资金，运营者自行取回。
    /// 仅 voided epoch 开放：正常 epoch 的结算资金归收款人 claim，绝不给运营者取回路径
    ///（防双花）；voided epoch 的 claim 已被拒，这笔钱不会再被任何人认领。
    function withdrawRefund(uint256 epochId) external onlyOperator {
        Epoch storage ep = epochsById[epochId];
        if (!ep.committed || !ep.voided) revert EpochNotVoided(epochId);
        uint256 refund = ep.settlementFunded;
        if (refund == 0) revert NothingToRefund(epochId);
        ep.settlementFunded = 0;
        if (asset == address(0)) {
            (bool okRefund,) = payable(operator).call{value: refund}("");
            require(okRefund, "refund transfer failed");
        } else {
            if (!IERC20(asset).transfer(operator, refund)) revert TokenTransferFailed();
        }
        emit RefundWithdrawn(epochId, refund);
    }

    /// 欺诈证明实质验证（S-38：不再 revert，失败返回原因码；None = 欺诈成立）。判定逻辑与
    /// 押金制之前逐字等价，仅把 revert 换成原因码返回。
    /// kind 判定拆分为独立内部函数（legacy codegen 的 stack too deep 收口，先例
    /// _epochView/_epochViewOn：coverage 模式关 optimizer/via_ir，四分支局部变量共占
    /// 一帧爆栈）——判定语义逐字保持，仅降低单函数栈槽压力。
    function _verifyFraud(Epoch storage ep, FraudProof calldata fp)
        internal
        view
        returns (RejectReason)
    {
        if (fp.intents.length == 0 || fp.intents.length > MAX_INTENTS_PER_CHALLENGE) {
            return RejectReason.TooManyIntents;
        }
        if (fp.kind == 1) return _verifyFraudKind1(ep, fp);
        if (fp.kind == 2) return _verifyFraudKind2(ep, fp);
        if (fp.kind == 3) return _verifyFraudKind3(ep, fp);
        if (fp.kind == 4) return _verifyFraudKind4(ep, fp);
        return RejectReason.BadFraudKind;
    }

    /// kind1 = 漏单：一条已提交意图，其收款人不在 net[] 中。
    function _verifyFraudKind1(Epoch storage ep, FraudProof calldata fp)
        internal
        view
        returns (RejectReason)
    {
        if (fp.intents.length != 1) return RejectReason.BadFraudKind;
        bytes32 ih = _intentHash(fp.intents[0]);
        if (!_verifyInclusion(ep, fp.intents[0], ih)) return RejectReason.BadInclusionProof;
        address recipient = address(fp.intents[0].recipient);
        (bool found,) = _indexOfRecipient(ep, recipient);
        if (found) return RejectReason.NotFraud;
        return RejectReason.None;
    }

    /// kind2 = 低付：同一收款人的已提交意图子集，uint256 和 > net[target].amount。
    function _verifyFraudKind2(Epoch storage ep, FraudProof calldata fp)
        internal
        view
        returns (RejectReason)
    {
        if (fp.targetNetIndex >= ep.net.length) return RejectReason.NetIndexOutOfBounds;
        address targetRecipient = ep.net[fp.targetNetIndex].recipient;
        // slither-disable-next-line uninitialized-local（误报：Solidity 默认 0 初始化，下方累加）
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
        return RejectReason.None;
    }

    /// kind3 = 已撤销消费（P2-3 §6.20.2）：一条已提交意图，其委托在「接受时刻 −
    /// margin」之前已撤销——运营者撤销观察缺席仍接受 = 可罚本体（§6.23.1 定夺 10）。
    /// 单意图（kind1 同款计数闸）；可罚性锚在「已接受」本身，不做 net 命中检查。
    function _verifyFraudKind3(Epoch storage ep, FraudProof calldata fp)
        internal
        view
        returns (RejectReason)
    {
        if (fp.intents.length != 1) return RejectReason.BadFraudKind;
        IntentProof calldata ip = fp.intents[0];
        bytes32 ih = _intentHash(ip);
        // 承诺树包含（意图确在本 epoch 被接受）∧ 接受树包含（接受时刻确如证明所声明）
        // ——缺一即 BadInclusionProof（伪造 / 回填接受时刻都被承诺面挡住，§6.23.1 定夺 8）。
        if (!_verifyInclusion(ep, ip, ih)) return RejectReason.BadInclusionProof;
        if (!_verifyAcceptanceInclusion(ep, ip)) return RejectReason.BadInclusionProof;
        uint64 ra = revocations.revokedAt(ip.delegationHash);
        // 未撤销（revokedAt = 0，与 revoked 布尔同语义）→ kind 不成立（NotFraud）。
        if (ra == 0) return RejectReason.NotFraud;
        // margin 守卫（§6.20.3）：撤销后 ACCEPT_MARGIN 秒内的接受不罚——运营者 RPC
        // 读陈旧 / 撤销观察滞后的余量。uint256 算术无溢出面。
        if (uint256(ra) + ACCEPT_MARGIN > uint256(ip.acceptedAt)) {
            return RejectReason.NotFraud;
        }
        return RejectReason.None;
    }

    /// kind4 = 跨分片消费（P2-3 §6.20.2）：委托已绑定到他方运营者（boundAt + margin
    /// ≤ acceptedAt）仍被本账本接受——分片账本看不见的跨分片预算超支的可罚本体
    ///（锚点是链上绑定映射 DSA.operatorOf，§6.19.1）。
    function _verifyFraudKind4(Epoch storage ep, FraudProof calldata fp)
        internal
        view
        returns (RejectReason)
    {
        if (fp.intents.length != 1) return RejectReason.BadFraudKind;
        IntentProof calldata ip = fp.intents[0];
        bytes32 ih = _intentHash(ip);
        if (!_verifyInclusion(ep, ip, ih)) return RejectReason.BadInclusionProof;
        if (!_verifyAcceptanceInclusion(ep, ip)) return RejectReason.BadInclusionProof;
        address op = dsa.operatorOf(ip.delegationHash);
        uint64 ba = dsa.boundAt(ip.delegationHash);
        // 未绑定（boundAt = 0 ⇔ operatorOf = 零地址）→ fail-open 三态，kind 不成立
        //（§6.19.2 决策 B 有意取舍，与聚合器摄取闸同口径）；绑到本合约 operator =
        // 本运营者自己的委托，非跨分片，kind4 无对象。
        if (ba == 0 || op == address(0) || op == operator) return RejectReason.NotFraud;
        if (uint256(ba) + ACCEPT_MARGIN > uint256(ip.acceptedAt)) {
            return RejectReason.NotFraud;
        }
        return RejectReason.None;
    }

    /// epoch 静态读面（S-66 读面拆分 1/2）：根锚 + 时刻 + 金额 9 字段（Epoch 声明序去
    /// 布尔组）。显式函数替代 public 自动 getter 的原因见 epochsById 处注释。
    function epochs(uint256 epochId)
        external
        view
        returns (
            bytes32 commitmentRoot,
            bytes32 revocationRoot,
            bytes32 acceptanceRoot,
            uint64 sealedAt,
            uint64 committedAt,
            uint256 bondedAmount,
            uint256 settlementFunded,
            uint64 settledAt,
            bytes32 nettingRoot
        )
    {
        Epoch storage ep = epochsById[epochId];
        commitmentRoot = ep.commitmentRoot;
        revocationRoot = ep.revocationRoot;
        acceptanceRoot = ep.acceptanceRoot;
        sealedAt = ep.sealedAt;
        committedAt = ep.committedAt;
        bondedAmount = ep.bondedAmount;
        settlementFunded = ep.settlementFunded;
        settledAt = ep.settledAt;
        nettingRoot = ep.nettingRoot;
    }

    /// epoch 状态位读面（S-66 读面拆分 2/2）：committed/settled/challenged/voided。
    function epochStatus(uint256 epochId)
        external
        view
        returns (bool committed, bool settled, bool challenged, bool voided)
    {
        Epoch storage ep = epochsById[epochId];
        committed = ep.committed;
        settled = ep.settled;
        challenged = ep.challenged;
        voided = ep.voided;
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

    /// 接受锚包含性验证（P2-3 §6.23）：叶 = `Merkle.acceptanceLeaf(seq, acceptedAt)`，
    /// 根 = `Epoch.acceptanceRoot`。与承诺树同叶集同序 ⇒ 复用同一 `leafIndex` /
    /// `acceptedCount`（自校验：错值 → 根不匹配）与同深度兄弟路径。
    /// 前置条件：调用方（_verifyFraudKind3/4）已先行通过 `_verifyInclusion`——同参数
    /// `leafIndex >= acceptedCount` 拦截在承诺树闸完成，此处不重复（重复即一条测试
    /// 不可达的恒假分支，S-66 coverage 门禁收口时删除）。
    function _verifyAcceptanceInclusion(Epoch storage ep, IntentProof calldata ip)
        internal
        view
        returns (bool)
    {
        if (ip.acceptanceSiblings.length != Merkle.treeDepth(ip.acceptedCount)) return false;
        bytes32 leafHash = Merkle.acceptanceLeaf(ip.seq, ip.acceptedAt);
        return Merkle.computeRoot(leafHash, ip.leafIndex, ip.acceptedCount, ip.acceptanceSiblings)
            == ep.acceptanceRoot;
    }
}
