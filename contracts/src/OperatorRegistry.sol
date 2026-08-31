// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

/// @title OperatorRegistry —— Phase 2 多运营者名册 + append-only 金额调度（TECH_SPEC §6.21）
/// @notice §6.17 决策 D 的实施砖：债券/押金金额走 append-only 调度（旧值永不改写，新值
///         追加生效，链上全史可审计），新 BatchSettler 实例部署时读取当刻值固化为
///         immutable；运营者名册 = self-registration 绑定实证（注册一条 = 声明对链上
///         一个真实 BatchSettler 实例的 operator 归属，任何人可独立复核）。
/// @dev 定夺（§6.21.1，记录在案）：
///      1. 「新实例读取当刻值固化」的读取点在**部署流程**而非构造器内部——构造器读外部
///         合约会把注册表写入者抬升为全部未来实例金额的链上决定者，并把注册表地址焊进
///         已冻结的构造 ABI（S-50 口径级联）。BatchSettler 逐字节不动。
///      2. registrar 触不到任何在役实例的判定面（调度只被未来部署读取）——与 S-50 否决
///         的运行时 setter 性质不同：setter 直接改写判定面金额，本合约只追加历史。
///      6. 记录面不是强制面：跳过注册表、偏离调度的部署不被阻止，只被全史与快照公开。
///      本合约不持有资金、不做写状态的外部调用（registerOperator 只对 settler 做只读
///      staticcall 取 getter）——零重入面，覆盖门禁下无豁免边。

/// BatchSettler 只读视图（S-28/S-50 immutable getter 快照源；名册注册的绑定实证目标）。
interface IBatchSettlerView {
    function operator() external view returns (address);
    function asset() external view returns (address);
    function challengeBond() external view returns (uint256);
}

contract OperatorRegistry {
    /// 金额调度条目：追加即成为「之后的部署」读取的当刻值（无预约生效窗口，§6.21.4）。
    struct ScheduleEntry {
        uint256 bond; // commit 债券（msg.value）
        uint256 challengeBond; // 挑战押金（BatchSettler 构造参数）
        uint64 writtenAt; // 追加时刻（block.timestamp）
    }

    /// 运营者名册条目：后三字段为注册时从 settler 实例 immutable getter 现场读出的
    /// 固化值快照（决策 D「存量实例各持其部署版本的值」的链上事实源）。
    struct OperatorEntry {
        address operator;
        address settler;
        address asset;
        uint256 challengeBond;
        uint64 registeredAt;
    }

    /// 调度写入者（immutable，部署 OperatorRegistry 的主体）。名册注册不经 registrar
    /// ——self-registration 绑定实证（§6.21.1 定夺 4），registrar 也无法替别人注册。
    address public immutable registrar;

    ScheduleEntry[] public schedule;
    OperatorEntry[] public operators;
    /// settler 去重：同一 BatchSettler 实例只登记一次（同一运营者可注册多个实例——
    /// 决策 D 的换金额路径 = 重部署 + 新实例注册，流水 append-only，无移除/停用）。
    mapping(address => bool) public isSettlerListed;
    mapping(address => uint256) public settlerCount;

    event ScheduleAppended(uint256 indexed index, uint256 bond, uint256 challengeBond);
    event OperatorRegistered(
        address indexed operator, address indexed settler, uint256 challengeBond
    );

    error ZeroRegistrar();
    error NotRegistrar();
    /// bond == 0（挑战赔付归零 = 乐观安全归零）或 challengeBond == 0（复活垃圾挑战面，
    /// S-50 ZeroChallengeBond 同语义，防未来部署直接撞构造 revert）。
    error ZeroScheduleAmount();
    /// 空调度读数 revert：部署流程不该在无调度时部署。
    error ScheduleEmpty();
    error SettlerAlreadyListed(address settler);
    error NotSettlerOperator(address settler, address expected, address actual);

    constructor(address registrar_) {
        if (registrar_ == address(0)) revert ZeroRegistrar();
        registrar = registrar_;
    }

    /// 追加一条金额调度（仅 registrar）。旧条目永不改写、无删除路径——动态性来自
    /// 调度 + 重部署，不来自 setter（§6.17 决策 D）。
    function appendSchedule(uint256 bond, uint256 challengeBond) external {
        if (msg.sender != registrar) revert NotRegistrar();
        if (bond == 0 || challengeBond == 0) revert ZeroScheduleAmount();
        schedule.push(
            ScheduleEntry({
                bond: bond, challengeBond: challengeBond, writtenAt: uint64(block.timestamp)
            })
        );
        emit ScheduleAppended(schedule.length - 1, bond, challengeBond);
    }

    /// 当刻调度（未来部署读取的值 = 最后一条）。
    function currentSchedule() external view returns (ScheduleEntry memory) {
        if (schedule.length == 0) revert ScheduleEmpty();
        return schedule[schedule.length - 1];
    }

    function scheduleCount() external view returns (uint256) {
        return schedule.length;
    }

    function operatorCount() external view returns (uint256) {
        return operators.length;
    }

    /// 名册自注册（§6.21.1 定夺 4/5）：调用者必须是 settler 实例的 immutable operator
    /// （无代码地址 / EOA 的接口调用直接 revert 气泡；归属不匹配 = 不可伪造的拒绝）。
    /// 注册时快照 asset/challengeBond 固化值，条目追加、settler 去重。
    function registerOperator(address settler) external {
        if (isSettlerListed[settler]) revert SettlerAlreadyListed(settler);
        IBatchSettlerView s = IBatchSettlerView(settler);
        // 全部 getter 先读后写（CEI；staticcall 视图调用无状态变更，零重入面）。
        address op = s.operator();
        if (op != msg.sender) revert NotSettlerOperator(settler, msg.sender, op);
        uint256 bond = s.challengeBond();
        address asset_ = s.asset();
        isSettlerListed[settler] = true;
        settlerCount[msg.sender] += 1;
        operators.push(
            OperatorEntry({
                operator: msg.sender,
                settler: settler,
                asset: asset_,
                challengeBond: bond,
                registeredAt: uint64(block.timestamp)
            })
        );
        emit OperatorRegistered(msg.sender, settler, bond);
    }
}
