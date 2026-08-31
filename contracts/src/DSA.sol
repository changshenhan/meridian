// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

/// @title DSA —— Delegated Spend Authority 注册（Contract 模式，TECH_SPEC §7）
/// @notice 链上与链下**同一 delegation_hash**：`registerDelegation` 用
///         `sha256(delegationABI)` 复算哈希，而 `delegationABI` 就是 mist-core
///         `delegation_abi()` 产出的规范字节原样上链（core/src/dsa.rs）。这样聚合器
///         （S-10）在 Contract 模式只依赖链上锚点，不重算哈希——两侧任何一侧改规范，
///         另一侧的 `sha256` 校验就会立即失配（§11 E-03 无反序列化歧义）。
/// @dev S-06 最小可跑版职责：验证 owner 签名（secp256k1，低位 s 防延展性）→ 去重 →
///      登记 delegation_hash → owner 绑定。委托的预算/类别/有效期语义校验在电路
///      （S-05）与聚合器（S-10）侧；本合约只锚定哈希→owner，供 RevocationRegistry
///      做 onlyOwner 校验。
/// @dev S-62（TECH_SPEC §6.19）委托→运营者绑定面（P2-2，决策 A/B）：dh → operator
///      独立映射，**不进 delegation_hash preimage**（改哈希派生会级联炸穿撤销索引
///      S-34/S-36、SDK 签名语义、电路公共输入与差分 fuzz S-57 全部锚点）。写入只认
///      owner 私钥（`msg.sender == owners[dh]`）而非注册入参——注册是「任何持有 owner
///      签名者可发」的许可面，让该签名携带 operator 等于允许第三方替 owner 选分片
///      运营者（支付路由劫持）。一次性固化：无解绑/改绑路径（TECH_SPEC §6.17.4
///      不可改绑——改绑窗口内旧账本在途消费不可回滚 = 双花面；迁移 = 撤销 + 重注册）。
contract DSA {
    event DelegationRegistered(bytes32 indexed delegationHash, address indexed owner);
    event OperatorBound(
        bytes32 indexed delegationHash, address indexed owner, address indexed operator
    );

    /// 已注册委托：delegation_hash -> owner。
    mapping(bytes32 => address) public owners;

    /// 运营者绑定（S-62）：delegation_hash -> operator。零地址 = 未绑定（聚合器
    /// 摄取绑定闸 fail-open 的链上事实源，TECH_SPEC §6.19.2）。
    mapping(bytes32 => address) public operators;

    /// 运营者绑定时刻（P2-3 §6.20.2/§6.23）：delegation_hash -> 绑定发生时的
    /// block.timestamp。一次性写——`bindOperator` 的 `AlreadyBound` 守卫保证本映射只在
    /// 首绑写入一次，绑定不可改 ⇒ 时刻随之不可变。kind4（跨分片消费）守卫的时间下界锚
    /// （`boundAt(dh) + ACCEPT_MARGIN <= acceptedAt`）；零值 = 未绑定（与 operators 零地址
    /// 同语义，§6.19.2 fail-open 三态）。
    mapping(bytes32 => uint64) public boundAt;

    /// secp256k1 群阶的一半（低位 s 判据，OpenZeppelin ECDSA 同款常量）。
    uint256 private constant SECP256K1N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    error AlreadyRegistered(bytes32 delegationHash);
    error BadOwnerSignature();
    error HighS();
    error MalformedABI();
    error NotRegistered(bytes32 delegationHash);
    error NotDelegationOwner();
    error AlreadyBound(bytes32 delegationHash);
    error ZeroOperator();

    /// @param delegationABI mist-core `canonical_delegation` 的原样字节
    ///        （前缀 "DSAv1\0" 6 + agent 20 + owner 20 + 其余字段，owner 定位于 [26:46]）
    /// @param ownerSig      owner 对 `sha256(delegationABI)` 的 secp256k1 紧凑签名 r||s（64 字节）
    function registerDelegation(bytes calldata delegationABI, bytes calldata ownerSig) external {
        // 最小可跑版只要求读到 owner 字段 [26:46]（前缀 6 + agent 20）；完整结构校验在
        // 聚合器与电路侧。字段级解析/版本校验可后续收紧。
        if (delegationABI.length < 46) revert MalformedABI();
        if (ownerSig.length != 64) revert BadOwnerSignature();

        bytes32 dh = sha256(delegationABI);
        if (owners[dh] != address(0)) revert AlreadyRegistered(dh);

        address owner = address(bytes20(delegationABI[26:46]));
        // ecrecover 内建接收 bytes32 r/s；低位 s 判据用其 uint256 值。
        bytes32 r = bytes32(ownerSig[0:32]);
        bytes32 s = bytes32(ownerSig[32:64]);
        // 拒绝高位 s，封堵签名延展性（TECH_SPEC §9）。
        if (uint256(s) > SECP256K1N_HALF) revert HighS();

        // sha256 输出可能 >= secp256k1 群阶 n，ecrecover 对 (hash>=n) 返回 0；
        // 由于 0 != owner，自然落入 BadOwnerSignature，无需额外分支。
        address recovered = ecrecover(dh, 27, r, s);
        if (recovered != owner) {
            recovered = ecrecover(dh, 28, r, s);
        }
        if (recovered != owner) revert BadOwnerSignature();

        owners[dh] = owner;
        emit DelegationRegistered(dh, owner);
    }

    /// 委托 owner 查询（RevocationRegistry 用它做 onlyOwner）。
    function ownerOf(bytes32 delegationHash) external view returns (address) {
        return owners[delegationHash];
    }

    /// TECH_SPEC §7：委托是否已注册。
    function isRegistered(bytes32 delegationHash) external view returns (bool) {
        return owners[delegationHash] != address(0);
    }

    /// S-62（§6.19.1）：owner 把已注册委托绑定到分片运营者。一次性固化，调用者必须是
    /// 委托 owner 本尊（`msg.sender` 判定，非签名转发——选型权钉在 owner 私钥上）。
    /// 存量委托（绑定面之前注册）由 owner 补绑即可受闸保护，不必重注册（§6.19.1 理由 3）。
    function bindOperator(bytes32 delegationHash, address operator) external {
        address owner = owners[delegationHash];
        if (owner == address(0)) revert NotRegistered(delegationHash);
        if (msg.sender != owner) revert NotDelegationOwner();
        // 零地址在本读协议里 = 「未绑定」：绑定为零会把 fail-open 放行语义伪装成已受闸。
        if (operator == address(0)) revert ZeroOperator();
        if (operators[delegationHash] != address(0)) revert AlreadyBound(delegationHash);

        operators[delegationHash] = operator;
        // P2-3 §6.23：绑定时刻（kind4 守卫锚）。首绑一次性写（上面 AlreadyBound 保证）。
        boundAt[delegationHash] = uint64(block.timestamp);
        emit OperatorBound(delegationHash, owner, operator);
    }

    /// 运营者绑定读面（S-62 聚合器摄取闸的 RPC 读目标）：零地址 = 未绑定。
    function operatorOf(bytes32 delegationHash) external view returns (address) {
        return operators[delegationHash];
    }
}
