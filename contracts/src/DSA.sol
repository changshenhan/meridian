// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.24;

/// @title DSA —— Delegated Spend Authority 注册（Contract 模式，TECH_SPEC §7）
/// @notice 链上与链下**同一 delegation_hash**：`registerDelegation` 用
///         `sha256(delegationABI)` 复算哈希，而 `delegationABI` 就是 meridian-core
///         `delegation_abi()` 产出的规范字节原样上链（core/src/dsa.rs）。这样聚合器
///         （S-10）在 Contract 模式只依赖链上锚点，不重算哈希——两侧任何一侧改规范，
///         另一侧的 `sha256` 校验就会立即失配（§11 E-03 无反序列化歧义）。
/// @dev S-06 最小可跑版职责：验证 owner 签名（secp256k1，低位 s 防延展性）→ 去重 →
///      登记 delegation_hash → owner 绑定。委托的预算/类别/有效期语义校验在电路
///      （S-05）与聚合器（S-10）侧；本合约只锚定哈希→owner，供 RevocationRegistry
///      做 onlyOwner 校验。
contract DSA {
    event DelegationRegistered(bytes32 indexed delegationHash, address indexed owner);

    /// 已注册委托：delegation_hash -> owner。
    mapping(bytes32 => address) public owners;

    /// secp256k1 群阶的一半（低位 s 判据，OpenZeppelin ECDSA 同款常量）。
    uint256 private constant SECP256K1N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    error AlreadyRegistered(bytes32 delegationHash);
    error BadOwnerSignature();
    error HighS();
    error MalformedABI();

    /// @param delegationABI meridian-core `canonical_delegation` 的原样字节
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
}
