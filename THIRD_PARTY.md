# THIRD-PARTY NOTICES

借鉴项目/依赖许可证合规清单（MASTER_PLAN S-01 / 蓝图"许可注意"）。

## 直接依赖（Cargo 依赖树）

| crate | 用途 | 许可证 |
|---|---|---|
| k256 | owner 签名 ECDSA-secp256k1 | Apache-2.0 OR MIT |
| ed25519-dalek | agent 签名 Ed25519 | BSD-3-Clause |
| sha2 | delegation_hash / intent_hash / 分片键 | Apache-2.0 OR MIT |
| serde / serde_json | 数据模型序列化、gate 报告 | Apache-2.0 OR MIT |
| hex | 十六进制显示 | Apache-2.0 OR MIT |
| proptest | property test | Apache-2.0 OR MIT |
| rand | 测试密钥生成 | Apache-2.0 OR MIT |
| criterion | 基准 | Apache-2.0 OR MIT |

结论：**全部为宽松许可（Apache-2.0 / MIT / BSD-3-Clause），无 GPL 系污染。** 可自由复制、修改、商用；分发时保留各 crate 许可证文本（Cargo 会在 crate 包内自带 LICENSE 文件，遵守即可）。

## 借鉴设计/思路（非代码复制，无需许可证，但记录出处）

| 思路 | 出处 | 借什么 |
|---|---|---|
| 模块化智能账户 + spend-policy | ERC-4337 / ERC-6900 | DSA 合约强制模式（Phase 2+） |
| ZK 授权态证明 | Sui zkLogin | DSA ZK 凭证模式 |
| 意图交易模型 | CoW Protocol | SpendIntent 语义 |
| 状态通道批量结算 | Lightning / Raiden | 聚合器 epoch 批量净额 |
| attestation 图 | EAS | L4 信任层（Phase 3） |
| web 数据交付证明 | TLSNotary / Reclaim | L4 履约证明（Phase 3） |
| 迭代声誉 | EigenTrust | L4 声誉函数（Phase 3） |

## 约束

- 后续任何新依赖必须经过本表审核，GPL 系一律不得引入。
- 引入新 crate 时同步更新本表。
