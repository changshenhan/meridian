# Meridian 审计范围书（v1 · 2026-08-29）

> 用途：委托第三方安全审计时随附的范围与不变量定义。审计前如代码变更，以 tag
> `audit-v1` 为准重验。当前状态：**范围书就绪，审计委托未启动**（无资金预算，
> 启动时从本文件直接出发）。

## 1. 范围内（In Scope）

合约（`contracts/src/`，主审计对象，资产直接暴露）：

| 文件 | 资产角色 | 风险等级 |
|---|---|---|
| `BatchSettler.sol` | 持有结算资金（原生 ETH 或 USDC/ERC-20）+ 运营者债券 | **高** |
| `IntentHelper.sol` / `Merkle.sol` | 欺诈证明的 sha256 Merkle 交叉实现 | 高（安全性依赖与 Rust 侧逐字节一致） |
| `DSA.sol` | 委托登记（不持资产，但登记错误 → 下游错付） | 中 |
| `RevocationRegistry.sol` | 撤销锚点 | 中 |

链下交叉一致性（第二审计对象）：

- `meridian-core::dsa::delegation_hash`（Rust sha2）↔ Solidity `sha256` 预编译：
  字节级一致（`"DSAv1\0"` 前缀 + agent + owner canonical 编码，ABI 区间 `[26:46]`）。
- 聚合器 `RevocationSet::sparse_root`（sha256 sparse merkle）↔ 链上 `commit` 锚定根。
- 欺诈证明重算路径：链上 `IntentProof` → `intent_hash` → 叶子 → 根 vs 聚合器
  `merkle::commitment_root`。

## 2. 核心不变量（审计须逐一攻击）

1. **债券安全**：挑战成功必罚没 `bond` 给挑战者且 `settlementFunded` 全额退运营者；
   任何路径下挑战者不可双取、债券不可被挑战者以外的路径转走。
2. **CEI 顺序**：所有状态变更先于外部转账（claim/challenge/settle 逐函数核）。
3. **挑战窗口时序**：`commit → settle → (6h) → claim` 严格分离；voided epoch 的
   claim 永久拒绝；挑战窗口关闭后无任何状态可再变更（除 claim）。
4. **欺诈证明 soundness**：漏单/低付两类证明无假阳性路径（`DuplicateIntent`、
   跨收款人 `BadFraudKind`、`leafIndex < acceptedCount`、siblings 深度匹配）；诚实
   运营者提交自洽 net[] **不可**被构陷（重点 fuzz）。
5. **资产模式隔离**：token 模式强制 `msg.value == 0`；ETH 模式不走 `transferFrom`；
   退款/claim 付的资产与 `asset` 一致；债券恒原生 ETH 不受 asset 影响。
6. **重放/延展性**：`registerDelegation` 低位 s 强制；delegation_hash 碰撞面；
   意图跨 epoch 不重复入账。
7. **算术**：净额求和溢出（uint256）、`msg.value ≥ Σnet` 边界、费用为 0/1 wei 的
   极端净额。

## 3. 范围外（Out of Scope，诚实披露）

- **ZK 电路**（`circuits/`，Noir）：约束逻辑审计需 Noir 专长，单独二期。当前生产
  摄取路径用 `FormatVerifier`（TEMPORARY 占位），**未**依赖电路正确性——审计报告
  须注明此临时态；真实 BB wrapper 接入后电路进范围。
- 聚合器内核 Rust 侧（WAL/lattice）：不持链上资产，故障模式 = 停机非盗币；作为
  运营风险单独评估。
- 网关/SDK（S-29）：明文 HTTP 已披露（部署须 TLS 反代）。

## 4. 已知自报问题（供审计交叉验证）

- 原型级撤销树碰撞属性（两委托同 32-bit 前缀共享撤销叶子）——TECH_SPEC §5.3 已记，
  真实树在 Phase 2。
- 超付不可证（需完备性）——设计上接受，出界记录见 TECH_SPEC §6.5。
- challenge 无押金（v1 反垃圾靠 gas 成本）——已知垃圾挑战向量，评估报告应给意见。

## 5. 测试与证据基线

- forge 63/63（含 S-28 USDC 10 例：黑名单/双资产退款/资产隔离）。
- anvil rust-smoke 三场景 e2e（快乐路径/撤销/欺诈挑战）+ m1_demo 10 万笔端到端。
- 全量门禁 `scripts/verify.sh` 10 步（pre-push 强制）。
