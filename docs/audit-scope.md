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
- 聚合器 `RevocationSet::sparse_root`（Pedersen sparse merkle，S-41 起与电路同哈希同叶规范，
  Rust 复现见 `aggregator/src/noir_pedersen.rs`）↔ 链上 `commit` 锚定根 ↔ 电路
  `revocation_root` 公共输入。
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
8. **挑战押金（S-38/S-50）**：押金金额为部署期构造参数 `challengeBond`（immutable，构造期
   `== 0` 即 revert），入场前仅四类 revert（未结算 / 已挑战 / 窗口外 / 金额不等）；
   入场后验证失败必走"事件 + 销毁"且 epoch 状态零改动（诚实 epoch 不可被失败挑战污染或
   void）；押金没收款只能进 `address(0)`，无任何一方可取回路径；成功路径押金 + 运营者债券
   一并给挑战者且不可双取；押金不形成跨交易余额状态。

## 3. 范围外（Out of Scope，诚实披露）

- **ZK 电路**（`circuits/`，Noir）：约束逻辑审计需 Noir 专长，单独二期。当前生产摄取
  路径**缺省**用 `FormatVerifier`（TEMPORARY 占位），**未**依赖电路正确性——审计报告
  须注明此临时态。S-40（2026-08-30）已交付真验证后端 `BbVerifier`（bb CLI wrapper，
  TECH_SPEC §6.13）：`MERIDIAN_VERIFY_BACKEND=bb` 显式开启后摄取路径**依赖电路正确性**
  （电路进审计范围）；该模式同时要求真电路 prover 产物（`PlaceholderProver` 产物会被
  fail-closed 全拒），prove 侧实装仍是独立交付物。
- 聚合器内核 Rust 侧（WAL/lattice）：不持链上资产，故障模式 = 停机非盗币；作为
  运营风险单独评估。
- 网关/SDK（S-29）：明文 HTTP 已披露（部署须 TLS 反代）。

## 4. 已知自报问题（供审计交叉验证）

- 撤销树碰撞属性——**两侧均已收口**：聚合器侧 S-34（2026-08-30，`RevocationSet::sparse_root`
  全 256-bit 索引，TECH_SPEC §4.6）；电路侧 S-36（2026-08-30，Noir 电路撤销树同步全宽化，
  depth 256，索引 = delegation_hash 全 32B LE，TECH_SPEC §5.3）。相异 delegation_hash 在两侧
  均派生相异叶。**哈希函数/叶值规范错配也已收口（S-41，2026-08-30）**：聚合器侧改为与电路
  同一棵 Pedersen 树（`aggregator/src/noir_pedersen.rs`，bb 预计算生成器硬编码 + 三层验证锚，
  TECH_SPEC §4.6），根数值可比。残余：聚合器尚不产出非成员路径（prover 侧消费，下一步
  候选②）；当前生产摄取路径 `FormatVerifier`（TEMPORARY）从不读 `pi.revocation_root`，
  真正的 `E_REVOKED` 闸口在 `submit()`。
- 超付不可证（需完备性）——设计上接受，出界记录见 TECH_SPEC §6.5。
- ~~challenge 无押金~~——**S-38 已收口（2026-08-30）**：`challenge` 变 `payable`，随笔押金
  （原生 ETH）；押金入场后任何实质验证失败不再 revert，改为 `ChallengeRejected` 事件 +
  押金全额销毁（`address(0)`），epoch 状态不变、仍可再挑战；成功路径挑战者拿回押金 +
  运营者债券。押金从不停留为合约状态（本笔交易内结清）。设计全文见 TECH_SPEC §6.5。
  ~~押金金额为固定常量，未动态化~~——**S-50 已收口（2026-08-30）**：金额改部署期构造参数
  `uint256 public immutable challengeBond`（`== 0` 构造即 revert `ZeroChallengeBond`），
  逐部署按 gas 价格/债券规模定夺；**只做部署期参数化，不做运行时 setter**（改运行时金额需
  引入 admin/governor 信任面，抬价 = 审查欺诈证明、降零 = 复活垃圾挑战，比金额过时严重
  得多——记录在案，见 TECH_SPEC §6.5）。残余自报：金额不随 gas 价格运行时自适应，随
  Phase 2 多运营者治理结构一起定夺。

## 5. 测试与证据基线

- forge 67/67（含 S-28 USDC 10 例：黑名单/双资产退款/资产隔离；S-38 挑战押金 2 例 +
  既有挑战负向用例改为"驳回即没收"断言；S-50 押金参数化 2 例：零押金构造拒绝 /
  非缺省押金端到端）。
- anvil rust-smoke 三场景 e2e（快乐路径/撤销/欺诈挑战）+ m1_demo 10 万笔端到端。
- 全量门禁 `scripts/verify.sh` 10 步（pre-push 强制）。
