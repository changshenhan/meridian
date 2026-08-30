# Meridian 审计范围书（v1 · 2026-08-29，S-58 与实态对齐 · 2026-08-31）

> 用途：委托第三方安全审计时随附的范围与不变量定义。审计前如代码变更，以 tag
> `audit-v1` 为准重验。当前状态：**范围书就绪且已与实态对齐（S-58，含 §6 冻结清单），
> 审计委托未启动**（付费项，预算待批；启动时从本文件 + §6 清单直接出发）。

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
  TECH_SPEC §6.13）；**prove 侧 S-43（2026-08-30）已实装**（`NoirProver`，TECH_SPEC
  §6.14）。`MERIDIAN_VERIFY_BACKEND=bb` 显式开启后摄取路径**依赖电路正确性**
  （电路进审计范围）；该模式同时要求真电路 prover 产物（`PlaceholderProver` 产物会被
  fail-closed 全拒）。全链真 ZK 装配的可运行示例见 §6.15（`noir_demo`）。
- 聚合器内核 Rust 侧（WAL/lattice）：不持链上资产，故障模式 = 停机非盗币；作为
  运营风险单独评估。
- 网关/SDK（S-29）：明文 HTTP 已披露（部署须 TLS 反代；部署口径已落 S-56，2026-08-30，
  TECH_SPEC §6.7 部署拓扑节 + docs/ops.md §7——网关恒回环明文、反代是信任边界但
  **不是认证边界**，bearer/admin key 是唯一凭据，无 mTLS）。

## 4. 已知自报问题（供审计交叉验证）

- 撤销树碰撞属性——**两侧均已收口**：聚合器侧 S-34（2026-08-30，`RevocationSet::sparse_root`
  全 256-bit 索引，TECH_SPEC §4.6）；电路侧 S-36（2026-08-30，Noir 电路撤销树同步全宽化，
  depth 256，索引 = delegation_hash 全 32B LE，TECH_SPEC §5.3）。相异 delegation_hash 在两侧
  均派生相异叶。**哈希函数/叶值规范错配也已收口（S-41，2026-08-30）**：聚合器侧改为与电路
  同一棵 Pedersen 树（`aggregator/src/noir_pedersen.rs`，bb 预计算生成器硬编码 + 三层验证锚，
  TECH_SPEC §4.6），根数值可比。**非成员路径也已产出（S-42，2026-08-30）**并由真 prover
  消费（S-43 电路自校验重算根对账）、绑定闸收口（S-44/S-48：`enforce_revocation_root`，
  证明公共输入 `revocation_root` 必须 ∈ 本账本撤销状态根集合）。残余：当前生产摄取路径
  `FormatVerifier`（TEMPORARY）从不读 `pi.revocation_root`，真正的 `E_REVOKED` 闸口在
  `submit()`。
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

## 5. 测试与证据基线（S-58 对齐至 2026-08-31，commit 见 git log）

**合约面（forge）**：

- forge **90/90**（S-38 押金制负向组改 `_challengeRejected` 断言；S-50 押金参数化 2 例；
  S-58 覆盖缺口 6 例：claim push 失败回滚可重试 / 挑战者拒收赔付整笔回滚 / kind1 多意图
  → BadFraudKind / kind2 目标行越界 / kind2 混入伪造意图 → BadInclusionProof /
  withdrawRefund push 失败可重试；USDC 套件含 false 返回与 revert 冒泡两种 token 失败语义）。
- **invariant fuzz**（2026-08-31，四步路径 ②）：`test/BatchSettlerInvariant.t.sol`
  64 runs × depth 256，三条全局不变量（资金守恒 ghost 记账 / 状态机单调 / voided 后
  claim 必拒），handler 覆盖 commit/settle 三模式/窗口内双路挑战/warp 过窗 claim。
- **跨实现差分 fuzz**（S-57，四步路径 ③）：Rust 生产实现批量产 140 golden vectors →
  forge 镜像四契约逐条比对（intent_hash ×64 / DSA owner 切片 ×32 / Merkle 树·根·证明·
  深度 / nettingRoot 编码**字节级** ×16），第三实现 Python 独立重算交叉确认；fixture
  漂移闸（verify.sh 8b）。
- **分支覆盖门禁**（S-58，四步路径 ④）：`scripts/coverage_gate.sh`（verify.sh 8c +
  CI solidity job）——src 全合约行/函数 100%、分支 100%，唯一豁免 BatchSettler 1 条
  结构不可达边（押金销毁 `require(okBurn)` 失败边，代码注释 + slither 报告定性）。
  阈值与豁免口径在脚本文件头；**缺口=补负向测试，不是调阈值**。
- **slither 全量扫描 + 人工定性**（2026-08-31，`docs/audit/slither-2026-08-31.md`）：
  首扫 12 结果 → 修复 2 处真问题（settle CEI 重排 / ZeroOperator 构造期挡下）、余项全部
  已知设计族并逐条代码内定性；深度人工审计第二轮修复高危审查向量（退款 push 失败
  阻断挑战）+ withdrawRefund 拉取兜底。

**链上面**：

- anvil rust-smoke 三场景 e2e（快乐路径/撤销/欺诈挑战）+ m1_demo 10 万笔端到端
  （verify.sh 步 10；CI 同款 alloy smoke）+ verifier_drill 三幕验证者挑战演练
  （S-61，镜像复算检出 → challenge 全链：诚实静默 / kind1 漏单 / kind2 低付；
  零合约改动，对账口径见 TECH_SPEC §6.18.6）。

**ZK/装配面（范围外声明的对照证据）**：

- 电路本地验收 `scripts/formal_zk.sh` 8 步（约束 < 2^18 门禁）+ 真 prover
  `NoirProver`（S-43）× 真验证 `BbVerifier`（S-40）闭环 e2e（verify.sh 9b/9c/9d/9e/9f）
  + 撤销根绑定闸（S-44/S-48 构造期配对闸）。

**门禁**：全量 `scripts/verify.sh`（fmt/clippy/测试/bench/perf gate/agg_sim/forge/差分
fuzz/覆盖门禁/ZK e2e/rust-smoke），pre-push 强制；GitHub Actions 三 job（ci/noir/
solidity）为 push 后第二道网。

## 6. 审计冻结清单（外聘审计启动时逐项执行，S-58 立）

冻结 = 把「当前实测态」钉成审计对象，之后到审计结束**只改 docs/audit/**（发现项记录），
不动 contracts/src。清单：

1. **主门禁复跑**：`scripts/verify.sh` 全绿（含步 8b 差分 fuzz 漂移闸 / 8c 覆盖门禁 /
   9b~9f ZK e2e）×2（push 前 + pre-push）。
2. **覆盖门禁复扫**：`bash scripts/coverage_gate.sh` 绿（行/函数 100%、分支 100% −
   BatchSettler 1 条不可达豁免边）。若冻结前临时改码，重跑后数字必须回到本文件 §5
   记录值，否则改 §5 并说明。
3. **slither 复扫**：结果集必须 ⊆ 本文件 §4 + `docs/audit/slither-2026-08-31.md` 的
   已知设计族（零新增真问题），每条与代码内定性注释一一对应。
4. **差分 fixture 漂移闸**：verify.sh 8b 绿（Solidity 镜像与 Rust 生产实现无漂移）。
5. **打 tag**：`git tag -a audit-v1 -m "audit freeze <date>" && git push origin audit-v1`
   ——范围书开头「以 tag audit-v1 为准」的锚点在此刻才成立。
6. **范围书数字核对**：§1 文件清单与 `contracts/src/` 目录实态一致（5 合约）；§5
   测试计数与 `forge test` 实跑一致；§4 已知问题与 TECH_SPEC 诚实边界口径一致。
7. **提交范围书**：本文件 + `docs/audit/` 报告随合同交付给审计方；TECH_SPEC §6.4/§6.5/
   §7 作为业务逻辑说明书附录。

**冻结期纪律**：期间任何 src 改动（哪怕一行注释）= 解冻，回到第 1 步重走全清单。
外聘审计是付费项（预算待批，价位参考见 slither 报告末节），未获预算批准前本清单
**不执行**、tag **不打**——打了 tag 而不送审只会制造「已审计」的假象。
