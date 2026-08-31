# Mist 开发者文档站（S-14c）

Mist 是**机器商务的结算与信任铁轨**：让 AI Agent 之间能互相花钱、互相信任。
本文档站面向开发者，从"5 分钟跑通"到"三种角色各自怎么接"。

```text
┌──────────────────────────────────────────────────────────────┐
│                     Mist 集成全景                          │
│                                                              │
│  agent 进程        框架（LangChain/AutoGen/Eliza…）           │
│  ┌─────────┐        ┌───────────────┐                        │
│  │mist-│  stdio │ mist-mcp  │                        │
│  │  sdk    │ ◄────► │  (6 工具,     │                        │
│  └────▲────┘        │   无任何私钥)  │                        │
│       │             └──────┬────────┘                        │
│       │  验签+执行          │                                │
│       │             ┌──────▼────────┐                        │
│       └────────────►│  聚合器内核    │   WAL 崩溃恢复          │
│                     │  (ingest/预算/ │   seq/幂等/净额结算     │
│                     │   WAL/净额)   │                        │
│                     └──────┬────────┘                        │
│                            │ commitment_root / netting_root  │
│                     ┌──────▼────────┐                        │
│                     │  BatchSettler │  Anvil → Base（S-15）   │
│                     │   (链上净额结算)│                        │
│                     └───────────────┘                        │
│                                                              │
│  vendor（收款方）：凭 verify_receipt 校验回执 → 到期 claim       │
└──────────────────────────────────────────────────────────────┘
```

## 三种角色，三条路

| 你想…… | 你是 | 用 | 入口 |
|---|---|---|---|
| **替 owner 花钱** | agent 进程 | `mist-sdk`（Rust） | [快速上手](quickstart.md) → [集成指南·agent](integration.md#作为-agent代理花钱) |
| **给 agent 暴露支付能力** | agent 框架 | `mist-mcp`（stdio） | [集成指南·框架](integration.md#作为-framework-给-agent-暴露-mist) |
| **收钱的商家** | vendor / 数据·算力市场 | `verify_receipt` + `BatchSettler` | [集成指南·vendor](integration.md#作为-vendor-收款方) |

## 文档地图

| 文档 | 内容 | 对象 |
|---|---|---|
| **[快速上手](quickstart.md)** | 5 分钟跑通：门禁自检 → M1 端到端 demo → 框架闭环 → 第一笔集成 | 所有人 |
| **[集成指南](integration.md)** | 三种角色逐角色 API + 错误码 + 幂等契约 + 诚实边界 | 集成工程师 |
| `docs/TECH_SPEC.md` | **代码契约 v1.0**（规范编码、WAL 格式、门禁、预算表）——一切以它为准 | 核心/集成工程师 |
| `docs/WHITEPAPER.md` | 对外白皮书（英文，引用 PoC 实测） | 对外 |
| `docs/why-no-new-chain.md` | 立场文《为什么机器商务不需要新链》 | 对外 |
| `docs/poc/*.md` | Phase 0 三个 PoC 实测报告（吞吐 488k/s、交付证明、ZK 约束） | 技术评审 |
| `mcp-server/README.md` | MCP 服务器：6 工具 + 错误码 + 框架接入坑 + 决策记录 D1-D6 | 框架接入 |
| `sdk/README.md` | SDK 幂等重试契约 + 传输形态 + 诚实边界 | agent 集成 |
| `docs/ops.md` | 生产拓扑 + 健康判定 + 指标口径 + 告警阈值（S-15）+ TLS 反代部署与排错（S-56） | 部署/运维 |
| `docs/zk-batch-verify-eval.md` | ZK 批验证评估（S-18）：批验证摊薄边界 + 递归聚合路径 + 预算线诚实修订 | 技术评审 |

## 规范与性能信条

- **每笔支付 = 签名意图**：owner 签发 `Delegation`（DSA 授权），agent 对每笔 `SpendIntent`
  签名，聚合器验签 + 强制预算（单笔 / 窗口速率 / 累计上限）+ WAL 落盘。
- **不做新链**：结算在链上**净额**进行（BatchSettler 挑战-担保-净额结算），单笔意图不进链。
- **性能即护城河**：Phase 0 PoC 实测 488,738 笔/s（满核）；M1 demo 单委托 100k 笔
  ~28k 笔/s 顺序提交全绿。每行代码按"要发表 benchmark"的要求写。
- **诚实边界**：ZK 证明的**缺省**路径仍是**占位**（`FormatVerifier` 只查格式与一致性 /
  `PlaceholderProver`）——生产默认不动。真电路两侧已交付（S-40 `BbVerifier` /
  S-43 `NoirProver`），经显式装配开启（网关 `MIST_VERIFY_BACKEND=bb` + SDK
  `SdkClient::with_noir` + `enforce_revocation_root`，TECH_SPEC §6.13/§6.14/§6.15；
  `contracts/rust-smoke/src/bin/noir_demo.rs` 是可运行的装配示例），上层 API 不变。
- **验证者面（P2-1，S-61）**：写者与验证者分离已有最小实证——独立验证者吃「已接受意图
  镜像流」复算账本，检出 commit≠settle 后构造欺诈证明上链挑战
  （`aggregator/src/fraud.rs` + `contracts/rust-smoke/src/bin/verifier_drill.rs` 三幕
  演练，TECH_SPEC §6.18）。诚实边界：验证者**不解决写者单点**（审查/停机/绑合谋），
  只提升「承诺与结算不符」的发现率；纯「承诺根错账」不可挑战（P2-3 撤销根与治理面接管）；
  演练为进程内双实体，不宣称已部署独立验证者网络。
- **绑定面（P2-2，S-62）**：分片多运营者的事前强制层已落地——DSA `dh → operator`
  独立绑定映射（owner 私钥一次性写入不可改绑，不进 delegation_hash preimage）+
  聚合器摄取绑定闸（绑他方 `E_OPERATOR` / 未绑定 fail-open / 读面不可得
  `E_BIND_BACKEND` fail-closed，读数永久缓存）+ 网关 JSON-RPC 读装配
  （`MIST_RPC_URL` + `MIST_DSA_ADDRESS` + `MIST_SELF_OPERATOR` 三者同给
  同不给，TECH_SPEC §6.19）。诚实边界：**存量未绑定委托 fail-open**（决策 B 有意取舍，
  owner 补绑收窄残余）；绑定合谋（owner 故意绑错分片）不在防御内；跨分片双花的密码学
  封堵挂 P2-3 事后欺诈 kind——绑定闸只挡「绑他方的后续意图」，不假装已封闭。
- **共识设计轮（P2-6/L3，S-69）**：砖单最后一项的独立设计轮已产出（TECH_SPEC §6.25，
  纯文档零代码）——问题定夺「共享账本买的是写者活性不是安全性」、共识对象 = WAL、
  摄取语义墙（接受 ≠ 记账 → 裁决进日志）、链上面定夺「QC 公证 + 债券连带 + kind5 等效
  签署」、协议形态定夺乐观复制（BFT 记为替代不开工）、分期砖单 L3-0..3。**实施 blocked**：
  解锁条件 = 审计冻结 v1 + 生产活性痛点数据；唯一例外 L3-0（摄取 / apply 分离可测性）
  不依赖解锁条件。诚实边界：设计轮全部语义改动未经实现验证，容错计数只作量级论证。
- **L3-0 apply 面（S-70，2026-09-01）**：§6.25.3 的主张「账本状态是 WAL 的确定性函数」
  落成可调用面——`aggregator/src/apply.rs` 的 `apply_log`（无 I/O / 时钟 / 网络 / 随机，
  输出 = f(初始状态, 条目序列)，`restore_from_wal` 重构到其上，重放语义逐字节不变）+
  `state_digest` 全键排序账本指纹。property test：N 副本乱序 + 重复投递同一条目多重集 →
  状态根与裁决史逐字节一致；在线摄取 ↔ WAL 重放 digest 等价（TECH_SPEC §6.26）。诚实
  边界：apply 是**记账面不是验证面**（不重验，S-10a 语义）；批内乱序收敛 ≠ 共识安全性
  （跨批流式乱序挂 L3-1）；digest 是**诊断面不是判定面**（无密码学承诺，不替代出证闸）。
- **monitor 收敛指纹升级（S-72，2026-09-01）**：§6.26.1 定夺 6 点名的 L3-3「digest 比对」
  半边提前兑现——`replicas_converged` 从 S-39 三元组（accepted/revoked_len/root，对
  「同计数不同内容」全盲）升级为**两腿**：三元组 ∧ `Aggregator::state_digest()`。digest
  在 restore 后计算一次（静默态语义，monitor 副本无在途写者；窗口域不含 per-process
  `created_at`，跨副本可比）；收敛 detail 逐字节保持 S-39 格式，失配 detail 增
  `diverged=<triple|digest>` + 各副本 digest 前缀；零合约/WAL/热路径改动，单实例
  `/healthz` JSON 不变（TECH_SPEC §6.12.1）。诚实边界：digest 腿是启动时点快照
  （monitor 运行期新推进不捕获）；告警信号非欺诈证据。

## 仓库结构

```
core/          DSA 授权原语 + 预算账本（mist-core）
aggregator/    结算内核：ingest / commitment lattice / WAL / 净额（mist-aggregator）
sdk/           Agent 集成层：authorize / pay / attest + 幂等重试（mist-sdk）
mcp-server/    MCP stdio 服务器：6 工具、keyless、真 ZK 证明直通（mist-mcp）
monitor/       S-15 可观测性：/metrics Prometheus 文本 + /healthz 健康判定（std-only）
bench/         基准基座 + 零分配/确定性门禁 + CI gate（mist-bench）
contracts/     Solidity：DSA / RevocationRegistry / BatchSettler + forge 测试 + rust-smoke
circuits/      Noir ZK 电路（spend_authorization，intent_hash 绑定 + 撤销非成员）
demos/         三框架演示闭环（LangChain / AutoGen / Eliza）+ 跨语言 hash 镜像
poc-delivery/  PoC ③ 交付证明（TLSNotary，独立 workspace）
```

> 代码契约以 `docs/TECH_SPEC.md` 为唯一事实源；进度以 `MASTER_PLAN.md` 为准（仓库外）。
