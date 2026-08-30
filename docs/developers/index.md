# Meridian 开发者文档站（S-14c）

Meridian 是**机器商务的结算与信任铁轨**：让 AI Agent 之间能互相花钱、互相信任。
本文档站面向开发者，从"5 分钟跑通"到"三种角色各自怎么接"。

```text
┌──────────────────────────────────────────────────────────────┐
│                     Meridian 集成全景                          │
│                                                              │
│  agent 进程        框架（LangChain/AutoGen/Eliza…）           │
│  ┌─────────┐        ┌───────────────┐                        │
│  │meridian-│  stdio │ meridian-mcp  │                        │
│  │  sdk    │ ◄────► │  (5 工具,     │                        │
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
| **替 owner 花钱** | agent 进程 | `meridian-sdk`（Rust） | [快速上手](quickstart.md) → [集成指南·agent](integration.md#作为-agent代理花钱) |
| **给 agent 暴露支付能力** | agent 框架 | `meridian-mcp`（stdio） | [集成指南·框架](integration.md#作为-framework-给-agent-暴露-meridian) |
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
| `mcp-server/README.md` | MCP 服务器：5 工具 + 错误码 + 框架接入坑 + 决策记录 D1-D5 | 框架接入 |
| `sdk/README.md` | SDK 幂等重试契约 + 传输形态 + 诚实边界 | agent 集成 |
| `docs/ops.md` | 生产拓扑 + 健康判定 + 指标口径 + 告警阈值（S-15） | 部署/运维 |
| `docs/zk-batch-verify-eval.md` | ZK 批验证评估（S-18）：批验证摊薄边界 + 递归聚合路径 + 预算线诚实修订 | 技术评审 |

## 规范与性能信条

- **每笔支付 = 签名意图**：owner 签发 `Delegation`（DSA 授权），agent 对每笔 `SpendIntent`
  签名，聚合器验签 + 强制预算（单笔 / 窗口速率 / 累计上限）+ WAL 落盘。
- **不做新链**：结算在链上**净额**进行（BatchSettler 挑战-担保-净额结算），单笔意图不进链。
- **性能即护城河**：Phase 0 PoC 实测 488,738 笔/s（满核）；M1 demo 单委托 100k 笔
  ~28k 笔/s 顺序提交全绿。每行代码按"要发表 benchmark"的要求写。
- **诚实边界**：ZK 证明的**缺省**路径仍是**占位**（`FormatVerifier` 只查格式与一致性 /
  `PlaceholderProver`）——生产默认不动。真电路两侧已交付（S-40 `BbVerifier` /
  S-43 `NoirProver`），经显式装配开启（网关 `MERIDIAN_VERIFY_BACKEND=bb` + SDK
  `SdkClient::with_noir` + `enforce_revocation_root`，TECH_SPEC §6.13/§6.14/§6.15；
  `contracts/rust-smoke/src/bin/noir_demo.rs` 是可运行的装配示例），上层 API 不变。

## 仓库结构

```
core/          DSA 授权原语 + 预算账本（meridian-core）
aggregator/    结算内核：ingest / commitment lattice / WAL / 净额（meridian-aggregator）
sdk/           Agent 集成层：authorize / pay / attest + 幂等重试（meridian-sdk）
mcp-server/    MCP stdio 服务器：5 工具、keyless（meridian-mcp）
monitor/       S-15 可观测性：/metrics Prometheus 文本 + /healthz 健康判定（std-only）
bench/         基准基座 + 零分配/确定性门禁 + CI gate（meridian-bench）
contracts/     Solidity：DSA / RevocationRegistry / BatchSettler + forge 测试 + rust-smoke
circuits/      Noir ZK 电路（spend_authorization，intent_hash 绑定 + 撤销非成员）
demos/         三框架演示闭环（LangChain / AutoGen / Eliza）+ 跨语言 hash 镜像
poc-delivery/  PoC ③ 交付证明（TLSNotary，独立 workspace）
```

> 代码契约以 `docs/TECH_SPEC.md` 为唯一事实源；进度以 `MASTER_PLAN.md` 为准（仓库外）。
