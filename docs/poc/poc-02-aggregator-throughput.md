# PoC ② 聚合器吞吐原型 — 报告

> **Phase 0 合闸 PoC ②**（蓝图 Phase 0 交付物："聚合器 10 万笔/秒吞吐原型"）。
> 状态：**已跑通**。验收目标 ≥ 100,000 笔/秒 → 实测 **488,738 笔/秒**（32 worker）。
> 日期：2026-08-16。代码：`bench/src/ingest.rs` + `bench/src/bin/poc_aggregator.rs`。

## 结论

单聚合器 ingest 快路径（**验签 → 并发 nonce 去重 → 分片预算记账**）在多核上**大幅越过
10 万笔/秒**。吞吐随核心数近乎线性放大，瓶颈是单线程 Ed25519 验签（~45k/s），
而验签是无状态的——并行化是聚合器架构放大的来源。

| 配置 | 吞吐（笔/秒） |
|---|---|
| 单线程基线 | ~47,600 |
| 2 worker | ~90,800 |
| 4 worker | ~177,000 |
| 8 worker | ~307,000 |
| 16 worker | ~387,000 |
| **32 worker（满核）** | **~488,700** |

验收目标 ≥ 100,000 → **PASS**，余量 ~4.9×。

## 口径与可复现

- **固定输入**：128 代理 × 2,000 意图/代理 = 256,000 笔，密钥由固定 seed 派生，**零随机**。
- **完整管线**：intent↔委托绑定 → agent Ed25519 验签（`verify_intent`）→ nonce 防重放
  （64 片 `Mutex<HashSet>`）→ 预算检查 + 记账（core `ShardedLedger`，64 片）。
- **无跨次污染**：每次 run 用全新 `ShardedIngest`（nonce 集 / 账本不残留）。
- **复现**：`cargo run --release -p meridian-bench --bin poc_aggregator -- --check 100000`。
- **机器**：32 核 Windows x86_64（基准平台，TECH_SPEC §8.1 口径）。

## 测量说明（诚实边界）

- **TEMPORARY 无 ZK**：与 S-07 同口径，`pay()` 的授权 = 验签 + 防重放 + 预算。S-09 在
  `ingest::process` 插入 `verify_proof`。真实聚合器会多一次证明验证与承诺格排序，
  最终数字以 S-10 生产内核实测为准。
- **原型形态**：nonce 分片是原型（独立于账本分片）；生产内核（S-10）会把 nonce 去重
  并入账本分片或 WAL，并加 commitment lattice 与崩溃恢复。
- **噪声**：同机多次运行单线程在 ~45k–48k 间浮动（±6%）。门禁用固定批次一次性测量
  （`aggregator_ingest_ops`，baseline ~43k），CI 用 15% 阈值抓灾难性回归。

## 对规范 v1.0 的意义

- 蓝图 L3 吞吐目标（≥10 万笔/秒）**在 Phase 0 原型上已验证可达成**，且余量接近 5×。
- "性能即护城河"从 S-11 起成为主线；本 PoC 是 S-10 生产内核的架构背书。

## 文件

- `bench/src/ingest.rs` — `ShardedIngest` 原型 + 固定输入 fixture + 单/多线程测量。
- `bench/src/bin/poc_aggregator.rs` — 吞吐报告 + `--check <ops>` 验收模式。
- `bench/benches/aggregator_bench.rs` — criterion 单线程管线基准。
- `bench/src/bin/gate.rs` — `aggregator_ingest_ops` 指标（CI 回归跟踪）。
