# Meridian

Agent 经济基础设施层 —— 机器商务的结算与信任铁轨。

Meridian 做"AI Agent 之间怎么互相花钱、互相信任"的标准 + 参考实现 + 基础设施：
**DSA 授权原语**（Delegated Spend Authority）+ **结算聚合器**。代码以最顶级性能为标准，每一行按"要发表 benchmark"的要求写。

## 文档

| 文件 | 层级 |
|---|---|
| **`docs/developers/`** | **开发者文档站（S-14c）：index / 快速上手 / 三角色集成指南** |
| `docs/TECH_SPEC.md` | 代码契约（v1.0，Phase 0 定稿） |
| `docs/WHITEPAPER.md` | 对外白皮书（英文，引用 PoC 实测） |
| `docs/why-no-new-chain.md` | 立场文《为什么机器商务不需要新链》 |
| `docs/poc/*.md` | Phase 0 三个 PoC 实测报告 |

新手上路：`docs/developers/quickstart.md`（5 分钟跑通 M1 demo + 框架闭环）。
三种角色怎么接：`docs/developers/integration.md`（agent / framework / vendor）。

## Phase 0 PoC（已全绿）

| PoC | 内容 | 结果 | 报告 |
|---|---|---|---|
| ① ZK 授权凭证 | `spend_authorization` 电路 | 约束 6880 ACIR + 1289 Brillig | TECH_SPEC §5.5 |
| ② 聚合器吞吐 | 验签→nonce→预算，满核 | **488,738 笔/s**（目标 ≥10 万，4.9×） | `docs/poc/poc-02-aggregator-throughput.md` |
| ③ 交付证明 | TLSNotary MPC-TLS 选择性披露 | 四条断言 PASS | `docs/poc/poc-03-delivery-proof.md` |

## Workspace

```
core/          DSA 授权原语 + 预算账本（meridian-core）
aggregator/    结算内核：ingest / commitment lattice / WAL / 净额（meridian-aggregator）
gateway/       S-29 网络 ingest 网关：多租户 Bearer + 每租户令牌桶，std-only HTTP/1.1（meridian-gateway）
sdk/           Agent 集成层：authorize / pay / attest + 幂等重试 + x402 fetch 拦截（S-30b）（meridian-sdk）
facilitator/   S-30c x402 merchant 参考实现：网关回执验证，fail-closed，std-only HTTP/1.1（meridian-facilitator）
mcp-server/    MCP stdio 服务器：5 工具、keyless（meridian-mcp）
monitor/       S-15 可观测性：/metrics Prometheus 文本 + /healthz 健康判定（std-only）
bench/         基准基座 + 零分配门禁 + CI gate（meridian-bench）
contracts/     Solidity：DSA / RevocationRegistry / BatchSettler + rust-smoke（独立 workspace）
circuits/      Noir ZK 电路（intent_hash 绑定 + 撤销非成员）
demos/         三框架演示闭环（LangChain / AutoGen / Eliza）
poc-delivery/  PoC ③ 交付证明（独立 workspace：tlsn 拉 mpz 大图，不进主 workspace）
```

## 命令

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
# 全量门禁（10 步，pre-push 钩子同款）
bash scripts/verify.sh
# M1 端到端 demo（10 万笔 → 净额结算，Anvil 全绿；需 foundry）
cd contracts/rust-smoke && cargo run --release --bin m1_demo
# 监控（S-15）：健康检查 + Prometheus 指标端点
cargo run -p meridian-monitor --bin meridian-monitor -- --wal <path> --once        # 一次快照
cargo run -p meridian-monitor --bin meridian-monitor -- --wal <path> --port 9100   # HTTP 服务
# 网络 ingest 网关（S-29）：POST /v1/authorize、/v1/intents + GET /v1/receipts/{hash}（S-30a）+ /healthz
cargo run -p meridian-gateway --bin meridian-gateway -- gateway.json
# 性能基座
cargo run -p meridian-bench --bin gate -- --record          # 记录 baseline（3 整轮取中位）
cargo run -p meridian-bench --bin gate                       # 与 baseline 比较，疑似回归自动复测
cargo bench -p meridian-bench --no-run                        # criterion 基准编译
# 吞吐验收
cargo run -p meridian-bench --bin poc_aggregator -- --check 100000
# v0.1 release 工装（门禁 → 构建 → dist 装配 + sha256；暂不公开）
bash scripts/release.sh
# 交付证明复现（首次编译拉 tlsn/mpz 框架，较久）
cd poc-delivery && cargo run --release
```

## 许可

Elastic-2.0。第三方依赖许可证见 `THIRD_PARTY.md`。
