# Meridian

Agent 经济基础设施层 —— 机器商务的结算与信任铁轨。

Meridian 做"AI Agent 之间怎么互相花钱、互相信任"的标准 + 参考实现 + 基础设施：
**DSA 授权原语**（Delegated Spend Authority）+ **结算聚合器**。代码以最顶级性能为标准，每一行按"要发表 benchmark"的要求写。

## 文档

| 文件 | 层级 |
|---|---|
| `docs/TECH_SPEC.md` | 代码契约（v1.0，Phase 0 定稿） |
| `docs/WHITEPAPER.md` | 对外白皮书（英文，引用 PoC 实测） |
| `docs/why-no-new-chain.md` | 立场文《为什么机器商务不需要新链》 |
| `docs/poc/*.md` | Phase 0 三个 PoC 实测报告 |

## Phase 0 PoC（已全绿）

| PoC | 内容 | 结果 | 报告 |
|---|---|---|---|
| ① ZK 授权凭证 | `spend_authorization` 电路 | 约束 6880 ACIR + 1289 Brillig | TECH_SPEC §5.5 |
| ② 聚合器吞吐 | 验签→nonce→预算，满核 | **488,738 笔/s**（目标 ≥10 万，4.9×） | `docs/poc/poc-02-aggregator-throughput.md` |
| ③ 交付证明 | TLSNotary MPC-TLS 选择性披露 | 四条断言 PASS | `docs/poc/poc-03-delivery-proof.md` |

## Workspace

```
core/          DSA 授权原语 + 预算账本（meridian-core）
bench/         基准基座 + 零分配门禁 + CI gate（meridian-bench）
poc-delivery/  PoC ③ 交付证明（独立 workspace：tlsn 拉 mpz 大图，不进主 workspace）
```

## 命令

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
# 性能基座
cargo run -p meridian-bench --bin gate -- --record          # 记录 baseline
cargo run -p meridian-bench --bin gate                       # 与 baseline 比较，回归 >1% 退出码 1
cargo bench -p meridian-bench --no-run                        # criterion 基准编译
# 吞吐验收
cargo run -p meridian-bench --bin poc_aggregator -- --check 100000
# 交付证明复现（首次编译拉 tlsn/mpz 框架，较久）
cd poc-delivery && cargo run --release
```

## 许可

Apache-2.0。第三方依赖许可证见 `THIRD_PARTY.md`。
