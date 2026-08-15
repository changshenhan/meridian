# Meridian

Agent 经济基础设施层 —— 机器商务的结算与信任铁轨。

Meridian 做"AI Agent 之间怎么互相花钱、互相信任"的标准 + 参考实现 + 基础设施：
**DSA 授权原语**（Delegated Spend Authority）+ **结算聚合器**。代码以最顶级性能为标准，每一行按"要发表 benchmark"的要求写。

## 文档（三层绑定）

| 文件 | 层级 |
|---|---|
| `../Meridian_架构蓝图.md` | 战略 |
| `../TECH_SPEC.md` | 代码契约 |
| `../MASTER_PLAN.md` | 总执行计划（单一事实源） |

## Workspace

```
core/     DSA 授权原语 + 预算账本（meridian-core）
bench/    基准基座 + 零分配门禁 + CI gate（meridian-bench）
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
```

## 许可

Apache-2.0。第三方依赖许可证见 `THIRD_PARTY.md`。
