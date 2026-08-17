# Meridian 运营手册（S-15 生产化）

面向部署/运维角色的生产拓扑、健康判定、指标口径与告警阈值。
代码契约以 `docs/TECH_SPEC.md` 为唯一事实源；本手册只讲**怎么跑、怎么看、怎么判**。

## 1. 生产拓扑

```text
agent 进程 / 框架         聚合器实例（多实例，热备）          可观测性
┌──────────────┐     ┌───────────────────────────┐    ┌─────────────────────┐
│  meridian-sdk│─┐   │  meridian-mcp (stdio)      │    │  meridian-monitor   │
│  或 MCP 框架 │ └─► │   内嵌 meridian-aggregator │◄─┐ │   restore WAL 副本  │
└──────────────┘     │   (生产配置, WAL 落盘)      │  │ │   /metrics  /healthz│
                     └───────────┬───────────────┘  │ └──────────┬──────────┘
                                 │ WAL 副本/多实例     │           │ scrape (Prometheus 语义)
                     ┌───────────▼───────────────┐  │ ┌──────────▼──────────┐
                     │ BatchSettler (链上净额结算) │  │ │  Prometheus → Grafana│
                     │ DSA / RevocationRegistry  │  │ │  meridian-dashboard  │
                     └───────────────────────────┘  └─┴─────────────────────┘
                         Base Sepolia → Base 主网
```

- **聚合器**：生产配置 `IngestConfig::production()`（32 账本分片、1M epoch 容量、60s epoch、
  WAL sync 每 10k 笔、单委托 nonce 容量 4096）。WAL 是崩溃恢复边界，必须放在持久盘。
- **monitor**：`restore_from_wal` **只读副本**，**不接热路径**（B8 信条：快照零分配、不碰分片锁）。
  它读到的是 WAL 最后一个持久点，不是实时内存——这是诚实的口径，不是缺陷。
- **链上**：`DSA` / `RevocationRegistry` / `BatchSettler` 由 `contracts/rust-smoke` 的
  `deploy` 二进制部署（dry-run 兜底 → `--live` 需 `MERIDIAN_OPERATOR_KEY`）。

## 2. meridian-monitor 用法

```bash
# 独立 WAL 检查（脚本探活 / 部署前体检），exit 0 = 全绿
meridian-monitor --wal /data/meridian.wal --once

# HTTP 服务（默认端口 9100，仅回环绑定）
meridian-monitor --wal /data/meridian.wal --port 9100
curl http://127.0.0.1:9100/healthz   # JSON，200=ok / 503=degraded
curl http://127.0.0.1:9100/metrics   # Prometheus 文本（v0.0.4 exposition format）
```

WAL 缺失/不可读 → 进程以非零码退出（monitor 不猜测，不伪造健康）。

## 3. 健康判定（/healthz）

| 检查 | 规则 | 不健康的含义 |
|---|---|---|
| `ledger_consistent` | 独立重放 WAL 的 Intent 数 == `accepted_count` | 内存账本与崩溃恢复边界漂移（WAL 写入故障第一信号） |
| `revocation_root_present` | 有撤销则撤销根必须非零 | 撤销未进 Merkle 承诺（聚合器内部不一致） |
| `epoch_backlog` | `pending_sealed ≤ 3` | 结算滞后（长时间不 process_pending，风险集中在 BatchSettler 消费端） |

> `wal_intents` 由 monitor 独立重放 WAL 得到——**不读聚合器内存**，否则 `ledger_consistent`
> 变成自比，失去检查意义。

## 4. /metrics 指标清单

| 指标 | 类型 | 口径 |
|---|---|---|
| `meridian_accepted_total` | gauge | 累计接受意图数（== 下一个待分配 seq） |
| `meridian_rejected_total` | gauge | **会话**计数（崩溃恢复后从 0 起；幂等 re-ack 不计） |
| `meridian_pending_sealed` | gauge | 已密封未消费 epoch 数 |
| `meridian_revoked_total` | gauge | 已撤销委托数 |
| `meridian_wal_bytes` | gauge | WAL 文件字节数 |
| `meridian_uptime_seconds` | gauge | 实例运行时长 |
| `meridian_ingest_rate_last_window` | gauge | 最近一次刮取窗口平均速率（增量/时长） |
| `meridian_epoch_capacity` / `meridian_ledger_shards` | gauge | 生产拓扑参数 |
| `meridian_instance_info` | gauge | 实例标识（label `instance`） |

**诚实边界**：吞吐是刮取窗口均值，**不是 p99**（p99 需热路径直方图，会碰 B8 零分配底线，
后续按需加、先测影响）。`rejected` 不持久化。Grafana 面板 `monitor/grafana/meridian-dashboard.json`
用 `rate(meridian_accepted_total[1m])` 看吞吐——因为计数语义在刮取器侧做增量，不误导为 counter。

## 5. 告警阈值建议

| 信号 | 建议阈值 | 处置 |
|---|---|---|
| `meridian_uptime_seconds` 下降/重置 | 与上次比对 | 进程重启/崩溃，查 WAL 完整性 |
| `/healthz` 503 | 任一检查降级 | `ledger_consistent` 优先——接管 WAL 核对账本 |
| `meridian_pending_sealed` | > 3 | 结算消费端阻塞，尽快 process_pending |
| `meridian_rejected_total` 激增 | 环比 | 客户端配置漂移或重放攻击，查错误码分布 |

## 6. 与 S-15 后续的接缝

- monitor 是 **scrape 语义**的只读视图；真热路径直方图/p99、多实例集群指标聚合是后续项。
- `deploy --live` 上链（Base Sepolia → 主网）需要真实操作者密钥与 gas，属**外向动作**，
  代码已就绪（dry-run 默认），实际执行等明确指示。
