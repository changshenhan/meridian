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

# 多副本热备组（S-39）：--wal 可重复传，一个端点聚合整组（TECH_SPEC §6.12）
meridian-monitor --wal /data/replicas/primary.wal --wal /data/replicas/standby.wal --port 9100
```

WAL 缺失/不可读 → 进程以非零码退出（monitor 不猜测，不伪造健康）。

## 3. 健康判定（/healthz）

| 检查 | 规则 | 不健康的含义 |
|---|---|---|
| `ledger_consistent` | 独立重放 WAL 的 Intent 数 == `accepted_count` | 内存账本与崩溃恢复边界漂移（WAL 写入故障第一信号） |
| `revocation_root_present` | 有撤销则撤销根必须非零 | 撤销未进 Merkle 承诺（聚合器内部不一致） |
| `epoch_backlog` | `pending_sealed ≤ 3` | 结算滞后（长时间不 process_pending，风险集中在 BatchSettler 消费端） |
| `replicas_converged`（仅多副本） | 全副本 `accepted_count` / `revoked_len` / `revocation_root` 相等 | 副本间账本推进或撤销承诺分歧（备份滞后/复制断档，S-39）——只报告不裁决，接管 WAL 人工核对 |

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
| `meridian_submit_duration_seconds` | histogram | `submit` 全路径 API 延迟（接受/拒绝/re-ack 一律计时；log2 μs 桶 ×32，`le` 累计 + `_sum`/`_count`，TECH_SPEC §6.11） |
| `meridian_submit_duration_p99_seconds` | gauge | 预计算 p99（log2 桶**上界**近似；精确分位数用 `_bucket` 跑 `histogram_quantile`） |
| `meridian_epoch_capacity` / `meridian_ledger_shards` | gauge | 生产拓扑参数 |
| `meridian_instance_info` | gauge | 实例标识（label `instance`） |
| `meridian_cluster_instances` | gauge | 被监控副本数（`--wal` 个数，S-39 多副本模式） |
| `meridian_cluster_accepted_total` | gauge | 副本间 accepted_count **max**（热备副本组同一逻辑账本，最新推进副本；**求和会双计备份副本**） |
| `meridian_cluster_replica_lag` | gauge | 副本间 accepted_count max−min（备份滞后笔数，0 = 收敛） |
| `meridian_cluster_pending_sealed` | gauge | 副本间最差结算滞后（max，取最差副本） |

**诚实边界**：吞吐是刮取窗口均值，不是 p99；p99 由 S-35 热路径直方图提供（桶上界近似，
会话计数不持久化——崩溃恢复后从 0 起）。直方图埋点为固定桶原子增量 + 两次 `Instant::now()`，
热路径仍零分配（B8 复测口径见 TECH_SPEC §8.2）。Grafana 面板 `monitor/grafana/meridian-dashboard.json`
用 `rate(meridian_accepted_total[1m])` 看吞吐——因为计数语义在刮取器侧做增量，不误导为 counter。

## 5. 告警阈值建议

| 信号 | 建议阈值 | 处置 |
|---|---|---|
| `meridian_uptime_seconds` 下降/重置 | 与上次比对 | 进程重启/崩溃，查 WAL 完整性 |
| `/healthz` 503 | 任一检查降级 | `ledger_consistent` 优先——接管 WAL 核对账本 |
| `meridian_pending_sealed` | > 3 | 结算消费端阻塞，尽快 process_pending |
| `meridian_rejected_total` 激增 | 环比 | 客户端配置漂移或重放攻击，查错误码分布 |
| `meridian_submit_duration_p99_seconds` | > 0.05（B6 目标 50 ms） | 热路径退化（分片争用 / WAL 慢盘 / 验证变贵），对照 `_bucket` 定位量级 |
| `meridian_cluster_replica_lag` | > 0（多副本） | 备份副本复制断档/滞后——failover 会丢账本尾部，查副本复制链路 |

## 6. 与 S-15 后续的接缝

- monitor 是 **scrape 语义**的只读视图；热路径直方图/p99 已由 S-35 兑现（TECH_SPEC §6.11），
  多实例集群指标聚合已由 S-39 兑现（TECH_SPEC §6.12：多 `--wal` 热备副本组，集群指标取
  max；独立分片多实例不属此口径，各自单实例 monitor + Prometheus 侧聚合）。
- `deploy --live` 上链（Base Sepolia → 主网）需要真实操作者密钥与 gas，属**外向动作**，
  代码已就绪（dry-run 默认），实际执行等明确指示。

## 7. TLS 反代部署（S-56，TECH_SPEC §6.7 部署拓扑节）

网关**恒明文 HTTP**（std-only，无 TLS 栈），生产必须由反代终结 TLS。拓扑：

```text
公网 :443 (TLS) ──► 反代（终结 TLS）──► 127.0.0.1:9400 meridian-gateway（明文）
                                      └► 127.0.0.1:9100 meridian-monitor（不进公共反代）
```

- 网关 `listen` 只绑回环；`0.0.0.0` 直暴露 = 无 TLS、无反代超时缓冲，属部署事故。
- 反代 → 网关的明文跳必须同机回环或专用内网（同一信任域）。
- **反代不是认证边界**：网关只认 `Authorization: Bearer`，不读 `X-Forwarded-For` 等
  代理注入头（伪造不改变判定，gateway 测试钉死）。反代侧按源 IP 限流可加，是额外
  防护层而非网关语义。

### 7.1 Caddy（最短路径，证书自动管理）

```caddy
gw.example.com {
    # 网关只讲 HTTP/1.1 且不支持 chunked 请求——原样透传，不做请求体改写
    reverse_proxy 127.0.0.1:9400 {
        flush_interval -1
        transport http {
            versions h1
        }
    }
    # 管理面纵深：即使 admin key 泄露，公网也摸不到端点
    @admin path /v1/admin/tenants
    respond @admin 403
}
# 管理操作走内网专用 listener（运维跳板机）：
# http://10.0.0.5:9441 { reverse_proxy 127.0.0.1:9400 }
```

### 7.2 nginx

```nginx
server {
    listen 443 ssl;
    server_name gw.example.com;
    ssl_certificate     /etc/nginx/certs/gw.crt;
    ssl_certificate_key /etc/nginx/certs/gw.key;

    # ≥ 网关 max_body_bytes(64 KiB) + 头部余量；代理先 413 抢答是常见误配
    client_max_body_size 128k;
    # > 网关 read_timeout_ms(5s)：bb 模式 /v1/intents 含真证明验证，代理先超时
    # 会把网关还在算的请求断成 5xx
    proxy_read_timeout   30s;
    proxy_connect_timeout 5s;

    location / {
        proxy_pass http://127.0.0.1:9400;
        proxy_http_version 1.1;              # 网关无 HTTP/2
        proxy_set_header Connection "";      # 让网关决定 keep-alive
        # 不要 proxy_request_buffering off / chunked 改写——网关拒 chunked 请求
    }

    # 管理面 ACL（纵深防御，非认证替代）——覆盖全部 /v1/admin/* 路径
    # （S-54 /v1/admin/tenants + S-57 /v1/admin/revocations）
    location /v1/admin/ {
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://127.0.0.1:9400;
        proxy_http_version 1.1;
    }
}
```

### 7.3 部署清单（首次上线逐项勾）

1. 网关配置 `listen` 确认回环；`admin_key` 已配置（不配置 = 管理端点不存在，S-54）。
2. 反代证书/域名就绪；网关经**域名**冒烟：`GET /healthz` 200。
3. 反代 body 上限 ≥ 网关 `max_body_bytes`；读超时 > 网关 `read_timeout_ms`。
4. `POST /v1/intents` 关闭代理层透明重试（nginx 无此行为；其它代理需确认）。
5. `/v1/admin/*`（S-54 租户表 + S-57 撤销面）反代层 ACL 生效：公网侧打该路径应
   403/404，内网跳板可通。
6. monitor 只回环，Prometheus 从内网刮取 `127.0.0.1:9100/metrics`（或独立内网反代）。
7. 用真实租户 key 走一次完整 `authorize → pay`（quickstart 链路）确认 TLS 链路不破坏
   线格式（bearer 头原样到达网关）。

### 7.4 排错映射（症状 → 病灶）

| 症状 | 病灶 |
|---|---|
| 合法信封拿 413 但网关日志无记录 | 反代 body 上限 < 64 KiB，代理先 413 抢答 |
| `POST /v1/intents` 偶发 5xx/504，网关侧无对应错误码 | 代理读超时 < 网关处理时长（bb 模式真证明验证），先断连接 |
| 请求被 400 `E_MALFORMED`、消息含 chunked | 反代把请求改写成 chunked（网关不支持） |
| 429 频度远超单租户配额 | 代理层对非幂等 POST 做了重试放大打点，或多 SDK 共用同 key |
| 公网可打 `/v1/admin/*`（租户表 / 撤销面） | 反代 ACL 缺失——admin key 是唯一凭据时纵深为 0 |
| SDK 报连接断开但网关无错 | 反代 `Connection` 头改写与网关 keep-alive 判定冲突（nginx 需 `proxy_set_header Connection ""`） |

**诚实边界**：本节示例未经参考机实跑验证（本机无 nginx/Caddy）——逐条对照的是网关
已实测语义（body 上限 / 读超时 / chunked 拒绝 / keep-alive / 代理头非信任，均有测试
锚定）；首次上线按 §7.3 清单在目标环境实测。无 mTLS；网关不校验 `Host` 头。

## 8. 运营撤销流程（S-57，TECH_SPEC §6.7 撤销面）

委托撤销事件流（§4.6）：链上 `DSA.revoke`（owner）→ **运营者传播进聚合器**。传播入口 =
网关管理端点 `POST /v1/admin/revocations`（admin key 门面，同 `/v1/admin/tenants`）：

```bash
curl -X POST https://gw.example.com/v1/admin/revocations \
  -H "Authorization: Bearer $MERIDIAN_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"delegation_hash":"<64hex>"}'
# 200 {"newly_revoked":true,"revocation_root":"<64hex>","revoked_len":1}
```

| 响应 | 含义 | 处置 |
|---|---|---|
| `200 newly_revoked:true` | 新撤销生效，`revocation_root` = 撤销后当刻根 | 记录根值，走下方确认两步 |
| `200 newly_revoked:false` | 该委托此前已撤销（幂等重放，根不变） | 无需处置 |
| `400 E_DELEG_UNKNOWN` | 聚合器注册表无此 dh | **先核对 dh**（手滑 dh 会白扰在途 witness）——若链上确已注册而聚合器没有，说明该委托注册事件未达本副本 |
| `401 / 404` | admin key 错 / 未配置 | 配置问题，与 §7.3 清单项 1 对齐 |

**确认两步**（撤销是否真生效）：

1. `GET /v1/revocation-witness/<dh>`（租户 key）→ `404 E_REVOKED` = 已入撤销集；
2. 拿另一张未撤销委托查 witness，`root` 应等于撤销响应里的 `revocation_root`（同一棵树）。

**多副本（S-39 副本组）逐副本撤销**：副本组无跨副本复制，每个副本的撤销集独立——
对**每个**副本的网关各调一次本端点（副本 `instance` 见 monitor 集群指标）。漏调副本会
继续接受已撤销委托的新意图，直至 `replicas_converged`（撤销根三元组不等）告警暴露。
**新意图的 `E_REVOKED` 拒绝即时生效于本进程**；撤销根上链随下个密封 epoch（≤ 1 epoch）。

**诚实边界**：链上 `RevocationRegistry.revoke` 不会自动进聚合器（v1 无链上监听器），
链上撤销 → 聚合器撤销之间是运营者人工传播，窗口期风险由运营者债券罚没兜底（§6.5）；
管理操作经 TLS 终结点之后执行（§7）；批量撤销 v1 不做（单请求单 dh，逐笔确认根推进）。
