# Mist 运营手册（S-15 生产化）

面向部署/运维角色的生产拓扑、健康判定、指标口径与告警阈值。
代码契约以 `docs/TECH_SPEC.md` 为唯一事实源；本手册只讲**怎么跑、怎么看、怎么判**。

## 1. 生产拓扑

```text
agent 进程 / 框架         聚合器实例（多实例，热备）          可观测性
┌──────────────┐     ┌───────────────────────────┐    ┌─────────────────────┐
│  mist-sdk│─┐   │  mist-mcp (stdio)      │    │  mist-monitor   │
│  或 MCP 框架 │ └─► │   内嵌 mist-aggregator │◄─┐ │   restore WAL 副本  │
└──────────────┘     │   (生产配置, WAL 落盘)      │  │ │   /metrics  /healthz│
                     └───────────┬───────────────┘  │ └──────────┬──────────┘
                                 │ WAL 副本/多实例     │           │ scrape (Prometheus 语义)
                     ┌───────────▼───────────────┐  │ ┌──────────▼──────────┐
                     │ BatchSettler (链上净额结算) │  │ │  Prometheus → Grafana│
                     │ DSA / RevocationRegistry  │  │ │  mist-dashboard  │
                     └───────────────────────────┘  └─┴─────────────────────┘
                         Base Sepolia → Base 主网
```

- **聚合器**：生产配置 `IngestConfig::production()`（32 账本分片、1M epoch 容量、60s epoch、
  WAL sync 每 10k 笔、单委托 nonce 容量 4096）。WAL 是崩溃恢复边界，必须放在持久盘。
- **monitor**：`restore_from_wal` **只读副本**，**不接热路径**（B8 信条：快照零分配、不碰分片锁）。
  它读到的是 WAL 最后一个持久点，不是实时内存——这是诚实的口径，不是缺陷。
- **链上**：`DSA` / `RevocationRegistry` / `BatchSettler` 由 `contracts/rust-smoke` 的
  `deploy` 二进制部署（dry-run 兜底 → `--live` 需 `MIST_OPERATOR_KEY`）。
- **运营者绑定闸（S-62，TECH_SPEC §6.19）**：网关 bin 三个环境变量**同给同不给**（半装配
  启动即退）：`MIST_RPC_URL`（`http://host:port`，std-only 不收 https）+
  `MIST_DSA_ADDRESS`（DSA 合约 `0x` + 40 hex）+ `MIST_SELF_OPERATOR`（本账本
  运营者地址，须与 BatchSettler 实例的 operator 一致——部署面职责）。绑定写面 =
  owner 对 `DSA.bindOperator(dh, operator)` 发一次性交易（不可改绑；存量委托由 owner
  补绑收窄 fail-open 残余，见 §6.19.5）。绑定读数每委托一次冷 RPC 后进程内缓存
  （不可变语义）；RPC 抖动 = 该笔 `E_BIND_BACKEND` 拒（fail-closed，不进缓存）——
  **同意图重发是安全的**（闸在 `try_commit` 之前，nonce 未消耗、幂等闸不缓存业务拒绝），
  重试属调用方/SDK 装配侧职责（SDK 业务拒绝不自动重试，仅 `E_REV_ROOT` 触发刷新重出）；
  RPC 端点要进部署可用性清单。

## 2. mist-monitor 用法

```bash
# 独立 WAL 检查（脚本探活 / 部署前体检），exit 0 = 全绿
mist-monitor --wal /data/mist.wal --once

# HTTP 服务（默认端口 9100，仅回环绑定）
mist-monitor --wal /data/mist.wal --port 9100
curl http://127.0.0.1:9100/healthz   # JSON，200=ok / 503=degraded
curl http://127.0.0.1:9100/metrics   # Prometheus 文本（v0.0.4 exposition format）

# 多副本热备组（S-39）：--wal 可重复传，一个端点聚合整组（TECH_SPEC §6.12）
mist-monitor --wal /data/replicas/primary.wal --wal /data/replicas/standby.wal --port 9100

# 声誉面（S-65）：追加 BatchSettler 事件派生的只读运营者指标（--settler/--rpc 同给同不给，
# 缺省两参不给 = 声誉序列完全不出现，TECH_SPEC §6.22）
mist-monitor --wal /data/mist.wal --settler 0x<40hex> --rpc http://127.0.0.1:8545 --port 9100
```

WAL 缺失/不可读 → 进程以非零码退出（monitor 不猜测，不伪造健康）。

## 3. 健康判定（/healthz）

| 检查 | 规则 | 不健康的含义 |
|---|---|---|
| `ledger_consistent` | 独立重放 WAL 的 Intent 数 == `accepted_count` | 内存账本与崩溃恢复边界漂移（WAL 写入故障第一信号） |
| `revocation_root_present` | 有撤销则撤销根必须非零 | 撤销未进 Merkle 承诺（聚合器内部不一致） |
| `epoch_backlog` | `pending_sealed ≤ 3` | 结算滞后（长时间不 process_pending，风险集中在 BatchSettler 消费端） |
| `replicas_converged`（仅多副本） | 全副本 `accepted_count` / `revoked_len` / `revocation_root` 三元组相等 **且** `state_digest` 逐字节相等（S-72 两腿，§6.12.1；失配腿见 detail `diverged=`） | `diverged=triple`：账本推进/撤销承诺分歧（备份滞后/复制断档，S-39）；`diverged=digest`（尤其 lag=0 时）：**同计数不同内容** = 账本内容分叉（REG 多注册 / LEDGER 金额 / 窗口内容），比滞后更严重——只报告不裁决，立即接管两副本 WAL 逐域人工比对 |

> `wal_intents` 由 monitor 独立重放 WAL 得到——**不读聚合器内存**，否则 `ledger_consistent`
> 变成自比，失去检查意义。

## 4. /metrics 指标清单

| 指标 | 类型 | 口径 |
|---|---|---|
| `mist_accepted_total` | gauge | 累计接受意图数（== 下一个待分配 seq） |
| `mist_rejected_total` | gauge | **会话**计数（崩溃恢复后从 0 起；幂等 re-ack 不计） |
| `mist_pending_sealed` | gauge | 已密封未消费 epoch 数 |
| `mist_revoked_total` | gauge | 已撤销委托数 |
| `mist_wal_bytes` | gauge | WAL 文件字节数 |
| `mist_uptime_seconds` | gauge | 实例运行时长 |
| `mist_ingest_rate_last_window` | gauge | 最近一次刮取窗口平均速率（增量/时长） |
| `mist_submit_duration_seconds` | histogram | `submit` 全路径 API 延迟（接受/拒绝/re-ack 一律计时；log2 μs 桶 ×32，`le` 累计 + `_sum`/`_count`，TECH_SPEC §6.11） |
| `mist_submit_duration_p99_seconds` | gauge | 预计算 p99（log2 桶**上界**近似；精确分位数用 `_bucket` 跑 `histogram_quantile`） |
| `mist_epoch_capacity` / `mist_ledger_shards` | gauge | 生产拓扑参数 |
| `mist_instance_info` | gauge | 实例标识（label `instance`） |
| `mist_cluster_instances` | gauge | 被监控副本数（`--wal` 个数，S-39 多副本模式） |
| `mist_cluster_accepted_total` | gauge | 副本间 accepted_count **max**（热备副本组同一逻辑账本，最新推进副本；**求和会双计备份副本**） |
| `mist_cluster_replica_lag` | gauge | 副本间 accepted_count max−min（备份滞后笔数，0 = 收敛） |
| `mist_cluster_pending_sealed` | gauge | 副本间最差结算滞后（max，取最差副本） |
| `mist_operator_*`（S-65 声誉面，TECH_SPEC §6.22） | gauge | 仅 `--settler`+`--rpc` 装配时出现：epochs_committed/settled、slash_total、slash_kind_total{kind}、bond_committed/claimed_wei、contract_balance_wei——全部从 BatchSettler 事件 + 余额派生，**不进任何判定面**（决策 E） |
| `mist_operator_chain_read_ok` | gauge | 1 = 本轮链上抓取成功 / 0 = 失败（失败保留上次快照继续渲染，绝不清零——清零会被误读为「罚没归零」） |

**诚实边界**：吞吐是刮取窗口均值，不是 p99；p99 由 S-35 热路径直方图提供（桶上界近似，
会话计数不持久化——崩溃恢复后从 0 起）。直方图埋点为固定桶原子增量 + 两次 `Instant::now()`，
热路径仍零分配（B8 复测口径见 TECH_SPEC §8.2）。Grafana 面板 `monitor/grafana/mist-dashboard.json`
用 `rate(mist_accepted_total[1m])` 看吞吐——因为计数语义在刮取器侧做增量，不误导为 counter。

## 5. 告警阈值建议

| 信号 | 建议阈值 | 处置 |
|---|---|---|
| `mist_uptime_seconds` 下降/重置 | 与上次比对 | 进程重启/崩溃，查 WAL 完整性 |
| `/healthz` 503 | 任一检查降级 | `ledger_consistent` 优先——接管 WAL 核对账本 |
| `mist_pending_sealed` | > 3 | 结算消费端阻塞，尽快 process_pending |
| `mist_rejected_total` 激增 | 环比 | 客户端配置漂移或重放攻击，查错误码分布 |
| `mist_submit_duration_p99_seconds` | > 0.05（B6 目标 50 ms） | 热路径退化（分片争用 / WAL 慢盘 / 验证变贵），对照 `_bucket` 定位量级 |
| `mist_cluster_replica_lag` | > 0（多副本） | 备份副本复制断档/滞后——failover 会丢账本尾部，查副本复制链路 |
| `/healthz` `replicas_converged` degraded 且 detail `diverged=digest`、`lag=0` | 任一次 | **同计数不同内容**（S-72 digest 腿，§6.12.1）：三元组全等但账本内容分叉——复制链路静默写错（比断档更危险：滞后可见、写错不可见），立即停止 failover 并人工比对两副本账本逐域找分叉点 |
| `mist_operator_slash_total` 增长 | 环比 | 运营者被成功欺诈挑战罚没（epoch voided）——最高优先安全事件，对照 `slash_kind_total{kind}` 与链上 `ChallengeSucceeded` 事件核查欺诈证明 |
| `mist_operator_chain_read_ok` | 持续 = 0 | 链上读面失败（RPC 不可得/事件解码失败）——声誉快照停留在旧值；**不拉低 /healthz**（账本健康面与链上读面告警分离，TECH_SPEC §6.22.1 定夺 5），查 monitor `--rpc` 连通性与节点状态 |

## 6. 与 S-15 后续的接缝

- monitor 是 **scrape 语义**的只读视图；热路径直方图/p99 已由 S-35 兑现（TECH_SPEC §6.11），
  多实例集群指标聚合已由 S-39 兑现（TECH_SPEC §6.12：多 `--wal` 热备副本组，集群指标取
  max；独立分片多实例不属此口径，各自单实例 monitor + Prometheus 侧聚合）。
- `deploy --live` 上链（Base Sepolia → 主网）需要真实操作者密钥与 gas，属**外向动作**，
  代码已就绪（dry-run 默认），实际执行等明确指示。

## 7. TLS 反代部署（S-56，TECH_SPEC §6.7 部署拓扑节）

网关**恒明文 HTTP**（std-only，无 TLS 栈），生产必须由反代终结 TLS。拓扑：

```text
公网 :443 (TLS) ──► 反代（终结 TLS）──► 127.0.0.1:9400 mist-gateway（明文）
                                      └► 127.0.0.1:9100 mist-monitor（不进公共反代）
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

委托撤销事件流（§4.6）：链上 `RevocationRegistry.revoke`（owner；事件 `Revoked`）→
**运营者传播进聚合器**（人工：下方端点 / fanout；自动：§8.1 观察面）。人工传播入口 =
网关管理端点 `POST /v1/admin/revocations`（admin key 门面，同 `/v1/admin/tenants`）：

```bash
curl -X POST https://gw.example.com/v1/admin/revocations \
  -H "Authorization: Bearer $MIST_ADMIN_KEY" \
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

**多副本（S-39 副本组）撤销传播（S-59 fanout）**：在**任一副本**（通常主副本）的配置里
声明其余副本，撤销一次调用即达全组——本地先撤销（即时生效），再并行转发到各对端的
同款端点：

```json
{ "listen": "127.0.0.1:9400", "...": "...",
  "revocation_peers": [
    { "url": "http://127.0.0.1:9401", "admin_key": "<peer-b-admin-key>", "timeout_ms": 2000 },
    { "url": "http://127.0.0.1:9402", "admin_key": "<peer-c-admin-key>" }
  ] }
```

响应带逐副本结果（未配置 peers 时该字段不出现，单副本口径不变）：

```json
{"newly_revoked":true,"revocation_root":"<64hex>","revoked_len":1,
 "fanout":[{"peer":"http://127.0.0.1:9401","accepted":true,"newly_revoked":true},
           {"peer":"http://127.0.0.1:9402","accepted":false,"detail":"connect: ..."}]}
```

| `fanout` 结果 | 处置 |
|---|---|
| 全部 `accepted:true` | 完成，走确认两步 |
| 某 peer `accepted:false`（连接/超时/非 200） | **重放同请求**（幂等，`newly_revoked:false` 但 fanout 照常执行 = 补漏重试）直到该 peer `accepted:true`；本地撤销不受影响已生效 |
| 某 peer `detail` 含 `E_DELEG_UNKNOWN` | 对端副本未注册该 dh（副本账本漂移）——先核对副本摄取健康，不要盲目重试 |
| 某 peer 恒 401/404 | 对端 admin key 未配 / 未配置——配置问题，不会自愈 |

未配置 `revocation_peers` 的副本组退回**逐副本人工撤销**：对每个副本的网关各调一次
本端点（副本 `instance` 见 monitor 集群指标）。无论哪种路径，漏调副本都会继续接受
已撤销委托的新意图，直至 `replicas_converged`（撤销根三元组不等）告警暴露——告警是
最后防线不是传播机制。**新意图的 `E_REVOKED` 拒绝即时生效于本进程**；撤销根上链随
下个密封 epoch（≤ 1 epoch）。

### 8.1 链上撤销观察面（S-67，TECH_SPEC §6.24）

配置 `revocation_watch` 节后，网关起旁路线程每 `poll_interval_ms`（缺省 15000）刮一次
`RevocationRegistry.Revoked` 事件（全史区间 `fromBlock: 0x0`），链上撤销自动落本账本
（决策 F：每运营者独立链上监听是 P2 硬前置）——人工传播（上节端点 / fanout）之外的
自动兜底：

```json
{ "listen": "127.0.0.1:9400", "...": "...",
  "revocation_watch": {
    "rpc_url": "http://127.0.0.1:8545",
    "registry_address": "0x<RevocationRegistry-40hex>",
    "poll_interval_ms": 15000
  } }
```

- **三个撤销来源汇于同一入口**（admin API / 对端 fanout / 链上观察），幂等语义统一；
  重复消费由观察面查重（已撤销的 dh 不重复落账）。观察面**不 fanout**——链上事件是
  全组共同事实源，每个副本各自观察同一事件流。
- 启动日志 `revocation_watch: on`；观察线程轮询失败打 stderr 一行（`revocation watch:
  poll failed: ...`）下一轮重试，**不退进程**（admin API / fanout 撤销路径仍可达）；
  静默轮询（无事件无脏日志）不打日志。
- **观察滞后** = 撤销生效延迟 ≤ 轮询间隔 + RPC 延迟（缺省 ~15s + RPC 往返）；观察面
  失灵期间撤销延迟无限延长——`poll failed` 日志连续出现 = 观察面病了，先查 RPC 端点
  与 `registry_address` 配置，撤销兜底退回人工传播（上节）。

**诚实边界**：观察面是尽力而为不是共识——轮询间隔内的撤销在本账本仍可被接受，窗口期
风险由运营者债券罚没兜底（§6.5，kind3 出证见 §6.23）；观察面未装配 / 挂掉 / 漏读 =
「撤销观察缺席」的运营者过失形态（链上可罚）。轮询是全史重扫，生产 RPC 的区块区间
上限（如 10k 块）未做分页——本地/测试链口径，生产量级待数据（TECH_SPEC §6.22.5 同缝）。
管理操作经 TLS 终结点之后执行（§7）；批量撤销 v1 不做（单请求单 dh，逐笔确认根推进）。

## 9. 多运营者多实例部署流程（S-64，TECH_SPEC §6.21）

Phase 2 决策 A（分片模型）：每张委托在授权期绑定唯一运营者（S-62 `DSA.bindOperator`），
各运营者跑完整 v1 栈（ledger / gateway / BatchSettler 实例各一套）。本节是「新增一个
运营者实例」的标准流程，锚定 `OperatorRegistry`（append-only 金额调度 + 运营者名册）。

### 9.1 金额调度（决策 D，§6.17 决策 D / §6.21.1）

- 债券（commit `msg.value`）与挑战押金（`BatchSettler.challengeBond`）的**建议值**由
  `OperatorRegistry.appendSchedule(bond, challengeBond)` 追加（仅 `registrar`）；旧条目
  永不改写、无删除路径，链上全史可审计。
- **不做运行时 setter**：调度只被**未来部署**读取，任何在役 BatchSettler 实例的
  immutable 金额不可被触碰（registrar 触不到在役实例判定面——这是与被否决的 setter
  信任面的本质区别）。
- 零金额构造性拒绝（`ZeroScheduleAmount`）：零债券 = 挑战赔付归零 = 乐观安全归零；
  零押金 = 复活垃圾挑战面。
- 换金额路径 = **追加新调度 + 重部署实例**（新实例注册进名册，旧实例照常在役至退役）。

### 9.2 新运营者实例上线（deploy.rs 全流程）

```bash
cd contracts && forge build
MIST_RPC_URL=<rpc> MIST_OPERATOR_KEY=0x... MIST_BOND=<wei> MIST_CHALLENGE_BOND=<wei>   cargo run --release --manifest-path contracts/rust-smoke/Cargo.toml --bin deploy -- --live
```

部署顺序（脚本自动完成）：DSA(无参) → RevocationRegistry(DSA) → OperatorRegistry
(registrar = 部署方) → `appendSchedule`（初值取 `MIST_BOND` / `MIST_CHALLENGE_BOND`，
缺省 1 ETH / 0.1 ETH）→ BatchSettler(operator, asset, **challengeBond ← currentSchedule()
读数**) → `registerOperator(settler)`。脚本自带两道核对：调度读数与写入值一致 +
部署后 `challengeBond()` 回读与调度读数一致（单一事实源在链上）。

### 9.3 运营者名册（读面与纪律）

- `registerOperator(settler)` 是 **self-registration 绑定实证**：调用者必须是
  `BatchSettler(settler).operator()` 本尊（链上 immutable getter 复核），注册时快照
  `asset` / `challengeBond` 固化值——名册 = 每实例实际金额的公开台账，任何人可与调度
  历史交叉核对。
- 名册 append-only：无移除/停用；同一运营者可注册多个实例（= 重部署换金额路径）。
  退役信号 = 名册条目时间戳之后事件缺失（声誉面从 BatchSettler 事件派生，P2-5）。

**诚实边界（部署面不强制）**：运营者可以跳过注册表、或部署偏离当刻调度的金额——
不被密码学阻止，只被名册快照/缺席公开（选型与验证者据此可查）。registrar 抬价/降额
影响的是后续部署的起点值，全史可审计；金额无下限校验（1 wei 债券合法——下限本身是
又一个不可调常量，靠可见性而非代码挡）。`registry_flow.rs`（verify 步 10）是本节全链
演练：调度 ×2 代 → 双实例各持其部署版本 → 名册快照回读 → 负向组 6 例全拒。
