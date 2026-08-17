# meridian-mcp — S-13 MCP 正式版

**MCP stdio 服务器**：内嵌**真实聚合器内核**（WAL + 幂等 re-ack + seq + 预算强制），
向主流 agent 框架暴露 5 个工具——`authorize` / `pay` / `balance` / `attest` /
`verify_receipt`。**服务器无任何私钥**：owner secp256k1 与 agent Ed25519 签名都在
框架侧完成，服务器只验签 + 执行。

## 运行

```bash
cargo build -p meridian-mcp --release

# WAL 目录优先级：env MERIDIAN_WAL_DIR（目录下 meridian.wal）> CLI 首参（文件路径）>
# ./meridian.wal。父目录不存在时自动创建。
MERIDIAN_WAL_DIR=demos/.wal target/release/meridian-mcp
```

任何支持 stdio MCP 的 agent 框架都能把它挂成工具。服务器自述名 `meridian`，
版本 `0.2.0`，能力 `tools`。

## 工具

| 工具 | 入参 | 返回 | 校验 |
|---|---|---|---|
| `authorize` | 委托全字段 + owner secp256k1 签名 + owner/agent 公钥（hex） | `AuthorizeReceipt` | owner 签名有效；委托字段自洽；绑定 agent 身份；防换钥重绑；幂等（同委托同 agent 重发返回既有回执） |
| `pay` | intent 全字段 + agent Ed25519 签名（hex） | `PayReceipt {intent_hash, seq, spend_nonce}` | 委托已注册；agent 签名；幂等 re-ack；预算规则；WAL 落盘 |
| `balance` | `delegation_hash` | `BalanceReceipt {delegation_hash, total_spent, total_cap, remaining}` | 委托已注册 |
| `attest` | `delegation_hash, pk_x, pk_y, binding` | `AttestReceipt {delegation_hash, pk_x, pk_y, agent_commit, binding}` | authorize 时绑定的 agent Ed25519 对 binding 消息验签 |
| `verify_receipt` | `delegation_hash, spend_nonce, intent_hash` | `VerifyReceiptResult {delegation_hash, spend_nonce, intent_hash, accepted, seq}` | 只读；聚合器幂等表确认 |

错误统一回 `{"ok":false,"error":"E_..."}` 形式的工具错误（`is_error=true`）。错误码
见 `meridian_core::error::Error::as_code()`：

| 码 | 含义 |
|---|---|
| `E_DELEG_EXPIRED` | 委托过期 |
| `E_DELEG_SIG` | owner secp256k1 签名无效 / 高位 s |
| `E_DELEG_UNKNOWN` | 委托未注册（未授权先 pay） |
| `E_INTENT_SIG` | agent Ed25519 签名无效 |
| `E_INTENT_EXPIRED` | 意图过期 |
| `E_INTENT_HASH` | intent_hash 与信封不符 |
| `E_NONCE` | 跨意图复用 spend_nonce |
| `E_BUDGET_PER_SPEND` | 超单笔上限 |
| `E_BUDGET_RATE` | 超窗口速率 |
| `E_BUDGET_TOTAL` | 超累计总上限 |
| `E_REVOKED` | 委托已撤销 |
| `E_CATEGORY` | 类别不在授权集 |
| `E_ORDERING` | agent DID 与委托不符 |
| `E_ATTEST_BIND` | 换钥重绑 / binding 签名无效 |

`verify_receipt` 是 **infallible** 的第 5 只读工具：拒绝与未知同报 `accepted=false`。
这是演示 vendor 能做诚实校验的关键——不校验回执，任何人都能伪造"已支付"。

## 框架接入（S-13b 演示闭环）

`demos/` 下三个框架脚本跑**同一闭环**：`authorize`（owner secp256k1 签 delegation）
→ `pay`（agent Ed25519 签 intent，付 vendor DID）→ `balance`（确认额度滚动）→
`verify_receipt`（确认 accepted:true + seq）→ **脚本内置 mock vendor** 凭回执授予
API 积分 + 返回模拟数据。每个 demo 内置自检：本地重算的 `delegation_hash` /
`intent_hash` 与服务器回执逐字节对得上（Python coincurve/ed25519 与 Node @noble
跨语言镜像 `core/src/dsa.rs` 规范布局）。

```bash
cargo build -p meridian-mcp --release
cd demos
PYTHONIOENCODING=utf-8 .venv/Scripts/python.exe langchain_demo.py
PYTHONIOENCODING=utf-8 .venv/Scripts/python.exe autogen_demo.py
cd eliza && node eliza_client.mjs
```

**框架适配坑（已踩平，代码注释同步）**：
- **langchain-mcp-adapters 0.1.0**：`get_tools()` 的每个工具**每次调用都新建一个 MCP
  会话**（→ 新子进程 → 新聚合器，authorize 与 pay 落到不同内核，`E_DELEG_UNKNOWN`）。
  必须 `client.session("meridian")` + `load_mcp_tools(session)` 共享**单一**会话。
- **autogen-ext 0.7.5**：`mcp_server_tools` 不显式传 `session` 同样每调用新建会话；
  须 `stdio_client` + `ClientSession` 建共享会话传入 factory。另需两个兼容层：
  (1) `FORMAT_MAPPING` 补 `uint8/16/32/64 → int`（rmcp/schemars 的 `format:"uint64"`
  等 autogen 不认识）；(2) `_extract_field_type` 折叠 rmcp `Option<String>` 生成的
  `"type":["string","null"]` 联合（list 不可哈希）。`run_json` 返回内容块 list，需
  拼 `text` 再 JSON 解析。
- **eliza（@noble/curves）**：2.x 移除 `./secp256k1` 子路径并重构签名 API，固定
  **1.x 线**（curves 1.9.7 / hashes 1.8.0）。`character.json`（官方
  `@elizaos/plugin-mcp` 配置面）按本机绝对路径自动生成，不入库。

## 诚实边界

1. **占位证明服务器侧（TEMPORARY）**：`pay` 由服务器用占位证明构造信封，真实
   `FormatVerifier` 只查 proof 非空 + public_inputs↔intent 一致性。真 S-09 电路
   prover 插 `SpendVerifier` 同缝，`pay` 不改。
2. **WAL 本步只追加、不恢复**（restore_from_wal 后续）：每 boot `Aggregator::new`
   重建状态。重启后 EAttestBind 靠 `Aggregator::registered` 兜底（authorize 同时查
   注册表）；客户端重发语义按 S-12（同意图重发 re-ack、跨意图 E_NONCE），首笔
   accepted 的 seq 以 `verify_receipt` 为准。
3. **`balance` 的 total_cap 来自 authorize 内存表**（非聚合器）；total_spent 来自
   聚合器。重启后 balance 需重新 authorize。
4. **agent-DID 与委托不符 → `E_ORDERING`**（原探针 `E_INTENT_HASH`）。

## 正式版 vs 探针（S-07）

| 维度 | S-07 探针 | S-13 正式版 |
|---|---|---|
| 状态层 | 手写 Mutex<HashMap> + ShardedLedger + payment_counter | **真实 `Aggregator` 内核**（WAL + 幂等 + seq + 预算） |
| pay 回执 | `{payment_id, total_spent, remaining}` | `{intent_hash, seq, spend_nonce}`（幂等 re-ack：同意图重发返回原 seq） |
| 工具数 | 2（authorize/pay） | 5（+ balance / attest / verify_receipt） |
| 错误码 | 未授权 pay → `E_DELEG_EXPIRED` | 未授权 pay → **`E_DELEG_UNKNOWN`**（委托已过期 ≠ 从未注册） |
| 幂等 | 无（重放即拒） | S-12 幂等闸口：re-ack / E_NONCE |

## 决策记录

### D1. 为什么用官方 Rust SDK（rmcp）而非手写 JSON-RPC
官方 SDK 承担协议胶水（initialize/negotiation/JSON-RPC framing/schema 生成），我们只
写业务逻辑。规范冻结前用被广泛实现的协议栈，把差异化留给性能层。

### D2. 为什么工具入参是扁平 hex 字符串，而不是嵌套 core 类型
`#[tool]` 宏用 schemars 生成工具 JSON Schema，要求入参实现 `JsonSchema`；core 的
`Delegation`/`SpendIntent` 只派生 serde。hex 对 agent 框架最友好，也与 core
`Signature64` 的 serde 表示一致。解析失败返回工具错误，不产生协议错误。

### D3. 为什么服务器无任何私钥（keyless）
owner 与 agent 私钥都在框架侧，签名外部完成；服务器只验签 + 执行。MCP 服务器是
无信任边界的外围，私钥进服务器 = 扩大攻击面且违背双钥分离。`SdkClient` 因此不用在
服务器侧（authorize/pay 需要私钥）。

### D4. 身份模型：注册时绑定 agent 传输身份公钥
`authorize` 把 delegation_hash 绑定到调用方提供的 Ed25519 公钥；`pay` 只用这把公钥
验 agent 签名。换钥重绑被 `E_ATTEST_BIND` 拒绝。`attest` 复用 core `attestation.rs`：
binding 消息 = `MERIDIAN-BINDING-v1\0 || x_le || y_le`，`agent_commit = sha256(x_le||y_le)`。

### D5. stdio 单进程（S-13 用户拍板）
MCP 服务器内嵌真实聚合器（WAL），框架经 stdio 连各自实例。网络 Transport + 独立
聚合器服务推迟到 S-15（TECH_SPEC §6.6 记接缝）。

## 测试

```bash
cargo test -p meridian-mcp        # 单元 + 9 集成（真实聚合器 + 临时 WAL + rmcp duplex）
cargo clippy -p meridian-mcp --all-targets -- -D warnings
```

集成测试 `tests/mcp_flow.rs` 用官方 rmcp client 通过 `tokio::io::duplex` 连
MeridianServer，走完整 MCP JSON-RPC：authorize→pay 闭环、幂等 re-ack、伪造签名、
超预算、未注册、verify_receipt、attest 篡改全部覆盖。**密钥与签名全部用 core 原语
现场构造，绝无 mock。**

## 布局

```
mcp-server/
├── src/
│   ├── lib.rs        # MeridianServer::new(Arc<Aggregator>) + ServerHandler
│   ├── state.rs      # 薄 keyless 层：验签 + 挂真实聚合器 + 5 工具回执
│   ├── tools.rs      # #[tool_router]/#[tool_handler] + 入参类型 + hex 解码
│   └── main.rs       # stdio 入口（WAL 路径优先级 + 聚合器接线）
└── tests/mcp_flow.rs # 9 个验收集成测试（真实 MCP client + 临时 WAL）
```
