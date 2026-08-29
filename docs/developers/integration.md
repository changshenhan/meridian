# 集成指南（三种角色）

Meridian 的集成面按**角色**分三条路，各自独立可接。本文按角色给 API、契约与坑。

```text
   owner                    agent                   framework
（私钥持有者）          （替 owner 花钱）        （LangChain/AutoGen/Eliza）
    │  签发 Delegation       │                       │
    ▼                        ▼                       ▼
 授权原语  ◄──────────────  SDK / MCP pay           MCP 5 工具（keyless）
                            │                       │
                            ▼                       ▼
                    聚合器内核（验签/预算/WAL/净额）  BatchSettler（链上净额）
                            │                       │
                            ▼                       ▼
                    回执 {seq, intent_hash}      vendor claim（收钱）
```

---

## 作为 Agent（替 owner 花钱）

**用 `meridian-sdk`（Rust）**。同步内核，无 async runtime；核心三点：

```rust
use meridian_sdk::{SdkClient, PayParams};

let mut client = SdkClient::in_process(owner_key, agent_key, limits)?;
client.authorize()?;                       // 注册 DSA（本地限额校验，错误码透传）
let receipt = client.pay(&PayParams { recipient, amount, category, spend_nonce, .. })?;
let cred = client.attest(&transport_pubkey)?;   // 双钥绑定凭据
```

### 幂等重试契约（"断线重试不产生双花"）

1. **固定 nonce**：每笔逻辑支付取固定 `spend_nonce`，整个重试周期不复用、不推进；
   只有聚合器返回**定局**（accepted 或永久拒绝）后，下一笔才拿新 nonce。
2. **只重试传输错误**：`SdkError::Transport` 触发重试（指数退避 + 封顶）；
   `SdkError::Meridian`（业务拒绝，错误码透传）**永不重试**。
3. **聚合器侧幂等**（S-12）：同一 `(spend_nonce, intent_hash)` 重发返回先前结果——
   accepted → 原 `seq`（不重复分配/记账）；rejected → 原原因。此闸口在过期检查之前 →
   已过期但曾被接受的意图重发仍 re-ack，绝不误判失败去换 nonce 重发（那才是双花来源）。

验证场景（`sdk/tests/e2e.rs`，真实聚合器 + 真实 WAL + 真实密码学，零 mock）：
回执丢失 → 重发 → re-ack 原 `seq 0`、`accepted_count == 1`、`total_spent == 42` 恰好一次；
超限意图回执丢失 → 重发 → 原错误码（不透传成成功）、nonce 不复活。

### 传输形态

`Transport` trait 抽象「聚合器连接」：S-12 提供 `InProcessAggregator`（进程内，测试与
单进程嵌入用）。**网络 Transport 是 S-15 接缝**——独立 agent 进程对接真实聚合器服务时
实现同一 trait 即可，`pay()` 重试与幂等逻辑不变。见 `sdk/README.md`。

### 诚实边界

- **证明占位**：`PlaceholderProver` + 聚合器 `FormatVerifier`（TEMPORARY）。真实 S-09
  电路 prover 实现 core `SpendProver`，经 `SdkClient::with_prover` 接入——`pay()` 与
  重试逻辑不用改。
- **NonceManager 不持久化**：进程崩溃后跨重启的 nonce 恢复经 `SdkClient::sync_nonce`
  （S-31：查询网关 `GET /v1/nonce/{delegation_hash}`，把本地计数推进到 `max(已接受) + 1`
  安全下界）再继续支付；不恢复直接 `pay()` 撞已消耗 nonce（`E_NONCE` 拒绝——不双花，
  但不可用）。重试窗口内重启以先前定局 re-ack，不双花。

---

## 作为 Framework（给 agent 暴露 Meridian）

**用 `meridian-mcp`（stdio）**。MCP 服务器**内嵌真实聚合器内核**（WAL + 幂等 + seq +
预算强制），**keyless**：服务器无任何私钥，owner secp256k1 与 agent Ed25519 签名都在
框架侧，服务器只验签 + 执行。

```sh
cargo build -p meridian-mcp --release
MERIDIAN_WAL_DIR=demos/.wal target/release/meridian-mcp     # 默认 ./meridian.wal
```

任何支持 stdio MCP 的框架都能挂成工具。自述名 `meridian`，版本 `0.2.0`。

### 5 工具

| 工具 | 入参 | 返回 | 校验 |
|---|---|---|---|
| `authorize` | 委托全字段 + owner secp256k1 签名 + owner/agent 公钥 | `AuthorizeReceipt` | owner 签名有效；字段自洽；防换钥重绑；幂等 |
| `pay` | intent 全字段 + agent Ed25519 签名 | `PayReceipt {intent_hash, seq, spend_nonce}` | 委托已注册；agent 签名；幂等 re-ack；预算；WAL |
| `balance` | `delegation_hash` | `BalanceReceipt {total_spent, total_cap, remaining}` | 委托已注册 |
| `attest` | `delegation_hash, pk_x, pk_y, binding` | `AttestReceipt {pk_x, pk_y, agent_commit, binding}` | 绑定 agent 对 binding 消息验签 |
| `verify_receipt` | `delegation_hash, spend_nonce, intent_hash` | `VerifyReceiptResult {accepted, seq}` | 只读；幂等表确认 |

错误统一回 `{"ok":false,"error":"E_..."}`。完整错误码表见 `mcp-server/README.md`；
代码在 `meridian_core::error::Error::as_code()`。

### 框架适配坑（已踩平）

- **langchain-mcp-adapters 0.1.0**：`get_tools()` 每工具每次调用新建 MCP 会话（→ 新
  子进程 → 新聚合器，authorize 与 pay 落到不同内核 → `E_DELEG_UNKNOWN`）。必须
  `client.session("meridian")` + `load_mcp_tools(session)` 共享**单一**会话。
- **autogen-ext 0.7.5**：同样须显式传共享 `ClientSession`（`stdio_client` +
  `ClientSession`）。另需两个兼容层：(1) `FORMAT_MAPPING` 补
  `uint8/16/32/64 → int`（rmcp/schemars 的 `format:"uint64"` autogen 不认识）；
  (2) `_extract_field_type` 折叠 `Option<String>` 生成的 `["string","null"]` 联合。
  `run_json` 返回内容块 list，需拼 `text` 再 JSON 解析。
- **eliza（@noble/curves）**：2.x 移除 `./secp256k1` 子路径并重构签名 API → 固定
  **1.x 线**（curves 1.9.7 / hashes 1.8.0）。

详见 `mcp-server/README.md`（含决策记录 D1-D5：为什么 keyless / 扁平 hex 入参 / stdio）。

---

## 作为 Vendor（收款方）

**核心：验证回执，绝不信任口说。** agent 说"我付过了"不算——凭 `verify_receipt`
拿到 `accepted: true` + `seq` 才算。

```jsonc
// agent 侧 pay 拿到：                        // vendor 侧核对：
{
  "intent_hash": "0x…",
  "seq": 42,
  "spend_nonce": 7
}
// → 调 verify_receipt：
//   { "delegation_hash": "0x…", "spend_nonce": 7, "intent_hash": "0x…" }
// → { "accepted": true, "seq": 42 }          // 幂等表确认，infallible
```

`verify_receipt` 是 **infallible** 的第 5 只读工具：拒绝与未知同报 `accepted=false`。
这是演示 vendor 能做诚实校验的关键——不校验回执，任何人都能伪造"已支付"。

### 到账：BatchSettler 净额结算

单笔意图**不进链**。聚合器按 epoch 汇总出**净额**（100 收款人 → 每人一个净额行），
链上 `BatchSettler` 结算：

```text
commit(BOND + commitment_root) → settle(Σnet + netting_root)
  → 挑战窗（任何人可对错账发起挑战，成功罚没运营者债券）
  → 收款人 claim(epoch, idx) 收到精确净额（原生 ETH）
```

vendor 要做的：**等到挑战窗过** → `claim(epoch, idx)` 收钱。挑战失败的账不会赖掉——
挑战成功则债券罚没 + settlementFunded 退款，错误账行被标记不可 claim（forge 53 测试
全覆盖，含欺诈挑战路径）。

### 信任模型一句话

- 收到的 `seq` = 聚合器幂等表里的账本序号（全网唯一）。
- 结算可挑战 → 运营者做假账要押上债券。
- 净额根 / 承诺根可链下重算交叉验证（M1 demo Section C 演示同根）。

---

## 错误码速查（`meridian_core::error::Error::as_code()`）

| 码 | 含义 |
|---|---|
| `E_DELEG_EXPIRED` | 委托过期 |
| `E_DELEG_SIG` | owner secp256k1 签名无效 / 高位 s |
| `E_DELEG_UNKNOWN` | 委托未注册（未授权先 pay） |
| `E_INTENT_SIG` | agent Ed25519 签名无效 |
| `E_INTENT_EXPIRED` | 意图过期 |
| `E_INTENT_HASH` | intent_hash 与信封不符 |
| `E_NONCE` | 跨意图复用 spend_nonce |
| `E_BUDGET_PER_SPEND` / `E_BUDGET_RATE` / `E_BUDGET_TOTAL` | 超单笔 / 超窗口速率 / 超累计总上限 |
| `E_REVOKED` | 委托已撤销 |
| `E_CATEGORY` | 类别不在授权集 |
| `E_ORDERING` | agent DID 与委托不符 |
| `E_ATTEST_BIND` | 换钥重绑 / binding 签名无效 |
