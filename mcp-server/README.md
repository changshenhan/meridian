# meridian-mcp — S-07 MCP 探针

**最小 MCP server**：`authorize`（注册委托）+ `pay`（模拟支付），让主流 agent 框架
今天就能调"花钱"。

## 运行

```bash
# 作为 MCP server（stdio）启动
cargo run -p meridian-mcp

# 或在 MCP 客户端配置里指向构建产物：
#   cargo build -p meridian-mcp --release
#   然后配置 command = "target/release/meridian-mcp"
```

任何支持 stdio MCP 的 agent 框架（Claude Desktop / Claude Code / 自定义 client）
都能把它挂成工具。服务器自述名 `meridian`，能力 `tools`。

## 工具

| 工具 | 入参 | 返回 | 校验 |
|---|---|---|---|
| `authorize` | 委托全字段 + owner secp256k1 签名 + owner/agent 公钥（hex） | 回执（delegation_hash、预算上限） | owner 签名有效；委托字段自洽；绑定 agent 身份；防换钥重绑 |
| `pay` | intent 全字段 + agent Ed25519 签名（hex） | 回执（payment_id、累计支出、剩余额度） | 委托已注册；agent 签名；intent 未过期；防重放；预算规则 1-6 |

错误统一回 `{"ok":false,"error":"E_DELEG_SIG"}` 形式的工具错误（`is_error=true`），
错误码见 `TECH_SPEC §11` / `meridian_core::error::Error::as_code()`。

## 决策记录（S-07）

### D1. 为什么用官方 Rust SDK（rmcp）而非手写 JSON-RPC
官方 SDK 承担协议胶水（initialize/negotiation/JSON-RPC framing/schema 生成），
我们只写业务逻辑。这符合 MASTER_PLAN 的一贯取向：**规范冻结前用被广泛实现的
协议栈**，把差异化留给性能层（S-11+）。

### D2. 为什么工具入参是扁平 hex 字符串，而不是嵌套 core 类型
rmcp 的 `#[tool]` 宏用 schemars 生成工具 JSON Schema，要求入参类型实现
`JsonSchema`；core 的 `Delegation`/`SpendIntent` 只派生 serde。hex 字符串
对 agent 框架最友好，也与 core `Signature64` 的 serde 表示一致。解析失败返回
工具错误，不产生协议错误。

### D3. TEMPORARY：`pay()` 无 ZK 证明（S-07 验收口径）
`pay()` 的授权 = agent Ed25519 验签 + 防重放 + 预算记账。**不含 ZK 证明**——
这是 S-07 的有意边界，与 MASTER_PLAN 验收"模拟支付闭环"一致。真实 circuit 证明
（spend_authorization，S-05 已编译验证约束数）在 **S-09** 接入同一条路径：
`state.rs::pay` 在验签后预留了 `verify_proof` 挂载点。

### D4. 身份模型：注册时绑定 agent 传输身份公钥
`authorize` 把 delegation_hash 绑定到调用方提供的 Ed25519 公钥；`pay` 只用
这把公钥验 agent 签名。换钥重绑被 `E_ATTEST_BIND` 拒绝。这是"双钥绑定"（S-05）
的探针级形态：真实 attestation 绑定在电路外做一次（Noir 内是 BabyJubJub 域），
S-07 先用 Ed25519 占位，S-09 换正式绑定。

### D5. 状态在进程内（单进程聚合器）
委托注册表、nonce 防重放、预算账本都在本进程内存。这是 S-07 最小形态；
分布式/持久化/多 writer 属于后续（S-10+，DSA 授权层）。账本复用 core 的
`ShardedLedger`（分片并发，与 S-05 验收一致）。

### D6. 无资金无牌照约束下，性能即护城河
本探针不碰真实资金/结算，只做授权与预算。真实结算走 S-06 合约 + 后续结算层。
性能从 S-11 起成为主线（core 已把 intent 验签压到 ~35µs，见 bench）。

## 测试

```bash
cargo test -p meridian-mcp        # 11 单元 + 4 集成（官方 rmcp client 走真实协议）
cargo clippy -p meridian-mcp --all-targets -- -D warnings
```

集成测试 `tests/mcp_flow.rs` 用官方 rmcp client 通过 `tokio::io::duplex` 连
MeridianServer，走完整 MCP JSON-RPC：authorize → pay 闭环 + 重放/伪造签名/
超预算/未注册全部拒绝。**密钥与签名全部用 core 原语现场构造，绝无 mock。**

## 布局

```
mcp-server/
├── src/
│   ├── lib.rs        # MeridianServer 结构 + 状态挂载
│   ├── state.rs      # 聚合器：授权/验签/防重放/预算（纯逻辑，无 MCP 类型）
│   ├── tools.rs      # #[tool_router]/#[tool_handler] 宏 + 入参类型 + hex 解码
│   └── main.rs       # stdio 入口
└── tests/mcp_flow.rs # 验收集成测试（真实 MCP client）
```
