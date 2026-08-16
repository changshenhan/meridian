# PoC ③ 交付证明（TLSNotary）— 报告

> **Phase 0 合闸 PoC ③**（蓝图 Phase 0 交付物："交付证明（TLSNotary 最小原型）"）。
> 状态：**已跑通**。日期：2026-08-16。代码：`poc-delivery/`（独立 workspace）。
> 复现：`cd poc-delivery && cargo run --release`。

## 结论

**PASS**。第三方（verifier）与交付方（prover）通过 2-party MPC-TLS **在线见证**一笔对
收款方 TLS 端点的交付，拿到经选择性披露的 transcript：订单号、交付载荷、服务器回执
ack 全部可见，**交付令牌对 verifier 隐藏**（`\0` 占位）。"对方说没收到"→"我有证据
证明给了"在 Phase 0 原型上闭环。

## 场景

Agent A 把订单 `ORD-001` 交付给 Agent B 的 TLS 端点 `https://delivery.meridian.test/deliver`。
A 手里有交付令牌（secret）。仲裁方 C 想要证据——既证明交付真实发生，又不让 A 泄露令牌。

## 见证结果（实测）

### 发送侧 transcript（verifier 可见，令牌已隐藏）

```
POST https://delivery.meridian.test:53598/deliver HTTP/1.1
host: delivery.meridian.test
connection: close
x-order-id: ORD-001
x-recipient: did:agent:b
x-delivery-token: [30 个 \0]
content-length: 88

{"order_id":"ORD-001","payload_hash":"c0ffee","recipient":"did:agent:b","ts":1700000000}
```

### 接收侧 transcript（服务器交付回执，完全披露）

```
HTTP/1.1 200 OK
content-type: application/json
connection: close
content-length: 298

{"ack":"{\"order_id\":\"ORD-001\",\"recipient\":\"did:agent:b\",\"payload_hash\":
\"6e02c8db0bf60f8e5bc6b8ed604c86e77d7a74e801a8842d515841a38e9ecc28\",
\"delivery_ack\":\"22d0dbb310f0f54d372e2228afacd06248ba90f100f6787c8d1016b9d084825e\",
\"received\":true,\"ts\":1700000000}","body_len":88,"ok":true}
```

## 断言（验收）

| # | 断言 | 结果 |
|---|---|---|
| 1 | 发送侧含 `POST` + `/deliver` + 订单号 `ORD-001`（东西真发出去了） | **PASS** |
| 2 | 交付令牌对 verifier 隐藏（不在披露字节中） | **PASS** |
| 3 | 接收侧含 `200 OK` + 服务器 `delivery_ack`（服务器真回了） | **PASS** |
| 4 | 服务器身份 = `delivery.meridian.test`（证书链由 prover 信任根核验） | **PASS** |

## 技术要点

- **MPC-TLS**：prover 与 verifier 共同模拟与收款方端点的 TLS 会话，TLS 密钥两方共享，
  transcript 的每一字节都在两方手中——prover 无法单方篡改交付记录。tlsn 版本
  `v0.1.0-alpha.15`（git 锁 tag，未上 crates.io）。
- **选择性披露**：`ProveConfig` 声明披露范围——除令牌位置外全部 `reveal_sent` +
  全部 `reveal_recv`；`PartialTranscript::sent_unsafe()` 把未披露位置置 `\0`。
- **本地证书**：rcgen 现场生成 CA + 叶证书（`delivery.meridian.test`），CA 作
  prover/verifier 的 RootCertStore 信任根；交付端点由 tokio-rustls 承载。
- **身份核验**：verifier 断言服务器名 = 交付域名（`server_identity()` 披露 + 断言）。

## 诚实边界

- **2-party 在线见证**：verifier 必须在场。生产形态（S-18 起）为 **3-party
  attestation**：notary 为 transcript 签 `NotaryCommitment`，证明离线可验证、可跨
  TEE/子网存证。概念同源，代码路径不浪费。
- **交付端点自签**：生产形态连真实收款方域名，走公开 PKI（由收款方证书与域名背书）。
- **Rustls 双 provider**：依赖图同时启 aws-lc-rs（tlsn）与 ring，需显式
  `install_default()`（main.rs 已注释）。

## 对规范 v1.0 的意义

- 蓝图 L4 交付证明在 Phase 0 原型上**跑通**：机器商务的"交付可证"从概念变成代码。
- 与 PoC ①（ZK 授权）拼合，S-08 三个 PoC 全绿——Phase 0 合闸所需的实证基础齐了。
- 披露粒度、非对称性（A 证交付、B 给 ack）直接进入规范 v1.0 的交付证据语义。

## 文件

- `poc-delivery/Cargo.toml` — 独立 workspace（tlsn+mpz 大图，不进主 workspace）。
- `poc-delivery/src/certs.rs` — rcgen 本地 CA + 叶证书。
- `poc-delivery/src/server.rs` — 交付端点（`POST /deliver` → ack）。
- `poc-delivery/src/proof.rs` — MPC-TLS prover + verifier + 见证断言（核心）。
- `poc-delivery/src/main.rs` — 编排入口。
