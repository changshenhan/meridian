# Meridian PoC ③ — 交付证明（TLSNotary）

> S-08b / Phase 0 合闸 PoC ③。蓝图交付物："交付证明（TLSNotary 最小原型）"。
> 独立 workspace，不挂主仓库（tlsn 拉 mpz 大框架，编译重，不进 CI 常规 workspace）。

## 这是什么

**场景**：Agent A 把东西交付给 Agent B 的 TLS 端点。B 说"没收到"，A 怎么证明"给了"？

**答案**：TLSNotary 2-party MPC-TLS。交付发生时，仲裁方（verifier）与 A（prover）
共同参与对 B 端点的 TLS 会话，在线见证这笔交付，拿到**经选择性披露的 transcript**：

- 披露：请求方法/路径、订单号、交付载荷、服务器回执 ack（`200 OK`）；
- 隐藏：交付令牌（secret）——A 证明交付真实发生，而不泄露密钥。

## 运行

```bash
cd poc-delivery
cargo run --release
```

首次编译拉 tlsn / mpz 框架，较久（几分钟）。之后增量编译快。

## 验证输出

程序跑完断言三件事（`src/proof.rs::run_delivery_proof`）：

1. 发送侧 transcript 含 `POST /deliver` 与订单号 `ORD-001` —— 东西真发出去了；
2. 交付令牌对 verifier 隐藏（不在披露字节中）—— 选择性披露成立；
3. 接收侧含 `200 OK` 与服务器 ack —— 服务器真回了。

## 代码地图

| 文件 | 职责 |
|---|---|
| `src/certs.rs` | rcgen 现场生成 CA + 叶证书（本地 TLS 端点的信任根） |
| `src/server.rs` | 交付端点：模拟收款方 B 的 TLS endpoint，`POST /deliver` → ack |
| `src/proof.rs` | MPC-TLS prover + verifier + 见证断言（核心） |
| `src/main.rs` | 编排：证书 → 端点 → 见证 → 打印 |

## 生产形态（诚实边界）

- 本 PoC 是 **2-party 在线见证**：verifier 必须在场。生产形态（S-18 起）是
  **3-party attestation**：notary 为 transcript 签 `NotaryCommitment`，证明**离线可验证**。
- TLS 会话的每一字节都在 MPC 内联合模拟，tlsn 保证 prover 无法篡改 transcript。
- 交付端点由本仓库自签证书模拟；生产形态连接真实收款方域名，走公开 PKI。
