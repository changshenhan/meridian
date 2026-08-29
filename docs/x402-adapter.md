# x402 结算适配层 — 设计稿 v0（S-30 立项）

> 状态：**立项设计稿**（2026-08-29 拍板立项）；S-30a / S-30b 已实现（2026-08-30），S-30c 待排。实现前先升级进 TECH_SPEC（先改 spec 后改码，S-30b = §6.8）。
> 背景：MASTER_PLAN 计划审读问题 ⑤——x402 竞争窗口缺席。x402（HTTP 402 原生支付，
> Coinbase 主推）正在成为 agent 按请求付费的事实协议层；Meridian 的正确站位是
> **x402 的结算后端**（卖水），不是再造一个付费协议。

## 1. x402 与 Meridian 的咬合点

x402 标准流程：client 请求 → server 回 `402` + `paymentRequirements`（金额/收款人/
资产/网络）→ client 签 EIP-3009 `transferWithAuthorization`（USDC on Base）→
facilitator 验证并逐笔上链结算。

两个结构性痛点正好是 Meridian 的主场：

| x402 痛点 | Meridian 对应能力 |
|---|---|
| 每笔一次链上 `transferWithAuthorization`，微额场景 gas 占比爆表 | 聚合器 10 万笔/秒链下摄取 + epoch 净额上链（**净额压缩数百倍**） |
| 支付额度 = 钱包余额，无委托/预算控制 | DSA：owner 签发预算锁死的委托（单笔/速率/总额/类目/过期），agent 持凭证消费 |

S-28 的 USDC 结算路径（`BatchSettler.asset = USDC`）恰好补上资产侧：商户收的就是
Base USDC，净额指令 `NetInstruction { recipient, amount }` 直接映射。

## 2. 两个集成面（v1 范围）

### 2.1 Meridian 作为 x402 的授权 + 摄取层（主推）

- agent 端：SDK 拦截 `402` → 把 `paymentRequirements` 映射成 `SpendIntent`
  （recipient=merchant 地址、amount、category=域名哈希、memo=x402 请求指纹）→
  走现有 `authorize / pay` 管线 → 拿 `Receipt.seq` 构造 x402 `paymentPayload`
  （自定义 scheme `meridian-v1`）。
- server/facilitator 端：验证 `paymentPayload` = 向 Meridian gateway 查询
  `Receipt`（**新增只读端点** `/v1/receipts/{intent_hash}`，Phase 2 缝，见 §4）→
  accepted 即放行 200。
- 结算：商户作为 `BatchSettler` claimant 按 epoch 领取 USDC 净额——**既有延迟
  claim 语义零改动**。

### 2.2 Meridian 作为 facilitator 的聚合后端（白标卖水面）

- 第三方 x402 facilitator 把逐笔 EIP-3009 验证换成 Meridian 摄取（SaaS/白标），
  审计账本 + WAL 提供对账。这是 MASTER_PLAN 商业模式的直接兑现点。

## 3. 映射表（v1 草案）

| x402 字段 | Meridian 字段 | 备注 |
|---|---|---|
| `payTo` | `intent.recipient` | 20B EVM 地址，Did 兼容 |
| `maxAmountRequired` | `intent.amount` | USDC 6 decimals 直通 |
| `resource` (URL) | `intent.category` | sha256(host+path)；类目白名单可限域 |
| `description` / nonce | `intent.memo` / `spend_nonce` | nonce 语义同 §6.2 |
| `asset`/`network` | 网关部署配置 | v1 仅 Base USDC（主网 `0x8335…2913`） |
| `paymentPayload.scheme = "meridian-v1"` | `IntentEnvelopeDto` JSON | wire 单一来源，S-29 已定 |

## 4. 缺口清单（诚实边界）

1. **只读查询端点**：`/v1/receipts/{intent_hash}` 返回 Receipt（含 seq）——merchant
   侧验证用。**已实现（S-30a）**：内核 `Aggregator::receipt()`（意图索引扩展 seq）+
   gateway `GET /v1/receipts/{hash}`（租户闸共用，404 `E_NOT_FOUND`，0x 前缀宽容）+
   SDK `HttpTransport::receipt()`。**语义边界（诚实）**：命中 = 已接受且**未结算**——
   索引随 settle 按 epoch 修剪、被拒意图不可查，**404 ≠ 未支付**；merchant 验证须在
   epoch 时延内完成（§4.2），终局保证在链上净额。TECH_SPEC §6.7 已落盘。
2. **确认时延**：Meridian 是 epoch 级终局（10s 密封 + 链上承诺），x402 merchant 预期
   准即时。v1 方案：**Receipt 即受理凭证**（运营者债券兜底 + 幂等重发可复验），商户
   风险敞口 ≤ 1 epoch——这与"债券/罚没"安全模型一致，需在白标合同里写明。
3. **EIP-3009 兼容模式**：存量 x402 client 不会说 `meridian-v1`。可选桥：facilitator
   接受标准 EIP-3009 payload 后转投 Meridian 摄取（ merchant 无感）——实现成本第二优先。
4. **规范上游**：x402 规范仍在演进，scheme 扩展注册路径未定——设计稿按"自定义 scheme"
   起步，跟进上游后再标准化。

## 5. 排期建议

1. S-30a：`/v1/receipts` 只读端点 + gateway 测试（小，~半天砖）。**已完成（2026-08-30）**——
   测试：aggregator `receipt_lookup_hits_before_settle_and_none_after` + gateway
   `handle_receipt_lookup_gate_and_hash_validation` / `e2e_receipt_lookup_x402_merchant_flow`。
2. S-30b：SDK 侧 x402 fetch 拦截（`X402Client` wrapper，schema `meridian-v1`）。**已完成
   （2026-08-30，TECH_SPEC §6.8）**：`sdk::x402` 模块——402 体解析（`accepts[]` camelCase、
   金额恒字符串原子单位、`payTo` 0x 20B）、字段映射（payTo→recipient /
   maxAmountRequired→amount / resource→category=sha256(host+path) query 不绑定 /
   memo=sha256(resource) 指纹 / maxTimeoutSeconds→expires_at 缺省 60s）、`SdkClient::pay`
   管线直通（幂等重试 §6.6 不变）、`X-PAYMENT` 重放（base64url 无 padding 手写实现，
   RFC 4648 向量锁定）。接缝：`Fetch` trait 可注入 HTTPS 客户端；内置 `HttpFetch` 仅
   `http://`（手写 TcpStream，真 socket 测试覆盖）。**诚实边界**：类别白名单在账本
   （TEMPORARY 管线）不强制——强制点 = ZK 电路断言 4（§5.2）与 Contract 模式链上，
   SDK 测试已固化此边界。测试：sdk 单测 5 + 集成 7（e2e 402→pay→重放全链路真记账 +
   `Aggregator::receipt` 回执可查）。
3. S-30c：facilitator 参考实现（axum/tokio 允许——merchant 侧不在内核热路径）。
4. EIP-3009 桥视生态牵引再排。
