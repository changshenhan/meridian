# x402 结算适配层 — 设计稿 v0（S-30 立项）

> 状态：**立项设计稿**（2026-08-29 拍板立项）；S-30a / S-30b / S-30c 已实现（2026-08-30）。实现前先升级进 TECH_SPEC（先改 spec 后改码，S-30b = §6.8，S-30c = §6.9）。
> 背景：MASTER_PLAN 计划审读问题 ⑤——x402 竞争窗口缺席。x402（HTTP 402 原生支付，
> Coinbase 主推）正在成为 agent 按请求付费的事实协议层；Mist 的正确站位是
> **x402 的结算后端**（卖水），不是再造一个付费协议。

## 1. x402 与 Mist 的咬合点

x402 标准流程：client 请求 → server 回 `402` + `paymentRequirements`（金额/收款人/
资产/网络）→ client 签 EIP-3009 `transferWithAuthorization`（USDC on Base）→
facilitator 验证并逐笔上链结算。

两个结构性痛点正好是 Mist 的主场：

| x402 痛点 | Mist 对应能力 |
|---|---|
| 每笔一次链上 `transferWithAuthorization`，微额场景 gas 占比爆表 | 聚合器 10 万笔/秒链下摄取 + epoch 净额上链（**净额压缩数百倍**） |
| 支付额度 = 钱包余额，无委托/预算控制 | DSA：owner 签发预算锁死的委托（单笔/速率/总额/类目/过期），agent 持凭证消费 |

S-28 的 USDC 结算路径（`BatchSettler.asset = USDC`）恰好补上资产侧：商户收的就是
Base USDC，净额指令 `NetInstruction { recipient, amount }` 直接映射。

## 2. 两个集成面（v1 范围）

### 2.1 Mist 作为 x402 的授权 + 摄取层（主推）

- agent 端：SDK 拦截 `402` → 把 `paymentRequirements` 映射成 `SpendIntent`
  （recipient=merchant 地址、amount、category=域名哈希、memo=x402 请求指纹）→
  走现有 `authorize / pay` 管线 → 拿 `Receipt.seq` 构造 x402 `paymentPayload`
  （自定义 scheme `mist-v1`）。
- server/facilitator 端：验证 `paymentPayload` = 向 Mist gateway 查询
  `Receipt`（**新增只读端点** `/v1/receipts/{intent_hash}`，Phase 2 缝，见 §4）→
  accepted 即放行 200。
- 结算：商户作为 `BatchSettler` claimant 按 epoch 领取 USDC 净额——**既有延迟
  claim 语义零改动**。

### 2.2 Mist 作为 facilitator 的聚合后端（白标卖水面）

- 第三方 x402 facilitator 把逐笔 EIP-3009 验证换成 Mist 摄取（SaaS/白标），
  审计账本 + WAL 提供对账。这是 MASTER_PLAN 商业模式的直接兑现点。

## 3. 映射表（v1 草案）

| x402 字段 | Mist 字段 | 备注 |
|---|---|---|
| `payTo` | `intent.recipient` | 20B EVM 地址，Did 兼容 |
| `maxAmountRequired` | `intent.amount` | USDC 6 decimals 直通 |
| `resource` (URL) | `intent.category` | sha256(host+path)；类目白名单可限域 |
| `description` / nonce | `intent.memo` / `spend_nonce` | nonce 语义同 §6.2 |
| `asset`/`network` | 网关部署配置 | v1 仅 Base USDC（主网 `0x8335…2913`） |
| `paymentPayload.scheme = "mist-v1"` | `IntentEnvelopeDto` JSON | wire 单一来源，S-29 已定 |

## 4. 缺口清单（诚实边界）

1. **只读查询端点**：`/v1/receipts/{intent_hash}` 返回 Receipt（含 seq）——merchant
   侧验证用。**已实现（S-30a）**：内核 `Aggregator::receipt()`（意图索引扩展 seq）+
   gateway `GET /v1/receipts/{hash}`（租户闸共用，404 `E_NOT_FOUND`，0x 前缀宽容）+
   SDK `HttpTransport::receipt()`。**语义边界（诚实）**：命中 = 已接受且**未结算**——
   索引随 settle 按 epoch 修剪、被拒意图不可查，**404 ≠ 未支付**；merchant 验证须在
   epoch 时延内完成（§4.2），终局保证在链上净额。TECH_SPEC §6.7 已落盘。
2. **确认时延**：Mist 是 epoch 级终局（10s 密封 + 链上承诺），x402 merchant 预期
   准即时。v1 方案：**Receipt 即受理凭证**（运营者债券兜底 + 幂等重发可复验），商户
   风险敞口 ≤ 1 epoch——这与"债券/罚没"安全模型一致，需在白标合同里写明。
3. **EIP-3009 兼容模式**：存量 x402 client 不会说 `mist-v1`。可选桥：facilitator
   接受标准 EIP-3009 payload 后转投 Mist 摄取（ merchant 无感）。**已实现
   （S-32，2026-08-30，TECH_SPEC §6.10）**：facilitator `eip3009` 模块——标准 `exact`
   payload 解析（`validAfter`/`validBefore` 数字与字符串宽容）→ 绑定校验（network /
   resource / `to == payTo` / `value == maxAmountRequired` / 时间窗）→ EIP-712 验签
   （k256 ecrecover + keccak256，v 宽容 0/1 与 27/28）→ 垫付转投 Mist 摄取
   （facilitator 以自身委托走全量 DSA 闸口，桥不旁路任何协议层检查）→ 重放闸
   （`(from, eip3009 nonce) → intent_hash`，重放直接落 S-30c 回执查询）。**诚实边界**：
   EIP-3009 的链上执行不在本件（client→运营商清算 = 运营商侧账务，memo 指纹留档）；
   被消费的是运营商自己的预算（垫付，client 信用风险由白标合同承担）；重放闸 S-32 为
   进程内存态，**S-33（2026-08-30）已持久化**——append-only JSONL 日志（摄取成功先内存
   登记再落盘 sync_data，重启重建闸表，坏行跳过计数），落盘失败 503 `E_REPLAY_JOURNAL`
   fail-closed（TECH_SPEC §6.10，bin 经 `MIST_BRIDGE_REPLAY_JOURNAL` 启用，缺省仍内存态）；
   EIP-712 domain 由配置显式给出。测试：eip3009 单测 7 + facilitator handle 纯分发 2 +
   真 socket e2e（exact client → 真摄取真记账 1 笔 → 重放不摄取 → 伪造 402）
   + S-33 增量（journal 单测 4 + open 重建 1 + 重启后重放闸 e2e 1）。
   **真 prover 装配（S-47，2026-08-30，TECH_SPEC §6.10/§6.14）**：`BridgeConfig.noir`
   （bin `MIST_BRIDGE_NOIR=1` + `MIST_BRIDGE_NOIR_ROOT` + `MIST_BRIDGE_ATTEST_SECRET`）
   经 `SdkClient::with_noir` 装配真电路 prover（§6.14 同源装配——S-46 装配面的首个
   二进制消费方）；缺省占位不变。门控 e2e：noir 装配桥在真 BbVerifier 网关
   （`enforce_revocation_root = true`）摄取 200，占位桥对照组 402（bb 全拒占位证明）。
4. **规范上游**：x402 规范仍在演进，scheme 扩展注册路径未定——设计稿按"自定义 scheme"
   起步，跟进上游后再标准化。

## 5. 排期建议

1. S-30a：`/v1/receipts` 只读端点 + gateway 测试（小，~半天砖）。**已完成（2026-08-30）**——
   测试：aggregator `receipt_lookup_hits_before_settle_and_none_after` + gateway
   `handle_receipt_lookup_gate_and_hash_validation` / `e2e_receipt_lookup_x402_merchant_flow`。
2. S-30b：SDK 侧 x402 fetch 拦截（`X402Client` wrapper，schema `mist-v1`）。**已完成
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
3. S-30c：facilitator 参考实现（§2.1 server 侧）。**已完成（2026-08-30，TECH_SPEC §6.9）**：
   `mist-facilitator` crate——`Facilitator::handle` 纯分发（/healthz 200 / 402 体复用
   sdk Serialize 类型 / `X-PAYMENT` 解码→scheme/network/resource 绑定校验→网关回执查询），
   **fail-closed 语义**（回执命中→200 放行 / 404→402 不放行 / 网关不可达→503
   `E_GATEWAY_UNAVAILABLE`）；std-only 手写 HTTP/1.1（§6.7 gateway 同先例）；bin
   `mist-facilitator` 环境变量配置。测试：7 个（handle 纯分发单测 + 三角色真 socket
   e2e——X402Client(HttpFetch) → facilitator 402 → 真网关 pay 真记账 → 重放 → 回执验证
   200 / 伪造 intentHash → 402 / 网关宕机 → 503）。**诚实边界**：单资源模型、明文 HTTP
   （TLS 反代终结）、不产 `X-PAYMENT-RESPONSE`、结算侧不在本件。
4. EIP-3009 桥：**已完成（S-32，2026-08-30，TECH_SPEC §6.10）**——见缺口清单 3。
   重放闸持久化（S-32 诚实边界"持久化去重是后续项"）：**已完成（S-33，2026-08-30，
   TECH_SPEC §6.10）**——`ReplayJournal` append-only JSONL + 启动重建 + 落盘失败
   503 fail-closed；残余边界（磁盘故障窗口、日志线性增长）见 TECH_SPEC §6.10。
5. x402 v2 wire 双协议：**已完成（S-72，2026-09-01，TECH_SPEC §6.8/§6.9/§6.10）**——
   sdk + facilitator wire 层 v1/v2 双协议：`PAYMENT-SIGNATURE`/`PAYMENT-REQUIRED`
   头 + CAIP-2 网络标识（`network_canonical` 规范形比较）+ v2 payload 结构
   （`accepted` 对象、`amount` 字段名、标准 base64）；402 = v1 body 不动 + v2 头
   声明；scheme 名 `mist-v1` 不改（与 x402 协议版本正交）。字段以上游
   `specs/x402-specification-v2.md` / `typescript/packages/core` 实核定（任务书
   `maxAmount` 猜测不成立，实际为 `maxAmountRequired`→`amount` 改名）。
