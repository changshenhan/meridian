# meridian-sdk — Agent 集成层（S-12）

独立 agent 进程接入 Meridian 聚合器的 Rust crate。封装 core 密码学原语 + 聚合器摄取
管线，暴露三个高层操作：

| 操作 | 作用 |
|---|---|
| `SdkClient::authorize(owner_key, agent, limits)` | 注册一张委托（DSA 授权，本地限额校验，错误码透传） |
| `SdkClient::pay(params)` | 幂等支付（固定 nonce + 断线重试，聚合器侧幂等兜底） |
| `SdkClient::attest(pk)` | 双钥绑定凭据（agent 传输身份 ↔ 电路签名公钥，S-05） |

同步内核，无 async runtime（聚合器是同步内核，agent 进程无需 tokio；tower/retry 模式
用同步轻量实现 `RetryPolicy`）。

## 幂等重试契约（"断线重试不产生双花"）

1. **固定 nonce**：每笔逻辑支付取固定 `spend_nonce`，整个重试周期不复用、不推进；
   只有聚合器返回**定局**（accepted 或永久拒绝）后，下一笔才拿新 nonce（`NonceManager`，
   每委托单调）。
2. **只重试传输错误**：`SdkError::Transport` 触发重试；聚合器业务拒绝
   （`SdkError::Meridian`，错误码经 `Error::as_code` 透传）**永不重试**。
3. **聚合器侧幂等**（S-12 配合改动）：同一 `(spend_nonce, intent_hash)` 的重发返回先前
   结果——accepted → 原 `seq`（不重复分配、不重复记账），rejected → 原原因（不透传成
   成功）。此闸口在过期检查之前 → 已过期但曾被接受的意图重发仍 re-ack，SDK 绝不会因
   `EIntentExpired` 误判失败去换新 nonce 重发（那才是双花的来源）。

验证（`sdk/tests/e2e.rs`，真实聚合器 + 真实 WAL + 真实密码学，零 mock）：

- `response_loss_retry_no_double_spend`：聚合器已接受、回执丢失 → 重发 → re-ack 原
  `seq 0`，`accepted_count == 1`，`total_spent == 42` 恰好一次（**双花防护**）；
  之后还能继续正常支付（新 nonce → `seq 1`）。
- `response_loss_retry_on_budget_rejection_reports_error`：超限意图被拒、回执丢失 →
  重发 → `E_BUDGET_PER_SPEND`（不透传成成功），nonce 不复活。
- `drop_first_never_delivered_retries`：请求从未送达 → 重试 → 正常接受。
- 其余：全链路 authorize→pay×2 记账逐笔正确、attest 可验 + 篡改必拒、错误码透传、
  未授权先 pay 本地拒绝。

断线模拟（`sdk/src/transport.rs`，测试用）：
- `DropFirstTransport`：请求**从未送达**（内层不被调用）。
- `ResponseLossTransport`：请求**已送达**（聚合器已处理——已接受或已拒绝）、回执丢失。

## 传输形态

`Transport` trait 抽象「聚合器连接」，`pay` 的重试只看 `SdkError`，不关心底层是进程内
调用还是网络 RPC：

```rust
pub trait Transport: Send + Sync {
    fn authorize(&self, sd: SignedDelegation, agent_pub: AgentPubKey) -> Result<(), SdkError>;
    fn submit(&self, env: &IntentEnvelope) -> Result<Receipt, SdkError>;
}
```

S-12 提供 `InProcessAggregator`（进程内聚合器，测试与单进程嵌入用）。**网络传输是 S-13
框架分发层的接缝**——独立 agent 进程对接真实聚合器服务时实现同一 trait 即可，`pay()`
重试与幂等逻辑不变。

## 诚实边界

- **证明是占位的**：`PlaceholderProver`（proof 非空 + 公共输入与信封一致）与聚合器内置
  `FormatVerifier`（TEMPORARY）配套。真实 S-09 电路 prover 实现 core `SpendProver`，经
  `SdkClient::with_prover` 接入——`pay()` 与重试逻辑不用改。
- **NonceManager 不持久化**：进程内单调计数；进程崩溃后跨重启的 nonce 恢复依赖聚合器
  WAL（崩溃重建） + 未来聚合器的 `next_nonce` 查询 RPC（Phase 2 缝）。v1 的崩溃恢复
  语义：重试窗口内重启会以先前定局 re-ack，不双花；重启后新支付从 nonce 0 重新计数，
  与聚合器已消耗 nonce 集无冲突（聚合器按 intent_hash 去重，不按 nonce 序号）。
- **tower 未引入**：同步内核用 `RetryPolicy` 轻量实现同款退避（指数退避 + 封顶）。若
  S-13 的框架层需要 async，可将 `pay()` 重试搬进 async 包装，契约不变。

## 测试

```sh
cargo test -p meridian-sdk          # 单元 + e2e（真实聚合器，需临时目录写 WAL）
cargo clippy --workspace --all-targets -- -D warnings
```

`docs/TECH_SPEC.md §6.6` 记录了 SDK 层与幂等重发闸口的设计；`MASTER_PLAN.md` S-12 为
进度唯一事实源。
