//! `pay()`：幂等支付（S-12 核心）。
//!
//! 断线重试不产生双花的机制（与聚合器侧配合，见 crate 文档）：
//! 1. 每笔逻辑支付取**固定 nonce**（[`NonceManager`]），整个重试周期复用同一
//!    (nonce, intent)；
//! 2. 仅传输错误（[`SdkError::Transport`]）触发重试；聚合器业务拒绝（错误码透传）不重试；
//! 3. 聚合器对同一 intent_hash 的重发幂等返回先前结果——accepted → 原 seq（不重复记账），
//!    拒绝 → 原原因（不透传成成功）。
//!
//! 证明 = [`PlaceholderProver`]（与聚合器 `FormatVerifier` 配套的 TEMPORARY 口径）；
//! 真实 S-09 电路 prover 实现 `meridian_core::zk::SpendProver`，经 `SdkClient::with_prover`
//! 接入，本函数不变。

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use meridian_aggregator::receipt::IntentEnvelope;
use meridian_core::dsa::{Amount, Category, Did};
use meridian_core::error::Error;
use meridian_core::zk::{SpendProof, SpendProofRequest, SpendProver, SpendPublicInputs};

use crate::error::SdkError;
use crate::SdkClient;

/// 支付参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayParams {
    pub delegation_hash: [u8; 32],
    pub recipient: Did,
    pub amount: Amount,
    pub category: Category,
    pub memo: Option<[u8; 32]>,
    pub expires_at: u64,
}

/// 支付回执。`seq` = 聚合器分配的统一摄取序号（承诺格位置）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayReceipt {
    pub intent_hash: [u8; 32],
    pub seq: u64,
    /// 本笔支付使用的 spend_nonce（幂等键；重试全程固定，聚合器据此去重）。
    pub spend_nonce: u64,
}

/// 重试策略（tower/retry 模式的同步轻量实现——聚合器是同步内核，agent 进程无需 tokio）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// 最大尝试次数（含首次）。
    pub max_attempts: u32,
    /// 初始退避（毫秒），每次翻倍，封顶 [`Self::max_backoff_ms`]。
    pub base_backoff_ms: u64,
    /// 退避上限（毫秒）。
    pub max_backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_attempts: 3,
            base_backoff_ms: 50,
            max_backoff_ms: 500,
        }
    }
}

/// 每委托的单调 spend_nonce 管理器。
///
/// 契约：**仅上一笔定局（accepted 或永久拒绝）后才取下一个**——重试全程 nonce 固定，这是
/// 双花防护的前提。进程内状态；跨进程崩溃恢复经 [`NonceManager::resync`]（S-31：聚合器
/// `GET /v1/nonce` 查询，§6.7，[`SdkClient::sync_nonce`](crate::SdkClient::sync_nonce) 包装）。
pub struct NonceManager {
    next: RwLock<HashMap<[u8; 32], u64>>,
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceManager {
    pub fn new() -> Self {
        NonceManager {
            next: RwLock::new(HashMap::new()),
        }
    }

    /// 分配下一个 nonce（每委托单调）。
    pub fn next(&self, dh: &[u8; 32]) -> u64 {
        let mut map = self.next.write().expect("nonce manager poisoned");
        let cur = map.entry(*dh).or_insert(0);
        let n = *cur;
        *cur = n + 1;
        n
    }

    /// S-31 跨重启恢复：把本地计数推进到 `max(本地, 远端)`。本地领先时**不动**
    /// （避免并发客户端被回退重发撞已消耗 nonce）；返回生效值。
    pub fn resync(&self, dh: &[u8; 32], remote_next: u64) -> u64 {
        let mut map = self.next.write().expect("nonce manager poisoned");
        let cur = map.entry(*dh).or_insert(0);
        if remote_next > *cur {
            *cur = remote_next;
        }
        *cur
    }
}

/// 占位 prover：proof 非空 + 公共输入与信封逐字段一致（聚合器 `FormatVerifier` + 一致性
/// 校验能过的口径）。真实后端（S-09 电路）实现 `SpendProver`，经 `SdkClient::with_prover`
/// 接入——本函数与重试逻辑不变。
#[derive(Debug, Clone, Copy, Default)]
pub struct PlaceholderProver;

impl SpendProver for PlaceholderProver {
    fn prove(&self, req: &SpendProofRequest) -> Result<SpendProof, Error> {
        let intent = req.intent;
        Ok(SpendProof {
            // 非空即过（FormatVerifier 门槛）；真实证明字节在 S-13 接缝替换。
            proof: vec![0x00, 0x01, 0x02],
            public_inputs: SpendPublicInputs {
                // 占位；真实 prover 填 attestation 承诺（attest() 产出）。
                agent_commit: [0u8; 32],
                delegation_hash: intent.delegation_hash,
                recipient: intent.recipient,
                amount: intent.amount,
                category: intent.category,
                spend_nonce: intent.spend_nonce,
                expires_at: intent.expires_at,
                revocation_root: req.revocation_root,
                now: req.now,
            },
        })
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

pub(crate) fn pay(client: &SdkClient, params: &PayParams) -> Result<PayReceipt, SdkError> {
    let dh = params.delegation_hash;
    // 授权上下文（agent DID + SignedDelegation）在 authorize 时记录。
    let agent = client.agent_for(&dh)?;
    let sd = client.signed_delegation_for(&dh)?;
    // 固定 nonce：本笔支付的重试全程不变。
    let nonce = client.next_nonce(&dh);
    let (intent, sig) = client.wallet().create_intent(
        agent,
        dh,
        params.recipient,
        params.amount,
        params.category,
        nonce,
        params.memo,
        params.expires_at,
    );
    let now = now_unix();
    let proof = client
        .prover()
        .prove(&SpendProofRequest {
            sd: &sd,
            intent: &intent,
            agent_key: &client.wallet().agent_key,
            revocation_root: [0u8; 32],
            now,
        })
        .map_err(SdkError::Meridian)?;
    let env = IntentEnvelope {
        intent,
        agent_sig: sig,
        proof,
    };

    let policy = *client.retry();
    let mut attempt: u32 = 1;
    loop {
        match client.transport().submit(&env) {
            Ok(r) if r.accepted => {
                return Ok(PayReceipt {
                    intent_hash: r.intent_hash,
                    seq: r.seq,
                    spend_nonce: nonce,
                });
            }
            Ok(r) => {
                // 永久拒绝：错误码透传，不重试。nonce 已被聚合器消耗，本笔到此为止。
                return Err(SdkError::Meridian(r.reject_reason.unwrap_or(Error::EProof)));
            }
            Err(e) => {
                // 仅传输错误重试；nonce/信封固定 → 聚合器幂等 re-ack → 不双花。
                if attempt >= policy.max_attempts {
                    return Err(e);
                }
                let exponent = (attempt - 1).min(62);
                let backoff = policy
                    .base_backoff_ms
                    .saturating_mul(1u64 << exponent)
                    .min(policy.max_backoff_ms);
                std::thread::sleep(Duration::from_millis(backoff));
                attempt += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_manager_is_monotonic_per_delegation() {
        let m = NonceManager::new();
        let dh_a = [1u8; 32];
        let dh_b = [2u8; 32];
        assert_eq!(m.next(&dh_a), 0);
        assert_eq!(m.next(&dh_a), 1);
        assert_eq!(m.next(&dh_b), 0); // 委托间独立
        assert_eq!(m.next(&dh_a), 2);
    }

    #[test]
    fn placeholder_prover_is_format_verifier_compatible() {
        // 构造最小 req（真实信封），验证产出的公共输入与 intent 一致（check_* 可过）。
        let owner_key = meridian_core::dsa::owner_signing_key_from_bytes([7u8; 32]);
        let wallet = crate::identity::AgentWallet::from_seed([9u8; 32]);
        let limits = crate::identity::DelegationLimits {
            max_per_spend: 1_000,
            rate_window_secs: 60,
            rate_max_per_window: 10_000,
            total_cap: 10_000,
            categories: vec![],
            not_before: 0,
            expires_at: u64::MAX,
        };
        let sd = crate::identity::create_delegation(&owner_key, [1u8; 20], 1, &limits).unwrap();
        let (intent, _sig) = wallet.create_intent(
            [1u8; 20],
            meridian_core::dsa::delegation_hash(&sd.delegation),
            [3u8; 20],
            42,
            [0xCD; 32],
            1,
            None,
            u64::MAX,
        );
        let req = SpendProofRequest {
            sd: &sd,
            intent: &intent,
            agent_key: &wallet.agent_key,
            revocation_root: [0u8; 32],
            now: 1_700_000_000,
        };
        let proof = PlaceholderProver.prove(&req).unwrap();
        let pi = &proof.public_inputs;
        assert_eq!(pi.delegation_hash, intent.delegation_hash);
        assert_eq!(pi.recipient, intent.recipient);
        assert_eq!(pi.amount, intent.amount);
        assert_eq!(pi.category, intent.category);
        assert_eq!(pi.spend_nonce, intent.spend_nonce);
        assert_eq!(pi.expires_at, intent.expires_at);
        assert!(!proof.proof.is_empty());
    }
}
