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
//! 真实 S-09 电路 prover 实现 `mist_core::zk::SpendProver`，经 `SdkClient::with_prover`
//! 接入，本函数不变。
//!
//! S-45 撤销 witness 自动新鲜度（§6.14 诚实边界 3 SDK 半边）：缓存（per-dh）未命中
//! 现取（§6.7 witness 查询端点）；`E_REV_ROOT` 业务拒绝 = witness 取自旧状态根 → 同
//! 意图现取新 witness 重出证明重交（nonce 未消耗——绑定闸在聚合器 `try_commit` 之前
//! 拒，同意图重发不撞幂等闸缓存的原拒绝），刷新封顶 `RetryPolicy::max_attempts`。

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mist_aggregator::receipt::IntentEnvelope;
use mist_core::dsa::{Amount, Category, Did};
use mist_core::error::Error;
use mist_core::zk::{
    RevocationWitness, SpendProof, SpendProofRequest, SpendProver, SpendPublicInputs,
};

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
/// 双花防护的前提。**从 1 起（S-46 全链发现）**：电路断言 7 `spend_nonce > 0`（防零
/// nonce 误用）——0 起使每张委托的首笔支付在真 prover（`NoirProver`）下必然 `E_PROVER`
/// （占位 prover 不消费 nonce，缺口只在全链路暴露）。进程内状态；跨进程崩溃恢复经
/// [`NonceManager::resync`]（S-31：聚合器
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

    /// 分配下一个 nonce（每委托单调，从 1 起；聚合器只禁复用不要求连续，§6.2）。
    pub fn next(&self, dh: &[u8; 32]) -> u64 {
        let mut map = self.next.write().expect("nonce manager poisoned");
        let n = map.entry(*dh).or_insert(1);
        let v = *n;
        *n = v + 1;
        v
    }

    /// S-31 跨重启恢复：把本地计数推进到 `max(本地, 远端)`。本地领先时**不动**
    /// （避免并发客户端被回退重发撞已消耗 nonce）；返回生效值。聚合器空集（远端 0）
    /// 不回退本地 1 起的初值。
    pub fn resync(&self, dh: &[u8; 32], remote_next: u64) -> u64 {
        let mut map = self.next.write().expect("nonce manager poisoned");
        let cur = map.entry(*dh).or_insert(1);
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
                revocation_root: req.revocation.root,
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

    // S-45 撤销 witness 自动新鲜度（§6.14 诚实边界 3 SDK 半边）：缓存（per-dh）未命中
    // 时现取（§6.7 witness 查询端点）。`Ok(None)` = 目标已撤销——无缓存可入库，按占位
    // 口径继续 prove，聚合器管线步 2b `E_REVOKED` 定局（fail-closed 不在此预判业务态）。
    let witness = match client.revocation_witness_for(&dh) {
        Some(w) => Some(w),
        None => match client.transport().revocation_witness(&dh)? {
            Some(w) => {
                client.store_revocation_witness(&dh, w.clone());
                Some(w)
            }
            None => None,
        },
    };
    // 同一 prove 闭包复用：`E_REV_ROOT` 刷新重出时 intent / nonce / now 全部不动，
    // 只换 witness 重出证明（revocation_root 是电路公共输入，换根必须重证）。
    let prove = |w: RevocationWitness| -> Result<SpendProof, SdkError> {
        client
            .prover()
            .prove(&SpendProofRequest {
                sd: &sd,
                intent: &intent,
                agent_key: &client.wallet().agent_key,
                attestation_secret: client.attestation_secret(),
                revocation: w,
                now,
            })
            .map_err(SdkError::Mist)
    };
    let mut env = IntentEnvelope {
        intent: intent.clone(),
        agent_sig: sig,
        proof: prove(witness.unwrap_or(RevocationWitness {
            root: [0u8; 32],
            path: Vec::new(),
        }))?,
    };

    let policy = *client.retry();
    let mut attempt: u32 = 1;
    // S-45：`E_REV_ROOT` 刷新重出计数。与传输重试（attempt）分开计——业务拒绝不走
    // 退避；封顶 `max_attempts` 防「transport 指向另一聚合器」时无限循环（该情况下
    // 现取的 witness 永远不在提交目标的接受集内）。
    let mut refreshes: u32 = 0;
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
                let reason = r.reject_reason.unwrap_or(Error::EProof);
                // 撤销根绑定闸（S-44 §6.2）拒绝 = witness 取自旧状态根（重启前中间
                // 状态 / 换代窄窗口）。nonce 未消耗（闸在 try_commit 之前拒、不占
                // nonce 占位）→ 同意图现取新 witness 重出证明重交，安全。
                if reason == Error::ERevRoot && refreshes < policy.max_attempts {
                    refreshes += 1;
                    let fresh = client
                        .transport()
                        .revocation_witness(&dh)?
                        .ok_or(SdkError::Mist(reason))?; // 已撤销 → 原拒绝定局
                    client.store_revocation_witness(&dh, fresh.clone());
                    env.proof = prove(fresh)?;
                    continue;
                }
                // 永久拒绝：错误码透传，不重试。nonce 已被聚合器消耗，本笔到此为止。
                return Err(SdkError::Mist(reason));
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
    use std::sync::atomic::{AtomicU32, Ordering};
    #[test]
    fn nonce_manager_is_monotonic_per_delegation() {
        let m = NonceManager::new();
        let dh_a = [1u8; 32];
        let dh_b = [2u8; 32];
        // S-46 起从 1 计：电路断言 7 `spend_nonce > 0`（TECH_SPEC §6.6）。
        assert_eq!(m.next(&dh_a), 1);
        assert_eq!(m.next(&dh_a), 2);
        assert_eq!(m.next(&dh_b), 1); // 委托间独立
        assert_eq!(m.next(&dh_a), 3);
    }

    #[test]
    fn nonce_resync_ignores_empty_remote() {
        // 聚合器空集（next_nonce = 0）不回退本地 1 起的初值（S-46 resync 语义）。
        let m = NonceManager::new();
        let dh = [3u8; 32];
        assert_eq!(m.resync(&dh, 0), 1);
        assert_eq!(m.next(&dh), 1);
        // 远端领先推进；本地领先不回退。
        assert_eq!(m.resync(&dh, 7), 7);
        assert_eq!(m.resync(&dh, 4), 7);
    }

    #[test]
    fn placeholder_prover_is_format_verifier_compatible() {
        // 构造最小 req（真实信封），验证产出的公共输入与 intent 一致（check_* 可过）。
        let owner_key = mist_core::dsa::owner_signing_key_from_bytes([7u8; 32]);
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
            mist_core::dsa::delegation_hash(&sd.delegation),
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
            attestation_secret: [0u8; 32],
            revocation: mist_core::zk::RevocationWitness {
                root: [0u8; 32],
                path: Vec::new(),
            },
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

    // -----------------------------------------------------------------------
    // S-45 撤销 witness 自动新鲜度 + E_REV_ROOT 刷新重出（§6.14 诚实边界 3）
    // -----------------------------------------------------------------------

    /// 测试传输桩：witness 查询返回可切换的「当刻」witness（`None` = 已撤销 / 不可得；
    /// 计数）；submit 前缀 `reject_before` 次回 `E_REV_ROOT` 业务拒（模拟 witness 取自
    /// 旧状态根），之后接受。`PlaceholderProver` 把 witness 根原样透传进公共输入 →
    /// 可据此断言「重出证明确实换了根」。
    #[derive(Clone)]
    struct MockTransport(std::sync::Arc<MockInner>);

    struct MockInner {
        witness: RwLock<Option<RevocationWitness>>,
        /// 首次 submit 时切换到的「当刻」witness（模拟换代发生在取 witness 与提交之间，
        /// 首提交因此撞旧根被 `E_REV_ROOT` 拒）。
        switch_on_submit: RwLock<Option<Option<RevocationWitness>>>,
        reject_before: AtomicU32,
        submissions: AtomicU32,
        witness_fetches: AtomicU32,
        submitted_roots: std::sync::Mutex<Vec<[u8; 32]>>,
    }

    impl MockTransport {
        fn new(witness: Option<RevocationWitness>, reject_before: u32) -> Self {
            MockTransport(std::sync::Arc::new(MockInner {
                witness: RwLock::new(witness),
                switch_on_submit: RwLock::new(None),
                reject_before: AtomicU32::new(reject_before),
                submissions: AtomicU32::new(0),
                witness_fetches: AtomicU32::new(0),
                submitted_roots: std::sync::Mutex::new(Vec::new()),
            }))
        }

        fn set_witness(&self, w: Option<RevocationWitness>) {
            *self.0.witness.write().expect("witness poisoned") = w;
        }

        /// 预挂「首次 submit 时换代」：把当刻 witness 切到 `w`（None = 撤销到不可得）。
        fn switch_witness_on_submit(&self, w: Option<RevocationWitness>) {
            *self.0.switch_on_submit.write().expect("switch poisoned") = Some(w);
        }

        fn submissions(&self) -> u32 {
            self.0.submissions.load(Ordering::SeqCst)
        }

        fn witness_fetches(&self) -> u32 {
            self.0.witness_fetches.load(Ordering::SeqCst)
        }

        fn submitted_roots(&self) -> Vec<[u8; 32]> {
            self.0
                .submitted_roots
                .lock()
                .expect("roots poisoned")
                .clone()
        }
    }

    impl crate::transport::Transport for MockTransport {
        fn authorize(
            &self,
            _: mist_core::dsa::SignedDelegation,
            _: mist_core::dsa::AgentPubKey,
        ) -> Result<(), SdkError> {
            Ok(())
        }

        fn submit(
            &self,
            env: &IntentEnvelope,
        ) -> Result<mist_aggregator::receipt::Receipt, SdkError> {
            self.0.submissions.fetch_add(1, Ordering::SeqCst);
            // 模拟「提交瞬间聚合器换代」：首提交后当刻 witness 变化（只触发一次）。
            if let Some(w) = self
                .0
                .switch_on_submit
                .write()
                .expect("switch poisoned")
                .take()
            {
                self.set_witness(w);
            }
            self.0
                .submitted_roots
                .lock()
                .expect("roots poisoned")
                .push(env.proof.public_inputs.revocation_root);
            let spent = self
                .0
                .reject_before
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
            Ok(mist_aggregator::receipt::Receipt {
                intent_hash: [0xAB; 32],
                accepted: !spent,
                reject_reason: spent.then_some(Error::ERevRoot),
                seq: 42,
            })
        }

        fn next_nonce(&self, _dh: &[u8; 32]) -> Result<Option<u64>, SdkError> {
            Ok(Some(0))
        }

        fn revocation_witness(
            &self,
            _dh: &[u8; 32],
        ) -> Result<Option<RevocationWitness>, SdkError> {
            self.0.witness_fetches.fetch_add(1, Ordering::SeqCst);
            Ok(self.0.witness.read().expect("witness poisoned").clone())
        }
    }

    fn stale_witness(root: u8) -> RevocationWitness {
        RevocationWitness {
            root: [root; 32],
            path: Vec::new(),
        }
    }

    fn refreshed_params(dh: [u8; 32], amount: u64) -> PayParams {
        PayParams {
            delegation_hash: dh,
            recipient: [3u8; 20],
            amount,
            category: [0xCD; 32],
            memo: None,
            expires_at: u64::MAX,
        }
    }

    fn refreshed_client(mock: MockTransport) -> (SdkClient, k256::ecdsa::SigningKey) {
        let wallet = crate::identity::AgentWallet::from_seed([9u8; 32]);
        let owner = mist_core::dsa::owner_signing_key_from_bytes([7u8; 32]);
        (SdkClient::new(wallet, Box::new(mock)), owner)
    }

    fn refreshed_limits() -> crate::identity::DelegationLimits {
        crate::identity::DelegationLimits {
            max_per_spend: 1_000,
            rate_window_secs: 60,
            rate_max_per_window: 10_000,
            total_cap: 10_000,
            categories: vec![],
            not_before: 0,
            expires_at: u64::MAX,
        }
    }

    #[test]
    fn pay_refreshes_witness_on_rev_root_and_resubmits_same_intent() {
        // 旧状态 witness → E_REV_ROOT 拒 → 现取新根重出证明重交 → 接受；nonce 不推进。
        let mock = MockTransport::new(Some(stale_witness(1)), 1);
        let (client, owner) = refreshed_client(mock.clone());
        let rec = client
            .authorize(&owner, [1u8; 20], &refreshed_limits())
            .unwrap();
        let dh = rec.delegation_hash;

        // 接受前把「当刻」witness 换新根（模拟换代后的聚合器状态）。
        mock.switch_witness_on_submit(Some(stale_witness(2)));

        let r = client.pay(&refreshed_params(dh, 42)).unwrap();
        assert_eq!(r.seq, 42);
        // 重出证明确实换了根：首次提交旧根、重交新根。
        assert_eq!(mock.submitted_roots(), vec![[1u8; 32], [2u8; 32]]);
        assert_eq!(mock.submissions(), 2);
        assert_eq!(mock.witness_fetches(), 2, "pay 起手一次 + 刷新一次");
        // 绑定闸拒不耗 nonce（§6.2）：重交复用同一 nonce，仅定局后才推进。
        assert_eq!(r.spend_nonce, 1);
        // 新根已入库（per-dh 缓存，后续支付复用不再现取）。
        let r2 = client.pay(&refreshed_params(dh, 43)).unwrap();
        assert_eq!(r2.spend_nonce, 2, "只有定局后才推进 nonce");
        assert_eq!(mock.witness_fetches(), 2, "缓存命中不再现取");
        assert_eq!(mock.submissions(), 3);
    }

    #[test]
    fn pay_fetches_witness_on_cache_miss_per_delegation() {
        // 无缓存的委托自动现取（§6.7 端点）——占位根被真实根替换（per-dh 分桶）。
        let mock = MockTransport::new(Some(stale_witness(3)), 0);
        let (client, owner) = refreshed_client(mock.clone());
        let rec = client
            .authorize(&owner, [1u8; 20], &refreshed_limits())
            .unwrap();
        let dh = rec.delegation_hash;

        client.pay(&refreshed_params(dh, 42)).unwrap();
        assert_eq!(
            mock.submitted_roots(),
            vec![[3u8; 32]],
            "占位根被自动现取的真实根替换"
        );
    }

    #[test]
    fn pay_keeps_rejection_when_witness_unavailable() {
        // 刷新时取不到 witness（Ok(None) = 已撤销）→ 原拒绝定局（fail-closed，不重试）。
        let mock = MockTransport::new(Some(stale_witness(1)), 1);
        let (client, owner) = refreshed_client(mock.clone());
        let rec = client
            .authorize(&owner, [1u8; 20], &refreshed_limits())
            .unwrap();
        let dh = rec.delegation_hash;

        // 刷新窗口内聚合器侧已撤销 → witness 查询 Ok(None)。
        mock.switch_witness_on_submit(None);

        let err = client.pay(&refreshed_params(dh, 42)).unwrap_err();
        assert_eq!(
            err.code(),
            "E_REV_ROOT",
            "refresh 不可得 → 原拒绝透传: {err:?}"
        );
        assert_eq!(mock.submissions(), 1, "不重试");
        assert_eq!(mock.witness_fetches(), 2, "起手 + 刷新各一次");
    }

    #[test]
    fn pay_caps_witness_refresh_attempts() {
        // 聚合器持续 E_REV_ROOT（如 transport 指向另一聚合器）→ 刷新封顶
        // `RetryPolicy::max_attempts`，不无限循环。
        let mock = MockTransport::new(Some(stale_witness(1)), u32::MAX);
        let (client, owner) = refreshed_client(mock.clone());
        let rec = client
            .authorize(&owner, [1u8; 20], &refreshed_limits())
            .unwrap();
        let dh = rec.delegation_hash;

        let err = client.pay(&refreshed_params(dh, 42)).unwrap_err();
        assert_eq!(err.code(), "E_REV_ROOT");
        // 起手 1 次 + 刷新 max_attempts（缺省 3）次；提交同数（每次刷新后重交一次）。
        assert_eq!(mock.witness_fetches(), 1 + 3);
        assert_eq!(mock.submissions(), 1 + 3);
    }
}
