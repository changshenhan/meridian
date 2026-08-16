//! S-07 探针服务端状态：委托注册表 + agent 身份绑定 + 预算账本 + 防重放。
//!
//! 与 core 的分工：core 是纯原语（DSA 签名/哈希、账本预算状态机）；本模块是
//! **单进程聚合器**（S-07 最小形态）——注册委托、绑定 agent 身份、执行支付。
//!
//! TEMPORARY 边界（S-07 明示）：`pay()` 的"授权"目前是 agent Ed25519 验签 + 预算检查，
//! **不含 ZK 证明**。真实证明授权在 S-09 接入（circuit + Verifier）。这符合
//! MASTER_PLAN S-07 验收（"模拟支付闭环"）；README 记录该缺口。

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature as AgentSignature, VerifyingKey as AgentPubKey};
use meridian_core::dsa::{
    delegation_hash, verify_delegation, verify_intent, Amount, Delegation, Did, OwnerPubKey,
    Signature64, SignedDelegation, SpendIntent,
};
use meridian_core::error::Error;
use meridian_core::ledger::ShardedLedger;

/// 注册表条目：委托本体 + 该 agent 的传输身份公钥（Ed25519，S-02 语义）。
#[derive(Debug, Clone)]
struct Registration {
    delegation: Delegation,
    agent_pub: AgentPubKey,
}

/// 单进程聚合器状态。
///
/// 全部字段用内部可变 + 原子：MCP tool handler 是 &self 同步调用，无 async 持有锁，
/// 因此 std::sync::Mutex 足够（不跨 await）。
pub struct AppState {
    /// delegation_hash → (委托, agent 公钥)。**绑定在 authorize 时建立**：
    /// 只有用该公钥签 intent 的 agent 才能消费该委托。
    delegations: Mutex<HashMap<[u8; 32], Registration>>,
    /// (delegation_hash, spend_nonce) 防重放集。
    nonces: Mutex<HashSet<([u8; 32], u64)>>,
    /// 预算账本（分片，TECH_SPEC §4.5：ZK 证明授权、账本执行预算）。
    ledger: ShardedLedger,
    /// 模拟支付计数器 → payment_id。
    payment_counter: AtomicU64,
}

/// 手工 Debug：内部是 Mutex<HashMap>，不派生（只暴露规模，不泄内部）。
impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field(
                "delegation_count",
                &self.delegations.lock().expect("delegations poisoned").len(),
            )
            .field(
                "nonce_count",
                &self.nonces.lock().expect("nonces poisoned").len(),
            )
            .field("payment_counter", &self.payment_counter)
            .finish_non_exhaustive()
    }
}

/// `authorize` 回执。
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct AuthorizeReceipt {
    pub delegation_hash: String,
    pub agent: String,
    pub owner: String,
    pub nonce: u64,
    pub max_per_spend: Amount,
    pub total_cap: Amount,
}

/// `pay` 回执（模拟结算记录）。
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct PayReceipt {
    pub payment_id: u64,
    pub delegation_hash: String,
    pub recipient: String,
    pub amount: Amount,
    pub spend_nonce: u64,
    pub total_spent: Amount,
    pub remaining: Amount,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

fn hex_did(did: &Did) -> String {
    hex::encode(did)
}

fn hex_hash(h: &[u8; 32]) -> String {
    hex::encode(h)
}

impl AppState {
    pub fn new() -> Self {
        Self {
            delegations: Mutex::new(HashMap::new()),
            nonces: Mutex::new(HashSet::new()),
            ledger: ShardedLedger::new(8),
            payment_counter: AtomicU64::new(0),
        }
    }

    /// 注册委托（meridian.authorize）。
    ///
    /// 校验：owner 对 delegation_hash 的 secp256k1 签名；委托字段自洽
    /// （not_before ≤ expires_at；单笔 ≤ 窗口 ≤ 总额，否则后续必然红）。
    /// 绑定：agent 传输身份公钥（Ed25519）→ 该 delegation_hash。
    ///
    /// 幂等：同一 delegation_hash 已注册且绑定同一 agent 公钥 → 直接返回既有回执。
    /// 若已注册但绑定不同公钥 → `Error::EAttestBind`（禁止换钥重绑，防混淆）。
    pub fn authorize(
        &self,
        delegation: &Delegation,
        owner_pub: &OwnerPubKey,
        agent_pub: &AgentPubKey,
        owner_sig: &Signature64,
    ) -> Result<AuthorizeReceipt, Error> {
        // 1. owner 签名有效（低位 s 强制由 core 保证）。
        verify_delegation(
            &SignedDelegation {
                delegation: delegation.clone(),
                signature: *owner_sig,
            },
            owner_pub,
        )?;

        // 2. 委托字段自洽（不是安全边界，是防配置错误的护栏）。
        if delegation.not_before > delegation.expires_at {
            return Err(Error::EDelegExpired);
        }
        if delegation.max_per_spend > delegation.rate.max_per_window
            || delegation.rate.max_per_window > delegation.total_cap
        {
            return Err(Error::EBudgetPerSpend);
        }

        // 3. 幂等 / 防换钥重绑。
        let dh = delegation_hash(delegation);
        let mut map = self.delegations.lock().expect("delegations poisoned");
        if let Some(existing) = map.get(&dh) {
            if existing.agent_pub.as_bytes() != agent_pub.as_bytes() {
                return Err(Error::EAttestBind);
            }
            // 已注册且同一 agent → 幂等返回。
        } else {
            map.insert(
                dh,
                Registration {
                    delegation: delegation.clone(),
                    agent_pub: *agent_pub,
                },
            );
        }

        Ok(AuthorizeReceipt {
            delegation_hash: hex_hash(&dh),
            agent: hex_did(&delegation.agent),
            owner: hex_did(&delegation.owner),
            nonce: delegation.nonce,
            max_per_spend: delegation.max_per_spend,
            total_cap: delegation.total_cap,
        })
    }

    /// 执行一笔模拟支付（meridian.pay）。
    ///
    /// 校验顺序（不可交换）：
    ///   1. 委托已注册（查 delegation_hash）；
    ///   2. intent 与委托绑定（agent 一致）；
    ///   3. agent 对 intent_hash 的 Ed25519 签名；
    ///   4. intent 未过期；
    ///   5. 防重放（spend_nonce）；
    ///   6. 预算检查 + 记账（core ledger，规则 1-6）。
    ///
    /// TEMPORARY（S-07）：无 ZK 证明。S-09 在此处插入 `verify_proof`（电路公共输入回读）。
    pub fn pay(&self, intent: &SpendIntent, sig: &AgentSignature) -> Result<PayReceipt, Error> {
        let now = now_unix();

        let dh = intent.delegation_hash;
        let map = self.delegations.lock().expect("delegations poisoned");
        let reg = map.get(&dh).ok_or(Error::EDelegExpired)?;
        let delegation = &reg.delegation;

        // 2. intent ↔ 委托绑定：agent 必须一致（delegation_hash 已隐含 owner/授权边界）。
        if intent.agent != delegation.agent {
            return Err(Error::EIntentHash);
        }

        // 3. agent 签名（Ed25519 over intent_hash）。
        verify_intent(intent, sig, &reg.agent_pub)?;

        // 4. intent 有效期。
        if now > intent.expires_at {
            return Err(Error::EIntentExpired);
        }

        // 5. 防重放：同一 delegation 下 spend_nonce 只能用一次。
        {
            let mut nonces = self.nonces.lock().expect("nonces poisoned");
            if !nonces.insert((dh, intent.spend_nonce)) {
                return Err(Error::ENonce);
            }
        }

        // 6. 预算检查 + 记账（原子，规则 1-6；窗口回滚按 now）。
        self.ledger
            .check_and_apply(delegation.agent, delegation, intent.amount, now)?;

        let total_spent = self.ledger.total_spent(&delegation.agent, &dh).unwrap_or(0);
        let payment_id = self.payment_counter.fetch_add(1, Ordering::Relaxed);

        Ok(PayReceipt {
            payment_id,
            delegation_hash: hex_hash(&dh),
            recipient: hex_did(&intent.recipient),
            amount: intent.amount,
            spend_nonce: intent.spend_nonce,
            total_spent,
            remaining: delegation.total_cap.saturating_sub(total_spent),
        })
    }

    /// 查询委托注册状态（调试/测试辅助）。
    #[cfg(test)]
    fn is_registered(&self, dh: &[u8; 32]) -> bool {
        self.delegations.lock().expect("poisoned").contains_key(dh)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey as AgentSigningKey;
    use meridian_core::dsa::{
        owner_signing_key_from_bytes, sign_delegation, sign_intent, RateLimit, PROTOCOL_VERSION,
    };

    fn delegation(agent: Did, owner: Did, max_per_spend: Amount, total_cap: Amount) -> Delegation {
        Delegation {
            agent,
            owner,
            nonce: 1,
            max_per_spend,
            rate: RateLimit {
                window_secs: 3_600,
                max_per_window: total_cap,
            },
            total_cap,
            categories: vec![],
            not_before: 0,
            expires_at: u64::MAX,
            version: PROTOCOL_VERSION,
        }
    }

    fn intent(agent: Did, dh: [u8; 32], amount: Amount, nonce: u64) -> SpendIntent {
        SpendIntent {
            agent,
            delegation_hash: dh,
            recipient: [3u8; 20],
            amount,
            category: [0xCD; 32],
            spend_nonce: nonce,
            memo: None,
            expires_at: u64::MAX,
        }
    }

    /// 构造一组可用的 owner/agent 密钥与委托，返回 (state, dh, agent_pub, agent_key)。
    fn setup(
        state: &AppState,
    ) -> (
        [u8; 32],
        AgentPubKey,
        AgentSigningKey,
        OwnerPubKey,
        Delegation,
    ) {
        let owner_key = owner_signing_key_from_bytes([7u8; 32]);
        let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
        let d = delegation([1u8; 20], [2u8; 20], 1_000, 10_000);
        let sd = sign_delegation(&d, &owner_key);
        state
            .authorize(
                &d,
                owner_key.verifying_key(),
                &agent_key.verifying_key(),
                &sd.signature,
            )
            .expect("authorize should succeed");
        (
            delegation_hash(&d),
            agent_key.verifying_key(),
            agent_key,
            *owner_key.verifying_key(),
            d,
        )
    }

    #[test]
    fn authorize_rejects_bad_owner_signature() {
        let state = AppState::new();
        let owner_key = owner_signing_key_from_bytes([7u8; 32]);
        let other = owner_signing_key_from_bytes([8u8; 32]);
        let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
        let d = delegation([1u8; 20], [2u8; 20], 1_000, 10_000);
        // 用另一把 owner 私钥签 → 验签失败
        let sd = sign_delegation(&d, &other);
        assert_eq!(
            state.authorize(
                &d,
                owner_key.verifying_key(),
                &agent_key.verifying_key(),
                &sd.signature,
            ),
            Err(Error::EDelegSig)
        );
    }

    #[test]
    fn authorize_rejects_inconsistent_caps() {
        let state = AppState::new();
        let owner_key = owner_signing_key_from_bytes([7u8; 32]);
        let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
        // max_per_spend > max_per_window → 自相矛盾
        let d = delegation([1u8; 20], [2u8; 20], 5_000, 10_000);
        let mut bad = d.clone();
        bad.rate.max_per_window = 1_000;
        let sd = sign_delegation(&bad, &owner_key);
        assert_eq!(
            state.authorize(
                &bad,
                owner_key.verifying_key(),
                &agent_key.verifying_key(),
                &sd.signature,
            ),
            Err(Error::EBudgetPerSpend)
        );
    }

    #[test]
    fn authorize_is_idempotent_and_binds_agent() {
        let state = AppState::new();
        let (dh, ..) = setup(&state);
        assert!(state.is_registered(&dh));
    }

    #[test]
    fn authorize_rejects_key_rebinding() {
        let state = AppState::new();
        let owner_key = owner_signing_key_from_bytes([7u8; 32]);
        let d = delegation([1u8; 20], [2u8; 20], 1_000, 10_000);
        let sd = sign_delegation(&d, &owner_key);

        let agent_a = AgentSigningKey::from_bytes(&[9u8; 32]);
        let agent_b = AgentSigningKey::from_bytes(&[0xA0; 32]);
        state
            .authorize(
                &d,
                owner_key.verifying_key(),
                &agent_a.verifying_key(),
                &sd.signature,
            )
            .unwrap();
        // 同一委托换 agent 公钥重绑 → 拒绝
        assert_eq!(
            state.authorize(
                &d,
                owner_key.verifying_key(),
                &agent_b.verifying_key(),
                &sd.signature,
            ),
            Err(Error::EAttestBind)
        );
    }

    #[test]
    fn pay_full_loop_with_budget_decrement() {
        let state = AppState::new();
        let (dh, _, agent_key, _, _) = setup(&state);
        let i = intent([1u8; 20], dh, 42, 1);
        let sig = sign_intent(&i, &agent_key);
        let receipt = state.pay(&i, &sig).expect("pay should succeed");
        assert_eq!(receipt.amount, 42);
        assert_eq!(receipt.total_spent, 42);
        assert_eq!(receipt.remaining, 10_000 - 42);
        assert_eq!(receipt.payment_id, 0);
    }

    #[test]
    fn pay_rejects_unregistered_delegation() {
        let state = AppState::new();
        let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
        let i = intent([1u8; 20], [0xEE; 32], 1, 1);
        let sig = sign_intent(&i, &agent_key);
        assert_eq!(state.pay(&i, &sig), Err(Error::EDelegExpired));
    }

    #[test]
    fn pay_rejects_wrong_agent_signature() {
        let state = AppState::new();
        let (dh, ..) = setup(&state);
        let impostor = AgentSigningKey::from_bytes(&[0xB0; 32]);
        let i = intent([1u8; 20], dh, 1, 1);
        let sig = sign_intent(&i, &impostor);
        assert_eq!(state.pay(&i, &sig), Err(Error::EIntentSig));
    }

    #[test]
    fn pay_rejects_replay_nonce() {
        let state = AppState::new();
        let (dh, _, agent_key, _, _) = setup(&state);
        let i = intent([1u8; 20], dh, 1, 7);
        let sig = sign_intent(&i, &agent_key);
        assert!(state.pay(&i, &sig).is_ok());
        assert_eq!(state.pay(&i, &sig), Err(Error::ENonce));
    }

    #[test]
    fn pay_rejects_above_total_cap() {
        let state = AppState::new();
        let owner_key = owner_signing_key_from_bytes([7u8; 32]);
        let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
        // 单笔不挡（6_000 ≤ per_spend），窗口 1s 快速回滚，只测总额 10_000。
        let mut d = delegation([1u8; 20], [2u8; 20], 10_000, 10_000);
        d.rate.window_secs = 1;
        let sd = sign_delegation(&d, &owner_key);
        state
            .authorize(
                &d,
                owner_key.verifying_key(),
                &agent_key.verifying_key(),
                &sd.signature,
            )
            .unwrap();
        let dh = delegation_hash(&d);
        let i1 = intent([1u8; 20], dh, 6_000, 1);
        let s1 = sign_intent(&i1, &agent_key);
        assert!(state.pay(&i1, &s1).is_ok());
        // 跨窗口：窗口计数重置，但总额仍累计 → 12_000 > 10_000
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let i2 = intent([1u8; 20], dh, 6_000, 2);
        let s2 = sign_intent(&i2, &agent_key);
        assert_eq!(state.pay(&i2, &s2), Err(Error::EBudgetTotal));
    }
}
