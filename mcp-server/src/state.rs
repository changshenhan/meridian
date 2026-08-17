//! S-13 MCP 服务器正式版状态层：**薄 keyless 层包住真实聚合器内核**。
//!
//! 与内核的分工：`meridian-aggregator`（S-10/S-12）负责一切账本执行——WAL 持久化、
//! 幂等 re-ack（同意图重发返回先前 seq）、单调 seq、预算强制、真错误码。本层只保留：
//!   1. 已授权委托的内存表（`total_cap` 给 balance；`agent_pub` 给 EAttestBind 与 attest）；
//!   2. authorize 的 owner 验签与委托字段自洽（探针既有逻辑原样保留）；
//!   3. pay 的占位证明构造（诚实边界，见 README）。
//!
//! 安全模型（Shape 1）：**服务器无任何私钥**。owner secp256k1 / agent Ed25519 密钥都在
//! 框架侧，签名外部完成；本层只验签 + 执行。`SdkClient` 不用在服务器侧（authorize/pay
//! 需要私钥），本层直连 `Aggregator`。
//!
//! 全部字段用内部可变 + 原子：MCP tool handler 是 &self 同步调用，无 async 持有锁，
//! 因此 std::sync::Mutex 足够（不跨 await）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::Signature as AgentSignature;
use ed25519_dalek::VerifyingKey as AgentPubKey;
use meridian_aggregator::ingest::Aggregator;
use meridian_aggregator::receipt::IntentEnvelope;
use meridian_core::attestation::{agent_commit, verify_binding, AttestationPubKey};
use meridian_core::dsa::{
    delegation_hash, verify_delegation, Amount, Delegation, Did, OwnerPubKey, Signature64,
    SignedDelegation, SpendIntent,
};
use meridian_core::error::Error;
use meridian_core::zk::{SpendProof, SpendPublicInputs};

/// 服务器登记的委托：委托本体 + 该 agent 的 Ed25519 传输公钥。
/// （`SignedDelegation` 不含 agent 公钥，EAttestBind / attest 需要它，故单独携带。）
#[derive(Debug, Clone)]
pub struct StoredDelegation {
    pub sd: SignedDelegation,
    pub agent_pub: AgentPubKey,
}

/// 薄 keyless 状态层。
pub struct AppState {
    /// 真实聚合器内核（WAL + 幂等 + seq + 预算）。
    pub(crate) agg: Arc<Aggregator>,
    /// delegation_hash → 已授权委托。绑定在 authorize 时建立。
    delegations: Mutex<HashMap<[u8; 32], StoredDelegation>>,
}

/// 手工 Debug：只暴露规模，不泄内部。
impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field(
                "delegation_count",
                &self.delegations.lock().expect("delegations poisoned").len(),
            )
            .field("accepted_count", &self.agg.accepted_count())
            .finish_non_exhaustive()
    }
}

/// `authorize` 回执（探针字段不变）。
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct AuthorizeReceipt {
    pub delegation_hash: String,
    pub agent: String,
    pub owner: String,
    pub nonce: u64,
    pub max_per_spend: Amount,
    pub total_cap: Amount,
}

/// `pay` 回执（S-13 新形态：内核对齐——seq = 入承诺的单调摄取序号）。
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct PayReceipt {
    pub intent_hash: String,
    pub seq: u64,
    pub spend_nonce: u64,
}

/// `balance` 回执（total_cap 来自 authorize 内存表；total_spent 来自聚合器）。
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct BalanceReceipt {
    pub delegation_hash: String,
    pub total_spent: u64,
    pub total_cap: Amount,
    pub remaining: u64,
}

/// `attest` 回执（双钥绑定凭据，S-05）。
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct AttestReceipt {
    pub delegation_hash: String,
    pub pk_x: String,
    pub pk_y: String,
    pub agent_commit: String,
    pub binding: String,
}

/// `verify_receipt` 结果（只读、infallible：拒绝 / 未知同报 accepted=false）。
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct VerifyReceiptResult {
    pub delegation_hash: String,
    pub spend_nonce: u64,
    pub intent_hash: String,
    pub accepted: bool,
    pub seq: u64,
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
    pub fn new(agg: Arc<Aggregator>) -> Self {
        Self {
            agg,
            delegations: Mutex::new(HashMap::new()),
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
    /// 注册表交叉检查：若本地表缺省但聚合器注册表已有（未来 restore_from_wal 后），
    /// 同样强制 EAttestBind。
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
            // 已注册且同一 agent → 幂等返回（不再重复 register）。
            return Ok(receipt_from(&existing.sd.delegation));
        }

        // 本地表缺省 → 查聚合器注册表（跨重启兜底；本步 WAL 只追加，两表本就在同步）。
        if let Some(reg) = self.agg.registered(&dh) {
            if reg.agent_pub.as_bytes() != agent_pub.as_bytes() {
                return Err(Error::EAttestBind);
            }
        }

        let sd = SignedDelegation {
            delegation: delegation.clone(),
            signature: *owner_sig,
        };
        self.agg.register(sd.clone(), *agent_pub);
        map.insert(
            dh,
            StoredDelegation {
                sd,
                agent_pub: *agent_pub,
            },
        );

        Ok(receipt_from(delegation))
    }

    /// 执行一笔支付（meridian.pay）。
    ///
    /// 由服务器用占位证明构造信封（诚实边界，见 README），`Aggregator::submit` 执行
    /// 全部闸口：幂等 re-ack（S-12，同意图重发返回先前 seq）→ 过期 → 注册表 →
    /// 撤销 → agent 绑定 → Ed25519 验签 → 证明 → 公共输入一致 → 窗口预留 → 预算 → WAL。
    /// 回执映射：accepted → {intent_hash, seq, spend_nonce}；rejected → 错误码透传。
    pub fn pay(&self, intent: &SpendIntent, sig: &AgentSignature) -> Result<PayReceipt, Error> {
        let env = IntentEnvelope {
            intent: intent.clone(),
            agent_sig: *sig,
            proof: Self::build_proof(intent),
        };
        let r = self.agg.submit(&env);
        if r.accepted {
            Ok(PayReceipt {
                intent_hash: hex_hash(&r.intent_hash),
                seq: r.seq,
                spend_nonce: intent.spend_nonce,
            })
        } else {
            Err(r.reject_reason.unwrap_or(Error::EProof))
        }
    }

    /// 查询委托剩余额度（meridian.balance）。
    pub fn balance(&self, dh: &[u8; 32]) -> Result<BalanceReceipt, Error> {
        let stored = self
            .delegations
            .lock()
            .expect("delegations poisoned")
            .get(dh)
            .cloned()
            .ok_or(Error::EDelegUnknown)?;
        let total_cap = stored.sd.delegation.total_cap;
        // 已注册委托在聚合器侧 provision → total_spent 必为 Some（从未支付为 0）。
        let total_spent = self.agg.total_spent(dh).unwrap_or(0);
        Ok(BalanceReceipt {
            delegation_hash: hex_hash(dh),
            total_spent,
            total_cap,
            remaining: total_cap.saturating_sub(total_spent),
        })
    }

    /// 双钥绑定凭据（meridian.attest，S-05）。
    ///
    /// agent Ed25519（authorize 时绑定到 dh）对 BabyJubJub attestation 公钥做绑定签名；
    /// 服务器重算 `agent_commit = sha256(x_le ‖ y_le)` 并用存储的 agent_pub 验签。
    pub fn attest(
        &self,
        dh: &[u8; 32],
        pk: &AttestationPubKey,
        binding: &AgentSignature,
    ) -> Result<AttestReceipt, Error> {
        let stored = self
            .delegations
            .lock()
            .expect("delegations poisoned")
            .get(dh)
            .cloned()
            .ok_or(Error::EDelegUnknown)?;
        let commit = agent_commit(pk);
        verify_binding(&stored.agent_pub, pk, binding, &commit)?;
        Ok(AttestReceipt {
            delegation_hash: hex_hash(dh),
            pk_x: hex::encode(pk.x),
            pk_y: hex::encode(pk.y),
            agent_commit: hex::encode(commit),
            binding: hex::encode(binding.to_bytes()),
        })
    }

    /// 只读确认（meridian.verify_receipt）：`(dh, spend_nonce, intent_hash)` 是否已被
    /// 接受及 seq。拒绝（预算拒）与未知同报 accepted=false（infallible）。
    pub fn verify_receipt(
        &self,
        dh: &[u8; 32],
        spend_nonce: u64,
        intent_hash: &[u8; 32],
    ) -> VerifyReceiptResult {
        let seq = self.agg.accepted_seq(dh, spend_nonce, *intent_hash);
        VerifyReceiptResult {
            delegation_hash: hex_hash(dh),
            spend_nonce,
            intent_hash: hex_hash(intent_hash),
            accepted: seq.is_some(),
            seq: seq.unwrap_or(0),
        }
    }

    /// 占位证明（诚实边界，见 README D3）：proof 非空 + 公共输入从 intent 派生。
    /// `agent_commit` / `revocation_root` = [0;32]（TEMPORARY），`now` = unix。
    /// `FormatVerifier` 只查 proof 非空 + 公共输入与 intent 一致（`check_public_inputs_consistent`），
    /// 不查这两项 → 占位成立。真 S-09 prover 插 `SpendVerifier` 同缝，pay 不改。
    fn build_proof(intent: &SpendIntent) -> SpendProof {
        SpendProof {
            proof: vec![0x00, 0x01, 0x02],
            public_inputs: SpendPublicInputs {
                agent_commit: [0u8; 32],
                delegation_hash: intent.delegation_hash,
                recipient: intent.recipient,
                amount: intent.amount,
                category: intent.category,
                spend_nonce: intent.spend_nonce,
                expires_at: intent.expires_at,
                revocation_root: [0u8; 32],
                now: now_unix(),
            },
        }
    }
}

fn receipt_from(d: &Delegation) -> AuthorizeReceipt {
    AuthorizeReceipt {
        delegation_hash: hex_hash(&delegation_hash(d)),
        agent: hex_did(&d.agent),
        owner: hex_did(&d.owner),
        nonce: d.nonce,
        max_per_spend: d.max_per_spend,
        total_cap: d.total_cap,
    }
}
