//! Meridian agent SDK（S-12）。
//!
//! 独立 agent 进程集成层：封装 core 密码学原语 + 聚合器摄取管线，暴露三个高层操作——
//! [`SdkClient::authorize`]（注册委托）、[`SdkClient::pay`]（幂等支付）、
//! [`SdkClient::attest`]（双钥绑定凭据）。错误码透传（`Error::as_code`），供 agent
//! 把拒绝原因原样转达给上层策略。
//!
//! # 幂等重试契约（"断线重试不产生双花"）
//!
//! - 每笔逻辑支付取**固定 nonce**，整个重试周期不复用、不推进；只有聚合器返回**定局**
//!   （accepted 或永久拒绝）后，下一笔才拿新 nonce（[`NonceManager`]）。
//! - 仅传输错误（[`SdkError::Transport`]）触发重试；聚合器的业务拒绝（[`SdkError::Meridian`]）
//!   永不重试。
//! - **聚合器侧幂等**（S-12 配合改动，`aggregator` 的 nonce 记录）：同一 intent（同 nonce +
//!   同 `intent_hash`）的重发返回先前结果——accepted → 原 seq，拒绝 → 原原因。因此断线重发
//!   绝不会把同一笔意图记两次（双花），也绝不会把一笔被拒绝的意图透传成成功。
//!
//! # 传输形态
//!
//! [`Transport`] trait 抽象「聚合器连接」。S-12 提供 [`InProcessAggregator`]（进程内聚合器，
//! 测试与单进程嵌入用）；网络传输是 S-13 框架分发层的接缝。
//!
//! # 诚实边界
//!
//! - 证明 = [`PlaceholderProver`]（proof 非空 + 公共输入与信封一致），与聚合器内置的
//!   `FormatVerifier`（TEMPORARY）配套。真实 S-09 电路 prover 实现 `SpendProver` 接入。
//! - `NonceManager` 为进程内单调计数；进程崩溃后不持久化——重启后经 [`SdkClient::sync_nonce`]
//!   （S-31，聚合器 `GET /v1/nonce` 查询，§6.7）恢复计数再继续支付。

pub mod attest;
pub mod authorize;
pub mod error;
pub mod identity;
pub mod pay;
pub mod transport;
pub mod transport_http;
pub mod x402;

pub use error::{SdkError, TransportError};
pub use identity::{owner_did, AgentWallet, DelegationLimits};
pub use meridian_aggregator::receipt::Receipt;
pub use pay::{NonceManager, PayParams, PayReceipt, RetryPolicy};
pub use transport::{DropFirstTransport, InProcessAggregator, ResponseLossTransport, Transport};
pub use transport_http::HttpTransport;
pub use x402::{
    base64url_encode, category_from_resource, Eip3009Extra, Fetch, HttpFetch, MeridianPayload,
    PaymentPayload, PaymentRequired, PaymentRequirements, ResourceRequest, ResourceResponse,
    X402Client, X402Outcome, X402Proof,
};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use meridian_core::attestation::AttestationPubKey;
use meridian_core::dsa::{Did, SignedDelegation};
use meridian_core::zk::SpendProver;

use crate::attest::AttestationCredential;
use crate::authorize::AuthorizeReceipt;

/// 聚合器响应式客户端。所有方法 `&self`（内部可变），可跨线程共享。
pub struct SdkClient {
    wallet: AgentWallet,
    transport: Box<dyn Transport>,
    prover: Box<dyn SpendProver + Send + Sync>,
    /// 每委托的单调 nonce（仅定局后推进）。
    nonces: NonceManager,
    /// 委托授权计数（delegation.nonce，防重放）。
    delegation_nonce: AtomicU64,
    /// 已授权委托：delegation_hash → (agent DID, SignedDelegation)。
    /// agent DID 供 pay 构造 intent（`intent.agent == delegation.agent` 绑定）；
    /// SignedDelegation 供 prover 引用（S-09 电路入参）。
    authorized: RwLock<HashMap<[u8; 32], (Did, SignedDelegation)>>,
    /// 重试策略（仅传输错误触发）。
    retry: RetryPolicy,
}

impl SdkClient {
    /// 默认占位 prover（与聚合器 `FormatVerifier` 配套）。
    pub fn new(wallet: AgentWallet, transport: Box<dyn Transport>) -> Self {
        Self::with_prover(wallet, transport, Box::new(crate::pay::PlaceholderProver))
    }

    /// 显式 prover（真实 S-09 电路后端实现 `SpendProver`）。
    pub fn with_prover(
        wallet: AgentWallet,
        transport: Box<dyn Transport>,
        prover: Box<dyn SpendProver + Send + Sync>,
    ) -> Self {
        SdkClient {
            wallet,
            transport,
            prover,
            nonces: NonceManager::new(),
            delegation_nonce: AtomicU64::new(1),
            authorized: RwLock::new(HashMap::new()),
            retry: RetryPolicy::default(),
        }
    }

    /// 覆盖重试策略。
    pub fn set_retry(&mut self, policy: RetryPolicy) {
        self.retry = policy;
    }

    /// 注册一张委托（authorize）。
    ///
    /// owner（`owner_key`）对 delegation 的 secp256k1 签名（低位 s，由 core 保证），本地
    /// 校验后经传输注册。agent DID 由调用方提供（与钱包 Ed25519 公钥一同绑定到该委托）。
    ///
    /// 幂等：同 delegation_hash（同一 delegation.nonce）重复注册返回既有回执。每次调用分配
    /// 新 delegation nonce → 是新的授权（新 dh），不是同委托覆盖。
    pub fn authorize(
        &self,
        owner_key: &k256::ecdsa::SigningKey,
        agent: Did,
        limits: &DelegationLimits,
    ) -> Result<AuthorizeReceipt, SdkError> {
        crate::authorize::authorize(
            &self.wallet,
            &*self.transport,
            owner_key,
            agent,
            limits,
            self.delegation_nonce.fetch_add(1, Ordering::Relaxed),
            &self.authorized,
        )
    }

    /// 幂等支付：固定 nonce + 幂等重试（见 crate 文档）。
    ///
    /// `Ok` = 已被聚合器接受（含断线后重发的 re-ack，返回原 seq）。`Err` 见 [`SdkError`]；
    /// 业务拒绝的错误码经 `Error::as_code` 透传。
    pub fn pay(&self, params: &PayParams) -> Result<PayReceipt, SdkError> {
        crate::pay::pay(self, params)
    }

    /// 双钥绑定凭据（S-05）：钱包 Ed25519 对 attestation 公钥的绑定签名 + `agent_commit`。
    /// 产出后自校验（防构造错误）；注册进电路是 ZK 集成（S-13+）的接缝。
    pub fn attest(&self, pk: &AttestationPubKey) -> Result<AttestationCredential, SdkError> {
        crate::attest::attest(&self.wallet, pk)
    }

    /// 已授权委托数（观测 / 测试）。
    pub fn authorized_count(&self) -> usize {
        self.authorized.read().expect("authorized poisoned").len()
    }

    pub(crate) fn wallet(&self) -> &AgentWallet {
        &self.wallet
    }

    pub(crate) fn transport(&self) -> &dyn Transport {
        &*self.transport
    }

    pub(crate) fn prover(&self) -> &(dyn SpendProver + Send + Sync) {
        &*self.prover
    }

    pub(crate) fn retry(&self) -> &RetryPolicy {
        &self.retry
    }

    pub(crate) fn agent_for(&self, dh: &[u8; 32]) -> Result<Did, SdkError> {
        self.authorized
            .read()
            .expect("authorized poisoned")
            .get(dh)
            .map(|(agent, _)| *agent)
            .ok_or_else(|| {
                SdkError::Local("delegation not authorized — call authorize() first".into())
            })
    }

    pub(crate) fn signed_delegation_for(
        &self,
        dh: &[u8; 32],
    ) -> Result<SignedDelegation, SdkError> {
        self.authorized
            .read()
            .expect("authorized poisoned")
            .get(dh)
            .map(|(_, sd)| sd.clone())
            .ok_or_else(|| {
                SdkError::Local("delegation not authorized — call authorize() first".into())
            })
    }

    pub(crate) fn next_nonce(&self, dh: &[u8; 32]) -> u64 {
        self.nonces.next(dh)
    }

    /// S-31 跨重启 nonce 恢复（§6.6）：查询聚合器（`GET /v1/nonce`，§6.7）并把本地
    /// [`NonceManager`] 推进到 `max(本地, 网关值)`，返回生效值。重启后**先调用本方法再
    /// 继续 `pay()`**——否则新支付从 nonce 0 起，与已消耗集冲突（§6.2 `E_NONCE` 拒绝，
    /// 不双花但不可用）。
    ///
    /// 单进程不重启场景无需调用（`pay()` 语义不变）。本地领先时网关值被忽略——并发
    /// 多客户端时各自单调推进，互不回退。未授权委托 → `SdkError::Local`（与 `pay()`
    /// 前置闸一致）。传输失败按 `SdkError::Transport` 上抛（重试候选）。
    pub fn sync_nonce(&self, dh: &[u8; 32]) -> Result<u64, SdkError> {
        // 先验授权上下文：与 pay() 同一前置闸，未授权委托不产生查询。
        self.agent_for(dh)?;
        let remote = self
            .transport
            .next_nonce(dh)?
            .ok_or_else(|| SdkError::Local("delegation not registered on aggregator".into()))?;
        Ok(self.nonces.resync(dh, remote))
    }
}

impl std::fmt::Debug for SdkClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SdkClient")
            .field("wallet", &self.wallet)
            .field(
                "authorized_count",
                &self.authorized.read().expect("authorized poisoned").len(),
            )
            .finish_non_exhaustive()
    }
}
