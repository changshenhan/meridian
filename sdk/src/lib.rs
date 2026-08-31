//! Mist agent SDK（S-12）。
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
//! - 仅传输错误（[`SdkError::Transport`]）触发重试；聚合器的业务拒绝（[`SdkError::Mist`]）
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
//! - 证明缺省 = [`PlaceholderProver`]（proof 非空 + 公共输入与信封一致），与聚合器内置的
//!   `FormatVerifier`（TEMPORARY）配套；真电路后端 [`crate::prover::NoirProver`] 经
//!   [`SdkClient::with_noir`] 显式接入——同一实例兼作 attestation keyring，
//!   [`SdkClient::attest_identity`] 的凭据承诺与 `pay()` 证明的 agent_commit 同一 secret
//!   单一来源（S-46 同源自洽，曲线数学仍全在 Noir）。
//! - `NonceManager` 为进程内单调计数；进程崩溃后不持久化——重启后经 [`SdkClient::sync_nonce`]
//!   （S-31，聚合器 `GET /v1/nonce` 查询，§6.7）恢复计数再继续支付。

pub mod attest;
pub mod authorize;
pub mod error;
pub mod identity;
pub mod pay;
pub mod prover;
pub mod transport;
pub mod transport_http;
pub mod x402;

pub use error::{SdkError, TransportError};
pub use identity::{owner_did, AgentWallet, DelegationLimits};
pub use mist_aggregator::receipt::Receipt;
pub use pay::{NonceManager, PayParams, PayReceipt, RetryPolicy};
pub use transport::{DropFirstTransport, InProcessAggregator, ResponseLossTransport, Transport};
pub use transport_http::HttpTransport;
pub use x402::{
    base64_decode_flexible, base64_std_encode, base64url_encode, category_from_resource,
    network_canonical, Eip3009Extra, Fetch, HttpFetch, MistPayload, PaymentPayload,
    PaymentPayloadV2, PaymentRequired, PaymentRequiredV2, PaymentRequirements,
    PaymentRequirementsV2, ResourceInfo, ResourceRequest, ResourceResponse, X402Client,
    X402Outcome, X402Proof, PAYMENT_HEADER_V2, PAYMENT_REQUIRED_HEADER, X402_VERSION_V2,
};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use mist_core::attestation::AttestationPubKey;
use mist_core::dsa::{Did, SignedDelegation};
use mist_core::zk::{RevocationWitness, SpendProver};

use crate::attest::AttestationCredential;
use crate::authorize::AuthorizeReceipt;

/// 聚合器响应式客户端。所有方法 `&self`（内部可变），可跨线程共享。
pub struct SdkClient {
    wallet: AgentWallet,
    transport: Box<dyn Transport>,
    prover: Arc<dyn SpendProver + Send + Sync>,
    /// attestation keyring（S-46 同源自洽）：[`crate::prover::NoirProver`] 的 keygen 侧
    /// （公钥派生）。与 `prover` 同一实例（单 `Arc`，进程级互斥共用）→ `attest_identity()`
    /// 派生公钥与 `pay()` 证明的 agent_commit 必然同一 secret（§6.14 诚实边界 2）。
    keyring: Option<Arc<crate::prover::NoirProver>>,
    /// 每委托的单调 nonce（仅定局后推进）。
    nonces: NonceManager,
    /// 委托授权计数（delegation.nonce，防重放）。
    delegation_nonce: AtomicU64,
    /// 已授权委托：delegation_hash → (agent DID, SignedDelegation)。
    /// agent DID 供 pay 构造 intent（`intent.agent == delegation.agent` 绑定）；
    /// SignedDelegation 供 prover 引用（S-09 电路入参）。
    authorized: RwLock<HashMap<[u8; 32], (Did, SignedDelegation)>>,
    /// attestation 私钥标量（S-43，真 prover 用；占位口径全零不消费）。
    attestation_secret: [u8; 32],
    /// 派生公钥缓存（S-46）：按 secret 键控（secret 变更自动重派生），省重复 oracle 进程。
    attested_pk: RwLock<Option<([u8; 32], AttestationPubKey)>>,
    /// 撤销非成员 witness（S-43 手动装配 / S-45 自动现取），按 delegation_hash 分桶
    /// ——witness 是 **per-dh 事实**（路径由目标索引决定），跨委托复用会被电路断言 8
    /// 重算根失配拒。无缓存的委托 = 占位口径（真 prover 以 E_PROVER 拒）。
    revocations: RwLock<HashMap<[u8; 32], RevocationWitness>>,
    /// 重试策略（仅传输错误触发）。
    retry: RetryPolicy,
}

impl SdkClient {
    fn from_parts(
        wallet: AgentWallet,
        transport: Box<dyn Transport>,
        prover: Arc<dyn SpendProver + Send + Sync>,
        keyring: Option<Arc<crate::prover::NoirProver>>,
        attestation_secret: [u8; 32],
    ) -> Self {
        SdkClient {
            wallet,
            transport,
            prover,
            keyring,
            nonces: NonceManager::new(),
            delegation_nonce: AtomicU64::new(1),
            authorized: RwLock::new(HashMap::new()),
            attestation_secret,
            attested_pk: RwLock::new(None),
            revocations: RwLock::new(HashMap::new()),
            retry: RetryPolicy::default(),
        }
    }

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
        Self::from_parts(wallet, transport, Arc::from(prover), None, [0u8; 32])
    }

    /// 真 prover 自洽装配（S-46，§6.14 诚实边界 2）：同一 [`crate::prover::NoirProver`]
    /// 实例同时作为 prove 后端与 attestation keyring（单 `Arc`，进程级互斥共用），
    /// `attestation_secret` 一并落位——`attest_identity()` 派生公钥与 `pay()` 证明的
    /// `agent_commit` **同一 secret 单一来源**（调用方不再手工对齐两处身份）。
    pub fn with_noir(
        wallet: AgentWallet,
        transport: Box<dyn Transport>,
        prover: crate::prover::NoirProver,
        attestation_secret: [u8; 32],
    ) -> Self {
        let prover = Arc::new(prover);
        Self::from_parts(
            wallet,
            transport,
            prover.clone(),
            Some(prover),
            attestation_secret,
        )
    }

    /// 配置 attestation 私钥标量（S-43：真 prover 的曲线身份来源；Rust 侧不透明字节）。
    pub fn set_attestation_secret(&mut self, secret: [u8; 32]) {
        self.attestation_secret = secret;
    }

    /// 配置某委托的撤销非成员 witness（S-43：聚合器 `RevocationSet::non_membership_witness`
    /// 直出；S-45 起按 delegation_hash 分桶——witness 是 per-dh 事实，跨委托复用会被
    /// 电路断言 8 重算根失配拒）。
    ///
    /// 新鲜度（S-45）：`pay()` 对无缓存的委托自动现取（§6.7 witness 查询端点），被
    /// `E_REV_ROOT` 拒（绑定闸开启 + witness 取自重启前的中间状态等窄窗口）时自动
    /// 刷新重出（§6.14 诚实边界 3）。本方法保留给离线 / 测试口径的显式注入。
    pub fn set_revocation_witness(&mut self, dh: [u8; 32], w: RevocationWitness) {
        self.revocations
            .write()
            .expect("revocations poisoned")
            .insert(dh, w);
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
    ///
    /// 显式公钥口径：离线 / 外部注册流（如 mcp-server）传入外部持有的
    /// `AttestationPubKey`。真 prover 路径请用 [`Self::attest_identity`]——公钥从
    /// `attestation_secret` 经 Noir 曲线 oracle 派生，与 `pay()` 证明的 agent_commit
    /// 同一来源（S-46 同源自洽）。
    pub fn attest(&self, pk: &AttestationPubKey) -> Result<AttestationCredential, SdkError> {
        crate::attest::attest(&self.wallet, pk)
    }

    /// attestation 公钥（S-46 同源派生）：从 `attestation_secret` 经 Noir 曲线 oracle
    /// 派生（keygen，`NoirProver::attestation_pubkey`，§6.14 诚实边界 2 收口）。keyring
    /// 未装配（[`Self::new`] / [`Self::with_prover`]）→ `SdkError::Local`；派生结果按
    /// secret 键控缓存（`set_attestation_secret` 变更后自动重派生，不回陈旧公钥）。
    pub fn attestation_pubkey(&self) -> Result<AttestationPubKey, SdkError> {
        let keyring = self.keyring.as_ref().ok_or_else(|| {
            SdkError::Local(
                "attestation keyring 未装配：用 SdkClient::with_noir 装配 NoirProver，\
                 或显式 attest(&pk)"
                    .into(),
            )
        })?;
        let secret = self.attestation_secret;
        if let Some((s, pk)) = self.attested_pk.read().expect("attested poisoned").as_ref() {
            if *s == secret {
                return Ok(*pk);
            }
        }
        let pk = keyring.attestation_pubkey(secret).map_err(SdkError::Mist)?;
        *self.attested_pk.write().expect("attested poisoned") = Some((secret, pk));
        Ok(pk)
    }

    /// 双钥绑定凭据（S-46 同源自洽，§6.14 诚实边界 2 收口）：attestation 公钥从
    /// `attestation_secret` 经 Noir 曲线 oracle 派生（keygen），绑定签名与承诺出自同一把
    /// 电路签名身份——`pay()` 经真 prover 产出的证明公共输入 `agent_commit` 与本凭据
    /// **同一 secret 单一来源**（本件之前该同源性由调用方手工保证）。keyring 未装配 →
    /// `SdkError::Local`（离线 / 外部注册流用显式 [`Self::attest`]）。
    pub fn attest_identity(&self) -> Result<AttestationCredential, SdkError> {
        let pk = self.attestation_pubkey()?;
        crate::attest::attest(&self.wallet, &pk)
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

    pub(crate) fn attestation_secret(&self) -> [u8; 32] {
        self.attestation_secret
    }

    /// 撤销 witness（S-43/S-45）：无缓存 = 占位口径（`root` 全零 + 空 path），只够
    /// `PlaceholderProver` 用——真 prover 会以 `E_PROVER` 拒绝（fail-closed）。缓存的
    /// 新鲜度由 [`crate::pay::pay`] 维护（未命中现取 + `E_REV_ROOT` 刷新）。
    pub(crate) fn revocation_witness_for(&self, dh: &[u8; 32]) -> Option<RevocationWitness> {
        self.revocations
            .read()
            .expect("revocations poisoned")
            .get(dh)
            .cloned()
    }

    pub(crate) fn store_revocation_witness(&self, dh: &[u8; 32], w: RevocationWitness) {
        self.revocations
            .write()
            .expect("revocations poisoned")
            .insert(*dh, w);
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
    /// 继续 `pay()`**——否则新支付从 nonce 1 起，与已消耗集冲突（§6.2 `E_NONCE` 拒绝，
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

    /// S-45 撤销 witness 显式刷新（镜像 [`Self::sync_nonce`] 口径，§6.7 / §6.14 诚实
    /// 边界 3）：查询聚合器当刻撤销树快照（`GET /v1/revocation-witness`）并入库，返回
    /// 该 witness。`pay()` 对无缓存的委托会自动现取，被 `E_REV_ROOT` 拒时也会自动刷新
    /// 重出——本方法供调用方在 prove 前主动取新鲜度（离线装配 / 观测 / 预热）。
    ///
    /// `Ok(None)` = 目标已撤销（`E_REVOKED`）——无非成员 witness 可得，缓存不动（后续
    /// `pay()` 走管线步 2b `E_REVOKED` 定局）。传输失败按 `SdkError::Transport` 上抛。
    pub fn sync_revocation_witness(
        &self,
        dh: &[u8; 32],
    ) -> Result<Option<RevocationWitness>, SdkError> {
        // 先验授权上下文：与 pay() 同一前置闸，未授权委托不产生查询。
        self.agent_for(dh)?;
        match self.transport.revocation_witness(dh)? {
            Some(w) => {
                self.store_revocation_witness(dh, w.clone());
                Ok(Some(w))
            }
            None => Ok(None),
        }
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
