//! 聚合器连接抽象（S-12）。
//!
//! [`Transport`] 把「聚合器长什么样」从 SDK 逻辑中解耦：`pay` 的重试/幂等只看
//! [`SdkError`]，不关心底层是进程内调用还是网络 RPC。S-12 提供 [`InProcessAggregator`]
//! （进程内聚合器，测试与单进程嵌入）；网络传输是 S-13 框架分发层的接缝。
//!
//! 断线模拟（测试用）：
//! - [`DropFirstTransport`]：请求**从未送达**（内层不被调用）。
//! - [`ResponseLossTransport`]：请求**已送达**（聚合器已处理——可能已接受或已拒绝），
//!   但回执丢失——正是幂等重试要兜的场景。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use mist_aggregator::ingest::{Aggregator, IngestConfig};
use mist_aggregator::receipt::{IntentEnvelope, Receipt};
use mist_aggregator::wal::Wal;
use mist_core::dsa::{AgentPubKey, SignedDelegation};
use mist_core::zk::{RevocationWitness, SpendVerifier};

use crate::error::{SdkError, TransportError};

/// 聚合器连接。`pay` 重试只对 [`SdkError::Transport`] 触发；写方法都应在定局时返回
/// `Ok`（含聚合器的业务拒绝 `Receipt`，由 SDK 映射为错误码）——传输失败才返回 `Err(Transport)`。
pub trait Transport: Send + Sync {
    /// 注册委托（authorize 后端）。定局返回 `Ok(())`；传输失败 `Err(Transport)`。
    fn authorize(&self, sd: SignedDelegation, agent_pub: AgentPubKey) -> Result<(), SdkError>;

    /// 提交意图信封（pay 后端）。聚合器侧幂等：同意图重发返回先前结果（accepted → 原 seq，
    /// 拒绝 → 原原因）。`Ok(receipt)` 即定局；`Err(Transport)` 是重试候选。
    fn submit(&self, env: &IntentEnvelope) -> Result<Receipt, SdkError>;

    /// S-31 只读下一 nonce 查询（§6.7，[`crate::pay::NonceManager`] 跨重启恢复）。
    /// `Ok(None)` = 委托未注册（404 `E_NOT_FOUND`）。
    fn next_nonce(&self, dh: &[u8; 32]) -> Result<Option<u64>, SdkError>;

    /// S-45 只读撤销非成员 witness 查询（§6.7，§6.14 诚实边界 3 SDK 半边）：目标 dh 的
    /// `root` + 深度 256 兄弟路径（聚合器当刻撤销树快照，同一棵确定性树）。
    /// `Ok(None)` = 目标已撤销（404 `E_REVOKED`——成员陈述不属于非成员接口，S-42
    /// fail-closed）；其余传输错误按 `SdkError` 语义上抛。
    fn revocation_witness(&self, dh: &[u8; 32]) -> Result<Option<RevocationWitness>, SdkError>;
}

/// 进程内聚合器（S-12 内置传输）。
pub struct InProcessAggregator {
    agg: Arc<Aggregator>,
}

impl InProcessAggregator {
    /// 包一层进程内聚合器（调用方提供 WAL 落盘路径）。
    pub fn new(
        cfg: IngestConfig,
        verifier: Box<dyn SpendVerifier + Send + Sync>,
        wal: Wal,
    ) -> Self {
        InProcessAggregator {
            agg: Arc::new(Aggregator::new(cfg, verifier, wal)),
        }
    }

    /// 用既有 Arc 包装（测试需要外部句柄观测聚合器状态时用）。
    pub fn from_inner(agg: Arc<Aggregator>) -> Self {
        InProcessAggregator { agg }
    }

    /// 对内部聚合器的只读访问（测试 / 观测：total_spent、accepted_count、nonce_count…）。
    pub fn inner(&self) -> &Aggregator {
        &self.agg
    }
}

impl std::fmt::Debug for InProcessAggregator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessAggregator")
            .field("accepted_count", &self.agg.accepted_count())
            .finish_non_exhaustive()
    }
}

impl Transport for InProcessAggregator {
    fn authorize(&self, sd: SignedDelegation, agent_pub: AgentPubKey) -> Result<(), SdkError> {
        self.agg.register(sd, agent_pub);
        Ok(())
    }

    fn submit(&self, env: &IntentEnvelope) -> Result<Receipt, SdkError> {
        Ok(self.agg.submit(env))
    }

    fn next_nonce(&self, dh: &[u8; 32]) -> Result<Option<u64>, SdkError> {
        Ok(self.agg.next_nonce(dh))
    }

    fn revocation_witness(&self, dh: &[u8; 32]) -> Result<Option<RevocationWitness>, SdkError> {
        Ok(self.agg.revocation_witness(dh).map(Into::into))
    }
}

/// 断线模拟：丢弃前 `drop_count` 次 `submit` 响应（回执丢失，聚合器侧可能已接受）。
/// 模拟的是「发送成功、响应丢失」——不是请求失败，因此不带重放。
#[derive(Debug)]
pub struct DropFirstTransport<T> {
    inner: T,
    drop_before: AtomicUsize,
}

impl<T: Transport> DropFirstTransport<T> {
    /// 丢弃前 `drop_count` 次 submit 的响应。
    pub fn new(inner: T, drop_count: usize) -> Self {
        DropFirstTransport {
            inner,
            drop_before: AtomicUsize::new(drop_count),
        }
    }
}

impl<T: Transport> Transport for DropFirstTransport<T> {
    fn authorize(&self, sd: SignedDelegation, agent_pub: AgentPubKey) -> Result<(), SdkError> {
        self.inner.authorize(sd, agent_pub)
    }

    fn submit(&self, env: &IntentEnvelope) -> Result<Receipt, SdkError> {
        // 只在剩余 > 0 时递减并丢弃（fetch_sub 会回绕到 usize::MAX，须 clamp）。
        if self
            .drop_before
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(SdkError::Transport(TransportError::Disconnected));
        }
        self.inner.submit(env)
    }

    // 只读查询：丢弃语义只针对 submit（nonce / witness 查询本就无副作用，直通内层）。
    fn next_nonce(&self, dh: &[u8; 32]) -> Result<Option<u64>, SdkError> {
        self.inner.next_nonce(dh)
    }

    fn revocation_witness(&self, dh: &[u8; 32]) -> Result<Option<RevocationWitness>, SdkError> {
        self.inner.revocation_witness(dh)
    }
}

/// 断线模拟：前 `lose_before` 次 `submit` **先送达内层**（聚合器已处理），再把回执丢弃，
/// 返回 `Disconnected`。模拟「聚合器已接受 / 已拒绝、回执丢失」——幂等重试的核心场景。
#[derive(Debug)]
pub struct ResponseLossTransport<T> {
    inner: T,
    lose_before: AtomicUsize,
}

impl<T: Transport> ResponseLossTransport<T> {
    /// 丢弃前 `lose_before` 次 submit 的**回执**（内层照常处理）。
    pub fn new(inner: T, lose_before: usize) -> Self {
        ResponseLossTransport {
            inner,
            lose_before: AtomicUsize::new(lose_before),
        }
    }
}

impl<T: Transport> Transport for ResponseLossTransport<T> {
    fn authorize(&self, sd: SignedDelegation, agent_pub: AgentPubKey) -> Result<(), SdkError> {
        self.inner.authorize(sd, agent_pub)
    }

    fn submit(&self, env: &IntentEnvelope) -> Result<Receipt, SdkError> {
        // 内层先处理（记录定局：accepted → 记 seq / 拒绝 → 记原因）。
        let receipt = self.inner.submit(env)?;
        // 只在剩余 > 0 时递减并丢弃回执（fetch_sub 会回绕到 usize::MAX，须 clamp）。
        if self
            .lose_before
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(SdkError::Transport(TransportError::Disconnected));
        }
        Ok(receipt)
    }

    // 只读查询：丢失语义只针对 submit 回执（nonce / witness 查询无副作用，直通内层）。
    fn next_nonce(&self, dh: &[u8; 32]) -> Result<Option<u64>, SdkError> {
        self.inner.next_nonce(dh)
    }

    fn revocation_witness(&self, dh: &[u8; 32]) -> Result<Option<RevocationWitness>, SdkError> {
        self.inner.revocation_witness(dh)
    }
}

// 两种断线模拟的计数语义在 `tests/e2e.rs` 用真实聚合器验证（需要真实信封，此处不重复
// 构造密钥）。
