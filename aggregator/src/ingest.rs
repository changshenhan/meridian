//! Ingest 管线（TECH_SPEC §6.2，MASTER_PLAN S-10）。
//!
//! `Aggregator::submit(env) -> Receipt` 快路径，顺序（§6.2 一致，S-12 增幂等闸口）：
//! 幂等重发（S-12：同意图同 nonce 已被接受 → 直接返回既有 seq，**最先**——重发时信封可能
//! 已过期，过期意图仍是已接受意图，不能诱发 SDK 用新 nonce 重发 → 双花）→ 意图有效期 →
//! 委托查表（未注册拒 `E_DELEG_UNKNOWN`）→ agent 绑定 → Ed25519 验签（证明前的廉价 DoS
//! 闸门）→ **运营者绑定闸（S-62 步 4b，§6.19.2：绑他方拒 `E_OPERATOR` / 未绑定放行 /
//! 读面不可得 `E_BIND_BACKEND`，不可变绑定读缓存）** → 验证明（`SpendVerifier`，登记以返回值为准）→ 公共输入与信封一致性 → 预留窗口槽
//! → nonce 去重 + 幂等 + 预算检查记账（分片锁内**分配 seq**）→ 定稿（accepted 才入承诺）→
//! WAL 追加 → 满窗即封。已封 epoch 由 `process_pending` 结算（`lattice::build_epoch`：
//! 承诺根/净额/净额根 + WAL EpochSeal/Netting 记录 + 上链 seam）。
//!
//! 并发一致性（关键不变量）：
//! - **同委托内 seq 序 == 账本应用序**：seq 在 `try_commit` 的分片锁内 `fetch_add`——同委托
//!   的两个意图在分片锁上串行，先提交者先拿 seq。WAL 重放按 seq 排序即可**精确**重建每委托
//!   的 nonce 集与 BudgetState（含窗口回滚边界），崩溃恢复后账本与 accepted 前缀一致
//!   （S-10c 验收）。
//! - **无回滚**：窗口槽在预算记账**之前**预留（`reserve` → `try_commit`）；预算拒只
//!   `finalize(rejected)`，不需要滚任何已提交状态。
//! - **无丢失**：满窗 / 已密封时 `reserve` 内部换新窗口整链重试（预算还没应用，无副作用）。
//!
//! B8 容量预置：`register` 时 provision 分片条目（预算零态 + 预置 nonce 记录集）；稳态
//! `try_commit` 的 `entry` 查找与 nonce 记录插入都在容量内 → 零分配。
//! WAL 失败 panic（持久化骨干，不可降级）。

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use meridian_core::dsa::{
    delegation_hash, intent_hash, verify_intent, AgentPubKey, Delegation, SignedDelegation,
};
use meridian_core::error::Error;
use meridian_core::ledger::{check_budget, BudgetState};
use meridian_core::zk::SpendVerifier;

use crate::health::HealthSnapshot;
use crate::hist::LatencyHistogram;
use crate::lattice::{ChainPublisher, EpochResult, NoopPublisher};
use crate::proof::check_public_inputs_consistent;
use crate::receipt::{IntentEnvelope, Receipt};
use crate::revocation::{NonMembershipWitness, RevocationSet};
use crate::wal::{DecodedRecord, Wal};
use crate::window::{EpochWindow, WindowEntry};

/// 意图索引条目：intent_hash → (recipient, amount, seq)。净额解析源（§6.3 步骤 D，
/// resolve 闭包忽略 seq）；seq 供只读回执查询（S-30a `receipt()`）。
type IntentRef = ([u8; 20], u64, u64);
/// WAL 重放的已接受意图元组：
/// (seq, intent_hash, delegation_hash, spend_nonce, amount, now, recipient)。
type ReplayIntent = (u64, [u8; 32], [u8; 32], u64, u64, u64, [u8; 20]);

/// 摄取配置。
#[derive(Debug, Clone)]
pub struct IngestConfig {
    /// 账本（nonce + 预算）分片数。
    pub ledger_shards: usize,
    /// epoch 窗口容量（收满即封）。
    pub epoch_capacity: usize,
    /// epoch 时长（秒；到时未满也封）。
    pub epoch_secs: u64,
    /// WAL 批量 fsync 阈值（条）。
    pub wal_sync_every: usize,
    /// 每委托 nonce 集容量预置（B8 零分配的关键，`register` 时 provision）。
    pub nonce_capacity_per_delegation: usize,
    /// 撤销根绑定闸（S-44，TECH_SPEC §6.2 / §4.6 残余③）：`true` 时证明公共输入
    /// `revocation_root` 必须 ∈ 撤销状态根集合（本账本出现过的全部撤销状态根），否则
    /// `E_REV_ROOT` 拒——自选根（空根 / 伪造根）的装饰性 ZK 收口。缺省 `false`：占位
    /// prover 口径不动（占位 witness 的根无语义），装配真验证后端（§6.13 `BbVerifier`）
    /// 时必须同步置 `true`（与 §6.13 / §6.14「生产默认不动，真后端显式开启」同口径）。
    pub enforce_revocation_root: bool,
}

impl IngestConfig {
    /// S-15 生产默认（文档化起点，按负载调优，见 docs/ops.md §拓扑与调优）：
    /// - `ledger_shards 32`：多核并发分片（吞吐随核数扩展）。
    /// - `epoch_capacity 1_000_000`：百万笔/epoch，对齐运营结算节奏。
    /// - `wal_sync_every 10_000`：万笔一批 fsync 摊薄磁盘 I/O；崩溃丢失窗口 = 至多
    ///   一个批量（标准 WAL 语义，S-10c）。
    /// - `nonce_capacity_per_delegation 4_096`：每委托一次性预置（稳态零分配）。
    pub fn production() -> Self {
        IngestConfig {
            ledger_shards: 32,
            epoch_capacity: 1_000_000,
            epoch_secs: 60,
            wal_sync_every: 10_000,
            nonce_capacity_per_delegation: 4_096,
            enforce_revocation_root: false,
        }
    }
}

impl Default for IngestConfig {
    fn default() -> Self {
        IngestConfig {
            ledger_shards: 64,
            epoch_capacity: 100_000,
            epoch_secs: 10,
            wal_sync_every: 1_000,
            nonce_capacity_per_delegation: 4_096,
            enforce_revocation_root: false,
        }
    }
}

// ---------------------------------------------------------------------------
// 委托注册表
// ---------------------------------------------------------------------------

/// 注册表中的委托条目：委托本体 + agent 的 Ed25519 公钥（验签快路径密钥）。
#[derive(Debug, Clone)]
pub struct RegisteredDelegation {
    pub delegation: Delegation,
    pub agent_pub: AgentPubKey,
}

/// 委托注册表：delegation_hash → 条目。读多写少，`RwLock`。
pub struct DelegationRegistry {
    map: RwLock<HashMap<[u8; 32], RegisteredDelegation>>,
}

impl DelegationRegistry {
    pub fn new() -> Self {
        DelegationRegistry {
            map: RwLock::new(HashMap::new()),
        }
    }

    /// 插入 / 覆盖。返回 `true` 表示新插入。
    pub fn register(&self, dh: [u8; 32], reg: RegisteredDelegation) -> bool {
        self.map
            .write()
            .expect("registry poisoned")
            .insert(dh, reg)
            .is_none()
    }

    pub fn lookup(&self, dh: &[u8; 32]) -> Option<RegisteredDelegation> {
        self.map.read().expect("registry poisoned").get(dh).cloned()
    }

    pub fn len(&self) -> usize {
        self.map.read().expect("registry poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.read().expect("registry poisoned").is_empty()
    }
}

impl Default for DelegationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// 账本分片（nonce 去重 + 预算记账）
// ---------------------------------------------------------------------------

/// 每 nonce 的结果（S-12 幂等重发返回，不透传成成功 / 不重复记账）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonceOutcome {
    /// 已接受：记住 seq（同意图重发返回同一 seq，不重复分配 / 不重复扣预算）。
    Accepted { seq: u64 },
    /// 已拒绝（nonce 已消耗，§6.2 不复用）：同意图重发原样返回原因。
    Rejected(Error),
}

/// nonce 记录：intent_hash 区分「同意图重发」vs「跨意图复用」（§6.2 禁止）。
#[derive(Debug, Clone, Copy)]
struct NonceState {
    intent_hash: [u8; 32],
    outcome: NonceOutcome,
}

/// 每委托的账本状态：预算 + nonce 记录（去重 + 幂等）。
struct DelegationLedgerState {
    budget: BudgetState,
    nonces: HashMap<u64, NonceState>,
}

/// 并发分片账本：键 = delegation_hash。每分片一把锁，串行化同委托的 nonce + 预算 + seq。
pub struct ShardedState {
    shards: Vec<Mutex<HashMap<[u8; 32], DelegationLedgerState>>>,
}

/// 分片键：delegation_hash 前 4 字节（BE）取模。哈希均匀 → 分片均匀。
fn shard_of(dh: &[u8; 32], shards: usize) -> usize {
    u32::from_be_bytes([dh[0], dh[1], dh[2], dh[3]]) as usize % shards
}

impl ShardedState {
    pub fn new(shard_count: usize) -> Self {
        assert!(shard_count > 0, "ledger_shards must be positive");
        let shards = (0..shard_count)
            .map(|_| Mutex::new(HashMap::new()))
            .collect();
        ShardedState { shards }
    }

    /// B8 容量预置：每个分片 HashMap 预置桶位，注册期内插入不 rehash。
    pub fn with_capacity(shard_count: usize, delegations_expected: usize) -> Self {
        assert!(shard_count > 0, "ledger_shards must be positive");
        let per = delegations_expected.div_ceil(shard_count);
        let shards = (0..shard_count)
            .map(|_| Mutex::new(HashMap::with_capacity(per.max(1))))
            .collect();
        ShardedState { shards }
    }

    /// 预置委托条目（零预算态 + 预置 nonce 集）。B8 关键；幂等。
    /// window_start=0：首次 check_budget 必回滚窗口到首次消费时间，重放与线上一致。
    pub fn provision(&self, dh: &[u8; 32], nonce_capacity: usize) {
        let idx = shard_of(dh, self.shards.len());
        let mut map = self.shards[idx].lock().expect("shard poisoned");
        map.entry(*dh).or_insert_with(|| DelegationLedgerState {
            budget: BudgetState::new(*dh, 0),
            nonces: HashMap::with_capacity(nonce_capacity),
        });
    }

    /// 幂等重发探针（S-12）：nonce 已被**同一 intent_hash** 接受 → 返回其 seq。
    /// 供 `submit` 在最前闸口调用——重发时信封可能已过期（过期意图仍是已接受意图，不能
    /// 因 EIntentExpired 拒绝而让 SDK 误判失败去重发新 nonce，那才是双花的来源）。
    /// 返回 None = 未接受（新提交 / 已被拒绝 / 跨意图复用，后续由 `try_commit` 裁决）。
    pub fn lookup_accept(
        &self,
        dh: &[u8; 32],
        spend_nonce: u64,
        intent_hash: [u8; 32],
    ) -> Option<u64> {
        let idx = shard_of(dh, self.shards.len());
        let map = self.shards[idx].lock().expect("shard poisoned");
        match map.get(dh)?.nonces.get(&spend_nonce)? {
            NonceState {
                intent_hash: stored,
                outcome: NonceOutcome::Accepted { seq },
            } if *stored == intent_hash => Some(*seq),
            _ => None,
        }
    }

    /// 原子：nonce 去重 + 幂等 → 预算检查记账 → 分片锁内分配 seq。`Ok(seq)` = accepted。
    ///
    /// 幂等（S-12）：同一 `intent_hash` 的重发返回先前结果——Accepted → 原 seq（不重复
    /// 分配、不重复扣预算），Rejected → 原原因（不透传成成功）。跨意图复用 nonce 仍
    /// `E_Nonce`（§6.2 不允许复用）。Err 时 nonce 已消耗。
    /// 防御路径：未 provision 的委托不该走到这里（管线在注册表查表时已拒）。
    /// 全 Copy 参数（B8 快路径，不引入结构体包装）。
    #[allow(clippy::too_many_arguments)]
    pub fn try_commit(
        &self,
        dh: &[u8; 32],
        delegation: &Delegation,
        intent_hash: [u8; 32],
        spend_nonce: u64,
        amount: u64,
        now: u64,
        seq_assigner: &AtomicU64,
    ) -> Result<u64, Error> {
        let idx = shard_of(dh, self.shards.len());
        let mut map = self.shards[idx].lock().expect("shard poisoned");
        let st = map.entry(*dh).or_insert_with(|| DelegationLedgerState {
            budget: BudgetState::new(*dh, 0),
            nonces: HashMap::new(),
        });
        if let Some(rec) = st.nonces.get(&spend_nonce) {
            if rec.intent_hash == intent_hash {
                return match rec.outcome {
                    NonceOutcome::Accepted { seq } => Ok(seq),
                    NonceOutcome::Rejected(e) => Err(e),
                };
            }
            return Err(Error::ENonce);
        }
        match check_budget(delegation, &mut st.budget, amount, now) {
            Ok(()) => {
                // seq 在锁内分配：同委托的提交序 == seq 序（重放精确性，见模块文档）。
                let seq = seq_assigner.fetch_add(1, Ordering::Relaxed);
                st.nonces.insert(
                    spend_nonce,
                    NonceState {
                        intent_hash,
                        outcome: NonceOutcome::Accepted { seq },
                    },
                );
                Ok(seq)
            }
            Err(e) => {
                // 预算拒也消耗 nonce（§6.2）；记下原因，同意图重发原样返回。
                st.nonces.insert(
                    spend_nonce,
                    NonceState {
                        intent_hash,
                        outcome: NonceOutcome::Rejected(e),
                    },
                );
                Err(e)
            }
        }
    }

    pub fn total_spent(&self, dh: &[u8; 32]) -> Option<u64> {
        let idx = shard_of(dh, self.shards.len());
        let map = self.shards[idx].lock().expect("shard poisoned");
        map.get(dh).map(|st| st.budget.total_spent)
    }

    pub fn nonce_count(&self, dh: &[u8; 32]) -> Option<usize> {
        let idx = shard_of(dh, self.shards.len());
        let map = self.shards[idx].lock().expect("shard poisoned");
        map.get(dh).map(|st| st.nonces.len())
    }

    /// S-31 只读派生：`max(已消耗 spend_nonce) + 1`（空集 → 0）。未 provision 的委托
    /// → `None`。取 max 而非 count：被拒意图同样消耗 nonce（§6.2），且聚合器不要求
    /// nonce 连续（只禁复用），调用方从该值起跳过任意数值都撞不上已消耗集。
    /// O(已消耗数) 扫描——只读路径（§6.7 S-31），`try_commit` 热路径零改动（B8）。
    pub fn next_nonce(&self, dh: &[u8; 32]) -> Option<u64> {
        let idx = shard_of(dh, self.shards.len());
        let map = self.shards[idx].lock().expect("shard poisoned");
        map.get(dh)
            .map(|st| st.nonces.keys().max().map_or(0, |n| n + 1))
    }
}

// ---------------------------------------------------------------------------
// 窗口管理（epoch 旋转 + 密封队列）
// ---------------------------------------------------------------------------

/// 一个已密封 epoch 的产物（供 commitment lattice 消费）。
#[derive(Debug, Clone)]
pub struct SealedEpoch {
    pub epoch_id: u64,
    pub sealed_at: u64,
    /// accepted 条目，**按 seq 升序**（承诺根可复算，B11）。
    pub entries: Vec<WindowEntry>,
}

/// 槽预留（提交侧在 finalize 前持有）。
struct SlotReservation {
    window: Arc<EpochWindow>,
    slot: usize,
}

struct CurrentWindow {
    window: Arc<EpochWindow>,
    created_at: u64,
}

/// 窗口管理器：当前窗口 + 密封队列。满/密封自动换新窗；时间到点由 lattice 驱动封。
struct WindowManager {
    current: Mutex<CurrentWindow>,
    sealed: Mutex<Vec<SealedEpoch>>,
    next_epoch: AtomicU64,
    capacity: usize,
}

impl WindowManager {
    fn new(capacity: usize, now: u64) -> Self {
        WindowManager {
            current: Mutex::new(CurrentWindow {
                window: Arc::new(EpochWindow::new(capacity)),
                created_at: now,
            }),
            sealed: Mutex::new(Vec::new()),
            next_epoch: AtomicU64::new(0),
            capacity,
        }
    }

    fn current(&self) -> Arc<EpochWindow> {
        Arc::clone(&self.current.lock().expect("window poisoned").window)
    }

    /// 预留槽。满 / 密封时换新窗口重试（不返回失败；总是成功）。
    fn reserve(&self, intent_hash: [u8; 32], now: u64) -> SlotReservation {
        loop {
            let w = self.current();
            match w.reserve(intent_hash) {
                Ok(slot) => return SlotReservation { window: w, slot },
                Err(_) => self.rotate_if_full(&w, now, false),
            }
        }
    }

    fn finalize(&self, r: &SlotReservation, seq: u64, accepted: bool) {
        r.window.finalize(r.slot, seq, accepted);
    }

    /// 满窗即封（提交后调用；加速 lattice 处理）。
    fn maybe_rotate(&self, now: u64) {
        let w = self.current();
        if w.is_full() {
            self.rotate_if_full(&w, now, false);
        }
    }

    /// 封当前窗并换新窗。`force=true` 允许封未满的窗（时间到点）。
    fn rotate_if_full(&self, seen: &Arc<EpochWindow>, now: u64, force: bool) {
        let mut cur = self.current.lock().expect("window poisoned");
        if Arc::ptr_eq(&cur.window, seen) && (force || seen.is_closed() || seen.is_full()) {
            let entries = seen.seal();
            let epoch_id = self.next_epoch.fetch_add(1, Ordering::Relaxed);
            self.sealed
                .lock()
                .expect("sealed poisoned")
                .push(SealedEpoch {
                    epoch_id,
                    sealed_at: now,
                    entries,
                });
            *cur = CurrentWindow {
                window: Arc::new(EpochWindow::new(self.capacity)),
                created_at: now,
            };
        }
    }

    /// 到时未满也封（lattice 驱动轮询调）。返回取走的全部已封 epoch。
    fn seal_expired(&self, now: u64, epoch_secs: u64) -> Vec<SealedEpoch> {
        let (w, created_at) = {
            let cur = self.current.lock().expect("window poisoned");
            (Arc::clone(&cur.window), cur.created_at)
        };
        if !w.is_closed() && w.claimed() > 0 && now.saturating_sub(created_at) >= epoch_secs {
            self.rotate_if_full(&w, now, true);
        }
        self.take_sealed()
    }

    fn take_sealed(&self) -> Vec<SealedEpoch> {
        std::mem::take(&mut *self.sealed.lock().expect("sealed poisoned"))
    }

    fn pending_sealed(&self) -> usize {
        self.sealed.lock().expect("sealed poisoned").len()
    }

    /// S-10c 恢复：把未密封尾（已接受但未承诺的意图）种子进当前窗口，并把 epoch 编号接到
    /// 最后一个已密封 epoch 之后（避免恢复后 epoch_id 与已上链的重复 / 被拒）。
    /// `tail` 必须按 seq 升序、长度 ≤ 容量（一窗内；撕裂点在「WAL 追加」与「满窗即封」之间时
    /// 可达整窗）。当前窗口由 `build` 新建为空窗，直接填入即可。
    fn restore_tail(&self, last_epoch_id: i64, tail: &[WindowEntry]) {
        assert!(
            tail.len() <= self.capacity,
            "unsealed tail {} exceeds window capacity {}",
            tail.len(),
            self.capacity
        );
        self.next_epoch
            .store((last_epoch_id + 1) as u64, Ordering::Relaxed);
        let w = self.current();
        for e in tail {
            let slot = w
                .reserve(e.intent_hash)
                .expect("restore tail fits one window");
            w.finalize(slot, e.seq, true);
        }
        // current.created_at = build 时的 now_fn()（本进程启动时刻）；时间密封以恢复点为界。
    }
}

// ---------------------------------------------------------------------------
// Aggregator
// ---------------------------------------------------------------------------

fn default_now() -> Box<dyn Fn() -> u64 + Send + Sync> {
    Box::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// 聚合器内核（单实例；B5 吞吐由多线程共享一个实例达成）。
pub struct Aggregator {
    cfg: IngestConfig,
    registry: DelegationRegistry,
    state: ShardedState,
    windows: WindowManager,
    verifier: Box<dyn SpendVerifier + Send + Sync>,
    wal: Wal,
    /// 意图索引：intent_hash → (recipient, amount)。已接受意图在 WAL 落盘后插入；
    /// `settle_epoch` 净额后按 epoch 修剪。崩溃后由 WAL 重放重建（§6.3 步骤 D 的解析源）。
    intents: Mutex<HashMap<[u8; 32], IntentRef>>,
    /// 链上发布 seam（S-10 用 `NoopPublisher` 只算不发布；S-11 换真实交易后端）。
    publisher: Box<dyn ChainPublisher + Send + Sync>,
    /// 撤销集（S-11）：链上 revoke 事件 → `revoke()` 落 WAL 后入集 → `submit` 闸口 +
    /// `settle_epoch` 的撤销根快照。崩溃后由 WAL Revoke 记录重放重建。
    revocations: RevocationSet,
    /// 全局接受序号（accepted 计数）。在分片锁内递增。
    seq: AtomicU64,
    /// 会话拒绝计数（S-15 观测；零分配原子增量，**不**持久化——崩溃恢复后从 0 起）。
    rejected: AtomicU64,
    /// `submit` 全路径延迟直方图（S-35，TECH_SPEC §6.11）：固定桶原子增量，零分配零锁
    /// （B8 口径不变）。会话计数不持久化（同 `rejected`），崩溃恢复后从 0 起。
    latency: LatencyHistogram,
    /// 撤销状态根集合（S-44，撤销根绑定闸的接受集）：本账本出现过的全部撤销状态根。
    /// 撤销集只增 → 状态根随撤销事件单调推进，集合 ≤ 撤销事件数 + 1。**S-49 起随 WAL
    /// 持久化**（TECH_SPEC §4.6 残余③）：绑定闸开启时的每次 `revoke` 把当刻根作为
    /// `RevokeRoot` 记录与撤销记录同批落盘，`restore_from_wal` 重放续接接受集（零重算）。
    /// WAL 缺根记录的撤销（旧格式 WAL / 闸关闭期）其历史根不追溯——恢复后回退
    /// {空根, 当前根} 口径，在途证明以 `E_REV_ROOT` 拒（拒绝是安全方向）。仅在
    /// `enforce_revocation_root = true` 时维护（闸关闭 = 占位口径，零额外开销）。
    revocation_roots: RwLock<HashSet<[u8; 32]>>,
    /// 运营者绑定闸（S-62，§6.19.2）：`Some` = 装配了绑定事实源（管线步 4b 生效）；
    /// `None` = 无闸（缺省口径，单运营者 / 占位形态逐字节不变）。绑定读数缓存在闸内
    /// （不可变语义），进程内不持久化（WAL 冻结面纪律，链上是事实源）。
    binding: Option<Arc<crate::binding::BindingGate>>,
    /// 本实例启动时刻（unix 秒；`snapshot()` 健康快照用）。
    started_at: u64,
    /// 实例标识（`meridian-<pid>`；S-15 多实例时每实例一 metrics endpoint）。
    instance_id: String,
    now_fn: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl Aggregator {
    /// 默认时钟构造。
    pub fn new(
        cfg: IngestConfig,
        verifier: Box<dyn SpendVerifier + Send + Sync>,
        wal: Wal,
    ) -> Self {
        Self::build(cfg, verifier, wal, default_now(), None, 0)
    }

    /// 可控时钟构造（测试）。
    pub fn with_clock(
        cfg: IngestConfig,
        verifier: Box<dyn SpendVerifier + Send + Sync>,
        wal: Wal,
        now_fn: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self::build(cfg, verifier, wal, now_fn, None, 0)
    }

    /// B8 验收用构造：可控时钟（agg_sim 固定 now 做时间密封）+ 容量预置
    /// （委托数 / 接受数，稳态插入零分配）。基准专用；测试与运维用上面两个即可。
    pub fn with_capacity_and_clock(
        cfg: IngestConfig,
        verifier: Box<dyn SpendVerifier + Send + Sync>,
        wal: Wal,
        now_fn: Box<dyn Fn() -> u64 + Send + Sync>,
        delegations_expected: usize,
        intents_expected: usize,
    ) -> Self {
        Self::build(
            cfg,
            verifier,
            wal,
            now_fn,
            Some(delegations_expected),
            intents_expected,
        )
    }

    /// B8 容量预置构造：分片桶位按预期委托数预分配（`register` 再逐委托 provision），
    /// 意图索引按预期接受数预分配（`submit` 的 HashMap insert 在稳态零分配的关键）。
    pub fn with_capacity(
        cfg: IngestConfig,
        verifier: Box<dyn SpendVerifier + Send + Sync>,
        wal: Wal,
        delegations_expected: usize,
        intents_expected: usize,
    ) -> Self {
        Self::build(
            cfg,
            verifier,
            wal,
            default_now(),
            Some(delegations_expected),
            intents_expected,
        )
    }

    fn build(
        cfg: IngestConfig,
        verifier: Box<dyn SpendVerifier + Send + Sync>,
        wal: Wal,
        now_fn: Box<dyn Fn() -> u64 + Send + Sync>,
        delegations_expected: Option<usize>,
        intents_expected: usize,
    ) -> Self {
        // 装配面配对闸（S-48，TECH_SPEC §6.13 / §6.2）：真电路验证后端对公共输入
        // `revocation_root` 有语义依赖，必须与撤销根绑定闸同步装配——此前只是文档
        // 口径（S-40 自己的 bin 接线就漏配了一次：gateway bb 模式仍用缺省配置），
        // 此处升级为构造保证：配对缺失构造即 panic（fail-fast，bin 启动即退，
        // 不落运行时半可用态——与 §6.13 后端探测「构造期报错」同一口径）。
        if verifier.requires_revocation_root_binding() && !cfg.enforce_revocation_root {
            panic!(
                "aggregator 装配错误：验证后端声明依赖撤销根公共输入 \
                 （SpendVerifier::requires_revocation_root_binding = true，TECH_SPEC \
                 §6.13），但 IngestConfig::enforce_revocation_root = false——撤销根绑定闸 \
                 关闭时证明可自选根，装饰性 ZK 复活（§6.2）。同步置位后重新构造。"
            );
        }
        let now = now_fn();
        let epoch_capacity = cfg.epoch_capacity;
        let state = match delegations_expected {
            Some(n) => ShardedState::with_capacity(cfg.ledger_shards, n),
            None => ShardedState::new(cfg.ledger_shards),
        };
        let agg = Aggregator {
            cfg,
            registry: DelegationRegistry::new(),
            state,
            windows: WindowManager::new(epoch_capacity, now),
            verifier,
            wal,
            intents: Mutex::new(HashMap::with_capacity(intents_expected)),
            publisher: Box::new(NoopPublisher),
            revocations: RevocationSet::with_capacity(intents_expected / 1000),
            seq: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            latency: LatencyHistogram::new(),
            revocation_roots: RwLock::new(HashSet::new()),
            binding: None,
            started_at: now,
            instance_id: format!("meridian-{}", std::process::id()),
            now_fn,
        };
        agg.seed_revocation_roots();
        agg
    }

    /// 装配运营者绑定闸（S-62，§6.19.2，Phase 2 P2-2）：`source` 是链上绑定事实源
    /// （进程内 `StaticBinding` / gateway JSON-RPC 实现），`self_operator` 是本账本
    /// 运营者地址。装配后管线步 4b 生效：绑他方拒 `E_OPERATOR`、未绑定 fail-open、
    /// 读面不可得 `E_BIND_BACKEND`（fail-closed）。**显式装配**——不调用 = 无闸，
    /// 缺省口径逐字节不变（单运营者 / 占位形态零改动）。
    pub fn with_operator_binding(
        mut self,
        source: Arc<dyn crate::binding::OperatorBinding + Send + Sync>,
        self_operator: crate::binding::OperatorAddress,
    ) -> Self {
        self.binding = Some(Arc::new(crate::binding::BindingGate::new(
            source,
            self_operator,
        )));
        self
    }

    /// 撤销状态根集合种子（S-44）：空根（账本 genesis 状态，任何账本都真实出现过）+
    /// 当刻根（WAL 重放路径由 `restore_from_wal` 在撤销集重建后补种；S-49 起中间状态根
    /// 另由 `RevokeRoot` 记录重放续接）。仅在绑定闸开启时维护——闸关闭 = 占位口径，
    /// 零额外开销（`sparse_root()` 与每 epoch 密封同成本级）。
    fn seed_revocation_roots(&self) {
        if !self.cfg.enforce_revocation_root {
            return;
        }
        let mut roots = self
            .revocation_roots
            .write()
            .expect("revocation roots poisoned");
        // 空根：撤销集为空的确定树根（S-41 规范，与电路空树逐位同源）。
        roots.insert(RevocationSet::new().sparse_root());
        roots.insert(self.revocations.sparse_root());
    }

    /// 从 WAL 重放恢复（崩溃恢复入口）。返回 (聚合器, 是否截断了撕裂尾)。
    ///
    /// 恢复范围（S-10a）：注册表（含 agent 公钥）+ 每委托 nonce 集 + 预算账本 + seq 计数。
    /// 意图按 seq 排序重放（分片锁保证同委托 seq 序 == 提交序）→ 与 accepted 前缀**精确**一致。
    /// 已接受但未密封的意图其承诺重建、已密封 epoch 的跳过由 S-10c 完成。
    pub fn restore_from_wal(
        cfg: IngestConfig,
        verifier: Box<dyn SpendVerifier + Send + Sync>,
        path: &Path,
        now_fn: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> std::io::Result<(Self, bool)> {
        let wal = Wal::open(path, cfg.wal_sync_every)?;
        let (records, valid_bytes, truncated) = wal.replay()?;
        if truncated {
            wal.truncate_to(valid_bytes)?;
        }
        let agg = Self::build(cfg.clone(), verifier, wal, now_fn, None, 0);

        // 1a. 撤销集重放（S-11）：Revoke 记录 → 撤销集（幂等；与注册表重建顺序无关）。
        for rec in &records {
            if let DecodedRecord::Revoke { delegation_hash } = rec {
                agg.revocations.insert(*delegation_hash);
            }
        }
        // 1a'. 撤销状态根集合续接（S-49，§4.6 残余③）：`RevokeRoot` 记录直接进接受集
        // （零重算——根在 revoke 时本已算过并落盘）。WAL 缺根记录的撤销（旧格式 WAL /
        // 闸关闭期）其历史根不追溯，回退 {空根, 当刻根} 口径——在途证明以 E_REV_ROOT
        // 拒（拒绝是安全方向，诚实边界）。
        if agg.cfg.enforce_revocation_root {
            let mut roots = agg
                .revocation_roots
                .write()
                .expect("revocation roots poisoned");
            for rec in &records {
                if let DecodedRecord::RevokeRoot { revocation_root } = rec {
                    roots.insert(*revocation_root);
                }
            }
        }
        // 1a''. 空根 + 重放后当刻根补种（S-44）。
        agg.seed_revocation_roots();
        // 1. 注册表 + provision。
        for rec in &records {
            if let DecodedRecord::Register(sd, agent_pub_bytes) = rec {
                let agent_pub =
                    AgentPubKey::from_bytes(agent_pub_bytes).map_err(std::io::Error::other)?;
                let dh = delegation_hash(&sd.delegation);
                agg.registry.register(
                    dh,
                    RegisteredDelegation {
                        delegation: sd.delegation.clone(),
                        agent_pub,
                    },
                );
                agg.state.provision(&dh, cfg.nonce_capacity_per_delegation);
            }
        }
        // 2. 已密封边界：最后一个 EpochSeal 的**累计**接受数 = 已承诺/已结算意图的上界。
        //    seq >= 该值 的意图是「未密封尾」——已接受、已落 WAL、但还没进任何 epoch 承诺，
        //    恢复后必须重建进当前窗口（S-10c，否则这些意图永远不会被净额结算）。
        let mut sealed_accepted_count: u64 = 0;
        let mut last_epoch_id: i64 = -1;
        for rec in &records {
            if let DecodedRecord::EpochSeal {
                epoch_id,
                accepted_count,
                ..
            } = rec
            {
                last_epoch_id = last_epoch_id.max(*epoch_id as i64);
                sealed_accepted_count = sealed_accepted_count.max(*accepted_count);
            }
        }
        // 3. 意图按 seq 排序重放（重建 nonce 集 + 账本 + seq + 意图索引）。
        let mut intents: Vec<ReplayIntent> = Vec::new();
        for rec in &records {
            if let DecodedRecord::Intent {
                seq,
                intent_hash,
                delegation_hash,
                spend_nonce,
                amount,
                now,
                recipient,
            } = rec
            {
                intents.push((
                    *seq,
                    *intent_hash,
                    *delegation_hash,
                    *spend_nonce,
                    *amount,
                    *now,
                    *recipient,
                ));
            }
        }
        intents.sort_by_key(|t| t.0);
        // 未密封尾（按 seq 升序，已排序）：重建当前窗口用。
        let tail: Vec<WindowEntry> = intents
            .iter()
            .filter(|t| t.0 >= sealed_accepted_count)
            .map(|(seq, ih, ..)| WindowEntry {
                seq: *seq,
                intent_hash: *ih,
            })
            .collect();
        for (seq, ih, dh, spend_nonce, amount, now, recipient) in intents {
            let reg = agg.registry.lookup(&dh).ok_or_else(|| {
                std::io::Error::other("WAL replay: intent for unregistered delegation")
            })?;
            let got = agg
                .state
                .try_commit(&dh, &reg.delegation, ih, spend_nonce, amount, now, &agg.seq)
                .map_err(std::io::Error::other)?;
            debug_assert_eq!(got, seq, "replay seq must match WAL seq");
            // 意图索引只收未密封意图：已提交的（seq < 边界）由 EpochSeal/Netting 覆盖，
            // 恢复后不再引用，不入索引避免驻留泄漏。
            if seq >= sealed_accepted_count {
                agg.intents
                    .lock()
                    .expect("intents poisoned")
                    .insert(ih, (recipient, amount, seq));
            }
        }
        // 4. 重建未密封窗口 + epoch 编号接到已密封序列之后。
        agg.windows.restore_tail(last_epoch_id, &tail);
        Ok((agg, truncated))
    }

    /// 登记委托（DSA 登记事件 → 注册表 + WAL + 账本 provision）。
    /// `agent_pub` 是 agent 的 Ed25519 公钥（验签快路径密钥；链上事件不含，需运营者提供）。
    pub fn register(&self, sd: SignedDelegation, agent_pub: AgentPubKey) {
        let dh = delegation_hash(&sd.delegation);
        self.wal
            .append_register(&sd, &agent_pub.to_bytes())
            .expect("WAL failure (durability backbone)");
        self.registry.register(
            dh,
            RegisteredDelegation {
                delegation: sd.delegation,
                agent_pub,
            },
        );
        self.state
            .provision(&dh, self.cfg.nonce_capacity_per_delegation);
    }

    /// 手动批量 fsync WAL 到盘（结算边界 / 优雅停机时调用，确保持久点后的状态可完整恢复）。
    /// 未 flush 的尾巴在崩溃中丢失属标准 WAL 语义（S-10c）；本方法让调用方选择持久化时机。
    pub fn flush_wal(&self) -> std::io::Result<()> {
        self.wal.flush()
    }

    /// 撤销委托（链上 revoke 事件 → 运营者调用）：WAL 追加后入撤销集（持久化骨干，WAL 失败
    /// panic）。返回是否新撤销（重复撤销幂等）。从本调用起，该委托的新意图 `submit` 一律
    /// `E_REVOKED` 拒；撤销根随下个密封 epoch 上链（S-11 验收：1 epoch 内进入撤销根）。
    pub fn revoke(&self, delegation_hash: [u8; 32]) -> bool {
        self.wal
            .append_revoke(delegation_hash)
            .expect("WAL failure (durability backbone)");
        let fresh = self.revocations.insert(delegation_hash);
        // 撤销状态根集合推进（S-44）：新状态根进接受集（撤销集只增 → 根单调变化，重复
        // 撤销幂等不产生新状态）。S-49：根随撤销落 WAL（`RevokeRoot` 记录，与撤销记录
        // 同批 fsync），恢复侧重放续接接受集、零重算（§4.6 残余③）。仅在绑定闸开启时
        // 维护（闸关闭零开销，占位口径——不落根记录，WAL 逐字节不变）。
        if fresh && self.cfg.enforce_revocation_root {
            let root = self.revocations.sparse_root();
            self.wal
                .append_revoke_root(root)
                .expect("WAL failure (durability backbone)");
            self.revocation_roots
                .write()
                .expect("revocation roots poisoned")
                .insert(root);
        }
        fresh
    }

    /// 撤销集当前根（下个 epoch 承诺时锚定；测试 / 观测）。
    pub fn revocation_root(&self) -> [u8; 32] {
        self.revocations.sparse_root()
    }

    /// 撤销非成员 witness 查询（S-45，§6.7）：供 prover 侧出真证明（§6.14 SDK 半边）。
    /// 与 [`Self::revocation_root`] 同一压实实现——root 与 path 出自同一棵确定性树。
    /// `None` = 目标已撤销（成员陈述不属于本接口语义，S-42 fail-closed；网关映射
    /// `404 E_REVOKED`）。**只读事实面**：未注册的 delegation_hash 照常返回非成员
    /// witness（撤销树覆盖完整 256-bit 索引空间），注册校验在摄取管线步 1。
    pub fn revocation_witness(&self, dh: &[u8; 32]) -> Option<NonMembershipWitness> {
        self.revocations.non_membership_witness(dh)
    }

    /// 某委托是否已撤销（测试 / 观测）。
    pub fn is_revoked(&self, dh: &[u8; 32]) -> bool {
        self.revocations.is_revoked(dh)
    }

    /// 已撤销委托数（测试 / 观测）。
    pub fn revoked_len(&self) -> usize {
        self.revocations.len()
    }

    /// 摄取单条意图（TECH_SPEC §6.2 管线，见模块文档）。永远返回 `Receipt`（不 panic，除非 WAL 失败）。
    ///
    /// S-35：外层计时包装——`submit` 全路径（接受/拒绝/幂等 re-ack 一律）记入延迟直方图
    /// （调用方观测到的 API 延迟）；内层 `submit_inner` 是原管线，B8 复测口径含本埋点。
    pub fn submit(&self, env: &IntentEnvelope) -> Receipt {
        let t0 = Instant::now();
        let r = self.submit_inner(env);
        self.latency.record_us(t0.elapsed().as_micros() as u64);
        r
    }

    /// 原摄取管线（S-35 前的 `submit` 本体，§6.2 十步顺序不变）。
    fn submit_inner(&self, env: &IntentEnvelope) -> Receipt {
        let now = (self.now_fn)();
        let intent = &env.intent;
        let ih = intent_hash(intent);

        // 0. 幂等重发（S-12）：同意图（同 nonce + 同 intent_hash）已被接受 → 直接返回既有 seq。
        //    必须在其它闸口之前——重发时信封可能已过期，而该意图早已接受；若让 EIntentExpired
        //    挡掉，SDK 会把已接受的支付误判为失败 → 用新 nonce 重发同一意图 → 双花。
        if let Some(seq) = self
            .state
            .lookup_accept(&intent.delegation_hash, intent.spend_nonce, ih)
        {
            return Receipt::accepted(ih, seq);
        }
        // 1. 意图有效期（早退：过期意图不占窗口 / 账本）。
        if now > intent.expires_at {
            return self.reject(ih, Error::EIntentExpired);
        }
        // 2. 委托查表（未注册拒）。
        let reg = match self.registry.lookup(&intent.delegation_hash) {
            Some(r) => r,
            None => return self.reject(ih, Error::EDelegUnknown),
        };
        // 2b. 撤销闸口（S-11）：注册表查找后立即查，最廉价——不耗 nonce / 窗口槽，撤销前已
        //     接受的意图仍留在承诺中支付（非追溯，TECH_SPEC §6.5）。
        if self.revocations.is_revoked(&intent.delegation_hash) {
            return self.reject(ih, Error::ERevoked);
        }
        // 3. agent 绑定：意图声明的 agent 必须与委托绑定的一致。
        if intent.agent != reg.delegation.agent {
            return self.reject(ih, Error::EOrdering);
        }
        // 4. Ed25519 快路径验签（证明前的廉价 DoS 闸门）。
        if let Err(e) = verify_intent(intent, &env.agent_sig, &reg.agent_pub) {
            return self.reject(ih, e);
        }
        // 4b. 运营者绑定闸（S-62，§6.19.2）：分片多运营者的事前强制——预算在账本侧
        //     ⇒ 分片间超支任何单账本都看不见，封堵锚点是链上绑定映射（DSA operatorOf，
        //     §6.19.1）。绑他方 → E_OPERATOR；未绑定 → fail-open（决策 B 有意取舍）；
        //     读面不可得 → E_BIND_BACKEND（fail-closed，绝不按未绑定放行）。位置在验签
        //     之后：未认证流量不得触发绑定冷读（RPC DoS 放大面收口）；在验证器之前：
        //     被拒不付真验证成本。闸在 try_commit 之前：被拒不耗 nonce / 窗口槽，同意图
        //     重发走全新校验（幂等闸不缓存 reject）。绑定不可改 ⇒ 闸内永久缓存冷读数。
        if let Some(gate) = &self.binding {
            if let Err(e) = gate.check(&intent.delegation_hash) {
                return self.reject(ih, e);
            }
        }
        // 5. 验证明（登记以验证器返回值为准）。
        let pi = match self.verifier.verify(&env.proof) {
            Ok(pi) => pi,
            Err(e) => return self.reject(ih, e),
        };
        // 6. 公共输入与信封一致（证明与信封不是同一笔意图 → 拒）。
        if let Err(e) = check_public_inputs_consistent(&pi, intent) {
            return self.reject(ih, e);
        }
        // 6b. 撤销根绑定闸（S-44，§6.2 / §4.6 残余③）：电路只证「path 与 root 自洽」，
        //     root 可由 prover 自选——绑定到本账本真实出现过的撤销状态，装饰性 ZK（拿
        //     空根 / 伪造根伪造非成员陈述）收口。置于 try_commit 之前：被拒不耗 nonce /
        //     窗口槽。安全性由步 2b 当前撤销闸兜底（任一历史状态未撤销 + 当前未撤销）。
        if self.cfg.enforce_revocation_root
            && !self
                .revocation_roots
                .read()
                .expect("revocation roots poisoned")
                .contains(&pi.revocation_root)
        {
            return self.reject(ih, Error::ERevRoot);
        }
        // 7. 预留窗口槽（记账前入窗口 → 无回滚；满 / 密封自动换窗重试）。
        let slot = self.windows.reserve(ih, now);
        // 8. nonce 去重 + 预算检查记账（分片锁内分配 seq）。预算的时间 = 证明的 now（§9）。
        let seq = match self.state.try_commit(
            &pi.delegation_hash,
            &reg.delegation,
            ih,
            pi.spend_nonce,
            pi.amount,
            pi.now,
            &self.seq,
        ) {
            Ok(seq) => seq,
            Err(e) => {
                self.windows.finalize(&slot, 0, false);
                return self.reject(ih, e);
            }
        };
        // 9. 定稿（accepted 入承诺）+ WAL。
        self.windows.finalize(&slot, seq, true);
        if let Err(e) = self.wal.append_intent(
            seq,
            ih,
            pi.delegation_hash,
            pi.spend_nonce,
            pi.amount,
            pi.now,
            pi.recipient,
        ) {
            panic!("WAL failure (durability backbone): {e}");
        }
        // WAL 落盘后登记意图索引（崩溃后可重放重建；settle 后按 epoch 修剪）。
        self.intents
            .lock()
            .expect("intents poisoned")
            .insert(ih, (pi.recipient, pi.amount, seq));
        // 10. 满窗即封。
        self.windows.maybe_rotate(now);
        Receipt::accepted(ih, seq)
    }

    /// 批量摄取（rayon 有界线程池，MASTER_PLAN 技术源）。返回与输入等长的回执数组。
    pub fn submit_batch(&self, pool: &rayon::ThreadPool, envs: &[IntentEnvelope]) -> Vec<Receipt> {
        use rayon::prelude::*;
        pool.install(|| envs.par_iter().map(|env| self.submit(env)).collect())
    }

    /// 取走已密封 epoch（commitment lattice 消费）。空则无。
    pub fn take_sealed(&self) -> Vec<SealedEpoch> {
        self.windows.take_sealed()
    }

    /// 到时未满也封（lattice 驱动轮询）。返回取走的全部已封 epoch。
    pub fn seal_expired(&self, now: u64, epoch_secs: u64) -> Vec<SealedEpoch> {
        self.windows.seal_expired(now, epoch_secs)
    }

    /// 结算一个已封 epoch（TECH_SPEC §6.3 步骤 A-E）：承诺根 → 确定性重排 → 净额 →
    /// 净额根 → WAL EpochSeal/Netting 记录 → 上链 seam → 修剪意图索引。
    ///
    /// 返回 `None` 仅当某 accepted 意图不在索引（不该发生：正常路径已接受意图必在索引；
    /// 此时放弃本 epoch 并保留索引，避免带洞净额）。调用方应只结算每个 epoch 一次
    /// （`process_pending` 从密封队列取走即不会重复）。
    pub fn settle_epoch(&self, se: &SealedEpoch) -> Option<EpochResult> {
        let mut resolve = |ih: &[u8; 32]| -> Option<([u8; 20], u64)> {
            self.intents
                .lock()
                .expect("intents poisoned")
                .get(ih)
                .map(|&(r, a, _seq)| (r, a))
        };
        // 撤销根快照（S-11）：本 epoch 承诺时的撤销集稀疏根，随 commit 上链；不并入承诺树
        // （承诺根的叶索引是欺诈证明位置，独立锚定撤销根）。
        let rev_root = self.revocations.sparse_root();
        let res = crate::lattice::build_epoch(
            se.epoch_id,
            se.sealed_at,
            &se.entries,
            &mut resolve,
            rev_root,
        )?;
        // WAL 记录（崩溃重放按 epoch_id 跳过已承诺 / 已结算的 epoch）。
        // accepted_count = **累计**接受数（截至本 epoch 末，含此前全部）：max(seq)+1。
        // 恢复时用它区分已密封 vs 未密封尾（seq >= 该值 → 未密封，需重建窗口，S-10c）。
        let cumulative_accepted = se.entries.last().map(|e| e.seq + 1).unwrap_or(0);
        self.wal
            .append_epoch_seal(
                se.epoch_id,
                res.commitment_root,
                cumulative_accepted,
                se.sealed_at,
            )
            .expect("WAL failure (durability backbone)");
        self.wal
            .append_netting(se.epoch_id, res.netting_root, res.net.len() as u64)
            .expect("WAL failure (durability backbone)");
        // 上链 seam（S-11 真实交易后端；失败由运营者重试）。
        self.publisher
            .commit(
                se.epoch_id,
                res.commitment_root,
                res.revocation_root,
                se.sealed_at,
            )
            .expect("publisher commit failed");
        self.publisher
            .settle(se.epoch_id, res.netting_root, res.net.len() as u64)
            .expect("publisher settle failed");
        // 修剪已净额意图的索引。
        let mut idx = self.intents.lock().expect("intents poisoned");
        for e in &se.entries {
            idx.remove(&e.intent_hash);
        }
        Some(res)
    }

    /// 取走并结算全部已封 epoch（lattice 驱动轮询入口）。
    pub fn process_pending(&self) -> Vec<EpochResult> {
        let sealed = self.windows.take_sealed();
        sealed
            .iter()
            .filter_map(|se| self.settle_epoch(se))
            .collect()
    }

    /// 当前已密封但未取走的 epoch 数（测试 / 观测）。
    pub fn pending_sealed(&self) -> usize {
        self.windows.pending_sealed()
    }

    pub fn registry_len(&self) -> usize {
        self.registry.len()
    }

    /// 某委托累计已花（测试 / 观测）。
    pub fn total_spent(&self, dh: &[u8; 32]) -> Option<u64> {
        self.state.total_spent(dh)
    }

    /// 某委托已用 nonce 数（测试 / 观测）。
    pub fn nonce_count(&self, dh: &[u8; 32]) -> Option<usize> {
        self.state.nonce_count(dh)
    }

    /// S-31 只读下一 nonce 查询（§6.7）：`max(已消耗) + 1`，未注册委托 → `None`。
    /// 崩溃恢复后由 WAL 重放重建（WAL 只含已接受意图——被拒 nonce 占位是瞬态的、
    /// 不重建，被拒意图从未承诺任何东西，重启后复用无害）→ 恢复后查询值 =
    /// `max(已接受) + 1`，可能低于重启前；仍是安全下界（大于它的 nonce 绝不撞已接受
    /// 集）。nonce 不随 settle 修剪，恢复前后对已接受集一致。走分片同一把锁（只读
    /// 路径，非热路径）。
    pub fn next_nonce(&self, dh: &[u8; 32]) -> Option<u64> {
        self.state.next_nonce(dh)
    }

    /// S-13a MCP 只读探针：`(dh, spend_nonce, intent_hash)` 是否已被接受？返回其 seq
    /// （= `submit` 最前幂等闸口的公共包装，与 re-ack 同源）。
    /// 拒绝（预算拒）、跨意图 nonce 复用、以及从未见过 → `None`。
    pub fn accepted_seq(
        &self,
        dh: &[u8; 32],
        spend_nonce: u64,
        intent_hash: [u8; 32],
    ) -> Option<u64> {
        self.state.lookup_accept(dh, spend_nonce, intent_hash)
    }

    /// 注册表只读（S-13a：authorize 的 EAttestBind 跨重启兜底——重启后也能查到
    /// 已注册委托绑定的 agent 公钥）。
    pub fn registered(&self, dh: &[u8; 32]) -> Option<RegisteredDelegation> {
        self.registry.lookup(dh)
    }

    /// S-30a 只读回执查询（x402 merchant 验证面，§6.7）：intent_hash → 受理回执（seq）。
    ///
    /// 语义边界（诚实）：命中 = **已接受且未结算**——意图索引随 `settle_epoch` 按 epoch
    /// 修剪，已结算意图返回 `None`；被拒意图不入索引（拒绝回执是瞬态响应，不持久化）
    /// 同样 `None`。即 `None` ≠ 未支付：终局保证在链上净额，商户侧验证必须在 epoch
    /// 时延内完成（x402-adapter.md §4.2）。走意图索引同一把 `Mutex`（只读路径，非热路径
    /// ——热路径 B8 口径不变）；崩溃恢复后由 WAL 重放重建（未密封尾，与修剪语义一致）。
    pub fn receipt(&self, intent_hash: &[u8; 32]) -> Option<Receipt> {
        let (_, _, seq) = *self
            .intents
            .lock()
            .expect("intents poisoned")
            .get(intent_hash)?;
        Some(Receipt::accepted(*intent_hash, seq))
    }

    /// 已接受总数（== 下一个待分配的 seq；测试 / 观测）。
    pub fn accepted_count(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    /// 拒绝计数（S-15 观测）：submit 的每个拒分支都走这里（零分配原子增量）。
    /// 幂等 re-ack 不经过（既非 accept 也非 reject）；崩溃恢复后从 0 起（不持久化）。
    #[inline(always)]
    fn reject(&self, ih: [u8; 32], e: Error) -> Receipt {
        self.rejected.fetch_add(1, Ordering::Relaxed);
        Receipt::rejected(ih, e)
    }

    /// 健康快照（S-15 监控/告警源）。无锁视图：只读原子 + 只读状态，不碰分片/窗口锁
    /// （B8：抓快照不引入热路径争用）。详见 `health::HealthSnapshot` 口径注释。
    pub fn snapshot(&self) -> HealthSnapshot {
        HealthSnapshot {
            instance_id: self.instance_id.clone(),
            started_at_unix: self.started_at,
            now: (self.now_fn)(),
            accepted_count: self.seq.load(Ordering::Relaxed),
            rejected_count: self.rejected.load(Ordering::Relaxed),
            pending_sealed: self.pending_sealed(),
            revoked_len: self.revoked_len(),
            revocation_root: self.revocation_root(),
            wal_len: self.wal.file_len().unwrap_or(0),
            submit_latency: self.latency.snapshot(),
            ledger_shards: self.cfg.ledger_shards,
            epoch_capacity: self.cfg.epoch_capacity,
            epoch_secs: self.cfg.epoch_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meridian_core::dsa::{
        owner_signing_key_from_bytes, sign_delegation, sign_intent, AgentSigningKey, RateLimit,
        SpendIntent,
    };
    use meridian_core::zk::{SpendProof, SpendPublicInputs};
    use std::collections::HashSet;

    use crate::bb::{BbBackend, BbVerifier};
    use crate::proof::FormatVerifier;
    use proptest::prelude::*;

    /// 装配面配对闸（S-48）测试替身：可声明「依赖撤销根公共输入」。
    struct RequiresBinding(bool);

    impl SpendVerifier for RequiresBinding {
        fn verify(&self, _proof: &SpendProof) -> Result<SpendPublicInputs, Error> {
            Ok(test_public_inputs())
        }
        fn requires_revocation_root_binding(&self) -> bool {
            self.0
        }
    }

    fn test_public_inputs() -> SpendPublicInputs {
        SpendPublicInputs {
            agent_commit: [0u8; 32],
            delegation_hash: [0u8; 32],
            recipient: [0u8; 20],
            amount: 0,
            category: [0u8; 32],
            spend_nonce: 1,
            expires_at: 0,
            revocation_root: [0u8; 32],
            now: 0,
        }
    }

    #[test]
    fn real_backend_without_binding_gate_panics_at_construction() {
        let c = Arc::new(AtomicU64::new(1_700_000_000));
        let now_fn: Box<dyn Fn() -> u64 + Send + Sync> = {
            let c = Arc::clone(&c);
            Box::new(move || c.load(Ordering::Relaxed))
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let wal = Wal::open(&tmp_path("pairing-guard"), 100_000).unwrap();
            Aggregator::with_clock(test_cfg(), Box::new(RequiresBinding(true)), wal, now_fn);
        }));
        assert!(
            result.is_err(),
            "真验证后端 + 闸关闭必须构造即 panic（§6.13 配对闸）"
        );
        let _ = std::fs::remove_file(tmp_path("pairing-guard"));
    }

    #[test]
    fn real_backend_with_binding_gate_constructs() {
        let c = Arc::new(AtomicU64::new(1_700_000_000));
        let now_fn: Box<dyn Fn() -> u64 + Send + Sync> = {
            let c = Arc::clone(&c);
            Box::new(move || c.load(Ordering::Relaxed))
        };
        let mut cfg = test_cfg();
        cfg.enforce_revocation_root = true;
        let wal = Wal::open(&tmp_path("pairing-ok"), 100_000).unwrap();
        let agg = Aggregator::with_clock(cfg, Box::new(RequiresBinding(true)), wal, now_fn);
        assert_eq!(agg.accepted_count(), 0);
        let _ = std::fs::remove_file(tmp_path("pairing-ok"));
    }

    #[test]
    fn bb_verifier_declares_revocation_root_binding() {
        // BbVerifier 覆写声明（真构造器 from_parts 不探测工具链，测试机无 bb 也可构造）。
        let v = BbVerifier::from_parts(
            vec![0u8; 4],
            BbBackend::Native { bin: "bb".into() },
            std::path::PathBuf::from("target/bb-verify-test"),
        );
        assert!(v.requires_revocation_root_binding());
    }

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "meridian-ingest-test-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn test_cfg() -> IngestConfig {
        IngestConfig {
            ledger_shards: 4,
            epoch_capacity: 1_000_000,
            epoch_secs: 60,
            wal_sync_every: 100_000,
            nonce_capacity_per_delegation: 100,
            enforce_revocation_root: false,
        }
    }

    fn test_aggregator(clock: &Arc<AtomicU64>, path: &Path) -> Aggregator {
        let c = Arc::clone(clock);
        let wal = Wal::open(path, 100_000).unwrap();
        Aggregator::with_clock(
            test_cfg(),
            Box::new(FormatVerifier),
            wal,
            Box::new(move || c.load(Ordering::Relaxed)),
        )
    }

    /// 宽松委托：金额大、额度大、永不过期。
    fn delegation(agent: [u8; 20], max_per_spend: u64, total_cap: u64) -> Delegation {
        Delegation {
            agent,
            owner: [2u8; 20],
            nonce: 7,
            max_per_spend,
            rate: RateLimit {
                window_secs: 60,
                max_per_window: 1_000_000,
            },
            total_cap,
            categories: vec![],
            not_before: 0,
            expires_at: u64::MAX,
            version: 1,
        }
    }

    /// 注册一个委托，返回 (sd, agent_pub)。
    fn register_default(agg: &Aggregator, agent: [u8; 20]) -> ([u8; 32], AgentPubKey) {
        let d = delegation(agent, 1_000, 1_000_000);
        let sd = sign_delegation(&d, &owner_signing_key_from_bytes([7u8; 32]));
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let agent_pub = agent_key.verifying_key();
        agg.register(sd, agent_pub);
        (meridian_core::dsa::delegation_hash(&d), agent_pub)
    }

    #[allow(clippy::too_many_arguments)]
    fn make_env(
        dh: [u8; 32],
        agent: [u8; 20],
        agent_key: &AgentSigningKey,
        recipient: [u8; 20],
        amount: u64,
        nonce: u64,
        now: u64,
    ) -> IntentEnvelope {
        let intent = SpendIntent {
            agent,
            delegation_hash: dh,
            recipient,
            amount,
            category: [0u8; 32],
            spend_nonce: nonce,
            memo: None,
            expires_at: now + 60,
        };
        let sig = sign_intent(&intent, agent_key);
        let proof = SpendProof {
            proof: vec![1, 2, 3],
            public_inputs: meridian_core::zk::SpendPublicInputs {
                agent_commit: [0u8; 32],
                delegation_hash: dh,
                recipient,
                amount,
                category: [0u8; 32],
                spend_nonce: nonce,
                expires_at: intent.expires_at,
                revocation_root: [0u8; 32],
                now,
            },
        };
        IntentEnvelope {
            intent,
            agent_sig: sig,
            proof,
        }
    }

    #[test]
    fn accept_and_seq_monotonic() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("seq");
        let agg = test_aggregator(&clock, &path);
        let (dh, agent_pub) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        let r1 = agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now));
        let r2 = agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 20, 2, now));
        let r3 = agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xCC; 20], 30, 3, now));
        assert_eq!((r1.accepted, r1.seq), (true, 0));
        assert_eq!((r2.accepted, r2.seq), (true, 1));
        assert_eq!((r3.accepted, r3.seq), (true, 2));
        assert_eq!(agg.accepted_count(), 3);
        assert_eq!(agg.total_spent(&dh), Some(60));
        assert_eq!(agg.nonce_count(&dh), Some(3));
        // 回执的 intent_hash 与意图一致。
        assert_eq!(
            r1.intent_hash,
            meridian_core::dsa::intent_hash(
                &make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now).intent
            )
        );
        let _ = agent_pub;
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn accepted_seq_reports_accepted_rejected_and_cross_intent() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("accepted_seq");
        let agg = test_aggregator(&clock, &path);
        let (dh, _agent_pub) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);

        // 已接受 → Some(seq)。
        let env1 = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now);
        let r1 = agg.submit(&env1);
        assert!(r1.accepted);
        let ih1 = meridian_core::dsa::intent_hash(&env1.intent);
        assert_eq!(agg.accepted_seq(&dh, 1, ih1), Some(0));

        // 预算拒（max_per_spend=1_000，付 2_000）→ nonce 已消耗但未接受 → None。
        let env2 = make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 2_000, 2, now);
        let r2 = agg.submit(&env2);
        assert!(!r2.accepted);
        assert_eq!(r2.reject_reason, Some(Error::EBudgetPerSpend));
        let ih2 = meridian_core::dsa::intent_hash(&env2.intent);
        assert_eq!(agg.accepted_seq(&dh, 2, ih2), None);

        // 跨意图同 nonce 复用 → E_NONCE，lookup_accept 也不认 → None。
        let env3 = make_env(dh, [1u8; 20], &agent_key, [0xCC; 20], 1, 1, now);
        let r3 = agg.submit(&env3);
        assert_eq!(r3.reject_reason, Some(Error::ENonce));
        let ih3 = meridian_core::dsa::intent_hash(&env3.intent);
        assert_eq!(agg.accepted_seq(&dh, 1, ih3), None);

        // 从未见过的 nonce → None。
        assert_eq!(agg.accepted_seq(&dh, 99, [0xFF; 32]), None);

        // 注册表只读：registered() 能看到注册的委托与 agent 绑定。
        let reg = agg.registered(&dh).expect("registered delegation present");
        assert_eq!(reg.delegation.agent, [1u8; 20]);
        assert_eq!(reg.agent_pub, agent_key.verifying_key());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unregistered_delegation_rejected() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("unknown");
        let agg = test_aggregator(&clock, &path);
        let d = delegation([1u8; 20], 1_000, 1_000_000);
        let dh = meridian_core::dsa::delegation_hash(&d);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, 1_700_000_000);
        let r = agg.submit(&env);
        assert!(!r.accepted);
        assert_eq!(r.reject_reason, Some(Error::EDelegUnknown));
        assert_eq!(r.seq, 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bad_agent_signature_rejected() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("badsig");
        let agg = test_aggregator(&clock, &path);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        // 用错误的 agent 密钥签。
        let wrong_key = AgentSigningKey::from_bytes(&[9u8; 32]);
        let env = make_env(dh, [1u8; 20], &wrong_key, [0xAA; 20], 10, 1, 1_700_000_000);
        let r = agg.submit(&env);
        assert!(!r.accepted);
        assert_eq!(r.reject_reason, Some(Error::EIntentSig));
        assert_eq!(r.seq, 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn duplicate_nonce_rejected_but_first_accepted() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("nonce");
        let agg = test_aggregator(&clock, &path);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        let e1 = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 5, now);
        let e2 = make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 20, 5, now); // 同 nonce
        assert!(agg.submit(&e1).accepted);
        let r2 = agg.submit(&e2);
        assert!(!r2.accepted);
        assert_eq!(r2.reject_reason, Some(Error::ENonce));
        assert_eq!(agg.nonce_count(&dh), Some(1));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resubmit_same_intent_returns_original_seq() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("resubmit-ok");
        let agg = test_aggregator(&clock, &path);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        let env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now);
        let r1 = agg.submit(&env);
        assert!((r1.accepted, r1.seq) == (true, 0));
        // 同一 intent 重发（S-12 断线重试语义）→ 幂等返回原 seq，不重复记账 / 不重复分配。
        let r2 = agg.submit(&env);
        assert!(r2.accepted);
        assert_eq!(r2.seq, r1.seq);
        assert_eq!(r2.intent_hash, r1.intent_hash);
        assert_eq!(agg.accepted_count(), 1);
        assert_eq!(agg.total_spent(&dh), Some(10));
        assert_eq!(agg.nonce_count(&dh), Some(1));
        // 后续新意图（新 nonce）不受影响。
        let r3 = agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 20, 2, now));
        assert!((r3.accepted, r3.seq) == (true, 1));
        assert_eq!(agg.total_spent(&dh), Some(30));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resubmit_accepted_after_expiry_returns_seq() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("resubmit-expired");
        let agg = test_aggregator(&clock, &path);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        let env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now); // expires_at = now+60
        let r1 = agg.submit(&env);
        assert!(r1.accepted);
        // 时钟越过意图过期时间；重发必须走幂等闸口返回原 seq，而不是 EIntentExpired
        //（否则 SDK 会误判失败 → 换新 nonce 重发 → 双花）。
        clock.fetch_add(61, Ordering::Relaxed);
        let r2 = agg.submit(&env);
        assert!(r2.accepted);
        assert_eq!(r2.seq, r1.seq);
        assert_eq!(agg.accepted_count(), 1);
        assert_eq!(agg.total_spent(&dh), Some(10));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resubmit_budget_rejected_intent_returns_reason() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("resubmit-rejected");
        let agg = test_aggregator(&clock, &path);
        let d = delegation([1u8; 20], 100, 1_000_000);
        let sd = sign_delegation(&d, &owner_signing_key_from_bytes([7u8; 32]));
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        agg.register(sd, agent_key.verifying_key());
        let dh = meridian_core::dsa::delegation_hash(&d);
        let now = clock.load(Ordering::Relaxed);
        let env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 101, 1, now);
        let r1 = agg.submit(&env);
        assert_eq!(r1.reject_reason, Some(Error::EBudgetPerSpend));
        // 同一意图重发：返回原拒绝原因（nonce 已消耗），不透传成成功。
        let r2 = agg.submit(&env);
        assert!(!r2.accepted);
        assert_eq!(r2.reject_reason, Some(Error::EBudgetPerSpend));
        assert_eq!(agg.accepted_count(), 0);
        assert_eq!(agg.total_spent(&dh), Some(0));
        assert_eq!(agg.nonce_count(&dh), Some(1));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn budget_per_spend_rejected() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("perspend");
        let agg = test_aggregator(&clock, &path);
        let d = delegation([1u8; 20], 100, 1_000_000);
        let sd = sign_delegation(&d, &owner_signing_key_from_bytes([7u8; 32]));
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        agg.register(sd, agent_key.verifying_key());
        let dh = meridian_core::dsa::delegation_hash(&d);
        let env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 101, 1, 1_700_000_000);
        let r = agg.submit(&env);
        assert!(!r.accepted);
        assert_eq!(r.reject_reason, Some(Error::EBudgetPerSpend));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn budget_total_rejected_second_over_cap() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("total");
        let agg = test_aggregator(&clock, &path);
        let d = delegation([1u8; 20], 1_000, 100); // total_cap=100
        let sd = sign_delegation(&d, &owner_signing_key_from_bytes([7u8; 32]));
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        agg.register(sd, agent_key.verifying_key());
        let dh = meridian_core::dsa::delegation_hash(&d);
        let now = clock.load(Ordering::Relaxed);
        assert!(
            agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 60, 1, now))
                .accepted
        );
        assert!(
            agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 40, 2, now))
                .accepted
        );
        let r3 = agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xCC; 20], 10, 3, now));
        assert!(!r3.accepted);
        assert_eq!(r3.reject_reason, Some(Error::EBudgetTotal));
        assert_eq!(agg.total_spent(&dh), Some(100));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn expired_intent_rejected() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("expintent");
        let agg = test_aggregator(&clock, &path);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, 1_699_999_000);
        // 时钟在 intent.expires_at (= now+60) 之后。
        clock.store(1_699_999_200, Ordering::Relaxed);
        let r = agg.submit(&env);
        assert!(!r.accepted);
        assert_eq!(r.reject_reason, Some(Error::EIntentExpired));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn expired_delegation_rejected() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("expdeleg");
        let agg = test_aggregator(&clock, &path);
        // 委托永不过期（u64::MAX）→ 永不触发；改用已过期委托。
        let d = Delegation {
            expires_at: 1_699_000_000,
            ..delegation([1u8; 20], 1_000, 1_000_000)
        };
        let sd = sign_delegation(&d, &owner_signing_key_from_bytes([7u8; 32]));
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        agg.register(sd, agent_key.verifying_key());
        let dh = meridian_core::dsa::delegation_hash(&d);
        let env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, 1_700_000_000);
        let r = agg.submit(&env);
        assert!(!r.accepted);
        assert_eq!(r.reject_reason, Some(Error::EDelegExpired));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn proof_public_inputs_mismatch_rejected() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("mismatch");
        let agg = test_aggregator(&clock, &path);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        // 信封的意图没问题，但证明的公共输入换了 dh。
        let mut env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now);
        env.proof.public_inputs.delegation_hash = [0x99; 32];
        let r = agg.submit(&env);
        assert!(!r.accepted);
        assert_eq!(r.reject_reason, Some(Error::EOrdering));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_proof_rejected() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("emptyproof");
        let agg = test_aggregator(&clock, &path);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        let mut env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now);
        env.proof.proof.clear();
        let r = agg.submit(&env);
        assert!(!r.accepted);
        assert_eq!(r.reject_reason, Some(Error::EProof));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn window_rotation_seals_full_epoch() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("rotate");
        let mut cfg = test_cfg();
        cfg.epoch_capacity = 4;
        let c = Arc::clone(&clock);
        let wal = Wal::open(&path, 100_000).unwrap();
        let agg = Aggregator::with_clock(
            cfg,
            Box::new(FormatVerifier),
            wal,
            Box::new(move || c.load(Ordering::Relaxed)),
        );
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        // 第 4 笔填满窗口 → 第 5 笔前自动封窗。
        for i in 0..6 {
            let r = agg.submit(&make_env(
                dh,
                [1u8; 20],
                &agent_key,
                [i as u8; 20],
                1,
                i + 1,
                now,
            ));
            assert!(r.accepted, "intent {i} should accept");
        }
        let sealed = agg.take_sealed();
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].epoch_id, 0);
        assert_eq!(sealed[0].entries.len(), 4);
        // 条目按 seq 升序。
        assert_eq!(
            sealed[0].entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn seal_expired_by_time() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("sealtime");
        let agg = test_aggregator(&clock, &path);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        assert!(
            agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 1, 1, now))
                .accepted
        );
        assert!(agg.pending_sealed() == 0);
        // 时间到点（epoch_secs=60）。
        clock.store(now + 61, Ordering::Relaxed);
        let sealed = agg.seal_expired(now + 61, 60);
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].entries.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn settle_epoch_produces_net_and_prunes_index() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("settle");
        let mut cfg = test_cfg();
        cfg.epoch_capacity = 4;
        let c = Arc::clone(&clock);
        let wal = Wal::open(&path, 100_000).unwrap();
        let agg = Aggregator::with_clock(
            cfg,
            Box::new(FormatVerifier),
            wal,
            Box::new(move || c.load(Ordering::Relaxed)),
        );
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        // 3 笔 → 0xAA，1 笔 → 0xBB；第 4 笔填满窗口 → 封 epoch。
        assert!(
            agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now))
                .accepted
        );
        assert!(
            agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 20, 2, now))
                .accepted
        );
        assert!(
            agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 5, 3, now))
                .accepted
        );
        assert!(
            agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 30, 4, now))
                .accepted
        );
        let sealed = agg.take_sealed();
        assert_eq!(sealed.len(), 1);
        let res = agg.settle_epoch(&sealed[0]).expect("settle ok");
        // 净额：AA=10+20+30=60，BB=5；规范序 AA（0xAA）在前。
        assert_eq!(res.net.len(), 2);
        assert_eq!(res.net[0].recipient, [0xAA; 20]);
        assert_eq!(res.net[0].amount, 60);
        assert_eq!(res.net[1].recipient, [0xBB; 20]);
        assert_eq!(res.net[1].amount, 5);
        // 承诺根 / 净额根非零；净额根 = keccak256(abi.encode(net))（lattice 单测锁定字节布局）。
        assert_ne!(res.commitment_root, [0u8; 32]);
        assert_ne!(res.netting_root, [0u8; 32]);
        // WAL 已记录 EpochSeal + Netting（先 flush 缓冲到盘，replay 读文件）。
        agg.wal.flush().unwrap();
        let (records, _, truncated) = agg.wal.replay().unwrap();
        assert!(!truncated);
        let seal = records
            .iter()
            .find(|r| matches!(r, DecodedRecord::EpochSeal { .. }))
            .expect("epoch seal recorded");
        assert!(matches!(
            seal,
            DecodedRecord::EpochSeal {
                epoch_id: 0,
                accepted_count: 4,
                ..
            }
        ));
        let net = records
            .iter()
            .find(|r| matches!(r, DecodedRecord::Netting { .. }))
            .expect("netting recorded");
        assert!(matches!(
            net,
            DecodedRecord::Netting {
                epoch_id: 0,
                net_count: 2,
                ..
            }
        ));
        // 索引已修剪：再 settle 同 epoch → 缺失解析 → None（不会重复记账 / 记录）。
        assert!(agg.settle_epoch(&sealed[0]).is_none());
        let _ = std::fs::remove_file(&path);
    }

    /// S-30a 只读回执查询：接受命中（seq 一致）、被拒/从未见 → None、结算修剪 → None。
    #[test]
    fn receipt_lookup_hits_before_settle_and_none_after() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("receipt");
        let mut cfg = test_cfg();
        cfg.epoch_capacity = 2;
        let c = Arc::clone(&clock);
        let wal = Wal::open(&path, 100_000).unwrap();
        let agg = Aggregator::with_clock(
            cfg,
            Box::new(FormatVerifier),
            wal,
            Box::new(move || c.load(Ordering::Relaxed)),
        );
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);

        // 接受 → 命中：accepted 回执含同一 seq。
        let env1 = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now);
        let r1 = agg.submit(&env1);
        assert!(r1.accepted);
        let ih1 = intent_hash(&env1.intent);
        let got = agg.receipt(&ih1).expect("accepted intent queryable");
        assert!(got.accepted);
        assert_eq!(got.seq, r1.seq);
        assert_eq!(got.intent_hash, ih1);
        assert_eq!(got.reject_reason, None);

        // 被拒意图不入索引（拒绝回执是瞬态响应）→ None。
        let env2 = make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 2_000, 2, now);
        let r2 = agg.submit(&env2);
        assert!(!r2.accepted);
        assert_eq!(agg.receipt(&intent_hash(&env2.intent)), None);

        // 从未见 → None。
        assert_eq!(agg.receipt(&[0xEE; 32]), None);

        // 结算修剪 → None（查询方语义：404 ≠ 未支付，终局保证在链上净额）。
        clock.store(now + 1, Ordering::Relaxed);
        assert!(
            agg.submit(&make_env(
                dh,
                [1u8; 20],
                &agent_key,
                [0xCC; 20],
                10,
                3,
                now + 1
            ))
            .accepted
        );
        let sealed = agg.take_sealed();
        assert_eq!(sealed.len(), 1);
        agg.settle_epoch(&sealed[0]).expect("settle ok");
        assert_eq!(agg.receipt(&ih1), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn restore_rebuilds_registry_ledger_and_seq() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("restore");
        let now = clock.load(Ordering::Relaxed);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let d = delegation([1u8; 20], 1_000, 1_000_000);
        let dh = meridian_core::dsa::delegation_hash(&d);

        {
            let agg = test_aggregator(&clock, &path);
            let sd = sign_delegation(&d, &owner_signing_key_from_bytes([7u8; 32]));
            agg.register(sd, agent_key.verifying_key());
            for i in 0..3 {
                let r = agg.submit(&make_env(
                    dh,
                    [1u8; 20],
                    &agent_key,
                    [i as u8; 20],
                    5,
                    i + 1,
                    now,
                ));
                assert!(r.accepted);
            }
            agg.wal.flush().unwrap();
        } // 模拟崩溃：聚合器丢弃，只剩 WAL

        let c = Arc::clone(&clock);
        let (agg2, truncated) = Aggregator::restore_from_wal(
            test_cfg(),
            Box::new(FormatVerifier),
            &path,
            Box::new(move || c.load(Ordering::Relaxed)),
        )
        .unwrap();
        assert!(!truncated);
        assert_eq!(agg2.registry_len(), 1);
        assert_eq!(agg2.total_spent(&dh), Some(15));
        assert_eq!(agg2.nonce_count(&dh), Some(3));
        assert_eq!(agg2.accepted_count(), 3);
        // 崩溃后继续摄取，seq 接着来。
        let r = agg2.submit(&make_env(dh, [1u8; 20], &agent_key, [0xEE; 20], 5, 4, now));
        assert!(r.accepted);
        assert_eq!(r.seq, 3);
        assert_eq!(agg2.total_spent(&dh), Some(20));
        let _ = std::fs::remove_file(&path);
    }

    /// 结算全部已封 epoch 并校验不变量（S-10c 的 fuzz 断言）：Σnet == Σaccepted；
    /// 每个 accepted 的 intent_hash 恰出现在一个 epoch 里一次；无 rejected 的 intent_hash
    /// 入承诺（无双重记账、无丢失）。
    fn settle_all_and_check(agg: &Aggregator, expected: &[(bool, [u8; 32], u64)]) {
        let now = (agg.now_fn)();
        let mut sum_accepted: u64 = 0;
        for (ok, _, amt) in expected {
            if *ok {
                sum_accepted = sum_accepted.saturating_add(*amt);
            }
        }
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut sum_net: u64 = 0;
        let mut total_entries = 0usize;
        // 反复封当前窗 + 取走密封队列结算，直到无新已封 epoch。
        loop {
            let sealed = agg.seal_expired(now + 10_000, 1);
            if sealed.is_empty() {
                break;
            }
            for se in &sealed {
                let res = agg.settle_epoch(se).expect("settle must succeed");
                total_entries += se.entries.len();
                for e in &se.entries {
                    assert!(
                        seen.insert(e.intent_hash),
                        "double entry: {:?}",
                        e.intent_hash
                    );
                }
                for l in &res.net {
                    sum_net = sum_net.saturating_add(l.amount);
                }
            }
        }
        assert_eq!(total_entries, seen.len(), "each entry exactly once");
        assert_eq!(sum_net, sum_accepted, "Σnet must equal Σaccepted");
        for (ok, ih, _) in expected {
            assert_eq!(
                seen.contains(ih),
                *ok,
                "accepted iff in commitment (no double-entry / no loss)"
            );
        }
    }

    /// S-10c 故障注入：撕裂尾（头完整、payload 残缺 + 错 crc）→ 恢复截断 → 账本与 accepted
    /// 前缀一致，继续摄取 seq 接着来，且全部意图可完整结算。
    #[test]
    fn restore_after_torn_tail_matches_accepted_prefix() {
        use std::fs::OpenOptions;
        use std::io::Write as _;
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("torntail");
        let now = clock.load(Ordering::Relaxed);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let d = delegation([1u8; 20], 100, 1_000_000); // max_per_spend=100
        let dh = meridian_core::dsa::delegation_hash(&d);
        let mut expected: Vec<(bool, [u8; 32], u64)> = Vec::new();
        {
            let agg = test_aggregator(&clock, &path);
            let sd = sign_delegation(&d, &owner_signing_key_from_bytes([7u8; 32]));
            agg.register(sd, agent_key.verifying_key());
            // 3 笔有效 + 1 笔超预算（101 > 100）+ 1 笔重复 nonce（2 已用）。
            for (amt, nonce) in [(10u64, 1u64), (20, 2), (30, 3)] {
                let env = make_env(
                    dh,
                    [1u8; 20],
                    &agent_key,
                    [nonce as u8; 20],
                    amt,
                    nonce,
                    now,
                );
                let r = agg.submit(&env);
                assert!(r.accepted);
                expected.push((true, meridian_core::dsa::intent_hash(&env.intent), amt));
            }
            let over = make_env(dh, [1u8; 20], &agent_key, [0xEE; 20], 101, 4, now);
            let r = agg.submit(&over);
            assert_eq!(r.reject_reason, Some(Error::EBudgetPerSpend));
            expected.push((false, meridian_core::dsa::intent_hash(&over.intent), 101));
            let dup = make_env(dh, [1u8; 20], &agent_key, [0xDD; 20], 5, 2, now);
            let r = agg.submit(&dup);
            assert_eq!(r.reject_reason, Some(Error::ENonce));
            expected.push((false, meridian_core::dsa::intent_hash(&dup.intent), 5));
            agg.wal.flush().unwrap();
            // 手工追加撕裂尾：一条头完整、payload 残缺 + 错 crc 的 Intent 记录。
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            let mut header = [0u8; 12];
            header[0..2].copy_from_slice(&0x4D4Du16.to_le_bytes());
            header[2] = 1; // version
            header[3] = 2; // RecordKind::Intent
            header[4..8].copy_from_slice(&116u32.to_le_bytes());
            header[8..12].copy_from_slice(&0u32.to_le_bytes()); // 错 crc
            f.write_all(&header).unwrap();
            f.write_all(&[0u8; 10]).unwrap();
        } // 崩溃：聚合器丢弃，WAL 带撕裂尾

        let c = Arc::clone(&clock);
        let (agg2, truncated) = Aggregator::restore_from_wal(
            test_cfg(),
            Box::new(FormatVerifier),
            &path,
            Box::new(move || c.load(Ordering::Relaxed)),
        )
        .unwrap();
        assert!(truncated, "torn tail must be detected and truncated");
        // 账本与 accepted 前缀一致（拒绝不占用）。
        assert_eq!(agg2.total_spent(&dh), Some(60));
        assert_eq!(agg2.nonce_count(&dh), Some(3));
        assert_eq!(agg2.accepted_count(), 3);
        // 继续摄取 seq 接着来，且全部意图能完整结算。
        let r = agg2.submit(&make_env(dh, [1u8; 20], &agent_key, [0x11; 20], 40, 5, now));
        assert!(r.accepted);
        assert_eq!(r.seq, 3);
        expected.push((true, r.intent_hash, 40));
        settle_all_and_check(&agg2, &expected);
        let _ = std::fs::remove_file(&path);
    }

    /// S-10c 未密封尾重建：崩溃时窗口未满未封 → 恢复后当前窗口重建全部尾意图 →
    /// 再提交到满 → 封 → 净额覆盖尾 + 新意图，Σnet == Σaccepted。
    #[test]
    fn restore_rebuilds_unsealed_window_tail() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("tail");
        let now = clock.load(Ordering::Relaxed);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let d = delegation([1u8; 20], 1_000, 1_000_000);
        let dh = meridian_core::dsa::delegation_hash(&d);
        let mut cfg = test_cfg();
        cfg.epoch_capacity = 4;
        {
            let c = Arc::clone(&clock);
            let wal = Wal::open(&path, 100_000).unwrap();
            let agg = Aggregator::with_clock(
                cfg.clone(),
                Box::new(FormatVerifier),
                wal,
                Box::new(move || c.load(Ordering::Relaxed)),
            );
            let sd = sign_delegation(&d, &owner_signing_key_from_bytes([7u8; 32]));
            agg.register(sd, agent_key.verifying_key());
            for amt in [10u64, 20, 30] {
                let env = make_env(dh, [1u8; 20], &agent_key, [amt as u8; 20], amt, amt, now);
                assert!(agg.submit(&env).accepted);
            }
            agg.wal.flush().unwrap();
        } // 崩溃：3 笔已接受但窗口未满未封（未密封尾）

        let c = Arc::clone(&clock);
        let (agg2, truncated) = Aggregator::restore_from_wal(
            cfg.clone(),
            Box::new(FormatVerifier),
            &path,
            Box::new(move || c.load(Ordering::Relaxed)),
        )
        .unwrap();
        assert!(!truncated);
        // 恢复后注册表/账本已重建；当前窗口含 3 笔尾意图。
        assert_eq!(agg2.registry_len(), 1);
        assert_eq!(agg2.total_spent(&dh), Some(60));
        // 提交第 4 笔 → 满窗自动封 → 承诺覆盖尾(3) + 新(1)。
        let r4 = agg2.submit(&make_env(dh, [1u8; 20], &agent_key, [0x44; 20], 40, 4, now));
        assert!(r4.accepted);
        assert_eq!(r4.seq, 3);
        let sealed = agg2.take_sealed();
        assert_eq!(sealed.len(), 1, "window sealed after 4th intent");
        assert_eq!(sealed[0].epoch_id, 0, "no prior seal → epoch 0");
        assert_eq!(
            sealed[0].entries.len(),
            4,
            "tail (3) + new (1) all in commitment"
        );
        assert_eq!(
            sealed[0].entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        let res = agg2.settle_epoch(&sealed[0]).expect("settle ok");
        let sum_net: u64 = res.net.iter().map(|l| l.amount).sum();
        assert_eq!(sum_net, 100, "Σnet == Σaccepted (10+20+30+40)");
        let _ = std::fs::remove_file(&path);
    }

    /// S-10c epoch 编号续接：崩溃前已封已结算 epoch 0 → 恢复后从 epoch 1 继续，
    /// 已提交意图不进当前窗口（无双重承诺）。
    #[test]
    fn restore_continues_epoch_numbering_after_prior_seal() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("epocont");
        let now = clock.load(Ordering::Relaxed);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let d = delegation([1u8; 20], 1_000, 1_000_000);
        let dh = meridian_core::dsa::delegation_hash(&d);
        let mut cfg = test_cfg();
        cfg.epoch_capacity = 4;
        {
            let c = Arc::clone(&clock);
            let wal = Wal::open(&path, 100_000).unwrap();
            let agg = Aggregator::with_clock(
                cfg.clone(),
                Box::new(FormatVerifier),
                wal,
                Box::new(move || c.load(Ordering::Relaxed)),
            );
            let sd = sign_delegation(&d, &owner_signing_key_from_bytes([7u8; 32]));
            agg.register(sd, agent_key.verifying_key());
            for i in 1..=4u64 {
                let env = make_env(dh, [1u8; 20], &agent_key, [i as u8; 20], 1, i, now);
                assert!(agg.submit(&env).accepted);
            }
            // 第 4 笔后满窗自动封（epoch 0）。
            let sealed = agg.take_sealed();
            assert_eq!(sealed.len(), 1);
            assert_eq!(sealed[0].epoch_id, 0);
            agg.settle_epoch(&sealed[0]).expect("settle epoch 0");
            agg.wal.flush().unwrap();
        } // 崩溃：epoch 0 已封已结算

        let c = Arc::clone(&clock);
        let (agg2, truncated) = Aggregator::restore_from_wal(
            cfg.clone(),
            Box::new(FormatVerifier),
            &path,
            Box::new(move || c.load(Ordering::Relaxed)),
        )
        .unwrap();
        assert!(!truncated);
        // 恢复后当前窗口为空（epoch 0 意图已提交，不入索引/窗口）；epoch 编号从 1 续。
        for i in 5..=8u64 {
            let env = make_env(dh, [1u8; 20], &agent_key, [i as u8; 20], 1, i, now);
            assert!(agg2.submit(&env).accepted);
        }
        let sealed = agg2.take_sealed();
        assert_eq!(sealed.len(), 1);
        assert_eq!(
            sealed[0].epoch_id, 1,
            "epoch numbering continues after restore"
        );
        assert_eq!(sealed[0].entries.len(), 4);
        assert_eq!(
            sealed[0].entries[0].seq, 4,
            "post-restore intents start at seq 4"
        );
        for e in &sealed[0].entries {
            assert!(e.seq >= 4, "no epoch-0 intent re-enters commitment");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// S-11：撤销后新意图 E_REVOKED 拒，不耗 nonce/窗口槽；撤销前已接受意图不受影响（非追溯）。
    #[test]
    fn revoked_delegation_new_intents_rejected() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("revoked");
        let agg = test_aggregator(&clock, &path);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        // 撤销前接受 1 笔。
        assert!(
            agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now))
                .accepted
        );
        // 撤销 → 新意图 E_REVOKED 拒，seq 不前进（不耗窗口槽）。
        assert!(agg.revoke(dh));
        assert!(!agg.revoke(dh), "重复撤销幂等");
        let r = agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 20, 2, now));
        assert!(!r.accepted);
        assert_eq!(r.reject_reason, Some(Error::ERevoked));
        assert_eq!(r.seq, 0);
        assert_eq!(agg.accepted_count(), 1, "撤销前意图不受影响");
        assert_eq!(agg.nonce_count(&dh), Some(1));
        // 撤销前已接受的意图仍可结算（非追溯）。
        let sealed = agg.seal_expired(now + 10_000, 1);
        assert_eq!(sealed.len(), 1);
        let res = agg.settle_epoch(&sealed[0]).expect("settle ok");
        let sum_net: u64 = res.net.iter().map(|l| l.amount).sum();
        assert_eq!(sum_net, 10);
        let _ = std::fs::remove_file(&path);
    }

    /// S-11：撤销根随下个密封 epoch 上链——epoch 0 无撤销 → 空根；revoke 后 epoch 1 的
    /// 撤销根 = 当前撤销集稀疏根且 ≠ epoch 0（验收：撤销事件 1 epoch 内进入撤销根）。
    #[test]
    fn revocation_root_anchored_in_next_epoch() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("revroot");
        let mut cfg = test_cfg();
        cfg.epoch_capacity = 4;
        let c = Arc::clone(&clock);
        let wal = Wal::open(&path, 100_000).unwrap();
        let agg = Aggregator::with_clock(
            cfg,
            Box::new(FormatVerifier),
            wal,
            Box::new(move || c.load(Ordering::Relaxed)),
        );
        // 两个委托：dh_a 用于 epoch 0 并随后撤销；dh_b 用于 epoch 1（被撤销委托不能再提交）。
        let (dh_a, _) = register_default(&agg, [0x01; 20]);
        let (dh_b, _) = register_default(&agg, [0x02; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        let empty_root = RevocationSet::new().sparse_root();
        // epoch 0：4 笔 dh_a，无撤销。
        for i in 0..4u64 {
            assert!(
                agg.submit(&make_env(
                    dh_a,
                    [0x01; 20],
                    &agent_key,
                    [i as u8; 20],
                    1,
                    i + 1,
                    now
                ))
                .accepted
            );
        }
        let sealed = agg.seal_expired(now + 10_000, 1);
        assert_eq!(sealed.len(), 1);
        let res0 = agg.settle_epoch(&sealed[0]).expect("settle epoch 0");
        assert_eq!(res0.revocation_root, empty_root, "epoch 0 撤销根 = 空根");
        // 撤销 dh_a → epoch 1 的撤销根变化。
        assert!(agg.revoke(dh_a));
        for i in 0..4u64 {
            assert!(
                agg.submit(&make_env(
                    dh_b,
                    [0x02; 20],
                    &agent_key,
                    [i as u8; 20],
                    1,
                    i + 1,
                    now
                ))
                .accepted
            );
        }
        let sealed = agg.seal_expired(now + 20_000, 1);
        assert_eq!(sealed.len(), 1);
        let res1 = agg.settle_epoch(&sealed[0]).expect("settle epoch 1");
        assert_eq!(res1.revocation_root, agg.revocation_root());
        assert_ne!(res1.revocation_root, res0.revocation_root, "撤销根已变化");
        let _ = std::fs::remove_file(&path);
    }

    /// S-11c 前提：撤销集崩溃后可重放重建，撤销根精确一致，且恢复后新意图仍 E_REVOKED。
    #[test]
    fn revoke_survives_crash_restore() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("revrestore");
        let now = clock.load(Ordering::Relaxed);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let d = delegation([1u8; 20], 1_000, 1_000_000);
        let dh = meridian_core::dsa::delegation_hash(&d);
        let expect_root;
        {
            let agg = test_aggregator(&clock, &path);
            let sd = sign_delegation(&d, &owner_signing_key_from_bytes([7u8; 32]));
            agg.register(sd, agent_key.verifying_key());
            agg.revoke(dh);
            expect_root = agg.revocation_root();
            agg.wal.flush().unwrap();
        } // 崩溃：聚合器丢弃，只剩 WAL

        let c = Arc::clone(&clock);
        let (agg2, truncated) = Aggregator::restore_from_wal(
            test_cfg(),
            Box::new(FormatVerifier),
            &path,
            Box::new(move || c.load(Ordering::Relaxed)),
        )
        .unwrap();
        assert!(!truncated);
        assert!(agg2.is_revoked(&dh), "撤销集由 WAL 重放重建");
        assert_eq!(agg2.revoked_len(), 1);
        assert_eq!(agg2.revocation_root(), expect_root, "撤销根崩溃前后一致");
        // 恢复后新意图仍拒。
        let r = agg2.submit(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now));
        assert!(!r.accepted);
        assert_eq!(r.reject_reason, Some(Error::ERevoked));
        let _ = std::fs::remove_file(&path);
    }

    /// S-11c：撤销与意图交错 + 崩溃恢复——撤销前 A 意图照常结算（非追溯）、撤销后 A 新意图
    /// E_REVOKED（seq 不前进）、恢复后撤销集/撤销根/nonce 集/seq 全部精确续接、B 不受影响，
    /// 全量结算保持不变量（Σnet == Σaccepted、每笔恰一次、rejected 不入承诺）。
    #[test]
    fn revoke_interleaved_crash_restore_ledger_consistent() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("revinter");
        let now = clock.load(Ordering::Relaxed);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let mut cfg = test_cfg();
        cfg.epoch_capacity = 1000; // 过程中不自动封窗，最后统一结算
        let mut expected: Vec<(bool, [u8; 32], u64)> = Vec::new();
        let dh_a;
        let dh_b;
        let expect_root;
        {
            let c = Arc::clone(&clock);
            let wal = Wal::open(&path, 100_000).unwrap();
            let agg = Aggregator::with_clock(
                cfg.clone(),
                Box::new(FormatVerifier),
                wal,
                Box::new(move || c.load(Ordering::Relaxed)),
            );
            let (a, _) = register_default(&agg, [0x01; 20]);
            let (b, _) = register_default(&agg, [0x02; 20]);
            dh_a = a;
            dh_b = b;
            // 撤销前：A 3 笔 + B 3 笔（同 seq 序落 WAL）。
            for i in 0..3u64 {
                for (dh, agent) in [(dh_a, [0x01; 20]), (dh_b, [0x02; 20])] {
                    let env = make_env(dh, agent, &agent_key, [i as u8; 20], 10, i + 1, now);
                    let r = agg.submit(&env);
                    assert!(r.accepted);
                    expected.push((true, meridian_core::dsa::intent_hash(&env.intent), 10));
                }
            }
            // 撤销 A。
            assert!(agg.revoke(dh_a));
            // 撤销后：A 新意图 E_REVOKED（不耗窗口槽）；B 继续接受。
            let env_rev = make_env(dh_a, [0x01; 20], &agent_key, [0xAA; 20], 10, 4, now);
            let r = agg.submit(&env_rev);
            assert!(!r.accepted);
            assert_eq!(r.reject_reason, Some(Error::ERevoked));
            expected.push((false, meridian_core::dsa::intent_hash(&env_rev.intent), 10));
            assert_eq!(agg.accepted_count(), 6, "ERevoked 不耗窗口槽");
            for i in 4..6u64 {
                let env = make_env(dh_b, [0x02; 20], &agent_key, [i as u8; 20], 5, i + 1, now);
                let r = agg.submit(&env);
                assert!(r.accepted);
                expected.push((true, meridian_core::dsa::intent_hash(&env.intent), 5));
            }
            expect_root = agg.revocation_root();
            agg.wal.flush().unwrap();
        } // 崩溃：聚合器丢弃，只剩 WAL

        // 恢复：撤销集/撤销根/nonce/seq 全部续接。
        let c = Arc::clone(&clock);
        let (agg2, truncated) = Aggregator::restore_from_wal(
            test_cfg(),
            Box::new(FormatVerifier),
            &path,
            Box::new(move || c.load(Ordering::Relaxed)),
        )
        .unwrap();
        assert!(!truncated);
        assert!(agg2.is_revoked(&dh_a));
        assert!(!agg2.is_revoked(&dh_b));
        assert_eq!(agg2.revocation_root(), expect_root, "撤销根崩溃前后一致");
        assert_eq!(agg2.nonce_count(&dh_a), Some(3), "A 只保留撤销前的 nonce");
        assert_eq!(agg2.nonce_count(&dh_b), Some(5), "B 的 nonce 完整");
        assert_eq!(
            agg2.accepted_count(),
            8,
            "恢复后已接受数 = 撤销前 6 + 撤销后 B 2"
        );
        // 恢复后续接：B 继续接受（seq 从 8 续）、A 仍 E_REVOKED。
        let env = make_env(dh_b, [0x02; 20], &agent_key, [0xBB; 20], 5, 7, now);
        let r = agg2.submit(&env);
        assert!(r.accepted);
        assert_eq!(r.seq, 8, "恢复后 seq 从已接受数续接");
        expected.push((true, meridian_core::dsa::intent_hash(&env.intent), 5));
        let r = agg2.submit(&make_env(
            dh_a, [0x01; 20], &agent_key, [0xCC; 20], 10, 5, now,
        ));
        assert!(!r.accepted);
        assert_eq!(r.reject_reason, Some(Error::ERevoked));
        // 全量结算：不变量保持（含 A 撤销前 3 笔、B 全部）。
        settle_all_and_check(&agg2, &expected);
        let _ = std::fs::remove_file(&path);
    }

    /// S-11c：撤销 + 崩溃后 epoch 编号续接（不重复已密封 epoch_id），撤销根随恢复后 epoch
    /// 锚定并已变化（1 epoch 内进入撤销根），撤销前接受的意图仍在原 epoch 净额中（非追溯）。
    #[test]
    fn revoke_crash_epoch_numbering_continues_and_root_anchors() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("revecpoch");
        let now = clock.load(Ordering::Relaxed);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let mut cfg = test_cfg();
        cfg.epoch_capacity = 4;
        let res0_root;
        let sum0: u64;
        let dh_a;
        let dh_b;
        {
            let c = Arc::clone(&clock);
            let wal = Wal::open(&path, 100_000).unwrap();
            let agg = Aggregator::with_clock(
                cfg.clone(),
                Box::new(FormatVerifier),
                wal,
                Box::new(move || c.load(Ordering::Relaxed)),
            );
            let (a, _) = register_default(&agg, [0x01; 20]);
            let (b, _) = register_default(&agg, [0x02; 20]);
            dh_a = a;
            dh_b = b;
            // epoch 0：4 笔 A（满窗即封）。
            for i in 0..4u64 {
                assert!(
                    agg.submit(&make_env(
                        dh_a,
                        [0x01; 20],
                        &agent_key,
                        [i as u8; 20],
                        1,
                        i + 1,
                        now
                    ))
                    .accepted
                );
            }
            let sealed = agg.seal_expired(now + 10_000, 1);
            assert_eq!(sealed.len(), 1);
            assert_eq!(sealed[0].epoch_id, 0);
            let res0 = agg.settle_epoch(&sealed[0]).expect("settle epoch 0");
            res0_root = res0.revocation_root;
            sum0 = res0.net.iter().map(|l| l.amount).sum();
            // 撤销 A 后崩溃。
            assert!(agg.revoke(dh_a));
            agg.wal.flush().unwrap();
        }

        // 恢复：epoch 编号接到 1，撤销集重建。
        let c = Arc::clone(&clock);
        let (agg2, truncated) = Aggregator::restore_from_wal(
            test_cfg(),
            Box::new(FormatVerifier),
            &path,
            Box::new(move || c.load(Ordering::Relaxed)),
        )
        .unwrap();
        assert!(!truncated);
        assert!(agg2.is_revoked(&dh_a));
        // epoch 1：4 笔 B（A 已撤销不能再用）。
        for i in 0..4u64 {
            assert!(
                agg2.submit(&make_env(
                    dh_b,
                    [0x02; 20],
                    &agent_key,
                    [i as u8; 20],
                    1,
                    i + 1,
                    now
                ))
                .accepted
            );
        }
        let sealed = agg2.seal_expired(now + 20_000, 1);
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].epoch_id, 1, "恢复后 epoch 编号续接（不重复 0）");
        let res1 = agg2.settle_epoch(&sealed[0]).expect("settle epoch 1");
        assert_eq!(res1.revocation_root, agg2.revocation_root());
        assert_ne!(
            res1.revocation_root, res0_root,
            "撤销根随恢复后 epoch 锚定并已变化"
        );
        // 非追溯：撤销前接受的 A 意图仍在 epoch 0 净额中。
        assert_eq!(sum0, 4);
        let _ = std::fs::remove_file(&path);
    }

    /// S-10c 并发 fuzz（确定性）：8 线程并发提交混入重复 nonce / 超预算的批次，结算全部
    /// epoch 后不变量保持——无双重记账、每个 accepted 恰一次、Σnet == Σaccepted。
    #[test]
    fn concurrent_batch_no_double_entry_and_net_equals_accepted() {
        use std::thread;
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("conc");
        let now = clock.load(Ordering::Relaxed);
        let mut cfg = test_cfg();
        cfg.epoch_capacity = 8;
        let c = Arc::clone(&clock);
        let wal = Wal::open(&path, 100_000).unwrap();
        let agg = Arc::new(Aggregator::with_clock(
            cfg,
            Box::new(FormatVerifier),
            wal,
            Box::new(move || c.load(Ordering::Relaxed)),
        ));
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        const THREADS: usize = 8;
        const PER: usize = 200;
        // 每 5 笔超预算（max_per_spend=1000 → EBudgetPerSpend）；每 7 笔跨线程重复 nonce
        // （→ ENonce）；其余有效。并发乱序提交。
        let envs: Vec<IntentEnvelope> = (0..THREADS * PER)
            .map(|i| {
                let t = i / PER;
                let n = i % PER;
                let amount = if n.is_multiple_of(5) { 5_000 } else { 1 };
                let nonce = if n.is_multiple_of(7) {
                    100_000 + t as u64
                } else {
                    (t * 1000 + n) as u64
                };
                let recipient = [(n % 250 + 1) as u8; 20];
                make_env(dh, [1u8; 20], &agent_key, recipient, amount, nonce, now)
            })
            .collect();
        let mut expected: Vec<(bool, [u8; 32], u64)> = envs
            .iter()
            .map(|env| {
                (
                    true,
                    meridian_core::dsa::intent_hash(&env.intent),
                    env.intent.amount,
                )
            })
            .collect();
        let threads: Vec<_> = envs
            .chunks(PER)
            .map(|chunk| {
                let agg = Arc::clone(&agg);
                let chunk = chunk.to_vec();
                thread::spawn(move || chunk.iter().map(|env| agg.submit(env)).collect::<Vec<_>>())
            })
            .collect();
        for (ti, t) in threads.into_iter().enumerate() {
            let receipts = t.join().unwrap();
            for (j, r) in receipts.into_iter().enumerate() {
                expected[ti * PER + j].0 = r.accepted;
            }
        }
        settle_all_and_check(&agg, &expected);
        let _ = std::fs::remove_file(&path);
    }

    // S-10c 随机 fuzz（proptest）：任意 (金额, nonce, 收款方, 时间偏移) 组合提交后结算，
    // 不变量保持：Σnet == Σaccepted、每 accepted 恰一次、无 rejected 入承诺。
    // 32 例 × ≤40 笔：覆盖随机碰撞/拒绝路径，CI 时间可控（全量 256 例在 S-10d 手动跑）。
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn fuzz_random_batch_preserves_invariants(
            ops in proptest::collection::vec(
                (any::<u16>(), any::<u16>(), any::<u16>(), any::<u8>()),
                0..40,
            ),
        ) {
            let clock = Arc::new(AtomicU64::new(1_700_000_000));
            let path = tmp_path("fuzz");
            let now = clock.load(Ordering::Relaxed);
            let mut cfg = test_cfg();
            cfg.epoch_capacity = 8;
            let c = Arc::clone(&clock);
            let wal = Wal::open(&path, 100_000).unwrap();
            let agg = Aggregator::with_clock(
                cfg,
                Box::new(FormatVerifier),
                wal,
                Box::new(move || c.load(Ordering::Relaxed)),
            );
            let (dh, _) = register_default(&agg, [1u8; 20]);
            let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
            let mut expected: Vec<(bool, [u8; 32], u64)> = Vec::new();
            for (amt, nonce, recip, off) in ops {
                let amount = amt as u64 % 1200; // 部分超 max_per_spend=1000
                let env = make_env(
                    dh,
                    [1u8; 20],
                    &agent_key,
                    [recip as u8; 20],
                    amount,
                    nonce as u64,
                    now + off as u64,
                );
                let r = agg.submit(&env);
                expected.push((
                    r.accepted,
                    meridian_core::dsa::intent_hash(&env.intent),
                    amount,
                ));
            }
            settle_all_and_check(&agg, &expected);
            let _ = std::fs::remove_file(&path);
        }
    }

    // S-11c 随机 fuzz（proptest）：submit/revoke 交错 + 中途崩溃恢复。确定性前缀保证覆盖
    // 撤销路径（A 接受一笔 → revoke A → A 再提交 E_REVOKED）；随后随机 op 混入（kind%3：
    // 0=revoke A 幂等 / 1=submit B / 2=submit A→必 E_REVOKED）。阶段 1 结算后崩溃→恢复，撤销
    // 集/根一致；阶段 2 续接。不变量：Σnet == Σaccepted、每笔恰一次、撤销后 A 新意图
    // E_REVOKED 拒且不入承诺、B 不受影响、崩溃对账本不可见。
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn fuzz_revoke_interleaved_preserves_invariants(
            ops in proptest::collection::vec(
                (any::<u16>(), any::<u16>(), any::<u8>(), any::<u8>()),
                0..48,
            ),
        ) {
            let clock = Arc::new(AtomicU64::new(1_700_000_000));
            let path = tmp_path("fuzzrev");
            let now = clock.load(Ordering::Relaxed);
            let mut cfg = test_cfg();
            cfg.epoch_capacity = 8;
            let mut plan: Vec<(u8, u16, u8, u8)> = vec![
                (2, 1, 0x11, 0), // 先接受一笔 A
                (0, 0, 0, 0),    // revoke A
                (2, 1, 0x22, 0), // A → E_REVOKED
            ];
            plan.extend(
                ops.into_iter()
                    .map(|(k, amt, recip, off)| (k as u8, amt, recip, off)),
            );
            let dh_a;
            let dh_b;
            let expect_root;
            // nonce 计数器在函数作用域：跨崩溃持续递增（不依赖恢复后的 nonce_count —— 预算
            // 拒的 nonce 已消耗但不落 WAL，恢复重建的集合只含 accepted）。
            let mut nonce_a: u64 = 1;
            let mut nonce_b: u64 = 1;
            {
                let c = Arc::clone(&clock);
                let wal = Wal::open(&path, 100_000).unwrap();
                let agg = Aggregator::with_clock(
                    cfg.clone(),
                    Box::new(FormatVerifier),
                    wal,
                    Box::new(move || c.load(Ordering::Relaxed)),
                );
                let (a, _) = register_default(&agg, [0x01; 20]);
                let (b, _) = register_default(&agg, [0x02; 20]);
                dh_a = a;
                dh_b = b;
                let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
                let mut expected: Vec<(bool, [u8; 32], u64)> = Vec::new();
                // A 撤销标记：前缀 op1（(0,0,0,0)）撤销后，后续 A 提交一律 E_REVOKED；
                // op0（(2,1,0x11,0)）在撤销前，接受。
                let mut a_revoked = false;
                for (k, amt, recip, off) in &plan {
                    let amount = (*amt % 1200) as u64; // 部分超 max_per_spend=1000 → 预算拒
                    match k % 3 {
                        0 => {
                            agg.revoke(dh_a); // 撤销幂等
                            a_revoked = true;
                        }
                        1 => {
                            let env = make_env(
                                dh_b,
                                [0x02; 20],
                                &agent_key,
                                [*recip; 20],
                                amount,
                                nonce_b,
                                now + *off as u64,
                            );
                            let r = agg.submit(&env);
                            nonce_b += 1;
                            expected.push((
                                r.accepted,
                                meridian_core::dsa::intent_hash(&env.intent),
                                amount,
                            ));
                        }
                        _ => {
                            // A 已撤销：必 E_REVOKED，不耗 nonce/窗口槽。
                            let env = make_env(
                                dh_a,
                                [0x01; 20],
                                &agent_key,
                                [*recip; 20],
                                amount,
                                nonce_a,
                                now + *off as u64,
                            );
                            let r = agg.submit(&env);
                            nonce_a += 1;
                            assert_eq!(
                                r.accepted, !a_revoked,
                                "A 撤销前接受、撤销后 E_REVOKED"
                            );
                            if a_revoked {
                                assert_eq!(r.reject_reason, Some(Error::ERevoked));
                            }
                            expected.push((
                                r.accepted,
                                meridian_core::dsa::intent_hash(&env.intent),
                                amount,
                            ));
                        }
                    }
                }
                // 阶段 1 结算（耗尽密封队列，写 EpochSeal/Netting 边界 → 崩溃点干净）。
                settle_all_and_check(&agg, &expected);
                expect_root = agg.revocation_root();
                agg.wal.flush().unwrap();
            } // 崩溃：聚合器丢弃，只剩 WAL

            // 恢复：撤销集/根一致；阶段 2 续接（epoch 编号 + seq + 撤销闸口续效）。
            let c = Arc::clone(&clock);
            let (agg2, truncated) = Aggregator::restore_from_wal(
                test_cfg(),
                Box::new(FormatVerifier),
                &path,
                Box::new(move || c.load(Ordering::Relaxed)),
            )
            .unwrap();
            assert!(!truncated);
            assert!(agg2.is_revoked(&dh_a));
            assert!(!agg2.is_revoked(&dh_b));
            assert_eq!(agg2.revocation_root(), expect_root, "撤销根崩溃前后一致");
            let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
            let mut expected2: Vec<(bool, [u8; 32], u64)> = Vec::new();
            for i in 0..10u64 {
                let env = make_env(
                    dh_b,
                    [0x02; 20],
                    &agent_key,
                    [i as u8; 20],
                    1,
                    nonce_b,
                    now,
                );
                let rb = agg2.submit(&env);
                nonce_b += 1;
                expected2.push((rb.accepted, meridian_core::dsa::intent_hash(&env.intent), 1));
                let env = make_env(
                    dh_a,
                    [0x01; 20],
                    &agent_key,
                    [i as u8; 20],
                    1,
                    nonce_a,
                    now,
                );
                let ra = agg2.submit(&env);
                nonce_a += 1;
                assert!(!ra.accepted, "恢复后 A 仍 E_REVOKED");
                assert_eq!(ra.reject_reason, Some(Error::ERevoked));
                expected2.push((false, meridian_core::dsa::intent_hash(&env.intent), 1));
            }
            settle_all_and_check(&agg2, &expected2);
            let _ = std::fs::remove_file(&path);
        }
    }

    /// S-35：submit 全路径一律计时——接受、拒绝、幂等 re-ack 每次 `submit` 调用恰计一次；
    /// 会话口径（不持久化），新实例从 0 起。
    #[test]
    fn latency_histogram_counts_every_submit_call() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("hist");
        let agg = test_aggregator(&clock, &path);
        assert_eq!(agg.snapshot().submit_latency.count, 0, "新实例零计数");
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        // 2 笔接受 + 1 笔预算拒（2_000 > max_per_spend=1_000）。
        assert!(
            agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now))
                .accepted
        );
        assert!(
            agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 20, 2, now))
                .accepted
        );
        let rej = agg.submit(&make_env(
            dh, [1u8; 20], &agent_key, [0xCC; 20], 2_000, 3, now,
        ));
        assert_eq!(rej.reject_reason, Some(Error::EBudgetPerSpend));
        // 幂等 re-ack（同意图重发）也计一次。
        let env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now);
        assert!(agg.submit(&env).accepted);
        let s = agg.snapshot().submit_latency;
        assert_eq!(s.count, 4, "接受×3（含 re-ack）+ 拒绝×1，每次调用恰计一次");
        assert!(s.sum_us > 0, "4 笔真实提交必有非零耗时");
        assert!(s.p99_us() > 0, "非空直方图 p99 必非零");
        assert_eq!(s.buckets.iter().sum::<u64>(), s.count, "Σ桶 == count");
        // 会话口径：恢复重建后直方图从 0 起（WAL 只记账本事实）。
        agg.wal.flush().unwrap();
        let c = Arc::clone(&clock);
        let (agg2, _) = Aggregator::restore_from_wal(
            test_cfg(),
            Box::new(FormatVerifier),
            &path,
            Box::new(move || c.load(Ordering::Relaxed)),
        )
        .unwrap();
        assert_eq!(agg2.snapshot().submit_latency.count, 0, "恢复后直方图重置");
        let _ = std::fs::remove_file(&path);
    }

    /// S-31：next_nonce = max(已消耗) + 1——被拒 nonce 同样占位（§6.2），跨意图跳号后
    /// 取 max 而非 count；崩溃恢复后由 WAL 重放重建，查询结果与重启前一致。
    #[test]
    fn next_nonce_is_max_consumed_plus_one_and_survives_recovery() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("next-nonce");
        let now = clock.load(Ordering::Relaxed);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        // register_default 内部构造同参委托 → delegation_hash 一致。
        let dh = meridian_core::dsa::delegation_hash(&delegation([1u8; 20], 1_000, 1_000_000));

        {
            let agg = test_aggregator(&clock, &path);
            // 未注册委托 → None（404 E_NOT_FOUND 的内核来源）。
            assert_eq!(agg.next_nonce(&[9u8; 32]), None);
            let (_, _agent_pub) = register_default(&agg, [1u8; 20]);
            // 注册未消费 → 0。
            assert_eq!(agg.next_nonce(&dh), Some(0));
            // nonce 1、2 accepted。
            assert!(
                agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now))
                    .accepted
            );
            assert!(
                agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 20, 2, now))
                    .accepted
            );
            // nonce 100 超单笔上限被拒——nonce 仍消耗（§6.2）→ next = 101（max 不是 count）。
            let rej = agg.submit(&make_env(
                dh, [1u8; 20], &agent_key, [0xCC; 20], 2_000, 100, now,
            ));
            assert!(!rej.accepted);
            assert_eq!(rej.reject_reason, Some(Error::EBudgetPerSpend));
            assert_eq!(agg.next_nonce(&dh), Some(101));
            agg.wal.flush().unwrap();
        } // 模拟崩溃：聚合器丢弃，只剩 WAL

        let c = Arc::clone(&clock);
        let (agg2, truncated) = Aggregator::restore_from_wal(
            test_cfg(),
            Box::new(FormatVerifier),
            &path,
            Box::new(move || c.load(Ordering::Relaxed)),
        )
        .unwrap();
        assert!(!truncated);
        // 恢复边界（诚实）：WAL 只重放已接受意图 → 被拒 nonce 100 的占位消失，
        // 查询值 = max(已接受) + 1 = 3（低于重启前，仍是安全下界）。
        assert_eq!(agg2.next_nonce(&dh), Some(3));
        // 恢复后从查询值继续支付：nonce 3 accepted（不撞已接受集）。
        let r = agg2.submit(&make_env(dh, [1u8; 20], &agent_key, [0xEE; 20], 5, 3, now));
        assert!(r.accepted);
        assert_eq!(agg2.next_nonce(&dh), Some(4));
        let _ = std::fs::remove_file(&path);
    }

    // -----------------------------------------------------------------------
    // S-44：撤销根绑定闸（§6.2 / §4.6 残余③）
    // -----------------------------------------------------------------------

    fn test_cfg_enforce_root() -> IngestConfig {
        let mut cfg = test_cfg();
        cfg.enforce_revocation_root = true;
        cfg
    }

    fn test_aggregator_cfg(cfg: IngestConfig, clock: &Arc<AtomicU64>, path: &Path) -> Aggregator {
        let c = Arc::clone(clock);
        let wal = Wal::open(path, 100_000).unwrap();
        Aggregator::with_clock(
            cfg,
            Box::new(FormatVerifier),
            wal,
            Box::new(move || c.load(Ordering::Relaxed)),
        )
    }

    /// 替换信封证明的 `revocation_root` 公共输入（该字段不参与 `check_public_inputs_consistent`
    /// ——S-44 前它整体无闸，绑定闸是第一个约束它的检查）。
    fn with_revocation_root(env: &IntentEnvelope, root: [u8; 32]) -> IntentEnvelope {
        let mut e = env.clone();
        e.proof.public_inputs.revocation_root = root;
        e
    }

    #[test]
    fn revocation_root_gate_off_accepts_any_root() {
        // 缺省（闸关）：任意根照单全收——占位口径行为逐字节不变（S-44 不动生产默认）。
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("revroot-off");
        let agg = test_aggregator(&clock, &path);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        let env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now);
        let r = agg.submit(&with_revocation_root(&env, [0xAB; 32]));
        assert!(r.accepted, "gate off: self-chosen root accepted (占位口径)");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn revocation_root_gate_rejects_self_chosen_root_without_consuming_nonce() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("revroot-self");
        let agg = test_aggregator_cfg(test_cfg_enforce_root(), &clock, &path);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        // 自选根（伪造 / 空集外的任意值）→ E_REV_ROOT。
        let env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now);
        let r = agg.submit(&with_revocation_root(&env, [0xAB; 32]));
        assert!(!r.accepted);
        assert_eq!(r.reject_reason, Some(Error::ERevRoot));
        assert_eq!(agg.accepted_count(), 0);
        // 闸在 try_commit 之前：nonce 未消耗，同意图换正确根重出证明可接受。
        let r2 = agg.submit(&with_revocation_root(&env, agg.revocation_root()));
        assert!(
            r2.accepted,
            "same intent re-proved with anchored root accepted"
        );
        assert_eq!(r2.seq, 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn revocation_root_gate_accepts_current_and_historical_roots() {
        // 根换代不拒在途证明：旧状态 witness（换代前取的快照）仍在接受集——
        // 语义 =「在该状态时未撤销」，安全性由管线步 2b 当前撤销闸兜底。
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("revroot-hist");
        let agg = test_aggregator_cfg(test_cfg_enforce_root(), &clock, &path);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let (dh_other, _) = register_default(&agg, [2u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);

        let root0 = agg.revocation_root(); // 空集状态（genesis）
        let env1 = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now);
        assert!(agg.submit(&with_revocation_root(&env1, root0)).accepted);

        // 撤销别人 → 根换代；dh 自身的在途证明（root0 witness）仍接受。
        assert!(agg.revoke(dh_other));
        let root1 = agg.revocation_root();
        assert_ne!(root0, root1);
        let env2 = make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 10, 2, now);
        assert!(
            agg.submit(&with_revocation_root(&env2, root0)).accepted,
            "historical state root still accepted"
        );

        // 当刻根当然接受；集合外的自选根拒。
        let env3 = make_env(dh, [1u8; 20], &agent_key, [0xCC; 20], 10, 3, now);
        assert!(agg.submit(&with_revocation_root(&env3, root1)).accepted);
        let env4 = make_env(dh, [1u8; 20], &agent_key, [0xDD; 20], 10, 4, now);
        assert_eq!(
            agg.submit(&with_revocation_root(&env4, [0xCD; 32]))
                .reject_reason,
            Some(Error::ERevRoot)
        );

        // 已撤销委托：步 2b 先拒（撤销闸先于绑定闸，E_REVOKED 语义不被绑定闸遮蔽）。
        let env5 = make_env(dh_other, [2u8; 20], &agent_key, [0xEE; 20], 10, 1, now);
        assert_eq!(
            agg.submit(&with_revocation_root(&env5, root1))
                .reject_reason,
            Some(Error::ERevoked)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn revocation_root_gate_accept_set_persists_across_restart() {
        // S-49（§4.6 残余③）：接受集随 WAL 持久化——`RevokeRoot` 记录重放续接，
        // 重启后跨换代的中间状态 witness 照常接受（不再回退 {空根, 当刻根}）。
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("revroot-restart");
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        let mid_root;
        let pre_restart_root;
        let dh;
        {
            let agg = test_aggregator_cfg(test_cfg_enforce_root(), &clock, &path);
            let (d, _) = register_default(&agg, [1u8; 20]);
            let (other, _) = register_default(&agg, [2u8; 20]);
            dh = d;
            // 两代撤销：R1（中间态）→ R2（重启前终点）。R1 的在途 witness 进程内有效。
            assert!(agg.revoke(other));
            mid_root = agg.revocation_root();
            assert!(agg.revoke([0xEE; 32]));
            pre_restart_root = agg.revocation_root();
            let env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now);
            assert!(agg.submit(&with_revocation_root(&env, mid_root)).accepted);
            agg.wal.flush().unwrap();
        }
        let c = Arc::clone(&clock);
        let (agg2, truncated) = Aggregator::restore_from_wal(
            test_cfg_enforce_root(),
            Box::new(FormatVerifier),
            &path,
            Box::new(move || c.load(Ordering::Relaxed)),
        )
        .unwrap();
        assert!(!truncated);
        assert_eq!(
            agg2.revocation_root(),
            pre_restart_root,
            "重放终点根与重启前一致（S-11c 前提不回归）"
        );

        // 重启后再换代：重启前的两个历史状态根（中间态 + 重启前当刻根）仍在接受集
        // ——持久化续接，不因换代或重启出集。
        assert!(agg2.revoke([0xFF; 32]));
        let env2 = make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 10, 2, now);
        assert!(
            agg2.submit(&with_revocation_root(&env2, mid_root)).accepted,
            "重启前的中间状态根随 WAL 续接"
        );
        let env3 = make_env(dh, [1u8; 20], &agent_key, [0xCC; 20], 10, 3, now);
        assert!(
            agg2.submit(&with_revocation_root(&env3, pre_restart_root))
                .accepted,
            "重启前的当刻根随 WAL 续接"
        );
        // 空根（种子）仍在集内；集合外的自选根仍拒（闸本体不松）。
        let env4 = make_env(dh, [1u8; 20], &agent_key, [0xDD; 20], 10, 4, now);
        assert!(
            agg2.submit(&with_revocation_root(
                &env4,
                RevocationSet::new().sparse_root()
            ))
            .accepted
        );
        let env5 = make_env(dh, [1u8; 20], &agent_key, [0xEE; 20], 10, 5, now);
        assert_eq!(
            agg2.submit(&with_revocation_root(&env5, [0xCD; 32]))
                .reject_reason,
            Some(Error::ERevRoot)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn revocation_root_gate_legacy_wal_without_root_records_falls_back_to_seeds() {
        // 诚实边界（S-49 收窄后残余）：WAL 缺根记录（旧格式 WAL 的历史 / 绑定闸关闭期
        // 发生的撤销）→ 中间状态根不追溯，恢复后回退 {空根, 当刻根} 口径——该状态的
        // 在途 witness 以 E_REV_ROOT 拒（拒绝是安全方向）。
        // 构造：绑定闸关闭时撤销（不落根记录），再以闸开启恢复。
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("revroot-legacy");
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        let mid_root;
        let dh;
        {
            let agg = test_aggregator_cfg(test_cfg(), &clock, &path);
            let (d, _) = register_default(&agg, [1u8; 20]);
            let (other, _) = register_default(&agg, [2u8; 20]);
            dh = d;
            assert!(agg.revoke(other));
            mid_root = agg.revocation_root();
            assert!(agg.revoke([0xEE; 32]));
            agg.wal.flush().unwrap();
        }
        let c = Arc::clone(&clock);
        let (agg2, truncated) = Aggregator::restore_from_wal(
            test_cfg_enforce_root(),
            Box::new(FormatVerifier),
            &path,
            Box::new(move || c.load(Ordering::Relaxed)),
        )
        .unwrap();
        assert!(!truncated);

        // 无根记录：重启后换代，重启前的中间状态根出集 → 拒（安全方向）。
        assert!(agg2.revoke([0xFF; 32]));
        let env2 = make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 10, 2, now);
        assert_eq!(
            agg2.submit(&with_revocation_root(&env2, mid_root))
                .reject_reason,
            Some(Error::ERevRoot)
        );
        // 当刻根与空根（种子）仍在集内。
        let env3 = make_env(dh, [1u8; 20], &agent_key, [0xCC; 20], 10, 3, now);
        assert!(
            agg2.submit(&with_revocation_root(&env3, agg2.revocation_root()))
                .accepted
        );
        let env4 = make_env(dh, [1u8; 20], &agent_key, [0xDD; 20], 10, 4, now);
        assert!(
            agg2.submit(&with_revocation_root(
                &env4,
                RevocationSet::new().sparse_root()
            ))
            .accepted
        );
        let _ = std::fs::remove_file(&path);
    }

    // -----------------------------------------------------------------------
    // S-62：运营者绑定闸（§6.19，Phase 2 P2-2）
    // -----------------------------------------------------------------------

    /// 读面故障注入替身：`fail` 置真 = 读面不可得（Err）。
    struct FlakyBinding {
        inner: crate::binding::StaticBinding,
        fail: std::sync::atomic::AtomicBool,
    }

    impl FlakyBinding {
        fn new() -> Self {
            FlakyBinding {
                inner: crate::binding::StaticBinding::new(),
                fail: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl crate::binding::OperatorBinding for FlakyBinding {
        fn operator_of(&self, dh: &[u8; 32]) -> Result<Option<[u8; 20]>, String> {
            if self.fail.load(Ordering::Relaxed) {
                return Err("rpc down (injected)".into());
            }
            Ok(self.inner.binding_of(dh))
        }
    }

    type DynBinding = Arc<dyn crate::binding::OperatorBinding + Send + Sync>;

    fn gate_aggregator(clock: &Arc<AtomicU64>, path: &Path, source: DynBinding) -> Aggregator {
        // 绑定闸与撤销根绑定闸相互独立：本节用例只关心绑定面，撤销根闸保持缺省。
        test_aggregator_cfg(test_cfg(), clock, path).with_operator_binding(source, [0xAA; 20])
    }

    #[test]
    fn operator_gate_rejects_delegation_bound_to_other_operator() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("opgate-other");
        let src = Arc::new(FlakyBinding::new());
        let agg = gate_aggregator(&clock, &path, Arc::clone(&src) as DynBinding);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        src.inner.bind(dh, [0xBB; 20]); // 他分片运营者

        let env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now);
        let r = agg.submit(&env);
        assert!(!r.accepted);
        assert_eq!(r.reject_reason, Some(Error::EOperator));
        assert_eq!(agg.accepted_count(), 0);

        // 闸在 try_commit 之前：nonce 未消耗 → owner 补绑到本运营者（不可改绑语义下的
        // 首绑，§6.19.1）后同一意图重交即可接受——幂等闸不缓存 reject。
        src.inner.bind(dh, [0xAA; 20]);
        // 缓存已固化旧读数（不可变语义）→ 本进程仍拒：这正是「补绑不回溯本进程」的
        // 缓存影子（§6.19.5）；绑定必须在委托首次被本账本消费前完成。
        assert_eq!(agg.submit(&env).reject_reason, Some(Error::EOperator));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn operator_gate_accepts_unbound_and_self_bound_delegations() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("opgate-pass");
        let src = Arc::new(FlakyBinding::new());
        let agg = gate_aggregator(&clock, &path, Arc::clone(&src) as DynBinding);
        let (dh_unbound, _) = register_default(&agg, [1u8; 20]);
        let (dh_self, _) = register_default(&agg, [2u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        src.inner.bind(dh_self, [0xAA; 20]); // 本运营者自己的委托

        let r1 = agg.submit(&make_env(
            dh_unbound, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now,
        ));
        assert!(r1.accepted, "未绑定委托 fail-open（决策 B 有意取舍）");
        let r2 = agg.submit(&make_env(
            dh_self, [2u8; 20], &agent_key, [0xBB; 20], 10, 1, now,
        ));
        assert!(r2.accepted, "绑定到本运营者的委托放行");
        assert_eq!(agg.accepted_count(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn operator_gate_read_failure_is_fail_closed_without_consuming_nonce() {
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("opgate-fail");
        let src = Arc::new(FlakyBinding::new());
        let agg = gate_aggregator(&clock, &path, Arc::clone(&src) as DynBinding);
        let (dh, _) = register_default(&agg, [1u8; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);

        src.fail.store(true, Ordering::Relaxed);
        let env = make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now);
        assert_eq!(agg.submit(&env).reject_reason, Some(Error::EBindBackend));
        assert_eq!(agg.accepted_count(), 0);

        // 读面恢复（瞬态故障不进缓存，下一笔重试）→ 同意图重交接受；nonce 未被消耗。
        src.fail.store(false, Ordering::Relaxed);
        let r = agg.submit(&env);
        assert!(r.accepted, "读面恢复后同意图重交接受（nonce 未消耗）");
        assert_eq!(r.seq, 0);
        assert_eq!(agg.next_nonce(&dh), Some(2));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn operator_gate_absent_keeps_default_semantics() {
        // 不装配 = 无闸（缺省口径逐字节不变）：即便链上（此处 StaticBinding）已绑他方，
        // 意图照常接受——单运营者 / 占位形态零改动（S-62 不动生产默认）。
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let path = tmp_path("opgate-absent");
        let agg = test_aggregator(&clock, &path);
        let src = Arc::new(FlakyBinding::new());
        let (dh, _) = register_default(&agg, [1u8; 20]);
        src.inner.bind(dh, [0xBB; 20]);
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let now = clock.load(Ordering::Relaxed);
        let r = agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now));
        assert!(r.accepted, "无闸装配：绑定面不参与判定");
        let _ = std::fs::remove_file(&path);
    }
}
