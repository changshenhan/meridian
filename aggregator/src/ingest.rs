//! Ingest 管线（TECH_SPEC §6.2，MASTER_PLAN S-10）。
//!
//! `Aggregator::submit(env) -> Receipt` 快路径，顺序（与 §6.2 一致）：
//! 意图有效期 → 委托查表（未注册拒 `E_DELEG_UNKNOWN`）→ agent 绑定 → Ed25519 验签（证明前
//! 的廉价 DoS 闸门）→ 验证明（`SpendVerifier`，登记以返回值为准）→ 公共输入与信封一致性 →
//! 预留窗口槽 → nonce 去重 + 预算检查记账（分片锁内**分配 seq**）→ 定稿（accepted 才入承诺）
//! → WAL 追加 → 满窗即封。已封 epoch 由 `process_pending` 结算（`lattice::build_epoch`：
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
//! B8 容量预置：`register` 时 provision 分片条目（预算零态 + 预置 nonce 集）；稳态
//! `try_commit` 的 `entry` 查找与 `nonces.insert` 都在容量内 → 零分配。
//! WAL 失败 panic（持久化骨干，不可降级）。

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use meridian_core::dsa::{
    delegation_hash, intent_hash, verify_intent, AgentPubKey, Delegation, SignedDelegation,
};
use meridian_core::error::Error;
use meridian_core::ledger::{check_budget, BudgetState};
use meridian_core::zk::SpendVerifier;

use crate::lattice::{ChainPublisher, EpochResult, NoopPublisher};
use crate::proof::check_public_inputs_consistent;
use crate::receipt::{IntentEnvelope, Receipt};
use crate::revocation::RevocationSet;
use crate::wal::{DecodedRecord, Wal};
use crate::window::{EpochWindow, WindowEntry};

/// 意图索引条目：intent_hash → (recipient, amount)。净额解析源（§6.3 步骤 D）。
type IntentRef = ([u8; 20], u64);
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
}

impl Default for IngestConfig {
    fn default() -> Self {
        IngestConfig {
            ledger_shards: 64,
            epoch_capacity: 100_000,
            epoch_secs: 10,
            wal_sync_every: 1_000,
            nonce_capacity_per_delegation: 4_096,
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

/// 每委托的账本状态：预算 + 已用 nonce 集。
struct DelegationLedgerState {
    budget: BudgetState,
    nonces: HashSet<u64>,
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
            nonces: HashSet::with_capacity(nonce_capacity),
        });
    }

    /// 原子：nonce 去重 → 预算检查记账 → 分片锁内分配 seq。`Ok(seq)` = accepted。
    /// Err 时 nonce 已消耗（§6.2：拒绝意图的 nonce 不允许复用）。
    /// 防御路径：未 provision 的委托不该走到这里（管线在注册表查表时已拒）。
    pub fn try_commit(
        &self,
        dh: &[u8; 32],
        delegation: &Delegation,
        spend_nonce: u64,
        amount: u64,
        now: u64,
        seq_assigner: &AtomicU64,
    ) -> Result<u64, Error> {
        let idx = shard_of(dh, self.shards.len());
        let mut map = self.shards[idx].lock().expect("shard poisoned");
        let st = map.entry(*dh).or_insert_with(|| DelegationLedgerState {
            budget: BudgetState::new(*dh, 0),
            nonces: HashSet::new(),
        });
        if !st.nonces.insert(spend_nonce) {
            return Err(Error::ENonce);
        }
        check_budget(delegation, &mut st.budget, amount, now)?;
        // seq 在锁内分配：同委托的提交序 == seq 序（重放精确性，见模块文档）。
        let seq = seq_assigner.fetch_add(1, Ordering::Relaxed);
        Ok(seq)
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
        let now = now_fn();
        let epoch_capacity = cfg.epoch_capacity;
        let state = match delegations_expected {
            Some(n) => ShardedState::with_capacity(cfg.ledger_shards, n),
            None => ShardedState::new(cfg.ledger_shards),
        };
        Aggregator {
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
            now_fn,
        }
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
                .try_commit(&dh, &reg.delegation, spend_nonce, amount, now, &agg.seq)
                .map_err(std::io::Error::other)?;
            debug_assert_eq!(got, seq, "replay seq must match WAL seq");
            // 意图索引只收未密封意图：已提交的（seq < 边界）由 EpochSeal/Netting 覆盖，
            // 恢复后不再引用，不入索引避免驻留泄漏。
            if seq >= sealed_accepted_count {
                agg.intents
                    .lock()
                    .expect("intents poisoned")
                    .insert(ih, (recipient, amount));
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

    /// 撤销委托（链上 revoke 事件 → 运营者调用）：WAL 追加后入撤销集（持久化骨干，WAL 失败
    /// panic）。返回是否新撤销（重复撤销幂等）。从本调用起，该委托的新意图 `submit` 一律
    /// `E_REVOKED` 拒；撤销根随下个密封 epoch 上链（S-11 验收：1 epoch 内进入撤销根）。
    pub fn revoke(&self, delegation_hash: [u8; 32]) -> bool {
        self.wal
            .append_revoke(delegation_hash)
            .expect("WAL failure (durability backbone)");
        self.revocations.insert(delegation_hash)
    }

    /// 撤销集当前根（下个 epoch 承诺时锚定；测试 / 观测）。
    pub fn revocation_root(&self) -> [u8; 32] {
        self.revocations.sparse_root()
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
    pub fn submit(&self, env: &IntentEnvelope) -> Receipt {
        let now = (self.now_fn)();
        let intent = &env.intent;
        let ih = intent_hash(intent);

        // 1. 意图有效期（早退：过期意图不占窗口 / 账本）。
        if now > intent.expires_at {
            return Receipt::rejected(ih, Error::EIntentExpired);
        }
        // 2. 委托查表（未注册拒）。
        let reg = match self.registry.lookup(&intent.delegation_hash) {
            Some(r) => r,
            None => return Receipt::rejected(ih, Error::EDelegUnknown),
        };
        // 2b. 撤销闸口（S-11）：注册表查找后立即查，最廉价——不耗 nonce / 窗口槽，撤销前已
        //     接受的意图仍留在承诺中支付（非追溯，TECH_SPEC §6.5）。
        if self.revocations.is_revoked(&intent.delegation_hash) {
            return Receipt::rejected(ih, Error::ERevoked);
        }
        // 3. agent 绑定：意图声明的 agent 必须与委托绑定的一致。
        if intent.agent != reg.delegation.agent {
            return Receipt::rejected(ih, Error::EOrdering);
        }
        // 4. Ed25519 快路径验签（证明前的廉价 DoS 闸门）。
        if let Err(e) = verify_intent(intent, &env.agent_sig, &reg.agent_pub) {
            return Receipt::rejected(ih, e);
        }
        // 5. 验证明（登记以验证器返回值为准）。
        let pi = match self.verifier.verify(&env.proof) {
            Ok(pi) => pi,
            Err(e) => return Receipt::rejected(ih, e),
        };
        // 6. 公共输入与信封一致（证明与信封不是同一笔意图 → 拒）。
        if let Err(e) = check_public_inputs_consistent(&pi, intent) {
            return Receipt::rejected(ih, e);
        }
        // 7. 预留窗口槽（记账前入窗口 → 无回滚；满 / 密封自动换窗重试）。
        let slot = self.windows.reserve(ih, now);
        // 8. nonce 去重 + 预算检查记账（分片锁内分配 seq）。预算的时间 = 证明的 now（§9）。
        let seq = match self.state.try_commit(
            &pi.delegation_hash,
            &reg.delegation,
            pi.spend_nonce,
            pi.amount,
            pi.now,
            &self.seq,
        ) {
            Ok(seq) => seq,
            Err(e) => {
                self.windows.finalize(&slot, 0, false);
                return Receipt::rejected(ih, e);
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
            .insert(ih, (pi.recipient, pi.amount));
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
                .copied()
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

    /// 已接受总数（== 下一个待分配的 seq；测试 / 观测）。
    pub fn accepted_count(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meridian_core::dsa::{
        owner_signing_key_from_bytes, sign_delegation, sign_intent, AgentSigningKey, RateLimit,
        SpendIntent,
    };
    use meridian_core::zk::SpendProof;

    use crate::proof::FormatVerifier;
    use proptest::prelude::*;

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
}
