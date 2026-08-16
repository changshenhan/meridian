//! Ingest 管线（TECH_SPEC §6.2，MASTER_PLAN S-10）。
//!
//! `Aggregator::submit(env) -> Receipt` 快路径，顺序（与 §6.2 一致）：
//! 意图有效期 → 委托查表（未注册拒 `E_DELEG_UNKNOWN`）→ agent 绑定 → Ed25519 验签（证明前
//! 的廉价 DoS 闸门）→ 验证明（`SpendVerifier`，登记以返回值为准）→ 公共输入与信封一致性 →
//! 预留窗口槽 → nonce 去重 + 预算检查记账（分片锁内**分配 seq**）→ 定稿（accepted 才入承诺）
//! → WAL 追加 → 满窗即封。
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

use crate::proof::check_public_inputs_consistent;
use crate::receipt::{IntentEnvelope, Receipt};
use crate::wal::{DecodedRecord, Wal};
use crate::window::{EpochWindow, WindowEntry};

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
        Self::build(cfg, verifier, wal, default_now(), None)
    }

    /// 可控时钟构造（测试）。
    pub fn with_clock(
        cfg: IngestConfig,
        verifier: Box<dyn SpendVerifier + Send + Sync>,
        wal: Wal,
        now_fn: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self::build(cfg, verifier, wal, now_fn, None)
    }

    /// B8 容量预置构造：分片桶位按预期委托数预分配（`register` 再逐委托 provision）。
    pub fn with_capacity(
        cfg: IngestConfig,
        verifier: Box<dyn SpendVerifier + Send + Sync>,
        wal: Wal,
        delegations_expected: usize,
    ) -> Self {
        Self::build(cfg, verifier, wal, default_now(), Some(delegations_expected))
    }

    fn build(
        cfg: IngestConfig,
        verifier: Box<dyn SpendVerifier + Send + Sync>,
        wal: Wal,
        now_fn: Box<dyn Fn() -> u64 + Send + Sync>,
        delegations_expected: Option<usize>,
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
        let agg = Self::build(cfg.clone(), verifier, wal, now_fn, None);

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
        // 2. 意图按 seq 排序重放。
        let mut intents: Vec<(u64, [u8; 32], u64, u64, u64)> = Vec::new();
        for rec in &records {
            if let DecodedRecord::Intent {
                seq,
                delegation_hash,
                spend_nonce,
                amount,
                now,
                ..
            } = rec
            {
                intents.push((*seq, *delegation_hash, *spend_nonce, *amount, *now));
            }
        }
        intents.sort_by_key(|t| t.0);
        for (seq, dh, spend_nonce, amount, now) in intents {
            let reg = agg.registry.lookup(&dh).ok_or_else(|| {
                std::io::Error::other("WAL replay: intent for unregistered delegation")
            })?;
            let got = agg
                .state
                .try_commit(&dh, &reg.delegation, spend_nonce, amount, now, &agg.seq)
                .map_err(std::io::Error::other)?;
            debug_assert_eq!(got, seq, "replay seq must match WAL seq");
        }
        Ok((agg, truncated))
    }

    /// 登记委托（DSA 登记事件 → 注册表 + WAL + 账本 provision）。
    /// `agent_pub` 是 agent 的 Ed25519 公钥（验签快路径密钥；链上事件不含，需运营者提供）。
    pub fn register(&self, sd: SignedDelegation, agent_pub: AgentPubKey) {
        let dh = delegation_hash(&sd.delegation);
        self.wal
            .append_register(&sd, &agent_pub.to_bytes())
            .expect("WAL failure (durability backbone)");
        self.registry
            .register(dh, RegisteredDelegation { delegation: sd.delegation, agent_pub });
        self.state.provision(&dh, self.cfg.nonce_capacity_per_delegation);
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
        ) {
            panic!("WAL failure (durability backbone): {e}");
        }
        // 10. 满窗即封。
        self.windows.maybe_rotate(now);
        Receipt::accepted(ih, seq)
    }

    /// 批量摄取（rayon 有界线程池，MASTER_PLAN 技术源）。返回与输入等长的回执数组。
    pub fn submit_batch(
        &self,
        pool: &rayon::ThreadPool,
        envs: &[IntentEnvelope],
    ) -> Vec<Receipt> {
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

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("meridian-ingest-test-{}-{}", name, std::process::id()));
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
        assert_eq!(r1.intent_hash, meridian_core::dsa::intent_hash(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 10, 1, now).intent));
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
        assert!(agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 60, 1, now)).accepted);
        assert!(agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xBB; 20], 40, 2, now)).accepted);
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
            let r = agg.submit(&make_env(dh, [1u8; 20], &agent_key, [i as u8; 20], 1, i + 1, now));
            assert!(r.accepted, "intent {i} should accept");
        }
        let sealed = agg.take_sealed();
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].epoch_id, 0);
        assert_eq!(sealed[0].entries.len(), 4);
        // 条目按 seq 升序。
        assert_eq!(sealed[0].entries.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![0, 1, 2, 3]);
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
        assert!(agg.submit(&make_env(dh, [1u8; 20], &agent_key, [0xAA; 20], 1, 1, now)).accepted);
        assert!(agg.pending_sealed() == 0);
        // 时间到点（epoch_secs=60）。
        clock.store(now + 61, Ordering::Relaxed);
        let sealed = agg.seal_expired(now + 61, 60);
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].entries.len(), 1);
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
                let r = agg.submit(&make_env(dh, [1u8; 20], &agent_key, [i as u8; 20], 5, i + 1, now));
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
}
