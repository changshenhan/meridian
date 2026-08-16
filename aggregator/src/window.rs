//! 锁自由 epoch 窗口（TECH_SPEC §6.3：窗口收满 10s 或 100_000 笔 → 密封）。
//!
//! 有界 lock-free 多写者 append-only 窗口。写者两步：
//! 1. `reserve(hash)`：`head.fetch_add(1)` 取唯一槽（无锁），写 intent_hash，置 `PENDING`。
//! 2. `finalize(slot, seq, accepted)`：写最终 seq（单写者，安全），置 `ACCEPTED`/`REJECTED`
//!    （Release），`inflight.fetch_sub`。
//!
//! 密封者 `seal()`：置 `closed=true`（SeqCst）→ 等 `inflight==0`（quiescence）→ 读终态
//! `head` → 等前 head 槽 decision（acquire）→ 收集 accepted 条目并**按 seq 排序**。
//!
//! **in-flight 协议（无丢失）**：写者先 `inflight.fetch_add(1, SeqCst)` 再
//! `closed.load(SeqCst)`——读到已关闭则放弃本 epoch（调用方换窗口重试）；读到未关闭则必然
//! 完成 claim + write + `inflight.fetch_sub`。密封者等 `inflight==0` 后 `head` 即终值，不会
//! 漏掉在途写者；拿到 Full/Sealed 的写者也递减 inflight，密封者不等待其条目。
//!
//! seq 不在此窗口内产生（`ingest.rs` 在分片锁内分配）：槽序（预留序）与 seq 序（提交序）在
//! 并发下可不同，故 `seal()` 按 seq 排序输出——承诺根必须可由公开数据（accepted 集）复算，
//! B11 确定性由 seq 排序保证。

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// 槽状态。仅写者写，密封者在 quiescence 后 acquire 读。
const PENDING: u64 = 0;
const ACCEPTED: u64 = 1;
const REJECTED: u64 = 2;

/// 承诺格的一格（§6.3 步骤 A 的 L 条目）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowEntry {
    pub seq: u64,
    pub intent_hash: [u8; 32],
}

/// 预留槽失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendError {
    /// 窗口已密封，拒绝新预留。
    Sealed,
    /// 容量已满，拒绝新预留（调用方换窗口重试）。
    Full,
}

struct Slot {
    entry: UnsafeCell<WindowEntry>,
    /// 0=PENDING, 1=ACCEPTED, 2=REJECTED。数据写入 happen-before 置值（Release）。
    state: AtomicU64,
}

// `state`（release 写 / acquire 读）作为发布同步点：槽内容只被写者在置终态前写、
// 被密封者在读到终态后读，两者由状态原子排序。
unsafe impl Sync for Slot {}

/// 一个 epoch 的接受窗口。
pub struct EpochWindow {
    slots: Box<[Slot]>,
    head: AtomicUsize,
    inflight: AtomicUsize,
    closed: AtomicBool,
}

impl EpochWindow {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "epoch capacity must be positive");
        let slots = (0..capacity)
            .map(|_| Slot {
                entry: UnsafeCell::new(WindowEntry {
                    seq: 0,
                    intent_hash: [0u8; 32],
                }),
                state: AtomicU64::new(PENDING),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        EpochWindow {
            slots,
            head: AtomicUsize::new(0),
            inflight: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        }
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// 已 claim 的槽数（含未 finalize 的在途）。用于满判定与密封者终态读。
    pub fn claimed(&self) -> usize {
        self.head.load(Ordering::Relaxed).min(self.slots.len())
    }

    pub fn is_full(&self) -> bool {
        self.head.load(Ordering::Relaxed) >= self.slots.len()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// 预留一个槽（写入 intent_hash，置 PENDING）。成功后调用方**必须** `finalize`。
    /// seq 由调用方在最终决定时写入（`finalize`）。
    pub fn reserve(&self, intent_hash: [u8; 32]) -> Result<usize, AppendError> {
        self.inflight.fetch_add(1, Ordering::SeqCst);
        // claim 前的密封闸门（协议见模块文档）。
        if self.closed.load(Ordering::SeqCst) {
            self.inflight.fetch_sub(1, Ordering::SeqCst);
            return Err(AppendError::Sealed);
        }
        let idx = self.head.fetch_add(1, Ordering::Relaxed);
        if idx >= self.slots.len() {
            self.inflight.fetch_sub(1, Ordering::SeqCst);
            return Err(AppendError::Full);
        }
        unsafe {
            *self.slots[idx].entry.get() = WindowEntry {
                seq: 0, // 占位；real seq 在 finalize 写入
                intent_hash,
            };
        }
        self.slots[idx].state.store(PENDING, Ordering::Release);
        Ok(idx)
    }

    /// 决定某槽的最终状态。accepted=true 时写入最终 seq 并入承诺；false 作废（seq 留空）。
    /// 单写者：槽数据（含 seq）只在置 ACCEPTED 前被本线程写，密封者在读到 ACCEPTED 后才读。
    pub fn finalize(&self, slot: usize, seq: u64, accepted: bool) {
        if accepted {
            unsafe {
                (*self.slots[slot].entry.get()).seq = seq;
            }
        }
        self.slots[slot].state.store(
            if accepted { ACCEPTED } else { REJECTED },
            Ordering::Release,
        );
        self.inflight.fetch_sub(1, Ordering::Release);
    }

    /// 密封：置 closed → 等 quiescence → 等全部决定 → 返回 accepted 条目（**按 seq 升序**）。
    /// 幂等（重复调用返回相同结果）；调用方应只调用一次。
    pub fn seal(&self) -> Vec<WindowEntry> {
        self.closed.store(true, Ordering::SeqCst);
        while self.inflight.load(Ordering::SeqCst) > 0 {
            std::hint::spin_loop();
        }
        let count = self.head.load(Ordering::SeqCst).min(self.slots.len());
        for i in 0..count {
            while self.slots[i].state.load(Ordering::Acquire) == PENDING {
                std::hint::spin_loop();
            }
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            if self.slots[i].state.load(Ordering::Acquire) == ACCEPTED {
                out.push(unsafe { *self.slots[i].entry.get() });
            }
        }
        out.sort_by_key(|e| e.seq);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_accepted_entry_seals() {
        let w = EpochWindow::new(8);
        let slot = w.reserve([0xAB; 32]).unwrap();
        w.finalize(slot, 1, true);
        let sealed = w.seal();
        assert_eq!(
            sealed,
            vec![WindowEntry {
                seq: 1,
                intent_hash: [0xAB; 32],
            }]
        );
    }

    #[test]
    fn rejected_entry_does_not_enter_commitment() {
        let w = EpochWindow::new(8);
        let good = w.reserve([0x01; 32]).unwrap();
        w.finalize(good, 1, true);
        let bad = w.reserve([0x02; 32]).unwrap();
        w.finalize(bad, 0, false);
        let sealed = w.seal();
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].seq, 1);
    }

    #[test]
    fn reserve_after_seal_is_rejected() {
        let w = EpochWindow::new(4);
        w.seal();
        assert_eq!(w.reserve([0u8; 32]), Err(AppendError::Sealed));
    }

    #[test]
    fn full_window_rejects_and_seals_all_accepted() {
        let w = EpochWindow::new(4);
        let mut accepted = Vec::new();
        for i in 0..6 {
            let r = w.reserve([i as u8; 32]);
            match r {
                Ok(slot) => {
                    w.finalize(slot, i as u64 + 1, true);
                    accepted.push(WindowEntry {
                        seq: i as u64 + 1,
                        intent_hash: [i as u8; 32],
                    });
                }
                Err(AppendError::Full) => break,
                Err(AppendError::Sealed) => panic!("not sealed yet"),
            }
        }
        let sealed = w.seal();
        assert_eq!(sealed, accepted);
    }

    #[test]
    fn concurrent_reserve_finalize_no_loss_and_sorted_by_seq() {
        use std::thread;
        const THREADS: usize = 8;
        const PER_THREAD: usize = 2_000;
        let w = std::sync::Arc::new(EpochWindow::new(THREADS * PER_THREAD + 16));
        let threads: Vec<_> = (0..THREADS)
            .map(|t| {
                let w = std::sync::Arc::clone(&w);
                thread::spawn(move || {
                    for i in 0..PER_THREAD {
                        let seq = (t * PER_THREAD + i) as u64 + 1;
                        let slot = w.reserve([seq as u8; 32]).unwrap();
                        // 一半接受一半拒绝，交错 finalize；seq 故意乱序给 finalize（单写者无碍）。
                        w.finalize(slot, seq, i % 2 == 0);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let sealed = w.seal();
        // 接受的那些必须全部出现、无重复、按 seq 升序。
        let expect: Vec<WindowEntry> = (1..=(THREADS * PER_THREAD) as u64)
            .filter(|s| (s - 1) % 2 == 0)
            .map(|seq| WindowEntry {
                seq,
                intent_hash: [seq as u8; 32],
            })
            .collect();
        assert_eq!(sealed.len(), THREADS * PER_THREAD / 2);
        assert_eq!(sealed, expect);
    }

    #[test]
    fn seal_is_idempotent() {
        let w = EpochWindow::new(8);
        let s = w.reserve([0xAB; 32]).unwrap();
        w.finalize(s, 1, true);
        let a = w.seal();
        let b = w.seal();
        assert_eq!(a, b);
    }
}
