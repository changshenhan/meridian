//! 热路径延迟直方图（S-35，TECH_SPEC §6.11）。
//!
//! 固定桶无锁直方图：32 个 log2 微秒桶（`[AtomicU64; 32]`）+ `count`/`sum_us` 原子计数。
//! 热路径代价 = 1 次原子 `fetch_add` ×3 + 调用方两次 `Instant::now()`，**零分配、零锁**
//! （B8 口径不变，`agg_sim --check-alloc` 门禁复核）。
//!
//! 口径：`Aggregator::submit` 全路径（接受/拒绝/幂等 re-ack 一律计时）——调用方观测到的
//! API 延迟，不是内核分段耗时。p99 是 log2 桶**上界**近似（桶内分布不假设）；要精确分布
//! 用导出的 `_bucket` 累计值自算（Prometheus `histogram_quantile`）。
//!
//! 诚实边界：会话计数**不持久化**（同 `rejected` 口径）——崩溃恢复后从 0 起；WAL 只记
//! 账本事实，延迟分布属瞬态观测。`sum_us` 用 u64 微秒整数累加（亚微秒部分归桶 0 不进和），
//! `_sum` 是下界口径。

use std::sync::atomic::{AtomicU64, Ordering};

/// 桶数：log2 μs ×32，覆盖 `[0, 2^31) μs`（≈35.8 分钟；超出钳入最高桶）。
pub const BUCKETS: usize = 32;

/// μs → 桶下标。桶 `i` 覆盖 `[2^i, 2^(i+1))` μs；桶 0 含 0（亚微秒）。
/// `floor(log2(us))` 下取整，≥ `2^31` μs 一律钳入桶 31（上界 ≈ 2147 s，已属告警态）。
#[inline]
pub fn bucket_of(us: u64) -> usize {
    if us == 0 {
        return 0;
    }
    (63 - us.leading_zeros() as usize).min(BUCKETS - 1)
}

/// 直方图只读快照（`snapshot()` 逐桶 `load` 拷出；纯只读，不碰任何锁）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LatencySnapshot {
    /// 每桶命中数（非累计；导出侧再累计成 Prometheus `le` 语义）。
    pub buckets: [u64; BUCKETS],
    /// 计量总次数（== submit 调用数）。
    pub count: u64,
    /// μs 整数累加和（下界口径，见模块文档）。
    pub sum_us: u64,
}

impl LatencySnapshot {
    /// p99 近似：最小累计占比 ≥ 99% 的桶的**上界** `2^(i+1)` μs。
    /// 空直方图 → 0。全部落在最高桶 → 上界 `2^32` μs。
    pub fn p99_us(&self) -> u64 {
        if self.count == 0 {
            return 0;
        }
        // ceil(count * 99 / 100)：p99 至少覆盖到第 ceil(0.99·N) 个观测。
        let threshold = (self.count * 99).div_ceil(100);
        let mut cum = 0u64;
        for (i, &b) in self.buckets.iter().enumerate() {
            cum += b;
            if cum >= threshold {
                return 1u64 << (i + 1);
            }
        }
        1u64 << BUCKETS
    }
}

/// 无锁延迟直方图（聚合器内核持有；`Send + Sync` 由原子保证）。
pub struct LatencyHistogram {
    buckets: [AtomicU64; BUCKETS],
    count: AtomicU64,
    sum_us: AtomicU64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyHistogram {
    pub const fn new() -> Self {
        LatencyHistogram {
            buckets: [const { AtomicU64::new(0) }; BUCKETS],
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
        }
    }

    /// 记一次延迟（μs；亚微秒 → 桶 0）。Relaxed：计数观测，无需跨线程定序。
    #[inline]
    pub fn record_us(&self, us: u64) {
        self.buckets[bucket_of(us)].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(us, Ordering::Relaxed);
    }

    /// 只读快照（无锁视图；S-15 信条：抓快照不引入热路径争用）。
    pub fn snapshot(&self) -> LatencySnapshot {
        LatencySnapshot {
            buckets: std::array::from_fn(|i| self.buckets[i].load(Ordering::Relaxed)),
            count: self.count.load(Ordering::Relaxed),
            sum_us: self.sum_us.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn bucket_boundaries_are_floor_log2() {
        assert_eq!(bucket_of(0), 0, "亚微秒/零 → 桶 0");
        assert_eq!(bucket_of(1), 0, "[1, 2) μs → 桶 0");
        assert_eq!(bucket_of(2), 1);
        assert_eq!(bucket_of(3), 1);
        assert_eq!(bucket_of(4), 2);
        assert_eq!(bucket_of(1 << 10), 10);
        assert_eq!(bucket_of((1 << 11) - 1), 10, "桶内不越界");
        assert_eq!(bucket_of(1 << 31), 31, "最高有效桶");
        assert_eq!(bucket_of(u64::MAX), 31, "超范围钳入最高桶");
    }

    #[test]
    fn record_and_snapshot_counts() {
        let h = LatencyHistogram::new();
        assert_eq!(h.snapshot(), LatencySnapshot::default(), "空直方图全零");
        h.record_us(0);
        h.record_us(1);
        h.record_us(5);
        h.record_us(100);
        let s = h.snapshot();
        assert_eq!(s.count, 4);
        assert_eq!(s.sum_us, 106);
        assert_eq!(s.buckets[0], 2); // 0、1
        assert_eq!(s.buckets[2], 1); // 5 ∈ [4, 8)
        assert_eq!(s.buckets[6], 1); // 100 ∈ [64, 128)
                                     // Σ桶 == count（守恒，导出侧累计语义依赖它）。
        assert_eq!(s.buckets.iter().sum::<u64>(), s.count);
    }

    #[test]
    fn p99_is_bucket_upper_bound_approximation() {
        let mut s = LatencySnapshot::default();
        assert_eq!(s.p99_us(), 0, "空 → 0");
        // 100 笔全落 [8, 16) μs → p99 = 桶上界 16。
        s.buckets[3] = 100;
        s.count = 100;
        s.sum_us = 1_200;
        assert_eq!(s.p99_us(), 16);
        // 99 笔桶 3 + 1 笔桶 4：累计到桶 3 = 99 < ceil(99) 达标 → 仍是 16。
        s.buckets[4] = 1;
        s.count = 100;
        assert_eq!(s.p99_us(), 16);
        // 98 + 2：桶 3 累计 98 < 99 → 落桶 4 → 上界 32。
        s.buckets[3] = 98;
        assert_eq!(s.p99_us(), 32);
        // 全落最高桶 → 上界 2^32。
        let mut top = LatencySnapshot::default();
        top.buckets[BUCKETS - 1] = 7;
        top.count = 7;
        assert_eq!(top.p99_us(), 1u64 << 32);
    }

    #[test]
    fn concurrent_records_all_counted() {
        let h = Arc::new(LatencyHistogram::new());
        const THREADS: usize = 8;
        const PER: u64 = 1_000;
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let h = Arc::clone(&h);
                thread::spawn(move || {
                    for i in 0..PER {
                        h.record_us(t as u64 * 1_000 + i % 7);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("record thread");
        }
        let s = h.snapshot();
        assert_eq!(s.count, THREADS as u64 * PER);
        assert_eq!(s.buckets.iter().sum::<u64>(), s.count, "Σ桶 == count");
        // t=0 的 1000 笔散在桶 0..2；t=1..7 各占桶 9..12。累计到桶 11 = 7000 < 7920
        // （ceil(0.99·8000)）→ p99 落桶 12（t=7 的 7000..7006 μs）→ 上界 2^13。
        assert_eq!(s.p99_us(), 8_192);
    }
}
