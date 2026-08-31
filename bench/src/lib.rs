//! 基准基座（TECH_SPEC §8 / MASTER_PLAN S-04）。
//!
//! 提供：计数分配器 + `NoAllocGuard`（热路径零分配断言，B8）。
//! 设计：线程本地计数；守卫包裹的代码段内若发生堆分配，`section_allocs()` 可观测。
//! 由全局分配器计数，测试只读线程本地计数，不做估计。
//!
//! `ingest`：PoC ② 聚合器 ingest 原型（验签 → nonce 去重 → 预算记账的吞吐管线）。

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

pub mod agg_fixture;
pub mod ingest;
pub mod rss;

thread_local! {
    static GUARD_DEPTH: Cell<usize> = const { Cell::new(0) };
    static SECTION_ALLOCS: Cell<usize> = const { Cell::new(0) };
    /// 守卫段内累计分配字节数（B7 内存上界：累计 ≥ 峰值，作保守上界断言 <1GB）。
    static SECTION_BYTES: Cell<usize> = const { Cell::new(0) };
}

/// 计数分配器：统计当前线程在守卫段内的堆分配次数。
pub struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if GUARD_DEPTH.with(|d| d.get()) > 0 {
            SECTION_ALLOCS.with(|c| c.set(c.get() + 1));
            SECTION_BYTES.with(|b| b.set(b.get() + layout.size()));
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if GUARD_DEPTH.with(|d| d.get()) > 0 {
            SECTION_ALLOCS.with(|c| c.set(c.get() + 1));
            SECTION_BYTES.with(|b| b.set(b.get() + layout.size()));
        }
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if GUARD_DEPTH.with(|d| d.get()) > 0 {
            SECTION_ALLOCS.with(|c| c.set(c.get() + 1));
            SECTION_BYTES.with(|b| b.set(b.get() + new_size));
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// 包裹一段代码，观测其堆分配次数。drop 后守卫解除。
pub struct NoAllocGuard;

impl NoAllocGuard {
    pub fn new() -> Self {
        GUARD_DEPTH.with(|d| d.set(d.get() + 1));
        SECTION_ALLOCS.with(|c| c.set(0));
        SECTION_BYTES.with(|b| b.set(0));
        NoAllocGuard
    }
}

impl Default for NoAllocGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NoAllocGuard {
    fn drop(&mut self) {
        GUARD_DEPTH.with(|d| d.set(d.get() - 1));
    }
}

/// 当前守卫段内发生的堆分配次数。
pub fn section_allocs() -> usize {
    SECTION_ALLOCS.with(|c| c.get())
}

/// 当前守卫段内累计分配字节数（≥ 峰值驻留；B7 用保守上界）。
pub fn section_alloc_bytes() -> usize {
    SECTION_BYTES.with(|b| b.get())
}

// ---------------------------------------------------------------------------
// B7 排序 + 承诺（100k 笔，TECH_SPEC §8.1 B7）—— agg_sim 与 lattice_b7 共用内核。
// ---------------------------------------------------------------------------

/// B7 输入规模。
pub const B7_N: usize = 100_000;

/// 固定 seed 的 xorshift64*：确定性伪随机（B11 口径，无 rand 依赖）。
struct Xs(u64);

impl Xs {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// B7 测量：commitment_root → reorder → aggregate → netting_root 全管线
/// （§6.3 步骤 A-E 纯计算侧）。5 轮取最短墙钟；每轮累计分配字节（≥ 峰值，作 <1GiB
/// 保守上界断言）。确定性夹具，零随机。返回 (best_wall_secs, max_cum_alloc_bytes)。
pub fn b7_measure() -> (f64, usize) {
    use meridian_aggregator::lattice;
    use meridian_aggregator::window::WindowEntry;
    use std::hint::black_box;
    use std::time::Instant;

    // 确定性构建 100k 个已封窗口条目（seq 升序、intent_hash 伪随机）。
    let mut rng = Xs(0x4D_45_52_49_44_49_41_4E); // "MERIDIAN"
    let entries: Vec<WindowEntry> = (0..B7_N as u64)
        .map(|seq| {
            let mut ih = [0u8; 32];
            for b in ih.iter_mut() {
                *b = rng.next() as u8;
            }
            WindowEntry {
                seq,
                intent_hash: ih,
                // 确定性接受时刻（P2-3 §6.23：acceptanceRoot 纳入 B7 管线测量）。
                accepted_at: 1_700_000_000 + seq,
            }
        })
        .collect();

    // 一次全管线。resolver 确定性映射 intent_hash → (recipient, amount)。
    let run = |entries: &[WindowEntry]| -> lattice::EpochResult {
        let mut resolve = |ih: &[u8; 32]| -> Option<([u8; 20], u64)> {
            let mut r = [0u8; 20];
            r.copy_from_slice(&ih[..20]);
            let amount = u64::from_le_bytes(ih[20..28].try_into().unwrap()) % 1000;
            Some((r, amount))
        };
        // 撤销根参数（S-11）：空撤销集根（bench 不测撤销稀疏根，取空集常量即可）。
        let empty_rev_root = meridian_aggregator::revocation::RevocationSet::new().sparse_root();
        lattice::build_epoch(0, 1_700_000_000, entries, &mut resolve, empty_rev_root)
            .expect("resolver total")
    };

    // 预热一轮（分配器 / 指令缓存热度），不记录。
    black_box(run(&entries));

    let mut best = f64::INFINITY;
    let mut alloc_bytes = 0usize;
    for _ in 0..5 {
        let g = NoAllocGuard::new();
        let t = Instant::now();
        let res = run(&entries);
        let secs = t.elapsed().as_secs_f64();
        drop(g);
        best = best.min(secs);
        alloc_bytes = alloc_bytes.max(section_alloc_bytes());
        black_box(res);
    }
    (best, alloc_bytes)
}
