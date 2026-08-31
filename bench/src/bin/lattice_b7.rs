//! B7 基准：100k 笔排序 + 承诺（commitment lattice，TECH_SPEC §8.1 B7）。
//!
//! 验收（MASTER_PLAN S-10 / §8.1）：**100k 排序+承诺 < 1s、< 1GB**。
//! 本 bin 直接调 `mist-aggregator::lattice` 全管线（`commitment_root` → `reorder` →
//! `aggregate` → `netting_root`，即 §6.3 步骤 A-E 的纯计算侧），测墙钟（5 轮取最短）与累计
//! 分配字节。累计分配 ≥ 峰值驻留，作 **<1GB 的保守上界**断言。
//!
//! 确定性夹具：固定 seed 的 xorshift64*，不依赖 rand（B11 风格）。S-10d 的 `agg_sim` 会把
//! B7 并入门禁 baseline（`gate.rs --record`）；这里给出 S-10b 的参考机实测记录。
//!
//! 用法：`cargo run --release -p mist-bench --bin lattice_b7`

use std::hint::black_box;
use std::time::Instant;

use mist_aggregator::lattice::{self, EpochResult};
use mist_aggregator::window::WindowEntry;
use mist_bench::{section_alloc_bytes, NoAllocGuard};

const N: usize = 100_000;
/// B7 墙钟上界。
const MAX_WALL_SECS: f64 = 1.0;
/// B7 内存上界（1 GiB）。
const MAX_ALLOC_BYTES: usize = 1 << 30;

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

/// 确定性构建 100k 个已封窗口条目（seq 升序、intent_hash 伪随机）。
fn build_entries() -> Vec<WindowEntry> {
    let mut rng = Xs(0x4D_45_52_49_44_49_41_4E); // "MERIDIAN"
    (0..N as u64)
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
        .collect()
}

/// 一次全管线（§6.3 步骤 A-E 纯计算侧）。resolver 确定性映射 intent_hash → (recipient, amount)，
/// 模拟意图索引（recipient = ih[0..20]，amount = ih[20..28] 取模）。
fn run_pipeline(entries: &[WindowEntry]) -> EpochResult {
    let mut resolve = |ih: &[u8; 32]| -> Option<([u8; 20], u64)> {
        let mut r = [0u8; 20];
        r.copy_from_slice(&ih[..20]);
        let amount = u64::from_le_bytes(ih[20..28].try_into().unwrap()) % 1000;
        Some((r, amount))
    };
    // 撤销根参数（S-11）：空撤销集根（bench 不测撤销稀疏根）。
    let empty_rev_root = mist_aggregator::revocation::RevocationSet::new().sparse_root();
    lattice::build_epoch(0, 1_700_000_000, entries, &mut resolve, empty_rev_root)
        .expect("resolver total")
}

fn main() {
    let entries = build_entries();

    // 预热一轮（分配器 / 指令缓存热度），不记录。
    black_box(run_pipeline(&entries));

    // 记录：5 轮取最短墙钟 + 每轮累计分配字节（max）。
    let mut best = f64::INFINITY;
    let mut alloc_bytes = 0usize;
    for _ in 0..5 {
        let g = NoAllocGuard::new();
        let t = Instant::now();
        let res = run_pipeline(&entries);
        let secs = t.elapsed().as_secs_f64();
        drop(g);
        best = best.min(secs);
        alloc_bytes = alloc_bytes.max(section_alloc_bytes());
        black_box(res);
    }

    let bytes_mib = alloc_bytes as f64 / 1_048_576.0;
    println!("lattice_b7: n = {N}");
    println!("  wall best   = {:.3} ms", best * 1e3);
    println!(
        "  cum alloc   = {:.3} MiB  (累计 ≥ 峰值，作 <1 GiB 保守上界)",
        bytes_mib
    );
    println!("  bounds      = wall < {MAX_WALL_SECS}s, alloc < 1 GiB");

    assert!(
        best < MAX_WALL_SECS,
        "B7 FAIL: wall {:.3} ms ≥ 1s",
        best * 1e3
    );
    assert!(
        alloc_bytes < MAX_ALLOC_BYTES,
        "B7 FAIL: alloc {alloc_bytes} B ≥ 1 GiB"
    );
    println!("B7 PASS");
}
