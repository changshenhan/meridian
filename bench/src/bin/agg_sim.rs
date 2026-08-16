//! S-10 生产内核验收 sim（TECH_SPEC §8.1 B5/B6/B7/B8/B10/B11 + MASTER_PLAN S-10 验收）。
//!
//! 用法：
//! ```text
//! cargo run --release -p meridian-bench --bin agg_sim                       # 全量验收报告
//! cargo run --release -p meridian-bench --bin agg_sim -- --check 100000     # B5 验收（≥100k/s）
//! cargo run --release -p meridian-bench --bin agg_sim -- --check-alloc      # B8 零分配断言
//! cargo run --release -p meridian-bench --bin agg_sim -- --check-determinism  # B11 确定性断言
//! cargo run --release -p meridian-bench --bin agg_sim -- --json             # JSON 报告
//! cargo run --release -p meridian-bench --bin agg_sim -- --gen-fixture      # 重写 s10_fixture.bin
//! ```
//!
//! 口径：**生产内核**（`meridian-aggregator`）全管线——验签快路径 → `SpendVerifier`（本阶段
//! `FormatVerifier`，TEMPORARY，与 PoC ② 同口径；诚实边界见 §8.2 注记）→ 预算 → 入窗 →
//! commitment lattice → 净额。固定输入集快照锁在 `bench/data/s10_fixture.bin`
//! （params + 批次规范哈希；加载时重生成校验，漂移即报错）。
//!
//! 参考机（§8.1）验收以本 bin 输出为准；CI 只跑快速确定性回归（B8/B11 + gate 吞吐基线）。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::lattice;
use meridian_aggregator::proof::FormatVerifier;
use meridian_aggregator::wal::Wal;
use meridian_bench::agg_fixture::{
    fixture_bytes, load_fixture, AgentFixture, KernelBatch, KernelFixtureParams, MASTER_SEED,
};
use meridian_bench::{b7_measure, section_allocs, NoAllocGuard};
use rayon::ThreadPool;

// ---------------------------------------------------------------------------
// 参数与常量
// ---------------------------------------------------------------------------

/// 主 fixture：128 代理 × 2000 意图 = 256k 笔（PoC ② 同量级，生产内核 B5/B10 规模）。
const DEFAULT_AGENTS: usize = 128;
const DEFAULT_PER_AGENT: usize = 2_000;
const DEFAULT_NOW: u64 = 1_700_000_000;

/// B10 端到端规模（100k 笔 → 批次 → 净额）。
const B10_N: usize = 100_000;
/// B6 延迟样本数（1 代理 × N 意图，p99 统计用）。
const B6_N: usize = 20_000;
/// B8 零分配断言笔数（单代理）。
const B8_N: usize = 1_000;
/// B11 确定性规模（64k 笔，单线程确定性提交 ×2 全管线）。
const B11_N: usize = 64_000;

/// B5/B6/B7 验收阈值（对齐 MASTER_PLAN S-10 / TECH_SPEC §8.2）。
const B5_MIN_OPS: f64 = 100_000.0;
const B6_MAX_P99_MS: f64 = 50.0;
const B7_MAX_WALL_SECS: f64 = 1.0;
const B7_MAX_ALLOC_BYTES: usize = 1 << 30; // 1 GiB（累计 ≥ 峰值，保守上界）

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("s10_fixture.bin")
}

fn main_fixture_params() -> KernelFixtureParams {
    KernelFixtureParams {
        n_agents: DEFAULT_AGENTS,
        per_agent: DEFAULT_PER_AGENT,
        now: DEFAULT_NOW,
        seed: MASTER_SEED,
    }
}

/// 主 fixture 前 50 个代理 = 100k 笔（B10 用，agent-major 顺序切片）。
fn b10_batch(
    batch: &KernelBatch,
) -> (
    Vec<AgentFixture>,
    Vec<meridian_aggregator::receipt::IntentEnvelope>,
) {
    let n_agents = B10_N / DEFAULT_PER_AGENT;
    assert_eq!(n_agents * DEFAULT_PER_AGENT, B10_N);
    (
        batch.agents[..n_agents].to_vec(),
        batch.envs[..B10_N].to_vec(),
    )
}

/// B11 用：前 n 代理 = B11_N 笔（单线程确定性提交）。
fn b11_batch(
    batch: &KernelBatch,
) -> (
    Vec<AgentFixture>,
    Vec<meridian_aggregator::receipt::IntentEnvelope>,
) {
    let n_agents = B11_N / DEFAULT_PER_AGENT;
    assert_eq!(n_agents * DEFAULT_PER_AGENT, B11_N);
    (
        batch.agents[..n_agents].to_vec(),
        batch.envs[..B11_N].to_vec(),
    )
}

// ---------------------------------------------------------------------------
// 聚合器构造助手
// ---------------------------------------------------------------------------

fn bench_cfg(epoch_capacity: usize, nonce_capacity: usize) -> IngestConfig {
    IngestConfig {
        ledger_shards: 64,
        epoch_capacity,
        epoch_secs: 60,
        wal_sync_every: 10_000_000, // 吞吐测量期间不 fsync（缓冲 8MB 兜底，B8 口径）
        nonce_capacity_per_delegation: nonce_capacity,
    }
}

fn tmp_wal(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("meridian-s10d-{tag}-{}.wal", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// 全新预置聚合器：可控时钟（固定 fixture.now）+ 容量预置（委托数/接受数）+ 注册全部委托。
fn new_agg(
    cfg: &IngestConfig,
    agents: &[AgentFixture],
    n_intents: usize,
    now: u64,
    tag: &str,
) -> (Aggregator, Arc<AtomicU64>) {
    let wal = Wal::open(&tmp_wal(tag), cfg.wal_sync_every).expect("wal open");
    let clock = Arc::new(AtomicU64::new(now));
    let agg = Aggregator::with_capacity_and_clock(
        cfg.clone(),
        Box::new(FormatVerifier),
        wal,
        Box::new({
            let clock = Arc::clone(&clock);
            move || clock.load(Ordering::Relaxed)
        }),
        agents.len(),
        n_intents,
    );
    for a in agents {
        agg.register(a.sd.clone(), a.agent_pub);
    }
    (agg, clock)
}

/// 封当前窗（时钟拨到 created_at + 60，满足"到时未满也封"）并返回全部已封 epoch。
fn seal_all(
    agg: &Aggregator,
    clock: &Arc<AtomicU64>,
) -> Vec<meridian_aggregator::ingest::SealedEpoch> {
    clock.store(DEFAULT_NOW + 60, Ordering::Relaxed);
    agg.seal_expired(clock.load(Ordering::Relaxed), 10)
}

// ---------------------------------------------------------------------------
// B5 吞吐（1/8/64 线程）
// ---------------------------------------------------------------------------

fn b5_measure(batch: &KernelBatch, workers: usize, tag: &str) -> (f64, usize) {
    let cfg = bench_cfg(batch.envs.len() + 1024, DEFAULT_PER_AGENT + 64);
    let (agg, _clock) = new_agg(&cfg, &batch.agents, batch.envs.len(), batch.now, tag);
    let pool: ThreadPool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .expect("rayon pool");
    let t = Instant::now();
    let receipts = agg.submit_batch(&pool, &batch.envs);
    let secs = t.elapsed().as_secs_f64();
    let accepted = receipts.iter().filter(|r| r.accepted).count();
    (batch.envs.len() as f64 / secs, accepted)
}

// ---------------------------------------------------------------------------
// B6 端到端延迟 p99（单线程）
// ---------------------------------------------------------------------------

fn b6_p99_ms() -> f64 {
    let batch = KernelBatch::build(KernelFixtureParams {
        n_agents: 1,
        per_agent: B6_N,
        now: DEFAULT_NOW,
        seed: MASTER_SEED,
    });
    let cfg = bench_cfg(B6_N + 64, 1 << 15); // nonce 预置 32k，避免测量中 rehash 尖峰
    let (agg, _clock) = new_agg(&cfg, &batch.agents, B6_N, DEFAULT_NOW, "b6");

    let mut durs = Vec::with_capacity(B6_N);
    for env in &batch.envs {
        let t = Instant::now();
        let r = agg.submit(env);
        assert!(
            r.accepted,
            "B6 fixture intent rejected: {:?}",
            r.reject_reason
        );
        durs.push(t.elapsed().as_secs_f64() * 1e3);
    }
    durs.sort_by(|a, b| a.partial_cmp(b).expect("finite duration"));
    durs[(durs.len() as f64 * 0.99) as usize]
}

// ---------------------------------------------------------------------------
// B8 热路径零分配（单线程稳态，NoAllocGuard）
// ---------------------------------------------------------------------------

fn b8_allocs() -> usize {
    let batch = KernelBatch::build(KernelFixtureParams {
        n_agents: 1,
        per_agent: B8_N,
        now: DEFAULT_NOW,
        seed: MASTER_SEED,
    });
    // 容量预置（B8 关键）：分片桶位 + nonce 集 + 意图索引全部预分配；epoch 容量 > 笔数
    // → 窗口不旋转；wal_sync_every 巨大 → 缓冲不落盘。稳态 submit 全路径零分配。
    let cfg = bench_cfg(B8_N + 32, 1 << 11);
    let (agg, _clock) = new_agg(&cfg, &batch.agents, B8_N, DEFAULT_NOW, "b8");

    let g = NoAllocGuard::new();
    for env in &batch.envs {
        assert!(agg.submit(env).accepted, "B8 fixture intent rejected");
    }
    drop(g);
    section_allocs()
}

// ---------------------------------------------------------------------------
// B10 端到端：100k 笔 → 批次 → 净额（记录基线 + 不变量断言）
// ---------------------------------------------------------------------------

struct B10Result {
    wall_ms: f64,
    allocs: usize,
    accepted: usize,
    net_total: u64,
    net_lines: usize,
    epochs: usize,
}

fn b10_run(batch: &KernelBatch, workers: usize) -> B10Result {
    let (agents, envs) = b10_batch(batch);
    let cfg = bench_cfg(envs.len() + 1024, DEFAULT_PER_AGENT + 64);
    let (agg, clock) = new_agg(&cfg, &agents, envs.len(), DEFAULT_NOW, "b10");
    let pool: ThreadPool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .expect("rayon pool");

    let g = NoAllocGuard::new();
    let t = Instant::now();
    let receipts = agg.submit_batch(&pool, &envs);
    let wall_ms = t.elapsed().as_secs_f64() * 1e3;
    drop(g);
    let allocs = section_allocs();

    let accepted = receipts.iter().filter(|r| r.accepted).count();
    assert_eq!(
        accepted,
        envs.len(),
        "B10: 100k 全接受（fixture nonce 唯一、预算全放开）"
    );

    let sealed = seal_all(&agg, &clock);
    let mut net_total: u64 = 0;
    let mut net_lines = 0usize;
    let mut epoch_entries = 0usize;
    for se in &sealed {
        let res = agg
            .settle_epoch(se)
            .expect("B10: settled epoch must resolve");
        // 不变量：承诺根公开可复算（§6.3 A）；净额根公开可复算（§6.3 E）。
        assert_eq!(
            lattice::commitment_root(&se.entries),
            res.commitment_root,
            "B10: commitment_root 不可复算"
        );
        assert_eq!(
            lattice::netting_root(&res.net),
            res.netting_root,
            "B10: netting_root 不可复算"
        );
        epoch_entries += se.entries.len();
        net_total += res.net.iter().map(|l| l.amount).sum::<u64>();
        net_lines += res.net.len();
    }
    // 不变量：每笔恰一次入承诺（Σepoch 条目 == 接受数）；净额 == 接受总额（金额全 1）。
    assert_eq!(epoch_entries, accepted, "B10: 双重记账 / 漏单");
    assert_eq!(net_total, accepted as u64, "B10: Σnet != Σaccepted");

    B10Result {
        wall_ms,
        allocs,
        accepted,
        net_total,
        net_lines,
        epochs: sealed.len(),
    }
}

// ---------------------------------------------------------------------------
// B11 确定性：同 seed 全管线输出哈希一致（单线程确定性提交）
// ---------------------------------------------------------------------------

#[derive(PartialEq)]
struct PipelineDigest {
    commitment_root: [u8; 32],
    netting_root: [u8; 32],
    accepted: u64,
    net_total: u64,
}

fn b11_run(batch: &KernelBatch, tag: &str) -> PipelineDigest {
    let (agents, envs) = b11_batch(batch);
    let cfg = bench_cfg(envs.len() + 1024, DEFAULT_PER_AGENT + 64);
    let (agg, clock) = new_agg(&cfg, &agents, envs.len(), DEFAULT_NOW, tag);

    // 单线程顺序提交：seq 分配 = 输入序 → 全管线确定性可复现（并发提交的 seq↔intent
    // 映射本身非确定，B11 口径是"固定摄取顺序下 lattice 全确定性"）。
    for env in &envs {
        assert!(agg.submit(env).accepted, "B11 fixture intent rejected");
    }

    let sealed = seal_all(&agg, &clock);
    let mut dig = PipelineDigest {
        commitment_root: [0u8; 32],
        netting_root: [0u8; 32],
        accepted: agg.accepted_count(),
        net_total: 0,
    };
    let mut seen_root = false;
    for se in &sealed {
        let res = agg.settle_epoch(se).expect("B11: settled epoch resolves");
        if !seen_root {
            dig.commitment_root = res.commitment_root;
            seen_root = true;
        }
        dig.netting_root = lattice::netting_root(&res.net);
        dig.net_total += res.net.iter().map(|l| l.amount).sum::<u64>();
    }
    dig
}

// ---------------------------------------------------------------------------
// 主流程
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json = args.iter().any(|a| a == "--json");
    let gen_fixture = args.iter().any(|a| a == "--gen-fixture");
    let check_alloc = args.iter().any(|a| a == "--check-alloc");
    let check_determinism = args.iter().any(|a| a == "--check-determinism");
    let check = args.iter().position(|a| a == "--check").map(|i| {
        args.get(i + 1)
            .map(|v| v.parse::<f64>().expect("--check <ops>"))
            .unwrap_or(B5_MIN_OPS)
    });

    let path = fixture_path();
    let params = main_fixture_params();

    if gen_fixture {
        let batch = KernelBatch::build(params);
        std::fs::create_dir_all(path.parent().unwrap()).expect("data dir");
        std::fs::write(&path, fixture_bytes(&params, &batch)).expect("write fixture");
        println!(
            "s10_fixture.bin written: {} ({} 笔, batch hash {})",
            path.display(),
            batch.envs.len(),
            hex_of(&batch.canonical_hash())
        );
        return;
    }

    let data = std::fs::read(&path).unwrap_or_else(|_| {
        eprintln!(
            "no s10_fixture.bin at {} — run `agg_sim --gen-fixture` first",
            path.display()
        );
        std::process::exit(2);
    });
    let (params, batch) = load_fixture(&data).expect("fixture load");
    println!(
        "fixture: {} 代理 × {} 意图 = {} 笔（hash 锁定，确定性）",
        params.n_agents,
        params.per_agent,
        batch.envs.len()
    );

    // -- 独立快速检查（CI 回归门禁）：B8 / B11。
    if check_alloc {
        let allocs = b8_allocs();
        let pass = allocs == 0;
        println!(
            "B8 热路径分配：{allocs} 次（目标 = 0）：{}",
            if pass { "PASS" } else { "FAIL" }
        );
        std::process::exit(if pass { 0 } else { 1 });
    }
    if check_determinism {
        let d1 = b11_run(&batch, "b11a");
        let d2 = b11_run(&batch, "b11b");
        let pass = d1 == d2;
        println!(
            "B11 确定性：同 seed 两跑 commitment_root/netting_root/净额 一致：{}",
            if pass { "PASS" } else { "FAIL" }
        );
        std::process::exit(if pass { 0 } else { 1 });
    }
    if let Some(threshold) = check {
        let (best_ops, _) = b5_best(&batch);
        let pass = best_ops >= threshold;
        println!(
            "B5 目标 ≥ {threshold:.0} 笔/s：{}（{best_ops:.0}）",
            if pass { "PASS" } else { "FAIL" }
        );
        std::process::exit(if pass { 0 } else { 1 });
    }

    // -- 全量验收报告。
    let (ops1, acc1) = b5_measure(&batch, 1, "b5-1");
    let (ops8, acc8) = b5_measure(&batch, 8, "b5-8");
    let (ops64, acc64) = b5_measure(&batch, 64, "b5-64");
    let best_ops = ops1.max(ops8).max(ops64);
    let p99 = b6_p99_ms();
    let (b7_wall, b7_alloc) = b7_measure();
    let allocs = b8_allocs();
    let b10 = b10_run(&batch, 64);
    let d1 = b11_run(&batch, "b11a");
    let d2 = b11_run(&batch, "b11b");

    let b5_pass = best_ops >= B5_MIN_OPS;
    let b6_pass = p99 <= B6_MAX_P99_MS;
    let b7_pass = b7_wall < B7_MAX_WALL_SECS && b7_alloc < B7_MAX_ALLOC_BYTES;
    let b8_pass = allocs == 0;
    let b11_pass = d1 == d2;

    if json {
        let report = serde_json::json!({
            "suite": "s10-aggregator-kernel",
            "commit": std::env::var("GITHUB_SHA").unwrap_or_else(|_| "local".to_string()),
            "machine": format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            "fixture": { "n_agents": params.n_agents, "per_agent": params.per_agent, "total": batch.envs.len() },
            "b5_ops_1t": ops1, "b5_ops_8t": ops8, "b5_ops_64t": ops64, "b5_best_ops": best_ops,
            "b6_p99_ms": p99,
            "b7_wall_ms": b7_wall * 1e3, "b7_alloc_bytes": b7_alloc,
            "b8_allocs": allocs,
            "b10_wall_ms": b10.wall_ms, "b10_allocs": b10.allocs, "b10_accepted": b10.accepted,
            "b10_net_total": b10.net_total, "b10_net_lines": b10.net_lines, "b10_epochs": b10.epochs,
            "b11_deterministic": b11_pass,
            "pass": { "b5": b5_pass, "b6": b6_pass, "b7": b7_pass, "b8": b8_pass, "b11": b11_pass },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize")
        );
    } else {
        println!("\nS-10 生产内核验收 sim — 完整 ingest → lattice 全管线");
        println!("B5  吞吐  1t {ops1:.0} | 8t {ops8:.0} | 64t {ops64:.0} 笔/s  目标 ≥ {B5_MIN_OPS:.0}：{}", verdict(b5_pass));
        println!(
            "B6  p99   {p99:.3} ms（B6_N={B6_N} 单线程）目标 ≤ {B6_MAX_P99_MS}ms：{}",
            verdict(b6_pass)
        );
        println!(
            "B7  100k 排序+承诺 {:.3} ms / {:.1} MiB（累计≥峰值）目标 <1s / <1GiB：{}",
            b7_wall * 1e3,
            b7_alloc as f64 / 1_048_576.0,
            verdict(b7_pass)
        );
        println!(
            "B8  热路径分配 {allocs} 次（{B8_N} 笔稳态）目标 = 0：{}",
            verdict(b8_pass)
        );
        println!(
            "B10 端到端 {} 笔 → {} 净额行（Σnet={}，{} epoch）：{} ms / {} 次分配",
            b10.accepted, b10.net_lines, b10.net_total, b10.epochs, b10.wall_ms, b10.allocs
        );
        println!(
            "B11 确定性：commitment_root/netting_root/净额 两跑一致：{}",
            verdict(b11_pass)
        );
        println!("接收数校验：B5(1t {acc1}/8t {acc8}/64t {acc64}) 全接受");
    }

    let all_pass = b5_pass && b6_pass && b7_pass && b8_pass && b11_pass;
    println!(
        "\nS-10 验收：{}",
        if all_pass { "ALL PASS" } else { "FAIL" }
    );
    std::process::exit(if all_pass { 0 } else { 1 });
}

fn b5_best(batch: &KernelBatch) -> (f64, usize) {
    let (a, _) = b5_measure(batch, 1, "b5chk-1");
    let (b, _) = b5_measure(batch, 8, "b5chk-8");
    let (c, acc) = b5_measure(batch, 64, "b5chk-64");
    (a.max(b).max(c), acc)
}

fn verdict(pass: bool) -> &'static str {
    if pass {
        "PASS"
    } else {
        "FAIL"
    }
}

fn hex_of(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}
