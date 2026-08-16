//! CI 性能门禁（TECH_SPEC §8.3 / MASTER_PLAN S-04）。
//!
//! 用法：
//!   cargo run -p meridian-bench --bin gate -- --record           # 写入 baseline.json
//!   cargo run -p meridian-bench --bin gate                        # 与 baseline 比较，回归 > 阈值则退出码 1
//!   cargo run -p meridian-bench --bin gate -- --fail-over 1.0     # 自定义阈值（%）
//!
//! 度量：固定输入集 + 固定迭代，输出 ops/sec，写入/比对 baseline.json。
//! 所有数字可复现（固定 seed、固定输入）。机器差异通过在同一参考平台上记录 baseline 消除。

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use meridian_bench::ingest::{measure_single_threaded, Batch, FixtureParams};
use meridian_core::dsa::{self, AgentSigningKey, Delegation, RateLimit, SpendIntent};
use meridian_core::ledger::{check_budget, BudgetState};

const SUITE: &str = "meridian-bench";
const DEFAULT_FAIL_OVER_PCT: f64 = 1.0;

#[derive(serde::Serialize, serde::Deserialize)]
struct Report {
    suite: String,
    commit: String,
    machine: String,
    metrics: BTreeMap<String, f64>,
    recorded_at_unix: u64,
}

/// 稳定计时：预热后采样 N 轮取中位数（抗单轮抖动），返回 ops/sec。
/// 分块内联摊销循环开销。调用方负责用 `black_box` 保留结果，防止被优化掉。
fn bench_per_sec<F: FnMut()>(mut f: F) -> f64 {
    for _ in 0..20_000 {
        f();
    }
    const ROUNDS: usize = 5;
    let mut samples = [0.0f64; ROUNDS];
    for s in samples.iter_mut() {
        let mut n: u64 = 0;
        let start = Instant::now();
        let deadline = start + Duration::from_millis(300);
        while Instant::now() < deadline {
            for _ in 0..10_000 {
                f();
                n += 1;
            }
        }
        *s = n as f64 / start.elapsed().as_secs_f64();
    }
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite sample"));
    samples[ROUNDS / 2]
}

fn sample_delegation() -> Delegation {
    Delegation {
        agent: [1u8; 20],
        owner: [2u8; 20],
        nonce: 1,
        max_per_spend: 1,
        rate: RateLimit {
            window_secs: 60,
            max_per_window: u64::MAX,
        },
        total_cap: u64::MAX,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
        version: 1,
    }
}

fn sample_intent(dh: [u8; 32]) -> SpendIntent {
    SpendIntent {
        agent: [1u8; 20],
        delegation_hash: dh,
        recipient: [3u8; 20],
        amount: 1,
        category: [0xCD; 32],
        spend_nonce: 7,
        memo: None,
        expires_at: u64::MAX,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let record = args.iter().any(|a| a == "--record");
    let fail_over = match args.iter().position(|a| a == "--fail-over") {
        Some(pos) => args
            .get(pos + 1)
            .map(|v| v.parse::<f64>().expect("bad --fail-over"))
            .unwrap_or(DEFAULT_FAIL_OVER_PCT),
        None => DEFAULT_FAIL_OVER_PCT,
    };

    // 固定输入
    let owner_key = dsa::owner_signing_key_from_bytes([7u8; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
    let delegation = sample_delegation();
    let signed = dsa::sign_delegation(&delegation, &owner_key);
    let intent = sample_intent(dsa::delegation_hash(&delegation));
    let agent_sig = dsa::sign_intent(&intent, &agent_key);
    let mut state = BudgetState::new(dsa::delegation_hash(&delegation), 0);
    let agent_pub = agent_key.verifying_key();

    let metrics: BTreeMap<String, f64> = BTreeMap::from([
        (
            "verify_delegation_ops".to_string(),
            bench_per_sec(|| {
                std::hint::black_box(dsa::verify_delegation(&signed, owner_key.verifying_key()))
                    .ok();
            }),
        ),
        (
            "sign_delegation_ops".to_string(),
            bench_per_sec(|| {
                std::hint::black_box(dsa::sign_delegation(&delegation, &owner_key));
            }),
        ),
        (
            "intent_sign_ops".to_string(),
            bench_per_sec(|| {
                std::hint::black_box(dsa::sign_intent(&intent, &agent_key));
            }),
        ),
        (
            "intent_verify_ops".to_string(),
            bench_per_sec(|| {
                std::hint::black_box(dsa::verify_intent(&intent, &agent_sig, &agent_pub)).ok();
            }),
        ),
        (
            "check_budget_ops".to_string(),
            bench_per_sec(|| {
                std::hint::black_box(check_budget(&delegation, &mut state, 1, 0)).ok();
            }),
        ),
        // PoC ②（S-08a）：聚合器完整 ingest 快路径（验签→nonce→预算记账）。
        // 单线程基线；多线程吞吐见 bin/poc_aggregator（10 万笔/秒验收）。
        // 固定批次一次性处理（nonce 不能跨次复用），见 ingest.rs。
        (
            "aggregator_ingest_ops".to_string(),
            measure_single_threaded(&Batch::build(FixtureParams {
                n_agents: 32,
                per_agent: 200,
            })),
        ),
    ]);

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("baseline.json");

    if record {
        let report = Report {
            suite: SUITE.to_string(),
            commit: std::env::var("GITHUB_SHA").unwrap_or_else(|_| "local".to_string()),
            machine: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            metrics,
            recorded_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock before epoch")
                .as_secs(),
        };
        let json = serde_json::to_string_pretty(&report).expect("serialize");
        std::fs::write(&path, format!("{json}\n")).expect("write baseline");
        println!("baseline written to {}", path.display());
        return;
    }

    let baseline_raw = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        eprintln!(
            "no baseline at {} — run with --record first",
            path.display()
        );
        std::process::exit(2);
    });
    let baseline: Report = serde_json::from_str(&baseline_raw).expect("parse baseline");

    println!(
        "{:<28} {:>14} {:>14} {:>10}",
        "metric", "baseline", "current", "delta%"
    );
    let mut regressions: Vec<String> = Vec::new();
    for (name, base) in &baseline.metrics {
        let cur = metrics.get(name).copied().unwrap_or(0.0);
        let delta = if *base > 0.0 {
            (cur - base) / base * 100.0
        } else {
            0.0
        };
        println!("{:<28} {:>14.1} {:>14.1} {:>9.2}%", name, base, cur, delta);
        if delta < -fail_over {
            regressions.push(name.clone());
        }
    }
    if !regressions.is_empty() {
        eprintln!("REGRESSION > {}% on: {}", fail_over, regressions.join(", "));
        std::process::exit(1);
    }
    println!("OK");
}
