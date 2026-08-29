//! CI 性能门禁（TECH_SPEC §8.3 / MASTER_PLAN S-04）。
//!
//! 用法：
//!   cargo run -p meridian-bench --bin gate -- --record           # 写入 baseline.json
//!   cargo run -p meridian-bench --bin gate                        # 与 baseline 比较，回归 > 阈值则退出码 1
//!   cargo run -p meridian-bench --bin gate -- --fail-over 1.0     # 自定义阈值（%）
//!
//! 度量：固定输入集 + 固定迭代，输出 ops/sec，写入/比对 baseline.json。
//! 所有数字可复现（固定 seed、固定输入）。机器差异通过在同一参考平台上记录 baseline 消除。
//!
//! 噪音稳健性（S-14b）：`intent_verify_ops` 等指标单机 run-to-run 波动实测 ±17%
//! （> 15% 阈值）。因此：单指标 9 轮取中位 + 疑似回归整轮复测确认（连续两轮同指标都退步
//! 才算真回归）；`--record` 3 整轮逐指标取中位。真实代码回归两轮都退步必然被抓住。

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use meridian_bench::agg_fixture::{
    measure_kernel_rss_mib, measure_kernel_single_threaded, KernelBatch, KernelFixtureParams,
    MASTER_SEED,
};
use meridian_bench::b7_measure;
use meridian_bench::ingest::{measure_single_threaded, Batch, FixtureParams};
use meridian_core::dsa::{self, AgentSigningKey, Delegation, RateLimit, SpendIntent};
use meridian_core::ledger::{check_budget, BudgetState};

const SUITE: &str = "meridian-bench";
const DEFAULT_FAIL_OVER_PCT: f64 = 1.0;

/// 每指标阈值，**始终生效**（不随显式 `--fail-over` 放宽）。
/// B12 稳态 RSS 回归 >3% 红（TECH_SPEC §8.2）。RSS 是内存计数器、非 timing：实测
/// run-to-run 方差 ~0.2%，3% 阈值永不误报；`--fail-over 15` 灾难模式是给 ±17% 噪音的
/// timing 指标设计的，RSS 不需要放宽。其余指标沿用全局 `fail_over`。
const METRIC_THRESHOLDS: &[(&str, f64)] = &[("agg_kernel_rss_mib", 3.0)];

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
    // S-14b：5 → 9 轮取中位。intent_verify_ops 单机 run-to-run 波动实测 ±17%
    // （> 15% 阈值），5 轮中位仍会被一次负载突发整体拉低；9 轮显著收窄。
    const ROUNDS: usize = 9;
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

/// 三值中位数（`--record` 3 整轮逐指标取中位）。
fn median3(a: f64, b: f64, c: f64) -> f64 {
    let mut v = [a, b, c];
    v.sort_by(|x, y| x.partial_cmp(y).expect("finite sample"));
    v[1]
}

/// 输出比对表并返回超过阈值% 退步的指标名（不退出——调用方决定复测/失败）。
/// `metric_thresholds` 是每指标覆盖（如 B12 RSS 3%）；未命中则用全局 `fail_over`。
fn compare_table(
    baseline: &Report,
    metrics: &BTreeMap<String, f64>,
    fail_over: f64,
    metric_thresholds: &[(&str, f64)],
) -> Vec<String> {
    println!(
        "{:<28} {:>14} {:>14} {:>10}",
        "metric", "baseline", "current", "delta%"
    );
    // 低值优指标（墙钟 / 内存）：回归 = delta **正**（变慢 / 驻留涨）。其余指标都是
    // ops/s（高值优），回归 = delta 负（变少）。统一以"退步超过阈值%" 判回归
    // （S-14b 核对时修正：此前只查负 delta，b7_wall_ms 变慢永远不触发 → 该指标的门禁
    // 形同虚设。B12 同向：RSS 涨 >3% 即红，TECH_SPEC §8.2）。
    const LOWER_IS_BETTER: &[&str] = &["agg_kernel_b7_wall_ms", "agg_kernel_rss_mib"];
    // 观测-only 指标（照常记录/打印，不参与回归判定）：PoC ② 原型 ingest 基准
    // （S-08a，"原型留作历史证据"）。共享 CI runner 上可**稳定**假报回归——CI 首跑
    // 实证：同 job 内 record 与 compare 隔数分钟，复测两轮 -16.67% / -16.48% 全过
    // 复测确认门槛，而生产内核同热路径指标 agg_kernel_ingest_ops 同 job 仅 -0.28%
    // 且本地参考机该原型指标从不越线。B5 吞吐验收走 agg_sim / poc_aggregator，
    // 生产热路径回归由 agg_kernel_ingest_ops / b7 / B8 / B11 覆盖。
    const GATE_EXEMPT: &[&str] = &["aggregator_ingest_ops"];
    let mut regressions: Vec<String> = Vec::new();
    for (name, base) in &baseline.metrics {
        let cur = metrics.get(name).copied().unwrap_or(0.0);
        let delta = if *base > 0.0 {
            (cur - base) / base * 100.0
        } else {
            0.0
        };
        println!("{:<28} {:>14.1} {:>14.1} {:>9.2}%", name, base, cur, delta);
        if GATE_EXEMPT.contains(&name.as_str()) {
            continue;
        }
        let threshold = metric_thresholds
            .iter()
            .find(|(n, _)| *n == name.as_str())
            .map(|(_, t)| *t)
            .unwrap_or(fail_over);
        let regressed = if LOWER_IS_BETTER.contains(&name.as_str()) {
            delta > threshold
        } else {
            delta < -threshold
        };
        if regressed {
            regressions.push(name.clone());
        }
    }
    regressions
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let record = args.iter().any(|a| a == "--record");
    // 每指标阈值始终生效（RSS 3%）；显式 --fail-over 只作用于无覆盖的指标（timing 类）。
    let metric_thresholds: &[(&str, f64)] = METRIC_THRESHOLDS;
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
    let agent_pub = agent_key.verifying_key();

    // 测量闭包：一整轮全指标采样（每指标 9 轮取中位）。确定性输入、每调用独立样本
    // （state/batch 在闭包内重建）→ 可复测确认，防单机负载突发误报（S-14b）。
    let measure = || {
        BTreeMap::from([
            (
                "verify_delegation_ops".to_string(),
                bench_per_sec(|| {
                    std::hint::black_box(dsa::verify_delegation(
                        &signed,
                        owner_key.verifying_key(),
                    ))
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
            ("check_budget_ops".to_string(), {
                let mut state = BudgetState::new(dsa::delegation_hash(&delegation), 0);
                bench_per_sec(|| {
                    std::hint::black_box(check_budget(&delegation, &mut state, 1, 0)).ok();
                })
            }),
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
            // S-10 生产内核（meridian-aggregator）：单线程 ingest 全管线吞吐
            // （验签 → SpendVerifier → 预算 → 入窗 → WAL），B5 口径的单线程基线。
            // B8 零分配 / B11 确定性是硬断言，走 agg_sim --check-alloc / --check-determinism
            // （CI 回归），不进吞吐 baseline。
            (
                "agg_kernel_ingest_ops".to_string(),
                measure_kernel_single_threaded(&KernelBatch::build(KernelFixtureParams {
                    n_agents: 32,
                    per_agent: 200,
                    now: 1_700_000_000,
                    seed: MASTER_SEED,
                })),
            ),
            // B7 排序 + 承诺（100k 笔）最佳墙钟（5 轮取最短），lattice 热路径回归。
            ("agg_kernel_b7_wall_ms".to_string(), b7_measure().0 * 1e3),
            // B12 稳态 RSS（MiB，TECH_SPEC §8.2）：生产内核全量填满后的进程驻留足迹。
            // 低值优指标，METRIC_THRESHOLDS 3%；记录基线后回归 >3% 红。
            ("agg_kernel_rss_mib".to_string(), measure_kernel_rss_mib()),
        ])
    };

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("baseline.json");

    if record {
        // --record：3 整轮测量逐指标取中位（一次即得稳健基线，无需外部多次校准）。
        let (a, b, c) = (measure(), measure(), measure());
        let metrics = a
            .iter()
            .map(|(k, v)| (k.clone(), median3(*v, b[k], c[k])))
            .collect();
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

    // 首轮测量 + 比对。
    let regressions = compare_table(&baseline, &measure(), fail_over, metric_thresholds);
    if !regressions.is_empty() {
        // 疑似回归 → 整轮复测确认：连续两轮同指标都退步才算真回归
        // （intent_verify_ops 等指标单机 run-to-run 波动 ±17% > 15% 阈值，S-14b）。
        eprintln!(
            "[gate] 疑似回归（{}）——整轮复测确认…",
            regressions.join(", ")
        );
        let confirmed = compare_table(&baseline, &measure(), fail_over, metric_thresholds);
        if !confirmed.is_empty() {
            eprintln!("REGRESSION > {}% on: {}", fail_over, confirmed.join(", "));
            std::process::exit(1);
        }
        eprintln!("复测无回归 —— 初次判定为测量噪音，通过");
    }
    println!("OK");
}
