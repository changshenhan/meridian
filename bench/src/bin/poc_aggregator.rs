//! PoC ② 聚合器吞吐原型（蓝图 Phase 0：≥ 10 万笔意图/秒）。
//!
//! 用法：
//! ```text
//! cargo run --release -p meridian-bench --bin poc_aggregator                       # 缩放曲线报告
//! cargo run --release -p meridian-bench --bin poc_aggregator -- --check 100000     # 验收模式（≥ 10万/秒）
//! cargo run --release -p meridian-bench --bin poc_aggregator -- --json             # JSON 报告（供文档回填）
//! ```
//!
//! 口径：固定输入（`DEFAULT_AGENTS` 代理 × `DEFAULT_PER_AGENT` 意图/代理，密钥由
//! 固定 seed 派生，零随机），每次 run 用全新 `ShardedIngest`（nonce/账本不跨次污染）。
//! 测的是**完整 ingest 快路径**：验签 → 并发 nonce 去重 → 分片账本预算记账。
//! 单线程是基线；多线程是"聚合器可水平放大"的架构证明（S-10 生产内核据此构建）。

use std::thread;

use meridian_bench::ingest::{
    measure_multi_threaded, measure_single_threaded, Batch, FixtureParams,
};

const DEFAULT_AGENTS: usize = 128;
const DEFAULT_PER_AGENT: usize = 2_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let check = args.iter().position(|a| a == "--check").map(|i| {
        args.get(i + 1)
            .map(|v| v.parse::<f64>().expect("--check <ops>"))
            .unwrap_or(100_000.0)
    });
    let json = args.iter().any(|a| a == "--json");

    let batch = Batch::build(FixtureParams {
        n_agents: DEFAULT_AGENTS,
        per_agent: DEFAULT_PER_AGENT,
    });
    let total = batch.items.len();

    let single = measure_single_threaded(&batch);
    let max_workers = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);

    // 缩放曲线：1 → 2 → 4 → 8 → 16 → 满核。每点全新 ingest，数字独立。
    let mut steps: Vec<usize> = vec![1, 2, 4, 8, 16];
    if !steps.contains(&max_workers) {
        steps.push(max_workers);
    }
    let curve: Vec<(usize, f64)> = steps
        .iter()
        .map(|w| (*w, measure_multi_threaded(&batch, *w)))
        .collect();
    let (best_workers, best_ops) = curve
        .iter()
        .cloned()
        .max_by(|a, b| a.1.partial_cmp(&b.1).expect("finite ops"))
        .expect("curve non-empty");

    if json {
        let scaling: Vec<serde_json::Value> = curve
            .iter()
            .map(|(w, o)| serde_json::json!({ "workers": w, "ops": o }))
            .collect();
        let report = serde_json::json!({
            "suite": "poc2-aggregator-throughput",
            "batch": { "agents": DEFAULT_AGENTS, "per_agent": DEFAULT_PER_AGENT, "total": total },
            "single_thread_ops": single,
            "max_workers": max_workers,
            "scaling": scaling,
            "best_ops": best_ops,
            "best_workers": best_workers,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize")
        );
    } else {
        println!("PoC ② 聚合器吞吐原型 — 完整 ingest 快路径（验签→nonce 去重→预算记账）");
        println!(
            "批次：{} 代理 × {} 意图/代理 = {} 笔（密钥固定 seed 派生，确定性）",
            DEFAULT_AGENTS, DEFAULT_PER_AGENT, total
        );
        println!("单线程基线：{single:.0} 笔/秒");
        println!("缩放曲线（workers → 笔/秒）：");
        for (w, o) in &curve {
            println!("  {w:>2}  →  {o:.0}");
        }
        println!("最优：{best_workers} worker → {best_ops:.0} 笔/秒");
    }

    if let Some(threshold) = check {
        let pass = best_ops >= threshold;
        println!(
            "[check] 目标 ≥ {threshold:.0} 笔/秒：{}（{best_ops:.0}）",
            if pass { "PASS" } else { "FAIL" }
        );
        std::process::exit(if pass { 0 } else { 1 });
    }
}
