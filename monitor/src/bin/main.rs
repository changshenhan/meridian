//! `meridian-monitor` CLI：生产配置聚合器 + 健康检查 + Prometheus 端点。
//!
//! 两种模式：
//! - 默认：HTTP 服务 `http://127.0.0.1:<port>`（`/healthz` JSON + `/metrics` Prometheus 文本）。
//! - `--once`：现场快照打 stdout 后退出（脚本探活/进程内嵌监控用）。
//!
//! 数据口径：本进程 `restore_from_wal` 一个聚合器副本（只读视图，**不**接热路径），
//! `accepted_count` 增量 = 吞吐（刮取窗口均值，非 p99——诚实边界见 crate 文档）。

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::proof::FormatVerifier;
use meridian_monitor::count_wal_intents;
use meridian_monitor::health::evaluate;
use meridian_monitor::metrics::{rate_from_delta, render_prometheus};
use meridian_monitor::server::{serve, Report, Reporter};

fn main() {
    let mut wal_path = PathBuf::from("meridian.wal");
    let mut port: u16 = 9100;
    let mut once = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--wal" => wal_path = args.next().map(PathBuf::from).expect("--wal <path>"),
            "--port" => {
                port = args
                    .next()
                    .expect("--port <n>")
                    .parse()
                    .expect("--port must be a number")
            }
            "--once" => once = true,
            "--help" | "-h" => {
                println!("usage: meridian-monitor [--wal <path>] [--port <n>] [--once]");
                return;
            }
            other => {
                eprintln!("unknown arg: {other} (see --help)");
                std::process::exit(2);
            }
        }
    }

    match run(&wal_path, port, once) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("meridian-monitor: {e}");
            std::process::exit(1);
        }
    }
}

fn run(wal_path: &std::path::Path, port: u16, once: bool) -> std::io::Result<i32> {
    let now_fn: Box<dyn Fn() -> u64 + Send + Sync> = Box::new(unix_now_secs);

    let (agg, truncated) = Aggregator::restore_from_wal(
        IngestConfig::production(),
        Box::new(FormatVerifier),
        wal_path,
        now_fn,
    )?;
    if truncated {
        eprintln!(
            "meridian-monitor: warning: WAL 尾部损坏已截断恢复（崩溃时未同步的字节）。\
             建议尽快接管该 WAL 并核对结算账本。"
        );
    }

    // 独立重放 WAL 数 Intent 记录（不信任聚合器内存的 accepted_count，否则自比）。
    let wal_intents = count_wal_intents(wal_path)?;
    let snap = agg.snapshot();
    if snap.accepted_count != wal_intents {
        eprintln!(
            "meridian-monitor: warning: 聚合器内存 accepted_count={} ≠ WAL Intent 数={} \
             （一致性降级，/healthz 将报 503）",
            snap.accepted_count, wal_intents
        );
    }
    let agg = Arc::new(agg);
    let reporter = ScrapeReporter {
        agg,
        wal_intents,
        prev: Mutex::new(None),
    };

    if once {
        let r = reporter.report();
        let health_json = serde_json::to_string_pretty(&r.health).unwrap();
        println!("{health_json}");
        println!("---");
        print!("{}", r.metrics);
        return Ok(if r.health.is_ok() { 0 } else { 3 });
    }

    let addr = format!("127.0.0.1:{port}");
    // 预检端口占用（serve 的 bind 错误也要在这里报得清晰）。
    let probe = TcpListener::bind(&addr)?;
    drop(probe);
    serve(&addr, reporter)?;
    Ok(0)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 每次刮取现场计算 Report；`accepted_count` 增量/间隔 → 吞吐（均值）。
struct ScrapeReporter {
    agg: Arc<Aggregator>,
    wal_intents: u64,
    prev: Mutex<Option<(u64, Instant)>>,
}

impl Reporter for ScrapeReporter {
    fn report(&self) -> Report {
        let snap = self.agg.snapshot();
        let mut prev = self.prev.lock().unwrap();
        let rate = match *prev {
            Some((prev_accepted, prev_ts)) => rate_from_delta(
                snap.accepted_count.saturating_sub(prev_accepted),
                prev_ts.elapsed().as_secs_f64(),
            ),
            None => 0.0,
        };
        *prev = Some((snap.accepted_count, Instant::now()));
        Report {
            health: evaluate(&snap, self.wal_intents),
            metrics: render_prometheus(&snap, rate),
        }
    }
}
