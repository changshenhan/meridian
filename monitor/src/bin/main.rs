//! `meridian-monitor` CLI：生产配置聚合器 + 健康检查 + Prometheus 端点。
//!
//! 两种模式：
//! - 默认：HTTP 服务 `http://127.0.0.1:<port>`（`/healthz` JSON + `/metrics` Prometheus 文本）。
//! - `--once`：现场快照打 stdout 后退出（脚本探活/进程内嵌监控用）。
//!
//! 数据口径：本进程 `restore_from_wal` **N ≥ 1 个**聚合器副本（只读视图，**不**接热路径）。
//! 单副本 = S-15 既有单实例口径（逐字节不变）；多副本 = S-39 集群聚合（热备副本组，
//! 同一逻辑账本取 max，副本分歧报 degraded——TECH_SPEC §6.12）。

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::proof::FormatVerifier;
use meridian_monitor::cluster::{evaluate_cluster, render_cluster_metrics, ClusterView};
use meridian_monitor::count_wal_intents;
use meridian_monitor::health::evaluate;
use meridian_monitor::metrics::{rate_from_delta, render_prometheus};
use meridian_monitor::server::{serve, Report, Reporter};

fn main() {
    let mut wal_paths: Vec<PathBuf> = Vec::new();
    let mut port: u16 = 9100;
    let mut once = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            // 可重复传：`--wal a.wal --wal b.wal` = 热备副本组集群聚合（S-39）。
            "--wal" => {
                wal_paths.push(PathBuf::from(args.next().expect("--wal <path>")));
            }
            "--port" => {
                port = args
                    .next()
                    .expect("--port <n>")
                    .parse()
                    .expect("--port must be a number")
            }
            "--once" => once = true,
            "--help" | "-h" => {
                println!("usage: meridian-monitor [--wal <path>]... [--port <n>] [--once]");
                println!(
                    "  --wal 可重复传多个 = 热备副本组集群聚合（instance label = WAL 文件名）"
                );
                return;
            }
            other => {
                eprintln!("unknown arg: {other} (see --help)");
                std::process::exit(2);
            }
        }
    }
    if wal_paths.is_empty() {
        wal_paths.push(PathBuf::from("meridian.wal"));
    }

    match run(&wal_paths, port, once) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("meridian-monitor: {e}");
            std::process::exit(1);
        }
    }
}

fn run(wal_paths: &[PathBuf], port: u16, once: bool) -> std::io::Result<i32> {
    // 副本名 = WAL 文件名 stem，作多副本模式的 instance label；重名会撞 Prometheus
    // 序列（不同目录同名文件），启动即报错，不猜（TECH_SPEC §6.12 实例标签）。
    let mut names: Vec<String> = Vec::with_capacity(wal_paths.len());
    for p in wal_paths {
        let stem = p
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .ok_or_else(|| std::io::Error::other(format!("{} 不是文件路径", p.display())))?;
        if names.contains(&stem) {
            return Err(std::io::Error::other(format!(
                "多副本模式的 WAL 文件名必须互异（撞 instance label）：{stem}"
            )));
        }
        names.push(stem);
    }

    let mut replicas = Vec::with_capacity(wal_paths.len());
    for (p, name) in wal_paths.iter().zip(&names) {
        let (agg, truncated) = Aggregator::restore_from_wal(
            IngestConfig::production(),
            Box::new(FormatVerifier),
            p,
            Box::new(unix_now_secs),
        )?;
        if truncated {
            eprintln!(
                "meridian-monitor: warning: 副本 {name} WAL 尾部损坏已截断恢复\
                 （崩溃时未同步的字节）。建议尽快接管该 WAL 并核对结算账本。"
            );
        }

        // 独立重放 WAL 数 Intent 记录（不信任聚合器内存的 accepted_count，否则自比）。
        let wal_intents = count_wal_intents(p)?;
        let snap = agg.snapshot();
        if snap.accepted_count != wal_intents {
            eprintln!(
                "meridian-monitor: warning: 副本 {name} 内存 accepted_count={} ≠ WAL Intent 数={} \
                 （一致性降级，/healthz 将报 503）",
                snap.accepted_count, wal_intents
            );
        }
        replicas.push(ReplicaScrape {
            name: name.clone(),
            agg: Arc::new(agg),
            wal_intents,
            prev: Mutex::new(None),
        });
    }
    let multi = replicas.len() > 1;
    let reporter = ClusterReporter { replicas, multi };

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

/// 单副本数据源：聚合器副本 + 独立 WAL Intent 计数 + 独立刮取窗口状态。
struct ReplicaScrape {
    name: String,
    agg: Arc<Aggregator>,
    wal_intents: u64,
    prev: Mutex<Option<(u64, Instant)>>,
}

impl ReplicaScrape {
    /// 现场快照 + 本副本窗口速率（各副本独立推算，互不共享窗口）。
    fn view(&self) -> (ClusterView, f64) {
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
        (
            ClusterView {
                name: self.name.clone(),
                snap,
            },
            rate,
        )
    }
}

/// 集群 Reporter（S-39）。单副本（multi=false）走既有单实例路径，输出逐字节不变；
/// 多副本走集群聚合（TECH_SPEC §6.12）。
struct ClusterReporter {
    replicas: Vec<ReplicaScrape>,
    multi: bool,
}

impl Reporter for ClusterReporter {
    fn report(&self) -> Report {
        if !self.multi {
            let r = &self.replicas[0];
            let (v, rate) = r.view();
            return Report {
                health: evaluate(&v.snap, r.wal_intents),
                metrics: render_prometheus(&v.snap, rate),
            };
        }
        let mut views = Vec::with_capacity(self.replicas.len());
        let mut rates = Vec::with_capacity(self.replicas.len());
        let mut wal_intents = Vec::with_capacity(self.replicas.len());
        for r in &self.replicas {
            let (v, rate) = r.view();
            wal_intents.push(r.wal_intents);
            views.push(v);
            rates.push(rate);
        }
        Report {
            health: evaluate_cluster(&views, &wal_intents),
            metrics: render_cluster_metrics(&views, &rates),
        }
    }
}
