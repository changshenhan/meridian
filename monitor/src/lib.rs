//! Meridian 聚合器可观测性脚手架（S-15）。
//!
//! 零新依赖：Prometheus 文本导出格式手写（精确按 exposition spec），HTTP 用 std
//! `TcpListener` 自写（metrics/healthz 两个只读端点足够；S-15 真实部署如需要高级路由/
//! 长连接可换 hyper/axum，接口不变）。
//!
//! 设计：刮取式监控（Prometheus 语义）。聚合器进程（或本脚手架`restore`一个 WAL 副本）
//! 暴露 `/metrics`（Prometheus 文本）+ `/healthz`（JSON，200/503）。吞吐由刮取器按
//! 两次快照的 `accepted_count` 增量推算；p99 由 S-35 热路径直方图提供（固定桶原子增量，
//! 仍不在热路径引入分配或锁——B8 口径不变，TECH_SPEC §6.11）。
//!
//! 诚实边界：`rejected` 是会话计数（崩溃恢复后从 0 起）；吞吐为最近一次刮取间隔的均值，
//! 不是 p99；直方图 p99 是 log2 桶**上界**近似（精确分位数用 `_bucket` 跑
//! `histogram_quantile`），同样会话口径、不持久化。
//!
//! 多实例（S-39）：`cluster.rs` 聚合 N 个热备 WAL 副本（同一逻辑账本取 max，副本分歧
//! 报 degraded）——口径见 TECH_SPEC §6.12。
//!
//! 声誉面（S-65）：`reputation.rs` + `rpc.rs` 从 BatchSettler 事件派生只读指标
//! （§6.17 决策 E——不进任何判定面；`--settler`/`--rpc` 同给同不给，缺省序列不出现）。

pub mod cluster;
pub mod health;
pub mod metrics;
pub mod reputation;
pub mod rpc;
pub mod server;

pub use cluster::{cluster_samples, evaluate_cluster, render_cluster_metrics, ClusterView};
pub use health::{evaluate, HealthCheck, HealthReport};
pub use metrics::{render_prometheus, PromSample};
pub use reputation::{fetch_reputation, render_reputation, ReputationSnapshot};
pub use rpc::JsonRpc;
pub use server::{serve, Report, Reporter};

use std::path::Path;

use meridian_aggregator::wal::{DecodedRecord, Wal};

/// 独立重放 WAL，统计 Intent 记录数。
///
/// 故意不读聚合器内存的 `accepted_count`（否则 `ledger_consistent` 检查变成自比）：
/// 这是从崩溃恢复边界的原始事实（WAL 文件）独立重算的账本上界。
pub fn count_wal_intents(path: &Path) -> std::io::Result<u64> {
    let wal = Wal::open(path, 1_000)?;
    let (records, _, _) = wal.replay()?;
    Ok(records
        .iter()
        .filter(|r| matches!(r, DecodedRecord::Intent { .. }))
        .count() as u64)
}
