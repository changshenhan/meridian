//! Meridian 聚合器可观测性脚手架（S-15）。
//!
//! 零新依赖：Prometheus 文本导出格式手写（精确按 exposition spec），HTTP 用 std
//! `TcpListener` 自写（metrics/healthz 两个只读端点足够；S-15 真实部署如需要高级路由/
//! 长连接可换 hyper/axum，接口不变）。
//!
//! 设计：刮取式监控（Prometheus 语义）。聚合器进程（或本脚手架`restore`一个 WAL 副本）
//! 暴露 `/metrics`（Prometheus 文本）+ `/healthz`（JSON，200/503）。吞吐/p99 由刮取器按
//! 两次快照的 `accepted_count` 增量推算——**不在热路径埋点**（B8 零分配 + 无锁）。
//!
//! 诚实边界：`rejected` 是会话计数（崩溃恢复后从 0 起）；吞吐为最近一次刮取间隔的均值，
//! 不是 p99（p99 需热路径直方图，S-15 后续按需加，届时评估 B8 影响）。

pub mod health;
pub mod metrics;
pub mod server;

pub use health::{evaluate, HealthCheck, HealthReport};
pub use metrics::{render_prometheus, PromSample};
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
