//! 聚合器健康快照（S-15 监控/告警数据源）。
//!
//! `HealthSnapshot` 是 `Aggregator::snapshot()` 的无锁视图：全部字段来自原子计数器或
//! 只读状态，**不**触碰任何分片锁/窗口锁——抓快照不会引入热路径争用（B8 信条）。
//!
//! 口径诚实边界：
//! - `accepted_count` / `rejected_count` 是**会话**计数（`rejected` 不持久化；崩溃恢复
//!   后从 0 起，accepted 由 WAL 重放精确重建）。
//! - `rejected` 计**实际拒绝**：幂等 re-ack（同意图重发）不计 accepted 也不计 rejected。
//! - 吞吐由外部刮取器按两次快照的 `accepted_count` 增量推算（单机或集群维度）；
//!   p99 由 S-35 热路径直方图（`hist::LatencySnapshot`）提供——固定桶原子增量，仍不在
//!   热路径引入分配或锁（B8 口径不变），会话计数不持久化。

use crate::hist::LatencySnapshot;

/// 单次抓取的健康快照（无锁视图）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSnapshot {
    /// 实例标识（`mist-<pid>`；S-15 多实例时每实例一 endpoint）。
    pub instance_id: String,
    /// 本实例启动时刻（unix 秒，聚合器构造时取）。
    pub started_at_unix: u64,
    /// 抓取时刻（unix 秒）。
    pub now: u64,
    /// 已接受总数（== 下一个待分配 seq）。
    pub accepted_count: u64,
    /// 本次会话拒绝数（不持久化）。
    pub rejected_count: u64,
    /// 已密封未消费的 epoch 数（运营方应及时 settle/process_pending）。
    pub pending_sealed: usize,
    /// 已撤销委托数。
    pub revoked_len: usize,
    /// 撤销 Merkle 根（未撤销过 = 全零）。
    pub revocation_root: [u8; 32],
    /// WAL 文件字节数（崩溃恢复边界可见性）。
    pub wal_len: u64,
    /// `submit` 全路径延迟直方图快照（S-35，会话计数不持久化；TECH_SPEC §6.11）。
    pub submit_latency: LatencySnapshot,
    // 生产拓扑参数（告警阈值 / 容量规划参考）。
    pub ledger_shards: usize,
    pub epoch_capacity: usize,
    pub epoch_secs: u64,
}

impl HealthSnapshot {
    /// 运行时长（秒）。
    pub fn uptime_secs(&self) -> u64 {
        self.now.saturating_sub(self.started_at_unix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hist::LatencySnapshot;

    #[test]
    fn uptime_is_saturating_and_forward() {
        let s = HealthSnapshot {
            instance_id: "t".into(),
            started_at_unix: 1_700_000_000,
            now: 1_700_000_060,
            accepted_count: 0,
            rejected_count: 0,
            pending_sealed: 0,
            revoked_len: 0,
            revocation_root: [0; 32],
            wal_len: 0,
            submit_latency: LatencySnapshot::default(),
            ledger_shards: 8,
            epoch_capacity: 100,
            epoch_secs: 60,
        };
        assert_eq!(s.uptime_secs(), 60);
        let past = HealthSnapshot {
            now: 1_690_000_000,
            ..s.clone()
        };
        assert_eq!(past.uptime_secs(), 0); // saturating：时钟回拨不 panic
    }
}
