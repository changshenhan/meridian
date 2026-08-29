//! 健康判定（供 `/healthz` 与独立 `--once` 检查）。
//!
//! 判定规则（诚实口径，见各检查 detail）：
//! - `ledger_consistent`：WAL 中 Intent 记录数 == 聚合器 accepted_count。不等说明
//!   内存账本与崩溃恢复边界漂移（WAL 写入故障时的第一个信号）。
//! - `revocation_root_present`：有撤销（revoked_len>0）则撤销根必须非零——撤销已进
//!   Merkle 承诺，零根 = 撤销丢失（聚合器内部不一致）。
//! - `epoch_backlog`：pending_sealed 是否超过阈值。结算滞后是运营风险（长时间不
//!   process_pending，风险集中在 BatchSettler 消费端），不是数据损坏——阈值可放宽。

use meridian_aggregator::health::HealthSnapshot;
use serde::Serialize;

/// 结算滞后告警边界：允许 pending_sealed 最多落后这么多 epoch。
pub const DEFAULT_MAX_BACKLOG_EPOCHS: usize = 3;

/// 单条检查结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthCheck {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// 汇总报告：`status` = "ok" | "degraded"（无 panic/崩溃态——那由进程退出表达）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthReport {
    pub status: &'static str,
    pub checks: Vec<HealthCheck>,
}

impl HealthReport {
    pub fn is_ok(&self) -> bool {
        self.status == "ok"
    }
}

/// 对快照跑全部检查。`wal_intents` 是独立读取 WAL 得到的 Intent 记录数
/// （不是从聚合器内存拿的——否则 `ledger_consistent` 变成自比）。
pub fn evaluate(s: &HealthSnapshot, wal_intents: u64) -> HealthReport {
    let mut checks = Vec::with_capacity(3);

    let consistent = s.accepted_count == wal_intents;
    checks.push(HealthCheck {
        name: "ledger_consistent",
        ok: consistent,
        detail: format!(
            "accepted_count={} wal_intents={}",
            s.accepted_count, wal_intents
        ),
    });

    // 撤销了就必须有非零承诺根（S-11 口径：撤销即重算稀疏根）。
    let root_ok = if s.revoked_len == 0 {
        true
    } else {
        s.revocation_root != [0; 32]
    };
    checks.push(HealthCheck {
        name: "revocation_root_present",
        ok: root_ok,
        detail: format!(
            "revoked_len={} root=0x{}",
            s.revoked_len,
            hex32(&s.revocation_root)
        ),
    });

    let backlog_ok = s.pending_sealed <= DEFAULT_MAX_BACKLOG_EPOCHS;
    checks.push(HealthCheck {
        name: "epoch_backlog",
        ok: backlog_ok,
        detail: format!(
            "pending_sealed={} threshold={} (epoch_capacity={})",
            s.pending_sealed, DEFAULT_MAX_BACKLOG_EPOCHS, s.epoch_capacity
        ),
    });

    let all_ok = checks.iter().all(|c| c.ok);
    HealthReport {
        status: if all_ok { "ok" } else { "degraded" },
        checks,
    }
}

/// 32 字节 → 64 字符 hex（std 手写，不引 hex crate）。
fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use meridian_aggregator::hist::LatencySnapshot;

    fn snap() -> HealthSnapshot {
        HealthSnapshot {
            instance_id: "t".into(),
            started_at_unix: 1_700_000_000,
            now: 1_700_000_100,
            accepted_count: 42,
            rejected_count: 7,
            pending_sealed: 1,
            revoked_len: 0,
            revocation_root: [0; 32],
            wal_len: 4096,
            submit_latency: LatencySnapshot::default(),
            ledger_shards: 8,
            epoch_capacity: 1000,
            epoch_secs: 60,
        }
    }

    #[test]
    fn all_green_when_consistent() {
        let r = evaluate(&snap(), 42);
        assert!(r.is_ok());
        assert_eq!(r.status, "ok");
        assert!(r.checks.iter().all(|c| c.ok));
    }

    #[test]
    fn ledger_drift_degrades() {
        // accepted=42 但 WAL 只落了 40 笔 Intent —— 崩溃恢复边界漂移。
        let r = evaluate(&snap(), 40);
        assert_eq!(r.status, "degraded");
        assert!(!r.checks[0].ok);
        assert!(r.checks[0].detail.contains("42"));
    }

    #[test]
    fn revocation_without_root_degrades() {
        let s = HealthSnapshot {
            revoked_len: 3,
            revocation_root: [0; 32],
            ..snap()
        };
        let r = evaluate(&s, 42);
        assert_eq!(r.status, "degraded");
        assert!(!r.checks[1].ok); // revocation_root_present
    }

    #[test]
    fn revocations_present_and_rooted_ok() {
        let mut s = snap();
        s.revoked_len = 3;
        s.revocation_root = [7u8; 32];
        let r = evaluate(&s, 42);
        assert!(r.is_ok());
        assert!(r.checks[1]
            .detail
            .contains("0707070707070707070707070707070707070707070707070707070707070707"));
    }

    #[test]
    fn epoch_backlog_threshold() {
        let s = HealthSnapshot {
            pending_sealed: DEFAULT_MAX_BACKLOG_EPOCHS + 1,
            ..snap()
        };
        let r = evaluate(&s, 42);
        assert_eq!(r.status, "degraded");
        assert!(!r.checks[2].ok);
    }

    #[test]
    fn json_serializes() {
        let r = evaluate(&snap(), 42);
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
    }
}
