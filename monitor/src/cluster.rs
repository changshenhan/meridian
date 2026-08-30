//! 多实例集群聚合（S-39，TECH_SPEC §6.12 / ops.md §6 挂账项收口）。
//!
//! 口径：N 个 WAL = **同一逻辑账本的热备副本组**（§1 拓扑「WAL 副本/多实例」），不是
//! 独立分片——集群账本指标取 max（最新推进副本），sum 会把备份副本双计。副本间分歧只
//! 报告（degraded + lag gauge），不裁决真值（裁决 = 接管 WAL 人工核对，ops.md §5）。

use meridian_aggregator::health::HealthSnapshot;

use crate::health::{evaluate, HealthCheck, HealthReport};
use crate::metrics::{render_prometheus_labeled, PromSample};

/// 副本收敛口径：`replicas_converged` 要求三元组严格相等（滞后 0），无「可调滞后阈值」
/// ——异步副本（跨机）部署的滞后告警走 `meridian_cluster_replica_lag` gauge（ops.md §5），
/// 健康检查只认完全一致，避免「允许落后 N 笔」把账本分歧常态化（fail-closed）。
///
/// 一次集群聚合的输入：副本名（WAL 文件名 stem，作 `instance` label）+ 其健康快照。
#[derive(Debug, Clone)]
pub struct ClusterView {
    pub name: String,
    pub snap: HealthSnapshot,
}

/// 集群级 gauge（不带 `instance` label；口径见 TECH_SPEC §6.12 表）。
pub fn cluster_samples(views: &[ClusterView]) -> Vec<PromSample> {
    let max_acc = views
        .iter()
        .map(|v| v.snap.accepted_count)
        .max()
        .unwrap_or(0);
    let min_acc = views
        .iter()
        .map(|v| v.snap.accepted_count)
        .min()
        .unwrap_or(0);
    let max_pending = views
        .iter()
        .map(|v| v.snap.pending_sealed)
        .max()
        .unwrap_or(0);
    vec![
        PromSample {
            name: "meridian_cluster_instances",
            help: "被监控副本数（--wal 个数）。",
            labels: vec![],
            value: views.len() as f64,
        },
        PromSample {
            name: "meridian_cluster_accepted_total",
            help: "副本间 accepted_count 最大值（热备副本组同一逻辑账本，取最新推进副本；求和会双计备份副本，TECH_SPEC 6.12）。",
            labels: vec![],
            value: max_acc as f64,
        },
        PromSample {
            name: "meridian_cluster_replica_lag",
            help: "副本间 accepted_count 最大差（备份滞后笔数，0 = 收敛）。",
            labels: vec![],
            value: (max_acc - min_acc) as f64,
        },
        PromSample {
            name: "meridian_cluster_pending_sealed",
            help: "副本间最差结算滞后（max，取最差副本）。",
            labels: vec![],
            value: max_pending as f64,
        },
    ]
}

/// 集群全量 metrics 文本：逐副本既有样本（`instance` label = 副本名）+ 集群 gauge。
pub fn render_cluster_metrics(views: &[ClusterView], rates: &[f64]) -> String {
    assert_eq!(views.len(), rates.len(), "views/rates 必须等长");
    let mut out = String::new();
    for (v, &rate) in views.iter().zip(rates) {
        out.push_str(&render_prometheus_labeled(&v.snap, rate, v.name.clone()));
    }
    for s in cluster_samples(views) {
        out.push_str(&s.render());
    }
    out
}

/// 集群健康：逐副本既有三检查（N > 1 时 detail 前缀 `replica=<名> ` 定位）+
/// 集群级 `replicas_converged`（仅 N > 1）。N = 1 时输出与单实例 `evaluate` 逐字节一致。
pub fn evaluate_cluster(views: &[ClusterView], wal_intents: &[u64]) -> HealthReport {
    assert_eq!(views.len(), wal_intents.len(), "views/wal_intents 必须等长");
    let multi = views.len() > 1;
    let mut report = HealthReport {
        status: "ok",
        checks: Vec::new(),
    };
    for (v, &wi) in views.iter().zip(wal_intents) {
        let r = evaluate(&v.snap, wi);
        report.checks.extend(r.checks.into_iter().map(|mut c| {
            if multi {
                c.detail = format!("replica={} {}", v.name, c.detail);
            }
            c
        }));
    }

    if multi {
        let converged = views.iter().all(|v| {
            v.snap.accepted_count == views[0].snap.accepted_count
                && v.snap.revoked_len == views[0].snap.revoked_len
                && v.snap.revocation_root == views[0].snap.revocation_root
        });
        let max_acc = views
            .iter()
            .map(|v| v.snap.accepted_count)
            .max()
            .unwrap_or(0);
        let min_acc = views
            .iter()
            .map(|v| v.snap.accepted_count)
            .min()
            .unwrap_or(0);
        let lag = max_acc - min_acc;
        let accepted: Vec<String> = views
            .iter()
            .map(|v| format!("{}={}", v.name, v.snap.accepted_count))
            .collect();
        report.checks.push(HealthCheck {
            // 严格收敛（三元组相等 ⇔ lag 0）：fail-closed，无「可调滞后阈值」——异步副本
            // 部署的滞后告警走 `meridian_cluster_replica_lag` gauge（ops.md §5），健康检查
            // 只认完全一致，避免「允许落后 N 笔」把账本分歧常态化。
            name: "replicas_converged",
            ok: converged,
            detail: format!("accepted=[{}] lag={}", accepted.join(","), lag),
        });
    }

    report.status = if report.checks.iter().all(|c| c.ok) {
        "ok"
    } else {
        "degraded"
    };
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::render_prometheus;
    use meridian_aggregator::hist::LatencySnapshot;

    fn snap(instance: &str, accepted: u64) -> HealthSnapshot {
        HealthSnapshot {
            instance_id: instance.into(),
            started_at_unix: 1_700_000_000,
            now: 1_700_000_100,
            accepted_count: accepted,
            rejected_count: 0,
            pending_sealed: 0,
            revoked_len: 0,
            revocation_root: [0; 32],
            wal_len: 4096,
            submit_latency: LatencySnapshot::default(),
            ledger_shards: 8,
            epoch_capacity: 1000,
            epoch_secs: 60,
        }
    }

    /// S-39：单副本集群健康口径 == 单实例 `evaluate`（逐字节一致，加法不动既有行为）；
    /// 带标签渲染退化路径（label = 自身 instance_id）== 既有 `render_prometheus`。
    #[test]
    fn single_replica_matches_standalone() {
        let v = ClusterView {
            name: "primary".into(),
            snap: snap("meridian-123", 42),
        };
        let r = evaluate_cluster(std::slice::from_ref(&v), &[42]);
        let solo = evaluate(&v.snap, 42);
        assert_eq!(r, solo);
        assert_eq!(r.status, "ok");
        // 健康检查无副本前缀（前缀只在 N > 1）。
        assert!(!r.checks.iter().any(|c| c.detail.starts_with("replica=")));

        let labeled = render_prometheus_labeled(&v.snap, 0.5, v.snap.instance_id.clone());
        assert_eq!(labeled, render_prometheus(&v.snap, 0.5));
        // 集群渲染 = 逐副本带标签渲染（label = 副本名）+ 集群 gauge 追加在尾部。
        let m = render_cluster_metrics(std::slice::from_ref(&v), &[0.5]);
        assert!(m.starts_with(&render_prometheus_labeled(&v.snap, 0.5, "primary".into())));
        assert!(m.contains("meridian_cluster_instances 1"));
    }

    #[test]
    fn cluster_gauges_take_max_not_sum() {
        // 热备副本组：两个副本同一逻辑账本（42/41），账本指标 max 而非 sum（83 会双计）。
        let views = vec![
            ClusterView {
                name: "primary".into(),
                snap: snap("a", 42),
            },
            ClusterView {
                name: "standby".into(),
                snap: snap("b", 41),
            },
        ];
        let s = cluster_samples(&views);
        let get = |n: &str| s.iter().find(|x| x.name == n).unwrap().value;
        assert_eq!(get("meridian_cluster_instances"), 2.0);
        assert_eq!(get("meridian_cluster_accepted_total"), 42.0);
        assert_eq!(get("meridian_cluster_replica_lag"), 1.0);
        assert_eq!(get("meridian_cluster_pending_sealed"), 0.0);
        // 集群 gauge 不带 instance label。
        let text = render_cluster_metrics(&views, &[1.0, 0.0]);
        assert!(text.contains("meridian_cluster_instances 2"));
        assert!(!text.contains("meridian_cluster_instances{"));
    }

    #[test]
    fn replica_lag_degrades_cluster() {
        let views = vec![
            ClusterView {
                name: "primary".into(),
                snap: snap("a", 42),
            },
            ClusterView {
                name: "standby".into(),
                snap: snap("b", 40),
            },
        ];
        let r = evaluate_cluster(&views, &[42, 40]);
        assert_eq!(r.status, "degraded");
        let c = r
            .checks
            .iter()
            .find(|c| c.name == "replicas_converged")
            .unwrap();
        assert!(!c.ok);
        assert!(c.detail.contains("lag=2"));
        assert!(c.detail.contains("primary=42"));
        assert!(c.detail.contains("standby=40"));
    }

    #[test]
    fn converged_replicas_stay_ok() {
        let views = vec![
            ClusterView {
                name: "primary".into(),
                snap: snap("a", 42),
            },
            ClusterView {
                name: "standby".into(),
                snap: snap("b", 42),
            },
        ];
        let r = evaluate_cluster(&views, &[42, 42]);
        assert_eq!(r.status, "ok");
        let c = r
            .checks
            .iter()
            .find(|c| c.name == "replicas_converged")
            .unwrap();
        assert!(c.ok);
        assert!(c.detail.contains("lag=0"));
    }

    /// 撤销承诺分歧（同 accepted、根不同）也算不收敛——撤销传播断档的信号。
    #[test]
    fn root_divergence_degrades_cluster() {
        let mut b = snap("b", 42);
        b.revoked_len = 2;
        b.revocation_root = [7u8; 32];
        let views = vec![
            ClusterView {
                name: "primary".into(),
                snap: snap("a", 42),
            },
            ClusterView {
                name: "standby".into(),
                snap: b,
            },
        ];
        let r = evaluate_cluster(&views, &[42, 42]);
        assert_eq!(r.status, "degraded");
        assert!(
            !r.checks
                .iter()
                .find(|c| c.name == "replicas_converged")
                .unwrap()
                .ok
        );
    }

    /// 逐副本检查在多副本模式带 replica 前缀定位（ledger 漂移落在哪个副本）。
    #[test]
    fn per_replica_checks_carry_replica_prefix() {
        let views = vec![
            ClusterView {
                name: "primary".into(),
                snap: snap("a", 42),
            },
            ClusterView {
                name: "standby".into(),
                snap: snap("b", 40),
            },
        ];
        let r = evaluate_cluster(&views, &[42, 39]);
        let drifted = r
            .checks
            .iter()
            .filter(|c| c.name == "ledger_consistent" && !c.ok)
            .count();
        assert_eq!(drifted, 1, "只有 standby 的账本漂移");
        assert!(r
            .checks
            .iter()
            .any(|c| c.name == "ledger_consistent" && c.detail.starts_with("replica=standby ")));
    }

    /// 任一副本 degraded 即整体 degraded（集群视图 fail-closed）。
    #[test]
    fn any_degraded_replica_degrades_cluster() {
        let mut bad = snap("b", 42);
        bad.pending_sealed = 4; // > 阈值 3，epoch_backlog 降级
        let views = vec![
            ClusterView {
                name: "primary".into(),
                snap: snap("a", 42),
            },
            ClusterView {
                name: "standby".into(),
                snap: bad,
            },
        ];
        let r = evaluate_cluster(&views, &[42, 42]);
        assert_eq!(r.status, "degraded");
    }

    #[test]
    fn empty_cluster_is_ok_and_zeroed() {
        let r = evaluate_cluster(&[], &[]);
        assert_eq!(r.status, "ok");
        assert!(cluster_samples(&[]).iter().all(|s| s.value == 0.0));
    }
}
