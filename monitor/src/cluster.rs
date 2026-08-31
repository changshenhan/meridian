//! 多实例集群聚合（S-39，TECH_SPEC §6.12 / ops.md §6 挂账项收口）。
//!
//! 口径：N 个 WAL = **同一逻辑账本的热备副本组**（§1 拓扑「WAL 副本/多实例」），不是
//! 独立分片——集群账本指标取 max（最新推进副本），sum 会把备份副本双计。副本间分歧只
//! 报告（degraded + lag gauge），不裁决真值（裁决 = 接管 WAL 人工核对，ops.md §5）。

use mist_aggregator::health::HealthSnapshot;

use crate::health::{evaluate, HealthCheck, HealthReport};
use crate::metrics::{render_prometheus_labeled, PromSample};

/// 副本收敛口径：`replicas_converged` **两腿**（S-72，§6.12.1）——三元组腿要求
/// `(accepted_count, revoked_len, revocation_root)` 严格相等（滞后 0），digest 腿要求
/// `state_digest` 逐字节相等（§6.26 全状态域内容指纹）。三元组是计数与承诺，对「同计数
/// 不同内容」（REG 多注册 / LEDGER 金额 / WINDOW 窗口内容 / INTENT 索引漂移）全盲，
/// digest 是唯一可见信号。无「可调滞后阈值」——异步副本（跨机）部署的滞后告警走
/// `mist_cluster_replica_lag` gauge（ops.md §5），健康检查只认完全一致，避免「允许落后
/// N 笔」把账本分歧常态化（fail-closed）。
///
/// 一次集群聚合的输入：副本名（WAL 文件名 stem，作 `instance` label）+ 其健康快照 +
/// 其 `state_digest`（monitor 在 restore 完成后计算一次：digest 语义定义在静默态
/// §6.26.2，monitor 副本只读不接热路径，digest 是 WAL 的确定性函数，启动后恒定）。
#[derive(Debug, Clone)]
pub struct ClusterView {
    pub name: String,
    pub snap: HealthSnapshot,
    pub state_digest: [u8; 32],
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
            name: "mist_cluster_instances",
            help: "被监控副本数（--wal 个数）。",
            labels: vec![],
            value: views.len() as f64,
        },
        PromSample {
            name: "mist_cluster_accepted_total",
            help: "副本间 accepted_count 最大值（热备副本组同一逻辑账本，取最新推进副本；求和会双计备份副本，TECH_SPEC 6.12）。",
            labels: vec![],
            value: max_acc as f64,
        },
        PromSample {
            name: "mist_cluster_replica_lag",
            help: "副本间 accepted_count 最大差（备份滞后笔数，0 = 收敛）。",
            labels: vec![],
            value: (max_acc - min_acc) as f64,
        },
        PromSample {
            name: "mist_cluster_pending_sealed",
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
        let first = &views[0];
        // 腿 1（S-39 口径不变）：三元组 = 计数与承诺收敛。
        let triple_equal = views.iter().all(|v| {
            v.snap.accepted_count == first.snap.accepted_count
                && v.snap.revoked_len == first.snap.revoked_len
                && v.snap.revocation_root == first.snap.revocation_root
        });
        // 腿 2（S-72，§6.12.1）：digest = 全状态域内容收敛（三元组的盲区在此）。
        let digest_equal = views.iter().all(|v| v.state_digest == first.state_digest);
        let converged = triple_equal && digest_equal;
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
        let mut detail = format!("accepted=[{}] lag={}", accepted.join(","), lag);
        if !converged {
            // 失配腿固定序 + 各副本 digest 前 16 hex：纯滞后（digest 相等）时证明「只是
            // 落后、内容一致」；digest 失配且 lag=0 = 同计数不同内容（内容分叉，比滞后
            // 更严重，ops.md §5 处置表）。收敛时 detail 逐字节保持 S-39 格式（定夺 2）。
            let mut legs: Vec<&str> = Vec::with_capacity(2);
            if !triple_equal {
                legs.push("triple");
            }
            if !digest_equal {
                legs.push("digest");
            }
            let digests: Vec<String> = views
                .iter()
                .map(|v| format!("{}={}", v.name, digest_prefix(&v.state_digest)))
                .collect();
            detail.push_str(&format!(
                " diverged={} digests=[{}]",
                legs.join(","),
                digests.join(",")
            ));
        }
        report.checks.push(HealthCheck {
            // 严格收敛（两腿全等 ⇔ lag 0 且内容一致）：fail-closed，无「可调滞后阈值」
            // ——异步副本部署的滞后告警走 `mist_cluster_replica_lag` gauge（ops.md §5），
            // 健康检查只认完全一致，避免「允许落后 N 笔」把账本分歧常态化。
            name: "replicas_converged",
            ok: converged,
            detail,
        });
    }

    report.status = if report.checks.iter().all(|c| c.ok) {
        "ok"
    } else {
        "degraded"
    };
    report
}

/// digest 前 8 字节的 16 hex（失配诊断前缀，定位到副本用；完整 64 hex 属日志/人工比对
/// 面，不进健康 JSON——§6.12.1 定夺 3）。
fn digest_prefix(d: &[u8; 32]) -> String {
    d[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::render_prometheus;
    use mist_aggregator::hist::LatencySnapshot;

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

    /// 副本视图构造（S-72：digest 腿入参；收敛用例给同值，分歧用例显式给不同值）。
    fn view(replica: &str, instance: &str, accepted: u64, digest: [u8; 32]) -> ClusterView {
        ClusterView {
            name: replica.into(),
            snap: snap(instance, accepted),
            state_digest: digest,
        }
    }

    /// S-39：单副本集群健康口径 == 单实例 `evaluate`（逐字节一致，加法不动既有行为）；
    /// 带标签渲染退化路径（label = 自身 instance_id）== 既有 `render_prometheus`。
    #[test]
    fn single_replica_matches_standalone() {
        let v = view("primary", "mist-123", 42, [0; 32]);
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
        assert!(m.contains("mist_cluster_instances 1"));
    }

    #[test]
    fn cluster_gauges_take_max_not_sum() {
        // 热备副本组：两个副本同一逻辑账本（42/41），账本指标 max 而非 sum（83 会双计）。
        let views = vec![
            view("primary", "a", 42, [0; 32]),
            view("standby", "b", 41, [0; 32]),
        ];
        let s = cluster_samples(&views);
        let get = |n: &str| s.iter().find(|x| x.name == n).unwrap().value;
        assert_eq!(get("mist_cluster_instances"), 2.0);
        assert_eq!(get("mist_cluster_accepted_total"), 42.0);
        assert_eq!(get("mist_cluster_replica_lag"), 1.0);
        assert_eq!(get("mist_cluster_pending_sealed"), 0.0);
        // 集群 gauge 不带 instance label。
        let text = render_cluster_metrics(&views, &[1.0, 0.0]);
        assert!(text.contains("mist_cluster_instances 2"));
        assert!(!text.contains("mist_cluster_instances{"));
    }

    #[test]
    fn replica_lag_degrades_cluster() {
        // digest 相等 + 三元组失配 = 纯滞后：detail 标 triple 腿，digests 列表证明内容一致。
        let views = vec![
            view("primary", "a", 42, [0x11; 32]),
            view("standby", "b", 40, [0x11; 32]),
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
        assert!(c.detail.contains("diverged=triple"), "{:?}", c.detail);
        assert!(!c.detail.contains("diverged=triple,digest"));
        assert!(c
            .detail
            .contains("digests=[primary=1111111111111111,standby=1111111111111111]"));
    }

    #[test]
    fn converged_replicas_stay_ok() {
        let views = vec![
            view("primary", "a", 42, [0x22; 32]),
            view("standby", "b", 42, [0x22; 32]),
        ];
        let r = evaluate_cluster(&views, &[42, 42]);
        assert_eq!(r.status, "ok");
        let c = r
            .checks
            .iter()
            .find(|c| c.name == "replicas_converged")
            .unwrap();
        assert!(c.ok);
        // S-72 定夺 2：收敛 detail 逐字节保持 S-39 格式（无 diverged=/digests= 字段）。
        assert_eq!(c.detail, "accepted=[primary=42,standby=42] lag=0");
    }

    /// S-72 缺口本体（§6.12.1）：三元组全等但 digest 失配 =「同计数不同内容」——
    /// S-39 三元组腿对此全盲（REG 多注册 / LEDGER 金额 / WINDOW 窗口内容），digest
    /// 腿是唯一可见信号，detail 只标 digest 腿（lag=0 排除滞后解释）。
    #[test]
    fn digest_leg_catches_same_count_different_content() {
        let views = vec![
            view("primary", "a", 42, [0xAA; 32]),
            view("standby", "b", 42, [0xBB; 32]),
        ];
        let r = evaluate_cluster(&views, &[42, 42]);
        assert_eq!(r.status, "degraded");
        let c = r
            .checks
            .iter()
            .find(|c| c.name == "replicas_converged")
            .unwrap();
        assert!(!c.ok);
        assert!(c.detail.contains("lag=0"), "{:?}", c.detail);
        assert!(c.detail.contains("diverged=digest"), "{:?}", c.detail);
        assert!(!c.detail.contains("triple"), "{:?}", c.detail);
        assert!(c
            .detail
            .contains("digests=[primary=aaaaaaaaaaaaaaaa,standby=bbbbbbbbbbbbbbbb]"));
    }

    /// 两腿同时失配：腿列表固定序 triple,digest（定夺 3）。
    #[test]
    fn both_legs_divergence_lists_both_in_fixed_order() {
        let views = vec![
            view("primary", "a", 42, [0x01; 32]),
            view("standby", "b", 40, [0x02; 32]),
        ];
        let r = evaluate_cluster(&views, &[42, 40]);
        assert_eq!(r.status, "degraded");
        let c = r
            .checks
            .iter()
            .find(|c| c.name == "replicas_converged")
            .unwrap();
        assert!(
            c.detail.contains("diverged=triple,digest"),
            "{:?}",
            c.detail
        );
    }

    /// 撤销承诺分歧（同 accepted、根不同）也算不收敛——撤销传播断档的信号。
    #[test]
    fn root_divergence_degrades_cluster() {
        let mut b = snap("b", 42);
        b.revoked_len = 2;
        b.revocation_root = [7u8; 32];
        let views = vec![
            view("primary", "a", 42, [0x33; 32]),
            ClusterView {
                name: "standby".into(),
                snap: b,
                state_digest: [0x33; 32],
            },
        ];
        let r = evaluate_cluster(&views, &[42, 42]);
        assert_eq!(r.status, "degraded");
        let c = r
            .checks
            .iter()
            .find(|c| c.name == "replicas_converged")
            .unwrap();
        assert!(!c.ok);
        // digest 相等（内容一致）但撤销承诺分歧 = triple 腿失配。
        assert!(c.detail.contains("diverged=triple"), "{:?}", c.detail);
    }

    /// 逐副本检查在多副本模式带 replica 前缀定位（ledger 漂移落在哪个副本）。
    #[test]
    fn per_replica_checks_carry_replica_prefix() {
        let views = vec![
            view("primary", "a", 42, [0; 32]),
            view("standby", "b", 40, [0; 32]),
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
            view("primary", "a", 42, [0; 32]),
            ClusterView {
                name: "standby".into(),
                snap: bad,
                state_digest: [0; 32],
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
