//! Prometheus 文本格式导出（精确按 exposition spec v0.0.4，手写，零依赖）。
//!
//! 每条 metric：`# HELP` + `# TYPE` + 样本行 `name{label="v"} value`。全部用 gauge
//! （计数语义由刮取器按增量处理，见 crate 文档——诚实：不加 counter 语义误导）。

use mist_aggregator::health::HealthSnapshot;
use mist_aggregator::hist::LatencySnapshot;

/// 单条样本（渲染前构造，便于测试断言）。
#[derive(Debug, Clone, PartialEq)]
pub struct PromSample {
    pub name: &'static str,
    pub help: &'static str,
    pub labels: Vec<(&'static str, String)>,
    pub value: f64,
}

impl PromSample {
    /// 按 exposition spec 渲染一行样本（含 HELP + TYPE 头）。
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# HELP {} {}\n", self.name, self.help));
        out.push_str(&format!("# TYPE {} gauge\n", self.name));
        out.push_str(self.name);
        if !self.labels.is_empty() {
            let labels: Vec<String> = self
                .labels
                .iter()
                .map(|(k, v)| format!("{k}=\"{}\"", escape_label(v)))
                .collect();
            out.push_str(&format!("{{{}}}", labels.join(",")));
        }
        out.push_str(&format!(" {}\n", self.value));
        out
    }
}

fn escape_label(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 刮取窗口平均速率：`delta_accepted` 笔 / `elapsed_secs` 秒。
/// `elapsed_secs <= 0`（同秒双刮取 / 时钟异常）→ 0.0，避免除零与无穷大。
pub fn rate_from_delta(delta_accepted: u64, elapsed_secs: f64) -> f64 {
    if elapsed_secs > 0.0 {
        delta_accepted as f64 / elapsed_secs
    } else {
        0.0
    }
}

/// 把一次健康快照渲染成 Prometheus 文本。
pub fn render_prometheus(s: &HealthSnapshot, ingest_rate: f64) -> String {
    render_prometheus_labeled(s, ingest_rate, s.instance_id.clone())
}

/// 多副本模式（S-39）入口：实例标签由调用方给（WAL 文件名 stem）——快照里的
/// `instance_id` 是 monitor 进程自身 pid（`mist-<pid>`），同一进程恢复 N 个副本
/// 会同值撞序列，无法区分。单副本模式走 `render_prometheus`（行为不变）。
pub fn render_prometheus_labeled(s: &HealthSnapshot, ingest_rate: f64, instance: String) -> String {
    let info_label = instance.clone();
    let mut out = String::new();
    for sample in samples(s, ingest_rate, instance) {
        out.push_str(&sample.render());
    }
    out.push_str(&render_submit_duration(&s.submit_latency, &info_label));
    out
}

/// 从快照派生样本集（测试友好：直接断言样本）。
pub fn samples(s: &HealthSnapshot, ingest_rate: f64, instance: String) -> Vec<PromSample> {
    vec![
        PromSample {
            name: "mist_accepted_total",
            help: "累计接受意图数（== 下一个待分配 seq）。",
            labels: vec![("instance", instance.clone())],
            value: s.accepted_count as f64,
        },
        PromSample {
            name: "mist_rejected_total",
            help: "本次会话拒绝数（不持久化；崩溃恢复后从 0 起）。",
            labels: vec![("instance", instance.clone())],
            value: s.rejected_count as f64,
        },
        PromSample {
            name: "mist_pending_sealed",
            help: "已密封未消费 epoch 数（结算滞后信号，见告警阈值）。",
            labels: vec![("instance", instance.clone())],
            value: s.pending_sealed as f64,
        },
        PromSample {
            name: "mist_revoked_total",
            help: "已撤销委托数。",
            labels: vec![("instance", instance.clone())],
            value: s.revoked_len as f64,
        },
        PromSample {
            name: "mist_wal_bytes",
            help: "WAL 文件字节数（崩溃恢复边界可见性）。",
            labels: vec![("instance", instance.clone())],
            value: s.wal_len as f64,
        },
        PromSample {
            name: "mist_uptime_seconds",
            help: "本实例运行时长（秒）。",
            labels: vec![("instance", instance.clone())],
            value: s.uptime_secs() as f64,
        },
        PromSample {
            name: "mist_ingest_rate_last_window",
            help: "最近一次刮取间隔的平均接受速率（笔/s；刮取窗口内增量/时长）。",
            labels: vec![("instance", instance.clone())],
            value: ingest_rate,
        },
        PromSample {
            name: "mist_epoch_capacity",
            help: "epoch 容量（配置）。",
            labels: vec![("instance", instance.clone())],
            value: s.epoch_capacity as f64,
        },
        PromSample {
            name: "mist_ledger_shards",
            help: "账本分片数（配置）。",
            labels: vec![("instance", instance.clone())],
            value: s.ledger_shards as f64,
        },
        PromSample {
            name: "mist_instance_info",
            help: "实例标识（值恒 1，取 label instance）。",
            labels: vec![("instance", instance)],
            value: 1.0,
        },
    ]
}

/// 桶 `i` 的 Prometheus `le` 值（秒）：桶上界 `2^(i+1)` μs = `2^(i+1) / 1e6` s。
/// f64 除法的最短往返表示对 2 的幂 + 1e6 精确还原（如 1048576/1e6 → "1.048576"）。
fn le_label(i: usize) -> String {
    format!("{}", (1u64 << (i + 1)) as f64 / 1e6)
}

/// `submit` 全路径延迟：Prometheus histogram 家族（`le` 累计 + `_sum`/`_count`）+
/// 预计算 p99 gauge（TECH_SPEC §6.11）。
///
/// 口径诚实：p99 是 log2 桶**上界**近似；精确分位数请在 Grafana 对 `_bucket` 跑
/// `histogram_quantile`。会话计数不持久化——实例重启后 `_count` 从 0 重爬
/// （`rate()` 在重启点会失真，用 `histogram_quantile` 的绝对快照口径）。
pub fn render_submit_duration(l: &LatencySnapshot, instance: &str) -> String {
    const BASE: &str = "mist_submit_duration_seconds";
    let mut out = String::new();
    out.push_str(&format!(
        "# HELP {BASE} submit 全路径 API 延迟（接受/拒绝/re-ack 一律计时；log2 μs 桶 ×32，TECH_SPEC §6.11）。\n"
    ));
    out.push_str(&format!("# TYPE {BASE} histogram\n"));
    let mut cum = 0u64;
    for (i, &b) in l.buckets.iter().enumerate() {
        cum += b;
        out.push_str(&format!(
            "{BASE}_bucket{{instance=\"{}\",le=\"{}\"}} {cum}\n",
            escape_label(instance),
            le_label(i)
        ));
    }
    out.push_str(&format!(
        "{BASE}_bucket{{instance=\"{}\",le=\"+Inf\"}} {}\n",
        escape_label(instance),
        l.count
    ));
    out.push_str(&format!(
        "{BASE}_sum{{instance=\"{}\"}} {}\n",
        escape_label(instance),
        l.sum_us as f64 / 1e6
    ));
    out.push_str(&format!(
        "{BASE}_count{{instance=\"{}\"}} {}\n",
        escape_label(instance),
        l.count
    ));
    // 预计算 p99（Grafana 直用；μs → 秒）。
    let p99_name = "mist_submit_duration_p99_seconds";
    out.push_str(&format!(
        "# HELP {p99_name} submit 延迟 p99（log2 桶上界近似；精确分位数用 _bucket 跑 histogram_quantile）。\n"
    ));
    out.push_str(&format!("# TYPE {p99_name} gauge\n"));
    out.push_str(&format!(
        "{p99_name}{{instance=\"{}\"}} {}\n",
        escape_label(instance),
        l.p99_us() as f64 / 1e6
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mist_aggregator::hist::BUCKETS;

    fn snap() -> HealthSnapshot {
        HealthSnapshot {
            instance_id: "mist-123".into(),
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
    fn renders_valid_prometheus_text() {
        let text = render_prometheus(&snap(), 0.5);
        assert!(text.contains("# TYPE mist_accepted_total gauge"));
        assert!(text.contains("mist_accepted_total{instance=\"mist-123\"} 42"));
        assert!(text.contains("mist_uptime_seconds{instance=\"mist-123\"} 100"));
        // 每个样本都有 HELP + TYPE + 值行。
        assert_eq!(
            text.matches("# TYPE").count(),
            text.matches("# HELP").count()
        );
    }

    #[test]
    fn escapes_label_quotes() {
        let s = PromSample {
            name: "x",
            help: "h",
            labels: vec![("instance", "a\"b".to_string())],
            value: 1.0,
        };
        assert!(s.render().contains("instance=\"a\\\"b\""));
    }

    #[test]
    fn rate_from_delta_basic() {
        // 100 笔 / 10 秒 → 10 笔/s。
        assert_eq!(rate_from_delta(100, 10.0), 10.0);
    }

    #[test]
    fn rate_from_delta_zero_or_negative_window() {
        // 同秒双刮取（dt=0）与时钟异常（负）都不除零、不产生无穷。
        assert_eq!(rate_from_delta(100, 0.0), 0.0);
        assert_eq!(rate_from_delta(100, -1.0), 0.0);
    }

    /// S-35：histogram 家族渲染——`le` 累计语义、+Inf == _count、p99 gauge 在场。
    #[test]
    fn renders_submit_duration_histogram() {
        let mut l = LatencySnapshot::default();
        l.buckets[0] = 2; // 亚微秒 + [1,2) μs
        l.buckets[6] = 1; // [64, 128) μs
        l.count = 3;
        l.sum_us = 100;
        let text = render_submit_duration(&l, "mist-123");

        // 家族头：一个 HELP + 一个 TYPE（histogram），不是逐样本 gauge。
        assert_eq!(
            text.matches("# HELP mist_submit_duration_seconds ").count(),
            1
        );
        assert!(text.contains("# TYPE mist_submit_duration_seconds histogram"));
        // le 升序 + 累计：桶 0 → 2，桶 6 累计 → 3。
        assert!(text.contains(
            "mist_submit_duration_seconds_bucket{instance=\"mist-123\",le=\"0.000002\"} 2"
        ));
        assert!(text.contains(
            "mist_submit_duration_seconds_bucket{instance=\"mist-123\",le=\"0.000064\"} 2"
        ));
        assert!(text.contains(
            "mist_submit_duration_seconds_bucket{instance=\"mist-123\",le=\"0.000128\"} 3"
        ));
        assert!(text
            .contains("mist_submit_duration_seconds_bucket{instance=\"mist-123\",le=\"+Inf\"} 3"));
        // 有限 le 桶数 == BUCKETS，累计值单调不减。
        let cum: Vec<u64> = text
            .lines()
            .filter(|x| x.contains("_bucket{") && !x.contains("+Inf"))
            .map(|x| x.rsplit(' ').next().unwrap().parse().unwrap())
            .collect();
        assert_eq!(cum.len(), BUCKETS);
        assert!(cum.windows(2).all(|w| w[0] <= w[1]), "le 累计必须单调不减");
        assert!(text.contains("mist_submit_duration_seconds_sum{instance=\"mist-123\"} 0.0001"));
        assert!(text.contains("mist_submit_duration_seconds_count{instance=\"mist-123\"} 3"));
        // p99：累计 2/3 < 99% → 落桶 6 → 上界 128 μs = 0.000128 s。
        assert!(text.contains("mist_submit_duration_p99_seconds{instance=\"mist-123\"} 0.000128"));
    }

    /// S-35：空直方图渲染不 NaN、p99 = 0；总渲染流含直方图家族。
    #[test]
    fn empty_histogram_renders_zero_p99() {
        let text = render_submit_duration(&LatencySnapshot::default(), "t");
        assert!(text.contains("mist_submit_duration_seconds_count{instance=\"t\"} 0"));
        assert!(text.contains("mist_submit_duration_p99_seconds{instance=\"t\"} 0"));
        assert!(!text.contains("NaN"), "空直方图不得产生 NaN");
        // render_prometheus 集成：gauge 家族 + histogram 家族同流。
        let full = render_prometheus(&snap(), 0.5);
        assert!(full.contains("# TYPE mist_submit_duration_seconds histogram"));
        assert_eq!(
            full.matches("# TYPE mist_submit_duration_seconds histogram")
                .count(),
            1,
            "histogram 家族只导出一次"
        );
    }

    /// le 标签格式抽查：首桶 2 μs、末桶上界 2^32 μs（秒记）。
    #[test]
    fn le_label_format() {
        assert_eq!(le_label(0), "0.000002");
        assert_eq!(le_label(6), "0.000128");
        assert_eq!(le_label(19), "1.048576");
        assert_eq!(le_label(BUCKETS - 1), "4294.967296");
    }
}
