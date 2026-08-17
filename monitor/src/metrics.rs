//! Prometheus 文本格式导出（精确按 exposition spec v0.0.4，手写，零依赖）。
//!
//! 每条 metric：`# HELP` + `# TYPE` + 样本行 `name{label="v"} value`。全部用 gauge
//! （计数语义由刮取器按增量处理，见 crate 文档——诚实：不加 counter 语义误导）。

use meridian_aggregator::health::HealthSnapshot;

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
    let info_label = s.instance_id.clone();
    let mut out = String::new();
    for sample in samples(s, ingest_rate, info_label) {
        out.push_str(&sample.render());
    }
    out
}

/// 从快照派生样本集（测试友好：直接断言样本）。
pub fn samples(s: &HealthSnapshot, ingest_rate: f64, instance: String) -> Vec<PromSample> {
    vec![
        PromSample {
            name: "meridian_accepted_total",
            help: "累计接受意图数（== 下一个待分配 seq）。",
            labels: vec![("instance", instance.clone())],
            value: s.accepted_count as f64,
        },
        PromSample {
            name: "meridian_rejected_total",
            help: "本次会话拒绝数（不持久化；崩溃恢复后从 0 起）。",
            labels: vec![("instance", instance.clone())],
            value: s.rejected_count as f64,
        },
        PromSample {
            name: "meridian_pending_sealed",
            help: "已密封未消费 epoch 数（结算滞后信号，见告警阈值）。",
            labels: vec![("instance", instance.clone())],
            value: s.pending_sealed as f64,
        },
        PromSample {
            name: "meridian_revoked_total",
            help: "已撤销委托数。",
            labels: vec![("instance", instance.clone())],
            value: s.revoked_len as f64,
        },
        PromSample {
            name: "meridian_wal_bytes",
            help: "WAL 文件字节数（崩溃恢复边界可见性）。",
            labels: vec![("instance", instance.clone())],
            value: s.wal_len as f64,
        },
        PromSample {
            name: "meridian_uptime_seconds",
            help: "本实例运行时长（秒）。",
            labels: vec![("instance", instance.clone())],
            value: s.uptime_secs() as f64,
        },
        PromSample {
            name: "meridian_ingest_rate_last_window",
            help: "最近一次刮取间隔的平均接受速率（笔/s；刮取窗口内增量/时长）。",
            labels: vec![("instance", instance.clone())],
            value: ingest_rate,
        },
        PromSample {
            name: "meridian_epoch_capacity",
            help: "epoch 容量（配置）。",
            labels: vec![("instance", instance.clone())],
            value: s.epoch_capacity as f64,
        },
        PromSample {
            name: "meridian_ledger_shards",
            help: "账本分片数（配置）。",
            labels: vec![("instance", instance.clone())],
            value: s.ledger_shards as f64,
        },
        PromSample {
            name: "meridian_instance_info",
            help: "实例标识（值恒 1，取 label instance）。",
            labels: vec![("instance", instance)],
            value: 1.0,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap() -> HealthSnapshot {
        HealthSnapshot {
            instance_id: "meridian-123".into(),
            started_at_unix: 1_700_000_000,
            now: 1_700_000_100,
            accepted_count: 42,
            rejected_count: 7,
            pending_sealed: 1,
            revoked_len: 0,
            revocation_root: [0; 32],
            wal_len: 4096,
            ledger_shards: 8,
            epoch_capacity: 1000,
            epoch_secs: 60,
        }
    }

    #[test]
    fn renders_valid_prometheus_text() {
        let text = render_prometheus(&snap(), 0.5);
        assert!(text.contains("# TYPE meridian_accepted_total gauge"));
        assert!(text.contains("meridian_accepted_total{instance=\"meridian-123\"} 42"));
        assert!(text.contains("meridian_uptime_seconds{instance=\"meridian-123\"} 100"));
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
}
