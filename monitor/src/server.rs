//! 只读 HTTP 服务：`/healthz`（JSON，200/503）+ `/metrics`（Prometheus 文本）。
//!
//! std-only（`TcpListener` 手写 HTTP/1.1 极简响应）。单线程串行 accept——监控端点本来
//! 就是低频刮取（Prometheus 默认 15s 间隔），不为此引 async 运行时。真实部署如需高并发/
//! 长连接再换 hyper/axum，`Reporter` trait 接口不变。

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::time::Duration;

use crate::health::HealthReport;
use serde_json::json;

/// 一次刮取周期的完整响应数据（由 `Reporter` 现场计算）。
pub struct Report {
    pub health: HealthReport,
    pub metrics: String,
}

/// 数据源抽象：HTTP 层不关心数据从哪来（本机聚合器实例 / 远端代理）。
pub trait Reporter {
    fn report(&self) -> Report;
}

/// 阻塞服务：绑定 `addr`，逐连接处理 `/healthz`、`/metrics`，其余 404。
pub fn serve(addr: &str, reporter: impl Reporter + Send + Sync + 'static) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    eprintln!("meridian-monitor: http://{addr}  (/metrics /healthz)");
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        // 请求头很小；读超时防恶意慢连接占线程。
        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..n]);

        let report = reporter.report();
        let (status, content_type, body) = route(&request, &report);
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.shutdown(Shutdown::Both);
    }
    Ok(())
}

fn route(request: &str, report: &Report) -> (&'static str, &'static str, String) {
    if request.starts_with("GET /healthz") {
        // 健康检查可读性优先：展开成 { status, checks: [{name, ok, detail}] }。
        let body = serde_json::to_string(&report.health).unwrap_or_else(|_| {
            json!({"status": "degraded", "error": "serialize failed"}).to_string()
        });
        let status = if report.health.is_ok() {
            "200 OK"
        } else {
            "503 Service Unavailable"
        };
        (status, "application/json", body)
    } else if request.starts_with("GET /metrics") {
        (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            report.metrics.clone(),
        )
    } else {
        ("404 Not Found", "text/plain", "not found\n".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::evaluate;
    use meridian_aggregator::health::HealthSnapshot;

    fn ok_report() -> Report {
        let s = HealthSnapshot {
            instance_id: "t".into(),
            started_at_unix: 1_700_000_000,
            now: 1_700_000_100,
            accepted_count: 42,
            rejected_count: 0,
            pending_sealed: 0,
            revoked_len: 0,
            revocation_root: [0; 32],
            wal_len: 4096,
            ledger_shards: 8,
            epoch_capacity: 1000,
            epoch_secs: 60,
        };
        Report {
            health: evaluate(&s, 42),
            metrics: "meridian_accepted_total 42\n".to_string(),
        }
    }

    #[test]
    fn routes_healthz_ok() {
        let (status, ct, body) = route("GET /healthz HTTP/1.1", &ok_report());
        assert_eq!(status, "200 OK");
        assert_eq!(ct, "application/json");
        assert!(body.contains("\"status\":\"ok\""));
        assert!(body.contains("ledger_consistent"));
    }

    #[test]
    fn routes_healthz_degraded_503() {
        let mut r = ok_report();
        r.health.status = "degraded";
        let (status, _, _) = route("GET /healthz HTTP/1.1", &r);
        assert_eq!(status, "503 Service Unavailable");
    }

    #[test]
    fn routes_metrics() {
        let (status, ct, body) = route("GET /metrics HTTP/1.1", &ok_report());
        assert_eq!(status, "200 OK");
        assert!(ct.contains("text/plain"));
        assert_eq!(body, "meridian_accepted_total 42\n");
    }

    #[test]
    fn routes_unknown_404() {
        let (status, _, _) = route("GET /favicon.ico HTTP/1.1", &ok_report());
        assert_eq!(status, "404 Not Found");
    }
}
