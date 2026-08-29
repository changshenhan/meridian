//! 网关守护进程入口（S-29）：`meridian-gateway <config.json>`。
//!
//! 聚合器内核参数沿用默认（IngestConfig::default）+ WAL 路径来自配置 `wal_path`
//! （缺省 `./gateway.wal`）。生产部署：明文 HTTP，前置反代终结 TLS（§6.7 诚实边界）。

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::proof::FormatVerifier;
use meridian_aggregator::wal::Wal;
use meridian_gateway::{Config, Gateway};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: meridian-gateway <config.json>");
        std::process::exit(2);
    }
    let cfg = Config::from_path(std::path::Path::new(&args[1])).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2);
    });

    // 聚合器内核（FormatVerifier TEMPORARY 口径；真实 ZK verifier 在此替换接入）。
    let wal_path = std::env::var("MERIDIAN_GATEWAY_WAL").unwrap_or_else(|_| "gateway.wal".into());
    let wal = Wal::open(std::path::Path::new(&wal_path), 10_000).expect("open wal");
    let agg = Arc::new(Aggregator::new(
        IngestConfig::default(),
        Box::new(FormatVerifier),
        wal,
    ));

    let listener =
        TcpListener::bind(&cfg.listen).unwrap_or_else(|e| panic!("bind {}: {e}", cfg.listen));
    let tenants = cfg.tenants.len();
    let gw = Arc::new(Gateway::new(agg, &cfg));
    eprintln!(
        "meridian-gateway listening on {} (tenants: {tenants}, max_conn: {})",
        cfg.listen, cfg.max_connections
    );
    meridian_gateway::http::serve(
        gw,
        listener,
        cfg.max_connections,
        Duration::from_millis(cfg.read_timeout_ms),
    )
    .expect("serve loop");
}
