//! 网关守护进程入口（S-29）：`meridian-gateway <config.json>`。
//!
//! 聚合器内核参数沿用默认（IngestConfig::default；bb 验证后端时撤销根绑定闸同步
//! 开启，S-48 装配面配对闸）+ WAL 路径来自配置 `wal_path`
//! （缺省 `./gateway.wal`）。生产部署：明文 HTTP，前置反代终结 TLS（§6.7 诚实边界）。

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use meridian_aggregator::bb::BbVerifier;
use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::proof::FormatVerifier;
use meridian_aggregator::wal::Wal;
use meridian_core::zk::SpendVerifier;
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

    // 聚合器内核：验证后端由 `MERIDIAN_VERIFY_BACKEND` 选择（S-40，TECH_SPEC §6.13）——
    // 缺省 `format`（FormatVerifier TEMPORARY 口径，生产默认不变）；`bb` 走真 ZK 验证
    // （BbVerifier，需 `MERIDIAN_BB_VK` + 可得的 bb 工具链；构造失败启动即退 fail-closed）。
    let verifier: Box<dyn SpendVerifier + Send + Sync> = match std::env::var(
        "MERIDIAN_VERIFY_BACKEND",
    )
    .as_deref()
    {
        Ok("bb") => match BbVerifier::from_env() {
            Ok(v) => {
                eprintln!(
                    "verify backend: bb (TECH_SPEC §6.13)——PlaceholderProver 占位 proof 会被全拒"
                );
                Box::new(v)
            }
            Err(e) => {
                eprintln!(
                        "MERIDIAN_VERIFY_BACKEND=bb 但后端不可得（{e}）：需 MERIDIAN_BB_VK + nargo/bb 工具链（Windows 原生或 WSL2 兜底）"
                    );
                std::process::exit(2);
            }
        },
        _ => Box::new(FormatVerifier),
    };
    // 装配面配对闸（S-48）：bb 模式的证明公共输入 `revocation_root` 有密码学语义，
    // 撤销根绑定闸（§6.2，S-44）必须同步开启——S-40 起漏配至此（缺省配置闸关闭，
    // 装饰性 ZK 在装配面复活）。聚合器构造期按
    // `SpendVerifier::requires_revocation_root_binding` 复查，漏配启动即 panic。
    let mut ingest_cfg = IngestConfig::default();
    if verifier.requires_revocation_root_binding() {
        ingest_cfg.enforce_revocation_root = true;
    }
    let wal_path = std::env::var("MERIDIAN_GATEWAY_WAL").unwrap_or_else(|_| "gateway.wal".into());
    let wal = Wal::open(std::path::Path::new(&wal_path), 10_000).expect("open wal");
    let agg = Arc::new(Aggregator::new(ingest_cfg, verifier, wal));

    let listener =
        TcpListener::bind(&cfg.listen).unwrap_or_else(|e| panic!("bind {}: {e}", cfg.listen));
    let tenants = cfg.tenants.len();
    let admin = if cfg.admin_key.is_some() { "on" } else { "off" };
    let peers = cfg.revocation_peers.len();
    // S-59：对端 url 配置期 fail-fast（坏 url 只会变成撤销时的必败 fanout）。
    for peer in &cfg.revocation_peers {
        if let Err(e) = peer.parse_url() {
            panic!("bad revocation peer: {e}");
        }
    }
    let gw = Arc::new(Gateway::new(agg, &cfg));
    eprintln!(
        "meridian-gateway listening on {} (tenants: {tenants}, max_conn: {}, admin: {admin}, revocation_peers: {peers})",
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
