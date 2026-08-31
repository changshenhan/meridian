//! 网关守护进程入口（S-29）：`mist-gateway <config.json>`。
//!
//! 聚合器内核参数沿用默认（IngestConfig::default；bb 验证后端时撤销根绑定闸同步
//! 开启，S-48 装配面配对闸）+ WAL 路径来自配置 `wal_path`
//! （缺省 `./gateway.wal`）。运营者绑定闸（S-62，§6.19.3）：`MIST_RPC_URL` +
//! `MIST_DSA_ADDRESS` + `MIST_SELF_OPERATOR` 三者同给同不给（半装配启动即退）。
//! 生产部署：明文 HTTP，前置反代终结 TLS（§6.7 诚实边界）。

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use mist_aggregator::bb::BbVerifier;
use mist_aggregator::ingest::{Aggregator, IngestConfig};
use mist_aggregator::proof::FormatVerifier;
use mist_aggregator::wal::Wal;
use mist_core::zk::SpendVerifier;
use mist_gateway::{Config, Gateway};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: mist-gateway <config.json>");
        std::process::exit(2);
    }
    let cfg = Config::from_path(std::path::Path::new(&args[1])).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2);
    });

    // 聚合器内核：验证后端由 `MIST_VERIFY_BACKEND` 选择（S-40，TECH_SPEC §6.13）——
    // 缺省 `format`（FormatVerifier TEMPORARY 口径，生产默认不变）；`bb` 走真 ZK 验证
    // （BbVerifier，需 `MIST_BB_VK` + 可得的 bb 工具链；构造失败启动即退 fail-closed）。
    let verifier: Box<dyn SpendVerifier + Send + Sync> = match std::env::var("MIST_VERIFY_BACKEND")
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
                        "MIST_VERIFY_BACKEND=bb 但后端不可得（{e}）：需 MIST_BB_VK + nargo/bb 工具链（Windows 原生或 WSL2 兜底）"
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
    let wal_path = std::env::var("MIST_GATEWAY_WAL").unwrap_or_else(|_| "gateway.wal".into());
    let wal = Wal::open(std::path::Path::new(&wal_path), 10_000).expect("open wal");
    let mut agg = Aggregator::new(ingest_cfg, verifier, wal);

    // 运营者绑定闸（S-62，§6.19.3，Phase 2 P2-2）：三环境变量同给同不给——半装配
    // （只给其一）启动即退 fail-fast，绝不落「闸语义不明」的静默态。未配置 = 无闸
    // （缺省口径逐字节不变，单运营者形态）。
    let binding_state = mist_gateway::binding::parse_binding_env(
        std::env::var("MIST_RPC_URL").ok(),
        std::env::var("MIST_DSA_ADDRESS").ok(),
        std::env::var("MIST_SELF_OPERATOR").ok(),
    )
    .unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2);
    });
    let binding_on = if let Some((source, self_operator)) = binding_state {
        agg = agg.with_operator_binding(source, self_operator);
        true
    } else {
        false
    };
    let agg = Arc::new(agg);

    // 撤销观察面（S-67，TECH_SPEC §6.24，决策 F）：配置 `revocation_watch` 节后起
    // 旁路线程刮链上 `Revoked` 事件自动落本账本。配置期 fail-fast（坏 url / 坏地址 /
    // 零间隔启动即退——静默接受只会变成运行时必败的观察面）；轮询失败 fail-visible
    // 重试（stderr 一行），绝不退进程——观察面挂掉不阻网关服务（admin API / fanout
    // 撤销路径仍可达）。不配置 = 不观察（缺省口径逐字节不变）。
    if let Some(watch_conf) = &cfg.revocation_watch {
        let watch = mist_gateway::watch::RevocationWatch::new(
            &watch_conf.rpc_url,
            &watch_conf.registry_address,
            watch_conf.poll_interval_ms,
        )
        .unwrap_or_else(|e| panic!("bad revocation_watch config: {e}"));
        let interval = watch.interval();
        let watch_agg = Arc::clone(&agg);
        std::thread::Builder::new()
            .name("revocation-watch".into())
            .spawn(move || loop {
                match watch.poll_once(&watch_agg) {
                    Ok(s) => {
                        // 静默轮询（seen=0 fresh=0 skipped=0）不刷屏；有事件或有脏
                        // 日志才打一行。
                        if s.fresh > 0 || s.skipped > 0 {
                            eprintln!(
                                "revocation watch: seen {} fresh {} skipped {}",
                                s.seen, s.fresh, s.skipped
                            );
                        }
                    }
                    // fail-visible：每轮失败一行 + 下一轮重试（定夺 5）。
                    Err(e) => eprintln!("revocation watch: poll failed: {e}"),
                }
                std::thread::sleep(interval);
            })
            .expect("spawn revocation watch thread");
    }

    let listener =
        TcpListener::bind(&cfg.listen).unwrap_or_else(|e| panic!("bind {}: {e}", cfg.listen));
    let tenants = cfg.tenants.len();
    let admin = if cfg.admin_key.is_some() { "on" } else { "off" };
    let peers = cfg.revocation_peers.len();
    let watch = if cfg.revocation_watch.is_some() {
        "on"
    } else {
        "off"
    };
    // S-59：对端 url 配置期 fail-fast（坏 url 只会变成撤销时的必败 fanout）。
    for peer in &cfg.revocation_peers {
        if let Err(e) = peer.parse_url() {
            panic!("bad revocation peer: {e}");
        }
    }
    let gw = Arc::new(Gateway::new(agg, &cfg));
    eprintln!(
        "mist-gateway listening on {} (tenants: {tenants}, max_conn: {}, admin: {admin}, revocation_peers: {peers}, revocation_watch: {watch}, operator binding: {})",
        cfg.listen,
        cfg.max_connections,
        if binding_on { "on" } else { "off" }
    );
    mist_gateway::http::serve(
        gw,
        listener,
        cfg.max_connections,
        Duration::from_millis(cfg.read_timeout_ms),
    )
    .expect("serve loop");
}
