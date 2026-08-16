//! PoC ③ 交付证明（TLSNotary）可执行入口。
//!
//! 跑一次完整见证：
//!   1. 现场生成 CA + 叶证书；
//!   2. 起本地交付端点（收款方 Agent B 的 TLS endpoint，POST /deliver → ack）；
//!   3. prover（Agent A）与 verifier（仲裁方）通过 2-party MPC-TLS 在线见证
//!      这笔交付：verifier 拿到选择性披露的 transcript —— 看到"订单号 + 载荷
//!      + 服务器 ack"，看不到交付令牌；
//!   4. 断言三件事（见 proof::run_delivery_proof），打印见证结果。
//!
//! 复现：`cargo run --release`（首次编译拉 tlsn/mpz 框架，较久）。

use std::net::SocketAddr;

use meridian_poc_delivery::certs;
use meridian_poc_delivery::proof::{run_delivery_proof, DELIVERY_BODY, DELIVERY_TOKEN};
use meridian_poc_delivery::server;

fn main() -> anyhow::Result<()> {
    // 依赖图里 rustls 同时启了 aws-lc-rs（tlsn）与 ring，显式选 aws-lc-rs 作默认
    // CryptoProvider，避免进程级自动判定 panic。
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install default CryptoProvider");

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    rt.block_on(run())
}

async fn run() -> anyhow::Result<()> {
    let certs = certs::generate()?;
    let (_server, port) = server::spawn(&certs, 0).await?;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;

    println!("=== Meridian PoC ③ 交付证明（TLSNotary 2-party MPC-TLS）===\n");
    println!("交付端点  : https://{}/deliver", certs::DELIVERY_DOMAIN);
    println!("交付令牌  : {DELIVERY_TOKEN}（对 verifier 隐藏）");
    println!("交付载荷  : {DELIVERY_BODY}\n");

    let receipt = run_delivery_proof(&certs, addr).await?;

    println!("【verifier 见证结果】");
    println!("  服务器身份: {}", receipt.server_name);
    println!("\n--- 发送侧 transcript（令牌处已隐藏，`\\0` 占位）---");
    println!("{}", receipt.sent_revealed);
    println!("\n--- 接收侧 transcript（服务器交付回执）---");
    println!("{}", receipt.received_revealed);
    println!("\n--- 断言 ---");
    println!("  [PASS] 发送侧含 POST /deliver 与订单号 ORD-001");
    println!("  [PASS] 交付令牌对 verifier 隐藏（不在披露字节中）");
    println!("  [PASS] 接收侧含 200 OK 与服务器 ack（东西真到了）");
    println!("\n结论: PASS —— 一笔 TLS 交付可被第三方选择性披露地见证。");
    println!(
        "      生产形态（S-18+）为 3-party attestation：notary 为 transcript 签名，\
         证明离线可验证。"
    );
    Ok(())
}
