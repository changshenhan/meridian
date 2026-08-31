//! 交付证明核心：TLSNotary 2-party MPC-TLS。
//!
//! 场景：Agent A（prover）把交付载荷 POST 到收款方 B 的 TLS 端点；第三方
//! （verifier / 仲裁方）与 A 共同跑 MPC-TLS，**在线见证**这笔 TLS 交付，并拿到
//! 一段经选择性披露的 transcript：
//!   - 披露：请求方法/路径/订单号/载荷哈希 + 服务器的交付回执 ack。
//!   - 隐藏：交付令牌（secret）——A 证明"东西真到了"而不泄露密钥。
//!
//! 这是蓝图 L4 交付证明的 Phase 0 形态（2-party 在线见证）。生产形态是
//! 3-party attestation（notary 签名 → 离线可验证，S-18 起），概念同源。

use std::future::IntoFuture;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use http_body_util::Full;
use hyper::{Request, StatusCode, Uri, body::Bytes};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tlsn::{
    Session,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::ServerName,
    transcript::PartialTranscript,
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
};

use crate::certs::{Certs, DELIVERY_DOMAIN};

/// 交付令牌（secret）：prover 知道、对 verifier 隐藏。
pub const DELIVERY_TOKEN: &str = "mist-delivery-token-2f3c9a";

/// 交付载荷 JSON（reveal 给 verifier）。
pub const DELIVERY_BODY: &str = r#"{"order_id":"ORD-001","payload_hash":"c0ffee","recipient":"did:agent:b","ts":1700000000}"#;

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;

/// 一次完整交付证明的运行结果。
#[derive(Debug)]
pub struct DeliveryReceipt {
    pub server_name: String,
    /// verifier 实际看到的发送字节（隐藏部分为 `\0`）。
    pub sent_revealed: String,
    /// verifier 实际看到的接收字节（含服务器 ack）。
    pub received_revealed: String,
}

/// 跑完整交付证明：起 duplex，prover 交付 + verifier 验证，返回见证结果。
pub async fn run_delivery_proof(certs: &Certs, server_addr: SocketAddr) -> Result<DeliveryReceipt> {
    let uri = format!("https://{DELIVERY_DOMAIN}:{}/deliver", server_addr.port());

    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);
    let prover = prover(prover_socket, &server_addr, &uri, certs);
    let verifier = verifier(verifier_socket, certs);
    let (_, (server_name, transcript)) =
        tokio::try_join!(prover, verifier).context("mpc-tls run")?;

    let sent = String::from_utf8(transcript.sent_unsafe().to_vec())
        .context("sent transcript not utf8")?;
    let received = String::from_utf8(transcript.received_unsafe().to_vec())
        .context("received transcript not utf8")?;

    // 见证断言（PoC 验收）：
    // 1. 发送侧含交付端点与订单号（东西真发出去了）。请求行是绝对形式
    //    （`POST https://…/deliver`），故分开断 POST 与路径。
    // 2. 令牌已被隐藏（不在 sent_revealed 里）。
    // 3. 接收侧含服务器 200 与 ack（服务器真回了）。
    assert!(
        sent.contains("POST ") && sent.contains("/deliver") && sent.contains("ORD-001"),
        "sent data must show the delivery request"
    );
    assert!(
        !sent.contains(DELIVERY_TOKEN),
        "delivery token must stay hidden from the verifier"
    );
    assert!(
        received.contains("200 OK") && received.contains("delivery_ack"),
        "received data must show the server ack"
    );

    Ok(DeliveryReceipt {
        server_name,
        sent_revealed: sent,
        received_revealed: received,
    })
}

#[allow(clippy::too_many_lines)]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    server_addr: &SocketAddr,
    uri: &str,
    certs: &Certs,
) -> Result<()> {
    let uri = uri.parse::<Uri>()?;
    let server_domain = uri.authority().context("uri authority")?.host().to_string();

    // 与 verifier 建 2-party session。
    let session = Session::new(verifier_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        )
        .await?;

    // 直连交付端点（普通 TCP；TLS 由 MPC 联合模拟）。
    let client_socket = tokio::net::TcpStream::connect(server_addr).await?;
    client_socket.set_nodelay(true)?;

    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(DELIVERY_DOMAIN.try_into()?))
            .root_store(RootCertStore {
                roots: vec![CertificateDer(certs.ca_der.as_ref().to_vec())],
            })
            .build()?,
        client_socket.compat(),
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    // 交付 POST：订单号 / 收款方在头，载荷在体，令牌在 secret 头。
    let body = Full::<Bytes>::from(DELIVERY_BODY.as_bytes().to_vec());
    let request = Request::builder()
        .method("POST")
        .uri(uri.clone())
        .header("Host", server_domain)
        .header("Connection", "close")
        .header("X-Order-Id", "ORD-001")
        .header("X-Recipient", "did:agent:b")
        .header("X-Delivery-Token", DELIVERY_TOKEN)
        .body(body)?;
    let response = request_sender.send_request(request).await?;
    assert!(
        response.status() == StatusCode::OK,
        "delivery endpoint must ack"
    );

    let mut prover = prover_task.await??;

    // 构造证明：披露 server 身份 + 全部发送数据（令牌除外）+ 全部接收数据。
    let mut builder = ProveConfig::builder(prover.transcript());
    builder.server_identity();

    let sent = prover.transcript().sent();
    let pos = sent
        .windows(DELIVERY_TOKEN.len())
        .position(|w| w == DELIVERY_TOKEN.as_bytes())
        .expect("delivery token must be in sent data");
    if pos > 0 {
        builder.reveal_sent(&(0..pos))?;
    }
    builder.reveal_sent(&(pos + DELIVERY_TOKEN.len()..sent.len()))?;

    let recv_len = prover.transcript().received().len();
    builder.reveal_recv(&(0..recv_len))?;

    let config = builder.build()?;
    prover.prove(&config).await?;
    prover.close().await?;

    handle.close();
    driver_task.await??;
    Ok(())
}

/// 返回（已核验的 server name, 选择性披露的 transcript）。
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
    certs: &Certs,
) -> Result<(String, PartialTranscript)> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(certs.ca_der.as_ref().to_vec())],
        })
        .build()?;
    let verifier = handle.new_verifier(verifier_config)?;

    // 校验 prover 提议的协议配置（防超载），然后跑 MPC-TLS。
    let verifier = match verifier.commit().await? {
        VerifierCommitStart::Mpc(verifier) => {
            let cfg = verifier.config();
            let reject = if cfg.max_sent_data() > MAX_SENT_DATA {
                Some("max_sent_data is too large")
            } else if cfg.max_recv_data() > MAX_RECV_DATA {
                Some("max_recv_data is too large")
            } else {
                None
            };
            if let Some(msg) = reject {
                verifier.reject(Some(msg)).await?;
                return Err(anyhow::anyhow!("protocol configuration rejected: {msg}"));
            }
            verifier.accept().await?.run().await?
        }
        VerifierCommitStart::Proxy(verifier) => {
            verifier.reject(Some("expecting MPC-TLS")).await?;
            return Err(anyhow::anyhow!("protocol configuration rejected: expecting MPC-TLS"));
        }
    };

    let verifier = verifier.verify().await?;
    if !verifier.request().server_identity() {
        let verifier = verifier
            .reject(Some("expecting to verify the server name"))
            .await?;
        verifier.close().await?;
        return Err(anyhow::anyhow!("prover did not reveal the server name"));
    }

    let (
        VerifierOutput {
            server_name,
            transcript,
            ..
        },
        verifier,
    ) = verifier.accept().await?;
    verifier.close().await?;

    handle.close();
    driver_task.await??;

    let server_name = server_name.expect("prover should have revealed server name");
    let transcript = transcript.expect("prover should have revealed transcript data");
    let ServerName::Dns(name) = &server_name;
    assert_eq!(name.as_str(), DELIVERY_DOMAIN, "server name must match delivery domain");

    Ok((name.as_str().to_string(), transcript))
}
