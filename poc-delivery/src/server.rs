//! 交付端点服务器（模拟"收款方 Agent B 的 endpoint"）。
//!
//! 本地 TLS + HTTP/1.1：prover 用 MPC-TLS 连进来 POST /deliver 交付载荷，
//! 服务器校验、计算交付回执 ack，回 200。ack 即"收到"的加密证据——tlsn 让
//! prover 事后能向 verifier 证明这个 ack 真的是从这个 TLS 端点发出的。

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::certs::Certs;

/// 交付载荷类型：prover 交付的东西（模拟，见 main）。
#[derive(Debug, serde::Serialize)]
pub struct DeliveryAck {
    pub order_id: String,
    pub recipient: String,
    pub payload_hash: String,
    pub delivery_ack: String,
    pub received: bool,
    pub ts: u64,
}

/// 在 127.0.0.1:port 上起交付端点，返回 (server task, 端口)。
pub async fn spawn(certs: &Certs, port: u16) -> Result<(tokio::task::JoinHandle<Result<()>>, u16)> {
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certs.leaf_der.clone()], certs.leaf_key.clone_key())
        .context("tls server config")?;
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let actual = listener.local_addr()?.port();
    let handle = tokio::spawn(async move {
        loop {
            let (tcp, _peer) = listener.accept().await?;
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(t) => t,
                    Err(_) => return, // 握手失败：忽略（可能是探测连接）
                };
                if let Err(e) = serve_connection(tls).await {
                    eprintln!("delivery server: {e:#}");
                }
            });
        }
    });
    Ok((handle, actual))
}

async fn serve_connection(tls: TlsStream<TcpStream>) -> Result<()> {
    let io = TokioIo::new(tls);
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .serve_connection(io, service_fn(deliver))
        .with_upgrades()
        .await
        .context("http serve")
}

/// POST /deliver → 记录载荷、回交付回执。
async fn deliver(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() != Method::POST {
        let mut resp = Response::new(Full::new(Bytes::from("method not allowed")));
        *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        return Ok(resp);
    }

    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    if path != "/deliver" {
        let mut resp = Response::new(Full::new(Bytes::from("not found")));
        *resp.status_mut() = StatusCode::NOT_FOUND;
        return Ok(resp);
    }

    // 收集请求体（交付载荷 JSON）。
    let collected = http_body_util::BodyExt::collect(body).await?;
    let payload: Bytes = collected.to_bytes();
    let body_str = String::from_utf8_lossy(&payload).to_string();

    // 载荷哈希 → 交付回执（"收到"证据）。
    let payload_hash = hex::encode(Sha256::digest(&payload));
    let order_id = parts
        .headers
        .get("x-order-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("UNKNOWN")
        .to_string();
    let recipient = parts
        .headers
        .get("x-recipient")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("UNKNOWN")
        .to_string();

    let ack = DeliveryAck {
        order_id,
        recipient,
        payload_hash,
        delivery_ack: hex::encode(Sha256::digest(b"meridian-delivery-ack")),
        received: true,
        ts: 1_700_000_000,
    };
    let ack_json = serde_json::to_string(&ack).expect("ack serializes");
    let body_len = body_str.len();

    let json = serde_json::json!({
        "ok": true,
        "body_len": body_len,
        "ack": ack_json,
    });
    let mut resp = Response::new(Full::new(Bytes::from(json.to_string())));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        "content-type",
        "application/json".parse().expect("valid header"),
    );
    Ok(resp)
}
