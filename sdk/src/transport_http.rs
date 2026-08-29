//! HTTP 网络传输（S-29，TECH_SPEC §6.7）：agent 侧接入 [`crate::transport::Transport`]
//! 的 std-only 客户端（TcpStream 手写 HTTP/1.1，不引 tokio——重试语义与本 crate 其余
//! 部分同为同步口径）。
//!
//! 错误映射（§6.7 状态表 → [`SdkError`]）：
//! - 连接失败 → `Transport(Disconnected)`；超时 → `Transport(Timeout)`
//! - 429 / 5xx → `Transport(Other)` —— **重试候选**（请求未进内核或内核内部错误，
//!   nonce 固定重发安全）
//! - 200 → 定局：`ReceiptDto::into_receipt`（业务拒绝原样透传 `reject_reason`）
//! - 400 / 401 / 413 → `Local` —— 配置/协议错误，不自动重试

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use meridian_aggregator::receipt::{IntentEnvelope, Receipt};
use meridian_aggregator::wire::{
    AuthorizeRequest, AuthorizeResponse, GatewayError, IntentEnvelopeDto, ReceiptDto,
};
use meridian_core::dsa::{AgentPubKey, SignedDelegation};

use crate::error::{SdkError, TransportError};
use crate::transport::Transport;

/// 网关 HTTP 客户端。
#[derive(Debug, Clone)]
pub struct HttpTransport {
    addr: String,
    bearer: String,
    timeout: Duration,
}

impl HttpTransport {
    /// `addr` 形如 `"127.0.0.1:9400"`；`bearer` 是网关租户表里的 key。
    pub fn new(addr: impl Into<String>, bearer: impl Into<String>) -> Self {
        HttpTransport {
            addr: addr.into(),
            bearer: bearer.into(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 发一次 POST / GET 并读完整响应体（Content-Length 定长读）。
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), TransportError> {
        let stream = TcpStream::connect(&self.addr).map_err(|_| TransportError::Disconnected)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|_| TransportError::Other("set timeout".into()))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|_| TransportError::Other("set timeout".into()))?;
        let mut writer = stream
            .try_clone()
            .map_err(|_| TransportError::Disconnected)?;
        let mut reader = BufReader::new(stream);

        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: meridian\r\nConnection: close\r\nAuthorization: Bearer {}\r\n", self.bearer);
        if let Some(b) = body {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                b.len()
            ));
        }
        req.push_str("\r\n");
        writer
            .write_all(req.as_bytes())
            .map_err(|_| TransportError::Disconnected)?;
        if let Some(b) = body {
            writer
                .write_all(b)
                .map_err(|_| TransportError::Disconnected)?;
        }
        writer.flush().map_err(|_| TransportError::Disconnected)?;

        // 状态行
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|_| TransportError::Disconnected)?;
        let status: u16 = line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or(TransportError::Other("malformed status line".into()))?;

        // 头部（只关心 Content-Length）
        let mut content_length: usize = 0;
        loop {
            let mut h = String::new();
            reader
                .read_line(&mut h)
                .map_err(|_| TransportError::Disconnected)?;
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((name, value)) = h.split_once(':') {
                if name.trim().eq_ignore_ascii_case("content-length") {
                    content_length = value
                        .trim()
                        .parse()
                        .map_err(|_| TransportError::Other("bad content-length".into()))?;
                }
            }
        }
        let mut body = vec![0u8; content_length];
        reader
            .read_exact(&mut body)
            .map_err(|_| TransportError::Disconnected)?;
        Ok((status, body))
    }

    fn map_transport_status(status: u16, body: &[u8]) -> SdkError {
        // 400/401/413 = 配置/协议错误：定局，不重试。其余（429/5xx/未知）= 重试候选。
        match status {
            400 | 401 | 413 => {
                let msg = gateway_error_message(body, status);
                SdkError::Local(msg)
            }
            429 => SdkError::Transport(TransportError::Other(gateway_error_message(body, status))),
            s if s >= 500 => SdkError::Transport(TransportError::Other(format!("gateway {s}"))),
            s => SdkError::Transport(TransportError::Other(format!(
                "unexpected gateway status {s}"
            ))),
        }
    }
}

/// 尽力从 GatewayError JSON 提取 message；解析失败退回状态码描述。
fn gateway_error_message(body: &[u8], status: u16) -> String {
    serde_json::from_slice::<GatewayError>(body)
        .map(|e| format!("{}: {}", e.error.code, e.error.message))
        .unwrap_or_else(|_| format!("gateway rejected with status {status}"))
}

impl Transport for HttpTransport {
    fn authorize(&self, sd: SignedDelegation, agent_pub: AgentPubKey) -> Result<(), SdkError> {
        let req = AuthorizeRequest {
            signed_delegation: sd,
            agent_pub: hex::encode(agent_pub.to_bytes()),
        };
        let body = serde_json::to_vec(&req)
            .map_err(|e| SdkError::Local(format!("serialize authorize: {e}")))?;
        let (status, resp) = self
            .request("POST", "/v1/authorize", Some(&body))
            .map_err(SdkError::Transport)?;
        if status != 200 {
            return Err(Self::map_transport_status(status, &resp));
        }
        let _ok: AuthorizeResponse = serde_json::from_slice(&resp)
            .map_err(|e| SdkError::Local(format!("bad authorize response: {e}")))?;
        Ok(())
    }

    fn submit(&self, env: &IntentEnvelope) -> Result<Receipt, SdkError> {
        let dto = IntentEnvelopeDto::from_envelope(env);
        let body = serde_json::to_vec(&dto)
            .map_err(|e| SdkError::Local(format!("serialize intent: {e}")))?;
        let (status, resp) = self
            .request("POST", "/v1/intents", Some(&body))
            .map_err(SdkError::Transport)?;
        if status != 200 {
            return Err(Self::map_transport_status(status, &resp));
        }
        let dto: ReceiptDto = serde_json::from_slice(&resp)
            .map_err(|e| SdkError::Local(format!("bad receipt response: {e}")))?;
        dto.into_receipt().map_err(SdkError::Local)
    }
}
