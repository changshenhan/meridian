//! x402 适配层 · 客户端（S-30b，TECH_SPEC §6.8，docs/x402-adapter.md §2.1）。
//!
//! 站位：Meridian 是 **x402 的结算后端**（卖水），不是再造付费协议。本模块 = agent 侧
//! fetch 拦截：资源服务器回 `402` + `paymentRequirements`（scheme `meridian-v1`）→
//! 映射成 [`PayParams`] 走 [`SdkClient::pay`]（幂等重试契约 §6.6 不变）→ 构造
//! `X-PAYMENT`（base64url JSON）重放请求。
//!
//! # 线格式（x402 v1 惯例：camelCase、金额恒字符串、base64url 无 padding）
//!
//! - 402 体消费 `accepts[]` 中 `scheme == "meridian-v1"` 的条目（无则 [`SdkError::Local`]）。
//! - `X-PAYMENT` payload：`{"intentHash", "seq", "spendNonce"}`——merchant 验证 =
//!   网关 `GET /v1/receipts/{intentHash}`（S-30a），信封不内嵌（离线验签是 S-30c 缝）。
//!
//! # 诚实边界（v1）
//!
//! - 内置 [`HttpFetch`] 仅支持明文 `http://`；https 资源须注入 HTTPS 客户端（[`Fetch`] 接缝）。
//! - `category = sha256(host+path)` 是 owner 白名单的粗粒度路由控制，query 不绑定。
//! - `X-PAYMENT-RESPONSE` 结算回执头不消费（epoch 结算语义，facilitator 是 S-30c）。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use meridian_core::dsa::Did;

use crate::error::SdkError;
use crate::pay::PayParams;
use crate::SdkClient;

/// x402 协议版本（v1）。
pub const X402_VERSION: u32 = 1;
/// Meridian 的自定义 scheme（docs/x402-adapter.md §3；上游注册路径未定前使用）。
pub const SCHEME: &str = "meridian-v1";
/// `X-PAYMENT` 头名（x402 HTTP transport 惯例）。
pub const PAYMENT_HEADER: &str = "X-PAYMENT";

// ---------------------------------------------------------------------------
// 402 响应体（消费侧）
// ---------------------------------------------------------------------------

/// 402 响应体（x402 v1：`{x402Version, error?, accepts[], extensions}`）。
///
/// agent 侧消费（Deserialize）、merchant 侧产出（Serialize，S-30c facilitator）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub accepts: Vec<PaymentRequirements>,
}

/// 单条支付要求（camelCase、金额恒字符串——JS BigInt 兼容惯例）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    /// 原子单位字符串（USDC 6 decimals）。
    pub max_amount_required: String,
    /// 付费资源 URL。
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// 收款方 0x EVM 地址（20B）。
    pub pay_to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    /// `exact` scheme 专属：EIP-3009 域参数（S-32，TECH_SPEC §6.10）。
    /// `meridian-v1` 条目不产出该字段（skip），Deserialize 缺省 None——旧 wire 兼容。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Eip3009Extra>,
}

/// EIP-3009 签名域参数（`extra`，x402 `exact` scheme 惯例）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip3009Extra {
    pub name: String,
    pub version: String,
}

impl PaymentRequirements {
    /// `maxAmountRequired` 字符串 → 原子单位 u64。
    pub fn amount(&self) -> Result<u64, SdkError> {
        self.max_amount_required
            .parse::<u64>()
            .map_err(|e| SdkError::Local(format!("bad maxAmountRequired: {e}")))
    }

    /// `payTo` 0x hex → 20B 收款地址。
    pub fn recipient(&self) -> Result<Did, SdkError> {
        let raw = self.pay_to.strip_prefix("0x").unwrap_or(&self.pay_to);
        let bytes = hex::decode(raw).map_err(|e| SdkError::Local(format!("bad payTo hex: {e}")))?;
        let arr: [u8; 20] = bytes.try_into().map_err(|v: Vec<u8>| {
            SdkError::Local(format!("payTo must be 20 bytes, got {}", v.len()))
        })?;
        Ok(arr)
    }
}

// ---------------------------------------------------------------------------
// X-PAYMENT 载荷（产出侧）
// ---------------------------------------------------------------------------

/// merchant 验证载荷：网关 `GET /v1/receipts/{intentHash}`（S-30a）所需的最小集合。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeridianPayload {
    /// 0x 32B hex——merchant 凭它查网关回执。
    pub intent_hash: String,
    pub seq: u64,
    pub spend_nonce: u64,
}

/// `X-PAYMENT` 头的完整 JSON（base64url 编码前）。
///
/// agent 侧产出（Serialize）、merchant 侧消费（Deserialize，S-30c facilitator）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
    pub resource: String,
    pub payload: MeridianPayload,
}

impl PaymentPayload {
    /// 序列化 + base64url（无 padding，`base64url` 惯例）。
    pub fn to_header_value(&self) -> Result<String, SdkError> {
        let json = serde_json::to_vec(self)
            .map_err(|e| SdkError::Local(format!("serialize payment payload: {e}")))?;
        Ok(base64url_encode(&json))
    }
}

// ---------------------------------------------------------------------------
// HTTP 执行器接缝
// ---------------------------------------------------------------------------

/// 资源请求（method + URL + 头 + 可选 body）。
#[derive(Debug, Clone)]
pub struct ResourceRequest {
    pub method: String,
    /// v1：`HttpFetch` 仅支持 `http://`；https 由调用方注入的 [`Fetch`] 处理。
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl ResourceRequest {
    pub fn get(url: impl Into<String>) -> Self {
        ResourceRequest {
            method: "GET".into(),
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }
}

/// 原始响应。
#[derive(Debug, Clone)]
pub struct ResourceResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// HTTP 执行器接缝：内置 [`HttpFetch`]（明文 http），https 资源注入自带 TLS 的实现。
pub trait Fetch {
    fn fetch(&self, req: &ResourceRequest) -> Result<ResourceResponse, SdkError>;
}

/// std-only 明文 HTTP/1.1 执行器（与 `transport_http` 同口径：Connection: close、
/// Content-Length 定长读）。**仅 `http://`**——https 资源会得到 `SdkError::Local`。
#[derive(Debug, Clone, Default)]
pub struct HttpFetch;

impl Fetch for HttpFetch {
    fn fetch(&self, req: &ResourceRequest) -> Result<ResourceResponse, SdkError> {
        let (host_port, path) = parse_http_url(&req.url)?;
        let stream = TcpStream::connect(&host_port)
            .map_err(|_| SdkError::Transport(crate::error::TransportError::Disconnected))?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let mut writer = stream
            .try_clone()
            .map_err(|_| SdkError::Transport(crate::error::TransportError::Disconnected))?;
        let mut reader = BufReader::new(stream);

        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n",
            req.method, path
        );
        for (k, v) in &req.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some(b) = &req.body {
            head.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        head.push_str("\r\n");
        writer
            .write_all(head.as_bytes())
            .map_err(|_| SdkError::Transport(crate::error::TransportError::Disconnected))?;
        if let Some(b) = &req.body {
            writer
                .write_all(b)
                .map_err(|_| SdkError::Transport(crate::error::TransportError::Disconnected))?;
        }
        writer
            .flush()
            .map_err(|_| SdkError::Transport(crate::error::TransportError::Disconnected))?;

        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|_| SdkError::Transport(crate::error::TransportError::Disconnected))?;
        let status: u16 = line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| SdkError::Local("malformed status line".into()))?;

        let mut headers = Vec::new();
        let mut content_length: Option<usize> = None;
        loop {
            let mut h = String::new();
            reader
                .read_line(&mut h)
                .map_err(|_| SdkError::Transport(crate::error::TransportError::Disconnected))?;
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((name, value)) = h.split_once(':') {
                let (name, value) = (name.trim(), value.trim());
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value
                        .parse()
                        .map(Some)
                        .map_err(|_| SdkError::Local("bad content-length".into()))?;
                }
                headers.push((name.to_string(), value.to_string()));
            }
        }
        // Content-Length 定长；无长度（如 204/连接关闭）读到 EOF。
        let mut body = Vec::new();
        match content_length {
            Some(n) => {
                body.resize(n, 0);
                reader
                    .read_exact(&mut body)
                    .map_err(|_| SdkError::Transport(crate::error::TransportError::Disconnected))?;
            }
            None => {
                reader
                    .read_to_end(&mut body)
                    .map_err(|_| SdkError::Transport(crate::error::TransportError::Disconnected))?;
            }
        }
        Ok(ResourceResponse {
            status,
            headers,
            body,
        })
    }
}

/// `http://host[:port]/path` → (host:port, path)。仅 http scheme。
fn parse_http_url(url: &str) -> Result<(String, String), SdkError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        SdkError::Local(
            "HttpFetch supports http:// only — inject an HTTPS-capable Fetch for https resources"
                .into(),
        )
    })?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(SdkError::Local(format!("bad url: {url}")));
    }
    Ok((authority.to_string(), path.to_string()))
}

// ---------------------------------------------------------------------------
// X402Client
// ---------------------------------------------------------------------------

/// 一次 x402 请求的结果。
#[derive(Debug)]
pub enum X402Outcome {
    /// 非 402：免费资源或其它状态，原样返回（未发生任何支付）。
    Free(ResourceResponse),
    /// 已支付并重放：最终响应 + 支付证明（供 merchant 对账 / 网关复验）。
    Paid {
        response: ResourceResponse,
        proof: X402Proof,
    },
}

/// 支付证明（`X-PAYMENT` payload 的类型化形态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X402Proof {
    pub intent_hash: [u8; 32],
    pub seq: u64,
    pub spend_nonce: u64,
}

/// x402 fetch 拦截客户端：一张委托（`delegation_hash`）+ 一个 [`Fetch`] 执行器。
pub struct X402Client<'a> {
    sdk: &'a SdkClient,
    fetch: &'a dyn Fetch,
    /// 本客户端消费用的委托（authorize 过的 delegation_hash）。
    delegation_hash: [u8; 32],
}

impl<'a> X402Client<'a> {
    pub fn new(sdk: &'a SdkClient, fetch: &'a dyn Fetch, delegation_hash: [u8; 32]) -> Self {
        X402Client {
            sdk,
            fetch,
            delegation_hash,
        }
    }

    /// 发请求：非 402 原样返回；402 → 支付 → `X-PAYMENT` 重放。
    pub fn request(&self, req: &ResourceRequest) -> Result<X402Outcome, SdkError> {
        let first = self.fetch.fetch(req)?;
        if first.status != 402 {
            return Ok(X402Outcome::Free(first));
        }

        // 402 → 解析 paymentRequirements（scheme meridian-v1，多条取首条）。
        let required: PaymentRequired = serde_json::from_slice(&first.body)
            .map_err(|e| SdkError::Local(format!("bad 402 body: {e}")))?;
        let entry = required
            .accepts
            .iter()
            .find(|a| a.scheme == SCHEME)
            .ok_or_else(|| {
                SdkError::Local(format!(
                    "no {SCHEME} entry in 402 accepts (v1 client only speaks {SCHEME})"
                ))
            })?;
        let amount = entry.amount()?;
        let recipient = entry.recipient()?;
        let category = category_from_resource(&entry.resource);
        // 请求指纹（审计对账）；resource 全文绑定进 memo。
        let memo: [u8; 32] = Sha256::digest(entry.resource.as_bytes()).into();
        let timeout = entry.max_timeout_seconds.unwrap_or(60);
        let expires_at = unix_now() + timeout;

        // 走既有 pay 管线（固定 nonce + 幂等重试 §6.6；业务拒绝原样透传）。
        let receipt = self.sdk.pay(&PayParams {
            delegation_hash: self.delegation_hash,
            recipient,
            amount,
            category,
            memo: Some(memo),
            expires_at,
        })?;

        // 构造 X-PAYMENT 重放。
        let payload = PaymentPayload {
            x402_version: X402_VERSION,
            scheme: SCHEME.to_string(),
            network: entry.network.clone(),
            resource: entry.resource.clone(),
            payload: MeridianPayload {
                intent_hash: format!("0x{}", hex::encode(receipt.intent_hash)),
                seq: receipt.seq,
                spend_nonce: receipt.spend_nonce,
            },
        };
        let mut replay = req.clone();
        replay
            .headers
            .push((PAYMENT_HEADER.to_string(), payload.to_header_value()?));
        let second = self.fetch.fetch(&replay)?;

        let proof = X402Proof {
            intent_hash: receipt.intent_hash,
            seq: receipt.seq,
            spend_nonce: receipt.spend_nonce,
        };
        if second.status == 402 {
            // 已付仍 402：资源服务器拒绝（网关侧已接受——merchant 侧排查）。
            return Err(SdkError::Local(format!(
                "payment rejected by resource server after X-PAYMENT (intent_hash 0x{}, seq {})",
                hex::encode(proof.intent_hash),
                proof.seq
            )));
        }
        Ok(X402Outcome::Paid {
            response: second,
            proof,
        })
    }
}

/// `resource` URL → 类目：`sha256(host + path)`（x402-adapter §3；query 不绑定——
/// 类目是 owner 白名单的粗粒度路由控制，非请求身份）。
pub fn category_from_resource(resource: &str) -> [u8; 32] {
    let after_scheme = resource
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(resource);
    let host_path = match after_scheme.find(['?', '#']) {
        Some(i) => &after_scheme[..i],
        None => after_scheme,
    };
    Sha256::digest(host_path.as_bytes()).into()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// base64url（RFC 4648 §5，无 padding；手写实现避免新依赖，向量锁定见测试）
// ---------------------------------------------------------------------------

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url 编码（无 padding，x402 `base64url` 惯例）。
pub fn base64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.as_chunks::<3>().0 {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        out.push(B64URL[(n >> 18) as usize & 63] as char);
        out.push(B64URL[(n >> 12) as usize & 63] as char);
        out.push(B64URL[(n >> 6) as usize & 63] as char);
        out.push(B64URL[n as usize & 63] as char);
    }
    match data.len() % 3 {
        1 => {
            let n = (data[data.len() - 1] as u32) << 16;
            out.push(B64URL[(n >> 18) as usize & 63] as char);
            out.push(B64URL[(n >> 12) as usize & 63] as char);
        }
        2 => {
            let n = ((data[data.len() - 2] as u32) << 16) | ((data[data.len() - 1] as u32) << 8);
            out.push(B64URL[(n >> 18) as usize & 63] as char);
            out.push(B64URL[(n >> 12) as usize & 63] as char);
            out.push(B64URL[(n >> 6) as usize & 63] as char);
        }
        _ => {}
    }
    out
}

/// base64url 解码（宽容 padding——发端无 padding，收端兼容标准编码器带的 `=`）。
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, SdkError> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c == b'=' {
            break; // padding：余下全按终止处理
        }
        let v = val(c).ok_or_else(|| SdkError::Local(format!("bad base64url char {c:#x}")))?;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_rfc4648_vectors() {
        // RFC 4648 §5 测试向量（BASE64URL 无 padding）。
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url_encode(plain.as_bytes()), encoded);
        }
        // 标准 base64 的 +/- 在 URL 变体里是 -/_（0xFB 0xFF 0xBF = 62,63,62,63）。
        assert_eq!(base64url_encode(&[0xFB, 0xFF, 0xBF]), "-_-_");
        assert_eq!(base64url_encode(&[0xFB]), "-w");
        assert_eq!(base64url_encode(&[0xFC]), "_A");
    }

    #[test]
    fn base64url_decode_roundtrip_and_padding_tolerance() {
        for plain in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let enc = base64url_encode(plain.as_bytes());
            assert_eq!(base64url_decode(&enc).unwrap(), plain.as_bytes());
            // 带 padding 的标准编码也能解。
            let padded = match enc.len() % 4 {
                2 => format!("{enc}=="),
                3 => format!("{enc}="),
                _ => enc.clone(),
            };
            assert_eq!(base64url_decode(&padded).unwrap(), plain.as_bytes());
        }
        assert!(base64url_decode("a+bc").is_err(), "标准字母表 +/ 不接受");
    }

    #[test]
    fn category_binds_host_and_path_not_query() {
        let a = category_from_resource("https://api.example.com/weather?city=1");
        let b = category_from_resource("https://api.example.com/weather?city=2");
        assert_eq!(a, b, "query 不绑定——类目是路由级控制");
        let c = category_from_resource("https://api.example.com/v2/weather");
        assert_ne!(a, c, "不同路径必不同类目");
        // host 变化必变。
        let d = category_from_resource("https://other.example.com/weather");
        assert_ne!(a, d);
        // 无 scheme 宽容。
        assert_eq!(
            category_from_resource("api.example.com/weather"),
            category_from_resource("https://api.example.com/weather")
        );
    }

    #[test]
    fn pay_to_and_amount_parsing() {
        let req = PaymentRequirements {
            scheme: SCHEME.into(),
            network: "base".into(),
            max_amount_required: "10000".into(),
            resource: "https://api.example.com/weather".into(),
            description: Some("Weather data".into()),
            pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C".into(),
            max_timeout_seconds: Some(30),
            asset: None,
            extra: None,
        };
        assert_eq!(req.amount().unwrap(), 10_000);
        assert_eq!(
            req.recipient().unwrap(),
            [
                0x20, 0x96, 0x93, 0xBC, 0x6A, 0xFC, 0x0C, 0x53, 0x28, 0xBA, 0x36, 0xFA, 0xF0, 0x3C,
                0x51, 0x4E, 0xF3, 0x12, 0x28, 0x7C
            ]
        );

        let bad = PaymentRequirements {
            max_amount_required: "12x4".into(),
            pay_to: "0x1234".into(),
            ..req.clone()
        };
        assert!(bad.amount().is_err());
        assert!(bad.recipient().is_err());

        // 非 20B payTo 拒绝。
        let short = PaymentRequirements {
            pay_to: "0x209693Bc".into(),
            ..req
        };
        assert!(short.recipient().is_err());
    }

    #[test]
    fn payment_required_parses_camel_case_wire() {
        let body = r#"{
            "x402Version": 1,
            "error": "Payment required",
            "accepts": [{
                "scheme": "exact",
                "network": "base",
                "maxAmountRequired": "500",
                "resource": "https://api.example.com/data",
                "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                "maxTimeoutSeconds": 60
            }, {
                "scheme": "meridian-v1",
                "network": "base",
                "maxAmountRequired": "10000",
                "resource": "https://api.example.com/data",
                "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
            }]
        }"#;
        let pr: PaymentRequired = serde_json::from_str(body).expect("parse 402 body");
        assert_eq!(pr.x402_version, 1);
        assert_eq!(pr.accepts.len(), 2);
        assert_eq!(pr.accepts[1].scheme, "meridian-v1");
        assert_eq!(pr.accepts[1].amount().unwrap(), 10_000);
        assert_eq!(pr.accepts[1].max_timeout_seconds, None);
        // exact 条目可携带 EIP-3009 域参数（S-32）；meridian-v1 条目缺省 None（旧 wire 兼容）。
        assert_eq!(pr.accepts[0].extra, None);
    }

    #[test]
    fn payment_requirements_extra_eip3009_domain_roundtrip() {
        let body = r#"{
            "x402Version": 1,
            "accepts": [{
                "scheme": "exact",
                "network": "base",
                "maxAmountRequired": "10000",
                "resource": "https://api.example.com/data",
                "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                "extra": {"name": "USD Coin", "version": "2"}
            }]
        }"#;
        let pr: PaymentRequired = serde_json::from_str(body).expect("parse 402 body");
        assert_eq!(
            pr.accepts[0].extra,
            Some(Eip3009Extra {
                name: "USD Coin".into(),
                version: "2".into()
            })
        );
        // 产出侧 skip_serializing_if：meridian-v1 条目不出现 extra 键。
        let plain = serde_json::to_string(&PaymentRequired {
            x402_version: X402_VERSION,
            error: None,
            accepts: vec![PaymentRequirements {
                scheme: SCHEME.into(),
                network: "base".into(),
                max_amount_required: "10000".into(),
                resource: "https://api.example.com/data".into(),
                description: None,
                pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C".into(),
                max_timeout_seconds: Some(30),
                asset: None,
                extra: None,
            }],
        })
        .expect("serialize");
        assert!(!plain.contains("extra"));
    }

    #[test]
    fn payment_payload_header_roundtrip_shape() {
        let payload = PaymentPayload {
            x402_version: X402_VERSION,
            scheme: SCHEME.into(),
            network: "base".into(),
            resource: "https://api.example.com/data".into(),
            payload: MeridianPayload {
                intent_hash: format!("0x{}", hex::encode([0xAB; 32])),
                seq: 7,
                spend_nonce: 3,
            },
        };
        let header = payload.to_header_value().expect("encode");
        // base64url 字母表：无 +/ 与 =。
        assert!(!header.contains('+') && !header.contains('/') && !header.contains('='));
        // JSON 形状（camelCase 键名）可逆解码。
        let json = String::from_utf8(base64url_decode(&header).expect("self-consistent decode"))
            .expect("utf8");
        assert!(json.contains("\"x402Version\":1"));
        assert!(json.contains("\"scheme\":\"meridian-v1\""));
        assert!(json.contains("\"intentHash\":\"0x"));
        assert!(json.contains("\"seq\":7"));
        assert!(json.contains("\"spendNonce\":3"));
    }

    #[test]
    fn parse_http_url_extracts_authority_and_path() {
        assert_eq!(
            parse_http_url("http://api.example.com/weather?x=1").unwrap(),
            ("api.example.com".into(), "/weather?x=1".into())
        );
        assert_eq!(
            parse_http_url("http://localhost:9400").unwrap(),
            ("localhost:9400".into(), "/".into())
        );
        // https → Local（诚实拒绝，不静默降级）。
        assert!(parse_http_url("https://api.example.com/").is_err());
    }
}
