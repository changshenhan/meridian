//! x402 适配层 · 客户端（S-30b，TECH_SPEC §6.8，docs/x402-adapter.md §2.1）。
//!
//! 站位：Mist 是 **x402 的结算后端**（卖水），不是再造付费协议。本模块 = agent 侧
//! fetch 拦截：资源服务器回 `402` + `paymentRequirements`（scheme `mist-v1`）→
//! 映射成 [`PayParams`] 走 [`SdkClient::pay`]（幂等重试契约 §6.6 不变）→ 构造
//! 支付头（v1 `X-PAYMENT` / v2 `PAYMENT-SIGNATURE`）重放请求。
//!
//! # 线格式（S-72 起 v1/v2 双协议；TECH_SPEC §6.8「双协议取舍」）
//!
//! - 协议谈判：402 先读 `PAYMENT-REQUIRED` 头（v2 形，标准 base64）→ v2 流转；
//!   无头回落 body（v1 形）→ v1 流转。版本判据唯一 = `x402Version`。
//! - v1：402 体 `accepts[]` 消费 `scheme == "mist-v1"` 条目；`X-PAYMENT`
//!   （base64url 无 padding）payload `{"intentHash", "seq", "spendNonce"}`。
//! - v2：`accepted` 支付要求（`amount` 字段名、无 requirement 级 resource——
//!   resource 在 402 顶层 `ResourceInfo.url`）、`PAYMENT-SIGNATURE`
//!   （标准 base64）payload `{resource, accepted, payload: {intentHash, seq,
//!   spendNonce}}`。
//! - merchant 验证两条路径同源：网关 `GET /v1/receipts/{intentHash}`（S-30a），
//!   信封不内嵌（离线验签是 S-30c 缝）。
//!
//! # 诚实边界（v1 + v2）
//!
//! - 内置 [`HttpFetch`] 仅支持明文 `http://`；https 资源须注入 HTTPS 客户端（[`Fetch`] 接缝）。
//! - `category = sha256(host+path)` 是 owner 白名单的粗粒度路由控制，query 不绑定。
//! - `X-PAYMENT-RESPONSE` / `PAYMENT-RESPONSE` 结算回执头不消费（epoch 结算语义，
//!   facilitator 是 S-30c）。
//! - v2 `accepted` 回显为类型化投影（`PaymentRequirementsV2`）：服务器条目里
//!   本类型未建模的字段（如扩展私有键）不参与回显——Mist 自家 facilitator 产出的
//!   字段全覆盖；对第三方 v2 服务器的未知字段回显保真是非目标。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use mist_core::dsa::Did;

use crate::error::SdkError;
use crate::pay::{PayParams, PayReceipt};
use crate::SdkClient;

/// x402 协议版本（v1；v1 wire 基线，S-30b）。
pub const X402_VERSION: u32 = 1;
/// x402 协议版本（v2，S-72；上游 `@x402/*` v2 wire）。
pub const X402_VERSION_V2: u32 = 2;
/// Mist 的自定义 scheme（docs/x402-adapter.md §3；上游注册路径未定前使用）。
///
/// scheme 命名与 x402 协议版本正交（S-72 定夺）：`mist-v1` 的"v1"是 Mist scheme
/// 版本，不随 x402 协议 v2 改名。
pub const SCHEME: &str = "mist-v1";
/// `X-PAYMENT` 头名（x402 v1 HTTP transport 惯例）。
pub const PAYMENT_HEADER: &str = "X-PAYMENT";
/// `PAYMENT-SIGNATURE` 头名（x402 v2 HTTP transport，S-72）。
pub const PAYMENT_HEADER_V2: &str = "PAYMENT-SIGNATURE";
/// `PAYMENT-REQUIRED` 头名（x402 v2 402 声明载体——协议信息走头，body 是 server
/// 实现关切；S-72）。
pub const PAYMENT_REQUIRED_HEADER: &str = "PAYMENT-REQUIRED";

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
    /// `mist-v1` 条目不产出该字段（skip），Deserialize 缺省 None——旧 wire 兼容。
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

// ---------------------------------------------------------------------------
// v2 wire 形（S-72：PAYMENT-REQUIRED 头 / PAYMENT-SIGNATURE 头；TECH_SPEC §6.8）
// ---------------------------------------------------------------------------

/// v2 资源信息（402 顶层 `resource`；v1 的 requirement 级 `resource`/`description`
/// 字段在 v2 移到这里）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// v2 单条支付要求（camelCase、金额恒字符串）。
///
/// 与 v1 [`PaymentRequirements`] 的字段差异（S-72，上游 `@x402/core` 实核）：
/// `maxAmountRequired` 改名 `amount`；`resource`/`description` 移出到 402 顶层
/// [`ResourceInfo`]；`outputSchema` 删除。`extra` 语义不变（EIP-3009 域参数）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirementsV2 {
    pub scheme: String,
    /// CAIP-2 规范形（`eip155:8453` 等；v1 字符串经 [`network_canonical`] 互通）。
    pub network: String,
    /// 原子单位字符串（USDC 6 decimals）——v2 字段名，语义同 v1 `maxAmountRequired`。
    pub amount: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    /// 收款方 0x EVM 地址（20B）。
    pub pay_to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Eip3009Extra>,
}

impl PaymentRequirementsV2 {
    /// `amount` 字符串 → 原子单位 u64（语义同 v1 [`PaymentRequirements::amount`]）。
    pub fn atomic_amount(&self) -> Result<u64, SdkError> {
        self.amount
            .parse::<u64>()
            .map_err(|e| SdkError::Local(format!("bad v2 amount: {e}")))
    }

    /// `payTo` 0x hex → 20B 收款地址（语义同 v1 [`PaymentRequirements::recipient`]）。
    pub fn recipient(&self) -> Result<Did, SdkError> {
        let raw = self.pay_to.strip_prefix("0x").unwrap_or(&self.pay_to);
        let bytes = hex::decode(raw).map_err(|e| SdkError::Local(format!("bad payTo hex: {e}")))?;
        let arr: [u8; 20] = bytes.try_into().map_err(|v: Vec<u8>| {
            SdkError::Local(format!("payTo must be 20 bytes, got {}", v.len()))
        })?;
        Ok(arr)
    }
}

/// v2 402 声明（`PAYMENT-REQUIRED` 头标准 base64 前的 JSON）。
///
/// 上游 v2 恒走头载体（body 是 server 实现关切）；`accepts` 为空 = 纯 error 声明
/// （Mist facilitator 的 error 402 不产 v2 头，见 TECH_SPEC §6.8 双协议取舍）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequiredV2 {
    pub x402_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: ResourceInfo,
    #[serde(default)]
    pub accepts: Vec<PaymentRequirementsV2>,
}

/// v2 付款载荷（`PAYMENT-SIGNATURE` 头标准 base64 前）。
///
/// v2 结构差异：**顶层无 `scheme`/`network`/`resource` 字符串**——scheme/network
/// 在 [`PaymentPayloadV2::accepted`] 里，resource 是顶层 [`ResourceInfo`] 对象
/// （402 声明的原样回显）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayloadV2 {
    pub x402_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    /// 服务器产出的支付要求，client 原样回显（v2 绑定语义：accepted 由服务器
    /// 产出、client 不改写）。
    pub accepted: PaymentRequirementsV2,
    pub payload: MistPayload,
}

impl PaymentPayloadV2 {
    /// 序列化 + 标准 base64（v2 发端口径，与上游 `encodePaymentSignatureHeader`
    /// 互操作；v1 发端仍是 [`PaymentPayload::to_header_value`] 的 base64url）。
    pub fn to_header_value(&self) -> Result<String, SdkError> {
        let json = serde_json::to_vec(self)
            .map_err(|e| SdkError::Local(format!("serialize payment payload v2: {e}")))?;
        Ok(base64_std_encode(&json))
    }
}

/// v1 网络名 → CAIP-2 规范形（S-72；未知输入原样透传——任意 CAIP-2 直通）。
///
/// 映射表 = 上游迁移指南 Network Identifier Mapping（`base`→`eip155:8453` 等）。
/// 比较恒在规范形上进行：v1 字符串与 CAIP-2 等价类互通，既有 v1 配置零迁移。
pub fn network_canonical(network: &str) -> &str {
    match network {
        "base" => "eip155:8453",
        "base-sepolia" => "eip155:84532",
        "ethereum" => "eip155:1",
        "sepolia" => "eip155:11155111",
        other => other,
    }
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
pub struct MistPayload {
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
    pub payload: MistPayload,
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

    /// 发请求：非 402 原样返回；402 → 协议谈判（v2 头优先，回落 v1 body）→
    /// 支付 → 对应版本支付头重放。
    pub fn request(&self, req: &ResourceRequest) -> Result<X402Outcome, SdkError> {
        let first = self.fetch.fetch(req)?;
        if first.status != 402 {
            return Ok(X402Outcome::Free(first));
        }

        // 协议谈判（§6.8 双协议取舍，"输出偏 v2"的消费端对称）：
        // `PAYMENT-REQUIRED` 头在场 → v2 流转（不发头即 v2 语义的 server，body
        // 必是 server 关切，不做 v2→v1 二次回落——确定性优先）。
        if let Some(v2) = header_value(&first.headers, PAYMENT_REQUIRED_HEADER) {
            return self.request_v2(req, &v2);
        }
        self.request_v1(req, &first.body)
    }

    /// v1 流转（S-30b 原样）：body 解析 paymentRequirements → `X-PAYMENT` 重放。
    fn request_v1(&self, req: &ResourceRequest, body: &[u8]) -> Result<X402Outcome, SdkError> {
        let required: PaymentRequired = serde_json::from_slice(body)
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
            payload: MistPayload {
                intent_hash: format!("0x{}", hex::encode(receipt.intent_hash)),
                seq: receipt.seq,
                spend_nonce: receipt.spend_nonce,
            },
        };
        self.finish(req, (PAYMENT_HEADER, payload.to_header_value()?), &receipt)
    }

    /// v2 流转（S-72）：`PAYMENT-REQUIRED` 头解析 → `PAYMENT-SIGNATURE` 重放。
    fn request_v2(&self, req: &ResourceRequest, header: &str) -> Result<X402Outcome, SdkError> {
        let decoded = base64_decode_flexible(header)
            .map_err(|e| SdkError::Local(format!("bad PAYMENT-REQUIRED encoding: {e}")))?;
        let required: PaymentRequiredV2 = serde_json::from_slice(&decoded)
            .map_err(|e| SdkError::Local(format!("bad PAYMENT-REQUIRED payload: {e}")))?;
        let entry = required
            .accepts
            .iter()
            .find(|a| a.scheme == SCHEME)
            .ok_or_else(|| {
                SdkError::Local(format!(
                    "no {SCHEME} entry in v2 PAYMENT-REQUIRED accepts (client only speaks {SCHEME})"
                ))
            })?;
        let amount = entry.atomic_amount()?;
        let recipient = entry.recipient()?;
        // v2 resource 映射源 = 402 顶层 ResourceInfo.url（§6.8 字段映射表）。
        let resource = required.resource.url.clone();
        let category = category_from_resource(&resource);
        let memo: [u8; 32] = Sha256::digest(resource.as_bytes()).into();
        let timeout = entry.max_timeout_seconds.unwrap_or(60);
        let expires_at = unix_now() + timeout;

        let receipt = self.sdk.pay(&PayParams {
            delegation_hash: self.delegation_hash,
            recipient,
            amount,
            category,
            memo: Some(memo),
            expires_at,
        })?;

        // v2 payload：accepted 原样回显 + resource 回显（绑定语义，§6.8）。
        let payload = PaymentPayloadV2 {
            x402_version: X402_VERSION_V2,
            resource: Some(required.resource),
            accepted: entry.clone(),
            payload: MistPayload {
                intent_hash: format!("0x{}", hex::encode(receipt.intent_hash)),
                seq: receipt.seq,
                spend_nonce: receipt.spend_nonce,
            },
        };
        self.finish(
            req,
            (PAYMENT_HEADER_V2, payload.to_header_value()?),
            &receipt,
        )
    }

    /// 共享重放尾段：带支付头重放 → 非 402 放行 / 已付仍 402 = 资源服务器拒绝
    /// （网关侧已接受——merchant 侧排查），不重试。
    fn finish(
        &self,
        req: &ResourceRequest,
        header: (&'static str, String),
        receipt: &PayReceipt,
    ) -> Result<X402Outcome, SdkError> {
        let mut replay = req.clone();
        replay.headers.push((header.0.to_string(), header.1));
        let second = self.fetch.fetch(&replay)?;
        let proof = X402Proof {
            intent_hash: receipt.intent_hash,
            seq: receipt.seq,
            spend_nonce: receipt.spend_nonce,
        };
        if second.status == 402 {
            return Err(SdkError::Local(format!(
                "payment rejected by resource server after {} (intent_hash 0x{}, seq {})",
                header.0,
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

/// 大小写不敏感取响应头。
fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
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
/// 标准 base64 字母表（v2 发端，S-72；`+/` 与 URL-safe `-_` 语义等位）。
const B64STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

/// 标准 base64 编码（带 padding；v2 发端口径，S-72——上游
/// `encodePaymentSignatureHeader` 同形，JSON 直编无 HMAC 包装）。
pub fn base64_std_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.as_chunks::<3>().0 {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        out.push(B64STD[(n >> 18) as usize & 63] as char);
        out.push(B64STD[(n >> 12) as usize & 63] as char);
        out.push(B64STD[(n >> 6) as usize & 63] as char);
        out.push(B64STD[n as usize & 63] as char);
    }
    match data.len() % 3 {
        1 => {
            let n = (data[data.len() - 1] as u32) << 16;
            out.push(B64STD[(n >> 18) as usize & 63] as char);
            out.push(B64STD[(n >> 12) as usize & 63] as char);
            out.push_str("==");
        }
        2 => {
            let n = ((data[data.len() - 2] as u32) << 16) | ((data[data.len() - 1] as u32) << 8);
            out.push(B64STD[(n >> 18) as usize & 63] as char);
            out.push(B64STD[(n >> 12) as usize & 63] as char);
            out.push(B64STD[(n >> 6) as usize & 63] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

/// 双字母表宽容 base64 解码（S-72 收端口径）：标准 `+/` 与 URL-safe `-_` 均收
/// （62/63 各自映射、两字母表额外字符互斥不歧义）、padding 可选——v1 发端
/// （base64url 无 padding）与 v2 发端（标准 base64）一码通吃。
pub fn base64_decode_flexible(s: &str) -> Result<Vec<u8>, SdkError> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'-' | b'+' => Some(62),
            b'_' | b'/' => Some(63),
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
        let v = val(c).ok_or_else(|| SdkError::Local(format!("bad base64 char {c:#x}")))?;
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
                "scheme": "mist-v1",
                "network": "base",
                "maxAmountRequired": "10000",
                "resource": "https://api.example.com/data",
                "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
            }]
        }"#;
        let pr: PaymentRequired = serde_json::from_str(body).expect("parse 402 body");
        assert_eq!(pr.x402_version, 1);
        assert_eq!(pr.accepts.len(), 2);
        assert_eq!(pr.accepts[1].scheme, "mist-v1");
        assert_eq!(pr.accepts[1].amount().unwrap(), 10_000);
        assert_eq!(pr.accepts[1].max_timeout_seconds, None);
        // exact 条目可携带 EIP-3009 域参数（S-32）；mist-v1 条目缺省 None（旧 wire 兼容）。
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
        // 产出侧 skip_serializing_if：mist-v1 条目不出现 extra 键。
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
            payload: MistPayload {
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
        assert!(json.contains("\"scheme\":\"mist-v1\""));
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

    // -----------------------------------------------------------------------
    // S-72：v2 wire 形
    // -----------------------------------------------------------------------

    #[test]
    fn network_canonical_maps_v1_names_and_passes_caip2_through() {
        // 上游迁移指南映射表。
        assert_eq!(network_canonical("base"), "eip155:8453");
        assert_eq!(network_canonical("base-sepolia"), "eip155:84532");
        assert_eq!(network_canonical("ethereum"), "eip155:1");
        assert_eq!(network_canonical("sepolia"), "eip155:11155111");
        // 任意 CAIP-2 原样透传（Anvil 本地链 e2e 依赖此路径）。
        assert_eq!(network_canonical("eip155:31337"), "eip155:31337");
        // 等价类互通：v1 名与 CAIP-2 规范化后相等。
        assert_eq!(network_canonical("base"), network_canonical("eip155:8453"));
        // 未知 v1 名原样透传（不猜）。
        assert_eq!(network_canonical("arbitrum"), "arbitrum");
    }

    #[test]
    fn base64_std_encode_matches_rfc4648_vectors_with_padding() {
        // RFC 4648 §4 测试向量（标准字母表、带 padding）。
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_std_encode(plain.as_bytes()), encoded);
        }
        // 0xFB 0xFF 0xBF → 62,63,62,63 = 标准 + / + /（URL 变体是 -_-_）。
        assert_eq!(base64_std_encode(&[0xFB, 0xFF, 0xBF]), "+/+/");
    }

    #[test]
    fn base64_decode_flexible_accepts_both_alphabets() {
        // 标准 base64（含 +/ 与 padding）可解。
        assert_eq!(
            base64_decode_flexible("Zm9vYmFy").unwrap(),
            b"foobar".to_vec()
        );
        assert_eq!(base64_decode_flexible("Zg==").unwrap(), b"f".to_vec());
        assert_eq!(
            base64_decode_flexible("+/+/").unwrap(),
            vec![0xFB, 0xFF, 0xBF]
        );
        // base64url（含 -_ 无 padding）同样可解——收端一码通吃。
        assert_eq!(
            base64_decode_flexible("-_-_").unwrap(),
            vec![0xFB, 0xFF, 0xBF]
        );
        assert_eq!(base64_decode_flexible("Zm9vYmFy").unwrap(), {
            let v = base64url_encode(b"foobar");
            base64_decode_flexible(&v).unwrap()
        });
        // 非法字符仍拒。
        assert!(base64_decode_flexible("a*bc").is_err());
    }

    #[test]
    fn payment_required_v2_parses_amount_shape_and_resource_info() {
        // v2 形：amount（非 maxAmountRequired）、resource 在顶层 ResourceInfo、
        // accepts 条目无 resource/description 字段。
        let body = r#"{
            "x402Version": 2,
            "resource": {"url": "https://api.example.com/data", "description": "Data"},
            "accepts": [{
                "scheme": "mist-v1",
                "network": "eip155:8453",
                "amount": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                "maxTimeoutSeconds": 30
            }]
        }"#;
        let pr: PaymentRequiredV2 = serde_json::from_str(body).expect("parse v2 402");
        assert_eq!(pr.x402_version, X402_VERSION_V2);
        assert_eq!(pr.resource.url, "https://api.example.com/data");
        assert_eq!(pr.accepts[0].scheme, SCHEME);
        assert_eq!(pr.accepts[0].atomic_amount().unwrap(), 10_000);
        assert_eq!(pr.accepts[0].max_timeout_seconds, Some(30));
        assert_eq!(pr.accepts[0].recipient().unwrap()[0], 0x20);
    }

    #[test]
    fn payment_payload_v2_header_shape_is_std_base64_json() {
        let payload = PaymentPayloadV2 {
            x402_version: X402_VERSION_V2,
            resource: Some(ResourceInfo {
                url: "https://api.example.com/data".into(),
                description: None,
                mime_type: None,
            }),
            accepted: PaymentRequirementsV2 {
                scheme: SCHEME.into(),
                network: "eip155:8453".into(),
                amount: "10000".into(),
                asset: None,
                pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C".into(),
                max_timeout_seconds: Some(30),
                extra: None,
            },
            payload: MistPayload {
                intent_hash: format!("0x{}", hex::encode([0xAB; 32])),
                seq: 7,
                spend_nonce: 3,
            },
        };
        let header = payload.to_header_value().expect("encode");
        // v2 发端 = 标准 base64：padding 在场，+// 可能出现（无 JSON 时至少无 -/_）。
        assert!(!header.contains('-') && !header.contains('_'), "{header}");
        // JSON 形状：accepted 对象回显 + intentHash，无顶层 scheme/network。
        let json =
            String::from_utf8(base64_decode_flexible(&header).expect("decode")).expect("utf8");
        assert!(json.contains("\"x402Version\":2"));
        assert!(json.contains("\"accepted\":{\"scheme\":\"mist-v1\""));
        assert!(json.contains("\"amount\":\"10000\""));
        assert!(json.contains("\"resource\":{\"url\":\"https://api.example.com/data\"}"));
        assert!(json.contains("\"intentHash\":\"0x"));
        // 顶层键序 = x402Version → resource → accepted → payload：顶层无 v1 的
        // scheme/network/resource 字符串键（它们只存在于 accepted / resource 对象内）。
        assert!(
            json.starts_with("{\"x402Version\":2,\"resource\":{\"url\":"),
            "顶层形状不是 v2 形: {json}"
        );
    }
}
