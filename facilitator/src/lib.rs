//! x402 merchant 参考实现（S-30c，TECH_SPEC §6.9，docs/x402-adapter.md §2.1 server 侧）。
//!
//! 受保护资源服务器怎么接 `mist-v1` 支付：验证逻辑**全部**落在"对 Mist 网关
//! 查回执"（S-30a 的 [`HttpTransport::receipt`] 即验证接口），零密码学依赖。
//! （S-32 起另含可选的 EIP-3009 兼容桥 [`eip3009`]——那条路径带 ecrecover。）
//!
//! # 分发逻辑（[`Facilitator::handle`] 纯分发，单测不经 socket）
//!
//! - `GET /healthz` → 200；其它路径 = 单一受保护资源（v1）。
//! - 无支付头 → 402 + paymentRequirements（`mist-v1`；配置了桥时附 `exact`
//!   条目——S-32 EIP-3009 兼容桥，[`eip3009`]）+ `PAYMENT-REQUIRED` 响应头
//!   （v2 形声明，S-72；`asset` 未配置则省——v2 client 回落 body 按 v1 语境重试）。
//! - 带支付头（`PAYMENT-SIGNATURE` v2 / `X-PAYMENT` v1，双字母表宽容 base64 解码）→
//!   按 `x402Version` 归一化（v1：顶层 `scheme`/`network`/`resource`；v2：
//!   `accepted.scheme`/`accepted.network` + 顶层 `resource.url`）→ 按 `scheme` 分发：
//!   - `mist-v1`：校验 scheme/network/resource（network 恒 `network_canonical`
//!     规范形比较——v1 字符串与 CAIP-2 等价类互通）→ 查网关：`Some` → 200 放行；
//!     `None` → 402（**404 ≠ 未支付**语义下"不可验证即不放行"）；`Err` → 503
//!     fail-closed（验证面不可用绝不放行）。
//!   - `exact`（S-32）：EIP-712 验签 → 桥转投 Mist 摄取（垫付模型）→ 查网关
//!     回执放行（TECH_SPEC §6.10；S-72 起 v1/v2 双 wire 形）；重放闸 S-33 起
//!     可持久化（[`replay`]），日志落盘失败 → 503 `E_REPLAY_JOURNAL` fail-closed。
//!
//! # 诚实边界（v1 + v2）
//!
//! 单资源模型、明文 HTTP（TLS 反代终结）、不产出 `X-PAYMENT-RESPONSE`/
//! `PAYMENT-RESPONSE` 结算头（对账走网关查询；已核实上游 axios v2 wrapper 缺头
//! 不硬失败）、结算侧（epoch claim、对账导出）不在本件——参考实现演示
//! "merchant 怎么接"，不是生产 facilitator。

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use mist_sdk::x402::{
    base64_decode_flexible, base64_std_encode, network_canonical, PaymentRequired,
    PaymentRequiredV2, PaymentRequirements, PaymentRequirementsV2, ResourceInfo,
    PAYMENT_REQUIRED_HEADER, X402_VERSION, X402_VERSION_V2,
};
use mist_sdk::{HttpTransport, Receipt, SdkError};

pub mod eip3009;
pub mod replay;

pub use eip3009::{Eip3009Bridge, Eip3009Domain};

/// x402 v1 协议头名（与 agent 侧一致）。
pub const PAYMENT_HEADER: &str = "X-PAYMENT";
/// 网关查询失败（fail-closed）的传输层错误码。
pub const E_GATEWAY_UNAVAILABLE: &str = "E_GATEWAY_UNAVAILABLE";
/// 重放闸日志落盘失败（S-33 fail-closed）的错误码。
pub const E_REPLAY_JOURNAL: &str = "E_REPLAY_JOURNAL";

/// facilitator 配置（单一受保护资源）。
#[derive(Debug, Clone)]
pub struct FacilitatorConfig {
    /// Mist 网关地址，如 `"127.0.0.1:9400"`。
    pub gateway_addr: String,
    /// 网关租户表里的 bearer key。
    pub gateway_bearer: String,
    /// 受保护资源 URL（进 402 body 的 `resource`，也绑定重放头的 resource 校验）。
    pub resource: String,
    /// 收款方 0x 20B 地址。
    pub pay_to: String,
    /// 单价（原子单位字符串）。
    pub amount: String,
    /// x402 network 标识（如 `"base"`）。
    pub network: String,
    /// 结算资产合约（可选）。
    pub asset: Option<String>,
    /// 支付有效期秒数（进 402 body 的 `maxTimeoutSeconds`）。
    pub max_timeout_seconds: u64,
    /// 200 放行时返回的资源内容。
    pub protected_body: String,
}

/// facilitator：纯分发 + std-only HTTP 管道（`http::serve`）。
pub struct Facilitator {
    cfg: FacilitatorConfig,
    /// 与网关的查询连接（S-30a `GET /v1/receipts/{hash}`）。
    transport: HttpTransport,
    /// EIP-3009 兼容桥（S-32；`None` = 未启用，exact scheme 回 402）。
    bridge: Option<Eip3009Bridge>,
    /// 资源绑定投影（桥校验用，构造一次）。
    binding: OnceLock<eip3009::ResourceBinding>,
    /// 402 body 缓存（构造一次，每次原样返回）。
    payment_required: OnceLock<String>,
    /// v2 `PAYMENT-REQUIRED` 头值缓存（`None` = `asset` 未配置，不产 v2 头——
    /// v2 schema 要求 asset 必填非空；构造一次）。
    payment_required_v2: OnceLock<Option<String>>,
}

impl Facilitator {
    pub fn new(cfg: FacilitatorConfig) -> Self {
        Facilitator::with_bridge(cfg, None)
    }

    /// 带桥构造（S-32：接受标准 `exact` scheme，验签后转投 Mist 摄取）。
    pub fn with_bridge(cfg: FacilitatorConfig, bridge: Option<Eip3009Bridge>) -> Self {
        let transport = HttpTransport::new(cfg.gateway_addr.clone(), cfg.gateway_bearer.clone());
        Facilitator {
            cfg,
            transport,
            bridge,
            binding: OnceLock::new(),
            payment_required: OnceLock::new(),
            payment_required_v2: OnceLock::new(),
        }
    }

    pub fn config(&self) -> &FacilitatorConfig {
        &self.cfg
    }

    /// 402 体（`mist-v1` 条目 + 配置了桥时的 `exact` 条目；构造失败是配置错误，
    /// panic 合理——启动即暴露）。
    fn payment_required_json(&self) -> &str {
        self.payment_required.get_or_init(|| {
            let mut accepts = vec![PaymentRequirements {
                scheme: mist_sdk::x402::SCHEME.to_string(),
                network: self.cfg.network.clone(),
                max_amount_required: self.cfg.amount.clone(),
                resource: self.cfg.resource.clone(),
                description: None,
                pay_to: self.cfg.pay_to.clone(),
                max_timeout_seconds: Some(self.cfg.max_timeout_seconds),
                asset: self.cfg.asset.clone(),
                extra: None,
            }];
            if let Some(bridge) = &self.bridge {
                let d = &bridge.config().domain;
                accepts.push(PaymentRequirements {
                    scheme: eip3009::EXACT_SCHEME.to_string(),
                    network: self.cfg.network.clone(),
                    max_amount_required: self.cfg.amount.clone(),
                    resource: self.cfg.resource.clone(),
                    description: None,
                    pay_to: self.cfg.pay_to.clone(),
                    max_timeout_seconds: Some(self.cfg.max_timeout_seconds),
                    asset: self.cfg.asset.clone(),
                    extra: Some(mist_sdk::x402::Eip3009Extra {
                        name: d.name.clone(),
                        version: d.version.clone(),
                    }),
                });
            }
            let pr = PaymentRequired {
                x402_version: X402_VERSION,
                error: None,
                accepts,
            };
            serde_json::to_string(&pr).expect("serialize 402 body")
        })
    }

    /// v2 `PAYMENT-REQUIRED` 头值（标准 base64 的 v2 声明；S-72）。
    ///
    /// `None` = `asset` 未配置——v2 schema 要求 `asset` 必填非空，此时不产 v2 头，
    /// v2 client 回落 body 按 v1 语境重试（我们照收，优雅降级，§6.8 双协议取舍）。
    /// accepts 恒产 CAIP-2 规范形（`network_canonical`）。
    fn payment_required_v2_header(&self) -> Option<String> {
        self.payment_required_v2
            .get_or_init(|| {
                let asset = self.cfg.asset.as_ref()?;
                let mut accepts = vec![PaymentRequirementsV2 {
                    scheme: mist_sdk::x402::SCHEME.to_string(),
                    network: network_canonical(&self.cfg.network).to_string(),
                    amount: self.cfg.amount.clone(),
                    asset: Some(asset.clone()),
                    pay_to: self.cfg.pay_to.clone(),
                    max_timeout_seconds: Some(self.cfg.max_timeout_seconds),
                    extra: None,
                }];
                if let Some(bridge) = &self.bridge {
                    let d = &bridge.config().domain;
                    accepts.push(PaymentRequirementsV2 {
                        scheme: eip3009::EXACT_SCHEME.to_string(),
                        network: network_canonical(&self.cfg.network).to_string(),
                        amount: self.cfg.amount.clone(),
                        asset: Some(asset.clone()),
                        pay_to: self.cfg.pay_to.clone(),
                        max_timeout_seconds: Some(self.cfg.max_timeout_seconds),
                        extra: Some(mist_sdk::x402::Eip3009Extra {
                            name: d.name.clone(),
                            version: d.version.clone(),
                        }),
                    });
                }
                let pr = PaymentRequiredV2 {
                    x402_version: X402_VERSION_V2,
                    error: None,
                    resource: ResourceInfo {
                        url: self.cfg.resource.clone(),
                        description: None,
                        mime_type: None,
                    },
                    accepts,
                };
                let json = serde_json::to_string(&pr).expect("serialize v2 402");
                Some(base64_std_encode(json.as_bytes()))
            })
            .clone()
    }

    fn unauthorized(&self, error: &str) -> FacilitatorResponse {
        let pr = PaymentRequired {
            x402_version: X402_VERSION,
            error: Some(error.to_string()),
            accepts: Vec::new(),
        };
        FacilitatorResponse {
            status: 402,
            body: serde_json::to_string(&pr).expect("serialize 402 error body"),
            // error 402 不带 v2 头（v2 schema 要求 accepts ≥ 1，§6.8 双协议取舍）。
            headers: Vec::new(),
        }
    }

    /// 纯分发：method / path / 支付头（http 层已按 v2 优先归一）→ 响应。
    /// 单测不经 socket。
    pub fn handle(&self, method: &str, path: &str, payment: Option<&str>) -> FacilitatorResponse {
        if method != "GET" {
            return FacilitatorResponse::status(405);
        }
        if path == "/healthz" {
            return FacilitatorResponse::ok("ok");
        }
        if path != "/" {
            return FacilitatorResponse::status(404);
        }

        let Some(header) = payment else {
            let mut resp = FacilitatorResponse {
                status: 402,
                body: self.payment_required_json().to_string(),
                headers: Vec::new(),
            };
            // v2 声明走头（body 维持 v1 形不动——v1 client 面零改动，§6.8）。
            if let Some(v2) = self.payment_required_v2_header() {
                resp.headers.push((PAYMENT_REQUIRED_HEADER.to_string(), v2));
            }
            return resp;
        };

        // 1. 双字母表宽容 base64 解码（v1 base64url / v2 标准 base64 一码通吃）。
        let decoded = match base64_decode_flexible(header) {
            Ok(d) => d,
            Err(e) => return self.unauthorized(&format!("bad payment header encoding: {e}")),
        };
        // 2. 版本归一化（判据唯一 = x402Version，§6.8）：
        //    v1 = 顶层 scheme/network/resource；v2 = accepted.scheme/accepted.network
        //    + 顶层 resource.url。
        let value: serde_json::Value = match serde_json::from_slice(&decoded) {
            Ok(v) => v,
            Err(e) => return self.unauthorized(&format!("bad payment payload: {e}")),
        };
        let version = match value.get("x402Version").and_then(serde_json::Value::as_u64) {
            Some(v) => v,
            None => return self.unauthorized("missing x402Version"),
        };
        let (scheme, network, resource) = match version {
            1 => (
                value.get("scheme").and_then(serde_json::Value::as_str),
                value.get("network").and_then(serde_json::Value::as_str),
                value.get("resource").and_then(serde_json::Value::as_str),
            ),
            2 => (
                value
                    .pointer("/accepted/scheme")
                    .and_then(serde_json::Value::as_str),
                value
                    .pointer("/accepted/network")
                    .and_then(serde_json::Value::as_str),
                // v2 resource = 顶层 ResourceInfo.url。
                value
                    .pointer("/resource/url")
                    .and_then(serde_json::Value::as_str),
            ),
            other => {
                return self.unauthorized(&format!(
                    "unsupported x402Version {other} (only {X402_VERSION} / {X402_VERSION_V2})"
                ))
            }
        };
        match scheme.unwrap_or("") {
            mist_sdk::x402::SCHEME => self.verify_mist(network, resource, &value, version),
            eip3009::EXACT_SCHEME => {
                if version == 2 {
                    self.ingest_exact_v2(&value)
                } else {
                    self.ingest_exact(&value)
                }
            }
            other => self.unauthorized(&format!(
                "unsupported scheme {other:?} (only {:?} / {})",
                mist_sdk::x402::SCHEME,
                eip3009::EXACT_SCHEME
            )),
        }
    }

    /// `mist-v1` 路径（S-30c；S-72 起 v1/v2 归一）：绑定校验 → 网关查回执。
    ///
    /// `network` / `resource` 为归一化后的条目（v1 顶层 / v2 accepted + resource.url）。
    fn verify_mist(
        &self,
        network: Option<&str>,
        resource: Option<&str>,
        value: &serde_json::Value,
        version: u64,
    ) -> FacilitatorResponse {
        let wire = match version {
            1 => "X-PAYMENT",
            _ => "PAYMENT-SIGNATURE",
        };
        let network = network.unwrap_or("");
        // network 恒规范形比较（v1 字符串与 CAIP-2 等价类互通，S-72）。
        if network_canonical(network) != network_canonical(&self.cfg.network) {
            return self.unauthorized(&format!("network mismatch: {network}"));
        }
        let resource = match resource {
            Some(r) => r,
            None => return self.unauthorized("resource binding required (missing resource)"),
        };
        if resource != self.cfg.resource {
            return self.unauthorized(&format!("resource mismatch: {resource}"));
        }
        // intentHash 解析（0x 前缀宽容；两版本 payload 内层同形）。
        let intent_hash_str = value
            .pointer("/payload/intentHash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let raw = intent_hash_str
            .strip_prefix("0x")
            .unwrap_or(intent_hash_str);
        let ih_bytes = match hex::decode(raw) {
            Ok(b) => b,
            Err(e) => return self.unauthorized(&format!("bad {wire} intentHash hex: {e}")),
        };
        let intent_hash: [u8; 32] = match ih_bytes.try_into() {
            Ok(a) => a,
            Err(v) => {
                return self.unauthorized(&format!("intentHash must be 32 bytes, got {}", v.len()))
            }
        };
        // 网关回执查询（唯一验证步骤）。fail-closed：网关不可用 → 503。
        self.receipt_gate(intent_hash)
    }

    /// `exact` 路径（S-32，TECH_SPEC §6.10）：桥验签 + 转投 Mist 摄取 → 回执闸。
    fn ingest_exact(&self, value: &serde_json::Value) -> FacilitatorResponse {
        let Some(bridge) = &self.bridge else {
            return self.unauthorized("exact scheme not enabled (no bridge configured)");
        };
        let payment: eip3009::ExactPayment = match serde_json::from_value(value.clone()) {
            Ok(p) => p,
            Err(e) => return self.unauthorized(&format!("bad exact payload: {e}")),
        };
        match bridge.ingest(&payment, self.binding(), unix_now()) {
            // 摄取成功 → 走同一回执闸（merchant 验证面与 mist-v1 完全一致）。
            Ok(intent_hash) => self.receipt_gate(intent_hash),
            Err(e) => self.bridge_error_response(&e),
        }
    }

    /// `exact` v2 路径（S-72，TECH_SPEC §6.10 v2 形）：scheme/network/amount 取自
    /// `accepted`（顶层无 scheme/network/resource），验签/摄取/回执闸与 v1 全同。
    fn ingest_exact_v2(&self, value: &serde_json::Value) -> FacilitatorResponse {
        let Some(bridge) = &self.bridge else {
            return self.unauthorized("exact scheme not enabled (no bridge configured)");
        };
        let payment: eip3009::ExactPaymentV2 = match serde_json::from_value(value.clone()) {
            Ok(p) => p,
            Err(e) => return self.unauthorized(&format!("bad exact payload: {e}")),
        };
        match bridge.ingest_v2(&payment, self.binding(), unix_now()) {
            Ok(intent_hash) => self.receipt_gate(intent_hash),
            Err(e) => self.bridge_error_response(&e),
        }
    }

    /// 桥错误 → 响应（摄取成功后的错误分流与 wire 版本无关，v1/v2 共用）。
    fn bridge_error_response(&self, e: &eip3009::BridgeError) -> FacilitatorResponse {
        match e.gateway_unavailable_sdk() {
            // 网关不可达 → 503 fail-closed（与 mist-v1 同口径）。
            Some(sdk) => FacilitatorResponse {
                status: 503,
                body: gateway_error_body(sdk),
                headers: Vec::new(),
            },
            // 重放闸日志落盘失败（S-33）→ 503 fail-closed：运维故障不归罪 client，
            // 也不放行（内存表已登记，client 重试命中重放闸不重复摄取）。
            None => match e {
                eip3009::BridgeError::Journal(_) => FacilitatorResponse {
                    status: 503,
                    body: json_error_body(E_REPLAY_JOURNAL, &e.message()),
                    headers: Vec::new(),
                },
                _ => self.unauthorized(&e.message()),
            },
        }
    }

    /// 回执闸（唯一放行判定）：`Some` → 200 / `None` → 402 / 传输失败 → 503。
    fn receipt_gate(&self, intent_hash: [u8; 32]) -> FacilitatorResponse {
        match self.transport.receipt(intent_hash) {
            Ok(Some(_receipt)) => FacilitatorResponse::ok(&self.cfg.protected_body),
            Ok(None) => self.unauthorized(
                "receipt not verifiable (404 != unpaid: not found / settled / rejected)",
            ),
            Err(e) => FacilitatorResponse {
                status: 503,
                body: gateway_error_body(&e),
                headers: Vec::new(),
            },
        }
    }

    /// 资源绑定投影（桥校验用；构造失败是配置错误，panic 合理——启动即暴露）。
    fn binding(&self) -> &eip3009::ResourceBinding {
        self.binding.get_or_init(|| eip3009::ResourceBinding {
            network: self.cfg.network.clone(),
            resource: self.cfg.resource.clone(),
            pay_to: eip3009::parse_addr20(&self.cfg.pay_to).expect("bad facilitator payTo"),
            amount: self.cfg.amount.parse().expect("bad facilitator amount"),
            max_timeout_seconds: self.cfg.max_timeout_seconds,
        })
    }
}

/// unix 秒（ facilitator 单进程时钟；与网关的时钟偏差是部署事实，诚实边界）。
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

/// facilitator 响应（`http.rs` 负责写线；handle 只产出它）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacilitatorResponse {
    pub status: u16,
    pub body: String,
    /// 附加响应头（S-72：402 的 `PAYMENT-REQUIRED` v2 声明在此走线）。
    pub headers: Vec<(String, String)>,
}

impl FacilitatorResponse {
    fn ok(body: &str) -> Self {
        FacilitatorResponse {
            status: 200,
            body: body.to_string(),
            headers: Vec::new(),
        }
    }

    fn status(status: u16) -> Self {
        FacilitatorResponse {
            status,
            body: String::new(),
            headers: Vec::new(),
        }
    }
}

/// 网关传输错误 → JSON 错误体（fail-closed 可观测）。
fn gateway_error_body(e: &SdkError) -> String {
    json_error_body(E_GATEWAY_UNAVAILABLE, &e.to_string())
}

/// 运维侧故障（网关不可达 / 重放闸日志落盘失败）→ 统一形态的 503 错误体。
fn json_error_body(code: &str, message: &str) -> String {
    serde_json::json!({
        "error": {"code": code, "message": message}
    })
    .to_string()
}

/// 回执只读透传（类型重导出，方便 merchant 上层对账引用）。
pub type VerifiedReceipt = Receipt;

pub mod http;
