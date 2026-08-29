//! x402 merchant 参考实现（S-30c，TECH_SPEC §6.9，docs/x402-adapter.md §2.1 server 侧）。
//!
//! 受保护资源服务器怎么接 `meridian-v1` 支付：验证逻辑**全部**落在"对 Meridian 网关
//! 查回执"（S-30a 的 [`HttpTransport::receipt`] 即验证接口），零密码学依赖。
//!
//! # 分发逻辑（[`Facilitator::handle`] 纯分发，单测不经 socket）
//!
//! - `GET /healthz` → 200；其它路径 = 单一受保护资源（v1）。
//! - 无 `X-PAYMENT` → 402 + paymentRequirements（`scheme: meridian-v1`）。
//! - 带 `X-PAYMENT` → base64url 解码 → 校验 scheme/network/resource → 查网关：
//!   `Some` → 200 放行；`None` → 402（**404 ≠ 未支付**语义下"不可验证即不放行"）；
//!   `Err` → 503 fail-closed（验证面不可用绝不放行）。
//!
//! # 诚实边界（v1）
//!
//! 单资源模型、明文 HTTP（TLS 反代终结）、不产出 `X-PAYMENT-RESPONSE`（对账走网关
//! 查询）、结算侧（epoch claim、对账导出）不在本件——参考实现演示"merchant 怎么接"，
//! 不是生产 facilitator。

use std::sync::OnceLock;

use meridian_sdk::x402::{
    base64url_decode, PaymentPayload, PaymentRequired, PaymentRequirements, X402_VERSION,
};
use meridian_sdk::{HttpTransport, Receipt, SdkError};

/// x402 协议头名（与 agent 侧一致）。
pub const PAYMENT_HEADER: &str = "X-PAYMENT";
/// 网关查询失败（fail-closed）的传输层错误码。
pub const E_GATEWAY_UNAVAILABLE: &str = "E_GATEWAY_UNAVAILABLE";

/// facilitator 配置（单一受保护资源）。
#[derive(Debug, Clone)]
pub struct FacilitatorConfig {
    /// Meridian 网关地址，如 `"127.0.0.1:9400"`。
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
    /// 402 body 缓存（构造一次，每次原样返回）。
    payment_required: OnceLock<String>,
}

impl Facilitator {
    pub fn new(cfg: FacilitatorConfig) -> Self {
        let transport = HttpTransport::new(cfg.gateway_addr.clone(), cfg.gateway_bearer.clone());
        Facilitator {
            cfg,
            transport,
            payment_required: OnceLock::new(),
        }
    }

    pub fn config(&self) -> &FacilitatorConfig {
        &self.cfg
    }

    /// 402 体（`meridian-v1` 单条目；构造失败是配置错误，panic 合理——启动即暴露）。
    fn payment_required_json(&self) -> &str {
        self.payment_required.get_or_init(|| {
            let pr = PaymentRequired {
                x402_version: X402_VERSION,
                error: None,
                accepts: vec![PaymentRequirements {
                    scheme: meridian_sdk::x402::SCHEME.to_string(),
                    network: self.cfg.network.clone(),
                    max_amount_required: self.cfg.amount.clone(),
                    resource: self.cfg.resource.clone(),
                    description: None,
                    pay_to: self.cfg.pay_to.clone(),
                    max_timeout_seconds: Some(self.cfg.max_timeout_seconds),
                    asset: self.cfg.asset.clone(),
                }],
            };
            serde_json::to_string(&pr).expect("serialize 402 body")
        })
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
        }
    }

    /// 纯分发：method / path / X-PAYMENT 头 → 响应。单测不经 socket。
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
            return FacilitatorResponse {
                status: 402,
                body: self.payment_required_json().to_string(),
            };
        };

        // 1. base64url 解码（宽容 padding）。
        let decoded = match base64url_decode(header) {
            Ok(d) => d,
            Err(e) => return self.unauthorized(&format!("bad X-PAYMENT encoding: {e}")),
        };
        // 2. JSON 解析（PaymentPayload camelCase wire）。
        let payload: PaymentPayload = match serde_json::from_slice(&decoded) {
            Ok(p) => p,
            Err(e) => return self.unauthorized(&format!("bad X-PAYMENT payload: {e}")),
        };
        // 3. scheme / network / resource 绑定校验。
        if payload.scheme != meridian_sdk::x402::SCHEME {
            return self.unauthorized(&format!(
                "unsupported scheme {:?} (only {:?})",
                payload.scheme,
                meridian_sdk::x402::SCHEME
            ));
        }
        if payload.network != self.cfg.network {
            return self.unauthorized(&format!("network mismatch: {}", payload.network));
        }
        if payload.resource != self.cfg.resource {
            return self.unauthorized(&format!("resource mismatch: {}", payload.resource));
        }
        // 4. intentHash 解析（0x 前缀宽容）。
        let raw = payload
            .payload
            .intent_hash
            .strip_prefix("0x")
            .unwrap_or(&payload.payload.intent_hash);
        let ih_bytes = match hex::decode(raw) {
            Ok(b) => b,
            Err(e) => return self.unauthorized(&format!("bad intentHash hex: {e}")),
        };
        let intent_hash: [u8; 32] = match ih_bytes.try_into() {
            Ok(a) => a,
            Err(v) => {
                return self.unauthorized(&format!("intentHash must be 32 bytes, got {}", v.len()))
            }
        };
        // 5. 网关回执查询（唯一验证步骤）。fail-closed：网关不可用 → 503。
        match self.transport.receipt(intent_hash) {
            Ok(Some(_receipt)) => FacilitatorResponse::ok(&self.cfg.protected_body),
            Ok(None) => self.unauthorized(
                "receipt not verifiable (404 != unpaid: not found / settled / rejected)",
            ),
            Err(e) => FacilitatorResponse {
                status: 503,
                body: gateway_error_body(&e),
            },
        }
    }
}

/// facilitator 响应（`http.rs` 负责写线；handle 只产出它）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacilitatorResponse {
    pub status: u16,
    pub body: String,
}

impl FacilitatorResponse {
    fn ok(body: &str) -> Self {
        FacilitatorResponse {
            status: 200,
            body: body.to_string(),
        }
    }

    fn status(status: u16) -> Self {
        FacilitatorResponse {
            status,
            body: String::new(),
        }
    }
}

/// 网关传输错误 → JSON 错误体（fail-closed 可观测）。
fn gateway_error_body(e: &SdkError) -> String {
    serde_json::json!({
        "error": {"code": E_GATEWAY_UNAVAILABLE, "message": e.to_string()}
    })
    .to_string()
}

/// 回执只读透传（类型重导出，方便 merchant 上层对账引用）。
pub type VerifiedReceipt = Receipt;

pub mod http;
