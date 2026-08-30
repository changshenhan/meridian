//! Meridian 网络 ingest 网关（S-29，TECH_SPEC §6.7）。
//!
//! std-only 线程网关：把 `Aggregator::register` / `submit` 暴露为 HTTP/1.1 端点。
//! 分层——`Gateway::handle(method, path, bearer, body)` 是**纯分发**（不碰 socket，
//! 单测直接打）；`http::serve` 只做 TCP/HTTP 解析与线程池管理。
//!
//! 口径（§6.7）：
//! - 业务拒绝 = HTTP 200 + `Receipt.reject_reason`（定局，SDK 永不重试）；
//!   传输层错误（E_AUTH 401 / E_RATE_LIMITED 429 / E_MALFORMED 400）是独立错误面。
//! - 令牌桶按租户分桶：容量 = rpm（整分钟突发预算），补充 = rpm/60 每秒。
//!   超限请求**未进内核**——无 seq、无记账，SDK 可安全退避重试。
//! - 租户表热更（S-54）：`POST /v1/admin/tenants` 整表替换（撤销/接入/轮换同一操作面），
//!   `RwLock` 读多写少；admin_key 独立于租户表，未配置 = 端点不存在。

pub mod http;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use meridian_aggregator::ingest::Aggregator;
use meridian_aggregator::wire::{
    AuthorizeRequest, AuthorizeResponse, GatewayError, IntentEnvelopeDto, NextNonceResponse,
    ReceiptDto, RevocationWitnessResponse,
};

/// 传输层错误码（§11 补充表；不进 core `Error` 内核枚举）。
pub const E_AUTH: &str = "E_AUTH";
pub const E_RATE_LIMITED: &str = "E_RATE_LIMITED";
pub const E_MALFORMED: &str = "E_MALFORMED";
/// 只读查询未命中（S-30a `/v1/receipts`）：不存在 / 已结算修剪 / 被拒。
/// **404 ≠ 未支付**——终局保证在链上净额（§6.7 语义边界）。
pub const E_NOT_FOUND: &str = "E_NOT_FOUND";
/// 撤销 witness 查询（S-45 `/v1/revocation-witness`）目标已撤销——非成员陈述不属于该
/// 目标（S-42 fail-closed，成员证明不由本接口给出）。复用 §11 主表内核码字符串（wire
/// 层响应码，语义同主表「委托已撤销」），不进内核枚举实例化。
pub const E_REVOKED: &str = "E_REVOKED";

/// 网关配置（JSON 文件形态，§6.7）。
///
/// ```json
/// { "listen": "127.0.0.1:9400", "max_connections": 256, "read_timeout_ms": 5000,
///   "max_body_bytes": 65536, "admin_key": "<admin-bearer-key>",
///   "tenants": { "<bearer-key>": { "tenant": "acme", "rpm": 6000 } } }
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub listen: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_read_timeout_ms")]
    pub read_timeout_ms: u64,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    pub tenants: HashMap<String, TenantConf>,
    /// 管理面 bearer key（S-54，§6.7）：独立于租户表（不进 `tenants` map，不能当租户
    /// key 用）。缺省不配置 = 管理端点不存在（404，不泄露管理面存在性）。
    #[serde(default)]
    pub admin_key: Option<String>,
}

fn default_max_connections() -> usize {
    256
}
fn default_read_timeout_ms() -> u64 {
    5000
}
fn default_max_body_bytes() -> usize {
    64 * 1024
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TenantConf {
    pub tenant: String,
    pub rpm: u64,
}

impl Config {
    pub fn from_json(s: &str) -> Result<Self, String> {
        serde_json::from_str(s).map_err(|e| format!("bad gateway config: {e}"))
    }

    pub fn from_path(p: &std::path::Path) -> Result<Self, String> {
        let s = std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))?;
        Self::from_json(&s)
    }
}

/// 租户表：bearer key → (租户 id, rpm)。
#[derive(Debug, Clone)]
pub struct TenantTable {
    by_key: HashMap<String, (String, u64)>,
}

impl TenantTable {
    pub fn from_conf(tenants: &HashMap<String, TenantConf>) -> Self {
        TenantTable {
            by_key: tenants
                .iter()
                .map(|(k, v)| (k.clone(), (v.tenant.clone(), v.rpm)))
                .collect(),
        }
    }

    pub fn lookup(&self, bearer: Option<&str>) -> Option<&(String, u64)> {
        let key = bearer?;
        self.by_key.get(key)
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

/// 每租户令牌桶（§6.7：std Mutex，容量 = rpm，补充 = rpm/60 每秒）。
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// 取一个令牌；`rpm` 是该租户速率上限。租户首见时桶满（整分钟突发预算一次给足，
    /// 与"容量 = rpm"口径一致——突发被限在 rpm，稳态被限在 rpm/60 每秒）。
    pub fn try_acquire(&self, tenant: &str, rpm: u64) -> bool {
        let mut buckets = self.buckets.lock().expect("rate limiter poisoned");
        let now = Instant::now();
        let b = buckets.entry(tenant.to_string()).or_insert(Bucket {
            tokens: rpm as f64,
            last: now,
        });
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * rpm as f64 / 60.0).min(rpm as f64);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// HTTP 响应（`http.rs` 负责写线；`Gateway::handle` 只产出它）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    pub fn json(status: u16, body: String) -> Self {
        Response { status, body }
    }

    pub fn error(status: u16, code: &str, message: impl Into<String>) -> Self {
        let err = GatewayError::new(code, message);
        Response {
            status,
            body: serde_json::to_string(&err).expect("GatewayError serializes"),
        }
    }
}

/// 网关：内核句柄 + 租户表（RwLock，S-54 整表热更）+ 限流器。经 `Arc` 共享给连接线程。
pub struct Gateway {
    agg: Arc<Aggregator>,
    /// 读多写少（S-54）：`gate()` 取读锁，热更端点锁内整体换表——并发请求要么见旧表
    /// 要么见新表，无「认证旧表 + 限流新表」的撕裂读。
    tenants: RwLock<TenantTable>,
    limiter: RateLimiter,
    max_body: usize,
    admin_key: Option<String>,
}

/// 管理端点响应（S-54）：整表替换成功后的摘要。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AdminReloadResponse {
    pub reloaded: bool,
    pub tenants: usize,
}

impl Gateway {
    pub fn new(agg: Arc<Aggregator>, cfg: &Config) -> Self {
        Gateway {
            agg,
            tenants: RwLock::new(TenantTable::from_conf(&cfg.tenants)),
            limiter: RateLimiter::default(),
            max_body: cfg.max_body_bytes,
            admin_key: cfg.admin_key.clone(),
        }
    }

    /// 供单测注入租户表（不走配置文件；管理端点缺省不存在，admin_key = None）。
    pub fn with_tenants(agg: Arc<Aggregator>, tenants: TenantTable, max_body: usize) -> Self {
        Gateway {
            agg,
            tenants: RwLock::new(tenants),
            limiter: RateLimiter::default(),
            max_body,
            admin_key: None,
        }
    }

    /// 注入管理面 key（builder，链在 `with_tenants`/`new` 之后）。
    pub fn with_admin_key(mut self, admin_key: Option<String>) -> Self {
        self.admin_key = admin_key;
        self
    }

    /// S-54 租户表整表替换（§6.7 管理面）：撤销 = 删 key、接入 = 加 key、轮换 = 同
    /// tenant id 换 key（令牌桶按 tenant id 分桶，轮换不重置限流状态）。返回替换后
    /// 租户 key 数。
    pub fn reload_tenants(&self, table: TenantTable) -> usize {
        let n = table.len();
        *self.tenants.write().expect("tenant table poisoned") = table;
        n
    }

    /// 纯分发：不碰 socket。`bearer` 取自 `Authorization: Bearer <key>` 头。
    pub fn handle(&self, method: &str, path: &str, bearer: Option<&str>, body: &[u8]) -> Response {
        match (method, path) {
            ("GET", "/healthz") => self.handle_healthz(),
            ("POST", "/v1/admin/tenants") => self.handle_admin_tenants(bearer, body),
            ("POST", "/v1/authorize") => {
                self.handle_authorized(bearer, body, Self::handle_authorize)
            }
            ("POST", "/v1/intents") => self.handle_authorized(bearer, body, Self::handle_intents),
            ("GET", p) if p.starts_with("/v1/receipts/") => {
                self.handle_receipt_lookup(bearer, &p["/v1/receipts/".len()..])
            }
            ("GET", p) if p.starts_with("/v1/nonce/") => {
                self.handle_nonce_lookup(bearer, &p["/v1/nonce/".len()..])
            }
            ("GET", p) if p.starts_with("/v1/revocation-witness/") => {
                self.handle_revocation_witness(bearer, &p["/v1/revocation-witness/".len()..])
            }
            ("POST", _) | ("GET", _) => Response::error(404, E_MALFORMED, "unknown route"),
            _ => Response::error(405, E_MALFORMED, "method not allowed"),
        }
    }

    fn handle_healthz(&self) -> Response {
        let snap = self.agg.snapshot();
        Response::json(
            200,
            format!(
                "{{\"status\":\"ok\",\"accepted_count\":{},\"instance\":\"{}\"}}",
                snap.accepted_count,
                snap.instance_id.replace('\\', "/").replace('"', "'")
            ),
        )
    }

    /// 共用租户闸：认证 → 限流（§6.7 顺序固定）。GET 只读路径与 POST 写路径同闸。
    /// 认证与限流共用一次读锁快照（S-54 整表热更下两者必出自同一张表）。
    fn gate(&self, bearer: Option<&str>) -> Result<(), Response> {
        let table = self.tenants.read().expect("tenant table poisoned");
        let Some((tenant, rpm)) = table.lookup(bearer) else {
            return Err(Response::error(
                401,
                E_AUTH,
                "missing or unknown bearer key",
            ));
        };
        if !self.limiter.try_acquire(tenant, *rpm) {
            return Err(Response::error(
                429,
                E_RATE_LIMITED,
                "tenant rate limit exceeded",
            ));
        }
        Ok(())
    }

    /// S-54 管理端点：`POST /v1/admin/tenants`（§6.7）。admin_key 未配置 = 端点不存在
    /// （404 同未路由路径，不泄露管理面）；key 不符 → 401；body 非法 → 400；超限 → 413。
    /// 管理请求不走租户限流（admin key 不在租户表，本就无从限流）。
    fn handle_admin_tenants(&self, bearer: Option<&str>, body: &[u8]) -> Response {
        let Some(admin) = self.admin_key.as_deref() else {
            return Response::error(404, E_MALFORMED, "unknown route");
        };
        if bearer != Some(admin) {
            return Response::error(401, E_AUTH, "missing or unknown admin key");
        }
        if body.len() > self.max_body {
            return Response::error(413, E_MALFORMED, "request body too large");
        }
        let tenants: HashMap<String, TenantConf> = match serde_json::from_slice(body) {
            Ok(t) => t,
            Err(e) => return Response::error(400, E_MALFORMED, format!("bad JSON: {e}")),
        };
        let n = self.reload_tenants(TenantTable::from_conf(&tenants));
        let resp = AdminReloadResponse {
            reloaded: true,
            tenants: n,
        };
        Response::json(
            200,
            serde_json::to_string(&resp).expect("AdminReloadResponse serializes"),
        )
    }

    /// 认证 → 限流 → body 上限 → 分发。共用闸门顺序固定（§6.7）。
    fn handle_authorized(
        &self,
        bearer: Option<&str>,
        body: &[u8],
        f: fn(&Self, &[u8]) -> Response,
    ) -> Response {
        if let Err(r) = self.gate(bearer) {
            return r;
        }
        if body.len() > self.max_body {
            return Response::error(413, E_MALFORMED, "request body too large");
        }
        f(self, body)
    }

    /// S-30a 只读回执查询：`GET /v1/receipts/{intent_hash}`（§6.7）。走租户闸
    /// （认证 + 限流）；GET 无 body，不做 body 上限检查。
    /// 命中 → 200 + ReceiptDto（accepted 回执）；未命中 → 404 `E_NOT_FOUND`
    /// （**404 ≠ 未支付**：已结算修剪 / 被拒 / 从未见——终局保证在链上净额）。
    fn handle_receipt_lookup(&self, bearer: Option<&str>, hash_hex: &str) -> Response {
        if let Err(r) = self.gate(bearer) {
            return r;
        }
        // 0x 前缀宽容（x402 生态惯例是 0x hex）；其余不合法 → 400。
        let hash_hex = hash_hex.strip_prefix("0x").unwrap_or(hash_hex);
        let ih = match meridian_aggregator::wire::hex_to_bytes32(hash_hex) {
            Ok(ih) => ih,
            Err(e) => return Response::error(400, E_MALFORMED, format!("bad intent_hash: {e}")),
        };
        match self.agg.receipt(&ih) {
            Some(r) => {
                let dto = ReceiptDto::from_receipt(&r);
                Response::json(
                    200,
                    serde_json::to_string(&dto).expect("ReceiptDto serializes"),
                )
            }
            None => Response::error(404, E_NOT_FOUND, "receipt not found"),
        }
    }

    /// S-31 只读下一 nonce 查询：`GET /v1/nonce/{delegation_hash}`（§6.7，§6.6 跨重启
    /// 恢复面）。走租户闸（认证 + 限流）；GET 无 body。命中 → 200 + `NextNonceResponse`
    /// （`max(已消耗) + 1` 安全下界）；未注册委托 → 404 `E_NOT_FOUND`。
    fn handle_nonce_lookup(&self, bearer: Option<&str>, hash_hex: &str) -> Response {
        if let Err(r) = self.gate(bearer) {
            return r;
        }
        // 0x 前缀宽容（与 /v1/receipts 同口径）。
        let hash_hex = hash_hex.strip_prefix("0x").unwrap_or(hash_hex);
        let dh = match meridian_aggregator::wire::hex_to_bytes32(hash_hex) {
            Ok(dh) => dh,
            Err(e) => {
                return Response::error(400, E_MALFORMED, format!("bad delegation_hash: {e}"))
            }
        };
        match self.agg.next_nonce(&dh) {
            Some(next) => {
                let dto = NextNonceResponse {
                    delegation_hash: hex::encode(dh),
                    next_nonce: next,
                };
                Response::json(
                    200,
                    serde_json::to_string(&dto).expect("NextNonceResponse serializes"),
                )
            }
            None => Response::error(404, E_NOT_FOUND, "delegation not registered"),
        }
    }

    /// S-45 只读撤销非成员 witness 查询：`GET /v1/revocation-witness/{delegation_hash}`
    /// （§6.7，§6.14 诚实边界 3 SDK 半边）。走租户闸（认证 + 限流）；GET 无 body。
    /// 命中 → 200 + `RevocationWitnessResponse`（root + 深度 256 兄弟路径扁平 hex，同一
    /// 棵确定性树）；目标已撤销 → 404 `E_REVOKED`（成员陈述不由本接口给出，S-42
    /// fail-closed）。未注册的 delegation_hash 照常返回 witness（只读事实面，注册校验
    /// 在摄取管线步 1）。
    fn handle_revocation_witness(&self, bearer: Option<&str>, hash_hex: &str) -> Response {
        if let Err(r) = self.gate(bearer) {
            return r;
        }
        // 0x 前缀宽容（与 /v1/receipts、/v1/nonce 同口径）。
        let hash_hex = hash_hex.strip_prefix("0x").unwrap_or(hash_hex);
        let dh = match meridian_aggregator::wire::hex_to_bytes32(hash_hex) {
            Ok(dh) => dh,
            Err(e) => {
                return Response::error(400, E_MALFORMED, format!("bad delegation_hash: {e}"))
            }
        };
        match self.agg.revocation_witness(&dh) {
            Some(w) => {
                let dto = RevocationWitnessResponse::from_witness(&dh, &w);
                Response::json(
                    200,
                    serde_json::to_string(&dto).expect("RevocationWitnessResponse serializes"),
                )
            }
            None => Response::error(404, E_REVOKED, "delegation revoked"),
        }
    }

    fn handle_authorize(&self, body: &[u8]) -> Response {
        let req: AuthorizeRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return Response::error(400, E_MALFORMED, format!("bad JSON: {e}")),
        };
        let (sd, agent_pub) = match req.to_parts() {
            Ok(p) => p,
            Err(e) => return Response::error(400, E_MALFORMED, e),
        };
        // register 返回 ()：DSA 验签在链上登记事件层已完成（ingest.rs 合约口径），
        // 网关只转发。WAL 失败 = 进程 panic（§6.7 状态表 5xx 行，进程管理器兜底）。
        self.agg.register(sd, agent_pub);
        let resp = AuthorizeResponse { registered: true };
        Response::json(
            200,
            serde_json::to_string(&resp).expect("AuthorizeResponse serializes"),
        )
    }

    fn handle_intents(&self, body: &[u8]) -> Response {
        let dto: IntentEnvelopeDto = match serde_json::from_slice(body) {
            Ok(d) => d,
            Err(e) => return Response::error(400, E_MALFORMED, format!("bad JSON: {e}")),
        };
        let env = match dto.into_envelope() {
            Ok(e) => e,
            Err(e) => return Response::error(400, E_MALFORMED, e),
        };
        // 业务拒绝 = 200 + Receipt.reject_reason（定局，§6.7 状态表）。
        let receipt = self.agg.submit(&env);
        let dto = ReceiptDto::from_receipt(&receipt);
        Response::json(
            200,
            serde_json::to_string(&dto).expect("ReceiptDto serializes"),
        )
    }
}
