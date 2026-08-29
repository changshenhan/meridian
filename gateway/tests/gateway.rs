//! S-29 网关验收（TECH_SPEC §6.7）：
//! - `Gateway::handle` 纯分发单测：认证 / 限流 / 畸形请求 / healthz / 路由。
//! - **真 socket e2e**：`serve` + SDK `HttpTransport` + `SdkClient` 全链路——authorize →
//!   pay×2 → 业务拒绝不重试 → 传输断连重试幂等（聚合器记账恰一次）。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::proof::FormatVerifier;
use meridian_aggregator::wal::Wal;
use meridian_core::dsa::owner_signing_key_from_bytes;
use meridian_gateway::http::serve;
use meridian_gateway::{
    Config, Gateway, TenantConf, TenantTable, E_AUTH, E_MALFORMED, E_NOT_FOUND, E_RATE_LIMITED,
};
use meridian_sdk::{
    AgentWallet, DelegationLimits, HttpTransport, PayParams, RetryPolicy, SdkClient, SdkError,
};

// ---------------------------------------------------------------------------
// 脚手架
// ---------------------------------------------------------------------------

static WAL_SEQ: AtomicU32 = AtomicU32::new(0);

fn wal_path(tag: &str) -> PathBuf {
    let seq = WAL_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "meridian-gw-{}-{tag}-{seq}.wal",
        std::process::id()
    ))
}

fn aggregator(tag: &str) -> (PathBuf, Arc<Aggregator>) {
    let path = wal_path(tag);
    let _ = std::fs::remove_file(&path);
    let wal = Wal::open(&path, 1_000).expect("open wal");
    let agg = Arc::new(Aggregator::new(
        IngestConfig::default(),
        Box::new(FormatVerifier),
        wal,
    ));
    (path, agg)
}

fn tenants_one(key: &str, tenant: &str, rpm: u64) -> TenantTable {
    let mut m = HashMap::new();
    m.insert(
        key.to_string(),
        TenantConf {
            tenant: tenant.to_string(),
            rpm,
        },
    );
    TenantTable::from_conf(&m)
}

/// HTTP 原始请求（单测不经 SDK，直接打 socket 验证线格式）。
fn raw_post(addr: &str, path: &str, bearer: Option<&str>, body: &[u8]) -> (u16, String) {
    let mut s = std::net::TcpStream::connect(addr).expect("connect");
    let auth = bearer
        .map(|b| format!("Authorization: Bearer {b}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: t\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let status: u16 = resp
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .expect("status line");
    let body = resp
        .rsplit_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

fn limits(max_per_spend: u64) -> DelegationLimits {
    DelegationLimits {
        max_per_spend,
        rate_window_secs: 60,
        rate_max_per_window: 10_000,
        total_cap: 10_000,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
    }
}

fn wallet_and_owner() -> (AgentWallet, k256::ecdsa::SigningKey) {
    let wallet = AgentWallet::from_seed([9u8; 32]);
    let owner_key = owner_signing_key_from_bytes([7u8; 32]);
    (wallet, owner_key)
}

fn pay_params(dh: [u8; 32], amount: u64) -> PayParams {
    PayParams {
        delegation_hash: dh,
        recipient: [3u8; 20],
        amount,
        category: [0xCD; 32],
        memo: None,
        expires_at: u64::MAX,
    }
}

// ---------------------------------------------------------------------------
// 1. Gateway::handle 纯分发单测
// ---------------------------------------------------------------------------

#[test]
fn handle_healthz_reports_kernel_counts() {
    let (_p, agg) = aggregator("healthz");
    let gw = Gateway::with_tenants(agg, tenants_one("k1", "t1", 1_000), 64 * 1024);
    let resp = gw.handle("GET", "/healthz", None, b"");
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("\"status\":\"ok\""));
    assert!(resp.body.contains("\"accepted_count\":0"));
}

#[test]
fn handle_rejects_missing_and_unknown_bearer() {
    let (_p, agg) = aggregator("auth");
    let gw = Gateway::with_tenants(agg, tenants_one("k1", "t1", 1_000), 64 * 1024);

    let r = gw.handle("POST", "/v1/intents", None, b"{}");
    assert_eq!(r.status, 401);
    assert!(r.body.contains(E_AUTH));

    let r = gw.handle("POST", "/v1/intents", Some("wrong-key"), b"{}");
    assert_eq!(r.status, 401);
    assert!(r.body.contains(E_AUTH));
}

#[test]
fn handle_rate_limits_per_tenant() {
    let (_p, agg) = aggregator("rate");
    let gw = Gateway::with_tenants(agg, tenants_one("k1", "t1", 2), 64 * 1024);

    // 前两发过闸（到达 JSON 解析 → 400 malformed）；第三发被令牌桶 429 挡下。
    let r1 = gw.handle("POST", "/v1/intents", Some("k1"), b"not-json");
    assert_eq!(r1.status, 400);
    assert!(r1.body.contains(E_MALFORMED));
    let r2 = gw.handle("POST", "/v1/intents", Some("k1"), b"not-json");
    assert_eq!(r2.status, 400);
    let r3 = gw.handle("POST", "/v1/intents", Some("k1"), b"not-json");
    assert_eq!(r3.status, 429);
    assert!(r3.body.contains(E_RATE_LIMITED));
}

#[test]
fn handle_rejects_malformed_body_and_bad_hex() {
    let (_p, agg) = aggregator("malformed");
    let gw = Gateway::with_tenants(agg, tenants_one("k1", "t1", 1_000), 64 * 1024);

    let r = gw.handle("POST", "/v1/authorize", Some("k1"), b"{not json");
    assert_eq!(r.status, 400);
    assert!(r.body.contains(E_MALFORMED));

    // signed_delegation 反序列化失败（null）与 JSON 语法错都归 E_MALFORMED（400）。
    let r = gw.handle(
        "POST",
        "/v1/authorize",
        Some("k1"),
        br#"{"signed_delegation":null,"agent_pub":"zz"}"#,
    );
    assert_eq!(r.status, 400);
    assert!(r.body.contains(E_MALFORMED));
}

#[test]
fn handle_rejects_unknown_route_and_method() {
    let (_p, agg) = aggregator("routes");
    let gw = Gateway::with_tenants(agg, tenants_one("k1", "t1", 1_000), 64 * 1024);
    assert_eq!(gw.handle("POST", "/nope", Some("k1"), b"").status, 404);
    assert_eq!(gw.handle("PUT", "/v1/intents", Some("k1"), b"").status, 405);
}

/// S-30a 只读回执查询闸门：与写端点同租户闸（401）+ 坏 hash 400 + 未命中 404
/// `E_NOT_FOUND`（0x 前缀宽容）。
#[test]
fn handle_receipt_lookup_gate_and_hash_validation() {
    let (_p, agg) = aggregator("receipt-gate");
    let gw = Gateway::with_tenants(agg, tenants_one("k1", "t1", 1_000), 64 * 1024);

    // 无认证 → 401（只读端点走同一租户闸）。
    let r = gw.handle("GET", "/v1/receipts/00", None, b"");
    assert_eq!(r.status, 401);
    assert!(r.body.contains(E_AUTH));

    // 坏 hex / 错长度 → 400。
    for bad in ["zz", "00", &hex::encode([1u8; 31])] {
        let r = gw.handle("GET", &format!("/v1/receipts/{bad}"), Some("k1"), b"");
        assert_eq!(r.status, 400, "bad hash {bad:?}");
        assert!(r.body.contains(E_MALFORMED));
    }

    // 0x 前缀宽容；未命中 → 404 E_NOT_FOUND（非 400——hash 格式对、只是没有回执）。
    let r = gw.handle(
        "GET",
        &format!("/v1/receipts/0x{}", hex::encode([7u8; 32])),
        Some("k1"),
        b"",
    );
    assert_eq!(r.status, 404);
    assert!(r.body.contains(E_NOT_FOUND));
}

/// S-31 只读下一 nonce 查询闸门：与写端点同租户闸（401）+ 坏 hash 400 + 未注册委托
/// 404 `E_NOT_FOUND`（0x 前缀宽容，与 /v1/receipts 同口径）。
#[test]
fn handle_nonce_lookup_gate_and_hash_validation() {
    let (_p, agg) = aggregator("nonce-gate");
    let gw = Gateway::with_tenants(agg, tenants_one("k1", "t1", 1_000), 64 * 1024);

    // 无认证 → 401（只读端点走同一租户闸）。
    let r = gw.handle("GET", "/v1/nonce/00", None, b"");
    assert_eq!(r.status, 401);
    assert!(r.body.contains(E_AUTH));

    // 坏 hex / 错长度 → 400。
    for bad in ["zz", "00", &hex::encode([1u8; 31])] {
        let r = gw.handle("GET", &format!("/v1/nonce/{bad}"), Some("k1"), b"");
        assert_eq!(r.status, 400, "bad hash {bad:?}");
        assert!(r.body.contains(E_MALFORMED));
    }

    // 0x 前缀宽容；未注册委托 → 404 E_NOT_FOUND。
    let r = gw.handle(
        "GET",
        &format!("/v1/nonce/0x{}", hex::encode([7u8; 32])),
        Some("k1"),
        b"",
    );
    assert_eq!(r.status, 404);
    assert!(r.body.contains(E_NOT_FOUND));
}

#[test]
fn handle_enforces_body_cap() {
    let (_p, agg) = aggregator("bodycap");
    let gw = Gateway::with_tenants(agg, tenants_one("k1", "t1", 1_000), 64);
    let big = vec![b'a'; 65];
    assert_eq!(
        gw.handle("POST", "/v1/intents", Some("k1"), &big).status,
        413
    );
}

#[test]
fn config_roundtrip_and_tenant_loading() {
    let cfg = Config::from_json(
        r#"{"listen":"127.0.0.1:9400","tenants":{"secret":{"tenant":"acme","rpm":6000}}}"#,
    )
    .expect("parse config");
    assert_eq!(cfg.max_connections, 256); // 默认值
    assert_eq!(cfg.read_timeout_ms, 5000);
    assert_eq!(cfg.max_body_bytes, 64 * 1024);
    let table = TenantTable::from_conf(&cfg.tenants);
    assert_eq!(table.len(), 1);
    let (tenant, rpm) = table.lookup(Some("secret")).expect("key found");
    assert_eq!((tenant.as_str(), *rpm), ("acme", 6000));
    assert!(table.lookup(Some("nope")).is_none());
    assert!(table.lookup(None).is_none());
}

// ---------------------------------------------------------------------------
// 2. 真 socket e2e：serve + HttpTransport + SdkClient 全链路
// ---------------------------------------------------------------------------

/// 起一个真实网关（随机端口，后台线程），返回 (addr, agg句柄)。
fn spawn_gateway(tag: &str) -> (String, Arc<Aggregator>) {
    let (_wal, agg) = aggregator(tag);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let gw = Arc::new(Gateway::with_tenants(
        Arc::clone(&agg),
        tenants_one("e2e-key", "e2e-tenant", u64::MAX),
        64 * 1024,
    ));
    std::thread::spawn(move || {
        let _ = serve(gw, listener, 256, Duration::from_secs(5));
    });
    (addr, agg)
}

#[test]
fn e2e_authorize_and_pay_over_http() {
    let (addr, agg) = spawn_gateway("e2e-full");
    let transport = HttpTransport::new(&addr, "e2e-key");
    let (wallet, owner) = wallet_and_owner();
    let mut client = SdkClient::new(wallet, Box::new(transport));
    client.set_retry(RetryPolicy {
        max_attempts: 3,
        base_backoff_ms: 0,
        max_backoff_ms: 0,
    });

    // authorize over HTTP。
    let rec = client.authorize(&owner, [1u8; 20], &limits(1_000)).unwrap();
    let dh = rec.delegation_hash;

    // pay×2：seq 单调、聚合器记账精确。
    let r1 = client.pay(&pay_params(dh, 42)).unwrap();
    assert_eq!(r1.seq, 0);
    let r2 = client.pay(&pay_params(dh, 7)).unwrap();
    assert_eq!(r2.seq, 1);
    assert_eq!(agg.accepted_count(), 2);
    assert_eq!(agg.total_spent(&dh), Some(49));

    // healthz 反映内核计数。
    let (status, body) = raw_get(&addr, "/healthz", None);
    assert_eq!(status, 200);
    assert!(
        body.contains("\"accepted_count\":2"),
        "healthz body: {body}"
    );

    // 真 socket POST 无认证 → 401（线格式 + 认证闸，不经 SDK 客户端）。
    let (status, body) = raw_post(&addr, "/v1/intents", None, b"{}");
    assert_eq!(status, 401);
    assert!(body.contains("E_AUTH"), "body: {body}");
}

/// GET（可选 Bearer；healthz 不走租户闸，`/v1/receipts` 走）。
fn raw_get(addr: &str, path: &str, bearer: Option<&str>) -> (u16, String) {
    let mut s = std::net::TcpStream::connect(addr).expect("connect");
    let auth = bearer
        .map(|b| format!("Authorization: Bearer {b}\r\n"))
        .unwrap_or_default();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: t\r\n{auth}Connection: close\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let status: u16 = resp
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .expect("status line");
    let body = resp
        .rsplit_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

/// S-30a x402 merchant 验证流：pay 后凭 intent_hash 查受理回执（seq 一致）；
/// 未受理 hash → None；原始 GET 走租户闸（带认证 200 / 无认证 401）。
#[test]
fn e2e_receipt_lookup_x402_merchant_flow() {
    let (addr, agg) = spawn_gateway("e2e-receipt");
    let transport = HttpTransport::new(&addr, "e2e-key");
    let (wallet, owner) = wallet_and_owner();
    let mut client = SdkClient::new(wallet, Box::new(transport));
    client.set_retry(RetryPolicy {
        max_attempts: 3,
        base_backoff_ms: 0,
        max_backoff_ms: 0,
    });

    let rec = client.authorize(&owner, [1u8; 20], &limits(1_000)).unwrap();
    let dh = rec.delegation_hash;
    let r1 = client.pay(&pay_params(dh, 42)).unwrap();

    // merchant 侧独立客户端（同租户 key）：payload 只带 intent_hash → 查询受理回执。
    let merchant = HttpTransport::new(&addr, "e2e-key");
    let got = merchant
        .receipt(r1.intent_hash)
        .expect("query ok")
        .expect("accepted intent queryable");
    assert!(got.accepted);
    assert_eq!(got.seq, r1.seq);
    assert_eq!(got.intent_hash, r1.intent_hash);
    assert_eq!(got.reject_reason, None);

    // 聚合器句柄同源一致。
    assert_eq!(agg.receipt(&r1.intent_hash).unwrap().seq, r1.seq);

    // 从未见过的 hash → Ok(None)。
    assert!(merchant.receipt([0xEE; 32]).unwrap().is_none());

    // 原始 GET：带认证 200 + ReceiptDto；无认证 401（只读端点走租户闸）。
    let path = format!("/v1/receipts/{}", hex::encode(r1.intent_hash));
    let (status, body) = raw_get(&addr, &path, Some("e2e-key"));
    assert_eq!(status, 200);
    assert!(body.contains("\"accepted\":true"), "body: {body}");
    assert!(
        body.contains(&format!("\"seq\":{}", r1.seq)),
        "body: {body}"
    );
    let (status, body) = raw_get(&addr, &path, None);
    assert_eq!(status, 401);
    assert!(body.contains("E_AUTH"), "body: {body}");
}

/// S-31 跨重启 nonce 恢复：pay×2 后重启新客户端（同钱包）——不 sync 直接 pay 撞已消耗
/// nonce（`E_NONCE` 业务拒）；`sync_nonce` 查询网关推进计数后 pay 成功；原始 GET 验证
/// 线格式（`max(已消耗) + 1`，带认证 200 / 无认证 401 / 未注册 404）。
#[test]
fn e2e_next_nonce_query_restarts_sdk_recovery() {
    let (addr, agg) = spawn_gateway("e2e-nonce");
    let (wallet, owner) = wallet_and_owner();

    // 第一段进程：authorize + pay×2。
    {
        let transport = HttpTransport::new(&addr, "e2e-key");
        let mut client = SdkClient::new(wallet.clone(), Box::new(transport));
        client.set_retry(RetryPolicy {
            max_attempts: 3,
            base_backoff_ms: 0,
            max_backoff_ms: 0,
        });
        let rec = client.authorize(&owner, [1u8; 20], &limits(1_000)).unwrap();
        let dh = rec.delegation_hash;
        client.pay(&pay_params(dh, 42)).unwrap();
        client.pay(&pay_params(dh, 43)).unwrap();
    } // 模拟重启：客户端（含 NonceManager）丢弃，聚合器存活。

    // 重启后的进程：新客户端从 nonce 0 重新计数。
    let transport = HttpTransport::new(&addr, "e2e-key");
    let mut client = SdkClient::new(wallet, Box::new(transport));
    client.set_retry(RetryPolicy {
        max_attempts: 3,
        base_backoff_ms: 0,
        max_backoff_ms: 0,
    });
    let rec = client.authorize(&owner, [1u8; 20], &limits(1_000)).unwrap();
    let dh = rec.delegation_hash;

    // 不恢复直接 pay → 跨意图复用 nonce 0 → E_NONCE（不双花，但不可用）。
    let err = client.pay(&pay_params(dh, 44)).unwrap_err();
    assert_eq!(
        err.code(),
        "E_NONCE",
        "expected nonce reuse rejection: {err:?}"
    );

    // sync_nonce：查网关 → 推进到 max(已接受) + 1 = 2 → 后续支付正常。
    assert_eq!(client.sync_nonce(&dh).unwrap(), 2);
    let r = client.pay(&pay_params(dh, 44)).unwrap();
    assert_eq!(r.spend_nonce, 2, "恢复后从网关值起计");
    assert_eq!(client.sync_nonce(&dh).unwrap(), 3, "支付后计数同步推进");

    // 原始 GET 线格式：带认证 200（delegation_hash 回显 + next_nonce）；无认证 401。
    let path = format!("/v1/nonce/{}", hex::encode(dh));
    let (status, body) = raw_get(&addr, &path, Some("e2e-key"));
    assert_eq!(status, 200);
    assert!(
        body.contains(&format!("\"next_nonce\":{}", 3)),
        "body: {body}"
    );
    assert!(body.contains(&hex::encode(dh)), "body: {body}");
    let (status, body) = raw_get(&addr, &path, None);
    assert_eq!(status, 401);
    assert!(body.contains("E_AUTH"), "body: {body}");

    // 未注册委托 → 404；SDK 视角 = Ok(None)（未注册 → sync_nonce 报 Local）。
    let transport2 = HttpTransport::new(&addr, "e2e-key");
    assert!(transport2.next_nonce([0xEE; 32]).unwrap().is_none());

    // 聚合器句柄同源一致。
    assert_eq!(agg.next_nonce(&dh), Some(3));
}

#[test]
fn e2e_business_rejection_is_final_not_transport() {
    let (addr, _agg) = spawn_gateway("e2e-reject");
    let transport = HttpTransport::new(&addr, "e2e-key");
    let (wallet, owner) = wallet_and_owner();
    let mut client = SdkClient::new(wallet, Box::new(transport));
    client.set_retry(RetryPolicy {
        max_attempts: 5,
        base_backoff_ms: 0,
        max_backoff_ms: 0,
    });

    let rec = client.authorize(&owner, [1u8; 20], &limits(1_000)).unwrap();
    let dh = rec.delegation_hash;

    // 超单笔上限：业务拒绝经 200 + reject_reason 透传 → SdkError::Meridian（非 Transport）。
    let err = client.pay(&pay_params(dh, 2_000)).unwrap_err();
    assert!(
        matches!(err, SdkError::Meridian(_)),
        "business rejection must not surface as transport error: {err:?}"
    );
    assert_eq!(err.code(), "E_BUDGET_PER_SPEND");
}

#[test]
fn e2e_bad_bearer_surfaces_local_error() {
    let (addr, _agg) = spawn_gateway("e2e-badauth");
    let transport = HttpTransport::new(&addr, "not-a-key");
    let (wallet, owner) = wallet_and_owner();
    let mut client = SdkClient::new(wallet, Box::new(transport));
    client.set_retry(RetryPolicy {
        max_attempts: 3,
        base_backoff_ms: 0,
        max_backoff_ms: 0,
    });

    // 401 → Local（配置错误，不重试）。
    let err = client
        .authorize(&owner, [1u8; 20], &limits(1_000))
        .unwrap_err();
    assert!(
        matches!(err, SdkError::Local(_)),
        "auth failure must not surface as transport error: {err:?}"
    );
    assert!(err.code().contains("E_AUTH"));
}

#[test]
fn e2e_connection_refused_is_transport_retry_candidate() {
    // 无人监听的端口 → Disconnected → Transport（重试候选）。
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    drop(listener); // 释放端口

    let transport = HttpTransport::new(&addr, "e2e-key");
    let (wallet, owner) = wallet_and_owner();
    let client = SdkClient::new(wallet, Box::new(transport));
    let err = client
        .authorize(&owner, [1u8; 20], &limits(1_000))
        .unwrap_err();
    assert!(
        matches!(err, SdkError::Transport(_)),
        "connection refused must be a transport error: {err:?}"
    );
}
