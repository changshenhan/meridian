//! S-30c facilitator 验收（TECH_SPEC §6.9）：
//! - `Facilitator::handle` 纯分发单测：402 wire 可被 sdk 反解析 / 坏 base64 / 错
//!   scheme / 错 network / 错 resource / 坏 intentHash → 402；405 / healthz / 404。
//! - **三角色真 socket e2e**：X402Client（HttpFetch）→ facilitator 402 → 真网关 pay
//!   （真密码学 + 真聚合器记账）→ X-PAYMENT 重放 → facilitator 查网关回执 → 200；
//!   伪造 intentHash → 402。
//! - **S-33 重放闸持久化**：facilitator 带 ReplayJournal 摄取 → 销毁重建（同日志路径）
//!   → 同 payload 重放 200 且不重复摄取；新 nonce 正常摄取。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mist_aggregator::bb::{BbBackend, BbVerifier};
use mist_aggregator::ingest::{Aggregator, IngestConfig};
use mist_aggregator::proof::FormatVerifier;
use mist_aggregator::wal::Wal;
use mist_core::dsa::owner_signing_key_from_bytes;
use mist_facilitator::eip3009::{
    eip3009_digest, keccak256, parse_addr20, Authorization, BridgeConfig, Eip3009Bridge,
    Eip3009Domain, ExactAcceptedV2, ExactPayload, ExactPayment, ExactPaymentV2, NoirAssembly,
};
use mist_facilitator::{Facilitator, FacilitatorConfig};
use mist_gateway::http::serve as gateway_serve;
use mist_gateway::{Gateway, TenantConf, TenantTable};
use mist_sdk::x402::{
    base64_decode_flexible, base64_std_encode, base64url_encode, network_canonical, Fetch,
    HttpFetch, PaymentRequired, PaymentRequiredV2, ResourceInfo, ResourceRequest, X402Client,
    X402Outcome, PAYMENT_REQUIRED_HEADER, X402_VERSION_V2,
};
use mist_sdk::{AgentWallet, DelegationLimits, HttpTransport, RetryPolicy, SdkClient, SdkError};

// ---------------------------------------------------------------------------
// 脚手架
// ---------------------------------------------------------------------------

static WAL_SEQ: AtomicU32 = AtomicU32::new(0);

fn aggregator(tag: &str) -> (PathBuf, Arc<Aggregator>) {
    let path = std::env::temp_dir().join(format!(
        "mist-fac-{}-{tag}-{seq}.wal",
        std::process::id(),
        seq = WAL_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
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

fn limits() -> DelegationLimits {
    DelegationLimits {
        max_per_spend: 100_000,
        rate_window_secs: 60,
        rate_max_per_window: 100_000,
        total_cap: 1_000_000,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
    }
}

const GATEWAY_KEY: &str = "fac-e2e-key";
const PAY_TO: &str = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const AMOUNT: &str = "10000";
const NETWORK: &str = "base";

/// 指向"无人监听端口"的 facilitator：纯分发单测里网关永远不会被查到
/// （那些分支在查询前就已返回）。
fn facilitator(resource: &str) -> Facilitator {
    Facilitator::new(FacilitatorConfig {
        gateway_addr: "127.0.0.1:1".into(),
        gateway_bearer: "unused".into(),
        resource: resource.into(),
        pay_to: PAY_TO.into(),
        amount: AMOUNT.into(),
        network: NETWORK.into(),
        asset: Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into()),
        max_timeout_seconds: 30,
        protected_body: "{\"weather\":\"clear+28C\"}".into(),
    })
}

/// 构造 agent 侧 X-PAYMENT 头（与 sdk 编码同 wire）。
fn payment_header(scheme: &str, network: &str, resource: &str, intent_hash_hex: &str) -> String {
    let json = format!(
        r#"{{"x402Version":1,"scheme":"{scheme}","network":"{network}","resource":"{resource}","payload":{{"intentHash":"{intent_hash_hex}","seq":0,"spendNonce":0}}}}"#
    );
    base64url_encode(json.as_bytes())
}

// ---------------------------------------------------------------------------
// 1. handle 纯分发单测（不经 socket）
// ---------------------------------------------------------------------------

#[test]
fn method_routing_and_healthz() {
    let f = facilitator("http://api.example.com/x");
    assert_eq!(f.handle("POST", "/", None).status, 405);
    assert_eq!(f.handle("GET", "/healthz", None).status, 200);
    assert_eq!(f.handle("GET", "/healthz", None).body, "ok");
    assert_eq!(f.handle("GET", "/other", None).status, 404);
    // healthz 不吃支付头（先路由后支付）。
    assert_eq!(f.handle("GET", "/healthz", Some("junk")).status, 200);
}

#[test]
fn no_payment_returns_parseable_402_requirements() {
    let resource = "http://api.example.com/weather";
    let f = facilitator(resource);
    let r = f.handle("GET", "/", None);
    assert_eq!(r.status, 402);

    // 402 body 必须能被 agent 侧 sdk PaymentRequired 反解析（wire 互锁）。
    let pr: PaymentRequired = serde_json::from_str(&r.body).expect("parse 402 body");
    assert_eq!(pr.x402_version, 1);
    assert_eq!(pr.accepts.len(), 1);
    let req = &pr.accepts[0];
    assert_eq!(req.scheme, "mist-v1");
    assert_eq!(req.network, NETWORK);
    assert_eq!(req.resource, resource);
    assert_eq!(req.pay_to, PAY_TO);
    assert_eq!(req.max_amount_required, AMOUNT);
    assert_eq!(req.max_timeout_seconds, Some(30));
    assert!(req.asset.is_some());
}

#[test]
fn malformed_payment_header_is_402_not_500() {
    let resource = "http://api.example.com/weather";
    let f = facilitator(resource);

    // 坏 base64url。
    let r = f.handle("GET", "/", Some("not*valid!!"));
    assert_eq!(r.status, 402);
    assert!(r.body.contains("bad payment header encoding"), "{}", r.body);

    // base64url 合法但 JSON 不合法。
    let r = f.handle("GET", "/", Some(&base64url_encode(b"{not json")));
    assert_eq!(r.status, 402);
    assert!(r.body.contains("bad payment payload"), "{}", r.body);
}

#[test]
fn scheme_network_resource_binding_enforced() {
    let resource = "http://api.example.com/weather";
    let f = facilitator(resource);

    // 错 scheme（未知 scheme）。
    let h = payment_header(
        "other",
        NETWORK,
        resource,
        &format!("0x{}", hex::encode([1u8; 32])),
    );
    let r = f.handle("GET", "/", Some(&h));
    assert_eq!(r.status, 402);
    assert!(r.body.contains("unsupported scheme"), "{}", r.body);

    // exact scheme 未配桥 → 402（S-32：桥是可选件）。
    let h = payment_header(
        "exact",
        NETWORK,
        resource,
        &format!("0x{}", hex::encode([1u8; 32])),
    );
    let r = f.handle("GET", "/", Some(&h));
    assert_eq!(r.status, 402);
    assert!(r.body.contains("exact scheme not enabled"), "{}", r.body);

    // 错 network。
    let h = payment_header(
        "mist-v1",
        "sepolia",
        resource,
        &format!("0x{}", hex::encode([1u8; 32])),
    );
    let r = f.handle("GET", "/", Some(&h));
    assert_eq!(r.status, 402);
    assert!(r.body.contains("network mismatch"), "{}", r.body);

    // 错 resource（重放头绑定的资源不是本服务器）。
    let h = payment_header(
        "mist-v1",
        NETWORK,
        "http://other.example.com/x",
        &format!("0x{}", hex::encode([1u8; 32])),
    );
    let r = f.handle("GET", "/", Some(&h));
    assert_eq!(r.status, 402);
    assert!(r.body.contains("resource mismatch"), "{}", r.body);

    // 坏 intentHash hex（S-72 起错误文案带 wire 头名——v1/v2 归一后可区分来源）。
    let h = payment_header("mist-v1", NETWORK, resource, "0xzz");
    let r = f.handle("GET", "/", Some(&h));
    assert_eq!(r.status, 402);
    assert!(
        r.body.contains("bad X-PAYMENT intentHash hex"),
        "{}",
        r.body
    );

    // intentHash 长度不对（31 字节）。
    let h = payment_header(
        "mist-v1",
        NETWORK,
        resource,
        &format!("0x{}", hex::encode([1u8; 31])),
    );
    let r = f.handle("GET", "/", Some(&h));
    assert_eq!(r.status, 402);
    assert!(r.body.contains("must be 32 bytes"), "{}", r.body);
}

// ---------------------------------------------------------------------------
// 1b. S-32：exact scheme（EIP-3009 桥）纯分发单测——桥校验在摄取前返回，
//     不经 socket（网关地址无监听也不触达）。
// ---------------------------------------------------------------------------

/// 指向"无人监听端口"的带桥 facilitator。
fn facilitator_with_bridge(resource: &str, gateway_addr: &str) -> Facilitator {
    Facilitator::with_bridge(
        FacilitatorConfig {
            gateway_addr: gateway_addr.into(),
            gateway_bearer: "unused".into(),
            resource: resource.into(),
            pay_to: PAY_TO.into(),
            amount: AMOUNT.into(),
            network: NETWORK.into(),
            asset: Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into()),
            max_timeout_seconds: 30,
            protected_body: "{\"weather\":\"clear+28C\"}".into(),
        },
        Some(Eip3009Bridge::new(bridge_config(gateway_addr))),
    )
}

fn bridge_config(gateway_addr: &str) -> BridgeConfig {
    BridgeConfig {
        gateway_addr: gateway_addr.into(),
        gateway_bearer: GATEWAY_KEY.into(),
        domain: Eip3009Domain {
            name: "USD Coin".into(),
            version: "2".into(),
            chain_id: 8453,
            verifying_contract: parse_addr20("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
                .expect("asset addr"),
        },
        agent_seed: [0xAAu8; 32],
        owner_seed: [0xBBu8; 32],
        limits: limits(),
        noir: None,
    }
}

/// 构造参数（避免 8 参函数——clippy too_many_arguments）。
struct ExactSpec<'a> {
    domain: &'a Eip3009Domain,
    /// `authorization.from` 的 key 种子。
    from_seed: [u8; 32],
    /// 签名 key 种子（与 `from_seed` 不同即伪造签名）。
    signer_seed: [u8; 32],
    to: &'a str,
    value: &'a str,
    valid_after: u64,
    valid_before: u64,
    nonce: [u8; 32],
}

/// 构造标准 `exact` payload。
fn exact_payment(spec: &ExactSpec) -> ExactPayment {
    let from_key = k256::ecdsa::SigningKey::from_bytes(&spec.from_seed.into()).expect("from key");
    let signer = k256::ecdsa::SigningKey::from_bytes(&spec.signer_seed.into()).expect("signer key");
    let point = from_key.verifying_key().to_encoded_point(false);
    let from: [u8; 20] = keccak256(&point.as_bytes()[1..65])[12..]
        .try_into()
        .expect("20 bytes");
    let auth = Authorization {
        from: format!("0x{}", hex::encode(from)),
        to: spec.to.into(),
        value: spec.value.into(),
        valid_after: spec.valid_after,
        valid_before: spec.valid_before,
        nonce: format!("0x{}", hex::encode(spec.nonce)),
    };
    let digest = eip3009_digest(spec.domain, &auth).expect("digest");
    let (sig, rid) = signer.sign_prehash_recoverable(&digest).expect("sign");
    let mut sig65 = sig.to_bytes().to_vec();
    sig65.push(rid.to_byte());
    ExactPayment {
        x402_version: 1,
        scheme: "exact".into(),
        network: NETWORK.into(),
        resource: "http://fac.example.com/weather".into(),
        payload: ExactPayload {
            signature: format!("0x{}", hex::encode(&sig65)),
            authorization: auth,
        },
    }
}

fn exact_header(payment: &ExactPayment) -> String {
    base64url_encode(&serde_json::to_vec(payment).expect("serialize exact payload"))
}

fn valid_window() -> (u64, u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    (now - 10, now + 600)
}

#[test]
fn exact_scheme_402_advertises_both_schemes() {
    let f = facilitator_with_bridge("http://fac.example.com/weather", "127.0.0.1:1");
    let r = f.handle("GET", "/", None);
    assert_eq!(r.status, 402);
    let pr: PaymentRequired = serde_json::from_str(&r.body).expect("parse 402 body");
    assert_eq!(pr.accepts.len(), 2);
    assert_eq!(pr.accepts[0].scheme, "mist-v1");
    assert_eq!(pr.accepts[1].scheme, "exact");
    // exact 条目带 EIP-3009 域参数（extra）；mist-v1 条目不带。
    let extra = pr.accepts[1].extra.as_ref().expect("extra");
    assert_eq!(extra.name, "USD Coin");
    assert_eq!(extra.version, "2");
    assert!(pr.accepts[0].extra.is_none());
}

#[test]
fn exact_scheme_binding_and_signature_enforced() {
    let f = facilitator_with_bridge("http://fac.example.com/weather", "127.0.0.1:1");
    let domain = Eip3009Domain {
        name: "USD Coin".into(),
        version: "2".into(),
        chain_id: 8453,
        verifying_contract: parse_addr20("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
            .expect("asset addr"),
    };
    let (after, before) = valid_window();

    // to != payTo → 402。
    let p = exact_payment(&ExactSpec {
        domain: &domain,
        from_seed: [1u8; 32],
        signer_seed: [1u8; 32],
        to: "0x1111111111111111111111111111111111111111",
        value: AMOUNT,
        valid_after: after,
        valid_before: before,
        nonce: [0x42; 32],
    });
    let r = f.handle("GET", "/", Some(&exact_header(&p)));
    assert_eq!(r.status, 402);
    assert!(r.body.contains("authorization.to != payTo"), "{}", r.body);

    // value != maxAmountRequired → 402。
    let p = exact_payment(&ExactSpec {
        domain: &domain,
        from_seed: [1u8; 32],
        signer_seed: [1u8; 32],
        to: PAY_TO,
        value: "999",
        valid_after: after,
        valid_before: before,
        nonce: [0x42; 32],
    });
    let r = f.handle("GET", "/", Some(&exact_header(&p)));
    assert_eq!(r.status, 402);
    assert!(r.body.contains("value != maxAmountRequired"), "{}", r.body);

    // 时间窗外 → 402。
    let p = exact_payment(&ExactSpec {
        domain: &domain,
        from_seed: [1u8; 32],
        signer_seed: [1u8; 32],
        to: PAY_TO,
        value: AMOUNT,
        valid_after: before + 10,
        valid_before: before + 20,
        nonce: [0x42; 32],
    });
    let r = f.handle("GET", "/", Some(&exact_header(&p)));
    assert_eq!(r.status, 402);
    assert!(r.body.contains("outside validity window"), "{}", r.body);

    // 伪造签名（签名 key != from 的 key）→ 402 EIP-3009 signature invalid。
    let p = exact_payment(&ExactSpec {
        domain: &domain,
        from_seed: [1u8; 32],
        signer_seed: [9u8; 32],
        to: PAY_TO,
        value: AMOUNT,
        valid_after: after,
        valid_before: before,
        nonce: [0x42; 32],
    });
    let r = f.handle("GET", "/", Some(&exact_header(&p)));
    assert_eq!(r.status, 402);
    assert!(r.body.contains("EIP-3009 signature invalid"), "{}", r.body);

    // resource 绑定（重放头里的资源不是本服务器）→ 402。
    let mut p = exact_payment(&ExactSpec {
        domain: &domain,
        from_seed: [1u8; 32],
        signer_seed: [1u8; 32],
        to: PAY_TO,
        value: AMOUNT,
        valid_after: after,
        valid_before: before,
        nonce: [0x42; 32],
    });
    p.resource = "http://other.example.com/x".into();
    let r = f.handle("GET", "/", Some(&exact_header(&p)));
    assert_eq!(r.status, 402);
    assert!(r.body.contains("resource mismatch"), "{}", r.body);

    // network 绑定 → 402。
    let mut p = exact_payment(&ExactSpec {
        domain: &domain,
        from_seed: [1u8; 32],
        signer_seed: [1u8; 32],
        to: PAY_TO,
        value: AMOUNT,
        valid_after: after,
        valid_before: before,
        nonce: [0x42; 32],
    });
    p.network = "sepolia".into();
    let r = f.handle("GET", "/", Some(&exact_header(&p)));
    assert_eq!(r.status, 402);
    assert!(r.body.contains("network mismatch"), "{}", r.body);
}

// ---------------------------------------------------------------------------
// 2.【主验收】三角色真 socket e2e
// ---------------------------------------------------------------------------

/// 起真网关（随机端口，后台线程）。
fn spawn_gateway(tag: &str) -> (String, PathBuf, Arc<Aggregator>) {
    let (wal, agg) = aggregator(tag);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let gw = Arc::new(Gateway::with_tenants(
        Arc::clone(&agg),
        tenants_one(GATEWAY_KEY, "fac-tenant", u64::MAX),
        64 * 1024,
    ));
    std::thread::spawn(move || {
        let _ = gateway_serve(gw, listener, 256, Duration::from_secs(5));
    });
    (addr, wal, agg)
}

/// 起真 facilitator（随机端口，后台线程）。
fn spawn_facilitator(gateway_addr: &str, resource: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let f = Arc::new(Facilitator::new(FacilitatorConfig {
        gateway_addr: gateway_addr.into(),
        gateway_bearer: GATEWAY_KEY.into(),
        resource: resource.into(),
        pay_to: PAY_TO.into(),
        amount: AMOUNT.into(),
        network: NETWORK.into(),
        asset: None,
        max_timeout_seconds: 30,
        protected_body: "{\"weather\":\"clear+28C\"}".into(),
    }));
    std::thread::spawn(move || {
        let _ = mist_facilitator::http::serve(f, listener);
    });
    format!("http://{addr}/")
}

#[test]
fn e2e_agent_pays_gateway_facilitator_verifies_receipt() {
    let (gw_addr, wal, agg) = spawn_gateway("e2e-roles");
    let resource = spawn_facilitator(&gw_addr, "http://fac.example.com/weather");

    // agent：真网关上的 SdkClient（真密码学 + 真记账）+ HttpFetch 真打 facilitator。
    let transport = HttpTransport::new(&gw_addr, GATEWAY_KEY);
    let (wallet, owner) = (
        AgentWallet::from_seed([9u8; 32]),
        owner_signing_key_from_bytes([7u8; 32]),
    );
    let mut client = SdkClient::new(wallet, Box::new(transport));
    client.set_retry(RetryPolicy {
        max_attempts: 3,
        base_backoff_ms: 0,
        max_backoff_ms: 0,
    });
    let rec = client.authorize(&owner, [1u8; 20], &limits()).unwrap();
    let dh = rec.delegation_hash;

    let x = X402Client::new(&client, &HttpFetch, dh);
    let outcome = x
        .request(&ResourceRequest::get(&resource))
        .expect("full x402 roundtrip");

    match outcome {
        X402Outcome::Paid { response, proof } => {
            // facilitator 查到网关回执后放行受保护内容。
            assert_eq!(response.status, 200);
            assert_eq!(response.body, b"{\"weather\":\"clear+28C\"}".to_vec());
            // 网关侧真记账恰一笔；proof ↔ 聚合器回执对账。
            assert_eq!(agg.accepted_count(), 1);
            let receipt = agg.receipt(&proof.intent_hash).expect("receipt queryable");
            assert_eq!(receipt.seq, proof.seq);
        }
        X402Outcome::Free(_) => panic!("402 资源必须走支付路径"),
    }

    drop(client);
    let _ = std::fs::remove_file(&wal);
}

/// 伪造 intentHash（网关从没受理过）→ facilitator 查网关 404 → Ok(None) → 402，
/// **不放行**（404 ≠ 未支付，不可验证即不放行）。
#[test]
fn e2e_forged_intent_hash_is_rejected_with_402() {
    let (gw_addr, _wal, agg) = spawn_gateway("e2e-forged");
    let url = spawn_facilitator(&gw_addr, "http://fac.example.com/weather");

    // 重放头里的 resource 绑定 402 body 里的 resource（非 socket URL）。
    let header = payment_header(
        "mist-v1",
        NETWORK,
        "http://fac.example.com/weather",
        &format!("0x{}", hex::encode([0xEE; 32])),
    );
    let (status, body) = raw_get_with_payment(&url, &header);
    assert_eq!(status, 402, "forged intent must not pass: {body}");
    assert!(body.contains("receipt not verifiable"), "{body}");
    assert_eq!(agg.accepted_count(), 0, "零记账");
}

#[test]
fn e2e_gateway_down_is_503_fail_closed() {
    // 网关端口 = 无人监听的随机端口（先 bind 再 drop 释放）。
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let dead_addr = listener.local_addr().expect("addr").to_string();
    drop(listener);
    let url = spawn_facilitator(&dead_addr, "http://fac.example.com/weather");

    let header = payment_header(
        "mist-v1",
        NETWORK,
        "http://fac.example.com/weather",
        &format!("0x{}", hex::encode([1u8; 32])),
    );
    let (status, body) = raw_get_with_payment(&url, &header);
    assert_eq!(status, 503, "gateway unavailable must fail closed: {body}");
    assert!(body.contains("E_GATEWAY_UNAVAILABLE"), "{body}");
}

/// 起带桥 facilitator（随机端口，后台线程）。`journal` 非空 = S-33 持久化重放闸。
fn spawn_facilitator_with_bridge(
    gateway_addr: &str,
    resource: &str,
    journal: Option<&std::path::Path>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let bridge = match journal {
        Some(p) => Eip3009Bridge::open(bridge_config(gateway_addr), p).expect("open journal"),
        None => Eip3009Bridge::new(bridge_config(gateway_addr)),
    };
    let f = Arc::new(Facilitator::with_bridge(
        FacilitatorConfig {
            gateway_addr: gateway_addr.into(),
            gateway_bearer: GATEWAY_KEY.into(),
            resource: resource.into(),
            pay_to: PAY_TO.into(),
            amount: AMOUNT.into(),
            network: NETWORK.into(),
            asset: None,
            max_timeout_seconds: 30,
            protected_body: "{\"weather\":\"clear+28C\"}".into(),
        },
        Some(bridge),
    ));
    std::thread::spawn(move || {
        let _ = mist_facilitator::http::serve(f, listener);
    });
    format!("http://{addr}/")
}

/// 裸 socket GET（带 X-PAYMENT 头）→ (status, body)。HttpFetch 只支持无头请求，
/// 伪造头场景直接打 socket。
fn raw_get_with_payment(url: &str, payment: &str) -> (u16, String) {
    // url = http://127.0.0.1:PORT/
    let rest = url.strip_prefix("http://").expect("http url");
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let mut s = std::net::TcpStream::connect(authority).expect("connect");
    let req = format!(
        "GET /{path} HTTP/1.1\r\nHost: {authority}\r\nX-Payment: {payment}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).unwrap();
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

// 供 clippy：Fetch trait 对象形态触达（HttpFetch 已直接用）。
#[allow(dead_code)]
fn _fetch_is_object_safe() -> Box<dyn Fetch> {
    Box::new(HttpFetch)
}

// 供 clippy：SdkError / PaymentRequired 引用保活（若上游重构导致未用则同步删）。
#[allow(dead_code)]
fn _type_witness(_: SdkError, _: PaymentRequired) {}

// ---------------------------------------------------------------------------
// 4. S-32：EIP-3009 兼容桥 e2e——标准 exact client（不会说 mist-v1）→
//    桥验签转投摄取 → 真网关真记账 → 回执放行；重放不再摄取；伪造 → 402。
// ---------------------------------------------------------------------------

#[test]
fn e2e_exact_scheme_bridge_ingests_verifies_and_dedups_replay() {
    let (gw_addr, wal, agg) = spawn_gateway("e2e-eip3009");
    let url = spawn_facilitator_with_bridge(&gw_addr, "http://fac.example.com/weather", None);
    let domain = Eip3009Domain {
        name: "USD Coin".into(),
        version: "2".into(),
        chain_id: 8453,
        verifying_contract: parse_addr20("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
            .expect("asset addr"),
    };
    let (after, before) = valid_window();

    //（402 体双 scheme 已在纯分发单测 exact_scheme_402_advertises_both_schemes 覆盖。）

    // 标准 exact client（真 EIP-3009 签名）付款 → 桥摄取 → 真记账 → 200 放行。
    let payment = exact_payment(&ExactSpec {
        domain: &domain,
        from_seed: [1u8; 32],
        signer_seed: [1u8; 32],
        to: PAY_TO,
        value: AMOUNT,
        valid_after: after,
        valid_before: before,
        nonce: [0x42; 32],
    });
    let header = exact_header(&payment);
    let (status, body) = raw_get_with_payment(&url, &header);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, "{\"weather\":\"clear+28C\"}");
    assert_eq!(
        agg.accepted_count(),
        1,
        "bridge must ingest exactly one intent"
    );

    // 重放同 payload → 200（回执命中）且不再摄取（重放闸）。
    let (status2, body2) = raw_get_with_payment(&url, &header);
    assert_eq!(status2, 200, "{body2}");
    assert_eq!(agg.accepted_count(), 1, "replay must not re-ingest");

    // 伪造签名（签名 key != from 的 key）→ 402，不摄取。
    let forged = exact_payment(&ExactSpec {
        domain: &domain,
        from_seed: [2u8; 32],
        signer_seed: [9u8; 32],
        to: PAY_TO,
        value: AMOUNT,
        valid_after: after,
        valid_before: before,
        nonce: [0x43; 32],
    });
    let (status3, body3) = raw_get_with_payment(&url, &exact_header(&forged));
    assert_eq!(status3, 402, "{body3}");
    assert_eq!(agg.accepted_count(), 1);

    drop(agg);
    let _ = std::fs::remove_file(&wal);
}

// ---------------------------------------------------------------------------
// 5. S-33：重放闸持久化——facilitator 带日志摄取 1 笔 → 销毁重建（同日志路径）→
//    同 payload 重放 200 且不再摄取（重启后重放闸仍命中）；新 nonce 正常摄取。
// ---------------------------------------------------------------------------

#[test]
fn e2e_replay_gate_survives_bridge_restart() {
    let (gw_addr, wal, agg) = spawn_gateway("e2e-replay-journal");
    let journal = std::env::temp_dir().join(format!(
        "mist-fac-e2e-journal-{}-{:x}.jsonl",
        std::process::id(),
        0x533_0001u32
    ));
    let _ = std::fs::remove_file(&journal);

    let domain = Eip3009Domain {
        name: "USD Coin".into(),
        version: "2".into(),
        chain_id: 8453,
        verifying_contract: parse_addr20("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
            .expect("asset addr"),
    };
    let (after, before) = valid_window();
    let payment = exact_payment(&ExactSpec {
        domain: &domain,
        from_seed: [4u8; 32],
        signer_seed: [4u8; 32],
        to: PAY_TO,
        value: AMOUNT,
        valid_after: after,
        valid_before: before,
        nonce: [0x77; 32],
    });
    let header = exact_header(&payment);

    // 第一生命周期：摄取 1 笔并落日志。
    let url =
        spawn_facilitator_with_bridge(&gw_addr, "http://fac.example.com/weather", Some(&journal));
    let (status, body) = raw_get_with_payment(&url, &header);
    assert_eq!(status, 200, "{body}");
    assert_eq!(agg.accepted_count(), 1);

    // 第二生命周期（重启）：同日志路径重建——同 payload 重放命中闸表，不再摄取。
    let url2 =
        spawn_facilitator_with_bridge(&gw_addr, "http://fac.example.com/weather", Some(&journal));
    let (status2, body2) = raw_get_with_payment(&url2, &header);
    assert_eq!(status2, 200, "重启后重放闸仍命中 → 回执放行: {body2}");
    assert_eq!(
        agg.accepted_count(),
        1,
        "restarted bridge must not re-ingest the same payload"
    );

    // 新 nonce 不被误挡（闸只挡已登记键）。
    let fresh = exact_payment(&ExactSpec {
        domain: &domain,
        from_seed: [4u8; 32],
        signer_seed: [4u8; 32],
        to: PAY_TO,
        value: AMOUNT,
        valid_after: after,
        valid_before: before,
        nonce: [0x78; 32],
    });
    let (status3, body3) = raw_get_with_payment(&url2, &exact_header(&fresh));
    assert_eq!(status3, 200, "{body3}");
    assert_eq!(agg.accepted_count(), 2);

    drop(agg);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(&journal);
}

// ---------------------------------------------------------------------------
// 6. S-47：桥接真 prover 装配（TECH_SPEC §6.10 第 4 步 / §6.14 CLI 消费）——
//    `BridgeConfig.noir` 经 `SdkClient::with_noir` 装配真电路 prover 的垫付
//    client，在真 BbVerifier 网关（enforce_revocation_root = true）上摄取成功；
//    占位 prover 的桥在同一网关被全拒（对照：装配确实在起作用）。
// ---------------------------------------------------------------------------

/// 仓库根（`gen-witness/` + `circuits/` 布局，与 sdk e2e 同款）。
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("facilitator/ 的上级即仓库根")
        .to_path_buf()
}

/// 真 BbVerifier 网关（§6.13 + §6.2 绑定闸开启）——占位证明在此必被全拒。
fn spawn_gateway_bb(
    tag: &str,
    vk: Vec<u8>,
    backend: &BbBackend,
) -> (String, PathBuf, Arc<Aggregator>) {
    // 自建 Wal（`aggregator()` 助手把 Wal 封进 FormatVerifier 聚合器，bb 模式需要
    // 自带 BbVerifier 的聚合器）。
    let wal_path = std::env::temp_dir().join(format!(
        "mist-fac-{}-{tag}-{seq}.wal",
        std::process::id(),
        seq = WAL_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&wal_path);
    let wal = Wal::open(&wal_path, 1_000).expect("open wal");
    let verifier = BbVerifier::from_parts(
        vk,
        backend.clone(),
        repo_root().join(format!("target/bb-fac-bridge-{tag}")),
    );
    let agg = Arc::new(Aggregator::new(
        IngestConfig {
            enforce_revocation_root: true,
            ..Default::default()
        },
        Box::new(verifier),
        wal,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let gw = Arc::new(Gateway::with_tenants(
        Arc::clone(&agg),
        tenants_one(GATEWAY_KEY, "fac-noir-tenant", u64::MAX),
        64 * 1024,
    ));
    std::thread::spawn(move || {
        let _ = gateway_serve(gw, listener, 256, Duration::from_secs(5));
    });
    (addr, wal_path, agg)
}

#[test]
fn e2e_bridge_with_noir_prover_pays_real_proof_into_bb_gateway() {
    if std::env::var("MIST_ZK_PROVER_E2E").as_deref() != Ok("1") {
        println!("SKIP: MIST_ZK_PROVER_E2E=1 未设（prove 侧重操作，不进默认 cargo test）");
        return;
    }
    let root = repo_root();
    if !root
        .join("circuits/target/spend_authorization.json")
        .exists()
        || !root.join("circuits/target/vk").exists()
    {
        println!("SKIP: circuits/target 工件不存在（formal_zk 未跑）");
        return;
    }
    let vk = std::fs::read(root.join("circuits/target/vk")).expect("read vk");
    let backend = match BbBackend::detect() {
        Some(b) => b,
        None => {
            println!("SKIP: bb 工具链不可得（Windows 原生与 WSL 兜底皆无）");
            return;
        }
    };

    let (gw_addr, wal, agg) = spawn_gateway_bb("e2e-noir-bridge", vk, &backend);
    // 撤销另一张委托：撤销集非空 → 绑定闸接受集含真实状态根（非退化空根口径）。
    let mut other = [0x3Du8; 32];
    other[31] = 0x07;
    agg.revoke(other);

    // 桥：noir 装配（S-47）。工具链探测在首次摄取时惰性发生（register_operator）。
    let mut cfg = bridge_config(&gw_addr);
    cfg.noir = Some(NoirAssembly {
        root: root.clone(),
        attestation_secret: {
            // 0xDEADBEEF（LE 不透明字节，< EdDSA 子群阶，§6.14 值域闸合法私钥）。
            let mut s = [0u8; 32];
            s[0] = 0xEF;
            s[1] = 0xBE;
            s[2] = 0xAD;
            s[3] = 0xDE;
            s
        },
    });
    assert_eq!(Eip3009Bridge::new(cfg.clone()).prover_mode(), "noir");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let fac_addr = listener.local_addr().expect("addr").to_string();
    let f = Arc::new(Facilitator::with_bridge(
        FacilitatorConfig {
            gateway_addr: gw_addr.clone(),
            gateway_bearer: GATEWAY_KEY.into(),
            resource: "http://fac.example.com/weather".into(),
            pay_to: PAY_TO.into(),
            amount: AMOUNT.into(),
            network: NETWORK.into(),
            asset: None,
            max_timeout_seconds: 30,
            protected_body: "{\"weather\":\"clear+28C\"}".into(),
        },
        Some(Eip3009Bridge::new(cfg)),
    ));
    std::thread::spawn(move || {
        let _ = mist_facilitator::http::serve(f, listener);
    });
    let url = format!("http://{fac_addr}/");

    let domain = Eip3009Domain {
        name: "USD Coin".into(),
        version: "2".into(),
        chain_id: 8453,
        verifying_contract: parse_addr20("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
            .expect("asset addr"),
    };
    let (after, before) = valid_window();
    let payment = exact_payment(&ExactSpec {
        domain: &domain,
        from_seed: [5u8; 32],
        signer_seed: [5u8; 32],
        to: PAY_TO,
        value: AMOUNT,
        valid_after: after,
        valid_before: before,
        nonce: [0x5E; 32],
    });

    // 标准 exact client → 桥摄取：witness 现取（S-45）→ with_noir 垫付 client 真证明
    // → 网关 BbVerifier 密码学接受 + 绑定闸放行 → 200。**e2e 通过本身即证装配生效**
    // （占位证明在 bb 模式下必被全拒）。
    let (status, body) = raw_get_with_payment(&url, &exact_header(&payment));
    assert_eq!(status, 200, "noir 装配桥摄取失败: {body}");
    assert_eq!(body, "{\"weather\":\"clear+28C\"}");
    assert_eq!(agg.accepted_count(), 1);

    // 重放同 payload → 200（重放闸命中）且不再摄取。
    let (status2, body2) = raw_get_with_payment(&url, &exact_header(&payment));
    assert_eq!(status2, 200, "{body2}");
    assert_eq!(agg.accepted_count(), 1, "replay must not re-ingest");

    // 对照组：占位 prover 的桥在同一 BbVerifier 网关上被拒（402）——证明上面的
    // 200 来自真电路证明而非占位口径漏网。
    let vk2 = std::fs::read(root.join("circuits/target/vk")).expect("read vk");
    let (gw2, wal2, agg2) = spawn_gateway_bb("e2e-noir-bridge-ctrl", vk2, &backend);
    let cfg2 = bridge_config(&gw2);
    assert!(cfg2.noir.is_none(), "缺省占位口径");
    let listener2 = TcpListener::bind("127.0.0.1:0").expect("bind");
    let fac2 = listener2.local_addr().expect("addr").to_string();
    let f2 = Arc::new(Facilitator::with_bridge(
        FacilitatorConfig {
            gateway_addr: gw2.clone(),
            gateway_bearer: GATEWAY_KEY.into(),
            resource: "http://fac.example.com/weather".into(),
            pay_to: PAY_TO.into(),
            amount: AMOUNT.into(),
            network: NETWORK.into(),
            asset: None,
            max_timeout_seconds: 30,
            protected_body: "{\"weather\":\"clear+28C\"}".into(),
        },
        Some(Eip3009Bridge::new(cfg2)),
    ));
    std::thread::spawn(move || {
        let _ = mist_facilitator::http::serve(f2, listener2);
    });
    let url2 = format!("http://{fac2}/");
    let fresh = exact_payment(&ExactSpec {
        domain: &domain,
        from_seed: [6u8; 32],
        signer_seed: [6u8; 32],
        to: PAY_TO,
        value: AMOUNT,
        valid_after: after,
        valid_before: before,
        nonce: [0x5F; 32],
    });
    let (status3, body3) = raw_get_with_payment(&url2, &exact_header(&fresh));
    assert_eq!(status3, 402, "占位证明在 BbVerifier 网关必须被拒: {body3}");
    assert_eq!(agg2.accepted_count(), 0);

    drop(agg);
    drop(agg2);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(&wal2);
}

// ---------------------------------------------------------------------------
// 7. S-72：x402 v2 wire 双协议——PAYMENT-REQUIRED 头 / PAYMENT-SIGNATURE 头 /
//    CAIP-2 网络标识 / exact 桥 v2 形（TECH_SPEC §6.8/§6.9/§6.10）。
// ---------------------------------------------------------------------------

/// 构造 agent 侧 v2 `PAYMENT-SIGNATURE` 头（mist-v1 形：scheme/network 进 accepted）。
fn v2_mist_header(network: &str, resource_url: &str, intent_hash_hex: &str) -> String {
    let json = format!(
        r#"{{"x402Version":2,"resource":{{"url":"{resource_url}"}},"accepted":{{"scheme":"mist-v1","network":"{network}","amount":"{amount}","asset":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","payTo":"{pay_to}","maxTimeoutSeconds":30}},"payload":{{"intentHash":"{intent_hash_hex}","seq":0,"spendNonce":0}}}}"#,
        amount = AMOUNT,
        pay_to = PAY_TO
    );
    base64_std_encode(json.as_bytes())
}

/// 裸 socket GET（带头名显式指定——v2 `PAYMENT-SIGNATURE` 场景）→ (status, head, body)。
fn raw_get_with_header(url: &str, header_name: &str, value: &str) -> (u16, String, String) {
    let rest = url.strip_prefix("http://").expect("http url");
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let mut s = std::net::TcpStream::connect(authority).expect("connect");
    let req = format!(
        "GET /{path} HTTP/1.1\r\nHost: {authority}\r\n{header_name}: {value}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let status: u16 = resp
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .expect("status line");
    let (head, body) = resp.rsplit_once("\r\n\r\n").unwrap_or((resp.as_str(), ""));
    (status, head.to_string(), body.to_string())
}

#[test]
fn v2_402_advertises_payment_required_header() {
    let f = facilitator("http://fac.example.com/weather");
    let r = f.handle("GET", "/", None);

    // v1 body 不动（既有 client 面零改动）。
    let pr: PaymentRequired = serde_json::from_str(&r.body).expect("v1 body still parses");
    assert_eq!(pr.x402_version, 1);

    // v2 声明走头：标准 base64 的 v2 JSON，accepts 恒 CAIP-2。
    let v2 = r
        .headers
        .iter()
        .find(|(k, _)| k == PAYMENT_REQUIRED_HEADER)
        .expect("402 must carry PAYMENT-REQUIRED header")
        .1
        .clone();
    let decoded = base64_decode_flexible(&v2).expect("flexible decode");
    let v2pr: PaymentRequiredV2 =
        serde_json::from_slice(&decoded).expect("v2 header decodes to PaymentRequired v2");
    assert_eq!(v2pr.x402_version, X402_VERSION_V2);
    assert_eq!(v2pr.resource.url, "http://fac.example.com/weather");
    assert_eq!(v2pr.accepts.len(), 1, "无桥 facilitator 只有 mist-v1 条目");
    assert_eq!(v2pr.accepts[0].scheme, "mist-v1");
    assert_eq!(v2pr.accepts[0].amount, AMOUNT);
    assert_eq!(
        v2pr.accepts[0].network,
        network_canonical(NETWORK),
        "v2 accepts 恒产 CAIP-2 规范形"
    );
    assert_eq!(v2pr.accepts[0].pay_to, PAY_TO);
}

#[test]
fn v2_402_header_omitted_without_asset_graceful_degradation() {
    // asset 未配置 → v2 schema 要求 asset 必填非空 → 不产 v2 头（v2 client 回落
    // body 按 v1 语境重试，我们照收）。
    let f = Facilitator::new(FacilitatorConfig {
        gateway_addr: "127.0.0.1:1".into(),
        gateway_bearer: "unused".into(),
        resource: "http://fac.example.com/weather".into(),
        pay_to: PAY_TO.into(),
        amount: AMOUNT.into(),
        network: NETWORK.into(),
        asset: None,
        max_timeout_seconds: 30,
        protected_body: "ok".into(),
    });
    let r = f.handle("GET", "/", None);
    assert_eq!(r.status, 402);
    assert!(
        !r.headers.iter().any(|(k, _)| k == PAYMENT_REQUIRED_HEADER),
        "asset 未配置不得产 v2 头"
    );
}

/// 纯分发绑定矩阵（不经 socket）：直接调 [`Facilitator::handle`]。
fn dispatch_with_v2(header_value: &str) -> (u16, String) {
    let f = facilitator("http://fac.example.com/weather");
    let r = f.handle("GET", "/", Some(header_value));
    (r.status, r.body)
}

#[test]
fn v2_mist_v1_wire_bindings_and_caip2_interop() {
    let ih = format!("0x{}", hex::encode([0x11u8; 32]));

    // CAIP-2 与 v1 名等价类互通：cfg.network = "base"，client 发 "eip155:8453"
    // → 绑定通过（网关 127.0.0.1:1 不可达 → 503 fail-closed = 绑定全过）。
    let (status, body) = dispatch_with_v2(&v2_mist_header(
        "eip155:8453",
        "http://fac.example.com/weather",
        &ih,
    ));
    assert_eq!(status, 503, "绑定通过应走到回执闸: {body}");

    // 异链 CAIP-2 → network mismatch 402。
    let (status, body) = dispatch_with_v2(&v2_mist_header(
        "eip155:1",
        "http://fac.example.com/weather",
        &ih,
    ));
    assert_eq!(status, 402);
    assert!(body.contains("network mismatch"), "{body}");

    // v2 名义下发 v1 字符串同样等价互通。
    let (status, _) = dispatch_with_v2(&v2_mist_header(
        "base",
        "http://fac.example.com/weather",
        &ih,
    ));
    assert_eq!(status, 503, "v1 名在 v2 wire 上同样互通");

    // resource 缺失 → 402（绑定必须成立）。
    let json = format!(
        r#"{{"x402Version":2,"accepted":{{"scheme":"mist-v1","network":"eip155:8453","amount":"{amount}","payTo":"{pay_to}"}},"payload":{{"intentHash":"{ih}"}}}}"#,
        amount = AMOUNT,
        pay_to = PAY_TO
    );
    let (status, body) = dispatch_with_v2(&base64_std_encode(json.as_bytes()));
    assert_eq!(status, 402);
    assert!(body.contains("resource binding required"), "{body}");

    // 错 resource → 402。
    let (status, body) = dispatch_with_v2(&v2_mist_header(
        "eip155:8453",
        "http://other.example.com/weather",
        &ih,
    ));
    assert_eq!(status, 402);
    assert!(body.contains("resource mismatch"), "{body}");
}

#[test]
fn v1_wire_accepts_caip2_network_via_canonical_comparison() {
    // v1 wire 同样吃等价类：cfg.network = "base"，client 发 "eip155:8453" → 通过
    // （503 = 绑定全过、回执闸 fail-closed）。
    let f = facilitator("http://fac.example.com/weather");
    let h = payment_header(
        "mist-v1",
        "eip155:8453",
        "http://fac.example.com/weather",
        &format!("0x{}", hex::encode([0x12u8; 32])),
    );
    let r = f.handle("GET", "/", Some(&h));
    assert_eq!(r.status, 503, "CAIP-2 在 v1 wire 上应互通: {}", r.body);
}

#[test]
fn version_dispatch_is_by_x402_version_field_only() {
    // 缺 x402Version → 402（判据唯一 = x402Version）。
    let json = r#"{"scheme":"mist-v1","network":"base","resource":"http://fac.example.com/weather","payload":{"intentHash":"0x00"}}"#;
    let (status, body) = dispatch_with_v2(&base64_std_encode(json.as_bytes()));
    assert_eq!(status, 402);
    assert!(body.contains("missing x402Version"), "{body}");

    // 未知版本 → 402。
    let json =
        r#"{"x402Version":3,"accepted":{"scheme":"mist-v1","network":"eip155:8453"},"payload":{}}"#;
    let (status, body) = dispatch_with_v2(&base64_std_encode(json.as_bytes()));
    assert_eq!(status, 402);
    assert!(body.contains("unsupported x402Version 3"), "{body}");
}

/// 起带 asset 的 facilitator（v2 402 头在场）。
fn spawn_facilitator_v2(gateway_addr: &str, resource: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let f = Arc::new(Facilitator::new(FacilitatorConfig {
        gateway_addr: gateway_addr.into(),
        gateway_bearer: GATEWAY_KEY.into(),
        resource: resource.into(),
        pay_to: PAY_TO.into(),
        amount: AMOUNT.into(),
        network: NETWORK.into(),
        asset: Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into()),
        max_timeout_seconds: 30,
        protected_body: "{\"weather\":\"clear+28C\"}".into(),
    }));
    std::thread::spawn(move || {
        let _ = mist_facilitator::http::serve(f, listener);
    });
    format!("http://{addr}/")
}

#[test]
fn e2e_agent_negotiates_v2_wire_from_402_header() {
    // 402 带 PAYMENT-REQUIRED 头 → SDK client 谈判 v2：PAYMENT-SIGNATURE 重放 →
    // facilitator v2 mist 路径（CAIP-2 等价互通）→ 网关回执 → 200。
    let (gw_addr, wal, agg) = spawn_gateway("e2e-v2-negotiate");
    let resource = spawn_facilitator_v2(&gw_addr, "http://fac.example.com/weather");

    let transport = HttpTransport::new(&gw_addr, GATEWAY_KEY);
    let wallet = AgentWallet::from_seed([9u8; 32]);
    let owner = owner_signing_key_from_bytes([7u8; 32]);
    let mut client = SdkClient::new(wallet, Box::new(transport));
    client.set_retry(RetryPolicy {
        max_attempts: 3,
        base_backoff_ms: 0,
        max_backoff_ms: 0,
    });
    let rec = client.authorize(&owner, [1u8; 20], &limits()).unwrap();
    let dh = rec.delegation_hash;

    let x = X402Client::new(&client, &HttpFetch, dh);
    let outcome = x
        .request(&ResourceRequest::get(&resource))
        .expect("v2-negotiated roundtrip");

    match outcome {
        X402Outcome::Paid { response, proof } => {
            assert_eq!(response.status, 200);
            assert_eq!(response.body, b"{\"weather\":\"clear+28C\"}".to_vec());
            assert_eq!(agg.accepted_count(), 1);
            let receipt = agg.receipt(&proof.intent_hash).expect("receipt queryable");
            assert_eq!(receipt.seq, proof.seq);
        }
        X402Outcome::Free(_) => panic!("402 资源必须走支付路径"),
    }

    drop(client);
    let _ = std::fs::remove_file(&wal);
}

/// v2 exact 桥 payload（真 EIP-3009 签名，v2 wire 形）。
fn exact_payment_v2(spec: &ExactSpec, resource_url: &str) -> ExactPaymentV2 {
    let from_key = k256::ecdsa::SigningKey::from_bytes(&spec.from_seed.into()).expect("from key");
    let signer = k256::ecdsa::SigningKey::from_bytes(&spec.signer_seed.into()).expect("signer key");
    let point = from_key.verifying_key().to_encoded_point(false);
    let from: [u8; 20] = keccak256(&point.as_bytes()[1..65])[12..]
        .try_into()
        .expect("20 bytes");
    let auth = Authorization {
        from: format!("0x{}", hex::encode(from)),
        to: spec.to.into(),
        value: spec.value.into(),
        valid_after: spec.valid_after,
        valid_before: spec.valid_before,
        nonce: format!("0x{}", hex::encode(spec.nonce)),
    };
    let digest = eip3009_digest(spec.domain, &auth).expect("digest");
    let (sig, rid) = signer.sign_prehash_recoverable(&digest).expect("sign");
    let mut sig65 = sig.to_bytes().to_vec();
    sig65.push(rid.to_byte());
    ExactPaymentV2 {
        x402_version: X402_VERSION_V2,
        resource: Some(ResourceInfo {
            url: resource_url.into(),
            description: None,
            mime_type: None,
        }),
        accepted: ExactAcceptedV2 {
            scheme: "exact".into(),
            network: "eip155:8453".into(),
            amount: AMOUNT.into(),
            pay_to: Some(PAY_TO.into()),
            asset: Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into()),
            max_timeout_seconds: Some(30),
            extra: Some(mist_sdk::x402::Eip3009Extra {
                name: spec.domain.name.clone(),
                version: spec.domain.version.clone(),
            }),
        },
        payload: ExactPayload {
            signature: format!("0x{}", hex::encode(&sig65)),
            authorization: auth,
        },
    }
}

#[test]
fn e2e_exact_v2_bridge_signs_ingests_and_dedups() {
    // 官方 v2 client（@x402/evm exact）的 wire 形：accepted 对象 + PAYMENT-SIGNATURE。
    let (gw_addr, wal, agg) = spawn_gateway("e2e-eip3009-v2");
    let url = spawn_facilitator_with_bridge(&gw_addr, "http://fac.example.com/weather", None);
    let domain = Eip3009Domain {
        name: "USD Coin".into(),
        version: "2".into(),
        chain_id: 8453,
        verifying_contract: parse_addr20("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
            .expect("asset addr"),
    };
    let (after, before) = valid_window();

    // v2 exact client 付款 → 桥摄取 → 真记账 → 200 放行。
    let payment = exact_payment_v2(
        &ExactSpec {
            domain: &domain,
            from_seed: [3u8; 32],
            signer_seed: [3u8; 32],
            to: PAY_TO,
            value: AMOUNT,
            valid_after: after,
            valid_before: before,
            nonce: [0x52; 32],
        },
        "http://fac.example.com/weather",
    );
    let header = base64_std_encode(&serde_json::to_vec(&payment).expect("serialize v2 exact"));
    let (status, _, body) = raw_get_with_header(&url, "PAYMENT-SIGNATURE", &header);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, "{\"weather\":\"clear+28C\"}");
    assert_eq!(agg.accepted_count(), 1, "v2 桥必须摄取恰一笔");

    // 重放同 payload → 200 且不再摄取（重放闸对 v2 形同样生效）。
    let (status2, _, _) = raw_get_with_header(&url, "PAYMENT-SIGNATURE", &header);
    assert_eq!(status2, 200);
    assert_eq!(agg.accepted_count(), 1, "replay must not re-ingest");

    // 异链 CAIP-2 → 402 network mismatch（v2 绑定同样 fail-fast）。
    let mut wrong_net = payment.clone();
    wrong_net.accepted.network = "eip155:1".into();
    let (status3, _, body3) = raw_get_with_header(
        &url,
        "PAYMENT-SIGNATURE",
        &base64_std_encode(&serde_json::to_vec(&wrong_net).expect("serialize")),
    );
    assert_eq!(status3, 402, "{body3}");
    assert!(body3.contains("network mismatch"), "{body3}");

    // accepted.amount 与配置不符 → 402。
    let mut wrong_amount = payment;
    wrong_amount.accepted.amount = "999".into();
    let (status4, _, body4) = raw_get_with_header(
        &url,
        "PAYMENT-SIGNATURE",
        &base64_std_encode(&serde_json::to_vec(&wrong_amount).expect("serialize")),
    );
    assert_eq!(status4, 402, "{body4}");
    assert!(body4.contains("accepted.amount"), "{body4}");

    drop(agg);
    let _ = std::fs::remove_file(&wal);
}

#[test]
fn e2e_dual_headers_prefer_v2_over_v1() {
    // 双头同带（socket 层归一）：v2 头给坏版本、v1 头给合法形——若 v2 被选中，
    // 错误落在版本上而非回执查询上（对齐上游 payment-signature 优先序）。
    let (gw_addr, wal, agg) = spawn_gateway("e2e-dual-headers");
    let url = spawn_facilitator_v2(&gw_addr, "http://fac.example.com/weather");
    let v2_bad = base64_std_encode(
        br#"{"x402Version":9,"accepted":{"scheme":"mist-v1","network":"eip155:8453"},"payload":{}}"#,
    );
    let v1_ok = payment_header(
        "mist-v1",
        NETWORK,
        "http://fac.example.com/weather",
        &format!("0x{}", hex::encode([0x14u8; 32])),
    );
    let rest = url.strip_prefix("http://").expect("http url");
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let mut s = std::net::TcpStream::connect(authority).expect("connect");
    let req = format!(
        "GET /{path} HTTP/1.1\r\nHost: {authority}\r\nX-Payment: {v1_ok}\r\nPAYMENT-SIGNATURE: {v2_bad}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    assert!(
        resp.contains("unsupported x402Version 9"),
        "v2 头必须优先于 v1: {resp}"
    );
    drop(agg);
    let _ = std::fs::remove_file(&wal);
}
