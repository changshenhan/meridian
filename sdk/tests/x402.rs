//! S-30b x402 客户端集成验收（TECH_SPEC §6.8）：scripted Fetch mock 走线格式全链路，
//! 支付路径用真实聚合器（进程内 + 真实密码学，与 e2e.rs 同口径）。
//!
//! 覆盖：free 透传 / 402→pay→X-PAYMENT 重放（真实记账 + 网关回执可查）/ 无 meridian-v1
//! 条目拒 / 二次 402 拒 / category 绑定 owner 白名单 / HttpFetch 真 socket。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::proof::FormatVerifier;
use meridian_aggregator::wal::Wal;
use meridian_core::dsa::owner_signing_key_from_bytes;

use meridian_sdk::x402::{
    base64url_encode, category_from_resource, Fetch, HttpFetch, ResourceRequest, X402Client,
    X402Outcome,
};
use meridian_sdk::{AgentWallet, DelegationLimits, InProcessAggregator, SdkClient, SdkError};

// ---------------------------------------------------------------------------
// 脚手架（与 e2e.rs 同款）
// ---------------------------------------------------------------------------

static WAL_SEQ: AtomicU32 = AtomicU32::new(0);

fn aggregator(tag: &str) -> (PathBuf, Arc<Aggregator>) {
    let path = std::env::temp_dir().join(format!(
        "meridian-sdk-x402-{}-{tag}-{seq}.wal",
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

const PAY_TO: &str = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const RESOURCE: &str = "http://api.example.com/weather?city=suzhou";

/// 402 体（x402 v1 线格式，camelCase、金额字符串）。
fn payment_required_body(scheme: &str, amount: &str) -> String {
    format!(
        r#"{{"x402Version":1,"error":"Payment required","accepts":[{{"scheme":"{scheme}","network":"base","maxAmountRequired":"{amount}","resource":"{resource}","payTo":"{pay_to}","maxTimeoutSeconds":30,"asset":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}}]}}"#,
        resource = RESOURCE,
        pay_to = PAY_TO
    )
}

/// 测试内 base64url 解码（与 SDK 编码互锁，断言重放头内容用）。
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
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
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        buf = (buf << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// scripted Fetch mock：按脚本依次吐响应，并记录收到的请求（断言重放头用）
// ---------------------------------------------------------------------------

struct ScriptedFetch {
    /// 每次 fetch 依序取一个响应。
    script: Mutex<Vec<meridian_sdk::x402::ResourceResponse>>,
    seen: Mutex<Vec<meridian_sdk::x402::ResourceRequest>>,
}

impl ScriptedFetch {
    fn new(responses: Vec<meridian_sdk::x402::ResourceResponse>) -> Self {
        ScriptedFetch {
            script: Mutex::new(responses),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<meridian_sdk::x402::ResourceRequest> {
        self.seen.lock().expect("seen").clone()
    }
}

impl Fetch for ScriptedFetch {
    fn fetch(
        &self,
        req: &meridian_sdk::x402::ResourceRequest,
    ) -> Result<meridian_sdk::x402::ResourceResponse, SdkError> {
        self.seen.lock().expect("seen").push(req.clone());
        self.script
            .lock()
            .expect("script")
            .pop()
            .ok_or_else(|| SdkError::Local("script exhausted".into()))
    }
}

fn response(status: u16, body: String) -> meridian_sdk::x402::ResourceResponse {
    meridian_sdk::x402::ResourceResponse {
        status,
        headers: vec![("content-type".into(), "application/json".into())],
        body: body.into_bytes(),
    }
}

/// 组装：真聚合器 + 已授权 client + X402Client。
fn setup(tag: &str, limits: DelegationLimits) -> (PathBuf, Arc<Aggregator>, SdkClient, [u8; 32]) {
    let (path, agg) = aggregator(tag);
    let transport = InProcessAggregator::from_inner(Arc::clone(&agg));
    let wallet = AgentWallet::from_seed([9u8; 32]);
    let owner = owner_signing_key_from_bytes([7u8; 32]);
    let client = SdkClient::new(wallet, Box::new(transport));
    let rec = client.authorize(&owner, [1u8; 20], &limits).unwrap();
    (path, agg, client, rec.delegation_hash)
}

// ---------------------------------------------------------------------------
// 1. 非 402：原样透传，未发生任何支付
// ---------------------------------------------------------------------------

#[test]
fn free_response_passthrough_no_payment() {
    let (path, agg, client, dh) = setup("free", limits());
    let fetch = ScriptedFetch::new(vec![response(200, "{\"ok\":true}".into())]);
    let x = X402Client::new(&client, &fetch, dh);

    match x.request(&ResourceRequest::get(RESOURCE)).unwrap() {
        X402Outcome::Free(r) => {
            assert_eq!(r.status, 200);
            assert_eq!(r.body, b"{\"ok\":true}".to_vec());
        }
        X402Outcome::Paid { .. } => panic!("免费资源不得进入支付路径"),
    }

    // 聚合器零记账。
    assert_eq!(agg.accepted_count(), 0);
    drop(client);
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// 2.【主验收】402 → pay（真实密码学 + 真实记账）→ X-PAYMENT 重放 → Paid{proof}
// ---------------------------------------------------------------------------

#[test]
fn e2e_402_pay_replay_x402_wire() {
    let (path, agg, client, dh) = setup("e2e-402", limits());
    let fetch = ScriptedFetch::new(vec![
        // 第二次（重放）：资源服务器放行。
        response(200, "{\"weather\":\"clear+28C\"}".into()),
        // 第一次：402 + paymentRequirements。
        response(402, payment_required_body("meridian-v1", "10000")),
    ]);
    let x = X402Client::new(&client, &fetch, dh);

    let proof = match x.request(&ResourceRequest::get(RESOURCE)).unwrap() {
        X402Outcome::Paid { response, proof } => {
            assert_eq!(response.status, 200);
            assert_eq!(response.body, b"{\"weather\":\"clear+28C\"}".to_vec());
            proof
        }
        X402Outcome::Free(_) => panic!("402 资源必须走支付路径"),
    };

    // 重放请求带 X-PAYMENT 头，内容为 base64url(camelCase JSON)。
    let requests = fetch.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].headers.is_empty(), "首请求不带支付头");
    let header = &requests[1]
        .headers
        .iter()
        .find(|(k, _)| k == "X-PAYMENT")
        .expect("重放必须带 X-PAYMENT 头")
        .1;
    assert!(
        !header.contains('+') && !header.contains('/') && !header.contains('='),
        "base64url 无 padding：{header}"
    );
    let json = String::from_utf8(base64url_decode(header).expect("decode")).expect("utf8");
    assert!(json.contains("\"x402Version\":1"));
    assert!(json.contains("\"scheme\":\"meridian-v1\""));
    assert!(json.contains("\"network\":\"base\""));
    assert!(json.contains(&format!("\"resource\":\"{RESOURCE}\"")));
    assert!(json.contains("\"intentHash\":\"0x"));
    assert!(json.contains("\"seq\":0"));
    assert!(json.contains("\"spendNonce\":1"));

    // 真实记账：恰一笔、金额 = maxAmountRequired、nonce 消耗 1。
    assert_eq!(agg.accepted_count(), 1);
    assert_eq!(agg.total_spent(&dh), Some(10_000));
    assert_eq!(agg.nonce_count(&dh), Some(1));

    // proof ↔ 网关回执（S-30a merchant 验证面）：同一意图、同一 seq。
    assert_eq!(proof.seq, 0);
    assert_eq!(proof.spend_nonce, 1);
    let receipt = agg.receipt(&proof.intent_hash).expect("回执必须可查");
    assert_eq!(receipt.intent_hash, proof.intent_hash);
    assert_eq!(receipt.seq, proof.seq);

    drop(client);
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// 3. 402 无 meridian-v1 条目 → Local（不伪装成其它 scheme 的 client）
// ---------------------------------------------------------------------------

#[test]
fn no_meridian_scheme_entry_is_local_error() {
    let (path, agg, client, dh) = setup("no-scheme", limits());
    let fetch = ScriptedFetch::new(vec![response(402, payment_required_body("exact", "10000"))]);
    let x = X402Client::new(&client, &fetch, dh);

    let err = x.request(&ResourceRequest::get(RESOURCE)).unwrap_err();
    assert!(matches!(err, SdkError::Local(_)));
    assert_eq!(agg.accepted_count(), 0, "未支付不得记账");

    drop(client);
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// 4. 二次 402：支付被资源服务器拒绝 → Local，不重试
// ---------------------------------------------------------------------------

#[test]
fn second_402_is_local_error() {
    let (path, agg, client, dh) = setup("second-402", limits());
    let fetch = ScriptedFetch::new(vec![
        response(402, payment_required_body("meridian-v1", "10000")),
        response(402, payment_required_body("meridian-v1", "10000")),
    ]);
    let x = X402Client::new(&client, &fetch, dh);

    let err = x.request(&ResourceRequest::get(RESOURCE)).unwrap_err();
    assert!(matches!(err, SdkError::Local(_)));
    let msg = err.to_string();
    assert!(msg.contains("rejected by resource server"), "{msg}");

    // 网关侧已接受（钱已出），merchant 侧排查——错误信息里带 intent_hash（0x hex）。
    assert_eq!(agg.accepted_count(), 1);
    assert!(msg.contains("intent_hash 0x"), "{msg}");
    assert!(msg.contains("seq 0"), "{msg}");

    drop(client);
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// 5. category 映射：resource → sha256(host+path) 进意图类目，与 owner 白名单同构
//
// 诚实边界（测试固化）：TEMPORARY 占位管线（PlaceholderProver + FormatVerifier）里
// 账本**不**强制类别白名单——白名单强制点 = ZK 电路断言 4（TECH_SPEC §5.2）与
// Contract 模式链上（§4.7）。账本只管预算（§4.5 规则清单无白名单）。因此本测试只验
// 映射正确性（白名单 = 派生类目时全链路无阻），负向（E_CATEGORY）等真 ZK 集成后补。
// ---------------------------------------------------------------------------

#[test]
fn category_maps_to_delegation_whitelist() {
    // 白名单 = resource 的 host+path 哈希 → 映射命中，全链路支付成功。
    let mut allow = limits();
    allow.categories = vec![category_from_resource(RESOURCE)];
    let (path, agg, client, dh) = setup("cat-ok", allow);
    let fetch = ScriptedFetch::new(vec![
        response(200, "ok".into()),
        response(402, payment_required_body("meridian-v1", "100")),
    ]);
    let x = X402Client::new(&client, &fetch, dh);
    assert!(matches!(
        x.request(&ResourceRequest::get(RESOURCE)).unwrap(),
        X402Outcome::Paid { .. }
    ));
    assert_eq!(agg.accepted_count(), 1);
    drop(client);
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// 6. HttpFetch：真 socket 往返（明文 http://，Content-Length 定长读）
// ---------------------------------------------------------------------------

#[test]
fn http_fetch_real_socket_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let body = "{\"weather\":\"clear+28C\"}";

    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf).expect("read request");
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        // 请求行 + Host + Connection: close 必须在线。
        assert!(req.starts_with("GET /weather?city=suzhou HTTP/1.1\r\n"));
        assert!(req.contains("Host: 127.0.0.1"));
        assert!(req.contains("Connection: close"));
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        conn.write_all(resp.as_bytes()).expect("write response");
    });

    let resp = HttpFetch
        .fetch(&ResourceRequest::get(format!(
            "http://{addr}/weather?city=suzhou"
        )))
        .expect("roundtrip");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, body.as_bytes().to_vec());
    server.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// 7. 重放头构造复用：encode 侧向量（与单测互锁的集成侧抽查）
// ---------------------------------------------------------------------------

#[test]
fn base64url_encode_integration_spot() {
    assert_eq!(base64url_encode(b"foobar"), "Zm9vYmFy");
    assert_eq!(base64url_encode(b""), "");
}
