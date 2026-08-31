//! S-13a 验收集成测试：真实 MCP 协议闭环 + 真实聚合器内核（WAL 持久化）。
//!
//! 用官方 rmcp client（任何 `ClientHandler`）通过 `tokio::io::duplex` 连接
//! MistServer，走完整 MCP JSON-RPC：`initialize` → `tools/call authorize/pay/
//! balance/attest/verify_receipt`。证明"agent 框架经 MCP 完成 DSA 授权 → 支付 → 对账"
//! 的全链路落在真实内核上（幂等 re-ack、单调 seq、预算强制、真错误码）。密钥与签名
//! 全部用 core 原语现场构造——绝无 mock。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey as AgentSigningKey;
use mist_aggregator::ingest::{Aggregator, IngestConfig};
use mist_aggregator::proof::FormatVerifier;
use mist_aggregator::wal::Wal;
use mist_core::attestation::{agent_commit, sign_binding, AttestationPubKey};
use mist_core::dsa::{
    delegation_hash, intent_hash, owner_signing_key_from_bytes, sign_delegation, sign_intent,
    Amount, Delegation, OwnerSigningKey, RateLimit, SpendIntent, PROTOCOL_VERSION,
};
use mist_mcp::tools::{AuthorizeRequest, PayRequest};
use mist_mcp::MistServer;
use rmcp::model::{CallToolRequestParams, ClientInfo, JsonObject};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{json, Value};

const AGENT_DID: [u8; 20] = [1u8; 20];
const OWNER_DID: [u8; 20] = [2u8; 20];
const TOTAL_CAP: Amount = 10_000;

/// 测试并行唯一 WAL 序号（防不同测试写同一文件）。
static WAL_SEQ: AtomicU32 = AtomicU32::new(0);

fn wal_path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mist-mcp-{}-{}-{}.wal",
        std::process::id(),
        tag,
        WAL_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    // 先删旧文件再 open（撕裂尾兜底，SDK e2e 同款模式）。
    let _ = std::fs::remove_file(&p);
    p
}

fn aggregator(tag: &str) -> Arc<Aggregator> {
    let wal = Wal::open(&wal_path(tag), 1_000).unwrap();
    Arc::new(Aggregator::new(
        IngestConfig::default(),
        Box::new(FormatVerifier),
        wal,
    ))
}

/// 探针客户端：仅实现 get_info，其余全默认（rmcp 官方测试同款）。
#[derive(Debug, Clone, Default)]
struct ProbeClient;

impl ClientHandler for ProbeClient {
    fn get_info(&self) -> ClientInfo {
        ClientInfo::default()
    }
}

fn delegation_fixture_with(max_per_spend: Amount, total_cap: Amount) -> Delegation {
    Delegation {
        agent: AGENT_DID,
        owner: OWNER_DID,
        nonce: 1,
        max_per_spend,
        rate: RateLimit {
            window_secs: 3_600,
            max_per_window: total_cap,
        },
        total_cap,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
        version: PROTOCOL_VERSION,
    }
}

fn delegation_fixture() -> Delegation {
    delegation_fixture_with(1_000, TOTAL_CAP)
}

fn intent_fixture(dh: [u8; 32], amount: Amount, nonce: u64) -> SpendIntent {
    SpendIntent {
        agent: AGENT_DID,
        delegation_hash: dh,
        recipient: [3u8; 20],
        amount,
        category: [0xCD; 32],
        spend_nonce: nonce,
        memo: None,
        expires_at: u64::MAX,
    }
}

fn owner_sec1_pubkey(owner_key: &OwnerSigningKey) -> String {
    hex::encode(owner_key.verifying_key().to_encoded_point(true).as_bytes())
}

/// 构造 authorize 工具参数（core 现场签名）。
fn authorize_args(
    d: &Delegation,
    owner_key: &OwnerSigningKey,
    agent_key: &AgentSigningKey,
) -> JsonObject {
    let sd = sign_delegation(d, owner_key);
    let req = AuthorizeRequest {
        agent: hex::encode(d.agent),
        owner: hex::encode(d.owner),
        nonce: d.nonce,
        max_per_spend: d.max_per_spend,
        rate_window_secs: d.rate.window_secs,
        rate_max_per_window: d.rate.max_per_window,
        total_cap: d.total_cap,
        categories: vec![],
        not_before: d.not_before,
        expires_at: d.expires_at,
        version: d.version,
        owner_signature: hex::encode(sd.signature.0),
        owner_pubkey: owner_sec1_pubkey(owner_key),
        agent_pubkey: hex::encode(agent_key.verifying_key().as_bytes()),
    };
    serde_json::to_value(&req)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

/// 构造 pay 工具参数（core 现场签名 intent）。
fn pay_args(i: &SpendIntent, sig: &ed25519_dalek::Signature) -> JsonObject {
    let req = PayRequest {
        agent: hex::encode(i.agent),
        delegation_hash: hex::encode(i.delegation_hash),
        recipient: hex::encode(i.recipient),
        amount: i.amount,
        category: hex::encode(i.category),
        spend_nonce: i.spend_nonce,
        memo: None,
        expires_at: i.expires_at,
        signature: hex::encode(sig.to_bytes()),
        proof: None,
    };
    serde_json::to_value(&req)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

fn balance_args(dh: [u8; 32]) -> JsonObject {
    json!({ "delegation_hash": hex::encode(dh) })
        .as_object()
        .unwrap()
        .clone()
}

fn verify_receipt_args(dh: [u8; 32], nonce: u64, ih: [u8; 32]) -> JsonObject {
    json!({ "delegation_hash": hex::encode(dh), "spend_nonce": nonce, "intent_hash": hex::encode(ih) })
        .as_object()
        .unwrap()
        .clone()
}

fn attest_args(
    dh: [u8; 32],
    pk: &AttestationPubKey,
    binding: &ed25519_dalek::Signature,
) -> JsonObject {
    json!({ "delegation_hash": hex::encode(dh), "pk_x": hex::encode(pk.x), "pk_y": hex::encode(pk.y),
            "binding": hex::encode(binding.to_bytes()) })
        .as_object()
        .unwrap()
        .clone()
}

/// MCP client 的具体类型：`serve()` 返回 `RunningService<RoleClient, H>`，
/// 其上的 `call_tool` 返回 `CallToolResult`。
type Probe = rmcp::service::RunningService<rmcp::RoleClient, ProbeClient>;

/// 起一个 in-process server + client，返回 (client, server_join_handle, aggregator)。
async fn setup(
    tag: &str,
) -> (
    Probe,
    tokio::task::JoinHandle<anyhow::Result<()>>,
    Arc<Aggregator>,
) {
    let agg = aggregator(tag);
    let (server_transport, client_transport) = tokio::io::duplex(4096);
    let server_agg = Arc::clone(&agg);
    let server_handle = tokio::spawn(async move {
        MistServer::new(server_agg)
            .serve(server_transport)
            .await?
            .waiting()
            .await?;
        anyhow::Ok(())
    });
    let client = ProbeClient.serve(client_transport).await.unwrap();
    (client, server_handle, agg)
}

async fn call_tool(
    client: &Probe,
    name: &'static str,
    args: JsonObject,
) -> rmcp::model::CallToolResult {
    client
        .call_tool(CallToolRequestParams::new(name).with_arguments(args))
        .await
        .expect("call_tool should not fail at protocol level")
}

/// 从工具回执中取文本内容。
fn result_text(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .expect("tool result should have text content")
        .to_string()
}

/// 从回执 JSON 里读 error 码（错误分支）。
fn error_code(result: &rmcp::model::CallToolResult) -> String {
    let body = result_text(result);
    let v: serde_json::Value = serde_json::from_str(&body).expect("error body is JSON");
    v["error"].as_str().expect("error field").to_string()
}

/// 从 Ok 回执 JSON 取 body（供字段断言）。
fn body(result: &rmcp::model::CallToolResult) -> Value {
    serde_json::from_str(&result_text(result)).expect("ok body is JSON")
}

#[tokio::test]
async fn authorize_then_pay_closed_loop() -> anyhow::Result<()> {
    let (client, server_handle, agg) = setup("closed_loop").await;

    // ---- 1. authorize：owner 签名委托，绑定 agent 身份 ----
    let d = delegation_fixture();
    let owner_key = owner_signing_key_from_bytes([7u8; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
    let auth = call_tool(
        &client,
        "authorize",
        authorize_args(&d, &owner_key, &agent_key),
    )
    .await;
    assert!(!auth.is_error.unwrap_or(false), "authorize should succeed");
    let auth_body = body(&auth);
    assert_eq!(
        auth_body["delegation_hash"].as_str().unwrap(),
        hex::encode(delegation_hash(&d)),
        "server-computed delegation_hash must match core canonical hash"
    );
    assert_eq!(auth_body["total_cap"].as_u64().unwrap(), TOTAL_CAP);

    // ---- 2. pay：agent 签名 intent，真实内核记账 ----
    let dh = delegation_hash(&d);
    let i = intent_fixture(dh, 42, 1);
    let sig = sign_intent(&i, &agent_key);
    let pay = call_tool(&client, "pay", pay_args(&i, &sig)).await;
    assert!(!pay.is_error.unwrap_or(false), "pay should succeed");
    let pay_body = body(&pay);
    assert_eq!(pay_body["seq"].as_u64().unwrap(), 0);
    assert_eq!(pay_body["spend_nonce"].as_u64().unwrap(), 1);
    assert_eq!(
        pay_body["intent_hash"].as_str().unwrap(),
        hex::encode(intent_hash(&i))
    );

    // ---- 3. 第二笔：seq 单调，聚合器账面对得上 ----
    let i2 = intent_fixture(dh, 100, 2);
    let sig2 = sign_intent(&i2, &agent_key);
    let pay2 = call_tool(&client, "pay", pay_args(&i2, &sig2)).await;
    assert!(!pay2.is_error.unwrap_or(false));
    assert_eq!(body(&pay2)["seq"].as_u64().unwrap(), 1);

    // ---- 4. balance：额度滚动 ----
    let bal = call_tool(&client, "balance", balance_args(dh)).await;
    let bal_body = body(&bal);
    assert_eq!(bal_body["total_spent"].as_u64().unwrap(), 142);
    assert_eq!(bal_body["remaining"].as_u64().unwrap(), TOTAL_CAP - 142);

    // ---- 5. 聚合器观测 ----
    assert_eq!(agg.accepted_count(), 2);
    assert_eq!(agg.total_spent(&dh), Some(142));
    assert_eq!(agg.nonce_count(&dh), Some(2));

    // ---- 6. verify_receipt：已接受意图有 seq ----
    let vr = call_tool(
        &client,
        "verify_receipt",
        verify_receipt_args(dh, 1, intent_hash(&i)),
    )
    .await;
    let vr_body = body(&vr);
    assert!(vr_body["accepted"].as_bool().unwrap());
    assert_eq!(vr_body["seq"].as_u64().unwrap(), 0);

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn idempotent_repay_same_nonce_same_seq() -> anyhow::Result<()> {
    let (client, server_handle, agg) = setup("re_ack").await;

    let d = delegation_fixture();
    let owner_key = owner_signing_key_from_bytes([7u8; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
    let auth = call_tool(
        &client,
        "authorize",
        authorize_args(&d, &owner_key, &agent_key),
    )
    .await;
    assert!(!auth.is_error.unwrap_or(false));

    let dh = delegation_hash(&d);
    let i = intent_fixture(dh, 10, 1);
    let sig = sign_intent(&i, &agent_key);

    // 同意图重发 → re-ack 原 seq，不重复记账、不报 E_NONCE（S-12 幂等闸口）。
    let first = call_tool(&client, "pay", pay_args(&i, &sig)).await;
    assert!(!first.is_error.unwrap_or(false));
    let first_seq = body(&first)["seq"].as_u64().unwrap();
    let replay = call_tool(&client, "pay", pay_args(&i, &sig)).await;
    assert!(
        !replay.is_error.unwrap_or(false),
        "same-intent resend re-acks"
    );
    assert_eq!(body(&replay)["seq"].as_u64().unwrap(), first_seq);
    assert_eq!(agg.accepted_count(), 1);
    assert_eq!(agg.total_spent(&dh), Some(10));

    // 跨意图同 nonce 复用 → E_NONCE（§6.2 保留）。
    let i_other = intent_fixture(dh, 20, 1); // 同 nonce、不同 recipient → 不同 intent_hash
    let sig_other = sign_intent(&i_other, &agent_key);
    let cross = call_tool(&client, "pay", pay_args(&i_other, &sig_other)).await;
    assert!(cross.is_error.unwrap_or(false));
    assert_eq!(error_code(&cross), "E_NONCE");
    assert_eq!(agg.accepted_count(), 1);

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn pay_rejects_forged_agent_sig_and_budget() -> anyhow::Result<()> {
    let (client, server_handle, agg) = setup("rejects").await;

    let d = delegation_fixture_with(100, TOTAL_CAP);
    let owner_key = owner_signing_key_from_bytes([7u8; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
    let auth = call_tool(
        &client,
        "authorize",
        authorize_args(&d, &owner_key, &agent_key),
    )
    .await;
    assert!(!auth.is_error.unwrap_or(false));
    let dh = delegation_hash(&d);

    // ---- 伪造 agent 签名：换私钥签同一 intent → E_INTENT_SIG ----
    let i = intent_fixture(dh, 1, 1);
    let impostor = AgentSigningKey::from_bytes(&[0xB0; 32]);
    let forged = sign_intent(&i, &impostor);
    let forged_result = call_tool(&client, "pay", pay_args(&i, &forged)).await;
    assert!(forged_result.is_error.unwrap_or(false));
    assert_eq!(error_code(&forged_result), "E_INTENT_SIG");

    // ---- 超单笔上限：101 > 100 → E_BUDGET_PER_SPEND；nonce 已消耗、未接受 ----
    let over = intent_fixture(dh, 101, 2);
    let sig_over = sign_intent(&over, &agent_key);
    let over_result = call_tool(&client, "pay", pay_args(&over, &sig_over)).await;
    assert!(over_result.is_error.unwrap_or(false));
    assert_eq!(error_code(&over_result), "E_BUDGET_PER_SPEND");
    assert_eq!(agg.total_spent(&dh), Some(0));
    assert_eq!(agg.nonce_count(&dh), Some(1));

    // 该被拒 nonce 的 verify_receipt → accepted=false（拒绝与未知同报）。
    let vr = call_tool(
        &client,
        "verify_receipt",
        verify_receipt_args(dh, 2, intent_hash(&over)),
    )
    .await;
    assert!(!body(&vr)["accepted"].as_bool().unwrap());

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn authorize_rejects_forged_owner_signature() -> anyhow::Result<()> {
    let (client, server_handle, _agg) = setup("bad_owner").await;

    let d = delegation_fixture();
    let real_owner = owner_signing_key_from_bytes([7u8; 32]);
    let forged_owner = owner_signing_key_from_bytes([0xE0; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);

    // 用错误 owner 私钥签名 → 验签失败 E_DELEG_SIG
    let mut args = authorize_args(&d, &forged_owner, &agent_key);
    args.insert("owner_pubkey".into(), json!(owner_sec1_pubkey(&real_owner)));
    let result = call_tool(&client, "authorize", args).await;
    assert!(result.is_error.unwrap_or(false));
    assert_eq!(error_code(&result), "E_DELEG_SIG");

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn authorize_idempotent_and_binds_agent() -> anyhow::Result<()> {
    let (client, server_handle, agg) = setup("bind").await;

    let d = delegation_fixture();
    let owner_key = owner_signing_key_from_bytes([7u8; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);

    // 同 dh 同 agent → 幂等返回，注册表只有一条。
    let a1 = call_tool(
        &client,
        "authorize",
        authorize_args(&d, &owner_key, &agent_key),
    )
    .await;
    assert!(!a1.is_error.unwrap_or(false));
    let a2 = call_tool(
        &client,
        "authorize",
        authorize_args(&d, &owner_key, &agent_key),
    )
    .await;
    assert!(!a2.is_error.unwrap_or(false));
    assert_eq!(
        body(&a2)["delegation_hash"].as_str().unwrap(),
        hex::encode(delegation_hash(&d))
    );
    assert_eq!(agg.registry_len(), 1);

    // 同 dh 异 agent → E_ATTEST_BIND（禁止换钥重绑）。
    let other_agent = AgentSigningKey::from_bytes(&[0xA0; 32]);
    let rebind = call_tool(
        &client,
        "authorize",
        authorize_args(&d, &owner_key, &other_agent),
    )
    .await;
    assert!(rebind.is_error.unwrap_or(false));
    assert_eq!(error_code(&rebind), "E_ATTEST_BIND");
    assert_eq!(agg.registry_len(), 1);

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn unregistered_delegation_pay_rejected() -> anyhow::Result<()> {
    let (client, server_handle, _agg) = setup("unknown").await;

    // 没走 authorize，直接 pay 一个随机构造 intent → E_DELEG_UNKNOWN（内核注册表未注册）。
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
    let i = SpendIntent {
        agent: AGENT_DID,
        delegation_hash: [0xEE; 32],
        recipient: [3u8; 20],
        amount: 1,
        category: [0xCD; 32],
        spend_nonce: 1,
        memo: None,
        expires_at: u64::MAX,
    };
    let sig = sign_intent(&i, &agent_key);
    let result = call_tool(&client, "pay", pay_args(&i, &sig)).await;
    assert!(result.is_error.unwrap_or(false));
    assert_eq!(error_code(&result), "E_DELEG_UNKNOWN");

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn balance_after_authorize() -> anyhow::Result<()> {
    let (client, server_handle, _agg) = setup("balance").await;

    let d = delegation_fixture();
    let owner_key = owner_signing_key_from_bytes([7u8; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
    let auth = call_tool(
        &client,
        "authorize",
        authorize_args(&d, &owner_key, &agent_key),
    )
    .await;
    assert!(!auth.is_error.unwrap_or(false));
    let dh = delegation_hash(&d);

    // 未支付：total_spent=0、remaining=total_cap。
    let bal = call_tool(&client, "balance", balance_args(dh)).await;
    let bal_body = body(&bal);
    assert_eq!(bal_body["total_spent"].as_u64().unwrap(), 0);
    assert_eq!(bal_body["total_cap"].as_u64().unwrap(), TOTAL_CAP);
    assert_eq!(bal_body["remaining"].as_u64().unwrap(), TOTAL_CAP);

    // 一笔后：滚动。
    let i = intent_fixture(dh, 42, 1);
    let sig = sign_intent(&i, &agent_key);
    let pay = call_tool(&client, "pay", pay_args(&i, &sig)).await;
    assert!(!pay.is_error.unwrap_or(false));
    let bal2 = call_tool(&client, "balance", balance_args(dh)).await;
    assert_eq!(body(&bal2)["total_spent"].as_u64().unwrap(), 42);

    // 未授权 dh → E_DELEG_UNKNOWN。
    let unknown = call_tool(&client, "balance", balance_args([0xDD; 32])).await;
    assert!(unknown.is_error.unwrap_or(false));
    assert_eq!(error_code(&unknown), "E_DELEG_UNKNOWN");

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn verify_receipt_accepted_and_unknown() -> anyhow::Result<()> {
    let (client, server_handle, _agg) = setup("verify").await;

    let d = delegation_fixture();
    let owner_key = owner_signing_key_from_bytes([7u8; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
    let auth = call_tool(
        &client,
        "authorize",
        authorize_args(&d, &owner_key, &agent_key),
    )
    .await;
    assert!(!auth.is_error.unwrap_or(false));
    let dh = delegation_hash(&d);

    // 已接受 → {accepted:true, seq}。
    let i = intent_fixture(dh, 42, 1);
    let sig = sign_intent(&i, &agent_key);
    let pay = call_tool(&client, "pay", pay_args(&i, &sig)).await;
    assert!(!pay.is_error.unwrap_or(false));
    let vr = call_tool(
        &client,
        "verify_receipt",
        verify_receipt_args(dh, 1, intent_hash(&i)),
    )
    .await;
    let vr_body = body(&vr);
    assert!(vr_body["accepted"].as_bool().unwrap());
    assert_eq!(vr_body["seq"].as_u64().unwrap(), 0);

    // 从未提交 → {accepted:false, seq:0}（infallible，无错误码）。
    let never = call_tool(
        &client,
        "verify_receipt",
        verify_receipt_args(dh, 99, [0xFF; 32]),
    )
    .await;
    assert!(!never.is_error.unwrap_or(false));
    let never_body = body(&never);
    assert!(!never_body["accepted"].as_bool().unwrap());
    assert_eq!(never_body["seq"].as_u64().unwrap(), 0);

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn attest_verify_and_tamper_reject() -> anyhow::Result<()> {
    let (client, server_handle, _agg) = setup("attest").await;

    let d = delegation_fixture();
    let owner_key = owner_signing_key_from_bytes([7u8; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
    let auth = call_tool(
        &client,
        "authorize",
        authorize_args(&d, &owner_key, &agent_key),
    )
    .await;
    assert!(!auth.is_error.unwrap_or(false));
    let dh = delegation_hash(&d);

    // 合法绑定：agent Ed25519（authorize 绑定）对 BabyJubJub 公钥签名。
    let pk = AttestationPubKey {
        x: [0x11; 32],
        y: [0x22; 32],
    };
    let binding = sign_binding(&agent_key, &pk);
    let att = call_tool(&client, "attest", attest_args(dh, &pk, &binding)).await;
    assert!(!att.is_error.unwrap_or(false), "attest should succeed");
    let att_body = body(&att);
    assert_eq!(
        att_body["agent_commit"].as_str().unwrap(),
        hex::encode(agent_commit(&pk))
    );

    // 篡改 pk_x → 绑定消息不匹配 → E_ATTEST_BIND。
    let mut forged = pk;
    forged.x[0] ^= 0x01;
    let att_forged = call_tool(&client, "attest", attest_args(dh, &forged, &binding)).await;
    assert!(att_forged.is_error.unwrap_or(false));
    assert_eq!(error_code(&att_forged), "E_ATTEST_BIND");

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

// ---------------------------------------------------------------------------
// S-52（TECH_SPEC §6.16）：客户端直通证明 + revocation_witness 事实面
// ---------------------------------------------------------------------------

/// 直通证明入参（S-52 wire：proof_hex + 三个自由量；共享字段由服务器从意图派生）。
fn proof_args(
    i: &SpendIntent,
    sig: &ed25519_dalek::Signature,
    proof_bytes: &[u8],
    agent_commit: [u8; 32],
    revocation_root: [u8; 32],
    now: u64,
) -> JsonObject {
    let req = PayRequest {
        agent: hex::encode(i.agent),
        delegation_hash: hex::encode(i.delegation_hash),
        recipient: hex::encode(i.recipient),
        amount: i.amount,
        category: hex::encode(i.category),
        spend_nonce: i.spend_nonce,
        memo: None,
        expires_at: i.expires_at,
        signature: hex::encode(sig.to_bytes()),
        proof: Some(mist_mcp::tools::ProofRequest {
            proof_hex: hex::encode(proof_bytes),
            agent_commit: hex::encode(agent_commit),
            revocation_root: hex::encode(revocation_root),
            now,
        }),
    };
    serde_json::to_value(&req)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

#[tokio::test]
async fn pay_with_client_proof_flows_through_format_backend() -> anyhow::Result<()> {
    let (client, server_handle, agg) = setup("proof_passthrough").await;

    let d = delegation_fixture();
    let owner_key = owner_signing_key_from_bytes([7u8; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
    let auth = call_tool(
        &client,
        "authorize",
        authorize_args(&d, &owner_key, &agent_key),
    )
    .await;
    assert!(!auth.is_error.unwrap_or(false));
    let dh = delegation_hash(&d);

    // 客户端直通证明（format 后端：proof 非空 + 公共输入与意图一致即过）。
    // 共享字段不在线上——服务器从意图派生，`check_public_inputs_consistent` 保证
    // 派生结果与证明声称的是同一笔意图（§6.16）。
    let i = intent_fixture(dh, 7, 1);
    let sig = sign_intent(&i, &agent_key);
    let pay = call_tool(
        &client,
        "pay",
        proof_args(
            &i,
            &sig,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            [0x11; 32],
            [0x22; 32],
            1_750_000_000,
        ),
    )
    .await;
    assert!(
        !pay.is_error.unwrap_or(false),
        "client proof should be accepted"
    );
    assert_eq!(body(&pay)["seq"].as_u64().unwrap(), 0);
    assert_eq!(agg.accepted_count(), 1);

    // 空 proof 字节 → E_PROOF（fail-closed，不因直通而绕过非空闸）。
    let i2 = intent_fixture(dh, 8, 2);
    let sig2 = sign_intent(&i2, &agent_key);
    let empty = call_tool(
        &client,
        "pay",
        proof_args(&i2, &sig2, &[], [0x11; 32], [0x22; 32], 1_750_000_000),
    )
    .await;
    assert!(empty.is_error.unwrap_or(false));
    assert_eq!(error_code(&empty), "E_PROOF");

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn pay_client_proof_reaches_verifier_not_server_placeholder() -> anyhow::Result<()> {
    // RejectAllVerifier 对照组（§6.16 测试口径）：若服务器把直通证明偷偷换成自己的
    // 占位（占位在 format 后端必过），本测试必红——直通证明**真实进入验证缝**。
    let agg = {
        let wal = Wal::open(&wal_path("proof_reject_all"), 1_000).unwrap();
        Arc::new(Aggregator::new(
            IngestConfig::default(),
            Box::new(mist_aggregator::proof::RejectAllVerifier),
            wal,
        ))
    };
    let (server_transport, client_transport) = tokio::io::duplex(4096);
    let server_agg = Arc::clone(&agg);
    let server_handle = tokio::spawn(async move {
        MistServer::new(server_agg)
            .serve(server_transport)
            .await?
            .waiting()
            .await?;
        anyhow::Ok(())
    });
    let client = ProbeClient.serve(client_transport).await.unwrap();

    let d = delegation_fixture();
    let owner_key = owner_signing_key_from_bytes([7u8; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
    let auth = call_tool(
        &client,
        "authorize",
        authorize_args(&d, &owner_key, &agent_key),
    )
    .await;
    assert!(!auth.is_error.unwrap_or(false));
    let dh = delegation_hash(&d);

    let i = intent_fixture(dh, 7, 1);
    let sig = sign_intent(&i, &agent_key);
    let pay = call_tool(
        &client,
        "pay",
        proof_args(
            &i,
            &sig,
            &[0x01, 0x02],
            [0x11; 32],
            [0x22; 32],
            1_750_000_000,
        ),
    )
    .await;
    assert!(
        pay.is_error.unwrap_or(false),
        "client proof must be verified"
    );
    assert_eq!(error_code(&pay), "E_PROOF");
    assert_eq!(agg.accepted_count(), 0);

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn revocation_witness_tool_serves_ledger_fact() -> anyhow::Result<()> {
    let (client, server_handle, agg) = setup("witness").await;

    let d = delegation_fixture();
    let owner_key = owner_signing_key_from_bytes([7u8; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
    let auth = call_tool(
        &client,
        "authorize",
        authorize_args(&d, &owner_key, &agent_key),
    )
    .await;
    assert!(!auth.is_error.unwrap_or(false));
    let dh = delegation_hash(&d);

    // 未撤销 → 非成员 witness（root = 空根，path = 256×32B 扁平 hex）。
    let wit = call_tool(
        &client,
        "revocation_witness",
        json!({ "delegation_hash": hex::encode(dh) })
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    assert!(!wit.is_error.unwrap_or(false), "non-revoked dh has witness");
    let wit_body = body(&wit);
    assert_eq!(
        wit_body["delegation_hash"].as_str().unwrap(),
        hex::encode(dh)
    );
    assert_eq!(wit_body["root"].as_str().unwrap().len(), 64);
    let path_hex = wit_body["path"].as_str().unwrap();
    assert_eq!(
        path_hex.len(),
        256 * 64,
        "256 × 32B 扁平 hex（S-42 树口径）"
    );

    // 服务器账本撤销另一张委托（与 m1_demo/noir_demo 同款通道）→ 根推进。
    let mut other = [0x5E; 32];
    other[31] = 0x01;
    assert!(agg.revoke(other));

    // 目标仍未撤销 → witness 可再取，root 已推进（同一棵确定性树）。
    let wit2 = call_tool(
        &client,
        "revocation_witness",
        json!({ "delegation_hash": hex::encode(dh) })
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let wit2_body = body(&wit2);
    assert_ne!(
        wit2_body["root"].as_str().unwrap(),
        wit_body["root"].as_str().unwrap(),
        "撤销事件推进撤销状态根"
    );

    // 目标已撤销 → E_REVOKED（S-42 fail-closed：非成员接口不给成员陈述）。
    assert!(agg.revoke(dh));
    let revoked = call_tool(
        &client,
        "revocation_witness",
        json!({ "delegation_hash": hex::encode(dh) })
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    assert!(revoked.is_error.unwrap_or(false));
    assert_eq!(error_code(&revoked), "E_REVOKED");

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}
