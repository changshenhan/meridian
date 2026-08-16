//! S-07 验收集成测试：真实 MCP 协议闭环。
//!
//! 用官方 rmcp client（任何 `ClientHandler`）通过 `tokio::io::duplex` 连接
//! MeridianServer，走完整 MCP JSON-RPC：`initialize` → `tools/call authorize`
//! → `tools/call pay`。证明"主流 agent 框架内可调 pay() 完成一次模拟支付闭环"
//! （S-07 验收口径）。密钥与签名全部用 core 原语现场构造——绝无 mock。

use ed25519_dalek::SigningKey as AgentSigningKey;
use meridian_core::dsa::{
    delegation_hash, owner_signing_key_from_bytes, sign_delegation, sign_intent, Amount,
    Delegation, OwnerSigningKey, RateLimit, SpendIntent, PROTOCOL_VERSION,
};
use meridian_mcp::tools::{AuthorizeRequest, PayRequest};
use meridian_mcp::MeridianServer;
use rmcp::model::{CallToolRequestParams, ClientInfo, JsonObject};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::json;

const AGENT_DID: [u8; 20] = [1u8; 20];
const OWNER_DID: [u8; 20] = [2u8; 20];
const TOTAL_CAP: Amount = 10_000;

/// 探针客户端：仅实现 get_info，其余全默认（rmcp 官方测试同款）。
#[derive(Debug, Clone, Default)]
struct ProbeClient;

impl ClientHandler for ProbeClient {
    fn get_info(&self) -> ClientInfo {
        ClientInfo::default()
    }
}

fn delegation_fixture() -> Delegation {
    Delegation {
        agent: AGENT_DID,
        owner: OWNER_DID,
        nonce: 1,
        max_per_spend: 1_000,
        rate: RateLimit {
            window_secs: 3_600,
            max_per_window: TOTAL_CAP,
        },
        total_cap: TOTAL_CAP,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
        version: PROTOCOL_VERSION,
    }
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
    };
    serde_json::to_value(&req)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

/// MCP client 的具体类型：`serve()` 返回 `RunningService<RoleClient, H>`，
/// 其上的 `call_tool` 返回 `CallToolResult`。
type Probe = rmcp::service::RunningService<rmcp::RoleClient, ProbeClient>;

/// 起一个 in-process server + client，返回 (client, server_join_handle)。
async fn setup() -> (Probe, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let (server_transport, client_transport) = tokio::io::duplex(4096);
    let server_handle = tokio::spawn(async move {
        MeridianServer::new()
            .serve(server_transport)
            .await?
            .waiting()
            .await?;
        anyhow::Ok(())
    });
    let client = ProbeClient.serve(client_transport).await.unwrap();
    (client, server_handle)
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
    json!({ "ok": false, "error": "__parse__" });
    let v: serde_json::Value = serde_json::from_str(&body).expect("error body is JSON");
    v["error"].as_str().expect("error field").to_string()
}

#[tokio::test]
async fn authorize_then_pay_closed_loop() -> anyhow::Result<()> {
    let (client, server_handle) = setup().await;

    // ---- 1. authorize：owner 签名委托，绑定 agent 身份 ----
    let d = delegation_fixture();
    let owner_key = owner_signing_key_from_bytes([7u8; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
    let auth_result = call_tool(
        &client,
        "authorize",
        authorize_args(&d, &owner_key, &agent_key),
    )
    .await;
    assert!(
        !auth_result.is_error.unwrap_or(false),
        "authorize should succeed"
    );
    let auth_body: serde_json::Value = serde_json::from_str(&result_text(&auth_result))?;
    assert_eq!(
        auth_body["delegation_hash"].as_str().unwrap(),
        hex::encode(delegation_hash(&d)),
        "server-computed delegation_hash must match core canonical hash"
    );
    assert_eq!(auth_body["total_cap"].as_u64().unwrap(), TOTAL_CAP);

    // ---- 2. pay：agent 签名 intent，走预算账本 ----
    let i = intent_fixture(delegation_hash(&d), 42, 1);
    let sig = sign_intent(&i, &agent_key);
    let pay_result = call_tool(&client, "pay", pay_args(&i, &sig)).await;
    assert!(!pay_result.is_error.unwrap_or(false), "pay should succeed");
    let pay_body: serde_json::Value = serde_json::from_str(&result_text(&pay_result))?;
    assert_eq!(pay_body["amount"].as_u64().unwrap(), 42);
    assert_eq!(pay_body["total_spent"].as_u64().unwrap(), 42);
    assert_eq!(pay_body["remaining"].as_u64().unwrap(), TOTAL_CAP - 42);
    assert_eq!(pay_body["payment_id"].as_u64().unwrap(), 0);
    assert_eq!(pay_body["spend_nonce"].as_u64().unwrap(), 1);

    // ---- 3. 第二笔正常支付：累计与剩余滚动 ----
    let i2 = intent_fixture(delegation_hash(&d), 100, 2);
    let sig2 = sign_intent(&i2, &agent_key);
    let pay2 = call_tool(&client, "pay", pay_args(&i2, &sig2)).await;
    let pay2_body: serde_json::Value = serde_json::from_str(&result_text(&pay2))?;
    assert_eq!(pay2_body["total_spent"].as_u64().unwrap(), 142);
    assert_eq!(pay2_body["remaining"].as_u64().unwrap(), TOTAL_CAP - 142);

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn pay_rejects_replay_over_budget_and_forged_sig() -> anyhow::Result<()> {
    let (client, server_handle) = setup().await;

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

    // ---- 防重放：同一 spend_nonce 第二次 → E_NONCE ----
    let i = intent_fixture(dh, 1, 7);
    let sig = sign_intent(&i, &agent_key);
    let first = call_tool(&client, "pay", pay_args(&i, &sig)).await;
    assert!(!first.is_error.unwrap_or(false));
    let replay = call_tool(&client, "pay", pay_args(&i, &sig)).await;
    assert!(
        replay.is_error.unwrap_or(false),
        "replay must be a tool error"
    );
    assert_eq!(error_code(&replay), "E_NONCE");

    // ---- 伪造签名：换 agent 私钥签同一 intent → E_INTENT_SIG ----
    let impostor = AgentSigningKey::from_bytes(&[0xB0; 32]);
    let forged = sign_intent(&i, &impostor);
    let forged_result = call_tool(&client, "pay", pay_args(&i, &forged)).await;
    assert!(forged_result.is_error.unwrap_or(false));
    assert_eq!(error_code(&forged_result), "E_INTENT_SIG");

    // ---- 超总额：独立委托（单笔不挡、窗口 1s 快回滚、总额 10_000），
    //      两笔 6_000 跨窗口 → 第二笔 E_BUDGET_TOTAL ----
    let mut d_ob = delegation_fixture();
    d_ob.max_per_spend = 10_000; // 6_000 不挡单笔
    d_ob.rate.window_secs = 1; // 快速回滚，隔离总额规则
    let auth_ob = call_tool(
        &client,
        "authorize",
        authorize_args(&d_ob, &owner_key, &agent_key),
    )
    .await;
    assert!(
        !auth_ob.is_error.unwrap_or(false),
        "authorize over-budget fixture"
    );
    let dh_ob = delegation_hash(&d_ob);
    let a = intent_fixture(dh_ob, 6_000, 1);
    let b = intent_fixture(dh_ob, 6_000, 2);
    let ok = call_tool(&client, "pay", pay_args(&a, &sign_intent(&a, &agent_key))).await;
    assert!(!ok.is_error.unwrap_or(false));
    // 跨窗口：窗口计数重置，总额仍累计 → 12_000 > 10_000
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let over = call_tool(&client, "pay", pay_args(&b, &sign_intent(&b, &agent_key))).await;
    assert!(
        over.is_error.unwrap_or(false),
        "over-budget must be a tool error"
    );
    assert_eq!(error_code(&over), "E_BUDGET_TOTAL");

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn authorize_rejects_forged_owner_signature() -> anyhow::Result<()> {
    let (client, server_handle) = setup().await;

    let d = delegation_fixture();
    let real_owner = owner_signing_key_from_bytes([7u8; 32]);
    let forged_owner = owner_signing_key_from_bytes([0xE0; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);

    // 用错误 owner 私钥签名 → 验签失败 E_DELEG_SIG
    let args = authorize_args(&d, &forged_owner, &agent_key);
    // 但 owner_pubkey 必须暴露"真实"公钥，让验签方用真钥验假签。
    let mut args = args;
    args.insert("owner_pubkey".into(), json!(owner_sec1_pubkey(&real_owner)));
    let result = call_tool(&client, "authorize", args).await;
    assert!(result.is_error.unwrap_or(false));
    assert_eq!(error_code(&result), "E_DELEG_SIG");

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn unregistered_delegation_pay_rejected() -> anyhow::Result<()> {
    let (client, server_handle) = setup().await;

    // 没走 authorize，直接 pay 一个随机构造 intent → E_DELEG_EXPIRED（未注册）
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
    assert_eq!(error_code(&result), "E_DELEG_EXPIRED");

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}
