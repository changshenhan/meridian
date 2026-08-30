//! S-52 门控 e2e（TECH_SPEC §6.16）：MCP 面真 ZK 全链——**客户端侧** `NoirProver`
//! 产真电路证明 → MCP `pay` 工具直通 → `BbVerifier` + 撤销根绑定闸聚合器密码学接受；
//! 对照组：同一聚合器上占位 `pay`（无 proof 入参）必拒 `E_PROOF`（bb 全拒占位证明，
//! 正向的接受不是占位漏网——S-47 桥 e2e 同口径）。
//!
//! keyless 保形（D3/§6.16）：`attestation_secret` 只在测试的"客户端侧"出现，服务器
//! （MeridianServer/AppState）全程只验证——真证明经 `revocation_witness` 工具取服务器
//! 侧撤销事实后由客户端产出，作为 `pay` 入参的数据回来。
//!
//! 门控：`MERIDIAN_MCP_NOIR_E2E=1` 才跑（verify.sh 步 9f，CI noir job 同款）。工件依赖
//! formal_zk 产出的 `circuits/target/spend_authorization.json` + `circuits/target/vk`；
//! 缺失则显式打印跳过原因（不静默成功）。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey as AgentSigningKey;
use meridian_aggregator::bb::{BbBackend, BbVerifier};
use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::proof::FormatVerifier;
use meridian_aggregator::wal::Wal;
use meridian_core::dsa::{delegation_hash, intent_hash, Delegation};
use meridian_core::zk::{RevocationWitness, SpendProver};
use meridian_mcp::MeridianServer;
use meridian_sdk::identity::{create_delegation, AgentWallet, DelegationLimits};
use meridian_sdk::prover::NoirProver;
use rmcp::model::{CallToolRequestParams, ClientInfo, JsonObject};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{json, Value};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("mcp-server/ 的上级即仓库根")
        .to_path_buf()
}

/// prove 重操作串行锁：NoirProver 互斥是实例级，`gen-witness/ProverSDK.toml` /
/// `circuits/ProverSDK.toml` 临时 witness 文件是路径级共享（跨 crate 的 prove e2e 亦然
/// ——S-46 同款模式），cargo test 并行时必须串行。
static PROVE_LOCK: Mutex<()> = Mutex::new(());

fn prove_guard() -> std::sync::MutexGuard<'static, ()> {
    PROVE_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn artifact(root: &Path, rel: &str, why: &str) -> Option<Vec<u8>> {
    match std::fs::read(root.join(rel)) {
        Ok(b) => Some(b),
        Err(_) => {
            println!("SKIP: {rel} 不存在（{why}）");
            None
        }
    }
}

/// 探针客户端（mcp_flow 同款）。
#[derive(Debug, Clone, Default)]
struct ProbeClient;

impl ClientHandler for ProbeClient {
    fn get_info(&self) -> ClientInfo {
        ClientInfo::default()
    }
}

type Probe = rmcp::service::RunningService<rmcp::RoleClient, ProbeClient>;

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

fn result_text(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .expect("tool result should have text content")
        .to_string()
}

fn body(result: &rmcp::model::CallToolResult) -> Value {
    serde_json::from_str(&result_text(result)).expect("ok body is JSON")
}

fn error_code(result: &rmcp::model::CallToolResult) -> String {
    let v: Value = serde_json::from_str(&result_text(result)).expect("error body is JSON");
    v["error"].as_str().expect("error field").to_string()
}

#[test]
fn mcp_noir_prover_full_path_via_pay_tool() {
    if std::env::var("MERIDIAN_MCP_NOIR_E2E").as_deref() != Ok("1") {
        println!("SKIP: MERIDIAN_MCP_NOIR_E2E=1 未设（prove 侧重操作，不进默认 cargo test）");
        return;
    }
    let _prove_serial = prove_guard();
    let root = repo_root();
    let _bytecode = match artifact(
        &root,
        "circuits/target/spend_authorization.json",
        "formal_zk 未跑",
    ) {
        Some(b) => b,
        None => return,
    };
    let vk = match artifact(&root, "circuits/target/vk", "formal_zk 未跑") {
        Some(b) => b,
        None => return,
    };
    let backend = match BbBackend::detect() {
        Some(b) => b,
        None => {
            println!("SKIP: bb 工具链不可得（Windows 原生与 WSL 兜底皆无）");
            return;
        }
    };

    // ——— 服务器侧：真 BbVerifier 聚合器 + 撤销根绑定闸（S-48 配对闸生效）———
    let wal_path = std::env::temp_dir().join(format!(
        "meridian-mcp-noir-{}-{}.wal",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&wal_path);
    let wal = Wal::open(&wal_path, 1_000).expect("open wal");
    let agg = Arc::new(Aggregator::new(
        IngestConfig {
            enforce_revocation_root: true,
            ..IngestConfig::default()
        },
        Box::new(BbVerifier::from_parts(
            vk,
            backend,
            root.join("target/mcp-noir-e2e"),
        )),
        wal,
    ));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async move {
        let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
        let server_agg = Arc::clone(&agg);
        let server_handle = tokio::spawn(async move {
            MeridianServer::new(server_agg)
                .serve(server_transport)
                .await?
                .waiting()
                .await?;
            anyhow::Ok(())
        });
        let client = ProbeClient.serve(client_transport).await.unwrap();

        // ---- 1. 客户端侧授权上下文（真实密钥，非手搓 fixture）----
        let wallet = AgentWallet::from_seed([0xA7u8; 32]);
        let owner_key = meridian_core::dsa::owner_signing_key_from_bytes([0x11u8; 32]);
        let agent_key: AgentSigningKey = wallet.agent_key.clone();
        let limits = DelegationLimits {
            max_per_spend: 5_000,
            rate_window_secs: 60,
            rate_max_per_window: 20_000,
            total_cap: 100_000,
            categories: vec![], // 空白名单：电路断言 4 不要求类别（S-09 口径）
            not_before: 1_700_000_000,
            expires_at: 1_900_000_000,
        };
        let sd = create_delegation(&owner_key, [0x0Bu8; 20], 1, &limits).expect("delegation");
        let d: &Delegation = &sd.delegation;
        let dh = delegation_hash(d);

        let auth = call_tool(
            &client,
            "authorize",
            json!({
                "agent": hex::encode(d.agent),
                "owner": hex::encode(d.owner),
                "nonce": d.nonce,
                "max_per_spend": d.max_per_spend,
                "rate_window_secs": d.rate.window_secs,
                "rate_max_per_window": d.rate.max_per_window,
                "total_cap": d.total_cap,
                "categories": [],
                "not_before": d.not_before,
                "expires_at": d.expires_at,
                "version": d.version,
                "owner_signature": hex::encode(sd.signature.0),
                "owner_pubkey": hex::encode(owner_key.verifying_key().to_encoded_point(true).as_bytes()),
                "agent_pubkey": hex::encode(agent_key.verifying_key().as_bytes()),
            })
            .as_object()
            .unwrap()
            .clone(),
        )
        .await;
        assert!(!auth.is_error.unwrap_or(false), "authorize: {}", result_text(&auth));

        // ---- 2. 服务器账本撤销另一张委托：撤销集非空、绑定闸接受集含真实状态根 ----
        let mut other = [0x5Eu8; 32];
        other[31] = 0x02;
        assert!(agg.revoke(other));

        // ---- 3. 客户端经 MCP 工具取撤销事实（真证明所需的唯一服务器侧数据）----
        let wit = call_tool(
            &client,
            "revocation_witness",
            json!({ "delegation_hash": hex::encode(dh) })
                .as_object()
                .unwrap()
                .clone(),
        )
        .await;
        assert!(
            !wit.is_error.unwrap_or(false),
            "witness: {}",
            result_text(&wit)
        );
        let wit_body = body(&wit);
        let wit_root = hex::decode(wit_body["root"].as_str().unwrap()).unwrap();
        let wit_path_raw = hex::decode(wit_body["path"].as_str().unwrap()).unwrap();
        let (path_chunks, path_rest) = wit_path_raw.as_chunks::<32>();
        assert!(path_rest.is_empty(), "path 必须是 32B 整数倍（S-45 wire 口径）");
        let witness = RevocationWitness {
            root: wit_root.clone().try_into().unwrap(),
            path: path_chunks.to_vec(),
        };
        assert_eq!(witness.path.len(), 256, "S-42 深度 256 树");

        // ---- 4. 客户端侧真电路证明（NoirProver 六步链，§6.14）----
        let now = 1_750_000_000u64; // not_before <= now <= expires_at（电路断言 5）
        let (intent, _sig) = wallet.create_intent(
            d.agent,
            dh,
            [0x9Cu8; 20],
            4_200,
            [0xC0; 32],
            1, // spend_nonce > 0（电路断言 7，S-46 口径）
            None,
            d.expires_at,
        );
        // attestation 私钥标量（LE）= 0xDEADBEEF（< EdDSA 子群阶）——只在客户端侧。
        let mut secret = [0u8; 32];
        secret[0] = 0xEF;
        secret[1] = 0xBE;
        secret[2] = 0xAD;
        secret[3] = 0xDE;
        let prover = NoirProver::from_repo_root(&root).expect("noir 工具链可得");
        let proof = prover
            .prove(&meridian_core::zk::SpendProofRequest {
                sd: &sd,
                intent: &intent,
                agent_key: &wallet.agent_key,
                attestation_secret: secret,
                revocation: witness,
                now,
            })
            .unwrap_or_else(|e| panic!("客户端真 prover 失败: {e:?}"));
        assert_eq!(
            proof.public_inputs.revocation_root,
            <[u8; 32]>::try_from(wit_root.as_slice()).unwrap(),
            "证明撤销根 = MCP 工具下发的服务器账本根（三方同源前半）"
        );

        // ---- 5. MCP pay 直通：真证明 → BbVerifier 密码学接受 ----
        let agent_sig = meridian_core::dsa::sign_intent(&intent, &agent_key);
        let pay = call_tool(
            &client,
            "pay",
            json!({
                "agent": hex::encode(intent.agent),
                "delegation_hash": hex::encode(intent.delegation_hash),
                "recipient": hex::encode(intent.recipient),
                "amount": intent.amount,
                "category": hex::encode(intent.category),
                "spend_nonce": intent.spend_nonce,
                "expires_at": intent.expires_at,
                "signature": hex::encode(agent_sig.to_bytes()),
                "proof": {
                    "proof_hex": hex::encode(&proof.proof),
                    "agent_commit": hex::encode(proof.public_inputs.agent_commit),
                    "revocation_root": hex::encode(proof.public_inputs.revocation_root),
                    "now": now,
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        )
        .await;
        assert!(!pay.is_error.unwrap_or(false), "pay: {}", result_text(&pay));
        let pay_body = body(&pay);
        assert_eq!(pay_body["spend_nonce"].as_u64().unwrap(), 1);
        assert_eq!(
            pay_body["intent_hash"].as_str().unwrap(),
            hex::encode(intent_hash(&intent))
        );
        assert_eq!(agg.accepted_count(), 1);
        assert_eq!(agg.total_spent(&dh), Some(4_200));

        // ---- 6. 对照组：占位 pay（无 proof 入参）在同一聚合器必拒 E_PROOF ----
        let (intent2, _sig2) = wallet.create_intent(
            d.agent,
            dh,
            [0x9Cu8; 20],
            100,
            [0xC0; 32],
            2,
            None,
            d.expires_at,
        );
        let sig2 = meridian_core::dsa::sign_intent(&intent2, &agent_key);
        let placeholder = call_tool(
            &client,
            "pay",
            json!({
                "agent": hex::encode(intent2.agent),
                "delegation_hash": hex::encode(intent2.delegation_hash),
                "recipient": hex::encode(intent2.recipient),
                "amount": intent2.amount,
                "category": hex::encode(intent2.category),
                "spend_nonce": intent2.spend_nonce,
                "expires_at": intent2.expires_at,
                "signature": hex::encode(sig2.to_bytes()),
            })
            .as_object()
            .unwrap()
            .clone(),
        )
        .await;
        assert!(placeholder.is_error.unwrap_or(false), "占位证明必被 bb 全拒");
        assert_eq!(error_code(&placeholder), "E_PROOF");
        assert_eq!(agg.accepted_count(), 1, "对照组不记账");

        client.cancel().await.unwrap();
        server_handle.await.expect("server task").expect("server ok");
    });
}

/// FormatVerifier 缺省口径回归：同一 MCP 面、占位 pay（无 proof 入参）仍被接受——
/// S-52 的直通是**增量**能力，缺省装配语义逐字节不变（§6.16 向后兼容承诺）。
#[tokio::test]
async fn placeholder_pay_still_accepted_under_default_format_backend() {
    let wal_path = std::env::temp_dir().join(format!(
        "meridian-mcp-noir-default-{}-{}.wal",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&wal_path);
    let wal = Wal::open(&wal_path, 1_000).unwrap();
    let agg = Arc::new(Aggregator::new(
        IngestConfig::default(),
        Box::new(FormatVerifier),
        wal,
    ));
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    let server_agg = Arc::clone(&agg);
    let server_handle = tokio::spawn(async move {
        MeridianServer::new(server_agg)
            .serve(server_transport)
            .await?
            .waiting()
            .await?;
        anyhow::Ok(())
    });
    let client = ProbeClient.serve(client_transport).await.unwrap();

    let owner_key = meridian_core::dsa::owner_signing_key_from_bytes([0x12u8; 32]);
    let agent_key = AgentSigningKey::from_bytes(&[0x13u8; 32]);
    let d = Delegation {
        agent: [0x0Bu8; 20],
        owner: [0x0Au8; 20],
        nonce: 1,
        max_per_spend: 1_000,
        rate: meridian_core::dsa::RateLimit {
            window_secs: 3_600,
            max_per_window: 10_000,
        },
        total_cap: 10_000,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
        version: meridian_core::dsa::PROTOCOL_VERSION,
    };
    let sd = meridian_core::dsa::sign_delegation(&d, &owner_key);
    let dh = delegation_hash(&d);
    let auth = call_tool(
        &client,
        "authorize",
        json!({
            "agent": hex::encode(d.agent),
            "owner": hex::encode(d.owner),
            "nonce": d.nonce,
            "max_per_spend": d.max_per_spend,
            "rate_window_secs": d.rate.window_secs,
            "rate_max_per_window": d.rate.max_per_window,
            "total_cap": d.total_cap,
            "categories": [],
            "not_before": d.not_before,
            "expires_at": d.expires_at,
            "version": d.version,
            "owner_signature": hex::encode(sd.signature.0),
            "owner_pubkey": hex::encode(owner_key.verifying_key().to_encoded_point(true).as_bytes()),
            "agent_pubkey": hex::encode(agent_key.verifying_key().as_bytes()),
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;
    assert!(!auth.is_error.unwrap_or(false), "authorize 应成功");

    let intent = meridian_core::dsa::SpendIntent {
        agent: d.agent,
        delegation_hash: dh,
        recipient: [0x9Cu8; 20],
        amount: 42,
        category: [0xC0; 32],
        spend_nonce: 1,
        memo: None,
        expires_at: u64::MAX,
    };
    let sig = meridian_core::dsa::sign_intent(&intent, &agent_key);
    let pay = call_tool(
        &client,
        "pay",
        json!({
            "agent": hex::encode(intent.agent),
            "delegation_hash": hex::encode(intent.delegation_hash),
            "recipient": hex::encode(intent.recipient),
            "amount": intent.amount,
            "category": hex::encode(intent.category),
            "spend_nonce": intent.spend_nonce,
            "expires_at": intent.expires_at,
            "signature": hex::encode(sig.to_bytes()),
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;
    assert!(
        !pay.is_error.unwrap_or(false),
        "缺省 format 口径下占位 pay 不变: {}",
        result_text(&pay)
    );
    assert_eq!(agg.accepted_count(), 1);

    client.cancel().await.unwrap();
    server_handle
        .await
        .expect("server task")
        .expect("server ok");
}
