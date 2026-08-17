//! S-12 SDK 端到端验收：真实聚合器（进程内 InProcessAggregator + 真实 WAL 落盘 + 真实密码学，
//! 无 mock）+ 断线模拟（`ResponseLossTransport` / `DropFirstTransport`）。
//!
//! 验收线（MASTER_PLAN S-12）：**SDK 可被独立 agent 进程集成；断线重试不产生双花。**

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::proof::FormatVerifier;
use meridian_aggregator::wal::Wal;
use meridian_core::attestation::{agent_commit, verify_binding, AttestationPubKey};
use meridian_core::dsa::owner_signing_key_from_bytes;

use meridian_sdk::{
    AgentWallet, DelegationLimits, InProcessAggregator, PayParams, ResponseLossTransport,
    RetryPolicy, SdkClient, SdkError,
};

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

/// WAL 临时文件唯一命名（测试并行，需各自独立路径）。
static WAL_SEQ: AtomicU32 = AtomicU32::new(0);

fn wal_path(tag: &str) -> PathBuf {
    let seq = WAL_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "meridian-sdk-e2e-{}-{tag}-{seq}.wal",
        std::process::id()
    ))
}

fn aggregator(tag: &str) -> (PathBuf, Arc<Aggregator>) {
    let path = wal_path(tag);
    // 打开前先删：Windows 上残留文件会挡住重建。
    let _ = std::fs::remove_file(&path);
    let wal = Wal::open(&path, 1_000).expect("open wal");
    let agg = Arc::new(Aggregator::new(
        IngestConfig::default(),
        Box::new(FormatVerifier),
        wal,
    ));
    (path, agg)
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

/// 快速重试：0 退避，最多 `max_attempts` 次。
fn fast_retry(client: &mut SdkClient, max_attempts: u32) {
    client.set_retry(RetryPolicy {
        max_attempts,
        base_backoff_ms: 0,
        max_backoff_ms: 0,
    });
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
// 1. 全链路：authorize → pay×2（聚合器侧记账逐笔正确）
// ---------------------------------------------------------------------------

#[test]
fn authorize_then_pay_full_loop() {
    let (path, agg) = aggregator("full-loop");
    let transport = InProcessAggregator::from_inner(Arc::clone(&agg));
    let (wallet, owner) = wallet_and_owner();
    let mut client = SdkClient::new(wallet, Box::new(transport));
    fast_retry(&mut client, 2);

    // authorize：注册一张委托（delegation nonce 自增 → 新 dh）。
    let rec = client.authorize(&owner, [1u8; 20], &limits(1_000)).unwrap();
    let dh = rec.delegation_hash;
    assert_eq!(rec.agent, [1u8; 20]);
    assert_eq!(client.authorized_count(), 1);

    // pay #1（nonce 0）→ seq 0。
    let r1 = client.pay(&pay_params(dh, 42)).unwrap();
    assert_eq!(r1.seq, 0);
    assert_eq!(r1.spend_nonce, 0);

    // pay #2（nonce 1）→ seq 1。
    let r2 = client.pay(&pay_params(dh, 7)).unwrap();
    assert_eq!(r2.seq, 1);
    assert_eq!(r2.spend_nonce, 1);

    // 聚合器记账：两笔恰一次，总额 49。
    assert_eq!(agg.accepted_count(), 2);
    assert_eq!(agg.total_spent(&dh), Some(49));
    assert_eq!(agg.nonce_count(&dh), Some(2));

    drop(client);
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// 2. 【验收】断线重试不产生双花：聚合器已接受、回执丢失 → 重发 → re-ack 原 seq
// ---------------------------------------------------------------------------

#[test]
fn response_loss_retry_no_double_spend() {
    let (path, agg) = aggregator("resp-loss");
    // 断线：第 1 次 submit 先送达聚合器（已接受、记 seq 0），回执丢失。
    let inner = InProcessAggregator::from_inner(Arc::clone(&agg));
    let transport = ResponseLossTransport::new(inner, 1);
    let (wallet, owner) = wallet_and_owner();
    let mut client = SdkClient::new(wallet, Box::new(transport));
    fast_retry(&mut client, 2);

    let rec = client.authorize(&owner, [1u8; 20], &limits(1_000)).unwrap();
    let receipt = client.pay(&pay_params(rec.delegation_hash, 42)).unwrap();

    // 重试成功：返回的是聚合器接受的同一 seq（幂等 re-ack），不是新 seq。
    assert_eq!(receipt.seq, 0);
    assert_eq!(receipt.spend_nonce, 0);

    // 双花防护：恰好接受一笔，总额恰好 42 一次，nonce 恰好消耗 1。
    assert_eq!(agg.accepted_count(), 1);
    assert_eq!(agg.total_spent(&rec.delegation_hash), Some(42));
    assert_eq!(agg.nonce_count(&rec.delegation_hash), Some(1));

    // 幂等 re-ack 之后还能继续正常支付（下一笔新 nonce）。
    let r2 = client.pay(&pay_params(rec.delegation_hash, 5)).unwrap();
    assert_eq!(r2.seq, 1);
    assert_eq!(r2.spend_nonce, 1);
    assert_eq!(agg.accepted_count(), 2);
    assert_eq!(agg.total_spent(&rec.delegation_hash), Some(47));

    drop(client);
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// 3. 【验收】断线重试不透传成功：超限意图被拒绝、回执丢失 → 重发 → 返回原错误码
// ---------------------------------------------------------------------------

#[test]
fn response_loss_retry_on_budget_rejection_reports_error() {
    let (path, agg) = aggregator("resp-loss-budget");
    let inner = InProcessAggregator::from_inner(Arc::clone(&agg));
    // 超单笔限额的意图：第 1 次送达即被聚合器拒绝（nonce 记为 Rejected），回执丢失。
    let transport = ResponseLossTransport::new(inner, 1);
    let (wallet, owner) = wallet_and_owner();
    let mut client = SdkClient::new(wallet, Box::new(transport));
    fast_retry(&mut client, 2);

    // max_per_spend=100，但付 101。
    let rec = client.authorize(&owner, [1u8; 20], &limits(100)).unwrap();
    let err = client
        .pay(&pay_params(rec.delegation_hash, 101))
        .unwrap_err();

    // 透传原错误码；断线重发不把拒绝变成成功。
    assert_eq!(err.code(), "E_BUDGET_PER_SPEND");
    assert!(matches!(err, SdkError::Meridian(_)));

    // 聚合器从未接受任何意图（spent 停留在注册时的 0）；nonce 已被拒绝记录消耗
    // （防同 nonce 换意图重放）。
    assert_eq!(agg.accepted_count(), 0);
    assert_eq!(agg.total_spent(&rec.delegation_hash), Some(0));
    assert_eq!(agg.nonce_count(&rec.delegation_hash), Some(1));

    drop(client);
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// 4. 请求从未送达（DropFirstTransport）→ 重试 → 正常接受
// ---------------------------------------------------------------------------

#[test]
fn drop_first_never_delivered_retries() {
    let (path, agg) = aggregator("drop-first");
    let inner = InProcessAggregator::from_inner(Arc::clone(&agg));
    let transport = meridian_sdk::DropFirstTransport::new(inner, 1);
    let (wallet, owner) = wallet_and_owner();
    let mut client = SdkClient::new(wallet, Box::new(transport));
    fast_retry(&mut client, 2);

    let rec = client.authorize(&owner, [1u8; 20], &limits(1_000)).unwrap();
    let receipt = client.pay(&pay_params(rec.delegation_hash, 42)).unwrap();

    // 首次请求从未送达 → 聚合器只看到重试这一次。
    assert_eq!(receipt.seq, 0);
    assert_eq!(agg.accepted_count(), 1);
    assert_eq!(agg.total_spent(&rec.delegation_hash), Some(42));

    drop(client);
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// 5. 双钥绑定凭据：attest → verify_binding 通过；篡改公钥 → 验签失败
// ---------------------------------------------------------------------------

#[test]
fn attest_produces_verifiable_credential() {
    let (path, agg) = aggregator("attest");
    let transport = InProcessAggregator::from_inner(Arc::clone(&agg));
    let (wallet, _owner) = wallet_and_owner();
    let client = SdkClient::new(wallet.clone(), Box::new(transport));

    let pk = AttestationPubKey {
        x: [0x11; 32],
        y: [0x22; 32],
    };
    let cred = client.attest(&pk).unwrap();

    // 承诺一致 + 绑定签名可验（attest 内部自校验过，这里用独立函数复核）。
    assert_eq!(cred.agent_commit, agent_commit(&pk));
    assert!(verify_binding(&wallet.agent_pub(), &pk, &cred.binding, &cred.agent_commit).is_ok());

    // 篡改公钥 → 验签必须失败。
    let mut forged = pk;
    forged.x[0] ^= 0x01;
    assert!(verify_binding(
        &wallet.agent_pub(),
        &forged,
        &cred.binding,
        &cred.agent_commit
    )
    .is_err());

    drop(client);
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// 6. 错误码透传 + 本地守卫
// ---------------------------------------------------------------------------

#[test]
fn authorize_error_code_passthrough() {
    let (path, agg) = aggregator("auth-err");
    let transport = InProcessAggregator::from_inner(Arc::clone(&agg));
    let (wallet, owner) = wallet_and_owner();
    let client = SdkClient::new(wallet, Box::new(transport));

    // 限额自相矛盾（rate_max < max_per_spend）→ 构造即拒绝，错误码透传。
    let mut l = limits(1_000);
    l.rate_max_per_window = 500;
    let err = client.authorize(&owner, [1u8; 20], &l).unwrap_err();
    assert_eq!(err.code(), "E_BUDGET_PER_SPEND");
    assert!(matches!(err, SdkError::Meridian(_)));

    // 未被本地记录（构造失败的委托不进 authorized）。
    assert_eq!(client.authorized_count(), 0);

    drop(client);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn pay_before_authorize_is_local_error() {
    let (path, agg) = aggregator("pay-first");
    let transport = InProcessAggregator::from_inner(Arc::clone(&agg));
    let (wallet, _owner) = wallet_and_owner();
    let client = SdkClient::new(wallet, Box::new(transport));

    // 未 authorize 就 pay → 本地错误（不进聚合器，不产生任何账）。
    let err = client.pay(&pay_params([0xEE; 32], 42)).unwrap_err();
    assert!(matches!(err, SdkError::Local(_)));

    drop(client);
    let _ = std::fs::remove_file(&path);
}
