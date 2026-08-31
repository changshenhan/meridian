//! S-15b 监控脚手架端到端：真实聚合器 WAL（真实密码学，无 mock）→ restore → 健康判定。
//!
//! 覆盖 main.rs 的关键链路（restore_from_wal + 独立 WAL 重数 + evaluate），但不拉起
//! HTTP 线程（那部分由 server.rs 路由单测覆盖）。数据口径诚实：`wal_intents` 独立重放
//! 文件数 Intent，不取自聚合器内存。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use ed25519_dalek::SigningKey as AgentSigningKey;
use mist_aggregator::ingest::{Aggregator, IngestConfig};
use mist_aggregator::proof::FormatVerifier;
use mist_aggregator::wal::Wal;
use mist_core::dsa::{
    delegation_hash, owner_signing_key_from_bytes, sign_delegation, sign_intent, Amount,
    Delegation, OwnerSigningKey, RateLimit, SpendIntent, PROTOCOL_VERSION,
};
use mist_core::zk::{SpendProof, SpendPublicInputs};
use mist_monitor::count_wal_intents;
use mist_monitor::health::evaluate;

const AGENT_DID: [u8; 20] = [1u8; 20];
const OWNER_DID: [u8; 20] = [2u8; 20];
const TOTAL_CAP: Amount = 10_000;

static WAL_SEQ: AtomicU32 = AtomicU32::new(0);

fn wal_path(tag: &str) -> PathBuf {
    let seq = WAL_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mist-monitor-e2e-{}-{tag}-{seq}.wal",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p); // Windows 残留文件挡住重建
    p
}

fn owner_key() -> OwnerSigningKey {
    owner_signing_key_from_bytes([7u8; 32])
}

fn delegation(max_per_spend: Amount) -> Delegation {
    Delegation {
        agent: AGENT_DID,
        owner: OWNER_DID,
        nonce: 1,
        max_per_spend,
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

fn intent(dh: [u8; 32], amount: Amount, nonce: u64) -> SpendIntent {
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

/// 造一个带 N 笔已接受意图 + 一笔撤销的 WAL（真实签名 / 占位证明 FormatVerifier 配套）。
fn populated_wal(tag: &str, n: u64) -> PathBuf {
    let path = wal_path(tag);
    let wal = Wal::open(&path, 1_000).unwrap();
    let agg = Aggregator::new(IngestConfig::default(), Box::new(FormatVerifier), wal);
    let owner = owner_key();
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
    let agent_pub = agent_key.verifying_key(); // &VerifyingKey（From<&VerifyingKey> 转 owned）
    let d = delegation(1_000);
    let sd = sign_delegation(&d, &owner);
    let dh = delegation_hash(&d);
    agg.register(sd, agent_pub);

    for i in 0..n {
        let it = intent(dh, 1 + i, i);
        let sig = sign_intent(&it, &agent_key);
        let env = mist_aggregator::receipt::IntentEnvelope {
            intent: it,
            agent_sig: sig,
            proof: SpendProof {
                proof: vec![0x00, 0x01, 0x02],
                public_inputs: SpendPublicInputs {
                    agent_commit: [0u8; 32],
                    delegation_hash: dh,
                    recipient: [3u8; 20],
                    amount: 1 + i,
                    category: [0xCD; 32],
                    spend_nonce: i,
                    expires_at: u64::MAX,
                    revocation_root: [0u8; 32],
                    now: 1_700_000_000,
                },
            },
        };
        let r = agg.submit(&env);
        assert!(r.accepted, "intent {i} should be accepted");
    }

    // 撤销第二张委托（新 dh），制造 revoked_len=1 + 非零撤销根。
    let d2 = Delegation {
        nonce: 2,
        ..d.clone()
    };
    let sd2 = sign_delegation(&d2, &owner);
    agg.register(sd2, agent_pub);
    let dh2 = delegation_hash(&d2);
    assert!(agg.revoke(dh2));

    // 记录还在 8MB 写缓冲里（sync_every=1000）；flush 到盘才能被独立重放看见。
    agg.flush_wal().expect("flush wal");
    drop(agg);
    path
}

#[test]
fn restore_populated_wal_health_green() {
    let path = populated_wal("green", 5);
    let (agg, truncated) = Aggregator::restore_from_wal(
        IngestConfig::production(),
        Box::new(FormatVerifier),
        &path,
        Box::new(|| 1_700_000_100u64),
    )
    .unwrap();
    assert!(!truncated, "WAL 完整，不应截断");
    assert_eq!(agg.accepted_count(), 5);
    assert_eq!(agg.revoked_len(), 1);

    let wal_intents = count_wal_intents(&path).unwrap();
    assert_eq!(wal_intents, 5, "独立重放：WAL 恰有 5 笔 Intent");

    let snap = agg.snapshot();
    let report = evaluate(&snap, wal_intents);
    assert!(report.is_ok(), "状态一致应全绿: {report:?}");
    assert!(report
        .checks
        .iter()
        .any(|c| c.name == "revocation_root_present" && c.ok));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn restore_mismatched_wal_degrades_ledger_consistent() {
    // 造 5 笔的 WAL，但用错误计数 → ledger_consistent 必须降级（防自比）。
    let path = populated_wal("mismatch", 5);
    let (agg, _) = Aggregator::restore_from_wal(
        IngestConfig::production(),
        Box::new(FormatVerifier),
        &path,
        Box::new(|| 1_700_000_100u64),
    )
    .unwrap();
    let snap = agg.snapshot();
    let report = evaluate(&snap, 3); // 谎报 3 笔
    assert_eq!(report.status, "degraded");
    let c = report
        .checks
        .iter()
        .find(|c| c.name == "ledger_consistent")
        .unwrap();
    assert!(!c.ok);
    assert!(c.detail.contains("accepted_count=5"), "{c:?}");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn empty_wal_health_green() {
    let path = wal_path("empty");
    let wal = Wal::open(&path, 1_000).unwrap();
    drop(wal);
    let (agg, _) = Aggregator::restore_from_wal(
        IngestConfig::production(),
        Box::new(FormatVerifier),
        &path,
        Box::new(|| 1_700_000_100u64),
    )
    .unwrap();
    let snap = agg.snapshot();
    assert_eq!(snap.accepted_count, 0);
    let report = evaluate(&snap, count_wal_intents(&path).unwrap());
    assert!(report.is_ok());

    let _ = std::fs::remove_file(&path);
}
