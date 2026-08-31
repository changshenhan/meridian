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
use mist_monitor::cluster::{evaluate_cluster, ClusterView};
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
    populated_wal_from(tag, n, 1)
}

/// 金额基址变体（S-72 digest 腿 e2e）：同 dh / 同笔数 / 不同金额 → 三元组全等、
/// digest 失配的最小分歧标本（REG/LEDGER/WINDOW 域内容漂移，计数与承诺不变）。
fn populated_wal_from(tag: &str, n: u64, amount_base: Amount) -> PathBuf {
    let path = wal_path(tag);
    let wal = Wal::open(&path, 1_000).unwrap();
    // 固定时钟：accepted_at 随 WAL Intent 记录重放重建并进 digest 窗口域（§6.26），
    // 墙钟会让两个构建跨秒产生假 digest 分歧——测试要的是内容差异，不是时刻差异。
    let agg = Aggregator::with_clock(
        IngestConfig::default(),
        Box::new(FormatVerifier),
        wal,
        Box::new(|| 1_700_000_000u64),
    );
    let owner = owner_key();
    let agent_key = AgentSigningKey::from_bytes(&[9u8; 32]);
    let agent_pub = agent_key.verifying_key(); // &VerifyingKey（From<&VerifyingKey> 转 owned）
    let d = delegation(1_000);
    let sd = sign_delegation(&d, &owner);
    let dh = delegation_hash(&d);
    agg.register(sd, agent_pub);

    for i in 0..n {
        let it = intent(dh, amount_base + i, i);
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
                    amount: amount_base + i,
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

/// 恢复两份 WAL 并装配集群视图（S-72 digest 腿共用脚手架：digest 在 restore 后取一次，
/// 与 bin/main.rs 的 ReplicaScrape 同口径）。
fn restored_views(pair: [(&str, &PathBuf); 2]) -> (Vec<ClusterView>, Vec<u64>) {
    let mut views = Vec::with_capacity(2);
    let mut wal_intents = Vec::with_capacity(2);
    for (name, p) in pair {
        let (agg, truncated) = Aggregator::restore_from_wal(
            IngestConfig::production(),
            Box::new(FormatVerifier),
            p,
            Box::new(|| 1_700_000_100u64),
        )
        .unwrap();
        assert!(!truncated, "{name}: WAL 完整，不应截断");
        views.push(ClusterView {
            name: name.into(),
            snap: agg.snapshot(),
            state_digest: agg.state_digest(),
        });
        wal_intents.push(count_wal_intents(p).unwrap());
    }
    (views, wal_intents)
}

/// S-72 digest 腿（TECH_SPEC §6.12.1）：同笔数、同撤销承诺、不同金额 → 三元组全等、
/// digest 失配 → degraded 且 detail 只标 digest 腿。这是 S-39 三元组的盲区标本
/// （REG 多注册 / LEDGER 金额 / WINDOW 内容对计数与承诺不可见），digest 是唯一信号。
#[test]
fn cluster_digest_leg_catches_same_count_different_content() {
    let pa = populated_wal("cl-digest-a", 5);
    let pb = populated_wal_from("cl-digest-b", 5, 500);
    let (views, wal_intents) = restored_views([("a", &pa), ("b", &pb)]);
    assert_eq!(views[0].snap.accepted_count, views[1].snap.accepted_count);
    assert_eq!(views[0].snap.revoked_len, views[1].snap.revoked_len);
    assert_eq!(
        views[0].snap.revocation_root, views[1].snap.revocation_root,
        "同 dh 撤销 → 撤销根必须相等（三元组腿不可见此分歧）"
    );
    assert_ne!(
        views[0].state_digest, views[1].state_digest,
        "金额分歧必须进 digest（LEDGER/INTENT/WINDOW 域）"
    );

    let r = evaluate_cluster(&views, &wal_intents);
    assert_eq!(r.status, "degraded");
    let c = r
        .checks
        .iter()
        .find(|c| c.name == "replicas_converged")
        .unwrap();
    assert!(!c.ok);
    assert!(c.detail.contains("lag=0"), "{:?}", c.detail);
    assert!(c.detail.contains("diverged=digest"), "{:?}", c.detail);
    assert!(!c.detail.contains("triple"), "{:?}", c.detail);

    let _ = std::fs::remove_file(&pa);
    let _ = std::fs::remove_file(&pb);
}

/// 同内容两份 WAL（固定时钟 → 确定性恢复）→ 两腿全等 → 收敛，detail 逐字节保持
/// S-39 格式（S-72 定夺 2：收敛输出不破下游告警/面板）。
#[test]
fn cluster_digest_identical_wals_converge_with_s39_detail_format() {
    let pa = populated_wal("cl-same-a", 5);
    let pb = populated_wal("cl-same-b", 5);
    let (views, wal_intents) = restored_views([("a", &pa), ("b", &pb)]);
    assert_eq!(
        views[0].state_digest, views[1].state_digest,
        "同内容 WAL 的 digest 必须逐字节一致（跨 WAL 构建、跨 restore 实例）"
    );

    let r = evaluate_cluster(&views, &wal_intents);
    assert_eq!(r.status, "ok");
    let c = r
        .checks
        .iter()
        .find(|c| c.name == "replicas_converged")
        .unwrap();
    assert!(c.ok);
    assert_eq!(c.detail, "accepted=[a=5,b=5] lag=0");

    let _ = std::fs::remove_file(&pa);
    let _ = std::fs::remove_file(&pb);
}
