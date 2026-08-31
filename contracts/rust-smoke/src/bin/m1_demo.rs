//! M1 端到端 demo —— S-14 里程碑验收（TECH_SPEC §12 DoD：Anvil 全绿）。
//!
//! 链路：agent 持 DSA → ZK 授权 → 聚合器 10 万笔 → BatchSettler 净额结算。
//!
//!   A. ZK 授权缝（S-09 FormatVerifier）：证明非空 + 公共输入与信封一致 → 接受；
//!      空证明 → EProof；公共输入与意图不符（篡改 pi.amount）→ EOrdering。
//!      真 S-09 UltraPlonk prover 插同一 `SpendVerifier` 缝，信封形态不变。
//!   B. 聚合器：单委托顺序提交 10 万笔确定性意图（epoch_capacity=100_000），
//!      满窗即封 → seal → settle_epoch。断言 accepted_count == 100_000、
//!      total_spent == Σ amounts、seq == 提交序。
//!   C. 承诺/净额根交叉验算：`merkle_root(leaf(seq, ih))` == `commitment_root`；
//!      `lattice::netting_root(net)` == `netting_root`（同根，链下重算侧）。
//!   D. WAL 崩溃恢复：`flush_wal`（结算/停机持久点）→ drop 聚合器 → `restore_from_wal` →
//!      accepted_count 仍 100_000、预算不拒绝重放、seq 续接（下一笔 seq == 100_000）。
//!      未 flush 的尾巴丢失属标准 WAL 语义（撕裂尾截断由 S-10c 单测覆盖）。
//!   E. BatchSettler 净额结算：commit(BOND) → settle(Σnet) → 过挑战窗 →
//!      逐收款人 claim，断言收款人余额增量 == 该 net 行净额（原生 ETH）。
//!
//! 依赖：forge build 产物（contracts/out/）+ anvil（foundry）。独立 workspace。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};

use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::lattice;
use meridian_aggregator::merkle::{leaf as merkle_leaf, merkle_root};
use meridian_aggregator::proof::FormatVerifier;
use meridian_aggregator::wal::Wal;
use meridian_core::dsa::{self, AgentSigningKey, Delegation, RateLimit};
use meridian_core::error::Error;

use contract_smoke::common::*;

/// M1 吞吐规格：单 epoch 10 万笔。
const TOTAL: usize = 100_000;
/// 收款人扇出：每 100 笔落一个收款人（`[0xEE;19]‖(i%100)` → 100 个收款人）。
const N_RECIPIENTS: usize = 100;
const EPOCH_CAPACITY: usize = TOTAL;
/// 聚合器委托：预算上限必须 ≥ Σ amounts（确定性 amounts 求和 < 1e8，见下）。
const TOTAL_CAP: u64 = 100_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    let mut anvil = spawn_anvil()?;
    let result = run_m1().await;
    let _ = anvil.kill();
    result
}

async fn run_m1() -> Result<()> {
    // ---- 链侧：部署方 = anvil #0（= operator）；owner = 固定私钥 ----
    let deployer: PrivateKeySigner = ANVIL_PKEY0.parse()?;
    let deployer_addr = deployer.address();
    let provider = ProviderBuilder::new()
        .wallet(deployer)
        .connect_http(RPC_URL.parse()?);
    wait_for_chain(&provider).await?;

    let owner_signer = PrivateKeySigner::from_bytes(&B256::from(OWNER_KEY_BYTES))?;
    provider
        .anvil_set_balance(owner_signer.address(), U256::from(ONE_ETH * 100))
        .await
        .context("anvil_setBalance(owner)")?;

    let dsa_addr = deploy(&provider, "DSA.sol/DSA.json", &[]).await?;
    // RevocationRegistry 部署保持合同栈完整（本 demo 不触发撤销路径，S-11d 场景2 已覆盖）；
    // P2-3：两者同时是 BatchSettler 的 kind3/kind4 锚面构造参数（§6.23.1 定夺 7）。
    let reg_addr = deploy(&provider, "RevocationRegistry.sol/RevocationRegistry.json", &abi_addr(dsa_addr)).await?;
    let mut settler_args = abi_addr(deployer_addr);
    settler_args.extend_from_slice(&abi_addr(Address::ZERO));
    // S-50：挑战押金为部署期构造参数（本 demo 沿用参考值 0.1 ether）。
    settler_args.extend_from_slice(&abi_u256(CHALLENGE_BOND));
    settler_args.extend_from_slice(&abi_addr(dsa_addr));
    settler_args.extend_from_slice(&abi_addr(reg_addr));
    let settler_addr = deploy(&provider, "BatchSettler.sol/BatchSettler.json", &settler_args).await?;
    let dsa_c = IDSA::new(dsa_addr, &provider);
    let settler = IBatchSettler::new(settler_addr, &provider);

    // ---- 委托：agent = [0x01;20]，owner = core 私钥派生地址（交叉实现契约）----
    let owner_key = dsa::owner_signing_key_from_bytes(OWNER_KEY_BYTES);
    let owner_did: [u8; 20] = {
        let encoded = owner_key.verifying_key().to_encoded_point(false);
        let hash = alloy::primitives::keccak256(&encoded.as_bytes()[1..]);
        hash[12..].try_into().unwrap()
    };
    assert_eq!(owner_did, owner_signer.address().into_array(), "core 私钥派生地址必须与 alloy 钱包一致");

    // 注意：本 demo 全量意图共用同一 `now` → 全部落同一个速率窗口（窗口永不滚动）。
    // 速率上限必须 ≥ 全量 Σ amounts（= 50,050,000），否则第 ~412 笔即触 EBudgetRate。
    let d = Delegation {
        agent: [0x01; 20],
        owner: owner_did,
        nonce: 1,
        max_per_spend: 1_000_000,
        rate: RateLimit { window_secs: 60, max_per_window: TOTAL_CAP },
        total_cap: TOTAL_CAP,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
        version: dsa::PROTOCOL_VERSION,
    };
    let dh = dsa::delegation_hash(&d);
    let sd = dsa::sign_delegation(&d, &owner_key);
    dsa_c.registerDelegation(Bytes::from(dsa::delegation_abi(&d)), Bytes::from(sd.signature.0))
        .send().await?
        .get_receipt().await?;
    let registered: bool = dsa_c.isRegistered(B256::from(dh)).call().await?;
    assert!(registered, "on-chain sha256(delegationABI) 必须等于 meridian-core delegation_hash");
    println!("OK M1: DSA 链上登记（sha256(delegationABI) == delegation_hash）");

    // ---- 聚合器：可控时钟 + WAL，单 epoch 容量 10 万 ----
    let clock = Arc::new(AtomicU64::new(1_700_000_000));
    let wal_path = std::env::temp_dir().join(format!("meridian-m1-{}.wal", std::process::id()));
    let agent_key = AgentSigningKey::from_bytes(&AGENT_KEY_BYTES);
    let agg = aggregator(clock.clone(), &wal_path);
    agg.register(sd, agent_key.verifying_key());

    // ============================================================
    // A. ZK 授权缝负向断言（拒绝不耗 nonce / 窗口槽）
    // ============================================================
    let now = clock.load(Ordering::Relaxed);
    let mut empty_proof = make_env(dh, [0x01; 20], &agent_key, [0xEE; 19].into_iter().chain([0u8]).collect::<Vec<_>>().try_into().unwrap(), 1, 0, now);
    empty_proof.proof.proof.clear();
    let r = agg.submit(&empty_proof);
    assert!(!r.accepted, "空证明必须拒");
    assert_eq!(r.reject_reason, Some(Error::EProof), "空证明 → EProof");

    let mut tampered = make_env(dh, [0x01; 20], &agent_key, [0xEE; 19].into_iter().chain([1u8]).collect::<Vec<_>>().try_into().unwrap(), 2, 1, now);
    tampered.proof.public_inputs.amount = 2 + 1; // 篡改 pi.amount：证明与信封不是同一笔意图
    let r = agg.submit(&tampered);
    assert!(!r.accepted, "公共输入与意图不符必须拒");
    assert_eq!(r.reject_reason, Some(Error::EOrdering), "pi↔intent 不一致 → EOrdering");
    println!("OK M1: ZK 授权缝负向断言（空证明 → EProof；篡改 pi.amount → EOrdering）");

    // ============================================================
    // B. 聚合器 10 万笔：顺序提交 → seq == 提交序 → 满窗即封 → 结算
    // ============================================================
    let t0 = Instant::now();
    let mut recv_sum = vec![0u64; N_RECIPIENTS];
    let mut expected_total: u64 = 0;
    for i in 0..TOTAL {
        let recipient = recipient_for(i);
        let amount = amount_for(i);
        let env = make_env(dh, [0x01; 20], &agent_key, recipient, amount, i as u64, now);
        let r = agg.submit(&env);
        assert!(r.accepted, "第 {i} 笔必须被接受");
        assert_eq!(r.seq, i as u64, "同委托顺序提交 seq 必须等于提交序");
        recv_sum[i % N_RECIPIENTS] += amount;
        expected_total += amount;
    }
    let submit_secs = t0.elapsed().as_secs_f64();
    assert_eq!(agg.accepted_count(), TOTAL as u64, "accepted_count 必须 = 100_000");
    assert_eq!(agg.total_spent(&dh), Some(expected_total), "total_spent 必须 = Σ amounts");
    let rate = TOTAL as f64 / submit_secs;
    println!("OK M1: 聚合器 10 万笔顺序提交 {submit_secs:.2}s（{rate:.0} 笔/s），seq==提交序，total_spent={expected_total}");

    // 满窗即封 → seal_expired 取回 → settle_epoch。
    let sealed = agg.seal_expired(clock.load(Ordering::Relaxed), 60);
    assert_eq!(sealed.len(), 1, "必须恰好一个密封 epoch");
    assert_eq!(sealed[0].entries.len(), TOTAL, "epoch 必须满 10 万笔");
    let (res, entries) = (agg.settle_epoch(&sealed[0]).expect("settle epoch"), sealed[0].entries.clone());
    assert_eq!(res.epoch_id, 0, "epoch 编号从 0 起");

    // ============================================================
    // C. 承诺 / 净额根交叉验算（链下重算侧，同根）
    // ============================================================
    let leaves: Vec<[u8; 32]> = entries.iter().map(|e| merkle_leaf(e.seq, e.intent_hash)).collect();
    assert_eq!(merkle_root(&leaves), res.commitment_root, "merkle 重算必须与内核承诺根同根");
    assert_eq!(lattice::netting_root(&res.net), res.netting_root, "lattice 重算必须与内核净额根同根");
    let sum_net: u128 = res.net.iter().map(|l| l.amount as u128).sum();
    assert_eq!(sum_net, expected_total as u128, "Σnet == Σamounts（净额守恒）");
    // net 按收款人字节升序（BTreeMap）：前 19 字节同 0xEE → 按末字节序。
    for (idx, line) in res.net.iter().enumerate() {
        assert_eq!(line.recipient, recipient_for(idx), "net 行 {idx} 收款人必须与确定性构造一致");
        assert_eq!(line.amount, recv_sum[idx], "net 行 {idx} 净额必须 = 该收款人 Σ amounts");
    }
    println!("OK M1: 承诺根/净额根交叉验算同根；净额守恒 Σnet==Σamounts（{N_RECIPIENTS} 收款人）");

    // ============================================================
    // E. BatchSettler 净额结算（Anvil 全绿）
    // ============================================================
    settler
        .commit(
            U256::from(res.epoch_id),
            B256::from(res.commitment_root),
            B256::from(res.revocation_root),
            B256::from(res.acceptance_root),
            res.sealed_at,
        )
        .value(U256::from(BOND))
        .send().await.context("commit send")?
        .get_receipt().await.context("commit receipt")?;
    settler
        .settle(U256::from(res.epoch_id), to_net(&res), B256::from(res.netting_root))
        .value(U256::from(sum_net))
        .send().await.context("settle send")?
        .get_receipt().await.context("settle receipt")?;
    fast_forward(&provider).await?;
    for (idx, line) in res.net.iter().enumerate() {
        let addr = Address::from_slice(&line.recipient);
        let before = provider.get_balance(addr).await?;
        settler.claim(U256::from(0), U256::from(idx as u64)).send().await?.get_receipt().await?;
        let delta = provider.get_balance(addr).await? - before;
        assert_eq!(delta, U256::from(line.amount), "收款人 {idx} 必须收精确净额");
    }
    println!("OK M1: BatchSettler commit→settle→过挑战窗→claim 全绿，{N_RECIPIENTS} 收款人收精确净额（共 {sum_net} wei）");

    // ============================================================
    // D. WAL 崩溃恢复：flush → drop 聚合器 → restore → 状态精确重建
    // ============================================================
    // flush_wal：结算/停机持久点（TECH_SPEC §8.1）。未 flush 的尾巴崩溃中丢失属标准 WAL
    // 语义（撕裂尾截断由 S-10c 单测覆盖）；此处模拟"全量落盘后的优雅重启"。
    agg.flush_wal().expect("flush wal");
    drop(agg);
    eprintln!("[m1] wal size before restore = {}", std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0));
    let clock2 = Arc::clone(&clock);
    let (agg2, truncated) = Aggregator::restore_from_wal(
        m1_config(&wal_path),
        Box::new(FormatVerifier),
        &wal_path,
        Box::new(move || clock2.load(Ordering::Relaxed)),
    )?;
    assert!(!truncated, "完整 WAL 不得报截断");
    assert_eq!(agg2.accepted_count(), TOTAL as u64, "恢复后 accepted_count 必须仍是 100_000");
    assert_eq!(agg2.total_spent(&dh), Some(expected_total), "恢复后预算必须精确重建（重放不拒）");
    // seq 续接：下一笔 seq == 100_000。
    let env = make_env(dh, [0x01; 20], &agent_key, [0xEE; 19].into_iter().chain([0u8]).collect::<Vec<_>>().try_into().unwrap(), 7, TOTAL as u64, now);
    let r = agg2.submit(&env);
    assert!(r.accepted, "恢复后继续摄取必须接受");
    assert_eq!(r.seq, TOTAL as u64, "seq 必须续接（100_000）");
    println!("OK M1: WAL 崩溃恢复 → accepted_count==100_000、预算不拒重放、seq 续接");

    let _ = std::fs::remove_file(&wal_path);
    println!("OK: M1 端到端 demo 全部通过（DSA → ZK 缝 → 100k 笔 → BatchSettler 净额结算，Anvil 全绿）");
    Ok(())
}

/// 确定性收款人：`[0xEE;19]‖(i%100)` → 100 个收款人，字节序即 net 序。
fn recipient_for(i: usize) -> [u8; 20] {
    let mut out = [0xEEu8; 20];
    out[19] = (i % N_RECIPIENTS) as u8;
    out
}

/// 确定性金额：`((i*7+3)%1000)+1` ∈ [1, 1000]，7 与 1000 互质 → 各值均匀。
fn amount_for(i: usize) -> u64 {
    ((i * 7 + 3) % 1000) as u64 + 1
}

/// M1 聚合器：单 epoch 容量 10 万、WAL fsync 每 1000 笔、非票容量 4096 起。
fn m1_config(wal_path: &std::path::Path) -> IngestConfig {
    let _ = wal_path;
    IngestConfig {
        ledger_shards: 8,
        epoch_capacity: EPOCH_CAPACITY,
        epoch_secs: 60,
        wal_sync_every: 1_000,
        nonce_capacity_per_delegation: 4_096,        enforce_revocation_root: false,
    }
}

/// 可控时钟 + WAL 的聚合器（FormatVerifier 诚实后端；epoch_capacity=100_000）。
fn aggregator(clock: Arc<AtomicU64>, wal_path: &std::path::Path) -> Aggregator {
    let c = Arc::clone(&clock);
    let wal = Wal::open(wal_path, 1_000).expect("open wal");
    Aggregator::with_clock(
        m1_config(wal_path),
        Box::new(FormatVerifier),
        wal,
        Box::new(move || c.load(Ordering::Relaxed)),
    )
}
