//! contract-smoke —— S-11d Anvil 端到端（BatchSettler v2 + 聚合器全链路）。
//!
//! 一条 anvil 会话内跑三条场景：
//!   场景1 快乐路径：注册（链上 DSA + 聚合器）→ 聚合器 submit 满窗 → 密封结算 →
//!         commit（债券 + 撤销根）→ settle（资金足）→ 过挑战窗 → claim：收款人收精确净额
//!         （原生 ETH）。
//!   场景2 撤销路径：链上 revoke → 运营者把 revoke 事件镜像进聚合器 → 新意图 E_REVOKED 拒
//!         （不耗 nonce / 窗口槽）→ 下个密封 epoch 撤销根变化（撤销 1 epoch 内锚定）。
//!   场景3 欺诈路径：commit 诚实承诺根 → settle 漏单 net[]（自洽 netting root）→ 挑战者出示
//!         漏单意图的包含证明（kind=1）→ 挑战成功 → 债券罚没给挑战者 + settlementFunded 退
//!         运营者 + epoch voided → 过窗后 claim 被 EpochVoided 拒。
//!
//! 交叉实现契约贯穿全流程：Solidity `sha256(delegationABI)` == Rust `delegation_hash`；
//! Solidity `IntentHelper.computeIntentHash` == Rust `intent_hash`（欺诈证明链下重算侧）；
//! Solidity `Merkle` 包含验证 == Rust `merkle_root`/`inclusion_proof`（承诺格同根）。
//!
//! 依赖：forge build 产物（contracts/out/）+ anvil（foundry）。独立 workspace。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use alloy::primitives::{keccak256, Address, B256, Bytes, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;
use anyhow::{Context, Result};

use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::lattice::EpochResult;
use meridian_aggregator::merkle::{acceptance_leaf, inclusion_proof, leaf as merkle_leaf};
use meridian_aggregator::proof::FormatVerifier;
use meridian_aggregator::wal::Wal;
use meridian_aggregator::window::WindowEntry;
use meridian_core::dsa::{self, AgentSigningKey, Delegation, RateLimit};
use meridian_core::error::Error;

/// S-14 共享件：anvil 部署 / sol! 绑定 / 信封构造（S-11d 与 M1 demo 复用）。
use contract_smoke::common::*;

/// aggregator epoch 容量（收满即封 → 每场景一窗，天然隔离）。
const EPOCH_CAPACITY: usize = 2;

#[tokio::main]
async fn main() -> Result<()> {
    let mut anvil = spawn_anvil()?;
    let result = run_smoke().await;
    let _ = anvil.kill();
    result
}

async fn run_smoke() -> Result<()> {
    // 1. 提供者：部署方 = anvil #0（= operator）；owner = 固定私钥；挑战者 = anvil #1。
    let deployer: PrivateKeySigner = ANVIL_PKEY0.parse()?;
    let deployer_addr = deployer.address();
    let provider = ProviderBuilder::new()
        .wallet(deployer)
        .connect_http(RPC_URL.parse()?);
    wait_for_chain(&provider).await?;

    let owner_signer = PrivateKeySigner::from_bytes(&B256::from(OWNER_KEY_BYTES))?;
    let owner_provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(RPC_URL.parse()?);
    let challenger: PrivateKeySigner = ANVIL_PKEY1.parse()?;
    let challenger_provider = ProviderBuilder::new()
        .wallet(challenger.clone())
        .connect_http(RPC_URL.parse()?);
    // anvil 只预置 mnemonic 前 10 个账户；owner 是自定义私钥，余额为 0 → revoke 缺 gas。
    provider
        .anvil_set_balance(owner_signer.address(), U256::from(ONE_ETH * 100))
        .await
        .context("anvil_setBalance(owner)")?;

    // 2. 部署合同栈（BatchSettler 构造参数 = operator + asset + challengeBond（S-50 部署期
    //    押金参数）+ P2-3 双锚面（DSA / RevocationRegistry，§6.23.1 定夺 7）；S-11d 走
    //    原生 ETH = address(0)）。
    let dsa_addr = deploy(&provider, "DSA.sol/DSA.json", &[]).await?;
    let reg_addr = deploy(&provider, "RevocationRegistry.sol/RevocationRegistry.json", &abi_addr(dsa_addr)).await?;
    let mut settler_args = abi_addr(deployer_addr);
    settler_args.extend_from_slice(&abi_addr(Address::ZERO));
    settler_args.extend_from_slice(&abi_u256(CHALLENGE_BOND));
    settler_args.extend_from_slice(&abi_addr(dsa_addr));
    settler_args.extend_from_slice(&abi_addr(reg_addr));
    let settler_addr = deploy(&provider, "BatchSettler.sol/BatchSettler.json", &settler_args).await?;
    let dsa_c = IDSA::new(dsa_addr, &provider);
    let reg_c = IRevocationRegistry::new(reg_addr, &owner_provider);
    let settler = IBatchSettler::new(settler_addr, &provider);
    let settler_ch = IBatchSettler::new(settler_addr, &challenger_provider);

    // 3. owner 身份交叉核对 + 聚合器（可控时钟 + WAL）。
    let owner_key = dsa::owner_signing_key_from_bytes(OWNER_KEY_BYTES);
    let owner_did: [u8; 20] = {
        let encoded = owner_key.verifying_key().to_encoded_point(false);
        let hash = keccak256(&encoded.as_bytes()[1..]); // 去掉 0x04 前缀
        hash[12..].try_into().unwrap()
    };
    assert_eq!(
        owner_did,
        owner_signer.address().into_array(),
        "core 私钥派生地址必须与 alloy 钱包一致"
    );

    let clock = Arc::new(AtomicU64::new(1_700_000_000));
    let wal_path = std::env::temp_dir().join(format!("meridian-smoke-{}.wal", std::process::id()));
    let agent_key = AgentSigningKey::from_bytes(&AGENT_KEY_BYTES);
    let agg = aggregator(clock.clone(), &wal_path);

    // 4. 注册两张委托（A = 场景1/2；B = 场景3）：链上 DSA + 聚合器，交叉实现契约断言。
    let d_a = delegation_for([0x01; 20], owner_did, 1);
    let dh_a = dsa::delegation_hash(&d_a);
    let sd_a = dsa::sign_delegation(&d_a, &owner_key);
    dsa_c.registerDelegation(Bytes::from(dsa::delegation_abi(&d_a)), Bytes::from(sd_a.signature.0))
        .send().await?
        .get_receipt().await?;
    let registered_a: bool = dsa_c.isRegistered(B256::from(dh_a)).call().await?;
    assert!(registered_a, "on-chain sha256(delegationABI) 必须等于 meridian-core delegation_hash");
    let onchain_owner_a: Address = dsa_c.ownerOf(B256::from(dh_a)).call().await?;
    assert_eq!(onchain_owner_a, Address::from_slice(&d_a.owner), "ownerOf 必须等于 owner");
    agg.register(sd_a, agent_key.verifying_key());

    let d_b = delegation_for([0x02; 20], owner_did, 2);
    let dh_b = dsa::delegation_hash(&d_b);
    let sd_b = dsa::sign_delegation(&d_b, &owner_key);
    dsa_c.registerDelegation(Bytes::from(dsa::delegation_abi(&d_b)), Bytes::from(sd_b.signature.0))
        .send().await?
        .get_receipt().await?;
    let registered_b: bool = dsa_c.isRegistered(B256::from(dh_b)).call().await?;
    assert!(registered_b, "on-chain sha256(delegationABI) 必须等于 meridian-core delegation_hash");
    let onchain_owner_b: Address = dsa_c.ownerOf(B256::from(dh_b)).call().await?;
    assert_eq!(onchain_owner_b, Address::from_slice(&d_b.owner), "ownerOf 必须等于 owner");
    agg.register(sd_b, agent_key.verifying_key());

    // ============================================================
    // 场景1 —— 快乐路径：epoch 0 = A 两笔 → commit → settle → claim。
    // ============================================================
    let r1 = [0xA1; 20];
    let r2 = [0xA2; 20];
    let mut now = clock.load(Ordering::Relaxed);
    assert!(agg.submit(&make_env(dh_a, [0x01; 20], &agent_key, r1, 30, 1, now)).accepted);
    assert!(agg.submit(&make_env(dh_a, [0x01; 20], &agent_key, r2, 70, 2, now)).accepted);
    let (res0, _entries0) = seal_and_settle(&agg, &clock).pop().expect("epoch 0");
    assert_eq!(res0.epoch_id, 0, "聚合器 epoch 编号从 0 起");

    settler
        .commit(
            U256::from(res0.epoch_id),
            B256::from(res0.commitment_root),
            B256::from(res0.revocation_root),
            B256::from(res0.acceptance_root),
            res0.sealed_at,
        )
        .value(U256::from(BOND))
        .send().await.context("commit send")?
        .get_receipt().await.context("commit receipt")?;
    let net0 = to_net(&res0);
    let sum0: u128 = res0.net.iter().map(|l| l.amount as u128).sum();
    settler
        .settle(U256::from(res0.epoch_id), net0, B256::from(res0.netting_root))
        .value(U256::from(sum0))
        .send().await.context("settle send")?
        .get_receipt().await.context("settle receipt")?;

    // 过挑战窗 → claim：收款人收到精确净额。
    fast_forward(&provider).await?;
    let before1 = provider.get_balance(Address::from_slice(&r1)).await?;
    let before2 = provider.get_balance(Address::from_slice(&r2)).await?;
    settler.claim(U256::from(0), U256::from(0)).send().await?.get_receipt().await?;
    settler.claim(U256::from(0), U256::from(1)).send().await?.get_receipt().await?;
    // net 按收款人字节升序（BTreeMap）：[0xA1]<[0xA2] → idx0=30, idx1=70。
    assert_eq!(provider.get_balance(Address::from_slice(&r1)).await? - before1, U256::from(30), "R1 收 30 wei");
    assert_eq!(provider.get_balance(Address::from_slice(&r2)).await? - before2, U256::from(70), "R2 收 70 wei");
    println!("OK 场景1 快乐路径：commit→settle→claim 收款人收 {sum0} wei");

    // ============================================================
    // 场景2 —— 撤销：链上 revoke → 聚合器 revoke → E_REVOKED → 撤销根变化。
    // ============================================================
    reg_c.revoke(B256::from(dh_a)).send().await?.get_receipt().await?;
    let revoked: bool = reg_c.isRevoked(B256::from(dh_a)).call().await?;
    assert!(revoked, "链上撤销后 isRevoked 为真");
    assert!(agg.revoke(dh_a), "运营者把链上 revoke 事件镜像进聚合器");
    now = clock.load(Ordering::Relaxed);
    let r = agg.submit(&make_env(dh_a, [0x01; 20], &agent_key, [0xAA; 20], 5, 3, now));
    assert!(!r.accepted, "已撤销 A 的新意图必须拒");
    assert_eq!(r.reject_reason, Some(Error::ERevoked), "拒绝原因 = E_REVOKED");
    println!("OK 场景2 撤销：revoke 后新意图 E_REVOKED 拒");

    // ============================================================
    // 场景3 —— 欺诈：epoch 1 = B 两笔 → commit 诚实根 → settle 漏单 → challenge 成功。
    // ============================================================
    let r3 = [0xB1; 20];
    let r4 = [0xB2; 20];
    now = clock.load(Ordering::Relaxed);
    let env3 = make_env(dh_b, [0x02; 20], &agent_key, r3, 40, 1, now);
    let env4 = make_env(dh_b, [0x02; 20], &agent_key, r4, 60, 2, now);
    assert!(agg.submit(&env3).accepted);
    assert!(agg.submit(&env4).accepted);
    let (res1, entries1) = seal_and_settle(&agg, &clock).pop().expect("epoch 1");
    assert_eq!(res1.epoch_id, 1, "epoch 编号续接");
    assert_ne!(res1.revocation_root, res0.revocation_root, "撤销 A 后撤销根变化（1 epoch 内锚定）");

    settler
        .commit(
            U256::from(1),
            B256::from(res1.commitment_root),
            B256::from(res1.revocation_root),
            B256::from(res1.acceptance_root),
            res1.sealed_at,
        )
        .value(U256::from(BOND))
        .send().await.context("commit1 send")?
        .get_receipt().await.context("commit1 receipt")?;

    // settle 漏单：只交 R3（40），漏掉 R4（60）——netting root 用错误 net[] 自洽重算。
    let wrong_net = vec![IBatchSettler::NetInstruction {
        recipient: Address::from_slice(&r3),
        amount: U256::from(40u64),
    }];
    let wrong_root = keccak256(wrong_net.abi_encode());
    settler
        .settle(U256::from(1), wrong_net, B256::from(wrong_root))
        .value(U256::from(40u64))
        .send().await.context("fraud settle send")?
        .get_receipt().await.context("fraud settle receipt")?;

    // 构造 kind=1 漏单证明：R4 意图在承诺根内，但收款人不在（错误）net[]。
    let ih4 = dsa::intent_hash(&env4.intent);
    let leaf_index = entries1
        .iter()
        .position(|e| e.intent_hash == ih4)
        .expect("R4 意图必须在密封 epoch entries 内");
    let leaves: Vec<[u8; 32]> = entries1.iter().map(|e| merkle_leaf(e.seq, e.intent_hash)).collect();
    let (accepted_count, siblings) = inclusion_proof(&leaves, leaf_index).expect("证明索引在界内");
    // P2-3：kind1 证据随行接受面字段（合约对 kind1 不校验，但 IntentProof 须良构）——
    // 平行接受树同叶集同序 ⇒ 同叶索引同深度。
    let acc_leaves: Vec<[u8; 32]> = entries1
        .iter()
        .map(|e| acceptance_leaf(e.seq, e.accepted_at))
        .collect();
    let (_, acc_siblings) = inclusion_proof(&acc_leaves, leaf_index).expect("接受树证明索引在界内");
    let intent_proof = IBatchSettler::IntentProof {
        agent: env4.intent.agent.into(),
        delegationHash: B256::from(env4.intent.delegation_hash),
        recipient: env4.intent.recipient.into(),
        amount: env4.intent.amount,
        category: B256::from(env4.intent.category),
        spendNonce: env4.intent.spend_nonce,
        memo: Bytes::new(),
        expiresAt: env4.intent.expires_at,
        acceptedAt: entries1[leaf_index].accepted_at,
        seq: entries1[leaf_index].seq,
        leafIndex: U256::from(leaf_index),
        acceptedCount: U256::from(accepted_count),
        siblings: siblings.into_iter().map(B256::from).collect(),
        acceptanceSiblings: acc_siblings.into_iter().map(B256::from).collect(),
    };
    let fp = IBatchSettler::FraudProof {
        kind: 1,
        targetNetIndex: U256::ZERO,
        intents: vec![intent_proof],
    };

    let challenger_before = provider.get_balance(challenger.address()).await?;
    // S-50：押金金额单一事实源在链上 —— 部署参数与本地常量交叉核对后按回读值随笔押入。
    let bond_on_chain = settler.challengeBond().call().await?;
    assert_eq!(
        bond_on_chain,
        U256::from(CHALLENGE_BOND),
        "challengeBond() 必须与部署参数一致"
    );
    // S-38：challenge 变 payable，随笔押金 challengeBond（成功路径原额退回）。
    let ch_rec = settler_ch
        .challenge(U256::from(1), fp)
        .value(bond_on_chain)
        .send().await.context("challenge send")?
        .get_receipt().await.context("challenge receipt")?;
    assert!(ch_rec.status(), "challenge 必须成功（不漏单则驳回没收押金）");
    assert!(
        ch_rec.logs().iter().any(|l| {
            l.topics().first() == Some(&keccak256("ChallengeSucceeded(uint256,address,uint8)"))
        }),
        "ChallengeSucceeded 事件必须发出"
    );
    let challenger_after = provider.get_balance(challenger.address()).await?;
    assert!(
        challenger_after - challenger_before > U256::from(BOND / 2),
        "债券罚没给挑战者（押金原额退回，扣 gas 后仍 > 一半债券）"
    );
    // epoch voided → 过窗后 claim 被 EpochVoided 拒。
    fast_forward(&provider).await?;
    let claim_result = settler.claim(U256::from(1), U256::from(0)).call().await;
    assert!(claim_result.is_err(), "voided epoch 的 claim 必须 revert");
    println!("OK 场景3 欺诈：挑战成功（leaf_index={leaf_index}）→ 债券罚没 + settlementFunded 退款 + claim 拒绝");

    let _ = std::fs::remove_file(&wal_path);
    println!("OK: 全部 S-11d Anvil 端到端场景通过");
    Ok(())
}

fn delegation_for(agent: [u8; 20], owner: [u8; 20], nonce: u64) -> Delegation {
    Delegation {
        agent,
        owner,
        nonce,
        max_per_spend: 1_000,
        rate: RateLimit { window_secs: 60, max_per_window: 10_000 },
        total_cap: 100_000,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
        version: dsa::PROTOCOL_VERSION,
    }
}

/// 可控时钟 + WAL 的聚合器（FormatVerifier 诚实后端；epoch_capacity=2 → 满窗即封）。
fn aggregator(clock: Arc<AtomicU64>, wal_path: &std::path::Path) -> Aggregator {
    let c = Arc::clone(&clock);
    let wal = Wal::open(wal_path, 1_000).expect("open wal");
    Aggregator::with_clock(
        IngestConfig {
            ledger_shards: 4,
            epoch_capacity: EPOCH_CAPACITY,
            epoch_secs: 60,
            wal_sync_every: 1_000,
            nonce_capacity_per_delegation: 64,            enforce_revocation_root: false,
        },
        Box::new(FormatVerifier),
        wal,
        Box::new(move || c.load(Ordering::Relaxed)),
    )
}

/// 密封并结算全部已封 epoch（耗尽密封队列；写 WAL EpochSeal/Netting 边界）。
fn seal_and_settle(agg: &Aggregator, clock: &AtomicU64) -> Vec<(EpochResult, Vec<WindowEntry>)> {
    clock.fetch_add(10_000, Ordering::Relaxed);
    let mut out = Vec::new();
    loop {
        let sealed = agg.seal_expired(clock.load(Ordering::Relaxed), 1);
        if sealed.is_empty() {
            break;
        }
        for se in sealed {
            let entries = se.entries.clone();
            if let Some(res) = agg.settle_epoch(&se) {
                out.push((res, entries));
            }
        }
    }
    out
}

