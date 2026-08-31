//! P2-1 验证者挑战演练（TECH_SPEC §6.18）——独立验证者实体全链三幕。
//!
//! 决策 C（写者与验证者分离）的实施演练：验证者**不复用运营者内存态**，信源 =
//! 已接受意图镜像流（信封 + Receipt.seq，§6.18.1），链上读取面 = `epochs()` getter +
//! settle 交易 calldata 解码（§6.18.2），复算走生产 netting 路径（`fraud::recompute`
//! → `lattice::build_epoch` 同一确定性代码），检出 → 出证闸 → challenge 全链走通。
//!
//! 三幕（一条 anvil 会话，三个 settler epoch，每幕独立聚合器/WAL）：
//!   幕 1 诚实对照：settle 诚实 net[] → 检出零信号 → 不出证不挑战 → 过窗 claim 收精确净额
//!        （「检出为空 = 静默」是验证者面必须有的负向能力：误报上链 = 押金销毁）。
//!   幕 2 kind1 漏单：人为错账 = settle 抽掉一行 → 验证者检出 → kind1 出证 → challenge →
//!        ChallengeSucceeded + epoch voided + 债券罚没给验证者 + claim 拒 EpochVoided。
//!        同幕附「缺漏镜像」负向：镜像缺该收款人 → 根不等 → 出证闸闭合 → 不挑战（保押金）。
//!   幕 3 kind2 低付：人为错账 = settle 少付一行 → kind2 出证 → 同款罚没断言。
//!
//! 错账注入点 = settle 调用参数（真实欺诈形态 commit≠settle；聚合器/合约零改动，§6.18）。
//! 演练形态为进程内双实体（验证者独立 signer = anvil #1，独立复算态）；生产形态 = 独立
//! 进程/独立运营者（§6.18.5 诚实边界）。settle 交易定位：演练规模下按回执哈希直取
//!（生产 = Settled 事件索引——同面公开数据）。
//!
//! 依赖：forge build 产物（contracts/out/）+ anvil（foundry）。独立 workspace。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use alloy::consensus::Transaction as _;
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::Provider;
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolCall, SolValue};
use anyhow::{Context, Result};

use meridian_aggregator::fraud::{self, ChainEpoch, FraudCandidate, IntentEvidence, MirrorIntent};
use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::lattice::{EpochResult, NetLine};
use meridian_aggregator::proof::FormatVerifier;
use meridian_aggregator::wal::Wal;
use meridian_core::dsa::{self, AgentSigningKey, Delegation, OwnerSigningKey, RateLimit};

use contract_smoke::common::*;

/// 嵌套类型具象化（泛型 fn 作用域内 `IBatchSettler::X` 路径不可解析，先具象化再用）。
type NetInstruction = IBatchSettler::NetInstruction;
type EpochView = IBatchSettler::EpochView;
type FraudProof = IBatchSettler::FraudProof;
type IntentProof = IBatchSettler::IntentProof;
type SettleCall = IBatchSettler::settleCall;

/// 每幕规模：3 收款人 × 3 笔 = 9 笔（epoch_capacity = 笔数满窗即封）。
const N_RECIPIENTS: usize = 3;
const PER_RECIPIENT: usize = 3;
const TOTAL: usize = N_RECIPIENTS * PER_RECIPIENT;
/// 聚合器委托：预算/速率上限 ≥ Σ amounts（每笔 100+i，每幕 Σ = 936）。
const TOTAL_CAP: u64 = 100_000;

#[tokio::main]
async fn main() -> Result<()> {
    let mut anvil = spawn_anvil()?;
    let result = run_drill().await;
    let _ = anvil.kill();
    result
}

async fn run_drill() -> Result<()> {
    // ---- 链侧：部署方 = anvil #0（= operator）；验证者 = anvil #1（独立 signer）----
    let operator: PrivateKeySigner = ANVIL_PKEY0.parse()?;
    let operator_addr = operator.address();
    let provider = ProviderBuilder::new()
        .wallet(operator)
        .connect_http(RPC_URL.parse()?);
    wait_for_chain(&provider).await?;

    let mut settler_args = abi_addr(operator_addr);
    settler_args.extend_from_slice(&abi_addr(Address::ZERO));
    settler_args.extend_from_slice(&abi_u256(CHALLENGE_BOND));
    let settler_addr = deploy(
        &provider,
        "BatchSettler.sol/BatchSettler.json",
        &settler_args,
    )
    .await?;
    let settler = IBatchSettler::new(settler_addr, &provider);
    let verifier_signer = verifier_wallet();
    let verifier_provider = ProviderBuilder::new()
        .wallet(verifier_signer.clone())
        .connect_http(RPC_URL.parse()?);
    let settler_verifier = IBatchSettler::new(settler_addr, &verifier_provider);
    // S-50：押金金额单一事实源在链上（部署参数与本地常量交叉核对）。
    let bond_on_chain = settler.challengeBond().call().await?;
    assert_eq!(
        bond_on_chain,
        U256::from(CHALLENGE_BOND),
        "challengeBond() 必须与部署参数一致"
    );

    let agent_key = AgentSigningKey::from_bytes(&AGENT_KEY_BYTES);
    let owner_key = dsa::owner_signing_key_from_bytes(OWNER_KEY_BYTES);
    let owner_did: [u8; 20] = {
        let encoded = owner_key.verifying_key().to_encoded_point(false);
        keccak256(&encoded.as_bytes()[1..])[12..]
            .try_into()
            .unwrap()
    };

    // ============================================================
    // 幕 1 —— 诚实对照：零检出 → 不挑战 → claim 全绿
    // ============================================================
    let (res0, mirror0) = ingest_act(&agent_key, &owner_key, owner_did, 1).await?;
    commit_act(&settler, 0, &res0).await?;
    let settle0 = settle_act(&settler, 0, res0.net.clone(), res0.netting_root).await?;

    // 验证者：镜像复算 + 链上读取 + 检出（§6.18.3）。
    let (view0, chain_net0) = read_chain_epoch(&provider, settler_addr, 0, settle0).await?;
    assert!(
        view0.settled && !view0.voided,
        "幕 1 链上面必须已结算未 voided"
    );
    let rec0 = fraud::recompute(&mirror0, [0u8; 32]).expect("镜像自洽");
    let chain0 = ChainEpoch {
        commitment_root: view0.commitmentRoot.into(),
        net: chain_net0,
    };
    let det0 = fraud::detect(&rec0, &chain0);
    assert!(det0.is_clean(), "诚实结算必须零检出信号：{det0:?}");
    assert!(
        fraud::fraud_candidates(&rec0, &chain0).is_empty(),
        "诚实面不得出证（误报 = 押金销毁）"
    );
    println!("OK 幕 1 诚实对照：镜像复算零检出 → 不出证不挑战（静默是验证者面的负向能力）");

    // 过窗 claim：收款人收精确净额（对照面 = 诚实路径不受验证者存在影响）。
    fast_forward(&provider).await?;
    for (idx, line) in res0.net.iter().enumerate() {
        let addr = Address::from_slice(&line.recipient);
        let before = provider.get_balance(addr).await?;
        settler
            .claim(U256::from(0), U256::from(idx as u64))
            .send()
            .await?
            .get_receipt()
            .await?;
        assert_eq!(
            provider.get_balance(addr).await? - before,
            U256::from(line.amount),
            "幕 1 收款人 {idx} 必须收精确净额"
        );
    }
    println!(
        "OK 幕 1 过窗 claim 全绿（{} 收款人收精确净额）",
        res0.net.len()
    );

    // ============================================================
    // 幕 2 —— kind1 漏单：settle 抽一行 → 检出 → 出证 → 罚没
    // ============================================================
    let (res2, mirror2) = ingest_act(&agent_key, &owner_key, owner_did, 2).await?;
    commit_act(&settler, 1, &res2).await?;
    // 人为错账：settle 抽掉收款人 2 的整行（漏单形态；nettingRoot 用错误 net[] 自洽重算）。
    let drop_line = res2
        .net
        .iter()
        .find(|l| l.recipient[19] == 2)
        .expect("收款人 2 行")
        .clone();
    let wrong_net: Vec<NetLine> = res2
        .net
        .iter()
        .filter(|l| l.recipient != drop_line.recipient)
        .cloned()
        .collect();
    let wrong_root2 = netting_root_of(&wrong_net);
    let settle2 = settle_act(&settler, 1, wrong_net, wrong_root2).await?;

    let (view2, chain_net2) = read_chain_epoch(&provider, settler_addr, 1, settle2).await?;
    assert!(view2.settled && !view2.voided);
    let rec2 = fraud::recompute(&mirror2, [0u8; 32]).expect("镜像自洽");
    let chain2 = ChainEpoch {
        commitment_root: view2.commitmentRoot.into(),
        net: chain_net2,
    };
    let det2 = fraud::detect(&rec2, &chain2);
    assert!(
        det2.commitment_root_match,
        "承诺根仍同（错账在净额面，不在承诺面）"
    );
    assert_eq!(det2.missing.len(), 1, "恰一个漏单收款人");
    assert_eq!(det2.missing[0].recipient, drop_line.recipient);
    assert_eq!(
        det2.missing[0].intent_seqs.len(),
        PER_RECIPIENT,
        "该收款人全部镜像意图"
    );
    let cands2 = fraud::fraud_candidates(&rec2, &chain2);
    assert_eq!(cands2.len(), 1, "kind1 恰一个候选");
    assert_eq!(cands2[0].kind, fraud::KIND_MISSING);
    assert_eq!(
        cands2[0].intents.len(),
        1,
        "kind1 恰 1 条意图（合约 BadFraudKind 上限）"
    );
    assert_eq!(cands2[0].intents[0].intent.recipient, drop_line.recipient);

    // 同幕负向：验证者镜像缺漏该收款人 → 重算根不等 → 出证闸闭合 → 不挑战（保押金）。
    let short: Vec<MirrorIntent> = mirror2
        .iter()
        .filter(|m| m.intent.recipient != drop_line.recipient)
        .cloned()
        .collect();
    let rec_short = fraud::recompute(&short, [0u8; 32]).unwrap();
    assert!(
        !fraud::detect(&rec_short, &chain2).commitment_root_match,
        "缺漏镜像根必然不等"
    );
    assert!(
        fraud::fraud_candidates(&rec_short, &chain2).is_empty(),
        "根不符绝不出证（兄弟路径必然错误 → BadInclusionProof → 押金销毁）"
    );
    println!("OK 幕 2 检出 kind1 漏单 + 缺漏镜像出证闸闭合（不赌押金）");

    challenge_and_assert(&provider, &settler, &settler_verifier, 1, &cands2[0]).await?;
    println!("OK 幕 2 challenge(kind=1) 成功 → voided + 债券罚没给验证者 + claim 拒");

    // ============================================================
    // 幕 3 —— kind2 低付：settle 少付一行 → kind2 出证 → 罚没
    // ============================================================
    let (res3, mirror3) = ingest_act(&agent_key, &owner_key, owner_did, 3).await?;
    commit_act(&settler, 2, &res3).await?;
    // 人为错账：收款人 1 的行少付 1（低付形态——收款人在 net[] 里但金额 < 已承诺 Σ）。
    let honest_sum3 = res3
        .net
        .iter()
        .find(|l| l.recipient[19] == 1)
        .expect("收款人 1 行")
        .amount;
    let mut low_net: Vec<NetLine> = res3.net.clone();
    let idx3 = low_net.iter().position(|l| l.recipient[19] == 1).unwrap();
    low_net[idx3].amount -= 1;
    let settle3 = settle_act(&settler, 2, low_net.clone(), netting_root_of(&low_net)).await?;

    let (view3, chain_net3) = read_chain_epoch(&provider, settler_addr, 2, settle3).await?;
    let rec3 = fraud::recompute(&mirror3, [0u8; 32]).expect("镜像自洽");
    let chain3 = ChainEpoch {
        commitment_root: view3.commitmentRoot.into(),
        net: chain_net3,
    };
    let det3 = fraud::detect(&rec3, &chain3);
    assert_eq!(det3.underpaid.len(), 1, "恰一个低付行");
    assert_eq!(det3.underpaid[0].honest_sum, honest_sum3 as u128);
    assert_eq!(det3.underpaid[0].chain_amount, honest_sum3 - 1);
    let cands3 = fraud::fraud_candidates(&rec3, &chain3);
    assert_eq!(cands3.len(), 1, "kind2 恰一个候选");
    assert_eq!(cands3[0].kind, fraud::KIND_UNDERPAID);
    assert_eq!(
        cands3[0].target_net_index,
        det3.underpaid[0].target_net_index
    );
    assert!(
        cands3[0].sum_amount() > (honest_sum3 - 1) as u128,
        "kind2 子集 Σ 必须 > 链上目标行额"
    );
    assert!(
        cands3[0]
            .intents
            .iter()
            .all(|e| e.intent.recipient[19] == 1),
        "kind2 子集必须同收款人（合约跨收款人守卫）"
    );
    println!(
        "OK 幕 3 检出 kind2 低付（Σ={} > 行额={}）",
        cands3[0].sum_amount(),
        honest_sum3 - 1
    );

    challenge_and_assert(&provider, &settler, &settler_verifier, 2, &cands3[0]).await?;
    println!("OK 幕 3 challenge(kind=2) 成功 → voided + 债券罚没给验证者 + claim 拒");

    // ============================================================
    // 幕 4 —— P2-5 声誉面核对（TECH_SPEC §6.22.4）：monitor 只读派生 vs 本会话
    // 真实链上事件（3 commit / 3 settle / kind1+kind2 两次罚没）。事件解码路径的
    // 链上真实性由幕 2/3 的真实罚没交易保证。
    // ============================================================
    let rpc = meridian_monitor::rpc::JsonRpc::new(RPC_URL).map_err(|e| anyhow::anyhow!("{e}"))?;
    let settler_hex = format!("0x{}", hex::encode(settler_addr));
    let rep = meridian_monitor::reputation::fetch_reputation(&rpc, &settler_hex)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert_eq!(rep.epochs_committed, 3, "幕 1-3 各 commit 一次");
    assert_eq!(rep.epochs_settled, 3, "幕 1-3 各 settle 一次（含被 voided 的）");
    assert_eq!(rep.slash_total, 2, "幕 2 kind1 + 幕 3 kind2 两次罚没");
    assert_eq!(rep.kind_counts.get(&1), Some(&1));
    assert_eq!(rep.kind_counts.get(&2), Some(&1));
    // bond_committed_wei 的口径是 Commit.bondedAmount（commit 债券 BOND），不是
    // challengeBond()（挑战押金，bond_on_chain）——两者金额不同，首版在此翻过车。
    assert_eq!(
        rep.bond_committed_wei,
        3 * BOND,
        "Σ Commit.bondedAmount = 3 × commit 债券 BOND"
    );
    // 合同余额 ≤ 3×BOND：构成含未领取结算资金/退款留存（§6.22.5），不等于净债券；
    // 本演练实态 = 幕 1 未罚没的 1×BOND（幕 2/3 债券已罚没给验证者出金、结算资金已退）。
    assert!(rep.contract_balance_wei <= 3 * BOND);
    let metrics = meridian_monitor::reputation::render_reputation(&rep, &settler_hex)
        + &meridian_monitor::reputation::render_read_ok(&settler_hex, true);
    assert!(metrics.contains("meridian_operator_slash_total{settler="));
    assert!(metrics.contains("meridian_operator_chain_read_ok{settler="));
    println!(
        "OK 幕 4 声誉面核对：monitor 派生（commit=3 settle=3 slash=2 kind={{1:1,2:1}} \
         bond_committed={} wei）与本会话链上事件一致",
        rep.bond_committed_wei
    );

    println!("OK: P2-1 验证者挑战演练三幕全过（诚实静默 / kind1 漏单 / kind2 低付，Anvil 全绿）+ P2-5 声誉面核对（幕 4）");
    Ok(())
}

/// 验证者 signer（anvil #1，独立于运营者 anvil #0）。
fn verifier_wallet() -> PrivateKeySigner {
    ANVIL_PKEY1.parse().expect("anvil #1 私钥")
}

/// 一幕摄取：独立聚合器（容量 = 笔数满窗即封）+ 独立 WAL + 镜像流记录。运营者与验证者
/// 共享提交流 = §6.18.1 的「镜像流」信源（生产 = 网关接受流多播副本）。上链 seam 为
/// NoopPublisher——上链由演练手动控制（错账注入点在 settle 调用参数）。
async fn ingest_act(
    agent_key: &AgentSigningKey,
    owner_key: &OwnerSigningKey,
    owner_did: [u8; 20],
    act: u64,
) -> Result<(EpochResult, Vec<MirrorIntent>)> {
    // 委托：每幕独立聚合器 → 独立预算/nonce 面（challenge 面 permissionless，链上不注册）。
    let d = Delegation {
        agent: [0x01; 20],
        owner: owner_did,
        nonce: act,
        max_per_spend: 1_000,
        rate: RateLimit {
            window_secs: 60,
            max_per_window: TOTAL_CAP,
        },
        total_cap: TOTAL_CAP,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
        version: dsa::PROTOCOL_VERSION,
    };
    let dh = dsa::delegation_hash(&d);
    let sd = dsa::sign_delegation(&d, owner_key);

    let clock = Arc::new(AtomicU64::new(1_700_000_000 + act * 1_000));
    let wal_path = std::env::temp_dir().join(format!(
        "meridian-verifier-drill-{}-act{act}.wal",
        std::process::id()
    ));
    let c = Arc::clone(&clock);
    let wal = Wal::open(&wal_path, 1_000).expect("open wal");
    let agg = Aggregator::with_clock(
        IngestConfig {
            ledger_shards: 4,
            epoch_capacity: TOTAL,
            epoch_secs: 60,
            wal_sync_every: 1_000,
            nonce_capacity_per_delegation: 64,
            enforce_revocation_root: false,
        },
        Box::new(FormatVerifier),
        wal,
        Box::new(move || c.load(Ordering::Relaxed)),
    );
    agg.register(sd.clone(), agent_key.verifying_key());

    // 提交 + 镜像记录（完整信封 + Receipt.seq）。spend_nonce 从 1 起（S-46 电路断言 7）。
    let now = clock.load(Ordering::Relaxed);
    let mut mirror = Vec::with_capacity(TOTAL);
    let mut i = 0usize;
    for r in 0..N_RECIPIENTS {
        for _ in 0..PER_RECIPIENT {
            let mut recipient = [0xEEu8; 20];
            recipient[19] = r as u8;
            let env = make_env(
                dh,
                [0x01; 20],
                agent_key,
                recipient,
                100 + i as u64,
                i as u64 + 1,
                now,
            );
            let receipt = agg.submit(&env);
            assert!(receipt.accepted, "第 {i} 笔必须被接受");
            mirror.push(MirrorIntent {
                intent: env.intent,
                seq: receipt.seq,
            });
            i += 1;
        }
    }
    assert_eq!(mirror.len(), TOTAL, "镜像流必须与提交数一致");

    // 满窗即封 → 结算（运营者侧诚实产物）。
    clock.fetch_add(10_000, Ordering::Relaxed);
    let sealed = agg.seal_expired(clock.load(Ordering::Relaxed), 1);
    assert_eq!(sealed.len(), 1, "必须恰好一个密封 epoch");
    assert_eq!(sealed[0].entries.len(), TOTAL);
    let res = agg.settle_epoch(&sealed[0]).expect("settle epoch");
    let _ = std::fs::remove_file(&wal_path);
    Ok((res, mirror))
}

/// 运营者 commit（诚实承诺根 + 撤销根 + 债券）。返回 settle 交易哈希由调用方传验证者。
async fn commit_act<P: Provider>(
    settler: &IBatchSettler::IBatchSettlerInstance<&P>,
    epoch_id: u64,
    res: &EpochResult,
) -> Result<()> {
    settler
        .commit(
            U256::from(epoch_id),
            B256::from(res.commitment_root),
            B256::from(res.revocation_root),
        )
        .value(U256::from(BOND))
        .send()
        .await
        .context("commit send")?
        .get_receipt()
        .await
        .context("commit receipt")?;
    Ok(())
}

/// 运营者 settle（净额由调用方注入：诚实或错账）。返回交易哈希（演练面 = 验证者经
/// 回执哈希取交易；生产 = Settled 事件 → 交易哈希，同面公开数据）。
async fn settle_act<P: Provider>(
    settler: &IBatchSettler::IBatchSettlerInstance<&P>,
    epoch_id: u64,
    net: Vec<NetLine>,
    netting_root: [u8; 32],
) -> Result<B256> {
    let on_chain_net = to_on_chain_net(&net);
    let value: u128 = net.iter().map(|l| l.amount as u128).sum();
    let receipt = settler
        .settle(U256::from(epoch_id), on_chain_net, B256::from(netting_root))
        .value(U256::from(value))
        .send()
        .await
        .context("settle send")?
        .get_receipt()
        .await
        .context("settle receipt")?;
    assert!(receipt.status(), "settle 必须成功");
    Ok(receipt.transaction_hash)
}

/// NetLine → BatchSettler.NetInstruction[]。
fn to_on_chain_net(net: &[NetLine]) -> Vec<NetInstruction> {
    net.iter()
        .map(|l| NetInstruction {
            recipient: Address::from_slice(&l.recipient),
            amount: U256::from(l.amount),
        })
        .collect()
}

/// net[] → nettingRoot（`keccak256(abi.encode(net))`——错账 net 的自洽根，与
/// `lattice::netting_root` 同口径；alloy `SolValue::abi_encode` 走动态数组编码）。
fn netting_root_of(net: &[NetLine]) -> [u8; 32] {
    keccak256(to_on_chain_net(net).abi_encode()).into()
}

/// 验证者链上读取面（§6.18.2）：`epochs()` getter + settle 交易 calldata 解码出 net[]，
/// 并自检 `keccak256(abi.encode(net)) == 链上 nettingRoot`（读面错误 fail-closed）。
async fn read_chain_epoch<P: Provider>(
    provider: &P,
    settler_addr: Address,
    epoch_id: u64,
    settle_hash: B256,
) -> Result<(EpochView, Vec<NetLine>)> {
    let settler = IBatchSettler::new(settler_addr, provider);
    let view = settler.epochs(U256::from(epoch_id)).call().await?;
    let tx = provider
        .get_transaction_by_hash(settle_hash)
        .await?
        .context("settle 交易不存在")?;
    let call = SettleCall::abi_decode(tx.input().as_ref()).context("settle calldata 解码")?;
    assert_eq!(
        call.epochId,
        U256::from(epoch_id),
        "settle 交易必须属于本 epoch"
    );
    assert_eq!(
        keccak256(call.net.abi_encode()),
        B256::from(view.nettingRoot),
        "calldata 解码面自检失败（keccak(abi.encode(net)) != 链上 nettingRoot）"
    );
    let net = call
        .net
        .iter()
        .map(|l| -> Result<NetLine> {
            let mut recipient = [0u8; 20];
            recipient.copy_from_slice(l.recipient.as_ref());
            Ok(NetLine {
                recipient,
                amount: u64::try_from(l.amount).context("net 行额超出 u64（协议面不可能）")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((view, net))
}

/// 出证 + 上链挑战 + 罚没断言（幕 2/3 共用）：押金随笔、事件、voided、余额、claim 拒。
async fn challenge_and_assert<P: Provider>(
    provider: &P,
    settler: &IBatchSettler::IBatchSettlerInstance<&P>,
    settler_verifier: &IBatchSettler::IBatchSettlerInstance<&P>,
    epoch_id: u64,
    cand: &FraudCandidate,
) -> Result<()> {
    let fp = FraudProof {
        kind: cand.kind,
        targetNetIndex: U256::from(cand.target_net_index),
        intents: cand.intents.iter().map(to_intent_proof).collect(),
    };
    let view_before = settler.epochs(U256::from(epoch_id)).call().await?;
    let verifier: PrivateKeySigner = verifier_wallet();
    let verifier_addr = verifier.address();
    let verifier_before = provider.get_balance(verifier_addr).await?;

    // 挑战在窗口内（幕 2/3 的 settle 都在 fast_forward 之后 → settledAt 相对最新时刻）。
    let rec = settler_verifier
        .challenge(U256::from(epoch_id), fp)
        .value(U256::from(CHALLENGE_BOND))
        .send()
        .await
        .context("challenge send")?
        .get_receipt()
        .await
        .context("challenge receipt")?;
    assert!(rec.status(), "challenge 必须成功（驳回 = 押金销毁）");
    assert!(
        rec.logs().iter().any(|l| {
            l.topics().first() == Some(&keccak256("ChallengeSucceeded(uint256,address,uint8)"))
        }),
        "ChallengeSucceeded 事件必须发出"
    );

    let view_after = settler.epochs(U256::from(epoch_id)).call().await?;
    assert!(
        view_after.challenged && view_after.voided,
        "挑战成功后 epoch 必须 challenged + voided"
    );
    assert_eq!(view_after.bondedAmount, U256::ZERO, "债券必须全额罚没");
    assert_eq!(
        view_after.settlementFunded,
        U256::ZERO,
        "结算资金必须退运营者"
    );
    // 罚没净额 = 运营者债券（gas 逐 wei 扣除核对）。押金（msg.value）随笔原额退回
    // ——付出与赔付相抵净零，挑战者净增只有债券（S-50 罚没口径的链上实测复述）。
    let gas = U256::from(rec.gas_used as u128 * rec.effective_gas_price);
    let verifier_after = provider.get_balance(verifier_addr).await?;
    assert_eq!(
        verifier_after + gas - verifier_before,
        view_before.bondedAmount,
        "验证者净增必须 = 运营者债券（押金原额退回净零，逐 wei）"
    );
    // 过窗后 claim 被 EpochVoided 拒（资金面冻结：错账行永不支付）。
    fast_forward(provider).await?;
    let claim = settler
        .claim(
            U256::from(epoch_id),
            U256::from(cand.target_net_index as u64),
        )
        .call()
        .await;
    assert!(claim.is_err(), "voided epoch 的 claim 必须 revert");
    Ok(())
}

/// IntentEvidence → BatchSettler.IntentProof（哈希 preimage 字段逐一映射；
/// memo None ↔ 空 bytes，与 `IntentHelper.computeIntentHash` 的 0x00 旗标口径一致）。
fn to_intent_proof(e: &IntentEvidence) -> IntentProof {
    IntentProof {
        agent: e.intent.agent.into(),
        delegationHash: B256::from(e.intent.delegation_hash),
        recipient: e.intent.recipient.into(),
        amount: e.intent.amount,
        category: B256::from(e.intent.category),
        spendNonce: e.intent.spend_nonce,
        memo: e
            .intent
            .memo
            .map(|m| Bytes::from(m.to_vec()))
            .unwrap_or_default(),
        expiresAt: e.intent.expires_at,
        seq: e.seq,
        leafIndex: U256::from(e.leaf_index),
        acceptedCount: U256::from(e.accepted_count),
        siblings: e.siblings.iter().map(|s| B256::from(*s)).collect(),
    }
}
