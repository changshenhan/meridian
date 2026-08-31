//! P2-1/P2-3 验证者挑战演练（TECH_SPEC §6.18/§6.23）——独立验证者实体全链五幕+锚面核对。
//!
//! 决策 C（写者与验证者分离）的实施演练：验证者**不复用运营者内存态**，信源 =
//! 已接受意图镜像流（信封 + Receipt.seq + 接受时刻锚，§6.18.1），链上读取面 =
//! `epochs()` getter + settle 交易 calldata 解码（§6.18.2），复算走生产 netting 路径
//!（`fraud::recompute` → `lattice::build_epoch` 同一确定性代码），检出 → 出证闸 →
//! challenge 全链走通。
//!
//! 五幕（一条 anvil 会话，settler1 三 epoch + settler2 四 epoch，每幕独立聚合器/WAL）：
//!   幕 1 诚实对照：settle 诚实 net[] → 检出零信号 → 不出证不挑战 → 过窗 claim 收精确净额
//!        （「检出为空 = 静默」是验证者面必须有的负向能力：误报上链 = 押金销毁）。
//!   幕 2 kind1 漏单：人为错账 = settle 抽掉一行 → 验证者检出 → kind1 出证 → challenge →
//!        ChallengeSucceeded + epoch voided + 债券罚没给验证者 + claim 拒 EpochVoided。
//!        同幕附「缺漏镜像」负向：镜像缺该收款人 → 根不等 → 出证闸闭合 → 不挑战（保押金）。
//!   幕 3 kind2 低付：人为错账 = settle 少付一行 → kind2 出证 → 同款罚没断言。
//!   幕 4 monitor 声誉面核对（settler1 三 epoch，P2-5 §6.22.4）。
//!   幕 5/5b kind3 已撤销消费（P2-3 §6.20/§6.20.1）：正向 = 链上撤销（余量外）后聚合器
//!        撤销观察缺席仍接受 → 信号 ⑥ → kind3 双树出证（承诺树+接受树）→ 罚没；负向 =
//!        事件前接受（§6.20.1 抽债券向量：先消费后补撤销）→ 聚合器零检出 → 手工朴素
//!        证明上链被守卫驳回 ChallengeRejected(NotFraud) + 押金销毁 + epoch 一字不动。
//!   幕 6/6b kind4 跨分片消费（§6.19.1）：正向 = 绑定他方运营者后（聚合器绑定闸未装配
//!        ——§6.23.1 定夺 10 故障注入本体）余量外仍接受 → 信号 ⑦ → kind4 出证 → 罚没；
//!        负向 = 事件前接受 → 同款朴素证明驳回（boundAt 锚变体）。
//!   幕 7 monitor 声誉面核对（settler2 四 epoch）：kind3/kind4 罚没计数与债券账解码同实态。
//!
//! 时间线纪律：链上事件时刻锚（revokedAt/boundAt）用 `anvil_set_next_block_timestamp`
//! 钉块，每幕从**活链时**重推（前幕 fast_forward 会使预排失效）；聚合器时钟独立钉在
//! 事件时刻的余量内/外（镜像 accepted_at 全体 = clock 基点）。
//!
//! 错账注入点 = settle 调用参数（真实欺诈形态 commit≠settle；聚合器/合约零改动，§6.18）。
//! 演练形态为进程内双实体（验证者独立 signer = anvil #1，独立复算态）；生产形态 = 独立
//! 进程/独立运营者（§6.18.5 诚实边界）。settle 交易定位：演练规模下按回执哈希直取
//!（生产 = Settled 事件索引——同面公开数据）。
//!
//! 依赖：forge build 产物（contracts/out/）+ anvil（foundry）。独立 workspace。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use alloy::consensus::Transaction as _;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolCall, SolValue};
use anyhow::{Context, Result};

use mist_aggregator::fraud::{
    self, ChainEpoch, EventAnchors, FraudCandidate, IntentEvidence, MirrorIntent,
};
use mist_aggregator::ingest::{Aggregator, IngestConfig};
use mist_aggregator::lattice::{EpochResult, NetLine};
use mist_aggregator::proof::FormatVerifier;
use mist_aggregator::wal::Wal;
use mist_core::dsa::{self, AgentSigningKey, Delegation, OwnerSigningKey, RateLimit};

use contract_smoke::common::*;

/// 嵌套类型具象化（泛型 fn 作用域内 `IBatchSettler::X` 路径不可解析，先具象化再用）。
type NetInstruction = IBatchSettler::NetInstruction;
/// 验证者合并快照（S-66 读面拆分：epochs() + epochStatus() 经 common::epoch_snapshot 合并读出）。
type EpochView = EpochSnapshot;
type FraudProof = IBatchSettler::FraudProof;
type IntentProof = IBatchSettler::IntentProof;
type SettleCall = IBatchSettler::settleCall;

/// 每幕规模：3 收款人 × 3 笔 = 9 笔（epoch_capacity = 笔数满窗即封）。
const N_RECIPIENTS: usize = 3;
const PER_RECIPIENT: usize = 3;
const TOTAL: usize = N_RECIPIENTS * PER_RECIPIENT;
/// 聚合器委托：预算/速率上限 ≥ Σ amounts（每笔 100+i，每幕 Σ = 936）。
const TOTAL_CAP: u64 = 100_000;
/// 幕 6/6b 的「他方运营者」（kind4 跨分片信号 ⑦ 的绑定目标；≠ 本账本 operator 即可）。
const CROSS_OP: [u8; 20] = [0xC5; 20];

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

    // owner 钱包（OWNER_KEY 固定私钥，零余额 → 撤销/绑定 gas 由 anvil 注资补足）。
    let owner_signer = PrivateKeySigner::from_bytes(&B256::from(OWNER_KEY_BYTES))?;
    let owner_provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(RPC_URL.parse()?);
    provider
        .anvil_set_balance(owner_signer.address(), U256::from(ONE_ETH * 100))
        .await
        .context("anvil_setBalance(owner)")?;

    // P2-3：DSA / RevocationRegistry 先行部署——BatchSettler 五参构造的双锚面
    //（§6.23.1 定夺 7：锚面缺失面伪装，构造参数显式上链）。
    let dsa_addr = deploy(&provider, "DSA.sol/DSA.json", &[]).await?;
    let reg_addr = deploy(
        &provider,
        "RevocationRegistry.sol/RevocationRegistry.json",
        &abi_addr(dsa_addr),
    )
    .await?;

    let mut settler_args = abi_addr(operator_addr);
    settler_args.extend_from_slice(&abi_addr(Address::ZERO));
    settler_args.extend_from_slice(&abi_u256(CHALLENGE_BOND));
    settler_args.extend_from_slice(&abi_addr(dsa_addr));
    settler_args.extend_from_slice(&abi_addr(reg_addr));
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
    // P2-3 幕 5/6：第二实例（同参再部署，独立 epoch 序列）——幕 4 的 settler1 声誉
    // 断言口径原样保留（3 commit / 3 settle / 2 罚没），kind3/4 幕全部落 settler2。
    let settler2_addr = deploy(
        &provider,
        "BatchSettler.sol/BatchSettler.json",
        &settler_args,
    )
    .await?;
    let settler2 = IBatchSettler::new(settler2_addr, &provider);
    let settler2_verifier = IBatchSettler::new(settler2_addr, &verifier_provider);
    // 链上锚面控制实例（owner 写面：registerDelegation / revoke / bindOperator）。
    let dsa_owner = IDSA::new(dsa_addr, &owner_provider);
    let reg_owner = IRevocationRegistry::new(reg_addr, &owner_provider);
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
    // kind4 自指基线 = 本账本 operator（CROSS_OP 之外的他方才构成跨分片信号 ⑦）。
    let self_op: [u8; 20] = operator_addr.into_array();
    // 幕 1-3 锚面：三幕委托不上链注册 → 事件锚缺席（revokedAt/boundAt 读 0 = None），
    // ⑥⑦ 静默缺席——「锚不可得 = 检出率损失，不是假证」的生产同款形态。
    let anchors_none = ChainAnchors::new(self_op);

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
        commitment_root: view0.commitment_root.into(),
        acceptance_root: view0.acceptance_root.into(),
        net: chain_net0,
    };
    let det0 = fraud::detect(&rec0, &chain0, &anchors_none);
    assert!(det0.is_clean(), "诚实结算必须零检出信号：{det0:?}");
    assert!(
        fraud::fraud_candidates(&rec0, &chain0, &anchors_none).is_empty(),
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
        commitment_root: view2.commitment_root.into(),
        acceptance_root: view2.acceptance_root.into(),
        net: chain_net2,
    };
    let det2 = fraud::detect(&rec2, &chain2, &anchors_none);
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
    let cands2 = fraud::fraud_candidates(&rec2, &chain2, &anchors_none);
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
        !fraud::detect(&rec_short, &chain2, &anchors_none).commitment_root_match,
        "缺漏镜像根必然不等"
    );
    assert!(
        fraud::fraud_candidates(&rec_short, &chain2, &anchors_none).is_empty(),
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
        commitment_root: view3.commitment_root.into(),
        acceptance_root: view3.acceptance_root.into(),
        net: chain_net3,
    };
    let det3 = fraud::detect(&rec3, &chain3, &anchors_none);
    assert_eq!(det3.underpaid.len(), 1, "恰一个低付行");
    assert_eq!(det3.underpaid[0].honest_sum, honest_sum3 as u128);
    assert_eq!(det3.underpaid[0].chain_amount, honest_sum3 - 1);
    let cands3 = fraud::fraud_candidates(&rec3, &chain3, &anchors_none);
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
    let rpc = mist_monitor::rpc::JsonRpc::new(RPC_URL).map_err(|e| anyhow::anyhow!("{e}"))?;
    let settler_hex = format!("0x{}", hex::encode(settler_addr));
    let rep = mist_monitor::reputation::fetch_reputation(&rpc, &settler_hex)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert_eq!(rep.epochs_committed, 3, "幕 1-3 各 commit 一次");
    assert_eq!(rep.epochs_settled, 3, "幕 1-3 各 settle 一次（含被 voided 的）");
    assert_eq!(rep.slash_total, 2, "幕 2 kind1 + 幕 3 kind2 两次罚没");
    assert_eq!(rep.kind_counts.get(&1), Some(&1));
    assert_eq!(rep.kind_counts.get(&2), Some(&1));
    // bond_committed_wei 的口径是 Commit.bonded_amount（commit 债券 BOND），不是
    // challengeBond()（挑战押金，bond_on_chain）——两者金额不同，首版在此翻过车。
    assert_eq!(
        rep.bond_committed_wei,
        3 * BOND,
        "Σ Commit.bonded_amount = 3 × commit 债券 BOND"
    );
    // 合同余额 ≤ 3×BOND：构成含未领取结算资金/退款留存（§6.22.5），不等于净债券；
    // 本演练实态 = 幕 1 未罚没的 1×BOND（幕 2/3 债券已罚没给验证者出金、结算资金已退）。
    assert!(rep.contract_balance_wei <= 3 * BOND);
    let metrics = mist_monitor::reputation::render_reputation(&rep, &settler_hex)
        + &mist_monitor::reputation::render_read_ok(&settler_hex, true);
    assert!(metrics.contains("mist_operator_slash_total{settler="));
    assert!(metrics.contains("mist_operator_chain_read_ok{settler="));
    println!(
        "OK 幕 4 声誉面核对：monitor 派生（commit=3 settle=3 slash=2 kind={{1:1,2:1}} \
         bond_committed={} wei）与本会话链上事件一致",
        rep.bond_committed_wei
    );

    // ============================================================
    // 幕 5 —— P2-3 kind3 已撤销消费（正向，settler2 epoch 0）：链上撤销（余量外）
    // 后聚合器撤销观察缺席仍接受 → 信号 ⑥ → kind3 双树出证 → challenge 罚没。
    // ============================================================
    let d5 = anchored_delegation(owner_did, 5);
    let dh5 = dsa::delegation_hash(&d5);
    let sd5 = dsa::sign_delegation(&d5, &owner_key);
    dsa_owner
        .registerDelegation(Bytes::from(dsa::delegation_abi(&d5)), Bytes::from(sd5.signature.0))
        .send()
        .await
        .context("幕 5 register send")?
        .get_receipt()
        .await?;
    // 钉撤销时刻：每幕从活链时重推（前幕 fast_forward 会使预排失效）。
    let t5 = latest_timestamp(&provider).await? + 3600;
    provider
        .anvil_set_next_block_timestamp(t5)
        .await
        .context("幕 5 set_next_block_timestamp")?;
    reg_owner
        .revoke(B256::from(dh5))
        .send()
        .await
        .context("幕 5 revoke send")?
        .get_receipt()
        .await?;
    let ra5: u64 = reg_owner.revokedAt(B256::from(dh5)).call().await?;
    assert_eq!(ra5, t5, "撤销时刻必须钉在 t5（revokedAt = 事件时刻锚）");

    // 聚合器时钟 = t5 + 1000（margin 300 < 1000 → 接受越界）：聚合器未观察到撤销
    //（撤销观察缺席 = §6.23.1 定夺 10 的故障注入本体）。accepted_at 全体 = t5+1000。
    let (res5, mirror5) = ingest_anchored_act(&agent_key, sd5, dh5, t5 + 1000);
    commit_act(&settler2, 0, &res5).await?;
    let settle5 = settle_act(&settler2, 0, res5.net.clone(), res5.netting_root).await?;

    let (view5, chain_net5) = read_chain_epoch(&provider, settler2_addr, 0, settle5).await?;
    let rec5 = fraud::recompute(&mirror5, [0u8; 32]).expect("镜像自洽");
    let chain5 = ChainEpoch {
        commitment_root: view5.commitment_root.into(),
        acceptance_root: view5.acceptance_root.into(),
        net: chain_net5,
    };
    let anchors5 = ChainAnchors::prefetch(&provider, dsa_addr, reg_addr, &[dh5], self_op).await?;
    let det5 = fraud::detect(&rec5, &chain5, &anchors5);
    assert_eq!(det5.revoked_consumption.len(), 1, "撤销余量外接受 → 信号 ⑥");
    assert!(det5.cross_shard_consumption.is_empty(), "⑥⑦ 相互独立");
    let cands5 = fraud::fraud_candidates(&rec5, &chain5, &anchors5);
    assert_eq!(cands5.len(), 1, "kind3 恰一个候选");
    assert_eq!(cands5[0].kind, fraud::KIND_REVOKED);
    assert_eq!(cands5[0].intents.len(), 1, "kind3 恰 1 条意图（BadFraudKind 上限）");
    challenge_and_assert(&provider, &settler2, &settler2_verifier, 0, &cands5[0]).await?;
    println!("OK 幕 5 kind3 已撤销消费：撤销观察缺席 → 出证罚没（承诺树+接受树双路径过链上守卫）");

    // ============================================================
    // 幕 5b —— kind3 负向（§6.20.1 抽债券向量链上死亡，settler2 epoch 1）：事件前
    // 接受（acceptedAt 在 revokedAt+margin 之内）→ 聚合器零检出 → 手工构造的朴素
    // 证明上链被守卫驳回 ChallengeRejected(NotFraud) + 押金销毁 + epoch 一字不动。
    // ============================================================
    let d5b = anchored_delegation(owner_did, 51);
    let dh5b = dsa::delegation_hash(&d5b);
    let sd5b = dsa::sign_delegation(&d5b, &owner_key);
    dsa_owner
        .registerDelegation(Bytes::from(dsa::delegation_abi(&d5b)), Bytes::from(sd5b.signature.0))
        .send()
        .await
        .context("幕 5b register send")?
        .get_receipt()
        .await?;
    let t5b = latest_timestamp(&provider).await? + 3600;
    // 诚实批次先上链（接受时刻 = t5b − 5000，在撤销事件之前——向量本体）。
    let (res5b, mirror5b) = ingest_anchored_act(&agent_key, sd5b, dh5b, t5b - 5000);
    commit_act(&settler2, 1, &res5b).await?;
    let settle5b = settle_act(&settler2, 1, res5b.net.clone(), res5b.netting_root).await?;
    // 事后补撤销（把 revokedAt 钉在 t5b——接受之后）：朴素挑战者据此刻主张 kind3。
    provider
        .anvil_set_next_block_timestamp(t5b)
        .await
        .context("幕 5b set_next_block_timestamp")?;
    reg_owner
        .revoke(B256::from(dh5b))
        .send()
        .await
        .context("幕 5b revoke send")?
        .get_receipt()
        .await?;
    let ra5b: u64 = reg_owner.revokedAt(B256::from(dh5b)).call().await?;
    assert_eq!(ra5b, t5b, "撤销时刻必须钉在 t5b（事件在接受之后）");

    let (view5b, chain_net5b) = read_chain_epoch(&provider, settler2_addr, 1, settle5b).await?;
    let rec5b = fraud::recompute(&mirror5b, [0u8; 32]).expect("镜像自洽");
    let chain5b = ChainEpoch {
        commitment_root: view5b.commitment_root.into(),
        acceptance_root: view5b.acceptance_root.into(),
        net: chain_net5b,
    };
    let anchors5b =
        ChainAnchors::prefetch(&provider, dsa_addr, reg_addr, &[dh5b], self_op).await?;
    // 聚合器侧：余量守卫拦下 → 零检出零候选（不出证 = 保押金）。
    assert!(
        fraud::detect(&rec5b, &chain5b, &anchors5b).is_clean(),
        "事件前接受：余量之内聚合器必须零信号（§6.20.1）"
    );
    assert!(
        fraud::fraud_candidates(&rec5b, &chain5b, &anchors5b).is_empty(),
        "事件前接受不得出证"
    );
    // 链上侧：绕过聚合器出证闸手工构造的朴素证明（自洽双树路径 + 镜像真实 accepted_at
    // + 链上接受根）——守卫判 NotFraud 驳回，押金销毁，epoch 不动。
    let ev5b = fraud::evidence_for(
        &rec5b,
        mirror5b[0].seq,
        chain5b.commitment_root,
        chain5b.acceptance_root,
    )
    .expect("自洽镜像必可出证（朴素证明的原料）");
    let fp5b = FraudProof {
        kind: fraud::KIND_REVOKED,
        targetNetIndex: U256::ZERO,
        intents: vec![to_intent_proof(&ev5b)],
    };
    challenge_and_expect_reject(&provider, &settler2, &settler2_verifier, 1, fp5b).await?;
    println!("OK 幕 5b 朴素证明 ChallengeRejected(NotFraud)：§6.20.1 抽债券向量链上死亡 + 押金销毁");

    // ============================================================
    // 幕 6 —— P2-3 kind4 跨分片消费（正向，settler2 epoch 2）：绑定他方运营者（余量
    // 外）后聚合器绑定闸未装配仍接受 → 信号 ⑦ → kind4 出证 → 罚没。锚 =
    // DSA.operatorOf/boundAt（§6.19.1）。
    // ============================================================
    let d6 = anchored_delegation(owner_did, 6);
    let dh6 = dsa::delegation_hash(&d6);
    let sd6 = dsa::sign_delegation(&d6, &owner_key);
    dsa_owner
        .registerDelegation(Bytes::from(dsa::delegation_abi(&d6)), Bytes::from(sd6.signature.0))
        .send()
        .await
        .context("幕 6 register send")?
        .get_receipt()
        .await?;
    let t6 = latest_timestamp(&provider).await? + 3600;
    provider
        .anvil_set_next_block_timestamp(t6)
        .await
        .context("幕 6 set_next_block_timestamp")?;
    dsa_owner
        .bindOperator(B256::from(dh6), Address::from(CROSS_OP))
        .send()
        .await
        .context("幕 6 bindOperator send")?
        .get_receipt()
        .await?;
    let ba6: u64 = dsa_owner.boundAt(B256::from(dh6)).call().await?;
    let op6: Address = dsa_owner.operatorOf(B256::from(dh6)).call().await?;
    assert_eq!(ba6, t6, "绑定时刻必须钉在 t6");
    assert_eq!(op6, Address::from(CROSS_OP), "绑定指向他方运营者");
    assert_ne!(op6.into_array(), self_op, "绑定须 ≠ 本账本 operator");

    let (res6, mirror6) = ingest_anchored_act(&agent_key, sd6, dh6, t6 + 1000);
    commit_act(&settler2, 2, &res6).await?;
    let settle6 = settle_act(&settler2, 2, res6.net.clone(), res6.netting_root).await?;

    let (view6, chain_net6) = read_chain_epoch(&provider, settler2_addr, 2, settle6).await?;
    let rec6 = fraud::recompute(&mirror6, [0u8; 32]).expect("镜像自洽");
    let chain6 = ChainEpoch {
        commitment_root: view6.commitment_root.into(),
        acceptance_root: view6.acceptance_root.into(),
        net: chain_net6,
    };
    let anchors6 = ChainAnchors::prefetch(&provider, dsa_addr, reg_addr, &[dh6], self_op).await?;
    let det6 = fraud::detect(&rec6, &chain6, &anchors6);
    assert_eq!(det6.cross_shard_consumption.len(), 1, "绑定他方后余量外接受 → 信号 ⑦");
    assert!(det6.revoked_consumption.is_empty());
    let cands6 = fraud::fraud_candidates(&rec6, &chain6, &anchors6);
    assert_eq!(cands6.len(), 1, "kind4 恰一个候选");
    assert_eq!(cands6[0].kind, fraud::KIND_CROSS_SHARD);
    challenge_and_assert(&provider, &settler2, &settler2_verifier, 2, &cands6[0]).await?;
    println!("OK 幕 6 kind4 跨分片消费：绑定闸未装配 → 出证罚没（operatorOf 锚过链上守卫）");

    // ============================================================
    // 幕 6b —— kind4 负向（settler2 epoch 3）：事件前接受（绑定在接受之后）→ 聚合器
    // 零检出 → 朴素证明被链上守卫驳回（同幕 5b 形态；boundAt 锚变体）。
    // ============================================================
    let d6b = anchored_delegation(owner_did, 61);
    let dh6b = dsa::delegation_hash(&d6b);
    let sd6b = dsa::sign_delegation(&d6b, &owner_key);
    dsa_owner
        .registerDelegation(Bytes::from(dsa::delegation_abi(&d6b)), Bytes::from(sd6b.signature.0))
        .send()
        .await
        .context("幕 6b register send")?
        .get_receipt()
        .await?;
    let t6b = latest_timestamp(&provider).await? + 3600;
    let (res6b, mirror6b) = ingest_anchored_act(&agent_key, sd6b, dh6b, t6b - 5000);
    commit_act(&settler2, 3, &res6b).await?;
    let settle6b = settle_act(&settler2, 3, res6b.net.clone(), res6b.netting_root).await?;
    provider
        .anvil_set_next_block_timestamp(t6b)
        .await
        .context("幕 6b set_next_block_timestamp")?;
    dsa_owner
        .bindOperator(B256::from(dh6b), Address::from(CROSS_OP))
        .send()
        .await
        .context("幕 6b bindOperator send")?
        .get_receipt()
        .await?;
    let ba6b: u64 = dsa_owner.boundAt(B256::from(dh6b)).call().await?;
    assert_eq!(ba6b, t6b, "绑定时刻必须钉在 t6b（事件在接受之后）");

    let (view6b, chain_net6b) = read_chain_epoch(&provider, settler2_addr, 3, settle6b).await?;
    let rec6b = fraud::recompute(&mirror6b, [0u8; 32]).expect("镜像自洽");
    let chain6b = ChainEpoch {
        commitment_root: view6b.commitment_root.into(),
        acceptance_root: view6b.acceptance_root.into(),
        net: chain_net6b,
    };
    let anchors6b =
        ChainAnchors::prefetch(&provider, dsa_addr, reg_addr, &[dh6b], self_op).await?;
    assert!(
        fraud::detect(&rec6b, &chain6b, &anchors6b).is_clean(),
        "事件前绑定：余量之内聚合器必须零信号"
    );
    assert!(fraud::fraud_candidates(&rec6b, &chain6b, &anchors6b).is_empty());
    let ev6b = fraud::evidence_for(
        &rec6b,
        mirror6b[0].seq,
        chain6b.commitment_root,
        chain6b.acceptance_root,
    )
    .expect("自洽镜像必可出证");
    let fp6b = FraudProof {
        kind: fraud::KIND_CROSS_SHARD,
        targetNetIndex: U256::ZERO,
        intents: vec![to_intent_proof(&ev6b)],
    };
    challenge_and_expect_reject(&provider, &settler2, &settler2_verifier, 3, fp6b).await?;
    println!("OK 幕 6b 朴素证明 ChallengeRejected(NotFraud)：boundAt 锚变体同款驳回 + 押金销毁");

    // ============================================================
    // 幕 7 —— P2-5 声誉面核对（settler2 全 4 epoch，§6.22.4）：monitor 只读派生 vs
    // 幕 5/6 真实链上事件（4 commit / 4 settle / kind3+kind4 两次罚没）。
    // ChallengeRejected（幕 5b/6b）是未知 topic0，被声誉面跳过不计数——只读派生对
    // 未建模事件静默，恰是「损失检出率，不产假计数」的同款边界。
    // ============================================================
    let settler2_hex = format!("0x{}", hex::encode(settler2_addr));
    let rep2 = mist_monitor::reputation::fetch_reputation(&rpc, &settler2_hex)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    assert_eq!(rep2.epochs_committed, 4, "幕 5/5b/6/6b 各 commit 一次");
    assert_eq!(rep2.epochs_settled, 4);
    assert_eq!(rep2.slash_total, 2, "幕 5 kind3 + 幕 6 kind4 两次罚没");
    assert_eq!(rep2.kind_counts.get(&3), Some(&1));
    assert_eq!(rep2.kind_counts.get(&4), Some(&1));
    assert_eq!(rep2.bond_committed_wei, 4 * BOND, "Σ Commit.bonded_amount = 4 × BOND");
    assert!(rep2.contract_balance_wei <= 4 * BOND);
    println!(
        "OK 幕 7 声誉面核对（settler2）：monitor kind3/4 解码（commit=4 settle=4 slash=2 \
         kind={{3:1,4:1}} bond_committed={} wei）与本会话链上事件一致",
        rep2.bond_committed_wei
    );

    println!("OK: P2-1/P2-3 验证者挑战演练五幕全过（诚实静默 / kind1 漏单 / kind2 低付 / kind3 已撤销消费 / kind4 跨分片消费，正负向 + 朴素证明驳回，Anvil 全绿）+ P2-5 声誉面核对（幕 4/7）");
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
        "mist-verifier-drill-{}-act{act}.wal",
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
                accepted_at: now,
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

/// 运营者 commit（诚实承诺根 + 撤销根 + 接受锚根 + 密封时刻 + 债券；P2-3 五参面）。
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
            B256::from(res.acceptance_root),
            res.sealed_at,
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
    let view = epoch_snapshot(&settler, epoch_id).await?;
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
        B256::from(view.netting_root),
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
    let view_before = epoch_snapshot(&settler, epoch_id).await?;
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

    let view_after = epoch_snapshot(&settler, epoch_id).await?;
    assert!(
        view_after.challenged && view_after.voided,
        "挑战成功后 epoch 必须 challenged + voided"
    );
    assert_eq!(view_after.bonded_amount, U256::ZERO, "债券必须全额罚没");
    assert_eq!(
        view_after.settlement_funded,
        U256::ZERO,
        "结算资金必须退运营者"
    );
    // 罚没净额 = 运营者债券（gas 逐 wei 扣除核对）。押金（msg.value）随笔原额退回
    // ——付出与赔付相抵净零，挑战者净增只有债券（S-50 罚没口径的链上实测复述）。
    let gas = U256::from(rec.gas_used as u128 * rec.effective_gas_price);
    let verifier_after = provider.get_balance(verifier_addr).await?;
    assert_eq!(
        verifier_after + gas - verifier_before,
        view_before.bonded_amount,
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
        acceptedAt: e.accepted_at,
        acceptanceSiblings: e.acceptance_siblings.iter().map(|s| B256::from(*s)).collect(),
    }
}

/// 幕 5/6 委托（链上注册与聚合器摄取同一份——kind3/4 锚面的对象）。nonce 每幕独立
///（链上 DSA 面同 owner 多委托并存；agent/限额形状与 [`ingest_act`] 同形）。
fn anchored_delegation(owner_did: [u8; 20], nonce: u64) -> Delegation {
    Delegation {
        agent: [0x01; 20],
        owner: owner_did,
        nonce,
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
    }
}

/// 当前活链时间戳（每幕钉点基线——前幕 fast_forward / 事件会使预排失效，逐幕重推）。
async fn latest_timestamp<P: Provider>(provider: &P) -> Result<u64> {
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .context("latest block 不存在")?;
    Ok(block.header.timestamp)
}

/// 事件时刻锚的链上读数（§6.23.1 定夺 9）：drill 侧 [`EventAnchors`] 实现——prefetch
/// 一次性读链入静态表，`detect`/`fraud_candidates` 走纯函数面。空表 = 锚缺席（None 语义，
/// 幕 1-3 委托未上链注册的形态）。
struct ChainAnchors {
    revoked: BTreeMap<[u8; 32], u64>,
    bound: BTreeMap<[u8; 32], (u64, [u8; 20])>,
    self_op: [u8; 20],
}

impl ChainAnchors {
    fn new(self_op: [u8; 20]) -> Self {
        Self {
            revoked: BTreeMap::new(),
            bound: BTreeMap::new(),
            self_op,
        }
    }

    /// 预取（幕 5/6 锚面）：`revokedAt ≠ 0` 入撤销表；`operatorOf` 非零地址再读
    /// `boundAt` 入绑定表。零时刻/零地址 = 未撤销/未绑定，归一为 None（守卫不因
    /// 缺锚反向定罪）。
    async fn prefetch<P: Provider>(
        provider: &P,
        dsa_addr: Address,
        reg_addr: Address,
        dhs: &[[u8; 32]],
        self_op: [u8; 20],
    ) -> Result<Self> {
        let dsa_c = IDSA::new(dsa_addr, provider);
        let reg_c = IRevocationRegistry::new(reg_addr, provider);
        let mut out = Self::new(self_op);
        for dh in dhs {
            let ra: u64 = reg_c.revokedAt(B256::from(*dh)).call().await?;
            if ra != 0 {
                out.revoked.insert(*dh, ra);
            }
            let op: Address = dsa_c.operatorOf(B256::from(*dh)).call().await?;
            if op != Address::ZERO {
                let ba: u64 = dsa_c.boundAt(B256::from(*dh)).call().await?;
                out.bound.insert(*dh, (ba, op.into_array()));
            }
        }
        Ok(out)
    }
}

impl EventAnchors for ChainAnchors {
    fn revoked_at(&self, dh: &[u8; 32]) -> Option<u64> {
        self.revoked.get(dh).copied()
    }

    fn bound_at(&self, dh: &[u8; 32]) -> Option<u64> {
        self.bound.get(dh).map(|(at, _)| *at)
    }

    fn operator_of(&self, dh: &[u8; 32]) -> Option<[u8; 20]> {
        self.bound.get(dh).map(|(_, op)| *op)
    }

    fn self_operator(&self) -> [u8; 20] {
        self.self_op
    }
}

/// 幕 5/6 摄取（P2-3）：委托已由调用方在链上注册（锚面对象 = 链上同一份 d/sd），聚合器
/// 时钟钉在 `clock_base`——全体镜像 `accepted_at` = clock_base（锚定余量内/外的关键
/// 旋钮：clock_base = 事件时刻 + 1000 越界 / − 5000 余量内）。注册进聚合器 → 满窗提交
/// + 镜像记录 → 密封结算。上链由调用方控制（错账/锚面时序注入点都在链侧）。
fn ingest_anchored_act(
    agent_key: &AgentSigningKey,
    sd: dsa::SignedDelegation,
    dh: [u8; 32],
    clock_base: u64,
) -> (EpochResult, Vec<MirrorIntent>) {
    let clock = Arc::new(AtomicU64::new(clock_base));
    let wal_path = std::env::temp_dir().join(format!(
        "mist-verifier-drill-{}-anchored-{clock_base}.wal",
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
    agg.register(sd, agent_key.verifying_key());

    // 提交 + 镜像记录（accepted_at = clock_base 快照——P2-3 镜像面接受锚）。
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
                accepted_at: now,
            });
            i += 1;
        }
    }
    assert_eq!(mirror.len(), TOTAL, "镜像流必须与提交数一致");

    clock.fetch_add(10_000, Ordering::Relaxed);
    let sealed = agg.seal_expired(clock.load(Ordering::Relaxed), 1);
    assert_eq!(sealed.len(), 1, "必须恰好一个密封 epoch");
    assert_eq!(sealed[0].entries.len(), TOTAL);
    let res = agg.settle_epoch(&sealed[0]).expect("settle epoch");
    let _ = std::fs::remove_file(&wal_path);
    (res, mirror)
}

/// 朴素证明上链驳回断言（幕 5b/6b 共用，§6.20.1）：证明自洽（双树路径为真）但守卫判
/// NotFraud → ChallengeRejected(reason=NotFraud) + 押金全额销毁 + epoch 一字不动。
async fn challenge_and_expect_reject<P: Provider>(
    provider: &P,
    settler: &IBatchSettler::IBatchSettlerInstance<&P>,
    settler_verifier: &IBatchSettler::IBatchSettlerInstance<&P>,
    epoch_id: u64,
    fp: FraudProof,
) -> Result<()> {
    let view_before = epoch_snapshot(&settler, epoch_id).await?;
    let verifier: PrivateKeySigner = verifier_wallet();
    let verifier_addr = verifier.address();
    let verifier_before = provider.get_balance(verifier_addr).await?;

    let rec = settler_verifier
        .challenge(U256::from(epoch_id), fp)
        .value(U256::from(CHALLENGE_BOND))
        .send()
        .await
        .context("naive challenge send")?
        .get_receipt()
        .await
        .context("naive challenge receipt")?;
    assert!(rec.status(), "驳回路径必须成功（不再 revert，S-38 原因码语义）");
    let rejected = rec
        .logs()
        .iter()
        .find(|l| {
            l.topics().first() == Some(&keccak256("ChallengeRejected(uint256,address,uint8)"))
        })
        .context("ChallengeRejected 事件必须发出")?;
    // reason = NotFraud(1)：事件 data 单字，低字节（见证 data 访问面：log.data().data）。
    assert_eq!(
        rejected.data().data[31], 1,
        "驳回原因必须 = NotFraud(1)（自洽证明但守卫判不成立）"
    );

    // 押金销毁：验证者净减 = 押金 + gas（无任何赔付方向）。
    let gas = U256::from(rec.gas_used as u128 * rec.effective_gas_price);
    let verifier_after = provider.get_balance(verifier_addr).await?;
    assert_eq!(
        verifier_before - verifier_after,
        U256::from(CHALLENGE_BOND) + gas,
        "押金必须全额销毁（验证者净减押金+gas，逐 wei）"
    );
    // epoch 一字不动：状态/债券/结算资金原封（仍可再挑战——驳回不是终审）。
    let view_after = epoch_snapshot(&settler, epoch_id).await?;
    assert!(
        !view_after.challenged && !view_after.voided,
        "驳回不改变 epoch 状态"
    );
    assert_eq!(
        view_after.bonded_amount, view_before.bonded_amount,
        "运营者债券不动"
    );
    assert_eq!(
        view_after.settlement_funded, view_before.settlement_funded,
        "结算资金不动"
    );
    Ok(())
}
