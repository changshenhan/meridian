//! 对外框架 demo 的真链结算侧车（S-76，TECH_SPEC §6.16）。
//!
//! 消费 mcp-server（或任一框架 demo / mcp_probe）产出的 WAL——钱的最后一公里：
//! 快照 → 账本恢复 → 显式密封当前尾 → settle_epoch → BatchSettler
//! commit → settle → 过挑战窗 → 逐收款人 claim 逐 wei 对账（m1_demo E 段同款）。
//!
//! 定夺（TECH_SPEC §6.16 S-76）：
//!   ① 侧车是 WAL **快照消费者不回写账本**：settle_epoch 落的 EpochSeal/Netting
//!      记录进 `<wal>.settle-snap-<pid>`，原 WAL 一字不动 → demo 第 7 步幂等重跑；
//!      RSM 性质（§6.26）保证快照侧与在线侧是同一 WAL 的同一确定性函数。
//!   ② 密封语义 = `seal_expired(now, 0)`：epoch_secs=0 即「运营者显式密封当前尾」，
//!      不模拟时间窗轮询（m1_demo 传 60 是吞吐演示口径）。
//!   ④ 不做链上 `registerDelegation`：WAL 注册面在验签后只存
//!      `RegisteredDelegation{delegation, agent_pub}`，owner 签名即弃不可重建；
//!      且 commit/settle/claim 不消费 DSA 登记状态（BatchSettler 仅 kind4 挑战守卫
//!      读 `operatorOf`/`boundAt`）。链上登记交叉锚由 m1_demo/noir_demo 覆盖。
//!   ⑤ 金额标度 = 账本 amount 与链上 wei 同一标度（m1_demo E 段先例）。
//!
//! 依赖：forge build 产物（contracts/out/）+ anvil（foundry 在 PATH）。
//! 用法：cargo run --release --bin demo_settle -- --wal <path-to-mist.wal>

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{bail, Context, Result};

use mist_aggregator::ingest::{Aggregator, IngestConfig};
use mist_aggregator::lattice;
use mist_aggregator::merkle::{leaf as merkle_leaf, merkle_root};
use mist_aggregator::proof::FormatVerifier;

use contract_smoke::common::*;

fn system_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

fn parse_args() -> Result<PathBuf> {
    let args: Vec<String> = std::env::args().collect();
    let idx = args
        .iter()
        .position(|a| a == "--wal")
        .context("用法：demo_settle --wal <path-to-mist.wal>")?;
    let wal = args
        .get(idx + 1)
        .context("用法：demo_settle --wal <path-to-mist.wal>")?;
    let wal = PathBuf::from(wal);
    if !wal.is_file() {
        bail!(
            "WAL 不存在：{}（先跑 mcp_probe 或框架 demo 产出账本）",
            wal.display()
        );
    }
    Ok(wal)
}

#[tokio::main]
async fn main() -> Result<()> {
    let wal = parse_args()?;
    let mut anvil = spawn_anvil()?;
    // 快照：拷贝后操作副本，原 WAL 一字不动（定夺 ①）。
    let mut snap_name = OsString::from(wal.as_os_str());
    snap_name.push(format!(".settle-snap-{}", std::process::id()));
    let snap = PathBuf::from(snap_name);
    std::fs::copy(&wal, &snap)
        .with_context(|| format!("copy {} → {}", wal.display(), snap.display()))?;
    let result = settle(&snap).await;
    let _ = anvil.kill();
    let _ = std::fs::remove_file(&snap); // 用后即焚（失败路径也清）
    result
}

async fn settle(snap: &Path) -> Result<()> {
    // ---- 账本恢复（RSM：状态 = WAL 的确定性函数，§6.26）----
    // 重放不验证明（Intent 记录是摄取后事实），FormatVerifier 仅占位验证缝。
    let (agg, truncated) = Aggregator::restore_from_wal(
        IngestConfig::default(),
        Box::new(FormatVerifier),
        snap,
        Box::new(system_now),
    )
    .with_context(|| format!("restore {}", snap.display()))?;
    if truncated {
        bail!(
            "WAL 撕裂尾非空（{}）——demo 账本应优雅停机落盘，撕裂尾 = 异常，fail-closed",
            snap.display()
        );
    }

    // ---- 显式密封当前尾（定夺 ②：epoch_secs=0）----
    let sealed = agg.seal_expired(system_now(), 0);
    if sealed.len() != 1 {
        bail!(
            "密封得 {} 个 epoch（预期恰 1）：WAL 无已接受意图，或尾已密封（重放侧不再密封）",
            sealed.len()
        );
    }
    let entries = sealed[0].entries.clone();
    let res = agg.settle_epoch(&sealed[0]).context("settle epoch")?;

    // ---- 结算前自检：链下重算与内核同根（m1_demo C 段同款）----
    let leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|e| merkle_leaf(e.seq, e.intent_hash))
        .collect();
    assert_eq!(
        merkle_root(&leaves),
        res.commitment_root,
        "承诺根链下重算必须与内核同根"
    );
    assert_eq!(
        lattice::netting_root(&res.net),
        res.netting_root,
        "净额根链下重算必须与内核同根"
    );
    let sum_net: u128 = res.net.iter().map(|l| l.amount as u128).sum();
    println!(
        "OK demo-settle: 快照密封 epoch {}（{} 笔意图 → {} 收款人，Σnet={sum_net} wei）",
        res.epoch_id,
        entries.len(),
        res.net.len()
    );

    // ---- 链上：m1_demo E 段同款（部署方 = anvil #0 = operator）----
    let deployer: PrivateKeySigner = ANVIL_PKEY0.parse()?;
    let deployer_addr = deployer.address();
    let provider = ProviderBuilder::new()
        .wallet(deployer)
        .connect_http(RPC_URL.parse()?);
    wait_for_chain(&provider).await?;

    // RevocationRegistry 部署保持合同栈完整（BatchSettler 构造器要求且交叉核对
    // revocations_.dsa() == dsa；本 demo 不触发撤销路径，S-11d 场景 2 已覆盖）。
    let dsa_addr = deploy(&provider, "DSA.sol/DSA.json", &[]).await?;
    let reg_addr = deploy(
        &provider,
        "RevocationRegistry.sol/RevocationRegistry.json",
        &abi_addr(dsa_addr),
    )
    .await?;
    let mut settler_args = abi_addr(deployer_addr);
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

    settler
        .commit(
            U256::from(res.epoch_id),
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
    settler
        .settle(U256::from(res.epoch_id), to_net(&res), B256::from(res.netting_root))
        .value(U256::from(sum_net))
        .send()
        .await
        .context("settle send")?
        .get_receipt()
        .await
        .context("settle receipt")?;
    fast_forward(&provider).await?;

    for (idx, line) in res.net.iter().enumerate() {
        let addr = Address::from_slice(&line.recipient);
        let before = provider.get_balance(addr).await?;
        settler
            .claim(U256::from(res.epoch_id), U256::from(idx as u64))
            .send()
            .await
            .with_context(|| format!("claim #{idx} send"))?
            .get_receipt()
            .await
            .with_context(|| format!("claim #{idx} receipt"))?;
        let delta = provider.get_balance(addr).await? - before;
        assert_eq!(delta, U256::from(line.amount), "收款人 {idx} 必须收精确净额");
        println!("OK demo-settle: claim #{idx} → {addr} 收 {} wei", line.amount);
    }
    println!(
        "OK demo-settle: 真链结算完成 commit→settle→过挑战窗→claim（{} 收款人，Σ={sum_net} wei）",
        res.net.len()
    );
    Ok(())
}
