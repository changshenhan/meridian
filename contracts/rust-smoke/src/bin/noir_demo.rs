//! M1 真 ZK demo —— S-51（TECH_SPEC §6.15，候选⑥）：demo 层真 ZK 装配示例。
//!
//! `m1_demo` 的 A 段（ZK 授权缝）在 demo 层一直是占位口径（FormatVerifier）。本 bin
//! 用 §6.13/§6.14 的真后端把同一条链重走一遍——**真电路证明 → 真验证后端 + 撤销根
//! 绑定闸 → 链上净额结算，撤销根三方同源**：
//!
//!   A. 装配面（§6.14 全套）：`SdkClient::with_noir` + `InProcessAggregator`
//!      （`BbVerifier` + `enforce_revocation_root = true`，S-48 构造期配对闸生效）。
//!   B. 授权上下文：`client.authorize()` → `create_delegation` 同参数重建同 dh →
//!      链上 `DSA.registerDelegation`，`isRegistered(dh)` 断言 sha256(delegationABI)
//!      == core delegation_hash（m1_demo 同款交叉实现契约）。
//!   C. 撤销根三方同源：聚合器 `revoke(另一委托)` → `pay()` 现取 witness（S-45）→
//!      证明公共输入 `revocation_root` 经绑定闸锚定本账本撤销树 → seal 后
//!      `EpochResult.revocation_root` == witness 根（逐字节，S-41 同棵 Pedersen 树）
//!      → 该根上链 `BatchSettler.commit`。
//!   D. 对照组：占位 `SdkClient::new` 在同一 BbVerifier 聚合器上必拒 `E_PROOF`——
//!      bb 全拒占位证明，正向的接受不是占位漏网（S-47 桥 e2e 对照组同口径）。
//!   E. 链上净额结算：`seal_expired`（epoch_capacity = 笔数，满窗即封）→
//!      `settle_epoch` → `commit(债券)` → `settle(Σnet)` → 过窗 → 逐收款人 `claim`。
//!
//! 依赖：forge build 产物（contracts/out/）+ anvil（foundry）+ nargo/bb 工具链
//! （NoirProver 三层探测，原生或 WSL 兜底）。门控 `MERIDIAN_NOIR_DEMO=1`（verify.sh
//! 步 9e）。CI 不跑（noir job 无 anvil、solidity job 无 nargo/bb，§6.15 诚实边界）。

use std::sync::Arc;

use alloy::primitives::{Bytes, B256, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};

use meridian_aggregator::bb::{BbBackend, BbVerifier};
use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::wal::Wal;
use meridian_core::error::Error;
use meridian_sdk::identity::{create_delegation, AgentWallet, DelegationLimits};
use meridian_sdk::prover::NoirProver;
use meridian_sdk::{InProcessAggregator, PayParams, SdkClient, SdkError};

use contract_smoke::common::*;

/// 支付笔数 = epoch 容量（满窗即封，`seal_expired` 恰好一个密封 epoch）。
const N_PAYMENTS: usize = 3;
/// attestation 私钥标量（LE 不透明字节，0xDEADBEEF < EdDSA 子群阶，§6.14 值域闸合法）。
const ATTEST_SECRET_SEED: [u8; 4] = [0xEF, 0xBE, 0xAD, 0xDE];

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var("MERIDIAN_NOIR_DEMO").as_deref() != Ok("1") {
        println!("SKIP: MERIDIAN_NOIR_DEMO=1 未设（真电路证明重操作，verify.sh 步 9e 显式开启）");
        return Ok(());
    }
    let mut anvil = spawn_anvil()?;
    let result = run_noir_demo().await;
    let _ = anvil.kill();
    result
}

async fn run_noir_demo() -> Result<()> {
    // ---- 工件 + 工具链：formal_zk 产物（9b/9c/9d 同款）与 bb 后端 ----
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("contracts/rust-smoke 的上两级即仓库根")
        .to_path_buf();
    let vk = std::fs::read(root.join("circuits/target/vk"))
        .context("circuits/target/vk 不存在（先跑 verify.sh 第 9 步 formal_zk）")?;
    if !root
        .join("circuits/target/spend_authorization.json")
        .exists()
    {
        anyhow::bail!("circuits/target/spend_authorization.json 不存在（先跑 formal_zk）");
    }
    let backend = BbBackend::detect().context("bb 工具链不可得（Windows 原生与 WSL 兜底皆无）")?;

    // ---- 链侧：部署方 = anvil #0（= operator）；owner = core 私钥派生地址 ----
    let deployer: PrivateKeySigner = ANVIL_PKEY0.parse()?;
    let deployer_addr = deployer.address();
    let provider = ProviderBuilder::new()
        .wallet(deployer)
        .connect_http(RPC_URL.parse()?);
    wait_for_chain(&provider).await?;

    let dsa_addr = deploy(&provider, "DSA.sol/DSA.json", &[]).await?;
    let _reg_addr = deploy(
        &provider,
        "RevocationRegistry.sol/RevocationRegistry.json",
        &abi_addr(dsa_addr),
    )
    .await?;
    let mut settler_args = abi_addr(deployer_addr);
    settler_args.extend_from_slice(&abi_addr(alloy::primitives::Address::ZERO));
    // S-50：挑战押金为部署期构造参数（本 demo 沿用参考值 0.1 ether）。
    settler_args.extend_from_slice(&abi_u256(CHALLENGE_BOND));
    let settler_addr = deploy(
        &provider,
        "BatchSettler.sol/BatchSettler.json",
        &settler_args,
    )
    .await?;
    let dsa_c = IDSA::new(dsa_addr, &provider);
    let settler = IBatchSettler::new(settler_addr, &provider);

    // ---- 聚合器：BbVerifier + 撤销根绑定闸（S-48：真后端 ⇒ 构造期强制配对）----
    let wal_path =
        std::env::temp_dir().join(format!("meridian-noir-demo-{}.wal", std::process::id()));
    let _ = std::fs::remove_file(&wal_path);
    let wal = Wal::open(&wal_path, 1_000).expect("open wal");
    let verifier = BbVerifier::from_parts(vk, backend, root.join("target/bb-demo-noir"));
    let agg = Arc::new(Aggregator::new(
        IngestConfig {
            epoch_capacity: N_PAYMENTS, // 满窗即封：3 笔 = 1 个密封 epoch
            epoch_secs: 60,
            enforce_revocation_root: true,
            ..Default::default()
        },
        Box::new(verifier),
        wal,
    ));

    // ---- SDK 装配（§6.14）：with_noir = prove 后端 + attestation keyring 同一实例 ----
    let wallet = AgentWallet::from_seed([0xA5u8; 32]);
    let agent: [u8; 20] = [0x0Bu8; 20];
    let limits = DelegationLimits {
        max_per_spend: 5_000,
        rate_window_secs: 60,
        rate_max_per_window: 20_000,
        total_cap: 100_000,
        categories: vec![], // 空白名单：电路断言 4 不要求类别（S-09 口径）
        not_before: 0,
        expires_at: 1_900_000_000,
    };
    let prover = NoirProver::from_repo_root(&root).context("noir 工具链不可得")?;
    let client = SdkClient::with_noir(
        wallet,
        Box::new(InProcessAggregator::from_inner(Arc::clone(&agg))),
        prover,
        {
            let mut s = [0u8; 32];
            s[..4].copy_from_slice(&ATTEST_SECRET_SEED);
            s
        },
    );

    // ---- B. 授权上下文：SDK authorize → 同参数重建同 dh → 链上登记（交叉实现契约）----
    let owner_signer = PrivateKeySigner::from_bytes(&B256::from(OWNER_KEY_BYTES))?;
    provider
        .anvil_set_balance(owner_signer.address(), U256::from(ONE_ETH * 100))
        .await
        .context("anvil_setBalance(owner)")?;
    let owner_key = meridian_core::dsa::owner_signing_key_from_bytes(OWNER_KEY_BYTES);
    let receipt = client
        .authorize(&owner_key, agent, &limits)
        .expect("authorize");
    // 同一 (owner, agent, nonce=1, limits) 确定性重建 → 同 dh（SDK 内部即同款构造）。
    let sd = create_delegation(&owner_key, agent, receipt.nonce, &limits).expect("delegation");
    assert_eq!(
        meridian_core::dsa::delegation_hash(&sd.delegation),
        receipt.delegation_hash,
        "重建委托必须与 SDK authorize 的委托同 dh"
    );
    dsa_c
        .registerDelegation(
            Bytes::from(meridian_core::dsa::delegation_abi(&sd.delegation)),
            Bytes::from(sd.signature.0),
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(
        dsa_c
            .isRegistered(B256::from(receipt.delegation_hash))
            .call()
            .await?,
        "on-chain sha256(delegationABI) 必须等于 meridian-core delegation_hash"
    );
    println!("OK NOIR-DEMO: 装配面 with_noir + BbVerifier(绑定闸开) + authorize + 链上 DSA 登记（dh 交叉核对一致）");

    // ---- attest_identity（S-46 同源）：凭据承诺与 pay() 证明的 agent_commit 同一 secret ----
    let cred = client.attest_identity().expect("attest_identity");
    println!(
        "OK NOIR-DEMO: attest_identity 同源派生（agent_commit={}…）",
        hex_prefix(&cred.agent_commit)
    );

    // ---- C. 撤销根三方同源：revoke 另一委托 → 绑定闸接受集含真实状态根 ----
    let mut other = [0x3Du8; 32];
    other[31] = 0x07;
    assert!(agg.revoke(other), "撤销另一张委托");
    let witness_root = agg
        .revocation_witness(&receipt.delegation_hash)
        .expect("目标委托未撤销，必有非成员 witness")
        .root;

    // ---- D. 对照组：占位 prover 在 BbVerifier 上必拒（bb 全拒占位证明）----
    let client2 = SdkClient::new(
        AgentWallet::from_seed([0xA5u8; 32]),
        Box::new(InProcessAggregator::from_inner(Arc::clone(&agg))),
    );
    client2
        .authorize(&owner_key, agent, &limits)
        .expect("authorize(placeholder)");
    client2
        .sync_nonce(&receipt.delegation_hash)
        .expect("sync_nonce");
    let negative = client2.pay(&PayParams {
        delegation_hash: receipt.delegation_hash,
        recipient: [0x9Fu8; 20],
        amount: 500,
        category: [0xC0u8; 32],
        memo: None,
        expires_at: limits.expires_at,
    });
    match negative {
        Err(SdkError::Meridian(Error::EProof)) => {}
        other => panic!("占位证明必须被 bb 全拒（E_PROOF），实际 {other:?}"),
    }
    assert_eq!(agg.accepted_count(), 0, "对照组拒绝不记账");
    println!("OK NOIR-DEMO: 对照组——占位证明在 BbVerifier 上 E_PROOF 全拒（正向非占位漏网）");

    // ---- C（续）. pay() × 3：真电路证明 + 绑定闸放行 ----
    let payments = [
        ([0x9Cu8; 20], 4_200u64),
        ([0x9Du8; 20], 1_700),
        ([0x9Eu8; 20], 900),
    ];
    let mut total: u64 = 0;
    for (i, (recipient, amount)) in payments.iter().enumerate() {
        let r = client
            .pay(&PayParams {
                delegation_hash: receipt.delegation_hash,
                recipient: *recipient,
                amount: *amount,
                category: [0xC0u8; 32],
                memo: None,
                expires_at: limits.expires_at,
            })
            .unwrap_or_else(|e| panic!("第 {i} 笔真 ZK 支付必须接受: {e:?}"));
        assert_eq!(r.seq, i as u64, "seq 必须等于提交序");
        total += amount;
    }
    assert_eq!(agg.accepted_count(), N_PAYMENTS as u64);
    assert_eq!(agg.total_spent(&receipt.delegation_hash), Some(total));
    println!("OK NOIR-DEMO: pay() × {N_PAYMENTS} 真电路证明 + 撤销根绑定闸放行（Σ={total}，seq==提交序）");

    // ---- E. 密封 → 撤销根三方同源断言 → 链上净额结算 ----
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let sealed = agg.seal_expired(now, 60);
    assert_eq!(sealed.len(), 1, "满窗即封：恰好一个密封 epoch");
    let res = agg.settle_epoch(&sealed[0]).expect("settle epoch");
    assert_eq!(
        res.revocation_root, witness_root,
        "结算撤销根必须 == 证明所用 witness 根（S-41 同棵 Pedersen 树，三方同源）"
    );
    let sum_net: u128 = res.net.iter().map(|l| l.amount as u128).sum();
    assert_eq!(sum_net, total as u128, "Σnet == Σamounts（净额守恒）");

    settler
        .commit(
            U256::from(res.epoch_id),
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
    settler
        .settle(
            U256::from(res.epoch_id),
            to_net(&res),
            B256::from(res.netting_root),
        )
        .value(U256::from(sum_net))
        .send()
        .await
        .context("settle send")?
        .get_receipt()
        .await
        .context("settle receipt")?;
    fast_forward(&provider).await?;
    for (idx, line) in res.net.iter().enumerate() {
        let addr = alloy::primitives::Address::from_slice(&line.recipient);
        let before = provider.get_balance(addr).await?;
        settler
            .claim(U256::from(res.epoch_id), U256::from(idx as u64))
            .send()
            .await?
            .get_receipt()
            .await?;
        let delta = provider.get_balance(addr).await? - before;
        assert_eq!(
            delta,
            U256::from(line.amount),
            "收款人 {idx} 必须收精确净额"
        );
    }
    let _ = std::fs::remove_file(&wal_path);
    println!(
        "OK NOIR-DEMO: 撤销根三方同源（证明 pi == 账本树 == 链上 commit）+ BatchSettler commit→settle→claim 全绿（{} 收款人，共 {sum_net} wei）",
        res.net.len()
    );
    println!("OK: M1 真 ZK demo 全部通过（with_noir 装配 → 真电路证明 → BbVerifier + 绑定闸 → 链上净额结算）");
    Ok(())
}

/// 打印 agent_commit 前 8 个 hex 字符（demo 输出用）。
fn hex_prefix(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}
