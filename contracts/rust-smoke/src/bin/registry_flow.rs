//! P2-4 多运营者多实例部署流程演练（TECH_SPEC §6.21.3）——决策 D 全链实证。
//!
//! §6.17 决策 D：债券/押金金额走 OperatorRegistry 的 append-only 调度（旧值永不改写、
//! 新值追加生效、链上全史可审计），新 BatchSettler 实例部署时读取当刻值固化为 immutable，
//! **动态性来自调度 + 重部署，不来自 setter**；运营者名册 = self-registration 绑定实证
//!（调用者必须 = `BatchSettler(settler).operator()` 本尊，链上可独立复核）。
//!
//! 流程（一条 anvil 会话）：
//!   1. 部署合同栈：DSA → RevocationRegistry → OperatorRegistry(registrar = operator)
//!      → appendSchedule v1 → BatchSettler#1（challengeBond ← currentSchedule() 读数）
//!      → registerOperator(settler#1)。
//!   2. 调度换代：appendSchedule v2 → BatchSettler#2（读 v2）→ registerOperator(settler#2)
//!      → 断言 settler#1 的 `challengeBond()` 仍是 v1（实例固化，无 setter 可触）。
//!   3. 名册读面：operatorCount / operators(i) 快照（settler/asset/challengeBond）/
//!      settlerCount / isSettlerListed 与调度历史交叉核对。
//!   4. 负向组（真 revert 回执）：非 registrar 追加 / 零 bond / 零 challengeBond /
//!      非 operator 注册他人实例 / 同一 settler 重复注册 / EOA settler。
//!
//! 依赖：forge build 产物（contracts/out/）+ anvil（foundry）。独立 workspace。

use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolError;
use anyhow::{Context, Result};

use contract_smoke::common::*;

type ScheduleEntry = IOperatorRegistry::ScheduleEntry;
type OperatorEntry = IOperatorRegistry::OperatorEntry;

/// 调度 v1 / v2（v2 为非缺省值，证明「读取当刻值」而非常量穿透）。
const V1_BOND: u128 = 1_000_000_000_000_000_000; // 1 ETH
const V1_CBOND: u128 = 100_000_000_000_000_000; // 0.1 ETH（与 common::CHALLENGE_BOND 同基线）
const V2_BOND: u128 = 2_000_000_000_000_000_000; // 2 ETH
const V2_CBOND: u128 = 370_000_000_000_000_000; // 0.37 ETH（S-50 非缺省用例同款）

#[tokio::main]
async fn main() -> Result<()> {
    let mut anvil = spawn_anvil()?;
    let result = run_flow().await;
    let _ = anvil.kill();
    result
}

async fn run_flow() -> Result<()> {
    // 部署方 = registrar = operator = anvil #0；非 registrar/非 operator = anvil #1。
    let operator: PrivateKeySigner = ANVIL_PKEY0.parse()?;
    let operator_addr = operator.address();
    let provider = ProviderBuilder::new()
        .wallet(operator)
        .connect_http(RPC_URL.parse()?);
    let intruder: PrivateKeySigner = ANVIL_PKEY1.parse()?;
    let intruder_addr = intruder.address();
    let intruder_provider = ProviderBuilder::new()
        .wallet(intruder)
        .connect_http(RPC_URL.parse()?);
    wait_for_chain(&provider).await?;

    let dsa_addr = deploy(&provider, "DSA.sol/DSA.json", &[]).await?;
    let rev_addr = deploy(
        &provider,
        "RevocationRegistry.sol/RevocationRegistry.json",
        &abi_addr(dsa_addr),
    )
    .await?;
    let registry_addr = deploy(
        &provider,
        "OperatorRegistry.sol/OperatorRegistry.json",
        &abi_addr(operator_addr),
    )
    .await?;
    let registry = IOperatorRegistry::new(registry_addr, &provider);
    let registry_intruder = IOperatorRegistry::new(registry_addr, &intruder_provider);
    assert_eq!(
        registry.registrar().call().await?,
        operator_addr,
        "registrar 必须为部署方"
    );
    println!(
        "合同栈部署完成：DSA {dsa_addr} / RevocationRegistry {rev_addr} / OperatorRegistry {registry_addr}"
    );

    // ---- 空调度读数必须 revert（部署流程不该在无调度时部署，§6.21.2）----
    if registry.currentSchedule().call().await.is_ok() {
        anyhow::bail!("空调度读数必须 revert（ScheduleEmpty）");
    }
    println!("  ✅ 负向：空调度 currentSchedule()");

    // ---- 调度 v1 → 实例#1（读取当刻值固化）----
    registry
        .appendSchedule(U256::from(V1_BOND), U256::from(V1_CBOND))
        .send()
        .await
        .context("appendSchedule v1 send")?
        .get_receipt()
        .await?;
    let s1: ScheduleEntry = registry.currentSchedule().call().await?;
    assert_eq!(s1.bond, U256::from(V1_BOND), "v1 bond 读数");
    assert_eq!(
        s1.challengeBond,
        U256::from(V1_CBOND),
        "v1 challengeBond 读数"
    );

    let mut args = abi_addr(operator_addr);
    args.extend_from_slice(&abi_addr(Address::ZERO));
    args.extend_from_slice(&abi_u256(s1.challengeBond.to::<u128>()));
    // P2-3：双锚面构造参数（§6.23.1 定夺 7）。
    args.extend_from_slice(&abi_addr(dsa_addr));
    args.extend_from_slice(&abi_addr(rev_addr));
    let settler1_addr = deploy(&provider, "BatchSettler.sol/BatchSettler.json", &args).await?;
    let settler1 = IBatchSettler::new(settler1_addr, &provider);
    assert_eq!(
        settler1.challengeBond().call().await?,
        U256::from(V1_CBOND),
        "实例#1 固化值必须 = v1 调度读数（部署后回读交叉核对）"
    );
    println!(
        "v1 调度 → BatchSettler#1 {settler1_addr}（challengeBond {} wei）",
        s1.challengeBond
    );

    // ---- 调度换代 v2 → 实例#2 ----
    registry
        .appendSchedule(U256::from(V2_BOND), U256::from(V2_CBOND))
        .send()
        .await
        .context("appendSchedule v2 send")?
        .get_receipt()
        .await?;
    assert_eq!(
        registry.scheduleCount().call().await?,
        U256::from(2),
        "调度全史 2 条"
    );
    let hist = registry.schedule(U256::ZERO).call().await?;
    assert_eq!(
        hist._0,
        U256::from(V1_BOND),
        "旧条目永不改写（append-only）"
    );
    assert_eq!(
        hist._1,
        U256::from(V1_CBOND),
        "旧条目永不改写（append-only）"
    );

    let mut args2 = abi_addr(operator_addr);
    args2.extend_from_slice(&abi_addr(Address::ZERO));
    args2.extend_from_slice(&abi_u256(V2_CBOND));
    args2.extend_from_slice(&abi_addr(dsa_addr));
    args2.extend_from_slice(&abi_addr(rev_addr));
    let settler2_addr = deploy(&provider, "BatchSettler.sol/BatchSettler.json", &args2).await?;
    let settler2 = IBatchSettler::new(settler2_addr, &provider);
    assert_eq!(
        settler2.challengeBond().call().await?,
        U256::from(V2_CBOND),
        "实例#2 固化值必须 = v2 调度读数"
    );
    assert_eq!(
        settler1.challengeBond().call().await?,
        U256::from(V1_CBOND),
        "实例#1 不受 v2 影响——动态性来自调度 + 重部署，不来自 setter"
    );
    println!(
        "v2 调度 → BatchSettler#2 {settler2_addr}（challengeBond {V2_CBOND} wei）；实例#1 仍 {} wei",
        V1_CBOND
    );

    // ---- 名册 self-registration（绑定实证）+ 快照回读 ----
    // 绑定实证负向先打：settler#2 此刻未列入名册、归属 operator = #0 ≠ 入侵者 →
    // 走的是 NotSettlerOperator 而非去重（SettlerAlreadyListed 前置的守卫序实测）。
    expect_revert(
        "非 operator 注册他人实例",
        async {
            registry_intruder
                .registerOperator(settler2_addr)
                .send()
                .await
                .map_err(anyhow::Error::from)?
                .get_receipt()
                .await
                .map_err(anyhow::Error::from)
        },
        Some(IOperatorRegistry::NotSettlerOperator::SELECTOR),
    )
    .await?;

    registry
        .registerOperator(settler1_addr)
        .send()
        .await
        .context("registerOperator #1 send")?
        .get_receipt()
        .await?;
    registry
        .registerOperator(settler2_addr)
        .send()
        .await
        .context("registerOperator #2 send")?
        .get_receipt()
        .await?;
    assert_eq!(registry.operatorCount().call().await?, U256::from(2));
    assert_eq!(
        registry.settlerCount(operator_addr).call().await?,
        U256::from(2)
    );
    let e1: OperatorEntry = registry.operators(U256::ZERO).call().await?;
    let e2: OperatorEntry = registry.operators(U256::ONE).call().await?;
    assert_eq!(e1.operator, operator_addr);
    assert_eq!(e1.settler, settler1_addr);
    assert_eq!(
        e1.challengeBond,
        U256::from(V1_CBOND),
        "快照 = 各实例部署版本"
    );
    assert_eq!(e2.settler, settler2_addr);
    assert_eq!(e2.challengeBond, U256::from(V2_CBOND));
    assert_eq!(e1.asset, Address::ZERO, "S-28 哨兵原样快照（原生 ETH）");
    assert!(registry.isSettlerListed(settler1_addr).call().await?);
    assert!(registry.isSettlerListed(settler2_addr).call().await?);
    println!(
        "名册 2 条：#1 {}（{} wei）/ #2 {}（{} wei）",
        settler1_addr, V1_CBOND, settler2_addr, V2_CBOND
    );

    // ---- 负向组（真 revert：send 期模拟即拒或回执 status 0；押金/状态零变动）----
    // alloy send 前先 gas 估算 → revert 在 send 期冒泡为 Err（anvil 错误体含 custom error
    // 选择器），选择器逐一核对 = 负向命中的是**预期错误**而非任意失败。
    expect_revert(
        "非 registrar 追加调度",
        async {
            registry_intruder
                .appendSchedule(U256::from(V1_BOND), U256::from(V1_CBOND))
                .send()
                .await
                .map_err(anyhow::Error::from)?
                .get_receipt()
                .await
                .map_err(anyhow::Error::from)
        },
        Some(IOperatorRegistry::NotRegistrar::SELECTOR),
    )
    .await?;

    expect_revert(
        "零 bond 追加",
        async {
            registry
                .appendSchedule(U256::ZERO, U256::from(V1_CBOND))
                .send()
                .await
                .map_err(anyhow::Error::from)?
                .get_receipt()
                .await
                .map_err(anyhow::Error::from)
        },
        Some(IOperatorRegistry::ZeroScheduleAmount::SELECTOR),
    )
    .await?;

    expect_revert(
        "零 challengeBond 追加",
        async {
            registry
                .appendSchedule(U256::from(V1_BOND), U256::ZERO)
                .send()
                .await
                .map_err(anyhow::Error::from)?
                .get_receipt()
                .await
                .map_err(anyhow::Error::from)
        },
        Some(IOperatorRegistry::ZeroScheduleAmount::SELECTOR),
    )
    .await?;

    expect_revert(
        "同一 settler 重复注册",
        async {
            registry
                .registerOperator(settler1_addr)
                .send()
                .await
                .map_err(anyhow::Error::from)?
                .get_receipt()
                .await
                .map_err(anyhow::Error::from)
        },
        Some(IOperatorRegistry::SettlerAlreadyListed::SELECTOR),
    )
    .await?;

    expect_revert(
        "EOA settler（无代码，接口调用空 revert）",
        async {
            registry
                .registerOperator(intruder_addr)
                .send()
                .await
                .map_err(anyhow::Error::from)?
                .get_receipt()
                .await
                .map_err(anyhow::Error::from)
        },
        None,
    )
    .await?;

    assert_eq!(
        registry.operatorCount().call().await?,
        U256::from(2),
        "负向组全程零名册变动"
    );
    assert_eq!(
        registry.scheduleCount().call().await?,
        U256::from(2),
        "负向组全程零调度变动"
    );

    println!("\n✅ P2-4 registry_flow 全链演练通过：append-only 调度 ×2 代 → 两实例各持其部署版本 → 名册快照回读一致 → 负向组 6 例全拒。");
    Ok(())
}

/// 负向用例：交易必须 revert（send 期模拟 Err 或回执 status 0），且错误体含预期
/// custom error 选择器（`None` = 空 revert 数据，如 EOA 无代码接口调用气泡）。
async fn expect_revert<F>(name: &str, fut: F, selector: Option<[u8; 4]>) -> Result<()>
where
    F: std::future::Future<Output = anyhow::Result<alloy::rpc::types::TransactionReceipt>>,
{
    let want = selector
        .map(|s| format!("0x{:02x}{:02x}{:02x}{:02x}", s[0], s[1], s[2], s[3]))
        .unwrap_or_default();
    match fut.await {
        Err(e) => {
            let msg = format!("{e:#}");
            anyhow::ensure!(
                selector.is_none() || msg.contains(&want),
                "{name}：revert 选择器不符（期望 {want}）：{msg}"
            );
        }
        Ok(receipt) => anyhow::ensure!(!receipt.status(), "{name}：交易意外成功"),
    }
    println!("  ✅ 负向：{name}");
    Ok(())
}
