//! S-15 生产化部署脚本：DSA / RevocationRegistry / BatchSettler 部署到目标链。
//!
//! 用法：
//!   # 先 forge build（产物在 contracts/out/）：
//!   cd contracts && forge build
//!
//!   # 默认 dry-run：打印部署计划（链/操作者/产物/构造参数/预估 gas），**不上链**。
//!   MERIDIAN_RPC_URL=https://sepolia.base.org \
//!     cargo run --release --manifest-path contracts/rust-smoke/Cargo.toml --bin deploy
//!
//!   # 真实部署（operator 私钥从 env 注入，绝不明文入参；部署方 = 操作者 operator）：
//!   MERIDIAN_RPC_URL=https://sepolia.base.org \
//!   MERIDIAN_OPERATOR_KEY=0x... \
//!     cargo run --release --manifest-path contracts/rust-smoke/Cargo.toml --bin deploy -- --live
//!
//! 目标链通过 RPC 自动识别（chain_id 84532 = Base Sepolia；8453 = Base 主网；1337 = anvil）。
//! 部署顺序（构造参数依赖）：DSA(无参) → RevocationRegistry(DSA 地址) → BatchSettler(操作者+资产)。
//!
//! S-28 结算资产：`MERIDIAN_SETTLEMENT_ASSET`（hex 地址）= ERC-20 结算资产（如 USDC）；
//! 未设置 = 原生 ETH（asset = address(0)，v2 行为）。Base 主网 USDC =
//! 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913；Base Sepolia =
//! 0x036CbD53842c5426634e7929541eC2318f3dCF7e。
//!
//! 诚实边界：本脚本**不**部署债券、不调用任何业务方法——只部署合同栈并打印后续清单
//! （注册操作者、质押等留待运营步骤）；`--live` 前请确认私钥安全与目标链正确。

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};

use contract_smoke::common::{abi_addr, wait_for_chain, IDSA};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// 按 chain_id 给链名 + 区块浏览器（verify 输出用）。
fn chain_meta(chain_id: u64) -> (&'static str, &'static str) {
    match chain_id {
        8453 => ("Base 主网", "https://basescan.org"),
        84532 => ("Base Sepolia", "https://sepolia.basescan.org"),
        31337 | 1337 => ("anvil (本地)", ""),
        _ => ("未知链", ""),
    }
}

/// 读取 forge out/ 产物部署并返回 (地址, 回执)。
async fn deploy_with_receipt<P: Provider>(
    provider: &P,
    artifact_rel: &str,
    constructor_args: &[u8],
    gas_limit: Option<u64>,
) -> Result<(Address, alloy::rpc::types::TransactionReceipt)> {
    let artifact_path = format!("{}/../out/{artifact_rel}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&artifact_path)
        .with_context(|| format!("读产物 {artifact_rel}（先 `cd contracts && forge build`）"))?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let obj = v["bytecode"]["object"].as_str().context("产物缺 bytecode.object")?;
    let mut input = hex::decode(obj.trim_start_matches("0x"))?;
    input.extend_from_slice(constructor_args);

    let mut tx = TransactionRequest::default().with_deploy_code(Bytes::from(input));
    if let Some(g) = gas_limit {
        tx = tx.with_gas_limit(g);
    }
    let pending = Provider::send_transaction(provider, tx).await?;
    let receipt = pending.get_receipt().await?;
    let addr = receipt.contract_address.context("部署失败：无合约地址")?;
    Ok((addr, receipt))
}

/// 通用部署主体（对 Provider 泛型化 → dry-run / live 两种 provider 形态各 monomorphize 一次）。
async fn run<P: Provider>(provider: &P, live: bool, gas_limit: Option<u64>) -> Result<()> {
    wait_for_chain(provider).await?; // 等待 RPC 就绪（anvil 起链 / 目标链握手）
    let chain_id = provider.get_chain_id().await?;
    let (chain_name, explorer) = chain_meta(chain_id);
    let accounts = provider.get_accounts().await?;
    let operator_addr = accounts.first().copied().unwrap_or(Address::ZERO);
    let gas_price = provider.get_gas_price().await?;

    println!("══════════════════════════════════════════════════════════");
    println!("  Meridian 合同栈部署计划");
    println!("  目标链    : {}（chain_id {chain_id}）", chain_name);
    println!("  RPC       : {}", env_or("MERIDIAN_RPC_URL", "http://127.0.0.1:8545"));
    println!("  操作者    : {operator_addr}{}", if accounts.is_empty() { "（dry-run 未带私钥，未知）" } else { "" });
    println!("  gas price : {gas_price}");
    println!("  模式      : {}", if live { "--live（真实上链）" } else { "--dry-run（只打印，不上链）" });
    println!("══════════════════════════════════════════════════════════");

    // 部署顺序（构造参数依赖链）：DSA(无参) → RevocationRegistry(DSA 地址) → BatchSettler(操作者地址)。
    let artifacts = [
        "DSA.sol/DSA.json",
        "RevocationRegistry.sol/RevocationRegistry.json",
        "BatchSettler.sol/BatchSettler.json",
    ];

    if !live {
        for artifact in &artifacts {
            let path = std::path::Path::new("contracts").join("out").join(artifact);
            println!(
                "  [dry-run] 将部署 ← {artifact}{}",
                if path.exists() { "" } else { "  ⚠ 产物缺失，先 `cd contracts && forge build`" }
            );
        }
        println!("\ndry-run 完成：未上链。--live 需 env MERIDIAN_OPERATOR_KEY。");
        return Ok(());
    }

    // ---- 真实部署 ----
    let dsa_addr: Address;
    let mut deployed: Vec<(&str, Address)> = Vec::new();

    let (addr, receipt) = deploy_with_receipt(provider, artifacts[0], &[], gas_limit).await?;
    println!("  ✅ DSA                → {addr}（tx {}，gas {}）", receipt.transaction_hash, receipt.gas_used);
    dsa_addr = addr;
    deployed.push(("DSA", addr));

    let (addr, receipt) = deploy_with_receipt(provider, artifacts[1], &abi_addr(dsa_addr), gas_limit).await?;
    println!("  ✅ RevocationRegistry → {addr}（tx {}，gas {}）", receipt.transaction_hash, receipt.gas_used);
    deployed.push(("RevocationRegistry", addr));

    // S-28：结算资产（MERIDIAN_SETTLEMENT_ASSET，未设 = 原生 ETH）。
    let asset: Address = match std::env::var("MERIDIAN_SETTLEMENT_ASSET") {
        Ok(s) if !s.is_empty() => s.parse().context("MERIDIAN_SETTLEMENT_ASSET 非法地址")?,
        _ => Address::ZERO,
    };

    let mut settler_args = abi_addr(operator_addr);
    settler_args.extend_from_slice(&abi_addr(asset));
    let (addr, receipt) =
        deploy_with_receipt(provider, artifacts[2], &settler_args, gas_limit).await?;
    println!(
        "  ✅ BatchSettler       → {addr}（asset: {}，tx {}，gas {}）",
        if asset == Address::ZERO { "native ETH".into() } else { format!("{asset}") },
        receipt.transaction_hash,
        receipt.gas_used
    );
    deployed.push(("BatchSettler", addr));

    // 事后冒烟：只读调用验证 ABI 对上（不触发任何状态变更）。
    let dsa_c = IDSA::new(dsa_addr, provider);
    let _ = dsa_c.ownerOf(Default::default()).call().await?;

    println!("\n════════ 部署完成 ════════");
    let mut json = serde_json::Map::new();
    json.insert("chain_id".into(), serde_json::json!(chain_id));
    json.insert("operator".into(), serde_json::json!(operator_addr.to_string()));
    for (name, addr) in &deployed {
        json.insert((*name).into(), serde_json::json!(addr.to_string()));
    }
    println!("{}", serde_json::to_string_pretty(&json)?);

    if !explorer.is_empty() {
        println!("\n验证（verify）链接（{chain_name}）：");
        for (name, addr) in &deployed {
            println!("  {name:<20} {explorer}/address/{addr}");
        }
    }
    println!("\n后续运营步骤（非部署脚本职责）：操作者注册 / 债券质押 / 监控接线——见 docs/ops.md。");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let live = args.iter().any(|a| a == "--live");
    let gas_limit = args
        .iter()
        .position(|a| a == "--gas-limit")
        .and_then(|p| args.get(p + 1))
        .and_then(|v| v.parse::<u64>().ok());

    let rpc = env_or("MERIDIAN_RPC_URL", "http://127.0.0.1:8545");

    if live {
        let key = std::env::var("MERIDIAN_OPERATOR_KEY")
            .context("--live 需要 env MERIDIAN_OPERATOR_KEY（部署方 = 操作者 operator 私钥）")?;
        let signer: PrivateKeySigner = key.parse().context("MERIDIAN_OPERATOR_KEY 解析失败")?;
        let provider = ProviderBuilder::new().wallet(signer).connect_http(rpc.parse()?);
        run(&provider, true, gas_limit).await
    } else {
        let provider = ProviderBuilder::new().connect_http(rpc.parse()?);
        run(&provider, false, gas_limit).await
    }
}
