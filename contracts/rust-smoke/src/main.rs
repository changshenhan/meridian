//! contract-smoke —— S-06c 链上集成冒烟。
//!
//! 流程：spawn anvil → 部署 DSA / RevocationRegistry / BatchSettler（forge out/ 产物）→
//! 用 meridian-core 构造 Delegation + delegation_abi + owner 低位 s 签名 → 注册 →
//! 断言链上 `isRegistered(meridian-core 的 delegation_hash)` == true（交叉实现契约：
//! Solidity `sha256(delegationABI)` 必须与 Rust `delegation_hash` 一致）→ 撤销 →
//! commit → settle。链上地址（owner）由核心私钥推导，与 alloy 钱包派生交叉核对。
//!
//! 独立 workspace；由 CI `solidity` job 驱动（forge build 产物就位后运行）。
//! TEMPORARY：S-08 前并入正式部署脚本，不进 SPEC 主流程（详见 contracts/README.md）。

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy::network::TransactionBuilder;
use alloy::primitives::{keccak256, Address, B256, Bytes, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolValue;
use anyhow::{Context, Result};

use meridian_core::dsa::{self, Delegation, RateLimit};

sol! {
    #[sol(rpc)]
    interface IDSA {
        event DelegationRegistered(bytes32 indexed delegationHash, address indexed owner);
        function registerDelegation(bytes calldata delegationABI, bytes calldata ownerSig) external;
        function ownerOf(bytes32 delegationHash) external view returns (address);
        function isRegistered(bytes32 delegationHash) external view returns (bool);
    }

    #[sol(rpc)]
    interface IRevocationRegistry {
        event Revoked(bytes32 indexed delegationHash, address indexed by);
        function revoke(bytes32 delegationHash) external;
        function isRevoked(bytes32 delegationHash) external view returns (bool);
    }

    #[sol(rpc)]
    interface IBatchSettler {
        struct NetInstruction {
            address recipient;
            uint256 amount;
        }
        event Commit(uint256 indexed epochId, bytes32 commitmentRoot, uint64 bondedAmount);
        event Settled(uint256 indexed epochId, bytes32 nettingRoot, uint64 netCount);
        function commit(uint256 epochId, bytes32 commitmentRoot) external payable;
        function settle(uint256 epochId, NetInstruction[] calldata net, bytes32 nettingRoot) external;
    }
}

const RPC_URL: &str = "http://127.0.0.1:8545";
/// anvil 默认账户 #0 私钥（部署方）。
const ANVIL_PKEY0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// core/合约测试共用的 owner 私钥字节（与 dsa.rs 测试同一把钥匙）。
const OWNER_KEY_BYTES: [u8; 32] = [7u8; 32];
const ONE_ETH: u128 = 1_000_000_000_000_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. spawn anvil（固定端口 8545；CI 无冲突）。
    let mut anvil = spawn_anvil()?;
    let result = run_smoke().await;
    let _ = anvil.kill();
    result
}

async fn run_smoke() -> Result<()> {
    // 2. provider：部署方 = anvil #0；owner = 固定私钥。
    let deployer: PrivateKeySigner = ANVIL_PKEY0.parse()?;
    let deployer_addr = deployer.address();
    // alloy 2.x：recommended fillers（nonce/gas/chainId）默认开启；connect_http 取 Url 且不返回 Result。
    let provider = ProviderBuilder::new()
        .wallet(deployer)
        .connect_http(RPC_URL.parse()?);
    wait_for_chain(&provider).await?;

    // owner 侧 provider（revoke 必须由 owner 发起）。
    let owner_signer = PrivateKeySigner::from_bytes(&B256::from(OWNER_KEY_BYTES))?;
    let owner_provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(RPC_URL.parse()?);
    // anvil 只预置 mnemonic 前 10 个账户（#0-#9）；owner 是自定义私钥，余额为 0。
    // 用 anvil_setBalance 给 owner 注资，否则 revoke（owner 发起）会 -32003 Insufficient funds。
    provider
        .anvil_set_balance(owner_signer.address(), U256::from(ONE_ETH * 100))
        .await
        .context("anvil_setBalance(owner)")?;

    // 3. 部署三合约。
    let dsa_addr = deploy(&provider, "DSA.sol/DSA.json", &[]).await?;
    let reg_addr = deploy(&provider, "RevocationRegistry.sol/RevocationRegistry.json", &abi_addr(dsa_addr)).await?;
    let settler_addr = deploy(&provider, "BatchSettler.sol/BatchSettler.json", &[]).await?;

    // 4. 用 core 构造委托：owner DID 从核心私钥推导，先与 alloy 派生交叉核对。
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

    let delegation = Delegation {
        agent: [0x01u8; 20],
        owner: owner_did,
        nonce: 1,
        max_per_spend: 1_000,
        rate: RateLimit { window_secs: 60, max_per_window: 10_000 },
        total_cap: 100_000,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
        version: dsa::PROTOCOL_VERSION,
    };
    let abi = dsa::delegation_abi(&delegation);
    let dh = dsa::delegation_hash(&delegation);
    let sd = dsa::sign_delegation(&delegation, &owner_key);

    // 5. 注册 + 交叉实现契约断言。
    let dsa_c = IDSA::new(dsa_addr, &provider);
    dsa_c.registerDelegation(Bytes::from(abi.clone()), Bytes::from(sd.signature.0))
        .send()
        .await?
        .get_receipt()
        .await?;
    // alloy 2.x：单返回值 `.call()` 直接返回该值（非元组）。
    let registered: bool = dsa_c.isRegistered(B256::from(dh)).call().await?;
    assert!(registered, "on-chain sha256(delegationABI) 必须等于 meridian-core delegation_hash");
    let onchain_owner: Address = dsa_c.ownerOf(B256::from(dh)).call().await?;
    assert_eq!(onchain_owner, Address::from_slice(&owner_did), "ownerOf 必须等于 owner");

    // 6. 撤销（owner 发起）+ 断言。
    let reg_c = IRevocationRegistry::new(reg_addr, &owner_provider);
    reg_c.revoke(B256::from(dh)).send().await?.get_receipt().await?;
    let revoked: bool = reg_c.isRevoked(B256::from(dh)).call().await?;
    assert!(revoked, "撤销后 must be revoked");

    // 7. commit + settle。
    let settler = IBatchSettler::new(settler_addr, &provider);
    let epoch = U256::from(1u64);
    let root = B256::from(keccak256(b"epoch-1"));
    settler
        .commit(epoch, root)
        .from(deployer_addr)
        .value(U256::from(ONE_ETH))
        .send()
        .await
        .context("commit send")?
        .get_receipt()
        .await
        .context("commit get_receipt")?;

    let net = vec![
        IBatchSettler::NetInstruction { recipient: Address::from_slice(&[0xA1; 20]), amount: U256::from(100u64) },
        IBatchSettler::NetInstruction { recipient: Address::from_slice(&[0xA2; 20]), amount: U256::from(200u64) },
    ];
    let netting_root = keccak256(net.abi_encode());
    settler.settle(epoch, net, netting_root).send().await?.get_receipt().await?;

    println!("OK: register→revoke→commit→settle 全链路通过（dh={dh:?}）");
    Ok(())
}

/// spawn anvil（stdout/stderr 丢弃；错误即失败）。
fn spawn_anvil() -> Result<Child> {
    Ok(Command::new("anvil")
        .arg("--port")
        .arg("8545")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn anvil（请确认 foundryup 已安装且 PATH 可达）")?)
}

/// 等待 anvil RPC 就绪（最多 10s）。
async fn wait_for_chain(provider: &impl Provider) -> Result<()> {
    for _ in 0..50 {
        if provider.get_block_number().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    anyhow::bail!("anvil RPC 10s 内未就绪")
}

/// 读取 forge out/ 产物创建字节码并部署；返回合约地址。
async fn deploy(provider: &impl Provider, artifact_rel: &str, constructor_args: &[u8]) -> Result<Address> {
    let artifact_path = format!("{}/../out/{artifact_rel}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&artifact_path)
        .with_context(|| format!("read artifact {artifact_path}（先跑 forge build）"))?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let obj = v["bytecode"]["object"].as_str().context("artifact 缺 bytecode.object")?;
    let mut input = hex::decode(obj.trim_start_matches("0x"))?;
    input.extend_from_slice(constructor_args);

    let tx = TransactionRequest::default().with_deploy_code(Bytes::from(input));
    let pending = Provider::send_transaction(provider, tx).await?;
    let receipt = pending.get_receipt().await?;
    receipt.contract_address.context("部署失败：无合约地址")
}

/// abi.encode(address)（构造参数，32 字节右对齐）。
fn abi_addr(a: Address) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[12..].copy_from_slice(a.as_slice());
    out
}
