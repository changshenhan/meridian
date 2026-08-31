//! rust-smoke 共享件：anvil 部署 / 链上助手 / sol! 绑定 / 意图信封构造。
//! 供 `main.rs`（S-11d 三场景）与 `bin/m1_demo.rs`（S-14 M1 端到端）复用。

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::sol;
use anyhow::{Context, Result};

use mist_aggregator::lattice::EpochResult;
use mist_aggregator::receipt::IntentEnvelope;
use mist_core::dsa::{self, AgentSigningKey, SpendIntent};
use mist_core::zk::{SpendProof, SpendPublicInputs};

sol! {
    #[sol(rpc)]
    interface IDSA {
        event DelegationRegistered(bytes32 indexed delegationHash, address indexed owner);
        /// P2-3（TECH_SPEC §6.19/§6.23）：运营者绑定面（kind4 锚）——一次性写 + 事件。
        event OperatorBound(bytes32 indexed delegationHash, address indexed operator);
        function registerDelegation(bytes calldata delegationABI, bytes calldata ownerSig) external;
        function ownerOf(bytes32 delegationHash) external view returns (address);
        function isRegistered(bytes32 delegationHash) external view returns (bool);
        function bindOperator(bytes32 delegationHash, address operator) external;
        function boundAt(bytes32 delegationHash) external view returns (uint64);
        function operatorOf(bytes32 delegationHash) external view returns (address);
    }

    #[sol(rpc)]
    interface IRevocationRegistry {
        event Revoked(bytes32 indexed delegationHash, address indexed by);
        function revoke(bytes32 delegationHash) external;
        function isRevoked(bytes32 delegationHash) external view returns (bool);
        /// P2-3：kind3 守卫的撤销时刻锚（0 = 未撤销）。
        function revokedAt(bytes32 delegationHash) external view returns (uint64);
    }

    /// S-64（TECH_SPEC §6.21）：P2-4 OperatorRegistry —— append-only 金额调度 + 运营者
    /// 名册。写面：appendSchedule（仅 registrar）/ registerOperator（绑定实证）。
    #[sol(rpc)]
    interface IOperatorRegistry {
        struct ScheduleEntry {
            uint256 bond;
            uint256 challengeBond;
            uint64 writtenAt;
        }
        struct OperatorEntry {
            address operator;
            address settler;
            address asset;
            uint256 challengeBond;
            uint64 registeredAt;
        }
        event ScheduleAppended(uint256 indexed index, uint256 bond, uint256 challengeBond);
        event OperatorRegistered(address indexed operator, address indexed settler, uint256 challengeBond);
        error ZeroRegistrar();
        error NotRegistrar();
        error ZeroScheduleAmount();
        error ScheduleEmpty();
        error SettlerAlreadyListed(address settler);
        error NotSettlerOperator(address settler, address expected, address actual);
        function appendSchedule(uint256 bond, uint256 challengeBond) external;
        function registerOperator(address settler) external;
        function currentSchedule() external view returns (ScheduleEntry memory);
        function schedule(uint256 index) external view returns (uint256, uint256, uint64);
        function scheduleCount() external view returns (uint256);
        function operatorCount() external view returns (uint256);
        function operators(uint256 index) external view returns (OperatorEntry memory);
        function isSettlerListed(address settler) external view returns (bool);
        function settlerCount(address operator) external view returns (uint256);
        function registrar() external view returns (address);
    }

    #[sol(rpc)]
    interface IBatchSettler {
        struct NetInstruction {
            address recipient;
            uint256 amount;
        }
        struct IntentProof {
            bytes20 agent;
            bytes32 delegationHash;
            bytes20 recipient;
            uint64 amount;
            bytes32 category;
            uint64 spendNonce;
            bytes memo;
            uint64 expiresAt;
            /// P2-3 接受时刻锚（§6.23）：kind3/4 时间守卫输入（kind1/2 随证据携带但合约不校验）。
            uint64 acceptedAt;
            uint64 seq;
            uint256 leafIndex;
            uint256 acceptedCount;
            bytes32[] siblings;
            /// P2-3 平行接受树兄弟路径（与承诺路径同叶序同深度，§6.23.1 定夺 6）。
            bytes32[] acceptanceSiblings;
        }
        struct FraudProof {
            uint8 kind;
            uint256 targetNetIndex;
            IntentProof[] intents;
        }
        event Commit(uint256 indexed epochId, bytes32 commitmentRoot, bytes32 revocationRoot, bytes32 acceptanceRoot, uint64 sealedAt, uint256 bondedAmount);
        event Settled(uint256 indexed epochId, bytes32 nettingRoot, uint64 netCount);
        event ChallengeSucceeded(uint256 indexed epochId, address indexed challenger, uint8 kind);
        /// P2-3：证明自洽但守卫判不成立（NotFraud 等）→ 驳回 + 押金销毁、epoch 不动。
        event ChallengeRejected(uint256 indexed epochId, address indexed challenger, uint8 reason);
        event Claimed(uint256 indexed epochId, address indexed recipient, uint256 amount);
        /// P2-1 验证者读取面（TECH_SPEC §6.18.2）：自动 getter 对 struct 内数组成员整体
        /// 省略（实测 ABI outputs 无 net[]）。S-66 读面拆分：Epoch 13 字段后，13 元组单
        /// getter 在 legacy codegen（forge coverage 关优化编译）超出栈上限不可编译（13
        /// 个隐式返回槽恒活跃，最小 13 元组函数同爆，与函数体无关）→ 拆为 `epochs()`
        /// （9 静态字段）+ `epochStatus()`（4 状态位）；验证者经 [`epoch_snapshot`]
        /// （本文件）合并读取，下游消费面零迁移。
        struct EpochView {
            bytes32 commitmentRoot;
            bytes32 revocationRoot;
            bytes32 acceptanceRoot;
            uint64 sealedAt;
            uint64 committedAt;
            uint256 bondedAmount;
            uint256 settlementFunded;
            uint64 settledAt;
            bytes32 nettingRoot;
        }
        struct EpochStatus {
            bool committed;
            bool settled;
            bool challenged;
            bool voided;
        }
        function commit(uint256 epochId, bytes32 commitmentRoot, bytes32 revocationRoot, bytes32 acceptanceRoot, uint64 sealedAt) external payable;
        function settle(uint256 epochId, NetInstruction[] calldata net, bytes32 nettingRoot) external payable;
        function claim(uint256 epochId, uint256 netIndex) external;
        function challenge(uint256 epochId, FraudProof calldata fp) external payable;
        function challengeBond() external view returns (uint256);
        function operator() external view returns (address);
        function epochs(uint256 epochId) external view returns (EpochView memory);
        function epochStatus(uint256 epochId) external view returns (EpochStatus memory);
    }
}

/// 验证者合并快照（拆分前 EpochView 全 13 字段同构：字段名/类型逐一保持，下游
/// `view.xxx` 消费面零迁移）。
#[derive(Debug, Clone)]
pub struct EpochSnapshot {
    pub commitment_root: B256,
    pub revocation_root: B256,
    pub acceptance_root: B256,
    pub sealed_at: u64,
    pub committed_at: u64,
    pub bonded_amount: U256,
    pub settlement_funded: U256,
    pub settled_at: u64,
    pub netting_root: B256,
    pub committed: bool,
    pub settled: bool,
    pub challenged: bool,
    pub voided: bool,
}

/// 验证者读面合并（S-66 拆分后的两次读合成）：`epochs()` + `epochStatus()`。
pub async fn epoch_snapshot<P: Provider>(
    settler: &IBatchSettler::IBatchSettlerInstance<&P>,
    epoch_id: u64,
) -> Result<EpochSnapshot> {
    let id = U256::from(epoch_id);
    let v = settler.epochs(id).call().await?;
    let s = settler.epochStatus(id).call().await?;
    Ok(EpochSnapshot {
        commitment_root: v.commitmentRoot,
        revocation_root: v.revocationRoot,
        acceptance_root: v.acceptanceRoot,
        sealed_at: v.sealedAt,
        committed_at: v.committedAt,
        bonded_amount: v.bondedAmount,
        settlement_funded: v.settlementFunded,
        settled_at: v.settledAt,
        netting_root: v.nettingRoot,
        committed: s.committed,
        settled: s.settled,
        challenged: s.challenged,
        voided: s.voided,
    })
}

pub const RPC_URL: &str = "http://127.0.0.1:8545";
/// anvil 默认账户 #0 私钥（部署方 = 运营者 operator）。
pub const ANVIL_PKEY0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// anvil 默认账户 #1 私钥（挑战者 challenger）。
pub const ANVIL_PKEY1: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
/// core/合约测试共用的 owner 私钥字节（与 dsa.rs 测试同一把钥匙）。
pub const OWNER_KEY_BYTES: [u8; 32] = [7u8; 32];
pub const ONE_ETH: u128 = 1_000_000_000_000_000_000;
/// commit 债券（msg.value）。
pub const BOND: u128 = ONE_ETH;
/// S-38/S-50 挑战押金：S-50 起为 BatchSettler 部署期构造参数（immutable）——本冒烟
/// 部署按此值传入构造器，部署后回读 `challengeBond()` 交叉核对（单一事实源在链上）。
pub const CHALLENGE_BOND: u128 = ONE_ETH / 10;
/// 与 BatchSettler 的 `CHALLENGE_WINDOW`（6h）一致。
pub const CHALLENGE_WINDOW_SECS: u64 = 6 * 3600;
pub const AGENT_KEY_BYTES: [u8; 32] = [5u8; 32];

/// EpochResult.net → BatchSettler.NetInstruction[]。
pub fn to_net(res: &EpochResult) -> Vec<IBatchSettler::NetInstruction> {
    res.net
        .iter()
        .map(|l| IBatchSettler::NetInstruction {
            recipient: Address::from_slice(&l.recipient),
            amount: U256::from(l.amount),
        })
        .collect()
}

/// 意图信封：FormatVerifier（S-09 缝）只要求 proof 非空 + 公共输入与信封一致。
/// 真 S-09 UltraPlonk prover 插 `SpendVerifier` 同缝，信封形态不变。
pub fn make_env(
    dh: [u8; 32],
    agent: [u8; 20],
    agent_key: &AgentSigningKey,
    recipient: [u8; 20],
    amount: u64,
    nonce: u64,
    now: u64,
) -> IntentEnvelope {
    let intent = SpendIntent {
        agent,
        delegation_hash: dh,
        recipient,
        amount,
        category: [0u8; 32],
        spend_nonce: nonce,
        memo: None,
        expires_at: now + 60,
    };
    let agent_sig = dsa::sign_intent(&intent, agent_key);
    let proof = SpendProof {
        proof: vec![1, 2, 3],
        public_inputs: SpendPublicInputs {
            agent_commit: [0u8; 32],
            delegation_hash: dh,
            recipient,
            amount,
            category: [0u8; 32],
            spend_nonce: nonce,
            expires_at: intent.expires_at,
            revocation_root: [0u8; 32],
            now,
        },
    };
    IntentEnvelope {
        intent,
        agent_sig,
        proof,
    }
}

/// spawn anvil（stdout/stderr 丢弃；错误即失败）。
pub fn spawn_anvil() -> Result<Child> {
    Command::new("anvil")
        .arg("--port")
        .arg("8545")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn anvil（请确认 foundryup 已安装且 PATH 可达）")
}

/// 等待 anvil RPC 就绪（最多 10s）。
pub async fn wait_for_chain(provider: &impl Provider) -> Result<()> {
    for _ in 0..50 {
        if provider.get_block_number().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    anyhow::bail!("anvil RPC 10s 内未就绪")
}

/// 快进链上时间到挑战窗口之后。
pub async fn fast_forward(provider: &impl Provider) -> Result<()> {
    provider
        .anvil_increase_time(CHALLENGE_WINDOW_SECS + 1)
        .await?;
    provider.anvil_mine(Some(1), None).await?;
    Ok(())
}

/// 读取 forge out/ 产物创建字节码并部署；返回合约地址。
pub async fn deploy(
    provider: &impl Provider,
    artifact_rel: &str,
    constructor_args: &[u8],
) -> Result<Address> {
    let artifact_path = format!("{}/../out/{artifact_rel}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&artifact_path)
        .with_context(|| format!("read artifact {artifact_path}（先跑 forge build）"))?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let obj = v["bytecode"]["object"]
        .as_str()
        .context("artifact 缺 bytecode.object")?;
    let mut input = hex::decode(obj.trim_start_matches("0x"))?;
    input.extend_from_slice(constructor_args);

    let tx = TransactionRequest::default().with_deploy_code(Bytes::from(input));
    let pending = Provider::send_transaction(provider, tx).await?;
    let receipt = pending.get_receipt().await?;
    receipt.contract_address.context("部署失败：无合约地址")
}

/// abi.encode(address)（构造参数，32 字节右对齐）。
pub fn abi_addr(a: Address) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[12..].copy_from_slice(a.as_slice());
    out
}

/// abi.encode(uint256)（S-50 挑战押金构造参数，32 字节右对齐）。
pub fn abi_u256(v: u128) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}
