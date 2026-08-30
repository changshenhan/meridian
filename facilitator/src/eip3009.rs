//! EIP-3009 兼容桥（S-32，TECH_SPEC §6.10，docs/x402-adapter.md §4 缺口 3）。
//!
//! 存量 x402 client 只会说标准 `exact` scheme（签 EIP-3009 `transferWithAuthorization`），
//! 不会说 `meridian-v1`。桥 = facilitator 侧把标准 payload **验签后转投 Meridian 摄取**，
//! merchant 侧零感知（验证面仍是"查网关回执"，S-30c 不变）。
//!
//! # 流程（[`Eip3009Bridge::ingest`]）
//!
//! 1. 绑定校验：network / resource / `authorization.to == payTo` / `value ==
//!    maxAmountRequired` / 时间窗（`validAfter <= now < validBefore`）。
//! 2. EIP-712 验签（ecrecover，链下密码学）：恢复地址 == `from`，否则拒。
//! 3. 重放闸：`(from, eip3009 nonce) -> intent_hash`，同 payload 重放不再摄取。S-33 起
//!    可持久化（[`Eip3009Bridge::open`]：append-only 日志 + 启动重建，[`crate::replay`]）。
//! 4. 转投 Meridian 摄取（垫付模型）：facilitator 以自身委托（惰性首用注册）走
//!    [`SdkClient::pay`]——预算 / 速率 / 撤销 / ZK 证明闸口全部保留，桥不旁路任何
//!    协议层检查。
//!
//! # 诚实边界（v1）
//!
//! EIP-3009 的链上执行不在本件（不调 `transferWithAuthorization`）——client 到运营商
//! 的清算是运营商侧账务（`memo` 指纹 + 原始 payload 留档）；被消费的是运营商自己的
//! Meridian 预算（垫付），client 信用风险由白标合同承担，不是协议层担保。重放闸：
//! [`Eip3009Bridge::new`] 仍为进程内存态（v0 兼容）；[`Eip3009Bridge::open`] 启用持久化，
//! 残余边界（落盘失败窗口 / 日志线性增长）见 [`crate::replay`] 与 TECH_SPEC §6.10。
//! EIP-712 domain 由配置显式给出，v1 不做域自动发现。

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::replay::{JournalState, ReplayJournal};
use meridian_sdk::x402::{category_from_resource, X402_VERSION};
use meridian_sdk::{AgentWallet, HttpTransport, PayParams, SdkClient, SdkError};

/// x402 标准 `exact` scheme 名（EIP-3009 载荷）。
pub const EXACT_SCHEME: &str = "exact";

/// EIP-712 domain typehash。
const DOMAIN_TYPEHASH: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
/// EIP-3009 `transferWithAuthorization` 结构体 typehash（USDC v2 同形）。
const TRANSFER_TYPEHASH: &str =
    "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

/// EIP-712 签名域（配置显式给出——USDC on Base：name "USD Coin" / version "2" /
/// chainId 8453 / `0x8335…2913`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip3009Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    /// 20B 资产合约地址。
    pub verifying_contract: [u8; 20],
}

/// 标准 `exact` payload 的 `authorization` 子对象（camelCase wire）。
///
/// `validAfter` / `validBefore` 兼容数字与十进制字符串两种 wire 形态（上游实现不一）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// 付款方 0x 20B 地址（ecrecover 必须恢复到它）。
    pub from: String,
    /// 收款方 0x 20B 地址（必须 == facilitator `payTo`）。
    pub to: String,
    /// 原子单位金额字符串（v1 直通 u64，超上限拒）。
    pub value: String,
    #[serde(deserialize_with = "de_u64_lenient")]
    pub valid_after: u64,
    #[serde(deserialize_with = "de_u64_lenient")]
    pub valid_before: u64,
    /// 0x 32B hex（bytes32，EIP-3009 侧幂等键）。
    pub nonce: String,
}

/// 标准 `exact` payload 的 `payload` 子对象。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactPayload {
    /// 0x 65B hex（r ++ s ++ v；v 宽容 0/1 与 27/28）。
    pub signature: String,
    pub authorization: Authorization,
}

/// 标准 `exact` scheme 的 `X-PAYMENT` 头 JSON（base64url 前）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactPayment {
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
    pub resource: String,
    pub payload: ExactPayload,
}

/// `validAfter` / `validBefore` 的宽容反序列化（数字或十进制字符串）。
fn de_u64_lenient<'de, D>(de: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(de)?;
    match v {
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom(format!("not a u64: {n}"))),
        serde_json::Value::String(s) => s
            .parse::<u64>()
            .map_err(|e| serde::de::Error::custom(format!("bad decimal u64: {e}"))),
        other => Err(serde::de::Error::custom(format!(
            "expected u64, got {other}"
        ))),
    }
}

/// 桥拒绝原因。`gateway_unavailable_sdk()` 决定响应码：503（fail-closed）或 402。
#[derive(Debug)]
pub enum BridgeError {
    /// wire 形态坏（JSON / hex / 金额越界）。
    BadFormat(String),
    /// 绑定不成立（network / resource / to / value / 时间窗）。
    Binding(String),
    /// EIP-712 验签失败（恢复地址 != from / 坏 v）。
    BadSignature(String),
    /// Meridian 摄取失败：业务拒绝（402）或网关不可达（503 fail-closed）。
    Ingest(SdkError),
    /// 重放闸日志落盘失败（S-33）→ 503 fail-closed（运维故障不归罪 client；
    /// 内存表已登记，client 重试命中重放闸不重复摄取）。
    Journal(String),
}

impl BridgeError {
    /// 网关不可达（摄取传输失败）→ 503 fail-closed（验证面不可用绝不放行）。
    pub fn gateway_unavailable_sdk(&self) -> Option<&SdkError> {
        match self {
            BridgeError::Ingest(e @ SdkError::Transport(_)) => Some(e),
            _ => None,
        }
    }

    /// 复用 S-30c 的 402 错误文案口径。
    pub fn message(&self) -> String {
        match self {
            BridgeError::BadFormat(m) => format!("bad exact payload: {m}"),
            BridgeError::Binding(m) => format!("binding mismatch: {m}"),
            BridgeError::BadSignature(m) => format!("EIP-3009 signature invalid: {m}"),
            BridgeError::Ingest(e) => format!("meridian ingest failed: {e}"),
            BridgeError::Journal(m) => format!("replay journal write failed: {m}"),
        }
    }
}

impl From<SdkError> for BridgeError {
    fn from(e: SdkError) -> Self {
        BridgeError::Ingest(e)
    }
}

/// 真 prover 装配参数（S-47，TECH_SPEC §6.10 第 4 步 / §6.14 CLI 消费）。
///
/// 纯数据投影（bin 从环境变量解析）；`NoirProver` 在 `register_operator` 惰性构造
/// （工具链探测 fail fast → `E_PROVER` → 503 fail-closed）。熵（`attestation_secret`）
/// 由调用方供给——SDK 不生成随机熵（§6.14 诚实边界 2）。
#[derive(Debug, Clone)]
pub struct NoirAssembly {
    /// 仓库根（`<root>/gen-witness` + `<root>/circuits`，`NoirProver::from_repo_root`）。
    pub root: std::path::PathBuf,
    /// attestation 私钥标量（LE 32B，值域闸 `< SUBORDER` 在 prove / keygen 入口）。
    pub attestation_secret: [u8; 32],
}

/// 桥配置。
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// 网关地址（运营商垫付 client 用）。
    pub gateway_addr: String,
    /// 网关租户表里的 bearer key。
    pub gateway_bearer: String,
    /// EIP-712 签名域。
    pub domain: Eip3009Domain,
    /// 运营商 agent 传输身份种子（Ed25519）。
    pub agent_seed: [u8; 32],
    /// 运营商 owner 种子（secp256k1，签委托）。
    pub owner_seed: [u8; 32],
    /// 垫付委托限额（预算 / 速率 / 类别白名单照常生效）。
    pub limits: meridian_sdk::DelegationLimits,
    /// 真 prover 装配（S-47）：`None` = 占位 prover（缺省，口径逐字节不变）；
    /// `Some` = `SdkClient::with_noir`（§6.14 同源装配）。与 §6.13
    /// `MERIDIAN_VERIFY_BACKEND` 缺省 `format` 同口径：生产默认不动。
    pub noir: Option<NoirAssembly>,
}

/// 资源绑定参数（facilitator 配置投影，桥校验用）。
#[derive(Debug, Clone)]
pub struct ResourceBinding {
    pub network: String,
    pub resource: String,
    pub pay_to: [u8; 20],
    /// 原子单位单价（`value` 必须等于它）。
    pub amount: u64,
    pub max_timeout_seconds: u64,
}

/// 垫付 client（惰性注册后的运行态）。
struct BridgeClient {
    client: SdkClient,
    delegation_hash: [u8; 32],
}

/// 重放闸键：`(from, eip3009 nonce)`。
type ReplayKey = ([u8; 20], [u8; 32]);

/// EIP-3009 兼容桥。
pub struct Eip3009Bridge {
    cfg: BridgeConfig,
    /// 惰性首用注册的垫付 client（注册失败下次重试）。
    client: Mutex<Option<BridgeClient>>,
    /// 重放闸：键 → intent_hash（进程内权威；`open` 构造时从日志预载）。
    seen: Mutex<HashMap<ReplayKey, [u8; 32]>>,
    /// 持久化日志（S-33；`None` = 进程内存态，v0 兼容）。
    journal: Option<ReplayJournal>,
    /// 启动重建时跳过的坏行数（可观测，不阻断重启）。
    skipped_journal_lines: usize,
}

impl Eip3009Bridge {
    pub fn new(cfg: BridgeConfig) -> Self {
        Eip3009Bridge {
            cfg,
            client: Mutex::new(None),
            seen: Mutex::new(HashMap::new()),
            journal: None,
            skipped_journal_lines: 0,
        }
    }

    /// 持久化构造（S-33，TECH_SPEC §6.10）：打开（不存在则创建）重放闸日志并重放重建
    /// 闸表。坏行跳过并计数（[`Self::skipped_journal_lines`]），不阻断重启；日志打开
    /// 失败（权限 / 磁盘）是启动期配置错误，调用方应立即失败。
    pub fn open(cfg: BridgeConfig, journal_path: &Path) -> std::io::Result<Self> {
        let JournalState {
            entries,
            skipped,
            journal,
        } = ReplayJournal::open(journal_path)?;
        let mut seen = HashMap::with_capacity(entries.len());
        for e in &entries {
            // 后写覆盖先写（与"重放即命中最新 intent_hash"语义一致）。
            seen.insert((e.from, e.nonce), e.intent_hash);
        }
        Ok(Eip3009Bridge {
            cfg,
            client: Mutex::new(None),
            seen: Mutex::new(seen),
            journal: Some(journal),
            skipped_journal_lines: skipped,
        })
    }

    pub fn config(&self) -> &BridgeConfig {
        &self.cfg
    }

    /// 垫付 client prover 模式（S-47 可观测：bin 启动日志用）。
    /// `"noir"` = 真电路 prover（§6.14 同源装配）；`"placeholder"` = 占位（缺省）。
    pub fn prover_mode(&self) -> &'static str {
        match &self.cfg.noir {
            Some(_) => "noir",
            None => "placeholder",
        }
    }

    /// 重放闸登记数（可观测：重放不再摄取）。
    pub fn seen_len(&self) -> usize {
        self.seen.lock().expect("bridge seen poisoned").len()
    }

    /// 启动重建时跳过的坏行数（S-33 可观测：崩溃撕裂 / 损坏行）。
    pub fn skipped_journal_lines(&self) -> usize {
        self.skipped_journal_lines
    }

    /// 重放闸是否启用持久化（S-33）。
    pub fn journal_enabled(&self) -> bool {
        self.journal.is_some()
    }

    /// 完整桥路径：绑定校验 → EIP-712 验签 → 重放闸 → 转投 Meridian 摄取。
    ///
    /// 返回意图哈希（摄取成功或重放命中）——调用方凭它走 S-30c 的网关回执查询。
    pub fn ingest(
        &self,
        payment: &ExactPayment,
        binding: &ResourceBinding,
        now: u64,
    ) -> Result<[u8; 32], BridgeError> {
        // 1. wire 版本与 scheme（调用方按 scheme 分发，这里复核）。
        if payment.x402_version != X402_VERSION {
            return Err(BridgeError::BadFormat(format!(
                "x402Version {} != {}",
                payment.x402_version, X402_VERSION
            )));
        }
        if payment.scheme != EXACT_SCHEME {
            return Err(BridgeError::BadFormat(format!(
                "scheme {:?} != {:?}",
                payment.scheme, EXACT_SCHEME
            )));
        }
        // 2. 绑定校验（fail-fast → 402）。
        if payment.network != binding.network {
            return Err(BridgeError::Binding(format!(
                "network mismatch: {}",
                payment.network
            )));
        }
        if payment.resource != binding.resource {
            return Err(BridgeError::Binding(format!(
                "resource mismatch: {}",
                payment.resource
            )));
        }
        let auth = &payment.payload.authorization;
        let from = parse_addr20(&auth.from).map_err(bad_format("from"))?;
        let to = parse_addr20(&auth.to).map_err(bad_format("to"))?;
        if to != binding.pay_to {
            return Err(BridgeError::Binding("authorization.to != payTo".into()));
        }
        let value: u64 = auth
            .value
            .parse()
            .map_err(|_| BridgeError::BadFormat(format!("bad value {:?}", auth.value)))?;
        if value != binding.amount {
            return Err(BridgeError::Binding("value != maxAmountRequired".into()));
        }
        if !(auth.valid_after <= now && now < auth.valid_before) {
            return Err(BridgeError::Binding(format!(
                "outside validity window [{}, {})",
                auth.valid_after, auth.valid_before
            )));
        }
        // 3. EIP-712 验签（ecrecover，链下密码学）。
        let digest = eip3009_digest(&self.cfg.domain, auth)?;
        let sig65 = parse_sig65(&payment.payload.signature)?;
        let recovered = recover_address(&digest, &sig65)?;
        if recovered != from {
            return Err(BridgeError::BadSignature(
                "recovered address != authorization.from".into(),
            ));
        }
        // 4. 重放闸：同 payload 重放不再摄取。
        let nonce = parse_hex32(&auth.nonce).map_err(bad_format("nonce"))?;
        if let Some(ih) = self
            .seen
            .lock()
            .expect("bridge seen poisoned")
            .get(&(from, nonce))
        {
            return Ok(*ih);
        }
        // 5. 转投 Meridian 摄取（垫付模型；全量 DSA 闸口照常生效）。传输失败经
        //    BridgeError::Ingest(Transport) 上抛 → 调用方 503 fail-closed。
        let memo = eip3009_memo(auth, &sig65);
        let expires_at = auth
            .valid_before
            .min(now.saturating_add(binding.max_timeout_seconds));
        let receipt = self.with_operator(|bc| {
            let params = PayParams {
                delegation_hash: bc.delegation_hash,
                recipient: to,
                amount: value,
                category: category_from_resource(&payment.resource),
                memo: Some(memo),
                expires_at,
            };
            bc.client.pay(&params).map_err(BridgeError::Ingest)
        })?;
        // 6. 重放闸登记：仅 accepted 登记（`?` 已上抛传输失败 / 业务拒绝不定局不登记——
        //    业务拒绝重放会再次摄取并再次被同一闸口拒，不产生净额）。先内存（本进程
        //    重放立即被挡）再落盘（S-33：跨重启去重；落盘失败 → [`BridgeError::Journal`]
        //    → 调用方 503 fail-closed，见模块文档诚实边界）。
        let ih = receipt.intent_hash;
        self.seen
            .lock()
            .expect("bridge seen poisoned")
            .insert((from, nonce), ih);
        if let Some(j) = &self.journal {
            j.append(&from, &nonce, &ih)
                .map_err(|e| BridgeError::Journal(e.to_string()))?;
        }
        Ok(ih)
    }

    /// 惰性垫付 client（首用注册；注册失败不缓存，下次重试）。
    fn with_operator<T>(
        &self,
        f: impl FnOnce(&mut BridgeClient) -> Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        let mut guard = self.client.lock().expect("bridge client poisoned");
        if guard.is_none() {
            *guard = Some(register_operator(&self.cfg).map_err(BridgeError::Ingest)?);
        }
        f(guard.as_mut().expect("operator initialized"))
    }
}

/// 运营商 agent DID：`keccak256(ed25519 agent 公钥)[..20]`（确定性，配置种子可复算）。
pub fn agent_did(agent_seed: &[u8; 32]) -> [u8; 20] {
    let wallet = AgentWallet::from_seed(*agent_seed);
    let pub_bytes = wallet.agent_pub().to_bytes();
    let digest = keccak256(&pub_bytes);
    let mut did = [0u8; 20];
    did.copy_from_slice(&digest[..20]);
    did
}

/// 注册运营商垫付委托（同配置幂等——delegation_hash 由种子 + 限额确定性派生）。
///
/// 注册后必须 [`SdkClient::sync_nonce`]（S-31，§6.6）：桥重启后客户端从 nonce 0 起，
/// 与已消耗集冲突（`E_NONCE` 定局拒）——持久化重放闸（S-33）把"重启"变成受支持场景，
/// nonce 恢复随之接线。首次注册时网关返回 0（无消耗），语义一致。
fn register_operator(cfg: &BridgeConfig) -> Result<BridgeClient, SdkError> {
    let wallet = AgentWallet::from_seed(cfg.agent_seed);
    let transport = HttpTransport::new(&cfg.gateway_addr, &cfg.gateway_bearer);
    // 真 prover 装配（S-47）：`with_noir` 把同一 `NoirProver` 实例装配为 prove 后端
    // 与 attestation keyring（§6.14 同源）；缺省占位（口径逐字节不变）。
    let client = match &cfg.noir {
        Some(a) => {
            // 工具链不可得 = `E_PROVER`（fail-closed，绝不降级回占位证明，§6.14 口径）；
            // 经 `Meridian` 变体透传错误码（永不重试），不吞成 Local 文案。
            let prover = meridian_sdk::prover::NoirProver::from_repo_root(&a.root)
                .map_err(SdkError::Meridian)?;
            SdkClient::with_noir(wallet, Box::new(transport), prover, a.attestation_secret)
        }
        None => SdkClient::new(wallet, Box::new(transport)),
    };
    let owner = SigningKey::from_bytes(&cfg.owner_seed.into())
        .map_err(|e| SdkError::Local(format!("bad operator owner seed: {e}")))?;
    let receipt = client.authorize(&owner, agent_did(&cfg.agent_seed), &cfg.limits)?;
    client.sync_nonce(&receipt.delegation_hash)?;
    Ok(BridgeClient {
        client,
        delegation_hash: receipt.delegation_hash,
    })
}

/// keccak256（sha3 crate，与 EVM 同算法）。
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// 32B word：20B 地址左填充（EIP-712 `abi.encode(address)`）。
fn addr_word(addr: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(addr);
    word
}

/// 32B word：u64 右对齐大端（EIP-712 `abi.encode(uint256)` 的定长子集）。
fn uint_word(v: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&v.to_be_bytes());
    word
}

/// EIP-712 待签摘要：`keccak256(0x1901 || domainSeparator || structHash)`。
///
/// `abi.encode` 全为定长 32B word（无动态类型），手写拼接即可——无 RLP / ABI 依赖。
pub fn eip3009_digest(
    domain: &Eip3009Domain,
    auth: &Authorization,
) -> Result<[u8; 32], BridgeError> {
    let value: u64 = auth
        .value
        .parse()
        .map_err(|_| BridgeError::BadFormat(format!("bad value {:?}", auth.value)))?;
    let mut struct_hash = Vec::with_capacity(32 * 7);
    struct_hash.extend_from_slice(&keccak256(TRANSFER_TYPEHASH.as_bytes()));
    struct_hash.extend_from_slice(&addr_word(
        &parse_addr20(&auth.from).map_err(bad_format("from"))?,
    ));
    struct_hash.extend_from_slice(&addr_word(
        &parse_addr20(&auth.to).map_err(bad_format("to"))?,
    ));
    struct_hash.extend_from_slice(&uint_word(value));
    struct_hash.extend_from_slice(&uint_word(auth.valid_after));
    struct_hash.extend_from_slice(&uint_word(auth.valid_before));
    struct_hash.extend_from_slice(&parse_hex32(&auth.nonce).map_err(bad_format("nonce"))?);
    let struct_hash = keccak256(&struct_hash);

    let mut dom = Vec::with_capacity(32 * 5);
    dom.extend_from_slice(&keccak256(DOMAIN_TYPEHASH.as_bytes()));
    dom.extend_from_slice(&keccak256(domain.name.as_bytes()));
    dom.extend_from_slice(&keccak256(domain.version.as_bytes()));
    dom.extend_from_slice(&uint_word(domain.chain_id));
    dom.extend_from_slice(&addr_word(&domain.verifying_contract));
    let domain_separator = keccak256(&dom);

    let mut pre = Vec::with_capacity(2 + 32 + 32);
    pre.extend_from_slice(b"\x19\x01");
    pre.extend_from_slice(&domain_separator);
    pre.extend_from_slice(&struct_hash);
    Ok(keccak256(&pre))
}

/// ecrecover：65B 签名（r ++ s ++ v，v 宽容 0/1 与 27/28）→ 20B 地址。
pub fn recover_address(digest: &[u8; 32], sig65: &[u8]) -> Result<[u8; 20], BridgeError> {
    let (v, sig_bytes) = sig65
        .split_last()
        .ok_or_else(|| BridgeError::BadFormat("signature must be 65 bytes (r ++ s ++ v)".into()))?;
    if sig_bytes.len() != 64 {
        return Err(BridgeError::BadFormat(format!(
            "signature must be 65 bytes, got {}",
            sig65.len()
        )));
    }
    let sig = Signature::from_slice(sig_bytes)
        .map_err(|e| BridgeError::BadFormat(format!("bad signature: {e}")))?;
    let parity = match v {
        0 | 27 => 0u8,
        1 | 28 => 1u8,
        other => return Err(BridgeError::BadSignature(format!("bad v: {other}"))),
    };
    let recovery_id = RecoveryId::new(parity == 1, false);
    let vk = VerifyingKey::recover_from_prehash(digest, &sig, recovery_id)
        .map_err(|e| BridgeError::BadSignature(format!("ecrecover failed: {e}")))?;
    let point = vk.to_encoded_point(false);
    let raw = point.as_bytes();
    debug_assert_eq!(raw[0], 4);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&keccak256(&raw[1..65])[12..]);
    Ok(addr)
}

/// 对账指纹：`keccak256(from || to || value || validAfter || validBefore || nonce ||
/// signature)`（进 `intent.memo`，运营商侧清算对账用——链上执行不在本件）。
pub fn eip3009_memo(auth: &Authorization, sig65: &[u8]) -> [u8; 32] {
    let value: u64 = auth.value.parse().unwrap_or(0);
    let mut buf = Vec::with_capacity(20 + 20 + 8 + 8 + 8 + 32 + 65);
    let from = parse_addr20(&auth.from).unwrap_or([0u8; 20]);
    let to = parse_addr20(&auth.to).unwrap_or([0u8; 20]);
    let nonce = parse_hex32(&auth.nonce).unwrap_or([0u8; 32]);
    buf.extend_from_slice(&from);
    buf.extend_from_slice(&to);
    buf.extend_from_slice(&value.to_be_bytes());
    buf.extend_from_slice(&auth.valid_after.to_be_bytes());
    buf.extend_from_slice(&auth.valid_before.to_be_bytes());
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(sig65);
    keccak256(&buf)
}

/// 0x 前缀宽容的 20B hex 解析。
pub fn parse_addr20(s: &str) -> Result<[u8; 20], String> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(raw).map_err(|e| format!("bad hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 20 bytes, got {}", v.len()))
}

/// 0x 前缀宽容的 32B hex 解析。
fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(raw).map_err(|e| format!("bad hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))
}

/// 0x 65B 签名解析。
fn parse_sig65(s: &str) -> Result<Vec<u8>, BridgeError> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes =
        hex::decode(raw).map_err(|e| BridgeError::BadFormat(format!("bad signature hex: {e}")))?;
    if bytes.len() != 65 {
        return Err(BridgeError::BadFormat(format!(
            "signature must be 65 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// 字段名绑定的 BadFormat 构造器（校验链里少写样板）。
fn bad_format(field: &'static str) -> impl Fn(String) -> BridgeError {
    move |e| BridgeError::BadFormat(format!("{field}: {e}"))
}

// ---------------------------------------------------------------------------
// 单测（TECH_SPEC §6.10 验收）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    /// 测试签名域（chainId 8453 / USDC 主网地址）。
    fn domain() -> Eip3009Domain {
        Eip3009Domain {
            name: "USD Coin".into(),
            version: "2".into(),
            chain_id: 8453,
            verifying_contract: parse_addr20("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913").unwrap(),
        }
    }

    const TO: &str = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";

    /// 签一笔标准 EIP-3009（keccak 摘要 + k256 可恢复签名）：`authorization.from` 取
    /// 签名 key 派生地址（keccak256(pubkey)[12..32]，与 [`recover_address`] 同式），
    /// 返回 (authorization, 65B 签名, 付款方地址)。
    fn signed_auth(
        domain: &Eip3009Domain,
        to: &str,
        value: &str,
    ) -> (Authorization, Vec<u8>, [u8; 20]) {
        let key = SigningKey::from_bytes(&[7u8; 32].into()).expect("key");
        let point = key.verifying_key().to_encoded_point(false);
        let from_addr: [u8; 20] = keccak256(&point.as_bytes()[1..65])[12..]
            .try_into()
            .expect("20 bytes");
        let auth = Authorization {
            from: format!("0x{}", hex::encode(from_addr)),
            to: to.into(),
            value: value.into(),
            valid_after: 100,
            valid_before: 1_000,
            nonce: format!("0x{}", hex::encode([0x11; 32])),
        };
        let digest = eip3009_digest(domain, &auth).expect("digest");
        let (sig, rid) = key.sign_prehash_recoverable(&digest).expect("sign");
        let mut sig65 = sig.to_bytes().to_vec();
        sig65.push(rid.to_byte());
        (auth, sig65, from_addr)
    }

    #[test]
    fn digest_is_deterministic_and_field_sensitive() {
        let (a, _sig, _addr) = signed_auth(&domain(), TO, "10000");
        assert_eq!(
            eip3009_digest(&domain(), &a).unwrap(),
            eip3009_digest(&domain(), &a).unwrap()
        );
        // 任一字段变化 → 摘要变化（typo 型绑定错误可测）。
        let mut b = a.clone();
        b.value = "10001".into();
        assert_ne!(
            eip3009_digest(&domain(), &a).unwrap(),
            eip3009_digest(&domain(), &b).unwrap()
        );
        let mut c = a.clone();
        c.nonce = format!("0x{}", hex::encode([0x12; 32]));
        assert_ne!(
            eip3009_digest(&domain(), &a).unwrap(),
            eip3009_digest(&domain(), &c).unwrap()
        );
    }

    #[test]
    fn ecrecover_roundtrip_and_v_parity_forms() {
        let d = domain();
        let (a, sig65, addr) = signed_auth(&d, TO, "10000");
        let digest = eip3009_digest(&d, &a).unwrap();
        assert_eq!(recover_address(&digest, &sig65).unwrap(), addr);
        assert_eq!(recover_address(&digest, &sig65).unwrap(), addr);

        // v ∈ {27,28} 与 {0,1} 等价（Ethereum 两种 wire 惯例）。
        let mut alt = sig65.clone();
        let parity = sig65[64];
        alt[64] = if parity == 0 { 27 } else { 28 };
        assert_eq!(recover_address(&digest, &alt).unwrap(), addr);

        // 坏 v 拒绝。
        let mut bad_v = sig65.clone();
        bad_v[64] = 2;
        assert!(matches!(
            recover_address(&digest, &bad_v),
            Err(BridgeError::BadSignature(_))
        ));
        // 长度错拒绝。
        assert!(matches!(
            recover_address(&digest, &sig65[..64]),
            Err(BridgeError::BadFormat(_))
        ));
    }

    #[test]
    fn signature_over_other_domain_recovers_wrong_address() {
        // 换 chainId 签名 → 摘要不同 → 恢复出的地址不是 from（域绑定生效；
        // ecrecover 数学上总能恢复某个点，校验靠"恢复地址 == from"比对）。
        let mut d = domain();
        d.chain_id = 1;
        let (a, sig65, from_addr) = signed_auth(&d, TO, "10000");
        let digest = eip3009_digest(&domain(), &a).unwrap();
        assert_ne!(recover_address(&digest, &sig65).unwrap(), from_addr);
        // 篡改摘要（同为 32B）→ 恢复地址 != from。
        let mut tampered = digest;
        tampered[0] ^= 1;
        assert_ne!(recover_address(&tampered, &sig65).unwrap(), from_addr);
    }

    #[test]
    fn lenient_u64_deserialize_accepts_number_and_string() {
        #[derive(Deserialize)]
        struct T {
            #[serde(deserialize_with = "de_u64_lenient")]
            v: u64,
        }
        assert_eq!(serde_json::from_str::<T>(r#"{"v": 123}"#).unwrap().v, 123);
        assert_eq!(serde_json::from_str::<T>(r#"{"v": "123"}"#).unwrap().v, 123);
        assert!(serde_json::from_str::<T>(r#"{"v": "12x"}"#).is_err());
        assert!(serde_json::from_str::<T>(r#"{"v": -1}"#).is_err());
    }

    #[test]
    fn exact_payment_parses_camel_case_wire() {
        let json = r#"{
            "x402Version": 1,
            "scheme": "exact",
            "network": "base",
            "resource": "https://api.example.com/weather",
            "payload": {
                "signature": "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "authorization": {
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                    "value": "10000",
                    "validAfter": 100,
                    "validBefore": "1000",
                    "nonce": "0x1111111111111111111111111111111111111111111111111111111111111111"
                }
            }
        }"#;
        let p: ExactPayment = serde_json::from_str(json).expect("parse exact payload");
        assert_eq!(p.scheme, "exact");
        assert_eq!(p.payload.authorization.value, "10000");
        assert_eq!(p.payload.authorization.valid_after, 100);
        assert_eq!(p.payload.authorization.valid_before, 1_000);
    }

    #[test]
    fn memo_is_deterministic_and_covers_signature() {
        let (a, sig65, _) = signed_auth(&domain(), TO, "10000");
        assert_eq!(eip3009_memo(&a, &sig65), eip3009_memo(&a, &sig65));
        let mut other = sig65.clone();
        other[0] ^= 1;
        assert_ne!(eip3009_memo(&a, &sig65), eip3009_memo(&a, &other));
    }

    #[test]
    fn agent_did_is_seed_deterministic() {
        assert_eq!(agent_did(&[3u8; 32]), agent_did(&[3u8; 32]));
        assert_ne!(agent_did(&[3u8; 32]), agent_did(&[4u8; 32]));
    }

    #[test]
    fn open_rebuilds_replay_gate_from_journal_and_counts_bad_lines() {
        // S-33：预置日志（1 好行 + 1 坏行）→ open 重建闸表（坏行跳过计数，不阻断）。
        let p = std::env::temp_dir().join(format!(
            "meridian-fac-bridge-open-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&p);
        std::fs::write(
            &p,
            format!(
                r#"{{"from":"0x{}","nonce":"0x{}","intentHash":"0x{}"}}
{{"from":"nothex","nonce":"0x00","intentHash":"0x00"}}"#,
                hex::encode([0xAB; 20]),
                hex::encode([0x42; 32]),
                hex::encode([0x77; 32]),
            ),
        )
        .expect("seed journal");

        // 无参构造：内存态（v0 兼容，无 journal）。
        let mem = Eip3009Bridge::new(bridge_cfg());
        assert!(!mem.journal_enabled());
        assert_eq!(mem.skipped_journal_lines(), 0);

        let b = Eip3009Bridge::open(bridge_cfg(), &p).expect("open");
        assert!(b.journal_enabled());
        assert_eq!(b.seen_len(), 1, "坏行跳过，好行入闸表");
        assert_eq!(b.skipped_journal_lines(), 1);
        let _ = std::fs::remove_file(&p);
    }

    /// 最小桥配置（open / new 构造用；摄取路径不在此测——e2e 覆盖）。
    fn bridge_cfg() -> BridgeConfig {
        BridgeConfig {
            gateway_addr: "127.0.0.1:1".into(),
            gateway_bearer: "unused".into(),
            domain: domain(),
            agent_seed: [0xAA; 32],
            owner_seed: [0xBB; 32],
            limits: meridian_sdk::DelegationLimits {
                max_per_spend: 100_000,
                rate_window_secs: 60,
                rate_max_per_window: 100_000,
                total_cap: 1_000_000,
                categories: vec![],
                not_before: 0,
                expires_at: u64::MAX,
            },
            noir: None,
        }
    }

    /// 缺省口径自检（S-47）：`noir: None` = 占位 prover，装配投影逐字段不变。
    #[test]
    fn default_config_is_placeholder_prover() {
        let cfg = bridge_cfg();
        assert!(cfg.noir.is_none());
        let b = Eip3009Bridge::new(cfg.clone());
        assert_eq!(b.prover_mode(), "placeholder");
        assert!(b.config().noir.is_none());
    }

    /// noir 装配投影（S-47）：`prover_mode` 报 `"noir"`，装配参数原样落位
    /// （真实 prove 链路在门控 e2e——工具链重操作不进默认 cargo test）。
    #[test]
    fn noir_assembly_is_reported_and_carried() {
        let mut cfg = bridge_cfg();
        cfg.noir = Some(NoirAssembly {
            root: std::path::PathBuf::from("/some/repo"),
            attestation_secret: [0x0E; 32],
        });
        let b = Eip3009Bridge::new(cfg.clone());
        assert_eq!(b.prover_mode(), "noir");
        let a = b.config().noir.as_ref().expect("noir assembly");
        assert_eq!(a.root, std::path::PathBuf::from("/some/repo"));
        assert_eq!(a.attestation_secret, [0x0E; 32]);
    }
}
