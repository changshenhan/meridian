//! S-13 MCP 工具定义：`authorize` / `pay` / `balance` / `attest` / `verify_receipt` /
//! `revocation_witness`（S-52）。
//!
//! 入参用**扁平 hex 字符串**而非嵌套 core 类型：`#[tool]` 宏需要入参类型实现
//! `JsonSchema`（rmcp 用 schemars 生成工具 JSON Schema），而 core 的 `Delegation`
//! /`SpendIntent` 只派生 serde、不派生 schemars。hex 字符串对 agent 框架最友好，
//! 也与 core 的 `Signature64` serde（hex 字符串）一致。
//!
//! 工具返回 `Result<String, String>`：Ok = 回执 JSON；Err = `{"error":"E_..."}`，
//! rmcp 会把 Err 分支标成 `is_error=true`（MCP 客户端/agent 可见真失败）。

use ed25519_dalek::Signature as AgentSignature;
use mist_core::attestation::AttestationPubKey;
use mist_core::dsa::{AgentPubKey, Delegation, OwnerPubKey, RateLimit, Signature64, SpendIntent};
use mist_core::zk::{SpendProof, SpendPublicInputs};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::ServerHandler;
use rmcp::{tool, tool_handler, tool_router};

use crate::MistServer;

/// hex 解码为定长数组（agent/owner DID 20B、hash 32B、签名 64B、SEC1 33B）。
fn decode<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    let raw = hex::decode(s).map_err(|e| format!("{what}: invalid hex: {e}"))?;
    let len = raw.len();
    // `&[u8] -> [u8; N]`（TryFrom<&[T]> for [T; N] 做拷贝），显式标注避免歧义。
    let arr: [u8; N] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("{what}: expected {N} bytes, got {len}"))?;
    Ok(arr)
}

/// 工具级错误体：agent 侧解析得到错误码。
fn err_body(code: &str) -> String {
    serde_json::json!({ "ok": false, "error": code }).to_string()
}

fn ok_body<T: serde::Serialize>(receipt: &T) -> String {
    serde_json::to_string(receipt).expect("receipt serializes")
}

/// `mist.authorize` 入参。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AuthorizeRequest {
    /// agent DID（20 字节 hex）。
    pub agent: String,
    /// owner DID（20 字节 hex）。
    pub owner: String,
    /// 委托序号（防重放）。
    pub nonce: u64,
    /// 单笔上限（USDC 基础单位，1e-6）。
    pub max_per_spend: u64,
    /// 窗口长度（秒）。
    pub rate_window_secs: u64,
    /// 窗口内速率上限。
    pub rate_max_per_window: u64,
    /// 累计总额上限。
    pub total_cap: u64,
    /// 允许的消费类别（32 字节 hex 列表；空 = 全类别）。
    pub categories: Vec<String>,
    /// 生效时间（unix 秒）。
    pub not_before: u64,
    /// 过期时间（unix 秒）。
    pub expires_at: u64,
    /// 协议版本。
    pub version: u8,
    /// owner 对 delegation 的 secp256k1 签名（r||s，64 字节 hex，低位 s）。
    pub owner_signature: String,
    /// owner 公钥（SEC1：33 字节压缩 或 65 字节未压缩，hex）。
    pub owner_pubkey: String,
    /// agent 传输身份公钥（Ed25519，32 字节 hex）。
    pub agent_pubkey: String,
}

impl AuthorizeRequest {
    fn into_parts(self) -> Result<(Delegation, Signature64, OwnerPubKey, AgentPubKey), String> {
        let delegation = Delegation {
            agent: decode::<20>(&self.agent, "agent")?,
            owner: decode::<20>(&self.owner, "owner")?,
            nonce: self.nonce,
            max_per_spend: self.max_per_spend,
            rate: RateLimit {
                window_secs: self.rate_window_secs,
                max_per_window: self.rate_max_per_window,
            },
            total_cap: self.total_cap,
            categories: self
                .categories
                .iter()
                .map(|c| decode::<32>(c, "categories"))
                .collect::<Result<Vec<_>, _>>()?,
            not_before: self.not_before,
            expires_at: self.expires_at,
            version: self.version,
        };
        let signature = Signature64(decode::<64>(&self.owner_signature, "owner_signature")?);
        let owner_pub_raw = decode::<65>(&self.owner_pubkey, "owner_pubkey");
        // 兼容 33B 压缩与 65B 未压缩；先按 65 试，再按 33 试。
        let owner_pub_bytes: Vec<u8> = match owner_pub_raw {
            Ok(b) => b.to_vec(),
            Err(_) => decode::<33>(&self.owner_pubkey, "owner_pubkey")?.to_vec(),
        };
        let owner_pub = OwnerPubKey::from_sec1_bytes(&owner_pub_bytes)
            .map_err(|e| format!("owner_pubkey: invalid SEC1 point: {e}"))?;
        let agent_pub = AgentPubKey::from_bytes(&decode::<32>(&self.agent_pubkey, "agent_pubkey")?)
            .map_err(|e| format!("agent_pubkey: invalid ed25519 point: {e}"))?;
        Ok((delegation, signature, owner_pub, agent_pub))
    }
}

/// `mist.pay` 可选的客户端直通证明（S-52，TECH_SPEC §6.16）。
///
/// keyless 保形（D3）：`attestation_secret` 不上服务器，真证明由框架侧客户端产出
/// （`NoirProver`，§6.14），作为**数据**随意图一起提交，服务器只验证。公共输入的共享
/// 字段（delegation_hash / recipient / amount / category / spend_nonce / expires_at）
/// 不在此上报——服务器从意图派生，`check_public_inputs_consistent` 保证派生结果与证明
/// 声称的是同一笔意图；客户端只报服务器无法自知的三个自由量 + 证明字节本体。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct ProofRequest {
    /// 电路证明字节（bb UltraHonk，hex）。
    pub proof_hex: String,
    /// attestation 承诺 `agent_commit`（32 字节 hex，客户端 attestation 身份）。
    pub agent_commit: String,
    /// 客户端所锚定的撤销状态根（32 字节 hex；bb + 撤销根绑定闸下必须 ∈ 聚合器接受集）。
    pub revocation_root: String,
    /// 证明时刻（unix 秒；电路断言 5 时间窗）。
    pub now: u64,
}

/// `mist.pay` 入参。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct PayRequest {
    /// agent DID（20 字节 hex）。
    pub agent: String,
    /// 目标委托的 delegation_hash（32 字节 hex）。
    pub delegation_hash: String,
    /// 收款方 DID（20 字节 hex）。
    pub recipient: String,
    /// 金额（USDC 基础单位）。
    pub amount: u64,
    /// 消费类别（32 字节 hex）。
    pub category: String,
    /// 花费序号（防重放，递增）。
    pub spend_nonce: u64,
    /// 备注（32 字节 hex；可缺省）。
    pub memo: Option<String>,
    /// 意图过期时间（unix 秒）。
    pub expires_at: u64,
    /// agent 对 intent 的 Ed25519 签名（64 字节 hex）。
    pub signature: String,
    /// 客户端直通证明（S-52，可缺省）：缺席 = 服务器占位证明（缺省口径逐字节不变，
    /// §6.16）；bb 验证后端装配下占位会被全拒（fail-closed）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<ProofRequest>,
}

impl PayRequest {
    fn into_parts(self) -> Result<(SpendIntent, AgentSignature, Option<SpendProof>), String> {
        let intent = SpendIntent {
            agent: decode::<20>(&self.agent, "agent")?,
            delegation_hash: decode::<32>(&self.delegation_hash, "delegation_hash")?,
            recipient: decode::<20>(&self.recipient, "recipient")?,
            amount: self.amount,
            category: decode::<32>(&self.category, "category")?,
            spend_nonce: self.spend_nonce,
            memo: self
                .memo
                .as_ref()
                .map(|m| decode::<32>(m, "memo"))
                .transpose()?,
            expires_at: self.expires_at,
        };
        let sig = AgentSignature::from_bytes(&decode::<64>(&self.signature, "signature")?);
        let proof = self.proof.map(|p| {
            Ok::<SpendProof, String>(SpendProof {
                proof: hex::decode(&p.proof_hex)
                    .map_err(|e| format!("proof.proof_hex: invalid hex: {e}"))?,
                public_inputs: SpendPublicInputs {
                    agent_commit: decode::<32>(&p.agent_commit, "proof.agent_commit")?,
                    delegation_hash: intent.delegation_hash,
                    recipient: intent.recipient,
                    amount: intent.amount,
                    category: intent.category,
                    spend_nonce: intent.spend_nonce,
                    expires_at: intent.expires_at,
                    revocation_root: decode::<32>(&p.revocation_root, "proof.revocation_root")?,
                    now: p.now,
                },
            })
        });
        let proof = proof.transpose()?;
        Ok((intent, sig, proof))
    }
}

/// `mist.balance` 入参。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct BalanceRequest {
    /// 目标委托的 delegation_hash（32 字节 hex）。
    pub delegation_hash: String,
}

impl BalanceRequest {
    fn into_dh(self) -> Result<[u8; 32], String> {
        decode::<32>(&self.delegation_hash, "delegation_hash")
    }
}

/// `mist.attest` 入参。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AttestRequest {
    /// 目标委托的 delegation_hash（32 字节 hex）。
    pub delegation_hash: String,
    /// attestation 公钥 x 坐标（BabyJubJub，32 字节小端 hex）。
    pub pk_x: String,
    /// attestation 公钥 y 坐标（BabyJubJub，32 字节小端 hex）。
    pub pk_y: String,
    /// agent Ed25519 对 `MIST-BINDING-v1\0 || x_le || y_le` 的绑定签名（64 字节 hex）。
    pub binding: String,
}

impl AttestRequest {
    fn into_parts(self) -> Result<([u8; 32], AttestationPubKey, AgentSignature), String> {
        let dh = decode::<32>(&self.delegation_hash, "delegation_hash")?;
        let pk = AttestationPubKey {
            x: decode::<32>(&self.pk_x, "pk_x")?,
            y: decode::<32>(&self.pk_y, "pk_y")?,
        };
        let binding = AgentSignature::from_bytes(&decode::<64>(&self.binding, "binding")?);
        Ok((dh, pk, binding))
    }
}

/// `mist.verify_receipt` 入参。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct VerifyReceiptRequest {
    /// 目标委托的 delegation_hash（32 字节 hex）。
    pub delegation_hash: String,
    /// 花费序号。
    pub spend_nonce: u64,
    /// 意图哈希（32 字节 hex）。
    pub intent_hash: String,
}

impl VerifyReceiptRequest {
    fn into_parts(self) -> Result<([u8; 32], u64, [u8; 32]), String> {
        Ok((
            decode::<32>(&self.delegation_hash, "delegation_hash")?,
            self.spend_nonce,
            decode::<32>(&self.intent_hash, "intent_hash")?,
        ))
    }
}

/// `mist.revocation_witness` 入参（S-52，§6.16）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct WitnessRequest {
    /// 目标委托的 delegation_hash（32 字节 hex）。
    pub delegation_hash: String,
}

impl WitnessRequest {
    fn into_dh(self) -> Result<[u8; 32], String> {
        decode::<32>(&self.delegation_hash, "delegation_hash")
    }
}

/// `#[tool_router]` 生成模块私有的 `tool_router()` 关联函数：每次调用重建一个
/// 装满路由的 `ToolRouter`（路由表由宏内联在构造器里，无跨请求状态）。
/// `#[tool_handler]` 生成的 `call_tool/list_tools/get_tool` 每请求调一次它，
/// 因此**不需要** struct 上的 `tool_router` 字段（MinimalServer 同款模式）。
/// 两者必须在同一模块（`tool_router()` 是模块私有）。
#[tool_router]
impl MistServer {
    /// 注册一张委托：校验 owner 对 delegation_hash 的 secp256k1 签名，
    /// 并把该委托绑定到 agent 传输身份公钥（Ed25519）。返回回执。
    #[tool(
        name = "authorize",
        description = "注册一张 DSA 委托（Delegated Spend Authority）：校验 owner 签名并绑定 agent 身份到真实聚合器。返回 delegation_hash 与预算上限。幂等：同委托同 agent 重发返回既有回执。"
    )]
    fn authorize(&self, req: Parameters<AuthorizeRequest>) -> Result<String, String> {
        let (delegation, signature, owner_pub, agent_pub) = req.0.into_parts()?;
        match self
            .state
            .authorize(&delegation, &owner_pub, &agent_pub, &signature)
        {
            Ok(receipt) => Ok(ok_body(&receipt)),
            Err(e) => Err(err_body(e.as_code())),
        }
    }

    /// 执行一笔支付：真实聚合器内核执行全部闸口（幂等 re-ack → 验签 → 预算 → WAL）。
    /// 返回回执（含 seq）。证明：`proof` 缺席 = 服务器占位（缺省口径）；携带时直通
    /// 验证器（S-52，§6.16——客户端产证明，服务器只验证，keyless 保形）。
    #[tool(
        name = "pay",
        description = "执行一笔支付（SpendIntent）：真实聚合器验签 + 预算强制 + WAL，幂等重发返回先前 seq。返回 {intent_hash, seq, spend_nonce}。可选 proof：客户端产的真 ZK 证明直通验证（keyless——服务器不持有任何密钥）。"
    )]
    fn pay(&self, req: Parameters<PayRequest>) -> Result<String, String> {
        let (intent, sig, proof) = req.0.into_parts()?;
        match self.state.pay(&intent, &sig, proof) {
            Ok(receipt) => Ok(ok_body(&receipt)),
            Err(e) => Err(err_body(e.as_code())),
        }
    }

    /// 查询委托剩余额度。
    #[tool(
        name = "balance",
        description = "查询委托剩余额度：聚合器累计已花 vs 授权 total_cap。返回 {total_spent, total_cap, remaining}。"
    )]
    fn balance(&self, req: Parameters<BalanceRequest>) -> Result<String, String> {
        let dh = req.0.into_dh()?;
        match self.state.balance(&dh) {
            Ok(receipt) => Ok(ok_body(&receipt)),
            Err(e) => Err(err_body(e.as_code())),
        }
    }

    /// 双钥绑定凭据。
    #[tool(
        name = "attest",
        description = "双钥绑定凭据（S-05）：authorize 时绑定的 agent Ed25519 对 BabyJubJub attestation 公钥签名。返回 agent_commit 与凭据。"
    )]
    fn attest(&self, req: Parameters<AttestRequest>) -> Result<String, String> {
        let (dh, pk, binding) = req.0.into_parts()?;
        match self.state.attest(&dh, &pk, &binding) {
            Ok(receipt) => Ok(ok_body(&receipt)),
            Err(e) => Err(err_body(e.as_code())),
        }
    }

    /// 只读确认一笔支付是否被接受。
    #[tool(
        name = "verify_receipt",
        description = "只读确认某 (delegation_hash, spend_nonce, intent_hash) 是否已被聚合器接受及 seq（幂等 re-ack 的确认侧）。拒绝与未知同报 accepted=false。"
    )]
    fn verify_receipt(&self, req: Parameters<VerifyReceiptRequest>) -> Result<String, String> {
        let (dh, nonce, ih) = req.0.into_parts()?;
        Ok(ok_body(&self.state.verify_receipt(&dh, nonce, &ih)))
    }

    /// 撤销非成员 witness（S-52，§6.16）：客户端构建真电路证明所需的唯一服务器侧
    /// 事实（S-45 网关 `GET /v1/revocation-witness/{dh}` 的 MCP 面）。
    #[tool(
        name = "revocation_witness",
        description = "撤销非成员 witness：给定 delegation_hash，返回当前撤销状态根 + 深度 256 兄弟路径（扁平 hex）。构建真 ZK 证明（pay 的 proof 入参）所需的撤销事实。目标已撤销 → E_REVOKED（非成员接口不给成员陈述）。"
    )]
    fn revocation_witness(&self, req: Parameters<WitnessRequest>) -> Result<String, String> {
        let dh = req.0.into_dh()?;
        match self.state.revocation_witness(&dh) {
            Ok(receipt) => Ok(ok_body(&receipt)),
            Err(e) => Err(err_body(e.as_code())),
        }
    }
}

/// ServerHandler 实现由宏生成（get_info / list_tools / call_tool / get_tool）。
/// 必须与 `#[tool_router]` 同模块：它生成的代码要访问模块私有的 `tool_router()` 构造器。
#[tool_handler(
    name = "mist",
    version = "0.2.0",
    instructions = "Mist DSA 正式版：authorize 注册委托、pay 预算内支付（可选 proof：客户端真 ZK 证明直通）、balance 查额度、attest 双钥绑定、revocation_witness 取撤销事实、verify_receipt 确认回执。"
)]
impl ServerHandler for MistServer {}

// ---- 编译期自检：确保工具类型可序列化为 JSON Schema 且可反序列化 -------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_types_roundtrip_json() {
        let req = AuthorizeRequest {
            agent: hex::encode([1u8; 20]),
            owner: hex::encode([2u8; 20]),
            nonce: 1,
            max_per_spend: 1_000,
            rate_window_secs: 3_600,
            rate_max_per_window: 10_000,
            total_cap: 10_000,
            categories: vec![],
            not_before: 0,
            expires_at: u64::MAX,
            version: 1,
            owner_signature: hex::encode([7u8; 64]),
            owner_pubkey: hex::encode([0x02u8; 33]),
            agent_pubkey: hex::encode([9u8; 32]),
        };
        let json = serde_json::to_value(&req).unwrap();
        let back: AuthorizeRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.nonce, 1);
        assert_eq!(back.agent, hex::encode([1u8; 20]));
    }

    #[test]
    fn new_request_types_roundtrip_json() {
        let bal = BalanceRequest {
            delegation_hash: hex::encode([0xAA; 32]),
        };
        let back: BalanceRequest =
            serde_json::from_value(serde_json::to_value(&bal).unwrap()).unwrap();
        assert_eq!(back.delegation_hash, hex::encode([0xAA; 32]));

        let att = AttestRequest {
            delegation_hash: hex::encode([0xAA; 32]),
            pk_x: hex::encode([0x11; 32]),
            pk_y: hex::encode([0x22; 32]),
            binding: hex::encode([0x33; 64]),
        };
        let back: AttestRequest =
            serde_json::from_value(serde_json::to_value(&att).unwrap()).unwrap();
        assert_eq!(back.pk_x, hex::encode([0x11; 32]));

        let vr = VerifyReceiptRequest {
            delegation_hash: hex::encode([0xAA; 32]),
            spend_nonce: 3,
            intent_hash: hex::encode([0xBB; 32]),
        };
        let back: VerifyReceiptRequest =
            serde_json::from_value(serde_json::to_value(&vr).unwrap()).unwrap();
        assert_eq!(back.spend_nonce, 3);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(
            decode::<20>("abcd", "agent"),
            Err("agent: expected 20 bytes, got 2".to_string())
        );
        assert!(decode::<20>(&hex::encode([1u8; 20]), "agent").is_ok());
    }
}
