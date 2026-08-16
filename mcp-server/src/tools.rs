//! S-07 MCP 工具定义：`authorize` / `pay`。
//!
//! 入参用**扁平 hex 字符串**而非嵌套 core 类型：`#[tool]` 宏需要入参类型实现
//! `JsonSchema`（rmcp 用 schemars 生成工具 JSON Schema），而 core 的 `Delegation`
//! /`SpendIntent` 只派生 serde、不派生 schemars。hex 字符串对 agent 框架最友好，
//! 也与 core 的 `Signature64` serde（hex 字符串）一致。
//!
//! 工具返回 `Result<String, String>`：Ok = 回执 JSON；Err = `{"error":"E_..."}`，
//! rmcp 会把 Err 分支标成 `is_error=true`（MCP 客户端/agent 可见真失败）。

use ed25519_dalek::Signature as AgentSignature;
use meridian_core::dsa::{
    AgentPubKey, Delegation, OwnerPubKey, RateLimit, Signature64, SpendIntent,
};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::ServerHandler;
use rmcp::{tool, tool_handler, tool_router};

use crate::MeridianServer;

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

/// `meridian.authorize` 入参。
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

/// `meridian.pay` 入参。
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
}

impl PayRequest {
    fn into_parts(self) -> Result<(SpendIntent, AgentSignature), String> {
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
        Ok((intent, sig))
    }
}

/// `#[tool_router]` 生成模块私有的 `tool_router()` 关联函数：每次调用重建一个
/// 装满路由的 `ToolRouter`（路由表由宏内联在构造器里，无跨请求状态）。
/// `#[tool_handler]` 生成的 `call_tool/list_tools/get_tool` 每请求调一次它，
/// 因此**不需要** struct 上的 `tool_router` 字段（MinimalServer 同款模式）。
/// 两者必须在同一模块（`tool_router()` 是模块私有）。
#[tool_router]
impl MeridianServer {
    /// 注册一张委托：校验 owner 对 delegation_hash 的 secp256k1 签名，
    /// 并把该委托绑定到 agent 传输身份公钥（Ed25519）。返回回执。
    #[tool(
        name = "authorize",
        description = "注册一张 DSA 委托（Delegated Spend Authority）：校验 owner 签名并绑定 agent 身份。返回 delegation_hash 与预算上限。"
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

    /// 执行一笔模拟支付：校验 agent 对 intent 的 Ed25519 签名、防重放、
    /// 预算检查与记账。返回回执（含累计支出与剩余额度）。
    #[tool(
        name = "pay",
        description = "执行一笔模拟支付（SpendIntent）：agent 签名 + 预算检查 + 记账。返回回执。TEMPORARY：无 ZK 证明，S-09 接入。"
    )]
    fn pay(&self, req: Parameters<PayRequest>) -> Result<String, String> {
        let (intent, sig) = req.0.into_parts()?;
        match self.state.pay(&intent, &sig) {
            Ok(receipt) => Ok(ok_body(&receipt)),
            Err(e) => Err(err_body(e.as_code())),
        }
    }
}

/// ServerHandler 实现由宏生成（get_info / list_tools / call_tool / get_tool）。
/// 必须与 `#[tool_router]` 同模块：它生成的代码要访问模块私有的 `tool_router()` 构造器。
#[tool_handler(
    name = "meridian",
    version = "0.1.0",
    instructions = "Meridian DSA 探针：authorize 注册委托、pay 模拟支付（预算内）。"
)]
impl ServerHandler for MeridianServer {}

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
    fn decode_rejects_wrong_length() {
        assert_eq!(
            decode::<20>("abcd", "agent"),
            Err("agent: expected 20 bytes, got 2".to_string())
        );
        assert!(decode::<20>(&hex::encode([1u8; 20]), "agent").is_ok());
    }
}
