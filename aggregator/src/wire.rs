//! Wire DTO（S-29 网络 ingest API，TECH_SPEC §6.7）。
//!
//! gateway 与 sdk 共用的 JSON 形状**单一来源**——两侧都依赖本 crate，禁止各自手写
//! 同构结构（wire 漂移 = 静默互不兼容）。
//!
//! 编码口径：
//! - 内核类型（`SpendIntent`/`SpendProof`/`SignedDelegation`…）已是 serde derive（
//!   `[u8; N]` → JSON 数字数组，zk.rs roundtrip 先例），DTO 直嵌不重定义。
//! - Ed25519 键/签名是 dalek 类型（无 serde）→ hex 字符串（`Signature64` 同款先例）：
//!   `agent_sig` = 64B hex、`agent_pub` = 32B hex。
//! - 错误：内核 `Error` 无 serde → `as_code()` 字符串（§11 错误码表）。

use meridian_core::dsa::{AgentPubKey, AgentSignature, SignedDelegation};
use meridian_core::error::Error;

use crate::receipt::{IntentEnvelope, Receipt};

/// hex 编码失败（wire 反序列化侧）。
pub fn hex_to_bytes32(s: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(s).map_err(|e| format!("bad hex: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", raw.len()));
    }
    Ok(raw.try_into().expect("length checked"))
}

// ---------------------------------------------------------------------------
// authorize
// ---------------------------------------------------------------------------

/// `POST /v1/authorize` 请求体。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthorizeRequest {
    pub signed_delegation: SignedDelegation,
    /// agent 的 Ed25519 传输公钥（32B hex；attestation 绑定由内核 §4.4 校验）。
    pub agent_pub: String,
}

/// `POST /v1/authorize` 响应体。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorizeResponse {
    pub registered: bool,
}

impl AuthorizeRequest {
    pub fn to_parts(&self) -> Result<(SignedDelegation, AgentPubKey), String> {
        let raw = hex::decode(&self.agent_pub).map_err(|e| format!("bad agent_pub hex: {e}"))?;
        if raw.len() != 32 {
            return Err(format!("agent_pub must be 32 bytes, got {}", raw.len()));
        }
        let arr: [u8; 32] = raw.try_into().expect("length checked");
        let agent_pub =
            AgentPubKey::from_bytes(&arr).map_err(|e| format!("invalid agent_pub: {e}"))?;
        Ok((self.signed_delegation.clone(), agent_pub))
    }
}

// ---------------------------------------------------------------------------
// intents
// ---------------------------------------------------------------------------

/// `POST /v1/intents` 请求体（§6.1 意图信封 wire 形态）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntentEnvelopeDto {
    pub intent: meridian_core::dsa::SpendIntent,
    /// agent 的 Ed25519 传输签名（64B hex，签名对象 = `intent_hash`）。
    pub agent_sig: String,
    pub proof: meridian_core::zk::SpendProof,
}

/// `POST /v1/intents` 响应体（§6.2 回执 wire 形态）。
/// 业务拒绝 = `accepted: false` + `reject_reason`（HTTP 200，定局——不是传输错误）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceiptDto {
    /// 32B hex。拒绝的意图也回填（供幂等重发比对）。
    pub intent_hash: String,
    pub accepted: bool,
    /// 规格 §11 错误码（如 `"E_BUDGET_RATE"`）；接受时为 null。
    pub reject_reason: Option<String>,
    pub seq: u64,
}

impl IntentEnvelopeDto {
    pub fn from_envelope(env: &IntentEnvelope) -> Self {
        IntentEnvelopeDto {
            intent: env.intent.clone(),
            agent_sig: hex::encode(env.agent_sig.to_bytes()),
            proof: env.proof.clone(),
        }
    }

    pub fn into_envelope(self) -> Result<IntentEnvelope, String> {
        let raw = hex::decode(&self.agent_sig).map_err(|e| format!("bad agent_sig hex: {e}"))?;
        if raw.len() != 64 {
            return Err(format!("agent_sig must be 64 bytes, got {}", raw.len()));
        }
        let arr: [u8; 64] = raw.try_into().expect("length checked");
        let agent_sig: AgentSignature = AgentSignature::from_bytes(&arr);
        Ok(IntentEnvelope {
            intent: self.intent,
            agent_sig,
            proof: self.proof,
        })
    }
}

impl ReceiptDto {
    pub fn from_receipt(r: &Receipt) -> Self {
        ReceiptDto {
            intent_hash: hex::encode(r.intent_hash),
            accepted: r.accepted,
            reject_reason: r.reject_reason.map(|e| e.as_code().to_string()),
            seq: r.seq,
        }
    }

    pub fn into_receipt(self) -> Result<Receipt, String> {
        let intent_hash = hex_to_bytes32(&self.intent_hash)?;
        let reject_reason = match self.reject_reason.as_deref() {
            None => None,
            Some(code) => {
                Some(Error::from_code(code).ok_or_else(|| format!("unknown error code: {code}"))?)
            }
        };
        Ok(Receipt {
            intent_hash,
            accepted: self.accepted,
            reject_reason,
            seq: self.seq,
        })
    }
}

/// 网关错误体（传输层，§11 补充表：E_AUTH / E_RATE_LIMITED / E_MALFORMED）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GatewayError {
    pub error: ErrorBody,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl GatewayError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        GatewayError {
            error: ErrorBody {
                code: code.to_string(),
                message: message.into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meridian_core::error::Error;

    #[test]
    fn from_code_mirrors_as_code_exactly() {
        // 全枚举镜像：as_code → from_code 恒等；未知码 None（不 panic）。
        for e in [
            Error::EDelegExpired,
            Error::EDelegSig,
            Error::EIntentSig,
            Error::EProof,
            Error::EBudgetPerSpend,
            Error::EBudgetRate,
            Error::EBudgetTotal,
            Error::ENonce,
            Error::ERevoked,
            Error::EIntentExpired,
            Error::EIntentHash,
            Error::ECategory,
            Error::ESeq,
            Error::EOrdering,
            Error::EAttestBind,
            Error::EDelegUnknown,
        ] {
            assert_eq!(Error::from_code(e.as_code()), Some(e));
        }
        assert_eq!(Error::from_code("E_NOPE"), None);
        assert_eq!(Error::from_code(""), None);
    }

    #[test]
    fn receipt_dto_roundtrip_preserves_reject_reason() {
        let receipt = Receipt {
            intent_hash: [0xAB; 32],
            accepted: false,
            reject_reason: Some(Error::EBudgetTotal),
            seq: 7,
        };
        let dto = ReceiptDto::from_receipt(&receipt);
        assert_eq!(dto.reject_reason.as_deref(), Some("E_BUDGET_TOTAL"));
        assert_eq!(dto.seq, 7);
        let back = dto.clone().into_receipt().expect("roundtrip");
        assert_eq!(back.intent_hash, receipt.intent_hash);
        assert!(!back.accepted);
        assert_eq!(back.reject_reason, Some(Error::EBudgetTotal));
        assert_eq!(back.seq, 7);

        // 接受路径：reject_reason = None roundtrip 保持 None。
        let accepted = Receipt {
            intent_hash: [1; 32],
            accepted: true,
            reject_reason: None,
            seq: 8,
        };
        let back = ReceiptDto::from_receipt(&accepted)
            .into_receipt()
            .expect("roundtrip");
        assert_eq!(back.reject_reason, None);
        assert!(back.accepted);
    }

    #[test]
    fn receipt_dto_rejects_unknown_code_and_bad_hex() {
        let dto = ReceiptDto {
            intent_hash: "00".to_string(), // 长度错
            accepted: true,
            reject_reason: None,
            seq: 0,
        };
        assert!(dto.into_receipt().is_err());

        let dto = ReceiptDto {
            intent_hash: hex::encode([1u8; 32]),
            accepted: false,
            reject_reason: Some("E_UNKNOWN_CODE".to_string()),
            seq: 0,
        };
        assert!(dto.into_receipt().is_err());
    }

    #[test]
    fn hex_to_bytes32_rejects_wrong_length() {
        assert!(hex_to_bytes32(&hex::encode([1u8; 32])).is_ok());
        assert!(hex_to_bytes32(&hex::encode([1u8; 31])).is_err());
        assert!(hex_to_bytes32(&hex::encode([1u8; 33])).is_err());
        assert!(hex_to_bytes32("zz").is_err());
    }
}
