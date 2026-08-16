//! ZK 授权验证契约（TECH_SPEC §4.4）。
//!
//! 这是 core 对外契约：`SpendVerifier::verify` 返回 `SpendPublicInputs`，聚合器**登记必须
//! 以返回值为准**（§9 电路/账本漂移防线）——"证明的是 A、账本记 B" 被此接口切断。
//!
//! 后端现状（S-10，诚实口径）：S-09 电路的 in-process 验证包装（`bb_rs` / stdlib 封装）是
//! 路线图里单独列出的 Phase 1 交付物（TECH_SPEC §5.3 "Rust 侧封装"），**未在本 crate 落地**。
//! 聚合器内置的格式校验后端（TEMPORARY，PoC ② 同口径）见 `meridian-aggregator::proof`，
//! 真实后端直接实现 `SpendVerifier` 插此接口即可。

use crate::dsa::{AgentSigningKey, Amount, Category, Did, SignedDelegation, SpendIntent};
use crate::error::Error;

/// ZK 证明 + 公共输入（§4.4）。`proof` 字节 = S-09 UltraHonk 证明（`bb prove` 输出）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpendProof {
    pub proof: Vec<u8>,
    pub public_inputs: SpendPublicInputs,
}

/// 电路公共输入（对齐电路 §5.1，S-09）。
///
/// 注意：owner 的 ECDSA 电路外（§5.2 断言 2，链上 `registerDelegation` + S-02
/// `verify_delegation`），故无 owner_commit；`intent_hash` 电路内派生，不作为公共输入；
/// `recipient`/`now` 为 S-09 新增公共输入。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpendPublicInputs {
    /// sha256(pub_x_le ‖ pub_y_le)，attestation 公钥承诺。
    pub agent_commit: [u8; 32],
    pub delegation_hash: [u8; 32],
    pub recipient: Did,
    pub amount: Amount,
    pub category: Category,
    pub spend_nonce: u64,
    pub expires_at: u64,
    /// 撤销树根（公共锚点，聚合器新鲜度惩罚 §6.5）。
    pub revocation_root: [u8; 32],
    /// 当前时间（电路内断言 5）。
    pub now: u64,
}

/// 证明请求（prove 侧入参；聚合器不构造，agent 侧 SDK 用）。
#[derive(Debug, Clone)]
pub struct SpendProofRequest<'a> {
    pub sd: &'a SignedDelegation,
    pub intent: &'a SpendIntent,
    /// agent 签名密钥（possess 证明；真实后端用 attestation 密钥对）。
    pub agent_key: &'a AgentSigningKey,
    pub revocation_root: [u8; 32],
    pub now: u64,
}

/// 证明生成器（agent 侧；S-12 SDK 接 S-09 电路）。
pub trait SpendProver {
    fn prove(&self, req: &SpendProofRequest) -> Result<SpendProof, Error>;
}

/// 证明验证器（聚合器侧；返回公共输入，登记以此为准）。
pub trait SpendVerifier {
    fn verify(&self, proof: &SpendProof) -> Result<SpendPublicInputs, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_inputs_roundtrip_serde() {
        let pi = SpendPublicInputs {
            agent_commit: [0x11; 32],
            delegation_hash: [0x22; 32],
            recipient: [0x33; 20],
            amount: 42,
            category: [0x44; 32],
            spend_nonce: 7,
            expires_at: 1_700_000_000,
            revocation_root: [0x55; 32],
            now: 1_699_999_999,
        };
        let sp = SpendProof {
            proof: vec![0xAA, 0xBB],
            public_inputs: pi.clone(),
        };
        let json = serde_json::to_string(&sp).unwrap();
        let back: SpendProof = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sp);
    }
}
