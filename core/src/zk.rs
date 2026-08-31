//! ZK 授权验证契约（TECH_SPEC §4.4）。
//!
//! 这是 core 对外契约：`SpendVerifier::verify` 返回 `SpendPublicInputs`，聚合器**登记必须
//! 以返回值为准**（§9 电路/账本漂移防线）——"证明的是 A、账本记 B" 被此接口切断。
//!
//! 后端现状（S-10，诚实口径）：S-09 电路的 in-process 验证包装（`bb_rs` / stdlib 封装）是
//! 路线图里单独列出的 Phase 1 交付物（TECH_SPEC §5.3 "Rust 侧封装"），**未在本 crate 落地**。
//! 聚合器内置的格式校验后端（TEMPORARY，PoC ② 同口径）见 `mist-aggregator::proof`，
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

/// 撤销非成员 witness（S-43，TECH_SPEC §6.14）：聚合器 `RevocationSet::
/// non_membership_witness` 直出，root 与 path 单一来源（同一棵确定性树）。
///
/// `path[d]` = 深度 d 层目标索引的兄弟子树根（BE Field 32B，电路 `revocation_path`
/// witness 同口径）。占位 prover 不消费 `path`（可为空）；真实后端要求
/// `path.len() == 256` 且能重算出 `root`（§6.14 步 5，fail-closed）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationWitness {
    pub root: [u8; 32],
    pub path: Vec<[u8; 32]>,
}

/// 证明请求（prove 侧入参；聚合器不构造，agent 侧 SDK 用）。
#[derive(Debug, Clone)]
pub struct SpendProofRequest<'a> {
    pub sd: &'a SignedDelegation,
    pub intent: &'a SpendIntent,
    /// agent 签名密钥（possess 证明；真实后端用 attestation 密钥对）。
    pub agent_key: &'a AgentSigningKey,
    /// attestation 私钥标量（S-43：BabyJubJub/EdDSA，LE 32B）。Rust 侧当不透明字节——
    /// 只进 Noir oracle 入参与签名标量归约，不进任何曲线运算（TECH_SPEC §6.14）。
    pub attestation_secret: [u8; 32],
    /// 撤销非成员 witness（聚合器 S-42 直出）。
    pub revocation: RevocationWitness,
    pub now: u64,
}

/// 证明生成器（agent 侧；S-12 SDK 接 S-09 电路）。
pub trait SpendProver {
    fn prove(&self, req: &SpendProofRequest) -> Result<SpendProof, Error>;
}

/// 证明验证器（聚合器侧；返回公共输入，登记以此为准）。
pub trait SpendVerifier {
    fn verify(&self, proof: &SpendProof) -> Result<SpendPublicInputs, Error>;

    /// 装配面配对声明（S-48，TECH_SPEC §6.13）：真电路验证后端必须覆写为 `true`——
    /// 它验证的证明公共输入 `revocation_root` 有密码学语义，摄取管线必须同步开启
    /// 撤销根绑定闸（`IngestConfig::enforce_revocation_root`，§6.2），否则证明可自选
    /// 根（空根 / 伪造根）绕开撤销锚定，装饰性 ZK 在装配面复活。占位/格式后端缺省
    /// `false`：占位 witness 的根无语义，绑定闸开启反而会把占位口径拒成 `E_REV_ROOT`。
    /// `Aggregator` 构造期按此配对检查，缺配即 panic（fail-fast，bin 启动即退）。
    fn requires_revocation_root_binding(&self) -> bool {
        false
    }
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
