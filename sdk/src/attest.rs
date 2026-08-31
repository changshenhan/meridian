//! `attest()`：双钥绑定凭据（S-05，core `attestation` 模块的 SDK 包装）。
//!
//! agent 的 Ed25519 传输身份对 attestation 公钥（BabyJubJub，S-09 电路签名密钥）做绑定
//! 签名 + 承诺。产出后自校验（防构造错误）；把凭据注册进电路 / 用真实 ZK 证明是 S-13+ 的
//! 接缝。

use ed25519_dalek::Signature as AgentSignature;

use mist_core::attestation::{agent_commit, sign_binding, verify_binding, AttestationPubKey};

use crate::error::SdkError;
use crate::identity::AgentWallet;

/// 双钥绑定凭据：attestation 公钥 + 电路内承诺 + Ed25519 绑定签名。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationCredential {
    pub pk: AttestationPubKey,
    /// `sha256(x_le || y_le)`，与 Noir 电路 `agent_commit_ok` 断言同源。
    pub agent_commit: [u8; 32],
    /// Ed25519（钱包传输身份）对 binding_message(pk) 的签名。
    pub binding: AgentSignature,
}

pub(crate) fn attest(
    wallet: &AgentWallet,
    pk: &AttestationPubKey,
) -> Result<AttestationCredential, SdkError> {
    let commit = agent_commit(pk);
    let binding = sign_binding(&wallet.agent_key, pk);
    // 自校验：Ed25519 验签 + 承诺一致（任一失败 = 构造错误，立即暴露）。
    verify_binding(&wallet.agent_pub(), pk, &binding, &commit)
        .map_err(|_| SdkError::Local("attestation binding self-check failed".to_string()))?;
    Ok(AttestationCredential {
        pk: *pk,
        agent_commit: commit,
        binding,
    })
}
