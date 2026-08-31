//! 双钥绑定（S-05，D-05 扩展）—— 传输身份 Ed25519 对 attestation key（BabyJubJub）的绑定。
//!
//! 动机：Noir 电路用的 `eddsa` 库（noir-lang/eddsa v0.1.3）验证的是 **BabyJubJub + Poseidon**
//! 的 EdDSA，**不是**标准 Ed25519（S-02 的 NodeId）。两把密钥以「双钥绑定」收敛：
//!
//!   · 传输身份（NodeId）：Ed25519，S-02 已验收，电路外快路径验签 —— **不改已验收代码**。
//!   · ZK 授权（attestation）：BabyJubJub + Poseidon EdDSA，在 Noir 电路内验证。
//!   · 绑定：注册时用 Ed25519 对 Jubjub 公钥 `(x_le || y_le)` 做绑定签名，绑定验证在电路外做一次。
//!
//! 电路内承诺 `agent_commit = sha256(x_le || y_le)`，与 `circuits/src/main.nr` 的
//! `agent_commit_ok` 规范完全一致（Noir 侧 `pub_x.to_le_bytes()` 即 32 字节小端）。
//! 绑定签名（Ed25519 over 域分离消息）只在本模块验证，**不进电路** —— 少一组椭圆曲线，
//! 直接压低约束数。

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::Error;

/// 域分离前缀：杜绝绑定签名与其它 Ed25519 上下文串用（§11 E-03 反串用）。
const BINDING_PREFIX: &[u8] = b"MIST-BINDING-v1\0";

/// BabyJubJub attestation 公钥，坐标取 32 字节小端（与 Noir `to_le_bytes` 一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationPubKey {
    /// x 坐标（小端 32 字节）。
    pub x: [u8; 32],
    /// y 坐标（小端 32 字节）。
    pub y: [u8; 32],
}

/// 绑定消息字节：`BINDING_PREFIX || x_le(32) || y_le(32)`。
pub fn binding_message(pk: &AttestationPubKey) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BINDING_PREFIX.len() + 64);
    msg.extend_from_slice(BINDING_PREFIX);
    msg.extend_from_slice(&pk.x);
    msg.extend_from_slice(&pk.y);
    msg
}

/// 电路内承诺值：`agent_commit = sha256(x_le || y_le)`。
/// Rust sha2 与 Noir sha256 库同为标准 SHA-256，结果一致（由测试锁定）。
pub fn agent_commit(pk: &AttestationPubKey) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&pk.x);
    buf[32..].copy_from_slice(&pk.y);
    Sha256::digest(buf).into()
}

/// 注册绑定签名：Ed25519（NodeId 私钥）对 attestation 公钥签名。
/// 只有本模块的 `verify_binding` 会验证它（电路外一次）。
pub fn sign_binding(agent: &SigningKey, pk: &AttestationPubKey) -> Signature {
    agent.sign(&binding_message(pk))
}

/// 电路外绑定验证（一次）：
///   1. Ed25519 验签：NodeId 确实为该 Jubjub 公钥做了绑定签名；
///   2. 承诺一致：`commit == sha256(x_le || y_le)`，与电路内断言同源。
///
/// 任一失败返回 `Error::EAttestBind`。
pub fn verify_binding(
    node_vk: &VerifyingKey,
    pk: &AttestationPubKey,
    binding_sig: &Signature,
    commit: &[u8; 32],
) -> Result<(), Error> {
    node_vk
        .verify(&binding_message(pk), binding_sig)
        .map_err(|_| Error::EAttestBind)?;
    if agent_commit(pk) != *commit {
        return Err(Error::EAttestBind);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    fn sample_pk() -> AttestationPubKey {
        AttestationPubKey {
            x: [0x11; 32],
            y: [0x22; 32],
        }
    }

    #[test]
    fn agent_commit_matches_sha256_concatenation() {
        let pk = sample_pk();
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&pk.x);
        buf[32..].copy_from_slice(&pk.y);
        let expected: [u8; 32] = Sha256::digest(buf).into();
        assert_eq!(agent_commit(&pk), expected);
    }

    #[test]
    fn binding_signs_and_verifies_roundtrip() {
        let agent = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sample_pk();
        let commit = agent_commit(&pk);
        let sig = sign_binding(&agent, &pk);
        assert!(verify_binding(&agent.verifying_key(), &pk, &sig, &commit).is_ok());
    }

    #[test]
    fn binding_rejects_wrong_node_key() {
        let agent = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let pk = sample_pk();
        let commit = agent_commit(&pk);
        let sig = sign_binding(&agent, &pk);
        assert_eq!(
            verify_binding(&other.verifying_key(), &pk, &sig, &commit),
            Err(Error::EAttestBind)
        );
    }

    #[test]
    fn binding_rejects_tampered_pubkey() {
        let agent = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sample_pk();
        let mut forged = pk;
        forged.x[0] ^= 0x01;
        let commit = agent_commit(&pk);
        let sig = sign_binding(&agent, &pk);
        // 用篡改后的公钥验签：消息不匹配 → 失败
        assert_eq!(
            verify_binding(&agent.verifying_key(), &forged, &sig, &commit),
            Err(Error::EAttestBind)
        );
    }

    #[test]
    fn binding_rejects_mismatched_commit() {
        let agent = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sample_pk();
        let wrong_commit = [0x99; 32];
        let sig = sign_binding(&agent, &pk);
        assert_eq!(
            verify_binding(&agent.verifying_key(), &pk, &sig, &wrong_commit),
            Err(Error::EAttestBind)
        );
    }
}
