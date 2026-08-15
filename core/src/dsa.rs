//! DSA —— Delegated Spend Authority（TECH_SPEC §4）。
//!
//! 角色分工：owner（人类/企业）用 ECDSA-secp256k1 签署 `Delegation`；
//! agent 用 Ed25519 签署 `SpendIntent`。ZK 证明授权，账本执行预算。
//!
//! 序列化是**规范序**（字段定序 + 类型前缀），哈希即 SHA-256(规范字节)，
//! 禁止反序列化歧义（§11 E-03）。

use ed25519_dalek::{Signer, Verifier};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::Signature as EcdsaSignature;
use k256::elliptic_curve::scalar::IsHigh;
use sha2::{Digest, Sha256};

pub use ed25519_dalek::{
    Signature as AgentSignature, SigningKey as AgentSigningKey, VerifyingKey as AgentPubKey,
};
pub use k256::ecdsa::{SigningKey as OwnerSigningKey, VerifyingKey as OwnerPubKey};

use crate::error::Error;

/// EVM 地址形态的 DID（20 字节）。
pub type Did = [u8; 20];
/// USDC 基础单位（1e-6 USD）。100 = $0.0001。
pub type Amount = u64;
/// 类别哈希（32 字节）。
pub type Category = [u8; 32];

pub const PROTOCOL_VERSION: u8 = 1;
const DELEGATION_PREFIX: &[u8] = b"DSAv1\0";
const INTENT_PREFIX: &[u8] = b"INTv1\0";

/// 窗口速率限额（§4.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RateLimit {
    pub window_secs: u64,
    pub max_per_window: Amount,
}

/// 委托消费凭证（§4.1）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Delegation {
    pub agent: Did,
    pub owner: Did,
    pub nonce: u64,
    pub max_per_spend: Amount,
    pub rate: RateLimit,
    pub total_cap: Amount,
    pub categories: Vec<Category>,
    pub not_before: u64,
    pub expires_at: u64,
    pub version: u8,
}

/// 紧凑 ECDSA 签名（r||s，64 字节）。序列化为 hex 字符串
/// （serde 不支持 [u8; 64] 数组，且 hex 更紧凑、可读）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature64(pub [u8; 64]);

impl serde::Serialize for Signature64 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Signature64 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(deserializer)?;
        let raw = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        let arr: [u8; 64] = raw
            .try_into()
            .map_err(|_| serde::de::Error::custom("signature must be exactly 64 bytes"))?;
        Ok(Signature64(arr))
    }
}

/// owner 的 ECDSA 签名 + 委托本体。签名对象是 `delegation_hash`。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    pub signature: Signature64,
}

/// 单笔消费意图（§4.3）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SpendIntent {
    pub agent: Did,
    pub delegation_hash: [u8; 32],
    pub recipient: Did,
    pub amount: Amount,
    pub category: Category,
    pub spend_nonce: u64,
    pub memo: Option<[u8; 32]>,
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
// 规范序列化（canonical encoding）
// ---------------------------------------------------------------------------

fn push_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn canonical_delegation(d: &Delegation) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + 40 + 48 + d.categories.len() * 32);
    out.extend_from_slice(DELEGATION_PREFIX);
    out.extend_from_slice(&d.agent);
    out.extend_from_slice(&d.owner);
    push_u64(&mut out, d.nonce);
    push_u64(&mut out, d.max_per_spend);
    push_u64(&mut out, d.rate.window_secs);
    push_u64(&mut out, d.rate.max_per_window);
    push_u64(&mut out, d.total_cap);
    push_u32(&mut out, d.categories.len() as u32);
    for c in &d.categories {
        out.extend_from_slice(c);
    }
    push_u64(&mut out, d.not_before);
    push_u64(&mut out, d.expires_at);
    push_u8(&mut out, d.version);
    out
}

fn canonical_intent(i: &SpendIntent) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + 20 + 32 + 20 + 8 + 32 + 8 + 1 + 32 + 8);
    out.extend_from_slice(INTENT_PREFIX);
    out.extend_from_slice(&i.agent);
    out.extend_from_slice(&i.delegation_hash);
    out.extend_from_slice(&i.recipient);
    push_u64(&mut out, i.amount);
    out.extend_from_slice(&i.category);
    push_u64(&mut out, i.spend_nonce);
    match i.memo {
        Some(m) => {
            push_u8(&mut out, 0x01);
            out.extend_from_slice(&m);
        }
        None => push_u8(&mut out, 0x00),
    }
    push_u64(&mut out, i.expires_at);
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// 规范序列化的公开导出（S-06，Contract 模式）：把规范字节原样上链
/// （`DSA.sol::registerDelegation` 用 `sha256(delegationABI)` 复算 delegation_hash，
/// 保证链上与链下同一哈希）。
pub fn delegation_abi(d: &Delegation) -> Vec<u8> {
    canonical_delegation(d)
}

/// Delegation 的规范哈希（owner 签名对象）。
pub fn delegation_hash(d: &Delegation) -> [u8; 32] {
    sha256(&canonical_delegation(d))
}

/// SpendIntent 的规范哈希（agent 签名对象）。
pub fn intent_hash(i: &SpendIntent) -> [u8; 32] {
    sha256(&canonical_intent(i))
}

// ---------------------------------------------------------------------------
// 签名
// ---------------------------------------------------------------------------

/// 由原始字节构造 owner 签名密钥（测试/演示用；生产从钱包导入）。
pub fn owner_signing_key_from_bytes(bytes: [u8; 32]) -> OwnerSigningKey {
    let sk = k256::elliptic_curve::SecretKey::from_bytes(&bytes.into()).expect("valid key bytes");
    OwnerSigningKey::from(&sk)
}

/// owner 签署一张委托（测试/发卡工具用；生产走钱包）。
pub fn sign_delegation(d: &Delegation, owner_key: &OwnerSigningKey) -> SignedDelegation {
    let h = delegation_hash(d);
    let sig: EcdsaSignature = owner_key
        .sign_prehash(&h)
        .expect("secp256k1 signing cannot fail");
    let sb = sig.to_bytes();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&sb[..]);
    SignedDelegation {
        delegation: d.clone(),
        signature: Signature64(bytes),
    }
}

/// 验证 owner 对委托的签名（§4.4）。
/// 拒绝 high-s 签名以封堵延展性攻击（verify_prehash 底层同样拒绝，此处显式防御）。
pub fn verify_delegation(sd: &SignedDelegation, owner_pub: &OwnerPubKey) -> Result<(), Error> {
    let sig: EcdsaSignature =
        EcdsaSignature::from_slice(&sd.signature.0).map_err(|_| Error::EDelegSig)?;
    if bool::from(sig.s().is_high()) {
        return Err(Error::EDelegSig);
    }
    let h = delegation_hash(&sd.delegation);
    owner_pub
        .verify_prehash(&h, &sig)
        .map_err(|_| Error::EDelegSig)
}

/// agent 签署一笔意图。
pub fn sign_intent(i: &SpendIntent, agent_key: &AgentSigningKey) -> AgentSignature {
    let h = intent_hash(i);
    agent_key.sign(&h)
}

/// 验证 agent 对意图的签名。
pub fn verify_intent(
    i: &SpendIntent,
    sig: &AgentSignature,
    agent_pub: &AgentPubKey,
) -> Result<(), Error> {
    let h = intent_hash(i);
    agent_pub.verify(&h, sig).map_err(|_| Error::EIntentSig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_delegation() -> Delegation {
        Delegation {
            agent: [1u8; 20],
            owner: [2u8; 20],
            nonce: 1,
            max_per_spend: 1_000,
            rate: RateLimit {
                window_secs: 60,
                max_per_window: 10_000,
            },
            total_cap: 100_000,
            categories: vec![],
            not_before: 0,
            expires_at: u64::MAX,
            version: PROTOCOL_VERSION,
        }
    }

    fn sample_intent(dh: [u8; 32]) -> SpendIntent {
        SpendIntent {
            agent: [1u8; 20],
            delegation_hash: dh,
            recipient: [3u8; 20],
            amount: 42,
            category: [0xCD; 32],
            spend_nonce: 7,
            memo: None,
            expires_at: u64::MAX,
        }
    }

    #[test]
    fn delegation_sign_verify_roundtrip() {
        let owner_key = owner_signing_key_from_bytes([7u8; 32]);
        let sd = sign_delegation(&sample_delegation(), &owner_key);
        assert_eq!(verify_delegation(&sd, owner_key.verifying_key()), Ok(()));
    }

    #[test]
    fn tampered_delegation_fails_verification() {
        let owner_key = owner_signing_key_from_bytes([7u8; 32]);
        let sd = sign_delegation(&sample_delegation(), &owner_key);
        let mut forged = sample_delegation();
        forged.total_cap = 1; // 篡改
        let forged = SignedDelegation {
            delegation: forged,
            signature: sd.signature,
        };
        assert_eq!(
            verify_delegation(&forged, owner_key.verifying_key()),
            Err(Error::EDelegSig)
        );
    }

    #[test]
    fn wrong_key_fails_verification() {
        let owner_key = owner_signing_key_from_bytes([7u8; 32]);
        let other_key = owner_signing_key_from_bytes([9u8; 32]);
        let sd = sign_delegation(&sample_delegation(), &owner_key);
        assert_eq!(
            verify_delegation(&sd, other_key.verifying_key()),
            Err(Error::EDelegSig)
        );
    }

    #[test]
    fn intent_sign_verify_roundtrip() {
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let i = sample_intent([0xAB; 32]);
        let sig = sign_intent(&i, &agent_key);
        assert_eq!(verify_intent(&i, &sig, &agent_key.verifying_key()), Ok(()));
    }

    #[test]
    fn tampered_intent_fails_verification() {
        let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
        let mut i = sample_intent([0xAB; 32]);
        let sig = sign_intent(&i, &agent_key);
        i.amount = 999; // 篡改
        assert_eq!(
            verify_intent(&i, &sig, &agent_key.verifying_key()),
            Err(Error::EIntentSig)
        );
    }

    #[test]
    fn hash_is_deterministic_and_sensitive() {
        let d = sample_delegation();
        assert_eq!(delegation_hash(&d), delegation_hash(&d));
        let mut d2 = d.clone();
        d2.total_cap += 1;
        assert_ne!(delegation_hash(&d), delegation_hash(&d2));

        let i = sample_intent([0xAB; 32]);
        assert_eq!(intent_hash(&i), intent_hash(&i));
        let mut i2 = i.clone();
        i2.amount += 1;
        assert_ne!(intent_hash(&i), intent_hash(&i2));
    }

    #[test]
    fn canonical_encoding_length_is_stable() {
        let d = sample_delegation();
        let bytes = canonical_delegation(&d);
        // 6 + agent20 + owner20 + 8*5 + 4 + categories0 + 8*2 + 1 = 6+40+40+4+16+1
        assert_eq!(bytes.len(), 107);
    }
}
