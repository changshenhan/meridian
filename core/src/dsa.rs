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
///
/// 零分配实现：规范字节直接流入 Sha256（与 `canonical_intent` 的字节序列逐字节一致，
/// golden vector 不变）——`submit` 热路径每笔调用两次（管线 + `verify_intent`），
/// Vec 中转会破坏 B8 零分配验收。
pub fn intent_hash(i: &SpendIntent) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(INTENT_PREFIX);
    h.update(i.agent);
    h.update(i.delegation_hash);
    h.update(i.recipient);
    h.update(i.amount.to_le_bytes());
    h.update(i.category);
    h.update(i.spend_nonce.to_le_bytes());
    match &i.memo {
        Some(m) => {
            h.update([0x01u8]);
            h.update(m);
        }
        None => h.update([0x00u8]),
    }
    h.update(i.expires_at.to_le_bytes());
    h.finalize().into()
}

/// ZK 授权绑定哈希（S-09，电路内断言 9 的意图字段级绑定对象）。
///
/// **注意与 `intent_hash(&SpendIntent)` 区分**：后者是 S-02 传输层 Ed25519 签名对象
/// （含 `INTv1\0` 前缀 + agent Did + memo）。ZK 上下文中 agent 身份是 attestation 公钥
/// 承诺 `agent_commit`（而非 Did），且 memo 不参与授权绑定，故这里只绑定电路公共输入
/// 7 元组（无前缀、无 agent、无 memo）：
/// `agent_commit(32) ‖ delegation_hash(32) ‖ recipient(20) ‖ amount_le(8) ‖
/// category(32) ‖ spend_nonce_le(8) ‖ expires_at_le(8)` = 140 字节。
///
/// 与 `circuits/src/main.nr::compute_intent_hash` 用同一规范字节；双侧由 golden vector
/// （`zk_intent_hash_golden` 测试）锁同一常量保证一致性。
pub fn zk_intent_hash(
    agent_commit: [u8; 32],
    delegation_hash: [u8; 32],
    recipient: Did,
    amount: Amount,
    category: Category,
    spend_nonce: u64,
    expires_at: u64,
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(140);
    preimage.extend_from_slice(&agent_commit);
    preimage.extend_from_slice(&delegation_hash);
    preimage.extend_from_slice(&recipient);
    preimage.extend_from_slice(&amount.to_le_bytes());
    preimage.extend_from_slice(&category);
    preimage.extend_from_slice(&spend_nonce.to_le_bytes());
    preimage.extend_from_slice(&expires_at.to_le_bytes());
    sha256(&preimage)
}

/// 撤销稀疏 Merkle 树索引：`delegation_hash[0..4]` LE 转 u32。
/// 与电路 `revocation_index` / gen-witness 建树用同一派生（S-09）。
pub fn revocation_index(delegation_hash: [u8; 32]) -> u32 {
    u32::from_le_bytes([
        delegation_hash[0],
        delegation_hash[1],
        delegation_hash[2],
        delegation_hash[3],
    ])
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
/// 产出**低位 s** 的规范签名：链上 DSA.sol 拒绝高位 s（延展性防线，TECH_SPEC §9），
/// 签发侧必须与之一致，否则合法委托会被链上 reject。
pub fn sign_delegation(d: &Delegation, owner_key: &OwnerSigningKey) -> SignedDelegation {
    let h = delegation_hash(d);
    let sig: EcdsaSignature = owner_key
        .sign_prehash(&h)
        .expect("secp256k1 signing cannot fail");
    // 已低位则原样（normalize_s 返回 None），否则取 n-s（ecrecover 同样可恢复）。
    let sig = sig.normalize_s().unwrap_or(sig);
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
    fn sign_delegation_always_low_s() {
        // S-06：DSA.sol 拒绝高位 s，签发侧必须产出规范低位 s（任何私钥下都成立）。
        // secp256k1 群阶 n 的一半，大端 32 字节（s <= n/2 即低位）。
        let n_half: [u8; 32] =
            hex::decode("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")
                .unwrap()
                .try_into()
                .unwrap();
        for seed in [7u8, 9u8, 0xAB, 0xCD] {
            let owner_key = owner_signing_key_from_bytes([seed; 32]);
            let sd = sign_delegation(&sample_delegation(), &owner_key);
            let s: [u8; 32] = sd.signature.0[32..].try_into().unwrap();
            // [u8] 按字节字典序比较 = 大端整数比较，s 必须 <= n/2。
            assert!(
                s.as_slice() <= n_half.as_slice(),
                "signature s must be low-s"
            );
        }
    }

    #[test]
    fn canonical_encoding_length_is_stable() {
        let d = sample_delegation();
        let bytes = canonical_delegation(&d);
        // 6 + agent20 + owner20 + 8*5 + 4 + categories0 + 8*2 + 1 = 6+40+40+4+16+1
        assert_eq!(bytes.len(), 107);
    }

    /// 与 circuits/src/main.nr 测试 fixture 同输入的 golden vector。
    /// golden hex 由此测试计算并锁定，Noir 侧（`intent_hash_matches_golden`）锁同一
    /// 常量 → 跨语言规范字节一致性（sha2 ↔ Noir sha256）由该常量传递保证。
    #[test]
    fn zk_intent_hash_golden() {
        let agent_commit: [u8; 32] = std::array::from_fn(|i| 0x11 + i as u8);
        let delegation_hash: [u8; 32] = std::array::from_fn(|i| 0x21 + i as u8);
        let recipient: Did = std::array::from_fn(|i| 0x31 + i as u8);
        let category: Category = std::array::from_fn(|i| 0x51 + i as u8);
        let h = zk_intent_hash(
            agent_commit,
            delegation_hash,
            recipient,
            1234,
            category,
            7,
            1_700_000_000,
        );
        let want = "2352acec5b8e431c2e9167f9a07c7b237285d836599b860dba4841663ededf57";
        assert_eq!(
            hex::encode(h),
            want,
            "golden zk_intent_hash（与 Noir compute_intent_hash 共享）"
        );
    }

    #[test]
    fn zk_intent_hash_sensitive_to_every_field() {
        let agent_commit: [u8; 32] = std::array::from_fn(|i| 0x11 + i as u8);
        let delegation_hash: [u8; 32] = std::array::from_fn(|i| 0x21 + i as u8);
        let recipient: Did = std::array::from_fn(|i| 0x31 + i as u8);
        let category: Category = std::array::from_fn(|i| 0x51 + i as u8);
        let base = zk_intent_hash(
            agent_commit,
            delegation_hash,
            recipient,
            1234,
            category,
            7,
            1_700_000_000,
        );

        let mut ac = agent_commit;
        ac[0] ^= 1;
        assert_ne!(
            zk_intent_hash(
                ac,
                delegation_hash,
                recipient,
                1234,
                category,
                7,
                1_700_000_000
            ),
            base
        );

        let mut dh = delegation_hash;
        dh[0] ^= 1;
        assert_ne!(
            zk_intent_hash(
                agent_commit,
                dh,
                recipient,
                1234,
                category,
                7,
                1_700_000_000
            ),
            base
        );

        let mut rc = recipient;
        rc[0] ^= 1;
        assert_ne!(
            zk_intent_hash(
                agent_commit,
                delegation_hash,
                rc,
                1234,
                category,
                7,
                1_700_000_000
            ),
            base
        );

        assert_ne!(
            zk_intent_hash(
                agent_commit,
                delegation_hash,
                recipient,
                1235,
                category,
                7,
                1_700_000_000
            ),
            base
        );

        let mut cat = category;
        cat[0] ^= 1;
        assert_ne!(
            zk_intent_hash(
                agent_commit,
                delegation_hash,
                recipient,
                1234,
                cat,
                7,
                1_700_000_000
            ),
            base
        );

        assert_ne!(
            zk_intent_hash(
                agent_commit,
                delegation_hash,
                recipient,
                1234,
                category,
                8,
                1_700_000_000
            ),
            base
        );

        assert_ne!(
            zk_intent_hash(
                agent_commit,
                delegation_hash,
                recipient,
                1234,
                category,
                7,
                1_700_000_001
            ),
            base
        );
    }

    #[test]
    fn revocation_index_is_le_first_four_bytes() {
        // 与电路派生一致：dh[0] 是最低位（LE）。
        let dh = [0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD];
        let full: [u8; 32] = {
            let mut a = [0u8; 32];
            a[..8].copy_from_slice(&dh);
            a
        };
        assert_eq!(
            revocation_index(full),
            u32::from_le_bytes([0x01, 0x02, 0x03, 0x04])
        );
        // 后 28 字节不影响索引（原型级 32-bit 索引，碰撞属性见 SPEC）。
        assert_eq!(
            revocation_index(full),
            revocation_index({
                let mut a = full;
                a[8] ^= 1;
                a
            })
        );
    }
}
