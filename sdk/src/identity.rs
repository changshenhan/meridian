//! Agent 身份与委托构造（S-12）。
//!
//! [`AgentWallet`] 持有 agent 的 Ed25519 传输身份密钥（S-02 NodeId 语义）。owner 的
//! secp256k1 密钥不驻留 wallet（角色分离）：`authorize` 由调用方传入 owner 私钥，SDK 只做
//! 构造 + 本地校验 + 传输注册。
//!
//! owner DID 取 EVM 地址形态（keccak256(未压缩公钥[1..]) 末 20 字节），与 rust-smoke / 链上
//! DSA.sol 一致（S-11d 交叉实现已断言）。

use ed25519_dalek::Signature as AgentSignature;
use k256::ecdsa::SigningKey as OwnerSigningKey;
use sha3::{Digest, Keccak256};

use mist_core::dsa::{
    delegation_hash, sign_delegation, sign_intent, verify_delegation, AgentPubKey, Amount,
    Category, Delegation, Did, OwnerPubKey, RateLimit, SignedDelegation, SpendIntent,
    PROTOCOL_VERSION,
};
use mist_core::error::Error;

/// 委托限额（§4.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationLimits {
    /// 单笔上限（USDC 基础单位，1e-6）。
    pub max_per_spend: Amount,
    /// 窗口长度（秒）。
    pub rate_window_secs: u64,
    /// 窗口内速率上限。
    pub rate_max_per_window: Amount,
    /// 累计总额上限。
    pub total_cap: Amount,
    /// 允许的消费类别（空 = 全类别）。
    pub categories: Vec<Category>,
    /// 生效时间（unix 秒）。
    pub not_before: u64,
    /// 过期时间（unix 秒）。
    pub expires_at: u64,
}

/// agent 侧身份：Ed25519 传输密钥（验签快路径密钥，S-02）。
#[derive(Debug, Clone)]
pub struct AgentWallet {
    /// Ed25519 传输身份私钥。agent DID 由调用方在 `authorize` 时指定（与公钥一同绑定）。
    pub agent_key: ed25519_dalek::SigningKey,
}

impl AgentWallet {
    /// 确定性种子构造（测试 / 离线发钥）。
    pub fn from_seed(seed: [u8; 32]) -> Self {
        AgentWallet {
            agent_key: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    /// agent 传输身份公钥。
    pub fn agent_pub(&self) -> AgentPubKey {
        self.agent_key.verifying_key()
    }

    /// 构造一笔 SpendIntent 并签名（agent Ed25519 over `intent_hash`）。
    #[allow(clippy::too_many_arguments)]
    pub fn create_intent(
        &self,
        agent: Did,
        delegation_hash: [u8; 32],
        recipient: Did,
        amount: Amount,
        category: Category,
        spend_nonce: u64,
        memo: Option<[u8; 32]>,
        expires_at: u64,
    ) -> (SpendIntent, AgentSignature) {
        let intent = SpendIntent {
            agent,
            delegation_hash,
            recipient,
            amount,
            category,
            spend_nonce,
            memo,
            expires_at,
        };
        let sig = sign_intent(&intent, &self.agent_key);
        (intent, sig)
    }
}

/// owner DID：keccak256(未压缩 SEC1 公钥[1..]) 末 20 字节（EVM 地址形态，与链上一致）。
pub fn owner_did(owner_pub: &OwnerPubKey) -> Did {
    let uncompressed = owner_pub.to_encoded_point(false);
    let mut hasher = Keccak256::new();
    hasher.update(&uncompressed.as_bytes()[1..]);
    let digest = hasher.finalize();
    let mut did = [0u8; 20];
    did.copy_from_slice(&digest[12..]);
    did
}

/// 构造一张委托并签名（owner secp256k1，低位 s 由 core 保证）。本地校验限额自洽
/// （`not_before ≤ expires_at`；单笔 ≤ 窗口 ≤ 总额，否则后续必然红）——返回规格错误码。
pub fn create_delegation(
    owner_key: &OwnerSigningKey,
    agent: Did,
    delegation_nonce: u64,
    limits: &DelegationLimits,
) -> Result<SignedDelegation, Error> {
    if limits.not_before > limits.expires_at {
        return Err(Error::EDelegExpired);
    }
    if limits.max_per_spend > limits.rate_max_per_window
        || limits.rate_max_per_window > limits.total_cap
    {
        return Err(Error::EBudgetPerSpend);
    }
    let owner_pub: OwnerPubKey = *owner_key.verifying_key();
    let delegation = Delegation {
        agent,
        owner: owner_did(&owner_pub),
        nonce: delegation_nonce,
        max_per_spend: limits.max_per_spend,
        rate: RateLimit {
            window_secs: limits.rate_window_secs,
            max_per_window: limits.rate_max_per_window,
        },
        total_cap: limits.total_cap,
        categories: limits.categories.clone(),
        not_before: limits.not_before,
        expires_at: limits.expires_at,
        version: PROTOCOL_VERSION,
    };
    let sd = sign_delegation(&delegation, owner_key);
    // 自检：签名可验、哈希一致（构造错误防御）。
    verify_delegation(&sd, &owner_pub)?;
    debug_assert_eq!(
        delegation_hash(&delegation),
        delegation_hash(&sd.delegation)
    );
    Ok(sd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mist_core::dsa::{owner_signing_key_from_bytes, verify_intent};

    fn limits(max_per_spend: u64, total_cap: u64) -> DelegationLimits {
        DelegationLimits {
            max_per_spend,
            rate_window_secs: 3_600,
            rate_max_per_window: total_cap,
            total_cap,
            categories: vec![],
            not_before: 0,
            expires_at: u64::MAX,
        }
    }

    #[test]
    fn wallet_signs_intent_verifiable_by_pubkey() {
        let wallet = AgentWallet::from_seed([9u8; 32]);
        let (intent, sig) = wallet.create_intent(
            [1u8; 20],
            [0xAA; 32],
            [0xBB; 20],
            42,
            [0u8; 32],
            1,
            None,
            u64::MAX,
        );
        assert!(verify_intent(&intent, &sig, &wallet.agent_pub()).is_ok());
    }

    #[test]
    fn delegation_roundtrips_verification() {
        let owner_key = owner_signing_key_from_bytes([7u8; 32]);
        let sd = create_delegation(&owner_key, [1u8; 20], 1, &limits(1_000, 10_000)).unwrap();
        assert!(verify_delegation(&sd, owner_key.verifying_key()).is_ok());
        // owner DID 是 EVM 地址形态：20 字节。
        assert_eq!(sd.delegation.owner.len(), 20);
    }

    #[test]
    fn inconsistent_limits_rejected_with_code() {
        let owner_key = owner_signing_key_from_bytes([7u8; 32]);
        let mut l = limits(5_000, 10_000);
        l.rate_max_per_window = 1_000; // max_per_spend > max_per_window → 自相矛盾
        assert_eq!(
            create_delegation(&owner_key, [1u8; 20], 1, &l),
            Err(Error::EBudgetPerSpend)
        );
        let mut l2 = limits(1_000, 10_000);
        l2.not_before = u64::MAX;
        l2.expires_at = 1;
        assert_eq!(
            create_delegation(&owner_key, [1u8; 20], 1, &l2),
            Err(Error::EDelegExpired)
        );
    }
}
