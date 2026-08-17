//! `authorize()`：注册一张委托（S-12）。
//!
//! 步骤：构造 + 本地限额校验（错误码透传）→ 传输注册（[`Transport::authorize`]）→
//! 本地记录（pay 构造 intent 的 agent DID + prover 的 SignedDelegation）。
//!
//! 幂等语义：每次调用分配新 delegation nonce → 是**新的授权**（新 delegation_hash）。
//! `authorize` 不重试（非消费操作，无双花风险）；重试会注册一张同限额新委托，无害。

use std::collections::HashMap;
use std::sync::RwLock;

use k256::ecdsa::SigningKey as OwnerSigningKey;

use meridian_core::dsa::{delegation_hash, Did, SignedDelegation};

use crate::error::SdkError;
use crate::identity::{create_delegation, AgentWallet, DelegationLimits};
use crate::transport::Transport;

/// `authorize` 回执。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeReceipt {
    pub delegation_hash: [u8; 32],
    pub agent: Did,
    pub owner: Did,
    /// 委托序号（防重放）。
    pub nonce: u64,
    pub max_per_spend: u64,
    pub total_cap: u64,
}

pub(crate) fn authorize(
    wallet: &AgentWallet,
    transport: &dyn Transport,
    owner_key: &OwnerSigningKey,
    agent: Did,
    limits: &DelegationLimits,
    delegation_nonce: u64,
    authorized: &RwLock<HashMap<[u8; 32], (Did, SignedDelegation)>>,
) -> Result<AuthorizeReceipt, SdkError> {
    // 1. 构造 + 本地校验（限额自洽 → 规格错误码透传）。
    let sd = create_delegation(owner_key, agent, delegation_nonce, limits)
        .map_err(SdkError::Meridian)?;
    let dh = delegation_hash(&sd.delegation);
    let owner = sd.delegation.owner;

    // 2. 传输注册（失败不落本地状态；未做本地幂等——非消费操作，重发无害）。
    transport.authorize(sd.clone(), wallet.agent_pub())?;

    // 3. 本地记录：agent DID（pay 构造 intent）+ SignedDelegation（prover 入参）。
    authorized
        .write()
        .expect("authorized poisoned")
        .insert(dh, (agent, sd));

    Ok(AuthorizeReceipt {
        delegation_hash: dh,
        agent,
        owner,
        nonce: delegation_nonce,
        max_per_spend: limits.max_per_spend,
        total_cap: limits.total_cap,
    })
}
