//! 意图信封与回执（TECH_SPEC §6.1/6.2）。

use mist_core::dsa::{AgentSignature, SpendIntent};
use mist_core::error::Error;
use mist_core::zk::SpendProof;

/// 意图信封（§6.1）。比 spec 伪代码多带 `agent_sig`：§6.2 摄入管线第一步是
/// "验签（Ed25519 快路径）"——这是证明前的廉价 DoS 闸门，必须由信封携带 S-02 传输层签名。
#[derive(Debug, Clone)]
pub struct IntentEnvelope {
    pub intent: SpendIntent,
    pub agent_sig: AgentSignature,
    pub proof: SpendProof,
}

/// 摄取回执（§6.2）。`seq` = 入承诺的摄取序号（单调）；拒绝的意图 seq = 0（不进承诺）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub intent_hash: [u8; 32],
    pub accepted: bool,
    pub reject_reason: Option<Error>,
    pub seq: u64,
}

impl Receipt {
    pub(crate) fn rejected(intent_hash: [u8; 32], reason: Error) -> Self {
        Receipt {
            intent_hash,
            accepted: false,
            reject_reason: Some(reason),
            seq: 0,
        }
    }

    pub(crate) fn accepted(intent_hash: [u8; 32], seq: u64) -> Self {
        Receipt {
            intent_hash,
            accepted: true,
            reject_reason: None,
            seq,
        }
    }
}
