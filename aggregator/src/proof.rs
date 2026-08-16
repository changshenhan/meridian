//! 证明验证后端（MASTER_PLAN S-10 决策，用户 2026-08-16）。
//!
//! `verify_proof` 落地为 core §4.4 的 `SpendVerifier` 接口；本模块提供后端：
//! - `FormatVerifier`（TEMPORARY）：proof 字节非空即通过，原样返回公共输入。
//!   真实后端是 S-09 电路的 in-process 验证包装（路线图单独交付物，TECH_SPEC §5.3
//!   "Rust 侧封装"），实现 `SpendVerifier` 插此即可。B5 测全管线时它把 proof 阶段做成
//!   与 PoC ② 同口径的格式门禁（诚实口径见 §8.2 注记；带真 ZK 的吞吐回填 §5.4）。
//! - `RejectAllVerifier`：恒拒，负向测试用。
//!
//! `check_public_inputs_consistent`：管线在 `verify` 之后把 `SpendPublicInputs` 与信封内
//! intent 逐字段比对——"登记以验证器返回值为准"（§9），但返回的公共输入不能与信封自相矛盾。

use meridian_core::dsa::SpendIntent;
use meridian_core::error::Error;
use meridian_core::zk::{SpendProof, SpendPublicInputs, SpendVerifier};

/// 格式校验后端（TEMPORARY）：proof 非空即过，原样返回公共输入。无密码学验证。
#[derive(Debug, Clone, Copy, Default)]
pub struct FormatVerifier;

impl SpendVerifier for FormatVerifier {
    fn verify(&self, proof: &SpendProof) -> Result<SpendPublicInputs, Error> {
        if proof.proof.is_empty() {
            return Err(Error::EProof);
        }
        Ok(proof.public_inputs.clone())
    }
}

/// 恒拒后端（负向测试用：验证明这一环必须挡下）。
#[derive(Debug, Clone, Copy, Default)]
pub struct RejectAllVerifier;

impl SpendVerifier for RejectAllVerifier {
    fn verify(&self, _proof: &SpendProof) -> Result<SpendPublicInputs, Error> {
        Err(Error::EProof)
    }
}

/// 公共输入与信封内 intent 的一致性（共享字段逐一比对）。
/// 不一致即 `E_ORDERING` 级矛盾——信封与证明声称的不是同一笔意图。
pub fn check_public_inputs_consistent(
    pi: &SpendPublicInputs,
    intent: &SpendIntent,
) -> Result<(), Error> {
    if pi.delegation_hash != intent.delegation_hash
        || pi.recipient != intent.recipient
        || pi.amount != intent.amount
        || pi.category != intent.category
        || pi.spend_nonce != intent.spend_nonce
        || pi.expires_at != intent.expires_at
    {
        return Err(Error::EOrdering);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use meridian_core::zk::SpendProof;

    fn pi() -> SpendPublicInputs {
        SpendPublicInputs {
            agent_commit: [0x01; 32],
            delegation_hash: [0x02; 32],
            recipient: [0x03; 20],
            amount: 42,
            category: [0x04; 32],
            spend_nonce: 7,
            expires_at: u64::MAX,
            revocation_root: [0x05; 32],
            now: 1_700_000_000,
        }
    }

    fn intent(dh: [u8; 32], recipient: [u8; 20], amount: u64, category: [u8; 32], nonce: u64, exp: u64) -> SpendIntent {
        SpendIntent {
            agent: [0x00; 20],
            delegation_hash: dh,
            recipient,
            amount,
            category,
            spend_nonce: nonce,
            memo: None,
            expires_at: exp,
        }
    }

    #[test]
    fn format_verifier_accepts_nonempty() {
        let f = FormatVerifier;
        let p = SpendProof {
            proof: vec![1, 2, 3],
            public_inputs: pi(),
        };
        assert_eq!(f.verify(&p).unwrap().amount, 42);
    }

    #[test]
    fn format_verifier_rejects_empty_proof() {
        let f = FormatVerifier;
        let p = SpendProof {
            proof: vec![],
            public_inputs: pi(),
        };
        assert_eq!(f.verify(&p), Err(Error::EProof));
    }

    #[test]
    fn reject_all_verifier_always_rejects() {
        let r = RejectAllVerifier;
        let p = SpendProof {
            proof: vec![1],
            public_inputs: pi(),
        };
        assert_eq!(r.verify(&p), Err(Error::EProof));
    }

    #[test]
    fn consistency_ok_when_mirror() {
        let p = pi();
        let i = intent(p.delegation_hash, p.recipient, p.amount, p.category, p.spend_nonce, p.expires_at);
        assert_eq!(check_public_inputs_consistent(&p, &i), Ok(()));
    }

    #[test]
    fn consistency_rejects_mismatched_delegation_hash() {
        let p = pi();
        let i = intent([0x99; 32], p.recipient, p.amount, p.category, p.spend_nonce, p.expires_at);
        assert_eq!(check_public_inputs_consistent(&p, &i), Err(Error::EOrdering));
    }

    #[test]
    fn consistency_rejects_mismatched_amount() {
        let p = pi();
        let i = intent(p.delegation_hash, p.recipient, p.amount + 1, p.category, p.spend_nonce, p.expires_at);
        assert_eq!(check_public_inputs_consistent(&p, &i), Err(Error::EOrdering));
    }
}
