//! Meridian 错误码（TECH_SPEC §11）。

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    EDelegExpired,
    EDelegSig,
    EIntentSig,
    EProof,
    EBudgetPerSpend,
    EBudgetRate,
    EBudgetTotal,
    ENonce,
    ERevoked,
    EIntentExpired,
    EIntentHash,
    ECategory,
    ESeq,
    EOrdering,
    /// 双钥绑定验证失败（S-05：Ed25519 对 attestation 公钥的绑定签名 / 承诺不匹配）。
    EAttestBind,
    /// 委托未注册（S-10：聚合器按 delegation_hash 查注册表，未注册拒绝）。
    EDelegUnknown,
}

impl Error {
    /// 规格 §11 的字符串码。
    pub fn as_code(self) -> &'static str {
        match self {
            Error::EDelegExpired => "E_DELEG_EXPIRED",
            Error::EDelegSig => "E_DELEG_SIG",
            Error::EIntentSig => "E_INTENT_SIG",
            Error::EProof => "E_PROOF",
            Error::EBudgetPerSpend => "E_BUDGET_PER_SPEND",
            Error::EBudgetRate => "E_BUDGET_RATE",
            Error::EBudgetTotal => "E_BUDGET_TOTAL",
            Error::ENonce => "E_NONCE",
            Error::ERevoked => "E_REVOKED",
            Error::EIntentExpired => "E_INTENT_EXPIRED",
            Error::EIntentHash => "E_INTENT_HASH",
            Error::ECategory => "E_CATEGORY",
            Error::ESeq => "E_SEQ",
            Error::EOrdering => "E_ORDERING",
            Error::EAttestBind => "E_ATTEST_BIND",
            Error::EDelegUnknown => "E_DELEG_UNKNOWN",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_code())
    }
}

impl std::error::Error for Error {}
