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
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_code())
    }
}

impl std::error::Error for Error {}
