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
    /// 真验证后端不可用（S-40：bb 缺失 / 临时目录 / 进程 spawn 失败）——与 EProof 的
    /// 密码学拒绝区分，fail-closed，绝不静默降级回格式校验（TECH_SPEC §6.13）。
    EVerifyBackend,
    /// 证明生成失败（S-43：nargo/bb 缺失、witness 求解失败、交叉校验失配、撤销 witness
    /// 不自洽）——fail-closed，绝不降级回占位证明（TECH_SPEC §6.14）。
    EProver,
    /// 证明公共输入 `revocation_root` 不在聚合器撤销状态根集合（S-44 撤销根绑定闸，
    /// TECH_SPEC §6.2 / §4.6 残余③）——自选根的装饰性 ZK 拒绝，不耗 nonce / 窗口槽。
    ERevRoot,
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
            Error::EVerifyBackend => "E_VERIFY_BACKEND",
            Error::EProver => "E_PROVER",
            Error::ERevRoot => "E_REV_ROOT",
        }
    }

    /// 规格码的逆映射（S-29 wire 层 roundtrip 用；未知码返回 None）。
    pub fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "E_DELEG_EXPIRED" => Error::EDelegExpired,
            "E_DELEG_SIG" => Error::EDelegSig,
            "E_INTENT_SIG" => Error::EIntentSig,
            "E_PROOF" => Error::EProof,
            "E_BUDGET_PER_SPEND" => Error::EBudgetPerSpend,
            "E_BUDGET_RATE" => Error::EBudgetRate,
            "E_BUDGET_TOTAL" => Error::EBudgetTotal,
            "E_NONCE" => Error::ENonce,
            "E_REVOKED" => Error::ERevoked,
            "E_INTENT_EXPIRED" => Error::EIntentExpired,
            "E_INTENT_HASH" => Error::EIntentHash,
            "E_CATEGORY" => Error::ECategory,
            "E_SEQ" => Error::ESeq,
            "E_ORDERING" => Error::EOrdering,
            "E_ATTEST_BIND" => Error::EAttestBind,
            "E_DELEG_UNKNOWN" => Error::EDelegUnknown,
            "E_VERIFY_BACKEND" => Error::EVerifyBackend,
            "E_PROVER" => Error::EProver,
            "E_REV_ROOT" => Error::ERevRoot,
            _ => return None,
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_code())
    }
}

impl std::error::Error for Error {}
