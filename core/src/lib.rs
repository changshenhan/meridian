//! Meridian core —— DSA 授权原语 + 预算账本 + 双钥绑定。
//!
//! 契约源：TECH_SPEC.md (v0.1)。任何行为偏差必须先改 spec 再改码。

pub mod attestation;
pub mod dsa;
pub mod error;
pub mod ledger;
