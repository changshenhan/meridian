//! Meridian L3 结算聚合器内核（MASTER_PLAN S-10）。
//!
//! 生产形态的 PoC ②：把原型（bench `ingest.rs`，验签→nonce→预算的吞吐管线）升级为
//! `Ingest`（验签快路径 → 验证明 → 预算检查 → 记账 → 入窗口）+ commitment lattice
//! （密封 → 上链 root → 按 `intent_hash` 确定性重排 → 净额生成）+ WAL 崩溃恢复。
//!
//! 与 PoC ② 原型的差异（S-10 决策，用户 2026-08-16）：
//! - `verify_proof` 落地为 `SpendVerifier` 接口（core §4.4 契约）；本 crate 内置
//!   `FormatVerifier`（TEMPORARY 格式校验后端，PoC ② 同口径）。真实 in-process bb wrapper
//!   是路线图单独交付物，实现该接口即可。
//! - nonce 去重并入账本分片（MASTER_PLAN S-10 注）：`ingest::ShardedState` 每分片
//!   (nonce 集 + BudgetState)，与 seq 分配同锁 → 同委托内 seq 序 == 账本应用序 → WAL 重放
//!   按 seq 排序可精确重建。
//! - 自写追加式 WAL（`wal.rs`），零重型 DB。

pub mod bb;
pub mod health;
pub mod hist;
pub mod ingest;
pub mod lattice;
pub mod merkle;
pub mod proof;
pub mod receipt;
pub mod revocation;
pub mod wal;
pub mod window;
pub mod wire;
