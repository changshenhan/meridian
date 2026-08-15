//! 预算账本（TECH_SPEC §4.5）—— 确定性速率/总额强制。
//! 设计决策：**ZK 证明授权，本账本执行预算。** 预算累计留在确定性账本，不进电路。

use std::collections::HashMap;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::dsa::{delegation_hash, Amount, Delegation, Did};
use crate::error::Error;

/// 每 (agent, delegation) 的预算记账状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetState {
    pub delegation_hash: [u8; 32],
    pub spent_in_window: Amount,
    pub window_start: u64, // unix 秒
    pub total_spent: Amount,
}

impl BudgetState {
    pub fn new(delegation_hash: [u8; 32], window_start: u64) -> Self {
        Self {
            delegation_hash,
            spent_in_window: 0,
            window_start,
            total_spent: 0,
        }
    }
}

/// 预算检查与记账（§4.5 规则 1-6，顺序不可交换）。
///
/// - 规则 1：委托有效期内（not_before ≤ now ≤ expires_at）。
/// - 规则 2：窗口回滚（now ≥ window_start + window_secs 时重置窗口计数）。
/// - 规则 3：单笔上限。
/// - 规则 4：窗口速率上限。
/// - 规则 5：累计总额上限。
/// - 规则 6：通过才记账。
pub fn check_budget(
    d: &Delegation,
    state: &mut BudgetState,
    amount: Amount,
    now: u64,
) -> Result<(), Error> {
    // 1. 有效期
    if now < d.not_before || now > d.expires_at {
        return Err(Error::EDelegExpired);
    }
    // 2. 窗口回滚
    if now >= state.window_start.saturating_add(d.rate.window_secs) {
        state.spent_in_window = 0;
        state.window_start = now;
    }
    // 3. 单笔上限
    if amount > d.max_per_spend {
        return Err(Error::EBudgetPerSpend);
    }
    // 4. 窗口速率（u128 防溢出）
    if state.spent_in_window as u128 + amount as u128 > d.rate.max_per_window as u128 {
        return Err(Error::EBudgetRate);
    }
    // 5. 累计总额
    if state.total_spent as u128 + amount as u128 > d.total_cap as u128 {
        return Err(Error::EBudgetTotal);
    }
    // 6. 记账
    state.spent_in_window += amount;
    state.total_spent += amount;
    Ok(())
}

/// 并发分片账本：分片键由 (agent, delegation_hash) 派生。
/// 每个分片单写者；不同分片可并行。
pub struct ShardedLedger {
    shards: Vec<Mutex<HashMap<[u8; 32], BudgetState>>>,
    shard_count: usize,
}

impl ShardedLedger {
    pub fn new(shard_count: usize) -> Self {
        let shard_count = shard_count.max(1);
        let shards = (0..shard_count)
            .map(|_| Mutex::new(HashMap::new()))
            .collect();
        Self {
            shards,
            shard_count,
        }
    }

    fn shard_of(agent: &Did, delegation_hash: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(agent);
        hasher.update(delegation_hash);
        hasher.finalize().into()
    }

    fn shard_index(key: &[u8; 32], shard_count: usize) -> usize {
        u32::from_be_bytes([key[0], key[1], key[2], key[3]]) as usize % shard_count
    }

    /// 原子地做"预算检查 + 记账"。delegation 的哈希必须与已有状态一致，
    /// 否则按全新委托记账（哈希绑定了委托内容，不会产生歧义）。
    pub fn check_and_apply(
        &self,
        agent: Did,
        delegation: &Delegation,
        amount: Amount,
        now: u64,
    ) -> Result<(), Error> {
        let dh = delegation_hash(delegation);
        let key = Self::shard_of(&agent, &dh);
        let idx = Self::shard_index(&key, self.shard_count);
        let mut map = self.shards[idx].lock().expect("shard poisoned");
        let state = map.entry(dh).or_insert_with(|| BudgetState::new(dh, now));
        check_budget(delegation, state, amount, now)
    }

    /// 只读：查询某委托累计支出。
    pub fn total_spent(&self, agent: &Did, delegation_hash: &[u8; 32]) -> Option<Amount> {
        let key = Self::shard_of(agent, delegation_hash);
        let idx = Self::shard_index(&key, self.shard_count);
        let map = self.shards[idx].lock().expect("shard poisoned");
        map.get(delegation_hash).map(|s| s.total_spent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::RateLimit;
    use proptest::prelude::*;

    fn delegation(max_per_spend: Amount, max_per_window: Amount, total_cap: Amount) -> Delegation {
        Delegation {
            agent: [1u8; 20],
            owner: [2u8; 20],
            nonce: 7,
            max_per_spend,
            rate: RateLimit {
                window_secs: 60,
                max_per_window,
            },
            total_cap,
            categories: vec![],
            not_before: 0,
            expires_at: u64::MAX,
            version: 1,
        }
    }

    // ------------------------------------------------------------------ 单元

    #[test]
    fn rejects_expired_delegation() {
        let d = delegation(1_000, 10_000, 100_000);
        let mut s = BudgetState::new(delegation_hash(&d), 0);
        // not_before=0 且现在远未来
        let mut late = d.clone();
        late.expires_at = 100;
        assert_eq!(
            check_budget(&late, &mut s, 1, 200),
            Err(Error::EDelegExpired)
        );
        // 尚未生效
        let mut early = d.clone();
        early.not_before = 500;
        assert_eq!(
            check_budget(&early, &mut s, 1, 100),
            Err(Error::EDelegExpired)
        );
    }

    #[test]
    fn rejects_above_per_spend() {
        let d = delegation(100, 10_000, 100_000);
        let mut s = BudgetState::new(delegation_hash(&d), 0);
        assert_eq!(
            check_budget(&d, &mut s, 101, 0),
            Err(Error::EBudgetPerSpend)
        );
        assert_eq!(check_budget(&d, &mut s, 100, 0), Ok(()));
    }

    #[test]
    fn rate_window_rolls_and_allows_again() {
        let d = delegation(1_000, 500, 100_000); // max_per_spend=1000（单笔不挡），窗口速率 500/60s
        let mut s = BudgetState::new(delegation_hash(&d), 0);
        assert_eq!(check_budget(&d, &mut s, 300, 10), Ok(()));
        // 超窗口速率
        assert_eq!(check_budget(&d, &mut s, 300, 11), Err(Error::EBudgetRate));
        // 窗口回滚（now >= 0+60）
        assert_eq!(check_budget(&d, &mut s, 300, 70), Ok(()));
        assert_eq!(s.spent_in_window, 300);
        assert_eq!(s.window_start, 70);
    }

    #[test]
    fn rejects_total_cap() {
        let d = delegation(1_000, 1_000, 500); // max_per_spend=1000（单笔不挡），总额 500
        let mut s = BudgetState::new(delegation_hash(&d), 0);
        assert_eq!(check_budget(&d, &mut s, 300, 0), Ok(()));
        assert_eq!(check_budget(&d, &mut s, 300, 1), Err(Error::EBudgetTotal));
    }

    #[test]
    fn applies_and_accumulates() {
        let d = delegation(100, 1_000, 100_000);
        let mut s = BudgetState::new(delegation_hash(&d), 0);
        for amt in [10u64, 20, 30] {
            check_budget(&d, &mut s, amt, 0).unwrap();
        }
        assert_eq!(s.spent_in_window, 60);
        assert_eq!(s.total_spent, 60);
    }

    // ------------------------------------------------------- property（参考模型对照）

    proptest! {
        #[test]
        fn budget_matches_reference_model(
            per_spend in 1u64..100_000,
            win_extra in 0u64..1_000_000,
            total_extra in 0u64..100_000_000,
            amounts in prop::collection::vec(0u64..200_000, 0..2000),
        ) {
            let max_per_spend = per_spend;
            let max_per_window = max_per_spend + win_extra;
            let total_cap = max_per_window + total_extra;
            let d = delegation(max_per_spend, max_per_window, total_cap);
            let mut state = BudgetState::new(delegation_hash(&d), 0);

            let mut ref_window: u128 = 0;
            let mut ref_total: u128 = 0;
            let mut ref_window_start: u64 = 0;

            for (i, amt) in amounts.into_iter().enumerate() {
                let now = i as u64 * 7;
                // 与实现同序的参考模型
                if now >= ref_window_start.saturating_add(d.rate.window_secs) {
                    ref_window = 0;
                    ref_window_start = now;
                }
                let expected = if now < d.not_before || now > d.expires_at {
                    Err(Error::EDelegExpired)
                } else if amt > d.max_per_spend {
                    Err(Error::EBudgetPerSpend)
                } else if ref_window + amt as u128 > d.rate.max_per_window as u128 {
                    Err(Error::EBudgetRate)
                } else if ref_total + amt as u128 > d.total_cap as u128 {
                    Err(Error::EBudgetTotal)
                } else {
                    Ok(())
                };

                let got = check_budget(&d, &mut state, amt, now);
                match expected {
                    Ok(()) => {
                        assert!(got.is_ok(), "expected Ok, got {:?} at i={i}", got);
                        ref_window += amt as u128;
                        ref_total += amt as u128;
                    }
                    Err(code) => {
                        assert_eq!(got, Err(code), "mismatch at i={i} amt={amt} now={now}");
                    }
                }
                assert_eq!(state.spent_in_window as u128, ref_window, "window drift at i={i}");
                assert_eq!(state.total_spent as u128, ref_total, "total drift at i={i}");
            }
        }
    }

    // ------------------------------------------------------------- 并发分片

    #[test]
    fn sharded_ledger_concurrent_same_delegation() {
        let d = delegation(1, u64::MAX, u64::MAX);
        let ledger = ShardedLedger::new(8);
        let agent = d.agent;
        let dh = delegation_hash(&d);
        std::thread::scope(|s| {
            for _ in 0..8 {
                let ledger = &ledger;
                let d = &d;
                s.spawn(move || {
                    for _ in 0..10_000 {
                        ledger.check_and_apply(agent, d, 1, 0).unwrap();
                    }
                });
            }
        });
        assert_eq!(ledger.total_spent(&agent, &dh), Some(80_000));
    }

    #[test]
    fn sharded_ledger_parallel_different_delegations() {
        let ledger = ShardedLedger::new(4);
        let agent = [0xAA; 20];
        std::thread::scope(|s| {
            for k in 0u8..16 {
                let mut d = delegation(1, u64::MAX, u64::MAX);
                d.nonce = k as u64;
                let ledger = &ledger;
                s.spawn(move || {
                    for _ in 0..5_000 {
                        ledger.check_and_apply(agent, &d, 1, 0).unwrap();
                    }
                });
            }
        });
        for k in 0u8..16 {
            let mut d = delegation(1, u64::MAX, u64::MAX);
            d.nonce = k as u64;
            assert_eq!(
                ledger.total_spent(&agent, &delegation_hash(&d)),
                Some(5_000)
            );
        }
    }
}
