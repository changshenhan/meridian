//! B8 —— 热路径零分配门禁（TECH_SPEC §8.2）。
//! check_budget 是聚合器单笔处理热路径，必须零堆分配。

use meridian_bench::{section_allocs, NoAllocGuard};
use meridian_core::dsa::{delegation_hash, Delegation, RateLimit};
use meridian_core::ledger::{check_budget, BudgetState};

fn sample_delegation() -> Delegation {
    Delegation {
        agent: [1u8; 20],
        owner: [2u8; 20],
        nonce: 1,
        max_per_spend: 1,
        rate: RateLimit {
            window_secs: 60,
            max_per_window: u64::MAX,
        },
        total_cap: u64::MAX,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
        version: 1,
    }
}

#[test]
fn check_budget_allocates_nothing_on_hot_path() {
    let d = sample_delegation();
    let mut state = BudgetState::new(delegation_hash(&d), 0);

    // 预热（守卫之外，允许首调内的延迟分配被排除）
    for _ in 0..10_000 {
        let _ = check_budget(&d, &mut state, 1, 0);
    }

    let guard = NoAllocGuard::new();
    for _ in 0..10_000 {
        let _ = check_budget(&d, &mut state, 1, 0);
    }
    let allocs = section_allocs();
    drop(guard);

    assert_eq!(
        allocs, 0,
        "check_budget must allocate zero on the hot path (got {allocs})"
    );
}
