//! 账本基准（TECH_SPEC §8.2 B9）：预算检查 ops/s。

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use mist_core::dsa::{delegation_hash, Delegation, RateLimit};
use mist_core::ledger::{check_budget, BudgetState};

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

fn bench_check_budget(c: &mut Criterion) {
    let d = sample_delegation();
    let mut state = BudgetState::new(delegation_hash(&d), 0);
    let mut group = c.benchmark_group("ledger");
    group.throughput(Throughput::Elements(1));
    group.bench_function("check_budget", |b| {
        b.iter(|| {
            black_box(check_budget(
                black_box(&d),
                black_box(&mut state),
                black_box(1),
                black_box(0),
            ))
        })
    });
    group.finish();
}

criterion_group!(ledger, bench_check_budget);
criterion_main!(ledger);
