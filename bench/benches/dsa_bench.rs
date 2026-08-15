//! DSA 基准（TECH_SPEC §8.2 B1）：delegation 签名/验签、intent 签名/验签。

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use meridian_core::dsa::{self, AgentSigningKey, Delegation, RateLimit, SpendIntent};

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

fn sample_intent(dh: [u8; 32]) -> SpendIntent {
    SpendIntent {
        agent: [1u8; 20],
        delegation_hash: dh,
        recipient: [3u8; 20],
        amount: 1,
        category: [0xCD; 32],
        spend_nonce: 7,
        memo: None,
        expires_at: u64::MAX,
    }
}

fn bench_verify_delegation(c: &mut Criterion) {
    let owner_key = dsa::owner_signing_key_from_bytes([7u8; 32]);
    let d = sample_delegation();
    let sd = dsa::sign_delegation(&d, &owner_key);
    let vk = owner_key.verifying_key();
    let mut group = c.benchmark_group("dsa");
    group.throughput(Throughput::Elements(1));
    group.bench_function("verify_delegation", |b| {
        b.iter(|| black_box(dsa::verify_delegation(black_box(&sd), black_box(vk))))
    });
    group.bench_function("sign_delegation", |b| {
        b.iter(|| black_box(dsa::sign_delegation(black_box(&d), black_box(&owner_key))))
    });
    group.finish();
}

fn bench_intent_sign_verify(c: &mut Criterion) {
    let agent_key = AgentSigningKey::from_bytes(&[5u8; 32]);
    let i = sample_intent([0xAB; 32]);
    let sig = dsa::sign_intent(&i, &agent_key);
    let vk = agent_key.verifying_key();
    let mut group = c.benchmark_group("dsa");
    group.throughput(Throughput::Elements(1));
    group.bench_function("intent_sign", |b| {
        b.iter(|| black_box(dsa::sign_intent(black_box(&i), black_box(&agent_key))))
    });
    group.bench_function("intent_verify", |b| {
        b.iter(|| {
            black_box(dsa::verify_intent(
                black_box(&i),
                black_box(&sig),
                black_box(&vk),
            ))
        })
    });
    group.finish();
}

criterion_group!(dsa, bench_verify_delegation, bench_intent_sign_verify);
criterion_main!(dsa);
