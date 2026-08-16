//! 聚合器 ingest 基准（PoC ②，TECH_SPEC §8.2 口径）：单线程完整管线吞吐。
//!
//! criterion 会多次调用同一闭包 —— 若按"单笔"iter，nonce 防重放会在批次耗尽后
//! 全部走 Err 快路径，数字失真。因此**每次 iter 用全新 `ShardedIngest` 处理整个
//! 固定批次**（nonce 集/账本不跨次），criterion 用 `Throughput::Elements(批次大小)`
//! 折算成 ops/s。多线程放大见 `bin/poc_aggregator`（10 万笔/秒验收）。

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use meridian_bench::ingest::{Batch, FixtureParams, ShardedIngest};

fn bench_aggregator_ingest(c: &mut Criterion) {
    // 32 代理 × 512 意图 = 16_384 笔；一次整批 ~0.4s，criterion 自适应到 ~5s。
    let batch = Batch::build(FixtureParams {
        n_agents: 32,
        per_agent: 512,
    });
    let total = batch.items.len() as u64;
    let mut group = c.benchmark_group("aggregator");
    group.throughput(Throughput::Elements(total));
    group.bench_function("ingest_batch", |b| {
        b.iter(|| {
            let ingest = ShardedIngest::new();
            for (i, intent, sig) in &batch.items {
                let a = &batch.agents[*i];
                black_box(ingest.process(&a.delegation, &a.agent_pub, intent, sig, batch.now))
                    .expect("fixture intents are valid and unique");
            }
        });
    });
    group.finish();
}

criterion_group!(aggregator, bench_aggregator_ingest);
criterion_main!(aggregator);
