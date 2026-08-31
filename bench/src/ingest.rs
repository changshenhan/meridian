//! PoC ② 聚合器 ingest 原型（TECH_SPEC §6.2 摄取快路径的 Phase 0 形态）。
//!
//! 蓝图 Phase 0 交付物："聚合器 10 万笔/秒吞吐原型"。本模块是**原型**——
//! S-10 才建生产内核（tokio/rayon + WAL + commitment lattice）。这里只证明
//! "验签 → 并发 nonce 去重 → 分片账本记账"这条管线在多核上能到 10 万笔/秒。
//!
//! 管线（与 mcp-server state.rs::pay 同构，去掉了 MCP 壳与回执构造）：
//!   1. intent ↔ 委托绑定（agent 一致）
//!   2. agent Ed25519 验签（stateless，可并行——吞吐的放大来源）
//!   3. nonce 防重放（按 delegation_hash 分片，64 片并发）
//!   4. 预算检查 + 记账（core `ShardedLedger`，64 片，本就线程安全）
//!
//! TEMPORARY（与 S-07 同口径）：无 ZK 证明。S-09 在此插入 `verify_proof`。
//! 这里的 nonce 分片是原型形态；生产内核的 nonce 去重会并入账本分片或 WAL。

use std::collections::HashSet;
use std::sync::Mutex;

use ed25519_dalek::{
    Signature as AgentSignature, SigningKey as AgentSigningKey, VerifyingKey as AgentPubKey,
};
use mist_core::dsa::{verify_intent, Delegation, SpendIntent};
use mist_core::error::Error;
use mist_core::ledger::ShardedLedger;

/// nonce 防重放分片数。128 代理 × 2000 意图 → 不同代理的 dh 均匀落片。
pub const NONCE_SHARDS: usize = 64;
/// 账本分片数（core ShardedLedger）。
pub const LEDGER_SHARDS: usize = 64;

/// nonce 防重放集的单个分片。
type NonceShard = Mutex<HashSet<([u8; 32], u64)>>;

/// 单进程、多核并行的 ingest 原型。
pub struct ShardedIngest {
    nonces: Vec<NonceShard>,
    ledger: ShardedLedger,
}

impl ShardedIngest {
    pub fn new() -> Self {
        let mut nonces = Vec::with_capacity(NONCE_SHARDS);
        for _ in 0..NONCE_SHARDS {
            nonces.push(Mutex::new(HashSet::new()));
        }
        Self {
            nonces,
            ledger: ShardedLedger::new(LEDGER_SHARDS),
        }
    }

    fn nonce_shard(dh: &[u8; 32]) -> usize {
        u32::from_be_bytes([dh[0], dh[1], dh[2], dh[3]]) as usize % NONCE_SHARDS
    }

    /// 处理一笔意图（完整 ingest 快路径）。
    pub fn process(
        &self,
        delegation: &Delegation,
        agent_pub: &AgentPubKey,
        intent: &SpendIntent,
        sig: &AgentSignature,
        now: u64,
    ) -> Result<(), Error> {
        // 1. intent ↔ 委托绑定。
        if intent.agent != delegation.agent {
            return Err(Error::EIntentHash);
        }
        // 2. agent 签名（Ed25519 over intent_hash）。
        verify_intent(intent, sig, agent_pub)?;
        // 3. nonce 防重放（分片锁，片间并行）。
        let shard = Self::nonce_shard(&intent.delegation_hash);
        let mut set = self.nonces[shard].lock().expect("nonce shard poisoned");
        if !set.insert((intent.delegation_hash, intent.spend_nonce)) {
            return Err(Error::ENonce);
        }
        drop(set);
        // 4. 预算检查 + 记账（原子；分片锁在 ShardedLedger 内部）。
        self.ledger
            .check_and_apply(delegation.agent, delegation, intent.amount, now)
    }
}

impl Default for ShardedIngest {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// 固定输入（fixture）—— 确定性、可复现，供 PoC 二进制与 gate 复用。
// ---------------------------------------------------------------------------

/// 一个代理的委托夹具。`agent_key` 只在建批次时用于现场签名，不保留在夹具里。
#[derive(Debug, Clone)]
pub struct AgentFixture {
    pub delegation: Delegation,
    pub agent_pub: AgentPubKey,
    pub dh: [u8; 32],
}

/// 预生成的一批意图（每项 = 代理索引 + intent + agent 签名）。
pub struct Batch {
    pub agents: Vec<AgentFixture>,
    pub items: Vec<(usize, SpendIntent, AgentSignature)>,
    pub now: u64,
}

/// 夹具参数：代理数 × 每代理意图数。
#[derive(Debug, Clone, Copy)]
pub struct FixtureParams {
    pub n_agents: usize,
    pub per_agent: usize,
}

/// 每个 agent 的委托：金额 1，预算全放开（u64::MAX），验证管线为主、预算不挡路。
fn fixture_delegation(agent_idx: usize) -> Delegation {
    Delegation {
        agent: [1 + agent_idx as u8; 20],
        owner: [2u8; 20],
        nonce: agent_idx as u64,
        max_per_spend: 1,
        rate: mist_core::dsa::RateLimit {
            window_secs: u64::MAX,
            max_per_window: u64::MAX,
        },
        total_cap: u64::MAX,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
        version: mist_core::dsa::PROTOCOL_VERSION,
    }
}

impl Batch {
    /// 构建固定输入批次（确定性：密钥由固定 seed 派生，无随机数）。
    pub fn build(p: FixtureParams) -> Self {
        let mut agents = Vec::with_capacity(p.n_agents);
        let mut items = Vec::with_capacity(p.n_agents * p.per_agent);
        for i in 0..p.n_agents {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let agent_key = AgentSigningKey::from_bytes(&seed);
            let delegation = fixture_delegation(i);
            let dh = mist_core::dsa::delegation_hash(&delegation);
            // 先签名（借 agent_key），再把 agent_key 移入 fixture。
            for n in 1..=p.per_agent {
                let intent = SpendIntent {
                    agent: delegation.agent,
                    delegation_hash: dh,
                    recipient: [3u8; 20],
                    amount: 1,
                    category: [0xCD; 32],
                    spend_nonce: n as u64,
                    memo: None,
                    expires_at: u64::MAX,
                };
                let sig = mist_core::dsa::sign_intent(&intent, &agent_key);
                items.push((i, intent, sig));
            }
            agents.push(AgentFixture {
                dh,
                agent_pub: agent_key.verifying_key(),
                delegation,
            });
        }
        Batch {
            agents,
            items,
            now: 1_700_000_000,
        }
    }
}

/// 单线程顺序处理整个批次，返回 ops/sec。
/// 每次调用用全新 `ShardedIngest`（nonce 集/账本不跨次污染），结果确定。
pub fn measure_single_threaded(batch: &Batch) -> f64 {
    let ingest = ShardedIngest::new();
    let start = std::time::Instant::now();
    for (i, intent, sig) in &batch.items {
        let a = &batch.agents[*i];
        ingest
            .process(&a.delegation, &a.agent_pub, intent, sig, batch.now)
            .expect("fixture intents are valid and unique");
    }
    let elapsed = start.elapsed().as_secs_f64();
    batch.items.len() as f64 / elapsed
}

/// 多线程处理整个批次（W 个 worker 均分连续切片），返回 ops/sec。
/// 每个 worker 独立跑完整管线；ingest 共享（分片锁保证并发安全）。
pub fn measure_multi_threaded(batch: &Batch, workers: usize) -> f64 {
    let ingest = ShardedIngest::new();
    let n = batch.items.len();
    let chunk = n.div_ceil(workers);
    let start = std::time::Instant::now();
    std::thread::scope(|s| {
        for w in 0..workers {
            // 取引用再进 move 闭包：`&ShardedIngest` 是 Copy，各 worker 共享同一份。
            let ingest = &ingest;
            s.spawn(move || {
                let lo = (w * chunk).min(n);
                let hi = ((w + 1) * chunk).min(n);
                for idx in lo..hi {
                    let (i, intent, sig) = &batch.items[idx];
                    let a = &batch.agents[*i];
                    ingest
                        .process(&a.delegation, &a.agent_pub, intent, sig, batch.now)
                        .expect("fixture intents are valid and unique");
                }
            });
        }
    });
    let elapsed = start.elapsed().as_secs_f64();
    n as f64 / elapsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_is_valid_and_unique() {
        let p = FixtureParams {
            n_agents: 8,
            per_agent: 32,
        };
        let batch = Batch::build(p);
        assert_eq!(batch.items.len(), 8 * 32);
        // 每笔都能通过完整管线（单线程串一次，验证全链路）。
        let ingest = ShardedIngest::new();
        for (i, intent, sig) in &batch.items {
            let a = &batch.agents[*i];
            ingest
                .process(&a.delegation, &a.agent_pub, intent, sig, batch.now)
                .unwrap();
        }
        // 全批次入账后：每委托总额 = per_agent。
        for a in &batch.agents {
            assert_eq!(
                ingest.ledger.total_spent(&a.delegation.agent, &a.dh),
                Some(32)
            );
        }
    }

    #[test]
    fn replay_is_rejected() {
        let batch = Batch::build(FixtureParams {
            n_agents: 2,
            per_agent: 4,
        });
        let ingest = ShardedIngest::new();
        let (i, intent, sig) = &batch.items[0];
        let a = &batch.agents[*i];
        ingest
            .process(&a.delegation, &a.agent_pub, intent, sig, batch.now)
            .unwrap();
        assert_eq!(
            ingest.process(&a.delegation, &a.agent_pub, intent, sig, batch.now),
            Err(Error::ENonce)
        );
    }

    #[test]
    fn multi_threaded_matches_serial_total() {
        let batch = Batch::build(FixtureParams {
            n_agents: 16,
            per_agent: 64,
        });
        let ingest = ShardedIngest::new();
        let n = batch.items.len();
        let workers = 8;
        let chunk = n.div_ceil(workers);
        std::thread::scope(|s| {
            for w in 0..workers {
                let ingest = &ingest;
                let batch = &batch;
                s.spawn(move || {
                    let lo = (w * chunk).min(n);
                    let hi = ((w + 1) * chunk).min(n);
                    for idx in lo..hi {
                        let (i, intent, sig) = &batch.items[idx];
                        let a = &batch.agents[*i];
                        ingest
                            .process(&a.delegation, &a.agent_pub, intent, sig, batch.now)
                            .unwrap();
                    }
                });
            }
        });
        for a in &batch.agents {
            assert_eq!(
                ingest.ledger.total_spent(&a.delegation.agent, &a.dh),
                Some(64)
            );
        }
    }
}
