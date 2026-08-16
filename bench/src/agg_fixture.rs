//! S-10 生产内核验收 fixture（agg_sim / gate 共用，B5/B6/B7/B8/B10/B11）。
//!
//! 与 PoC ② 同构：固定 seed 派生密钥、零随机、预算全放开（验证管线为主、预算不挡路）。
//! 但信封携带生产内核所需的 `agent_sig`（Ed25519 快路径）+ `SpendProof`（FormatVerifier
//! 后端口径：public_inputs 与 intent 逐字段一致）。
//!
//! 确定性输入集快照锁在 `bench/data/s10_fixture.bin`——**params + 批次规范哈希**。
//! 加载时按 params 重新生成并校验哈希：任何生成器改动都会触发"fixture 漂移"报警，
//! `--gen-fixture` 重新快照（TECH_SPEC §8.1 "固定 seed、固定输入集、结果可复现"）。

use ed25519_dalek::{SigningKey as AgentSigningKey, VerifyingKey as AgentPubKey};
use meridian_aggregator::receipt::IntentEnvelope;
use meridian_core::dsa::{
    delegation_hash, owner_signing_key_from_bytes, sign_delegation, sign_intent, Delegation,
    RateLimit, SignedDelegation, SpendIntent, PROTOCOL_VERSION,
};
use meridian_core::zk::{SpendProof, SpendPublicInputs};
use sha2::{Digest, Sha256};

/// S-10 fixture 主 seed：所有 agent 密钥由 `seed ^ agent_idx` 确定性派生（agg_sim / gate 共用）。
pub const MASTER_SEED: u64 = 0x4D_45_52_49_44_49_41_4E; // "MERIDIAN"

/// fixture 参数：代理数 × 每代理意图数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelFixtureParams {
    pub n_agents: usize,
    pub per_agent: usize,
    /// 公共时钟（Unix 秒；intent.expires_at = now + 60）。
    pub now: u64,
    /// 主 seed：所有 agent 密钥由它确定性派生。
    pub seed: u64,
}

/// 一个代理的委托 + 密钥 + 已签委托（密钥只用于现场签名，不保留在文件快照里）。
#[derive(Debug, Clone)]
pub struct AgentFixture {
    pub delegation: Delegation,
    pub sd: SignedDelegation,
    pub dh: [u8; 32],
    pub agent_pub: AgentPubKey,
    pub key: AgentSigningKey,
}

/// 预生成的一批生产内核信封（intent + agent_sig + proof）。
#[derive(Debug, Clone)]
pub struct KernelBatch {
    pub agents: Vec<AgentFixture>,
    pub envs: Vec<IntentEnvelope>,
    pub now: u64,
    pub per_agent: usize,
}

/// 每代理的委托：金额 1、预算全放开（u64::MAX）、`categories` 空。
/// `categories: vec![]` 同时是 B8 关键：注册表 `lookup().cloned()` 克隆空 Vec 零分配。
fn delegation_for(agent_idx: usize) -> Delegation {
    Delegation {
        agent: [1 + agent_idx as u8; 20],
        owner: [2u8; 20],
        nonce: agent_idx as u64,
        max_per_spend: 1,
        rate: RateLimit {
            window_secs: u64::MAX,
            max_per_window: u64::MAX,
        },
        total_cap: u64::MAX,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
        version: PROTOCOL_VERSION,
    }
}

/// 每代理的收款方：前 4 字节 = agent_idx（LE），其余 = 0xAA。
/// 跨代理不同 → 净额聚合产生真实的多收款方净指令（B10 的 net[] 有意义）。
fn recipient_for(agent_idx: usize) -> [u8; 20] {
    let mut r = [0xAA; 20];
    r[..4].copy_from_slice(&(agent_idx as u32).to_le_bytes());
    r
}

impl KernelBatch {
    /// 确定性构建批次（密钥由 `seed ^ agent_idx` 派生，零随机）。
    pub fn build(p: KernelFixtureParams) -> Self {
        let mut agents = Vec::with_capacity(p.n_agents);
        let mut envs = Vec::with_capacity(p.n_agents * p.per_agent);
        for i in 0..p.n_agents {
            let mut key_seed = [0u8; 32];
            key_seed[..8].copy_from_slice(
                &(p.seed ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)).to_le_bytes(),
            );
            let agent_key = AgentSigningKey::from_bytes(&key_seed);
            let delegation = delegation_for(i);
            let dh = delegation_hash(&delegation);
            let sd = sign_delegation(&delegation, &owner_signing_key_from_bytes([7u8; 32]));
            let agent = delegation.agent;
            let recipient = recipient_for(i);
            for n in 1..=p.per_agent {
                let nonce = n as u64;
                let intent = SpendIntent {
                    agent,
                    delegation_hash: dh,
                    recipient,
                    amount: 1,
                    category: [0xCD; 32],
                    spend_nonce: nonce,
                    memo: None,
                    expires_at: p.now + 60,
                };
                let sig = sign_intent(&intent, &agent_key);
                let proof = SpendProof {
                    proof: vec![1, 2, 3],
                    public_inputs: SpendPublicInputs {
                        agent_commit: [0u8; 32],
                        delegation_hash: dh,
                        recipient,
                        amount: 1,
                        category: [0xCD; 32],
                        spend_nonce: nonce,
                        expires_at: intent.expires_at,
                        revocation_root: [0u8; 32],
                        now: p.now,
                    },
                };
                envs.push(IntentEnvelope {
                    intent,
                    agent_sig: sig,
                    proof,
                });
            }
            agents.push(AgentFixture {
                dh,
                sd,
                agent_pub: agent_key.verifying_key(),
                delegation,
                key: agent_key,
            });
        }
        KernelBatch {
            agents,
            envs,
            now: p.now,
            per_agent: p.per_agent,
        }
    }

    /// 一批的**规范哈希**：所有信封按确定性字节布局的顺序 sha256。
    /// 锁定"生成器输出"——任何字节级改动（密钥派生、字段、顺序）都会改变哈希。
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        for (i, env) in self.envs.iter().enumerate() {
            let agent_idx = i / self.per_agent;
            let mut buf = Vec::with_capacity(278);
            buf.extend_from_slice(&(agent_idx as u16).to_le_bytes());
            buf.extend_from_slice(&meridian_core::dsa::intent_hash(&env.intent));
            buf.extend_from_slice(&env.intent.delegation_hash);
            buf.extend_from_slice(&env.intent.recipient);
            buf.extend_from_slice(&env.intent.amount.to_le_bytes());
            buf.extend_from_slice(&env.intent.category);
            buf.extend_from_slice(&env.intent.spend_nonce.to_le_bytes());
            buf.extend_from_slice(&env.intent.expires_at.to_le_bytes());
            buf.extend_from_slice(&env.agent_sig.to_bytes());
            buf.extend_from_slice(&env.proof.public_inputs.now.to_le_bytes());
            buf.extend_from_slice(&env.proof.public_inputs.revocation_root);
            buf.extend_from_slice(&env.proof.public_inputs.agent_commit);
            h.update(&buf);
        }
        h.finalize().into()
    }
}

/// fixture 文件快照：magic + version + params + 批次规范哈希。
/// 64B 固定布局，LE 定序。`load` 只读 params，`verify` 重新生成校验哈希。
pub const FIXTURE_MAGIC: [u8; 4] = *b"S10F";
pub const FIXTURE_VERSION: u32 = 1;

impl KernelFixtureParams {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&FIXTURE_MAGIC);
        out.extend_from_slice(&FIXTURE_VERSION.to_le_bytes());
        out.extend_from_slice(&(self.n_agents as u32).to_le_bytes());
        out.extend_from_slice(&(self.per_agent as u32).to_le_bytes());
        out.extend_from_slice(&self.now.to_le_bytes());
        out.extend_from_slice(&self.seed.to_le_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<(Self, [u8; 32]), String> {
        if b.len() != 64 {
            return Err(format!("s10_fixture.bin: 期望 64B，实际 {}", b.len()));
        }
        if b[..4] != FIXTURE_MAGIC {
            return Err("s10_fixture.bin: magic 不匹配（非 S10F）".into());
        }
        if u32::from_le_bytes(b[4..8].try_into().unwrap()) != FIXTURE_VERSION {
            return Err("s10_fixture.bin: 版本不匹配".into());
        }
        let p = KernelFixtureParams {
            n_agents: u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize,
            per_agent: u32::from_le_bytes(b[12..16].try_into().unwrap()) as usize,
            now: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            seed: u64::from_le_bytes(b[24..32].try_into().unwrap()),
        };
        let hash: [u8; 32] = b[32..64].try_into().unwrap();
        Ok((p, hash))
    }
}

/// 组装快照文件字节：params + 批次哈希。
pub fn fixture_bytes(params: &KernelFixtureParams, batch: &KernelBatch) -> Vec<u8> {
    let mut out = params.to_bytes();
    out.extend_from_slice(&batch.canonical_hash());
    out
}

/// 从快照字节加载参数，并按参数重新生成批次后校验哈希。返回 (params, batch)。
/// 哈希不匹配 = 生成器漂移（密钥派生 / 布局 / 顺序改动）→ 显式报错，`--gen-fixture` 重照。
pub fn load_fixture(data: &[u8]) -> Result<(KernelFixtureParams, KernelBatch), String> {
    let (p, expect_hash) = KernelFixtureParams::from_bytes(data)?;
    let batch = KernelBatch::build(p);
    let got = batch.canonical_hash();
    if got != expect_hash {
        return Err(format!(
            "s10_fixture.bin 哈希漂移：生成器已改动。期望 {}，实际 {}\n  用 `agg_sim --gen-fixture` 重新快照。",
            hex_of(&expect_hash),
            hex_of(&got)
        ));
    }
    Ok((p, batch))
}

fn hex_of(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// 单线程顺序处理整个生产内核批次，返回 ops/sec（gate 吞吐基线，B5 口径的单线程变体）。
/// 每次调用全新 `Aggregator`（nonce/账本不跨次污染），结果确定；容量预置 + 可控时钟
/// 与 agg_sim 的 `new_agg` 同构，保证同一测量口径。
pub fn measure_kernel_single_threaded(batch: &KernelBatch) -> f64 {
    use meridian_aggregator::ingest::{Aggregator, IngestConfig};
    use meridian_aggregator::proof::FormatVerifier;
    use meridian_aggregator::wal::Wal;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    let cfg = IngestConfig {
        ledger_shards: 64,
        epoch_capacity: batch.envs.len() + 1024,
        epoch_secs: 60,
        wal_sync_every: 10_000_000, // 测量期间不 fsync（缓冲兜底，B8 口径）
        nonce_capacity_per_delegation: batch.per_agent + 64,
    };
    let mut wal_path = std::env::temp_dir();
    wal_path.push(format!("meridian-gate-kernel-{}.wal", std::process::id()));
    let _ = std::fs::remove_file(&wal_path);
    let wal = Wal::open(&wal_path, cfg.wal_sync_every).expect("gate kernel wal open");
    let clock = Arc::new(AtomicU64::new(batch.now));
    let agg = Aggregator::with_capacity_and_clock(
        cfg,
        Box::new(FormatVerifier),
        wal,
        Box::new({
            let clock = Arc::clone(&clock);
            move || clock.load(Ordering::Relaxed)
        }),
        batch.agents.len(),
        batch.envs.len(),
    );
    for a in &batch.agents {
        agg.register(a.sd.clone(), a.agent_pub);
    }
    let start = std::time::Instant::now();
    for env in &batch.envs {
        assert!(agg.submit(env).accepted, "kernel fixture intent rejected");
    }
    let elapsed = start.elapsed().as_secs_f64();
    batch.envs.len() as f64 / elapsed
}
