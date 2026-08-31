//! S-57 跨实现差分 fuzz（审计四步路径 ③，TECH_SPEC §8.3）：Rust 生产实现批量产
//! golden vectors → `contracts/test/fixtures/differential.json` → forge
//! `DifferentialTest` 逐条比对 Solidity 镜像（IntentHelper / Merkle / DSA sha256 /
//! nettingRoot / acceptanceLeaf——P2-3 第五契约，§6.23）。
//!
//! 设计钉子：
//! - **调生产实现**，不是测试替身——差分的意义就在两侧都是交付物本体。
//! - **splitmix64 固定种子**：跨平台确定性（纯 u64 wrapping 运算），fixture 逐字节
//!   稳定；verify.sh 步 8b 重生成后 `cmp` 入库版本做漂移闸。要更宽的输入面，改
//!   `SEED` 重生成并提交（TECH_SPEC §8.3 诚实边界）。
//! - **顶层并行数组**：forge-std 的 `parseJson*Array` 只吃扁平数组，嵌套对象得逐
//!   元素下标路径解析（64×8 次 cheatcode 调用），扁平化让 Solidity 侧一次拉全列。
//! - 零新依赖：随机数手写 splitmix64（不引 rand），JSON 走 rust-smoke 已有 serde_json。

use std::path::PathBuf;

use mist_aggregator::lattice::{abi_encode_net, netting_root, NetLine};
use mist_aggregator::merkle::{
    acceptance_leaf, inclusion_proof, leaf as merkle_leaf, merkle_root, EMPTY_LEAF,
};
use mist_core::dsa::{
    delegation_abi, delegation_hash, intent_hash, Delegation, RateLimit, SpendIntent,
};
use serde_json::{json, Value};

/// 固定种子（TECH_SPEC §8.3：输入面 = 种子的函数，改种子 = 换一批向量）。
const SEED: u64 = 0x4d_45_52_49_44_49_41_4e; // "MERIDIAN"

/// splitmix64：纯 u64 wrapping 运算，跨平台/跨版本位稳定。
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E_37_79_B9_7F_4A_7C_15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF_58_47_6D_1C_E4_E5_B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94_D0_49_BB_13_31_11_EB);
        z ^ (z >> 31)
    }

    /// [0, n) 均匀。
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// [0, len] 均匀。
    fn len_range(&mut self, len: usize) -> usize {
        self.below(len + 1)
    }
}

/// 边界值注入：每 `EDGE_PERIOD` 个向量塞一个已知边界，剩余全随机。
/// 差分 fuzz 的价值一半在边界——纯随机会漏掉补齐/溢出/端序分支。
const EDGE_PERIOD: usize = 6;
const EDGES: [u64; 6] = [0, 1, 0xffff_ffff, 1u64 << 32, 1u64 << 63, u64::MAX];

fn u64_with_edges(rng: &mut Rng, i: usize) -> u64 {
    if i % EDGE_PERIOD == EDGE_PERIOD - 1 {
        EDGES[(i / EDGE_PERIOD) % EDGES.len()]
    } else {
        rng.next_u64()
    }
}

fn rand_arr<const N: usize>(rng: &mut Rng) -> [u8; N] {
    core::array::from_fn(|_| (rng.next_u64() & 0xff) as u8)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2 + 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn concat_hex(chunks: &[[u8; 32]]) -> String {
    let mut all = Vec::with_capacity(chunks.len() * 32);
    for c in chunks {
        all.extend_from_slice(c);
    }
    hex(&all)
}

/// 面 1：`IntentHelper.computeIntentHash` ↔ `core::dsa::intent_hash`
/// （64 向量：偶数下标 memo 空 / 奇数 32B，每 6 个塞一个边界值）。
fn intents(rng: &mut Rng, n: usize) -> Value {
    let mut agent = Vec::with_capacity(n);
    let mut dh = Vec::with_capacity(n);
    let mut recipient = Vec::with_capacity(n);
    let mut amount = Vec::with_capacity(n);
    let mut category = Vec::with_capacity(n);
    let mut nonce = Vec::with_capacity(n);
    let mut memo = Vec::with_capacity(n);
    let mut expires = Vec::with_capacity(n);
    let mut hash = Vec::with_capacity(n);
    for i in 0..n {
        let intent = SpendIntent {
            agent: rand_arr(rng),
            delegation_hash: rand_arr(rng),
            recipient: rand_arr(rng),
            amount: u64_with_edges(rng, i),
            category: rand_arr(rng),
            spend_nonce: u64_with_edges(rng, i.wrapping_add(1)),
            memo: (i % 2 == 1).then(|| rand_arr(rng)),
            expires_at: u64_with_edges(rng, i.wrapping_add(2)),
        };
        agent.push(hex(&intent.agent));
        dh.push(hex(&intent.delegation_hash));
        recipient.push(hex(&intent.recipient));
        amount.push(intent.amount);
        category.push(hex(&intent.category));
        nonce.push(intent.spend_nonce);
        // forge-std 的 parseJsonBytesArray 要求 hex 前缀——空 memo 写 "0x"（不是 ""）。
        memo.push(intent.memo.map_or_else(|| "0x".to_string(), |m| hex(&m)));
        expires.push(intent.expires_at);
        hash.push(hex(&intent_hash(&intent)));
    }
    json!({
        "agent": agent, "delegationHash": dh, "recipient": recipient, "amount": amount,
        "category": category, "spendNonce": nonce, "memo": memo, "expiresAt": expires,
        "hash": hash,
    })
}

/// 面 2：`DSA.sha256(delegationABI)` + owner 切片 [26:46] ↔ `delegation_hash` /
/// `delegation_abi`（32 向量，categories 0..3 变长）。
fn delegations(rng: &mut Rng, n: usize) -> Value {
    let mut abi = Vec::with_capacity(n);
    let mut hash = Vec::with_capacity(n);
    let mut owner = Vec::with_capacity(n);
    for i in 0..n {
        let d = Delegation {
            agent: rand_arr(rng),
            owner: rand_arr(rng),
            nonce: u64_with_edges(rng, i),
            max_per_spend: u64_with_edges(rng, i.wrapping_add(1)),
            rate: RateLimit {
                window_secs: u64_with_edges(rng, i.wrapping_add(2)),
                max_per_window: u64_with_edges(rng, i.wrapping_add(3)),
            },
            total_cap: u64_with_edges(rng, i.wrapping_add(4)),
            categories: (0..rng.len_range(3)).map(|_| rand_arr(rng)).collect(),
            not_before: u64_with_edges(rng, i.wrapping_add(5)),
            expires_at: u64_with_edges(rng, i.wrapping_add(6)),
            version: (rng.next_u64() & 0xff) as u8,
        };
        abi.push(hex(&delegation_abi(&d)));
        hash.push(hex(&delegation_hash(&d)));
        owner.push(hex(&d.owner));
    }
    json!({ "abi": abi, "hash": hash, "owner": owner })
}

/// 树计数刻意混入非 2 幂——补齐分支（EMPTY_LEAF）是两侧错配的高发处。
const TREE_COUNTS: [usize; 10] = [1, 2, 3, 4, 5, 7, 8, 11, 13, 16];

/// 树深面计数（含 0/1 边界与 next_power_of_two 跳变点 15/16/17）。
const DEPTH_COUNTS: [u64; 11] = [0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17];

/// 面 3：`Merkle.leaf` / `merkle_root` / `Merkle.computeRoot`（链上重推包含证明）。
fn merkle(rng: &mut Rng) -> (Value, Value, Value, Value) {
    let mut seq = Vec::new();
    let mut ih = Vec::new();
    let mut leaf = Vec::new();
    for i in 0..8 {
        let s = match i {
            0 => 0, // 边界：seq 0
            1 => u64::MAX,
            _ => rng.next_u64(),
        };
        let h = rand_arr(rng);
        seq.push(s);
        ih.push(hex(&h));
        leaf.push(hex(&merkle_leaf(s, h)));
    }

    let mut t_count = Vec::new();
    let mut t_leaves = Vec::new();
    let mut t_root = Vec::new();
    let mut p_count = Vec::new();
    let mut p_index = Vec::new();
    let mut p_leaf = Vec::new();
    let mut p_siblings = Vec::new();
    let mut p_root = Vec::new();
    for &n in TREE_COUNTS.iter() {
        let leaves: Vec<[u8; 32]> = (0..n).map(|_| rand_arr(rng)).collect();
        let root = merkle_root(&leaves);
        t_count.push(n);
        t_leaves.push(concat_hex(&leaves));
        t_root.push(hex(&root));
        let index = rng.below(n);
        let (_, siblings) =
            inclusion_proof(&leaves, index).expect("index 由 below(n) 产出必在界内");
        p_count.push(n);
        p_index.push(index);
        p_leaf.push(hex(&leaves[index]));
        p_siblings.push(concat_hex(&siblings));
        p_root.push(hex(&root));
    }
    (
        json!({ "seq": seq, "intentHash": ih, "leaf": leaf }),
        json!({ "count": t_count, "leaves": t_leaves, "root": t_root }),
        json!({
            "count": p_count, "index": p_index, "leaf": p_leaf,
            "siblings": p_siblings, "root": p_root,
        }),
        json!({
            "count": DEPTH_COUNTS,
            // log2(next_power_of_two(n))，n<=1 → 0；p 是 2 的幂 → trailing_zeros 即 log2。
            "expect": DEPTH_COUNTS
                .iter()
                .map(|&n| {
                    let p = if n <= 1 { 1 } else { n.next_power_of_two() };
                    p.trailing_zeros() as u64
                })
                .collect::<Vec<_>>(),
        }),
    )
}

/// 面 5：`Merkle.acceptanceLeaf` ↔ `merkle::acceptance_leaf`（P2-3 §6.23 接受锚叶，
/// 22B 原像 sha256("ACCV1\0" ‖ seq_le ‖ acceptedAt_le)——kind3/4 时间守卫的锚定叶面；
/// S-57 第五契约）。8 向量：seq/acceptedAt 各含 0 与 u64::MAX 边界（0 = 未锚哨兵，
/// 时间守卫对 0 恒不成立——恰是要逐字节锁死的分支）。
fn acceptance_leaves(rng: &mut Rng) -> Value {
    let mut seq = Vec::new();
    let mut accepted_at = Vec::new();
    let mut leaf = Vec::new();
    for i in 0..8 {
        let s = match i {
            0 => 0, // 边界：seq 0
            1 => u64::MAX,
            _ => rng.next_u64(),
        };
        let a = match i {
            0 => 0, // 边界：acceptedAt 0（未锚哨兵）
            1 => u64::MAX,
            _ => rng.next_u64(),
        };
        seq.push(s);
        accepted_at.push(a);
        leaf.push(hex(&acceptance_leaf(s, a)));
    }
    json!({ "seq": seq, "acceptedAt": accepted_at, "leaf": leaf })
}

/// 面 4：`nettingRoot = keccak256(abi.encode(net))` ↔ `abi_encode_net` /
/// `netting_root`（16 向量，1..8 行，含零地址 / 全 ff / 零额 / u64::MAX 边界）。
/// 同时锁**编码字节**（比根更强：根失配时能定位到编码层）。
fn netting(rng: &mut Rng, n: usize) -> Value {
    let mut count = Vec::with_capacity(n);
    let mut recipient = Vec::new();
    let mut amount = Vec::new();
    let mut encoding = Vec::with_capacity(n);
    let mut root = Vec::with_capacity(n);
    for i in 0..n {
        let lines = 1 + i % 8;
        count.push(lines as u64);
        let mut net = Vec::with_capacity(lines);
        for j in 0..lines {
            let r = if i % EDGE_PERIOD == EDGE_PERIOD - 1 && j == 0 {
                // 边界：abi.encode 左补 12B 的两个极端（零地址 / 全 ff）。
                if i % 2 == 0 {
                    [0u8; 20]
                } else {
                    [0xff; 20]
                }
            } else {
                rand_arr(rng)
            };
            let a = u64_with_edges(rng, i.wrapping_add(j));
            recipient.push(hex(&r));
            amount.push(a);
            net.push(NetLine {
                recipient: r,
                amount: a,
            });
        }
        encoding.push(hex(&abi_encode_net(&net)));
        root.push(hex(&netting_root(&net)));
    }
    json!({
        "count": count, "recipient": recipient, "amount": amount,
        "encoding": encoding, "root": root,
    })
}

fn main() {
    let mut out_path = PathBuf::from("target/differential.json");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--out" {
            out_path = PathBuf::from(args.next().expect("--out 需要路径参数"));
        }
    }

    let mut rng = Rng(SEED);
    let (leaves, trees, proofs, depths) = merkle(&mut rng);
    let acc_leaves = acceptance_leaves(&mut rng);
    // 产出顺序固定（merkle → acceptance_leaves → intents → delegations → net）= 种子
    // 到向量的确定性映射。
    let intents = intents(&mut rng, 64);
    let delegations = delegations(&mut rng, 32);
    let net = netting(&mut rng, 16);

    // serde_json 缺省 Map = BTreeMap（键排序）→ 输出逐字节确定，无 preserve_order 依赖。
    let doc = json!({
        "seed": SEED,
        "intents": intents,
        "delegations": delegations,
        "merkleLeaves": leaves,
        "merkleTrees": trees,
        "merkleProofs": proofs,
        "merkleDepths": depths,
        "merkleEmptyRoot": hex(&EMPTY_LEAF),
        "acceptanceLeaves": acc_leaves,
        "netCases": net,
    });

    if let Some(dir) = out_path.parent() {
        std::fs::create_dir_all(dir).expect("创建输出目录失败");
    }
    std::fs::write(&out_path, doc.to_string()).expect("写 fixture 失败");
    println!(
        "difffuzz: 64 intents + 32 delegations + 8 leaves + 10 trees/proofs + 11 depths + 8 acceptance leaves + 16 net vectors -> {}",
        out_path.display()
    );
}
