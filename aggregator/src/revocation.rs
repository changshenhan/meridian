//! 撤销集 + 撤销稀疏 Merkle 根（MASTER_PLAN S-11，TECH_SPEC §4.6；S-34 收口碰撞、S-41 哈希对齐电路）。
//!
//! 撤销链上事件 1 epoch 内进入撤销根：`RevocationSet` 收集被撤销委托的 delegation_hash，
//! `sparse_root()` 把它压实成一个 32B 根，随下个密封 epoch 的 `ChainPublisher::commit`
//! 锚定到链（`BatchSettler.commit` 的 `revocationRoot` 参数）。
//!
//! **S-41 起与电路是同一棵树**（TECH_SPEC §4.6 定夺：改聚合器侧、电路不动）——哈希 = Noir
//! `std::hash::pedersen_hash`（`noir_pedersen.rs` 复现，bb 预计算生成器），叶子为 Field：
//! 空叶 = 0，撤销叶 = `encode_field(dh)`（低 31 字节 LE 截断，与 gen-witness 撤销叶同一编码）；
//! 空子树根表 `empty_roots[0] = 0`、`empty_roots[k] = pedersen_hash([E,E])` 逐层叠（与
//! gen-witness `compute_empty_roots` 同一迭代）。根的 32B 外形 = Field 的大端编码（bb 公共
//! 输入序列化口径，TECH_SPEC §6.13）——聚合器锚定根与电路 `revocation_root` 公共输入数值可比。
//!
//! 结构：深度 256 稀疏 Merkle。叶索引 = `dh` 全 32 字节的 LE u256（位 k =
//! `(dh[k/8] >> (k%8)) & 1`；第 d 层节点索引 = 索引右移 d）。空子树根表 `OnceLock` 预计算
//! （257 次哈希），插入时逐层上推 + 节点缓存，复杂度 O(256·|revoked|) 次哈希——只在密封
//! （每 epoch 一次）调用，撤销又是稀有事件，热路径（摄取/submit 闸口）不受影响（闸口是
//! 集合精确查找，与树无关）。代价记录：哈希从 sha256（SHA-NI）换成固定基 Grumpkin MSM
//! （每层 ~50µs 量级），S-41 时点比 sha256 版慢约 3 个数量级；perf gate 9 指标不含
//! sparse_root（TECH_SPEC §8.2 基线口径不动）。
//!
//! **S-34 碰撞收口**：S-11 原型版索引只取 `dh[0..4]`（32-bit 前缀）——两委托同前缀共享
//! 叶子、后写覆盖先写，锚定根只承诺其一（audit-scope §4 自报项）。改全 256-bit 索引后
//! `delegation_hash` 整体即索引，**相异 dh 必相异叶**。电路侧已于 S-36 同步全宽化（Noir
//! 撤销树 depth 256，同一派生同一位序，TECH_SPEC §5.3）。
//!
//! 验证锚（TECH_SPEC §4.6）：① Noir stdlib pedersen golden；② bb 预计算点过曲线方程
//! （均在 noir_pedersen.rs）；③ 空子树根表 + gen-witness fixture 全树根（本文件单测，
//! golden 由 Python 第三实现与 Noir nargo 输出交叉锁定）。

use std::collections::{HashMap, HashSet};
use std::sync::{OnceLock, RwLock};

use crate::noir_pedersen::{pedersen_hash2, Fe};

/// 稀疏树深度 = 撤销索引的位数（S-34：全 256-bit，`delegation_hash` 整体即索引）。
pub const SPARSE_DEPTH: usize = 256;

/// 节点索引右移一层（LE u256 语义的 `>> 1`：低位出树，高位下移）。
fn shr1(mut idx: [u8; 32]) -> [u8; 32] {
    for i in 0..31 {
        idx[i] = (idx[i] >> 1) | (idx[i + 1] << 7);
    }
    idx[31] >>= 1;
    idx
}

/// 截取索引低 `depth` 位（depth 参数化建树用；`depth == SPARSE_DEPTH` 时恒等）。
fn truncate_idx(mut idx: [u8; 32], depth: usize) -> [u8; 32] {
    let whole = depth / 8;
    if whole < 32 {
        for byte in idx.iter_mut().skip(whole + 1) {
            *byte = 0;
        }
        idx[whole] &= ((1u16 << (depth % 8)) - 1) as u8;
    }
    idx
}

/// 空子树根表：`empty_roots[0]` = 空叶（Field 0，电路 EMPTY 口径），
/// `empty_roots[k]` = 高度 k 的全空子树根（pedersen_hash 逐层叠，与 gen-witness
/// `compute_empty_roots` 同一迭代）。
fn empty_roots() -> &'static [Fe; SPARSE_DEPTH + 1] {
    static TABLE: OnceLock<[Fe; SPARSE_DEPTH + 1]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [Fe::zero(); SPARSE_DEPTH + 1];
        for k in 1..=SPARSE_DEPTH {
            t[k] = pedersen_hash2(t[k - 1], t[k - 1]);
        }
        t
    })
}

/// 撤销集合（读多写少，`RwLock`）。崩溃后由 WAL 的 Revoke 记录重放重建（S-11c）。
#[derive(Default)]
pub struct RevocationSet {
    set: RwLock<HashSet<[u8; 32]>>,
}

impl RevocationSet {
    pub fn new() -> Self {
        RevocationSet::default()
    }

    /// 容量预置（B8 口径：注册期预分配，稳态插入零分配）。
    pub fn with_capacity(cap: usize) -> Self {
        RevocationSet {
            set: RwLock::new(HashSet::with_capacity(cap)),
        }
    }

    /// 插入被撤销委托的 delegation_hash。返回是否新插入（重复撤销幂等）。
    pub fn insert(&self, dh: [u8; 32]) -> bool {
        self.set.write().expect("revocations poisoned").insert(dh)
    }

    /// submit 闸口：委托是否已撤销。
    pub fn is_revoked(&self, dh: &[u8; 32]) -> bool {
        self.set.read().expect("revocations poisoned").contains(dh)
    }

    pub fn len(&self) -> usize {
        self.set.read().expect("revocations poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.read().expect("revocations poisoned").is_empty()
    }

    /// 撤销集快照（dh 升序）。`state_digest`（§6.26）的规范序列化输入——HashSet 迭代序
    /// 不确定，必须排序后才可跨进程 / 跨副本比较。诊断面：`sparse_root()` 是密码学锚，
    /// digest 用廉价的排序列表（不付 MSM 成本）。
    pub fn sorted_revoked(&self) -> Vec<[u8; 32]> {
        let mut out: Vec<[u8; 32]> = self
            .set
            .read()
            .expect("revocations poisoned")
            .iter()
            .copied()
            .collect();
        out.sort_unstable();
        out
    }

    /// 当前集合的撤销树根（32B 大端 Field，电路 `revocation_root` 公共输入口径）。
    /// 空集 = 全空树根（深度 256 的确定性常量）。
    pub fn sparse_root(&self) -> [u8; 32] {
        let set = self.set.read().expect("revocations poisoned");
        build_nodes(&set, SPARSE_DEPTH).root()
    }

    /// 非成员 witness（S-42，TECH_SPEC §4.6 残余②前半）：目标 `dh` 处插入空叶（未撤销）
    /// 所需的 `root` + 兄弟路径。供 prover 侧出撤销 witness（候选①「真 prover」消费——
    /// 电路 §5.2 断言 8 吃 `path` 重算根、与公共输入 `revocation_root` 对账）。
    ///
    /// 与 [`Self::sparse_root`] 同一条压实实现（同一节点缓存、同一确定性），故 `root` 与
    /// `sparse_root()` 恒等。`path[d]` = 深度 d 层目标索引的兄弟子树根（BE Field 32B）；
    /// 兄弟分支为空时 = `empty_roots[d]`。方向约定与电路 `compute_merkle_root` 一致：
    /// 索引第 d 位为 0 → 当前节点是左孩子 → 重算取 `H(当前 ‖ path[d])`，为 1 取
    /// `H(path[d] ‖ 当前)`。
    ///
    /// 目标已在撤销集时返回 `None`——已撤销委托的叶子不是 `EMPTY`，其路径是**成员**证明，
    /// 不属于本接口语义（fail-closed：调用方不能拿成员路径冒充非成员）。
    pub fn non_membership_witness(&self, dh: &[u8; 32]) -> Option<NonMembershipWitness> {
        if self.is_revoked(dh) {
            return None;
        }
        let set = self.set.read().expect("revocations poisoned");
        Some(build_nodes(&set, SPARSE_DEPTH).path_for(dh))
    }
}

/// 非成员 witness（TECH_SPEC §4.6）：`root` + 深度 256 的兄弟路径。
/// `path[d]` 均为 BE Field 32B（电路 `revocation_path` witness 同口径）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonMembershipWitness {
    pub root: [u8; 32],
    pub path: Vec<[u8; 32]>,
}

/// S-43：聚合器产出 → prover 请求消费的契约类型转换（TECH_SPEC §6.14）。
/// 字段同构（root + BE Field 32B 路径），单一转换点防两处口径漂移。
impl From<NonMembershipWitness> for mist_core::zk::RevocationWitness {
    fn from(w: NonMembershipWitness) -> Self {
        mist_core::zk::RevocationWitness {
            root: w.root,
            path: w.path,
        }
    }
}

/// 压实树的部分节点缓存：`(深度 d, 该深度节点索引) → 子树根`（d 从 0 叶层到 depth 根层）。
/// `sparse_root` 与 `non_membership_witness` 共用——保证根与路径出自同一棵确定性树。
struct NodeCache {
    nodes: HashMap<(usize, [u8; 32]), Fe>,
    depth: usize,
}

impl NodeCache {
    fn root(&self) -> [u8; 32] {
        // 空集缓存为空 → 全空树根（build_root 原口径）；非空集必达根层节点。
        self.nodes
            .get(&(self.depth, [0u8; 32]))
            .copied()
            .unwrap_or(empty_roots()[self.depth])
            .to_be_bytes()
    }

    /// 沿目标索引自叶向根取兄弟子树根（`path[d]`）。
    fn path_for(&self, target: &[u8; 32]) -> NonMembershipWitness {
        let empty = empty_roots();
        let mut idx = truncate_idx(*target, self.depth);
        let mut path = Vec::with_capacity(self.depth);
        for (d, empty_root) in empty.iter().enumerate().take(self.depth) {
            let mut sib = idx;
            sib[0] ^= 1; // 兄弟索引 = 本层索引翻转最低位（LE u256 的第 d 位）
            path.push(nodes_get(&self.nodes, d, sib, *empty_root).to_be_bytes());
            idx = shr1(idx);
        }
        NonMembershipWitness {
            root: self.root(),
            path,
        }
    }
}

/// 节点缓存查询：命中已压实分支用缓存，否则该兄弟分支全空 → `empty_roots[d]`。
fn nodes_get(nodes: &HashMap<(usize, [u8; 32]), Fe>, d: usize, sib: [u8; 32], empty: Fe) -> Fe {
    nodes.get(&(d, sib)).copied().unwrap_or(empty)
}

/// 建树：逐撤销叶自叶向根上推 + 节点缓存（`sparse_root` / `non_membership_witness` 共用）。
fn build_nodes(set: &HashSet<[u8; 32]>, depth: usize) -> NodeCache {
    let empty = empty_roots();
    if set.is_empty() {
        // 空集：无撤销叶可上推，全部节点 = 空子树根（path_for 的缓存查询同样兜到 empty）。
        return NodeCache {
            nodes: HashMap::new(),
            depth,
        };
    }
    let mut nodes: HashMap<(usize, [u8; 32]), Fe> = HashMap::with_capacity(depth * set.len());
    for dh in set.iter() {
        let mut idx = truncate_idx(*dh, depth);
        let mut value = Fe::encode_field_le31(dh); // 撤销叶 = encode_field(dh)（电路/gen-witness 同编码）
        nodes.insert((0, idx), value); // 叶层节点也必须登记：相邻撤销叶互作兄弟时要能找到
        for (d, empty_root) in empty[..depth].iter().enumerate() {
            let mut sib = idx;
            sib[0] ^= 1; // 兄弟索引 = 本层索引翻转最低位（LE u256 的第 d 位）
            let sibling = nodes_get(&nodes, d, sib, *empty_root);
            value = if sib[0] & 1 == 1 {
                // 本层第 d 位为 0 → 当前节点是左孩子 → H(当前 ‖ 兄弟)
                pedersen_hash2(value, sibling)
            } else {
                pedersen_hash2(sibling, value)
            };
            idx = shr1(idx);
            nodes.insert((d + 1, idx), value);
        }
    }
    NodeCache { nodes, depth }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn dh(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// 深度 256 全空树根锁定（Python 第三实现 + Noir gen-witness `compute_empty_roots`
    /// 双向交叉，TECH_SPEC §4.6 验证锚③）。
    #[test]
    fn empty_root_matches_golden() {
        let root = RevocationSet::new().sparse_root();
        assert_eq!(
            hex::encode(root),
            "19f94e515e40bf63756ea194d2a64dda55a255f3ea6c70dcf68f39f1765631ca"
        );
    }

    /// 空子树根表逐层与 Noir golden 锁定（gen-witness `revocation_empty_roots_match_aggregator_golden`
    /// 反向断言同一组常量）。
    #[test]
    fn empty_roots_table_matches_noir_golden() {
        let empty = empty_roots();
        let cases: [(usize, &str); 5] = [
            (
                1,
                "27b1d0839a5b23baf12a8d195b18ac288fcf401afb2f70b8a4b529ede5fa9fed",
            ),
            (
                2,
                "21dbfd1d029bf447152fcf89e355c334610d1632436ba170f738107266a71550",
            ),
            (
                3,
                "0bcd1f91cf7bdd471d0a30c58c4706f3fdab3807a954b8f5b5e3bfec87d001bb",
            ),
            (
                8,
                "0cd8d5695bc2dde99dd531671f76f1482f14ddba8eeca7cb9686d4a62359c257",
            ),
            (
                16,
                "1864fcdaa80ff2719154fa7c8a9050662972707168d69eac9db6fd3110829f80",
            ),
        ];
        for (k, want) in cases {
            assert_eq!(
                hex::encode(empty[k].to_be_bytes()),
                want,
                "empty_roots[{k}]"
            );
        }
    }

    /// **全树交叉（最强锚）**：gen-witness fixture（撤销集 {`0x01…32`, `0x02…32`}，撤销叶 =
    /// encode_field）的 `revocation_root`——Rust 聚合器树与 Noir `nargo execute` 输出必须
    /// 相等（Python 第三实现同值，TECH_SPEC §4.6 验证锚③）。
    #[test]
    fn gen_witness_fixture_root_matches_noir() {
        let rs = RevocationSet::new();
        rs.insert([0x01; 32]);
        rs.insert([0x02; 32]);
        assert_eq!(
            hex::encode(rs.sparse_root()),
            "092fca75790d95bddddd0b1995d54253c7677ee1e798d6ee4c6d251b9f2d8621"
        );
    }

    /// 空集根 = 全空树根；插入后根变化；再插入同 dh 幂等（根不变）。
    #[test]
    fn root_is_deterministic_and_moves_on_insert() {
        let rs = RevocationSet::new();
        let empty = rs.sparse_root();
        let r1 = rs.sparse_root();
        assert_eq!(empty, r1);
        assert!(rs.insert(dh(0x11)));
        let r2 = rs.sparse_root();
        assert_ne!(empty, r2);
        assert_eq!(r2, rs.sparse_root());
        assert!(!rs.insert(dh(0x11)), "重复撤销幂等");
        assert_eq!(r2, rs.sparse_root());
        assert_eq!(rs.len(), 1);
        assert!(rs.is_revoked(&dh(0x11)));
        assert!(!rs.is_revoked(&dh(0x22)));
    }

    /// 单元素根 == 沿空路径手推（深度 256，每层兄弟 = 空子树根；左/右由索引第 d 位决定；
    /// 叶 = encode_field(dh)）。
    #[test]
    fn single_element_root_matches_manual_path() {
        let rs = RevocationSet::new();
        rs.insert(dh(0xAB));
        let empty = empty_roots();
        let mut cur = Fe::encode_field_le31(&dh(0xAB));
        for (d, empty_root) in empty[..SPARSE_DEPTH].iter().enumerate() {
            let bit = (dh(0xAB)[d / 8] >> (d % 8)) & 1;
            cur = if bit == 0 {
                pedersen_hash2(cur, *empty_root)
            } else {
                pedersen_hash2(*empty_root, cur)
            };
        }
        assert_eq!(rs.sparse_root(), cur.to_be_bytes());
    }

    /// **S-34 碰撞回归**：两委托同 `dh[0..4]`（旧 32-bit 前缀索引相同）但高位相异——
    /// 原型版后写覆盖先写，根只承诺其一（root{A,B} == root{最后写入者}）；现版本三根
    /// （只撤 A / 只撤 B / 双撤）两两相异，锚定根必须反映两叶。
    #[test]
    fn same_prefix_revocations_are_both_anchored() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0..4].copy_from_slice(&0x00C0FFEEu32.to_le_bytes());
        b[0..4].copy_from_slice(&0x00C0FFEEu32.to_le_bytes());
        a[31] = 0x01;
        b[31] = 0x02;
        assert_eq!(&a[0..4], &b[0..4], "构造约束：同 32-bit 前缀");
        assert_ne!(a, b);

        let only_a = RevocationSet::new();
        only_a.insert(a);
        let only_b = RevocationSet::new();
        only_b.insert(b);
        let both = RevocationSet::new();
        both.insert(a);
        both.insert(b);

        let (ra, rb, rab) = (
            only_a.sparse_root(),
            only_b.sparse_root(),
            both.sparse_root(),
        );
        assert_ne!(ra, rb, "相异 dh 必相异叶");
        assert_ne!(rab, ra, "第二撤销必须移动锚定根（原型版：不变）");
        assert_ne!(rab, rb, "第一撤销不可被后写覆盖");
        assert_eq!(both.len(), 2);
        assert_eq!(both.sparse_root(), rab, "压实确定性");
    }

    /// 撤销叶编码边界（电路 `encode_field` 只取低 31 字节）：仅 byte 31 相异的两 dh 占
    /// **同值异位**两叶——锚定根反映两个位置（无碰撞可乘，TECH_SPEC §4.6 残余边界①）。
    #[test]
    fn leaf_value_ignores_byte31_but_positions_differ() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 0x33;
        b[0] = 0x33;
        a[31] = 0x01;
        b[31] = 0x02;
        assert_eq!(
            Fe::encode_field_le31(&a),
            Fe::encode_field_le31(&b),
            "叶值只编码低 31 字节"
        );
        let only_a = RevocationSet::new();
        only_a.insert(a);
        let only_b = RevocationSet::new();
        only_b.insert(b);
        let both = RevocationSet::new();
        both.insert(a);
        both.insert(b);
        assert_ne!(only_a.sparse_root(), only_b.sparse_root(), "位置相异");
        assert_ne!(both.sparse_root(), only_a.sparse_root());
        assert_ne!(both.sparse_root(), only_b.sparse_root());
    }

    /// 小深度随机集合：内部算法 vs 独立朴素递归（整棵 2^depth 树下钻）逐例一致。
    /// depth 1..=8，确定性伪随机抽样子集集合（dh 由低 depth 位决定，保证落在小树里）。
    #[test]
    fn matches_naive_builder_on_small_depth() {
        let naive = |positions: &[(u32, [u8; 32])], depth: usize| -> Fe {
            fn rec(level: usize, node: u32, positions: &[(u32, [u8; 32])], empty: &[Fe]) -> Fe {
                if level == 0 {
                    positions
                        .iter()
                        .find(|(i, _)| *i == node)
                        .map(|(_, v)| Fe::encode_field_le31(v))
                        .unwrap_or(empty[0])
                } else {
                    pedersen_hash2(
                        rec(level - 1, node * 2, positions, empty),
                        rec(level - 1, node * 2 + 1, positions, empty),
                    )
                }
            }
            rec(depth, 0, positions, empty_roots())
        };
        // 确定性伪随机位置集合（重复组合覆盖共享子树路径）。
        let mut x = 0x5EEDu32;
        let mut rng = move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        for depth in 1..=8usize {
            for _case in 0..64 {
                let count = (rng() % 6) as usize;
                let mut positions = Vec::new();
                let set = RevocationSet::new();
                for _ in 0..count {
                    // 用低 depth 位构造索引（dh[0] 低 depth 位 = idx，其余全零 → 同 idx 即同 dh）。
                    let idx = rng() & ((1 << depth) - 1);
                    let mut d = [0u8; 32];
                    d[0] = idx as u8;
                    if set.insert(d) {
                        positions.push((idx, d));
                    }
                }
                assert_eq!(
                    build_nodes(&set.set.read().expect("poisoned"), depth).root(),
                    naive(&positions, depth).to_be_bytes(),
                    "depth={depth} positions={positions:?}"
                );
            }
        }
    }

    // ——— S-42：非成员路径（TECH_SPEC §4.6 残余②前半）———

    /// 电路口径的路径重算：EMPTY 叶起步，逐层 `H(当前 ‖ 兄弟)` / `H(兄弟 ‖ 当前)`
    /// （左/右由索引第 d 位定，与电路 `compute_merkle_root` 同一方向约定）。
    fn recompute(target: &[u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
        assert_eq!(path.len(), SPARSE_DEPTH);
        let mut cur = Fe::zero();
        for (d, sib) in path.iter().enumerate() {
            let bit = (target[d / 8] >> (d % 8)) & 1;
            cur = if bit == 0 {
                pedersen_hash2(cur, Fe::from_be_bytes(sib))
            } else {
                pedersen_hash2(Fe::from_be_bytes(sib), cur)
            };
        }
        cur.to_be_bytes()
    }

    /// 根锚：非成员 witness 的 `root` 与 `sparse_root()` 恒等（同一条压实实现），且路径
    /// 重算（电路口径）回到同一根——路径与根自洽，prover 侧拿去即过电路断言 8 的根对账。
    #[test]
    fn non_membership_path_recomputes_sparse_root() {
        let cases: &[&[[u8; 32]]] = &[
            &[], // 空集：path = 全空子树根表
            &[dh(0x21)],
            &[dh(0x01), dh(0x02)], // gen-witness fixture 同集
            &[dh(0xAA), dh(0xAB), dh(0x11)],
        ];
        for revoked in cases {
            let rs = RevocationSet::new();
            for d in *revoked {
                rs.insert(*d);
            }
            let target = dh(0x21);
            if revoked.contains(&target) {
                continue;
            }
            let w = rs
                .non_membership_witness(&target)
                .expect("未撤销必有 witness");
            assert_eq!(w.root, rs.sparse_root(), "root 与 sparse_root 恒等");
            assert_eq!(recompute(&target, &w.path), w.root, "路径重算回根");
        }
    }

    /// 与独立朴素建树交叉：把目标作为**空叶**（值 0）插入撤销集后的朴素递归根 ==
    /// witness 的 root（逐例 depth 1..=8，覆盖兄弟分支非空/共享子树路径）。
    #[test]
    fn non_membership_path_matches_naive_builder_with_empty_leaf() {
        let naive_root = |positions: &[(u32, Option<[u8; 32]>)], depth: usize| -> Fe {
            fn rec(
                level: usize,
                node: u32,
                positions: &[(u32, Option<[u8; 32]>)],
                empty: &[Fe],
            ) -> Fe {
                if level == 0 {
                    match positions.iter().find(|(i, _)| *i == node) {
                        Some((_, Some(v))) => Fe::encode_field_le31(v),
                        // None = 目标空叶（非成员）；缺席 = 无关分支 → 空子树根
                        Some((_, None)) => empty[0],
                        None => empty[0],
                    }
                } else {
                    pedersen_hash2(
                        rec(level - 1, node * 2, positions, empty),
                        rec(level - 1, node * 2 + 1, positions, empty),
                    )
                }
            }
            rec(depth, 0, positions, empty_roots())
        };
        let mut x = 0x5EEDu32;
        let mut rng = move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        for depth in 1..=8usize {
            for _case in 0..32 {
                let count = (rng() % 5) as usize;
                let set = RevocationSet::new();
                let mut positions: Vec<(u32, Option<[u8; 32]>)> = Vec::new();
                for _ in 0..count {
                    let idx = rng() & ((1 << depth) - 1);
                    let mut d = [0u8; 32];
                    d[0] = idx as u8;
                    if set.insert(d) {
                        positions.push((idx, Some(d)));
                    }
                }
                // 目标 = 撤销集之外的确定性位置（撞上已撤销位置则跳过本例）。
                let target_idx = rng() & ((1 << depth) - 1);
                let mut target = [0u8; 32];
                target[0] = target_idx as u8;
                if set.is_revoked(&target) {
                    continue;
                }
                positions.push((target_idx, None));
                // 公共入口恒为全深 256（朴素建树下钻不了 2^256）；depth 参数化走同一条
                // build_nodes/NodeCache 实现（truncate_idx 建小树），与 naive 同深度对账。
                let w = build_nodes(&set.set.read().expect("poisoned"), depth).path_for(&target);
                assert_eq!(
                    w.root,
                    naive_root(&positions, depth).to_be_bytes(),
                    "depth={depth} target={target_idx} positions={positions:?}"
                );
            }
        }
    }

    /// fail-closed：目标已撤销 → `None`（成员路径不冒充非成员）；未撤销 → `Some`。
    #[test]
    fn non_membership_is_none_for_revoked_target() {
        let rs = RevocationSet::new();
        rs.insert(dh(0x21));
        assert!(rs.non_membership_witness(&dh(0x21)).is_none());
        assert!(rs.non_membership_witness(&dh(0x22)).is_some());
        // 空集：任何目标都非成员。
        assert!(RevocationSet::new()
            .non_membership_witness(&dh(0x33))
            .is_some());
    }

    /// 空集路径 = 空子树根表逐层（`path[d] == empty_roots[d]`），root = 全空树根。
    #[test]
    fn non_membership_path_of_empty_set_is_empty_roots() {
        let rs = RevocationSet::new();
        let w = rs.non_membership_witness(&dh(0x07)).expect("空集非成员");
        let empty = empty_roots();
        for (d, p) in w.path.iter().enumerate() {
            assert_eq!(*p, empty[d].to_be_bytes(), "path[{d}]");
        }
        assert_eq!(w.root, empty[SPARSE_DEPTH].to_be_bytes());
    }

    /// 兄弟分支命中撤销叶：目标与一撤销叶仅 bit 0 相异（同父）→ `path[0]` = 该撤销叶
    /// （encode_field 口径），且重算回根——prover 侧目标与撤销叶相邻时缓存命中路径。
    #[test]
    fn non_membership_path_hits_revoked_sibling_leaf() {
        let rs = RevocationSet::new();
        let mut sib = dh(0x21);
        sib[0] ^= 0x01; // bit 0 翻转 → 与目标同父
        rs.insert(sib);
        let target = dh(0x21);
        let w = rs.non_membership_witness(&target).expect("未撤销");
        assert_eq!(
            w.path[0],
            Fe::encode_field_le31(&sib).to_be_bytes(),
            "path[0] = 相邻撤销叶"
        );
        assert_eq!(recompute(&target, &w.path), w.root);
        assert_eq!(w.root, rs.sparse_root());
    }

    /// fixture 全树交叉锚（S-41 同源）：撤销集 {0x01…32, 0x02…32} 的非成员 witness 根 ==
    /// 已锁定的 Noir golden 根（与 `gen_witness_fixture_root_matches_noir` 同值）。
    #[test]
    fn non_membership_witness_root_matches_fixture_golden() {
        let rs = RevocationSet::new();
        rs.insert([0x01; 32]);
        rs.insert([0x02; 32]);
        let target = fixture_dh();
        let w = rs.non_membership_witness(&target).expect("目标不在撤销集");
        assert_eq!(
            hex::encode(w.root),
            "092fca75790d95bddddd0b1995d54253c7677ee1e798d6ee4c6d251b9f2d8621"
        );
        assert_eq!(recompute(&target, &w.path), w.root);
    }

    /// gen-witness fixture 的 delegation_hash（[0x21+i]）。
    fn fixture_dh() -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in (0x21..0x41).take(32).enumerate() {
            out[i] = b;
        }
        out
    }

    /// **跨实现锚（Noir 侧同款测试 `aggregator_non_membership_path_digest`）**：fixture 撤销集
    /// 的非成员路径逐层 Field 大端 32B 扁平（256×32 = 8192B）后取 sha256——gen-witness
    /// `build_path`（CI 管线喂电路 `revocation_path` witness 的实现）必须产出**同一字节序列**。
    /// 摘要比逐层 pin 256 个 Field 紧凑，且逐字节敏感（任一层相异即红）。
    #[test]
    fn non_membership_path_digest_matches_noir_golden() {
        let rs = RevocationSet::new();
        rs.insert([0x01; 32]);
        rs.insert([0x02; 32]);
        let target = fixture_dh();
        let w = rs.non_membership_witness(&target).expect("目标不在撤销集");
        let mut flat = Vec::with_capacity(256 * 32);
        for p in &w.path {
            flat.extend_from_slice(p);
        }
        assert_eq!(flat.len(), 8192);
        let digest = sha2::Sha256::digest(&flat);
        assert_eq!(
            hex::encode(digest),
            "9342885b1237b774f32c279e3f43139a0dbfab9bc11d966afc194ceb47a4269e",
            "路径摘要漂移：Noir 侧 golden 需同步重算（gen-witness aggregator_non_membership_path_digest）"
        );
    }
}
