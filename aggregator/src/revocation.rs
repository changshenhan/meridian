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

    /// 当前集合的撤销树根（32B 大端 Field，电路 `revocation_root` 公共输入口径）。
    /// 空集 = 全空树根（深度 256 的确定性常量）。
    pub fn sparse_root(&self) -> [u8; 32] {
        let set = self.set.read().expect("revocations poisoned");
        build_root(&set, SPARSE_DEPTH)
    }
}

/// 压实根。`depth` 参数化（测试与公共入口共用一条实现）：树只覆盖索引低 `depth` 位，
/// 第 d 层节点索引 = 索引右移 d。
fn build_root(set: &HashSet<[u8; 32]>, depth: usize) -> [u8; 32] {
    let empty = empty_roots();
    if set.is_empty() {
        return empty[depth].to_be_bytes();
    }
    // 部分树节点：(深度 d, 该深度节点索引) → 子树根。d 从 0（叶层）到 depth（根层）。
    let mut nodes: HashMap<(usize, [u8; 32]), Fe> = HashMap::with_capacity(depth * set.len());
    for dh in set.iter() {
        let mut idx = truncate_idx(*dh, depth);
        let mut value = Fe::encode_field_le31(dh); // 撤销叶 = encode_field(dh)（电路/gen-witness 同编码）
        nodes.insert((0, idx), value); // 叶层节点也必须登记：相邻撤销叶互作兄弟时要能找到
        for (d, empty_root) in empty[..depth].iter().enumerate() {
            let mut sib = idx;
            sib[0] ^= 1; // 兄弟索引 = 本层索引翻转最低位（LE u256 的第 d 位）
            let sibling = nodes.get(&(d, sib)).copied().unwrap_or(*empty_root);
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
    nodes[&(depth, [0u8; 32])].to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    build_root(&set.set.read().expect("poisoned"), depth),
                    naive(&positions, depth).to_be_bytes(),
                    "depth={depth} positions={positions:?}"
                );
            }
        }
    }
}
