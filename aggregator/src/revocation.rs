//! 撤销集 + sha256 sparse merkle 根（MASTER_PLAN S-11，TECH_SPEC §4.6；S-34 收口碰撞）。
//!
//! 撤销链上事件 1 epoch 内进入撤销根：`RevocationSet` 收集被撤销委托的 delegation_hash，
//! `sparse_root()` 把它压实成一个 32B 根，随下个密封 epoch 的 `ChainPublisher::commit`
//! 锚定到链（`BatchSettler.commit` 的 `revocationRoot` 参数）。
//!
//! 结构：深度 256 的 sha256 sparse merkle。叶索引 = `dh` 全 32 字节的 LE u256
//! （位 k = `(dh[k/8] >> (k%8)) & 1`；第 d 层节点索引 = 索引右移 d）；叶值 = dh（32B）；
//! 空叶 = `sha256("")`（与承诺树 `merkle::EMPTY_LEAF` 同常量）。空子树根表
//! `empty_roots[k] = sha256(empty_roots[k-1] ‖ empty_roots[k-1])` 预计算（`OnceLock`），
//! 插入时逐层上推，复杂度 O(256·|revoked|)——只在密封（每 epoch 一次）调用。
//!
//! **S-34 碰撞收口**：S-11 原型版索引只取 `dh[0..4]`（32-bit 前缀，当时与电路共享派生）——
//! 两委托同前缀共享叶子、后写覆盖先写，锚定根只承诺其一（audit-scope §4 自报项）。改全
//! 256-bit 索引后 `delegation_hash` 整体即索引，**相异 dh 必相异叶**。电路侧已于 S-36
//! 同步全宽化（Noir 撤销树 depth 256，同一派生同一位序，TECH_SPEC §5.3）。代价是
//! O(32·|revoked|) → O(256·|revoked|)（稀有事 × 低频路径，见上）。
//!
//! **诚实缝（非活跃错配；S-34 收窄碰撞、S-36 收窄索引）**：电路侧撤销根是 Pedersen 树
//! （叶 EMPTY(0) Field），本侧是 sha256 树（叶 dh 32B）——索引派生已全等，残余错配是
//! 哈希函数与叶值/空叶规范，两侧根数值不可比。内核用 `FormatVerifier`
//! 从不读 `pi.revocation_root`，真正的 E_REVOKED 闸口在 `submit()`（注册表查找后立即查集，
//! 集合精确查找，不走树）。完全对齐（同哈希 + 同叶规范）随真 ZK 集成方向定夺后收口
//! ——本文件 + TECH_SPEC §4.6 记录。

use std::collections::{HashMap, HashSet};
use std::sync::{OnceLock, RwLock};

use sha2::{Digest, Sha256};

use crate::merkle::EMPTY_LEAF;

fn h(data: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(data);
    s.finalize().into()
}

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

/// 空子树根表：`empty_roots[k]` = 高度 k 的全空子树根（k=0 即空叶 sha256("")）。
fn empty_roots() -> &'static [[u8; 32]; SPARSE_DEPTH + 1] {
    static TABLE: OnceLock<[[u8; 32]; SPARSE_DEPTH + 1]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [[0u8; 32]; SPARSE_DEPTH + 1];
        t[0] = EMPTY_LEAF;
        for k in 1..=SPARSE_DEPTH {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&t[k - 1]);
            buf[32..].copy_from_slice(&t[k - 1]);
            t[k] = h(&buf);
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

    /// 当前集合的 sha256 sparse root。空集 = 全空树根（深度 256 的确定性常量）。
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
        return empty[depth];
    }
    // 部分树节点：(深度 d, 该深度节点索引) → 子树根。d 从 0（叶层）到 depth（根层）。
    let mut nodes: HashMap<(usize, [u8; 32]), [u8; 32]> = HashMap::with_capacity(depth * set.len());
    for dh in set.iter() {
        let mut idx = truncate_idx(*dh, depth);
        let mut value = *dh; // 叶值 = dh
        nodes.insert((0, idx), value); // 叶层节点也必须登记：相邻撤销叶互作兄弟时要能找到
        for (d, empty_root) in empty[..depth].iter().enumerate() {
            let mut sib = idx;
            sib[0] ^= 1; // 兄弟索引 = 本层索引翻转最低位（LE u256 的第 d 位）
            let sibling = nodes.get(&(d, sib)).copied().unwrap_or(*empty_root);
            let mut buf = [0u8; 64];
            if sib[0] & 1 == 1 {
                // 本层第 d 位为 0 → 当前节点是左孩子
                buf[..32].copy_from_slice(&value);
                buf[32..].copy_from_slice(&sibling);
            } else {
                buf[..32].copy_from_slice(&sibling);
                buf[32..].copy_from_slice(&value);
            }
            value = h(&buf);
            idx = shr1(idx);
            nodes.insert((d + 1, idx), value);
        }
    }
    nodes[&(depth, [0u8; 32])]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dh(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// 深度 256 全空树根锁定（Python 独立计算，交叉实现契约）：
    /// 逐层 empty_roots[k] = sha256(empty_roots[k-1] ‖ empty_roots[k-1])，k=0 起 sha256("")。
    #[test]
    fn empty_root_matches_golden() {
        let root = RevocationSet::new().sparse_root();
        assert_eq!(
            hex::encode(root),
            "9a596033c82b65c5eef0f5f160b9c9893844765a15ab685486931c870004b910"
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

    /// 单元素根 == 沿空路径手推（深度 256，每层兄弟 = 空子树根；左/右由索引第 d 位决定）。
    #[test]
    fn single_element_root_matches_manual_path() {
        let rs = RevocationSet::new();
        rs.insert(dh(0xAB));
        let empty = empty_roots();
        let mut cur = dh(0xAB);
        for (d, empty_root) in empty[..SPARSE_DEPTH].iter().enumerate() {
            let bit = (dh(0xAB)[d / 8] >> (d % 8)) & 1;
            let mut buf = [0u8; 64];
            if bit == 0 {
                buf[..32].copy_from_slice(&cur);
                buf[32..].copy_from_slice(empty_root);
            } else {
                buf[..32].copy_from_slice(empty_root);
                buf[32..].copy_from_slice(&cur);
            }
            cur = h(&buf);
        }
        assert_eq!(rs.sparse_root(), cur);
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

    /// 小深度随机集合：内部算法 vs 独立朴素递归（整棵 2^depth 树下钻）逐例一致。
    /// depth 1..=8，确定性伪随机抽样子集集合（dh 由低 depth 位决定，保证落在小树里）。
    #[test]
    fn matches_naive_builder_on_small_depth() {
        let naive = |positions: &[(u32, [u8; 32])], depth: usize| -> [u8; 32] {
            fn rec(
                level: usize,
                node: u32,
                positions: &[(u32, [u8; 32])],
                empty: &[[u8; 32]],
            ) -> [u8; 32] {
                if level == 0 {
                    positions
                        .iter()
                        .find(|(i, _)| *i == node)
                        .map(|(_, v)| *v)
                        .unwrap_or(empty[0])
                } else {
                    let mut buf = [0u8; 64];
                    buf[..32].copy_from_slice(&rec(level - 1, node * 2, positions, empty));
                    buf[32..].copy_from_slice(&rec(level - 1, node * 2 + 1, positions, empty));
                    h(&buf)
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
                    naive(&positions, depth),
                    "depth={depth} positions={positions:?}"
                );
            }
        }
    }
}
