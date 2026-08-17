//! 撤销集 + sha256 sparse merkle 根（MASTER_PLAN S-11，TECH_SPEC §4.6）。
//!
//! 撤销链上事件 1 epoch 内进入撤销根：`RevocationSet` 收集被撤销委托的 delegation_hash，
//! `sparse_root()` 把它压实成一个 32B 根，随下个密封 epoch 的 `ChainPublisher::commit`
//! 锚定到链（`BatchSettler.commit` 的 `revocationRoot` 参数）。
//!
//! 结构：深度 32 的 sha256 sparse merkle。叶索引 = `dsa::revocation_index(dh)` =
//! `u32::from_le_bytes(dh[0..4])`（与电路共享的派生，S-09）；叶值 = dh（32B）；空叶 =
//! `sha256("")`（与承诺树 `merkle::EMPTY_LEAF` 同常量）。空子树根表
//! `empty_roots[k] = sha256(empty_roots[k-1] ‖ empty_roots[k-1])` 预计算，插入时逐层上推，
//! 复杂度 O(32·|revoked|)。
//!
//! **诚实缝（非活跃错配）**：电路侧撤销根是 Pedersen sparse merkle（main.nr，叶 EMPTY(0)），
//! 聚合器侧这里是 sha256。内核用 `FormatVerifier` 从不读 `pi.revocation_root`，真正的
//! E_REVOKED 闸口在 `submit()`（注册表查找后立即查集）。真对齐（聚合器算 Pedersen 树）推迟到
//! 真 ZK 集成——本文件 + TECH_SPEC §4.6 记录。

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use meridian_core::dsa::revocation_index;
use sha2::{Digest, Sha256};

use crate::merkle::EMPTY_LEAF;

fn h(data: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(data);
    s.finalize().into()
}

/// 稀疏树深度 = 撤销索引的位数。
pub const SPARSE_DEPTH: usize = 32;

/// 空子树根表：`empty_roots[k]` = 高度 k 的全空子树根（k=0 即空叶 sha256("")）。
fn empty_roots() -> [[u8; 32]; SPARSE_DEPTH + 1] {
    let mut t = [[0u8; 32]; SPARSE_DEPTH + 1];
    t[0] = EMPTY_LEAF;
    for k in 1..=SPARSE_DEPTH {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&t[k - 1]);
        buf[32..].copy_from_slice(&t[k - 1]);
        t[k] = h(&buf);
    }
    t
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

    /// 当前集合的 sha256 sparse root。空集 = 全空树根（深度 32 的确定性常量）。
    pub fn sparse_root(&self) -> [u8; 32] {
        let set = self.set.read().expect("revocations poisoned");
        let empty = empty_roots();
        if set.is_empty() {
            return empty[SPARSE_DEPTH];
        }
        // 部分树节点：(深度 d, 该深度节点索引) → 子树根。d 从 0（叶层）到 32（根层）。
        let mut nodes: HashMap<(usize, u32), [u8; 32]> =
            HashMap::with_capacity(SPARSE_DEPTH * set.len());
        for dh in set.iter() {
            let mut idx = revocation_index(*dh);
            let mut value = *dh; // 叶值 = dh
            nodes.insert((0, idx), value); // 叶层节点也必须登记：相邻撤销叶互作兄弟时要能找到
            for (d, empty_root) in empty[..SPARSE_DEPTH].iter().enumerate() {
                let sibling = nodes.get(&(d, idx ^ 1)).copied().unwrap_or(*empty_root);
                let mut buf = [0u8; 64];
                if idx & 1 == 0 {
                    buf[..32].copy_from_slice(&value);
                    buf[32..].copy_from_slice(&sibling);
                } else {
                    buf[..32].copy_from_slice(&sibling);
                    buf[32..].copy_from_slice(&value);
                }
                value = h(&buf);
                idx >>= 1;
                nodes.insert((d + 1, idx), value);
            }
        }
        nodes[&(SPARSE_DEPTH, 0)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dh(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// 深度 32 全空树根锁定（Python 独立计算，交叉实现契约）：
    /// 逐层 empty_roots[k] = sha256(empty_roots[k-1] ‖ empty_roots[k-1])，k=0 起 sha256("")。
    #[test]
    fn empty_root_matches_golden() {
        let root = RevocationSet::new().sparse_root();
        assert_eq!(
            hex::encode(root),
            "10ffc30c0167c8fb55b87078ee3c94b19d9ba7ba9f01eb58c4eeb88d73bd304d"
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

    /// 单元素根 == 沿空路径手推（深度 32，每层兄弟 = 空子树根）。
    #[test]
    fn single_element_root_matches_manual_path() {
        let rs = RevocationSet::new();
        rs.insert(dh(0xAB));
        let empty = empty_roots();
        let mut idx = revocation_index(dh(0xAB));
        let mut cur = dh(0xAB);
        for empty_root in empty[..SPARSE_DEPTH].iter() {
            let mut buf = [0u8; 64];
            if idx & 1 == 0 {
                buf[..32].copy_from_slice(&cur);
                buf[32..].copy_from_slice(empty_root);
            } else {
                buf[..32].copy_from_slice(empty_root);
                buf[32..].copy_from_slice(&cur);
            }
            cur = h(&buf);
            idx >>= 1;
        }
        assert_eq!(rs.sparse_root(), cur);
    }

    /// 小深度随机集合：内部算法 vs 独立朴素递归（整棵 2^depth 树下钻）逐例一致。
    /// depth 3 → 8 叶，遍历全部 2^8 子集的一个确定性伪随机抽样子集集合。
    #[test]
    fn matches_naive_builder_on_small_depth() {
        let empty = empty_roots();
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
            rec(depth, 0, positions, &empty)
        };
        // 确定性伪随机位置集合（重复组合覆盖共享子树路径）。
        let mut x = 0x5EEDu32;
        let mut rng = move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        for depth in 1..=3usize {
            for _case in 0..64 {
                let count = (rng() % 6) as usize;
                let mut positions = Vec::new();
                let set = RevocationSet::new();
                for _ in 0..count {
                    // 用低 depth 位构造索引，保证落在小树里。
                    let idx = rng() & ((1 << depth) - 1);
                    // 用 dh 前 4 字节（LE）= idx 的假哈希不可行——直接用 idx 构造 dh[0..4]。
                    let mut d = [0u8; 32];
                    d[0..4].copy_from_slice(&idx.to_le_bytes());
                    if set.insert(d) {
                        positions.push((idx, d));
                    }
                }
                assert_eq!(
                    sparse_root_at(&set, depth),
                    naive(&positions, depth),
                    "depth={depth} positions={positions:?}"
                );
            }
        }
    }

    /// 深度参数化的内部入口（测试专用镜像；公共 `sparse_root()` 恒为 32）。
    fn sparse_root_at(set: &RevocationSet, depth: usize) -> [u8; 32] {
        let guard = set.set.read().expect("poisoned");
        let empty = empty_roots();
        if guard.is_empty() {
            return empty[depth];
        }
        let mut nodes: HashMap<(usize, u32), [u8; 32]> =
            HashMap::with_capacity(depth * guard.len());
        for dh in guard.iter() {
            let mut idx = revocation_index(*dh) & ((1u32 << depth) - 1);
            let mut value = *dh;
            nodes.insert((0, idx), value);
            for (d, empty_root) in empty[..depth].iter().enumerate() {
                let sibling = nodes.get(&(d, idx ^ 1)).copied().unwrap_or(*empty_root);
                let mut buf = [0u8; 64];
                if idx & 1 == 0 {
                    buf[..32].copy_from_slice(&value);
                    buf[32..].copy_from_slice(&sibling);
                } else {
                    buf[..32].copy_from_slice(&sibling);
                    buf[32..].copy_from_slice(&value);
                }
                value = h(&buf);
                idx >>= 1;
                nodes.insert((d + 1, idx), value);
            }
        }
        nodes[&(depth, 0)]
    }
}
