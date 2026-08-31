//! sha256 Merkle 助手（commitment lattice 用，TECH_SPEC §6.3 步骤 A 的 `root = merkle(L)`）。
//!
//! 构造：叶子 = 调用方提供的 32B 哈希；补齐到 2 的幂（零叶子 = sha256("") 的 32B）；
//! 逐层 `sha256(left ‖ right)`。公开可复算 → B11 确定性 + S-11 挑战者可重推同一根。

use sha2::{Digest, Sha256};

fn h(data: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(data);
    s.finalize().into()
}

/// 空叶子 / 补齐叶子（sha256("")）。与 `merkle_root(&[])` 的结果一致。
pub const EMPTY_LEAF: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// 叶子 = sha256(seq_le(8) ‖ intent_hash(32)) = 40B 的单叶子哈希。
/// 锁在 §6.3：L = [(seq_i, intent_hash_i)] 按摄取顺序，每片叶子即一（seq, hash）对。
pub fn leaf(seq: u64, intent_hash: [u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 40];
    buf[..8].copy_from_slice(&seq.to_le_bytes());
    buf[8..].copy_from_slice(&intent_hash);
    h(&buf)
}

/// 接受锚叶前缀（"ACCV1\0"，P2-3 §6.23）。
pub const ACCEPTANCE_LEAF_PREFIX: [u8; 6] = *b"ACCV1\0";

/// 接受锚叶（P2-3 §6.23）= sha256("ACCV1\0" ‖ seq_le(8) ‖ accepted_at_le(8)) = 22B 原像。
/// 与 Solidity `Merkle.acceptanceLeaf` 逐字节对齐（S-57 差分闸第三契约扩展）：
/// 平行接受树与承诺树同叶集同序（seq 升序），单独锚定接受时刻、不并入承诺叶原像
///（§6.20.1 否决路线 1：改承诺叶原像会炸穿撤销索引/SDK/电路全部锚点）。
pub fn acceptance_leaf(seq: u64, accepted_at: u64) -> [u8; 32] {
    let mut buf = [0u8; 22];
    buf[..6].copy_from_slice(&ACCEPTANCE_LEAF_PREFIX);
    buf[6..14].copy_from_slice(&seq.to_le_bytes());
    buf[14..].copy_from_slice(&accepted_at.to_le_bytes());
    h(&buf)
}

/// Merkle 根：2 的幂补齐，零叶子 = EMPTY_LEAF，逐层 sha256(left‖right)。
/// 空输入返回 sha256("")（与 EMPTY_LEAF 相同）。
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return EMPTY_LEAF;
    }
    let n = leaves.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(n);
    layer.extend_from_slice(leaves);
    layer.resize(n, EMPTY_LEAF);
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        // as_chunks（clippy 1.98 chunks_exact_to_as_chunks）：层数恒为 2 的幂，余块恒空。
        for pair in layer.as_chunks::<2>().0 {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(h(&buf));
        }
        layer = next;
    }
    layer[0]
}

/// 包含证明生成器：(accepted_count, siblings[自底层向上])。`index` 指向 `leaves` 内的位置，
/// 与 Solidity `ChallengeTestHelper::proofFor`（contracts/test/）逐字节对齐——欺诈证明的
/// 链下生成侧（S-11）。
///
/// 叶索引 = seq − epoch 起始 seq；`accepted_count` 由链上验证器自校验（错值 → 根不匹配）。
/// 返回 `None` 当 `index` 越界。
pub fn inclusion_proof(leaves: &[[u8; 32]], index: usize) -> Option<(usize, Vec<[u8; 32]>)> {
    if index >= leaves.len() {
        return None;
    }
    let n = leaves.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(n);
    layer.extend_from_slice(leaves);
    layer.resize(n, EMPTY_LEAF);
    let mut siblings = Vec::with_capacity(n.trailing_zeros() as usize);
    let mut idx = index;
    while layer.len() > 1 {
        siblings.push(layer[idx ^ 1]);
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.as_chunks::<2>().0 {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(h(&buf));
        }
        layer = next;
        idx >>= 1;
    }
    Some((leaves.len(), siblings))
}

/// 验证包含证明：沿路径重推根并与 `root` 比较。siblings 自底层向上；长度须 ==
/// `tree_depth(accepted_count)`（与 Solidity `Merkle.computeRoot` 的边界检查对齐）。
pub fn verify_inclusion(
    leaf_hash: [u8; 32],
    index: usize,
    accepted_count: usize,
    siblings: &[[u8; 32]],
    root: [u8; 32],
) -> bool {
    let depth = accepted_count.next_power_of_two().trailing_zeros() as usize;
    if index >= accepted_count || siblings.len() != depth {
        return false;
    }
    let mut cur = leaf_hash;
    for (i, s) in siblings.iter().enumerate() {
        let mut buf = [0u8; 64];
        if (index >> i) & 1 == 0 {
            buf[..32].copy_from_slice(&cur);
            buf[32..].copy_from_slice(s);
        } else {
            buf[..32].copy_from_slice(s);
            buf[32..].copy_from_slice(&cur);
        }
        cur = h(&buf);
    }
    cur == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_is_its_own_root() {
        let l = leaf(1, [0xAB; 32]);
        assert_eq!(merkle_root(&[l]), l);
    }

    #[test]
    fn empty_is_emitted() {
        assert_eq!(merkle_root(&[]), EMPTY_LEAF);
    }

    #[test]
    fn padding_uses_empty_leaf() {
        // 3 叶子 → 补齐 4 叶。根的 left 子树 = merkle(叶1,叶2)，right 子树 = merkle(叶3,EMPTY)。
        let a = leaf(1, [0x01; 32]);
        let b = leaf(2, [0x02; 32]);
        let c = leaf(3, [0x03; 32]);
        let full = merkle_root(&[a, b, c, EMPTY_LEAF]);
        assert_eq!(merkle_root(&[a, b, c]), full);
    }

    #[test]
    fn deterministic_and_order_sensitive() {
        let a = leaf(1, [0x01; 32]);
        let b = leaf(2, [0x02; 32]);
        assert_eq!(merkle_root(&[a, b]), merkle_root(&[a, b]));
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]));
    }

    /// 接受锚叶（P2-3 §6.23）：原像 22B（"ACCV1\0" ‖ seq_le(8) ‖ accepted_at_le(8)），
    /// 独立重算原像对账 golden + 字段敏感性（seq / accepted_at 任一变化 → 叶变）。
    #[test]
    fn acceptance_leaf_matches_preimage_and_is_field_sensitive() {
        let mut preimage = Vec::with_capacity(22);
        preimage.extend_from_slice(&ACCEPTANCE_LEAF_PREFIX);
        preimage.extend_from_slice(&7u64.to_le_bytes());
        preimage.extend_from_slice(&1_700_000_123u64.to_le_bytes());
        let mut s = Sha256::new();
        s.update(&preimage);
        let golden: [u8; 32] = s.finalize().into();
        assert_eq!(acceptance_leaf(7, 1_700_000_123), golden);
        assert_ne!(acceptance_leaf(8, 1_700_000_123), golden);
        assert_ne!(acceptance_leaf(7, 1_700_000_124), golden);
        // accepted_at = 0（旧格式哨兵，§6.23.1 定夺 1）仍是确定性 32B 叶。
        assert_eq!(acceptance_leaf(7, 0), acceptance_leaf(7, 0));
    }

    /// 任意叶数任意索引：proof → verify 恒真。小树枚举全部索引；100k 容量级采样（每个 proof
    /// 本身 O(n log n)，全枚举 100k 索引是 O(n² log n)——用采样控测试时长）。
    #[test]
    fn inclusion_proof_roundtrip_all_indexes() {
        for count in [1usize, 2, 3, 4] {
            let leaves: Vec<[u8; 32]> = (0..count as u64)
                .map(|seq| leaf(seq + 1, [seq as u8; 32]))
                .collect();
            let root = merkle_root(&leaves);
            for index in 0..count {
                check_proof(&leaves, root, index);
            }
        }
        // 100k 容量级：采样首尾 + 确定性中间点。
        let count = 100_000usize;
        let leaves: Vec<[u8; 32]> = (0..count as u64)
            .map(|seq| leaf(seq + 1, [seq as u8; 32]))
            .collect();
        let root = merkle_root(&leaves);
        for index in [0usize, 1, 2, 37, 65_535, 65_536, 99_998, 99_999] {
            check_proof(&leaves, root, index);
        }
    }

    fn check_proof(leaves: &[[u8; 32]], root: [u8; 32], index: usize) {
        let (accepted, siblings) = inclusion_proof(leaves, index).unwrap();
        assert_eq!(accepted, leaves.len());
        assert_eq!(
            siblings.len(),
            leaves.len().next_power_of_two().trailing_zeros() as usize
        );
        assert!(
            verify_inclusion(leaves[index], index, accepted, &siblings, root),
            "verify failed: count={} index={index}",
            leaves.len()
        );
    }

    /// 边界防御：越界索引 → None；篡改兄弟路径 / 错 accepted_count → verify 为假。
    #[test]
    fn inclusion_proof_rejects_tampering() {
        let leaves: Vec<[u8; 32]> = (0..4u64)
            .map(|seq| leaf(seq + 1, [seq as u8; 32]))
            .collect();
        let root = merkle_root(&leaves);
        assert!(inclusion_proof(&leaves, 4).is_none());
        let (accepted, siblings) = inclusion_proof(&leaves, 1).unwrap();
        assert!(verify_inclusion(leaves[1], 1, accepted, &siblings, root));
        // 篡改一个兄弟 → 根不匹配。
        let mut tampered = siblings.clone();
        tampered[0] = leaf(99, [0xEE; 32]);
        assert!(!verify_inclusion(leaves[1], 1, accepted, &tampered, root));
        // 错误 accepted_count（改变深度）→ 假。
        assert!(!verify_inclusion(leaves[1], 1, 5, &siblings, root));
        // 越界 index → 假。
        assert!(!verify_inclusion(leaves[1], 7, accepted, &siblings, root));
    }
}
