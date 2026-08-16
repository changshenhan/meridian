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
        for pair in layer.chunks_exact(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(h(&buf));
        }
        layer = next;
    }
    layer[0]
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
}
