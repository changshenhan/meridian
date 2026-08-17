//! Commitment lattice（MASTER_PLAN S-10b，TECH_SPEC §6.3 步骤 A-E）。
//!
//! 密封（窗口满/到点）→ 承诺根（sha256 merkle over (seq‖intent_hash)，公开可复算）→
//! 按 intent_hash 确定性重排 → 按 recipient 聚合净额 → nettingRoot =
//! keccak256(abi.encode(net[]))——**对齐 `BatchSettler.settle`**（代码为准；TECH_SPEC §6.3
//! 的 "merkle(net[])" 文字与合约不一致，已在 S-10 修订）。
//!
//! 确定性（B11）：全部纯函数、无随机、无时钟依赖 → 同输入同输出。net 数组按 recipient 字节
//! 升序（BTreeMap 规范序）——nettingRoot 对数组序敏感，运营者与挑战者必须能重推同一字节序。
//!
//! `ChainPublisher` 是上链 seam：S-11 用 `BatchSettler.commit/settle` 交易实现；S-10 用
//! `NoopPublisher`（内核只算不发布）。

use std::collections::BTreeMap;

use meridian_core::error::Error;
use sha3::{Digest, Keccak256};

use crate::merkle::{leaf, merkle_root};
use crate::window::WindowEntry;

/// 意图解析：intent_hash → (recipient, amount)。`aggregate` / `build_epoch` 用它把已密封
/// 条目的哈希解析回明文收款方（净额聚合所需；正常路径索引必含）。
pub type Resolver<'a> = dyn FnMut(&[u8; 32]) -> Option<([u8; 20], u64)> + 'a;

/// 净额指令（对齐 `BatchSettler.NetInstruction { recipient; amount }`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetLine {
    pub recipient: [u8; 20],
    pub amount: u64,
}

/// 一个 epoch 的 lattice 产物（承诺根 + 撤销根 + 净额 + 净额根）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochResult {
    pub epoch_id: u64,
    pub sealed_at: u64,
    pub commitment_root: [u8; 32],
    /// 本 epoch 承诺时的撤销根（`RevocationSet::sparse_root` 快照；单独锚定，不并入承诺树，
    /// 避免破坏承诺根的叶索引——S-11 决策）。
    pub revocation_root: [u8; 32],
    pub net: Vec<NetLine>,
    pub netting_root: [u8; 32],
}

/// 链上发布 seam（S-11 实现为 BatchSettler 交易；失败由运营者重试，内核不内化重试）。
pub trait ChainPublisher {
    fn commit(
        &self,
        epoch_id: u64,
        commitment_root: [u8; 32],
        revocation_root: [u8; 32],
        sealed_at: u64,
    ) -> Result<(), Error>;
    fn settle(&self, epoch_id: u64, netting_root: [u8; 32], net_count: u64) -> Result<(), Error>;
}

/// 占位发布者：只算不发布（S-10 用；S-11 换真实交易后端）。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopPublisher;

impl ChainPublisher for NoopPublisher {
    fn commit(
        &self,
        _epoch_id: u64,
        _commitment_root: [u8; 32],
        _revocation_root: [u8; 32],
        _sealed_at: u64,
    ) -> Result<(), Error> {
        Ok(())
    }
    fn settle(
        &self,
        _epoch_id: u64,
        _netting_root: [u8; 32],
        _net_count: u64,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// 步骤 B：承诺根 = sha256 merkle over L。L 由 `seal()` 保证按 seq 升序。
pub fn commitment_root(entries: &[WindowEntry]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = entries.iter().map(|e| leaf(e.seq, e.intent_hash)).collect();
    merkle_root(&leaves)
}

/// 步骤 C：按 intent_hash 确定性重排（并列时按 seq 决序，全确定）。
pub fn reorder(entries: &[WindowEntry]) -> Vec<WindowEntry> {
    let mut out = entries.to_vec();
    out.sort_by_key(|e| (e.intent_hash, e.seq));
    out
}

/// 步骤 D：净额 = 按 recipient 聚合（BTreeMap → recipient 字节升序，规范序）。
/// `resolve` 把 intent_hash 解析回 (recipient, amount)；任一缺失返回 None（不应发生，
/// 由调用方丢弃该 epoch 并告警——正常路径所有已接受意图都在索引里）。
pub fn aggregate(ordered: &[WindowEntry], resolve: &mut Resolver<'_>) -> Option<Vec<NetLine>> {
    let mut map: BTreeMap<[u8; 20], u64> = BTreeMap::new();
    for e in ordered {
        let (recipient, amount) = resolve(&e.intent_hash)?;
        let slot = map.entry(recipient).or_insert(0);
        *slot = slot.saturating_add(amount);
    }
    Some(
        map.into_iter()
            .map(|(recipient, amount)| NetLine { recipient, amount })
            .collect(),
    )
}

/// Solidity `abi.encode(NetInstruction[])`（`BatchSettler.settle` 的锚定字节布局）：
/// head 偏移（uint256）→ 长度（uint256）→ 每元素 = address（左补 32B）‖ uint256（32B BE）。
/// Solidity 定宽 32B/字段——**不能用 u64 8B 直接写**，必须左补。
pub fn abi_encode_net(net: &[NetLine]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 32 + net.len() * 64);
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&32u64.to_be_bytes()); // head: 数组数据偏移（uint256）
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&(net.len() as u64).to_be_bytes()); // 数组长度（uint256）
    for line in net {
        out.extend_from_slice(&[0u8; 12]); // address (20B) 左补至 32B
        out.extend_from_slice(&line.recipient);
        out.extend_from_slice(&[0u8; 24]); // uint256 左补高位
        out.extend_from_slice(&line.amount.to_be_bytes());
    }
    out
}

/// 步骤 E：nettingRoot = keccak256(abi.encode(net[]))（合约权威定义）。
pub fn netting_root(net: &[NetLine]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(abi_encode_net(net));
    h.finalize().into()
}

/// 全管线：承诺根 → 重排 → 净额 → 净额根。`revocation_root` 由调用方（`settle_epoch` 里的
/// `RevocationSet::sparse_root` 快照）传入，随承诺根一起上链（S-11 撤销根 1 epoch 内锚定）。
pub fn build_epoch(
    epoch_id: u64,
    sealed_at: u64,
    entries: &[WindowEntry],
    resolve: &mut Resolver<'_>,
    revocation_root: [u8; 32],
) -> Option<EpochResult> {
    let commitment_root = commitment_root(entries);
    let ordered = reorder(entries);
    let net = aggregate(&ordered, resolve)?;
    let netting_root = netting_root(&net);
    Some(EpochResult {
        epoch_id,
        sealed_at,
        commitment_root,
        revocation_root,
        net,
        netting_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window::WindowEntry;

    fn entry(seq: u64, ih: [u8; 32]) -> WindowEntry {
        WindowEntry {
            seq,
            intent_hash: ih,
        }
    }

    /// Ethereum 空哈希：锁定 `Keccak256`（keccak 而非 NIST SHA3-256）。
    #[test]
    fn keccak256_known_vector() {
        let mut h = Keccak256::new();
        h.update(b"");
        let out: [u8; 32] = h.finalize().into();
        assert_eq!(
            hex::encode(out),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    /// abi.encode 字节布局锁定（对齐 BatchSettler.settle）。
    #[test]
    fn abi_encode_layout_matches_solidity() {
        let net = vec![
            NetLine {
                recipient: [0xA1; 20],
                amount: 100,
            },
            NetLine {
                recipient: [0xA2; 20],
                amount: 200,
            },
        ];
        let got = abi_encode_net(&net);
        let expect = concat!(
            "0000000000000000000000000000000000000000000000000000000000000020",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "000000000000000000000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "0000000000000000000000000000000000000000000000000000000000000064",
            "000000000000000000000000a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
            "00000000000000000000000000000000000000000000000000000000000000c8",
        );
        let got_hex = hex::encode(&got);
        assert_eq!(
            got_hex,
            expect,
            "\ngot len={} expect len={}\ngot={}\nexpect={}",
            got_hex.len(),
            expect.len(),
            got_hex,
            expect
        );
    }

    /// 承诺根：merkle over (seq‖intent_hash)，公开可复算。
    #[test]
    fn commitment_root_reproducible() {
        let entries = vec![
            entry(1, [0x11; 32]),
            entry(2, [0x22; 32]),
            entry(3, [0x33; 32]),
        ];
        let r1 = commitment_root(&entries);
        let r2 = commitment_root(&entries);
        assert_eq!(r1, r2);
        // 顺序敏感：seq 序变 → 根变。
        let shuffled = vec![entries[2], entries[0], entries[1]];
        assert_ne!(r1, commitment_root(&shuffled));
    }

    /// 确定性重排：按 intent_hash 升序，同 seed 两跑一致。
    #[test]
    fn reorder_is_deterministic_and_by_hash() {
        let entries = vec![
            entry(1, [0x03; 32]),
            entry(2, [0x01; 32]),
            entry(3, [0x02; 32]),
        ];
        let a = reorder(&entries);
        let b = reorder(&entries);
        assert_eq!(a, b);
        assert_eq!(
            a.iter().map(|e| e.intent_hash[0]).collect::<Vec<_>>(),
            vec![0x01, 0x02, 0x03]
        );
        // 并列：同 intent_hash 按 seq。
        let tie = vec![entry(9, [0x01; 32]), entry(3, [0x01; 32])];
        assert_eq!(
            reorder(&tie).iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![3, 9]
        );
    }

    /// 净额按 recipient 聚合，规范序（recipient 升序）。
    #[test]
    fn aggregate_sums_by_recipient_sorted() {
        let entries = vec![
            entry(1, [0x01; 32]),
            entry(2, [0x02; 32]),
            entry(3, [0x03; 32]),
            entry(4, [0x04; 32]),
        ];
        // 索引：01→B, 02→A, 03→B, 04→A。
        let mut resolve = |ih: &[u8; 32]| -> Option<([u8; 20], u64)> {
            let (r, amt) = match ih[0] {
                0x01 => ([0xBB; 20], 10),
                0x02 => ([0xAA; 20], 20),
                0x03 => ([0xBB; 20], 30),
                0x04 => ([0xAA; 20], 40),
                _ => return None,
            };
            Some((r, amt))
        };
        let net = aggregate(&entries, &mut resolve).unwrap();
        // 排序：A(AA) 在前，B(BB) 在后。
        assert_eq!(net.len(), 2);
        assert_eq!(net[0].recipient, [0xAA; 20]);
        assert_eq!(net[0].amount, 60);
        assert_eq!(net[1].recipient, [0xBB; 20]);
        assert_eq!(net[1].amount, 40);
    }

    /// 缺失解析 → None（调用方丢弃该 epoch）。
    #[test]
    fn aggregate_none_on_missing_resolve() {
        let entries = vec![entry(1, [0x01; 32]), entry(2, [0x02; 32])];
        let mut resolve = |ih: &[u8; 32]| -> Option<([u8; 20], u64)> {
            (ih[0] == 0x01).then_some(([0xAA; 20], 5))
        };
        assert!(aggregate(&entries, &mut resolve).is_none());
    }

    /// B11 确定性：同 entries + 同 resolve → 承诺根 / 净额根一致。
    #[test]
    fn build_epoch_deterministic() {
        let entries: Vec<WindowEntry> = (0..10).map(|i| entry(i, [(i as u8) ^ 0x5A; 32])).collect();
        let mut r1 = |ih: &[u8; 32]| Some(([ih[0]; 20], ih[1] as u64));
        let mut r2 = |ih: &[u8; 32]| Some(([ih[0]; 20], ih[1] as u64));
        let a = build_epoch(7, 1_700_000_000, &entries, &mut r1, [0xAB; 32]).unwrap();
        let b = build_epoch(7, 1_700_000_000, &entries, &mut r2, [0xAB; 32]).unwrap();
        assert_eq!(a.commitment_root, b.commitment_root);
        assert_eq!(a.revocation_root, [0xAB; 32]);
        assert_eq!(a.netting_root, b.netting_root);
        assert_eq!(a.net, b.net);
    }
}
