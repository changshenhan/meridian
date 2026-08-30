//! 独立验证者面（TECH_SPEC §6.18，P2-1）——镜像复算 → 检出 → 欺诈证明构造。
//!
//! 写者与验证者分离（§6.17 决策 C）的最小实证：验证者**不复用运营者内存态**，吃
//! 「已接受意图镜像流」（信封 + `Receipt.seq`；生产口径 = 网关接受流的多播副本），
//! 走与运营者同一的生产 netting 路径（`lattice::build_epoch`，确定性重排/聚合 B11）
//! 复算账本，与链上结算面比对，检出 commit≠settle 后构造 `BatchSettler.FraudProof`
//! 的入参候选。链 I/O（settle calldata 解码、challenge 提交）不在本模块（无 alloy
//! 依赖），见 `contracts/rust-smoke/src/bin/verifier_drill.rs`。
//!
//! 两条纪律（§6.18.3）：
//! · **出证闸（保押金）**：镜像重算承诺根 == 链上 `commitmentRoot` 才出证——兄弟路径
//!   由镜像叶集构造，镜像不完整时兄弟路径必然错误（链上 `BadInclusionProof` → 押金
//!   销毁，S-38 驳回即没收）。根不符时检出信号只告警不上链。
//! · **逐条自检（fail-closed）**：每条出证意图构造后用 `merkle::verify_inclusion`
//!   重验；任何一条不过即丢弃整个候选（绝不上链赌押金）。
//!
//! 诚实边界（§6.18.5）：镜像被篡改/缺漏 = 检出率下降，不产生假证——链上
//! `_verifyFraud` 二次验证是最终锚；撤销根比对不在本模块（挂 P2-3「过时撤销根」）。

use std::collections::BTreeMap;

use meridian_core::dsa::{self, SpendIntent};

use crate::lattice::{self, NetLine};
use crate::merkle::{self, leaf as merkle_leaf};
use crate::window::WindowEntry;

/// 单次挑战携带的意图上界（= `BatchSettler.MAX_INTENTS_PER_CHALLENGE`；超限 →
/// `TooManyIntents` 驳回没收押金）。
pub const MAX_INTENTS_PER_CHALLENGE: usize = 32;
/// `BatchSettler.FraudProof.kind`：1 = 漏单，2 = 低付。
pub const KIND_MISSING: u8 = 1;
pub const KIND_UNDERPAID: u8 = 2;

/// 镜像条目：一条已接受意图（完整信封）+ 摄取序号。
///
/// 重发（S-12 幂等）返回同一 `seq` 的同一意图——镜像侧视为同一条（按 seq 去重）；
/// 同 `seq` 不同意图 = 镜像自相矛盾，`recompute` 返回 `None`（fail-closed）。
#[derive(Debug, Clone)]
pub struct MirrorIntent {
    pub intent: SpendIntent,
    pub seq: u64,
}

/// 镜像复算产物（检出与出证的验证者侧数据面）。
#[derive(Debug, Clone)]
pub struct Recomputed {
    /// 镜像叶集重算的承诺根（出证闸的左侧）。
    pub commitment_root: [u8; 32],
    /// 镜像净额（生产 netting 路径，BTreeMap recipient 字节升序）。
    pub net: Vec<NetLine>,
    /// 叶集（`leaf(seq, intent_hash)`，与 `entries` 同序）——出证兄弟路径的构造源。
    pub leaves: Vec<[u8; 32]>,
    /// seq 升序条目；承诺格叶索引 = 本 vec 下标。
    pub entries: Vec<WindowEntry>,
    /// 明文意图，与 `entries` 同序（IntentProof 的哈希 preimage 源——WAL 面没有这份
    /// 数据，见 §6.18.1「WAL 副本不可独立出证」）。
    pub intents: Vec<SpendIntent>,
}

/// 链上结算面（§6.18.2：net[] 来自 settle 交易 calldata，承诺根来自 `epochs()` getter
/// / Commit 事件；调用方须先自检 `netting_root == keccak256(abi.encode(net))`）。
#[derive(Debug, Clone)]
pub struct ChainEpoch {
    pub commitment_root: [u8; 32],
    pub net: Vec<NetLine>,
}

/// 检出信号（诊断面，§6.18.3 ①-⑤）。任何信号都不直接上链——出证走 [`fraud_candidates`]。
#[derive(Debug, Clone, Default)]
pub struct Detection {
    /// ① 镜像重算承诺根 == 链上 commitmentRoot。
    pub commitment_root_match: bool,
    /// ② 漏单候选（kind1 可证）：镜像收款人在链上 net[] 无行。
    pub missing: Vec<MissingLine>,
    /// ③ 低付候选（kind2 可证）：链上行额 < 该收款人已承诺 Σ。
    pub underpaid: Vec<UnderpaidLine>,
    /// ④ 多付（运营者自损，仅告警）：链上行额 > 已承诺 Σ。
    pub overpaid: Vec<NetDelta>,
    /// ⑤ 凭空收款行（资金流向未承诺方，合约无 kind，仅告警）。
    pub phantom: Vec<PhantomLine>,
}

impl Detection {
    /// 是否零信号（诚实面：根同 + 净额逐行同 + 无多付/凭空行）。
    pub fn is_clean(&self) -> bool {
        self.commitment_root_match
            && self.missing.is_empty()
            && self.underpaid.is_empty()
            && self.overpaid.is_empty()
            && self.phantom.is_empty()
    }
}

/// ② 漏单：`recipient` 在链上 net[] 无行；`intent_seqs` 为该收款人的镜像意图（seq 升序）。
#[derive(Debug, Clone)]
pub struct MissingLine {
    pub recipient: [u8; 20],
    pub intent_seqs: Vec<u64>,
}

/// ③ 低付：链上 net 行 `target_net_index` 付了 `chain_amount`，该收款人已承诺 Σ 为
/// `honest_sum`（u128——Σamounts 语义，u64 和可能溢出，只有 kind2 判得出来）。
#[derive(Debug, Clone)]
pub struct UnderpaidLine {
    pub target_net_index: usize,
    pub recipient: [u8; 20],
    pub honest_sum: u128,
    pub chain_amount: u64,
    pub intent_seqs: Vec<u64>,
}

/// ④ 多付：链上行额与该收款人已承诺 Σ 的差方向记录（运营者自损，不可挑战）。
#[derive(Debug, Clone)]
pub struct NetDelta {
    pub recipient: [u8; 20],
    pub honest_sum: u128,
    pub chain_amount: u64,
}

/// ⑤ 凭空收款行：链上行收款人在镜像净额中无任何已承诺意图。
#[derive(Debug, Clone)]
pub struct PhantomLine {
    pub recipient: [u8; 20],
    pub chain_amount: u64,
}

/// 一条出证意图的完整证据（→ `BatchSettler.IntentProof` 的全部字段源）。
#[derive(Debug, Clone)]
pub struct IntentEvidence {
    pub intent: SpendIntent,
    pub seq: u64,
    /// 承诺格叶索引（= seq 在叶集中的名次）。
    pub leaf_index: usize,
    /// 已接受意图数（未补齐叶数；合约侧 `Merkle.treeDepth` 按它算深度）。
    pub accepted_count: usize,
    /// 兄弟路径（自底层向上）。
    pub siblings: Vec<[u8; 32]>,
}

/// 一个可上链的欺诈证明候选（→ `BatchSettler.FraudProof`）。
#[derive(Debug, Clone)]
pub struct FraudCandidate {
    /// [`KIND_MISSING`] / [`KIND_UNDERPAID`]。
    pub kind: u8,
    /// kind2 的目标 net 行（kind1 恒 0）。
    pub target_net_index: usize,
    pub intents: Vec<IntentEvidence>,
}

impl FraudCandidate {
    /// Σ（出证意图金额）——kind2 的断言面：必须 > 链上目标行额。
    pub fn sum_amount(&self) -> u128 {
        self.intents.iter().map(|e| e.intent.amount as u128).sum()
    }
}

/// 镜像复算：走生产 netting 路径（§6.18.3——验证者与运营者同一确定性代码，不同只在
/// 输入）。`revocation_root` 占位传入（撤销根比对不在本砖，§6.18.5）；返回 `None`
/// 仅当镜像自相矛盾（同 seq 不同意图）。
pub fn recompute(mirror: &[MirrorIntent], revocation_root: [u8; 32]) -> Option<Recomputed> {
    // seq 去重：重发（S-12）= 同 seq 同意图，取第一条即可；同 seq 不同意图 = 矛盾。
    let mut by_seq: BTreeMap<u64, &MirrorIntent> = BTreeMap::new();
    for m in mirror {
        match by_seq.get(&m.seq) {
            Some(prev) => {
                if dsa::intent_hash(&prev.intent) != dsa::intent_hash(&m.intent) {
                    return None;
                }
            }
            None => {
                by_seq.insert(m.seq, m);
            }
        }
    }
    // entries（seq 升序）与明文 intents 同一遍构造（同序，出证 preimage 随取随有）。
    let mut entries = Vec::with_capacity(by_seq.len());
    let mut intents = Vec::with_capacity(by_seq.len());
    for (&seq, m) in &by_seq {
        entries.push(WindowEntry {
            seq,
            intent_hash: dsa::intent_hash(&m.intent),
        });
        intents.push(m.intent.clone());
    }
    // 解析闭包：intent_hash → (recipient, amount)（`lattice::aggregate` 的净额源）。
    let mut resolve = |ih: &[u8; 32]| -> Option<([u8; 20], u64)> {
        intents
            .iter()
            .find(|it| dsa::intent_hash(it) == *ih)
            .map(|it| (it.recipient, it.amount))
    };
    let res = lattice::build_epoch(0, 0, &entries, &mut resolve, revocation_root)?;
    Some(Recomputed {
        commitment_root: res.commitment_root,
        net: res.net,
        leaves: entries
            .iter()
            .map(|e| merkle_leaf(e.seq, e.intent_hash))
            .collect(),
        entries,
        intents,
    })
}

/// 检出（§6.18.3 ①-⑤）。纯诊断：不构造兄弟路径、不看出证闸——根不符时信号仍报出，
/// 但只有 [`fraud_candidates`] 决定能不能上链。
pub fn detect(rec: &Recomputed, chain: &ChainEpoch) -> Detection {
    let mut det = Detection {
        commitment_root_match: rec.commitment_root == chain.commitment_root,
        ..Default::default()
    };
    // 镜像净额行 → 链上同名行比对（net 规模小，线性找行；行序 = recipient 字节升序）。
    let mut chain_taken = vec![false; chain.net.len()];
    for line in &rec.net {
        match chain.net.iter().position(|c| c.recipient == line.recipient) {
            None => det.missing.push(MissingLine {
                recipient: line.recipient,
                intent_seqs: recipient_seqs(rec, line.recipient),
            }),
            Some(idx) => {
                chain_taken[idx] = true;
                let honest_sum = line.amount as u128;
                if honest_sum > chain.net[idx].amount as u128 {
                    det.underpaid.push(UnderpaidLine {
                        target_net_index: idx,
                        recipient: line.recipient,
                        honest_sum,
                        chain_amount: chain.net[idx].amount,
                        intent_seqs: recipient_seqs(rec, line.recipient),
                    });
                } else if chain.net[idx].amount as u128 > honest_sum {
                    det.overpaid.push(NetDelta {
                        recipient: line.recipient,
                        honest_sum,
                        chain_amount: chain.net[idx].amount,
                    });
                }
            }
        }
    }
    for (idx, c) in chain.net.iter().enumerate() {
        if !chain_taken[idx] {
            det.phantom.push(PhantomLine {
                recipient: c.recipient,
                chain_amount: c.amount,
            });
        }
    }
    det
}

/// 欺诈证明候选（出证面，§6.18.3 出证闸）。返回空 = 不可出证（根不符 / 无 kind1/kind2
/// 证据 / 自检失败）。
pub fn fraud_candidates(rec: &Recomputed, chain: &ChainEpoch) -> Vec<FraudCandidate> {
    // 出证闸：兄弟路径来自镜像叶集——根不等 ⇒ 路径必然错误 ⇒ 上链 = 押金白送。
    if rec.commitment_root != chain.commitment_root {
        return Vec::new();
    }
    let det = detect(rec, chain);
    let mut out = Vec::new();
    // kind1 漏单：合约要求恰 1 条意图（`BadFraudKind`），每缺失收款人产一个候选，
    // 取该收款人 seq 最小的一条（确定性；其余条目留给后续挑战轮）。
    for m in &det.missing {
        let Some(seq) = m.intent_seqs.first().copied() else {
            continue;
        };
        let Some(c) = evidence_for(rec, seq, chain.commitment_root) else {
            continue;
        };
        out.push(FraudCandidate {
            kind: KIND_MISSING,
            target_net_index: 0,
            intents: vec![c],
        });
    }
    // kind2 低付：同收款人意图子集 ≤ 上界，Σ > 链上行额。超上界时按金额贪心取
    //（子集元素同为该收款人——`BadFraudKind` 的跨收款人守卫不触发）。
    for u in &det.underpaid {
        let mut idxs: Vec<usize> = (0..rec.intents.len())
            .filter(|&i| rec.intents[i].recipient == u.recipient)
            .collect();
        // 金额降序（并列按 seq 升序破平，全确定）——贪心用最少意图数过线，留出上界余量。
        idxs.sort_by_key(|&i| (std::cmp::Reverse(rec.intents[i].amount), rec.entries[i].seq));
        idxs.truncate(MAX_INTENTS_PER_CHALLENGE);
        let mut intents = Vec::with_capacity(idxs.len());
        let mut sum = 0u128;
        for &i in &idxs {
            let Some(c) = evidence_at(rec, i, chain.commitment_root) else {
                intents.clear();
                break;
            };
            sum += c.intent.amount as u128;
            intents.push(c);
        }
        // 贪心取最大金额 Σ 仍 ≤ 行额 = 镜像面与检出矛盾（不该发生）；不出证。
        if intents.is_empty() || sum <= u.chain_amount as u128 {
            continue;
        }
        out.push(FraudCandidate {
            kind: KIND_UNDERPAID,
            target_net_index: u.target_net_index,
            intents,
        });
    }
    out
}

/// 某收款人的全部镜像意图 seq（升序；`recompute` 的 entries 已按 seq 升序）。
fn recipient_seqs(rec: &Recomputed, recipient: [u8; 20]) -> Vec<u64> {
    rec.entries
        .iter()
        .zip(&rec.intents)
        .filter(|(_, it)| it.recipient == recipient)
        .map(|(e, _)| e.seq)
        .collect()
}

/// 按 seq 出证一条意图（叶索引 = seq 在 entries 中的名次）。
fn evidence_for(rec: &Recomputed, seq: u64, root: [u8; 32]) -> Option<IntentEvidence> {
    let i = rec.entries.iter().position(|e| e.seq == seq)?;
    evidence_at(rec, i, root)
}

/// 按叶索引出证一条意图，出证前过逐条自检（fail-closed：任一不过 → None → 候选丢弃）。
fn evidence_at(rec: &Recomputed, i: usize, root: [u8; 32]) -> Option<IntentEvidence> {
    let entry = rec.entries.get(i)?;
    let intent = rec.intents.get(i)?;
    if dsa::intent_hash(intent) != entry.intent_hash {
        return None; // 明文与承诺叶错位（镜像被篡改）——绝不带着错路径上链
    }
    let (accepted_count, siblings) = merkle::inclusion_proof(&rec.leaves, i)?;
    // 自检：重推根必须等于链上承诺根（= 出证闸成立的逐条复述）。
    if !merkle::verify_inclusion(
        merkle_leaf(entry.seq, entry.intent_hash),
        i,
        accepted_count,
        &siblings,
        root,
    ) {
        return None;
    }
    Some(IntentEvidence {
        intent: intent.clone(),
        seq: entry.seq,
        leaf_index: i,
        accepted_count,
        siblings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 确定性镜像：`i` 号意图 → 收款人 `[0xEE;19]‖(i % recipients)`，金额 `100 + i`。
    fn make_mirror(n: usize, recipients: usize) -> Vec<MirrorIntent> {
        (0..n)
            .map(|i| {
                let mut recipient = [0xEEu8; 20];
                recipient[19] = (i % recipients) as u8;
                MirrorIntent {
                    intent: SpendIntent {
                        agent: [0x01; 20],
                        delegation_hash: [0xDD; 32],
                        recipient,
                        amount: 100 + i as u64,
                        category: [0; 32],
                        spend_nonce: i as u64 + 1,
                        memo: None,
                        expires_at: 1_000,
                    },
                    seq: i as u64,
                }
            })
            .collect()
    }

    /// 诚实链上面 = 镜像复算的根与净额。
    fn honest_chain(rec: &Recomputed) -> ChainEpoch {
        ChainEpoch {
            commitment_root: rec.commitment_root,
            net: rec.net.clone(),
        }
    }

    fn recipient(rec: &Recomputed, i: usize) -> [u8; 20] {
        rec.intents
            .iter()
            .find(|it| it.spend_nonce == i as u64 + 1)
            .unwrap()
            .recipient
    }

    #[test]
    fn honest_epoch_yields_no_detection_and_no_candidates() {
        let mirror = make_mirror(9, 3);
        let rec = recompute(&mirror, [0; 32]).expect("镜像自洽");
        let chain = honest_chain(&rec);
        let det = detect(&rec, &chain);
        assert!(det.is_clean(), "诚实面必须零信号：{det:?}");
        assert!(fraud_candidates(&rec, &chain).is_empty(), "诚实面不得出证");
    }

    #[test]
    fn kind1_missing_recipient_is_detected_and_provable() {
        let mirror = make_mirror(9, 3);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        // 人为错账：抽掉一个收款人行（settle 漏单形态）。
        let drop = recipient(&rec, 0);
        let mut net = rec.net.clone();
        let dropped_amount = net
            .remove(net.iter().position(|l| l.recipient == drop).unwrap())
            .amount;
        let chain = ChainEpoch {
            commitment_root: rec.commitment_root,
            net,
        };

        let det = detect(&rec, &chain);
        assert!(det.commitment_root_match, "承诺根仍同（错账在净额面）");
        assert_eq!(det.missing.len(), 1, "恰一个漏单收款人");
        assert_eq!(det.missing[0].recipient, drop);
        assert_eq!(
            det.missing[0].intent_seqs.len(),
            3,
            "该收款人的全部镜像意图"
        );

        let cands = fraud_candidates(&rec, &chain);
        assert_eq!(cands.len(), 1, "每缺失收款人一个 kind1 候选");
        let c = &cands[0];
        assert_eq!(c.kind, KIND_MISSING);
        assert_eq!(c.intents.len(), 1, "kind1 恰 1 条意图（BadFraudKind）");
        assert_eq!(c.intents[0].intent.recipient, drop);
        // 取该收款人 seq 最小的一条（确定性），其金额 ≠ 行额（行额是 3 笔的和）。
        assert_ne!(c.intents[0].intent.amount as u128, dropped_amount as u128);
        // 逐条自检独立复述：兄弟路径重推 == 链上承诺根。
        for e in &c.intents {
            assert!(merkle::verify_inclusion(
                merkle_leaf(e.seq, dsa::intent_hash(&e.intent)),
                e.leaf_index,
                e.accepted_count,
                &e.siblings,
                chain.commitment_root,
            ));
        }
    }

    #[test]
    fn kind2_underpaid_line_is_detected_and_provable() {
        let mirror = make_mirror(9, 3);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        // 人为错账：低付一行（settle 少付形态）。
        let mut net = rec.net.clone();
        net[1].amount -= 1;
        let target = net[1].recipient;
        let honest = rec.net[1].amount;
        let chain = ChainEpoch {
            commitment_root: rec.commitment_root,
            net,
        };

        let det = detect(&rec, &chain);
        assert_eq!(det.underpaid.len(), 1);
        assert_eq!(det.underpaid[0].target_net_index, 1);
        assert_eq!(det.underpaid[0].honest_sum, honest as u128);
        assert_eq!(det.underpaid[0].chain_amount, honest - 1);

        let cands = fraud_candidates(&rec, &chain);
        assert_eq!(cands.len(), 1);
        let c = &cands[0];
        assert_eq!(c.kind, KIND_UNDERPAID);
        assert_eq!(c.target_net_index, 1);
        assert!(c.sum_amount() > (honest - 1) as u128, "子集 Σ 必须 > 行额");
        assert!(
            c.intents.iter().all(|e| e.intent.recipient == target),
            "同收款人子集"
        );
        for e in &c.intents {
            assert!(merkle::verify_inclusion(
                merkle_leaf(e.seq, dsa::intent_hash(&e.intent)),
                e.leaf_index,
                e.accepted_count,
                &e.siblings,
                chain.commitment_root,
            ));
        }
    }

    #[test]
    fn overpaid_and_phantom_lines_alert_without_candidates() {
        let mirror = make_mirror(6, 2);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        // 多付一行 + 凭空收款行（合约无 kind 的两种形态）。
        let mut net = rec.net.clone();
        net[0].amount += 5;
        let phantom = [0x77u8; 20];
        net.push(NetLine {
            recipient: phantom,
            amount: 42,
        });
        let chain = ChainEpoch {
            commitment_root: rec.commitment_root,
            net,
        };

        let det = detect(&rec, &chain);
        assert!(det.commitment_root_match);
        assert!(
            det.missing.is_empty() && det.underpaid.is_empty(),
            "无 kind1/kind2 证据"
        );
        assert_eq!(det.overpaid.len(), 1);
        assert_eq!(
            det.overpaid[0].chain_amount - det.overpaid[0].honest_sum as u64,
            5
        );
        assert_eq!(det.phantom.len(), 1);
        assert_eq!(det.phantom[0].recipient, phantom);
        assert!(
            fraud_candidates(&rec, &chain).is_empty(),
            "不可挑战面不得出证"
        );
    }

    #[test]
    fn incomplete_mirror_gates_all_candidates() {
        let mirror = make_mirror(9, 3);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        let drop = recipient(&rec, 0);
        let mut net = rec.net.clone();
        net.remove(net.iter().position(|l| l.recipient == drop).unwrap());
        let chain = ChainEpoch {
            commitment_root: rec.commitment_root,
            net,
        };
        // 镜像缺一笔（该收款人全部意图缺失）→ 根不等 → 出证闸闭合，检出信号仍报。
        let short: Vec<MirrorIntent> = mirror
            .iter()
            .filter(|m| m.intent.recipient != drop)
            .cloned()
            .collect();
        let rec_short = recompute(&short, [0; 32]).unwrap();
        let det = detect(&rec_short, &chain);
        assert!(!det.commitment_root_match, "缺漏镜像重算根必然不等");
        assert!(
            fraud_candidates(&rec_short, &chain).is_empty(),
            "根不符绝不出证（保押金）"
        );
    }

    #[test]
    fn tampered_mirror_intent_gates_proofs() {
        let mirror = make_mirror(9, 3);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        let chain = honest_chain(&rec);
        // 攻击者篡改镜像信封金额 → 明文与承诺叶错位 → 根不等 → 闸闭合。
        let mut bad = mirror.clone();
        bad[4].intent.amount += 1;
        let rec_bad = recompute(&bad, [0; 32]).unwrap();
        assert_ne!(rec_bad.commitment_root, chain.commitment_root);
        assert!(fraud_candidates(&rec_bad, &chain).is_empty());
        // 明文/叶错位单独兜底（evidence 层）：即使根偶然相同也拒绝出证。
        let mut rec_mix = rec.clone();
        rec_mix.intents[2].amount += 7;
        assert!(evidence_at(&rec_mix, 2, chain.commitment_root).is_none());
    }

    #[test]
    fn underpaid_with_more_intents_than_cap_takes_greedy_subset() {
        // 40 笔落同一收款人（> 32 上界），链上只付 1 笔的金额。
        let mut mirror = make_mirror(40, 40);
        for m in mirror.iter_mut() {
            m.intent.recipient = [0xEE; 20];
        }
        let rec = recompute(&mirror, [0; 32]).unwrap();
        let mut net = rec.net.clone();
        net[0].amount = mirror[0].intent.amount; // 少付 39 笔
        let paid = net[0].amount;
        let chain = ChainEpoch {
            commitment_root: rec.commitment_root,
            net,
        };

        let cands = fraud_candidates(&rec, &chain);
        assert_eq!(cands.len(), 1);
        let c = &cands[0];
        assert_eq!(c.kind, KIND_UNDERPAID);
        assert!(
            c.intents.len() <= MAX_INTENTS_PER_CHALLENGE,
            "子集不得超合约 gas 上界（TooManyIntents → 押金没收）"
        );
        assert!(c.sum_amount() > paid as u128, "贪心子集必须过线");
    }

    #[test]
    fn mirror_conflicts_are_fail_closed() {
        let mut mirror = make_mirror(6, 2);
        let rec = recompute(&mirror, [0; 32]).expect("自洽镜像可复算");
        assert_eq!(rec.entries.len(), 6);
        // 重发同 seq 同意图 = 同一条（S-12 幂等面）。
        let dup = mirror[0].clone();
        mirror.push(dup);
        let rec_dup = recompute(&mirror, [0; 32]).unwrap();
        assert_eq!(rec_dup.entries.len(), 6, "重发不得改变复算结果");
        // 同 seq 不同意图 = 镜像自相矛盾 → None（fail-closed）。
        let mut conflict = make_mirror(6, 2);
        conflict[3].intent.amount += 1;
        conflict[3].seq = 0;
        assert!(recompute(&conflict, [0; 32]).is_none());
    }

    #[test]
    fn evidence_rejects_out_of_range_seq() {
        let mirror = make_mirror(4, 2);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        assert!(
            evidence_for(&rec, 99, rec.commitment_root).is_none(),
            "越界 seq 不得出证"
        );
    }
}
