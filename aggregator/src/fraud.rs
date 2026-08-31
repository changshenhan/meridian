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
//! P2-3 接受锚（§6.23）：kind3（已撤销消费）/ kind4（跨分片消费）两个事后欺诈 kind
//! 的检出与出证。事件时刻锚（撤销 / 绑定时刻）在 DSA / RevocationRegistry 里——经
//! [`EventAnchors`] 读面注入，本模块保持纯函数（无 alloy 依赖，链 I/O 在演练 bin）；
//! kind3/4 的出证闸在承诺根闸之上**追加接受根闸**（镜像重算 `acceptanceRoot` == 链上
//! `acceptanceRoot`——接受叶集缺漏 ⇒ 兄弟路径必然错误，缺镜像 = 检出率损失不是假证）。
//! kind1/kind2 证据同样携带接受面字段（`accepted_at` / `acceptance_siblings`），但合约
//! 对其不校验——向后兼容的证据形状。
//!
//! 诚实边界（§6.18.5）：镜像被篡改/缺漏 = 检出率下降，不产生假证——链上
//! `_verifyFraud` 二次验证是最终锚；撤销根比对仍不在本模块（挂「过时撤销根」）。

use std::collections::BTreeMap;

use mist_core::dsa::{self, SpendIntent};

use crate::lattice::{self, NetLine};
use crate::merkle::{self, leaf as merkle_leaf};
use crate::window::WindowEntry;

/// 单次挑战携带的意图上界（= `BatchSettler.MAX_INTENTS_PER_CHALLENGE`；超限 →
/// `TooManyIntents` 驳回没收押金）。
pub const MAX_INTENTS_PER_CHALLENGE: usize = 32;
/// `BatchSettler.FraudProof.kind`：1 = 漏单，2 = 低付。
pub const KIND_MISSING: u8 = 1;
pub const KIND_UNDERPAID: u8 = 2;
/// P2-3（§6.23）：3 = 已撤销消费（撤销余量外仍被本账本接受），4 = 跨分片消费（绑定
/// 他方运营者后余量内仍被接受）。与 `BatchSettler._verifyFraud` 的 kind 分支同值。
pub const KIND_REVOKED: u8 = 3;
pub const KIND_CROSS_SHARD: u8 = 4;
/// 接受时刻余量（秒）= `BatchSettler.ACCEPT_MARGIN` 同值常量（§6.23.1 定夺 3，
/// Rust / 合约两侧各自钉死；合约侧 immutable，改值走重部署）。
pub const ACCEPT_MARGIN: u64 = 300;

/// 镜像条目：一条已接受意图（完整信封）+ 摄取序号 + 接受时刻。
///
/// 重发（S-12 幂等）返回同一 `seq` 的同一意图——镜像侧视为同一条（按 seq 去重）；
/// 同 `seq` 不同意图 = 镜像自相矛盾，`recompute` 返回 `None`（fail-closed）。
#[derive(Debug, Clone)]
pub struct MirrorIntent {
    pub intent: SpendIntent,
    pub seq: u64,
    /// 接受时刻（P2-3 §6.23）：镜像摄取入口的 `now_fn()` 快照。0 = 「未知」哨兵
    /// （旧格式 WAL 恢复 / 不消费接受锚面的镜像）——时间守卫对 0 恒不成立（不可罚，
    /// 绝不因缺锚反向定罪）。
    pub accepted_at: u64,
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
    /// 平行接受树根（P2-3 §6.23）：`acceptance_leaf(seq, accepted_at)` 同叶集同序重算——
    /// kind3/4 出证闸的左侧（追加在承诺根闸之上）。
    pub acceptance_root: [u8; 32],
    /// 接受叶集（与 `entries` 同序）——kind3/4 接受树兄弟路径的构造源。
    pub acceptance_leaves: Vec<[u8; 32]>,
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
    /// 平行接受树根（`epochs()` getter / `Commit` 事件，P2-3 §6.23）——kind3/4 出证闸右侧。
    pub acceptance_root: [u8; 32],
    pub net: Vec<NetLine>,
}

/// 检出信号（诊断面，§6.18.3 ①-⑤ + §6.23 ⑥⑦）。任何信号都不直接上链——出证走
/// [`fraud_candidates`]。
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
    /// ⑥ 已撤销消费（kind3 可证，P2-3）：撤销余量外仍被本账本接受。
    pub revoked_consumption: Vec<RevokedConsumption>,
    /// ⑦ 跨分片消费（kind4 可证，P2-3）：绑定他方运营者后余量内仍被接受。
    pub cross_shard_consumption: Vec<CrossShardConsumption>,
}

impl Detection {
    /// 是否零信号（诚实面：根同 + 净额逐行同 + 无多付/凭空行 + 无事件锚越界接受）。
    pub fn is_clean(&self) -> bool {
        self.commitment_root_match
            && self.missing.is_empty()
            && self.underpaid.is_empty()
            && self.overpaid.is_empty()
            && self.phantom.is_empty()
            && self.revoked_consumption.is_empty()
            && self.cross_shard_consumption.is_empty()
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

/// ⑥ 已撤销消费（P2-3 kind3，§6.20.2）：委托在 `revoked_at` 撤销，`accepted_at ≥
/// revoked_at + ACCEPT_MARGIN` 仍被接受——撤销观察缺席的可罚本体。每 dh 只取首条
///（最低 seq，确定性；同 dh 其余条目留给后续挑战轮）。
#[derive(Debug, Clone)]
pub struct RevokedConsumption {
    pub delegation_hash: [u8; 32],
    /// 撤销时刻（[`EventAnchors::revoked_at`]）。
    pub revoked_at: u64,
    /// 首条越界接受的镜像条目。
    pub seq: u64,
    pub accepted_at: u64,
}

/// ⑦ 跨分片消费（P2-3 kind4，§6.19.1 / §6.20.2）：委托绑定到他方运营者（≠ 本账本
/// operator）后，`accepted_at ≥ bound_at + ACCEPT_MARGIN` 仍被接受——跨分片预算超支
/// 的过失形态。每 dh 只取首条（同上确定性口径）。
#[derive(Debug, Clone)]
pub struct CrossShardConsumption {
    pub delegation_hash: [u8; 32],
    /// 绑定时刻（[`EventAnchors::bound_at`]）。
    pub bound_at: u64,
    /// 绑定指向的运营者（≠ [`EventAnchors::self_operator`] 才进信号；绑回本运营者 =
    /// 本分片正常委托，§6.19.2 三态同口径）。
    pub bound_operator: [u8; 20],
    pub seq: u64,
    pub accepted_at: u64,
}

/// 事件时刻锚读面（P2-3 §6.23.1 定夺 9）：kind3/kind4 守卫的事件时刻与绑定事实在
/// DSA / RevocationRegistry 里——fraud.rs 保持纯函数（无 alloy 依赖），链 I/O 由调用方
///（`verifier_drill`）实现本 trait 注入。`None` = 事件未发生 / 未绑定（链上零地址 /
/// 零时刻归一，§6.19.2 口径：未绑定三态 fail-open，不参与定罪）。
pub trait EventAnchors {
    /// 委托撤销时刻（`RevocationRegistry.revokedAt`；`None` = 未撤销）。
    fn revoked_at(&self, delegation_hash: &[u8; 32]) -> Option<u64>;
    /// 委托绑定时刻（`DSA.boundAt`；`None` = 未绑定）。
    fn bound_at(&self, delegation_hash: &[u8; 32]) -> Option<u64>;
    /// 绑定指向的运营者（`DSA.operatorOf`；`None` = 零地址 = 未绑定）。
    fn operator_of(&self, delegation_hash: &[u8; 32]) -> Option<[u8; 20]>;
    /// 本账本运营者（`BatchSettler.operator`）——跨分片判定的自指基线。
    fn self_operator(&self) -> [u8; 20];
}

/// 一条出证意图的完整证据（→ `BatchSettler.IntentProof` 的全部字段源）。
#[derive(Debug, Clone)]
pub struct IntentEvidence {
    pub intent: SpendIntent,
    pub seq: u64,
    /// 承诺格叶索引（= seq 在叶集中的名次；接受树同叶序 ⇒ 同索引，§6.23.1 定夺 6）。
    pub leaf_index: usize,
    /// 已接受意图数（未补齐叶数；合约侧 `Merkle.treeDepth` 按它算深度）。
    pub accepted_count: usize,
    /// 承诺树兄弟路径（自底层向上）。
    pub siblings: Vec<[u8; 32]>,
    /// 接受时刻（kind3/4 时间守卫的输入；kind1/2 随证据携带但合约不校验）。
    pub accepted_at: u64,
    /// 接受树兄弟路径（与承诺路径同深度；kind3/4 必验，kind1/2 合约不校验）。
    pub acceptance_siblings: Vec<[u8; 32]>,
}

/// 一个可上链的欺诈证明候选（→ `BatchSettler.FraudProof`）。
#[derive(Debug, Clone)]
pub struct FraudCandidate {
    /// [`KIND_MISSING`] / [`KIND_UNDERPAID`] / [`KIND_REVOKED`] / [`KIND_CROSS_SHARD`]。
    pub kind: u8,
    /// kind2 的目标 net 行（kind1/kind3/kind4 恒 0）。
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
            // 镜像侧接受时刻锚（P2-3 §6.23）：镜像摄取入口快照原样落账本面；0 = 「未知」
            // 哨兵（旧格式 WAL 恢复 / 不消费接受锚面的镜像）——时间守卫对 0 恒不成立。
            accepted_at: m.accepted_at,
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
        acceptance_root: res.acceptance_root,
        acceptance_leaves: entries
            .iter()
            .map(|e| merkle::acceptance_leaf(e.seq, e.accepted_at))
            .collect(),
        entries,
        intents,
    })
}

/// 余量判定（P2-3）：欺诈成立 ⇔ 事件时刻 + [`ACCEPT_MARGIN`] ≤ 接受时刻——与合约
/// `eventAt + ACCEPT_MARGIN > acceptedAt → NotFraud` 同式（等号落在可罚侧）。
/// `checked_add` 防时刻溢出：u64 域内真和 > `u64::MAX` ⇒ 链上 uint256 域同式必判
/// `NotFraud`，此处恒「不罚」（两侧口径一致，绝不假阳性）。
fn margin_exceeded(event_at: u64, accepted_at: u64) -> bool {
    match event_at.checked_add(ACCEPT_MARGIN) {
        Some(deadline) => accepted_at >= deadline,
        None => false,
    }
}

/// 检出（§6.18.3 ①-⑤ + §6.23 ⑥⑦）。纯诊断：不构造兄弟路径、不看出证闸——根不符时
/// 信号仍报出，但只有 [`fraud_candidates`] 决定能不能上链。⑥⑦ 依赖 [`EventAnchors`]：
/// 锚缺席（实现返回 `None`）= 信号静默缺席（检出率损失，不是假证）。
pub fn detect(rec: &Recomputed, chain: &ChainEpoch, anchors: &dyn EventAnchors) -> Detection {
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
    // ⑥⑦ 事件时刻锚检测（P2-3 §6.23）：按 dh 聚合镜像条目（entries 已按 seq 升序，
    // 聚合保序），每 dh 只取首条越界接受——确定性出证锚（同 dh 其余条目留给后续轮）。
    let mut by_dh: BTreeMap<[u8; 32], Vec<usize>> = BTreeMap::new();
    for (i, it) in rec.intents.iter().enumerate() {
        by_dh.entry(it.delegation_hash).or_default().push(i);
    }
    let self_op = anchors.self_operator();
    for (dh, idxs) in &by_dh {
        // ⑥ 已撤销消费：撤销余量外（含 `revoked_at + margin == acceptedAt` 边界）仍被接受。
        if let Some(revoked_at) = anchors.revoked_at(dh) {
            if let Some(&i) = idxs
                .iter()
                .find(|&&i| margin_exceeded(revoked_at, rec.entries[i].accepted_at))
            {
                det.revoked_consumption.push(RevokedConsumption {
                    delegation_hash: *dh,
                    revoked_at,
                    seq: rec.entries[i].seq,
                    accepted_at: rec.entries[i].accepted_at,
                });
            }
        }
        // ⑦ 跨分片消费：绑定指向他方运营者（未绑定 / 绑回本运营者 = 本分片正常委托，
        // §6.19.2 三态同口径）且余量外仍被接受。
        if let Some(bound_operator) = anchors.operator_of(dh) {
            if bound_operator != self_op {
                if let Some(bound_at) = anchors.bound_at(dh) {
                    if let Some(&i) = idxs
                        .iter()
                        .find(|&&i| margin_exceeded(bound_at, rec.entries[i].accepted_at))
                    {
                        det.cross_shard_consumption.push(CrossShardConsumption {
                            delegation_hash: *dh,
                            bound_at,
                            bound_operator,
                            seq: rec.entries[i].seq,
                            accepted_at: rec.entries[i].accepted_at,
                        });
                    }
                }
            }
        }
    }
    det
}

/// 欺诈证明候选（出证面，§6.18.3 出证闸 + §6.23 接受根闸）。返回空 = 不可出证（根
/// 不符 / 无证据 / 自检失败）。
pub fn fraud_candidates(
    rec: &Recomputed,
    chain: &ChainEpoch,
    anchors: &dyn EventAnchors,
) -> Vec<FraudCandidate> {
    // 出证闸：兄弟路径来自镜像叶集——根不等 ⇒ 路径必然错误 ⇒ 上链 = 押金白送。
    if rec.commitment_root != chain.commitment_root {
        return Vec::new();
    }
    // P2-3 接受根闸（kind3/4 专用，§6.23.1 定夺 9）：接受树兄弟路径来自镜像接受叶集，
    // 镜像接受面缺漏 ⇒ 路径必然错误 ⇒ 不出证（检出率损失不是假证，§6.18.3 同款）。
    // kind1/kind2 证据虽携带接受面字段，合约对其不校验——不受此闸影响（其接受路径
    // 对镜像根自检保良构，见下方 kind1/kind2 出证点）。
    let acceptance_anchored = rec.acceptance_root == chain.acceptance_root;
    let det = detect(rec, chain, anchors);
    let mut out = Vec::new();
    // kind1 漏单：合约要求恰 1 条意图（`BadFraudKind`），每缺失收款人产一个候选，
    // 取该收款人 seq 最小的一条（确定性；其余条目留给后续挑战轮）。
    // 接受面路径对**镜像根**自检（§6.23.1 定夺 9：kind1/2 证据携带接受字段但合约不校验
    // ——字段只需良构；链上根闸只挡 kind3/4，此处对链上根自检会吞掉 kind1/2 候选）。
    for m in &det.missing {
        let Some(seq) = m.intent_seqs.first().copied() else {
            continue;
        };
        let Some(c) = evidence_for(rec, seq, chain.commitment_root, rec.acceptance_root) else {
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
            // 同 kind1：接受面路径对镜像根自检（合约对 kind2 不校验接受字段）。
            let Some(c) = evidence_at(rec, i, chain.commitment_root, rec.acceptance_root) else {
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
    // kind3/kind4：单意图（BadFraudKind 同款计数闸，§6.23.1 定夺 8），每 dh 最低 seq
    // 的越界接受；接受根闸闭合时不产候选（检出信号 ⑥⑦ 仍由 `detect` 报出）。
    if acceptance_anchored {
        for r in &det.revoked_consumption {
            let Some(c) = evidence_for(rec, r.seq, chain.commitment_root, chain.acceptance_root)
            else {
                continue;
            };
            out.push(FraudCandidate {
                kind: KIND_REVOKED,
                target_net_index: 0,
                intents: vec![c],
            });
        }
        for cs in &det.cross_shard_consumption {
            let Some(c) = evidence_for(rec, cs.seq, chain.commitment_root, chain.acceptance_root)
            else {
                continue;
            };
            out.push(FraudCandidate {
                kind: KIND_CROSS_SHARD,
                target_net_index: 0,
                intents: vec![c],
            });
        }
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

/// 按 seq 出证一条意图（叶索引 = seq 在 entries 中的名次；两根各过各的闸）。
///
/// pub 面（§6.18.3 负向演示）：验证者演练的「朴素证明」需要绕过 [`fraud_candidates`]
/// 的检出面手工构造——事件前接受的意图在聚合器侧检出为零，出证函数仍须可达，用于
/// 链上守卫驳回路径（`ChallengeRejected(NotFraud)`）的实证。逐条自检照常生效。
pub fn evidence_for(
    rec: &Recomputed,
    seq: u64,
    commitment_root: [u8; 32],
    acceptance_root: [u8; 32],
) -> Option<IntentEvidence> {
    let i = rec.entries.iter().position(|e| e.seq == seq)?;
    evidence_at(rec, i, commitment_root, acceptance_root)
}

/// 按叶索引出证一条意图，出证前过逐条自检（fail-closed：任一不过 → None → 候选丢弃）。
/// 承诺树与接受树同叶集同序 ⇒ 复用同一叶索引 / 深度，两条路径同批自检（§6.23.1 定夺 6）。
fn evidence_at(
    rec: &Recomputed,
    i: usize,
    commitment_root: [u8; 32],
    acceptance_root: [u8; 32],
) -> Option<IntentEvidence> {
    let entry = rec.entries.get(i)?;
    let intent = rec.intents.get(i)?;
    if dsa::intent_hash(intent) != entry.intent_hash {
        return None; // 明文与承诺叶错位（镜像被篡改）——绝不带着错路径上链
    }
    let (accepted_count, siblings) = merkle::inclusion_proof(&rec.leaves, i)?;
    let (acc_count, acceptance_siblings) = merkle::inclusion_proof(&rec.acceptance_leaves, i)?;
    // 自检：重推根必须等于链上根（= 出证闸成立的逐条复述）。
    if !merkle::verify_inclusion(
        merkle_leaf(entry.seq, entry.intent_hash),
        i,
        accepted_count,
        &siblings,
        commitment_root,
    ) {
        return None;
    }
    if !merkle::verify_inclusion(
        merkle::acceptance_leaf(entry.seq, entry.accepted_at),
        i,
        acc_count,
        &acceptance_siblings,
        acceptance_root,
    ) {
        return None;
    }
    Some(IntentEvidence {
        intent: intent.clone(),
        seq: entry.seq,
        leaf_index: i,
        accepted_count,
        siblings,
        accepted_at: entry.accepted_at,
        acceptance_siblings,
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
                    // 缺省 = 「未知」哨兵（旧格式 WAL 同语义）：kind1/2 用例不消费接受锚面。
                    accepted_at: 0,
                }
            })
            .collect()
    }

    /// kind3/4 场景镜像：单条意图（合约单意图闸的最小面），委托哈希 / 接受时刻参数化。
    fn single_mirror(dh: [u8; 32], accepted_at: u64) -> Vec<MirrorIntent> {
        vec![MirrorIntent {
            intent: SpendIntent {
                agent: [0x01; 20],
                delegation_hash: dh,
                recipient: [0xB1; 20],
                amount: 100,
                category: [0; 32],
                spend_nonce: 1,
                memo: None,
                expires_at: 1_000,
            },
            seq: 1,
            accepted_at,
        }]
    }

    /// 全部条目盖同一接受时刻（kind3/4 场景：单一锚时刻足够，§6.23.1 定夺 2）。
    fn stamp_accepted_at(mirror: &mut [MirrorIntent], at: u64) {
        for m in mirror.iter_mut() {
            m.accepted_at = at;
        }
    }

    /// 测试锚：静态表实现（生产形态 = 演练 bin 的链上读数，§6.23.1 定夺 9）。空表 =
    /// 「无锚可用」——⑥⑦ 静默缺席（检出率损失，不是假证）。
    struct TableAnchors {
        revoked: BTreeMap<[u8; 32], u64>,
        bound: BTreeMap<[u8; 32], (u64, [u8; 20])>,
        self_op: [u8; 20],
    }

    impl Default for TableAnchors {
        fn default() -> Self {
            Self {
                revoked: BTreeMap::new(),
                bound: BTreeMap::new(),
                self_op: [0x11; 20],
            }
        }
    }

    impl TableAnchors {
        fn revoked(mut self, dh: [u8; 32], at: u64) -> Self {
            self.revoked.insert(dh, at);
            self
        }

        fn bound(mut self, dh: [u8; 32], at: u64, op: [u8; 20]) -> Self {
            self.bound.insert(dh, (at, op));
            self
        }
    }

    impl EventAnchors for TableAnchors {
        fn revoked_at(&self, dh: &[u8; 32]) -> Option<u64> {
            self.revoked.get(dh).copied()
        }
        fn bound_at(&self, dh: &[u8; 32]) -> Option<u64> {
            self.bound.get(dh).map(|(at, _)| *at)
        }
        fn operator_of(&self, dh: &[u8; 32]) -> Option<[u8; 20]> {
            self.bound.get(dh).map(|(_, op)| *op)
        }
        fn self_operator(&self) -> [u8; 20] {
            self.self_op
        }
    }

    /// 诚实链上面 = 镜像复算的根与净额（含平行接受树根）。
    fn honest_chain(rec: &Recomputed) -> ChainEpoch {
        ChainEpoch {
            commitment_root: rec.commitment_root,
            acceptance_root: rec.acceptance_root,
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
        let det = detect(&rec, &chain, &TableAnchors::default());
        assert!(det.is_clean(), "诚实面必须零信号：{det:?}");
        assert!(
            fraud_candidates(&rec, &chain, &TableAnchors::default()).is_empty(),
            "诚实面不得出证"
        );
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
            acceptance_root: rec.acceptance_root,
            net,
        };

        let det = detect(&rec, &chain, &TableAnchors::default());
        assert!(det.commitment_root_match, "承诺根仍同（错账在净额面）");
        assert_eq!(det.missing.len(), 1, "恰一个漏单收款人");
        assert_eq!(det.missing[0].recipient, drop);
        assert_eq!(
            det.missing[0].intent_seqs.len(),
            3,
            "该收款人的全部镜像意图"
        );

        let cands = fraud_candidates(&rec, &chain, &TableAnchors::default());
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
            acceptance_root: rec.acceptance_root,
            net,
        };

        let det = detect(&rec, &chain, &TableAnchors::default());
        assert_eq!(det.underpaid.len(), 1);
        assert_eq!(det.underpaid[0].target_net_index, 1);
        assert_eq!(det.underpaid[0].honest_sum, honest as u128);
        assert_eq!(det.underpaid[0].chain_amount, honest - 1);

        let cands = fraud_candidates(&rec, &chain, &TableAnchors::default());
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
            acceptance_root: rec.acceptance_root,
            net,
        };

        let det = detect(&rec, &chain, &TableAnchors::default());
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
            fraud_candidates(&rec, &chain, &TableAnchors::default()).is_empty(),
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
            acceptance_root: rec.acceptance_root,
            net,
        };
        // 镜像缺一笔（该收款人全部意图缺失）→ 根不等 → 出证闸闭合，检出信号仍报。
        let short: Vec<MirrorIntent> = mirror
            .iter()
            .filter(|m| m.intent.recipient != drop)
            .cloned()
            .collect();
        let rec_short = recompute(&short, [0; 32]).unwrap();
        let det = detect(&rec_short, &chain, &TableAnchors::default());
        assert!(!det.commitment_root_match, "缺漏镜像重算根必然不等");
        assert!(
            fraud_candidates(&rec_short, &chain, &TableAnchors::default()).is_empty(),
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
        assert!(fraud_candidates(&rec_bad, &chain, &TableAnchors::default()).is_empty());
        // 明文/叶错位单独兜底（evidence 层）：即使根偶然相同也拒绝出证。
        let mut rec_mix = rec.clone();
        rec_mix.intents[2].amount += 7;
        assert!(evidence_at(&rec_mix, 2, chain.commitment_root, chain.acceptance_root).is_none());
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
            acceptance_root: rec.acceptance_root,
            net,
        };

        let cands = fraud_candidates(&rec, &chain, &TableAnchors::default());
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
            evidence_for(&rec, 99, rec.commitment_root, rec.acceptance_root).is_none(),
            "越界 seq 不得出证"
        );
    }

    // ------------------------------------------------------------------ P2-3 接受锚（§6.23）

    const DH3: [u8; 32] = [0xD3; 32];
    const DH4: [u8; 32] = [0xD4; 32];
    /// 事件时刻基点（撤销 / 绑定时刻；接受时刻相对它取余量内 / 外）。
    const T0: u64 = 1_700_000_000;
    /// 他方运营者（跨分片消费的绑定指向）。
    const CROSS_OP: [u8; 20] = [0xC5; 20];

    /// kind3 正向：撤销余量外仍被接受 → 信号 ⑥ + kind3 候选（单意图，双树路径同批自检）。
    #[test]
    fn kind3_revoked_consumption_is_detected_and_provable() {
        let mirror = single_mirror(DH3, T0 + 1_000);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        let chain = honest_chain(&rec);
        let anchors = TableAnchors::default().revoked(DH3, T0);

        let det = detect(&rec, &chain, &anchors);
        assert_eq!(det.revoked_consumption.len(), 1, "恰一条越界接受");
        let s = &det.revoked_consumption[0];
        assert_eq!(s.delegation_hash, DH3);
        assert_eq!(s.revoked_at, T0);
        assert_eq!(s.seq, 1);
        assert_eq!(s.accepted_at, T0 + 1_000);
        assert!(det.cross_shard_consumption.is_empty(), "⑥⑦ 独立");
        assert!(!det.is_clean(), "有信号即非诚实面");

        let cands = fraud_candidates(&rec, &chain, &anchors);
        assert_eq!(cands.len(), 1);
        let c = &cands[0];
        assert_eq!(c.kind, KIND_REVOKED);
        assert_eq!(
            c.intents.len(),
            1,
            "kind3 单意图（BadFraudKind 同款计数闸）"
        );
        let e = &c.intents[0];
        assert_eq!(e.accepted_at, T0 + 1_000);
        // 两条路径同批自检：承诺树 + 接受树重推 == 链上根。
        assert!(merkle::verify_inclusion(
            merkle_leaf(e.seq, dsa::intent_hash(&e.intent)),
            e.leaf_index,
            e.accepted_count,
            &e.siblings,
            chain.commitment_root,
        ));
        assert!(merkle::verify_inclusion(
            merkle::acceptance_leaf(e.seq, e.accepted_at),
            e.leaf_index,
            e.accepted_count,
            &e.acceptance_siblings,
            chain.acceptance_root,
        ));
    }

    /// kind3 margin 边界（与合约守卫同式）：`revokedAt + margin == acceptedAt` → 可罚
    ///（合约判 `>`，等号落在欺诈侧）；−1 → 余量之内零信号；哨兵 acceptedAt = 0 → 恒不罚。
    #[test]
    fn kind3_margin_boundaries() {
        let anchors = TableAnchors::default().revoked(DH3, T0);
        let scenario = |accepted_at: u64| {
            let rec = recompute(&single_mirror(DH3, accepted_at), [0; 32]).unwrap();
            let chain = honest_chain(&rec);
            (rec, chain)
        };

        // 等号 = 可罚。
        let (rec, chain) = scenario(T0 + ACCEPT_MARGIN);
        assert_eq!(detect(&rec, &chain, &anchors).revoked_consumption.len(), 1);
        assert_eq!(fraud_candidates(&rec, &chain, &anchors).len(), 1);

        // 余量之内第一秒：诚实面（零信号 + 不出证）。
        let (rec, chain) = scenario(T0 + ACCEPT_MARGIN - 1);
        assert!(detect(&rec, &chain, &anchors).is_clean());
        assert!(fraud_candidates(&rec, &chain, &anchors).is_empty());

        // 「未知」哨兵（旧格式 WAL，§6.23.1 定夺 1）：绝不因缺锚反向定罪。
        let (rec, chain) = scenario(0);
        assert!(detect(&rec, &chain, &anchors).is_clean());
        assert!(fraud_candidates(&rec, &chain, &anchors).is_empty());
    }

    /// kind3 负向：撤销面无锚读数 → ⑥ 静默缺席（检出率损失，不是假证），出证面零候选。
    #[test]
    fn kind3_without_anchor_yields_nothing() {
        let mirror = single_mirror(DH3, T0 + 1_000);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        let chain = honest_chain(&rec);
        let det = detect(&rec, &chain, &TableAnchors::default());
        assert!(det.is_clean());
        assert!(fraud_candidates(&rec, &chain, &TableAnchors::default()).is_empty());
    }

    /// kind4 正向：绑定他方运营者后余量外仍被接受 → 信号 ⑦ + kind4 候选。
    #[test]
    fn kind4_cross_shard_consumption_is_detected_and_provable() {
        let mirror = single_mirror(DH4, T0 + 1_000);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        let chain = honest_chain(&rec);
        let anchors = TableAnchors::default().bound(DH4, T0, CROSS_OP);

        let det = detect(&rec, &chain, &anchors);
        assert_eq!(det.cross_shard_consumption.len(), 1);
        let s = &det.cross_shard_consumption[0];
        assert_eq!(s.delegation_hash, DH4);
        assert_eq!(s.bound_operator, CROSS_OP);
        assert_ne!(s.bound_operator, anchors.self_operator(), "绑定须指向他方");
        assert_eq!(s.seq, 1);
        assert_eq!(s.accepted_at, T0 + 1_000);
        assert!(det.revoked_consumption.is_empty());

        let cands = fraud_candidates(&rec, &chain, &anchors);
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].kind, KIND_CROSS_SHARD);
        assert_eq!(cands[0].intents.len(), 1);
        assert_eq!(cands[0].intents[0].accepted_at, T0 + 1_000);
    }

    /// kind4 负向三态（§6.19.2 口径）：未绑定（锚 None）/ 绑回本运营者 / 余量之内 →
    /// 不罚、不出证。
    #[test]
    fn kind4_unbound_self_bound_and_within_margin_are_not_fraud() {
        let mirror = single_mirror(DH4, T0 + 1_000);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        let chain = honest_chain(&rec);

        // 未绑定（operatorOf = 零地址 → None）：fail-open 三态，不参与定罪。
        assert!(detect(&rec, &chain, &TableAnchors::default()).is_clean());
        assert!(fraud_candidates(&rec, &chain, &TableAnchors::default()).is_empty());

        // 绑回本运营者 = 本分片内正常委托，kind4 无对象。
        let self_bound = TableAnchors::default().bound(DH4, T0, [0x11; 20]);
        assert!(detect(&rec, &chain, &self_bound).is_clean());
        assert!(fraud_candidates(&rec, &chain, &self_bound).is_empty());

        // 事件发生在余量之内（acceptedAt < boundAt + margin）：§6.20.1 抽债券向量。
        let short = single_mirror(DH4, T0 + ACCEPT_MARGIN - 1);
        let rec_s = recompute(&short, [0; 32]).unwrap();
        let chain_s = honest_chain(&rec_s);
        let anchors = TableAnchors::default().bound(DH4, T0, CROSS_OP);
        assert!(detect(&rec_s, &chain_s, &anchors).is_clean());
        assert!(fraud_candidates(&rec_s, &chain_s, &anchors).is_empty());
    }

    /// 接受根闸（§6.23.1 定夺 9）：镜像接受面与链上 acceptanceRoot 不符 → kind3/4 绝不
    /// 出证（检出信号 ⑥ 照常报出），kind1/kind2 不受影响（合约不校验其接受字段）。
    #[test]
    fn acceptance_root_gate_blocks_kind3_and_kind4_only() {
        let mut mirror = make_mirror(3, 3);
        for m in mirror.iter_mut() {
            m.intent.delegation_hash = DH3;
        }
        stamp_accepted_at(&mut mirror, T0 + 1_000);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        // 链上面：净额漏一行（kind1 面）+ 接受根失配（镜像接受面缺漏）。
        let mut net = rec.net.clone();
        net.remove(0);
        let chain = ChainEpoch {
            commitment_root: rec.commitment_root,
            acceptance_root: [0xAA; 32],
            net,
        };
        let anchors = TableAnchors::default().revoked(DH3, T0);

        let det = detect(&rec, &chain, &anchors);
        assert_eq!(det.missing.len(), 1, "kind1 信号照常");
        assert_eq!(det.revoked_consumption.len(), 1, "⑥ 照常报出（诊断面）");

        let cands = fraud_candidates(&rec, &chain, &anchors);
        assert_eq!(cands.len(), 1, "kind1 不受此闸影响");
        assert_eq!(cands[0].kind, KIND_MISSING, "接受根闸只挡 kind3/4");
    }

    /// 每 dh 取最低 seq 的确定性（§6.23.1 定夺 9）：多委托同时越界 → 各产一个候选，
    /// 同 dh 多条越界只取最低 seq；候选序 = dh 字节升序（BTreeMap 键序）。
    #[test]
    fn kind3_candidates_are_deterministic_per_delegation_hash() {
        let mut mirror = single_mirror(DH3, T0 + 1_000);
        // DH3 的第二条（seq 3，更晚）——不得出现在候选里。
        let mut later = single_mirror(DH3, T0 + 3_000);
        later[0].seq = 3;
        later[0].intent.spend_nonce = 3;
        mirror.extend(later);
        // 另一 dh 的一条（seq 2）。
        let mut other = single_mirror(DH4, T0 + 2_000);
        other[0].seq = 2;
        other[0].intent.spend_nonce = 2;
        mirror.extend(other);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        let chain = honest_chain(&rec);
        let anchors = TableAnchors::default().revoked(DH3, T0).revoked(DH4, T0);

        let cands = fraud_candidates(&rec, &chain, &anchors);
        assert_eq!(cands.len(), 2, "每 dh 一个候选，同 dh 不重复");
        assert!(cands.iter().all(|c| c.kind == KIND_REVOKED));
        assert_eq!(cands[0].intents[0].seq, 1, "DH3 取最低 seq");
        assert_eq!(cands[0].intents[0].intent.delegation_hash, DH3);
        assert_eq!(cands[1].intents[0].seq, 2, "DH4 取最低 seq");
        assert_eq!(cands[1].intents[0].intent.delegation_hash, DH4);
    }

    /// kind1 证据携带接受面字段（向后兼容的证据形状）：字段齐备、与承诺路径同深度、
    /// 接受路径对镜像接受根自洽（合约对 kind1/kind2 不校验，字段只是随行）。
    #[test]
    fn kind1_evidence_carries_acceptance_fields() {
        let mut mirror = make_mirror(4, 2);
        stamp_accepted_at(&mut mirror, T0 + 7);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        let mut net = rec.net.clone();
        net.remove(0); // 漏单
        let chain = ChainEpoch {
            commitment_root: rec.commitment_root,
            acceptance_root: rec.acceptance_root,
            net,
        };

        let cands = fraud_candidates(&rec, &chain, &TableAnchors::default());
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].kind, KIND_MISSING);
        let e = &cands[0].intents[0];
        assert_eq!(e.accepted_at, T0 + 7);
        assert_eq!(e.acceptance_siblings.len(), e.siblings.len(), "两树同深度");
        assert!(merkle::verify_inclusion(
            merkle::acceptance_leaf(e.seq, e.accepted_at),
            e.leaf_index,
            e.accepted_count,
            &e.acceptance_siblings,
            rec.acceptance_root,
        ));
    }

    /// 时刻溢出（u64 域）：`event_at + margin` 真和超出 u64 → `checked_add` → 恒「不罚」
    ///——与合约 uint256 域内同式必判 NotFraud 的口径一致（§6.23.1 定夺 9 checked_add）。
    #[test]
    fn margin_overflow_is_not_fraud() {
        let mirror = single_mirror(DH3, u64::MAX);
        let rec = recompute(&mirror, [0; 32]).unwrap();
        let chain = honest_chain(&rec);
        let anchors = TableAnchors::default().revoked(DH3, u64::MAX - ACCEPT_MARGIN + 1);

        assert!(!margin_exceeded(u64::MAX - ACCEPT_MARGIN + 1, u64::MAX));
        assert!(detect(&rec, &chain, &anchors).is_clean());
        assert!(fraud_candidates(&rec, &chain, &anchors).is_empty());
        // 对照：未溢出且恰过线 → 可罚。
        assert!(margin_exceeded(0, ACCEPT_MARGIN));
    }
}
