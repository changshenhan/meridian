//! RSM apply 面（L3-0，TECH_SPEC §6.26）：账本状态 = 日志条目序列的确定性函数。
//!
//! 「账本状态是 WAL 的确定性函数」（§6.25.3 共识对象 = WAL 的 RSM 分解）在此从一句被
//! 引用的主张变成一个可调用的函数：[`apply_log`] **无 I/O、无时钟读、无网络、无随机**，
//! 输出 = `f(初始状态, 条目序列)`，条目序列即 [`DecodedRecord`](crate::wal::DecodedRecord)
//! （WAL 重放解码形态，不新造条目类型）。允许内部可变性（对副本自身账本状态的 mutate）
//! ——这正是 RSM apply 的定义，不追求函数式纯粹性（§6.26.1 定夺 1）。
//!
//! 乱序投递的收敛由**批内归一化**保证（§6.26.1 定夺 3），不由投递顺序保证：撤销集 /
//! 撤销根接受集先于意图（集合操作幂等）、注册先于意图（因果前件）、**意图按 seq 升序**
//! 记账（seq 是序权威——分片锁保证同委托提交序 == seq 序，`ingest.rs` 模块文档锚）。
//! 每一 pass 内部再按条目内容全序排序，使执行序与裁决史都是条目**多重集**的全函数
//! （同一集合的任意到达排列 + 重复投递 → 同一状态 + 同一裁决史）。跨批流式乱序
//! （seq 6 先于 seq 5 到达且 5 未到就推进）需要 holdback 缓冲 + seq 稠密性处置，
//! 是日志复制的协议定夺，挂 L3-1（§6.26.1 定夺 7）。
//!
//! apply 是**记账面不是验证面**：日志条目是已裁决事实（在线已过信封验证 / 证明验证 /
//! 绑定闸，§6.2 步 0-6b），apply 不重验（S-10a 起的既有语义）。与在线路径的共享核是
//! [`ShardedState::try_commit`]（幂等性 S-12 使重复投递天然吸收）；在线 `Receipt` 与
//! [`ApplyVerdict`] 是同一裁决的两种形态。**否决**「在线路径改走 apply」——那会把窗口
//! reserve/finalize/maybe_rotate 的热路径时序与重放路径强行统一，破坏 S-10c「重放不
//! 重新密封、未密封尾直接重建窗口」的恢复语义，且对热路径零收益（§6.26.1 定夺 2）。

use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicU64;
use std::sync::{Mutex, RwLock};

use mist_core::dsa::{delegation_hash, AgentPubKey, SignedDelegation};
use mist_core::error::Error;
use sha2::{Digest, Sha256};

use crate::ingest::{
    DelegationRegistry, IngestConfig, IntentRef, RegisteredDelegation, ShardedState, WindowManager,
};
use crate::revocation::RevocationSet;
use crate::wal::DecodedRecord;
use crate::window::WindowEntry;

/// 账本可变部件的引用束（crate 内可见）：`apply_log` / `state_digest` 的输入。
/// 由 `Aggregator::ledger_parts()` 装配——private 字段不出 `ingest.rs` 即可构造，
/// apply 面不引入新的字段可见性。
pub(crate) struct LedgerParts<'a> {
    pub(crate) cfg: &'a IngestConfig,
    pub(crate) registry: &'a DelegationRegistry,
    pub(crate) state: &'a ShardedState,
    pub(crate) windows: &'a WindowManager,
    pub(crate) revocations: &'a RevocationSet,
    pub(crate) revocation_roots: &'a RwLock<HashSet<[u8; 32]>>,
    pub(crate) intents: &'a Mutex<HashMap<[u8; 32], IntentRef>>,
    pub(crate) seq: &'a AtomicU64,
}

/// 每条日志条目的裁决（§6.26.1 定夺 4：total map，每条目恰好产出一个）。
/// 顺序 = 归一化执行序（不是 WAL 记录到达序——条目集不含撤销 / 注册的日志位置，
/// 到达序不可恢复；L3-1 的日志复制条目带位置后裁决史才回到日志序）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApplyVerdict {
    /// 委托注册（重建注册表 + provision 分片条目）。`first` = 新插入
    /// （重复注册幂等覆盖，同 dh 同内容）。
    Registered { dh: [u8; 32], first: bool },
    /// 已接受意图记账成功。`seq` = 日志条目携带的序号（重放侧 `try_commit` 再分配，
    /// debug 断言两者一致——seq 稠密且按序记账时恒成立）。
    Accepted { seq: u64 },
    /// 撤销落账。`first` = 是否新插入（重复撤销幂等）。
    Revoked { dh: [u8; 32], first: bool },
    /// 撤销状态根记录（S-49）。`seeded` = 是否进接受集（仅 `enforce_revocation_root`
    /// 开启时；闸关闭 = 占位口径，记录被如实承认但状态不动）。
    RevokeRoot { root: [u8; 32], seeded: bool },
    /// epoch 密封边界（它改变密封边界——重放用它切分未密封尾，S-10c）。
    SealedBoundary { epoch_id: u64, accepted_count: u64 },
    /// 净额记录（重放面仅跳过计数用，不改变任何账本状态——如实标注为跳过）。
    NettedSkip { epoch_id: u64 },
}

/// apply 的输出：状态 + 裁决史（§6.25.4 路线 3：裁决史也是账本事实，可重放可审计）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApplyReport {
    /// 裁决史（归一化执行序）。
    pub verdicts: Vec<ApplyVerdict>,
    /// 已密封边界的累计接受数（seq ≥ 该值的意图 = 未密封尾，S-10c）。
    pub sealed_accepted_count: u64,
    /// 最后一个已密封 epoch（epoch 编号续接的基准；无密封 = -1）。
    pub last_epoch_id: i64,
    /// 重建进当前窗的未密封尾长度。
    pub tail_len: usize,
}

/// apply 失败（fail-closed：条目无法记账即终止，绝不静默丢弃）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApplyError {
    /// 意图引用未注册委托（WAL 自洽性破坏：注册记录先于意图是日志不变量）。
    UnregisteredDelegation { dh: [u8; 32] },
    /// 注册记录的 agent 公钥不是合法 Ed25519 曲线点。
    BadAgentPub,
    /// 记账失败（`try_commit` 拒绝：预算 / nonce 复用——已接受日志里的意图不该被拒）。
    Commit {
        dh: [u8; 32],
        spend_nonce: u64,
        error: Error,
    },
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::UnregisteredDelegation { dh } => write!(
                f,
                "WAL replay: intent for unregistered delegation {}",
                hex::encode(dh)
            ),
            ApplyError::BadAgentPub => {
                write!(f, "WAL replay: register record has invalid agent pubkey")
            }
            ApplyError::Commit {
                dh,
                spend_nonce,
                error,
            } => write!(
                f,
                "WAL replay: intent commit failed dh={} nonce={} {}",
                hex::encode(dh),
                spend_nonce,
                error
            ),
        }
    }
}

/// 归一化 apply：把日志条目序列记进账本状态，返回裁决史与密封边界。
///
/// 执行序（§6.26.1 定夺 3，每一 pass 内按条目内容全序排序）：
/// 1. 撤销集（dh 升序）→ 撤销根接受集（root 升序，仅闸开启时入集）；
/// 2. 注册表（dh 升序）+ 分片 provision；
/// 3. 密封边界扫描（EpochSeal 的**累计**接受数取 max = 已承诺 / 已结算意图上界）；
/// 4. 意图按 (seq, 条目内容) 全序记账 → 未密封尾重建进当前窗 + epoch 编号续接（S-10c）。
///
/// 状态语义与重构前的 `restore_from_wal` 内联重放逐字节等价（既有 S-10c / S-11 / S-49
/// 恢复测试组为回归锚）；净额记录不改变任何账本状态（重放面仅跳过计数用）。
pub(crate) fn apply_log(
    parts: &LedgerParts<'_>,
    records: &[DecodedRecord],
) -> Result<ApplyReport, ApplyError> {
    let mut report = ApplyReport {
        verdicts: Vec::with_capacity(records.len()),
        sealed_accepted_count: 0,
        last_epoch_id: -1,
        tail_len: 0,
    };

    // pass 1：撤销集（dh 升序）——集合操作幂等、与记录序无关。
    let mut revokes: Vec<[u8; 32]> = records
        .iter()
        .filter_map(|r| match r {
            DecodedRecord::Revoke { delegation_hash } => Some(*delegation_hash),
            _ => None,
        })
        .collect();
    revokes.sort_unstable();
    for dh in revokes {
        let first = parts.revocations.insert(dh);
        report.verdicts.push(ApplyVerdict::Revoked { dh, first });
    }

    // pass 1'：撤销根接受集（root 升序；S-49——根在 revoke 时本已算过并落盘，重放零重算）。
    let mut roots: Vec<[u8; 32]> = records
        .iter()
        .filter_map(|r| match r {
            DecodedRecord::RevokeRoot { revocation_root } => Some(*revocation_root),
            _ => None,
        })
        .collect();
    roots.sort_unstable();
    for root in roots {
        let mut seeded = false;
        if parts.cfg.enforce_revocation_root {
            seeded = parts
                .revocation_roots
                .write()
                .expect("revocation roots poisoned")
                .insert(root);
        }
        report
            .verdicts
            .push(ApplyVerdict::RevokeRoot { root, seeded });
    }

    // pass 2：注册先于意图（意图引用委托，因果前件）。dh 升序 + 内容全序；
    // 同 dh 重复注册 = 幂等覆盖（内容相同才合法——dh 碰撞即 sha256 碰撞）。
    let mut registers: Vec<(&SignedDelegation, &[u8; 32])> = records
        .iter()
        .filter_map(|r| match r {
            DecodedRecord::Register(sd, agent_pub) => Some((sd, agent_pub)),
            _ => None,
        })
        .collect();
    registers.sort_unstable_by(|(a, a_pub), (b, b_pub)| {
        let dh_a = delegation_hash(&a.delegation);
        let dh_b = delegation_hash(&b.delegation);
        (dh_a, a_pub.as_slice()).cmp(&(dh_b, b_pub.as_slice()))
    });
    for (sd, agent_pub_bytes) in registers {
        let agent_pub =
            AgentPubKey::from_bytes(agent_pub_bytes).map_err(|_| ApplyError::BadAgentPub)?;
        let dh = delegation_hash(&sd.delegation);
        let first = parts.registry.register(
            dh,
            RegisteredDelegation {
                delegation: sd.delegation.clone(),
                agent_pub,
            },
        );
        parts
            .state
            .provision(&dh, parts.cfg.nonce_capacity_per_delegation);
        report.verdicts.push(ApplyVerdict::Registered { dh, first });
    }

    // pass 3：密封边界扫描（max 与顺序无关）。epoch 编号接到已密封序列之后（S-10c）。
    for rec in records {
        if let DecodedRecord::EpochSeal {
            epoch_id,
            accepted_count,
            ..
        } = rec
        {
            report.last_epoch_id = report.last_epoch_id.max(*epoch_id as i64);
            report.sealed_accepted_count = report.sealed_accepted_count.max(*accepted_count);
        }
    }
    let mut seals: Vec<(u64, u64)> = records
        .iter()
        .filter_map(|r| match r {
            DecodedRecord::EpochSeal {
                epoch_id,
                accepted_count,
                ..
            } => Some((*epoch_id, *accepted_count)),
            _ => None,
        })
        .collect();
    seals.sort_unstable();
    for (epoch_id, accepted_count) in seals {
        report.verdicts.push(ApplyVerdict::SealedBoundary {
            epoch_id,
            accepted_count,
        });
    }

    // pass 3'：净额记录（重放面仅跳过计数用——如实的「跳过」裁决，total map 不留静默）。
    let mut nettings: Vec<u64> = records
        .iter()
        .filter_map(|r| match r {
            DecodedRecord::Netting { epoch_id, .. } => Some(*epoch_id),
            _ => None,
        })
        .collect();
    nettings.sort_unstable();
    for epoch_id in nettings {
        report.verdicts.push(ApplyVerdict::NettedSkip { epoch_id });
    }

    // pass 4：意图按 (seq, 条目内容) 全序记账（重建 nonce 集 + 账本 + seq + 意图索引）。
    // 内容全序使重复 seq 的重复条目也确定化（重复投递由 try_commit 幂等吸收，S-12）。
    let mut intents: Vec<IntentRecord> = records
        .iter()
        .filter_map(|r| match r {
            DecodedRecord::Intent {
                seq,
                intent_hash,
                delegation_hash,
                spend_nonce,
                amount,
                now,
                recipient,
                accepted_at,
            } => Some(IntentRecord {
                seq: *seq,
                intent_hash: *intent_hash,
                delegation_hash: *delegation_hash,
                spend_nonce: *spend_nonce,
                amount: *amount,
                now: *now,
                recipient: *recipient,
                accepted_at: *accepted_at,
            }),
            _ => None,
        })
        .collect();
    intents.sort_unstable();
    // 未密封尾（已接受但未进任何 epoch 承诺）：重建当前窗口用（S-10c，否则这些意图
    // 永远不会被净额结算）。重复投递的同一意图必须只重建一份（窗口条目以 seq 为键，
    // 重复入窗 = 窗口域双重记账 → 副本间该域发散）；排序后相邻重复 `dedup` 即确定性的
    // 多重集 → 集合（裁决史不受影响——定夺 4 的 total map 仍每条目一个裁决）。
    let mut tail: Vec<WindowEntry> = intents
        .iter()
        .filter(|t| t.seq >= report.sealed_accepted_count)
        .map(|t| WindowEntry {
            seq: t.seq,
            intent_hash: t.intent_hash,
            accepted_at: t.accepted_at,
        })
        .collect();
    tail.dedup();
    for t in &intents {
        let reg = parts.registry.lookup(&t.delegation_hash).ok_or(
            ApplyError::UnregisteredDelegation {
                dh: t.delegation_hash,
            },
        )?;
        let got = parts
            .state
            .try_commit(
                &t.delegation_hash,
                &reg.delegation,
                t.intent_hash,
                t.spend_nonce,
                t.amount,
                t.now,
                parts.seq,
            )
            .map_err(|error| ApplyError::Commit {
                dh: t.delegation_hash,
                spend_nonce: t.spend_nonce,
                error,
            })?;
        debug_assert_eq!(got, t.seq, "replay seq must match WAL seq");
        // 意图索引只收未密封意图：已提交的（seq < 边界）由 EpochSeal/Netting 覆盖，
        // 恢复后不再引用，不入索引避免驻留泄漏。
        if t.seq >= report.sealed_accepted_count {
            parts
                .intents
                .lock()
                .expect("intents poisoned")
                .insert(t.intent_hash, (t.recipient, t.amount, t.seq));
        }
        report.verdicts.push(ApplyVerdict::Accepted { seq: t.seq });
    }
    // 重建未密封窗口 + epoch 编号接到已密封序列之后（S-10c）。
    parts.windows.restore_tail(report.last_epoch_id, &tail);
    report.tail_len = tail.len();
    Ok(report)
}

/// WAL Intent 记录的排序视图（`(seq, …)` 全序：重复 seq 的重复条目也确定化）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct IntentRecord {
    seq: u64,
    intent_hash: [u8; 32],
    delegation_hash: [u8; 32],
    spend_nonce: u64,
    amount: u64,
    now: u64,
    recipient: [u8; 20],
    accepted_at: u64,
}

/// 账本状态指纹（§6.26.1 定夺 5）：sha256 over 全键排序的规范序列化。副本收敛检查的
/// 可执行形态（RSM：日志一致 ⇒ 状态一致）。**诊断面不是判定面**——无密码学承诺，
/// 不能替代 §6.5 的承诺根 / 出证闸；口径跨版本可漂移（变更须同步所有副本消费者）。
/// 不含会话面（rejected 计数 / latency / started_at / instance_id / verifier / WAL 路径
/// ——它们不是账本状态，恢复后从 0 起，§6.2 既有口径）。
pub(crate) fn state_digest(parts: &LedgerParts<'_>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"MIST-APPLY-DIGEST-V1");
    // 每域先写域标签 + 条目数（digest_into 自带计数）再写内容——定长记录流 + 计数前缀
    // 使拼接无歧义。
    h.update(b"REG");
    parts.registry.digest_into(&mut h);
    h.update(b"LEDGER");
    parts.state.digest_into(&mut h);
    h.update(b"SEQ");
    h.update(
        parts
            .seq
            .load(std::sync::atomic::Ordering::Relaxed)
            .to_le_bytes(),
    );
    h.update(b"REVOKE");
    let revoked = parts.revocations.sorted_revoked();
    h.update((revoked.len() as u64).to_le_bytes());
    for dh in revoked {
        h.update(dh);
    }
    h.update(b"REVROOT");
    let mut roots: Vec<[u8; 32]> = parts
        .revocation_roots
        .read()
        .expect("revocation roots poisoned")
        .iter()
        .copied()
        .collect();
    roots.sort_unstable();
    h.update((roots.len() as u64).to_le_bytes());
    for root in roots {
        h.update(root);
    }
    h.update(b"INTENT");
    let intents = parts.intents.lock().expect("intents poisoned");
    let mut indexed: Vec<([u8; 32], IntentRef)> = intents.iter().map(|(ih, r)| (*ih, *r)).collect();
    indexed.sort_unstable();
    h.update((indexed.len() as u64).to_le_bytes());
    for (ih, (recipient, amount, seq)) in indexed {
        h.update(ih);
        h.update(recipient);
        h.update(amount.to_le_bytes());
        h.update(seq.to_le_bytes());
    }
    h.update(b"WINDOW");
    let tail = parts.windows.unsealed_tail();
    h.update((tail.len() as u64).to_le_bytes());
    for e in tail {
        h.update(e.seq.to_le_bytes());
        h.update(e.intent_hash);
        h.update(e.accepted_at.to_le_bytes());
    }
    h.update(b"EPOCH");
    h.update(parts.windows.next_epoch_id().to_le_bytes());
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// 测试（§6.26.3）：乱序 / 重复投递收敛 property test + digest 口径锚。
// 裸副本（不经 Aggregator / WAL）直接装配 apply 面——apply 纯函数面无 I/O 的直接演示。
// 在线摄取 ↔ WAL 重放的 digest 等价测试在 `ingest.rs`（复用其信封 / 验证器替身）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mist_core::dsa::{
        intent_hash, owner_signing_key_from_bytes, sign_delegation, AgentSigningKey, Delegation,
        RateLimit, SpendIntent,
    };
    use proptest::prelude::*;

    /// 裸副本：apply 面的全部账本部件（§6.26.1 定夺 1——不引 Aggregator / WAL 即可
    /// 装配 RSM 状态机；WAL 只是在线写路径的持久化附件，不是 apply 的输入）。
    struct BareReplica {
        cfg: IngestConfig,
        registry: DelegationRegistry,
        state: ShardedState,
        windows: WindowManager,
        revocations: RevocationSet,
        revocation_roots: RwLock<HashSet<[u8; 32]>>,
        intents: Mutex<HashMap<[u8; 32], IntentRef>>,
        seq: AtomicU64,
    }

    impl BareReplica {
        fn new(shards: usize, enforce: bool) -> Self {
            let capacity = 4096; // 尾长上界远小于容量（restore_tail 断言一窗内）
            BareReplica {
                cfg: IngestConfig {
                    ledger_shards: shards,
                    enforce_revocation_root: enforce,
                    ..IngestConfig::default()
                },
                registry: DelegationRegistry::new(),
                state: ShardedState::new(shards),
                windows: WindowManager::new(capacity, 0),
                revocations: RevocationSet::new(),
                revocation_roots: RwLock::new(HashSet::new()),
                intents: Mutex::new(HashMap::new()),
                seq: AtomicU64::new(0),
            }
        }

        fn parts(&self) -> LedgerParts<'_> {
            LedgerParts {
                cfg: &self.cfg,
                registry: &self.registry,
                state: &self.state,
                windows: &self.windows,
                revocations: &self.revocations,
                revocation_roots: &self.revocation_roots,
                intents: &self.intents,
                seq: &self.seq,
            }
        }

        fn apply(&self, records: &[DecodedRecord]) -> ApplyReport {
            apply_log(&self.parts(), records).expect("generated log must apply cleanly")
        }

        fn digest(&self) -> [u8; 32] {
            state_digest(&self.parts())
        }
    }

    /// 宽松委托（金额 / 额度大、永不过期）——生成的意图全部可被 apply 记账
    /// （apply 不重验信封，但 `try_commit` 仍走预算检查）。
    fn delegation(agent: [u8; 20]) -> Delegation {
        Delegation {
            agent,
            owner: [2u8; 20],
            nonce: 7,
            max_per_spend: 1_000_000,
            rate: RateLimit {
                window_secs: 60,
                max_per_window: u64::MAX / 4,
            },
            total_cap: u64::MAX / 4,
            categories: vec![],
            not_before: 0,
            expires_at: u64::MAX,
            version: 1,
        }
    }

    /// 追加一条 Register 记录（真实 Ed25519 agent 公钥——`from_bytes` 校验曲线点），
    /// 返回其 delegation_hash。
    fn push_register(records: &mut Vec<DecodedRecord>, tag: u8) -> [u8; 32] {
        let d = delegation([tag; 20]);
        let dh = delegation_hash(&d);
        let sd = sign_delegation(&d, &owner_signing_key_from_bytes([9u8; 32]));
        let agent_pub = AgentSigningKey::from_bytes(&[tag; 32])
            .verifying_key()
            .to_bytes();
        records.push(DecodedRecord::Register(sd, agent_pub));
        dh
    }

    /// 追加一条 Intent 记录（真实 intent_hash；nonce 由调用方保证每委托唯一）。
    #[allow(clippy::too_many_arguments)]
    fn push_intent(
        records: &mut Vec<DecodedRecord>,
        dh: [u8; 32],
        agent: [u8; 20],
        nonce: u64,
        seq: u64,
        amount: u64,
        recipient: [u8; 20],
        now: u64,
    ) {
        let intent = SpendIntent {
            agent,
            delegation_hash: dh,
            recipient,
            amount,
            category: [0u8; 32],
            spend_nonce: nonce,
            memo: None,
            expires_at: now + 60,
        };
        records.push(DecodedRecord::Intent {
            seq,
            intent_hash: intent_hash(&intent),
            delegation_hash: dh,
            spend_nonce: nonce,
            amount,
            now,
            recipient,
            accepted_at: now,
        });
    }

    /// 生成一致日志集：Register 在前，Intent 按 seq 连续编号，Revoke 随 RevokeRoot
    /// （值 = 便签撤销集当刻真根，与在线 `revoke` 落盘口径一致），EpochSeal 的
    /// `accepted_count` = 当刻意图数（边界切在该处，S-10c 语义）。**撤销后不再生成
    /// 被撤委托的意图**——与在线事实一致（撤销后新意图被拒、不落 WAL；apply 不重验
    /// 撤销闸，但日志不该含它本来不会有的条目）。
    fn gen_log(ops: &[(u16, u16, u16, u8)]) -> Vec<DecodedRecord> {
        let mut records = Vec::new();
        let dh_a = push_register(&mut records, 0x01);
        let dh_b = push_register(&mut records, 0x02);
        let scratch = RevocationSet::new();
        let mut nonces = [1u64, 1];
        let mut seq = 0u64;
        for &(k, amt, recip, off) in ops {
            let now = 1_700_000_000 + u64::from(off);
            match k % 4 {
                0 => {
                    // A 的意图只在撤销前生成（撤销后新意图被拒、不落 WAL）。
                    if scratch.is_revoked(&dh_a) {
                        continue;
                    }
                    push_intent(
                        &mut records,
                        dh_a,
                        [0x01; 20],
                        nonces[0],
                        seq,
                        (u64::from(amt) % 1200) + 1,
                        [recip as u8; 20],
                        now,
                    );
                    nonces[0] += 1;
                    seq += 1;
                }
                1 => {
                    push_intent(
                        &mut records,
                        dh_b,
                        [0x02; 20],
                        nonces[1],
                        seq,
                        (u64::from(amt) % 1200) + 1,
                        [recip as u8; 20],
                        now,
                    );
                    nonces[1] += 1;
                    seq += 1;
                }
                2 => {
                    records.push(DecodedRecord::Revoke {
                        delegation_hash: dh_a,
                    });
                    scratch.insert(dh_a);
                    records.push(DecodedRecord::RevokeRoot {
                        revocation_root: scratch.sparse_root(),
                    });
                }
                _ => {
                    records.push(DecodedRecord::EpochSeal {
                        epoch_id: u64::from(k) % 7,
                        commitment_root: [k as u8; 32],
                        accepted_count: seq,
                        sealed_at: now,
                    });
                }
            }
        }
        records
    }

    /// splitmix64（跨平台位稳定，S-57 `difffuzz` 同款）——乱序 / 重复投递的确定性洗牌。
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// 乱序投递：Fisher-Yates 洗牌（种子 = 副本号）。
    fn shuffled(records: &[DecodedRecord], seed: u64) -> Vec<DecodedRecord> {
        let mut v = records.to_vec();
        let mut s = seed;
        for i in (1..v.len()).rev() {
            let j = (splitmix64(&mut s) % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
        v
    }

    /// 重复投递：每条目追加 0..2 次重复（at-least-once 传输形态；多重集对所有副本一致）。
    fn with_dups(records: &[DecodedRecord], seed: u64) -> Vec<DecodedRecord> {
        let mut out = Vec::with_capacity(records.len() * 2);
        let mut s = seed;
        for r in records {
            out.push(r.clone());
            for _ in 0..(splitmix64(&mut s) % 3) {
                out.push(r.clone());
            }
        }
        out
    }

    // **核心 property（§6.26.1 定夺 3 / 定夺 7）**：同一日志条目多重集、不同到达排列 +
    // 重复投递 → N 副本的状态根与裁决史逐字节一致（RSM apply 是条目集的函数，不是
    // 到达序的函数）。
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn permuted_and_duplicated_delivery_converges(
            ops in proptest::collection::vec(
                (any::<u16>(), any::<u16>(), any::<u16>(), any::<u8>()),
                0..40,
            ),
        ) {
            let log = gen_log(&ops);
            // 裁决史是**字面执行史**（每条目一个裁决，重复条目产生重复裁决）——裁决史
            // 比对必须在同一多重集内进行：先按规范序定重复度，再洗牌（洗牌只换到达序、
            // 不改多重集）。状态根（digest）则跨不同重复度也必须收敛（幂等吸收，S-12）。
            let mut digests: Vec<[u8; 32]> = Vec::new();
            for replica in 0..4u64 {
                let canonical = with_dups(&log, 0xD00D_0000 + replica);
                let delivered = shuffled(&canonical, 0xC0FF_EE00 + replica);
                let base = BareReplica::new(4, true);
                let base_report = base.apply(&canonical);
                // 裁决史契约：每条日志条目恰好产出一个裁决（total map，无静默跳过）。
                prop_assert_eq!(base_report.verdicts.len(), canonical.len());
                let base_digest = base.digest();

                let rep = BareReplica::new(4, true);
                let report = rep.apply(&delivered);
                prop_assert_eq!(report.verdicts.len(), delivered.len());
                prop_assert_eq!(report, base_report, "裁决史逐字节一致（副本 {}）", replica);
                prop_assert_eq!(rep.digest(), base_digest, "状态根逐字节一致（副本 {}）", replica);
                digests.push(rep.digest());
            }
            // 状态收敛跨不同重复投递度也成立（重复条目被幂等吸收）。
            for d in &digests {
                prop_assert_eq!(*d, digests[0]);
            }
        }
    }

    /// digest 对每个状态域敏感（少一个域的扰动都测不出来 = 收敛检查是假的全局比对）。
    #[test]
    fn digest_is_sensitive_to_every_state_domain() {
        // 基线：2 注册 + 2 意图（A 一笔 + B 一笔），无撤销 / 密封。
        let base_ops: Vec<(u16, u16, u16, u8)> = vec![(0, 5, 1, 0), (1, 7, 2, 1)];
        let base = BareReplica::new(4, true);
        base.apply(&gen_log(&base_ops));
        let d0 = base.digest();

        // 1) 账本域：多一笔意图（nonce 集 + budget 变）。
        let more_intent: Vec<_> = base_ops.iter().copied().chain([(1, 9, 3, 2)]).collect();
        let r = BareReplica::new(4, true);
        r.apply(&gen_log(&more_intent));
        assert_ne!(r.digest(), d0, "账本域扰动必须改变 digest");

        // 2) 撤销集 + 撤销根接受集：revoke A（同时引入两个域）。
        let revoked: Vec<_> = base_ops.iter().copied().chain([(2, 0, 0, 3)]).collect();
        let r = BareReplica::new(4, true);
        r.apply(&gen_log(&revoked));
        assert_ne!(r.digest(), d0, "撤销域扰动必须改变 digest");

        // 3) 密封边界 + epoch 编号：加一个 seal（未密封尾被清空 + next_epoch 续接）。
        let sealed: Vec<_> = base_ops.iter().copied().chain([(3, 0, 0, 4)]).collect();
        let r = BareReplica::new(4, true);
        r.apply(&gen_log(&sealed));
        assert_ne!(r.digest(), d0, "密封边界扰动必须改变 digest");

        // 4) 意图索引域：同样两笔意图、不同收款方（索引 recipient 变、预算不变）。
        let other_recip: Vec<(u16, u16, u16, u8)> = vec![(0, 5, 9, 0), (1, 7, 2, 1)];
        let r = BareReplica::new(4, true);
        r.apply(&gen_log(&other_recip));
        assert_ne!(r.digest(), d0, "意图索引域扰动必须改变 digest");

        // 5) 注册表域：多注册一个委托（注册表条目 + provision 空账本条目）。
        let with_register = {
            let mut log = gen_log(&base_ops);
            push_register(&mut log, 0x03);
            log
        };
        let r = BareReplica::new(4, true);
        r.apply(&with_register);
        assert_ne!(r.digest(), d0, "注册表域扰动必须改变 digest");
    }

    /// digest 不泄漏内部分片：同一日志、不同 `ledger_shards` → 同一 digest
    /// （规范序列化全局排序，分片是实现细节）。副本可用任意分片数互比。
    #[test]
    fn digest_is_invariant_to_shard_count() {
        let log = gen_log(&[(0, 5, 1, 0), (1, 7, 2, 1), (2, 0, 0, 2), (1, 3, 4, 3)]);
        let mut expected = None;
        for shards in [1usize, 4, 64] {
            let rep = BareReplica::new(shards, true);
            rep.apply(&log);
            let d = rep.digest();
            if let Some(e) = expected {
                assert_eq!(d, e, "shards={shards}");
            }
            expected = Some(d);
        }
    }

    /// golden 锚：同一日志 → 同一 digest（跨进程 / 跨投递序稳定的规范序列化锚）。
    /// digest 不是协议常量——**口径变更（新增状态域 / 域序调整）必然改值**，改值时须
    /// 同步所有副本消费者（§6.26.1 定夺 6）；此锚使该变更是「有意识的」而非漂移。
    #[test]
    fn golden_digest_pins_canonical_serialization() {
        let log = gen_log(&[
            (0, 5, 1, 0),
            (1, 7, 2, 1),
            (2, 0, 0, 2),
            (1, 3, 4, 3),
            (3, 0, 0, 4),
            (1, 11, 5, 5),
        ]);
        let rep = BareReplica::new(4, true);
        let report = rep.apply(&log);
        assert_eq!(
            report.tail_len, 1,
            "seal(accepted_count=3) 后尾 = seq 3 一笔"
        );
        assert_eq!(report.last_epoch_id, 3);
        assert_eq!(
            hex::encode(rep.digest()),
            "0c6c5849518e384504b76b98718451c255aa3bf9f0a83e9f4c727b27f9aebb7d",
            "digest 口径漂移：状态域增删 / 域序 / 序列化调整需同步所有副本消费者（§6.26.1 定夺 6）"
        );
    }
}
