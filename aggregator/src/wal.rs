//! 自写追加式 WAL（MASTER_PLAN S-10：`sled` 或自写，不引重型 DB → 自写）。
//!
//! 记录格式（固定头 + payload）：
//! ```text
//! [magic u16 LE = 0x4D4D][version u8 = 1][kind u8][len u32 LE][crc32 u32 LE][payload len 字节]
//! ```
//! 12 字节头 + payload。重放：顺序读、逐条校验和，尾部撕裂（校验和错 / 记录残缺）即停并
//! 截断到最后一个合法字节（S-10c 的 torn-write 语义）。
//!
//! **持久化模型（诚实口径）**：`append_*` 写入内存缓冲，满 `sync_every` 条、缓冲将满、
//! 或显式 `flush` 才 `sync_data`（批量 fsync）。崩溃恢复保证的是**最后一个 fsync 前缀**的
//! 账本一致——未 sync 的尾巴在崩溃中丢失属标准 WAL 语义（agent 幂等重试：nonce 不在重放集
//! → 重接受，无双重记账）。
//!
//! 热路径（`append_intent`）零分配：payload 固定 116B（seq8+intent_hash32+dh32+nonce8+
//! amount8+now8+recipient20），写在栈上；缓冲**固定预置 8MB**，`append_raw` 在 extend 前检查
//! 剩余容量，不够先 flush——缓冲永不 realloc，内存上界与 `sync_every` 无关（B8 口径，见
//! TECH_SPEC §8.1 容量预置注记）。含 recipient：净额指令（按 recipient 聚合）崩溃后必须可从
//! WAL 重建，intent_hash 只提交 recipient、不含明文。

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use meridian_core::dsa::SignedDelegation;

/// 记录魔法数（"MM"）。
const MAGIC: u16 = 0x4D4D;
/// 格式版本。
const VERSION: u8 = 1;
/// 头长度 = magic2 + version1 + kind1 + len4 + crc4。
const HEADER_LEN: usize = 12;
/// Intent 记录 payload 固定长度（116B）：seq8 + intent_hash32 + dh32 + nonce8 + amount8 + now8
/// + recipient20（净额恢复所需）。
const INTENT_PAYLOAD_LEN: usize = 116;
/// 单记录最大长度（含头）。Register（JSON 委托）最大规模。
const MAX_RECORD_LEN: usize = 64 * 1024;
/// 缓冲固定预置容量（8MB）：append 前检查，不够先 flush → 永不 realloc。
/// 上界固定，与 `sync_every` 解耦（避免 sync_every 大时天文内存）。
const WAL_BUFFER_CAP: usize = 8 * 1024 * 1024;

/// 记录类型。
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    Register = 1,
    Intent = 2,
    EpochSeal = 3,
    Netting = 4,
    /// 撤销委托（S-11）：崩溃后重放重建撤销集 → 下个 epoch 的撤销根精确一致。
    Revoke = 5,
    /// 撤销状态根（S-49，§4.6 残余③）：撤销根绑定闸接受集随 WAL 持久化——`revoke`
    /// 在绑定闸开启时把当刻根与撤销记录同批落盘，重放直接进接受集（零重算）。
    RevokeRoot = 6,
}

impl RecordKind {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => RecordKind::Register,
            2 => RecordKind::Intent,
            3 => RecordKind::EpochSeal,
            4 => RecordKind::Netting,
            5 => RecordKind::Revoke,
            6 => RecordKind::RevokeRoot,
            _ => return None,
        })
    }
}

/// 重放解码后的记录（恢复侧用）。
#[derive(Debug, Clone)]
pub enum DecodedRecord {
    /// 委托注册（DSA 登记事件落 WAL，重放重建注册表）。
    /// 携带 agent 的 Ed25519 公钥（验签快路径密钥；链上事件不含传输层密钥，必须落盘）。
    Register(SignedDelegation, [u8; 32]),
    /// 已接受意图（重放重建 nonce 集 + 账本 + seq + 意图索引）。
    Intent {
        seq: u64,
        intent_hash: [u8; 32],
        delegation_hash: [u8; 32],
        spend_nonce: u64,
        amount: u64,
        now: u64,
        /// 收款方（净额按 recipient 聚合，崩溃后必须可恢复）。
        recipient: [u8; 20],
    },
    /// epoch 密封（承诺根上链前的记录；重放时用于跳过已承诺 epoch）。
    EpochSeal {
        epoch_id: u64,
        commitment_root: [u8; 32],
        accepted_count: u64,
        sealed_at: u64,
    },
    /// 净额结果（settle 记录；重放时用于跳过已结算 epoch）。
    Netting {
        epoch_id: u64,
        netting_root: [u8; 32],
        net_count: u64,
    },
    /// 撤销委托（重放重建撤销集）。
    Revoke { delegation_hash: [u8; 32] },
    /// 撤销状态根（S-49，重放重建绑定闸接受集——§4.6 残余③）。值 = 撤销记录之后
    /// 当刻撤销集的稀疏根（BE Field 32B，与 §6.3 `sparse_root()` 同口径）。
    RevokeRoot { revocation_root: [u8; 32] },
}

struct WalInner {
    file: File,
    buf: Vec<u8>,
    buf_len: usize,
    records_buffered: usize,
    sync_every: usize,
}

impl WalInner {
    fn flush_locked(&mut self) -> std::io::Result<()> {
        if self.buf_len > 0 {
            self.file.write_all(&self.buf[..self.buf_len])?;
            self.file.sync_data()?;
            // 必须 clear：不清则 `buf` 仍含已刷前缀，而 `buf_len` 从 0 重新计，
            // 下一次 flush 写 `buf[..buf_len]` 会**重写旧前缀**（重复注册/意图）→ 重放
            // CRC 错截断（S-14 M1 回归）。clear 只清长度、保留 8MB 容量 → 仍零 realloc。
            self.buf.clear();
            self.buf_len = 0;
            self.records_buffered = 0;
        }
        Ok(())
    }

    fn append_raw(&mut self, kind: RecordKind, payload: &[u8]) -> std::io::Result<()> {
        debug_assert!(payload.len() <= MAX_RECORD_LEN, "record too large");
        let added = HEADER_LEN + payload.len();
        // 缓冲将满先 flush——保证 extend 永不超出预置容量 → 永不 realloc（B8）。
        if self.buf_len + added > self.buf.capacity() {
            self.flush_locked()?;
        }
        let mut header = [0u8; HEADER_LEN];
        header[0..2].copy_from_slice(&MAGIC.to_le_bytes());
        header[2] = VERSION;
        header[3] = kind as u8;
        header[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let crc = crc32fast::hash(payload);
        header[8..12].copy_from_slice(&crc.to_le_bytes());
        self.buf.extend_from_slice(&header);
        self.buf.extend_from_slice(payload);
        self.buf_len += added;
        self.records_buffered += 1;
        if self.records_buffered >= self.sync_every {
            self.flush_locked()?;
        }
        Ok(())
    }
}

/// 追加式 WAL。线程安全（内部 Mutex）；热路径零分配。
pub struct Wal {
    inner: Mutex<WalInner>,
}

impl Wal {
    /// 打开（不存在则创建）追加式 WAL。`sync_every` 条记录批量 fsync 一次。
    ///
    /// 用 `write(true)` 而非 `append(true)`：Windows 上 append 只给 `FILE_APPEND_DATA`，
    /// `set_len`（撕裂尾截断）需要 `FILE_WRITE_DATA`。写入位置由内部 Mutex 串行化维护——
    /// 所有会移动位置的操作用完都 seek 回文件尾（见各方法）。
    pub fn open(path: &Path, sync_every: usize) -> std::io::Result<Self> {
        // truncate(false)：恢复 WAL 必须保留既有记录（重放的前提），绝不可在打开时清空。
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        let buf = Vec::with_capacity(WAL_BUFFER_CAP);
        let wal = Wal {
            inner: Mutex::new(WalInner {
                file,
                buf,
                buf_len: 0,
                records_buffered: 0,
                sync_every: sync_every.max(1),
            }),
        };
        wal.inner
            .lock()
            .expect("wal poisoned")
            .file
            .seek(SeekFrom::End(0))?; // 追加位置（对既有文件）
        Ok(wal)
    }

    /// 热路径：追加一条已接受意图。payload 固定 116B、零分配。
    #[allow(clippy::too_many_arguments)]
    pub fn append_intent(
        &self,
        seq: u64,
        intent_hash: [u8; 32],
        delegation_hash: [u8; 32],
        spend_nonce: u64,
        amount: u64,
        now: u64,
        recipient: [u8; 20],
    ) -> std::io::Result<()> {
        let mut payload = [0u8; INTENT_PAYLOAD_LEN];
        payload[0..8].copy_from_slice(&seq.to_le_bytes());
        payload[8..40].copy_from_slice(&intent_hash);
        payload[40..72].copy_from_slice(&delegation_hash);
        payload[72..80].copy_from_slice(&spend_nonce.to_le_bytes());
        payload[80..88].copy_from_slice(&amount.to_le_bytes());
        payload[88..96].copy_from_slice(&now.to_le_bytes());
        payload[96..116].copy_from_slice(&recipient);
        self.inner
            .lock()
            .expect("wal poisoned")
            .append_raw(RecordKind::Intent, &payload)
    }

    /// 冷路径：委托注册（serde_json，确定性）。`agent_pub` 是 agent 的 Ed25519 公钥
    /// （验签快路径密钥）；与委托绑定为一条记录（无 agent_pub 的登记无法恢复验签能力）。
    pub fn append_register(
        &self,
        sd: &SignedDelegation,
        agent_pub: &[u8; 32],
    ) -> std::io::Result<()> {
        let payload = serde_json::to_vec(&(sd, agent_pub)).expect("SignedDelegation serializable");
        self.inner
            .lock()
            .expect("wal poisoned")
            .append_raw(RecordKind::Register, &payload)
    }

    /// 冷路径：epoch 密封记录。
    pub fn append_epoch_seal(
        &self,
        epoch_id: u64,
        commitment_root: [u8; 32],
        accepted_count: u64,
        sealed_at: u64,
    ) -> std::io::Result<()> {
        let mut payload = [0u8; 56];
        payload[0..8].copy_from_slice(&epoch_id.to_le_bytes());
        payload[8..40].copy_from_slice(&commitment_root);
        payload[40..48].copy_from_slice(&accepted_count.to_le_bytes());
        payload[48..56].copy_from_slice(&sealed_at.to_le_bytes());
        self.inner
            .lock()
            .expect("wal poisoned")
            .append_raw(RecordKind::EpochSeal, &payload)
    }

    /// 冷路径：净额结果记录。
    pub fn append_netting(
        &self,
        epoch_id: u64,
        netting_root: [u8; 32],
        net_count: u64,
    ) -> std::io::Result<()> {
        let mut payload = [0u8; 48];
        payload[0..8].copy_from_slice(&epoch_id.to_le_bytes());
        payload[8..40].copy_from_slice(&netting_root);
        payload[40..48].copy_from_slice(&net_count.to_le_bytes());
        self.inner
            .lock()
            .expect("wal poisoned")
            .append_raw(RecordKind::Netting, &payload)
    }

    /// 冷路径：撤销委托记录（payload 固定 32B = delegation_hash）。
    pub fn append_revoke(&self, delegation_hash: [u8; 32]) -> std::io::Result<()> {
        self.inner
            .lock()
            .expect("wal poisoned")
            .append_raw(RecordKind::Revoke, &delegation_hash)
    }

    /// 冷路径：撤销状态根记录（S-49，§4.6 残余③；payload 固定 32B = BE Field 根）。
    /// 仅绑定闸开启时由 `revoke` 追加——根在该处本已算过，落盘让恢复侧零重算续接接受集。
    pub fn append_revoke_root(&self, revocation_root: [u8; 32]) -> std::io::Result<()> {
        self.inner
            .lock()
            .expect("wal poisoned")
            .append_raw(RecordKind::RevokeRoot, &revocation_root)
    }

    /// 批量 fsync 到盘。
    pub fn flush(&self) -> std::io::Result<()> {
        self.inner.lock().expect("wal poisoned").flush_locked()
    }

    /// 从文件头重放全部合法记录。返回 `(记录, valid_bytes, 是否截断了撕裂尾部)`。
    ///
    /// 遇到第一个校验和错 / 记录残缺即停，`valid_bytes` = 该处字节偏移（合法前缀长度），
    /// 调用方用 `truncate_to(valid_bytes)` 截掉尾部（恢复路径做）。
    pub fn replay(&self) -> std::io::Result<(Vec<DecodedRecord>, u64, bool)> {
        let mut inner = self.inner.lock().expect("wal poisoned");
        inner.file.seek(SeekFrom::Start(0))?;
        let mut raw = Vec::new();
        inner.file.read_to_end(&mut raw)?;
        inner.file.seek(SeekFrom::End(0))?; // 恢复 append 位置
        drop(inner);

        let mut records = Vec::new();
        let mut pos = 0usize;
        let mut truncated = false;
        while pos + HEADER_LEN <= raw.len() {
            let magic = u16::from_le_bytes([raw[pos], raw[pos + 1]]);
            let version = raw[pos + 2];
            let kind = raw[pos + 3];
            let len = u32::from_le_bytes(raw[pos + 4..pos + 8].try_into().unwrap()) as usize;
            let crc = u32::from_le_bytes(raw[pos + 8..pos + 12].try_into().unwrap());
            if magic != MAGIC || version != VERSION || len > MAX_RECORD_LEN {
                truncated = true;
                break;
            }
            if pos + HEADER_LEN + len > raw.len() {
                truncated = true; // 记录残缺（撕裂尾）
                break;
            }
            let payload = &raw[pos + HEADER_LEN..pos + HEADER_LEN + len];
            if crc32fast::hash(payload) != crc {
                truncated = true;
                break;
            }
            let kind = match RecordKind::from_u8(kind) {
                Some(k) => k,
                None => {
                    truncated = true;
                    break;
                }
            };
            match kind {
                RecordKind::Register => {
                    let (sd, agent_pub): (SignedDelegation, [u8; 32]) =
                        serde_json::from_slice(payload).map_err(std::io::Error::other)?;
                    records.push(DecodedRecord::Register(sd, agent_pub));
                }
                RecordKind::Intent => {
                    if len != INTENT_PAYLOAD_LEN {
                        truncated = true;
                        break;
                    }
                    let seq = u64::from_le_bytes(payload[0..8].try_into().unwrap());
                    let intent_hash = payload[8..40].try_into().unwrap();
                    let dh = payload[40..72].try_into().unwrap();
                    let spend_nonce = u64::from_le_bytes(payload[72..80].try_into().unwrap());
                    let amount = u64::from_le_bytes(payload[80..88].try_into().unwrap());
                    let now = u64::from_le_bytes(payload[88..96].try_into().unwrap());
                    let recipient: [u8; 20] = payload[96..116].try_into().unwrap();
                    records.push(DecodedRecord::Intent {
                        seq,
                        intent_hash,
                        delegation_hash: dh,
                        spend_nonce,
                        amount,
                        now,
                        recipient,
                    });
                }
                RecordKind::EpochSeal => {
                    if len != 56 {
                        truncated = true;
                        break;
                    }
                    let epoch_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
                    let commitment_root = payload[8..40].try_into().unwrap();
                    let accepted_count = u64::from_le_bytes(payload[40..48].try_into().unwrap());
                    let sealed_at = u64::from_le_bytes(payload[48..56].try_into().unwrap());
                    records.push(DecodedRecord::EpochSeal {
                        epoch_id,
                        commitment_root,
                        accepted_count,
                        sealed_at,
                    });
                }
                RecordKind::Netting => {
                    if len != 48 {
                        truncated = true;
                        break;
                    }
                    let epoch_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
                    let netting_root = payload[8..40].try_into().unwrap();
                    let net_count = u64::from_le_bytes(payload[40..48].try_into().unwrap());
                    records.push(DecodedRecord::Netting {
                        epoch_id,
                        netting_root,
                        net_count,
                    });
                }
                RecordKind::Revoke => {
                    if len != 32 {
                        truncated = true;
                        break;
                    }
                    records.push(DecodedRecord::Revoke {
                        delegation_hash: payload.try_into().unwrap(),
                    });
                }
                RecordKind::RevokeRoot => {
                    if len != 32 {
                        truncated = true;
                        break;
                    }
                    records.push(DecodedRecord::RevokeRoot {
                        revocation_root: payload.try_into().unwrap(),
                    });
                }
            }
            pos += HEADER_LEN + len;
        }
        let valid_bytes = if truncated {
            pos as u64
        } else {
            raw.len() as u64
        };
        Ok((records, valid_bytes, truncated))
    }

    /// 截断到 `valid_bytes`（去掉撕裂尾部）。返回实际截断到的字节数。
    ///
    /// 不先 flush：缓冲中未落盘的记录比 `valid_bytes` 新，应保留在内存缓冲里，截断后随下次
    /// flush 写到新文件尾。截断后 seek 回文件尾（Windows 上 set_len 不动位置指针）。
    pub fn truncate_to(&self, valid_bytes: u64) -> std::io::Result<u64> {
        let mut inner = self.inner.lock().expect("wal poisoned");
        let cur = inner.file.metadata()?.len();
        let target = valid_bytes.min(cur);
        inner.file.set_len(target)?;
        inner.file.seek(SeekFrom::End(0))?;
        Ok(target)
    }

    pub fn file_len(&self) -> std::io::Result<u64> {
        Ok(self
            .inner
            .lock()
            .expect("wal poisoned")
            .file
            .metadata()?
            .len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use meridian_core::dsa::{
        owner_signing_key_from_bytes, sign_delegation, Delegation, RateLimit,
    };

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("meridian-wal-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn sample_sd() -> SignedDelegation {
        let d = Delegation {
            agent: [1u8; 20],
            owner: [2u8; 20],
            nonce: 7,
            max_per_spend: 100,
            rate: RateLimit {
                window_secs: 60,
                max_per_window: 1_000,
            },
            total_cap: 10_000,
            categories: vec![],
            not_before: 0,
            expires_at: u64::MAX,
            version: 1,
        };
        let key = owner_signing_key_from_bytes([7u8; 32]);
        sign_delegation(&d, &key)
    }

    #[test]
    fn append_and_replay_roundtrip() {
        let path = tmp_path("roundtrip");
        let w = Wal::open(&path, 1000).unwrap();
        w.append_register(&sample_sd(), &[0x11; 32]).unwrap();
        w.append_intent(1, [0xAB; 32], [0xCD; 32], 5, 42, 1_700_000_000, [0xEE; 20])
            .unwrap();
        w.flush().unwrap();
        let (records, valid, truncated) = w.replay().unwrap();
        assert!(!truncated);
        assert_eq!(valid, w.file_len().unwrap());
        assert_eq!(records.len(), 2);
        match &records[1] {
            DecodedRecord::Intent {
                seq,
                intent_hash,
                spend_nonce,
                amount,
                now,
                recipient,
                ..
            } => {
                assert_eq!(*seq, 1);
                assert_eq!(*intent_hash, [0xAB; 32]);
                assert_eq!(*spend_nonce, 5);
                assert_eq!(*amount, 42);
                assert_eq!(*now, 1_700_000_000);
                assert_eq!(*recipient, [0xEE; 20]);
            }
            other => panic!("expected Intent, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn buffered_records_replay_after_flush() {
        let path = tmp_path("buffered");
        let w = Wal::open(&path, 100_000).unwrap(); // 不自动 fsync
        for seq in 1..=100u64 {
            w.append_intent(seq, [0xAB; 32], [0xCD; 32], seq, 1, 0, [0xEE; 20])
                .unwrap();
        }
        // 未 flush：内存缓冲，文件未落盘。
        assert_eq!(w.file_len().unwrap(), 0);
        w.flush().unwrap();
        let (records, _, truncated) = w.replay().unwrap();
        assert!(!truncated);
        assert_eq!(records.len(), 100);
        let _ = std::fs::remove_file(&path);
    }

    /// S-14 M1 回归：跨多次 fsync 的重放不得重复前缀。
    ///
    /// 曾有的缺陷：`flush_locked` 写 `buf[..buf_len]` 后只清 `buf_len` 不清 `buf`——第二次
    /// flush 时 `buf` 里还躺着第一批记录的字节，而 `buf_len` 从 0 重新计 → `buf[..buf_len]`
    /// 是**旧前缀**被原样重写（重复 Register + 重复意图）→ 重放遇 CRC 错截断。
    /// 仅当记录数跨过 `sync_every` 触达第二次 flush 才会暴露，故此前 2~10 条的单测全绿。
    #[test]
    fn multi_flush_replay_no_duplicate_prefix() {
        let path = tmp_path("multiflush");
        let w = Wal::open(&path, 100).unwrap(); // 每 100 条自动 fsync；末 50 条显式 flush
        for seq in 1..=250u64 {
            w.append_intent(seq, [0xAB; 32], [0xCD; 32], seq, 1, 0, [0xEE; 20])
                .unwrap();
        }
        w.flush().unwrap(); // 持久化缓冲中未达阈值的尾巴（200 之后的 50 条）
        let (records, valid, truncated) = w.replay().unwrap();
        assert!(!truncated, "多次 flush 后重放不得截断");
        assert_eq!(valid, w.file_len().unwrap());
        assert_eq!(
            records.len(),
            250,
            "不得出现重复前缀（250 条必须恰好重放 250 条）"
        );
        let mut expect = 1u64;
        for r in &records {
            match r {
                DecodedRecord::Intent { seq, .. } => {
                    assert_eq!(*seq, expect, "seq 必须严格递增 1..=250");
                    expect += 1;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        // 精确字节校验：250 条 Intent × 128B，绝无旧前缀残留。
        assert_eq!(
            w.file_len().unwrap(),
            250 * (HEADER_LEN + INTENT_PAYLOAD_LEN) as u64
        );
        let _ = std::fs::remove_file(&path);
    }

    /// S-11：Revoke 记录 roundtrip（撤销集崩溃恢复的前提）。
    #[test]
    fn revoke_record_roundtrip() {
        let path = tmp_path("revoke");
        let w = Wal::open(&path, 1000).unwrap();
        w.append_revoke([0xAB; 32]).unwrap();
        w.append_revoke([0xCD; 32]).unwrap();
        w.flush().unwrap();
        let (records, valid, truncated) = w.replay().unwrap();
        assert!(!truncated);
        assert_eq!(valid, w.file_len().unwrap());
        assert_eq!(records.len(), 2);
        assert!(matches!(
            &records[0],
            DecodedRecord::Revoke { delegation_hash } if *delegation_hash == [0xAB; 32]
        ));
        assert!(matches!(
            &records[1],
            DecodedRecord::Revoke { delegation_hash } if *delegation_hash == [0xCD; 32]
        ));
        // 旧 WAL（无 Revoke 字节）兼容：kind=5 不存在的场景被 from_u8 判为撕裂 → 截断。
        let _ = std::fs::remove_file(&path);
    }

    /// S-49：RevokeRoot 记录 roundtrip（绑定闸接受集崩溃恢复的前提），且与 Revoke
    /// 同批交错时按序解码（撤销记录与根记录是两条记录，恢复侧按并集消费、不依赖配对）。
    #[test]
    fn revoke_root_record_roundtrip() {
        let path = tmp_path("revroot");
        let w = Wal::open(&path, 1000).unwrap();
        w.append_revoke([0xAB; 32]).unwrap();
        w.append_revoke_root([0x11; 32]).unwrap();
        w.append_revoke([0xCD; 32]).unwrap();
        w.append_revoke_root([0x22; 32]).unwrap();
        w.flush().unwrap();
        let (records, valid, truncated) = w.replay().unwrap();
        assert!(!truncated);
        assert_eq!(valid, w.file_len().unwrap());
        assert_eq!(records.len(), 4);
        assert!(matches!(
            &records[1],
            DecodedRecord::RevokeRoot { revocation_root } if *revocation_root == [0x11; 32]
        ));
        assert!(matches!(
            &records[3],
            DecodedRecord::RevokeRoot { revocation_root } if *revocation_root == [0x22; 32]
        ));
        // 长度错（≠32B）判撕裂：与其它固定长度种类同口径（手工构造 kind=6、len=33、
        // CRC 合法的记录——payload 长度闸必须独立于 CRC 命中）。
        let _ = std::fs::remove_file(&path);
        let path = tmp_path("revroot-badlen");
        let mut raw = Vec::new();
        raw.extend_from_slice(&MAGIC.to_le_bytes());
        raw.push(VERSION);
        raw.push(RecordKind::RevokeRoot as u8);
        raw.extend_from_slice(&33u32.to_le_bytes());
        raw.extend_from_slice(&crc32fast::hash(&[0u8; 33]).to_le_bytes());
        raw.extend_from_slice(&[0u8; 33]);
        std::fs::write(&path, &raw).unwrap();
        let w = Wal::open(&path, 1000).unwrap();
        let (_, _, truncated) = w.replay().unwrap();
        assert!(truncated, "长度失配的根记录必须截断，不得解码垃圾");
        let _ = std::fs::remove_file(&path);
    }

    /// S-11c：Revoke 记录与其它记录种类交错（注册/意图/封窗/净额）时，记录边界与 CRC 正确，
    /// 重放逐条解码一致且不截断——撤销集重放与顺序无关（幂等并集），但解码层必须跨种类稳健。
    #[test]
    fn revoke_interleaved_replay_decodes_all_kinds() {
        let path = tmp_path("revinter");
        let w = Wal::open(&path, 1000).unwrap();
        w.append_register(&sample_sd(), &[0x11; 32]).unwrap(); // 0 Register
        w.append_intent(1, [0xAB; 32], [0xCD; 32], 5, 42, 1_700_000_000, [0xEE; 20])
            .unwrap(); // 1 Intent
        w.append_revoke([0x01; 32]).unwrap(); // 2 Revoke
        w.append_intent(2, [0xBB; 32], [0xCD; 32], 6, 43, 1_700_000_001, [0xFF; 20])
            .unwrap(); // 3 Intent
        w.append_epoch_seal(0, [0x77; 32], 2, 1_700_000_002)
            .unwrap(); // 4 EpochSeal
        w.append_revoke([0x02; 32]).unwrap(); // 5 Revoke
        w.append_netting(0, [0x88; 32], 1).unwrap(); // 6 Netting
        w.append_intent(3, [0xCC; 32], [0xDD; 32], 7, 44, 1_700_000_003, [0x12; 20])
            .unwrap(); // 7 Intent
        w.flush().unwrap();
        let (records, valid, truncated) = w.replay().unwrap();
        assert!(!truncated);
        assert_eq!(valid, w.file_len().unwrap());
        assert_eq!(records.len(), 8);
        // 种类按序解码，Revoke 出现在插入位置且 dh 正确。
        assert!(matches!(&records[0], DecodedRecord::Register(_, _)));
        assert!(matches!(&records[1], DecodedRecord::Intent { seq, .. } if *seq == 1));
        assert!(matches!(
            &records[2],
            DecodedRecord::Revoke { delegation_hash } if *delegation_hash == [0x01; 32]
        ));
        assert!(matches!(&records[3], DecodedRecord::Intent { seq, .. } if *seq == 2));
        assert!(matches!(
            &records[4],
            DecodedRecord::EpochSeal { epoch_id, .. } if *epoch_id == 0
        ));
        assert!(matches!(
            &records[5],
            DecodedRecord::Revoke { delegation_hash } if *delegation_hash == [0x02; 32]
        ));
        assert!(matches!(&records[6], DecodedRecord::Netting { .. }));
        assert!(matches!(&records[7], DecodedRecord::Intent { seq, .. } if *seq == 3));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn torn_tail_is_truncated_on_replay() {
        let path = tmp_path("torn");
        let w = Wal::open(&path, 1000).unwrap();
        for seq in 1..=10u64 {
            w.append_intent(seq, [0xAB; 32], [0xCD; 32], seq, 1, 0, [0xEE; 20])
                .unwrap();
        }
        w.flush().unwrap();
        let valid = w.file_len().unwrap();

        // 手工追加一条残缺记录（头完整、payload 只写一半 → crc 不过/长度不足）。
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        let mut header = [0u8; HEADER_LEN];
        header[0..2].copy_from_slice(&MAGIC.to_le_bytes());
        header[2] = VERSION;
        header[3] = RecordKind::Intent as u8;
        header[4..8].copy_from_slice(&(INTENT_PAYLOAD_LEN as u32).to_le_bytes());
        header[8..12].copy_from_slice(&0u32.to_le_bytes()); // 错 crc
        f.write_all(&header).unwrap();
        f.write_all(&[0u8; 10]).unwrap(); // payload 残缺
        drop(f);

        let (records, valid_bytes, truncated) = w.replay().unwrap();
        assert!(truncated);
        assert_eq!(records.len(), 10, "撕裂尾前的 10 条完好");
        assert_eq!(valid_bytes, valid);
        let new_len = w.truncate_to(valid).unwrap();
        assert_eq!(new_len, valid);
        let (records2, _, truncated2) = w.replay().unwrap();
        assert!(!truncated2);
        assert_eq!(records2.len(), 10);
        let _ = std::fs::remove_file(&path);
    }
}
