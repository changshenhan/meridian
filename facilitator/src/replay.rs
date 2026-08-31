//! EIP-3009 重放闸持久化（S-33，TECH_SPEC §6.10）。
//!
//! S-32 的重放闸是进程内存态（诚实边界"持久化去重是后续项"）：重启丢失后同一 EIP-3009
//! payload 可能再次摄取，双花的是运营商垫付预算。本件把闸表落盘：append-only JSONL，
//! 摄取成功后**先内存登记、再落盘**（单行 write + `flush` + `sync_data`，崩溃最坏丢尾部
//! 半行）；启动时重放日志重建闸表（[`Eip3009Bridge::open`]，见 `eip3009.rs`）。
//!
//! 结构选择（诚实）：EIP-3009 `nonce` 每笔天然唯一 → 日志只有追加、无重复键可压实，
//! 大小随桥接笔数线性增长（每行约 150B）；参考实现不设轮转/归档，运维侧按需处理。
//! 坏行（崩溃撕裂 / 手工损坏）在重建时跳过并计数（[`JournalState::skipped`]）——启动即
//! 可观测，但不阻断重启（fail-open 于历史行，fail-closed 于本进程写路径：落盘失败上抛）。

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// 单条登记的 wire 形态（每行一个 JSON 对象，camelCase 同 §6.10 惯例）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JournalLine {
    from: String,
    nonce: String,
    intent_hash: String,
}

/// 重建出的闸表条目（二进制形态，桥侧直接入表）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalEntry {
    /// 付款方 20B 地址（重放闸键之一）。
    pub from: [u8; 20],
    /// EIP-3009 `nonce` 32B（重放闸键之二）。
    pub nonce: [u8; 32],
    /// 该 payload 首次摄取得到的意图哈希（重放直接落回执查询）。
    pub intent_hash: [u8; 32],
}

/// [`ReplayJournal::open`] 的产物：日志句柄 + 重建出的闸表条目 + 坏行统计。
#[derive(Debug)]
pub struct JournalState {
    /// 重建出的历史登记（顺序保留；键去重在桥侧闸表完成，后写覆盖先写）。
    pub entries: Vec<JournalEntry>,
    /// 跳过的坏行数（崩溃撕裂 / 损坏；不阻断重启）。
    pub skipped: usize,
    /// 追加句柄（`create + append` 打开，进程生命周期内复用；摄取成功后落盘用）。
    pub journal: ReplayJournal,
}

/// append-only 重放闸日志（线程安全：单文件句柄锁内整行写出）。
#[derive(Debug)]
pub struct ReplayJournal {
    file: Mutex<File>,
}

impl ReplayJournal {
    /// 打开（不存在则创建）并重放重建：返回条目 + 坏行统计 + 追加句柄。
    pub fn open(path: &Path) -> std::io::Result<JournalState> {
        let (entries, skipped) = match File::open(path) {
            Ok(f) => rebuild(BufReader::new(f)),
            // 首次启动：空日志。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Vec::new(), 0),
            Err(e) => return Err(e),
        };
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(JournalState {
            entries,
            skipped,
            journal: ReplayJournal {
                file: Mutex::new(file),
            },
        })
    }

    /// 追加一条登记并落盘（`flush` + `sync_data`）。
    ///
    /// 摄取成功后调用；失败上抛（调用方 503 fail-closed）——诚实边界：此刻意图可能
    /// **已摄取**而登记不可持久化（TECH_SPEC §6.10 残余边界 ①）。
    pub fn append(
        &self,
        from: &[u8; 20],
        nonce: &[u8; 32],
        intent_hash: &[u8; 32],
    ) -> std::io::Result<()> {
        let line = JournalLine {
            from: format!("0x{}", hex::encode(from)),
            nonce: format!("0x{}", hex::encode(nonce)),
            intent_hash: format!("0x{}", hex::encode(intent_hash)),
        };
        let serialized = serde_json::to_string(&line).expect("serialize journal line");
        let mut f = self.file.lock().expect("replay journal poisoned");
        f.write_all(serialized.as_bytes())?;
        f.write_all(b"\n")?;
        f.flush()?;
        f.sync_data()
    }
}

/// 逐行重放：返回 (条目, 坏行数)。坏行 = 非 JSON / 字段缺坏 / 长度错——全部跳过。
fn rebuild(reader: BufReader<File>) -> (Vec<JournalEntry>, usize) {
    let mut entries = Vec::new();
    let mut skipped = 0usize;
    for line in reader.lines() {
        let Ok(line) = line else {
            skipped += 1; // 读失败（IO 错误行）——同坏行口径
            continue;
        };
        match parse_line(&line) {
            Some(e) => entries.push(e),
            None => skipped += 1,
        }
    }
    (entries, skipped)
}

/// 单行解析（0x 前缀宽容；空行 / 半行 / 坏字段一律 `None`）。
fn parse_line(line: &str) -> Option<JournalEntry> {
    if line.trim().is_empty() {
        return None;
    }
    let l: JournalLine = serde_json::from_str(line).ok()?;
    Some(JournalEntry {
        from: parse_fixed20(&l.from)?,
        nonce: parse_fixed32(&l.nonce)?,
        intent_hash: parse_fixed32(&l.intent_hash)?,
    })
}

fn parse_fixed20(s: &str) -> Option<[u8; 20]> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(raw).ok()?.try_into().ok()
}

fn parse_fixed32(s: &str) -> Option<[u8; 32]> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(raw).ok()?.try_into().ok()
}

// ---------------------------------------------------------------------------
// 单测（TECH_SPEC §6.10 / S-33 验收）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    /// 唯一临时路径（不删旧重建同一路径；测试末尾自行清理）。
    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mist-fac-replay-{tag}-{}-{}.jsonl",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn entry(from_byte: u8, nonce_byte: u8, ih_byte: u8) -> JournalEntry {
        JournalEntry {
            from: [from_byte; 20],
            nonce: [nonce_byte; 32],
            intent_hash: [ih_byte; 32],
        }
    }

    #[test]
    fn open_missing_file_yields_empty_state() {
        let p = temp_path("missing");
        let _ = std::fs::remove_file(&p);
        let st = ReplayJournal::open(&p).expect("open");
        assert!(st.entries.is_empty());
        assert_eq!(st.skipped, 0);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn append_then_reload_roundtrips_entries() {
        let p = temp_path("roundtrip");
        let _ = std::fs::remove_file(&p);
        {
            let st = ReplayJournal::open(&p).expect("open");
            let e1 = entry(0x11, 0x22, 0x33);
            st.journal
                .append(&e1.from, &e1.nonce, &e1.intent_hash)
                .expect("append 1");
            st.journal
                .append(&[0xAA; 20], &[0xEE; 32], &[0x77; 32])
                .expect("append 2");
        }
        let st = ReplayJournal::open(&p).expect("reopen");
        assert_eq!(st.skipped, 0);
        assert_eq!(st.entries.len(), 2);
        assert_eq!(st.entries[0], entry(0x11, 0x22, 0x33));
        assert_eq!(
            st.entries[1],
            JournalEntry {
                from: [0xAA; 20],
                nonce: [0xEE; 32],
                intent_hash: [0x77; 32],
            }
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn reload_skips_torn_and_corrupt_lines_but_keeps_good_ones() {
        let p = temp_path("corrupt");
        let good = |from: u8, nonce: u8, ih: u8| {
            format!(
                r#"{{"from":"0x{}","nonce":"0x{}","intentHash":"0x{}"}}"#,
                hex::encode([from; 20]),
                hex::encode([nonce; 32]),
                hex::encode([ih; 32])
            )
        };
        // 崩溃撕裂语义的三类坏行：空行 / 半行尾随字节（"good2" + "trun" 同行）/ 坏 JSON。
        let body = format!(
            "{}\n\n{}trun\n{}\n{{bad json}}\n",
            good(1, 1, 1),
            good(2, 2, 2),
            good(3, 3, 3),
        );
        std::fs::write(&p, body).expect("seed journal");
        let st = ReplayJournal::open(&p).expect("open");
        assert_eq!(st.entries, vec![entry(1, 1, 1), entry(3, 3, 3)]);
        assert_eq!(st.skipped, 3, "空行 + 截断行 + 坏 JSON 行");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn append_accepts_0x_less_and_prefix_forms_on_reload() {
        // wire 惯例：写出恒带 0x；重建侧对无前缀形态宽容（手改文件不炸启动）。
        let p = temp_path("no-prefix");
        std::fs::write(
            &p,
            format!(
                r#"{{"from":"{}","nonce":"{}","intentHash":"{}"}}"#,
                hex::encode([9u8; 20]),
                hex::encode([8u8; 32]),
                hex::encode([7u8; 32])
            ),
        )
        .expect("seed");
        let st = ReplayJournal::open(&p).expect("open");
        assert_eq!(st.entries.len(), 1);
        assert_eq!(st.skipped, 0);
        assert_eq!(st.entries[0].from, [9u8; 20]);
        let _ = std::fs::remove_file(&p);
    }
}
