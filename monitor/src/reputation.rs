//! 声誉派生（S-65，TECH_SPEC §6.22）：BatchSettler 罚没/结算事件的只读派生指标
//! （§6.17 决策 E）。
//!
//! 信源（§6.22.1 定夺 1）：`eth_getLogs` 四类事件（Commit / Settled / ChallengeSucceeded
//! / Claimed）+ `eth_getBalance` 合约余额；**不读 OperatorRegistry 名册**（§6.21.4 锚：
//! 刷名册无收益）。用途限于展示与告警——monitor 无任何合约写调用，判定面零改动。
//!
//! 两条失败语义（定夺 5/6，方向相反）：
//! - 读失败（RPC 不可得 / JSON-RPC error）→ fail-visible：`chain_read_ok 0` + 保留上次
//!   成功快照。把指标清零会被误读为「罚没归零」= 洗白方向的假信号。
//! - 解码失败（topic0 命中但字段解不出）→ fail-closed：整轮 Err。丢一条
//!   `ChallengeSucceeded` = 罚没被抹掉一行，同样是洗白方向，绝不静默跳过。

use std::collections::BTreeMap;

use crate::rpc::JsonRpc;

/// `Commit(uint256,bytes32,bytes32,bytes32,uint64,uint256)` topic0。
/// 独立锚定：`cast keccak "Commit(uint256,bytes32,bytes32,bytes32,uint64,uint256)"`（见测试）。
pub const TOPIC_COMMIT: [u8; 32] = [
    0xed, 0x84, 0x0f, 0xad, 0x31, 0x01, 0xe0, 0xe2, 0x4a, 0xe3, 0xa3, 0xb4, 0xac, 0x6e, 0x3e, 0x01,
    0xcb, 0xa6, 0x15, 0x9d, 0x58, 0x23, 0x15, 0x60, 0x8e, 0xff, 0x3c, 0xe3, 0x6f, 0xff, 0xdb, 0xe0,
];
/// `Settled(uint256,bytes32,uint64)` topic0。
pub const TOPIC_SETTLED: [u8; 32] = [
    0x63, 0x19, 0x6d, 0xde, 0x78, 0x8d, 0x13, 0x54, 0x5b, 0x91, 0x7f, 0x63, 0x6b, 0x25, 0x57, 0xfe,
    0x6d, 0x4d, 0xce, 0x74, 0xd0, 0x57, 0xfd, 0x04, 0x3e, 0xdd, 0xa6, 0x7b, 0xe6, 0x44, 0x19, 0xba,
];
/// `ChallengeSucceeded(uint256,address,uint8)` topic0。
pub const TOPIC_SLASH: [u8; 32] = [
    0x41, 0x66, 0xc4, 0xf6, 0x52, 0xec, 0x87, 0x5e, 0xdb, 0xf5, 0x12, 0x3e, 0xbe, 0x58, 0x47, 0xe5,
    0x94, 0xdf, 0x41, 0x56, 0x8c, 0x35, 0x89, 0xfd, 0x09, 0x32, 0xd7, 0xd7, 0x12, 0x98, 0x90, 0x9d,
];
/// `Claimed(uint256,address,uint256)` topic0。
pub const TOPIC_CLAIMED: [u8; 32] = [
    0x4e, 0xc9, 0x0e, 0x96, 0x55, 0x19, 0xd9, 0x26, 0x81, 0x26, 0x74, 0x67, 0xf7, 0x75, 0xad, 0xa5,
    0xbd, 0x21, 0x4a, 0xa9, 0x2c, 0x0d, 0xc9, 0x3d, 0x90, 0xa5, 0xe8, 0x80, 0xce, 0x9e, 0xd0, 0x26,
];

// topic0 常量是钉死的字面量（`cast keccak "<sig>"` 独立锚定，见测试）——生产路径
// 不做哈希重算，签名→哈希的现算只在测试锚定用。

/// 一次声誉快照（成功抓取的累计结果；测试友好：直接构造断言）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReputationSnapshot {
    /// `Commit` 事件数（已提交 epoch 数，含后被 voided 的）。
    pub epochs_committed: u64,
    /// `Settled` 事件数。
    pub epochs_settled: u64,
    /// `ChallengeSucceeded` 事件数 = 罚没次数 = voided epoch 数。
    pub slash_total: u64,
    /// 罚没按 kind 分解（kind = 合约 `uint8`）。
    pub kind_counts: BTreeMap<u8, u64>,
    /// Σ `Commit.bondedAmount`：债券承诺累计（在押上界，§6.22.1 定夺 2）。
    pub bond_committed_wei: u128,
    /// Σ `Claimed.amount`：运营者已领取额。
    pub bond_claimed_wei: u128,
    /// `eth_getBalance(settler)`：合约余额（含未领取结算资金/退款留存，不等于净债券）。
    pub contract_balance_wei: u128,
}

/// 32B 大端字 → u128（顶 16B 非零 = 超出 u128 值域 → Err，fail-closed：金额截断是
/// 静默低估，方向与洗白同侧）。
fn word_to_u128(word: &[u8]) -> Result<u128, String> {
    if word.len() != 32 {
        return Err(format!("amount word must be 32B (got {}B)", word.len()));
    }
    if word[..16].iter().any(|&b| b != 0) {
        return Err("amount exceeds u128 wei range".to_string());
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&word[16..]);
    Ok(u128::from_be_bytes(buf))
}

impl ReputationSnapshot {
    /// 累计一条事件。topic0 未知的跳过（`RefundWithdrawn` / `ChallengeRejected` 等
    /// 非声誉事件，定夺 6）；已知但字段解不出 → Err（fail-closed）。
    pub fn apply_log(&mut self, log: &crate::rpc::Log) -> Result<(), String> {
        let t0 = log
            .topics
            .first()
            .ok_or_else(|| "log without topics".to_string())?;
        if *t0 == TOPIC_COMMIT {
            // topics = [t0, epochId]；data = commitmentRoot(32) + revocationRoot(32) +
            // acceptanceRoot(32) + sealedAt(32) + bondedAmount(32)（P2-3 起五字 160B，
            // 金额字是最后一个）。
            if log.topics.len() != 2 || log.data.len() != 160 {
                return Err(format!(
                    "Commit log shape: topics={} data={}B",
                    log.topics.len(),
                    log.data.len()
                ));
            }
            self.bond_committed_wei = self
                .bond_committed_wei
                .checked_add(word_to_u128(&log.data[128..160])?)
                .ok_or_else(|| "bond_committed_wei overflow".to_string())?;
            self.epochs_committed += 1;
        } else if *t0 == TOPIC_SETTLED {
            // topics = [t0, epochId]；data = nettingRoot(32) + netCount(uint64 in 32B)
            if log.topics.len() != 2 || log.data.len() != 64 {
                return Err(format!(
                    "Settled log shape: topics={} data={}B",
                    log.topics.len(),
                    log.data.len()
                ));
            }
            self.epochs_settled += 1;
        } else if *t0 == TOPIC_SLASH {
            // topics = [t0, epochId, challenger]；data = kind(uint8 in 32B)
            if log.topics.len() != 3 || log.data.len() != 32 {
                return Err(format!(
                    "ChallengeSucceeded log shape: topics={} data={}B",
                    log.topics.len(),
                    log.data.len()
                ));
            }
            let kind = log.data[31];
            *self.kind_counts.entry(kind).or_insert(0) += 1;
            self.slash_total += 1;
        } else if *t0 == TOPIC_CLAIMED {
            // topics = [t0, epochId, recipient]；data = amount(32)
            if log.topics.len() != 3 || log.data.len() != 32 {
                return Err(format!(
                    "Claimed log shape: topics={} data={}B",
                    log.topics.len(),
                    log.data.len()
                ));
            }
            self.bond_claimed_wei = self
                .bond_claimed_wei
                .checked_add(word_to_u128(&log.data)?)
                .ok_or_else(|| "bond_claimed_wei overflow".to_string())?;
        }
        // 未知 topic0：跳过（定夺 6）。
        Ok(())
    }
}

/// 全量抓取（getLogs → 逐条累计 → getBalance）。任一步失败整轮 Err（fail-closed，
/// 定夺 6）——调用方按定夺 5 保留旧快照 + `chain_read_ok 0`。
pub fn fetch_reputation(rpc: &JsonRpc, settler: &str) -> Result<ReputationSnapshot, String> {
    let logs = rpc.eth_get_logs(
        settler,
        &[TOPIC_COMMIT, TOPIC_SETTLED, TOPIC_SLASH, TOPIC_CLAIMED],
    )?;
    let mut snap = ReputationSnapshot::default();
    for log in &logs {
        snap.apply_log(log)?;
    }
    snap.contract_balance_wei = word_to_u128(&rpc.eth_get_balance(settler)?)?;
    Ok(snap)
}

/// wei u128 → f64（Prometheus 文本格式是 f64；> 2^53 按浮点舍入，§6.22.5）。
fn wei_f64(v: u128) -> f64 {
    v as f64
}

/// 成功快照的声誉序列（gauge；计数语义由刮取器按增量处理，crate 既有口径）。
pub fn render_reputation(s: &ReputationSnapshot, settler: &str) -> String {
    let mut out = String::new();
    let mut push = |name: &str, help: &str, labels: String, value: f64| {
        out.push_str(&format!("# HELP {name} {help}\n"));
        out.push_str(&format!("# TYPE {name} gauge\n"));
        if labels.is_empty() {
            out.push_str(&format!("{name} {value}\n"));
        } else {
            out.push_str(&format!("{name}{{{labels}}} {value}\n"));
        }
    };
    let sl = format!("settler=\"{}\"", escape_label(settler));
    push(
        "mist_operator_epochs_committed_total",
        "已提交 epoch 数（Commit 事件计数，含后被 voided 的；TECH_SPEC §6.22）。",
        sl.clone(),
        s.epochs_committed as f64,
    );
    push(
        "mist_operator_epochs_settled_total",
        "已结算 epoch 数（Settled 事件计数）。",
        sl.clone(),
        s.epochs_settled as f64,
    );
    push(
        "mist_operator_slash_total",
        "罚没次数（ChallengeSucceeded 事件数 = voided epoch 数；决策 E 只读派生不进判定面）。",
        sl.clone(),
        s.slash_total as f64,
    );
    for (kind, count) in &s.kind_counts {
        push(
            "mist_operator_slash_kind_total",
            "罚没按欺诈 kind 分解（kind = BatchSettler 欺诈证明 kind，十进制）。",
            format!("{sl},kind=\"{kind}\""),
            *count as f64,
        );
    }
    push(
        "mist_operator_bond_committed_wei",
        "债券承诺累计（Σ Commit.bondedAmount，在押上界；f64 渲染 > 2^53 按浮点舍入）。",
        sl.clone(),
        wei_f64(s.bond_committed_wei),
    );
    push(
        "mist_operator_bond_claimed_wei",
        "运营者已领取额（Σ Claimed.amount）。",
        sl.clone(),
        wei_f64(s.bond_claimed_wei),
    );
    push(
        "mist_operator_contract_balance_wei",
        "BatchSettler 合约余额（eth_getBalance；含未领取结算资金/挑战者退款留存，不等于净债券）。",
        sl,
        wei_f64(s.contract_balance_wei),
    );
    out
}

/// 读面健康序列（定夺 5）：ok=false 时其他声誉序列可能是旧快照，告警以此行判定新鲜度。
pub fn render_read_ok(settler: &str, ok: bool) -> String {
    format!(
        "# HELP mist_operator_chain_read_ok 声誉面链上读健康（1=本轮抓取成功；0=失败，保留上次快照）。\n\
         # TYPE mist_operator_chain_read_ok gauge\n\
         mist_operator_chain_read_ok{{settler=\"{}\"}} {}\n",
        escape_label(settler),
        if ok { 1 } else { 0 }
    )
}

fn escape_label(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 装配面解析（bin fail-fast）：`--settler` / `--rpc` 同给同不给，缺一即 Err（半装配
/// = 声誉面语义不明，§6.19.3 同款）。`None` = 未给任何参数 → 无声誉序列（缺省口径，
/// 定夺 4）。入参化以便测试。
pub fn parse_reputation_args(
    settler: Option<String>,
    rpc_url: Option<String>,
) -> Result<Option<(JsonRpc, String)>, String> {
    match (settler, rpc_url) {
        (None, None) => Ok(None),
        (Some(s), Some(url)) => {
            validate_settler(&s)?;
            let rpc = JsonRpc::new(&url)?;
            Ok(Some((rpc, s)))
        }
        _ => Err(
            "声誉面半装配：--settler 与 --rpc 必须同给同不给（TECH_SPEC §6.22.1 定夺 4）\
             ——只给其一 = 声誉面语义不明，启动即退。"
                .into(),
        ),
    }
}

/// settler 地址形态：`0x` + 40 hex（label 原样保留用户输入，不发大小写归一——
/// 指标 label 稳定性优先，链上调用原串透传）。
fn validate_settler(s: &str) -> Result<(), String> {
    let raw = s
        .strip_prefix("0x")
        .ok_or_else(|| format!("settler must be 0x + 40 hex (got {s:?})"))?;
    if raw.len() != 40 || hex::decode(raw).is_err() {
        return Err(format!("settler must be 0x + 40 hex (got {s:?})"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::Log;
    // topic0 常量的独立锚定（`cast keccak "<sig>"`，foundry keccak 与 EVM 同算法）
    // 只在测试面用——生产路径不重算哈希，常量本体是钉死的字面量。
    use sha3::{Digest, Keccak256};

    fn word(v: u128) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        out[16..].copy_from_slice(&v.to_be_bytes());
        out
    }

    fn hash_word(b: u8) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        out[31] = b;
        out
    }

    fn t32(b: u8) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[31] = b;
        t
    }

    const SETTLER: &str = "0x0000000000000000000000000000000000000042";

    /// 签名 → topic0 现算（只用于锚定常量字面量）。
    fn topic0(sig: &str) -> [u8; 32] {
        let mut h = Keccak256::new();
        h.update(sig.as_bytes());
        h.finalize().into()
    }

    #[test]
    fn topic0_constants_match_cast_anchors() {
        // 独立锚定：`cast keccak "<sig>"`（foundry keccak，与 EVM 同算法）。
        assert_eq!(
            topic0("Commit(uint256,bytes32,bytes32,bytes32,uint64,uint256)"),
            TOPIC_COMMIT
        );
        assert_eq!(topic0("Settled(uint256,bytes32,uint64)"), TOPIC_SETTLED);
        assert_eq!(
            topic0("ChallengeSucceeded(uint256,address,uint8)"),
            TOPIC_SLASH
        );
        assert_eq!(topic0("Claimed(uint256,address,uint256)"), TOPIC_CLAIMED);
    }

    #[test]
    fn accumulates_all_four_event_kinds() {
        let mut s = ReputationSnapshot::default();
        // Commit ×2（债券 1 ETH + 0.5 ETH）。P2-3 起 data 五字：承诺根/撤销根/接受根/sealedAt/金额。
        s.apply_log(&Log {
            topics: vec![TOPIC_COMMIT, t32(0)],
            data: [
                hash_word(1),
                hash_word(2),
                hash_word(3),
                word(1_700_000_000),
                word(1_000_000_000_000_000_000),
            ]
            .concat(),
        })
        .unwrap();
        s.apply_log(&Log {
            topics: vec![TOPIC_COMMIT, t32(1)],
            data: [
                hash_word(4),
                hash_word(5),
                hash_word(6),
                word(1_700_000_060),
                word(500_000_000_000_000_000),
            ]
            .concat(),
        })
        .unwrap();
        // Settled ×1。
        s.apply_log(&Log {
            topics: vec![TOPIC_SETTLED, t32(0)],
            data: [hash_word(9), word(3)].concat(),
        })
        .unwrap();
        // 罚没 ×2：kind1 + kind2。
        s.apply_log(&Log {
            topics: vec![TOPIC_SLASH, t32(1), t32(0xAA)],
            data: word(1),
        })
        .unwrap();
        s.apply_log(&Log {
            topics: vec![TOPIC_SLASH, t32(2), t32(0xAB)],
            data: word(2),
        })
        .unwrap();
        // Claim ×1（0.25 ETH）。
        s.apply_log(&Log {
            topics: vec![TOPIC_CLAIMED, t32(0), t32(0xBB)],
            data: word(250_000_000_000_000_000),
        })
        .unwrap();
        s.contract_balance_wei = 777;

        assert_eq!(s.epochs_committed, 2);
        assert_eq!(s.epochs_settled, 1);
        assert_eq!(s.slash_total, 2);
        assert_eq!(s.kind_counts.get(&1), Some(&1));
        assert_eq!(s.kind_counts.get(&2), Some(&1));
        assert_eq!(s.bond_committed_wei, 1_500_000_000_000_000_000);
        assert_eq!(s.bond_claimed_wei, 250_000_000_000_000_000);
        assert_eq!(s.contract_balance_wei, 777);
    }

    #[test]
    fn unknown_topic0_is_skipped() {
        // RefundWithdrawn / ChallengeRejected 等非声誉事件（定夺 6）。
        let mut s = ReputationSnapshot::default();
        s.apply_log(&Log {
            topics: vec![t32(0xEE), t32(0)],
            data: word(5),
        })
        .unwrap();
        assert_eq!(s, ReputationSnapshot::default());
    }

    #[test]
    fn malformed_known_event_fails_closed() {
        let mut s = ReputationSnapshot::default();
        // topic0 命中但 data 字数不足（丢字段 = 罚没被抹掉一行的方向，绝不静默跳过）。
        let r = s.apply_log(&Log {
            topics: vec![TOPIC_SLASH, t32(1), t32(0xAA)],
            data: vec![0u8; 31],
        });
        assert!(r.is_err());
        // topic 数不对同款。
        let r = s.apply_log(&Log {
            topics: vec![TOPIC_SLASH, t32(1)],
            data: word(1),
        });
        assert!(r.is_err());
        // Commit 金额超 u128 值域 → Err（截断 = 静默低估，洗白方向）。
        //（金额是 data 末字 [128..160]；前 32B 是 commitmentRoot，写那里不触发。）
        let mut data = vec![0u8; 160];
        data[128] = 0xFF;
        let r = s.apply_log(&Log {
            topics: vec![TOPIC_COMMIT, t32(0)],
            data,
        });
        assert!(r.is_err());
        // 此前累计不受半途 Err 影响（整轮由 fetch 层 fail-closed 丢弃）。
        assert_eq!(s.slash_total, 0);
    }

    #[test]
    fn render_contains_all_series_with_settler_label() {
        let s = ReputationSnapshot {
            epochs_committed: 3,
            epochs_settled: 2,
            slash_total: 2,
            kind_counts: BTreeMap::from([(1, 1), (2, 1)]),
            bond_committed_wei: 3_000_000_000_000_000_000,
            bond_claimed_wei: 1_000_000_000_000_000_000,
            contract_balance_wei: 123,
        };
        let text = render_reputation(&s, SETTLER);

        assert!(text.contains(
            "mist_operator_epochs_committed_total{settler=\"0x0000000000000000000000000000000000000042\"} 3"
        ));
        assert!(text.contains("mist_operator_slash_total{settler=") && text.contains("} 2"));
        // kind 分解升序（BTreeMap），label 形如 ,kind="1"。
        assert!(text.contains(",kind=\"1\"} 1"));
        assert!(text.contains(",kind=\"2\"} 1"));
        // Rust f64 Display 不用科学计数法：3 ETH wei 原样十进制。
        assert!(text.contains(
            "mist_operator_bond_committed_wei{settler=\"0x0000000000000000000000000000000000000042\"} 3000000000000000000"
        ));
        assert!(text.contains("mist_operator_contract_balance_wei") && text.contains("} 123"));
        // HELP/TYPE 成对。
        assert_eq!(
            text.matches("# TYPE").count(),
            text.matches("# HELP").count()
        );
        // 全部 gauge。
        assert!(!text.contains("# TYPE mist_operator_slash_kind_total counter"));
    }

    #[test]
    fn read_ok_renders_both_states() {
        assert!(render_read_ok(SETTLER, true).contains("} 1"));
        assert!(render_read_ok(SETTLER, false).contains("} 0"));
    }

    #[test]
    fn parse_args_all_or_nothing() {
        let none: Option<String> = None;
        let s = Some(SETTLER.to_string());
        let u = Some("http://127.0.0.1:8545".to_string());
        // 全缺 = 无声誉面（缺省口径）。
        assert!(parse_reputation_args(none.clone(), none.clone())
            .unwrap()
            .is_none());
        // 全给 = 装配成功。
        let (rpc, settler) = parse_reputation_args(s.clone(), u.clone())
            .unwrap()
            .expect("assembled");
        assert_eq!(settler, SETTLER);
        let _ = rpc;
        // 半装配 fail-fast。
        assert!(parse_reputation_args(s.clone(), none.clone()).is_err());
        assert!(parse_reputation_args(none.clone(), u.clone()).is_err());
        // https 拒（std-only 无 TLS）。
        assert!(parse_reputation_args(s.clone(), Some("https://127.0.0.1:8545".into())).is_err());
        // 地址形态拒。
        assert!(parse_reputation_args(Some("0x42".into()), u.clone()).is_err());
        assert!(parse_reputation_args(Some("0000".into()), u).is_err());
    }

    /// fake JSON-RPC socket 往返：eth_getLogs + eth_getBalance 两调用 → 完整快照
    /// （解码/累计/余额路径全走真 TcpStream；§6.22.4 的链上事件形状由 verifier_drill
    /// 幕 4 用真实罚没交易保证）。
    #[test]
    fn fetch_over_real_socket() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            // 两个请求：getLogs → getBalance。每个请求按 Content-Length 精确读
            //（S-62 坑①：客户端不关写半等响应，read_to_end 会死锁）。
            for i in 0..2 {
                let (mut sock, _) = listener.accept().unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                let header_end;
                loop {
                    let n = sock.read(&mut chunk).unwrap();
                    assert!(n > 0, "client closed early");
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = find_header_end(&buf) {
                        header_end = pos;
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse().ok())?
                    })
                    .expect("content-length");
                while buf.len() < header_end + 4 + len {
                    let n = sock.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    buf.extend_from_slice(&chunk[..n]);
                }
                let body = String::from_utf8_lossy(&buf[header_end + 4..]).to_string();
                assert!(body.contains("jsonrpc"));

                let resp = if i == 0 {
                    // 两条事件：Commit(1 ETH) + ChallengeSucceeded(kind=2)，
                    // 外加一条未知 topic0（应被跳过）。
                    let logs = serde_json::json!([
                        {
                            "topics": [
                                format!("0x{}", hex::encode(TOPIC_COMMIT)),
                                format!("0x{}", hex::encode(t32(0)))
                            ],
                            "data": format!(
                                "0x{}{}{}{}{}",
                                hex::encode(hash_word(1)),
                                hex::encode(hash_word(2)),
                                hex::encode(hash_word(3)),
                                hex::encode(word(1_700_000_000)),
                                hex::encode(word(1_000_000_000_000_000_000u128))
                            )
                        },
                        {
                            "topics": [
                                format!("0x{}", hex::encode(TOPIC_SLASH)),
                                format!("0x{}", hex::encode(t32(1))),
                                format!("0x{}", hex::encode(t32(0xAA)))
                            ],
                            "data": format!("0x{}", hex::encode(word(2)))
                        },
                        {
                            "topics": [format!("0x{}", hex::encode(t32(0xEE)))],
                            "data": "0x"
                        }
                    ]);
                    serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": logs }).to_string()
                } else {
                    serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": "0x1bc16d674ec80000" })
                        .to_string()
                };
                let http = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp.len(),
                    resp
                );
                sock.write_all(http.as_bytes()).unwrap();
            }
        });

        fn find_header_end(buf: &[u8]) -> Option<usize> {
            buf.windows(4).position(|w| w == b"\r\n\r\n")
        }

        let rpc = JsonRpc::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let snap = fetch_reputation(&rpc, SETTLER).unwrap();
        assert_eq!(snap.epochs_committed, 1);
        assert_eq!(snap.slash_total, 1);
        assert_eq!(snap.kind_counts.get(&2), Some(&1));
        assert_eq!(snap.bond_committed_wei, 1_000_000_000_000_000_000);
        // 0x1bc16d674ec80000 = 2 ETH（短字右对齐路径）。
        assert_eq!(snap.contract_balance_wei, 2_000_000_000_000_000_000);
        server.join().unwrap();
    }

    /// 读失败 fail-visible 的原料：RPC error / 连接不可得 → fetch 返回 Err（渲染层
    /// 保留旧快照 + read_ok 0，由 main 的 ReputationReporter 组合，见集成测试）。
    #[test]
    fn fetch_fails_closed_on_rpc_error() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = sock.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") && body_complete(&buf) {
                    break;
                }
                if n == 0 {
                    break;
                }
            }
            let resp = serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "error": { "code": -32000, "message": "mock: node is down" }
            })
            .to_string();
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                resp.len(),
                resp
            );
            sock.write_all(http.as_bytes()).unwrap();
        });

        fn body_complete(buf: &[u8]) -> bool {
            let head_end = match buf.windows(4).position(|w| w == b"\r\n\r\n") {
                Some(p) => p,
                None => return false,
            };
            let head = String::from_utf8_lossy(&buf[..head_end]);
            let len: usize = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse().ok())?
                })
                .unwrap_or(0);
            buf.len() >= head_end + 4 + len
        }

        let rpc = JsonRpc::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let err = fetch_reputation(&rpc, SETTLER).unwrap_err();
        assert!(err.contains("json-rpc error"), "got: {err}");
        server.join().unwrap();

        // 连接不可得：端口上无监听 → Err（不吞成空快照）。
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        assert!(fetch_reputation(
            &JsonRpc::new(&format!("http://127.0.0.1:{dead_port}")).unwrap(),
            SETTLER
        )
        .is_err());
    }
}
