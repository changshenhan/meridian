//! 撤销观察面（S-67，TECH_SPEC §6.24）：gateway 进程内置的链上撤销观察——
//! `eth_getLogs` 刮 `RevocationRegistry.Revoked` 事件 → 解析 delegation_hash →
//! 本账本 `Aggregator::revoke`。决策 F（§6.17）：每运营者独立链上监听是 P2 硬前置，
//! 观察面把「链上撤销 → 聚合器撤销」从运营者人工传播变为自动兜底。
//!
//! 形态与 §6.19.3 绑定读客户端同款（共用 `rpc_post` 往返骨架）：std-only，
//! **读失败一律 Err 上抛**（fail-visible，线程循环重试），本层绝不把读失败吞成
//! 「无事件」。驱动形态 = `poll_once` 单步接口（定夺 8）：调用方（bin 装配线程）
//! 循环驱动，单测直接驱动不 sleep。
//!
//! 定夺要点（§6.24.1，事实源在 spec）：消费前 `is_revoked` 查重（`revoke` 的 WAL
//! append 在 fresh 检查之前，重复消费不查重 = WAL 每轮膨胀）；每轮全史重扫
//! `fromBlock: "0x0"`（与 §6.22.5 声誉面同缝）；观察面不 fanout（链上是全组共同
//! 事实源）；日志解析 topic0 + 地址双重校验（RPC 端过滤是实现行为不是协议保证）。

use std::time::Duration;

use meridian_aggregator::ingest::Aggregator;

use crate::binding::rpc_post;

/// 观察轮询读超时。刮取是旁路轮询路径而非热路径，超时给到秒级：慢 RPC 只该拖慢
/// 本轮观察，不该让观察面认为链上不可达（§6.22.3 声誉面同款口径）。
const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// `Revoked(bytes32,address)` 的 topic0（keccak256 事件签名，sha3 crate 与 EVM 同
/// 算法现算）。预期值由 `cast keccak "Revoked(bytes32,address)"` 独立锚定（见测试），
/// 不手算——§6.19.3 selector 同纪律。
fn revoked_topic0() -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(b"Revoked(bytes32,address)");
    h.finalize().into()
}

/// 撤销观察面配置（config.json `revocation_watch` 节，§6.24.1 定夺 6）。缺省不配置 =
/// 不观察（缺省口径逐字节不变，序列化不出现本节）。不用 env：观察面是部署拓扑配置
///（与 `revocation_peers` 同面），也不复用绑定闸 `MERIDIAN_RPC_URL`——绑定闸
///「三同给同不给」的半装配语义与观察面无关，纠缠只会制造静默漏配。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RevocationWatchConf {
    pub rpc_url: String,
    /// `RevocationRegistry` 合约地址（`0x` + 40 hex）。
    pub registry_address: String,
    /// 轮询间隔。缺省 15000ms；显式给 0 拒（轮询间隔 0 = 打死 RPC）。
    #[serde(default = "default_watch_interval_ms")]
    pub poll_interval_ms: u64,
}

fn default_watch_interval_ms() -> u64 {
    15_000
}

/// 单轮观察统计（bin 日志与测试断言面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PollStats {
    /// 通过双重校验（topic0 + 地址）的 `Revoked` 日志条数。
    pub seen: usize,
    /// 其中新落账（`fresh == true`）的撤销条数。
    pub fresh: usize,
    /// 跳过的脏日志条数（地址不符 / topic0 不符 / topic 缺失 / 坏 hex）——fail-visible
    /// 计数，不 panic：刮取面对脏数据鲁棒，干净数据靠双重过滤保证。
    pub skipped: usize,
}

/// 撤销观察客户端（装配一次，多轮 `poll_once` 复用）。
pub struct RevocationWatch {
    host: String,
    port: u16,
    /// `RevocationRegistry` 合约地址（20B；日志 `address` 字段逐字节比对——配置侧
    /// 大小写随意，比较走字节归一）。
    registry: [u8; 20],
    interval: Duration,
    topic0: [u8; 32],
    timeout: Duration,
}

impl RevocationWatch {
    /// 装配期校验（bin fail-fast / 测试直接用）：url 只收 `http://host:port`
    ///（std-only 无 TLS，§6.7 口径）、地址 20B hex、interval > 0。
    pub fn new(url: &str, registry_address: &str, interval_ms: u64) -> Result<Self, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| format!("watch rpc url must be http://host:port (got {url:?})"))?;
        if rest.is_empty() || rest.contains('/') {
            return Err(format!(
                "watch rpc url must be http://host:port (got {url:?})"
            ));
        }
        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| format!("watch rpc url missing port (got {url:?})"))?;
        let port: u16 = port
            .parse()
            .map_err(|_| format!("watch rpc url bad port (got {url:?})"))?;
        if host.is_empty() {
            return Err(format!("watch rpc url missing host (got {url:?})"));
        }
        let raw = registry_address.strip_prefix("0x").ok_or_else(|| {
            format!("watch registry_address must be 0x + 40 hex (got {registry_address:?})")
        })?;
        let bytes = hex::decode(raw).map_err(|e| {
            format!("watch registry_address bad hex (got {registry_address:?}): {e}")
        })?;
        let registry: [u8; 20] = bytes.try_into().map_err(|_| {
            format!("watch registry_address must be 20B (got {registry_address:?})")
        })?;
        if interval_ms == 0 {
            return Err("watch poll_interval_ms must be > 0 (0 = hammer the RPC)".into());
        }
        Ok(RevocationWatch {
            host: host.to_string(),
            port,
            registry,
            interval: Duration::from_millis(interval_ms),
            topic0: revoked_topic0(),
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        })
    }

    /// 轮询间隔（bin 驱动线程 sleep 用）。
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// 单轮观察（§6.24.1 定夺 3：全史重扫；定夺 2：消费前查重）。`Err` = 本轮失败
    ///（fail-visible 上抛，驱动线程重试下一轮）；`Ok(stats)` = 本轮完成（含脏日志
    /// 跳过计数）。
    pub fn poll_once(&self, agg: &Aggregator) -> Result<PollStats, String> {
        let logs = self.get_logs()?;
        let mut stats = PollStats::default();
        for log in &logs {
            match self.parse_dh(log) {
                Some(dh) => {
                    stats.seen += 1;
                    // 查重跳过（定夺 2）：`revoke` 的 WAL append 无条件执行，重复消费
                    // 不查重 = WAL 每轮膨胀。竞态窗口（admin 并发撤销插在查重与
                    // revoke 之间）最坏 = 一条重复 WAL 记录（恢复侧重放幂等，无害）。
                    if agg.is_revoked(&dh) {
                        continue;
                    }
                    agg.revoke(dh);
                    stats.fresh += 1;
                }
                None => stats.skipped += 1,
            }
        }
        Ok(stats)
    }

    /// `eth_getLogs`：全史区间 + 地址/topic0 过滤（§6.24.1 定夺 3）。RPC 端过滤后
    /// 返回的日志仍逐条过解析防线（定夺 7）。
    fn get_logs(&self) -> Result<Vec<serde_json::Value>, String> {
        let params = serde_json::json!([{
            "address": format!("0x{}", hex::encode(self.registry)),
            "topics": [[format!("0x{}", hex::encode(self.topic0))]],
            "fromBlock": "0x0",
            "toBlock": "latest",
        }]);
        let result = rpc_post(&self.host, self.port, self.timeout, "eth_getLogs", params)?;
        result
            .as_array()
            .cloned()
            .ok_or_else(|| "rpc eth_getLogs: result is not a log array".to_string())
    }

    /// 日志解析防线（定夺 7）：topic0 + 日志地址双重校验，`None` = 脏日志（跳过并
    /// 计数，绝不 panic）。topic0 匹配已唯一确定事件 ABI（`Revoked(bytes32 indexed,
    /// address indexed)` → topic1 = delegationHash），topic 数只要求下界 2。
    fn parse_dh(&self, log: &serde_json::Value) -> Option<[u8; 32]> {
        let addr_hex = log.get("address")?.as_str()?;
        let addr = hex::decode(addr_hex.strip_prefix("0x")?).ok()?;
        if addr.as_slice() != self.registry {
            return None;
        }
        let topics = log.get("topics")?.as_array()?;
        if topics.len() < 2 {
            return None;
        }
        let t0 = hex::decode(topics[0].as_str()?.strip_prefix("0x")?).ok()?;
        if t0.as_slice() != self.topic0 {
            return None;
        }
        let dh_hex = topics[1].as_str()?.strip_prefix("0x")?;
        hex::decode(dh_hex).ok()?.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::path::PathBuf;

    use meridian_aggregator::ingest::{Aggregator, IngestConfig};
    use meridian_aggregator::proof::FormatVerifier;
    use meridian_aggregator::wal::Wal;

    /// `cast keccak "Revoked(bytes32,address)"`（foundry keccak）独立锚定——实现侧
    /// sha3 现算必须等于此字面量（§6.19.3 selector 同纪律，不手算）。
    const REVOKED_TOPIC0_CAST: [u8; 32] = [
        0x5b, 0xc2, 0xba, 0xf8, 0x70, 0xc5, 0xba, 0xf1, 0x89, 0x83, 0x8b, 0x5e, 0x0b, 0x0e, 0x3b,
        0x04, 0xa3, 0x26, 0x3e, 0x2d, 0xf5, 0xd3, 0x05, 0xd1, 0xc1, 0x5f, 0x3e, 0x60, 0x22, 0xf5,
        0xdc, 0x45,
    ];

    #[test]
    fn revoked_topic0_matches_cast_keccak() {
        assert_eq!(revoked_topic0(), REVOKED_TOPIC0_CAST);
    }

    #[test]
    fn watch_config_validates_url_addr_interval() {
        let reg = format!("0x{}", hex::encode([0x33u8; 20]));
        assert!(RevocationWatch::new("http://127.0.0.1:8545", &reg, 15_000).is_ok());
        // https 拒（std-only 无 TLS，§6.7 口径）。
        assert!(RevocationWatch::new("https://127.0.0.1:8545", &reg, 15_000).is_err());
        assert!(RevocationWatch::new("http://127.0.0.1", &reg, 15_000).is_err());
        assert!(RevocationWatch::new("http://127.0.0.1:8545/path", &reg, 15_000).is_err());
        assert!(RevocationWatch::new("", &reg, 15_000).is_err());
        // 地址形态：缺 0x / 非 40 hex / 非 20B。
        assert!(
            RevocationWatch::new("http://127.0.0.1:8545", &hex::encode([0x33u8; 20]), 15_000)
                .is_err()
        );
        assert!(RevocationWatch::new("http://127.0.0.1:8545", "0x11", 15_000).is_err());
        assert!(RevocationWatch::new(
            "http://127.0.0.1:8545",
            "0xZZ00000000000000000000000000000000000000",
            15_000
        )
        .is_err());
        // 轮询间隔 0 拒（定夺 6）。
        assert!(RevocationWatch::new("http://127.0.0.1:8545", &reg, 0).is_err());
    }

    #[test]
    fn watch_conf_serde_defaults() {
        let json = r#"{"rpc_url":"http://127.0.0.1:8545","registry_address":"0x3300000000000000000000000000000000000033"}"#;
        let conf: RevocationWatchConf = serde_json::from_str(json).unwrap();
        assert_eq!(conf.poll_interval_ms, 15_000, "缺省 15000ms（定夺 6）");
        assert_eq!(conf.rpc_url, "http://127.0.0.1:8545");
    }

    // -----------------------------------------------------------------------
    // fake JSON-RPC 服务器（真 TCP 往返；S-62 坑：客户端按 Content-Length 精确读，
    // 服务器同样读完请求 body 再写响应）。
    // -----------------------------------------------------------------------

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn spawn_fake_rpc(resp_body: String) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut s = stream;
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                let mut header_end = None;
                loop {
                    let n = match s.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = find_subslice(&buf, b"\r\n\r\n") {
                        header_end = Some(p);
                        break;
                    }
                }
                let Some(p) = header_end else { continue };
                // 按 Content-Length 精确读 body（客户端不关写半等响应）。
                let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
                let cl = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                let mut body = buf[p + 4..].to_vec();
                while body.len() < cl {
                    let n = match s.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    body.extend_from_slice(&chunk[..n]);
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        addr
    }

    /// 一条 `Revoked` 事件日志的 anvil 返回形状（address + topics[0..3]，data 空）。
    fn revoked_log(registry: &[u8; 20], dh: &[u8; 32]) -> serde_json::Value {
        serde_json::json!({
            "address": format!("0x{}", hex::encode(registry)),
            "topics": [
                format!("0x{}", hex::encode(revoked_topic0())),
                format!("0x{}", hex::encode(dh)),
                format!("0x{:040}", 0x_ab_cd), // indexed by（观察面不消费）
            ],
            "data": "0x",
            "blockNumber": "0x1",
            "blockHash": format!("0x{}", hex::encode([0u8; 32])),
            "transactionHash": format!("0x{}", hex::encode([1u8; 32])),
            "logIndex": "0x0",
        })
    }

    fn logs_result(logs: Vec<serde_json::Value>) -> String {
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": logs }).to_string()
    }

    const REGISTRY: [u8; 20] = [0x33; 20];

    fn watch_for(addr: &SocketAddr) -> RevocationWatch {
        RevocationWatch::new(
            &format!("http://{}", addr),
            &format!("0x{}", hex::encode(REGISTRY)),
            15_000,
        )
        .expect("watch")
    }

    fn aggregator(tag: &str) -> (PathBuf, Aggregator) {
        let path =
            std::env::temp_dir().join(format!("meridian-watch-{}-{tag}.wal", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let wal = Wal::open(&path, 1_000).expect("open wal");
        let agg = Aggregator::new(IngestConfig::default(), Box::new(FormatVerifier), wal);
        (path, agg)
    }

    #[test]
    fn poll_consumes_revoked_events_into_ledger() {
        let dh1 = [0x01u8; 32];
        let dh2 = [0x02u8; 32];
        let addr = spawn_fake_rpc(logs_result(vec![
            revoked_log(&REGISTRY, &dh1),
            revoked_log(&REGISTRY, &dh2),
        ]));
        let watch = watch_for(&addr);
        let (_wal_path, agg) = aggregator("consume");

        let stats = watch.poll_once(&agg).expect("poll");
        assert_eq!(stats.seen, 2);
        assert_eq!(stats.fresh, 2);
        assert_eq!(stats.skipped, 0);
        assert!(agg.is_revoked(&dh1), "链上撤销事件进本账本（决策 F）");
        assert!(agg.is_revoked(&dh2));
        assert_eq!(agg.revoked_len(), 2);
    }

    #[test]
    fn repeated_poll_dedups_and_wal_does_not_grow() {
        let dh = [0x0au8; 32];
        let addr = spawn_fake_rpc(logs_result(vec![revoked_log(&REGISTRY, &dh)]));
        let watch = watch_for(&addr);
        let (wal_path, agg) = aggregator("dedup");

        let first = watch.poll_once(&agg).expect("poll 1");
        assert_eq!(first.fresh, 1);
        let wal_len_after_first = std::fs::metadata(&wal_path).expect("wal").len();

        // 同一事件再消费（全史重扫形态）：查重跳过，不打 revoke，WAL 不膨胀（定夺 2）。
        let second = watch.poll_once(&agg).expect("poll 2");
        assert_eq!(second.seen, 1);
        assert_eq!(second.fresh, 0, "已撤销的重复事件不重复落账");
        assert_eq!(
            std::fs::metadata(&wal_path).expect("wal").len(),
            wal_len_after_first
        );
        assert_eq!(agg.revoked_len(), 1);
    }

    #[test]
    fn dirty_logs_are_skipped_per_entry() {
        let dh = [0x0bu8; 32];
        let mut bad_topic0 = revoked_log(&REGISTRY, &dh);
        bad_topic0["topics"][0] = serde_json::json!(format!("0x{}", hex::encode([0u8; 32])));
        let mut missing_topic = revoked_log(&REGISTRY, &dh);
        missing_topic["topics"] =
            serde_json::json!([format!("0x{}", hex::encode(revoked_topic0()))]);
        let mut bad_hex = revoked_log(&REGISTRY, &dh);
        bad_hex["topics"][1] = serde_json::json!("0xzz");
        // 非 JSON 的 topic1（strip 前缀后 decode 必败）。
        let mut no_0x = revoked_log(&REGISTRY, &dh);
        no_0x["topics"][1] = serde_json::json!("not-hex");

        let addr = spawn_fake_rpc(logs_result(vec![
            bad_topic0,
            missing_topic,
            bad_hex,
            no_0x,
            revoked_log(&REGISTRY, &dh), // 唯一合法
        ]));
        let watch = watch_for(&addr);
        let (_wal_path, agg) = aggregator("dirty");

        let stats = watch.poll_once(&agg).expect("poll");
        assert_eq!(stats.seen, 1);
        assert_eq!(stats.fresh, 1);
        assert_eq!(stats.skipped, 4, "脏日志逐条跳过，绝不 panic（定夺 7）");
        assert!(agg.is_revoked(&dh));
    }

    #[test]
    fn address_mismatch_never_consumes() {
        let dh = [0x0cu8; 32];
        // 其他合约的同名事件：getLogs 的 address 过滤是 RPC 实现行为不是协议保证，
        // 解析层必须逐字节比对日志地址（定夺 7）——否则 = 撤销错误的 dh。
        let other: [u8; 20] = [0x44; 20];
        let addr = spawn_fake_rpc(logs_result(vec![revoked_log(&other, &dh)]));
        let watch = watch_for(&addr);
        let (_wal_path, agg) = aggregator("addr");

        let stats = watch.poll_once(&agg).expect("poll");
        assert_eq!(stats.seen, 0);
        assert_eq!(stats.skipped, 1);
        assert!(!agg.is_revoked(&dh), "地址不符的撤销事件绝不消费");
    }

    #[test]
    fn rpc_failures_are_err_not_silent() {
        // json-rpc error（fail-visible 上抛，驱动线程重试——定夺 5）。
        let err_addr = spawn_fake_rpc(
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "error": { "code": -32000, "message": "query returned more than 10000 results" }
            })
            .to_string(),
        );
        let (_wal_path, agg) = aggregator("rpcerr");
        assert!(watch_for(&err_addr).poll_once(&agg).is_err());

        // 非 JSON 响应。
        let garbage_addr = spawn_fake_rpc("<html>gateway error</html>".into());
        assert!(watch_for(&garbage_addr).poll_once(&agg).is_err());

        // result 非数组。
        let odd_addr = spawn_fake_rpc(
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": null }).to_string(),
        );
        assert!(watch_for(&odd_addr).poll_once(&agg).is_err());

        // 连接不可得（占用后立即释放的端口）。
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let watch = RevocationWatch::new(
            &format!("http://127.0.0.1:{port}"),
            &format!("0x{}", hex::encode(REGISTRY)),
            15_000,
        )
        .expect("watch");
        assert!(watch.poll_once(&agg).is_err());
    }
}
