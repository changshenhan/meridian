//! std-only JSON-RPC 客户端（S-65 声誉面，TECH_SPEC §6.22.3）：`eth_getLogs` 取
//! BatchSettler 罚没/结算事件 + `eth_getBalance` 读合同余额——决策 E 声誉派生的信源面。
//!
//! 形态与 §6.19.3 网关绑定读客户端同款：TcpStream 单次 HTTP/1.1 往返
//! （`Connection: close`），只解析状态行与 body，不实现通用 HTTP；JSON 编解码用
//! serde_json（monitor 既有依赖）。**读失败一律 Err 上抛** → 声誉面按 §6.22.1 定夺 5
//! fail-visible（`chain_read_ok 0` + 保留旧快照），本层绝不把读失败吞成空结果。
//!
//! url 只收 `http://host:port`（std-only 无 TLS，§6.7 口径——https 一律拒，
//! 明文误配比静默不可达好）。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// 读/写超时。声誉面是刮取路径（默认 15s 间隔）而非热路径，超时给到秒级：慢 RPC
/// 只该拖慢本轮刮取，不该让刮取器认为 monitor 掉线。
const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// 一条链上事件 log：topics（32B 主题字数组，topic0 = 事件签名哈希）+ data（ABI
/// 非索引参数的裸 32B 字序列）。
#[derive(Debug, Clone, PartialEq)]
pub struct Log {
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// JSON-RPC 客户端（单实例可复用；每次调用一条新连接）。
pub struct JsonRpc {
    host: String,
    port: u16,
    timeout: Duration,
}

impl JsonRpc {
    /// `url` 只收 `http://host:port`（std-only 无 TLS；https / 带路径 / 缺端口一律拒，
    /// §6.19.3 同款口径）。
    pub fn new(url: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| format!("rpc url must be http://host:port (got {url:?})"))?;
        if rest.is_empty() || rest.contains('/') {
            return Err(format!("rpc url must be http://host:port (got {url:?})"));
        }
        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| format!("rpc url missing port (got {url:?})"))?;
        if host.is_empty() {
            return Err(format!("rpc url missing host (got {url:?})"));
        }
        let port: u16 = port
            .parse()
            .map_err(|_| format!("rpc url bad port (got {url:?})"))?;
        Ok(JsonRpc {
            host: host.to_string(),
            port,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        })
    }

    /// 单次 JSON-RPC 调用：返回 `result` 字段原值。json-rpc error / 缺 result /
    /// 非 JSON 响应一律 Err（fail-closed 上抛）。
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let addr = format!("{}:{}", self.host, self.port);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        })
        .to_string();

        let mut stream = TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|e| format!("set timeout {addr}: {e}"))?;
        let req = format!(
            "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(req.as_bytes())
            .and_then(|_| stream.write_all(body.as_bytes()))
            .map_err(|e| format!("write {addr}: {e}"))?;
        let mut resp = Vec::new();
        stream
            .read_to_end(&mut resp)
            .map_err(|e| format!("read {addr}: {e}"))?;

        let text = String::from_utf8_lossy(&resp);
        let (_, resp_body) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| format!("rpc {addr}: malformed response (no header/body split)"))?;
        let v: serde_json::Value =
            serde_json::from_str(resp_body).map_err(|e| format!("rpc {addr}: bad json: {e}"))?;
        if let Some(err) = v.get("error") {
            return Err(format!("rpc {addr}: json-rpc error: {err}"));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| format!("rpc {addr}: missing result"))
    }

    /// `eth_getLogs`：按合约地址 + topic0 集合取全历史事件（`fromBlock: 0x0`，
    /// §6.22.5 诚实边界：每次刮取全量重扫，本砖不做增量游标）。
    pub fn eth_get_logs(&self, address: &str, topics0: &[[u8; 32]]) -> Result<Vec<Log>, String> {
        let topics: Vec<String> = topics0
            .iter()
            .map(|t| format!("0x{}", hex::encode(t)))
            .collect();
        let params = serde_json::json!([{
            "address": address,
            "topics": [topics],
            "fromBlock": "0x0",
            "toBlock": "latest",
        }]);
        let result = self.call("eth_getLogs", params)?;
        let arr = result
            .as_array()
            .ok_or_else(|| "eth_getLogs: result is not an array".to_string())?;
        let mut logs = Vec::with_capacity(arr.len());
        for (i, entry) in arr.iter().enumerate() {
            let topics_v = entry
                .get("topics")
                .and_then(|t| t.as_array())
                .ok_or_else(|| format!("eth_getLogs: log[{i}] missing topics array"))?;
            let mut topics = Vec::with_capacity(topics_v.len());
            for t in topics_v {
                let s = t
                    .as_str()
                    .ok_or_else(|| format!("eth_getLogs: log[{i}] non-string topic"))?;
                topics.push(parse_hex_word(s).map_err(|e| format!("eth_getLogs: log[{i}] {e}"))?);
            }
            let data_s = entry
                .get("data")
                .and_then(|d| d.as_str())
                .ok_or_else(|| format!("eth_getLogs: log[{i}] missing data"))?;
            let data_raw = data_s
                .strip_prefix("0x")
                .ok_or_else(|| format!("eth_getLogs: log[{i}] data missing 0x prefix"))?;
            let data = hex::decode(data_raw)
                .map_err(|e| format!("eth_getLogs: log[{i}] bad data hex: {e}"))?;
            logs.push(Log { topics, data });
        }
        Ok(logs)
    }

    /// `eth_getBalance(address, "latest")`：32B 大端字（声誉面用它读 BatchSettler
    /// 合约余额——§6.22.1 定夺 2：在押债券不走事件差的信源补充）。
    pub fn eth_get_balance(&self, address: &str) -> Result<[u8; 32], String> {
        let result = self.call("eth_getBalance", serde_json::json!([address, "latest"]))?;
        let s = result
            .as_str()
            .ok_or_else(|| "eth_getBalance: result is not a string".to_string())?;
        parse_hex_word(s).map_err(|e| format!("eth_getBalance: {e}"))
    }
}

/// `0x` 前缀 hex → 32B 大端字（**右对齐**，接受短字：`eth_getBalance` 返回最小宽度
/// hex；topic 的 address 字同样是右对齐值）。**奇数长度合法**——前导 nibble 为 0 时
/// 节点返回奇数位（anvil 实测 `eth_getBalance` → `0xde0b6b3a7640000`），左补一个零
/// nibble。空串 / 超 32B / 非 hex 一律 Err。
pub fn parse_hex_word(s: &str) -> Result<[u8; 32], String> {
    let raw = s
        .strip_prefix("0x")
        .ok_or_else(|| format!("hex word missing 0x prefix (got {s:?})"))?;
    if raw.is_empty() || raw.len() > 64 {
        return Err(format!("hex word bad length (got {s:?})"));
    }
    // 奇数位 = 高位 nibble 为 0（最小宽度表示），补齐成整字节再解。
    let padded = if raw.len() % 2 != 0 {
        format!("0{raw}")
    } else {
        raw.to_string()
    };
    let bytes = hex::decode(&padded).map_err(|e| format!("hex word bad hex (got {s:?}): {e}"))?;
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_url_accepts_only_http_host_port() {
        assert!(JsonRpc::new("http://127.0.0.1:8545").is_ok());
        // https 拒（std-only 无 TLS，§6.7 口径）。
        assert!(JsonRpc::new("https://127.0.0.1:8545").is_err());
        assert!(JsonRpc::new("http://127.0.0.1").is_err());
        assert!(JsonRpc::new("http://127.0.0.1:8545/").is_err());
        assert!(JsonRpc::new("http://127.0.0.1:port").is_err());
        assert!(JsonRpc::new("http://:8545").is_err());
        assert!(JsonRpc::new("").is_err());
    }

    #[test]
    fn parse_hex_word_shapes() {
        // 空字 / 最小宽度 / 全宽右对齐。
        assert!(parse_hex_word("0x").is_err());
        assert_eq!(parse_hex_word("0x00").unwrap(), {
            let mut w = [0u8; 32];
            w[31] = 0;
            w
        });
        let mut w = [0u8; 32];
        w[30] = 0x1b;
        w[31] = 0xc1;
        assert_eq!(parse_hex_word("0x1bc1").unwrap(), w);
        let full = [0xABu8; 32];
        assert_eq!(
            parse_hex_word(&format!("0x{}", hex::encode(full))).unwrap(),
            full
        );
        // 奇数长度合法（anvil eth_getBalance 实测 0xde0b6b3a7640000）：左补零 nibble。
        let mut w = [0u8; 32];
        w[31] = 0x1;
        assert_eq!(parse_hex_word("0x1").unwrap(), w);
        let mut w = [0u8; 32];
        w[30] = 0x0d;
        w[31] = 0xe0;
        assert_eq!(parse_hex_word("0xde0").unwrap(), w);
        // 超宽 / 非 hex / 缺前缀。
        assert!(parse_hex_word(&format!("0x{}", "11".repeat(33))).is_err());
        assert!(parse_hex_word("0xZZ").is_err());
        assert!(parse_hex_word("00").is_err());
    }
}
