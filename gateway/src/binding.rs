//! 运营者绑定读实现（S-62，TECH_SPEC §6.19.3）：std-only JSON-RPC `eth_call` 读
//! DSA `operatorOf(bytes32)`——聚合器摄取绑定闸（§6.19.2）的生产事实源。
//!
//! 形态与 S-59 fanout HTTP 客户端同款：TcpStream 单次 HTTP/1.1（`Connection: close`），
//! 只解析状态行与 body，不实现通用 HTTP；JSON 编解码用 serde_json（gateway 既有依赖，
//! aggregator 保持零依赖不受影响）。**读失败一律 Err 上抛** → 闸 fail-closed
//! `E_BIND_BACKEND`（§6.19.2），本层绝不把读失败翻译成「未绑定」。
//!
//! 装配口径（bin fail-fast）：`MIST_RPC_URL` + `MIST_DSA_ADDRESS` +
//! `MIST_SELF_OPERATOR` 三者同给同不给——只给其一 = 半装配 = 闸语义不明，
//! 启动即退（§6.19.3）。url 只收 `http://host:port`（std-only 无 TLS，§6.7 口径）。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use mist_aggregator::binding::{OperatorAddress, OperatorBinding};

/// 读超时（毫秒）。绑定冷读是每委托一次的成本，超时收紧到网关常规请求同级。
const DEFAULT_TIMEOUT_MS: u64 = 2000;

/// `operatorOf(bytes32)` 的 4B 选择器（keccak256 签名首 4 字节，sha3 crate 与 EVM
/// 同算法）。预期值由 `cast sig "operatorOf(bytes32)"` 独立锚定（见测试）。
fn operator_of_selector() -> [u8; 4] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(b"operatorOf(bytes32)");
    let d: [u8; 32] = h.finalize().into();
    [d[0], d[1], d[2], d[3]]
}

/// JSON-RPC 绑定读客户端。
pub struct JsonRpcBinding {
    host: String,
    port: u16,
    /// DSA 合约地址（`eth_call.to`）。
    contract: OperatorAddress,
    timeout: Duration,
}

impl JsonRpcBinding {
    /// `url` 只收 `http://host:port`（std-only 无 TLS；https 一律拒——明文误配比
    /// 静默不可达好，S-56 部署口径）。
    pub fn new(url: &str, contract: OperatorAddress) -> Result<Self, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| format!("rpc url must be http://host:port (got {url:?})"))?;
        if rest.is_empty() || rest.contains('/') {
            return Err(format!("rpc url must be http://host:port (got {url:?})"));
        }
        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| format!("rpc url missing port (got {url:?})"))?;
        let port: u16 = port
            .parse()
            .map_err(|_| format!("rpc url bad port (got {url:?})"))?;
        Ok(JsonRpcBinding {
            host: host.to_string(),
            port,
            contract,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        })
    }

    /// 单次 `eth_call`：返回 ABI 解码前的原始返回字节。
    fn eth_call(&self, to: &OperatorAddress, data: &[u8]) -> Result<Vec<u8>, String> {
        let params = serde_json::json!([
            { "to": format!("0x{}", hex::encode(to)), "data": format!("0x{}", hex::encode(data)) },
            "latest"
        ]);
        let result = rpc_post(&self.host, self.port, self.timeout, "eth_call", params)?;
        let raw = result
            .as_str()
            .and_then(|s| s.strip_prefix("0x"))
            .ok_or_else(|| "rpc eth_call: result missing 0x string".to_string())?;
        hex::decode(raw).map_err(|e| format!("rpc eth_call: bad result hex: {e}"))
    }
}

/// 单次 JSON-RPC POST 往返骨架（§6.19.3 `eth_call` 与 §6.24 `eth_getLogs` 共用，
/// S-67 抽取——TCP 连接/超时/请求行/响应切分/错误上抛行为逐字节不变）。返回
/// `result` 字段原值；json-rpc `error` / 缺 result / 非 JSON 响应一律 Err（fail-closed
/// 上抛，本层绝不把读失败翻译成业务默认值）。
pub(crate) fn rpc_post(
    host: &str,
    port: u16,
    timeout: Duration,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let addr = format!("{}:{}", host, port);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();

    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
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

impl OperatorBinding for JsonRpcBinding {
    /// `DSA.operatorOf(bytes32)` 读数：返回 32B ABI word，低 20B = 地址。短返回 /
    /// 非 32B 编码一律 Err（fail-closed 上抛成 `E_BIND_BACKEND`）；零地址按读协议
    /// 归一为「未绑定」（`Ok(None)`）。
    fn operator_of(&self, dh: &[u8; 32]) -> Result<Option<OperatorAddress>, String> {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&operator_of_selector());
        data.extend_from_slice(dh);
        let out = self.eth_call(&self.contract, &data)?;
        if out.len() != 32 {
            return Err(format!(
                "operatorOf: expected 32B ABI word, got {}B",
                out.len()
            ));
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&out[12..]);
        if addr == [0u8; 20] {
            Ok(None)
        } else {
            Ok(Some(addr))
        }
    }
}

/// `0x` + 40 hex → 20B 地址（装配面解析，fail-fast 文案）。
pub fn parse_addr20(s: &str) -> Result<OperatorAddress, String> {
    let raw = s
        .strip_prefix("0x")
        .ok_or_else(|| format!("address must be 0x + 40 hex (got {s:?})"))?;
    let bytes = hex::decode(raw).map_err(|e| format!("address bad hex (got {s:?}): {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("address must be 20B (got {s:?})"))
}

/// 装配产物：绑定事实源 + 本运营者地址（闸装配入参的类型别名）。
pub type AssembledBinding = (Arc<dyn OperatorBinding + Send + Sync>, OperatorAddress);

/// 装配面解析（bin fail-fast 用）：三环境变量**同给同不给**，缺一即 Err（半装配 =
/// 闸语义不明，§6.19.3）。`None` = 未给任何变量 → 无闸装配（缺省口径）。
/// 入参化以便测试（bin 侧传 `std::env::var` 结果）。
pub fn parse_binding_env(
    rpc_url: Option<String>,
    dsa_address: Option<String>,
    self_operator: Option<String>,
) -> Result<Option<AssembledBinding>, String> {
    match (rpc_url, dsa_address, self_operator) {
        (None, None, None) => Ok(None),
        (Some(url), Some(dsa), Some(op)) => {
            let contract = parse_addr20(&dsa)?;
            let self_op = parse_addr20(&op)?;
            let binding = JsonRpcBinding::new(&url, contract)?;
            Ok(Some((Arc::new(binding), self_op)))
        }
        _ => Err("运营者绑定闸半装配：MIST_RPC_URL / MIST_DSA_ADDRESS / \
             MIST_SELF_OPERATOR 必须同给同不给（TECH_SPEC §6.19.3）——只给其一 \
             = 闸语义不明，启动即退。"
            .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_of_selector_matches_cast() {
        // 独立锚定：`cast sig "operatorOf(bytes32)"`（foundry keccak）= 0x63ea4ab2。
        assert_eq!(operator_of_selector(), [0x63, 0xea, 0x4a, 0xb2]);
    }

    #[test]
    fn rpc_url_accepts_only_http_host_port() {
        let c = [0x11u8; 20];
        assert!(JsonRpcBinding::new("http://127.0.0.1:8545", c).is_ok());
        // https 拒（std-only 无 TLS，§6.7 口径）。
        assert!(JsonRpcBinding::new("https://127.0.0.1:8545", c).is_err());
        assert!(JsonRpcBinding::new("http://127.0.0.1", c).is_err());
        assert!(JsonRpcBinding::new("http://127.0.0.1:8545/path", c).is_err());
        assert!(JsonRpcBinding::new("http://127.0.0.1:port", c).is_err());
        assert!(JsonRpcBinding::new("", c).is_err());
    }

    #[test]
    fn parse_addr20_shapes() {
        assert_eq!(
            parse_addr20("0x0000000000000000000000000000000000000001").unwrap(),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert!(parse_addr20("0000000000000000000000000000000000000001").is_err());
        assert!(parse_addr20("0x11").is_err());
        assert!(parse_addr20("0xZZ00000000000000000000000000000000000001").is_err());
    }

    #[test]
    fn binding_env_requires_all_or_nothing() {
        let none: Option<String> = None;
        let url = Some("http://127.0.0.1:8545".into());
        let dsa = Some(format!("0x{}", hex::encode([0x22u8; 20])));
        let op = Some(format!("0x{}", hex::encode([0xAAu8; 20])));

        // 全缺 = 无闸装配（缺省口径）。
        assert!(parse_binding_env(none.clone(), none.clone(), none.clone())
            .unwrap()
            .is_none());
        // 全给 = 装配成功，self_operator 进闸。
        let (src, self_op) = parse_binding_env(url.clone(), dsa.clone(), op.clone())
            .unwrap()
            .expect("assembled");
        assert_eq!(self_op, [0xAAu8; 20]);
        let _ = src;
        // 任一缺失 = 半装配，fail-fast。
        assert!(parse_binding_env(url.clone(), none.clone(), op.clone()).is_err());
        assert!(parse_binding_env(none.clone(), dsa.clone(), op.clone()).is_err());
        assert!(parse_binding_env(url.clone(), dsa.clone(), none.clone()).is_err());
    }
}
