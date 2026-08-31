//! S-62 绑定读 socket e2e（TECH_SPEC §6.19.3）：本地 fake JSON-RPC 服务器（TcpListener，
//! 真实 HTTP/1.1 往返）× `JsonRpcBinding` × `BindingGate` 三态——绑他人拒 / 未绑定与
//! 自绑放行 / RPC 不可得 fail-closed。不需要 alloy / anvil：聚合器只依赖读面协议。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use mist_aggregator::binding::{BindingGate, OperatorBinding};
use mist_core::error::Error;
use mist_gateway::binding::JsonRpcBinding;

const SELF: [u8; 20] = [0xAA; 20];
const OTHER: [u8; 20] = [0xBB; 20];
const CONTRACT: [u8; 20] = [0x22; 20];

/// fake JSON-RPC 服务器：单线程 accept 循环，`Connection: close` 单请求一连接。
/// `mode` 决定响应形态（正常 eth_call 结果 / 短返回 / json-rpc error）。
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Normal,
    ShortResult,
    RpcError,
}

fn spawn_jsonrpc(bindings: Arc<Mutex<HashMap<[u8; 32], [u8; 20]>>>, mode: Mode) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake rpc");
    let addr = format!("http://{}", listener.local_addr().expect("addr"));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s: TcpStream = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            // 客户端不关写半（等响应）⇒ 不能 read_to_end（会双向等死）：
            // 先读到 header 尾，再按 Content-Length 精确取 body。
            let mut raw = Vec::new();
            let mut chunk = [0u8; 1024];
            let head_end = loop {
                match s.read(&mut chunk) {
                    Ok(0) => break raw.len(),
                    Ok(n) => {
                        raw.extend_from_slice(&chunk[..n]);
                        if let Some(pos) = find_subslice(&raw, b"\r\n\r\n") {
                            break pos + 4;
                        }
                    }
                    Err(_) => break raw.len(),
                }
            };
            let text = String::from_utf8_lossy(&raw);
            let (head, body_so_far) = text.split_at(head_end.min(text.len()));
            let content_len: usize = head
                .lines()
                .find_map(|l| {
                    l.strip_prefix("Content-Length:")
                        .map(|v| v.trim().parse().unwrap_or(0))
                })
                .unwrap_or(0);
            let mut body = body_so_far.to_string();
            while body.len() < content_len {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.push_str(&String::from_utf8_lossy(&chunk[..n])),
                }
            }
            let req: serde_json::Value =
                serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);

            // 从 calldata 解出 dh（selector 4B + dh 32B），查表出 ABI word。
            let data_hex = req["params"][0]["data"].as_str().unwrap_or("0x");
            let data = hex::decode(data_hex.trim_start_matches("0x")).unwrap_or_default();
            let dh: [u8; 32] = data
                .get(4..36)
                .map(|s| s.try_into().unwrap())
                .unwrap_or([0; 32]);
            let operator = bindings
                .lock()
                .expect("bindings")
                .get(&dh)
                .copied()
                .unwrap_or([0u8; 20]);
            let mut word = [0u8; 32];
            word[12..].copy_from_slice(&operator);

            let resp = match mode {
                Mode::Normal => serde_json::json!({
                    "jsonrpc": "2.0", "id": 1,
                    "result": format!("0x{}", hex::encode(word)),
                }),
                Mode::ShortResult => serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "result": "0x1234",
                }),
                Mode::RpcError => serde_json::json!({
                    "jsonrpc": "2.0", "id": 1,
                    "error": { "code": -32000, "message": "execution reverted" },
                }),
            };
            let resp_body = resp.to_string();
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                resp_body.len(),
                resp_body
            );
            let _ = s.write_all(http.as_bytes());
        }
    });
    addr
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn bind_addr(addr: &str) -> JsonRpcBinding {
    JsonRpcBinding::new(addr, CONTRACT).expect("binding")
}

fn gate_for(addr: &str) -> BindingGate {
    BindingGate::new(
        Arc::new(bind_addr(addr)) as Arc<dyn OperatorBinding + Send + Sync>,
        SELF,
    )
}

#[test]
fn jsonrpc_gate_tri_state_over_real_socket() {
    let bindings = Arc::new(Mutex::new(HashMap::new()));
    bindings.lock().expect("bindings").insert([0x01; 32], OTHER); // 绑他分片
    bindings.lock().expect("bindings").insert([0x02; 32], SELF); // 本分片
    let addr = spawn_jsonrpc(Arc::clone(&bindings), Mode::Normal);
    let gate = gate_for(&addr);

    assert_eq!(gate.check(&[0x01; 32]), Err(Error::EOperator));
    assert!(gate.check(&[0x02; 32]).is_ok(), "绑定到本运营者放行");
    assert!(
        gate.check(&[0x03; 32]).is_ok(),
        "未绑定（零地址读数）fail-open"
    );

    // 冷读缓存：同一 dh 再查不再触网——把表清空 + 关服务器也不影响已缓存判定。
    bindings.lock().expect("bindings").clear();
    assert_eq!(gate.check(&[0x01; 32]), Err(Error::EOperator));
}

#[test]
fn jsonrpc_short_result_is_fail_closed() {
    let addr = spawn_jsonrpc(Arc::new(Mutex::new(HashMap::new())), Mode::ShortResult);
    assert_eq!(
        gate_for(&addr).check(&[0x01; 32]),
        Err(Error::EBindBackend),
        "非 32B 返回 = 读面不可得，绝不按未绑定放行"
    );
}

#[test]
fn jsonrpc_error_response_is_fail_closed() {
    let addr = spawn_jsonrpc(Arc::new(Mutex::new(HashMap::new())), Mode::RpcError);
    assert_eq!(gate_for(&addr).check(&[0x01; 32]), Err(Error::EBindBackend));
}

#[test]
fn jsonrpc_unreachable_node_is_fail_closed() {
    // 占用后立即释放的端口 = 连接必败（读面不可得的传输形态）。
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    let addr = format!("http://127.0.0.1:{port}");
    assert_eq!(gate_for(&addr).check(&[0x01; 32]), Err(Error::EBindBackend));
}
