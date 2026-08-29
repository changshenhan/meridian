//! std-only HTTP/1.1 服务层（S-29，TECH_SPEC §6.7）。
//!
//! 只做 TCP/HTTP 管道：解析请求行/头/Content-Length、body 上限、keep-alive、
//! thread-per-connection + 连接上限（`Mutex<usize>` + `Condvar` 手写信号量——std 无
//! Semaphore）。分发一律交给 [`crate::Gateway::handle`]（纯函数，单测不经 socket）。
//!
//! 诚实边界（§6.7）：明文 HTTP，TLS 由部署拓扑反代终结；仅支持 `Content-Length`
//! 请求（无 chunked——SDK 客户端不发 chunked）；`Connection: close` 显式尊重。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::Gateway;

/// 一条 HTTP 请求的解析产物（网关只关心这几样）。
struct Request {
    method: String,
    path: String,
    bearer: Option<String>,
    body: Vec<u8>,
    keep_alive: bool,
}

/// 信号量（std 无 Semaphore：Mutex<usize> + Condvar）。
#[derive(Debug)]
pub struct ConnectionGate {
    max: usize,
    active: std::sync::Mutex<usize>,
    cv: std::sync::Condvar,
}

impl ConnectionGate {
    pub fn new(max: usize) -> Self {
        ConnectionGate {
            max,
            active: std::sync::Mutex::new(0),
            cv: std::sync::Condvar::new(),
        }
    }

    fn acquire(&self) {
        let mut n = self.active.lock().expect("gate poisoned");
        while *n >= self.max {
            n = self.cv.wait(n).expect("gate poisoned");
        }
        *n += 1;
    }

    fn release(&self) {
        let mut n = self.active.lock().expect("gate poisoned");
        *n -= 1;
        self.cv.notify_one();
    }
}

/// 阻塞服务循环（每个连接一线程；调用方负责在主线程守护进程化）。
/// `max_connections` / `read_timeout` 来自 [`crate::Config`]。
pub fn serve(
    gateway: Arc<Gateway>,
    listener: TcpListener,
    max_connections: usize,
    read_timeout: Duration,
) -> std::io::Result<()> {
    let gate = Arc::new(ConnectionGate::new(max_connections));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue, // 单连接 accept 失败不拖垮服务
        };
        gate.acquire();
        let gateway = Arc::clone(&gateway);
        let gate = Arc::clone(&gate);
        std::thread::spawn(move || {
            let _ = handle_connection(gateway, stream, read_timeout);
            gate.release();
        });
    }
    Ok(())
}

fn handle_connection(
    gateway: Arc<Gateway>,
    stream: TcpStream,
    read_timeout: Duration,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(read_timeout))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    // keep-alive：循环处理直到客户端显式 close 或解析失败。
    loop {
        let req = match parse_request(&mut reader, gateway.max_body) {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(()), // 对端关闭（干净）
            Err((status, msg)) => {
                let resp = crate::Response::error(status, crate::E_MALFORMED, msg);
                write_response(&mut writer, &resp, false)?;
                return Ok(());
            }
        };

        let resp = gateway.handle(&req.method, &req.path, req.bearer.as_deref(), &req.body);
        write_response(&mut writer, &resp, req.keep_alive)?;
        if !req.keep_alive {
            return Ok(());
        }
    }
}

/// 解析一条请求。`Ok(None)` = 对端关闭；`Err((status, msg))` = 协议错误（回 4xx 后断开）。
fn parse_request(
    reader: &mut BufReader<TcpStream>,
    max_body: usize,
) -> Result<Option<Request>, (u16, String)> {
    // 请求行
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(_) => return Ok(None), // 读超时/断连按对端关闭处理
    }
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| (400, "empty request line".to_string()))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| (400, "missing path".to_string()))?
        .to_string();

    // 头部
    let mut content_length: usize = 0;
    let mut bearer: Option<String> = None;
    let mut keep_alive = true;
    loop {
        let mut h = String::new();
        match reader.read_line(&mut h) {
            Ok(0) => return Ok(None),
            Ok(_) => {}
            Err(_) => return Ok(None),
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let Some((name, value)) = h.split_once(':') else {
            return Err((400, "malformed header".to_string()));
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => {
                content_length = value
                    .parse()
                    .map_err(|_| (400, "bad content-length".to_string()))?;
            }
            "authorization" => {
                if let Some(key) = value
                    .strip_prefix("Bearer ")
                    .or_else(|| value.strip_prefix("bearer "))
                {
                    bearer = Some(key.trim().to_string());
                }
            }
            "connection" => {
                if value.eq_ignore_ascii_case("close") {
                    keep_alive = false;
                }
            }
            "transfer-encoding" => {
                return Err((400, "chunked requests not supported".to_string()));
            }
            _ => {}
        }
    }

    if content_length > max_body {
        return Err((413, "request body too large".to_string()));
    }
    let mut body = vec![0u8; content_length];
    reader
        .read_exact(&mut body)
        .map_err(|_| (400, "truncated body".to_string()))?;

    Ok(Some(Request {
        method,
        path,
        bearer,
        body,
        keep_alive,
    }))
}

/// 写响应 + 恒 JSON content-type；`keep_alive=false` 时带 `Connection: close`。
fn write_response(
    w: &mut TcpStream,
    resp: &crate::Response,
    keep_alive: bool,
) -> std::io::Result<()> {
    let status_text = match resp.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500..=599 => "Internal Server Error",
        _ => "OK",
    };
    let conn = if keep_alive { "keep-alive" } else { "close" };
    write!(
        w,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
        resp.status,
        status_text,
        resp.body.len(),
        conn
    )?;
    w.write_all(resp.body.as_bytes())?;
    w.flush()
}
