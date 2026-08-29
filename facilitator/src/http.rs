//! std-only HTTP/1.1 管道（S-30c，§6.7 gateway http 同先例，精简版）。
//!
//! 单请求 close 模式（agent 侧 `HttpFetch` 恒发 `Connection: close`）；只关心
//! 请求行 / `X-PAYMENT` 头。分发一律交给 [`crate::Facilitator::handle`]（纯分发）。

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::{Facilitator, FacilitatorResponse, PAYMENT_HEADER};

/// 阻塞服务循环（每连接一线程；调用方负责守护进程化）。
pub fn serve(facilitator: Arc<Facilitator>, listener: TcpListener) -> std::io::Result<()> {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let facilitator = Arc::clone(&facilitator);
        std::thread::spawn(move || {
            let _ = handle_connection(facilitator, stream);
        });
    }
    Ok(())
}

fn handle_connection(facilitator: Arc<Facilitator>, stream: TcpStream) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(()); // 对端关闭
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    if method.is_empty() || path.is_empty() {
        write_response(&mut writer, &FacilitatorResponse::status(400))?;
        return Ok(());
    }

    let mut payment: Option<String> = None;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            break;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((name, value)) = h.split_once(':') {
            if name.trim().eq_ignore_ascii_case(PAYMENT_HEADER) {
                payment = Some(value.trim().to_string());
            }
        }
    }

    let resp = facilitator.handle(&method, &path, payment.as_deref());
    write_response(&mut writer, &resp)
}

/// 写响应；恒 `Connection: close`（单请求模型）。
fn write_response(w: &mut TcpStream, resp: &FacilitatorResponse) -> std::io::Result<()> {
    let status_text = match resp.status {
        200 => "OK",
        400 => "Bad Request",
        402 => "Payment Required",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500..=599 => "Internal Server Error",
        _ => "OK",
    };
    write!(
        w,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp.status,
        status_text,
        resp.body.len()
    )?;
    w.write_all(resp.body.as_bytes())?;
    w.flush()
}
