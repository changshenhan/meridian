//! meridian-facilitator 守护进程（S-30c）：单一受保护资源 + 网关回执验证。
//!
//! 配置经环境变量（与 gateway bin 同风格）：
//! - `MERIDIAN_GATEWAY_ADDR`（必填，如 `127.0.0.1:9400`）
//! - `MERIDIAN_GATEWAY_BEARER`（必填，网关租户 key）
//! - `MERIDIAN_RESOURCE`（必填，受保护资源 URL）
//! - `MERIDIAN_PAY_TO`（必填，0x 收款地址）/ `MERIDIAN_AMOUNT`（必填，原子单位字符串）
//! - `MERIDIAN_NETWORK`（缺省 `base`）/ `MERIDIAN_ASSET`（可选）
//! - `MERIDIAN_MAX_TIMEOUT`（缺省 60）/ `MERIDIAN_PROTECTED`（缺省示例 JSON）
//! - `PORT`（缺省 9500）

use std::net::TcpListener;
use std::sync::Arc;

use meridian_facilitator::{Facilitator, FacilitatorConfig};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_req(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing required env {name}"))
}

fn main() {
    let cfg = FacilitatorConfig {
        gateway_addr: env_req("MERIDIAN_GATEWAY_ADDR"),
        gateway_bearer: env_req("MERIDIAN_GATEWAY_BEARER"),
        resource: env_req("MERIDIAN_RESOURCE"),
        pay_to: env_req("MERIDIAN_PAY_TO"),
        amount: env_req("MERIDIAN_AMOUNT"),
        network: env_or("MERIDIAN_NETWORK", "base"),
        asset: std::env::var("MERIDIAN_ASSET").ok(),
        max_timeout_seconds: env_or("MERIDIAN_MAX_TIMEOUT", "60")
            .parse()
            .expect("MERIDIAN_MAX_TIMEOUT"),
        protected_body: env_or("MERIDIAN_PROTECTED", r#"{"served":"by-meridian-x402"}"#),
    };
    let addr = format!("127.0.0.1:{}", env_or("PORT", "9500"));

    let facilitator = Arc::new(Facilitator::new(cfg));
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    eprintln!(
        "meridian-facilitator: serving http://{addr} resource={} gateway={}",
        facilitator.config().resource,
        facilitator.config().gateway_addr
    );
    if let Err(e) = meridian_facilitator::http::serve(facilitator, listener) {
        panic!("serve: {e}");
    }
}
