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
//!
//! EIP-3009 兼容桥（S-32，TECH_SPEC §6.10，可选）：
//! - `MERIDIAN_BRIDGE=1` 启用——402 体附 `exact` 条目，接受标准 EIP-3009 payload。
//! - `MERIDIAN_BRIDGE_AGENT_SEED` / `MERIDIAN_BRIDGE_OWNER_SEED`（启用时必填，0x 32B hex）
//! - `MERIDIAN_BRIDGE_DOMAIN_NAME`（缺省 `USD Coin`）/ `MERIDIAN_BRIDGE_DOMAIN_VERSION`（缺省 `2`）
//! - `MERIDIAN_BRIDGE_CHAIN_ID`（缺省 8453）/ 域合约缺省取 `MERIDIAN_ASSET`（USDC 主网）
//! - `MERIDIAN_BRIDGE_REPLAY_JOURNAL`（可选，S-33 重放闸持久化文件路径；缺省进程内存态）

use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;

use meridian_facilitator::eip3009::{BridgeConfig, Eip3009Bridge, Eip3009Domain};
use meridian_facilitator::{Facilitator, FacilitatorConfig};
use meridian_sdk::DelegationLimits;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_req(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing required env {name}"))
}

fn env_seed(name: &str) -> [u8; 32] {
    let raw = env_req(name);
    let hexed = raw.strip_prefix("0x").unwrap_or(&raw);
    hex::decode(hexed)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .unwrap_or_else(|| panic!("{name} must be 0x 32B hex"))
}

fn env_addr20(name: &str, default: &str) -> [u8; 20] {
    let raw = env_or(name, default);
    let hexed = raw.strip_prefix("0x").unwrap_or(&raw);
    hex::decode(hexed)
        .ok()
        .and_then(|v| <[u8; 20]>::try_from(v).ok())
        .unwrap_or_else(|| panic!("{name} must be 0x 20B hex"))
}

/// 桥配置（`MERIDIAN_BRIDGE=1` 时启用；缺种子即 panic——配置错误启动即暴露）。
fn bridge_config(gateway_addr: String, gateway_bearer: String, asset: &str) -> BridgeConfig {
    BridgeConfig {
        gateway_addr,
        gateway_bearer,
        domain: Eip3009Domain {
            name: env_or("MERIDIAN_BRIDGE_DOMAIN_NAME", "USD Coin"),
            version: env_or("MERIDIAN_BRIDGE_DOMAIN_VERSION", "2"),
            chain_id: env_or("MERIDIAN_BRIDGE_CHAIN_ID", "8453")
                .parse()
                .expect("MERIDIAN_BRIDGE_CHAIN_ID"),
            verifying_contract: env_addr20("MERIDIAN_BRIDGE_ASSET", asset),
        },
        agent_seed: env_seed("MERIDIAN_BRIDGE_AGENT_SEED"),
        owner_seed: env_seed("MERIDIAN_BRIDGE_OWNER_SEED"),
        limits: DelegationLimits {
            max_per_spend: env_or("MERIDIAN_BRIDGE_MAX_PER_SPEND", "1000000000")
                .parse()
                .expect("MERIDIAN_BRIDGE_MAX_PER_SPEND"),
            rate_window_secs: 60,
            rate_max_per_window: env_or("MERIDIAN_BRIDGE_RATE_MAX", "10000000000")
                .parse()
                .expect("MERIDIAN_BRIDGE_RATE_MAX"),
            total_cap: env_or("MERIDIAN_BRIDGE_TOTAL_CAP", "100000000000")
                .parse()
                .expect("MERIDIAN_BRIDGE_TOTAL_CAP"),
            categories: vec![],
            not_before: 0,
            expires_at: u64::MAX,
        },
    }
}

fn main() {
    let gateway_addr = env_req("MERIDIAN_GATEWAY_ADDR");
    let gateway_bearer = env_req("MERIDIAN_GATEWAY_BEARER");
    let asset = env_or(
        "MERIDIAN_ASSET",
        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    );
    let cfg = FacilitatorConfig {
        resource: env_req("MERIDIAN_RESOURCE"),
        pay_to: env_req("MERIDIAN_PAY_TO"),
        amount: env_req("MERIDIAN_AMOUNT"),
        network: env_or("MERIDIAN_NETWORK", "base"),
        max_timeout_seconds: env_or("MERIDIAN_MAX_TIMEOUT", "60")
            .parse()
            .expect("MERIDIAN_MAX_TIMEOUT"),
        protected_body: env_or("MERIDIAN_PROTECTED", r#"{"served":"by-meridian-x402"}"#),
        gateway_addr: gateway_addr.clone(),
        gateway_bearer: gateway_bearer.clone(),
        asset: Some(asset.clone()),
    };
    let bridge = if env_or("MERIDIAN_BRIDGE", "0") == "1" {
        let bc = bridge_config(gateway_addr, gateway_bearer, &asset);
        Some(match std::env::var("MERIDIAN_BRIDGE_REPLAY_JOURNAL").ok() {
            // S-33：持久化重放闸——启动重建闸表（坏行跳过计数），日志打开失败即退出
            // （配置错误启动即暴露，同缺种子 panic 口径）。
            Some(p) => {
                let path = Path::new(&p);
                let b = Eip3009Bridge::open(bc, path)
                    .unwrap_or_else(|e| panic!("open replay journal {p}: {e}"));
                eprintln!(
                    "meridian-facilitator: replay journal {} loaded={} skipped={}",
                    p,
                    b.seen_len(),
                    b.skipped_journal_lines()
                );
                b
            }
            None => Eip3009Bridge::new(bc),
        })
    } else {
        None
    };
    let bridge_enabled = bridge.is_some();
    let addr = format!("127.0.0.1:{}", env_or("PORT", "9500"));

    let facilitator = Arc::new(Facilitator::with_bridge(cfg, bridge));
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    eprintln!(
        "meridian-facilitator: serving http://{addr} resource={} gateway={} eip3009-bridge={}",
        facilitator.config().resource,
        facilitator.config().gateway_addr,
        bridge_enabled
    );
    if let Err(e) = meridian_facilitator::http::serve(facilitator, listener) {
        panic!("serve: {e}");
    }
}
