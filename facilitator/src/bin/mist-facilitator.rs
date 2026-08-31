//! mist-facilitator 守护进程（S-30c）：单一受保护资源 + 网关回执验证。
//!
//! 配置经环境变量（与 gateway bin 同风格）：
//! - `MIST_GATEWAY_ADDR`（必填，如 `127.0.0.1:9400`）
//! - `MIST_GATEWAY_BEARER`（必填，网关租户 key）
//! - `MIST_RESOURCE`（必填，受保护资源 URL）
//! - `MIST_PAY_TO`（必填，0x 收款地址）/ `MIST_AMOUNT`（必填，原子单位字符串）
//! - `MIST_NETWORK`（缺省 `base`）/ `MIST_ASSET`（可选）
//! - `MIST_MAX_TIMEOUT`（缺省 60）/ `MIST_PROTECTED`（缺省示例 JSON）
//! - `PORT`（缺省 9500）
//!
//! EIP-3009 兼容桥（S-32，TECH_SPEC §6.10，可选）：
//! - `MIST_BRIDGE=1` 启用——402 体附 `exact` 条目，接受标准 EIP-3009 payload。
//! - `MIST_BRIDGE_AGENT_SEED` / `MIST_BRIDGE_OWNER_SEED`（启用时必填，0x 32B hex）
//! - `MIST_BRIDGE_DOMAIN_NAME`（缺省 `USD Coin`）/ `MIST_BRIDGE_DOMAIN_VERSION`（缺省 `2`）
//! - `MIST_BRIDGE_CHAIN_ID`（缺省 8453）/ 域合约缺省取 `MIST_ASSET`（USDC 主网）
//! - `MIST_BRIDGE_REPLAY_JOURNAL`（可选，S-33 重放闸持久化文件路径；缺省进程内存态）
//! - `MIST_BRIDGE_NOIR`（可选，S-47 真 prover 装配，TECH_SPEC §6.10/§6.14）：`=1`
//!   时垫付 client 经 `SdkClient::with_noir` 用真电路 prover（NoirProver，§6.14 同源
//!   装配）；缺省占位 prover（口径同 `MIST_VERIFY_BACKEND` 缺省 `format`——生产
//!   默认不动，真后端显式开启）。
//!   - `MIST_BRIDGE_NOIR_ROOT`（noir 模式可选，缺省 `.`）：仓库根（`gen-witness/`
//!     + `circuits/` 所在目录）；启动期检查两目录存在（fail-fast，配置错误启动即暴露）。
//!   - `MIST_BRIDGE_ATTEST_SECRET`（noir 模式必填，0x 32B hex）：attestation 私钥
//!     标量（熵由调用方供给，SDK 不生成随机熵，§6.14 诚实边界 2）；prove/keygen 入口
//!     另有值域闸（< EdDSA 子群阶，越界 `E_PROVER` fail-closed）。

use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;

use mist_facilitator::eip3009::{BridgeConfig, Eip3009Bridge, Eip3009Domain};
use mist_facilitator::{Facilitator, FacilitatorConfig};
use mist_sdk::DelegationLimits;

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

/// 桥配置（`MIST_BRIDGE=1` 时启用；缺种子即 panic——配置错误启动即暴露）。
fn bridge_config(gateway_addr: String, gateway_bearer: String, asset: &str) -> BridgeConfig {
    BridgeConfig {
        gateway_addr,
        gateway_bearer,
        domain: Eip3009Domain {
            name: env_or("MIST_BRIDGE_DOMAIN_NAME", "USD Coin"),
            version: env_or("MIST_BRIDGE_DOMAIN_VERSION", "2"),
            chain_id: env_or("MIST_BRIDGE_CHAIN_ID", "8453")
                .parse()
                .expect("MIST_BRIDGE_CHAIN_ID"),
            verifying_contract: env_addr20("MIST_BRIDGE_ASSET", asset),
        },
        agent_seed: env_seed("MIST_BRIDGE_AGENT_SEED"),
        owner_seed: env_seed("MIST_BRIDGE_OWNER_SEED"),
        limits: DelegationLimits {
            max_per_spend: env_or("MIST_BRIDGE_MAX_PER_SPEND", "1000000000")
                .parse()
                .expect("MIST_BRIDGE_MAX_PER_SPEND"),
            rate_window_secs: 60,
            rate_max_per_window: env_or("MIST_BRIDGE_RATE_MAX", "10000000000")
                .parse()
                .expect("MIST_BRIDGE_RATE_MAX"),
            total_cap: env_or("MIST_BRIDGE_TOTAL_CAP", "100000000000")
                .parse()
                .expect("MIST_BRIDGE_TOTAL_CAP"),
            categories: vec![],
            not_before: 0,
            expires_at: u64::MAX,
        },
        noir: noir_assembly(),
    }
}

/// 真 prover 装配（S-47，TECH_SPEC §6.10 第 4 步 / §6.14 CLI 消费）。
/// `MIST_BRIDGE_NOIR=1` 才启用；缺省 `None`（占位 prover，口径逐字节不变）。
/// 仓库根目录存在性在此 fail-fast（配置错误启动即暴露，同缺种子 panic 口径）；
/// 工具链探测仍惰性（首次 `pay()` 时 `NoirProver::from_dirs`，不可得 `E_PROVER`
/// → 503 fail-closed）。
fn noir_assembly() -> Option<mist_facilitator::eip3009::NoirAssembly> {
    if env_or("MIST_BRIDGE_NOIR", "0") != "1" {
        return None;
    }
    let root = std::path::PathBuf::from(env_or("MIST_BRIDGE_NOIR_ROOT", "."));
    for dir in ["gen-witness", "circuits"] {
        assert!(
            root.join(dir).is_dir(),
            "MIST_BRIDGE_NOIR_ROOT({}) 缺 {dir}/ 目录（NoirProver 仓库布局装配需要）",
            root.display()
        );
    }
    Some(mist_facilitator::eip3009::NoirAssembly {
        root,
        attestation_secret: env_seed("MIST_BRIDGE_ATTEST_SECRET"),
    })
}

fn main() {
    let gateway_addr = env_req("MIST_GATEWAY_ADDR");
    let gateway_bearer = env_req("MIST_GATEWAY_BEARER");
    let asset = env_or("MIST_ASSET", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
    let cfg = FacilitatorConfig {
        resource: env_req("MIST_RESOURCE"),
        pay_to: env_req("MIST_PAY_TO"),
        amount: env_req("MIST_AMOUNT"),
        network: env_or("MIST_NETWORK", "base"),
        max_timeout_seconds: env_or("MIST_MAX_TIMEOUT", "60")
            .parse()
            .expect("MIST_MAX_TIMEOUT"),
        protected_body: env_or("MIST_PROTECTED", r#"{"served":"by-mist-x402"}"#),
        gateway_addr: gateway_addr.clone(),
        gateway_bearer: gateway_bearer.clone(),
        asset: Some(asset.clone()),
    };
    let bridge = if env_or("MIST_BRIDGE", "0") == "1" {
        let bc = bridge_config(gateway_addr, gateway_bearer, &asset);
        Some(match std::env::var("MIST_BRIDGE_REPLAY_JOURNAL").ok() {
            // S-33：持久化重放闸——启动重建闸表（坏行跳过计数），日志打开失败即退出
            // （配置错误启动即暴露，同缺种子 panic 口径）。
            Some(p) => {
                let path = Path::new(&p);
                let b = Eip3009Bridge::open(bc, path)
                    .unwrap_or_else(|e| panic!("open replay journal {p}: {e}"));
                eprintln!(
                    "mist-facilitator: replay journal {} loaded={} skipped={}",
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
    // S-47 可观测：垫付 client prover 模式（noir = 真电路 prover，§6.14 同源装配）。
    if let Some(b) = &bridge {
        eprintln!(
            "mist-facilitator: bridge prover={} (TECH_SPEC §6.10/§6.14)",
            b.prover_mode()
        );
    }
    let bridge_enabled = bridge.is_some();
    let addr = format!("127.0.0.1:{}", env_or("PORT", "9500"));

    let facilitator = Arc::new(Facilitator::with_bridge(cfg, bridge));
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    eprintln!(
        "mist-facilitator: serving http://{addr} resource={} gateway={} eip3009-bridge={}",
        facilitator.config().resource,
        facilitator.config().gateway_addr,
        bridge_enabled
    );
    if let Err(e) = mist_facilitator::http::serve(facilitator, listener) {
        panic!("serve: {e}");
    }
}
