//! S-13 MCP 服务器正式版：stdio 入口，内嵌真实聚合器内核（WAL 持久化）。
//!
//! 启动方式（任意 MCP 客户端）：
//!   cargo run -p mist-mcp                       # 本地（WAL 在 ./mist.wal）
//!   MIST_WAL_DIR=demos/.wal cargo run -p mist-mcp
//!   或构建二进制后作为 MCP server 配置到 agent 框架（LangChain / AutoGen / ElizaOS…）。
//!
//! WAL 路径优先级：env `MIST_WAL_DIR`（目录，文件名 mist.wal）> CLI 首个参数
//! （文件路径）> `./mist.wal`。
//!
//! 验证后端（S-52，TECH_SPEC §6.16，网关 bin 同款）：env `MIST_VERIFY_BACKEND`
//! 缺省 `format`（FormatVerifier 占位口径不变）；`bb` 走真 ZK 验证（BbVerifier）+
//! 撤销根绑定闸（S-48 配对闸）——此时 pay 必须带客户端直通 proof 入参（keyless：
//! 证明在框架侧产出，服务器只验证）。

use std::path::PathBuf;
use std::sync::Arc;

use mist_aggregator::bb::BbVerifier;
use mist_aggregator::ingest::{Aggregator, IngestConfig};
use mist_aggregator::proof::FormatVerifier;
use mist_aggregator::wal::Wal;
use mist_core::zk::SpendVerifier;
use mist_mcp::MistServer;
use rmcp::transport::stdio;
use rmcp::ServiceExt;

fn wal_path() -> PathBuf {
    if let Ok(dir) = std::env::var("MIST_WAL_DIR") {
        return PathBuf::from(dir).join("mist.wal");
    }
    std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("mist.wal"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = wal_path();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            // Wal::open 不建目录。
            std::fs::create_dir_all(parent)?;
        }
    }
    let wal = Wal::open(&path, 1_000)?;
    // 验证后端（S-52，TECH_SPEC §6.16，网关 bin 同款）：缺省 `format`（FormatVerifier
    // TEMPORARY 口径，生产默认不变）；`bb` 走真 ZK 验证（BbVerifier，需 MIST_BB_VK +
    // 可得的 bb 工具链；不可得启动即退 fail-closed）。S-52 起 pay 的 proof 入参直通本
    // 验证缝（keyless：客户端产证明，服务器只验证，§6.16）。
    let verifier: Box<dyn SpendVerifier + Send + Sync> = match std::env::var("MIST_VERIFY_BACKEND")
        .as_deref()
    {
        Ok("bb") => match BbVerifier::from_env() {
            Ok(v) => {
                eprintln!(
                    "verify backend: bb (TECH_SPEC §6.16)——占位证明 / 无 proof 入参的 pay 会被全拒"
                );
                Box::new(v)
            }
            Err(e) => {
                eprintln!(
                    "MIST_VERIFY_BACKEND=bb 但后端不可得（{e}）：需 MIST_BB_VK + nargo/bb 工具链（Windows 原生或 WSL2 兜底）"
                );
                std::process::exit(2);
            }
        },
        _ => Box::new(FormatVerifier),
    };
    // 装配面配对闸（S-48）：bb 模式的证明公共输入 `revocation_root` 有密码学语义，
    // 撤销根绑定闸必须同步开启——聚合器构造期按
    // `SpendVerifier::requires_revocation_root_binding` 复查，漏配启动即 panic。
    let mut ingest_cfg = IngestConfig::default();
    if verifier.requires_revocation_root_binding() {
        ingest_cfg.enforce_revocation_root = true;
    }
    let agg = Arc::new(Aggregator::new(ingest_cfg, verifier, wal));
    let service = MistServer::new(agg);
    let running = service.serve(stdio()).await?;
    running.waiting().await?;
    Ok(())
}
