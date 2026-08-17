//! S-13 MCP 服务器正式版：stdio 入口，内嵌真实聚合器内核（WAL 持久化）。
//!
//! 启动方式（任意 MCP 客户端）：
//!   cargo run -p meridian-mcp                       # 本地（WAL 在 ./meridian.wal）
//!   MERIDIAN_WAL_DIR=demos/.wal cargo run -p meridian-mcp
//!   或构建二进制后作为 MCP server 配置到 agent 框架（LangChain / AutoGen / ElizaOS…）。
//!
//! WAL 路径优先级：env `MERIDIAN_WAL_DIR`（目录，文件名 meridian.wal）> CLI 首个参数
//! （文件路径）> `./meridian.wal`。

use std::path::PathBuf;
use std::sync::Arc;

use meridian_aggregator::ingest::{Aggregator, IngestConfig};
use meridian_aggregator::proof::FormatVerifier;
use meridian_aggregator::wal::Wal;
use meridian_mcp::MeridianServer;
use rmcp::transport::stdio;
use rmcp::ServiceExt;

fn wal_path() -> PathBuf {
    if let Ok(dir) = std::env::var("MERIDIAN_WAL_DIR") {
        return PathBuf::from(dir).join("meridian.wal");
    }
    std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("meridian.wal"))
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
    let agg = Arc::new(Aggregator::new(
        IngestConfig::default(),
        Box::new(FormatVerifier),
        wal,
    ));
    let service = MeridianServer::new(agg);
    let running = service.serve(stdio()).await?;
    running.waiting().await?;
    Ok(())
}
