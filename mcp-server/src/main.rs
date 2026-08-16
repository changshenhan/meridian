//! S-07 MCP 探针：stdio 入口。
//!
//! 启动方式（任意 MCP 客户端）：
//!   cargo run -p meridian-mcp          # 本地
//!   或构建二进制后作为 MCP server 配置到 agent 框架。

use meridian_mcp::MeridianServer;
use rmcp::transport::stdio;
use rmcp::ServiceExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = MeridianServer::new();
    let running = service.serve(stdio()).await?;
    running.waiting().await?;
    Ok(())
}
