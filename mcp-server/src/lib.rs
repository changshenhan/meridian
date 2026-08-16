//! S-07 MCP 探针：`meridian.authorize` / `meridian.pay`。
//!
//! 形态：**单进程聚合器** + **stdin/stdout MCP server**。任何主流 agent 框架
//! （Claude Desktop / Code / 自定义 MCP client）都能把本 server 配成 MCP 工具，
//! 让 agent 今天就"花钱"——经过授权的预算内模拟支付。
//!
//! TEMPORARY 边界（S-07 验收口径，README 决策记录里有完整版）：
//! `pay()` 的授权 = agent Ed25519 验签 + 预算检查，**无 ZK 证明**。
//! S-09 把真实 circuit 证明插进同一路径（state.rs::pay 内留了挂载点）。
//!
//! 依赖的 core 语义：owner ECDSA-secp256k1 签 `Delegation`，agent Ed25519 签
//! `SpendIntent`；账本执行预算（规则 1-6）。全部复用 S-02/S-05/S-06 已验收代码。
//!
//! 模块划分（宏作用域约束：`#[tool_router]` 生成的 `tool_router()` 关联函数与
//! `#[tool_handler]` 必须同模块，见 tools.rs）。

use std::sync::Arc;

pub mod state;
pub mod tools;

use state::AppState;

/// Meridian MCP 探针服务端（S-07）。
#[derive(Clone)]
pub struct MeridianServer {
    pub(crate) state: Arc<AppState>,
}

impl MeridianServer {
    pub fn new() -> Self {
        Self {
            state: Arc::new(AppState::new()),
        }
    }
}

impl Default for MeridianServer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MeridianServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeridianServer")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
