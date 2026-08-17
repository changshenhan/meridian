//! S-13 MCP 服务器正式版：`meridian.authorize` / `meridian.pay` / `meridian.balance` /
//! `meridian.attest` / `meridian.verify_receipt`。
//!
//! 形态：**stdio MCP server + 内嵌真实聚合器内核**（`meridian-aggregator`：WAL 持久化、
//! 幂等 re-ack、单调 seq、真错误码、预算强制）。任何主流 agent 框架（LangChain / AutoGen /
//! ElizaOS / Claude Desktop / 自定义 MCP client）都能把本 server 配成 MCP 工具，让 agent
//! 用 DSA 授权自动购买数据 / API 额度。
//!
//! 安全模型（Shape 1，延续 S-07）：**服务器不持有任何私钥**。owner secp256k1 与 agent
//! Ed25519 密钥都在框架侧、签名外部完成；服务器只验签 + 执行。authorize 校验 owner 对
//! delegation_hash 的 secp256k1 签名后调 `Aggregator::register`；pay 由服务器用占位证明
//! 构造信封（诚实边界，见 README）后 `Aggregator::submit`——幂等重发（S-12）免费获得。
//!
//! TEMPORARY 边界（诚实口径，README 决策记录有完整版）：`pay()` 的 ZK 证明目前是服务器
//! 侧占位（proof 非空 + 公共输入与 intent 一致），`FormatVerifier` 只做格式门禁。真实
//! S-09 电路 prover 实现 `SpendVerifier` 插同一路径即可，`pay` 不改。
//!
//! 模块划分（宏作用域约束：`#[tool_router]` 生成的 `tool_router()` 关联函数与
//! `#[tool_handler]` 必须同模块，见 tools.rs）。

use std::sync::Arc;

use meridian_aggregator::ingest::Aggregator;

pub mod state;
pub mod tools;

use state::AppState;

/// Meridian MCP 服务器正式版（S-13）。
#[derive(Clone)]
pub struct MeridianServer {
    pub(crate) state: Arc<AppState>,
}

impl MeridianServer {
    /// 注入聚合器内核（main.rs / 测试各自构造，WAL 路径由调用方决定）。
    pub fn new(agg: Arc<Aggregator>) -> Self {
        Self {
            state: Arc::new(AppState::new(agg)),
        }
    }
}

impl std::fmt::Debug for MeridianServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeridianServer")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
