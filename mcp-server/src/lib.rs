//! S-13 MCP 服务器正式版：`meridian.authorize` / `meridian.pay` / `meridian.balance` /
//! `meridian.attest` / `meridian.verify_receipt` / `meridian.revocation_witness`（S-52）。
//!
//! 形态：**stdio MCP server + 内嵌真实聚合器内核**（`meridian-aggregator`：WAL 持久化、
//! 幂等 re-ack、单调 seq、真错误码、预算强制）。任何主流 agent 框架（LangChain / AutoGen /
//! ElizaOS / Claude Desktop / 自定义 MCP client）都能把本 server 配成 MCP 工具，让 agent
//! 用 DSA 授权自动购买数据 / API 额度。
//!
//! 安全模型（Shape 1，延续 S-07）：**服务器不持有任何私钥**。owner secp256k1 与 agent
//! Ed25519 密钥都在框架侧、签名外部完成；服务器只验签 + 执行。authorize 校验 owner 对
//! delegation_hash 的 secp256k1 签名后调 `Aggregator::register`；pay 的证明来源分派
//! （S-52，TECH_SPEC §6.16）：客户端直通证明优先（真 ZK，keyless 保形——证明是数据
//! 不是密钥），缺席才由服务器用占位证明构造信封（诚实边界，见 README）后
//! `Aggregator::submit`——幂等重发（S-12）免费获得。
//!
//! ZK 语义（README 决策记录 D6 / §6.16）：`pay` 可选 `proof` 入参直通同一 `SpendVerifier`
//! 缝，真验证后端（`BbVerifier`，bin `MERIDIAN_VERIFY_BACKEND=bb` + S-48 撤销根绑定闸）
//! 下占位被全拒；`revocation_witness` 工具下发客户端构建真证明所需的撤销事实。
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
