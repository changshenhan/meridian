//! SDK 错误（S-12）：传输错误 vs 业务错误码 vs 本地错误。
//!
//! 重试判据在类型上分叉：只有 [`SdkError::Transport`] 是重试候选；[`SdkError::Mist`]
//! 是聚合器/本地校验的定局拒绝（错误码经 `Error::as_code` 透传），永不重试。

use std::fmt;

use mist_core::error::Error;

/// 传输层错误（网络 / 进程间断线）。`pay` 重试只看这一支。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// 连接断开 / 对端无响应（回执可能已产生——这正是幂等重试要兜的场景）。
    Disconnected,
    /// 超时。
    Timeout,
    /// 其它传输失败。
    Other(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Disconnected => write!(f, "transport disconnected"),
            TransportError::Timeout => write!(f, "transport timeout"),
            TransportError::Other(s) => write!(f, "transport error: {s}"),
        }
    }
}

/// SDK 错误。
#[derive(Debug)]
pub enum SdkError {
    /// 传输层错误——重试候选（nonce 固定重发，聚合器幂等兜底）。
    Transport(TransportError),
    /// Mist 错误码（聚合器拒绝 / 本地构造校验）。`Error::as_code()` 透传，永不重试。
    Mist(Error),
    /// 本地错误（参数 / 状态，非协议码）。
    Local(String),
}

impl SdkError {
    /// 错误码透传：业务错误返回规格码（如 `"E_BUDGET_PER_SPEND"`），传输/本地错误给描述。
    pub fn code(&self) -> String {
        match self {
            SdkError::Mist(e) => e.as_code().to_string(),
            other => other.to_string(),
        }
    }
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdkError::Transport(t) => write!(f, "{t}"),
            SdkError::Mist(e) => write!(f, "{}", e.as_code()),
            SdkError::Local(s) => write!(f, "local: {s}"),
        }
    }
}

impl std::error::Error for SdkError {}
