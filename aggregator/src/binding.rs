//! 运营者绑定闸（S-62，TECH_SPEC §6.19）——Phase 2 P2-2 分片多运营者的**事前强制层**。
//!
//! 预算强制层在账本侧（§4.5）⇒ 分片多账本下同一委托可在两张账本各消费一次（跨分片
//! 双花，任何单账本内部不可见）。封堵的链上锚点 = DSA `dh → operator` 绑定映射
//! （§6.19.1，独立映射不进 delegation_hash preimage）：本模块在摄取管线步 4b 读该
//! 映射，**绑定到其他运营者的意图当场拒**（`E_OPERATOR`），把跨分片双花从「事后欺诈
//! 证明（P2-3）」前移到「事前不发生」。
//!
//! 三态判定（唯一策略点，[`BindingGate::check`]）：
//!
//! | 链上读数 | 判定 | 依据 |
//! |---|---|---|
//! | 未绑定（`None`） | 放行 | 决策 B fail-open：fail-closed = 闸上线当天冻结全部存量委托 |
//! | 绑定 = 本运营者 | 放行 | 本分片的委托 |
//! | 绑定 ≠ 本运营者 | `E_OPERATOR` | 他分片的委托，事前拒绝 |
//! | 读面不可得（Err） | `E_BIND_BACKEND` | fail-closed：看不到绑定面 ≠ 绑定不存在 |
//!
//! 事实源与策略分离：[`OperatorBinding`] trait 只回答链上事实（测试内 `StaticBinding`
//! 进程内映射 / gateway 侧 JSON-RPC `eth_call`），三态策略集中在此，测试一次锚定。
//!
//! **不可变绑定读缓存**：绑定一经写入永不改变（§6.19.1 无改绑路径）⇒ 读数可永久缓存，
//! 每委托只付一次冷读，热路径 = 一次哈希查找（B8 内核 `try_commit` 零改动）。读失败
//! **不进缓存**（瞬态，下一笔重试）。缓存进程内不持久化（WAL 冻结面纪律）：重启后
//! 冷缓存首笔重读——链上是事实源，拒绝方向安全。

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use mist_core::error::Error;

/// 运营者地址（EVM 20B，与 DSA `operators` 映射同形态）。
pub type OperatorAddress = [u8; 20];

/// 绑定事实源：读 DSA `operatorOf(dh)`（§6.19.1）。
///
/// 实现约定：
/// - `Ok(None)` = 未绑定（零地址读数）——**不是**错误，闸按 fail-open 放行；
/// - `Err(_)` = 读面不可得（RPC 失败 / 短返回 / 非 32B 编码）——闸 fail-closed 拒
///   `E_BIND_BACKEND`，错误细节不进 `Error`（fieldless 枚举，wire 只传码）；
///   实现应自行记录日志/指标。
pub trait OperatorBinding: Send + Sync {
    fn operator_of(&self, dh: &[u8; 32]) -> Result<Option<OperatorAddress>, String>;
}

/// 进程内静态绑定表（测试替身 / in-process 装配形态，如演练与 InProcessAggregator）。
/// 缺席 = 未绑定。生产装配（网关 bin）走 gateway 的 JSON-RPC 实现，本表不触网。
#[derive(Default)]
pub struct StaticBinding {
    map: RwLock<HashMap<[u8; 32], OperatorAddress>>,
}

impl StaticBinding {
    pub fn new() -> Self {
        Self::default()
    }

    /// 写入一条绑定（模拟 `DSA.bindOperator`；本表无改绑校验——那是合约侧职责）。
    pub fn bind(&self, dh: [u8; 32], operator: OperatorAddress) {
        self.map
            .write()
            .expect("static binding poisoned")
            .insert(dh, operator);
    }

    pub fn binding_of(&self, dh: &[u8; 32]) -> Option<OperatorAddress> {
        self.map
            .read()
            .expect("static binding poisoned")
            .get(dh)
            .copied()
    }
}

impl OperatorBinding for StaticBinding {
    fn operator_of(&self, dh: &[u8; 32]) -> Result<Option<OperatorAddress>, String> {
        Ok(self.binding_of(dh))
    }
}

/// 绑定闸：事实源 + 本运营者身份 + 不可变读缓存。
pub struct BindingGate {
    source: Arc<dyn OperatorBinding + Send + Sync>,
    self_operator: OperatorAddress,
    /// 不可变绑定读缓存：dh → 链上读数（`None` = 未绑定，同样可缓存——未绑定委托在
    /// 读协议里也是终态，除非 owner 补绑；补绑后本进程按缓存口径继续放行 = fail-open
    /// 残余的进程内影子，§6.19.5）。读失败不进缓存。
    cache: Mutex<HashMap<[u8; 32], Option<OperatorAddress>>>,
}

impl BindingGate {
    pub fn new(
        source: Arc<dyn OperatorBinding + Send + Sync>,
        self_operator: OperatorAddress,
    ) -> Self {
        BindingGate {
            source,
            self_operator,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// 管线步 4b 判定（§6.19.2）。`Err` = 拒（不耗 nonce / 窗口槽，闸在 `try_commit`
    /// 之前；同意图重发走全新校验，不被幂等闸缓存的原拒绝命中）。
    pub fn check(&self, dh: &[u8; 32]) -> Result<(), Error> {
        let cached = self
            .cache
            .lock()
            .expect("binding cache poisoned")
            .get(dh)
            .copied();
        let bound = match cached {
            Some(b) => b,
            None => {
                // 冷读：Err 即拒且**不缓存**（瞬态失败不该把整个委托钉死在拒绝态——
                // 那会把读面抖动放大成账本停摆；fail-closed 的粒度是「这笔」，不是
                // 「这个委托」）。
                let read = self
                    .source
                    .operator_of(dh)
                    .map_err(|_| Error::EBindBackend)?;
                self.cache
                    .lock()
                    .expect("binding cache poisoned")
                    .insert(*dh, read);
                read
            }
        };
        match bound {
            // 未绑定 → fail-open（决策 B；§6.19.5 诚实边界：有意取舍不是疏漏）。
            // 零地址读数按读协议 = 未绑定（DSA 侧构造性禁止绑定为零，这里是防御性
            // 归一——实现侧忘了映射零地址也不改判语义）。
            None => Ok(()),
            Some(op) if op == [0u8; 20] => Ok(()),
            Some(op) if op == self.self_operator => Ok(()),
            Some(_) => Err(Error::EOperator),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dh(n: u8) -> [u8; 32] {
        [n; 32]
    }

    const SELF: OperatorAddress = [0xAA; 20];
    const OTHER: OperatorAddress = [0xBB; 20];

    fn gate(source: Arc<dyn OperatorBinding + Send + Sync>) -> BindingGate {
        BindingGate::new(source, SELF)
    }

    /// 计数读源：每次冷读 +1，可切换为恒 Err（读面故障注入）。
    struct CountingBinding {
        inner: StaticBinding,
        cold_reads: std::sync::atomic::AtomicUsize,
        fail: std::sync::atomic::AtomicBool,
    }

    impl CountingBinding {
        fn new() -> Self {
            CountingBinding {
                inner: StaticBinding::new(),
                cold_reads: std::sync::atomic::AtomicUsize::new(0),
                fail: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl OperatorBinding for CountingBinding {
        fn operator_of(&self, dh: &[u8; 32]) -> Result<Option<OperatorAddress>, String> {
            // 计数含失败尝试（语义 = 冷读次数，非成功次数）。
            self.cold_reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.fail.load(std::sync::atomic::Ordering::Relaxed) {
                return Err("rpc down".into());
            }
            Ok(self.inner.binding_of(dh))
        }
    }

    #[test]
    fn unbound_delegation_is_fail_open() {
        let src = Arc::new(StaticBinding::new());
        assert!(
            gate(src).check(&dh(1)).is_ok(),
            "未绑定放行（决策 B fail-open）"
        );
    }

    #[test]
    fn bound_to_self_passes_and_bound_to_other_rejects_with_e_operator() {
        let src = Arc::new(StaticBinding::new());
        src.bind(dh(1), SELF);
        src.bind(dh(2), OTHER);
        let g = gate(Arc::clone(&src) as Arc<dyn OperatorBinding + Send + Sync>);
        assert!(g.check(&dh(1)).is_ok());
        assert_eq!(g.check(&dh(2)), Err(Error::EOperator));
    }

    #[test]
    fn read_failure_is_fail_closed_and_not_cached() {
        let src = Arc::new(CountingBinding::new());
        src.fail.store(true, std::sync::atomic::Ordering::Relaxed);
        let g = gate(Arc::clone(&src) as Arc<dyn OperatorBinding + Send + Sync>);
        // 读面不可得 → E_BIND_BACKEND（fail-closed，绝不按未绑定放行）。
        assert_eq!(g.check(&dh(1)), Err(Error::EBindBackend));
        // 恢复后重读成功：瞬态失败不进缓存，不把委托钉死在拒绝态。
        src.fail.store(false, std::sync::atomic::Ordering::Relaxed);
        src.inner.bind(dh(1), OTHER);
        assert_eq!(g.check(&dh(1)), Err(Error::EOperator));
        assert_eq!(src.cold_reads.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    fn immutable_read_is_cached_after_first_cold_read() {
        let src = Arc::new(CountingBinding::new());
        let g = gate(Arc::clone(&src) as Arc<dyn OperatorBinding + Send + Sync>);
        assert!(g.check(&dh(1)).is_ok());
        assert!(g.check(&dh(1)).is_ok());
        assert!(g.check(&dh(1)).is_ok());
        // 绑定不可改（§6.19.1 无改绑路径）⇒ 后续命中缓存，不再触源。
        assert_eq!(src.cold_reads.load(std::sync::atomic::Ordering::Relaxed), 1);
        // 事后补绑（owner 给存量委托绑定）对本进程不可见 = 缓存的 fail-open 影子；
        // 重启（冷缓存）后按新读数判定。此处锚定缓存语义本身。
        src.inner.bind(dh(1), OTHER);
        assert!(g.check(&dh(1)).is_ok(), "命中缓存：补绑不回溯本进程");
    }

    #[test]
    fn zero_address_binding_is_treated_as_unbound() {
        // 链上侧构造性禁止绑定为零地址（DSA ZeroOperator）；防御性口径：读面若返回
        // 零地址（旧实现 / 误配），闸按未绑定 fail-open 处理而非 panic。
        let src = Arc::new(StaticBinding::new());
        src.bind(dh(1), [0u8; 20]);
        assert!(gate(src).check(&dh(1)).is_ok());
    }
}
