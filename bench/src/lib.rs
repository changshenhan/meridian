//! 基准基座（TECH_SPEC §8 / MASTER_PLAN S-04）。
//!
//! 提供：计数分配器 + `NoAllocGuard`（热路径零分配断言，B8）。
//! 设计：线程本地计数；守卫包裹的代码段内若发生堆分配，`section_allocs()` 可观测。
//! 由全局分配器计数，测试只读线程本地计数，不做估计。
//!
//! `ingest`：PoC ② 聚合器 ingest 原型（验签 → nonce 去重 → 预算记账的吞吐管线）。

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

pub mod ingest;

thread_local! {
    static GUARD_DEPTH: Cell<usize> = const { Cell::new(0) };
    static SECTION_ALLOCS: Cell<usize> = const { Cell::new(0) };
    /// 守卫段内累计分配字节数（B7 内存上界：累计 ≥ 峰值，作保守上界断言 <1GB）。
    static SECTION_BYTES: Cell<usize> = const { Cell::new(0) };
}

/// 计数分配器：统计当前线程在守卫段内的堆分配次数。
pub struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if GUARD_DEPTH.with(|d| d.get()) > 0 {
            SECTION_ALLOCS.with(|c| c.set(c.get() + 1));
            SECTION_BYTES.with(|b| b.set(b.get() + layout.size()));
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if GUARD_DEPTH.with(|d| d.get()) > 0 {
            SECTION_ALLOCS.with(|c| c.set(c.get() + 1));
            SECTION_BYTES.with(|b| b.set(b.get() + layout.size()));
        }
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if GUARD_DEPTH.with(|d| d.get()) > 0 {
            SECTION_ALLOCS.with(|c| c.set(c.get() + 1));
            SECTION_BYTES.with(|b| b.set(b.get() + new_size));
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// 包裹一段代码，观测其堆分配次数。drop 后守卫解除。
pub struct NoAllocGuard;

impl NoAllocGuard {
    pub fn new() -> Self {
        GUARD_DEPTH.with(|d| d.set(d.get() + 1));
        SECTION_ALLOCS.with(|c| c.set(0));
        SECTION_BYTES.with(|b| b.set(0));
        NoAllocGuard
    }
}

impl Default for NoAllocGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NoAllocGuard {
    fn drop(&mut self) {
        GUARD_DEPTH.with(|d| d.set(d.get() - 1));
    }
}

/// 当前守卫段内发生的堆分配次数。
pub fn section_allocs() -> usize {
    SECTION_ALLOCS.with(|c| c.get())
}

/// 当前守卫段内累计分配字节数（≥ 峰值驻留；B7 用保守上界）。
pub fn section_alloc_bytes() -> usize {
    SECTION_BYTES.with(|b| b.get())
}
