//! 跨平台进程 RSS（驻留内存）探针——B12 稳态 RSS 基线（TECH_SPEC §8.2）。
//!
//! 实现：
//! - Linux：读 `/proc/self/status` 的 `VmRSS` 行（内核报告的已驻留页，单位 kB）。
//! - Windows：`GetProcessMemoryInfo`（psapi）的 `WorkingSetSize`（进程工作集 = 驻留物理页）。
//! - 其余平台 `compile_error`（B12 只定义在 Linux/Windows：CI 跑 Linux、参考机跑 Windows）。

/// 当前进程 RSS（字节）。进程级口径：包含 gate 二进制自身 + 已构造的聚合器状态，
/// 同一次运行内多次采样取峰值即"稳态驻留足迹"（工作集由 OS 管理，不瞬时回落）。
pub fn current_rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        use std::io::BufRead;
        let f = std::fs::File::open("/proc/self/status").expect("open /proc/self/status");
        for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
            // 形如 "VmRSS:    123456 kB"
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb = rest.trim().trim_end_matches("kB").trim();
                return kb.parse::<u64>().expect("parse VmRSS kB") * 1024;
            }
        }
        panic!("VmRSS 行未在 /proc/self/status 中找到");
    }

    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        // `GetCurrentProcess` 返回伪句柄（-1，代表"本进程"），无需 CloseHandle。
        let process: HANDLE = unsafe { GetCurrentProcess() };
        let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            GetProcessMemoryInfo(
                process,
                &mut pmc,
                std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            )
        };
        assert_ne!(ok, 0, "GetProcessMemoryInfo 失败");
        pmc.WorkingSetSize as u64
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        compile_error!("B12 RSS 探针只支持 Linux / Windows");
    }
}

#[cfg(test)]
mod tests {
    /// 冒烟：当前平台探针能读到非零 RSS（Windows psapi / Linux /proc 均要跑通）。
    #[test]
    fn current_rss_bytes_is_positive() {
        assert!(super::current_rss_bytes() > 0);
    }
}
