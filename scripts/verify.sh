#!/usr/bin/env bash
#
# meridian 本地验证流水线（S-10d 门禁）。
#
# 背景：GitHub 私有仓库 Actions 于 2026-08-17 起被账户计费阻断（账户 included 额度
# $12 被 ANAI 私有 repo 用尽 93.5% + 无 spending limit → 全账户私有 CI 硬停）。meridian
# 的验证门禁因此改为本地执行——跑在记录 baseline.json 的同一台参考机上，比共享 runner
# （±10% 噪声）更稳，且零 GitHub 计费分钟。
#
# 用法：
#   scripts/verify.sh            # 全量门禁（本脚本即主门禁，pre-push 钩子调用）
#
# 退出码：0 = 全绿（可推送）；1 = 存在失败项（pre-push 拒绝推送）。
# 跳过单个阶段：GATE_SKIP="perf" scripts/verify.sh（perf|alloc|det 逗号分隔）。
#
# 诚实边界：
#   - gate 阈值 15%（--fail-over 15）抓灾难性回归，对齐原 CI 注释口径；1% 精准基线
#     （TECH_SPEC §8.3）留在受控参考机手动执行（--record / --fail-over 1）。
#   - forge（solidity job）与 nargo/bb（noir/ZK job）需要 Linux 工具链。本机未装时
#     打印 [SKIP] 并继续——Rust workspace（核心交付物）不因缺失外围工具而被挡。
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

FAIL=0
SKIP_SET="${GATE_SKIP:-}"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
pass() { printf '    \033[1;32m[PASS]\033[0m %s\n' "$*"; }
fail() { printf '    \033[1;31m[FAIL]\033[0m %s\n' "$*"; FAIL=1; }
skip() { printf '    \033[1;33m[SKIP]\033[0m %s\n' "$*"; }

want() { # want <tag>  -> 0 if should run
    case ",$SKIP_SET," in *",$1,"*) return 1 ;; *) return 0 ;; esac
}

run() { # run <label> <cmd...>
    local label="$1"; shift
    if "$@"; then pass "$label"; else fail "$label"; fi
}

if want fmt; then
    step "1/10 cargo fmt --all --check"
    run "fmt" cargo fmt --all --check
else
    skip "fmt"
fi

if want clippy; then
    step "2/10 cargo clippy (-D warnings, all targets)"
    run "clippy" cargo clippy --workspace --all-targets -- -D warnings
else
    skip "clippy"
fi

if want test; then
    step "3/10 cargo test (workspace)"
    run "test" cargo test --workspace
else
    skip "test"
fi

if want bench; then
    step "4/10 bench 编译检查 (--no-run)"
    run "bench compile" cargo bench -p meridian-bench --no-run
else
    skip "bench"
fi

# S-15 生产化：meridian-monitor 二进制构建 + `--once` 健康烟测（空 WAL → ok → exit 0）。
# Rust 主门禁的一部分（不跳过）：监控是部署面第一道可观测探针，编译坏了等于运维盲区。
# WAL 用 mktemp 唯一名（不删旧重建同一路径）。注意：ROOT 是普通 shell 变量，**不 export**，
# 不能在嵌套 `bash -c '...'` 里引用（为空 → WAL 路径解析到 Windows 根 → os error 3）。
# 因此在外部 shell 算好 WAL 路径再直接传参，无需嵌套 bash。
if want monitor; then
    step "5/10 meridian-monitor 构建 + --once 健康烟测 (S-15b)"
    run "monitor build" cargo build -p meridian-monitor --bin meridian-monitor
    W="$(mktemp -u "$ROOT/target/monitor-smoke-XXXXXX.wal")"
    run "monitor --once" cargo run -q -p meridian-monitor --bin meridian-monitor -- --wal "$W" --once
else
    skip "monitor"
fi

if want perf; then
    step "6/10 性能门禁 (release, --fail-over 15 抓灾难性回归)"
    # 混合架构坑（2026-08-30 实测，i9-14900HX 8P+16E）：后台/headless 会话跑本脚本会被
    # Windows 11 调度到 E-core（EcoQoS）——整数型指标假回归 -60~70%（SHA-NI 硬件加速类
    # 不受影响，易误判成"代码回归"）。clocks/亲和性/内存均正常，唯有钉 P-core 线程
    # （0-15）后回到基线 ±10%。规避：从前台交互 shell 跑，或把进程树亲和性钉 0-15。
    run "perf gate" cargo run --release -p meridian-bench --bin gate -- --fail-over 15
else
    skip "perf"
fi

if want alloc || want det; then
    step "7/10 agg_sim 回归 (B8 热路径零分配 + B11 确定性)"
    if want alloc; then
        run "agg_sim B8 zero-alloc" cargo run --release -p meridian-bench --bin agg_sim -- --check-alloc
    else
        skip "agg_sim B8 zero-alloc"
    fi
    if want det; then
        run "agg_sim B11 determinism" cargo run --release -p meridian-bench --bin agg_sim -- --check-determinism
    else
        skip "agg_sim B11 determinism"
    fi
else
    skip "agg_sim"
fi

# 可选外围——缺失不阻塞 Rust 主门禁。工具不在 PATH 时兜底查标准安装位置
# （foundryup → ~/.foundry/bin；noirup → ~/.nargo/bin；bbup → ~/.bb）。
if command -v forge >/dev/null 2>&1 || [ -x "$HOME/.foundry/bin/forge" ]; then
    step "8/10 solidity (forge build + test)"
    run "forge build+test" bash -c 'export PATH="$HOME/.foundry/bin:$PATH"; cd contracts && forge build && forge test'
else
    skip "forge 未找到 → solidity 门禁跳过"
fi

if { command -v nargo >/dev/null 2>&1 || [ -x "$HOME/.nargo/bin/nargo" ]; } \
   && { command -v bb >/dev/null 2>&1 || [ -x "$HOME/.bb/bb" ]; }; then
    step "9/10 ZK (smoke_zk + formal_zk)"
    run "zk smoke" bash -c 'export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"; bash scripts/smoke_zk.sh'
    run "zk formal" bash -c 'export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"; bash scripts/formal_zk.sh'
else
    skip "nargo/bb 未找到 → ZK 门禁跳过（需 Linux；可借 neuralzoo Linux 服务器或 WSL）"
fi

# S-11d + S-14：Anvil 端到端（聚合器 + BatchSettler v2 全链路 + M1 里程碑 demo）。依赖 forge
# build 产物（上一步 7/9 已生成）+ anvil 可执行；两者缺一即跳过（不阻塞 Rust 主门禁）。
# m1_demo 用 release（100k 笔 debug 下 ~9min，release ~4s）；rust-smoke 场景小，debug 够。
if { command -v forge >/dev/null 2>&1 || [ -x "$HOME/.foundry/bin/forge" ]; } \
   && { command -v anvil >/dev/null 2>&1 || [ -x "$HOME/.foundry/bin/anvil" ]; }; then
    step "10/10 rust-smoke Anvil 端到端 (S-11d) + M1 里程碑 demo (S-14a) + 部署脚本编译 (S-15a)"
    # S-15a：deployer 编译门禁（alloy 依赖回归照妖镜；dry-run/--live 均不在此跑）。
    run "deployer compile" bash -c 'cd contracts/rust-smoke && cargo build --bin deploy'
    run "rust-smoke" bash -c 'export PATH="$HOME/.foundry/bin:$PATH"; cd contracts/rust-smoke && cargo run'
    run "m1_demo" bash -c 'export PATH="$HOME/.foundry/bin:$PATH"; cd contracts/rust-smoke && cargo run --release --bin m1_demo'
else
    skip "forge/anvil 未找到 → rust-smoke 门禁跳过"
fi

printf '\n'
if [ "$FAIL" -eq 0 ]; then
    printf '\033[1;32m✓ 本地门禁全部通过 —— 可以推送\033[0m\n'
    exit 0
else
    printf '\033[1;31m✗ 存在失败项 —— 拒绝推送（见上方 [FAIL]）\033[0m\n'
    exit 1
fi
