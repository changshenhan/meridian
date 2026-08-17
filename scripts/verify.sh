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
    step "1/6 cargo fmt --all --check"
    run "fmt" cargo fmt --all --check
else
    skip "fmt"
fi

if want clippy; then
    step "2/6 cargo clippy (-D warnings, all targets)"
    run "clippy" cargo clippy --workspace --all-targets -- -D warnings
else
    skip "clippy"
fi

if want test; then
    step "3/6 cargo test (workspace)"
    run "test" cargo test --workspace
else
    skip "test"
fi

if want bench; then
    step "4/6 bench 编译检查 (--no-run)"
    run "bench compile" cargo bench -p meridian-bench --no-run
else
    skip "bench"
fi

if want perf; then
    step "5/6 性能门禁 (release, --fail-over 15 抓灾难性回归)"
    run "perf gate" cargo run --release -p meridian-bench --bin gate -- --fail-over 15
else
    skip "perf"
fi

if want alloc || want det; then
    step "6/6 agg_sim 回归 (B8 热路径零分配 + B11 确定性)"
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
    step "7/8 solidity (forge build + test)"
    run "forge build+test" bash -c 'export PATH="$HOME/.foundry/bin:$PATH"; cd contracts && forge build && forge test'
else
    skip "forge 未找到 → solidity 门禁跳过"
fi

if { command -v nargo >/dev/null 2>&1 || [ -x "$HOME/.nargo/bin/nargo" ]; } \
   && { command -v bb >/dev/null 2>&1 || [ -x "$HOME/.bb/bb" ]; }; then
    step "8/8 ZK (smoke_zk + formal_zk)"
    run "zk smoke" bash -c 'export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"; bash scripts/smoke_zk.sh'
    run "zk formal" bash -c 'export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"; bash scripts/formal_zk.sh'
else
    skip "nargo/bb 未找到 → ZK 门禁跳过（需 Linux；可借 neuralzoo Linux 服务器或 WSL）"
fi

printf '\n'
if [ "$FAIL" -eq 0 ]; then
    printf '\033[1;32m✓ 本地门禁全部通过 —— 可以推送\033[0m\n'
    exit 0
else
    printf '\033[1;31m✗ 存在失败项 —— 拒绝推送（见上方 [FAIL]）\033[0m\n'
    exit 1
fi
