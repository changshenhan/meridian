#!/usr/bin/env bash
#
# mist 本地验证流水线（S-10d 门禁）。
#
# 背景：GitHub Actions 曾于 2026-08-17 起被账户计费阻断（账户 included 额度被私有
# repo 用尽 + 无 spending limit → 全账户私有 CI 硬停），mist 的验证门禁因此改为
# 本地执行——跑在记录 baseline.json 的同一台参考机上，比共享 runner（±10% 噪声）
# 更稳，且零 GitHub 计费分钟。2026-08-30 起 Actions 恢复可用，ci/noir/solidity 三
# job 作为 push 后第二道网继续盯绿（本地门禁仍是主门禁）。
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
#   - forge（solidity job）需要 Linux 工具链，本机未装时打印 [SKIP] 并继续。
#   - ZK（noir job）自 S-37 起有 WSL2 兜底（默认发行版 MeridianUbuntu）：Windows 侧
#     找不到 nargo/bb 时自动借 wsl.exe 跑同一对脚本，ZK 门禁真正进入本地 pre-push；
#     Windows 与 WSL 皆无工具链时才 [SKIP]。
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
    run "bench compile" cargo bench -p mist-bench --no-run
else
    skip "bench"
fi

# S-15 生产化：mist-monitor 二进制构建 + `--once` 健康烟测（空 WAL → ok → exit 0）。
# Rust 主门禁的一部分（不跳过）：监控是部署面第一道可观测探针，编译坏了等于运维盲区。
# WAL 用 mktemp 唯一名（不删旧重建同一路径）。注意：ROOT 是普通 shell 变量，**不 export**，
# 不能在嵌套 `bash -c '...'` 里引用（为空 → WAL 路径解析到 Windows 根 → os error 3）。
# 因此在外部 shell 算好 WAL 路径再直接传参，无需嵌套 bash。
if want monitor; then
    step "5/10 mist-monitor 构建 + --once 健康烟测 (S-15b)"
    run "monitor build" cargo build -p mist-monitor --bin mist-monitor
    W="$(mktemp -u "$ROOT/target/monitor-smoke-XXXXXX.wal")"
    run "monitor --once" cargo run -q -p mist-monitor --bin mist-monitor -- --wal "$W" --once
    # S-39 多副本集群烟测：两个空 WAL 副本 → 集群收敛 ok → exit 0（覆盖集群 CLI/渲染路径）。
    W1="$(mktemp -u "$ROOT/target/monitor-smoke-XXXXXX.wal")"
    W2="$(mktemp -u "$ROOT/target/monitor-smoke-XXXXXX.wal")"
    run "monitor cluster --once" cargo run -q -p mist-monitor --bin mist-monitor -- --wal "$W1" --wal "$W2" --once
else
    skip "monitor"
fi

if want perf; then
    step "6/10 性能门禁 (release, --fail-over 15 抓灾难性回归)"
    # 混合架构坑（2026-08-30 实测，i9-14900HX 8P+16E）：后台/headless 会话跑本脚本会被
    # Windows 11 调度到 E-core（EcoQoS）——整数型指标假回归 -60~70%（SHA-NI 硬件加速类
    # 不受影响，易误判成"代码回归"）。clocks/亲和性/内存均正常，唯有钉 P-core 线程
    # （0-15）后回到基线 ±10%。规避：从前台交互 shell 跑，或把进程树亲和性钉 0-15。
    run "perf gate" cargo run --release -p mist-bench --bin gate -- --fail-over 15
else
    skip "perf"
fi

if want alloc || want det; then
    step "7/10 agg_sim 回归 (B8 热路径零分配 + B11 确定性)"
    if want alloc; then
        run "agg_sim B8 zero-alloc" cargo run --release -p mist-bench --bin agg_sim -- --check-alloc
    else
        skip "agg_sim B8 zero-alloc"
    fi
    if want det; then
        run "agg_sim B11 determinism" cargo run --release -p mist-bench --bin agg_sim -- --check-determinism
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

    # S-57：跨实现差分 fuzz（TECH_SPEC §8.3，审计四步路径 ③）。重生成 fixture 到
    # target/ 与入库版本 cmp（漂移闸——改任一侧规范不回填 fixture 即红）+ 差分测试。
    # 写 target/ 不碰工作树；forge 侧 8/10 已跑 DifferentialTest（fixture 入库版），
    # 这里只对漂移负责。
    step "8b/10 跨实现差分 fuzz (S-57, Rust 生产实现 -> golden fixture -> forge 镜像)"
    run "difffuzz regen" bash -c "cd contracts/rust-smoke && cargo run --quiet --bin difffuzz -- --out '$ROOT/target/differential.json'"
    if cmp -s "$ROOT/target/differential.json" "$ROOT/contracts/test/fixtures/differential.json"; then
        pass "difffuzz golden 无漂移（重生成 == 入库 fixture）"
    else
        fail "difffuzz golden 漂移：contracts/test/fixtures/differential.json 与重生成不一致（改了规范或种子未回填 fixture）"
    fi

    # S-58（TECH_SPEC §8.3，审计四步路径 ④）：分支覆盖门禁。src 全合约行/函数 100%、
    # 分支 100%（BatchSettler 豁免 1 条结构不可达边：押金销毁 require 失败边）。阈值
    # 与豁免口径都在 scripts/coverage_gate.sh 文件头，缺口=补负向测试不是调阈值。
    step "8c/10 分支覆盖门禁 (S-58, forge coverage lcov)"
    run "coverage gate" bash "$ROOT/scripts/coverage_gate.sh"
else
    skip "forge 未找到 → solidity 门禁跳过"
fi

# S-37：第 9 步 ZK 门禁三层探测。① Windows 原生 nargo/bb（历史路径，实际不可得——
# nargo 1.0.0-beta.26 无法在 Windows 构建）；② WSL2 兜底（默认发行版 MeridianUbuntu、
# root 用户，工具在 /root/.nargo/bin 与 /root/.bb，MIST_WSL_DISTRO 可覆盖）；
# ③ 皆无才 SKIP。ZK 门禁由此真正进入本地 pre-push（电路回归不再只靠 CI 兜底）。
# 配套：跑前把 gen-witness/Prover.toml 备份到 target/，跑后还原——nargo
# `--overwrite-return` 会追加/改写 return 键（不进版本库），pre-push 不再污染工作树，
# 开发者手工改动也原样保留（见 TECH_SPEC §8.3）。
zk_wsl_ready() { # zk_wsl_ready <distro>  -> 0 = WSL 兜底可用
    command -v wsl.exe >/dev/null 2>&1 || return 1
    case "$ROOT" in [A-Za-z]:/*) ;; *) return 1 ;; esac
    wsl.exe -d "$1" -u root -e bash -lc \
        'export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"; command -v nargo >/dev/null 2>&1 && command -v bb >/dev/null 2>&1' \
        >/dev/null 2>&1
}

if [ -f "$ROOT/gen-witness/Prover.toml" ]; then
    cp "$ROOT/gen-witness/Prover.toml" "$ROOT/target/Prover.toml.pregate"
fi

if { command -v nargo >/dev/null 2>&1 || [ -x "$HOME/.nargo/bin/nargo" ]; } \
   && { command -v bb >/dev/null 2>&1 || [ -x "$HOME/.bb/bb" ]; }; then
    step "9/10 ZK (smoke_zk + formal_zk, Windows 原生)"
    run "zk smoke" bash -c 'export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"; bash scripts/smoke_zk.sh'
    run "zk formal" bash -c 'export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"; bash scripts/formal_zk.sh'
else
    WSL_DISTRO="${MIST_WSL_DISTRO:-MeridianUbuntu}"
    if zk_wsl_ready "$WSL_DISTRO"; then
        step "9/10 ZK (smoke_zk + formal_zk, WSL2 兜底 S-37: $WSL_DISTRO)"
        WSL_ROOT="/mnt/$(printf '%s' "${ROOT:0:1}" | tr 'A-Z' 'a-z')${ROOT:2}"
        run "zk smoke" wsl.exe -d "$WSL_DISTRO" -u root -e bash -lc \
            "export PATH=\"\$HOME/.nargo/bin:\$HOME/.bb:\$PATH\"; cd '$WSL_ROOT' && bash scripts/smoke_zk.sh"
        run "zk formal" wsl.exe -d "$WSL_DISTRO" -u root -e bash -lc \
            "export PATH=\"\$HOME/.nargo/bin:\$HOME/.bb:\$PATH\"; cd '$WSL_ROOT' && bash scripts/formal_zk.sh"
    else
        skip "nargo/bb 未找到（Windows 与 WSL 发行版 $WSL_DISTRO 皆无）→ ZK 门禁跳过（MIST_WSL_DISTRO 可覆盖发行版）"
    fi
fi

# S-40：bb 后端 e2e（真 ZK 验证通路，TECH_SPEC §6.13）。纯 Rust 侧进程调 bb——Windows
# 侧跑（cargo 在 Windows），bb 本体由后端解析走原生/WSL 兜底。工件依赖第 9 步刚产出的
# proof/vk（新鲜且与 VK 配对）；工件缺失（第 9 步被跳过）则同口径跳过。
if [ -f "$ROOT/circuits/target/proof" ] && [ -f "$ROOT/circuits/target/vk" ]; then
    step "9b/10 bb-verify e2e (S-40, 真证明正/负向)"
    run "bb-verify e2e" env MIST_BB_E2E=1 cargo test -p mist-aggregator --test bb_verify_e2e
else
    step "9b/10 bb-verify e2e (S-40)"
    skip "circuits/target/{proof,vk} 不存在（第 9 步 ZK 被跳过）→ bb-verify e2e 跳过"
fi

# S-43：真 prover e2e（TECH_SPEC §6.14，prove 侧 TEMPORARY 缝收口）。SDK 委托/意图 +
# 聚合器撤销集非成员 witness（S-42）→ NoirProver 真电路证明 → BbVerifier 密码学接受。
# 依赖第 9 步刚产出的 circuits/target/{spend_authorization.json,vk}（bb 字节码 + VK）；
# 缺失（第 9 步被跳过）则同口径跳过。MIST_ZK_PROVER_E2E 门控测试本体。
if [ -f "$ROOT/circuits/target/spend_authorization.json" ] && [ -f "$ROOT/circuits/target/vk" ]; then
    step "9c/10 noir-prover e2e (S-43, 真证明全链正/负向)"
    run "noir-prover e2e" env MIST_ZK_PROVER_E2E=1 cargo test -p mist-sdk --test noir_prover_e2e
else
    step "9c/10 noir-prover e2e (S-43)"
    skip "circuits/target/{spend_authorization.json,vk} 不存在（第 9 步 ZK 被跳过）→ noir-prover e2e 跳过"
fi

# S-47：桥接真 prover e2e（TECH_SPEC §6.10 第 4 步 / §6.14 CLI 消费）。facilitator
# EIP-3009 桥经 BridgeConfig.noir（SdkClient::with_noir）在真 BbVerifier 网关上摄取；
# 占位桥对照组 402（bb 全拒占位证明）。工件依赖 9c 同款；MIST_ZK_PROVER_E2E 门控
# 测试本体（同门同工件，过滤器只选 noir 桥用例，不重跑全量 facilitator e2e）。
if [ -f "$ROOT/circuits/target/spend_authorization.json" ] && [ -f "$ROOT/circuits/target/vk" ]; then
    step "9d/10 bridge noir-prover e2e (S-47, with_noir CLI 消费)"
    run "bridge noir-prover e2e" env MIST_ZK_PROVER_E2E=1 cargo test -p mist-facilitator --test facilitator e2e_bridge_with_noir_prover
else
    step "9d/10 bridge noir-prover e2e (S-47)"
    skip "circuits/target/{spend_authorization.json,vk} 不存在（第 9 步 ZK 被跳过）→ bridge noir-prover e2e 跳过"
fi

# S-51：demo 层真 ZK 装配示例（TECH_SPEC §6.15）。with_noir 装配 → 真电路证明 →
# BbVerifier + 撤销根绑定闸 → BatchSettler Anvil 净额结算（撤销根三方同源断言）。
# 依赖第 9 步刚产出的 circuits/target/{spend_authorization.json,vk} + 步 8/10 同款
# anvil 工具链；缺任一即同口径跳过。CI 不跑（noir job 无 anvil、solidity job 无
# nargo/bb，§6.15 诚实边界——同 m1_demo 的 CI 口径）。
if [ -f "$ROOT/circuits/target/spend_authorization.json" ] && [ -f "$ROOT/circuits/target/vk" ] \
   && { command -v anvil >/dev/null 2>&1 || [ -x "$HOME/.foundry/bin/anvil" ]; }; then
    step "9e/10 demo 层真 ZK 装配示例 (S-51, with_noir × BbVerifier × BatchSettler)"
    run "noir demo e2e" bash -c 'export PATH="$HOME/.foundry/bin:$PATH"; cd contracts/rust-smoke && MIST_NOIR_DEMO=1 cargo run --quiet --bin noir_demo'
else
    step "9e/10 demo 层真 ZK 装配示例 (S-51)"
    skip "circuits 工件 / anvil 不可得 → demo 层真 ZK 示例跳过"
fi

if [ -f "$ROOT/target/Prover.toml.pregate" ] && ! cmp -s "$ROOT/target/Prover.toml.pregate" "$ROOT/gen-witness/Prover.toml"; then
    cp "$ROOT/target/Prover.toml.pregate" "$ROOT/gen-witness/Prover.toml"
    printf '    \033[1;33m[CLEAN]\033[0m gen-witness/Prover.toml 已还原（nargo --overwrite-return 改写，return 键不进版本库）\n'
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
    # P2-1 验证者挑战演练（TECH_SPEC §6.18）：镜像复算检出 commit≠settle → 欺诈证明 →
    # challenge 全链（三幕：诚实静默 / kind1 漏单 / kind2 低付）。零合约改动，debug 够。
    run "verifier_drill" bash -c 'export PATH="$HOME/.foundry/bin:$PATH"; cd contracts/rust-smoke && cargo run --quiet --bin verifier_drill'
    # P2-4 多运营者多实例部署流程演练（TECH_SPEC §6.21.3）：append-only 调度 ×2 代 →
    # 两 BatchSettler 实例各持其部署版本 → 名册 self-registration 快照 → 负向组 6 例全拒。
    run "registry_flow" bash -c 'export PATH="$HOME/.foundry/bin:$PATH"; cd contracts/rust-smoke && cargo run --quiet --bin registry_flow'
    # S-76：对外框架 demo 真链 settle 完整化（TECH_SPEC §6.16）。三件套——mcp_probe
    # （Rust 侧 MCP stdio 客户端参考实现）走真协议驱动 mist-mcp 产真 WAL → demo_settle
    # 消费真 WAL 真链结算（快照侧车：拷贝后操作副本，原 WAL 不回写，幂等）。WAL 目录
    # 用 target/ 一次性目录（框架 demo 用 demos/.wal 且自带启动清盘，门禁不碰工作树）。
    run "mist-mcp bins build (mist-mcp + mcp_probe)" cargo build -p mist-mcp --bins
    PROBE_WAL_DIR="$ROOT/target/mcp-probe-smoke"
    rm -rf "$PROBE_WAL_DIR"
    run "mcp_probe 冒烟 (真 stdio 协议产真 WAL)" bash -c "cargo run -q -p mist-mcp --bin mcp_probe -- '$PROBE_WAL_DIR'"
    run "demo_settle 真链结算 (probe WAL -> commit/settle/claim)" bash -c "export PATH=\"\$HOME/.foundry/bin:\$PATH\"; cd contracts/rust-smoke && cargo run --quiet --bin demo_settle -- --wal '$PROBE_WAL_DIR/mist.wal'"
else
    skip "forge/anvil 未找到 → rust-smoke 门禁跳过"
fi

printf '\n'
# S-52：mcp-server 真 ZK e2e（TECH_SPEC §6.16，MCP 面证明直通）。客户端侧 NoirProver
# 真电路证明 → MCP pay 工具 → BbVerifier + 撤销根绑定闸聚合器密码学接受；对照组占位
# pay 必拒 E_PROOF。工件依赖 9c 同款；MIST_MCP_NOIR_E2E 门控测试本体。
if [ -f "$ROOT/circuits/target/spend_authorization.json" ] && [ -f "$ROOT/circuits/target/vk" ]; then
    step "9f/10 mcp-server noir-prover e2e (S-52, MCP 面证明直通)"
    run "mcp noir-prover e2e" env MIST_MCP_NOIR_E2E=1 cargo test -p mist-mcp --test mcp_noir_e2e
else
    step "9f/10 mcp-server noir-prover e2e (S-52)"
    skip "circuits/target/{spend_authorization.json,vk} 不存在（第 9 步 ZK 被跳过）→ mcp noir-prover e2e 跳过"
fi

if [ "$FAIL" -eq 0 ]; then
    printf '\033[1;32m✓ 本地门禁全部通过 —— 可以推送\033[0m\n'
    exit 0
else
    printf '\033[1;31m✗ 存在失败项 —— 拒绝推送（见上方 [FAIL]）\033[0m\n'
    exit 1
fi
