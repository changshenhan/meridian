#!/usr/bin/env bash
# S-58（2026-08-31，审计四步路径 ④，TECH_SPEC §8.3）：forge coverage 分支覆盖门禁。
#
# 跑 `forge coverage --report lcov`（在 contracts/），对 src/ 全部合约按阈值硬闸：
#   - 行覆盖 == 100%
#   - 函数覆盖 == 100%
#   - 分支覆盖 == 100%，唯一豁免 BatchSettler.sol 允许欠 BRANCH_DEFICIT=1 条——
#     向 address(0) 销毁挑战押金的 `require(okBurn, "bond burn failed")` 失败边
#     结构不可达（ETH 向无代码地址推送不可能失败，无测试可达路径），代码注释与
#     docs/audit/slither-2026-08-31.md 同步定性。
#
# 用法：scripts/coverage_gate.sh   （cwd 不限；内部 cd 到仓库 contracts/）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BRANCH_DEFICIT=1 # 仅 BatchSettler.sol：押金销毁 require 失败边结构不可达（见文件头）

if ! command -v forge >/dev/null 2>&1 && [ ! -x "$HOME/.foundry/bin/forge" ]; then
    echo "[coverage-gate] forge 未找到 —— 覆盖门禁跳过（上游 8/10 步同口径）"
    exit 2
fi
export PATH="$HOME/.foundry/bin:$PATH"

cd "$ROOT/contracts"

# --ir-minimum 是禁用项：它对 require/内部函数的行·分支归因整体漂移（S-58 实证：
# Merkle/IntentHelper 假性缺 5 条分支），宁可让 stack too deep 暴露测试侧栈问题
# （已在 _epochView/_epochViewOn 收口）也不出假数据。
forge coverage --report lcov >/dev/null

fail=0
# 逐 SF:src/ 记录检查 LF/LH、FNF/FNH、BRF/BRH。lcov 是单遍解析的简单格式，awk 足够。
awk -v deficit="$BRANCH_DEFICIT" '
    /^SF:/ {
        sf = substr($0, 4)
        if (sf ~ /^src\//) { lf=lh=brf=brh=fnf=fnh=0; insrc = 1 } else { insrc = 0 }
    }
    insrc && /^LF:/ { lf = substr($0, 4) }
    insrc && /^LH:/ { lh = substr($0, 4) }
    insrc && /^BRF:/ { brf = substr($0, 5) }
    insrc && /^BRH:/ { brh = substr($0, 5) }
    insrc && /^FNF:/ { fnf = substr($0, 5) }
    insrc && /^FNH:/ { fnh = substr($0, 5) }
    insrc && /^end_of_record/ {
        allowed = (sf ~ /BatchSettler\.sol$/) ? deficit : 0
        if (lh != lf) { printf "FAIL 行覆盖  %-22s %d/%d\n", sf, lh, lf; bad = 1 }
        if (fnh != fnf) { printf "FAIL 函数覆盖 %-22s %d/%d\n", sf, fnh, fnf; bad = 1 }
        if (brh + allowed < brf) {
            printf "FAIL 分支覆盖 %-22s %d/%d（豁免 %d 条）\n", sf, brh, brf, allowed
            bad = 1
        } else {
            printf "ok   %-22s 行 %d/%d  分支 %d/%d%s  函数 %d/%d\n", \
                sf, lh, lf, brh, brf, (allowed ? "-（豁免 1 条不可达边）" : ""), fnh, fnf
        }
    }
    END { exit bad }
' lcov.info || fail=1

rm -f lcov.info
if [ "$fail" -ne 0 ]; then
    echo "[coverage-gate] 红：缺口=可测负向缝隙（补测试），不是调阈值。唯一合法豁免见文件头。"
    exit 1
fi
echo "[coverage-gate] 绿：src 全合约行/函数 100%，分支 100%（BatchSettler 豁免 1 条不可达边）"
