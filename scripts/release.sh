#!/usr/bin/env bash
#
# Mist v0.1 release 工装（S-14c）。
#
# 目标：让 v0.1 发布是"一条命令"的机械动作，且完全可复现。
# 边界：仓库**暂不公开**（S-08e 续，任务 #24，用户已拍板）——本脚本默认只做**本地可复现
# 产物** + 打印延迟发布的检查清单；`--publish` 之前不会触网。
#
# 用法：
#   scripts/release.sh                # 全量门禁 → release 构建 → dist 装配 + sha256 → 检查清单
#   scripts/release.sh --tag          # 额外打注解 tag v0.1.0（本地）
#   scripts/release.sh --publish      # ⛔ 仅限任务 #24 解除后手动执行：真发布（见检查清单）
#
# 退出码：0 = 产物就绪；1 = 门禁失败或构建失败（拒绝装配）；2 = 用法错误。
#
# 产物：target/release-dist/mist-v0.1.0/<组件> + SHA256SUMS + VERSION + manifest.json
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

VERSION="$(grep -m1 '^version' Cargo.toml | sed 's/version *= *"\(.*\)"/\1/')"
[ -n "$VERSION" ] || { echo "无法从 Cargo.toml 读版本"; exit 2; }

PUBLISH=0
TAG=0
for a in "$@"; do
    case "$a" in
        --publish) PUBLISH=1 ;;
        --tag) TAG=1 ;;
        *) echo "未知参数: $a（支持 --tag / --publish）"; exit 2 ;;
    esac
done

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
pass() { printf '    \033[1;32m[PASS]\033[0m %s\n' "$*"; }

if [ "$PUBLISH" -eq 1 ]; then
    echo "⛔ --publish 仅限任务 #24（仓库公开）解除后执行。当前仍处于'暂不公开'。"
    exit 2
fi

step "1/4 全量门禁（verify.sh，失败即拒绝装配）"
if ! bash scripts/verify.sh; then
    echo "✗ 门禁失败 —— 中止 release 装配"
    exit 1
fi
pass "verify.sh 全绿"

step "2/4 release 构建（workspace + mcp + M1 demo）"
cargo build --workspace --release
cargo build -p mist-mcp --release
cargo build --release --manifest-path contracts/rust-smoke/Cargo.toml --bin m1_demo
pass "release 构建完成"

DIST="target/release-dist/mist-v${VERSION}"
rm -rf "$DIST"; mkdir -p "$DIST"

step "3/4 装配 dist 产物 + SHA256SUMS"
# 可分发组件：MCP 服务器（主交付物）+ M1 端到端 demo（验收见证）+ rust-smoke 场景集。
# 哈希在装配时计算 → 每次构建的 SHA256SUMS 不同（正常：二进制含构建路径/时间戳；
# 源码签名的可复现性由 git tag + verify.sh 全门禁保证）。
BINS=(
    "target/release/mist-mcp.exe::mist-mcp.exe"
    "contracts/rust-smoke/target/release/m1_demo.exe::m1_demo.exe"
    "contracts/rust-smoke/target/release/contract-smoke.exe::contract-smoke.exe"
)
COPIED=0
for entry in "${BINS[@]}"; do
    src="${entry%%::*}"; dst="${entry##*::}"
    if [ -f "$src" ]; then cp "$src" "$DIST/$dst"; COPIED=$((COPIED+1)); fi
done
# 文档 + 演示脚本 + 集成 README
cp -r docs "$DIST/docs"
cp demos/langchain_demo.py demos/autogen_demo.py demos/mist_demo_common.py "$DIST/" 2>/dev/null || true
cp mcp-server/README.md sdk/README.md "$DIST/" 2>/dev/null || true
echo "$VERSION" > "$DIST/VERSION"
git rev-parse HEAD > "$DIST/COMMIT"
(cd "$DIST" && find . -type f | sort | xargs sha256sum > SHA256SUMS)
pass "装配完成（$COPIED 个二进制 + 文档 + 演示）"

step "4/4 版本与发布检查清单"
git describe --tags --always 2>/dev/null || echo "（无 tag）"
if [ "$TAG" -eq 1 ]; then
    git tag -a "v${VERSION}" -m "Mist v${VERSION}（本地，待公开后推送）"
    pass "本地 tag v${VERSION}"
fi

cat <<EOF

══════════════════════════════════════════════════════════════
  v0.1 延迟发布检查清单（任务 #24 解除后执行）
══════════════════════════════════════════════════════════════
  1. 安全复核：scripts/secret_scan（若存在）+ 全仓 secrets grep
  2. 代码签名：发布二进制签名（Windows Authenticode / macOS notarize）
  3. 公开 tag：git push origin v${VERSION}
  4. GitHub Release：上传 target/release-dist/mist-v${VERSION}/ 全部产物
  5. crates.io（如发布）：cargo publish -p mist-core / -p mist-sdk（先 dry-run）
  6. 文档站部署：docs/developers/ 对外发布
  7. 立场复核：WHITEPAPER 引用 PoC 实测数字与最终仓库一致
══════════════════════════════════════════════════════════════
  产物就绪：$(cd "$DIST" && cygpath -w "$PWD" 2>/dev/null || pwd)
EOF
pass "release 工装完成（v${VERSION} 本地产物，未触网）"
