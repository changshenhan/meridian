#!/usr/bin/env bash
# WSL Ubuntu 引导脚本(重启后执行)——幂等
# 调用: wsl -d MeridianUbuntu -u root bash /mnt/c/.../scripts/wsl-bootstrap.sh
# 职责: 装 nargo v1.0.0-beta.26 + bb 6.0.0-nightly.20260724(与 circuits/README 配对一致)
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"

echo "=== [1/3] apt 基础依赖 ==="
apt-get update -y
apt-get install -y --no-install-recommends curl git python3 jq build-essential

echo "=== [2/3] nargo v1.0.0-beta.26 (noirup) ==="
if ! command -v nargo >/dev/null 2>&1; then
  curl -sL https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
  export PATH="$HOME/.nargo/bin:$PATH"
fi
noirup --version 1.0.0-beta.26
nargo --version

echo "=== [3/3] bb 6.0.0-nightly.20260724 (bbup, aztec-packages 通道) ==="
if ! command -v bb >/dev/null 2>&1; then
  curl -sL https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
  export PATH="$HOME/.bb:$PATH"
fi
bbup --version 6.0.0-nightly.20260724
bb --version

echo "=== 完成: nargo + bb 就绪 ==="
echo "nargo=$(nargo --version) bb=$(bb --version)"
