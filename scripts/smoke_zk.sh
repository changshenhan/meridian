#!/usr/bin/env bash
# TEMPORARY —— S-05 管线冒烟（CI 专用脚手架）。
# 链路：smoke-gen 生成确定性签名 → nargo compile/execute → bb write_vk/prove →
#       bb verify → 公共输入回读（smoke_readback.py）→ 负向篡改测试。
# 验证完成后删除；不进 SPEC / 文档（仅 circuits/README.md 一行 TEMPORARY 备注）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SMOKE="$ROOT/circuits/smoke"

echo "[smoke] 1/5 generate deterministic signature -> Prover.toml"
cargo run --release --manifest-path "$ROOT/circuits/smoke-gen/Cargo.toml" -- "$SMOKE/Prover.toml"

echo "[smoke] 2/5 nargo compile + execute (ACIR + witness)"
( cd "$SMOKE" && nargo compile && nargo execute )

echo "[smoke] 3/5 bb write_vk + prove"
( cd "$SMOKE" && bb write_vk -b target/smoke.json -o target )
( cd "$SMOKE" && bb prove -b target/smoke.json -w target/smoke.gz -o target )

echo "[smoke] 4/5 bb verify"
( cd "$SMOKE" && bb verify -p target/proof -k target/vk )

echo "[smoke] 5/5 public-input readback"
python3 "$ROOT/scripts/smoke_readback.py" "$SMOKE"

echo "[smoke] negative: tampered public input must fail execution"
cp "$SMOKE/Prover.toml" /tmp/smoke_prover_ok.toml
( cd "$SMOKE" && sed -i 's/^message = .*/message = 59/' Prover.toml )
if ( cd "$SMOKE" && nargo execute ); then
  echo "NEGATIVE FAILED: tampered public input still solved" >&2
  cp /tmp/smoke_prover_ok.toml "$SMOKE/Prover.toml"
  exit 1
fi
cp /tmp/smoke_prover_ok.toml "$SMOKE/Prover.toml"
echo "[smoke] negative OK: tampered public input rejected"
echo "[smoke] pipeline OK"
