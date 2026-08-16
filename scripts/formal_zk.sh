#!/usr/bin/env bash
# S-09 正式电路 spend_authorization 端到端管线（CI）。链路：
#   gen-witness（Noir 内确定性 EdDSA 挑战 eddsa_challenge + 撤销稀疏树）→
#   build 脚本（Python 大整数算签名标量 s）→ circuits/Prover.toml →
#   nargo execute → bb write_vk/prove/verify → 公共输入回读(121) → 负向篡改 →
#   B2/B3/B4 计时基线 + 约束门禁 → bb write_solidity_verifier（EVM 验证器，Phase 4 复用）。
# 非 TEMPORARY：正式电路的回归 + 基准管线（区别于 smoke 的 S-05 冒烟脚手架）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"

echo "[formal] 1/8 gen-witness — fetch + compile + test + execute (--overwrite-return)"
(
  cd "$ROOT/gen-witness"
  nargo fetch
  nargo compile
  nargo test
  nargo execute --overwrite-return
)

echo "[formal] 2/8 build circuits/Prover.toml from gen-witness return"
python3 "$ROOT/scripts/formal_gen_to_prover.py" "$ROOT/gen-witness" "$ROOT/circuits"

echo "[formal] 3/8 spend_authorization — nargo execute (witness)"
( cd "$ROOT/circuits" && nargo execute )

echo "[formal] 4/8 bb write_vk + prove + verify"
# --verifier_target evm-no-zk：CLI 翻译成 oracle_hash=keccak + disable_zk=true，选中
# UltraKeccakFlavor。必须与 8/8 write_solidity_verifier 一致——bb 6.0.0-nightly 的
# CircuitWriteSolidityVerifier 硬编码 UltraKeccakFlavor::VerificationKey（1888B），
# 默认 poseidon2 的 UltraFlavor VK（3680B）对不上（CI run 31933941769 实测
# "expected 1888, got 3680"）。
( cd "$ROOT/circuits" && bb write_vk -t evm-no-zk -b target/spend_authorization.json -o target )
( cd "$ROOT/circuits" && bb prove -t evm-no-zk -b target/spend_authorization.json -w target/spend_authorization.gz -o target )
( cd "$ROOT/circuits" && bb verify -t evm-no-zk -p target/proof -k target/vk )

echo "[formal] 5/8 public-input readback (121 fields)"
python3 "$ROOT/scripts/formal_readback.py" "$ROOT/circuits"

echo "[formal] 6/8 negative: tampered spend_nonce must fail witness solving"
cp "$ROOT/circuits/Prover.toml" /tmp/formal_prover_ok.toml
( cd "$ROOT/circuits" && sed -i 's/^spend_nonce = .*/spend_nonce = "8"/' Prover.toml )
if ( cd "$ROOT/circuits" && nargo execute ); then
  echo "NEGATIVE FAILED: tampered spend_nonce still solved" >&2
  cp /tmp/formal_prover_ok.toml "$ROOT/circuits/Prover.toml"
  exit 1
fi
cp /tmp/formal_prover_ok.toml "$ROOT/circuits/Prover.toml"
( cd "$ROOT/circuits" && nargo execute )  # 恢复干净 witness 供 bench 复用
echo "[formal] negative OK"

echo "[formal] 7/8 B2/B3/B4 timing baseline + constraint gate"
python3 "$ROOT/scripts/formal_bench.py" "$ROOT/circuits"

echo "[formal] 8/8 EVM verifier (bb write_solidity_verifier, Phase 4 reuse)"
mkdir -p "$ROOT/circuits/artifacts"
( cd "$ROOT/circuits" && bb write_solidity_verifier -t evm-no-zk -k target/vk -o artifacts/UltraVerifier.sol )
ls -la "$ROOT/circuits/artifacts"
echo "[formal] pipeline OK"
