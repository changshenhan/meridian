#!/usr/bin/env python3
"""S-09 正式管线：公共输入回读比对（spend_authorization，121 个公共 witness）。

main 公共参数顺序：agent_commit[32] ‖ delegation_hash[32] ‖ recipient[20] ‖
amount(u64→1) ‖ category[32] ‖ spend_nonce(1) ‖ expires_at(1) ‖
revocation_root(Field→1) ‖ now(1) = 121 个 field。

编码（v1.0.0-beta.26，noirc_evaluator::ssa::split_public_and_private_inputs）：
`pub [u8; 32]` → 每字节一个公共 witness，`pub u64` / `pub Field` → 一个 witness。
bb 的 public_inputs 每 field 为 32 字节**大端**（smoke_readback.py 已实测确认）。

比对策略：先按参数顺序严格比对（强：能发现字段间串位/错绑）；若 bb 按 witness 索引
顺序输出（旧 smoke 亦曾遇到），退化为多重集比对（仍校验 121 个值齐全），并打印顺序态。
字段级绑定由 nargo 正/负测试 + golden 向量 + formal_gen_to_prover 第三实现交叉校验兜底，
此处回读是端到端一致性检查。
"""
import sys
import tomllib
from pathlib import Path

FIELD = 32


def be(b: bytes) -> int:
    return int.from_bytes(b, "big")


def to_int(v):
    return v if isinstance(v, int) else int(str(v), 0)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: formal_readback.py <circuits_dir>", file=sys.stderr)
        return 2
    circ = Path(sys.argv[1])
    prover = tomllib.loads((circ / "Prover.toml").read_text(encoding="utf-8"))

    candidates = ["target/public_inputs", "target/proof_public_inputs"]
    pi_path = next((circ / c for c in candidates if (circ / c).exists()), None)
    if pi_path is None:
        print("ERROR: no public_inputs file found under target/", file=sys.stderr)
        return 1

    raw = pi_path.read_bytes()
    if len(raw) % FIELD != 0:
        print(f"ERROR: {pi_path} size {len(raw)} not a multiple of {FIELD}", file=sys.stderr)
        return 1
    actual = [be(raw[i:i + FIELD]) for i in range(0, len(raw), FIELD)]

    expected = (
        [to_int(x) for x in prover["agent_commit"]]
        + [to_int(x) for x in prover["delegation_hash"]]
        + [to_int(x) for x in prover["recipient"]]
        + [to_int(prover["amount"])]
        + [to_int(x) for x in prover["category"]]
        + [to_int(prover["spend_nonce"])]
        + [to_int(prover["expires_at"])]
        + [to_int(prover["revocation_root"])]
        + [to_int(prover["now"])]
    )
    if len(expected) != 121:
        print(f"ERROR: expected 121 public inputs, built {len(expected)}", file=sys.stderr)
        return 1

    if len(actual) != len(expected):
        print(f"READBACK MISMATCH: {len(actual)} public inputs, expected {len(expected)}",
              file=sys.stderr)
        return 1

    if actual == expected:
        print(f"public input readback OK: {len(actual)} fields, parameter order")
        return 0

    if sorted(actual) == sorted(expected):
        print(f"public input readback OK (multiset): {len(actual)} fields, witness-index order")
        return 0

    print("READBACK MISMATCH: decoded public inputs do not match Prover.toml", file=sys.stderr)
    for i, (a, e) in enumerate(zip(actual, expected)):
        if a != e:
            print(f"  #{i}: got {a} want {e}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
