#!/usr/bin/env python3
"""TEMPORARY —— S-05 冒烟：公共输入回读比对。

读取 bb prove 输出的 public_inputs（32 字节 field 数组），与 Prover.toml 的公共参数
（message_hash / pub_key_x / pub_key_y / message）做多重集比对，并报告实际顺序。

公开输入编码（v1.0.0-beta.26，noirc_evaluator::ssa::split_public_and_private_inputs）：
`pub [u8; 32]` → 每个字节一个公共 witness（field），`pub Field` → 一个 witness，
故本电路共 32+32+32+1 = 97 个公共输入。首次 CI 会确认 field 的大小端序与
public_inputs 文件名，如有出入据此脚本调整一次。

验证完成后删除；不进 SPEC / 文档。
"""
import sys
import tomllib
from pathlib import Path

FIELD = 32  # barretenberg field = 32 bytes


def le(b: bytes) -> int:
    return int.from_bytes(b, "little")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: smoke_readback.py <smoke_dir>", file=sys.stderr)
        return 2
    smoke = Path(sys.argv[1])
    prover = tomllib.loads((smoke / "Prover.toml").read_text())

    candidates = ["target/public_inputs", "target/proof_public_inputs"]
    pi_path = next((smoke / c for c in candidates if (smoke / c).exists()), None)
    if pi_path is None:
        print("ERROR: no public_inputs file found under target/", file=sys.stderr)
        return 1

    raw = pi_path.read_bytes()
    if len(raw) % FIELD != 0:
        print(f"ERROR: {pi_path} size {len(raw)} not a multiple of {FIELD}", file=sys.stderr)
        return 1
    actual = [le(raw[i : i + FIELD]) for i in range(0, len(raw), FIELD)]

    expected = (
        list(prover["message_hash"])
        + list(prover["pub_key_x"])
        + list(prover["pub_key_y"])
        + [prover["message"]]
    )

    if len(actual) != len(expected):
        print(
            f"READBACK MISMATCH: {len(actual)} public inputs, expected {len(expected)}",
            file=sys.stderr,
        )
        return 1

    if sorted(actual) != sorted(expected):
        print("READBACK MISMATCH: decoded public inputs do not match Prover.toml", file=sys.stderr)
        for a, e in zip(sorted(actual), sorted(expected)):
            if a != e:
                print(f"  got {a:08x} want {e:08x}", file=sys.stderr)
        return 1

    order_note = (
        "parameter order"
        if actual == expected
        else "witness-index order (not parameter order)"
    )
    print(f"public input readback OK: {len(actual)} fields, in {order_note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
