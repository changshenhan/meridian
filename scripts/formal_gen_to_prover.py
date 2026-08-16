#!/usr/bin/env python3
"""S-09 正式管线：gen-witness 返回值 → circuits/Prover.toml。

读取 gen-witness/Prover.toml 中 `nargo execute --overwrite-return` 写入的 `return` 键
（确定性签名 + 撤销树 witness），连同固定场景参数拼出正式电路 spend_authorization 的
Prover.toml（全部公共 + 私有 witness）。

固定场景参数以**常量**写在本脚本（gen-witness/Prover.toml 的输入在 --overwrite-return
后可能被覆盖为仅剩 `return`，故不依赖它）：delegation_hash=[0x21+i]、recipient=[0x31+i]、
category=[0x51+i]、amount=1234、spend_nonce=7、expires_at=1700000000、
now=1650000000、max_per_spend=5000、categories_len=0、not_before=0。
若 gen-witness/Prover.toml 输入键仍在，则交叉校验一致（防漂移）。

第三实现交叉校验（同 core/src/dsa.rs 的 Rust sha2 为第二实现；Noir 为第一）：
  · agent_commit   = sha256(pub_x_le ‖ pub_y_le)   ← 与电路断言 1 同规范
  · intent_hash    = sha256(agent_commit ‖ delegation_hash ‖ recipient ‖ amount_le ‖
                            category ‖ spend_nonce_le ‖ expires_at_le)   ← 断言 9
  · revocation_index = delegation_hash[0..4] LE    ← 断言 8 索引
三者任一失配 → 退出非零，CI 红。
"""
import hashlib
import sys
import tomllib
from pathlib import Path

# ——— 固定场景常量（必须与 gen-witness/Prover.toml 一致）———
DELEGATION_HASH = bytes(range(0x21, 0x41))      # 0x21+i, i∈0..32
RECIPIENT = bytes(range(0x31, 0x45))            # 0x31+i, i∈0..20
CATEGORY = bytes(range(0x51, 0x71))             # 0x51+i, i∈0..32
AMOUNT = 1234
SPEND_NONCE = 7
EXPIRES_AT = 1_700_000_000
NOW = 1_650_000_000                             # 窗口内：not_before=0 ≤ now ≤ expires_at
MAX_PER_SPEND = 5_000
MAX_CATEGORIES = 8


def to_int(v):
    return v if isinstance(v, int) else int(str(v), 0)


def emit_bytes(b: bytes) -> str:
    return "[" + ", ".join(f"0x{x:02x}" for x in b) + "]"


def le32(v: int) -> bytes:
    return v.to_bytes(32, "little")


def read_return(data):
    if "return" not in data:
        print("ERROR: gen-witness/Prover.toml has no `return` key "
              "(did nargo execute --overwrite-return run?)", file=sys.stderr)
        print("--- file head ---\n" + str(data)[:2000], file=sys.stderr)
        sys.exit(1)
    ret = data["return"]
    if isinstance(ret, dict):
        get = ret.get
        fields = {k: get(k) for k in (
            "agent_pub_x", "agent_pub_y", "sig_s", "sig_r8_x", "sig_r8_y",
            "revocation_root", "revocation_index", "revocation_path", "intent_hash")}
    elif isinstance(ret, list):
        # 位置映射（WitnessOut 字段顺序）防御性兜底
        (px, py, s, r8x, r8y, root, idx, path, ih) = ret
        fields = {"agent_pub_x": px, "agent_pub_y": py, "sig_s": s,
                  "sig_r8_x": r8x, "sig_r8_y": r8y, "revocation_root": root,
                  "revocation_index": idx, "revocation_path": path, "intent_hash": ih}
    else:
        print(f"ERROR: unexpected `return` type {type(ret)}", file=sys.stderr)
        sys.exit(1)
    if any(v is None for v in fields.values()):
        print(f"ERROR: incomplete `return` keys: {list(fields.keys())}", file=sys.stderr)
        sys.exit(1)
    return {
        "agent_pub_x": to_int(fields["agent_pub_x"]),
        "agent_pub_y": to_int(fields["agent_pub_y"]),
        "sig_s": to_int(fields["sig_s"]),
        "sig_r8_x": to_int(fields["sig_r8_x"]),
        "sig_r8_y": to_int(fields["sig_r8_y"]),
        "revocation_root": to_int(fields["revocation_root"]),
        "revocation_index": to_int(fields["revocation_index"]),
        "revocation_path": [to_int(x) for x in fields["revocation_path"]],
        "intent_hash": bytes(to_int(x) for x in fields["intent_hash"]),
    }


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: formal_gen_to_prover.py <gen-witness_dir> <circuits_dir>", file=sys.stderr)
        return 2
    gen = Path(sys.argv[1])
    circ = Path(sys.argv[2])

    data = tomllib.loads((gen / "Prover.toml").read_text(encoding="utf-8"))
    w = read_return(data)

    # 若 gen-witness/Prover.toml 输入键仍保留（未被 --overwrite-return 覆盖），交叉校验防漂移
    if "delegation_hash" in data:
        if bytes(to_int(x) for x in data["delegation_hash"]) != DELEGATION_HASH:
            print("DRIFT: gen-witness/Prover.toml delegation_hash differs from constant",
                  file=sys.stderr)
            return 1
        if to_int(data["amount"]) != AMOUNT:
            print("DRIFT: gen-witness/Prover.toml amount differs from constant", file=sys.stderr)
            return 1

    # ——— 第三实现交叉校验 ———
    agent_commit = hashlib.sha256(le32(w["agent_pub_x"]) + le32(w["agent_pub_y"])).digest()
    preimage = (
        agent_commit + DELEGATION_HASH + RECIPIENT
        + AMOUNT.to_bytes(8, "little") + CATEGORY
        + SPEND_NONCE.to_bytes(8, "little") + EXPIRES_AT.to_bytes(8, "little")
    )
    want_ih = hashlib.sha256(preimage).digest()
    if want_ih != w["intent_hash"]:
        print("CROSS-CHECK FAIL: intent_hash mismatch (Python vs gen-witness)", file=sys.stderr)
        print(f"  gen  = {w['intent_hash'].hex()}", file=sys.stderr)
        print(f"  want = {want_ih.hex()}", file=sys.stderr)
        return 1
    want_idx = int.from_bytes(DELEGATION_HASH[0:4], "little")
    if want_idx != w["revocation_index"]:
        print("CROSS-CHECK FAIL: revocation_index mismatch", file=sys.stderr)
        print(f"  gen  = {w['revocation_index']} want = {want_idx}", file=sys.stderr)
        return 1

    if len(w["revocation_path"]) != 32:
        print(f"CROSS-CHECK FAIL: revocation_path length {len(w['revocation_path'])} != 32",
              file=sys.stderr)
        return 1

    categories = [[0] * 32 for _ in range(MAX_CATEGORIES)]
    out = {
        # —— public ——
        "agent_commit": emit_bytes(agent_commit),
        "delegation_hash": emit_bytes(DELEGATION_HASH),
        "recipient": emit_bytes(RECIPIENT),
        "amount": f'"{AMOUNT}"',
        "category": emit_bytes(CATEGORY),
        "spend_nonce": f'"{SPEND_NONCE}"',
        "expires_at": f'"{EXPIRES_AT}"',
        "revocation_root": f'"{w["revocation_root"]}"',
        "now": f'"{NOW}"',
        # —— private ——
        "agent_pub_x": f'"{w["agent_pub_x"]}"',
        "agent_pub_y": f'"{w["agent_pub_y"]}"',
        "sig_s": f'"{w["sig_s"]}"',
        "sig_r8_x": f'"{w["sig_r8_x"]}"',
        "sig_r8_y": f'"{w["sig_r8_y"]}"',
        "max_per_spend": f'"{MAX_PER_SPEND}"',
        "categories": "[" + ", ".join(emit_bytes(c) for c in categories) + "]",
        "categories_len": "0",
        "not_before": "0",
        "revocation_path": "[" + ", ".join(f'"{x}"' for x in w["revocation_path"]) + "]",
    }
    body = "\n".join(f"{k} = {v}" for k, v in out.items()) + "\n"
    (circ / "Prover.toml").write_text(body)
    print(f"wrote {circ / 'Prover.toml'} ({len(body)} bytes)")
    print(f"agent_commit     = {agent_commit.hex()}")
    print(f"intent_hash      = {w['intent_hash'].hex()}")
    print(f"revocation_root  = {w['revocation_root']}")
    print(f"revocation_index = {w['revocation_index']} (want {want_idx})")
    print(f"revocation_path  = [{len(w['revocation_path'])} fields]")
    print("cross-check OK (Python 3rd implementation matches gen-witness)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
