#!/usr/bin/env python3
"""S-09 正式管线：gen-witness 返回值 → circuits/Prover.toml。

读取 gen-witness/Prover.toml 中 `nargo execute --overwrite-return` 写入的 `return` 键
（EdDSA 挑战 + 撤销树 witness），连同固定场景参数拼出正式电路 spend_authorization 的
Prover.toml（全部公共 + 私有 witness）。

固定场景参数以**常量**写在本脚本（gen-witness/Prover.toml 的输入在 --overwrite-return
后可能被覆盖为仅剩 `return`，故不依赖它）：delegation_hash=[0x21+i]、recipient=[0x31+i]、
category=[0x51+i]、amount=1234、spend_nonce=7、expires_at=1700000000、
now=1650000000、max_per_spend=5000、categories_len=0、not_before=0、secret=4242。
若 gen-witness/Prover.toml 输入键仍在，则交叉校验一致（防漂移）。

签名标量 s = (r + h·secret) % SUBORDER 在本脚本用 **Python 大整数**计算（r、h 由
gen-witness 输出）。Noir 1.0 移除了 Field 模运算（`%` 编译报错，eddsa fork 测试亦注明
"fields can't use modulo"），mod-n 归约移到本可信 Python 层（与 Rust core 的纯字节
逻辑同级，非曲线数学；R8/h/公钥仍在 Noir）。端到端正确性由正式电路 eddsa_verify
（CI nargo execute + bb prove/verify）把关：s 错则证明失败。

第三实现交叉校验（同 core/src/dsa.rs 的 Rust sha2 为第二实现；Noir 为第一）：
  · agent_commit   = sha256(pub_x_le ‖ pub_y_le)   ← 与电路断言 1 同规范
  · intent_hash    = sha256(agent_commit ‖ delegation_hash ‖ recipient ‖ amount_le ‖
                            category ‖ spend_nonce_le ‖ expires_at_le)   ← 断言 9
  · revocation_path 长度 = 256                      ← 断言 8 索引位宽（S-36 全宽化；
    索引 = delegation_hash 本身（公共输入），无独立 witness 字段可交叉，位序契约由
    电路/生成器/聚合器三侧同名回归测试固化）
  · 0 <= s < SUBORDER                               ← 断言 2 验签域
任一失配 → 退出非零，CI 红。
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
# 场景 attestation 私钥（与 gen-witness/Prover.toml `secret` 一致；Drift 检查兜底）
SECRET = 4242
# BabyJubJub 子群阶（与 eddsa fork / circuits 测试的 SUBORDER 一致）。签名标量
# s = (r + h·secret) mod SUBORDER 在此用 Python 大整数归约（Noir 1.0 无 Field 模运算）。
SUBORDER = 2_736_030_358_979_909_402_780_800_718_157_159_386_076_813_972_158_567_259_200_215_660_948_447_373_041


def to_int(v):
    return v if isinstance(v, int) else int(str(v), 0)


def emit_bytes(b: bytes) -> str:
    return "[" + ", ".join(f"0x{x:02x}" for x in b) + "]"


def le32(v: int) -> bytes:
    return v.to_bytes(32, "little")


WITNESS_KEYS = (
    "agent_pub_x", "agent_pub_y", "sig_r", "sig_h", "sig_r8_x", "sig_r8_y",
    "revocation_root", "revocation_path", "intent_hash",
)
# 扁平返回的顺序 = WitnessOut 字段顺序：7 标量 + 256 path + 32 ih = 295（S-36：
# revocation_index 字段退役——索引 = delegation_hash 本身，256-bit 落不进单个 Field）
FLAT_HEAD = 7  # agent_pub_x..revocation_root 共 7 个标量
PATH_LEN = 256  # REVOCATION_DEPTH（gen-witness / circuits 同值）


def parse_fields(fields):
    if any(v is None for v in fields.values()):
        print(f"ERROR: incomplete `return` keys: {list(fields.keys())}", file=sys.stderr)
        sys.exit(1)
    return {
        "agent_pub_x": to_int(fields["agent_pub_x"]),
        "agent_pub_y": to_int(fields["agent_pub_y"]),
        "sig_r": to_int(fields["sig_r"]),
        "sig_h": to_int(fields["sig_h"]),
        "sig_r8_x": to_int(fields["sig_r8_x"]),
        "sig_r8_y": to_int(fields["sig_r8_y"]),
        "revocation_root": to_int(fields["revocation_root"]),
        "revocation_path": [to_int(x) for x in fields["revocation_path"]],
        "intent_hash": bytes(to_int(x) for x in fields["intent_hash"]),
    }


def read_return(data):
    # nargo --overwrite-return 的序列化形态未在本地可见，三种都解析：
    #   a) `return` 键为表（struct → [return] 嵌套表）
    #   b) `return` 键为列表（嵌套 9 元素或扁平 295 值）
    #   c) 整个文件被覆盖成返回值本身（顶层即 WitnessOut 字段）
    ret = data.get("return")
    if isinstance(ret, dict):
        return parse_fields({k: ret.get(k) for k in WITNESS_KEYS})
    if isinstance(ret, list):
        if len(ret) == 9:
            # 嵌套形态：[7 标量, path[256], ih[32]]
            (px, py, r, h, r8x, r8y, root, path, ih) = ret
            return parse_fields({"agent_pub_x": px, "agent_pub_y": py, "sig_r": r,
                                 "sig_h": h, "sig_r8_x": r8x, "sig_r8_y": r8y,
                                 "revocation_root": root,
                                 "revocation_path": path, "intent_hash": ih})
        if len(ret) == FLAT_HEAD + PATH_LEN + 32:
            # 扁平形态：字段顺序 7 标量 + 256 path + 32 ih
            head, path, ih = (ret[:FLAT_HEAD], ret[FLAT_HEAD:FLAT_HEAD + PATH_LEN],
                              ret[FLAT_HEAD + PATH_LEN:])
            return parse_fields({"agent_pub_x": head[0], "agent_pub_y": head[1], "sig_r": head[2],
                                 "sig_h": head[3], "sig_r8_x": head[4], "sig_r8_y": head[5],
                                 "revocation_root": head[6],
                                 "revocation_path": path, "intent_hash": ih})
        print(f"ERROR: `return` list length {len(ret)} "
              f"(expected 9 nested or {FLAT_HEAD + PATH_LEN + 32} flat)", file=sys.stderr)
        print("--- first 3 values ---", file=sys.stderr)
        print(str(ret[:3])[:500], file=sys.stderr)
        sys.exit(1)
    if all(k in data for k in WITNESS_KEYS):
        # 顶层即返回值（--overwrite-return 直接覆盖了输入文件）
        return parse_fields({k: data[k] for k in WITNESS_KEYS})
    print("ERROR: gen-witness/Prover.toml has no parseable `return` (did "
          "nargo execute --overwrite-return run?)", file=sys.stderr)
    print("--- file head ---\n" + str(data)[:2000], file=sys.stderr)
    sys.exit(1)


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
        if "secret" in data and to_int(data["secret"]) != SECRET:
            print("DRIFT: gen-witness/Prover.toml secret differs from constant", file=sys.stderr)
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
    # ——— 签名标量 s = (r + h·secret) % SUBORDER（Python 大整数归约）———
    # Noir 1.0 无 Field 模运算 → mod-n 归约在此做（r、h 为 gen-witness 输出）。
    # 端到端由正式电路 eddsa_verify 把关（s 错则 circuits nargo execute 断言失败）。
    sig_s = (w["sig_r"] + w["sig_h"] * SECRET) % SUBORDER
    if not (0 <= sig_s < SUBORDER):
        print("CROSS-CHECK FAIL: sig_s out of range [0, SUBORDER)", file=sys.stderr)
        print(f"  sig_s = {sig_s}", file=sys.stderr)
        return 1

    # 断言 8 索引位宽（S-36 全宽化）：path 256 层，索引 = delegation_hash 本身
    # （无独立 witness 字段可交叉——位序契约由三侧同名回归测试固化）。
    if len(w["revocation_path"]) != PATH_LEN:
        print(f"CROSS-CHECK FAIL: revocation_path length {len(w['revocation_path'])} "
              f"!= {PATH_LEN}", file=sys.stderr)
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
        "sig_s": f'"{sig_s}"',
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
    print(f"revocation_path  = [{len(w['revocation_path'])} fields] (full-width index "
          f"= delegation_hash, S-36)")
    print(f"sig_s            = {sig_s}  (computed: (sig_r + sig_h*{SECRET}) % SUBORDER)")
    print("cross-check OK (Python 3rd implementation matches gen-witness)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
