#!/usr/bin/env python3
"""
bb-msgpack-parse.py -- reverse-engineering companion for
"Anatomy of a Barretenberg proof bundle" (article 01).

Zero-dependency msgpack decoder + BN254/Grumpkin field tools, used to dissect the
artifact bundle produced by:

    nargo execute          -> <circuit>.gz   (witness,  gzipped msgpack)
    nargo compile          -> <circuit>.json (ACIR,     JSON with base64 msgpack bytecode)
    bb write_vk -t evm-no-zk -> vk           (raw 32B BE fields, NOT msgpack)
    bb prove    -t evm-no-zk -> proof        (raw 32B BE fields, NOT msgpack)

Tested against bb 6.0.0-nightly.20260724 / nargo 1.0.0-beta.26.

Usage:
    python3 bb-msgpack-parse.py <dir-containing-artifacts> [cmd]
Commands: witness | circuit | vk | proof | all   (default: all)
"""

import base64
import gzip
import json
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------- msgpack ---
# Minimal RFC 8949 (msgpack) decoder. Bins stay bytes; strings become str;
# maps become dicts (keys must be hashable - they are, in these files).


class Bin(bytes):
    """bytes, but prints as hex so bin8 fields stay readable."""
    def __repr__(self):
        b = bytes(self)
        if len(b) <= 16:
            return f"bin[{len(b)}]={b.hex()}"
        return f"bin[{len(b)}]={b[:8].hex()}..{b[-4:].hex()}"


class Reader:
    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise ValueError(f"truncated: want {n} at off {self.i}, have {len(self.d)-self.i}")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def byte(self) -> int:
        return self.take(1)[0]

    def value(self):
        b = self.byte()
        if b <= 0x7F:
            return b                                    # positive fixint
        if b >= 0xE0:
            return b - 0x100                            # negative fixint
        if 0x80 <= b <= 0x8F:
            return {self.value(): self.value() for _ in range(b & 0x0F)}   # fixmap
        if 0x90 <= b <= 0x9F:
            return [self.value() for _ in range(b & 0x0F)]                 # fixarray
        if 0xA0 <= b <= 0xBF:
            return self.take(b & 0x1F).decode("utf-8", "replace")          # fixstr
        if b == 0xC0: return None
        if b == 0xC2: return False
        if b == 0xC3: return True
        if b == 0xC4: return Bin(self.take(self.byte()))                # bin8
        if b == 0xC5: return Bin(self.take(struct.unpack(">H", self.take(2))[0]))
        if b == 0xC6: return Bin(self.take(struct.unpack(">I", self.take(4))[0]))
        if b == 0xC7:  # ext8
            n, t = self.byte(), self.byte()
            return ("ext", t, Bin(self.take(n)))
        if b == 0xC8:  # ext16
            n = struct.unpack(">H", self.take(2))[0]
            t = self.byte()
            return ("ext", t, Bin(self.take(n)))
        if b == 0xC9:  # ext32
            n = struct.unpack(">I", self.take(4))[0]
            t = self.byte()
            return ("ext", t, Bin(self.take(n)))
        if b == 0xCA: return struct.unpack(">f", self.take(4))[0]
        if b == 0xCB: return struct.unpack(">d", self.take(8))[0]
        if b == 0xCC: return self.byte()
        if b == 0xCD: return struct.unpack(">H", self.take(2))[0]
        if b == 0xCE: return struct.unpack(">I", self.take(4))[0]
        if b == 0xCF: return struct.unpack(">Q", self.take(8))[0]
        if b == 0xD0: return struct.unpack(">b", self.take(1))[0]
        if b == 0xD1: return struct.unpack(">h", self.take(2))[0]
        if b == 0xD2: return struct.unpack(">i", self.take(4))[0]
        if b == 0xD3: return struct.unpack(">q", self.take(8))[0]
        if 0xD4 <= b <= 0xD8:  # fixext 1/2/4/8/16
            n = 1 << (b - 0xD4)
            t = self.byte()
            return ("ext", t, Bin(self.take(n)))
        if b == 0xD9: return self.take(self.byte()).decode("utf-8", "replace")
        if b == 0xDA: return self.take(struct.unpack(">H", self.take(2))[0]).decode("utf-8", "replace")
        if b == 0xDB: return self.take(struct.unpack(">I", self.take(4))[0]).decode("utf-8", "replace")
        if b == 0xDC: return [self.value() for _ in range(struct.unpack(">H", self.take(2))[0])]
        if b == 0xDD: return [self.value() for _ in range(struct.unpack(">I", self.take(4))[0])]
        if b == 0xDE:
            return {self.value(): self.value()
                    for _ in range(struct.unpack(">H", self.take(2))[0])}
        if b == 0xDF:
            return {self.value(): self.value()
                    for _ in range(struct.unpack(">I", self.take(4))[0])}
        raise ValueError(f"unknown msgpack prefix 0x{b:02x} at offset {self.i-1}")


def parse_all(data: bytes):
    """Msgpack files can carry several top-level objects back to back
    (nargo's witness does). Return the list."""
    r, out = Reader(data), []
    while r.i < len(r.d):
        out.append(r.value())
    return out


# ------------------------------------------------------- BN254 / Grumpkin ---
P = 21888242871839275222246405745257275088696311157297823662689037894645226208583
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
# Trap documented in the article: Honk (UltraKeccak / "evm-no-zk") commitments are
# BN254 G1 points, y^2 = x^3 + 3 -- NOT Grumpkin (y^2 = x^3 - 17). Grumpkin is
# where Noir's Pedersen hash generators live (a different part of the stack).
B_BN254 = 3
B_GRUMPKIN = -17 % P


def fields(raw: bytes):
    assert len(raw) % 32 == 0, f"len {len(raw)} not a multiple of 32"
    return [int.from_bytes(raw[i:i + 32], "big") for i in range(0, len(raw), 32)]


def on_curve(x: int, y: int, b: int = B_BN254) -> bool:
    return x < P and y < P and (y * y - (x * x * x + b)) % P == 0


def scan_curve(vals, label: str):
    """Slide a 2-window over the field words; report consecutive on-curve
    (x,y) pairs - the empirical signature of commitment points in a raw file.
    (0,0) pairs count separately: bb uses them for points at infinity."""
    runs, i = [], 0
    while i < len(vals) - 1:
        if on_curve(vals[i], vals[i + 1]) and (vals[i] or vals[i + 1]):
            j = i
            while j + 1 < len(vals) and on_curve(vals[j], vals[j + 1]) \
                    and (vals[j] or vals[j + 1]):
                j += 2
            runs.append((i, j))
            i = j
        else:
            i += 1
    zero_pairs = sum(1 for k in range(0, len(vals) - 1, 2)
                     if vals[k] == 0 and vals[k + 1] == 0)
    print(f"  {label}: {len(vals)} field words, "
          f"{sum(1 for v in vals if v >= P)} word(s) >= Fp modulus, "
          f"{sum(1 for v in vals if v >= R)} word(s) >= Fr modulus")
    for a, b in runs:
        print(f"    run of on-curve (x,y) pairs at words [{a}..{b - 1}] "
              f"({(b - a) // 2} points)")
    if zero_pairs:
        print(f"    {zero_pairs} aligned (0,0) word pairs = points at infinity")
    return runs


# ----------------------------------------------------------------- views ----
def u256_be(raw: bytes, i: int) -> int:
    return int.from_bytes(raw[i * 32:(i + 1) * 32], "big")


def skeleton(o, depth=5, indent=0, prefix=""):
    """Type/size tree for structure discovery - does not assume any schema."""
    pad = "  " * indent
    if isinstance(o, Bin):
        print(f"{pad}{prefix}bin[{len(o)}]")
    elif isinstance(o, dict):
        print(f"{pad}{prefix}map[{len(o)}] keys={list(map(str, list(o.keys())[:8]))}")
        if depth > 0:
            for k, v in list(o.items())[:8]:
                skeleton(v, depth - 1, indent + 1, prefix=f"{k!r}: ")
    elif isinstance(o, list):
        print(f"{pad}{prefix}list[{len(o)}]")
        if depth > 0:
            for i, v in enumerate(o[:8]):
                skeleton(v, depth - 1, indent + 1, prefix=f"[{i}] ")
    else:
        print(f"{pad}{prefix}{type(o).__name__}: {o!r}")


def find_opcodes(o):
    """Locate the (first) long list whose elements look like ACIR opcodes."""
    best = None
    def walk(x):
        nonlocal best
        if isinstance(x, list):
            if len(x) > 100 and all(isinstance(e, (list, dict)) for e in x[:20]):
                if best is None or len(x) > len(best):
                    best = x
            for e in x:
                walk(e)
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
    walk(o)
    return best


def show_witness(t: Path, name: str):
    raw = gzip.decompress((t / f"{name}.gz").read_bytes())
    print(f"\n=== witness {name}.gz: gz {size(name + '.gz', t)}B -> raw {len(raw)}B ===")
    print("first 48 bytes:", raw[:48].hex(" "))
    objs = parse_all(raw)
    print(f"top-level msgpack objects: {len(objs)}")
    for k, o in enumerate(objs):
        print(f"  [{k}] {describe(o)}")

    # objects[1] = [ [ [ version, {witness_index: bin32, ...} ] ] ]
    deep = objs[1][0][0]
    ver, wmap = deep[0], deep[1]
    keys = sorted(wmap.keys())
    vals = [bytes(wmap[k]) for k in keys]
    print(f"  witness map: {len(wmap)} entries, keys {keys[0]}..{keys[-1]}, "
          f"dense 0..{keys[-1]}? {'yes' if keys == list(range(len(keys))) else 'NO (sparse)'}")
    gaps = [k for k in range(keys[0], keys[-1] + 1) if k not in wmap]
    print(f"  missing keys in range: {len(gaps)}"
          + (f" e.g. {gaps[:10]}" if gaps else ""))
    print(f"  value widths: {sorted({len(v) for v in vals})}B; "
          f"zero values: {sum(1 for v in vals if not any(v))}")
    print("  first 3 entries:")
    for k in keys[:3]:
        print(f"    w{k}: {bytes(wmap[k]).hex()}")
    print("  return witness entry (highest keys):")
    for k in keys[-3:]:
        print(f"    w{k}: {bytes(wmap[k]).hex()}")
    return objs


def describe(o, depth=0, maxlist=4):
    if isinstance(o, Bin):
        return repr(o)
    if isinstance(o, dict):
        if depth >= 2:
            return f"map[{len(o)}]"
        items = list(o.items())[:maxlist]
        more = f" ...(+{len(o) - maxlist})" if len(o) > maxlist else ""
        inner = ", ".join(f"{describe(k, depth+1)}: {describe(v, depth+1)}"
                          for k, v in items)
        return "{" + inner + more + "}"
    if isinstance(o, list):
        if depth >= 2:
            return f"list[{len(o)}]"
        head = [describe(x, depth + 1) for x in o[:maxlist]]
        more = f" ...(+{len(o) - maxlist})" if len(o) > maxlist else ""
        return "[" + ", ".join(head) + more + "]"
    return repr(o)


def show_circuit(t: Path, name: str):
    d = json.loads((t / f"{name}.json").read_text())
    print(f"\n=== circuit {name}.json ===")
    print("top-level keys:", list(d.keys()))
    bc = base64.b64decode(d["bytecode"])
    print(f"bytecode: {len(d['bytecode'])} b64 chars -> {len(bc)} bytes")
    print("first 8 bytes:", bc[:8].hex(" "))
    if bc[:2] == b"\x1f\x8b":                       # !!! gzip, not raw msgpack
        inner = gzip.decompress(bc)
        print(f"!!! bytecode is GZIP: {len(bc)} -> {len(inner)} bytes msgpack")
        bc = inner
    objs = parse_all(bc)
    print(f"top-level msgpack objects: {len(objs)}")
    for k, o in enumerate(objs):
        print(f"  [{k}] {describe(o, depth=0)}")

    # Structure-agnostic skeleton of the payload object.
    print("  --- payload skeleton (type/size tree, depth 5) ---")
    skeleton(objs[-1], depth=5)

    # ACIR opcodes: find every list-of-maps-or-enums that looks like opcodes.
    ops = find_opcodes(objs[-1])
    if ops is not None:
        print(f"  opcodes: {len(ops)}")
        kinds = {}
        for op in ops:
            if isinstance(op, dict):
                key = "map{" + ",".join(sorted(map(str, op.keys()))) + "}"
            elif isinstance(op, list):
                if len(op) == 2 and isinstance(op[0], int):
                    key = f"enum[tag={op[0]}]"
                else:
                    key = f"list[{len(op)}]"
            else:
                key = type(op).__name__
            kinds[key] = kinds.get(key, 0) + 1
        for key, n in sorted(kinds.items(), key=lambda kv: -kv[1]):
            print(f"    opcode shape <{key}> x{n}")
        one = next(iter(ops))
        print(f"    sample opcode: {describe(one, depth=1)}")


def show_vk(t: Path):
    raw = (t / "vk").read_bytes()
    print(f"\n=== vk: {len(raw)}B = {len(raw)//32} x 32B BE fields (raw, NOT msgpack) ===")
    vals = fields(raw)
    for i in range(min(12, len(vals))):
        print(f"  [{i:3d}] {vals[i]:>10d}  (0x{vals[i]:x})")
    scan_curve(vals, "vk")


def show_proof(t: Path):
    raw = (t / "proof").read_bytes()
    print(f"\n=== proof: {len(raw)}B = {len(raw)//32} x 32B BE fields (raw, NOT msgpack) ===")
    vals = fields(raw)
    nonzero = [i for i, v in enumerate(vals) if v != 0]
    print(f"  first nonzero word: [{nonzero[0]}]" if nonzero else "  all zero")
    scan_curve(vals, "proof")


def size(name: str, t: Path) -> int:
    return (t / name).stat().st_size


def main():
    t = Path(sys.argv[1])
    cmd = sys.argv[2] if len(sys.argv) > 2 else "all"
    if cmd in ("witness", "all"):
        show_witness(t, "spend_authorization")
    if cmd in ("circuit", "all"):
        show_circuit(t, "spend_authorization")
    if cmd in ("vk", "all"):
        show_vk(t)
    if cmd in ("proof", "all"):
        show_proof(t)


if __name__ == "__main__":
    main()
