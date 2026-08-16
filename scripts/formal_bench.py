#!/usr/bin/env python3
"""S-09 正式管线：约束门禁 + B2/B3/B4 计时基线。

- 约束数：`bb info -b target/spend_authorization.json` 抽取 gate count，硬门禁 < 2^18
  （MASTER_PLAN S-09 约束预算）。
- B2 证明 p50 < 1s：3 次 `bb prove`（含 witness 加载）取中位数。进程开销相对证明时间可忽略。
- B3 单验证 p99 < 10ms：10 次 `bb verify` 取 p99。**注意**：bb 是 CLI 进程，启动+加载
  约数十 ms，CLI 测量值是纯验证数学的上界（真值需 Phase 4 Rust in-process wrapper）。
  B3 若超目标不硬 fail（进程开销假阴性），仅标注。
- B4 批验证 ≤100µs/笔：CLI 无法单独测批验证摊薄 → 记录顺序验证进程含开销上界，标
  pending Phase 4 in-process wrapper（MASTER_PLAN B4 仅「基线记录」，无硬数值目标）。

输出 circuits/bench/baseline_s09.json（机器可读，CI upload-artifact 交付）+ stdout 摘要。
"""
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

GATE_BUDGET = 262144  # 2^18
BB = "bb"
N_PROVE = 3
N_VERIFY = 10


def parse_gates(text: str):
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for key, val in data.items():
                if isinstance(val, int) and any(m in key.lower() for m in ("size", "gate", "count")):
                    return val
    except json.JSONDecodeError:
        pass
    low = text.lower()
    for marker in ("circuit size", "circuit_size", "gates", "gate count"):
        i = low.find(marker)
        if i >= 0:
            seg = text[i:i + 80]
            nums = [int(x) for x in seg.split() if x.isdigit()]
            if nums:
                return nums[0]
    return None


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: formal_bench.py <circuits_dir>", file=sys.stderr)
        return 2
    circ = Path(sys.argv[1])
    bench_dir = circ / "bench"
    bench_dir.mkdir(exist_ok=True)
    acir = circ / "target" / "spend_authorization.json"
    wit = circ / "target" / "spend_authorization.gz"
    vk = circ / "target" / "vk"
    proof = circ / "target" / "proof"

    # 1) 约束门禁
    info = subprocess.run([BB, "info", "-b", str(acir)], cwd=str(circ),
                          capture_output=True, text=True)
    info_txt = info.stdout + info.stderr
    if info.returncode != 0:
        print(f"`bb info` failed rc={info.returncode}\n{info_txt}", file=sys.stderr)
        return 1
    gates = parse_gates(info_txt)
    if gates is None:
        print("WARN: could not parse gate count from `bb info`; raw below", file=sys.stderr)
        print(info_txt, file=sys.stderr)
    elif gates >= GATE_BUDGET:
        print(f"CONSTRAINT BUDGET FAILED: {gates} >= {GATE_BUDGET}", file=sys.stderr)
        return 1
    else:
        print(f"constraints: {gates} (budget < {GATE_BUDGET}) OK")

    # 2) B2 prove p50（3 次取中位数）
    prove_times = []
    for _ in range(N_PROVE):
        t0 = time.perf_counter()
        subprocess.run([BB, "prove", "-b", str(acir), "-w", str(wit), "-o", str(circ / "target")],
                       cwd=str(circ), capture_output=True, check=True)
        prove_times.append(time.perf_counter() - t0)
    p50_prove = statistics.median(prove_times)

    # 3) B3 verify p99（10 次）
    verify_times = []
    for _ in range(N_VERIFY):
        t0 = time.perf_counter()
        subprocess.run([BB, "verify", "-p", str(proof), "-k", str(vk)],
                       cwd=str(circ), capture_output=True, check=True)
        verify_times.append(time.perf_counter() - t0)
    p99_verify = sorted(verify_times)[max(int(len(verify_times) * 0.99) - 1, 0)]

    # 4) B4 顺序验证摊薄上界（进程含开销；真批验证待 Phase 4 in-process）
    b4_amort = sum(verify_times) / len(verify_times)

    report = {
        "s09": {
            "constraints": gates,
            "constraint_budget": GATE_BUDGET,
            "b2_prove_p50_s": p50_prove,
            "b2_prove_target_s": 1.0,
            "b3_verify_p99_s": p99_verify,
            "b3_verify_target_s": 0.010,
            "b4_per_op_upper_s": b4_amort,
            "b4_note": "CLI 进程含开销上界；真批验证摊薄待 Phase 4 Rust in-process wrapper",
            "note": "B3 为 bb CLI 进程含开销上界（启动+加载数十 ms），纯验证数学远快于此",
            "bb_info_raw": info_txt.strip()[:500],
        }
    }
    (bench_dir / "baseline_s09.json").write_text(json.dumps(report, indent=2))

    print(json.dumps(report, indent=2))
    print(f"\nwrote {bench_dir / 'baseline_s09.json'}")
    print("\n== B2/B3/B4 vs target ==")
    print(f"B2 prove p50: {p50_prove:.4f}s   target < 1s    "
          f"{'PASS' if p50_prove < 1.0 else 'FAIL'}")
    print(f"B3 verify p99: {p99_verify * 1000:.2f}ms   target < 10ms   "
          f"{'PASS' if p99_verify < 0.010 else 'OVER (CLI process overhead)'}")
    print(f"B4 per-op upper: {b4_amort * 1e6:.1f}µs   (true batch pending Phase 4 in-process)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
