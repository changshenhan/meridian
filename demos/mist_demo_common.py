"""S-13b 共享组件：规范编码 + 密钥签名 + mock vendor + 统一闭环驱动。

跨语言逐字节镜像 core/src/dsa.rs 的 canonical 布局：
  - delegation_hash = sha256(b"DSAv1\\0" ‖ agent(20) ‖ owner(20) ‖ nonce_le(8) ‖
    max_per_spend_le(8) ‖ rate.window_secs_le(8) ‖ rate.max_per_window_le(8) ‖
    total_cap_le(8) ‖ u32le(len(categories)) ‖ categories(32 each) ‖
    not_before_le(8) ‖ expires_at_le(8) ‖ version(1))
  - intent_hash     = sha256(b"INTv1\\0" ‖ agent(20) ‖ dh(32) ‖ recipient(20) ‖
    amount_le(8) ‖ category(32) ‖ spend_nonce_le(8) ‖
    (0x01‖memo(32) if memo else 0x00) ‖ expires_at_le(8))

签名（与 core 原语一致）：
  - owner：secp256k1 ECDSA 对 delegation_hash 签名，64B r‖s **低 s**
    （coincurve 默认低 s，与 k256 normalize_s 一致；高位 s 会被链上拒绝）。
  - agent：Ed25519 对 intent_hash **裸签**（cryptography，无 prehash，
    与 ed25519-dalek raw Ed25519 一致）。
"""

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

import coincurve
from coincurve.ecdsa import der_to_cdata, serialize_compact
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ---- 规范前缀（core/src/dsa.rs 常量） -----------------------------------------
DELEGATION_PREFIX = b"DSAv1\0"
INTENT_PREFIX = b"INTv1\0"
PROTOCOL_VERSION = 1

# ---- 固定 DID 夹具：服务器不推 DID、只验 owner 签名，固定 DID 免 keccak -------
AGENT_DID = bytes([0x01] * 20)
OWNER_DID = bytes([0x02] * 20)
VENDOR_DID = bytes([0x03] * 20)  # 收款方 = 脚本内置 mock vendor

# ---- 演示委托参数 -------------------------------------------------------------
EXPIRES_AT = 4102444800  # 2100 年 epoch（避开 JS u64 JSON 精度）
TOTAL_CAP = 10_000
MAX_PER_SPEND = 1_000
RATE_WINDOW_SECS = 3_600
CATEGORY = bytes([0xCD] * 32)

# ---- 演示密钥（16 进制递增字节，仅本地演示，非生产） --------------------------
OWNER_SK = bytes(range(1, 33))   # 演示 owner 私钥（secp256k1）
AGENT_SK = bytes(range(33, 65))  # 演示 agent 私钥（Ed25519）


def delegation_hash(
    *,
    agent=AGENT_DID,
    owner=OWNER_DID,
    nonce=1,
    max_per_spend=MAX_PER_SPEND,
    rate_window_secs=RATE_WINDOW_SECS,
    rate_max_per_window=TOTAL_CAP,
    total_cap=TOTAL_CAP,
    categories=(),
    not_before=0,
    expires_at=EXPIRES_AT,
    version=PROTOCOL_VERSION,
) -> bytes:
    """规范 delegation_hash（逐字节镜像 canonical_delegation）。"""
    out = bytearray()
    out += DELEGATION_PREFIX
    out += agent
    out += owner
    out += nonce.to_bytes(8, "little")
    out += max_per_spend.to_bytes(8, "little")
    out += rate_window_secs.to_bytes(8, "little")
    out += rate_max_per_window.to_bytes(8, "little")
    out += total_cap.to_bytes(8, "little")
    out += len(categories).to_bytes(4, "little")
    for c in categories:
        out += c
    out += not_before.to_bytes(8, "little")
    out += expires_at.to_bytes(8, "little")
    out += bytes([version])
    return hashlib.sha256(out).digest()


def intent_hash(
    *,
    agent=AGENT_DID,
    delegation_hash: bytes,
    recipient=VENDOR_DID,
    amount: int,
    category=CATEGORY,
    spend_nonce: int,
    memo: bytes | None = None,
    expires_at=EXPIRES_AT,
) -> bytes:
    """规范 intent_hash（逐字节镜像 intent_hash 热路径）。"""
    out = bytearray()
    out += INTENT_PREFIX
    out += agent
    out += delegation_hash
    out += recipient
    out += amount.to_bytes(8, "little")
    out += category
    out += spend_nonce.to_bytes(8, "little")
    if memo is not None:
        out += b"\x01" + memo
    else:
        out += b"\x00"
    out += expires_at.to_bytes(8, "little")
    return hashlib.sha256(out).digest()


# ---- 签名 ---------------------------------------------------------------------

def owner_sign(dh: bytes) -> bytes:
    """secp256k1 对 delegation_hash 签名 → 64B r‖s（低 s）。

    coincurve 21 的 `sign()` 返回 DER；`der_to_cdata`→`serialize_compact` 转回
    64B compact（libsecp256k1 默认低 s，与 k256 normalize_s 一致）。
    """
    sk = coincurve.PrivateKey(OWNER_SK)
    der = sk.sign(dh, hasher=None)
    return serialize_compact(der_to_cdata(der))


def owner_pubkey_sec1() -> str:
    """owner 公钥 SEC1 压缩 33B hex（authorize 入参 owner_pubkey）。"""
    return coincurve.PublicKey.from_secret(OWNER_SK).format(compressed=True).hex()


def agent_sign(data: bytes) -> bytes:
    """Ed25519 裸签（无 prehash）→ 64B 签名。"""
    sk = Ed25519PrivateKey.from_private_bytes(AGENT_SK)
    return sk.sign(data)


def agent_pubkey() -> str:
    """agent 传输身份公钥 Ed25519 原始 32B hex。"""
    sk = Ed25519PrivateKey.from_private_bytes(AGENT_SK)
    raw = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


# ---- 脚本内置 mock vendor（凭 verify_receipt 校验后授予 API 积分） ------------

class MockVendor:
    """演示 vendor：只认聚合器 `verify_receipt` 确认过的支付。

    收到 {accepted:true, seq} 才给收款方授予积分（amount*1000），再吐出模拟数据。
    若不校验回执，任何人都能伪造"已支付"，这正是 verify_receipt 存在的原因。
    """

    def __init__(self) -> None:
        self.credits: dict[str, int] = {}

    def grant(self, receipt: dict, amount: int) -> dict:
        if not receipt.get("accepted"):
            raise AssertionError("mock vendor 拒绝：verify_receipt 未确认（accepted != true）")
        did = receipt["delegation_hash"]
        self.credits[did] = self.credits.get(did, 0) + amount * 1000
        return {
            "vendor": "mock-data-market",
            "credits_granted": amount * 1000,
            "credits_total": self.credits[did],
            "data": [  # 模拟数据行：agent 用 DSA 买到的"数据/API 额度"
                {"row": 1, "ticker": "MIST", "price": amount, "ok": True},
                {"row": 2, "ticker": "DSA", "price": amount * 2, "ok": True},
            ],
        }


# ---- 统一闭环序列（3 个框架脚本同一序列） ------------------------------------

async def run_closed_loop(call_tool, log=print) -> None:
    """authorize → revocation_witness → pay → balance → verify_receipt → vendor 授予积分。

    `call_tool(name, args) -> (ok: bool, body: dict)`：框架 MCP 工具调用包装。
    每步带**内置自检**：本地重算的 delegation_hash / intent_hash 必须与服务器
    回执对得上（跨语言规范编码防漂移）。
    """
    dh = delegation_hash()
    owner_sig = owner_sign(dh)

    # 1. authorize：owner 签 delegation，绑定 agent 身份
    auth_args = {
        "agent": AGENT_DID.hex(),
        "owner": OWNER_DID.hex(),
        "nonce": 1,
        "max_per_spend": MAX_PER_SPEND,
        "rate_window_secs": RATE_WINDOW_SECS,
        "rate_max_per_window": TOTAL_CAP,
        "total_cap": TOTAL_CAP,
        "categories": [],
        "not_before": 0,
        "expires_at": EXPIRES_AT,
        "version": PROTOCOL_VERSION,
        "owner_signature": owner_sig.hex(),
        "owner_pubkey": owner_pubkey_sec1(),
        "agent_pubkey": agent_pubkey(),
    }
    ok, auth = await call_tool("authorize", auth_args)
    assert ok, f"authorize 失败: {auth.get('error')}"
    # 自检：本地重算 delegation_hash == 服务器回执
    assert auth["delegation_hash"] == dh.hex(), (
        f"delegation_hash 漂移: local={dh.hex()} server={auth['delegation_hash']}"
    )
    log(f"[1/6] authorize OK  dh={dh.hex()[:16]}…  total_cap={auth['total_cap']}")

    # 2. revocation_witness：撤销非成员事实面（S-52 第 6 工具，TECH_SPEC §6.16）——
    # 客户端构建真电路证明所需的唯一服务器侧事实。本演示用占位证明（缺省 format
    # 后端）不消费 witness，此步验证的是工具连通与载荷形状（root 32B + path
    # 256×32B 扁平）；真证明路径需 nargo/bb 工具链，由 Rust 门控 e2e 实证（§6.16）。
    ok, wit = await call_tool("revocation_witness", {"delegation_hash": dh.hex()})
    assert ok, f"revocation_witness 失败: {wit.get('error')}"
    assert wit["delegation_hash"] == dh.hex(), (
        f"witness 回执 dh 漂移: {wit['delegation_hash']}"
    )
    assert len(wit["root"]) == 64, f"root 形状漂移: {len(wit['root'])} hex 字符"
    assert len(wit["path"]) == 16384, f"path 形状漂移: {len(wit['path'])} hex 字符"
    int(wit["root"], 16)
    int(wit["path"], 16)  # 均 hex 可解码
    log(f"[2/6] revocation_witness OK  root={wit['root'][:16]}…  path=256×32B")

    # 3. pay：agent 签 intent，付 vendor DID
    amount, spend_nonce = 142, 1
    ih = intent_hash(delegation_hash=dh, amount=amount, spend_nonce=spend_nonce)
    pay_args = {
        "agent": AGENT_DID.hex(),
        "delegation_hash": dh.hex(),
        "recipient": VENDOR_DID.hex(),
        "amount": amount,
        "category": CATEGORY.hex(),
        "spend_nonce": spend_nonce,
        "memo": None,
        "expires_at": EXPIRES_AT,
        "signature": agent_sign(ih).hex(),
    }
    ok, pay = await call_tool("pay", pay_args)
    assert ok, f"pay 失败: {pay.get('error')}"
    # 自检：服务器回执 intent_hash == 本地重算
    assert pay["intent_hash"] == ih.hex(), (
        f"intent_hash 漂移: local={ih.hex()} server={pay['intent_hash']}"
    )
    log(f"[3/6] pay OK      seq={pay['seq']}  intent_hash={ih.hex()[:16]}…  amount={amount}")

    # 4. balance：额度滚动
    ok, bal = await call_tool("balance", {"delegation_hash": dh.hex()})
    assert ok, f"balance 失败: {bal.get('error')}"
    assert bal["total_spent"] == amount, f"balance 漂移: total_spent={bal['total_spent']}"
    log(f"[4/6] balance OK  spent={bal['total_spent']}  remaining={bal['remaining']}")

    # 5. verify_receipt：聚合器只读确认（vendor 校验侧）
    ok, vr = await call_tool(
        "verify_receipt",
        {
            "delegation_hash": dh.hex(),
            "spend_nonce": spend_nonce,
            "intent_hash": ih.hex(),
        },
    )
    assert ok, f"verify_receipt 失败: {vr.get('error')}"
    assert vr["accepted"] is True, "verify_receipt 应 accepted=true"
    log(f"[5/6] verify_receipt OK  accepted={vr['accepted']}  seq={vr['seq']}")

    # 6. mock vendor：凭确认回执授予积分 + 返回模拟数据
    data = MockVendor().grant(vr, amount)
    log(f"[6/6] vendor granted credits={data['credits_granted']}  rows={len(data['data'])}")

    log("闭环完成：agent 用 DSA 自动购买数据/API 额度 ✔")


# ---- 第 7 步：真链结算侧车（S-76，TECH_SPEC §6.16） ----------------------------

DEMO_WAL_DIR = Path(__file__).resolve().parent / ".wal"


def fresh_wal_dir() -> None:
    """demo WAL = 本轮 scratch 面，启动清盘保证确定性复跑（S-76 定夺 ⑧）。

    mist-mcp 启动不重放旧 WAL（`restore_from_wal` 是显式入口，bin 未接）：S-76 起
    变更工具回执前强制 fsync（定夺 ⑦），WAL 首次真实落盘——旧账本残留从「不可见」
    变「必现」（复跑会在旧账本上追加重复 Register/Intent 记录）。demo 面以清盘收口；
    生产账本进程的 WAL 管理不归 demo 面。
    """
    shutil.rmtree(DEMO_WAL_DIR, ignore_errors=True)


def run_onchain_settle(log=print) -> None:
    """第 7 步：运营者侧真链结算——BatchSettler commit→settle→过挑战窗→claim。

    消费 MCP 会话产出的 WAL（demos/.wal/mist.wal）：demo_settle 拷贝快照后从快照
    恢复账本、显式密封当前尾、净额结算上链并逐收款人对账（原 WAL 一字不动 → 幂等
    重跑，TECH_SPEC §6.16 定夺 ①）。降级口径（同节定夺 ⑥）：二进制缺失 = 打印一行
    构建指引后跳过（6 步闭环仍完整）；存在但失败 = loud fail。跑本步需 foundry
    （anvil）在 PATH。独立于 MCP 会话——结算不消费 MCP 面，本函数是同步阻塞调用。
    """
    suffix = ".exe" if sys.platform == "win32" else ""
    repo = Path(__file__).resolve().parent.parent
    # demo_settle 在 contracts/rust-smoke 独立 workspace（自带 target/，不进主仓
    # fmt/clippy/test 门禁），产物落 contracts/rust-smoke/target/release/。
    settle_bin = (
        repo / "contracts" / "rust-smoke" / "target" / "release" / f"demo_settle{suffix}"
    )
    if not settle_bin.is_file():
        log(
            "[7/7] 链上结算 跳过（demo_settle 未构建）："
            "cd contracts/rust-smoke && cargo build --release --bin demo_settle（另需 foundry）"
        )
        return
    wal = DEMO_WAL_DIR / "mist.wal"
    if not wal.is_file():
        raise AssertionError(f"WAL 不存在：{wal}（MCP 会话应已产出真账本）")
    log(f"[7/7] 链上结算：demo_settle 消费 {wal} → commit→settle→过挑战窗→claim")
    proc = subprocess.run(
        [str(settle_bin), "--wal", str(wal)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    for line in (proc.stdout or "").splitlines():
        if line.strip():
            log(f"    {line}")
    if proc.returncode != 0:
        raise AssertionError(
            f"demo_settle 失败（exit {proc.returncode}）: {(proc.stderr or '').strip()}"
        )
    log("[7/7] 链上结算 OK  收款人余额增量 == 净额行（逐 wei 对账）")
