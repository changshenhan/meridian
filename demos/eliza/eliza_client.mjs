// S-13b 演示③：ElizaOS 同栈 MCP client（@modelcontextprotocol/sdk）接入 Meridian DSA。
//
// 用法（在 demos/eliza/ 下）：
//     node eliza_client.mjs
//
// 两条接入面：
//   1. character.json —— 官方 @elizaos/plugin-mcp 的集成配置面（settings.mcp.servers.
//      meridian，stdio 拉起 meridian-mcp）。本脚本启动时按本机绝对路径自动生成，
//      配置给真实 Eliza 运行时即可把 6 个工具暴露给 agent 的 LLM。
//   2. eliza_client.mjs —— 用与 plugin 相同的 @modelcontextprotocol/sdk 栈直连跑同一
//      闭环（authorize→revocation_witness→pay→balance→verify_receipt→vendor），
//      完整 LLM 驱动可选（需模型 key）。
//
// 密码学：@noble/curves ed25519（RFC8032 确定性裸签，与 ed25519-dalek 逐字节一致）、
// secp256k1（默认低 s，与 k256 normalize_s 一致）；哈希逐字节镜像 core/src/dsa.rs。

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { secp256k1 } from "@noble/curves/secp256k1";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(__dirname, "..", "..");
const BIN = resolve(REPO, "target", "release", "meridian-mcp.exe");
const WAL_DIR = resolve(__dirname, "..", ".wal");

// ---- 规范编码（逐字节镜像 core/src/dsa.rs） -----------------------------------
const enc = new TextEncoder();
const DELEGATION_PREFIX = enc.encode("DSAv1\0");
const INTENT_PREFIX = enc.encode("INTv1\0");

function u64le(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}
function u32le(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}
function concat(...arrays) {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}
function hex(b) {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function delegationHash(o) {
  const parts = [
    DELEGATION_PREFIX,
    o.agent, o.owner,
    u64le(o.nonce),
    u64le(o.maxPerSpend),
    u64le(o.rateWindowSecs),
    u64le(o.rateMaxPerWindow),
    u64le(o.totalCap),
    u32le(o.categories.length),
    ...o.categories,
    u64le(o.notBefore),
    u64le(o.expiresAt),
    Uint8Array.of(o.version),
  ];
  return sha256(concat(...parts));
}

function intentHash(o) {
  const parts = [
    INTENT_PREFIX,
    o.agent,
    o.delegationHash,
    o.recipient,
    u64le(o.amount),
    o.category,
    u64le(o.spendNonce),
    o.memo ? Uint8Array.of(0x01, ...o.memo) : Uint8Array.of(0x00),
    u64le(o.expiresAt),
  ];
  return sha256(concat(...parts));
}

// ---- 演示固定参数（与 Python common 一致） -------------------------------------
const AGENT_DID = new Uint8Array(20).fill(0x01);
const OWNER_DID = new Uint8Array(20).fill(0x02);
const VENDOR_DID = new Uint8Array(20).fill(0x03);
const CATEGORY = new Uint8Array(32).fill(0xcd);
const EXPIRES_AT = 4102444800; // 2100 epoch（JS Number 安全整数内）
const TOTAL_CAP = 10_000;
const MAX_PER_SPEND = 1_000;
const RATE_WINDOW_SECS = 3_600;
const OWNER_SK = Uint8Array.from({ length: 32 }, (_, i) => (i + 1) & 0xff);
const AGENT_SK = Uint8Array.from({ length: 32 }, (_, i) => (i + 33) & 0xff);

// ---- 签名（noble，与 core 原语一致） -------------------------------------------
function ownerSign(dh) {
  return secp256k1.sign(dh, OWNER_SK).toCompactRawBytes(); // 64B r||s 低 s
}
function ownerPubkeySec1() {
  return secp256k1.getPublicKey(OWNER_SK, true); // 33B 压缩 SEC1
}
function agentSign(data) {
  return ed25519.sign(data, AGENT_SK); // RFC8032 裸签，与 dalek 一致
}
function agentPubkey() {
  return ed25519.getPublicKey(AGENT_SK);
}

// ---- 脚本内置 mock vendor ------------------------------------------------------
const credits = new Map();
function mockVendorGrant(receipt, amount) {
  if (!receipt.accepted) throw new Error("mock vendor 拒绝：verify_receipt 未确认");
  const key = receipt.delegation_hash;
  credits.set(key, (credits.get(key) ?? 0) + amount * 1000);
  return {
    vendor: "mock-data-market",
    credits_granted: amount * 1000,
    credits_total: credits.get(key),
    data: [
      { row: 1, ticker: "MERIDIAN", price: amount, ok: true },
      { row: 2, ticker: "DSA", price: amount * 2, ok: true },
    ],
  };
}

// ---- 统一闭环序列 ---------------------------------------------------------------
async function runClosedLoop(callTool, log) {
  const dh = delegationHash({
    agent: AGENT_DID, owner: OWNER_DID, nonce: 1,
    maxPerSpend: MAX_PER_SPEND, rateWindowSecs: RATE_WINDOW_SECS,
    rateMaxPerWindow: TOTAL_CAP, totalCap: TOTAL_CAP,
    categories: [], notBefore: 0, expiresAt: EXPIRES_AT, version: 1,
  });

  // 1. authorize
  const { ok: authOk, body: auth } = await callTool("authorize", {
    agent: hex(AGENT_DID), owner: hex(OWNER_DID), nonce: 1,
    max_per_spend: MAX_PER_SPEND, rate_window_secs: RATE_WINDOW_SECS,
    rate_max_per_window: TOTAL_CAP, total_cap: TOTAL_CAP,
    categories: [], not_before: 0, expires_at: EXPIRES_AT, version: 1,
    owner_signature: hex(ownerSign(dh)),
    owner_pubkey: hex(ownerPubkeySec1()),
    agent_pubkey: hex(agentPubkey()),
  });
  if (!authOk) throw new Error(`authorize 失败: ${auth.error}`);
  if (auth.delegation_hash !== hex(dh)) {
    throw new Error(`delegation_hash 漂移: local=${hex(dh)} server=${auth.delegation_hash}`);
  }
  log(`[1/6] authorize OK  dh=${hex(dh).slice(0, 16)}…  total_cap=${auth.total_cap}`);

  // 2. revocation_witness：撤销非成员事实面（S-52 第 6 工具，TECH_SPEC §6.16）——
  // 客户端构建真电路证明所需的唯一服务器侧事实。本演示用占位证明（缺省 format
  // 后端）不消费 witness，此步验证工具连通与载荷形状（root 32B + path 256×32B
  // 扁平）；真证明路径需 nargo/bb 工具链，由 Rust 门控 e2e 实证（§6.16）。
  const { ok: witOk, body: wit } = await callTool("revocation_witness", {
    delegation_hash: hex(dh),
  });
  if (!witOk) throw new Error(`revocation_witness 失败: ${wit.error}`);
  if (wit.delegation_hash !== hex(dh)) {
    throw new Error(`witness 回执 dh 漂移: ${wit.delegation_hash}`);
  }
  if (wit.root.length !== 64) throw new Error(`root 形状漂移: ${wit.root.length} hex 字符`);
  if (wit.path.length !== 16384) throw new Error(`path 形状漂移: ${wit.path.length} hex 字符`);
  log(`[2/6] revocation_witness OK  root=${wit.root.slice(0, 16)}…  path=256×32B`);

  // 3. pay
  const amount = 142, spendNonce = 1;
  const ih = intentHash({
    agent: AGENT_DID, delegationHash: dh, recipient: VENDOR_DID,
    amount, category: CATEGORY, spendNonce, memo: null, expiresAt: EXPIRES_AT,
  });
  const { ok: payOk, body: pay } = await callTool("pay", {
    agent: hex(AGENT_DID), delegation_hash: hex(dh), recipient: hex(VENDOR_DID),
    amount, category: hex(CATEGORY), spend_nonce: spendNonce, memo: null,
    expires_at: EXPIRES_AT, signature: hex(agentSign(ih)),
  });
  if (!payOk) throw new Error(`pay 失败: ${pay.error}`);
  if (pay.intent_hash !== hex(ih)) {
    throw new Error(`intent_hash 漂移: local=${hex(ih)} server=${pay.intent_hash}`);
  }
  log(`[3/6] pay OK      seq=${pay.seq}  intent_hash=${hex(ih).slice(0, 16)}…  amount=${amount}`);

  // 4. balance
  const { ok: balOk, body: bal } = await callTool("balance", { delegation_hash: hex(dh) });
  if (!balOk) throw new Error(`balance 失败: ${bal.error}`);
  if (bal.total_spent !== amount) throw new Error(`balance 漂移: total_spent=${bal.total_spent}`);
  log(`[4/6] balance OK  spent=${bal.total_spent}  remaining=${bal.remaining}`);

  // 5. verify_receipt
  const { ok: vrOk, body: vr } = await callTool("verify_receipt", {
    delegation_hash: hex(dh), spend_nonce: spendNonce, intent_hash: hex(ih),
  });
  if (!vrOk) throw new Error(`verify_receipt 失败: ${vr.error}`);
  if (vr.accepted !== true) throw new Error("verify_receipt 应 accepted=true");
  log(`[5/6] verify_receipt OK  accepted=${vr.accepted}  seq=${vr.seq}`);

  // 6. mock vendor 授予积分
  const data = mockVendorGrant(vr, amount);
  log(`[6/6] vendor granted credits=${data.credits_granted}  rows=${data.data.length}`);

  log("闭环完成：agent 用 DSA 自动购买数据/API 额度 ✔");
}

// ---- 入口 ----------------------------------------------------------------------
async function main() {
  // 配置面：为真实 @elizaos/plugin-mcp 生成 character.json（绝对路径 stdio 配置）。
  const character = {
    name: "meridian-buyer",
    modelProvider: "anthropic",
    settings: {
      mcp: {
        servers: {
          meridian: {
            command: BIN,
            args: [],
            env: { MERIDIAN_WAL_DIR: WAL_DIR },
          },
        },
      },
    },
  };
  writeFileSync(resolve(__dirname, "character.json"), JSON.stringify(character, null, 2));
  console.log(`[eliza] character.json 已生成（plugin-mcp 集成配置面）: command=${BIN}`);

  const transport = new StdioClientTransport({
    command: BIN,
    args: [],
    env: { MERIDIAN_WAL_DIR: WAL_DIR },
  });
  const client = new Client({ name: "meridian-eliza-demo", version: "0.1.0" });
  await client.connect(transport);

  const { tools } = await client.listTools();
  const names = new Set(tools.map((t) => t.name));
  for (const need of ["authorize", "pay", "balance", "attest", "verify_receipt"]) {
    if (!names.has(need)) throw new Error(`MCP 工具不全: 缺 ${need}`);
  }

  const callTool = async (name, args) => {
    const res = await client.callTool({ name, arguments: args });
    const text = (res.content.find((c) => c.type === "text") ?? {}).text ?? "";
    const body = JSON.parse(text);
    return { ok: res.isError !== true && !body.error, body };
  };

  await runClosedLoop(callTool, (s) => console.log(`  [eliza] ${s}`));
  await client.close();
}

main().then(
  () => process.exit(0),
  (e) => {
    console.error(`[eliza] 失败: ${e.message}`);
    process.exit(1);
  },
);
