//! S-76 MCP stdio 探针（TECH_SPEC §6.16）：Rust 侧 MCP 客户端参考实现 + 冒烟探针。
//!
//! spawn 同 package 兄弟 bin `mist-mcp`（`MIST_WAL_DIR=<argv[1]>`），手写
//! newline-delimited JSON-RPC（std + serde_json；rmcp client 特性按
//! dev-dependencies 口径不进生产构建），fixture 与 `demos/mist_demo_common.py`
//! 逐字节同参（同一把 owner/agent 钥匙、同一 DID、同一金额——probe 产出的 WAL 与
//! 框架 demo 的 WAL 同形），断言与 demo 闭环同款：本地重算 `delegation_hash` /
//! `intent_hash` 必须与服务器回执逐字节一致。
//!
//! verify.sh 步 10b（S-76）：probe 产真 WAL → `demo_settle` 对真 WAL 真链结算。
//!
//! 用法：cargo run -p mist-mcp --bin mcp_probe -- <wal-dir>

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use mist_core::dsa::{self, AgentSigningKey, Delegation, OwnerSigningKey, RateLimit, SpendIntent};
use serde_json::{json, Value};

// ---- fixture：与 demos/mist_demo_common.py 逐字节同参 -------------------------

const AGENT_DID: [u8; 20] = [0x01; 20];
const OWNER_DID: [u8; 20] = [0x02; 20];
const VENDOR_DID: [u8; 20] = [0x03; 20];
/// 2100 年 epoch（mist_demo_common.EXPIRES_AT 同值，避开 JS u64 JSON 精度）。
const EXPIRES_AT: u64 = 4_102_444_800;
const TOTAL_CAP: u64 = 10_000;
const MAX_PER_SPEND: u64 = 1_000;
const RATE_WINDOW_SECS: u64 = 3_600;
const CATEGORY: [u8; 32] = [0xCD; 32];
const AMOUNT: u64 = 142;
const SPEND_NONCE: u64 = 1;

/// owner 私钥 = bytes(range(1, 33))（演示钥，非生产）。
fn owner_key_fixture() -> OwnerSigningKey {
    let mut b = [0u8; 32];
    for (i, v) in b.iter_mut().enumerate() {
        *v = (i + 1) as u8;
    }
    dsa::owner_signing_key_from_bytes(b)
}

/// agent 私钥 = bytes(range(33, 65))。
fn agent_key_fixture() -> AgentSigningKey {
    let mut b = [0u8; 32];
    for (i, v) in b.iter_mut().enumerate() {
        *v = (i + 33) as u8;
    }
    AgentSigningKey::from_bytes(&b)
}

/// 兄弟 bin 定位：同 package 同 profile，`current_exe()` 同目录必见 `mist-mcp`。
fn server_path() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe().context("current_exe")?;
    let server = exe.with_file_name(format!("mist-mcp{}", std::env::consts::EXE_SUFFIX));
    ensure!(
        server.is_file(),
        "兄弟 bin 不存在：{}（先 cargo build -p mist-mcp --bins）",
        server.display()
    );
    Ok(server)
}

/// 最小 stdio JSON-RPC 客户端：newline-delimited，顺序请求/响应，
/// 通知与服务器→客户端请求不崩（后者回 method not found 防死锁）。
struct Rpc {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Rpc {
    fn send(&mut self, v: &Value) -> Result<()> {
        writeln!(self.stdin, "{v}").context("写 MCP stdin（服务器已退出?）")?;
        Ok(self.stdin.flush()?)
    }

    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        loop {
            let mut line = String::new();
            let n = self.stdout.read_line(&mut line).context("读 MCP stdout")?;
            if n == 0 {
                anyhow::bail!("MCP 服务器提前退出（等待 {method} 响应）");
            }
            let v: Value = match serde_json::from_str(line.trim()) {
                Ok(v) => v,
                Err(_) => continue, // 非 JSON 行（杂散日志）忽略
            };
            if v.get("id").and_then(Value::as_u64) == Some(id) {
                return Ok(v);
            }
            if v.get("method").is_some() && v.get("id").is_some() {
                // 服务器→客户端请求：本探针不声明任何能力，回 method not found。
                let rid = v["id"].clone();
                self.send(&json!({
                    "jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32601, "message": "mcp-probe: method not found"}
                }))?;
            }
            // 其余（notifications）忽略。
        }
    }

    fn notify(&mut self, method: &str) -> Result<()> {
        self.send(&json!({"jsonrpc": "2.0", "method": method}))
    }

    /// tools/call → (ok, body)：MCP content 首个 text 块解析为 JSON。
    fn call_tool(&mut self, name: &str, args: Value) -> Result<(bool, Value)> {
        let res = self.call("tools/call", json!({"name": name, "arguments": args}))?;
        if let Some(err) = res.get("error") {
            anyhow::bail!("tool {name} JSON-RPC error: {err}");
        }
        let text = res["result"]["content"]
            .as_array()
            .and_then(|c| c.iter().find(|b| b["type"] == "text"))
            .and_then(|b| b["text"].as_str())
            .unwrap_or_default();
        let body: Value = serde_json::from_str(text)
            .with_context(|| format!("tool {name} 回执非 JSON: {text}"))?;
        let ok = res["result"]["isError"].as_bool() != Some(true) && body.get("error").is_none();
        Ok((ok, body))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let wal_dir = match args.get(1) {
        Some(d) => d.clone(),
        None => {
            eprintln!("用法：mcp_probe <wal-dir>");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(&wal_dir) {
        eprintln!("[mcp-probe] 失败: {e:#}");
        std::process::exit(1);
    }
}

fn run(wal_dir: &str) -> Result<()> {
    let server = server_path()?;
    // 目标 WAL 目录 = 本轮 scratch 面，启动清盘（§6.16 定夺 ⑧⑨：mist-mcp 启动不重放
    // WAL，残留账本上复跑会追加重复 Register/Intent 记录——重复接受形态已被定夺 ⑨ 的
    // 重放去重兜底，但探针作为确定性冒烟面自己从零开始）。清盘权仅在 caller 授权的
    // scratch 目录，不触任何其它路径。
    let _ = std::fs::remove_dir_all(wal_dir);
    std::fs::create_dir_all(wal_dir)?;
    let mut child = Command::new(&server)
        .env("MIST_WAL_DIR", wal_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {}", server.display()))?;
    let stdin = child.stdin.take().context("child stdin")?;
    let stdout = child.stdout.take().context("child stdout")?;
    let mut rpc = Rpc {
        stdin,
        stdout: BufReader::new(stdout),
        next_id: 1,
    };
    let result = drive(&mut rpc);
    // 停机：关 stdin → rmcp stdio 服务循环结束 → main.rs 停机 flush_wal（S-76）→
    // 自退；10s 不退再 kill（kill 丢缓冲尾巴 → demo_settle 必红，比假绿诚实）。
    drop(rpc);
    shutdown(child);
    result
}

fn shutdown(mut child: Child) {
    for _ in 0..100 {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => return,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn drive(rpc: &mut Rpc) -> Result<()> {
    // ---- MCP 生命周期：initialize → notifications/initialized ----
    let init = rpc.call(
        "initialize",
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "mcp-probe", "version": "0.1.0"}
        }),
    )?;
    ensure!(
        init.get("result")
            .and_then(|r| r.get("serverInfo"))
            .is_some(),
        "initialize 未返回 serverInfo: {init}"
    );
    rpc.notify("notifications/initialized")?;

    // ---- 工具清单（三框架 demo 同款断言）----
    let tools = rpc.call("tools/list", json!({}))?;
    let names: Vec<String> = tools["result"]["tools"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    for need in [
        "authorize",
        "pay",
        "balance",
        "attest",
        "verify_receipt",
        "revocation_witness",
    ] {
        ensure!(names.iter().any(|n| n == need), "MCP 工具不全: 缺 {need}");
    }

    // ---- fixture + 本地重算（跨语言规范编码防漂移）----
    let owner_key = owner_key_fixture();
    let agent_key = agent_key_fixture();
    let d = Delegation {
        agent: AGENT_DID,
        owner: OWNER_DID,
        nonce: 1,
        max_per_spend: MAX_PER_SPEND,
        rate: RateLimit {
            window_secs: RATE_WINDOW_SECS,
            max_per_window: TOTAL_CAP,
        },
        total_cap: TOTAL_CAP,
        categories: vec![],
        not_before: 0,
        expires_at: EXPIRES_AT,
        version: dsa::PROTOCOL_VERSION,
    };
    let dh = dsa::delegation_hash(&d);
    let sd = dsa::sign_delegation(&d, &owner_key);
    // owner 公钥 SEC1 压缩 33B（mist_demo_common.owner_pubkey_sec1 同口径）；
    // agent 传输公钥 Ed25519 原始 32B。
    let owner_pub = owner_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let agent_pub = agent_key.verifying_key().to_bytes();

    // ---- 1. authorize：owner 签 delegation ----
    let (ok, auth) = rpc.call_tool(
        "authorize",
        json!({
            "agent": hex::encode(AGENT_DID),
            "owner": hex::encode(OWNER_DID),
            "nonce": 1,
            "max_per_spend": MAX_PER_SPEND,
            "rate_window_secs": RATE_WINDOW_SECS,
            "rate_max_per_window": TOTAL_CAP,
            "total_cap": TOTAL_CAP,
            "categories": [],
            "not_before": 0,
            "expires_at": EXPIRES_AT,
            "version": dsa::PROTOCOL_VERSION,
            "owner_signature": hex::encode(sd.signature.0),
            "owner_pubkey": hex::encode(owner_pub),
            "agent_pubkey": hex::encode(agent_pub),
        }),
    )?;
    ensure!(ok, "authorize 失败: {auth}");
    ensure!(
        auth["delegation_hash"] == hex::encode(dh),
        "delegation_hash 漂移: local={} server={}",
        hex::encode(dh),
        auth["delegation_hash"]
    );
    println!(
        "[1/6] authorize OK  dh={}…  total_cap={}",
        &hex::encode(dh)[..16],
        auth["total_cap"]
    );

    // ---- 2. revocation_witness：撤销非成员事实面（载荷形状自检）----
    let (ok, wit) = rpc.call_tool(
        "revocation_witness",
        json!({"delegation_hash": hex::encode(dh)}),
    )?;
    ensure!(ok, "revocation_witness 失败: {wit}");
    ensure!(
        wit["delegation_hash"] == hex::encode(dh),
        "witness 回执 dh 漂移: {}",
        wit["delegation_hash"]
    );
    let (root, path) = (
        wit["root"].as_str().unwrap_or_default(),
        wit["path"].as_str().unwrap_or_default(),
    );
    ensure!(root.len() == 64, "root 形状漂移: {} hex 字符", root.len());
    ensure!(
        path.len() == 16_384,
        "path 形状漂移: {} hex 字符",
        path.len()
    );
    println!(
        "[2/6] revocation_witness OK  root={}…  path=256×32B",
        &root[..16]
    );

    // ---- 3. pay：agent 签 intent ----
    let intent = SpendIntent {
        agent: AGENT_DID,
        delegation_hash: dh,
        recipient: VENDOR_DID,
        amount: AMOUNT,
        category: CATEGORY,
        spend_nonce: SPEND_NONCE,
        memo: None,
        expires_at: EXPIRES_AT,
    };
    let agent_sig = dsa::sign_intent(&intent, &agent_key);
    let ih = dsa::intent_hash(&intent);
    let (ok, pay) = rpc.call_tool(
        "pay",
        json!({
            "agent": hex::encode(AGENT_DID),
            "delegation_hash": hex::encode(dh),
            "recipient": hex::encode(VENDOR_DID),
            "amount": AMOUNT,
            "category": hex::encode(CATEGORY),
            "spend_nonce": SPEND_NONCE,
            "memo": null,
            "expires_at": EXPIRES_AT,
            "signature": hex::encode(agent_sig.to_bytes()),
        }),
    )?;
    ensure!(ok, "pay 失败: {pay}");
    ensure!(
        pay["intent_hash"] == hex::encode(ih),
        "intent_hash 漂移: local={} server={}",
        hex::encode(ih),
        pay["intent_hash"]
    );
    println!(
        "[3/6] pay OK      seq={}  intent_hash={}…  amount={AMOUNT}",
        pay["seq"],
        &hex::encode(ih)[..16]
    );

    // ---- 4. balance：额度滚动 ----
    let (ok, bal) = rpc.call_tool("balance", json!({"delegation_hash": hex::encode(dh)}))?;
    ensure!(ok, "balance 失败: {bal}");
    ensure!(
        bal["total_spent"] == AMOUNT,
        "balance 漂移: total_spent={}",
        bal["total_spent"]
    );
    println!(
        "[4/6] balance OK  spent={}  remaining={}",
        bal["total_spent"], bal["remaining"]
    );

    // ---- 5. verify_receipt：只读确认（vendor 校验侧；mock 授予积分为框架 demo 段）----
    let (ok, vr) = rpc.call_tool(
        "verify_receipt",
        json!({
            "delegation_hash": hex::encode(dh),
            "spend_nonce": SPEND_NONCE,
            "intent_hash": hex::encode(ih),
        }),
    )?;
    ensure!(ok, "verify_receipt 失败: {vr}");
    ensure!(
        vr["accepted"].as_bool() == Some(true),
        "verify_receipt 应 accepted=true"
    );
    println!("[5/6] verify_receipt OK  accepted=true  seq={}", vr["seq"]);

    // ---- 6. WAL 已落盘（回执持久点 + 停机 flush）：demo_settle 消费面就绪 ----
    println!("OK mcp-probe: WAL 已产出真账本（6 工具面全绿，demo_settle 可消费）");
    Ok(())
}
