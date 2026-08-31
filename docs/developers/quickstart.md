# 快速上手（5 分钟）

三个前置：**Rust**（工具链见 `rust-toolchain.toml`）、**foundry**（`anvil` / `forge`，
Linux 或 WSL 均可用；Windows 用同款可执行文件）、可选 **nargo/bb**（ZK 门禁，仅 Linux）。

```sh
git clone <mist-repo> && cd mist
cargo build --workspace            # 首次编译较久；或直接跑下面的命令（自动编译）
```

## 1. 门禁自检（30 秒）

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

三行全绿即地基健康（fmt / clippy `-D warnings` / 测试——测试含聚合器内核、WAL 崩溃恢复、
SDK 幂等 e2e、MCP 集成共一百多个）。

## 2. M1 端到端 demo（亲眼看到 10 万笔 → 净额结算）

这是里程碑验收 demo：agent 持 DSA → ZK 授权缝 → 聚合器顺序提交 **10 万笔** → 承诺根/净额
根交叉验算 → BatchSettler 链上净额结算（100 个收款人收精确净额）→ WAL 崩溃恢复续接。
自动拉起本地 Anvil（临时链），全绿退出。

```sh
cd contracts/rust-smoke
cargo run --release --bin m1_demo      # ~4s（release）；debug 下 100k 笔约 9 分钟
```

输出末尾：

```
OK M1: 聚合器 10 万笔顺序提交 3.49s（28668 笔/s），seq==提交序，total_spent=50050000
OK M1: BatchSettler commit→settle→过挑战窗→claim 全绿，100 收款人收精确净额
OK: M1 端到端 demo 全部通过
```

## 3. 框架闭环（3 家 demo 同一条链路）

```sh
cargo build -p mist-mcp --release   # MCP 服务器（内嵌真实聚合器，stdio）
cd demos
PYTHONIOENCODING=utf-8 .venv/Scripts/python.exe langchain_demo.py
PYTHONIOENCODING=utf-8 .venv/Scripts/python.exe autogen_demo.py
cd eliza && node eliza_client.mjs
```

三个 demo 跑**同一闭环**：`authorize`（owner secp256k1 签 delegation）→ `pay`（agent
Ed25519 签 intent，付 vendor）→ `balance`（额度滚动）→ `verify_receipt`（回执确认）→
**脚本内置 mock vendor** 凭回执授予 API 积分。每步内建自检：本地重算的 hash 与服务器回执
逐字节对得上。

依赖安装（`demos/` 下，版本 pinned）：`uv venv` + `langchain-mcp-adapters` /
`autogen-ext[mcp]` / `mcp` + `coincurve` / `cryptography`；eliza 目录 `npm i`。
`character.json`（官方 `@elizaos/plugin-mcp` 配置面）按本机绝对路径自动生成，不入库。

## 4. 第一笔集成（SDK 三行）

以"替 owner 花钱"为例（Rust，`sdk/`）：

```rust
use mist_sdk::{SdkClient, PayParams};

// 1) 注册委托：owner 私钥签发 DSA 授权给 agent，限制单笔/窗口/总额
let mut client = SdkClient::in_process(owner_key, agent_key, limits)?;
client.authorize()?;                                 // 本地限额校验 + 提交注册

// 2) 幂等支付：固定 spend_nonce，断线重试不双花（聚合器侧幂等兜底）
let receipt = client.pay(&PayParams {
    recipient: vendor_did, amount: 42, category: CAT_QUERY,
    spend_nonce: 1, ..Default::default()
})?;
// receipt.seq —— 这笔在全网账本里的序号（可作"支付凭证"）

// 3) 双钥绑定凭据：agent 传输身份 ↔ 电路签名公钥。真 prover 路径（SdkClient::with_noir
//    装配 NoirProver）用 attest_identity()：公钥从 attestation_secret 经 Noir 曲线 oracle
//    派生，与 pay() 证明的 agent_commit 同一来源（S-46 同源自洽）。离线/外部注册流才显式
//    传公钥：attest(&attestation_pubkey)
let cred = client.attest_identity()?;
```

不需要 Rust？agent 框架走 MCP（第 3 步）即可，6 个工具覆盖 authorize / pay / balance /
attest / verify_receipt / revocation_witness，密钥（及 ZK 证明）由框架侧持有（服务器
keyless，S-52：pay 可选 proof 直通真 ZK 证明，服务器只验证）。

## 下一步

- **三选一角色**：→ [集成指南](integration.md)
- **代码契约**：→ `docs/TECH_SPEC.md`（规范编码、WAL 格式、预算规则、门禁口径）
- **性能信条与 PoC 实测**：→ `docs/poc/*.md`
