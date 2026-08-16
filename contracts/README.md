# contracts —— 链上结算层（S-06 最小可跑版）

Phase 0 的链上部分：三个最小合约（TECH_SPEC §7）在 Anvil 上跑通
"注册 → 撤销 → commit → settle" 全链路。**S-08 前为桩，生产化在 S-11。**

## 目录结构

```
src/
  DSA.sol              委托注册（Contract 模式 + 撤销锚点来源）
  RevocationRegistry.sol  撤销注册表（仅 owner 可撤销）
  BatchSettler.sol     乐观批量结算（commit 债券 / settle / challenge 窗口）
test/
  DelegationHelper.sol   与 meridian-core 逐字节一致的 canonical 编码（测试库）
  DSA.t.sol              7 个用例
  RevocationRegistry.t.sol 3 个用例
  BatchSettler.t.sol     9 个用例
rust-smoke/            alloy 链上集成冒烟（TEMPORARY，S-08 前并入部署脚本）
foundry.toml           solc 0.8.24 / cancun / via_ir
foundry.lock           forge-std v1.9.6（rev 3b20d60）
```

## 交叉实现契约（S-06 的核心约束）

`DSA.sol::registerDelegation(bytes delegationABI, bytes ownerSig)` 在链上重算
`delegation_hash = sha256(delegationABI)`，owner 从 ABI 的字节区间 `[26:46]`
（`"DSAv1\0"` 6 字节前缀 + agent 20 + owner 20）解析。**链下 meridian-core 的
`delegation_hash` 必须与链上一致** —— Rust `sha2` ↔ Solidity `sha256` 预编译
双向验收（forge 测试 + rust-smoke 都断言了这一点）。

- canonical 编码：`DELEGATION_PREFIX = b"DSAv1\0"`，随后 agent(20) owner(20)
  nonce u64LE max_per_spend u64LE window_secs u64LE max_per_window u64LE
  total_cap u64LE categories_len u32LE categories(32×n) not_before u64LE
  expires_at u64LE version u8。
- owner 签名：secp256k1 prehash ECDSA，**强制低位 s**（`n/2` 上限）。`DSA.sol`
  对 `s > SECP256K1N_HALF` 直接 `revert HighS()`，因此签发侧必须规范化（
  `core/src/dsa.rs::sign_delegation` 已做）。

## 本机验证

```bash
cd contracts
forge build
forge test          # 19 用例全绿
cd rust-smoke && cargo run   # anvil 部署 + 全链路（需先 forge build 产出 out/）
```

## alloy 版本锁定

- alloy `2.4`（`sol-types` + `signer-local` + `provider-anvil-api` 特性）。
- 2.x 与 1.x API 差异：recommended fillers 默认开启（无需
  `with_recommended_fillers`）；`connect_http(Url)` 不返回 Result；单返回值
  `.call().await?` 直接是值本身；`TransactionBuilder` trait 需显式 `use`。

## 已知坑（已记录）

1. **anvil 只预置 mnemonic 前 10 个账户（#0–#9）**。自定义私钥（如 owner
   `[7;32]`）余额为 0，任何发送交易都会 `-32003 Insufficient funds`。rust-smoke
   在 revoke 前用 `anvil_setBalance` 给 owner 注资（`provider-anvil-api` 特性）。
2. **nargo 1.0 的 git 依赖只认 `tag`**（见 `circuits/README.md`）。
3. **`bytes.concat` 多参数 stack-too-deep** → `via_ir = true`（foundry.toml）。
4. **forge-std 安装**：`forge install forge-std=foundry-rs/forge-std@v1.9.6`
   （alias= 形式）；`contracts/lib/`、`out/`、`cache/` 在 .gitignore 中，CI 各自安装构建。

## CI（.github/workflows/ci.yml `solidity` job）

foundryup 钉 `v1.7.1`（与本机对齐）→ `forge install`（按 foundry.lock）
→ `forge build` + `forge test` → alloy 冒烟（`cargo run`，自动 spawn anvil）。

## 决策记录

- 三合约合一层（不再分多文件单例）：DSA 做委托注册 + 撤销锚点来源，BatchSettler
  只管结算，RevocationRegistry 独立成表 —— 与 S-10/S-11 聚合器对接路径对齐。
- `sha256`（非 keccak）作 delegation_hash：让 Solidity 预编译与 Rust `sha2`
  原生对齐，避免 EVM keccak ↔ 链下 sha2 的往返不一致。
