# contracts —— 链上结算层（S-06 最小可跑 → S-11 生产化）

Phase 0 的链上部分：合约在 Anvil 上跑通"注册 → 撤销 → commit → settle → claim →
challenge"全链路。**S-06 为占位，S-11 生产化完成**：`BatchSettler` v2 完整挑战流
（fraud proof + 债券罚没 + epoch voided 回滚 + 延迟 claim），撤销根随 commit 锚定上链。

## 目录结构

```
src/
  DSA.sol              委托注册（Contract 模式 + 撤销锚点来源）
  RevocationRegistry.sol  撤销注册表（仅 owner 可撤销）
  BatchSettler.sol     乐观批量结算 v2（operator 守卫 / commit 锚定撤销根 / settle 存
                       net[]+结算资金 / 延迟 claim / challenge 完整验证 + 罚没）
  IntentHelper.sol     intent_hash 规范编码镜像（与 meridian-core dsa.rs 逐字节一致）
  Merkle.sol           sha256 包含验证器（EMPTY_LEAF + next_power_of_two 树深）
test/
  DelegationHelper.sol   与 meridian-core 逐字节一致的 canonical 编码（测试库）
  InternalHarnesses.sol  外部包装合约，让 vm.expectRevert 能捕获内部库 revert
  DSA.t.sol              7 个用例
  RevocationRegistry.t.sol 3 个用例
  BatchSettler.t.sol     31 个用例（挑战正反/去重/跨收款人/窗口/罚没账/void 后 claim）
  IntentHelper.t.sol     5 个用例（golden vector 对 Rust 计算值）
  Merkle.t.sol           7 个用例（已知向量对 Rust merkle_root）
rust-smoke/            alloy 链上集成冒烟（TEMPORARY，S-11d 并入 Anvil 端到端）
foundry.toml           solc 0.8.24 / cancun / via_ir
foundry.lock           forge-std v1.9.6（rev 3b20d60）
```

## 交叉实现契约

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

S-11 新增两处交叉实现：
- `IntentHelper.computeIntentHash` —— intent_hash 规范 preimage（`INTENT_PREFIX=b"INTv1\0"`
  + agent/dh/recipient/amount/category/spend_nonce/memo_tag/expires_at，全小端），与
  `core/src/dsa.rs::intent_hash` 逐字节一致；欺诈证明的链上重算侧。
- `Merkle.computeRoot/leaf/treeDepth` —— 承诺格 sha256 树（叶 = sha256(seq_le(8)‖ih)，
  补齐空叶 = sha256("")），与 `aggregator/src/merkle.rs` 对齐；Rust `inclusion_proof`
  生成的兄弟路径经 `ChallengeTestHelper.proofFor` 逐字节对齐 Solidity 验证器。

## 本机验证

```bash
cd contracts
forge build
forge test          # 53 用例全绿
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
5. **`vm.expectRevert(bytes4)` 匹配不了带参自定义 error**——需
   `abi.encodeWithSelector(Err.selector, arg)`；**内部库调用 revert 也捕获不了**（
   `expectRevert` 只捕外部调用）——用 `InternalHarnesses.sol` 外部包装。

## CI（.github/workflows/ci.yml `solidity` job）

CI 直接下载钉死版本 `v1.7.1` 的官方 release 产物（绕开 foundryup：其落点依赖
`${XDG_CONFIG_HOME:-$HOME}`，与 `$HOME/.foundry` 不一致）→ `forge install`（按
foundry.lock）→ `forge build` + `forge test` → alloy 冒烟（`cargo run`，自动 spawn anvil）。
**主门禁已迁本地 `scripts/verify.sh`**（GitHub 私有 Actions 被账户计费卡死，见
MASTER_PLAN S-10d），CI 降级为可选二道网。

## 决策记录

- 三合约合一层（不再分多文件单例）：DSA 做委托注册 + 撤销锚点来源，BatchSettler
  只管结算，RevocationRegistry 独立成表 —— 与 S-10/S-11 聚合器对接路径对齐。
- `sha256`（非 keccak）作 delegation_hash：让 Solidity 预编译与 Rust `sha2`
  原生对齐，避免 EVM keccak ↔ 链下 sha2 的往返不一致。
- **S-11 结算资产 = 原生 ETH**（用户决策 2026-08-17）：bond = `msg.value`；settle 携带
  `msg.value ≥ Σnet` 作结算资金源；claim 付原生 ETH。USDC/ERC-20 推迟 Phase 2——
  `NetInstruction { recipient, amount }` 形状不变，资产置换不动净额结构。
- **延迟 claim**（用户决策）：settle 记 net 列表+根；挑战窗口过后收款人逐条 `claim()`；
  挑战成功 → epoch voided → claims 拒绝。挑战与 claim 严格时间分离 → 挑战成功时无任何
  claim 已付，`settlementFunded` 退款干净。
- **`operator` 守卫必须加**：无守卫时任何人可拿自洽 net[] settle 已提交 epoch → 挑战成功
  → 运营者债券被罚没（griefing，无对手方获利）。
