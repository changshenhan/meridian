# `circuits/` — ZK 授权电路（Noir）

`spend_authorization`：DSA 授权电路完整版（TECH_SPEC §5，S-05 去 ECDSA 最小版 +
S-09 intent_hash 字段级绑定 + 撤销 Merkle 非成员）。本文档是 S-05/S-09 的**决策记录**
与工具链锁定真相源；MASTER_PLAN 与 TECH_SPEC 引用这里。

## 工具链锁定

| 组件 | 版本 | 安装 | 说明 |
|---|---|---|---|
| `nargo` | `v1.0.0-beta.26` | `noirup --version 1.0.0-beta.26` | Noir 编译器。**无 prove/verify 子命令**（proving 外移到 `bb`） |
| `bb`（Barretenberg） | `6.0.0-nightly.20260724` | `bbup --version 6.0.0-nightly.20260724` | UltraPlonk 后端；`write_vk` / `prove` / `verify` |
| Rust 工具链 | `rust-toolchain.toml` | — | smoke-gen（TEMPORARY）在 Windows 本地即可构建 |

**平台事实（S-05 决策）**：nargo v1.0.0-beta.26 无法在 Windows 构建（`termion` 仅 unix 的硬依赖，
无 feature 可关），且该版本无 Windows 预编译二进制。因此**本地 Windows 只做 Rust 侧
（core + smoke-gen）；ZK 电路的 compile / test / 约束数 / prove-verify-回读 全部在 CI 跑**
（`.github/workflows/ci.yml` 的 `noir` job，ubuntu-latest）。电路改动后请 push 到 CI 验证。

**字节码版本配对（已解析）**：nargo v1.0.0-beta.26 未入 bbup 的 `bb-versions.json`（最细到
beta.22），bbup 默认（查询 nargo）会失败。配对依据 = noir v1.0.0-beta.26 的
`EXTERNAL_NOIR_LIBRARIES.yml` 钉的 aztec-packages commit `0e7787a`（2026-07-24）→
barretenberg `v6.0.0-nightly.20260724`。升级任何一侧都要重查此配对。

## 外部库清单（git tag 锁定，Noir 1.0 已把下列移出 stdlib）

| 库 | 锁定 | 用途 |
|---|---|---|
| `eddsa` | fork tag `v1.0-7e206c9`（changshenhan/eddsa，指向 1.0 端口 commit `7e206c9`） | BabyJubJub + Poseidon 的 EdDSA：agent attestation key 验签（`eddsa_verify`） |
| `edwards` | `v0.2.5` | **仅测试用**——构造在曲线上的 R8 点（`Curve { x, y }.mul(ScalarField::<63>::from(...))`）。替代 eddsa 0.x 时代的 `ec` |
| `poseidon` | `v0.3.0` | eddsa 库的 hasher（`PoseidonHasher`） |
| `sha256` | `v0.3.0` | `agent_commit` 承诺哈希（链下 Rust `sha2` 复现同一规范，见下） |

> **eddsa tag 陷阱（S-05 CI 首跑实测失败 → 决策记录）**：eddsa 最新 tag `v0.1.3` 仍是 Noir 0.x
> API（内部用已被移除的 `u1` 类型 + 0.x comptime-global 模式），与 nargo v1.0.0-beta.26 不兼容
> （CI run 31903435847：44 个编译错误，全数来自 `ec` v0.1.2 / `poseidon` v0.1.1 两个传递依赖）。
> 修复一：改用 eddsa@main 的 1.0 端口（commit `7e206c9`，2026-04-08，`compiler_version = ">=1.0.0"`，
> 0 个 `u1`）——`eddsa_verify` / `eddsa_to_pub` API 与测试向量完全一致；其 `ec` 依赖换成
> `noir-edwards` v0.2.5，`poseidon` 升到 v0.3.0。
> 修复二（CI run 31904604734 实测）：nargo 1.0 的 git 依赖**只认 `tag` 键**，`rev = ...` 直接
> "Git dependencies must have a `tag` key" 解析失败。上游没有 1.0 兼容 tag → 把 7e206c9 fork
> 到 `changshenhan/eddsa` 并打 tag `v1.0-7e206c9` 锁定。tag 指向的 SHA 由我们控制（永不移位），
> 比上游 rev 更稳；该 fork 只是"git tag 锁定"机制的载体，不 fork 维护、不改一行源码。

> 锁定方式：`Nargo.toml` 里按 git + tag 引用。升级必须改 tag + CI 全绿 + 约束数记录更新，
> 不允许 "latest" 漂移。`nargo fetch` 按 lockfile 固化。

## 双钥绑定（D-05 扩展，S-05 决策记录）

S-02 的 Ed25519（NodeId）**保持传输层身份，不改已验收代码**。ZK 授权新增一把 attestation key：

| 钥 | 曲线 | 用途 | 验证位置 |
|---|---|---|---|
| NodeId | Ed25519 | 传输身份、注册时**绑定签名**的签发钥 | 电路外快路径（S-02，Rust） |
| attestation key | BabyJubJub | 对 `encode_field(intent_hash)` 签 EdDSA（S-09：签名对象 = intent_hash 31B LE 编码，不再是裸 message） | **电路内** `eddsa_verify` |

绑定协议：注册时 `sign_binding(Ed25519_sk, jubjub_pk)`，签名对象 =
`b"MERIDIAN-BINDING-v1\0" || pub_x_le || pub_y_le`；`agent_commit = sha256(pub_x_le || pub_y_le)`。
绑定验证在**电路外做一次**（`core/src/attestation.rs`），电路只解 `agent_commit` 承诺。
详见 `core/src/attestation.rs` 头注释与测试。

**链下一电路承诺一致性约束**：`agent_commit` 的规范 = `sha256(x_le32 || y_le32)`，两侧实现
（Rust `sha2` 与 Noir `sha256::digest`）必须一致。任何一侧改动需双端测试同步改。

## 电路断言（S-09 范围，对齐 TECH_SPEC §5.2）

1. `sha256(pub_x_le || pub_y_le) == agent_commit`（承诺解承诺）
2. `eddsa_verify(pub, sig, encode_field(intent_hash)) == true`（agent 对签名对象的 EdDSA）
3. `amount <= max_per_spend`
4. `categories_len == 0`，或 `category ∈ categories`（空白名单不要求）
5. `not_before <= now <= expires_at`
6. `delegation_hash[0] > 0`（公共锚点非零，证明绑定真实委托上下文）
7. `spend_nonce > 0`（防零 nonce 误用）
8. `compute_merkle_root(EMPTY, index, path) == revocation_root`（撤销非成员，叶子=EMPTY）
9. `intent_hash == sha256(agent_commit ‖ delegation_hash ‖ recipient ‖ amount_le ‖
   category ‖ spend_nonce_le ‖ expires_at_le)`（字段级绑定，140B 规范字节）

owner 的 secp256k1 ECDSA **电路外验证**（S-09 决策）：链上 `DSA.sol::registerDelegation`
强制 + S-02 `verify_delegation` 已验收 + `attestation.rs` 双钥绑定；电路只锚定
`delegation_hash`。

**签名对象编码**：`encode_field(intent_hash)` = 低 31 字节 LE 截断 → Field（248-bit <
BN254 域，单射；断言 9 在电路内钉死完整 intent_hash → 无 mod-p 碰撞可乘）。

**撤销树**：深度 256 稀疏 Merkle（S-36 全宽化），叶子=EMPTY(0)，索引 = `delegation_hash`
全 32 字节 LE u256（位 k = `(dh[k/8] >> (k%8)) & 1`，按字节现场派生——索引不落单个 Field，
BN254 域仅 ~254 bit；与聚合器 `RevocationSet` 同一派生同一位序）。
`std::merkle` 已移出 Noir 1.0 stdlib → 内联 `compute_merkle_root`（merkle_insert 模式，
`std::hash::pedersen_hash`）。原型级碰撞属性（两 delegation 同 32-bit 前缀共享叶子→撤销
共享）两侧均已收口：聚合器 S-34、电路 S-36（回归测试 `full_width_index_collides_prefix_only`
固化）。

## 约束数记录（S-05 验收 + S-09 正式门禁）

- **位置**：CI `noir` job 的 `nargo info` 输出 + 正式管线 `bb gates`（formal_bench.py）。
- 记录方式：首次 CI 绿后，把约束数回填到 TECH_SPEC §5.5 预算表（约束目标 < 2^18）。
- **硬门禁**：formal_bench.py 断言 `bb gates` 的 circuit_size < 2^18，超了 CI 红。
- **bb 子命令名（CI run 31933654531 实测）**：bb 6.0.0-nightly.20260724 无 `info` / `contract`
  子命令，门数用 `bb gates -b <acir>`（输出 `{"functions":[{"circuit_size":G}]}`），
  EVM 验证器用 `bb write_solidity_verifier -t evm-no-zk -k vk -o out.sol`。升级 bb 需复查子命令名。
- **Flavor 一致性（CI run 31933941769 实测）**：`write_solidity_verifier` 硬编码
  `UltraKeccakFlavor::VerificationKey`（oracle_hash=keccak + disable_zk）。因此
  `write_vk` / `prove` / `verify` 必须统一加 `-t evm-no-zk`，否则默认 poseidon2 的
  UltraFlavor VK（3680B）与 keccak VK（1888B）尺寸不匹配（`expected 1888, got 3680`）。
- 每次电路改动：约束数变化需在 PR 描述里说明，避免无解释的膨胀。

## `gen-witness/` — 正式电路 witness 生成器（S-09c）

仓库根的 `gen-witness`（Noir 包）：确定性生成正式电路的 witness——Noir 内做
`eddsa_challenge`（镜像电路的 `eddsa_verify` 的 Poseidon 域，输出 `(r, h, r8.x, r8.y)`）
+ 撤销稀疏树建树/寻路（`unconstrained` brillig 递归 `subtree_root`；S-05 教训：不做跨语言
曲线数学）。**签名标量 `s = (r + h·secret) % SUBORDER` 由 build 脚本用 Python 大整数计算**：
Noir 1.0 移除了 Field 模运算（`%` 编译报错，eddsa fork 自身测试亦注明 "fields can't use
modulo"），且 `ScalarField` 无算符、`base4_slices` 为 `pub(crate)`——mod-n 归约在 Noir 内
无法做。该归约是纯整数逻辑（非曲线数学；R8/h/公钥仍在 Noir），与 Rust core 的纯字节逻辑
同级，端到端由正式电路 `eddsa_verify`（CI prove）把关：s 错则证明失败。Rust core 侧只做
纯字节逻辑（`zk_intent_hash`；撤销索引自 S-36 起即 `delegation_hash` 本身，无独立派生）。

`nargo execute --overwrite-return` 把返回值（EdDSA 挑战/pubkey/撤销 root+path/intent_hash）
写入 `gen-witness/Prover.toml` 的 `return` 键 → `scripts/formal_gen_to_prover.py`
（**第三实现**交叉校验：Python hashlib 独立复算 `agent_commit` 与 `intent_hash`，防三侧
漂移；另算 `sig_s` 并校验 `0 ≤ s < SUBORDER`）→ `circuits/Prover.toml`。固定场景常量在
`gen-witness/Prover.toml` 与 build 脚本两处定义，build 脚本读回输入键即交叉校验（防漂移）。
`circuits/Prover.toml` 为生成物，gitignore。

## `scripts/formal_zk.sh` — S-09 正式管线（非 TEMPORARY）

`gen-witness → Prover.toml → nargo execute → bb write_vk/prove/verify → 公共输入回读
（121 fields，formal_readback.py）→ 负向篡改（spend_nonce → 求解必失败）→ B2/B3/B4 计时
基线 + 约束门禁（formal_bench.py）→ `bb write_solidity_verifier` EVM 验证器（`circuits/artifacts/`，
Phase 4 复用）。B2 证明 p50<1s / B3 单验证 p99<10ms（bb CLI 进程含开销上界）/ B4 批验证
摊薄待 Phase 4 in-process wrapper。基线报告 `circuits/bench/baseline_s09.json` 由 CI
upload-artifact 交付。smoke 保持 TEMPORARY 原状，不作为正式基线。

## `smoke/` — TEMPORARY 管线脚手架（不进文档/SPEC）

仓库根的 `smoke`（secp256k1 blackbox）+ `circuits/smoke-gen`（Rust，k256 确定性签名）+ 
`scripts/smoke_zk.sh` / `scripts/smoke_readback.py`：在 CI 上把
`nargo compile → execute → bb write_vk → prove → verify → 公共输入回读 → 负向篡改` 全链路
先跑通，为正式电路铺路。代码内已标注 TEMPORARY；验证完成后删除。**不允许**把该脚手架
写进 TECH_SPEC / 文档（secp256k1 blackbox 仅作 smoke-test 脚手架，不是 DSA 设计）。
`smoke` 放在仓库根而非 `circuits/` 下，是 nargo 1.0 workspace 解析所致（顶层
Nargo.toml 即 workspace 根，且禁止 [package]+[workspace] 同文件），见 `smoke/Nargo.toml` 注释。

## 目录

```
circuits/
  Nargo.toml        spend_authorization 包（外部库 git-tag 锁定）
  src/main.nr       电路 + 正/负向黑箱测试（Noir 1.0：mod tests + #[test]，无 cfg）
  smoke-gen/        独立 Rust workspace；生成 smoke 的 Prover.toml（k256，确定性，TEMPORARY）
gen-witness/
  Nargo.toml        S-09 正式电路 witness 生成器（顶层包，避开支 workspace 嵌套）
  src/main.nr       eddsa_challenge（s 归约在 build 脚本）+ 撤销稀疏树建树/寻路 + 自检 #[test]
  Prover.toml       固定场景输入（nargo execute --overwrite-return 追加 return 键）
smoke/
  Nargo.toml        TEMPORARY 冒烟电路（仅 stdlib；顶层包，避开支 workspace 嵌套）
scripts/
  formal_zk.sh      S-09 正式管线编排（8 步）
  formal_gen_to_prover.py / formal_readback.py / formal_bench.py
```
