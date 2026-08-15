# `circuits/` — ZK 授权电路（Noir）

`spend_authorization`：DSA 授权电路（TECH_SPEC §5，S-05 去 ECDSA 最小版）。
本文档是 S-05 的**决策记录**与工具链锁定真相源；MASTER_PLAN 与 TECH_SPEC 引用这里。

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
| attestation key | BabyJubJub | 对 `message`（签名对象）签 EdDSA | **电路内** `eddsa_verify` |

绑定协议：注册时 `sign_binding(Ed25519_sk, jubjub_pk)`，签名对象 =
`b"MERIDIAN-BINDING-v1\0" || pub_x_le || pub_y_le`；`agent_commit = sha256(pub_x_le || pub_y_le)`。
绑定验证在**电路外做一次**（`core/src/attestation.rs`），电路只解 `agent_commit` 承诺。
详见 `core/src/attestation.rs` 头注释与测试。

**链下一电路承诺一致性约束**：`agent_commit` 的规范 = `sha256(x_le32 || y_le32)`，两侧实现
（Rust `sha2` 与 Noir `sha256::digest`）必须一致。任何一侧改动需双端测试同步改。

## 电路断言（S-05 范围）

1. `sha256(pub_x_le || pub_y_le) == agent_commit`（承诺解承诺）
2. `eddsa_verify(pub, sig, message) == true`（agent 对签名对象的 EdDSA）
3. `amount <= max_per_spend`
4. `categories_len == 0`，或 `category ∈ categories`（空白名单不要求）
5. `not_before <= now <= expires_at`
6. `delegation_hash[0] > 0`（公共锚点非零，证明绑定真实委托上下文）

完整版（owner secp256k1 ECDSA + 撤销 Merkle 非成员 + `intent_hash` 字段级绑定）→ S-09。

## 约束数记录（S-05 验收）

- **位置**：CI `noir` job 的 `nargo info` 输出（当前 ACIR + bytecode witness 计数）。
- 记录方式：首次 CI 绿后，把 `nargo info` 的约束数回填到 TECH_SPEC §5.5 预算表
  （约束目标 < 2^18 含 S-09 的 ECDSA+Ed25519+merkle，S-05 最小版应显著低于该上限）。
- 每次电路改动：约束数变化需在 PR 描述里说明，避免无解释的膨胀。

## `smoke/` — TEMPORARY 管线脚手架（不进文档/SPEC）

`circuits/smoke`（secp256k1 blackbox）+ `circuits/smoke-gen`（Rust，k256 确定性签名）+ 
`scripts/smoke_zk.sh` / `scripts/smoke_readback.py`：在 CI 上把
`nargo compile → execute → bb write_vk → prove → verify → 公共输入回读 → 负向篡改` 全链路
先跑通，为正式电路铺路。代码内已标注 TEMPORARY；验证完成后删除。**不允许**把该脚手架
写进 TECH_SPEC / 文档（secp256k1 blackbox 仅作 smoke-test 脚手架，不是 DSA 设计）。

## 目录

```
circuits/
  Nargo.toml        spend_authorization 包（外部库 git-tag 锁定）
  src/main.nr       电路 + 正/负向黑箱测试（Noir 1.0：mod tests + #[test]，无 cfg）
  smoke/            TEMPORARY 冒烟电路（仅 stdlib）
  smoke-gen/        独立 Rust workspace；生成 smoke 的 Prover.toml（k256，确定性）
```
