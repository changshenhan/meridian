# `circuits/` — ZK 授权电路（Noir）

`spend_authorization`：DSA 授权电路（TECH_SPEC §5，S-05 去 ECDSA 最小版）。
本文档是 S-05 的**决策记录**与工具链锁定真相源；MASTER_PLAN 与 TECH_SPEC 引用这里。

## 工具链锁定

| 组件 | 版本 | 安装 | 说明 |
|---|---|---|---|
| `nargo` | `v1.0.0-beta.26` | `noirup --version 1.0.0-beta.26` | Noir 编译器。**无 prove/verify 子命令**（proving 外移到 `bb`） |
| `bb`（Barretenberg） | bbup 默认（CI 记录 `bb --version`） | `bbup` | UltraPlonk 后端；`write_vk` / `prove` / `verify` |
| Rust 工具链 | `rust-toolchain.toml` | — | smoke-gen（TEMPORARY）在 Windows 本地即可构建 |

**平台事实（S-05 决策）**：nargo v1.0.0-beta.26 无法在 Windows 构建（`termion` 仅 unix 的硬依赖，
无 feature 可关），且该版本无 Windows 预编译二进制。因此**本地 Windows 只做 Rust 侧
（core + smoke-gen）；ZK 电路的 compile / test / 约束数 / prove-verify-回读 全部在 CI 跑**
（`.github/workflows/ci.yml` 的 `noir` job，ubuntu-latest）。电路改动后请 push 到 CI 验证。

**字节码版本配对**：nargo 与 bb 的 bytecode 必须匹配。CI 首次运行如报不匹配，按报错
调整 bb 版本一次并回写本表（bbup 默认通常即配 beta.26）。

## 外部库清单（git tag 锁定，Noir 1.0 已把下列移出 stdlib）

| 库 | tag | 用途 |
|---|---|---|
| `eddsa` | `v0.1.3` | BabyJubJub + Poseidon 的 EdDSA：agent attestation key 验签（`eddsa_verify`） |
| `ec` | `v0.1.2` | eddsa 下游依赖；**仅测试用**——构造在曲线上的 R8 点（`baby_jubjub().curve.mul(...)`） |
| `poseidon` | `v0.1.1` | eddsa 库的 hasher（`PoseidonHasher`） |
| `sha256` | `v0.3.0` | `agent_commit` 承诺哈希（链下 Rust `sha2` 复现同一规范，见下） |

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
  src/main.nr       电路 + 正/负向黑箱测试（#[cfg(test)]）
  smoke/            TEMPORARY 冒烟电路（仅 stdlib）
  smoke-gen/        独立 Rust workspace；生成 smoke 的 Prover.toml（k256，确定性）
```
