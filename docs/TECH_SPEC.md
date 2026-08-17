# MERIDIAN — 技术规格书
## L2 DSA 授权原语 + 结算聚合器 · v1.0（Phase 0 定稿版）

> 本规格是**绑定文档**：团队照此写代码。任何偏差须先改本文件、写明理由，再改代码。
> 对应蓝图：《Meridian_架构蓝图.md》 §3 L2/L3、§6.5 性能信条、§10 行动清单。
> 状态：**Phase 0 定稿（S-08c）**。性能预算表已回填 PoC 实测（§8.2 标注）；
> 未实测项仍为目标，以 `bench/` 实际测量为准，测量后回填并修订。

---

## 1. 目的与范围

本规格覆盖 Phase 0/1 需要开工的全部代码契约：

1. **DSA 授权原语**（L2 王冠）——委托模型、签名验证、两种执行模式。
2. **ZK 电路** `spend_authorization`——授权证明的输入输出与断言。
3. **结算聚合器**（L3）——摄取、排序承诺、批量结算、债券安全模型。
4. **预算账本**——速率/总额限额的确定性状态机。
5. **链上合约**——DSA 注册表、撤销注册表、批量结算器。
6. **性能测试用例与 CI 门禁**——§6.5 预算的可复现测量。

**不在本规格范围**：L1 身份层（.agent 域名）、L4 信任层、L5 编排层、客户端 SDK 的 UI、框架集成（MCP tool）——各自后续单独出 spec。

---

## 2. 术语与单位

| 术语 | 定义 |
|---|---|
| `Amount` | `u64`，账本/电路侧金额单位；链上结算按 S-11 用户决策用**原生 ETH**（wei，Solidity `uint256` 承接）。USDC 基础单位（1e-6 USD）推迟 Phase 2（§7 缝） |
| `Did` | 固定 20 字节（兼容 EVM 地址形态；`did:agent:<hex>` / `did:pkh:eip155:1:<hex>`） |
| `Delegation` | 主人签发、授予 agent 的委托消费凭证 |
| `SpendIntent` | agent 单笔消费意图 |
| `EnforcementMode` | `Contract`（合约强制）/ `ZkCredential`（零知识凭证） |
| `Epoch` | 聚合器出批次周期，默认 `10s` 或 `100_000` 笔，先到先出 |
| `RevocationRoot` | 撤销集合的稀疏 Merkle 根，作为电路公共输入 |

---

## 3. 工作区布局（monorepo）

```
meridian/
  spec/            # 本文件 + 各层规格
  core/            # Rust 核心引擎（lib）
    src/dsa.rs        # Delegation 模型 + 签名验证
    src/ledger.rs     # 预算账本状态机
    src/zk.rs         # 电路 host：Noir 证明/验证封装
    src/agg.rs        # 聚合器：摄取/排序/承诺/批次
    src/chain.rs      # 合约 ABI 绑定（alloy）
    src/error.rs
  noir/
    spend/            # spend_authorization 电路
    revocation/       # 撤销非成员电路（v1 并入 spend）
  contracts/       # Solidity
    DSA.sol
    RevocationRegistry.sol
    BatchSettler.sol
  sdk/             # agent 客户端 SDK（S-12：authorize/pay/attest + 幂等重试，见 §6.6）
  bench/           # 基准基座 + baseline.json + compare 工具
  tests/           # 单元 / property / 集成 / fuzz
```

---

## 4. L2 — DSA 授权原语

### 4.1 Delegation 数据结构

```rust
#[derive(Clone, Debug, PartialEq)]
pub struct Delegation {
    pub agent: Did,            // 被授权者
    pub owner: Did,            // 授权者（人类/企业）
    pub nonce: u64,            // 授权唯一编号；同时是撤销锚点
    pub max_per_spend: Amount, // 单笔上限
    pub rate: RateLimit,       // 窗口速率
    pub total_cap: Amount,     // 累计总上限（账本强制）
    pub categories: Vec<[u8; 32]>, // 类别白名单（哈希；空 = 不限制类别）
    pub not_before: u64,       // Unix 秒
    pub expires_at: u64,       // Unix 秒
    pub version: u8,           // 协议版本，当前 = 1
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateLimit {
    pub window_secs: u64,      // 窗口长度，默认 60
    pub max_per_window: Amount,
}

#[derive(Clone, Debug)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    pub signature: Signature,  // owner 的 ECDSA(secp256k1) over delegation_hash
}

pub fn delegation_hash(d: &Delegation) -> [u8; 32];
// 规范序列化：字段定序 + 类型前缀，禁止反序列化歧义（见 §11 E-03）
```

### 4.2 签名方案（决策）

| 角色 | 方案 | 验证位置 |
|---|---|---|
| owner 签名 Delegation | **ECDSA secp256k1**（人类=EVM 钱包，原生可验） | **电路外**（S-09 决策）：链上 `DSA.sol::registerDelegation` + S-02 `verify_delegation`；电路只锚定 `delegation_hash` |
| agent 签名 SpendIntent（传输身份） | **Ed25519**（NodeId，S-02） | 电路外快路径验签 |
| agent 签 intent_hash（ZK 授权） | **BabyJubJub + Poseidon EdDSA**（attestation key） | **电路内** `eddsa_verify`（§5.2 断言 2） |
| 批量证明/批次承诺 | Blake2b-256 | 快速、无 SHA-2 扩展攻击面 |

> 双钥绑定（D-05 扩展，S-05/S-09 决策记录）：NodeId 是传输层身份，注册时绑定
> attestation key（`core/src/attestation.rs`）；ZK 电路用后者签 intent_hash。记录在案：
> secp256k1 进电路贵（~2^18 约束）→ **v1 直接电路外验证**（链上 + S-02），不付该成本；
> Phase 2 再评估 BLS/曲线切换 + 批验证优化（§5.4）。

### 4.3 SpendIntent

```rust
#[derive(Clone, Debug, PartialEq)]
pub struct SpendIntent {
    pub agent: Did,
    pub delegation_hash: [u8; 32],
    pub recipient: Did,        // 收款方
    pub amount: Amount,
    pub category: [u8; 32],    // 类别哈希
    pub spend_nonce: u64,      // agent 作用域单调递增，防重放
    pub memo: Option<[u8; 32]>,// 可选备注（公开）
    pub expires_at: u64,       // 意图过期（秒），拒绝过期意图
}

pub fn intent_hash(i: &SpendIntent) -> [u8; 32];  // agent 的 Ed25519 签名对象
```

### 4.4 授权验证接口（core 对外契约）

```rust
// ---------- DSA 静态验证（不依赖账本） ----------
pub fn verify_delegation(sd: &SignedDelegation, owner_pub: &PublicKey) -> Result<(), Error>;

// ---------- ZK 模式 ----------
pub struct SpendProofRequest<'a> {
    pub sd: &'a SignedDelegation,
    pub intent: &'a SpendIntent,
    pub agent_keypair: &'a Keypair,    // agent 签名 possession 证明
    pub revocation_root: [u8; 32],     // 当前撤销根（链上观测）
    pub now: u64,
}

pub struct SpendProof {
    pub proof: Vec<u8>,                // Noir/BB 证明字节
    pub public_inputs: SpendPublicInputs,
}

// 对齐电路 §5.1（S-09）：owner 的 ECDSA 电路外（§5.2 断言 2），无 owner_commit；
// intent_hash 电路内派生，不作为公共输入；recipient/now 为 S-09 新增公共输入。
pub struct SpendPublicInputs {
    pub agent_commit: [u8; 32],        // sha256(pub_x_le || pub_y_le)
    pub delegation_hash: [u8; 32],
    pub recipient: [u8; 20],
    pub amount: u64,
    pub category: [u8; 32],
    pub spend_nonce: u64,
    pub expires_at: u64,
    pub revocation_root: [u8; 32],     // 撤销树根（公共锚点）
    pub now: u64,                      // 当前时间（断言 5）
}

pub trait SpendProver {
    fn prove(&self, req: &SpendProofRequest) -> Result<SpendProof, Error>;
}
pub trait SpendVerifier {
    fn verify(&self, proof: &SpendProof) -> Result<SpendPublicInputs, Error>;
    // 返回 pub inputs：聚合器用其登记账本，杜绝"证明的是 A、账本记 B"
}
```

> **已实现（S-10，`meridian-aggregator::proof::FormatVerifier`）**：TEMPORARY 后端口径——
> proof 非空 + `public_inputs` 与 intent 逐字段一致，返回值为登记 ground truth（§9）。
> S-09 实测真 ZK 单验证 7.62ms → 进 critical path 物理上到不了 100k/s（§5.4 分阶段）；
> 真实 in-process bb wrapper 是路线图单独交付物（Phase 2），插此接口即可，B5 口径不变。

### 4.5 预算账本（BudgetState）—— 确定性状态机

```rust
pub struct BudgetState {
    pub delegation_hash: [u8; 32],
    pub spent_in_window: Amount,
    pub window_start: u64,     // Unix 秒
    pub total_spent: Amount,
}

pub fn check_budget(
    d: &Delegation,
    state: &mut BudgetState,
    amount: Amount,
    now: u64,
) -> Result<(), Error>;
```

**规则（必须逐字实现，property test 覆盖）：**
1. `now < d.not_before || now > d.expires_at` → 拒绝 `E_DELEG_EXPIRED`。
2. 窗口回滚：`now >= state.window_start + d.rate.window_secs` → 重置 `spent_in_window = 0, window_start = now`。
3. `amount > d.max_per_spend` → 拒绝 `E_BUDGET_PER_SPEND`。
4. `state.spent_in_window + amount > d.rate.max_per_window` → 拒绝 `E_BUDGET_RATE`。
5. `state.total_spent + amount > d.total_cap` → 拒绝 `E_BUDGET_TOTAL`。
6. 全部通过才变更状态：`spent_in_window += amount; total_spent += amount`。
7. **并发**：账本按 `(agent, delegation_hash)` 分片，单写者；不同分片并行。

> 设计决策（记录在案）：**ZK 证明授权，账本执行预算。** 预算累计状态留在聚合器确定性账本（廉价、可并发、可审计），不进电路。代价：聚合器需诚实记账（用债券/惩罚约束，见 §6.5）。若未来需"预算隐私"，Phase 2 引入电路内累计（递归证明）。此决策是 v1 性能与正确性的平衡点。

### 4.6 撤销（Revocation）

- 链上 `RevocationRegistry`：`delegation_hash → revoked`。
- **电路侧**：撤销非成员证明——`delegation_hash` 对应叶子 = `EMPTY`（非成员），即未撤销。
  树深 32，索引 = `revocation_index(dh)` = `delegation_hash[0..4]` LE，叶子 = EMPTY(0)
  （Pedersen sparse merkle，§5.2 断言 8）。
- **聚合器侧（S-11 新增）**：`RevocationSet`（`aggregator/src/revocation.rs`）收集被撤销委托
  的 `delegation_hash`，`sparse_root()` 压实成 32B 根（**sha256** sparse merkle，索引 =
  `revocation_index(dh)`，叶子 = dh，空子树根表 `empty_roots[k]=sha256(empty_roots[k-1]‖
  empty_roots[k-1])`，O(32·|revoked|)；空根 golden `10ffc30c…304d` Python 交叉 + 朴素全树
  交叉验证）。撤销事件流：链上 revoke → 运营者调 `Aggregator::revoke(dh)`（WAL 追加
  `Revoke` 记录后入集，崩溃可重放重建）→ `submit()` 在注册表查找后立即查集，已撤销委托
  新意图一律 `E_REVOKED` 拒（最廉价闸口，不耗 nonce/窗口槽）→ 撤销根随**下个密封 epoch**
  的 `ChainPublisher::commit` 上链（S-11 验收：1 epoch 内进入撤销根）。
- 撤销即时性：聚合器拉取注册表延迟 ≤ 1 个 epoch；对"已撤销仍消费"的窗口期，用债券惩罚运营者（§6.5）。
- **诚实缝（非活跃错配，S-11 记录在案）**：聚合器撤销根是 **sha256** 树，电路根是
  **Pedersen** 树——内核用 `FormatVerifier` 从不读 `pi.revocation_root`，真正的 `E_REVOKED`
  闸口在 `submit()`；真对齐（聚合器算 Pedersen 树）推迟到真 ZK 集成（revocation.rs + 本行）。

### 4.7 两种模式映射（实现同一接口）

| 模式 | 路径 | 预算强制点 | 场景 |
|---|---|---|---|
| `Contract` | 模块化智能账户（ERC-4337/6900），DSA 作为 spend-policy 模块 | 链上合约 | 中额、低频、需即时链上可查 |
| `ZkCredential` ★ | 本 spec §5 电路 + 聚合器 | 聚合器账本 | 微额、高频、海量 |

两种模式最终都由 `BatchSettler` 净额结算。**S-11 起用原生 ETH**（bond = `msg.value`，
claim 付原生 ETH；`BatchSettler` v2，见 §7）。USDC/ERC-20 结算推迟 Phase 2（§7 缝：
接口已按 `recipient + amount` 指令形状设计，资产置换不动净额结构）。

---

## 5. ZK 电路 `spend_authorization`（Noir）

### 5.1 输入表

| 类别 | 名称 | 说明 |
|---|---|---|
| **Public** | `agent_commit` | `sha256(agent_pub_x_le ‖ agent_pub_y_le)` attestation 公钥承诺 |
| | `delegation_hash` | 绑定的委托哈希（公共锚点，断言 6 强制非零） |
| | `recipient` | 收款地址（20B，S-09 新增，绑定进 intent_hash） |
| | `amount` / `category` / `spend_nonce` / `expires_at` | 本笔消费字段（全部绑定进 intent_hash） |
| | `revocation_root` | 撤销树根（未撤销证明） |
| | `now` | 当前时间（断言 5 有效期窗口） |
| **Private** | `agent_pub_x` / `agent_pub_y` | 解承诺，验 agent EdDSA（断言 1） |
| | `sig_s` / `sig_r8_x` / `sig_r8_y` | agent 对 `encode_field(intent_hash)` 的 EdDSA（断言 2） |
| | `max_per_spend` / `categories` / `categories_len` / `not_before` | 委托相关字段（预算/白名单/有效期，断言 3-5） |
| | `revocation_path` | 稀疏 Merkle 非成员证明路径（叶子=EMPTY，深度 32，断言 8） |

**不存在的输入（S-09 决策）**：`owner_commit` / `owner_pubkey` / `owner_sig` 不进入电路
（owner ECDSA 电路外，见 §5.2 断言 2）；`intent_hash` 不再是公共输入——断言 9 在电路内
派生它（防止电路只验「签名对象」而不验「字段绑定」；聚合器以回读的公共输入为准登记）。

### 5.2 电路断言（证明即通过以下全部）

```
1. sha256(pub_x_le ‖ pub_y_le) == agent_commit            // attestation 公钥承诺解承诺
2. [owner ECDSA —— 电路外]                                  // 见下方决策记录
3. amount <= delegation.max_per_spend                       // 单笔限额
4. categories_len == 0，或 category ∈ categories            // 类别白名单（空白名单不要求）
5. delegation.not_before <= now <= delegation.expires_at    // 有效期
6. delegation_hash[0] > 0                                   // 公共锚点非零（S-05）
7. spend_nonce > 0                                          // 防零 nonce 误用
8. compute_merkle_root(EMPTY, index, path) == revocation_root  // 撤销非成员，叶子=EMPTY
9. intent_hash == sha256(agent_commit ‖ delegation_hash ‖ recipient ‖ amount_le ‖
                          category ‖ spend_nonce_le ‖ expires_at_le)  // 字段级绑定
   // intent_hash 电路内派生（不再作为公共输入），签名对象 = encode_field(intent_hash)。
   // encode_field = 低 31 字节 LE 截断 → Field（248-bit < BN254 域，单射）；
   // 断言 9 钉死完整 32B 哈希 → 无 mod-p 碰撞可乘。
```

**断言 2（owner ECDSA）电路外决策（S-09）**：owner 对 `delegation_hash` 的 secp256k1
签名**不进电路**。三层电路外强制：① 链上 `DSA.sol::registerDelegation` 校验委托签名并
存 `delegation_hash`；② S-02 `verify_delegation`（Ed25519 NodeId 绑定 + 委托验签，已验收）；
③ `core/src/attestation.rs` 双钥绑定（NodeId ↔ attestation key）。电路只锚定
`delegation_hash` 这一已链上登记、已验证绑定的公共锚点。secp256k1 blackbox 仅作 TEMPORARY
smoke 脚手架，**不作为设计**（见 §5.3 / `circuits/README.md`）。

**安全要点**：`intent_hash` 在电路内由 7 个公共输入（agent_commit、delegation_hash、
recipient、amount、category、spend_nonce、expires_at）按断言 9 的规范字节派生并绑定，签名对象经
`encode_field` 单射编码（断言 2）。聚合器登记账本时必须以 `SpendVerifier::verify` 返回的
公共输入（agent_commit / delegation_hash / recipient / amount / category / spend_nonce /
expires_at / revocation_root / now）为准（接口已设计成"返回即登记"，杜绝漂移）。

### 5.3 证明系统与工具链

- **Proving**：Noir（`nargo`）+ Barretenberg 后端（`bb`，**UltraHonk**）。版本**固定锁定**：
  nargo = v1.0.0-beta.26、bb = v6.0.0-nightly.20260724（字节码配对依据 = noir beta.26 的
  `EXTERNAL_NOIR_LIBRARIES.yml` 钉 aztec-packages commit 0e7787a）；完整工具链与平台事实见
  `circuits/README.md`（S-05/S-09 决策记录）。
- **验证路径**：nargo v1.0.0-beta.26 无法在 Windows 构建（`termion` 仅 unix，无 feature 可关），
  本地 Windows 只做 Rust 侧；电路 compile / test / 约束数 / prove-verify-回读 / 计时 / EVM
  验证器 全部在 CI（ubuntu，`.github/workflows/ci.yml` 的 `noir` job）执行。电路改动以 CI 绿为验收。
- **外部库（git 锁定；Noir 1.0 已把下列移出 stdlib）**：`eddsa` fork tag `v1.0-7e206c9`
  （changshenhan/eddsa，指向 1.0 端口 commit 7e206c9；v0.1.3 仍是 Noir 0.x `u1` API，与 beta.26 不兼容；
  nargo 1.0 git 依赖只认 `tag` → fork+tag 锁定）、`edwards` v0.2.5（测试构造曲线点，替代 `ec`）、
  `poseidon` v0.3.0、`sha256` v0.3.0（`agent_commit` 承诺哈希，链下 Rust `sha2` 同一规范）。
  清单与锁定方式见 `circuits/README.md`。
- **签名标量 s 的 mod-n 归约（S-09c 决策）**：Noir 1.0 移除 Field 模运算且 `ScalarField` 无算符
  → `s = (r + h·secret) % SUBORDER` 由 build 脚本（`scripts/formal_gen_to_prover.py`，Python
  大整数）计算；该归约是纯整数逻辑（R8/h/公钥仍在 Noir 内），端到端由正式电路
  `eddsa_verify`（CI prove）把关：s 错则证明失败。
- **撤销树**：内联 `compute_merkle_root`（`std::merkle` 已移出 Noir 1.0 stdlib，merkle_insert
  官方模式 + `std::hash::pedersen_hash`），深度 32，叶子=EMPTY(0)，index =
  `delegation_hash[0..4]` LE。原型级碰撞属性（两 delegation 同 32-bit 前缀共享叶子→撤销共享）
  ——真实树 S-11 对接 RevocationRegistry 时再设计。
- **EVM 验证器（Phase 4 复用）**：`bb write_solidity_verifier -t evm-no-zk -k vk -o UltraVerifier.sol`
  编译 Solidity 验证器（CI 产物 `circuits/artifacts/UltraVerifier.sol`）。**Flavor 一致性
  约束**：bb 6.0.0-nightly 的 `CircuitWriteSolidityVerifier` 硬编码 `UltraKeccakFlavor::
  VerificationKey`（oracle_hash=keccak + disable_zk，1888B），因此 `write_vk` / `prove` /
  `verify` 必须统一 `-t evm-no-zk`（默认 poseidon2 的 UltraFlavor VK 3680B 尺寸不匹配，
  CI run 31933941769 → 修复 31934410549 全绿）。
- **Rust 侧封装**：聚合器用 `bb_rs` 或 stdlib 封装验证器；目标单验证 < 10ms、批验证摊薄 ≤
  100μs/笔（§5.5）。真批验证/递归聚合见 §5.4。
- **S-09 验收（CI 全绿，run 31934410549）**：正式管线 8 步全通——`gen-witness`（Noir 内
  确定性 eddsa_sign + 撤销树）→ `formal_gen_to_prover.py` 交叉校验 → 正式电路 prove/verify
  /公共输入回读(121)/负向篡改/B2-B4 计时基线/约束门禁(<2^18)/EVM 验证器。TEMPORARY `smoke/`
  （secp256k1 blackbox）保持原状，仅作脚手架，**不进文档/SPEC**（字节序等坑记在
  `scripts/smoke_readback.py` docstring）。**已知提示（非阻断）**：nargo soundness 检查对
  `noir-edwards` 的 `__add_unconstrained`（BabyJubJub 点加，`unsafe`）报 "Brillig function
  call isn't properly covered by a manual constraint" —— 警告而非错误；gen-witness 与正式
  电路共享该库约束覆盖，prove/verify 端到端兜底。
- **EVM 集成预留**：`circuits/artifacts/UltraVerifier.sol`（UltraHonk keccak-flavor）供
  Phase 4 的 L3 预编译使用。

### 5.4 批验证策略（100μs/笔 预算的达成路径）

| 阶段 | 手段 | 摊薄效果 |
|---|---|---|
| v1 | 单证明 + 非阻塞异步并发验证 | 并行吞吐提升 |
| v1.1 | UltraHonk 批验证（BB 原生 batch verify） | 验证成本均摊 |
| Phase 2 | 电路内"递归聚合"：N 笔 → 1 个聚合证明 | 摊销到近乎固定成本 |

> 诚实预算：100μs/笔是**目标线**。owner ECDSA 电路外（§5.2），电路内是 BabyJubJub EdDSA +
> pedersen Merkle + sha256——单验证 ~ms 级（§5.5 实测），v1.1 批验证先达摊薄线，递归聚合
> （Phase 2）才真正击穿。基准（§8）会产生真实数字回填预算表。

### 5.5 约束预算（目标 + S-09 实测）

| 项 | 目标 | S-09 实测（CI run 31934410549） |
|---|---|---|
| 电路约束数 | < 2^18 | **66736**（`bb gates` circuit_size；含 sha256 intent_hash + pedersen Merkle + Jubjub EdDSA） |
| 证明生成（agent 侧，桌面级） | p50 < 1s | 1.8457s（CI 2 核共享 runner，`bb prove` 进程含 witness 加载；桌面级/优化留待 Phase 4） |
| 单证明验证（聚合器） | < 10ms | **7.62ms p99 PASS**（`bb verify` CLI 进程含启动开销，纯验证数学更小） |
| 批验证摊薄（≥256 笔/批） | ≤ 100μs / 笔 | 7.62ms/笔 CLI 上界；真批验证摊薄待 Phase 4 in-process wrapper |

**S-05 基线**（run 31926682045）：最小版 = 6880 ACIR opcodes + 1289 Brillig opcodes。
**S-09 完整版**（run 31934410549）：circuit_size = **66736**，ACIR opcodes = 9044（`bb gates`
输出）——owner ECDSA 移出电路（§5.2 断言 2）省下 ~2^18 级预算，其余（intent_hash sha256 +
撤销 Merkle + Jubjub EdDSA）仍在 2^18 预算内，为后续安全增强（如字段级类别解析）留有余量。
证明/验证时延见 `circuits/bench/baseline_s09.json`（CI upload-artifact 交付）。

---

## 6. L3 — 结算聚合器

### 6.1 意图信封

```rust
pub struct IntentEnvelope {
    pub intent: SpendIntent,
    pub proof: SpendProof,             // ZK 模式
    // Contract 模式：proof 为合约校验引用（tx hash / 链上事件）
}

pub struct Receipt {
    pub intent_hash: [u8; 32],
    pub accepted: bool,
    pub reject_reason: Option<Error>,
    pub seq: u64,                      // 摄取序号（入承诺）
}
```

### 6.2 摄取接口

```rust
pub trait Ingest {
    fn submit(&self, env: IntentEnvelope) -> Result<Receipt, Error>;
}
```

- 摄入管线：验签（Ed25519 快路径）→ 验证明（§5）→ 预算检查（§4.5）→ 记账 → 入窗口队列。
- 拒绝原因必须进 `Receipt`，供 agent 端幂等重试（nonce 不允许复用）。
- **幂等重发（S-12，管线最前闸口）**：同一 `spend_nonce` + 同一 `intent_hash` 的重发
  **在过期检查之前**直接返回既有结果——accepted → 原 `seq`（不重复分配、不重复记账）；
  rejected → 原错误码（不透传成成功）。此闸口在过期检查之前，因此**已过期但曾被接受的
  意图重发**仍返回原 `seq`——SDK 断线重试绝不因 `EIntentExpired` 误判失败而换新 nonce
  重发（那才是双花的来源）。跨意图复用 nonce 仍 `E_Nonce`（§6.2 不允许复用，原语义
  不变）。

### 6.3 排序与承诺（commitment lattice，防抢跑）

```
窗口 W 收满（10s 或 100_000 笔）→
  A. 密封：L = [(seq_i, intent_hash_i)]，按摄取顺序；root = merkle(L)
  B. 承诺：root + revocation_root 上链，质押债券（BatchSettler.commit(epoch_id, root,
     revocation_root) payable onlyOperator，msg.value = bond）
  C. 确定性重排：sort L by intent_hash（公开规则，任何人可重推）
  D. 处理：按重排序执行预算净额 → 生成净额指令 net[i] = (recipient, amount)
  E. 结算：BatchSettler.settle(epoch_id, net[], netting_root) payable onlyOperator，
     msg.value ≥ Σnet（结算资金源，S-11 延迟 claim）
```

- 排序规则公开且由哈希决定 → 摄取顺序不可被"位置/金额"套利（无夹子）。
- `netting_root = keccak256(abi.encode(net[]))`（对齐 `BatchSettler.settle` 的实现——以代码为准）；
  `net[]` 公开，任何人可复算验证净额正确。
- 双花防线：意图唯一（intent_hash），账本原子记账，跨 epoch 不重复。

### 6.4 批量结算（BatchSettler 合约）

净额结算的链上成本 = 每 epoch 仅按**净头寸**转账（典型 100k 笔 → 数百条净额指令），Gas 与吞吐完全可行。

**结算节奏（S-11 延迟 claim 模式，用户决策 2026-08-17）**：
1. `commit`：运营者质押债券（`msg.value`）+ 锚定承诺根与撤销根，一次性；
2. `settle`：运营者提交 `net[]` + `nettingRoot`（链式 keccak 校验），**同笔携带 ≥ Σnet
   的结算资金**（`settlementFunded` 存入；挑战成功时全额退运营者，多付部分留在合同视作
   捐赠）；
3. 挑战窗口（6h）：任何人可提交欺诈证明（§6.5）；挑战成功 → epoch `voided`；
4. `claim`：窗口过后收款人**逐条**领取原生 ETH。挑战与 claim 严格时间分离 → 挑战成功时
   无任何 claim 已付，退款干净。

### 6.5 债券/惩罚（乐观安全模型）

| 承诺 | 违约 | 惩罚 |
|---|---|---|
| 运营者质押债券（**原生 ETH**，`commit` 时 `msg.value`） | 等价双花 / 漏单 / 提交与承诺不符的 net[] | 债券罚没，判给挑战者 |
| 预算账本诚实 | 已撤销仍放行 / 超限记账 | 债券罚没 + 声誉分（Phase 2） |
| 撤销根最新 | 用过时撤销根放行已撤销委托 | 债券罚没 |

- **欺诈证明类型（S-11，sound + 有界）**：
  - **漏单（missing-recipient）**：出示一条明文 SpendIntent + `seq`/`leafIndex`/
    `acceptedCount` + merkle 兄弟路径。链上重算 `intent_hash`（字节精确）→ 叶子 →
    验证在承诺根内；若收款人 ∉ `net[]` → 欺诈。
  - **低付（under-payment）**：出示同一收款人的已提交意图**子集**，uint256 和 >
    `net[target].amount` → 欺诈（单调子集，不需完备性）。超付不可证（出界，见下）。
  - **两个防假阳性硬守卫**：同笔意图重复计入 → `DuplicateIntent` 拒；跨收款人子集
    （低付要求每条 `recipient == net[target].recipient`）→ `BadFraudKind` 拒。
    外加边界：`leafIndex < acceptedCount`、`siblings.length == treeDepth(acceptedCount)`。
- **挑战窗口**：`settle` 后 `CHALLENGE_WINDOW`（6h）内，任何人可对 `commit ≠ settle` 提交
  欺诈证明。**CEI 顺序**：验证通过 → 先置 `challenged`/`voided` → 债券罚没给挑战者 +
  `settlementFunded`（= Σnet）全额退运营者 → 后续 claim 全部拒绝。验证失败整笔回滚（挑战者
  吃 gas——窗口内无押金，v1 反垃圾手段）。单次挑战 `MAX_INTENTS_PER_CHALLENGE = 32`
  （epoch_capacity=100k → 树深 17，每意图 ~19 次 sha256 预编译，~500-600k gas）。
- **诚实路径**：v1 信任运营者（我们自己是第一个运营者），债券起震慑作用；Phase 2 引入多运营者 + 共享账本（L3 前置）。
- **出界**：超付不可证（需完备性）；按 epoch 结算资金后超付是运营者自损（自掏 Σnet 付虚高
  行），不掏空其他 claim 方。整 epoch void 会惩罚诚实收款人（该 epoch 全部 claim 拒绝）——
  v1 接受（§6.5 "net[] 回滚"口径），按收款人封禁是后续增强。

### 6.6 SDK 集成层（S-12）

独立 agent 进程集成层（`sdk/` crate，`meridian-sdk`）：封装 core 密码学原语 + 聚合器
摄取管线，暴露三个高层操作——`authorize()`（注册委托）/ `pay()`（幂等支付）/
`attest()`（双钥绑定凭据）。错误码经 `Error::as_code` 透传，供 agent 把拒绝原因原样
转达上层策略。

**幂等重试契约（"断线重试不产生双花"）**：
1. 每笔逻辑支付取**固定 `spend_nonce`**，整个重试周期不复用、不推进；只有聚合器返回
   定局（accepted 或永久拒绝）后，下一笔才取新 nonce（`NonceManager`，每委托单调）。
2. **仅传输错误**（`SdkError::Transport`）触发重试；聚合器的业务拒绝（`SdkError::Meridian`，
   错误码透传）**永不重试**。
3. 聚合器侧幂等（§6.2 幂等重发闸口）兜底重发：断线重发返回先前结果 → 不会把同一笔意图
   记两次（双花），也绝不会把一笔被拒绝的意图透传成成功。

**传输形态**：`Transport` trait 抽象「聚合器连接」——`authorize` / `submit`。S-12 提供
`InProcessAggregator`（进程内聚合器，测试与单进程嵌入用）；网络传输是 S-13 框架分发层
的接缝。

**诚实边界**：
- 证明 = `PlaceholderProver`（proof 非空 + 公共输入与信封一致），与聚合器内置
  `FormatVerifier`（TEMPORARY）配套；真实 S-09 电路 prover 实现 core `SpendProver`
  经 `SdkClient::with_prover` 接入，`pay()` 重试逻辑不变。
- `NonceManager` 为进程内单调计数，崩溃后不持久化；跨重启恢复依赖聚合器 WAL + 未来
  `next_nonce` 查询 RPC（Phase 2 缝，sdk/README 记录）。

---

## 7. 链上合约接口（Solidity，S-06 最小可跑 → S-11 生产化）

五个合约在 `contracts/src/`（S-11 增 `IntentHelper.sol` / `Merkle.sol` 交叉实现；
forge test **53 用例**全绿，见 `contracts/README.md`）。签名与语义以代码为准，此处为契约要点。

```solidity
// DSA.sol —— 委托注册（Contract 模式 + 撤销锚点来源）
contract DSA {
    event DelegationRegistered(bytes32 indexed delegationHash, address indexed owner);
    function registerDelegation(bytes calldata delegationABI, bytes calldata ownerSig) external;
    function ownerOf(bytes32 delegationHash) external view returns (address);
    function isRegistered(bytes32 delegationHash) external view returns (bool);
    error AlreadyRegistered(); error BadOwnerSignature(); error HighS(); error MalformedABI();
}

// RevocationRegistry.sol —— 独立撤销表（仅 owner 可撤销）
contract RevocationRegistry {
    event Revoked(bytes32 indexed delegationHash, address indexed by);
    function revoke(bytes32 delegationHash) external;   // 仅 owner，未注册 reverts
    function isRevoked(bytes32 delegationHash) external view returns (bool);
    error NotOwner(); error NotRegistered();
}

// BatchSettler.sol —— 乐观批量结算（S-11 v2 生产化：operator 守卫 + 延迟 claim + 完整挑战流）
contract BatchSettler {
    struct NetInstruction { address recipient; uint256 amount; }
    struct IntentProof {
        bytes20 agent; bytes32 delegationHash; bytes20 recipient; uint64 amount;
        bytes32 category; uint64 spendNonce; bytes memo; uint64 expiresAt;
        uint64 seq; uint256 leafIndex; uint256 acceptedCount; bytes32[] siblings;
    }
    struct FraudProof { uint8 kind; uint256 targetNetIndex; IntentProof[] intents; }
    // kind 1 = 漏单（收款人 ∉ net[]）；kind 2 = 低付（同收款人意图子集和 > net[target].amount）

    event Commit(uint256 indexed epochId, bytes32 commitmentRoot, bytes32 revocationRoot,
                 uint256 bondedAmount);
    event Settled(uint256 indexed epochId, bytes32 nettingRoot, uint64 netCount);
    event ChallengeSucceeded(uint256 indexed epochId, address indexed challenger, uint8 kind);
    event Claimed(uint256 indexed epochId, address indexed recipient, uint256 amount);

    address public immutable operator;                 // 唯一运营者（onlyOperator 守卫）
    uint256 public constant CHALLENGE_WINDOW = 6 hours;
    uint256 public constant MAX_INTENTS_PER_CHALLENGE = 32;

    function commit(uint256 epochId, bytes32 commitmentRoot, bytes32 revocationRoot)
        external payable onlyOperator;                // 质押债券（msg.value）+ 锚定撤销根，一次性
    function settle(uint256 epochId, NetInstruction[] calldata net, bytes32 nettingRoot)
        external payable onlyOperator;                // keccak(net) 校验 + 存 net[] + msg.value ≥ Σnet
    function claim(uint256 epochId, uint256 netIndex) external;  // 窗口后逐条领原生 ETH；voided 拒
    function challenge(uint256 epochId, FraudProof calldata fp) external; // 窗口内完整验证欺诈证明

    error EpochAlreadyCommitted(uint256); error EpochAlreadySettled(uint256);
    error EpochAlreadyChallenged(uint256); error EpochUnknown(uint256); error EpochVoided(uint256);
    error WrongNettingRoot(); error ChallengeWindowClosed(); error ChallengeWindowOpen();
    error AlreadyClaimed(uint256,uint256); error NetIndexOutOfBounds(uint256,uint256);
    error TooManyIntents(); error DuplicateIntent(); error BadInclusionProof(); error NotFraud();
    error InsufficientSettlementFunding(); error BadFraudKind(); error NotOperator();
}
```

**关键契约（S-06 交叉实现）**：`registerDelegation` 在链上重算
`delegation_hash = sha256(delegationABI)`，owner 解析自 ABI 字节区间 `[26:46]`
（`"DSAv1\0"` 前缀 + agent + owner，canonical 编码见 `core/src/dsa.rs`）。
链下 meridian-core 的 `delegation_hash` 必须与之一致（Rust `sha2` ↔ Solidity
`sha256` 预编译，双向验收）。owner 签名强制低位 s（`s > n/2` → `revert HighS`）。

- 部署底座：Base（主网 Phase 2 起）；测试：Anvil 本地链 + Base Sepolia。
- **S-11 结算资产 = 原生 ETH**（bond = `msg.value`；claim 付原生 ETH）；USDC/ERC-20 结算
  推迟 Phase 2——`NetInstruction { recipient, amount }` 指令形状不变，资产置换不动净额结构。
- S-11 生产化：BatchSettler 完整 fraud-proof（漏单/低付，sound+有界）+ 债券罚没 +
  epoch voided 回滚 + 延迟 claim；撤销事件 1 epoch 内进入聚合器撤销根（sha256 sparse root，
  随 commit 上链）；真实 sha256 Merkle 已替换占位（`IntentHelper.sol`/`Merkle.sol` 交叉实现）。

---

## 8. 性能测试用例（bench/ 基座）

### 8.1 基准平台（基准必须在此描述下运行并随报告附带）

- 参考机（目标平台）：16c/32t，64GB RAM，NVMe，Linux，CPU 支持 `avx2/adx/bmi2`。
- 实测机（S-08a / S-10）：32 核 Windows x86_64，release build；PoC ② 与 S-10 生产内核
  吞吐数字均按此机回填（§8.2 两组实测，`agg_sim` 全量报告）。参考机（Linux 16c/32t）
  复测作为 S-11 前的复核项。
- 报告必须含 `git sha`、CPU/内存/OS、`-C target-cpu=native` 是否启用。
- 一切基准**固定 seed、固定输入集**（`bench/data/*.bin` 入 repo），结果必须可复现。

### 8.2 测试清单

| # | 用例 | 指标 | 目标 | 门禁 |
|---|---|---|---|---|
| B1 | delegation 签名/验签 | ops/s, p99 | 验签 > 50k ops/s | 回归 >1% 红 |
| B2 | ZK 证明生成（agent 侧） | p50/p99, 约束数 | p50 < 1s | 回归 >5% 红 |
| B3 | ZK 单验证 | p99 | < 10ms | 回归 >5% 红 |
| B4 | ZK 批验证（≥256 笔） | 摊薄 μs/笔 | ≤ 100μs | 回归 >5% 红 |
| B5 | 聚合器摄入吞吐 | 笔/s（1/8/64 线程） | 单实例 ≥ 100k 笔/s | 回归 >1% 红 |
| B6 | 摄入端到端延迟 | p99 | ≤ 50ms | 回归 >1% 红 |
| B7 | 排序+承诺（100k 笔） | 耗时, 内存峰值 | < 1s, < 1GB | 回归 >1% 红 |
| B8 | 热路径分配 | allocs/笔 | **= 0** | 非 0 即红 |
| B9 | 预算检查 | ops/s | > 1M ops/s | 回归 >1% 红 |
| B10 | 端到端 100k 笔→批次→净额 | 墙钟, allocs, 峰值 | 记录基线 | 首次=基线 |
| B11 | 确定性 | 同 seed 输出 | 输出哈希一致 | 不一致即红 |
| B12 | 内存 | 稳态 RSS | 记录基线 | 回归 >3% 红 |

> **S-08a 实测（PoC ②，`docs/poc/poc-02-aggregator-throughput.md`）**：B5 聚合器摄入
> 吞吐，32 线程满核 **488,738 笔/s**（目标 ≥100k → **PASS**，余量 ~4.9×）；单线程基线
> ~47.6k/s（瓶颈=Ed25519 验签，无状态 → 并行近线性放大）。口径：TEMPORARY 无 ZK
> （S-09 挂 `verify_proof`），nonce 分片为原型形态。原型留作历史证据。

> **S-10 实测（生产内核，`docs/poc/poc-04-aggregator-kernel.md`，输入快照
> `bench/data/s10_fixture.bin`）**：B5 单实例 1t **46,243** | 8t **309,260** | 64t **576,406**
> 笔/s（目标 ≥100k → **PASS**，余量 ~5.8×）；B6 摄入端到端 p99 **0.030 ms**（≤50ms →
> **PASS**）；B7 100k 排序+承诺 **46.5 ms / 33.1 MiB** 累计分配（<1s / <1GB → **PASS**）；
> B8 热路径 **0 分配**（=0 → **PASS**）；B10 100k 笔→1 批→50 条净额（Σnet=100k）
> **180.9 ms / 0 分配**（基线记录）；B11 同 seed 两跑 lattice 输出一致（**PASS**）。
> 口径：全管线含 `SpendVerifier`（本阶段 `FormatVerifier`，TEMPORARY，与 PoC ② 同口径）。
> CI 只跑回归门禁（B8/B11 硬断言 + gate 吞吐基线），全量验收在参考机 `agg_sim`。

### 8.3 可复现与验证门禁

- **主门禁 = 本地流水线**：`scripts/verify.sh`（fmt → clippy `-D warnings` → `cargo test
  --workspace` → bench 编译 → perf gate（`cargo run --release -p meridian-bench --bin
  gate -- --fail-over 15`，抓灾难性回归）→ `agg_sim --check-alloc`（B8 零分配）/
  `--check-determinism`（B11））。挂 `.githooks/pre-push` 钩子（注册：
  `git config core.hooksPath .githooks`），**推送前必须全绿**；紧急放行
  `git push --no-verify`。跑在记录 baseline.json 的参考机上，比共享 runner（±10% 噪声）
  更稳。
- **1% 精准基线**（人工，受控参考机）：`gate -- --record` 更新 baseline 后
  `gate -- --fail-over 1`。同机多次 run 噪声 ±6%（§8.2），低于 15% 门禁，不误拒。
- baseline.json 入库；`scripts/verify.sh` 必须通过全量套件。
- **S-11d 链上端到端（verify.sh 9/9）**：`rust-smoke`（`contracts/rust-smoke`，独立
  workspace）在一条 anvil 会话内跑三场景——① 快乐路径：注册→submit→密封结算→
  `commit`（债券+撤销根）→`settle`（资金足）→过窗 `claim` 收款人收精确净额；② 撤销：
  链上 revoke→聚合器 revoke→新意图 `E_REVOKED` 拒→下个 epoch 撤销根变化；③ 欺诈：
  `commit` 诚实根→`settle` 漏单（自洽 netting root）→kind=1 包含证明 `challenge` 成功→
  债券罚没+`settlementFunded` 退运营者+epoch voided→claim 拒绝。依赖 forge build 产物 +
  anvil，缺任一则 `[SKIP]`（不阻塞 Rust 主门禁）。
- 热路径零分配用分配器钩子断言（`dhat` 或自写 alloc hook），不靠估计。
- **GitHub CI**（`.github/workflows/ci.yml`）：**可选第二道网**，2026-08-17 起被账户
  计费阻断（私有 Actions included 额度耗尽）而挂起。solidity（forge）与 ZK（nargo/bb）
  job 需 Linux 工具链，本机未装时 `verify.sh` 打印 `[SKIP]`；可借 Linux 服务器或 WSL 补上。

### 8.4 输出 schema（JSON）

```json
{
  "suite": "meridian-bench",
  "commit": "<git sha>",
  "machine": {"cpu": "...", "cores": 32, "ram_gb": 64, "os": "...", "simd": ["avx2","adx","bmi2"]},
  "metrics": {
    "zk_verify_single_p99_us": 0.0,
    "zk_verify_batch_per_intent_us": 0.0,
    "agg_ingest_throughput_ips": 0,
    "agg_ingest_p99_ms": 0.0,
    "allocations_per_intent": 0
  },
  "baseline": "baseline.json",
  "regressions": [{"metric": "agg_ingest_throughput_ips", "delta_pct": 1.3}]
}
```

---

## 9. 安全威胁模型与对策

| 威胁 | 场景 | 对策 |
|---|---|---|
| 重放 | 同一 intent 多次提交 | `spend_nonce` 单调 + 账本登记 intent_hash，拒绝重复 |
| 超限消费 | agent 超 rate/total | 账本原子预算检查（§4.5） |
| 已撤销仍花 | 撤销后继续用旧委托 | 撤销根进电路（§5.2#8）+ 聚合器新鲜度惩罚（§6.5） |
| agent 私钥泄露 | agent 密钥被夺 | 密钥轮换 + 主人 DSA 撤销 + 找回路径（L1 身份层） |
| 恶意运营者 | 承诺与结算不符 / 账本作恶 | 债券 + 欺诈证明 + 挑战窗口（§6.5） |
| 抢跑/夹子 | 按摄取顺序套利 | 承诺格 + 哈希确定性重排（§6.3） |
| 签名延展性 | ECDSA malleability | 强制低位 `s` + 规范化序列化（§11 E-03） |
| 电路/账本漂移 | 证明的是 A、账本记 B | `SpendVerifier::verify` 返回公共输入，登记必须以返回值为准 |
| Sybil 声誉刷量 | Phase 2 声誉攻击 | 质押绑定 + 履约证明（L4 spec 覆盖） |

---

## 10. 测试策略

| 层 | 手段 | 关键不变量 |
|---|---|---|
| 单元 | 每函数边界用例 | 错误码覆盖（§11） |
| Property（proptest） | 预算状态机 | 恒非负；窗口回滚正确；`total_cap` 封顶；并发分片无竞争 |
| ZK 负向 | 篡改 amount/category/nonce/过期/撤销 | 全部必须验证失败 |
| ZK 正向 | 合法边界值 | 必须通过 |
| 集成 | Anvil 本地链 + 真实 USDC（Base Sepolia） | `提交→承诺→结算→余额` 全链路一致 |
| Fuzz | 排序/账本并发/nonce | 无双重记账；承诺根稳定；崩溃可恢复（WAL 重放） |
| 确定性 | 同 seed 全管线 | 输出哈希一致（B11） |

---

## 11. 错误码

| 码 | 含义 |
|---|---|
| `E_DELEG_EXPIRED` | 委托未生效或已过期 |
| `E_DELEG_UNKNOWN` | 委托未注册（聚合器按 delegation_hash 查注册表未命中） |
| `E_DELEG_SIG` | owner 签名验证失败 |
| `E_ATTEST_BIND` | 换钥重绑被拒（attestation 双钥绑定，S-05） |
| `E_INTENT_SIG` | agent 签名验证失败 |
| `E_PROOF` | ZK 证明无效 |
| `E_BUDGET_PER_SPEND` | 超过单笔上限 |
| `E_BUDGET_RATE` | 超过窗口速率 |
| `E_BUDGET_TOTAL` | 超过累计总上限 |
| `E_NONCE` | 同 nonce **换意图**重放（§6.2 幂等重发：同意图重发返回先前结果，不是本码） |
| `E_REVOKED` | 委托已撤销 |
| `E_INTENT_EXPIRED` | 意图过期 |
| `E_INTENT_HASH` | intent_hash 与字段不一致 |
| `E_CATEGORY` | 类别不在白名单 |
| `E_SEQ` | 摄取序号冲突 |
| `E_ORDERING` | 承诺与重排不一致（欺诈信号） |
| `E_09` | 未定义（预留） |

---

## 12. 完成定义（DoD）

| 模块 | DoD |
|---|---|
| `dsa` | 签名/验签 + 预算状态机全过 property/fuzz；错误码全覆盖 |
| `zk` | 电路约束 < 2^18；正向/负向全过；验证接口返回公共输入；EVM 验证器编译通过 |
| `agg` | 10 万笔确定性排序；承诺根可复现；WAL 崩溃恢复；B5/B6/B7/B8 达标 |
| `contracts` | Anvil 集成测试全绿；commit/settle/challenge 全路径可挑战 |
| `bench` | §8 全套件可在参考机复现；baseline.json 入库；CI 门禁生效 |
| `sdk` | authorize/pay/attest 全可用；断线重试不双花（e2e：re-ack 原 seq、accept 一次） |
| **里程碑 M1** | 端到端 demo：agent 持 DSA → ZK 授权 → 聚合器 100k 笔 → BatchSettler 净额结算，Anvil 上全绿 |

---

## 13. 里程碑映射

| 蓝图阶段 | 本 spec 对应 |
|---|---|
| Phase 0（研究/标准） | §4-§7 契约冻结 + 三个 PoC **全绿**（见下"Phase 0 实证清单"） |
| Phase 1（参考实现） | §4-§8 全部实现 + 里程碑 M1 + 开源仓库 `meridian-commerce` |
| Phase 2（聚合器运营） | 生产化：多运营者、债券经济、Base 主网部署、递归聚合 |

### Phase 0 实证清单（S-08c 合闸时点）

| PoC | 内容 | 结果 | 证据 |
|---|---|---|---|
| ① ZK 授权凭证 | `spend_authorization` 完整版（§5.2 九断言 + 正/负向 + 双钥绑定 + 撤销非成员 + intent_hash 字段级绑定） | **PASS**（约束 66736 < 2^18，回填 §5.5） | CI run 31934410549；§5.5 |
| ② 聚合器吞吐 | 验签→nonce 去重→预算记账，固定输入满核 | **PASS** 488,738 笔/s（目标 ≥10 万） | `docs/poc/poc-02-aggregator-throughput.md` |
| ③ 交付证明 | TLSNotary 2-party MPC-TLS 选择性披露见证交付 | **PASS** 四条断言 | `docs/poc/poc-03-delivery-proof.md` |

---

## 14. 活文档说明

- **性能预算表（§8.2）是活的**：每个数字以 `bench/` 实测为准回填；偏差须在本文件记录原因与修订线。
- **本规格绑定 Phase 0/1**；任何接口签名变更走 PR 评审，先改 spec 后改码。
- 下一位要开工的模块：**聚合器内核**（S-10，WAL / commitment lattice / 崩溃恢复）。
  S-09（ZK 电路完整版：intent_hash 字段级绑定 + 撤销非成员，owner ECDSA 电路外）已完成；
  S-10 起 Phase 2 级联。EVM 验证器（`circuits/artifacts/UltraVerifier.sol`，keccak-flavor）
  供 Phase 4 L3 预编译复用。

---

*TECH_SPEC v1.0 · 2026-08-16 · Phase 0 定稿（S-08c）· 绑定文档，先改 spec 后改码。*
