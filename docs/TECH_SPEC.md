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
| `Amount` | `u64`，账本/电路侧金额单位；链上结算按 S-11 用户决策用**原生 ETH**（wei，Solidity `uint256` 承接）。USDC（基础单位 1e-6 USD，`uint256` 承接）经 **S-28 资产参数化**路径支持（§7）：`BatchSettler.asset` 构造参数，`address(0)` = 原生 ETH |
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
- **电路侧（S-36 全宽化）**：撤销非成员证明——`delegation_hash` 对应叶子 = `EMPTY`（非成员），
  即未撤销。树深 256，索引 = `delegation_hash` 全 32 字节的 LE u256，叶子 = EMPTY(0)
  （Pedersen sparse merkle，§5.2 断言 8）——与聚合器 `RevocationSet`（下）**同一派生、同一位
  序**。电路内索引不落单个 Field（BN254 域仅 ~254 bit，容不下 256-bit 索引；
  `Field::to_le_bits::<256>` 直接不可满足，S-36 实测），位由字节现场派生（`compute_merkle_root`
  直收 `[u8;32]` 索引字节，位 k = `(dh[k/8] >> (k%8)) & 1`），无截断、无 mod-p 碰撞可乘。
- **聚合器侧（S-11 新增，S-34 收口碰撞，S-41 哈希对齐电路）**：`RevocationSet`（`aggregator/src/revocation.rs`）
  收集被撤销委托的 `delegation_hash`，`sparse_root()` 压实成 32B 根——**S-41 起与电路是同一棵
  树**：哈希 = Noir `std::hash::pedersen_hash`（非对称 2-field 哈希，`[左, 右]` 序有义）；叶值 =
  Field——空叶 = 0，撤销叶 = `encode_field(dh)`（低 31 字节 LE 截断 → Field，与 gen-witness 的
  撤销叶同一编码）；空子树根表 `empty_roots[0] = 0`、`empty_roots[k] = pedersen_hash([E,E])` 逐层
  叠（与 gen-witness `compute_empty_roots` 同一迭代）。
  **树深 256，索引 = `dh` 全 32 字节的 LE u256**（位 k = `(dh[k/8] >> (k%8)) & 1`；第 d 层
  节点索引 = 索引右移 d）——**S-34/S-36 起与电路侧同一派生、逐位全等**（不再是"低 32 位扩位"
  关系，见上）。根的 32B 外形 = Field 的**大端**编码（bb 公共输入序列化口径，§6.13），随下个
  密封 epoch 的 `ChainPublisher::commit` 上链。
  **S-11 原型版两侧均用 32-bit 前缀索引**（`delegation_hash[0..4]`
  LE）：两委托同前缀共享叶子、后写覆盖先写，锚定根只承诺其一（audit-scope §4 自报项）。
  S-34（2026-08-30）聚合器侧、S-36（2026-08-30）电路侧先后改为全 256-bit 索引：
  `delegation_hash` 整体即索引，**相异 dh 必相异叶**，
  碰撞面收口（`delegation_hash` 本就是 ecrecover 域内的 256-bit 抗碰摘要）。代价：`sparse_root`
  从 O(32·|revoked|) 次 sha256 变 O(256·|revoked|) 次固定基 Grumpkin MSM（每层 ~50µs 量级，
  比 SHA-NI 加速的 sha256 慢约 3 个数量级）——只在密封（每 epoch 一次）调用，撤销又是稀有事件，
  热路径（摄取/submit 闸口）不受影响（闸口是集合精确查找，与树无关）；perf gate 9 指标不含
  sparse_root，§8.2 基线口径不动。
- **S-41 哈希对齐的 Rust 复现路径（`aggregator/src/noir_pedersen.rs`，零新依赖）**：Noir
  `pedersen_hash([l, r])`（分隔符 0，N=2）= bb 的 Pedersen：取 MSM `l·G0 + r·G1 + 2·G_len` 的
  **x 坐标**（第三项是 length 标量 = 输入个数 N，生成器来自独立域 `"pedersen_hash_length"`）。
  其中 G0/G1 取自 bb 预计算表 `DEFAULT_DOMAIN_SEPARATOR[0..2]`、G_len 取自
  `"pedersen_hash_length"[0]`——**bb 6.0.0-nightly.20260724 把这两组生成器硬编码在
  `crypto/generators/generator_data.hpp` + `ecc/groups/precomputed_generators_grumpkin_impl.hpp`**
  （8 + 1 个常量点）。本场景 N=2 恰好完全落在预计算范围内，**无需复现运行时
  `derive_generators`**（S-05 教训：不做跨语言曲线推导）。Rust 侧内嵌这 3 个 bb 常量点 +
  手写 BN254-Fr（Grumpkin 基域）Montgomery 算术与 Jacobian 点运算（零新依赖、无 C 依赖），
  固定基 4-bit 窗口表 `OnceLock` 预计算。**三层验证锚**：
  ① Noir stdlib 自带 golden（`noir_stdlib/src/hash/mod.nr::assert_pedersen`，bb 对齐产物）：
  `pedersen_hash_with_separator([1],1)`、`pedersen_hash_with_separator([1,2],2)` 锁 Rust 实现；
  ② bb 的 9 个预计算点全部过 Grumpkin 曲线方程自检（y² = x³ + b，b = p − 17）锁域算术；
  ③ **全树交叉（最强锚）**：gen-witness fixture（撤销集 {`0x01…32`, `0x02…32`}）的
  `revocation_root`——Rust `RevocationSet` 算出的根必须与 Noir `nargo execute` 输出相等
  （gen-witness `revocation_empty_roots_match_aggregator_golden` 锁空子树表 + 聚合器
  fixture golden 锁全树，双向）。撤销事件流：链上 revoke → 运营者调 `Aggregator::revoke(dh)`
  （网络化部署经网关管理端点 `POST /v1/admin/revocations`，S-57，§6.7 撤销面）（WAL 追加
  `Revoke` 记录后入集，崩溃可重放重建）→ `submit()` 在注册表查找后立即查集，已撤销委托
  新意图一律 `E_REVOKED` 拒（最廉价闸口，不耗 nonce/窗口槽）→ 撤销根随**下个密封 epoch**
  的 `ChainPublisher::commit` 上链（S-11 验收：1 epoch 内进入撤销根）。
- 撤销即时性：聚合器拉取注册表延迟 ≤ 1 个 epoch；对"已撤销仍消费"的窗口期，用债券惩罚运营者（§6.5）。
- **诚实缝状态（S-41 定夺并收口）**：S-11 记录的错配是哈希函数 + 叶值/空叶规范（索引派生
  已在 S-34/S-36 全等）。定夺：**改聚合器侧，电路不动**——电路改哈希不可行（sha256 需在
  电路内再付 256 层，约束爆炸；poseidon/poseidon2 换型同样要在电路内付 256 次置换且需
  复现其 Rust 实现，约束预算与 prove 时长双输），而聚合器侧对齐只需要复现哈希本身，且
  bb 的预计算生成器恰好覆盖本场景（见上，无需跨语言曲线推导）。S-41 后三要素（哈希函数 +
  叶值/空叶规范 + 索引派生）两侧全等，聚合器 `sparse_root()` 与电路 `revocation_root`
  公共输入（pub Field）**数值可比**（同一 Field 的大端 32B 外形）——bb 模式下
  `pi.revocation_root` 可以来自聚合器账本树（§6.13 诚实边界 3 收口）。残余边界：
  ① 电路内撤销叶 = `encode_field(dh)` 只编码低 31 字节（byte 31 不参与叶值）——叶值非单射，
  但叶**位置**（全 256-bit 索引）单射，两 dh 仅 byte 31 相异时占同值异位两叶，无碰撞可乘；
  ② **S-42（2026-08-30）聚合器已产出非成员路径**：`RevocationSet::non_membership_witness(dh)`
  返回 `{root, path[256]}`——`path[d]` = 深度 d 层目标索引的兄弟子树根（BE Field 32B，与
  `build_root` 同一条插入循环先建全量节点缓存、再沿目标索引上溯取兄弟，兄弟分支为空时取
  `empty_roots[d]`）；目标 dh 已在撤销集时返回 `None`（fail-closed，撤销叶的路径是成员证明、
  不是本接口的语义）。与 `sparse_root()` 同根（同一缓存、同一确定性压实），Rust 侧锚：路径
  重算根（EMPTY 叶 + 逐层兄弟，左/右由索引位定）与 `sparse_root()` 逐例相等、与独立朴素递归
  建树（目标作为空叶插入）一致；**电路消费交叉锚 S-43 已落地**（§6.14 真 prover 步 6：
  Noir `compute_merkle_root` 吃聚合器产路径重算 == 公共输入根，`nargo execute` 断言 8
  自校验，e2e 实证）；prover 侧消费聚合器树出 witness 随 §6.14 兑现。
  残余③ **S-44（2026-08-30）定夺收口（聚合器半边）**：证明公共输入 `revocation_root`
  绑定聚合器账本的撤销状态——摄取管线新增撤销根绑定闸（§6.2），`pi.revocation_root`
  必须 ∈ **撤销状态根集合**（本账本出现过的全部撤销状态根；撤销集只增 → 状态根按撤销
  事件单调推进，集合 ≤ 撤销事件数 + 1）。非成员证明在任一历史状态成立 + 管线步 2b 的
  当前撤销闸（`E_REVOKED`）⇒ 当前未撤销：安全性由 2b 兜底、密码学陈述由绑定闸锚到
  真实状态——**自选根（空根 / 伪造根）的装饰性 ZK 收口**。根换代时在途证明（witness
  取自旧状态快照）不因换代被拒——旧状态根仍在集合内，语义 =「在该状态时未撤销」，
  与 §6.5「撤销前已接受的意图仍留在承诺中支付（非追溯）」同一口径。**S-49（2026-08-30）
  集合随 WAL 持久化**：`revoke` 在绑定闸开启时把当刻根作为新 WAL 记录种类 `RevokeRoot`
  （kind 6，payload 固定 32B = 根的 BE Field 外形）与撤销记录同批落盘，
  `restore_from_wal` 重放根记录**直接进接受集、零重算**——根在 `revoke` 时本已算过
  （S-44 放弃持久化的理由「逐状态重算 = O(撤销数²) 次 MSM 建树」不发生：恢复成本与
  S-44 持平，仍只付空根与当刻根两次建树）。诚实边界（收窄）：WAL 缺根记录的撤销
  （旧格式 WAL 的历史、或绑定闸关闭期发生的撤销）其历史根**不追溯**——恢复后该部分
  中间状态回退 {空根, 当前根} 口径，在途证明（witness 取自该状态）以 `E_REV_ROOT` 拒
  （不安全方向为拒绝，可取新 witness 重出证明；SDK 侧自动刷新重试 S-45 已落地，见
  §6.14 诚实边界 3 / §6.7 witness 查询端点）。撕裂尾边界：撤销记录与根记录是两条
  记录、同批 fsync——尾部截断可能只保住撤销记录（根记录丢失），重放侧该状态根缺位
  仍走安全拒绝方向，绝不冒名接受。

### 4.7 两种模式映射（实现同一接口）

| 模式 | 路径 | 预算强制点 | 场景 |
|---|---|---|---|
| `Contract` | 模块化智能账户（ERC-4337/6900），DSA 作为 spend-policy 模块 | 链上合约 | 中额、低频、需即时链上可查 |
| `ZkCredential` ★ | 本 spec §5 电路 + 聚合器 | 聚合器账本 | 微额、高频、海量 |

两种模式最终都由 `BatchSettler` 净额结算。**S-11 起用原生 ETH**（bond = `msg.value`，
claim 付原生 ETH；`BatchSettler` v2，见 §7）。**S-28 资产参数化**（§7）：
`BatchSettler(operator, asset, challengeBond)`——`asset = address(0)` 即 v2 原生 ETH 行为
（逐字节保留）；`challengeBond` 为挑战押金（S-50 部署期参数化，>0 闸）；
`asset = USDC/ERC-20` 时结算资金/claim/退款走 token，**债券仍原生 ETH**（惩罚质押与结算
资产分离，不引入 token 质押的重入面）——`recipient + amount` 净额指令结构不变。

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
| | `revocation_path` | 稀疏 Merkle 非成员证明路径（叶子=EMPTY，深度 256，断言 8） |

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
8. compute_merkle_root(EMPTY, delegation_hash, path) == revocation_root  // 撤销非成员（叶子=EMPTY，
   // 索引 = delegation_hash 全 256-bit LE，S-36 全宽化；位 k = (dh[k/8]>>(k%8))&1）
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
  **S-36 起本机 WSL2（MeridianUbuntu）已装 nargo/bb（root，`~/.nargo/bin`、`~/.bb`），电路
  改动可本地走 `scripts/formal_zk.sh` 全管线验收，CI 仍为第二道网。**
- **外部库（git 锁定；Noir 1.0 已把下列移出 stdlib）**：`eddsa` fork tag `v1.0-7e206c9`
  （changshenhan/eddsa，指向 1.0 端口 commit 7e206c9；v0.1.3 仍是 Noir 0.x `u1` API，与 beta.26 不兼容；
  nargo 1.0 git 依赖只认 `tag` → fork+tag 锁定）、`edwards` v0.2.5（测试构造曲线点，替代 `ec`）、
  `poseidon` v0.3.0、`sha256` v0.3.0（`agent_commit` 承诺哈希，链下 Rust `sha2` 同一规范）。
  清单与锁定方式见 `circuits/README.md`。
- **签名标量 s 的 mod-n 归约（S-09c 决策）**：Noir 1.0 移除 Field 模运算且 `ScalarField` 无算符
  → `s = (r + h·secret) % SUBORDER` 由 build 脚本（`scripts/formal_gen_to_prover.py`，Python
  大整数）计算；该归约是纯整数逻辑（R8/h/公钥仍在 Noir 内），端到端由正式电路
  `eddsa_verify`（CI prove）把关：s 错则证明失败。
- **撤销树（S-36 全宽化）**：内联 `compute_merkle_root`（`std::merkle` 已移出 Noir 1.0 stdlib，
  merkle_insert 官方模式 + `std::hash::pedersen_hash`），深度 256，叶子=EMPTY(0)，索引 =
  `delegation_hash` 全 32 字节 LE u256，位 k = `(dh[k/8] >> (k%8)) & 1`（按字节现场派生，不落
  单个 Field——BN254 域容不下 256-bit 索引，`Field::to_le_bits::<256>` 不可满足，S-36 实测）。
  原型级碰撞属性（两 delegation 同 32-bit 前缀共享叶子→撤销共享）**两侧均已收口**：聚合器侧
  S-34（§4.6）、电路侧 S-36——同一 delegation_hash 在两侧派生同一索引，同前缀异哈希的委托
  在电路上也走不同叶（回归测试固化）。
- **EVM 验证器（Phase 4 复用）**：`bb write_solidity_verifier -t evm-no-zk -k vk -o UltraVerifier.sol`
  编译 Solidity 验证器（CI 产物 `circuits/artifacts/UltraVerifier.sol`）。**Flavor 一致性
  约束**：bb 6.0.0-nightly 的 `CircuitWriteSolidityVerifier` 硬编码 `UltraKeccakFlavor::
  VerificationKey`（oracle_hash=keccak + disable_zk，1888B），因此 `write_vk` / `prove` /
  `verify` 必须统一 `-t evm-no-zk`（默认 poseidon2 的 UltraFlavor VK 3680B 尺寸不匹配，
  CI run 31933941769 → 修复 31934410549 全绿）。
- **Rust 侧封装**：聚合器用 `bb_rs` 或 stdlib 封装验证器；目标单验证 < 10ms、批验证摊薄 ≤
  100μs/笔（§5.5）。真批验证/递归聚合见 §5.4。**S-40 落地口径**：bb CLI 子进程 wrapper
  （`aggregator/src/bb.rs::BbVerifier`，§6.13），in-process 绑定收益上界 ~15%（S-18 延迟
  分解）留作后续项；目标单验证 < 10ms 已实测达标（§5.5），100μs/笔仍待递归聚合。
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
> pedersen Merkle + sha256——单验证 ~ms 级（§5.5 实测）。**S-18 评估 + 实测（`docs/zk-batch-verify-eval.md` §5）**：
> 批验证（v1.1）只摊薄固定成本（配对合成、setup 共享），每证明的 MSM 主成本不跨证明共享。S-18
> 在参考机（32 核 WSL2）实测两处硬结论：① BB 6.0.0-nightly.20260724 的 CLI `batch_verify`
> 对 UltraHonk **无 handler**（`No handler for subcommand`，仅 Chonk folding 栈可用）、msgpack
> schema 亦仅有 `ChonkBatchVerify`——**BB 原生批验证对本 flavor（evm-no-zk keccak）客观不可用**；
> ② 延迟分解实测 CLI 进程开销仅 0.77ms p50（占 15.5%），纯验证数学 ≈4.21ms 为主导成本（MSM），
> in-process wrapper 收益上界 ~15%。**100μs/笔 单靠批验证不可达，需递归聚合（Phase 2/4）才击穿**；
> B4 预算线按诚实修订执行（§8.2）。
>
> **S-55 递归聚合实测收口（`docs/zk-recursion-eval.md`）**：上表 Phase 2 行在本 nightly
> （bb 6.0.0-nightly.20260724）**实证 blocked-on-upstream**——Chonk folding 栈能折叠
> spend_authorization（Load/Accumulate 通过），但 ① ChonkProve 被规范 hiding kernel ABI
> 卡死（`HIDING_KERNEL_ULTRA_OPS 0 vs 363`，占位电路同样复现）；② 链长上限 8 折
> （N≥8 触发 sumcheck `round_number < 256` 断言）；③ `write_solidity_verifier` 对 Chonk
> 未实现（无 EVM 缝）；④ Mega/MegaZK poseidon2 flavor 重基丢掉 evm-no-zk 链上友好性。
> 边际折叠成本实测 **≈1.0s/折**（≈200× 单笔直验 5.14ms），击穿 100μs/笔 需 N≥10⁴ 而
> 链长限 8——量级倒挂，非调优可救。**v1/v1.1 实线维持单验证口径，吞吐靠非阻塞异步
> 并发验证**；上游（Aztec）解耦 hiding kernel ABI 或实现 chonk solidity verifier 后重评。

### 5.5 约束预算（目标 + S-09 实测）

| 项 | 目标 | S-36 实测（2026-08-30，本机 WSL2 nargo 1.0.0-beta.26 / bb 6.0.0-nightly.20260724） |
|---|---|---|
| 电路约束数 | < 2^18 | **82742**（`bb gates` circuit_size；含 sha256 intent_hash + pedersen Merkle depth 256 + Jubjub EdDSA；S-09 depth-32 版为 66736，全宽化边际 +16k 门 ≈ 71 门/层） |
| 证明生成（agent 侧，桌面级） | p50 < 1s | **0.325s**（S-18 参考机 32 核 WSL2 本机实测；CI 2 核共享 runner 1.8457s） |
| 单证明验证（聚合器） | < 10ms | **5.14ms p99 PASS**（参考机 32 核 WSL2；延迟分解：CLI 开销 0.77ms p50 / 15.5%，纯数学 ≈4.21ms 主导；CI 2 核 7.62ms） |
| 验证摊薄（≥256 笔/批） | ≤ 100μs / 笔（**S-18 诚实修订**，见 §8.2） | 参考机实测单验证 CLI 上界 **4983.8μs/笔**（32 核）；BB 原生批验证对 UltraHonk 不可用（实证，`docs/zk-batch-verify-eval.md` §5）；**100μs 需递归聚合**（Phase 2/4） |

**S-05 基线**（run 31926682045）：最小版 = 6880 ACIR opcodes + 1289 Brillig opcodes。
**S-09 完整版**（run 31934410549，撤销树 depth 32）：circuit_size = 66736，ACIR opcodes = 9044。
**S-36 全宽化**（撤销树 depth 256）：circuit_size = **82742**，ACIR opcodes = 15819（`bb gates`
输出）——owner ECDSA 移出电路（§5.2 断言 2）省下 ~2^18 级预算，其余（intent_hash sha256 +
撤销 Merkle + Jubjub EdDSA）仍在 2^18 预算内（余量 ~69%），为后续安全增强（如字段级类别解析）
留有余量。
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
- **撤销根绑定闸（S-44，§4.6 残余③聚合器半边）**：验证明与公共输入一致性检查之后、
  预留窗口槽之前——`pi.revocation_root` 必须 ∈ 撤销状态根集合（本账本出现过的全部
  撤销状态根：空根 ∪ 每次 `revoke` 后的新根 ∪ 当前根），否则 `E_REV_ROOT` 拒（不耗
  nonce / 窗口槽——闸在 `try_commit` 之前，被拒意图不占 nonce 占位）。语义：电路只证
  「path 与 root 自洽」，root 本身可由 prover 自选——绑定闸把公共输入锚到聚合器真实
  出现过的撤销状态，装饰性 ZK（拿空根伪造非成员陈述）收口。**配置开关**
  `IngestConfig::enforce_revocation_root`，缺省 `false`（占位 prover 口径不动：占位
  witness 的根无语义，默认装配行为逐字节不变——与 §6.13 `MERIDIAN_VERIFY_BACKEND`
  缺省 `format`、§6.14 缺省 `PlaceholderProver` 同一口径：生产默认不动，真后端显式
  开启）；装配真验证后端（§6.13 `BbVerifier`）时必须同步置 `true`（bb 模式 + 绑定闸
  = 全链真 ZK 的完整形态）。**S-48 起该配对升级为构造保证**：`SpendVerifier::
  requires_revocation_root_binding()`（缺省 `false`，`BbVerifier` 覆写 `true`）声明
  后端对 `revocation_root` 的语义依赖，`Aggregator` 全构造汇合点（`build`）构造期检查
  配对——真验证后端 + 闸关闭 = 构造即 panic（fail-fast，bin 启动即退，不落运行时半可用
  态；此前仅文档口径，S-40 的 bin 接线已实际漏配一次，见 §6.13 接线）。撤销集只增 → 集合 ≤ 撤销事件数 + 1，闸成本 = 一次哈希集
  查找（热路径零分配）；根的计算只在 `revoke` 事件与集合未命中时发生（与 §6.3 每
  epoch 密封已付的 `sparse_root()` 同成本级，不新增热路径代价）。**S-49 起集合随 WAL
  持久化**（记录种类 `RevokeRoot`，kind 6，与撤销记录同批落盘、重放零重算）：重启后
  接受集跨换代续接；残余边界（旧格式 WAL / 绑定闸关闭期的撤销无根记录 → 该部分历史
  根不追溯）见 §4.6 残余③。**S-45 起 SDK 侧对 `E_REV_ROOT`
  自动刷新重出**（witness 查询端点 §6.7 + 同意图重出证明重交，nonce 未消耗故安全——
  本闸在 `try_commit` 之前拒，同意图重发不被幂等闸缓存的原拒绝命中，走全新校验）。

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
   捐赠）。**资产差异（S-28）**：原生 ETH 模式资金 = `msg.value`；ERC-20 模式 = settle
   时 `transferFrom` 从运营者拉款（需事先 approve），且强制 `msg.value == 0`（防 ETH
   误入卡死）；
3. 挑战窗口（6h）：任何人可提交欺诈证明（§6.5）；挑战成功 → epoch `voided`；
4. `claim`：窗口过后收款人**逐条**领取原生 ETH。挑战与 claim 严格时间分离 → 挑战成功时
   无任何 claim 已付，退款干净。

### 6.5 债券/惩罚（乐观安全模型）

| 承诺 | 违约 | 惩罚 |
|---|---|---|
| 运营者质押债券（**原生 ETH**，`commit` 时 `msg.value`） | 等价双花 / 漏单 / 提交与承诺不符的 net[] | 债券罚没，判给挑战者 |
| 预算账本诚实 | 已撤销仍放行 / 超限记账 | 债券罚没 + 声誉分（Phase 2） |
| 撤销根最新 | 用过时撤销根放行已撤销委托 | 债券罚没 |
| 挑战者押金（`challenge` 随笔 `msg.value`，原生 ETH，S-38） | 欺诈证明被驳回（押金入场后任何实质验证失败） | 押金全额销毁（`address(0)`，任何一方不可取回）；epoch 状态不变、仍可再挑战 |

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
  `settlementFunded`（= Σnet）全额退运营者 → 后续 claim 全部拒绝。单次挑战
  `MAX_INTENTS_PER_CHALLENGE = 32`（epoch_capacity=100k → 树深 17，每意图 ~19 次 sha256
  预编译，~500-600k gas）。
- **挑战押金（S-38，收口 audit-scope §4「challenge 无押金」）**：v1 反垃圾原本只靠 gas
  （无效挑战整笔回滚、挑战者零损失）——垃圾挑战向量在 gas 便宜的链上不成立。S-38 起
  `challenge` 变 `payable`，押金为**部署期构造参数**（S-50，原生 ETH，与 `asset` 无关、
  与运营者债券同币种）：
  - **押金金额参数化（S-50，收口 S-38 残余自报「固定常量未动态化」）**：
    `BatchSettler(operator, asset, challengeBond)`，`uint256 public immutable challengeBond`
    （`anvil` 本地参考值 `0.1 ether`）。设计决策（记录在案）：**只做部署期参数化，不做
    运行时 setter**——改运行时金额必须引入 admin/governor 信任面，而该角色天然可双向作恶：
    抬价 → 审查欺诈证明（挑战成本 → ∞，等于拆掉 §6.5 乐观安全模型）、降零 → 复活 S-38
    收口的垃圾挑战向量。二者都比"金额过时"严重得多，v1 单运营者阶段不值得为此开 admin 面
    （本合约目前唯一权限角色 `operator` 也是 immutable，同口径）。金额随 gas 价格/债券规模
    的运行时自适应挂 Phase 2 多运营者（那时本就有治理结构可挂靠）。**部署期 fail-fast 闸**：
    `challengeBond_ == 0` 构造即 revert（`ZeroChallengeBond`）——零押金部署等于静默回退到
    S-38 之前的垃圾挑战面，构造期挡下比事后靠人眼发现可靠。
  - 其余押金语义与 S-38 逐字不变（金额来源换成 `challengeBond` 读取，四处使用点无一处
    引入新状态）：
  1. **押金入场前 revert（零成本守卫，无押金风险）**：epoch 未结算（`EpochUnknown`）、
     已被成功挑战或 voided（`EpochAlreadyChallenged`）、窗口关闭（`ChallengeWindowClosed`）、
     `msg.value != challengeBond`（`WrongChallengeBond`）。这四类是"状态/参数不合法"，
     证明根本没被审理，不构成垃圾挑战向量。
  2. **押金入场后"驳回即没收"**：押金随交易进入合约，欺诈证明的任何实质验证失败（非欺诈
     `NotFraud`、包含证明不成立、同笔重复计入、跨收款人子集、kind 形状非法、意图数越界、
     目标行越界）**不再 revert**——返回 `ChallengeRejected(epochId, challenger, reason)`
     事件，押金全额转入 `address(0)` 销毁，epoch 状态**一字不动**（不置 `challenged`/不
     `voided`/运营者债券与结算资金原封），该 epoch 仍可被再次挑战。垃圾挑战者每次尝试
     实付一笔押金（`challengeBond`，部署期定），gas 之外有了真押金。
  3. **没收款销毁（不判给任何一方）**：押金没收款转 `address(0)`，运营者/挑战者/其他方均
     不可取回——不给运营者制造"被挑战有赏"的激励，也不给任何路径新增可窃取资金池。
     （对照：运营者债券没收款**判给挑战者**，那是欺诈成立的赔偿，两者性质不同。）
  4. **押金从不停留为合约状态**：成功路径挑战者拿回 `challengeBond + 运营者债券`（一笔
     call），失败路径押金销毁，均在本笔交易内结清——合约不新增任何跨交易的挑战方余额记账，
     不扩大 §6.4 的资金面。
  5. **CEI 顺序**：拒绝路径 = 事件（状态）→ 销毁转账；成功路径 = 先置 `challenged`/`voided`
     → 挑战者转账 → 运营者退款转账。两次外部调用目标分别是挑战者（可能拒收 → `require`
     整笔回滚，与 S-11 行为一致）与运营者。
  6. **退款推送失败不阻断挑战（审计加固，收口「运营者审查欺诈证明」向量）**：挑战的
     唯一对手方就是运营者本身——若运营者退款 push 失败导致 `require` 整笔回滚（原实现），
     恶意运营者只需把 operator 地址做成收 ETH 即 revert 的合约（或让自身进 token 黑名单，
     真实 USDC 黑名单是 revert 冒泡），就能让每一次合法欺诈证明原子回滚 → epoch 永不
     `voided` → 债券机制对唯一需要防的人失效。修复：退款 push 失败（ETH `call` 返回
     `false` / token `transfer` 返回 `false` 或 revert 冒泡经 `catch` 吸收）**不阻断挑战**，
     资金留在合约并记回 `settlementFunded`；运营者经 `withdrawRefund(epochId)` 拉取兜底
     （`onlyOperator`，仅 `voided` epoch 开放——正常 epoch 的结算资金归收款人 claim，绝不
     给运营者取回路径防双花；voided epoch 的 claim 已被拒，这笔钱不会再被任何人认领）。
     回记账为贷记方向且外呼期间重入面闭合（slither `reentrancy-eth` 定性留档在代码注释）。
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
   **从 1 起（S-46 全链发现）**：电路断言 7 `spend_nonce > 0`（§5.1 防零 nonce 误用）
   ——0 起使每张委托的**首笔支付在真 prover 下必然 `E_PROVER`**（占位 prover 不消费
   nonce、聚合器不要求连续，缺口只在全链路暴露）。聚合器只禁复用（§6.2），1 起与
   已消耗集零冲突。
2. **仅传输错误**（`SdkError::Transport`）触发重试；聚合器的业务拒绝（`SdkError::Meridian`，
   错误码透传）**永不重试**。
3. 聚合器侧幂等（§6.2 幂等重发闸口）兜底重发：断线重发返回先前结果 → 不会把同一笔意图
   记两次（双花），也绝不会把一笔被拒绝的意图透传成成功。

**传输形态**：`Transport` trait 抽象「聚合器连接」——`authorize` / `submit` /
`next_nonce`（S-31 只读查询）。S-12 提供 `InProcessAggregator`（进程内聚合器，测试与
单进程嵌入用）；网络传输是 S-13 框架分发层的接缝。

**诚实边界**：
- 证明 = `PlaceholderProver`（proof 非空 + 公共输入与信封一致，**默认装配**），与聚合器内置
  `FormatVerifier`（TEMPORARY）配套；真实 S-09 电路 prover = `NoirProver`（S-43，§6.14，
  实现 core `SpendProver`）经 `SdkClient::with_prover` 显式接入，`pay()` 重试逻辑不变。
- `NonceManager` 为进程内单调计数，崩溃后不持久化。**跨重启恢复（S-31）**：重启后
  经 `SdkClient::sync_nonce(delegation_hash)` 查询聚合器（§6.7 `GET /v1/nonce`）把本地
  计数推进到 `max(已消耗) + 1` 后再继续支付——否则重启后的新支付从 nonce 1 重发，与
  聚合器已消耗 nonce 集冲突（§6.2 跨意图复用 = `E_NONCE` 拒绝，不双花但不可用）。
  空集（聚合器 `next_nonce` = 0）不回退本地 1 起的初值（S-46：`resync` 只取
  `max(本地, 网关)`，网关 0 < 本地 1 时不动）。
  单进程不重启场景无需调用（`pay()` 语义不变）。

### 6.7 网络 ingest API（S-29，多租户网关）

S-12 留的传输接缝兑现：外部 agent/数据市场经网络接入聚合器（S-16 集成谈判的硬前置）。
crate：`meridian-gateway`（`gateway/`）+ `aggregator::wire`（wire DTO 单一来源）+
`sdk::transport_http::HttpTransport`（agent 侧客户端）。

**形态决策（记录在案）**：std-only 手写 HTTP/1.1 线程网关，**不引入 tokio/axum**——
聚合器是同步内核（§4.5 单写者分片 + B8 零分配热路径），monitor `server.rs` 已立 std-only
HTTP 先例；网关层分配（JSON 解析）不进内核热路径。内核 `Aggregator` 经 `Arc` 共享给
连接线程池，吞吐目标 = 网关层不是瓶颈（内核实测 576k 笔/s，B5）。

**端点（v1.0）**：

| 方法 | 路径 | 语义 | 对应内核 |
|---|---|---|---|
| POST | `/v1/authorize` | 注册委托（§6.2 摄入管线的 register 前置） | `Aggregator::register` |
| POST | `/v1/intents` | 幂等提交意图信封（同意图重发返回先前结果，§6.2 幂等闸口） | `Aggregator::submit` |
| GET | `/v1/receipts/{intent_hash}` | 只读回执查询（S-30a，x402 merchant 验证面） | `Aggregator::receipt` |
| GET | `/v1/nonce/{delegation_hash}` | 只读下一 nonce 查询（S-31，SDK 跨重启恢复） | `Aggregator::next_nonce` |
| GET | `/v1/revocation-witness/{delegation_hash}` | 只读撤销非成员 witness 查询（S-45，§6.14 SDK 半边） | `Aggregator::revocation_witness` |
| POST | `/v1/admin/tenants` | 租户表整表热更（撤销/接入/轮换，S-54，admin_key 独立认证） | `Gateway::reload_tenants` |
| POST | `/v1/admin/revocations` | 运营者撤销委托（S-57，§4.6 撤销事件流网络入口，admin_key 同门面） | `Aggregator::revoke` |
| GET | `/healthz` | 网关存活（含内核 `accepted_count` 快照） | — |

**请求/响应（wire，JSON）**：

- `POST /v1/authorize`：`{"signed_delegation": SignedDelegation, "agent_pub": <32B hex>}`
  → `200 {"registered": true}`；业务拒绝 → `200/4xx {"error": {"code": "E_*"}}`
- `POST /v1/intents`：`{"intent": SpendIntent, "agent_sig": <64B hex>, "proof": SpendProof}`
  （`Signature64` 同款 hex 编码先例）→ **HTTP 200 + Receipt JSON**——**业务拒绝是定局
  响应不是传输错误**（`{"intent_hash": hex, "accepted": false, "reject_reason": "E_*",
  "seq": 0}`），SDK 对 `E_*` **永不重试**（幂等重试语义 §6.6 不变，重试只由传输层失败触发）。
- 信封 JSON 由 `aggregator::wire` 的 `IntentEnvelopeDto`/`ReceiptDto` 承载（serde derive，
  与内核类型 `From` 互转）；gateway 与 sdk 共用同一 DTO 定义——wire 形状单一来源，禁止
  两侧各自手写 JSON 结构。

**只读回执查询（S-30a，x402 适配层缺口 1，docs/x402-adapter.md §4）**：

- `GET /v1/receipts/<32B hex>`（可选 `0x` 前缀）→ `200` + `ReceiptDto`（accepted 回执，
  含 seq）；未命中 → `404 {"error":{"code":"E_NOT_FOUND"}}`。走与写端点相同的租户闸
  （认证 + 限流；无 body 上限——GET 无 body）。`E_NOT_FOUND` 是传输层补充码（§11），
  不进内核枚举。
- **语义边界（诚实）**：查询命中 = **已接受且未结算**——意图索引（§6.3 步骤 D 的净额
  解析源，`IntentRef`）随 `settle_epoch` 按 epoch 修剪，已结算意图查询返回 404；被拒
  意图不入索引（拒绝回执是瞬态响应，不持久化）也不可查。即：**404 ≠ 未支付**，商户
  侧验证必须在 epoch 时延内完成（x402 敞口口径见 x402-adapter §4.2——Receipt 即受理
  凭证，终局保证在链上净额，不在网关）。
- 内核侧：`Aggregator::receipt(&intent_hash) -> Option<Receipt>`——意图索引值从
  `(recipient, amount)` 扩展为 `(recipient, amount, seq)`（净额解析闭包忽略 seq 字段，
  lattice 接口不变）；查询走同一把 `Mutex`（只读路径，非热路径——热路径 B8 口径不变）。
  崩溃恢复后索引由 WAL 重放重建（未密封尾），已密封意图不可查（与修剪语义一致）。

**只读下一 nonce 查询（S-31，§6.6 NonceManager 跨重启恢复，Phase 2 缝收口）**：

- `GET /v1/nonce/<32B hex>`（可选 `0x` 前缀）→ `200` + `{"delegation_hash": "<64hex>",
  "next_nonce": <u64>}`；未注册委托 → `404 {"error":{"code":"E_NOT_FOUND"}}`。走与
  `/v1/receipts` 相同的租户闸（认证 + 限流；GET 无 body）。响应 DTO = `wire::NextNonceResponse`。
- **语义**：`next_nonce = max(已消耗 spend_nonce) + 1`（空集 → 0）——是**安全下界**而非
  精确计数：聚合器不要求 nonce 连续（§6.2 只禁复用），调用方从该值起跳过任意数值都不会
  撞上已消耗集。取 max 而非 count，因为被拒意图同样消耗 nonce（§6.2 预算拒也占位）。
- 内核侧：`Aggregator::next_nonce(&dh) -> Option<u64>`——分片账本只读派生（锁内扫该委托
  nonce 记录集），`None` = 委托未注册。**热路径零改动**（`try_commit` 不加字段不加分支，
  B8 口径不变）；扫描成本 O(已消耗数)，只读路径可接受（与 `receipt()` 同级）。**崩溃恢复
  边界（诚实）**：WAL 只记录已接受意图——被拒 nonce 的占位是瞬态的、不重建（被拒意图从未
  承诺任何东西，重启后该 nonce 复用无害），故恢复后的查询值 = `max(已接受) + 1`，可能**低于**
  重启前。这仍是安全下界：任何大于该值的 nonce 绝不与已接受意图冲突（双花安全不变量
  钉在「不撞已接受」上，不是「不撞已拒绝」）。nonce 记录不随 settle 修剪，恢复前后对已接受
  集的查询一致。
- SDK 侧：`Transport::next_nonce(&dh)`（trait 方法，`InProcessAggregator` / `HttpTransport`
  同实现；404 → `Ok(None)`）；`SdkClient::sync_nonce(dh) -> Result<u64>`——查询并把本地
  `NonceManager` 推进到 `max(本地计数, 网关值)`（本地领先时不动——避免并发客户端回退），
  返回生效值。未授权委托 → `SdkError::Local`（与 `pay()` 前置闸一致）。

**只读撤销 witness 查询（S-45，§6.14 诚实边界 3 SDK 半边收口）**：

- `GET /v1/revocation-witness/<32B hex>`（可选 `0x` 前缀）→ `200` +
  `wire::RevocationWitnessResponse`：

  ```json
  { "delegation_hash": "<64hex>", "root": "<64hex>", "path": "<16384hex>" }
  ```

  `root` = 当前撤销状态根（BE Field 32B，电路 `revocation_root` 公共输入口径，§4.6）；
  `path` = 深度 256 的兄弟路径 **扁平 hex**（256 × 32B BE Field 依深度序拼接，8192B →
  16384 hex 字符——与 gen-witness 扁平 witness 格式同口径，SDK 侧按 32B 分块还原
  `Vec<[u8; 32]>`）。响应体 ~16.5KB，远小于请求体上限口径，无独立上限检查（GET 无 body）。
- 内核侧：`Aggregator::revocation_witness(&dh) -> Option<NonMembershipWitness>`——S-42
  `RevocationSet::non_membership_witness` 直出（与 `sparse_root()` 同一压实实现，root 与
  路径出自同一棵确定性树）。`None` = 目标**已撤销**（撤销叶的路径是成员证明，不属于本
  接口语义，S-42 fail-closed）→ `404 {"error":{"code":"E_REVOKED"}}`。`E_REVOKED` 复用
  §11 主表内核码字符串（wire 层响应用码，语义同主表「委托已撤销」），不新增传输层码。
  走与 `/v1/receipts`、`/v1/nonce` 相同的租户闸（认证 + 限流；GET 无 body）。
- **语义边界（诚实）**：对**从未注册**的 delegation_hash 照常返回非成员 witness（空集
  子树根 + 全空路径）——撤销树覆盖完整 256-bit 索引空间，注册与否不是树的事实；该委托
  的意图提交仍会被管线步 1 注册闸（`E_DELEG_UNKNOWN`）拒，witness 端点不做注册校验
  （查询是只读事实面，不是授权面）。witness 是**当刻树快照**：撤销事件发生后取到的
  witness 换根，先前取的在途证明不因换代本身被拒（§6.2 绑定闸接受全部历史状态根）。
- SDK 侧：`Transport::revocation_witness(&dh)`（trait 方法，`InProcessAggregator` /
  `HttpTransport` 同实现；404 `E_REVOKED` → `Ok(None)`，其余 404 码 fail-closed 上抛
  `Local`——端点不会返回其它 404 码，出现即协议漂移）。`SdkClient` 按 delegation_hash
  分桶缓存 witness（**witness 是 per-dh 事实**：路径由目标索引决定，跨委托复用会被
  电路断言 8 重算根失配拒）：`pay()` 缓存未命中时现取入库；`E_REV_ROOT` 业务拒绝时
  现取新 witness 同意图重出证明重交（§6.14 诚实边界 3）；`sync_revocation_witness(dh)`
  显式刷新（镜像 `sync_nonce` 口径）。

**认证与多租户**：

- `Authorization: Bearer <key>`；租户表 = JSON 配置文件（`{"<key>": {"tenant": "<id>",
  "rpm": <上限>}}`），网关启动时加载。运行期可经管理端点整表热更（下节）；配置文件
  仍是事实源（部署流程 = 改文件 → 调管理端点推送同内容）。
- **每租户令牌桶**（容量=burst，速率=rpm/60）：std 原子实现，`Mutex<桶态>` 按 tenant
  分桶。超限 → `429 E_RATE_LIMITED`（该请求**未进内核**，无 seq、无记账，可安全重试）。
- 无/错 key → `401 E_AUTH`。`E_AUTH`/`E_RATE_LIMITED`/`E_MALFORMED` 是**传输层错误码**
  （§11 补充表），不进 core `Error` 内核枚举——内核语义零改动。

**租户表热更新（S-54，`POST /v1/admin/tenants`，管理面）**：

- `Config.admin_key: Option<String>`（serde default，缺省不配置）——**管理面 bearer key，
  独立于租户表**：不进 `tenants` map，不能作为租户 key 使用（租户闸只查租户表，
  两面由构造隔离）。缺省不配置时端点**不存在**（404 unknown route，与其它未路由路径
  同响应——不泄露管理面存在性）。
- `POST /v1/admin/tenants`，`Authorization: Bearer <admin_key>`，body = 租户表**全量**
  JSON（`{"<key>": {"tenant": "<id>", "rpm": <n>}}`），语义是**整表替换**（声明式、
  幂等；不是增量 patch）：

  - 撤销 = 新表删去该 key → 替换后新请求立即 `401 E_AUTH`（在途已认证请求不追溯）；
  - 接入 = 新表加入新 key；轮换 = 同 tenant id 换 key（**令牌桶按 tenant id 分桶，
    轮换不重置限流状态**——限流针对租户额度而非密钥身份）；
  - 热更新 / 撤销 / 轮换是同一操作面（整表替换自然覆盖三者），不设三个端点。
- 响应 `200 {"reloaded": true, "tenants": <n>}`（`n` = 替换后租户 key 数）。
  错误映射：body 非法 JSON / 字段缺失 → `400 E_MALFORMED`；body > `max_body_bytes`
  → `413`；admin key 不符 / 缺失 → `401 E_AUTH`。管理请求**不走租户限流**（admin key
  不在租户表，本就无从限流；管理面信任边界 = 持有 admin key 者）。
- **并发语义**：`TenantTable` 由 std `RwLock` 保护——`gate()` 取读锁（读多写少，锁成本
  相对 JSON 解析可忽略；B8 口径是内核热路径，网关层本就不在约束内，`try_commit` 内核
  零改动）。替换 = **锁内整体换表**：并发请求要么看到旧表要么看到新表，无中间态
  （不会出现「认证用旧表、限流用新表」的撕裂读）。
- **诚实边界**：无管理 UI（端点即全部接口面）；配置文件无自动 watch（推送式——文件
  变更在调端点前不生效）；admin key 明文传输（§6.7 明文 HTTP 缝未动，管理操作必须在
  TLS 终结点之后，见部署口径）；空表替换允许（显式「撤销全部租户」，admin key 独立
  存在故仍可再推恢复）。

**运营者撤销面（S-57，`POST /v1/admin/revocations`，管理面）**：

- 缺口本体：§4.6 撤销事件流「链上 revoke → 运营者调 `Aggregator::revoke(dh)`」此前
  只有进程内入口——网络化部署里运营者（远程操作方）对网关内嵌聚合器**无从触发撤销**，
  安全关键操作悬空。本端点补齐操作面；内核语义零改动（`Aggregator::revoke`：WAL 追加
  + 撤销集入叶 + 撤销根推进随 S-49 同批落盘）。
- 门面同 `/v1/admin/tenants`：`Authorization: Bearer <admin_key>`；未配置 admin key =
  端点不存在（404 unknown route，不泄露存在性）；不符 / 缺失 → `401 E_AUTH`；管理
  请求不走租户限流。body > `max_body_bytes` → `413`。
- body：`{"delegation_hash": "<64hex>"}`（0x 前缀宽容，同只读查询口径）。**单 dh**——
  批量撤销 v1 不做（撤销低频高危，逐笔确认根推进；诚实边界记录在案）。
- 语义（三路）：

  - 未注册 dh → `400 E_DELEG_UNKNOWN`（复用 §11 主表内核码字符串作 wire 响应码，
    同 `E_REVOKED` 口径）——对齐链上 `DSA.revoke` 未注册 reverts 的语义：手滑 dh 是
    配置错误，请求期暴露比静默污染撤销树好；撤销会**换根并扰动全部在途 witness**
    （可用性扰动），不该被一个错 dh 触发。fail-closed 方向 = 拒绝。
  - 已撤销（幂等重放）→ `200 {"newly_revoked": false, "revocation_root": "<64hex>",
    "revoked_len": <n>}`——**不重复落 WAL 撤销记录**（端点侧先查 `is_revoked` 再调
    `revoke`；并发窗口内两请求同 dh 至多多一条幂等撤销记录，撤销集入叶天然去重，
    `revoke()` 返回值定夺响应，无撕裂）；根不变。
  - 新撤销 → `revoke(dh)` → `200 {"newly_revoked": true, "revocation_root": "<64hex>",
    "revoked_len": <n>}`。`revocation_root` = 撤销后当刻树根（撤销集非空立即换根）；
    **链上承诺随下个密封 epoch**（§4.6）。运营者交叉确认：同 dh 再查
    `/v1/revocation-witness/{dh}` → `404 E_REVOKED`，其余委托 witness 根 = 响应根。
- **语义边界（诚实）**：撤销即时生效于**本进程**（该委托新意图 `E_REVOKED` 拒）。
  链上 `RevocationRegistry` 的 revoke 与本端点是两级独立动作（链上撤销不自动进聚合器，
  v1 无链上监听器——运营者负责传播，§4.6 债券罚没兜底「已撤销仍消费」窗口）。

**撤销跨副本传播（S-59，§6.7 管理面）**：

- 缺口本体：S-57 端点只撤销**本进程**，副本组（S-39）各副本互不感知——逐副本人工调
  端点，漏调副本继续接受已撤销委托直至 `replicas_converged` 告警（monitor 滞后告警是
  事後发现，不是阻断）。本件把传播**机制化**：撤销入口一次调用即达全组，人工逐副本
  从主路径退为故障兜底。
- 配置（`Config.revocation_peers`，serde default 空 = **缺省口径逐字节不变**——单副本
  零改动，响应体不出现 fanout 字段）：每项 `{ "url", "admin_key", "timeout_ms" }`——
  对端网关 base URL（**必须 `http://`**，网关恒明文 + 反代终结的部署口径不变，配置期
  拒 `https://`：std-only 无 TLS 依赖，静默接受只会变成运行时必败）+ 对端 admin key
  （对端可各不相同；对端未配置 admin key = 其端点 404，outcome 记失败）+ 单对端超时
  （缺省 2000ms）。
- 语义：`POST /v1/admin/revocations` 先**本地撤销**（安全优先——本地即时生效不等对端），
  再**并行** fanout 到全部 peer（每对端一个线程，POST 同款端点 + 对端 key，body 为
  归一化 dh）。响应增 `fanout: [{peer, accepted, newly_revoked?, detail?}]`
  （`skip_serializing_if` 空缺省不出现；`accepted` = 对端 HTTP 200；失败原因进
  `detail`：连接/超时/非 200 状态 + 对端 body 摘要）。**整体状态恒 200**——撤销本体
  成功后不因对端故障降级（撤销单调不可回滚，回滚 = 假撤销）；对端失败 **fail-visible**
  不吞错、**不 auto-retry**（网关无后台任务，重试是运营者动作：幂等重放同请求即可，
  重放路径 `newly_revoked: false` 但 fanout 照常执行 = 补漏重试）。
- 语义边界（诚实）：fanout 是**尽力传播不是共识**——对端列表来自静态配置，配置漏写
  副本依旧漏（`replicas_converged` 告警仍是最后防线）；对端 400 `E_DELEG_UNKNOWN`
  （副本账本漂移，对端未注册该 dh）原样透传进 `detail` 不猜测；网关不做发现、不做
  心跳、不缓存对端状态（S-39 monitor 集群面已覆盖可观测性）。链上撤销两级独立口径不变。

**HTTP 状态映射**：

| 状态 | 场景 | SDK 视角 |
|---|---|---|
| 200 | 内核 Receipt（accepted 或 E_* 业务拒绝） | 定局 |
| 400 | JSON 不合法 / 字段缺失 / hex 非法（`E_MALFORMED`）；撤销目标未注册（`E_DELEG_UNKNOWN`，S-57，复用 §11 主表码） | 定局（重发同请求无害，但不自动重试） |
| 404 | 只读查询未命中（`E_NOT_FOUND`：回执不存在；`E_REVOKED`：witness 查询目标已撤销） | 定局（重发同查询无害，结果不变） |
| 401 | Bearer 缺失/未知（`E_AUTH`） | 配置错误，不重试 |
| 413 | 请求体 > 64 KiB | 不重试（信封远小于此） |
| 429 | 租户限流（`E_RATE_LIMITED`） | **重试候选**（退避） |
| 5xx | 内核 panic/内部错误（v1 不发生：内核 WAL 失败即 panic，由进程管理器兜底） | 重试候选 |

**并发与健壮性**：thread-per-connection + 信号量上限（`max_connections`，默认 256）；
keep-alive（`Connection: close` 尊重客户端显式关闭）；请求读超时 5s；请求体上限 64 KiB。
网关崩溃恢复 = 内核语义（WAL 重放，S-10c），网关自身无状态。

**诚实边界（v1）**：明文 HTTP——TLS 由部署拓扑的反代终结（生产部署前必须有 TLS 终结点，
S-15 部署清单项）；无指标端点（monitor `server.rs` 独立刮取）；`/v1/intents` 批量端点
（`submit_batch`）不暴露（单请求单意图，批量走 SDK 侧并发）。

**部署拓扑 · TLS 反代终结（S-56，具体配置与排错表见 docs/ops.md §7）**：

- 网关**恒明文 HTTP**（std-only，不引 TLS 依赖——依赖面即攻击面，与 B8 同口径）；TLS
  在反代终结，**反代是网关的信任边界**。`listen` 生产必须回环绑定（缺省
  `127.0.0.1:9400` 即回环）；反代 → 网关一跳是明文，必须落在同一信任域内（同机回环 /
  专用内网）——跨网段明文跳等于没终结。
- **反代不是认证边界**：网关认证只看 `Authorization: Bearer`，不读 `X-Forwarded-For` /
  `X-Real-IP` / `X-Admin` / `Host` 等任何代理可注入头（伪造这些头不改变认证与限流判定，
  gateway 测试钉死）——不能靠「在反代后面」这一网络位置补安全，bearer key 是唯一凭据。
  限流按租户 key 分桶（S-54），与来源 IP 无关：反代聚合多客户端不影响额度正确性，
  反代侧按 IP 限流是**额外的**防护层而非网关语义。
- **反代侧语义钉死**（症状 → 处置见 ops.md §7 排错表）：
  - HTTP/1.1 透传——网关无 HTTP/2，chunked 请求恒 `400 E_MALFORMED`（反代不得对内
    重写为 chunked；Caddy `flush_interval -1` 透传原样）；
  - 请求体上限 ≥ 网关 `max_body_bytes`（64 KiB）+ 头部余量——代理先 413 抢答会让
    合法信封被代理拒（症状：`Content-Length` 合法却拿不到网关错误码）；
  - 代理超时 > 网关 `read_timeout_ms`（5s）且读超时覆盖完整请求——`/v1/intents` 在
    bb 模式下含真证明验证（§6.13），代理先超时会把网关还在算的请求断成 5xx，
    SDK 侧表现为重试候选但其实是配置错；
  - **代理层不得对 `POST /v1/intents` 透明重试**——网关 200 即定局（业务拒绝也在
    200 里，§6.7 状态映射），代理重试只放大限流打点与 re-ack 幂等记账（不重账但
    打点膨胀）；429/5xx 的重试语义归 SDK `RetryPolicy` 退避；
  - `/healthz` 可直通（无认证的回环事实面）；`/v1/admin/*`（S-54 租户表 + S-57 撤销面）
    **必须在反代层加 ACL**（源 IP 白名单或独立 listener）——admin key 明文只出现在
    回环跳内，TLS 终结后它仍是唯一凭据，ACL 是纵深防御而非替代。
- monitor（9100）恒回环绑定，**不进公共反代**（Prometheus 刮取走内网或独立反代）。

**诚实边界（部署面，S-56）**：无 mTLS（v1 信任域内单跳不做双向认证）；网关不校验
`Host` 头（回环绑定即拓扑边界）；本节与 ops.md §7 的示例配置未经参考机实跑验证
（本机无 nginx/Caddy）——逐条对照的是网关**已实测语义**（body 上限、读超时、chunked
拒绝、keep-alive、代理头非信任，均有测试锚定），不是跑通的部署，首次上线前须在目标
环境过一遍 ops.md §7 部署清单。

### 6.8 x402 适配层 · 客户端（S-30b，docs/x402-adapter.md §2.1）

站位：Meridian 是 **x402 的结算后端**（卖水），不是再造付费协议。本节 = agent 侧
fetch 拦截：标准 x402 资源服务器回 `402` 后，把 `paymentRequirements`（scheme
`meridian-v1`）映射成 [`SdkClient::pay`] 意图，支付后带 `X-PAYMENT` 头重放请求。
crate：`sdk::x402`（std-only，与 crate 其余部分同同步口径）。

**线格式（对齐 x402 v1 惯例；自定义 scheme 起步，上游注册路径跟进后标准化）**：

- 402 响应体（消费侧字段，camelCase、金额恒字符串）：`{"x402Version": 1,
  "accepts": [{"scheme", "network", "maxAmountRequired": "<原子单位字符串>",
  "resource": "<URL>", "description", "payTo": "<0x 20B>", "maxTimeoutSeconds",
  "asset"}]}`。v1 只消费 `scheme == "meridian-v1"` 的条目（多条取首条）；无则
  `SdkError::Local`（不伪装成其它 scheme 的 client）。
- `X-PAYMENT` 头（base64url 无 padding 的 JSON，`{"x402Version", "scheme":
  "meridian-v1", "network", "resource", "payload": {"intentHash": "<0x 32B>",
  "seq", "spendNonce"}}`）。merchant 验证 = 对网关查 `GET /v1/receipts/{intentHash}`
  （§6.7 S-30a），accepted 即放行——**信封不内嵌**（离线验签是 S-30c facilitator 缝）。

**字段映射（x402 → SpendIntent，docs/x402-adapter.md §3）**：

| x402 字段 | Meridian 字段 | 语义 |
|---|---|---|
| `payTo` | `intent.recipient` | 0x 20B EVM 地址直通 |
| `maxAmountRequired` | `intent.amount` | USDC 6 decimals 原子单位直通（字符串解析） |
| `resource` | `intent.category` | `sha256(host + path)`——类目是 owner 白名单的粗粒度路由控制，query 不绑定（诚实边界） |
| `resource`（全文） | `intent.memo` | `sha256(resource)[..32]` 请求指纹（审计对账用） |
| `maxTimeoutSeconds` | `intent.expires_at` | `now + maxTimeout`（缺省 60s）——支付有效期绑定服务器要求 |
| `spend_nonce` | `NonceManager` | 幂等语义 §6.6 不变 |
| `network` / `asset` | 回显进 payload | v1 仅 Base USDC，网关部署配置裁决 |

**执行流**：`X402Client::request` → `Fetch::fetch`（HTTP 执行器接缝）→ 非 402 原样
返回（`X402Outcome::Free`）→ 402 → 映射 → `SdkClient::pay`（固定 nonce + 幂等重试，
§6.6）→ `X-PAYMENT` 重放 → 二次 402 = `SdkError::Local`（支付被资源服务器拒绝，不重试）；
否则 `X402Outcome::Paid { response, proof }`（proof 含 intent_hash/seq/spend_nonce，
供对账）。

**接缝与诚实边界（v1）**：`Fetch` trait 由调用方注入；内置 `HttpFetch` 仅支持明文
`http://`（手写 TcpStream，与 §6.7 同口径），**https 资源须注入 HTTPS 客户端**（如
reqwest 包装）；base64url 手写实现（RFC 4648 向量锁定，不引新依赖）；每
`X402Client` 绑定一张委托（`delegation_hash`）；`X-PAYMENT-RESPONSE` 结算回执头
v1 不消费（epoch 结算语义下 merchant 对账走网关查询，facilitator /verify /settle
是 S-30c 范围）。

### 6.9 x402 适配层 · merchant 参考实现（S-30c，docs/x402-adapter.md §2.1 server 侧）

crate `meridian-facilitator`（`facilitator/`）。x402 缺口清单的 merchant 验证面参考
实现：**受保护资源服务器**如何接 `meridian-v1` 支付——验证逻辑全部落在"对 Meridian
网关查回执"，零密码学依赖（S-30a 的查询接口即验证接口）。S-32 起该 crate 另含可选的
EIP-3009 兼容桥（含 ecrecover，见 §6.10）；本节的"零密码学"指 `meridian-v1` 路径。

**形态决策**：std-only 手写 HTTP/1.1（§6.7 同先例，thread-per-connection、单请求
close 模式）；axum/tokio 虽允许（merchant 侧不在内核热路径）但不必要——参考实现的
价值是"最少代码演示集成面"，不是性能。

**分发逻辑（`Facilitator::handle` 纯分发，单测不经 socket）**：

- `GET /healthz` → `200`；其它路径 = 单一受保护资源（v1）。
- 无 `X-PAYMENT` → `402` + paymentRequirements JSON（`scheme: meridian-v1`，
  wire 类型复用 `sdk::x402` 的 `PaymentRequired`/`PaymentRequirements` Serialize）。
- 带 `X-PAYMENT` → base64url 解码（`sdk::x402::base64url_decode`，宽容 padding）→
  `PaymentPayload` 解析 → 校验 `scheme` / `network` / `resource` 与配置一致 →
  `HttpTransport::receipt(intent_hash)` 查网关（S-30a）：
  - `Ok(Some(_))` → `200` 受保护资源内容；
  - `Ok(None)` → `402`（**404 ≠ 未支付**语义下"不可验证即不放行"——未结算/被拒/
    过期统一回 402，错误信息区分）；
  - `Err(_)`（网关传输失败）→ `503` **fail-closed**（验证面不可用绝不放行）。

**诚实边界（v1）**：单资源模型（无路由/鉴权中间件）；明文 HTTP（TLS 反代终结）；
不产出 `X-PAYMENT-RESPONSE`（对账走网关查询）；结算侧（epoch claim、对账导出）
不在本件——参考实现演示的是"merchant 怎么接"，不是生产 facilitator。

**三角色 e2e 验收**：X402Client（agent，HttpFetch）→ facilitator `402` → `pay`
（经真网关 + 真聚合器）→ `X-PAYMENT` 重放 → facilitator 查网关回执 → `200`；
另验伪造 `intentHash` → `402`。

### 6.10 x402 适配层 · EIP-3009 兼容桥（S-32，docs/x402-adapter.md §4 缺口 3）

**问题**：存量 x402 client 只会说标准 `exact` scheme（签 EIP-3009
`transferWithAuthorization`），不会说 `meridian-v1`。桥 = facilitator 侧把标准
payload **验签后转投 Meridian 摄取**，merchant 侧零感知（仍是"查网关回执"单一
验证面，§6.9 不变）。

**形态**：`facilitator/src/eip3009.rs`（模块 `Eip3009Bridge`）。新增依赖
`k256`（workspace 已有，ecrecover 用）与 `sha3`（keccak256 用）——**不引新外部
依赖**；EIP-712 的 `abi.encode` 为定长类型序列，手写拼接（全 32B word）。

**402 体（双 scheme）**：`accepts[]` 增第二条 `scheme: "exact"` 条目，
`PaymentRequirements` 增可选 `extra: {name, version}`（serde default + skip——
EIP-3009 域参数，x402 exact 惯例）；`meridian-v1` 条目与其余字段不动。

**桥接流程（`X-PAYMENT` scheme == `"exact"` 时）**：

1. 解析标准 payload：`{"x402Version", "scheme": "exact", "network", "resource",
   "payload": {"signature": "<0x 65B r||s||v>", "authorization": {"from", "to",
   "value": "<原子单位字符串>", "validAfter", "validBefore", "nonce":
   "<0x 32B>"}}}`（camelCase，与 §6.8 同 wire 惯例）。
2. 绑定校验（fail-fast → 402）：`network` / `resource` 与配置一致；
   `authorization.to == payTo`；`value == maxAmountRequired`（原子单位，超 u64
   拒）；`validAfter <= now < validBefore`。
3. **EIP-712 验签**（ecrecover，链下密码学）：domain（`name` / `version` /
   `chainId` / `verifyingContract` 来自配置）+ `TransferWithAuthorization`
   typehash → keccak256 → k256 `recover_from_prehash`（v ∈ {0,1,27,28} 宽容）→
   恢复地址（`keccak256(pubkey)[12..32]`）== `from`，否则 402。
4. **转投 Meridian 摄取（垫付模型）**：facilitator 以自身身份（`AgentWallet` +
   owner key，均来自配置种子）经 `SdkClient::authorize` 注册一张委托（限额来自
   配置，惰性首用注册），随后 `SdkClient::pay` 桥接意图：`recipient = to`、
   `amount = value`、`category = sha256(host + path)`（§6.8 同映射）、
   `memo = keccak256(规范序列化 authorization ++ signature)[..32]`（对账指纹）、
   `expires_at = min(validBefore, now + maxTimeoutSeconds)`。`spend_nonce` 走
   `NonceManager`（§6.6 幂等语义不变）；S-33 起 `register_operator` 注册后接
   [`SdkClient::sync_nonce`]（S-31）——持久化重放闸把"重启"变成受支持场景，而
   `authorize` 的 delegation nonce 是进程内自增（重启归零 → 同 delegation_hash），不恢复
   则首笔支付撞已消耗 nonce（`E_NONCE` 定局拒）。摄取仍走**全量 DSA 闸口**（预算/速率/
   撤销/ZK 证明），桥不旁路任何协议层检查。
   **真 prover 装配（S-47，S-46 候选⑤首块）**：`BridgeConfig.noir`（`None` = 占位
   prover，缺省口径逐字节不变；`Some(NoirAssembly { root, attestation_secret })` =
   `NoirProver::from_repo_root(root)` + `SdkClient::with_noir`，§6.14 同源装配——垫付
   client 的 prove 后端与 attestation keyring 同一实例同一 secret）。缺省占位与
   §6.13 `MERIDIAN_VERIFY_BACKEND` 缺省 `format`、§6.14 缺省 `PlaceholderProver`
   同口径：生产默认不动，真后端显式开启。bin 侧 `MERIDIAN_BRIDGE_NOIR=1` +
   `MERIDIAN_BRIDGE_NOIR_ROOT`（缺省 `.`）+ `MERIDIAN_BRIDGE_ATTEST_SECRET`
   （0x 32B hex，启用时必填——熵由调用方供给，SDK 不生成随机熵，§6.14 诚实边界 2）；
   启动期检查 root 下 `gen-witness/` 与 `circuits/` 存在（fail-fast，配置错误启动即
   暴露，同缺种子 panic 口径），工具链探测仍惰性（首次 `pay()` 时
   `NoirProver::from_dirs`，不可得 `E_PROVER` → 503 fail-closed）。
5. **重放闸**：进程内 `(from, eip3009_nonce) → intent_hash` 映射——同 payload
   重放不再摄取，直接落 §6.9 的回执查询路径（accepted → 200 / 未命中 → 402）。
6. 桥的 `SdkError` 不透传内部细节：摄取失败统一 402（业务拒绝）或 503（网关
   不可达，fail-closed 同 §6.9）。

**诚实边界（v1）**：

- **EIP-3009 的链上执行不在本件**（不调 `transferWithAuthorization`）——client
  → 运营商的清算是运营商侧账务（`memo` 指纹 + 原始 payload 留档），merchant
  收到的是 Meridian 净额。桥只做"验签 + 摄取"，不碰资产。
- **垫付模型**：被消费的是运营商自己的 Meridian 预算——client 信用风险由白标
  合同承担（§4.2 受理凭证同口径），不是协议层担保。
- **重放闸持久化（S-33，2026-08-30）**：S-32 的重放闸是进程内存态（重启丢失后同一
  EIP-3009 payload 可能再次摄取，双花的是运营商自身预算）。S-33 收口：`facilitator/src/replay.rs`
  的 `ReplayJournal`——append-only JSONL，每行 `{"from","nonce","intentHash"}`（0x 20B/32B hex，
  camelCase 同 §6.10 wire 惯例），摄取成功后**先内存登记、再落盘**（单行 write + `flush` +
  `sync_data`，崩溃最坏丢尾部半行）；`Eip3009Bridge::open(cfg, path)` 启动时重放日志重建闸表，
  坏行（崩溃撕裂 / 损坏）跳过并计数（`skipped_journal_lines()` 可观测，不阻断重启）。
  日志写失败 → `BridgeError::Journal` → **503 fail-closed**（`E_REPLAY_JOURNAL`，运维故障
  不归罪 client；内存表已登记，client 重试命中重放闸不重复摄取）。
  bin 经 `MERIDIAN_BRIDGE_REPLAY_JOURNAL` 启用（缺省仍进程内存态，v0 兼容）。
  **诚实边界（残余）**：① 落盘失败时意图**已摄取**而登记不可持久化——响应 503 但本进程
  内存闸已挡重放，跨进程重复摄取的概率限于磁盘故障窗口；② 日志随桥接笔数线性增长
  （EIP-3009 `nonce` 每笔天然唯一，无重复键可压实；参考实现不设轮转/归档，运维侧按需处理）。
- EIP-712 domain 由配置显式给出（USDC on Base：name `"USD Coin"` / version
  `"2"` / chainId 8453 / `0x8335…2913`），v1 不做域自动发现（`eip712Domain`
  扩展随上游演进）。
- EIP-3009 `nonce` 不查 USDC 合约状态（不提交链上，无需）；`value` 以 u64 直通
  Meridian `Amount`（超上限即拒，见 2）。

**验收**：模块单测（EIP-712 digest 构造 / ecrecover 往返 / 坏 v / 冒充 from /
`to` / `value` 不符 / 时间窗 / 超额）+ `handle` 纯分发单测（exact 路径绑定与
重放闸）+ 真 socket e2e（真聚合器 + 真网关：标准 exact client → 桥摄取 → 200；
重放同 payload → 200 且不再摄取；伪造签名 / `to` 不符 / 过期 → 402）。
**S-33 增量**：`replay.rs` 单测（append/重载往返、坏行跳过计数、缺文件建空）+
`Eip3009Bridge::open` 重建单测（预置日志 → 闸表命中 / 坏行计数）+ 真 socket e2e
（facilitator 带 `MERIDIAN_BRIDGE_REPLAY_JOURNAL` 摄取 1 笔 → **销毁重建**（同日志路径）
→ 同 payload 重放 200 且 `accepted_count` 不变（重启后重放闸仍命中）；新 nonce 正常摄取
（闸不误挡））。
**S-47 增量**：`BridgeConfig.noir` 装配单测（缺省 `None` 口径逐字节不变 / noir 装配
`config()` 投影）+ 门控 e2e（`MERIDIAN_ZK_PROVER_E2E=1`，与 §6.14 9c 同门同工件）：
真 BbVerifier 网关（`enforce_revocation_root = true`）+ noir 装配桥摄取 1 笔 →
真电路证明经 `with_noir` 垫付 client 产出并被聚合器密码学接受（占位证明在 bb 模式下
必被全拒，§6.13——e2e 通过本身即证装配生效），重放同 payload 落重放闸不再摄取。

### 6.11 热路径延迟直方图（S-35，ops.md §5 挂账项收口）

S-15 立「不在热路径埋点」的口径时把 p99 挂账为「后续按需加、先测影响」。本节兑现：
固定桶无锁直方图，**热路径仍零分配、零锁**（B8 口径不变），以两次 `Instant::now()` +
一次原子 `fetch_add` 的常数代价换 p99 可观测性。

**形态（`aggregator/src/hist.rs`，`LatencyHistogram`）**：

- 32 个 log2 微秒桶（`[AtomicU64; 32]`）+ `count` / `sum_us` 两个原子计数器。桶 `i`
  覆盖 `[2^i, 2^(i+1))` μs（桶 0 含 0 = 亚微秒），`bucket_of(us)` = `floor(log2(us))`
  下取整、≥2^31 μs 一律钳入桶 31（上界 ≈ 2147 s，超过即告警态，不需要更宽）。
- 计量点：`Aggregator::submit` 全路径（接受、拒绝、幂等 re-ack 一律计时）——语义是
  **调用方观测到的 API 延迟**，不是内核分段耗时。
- 查询：`snapshot()` 逐桶 `load(Relaxed)` 拷出 `LatencySnapshot`（纯只读，不碰任何
  锁，B8：抓快照不引入热路径争用）；`p99_us()` 取最小累计占比 ≥ 99% 的桶的
  **上界** `2^(i+1)` μs。

**诚实边界**：

- p99 是 **log2 桶上界近似**，不是精确分位数（桶内均匀分布不假设）；要精确分布用
  `/metrics` 的 `_bucket` 原始累计值自算（Prometheus `histogram_quantile`）。
- 会话计数，**不持久化**（同 `rejected` 口径）：崩溃恢复后直方图从 0 起；WAL 只记录
  账本事实，延迟分布属瞬态观测。
- `sum_us` 用 u64 微秒整数累加（亚微秒部分归桶 0 不进和）——`_sum` 是下界口径。

**导出（`monitor/src/metrics.rs`）**：Prometheus histogram 家族
`meridian_submit_duration_seconds_bucket{le=...}`（32 个有限 `le` 升序 +
`+Inf`，累计语义）/ `_sum` / `_count`（`# TYPE ... histogram`），外加预计算的
`meridian_submit_duration_p99_seconds` gauge（Grafana 直用；精确分位数请在
Grafana 侧对 `_bucket` 跑 `histogram_quantile`）。`le` 值以秒记（`2^i μs = 2^(i-6) s`）。

**性能账（B5/B6/B8 复测口径）**：埋点代价 = 每次 `submit` 两次 `Instant::now()` +
1 次 `fetch_add(Relaxed)`，无分支外的新分配。实测影响见 §8.2 B5 注（S-35 回填）。

### 6.12 多实例集群指标聚合（S-39，ops.md §6 挂账项收口）

S-15 起 monitor 只盯一个 WAL；§1 拓扑的「聚合器实例（多实例，热备）+ WAL 副本」部署形态
缺一个聚合视图。本节兑现：`meridian-monitor --wal <path>` **可重复传**（N ≥ 1），单进程
逐副本 `restore_from_wal`，一个 `/metrics` + `/healthz` 端点服务整个副本组。

**口径决策（记录在案）**：本件聚合的语义是**热备副本组**——N 个 WAL 是同一逻辑账本的
副本（§1 拓扑「WAL 副本/多实例」），不是独立分片。因此集群账本类指标取 **max**（最新
推进副本）而非 sum（sum 会把备份副本双计）；独立分片多实例（每实例独立账本）不属于本
件口径，各自跑单实例 monitor + Prometheus 侧聚合即可，需求明确后再议。

**健康（`monitor/src/cluster.rs::evaluate_cluster`）**：

- 逐副本跑既有三检查（§3，口径不变），N > 1 时每条 `detail` 前缀
  `replica=<名字> ` 定位到副本；N = 1 时输出与单实例模式**逐字节一致**（S-39 是加法，
  不动既有单实例 JSON）。
- 新增集群级检查 `replicas_converged`（仅 N > 1）：全副本
  `(accepted_count, revoked_len, revocation_root)` 三元组逐一相等（账本推进 + 撤销承诺
  都收敛），否则 degraded。**无「可调滞后阈值」**——相等即滞后 0，容忍「落后 N 笔」会把
  账本分歧常态化（fail-closed）；异步副本复制（跨机）部署的滞后告警走
  `meridian_cluster_replica_lag` gauge 阈值（§8.3 口径：告警阈值属运营配置，健康判定不放宽）。

**指标（`monitor/src/cluster.rs::cluster_samples`，集群 gauge 不带 `instance` label）**：

| 指标 | 口径 |
|---|---|
| `meridian_cluster_instances` | 被监控副本数（`--wal` 个数） |
| `meridian_cluster_accepted_total` | 副本间 accepted_count **max**（热备组同一逻辑账本，最新推进副本；求和会双计） |
| `meridian_cluster_replica_lag` | 副本间 accepted_count max−min（备份滞后笔数，0 = 收敛） |
| `meridian_cluster_pending_sealed` | 副本间最差结算滞后（max，取最差副本） |

**实例标签（诚实边界）**：N > 1 时每副本样本的 `instance` label = **WAL 文件名（stem）**
——快照里的 `instance_id` 是 `meridian-<monitor 进程 pid>`（§4.1 口径），同一 monitor 进程
恢复 N 个副本会同值，Prometheus 序列会撞。N = 1 时保持 `instance = <instance_id>` 既有
行为（Grafana 面板 `label_values(meridian_instance_info, instance)` 不变）。多副本模式要求
各 WAL 文件名互异（启动即报错退出，不猜）。

**实现（`monitor/src/bin/main.rs`）**：`ReplicaScrape`（每副本聚合器 + 独立 WAL Intent
计数 + 独立刮取窗口状态）× N + `ClusterReporter` 实现 `Reporter`（`server.rs` 接口不变）；
`--once` 输出集群 health JSON + 全量 metrics 文本，退出码沿用 0/3（任一副本 degraded 即
3）。吞吐速率逐副本独立按各自窗口增量推算。

**诚实边界**：集群聚合是**副本组视角**，不是分布式共识监控——副本间分歧只报告（degraded
+ lag gauge），不裁决谁是真值（裁决 = 接管 WAL 人工核对，§5 处置）；每副本吞吐仍是刮取
窗口均值（§4 口径不变）；`--once` 模式下 N 个副本逐个全量重放 WAL，启动耗时随副本数线性。

### 6.13 真实 ZK 验证后端（S-40，bb wrapper，验证侧 TEMPORARY 缝收口）

S-10 起摄取路径验证证明用 `FormatVerifier`（TEMPORARY，proof 非空即过，`aggregator/src/proof.rs`）
挂账至今。S-09 实测真验证 5.14ms p99（§5.5），本件把**验证侧**换成真电路验证：`BbVerifier`
（`aggregator/src/bb.rs`）实现同一 `SpendVerifier` 缝，子进程调用 bb CLI 验 UltraHonk 证明。
上层 API 与摄取闸口次序不变（验证在验签/预算之后、公共输入一致性比对之前）。

**bb verify 契约（S-40 实测，bb 6.0.0-nightly.20260724）**：

- `bb verify -t evm-no-zk -p <proof> -k <vk> -i <public_inputs>`，flavor 必须与 §5.3 写 VK 时
  一致（`evm-no-zk`，UltraKeccakFlavor，VK 1888B）。
- proof 文件 = **纯证明**（本电路实测 8128B），**不含**公共输入——实测按 32B 字段对齐逐字段
  比对排除内嵌/拼头/拼尾三种布局（大端/小端/Montgomery 形式均不匹配）。
- public_inputs 独立文件：121 字段 × 32B **大端**（§5.3 回读脚本同规范）。`-i` 缺省路径是
  `<cwd>/target/public_inputs`（cwd 不对即 `Unable to open file`）——**必须显式传 `-i`**。
- 防篡改实测：改 pi 任一字节 → `Non-canonical public input: value >= field modulus` 拒绝；
  改 proof 任一字节 → `Deserialized point is not on the curve` 拒绝。公共输入与证明是真密码学绑定。

**公共输入序列化（`serialize_public_inputs`，121 字段 × 32B 大端 = 3872B）**：字段序 = 电路
§5.1 参数序——`agent_commit[32B]`→32 字段、`delegation_hash[32B]`→32、`recipient[20B]`→20、
`amount(u64)`→1、`category[32B]`→32、`spend_nonce(u64)`→1、`expires_at(u64)`→1、
`revocation_root`→1、`now(u64)`→1。编码规则：`[u8; N]` **每字节一个字段**、`u64` 一个字段，
各按 32B 大端展开；`revocation_root` Rust 侧是 `[u8; 32]` 但电路是 `pub Field` → 按 256-bit
**大端整数**取一个字段（不是 32 个字节字段）。与 `scripts/formal_readback.py` 的 expected
构造同一规范（第三实现交叉校验兜底）。

**BbVerifier（`impl SpendVerifier`）**：`proof.proof` 字节直接喂 bb（S-09 CLI 管线产物口径）；
临时目录 `target/bb-verify/<pid>-<原子计数>/`（并发安全，无新依赖），写 proof/pi/vk 三文件 →
调 bb → 退出码 0 = 通过并原样返回公共输入、非 0 = `E_PROOF`。**fail-closed**：bb 不可得、
临时目录建不了、进程 spawn 失败一律 `E_VERIFY_BACKEND`（新错误码）——与密码学拒绝区分
（运营可见），**绝不静默降级回格式校验**（静默降级 = 安全事故）。

**后端解析（三层，探测逻辑与 §8.3 verify.sh 第 9 步同款）**：① Windows 原生 bb
（`MERIDIAN_BB_BIN` 覆盖路径）→ ② WSL2 兜底（`MERIDIAN_WSL_DISTRO` 缺省 MeridianUbuntu，
Windows 路径经 `/mnt/<盘>/` 转换后进 WSL 调 bb）→ ③ 皆无 → **构造期报错**（bin 启动即退，
不落运行时半可用态）。

**接线**：`meridian-gateway` 环境变量 `MERIDIAN_VERIFY_BACKEND=format|bb`（**缺省 format**，
生产默认口径本件不动）+ `MERIDIAN_BB_VK`（vk 文件路径，bb 模式必填、无缺省）。bench / perf
gate 口径不变（FormatVerifier，§8.2 吞吐基线不回填）。**装配配对闸（S-48）**：bb 模式下
证明公共输入 `revocation_root` 有密码学语义，网关 bin 同步置
`IngestConfig::enforce_revocation_root = true`（§6.2 绑定闸，S-40 本件当时漏配——bin 接线
仍是 `IngestConfig::default()`，绑定闸关闭，装饰性 ZK 在装配面复活）；该配对同步升级为
构造保证（`SpendVerifier::requires_revocation_root_binding` 缺省 `false` / `BbVerifier`
覆写 `true`，`Aggregator` 构造期检查，漏配即 panic 启动即退）——未来任何真验证后端
装配点（monitor / mcp-server / 新 bin）不再可能静默漏配。

**验收测试**：单测（序列化 golden：121 字段/3872B/字段序/revocation_root 大端整数口径；
fail-closed 错误码）+ e2e（`aggregator/tests/bb_verify_e2e.rs`）：从 `circuits/Prover.toml`
**手工重建**公共输入（第三实现，不读 bb 的 public_inputs 文件——防止序列化器抄自己的答案），
配 `circuits/target/{proof,vk}` 真工件跑四案——真证明接受 / 篡改 proof 拒 / 篡改 pi 拒 /
pi 与信封不一致拒。e2e 由 `MERIDIAN_BB_E2E=1` 门控：verify.sh 第 9 步 formal_zk 产出新鲜
工件后第三 run 拉起；CI noir job formal 之后同款（ubuntu 原生 bb，走 Windows 原生分支语义）。

**诚实边界**：

1. **只收口验证侧，prove 侧 S-43 收口（§6.14）**：SDK 生产路径的 proof 仍来自
   `PlaceholderProver`（格式占位）——`MERIDIAN_VERIFY_BACKEND=bb` 开启后这些 proof
   **会被全拒**（fail-closed 的正确行为，不是 bug）；真 prover（agent 侧 S-09 电路 prove）
   实现 core `SpendProver`（`NoirProver`，§6.14），**默认装配仍为占位后端**（两侧真后端都
   经显式配置开启才算全链真 ZK）。e2e 用 CLI 管线真产物实证密码学通路。
2. **CLI 子进程 wrapper 不是 in-process**：进程开销 ~0.77ms（§5.5 延迟分解占 15.5%），单验证
   p99 ~5-8ms 仍在 §5.5 的 10ms 预算线内；100μs/笔 摊薄目标需递归聚合（§5.4 Phase 2，S-18
   实证 BB 原生批验证对本 flavor 不可用）。in-process 封装（`bb_rs`/stdlib 绑定）收益上界
   ~15%，留作后续项。
3. **撤销根哈希错配（§4.6 残余诚实缝）S-41 已收口**：聚合器账本撤销树自 S-41 起与电路同
   哈希同叶规范（`aggregator/src/noir_pedersen.rs` 复现 Noir `pedersen_hash`，三层验证锚见
   §4.6），`sparse_root()` 与电路 `revocation_root` 公共输入数值可比。本件（S-40）当时该缝
   仍在：bb 模式下 `revocation_root` 公共输入只能来自 gen-witness 管线，不可直接喂聚合器
   账本树根。残余：聚合器尚不产出非成员路径，prover 侧消费聚合器树属下一步候选②。
4. **每笔验证 = 一次临时目录写盘 + 一次 bb 进程**：吞吐受文件系统与进程 spawn 支配，bb 后端
   不进 perf gate（吞吐基线口径不变）。

### 6.14 真 prover（S-43，agent 侧 `NoirProver`，prove 侧 TEMPORARY 缝收口）

§6.13 诚实边界 1 兑现：SDK 侧真电路证明生成。`meridian-sdk::prover::NoirProver` 实现
core `SpendProver`，六步链路——Rust 只做纯字节逻辑与进程编排，**一切曲线数学（BJJ 标量乘、
Poseidon）留在 Noir**（S-05 教训守住）。

**契约变更（core/src/zk.rs）**：

- `SpendProofRequest` 新增 `attestation_secret: [u8; 32]`——BabyJubJub/EdDSA 私钥标量
  （LE 32B）。Rust 侧当**不透明字节**：只进 Noir oracle 入参与大整数归约，不进任何曲线
  运算（与 gen-witness `secret: Field` 同一语义）。
- `revocation_root: [u8; 32]` 升格为 `revocation: RevocationWitness { root, path }`——
  S-42 聚合器 `RevocationSet::non_membership_witness` 直出，root 与 path **单一来源**
  （同一棵确定性树），防「根与路径各拿一份」漂移。
- 新错误码 `E_PROVER`：证明生成失败（工具链不可得 / witness 求解失败 / 交叉校验失配 /
  撤销 witness 不自洽）。fail-closed，**绝不降级回占位证明**（对齐 §6.13 的
  `E_VERIFY_BACKEND` 口径）。
- `attestation_secret` 值域闸：必须是合法 EdDSA 私钥标量（数值 < 子群阶 SUBORDER）——
  越界值进 oracle 会被 nargo 按 BN254 域模拒绝（Field 反序列化失败），prove 入口前置
  同一闸给出同一错误码（e2e 实证：`[0x42; 32]` 即越界）。

**prove 链路（六步）**：

1. Rust 算 `zk_intent_hash`（`core::dsa` 纯字节逻辑，第二实现）。
2. **Noir oracle**：gen-witness 复用为曲线 oracle——`nargo execute oracle
   --prover-name ProverSDK --overwrite-return`（`--prover-name` 读写包目录下独立的
   `ProverSDK.toml`，**不碰**正式管线 `Prover.toml`，S-37 的备份还原逻辑不在此依赖；
   witness 显式命名 `oracle.gz` 不覆盖正式工件）。入参 `revoked_a/b` 填零 = 空撤销集
   （叶 `encode_field(0) = 0 = EMPTY`），树输出**弃用**——撤销 witness 一律来自聚合器
   （见步 5）。取 `agent_pub_x/y`、`sig_r/h`、`sig_r8_x/y`。
3. **Rust 交叉校验**（第三实现锚，镜像 `formal_gen_to_prover.py`）：
   `agent_commit = sha256(x_le ‖ y_le)`、`intent_hash` 重算 == oracle 输出；任一失配
   `E_PROVER`。
4. **签名标量归约**（`sdk/src/prover/scalar.rs`，Rust 大整数、零新依赖）：
   `s = (r + h·secret) mod SUBORDER`（SUBORDER 254-bit；u64 limb 乘法 + 二进制长除
   归约）。golden 锚 = `formal_gen_to_prover.py` fixture 的 s（Python 第三实现锁定）。
   Noir 1.0 无 Field 模运算，归约必须在电路线外做（§6.13 同源决策记录）。
5. **撤销 witness 自洽**（fail-closed）：`path.len() == 256`（占位口径在步 0 前置闸
   即拒，不进任何重操作）；用聚合器
   `noir_pedersen`（pub 导出）从 path + EMPTY 叶重算根 == `revocation.root`（方向约定 =
   电路 `compute_merkle_root`：索引位 0 → `H(当前 ‖ path[d])`）。已撤销目标在 S-42 接口
   即返回 `None`，prove 侧不提供绕过路径。
6. 拼 `circuits/ProverSDK.toml`（公共 + 私有 witness 全量，字段序 = §5.1）→
   `nargo execute sdkproof`（**电路自校验**：断言 1-9 全过才有 witness——§4.6 残余②尾
   的「电路消费交叉锚」在此兑现：Noir `compute_merkle_root` 吃聚合器产路径重算，与公共
   输入 `revocation_root` 对账）→ `bb prove -t evm-no-zk -b target/spend_authorization.json
   -w target/sdkproof.gz -o target/sdkout`（flavor 与 §6.13 验证侧一致，UltraKeccakFlavor）→
   proof（8128B）读出 + bb 产 `public_inputs` 与 Rust `serialize_public_inputs` 逐字节
   比对 → `SpendProof`。

**工程口径**：prove 全程进程级互斥（`Mutex`）——`ProverSDK.toml` 落在包目录，并发证明
串行化（证明是重操作，可接受）；工具链解析复用 §6.13 三层探测语义（`MERIDIAN_BB_BIN` /
`MERIDIAN_NARGO_BIN` → PATH → WSL2 兜底 `MERIDIAN_WSL_DISTRO`，Windows 路径经 `/mnt/<盘>/`
转换），皆不可得 `E_PROVER`。

**keygen（S-46，attestation 同源，诚实边界 2 收口）**：`NoirProver::attestation_pubkey(secret)`
从 `attestation_secret` 派生 BabyJubJub attestation 公钥——复用步 2 的**同一 oracle 入口**
（`nargo execute keygen --prover-name ProverSDK --overwrite-return`，witness 工件独立命名
`target/keygen.gz`，不碰正式管线工件；`--prover-name ProverSDK` 与 prove 同一套临时 toml，
跑完即清理）：意图入参填零（只消费 `agent_pub_x/y`，签名/撤销树输出弃用——`eddsa_to_pub`
是 prove 链路同一函数，零漂移）→ Field 大端外形翻 LE（电路 `to_le_bytes` 口径，
`formal_gen_to_prover.py` 的 `le32` 同款）→ `AttestationPubKey` → 交叉校验
`core::attestation::agent_commit(pk)` == oracle 口径承诺（锁定 LE 翻转的肢序，失配
`E_PROVER`）。secret 值域闸（< SUBORDER）与 prove 入口同闸同错误码。曲线数学**仍全在
Noir**（S-05 教训守住）。装配：`SdkClient::with_noir(wallet, transport, NoirProver, secret)`
把同一实例同时装配为 prover 与 keyring（单 `Arc`，进程级互斥共用）；`attest_identity()`
用派生公钥出绑定凭据（派生结果按 secret 键控缓存，secret 变更自动重派生）——`attest()`
的 `agent_commit` 与 `pay()` 证明公共输入 `agent_commit` **同一 secret 单一来源**，
「由调用方保证」的接缝关闭（e2e 实证相等）。`attest(&pk)` 显式口径保留（离线 / 外部
注册流，如 mcp-server）。**CLI 消费（S-47）**：facilitator EIP-3009 桥垫付 client
经 `BridgeConfig.noir`（bin `MERIDIAN_BRIDGE_NOIR=1`）接入同一装配——S-46 装配面
的首个二进制消费方（§6.10 第 4 步），`pay()` 的证明公共输入 `agent_commit` 与潜在
`attest_identity()` 同 secret 单一来源由构造保证；缺省占位不变（口径同上）。

**验收测试**：单测（scalar golden + 边界、十进制互转、Prover.toml 组装形状、路径重算根）
+ e2e（`sdk/tests/noir_prover_e2e.rs`，`MERIDIAN_ZK_PROVER_E2E=1` 门控）：真实场景
（SDK 建委托/意图 + 聚合器 `RevocationSet` 含真实撤销条目 → `non_membership_witness`）→
`NoirProver.prove` → `BbVerifier.verify` **密码学接受**（prove × verify 两侧真后端首次
闭环）；负向：篡改 proof 拒 / 篡改公共输入拒。**S-46 同源全链**（同文件同门控）：
`with_noir` + `attest_identity` → `pay()` 真证明 → 进程内聚合器（`BbVerifier` +
`enforce_revocation_root`，§6.2 绑定闸开启）接受，且 `attest_identity().agent_commit ==
直接 prove 的公共输入 agent_commit`（同源实证）。接线：verify.sh 第 9 步后挂 **9c**
（工件依赖 9b 同款：第 9 步产出编译产物与 vk）；CI noir job formal 之后同款。
**S-47 增量**：verify.sh 挂 **9d**（同门同工件，facilitator 桥 e2e，过滤器只选 noir
桥用例）；CI noir job 同款步。

**诚实边界**：

1. **SDK 默认 prover 不切换**：`SdkClient::new` 仍装配 `PlaceholderProver`，`NoirProver`
   经 `SdkClient::with_prover` 显式接入（与 §6.13 `MERIDIAN_VERIFY_BACKEND` 缺省 format
   同口径——生产默认不动，两侧真后端都开才算全链真 ZK）。每笔证明 = 三次子进程
   （oracle execute + 电路 execute + bb prove，B2 ~0.43s 量级），成本口径见 §5.5；
   100μs/笔 目标仍归递归聚合（§5.4 Phase 2）。
2. **attestation 同源性 S-46 收口（SDK 内自洽装配）**：`NoirProver::attestation_pubkey`
   从 `attestation_secret` 经 Noir 曲线 oracle 派生公钥（`eddsa_to_pub`，与 prove 链路
   同一函数零漂移，曲线数学不进 Rust），`SdkClient::with_noir` 把同一实例装配为
   prover + keyring，`attest_identity()` 出绑定凭据——`attest()` 的 `agent_commit` 与
   `pay()` 证明公共输入同源由构造保证（本件之前「由调用方保证」的接缝关闭）。Rust 侧
   Jubjub 密钥生成接缝同步关闭（keygen 也是 Noir）。残余：**熵来源（secret 的生成）由
   调用方供给**——SDK 不生成随机熵（不引入 rand 依赖），keygen 入口只做值域闸（<
   SUBORDER，非法标量 `E_PROVER` fail-closed）；显式 `attest(&pk)` 口径保留（mcp-server
   等外部注册流），聚合器登记以公共输入为准（§9）。
3. **撤销根换代**：prove 请求的 witness 是聚合器当刻树快照。**S-44（§4.6 残余③聚合器
   半边）收口绑定语义**：聚合器侧撤销根绑定闸（§6.2，`enforce_revocation_root`）接受
   本账本出现过的全部撤销状态根——换代窗口内的在途证明（旧状态 witness）不被换代本身
   拒，安全性由管线步 2b 当前撤销闸兜底。**SDK 半边 S-45 收口（witness 自动新鲜度 +
   `E_REV_ROOT` 刷新重出）**：witness 查询端点（§6.7 `GET /v1/revocation-witness`）+
   `Transport::revocation_witness`；`SdkClient` 按 delegation_hash 分桶缓存（per-dh
   事实，跨委托复用会被电路断言 8 拒），`pay()` 未命中现取，`E_REV_ROOT` 业务拒绝时
   现取新 witness **同意图重出证明重交**（intent 不变 → intent_hash 不变；nonce 不
   推进——绑定闸在 `try_commit` 之前拒、不占 nonce 占位，同意图重发不撞幂等闸缓存的
   原拒绝，走全新校验）；刷新次数封顶 `RetryPolicy::max_attempts`（防 transport 指向
   另一聚合器时无限循环），取不到 witness（`Ok(None)` = 已撤销）即按原拒绝定局
   （fail-closed，`Ok(None)` 不重试）。手动装配 `set_revocation_witness(dh, w)` 保留
   （离线 / 测试口径），分桶键 = 目标 delegation_hash（S-43 单槽 API 废弃——单槽对
   多委托客户端是错配：后写覆盖先写，先取的委托拿到别的索引的路径）。
4. gen-witness 的 `MAX_REVOKED = 2` 固定撤销集仍只服务正式管线 fixture；真撤销 witness
   一律来自聚合器 `RevocationSet`（S-42），oracle 的撤销树输出弃用。

### 6.15 demo 层真 ZK 装配示例（S-51，M1 真 ZK capstone，候选⑥）

§6.13/§6.14 的装配面（SDK `with_noir`、网关 bb、桥 noir 装配）此前的实证都在 **crate e2e
测试**里；demo/smoke 层（`contracts/rust-smoke` 的 Anvil 端到端）仍只有占位 ZK 缝
（`m1_demo` A 段）。本件补 demo 层真 ZK 装配示例：`contracts/rust-smoke/src/bin/noir_demo.rs`
（独立 workspace 新 bin，`MERIDIAN_NOIR_DEMO=1` 门控，verify.sh 步 9e）——**真电路证明 →
真验证后端 + 撤销根绑定闸 → 链上净额结算，撤销根三方同源**的 M1 形态首次走通：

1. **装配面（§6.14 全套，demo 即可运行的装配答案）**：`SdkClient::with_noir(wallet,
   transport, NoirProver, attestation_secret)` + `InProcessAggregator`（`BbVerifier::
   from_parts(vk, backend, tmp_root)` + `IngestConfig::enforce_revocation_root = true`，
   §6.13/§6.2/§6.14 同口径；S-48 构造期配对闸在此生效）。
2. **授权上下文**：`client.authorize()`（S-46 NonceManager 1 起口径）→ `create_delegation`
   同参数重建同 dh（assert 相等）→ 链上 `DSA.registerDelegation`，`isRegistered(dh)`
   断言 **sha256(delegationABI) == meridian-core delegation_hash**（m1_demo 同款交叉实现
   契约，S-11d）。
3. **撤销根三方同源断言（本件核心）**：聚合器 `revoke(另一委托)`（撤销集非空，绑定闸
   接受集含真实状态根）→ `pay()` 现取 witness（S-45）→ 证明公共输入 `revocation_root`
   经绑定闸锚定本账本撤销树 → seal 后 `EpochResult.revocation_root` == 证明所用的
   witness 根（**逐字节**，S-41 同棵 Pedersen 树的可比性）→ 该根上链
   `BatchSettler.commit`——agent 证明、聚合器账本、链上结算三方同一撤销状态根。
4. **对照组（诚实口径）**：占位 `SdkClient::new`（同 dh，`sync_nonce` 推进到远端后）
   `pay()` 在同一 BbVerifier 聚合器上必拒 `E_PROOF`——bb 全拒占位证明，正向的接受不是
   占位漏网（S-47 桥 e2e 对照组同口径）。
5. **链上净额结算**：`seal_expired`（epoch_capacity = 笔数，满窗即封）→ `settle_epoch` →
   `commit(债券)` → `settle(Σnet)` → 过挑战窗 → 逐收款人 `claim`，余额增量 == 净额行
   （m1_demo E 段同款，笔数小、走真 ZK）。

门禁：verify.sh **9e**（工件依赖 9b/9c/9d 同款 `circuits/target/{spend_authorization.json,
vk}` + anvil 可得；缺任一即 `[SKIP]`）。**CI 不跑本步**（noir job 无 anvil、solidity job
无 nargo/bb，跨 job 工具链拼装收益不抵复杂度；同 `m1_demo` 的 CI 口径——S-14a 起即
verify.sh 专属），本地参考机全量实证。

诚实边界：demo 笔数 3（真电路证明 ~1.3s/笔，100k 笔吞吐口径仍归 `m1_demo` 的占位缝 +
递归聚合 §5.4 Phase 2）；`m1_demo` 本体不动（占位 ZK 缝是 M1 吞吐规格的诚实实现）。

### 6.16 mcp-server 证明直通（S-52，keyless 保形的真 ZK 装配，候选⑤收口）

§6.13–§6.15 的装配面落在 SDK / 网关 / 桥 / demo 四处后，MCP 面仍是**双重占位**：服务器
自建占位证明（`AppState::build_proof`）+ `FormatVerifier`。本件把 MCP 面收口为
**证明直通**，同时不动摇 keyless 安全模型（`mcp-server/README.md` D3：服务器无任何私钥）。

**设计决策（记录在案，候选⑤「keyless 模型需先定夺」的定夺结果）**——`attestation_secret`
不上服务器，三条路取其三：

1. secret 上服务器 + 服务器代证 = **否决**：违背 D3 双钥分离（私钥进无信任边界的外围 =
   扩大攻击面），把 Shape 1 降级成 Shape 2。
2. 维持双重占位 = **否决**：bb 装配普及后 MCP 面成为唯一无法接入真 ZK 的集成层。
3. **证明直通（采纳）**：证明是**数据**不是密钥——真证明由框架侧客户端产出（`NoirProver`
   持 attestation secret，§6.14 `SdkClient::with_noir` 同源模型的客户端形态），作为
   `pay` 入参随意图一起提交，服务器只做**验证**。这与网关摄取面的信任模型完全一致
   （§6.7：客户端提交信封、服务器验证记账），MCP 层从「自证自验的占位闭环」升级为
   「验证面真 ZK + 证明来源外置」。

**线格式（`meridian.pay` 入参新增 optional `proof` 对象）**：

```json
{ "proof_hex": "<bb UltraHonk 证明字节，hex>",
  "agent_commit": "<32B hex>", "revocation_root": "<32B hex>", "now": <unix 秒> }
```

公共输入的**共享字段**（`delegation_hash` / `recipient` / `amount` / `category` /
`spend_nonce` / `expires_at`）不由客户端重复上报——服务器从信封内 intent 派生，
`check_public_inputs_consistent`（§6.2 步 8）保证派生结果与证明声称的是同一笔意图；
客户端只上报**服务器无法自知的三个自由量**：`agent_commit`（客户端 attestation 身份）、
`revocation_root`（客户端所锚定的撤销状态）、`now`（证明时刻）。缺省 `proof` 缺席 =
服务器占位证明（`build_proof`，占位口径**逐字节不变**）——向后兼容，存量框架无感。

**装配面（`meridian-mcp` bin，网关 bin 同款）**：`MERIDIAN_VERIFY_BACKEND`（缺省
`format` 口径不变；`bb` → `BbVerifier::from_env`，工具链不可得**启动即退** fail-closed）
+ S-48 构造期配对闸（`requires_revocation_root_binding()` ⇒ `enforce_revocation_root =
true`）。bb 模式下占位证明 / 派生错位 / 篡改任一公共输入 = 密码学拒 `E_PROOF`。

**新工具 `meridian.revocation_witness`（第 6 个工具）**：客户端构建真证明所需的**唯一
服务器侧事实**——S-45 网关 `GET /v1/revocation-witness/{dh}` 的 MCP 面（`root` 64hex +
`path` 256×32B 扁平 hex = 16384 字符，MCP 面首次大载荷）；已撤销 → `E_REVOKED`
（§11 同码）。没有它，MCP 客户端拿不到非成员路径，真证明无从谈起。

**测试**：`mcp_flow` +3（直通证明被验证器**真实消费**——`RejectAllVerifier` 对照组
`E_PROOF`，服务器绝不偷偷换成自己的占位；缺省口径占位不变；witness 工具正/负向）+
门控 e2e `MERIDIAN_MCP_NOIR_E2E=1`（`mcp-server/tests/mcp_noir_e2e.rs`：客户端侧
`NoirProver` 真电路证明 → MCP `pay` 工具 → `BbVerifier` + 撤销根绑定闸聚合器接受；
对照组：同一聚合器上占位 `pay` 必拒 `E_PROOF`）。verify.sh **9f** + CI noir job 同款。

**诚实边界**：`format` 缺省后端下 `agent_commit` / `revocation_root` / `now` 三个自由量
无密码学约束（与网关格式口径一致，真约束在 bb 装配 + 撤销根绑定闸）；服务器侧产证明
**不在本件也永远不在**（keyless 是设计约束不是待办）；证明 8128B 经 JSON hex 走 stdio，
MCP 面单笔载荷 ~20KB（吞吐口径不适用于 MCP 面）；WAL 不落证明（`RecordKind::Intent`
固定 116B payload，§10），直通不影响 WAL 格式与恢复语义。

**框架 demo 面（S-53，候选⑨收口）**：`demos/` 三框架脚本（LangChain / AutoGen /
ElizaOS，S-13b 同一闭环）在 `authorize` 之后加入 `meridian.revocation_witness` 步——
回执形状自检（`root` 64 hex + `path` 256×32B 扁平 = 16384 hex 字符 + 回执
`delegation_hash` 与本地重算逐字节一致），三个框架逐字节同口径。诚实边界：`pay` 的
optional `proof` 直通**不在框架脚本演示范围**——真电路证明需要 nargo/bb 工具链（§5.3），
Python/JS 脚本侧不可得，硬造即假演示；该路径由本节门控 e2e `mcp_noir_e2e` 实证，
框架脚本演示的是 witness 事实面（真证明的前置事实来源）。

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

// BatchSettler.sol —— 乐观批量结算（S-11 v2 生产化：operator 守卫 + 延迟 claim + 完整挑战流；
//                      S-28 资产参数化：asset = address(0) 原生 ETH / ERC-20（如 USDC））
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
    event ChallengeRejected(uint256 indexed epochId, address indexed challenger, uint8 reason);
    event RefundWithdrawn(uint256 indexed epochId, uint256 amount);
    event Claimed(uint256 indexed epochId, address indexed recipient, uint256 amount);

    address public immutable operator;                 // 唯一运营者（onlyOperator 守卫）
    address public immutable asset;                    // S-28：address(0) = 原生 ETH（v2 行为）；
                                                       //        否则 = ERC-20 结算资产（如 USDC）
    uint256 public immutable challengeBond;            // S-50：挑战押金（部署期参数，>0 闸）；
                                                       //        恒原生 ETH（与 asset 无关）
    uint256 public constant CHALLENGE_WINDOW = 6 hours;
    uint256 public constant MAX_INTENTS_PER_CHALLENGE = 32;

    constructor(address operator_, address asset_, uint256 challengeBond_);
                                                       // bond/押金恒原生 ETH（两模式相同）；
                                                       // challengeBond_ == 0 构造即 revert

    function commit(uint256 epochId, bytes32 commitmentRoot, bytes32 revocationRoot)
        external payable onlyOperator;                // 质押债券（msg.value）+ 锚定撤销根，一次性
    function settle(uint256 epochId, NetInstruction[] calldata net, bytes32 nettingRoot)
        external payable onlyOperator;                // keccak(net) 校验 + 存 net[] + msg.value ≥ Σnet
    function claim(uint256 epochId, uint256 netIndex) external;  // 窗口后逐条领取结算资产（ETH/token）；voided 拒
    function challenge(uint256 epochId, FraudProof calldata fp)
        external payable;                             // S-38 押金制：入场前 4 类 revert；入场后
                                                      // 驳回即销毁押金（ChallengeRejected），epoch 不动
    function withdrawRefund(uint256 epochId) external onlyOperator;
                                                      // 审计加固：挑战成功时退款 push 失败的
                                                      // 留存量拉取兜底（仅 voided epoch 可取）

    error EpochAlreadyCommitted(uint256); error EpochAlreadySettled(uint256);
    error EpochAlreadyChallenged(uint256); error EpochUnknown(uint256); error EpochVoided(uint256);
    error WrongNettingRoot(); error ChallengeWindowClosed(); error ChallengeWindowOpen();
    error AlreadyClaimed(uint256,uint256); error NetIndexOutOfBounds(uint256,uint256);
    error InsufficientSettlementFunding(); error NotOperator();
    error WrongChallengeBond();                        // S-38：msg.value != challengeBond
    error ZeroChallengeBond();                         // S-50：challengeBond_ == 0 构造即 revert
    // S-38 移除（押金入场后不再 revert，改为 ChallengeRejected 的 reason 码）：
    // TooManyIntents / DuplicateIntent / BadInclusionProof / NotFraud / BadFraudKind
    error TokenTransferFailed(); error EthValueInTokenMode();   // S-28 资产参数化
    error EpochNotVoided(uint256); error NothingToRefund(uint256);  // 审计加固：withdrawRefund 守卫
}
```

**关键契约（S-06 交叉实现）**：`registerDelegation` 在链上重算
`delegation_hash = sha256(delegationABI)`，owner 解析自 ABI 字节区间 `[26:46]`
（`"DSAv1\0"` 前缀 + agent + owner，canonical 编码见 `core/src/dsa.rs`）。
链下 meridian-core 的 `delegation_hash` 必须与之一致（Rust `sha2` ↔ Solidity
`sha256` 预编译，双向验收）。owner 签名强制低位 s（`s > n/2` → `revert HighS`）。

- 部署底座：Base（主网 Phase 2 起）；测试：Anvil 本地链 + Base Sepolia。
- **S-11 结算资产 = 原生 ETH**（bond = `msg.value`；claim 付原生 ETH）；**S-28 资产参数化
  落地 ERC-20 结算**——`BatchSettler(operator, asset, challengeBond)`（S-50 押金随构造
  参数化）：`asset = address(0)` 逐字节保留 v2
  行为，`asset = USDC` 时 settle `transferFrom` 拉款 / claim 付 token / void 退款退 token
  （bond 仍原生 ETH），强制 token 模式 `msg.value == 0`（`EthValueInTokenMode`）；
  `NetInstruction { recipient, amount }` 指令形状不变，资产置换不动净额结构。欺诈证明机制
  单一实现（不因资产模式分叉）。Base 主网 USDC = `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`，
  Base Sepolia USDC = `0x036CbD53842c5426634e7929541eC2318f3dCF7e`（部署时核对，勿硬编码进合约）。
- S-11 生产化：BatchSettler 完整 fraud-proof（漏单/低付，sound+有界）+ 债券罚没 +
  epoch voided 回滚 + 延迟 claim；撤销事件 1 epoch 内进入聚合器撤销根（Pedersen sparse root，
  S-41 起与电路同源，见 §4.6，随 commit 上链）；真实 sha256 Merkle 已替换占位
  （`IntentHelper.sol`/`Merkle.sol` 交叉实现）。

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
| B4 | ZK 验证摊薄（≥256 笔/批） | 摊薄 μs/笔 | **S-18 诚实修订**（实测见 `docs/zk-batch-verify-eval.md` §5）：BB 原生批验证对 UltraHonk 不可用（CLI 无 handler + msgpack 仅 Chonk，实证）；实线 = 单验证 CLI 上界 **4983.8μs/笔**（参考机 32 核）；**≤100μs/笔 挂递归聚合（Phase 2/4）**——**S-55 实测该里程碑 blocked-on-upstream**（Chonk 栈可折叠但 prove 被规范 hiding kernel ABI 卡死 / 链长限 8 / 无 chonk solidity verifier，边际 ≈1.0s/折，见 `docs/zk-recursion-eval.md`）；v1/v1.1 吞吐靠非阻塞异步并发验证 | 回归 >5% 红 |
| B5 | 聚合器摄入吞吐 | 笔/s（1/8/64 线程） | 单实例 ≥ 100k 笔/s | 回归 >1% 红 |
| B6 | 摄入端到端延迟 | p99 | ≤ 50ms | 回归 >1% 红 |
| B7 | 排序+承诺（100k 笔） | 耗时, 内存峰值 | < 1s, < 1GB | 回归 >1% 红 |
| B8 | 热路径分配 | allocs/笔 | **= 0** | 非 0 即红 |
| B9 | 预算检查 | ops/s | > 1M ops/s | 回归 >1% 红 |
| B10 | 端到端 100k 笔→批次→净额 | 墙钟, allocs, 峰值 | 记录基线 | 首次=基线 |
| B11 | 确定性 | 同 seed 输出 | 输出哈希一致 | 不一致即红 |
| B12 | 内存 | 稳态 RSS（gate `agg_kernel_rss_mib`，MiB） | 记录基线 63.8 MiB（S-18 实测回填） | 回归 >3% 红（gate 强制） |

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

> **S-35 实测回填（§6.11 热路径埋点性能账，Windows 实测机 P-core 钉定，gate 9 轮中位
> vs `bench/baseline.json`）**：`aggregator_ingest_ops` **-0.48%**（kernel 口径）/
> **+3.69%**（bench 口径，run-to-run 噪声带内）、B7 墙钟 +4.75%、RSS +1.55%（< 3% 硬
> 阈值）——均在 gate ±15% 与历史噪声带（±17%）内，**B5/B6/B8 口径不变**（B8 分配数
> 仍 = 0，`agg_sim --check-alloc` 复测通过）。结论：每次 `submit` 两次 `Instant::now()`
> + 3 次 `fetch_add(Relaxed)` 对 ~22 μs/笔 的单线程稳态成本 < 1%，被噪声淹没。

> **S-14b/S-18 实测回填（`bench/baseline.json`，Windows x86_64 release 实测机，单线程
> `gate` 全指标）**：B1 `verify_delegation_ops` **19,558/s**、`sign_delegation_ops`
> **35,976/s**；B9 `check_budget_ops` **1.82×10⁹/s**（>1M → **PASS**，余量 ~1800×）；
> `intent_verify_ops` 51,573/s、`intent_sign_ops` 95,812/s。**B1 目标修订（诚实口径）**：
> 原「验签 > 50k ops/s」未标注线程基数；实测为 k256 单线程 secp256k1 验签上界
> （~20k/s，纯数学，无 SIMD 加速），且 delegation 验签是**冷路径**（register 时每委托
> 一次，不进 ingest 热路径）。修订为：单线程验签 ≥ 15k/s（实测余量 ~1.3×），多线程按核
> 线性放大（B5 实测证）。B12 稳态 RSS **63.8 MiB**（gate 指标 `agg_kernel_rss_mib`：
> 64 代理 × 1000 笔 = 64k 全量提交填满状态后驻留采样峰值；跨平台探针 `/proc`（Linux）/
> `GetProcessMemoryInfo`（Windows），run-to-run 方差 ~0.2%，3% 阈值永不误报；**gate 强制、
> 不受 `--fail-over` 放宽**）。

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
- **短突发测量抗噪（S-35b，2026-08-30）**：`agg_kernel_ingest_ops` 的测量窗是 32×200=
  6400 笔 ≈ 0.2 s 短突发，单次采样对共享 runner 的调度/邻居噪声极敏感——CI 实证三次：
  gate 原型指标 `aggregator_ingest_ops` 在 CI 首跑同 job 内 record vs compare 两轮
  -16.67%/-16.48%（当时以 GATE_EXEMPT 豁免）；S-35 推送后同签名落在生产指标
  `agg_kernel_ingest_ops`（-16.37%/-17.08% 两轮"确认"，重跑即绿——CI 的 baseline 是
  同一 run 里同一份代码 `--record` 现录的，同码两跑差 17% 只能是 runner 噪声而非代码
  回归）；S-35b 第一版收口（同一 fixture 复测 5 轮取中位，S-14b 的 9 轮中位同法）只
  治住了**突发内**噪声，同 job 仍复现 -19.88%/-19.75%（baseline 本身跨 run 也在
  26.9k~30.9k 摆 13%——噪声是 record/compare **阶段级**漂移，复测轮数治不了）。
  最终收口：**阈值必须高于噪声地板**。CI（`ci.yml`）传 `--ci` 给 gate：该指标阈值放宽
  到 25%（噪声地板 ~±20% 之上，仍抓灾难性回归）；本地参考机（P-core 钉定，run-to-run
  实测 ±6%）不传 `--ci`，15%/1% 精度口径不变。5 轮中位保留（治突发内噪声，与阶段级
  漂移正交）。
- baseline.json 入库；`scripts/verify.sh` 必须通过全量套件。
- **ZK 门禁本地化（S-37，2026-08-30）**：`verify.sh` 第 9 步（smoke_zk + formal_zk）从
  「Windows 侧找不到 nargo/bb 即 `[SKIP]`」（nargo 1.0.0-beta.26 无法在 Windows 构建，
  `termion` 仅 unix，见 §5.3）改为**三层探测**：① Windows 原生（保留，实际不可得）；
  ② **WSL2 兜底**——`wsl.exe` 可用且发行版内有 nargo/bb 时，借 `/mnt/<盘>` 路径在 WSL
  内跑同一对脚本（发行版默认 `MeridianUbuntu`，root（工具装在 `/root/.nargo/bin`、
  `/root/.bb`），可用 `MERIDIAN_WSL_DISTRO` 环境变量覆盖）；③ 两者皆无才 `[SKIP]`。
  S-36 起本机 WSL2 已具备工具链（§5.1），**ZK 门禁由此真正进入本地 pre-push**——电路
  回归不再只靠 CI 第二道网兜底。边界诚实口径：WSL 兜底跑的是与 CI 相同的脚本与锁定
  版本，但宿主是本机（32 核），§5.4 的计时基线在本地参考机跑出（与 CI 2 核数值差异
  见 §5.5 表）；`nargo fetch` 需网络（WSL 内可达 crates.io/ GitHub tag）。配套收口：
  门禁跑前把 `gen-witness/Prover.toml` 备份到 `target/`、跑后还原（`nargo execute
  --overwrite-return` 会追加/改写 `return` 键，该键不进版本库）——pre-push 不再污染
  工作树，且开发者对 Prover.toml 的手工改动在门禁后原样保留。
- **S-11d 链上端到端（verify.sh 9/9）**：`rust-smoke`（`contracts/rust-smoke`，独立
  workspace）在一条 anvil 会话内跑三场景——① 快乐路径：注册→submit→密封结算→
  `commit`（债券+撤销根）→`settle`（资金足）→过窗 `claim` 收款人收精确净额；② 撤销：
  链上 revoke→聚合器 revoke→新意图 `E_REVOKED` 拒→下个 epoch 撤销根变化；③ 欺诈：
  `commit` 诚实根→`settle` 漏单（自洽 netting root）→kind=1 包含证明 `challenge`（S-38
  随笔押金 `CHALLENGE_BOND`，成功路径原额退回）成功→债券罚没+`settlementFunded` 退运营者
  +epoch voided→claim 拒绝。依赖 forge build 产物 + anvil，缺任一则 `[SKIP]`（不阻塞
  Rust 主门禁）。
- **跨实现差分 fuzz（S-57，2026-08-31，审计四步路径 ③）**：S-11a 的交叉实现契约
  （`IntentHelper.computeIntentHash` ↔ `core::dsa::intent_hash` / `Merkle` ↔
  `aggregator::merkle` / `DSA.sha256(delegationABI)` ↔ `delegation_hash` /
  `nettingRoot = keccak256(abi.encode(net))` ↔ `lattice::abi_encode_net`）此前只有
  **单个** golden vector（`Merkle.t.sol` / `IntentHelper.t.sol` 各一）+ 深度审计的
  人工逐行读码。本步把「读出来一致」升级为「机器批量差分」：`contracts/rust-smoke/
  src/bin/difffuzz.rs`（splitmix64 固定种子，跨平台确定性，零新依赖）调**生产实现**
  （不是测试替身）批量产 golden vectors → `contracts/test/fixtures/differential.json`
  （并行数组，64 意图 + 32 委托 + 8 叶 + 10 棵树（n=1..16 含非 2 幂补齐）+ 16 净额
  向量，每棵树附包含证明（index + siblings）供 `Merkle.computeRoot` 重推）→
  `contracts/test/Differential.t.sol` 逐条比对 Solidity 镜像（含 `abi.encode(net)`
  编码字节级比对，不只比根）。门禁：`verify.sh` 新步 **8b**——重生成 fixture 到
  `target/` 与入库版本 `cmp` 漂移闸（改任一侧规范不回填 fixture 即红）+ forge 差分
  测试。诚实边界：单向差分（Rust → Solidity 镜像），反向（Solidity 产 Rust 消费）
  由 S-11d rust-smoke 三场景 + forge 全量兜底；随机向量固定种子，不追新输入——要更
  宽的输入面，改种子重生成并提交（漂移闸强制 fixture 与代码同步）。
- **分支覆盖门禁（S-58，2026-08-31，审计四步路径 ④）**：`scripts/coverage_gate.sh` ——
  `forge coverage --report lcov` 对 `contracts/src` 全部 5 合约出行/语句/分支/函数覆盖，
  阈值硬闸：**行 100%、函数 100%、分支 100%**，唯一豁免 `BatchSettler.sol` 允许分支欠
  **1** 条——向 `address(0)` 销毁挑战押金的 `require(okBurn, "bond burn failed")`
  （§6.5）失败边**结构不可达**：ETH 向无代码地址推送不可能失败，无测试可达路径，代码
  注释与 `docs/audit/slither-2026-08-31.md` §coverage 同步定性，阈值放宽是记录在案的
  豁免而非放水。接线：`verify.sh` 新步 **8c**（forge 存在时随 8/8b 同批跑）+ ci.yml
  solidity job 同款步。扫描结果（2026-08-31 实测）：BatchSettler 行 134/134、其余 4 合约
  行/分支/函数全 100%，BatchSettler 分支 61/62（豁免 1 条即满）。**实施坑（已钉）**：
  `forge coverage` 禁优化器编译——测试侧 10 元组「解构成局部变量再回填命名返回值」
  会 stack too deep；S-58 前用 `--ir-minimum` 兜底跑出的覆盖数据整体失真（Merkle/
  IntentHelper 假性缺分支、行归因漂移，把人工排查引向伪缺口）——`_epochView`/
  `_epochViewOn` 改为直接 `return bs.epochs(epochId)` 后全量测试在无优化器下可编译，
  数据才可信。缺口收口 = 7 条负向测试（claim push 失败回滚可重试 / 挑战者拒收赔付整笔
  回滚且 epoch 仍可挑战 / withdrawRefund push 失败可重试（ETH）/ withdrawRefund
  transfer 返 false → TokenTransferFailed（token）/ kind1 多意图 → BadFraudKind /
  kind2 目标行越界 → NetIndexOutOfBounds / kind2 混入伪造意图 → BadInclusionProof），
  全部是审计面负向缝隙而非凑数行。冻结清单（外聘审计启动时逐项执行）见
  `docs/audit-scope.md` §6。
- 热路径零分配用分配器钩子断言（`dhat` 或自写 alloc hook），不靠估计。
- **GitHub CI**（`.github/workflows/ci.yml`）：**第二道网**（2026-08-30 起恢复可用，
  S-35b 后每轮 push 均实跑并盯绿：ci / noir / solidity 三 job；额度阻断期间曾挂起，
  历史记录见 git log）。solidity（forge）与 ZK（nargo/bb）job 需 Linux 工具链：
  ZK 一侧已由 S-37 的 WSL2 兜底进本地 pre-push（见上），forge/anvil 本机未装时
  `verify.sh` 仍打印 `[SKIP]`（不阻塞 Rust 主门禁）。

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
| `E_VERIFY_BACKEND` | 真验证后端不可得（S-40，fail-closed 不降级） |
| `E_PROVER` | 证明生成失败（S-43，fail-closed 不降级） |
| `E_REV_ROOT` | 证明公共输入 `revocation_root` 不在聚合器撤销状态根集合（S-44 绑定闸，§6.2；仅 `enforce_revocation_root = true` 时触发） |
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

**传输层错误码（S-29 wire 层，不进内核 `Error` 枚举）**：

| 码 | 含义 | HTTP 状态 | SDK 重试 |
|---|---|---|---|
| `E_AUTH` | Bearer 缺失/未知租户 | 401 | 否 |
| `E_RATE_LIMITED` | 租户令牌桶超限（未进内核，无 seq） | 429 | 是（退避） |
| `E_MALFORMED` | JSON/字段/hex 不合法 | 400 | 否 |
| `E_NOT_FOUND` | 只读查询未命中（回执不存在 / 已结算修剪 / 被拒——**404 ≠ 未支付**，§6.7） | 404 | 否 |
| `E_REVOKED` | 撤销 witness 查询目标已撤销（无非成员 witness 可给，S-45 §6.7；复用 §11 主表内核码字符串，不进内核枚举实例化） | 404 | 否（`Transport::revocation_witness` 映射 `Ok(None)`） |

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
| ① ZK 授权凭证 | `spend_authorization` 完整版（§5.2 九断言 + 正/负向 + 双钥绑定 + 撤销非成员 + intent_hash 字段级绑定） | **PASS**（约束 82742 < 2^18，S-36 全宽化后复测，回填 §5.5） | S-09: CI run 31934410549；S-36: 本机 formal_zk.sh 8/8；§5.5 |
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
