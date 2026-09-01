# Mist — 技术规格书
## L2 DSA 授权原语 + 结算聚合器 · v1.0（Phase 0 定稿版）

> 本规格是**绑定文档**：团队照此写代码。任何偏差须先改本文件、写明理由，再改代码。
> 对应蓝图：《Mist_架构蓝图.md》 §3 L2/L3、§6.5 性能信条、§10 行动清单。
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
mist/
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

> **已实现（S-10，`mist-aggregator::proof::FormatVerifier`）**：TEMPORARY 后端口径——
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
`BatchSettler(operator, asset, challengeBond, dsa, revocations)`（S-66 起 5 参；S-50 时点
为前三参）——`asset = address(0)` 即 v2 原生 ETH 行为
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

- 摄入管线：验签（Ed25519 快路径）→ **运营者绑定闸（S-62，步 4b，§6.19）** → 验证明
  （§5）→ 预算检查（§4.5）→ 记账 → 入窗口队列。
- 拒绝原因必须进 `Receipt`，供 agent 端幂等重试（nonce 不允许复用）。
- **运营者绑定闸（S-62，§6.19.2，Phase 2 P2-2）**：验签之后、验证明之前——意图委托的
  链上绑定（DSA `operatorOf(dh)`，§6.19.1）**已绑定且 ≠ 本账本运营者** → `E_OPERATOR`
  拒；**未绑定放行**（决策 B fail-open）；**绑定读面不可得 → `E_BIND_BACKEND` 拒**
  （fail-closed，绝不静默降级）。绑定不可改 ⇒ 读数进程内永久缓存（每委托一次冷 RPC，
  热路径一次哈希查找；读失败不进缓存，瞬态下一笔重试）。被拒不耗 nonce / 窗口槽
  （闸在 `try_commit` 之前），同意图重发走全新校验不被幂等闸缓存的原拒绝命中。位置在
  验签后：未认证流量不得触发绑定冷读（RPC DoS 放大面收口）。**装配显式**：
  `Aggregator::with_operator_binding(source, self_operator)`，不装配 = 无闸（缺省口径
  逐字节不变）；网关 bin 三个环境变量同给同不给（§6.19.3）。
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
  witness 的根无语义，默认装配行为逐字节不变——与 §6.13 `MIST_VERIFY_BACKEND`
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
5. `releaseBond`（S-77 债券 lifecycle 收口，主网真跑前主会话自审发现）：窗口无损过后
   运营者拉回该 epoch 债券（`BondReleased` 事件）。前置 = `settled` ∧ ¬`voided` ∧
   `block.timestamp > settledAt + CHALLENGE_WINDOW` ∧ `bondedAmount > 0`；债券恒原生
   ETH（S-28），无 token 分支。**修复前缺陷**：`bondedAmount` 仅两条出路（challenge
   成功判给挑战者 / 永久滞留合约），happy path 无退回路径——理性运营者均衡是债券 → 0，
   §6.5 震慑静默失效；不变量①（资金守恒）无"已退债券"项反而把滞留固化为预期行为，
   fuzz 全绿不可见。窗口过后 `challenge` 已被 `ChallengeWindowClosed` 前置挡下，release
   与罚没无竞态窗口。commit 后长期不 settle 的 epoch 债券同样无退回路径：对"承诺了却
   不结算"的运营者，债券锁死即惩罚，不开"承诺随时可抽"的后门。

### 6.5 债券/惩罚（乐观安全模型）

| 承诺 | 违约 | 惩罚 |
|---|---|---|
| 运营者质押债券（**原生 ETH**，`commit` 时 `msg.value`） | 等价双花 / 漏单 / 提交与承诺不符的 net[] | 债券罚没，判给挑战者 |
| 预算账本诚实 | 已撤销仍放行 / 超限记账 | 债券罚没 + 声誉分（Phase 2，设计轮定夺：只读派生不进判定面，§6.17 决策 E / 砖 P2-5） |
| 撤销根最新 | 用过时撤销根放行已撤销委托 | 债券罚没 |
| 挑战者押金（`challenge` 随笔 `msg.value`，原生 ETH，S-38） | 欺诈证明被驳回（押金入场后任何实质验证失败） | 押金全额销毁（`address(0)`，任何一方不可取回）；epoch 状态不变、仍可再挑战 |

**债券生命周期（S-77 收口）**：债券金额 = `commit` 时运营者自选 `msg.value`（**协议无
最低值检查**；`1 ether` 是测试常量与建议规模，非协议要求——S-77 前文档曾误作协议事实）。
路径：欺诈成立 → 罚没判给挑战者；窗口无损过 → `releaseBond` 拉回（§6.4 第 5 步）；
commit 后不 settle → 锁死（惩罚）。

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
    `BatchSettler(operator, asset, challengeBond, …)`（S-50 时点签名；S-66 增锚两参，§7），
    `uint256 public immutable challengeBond`
    （`anvil` 本地参考值 `0.1 ether`）。设计决策（记录在案）：**只做部署期参数化，不做
    运行时 setter**——改运行时金额必须引入 admin/governor 信任面，而该角色天然可双向作恶：
    抬价 → 审查欺诈证明（挑战成本 → ∞，等于拆掉 §6.5 乐观安全模型）、降零 → 复活 S-38
    收口的垃圾挑战向量。二者都比"金额过时"严重得多，v1 单运营者阶段不值得为此开 admin 面
    （本合约目前唯一权限角色 `operator` 也是 immutable，同口径）。金额随 gas 价格/债券规模
    的运行时自适应挂 Phase 2 多运营者（那时本就有治理结构可挂靠）——**设计轮定夺
    （2026-08-31，§6.17 决策 D / 砖 P2-4）：append-only 金额调度 + 实例固化，仍不做
    运行时 setter。**已落地（S-64，§6.21）**：OperatorRegistry 持有 append-only 调度
    （读取点在部署流程，BatchSettler 构造 ABI 不动），名册快照公开每实例固化值**。**部署期 fail-fast 闸**：
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
- **诚实路径**：v1 信任运营者（我们自己是第一个运营者），债券起震慑作用；Phase 2 引入
  多运营者 + 共享账本（L3 前置）——**设计轮定夺（2026-08-31，§6.17）：分片优先于共识
  （决策 A），共享账本共识退为 P2-6/blocked；验证面先行零合约改动（决策 C / 砖 P2-1）**。
  独立共识设计轮已产出（2026-09-01，§6.25：问题定义 / 乐观复制形态定夺 / 砖单 L3-0..3），
  P2-6/L3 **实施**仍 blocked（解锁条件 §6.25.7）。
- **出界**：超付不可证（需完备性）；按 epoch 结算资金后超付是运营者自损（自掏 Σnet 付虚高
  行），不掏空其他 claim 方。整 epoch void 会惩罚诚实收款人（该 epoch 全部 claim 拒绝）——
  v1 接受（§6.5 "net[] 回滚"口径），按收款人封禁是后续增强。

### 6.6 SDK 集成层（S-12）

独立 agent 进程集成层（`sdk/` crate，`mist-sdk`）：封装 core 密码学原语 + 聚合器
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
2. **仅传输错误**（`SdkError::Transport`）触发重试；聚合器的业务拒绝（`SdkError::Mist`，
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
crate：`mist-gateway`（`gateway/`）+ `aggregator::wire`（wire DTO 单一来源）+
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
  链上 `RevocationRegistry` 的 revoke 与本端点是两级独立动作（链上撤销不自动经本端点
  进聚合器——自动兜底由撤销观察面承担（S-67，§6.24），人工传播走本端点 / S-59 fanout，
  §4.6 债券罚没兜底「已撤销仍消费」窗口）。

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

站位：Mist 是 **x402 的结算后端**（卖水），不是再造付费协议。本节 = agent 侧
fetch 拦截：标准 x402 资源服务器回 `402` 后，把 `paymentRequirements`（scheme
`mist-v1`）映射成 [`SdkClient::pay`] 意图，支付后带 `X-PAYMENT` 头重放请求。
crate：`sdk::x402`（std-only，与 crate 其余部分同同步口径）。

**线格式（v1 基线 + S-72 起 v1/v2 双协议；scheme 名 `mist-v1` 是 Mist 自己的
scheme 命名，与 x402 协议版本号正交，不随 v2 改名）**：

- **v1（402 响应体消费侧，camelCase、金额恒字符串）**：`{"x402Version": 1,
  "accepts": [{"scheme", "network", "maxAmountRequired": "<原子单位字符串>",
  "resource": "<URL>", "description", "payTo": "<0x 20B>", "maxTimeoutSeconds",
  "asset"}]}`。v1 只消费 `scheme == "mist-v1"` 的条目（多条取首条）；无则
  `SdkError::Local`（不伪装成其它 scheme 的 client）。
- **v1（`X-PAYMENT` 头，base64url 无 padding 的 JSON）**：`{"x402Version",
  "scheme": "mist-v1", "network", "resource", "payload": {"intentHash":
  "<0x 32B>", "seq", "spendNonce"}}`。merchant 验证 = 对网关查
  `GET /v1/receipts/{intentHash}`（§6.7 S-30a），accepted 即放行——**信封不内嵌**
  （离线验签是 S-30c facilitator 缝）。
- **v2（S-72，上游 `@x402/*` v2 wire；字段以上游 `specs/x402-specification-v2.md`
  与 `typescript/packages/core` 为准核实）**：付款请求头 `PAYMENT-SIGNATURE`、
  402 声明头 `PAYMENT-REQUIRED`（标准 base64 的 JSON，body 另说）、网络标识
  CAIP-2。与 v1 的结构性差异：① `PaymentPayload v2 = {x402Version: 2,
  resource?: ResourceInfo, accepted: PaymentRequirements, payload: {...}}`——
  **顶层无 `scheme`/`network`/`resource` 字符串**，scheme/network 从 `accepted`
  取；② `PaymentRequirements v2` 的 `maxAmountRequired` **改名 `amount`**，
  `resource`/`description`/`mimeType` 移出到 402 顶层 `resource: ResourceInfo`
  对象（`{url, description?, mimeType?, ...}`），`outputSchema` 删除（Mist 从未
  产出，无迁移负担）；③ 402 的协议信息走 `PAYMENT-REQUIRED` **头**（body 是
  server 实现关切，上游 v2 恒 `{}`）。
- **双协议取舍（S-72 定夺）**：
  - **版本判据唯一 = 载荷里的 `x402Version` 字段**（1 → v1 形、2 → v2 形）；
    头名只决定"从哪里读"，不作版本判据。`x402Version` 缺失 = 拒（402）。
  - **收端双头名双字母表**：facilitator 同时听 `X-PAYMENT` 与
    `PAYMENT-SIGNATURE`（都带时 v2 优先，对齐上游 `payment-signature ||
    X-PAYMENT` 优先序）；解码用"双字母表宽容 base64"（标准 `+/` 与 URL-safe
    `-_` 均收、padding 可选）——上游 v2 发标准 base64，Mist v1 发 base64url
    无 padding，收端统一兼容。**v1 发端维持 base64url 无 padding 不动**（既有
    wire 兼容），**v2 发端用标准 base64**（与上游 `encodePaymentSignatureHeader`
    互操作）。
  - **402 输出双载体**：body 维持 v1 形不动（既有 v1 client 面零改动）+
    新增 `PAYMENT-REQUIRED` 响应头（标准 base64 的 v2 `PaymentRequired` JSON，
    `accepts` 恒产 CAIP-2 规范形）。`asset` 未配置时不产该头（v2 schema 要求
    `asset` 必填非空；v2 client 缺头自动回落 body→按 v1 语境重试，我们照收——
    优雅降级）。**error 402**（绑定失败等）不带 v2 头（v2 schema 要求
    `accepts` 至少 1 条），回落语义同上。
  - **网络标识互通**：`network_canonical()` 把已知 v1 名（`base`/`base-sepolia`/
    `ethereum`/`sepolia`）映射 `eip155:8453/84532/1/11155111`，其余原样透传
    （任意 CAIP-2 如 Anvil `eip155:31337` 直通）；**比较恒在规范形上进行**——
    v1 字符串与 CAIP-2 等价类互通，既有 v1 配置（`MIST_NETWORK=base`）零迁移。
  - **结算响应头**：Mist 继续不产出 `X-PAYMENT-RESPONSE`/`PAYMENT-RESPONSE`
    （诚实边界不变：结算 = epoch 语义，对账走网关查询）。已核实上游 axios v2
    wrapper 对缺结算头 try/catch 不硬失败——v2 client 互操作不受影响。
  - **client 侧谈判**：`X402Client` 402 时先读 `PAYMENT-REQUIRED` 头（v2 优先，
    与"输出偏 v2"对称）→ v2 流转（resource.url 供 category/memo 映射，
    `PAYMENT-SIGNATURE` + 标准 base64 发送，`accepted` 原样回显）；无头回落
    body v1 解析 → v1 流转原样（既有 v1 用例零改动）。

**字段映射（x402 → SpendIntent，docs/x402-adapter.md §3）**：

| x402 字段 | Mist 字段 | 语义 |
|---|---|---|
| `payTo` | `intent.recipient` | 0x 20B EVM 地址直通 |
| `maxAmountRequired` | `intent.amount` | USDC 6 decimals 原子单位直通（字符串解析） |
| `resource` | `intent.category` | `sha256(host + path)`——类目是 owner 白名单的粗粒度路由控制，query 不绑定（诚实边界） |
| `resource`（全文） | `intent.memo` | `sha256(resource)[..32]` 请求指纹（审计对账用） |
| `maxTimeoutSeconds` | `intent.expires_at` | `now + maxTimeout`（缺省 60s）——支付有效期绑定服务器要求 |
| `spend_nonce` | `NonceManager` | 幂等语义 §6.6 不变 |
| `network` / `asset` | 回显进 payload | v1 仅 Base USDC，网关部署配置裁决 |

v2（S-72）同表映射，字段名差异：`maxAmountRequired` → `amount`；`resource`
映射源 = 402 顶层 `resource.url`（v2 requirements 无 resource 字段）；`network`
为 CAIP-2 规范形（`network_canonical` 后语义同上）。

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

crate `mist-facilitator`（`facilitator/`）。x402 缺口清单的 merchant 验证面参考
实现：**受保护资源服务器**如何接 `mist-v1` 支付——验证逻辑全部落在"对 Mist
网关查回执"，零密码学依赖（S-30a 的查询接口即验证接口）。S-32 起该 crate 另含可选的
EIP-3009 兼容桥（含 ecrecover，见 §6.10）；本节的"零密码学"指 `mist-v1` 路径。

**形态决策**：std-only 手写 HTTP/1.1（§6.7 同先例，thread-per-connection、单请求
close 模式）；axum/tokio 虽允许（merchant 侧不在内核热路径）但不必要——参考实现的
价值是"最少代码演示集成面"，不是性能。

**分发逻辑（`Facilitator::handle` 纯分发，单测不经 socket）**：

- `GET /healthz` → `200`；其它路径 = 单一受保护资源（v1）。
- 无支付头 → `402` + paymentRequirements JSON（`scheme: mist-v1`，wire 类型复用
  `sdk::x402` 的 `PaymentRequired`/`PaymentRequirements` Serialize）+ **S-72 起
  附 `PAYMENT-REQUIRED` 响应头**（标准 base64 的 v2 形声明，§6.8 双协议取舍；
  `asset` 未配置则省）。
- 带支付头（`PAYMENT-SIGNATURE` v2 优先 / `X-PAYMENT` v1，§6.8）→ 双字母表宽容
  base64 解码（`sdk::x402::base64_decode_flexible`）→ 按 `x402Version` 归一化
  （v1：顶层 `scheme`/`network`/`resource`；v2：`accepted.scheme`/`accepted.network`
  + 顶层 `resource.url`）→ 校验 `scheme` / `network`（`network_canonical` 规范形
  比较，v1 字符串与 CAIP-2 等价类互通）/ `resource` 与配置一致 →
  `HttpTransport::receipt(intent_hash)` 查网关（S-30a）：
  - `Ok(Some(_))` → `200` 受保护资源内容；
  - `Ok(None)` → `402`（**404 ≠ 未支付**语义下"不可验证即不放行"——未结算/被拒/
    过期统一回 402，错误信息区分）；
  - `Err(_)`（网关传输失败）→ `503` **fail-closed**（验证面不可用绝不放行）。

**诚实边界（v1；S-72 后仍成立）**：单资源模型（无路由/鉴权中间件）；明文 HTTP
（TLS 反代终结）；不产出 `X-PAYMENT-RESPONSE`/`PAYMENT-RESPONSE` 结算头（对账走
网关查询；已核实上游 axios v2 wrapper 缺头不硬失败）；结算侧（epoch claim、对账
导出）不在本件——参考实现演示的是"merchant 怎么接"，不是生产 facilitator。

**三角色 e2e 验收**：X402Client（agent，HttpFetch）→ facilitator `402` → `pay`
（经真网关 + 真聚合器）→ `X-PAYMENT` 重放 → facilitator 查网关回执 → `200`；
另验伪造 `intentHash` → `402`。

### 6.10 x402 适配层 · EIP-3009 兼容桥（S-32，docs/x402-adapter.md §4 缺口 3）

**问题**：存量 x402 client 只会说标准 `exact` scheme（签 EIP-3009
`transferWithAuthorization`），不会说 `mist-v1`。桥 = facilitator 侧把标准
payload **验签后转投 Mist 摄取**，merchant 侧零感知（仍是"查网关回执"单一
验证面，§6.9 不变）。

**形态**：`facilitator/src/eip3009.rs`（模块 `Eip3009Bridge`）。新增依赖
`k256`（workspace 已有，ecrecover 用）与 `sha3`（keccak256 用）——**不引新外部
依赖**；EIP-712 的 `abi.encode` 为定长类型序列，手写拼接（全 32B word）。

**402 体（双 scheme）**：`accepts[]` 增第二条 `scheme: "exact"` 条目，
`PaymentRequirements` 增可选 `extra: {name, version}`（serde default + skip——
EIP-3009 域参数，x402 exact 惯例）；`mist-v1` 条目与其余字段不动。

**桥接流程（`X-PAYMENT` scheme == `"exact"` 时）**：

1. 解析标准 payload（S-72 起双协议形，内层 `payload` 同构）：
   - **v1**：`{"x402Version": 1, "scheme": "exact", "network", "resource",
     "payload": {"signature": "<0x 65B r||s||v>", "authorization": {"from", "to",
     "value": "<原子单位字符串>", "validAfter", "validBefore", "nonce":
     "<0x 32B>"}}}`（camelCase，与 §6.8 同 wire 惯例）。
   - **v2**：`{"x402Version": 2, "resource?: ResourceInfo", "accepted":
     {"scheme": "exact", "network": "<CAIP-2>", "amount", "asset", "payTo",
     "maxTimeoutSeconds", "extra": {name, version}}, "payload": {同 v1 内层}}`——
     顶层无 `scheme`/`network`/`resource` 字符串（§6.8 结构差异 ①），scheme/
     network/amount 从 `accepted` 取。
2. 绑定校验（fail-fast → 402）：`network` 与配置一致（`network_canonical`
   规范形比较，S-72 起 v1 字符串与 CAIP-2 等价类互通）；
   v1 另校验 `resource` 与配置一致（v2 无 requirement 级 resource 字段——
   `accepted` 由服务器产出、client 原样回显，绑定天然成立；跨资源重放仍被
   网关回执的 `memo = sha256(resource)` 绑定挡住，§6.8 字段映射表）；
   `authorization.to == payTo`；`value == 金额要求`（v1 = `maxAmountRequired` /
   v2 = `accepted.amount`，原子单位，超 u64 拒）；`validAfter <= now <
   validBefore`。EIP-712 domain（`extra.name`/`version` + 配置 chainId/
   verifyingContract）v1 = v2 未变（上游同约定）。
3. **EIP-712 验签**（ecrecover，链下密码学）：domain（`name` / `version` /
   `chainId` / `verifyingContract` 来自配置）+ `TransferWithAuthorization`
   typehash → keccak256 → k256 `recover_from_prehash`（v ∈ {0,1,27,28} 宽容）→
   恢复地址（`keccak256(pubkey)[12..32]`）== `from`，否则 402。
4. **转投 Mist 摄取（垫付模型）**：facilitator 以自身身份（`AgentWallet` +
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
   §6.13 `MIST_VERIFY_BACKEND` 缺省 `format`、§6.14 缺省 `PlaceholderProver`
   同口径：生产默认不动，真后端显式开启。bin 侧 `MIST_BRIDGE_NOIR=1` +
   `MIST_BRIDGE_NOIR_ROOT`（缺省 `.`）+ `MIST_BRIDGE_ATTEST_SECRET`
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
  收到的是 Mist 净额。桥只做"验签 + 摄取"，不碰资产。
- **垫付模型**：被消费的是运营商自己的 Mist 预算——client 信用风险由白标
  合同承担（§4.2 受理凭证同口径），不是协议层担保。
- **重放闸持久化（S-33，2026-08-30）**：S-32 的重放闸是进程内存态（重启丢失后同一
  EIP-3009 payload 可能再次摄取，双花的是运营商自身预算）。S-33 收口：`facilitator/src/replay.rs`
  的 `ReplayJournal`——append-only JSONL，每行 `{"from","nonce","intentHash"}`（0x 20B/32B hex，
  camelCase 同 §6.10 wire 惯例），摄取成功后**先内存登记、再落盘**（单行 write + `flush` +
  `sync_data`，崩溃最坏丢尾部半行）；`Eip3009Bridge::open(cfg, path)` 启动时重放日志重建闸表，
  坏行（崩溃撕裂 / 损坏）跳过并计数（`skipped_journal_lines()` 可观测，不阻断重启）。
  日志写失败 → `BridgeError::Journal` → **503 fail-closed**（`E_REPLAY_JOURNAL`，运维故障
  不归罪 client；内存表已登记，client 重试命中重放闸不重复摄取）。
  bin 经 `MIST_BRIDGE_REPLAY_JOURNAL` 启用（缺省仍进程内存态，v0 兼容）。
  **诚实边界（残余）**：① 落盘失败时意图**已摄取**而登记不可持久化——响应 503 但本进程
  内存闸已挡重放，跨进程重复摄取的概率限于磁盘故障窗口；② 日志随桥接笔数线性增长
  （EIP-3009 `nonce` 每笔天然唯一，无重复键可压实；参考实现不设轮转/归档，运维侧按需处理）。
- EIP-712 domain 由配置显式给出（USDC on Base：name `"USD Coin"` / version
  `"2"` / chainId 8453 / `0x8335…2913`），v1 不做域自动发现（`eip712Domain`
  扩展随上游演进）。
- EIP-3009 `nonce` 不查 USDC 合约状态（不提交链上，无需）；`value` 以 u64 直通
  Mist `Amount`（超上限即拒，见 2）。

**验收**：模块单测（EIP-712 digest 构造 / ecrecover 往返 / 坏 v / 冒充 from /
`to` / `value` 不符 / 时间窗 / 超额）+ `handle` 纯分发单测（exact 路径绑定与
重放闸）+ 真 socket e2e（真聚合器 + 真网关：标准 exact client → 桥摄取 → 200；
重放同 payload → 200 且不再摄取；伪造签名 / `to` 不符 / 过期 → 402）。
**S-33 增量**：`replay.rs` 单测（append/重载往返、坏行跳过计数、缺文件建空）+
`Eip3009Bridge::open` 重建单测（预置日志 → 闸表命中 / 坏行计数）+ 真 socket e2e
（facilitator 带 `MIST_BRIDGE_REPLAY_JOURNAL` 摄取 1 笔 → **销毁重建**（同日志路径）
→ 同 payload 重放 200 且 `accepted_count` 不变（重启后重放闸仍命中）；新 nonce 正常摄取
（闸不误挡））。
**S-47 增量**：`BridgeConfig.noir` 装配单测（缺省 `None` 口径逐字节不变 / noir 装配
`config()` 投影）+ 门控 e2e（`MIST_ZK_PROVER_E2E=1`，与 §6.14 9c 同门同工件）：
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
`mist_submit_duration_seconds_bucket{le=...}`（32 个有限 `le` 升序 +
`+Inf`，累计语义）/ `_sum` / `_count`（`# TYPE ... histogram`），外加预计算的
`mist_submit_duration_p99_seconds` gauge（Grafana 直用；精确分位数请在
Grafana 侧对 `_bucket` 跑 `histogram_quantile`）。`le` 值以秒记（`2^i μs = 2^(i-6) s`）。

**性能账（B5/B6/B8 复测口径）**：埋点代价 = 每次 `submit` 两次 `Instant::now()` +
1 次 `fetch_add(Relaxed)`，无分支外的新分配。实测影响见 §8.2 B5 注（S-35 回填）。

### 6.12 多实例集群指标聚合（S-39，ops.md §6 挂账项收口）

S-15 起 monitor 只盯一个 WAL；§1 拓扑的「聚合器实例（多实例，热备）+ WAL 副本」部署形态
缺一个聚合视图。本节兑现：`mist-monitor --wal <path>` **可重复传**（N ≥ 1），单进程
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
  都收敛）**且** `state_digest` 逐字节相等（S-72 两腿升级，§6.12.1），否则 degraded。
  **无「可调滞后阈值」**——相等即滞后 0，容忍「落后 N 笔」会把
  账本分歧常态化（fail-closed）；异步副本复制（跨机）部署的滞后告警走
  `mist_cluster_replica_lag` gauge 阈值（§8.3 口径：告警阈值属运营配置，健康判定不放宽）。

**指标（`monitor/src/cluster.rs::cluster_samples`，集群 gauge 不带 `instance` label）**：

| 指标 | 口径 |
|---|---|
| `mist_cluster_instances` | 被监控副本数（`--wal` 个数） |
| `mist_cluster_accepted_total` | 副本间 accepted_count **max**（热备组同一逻辑账本，最新推进副本；求和会双计） |
| `mist_cluster_replica_lag` | 副本间 accepted_count max−min（备份滞后笔数，0 = 收敛） |
| `mist_cluster_pending_sealed` | 副本间最差结算滞后（max，取最差副本） |

**实例标签（诚实边界）**：N > 1 时每副本样本的 `instance` label = **WAL 文件名（stem）**
——快照里的 `instance_id` 是 `mist-<monitor 进程 pid>`（§4.1 口径），同一 monitor 进程
恢复 N 个副本会同值，Prometheus 序列会撞。N = 1 时保持 `instance = <instance_id>` 既有
行为（Grafana 面板 `label_values(mist_instance_info, instance)` 不变）。多副本模式要求
各 WAL 文件名互异（启动即报错退出，不猜）。

**实现（`monitor/src/bin/main.rs`）**：`ReplicaScrape`（每副本聚合器 + 独立 WAL Intent
计数 + 独立刮取窗口状态）× N + `ClusterReporter` 实现 `Reporter`（`server.rs` 接口不变）；
`--once` 输出集群 health JSON + 全量 metrics 文本，退出码沿用 0/3（任一副本 degraded 即
3）。吞吐速率逐副本独立按各自窗口增量推算。

**诚实边界**：集群聚合是**副本组视角**，不是分布式共识监控——副本间分歧只报告（degraded
+ lag gauge），不裁决谁是真值（裁决 = 接管 WAL 人工核对，§5 处置）；每副本吞吐仍是刮取
窗口均值（§4 口径不变）；`--once` 模式下 N 个副本逐个全量重放 WAL，启动耗时随副本数线性。

#### 6.12.1 收敛判定两腿升级（S-72，state_digest 指纹）

S-39 的 `replicas_converged` 只比**计数与承诺**（accepted / revoked_len / 撤销根），对
「同计数不同内容」的账本分歧**全盲**：REG 多注册（同 accepted 下多注册一个委托）、
LEDGER 金额分歧（同 dh 的预算四域不同）、WINDOW 窗口域内容分歧（同笔数不同意图）、
INTENT 索引（ih → seq 映射）漂移——这四类分歧三元组全等，撤销根也拦不住 REG/LEDGER/
WINDOW/INTENT 域（撤销根只锚撤销集）。本件把收敛判定升级为**两腿**：三元组腿（S-39
口径不变）∧ **digest 腿**（§6.26 `Aggregator::state_digest()`，全状态域内容指纹）。

**定夺（记录在案）**：

1. **monitor 半边提前兑现 L3-3**：§6.26.1 定夺 6 点名「S-39 三元组比对 → digest 比对是
   L3-3 的自然升级点」。L3-3 全量（绑定闸/kind4 退役、声誉信源改 QC）仍挂账，digest
   比对这半边对现有单写者栈独立有价值（复制链路静默写错的可观测性），提前落地；零合约
   /WAL/热路径改动（monitor 只读面）。
2. **单一检查名不变**：仍是 `replicas_converged`，收敛判定加第二腿——不新增检查名
   （收敛是一个语义问题：「副本组是否收敛？」）。失配时 `detail` 用 `diverged=` 列出
   失配腿（`triple` / `digest`，固定序），**收敛时 detail 逐字节保持 S-39 格式**
   （`accepted=[a=3,b=4] lag=0`）——下游告警/面板不破。
3. **detail 失配格式**：`accepted=[...] lag=N diverged=<腿列表> digests=[a=<16hex>,b=…]`
   ——失配时恒附各副本 digest 前 16 hex（8 字节）：纯滞后（digest 相等）时它证明
   「只是落后、内容一致」；digest 失配时它定位到副本。digest 失配而 lag=0 是**内容分叉**
   信号，比 lag>0 更严重（复制链路静默写错，不是断档），ops.md §5 处置表单列。
4. **digest 在 restore 完成后计算一次**（`ReplicaScrape` 启动期持有，不随刮取重算）：
   §6.26.2 把 digest 语义定义在**静默态**（重放完成 / 无在途写者）——monitor 副本
   restore 后即静默（只读视图，不接热路径），digest 是 WAL 的确定性函数，启动后恒定；
   每次刮取重算是 O(账本) 纯浪费。窗口域不含 per-process `created_at`（§6.26 序列化只
   取 `(seq, intent_hash, accepted_at)`，`accepted_at` 随 WAL Intent 记录重放重建）——
   跨副本（跨进程启动时刻）digest 可比性由此成立。
5. **digest 不进 metrics**：不加 `mist_cluster_digest_*` gauge——digest 失配的告警面就是
   `/healthz` 503（二元事实，无阈值语义），gauge 是同一事实的第二表示，纯增表面积；
   64 hex 也不适合进 Prometheus label（N 副本高基数无收益）。
6. **HealthSnapshot 不动**：digest 挂在集群面输入 `ClusterView`（monitor 自有类型），
   不进单实例快照——单实例 `/healthz` JSON 逐字节不变（S-39「加法不动既有行为」纪律
   延续；§6.26.1 定夺 6 的「本轮不动 health.rs」口径同源）。

**诚实边界**：digest 腿是**诊断面不是判定面**（§6.26.2）——digest 失配 = 告警信号，
不是欺诈证据（无密码学承诺，任何人可在自己副本上重算）；monitor 副本 restore 后静默，
**运行期**新推进（复制链路在 monitor 启动后继续写）不被本检查捕获（要重刮得重启 monitor
——与 §6.12「逐个全量重放」的启动口径一致，副本组是启动时点快照）。

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
（`MIST_BB_BIN` 覆盖路径）→ ② WSL2 兜底（`MIST_WSL_DISTRO` 缺省 MeridianUbuntu，
Windows 路径经 `/mnt/<盘>/` 转换后进 WSL 调 bb）→ ③ 皆无 → **构造期报错**（bin 启动即退，
不落运行时半可用态）。

**接线**：`mist-gateway` 环境变量 `MIST_VERIFY_BACKEND=format|bb`（**缺省 format**，
生产默认口径本件不动）+ `MIST_BB_VK`（vk 文件路径，bb 模式必填、无缺省）。bench / perf
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
pi 与信封不一致拒。e2e 由 `MIST_BB_E2E=1` 门控：verify.sh 第 9 步 formal_zk 产出新鲜
工件后第三 run 拉起；CI noir job formal 之后同款（ubuntu 原生 bb，走 Windows 原生分支语义）。

**诚实边界**：

1. **只收口验证侧，prove 侧 S-43 收口（§6.14）**：SDK 生产路径的 proof 仍来自
   `PlaceholderProver`（格式占位）——`MIST_VERIFY_BACKEND=bb` 开启后这些 proof
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

§6.13 诚实边界 1 兑现：SDK 侧真电路证明生成。`mist-sdk::prover::NoirProver` 实现
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
串行化（证明是重操作，可接受）；工具链解析复用 §6.13 三层探测语义（`MIST_BB_BIN` /
`MIST_NARGO_BIN` → PATH → WSL2 兜底 `MIST_WSL_DISTRO`，Windows 路径经 `/mnt/<盘>/`
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
经 `BridgeConfig.noir`（bin `MIST_BRIDGE_NOIR=1`）接入同一装配——S-46 装配面
的首个二进制消费方（§6.10 第 4 步），`pay()` 的证明公共输入 `agent_commit` 与潜在
`attest_identity()` 同 secret 单一来源由构造保证；缺省占位不变（口径同上）。

**验收测试**：单测（scalar golden + 边界、十进制互转、Prover.toml 组装形状、路径重算根）
+ e2e（`sdk/tests/noir_prover_e2e.rs`，`MIST_ZK_PROVER_E2E=1` 门控）：真实场景
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
   经 `SdkClient::with_prover` 显式接入（与 §6.13 `MIST_VERIFY_BACKEND` 缺省 format
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
（独立 workspace 新 bin，`MIST_NOIR_DEMO=1` 门控，verify.sh 步 9e）——**真电路证明 →
真验证后端 + 撤销根绑定闸 → 链上净额结算，撤销根三方同源**的 M1 形态首次走通：

1. **装配面（§6.14 全套，demo 即可运行的装配答案）**：`SdkClient::with_noir(wallet,
   transport, NoirProver, attestation_secret)` + `InProcessAggregator`（`BbVerifier::
   from_parts(vk, backend, tmp_root)` + `IngestConfig::enforce_revocation_root = true`，
   §6.13/§6.2/§6.14 同口径；S-48 构造期配对闸在此生效）。
2. **授权上下文**：`client.authorize()`（S-46 NonceManager 1 起口径）→ `create_delegation`
   同参数重建同 dh（assert 相等）→ 链上 `DSA.registerDelegation`，`isRegistered(dh)`
   断言 **sha256(delegationABI) == mist-core delegation_hash**（m1_demo 同款交叉实现
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

**线格式（`mist.pay` 入参新增 optional `proof` 对象）**：

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

**装配面（`mist-mcp` bin，网关 bin 同款）**：`MIST_VERIFY_BACKEND`（缺省
`format` 口径不变；`bb` → `BbVerifier::from_env`，工具链不可得**启动即退** fail-closed）
+ S-48 构造期配对闸（`requires_revocation_root_binding()` ⇒ `enforce_revocation_root =
true`）。bb 模式下占位证明 / 派生错位 / 篡改任一公共输入 = 密码学拒 `E_PROOF`。

**新工具 `mist.revocation_witness`（第 6 个工具）**：客户端构建真证明所需的**唯一
服务器侧事实**——S-45 网关 `GET /v1/revocation-witness/{dh}` 的 MCP 面（`root` 64hex +
`path` 256×32B 扁平 hex = 16384 字符，MCP 面首次大载荷）；已撤销 → `E_REVOKED`
（§11 同码）。没有它，MCP 客户端拿不到非成员路径，真证明无从谈起。

**测试**：`mcp_flow` +3（直通证明被验证器**真实消费**——`RejectAllVerifier` 对照组
`E_PROOF`，服务器绝不偷偷换成自己的占位；缺省口径占位不变；witness 工具正/负向）+
门控 e2e `MIST_MCP_NOIR_E2E=1`（`mcp-server/tests/mcp_noir_e2e.rs`：客户端侧
`NoirProver` 真电路证明 → MCP `pay` 工具 → `BbVerifier` + 撤销根绑定闸聚合器接受；
对照组：同一聚合器上占位 `pay` 必拒 `E_PROOF`）。verify.sh **9f** + CI noir job 同款。

**诚实边界**：`format` 缺省后端下 `agent_commit` / `revocation_root` / `now` 三个自由量
无密码学约束（与网关格式口径一致，真约束在 bb 装配 + 撤销根绑定闸）；服务器侧产证明
**不在本件也永远不在**（keyless 是设计约束不是待办）；证明 8128B 经 JSON hex 走 stdio，
MCP 面单笔载荷 ~20KB（吞吐口径不适用于 MCP 面）；WAL 不落证明（`RecordKind::Intent`
固定 116B payload，§10），直通不影响 WAL 格式与恢复语义。

**框架 demo 面（S-53，候选⑨收口）**：`demos/` 三框架脚本（LangChain / AutoGen /
ElizaOS，S-13b 同一闭环）在 `authorize` 之后加入 `mist.revocation_witness` 步——
回执形状自检（`root` 64 hex + `path` 256×32B 扁平 = 16384 hex 字符 + 回执
`delegation_hash` 与本地重算逐字节一致），三个框架逐字节同口径。诚实边界：`pay` 的
optional `proof` 直通**不在框架脚本演示范围**——真电路证明需要 nargo/bb 工具链（§5.3），
Python/JS 脚本侧不可得，硬造即假演示；该路径由本节门控 e2e `mcp_noir_e2e` 实证，
框架脚本演示的是 witness 事实面（真证明的前置事实来源）。

**框架 demo 真链 settle 完整化（S-76，2026-09-01，任务书「完成后」条款点名砖）**：
缺口本体——三框架闭环止步 mock vendor（凭 `verify_receipt` 回执授 API 积分），钱的
最后一公里（BatchSettler commit → settle → 过挑战窗 → claim）在对外演示面整段缺失；
Rust 侧 `m1_demo`/`noir_demo` 有完整演练但自带合成意图，不消费对外 demo 产出的账本。
四件工件：

1. `mcp-server/src/bin/mcp_probe.rs`（bin `mcp_probe`）——Rust 侧 MCP stdio 客户端
   参考实现 + 冒烟探针：spawn 同 package 兄弟 bin `mist-mcp`（`current_exe()` 兄弟
   定位 + `EXE_SUFFIX`），手写 newline-delimited JSON-RPC（initialize →
   notifications/initialized → `tools/call`），fixture 与 `mist_demo_common.py`
   逐字节同参（同 owner/agent 密钥与 DID/同金额——probe 产出的 WAL 与框架 demo 的
   WAL 同形），断言与 demo 闭环同款（本地重算 `delegation_hash`/`intent_hash` ==
   服务器回执）。
2. `contracts/rust-smoke/src/bin/demo_settle.rs`（bin `demo_settle`）——运营者结算
   侧车：`--wal <path>` → 拷贝 WAL 快照（定夺 ①）→ `restore_from_wal`
   （`IngestConfig::default()` + FormatVerifier，重放不验证明）→ `seal_expired(now, 0)`
   （定夺 ②）→ `settle_epoch` → spawn anvil → deploy DSA/RevocationRegistry/
   BatchSettler（`m1_demo` 同构造参数）→ `commit(epochId, commitmentRoot,
   revocationRoot, acceptanceRoot, sealedAt).value(BOND)` →
   `settle(net, nettingRoot).value(Σnet)` → fast_forward 过挑战窗 → 逐收款人 claim
   断言余额增量 == net 行金额（`m1_demo` E 段同款逐 wei 对账）。
3. 三框架 demo 第 7 步：`mist_demo_common.run_onchain_settle()`（Python 两框架共享）
   / `eliza_client.mjs` 同款——subprocess 调 release `demo_settle`，闭环保留 6 步
   不动，第 7 步独立于 MCP 会话（结算不消费 MCP 面）、在会话关闭后调用；三框架
   启动时清盘自有 WAL 目录（`fresh_wal_dir()` / `rmSync`，定夺 ⑧）。
4. verify.sh 新步 **10b**：`cargo build -p mist-mcp --bins` → `mcp_probe <dir>` 产
   真 WAL → `demo_settle --wal` 对真 WAL 结算断言。foundry 门控同 step 10（anvil
   不可得 skip）；verify.sh 是本地门禁，CI 不跑（同 verifier_drill/registry_flow 口径）。

九条定夺（记录在案；⑦⑧⑨ 为实施期发现，2026-09-01 回填；⑨ 由端到端首验的
双付事故驱动）：

1. **侧车是 WAL 快照消费者，不回写账本**——拷贝快照后从快照恢复，`settle_epoch` 落的
   EpochSeal/Netting 记录进快照不进原 WAL。理由：ⓐ demo 第 7 步幂等重跑（回写原 WAL
   则第二次 restore 见已密封尾 → 无可结算 → 演示碎）；ⓑ RSM 性质（§6.26）保证快照侧
   与在线侧是同一 WAL 的同一确定性函数，密封/根/epoch_id 逐字节可比；ⓒ 结算状态的
   所有权归账本进程，侧车不制造第二个写者。
2. **密封语义 = `seal_expired(now, 0)`**：`epoch_secs=0` 即「运营者显式密封当前尾」，
   不模拟时间窗轮询（`m1_demo` 传 60 是吞吐演示口径）；restore 后 `created_at` =
   侧车启动时刻（ingest.rs `restore_tail` 注释），0 阈值使密封无条件发生。
3. **probe 走真 MCP 协议不走进程内直调**——门禁覆盖「mist-mcp 二进制 → stdio
   JSON-RPC → WAL 落盘」全链，与框架 demo 的消费面同一（三框架是同一协议的薄包装）；
   手写 JSON-RPC 只用 std 依赖（协议面 = newline-delimited JSON-RPC 2.0，MCP 标准）。
4. **侧车不做链上 `registerDelegation`**——WAL 注册面在验签后只存
   `RegisteredDelegation{delegation, agent_pub}`，owner 签名即弃不可重建；且
   commit/settle/claim 不消费 DSA 登记状态（BatchSettler 仅 kind4 挑战守卫读
   `operatorOf`/`boundAt`）。链上登记交叉锚由 `m1_demo`/`noir_demo` 覆盖。
5. **金额标度 = 账本 amount 与链上 wei 同一标度**（`m1_demo` E 段先例）：demo 一笔
   142 → vendor 收 142 wei——单位演示，不是定价口径（定价见宣发③，[BOSS] 占位）。
6. **demo 第 7 步降级口径**：`demo_settle` 二进制缺失 → 打印一行构建指引后跳过
   （诚实降级，6 步闭环仍完整）；存在但失败 → loud fail——绝不静默吞错硬造全绿。
   跑第 7 步需 foundry（anvil）在 PATH。
7. **MCP 面回执持久点（实施期发现）**：动手前查证 mcp-server 此前**从未调用
   `flush_wal`**——MCP 面记录数远低于 `sync_every`（mcp bin 开 1_000）阈值，缓冲
   整本随进程退出丢失，`demo_settle` 要消费的 WAL 恒为空文件，本砖前提（真账本
   落盘）不成立。定夺：ⓐ 变更工具（authorize / pay）的回执离开状态层前强制 fsync
   （`AppState::persist`；幂等 re-ack 路径同样补 flush——上一次「注册成功但回执前
   失败」的重发在此补上，fsync 幂等）；失败 → 新错误码 `E_WAL`（§11，fail-visible，
   **回执 = 已持久化事实**，绝不静默吞掉）；ⓑ bin 停机路径（stdin EOF / Ctrl-C 后）
   补 `flush_wal` 兜底其余路径。读面工具（balance / verify_receipt / witness /
   attest）不落账本事实，不加。kill -9 / 断电丢未 fsync 尾巴仍属标准 WAL 语义
   （§8.1）。
8. **demo WAL = 本轮 scratch 面，启动清盘（不是账本档案）**：三框架脚本启动时清掉
   `demos/.wal`。理由：mist-mcp 启动**不重放** WAL（`restore_from_wal` 是显式入口，
   bin 未接），定夺 ⑦ 使 WAL 首次真实落盘后，复跑会在旧账本上追加重复
   Register/Intent 记录（重启缝隙从「被 flush 缺口掩盖」变「必现」）；demo 语义 =
   一轮完整会话的账本，清盘保证每轮从零开始、确定性复跑。**边界诚实**：这是 demo
   面 scratch 语义，不是账本进程的清盘面——生产 WAL 只增，清盘权不在任何消费方；
   「bin 启动重放 + 内存委托表重建」是独立缝（S-78 候选，见下诚实边界）。

9. **重放侧未密封尾按意图身份 `(seq, intent_hash)` 去重（实施期发现，真实事故驱动）**
   ——定夺 ⑧ 落地后的首轮端到端验证即复现：mcp_probe 对同一 WAL 目录连跑三次（不复
   位），WAL 累积三条同 `intent_hash` 的 Intent 记录（每个无重放的新进程把同一逻辑
   意图当新意图接受，各带自己的 `accepted_at`，seq 都从 0 起）。`restore_from_wal` 重
   放该 WAL 时**账本与结算发散**：账本侧 `try_commit` 按 S-12 幂等吸收重复（total_spent
   = 142、nonce 集一席），但未密封尾重建按**整条记录字节**排序后相邻去重——同
   `(seq, ih)` 而 `accepted_at` 不同的记录字节不等，两份都进窗 → `seal_expired` 出
   2 条目 → 净额 Σ=284，链上给 vendor 双倍支付一笔 142 的意图。修复：尾去重键改为
   意图身份 `(seq, intent_hash)`（`apply_log` pass 4，与账本侧幂等吸收键一致），排序
   后相邻去重仍确定（同 `(seq, ih)` 记录的其余字段由意图本身决定，仅时间戳不同；保留
   组内最小 `accepted_at` = 首次接受时刻，接受树锚原始事实）。裁决史不变（仍每条目一
   裁决）；`permuted_and_duplicated_delivery_converges` property test 语义不变（其重复
   投递是字节级副本，新旧键下都收敛）。**边界诚实**：ⓐ 这修的是「重复 WAL 不得双付」
   的防御纵深——病根是无重放写入端能产出重复记录（S-78 候选，恢复面接上即根除）；
   ⓑ 同 nonce 跨意图的重复记录（无重放进程各自花同一 nonce 但 memo 不同）重放时
   `try_commit` 报 `E_NONCE` → 恢复整体 fail-closed（不静默择一），仍由 S-78 根治；
   ⓒ probe 自此启动时清点并复位目标 WAL 目录（定夺 ⑧ 同款语义，参考客户端对
   caller 目录的 scratch 约定），门禁与复跑不再天然产出病态 WAL。

**债券 happy-path 退回 `releaseBond`（S-77，2026-09-01，主网真跑前主会话自审发现）**：
主网真跑一笔结算的预算核算中发现 `bondedAmount` 全函数集仅两条出路（challenge 成功
判给挑战者 / 永久滞留合约）——happy path 无退回路径，spec 口径（§6.5「震慑作用」、
宣发③「locked and at risk」）与合约不符：理性运营者均衡是债券 → 0（反正拿不回），
§6.5 乐观安全模型静默失效；不变量①无「已退债券」项反而把滞留固化为预期行为，fuzz
全绿不可见（教训：**守恒式"绿"≠生命周期完备，动作面覆盖不可省**）。修复 = §6.4
第 5 步 `releaseBond`（settled ∧ ¬voided ∧ 窗口过 ∧ bondedAmount>0 → CEI 退债 +
`BondReleased`；窗口后 challenge 已被 `ChallengeWindowClosed` 前置挡下，与罚没无
竞态）+ 单元 6+1 用例（push 失败可重试 = withdrawRefund 重试语义同款，ToggleOperator
拒收面补 `require(ok)` 失败边——覆盖门禁 79/81 红到绿）+ invariant handler 动作面
（ghost 净扣）。forge 130→137 全绿；
slither 复扫 17 结果，新增 3 条全落既有已知设计类（reentrancy-events / timestamp /
low-level-calls，与 withdrawRefund 同性质：push 语义 + 事件仅观测面 + 时间戳量级差
3 个数量级），**零新类别**、arbitrary-send-eth 未命中（仅向 immutable `operator`
发送）。债券金额口径同步勘正：协议无最低值检查，`1 ether` 是测试常量与建议规模
非协议要求（§6.5）。S-76 文本中的 S-77 候选指针（bin 启动重放恢复缝）顺延为 S-78。

### 6.17 Phase 2 多运营者治理（设计轮，P2-0，2026-08-31）

**定位**：v1 是「诚实路径」单运营者（§6.5——我们自己是第一个运营者，债券起震慑作用）。
全库「Phase 2」挂账点（§4.5 预算诚实记账、§6.5 声誉分行与押金运行时自适应、§6.5 诚实
路径多运营者、§10 Sybil 行）在此收拢为一份设计轮产出。**本节是设计，不是实现声明**——
P2 各实施砖开工前必须先回填本节定夺项（先改后码纪律在本阶段的落点）。

#### 6.17.1 v1 单运营者耦合点盘点（设计输入）

| # | 耦合点 | 现状（已实证） | Phase 2 需求 |
|---|---|---|---|
| 1 | 结算写者 | `BatchSettler.operator` = `address public immutable`，`onlyOperator` 守 commit/settle/withdrawRefund | 多运营者各自提交各自 epoch |
| 2 | 预算强制层 | §4.5 设计决策：预算累计状态留在聚合器确定性账本（**off-chain**），靠债券约束诚实记账 | **跨账本双花**：两张独立账本各自持有同一委托的 `BudgetState`，同一 `total_cap` 可被各消费一次，任何单账本内部不可见此超支 |
| 3 | 撤销观察 | v1 无链上监听器，「运营者负责传播」（§4.6 债券罚没兜底）；S-59 fanout 是**单运营者**副本组内传播（尽力而为非共识）。**已落地（S-67，§6.24）**：gateway 内置链上 `Revoked` 事件观察线程 | 每运营者独立的链上撤销观察面 |
| 4 | 挑战押金金额 | 部署期构造参数 `immutable challengeBond`（S-50），运行时 setter 被否决（governor 双向作恶论证） | 金额随 gas 价格/债券规模的适应性 |
| 5 | 声誉分 | §6.5 行 2 挂账「债券罚没 + 声誉分（Phase 2）」 | 派生源与暴露面 |
| 6 | Sybil 防护 | §10 表「质押绑定 + 履约证明（L4 spec 覆盖）」 | L4 范围，本设计轮不展开 |
| 7 | 验证面 | 挑战入口**本就 permissionless**（任何人 + 押金，S-38），但无独立验证者实体在跑——v1 的发现率实际等于运营者自查 | 去中心化验证 |

#### 6.17.2 核心决策（记录在案）

**决策 A —— 分片优先于共识。** Phase 2 的「多运营者」定义为**按委托分片的独立运营者
集合**：每张委托在授权期绑定唯一运营者，各运营者跑完整 v1 栈（ledger / gateway /
BatchSettler 实例各一套），各自 commit/settle 各自 epoch。不是 BFT 共享账本。理由：

1. 预算在账本侧（§4.5 决策）——共享账本要求全部写者对同一账本状态达成共识，共识协议
   本身是 L3 级交付物，其正确性论证量级远超本仓已验证面（本仓全部安全论证建立在
   「单写者确定性账本 + 乐观挑战」上，§6.5）。
2. 分片完整复用 v1 栈与全部门禁（每运营者一套实例），增量可测、可审计、可回滚。
3. S-55 已实证 ZK 侧升级 blocked-on-upstream；不把账本层升级绑在另一条未验证路径上。

代价：跨分片双花必须另设封堵（决策 B）；单委托吞吐受其分片运营者的单写者限制
（§4.5 规则 7 的 `(agent, delegation_hash)` 分片内并发不变）。

**决策 B —— 跨分片双花在链上封堵：授权期绑定 + 新欺诈证明 kind「跨分片消费」。**
预算在账本侧 ⇒ 分片间超支任何单账本都看不见，封堵必须落在可公开验证的锚点上：

- **绑定**：DSA 增加委托→运营者绑定面（`dh → operator` 映射，owner 在注册期写入）。
  **绑定不进 delegation_hash preimage**——DSA 的 `dh = sha256(delegationABI)`（DSA.sol），
  绑定是独立映射。改哈希派生会级联炸穿撤销索引（S-34/S-36 全 32B LE 位派生）、SDK、
  电路公共输入与差分 fuzz（S-57）全部锚点，不可接受。
- **事前强制**：聚合器摄取面拒绝「绑定到其他运营者」的意图。Contract 模式已有链上读
  路径（S-10 `isRevoked` 快查同款 RPC 读），成本同级。
- **事后强制**：BatchSettler 新欺诈证明 kind——出示意图原文 + merkle 兄弟路径（证明
  ∈ 承诺根，复用漏单 kind 的包含验证）+ 链上绑定映射读数（`intent.delegation_hash`
  绑定到 ≠ 本合约 `operator`）→ 债券罚没判挑战者。`SpendIntent.delegation_hash` 已在
  意图信封内（§6.1），链上可读，不需新增协议字段。
  **（P2-3 开工定夺修正，§6.20：本条原文「与漏单/低付同款 sound + 有界」不成立**——
  朴素条件把「事件前合法接受」也判成欺诈，是对诚实运营者的抽债券向量；健全形态需要
  接受锚（acceptanceRoot），详见 §6.20.1/6.20.2。）
- **诚实边界**：绑定映射由 owner 写 ⇒ owner 与运营者合谋（故意绑错分片）不在密码学
  防御内——那是 §10 威胁模型的授权滥用面，靠 Sybil/声誉（决策 E、L4）缓解。
- **存量委托**：绑定面上线前已注册的委托 = 未绑定。**未绑定委托不受摄取闸约束**
  （fail-open 是有意取舍：fail-closed 等于让闸上线当天冻结全部存量委托的支付能力），
  但跨分片欺诈证明 kind 对未绑定委托不成立 ⇒ 存量委托在剩余有效期内仍是跨分片双花面。
  缓解 = owner 重注册（新绑定）；彻底收口要等存量全部过期。**记录在案：这是 fail-open
  的已知代价，不假装闸上线就封闭了。**

**决策 C —— 写者与验证者分离先行，且验证面零合约改动。** 挑战入口本就 permissionless
（S-38 押金语义对任何地址一致），多运营者第一阶段的多方制衡 = **独立验证者实体**：运行
同一确定性账本复算（S-59 副本组机制的同构扩展——副本组已经持有完整 WAL 并做
`replicas_converged` 三元组比对），检测到 commit ≠ settle 后上链发起挑战。合约零改动，
改动在运维与监控面（砖单 P2-1）。诚实边界：验证者不解决写者单点（审查/停机/绑合谋），
只解决「承诺与结算不符」的发现率——从「运营者自查」升级为「第三方可复算」。

**决策 D —— 债券/押金金额：append-only 调度 + 实例固化，不做运行时 setter。** S-50 的
信任面论证在多运营者下**保留**：governor 抬价 = 审查欺诈证明（挑战成本 → ∞）、降零 =
复活垃圾挑战，性质不随治理结构存在而改变。口径改为：新合约 `OperatorRegistry` 持有
**append-only** 的金额调度（旧值永不改写，新值追加生效，链上全史可审计），新
BatchSettler 实例部署时读取当刻值**固化为 immutable**；存量实例各持其部署版本的值。
S-50 挂账的押金「运行时自适应」以此口径收口：动态性来自调度 + 重部署，不来自 setter。

**决策 E —— 声誉分是链上罚没历史的只读派生，不进任何判定面。** 唯一事实源 =
BatchSettler 罚没/voided 事件；声誉 = monitor 面派生指标（罚没次数 / 在押债券 /
存续 epoch 数 / 副本收敛记录），用途限于展示与选型参考。**任何合约判定路径不得读
声誉**——把声誉写进判定 = 制造新的可攻击信任面（刷量/打压，§10 Sybil 行的自指放大）。

**决策 F —— 撤销观察：每运营者独立链上监听是 P2 硬前置。** v1「运营者负责传播」口径
在多运营者下失效：S-59 fanout 只覆盖单运营者副本组内，分片后漏看的运营者会接受已撤销
委托。兜底仍是债券罚没（§4.6），且过错事后可证（`RevocationRegistry` 撤销交易时间戳
≤ commit 时间 ⇒ 可证用过时撤销根）；**是否把「过时撤销根」做成独立欺诈证明 kind 挂
P2-3 定夺**（与跨分片 kind 共享包含验证骨架，边际成本低，倾向做——已按接受锚后置落地，
S-66 kind3/§6.20.4）。**观察面本体已落地（S-67，§6.24）**：gateway 进程内置
`Revoked` 事件观察线程，链上撤销自动进本账本。

#### 6.17.3 分期砖单

| 砖 | 内容 | 依赖 | 规模 |
|---|---|---|---|
| **P2-1** | 验证者挑战演练：独立账本复算检出 commit≠settle → 欺诈证明提交工具链，本地 anvil 全链演练（人为错账 → 第三方检出 → challenge → voided + 罚没）。**已落地（S-61，2026-08-31，§6.18）** | 决策 C，**零合约改动** | 小 |
| **P2-2** | DSA 委托→运营者绑定面（独立映射不进哈希，owner 注册期写入）+ 聚合器摄取绑定闸（Contract 模式 RPC 读）+ 存量委托 fail-open 口径。**已落地（S-62，2026-08-31，§6.19）**——写入形态定夺收窄为「owner 私钥一次性交易 `bindOperator`」（§6.19.1），存量委托由 owner 补绑收窄 fail-open 残余 | 决策 A/B | 中 |
| **P2-3** | BatchSettler「跨分片消费」欺诈证明 kind +（P2-3 开工时定夺）「过时撤销根」kind。**已落地（S-66，2026-08-31，§6.23；方案老板 2026-08-31 确认，§6.20）**：开工定夺（S-63，§6.20）判两个 kind 的朴素形态均不可健全实现（接受时刻墙，§6.20.1），健全形态 = 平行接受承诺树 acceptanceRoot（§6.20.2），规模重估「中」→「大」，次序调到 P2-4 之后 | P2-2 | 大 |
| **P2-4** | OperatorRegistry（append-only 金额调度 + 运营者名册）+ 多实例部署流程与文档。**已落地（S-64，2026-08-31，§6.21）**——BatchSettler 逐字节不动，读取点定在部署流程（定夺 1），名册 = self-registration 绑定实证（定夺 4），deploy.rs 三参构造潜伏缺陷顺带修复 | 决策 D | 中 |
| **P2-5** | 声誉派生（monitor 面只读指标）。**已落地（S-65，2026-08-31，§6.22）**——零合约改动，信源定夺为事件 + 合约余额（不走事件差，定夺 2），真 anvil 锚 = verifier_drill 幕 4 | 决策 E | 小 |
| **P2-6/L3** | 共享账本共识（多写者同一账本）。**独立共识设计轮已产出（S-69，2026-09-01，§6.25）**：问题定义（买的是写者活性不是安全性）、共识对象 = WAL 的 RSM 分解、摄取语义墙、QC 公证链上面 + kind5、协议形态定夺乐观复制、分期砖单 L3-0..3——**实施仍 blocked**（解锁条件 §6.25.7：审计冻结未打 + 无生产活性痛点数据；L3-0 不依赖解锁条件） | 前置 = P2-1..5 实证 + 独立共识设计轮，**均已满足**；决策 A 在本阶段**不实施** | 大 / blocked（设计轮已清，实施挂解锁条件） |

**次序约束（与审计冻结清单的关系，S-58）**：冻结纪律在**外聘审计启动时**才生效
（预算未批则清单不执行、tag 不打）；故 P2 合约砖（P2-2/3/4）在审计启动前可推进，
但**每砖合入后必须同步重对齐 audit-scope §1 文件清单 / §5 测试计数 / §4 已知问题**
（S-58 口径的延续——范围书与实态漂移 = 范围书失效），审计对象以最终 tag 为准。
P2-1/P2-5 无合约改动，不触碰冻结面。

#### 6.17.4 诚实边界

- **P2-1 已落地**（S-61，§6.18）：Rust 验证面 `fraud.rs` + anvil 三幕演练有测试锚定。
- **P2-2 已落地**（S-62，§6.19）：链上绑定面 + 摄取绑定闸 + JSON-RPC 读装配有测试锚定；
  P2-3 开工定夺已完成（S-63，§6.20），**现已落地**（S-66，§6.23）——跨分片双花与已撤销
  消费经平行接受锚 acceptanceRoot + kind3/kind4 上线（方案老板 2026-08-31 确认）；绑定闸
  挡「绑他方的后续意图」，存量未绑定委托 fail-open 如故（§6.19.5）。**P2-4 已落地**（S-64，§6.21）：
  OperatorRegistry 调度/名册是**记录面不是强制面**——跳过注册表、偏离调度、registrar
  降额均不被密码学阻止，只被全史与快照公开（§6.21.4）。**P2-5 已落地**（S-65，§6.22）：
  声誉指标从 BatchSettler 事件 + 合约余额派生（monitor 面），读失败 fail-visible 不清零、
  解码失败 fail-closed、缺省无参时序列完全不出现（定夺 4-6）。**决策 F 观察面已落地**
  （S-67，§6.24）：gateway 内置链上 `Revoked` 事件观察线程（零合约改动，尽力而为非
  共识）。**P2-6/L3 独立共识设计轮已产出**（S-69，§6.25）——问题定义 / 语义定夺 / 砖单
  L3-0..3 落笔，实施仍 blocked（解锁条件 §6.25.7）。
- **不可改绑**（v1 口径，P2-2 落地时钉进合约）：改绑窗口内旧账本在途意图的预算消费
  不可回滚 = 双花面。迁移路径 = owner 撤销旧委托 + 注册新委托（预算重置的代价由
  owner 承担，链上全程可见）。
- 验证者合谋、写者审查、绑定合谋（决策 B 诚实边界）不在 P2-1..5 防御内——那需要
  P2-6 共识或外部追责，P2 阶段以「多方独立验证提高发现率」为边界。
- 分片模型下无全局账本视图：跨分片的总量统计、全局撤销根快照等聚合面不存在
  （monitor 只能按运营者分别聚合，S-39 集群指标是**同账本副本**聚合，语义不同）。
- 声誉分无抗 Sybil 语义（决策 E 只读派生不改这一点，L4 覆盖）。

### 6.18 P2-1 验证者挑战演练（实施，2026-08-31）

**定位**：§6.17 决策 C 的实施砖——写者与验证者分离的最小实证。独立验证者实体**不复用
运营者内存态**，从公开面复算账本，检出 commit≠settle 后构造欺诈证明上链挑战。
**零合约改动**（决策 C：BatchSettler 逐字节不动，P2-1 不触碰审计冻结面 §6.17.3）。

#### 6.18.1 验证者信源面（定夺记录在案）

- **出证信源 = 已接受意图镜像流**：完整意图信封 + `Receipt.seq`。生产口径 = 网关/聚合器
  接受流的多播副本（S-59 副本组机制的同构扩展——副本组已复制 WAL 并做三元组比对，
  验证者在此之上需要信封面）；本砖落地为演练内共享提交流。
- **WAL 副本不可独立出证（设计发现，记录在案）**：WAL Intent 记录 payload 仅
  seq/intent_hash/delegation_hash/spend_nonce/amount/now/recipient 七字段；意图信封的
  agent/category/memo/expires_at 在聚合器接受后即被修剪（内存 `IntentRef` 同款只留
  recipient/amount/seq）——`IntentProof` 的哈希 preimage 无法从 WAL 重建。本砖**不改
  WAL 格式**（§6.17.3 冻结面纪律），信源定为镜像流。
- **soundness 不依赖镜像信任**：每条出证意图出证前 Rust 侧自检（`intent_hash` 重算 +
  `merkle::inclusion_proof` 兄弟路径重算 == 链上 `commitmentRoot`）。镜像被篡改/缺漏 =
  检出率下降，不产生假证——链上二次验证（S-38 `_verifyFraud`）是最终锚。

#### 6.18.2 链上读取面（定夺记录在案）

- **settle 交易 calldata 是净额的公开事实源**：Solidity 自动 getter 对 struct 内数组成员
  整体省略（实测 `epochs()` ABI outputs 无 `net[]`），外部验证者经 getter 读不到 net[]。
  验证者读 `Settled` 事件 → 取 settle 交易 → abi-decode `settle(epochId, net[], nettingRoot)`
  calldata 得 net[]。calldata 是链上公开数据，零合约改动。
- **S-66 读面拆分（13 元组爆栈收口）**：P2-3 给 `Epoch` 增 3 字段后（13 读面字段），自动
  getter 的 13 元组返回在 legacy codegen（`forge coverage` 关优化编译）恒爆栈——13 个隐式
  返回槽恒活跃，最小 13 元组函数亦不可编译（`AsmCodeGen.cpp` "value0 is 1 slot(s) too
  deep"，与函数体无关）。定夺：`epochs` mapping 改 internal（`epochsById`），读面拆为
  显式 **`epochs(epochId)`（9 静态字段：3 root + 3 时刻 + 2 金额 + nettingRoot）** 与
  **`epochStatus(epochId)`（4 状态位：committed/settled/challenged/voided）**；net[] /
  claimed 依自动 getter 规则本就不在返回面。验证者侧（rust-smoke `common.rs`）以
  `epoch_snapshot()` 两次读合成 13 字段快照，下游消费面零迁移。
- 自检闭环：解码出的 net[] 重编码 `keccak256(abi.encode(net))` 必须等于链上
  `nettingRoot`（合约 settle 已强制等式，读面错误 = 解码 bug）→ 不等 fail-closed 不出证。

#### 6.18.3 检出面与出证闸

- **复算走生产 netting 路径**：验证者与运营者跑同一 `lattice::build_epoch`（确定性重排
  B11 + BTreeMap 净额序），不同只在输入——验证者吃镜像流。这保证 nettingRoot 对数组
  字节序的口径天然一致。
- 检出信号（诊断面）：① 承诺根不符（镜像缺漏或运营者错承诺）② 漏单——镜像中已核验
  意图的收款人在链上 net[] 无行（kind1 可证）③ 低付——net 行额 < 该收款人已承诺 Σ
  （kind2 可证）④ 多付——net 行额 > Σ（运营者自损，不可挑战仅告警）⑤ 凭空收款行——
  net 行收款人无任何已承诺意图（资金流向未承诺方，合约无 kind，不可挑战仅告警）。
- **出证闸（保押金）**：镜像重算承诺根 == 链上 `commitmentRoot` 才出证。兄弟路径由镜像
  叶集构造——镜像不完整时兄弟路径必然错误（链上 `BadInclusionProof` → 押金销毁，S-38
  驳回即没收）。根不符时全部检出信号只告警不上链。
- kind1 漏单恰 1 条意图（合约 `BadFraudKind` 上限）；kind2 低付取同收款人意图子集
  ≤ `MAX_INTENTS_PER_CHALLENGE`(32)，>32 时按金额贪心取子集直至 Σ > 行额（每个子集
  元素同为该收款人，`BadFraudKind` 防假阳性守卫不触发）。

#### 6.18.4 工件

- `aggregator/src/fraud.rs`：镜像复算 / 检出 / 出证候选构造（纯函数，无 alloy 依赖；
  链 I/O 在演练 bin）。单测锚定：诚实零检出、kind1/kind2 出证（含逐条自检）、多付与
  凭空收款行只告警、镜像缺漏/篡改触发出证闸、贪心子集上界。
- `contracts/rust-smoke/src/bin/verifier_drill.rs`：anvil 三幕全链演练——幕 1 诚实对照
  （检出空 → 不挑战 → claim 全绿）；幕 2 kind1 漏单（人为错账 = settle 抽行 → 验证者
  检出 → challenge → `ChallengeSucceeded` + voided + 债券罚没给验证者 + claim 拒
  `EpochVoided`）；幕 3 kind2 低付（settle 低付一行 → 同款断言）。错账注入点 =
  settle 调用参数（真实欺诈形态，聚合器/合约零改动）；验证者用独立 signer（anvil #1）。
- verify.sh 步 10 挂 `verifier_drill`（同 rust-smoke 门禁口径：forge/anvil 不可得即跳过）。

#### 6.18.5 诚实边界

- 演练为**进程内双实体**（验证者与运营者同进程、独立 signer 与独立复算态）；生产形态 =
  独立进程/独立运营者（决策 C），本砖不宣称已部署独立验证者网络。
- 验证者不解决写者单点（审查/停机/绑合谋，决策 C 边界）——只提升「承诺与结算不符」的
  发现率：从运营者自查升级为第三方可复算。
- **纯「承诺根错账」不可挑战**：运营者 commit 了不含镜像意图的根（settle 与其自洽）——
  信号①可检出，但验证者无法构造错根的包含证明（不知错根叶集），上链挑战不可得；
  发现只能告警，罚没路径不在本砖（治理面）。
- **撤销根比对不在本砖**：验证者可复算撤销根并比对（S-41 后口径可比），链上 kind3
  （S-66 落地）锚的是 per-意图撤销时刻（`RevocationRegistry.revokedAt`）而非撤销根
  比对——撤销根不符仍只是发现/告警面（比对的发现价值不受 kind3 影响，§6.20.4）。
- 镜像完整性是出证可用性前提：镜像缺漏 → 该 epoch 零出证能力（检出率损失，非正确性
  损失——出证闸 fail-closed 方向安全）。
- challengeBond 是验证者成本：驳回即没收（S-38）→ 出证闸与逐条自检是成本纪律，不是
  可选优化；误报上链 = 押金销毁。

#### 6.18.6 落地实测注记（S-61）

- 三幕全绿（exit 0），verify.sh 步 10 接线后随门禁同步跑；aggregator 单测 109→118。
- **罚没口径实测（首版断言写错被链上对账抓出，记录在案）**：挑战者付 0.1 ETH 押金
  （`msg.value`）→ 成功赔付 `challengeBond + bond` → 净增 = **运营者债券**（押金原额
  退回，净零）。首版断言误写「净增 = 押金 + 债券」（1.1 ETH），anvil 逐 wei 对账实际
  1.0 ETH——与 S-50 罚没口径一致，断言修正为债券一项。净零语义比「押金+债券」更严格：
  押金不是赏金，只是准入门槛。
- rust-smoke 独立 workspace 不在 fmt 门禁内，但 clippy 已与新工具链（1.96：
  `needless_question_mark` / `needless_late_init`）对齐清零（`common.rs` / `bin/deploy.rs`
  顺手修正）。

### 6.19 P2-2 DSA 委托→运营者绑定面（实施，2026-08-31）

**定位**：§6.17 决策 A/B 的实施砖（砖单 P2-2）——分片多运营者的事前强制层。委托在链上
锚定其唯一运营者，聚合器摄取面拒绝「绑定到其他运营者」的意图，把跨分片双花从
「事后欺诈证明（P2-3）」前移到「事前不发生」。P2-3 的跨分片欺诈 kind 消费本节绑定映射。

#### 6.19.1 链上绑定面（DSA.sol，定夺记录在案）

- **独立映射，不进哈希 preimage**（决策 B 硬约束）：`DSA.operators: dh → operator` 与
  `owners` 并列。`dh = sha256(delegationABI)` 派生、SDK 签名语义（owner 对 dh 签名）、
  电路公共输入、撤销索引（S-34/S-36）、差分 fuzz（S-57）锚点全部不动。
- **写入定夺：独立一次性 owner 交易，而非扩展 `registerDelegation` 入参**。设计轮原文
  「owner 在注册期写入」收窄为：`bindOperator(dh, operator)`，`msg.sender == owners[dh]`
  才可写、写入即固化（无解绑/改绑函数）。三条理由（记录在案）：
  1. **owner 签名语义逐字节不动**——扩展注册入参需要 owner 对 `(dh, operator)` 联合
     签名，动 core 签名派生 → 级联 SDK / 电路 / 差分 fuzz 全锚点，违背决策 B 本意；
  2. **抗抢跑**：`registerDelegation` 是「任何持有 owner 签名者可发」的许可面（签名
     可离线转发），注册入参带 operator 等于允许持有该签名的任意第三方替 owner 选
     分片运营者（支付路由劫持面）；`msg.sender == owner` 把选型权钉在 owner 私钥上；
  3. **存量委托可事后补绑**——注册 ABI 不变，绑定面上线前已注册的委托由 owner 直接
     补绑即可受闸保护，**不必撤销 + 重注册**（决策 B 的「缓解 = owner 重注册」收窄为
     「owner 补绑」，预算不重置）。
- **不可改绑保留**（§6.17.4）：无任何改绑路径。事后**首绑**一张已被其他账本 fail-open
  服务过的委托，其补绑前的在途意图仍是他分片账本上的既成消费——这是存量 fail-open
  残余的窄化（窗口从「委托整个剩余有效期」缩到「补绑前」），不是消灭；补绑前的双花
  面与未绑定态等价，P2-3 的跨分片 kind 对补绑前的消费同样不成立。改绑（换运营者）
  的迁移路径仍是 owner 撤销旧委托 + 注册新委托 + 绑定。
- **`operator == address(0)` 构造性禁止**：读协议以零地址表示「未绑定」，绑定为零地址
  会制造「已绑定却读作未绑定」的谎言面（闸 fail-open 放行语义被伪造）。`ZeroOperator`
  revert。
- 读面：`operatorOf(dh) → address`（零地址 = 未绑定，fail-open 语义的链上事实源）。
  事件 `OperatorBound(dh, owner, operator)` 供监听方增量建表。

#### 6.19.2 聚合器摄取绑定闸（定夺记录在案）

- **事实源与策略分离**：`aggregator/src/binding.rs` 的 `OperatorBinding` trait 只回答
  链上事实「`operatorOf(dh)` 读数」（`Some` = 已绑定 / `None` = 未绑定，读失败 = Err）；
  策略（未绑定放行 / 绑他人拒绝 / 读失败 fail-closed）集中在聚合器侧 `BindingGate`，
  测试一次锚定，不随实现形态漂移。
- **三态判定（唯一策略点）**：
  - 未绑定（`None`）→ 放行（决策 B fail-open，有意取舍：fail-closed = 闸上线当天冻结
    全部存量委托）；
  - 绑定到其他运营者 → `E_OPERATOR` 拒；
  - **绑定读面不可得 → `E_BIND_BACKEND` 拒（fail-closed）**——看不到绑定面不等于绑定
    不存在，与 §6.13 `E_VERIFY_BACKEND`「绝不静默降级」同一纪律。传输错误**不进缓存**
    （瞬态），下一笔重试读。
- **不可变绑定读缓存**：绑定一经写入永不改变（6.19.1 无改绑路径）⇒ 读数可永久缓存
  （`Mutex<HashMap<dh, Option<operator>>>`），每委托只付一次 RPC 冷读，热路径 =
  一次哈希查找（与「绑定面上线后摄取面每笔多一次链上 RPC」的吞吐灾难划清界限；
  B8 内核 `try_commit` 零改动）。缓存是**进程内**的：重启后冷缓存，首笔重读——
  链上事实源不持久化进 WAL（WAL 冻结面纪律，§6.17.3）。
- **管线位置 = 步 4b（验签后、验证明前）**：绑定冷读是一次网络往返，放在 Ed25519
  快路径验签**之后**，未认证流量不得触发 RPC 读（DoS 放大面收口）；放在验证器之前，
  被拒不付真验证成本。被拒不耗 nonce / 窗口槽（与步 2b / 6b 同口径），同意图重发
  不撞幂等闸缓存的原拒绝（reject 不入 nonce 记录）。
- **闸的装配是显式的**：`Aggregator::with_operator_binding(source, self_operator)`
  builder——不装配 = 无闸（缺省口径逐字节不变，占位 / 单运营者形态零改动）；
  `self_operator` 是本账本运营者地址（20B），装配方（bin / 演练）负责与链上身份一致。
  测试替身 = `StaticBinding`（进程内映射，无网络）。

#### 6.19.3 网关装配面（JSON-RPC 读实现）

- `gateway/src/binding.rs`：std-only JSON-RPC `eth_call` 客户端（TcpStream 单次 HTTP/1.1，
  S-59 fanout 客户端同款形态；serde_json 编解码），读 `DSA.operatorOf(bytes32)`——
  calldata = `selector + 32B dh`，返回 32B ABI 编码取低 20B。RPC error / 短返回 /
  非 32B 返回一律 Err（fail-closed 上抛成 `E_BIND_BACKEND`）。
- bin 装配 fail-fast：`MIST_RPC_URL` + `MIST_DSA_ADDRESS` +
  `MIST_SELF_OPERATOR` **三者同给同不给**——只给其一启动即退（半装配 = 闸语义
  不明的静默降级面）。url 只收 `http://host:port`（std-only 无 TLS，§6.7 口径）；
  地址收 `0x` + 20B hex。启动日志 `operator binding: on(<addr>)|off`。
- **诚实边界**：绑定的实时性 = RPC 节点的事实（读的是最新已确认状态，无最终性/
  重组防护）——绑定面是授权期一次性写入且不可改，重组窗口内读到未确认值的最坏
  影响是闸的判定落后一笔，不构成放行已绑定他方的持续路径（缓存固化的是错值时，
  该委托属配置攻击面 = owner 私钥面，非协议面）。

#### 6.19.4 工件与测试

- `contracts/src/DSA.sol`：`operators` 映射 + `bindOperator` + `operatorOf` + 事件
  （+4 error / 1 event）；forge 用例：绑定成功 + 事件、四类 revert（未注册 / 非 owner /
  重绑 / 零地址）、`operatorOf` 读数、不可改绑（绑定后无路径变更）。
- `aggregator/src/binding.rs`：trait + `BindingGate`（缓存 + 三态）+ `StaticBinding`
  替身，单测：三态各一、读失败 fail-closed 且不进缓存、缓存命中后源端故障不再读
  （不可变语义）、被拒不耗 nonce（同意图重发同码）。
- `gateway/src/binding.rs` + bin 装配 + 本地 fake JSON-RPC socket e2e（绑他人拒 /
  未绑定放行 / RPC 不可得 `E_BIND_BACKEND`）。
- core `error.rs` 两新码 `E_OPERATOR` / `E_BIND_BACKEND`（§11 表同步；wire roundtrip
  全枚举镜像测试补齐）。

#### 6.19.5 诚实边界

- **绑定合谋不在防御内**（决策 B 原文保留）：绑定由 owner 写 ⇒ owner 故意绑错分片
  （或与运营者合谋）是 §10 授权滥用面，靠 Sybil/声誉（决策 E、L4）缓解，本闸不防。
- **存量 fail-open 是有意取舍**：未绑定委托不受闸约束（决策 B）；补绑收窄但不消灭
  （6.19.1）。跨分片双花的密码学封堵 = P2-3 事后 kind——朴素形态已被 §6.20.1 定夺为
  不可健全实现（接受时刻墙），健全形态（acceptanceRoot 接受锚 + kind4）**已落地**
  （S-66，§6.23）。
- 闸只挡「绑他人」，不验证「绑的就是我声称的运营者」之外的事实——运营者身份与
  BatchSettler 实例的一致性是部署面职责（P2-4 OperatorRegistry 前以配置纪律承担）。
- **`E_BIND_BACKEND` 的重试面在调用方**：SDK 业务拒绝不自动重试（仅 `E_REV_ROOT` 触发
  witness 刷新重出）——但被本闸拒的意图 nonce 未消耗、幂等闸不缓存业务拒绝，同意图
  原样重发是安全的（读面恢复后即过闸）；运维按 ops.md §1 的 RPC 可用性清单部署。

### 6.20 P2-3 欺诈 kind 开工定夺——接受时刻墙与接受锚设计（设计轮，2026-08-31，S-63）

**定位**：§6.17 决策 B/F 的实施砖（P2-3）开工定夺。**本节是设计定夺，不是实现声明**——
在定夺前 P2-3 的两个事后 kind（「跨分片消费」「过时撤销根/已撤销消费」）不写一行合约码。
本轮产出是一份**否定性前置结论**（朴素形态不可实现）+ 一份健全化设计（接受锚），以及
由此的砖单重排。

> **方案确认（老板，2026-08-31）**：§6.20.2 接受锚健全化方案（acceptanceRoot 平行承诺
> 树 + kind3/kind4 时间守卫，含 §6.20.1 抽债券向量的链上封堵口径）已过目拍板（"可以"），
> P2-3 依 §6.23 实施落地。

#### 6.20.1 朴素形态不可实现：接受时刻墙（设计发现，推翻决策 B 的可实现性假设）

- **朴素形态**（决策 B 原文的链上条件）：`inclusion(ip) ∧ 事件时刻 ≤ commit 时刻 ∧
  事件指向他方`（kind4 绑定读数 ≠ 本合约 operator；kind3 撤销读数 = true）。决策 B 称
  其「与漏单/低付同款 sound + 有界」——**该断言不成立**。
- **墙本体**：两个 kind 的可罚本体都是「**意图在被撤销/被绑定之后被接受**」，而链上
  承诺面只断言「意图在承诺根里」，不断言「意图何时被接受」——事件（撤销/绑定）与
  接受这两个时刻的先后在链上不可分辨。`intent_hash` 原像（core/src/dsa.rs，140B）与
  承诺叶（`Merkle.leaf(seq, ih)`）都不携带接受时刻；`IntentProof` 同样没有。
- **假阳性案例（不可免）**：意图在事件前被合法接受——未绑定态 fail-open 放行（§6.19.2
  有意取舍）/ 未撤销时接受（Contract 模式摄取面 `isRevoked` 快查通过，S-10）——事件
  发生在接受之后、commit 之前，朴素条件全满足 → 诚实运营者债券被罚没。
- **这不是理论缝，是活的抽债券向量**：owner（或与其合谋者）先在 A 账本未绑定态消费，
  再行使 owner 权利把委托绑到 B（`bindOperator` 是 owner 私钥许可面，§6.19.1），随后
  任何人可对 A 的已 commit epoch 提交朴素跨分片证明 → A 债券被判给挑战者。「事后
  kind」在朴素形态下从防御面退化为**对诚实运营者的抽债券机器**——比没有 kind 更糟。
- **kind3 同一堵墙且多一层矛盾**：事件（撤销）前接受的意图被承诺/结算是**应然**行为
  （接受时未撤销 = 有效意图，用户已付费，结算应付）——若按朴素条件把它列为欺诈，运营者
  面临「结算 = 被罚 / 排除 = 用户损失」的双输义务；义务自相矛盾本身就证明朴素条件
  不可能是欺诈条件。
- **被否决的健全化路线（记录在案）**：
  1. 把接受时刻塞进 `intent_hash` / 承诺叶原像 → 炸穿 S-34/S-36 撤销索引、SDK 签名语义、
     电路公共输入、差分 fuzz（S-57）全部锚点——决策 B 自己的硬约束（§6.17.2）；
  2. commit 声明「承诺滞后上界 L」推断接受下界（`事件时刻 + margin + L ≤ committedAt`
     ⇒ 全部在案意图接受于事件后）→ L 的执行在账本侧、挑战者不可见：不执行 L 的诚实
     运营者被旧意图假阳性咬中，前提失效即假阳性回归；
  3. 每 epoch 声明「已处理撤销游标」并把「游标落后于链上撤销」定为欺诈 → 惩罚对象是
     观察滞后本身而非「已撤销仍接受」，无撤销消费也照罚 = griefing 机器（且与 §6.20.2
     之前的链上无 per-意图状态锚同病）。

#### 6.20.2 健全化设计：接受锚（acceptanceRoot，平行承诺树）

**采纳路线：给「接受时刻」补一个链上可验证的承诺面——新平行树，不动既有哈希/叶原像。**

- **账本面**：`acceptedAt` = 聚合器**自派时钟**（`now_fn`）的接受时刻——WAL Intent 记录
  116B payload **已含 now 字段**（S-61 口径），恢复侧零格式改动即可重建；内存面
  `WindowEntry` / 意图索引各增 8B。不引客户端时钟（无客户端偏差可谈，margin 只需覆盖
  运营者自身观察/RPC 读滞后）。
- **承诺面**：`acceptanceRoot` = 与承诺树**同叶集同序**（seq 序、`lattice::build_epoch`
  的确定性重排输入同源）的第二棵 Merkle 树，叶 = `sha256("ACCV1\0" ‖ seq_le(8) ‖
  acceptedAt_le(8))`。复用 `Merkle.leaf/computeRoot`（零新密码学，S-57 差分闸可挂第三
  契约）；与撤销根同款「单独锚定不并入承诺树」（不破坏承诺叶索引，S-11 决策）。
- **合约面**：`Epoch` 增 `acceptanceRoot` + `committedAt`；`IntentProof` 增 `acceptedAt`
  + `acceptanceSiblings`（两树同叶序 ⇒ 同 `leafIndex`/`acceptedCount`/同深度）。链上
  事件面补时刻：`DSA.boundAt`（绑定时刻，一次性写）、`RevocationRegistry.revokedAt`
  （撤销时刻，一次性写）——撤销/绑定均单向不可变（§6.19.1 / RevocationRegistry 无
  解除路径），时刻随之不可变。
- **守卫（margin = 协议常量 `ACCEPT_MARGIN`，覆盖运营者 RPC 读陈旧 / 撤销观察滞后）**：
  - kind3（已撤销消费）：`inclusion ∧ acceptanceInclusion ∧
    revokedAt(dh) + margin ≤ acceptedAt`（单意图，kind1 同款 `BadFraudKind` 计数闸）；
  - kind4（跨分片消费）：`inclusion ∧ acceptanceInclusion ∧
    boundAt(dh) + margin ≤ acceptedAt ∧ operatorOf(dh) ∉ {address(0), self}`
    （零地址 = 未绑定 = fail-open，kind 不成立，与 §6.19.2 三态同口径）。
- **健全性（相对诚实运营者）**：诚实运营者的接受树如实记录 ⇒ 事件前接受的意图
  `acceptedAt < 事件时刻` → 挑战必败，§6.20.1 假阳性案例**归零**。可罚语义 = 「接受时刻
  已过事件时刻 + margin 仍接受」——Contract 模式摄取面已有 `isRevoked` 快查（S-10）、
  P2-2 起有绑定闸（§6.19），该接受只能来自观察面失灵/绕过，正是债券要保的诚实性。
  两 kind 的出证骨架与 kind1/2 共享（包含验证 + 押金入场/驳回即没收语义零改动）。

#### 6.20.3 诚实边界（定夺级）

- **接受树是运营者自证事实**：`acceptedAt` 由运营者构造，故意回填可逃逸两 kind——与
  §6.17.4「绑定合谋不在防御内」同层：对抗**故意**造假超出乐观挑战模型。本设计把
  「过失」（监听滞后/闸失配/绕过）变为可证（这些恰是债券机制的目标行为），把「故意」
  留在治理/声誉面（决策 E、L4）。
- 链上可得的接受下界锚只有 `registerAt(dh) ≤ acceptedAt`（委托先注册）与跨 epoch 有序窗
  （epoch k 的接受 ∈ (sealAt_{k-1}, sealAt_k]，需 commit 增发 `sealedAt` 且上限
  `sealedAt_k ≤ committedAt` 可由块时间戳核对）——都堵不死回填，只收窄伪造空间；
  落地时作为**廉价一致性检查**顺带上，**不作为健全性依据**。
- margin 是公平性/威慑旋钮：太小 → RPC 陈旧期的正常接受被罚（假阳性回归）；太大 →
  过失免罚窗口变宽。缺省值在实现砖开工时按观测滞后实测定夺并记录在案。
- **规模重估：P2-3「中」→「大」**（账本内存/恢复 + 新树 + commit ABI + 合约四面 +
  fraud.rs 出证 + 演练两幕 + 差分叶锚 + audit-scope §1/§4/§5 重对齐）。**定夺：做，
  次序调到 P2-4 之后**——P2-4（OperatorRegistry）无此墙、可独立落地；P2-4/P2-5 完成
  后本节即接受锚砖的唯一事实源。

#### 6.20.4 决策 F「过时撤销根」定夺（落笔）

**做**（决策 F 倾向确认），但**仅在接受锚落地之后**——朴素形态（§6.20.1 kind3）不可
健全实现，且「只承诺正确的撤销根、不承诺 per-意图接受状态」的中间形态（§6.20.1 否决
路线 3）是 griefing 机器。§6.18.5 的「验证者可复算撤销根并比对，链上无对应 kind」挂账
**已收口**（S-66 接受锚砖落地，kind3/4 上线，§6.23）；验证者侧撤销根比对的**发现/告警**
价值（信号①同款，不上链）不受本定夺影响。
- 读面无最终性保障（6.19.3）；缓存进程内不持久化（重启冷读，可用性自伤方向安全）。

### 6.21 P2-4 OperatorRegistry：append-only 金额调度 + 运营者名册（实施，2026-08-31）

**定位**：§6.17 决策 D 的实施砖——新合约 `OperatorRegistry`（`contracts/src/OperatorRegistry.sol`）
持有 append-only 的债券/押金金额调度与运营者名册，并为多运营者多实例部署提供流程与发现面。
**BatchSettler 逐字节不动**（冻结面纪律 + S-50 构造语义已锚定），本砖是纯增量合约。

#### 6.21.1 定夺记录（先改后码）

1. **「新实例读取当刻值固化」的读取点在部署流程，不在构造器内部。** 让 `BatchSettler`
   构造器收注册表地址并读数，会把注册表写入者抬升为全部未来实例金额的链上决定者，并把
   注册表地址焊进已冻结的构造 ABI（S-50 口径级联）。定夺：部署流程（`deploy.rs` /
   §6.21.3 演练）读 `currentSchedule()` 后作为构造参数直传 + 部署后回读
   `challengeBond()` 交叉核对（S-50「单一事实源在链上」同口径）——固化结果等价
   （immutable、逐部署一版），冻结面零触碰。
2. **调度写入者 = `registrar`（immutable，部署 OperatorRegistry 的主体）。** 决策 D 的
   信任面论证在此层收窄为：registrar **触不到任何在役实例的判定面**（调度只被未来部署
   读取，存量实例各持其部署版本），每次追加即事件 + 数组追加、无改写/删除路径、全史
   链上可审计。这与 S-50 否决的运行时 setter 性质不同：setter 直接改写判定面金额。
3. **调度条目只增不改、追加即生效。** `ScheduleEntry{bond, challengeBond, writtenAt}`
   追加后即成为「之后的部署」读取的当刻值（无预约生效窗口——生效时刻 = 追加交易时刻，
   诚实边界见 §6.21.4）。`bond == 0` 或 `challengeBond == 0` 构造性拒绝
   （`ZeroScheduleAmount`）：零债券 = 挑战赔付归零 = 乐观安全归零；零押金 = 复活垃圾
   挑战面（S-50 `ZeroChallengeBond` 同语义，防未来部署直接撞构造 revert）。
4. **名册写入形态 = self-registration 绑定实证。** `registerOperator(settler)` 的调用者
   必须是 `BatchSettler(settler).operator()` 本尊（链上读 immutable getter；无代码 /
   不匹配即 revert）。名册条目因此不可伪造：注册一条 = 声明对链上一个真实存在的
   BatchSettler 实例的 operator 归属，任何人可独立复核。写入面**无需 registrar 权限**
   （registrar 也无法替别人注册）——注册是 permissionless-but-provable。
5. **注册时快照固化值。** 条目 `OperatorEntry{operator, settler, asset, challengeBond,
   registeredAt}` 的后三者从实例 immutable getter 现场读出 = 决策 D「存量实例各持其
   部署版本的值」的链上事实源，可与调度历史交叉核对（该实例部署时点的当刻调度值）。
   同一运营者可注册多个实例（决策 D 的换金额路径 = 重部署 + 新实例注册），流水
   append-only，无移除/停用路径。
6. **记录面不是强制面。** 运营者完全可以不经注册表部署 BatchSettler、或部署偏离当刻
   调度的金额（BatchSettler 构造参数仍直传，本砖不加任何强制钩子）。注册表的价值 =
   ①金额决策的链上全史（可审计）；②实例固化值的公开台账（选型/验证者/monitor 读面，
   P2-5 输入）；③多实例部署流程的锚。偏离与跳过经快照/缺席公开可见，不密码学阻止。

#### 6.21.2 合约接口（OperatorRegistry.sol）

- **读面**：`registrar`、`schedule(uint256)` / `scheduleCount()`、`currentSchedule()`
  （空调度 revert `ScheduleEmpty`——部署流程不该在无调度时部署）、`operators(uint256)` /
  `operatorCount()`、`isSettlerListed(settler)`、`settlerCount(operator)`。
- **写面**：`appendSchedule(bond, challengeBond)`（仅 registrar，追加 + 事件）；
  `registerOperator(settler)`（permissionless，绑定实证 + 快照 + 事件）。
- **错误**：`ZeroRegistrar` / `NotRegistrar` / `ZeroScheduleAmount` / `ScheduleEmpty` /
  `SettlerAlreadyListed(settler)` / `NotSettlerOperator(settler, expected, actual)`。
- 本合约不持有资金、不做任何外部调用写状态（`registerOperator` 只对 settler 做只读
  staticcall 取 getter）——零重入面，覆盖门禁下无豁免边。

#### 6.21.3 多实例部署流程（deploy.rs + registry_flow 演练）

- **部署顺序**（构造参数依赖链）：DSA(无参) → RevocationRegistry(DSA) →
  OperatorRegistry(registrar = operator) → `appendSchedule`（初始调度，金额取
  `MIST_BOND` / `MIST_CHALLENGE_BOND`，缺省 1 ETH / 0.1 ETH）→
  BatchSettler(operator, asset, challengeBond ← `currentSchedule()` 读数) →
  `registerOperator(settler)`。
- **顺带修复 deploy.rs 潜伏缺陷**：S-50 把 BatchSettler 构造改为三参后，`deploy.rs` 仍传
  两参——verify 步 10 只做编译门禁（S-15a），运行时部署必然 revert。本砖接线时修复，
  并把部署后回读 `challengeBond()` 与调度读数交叉核对。
- **`registry_flow.rs` anvil 演练**（verify 步 10 接线）：v1 调度 → settler1（读 v1）→
  注册 → v2 调度 → settler2（读 v2）→ 注册 → 断言（调度历史 2 条且 entry0 不变 /
  两实例冻结值各自不同 / 重复注册拒 / 非 operator 注册拒 / v1 实例 `challengeBond()`
  不受 v2 影响）——决策 D「动态性来自调度 + 重部署，不来自 setter」的全链实证。

#### 6.21.4 诚实边界

- **registrar 写面是部署授权方信任面**：可追加任意金额（含 1 wei 债券——金额无下限，
  下限本身是又一个不可调常量）。缓解不是密码学而是可见性：全史可审计 + 部署读数公开 +
  名册快照把每个实例实际固化的值公开。registrar 抬价/降额影响的是「未来部署的起点值」，
  决策 D 的 governor 论证（抬价 = 审查欺诈证明、降零 = 复活垃圾挑战）在此层同样成立，
  只是作用域从「全部在役实例」收窄为「后续部署」。
- **无预约生效窗口**：追加即生效，被部署读数窗口夹住的调度变更 = 部署方读到旧值（事后
  可由 writtenAt 与部署交易时刻对账发现，不可阻止）。
- **名册不验证字节码型号**：只验证 `operator()` 归属 + 快照 getter 读数。一个自制的
  「假 settler」只要 `operator()` 返回调用者也能注册——但决策 E 的声誉面从 BatchSettler
  **事件**（罚没/voided）派生而不读名册，刷名册无收益；快照读数本身仍是该地址的公开事实。
- **名册无移除/停用**：退役运营者条目永留。声誉面不读名册状态（决策 E），不产生
  「停用即洗白」面；条目时间戳与后续事件缺失即事实上的退役信号。
- **部署面不强制**（定夺 6）：跳过注册表 / 偏离调度的部署不被阻止，只被公开。

#### 6.21.5 测试与门禁

- forge `OperatorRegistry.t.sol`：调度正/负向（零 registrar / 非 registrar / 两种零金额
  分支 / 空调度读数 / 追加历史不可变）+ 名册正/负向（成功快照回读 / 非 operator /
  EOA settler / 重复 settler / 同 operator 多实例）+ 决策 D 全链流（v1 → 实例1 →
  v2 → 实例2，两实例冻结值各持其部署版本）。
- `registry_flow.rs` 进 verify 步 10；coverage 门禁下新合约行/函数/分支 100%（无豁免边）；
  audit-scope §1 文件清单 + §5 计数、contracts/README 计数同步重对齐（§6.17.3 次序约束）。

### 6.22 P2-5 声誉派生 monitor 面（实施，2026-08-31）

**定位**：§6.17 决策 E 的实施砖——链上罚没历史的只读派生指标，落在 monitor 的 Prometheus
导出面。**零合约改动**（BatchSettler / DSA / OperatorRegistry 逐字节不动，不触碰审计冻结面
§6.17.3），聚合器 / 网关判定面零改动（决策 E：声誉不进任何判定路径——本节全部产出都是
`/metrics` 序列，消费方只有人与告警器）。

#### 6.22.1 定夺记录（先改后码）

1. **信源 = BatchSettler 事件 + 合约余额，不读名册。** 事件从 JSON-RPC `eth_getLogs`
   （`address = settler`，`fromBlock: 0x0` → `latest`）取四类：`Commit` / `Settled` /
   `ChallengeSucceeded` / `Claimed`；余额走 `eth_getBalance(settler, "latest")`。
   **不读 OperatorRegistry**（§6.21.4 锚：声誉面从事件派生而不读名册，刷名册无收益）。
2. **在押债券不走「事件差」。** voided epoch 的债券金额不在任何事件里
   （`ChallengeSucceeded` 只带 epochId/challenger/kind），`Σcommit − Σclaimed − Σvoided_bond`
   的第三项不可得，事件差是**结构性高估**——不做。合同余额是链上事实，暴露
   `mist_operator_contract_balance_wei`，help 注明构成（在押债券 + 未领取结算资金 +
   未领取挑战者押金退款 / 结算留存），不做「净债券」的假装精确。事件侧同时暴露
   `bond_committed_wei`（Σ `Commit.bondedAmount`，债券承诺累计上界）与
   `bond_claimed_wei`（Σ `Claimed.amount`，运营者已领取额）两个互补口径。
3. **罚没计数口径。** `slash_total` = `ChallengeSucceeded` 事件数（= voided epoch 数 =
   罚没次数），按 kind 分解 `slash_kind_total{kind}`（kind 值 = 合约 `uint8` 十进制）。
   `ChallengeRejected`（押金销毁）**不是罚没**，不产声誉指标——押金方向与运营者无关。
4. **缺省口径逐字节不变。** 不带 `--settler` / `--rpc` 时声誉序列**完全不出现**——不产
   零值序列（「无数据」≠「零罚没」，零值序列会被刮取告警误读成清白证明）。两参同给同不给，
   半装配启动即退（§6.19.3 同款）。单实例单 settler：分片模型无全局账本视图，monitor 只能
   按运营者分别聚合（§6.17.4），多运营者 = 多 monitor 实例。
5. **读失败 fail-visible，绝不清零。** 抓取 Err → `mist_operator_chain_read_ok 0`，
   保留上一次成功快照继续渲染（把指标清零会被误读为「罚没归零」= 洗白方向的假信号）；
   从未成功过 → 只渲染 `chain_read_ok 0`，无其他声誉序列。链上读面失败**不**拉低
   `/healthz`（healthz 是账本健康面 §6.12；两者告警分离，ops.md 告警表单列一行）。
6. **事件解码失败 fail-closed。** topic0 命中四类之一但字段解不出（data 字数不足等）→
   整次抓取 Err（按定夺 5 保留旧快照 + read_ok 0）。**丢一条 `ChallengeSucceeded` =
   罚没被抹掉一行，是洗白方向**，绝不静默跳过；未知 topic0（`RefundWithdrawn` /
   `ChallengeRejected` 等非声誉事件）跳过。
7. **监控面不进判定面**（决策 E 落地形态）：monitor 无任何合约写调用、无判定消费方；
   指标用途限于展示与告警。

#### 6.22.2 指标面（label：`settler` = 0x 40 hex 合约地址）

| 指标 | 来源 | 说明 |
|---|---|---|
| `mist_operator_epochs_committed_total` | `Commit` 事件计数 | 已提交 epoch 数（含后被 voided 的） |
| `mist_operator_epochs_settled_total` | `Settled` 事件计数 | 已结算 epoch 数 |
| `mist_operator_slash_total` | `ChallengeSucceeded` 计数 | 罚没次数（= voided epoch 数） |
| `mist_operator_slash_kind_total{kind}` | `ChallengeSucceeded` 按 kind | 罚没 kind 分解 |
| `mist_operator_bond_committed_wei` | Σ `Commit.bondedAmount` | 债券承诺累计（在押上界） |
| `mist_operator_bond_claimed_wei` | Σ `Claimed.amount` | 运营者已领取额 |
| `mist_operator_contract_balance_wei` | `eth_getBalance` | 合约余额（构成见定夺 2） |
| `mist_operator_chain_read_ok` | 抓取健康 | 1 = 本轮抓取成功 / 0 = 失败（保留旧值） |

全部 gauge（crate 既有口径：计数语义由刮取器按增量处理，不加 counter 语义误导）。
wei 值经 f64 渲染，> 2^53 按浮点舍入（help 注明）。

#### 6.22.3 实现面

- `monitor/src/rpc.rs`：std-only JSON-RPC 客户端（TcpStream 单次 HTTP/1.1 往返，
  `Connection: close`，url 只收 `http://host:port`——§6.19.3 网关绑定读同款形态与同款
  坑位教训：读失败一律 Err 上抛，绝不吞成空结果）。
- `monitor/src/reputation.rs`：log 解码（topics/data → 事件）+ 快照累计 + Prometheus 渲染
  + `fetch_reputation`（getLogs + getBalance 两调用，任一失败整轮 Err）。
- `monitor/src/bin/main.rs`：`--settler <0x40hex> --rpc <url>` 装配 `ReputationReporter`
  包裹既有 Reporter（单/多副本两种模式都追加声誉序列；health 原样透传）。
- topic0 常量 = keccak256(事件签名)，sha3 crate（workspace 既有）现算 + 测试钉字面量
  （`cast keccak` 独立锚，§6.19.3 selector 锚定同纪律）。

#### 6.22.4 真 anvil 锚（verifier_drill 幕 4）

P2-1 演练（§6.18）三幕已产出真实链上事件（3 commit / 3 settle / kind1+kind2 两次罚没），
追加**幕 4 = 声誉面核对**：monitor `fetch_reputation` 对同一 settler 抓取，断言
`epochs_committed=3`、`epochs_settled=3`、`slash_total=2`、kind 分解 `{1:1, 2:1}`、
`bond_committed=3×challengeBond`、`chain_read_ok=1`，合同余额 ∈ [0, 3×challengeBond]。
事件解码路径的链上真实性由幕 2/3 的真实罚没交易保证——fake-RPC 单测只证解码 / 渲染 /
装配 / fail-visible 逻辑，不证链上事件形状。

#### 6.22.5 诚实边界

- **全历史扫描**：每次刮取从 `fromBlock: 0x0` 重扫，O(全史事件数)——本砖不做增量游标 /
  区间缓存（量级待生产数据，记为后续面）。
- **reorg**：`latest` 视图读数，重组会改写历史事件集；monitor 不做确认策略，计数按最新
  视图重建（不保证单调）。本地 anvil 无 reorg；生产刮取间隔远小于重组深度时窗口极小，
  记录在案。
- **合同余额 ≠ 净债券**（定夺 2）：含未领取结算资金与退款留存，三个金额指标互补阅读，
  不产单值「净债券」。
- **f64 渲染精度**：wei > 2^53 按浮点舍入（Prometheus 文本格式约束）。
- **声誉无抗 Sybil 语义**（决策 E 只读派生不改这一点，L4 覆盖）；罚没次数 ≠ 罚没金额。
- **监控面是事实面不是审计面**：合约判定、监控告警均不消费声誉做决策（决策 E）；
  多运营者全局视图不存在（§6.17.4）。

### 6.23 P2-3 接受锚实施（账本 acceptanceRoot + kind3/kind4，2026-08-31，S-66）

**定位**：§6.20.2 健全化设计的实施砖（§6.20 本节为唯一设计事实源）——给「接受时刻」补
链上可验证的承诺面（平行接受树 acceptanceRoot），使「已撤销消费」（kind3）/「跨分片消费」
（kind4）两个事后欺诈 kind 在不伤诚实运营者的前提下可证。本节记录实施定夺（先改后码），
与 §6.20.2 的偏差逐条给出理由。

#### 6.23.1 定夺记录（先改后码）

1. **WAL Intent payload 116B → 124B（更正 §6.20.2「恢复侧零格式改动」的前提）**。
   设计原文假设 WAL Intent 记录的 now 字段即 acceptedAt——查证为假：该字段存的是证明
   公共输入 `pi.now`（**客户端时刻**，`check_public_inputs_consistent` 不校验它，S-10 口径），
   且对预算重放承载语义（`try_commit` 消费它，S-10c「恢复后账本与 accepted 前缀一致」）。
   复用它作 acceptedAt 要么 (a) 把客户端时钟引入接受锚——客户端把 `now` 填到未来即可把
   「事件后接受」伪装成「事件前接受」，接受锚的牙被拔掉，还制造新的对诚实运营者的假阳性
   向量（正是 §6.20.1 要消灭的那类）；要么 (b) 改语义破坏恢复精度。定夺：**payload 追加
   8B `accepted_at` 尾字段（116 → 124），双长度重放**（len 116 = 旧格式 → `accepted_at = 0`
   未知哨兵；len 124 = 新格式），`VERSION` 保持 1（长度自描述，无需版本位）。哨兵语义：
   `事件时刻 + margin ≤ 0` 恒假 ⇒ 守卫永不成立——不安全方向是「不可罚」（不可出证），
   绝不产生假阳性。诚实边界：旧格式 WAL 恢复的尾部 epoch 接受锚无牙（kind3/4 不可出证，
   检出率损失非正确性损失）。
2. **acceptedAt = 摄取入口的 `now_fn()` 快照（B8 口径：零新增热路径时钟读）**。
   `submit_inner` 入口已有 `let now = (self.now_fn)();`（预算窗回滚用）——接受时刻复用同一
   快照，不二次取钟。invariant `acceptedAt ≤ sealedAt` 由「本 epoch 最后一条接受条的
   accepted_at == 传给 `maybe_rotate` 的 now」构造性成立（密封只能发生在最后一次接受之后）。
   内存面 `WindowEntry` +8B；**意图索引（`IntentRef`）不增**——实施查证其无消费方（净额
   解析用 recipient/amount、回执用 seq、恢复尾重建走 `ReplayIntent` 元组不走索引），接受锚
   的账本事实只落在 `WindowEntry` + WAL Intent，索引加字段是驻留浪费（§6.20.2 原文
   「意图索引各增 8B」按无增益收窄）。
3. **`ACCEPT_MARGIN = 300`（秒，协议常量，无 setter，Rust/合约两侧同值常量）**。本仓无生产
   遥测，按已知事实推定：S-59 撤销传播实测 = 本地同步调用 ~0s；链上事件路径 = 块时 + 轮询
   间隔（~17s 量级）。300s ≈ 2 个数量级于本地传播、~18× 于链上路径，同时 << CHALLENGE_WINDOW
   （6h）。太小 → RPC 陈旧期的正常接受被罚（假阳性回归，§6.20.3）；太大 → 过失免罚窗口变宽。
   **诚实边界：这是推定缺省不是实测标定**——生产运行后按观测滞后重定夺需走部署新实例路径
   （合约 immutable）。
4. **廉价一致性检查收窄：`registerAt` 锚被事件下界蕴含，不单独实现**。§6.20.3 给的
   `registerAt(dh) ≤ acceptedAt` 在两 kind 守卫下是冗余：`bindOperator` / `revoke` 均要求
   委托已注册（DSA / RevocationRegistry 的 `NotRegistered` 守卫）⇒ 守卫成立时
   `registerAt ≤ 事件时刻 ≤ 事件时刻 + margin ≤ acceptedAt`。下界锚已蕴含注册锚，新增
   映射（+8B/dh）无增益——**DSA 只增 `boundAt`**。
5. **`sealedAt` = 声明面（观测），不进判定面**。`commit` 增发 `sealedAt`（运营者声明的密封
   时刻）+ 链上写 `committedAt = block.timestamp`。§6.20.3 的跨 epoch 有序窗
   （epoch k 的接受 ∈ (sealAt_{k-1}, sealAt_k]）与 `sealedAt ≤ committedAt` 的核对在**观测面**
   （验证者 / monitor 离线比对）做，不进合约判定：判定面若 require `sealedAt ≤ block.timestamp`，
   自派时钟超前链钟 δ 的诚实运营者在密封后立即 commit 即 revert（可用性陷阱），而它对回填
   逃逸方向无约束力（逃逸者要的是把 acceptedAt 改**小**，上界锚管不着）。判定面只消费
   §6.20.2 的健全守卫 + 两树包含验证；声明面事实供观测核对（决策 E 同口径：声明面不进判定）。
6. **ABI 扩展形态**：`Epoch` 增 `acceptanceRoot` / `sealedAt` / `committedAt`；`IntentProof` 增
   `acceptedAt`(uint64) + `acceptanceSiblings`(bytes32[])（两树同叶序 ⇒ 同 `leafIndex` /
   `acceptedCount` / 同深度）；`commit(epochId, commitmentRoot, revocationRoot, acceptanceRoot,
   sealedAt)`；`Commit` 事件增 `acceptanceRoot` + `sealedAt`——**`monitor/src/reputation.rs`
   的 topic0 常量与 `bondedAmount` 数据偏移同步**（签名变 keccak 变；data 内偏移
   `[64..96] → [96..128]`，锚定测试字面量重算）。
7. **BatchSettler 构造器增两 immutable 地址（§6.20.2 未言明，守卫读面的必然要求）**。
   kind4 需读 `DSA.boundAt/operatorOf`、kind3 需读 `RevocationRegistry.revokedAt`——事件时刻
   锚在别的合约里，BatchSettler 必须持地址。`constructor(operator_, asset_, challengeBond_,
   dsa_, revocations_)`：零地址拒（`ZeroAnchor`——缺依赖 = kind3/4 守卫静默失效面伪装），
   构造期交叉核对 `revocations.dsa() == dsa_`（`DsaMismatch`——注册表自身也指向 DSA，两指针
   失配 = 部署配置错误，构造期暴露）。
8. **无新 RejectReason / 错误码**：接受包含失败 → `BadInclusionProof`；时间守卫不成立 /
   未撤销（revokedAt = 0）/ 未绑定（operatorOf = 0）/ 绑到本合约 operator → `NotFraud`；
   意图数 ≠ 1 → `BadFraudKind`（两 kind 均单意图，kind1 同款计数闸）。§11 表与 §6.5
   RejectReason 语义零改动。
9. **fraud.rs 出证面**：新 trait `EventAnchors`（`revoked_at` / `bound_at` / `operator_of` /
   `self_operator`；`None` = 事件未发生 / 未绑定，链上零地址归一同 §6.19.2 口径）——
   fraud.rs 保持纯函数（无 alloy 依赖，链 I/O 在演练 bin，§6.18 口径）；检测信号
   ⑥（已撤销消费）/ ⑦（跨分片消费）+ kind3/kind4 候选（单意图、每 dh 取最低 seq 的确定性、
   `checked_add` 防时刻溢出）；kind3/4 候选的出证闸在承诺根闸之上**追加接受根闸**（镜像重算
   `acceptanceRoot` == 链上 `acceptanceRoot`——缺镜像 = 检出率损失不是假证，同 §6.18.3）。
   kind1/kind2 证据携带接受面字段但合约对其不校验（向后兼容的证据形状）。
10. **演练锚（verifier_drill 幕 5/6）**：错账注入点 = **聚合器撤销观察缺席 / 绑定闸未装配**
    （不调 `agg.revoke` / 不配 binding gate）→ 已撤销 / 已他绑仍被接受 = kind3/kind4 的可罚
    本体（过失形态，§6.20.2 健全性论证的原样复现）。正向：出证 → challenge → 罚没；负向：
    事件前接受 → 手工构造的朴素 kind3/kind4 证明 → `ChallengeRejected(NotFraud)` + 押金销毁
    = **§6.20.1 抽债券向量在链上死亡的实证**。聚合器时钟与 anvil 链时对齐（margin 比较跨
    两侧钟）。
11. **差分叶锚（S-57 第三契约扩展）**：`Merkle.acceptanceLeaf(seq, acceptedAt)` ↔
    `merkle::acceptance_leaf`（前缀 `"ACCV1\0"`，22B 原像）进 `difffuzz` fixture +
    `Differential.t.sol`，与既有四契约同批差分。

#### 6.23.2 诚实边界

- **接受树是运营者自证事实**（§6.20.3 原文有效）：故意回填可逃逸两 kind——与绑定合谋同层，
  本砖把**过失**（观察滞后 / 闸失灵 / 绕过）变为可证，「故意」留治理/声誉面。
- 旧格式 WAL（116B）恢复的尾部 `accepted_at = 0`：kind3/4 不可出证（检出率损失）。
- margin 是推定缺省不是实测标定（定夺 3）；生产重定夺走重部署。
- 观测面核对（sealedAt 有序窗 / committedAt 上界）本砖只落数据面（链上字段），离线比对器
  属 monitor/验证者后续面（记录不做）。
- kind3 的可罚本体要求运营者撤销观察缺席——生产形态下 Contract 模式 `isRevoked` 快查（S-10）
  与 ZK 模式撤销根绑定闸（S-44）把缺席收窄为配置错误；债券保的正是「观察面失灵仍接受」。
- kind4 对**补绑前的在途消费不成立**（§6.19.1 存量 fail-open 残余的窄化口径不变）。

#### 6.23.3 工件与测试

- aggregator：`merkle::acceptance_leaf` / `WindowEntry.accepted_at` /
  `lattice::acceptance_root` + `EpochResult.acceptance_root` / WAL 124B 双长重放 /
  ingest 传递 / `fraud.rs` `EventAnchors` + 信号 ⑥⑦ + kind3/kind4 候选。
- contracts：`Merkle.acceptanceLeaf` / `DSA.boundAt` / `RevocationRegistry.revokedAt` /
  `BatchSettler` commit 扩展 + Epoch/IntentProof 扩展 + kind3/kind4 守卫（`_verifyFraud`
  按 kind 拆独立内部函数，先例 `_epochView` 收栈口径，判定语义逐字保持）+ 构造期两错误
  （`ZeroAnchor` / `DsaMismatch`）+ **S-66 读面拆分（§6.18.2）**。
- forge 用例（S-66 收口后 **130 全绿**，`BatchSettler.t.sol` 65 例）：commit 扩展面 /
  kind3 正负向 / kind4 正负向（含未绑定零地址、绑本合约 operator、事件后接受不罚）/
  多意图计数闸（kind1/3/4 同款）/ margin 边界（`revokedAt + margin == acceptedAt` 成立、
  −1 不成立；kind4 `boundAt + margin` 同款）/ 双树负向四例（承诺面伪造 kind3/kind4、
  接受面回填 kind3/kind4、接受路径深度错）/ 构造期 `ZeroAnchor` / `DsaMismatch` /
  旧格式哨兵不可罚。
- `verifier_drill` 幕 5/6（正负向各一）+ `difffuzz` 接受叶向量 + `Differential.t.sol`
  第五契约；覆盖门禁全绿（行/函数 100%，分支唯一豁免仍是既有 bond burn 不可达边——
  新增 kind3/4 分支零豁免，`_verifyAcceptanceInclusion` 的 leafIndex 预检按不可达边
  删除，拦截由 `_verifyInclusion` 承担）；audit-scope §1/§4/§5 与 contracts/README
  重对齐（§6.17.3 次序约束）。

### 6.24 撤销观察面（实施，2026-08-31，S-67）

**定位**：§6.17.1 挂账点 3 / 决策 F「每运营者独立链上监听是 P2 硬前置」的实施砖。
运营者网关进程内置旁路观察线程：`eth_getLogs` 刮 `RevocationRegistry.Revoked` 事件 →
解析 delegation_hash → 本账本 `Aggregator::revoke`。**零合约改动**（信源事件自 S-11
存在，`Revoked(bytes32 indexed delegationHash, address indexed by)`）——不触碰审计冻结面。
观察面把「链上撤销 → 聚合器撤销」从运营者人工传播（S-57 API / S-59 fanout 都要有人
发起）变为自动兜底，撤销生效延迟从 ∞ 收窄到 ≤ 轮询间隔 + RPC 延迟。

#### 6.24.1 定夺记录（先改后码）

1. **落点 = gateway 进程内置观察线程，不是独立 bin、不是 monitor**。消费对象是本进程
   聚合器账本（决策 F：每运营者对自己的账本负责）；gateway 已持有 `Arc<Aggregator>`、
   std-only JSON-RPC 先例（§6.19.3 binding.rs）与撤销面装配点（S-57/S-59）。独立 bin
   要么经 admin API 回环打本进程（多一跳 + admin key 配置纠缠），要么需要账本句柄
   跨进程（不存在）。monitor 是只读观测面（决策 E），给它加写路径 = 越权破「monitor
   不进判定面」口径。
2. **消费前查重：`is_revoked(dh)` 为真即跳过，不打 `revoke`**。事实：`Aggregator::revoke`
   的 WAL append 在 `fresh` 检查**之前**无条件执行——重复调用会写重复 WAL 记录；观察
   轮询是重复消费形态（定夺 3），不查重 = WAL 每轮膨胀。查重是内存 HashSet 读。竞态
   窗口（admin 并发撤销插在查重与 revoke 之间）最坏后果 = 一条重复 WAL 记录（恢复侧
   重放幂等，语义无害），不加锁。
3. **每轮全史重扫（`fromBlock: "0x0"`），不做增量游标**——与 §6.22.5 monitor 声誉面
   同款口径。增量游标有 reorg 漏读窗口（事件重排到更晚块 → 游标已过 → 永久漏，漏 =
   已撤销继续接受 = kind3 可罚本体的观察面自伤）；全史重扫 + 定夺 2 查重 = 重复消费
   天然幂等；撤销低频（人级操作）。诚实边界：O(全史) getLogs 每轮 + 生产 RPC 的区间
   上限（如 10k 块）未做分页——与 §6.22.5 同缝，两条观察面一起收后续面；v1 运行环境
   是本地/测试链。
4. **观察面不 fanout**。链上事件是全组**共同事实源**——每个副本各自观察同一事件流
   （决策 F 语义）；观察面打 S-59 fanout = 把事实经 API 面复制一遍（对端本来就会自己
   看到）。fanout 保持单一职责（API 撤销的组内加速器），观察保持单一职责（链 → 本账本）。
   三个撤销来源（S-57 admin API / S-59 对端 fanout / 本观察面）汇于同一入口
   `Aggregator::revoke`，幂等语义统一。
5. **失败语义：fail-visible 重试，不 panic 不退进程**。单轮 getLogs 失败 → stderr 一行
   + 下一轮重试；观察面挂掉不阻网关服务（admin API / fanout 撤销路径仍可达）。诚实
   边界：观察面静默失灵 = 撤销生效延迟无限延长 = kind3 可罚本体的敞口——v1 无
   观察 lag 健康指标（记录不做，monitor 侧后续面）。
6. **配置 = `Config.revocation_watch: Option<RevocationWatchConf>`**（config.json 节，
   serde default + `skip_serializing_if`——缺省 None 时序列化逐字节不变）。字段
   `rpc_url` + `registry_address`（20B hex，必填）+ `poll_interval_ms`（缺省 15000，
   显式给 0 拒——轮询间隔 0 = 打死 RPC）。不用 env：观察面是部署拓扑配置（与
   `revocation_peers` 同面）；不复用绑定闸 `MIST_RPC_URL`：绑定闸「三同给同不给」
   的半装配语义与观察面装配无关，纠缠只会制造「配了绑定忘了 watch」的静默漏配。
   url 只收 `http://host:port`（std-only 无 TLS，§6.7 口径）。
7. **日志解析防线：topic0 + 日志地址双重校验**。topic0 = `keccak("Revoked(bytes32,address)")`
   （sha3 现算，测试面以 foundry keccak 字面量独立锚定——§6.19.3 selector 同纪律，
   不手算）；getLogs 请求带 `address` 过滤，但解析层再校验 `log.address == registry`
   ——RPC 端过滤是实现行为不是协议保证，混入其他合约同名事件的后果 = 撤销错误的 dh。
   topic0 不匹配 / topic 数量错 / 坏 hex / 地址不符的日志**逐条跳过并计数**（fail-visible
   进返回 stats），绝不 panic——刮取面对脏数据鲁棒，干净数据靠双重过滤保证。
8. **驱动形态：`poll_once(&self, agg) -> Result<PollStats, String>` 单步接口**，
   线程只是 `loop { poll_once; sleep(interval) }` 驱动器——单测直接驱动不 sleep，
   真实线程行为由装配面覆盖。
9. **验证形态：fake JSON-RPC 服务器真 TCP 往返**（§6.19.3 先例：客户端按
   `Content-Length` 精确读——`read_to_end` 等对端关写半会死锁）+ 真 Aggregator
   （缺省 FormatVerifier 配置）。`Revoked` 事件形状由 forge 既有用例锚定（事件在
   S-11 起有 vm.expectEmit 覆盖），观察面消费的是日志形状不是链上行为；**anvil 端到端
   演练不做**（fake 响应按 anvil 实际返回形状构造，与 §6.22.3 fake-RPC + 真链上事件
   同款分工）——诚实边界记录在案。
10. **与 kind3 的语义关系（文档钉）**：判定面消费链上 `revokedAt`（§6.23 守卫），观察面
    快慢不影响判定正确性，只影响本账本的撤销生效窗口长度；观察面失灵 = kind3 可罚
    本体的运营者过失形态具象（§6.23.2「撤销观察缺席」在生产形态 = 观察面未装配 / 挂掉
    / 漏读）——债券罚没语义不变。

#### 6.24.2 诚实边界

- **观察面是尽力而为不是共识**：轮询间隔内的撤销在本账本仍可接受（预算快路径无
  Contract 模式 `isRevoked` 读时），窗口期风险由债券罚没兜底（§6.5 / kind3）。ZK 模式
  的撤销根绑定闸（S-44）挡的是「证明用旧根」，不挡「接受后才撤销」。
- 全史重扫的成本面与 reorg 语义见定夺 3（§6.22.5 同缝）；无观察 lag 指标（定夺 5）。
- fake RPC 单测证解析与消费语义，不证真 anvil 日志流形状（定夺 9）。
- 观察面只覆盖 `RevocationRegistry.Revoked`——`DSA` 层面无撤销事件（撤销只经注册表），
  绑定事件（`OperatorBound`）不消费：绑定闸走摄取面同步读（§6.19.2），事后对账不归
  观察面。

#### 6.24.3 工件与测试

- `gateway/src/watch.rs`：`RevocationWatchConf`（配置解析 + url/地址/interval 校验）、
  `RevocationWatch`（getLogs 客户端 + 解析 + `poll_once`）、`PollStats{seen, fresh,
  skipped}`、topic0 常量锚定测试。
- `gateway/src/binding.rs`：HTTP/JSON-RPC 往返骨架抽 `pub(crate)` 共用（`eth_call` 与
  `eth_getLogs` 同骨架，行为逐字节不变）。
- `Config.revocation_watch` 装配 + bin 起线程 + 启动日志；缺省 None 口径逐字节不变。
- 测试（gateway watch 单测 + 真 socket）：双事件消费 / 重复轮查重（revoked_len 不变 +
  WAL 不膨胀）/ 脏日志逐条跳过（topic0 错 / topic 缺 / 坏 hex / 地址不符）/ 地址不符
  防线 / json-rpc error 与连接失败 Err 上抛 / 配置负向组（https / 坏地址 / 零间隔）/
  缺省 None 序列化不出现。
- ops.md 撤销面诚实边界收口（「v1 无链上监听器」段落改写）+ audit-scope §5 链上面
  基线补观察面条目。

### 6.25 P2-6/L3 共享账本共识设计轮（设计轮，2026-09-01，S-69）

**定位**：§6.17.3 砖单最后一项的独立设计轮——前置「P2-1..5 实证」已满足（S-61/62/66/64/65/67
全部落地），本节兑现前置要求的另一半。**本节是设计，不是实现声明**：P2-6/L3 维持
blocked（决策 A「分片优先于共识」不变），本设计轮的产出是把这个挂账项拆成可开工的问题
定义、语义定夺与分期砖单，并记录它为什么现在仍不开工。零代码（先改后码纪律在纯设计轮的
落点 = 本节定夺项，实施砖开工前必须逐条复核）。

#### 6.25.1 设计输入（全部为仓库已实证事实）

1. **决策 A 的代价条款**（§6.17.2）：预算强制层在账本侧（§4.5 设计决策）⇒ 共享账本要求
   全部写者对同一账本状态达成共识；共识协议是 L3 级交付物，正确性论证量级远超本仓已验证
   面。代价另一半：单委托吞吐受其分片运营者单写者封顶（§4.5 规则 7）。
2. **P2-1..5 收窄后的残余威胁面**（§6.17.4）：验证者合谋、写者审查/停机、绑定合谋——
   P2 阶段的结论是「多方独立验证提高发现率」，不是消除；「那需要 P2-6 共识或外部追责」
   是本节的立项理由。
3. **账本确定性是本仓最强已验证性质**：§4.5 确定性状态机 + B11 同 seed 全管线输出哈希
   一致 + `restore_from_wal` 重放（§4.1）+ S-57 四契约跨实现差分（逐字节）+ S-39
   `replicas_converged` 三元组比对。**同一 WAL → 同一账本状态**是已验证性质，不是本节
   引入的假设。
4. **S-39 副本组 ≠ 共识**（§6.12 诚实边界）：副本组是同一逻辑账本的复制，分歧只报告
   （degraded + lag gauge）不裁决——共识缺的正是「裁决谁是真值」。
5. **接受时刻墙先例**（§6.20.1）：把可罚事实锚到「接受时刻」的设计，必须先问「接受语义
   在目标形态下是否还成立」——本节对共识照此纪律执行（6.25.4）。
6. **威胁模型对写者的假设是拜占庭**（§9 恶意运营者行 + §6.5）：本仓对运营者的整套安全
   论证建立在「会作恶，靠债券 + 欺诈证明事后惩罚」上。任何共识设计必须在这个假设下论证，
   crash-only 的容错论证不满足本仓门槛。
7. **P2 各机制带有分片模型烙印**：绑定面（S-62 `dh→operator`）、kind4（跨分片消费）、
   OperatorRegistry 名册（S-64）、每运营者独立撤销观察（决策 F / S-67）——都是
   「账本 = 运营者私有」的产物，共享账本下去留必须逐项清点（6.25.5）。

#### 6.25.2 问题定义：P2-1..5 之后，共识到底买什么

**定夺级发现：共享账本买的不是安全性，是写者活性。** 分片模型在 P2-1..5 落地后，安全面
已封到链上：错结算（kind1/2）、已撤销消费（kind3）、跨分片消费（kind4）均可事后罚没；
剩下的残余全部是**活性/发现率**问题——

| 残余面 | 为什么欺诈证明管不了它 | 共享账本买到什么 |
|---|---|---|
| 写者停机（分片不可用） | 「不服务」不是可罚的链上事实 | f 个写者故障仍可写（quorum 活性） |
| 写者审查（拒收意图） | 同上，不可出证 | 提案者轮换 + 客户端多写者重投（可绕过单方，见 6.25.6 诚实边界） |
| 验证者合谋 | 发现率归零且无证据 | 承诺根须写者集公证（6.25.5），合谋门槛从 1 方抬到 quorum |
| 无全局账本视图 | 结构性缺失（§6.17.4） | 一份账本，聚合面自然存在 |
| 每委托吞吐单点封顶 | 性质非缺陷 | 全序日志取代单写者分片（§4.5 规则 7 退役） |

**不构成新增收益的一项（记录在案）**：跨分片双花的结构性消除（一份 `BudgetState`）——
该面已被 P2-2（事前绑定闸）+ P2-3（kind4 事后罚）在链上用别的方式封住。**为了这个上
共识是重复建设**；P2-6 的立项理由只能落在活性与合谋门槛上。

#### 6.25.3 共识对象 = WAL：本仓的 RSM 分解（关键简化）

**定夺：共识的对象是日志（WAL 全序），不是账本状态。** 论证：账本状态是 WAL 的确定性
函数（输入 3），因此——

- 状态无需共识：日志一致 ⇒ 状态一致，等价性已被 B11 / S-57 / S-39 锚定，不引入新的
  状态一致性论证；
- 复制 = 日志复制；follower = 现有 `restore_from_wal` 消费方的升级（S-39 副本组从
  「事后比对告警」升级为「参与出证与签名」）；
- 共识协议的正确性论证从「状态机复制 + 应用语义」缩到「纯日志全序」。

代价（诚实记录）：**即便如此仍是 L3 级交付物**——决策 A 理由 1 不因此消失，缩的是一个
量级，不是降到零；日志全序机制本身（谁提案、如何避免分叉、如何容错）仍是一个分布式
协议，其 bug 形态（活锁 / 分叉 / 脑裂）在本仓现有门禁（单元 / property / 差分 / anvil）
中**没有对应测试层**，必须新增（6.25.7 L3-1）。

#### 6.25.4 摄取语义墙（本设计轮的「接受时刻墙」级发现）

**定夺级发现：§6.2 摄取契约在多写者下不成立，必须改语义。** 今天的「接受」是原子的：
单写者在一次 `try_commit` 内完成 验签 → 绑定闸 → 验证明 → 预算检查 → 记账 → 分配 seq →
入窗口队列（§6.2 管线）。`Receipt.seq` 同时是三件事：账本位置、预算占用凭证、客户端回执。

多写者下两个写者可并发接受两条合计超预算的意图（§4.5 规则 7 的保护消失）——
**接受 ≠ 记账**，谁被记账取决于日志全序中谁先被 apply。三条出路（记录在案，含否决理由）：

1. **回执降级为临时接受**：摄取面照发 seq，apply 时被淘汰的意图事后作废。**否决**——
   违反 §6.2 幂等契约（rejected 不得透传成成功）与 §6.6 SDK 幂等重试契约（建立在回执
   终态上）：客户端按回执发货 = 双花向量。
2. **两阶段摄取**（reserve → confirm）：接受面预留，apply 后确认。**否决**——确认延迟 =
   共识延迟进热路径（6.25.6 性能边界）；且预留状态本身需要跨写者一致，预留就是一次
   小共识，问题没消掉只是搬进预留面。
3. **日志承载裁决结果（采纳）**：日志条目分两类——提案（意图信封 / 撤销事件）与
   **裁决（apply 结果：接受或 `Rejected{reason}`）**。确定性 apply = 现有摄取管线去掉
   网络 I/O（验签 / 证明 / 预算 / 记账全部是纯函数，确定性已锚）；按日志全序逐条 apply，
   失败者落裁决条目。回执 = 「我的提案被 apply 后的裁决」，由受理写者**读回**（读己之写；
   与 S-68 公共 RPC 写后读滞后重试同类问题——写已上链，读可能打到滞后副本）。
   所有副本对同一日志 apply 得到同一状态**与同一裁决史**——裁决史也是账本事实，进 WAL、
   可重放、可审计。

代价（诚实记录）：日志体积含被拒条目（拒绝也留痕——与 S-38「驳回即没收」的审计哲学一致，
垃圾意图的拒绝原因上链可查）；摄取回执从同步变异步（读回延迟 ≥ 批次共识延迟，6.25.6）。

#### 6.25.5 链上面：承诺锚从「运营者私章」变「写者集公证」，存量机制逐项清点

**定夺：commit 必须携带写者集阈值签名凭证（QC），单人 commit 在共享账本模型下不成立。**

- 今天：`commit(epochId, commitmentRoot, revocationRoot, acceptanceRoot, sealedAt)` 由唯一
  `operator`（immutable）签发，债券 = 该运营者 `msg.value`（§6.4/6.5，S-66 后签名）。
- 共享账本：承诺根是共享账本状态的函数，任何单个写者都无法独立声称它——除非其余写者的
  账本与它一致。锚 = ≥quorum 写者**各自复算后**对 (epochId, 三根, sealedAt) 的签名聚合。
- 为什么「复算后签名」可强制（关键简化，仓库事实）：账本确定性 + 复算零信任——诚实写者
  「只签自己算出来的根」不需要信任任何人。与 §6.18.3 验证者出证闸同构（镜像重算根 ==
  链上根才出证）。

**债券归责重定（§6.5 的 P2-6 版）**：错误根 + QC ⇒ 签名者集中含 faulty 方。证据不变——
kind1/2/3 的欺诈证明**不关心谁 commit，只关心承诺根 / 净额与可证意图矛盾**。归责定夺：
**QC 全体签名者连带罚没**（各自债券 → 挑战者）。理由：每个签名者本可复算拒绝签名；按
「各自复算结果」归责的替代方案链上不可验证（链上无法知道谁复算过谁没复算）。新欺诈 kind
**kind5（等效签署 / equivocation）**：同一 epochId 两份不同根的 QC 签名（签名是公开链上
数据）——纯密码学证据，无需意图与路径，链上比对即判，与 kind1..4 共用挑战 / 押金框架。

**存量机制去留清点（防止 P2 砖被误丢弃或误沿用）**：

| 机制 | 去留 | 理由 |
|---|---|---|
| 承诺根 / 净额 / 哈希确定性重排（§6.3/6.4） | 保留不动 | 与账本形态无关 |
| kind1（漏单）/ kind2（低付）/ kind3（已撤销消费） | 保留 | 根 / 事件时刻锚定，不绑运营者身份 |
| acceptanceRoot 与 acceptedAt 锚（S-66） | 保留，**来源要换** | acceptedAt 现为运营者自派时钟（§6.23.1 定夺 2）；共享账本下换成**日志条目内定**（排序盖章时刻），否则多写者各持己钟，§6.20.2 锚的语义分裂 |
| 撤销集 / 撤销根绑定闸（S-44/S-49） | 保留 | 随日志复制 |
| 撤销观察面（S-67） | 保留，查重从优化变必需 | 任一写者的观察可入日志，重复提案是常态——S-67 定夺②（消费前 `is_revoked` 查重 + WAL 不膨胀）在多写者下由「竞态防膨胀」升格为「协议必需」 |
| **绑定面 + 摄取绑定闸 + kind4（S-62/S-66）** | **退役** | 共享账本下「绑定他方运营者」语义消失（没有「他方」）。**记录在案：这不是 P2-2 白做**——绑定面是分片模型（决策 A）的安全支柱；两条路线共用承诺 / 欺诈证明底座，分叉只在绑定层。存量委托迁移 = 分片路线运行至委托过期 |
| OperatorRegistry（S-64） | 延续改造 | 名册语义保留（append-only 调度 / 实例固化不变），从「运营者名册」扩为「写者集名册」 |
| `BatchSettler.operator` immutable 单地址 | 改造退役 | → 写者集 + 阈值验证（合约面全改，触碰审计冻结面全部内容） |

#### 6.25.6 协议形态定夺：乐观复制（verify-then-attest）优先，BFT 记为替代不开工

**定夺：本仓若做 P2-6，采用「验证性复制的乐观共识」，不做 BFT。**

论证（三条，全部落在仓库已验证事实上）：

1. **本仓安全模型是乐观的，不是预防的**。§6.5 每一行都是「事后可证 + 债券惩罚」——单
   运营者今天就能提交错误根，模型容忍它发生，靠挑战窗口 + 罚没收口。BFT 的卖点（密码学
   预防分叉）买的是本仓已经用别的方式买到的东西（错误内容人人可零信任复算、可罚），而
   它的成本（3f+1、视图更换、正确性论证量级——决策 A 理由 1）是纯增量。
2. **确定性账本把「验证」成本打到零**。BFT 需要预防的恶意提案，在 Mist 里可被任何
   副本零信任复算拒绝——当检测免费时，预防的边际价值就是检测的价值。乐观形态 = 提案 →
   各写者 apply + 复算 → 达标者签名 → 阈值聚合 QC → commit。作恶门槛从今天单运营者模型
   的「1 方拜占庭即可」抬到「quorum 拜占庭」，**不是回退**。
3. **日志全序仍需要一个机制，可选择的只是形态**：预防式（BFT）或乐观式（签名复制 +
   可罚分叉）。乐观式的日志分叉证据 = kind5 等效签署（纯签名比对）；推进活性 = 提案者
   轮换 + quorum 可用。

诚实边界（定夺级，全部记录在案）：

- **乐观共识的安全性是经济性的**，与 §6.5 同类而非更强：拜占庭 ≥ quorum 时日志可分叉、
  错根可上链，靠罚没与挑战窗口收口。共识买的是「作恶需要 quorum」这个门槛，不是
  「作恶不可能」。
- **提案者审查不可被其余写者察觉**（与今天单运营者同缝）：签名者只能验证提案内容自洽，
  无法验证提案完整（看不见客户端对其他写者的提交流）。缓解 = 提案者轮换（损害有界）+
  客户端向多写者重投。**审查抗性在这个形态下是「可绕过单方」，不是「不可审查」**。
- **预算竞争的排序权 = 提案权**：§6.3 确定性重排只封净额套利，不封预算竞争——同一窗口
  内预算不足时谁先被 apply 由日志序决定，日志序由提案者组装序决定。今天排序权 = 单运营者
  摄取序（同样有此权力），共享账本把它**轮换化**了，是缓解不是消除。
- **每笔确认延迟换写者活性**：§5.4 的 100μs/笔 热路径目标在「每笔一共识」下不可达
  （共识轮 = 百毫秒量级）。采纳 6.25.4 路线 3 的天然解法：**日志条目 = 窗口批次**（提案
  批次化，确认延迟 = 批次共识延迟）；摄取快路径（本地预算预检）保留为**准入预检**（非
  终态）。§8.2 须新增「确认延迟」口径与摄取延迟分开——这是新增指标，不是现有 9 指标的
  放宽。
- **BFT 替代的复核条件（reopening condition）**：若出现**预防性**分叉免疫的需求（监管 /
  结算终局性要求），乐观形态不满足，届时重启评估并走独立协议设计轮——本节定夺不覆盖
  该场景。

#### 6.25.7 分期砖单（L3-x，全部未开工）

| 砖 | 内容 | 规模 |
|---|---|---|
| **L3-0** | **摄取 / apply 分离的可测性收口**：把现有摄取管线抽成纯 apply 函数（输入日志条目序列，输出状态 + 裁决），property test = N 副本乱序投递同一条目集合 → 状态根与裁决史逐字节一致。**不改 WAL 格式、不改链上面**——共享账本的地基，也是对现有单写者栈独立有价值的重构（当前管线与网络 I/O 耦合）。**已落地（S-70，2026-09-01，§6.26）** | 中 |
| **L3-1** | WAL 格式版本化 + 日志复制（签名条目 + 副本同步 + 裁决读回）——**触碰 WAL 冻结面**（§6.18.1 纪律），必须与审计重冻结（S-58 §6 清单）同轮；新增分布式协议测试层（分叉 / 重复 / 乱序投递负向组），本仓现有门禁无此层 | 大 |
| **L3-2** | 链上面：写者集 + 阈值 QC + 债券连带 + kind5 等效签署；`operator` 单地址退役——合约面全改，重走 S-58 冻结与覆盖门禁 | 大 |
| **L3-3** | 观察面 / monitor / ops 迁移：绑定闸与 kind4 退役路径、S-39 副本组语义升级、S-65 声誉信源改 QC 事件（digest 指纹半边已由 S-72 提前兑现，2026-09-01，§6.12.1） | 中 |

**解锁条件（P2-6/L3 维持 blocked 的理由，记录在案）**：

1. **审计冻结 v1 未打**（预算未批，S-58 §6 清单不执行）——L3-1/L3-2 在冻结前开工 =
   冻结面直接作废重来，违反冻结纪律本身。
2. **无生产活性痛点数据**：分片模型（P2 现状）尚无生产运行证据表明单写者停机 / 审查是
   真实痛点——S-68 只是部署路径彩排，不是运营数据。为了不存在的痛点上 L3 级复杂度 =
   负收益。
3. **L3-0 是唯一不依赖解锁条件、且独立有价值的砖**——若未来开工，从 L3-0 起步；若不开工，
   L3-0 也可作为独立重构排入普通轮次（它同时改善现有栈的可测性）。

#### 6.25.8 诚实边界（设计轮级汇总）

- **本节全部是设计**：无一行代码、无测试锚；本节引用的每个「已实证」均可回溯到具体 S 轮，
  每个新增判断均标「定夺记录在案」。实施砖开工时必须逐条复核（先改后码纪律在 L3 的落点）。
- **6.25.4 路线 3 与 6.25.5 的归责设计是未经实现验证的新增判断**：「裁决史进 WAL」的日志
  膨胀代价、QC 阈值签名的 gas 成本、连带罚没的合约复杂度均为估算不是实测——L3-0/L3-2
  开工时先量测再定夺。
- **容错计数（f / quorum / 3f+1）只用于作恶门槛的量级论证，不是形式化安全证明**——本仓
  无人做过分布式协议形式化，不假装有；乐观形态的「安全性 = 经济性」边界（6.25.6）优先于
  任何计数直觉。
- **未解决面（识别但未收口）**：提案者审查（6.25.6）、quorum 合谋、客户端提交流在写者间
  无共享协议（谁也没法证明「我投过但没人收」）、跨写者的时钟来源（acceptedAt 日志内定的
  具体盖章方未定夺）——全部挂给实施砖的定夺轮。

### 6.26 L3-0 摄取 / apply 分离的可测性收口（实施，2026-09-01，S-70）

§6.25.7 砖单中唯一不依赖解锁条件、且对现有单写者栈独立有价值的砖（6.25.7 条目 3）。
**不改 WAL 格式、不改链上面、不改摄取管线热路径**（§6.2 十步顺序与 B8 口径逐字节不动）。

#### 6.26.1 定夺记录（先改后码）

1. **apply 面的可执行形态**：`aggregator/src/apply.rs::apply_log(parts, records)` ——
   「账本状态是日志的确定性函数」（6.25.3）从一句被引用的主张变成一个可调用的函数。
   「纯」的口径钉死为：**无 I/O、无时钟读、无网络、无随机**；输出 =
   `f(初始状态, 条目序列)`，条目序列即 `DecodedRecord`（WAL 重放解码形态，不新造类型）。
   它允许内部可变性（对副本自身账本状态的 mutate）——这正是 RSM apply 的定义，不追求
   函数式纯粹性。`parts` = `LedgerParts`（注册表 / 分片账本 / 窗口 / 撤销集 / 撤销根
   接受集 / 意图索引 / seq 计数器的引用束），`pub(crate)`——L3-1 若跨 crate 再升级可见性。
2. **apply 是记账面，不是验证面**：日志条目是**已裁决事实**（在线已过信封验证 / 证明
   验证 / 绑定闸，§6.2 步 0-6b），apply 不重验——WAL 重放不重验是既有语义（S-10a 起）。
   在线路径与 apply 的共享核是 `try_commit`（同委托提交序 == seq 序的既有锚）；在线
   `Receipt` 与 apply 的 `ApplyVerdict` 是同一裁决的两种形态（在线含信封闸，apply 是
   日志形态）。**否决**「在线路径改走 apply」——那会把窗口 reserve/finalize/maybe_rotate
   的热路径时序与重放路径强行统一，破坏 S-10c「重放不重新密封、未密封尾直接重建窗口」
   的恢复语义（既有测试组锚定），且对热路径零收益。
3. **归一化语义 = 现行 `restore_from_wal` 重放语义逐字节保留**（乱序投递的收敛由归一化
   保证，不由投递顺序保证）：① 撤销集 / 撤销根接受集先于意图重建（WAL 记录序无关，
   集合操作幂等）；② 注册先于意图（意图引用委托，因果前件）；③ **意图按 `seq` 升序
   重放**——seq 是序权威（分片锁保证同委托提交序 == seq 序，lib.rs 模块文档锚）；
   ④ 未密封尾（seq ≥ 最后 EpochSeal 累计接受数）重建进当前窗口 + epoch 编号续接
   （S-10c）；⑤ `RevokeRoot` 仅 `enforce_revocation_root = true` 进接受集（S-49）。
   apply 的错误（意图引用未注册委托 / `try_commit` 失败）即 Err 终止（fail-closed，
   与现行 `io::Error` 上抛同口径）。
4. **裁决史契约：每条日志条目恰好产出一个 `ApplyVerdict`**（total map，无静默跳过）。
   EpochSeal 产出边界裁决（它改变密封边界——是状态事实）；Netting 产出「跳过」裁决
   （重放面仅计数用，如实标注）。重复投递的意图由 `try_commit` 的 S-12 幂等性天然吸收
   （返回既有 seq，不重复扣预算、不重复分配 seq）。
5. **`state_digest()` = 副本收敛检查的可执行形态**：sha256（域分隔符
   `MIST-APPLY-DIGEST-V1`）over **全键排序**的规范序列化——注册表（dh 升序 +
   `delegation_hash(delegation)` 作内容指纹 + agent_pub）、分片账本（dh 升序 →
   budget 四域 + nonce 升序 → (nonce, intent_hash, 裁决码 `Error::as_code()`)）、
   seq 计数、撤销集（dh 升序）、撤销根接受集（升序）、意图索引（ih 升序）、当前窗
   未密封尾（seq 升序，`EpochWindow::accepted_entries()` 只读快照）、next_epoch。
   **不含会话面**（rejected 计数 / latency / started_at / instance_id / verifier /
   WAL 路径——它们不是账本状态，恢复后从 0 起，§6.2 既有口径）。
   撤销集内容指纹用排序 dh 列表而不用 `sparse_root()`：digest 是调试 / 收敛检查工具，
   不付 MSM 成本（MSM 根的密码学锚另有 `revocation_root()`）。
6. **digest 不是协议常量**：规范序列化口径变更（新增状态域 / 域序调整）会改变 digest
   值——这是**有意的**（迫使口径变更被同步到所有副本消费者），golden 锚定的是
   「同版本内跨进程 / 跨投递序稳定」，不是跨版本稳定。monitor / 集群面接线挂 L3-3
   （S-39 三元组比对 → digest 比对是 L3-3 的自然升级点，本轮不动 health.rs）。
   **monitor 半边已提前兑现（S-72，2026-09-01，§6.12.1）**：`replicas_converged` 两腿
   （三元组 ∧ digest）；L3-3 余下挂账（绑定闸/kind4 退役路径、声誉信源改 QC）不动。
7. **property test 的乱序范围 = 批内乱序**：一次 `apply_log` 调用接收一个条目批次，
   批内归一化（定夺 3）⇒ 同一集合的任意到达排列 + 重复投递收敛到同一状态与同一裁决史。
   **跨批乱序（流式投递：seq 6 先于 seq 5 到达且 5 未到就推进）不在此砖**——需要
   holdback 缓冲 + seq 稠密性预扫描，且稠密性破洞的处置（等 / 跳 / 拒）是日志复制的
   协议定夺，挂 L3-1（WAL 格式面配合）。在线↔重放的等价性另由 digest 断言锚定
   （同一批意图在线摄取后的状态 == WAL 重放后的状态，逐字节）。

#### 6.26.2 诚实边界

- **apply 不缩小在线管线的验证面**：验签 / 证明 / 绑定闸 / 撤销根闸仍在在线路径
  （§6.2），apply 复用它们的裁决结果。6.25.4 路线 3 的「确定性 apply = 现有摄取管线
  去掉网络 I/O」在本砖只兑现**记账半边**；验证半边的纯函数化（验签已是纯函数、证明
  验证依赖后端）仍属 L3-1/L3-2 的协议定夺。
- **批内乱序收敛 ≠ 共识安全性**：它钉住的是「apply 是条目集合的函数」这一 RSM 前提；
  日志全序由谁保证（提案者 / QC）是 6.25 的协议面，本砖不触及。
- **digest 是诊断面不是判定面**：副本 digest 不一致是告警信号（进 monitor 挂 L3-3），
  不是欺诈证据——digest 无密码学承诺（任何人可在自己副本上重算），不能替代
  §6.5 的承诺根 / 出证闸。（monitor 面接线已由 S-72 兑现，§6.12.1；告警语义 = 信号
  非证据的口径在 §6.12.1 诚实边界延续。）
- **窗口快照的并发语义**：`accepted_entries()` 读 PENDING 槽即跳过（与 `seal()` 同一
  Release/Acquire 协议），在线摄取进行中调用得到的是瞬时快照（可能漏在途槽）——
  digest 语义定义在**静默态**（重放完成 / 无在途写者），不承诺并发快照一致性。

#### 6.26.3 工件与测试

- `aggregator/src/apply.rs`：`LedgerParts` / `apply_log` / `ApplyReport` / `ApplyVerdict`
  / `state_digest`；`RevocationSet::sorted_revoked()`、`EpochWindow::accepted_entries()`
  两个只读快照接口。
- `restore_from_wal` 改为 `build` + `apply_log`（行为逐字节等价，既有 S-10c / S-11 /
  S-49 / S-62 恢复测试组为回归锚）。
- property test：生成一致日志集（Register/Intent/Revoke/RevokeRoot/EpochSeal）→
  基准副本 apply → N 副本乱序投递（条目排列 + 重复投递）→ state_digest 与裁决史
  逐字节一致；在线摄取 vs WAL 重放的 state_digest 相等；digest 灵敏度（每个状态域
  变动 → digest 变）；golden digest 锚定规范序列化。

---

## 7. 链上合约接口（Solidity，S-06 最小可跑 → S-11 生产化）

六个合约在 `contracts/src/`（S-11 增 `IntentHelper.sol` / `Merkle.sol` 交叉实现；S-64 增
`OperatorRegistry.sol`；S-66 增接受锚面；forge test **130 用例**全绿，见
`contracts/README.md`）。签名与语义以代码为准，此处为契约要点。

```solidity
// DSA.sol —— 委托注册（Contract 模式 + 撤销锚点来源）+ 运营者绑定面（S-62，§6.19）
contract DSA {
    event DelegationRegistered(bytes32 indexed delegationHash, address indexed owner);
    event OperatorBound(bytes32 indexed delegationHash, address indexed owner, address indexed operator);
    function registerDelegation(bytes calldata delegationABI, bytes calldata ownerSig) external;
    /// 委托→运营者绑定（§6.19.1）：仅委托 owner 的私钥可写（msg.sender == owners[dh]），
    /// 一次性固化、不可改绑；operator == 0 拒（零地址 = 未绑定的读协议语义）。
    function bindOperator(bytes32 delegationHash, address operator) external;
    function ownerOf(bytes32 delegationHash) external view returns (address);
    function isRegistered(bytes32 delegationHash) external view returns (bool);
    /// 绑定读面：零地址 = 未绑定（聚合器摄取闸 fail-open 语义的事实源）。
    function operatorOf(bytes32 delegationHash) external view returns (address);
    /// S-66（§6.23.1 定夺 4）：绑定时刻锚（kind4 守卫输入，0 = 未绑定）——
    /// 注册下界锚被事件下界蕴含，不单独实现。
    function boundAt(bytes32 delegationHash) external view returns (uint64);
    error AlreadyRegistered(); error BadOwnerSignature(); error HighS(); error MalformedABI();
    error NotRegistered(); error NotDelegationOwner(); error AlreadyBound(); error ZeroOperator();
}

// OperatorRegistry.sol —— P2-4（S-64，§6.21）：append-only 金额调度 + 运营者名册
//（决策 D：动态性来自调度 + 重部署，不来自 setter；记录面不是强制面，§6.21.1 定夺 6）
contract OperatorRegistry {
    struct ScheduleEntry { uint256 bond; uint256 challengeBond; uint64 writtenAt; }
    struct OperatorEntry { address operator; address settler; address asset;
                           uint256 challengeBond; uint64 registeredAt; }   // 注册时快照
    address public immutable registrar;
    // 调度：旧条目永不改写、无删除路径；currentSchedule() = 末条（未来部署读取的当刻值）
    function appendSchedule(uint256 bond, uint256 challengeBond) external; // 仅 registrar
    function currentSchedule() external view returns (ScheduleEntry memory);
    // 名册：self-registration 绑定实证——调用者必须 = BatchSettler(settler).operator()，
    // 注册时快照 asset/challengeBond 固化值；append-only 无移除/停用；settler 去重。
    function registerOperator(address settler) external;   // permissionless（可证明归属）
    function operators(uint256) external view returns (OperatorEntry memory);
    function isSettlerListed(address settler) external view returns (bool);
    function settlerCount(address operator) external view returns (uint256);
    error ZeroRegistrar(); error NotRegistrar(); error ZeroScheduleAmount();
    error ScheduleEmpty(); error SettlerAlreadyListed(address);
    error NotSettlerOperator(address settler, address expected, address actual);
}

// RevocationRegistry.sol —— 独立撤销表（仅 owner 可撤销）
contract RevocationRegistry {
    event Revoked(bytes32 indexed delegationHash, address indexed by);
    function revoke(bytes32 delegationHash) external;   // 仅 owner，未注册 reverts
    function isRevoked(bytes32 delegationHash) external view returns (bool);
    /// S-66（§6.23）：kind3 守卫的撤销时刻锚（0 = 未撤销，与 isRevoked 同语义）。
    function revokedAt(bytes32 delegationHash) external view returns (uint64);
    error NotOwner(); error NotRegistered();
}

// BatchSettler.sol —— 乐观批量结算（S-11 v2 生产化：operator 守卫 + 延迟 claim + 完整挑战流；
//                      S-28 资产参数化：asset = address(0) 原生 ETH / ERC-20（如 USDC）；
//                      S-66 接受锚面：acceptanceRoot + kind3/kind4 + 读面拆分 §6.18.2）
contract BatchSettler {
    struct NetInstruction { address recipient; uint256 amount; }
    struct IntentProof {
        bytes20 agent; bytes32 delegationHash; bytes20 recipient; uint64 amount;
        bytes32 category; uint64 spendNonce; bytes memo; uint64 expiresAt;
        uint64 acceptedAt;                 // S-66：接受时刻锚（kind3/4 时间守卫输入；
                                           //   kind1/2 随证据携带但不校验——向后兼容形状）
        uint64 seq; uint256 leafIndex; uint256 acceptedCount; bytes32[] siblings;
        bytes32[] acceptanceSiblings;      // S-66：平行接受树路径（两树同叶序 ⇒ 同
                                           //   leafIndex/acceptedCount/同深度，§6.23.1 定夺 6）
    }
    struct FraudProof { uint8 kind; uint256 targetNetIndex; IntentProof[] intents; }
    // kind 1 = 漏单（收款人 ∉ net[]）；kind 2 = 低付（同收款人意图子集和 > net[target].amount）；
    // kind 3 = 已撤销消费（单意图，revokedAt + margin ≤ acceptedAt 仍被接受，§6.20.2）；
    // kind 4 = 跨分片消费（单意图，绑他方运营者且 boundAt + margin ≤ acceptedAt，§6.19.1）。
    // kind1/2/3/4 均 intents.length 闸（1/≤32/1/1）。

    event Commit(uint256 indexed epochId, bytes32 commitmentRoot, bytes32 revocationRoot,
                 bytes32 acceptanceRoot, uint64 sealedAt, uint256 bondedAmount);  // S-66 扩展
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
    DSA public immutable dsa;                          // S-66：kind4 锚（boundAt/operatorOf）
    RevocationRegistry public immutable revocations;   // S-66：kind3 锚（revokedAt）
    uint256 public constant CHALLENGE_WINDOW = 6 hours;
    uint256 public constant MAX_INTENTS_PER_CHALLENGE = 32;
    uint256 public constant ACCEPT_MARGIN = 300;       // S-66：接受时刻余量（秒，协议常量，
                                                       //   Rust/合约同值，§6.23.1 定夺 3）

    constructor(address operator_, address asset_, uint256 challengeBond_,
                DSA dsa_, RevocationRegistry revocations_);
                                                       // bond/押金恒原生 ETH（两模式相同）；
                                                       // challengeBond_ == 0 / 锚零地址
                                                       //（ZeroAnchor）/ revocations_.dsa() !=
                                                       // dsa_（DsaMismatch）构造即 revert

    function commit(uint256 epochId, bytes32 commitmentRoot, bytes32 revocationRoot,
                    bytes32 acceptanceRoot, uint64 sealedAt)
        external payable onlyOperator;                // 质押债券（msg.value）+ 锚定撤销根/接受根，
                                                      // 一次性；sealedAt 是声明面（观测，定夺 5），
                                                      // committedAt 由合约以 block.timestamp 写定
    function settle(uint256 epochId, NetInstruction[] calldata net, bytes32 nettingRoot)
        external payable onlyOperator;                // keccak(net) 校验 + 存 net[] + msg.value ≥ Σnet
    function claim(uint256 epochId, uint256 netIndex) external;  // 窗口后逐条领取结算资产（ETH/token）；voided 拒
    function challenge(uint256 epochId, FraudProof calldata fp)
        external payable;                             // S-38 押金制：入场前 4 类 revert；入场后
                                                      // 驳回即销毁押金（ChallengeRejected），epoch 不动
    function withdrawRefund(uint256 epochId) external onlyOperator;
                                                      // 审计加固：挑战成功时退款 push 失败的
                                                      // 留存量拉取兜底（仅 voided epoch 可取）

    // S-66 读面拆分（§6.18.2）：Epoch 13 读面字段后自动 getter 的 13 元组返回在 legacy
    // codegen（forge coverage 关优化编译）恒爆栈 → 拆两个显式读面（net[]/claimed 不在返回面）。
    function epochs(uint256 epochId) external view
        returns (bytes32 commitmentRoot, bytes32 revocationRoot, bytes32 acceptanceRoot,
                 uint64 sealedAt, uint64 committedAt, uint256 bondedAmount,
                 uint256 settlementFunded, uint64 settledAt, bytes32 nettingRoot);
    function epochStatus(uint256 epochId) external view
        returns (bool committed, bool settled, bool challenged, bool voided);

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
    error ZeroAnchor(); error DsaMismatch();           // S-66：构造期锚守卫（§6.23.1 定夺 7）
}
```

**关键契约（S-06 交叉实现）**：`registerDelegation` 在链上重算
`delegation_hash = sha256(delegationABI)`，owner 解析自 ABI 字节区间 `[26:46]`
（`"DSAv1\0"` 前缀 + agent + owner，canonical 编码见 `core/src/dsa.rs`）。
链下 mist-core 的 `delegation_hash` 必须与之一致（Rust `sha2` ↔ Solidity
`sha256` 预编译，双向验收）。owner 签名强制低位 s（`s > n/2` → `revert HighS`）。

- 部署底座：Base（主网 Phase 2 起）；测试：Anvil 本地链 + Base Sepolia。
- **S-11 结算资产 = 原生 ETH**（bond = `msg.value`；claim 付原生 ETH）；**S-28 资产参数化
  落地 ERC-20 结算**——`BatchSettler(operator, asset, challengeBond, dsa, revocations)`
  （S-50 押金随构造参数化；S-66 增 kind3/4 守卫锚两参）：`asset = address(0)` 逐字节保留 v2
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

> **S-66 实测回填（B7 基线重录，2026-08-31）**：P2-3 接受锚把 `acceptanceRoot` 纳入 B7
> 管线测量（`b7_measure` 构造确定性接受时刻，`lattice::build_epoch` 出双树根，bench 侧
> 注释锚定）——B7 在承诺树之外新增一棵 100k 叶 sha256 Merkle 树（接受叶 22B 原像），
> **固有成本 +19ms**：`agg_kernel_b7_wall_ms` 48.1 → **67.0 ms**（`gate --record` 5 轮
> 取最短重录；门禁比对轮实测 69.1/68.8，两轮 +43% 一致，非噪声）。B7 预算线
> <1s / <1GB **不变**（余量 ~15×）；回归门禁以重录后的 baseline 为准。其余指标重录值
> 全部在门内：`agg_kernel_ingest_ops` -10.5%（内含 WAL Intent 记录 116→124B 的真实
> 小幅成本，±6% 噪声地板之上的最差项，< 15% 门禁）、`agg_kernel_rss_mib` 63.8 →
> 63.4 MiB、其余 ±2% 内。B12 行的 S-18 历史锚 63.8 MiB 保留，以 baseline.json 现值为准。

### 8.3 可复现与验证门禁

- **主门禁 = 本地流水线**：`scripts/verify.sh`（fmt → clippy `-D warnings` → `cargo test
  --workspace` → bench 编译 → perf gate（`cargo run --release -p mist-bench --bin
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
  `/root/.bb`），可用 `MIST_WSL_DISTRO` 环境变量覆盖）；③ 两者皆无才 `[SKIP]`。
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
  向量 + 8 接受叶（S-66 第五契约，§6.23.1 定夺 11），每棵树附包含证明
  （index + siblings）供 `Merkle.computeRoot` 重推）→
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
  "suite": "mist-bench",
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
| `E_OPERATOR` | 意图委托的链上绑定指向其他运营者（S-62 运营者绑定闸，§6.19.2；未绑定 fail-open 放行） |
| `E_BIND_BACKEND` | 运营者绑定读面不可得（RPC 失败 / 短返回，S-62，§6.19.2）——fail-closed，绝不按未绑定放行 |
| `E_WAL` | 回执持久化失败（S-76：MCP 面变更工具回执前 `flush_wal` 失败，§6.16 / §8.1）——fail-visible，回执不落盘就不是已持久化事实 |
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
| Phase 1（参考实现） | §4-§8 全部实现 + 里程碑 M1 + 开源仓库 `mist-commerce` |
| Phase 2（聚合器运营） | 生产化：多运营者、债券经济、Base 主网部署、递归聚合 |

### Phase 0 实证清单（S-08c 合闸时点）

| PoC | 内容 | 结果 | 证据 |
|---|---|---|---|
| ① ZK 授权凭证 | `spend_authorization` 完整版（§5.2 九断言 + 正/负向 + 双钥绑定 + 撤销非成员 + intent_hash 字段级绑定） | **PASS**（约束 82742 < 2^18，S-36 全宽化后复测，回填 §5.5） | S-09: CI run 31934410549；S-36: 本机 formal_zk.sh 8/8；§5.5 |
| ② 聚合器吞吐 | 验签→nonce 去重→预算记账，固定输入满核 | **PASS** 488,738 笔/s（目标 ≥10 万） | `docs/poc/poc-02-aggregator-throughput.md` |
| ③ 交付证明 | TLSNotary 2-party MPC-TLS 选择性披露见证交付 | **PASS** 四条断言 | `docs/poc/poc-03-delivery-proof.md` |

---

## 14. 活文档说明

- **2026-09-01 x402 v2 wire format 双协议支持（S-72，老板任务书"支持 x402 v2 协议，
  同时保持 v1 兼容"；编号沿用任务书——与 §6.12.1 的 S-72 monitor 收敛为不同任务，
  老板重发该号）**：sdk + facilitator 的 wire 层升级 v1/v2 双协议（§6.8/§6.9/§6.10
  同步修订）。**字段依据上游实核定**（本地 clone `D:\eco-attach\x402` HEAD `dffb81c4`：
  `specs/x402-specification-v2.md` + `typescript/packages/core`），任务书 wire 对照表的
  `maxAmount` 猜测**不成立**——v2 实际是 `maxAmountRequired` 改名 `amount`；
  另两项任务书未列的关键结构差异：v2 payload 顶层无 `scheme`/`network`（进
  `accepted`）、402 协议信息走 `PAYMENT-REQUIRED` 头。**双协议取舍**：版本判据唯一
  = `x402Version`；收端双头名（v2 优先）+ 双字母表宽容 base64；发端 v1 维持
  base64url、v2 用标准 base64；402 = v1 body 不动 + v2 头声明（asset 未配置 /
  error 402 不产 v2 头，v2 client 回落 body 按 v1 语境重试，优雅降级）；网络标识
  `network_canonical` 规范形比较（v1 名 ↔ CAIP-2 等价类互通，既有 `MIST_NETWORK=base`
  零迁移）；scheme 名 `mist-v1` 不改（与 x402 协议版本正交，§6.8 表述同步更新）。
  **为何 golden / 锚不受影响**：x402 wire 层在网关摄取面之外（§6.7 /v1/receipts 只认
  intentHash），`state_digest` 指纹域 = 账本副本状态（§6.12.1），x402 头名/编码/
  网络标识不进任何 digest 原像；DSAv1 前缀、种子魔数、域分隔符均不涉及。端到端
  互操作验证：npm `@x402/axios` + `@x402/evm` v2 client 打本地 facilitator（桥 exact
  路径，链下验签零 gas）。
- **2026-09-01 全面改版 Meridian→Mist（S-71，老板拍板"那就全面改版。叫做Mist就行"）**：
  全仓更名——crate 名（mist-core / mist-aggregator / mist-sdk / mist-gateway /
  mist-facilitator / mist-monitor / mist-mcp / mist-bench 等）、env 变量（MERIDIAN_*→MIST_*）、
  Prometheus 指标前缀（mist_*）、x402 scheme（meridian-v1→mist-v1）、域分隔符
  （MERIDIAN-APPLY-DIGEST-V1→MIST-APPLY-DIGEST-V1）、bin 名、4 个文件名、GitHub repo
  （changshenhan/meridian→changshenhan/mist）。**逐字保留项**：`MeridianUbuntu`（本机 WSL2
  发行版名——环境事实，非品牌）；4 处种子魔数 `0x4D_45_52_49_44_49_41_4E`（hex 恰拼
  "MERIDIAN"——历史巧合，改值即作废 golden fixture / 差分向量 / 基准输入）；`DSAv1\0`
  哈希前缀（协议标识，与品牌无关）；链上四合约地址（不含项目名，零影响）；
  `docs/audit/slither-2026-08-31.md` 点时历史报告不改。**state_digest golden 重锚**：域
  分隔符随更名改值，digest 值按 §6.26.1 定夺 6（digest 不是协议常量，口径变更必改值）回填
  golden 测试 `0c6c5849518e3845…`。
- **性能预算表（§8.2）是活的**：每个数字以 `bench/` 实测为准回填；偏差须在本文件记录原因与修订线。
- **本规格绑定 Phase 0/1**；任何接口签名变更走 PR 评审，先改 spec 后改码。
- 下一位要开工的模块：**聚合器内核**（S-10，WAL / commitment lattice / 崩溃恢复）。
  S-09（ZK 电路完整版：intent_hash 字段级绑定 + 撤销非成员，owner ECDSA 电路外）已完成；
  S-10 起 Phase 2 级联。EVM 验证器（`circuits/artifacts/UltraVerifier.sol`，keccak-flavor）
  供 Phase 4 L3 预编译复用。

---

*TECH_SPEC v1.0 · 2026-08-16 · Phase 0 定稿（S-08c）· 绑定文档，先改 spec 后改码。*
