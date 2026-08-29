# ZK 批验证评估（S-18 代码侧先行）

> 状态：**实测收口（2026-08-29）**。nargo/bb 工具链已在参考机（本机 WSL2，32 核）落地，
> 门禁真跑 + 延迟分解 + 批验证接口实证完成，B4 预算线已按诚实修订执行（§5/§6）。
> §2/§3 保留初稿分析口径，被实测修正的结论以 §4/§5/§6 为准。

## 1. 目标线与现状

- **B4 预算线**（TECH_SPEC §8.2）：批验证（≥256 笔/批）摊薄 **≤ 100μs / 笔**。
- **已实测**（§5.5，CI 2 核共享 runner，`bb verify` CLI 进程）：单证明验证 **7.62ms p99**，
  含 CLI 进程启动开销（纯验证数学更小）。批验证摊薄当时记为「7.62ms/笔 CLI 上界；
  真批验证待 in-process wrapper」。
- **电路**：`spend_authorization`，`bb gates` circuit_size = **66,736**（含 sha256 intent_hash
  + pedersen Merkle + Jubjub EdDSA）。证明模式 UltraKeccakFlavor（`-t evm-no-zk`，keccak VK
  1888B）。

## 2. 批验证摊薄的技术分析

UltraPlonk/UltraHonk 单证明验证成本结构（按量级）：

| 成本项 | 量级 | 批验证能否均摊 |
|---|---|---|
| 多项式承诺 MSM（多标量乘） | **主导项**，O(#承诺 × 254bit) | **否**——每个证明的承诺点不同，桶不共享，主成本按笔保留 |
| 多配对合成（pairing / GT 幂） | 中 | **是**——N 个配对随机线性组合成 1 个，摊薄 |
| 验证者预处理 / setup / 预计算表 | 中 | **是**——同一 VK 共享，摊薄 |
| 证明反序列化 / 转录 / 标量域运算 | 低-中 | 部分——转录逐证明保留，域运算按笔保留 |

**结论（分析）**：批验证摊薄的是**固定成本**（配对合成、setup 共享、预处理），
**每证明的 MSM 主成本无法跨证明共享**。因此：

- 从 7.62ms **CLI 上界**出发（纯数学约 2-5ms），批验证（256 笔）现实的摊薄收益在
  **数倍**量级，约 **0.5-2ms / 笔**（分析估计，待实测），**不是**数量级式的 100μs。
- **≤100μs/笔 单靠 UltraPlonk 批验证不可达**（66k 约束电路的 MSM 主成本在那里）。

## 3. 达到 100μs/笔 的真实路径：递归聚合（Phase 2/4）

`std::recursion`（Noir）+ BB 递归验证：**N 笔 → 1 个聚合证明**，验证端只做一次聚合证明
验证，摊薄到近乎固定成本。这才是 §5.4 表格里「Phase 2 递归聚合 → 摊销到近乎固定成本」
的本意。批验证（v1.1）只是中途手段，先达一个改善过的摊薄线，**击穿 100μs 靠递归**。

递归聚合的代价（预研，Phase 4 实测确认）：
- 递归电路本身有固定约束开销（验证器电路，量级 ~数十万 gate，比单笔 66,736 大）；
  但**每笔摊薄**随聚合规模 N 下降，N=256 时单笔增量约束 ≈ 递归电路 / N。
- 需要 Borromean/honk recursion 工具链支持（BB nightly 已具备递归能力）。
- 聚合证明的验证仍是单次 UltraPlonk 验证（~ms 级），摊到 N 笔 → 100μs 量级可达。

## 4. 落地方案与门禁修订建议（S-18 实测后定局）

| 选项 | 手段 | 摊薄效果 | 结论（实测后） |
|---|---|---|---|
| A（先落地） | BB 原生批验证 + in-process wrapper（免 CLI 启动） | ~0.5-2ms/笔（分析） | **否决（实证）**：BB 6.0.0-nightly.20260724 的 CLI `batch_verify` 仅注册了帮助文本、实际执行 `No handler for subcommand batch_verify`；msgpack schema 亦仅有 `ChonkBatchVerify`（folding 栈，非本 flavor）——**BB 原生批验证对 UltraHonk（evm-no-zk keccak）客观不可用** |
| A'（半项） | 仅 in-process wrapper（拿掉 CLI 启动） | **上界 ~15%（0.77ms/笔）** | 收益有限（实测分解见 §5）：CLI 进程开销 p50 仅 0.77ms / 15.5%，纯验证数学 ≈4.21ms 才是主导（MSM）——**推翻本文件初稿"CLI 开销占比显著"的假设** |
| B（击穿线） | 递归聚合 N 笔 → 1 证明 | 近固定成本 / N → **100μs 可达** | Phase 2/4 立项，本步只预研（维持） |
| **C（诚实修订）** | **修订 B4 预算线**：实线 = 单验证 CLI 上界 4983.8μs/笔（参考机 32 核）；≤100μs/笔 挂递归聚合里程碑（Phase 2/4） | — | **已执行**（TECH_SPEC §8.2 / §5.5 已回填） |

## 5. 实测前置条件（待环境）

## 5. 实测（S-18 收尾，2026-08-29，参考机 = 本机 WSL2）

- **环境**：Win11 Home + WSL2（Ubuntu 24.04 rootfs，D:\WSL VHD），**32 核 / 15G**；
  nargo 1.0.0-beta.26 + bb 6.0.0-nightly.20260724（与 circuits/README 配对一致）。
  此前 Windows 侧缺的 VirtualMachinePlatform feature 经 DISM 启用 + 重启后落地。
  （曾评估借 neuralzoo Linux 服务器，老板拍板不部署生产服务器、只用本机。）
- **门禁真跑**：`smoke_zk.sh` 5/5（prove 98.66MiB → verify ultra_honk 32 线程 →
  公共输入回读 97 fields → 负向篡改正确拒绝）+ `formal_zk.sh` 8/8（gen-witness →
  prove/verify/公共输入回读(121)/负向篡改/B2/B3/B4 计时 + 约束门禁 66736 < 2^18 →
  `write_solidity_verifier` UltraKeccakFlavor EVM 验证器）。
- **B2/B3/B4 参考机实测**（`circuits/bench/baseline_s09.json`，本机不入库）：

  | 项 | CI 2 核（旧基线） | 参考机 32 核（S-18 实测） |
  |---|---|---|
  | B2 prove p50 | 1.8457s | **0.325s**（目标 <1s PASS） |
  | B3 verify p99 | 7.62ms | **5.14ms**（目标 <10ms PASS） |
  | B4 摊薄 CLI 上界 | 7623.4μs/笔 | **4983.8μs/笔** |

- **延迟分解（40 轮，python 计时 subprocess）**：

  | 项 | p50 | 占比 |
  |---|---|---|
  | `bb --version`（进程 + 库初始化，无数学） | 0.77ms | **15.5%** |
  | `bb verify`（全流程） | 4.97ms | 100% |
  | 纯验证数学上界（含 vk/proof IO） | ≈4.21ms | 主导（MSM） |

- **批验证接口实证**：`bb batch_verify --help` 存在（"Batch-verify multiple Chonk
  proofs"）但执行即 `No handler for subcommand batch_verify`——帮助文本注册了 handler
  没实现；msgpack schema 全量扫（`bb msgpack schema`）仅有 `ChonkBatchVerify` /
  `ChonkBatchVerifier{Start,Queue,Stop}`，无任何 UltraHonk 批验证入口。

## 6. 结论一句话

**初稿的批验证路线实测后关闭**：BB 原生批验证对 UltraHonk 不存在（实证），in-process
wrapper 收益上界仅 ~15%（CLI 开销 0.77ms/15.5%，MSM 纯数学才是主导）——**100μs/笔 只能
靠递归聚合（Phase 2/4）**；C 选项诚实修订已执行（B4 实线 = 单验证 CLI 上界 4983.8μs/笔
参考机实测，≤100μs 挂递归里程碑），不凑数。
