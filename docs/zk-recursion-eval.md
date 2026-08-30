# ZK 递归聚合评估（S-55 代码侧先行）

> 状态：**实测收口（2026-08-30）**。先行文档（先改后码）：在动 Phase 2 递归聚合这块
> 大砖之前，回答「本 nightly 的递归栈能否折叠 spend_authorization、每折成本多少、
> 离 100μs/笔 有多远」。先例 = `docs/zk-batch-verify-eval.md`（S-18）。
> 工具链：nargo 1.0.0-beta.26 + bb 6.0.0-nightly.20260724，参考机 = 本机 WSL2（32 核 / 15G）。

## 1. 目标线与现状

- **B4 预算线**（TECH_SPEC §8.2，S-18 诚实修订）：实线 = 单验证 CLI 上界 **4983.8μs/笔**
  （参考机 32 核）；**≤ 100μs/笔 挂递归聚合里程碑（Phase 2/4）**——即本文要评估的路径。
- **电路**：`spend_authorization`（S-36 全宽化后 `bb gates` circuit_size = 82,742，
  UltraKeccakFlavor evm-no-zk 口径）。
- **问题**：S-18 扫源只确认了 `ChonkBatchVerify` 的存在（folding 栈的批量验证入口），
  没有回答折叠栈本身能否用。本文补齐。

## 2. 递归栈扫源（Aztec barretenberg，与本地 bb 配对的 nightly）

本次全量读源（`gh api repos/AztecProtocol/barretenberg/contents/...`，本地留存于
git-ignored 的 `circuits/target/zkeval/`）：`bbapi_chonk.cpp/hpp`、`chonk_step_processor.cpp`、
`chonk.cpp`、`private_execution_steps.cpp/hpp`、`circuit_input.hpp`、`api_chonk.cpp`、`cli.cpp`。

- **S-18 结论修正**：本 nightly 的 ClientIVC（Chonk）folding 栈**完整存在**，msgpack API 面
  远不止批验证——`ChonkStart / ChonkLoad / ChonkAccumulate / ChonkProve / ChonkVerify /
  ChonkVerifyFromFields / ChonkBatchVerify / ChonkCompressProof / ChonkStats /
  ChonkComputeVk / ChonkCheckPrecomputedVk / ChonkBatchVerifier{Start,Queue,Stop}`。
- **两条装配路线**：① CLI `bb prove --scheme chonk --ivc_inputs_path <msgpack>`，输入 =
  `PrivateExecutionStepRaw` 数组 `{bytecode, witness, vk, functionName, kind}`（bytecode/witness
  到手为 gzip，CLI 内部 gunzip）；② `bb msgpack run` 逐命令会话（自建 python 客户端驱动，
  见 §3 方法）。栈约束：**≥4 个电路、首个必须 App、HidingKernel 只能在末位**。

## 3. 实证（S-55，参考机 32 核 WSL2）

**方法**：bb 的 msgpack 帧协议无文档，自建纯 python 客户端逆向收口——帧 = `uint32 LE 长度 +
msgpack 缓冲`，请求 = `[[CommandName, {camelCase fields}]]`，响应流 = `[ResponseName, {fields}]`
逐帧；`vector<unsigned char>` 走 msgpack bin、`CircuitKind` 走整数（App=0/HidingKernel=2）。
msgpack API 路径的 bytecode/witness 需要**解压后的 bincode**（只有 CLI 路径内部 gunzip）——
这是本次最大的非显然坑，对照 `private_execution_steps.cpp`（CLI 解压）与 `bbapi_chonk.cpp`
（API 直接消费）确认。VK 由 `ChonkComputeVk` 派生后内嵌（不内嵌则在 prove 期报
"precomputed VK is required"）。

### 3.1 可折叠性：✅ 栈接受本电路

`ChonkLoad` + `ChonkAccumulate`（含预计算 VK）对 `spend_authorization` **全部通过**——
MegaZK flavor 的 folding 栈能吃我们的电路，无约束兼容性问题。

### 3.2 成本实测

| 项 | 实测 |
|---|---|
| `ChonkComputeVk`（app） | **0.549s**，VK = **4832B**（MegaZK poseidon2） |
| `ChonkComputeVk`（hiding_min 占位电路） | 0.020s，VK = 3808B |
| 折叠会话 N=3（3 app + 1 hiding = 4 折） | **2.37s** |
| 折叠会话 N=7（7 app + 1 hiding = 8 折） | **6.38s** |
| **边际折叠成本** | **≈ 1.0s / 折**（两点线性） |
| 内存 | ~260MB（4 电路 CLI 会话） |
| `ChonkStats`（Mega 口径） | acir_opcodes = **15,819**，circuit_size = **82,338**（vs UltraKeccak 口径 82,742） |

### 3.3 三处硬阻断（实证，非"没调通"）

1. **ChonkProve 被规范 hiding kernel ABI 卡死**：末步报
   `HIDING_KERNEL_ULTRA_OPS: 0 vs 363`（op 队列子表大小断言）。用最小占位电路
   （`assert(x != y)` 两个门）替换末步**同样复现**——即 ChonkProve 要求末位 hiding
   电路的形状严格等于 Aztec client-IVC 的规范 hiding kernel（363 个 ultra op），
   独立 Noir 仓库开箱不可用。
2. **链长上限 8 折**：N=7（8 折）通过，N≥8 个 app 折叠即触发 sumcheck
   `round_number < 256U` 断言（256 越界；错误数随 N 增长，N=14 时 6 个）。根因未深挖
   （疑似与同电路重复折叠的轮次累积相关），但即使绕开阻断 ①，长链聚合也被此卡死。
3. **无 EVM 缝**：`ChonkAPI::write_solidity_verifier` 在本 nightly 是
   `throw_or_abort("API function contract not implemented")`——Chonk 证明**没有 Solidity
   验证器**，进不了 L2 链上验证器（我们的结算缝）。

### 3.4 flavor 错位（第四处结构性代价）

生产证明是 UltraKeccakFlavor evm-no-zk（VK 1888B，UltraVerifier.sol keccak）；Chonk 走
Mega/MegaZK poseidon2（app VK 4832B、hiding VK 3808B）。上递归 = **全链 flavor 重基**：
电路 prove/verify、公共输入口径、EVM 验证器全部重做，且丢掉 evm-no-zk 的链上友好性
（MegaZK 需 poseidon2 precompile 生态，keccak 验证器路线不复用）。

## 4. 落地方案表（实测后定局）

| 选项 | 手段 | 结论（实测后） |
|---|---|---|
| A | 用本 nightly Chonk 装配递归聚合 | **否决（实证）**：阻断①②③ + flavor 重基，四项独立成立，任一项单独即致不可交付 |
| B | 等上游开放（Aztec 解耦 hiding kernel ABI / 开放独立 folding API / 实现 chonk solidity verifier） | **Phase 2 挂监控**：阻断①②属于 ABI 耦合而非数学缺失（Load/Accumulate 已证明栈能吃我们的电路），上游动向值得跟 |
| **C（诚实修订，已执行）** | B4 里程碑标注 **blocked-on-upstream**：v1/v1.1 实线维持 4983.8μs/笔，吞吐靠 v1 非阻塞异步并发验证；100μs/笔 不再假设递归在本工具链可达 | **已回填**（TECH_SPEC §5.4/§8.2） |

## 5. 100μs/笔 的算术（即使三处阻断全修）

- 边际折叠 ≈ **1.0s/折**，摊薄到 N 笔 → 100μs/笔 需要 **N ≥ 10⁴** 条电路折进一个栈；
  而实测链长上限是 **8 折**（§3.3②）——差 3 个数量级。
- 生成侧：10⁴ 折 × 1.0s ≈ **2.8 小时/聚合证明**（即便链长不限）。
- 量级倒挂：1 折 ≈ 1.0s，而单证明直验仅 5.14ms——**folding 每折成本 ≈ 200× 单笔直验**。
  在我们这个"验证端摊薄"场景里，递归只有把 N 万笔折成一证才回本；N=8 的链反而
  6.38s/7 ≈ 0.91s/笔，比直验**差 176 倍**。
- 结论：这不是工程调优问题（并行、缓存都救不了 3 个数量级 × 2.8 小时 × 无 EVM 缝），
  是**本工具链下路线客观不可行**。

## 6. 结论一句话

**递归聚合路线在本 nightly 实测后关闭（blocked-on-upstream）**：Chonk 栈能折叠
spend_authorization（可折叠性 ✅）但 ChonkProve 被规范 hiding kernel ABI 卡死（363 op
断言）、链长限 8 折、无 Solidity 验证器、且 MegaZK 重基丢掉 evm-no-zk——即使全修，
1.0s/折 的边际成本也要 N≥10⁴ 才击穿 100μs/笔，而链长上限 8。B4 实线维持 4983.8μs/笔
（异步并发验证撑吞吐），**不凑数**。工具链脚本（msgpack 客户端 / 会话驱动）留存于
git-ignored 的 `circuits/target/zkeval/`，阻断解除后再提升为 `scripts/`。
