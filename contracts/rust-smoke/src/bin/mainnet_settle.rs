//! Base 主网真跑侧车（S-79）：S-77 修复版 BatchSettler（名册 #2）全生命周期真钱演示。
//!
//! 主网不可 warp，6h 挑战窗必须真等 → 两阶段分次运行：
//!
//!   --phase commit --settler <addr> --state <path> [--bond <wei>]
//!       真意图入账（内存 WAL：收款人 = 运营者签名者自址 ×5 ×200 wei）→ 显式密封
//!       → settle_epoch → 链下重算根自检（m1_demo C 段同款）→ 链上
//!       commit{value: bond} → settle{value: Σnet} → 结算快照落盘（--state）。
//!
//!   --phase claim --state <path>
//!       读链上 settledAt 验挑战窗（未到窗即退出并报剩余秒数）→ 逐行 claim
//!       （结算合约余额断言）→ releaseBond（债券退回断言，S-77 新面）→ 全量对账单。
//!
//! 余额断言走**合约侧**（get_balance(settler)）而非收款人侧：本跑收款人 = 运营者自址
//! = 交易签名者，收款人余额差会被同笔 tx 的 gas 扣减污染；合约余额无 gas 参与（前提：
//! 实例新启、只承载本 epoch 的 bond + Σnet，claim 前显式断言）。
//!
//! 诚实边界（与既有 demo 侧车同口径）：
//!   ① 证明缝 = FormatVerifier 占位（真 ZK prover 是独立缝，m1_demo/noir_demo 覆盖）；
//!   ② 委托不上链登记（demo_settle 定夺 ④：commit/settle/claim 不消费 DSA 登记状态）；
//!   ③ 委托 owner = 运营者签名者本钥派生（owner 身份与链上 operator 同一把钥，非托管：
//!      资金只进出运营者自址与结算合约）；agent = 演示钥 fixture；
//!   ④ 金额标度 = 账本 amount 与链上 wei 同一标度（m1_demo E 段先例，§6.16）。
//!
//! 绝不进 verify.sh 执行面（真钱）；门禁只覆盖编译面（fmt/clippy/build）。
//!
//! 环境变量：MIST_RPC_URL（缺省回退旧名 MERIDIAN_RPC_URL——S-71 保留项）+
//! MIST_OPERATOR_KEY（同回退）。私钥只读不打印。
//!
//! 用法（本 crate 为独立 workspace）：
//!   cargo run --release --manifest-path contracts/rust-smoke/Cargo.toml -- \
//!     --bin mainnet_settle -- --phase commit --settler 0x… --state /tmp/mist-mainnet-run.json
//!   （真等 6h 挑战窗后）
//!   cargo run --release --manifest-path contracts/rust-smoke/Cargo.toml -- \
//!     --bin mainnet_settle -- --phase claim --state /tmp/mist-mainnet-run.json

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use mist_aggregator::ingest::{Aggregator, IngestConfig};
use mist_aggregator::lattice;
use mist_aggregator::merkle::{leaf as merkle_leaf, merkle_root};
use mist_aggregator::proof::FormatVerifier;
use mist_aggregator::wal::Wal;
use mist_core::dsa::{self, AgentSigningKey, Delegation, RateLimit};

use contract_smoke::common::*;

/// commit 债券缺省值（协议无最低值，commit 时自选——老板口径「少一点」取 0.0005 ETH；
/// 诚实演示：真钱托管 6 小时，事后经 S-77 releaseBond 原额退回）。
const DEFAULT_BOND_WEI: u128 = 500_000_000_000_000;
/// 真意图批次：5 笔 × 200 wei（Σnet = 1000 wei，结算资金同额注资、claim 后回笼）。
const N_INTENTS: u64 = 5;
const AMOUNT_PER_INTENT: u64 = 200;
/// 委托预算（≥ Σ amounts 即可，留余量）。
const TOTAL_CAP: u64 = 10_000;
/// gas 余量（wei）：commit/settle/claim/release 四笔 gas 的宽裕上界。
const GAS_MARGIN_WEI: u128 = 10_000_000_000_000;

fn system_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

/// deploy.rs env_or 同款（bin 本地件，bin 间不互引）。
fn env_or(key: &str, fallback_key: &str) -> Result<String> {
    std::env::var(key)
        .or_else(|_| std::env::var(fallback_key))
        .with_context(|| format!("缺环境变量 {key}（或旧名 {fallback_key}）"))
}

/// 运营者签名者 + RPC URL（私钥只读不打印；S-71 新名 → 旧名回退）。
fn signer_and_rpc() -> Result<(PrivateKeySigner, String)> {
    let key = env_or("MIST_OPERATOR_KEY", "MERIDIAN_OPERATOR_KEY")?;
    let rpc = env_or("MIST_RPC_URL", "MERIDIAN_RPC_URL")?;
    let signer: PrivateKeySigner = key.parse().context("解析 OPERATOR_KEY 失败")?;
    Ok((signer, rpc))
}

struct Args {
    phase: String,
    settler: Option<Address>,
    state: PathBuf,
    bond: u128,
}

fn parse_args() -> Result<Args> {
    let argv: Vec<String> = std::env::args().collect();
    let mut phase = None;
    let mut settler = None;
    let mut state = None;
    let mut bond = DEFAULT_BOND_WEI;
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--phase" => {
                phase = Some(argv.get(i + 1).context("--phase 缺值")?.clone());
                i += 2;
            }
            "--settler" => {
                let v = argv.get(i + 1).context("--settler 缺值")?;
                settler = Some(
                    v.parse::<Address>()
                        .with_context(|| format!("--settler {v} 地址解析失败"))?,
                );
                i += 2;
            }
            "--state" => {
                state = Some(PathBuf::from(argv.get(i + 1).context("--state 缺值")?));
                i += 2;
            }
            "--bond" => {
                bond = argv
                    .get(i + 1)
                    .context("--bond 缺值")?
                    .parse::<u128>()
                    .context("--bond 须为 wei 数值")?;
                i += 2;
            }
            other => bail!("未知参数 {other}"),
        }
    }
    let phase = phase.context("缺 --phase（commit | claim）")?;
    let state = state.context("缺 --state <path>")?;
    Ok(Args {
        phase,
        settler,
        state,
        bond,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    match args.phase.as_str() {
        "commit" => commit_phase(args).await,
        "claim" => claim_phase(args).await,
        p => bail!("未知 phase：{p}（commit | claim）"),
    }
}

/// 读回重试（deploy.rs read_retry 同款）：公共 RPC 负载均衡滞后节点写后读假 revert 的
/// 彩排修复遗产；真 revert 照样上抛。
async fn read_retry<T, F, Fut>(mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    const RETRIES: usize = 5;
    for attempt in 0..RETRIES {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt + 1 < RETRIES => {
                eprintln!(
                    "  ⚠ RPC 读回失败（滞后节点？重试 {}/{}）：{e}",
                    attempt + 1,
                    RETRIES - 1
                );
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("重试循环必在 RETRIES 次内返回")
}

/// 当前链头时间戳（verifier_drill 同款）。
async fn latest_timestamp<P: Provider>(provider: &P) -> Result<u64> {
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .context("latest block 不存在")?;
    Ok(block.header.timestamp)
}

/// owner DID = keccak(uncompressed pubkey)[12..]（m1_demo 同款派生）。
fn did_of(key: &dsa::OwnerSigningKey) -> [u8; 20] {
    let encoded = key.verifying_key().to_encoded_point(false);
    let hash = alloy::primitives::keccak256(&encoded.as_bytes()[1..]);
    hash[12..].try_into().expect("keccak 输出 32B 取尾 20B")
}

// ---------------------------------------------------------------------------
// commit 阶段：账本 → 密封 → 结算 → 链上 commit/settle → 快照落盘
// ---------------------------------------------------------------------------

async fn commit_phase(args: Args) -> Result<()> {
    let settler_addr = args.settler.context("commit 阶段需要 --settler <addr>")?;
    let (signer, rpc) = signer_and_rpc()?;
    let operator = signer.address();

    // ---- 账本：真意图入账（内存 WAL；RSM 语义与 demo 侧车同源）----
    let now = system_now();
    let wal_path = std::env::temp_dir().join(format!("mist-mainnet-{}.wal", std::process::id()));
    let wal = Wal::open(&wal_path, 1_000).context("open wal")?;
    let agg = Aggregator::new(IngestConfig::default(), Box::new(FormatVerifier), wal);

    // 委托 owner = 运营者本钥（同一标量派生同址——m1_demo「owner_did == 派生地址」
    // 断言的 live 版）；agent = 演示钥（fixture，诚实边界 ①③）。
    let owner_bytes: [u8; 32] = signer.credential().to_bytes().into();
    let owner_key = dsa::owner_signing_key_from_bytes(owner_bytes);
    assert_eq!(
        did_of(&owner_key),
        operator.into_array(),
        "owner 派生地址必须 == 运营者签名者地址"
    );
    let d = Delegation {
        agent: [0x01; 20],
        owner: did_of(&owner_key),
        nonce: 1,
        max_per_spend: AMOUNT_PER_INTENT,
        rate: RateLimit {
            window_secs: 3600,
            max_per_window: TOTAL_CAP,
        },
        total_cap: TOTAL_CAP,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
        version: dsa::PROTOCOL_VERSION,
    };
    let dh = dsa::delegation_hash(&d);
    let sd = dsa::sign_delegation(&d, &owner_key);
    let agent_key = AgentSigningKey::from_bytes(&AGENT_KEY_BYTES);
    agg.register(sd, agent_key.verifying_key());

    for i in 0..N_INTENTS {
        let env = make_env(
            dh,
            [0x01; 20],
            &agent_key,
            operator.into_array(),
            AMOUNT_PER_INTENT,
            i,
            now,
        );
        let r = agg.submit(&env);
        assert!(r.accepted, "第 {i} 笔必须被接受（收款人 = 运营者自址）");
    }
    println!(
        "OK mainnet-settle: 账本入账 {N_INTENTS} 笔 × {AMOUNT_PER_INTENT} wei（收款人 = 运营者自址）"
    );

    // ---- 显式密封当前尾（demo_settle 定夺 ②：epoch_secs=0）----
    let sealed = agg.seal_expired(system_now(), 0);
    if sealed.len() != 1 {
        bail!("密封得 {} 个 epoch（预期恰 1）", sealed.len());
    }
    let entries = sealed[0].entries.clone();
    let res = agg.settle_epoch(&sealed[0]).context("settle epoch")?;
    let sum_net: u128 = res.net.iter().map(|l| l.amount as u128).sum();

    // ---- 链下重算根自检（m1_demo C 段同款）----
    let leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|e| merkle_leaf(e.seq, e.intent_hash))
        .collect();
    assert_eq!(
        merkle_root(&leaves),
        res.commitment_root,
        "承诺根链下重算必须与内核同根"
    );
    assert_eq!(
        lattice::netting_root(&res.net),
        res.netting_root,
        "净额根链下重算必须与内核同根"
    );
    println!(
        "OK mainnet-settle: 密封 epoch {}（{} 笔意图 → {} 收款人，Σnet={sum_net} wei）+ 根自检绿",
        res.epoch_id,
        entries.len(),
        res.net.len()
    );

    // ---- 链上 ----
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(rpc.parse()?);
    let onchain_operator = read_retry(|| async {
        IBatchSettler::new(settler_addr, &provider)
            .operator()
            .call()
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    })
    .await
    .context("读 settler.operator()")?;
    // 运营者守卫：签名者必须 == settler.operator()（否则 commit 恒 NotOperator）。
    if onchain_operator != operator {
        bail!("签名者 {operator:?} != settler.operator() {onchain_operator:?}——commit 必被拒");
    }
    let bond_u256 = U256::from(args.bond);
    let balance = provider.get_balance(operator).await.context("读余额")?;
    if balance < U256::from(args.bond + sum_net + GAS_MARGIN_WEI) {
        bail!(
            "余额 {balance} 不足以覆盖 bond({}) + Σnet({sum_net}) + gas 余量({GAS_MARGIN_WEI})",
            args.bond
        );
    }

    let commit_receipt = IBatchSettler::new(settler_addr, &provider)
        .commit(
            U256::from(res.epoch_id),
            B256::from(res.commitment_root),
            B256::from(res.revocation_root),
            B256::from(res.acceptance_root),
            res.sealed_at,
        )
        .value(bond_u256)
        .send()
        .await
        .context("commit send")?
        .get_receipt()
        .await
        .context("commit receipt")?;
    println!(
        "OK mainnet-settle: commit tx {}（bond {} wei 托管）",
        commit_receipt.transaction_hash, args.bond
    );

    let settle_receipt = IBatchSettler::new(settler_addr, &provider)
        .settle(
            U256::from(res.epoch_id),
            to_net(&res),
            B256::from(res.netting_root),
        )
        .value(U256::from(sum_net))
        .send()
        .await
        .context("settle send")?
        .get_receipt()
        .await
        .context("settle receipt")?;
    println!(
        "OK mainnet-settle: settle tx {}（结算资金 {sum_net} wei）",
        settle_receipt.transaction_hash
    );

    // ---- 快照落盘（claim 阶段输入 + 对账单底稿）----
    let state = json!({
        "settler": format!("{settler_addr:?}"),
        "operator": format!("{operator:?}"),
        "epoch_id": res.epoch_id,
        "bond_wei": args.bond.to_string(),
        "sum_net_wei": sum_net.to_string(),
        "commitment_root": hex::encode(res.commitment_root),
        "revocation_root": hex::encode(res.revocation_root),
        "acceptance_root": hex::encode(res.acceptance_root),
        "netting_root": hex::encode(res.netting_root),
        "sealed_at": res.sealed_at,
        "net": res
            .net
            .iter()
            .map(|l| json!({
                "recipient": hex::encode(l.recipient),
                "amount_wei": l.amount.to_string()
            }))
            .collect::<Vec<_>>(),
        "tx_commit": format!("{:?}", commit_receipt.transaction_hash),
        "tx_settle": format!("{:?}", settle_receipt.transaction_hash),
        "committed_at_unix": system_now(),
    });
    write_state(&args.state, &state)?;
    println!(
        "OK mainnet-settle: 快照已落盘 {}（6h 挑战窗后跑 --phase claim）",
        args.state.display()
    );
    Ok(())
}

fn write_state(path: &Path, state: &Value) -> Result<()> {
    if path.exists() {
        bail!("{} 已存在——拒绝覆盖（换路径或手工清理）", path.display());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
    }
    let pretty = serde_json::to_string_pretty(state)?;
    std::fs::write(path, pretty + "\n").with_context(|| format!("写快照 {}", path.display()))
}

// ---------------------------------------------------------------------------
// claim 阶段：验窗 → 逐行 claim（合约余额断言）→ releaseBond（债券退回断言）→ 对账单
// ---------------------------------------------------------------------------

async fn claim_phase(args: Args) -> Result<()> {
    let raw = std::fs::read_to_string(&args.state)
        .with_context(|| format!("读快照 {}", args.state.display()))?;
    let st: Value = serde_json::from_str(&raw).context("快照 JSON 解析")?;
    let settler_addr: Address = st["settler"]
        .as_str()
        .context("快照缺 settler")?
        .parse()
        .context("settler 地址解析")?;
    let operator: Address = st["operator"]
        .as_str()
        .context("快照缺 operator")?
        .parse()
        .context("operator 地址解析")?;
    let epoch_id = st["epoch_id"].as_u64().context("快照缺 epoch_id")?;
    let bond: u128 = st["bond_wei"]
        .as_str()
        .context("快照缺 bond_wei")?
        .parse()
        .context("bond_wei 解析")?;
    let sum_net: u128 = st["sum_net_wei"]
        .as_str()
        .context("快照缺 sum_net_wei")?
        .parse()
        .context("sum_net_wei 解析")?;
    let net: Vec<(Address, u128)> = st["net"]
        .as_array()
        .context("快照缺 net")?
        .iter()
        .map(|l| {
            Ok((
                l["recipient"]
                    .as_str()
                    .context("net 行缺 recipient")?
                    .parse()?,
                l["amount_wei"]
                    .as_str()
                    .context("net 行缺 amount_wei")?
                    .parse()?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    let (signer, rpc) = signer_and_rpc()?;
    let signer_addr = signer.address();
    if signer_addr != operator {
        bail!(
            "签名者 {signer_addr:?} != 快照 operator {operator:?}——claim/release 均为 onlyOperator"
        );
    }
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(rpc.parse()?);
    let settler = IBatchSettler::new(settler_addr, &provider);

    // ---- 状态位 + 窗口验证（真等：未到窗即报剩余时间退出）----
    let view = read_retry(|| async {
        settler
            .epochs(U256::from(epoch_id))
            .call()
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    })
    .await
    .context("读 epochs()")?;
    let status = read_retry(|| async {
        settler
            .epochStatus(U256::from(epoch_id))
            .call()
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    })
    .await
    .context("读 epochStatus()")?;
    if !status.settled || status.challenged || status.voided {
        bail!(
            "epoch {epoch_id} 状态异常：settled={} challenged={} voided={}",
            status.settled,
            status.challenged,
            status.voided
        );
    }
    let window: u64 = read_retry(|| async {
        let v = settler
            .CHALLENGE_WINDOW()
            .call()
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        u64::try_from(v).map_err(|_| anyhow::anyhow!("CHALLENGE_WINDOW 溢出 u64"))
    })
    .await
    .context("读 CHALLENGE_WINDOW()")?;
    let now = latest_timestamp(&provider).await?;
    let unlock = view.settledAt.saturating_add(window);
    if now < unlock {
        bail!(
            "挑战窗未过：还剩 {} 秒（{} 解锁）——到点后重跑 --phase claim",
            unlock - now,
            humantime(unlock)
        );
    }
    println!(
        "OK mainnet-settle: 窗已过（settledAt={} window={window}s now={now}）bonded={} wei",
        view.settledAt, view.bondedAmount
    );

    // ---- 实例隔离前提（合约侧余额断言的地基）：只承载本 epoch 的 bond + Σnet ----
    let contract_before = provider.get_balance(settler_addr).await?;
    let expected = U256::from(bond + sum_net);
    assert_eq!(
        contract_before, expected,
        "合约余额必须是 bond+Σnet（新启实例单 epoch 前提）——否则换用逐 epoch 记账口径"
    );

    // ---- 逐行 claim（合约余额减量 == 行净额）----
    let mut claim_txs = Vec::new();
    for (idx, (recipient, amount)) in net.iter().enumerate() {
        let receipt = settler
            .claim(U256::from(epoch_id), U256::from(idx as u64))
            .send()
            .await
            .with_context(|| format!("claim #{idx} send"))?
            .get_receipt()
            .await
            .with_context(|| format!("claim #{idx} receipt"))?;
        let after = provider.get_balance(settler_addr).await?;
        let delta = contract_before - after;
        assert_eq!(
            delta,
            U256::from(*amount),
            "claim #{idx} 合约必须精确支出净额"
        );
        println!(
            "OK mainnet-settle: claim #{idx} tx {} → {recipient:?} 收 {amount} wei（合约余额断言绿）",
            receipt.transaction_hash
        );
        claim_txs.push(format!("{:?}", receipt.transaction_hash));
    }

    // ---- S-77 releaseBond：债券原额退回运营者（happy path 收口）----
    let release_receipt = settler
        .releaseBond(U256::from(epoch_id))
        .send()
        .await
        .context("releaseBond send")?
        .get_receipt()
        .await
        .context("releaseBond receipt")?;
    let bonded_after = settler
        .epochs(U256::from(epoch_id))
        .call()
        .await
        .context("release 后读 epochs()")?
        .bondedAmount;
    assert_eq!(bonded_after, U256::ZERO, "bond 必须清零");
    let after_release = provider.get_balance(settler_addr).await?;
    assert_eq!(
        after_release,
        U256::ZERO,
        "合约必须被排干（bond 已退运营者）"
    );
    println!(
        "OK mainnet-settle: releaseBond tx {} → 债券 {bond} wei 原额退回（记账清零 + 合约排干断言绿）",
        release_receipt.transaction_hash
    );

    // ---- 全量对账单 ----
    println!("── 主网真跑对账单 ──────────────────────────────");
    println!("settler #2: {settler_addr:?}");
    println!("commit  tx: {}", st["tx_commit"].as_str().unwrap_or("?"));
    println!("settle  tx: {}", st["tx_settle"].as_str().unwrap_or("?"));
    for (idx, tx) in claim_txs.iter().enumerate() {
        println!("claim#{idx} tx: {tx}");
    }
    println!("release tx: {:?}", release_receipt.transaction_hash);
    println!(
        "资金面：bond {bond} wei 托管 {} 秒后原额退回；Σnet {sum_net} wei 已付收款人",
        unlock - view.committedAt
    );
    Ok(())
}

/// Unix 秒 → `YYYY-MM-DD HH:MM UTC`（无 chrono 依赖，纯 UTC 换算；civil-from-days
/// Howard Hinnant 算法）。
fn humantime(unix: u64) -> String {
    let days = unix / 86_400;
    let secs = unix % 86_400;
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        secs / 3600,
        (secs % 3600) / 60
    )
}
