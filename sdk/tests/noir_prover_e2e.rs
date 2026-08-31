//! S-43 真 prover 端到端（TECH_SPEC §6.14）：SDK 委托/意图 + 聚合器撤销集非成员
//! witness（S-42 产出）→ [`NoirProver`] 真电路证明（Noir oracle 曲线数学 + 电路
//! 断言 1-9 自校验 + bb prove）→ `BbVerifier`（§6.13 验证后端）密码学接受；负向：
//! 篡改 proof / 篡改公共输入皆 `E_PROOF`。
//!
//! 这是 §4.6 残余②「电路消费交叉锚」的实证：电路吃**聚合器出的撤销路径**重算根并与
//! 公共输入 `revocation_root` 对账，全链真 ZK。
//!
//! 门控：`MIST_ZK_PROVER_E2E=1` 才跑（verify.sh 步 9c，紧随 9b；CI noir job
//! 同款）。工件依赖第 9 步 formal_zk 产出的 `circuits/target/spend_authorization.json`
//! （bb 字节码）与 `circuits/target/vk`；缺失则显式打印跳过原因（不静默成功）。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mist_aggregator::bb::{BbBackend, BbVerifier};
use mist_aggregator::ingest::{Aggregator, IngestConfig};
use mist_aggregator::revocation::RevocationSet;
use mist_aggregator::wal::Wal;
use mist_core::attestation::agent_commit;
use mist_core::error::Error;
use mist_core::zk::{SpendProofRequest, SpendProver, SpendVerifier};
use mist_sdk::identity::{create_delegation, AgentWallet, DelegationLimits};
use mist_sdk::prover::NoirProver;
use mist_sdk::{InProcessAggregator, PayParams, SdkClient};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("sdk/ 的上级即仓库根")
        .to_path_buf()
}

/// prove 重操作串行锁（测试文件内）：NoirProver 的进程级互斥是**实例级**（自有 `Mutex`），
/// 而临时 witness 文件 `gen-witness/ProverSDK.toml` / `circuits/ProverSDK.toml` 是**路径级
/// 共享**——两条 prove 测试并行跑会互相踩写。cargo test 默认并行，必须在测试体串行。
static PROVE_LOCK: Mutex<()> = Mutex::new(());

fn prove_guard() -> std::sync::MutexGuard<'static, ()> {
    PROVE_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn artifact(root: &Path, rel: &str, why: &str) -> Option<Vec<u8>> {
    match std::fs::read(root.join(rel)) {
        Ok(b) => Some(b),
        Err(_) => {
            println!("SKIP: {rel} 不存在（{why}）");
            None
        }
    }
}

#[test]
fn noir_prover_e2e_real_proof_via_aggregator_revocation() {
    if std::env::var("MIST_ZK_PROVER_E2E").as_deref() != Ok("1") {
        println!("SKIP: MIST_ZK_PROVER_E2E=1 未设（prove 侧重操作，不进默认 cargo test）");
        return;
    }
    // 临时 witness 文件路径级共享（见 PROVE_LOCK 注释）——跨测试串行。
    let _prove_serial = prove_guard();
    let root = repo_root();
    let _bytecode = match artifact(
        &root,
        "circuits/target/spend_authorization.json",
        "formal_zk 未跑",
    ) {
        Some(b) => b,
        None => return,
    };
    let vk = match artifact(&root, "circuits/target/vk", "formal_zk 未跑") {
        Some(b) => b,
        None => return,
    };
    let backend = match BbBackend::detect() {
        Some(b) => b,
        None => {
            println!("SKIP: bb 工具链不可得（Windows 原生与 WSL 兜底皆无）");
            return;
        }
    };

    // ——— SDK 委托 + 意图（真实授权上下文，非手搓 fixture）———
    let wallet = AgentWallet::from_seed([0xA5u8; 32]);
    let owner_key = mist_core::dsa::owner_signing_key_from_bytes([0x0Fu8; 32]);
    let limits = DelegationLimits {
        max_per_spend: 5_000,
        rate_window_secs: 60,
        rate_max_per_window: 20_000,
        total_cap: 100_000,
        categories: vec![], // 空白名单：电路断言 4 不要求类别（S-09 口径）
        not_before: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    let sd = create_delegation(&owner_key, [0x0Bu8; 20], 1, &limits).expect("delegation");
    let dh = mist_core::dsa::delegation_hash(&sd.delegation);
    let (intent, _agent_sig) = wallet.create_intent(
        sd.delegation.agent,
        dh,
        [0x9Cu8; 20],
        4_200,
        [0xC0; 32],
        7, // spend_nonce > 0（电路断言 7）
        None,
        1_800_000_000,
    );

    // ——— 聚合器撤销集（真实撤销事件）→ 非成员 witness（S-42 直出）———
    let revocations = RevocationSet::new();
    let mut other = [0x5Eu8; 32];
    other[31] = 0x01;
    revocations.insert(other); // 撤销另一张委托：目标 dh 仍非成员
    let witness = revocations
        .non_membership_witness(&dh)
        .expect("目标委托未撤销，必有非成员 witness");

    // ——— 真 prover（NoirProver，§6.14 六步链）———
    let prover = NoirProver::from_repo_root(&root).expect("noir 工具链可得（原生或 WSL 兜底）");
    let secret = {
        // attestation 私钥标量（LE 不透明字节）= 0xDEADBEEF（< EdDSA 子群阶，合法私钥）。
        let mut s = [0u8; 32];
        s[0] = 0xEF;
        s[1] = 0xBE;
        s[2] = 0xAD;
        s[3] = 0xDE;
        s
    };
    let req = SpendProofRequest {
        sd: &sd,
        intent: &intent,
        agent_key: &wallet.agent_key,
        attestation_secret: secret,
        revocation: witness.into(),
        now: 1_750_000_000, // not_before <= now <= expires_at（电路断言 5）
    };
    let proof = prover
        .prove(&req)
        .unwrap_or_else(|e| panic!("真 prover 失败（电路断言/交叉校验/后端故障）: {e:?}"));
    assert_eq!(proof.public_inputs.delegation_hash, dh);
    assert_eq!(proof.public_inputs.amount, 4_200);
    assert_eq!(
        proof.public_inputs.revocation_root,
        revocations.sparse_root(),
        "公共输入撤销根 = 聚合器锚定根（同一棵树）"
    );
    assert!(!proof.proof.is_empty());

    // ——— 验证侧（§6.13 BbVerifier）密码学接受 ———
    let verifier = BbVerifier::from_parts(vk, backend, root.join("target/bb-prover-e2e"));
    let out = verifier
        .verify(&proof)
        .unwrap_or_else(|e| panic!("真证明被验证侧拒绝: {e:?}"));
    assert_eq!(out.delegation_hash, dh);
    assert_eq!(out.amount, 4_200);
    assert_eq!(out.revocation_root, revocations.sparse_root());

    // ——— 负向一：篡改 proof → E_PROOF ———
    let mut tampered = proof.proof.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    let bad = mist_core::zk::SpendProof {
        proof: tampered,
        public_inputs: proof.public_inputs.clone(),
    };
    assert_eq!(verifier.verify(&bad), Err(Error::EProof));

    // ——— 负向二：公共输入与证明绑定不一致（金额 +1）→ E_PROOF ———
    let mut wrong_pi = proof.public_inputs.clone();
    wrong_pi.amount += 1;
    let bad_pi = mist_core::zk::SpendProof {
        proof: proof.proof,
        public_inputs: wrong_pi,
    };
    assert_eq!(verifier.verify(&bad_pi), Err(Error::EProof));
}

#[test]
fn noir_prover_fails_closed_without_revocation_witness() {
    // 纯 Rust（无工具链依赖）：占位口径（空 path）不可进真后端——构造期工具链不可得
    // 或 prove 期前置闸都会报 E_PROVER，绝不降级回占位证明（§6.14 fail-closed）。
    // 工具链可得时也成立：path 长度闸在 prove 入口先于一切重操作。
    let root = repo_root();
    let wallet = AgentWallet::from_seed([0xA6u8; 32]);
    let owner_key = mist_core::dsa::owner_signing_key_from_bytes([0x10u8; 32]);
    let limits = DelegationLimits {
        max_per_spend: 1_000,
        rate_window_secs: 60,
        rate_max_per_window: 10_000,
        total_cap: 10_000,
        categories: vec![],
        not_before: 0,
        expires_at: u64::MAX,
    };
    let sd = create_delegation(&owner_key, [0x0Bu8; 20], 1, &limits).expect("delegation");
    let dh = mist_core::dsa::delegation_hash(&sd.delegation);
    let (intent, _sig) = wallet.create_intent(
        sd.delegation.agent,
        dh,
        [0x9Du8; 20],
        42,
        [0xC1; 32],
        1,
        None,
        u64::MAX,
    );
    let req = SpendProofRequest {
        sd: &sd,
        intent: &intent,
        agent_key: &wallet.agent_key,
        attestation_secret: [0x42u8; 32],
        revocation: mist_core::zk::RevocationWitness {
            root: [0u8; 32],
            path: Vec::new(), // 占位口径
        },
        now: 1_750_000_000,
    };
    match NoirProver::from_repo_root(&root) {
        Ok(prover) => {
            // 工具链可得：prove 应在 path 长度前置闸被拒（fail-closed）。
            assert_eq!(prover.prove(&req), Err(Error::EProver));
        }
        Err(e) => assert_eq!(e, Error::EProver, "工具链缺失 = 构造期 E_PROVER"),
    }
}

// ---------------------------------------------------------------------------
// S-46：SDK pay() × NoirProver 全链路（attest 同源自洽装配，§6.14 诚实边界 2 收口）
// ---------------------------------------------------------------------------

#[test]
fn sdk_pay_full_path_with_noir_prover_and_attested_identity() {
    if std::env::var("MIST_ZK_PROVER_E2E").as_deref() != Ok("1") {
        println!("SKIP: MIST_ZK_PROVER_E2E=1 未设（prove 侧重操作，不进默认 cargo test）");
        return;
    }
    let _prove_serial = prove_guard();
    let root = repo_root();
    let _bytecode = match artifact(
        &root,
        "circuits/target/spend_authorization.json",
        "formal_zk 未跑",
    ) {
        Some(b) => b,
        None => return,
    };
    let vk = match artifact(&root, "circuits/target/vk", "formal_zk 未跑") {
        Some(b) => b,
        None => return,
    };
    let backend = match BbBackend::detect() {
        Some(b) => b,
        None => {
            println!("SKIP: bb 工具链不可得（Windows 原生与 WSL 兜底皆无）");
            return;
        }
    };

    // ——— 进程内聚合器：BbVerifier（§6.13）+ 撤销根绑定闸（§6.2，S-44）———
    let wal_path =
        std::env::temp_dir().join(format!("mist-sdk-noir-pay-{}.wal", std::process::id()));
    let _ = std::fs::remove_file(&wal_path);
    let wal = Wal::open(&wal_path, 1_000).expect("open wal");
    let verifier = BbVerifier::from_parts(vk, backend, root.join("target/bb-sdk-pay-e2e"));
    let agg = Arc::new(Aggregator::new(
        IngestConfig {
            enforce_revocation_root: true,
            ..Default::default()
        },
        Box::new(verifier),
        wal,
    ));
    // 撤销另一张委托：撤销集非空 → 绑定闸接受集含真实状态根（非退化空根口径）。
    let mut other = [0x7Au8; 32];
    other[31] = 0x03;
    agg.revoke(other);

    // ——— SDK 自洽装配（S-46）：同一 NoirProver 兼作 prove 后端与 attestation keyring———
    let wallet = AgentWallet::from_seed([0xB7u8; 32]);
    let owner_key = mist_core::dsa::owner_signing_key_from_bytes([0x11u8; 32]);
    let limits = DelegationLimits {
        max_per_spend: 5_000,
        rate_window_secs: 60,
        rate_max_per_window: 20_000,
        total_cap: 100_000,
        categories: vec![],
        not_before: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    let prover = NoirProver::from_repo_root(&root).expect("noir 工具链可得（原生或 WSL 兜底）");
    let secret = {
        // attestation 私钥标量（LE 不透明字节）= 0xDEADBEEF（< EdDSA 子群阶，合法私钥）。
        let mut s = [0u8; 32];
        s[0] = 0xEF;
        s[1] = 0xBE;
        s[2] = 0xAD;
        s[3] = 0xDE;
        s
    };
    let client = SdkClient::with_noir(
        wallet.clone(),
        Box::new(InProcessAggregator::from_inner(Arc::clone(&agg))),
        prover,
        secret,
    );
    let rec = client
        .authorize(&owner_key, [0x0Bu8; 20], &limits)
        .expect("authorize");
    let dh = rec.delegation_hash;

    // 同源凭据：公钥由 keygen 从 attestation_secret 经 Noir 曲线 oracle 派生。
    let cred = client
        .attest_identity()
        .expect("keygen 派生 + 绑定自校验（S-46）");
    let pk = client.attestation_pubkey().expect("派生缓存命中");
    assert_eq!(cred.agent_commit, agent_commit(&pk));

    // pay 全链：witness 自动现取（S-45）→ NoirProver 真证明 → BbVerifier 密码学验证 +
    // 绑定闸接受（enforce_revocation_root = true，witness 取自同一账本树）。
    let receipt = client
        .pay(&PayParams {
            delegation_hash: dh,
            recipient: [0x9Cu8; 20],
            amount: 4_200,
            category: [0xC0; 32],
            memo: None,
            expires_at: 1_800_000_000,
        })
        .unwrap_or_else(|e| panic!("pay 全链失败（prove / 验证 / 绑定闸）: {e:?}"));
    assert_eq!(receipt.seq, 0);
    assert!(
        receipt.spend_nonce >= 1,
        "电路断言 7：spend_nonce 从 1 计（S-46 NonceManager 修正）"
    );
    assert_eq!(agg.accepted_count(), 1);
    assert_eq!(agg.total_spent(&dh), Some(4_200));

    // 同源对账（最强锚）：独立请求直接走 prove 六步链（同一 secret），公共输入
    // agent_commit 必须与 attest_identity 凭据一致——attest 与 prove 的电路签名身份
    // 单一来源由构造保证，不再依赖调用方手工对齐。
    let standalone = NoirProver::from_repo_root(&root).expect("工具链");
    let sd = create_delegation(&owner_key, [0x0Bu8; 20], 9, &limits).expect("delegation");
    let sdh = mist_core::dsa::delegation_hash(&sd.delegation);
    let (intent, _sig) = wallet.create_intent(
        sd.delegation.agent,
        sdh,
        [0x9Cu8; 20],
        100,
        [0xC0; 32],
        9, // spend_nonce > 0（电路断言 7）
        None,
        1_800_000_000,
    );
    let witness = agg
        .revocation_witness(&sdh)
        .expect("未撤销委托必有非成员 witness")
        .into();
    let proof = standalone
        .prove(&SpendProofRequest {
            sd: &sd,
            intent: &intent,
            agent_key: &wallet.agent_key,
            attestation_secret: secret,
            revocation: witness,
            now: 1_750_000_000,
        })
        .unwrap_or_else(|e| panic!("standalone prove 失败: {e:?}"));
    assert_eq!(
        proof.public_inputs.agent_commit, cred.agent_commit,
        "attest_identity 凭据承诺 == 证明公共输入 agent_commit（同源实证，S-46）"
    );

    drop(client);
    let _ = std::fs::remove_file(&wal_path);
}
