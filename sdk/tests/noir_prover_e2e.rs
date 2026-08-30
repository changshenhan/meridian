//! S-43 真 prover 端到端（TECH_SPEC §6.14）：SDK 委托/意图 + 聚合器撤销集非成员
//! witness（S-42 产出）→ [`NoirProver`] 真电路证明（Noir oracle 曲线数学 + 电路
//! 断言 1-9 自校验 + bb prove）→ `BbVerifier`（§6.13 验证后端）密码学接受；负向：
//! 篡改 proof / 篡改公共输入皆 `E_PROOF`。
//!
//! 这是 §4.6 残余②「电路消费交叉锚」的实证：电路吃**聚合器出的撤销路径**重算根并与
//! 公共输入 `revocation_root` 对账，全链真 ZK。
//!
//! 门控：`MERIDIAN_ZK_PROVER_E2E=1` 才跑（verify.sh 步 9c，紧随 9b；CI noir job
//! 同款）。工件依赖第 9 步 formal_zk 产出的 `circuits/target/spend_authorization.json`
//! （bb 字节码）与 `circuits/target/vk`；缺失则显式打印跳过原因（不静默成功）。

use std::path::{Path, PathBuf};

use meridian_aggregator::bb::{BbBackend, BbVerifier};
use meridian_aggregator::revocation::RevocationSet;
use meridian_core::error::Error;
use meridian_core::zk::{SpendProofRequest, SpendProver, SpendVerifier};
use meridian_sdk::identity::{create_delegation, AgentWallet, DelegationLimits};
use meridian_sdk::prover::NoirProver;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("sdk/ 的上级即仓库根")
        .to_path_buf()
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
    if std::env::var("MERIDIAN_ZK_PROVER_E2E").as_deref() != Ok("1") {
        println!("SKIP: MERIDIAN_ZK_PROVER_E2E=1 未设（prove 侧重操作，不进默认 cargo test）");
        return;
    }
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
    let owner_key = meridian_core::dsa::owner_signing_key_from_bytes([0x0Fu8; 32]);
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
    let dh = meridian_core::dsa::delegation_hash(&sd.delegation);
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
    let bad = meridian_core::zk::SpendProof {
        proof: tampered,
        public_inputs: proof.public_inputs.clone(),
    };
    assert_eq!(verifier.verify(&bad), Err(Error::EProof));

    // ——— 负向二：公共输入与证明绑定不一致（金额 +1）→ E_PROOF ———
    let mut wrong_pi = proof.public_inputs.clone();
    wrong_pi.amount += 1;
    let bad_pi = meridian_core::zk::SpendProof {
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
    let owner_key = meridian_core::dsa::owner_signing_key_from_bytes([0x10u8; 32]);
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
    let dh = meridian_core::dsa::delegation_hash(&sd.delegation);
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
        revocation: meridian_core::zk::RevocationWitness {
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
