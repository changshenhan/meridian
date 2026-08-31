//! S-40 bb 后端端到端（TECH_SPEC §6.13）：真电路证明 × `BbVerifier` 密码学通路。
//!
//! 公共输入从 `circuits/Prover.toml` **手工重建**（本测试 = 第三实现，不读 bb 的
//! public_inputs 文件——防止序列化器抄自己的答案），配 `circuits/target/{proof,vk}`
//! 真工件（第 9 步 formal_zk 管线产出）跑正/负向：
//! 真证明接受 / 篡改 proof 拒 / 篡改 pi 拒；「pi 与信封不一致」为纯 Rust 一致性比对
//! （`check_public_inputs_consistent`，无需 bb）。
//!
//! 门控：`MIST_BB_E2E=1` 才跑（verify.sh 第 9 步 formal_zk 之后挂起；CI noir job
//! formal 之后同款）。工件缺失或 bb 工具链不可得时打印跳过原因并返回（不静默成功：
//! 每次跳过都显式说明）。

use std::path::PathBuf;

use mist_aggregator::bb::{BbBackend, BbVerifier};
use mist_aggregator::proof::check_public_inputs_consistent;
use mist_core::dsa::SpendIntent;
use mist_core::error::Error;
use mist_core::zk::{SpendProof, SpendPublicInputs, SpendVerifier};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("aggregator/ 的上级即仓库根")
        .to_path_buf()
}

/// 十进制字符串（任意长度）→ 32B 大端（反复除 256 取余，无 bigint 依赖）。
fn decimal_to_be32(s: &str) -> [u8; 32] {
    let digits: Vec<u8> = s.trim().bytes().map(|b| b - b'0').collect();
    assert!(
        !digits.is_empty() && digits.iter().all(|d| *d < 10),
        "非十进制串: {s}"
    );
    let mut digits = digits;
    let mut out = Vec::new();
    while digits.iter().any(|d| *d != 0) {
        let mut rem = 0u32;
        let mut next = Vec::with_capacity(digits.len());
        for d in digits {
            let cur = rem * 10 + d as u32;
            next.push((cur / 256) as u8);
            rem = cur % 256;
        }
        while next.first() == Some(&0) {
            next.remove(0);
        }
        out.push(rem as u8);
        digits = next;
    }
    assert!(out.len() <= 32, "值超出 256-bit（≥ 域模数口径）: {s}");
    let mut be = [0u8; 32];
    // out[0] 是最低有效字节（反复除 256 的余数序）→ 大端排到尾部。
    for (i, b) in out.iter().enumerate() {
        be[31 - i] = *b;
    }
    be
}

/// Prover.toml 手工解析（只认本管线产出的两种形态：`[0x.., ..]` 字节数组 / 带引号
/// 十进制标量）。第三实现口径：与 `formal_readback.py`、`aggregator::bb` 互相交叉。
fn prover_field(src: &str, key: &str) -> String {
    let prefix = format!("{key} =");
    let line = src
        .lines()
        .find(|l| l.trim_start().starts_with(&prefix))
        .unwrap_or_else(|| panic!("Prover.toml 缺字段 {key}"));
    let raw = line.trim_start().strip_prefix(&prefix).unwrap().trim();
    raw.trim_matches('"').to_string()
}

fn prover_bytes(src: &str, key: &str) -> Vec<u8> {
    prover_field(src, key)
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            let s = s.trim();
            u32::from_str_radix(s.trim_start_matches("0x"), 16)
                .unwrap_or_else(|e| panic!("{key} 字节解析失败 ({s}): {e}")) as u8
        })
        .collect()
}

fn pi_from_prover(src: &str) -> SpendPublicInputs {
    let arr = |k: &str, n: usize| {
        let v = prover_bytes(src, k);
        assert_eq!(v.len(), n, "{k} 长度 {n} 期望");
        let mut out = [0u8; 32];
        out[..n].copy_from_slice(&v);
        (out, n)
    };
    let (agent_commit, _) = arr("agent_commit", 32);
    let (delegation_hash, _) = arr("delegation_hash", 32);
    let (recipient32, _) = arr("recipient", 20);
    let (category, _) = arr("category", 32);
    let mut recipient = [0u8; 20];
    recipient.copy_from_slice(&recipient32[..20]);
    SpendPublicInputs {
        agent_commit,
        delegation_hash,
        recipient,
        amount: prover_field(src, "amount").parse().expect("amount"),
        category,
        spend_nonce: prover_field(src, "spend_nonce")
            .parse()
            .expect("spend_nonce"),
        expires_at: prover_field(src, "expires_at").parse().expect("expires_at"),
        revocation_root: decimal_to_be32(&prover_field(src, "revocation_root")),
        now: prover_field(src, "now").parse().expect("now"),
    }
}

fn intent_for(pi: &SpendPublicInputs) -> SpendIntent {
    SpendIntent {
        agent: [0x00; 20],
        delegation_hash: pi.delegation_hash,
        recipient: pi.recipient,
        amount: pi.amount,
        category: pi.category,
        spend_nonce: pi.spend_nonce,
        memo: None,
        expires_at: pi.expires_at,
    }
}

#[test]
fn bb_verify_e2e_real_proof_positive_and_negative() {
    if std::env::var("MIST_BB_E2E").as_deref() != Ok("1") {
        println!("SKIP: MIST_BB_E2E=1 未设（纯 Rust 侧不碰 bb 工具链）");
        return;
    }
    let root = repo_root();
    let proof_bytes = match std::fs::read(root.join("circuits/target/proof")) {
        Ok(b) => b,
        Err(_) => {
            println!("SKIP: circuits/target/proof 不存在（formal_zk 未跑，工件缺）");
            return;
        }
    };
    let vk = match std::fs::read(root.join("circuits/target/vk")) {
        Ok(b) => b,
        Err(_) => {
            println!("SKIP: circuits/target/vk 不存在（formal_zk 未跑，工件缺）");
            return;
        }
    };
    let prover_toml =
        std::fs::read_to_string(root.join("circuits/Prover.toml")).expect("Prover.toml");
    let pi = pi_from_prover(&prover_toml);
    let backend = match BbBackend::detect() {
        Some(b) => b,
        None => {
            println!("SKIP: bb 工具链不可得（Windows 原生与 WSL 兜底皆无）");
            return;
        }
    };
    let verifier = BbVerifier::from_parts(vk, backend, root.join("target/bb-verify"));
    // 装配面配对声明（S-48，§6.13）：真后端必须声明依赖撤销根公共输入，
    // 聚合器据此构造期强制绑定闸（§6.2）同步装配。
    assert!(verifier.requires_revocation_root_binding());

    // 正向：真证明 + 第三实现重建的公共输入 → bb 密码学接受，公共输入原样返回。
    let good = SpendProof {
        proof: proof_bytes.clone(),
        public_inputs: pi.clone(),
    };
    let out = verifier
        .verify(&good)
        .unwrap_or_else(|e| panic!("真证明被拒（序列化或后端故障）: {e}"));
    assert_eq!(out.amount, pi.amount);
    assert_eq!(out.delegation_hash, pi.delegation_hash);
    assert_eq!(out.revocation_root, pi.revocation_root);

    // 负向一：篡改 proof 任一字节 → 密码学拒绝（E_PROOF，非后端故障）。
    let mut tampered = proof_bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    let bad_proof = SpendProof {
        proof: tampered,
        public_inputs: pi.clone(),
    };
    assert_eq!(verifier.verify(&bad_proof), Err(Error::EProof));

    // 负向二：pi 与证明绑定不一致（金额 +1）→ E_PROOF。等价于「信封声称另一笔意图」
    // 在密码学层的拒绝；进程内的一致性比对（E_ORDERING）另测。
    let mut wrong_pi = pi.clone();
    wrong_pi.amount += 1;
    let bad_pi = SpendProof {
        proof: proof_bytes,
        public_inputs: wrong_pi,
    };
    assert_eq!(verifier.verify(&bad_pi), Err(Error::EProof));

    // 一致性比对（无需 bb）：重建的公共输入与同源 intent 一致；金额漂移被拒。
    assert_eq!(
        check_public_inputs_consistent(&pi, &intent_for(&pi)),
        Ok(())
    );
    let mut drifted_intent = intent_for(&pi);
    drifted_intent.amount += 1;
    assert_eq!(
        check_public_inputs_consistent(&pi, &drifted_intent),
        Err(Error::EOrdering)
    );
}

#[test]
fn prover_toml_parser_shape() {
    // 第三实现的形状自检（不依赖 bb）：字段齐全 + 字节序/数量正确。
    let src = "agent_commit = [0xea, 0x01]\ndelegation_hash = [0x21, 0x22]\nrecipient = [0x31]\ncategory = [0x51]\namount = \"1234\"\nspend_nonce = \"7\"\nexpires_at = \"1700000000\"\nrevocation_root = \"256\"\nnow = \"1650000000\"\n";
    assert_eq!(prover_bytes(src, "agent_commit"), vec![0xea, 0x01]);
    assert_eq!(prover_field(src, "amount"), "1234");
    // 256 = 0x..0100 → 大端 32B 第 30 字节为 1。
    assert_eq!(decimal_to_be32("256")[30], 1);
    assert_eq!(decimal_to_be32("0"), [0u8; 32]);
    // u64::MAX 十进制口径（跨实现锚点）。
    let max = decimal_to_be32("18446744073709551615");
    assert_eq!(&max[24..], &u64::MAX.to_be_bytes());
}
