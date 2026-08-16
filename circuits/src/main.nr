//! spend_authorization — DSA 授权电路完整版（TECH_SPEC §5，S-09）。
//!
//! 双钥绑定（D-05 扩展，S-05/S-09 决策记录）：
//!   · 传输身份：agent 的 Ed25519（NodeId，S-02，电路外快路径验签）——**不改已验收代码**
//!   · ZK 授权：agent 的 attestation key（BabyJubJub + Poseidon EdDSA）对
//!     encode_field(intent_hash) 签名，本电路验证
//!   · owner 的 secp256k1 ECDSA（对 delegation_hash）：**电路外验证**（S-09 决策）
//!     —— 链上 DSA.sol::registerDelegation 已强制 + S-02 verify_delegation 已验收 +
//!     attestation.rs 双钥绑定；电路只锚定 delegation_hash
//!   · 绑定：注册时 Ed25519(NodeId) 对 Jubjub 公钥做绑定签名，绑定验证在电路外做一次
//!     （core/src/attestation.rs）
//!
//! 本电路断言（S-09 范围，对齐 TECH_SPEC §5.2）：
//!   1. sha256(pub_x_le || pub_y_le) == agent_commit      // attestation 公钥承诺解承诺
//!   2. [owner ECDSA —— 电路外]                           // 链上 + S-02 verify_delegation
//!   3. amount <= delegation.max_per_spend                 // 单笔限额
//!   4. categories_len == 0，或 category ∈ categories      // 类别白名单（空白名单不要求）
//!   5. delegation.not_before <= now <= delegation.expires_at  // 有效期
//!   6. delegation_hash[0] > 0                             // 公共锚点非零（S-05）
//!   7. spend_nonce > 0                                    // 防零 nonce 误用（由断言 9 绑定）
//!   8. compute_merkle_root(EMPTY, index, path) == revocation_root  // 撤销非成员，叶子=EMPTY
//!   9. intent_hash == sha256(agent_commit ‖ delegation_hash ‖ recipient ‖ amount_le ‖
//!      category ‖ spend_nonce_le ‖ expires_at_le)         // 字段级绑定（签名对象 = 该哈希）
//!
//! 签名对象：encode_field(intent_hash)（31 字节 LE 截断 → Field，248-bit < BN254 域，
//! 单射；intent_hash 由断言 9 在电路内完全钉死，无 mod-p 碰撞可乘）。
//!
//! 撤销树：深度 32 稀疏 Merkle，叶子=EMPTY(0)，index = delegation_hash[0..4] LE。
//! std::merkle 已在 Noir 1.0 移出 stdlib → 内联 compute_merkle_root（merkle_insert 模式，
//! std::hash::pedersen_hash）。原型级碰撞属性（两 delegation 同 32-bit 前缀共享叶子→撤销
//! 共享）在 SPEC 标注，真实树 S-11 对接 RevocationRegistry 时再设计。

use eddsa::eddsa_verify;
use poseidon::poseidon::PoseidonHasher;
use sha256;

/// 类别白名单容量（Noir 数组定长；多余槽位填零，用 categories_len 约束有效长度）。
/// Noir 1.0 已移除 `usize`：模块级常量用 `global`（`const` 是函数内局部常量），
/// 数组长度/数值泛型统一用 `u32`（CI run 31905033362 实测）。
global MAX_CATEGORIES: u32 = 8;

/// 撤销稀疏 Merkle 树深度（原型；真实树设计见 S-11）。
global REVOCATION_DEPTH: u32 = 32;

/// 断言 3+4+5：预算与有效期约束（拆出以便黑箱测试覆盖正/负两态）。
fn budget_and_window_ok(
    amount: u64,
    max_per_spend: u64,
    categories: [[u8; 32]; MAX_CATEGORIES],
    categories_len: u32,
    category: [u8; 32],
    not_before: u64,
    now: u64,
    expires_at: u64,
) -> bool {
    let mut ok = amount <= max_per_spend;
    ok &= not_before <= now;
    ok &= now <= expires_at;
    if categories_len > 0 {
        let mut found = false;
        for i in 0..MAX_CATEGORIES {
            if i < categories_len {
                found = found | (categories[i] == category);
            }
        }
        ok &= found;
    }
    ok
}

/// 断言 1：attestation 公钥承诺解承诺 = sha256(pub_x_le_bytes || pub_y_le_bytes)。
/// 链下 Rust 侧（core/src/attestation.rs）必须用同一规范计算 agent_commit。
fn agent_commit_ok(agent_commit: [u8; 32], pub_x: Field, pub_y: Field) -> bool {
    let xb: [u8; 32] = pub_x.to_le_bytes();
    let yb: [u8; 32] = pub_y.to_le_bytes();
    let mut pk = [0u8; 64];
    for i in 0..32 {
        pk[i] = xb[i];
        pk[i + 32] = yb[i];
    }
    sha256::digest(pk) == agent_commit
}

/// 断言 9：intent_hash 字段级绑定。
/// 规范字节（140B）：agent_commit(32) ‖ delegation_hash(32) ‖ recipient(20) ‖
/// amount_le(8) ‖ category(32) ‖ spend_nonce_le(8) ‖ expires_at_le(8)。
/// 链下 Rust 侧（core/src/dsa.rs::intent_hash）必须用同一规范计算。
fn compute_intent_hash(
    agent_commit: [u8; 32],
    delegation_hash: [u8; 32],
    recipient: [u8; 20],
    amount: u64,
    category: [u8; 32],
    spend_nonce: u64,
    expires_at: u64,
) -> [u8; 32] {
    let mut preimage = [0u8; 140];
    for i in 0..32 {
        preimage[i] = agent_commit[i];
        preimage[32 + i] = delegation_hash[i];
    }
    for i in 0..20 {
        preimage[64 + i] = recipient[i];
    }
    let amount_le: [u8; 8] = amount.to_le_bytes();
    for i in 0..8 {
        preimage[84 + i] = amount_le[i];
    }
    for i in 0..32 {
        preimage[92 + i] = category[i];
    }
    let nonce_le: [u8; 8] = spend_nonce.to_le_bytes();
    for i in 0..8 {
        preimage[124 + i] = nonce_le[i];
    }
    let exp_le: [u8; 8] = expires_at.to_le_bytes();
    for i in 0..8 {
        preimage[132 + i] = exp_le[i];
    }
    sha256::digest(preimage)
}

/// 签名对象编码：intent_hash 低 31 字节 LE → Field（单射于 31 字节域；见文件头）。
fn encode_field(intent_hash: [u8; 32]) -> Field {
    let mut f: Field = 0;
    let mut mul: Field = 1;
    for i in 0..31 {
        f += intent_hash[i] as Field * mul;
        mul = mul * 256;
    }
    f
}

/// 断言 2（agent 侧）：attestation key 对 encode_field(intent_hash) 的 EdDSA 验证。
fn agent_sig_ok(
    pub_x: Field,
    pub_y: Field,
    sig_s: Field,
    sig_r8_x: Field,
    sig_r8_y: Field,
    intent_hash: [u8; 32],
) -> bool {
    let message = encode_field(intent_hash);
    eddsa_verify::<PoseidonHasher>(pub_x, pub_y, sig_s, sig_r8_x, sig_r8_y, message)
}

/// 内联 compute_merkle_root（std::merkle 已移出 Noir 1.0 stdlib；merkle_insert 官方测试
/// 同款实现，pedersen_hash 为 blackbox 内建）。
fn compute_merkle_root<let N: u32>(leaf: Field, index: Field, hash_path: [Field; N]) -> Field {
    let index_bits: [bool; N] = index.to_le_bits();
    let mut current = leaf;
    for i in 0..N {
        let path_bit = index_bits[i];
        let (hash_left, hash_right) = if path_bit {
            (hash_path[i], current)
        } else {
            (current, hash_path[i])
        };
        current = std::hash::pedersen_hash([hash_left, hash_right]);
    }
    current
}

/// 撤销树索引：delegation_hash[0..4] LE 转 u32 → Field。与 gen-witness / core 派生一致。
fn revocation_index(delegation_hash: [u8; 32]) -> Field {
    let lo = delegation_hash[0] as u32;
    let b1 = delegation_hash[1] as u32;
    let b2 = delegation_hash[2] as u32;
    let hi = delegation_hash[3] as u32;
    (lo | (b1 << 8) | (b2 << 16) | (hi << 24)) as Field
}

/// 断言 8：撤销非成员。delegation_hash 未撤销 ⇔ 其索引处叶子为 EMPTY(0)。
fn revocation_ok(
    delegation_hash: [u8; 32],
    revocation_root: Field,
    revocation_path: [Field; REVOCATION_DEPTH],
) -> bool {
    let index = revocation_index(delegation_hash);
    compute_merkle_root(0, index, revocation_path) == revocation_root
}

pub fn main(
    // ——— Public ———
    agent_commit: pub [u8; 32],
    delegation_hash: pub [u8; 32],
    recipient: pub [u8; 20],
    amount: pub u64,
    category: pub [u8; 32],
    // S-05 仅携带未约束；S-09 由 intent_hash 字段级绑定（断言 9）+ 账本幂等登记真正约束。
    spend_nonce: pub u64,
    expires_at: pub u64,
    revocation_root: pub Field,
    now: pub u64,
    // ——— Private ———
    agent_pub_x: Field,
    agent_pub_y: Field,
    sig_s: Field,
    sig_r8_x: Field,
    sig_r8_y: Field,
    max_per_spend: u64,
    categories: [[u8; 32]; MAX_CATEGORIES],
    categories_len: u32,
    not_before: u64,
    revocation_path: [Field; REVOCATION_DEPTH],
) {
    // 断言 1：attestation 公钥承诺解承诺
    assert(agent_commit_ok(agent_commit, agent_pub_x, agent_pub_y));
    // 断言 9 + 断言 2：intent_hash 字段级绑定，agent 对其编码签名
    let intent_hash = compute_intent_hash(
        agent_commit,
        delegation_hash,
        recipient,
        amount,
        category,
        spend_nonce,
        expires_at,
    );
    assert(agent_sig_ok(
        agent_pub_x,
        agent_pub_y,
        sig_s,
        sig_r8_x,
        sig_r8_y,
        intent_hash,
    ));
    // 断言 3+4+5：预算 / 类别白名单 / 有效期
    assert(budget_and_window_ok(
        amount,
        max_per_spend,
        categories,
        categories_len,
        category,
        not_before,
        now,
        expires_at,
    ));
    // 断言 8：撤销非成员（叶子=EMPTY）
    assert(revocation_ok(delegation_hash, revocation_root, revocation_path));
    // 断言 6+7：公共锚点非零，保证证明绑定到一条真实委托上下文；nonce 防零误用
    assert(delegation_hash[0] > 0);
    assert(spend_nonce > 0);
}

// Noir 1.0 没有 `#[cfg(test)]`（`cfg` 不在作用域）；测试函数用 `#[test]` 标记，
// `nargo test` 收集执行，`nargo compile` 亦会做类型检查（edwards 为测试专用依赖）。
//
// 建树/建路径的「真树」逻辑放在 gen-witness（S-09c，Noir 包，确定性 eddsa_sign +
// 稀疏树），此处测试用「构造性 root」验证接线：任意 path + compute_merkle_root 自算
// root，revocation_ok 必须通过（电路职责 = 校验 path↔root，真树正确性由 prove/verify
// 管线 + nargo test 对同一 gen 代码的双重执行兜底）。
mod tests {
    use crate::{
        agent_commit_ok, agent_sig_ok, budget_and_window_ok, compute_intent_hash, compute_merkle_root,
        encode_field, revocation_index, revocation_ok, MAX_CATEGORIES, REVOCATION_DEPTH,
    };
    use edwards::{bjj::BabyJubJub, Curve, CurveTrait, ScalarField};
    use eddsa::eddsa_to_pub;
    use poseidon::poseidon::PoseidonHasher;
    use sha256;

    // eddsa@main 的 BASE8 常量（模块级 global 未 `pub`，测试侧复制一份；见 eddsa/src/lib.nr）。
    global BASE8_X: Field =
        5299619240641551281634865583518297030282874472190772894086521144482721001553;
    global BASE8_Y: Field =
        16950150798460657717958625567821834550301663161624707787222815936182638968203;
    // eddsa 库的 SUBORDER 非 pub，测试侧复制一份（eddsa_verify 断言 s < SUBORDER）。
    global SUBORDER: Field =
        2736030358979909402780800718157159386076813972158567259200215660948447373041;

    /// 确定性 BabyJubJub EdDSA 签名（镜像 eddsa_verify 的 Poseidon 域：
    /// h = Poseidon(R8x, R8y, Ax, Ay, message)，s = (r + h*sk) % suborder）。
    /// 与 gen-witness（S-09c）同一实现，gen 侧签名必须通过本电路的 eddsa_verify。
    fn test_sign(secret: Field, message: Field) -> (Field, Field, Field, Field, Field) {
        let mut h1 = PoseidonHasher::default();
        h1.write(secret);
        h1.write(message);
        let r = h1.finish();
        let base8: BabyJubJub = Curve { x: BASE8_X, y: BASE8_Y };
        let r8 = base8.mul(ScalarField::<64>::from(r));
        let (ax, ay) = eddsa_to_pub(secret);
        let mut h2 = PoseidonHasher::default();
        h2.write(r8.x);
        h2.write(r8.y);
        h2.write(ax);
        h2.write(ay);
        h2.write(message);
        let h = h2.finish();
        let s = (r + h * secret) % SUBORDER;
        (ax, ay, s, r8.x, r8.y)
    }

    // ——— 固定输入骨架（与 core Rust 侧 golden vector 共享，S-09b 锁一致性）———
    fn fixture_agent_commit() -> [u8; 32] {
        let mut c = [0u8; 32];
        for i in 0..32 {
            c[i] = (0x11 + i) as u8;
        }
        c
    }

    fn fixture_delegation_hash() -> [u8; 32] {
        let mut c = [0u8; 32];
        for i in 0..32 {
            c[i] = (0x21 + i) as u8;
        }
        c
    }

    fn fixture_recipient() -> [u8; 20] {
        let mut c = [0u8; 20];
        for i in 0..20 {
            c[i] = (0x31 + i) as u8;
        }
        c
    }

    fn fixture_category() -> [u8; 32] {
        let mut c = [0u8; 32];
        for i in 0..32 {
            c[i] = (0x51 + i) as u8;
        }
        c
    }

    #[test]
    fn intent_hash_matches_golden() {
        // golden vector 由 core Rust zk_intent_hash()（sha2 规范字节）算得（S-09b）：
        // 2352acec5b8e431c2e9167f9a07c7b237285d836599b860dba4841663ededf57。
        // 双侧锁同一常量 → Noir/Rust 规范一致性由该常量传递锁定。
        let h = compute_intent_hash(
            fixture_agent_commit(),
            fixture_delegation_hash(),
            fixture_recipient(),
            1234,
            fixture_category(),
            7,
            1_700_000_000,
        );
        let want: [u8; 32] = [
            0x23, 0x52, 0xac, 0xec, 0x5b, 0x8e, 0x43, 0x1c, 0x2e, 0x91, 0x67, 0xf9, 0xa0, 0x7c,
            0x7b, 0x23, 0x72, 0x85, 0xd8, 0x36, 0x59, 0x9b, 0x86, 0x0d, 0xba, 0x48, 0x41, 0x66,
            0x3e, 0xde, 0xdf, 0x57,
        ];
        assert(h == want);
    }

    #[test]
    fn intent_hash_binds_every_field() {
        let base = compute_intent_hash(
            fixture_agent_commit(),
            fixture_delegation_hash(),
            fixture_recipient(),
            1234,
            fixture_category(),
            7,
            1_700_000_000,
        );

        let mut ac = fixture_agent_commit();
        ac[0] ^= 0x01;
        assert(compute_intent_hash(ac, fixture_delegation_hash(), fixture_recipient(), 1234, fixture_category(), 7, 1_700_000_000) != base);

        let mut dh = fixture_delegation_hash();
        dh[0] ^= 0x01;
        assert(compute_intent_hash(fixture_agent_commit(), dh, fixture_recipient(), 1234, fixture_category(), 7, 1_700_000_000) != base);

        let mut rc = fixture_recipient();
        rc[0] ^= 0x01;
        assert(compute_intent_hash(fixture_agent_commit(), fixture_delegation_hash(), rc, 1234, fixture_category(), 7, 1_700_000_000) != base);

        assert(compute_intent_hash(fixture_agent_commit(), fixture_delegation_hash(), fixture_recipient(), 1235, fixture_category(), 7, 1_700_000_000) != base);

        let mut cat = fixture_category();
        cat[0] ^= 0x01;
        assert(compute_intent_hash(fixture_agent_commit(), fixture_delegation_hash(), fixture_recipient(), 1234, cat, 7, 1_700_000_000) != base);

        assert(compute_intent_hash(fixture_agent_commit(), fixture_delegation_hash(), fixture_recipient(), 1234, fixture_category(), 8, 1_700_000_000) != base);

        assert(compute_intent_hash(fixture_agent_commit(), fixture_delegation_hash(), fixture_recipient(), 1234, fixture_category(), 7, 1_700_000_001) != base);
    }

    #[test]
    fn encode_field_differs_when_hash_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[30] = 1;
        assert(encode_field(a) != encode_field(b));
        a[30] = 0;
        a[31] = 1; // 最高字节不参与编码，但断言 9 钉死完整哈希 → 无碰撞可乘
        assert(encode_field(a) == encode_field(b));
    }

    #[test]
    fn agent_sig_accepts_valid_and_rejects_tampered() {
        let secret = 1234;
        let intent = compute_intent_hash(
            fixture_agent_commit(),
            fixture_delegation_hash(),
            fixture_recipient(),
            1234,
            fixture_category(),
            7,
            1_700_000_000,
        );
        let message = encode_field(intent);
        let (ax, ay, s, r8x, r8y) = test_sign(secret, message);

        // 正例：有效签名通过
        assert(agent_sig_ok(ax, ay, s, r8x, r8y, intent));
        // 负例 1：intent_hash 被改（签名对象变）→ false
        let mut forged = intent;
        forged[0] ^= 0x01;
        assert(!agent_sig_ok(ax, ay, s, r8x, r8y, forged));
        // 负例 2：换另一把仍在曲线上的公钥 → false
        let (bx, by, _, _, _) = test_sign(4567, message);
        assert(!agent_sig_ok(bx, by, s, r8x, r8y, intent));
        // 负例 3：s 被篡改（仍 < suborder，不触发 assert）→ false
        assert(!agent_sig_ok(ax, ay, s + 1, r8x, r8y, intent));
    }

    #[test]
    fn revocation_accepts_built_root_and_rejects_mismatch() {
        let dh = fixture_delegation_hash();
        let index = revocation_index(dh);
        // 构造性 root：任意 path + compute_merkle_root 自算 root → revocation_ok 必过
        let mut path = [0; REVOCATION_DEPTH];
        for i in 0..REVOCATION_DEPTH {
            path[i] = (i as Field) * 7 + 1;
        }
        let root = compute_merkle_root(0, index, path);
        assert(revocation_ok(dh, root, path));
        // 负例 1：root 被篡改 → false
        assert(!revocation_ok(dh, root + 1, path));
        // 负例 2：换了 index 的 delegation_hash（同一 root/path）→ false
        let mut other = dh;
        other[0] ^= 0x01;
        assert(!revocation_ok(other, root, path));
    }

    #[test]
    fn budget_accepts_valid_spend() {
        let categories = [[0u8; 32]; MAX_CATEGORIES];
        assert(budget_and_window_ok(100, 100, categories, 0, [1u8; 32], 0, 50, 100));
    }

    #[test]
    fn budget_rejects_overspend() {
        let categories = [[0u8; 32]; MAX_CATEGORIES];
        assert(!budget_and_window_ok(101, 100, categories, 0, [1u8; 32], 0, 50, 100));
    }

    #[test]
    fn budget_rejects_expired_and_not_yet_valid() {
        let categories = [[0u8; 32]; MAX_CATEGORIES];
        // 已过期：now > expires_at
        assert(!budget_and_window_ok(10, 100, categories, 0, [1u8; 32], 0, 200, 100));
        // 未生效：now < not_before
        assert(!budget_and_window_ok(10, 100, categories, 0, [1u8; 32], 50, 10, 100));
    }

    #[test]
    fn category_whitelist_accepts_only_listed() {
        let mut categories = [[0u8; 32]; MAX_CATEGORIES];
        categories[0] = [0xAA; 32];
        categories[1] = [0xBB; 32];
        assert(budget_and_window_ok(10, 100, categories, 2, [0xAA; 32], 0, 50, 100));
        assert(budget_and_window_ok(10, 100, categories, 2, [0xBB; 32], 0, 50, 100));
        assert(!budget_and_window_ok(10, 100, categories, 2, [0xCC; 32], 0, 50, 100));
    }

    #[test]
    fn agent_commit_matches_pubkey() {
        // 用 eddsa_to_pub 生成曲线上的点，正向验证承诺；再篡改一点验证失败。
        let (pub_x, pub_y) = eddsa_to_pub(1234);
        let xb: [u8; 32] = pub_x.to_le_bytes();
        let yb: [u8; 32] = pub_y.to_le_bytes();
        let mut pk = [0u8; 64];
        for i in 0..32 {
            pk[i] = xb[i];
            pk[i + 32] = yb[i];
        }
        let commit = sha256::digest(pk);
        assert(agent_commit_ok(commit, pub_x, pub_y));
        // 篡改承诺（agent_commit 与公钥不符 → 解承诺失败）
        let mut forged = commit;
        forged[0] ^= 0x01;
        assert(!agent_commit_ok(forged, pub_x, pub_y));
    }
}
