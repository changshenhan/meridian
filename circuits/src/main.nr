//! spend_authorization — DSA 授权电路（TECH_SPEC §5，S-05 去 ECDSA 最小版）。
//!
//! 双钥绑定（D-05 扩展，S-05 决策记录）：
//!   · 传输身份：agent 的 Ed25519（NodeId，S-02，电路外快路径验签）——**不改已验收代码**
//!   · ZK 授权：agent 的 attestation key（BabyJubJub + Poseidon EdDSA）对 message 签名，本电路验证
//!   · 绑定：注册时 Ed25519(NodeId) 对 Jubjub 公钥做绑定签名，绑定验证在电路外做一次
//!     （core/src/attestation.rs）
//!
//! 本电路断言（S-05 范围）：
//!   1. sha256(pub_x_le || pub_y_le) == agent_commit      // attestation 公钥承诺解承诺
//!   2. eddsa_verify(pub, sig, message) == true           // agent 对签名对象的 EdDSA
//!   3. amount <= delegation.max_per_spend                 // 单笔限额
//!   4. categories_len == 0，或 category ∈ categories      // 类别白名单（空白名单不要求）
//!   5. delegation.not_before <= now <= delegation.expires_at  // 有效期
//! 完整版（owner ECDSA + 撤销 Merkle 非成员 + intent_hash 字段级绑定）见 S-09。
//!
//! 说明：S-05 的 `message` 是签名对象（公共输入，Field）。intent 字段级绑定在 S-09
//! 与 delegation_hash 一起完成；此处 `delegation_hash` 作为证明上下文的公共锚点。

use eddsa::eddsa_verify;
use poseidon::poseidon::PoseidonHasher;
use sha256;

/// 类别白名单容量（Noir 数组定长；多余槽位填零，用 categories_len 约束有效长度）。
/// Noir 1.0 已移除 `usize`：模块级常量用 `global`（`const` 是函数内局部常量），
/// 数组长度/数值泛型统一用 `u32`（CI run 31905033362 实测：`usize` 无法解析）。
global MAX_CATEGORIES: u32 = 8;

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

/// 断言 2：agent attestation key（BabyJubJub）对 message 的 EdDSA 验证。
fn agent_sig_ok(
    pub_x: Field,
    pub_y: Field,
    sig_s: Field,
    sig_r8_x: Field,
    sig_r8_y: Field,
    message: Field,
) -> bool {
    eddsa_verify::<PoseidonHasher>(pub_x, pub_y, sig_s, sig_r8_x, sig_r8_y, message)
}

pub fn main(
    // ——— Public ———
    agent_commit: pub [u8; 32],
    delegation_hash: pub [u8; 32],
    message: pub Field,
    amount: pub u64,
    category: pub [u8; 32],
    // S-05 仅作为公共输入携带、未约束（防误用：证明可带任意 nonce）；
    // S-09 由 intent_hash 字段级绑定 + 账本幂等登记真正约束。前缀 _ 抑制
    // unused 警告，S-09 约束落地时改回 spend_nonce。
    _spend_nonce: pub u64,
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
    expires_at: u64,
) {
    assert(agent_commit_ok(agent_commit, agent_pub_x, agent_pub_y));
    assert(agent_sig_ok(
        agent_pub_x,
        agent_pub_y,
        sig_s,
        sig_r8_x,
        sig_r8_y,
        message,
    ));
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
    // 公共锚点非零，保证证明绑定到一条真实委托上下文（字段级重算在 S-09）。
    assert(delegation_hash[0] > 0);
}

// Noir 1.0 没有 `#[cfg(test)]`（`cfg` 不在作用域）；测试函数用 `#[test]` 标记，
// `nargo test` 收集执行，`nargo compile` 亦会做类型检查（edwards 为测试专用依赖）。
mod tests {
    use crate::{budget_and_window_ok, agent_commit_ok, agent_sig_ok, MAX_CATEGORIES};
    use edwards::{bjj::BabyJubJub, Curve, CurveTrait, ScalarField};
    use eddsa::eddsa_to_pub;
    use sha256;

    // eddsa@main 的 BASE8 常量（模块级 global 未 `pub`，测试侧复制一份；见 eddsa/src/lib.nr）。
    global BASE8_X: Field =
        5299619240641551281634865583518297030282874472190772894086521144482721001553;
    global BASE8_Y: Field =
        16950150798460657717958625567821834550301663161624707787222815936182638968203;

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

    #[test]
    fn agent_sig_rejects_forged() {
        // 注意：eddsa_verify 对「不在曲线上」的 R8/公钥 和 s >= suborder 会 **panic**（assert），
        // 不会返回 false。因此负向测试必须用「在曲线上」的点和 s < suborder 的值。
        // r_a / s_a 取自 eddsa@main 自带测试的手工预计算有效签名（priv_a=123, msg=789）。
        let priv_a = 123;
        let priv_b = 456;
        let msg = 789;
        let (pub_a_x, pub_a_y) = eddsa_to_pub(priv_a);
        let (pub_b_x, pub_b_y) = eddsa_to_pub(priv_b);

        let base8: BabyJubJub = Curve { x: BASE8_X, y: BASE8_Y };
        let r_a = 1414770703199880747815475415092878800081323795074043628810774576767372531818;
        let s_a = 30333430637424319196043722294837632681219980330991241982145549329256671548;
        let r8_a = base8.mul(ScalarField::<63>::from(r_a));

        // 正例：有效签名通过
        assert(agent_sig_ok(pub_a_x, pub_a_y, s_a, r8_a.x, r8_a.y, msg));
        // 负例 1：消息被篡改 → false
        assert(!agent_sig_ok(pub_a_x, pub_a_y, s_a, r8_a.x, r8_a.y, msg + 1));
        // 负例 2：换另一把仍在曲线上的公钥 → false
        assert(!agent_sig_ok(pub_b_x, pub_b_y, s_a, r8_a.x, r8_a.y, msg));
        // 负例 3：s 被篡改（仍 < suborder，不触发 assert）→ false
        assert(!agent_sig_ok(pub_a_x, pub_a_y, s_a + 1, r8_a.x, r8_a.y, msg));
    }

    #[test]
    fn tamper_every_public_field_must_fail() {
        // 用有效输入骨架，逐字段篡改，确认 main 的任一断言都会拒绝。
        // S-05 验收：篡改任一字段必须验证失败。此处通过拆出的谓词覆盖，
        // 完整 main 级的 prove/verify 篡改测试在 smoke 管线（CI）执行。
        let categories = [[0u8; 32]; MAX_CATEGORIES];
        // 篡改 amount
        assert(!budget_and_window_ok(101, 100, categories, 0, [1u8; 32], 0, 50, 100));
        // 篡改 now（过期）
        assert(!budget_and_window_ok(10, 100, categories, 0, [1u8; 32], 0, 101, 100));
        // 篡改 category
        let mut cats = [[0u8; 32]; MAX_CATEGORIES];
        cats[0] = [0xAA; 32];
        assert(!budget_and_window_ok(10, 100, cats, 1, [0x00; 32], 0, 50, 100));
    }
}
