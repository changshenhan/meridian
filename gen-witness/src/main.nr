//! gen-witness —— S-09 正式电路 spend_authorization 的确定性 witness 生成器（CI 管线用）。
//!
//! 与 smoke-gen（Rust，TEMPORARY）不同：此处签名（eddsa_sign）与撤销树建树/寻路全部在
//! Noir 内做（S-05 教训：不做跨语言曲线数学）。Rust core 侧只负责纯字节逻辑
//! （zk_intent_hash / revocation_index，见 core/src/dsa.rs），由共享 hex 向量锁定。
//!
//! 用法（CI formal_zk.sh）：
//!   nargo fetch && nargo compile && nargo execute --overwrite-return
//! → 返回值（签名/pubkey/撤销树/path/intent_hash）写入本包 Prover.toml 的 `return` 键，
//!   由 scripts/formal_gen_to_prover.py 转成 circuits/Prover.toml 喂正式电路。
//!
//! 关键一致性约束（与 circuits/src/main.nr 零漂移）：
//!   · compute_intent_hash / encode_field / revocation_index / compute_merkle_root
//!     与电路同实现（sha256 规范字节、31B LE、delegation_hash[0..4] LE、pedersen_hash）
//!   · eddsa_sign 镜像电路的 eddsa_verify 的 Poseidon 域（h = Poseidon(R8x,R8y,Ax,Ay,m)，
//!     s = (r + h*sk) % SUBORDER）——gen 签名必须通过电路验签
//!   · 撤销树：稀疏 Merkle，深度 32，叶子=EMPTY(0)；撤销委托的叶子 = encode_field(hash)（非零）；
//!     目标委托不在撤销集 → 其叶子为 EMPTY → 电路 compute_merkle_root(0, idx, path) == root
//!
//! 建树用 unconstrained（brillig）递归（subtree_root）：gen-witness 只求值不证明，unconstrained
//! 值被 witness-hint 进约束系统，避免在生成器里堆约束、也规避约束上下文递归风险。
//! 树正确性由本包 #[test]（build→compute_merkle_root 自验）与正式电路 prove/verify 双重兜底。

use eddsa::{eddsa_to_pub, eddsa_verify};
use edwards::{bjj::BabyJubJub, Curve, CurveTrait, ScalarField};
use poseidon::poseidon::PoseidonHasher;
use sha256;

/// 撤销稀疏 Merkle 树深度（与电路 REVOCATION_DEPTH 一致）。
global REVOCATION_DEPTH: u32 = 32;

/// 本生成器支持的最大撤销集大小（固定入参数组定长；不足补零位 + revoked_len）。
global MAX_REVOKED: u32 = 2;

// eddsa fork 的 BASE8 / SUBORDER 为模块级未 pub 常量，复制一份（见 eddsa/src/lib.nr）。
global BASE8_X: Field =
    5299619240641551281634865583518297030282874472190772894086521144482721001553;
global BASE8_Y: Field =
    16950150798460657717958625567821834550301663161624707787222815936182638968203;
global SUBORDER: Field =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;

// ——— 以下 4 个函数与 circuits/src/main.nr 同实现（零漂移）———

/// intent_hash 字段级绑定（断言 9 的规范字节，140B）。
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

/// 签名对象编码：intent_hash 低 31 字节 LE → Field（与电路 encode_field 一致）。
fn encode_field(intent_hash: [u8; 32]) -> Field {
    let mut f: Field = 0;
    let mut mul: Field = 1;
    for i in 0..31 {
        f += intent_hash[i] as Field * mul;
        mul = mul * 256;
    }
    f
}

/// 撤销树索引（u32）：delegation_hash[0..4] LE。与电路 revocation_index（Field）值一致。
fn revocation_index_u32(delegation_hash: [u8; 32]) -> u32 {
    let lo = delegation_hash[0] as u32;
    let b1 = delegation_hash[1] as u32;
    let b2 = delegation_hash[2] as u32;
    let hi = delegation_hash[3] as u32;
    lo | (b1 << 8) | (b2 << 16) | (hi << 24)
}

/// 内联 compute_merkle_root（与电路同实现，merkle_insert 模式，pedersen_hash）。
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

// ——— 以下为 gen-witness 特有：确定性签名 + 撤销树建树/寻路 ———

/// attestation 公钥承诺 = sha256(pub_x_le ‖ pub_y_le)（与电路 agent_commit_ok 同规范）。
fn agent_commit_from_pubkey(pub_x: Field, pub_y: Field) -> [u8; 32] {
    let xb: [u8; 32] = pub_x.to_le_bytes();
    let yb: [u8; 32] = pub_y.to_le_bytes();
    let mut pk = [0u8; 64];
    for i in 0..32 {
        pk[i] = xb[i];
        pk[i + 32] = yb[i];
    }
    sha256::digest(pk)
}

/// 确定性 BabyJubJub EdDSA 签名（镜像电路 eddsa_verify 的 Poseidon 域；eddsa fork 无 sign）。
/// 返回 (s, r8_x, r8_y)；公钥由 eddsa_to_pub 单独取。
fn eddsa_sign(secret: Field, message: Field) -> (Field, Field, Field) {
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
    (s, r8.x, r8.y)
}

/// 空子树根表：empty_roots[k] = 深度 k 的全空树根（pedersen 叠 2 的平方）。
unconstrained fn compute_empty_roots() -> [Field; 33] {
    let mut roots: [Field; 33] = [0; 33];
    let mut r: Field = 0;
    for i in 1..33 {
        r = std::hash::pedersen_hash([r, r]);
        roots[i] = r;
    }
    roots
}

/// 子树的根（unconstrained/brillig 递归）。位置/层级用 u64 避免 u32 移位越界。
/// 撤销集 revoked：[(index, 叶值)]，叶值 = encode_field(撤销委托哈希)（非零）。
/// 子树不含任何撤销叶 → 短路为空子树根；含 → 递归左右子。
unconstrained fn subtree_root(
    level: u64,
    pos: u64,
    revoked: [(u32, Field); MAX_REVOKED],
    revoked_len: u32,
    empty_roots: [Field; 33],
) -> Field {
    let mut has = false;
    for j in 0..MAX_REVOKED {
        if j < revoked_len {
            has = has | (((revoked[j].0 as u64) >> level) == pos);
        }
    }
    if !has {
        return empty_roots[level as u32];
    }
    if level == 0 {
        let mut v: Field = 0;
        for j in 0..MAX_REVOKED {
            if j < revoked_len && (revoked[j].0 as u64) == pos {
                v = revoked[j].1;
            }
        }
        return v;
    }
    let left = subtree_root(level - 1, pos * 2, revoked, revoked_len, empty_roots);
    let right = subtree_root(level - 1, pos * 2 + 1, revoked, revoked_len, empty_roots);
    std::hash::pedersen_hash([left, right])
}

/// 目标叶子索引的兄弟路径：path[i] = 第 i 层兄弟子树根（撤销树，EMPTY 叶子）。
unconstrained fn build_path(
    target: u32,
    revoked: [(u32, Field); MAX_REVOKED],
    revoked_len: u32,
    empty_roots: [Field; 33],
) -> [Field; 32] {
    let mut path: [Field; 32] = [0; 32];
    let mut i: u64 = 0;
    while i < 32 {
        let anc: u64 = (target as u64) >> i;
        let sib: u64 = anc ^ 1;
        path[i as u32] = subtree_root(i, sib, revoked, revoked_len, empty_roots);
        i += 1;
    }
    path
}

/// 生成器返回值（转 Prover.toml 后喂正式电路）。
struct WitnessOut {
    agent_pub_x: Field,
    agent_pub_y: Field,
    sig_s: Field,
    sig_r8_x: Field,
    sig_r8_y: Field,
    revocation_root: Field,
    revocation_index: Field,
    revocation_path: [Field; REVOCATION_DEPTH],
    intent_hash: [u8; 32],
}

pub fn main(
    secret: Field,
    delegation_hash: [u8; 32],
    recipient: [u8; 20],
    amount: u64,
    category: [u8; 32],
    spend_nonce: u64,
    expires_at: u64,
    revoked_a: [u8; 32],
    revoked_b: [u8; 32],
) -> pub WitnessOut {
    // agent 身份：Jubjub 公钥 → 承诺（断言 1 的 agent_commit）
    let (pub_x, pub_y) = eddsa_to_pub(secret);
    let agent_commit = agent_commit_from_pubkey(pub_x, pub_y);
    // 签名对象：encode_field(intent_hash)（断言 9 + 断言 2）
    let intent_hash = compute_intent_hash(
        agent_commit,
        delegation_hash,
        recipient,
        amount,
        category,
        spend_nonce,
        expires_at,
    );
    let message = encode_field(intent_hash);
    let (sig_s, sig_r8_x, sig_r8_y) = eddsa_sign(secret, message);

    // 撤销树：目标不在撤销集 → EMPTY 叶子；revoked_a/b 叶子 = encode_field(hash)
    let empty_roots = compute_empty_roots();
    let revoked: [(u32, Field); MAX_REVOKED] = [
        (revocation_index_u32(revoked_a), encode_field(revoked_a)),
        (revocation_index_u32(revoked_b), encode_field(revoked_b)),
    ];
    let revocation_root = subtree_root(32, 0, revoked, MAX_REVOKED, empty_roots);
    let target_index = revocation_index_u32(delegation_hash);
    let revocation_path = build_path(target_index, revoked, MAX_REVOKED, empty_roots);

    WitnessOut {
        agent_pub_x: pub_x,
        agent_pub_y: pub_y,
        sig_s,
        sig_r8_x,
        sig_r8_y,
        revocation_root,
        revocation_index: target_index as Field,
        revocation_path,
        intent_hash,
    }
}

mod tests {
    use crate::{
        build_path, compute_empty_roots, compute_intent_hash, compute_merkle_root, eddsa_sign,
        encode_field, revocation_index_u32, subtree_root, MAX_REVOKED, REVOCATION_DEPTH,
    };
    use eddsa::{eddsa_to_pub, eddsa_verify};
    use poseidon::poseidon::PoseidonHasher;

    // ——— 固定输入（与正式管线 gen-witness/Prover.toml 一致；除 revoked 外与
    //     circuits/src/main.nr 测试的共享 golden fixture 相同）———

    fn fixture_delegation_hash() -> [u8; 32] {
        let mut c = [0u8; 32];
        for i in 0..32 {
            c[i] = (0x21 + i) as u8;
        }
        c
    }

    fn revoked_a() -> [u8; 32] {
        [0x01; 32]
    }

    fn revoked_b() -> [u8; 32] {
        [0x02; 32]
    }

    #[test]
    fn sign_verify_roundtrip() {
        // gen 侧签名必须通过电路同款验签（eddsa_verify::<PoseidonHasher>）。
        let secret = 4242;
        let message = 987654321;
        let (s, r8x, r8y) = eddsa_sign(secret, message);
        let (px, py) = eddsa_to_pub(secret);
        assert(eddsa_verify::<PoseidonHasher>(px, py, s, r8x, r8y, message));
        // 负例：message 篡改 → 验签失败
        assert(!eddsa_verify::<PoseidonHasher>(px, py, s, r8x, r8y, message + 1));
    }

    #[test]
    fn tree_consistency_and_revocation() {
        // 目标委托不在撤销集：EMPTY 叶子证明必须等于树根。
        let dh = fixture_delegation_hash();
        let ra = revoked_a();
        let rb = revoked_b();
        let empty_roots = compute_empty_roots();
        let revoked: [(u32, Field); MAX_REVOKED] = [
            (revocation_index_u32(ra), encode_field(ra)),
            (revocation_index_u32(rb), encode_field(rb)),
        ];
        let root = subtree_root(32, 0, revoked, MAX_REVOKED, empty_roots);
        let target = revocation_index_u32(dh);
        let path = build_path(target, revoked, MAX_REVOKED, empty_roots);
        assert(compute_merkle_root(0, target as Field, path) == root);

        // 已撤销委托：其叶子非 EMPTY → 同一 root 下 EMPTY 证明必失败。
        let r1 = revoked[0].0;
        let r1_path = build_path(r1, revoked, MAX_REVOKED, empty_roots);
        assert(compute_merkle_root(0, r1 as Field, r1_path) != root);
    }

    #[test]
    fn intent_hash_golden() {
        // golden 与 core Rust zk_intent_hash() 锁定（S-09b）：
        // 2352acec5b8e431c2e9167f9a07c7b237285d836599b860dba4841663ededf57。
        // 注意：此处 agent_commit 必须用共享 fixture（0x11+i），不是由 secret 派生——
        // 黄金向量锁的是 compute_intent_hash 函数本身，与场景密钥无关。
        let mut agent_commit = [0u8; 32];
        for i in 0..32 {
            agent_commit[i] = (0x11 + i) as u8;
        }
        let mut recipient = [0u8; 20];
        for i in 0..20 {
            recipient[i] = (0x31 + i) as u8;
        }
        let mut category = [0u8; 32];
        for i in 0..32 {
            category[i] = (0x51 + i) as u8;
        }
        let h = compute_intent_hash(
            agent_commit,
            fixture_delegation_hash(),
            recipient,
            1234,
            category,
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
    fn revocation_index_le_bytes() {
        // 锁定 LE 派生：delegation_hash[0..4] LE → u32。
        let mut dh = [0u8; 32];
        dh[0] = 0x01;
        dh[1] = 0x02;
        dh[2] = 0x03;
        dh[3] = 0x04;
        assert(revocation_index_u32(dh) == 0x04030201);
    }
}
