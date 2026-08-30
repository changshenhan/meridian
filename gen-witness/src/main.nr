//! gen-witness —— S-09 正式电路 spend_authorization 的确定性 witness 生成器（CI 管线用）。
//!
//! 与 smoke-gen（Rust，TEMPORARY）不同：此处签名（eddsa_sign）与撤销树建树/寻路全部在
//! Noir 内做（S-05 教训：不做跨语言曲线数学）。Rust core 侧只负责纯字节逻辑
//! （zk_intent_hash，见 core/src/dsa.rs），由共享 hex 向量锁定。
//!
//! 用法（CI formal_zk.sh）：
//!   nargo fetch && nargo compile && nargo execute --overwrite-return
//! → 返回值（签名/pubkey/撤销树/path/intent_hash）写入本包 Prover.toml 的 `return` 键，
//!   由 scripts/formal_gen_to_prover.py 转成 circuits/Prover.toml 喂正式电路。
//!
//! 关键一致性约束（与 circuits/src/main.nr 零漂移）：
//!   · compute_intent_hash / encode_field / compute_merkle_root 与电路同实现
//!     （sha256 规范字节、31B LE、pedersen_hash）；撤销索引 = delegation_hash 全 32B LE
//!     （S-36 全宽化，与电路/聚合器 RevocationSet 同一派生同一位序）
//!   · eddsa_challenge 镜像电路的 eddsa_verify 的 Poseidon 域
//!     （h = Poseidon(R8x,R8y,Ax,Ay,m)），输出 (r, h, r8x, r8y)。
//!     签名标量 s = (r + h*sk) % SUBORDER 由 build 脚本（Python 大整数）计算：
//!     Noir 1.0 移除了 Field 模运算（`%` 编译报错，eddsa fork 自身测试亦注明
//!     "fields can't use modulo"），且 ScalarField 无算符、base4_slices 为 pub(crate)，
//!     无法在 Noir 内做 mod-n 归约 → 归约移到可信 Python 层（与 Rust core 的纯字节
//!     逻辑同级，非曲线数学；R8/h/公钥仍在 Noir）。端到端正确性由正式电路
//!     eddsa_verify（CI nargo execute + bb prove/verify）把关：s 错则证明失败。
//!   · 撤销树：稀疏 Merkle，深度 256（S-36 全宽化），叶子=EMPTY(0)；撤销委托的叶子 =
//!     encode_field(hash)（非零）；目标委托不在撤销集 → 其叶子为 EMPTY →
//!     电路 compute_merkle_root(0, delegation_hash, path) == root
//!
//! 建树用 unconstrained（brillig）递归（subtree_root）：gen-witness 只求值不证明，unconstrained
//! 值被 witness-hint 进约束系统，避免在生成器里堆约束、也规避约束上下文递归风险。
//! 树正确性由本包 #[test]（build→compute_merkle_root 自验）与正式电路 prove/verify 双重兜底。

use eddsa::eddsa_to_pub; // eddsa_verify 仅在测试模块用（fork 常量正例）
use edwards::{bjj::BabyJubJub, Curve, CurveTrait, ScalarField};
use poseidon::poseidon::PoseidonHasher;
use sha256;
// Noir 1.0：Hasher trait 提供 write/finish，需显式导入（CI run 31931011528 实测）。
use std::hash::Hasher;

/// 撤销稀疏 Merkle 树深度 = 撤销索引位数（与电路 REVOCATION_DEPTH 一致；S-36 全宽化：
/// 索引 = delegation_hash 全 32B LE u256，与聚合器 RevocationSet::SPARSE_DEPTH 同值）。
global REVOCATION_DEPTH: u32 = 256;

/// 本生成器支持的最大撤销集大小（固定入参数组定长；不足补零位 + revoked_len）。
global MAX_REVOKED: u32 = 2;

// eddsa fork 的 BASE8 为模块级未 pub 常量，复制一份（见 eddsa/src/lib.nr）。
// SUBORDER 不再在此复制：签名标量归约已移到 build 脚本（formal_gen_to_prover.py），
// 其 SUBORDER 常量与 eddsa fork 的 eddsa_verify 断言值一致；不一致则证明失败（CI 红）。
global BASE8_X: Field =
    5299619240641551281634865583518297030282874472190772894086521144482721001553;
global BASE8_Y: Field =
    16950150798460657717958625567821834550301663161624707787222815936182638968203;

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
    // Noir 1.0 beta.26 的 u64 无 to_le_bytes（CI run 31931011528 实测）：转 Field 取
    // 32 字节 LE，低 8 字节即 u64 的 LE 表示（u64 < 2^64；Rust sha2 用 amount.to_le_bytes()）。
    let amount_le: [u8; 32] = (amount as Field).to_le_bytes();
    for i in 0..8 {
        preimage[84 + i] = amount_le[i];
    }
    for i in 0..32 {
        preimage[92 + i] = category[i];
    }
    let nonce_le: [u8; 32] = (spend_nonce as Field).to_le_bytes();
    for i in 0..8 {
        preimage[124 + i] = nonce_le[i];
    }
    let exp_le: [u8; 32] = (expires_at as Field).to_le_bytes();
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

/// 撤销树索引位（S-36 全宽化）：位 k = (idx[k/8] >> (k%8)) & 1（LE u256 位序，与聚合器
/// RevocationSet 同一派生）。索引即 delegation_hash 本身，不落单个 Field（BN254 域仅
/// ~254 bit）——电路侧按位现场派生，本包建树/寻路按 256-bit 字节运算（下）。
fn index_bit(idx: [u8; 32], k: u32) -> bool {
    // Noir 移位量与被移对象必须同位宽（u8 >> u32 报 "Integers must have the same bit
    // width"，S-36 实测）→ 移位量 cast u8（k%8 ≤ 7 无损）。
    ((idx[k / 8] >> ((k % 8) as u8)) & 1) == 1
}

/// 256-bit LE 右移 1 位（与聚合器 revocation.rs::shr1 同语义）。
unconstrained fn shr1(mut a: [u8; 32]) -> [u8; 32] {
    for i in 0..31 {
        a[i] = (a[i] >> 1) | (a[i + 1] << 7);
    }
    a[31] >>= 1;
    a
}

/// 256-bit LE 左移 1 位带进位：pos ← pos*2 + bit（建树自根向下寻路用；u16 中转避免
/// u8 左移高位丢失歧义）。
unconstrained fn shl1(pos: [u8; 32], bit: bool) -> [u8; 32] {
    let mut r: [u8; 32] = [0; 32];
    let mut carry: u16 = if bit { 1 } else { 0 };
    for i in 0..32 {
        let v: u16 = (pos[i] as u16) * 2 + carry;
        r[i] = (v & 0xFF) as u8;
        carry = v >> 8;
    }
    r
}

/// 256-bit LE 全等。
unconstrained fn eq256(a: [u8; 32], b: [u8; 32]) -> bool {
    let mut eq = true;
    for i in 0..32 {
        eq = eq & (a[i] == b[i]);
    }
    eq
}

/// 内联 compute_merkle_root（与电路同实现，merkle_insert 模式，pedersen_hash；
/// 索引按字节传入、按位现场派生——与电路 compute_merkle_root 零漂移）。
fn compute_merkle_root<let N: u32>(leaf: Field, index: [u8; 32], hash_path: [Field; N]) -> Field {
    let mut current = leaf;
    for i in 0..N {
        let path_bit = index_bit(index, i);
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

/// 确定性 BabyJubJub EdDSA 挑战（镜像电路 eddsa_verify 的 Poseidon 域；eddsa fork 无 sign，
/// 且 Noir 1.0 无法做 `% SUBORDER`）。返回 (r, h, r8_x, r8_y)：
///   r  = Poseidon(secret, message)            ← 确定性 nonce
///   r8 = [r]B8                                ← 验证方程左点
///   h  = Poseidon(r8.x, r8.y, A.x, A.y, m)    ← 挑战
/// 签名标量 s = (r + h*secret) % SUBORDER 由 build 脚本（Python 大整数）计算，
/// 见 scripts/formal_gen_to_prover.py（文件头注释说明 why）。
fn eddsa_challenge(secret: Field, message: Field) -> (Field, Field, Field, Field) {
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
    (r, h, r8.x, r8.y)
}

/// 空子树根表：empty_roots[k] = 深度 k 的全空树根（pedersen 叠 2 的平方；S-36 深度 256）。
unconstrained fn compute_empty_roots() -> [Field; 257] {
    let mut roots: [Field; 257] = [0; 257];
    let mut r: Field = 0;
    for i in 1..257 {
        r = std::hash::pedersen_hash([r, r]);
        roots[i] = r;
    }
    roots
}

/// 子树的根（unconstrained/brillig 递归）。S-36 全宽化：位置/索引为 256-bit LE 字节串，
/// u64/u32 装不下，改按字节运算。
/// 参数：
///   height      距叶子的层数（根 = REVOCATION_DEPTH = 256，叶 = 0）
///   pos         本子树位置（256-bit LE；height 层处 pos = 索引 >> height，由根向下
///               逐层 shl1 构造，高位自然为零）
///   revoked_idx 撤销索引原值（delegation_hash 全 32B）
///   shifted     shifted[j] = revoked_idx[j] >> height（随递归同步维护：子层 =
///               shl1(shifted[j], bit_{height-1}(revoked_idx[j]))）——成员判定只需
///               eq256(shifted[j], pos)，避免每节点重算 256 位移位
///   revoked_leaf / revoked_len  撤销叶值（= encode_field(撤销委托哈希)，非零）与有效长度
/// 子树不含任何撤销叶 → 短路为空子树根；含 → 递归左右子。
unconstrained fn subtree_root(
    height: u64,
    pos: [u8; 32],
    revoked_idx: [[u8; 32]; MAX_REVOKED],
    shifted: [[u8; 32]; MAX_REVOKED],
    revoked_leaf: [Field; MAX_REVOKED],
    revoked_len: u32,
    empty_roots: [Field; 257],
) -> Field {
    let mut has = false;
    for j in 0..MAX_REVOKED {
        if j < revoked_len {
            has = has | eq256(shifted[j], pos);
        }
    }
    // Noir 1.0 无 `&&`/`||` 运算符（编译器："Noir has no logical-and (&&) operator",
    // 建议用 `&`）且不支持提前 `return`（"Early 'return' is unsupported"）——两者均为
    // CI run 31933379072 实测。改为 if/else 表达式 + `&`（brillig 递归保留）。
    if !has {
        empty_roots[height as u32]
    } else if height == 0 {
        let mut v: Field = 0;
        for j in 0..MAX_REVOKED {
            if (j < revoked_len) & eq256(shifted[j], pos) {
                v = revoked_leaf[j];
            }
        }
        v
    } else {
        // 子层 shifted'_j = revoked_j >> (height-1) = (revoked_j >> height)*2
        //        + bit_{height-1}(revoked_j)——左右子同值（shifted 跟随撤销索引，不跟随
        //        pos；左右由 pos_child 区分，成员判定 eq256(shifted', pos_child) 自然分岔）。
        // bit_{height-1}(revoked_j) 直接按字节取位（无需移位）。
        let lvl: u32 = (height - 1) as u32;
        let byte = lvl / 8;
        let off = lvl % 8;
        let mut child_shifted: [[u8; 32]; MAX_REVOKED] = [[0; 32]; MAX_REVOKED];
        for j in 0..MAX_REVOKED {
            let b = ((revoked_idx[j][byte] >> (off as u8)) & 1) == 1;
            child_shifted[j] = shl1(shifted[j], b);
        }
        // pos*2（左，进位 0）/ pos*2 + 1（右，进位 1）
        let left_pos = shl1(pos, false);
        let right_pos = shl1(pos, true);
        let left = subtree_root(
            height - 1, left_pos, revoked_idx, child_shifted, revoked_leaf, revoked_len,
            empty_roots,
        );
        let right = subtree_root(
            height - 1, right_pos, revoked_idx, child_shifted, revoked_leaf, revoked_len,
            empty_roots,
        );
        std::hash::pedersen_hash([left, right])
    }
}

/// 目标叶子索引的兄弟路径：path[i] = 第 i 层兄弟子树根（撤销树，EMPTY 叶子）。
/// target = delegation_hash（即索引本身，S-36 全宽化）。第 i 层祖先 = target >> i
/// （增量 shr1 维护），兄弟 = 祖先第 0 位翻转（仅字节 0 变）。
unconstrained fn build_path(
    target: [u8; 32],
    revoked_idx: [[u8; 32]; MAX_REVOKED],
    revoked_leaf: [Field; MAX_REVOKED],
    revoked_len: u32,
    empty_roots: [Field; 257],
) -> [Field; REVOCATION_DEPTH] {
    let mut path: [Field; REVOCATION_DEPTH] = [0; REVOCATION_DEPTH];
    let mut anc: [u8; 32] = target;
    let mut shifted: [[u8; 32]; MAX_REVOKED] = [[0; 32]; MAX_REVOKED];
    for j in 0..MAX_REVOKED {
        shifted[j] = revoked_idx[j];
    }
    let mut i: u64 = 0;
    while i < REVOCATION_DEPTH as u64 {
        // 兄弟 = 祖先第 0 位翻转
        let mut sib: [u8; 32] = anc;
        sib[0] = sib[0] ^ 1;
        path[i as u32] = subtree_root(
            i, sib, revoked_idx, shifted, revoked_leaf, revoked_len, empty_roots,
        );
        anc = shr1(anc);
        for j in 0..MAX_REVOKED {
            shifted[j] = shr1(shifted[j]);
        }
        i += 1;
    }
    path
}

/// 生成器返回值（转 Prover.toml 后喂正式电路）。
/// 字段顺序 = 扁平序列化顺序：7 标量 ‖ revocation_path[256] ‖ intent_hash[32]（=295）。
/// sig_s 不在其中：由 build 脚本从 (sig_r, sig_h) 计算（Python 大整数 mod SUBORDER）。
/// revocation_index 字段已随 S-36 退役：索引 = delegation_hash 全 32B LE（公共输入本身，
/// 无独立 witness 字段；256-bit 也落不进单个 Field）。
pub struct WitnessOut {
    agent_pub_x: Field,
    agent_pub_y: Field,
    sig_r: Field,
    sig_h: Field,
    sig_r8_x: Field,
    sig_r8_y: Field,
    revocation_root: Field,
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
    let (sig_r, sig_h, sig_r8_x, sig_r8_y) = eddsa_challenge(secret, message);

    // 撤销树：目标不在撤销集 → EMPTY 叶子；revoked_a/b 叶子 = encode_field(hash)。
    // 索引 = delegation_hash 全 32B LE（S-36 全宽化）。subtree_root/build_path/
    // compute_empty_roots 为 unconstrained（brillig，只求值不证明）→ 约束上下文调用需
    // unsafe {}（Noir 1.0："Call to unconstrained function from constrained function is
    // unsafe"，CI run 31933379072 实测）。
    let empty_roots = unsafe { compute_empty_roots() };
    let revoked_idx: [[u8; 32]; MAX_REVOKED] = [revoked_a, revoked_b];
    let revoked_leaf: [Field; MAX_REVOKED] = [encode_field(revoked_a), encode_field(revoked_b)];
    // 根层 shifted = revoked >> 256 = 全零（不变量：shifted[j] = revoked_j >> height）。
    let root_shifted: [[u8; 32]; MAX_REVOKED] = [[0; 32]; MAX_REVOKED];
    let revocation_root = unsafe {
        subtree_root(
            REVOCATION_DEPTH as u64,
            [0; 32],
            revoked_idx,
            root_shifted,
            revoked_leaf,
            MAX_REVOKED,
            empty_roots,
        )
    };
    let revocation_path =
        unsafe { build_path(delegation_hash, revoked_idx, revoked_leaf, MAX_REVOKED, empty_roots) };

    WitnessOut {
        agent_pub_x: pub_x,
        agent_pub_y: pub_y,
        sig_r,
        sig_h,
        sig_r8_x,
        sig_r8_y,
        revocation_root,
        revocation_path,
        intent_hash,
    }
}

mod tests {
    use crate::{
        build_path, compute_empty_roots, compute_intent_hash, compute_merkle_root,
        eddsa_challenge, encode_field, eq256, index_bit, shl1, shr1, subtree_root, MAX_REVOKED,
        REVOCATION_DEPTH,
    };
    use eddsa::{eddsa_to_pub, eddsa_verify};
    use edwards::{bjj::BabyJubJub, Curve, CurveTrait, ScalarField};
    use poseidon::poseidon::PoseidonHasher;
    use crate::{BASE8_X, BASE8_Y};

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

    /// 上游 noir-lang/eddsa（commit 7e206c9）测试的预计算签名常量：secret=123, msg=789。
    /// eddsa fork 自身测试同款模式——"Manually computed as fields can't use modulo"，
    /// 上游 CI（test.yml 跨版本跑 nargo test）持续验证这些常量在 PoseidonHasher 域下通过
    /// eddsa_verify。此处复用作为本包验签域的正例；正式管线的签名标量由 build 脚本计算
    /// （Python 大整数），端到端由正式电路 eddsa_verify 把关。
    #[test]
    fn fork_signature_constants_verify() {
        let (px, py) = eddsa_to_pub(123);
        let r = 1414770703199880747815475415092878800081323795074043628810774576767372531818;
        let s = 30333430637424319196043722294837632681219980330991241982145549329256671548;
        let base8: BabyJubJub = Curve { x: BASE8_X, y: BASE8_Y };
        let r8 = base8.mul(ScalarField::<63>::from(r));
        let msg: Field = 789;
        assert(eddsa_verify::<PoseidonHasher>(px, py, s, r8.x, r8.y, msg));
        // 负例：message 篡改 → 验签失败（同一 r8，改 msg 后 h 变）
        assert(!eddsa_verify::<PoseidonHasher>(px, py, s, r8.x, r8.y, msg + 1));
    }

    #[test]
    fn challenge_deterministic() {
        // eddsa_challenge 在同一输入下必须确定（r、h、r8 固定）——witness 生成确定性。
        // 逐项 assert：Noir 1.0 无 `&&`/`||` 运算符（Field `==` 返回 Field-truth，`&&` 在
        // Field 语境报 "Bitwise operations are invalid on Field"、bool 语境报 "Noir has no
        // logical-and"；eddsa fork 测试亦规避 `&&`/`||`，CI run 31933379072 实测），
        // 故拆成单比较。
        let (r1, h1, x1, y1) = eddsa_challenge(4242, 987654321);
        let (r2, h2, x2, y2) = eddsa_challenge(4242, 987654321);
        assert(r1 == r2);
        assert(h1 == h2);
        assert(x1 == x2);
        assert(y1 == y2);
        // 换 message → 挑战全变（r、h 均变；r 变则 R8 变）
        let (r3, h3, _, _) = eddsa_challenge(4242, 987654322);
        assert(r1 != r3);
        assert(h1 != h3);
    }

    #[test]
    fn tree_consistency_and_revocation() {
        // 目标委托不在撤销集：EMPTY 叶子证明必须等于树根（S-36 全宽索引：索引 = dh 本身）。
        let dh = fixture_delegation_hash();
        let ra = revoked_a();
        let rb = revoked_b();
        let empty_roots = unsafe { compute_empty_roots() };
        let revoked_idx: [[u8; 32]; MAX_REVOKED] = [ra, rb];
        let revoked_leaf: [Field; MAX_REVOKED] = [encode_field(ra), encode_field(rb)];
        let root_shifted: [[u8; 32]; MAX_REVOKED] = [[0; 32]; MAX_REVOKED];
        let root = unsafe {
            subtree_root(
                REVOCATION_DEPTH as u64,
                [0; 32],
                revoked_idx,
                root_shifted,
                revoked_leaf,
                MAX_REVOKED,
                empty_roots,
            )
        };
        let path = unsafe { build_path(dh, revoked_idx, revoked_leaf, MAX_REVOKED, empty_roots) };
        assert(compute_merkle_root(0, dh, path) == root);

        // 已撤销委托：其叶子非 EMPTY → 同一 root 下 EMPTY 证明必失败。
        let r1_path =
            unsafe { build_path(ra, revoked_idx, revoked_leaf, MAX_REVOKED, empty_roots) };
        assert(compute_merkle_root(0, ra, r1_path) != root);
    }

    #[test]
    fn full_width_index_collides_prefix_only() {
        // S-36 碰撞回归（镜像 circuits 同名测试/聚合器 S-34 回归）：两 dh 同低 32 位前缀、
        // 高位相异——32-bit 前缀索引时代共享叶子（后写覆盖先写），全宽索引下必走相异叶，
        // 各自的非成员根互不相等。
        let mut low_a = [0u8; 32];
        let mut low_b = [0u8; 32];
        low_a[0] = 0xAA;
        low_a[1] = 0xBB;
        low_a[2] = 0xCC;
        low_a[3] = 0xDD;
        low_b[0] = 0xAA;
        low_b[1] = 0xBB;
        low_b[2] = 0xCC;
        low_b[3] = 0xDD;
        low_a[20] = 0x11;
        low_b[20] = 0x22;
        let empty_roots = unsafe { compute_empty_roots() };
        // 撤销集只含 a：b 的未撤销证明必须成立，且 a 自己的 EMPTY 证明必须失败
        let revoked_idx: [[u8; 32]; MAX_REVOKED] = [low_a, [0; 32]];
        let revoked_leaf: [Field; MAX_REVOKED] = [encode_field(low_a), 0];
        let path_b =
            unsafe { build_path(low_b, revoked_idx, revoked_leaf, 1, empty_roots) };
        let root = unsafe {
            subtree_root(
                REVOCATION_DEPTH as u64,
                [0; 32],
                revoked_idx,
                [[0; 32]; MAX_REVOKED],
                revoked_leaf,
                1,
                empty_roots,
            )
        };
        assert(compute_merkle_root(0, low_b, path_b) == root);
        // a 的 EMPTY 证明（同树）必失败：其叶子已被撤销叶占据
        let path_a =
            unsafe { build_path(low_a, revoked_idx, revoked_leaf, 1, empty_roots) };
        assert(compute_merkle_root(0, low_a, path_a) != root);
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
    fn revocation_empty_roots_match_aggregator_golden() {
        // S-41 反向锁定（TECH_SPEC §4.6 验证锚③）：聚合器 `aggregator/src/noir_pedersen.rs`
        // 复现的 Noir pedersen_hash 算出的空子树根表与本电路 `compute_empty_roots` 必须
        // 逐层同值——以下常量 = 聚合器侧 Rust golden（hex 见 revocation.rs 单测，第三实现
        // Python 交叉）。双向：聚合器单测锁 hex ↔ 本测试锁同值十进制。
        let empty_roots = unsafe { compute_empty_roots() };
        assert(
            empty_roots[1]
                == 17954372136461894568820199868962143715279932924957662285438325406238856880109,
        );
        assert(
            empty_roots[2]
                == 15315010434373228768515045847926951401477884091230007539886053341418284848464,
        );
        assert(
            empty_roots[8]
                == 5810866061421176229185100919314262997457801135114610274353230460838429180503,
        );
        assert(
            empty_roots[16]
                == 11033938207523021649122316027295742559227608161317650429835019071130941169536,
        );
        assert(
            empty_roots[256]
                == 11748306663608198149817056492228663363734754727859538139122908701354431492554,
        );
        // 全树交叉（最强锚）：撤销集 {0x01…32, 0x02…32}（与聚合器
        // `gen_witness_fixture_root_matches_noir` 同一 fixture）的整树根——聚合器
        // RevocationSet 算出的根必须是同一个 Field。
        let ra = revoked_a();
        let rb = revoked_b();
        let revoked_idx: [[u8; 32]; MAX_REVOKED] = [ra, rb];
        let revoked_leaf: [Field; MAX_REVOKED] = [encode_field(ra), encode_field(rb)];
        let root = unsafe {
            subtree_root(
                REVOCATION_DEPTH as u64,
                [0; 32],
                revoked_idx,
                [[0; 32]; MAX_REVOKED],
                revoked_leaf,
                MAX_REVOKED,
                empty_roots,
            )
        };
        assert(
            root == 4155254769118169116647862288831891899637773286975008049501227812260722607649,
        );
    }

    #[test]
    fn revocation_index_bit_is_full_le_u256() {
        // 锁定全宽位派生（S-36）：位 k = (dh[k/8] >> (k%8)) & 1——LE 字节序、字节内 LSB 在前，
        // 与聚合器 RevocationSet 位序契约（TECH_SPEC §4.6）一致。
        let mut dh = [0u8; 32];
        dh[0] = 0x01; // bit 0
        dh[1] = 0x80; // bit 15
        dh[31] = 0x80; // bit 255
        assert(index_bit(dh, 0));
        assert(!index_bit(dh, 1));
        assert(index_bit(dh, 15));
        assert(!index_bit(dh, 14));
        assert(index_bit(dh, 255));
        assert(!index_bit(dh, 254));
        // 全零索引无任何位
        let mut z = [0u8; 32];
        z[17] = 0xFF;
        assert(index_bit(z, 136));
        assert(index_bit(z, 143));
        assert(!index_bit(z, 135));
        assert(!index_bit(z, 144));
    }

    #[test]
    fn shl1_shr1_roundtrip_256bit() {
        // 256-bit LE 移位原语自验：shl1 带 bit 进位、shr1 逆行；高位不越出 32 字节。
        let mut v: [u8; 32] = [0; 32];
        v[31] = 0xFF; // 最高字节全 1
        // 左移进位溢出高位（可承受：寻路 pos 只在深度 ≤ 256 内增长，不越界）。
        // shl1/shr1/eq256 是 unconstrained（brillig）→ 测试（约束上下文）内调用需 unsafe{}。
        let shifted = unsafe { shl1(v, true) };
        assert(shifted[0] == 1);
        let round = unsafe { shr1(shifted) };
        assert(round[31] == 0x7F);
        // 空位往返
        let z: [u8; 32] = [0; 32];
        let up = unsafe { shl1(z, true) };
        let down = unsafe { shr1(up) };
        assert(unsafe { eq256(down, z) });
        assert(!(unsafe { eq256(up, z) }));
    }

    #[test]
    fn aggregator_non_membership_path_digest() {
        // S-42 跨实现锚（TECH_SPEC §4.6 残余②前半）：本电路 `build_path`（CI 管线喂正式
        // 电路 `revocation_path` witness 的实现）对 fixture 撤销集 {0x01…32, 0x02…32} 产出的
        // 非成员路径，与聚合器 `RevocationSet::non_membership_witness`（S-42，Rust 侧）产出
        // 的路径必须**逐字节同一**——任一层相异即红。逐层 pin 256 个 Field 太重，取
        // 「逐层 Field 大端 32B 扁平（256×32 = 8192B）→ sha256」摘要（对任一层的任何字节
        // 漂移敏感）。golden = 聚合器 Rust 侧单测 `non_membership_path_digest_matches_noir_golden`
        // 同值（双向：Rust 锁 hex ↔ 本测试锁字节常量）。
        let dh = fixture_delegation_hash();
        let ra = revoked_a();
        let rb = revoked_b();
        // Safety: compute_empty_roots / build_path 均 unconstrained（brillig），只求值不证明。
        let empty_roots = unsafe { compute_empty_roots() };
        let path = unsafe {
            build_path(
                dh,
                [ra, rb],
                [encode_field(ra), encode_field(rb)],
                MAX_REVOKED,
                empty_roots,
            )
        };
        // 逐层 Field → 32B 大端扁平（聚合器 path[d] 也是 BE Field 32B 外形，TECH_SPEC §4.6）。
        let mut flat: [u8; 8192] = [0; 8192];
        for i in 0..REVOCATION_DEPTH {
            let pb: [u8; 32] = path[i].to_be_bytes();
            for j in 0..32u32 {
                flat[(i * 32) + j] = pb[j];
            }
        }
        let digest = sha256::digest(flat);
        // golden = 9342885b1237b774f32c279e3f43139a0dbfab9bc11d966afc194ceb47a4269e
        let want: [u8; 32] = [
            0x93, 0x42, 0x88, 0x5b, 0x12, 0x37, 0xb7, 0x74, 0xf3, 0x2c, 0x27, 0x9e, 0x3f, 0x43,
            0x13, 0x9a, 0x0d, 0xbf, 0xab, 0x9b, 0xc1, 0x1d, 0x96, 0x6a, 0xfc, 0x19, 0x4c, 0xeb,
            0x47, 0xa4, 0x26, 0x9e,
        ];
        assert(digest == want);
    }
}
