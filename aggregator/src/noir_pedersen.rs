//! Noir `std::hash::pedersen_hash` 的 Rust 逐位复现（S-41，TECH_SPEC §4.6 撤销树哈希对齐）。
//!
//! 为什么是这份文件：S-40 收口验证侧后，bb 模式要求聚合器账本撤销根与电路
//! `revocation_root` 公共输入数值可比，而电路树用的是 Noir `pedersen_hash`（bb Pedersen）。
//! 定夺记录见 TECH_SPEC §4.6：改聚合器侧、电路不动（电路换哈希要再付 256 层置换，约束
//! 预算与 prove 时长双输）。
//!
//! 规范（noir_stdlib/src/hash/mod.nr @ v1.0.0-beta.26，`pedersen_hash_with_separator`）：
//! `pedersen_hash([l, r])`（分隔符 0，N=2）= 取 MSM `l·G0 + r·G1 + 2·G_len` 的 **x 坐标**，
//! 第三项是 length 标量（= 输入个数 N）乘独立域 `"pedersen_hash_length"` 的生成器；
//! G0/G1/G_len 分别取域 `"DEFAULT_DOMAIN_SEPARATOR"` 的下标 0/1 与 length 域下标 0。bb
//! （6.0.0-nightly.20260724）把这两组生成器**硬编码**在
//! `crypto/generators/generator_data.hpp` + `ecc/groups/precomputed_generators_grumpkin_impl.hpp`
//! （8 + 1 个常量点，本文件内嵌其中 4 个）——本场景 N=2 完全落在预计算范围内，
//! **无需复现运行时 `derive_generators`**（S-05 教训：不做跨语言曲线推导）。
//!
//! 域与曲线：Grumpkin 坐标域 = BN254 标量域 r（218882…95617），曲线 y² = x³ + b，
//! b = r − 17。实现为手写 Montgomery 算术（4×u64 肢，零新依赖）+ Jacobian 点运算 +
//! 固定基 4-bit 窗口表（`OnceLock` 预计算）。验证锚（三层，均固化为本文件/revocation 单测）：
//! ① Noir stdlib 自带 golden（`hash/mod.nr::assert_pedersen`，bb 对齐产物）；
//! ② bb 的 9 个预计算点全部过曲线方程（锁域算术与常量）；
//! ③ 空子树根表 + gen-witness fixture 全树根（revocation.rs 单测，与 Noir nargo 输出锁定）。
//!
//! 诚实边界：只实现 N=2 哈希与 S-41 撤销树所需的最小面；`pedersen_hash_with_separator`
//! 的一般分隔符路径、生成器运行时推导均不在内（需求超出 bb 预计算表时才需要）。

use std::sync::OnceLock;

// ——— 域算术（BN254 标量域 r，Montgomery 形式，R = 2^256）———

/// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
/// （= Grumpkin 基域），小端 u64 肢。
const MODULUS: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// `-r^{-1} mod 2^64`（REDC 用），编译期 Newton 迭代求出。
const INV: u64 = {
    let mut inv: u64 = 1;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(MODULUS[0].wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
};

fn cmp_ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn add_mod(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (v1, c1) = a[i].overflowing_add(b[i]);
        let (v2, c2) = v1.overflowing_add(carry);
        out[i] = v2;
        carry = (c1 as u64) | (c2 as u64);
    }
    if carry == 1 || cmp_ge(&out, &MODULUS) {
        out = sub_mod(&out, &MODULUS);
    }
    out
}

fn sub_mod(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (v1, b1) = a[i].overflowing_sub(b[i]);
        let (v2, b2) = v1.overflowing_sub(borrow);
        out[i] = v2;
        borrow = (b1 as u64) | (b2 as u64);
    }
    if borrow == 1 {
        // 回绕（a < b，均 < r）→ a − b + r ∈ (0, r)：裸加一次即归约。
        // 不能走 add_mod——out + r 会溢出 2^256，其 carry 分支再去减 r 就和这里
        // 乒乓递归到栈爆（S-41 实测：Jacobian 公式的负数减法必然踩中）。
        // 该加法**必然**溢出（wrapped + r = (a−b+r) + 2^256），进位就是模 2^256 的
        // 还原本身，结果肢已正确，丢弃进位即可——不加 debug_assert。
        let mut carry = 0u64;
        for i in 0..4 {
            let (v1, c1) = out[i].overflowing_add(MODULUS[i]);
            let (v2, c2) = v1.overflowing_add(carry);
            out[i] = v2;
            carry = (c1 as u64) | (c2 as u64);
        }
        let _ = carry;
    }
    out
}

/// 512-bit 乘积（操作数为非 Montgomery 的普通值且 < r < 2^254 → 8 肢足够）。
fn mul_wide(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut carry: u64 = 0;
        for j in 0..4 {
            let v = (a[i] as u128) * (b[j] as u128) + t[i + j] as u128 + carry as u128;
            t[i + j] = v as u64;
            carry = (v >> 64) as u64;
        }
        t[i + 4] = t[i + 4].wrapping_add(carry);
    }
    t
}

/// REDC：t < 2^512 → t·R^{-1} mod r（输出 < 2r，已条件减一次）。
fn mont_reduce(mut t: [u64; 8]) -> [u64; 4] {
    for i in 0..4 {
        let m = t[i].wrapping_mul(INV);
        let mut carry: u128 = 0;
        for j in 0..4 {
            let v = t[i + j] as u128 + (m as u128) * (MODULUS[j] as u128) + carry;
            t[i + j] = v as u64;
            carry = v >> 64;
        }
        // t + m·r < 2^512 → 进位最多传播一层
        let mut k = i + 4;
        while carry > 0 && k < 8 {
            let v = t[k] as u128 + carry;
            t[k] = v as u64;
            carry = v >> 64;
            k += 1;
        }
        debug_assert!(carry == 0, "REDC 进位越出 512-bit（不变量被破坏）");
    }
    let mut out = [t[4], t[5], t[6], t[7]];
    if cmp_ge(&out, &MODULUS) {
        out = sub_mod(&out, &MODULUS);
    }
    out
}

/// R mod r（Montgomery 恒等元）。
fn r_mont() -> [u64; 4] {
    static R: OnceLock<[u64; 4]> = OnceLock::new();
    *R.get_or_init(|| pow2_mod(256))
}

/// R² mod r（Montgomery 进入用）。
fn r2_mont() -> [u64; 4] {
    static R2: OnceLock<[u64; 4]> = OnceLock::new();
    *R2.get_or_init(|| pow2_mod(512))
}

/// 2^n mod r（n ≤ 512，仅常量表 init 用——避免硬编码 R/R2 魔数）。
fn pow2_mod(n: usize) -> [u64; 4] {
    let mut x = [1u64, 0, 0, 0];
    for _ in 0..n {
        x = add_mod(&x, &x);
    }
    x
}

/// 平方幂（Montgomery 形式内平方/乘均为同形式运算，指数按普通值肢位读）。
fn mont_pow(base: Fe, exp: &[u64; 4]) -> Fe {
    let mut acc = Fe(r_mont());
    for i in (0..4).rev() {
        for bit in (0..64).rev() {
            acc = mont_mul(&acc, &acc);
            if (exp[i] >> bit) & 1 == 1 {
                acc = mont_mul(&acc, &base);
            }
        }
    }
    acc
}

fn mont_mul(a: &Fe, b: &Fe) -> Fe {
    Fe(mont_reduce(mul_wide(&a.0, &b.0)))
}

fn to_mont(v: &[u64; 4]) -> Fe {
    // v·R mod r = REDC(v · R²)
    Fe(mont_reduce(mul_wide(v, &r2_mont())))
}

fn from_mont(a: &Fe) -> [u64; 4] {
    // a·R^{-1} mod r = Montgomery 乘以普通 1
    mont_mul(a, &Fe([1, 0, 0, 0])).0
}

/// BN254 标量域元素（内部 Montgomery 形式）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fe([u64; 4]);

impl Fe {
    pub fn zero() -> Fe {
        Fe([0, 0, 0, 0])
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    fn add(self, other: Fe) -> Fe {
        Fe(add_mod(&self.0, &other.0))
    }

    fn sub(self, other: Fe) -> Fe {
        Fe(sub_mod(&self.0, &other.0))
    }

    fn mul(self, other: Fe) -> Fe {
        mont_mul(&self, &other)
    }

    /// 32B 大端 → 域元素（bb 公共输入序列化的逆，电路 pub Field 口径）。
    /// **肢序坑**：内部算术（add/mul/REDC）按 limb[0] = 最低位写，大端字节的高位
    /// u64 必须落到 limb[3]——反着解会产出确定性垃圾值（S-41 实测：内部一致性测试
    /// 全过、对不上 stdlib golden，就是这一处）。
    pub fn from_be_bytes(b: &[u8; 32]) -> Fe {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[3 - i] = u64::from_be_bytes(b[i * 8..i * 8 + 8].try_into().expect("limb slice"));
        }
        to_mont(&limbs)
    }

    /// 域元素 → 32B 大端（bb 公共输入序列化口径；撤销根上链/进公共输入即此外形）。
    pub fn to_be_bytes(self) -> [u8; 32] {
        let v = from_mont(&self);
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&v[3 - i].to_be_bytes());
        }
        out
    }

    /// 电路/gen-witness 的撤销叶编码：`encode_field(dh)` = 低 31 字节 LE 截断 → Field
    /// （dh[31] 不参与叶值；叶位置由全 256-bit 索引单射保证，见 TECH_SPEC §4.6）。
    pub fn encode_field_le31(dh: &[u8; 32]) -> Fe {
        let mut buf = [0u8; 32];
        buf[..31].copy_from_slice(&dh[..31]);
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(buf[i * 8..i * 8 + 8].try_into().expect("limb slice"));
        }
        to_mont(&limbs)
    }
}

// ——— Grumpkin 点算术（Jacobian，a = 0，y² = x³ + r − 17）———

#[derive(Clone, Copy)]
struct Aff {
    x: Fe,
    y: Fe,
}

#[derive(Clone, Copy)]
struct Jac {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl Jac {
    fn infinity() -> Jac {
        Jac {
            x: Fe::zero(),
            y: Fe([1, 0, 0, 0]),
            z: Fe::zero(),
        }
    }

    fn from_aff(a: Aff) -> Jac {
        Jac {
            x: a.x,
            y: a.y,
            z: Fe(r_mont()),
        }
    }

    fn is_infinity(self) -> bool {
        self.z.is_zero()
    }

    fn to_aff(self) -> Option<Aff> {
        if self.is_infinity() {
            return None;
        }
        let zinv = mont_pow(self.z, &sub_mod(&MODULUS, &[2, 0, 0, 0]));
        let zinv2 = zinv.mul(zinv);
        Some(Aff {
            x: self.x.mul(zinv2),
            y: self.y.mul(zinv2).mul(zinv),
        })
    }

    /// 倍点（dbl-2009-l，a = 0）：A = X1²、B = Y1²、C = B²、
    /// D = 2·((X1 + B)² − A − C)、E = 3A、F = E²。
    ///
    /// 小常数（2/3/4/8）一律用加法表达，**绝不 `mul(Fe([2,0,0,0]))`**——裸整数不是
    /// Montgomery 形式（2 应存 2·R mod r），裸乘会把 R-标度打掉且可产出未归约值
    /// （S-41 实测：debug_assert 当场抓住，release 下会静默算错）。
    fn double(self) -> Jac {
        if self.is_infinity() || self.y.is_zero() {
            return Jac::infinity();
        }
        let a = self.x.mul(self.x);
        let b = self.y.mul(self.y);
        let c = b.mul(b);
        let xb = self.x.add(b);
        let d = xb.mul(xb).sub(a).sub(c);
        let d = d.add(d); // D = 2·((X1+B)² − A − C)
        let e = a.add(a).add(a); // E = 3A
        let f = e.mul(e);
        let x3 = f.sub(d).sub(d);
        let c2 = c.add(c);
        let c4 = c2.add(c2);
        let c8 = c4.add(c4); // 8C
        let y3 = e.mul(d.sub(x3)).sub(c8);
        let yz = self.y.mul(self.z);
        Jac {
            x: x3,
            y: y3,
            z: yz.add(yz), // Z3 = 2·Y1·Z1
        }
    }

    /// 混合加法（madd-2007-bl，a = 0）：self（Jacobian）+ p（affine）。
    /// 含全部退化分支（无穷远 / 同点 / 互逆点）——MSM 累加值理论上可命中任一分支。
    /// 小常数乘法走加法（理由同 [`Jac::double`] 的 Montgomery 裸常量坑）。
    fn add_aff(self, p: Aff) -> Jac {
        if self.is_infinity() {
            return Jac::from_aff(p);
        }
        let z1z1 = self.z.mul(self.z);
        let u2 = p.x.mul(z1z1);
        let s2 = p.y.mul(self.z).mul(z1z1);
        let h = u2.sub(self.x);
        let r0 = s2.sub(self.y);
        if h.is_zero() {
            if r0.is_zero() {
                return self.double();
            }
            return Jac::infinity();
        }
        let hh = h.mul(h);
        let i = hh.add(hh).add(hh).add(hh); // I = 4·HH
        let j = h.mul(i);
        let rr = r0.add(r0);
        let v = self.x.mul(i);
        let x3 = rr.mul(rr).sub(j).sub(v).sub(v);
        let y1j2 = self.y.mul(j);
        let y1j2 = y1j2.add(y1j2);
        let y3 = rr.mul(v.sub(x3)).sub(y1j2);
        let zh = self.z.add(h);
        let z3 = zh.mul(zh).sub(z1z1).sub(hh);
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

/// 仿射标量乘（朴素 double-and-add，254 位全宽；init 与 golden 测试用，热路径走窗口表）。
fn mul_scalar(p: Aff, k: &[u64; 4]) -> Jac {
    let mut acc = Jac::infinity();
    for i in (0..4).rev() {
        for bit in (0..64).rev() {
            acc = acc.double();
            if (k[i] >> bit) & 1 == 1 {
                acc = acc.add_aff(p);
            }
        }
    }
    acc
}

// ——— bb 预计算生成器（crypto/generators/generator_data.hpp +
//      ecc/groups/precomputed_generators_grumpkin_impl.hpp @ 0e7787a）———

/// `DEFAULT_DOMAIN_SEPARATOR` 的 8 个预计算点（Grumpkin 仿射坐标，大端十六进制）。
const DEFAULT_DOMAIN_SEPARATORS: [(&str, &str); 8] = [
    (
        "083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a",
        "1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d",
    ),
    (
        "054aa86a73cb8a34525e5bbed6e43ba1198e860f5f3950268f71df4591bde402",
        "209dcfbf2cfb57f9f6046f44d71ac6faf87254afc7407c04eb621a6287cac126",
    ),
    (
        "1c44f2a5207c81c28a8321a5815ce8b1311024bbed131819bbdaf5a2ada84748",
        "03aaee36e6422a1d0191632ac6599ae9eba5ac2c17a8c920aa3caf8b89c5f8a8",
    ),
    (
        "26d8b1160c6821a30c65f6cb47124afe01c29f4338f44d4a12c9fccf22fb6fb2",
        "05c70c3b9c0d25a4c100e3a27bf3cc375f8af8cdd9498ec4089a823d7464caff",
    ),
    (
        "20ed9c6a1d27271c4498bfce0578d59db1adbeaa8734f7facc097b9b994fcf6e",
        "29cd7d370938b358c62c4a00f73a0d10aba7e5aaa04704a0713f891ebeb92371",
    ),
    (
        "0224a8abc6c8b8d50373d64cd2a1ab1567bf372b3b1f7b861d7f01257052d383",
        "2358629b90eafb299d6650a311e79914b0215eb0a790810b26da5a826726d711",
    ),
    (
        "0f106f6d46bc904a5290542490b2f238775ff3c445b2f8f704c466655f460a2a",
        "29ab84d472f1d33f42fe09c47b8f7710f01920d6155250126731e486877bcf27",
    ),
    (
        "0298f2e42249f0519c8a8abd91567ebe016e480f219b8c19461d6a595cc33696",
        "035bec4b8520a4ece27bd5aafabee3dfe1390d7439c419a8c55aceb207aac83b",
    ),
];

/// `"pedersen_hash_length"` 域的预计算点（length 标量专用生成器）。
const PEDERSEN_HASH_LENGTH: (&str, &str) = (
    "2df8b940e5890e4e1377e05373fae69a1d754f6935e6a780b666947431f2cdcd",
    "2ecd88d15967bc53b885912e0d16866154acb6aac2d3f85e27ca7eefb2c19083",
);

fn parse_aff(x_hex: &str, y_hex: &str) -> Aff {
    let xb: [u8; 32] = hex::decode(x_hex)
        .expect("generator x hex")
        .try_into()
        .expect("x 32B");
    let yb: [u8; 32] = hex::decode(y_hex)
        .expect("generator y hex")
        .try_into()
        .expect("y 32B");
    Aff {
        x: Fe::from_be_bytes(&xb),
        y: Fe::from_be_bytes(&yb),
    }
}

/// 曲线方程自检（bb 常量点 × 域算术，双向锁定；验证锚②，仅测试用）。
#[cfg(test)]
fn on_curve(p: Aff) -> bool {
    // b = r − 17（直接以普通肢进 Montgomery，不走字节往返）
    let b = to_mont(&sub_mod(&MODULUS, &[17, 0, 0, 0]));
    let x2 = p.x.mul(p.x);
    p.y.mul(p.y) == x2.mul(p.x).add(b)
}

/// 固定基 4-bit 窗口表：`[w][n]` = 16^w · (n+1) · G（仿射），n ∈ 0..15（nibble 0 跳过）。
struct WindowTable(Box<[[Aff; 15]; 64]>);

impl WindowTable {
    fn build(g: Aff) -> WindowTable {
        let mut t: Box<[[Aff; 15]; 64]> = Box::new([[g; 15]; 64]);
        // 第 0 窗：n·G（n = 1..15）
        for n in 1..=15u64 {
            t[0][(n - 1) as usize] = mul_scalar(g, &[n, 0, 0, 0]).to_aff().expect("n·G 非无穷远");
        }
        // 第 w 窗 = 第 w−1 窗每点 4 次倍乘（×16）
        for w in 1..64 {
            for n in 0..15 {
                let mut j = Jac::from_aff(t[w - 1][n]);
                for _ in 0..4 {
                    j = j.double();
                }
                t[w][n] = j.to_aff().expect("16^w·n·G 非无穷远");
            }
        }
        WindowTable(t)
    }

    fn get(&self, window: usize, nibble: usize) -> Aff {
        self.0[window][nibble - 1]
    }
}

struct Tables {
    g0: WindowTable,
    g1: WindowTable,
    two_glen: Aff,
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let g0 = parse_aff(
            DEFAULT_DOMAIN_SEPARATORS[0].0,
            DEFAULT_DOMAIN_SEPARATORS[0].1,
        );
        let g1 = parse_aff(
            DEFAULT_DOMAIN_SEPARATORS[1].0,
            DEFAULT_DOMAIN_SEPARATORS[1].1,
        );
        let glen = parse_aff(PEDERSEN_HASH_LENGTH.0, PEDERSEN_HASH_LENGTH.1);
        Tables {
            g0: WindowTable::build(g0),
            g1: WindowTable::build(g1),
            two_glen: mul_scalar(glen, &[2, 0, 0, 0])
                .to_aff()
                .expect("2·G_len 非无穷远"),
        }
    })
}

/// 固定基 MSM 累加：acc + s·G（s 为域元素标量，4-bit 窗口 LSB 先查表）。
fn msm_into(mut acc: Jac, s: Fe, table: &WindowTable) -> Jac {
    let v = from_mont(&s); // 普通值 < r < 2^254 → 64 窗口 × 4 bit 覆盖 256 bit
    for w in 0..64usize {
        let nibble = ((v[w / 16] >> ((w % 16) * 4)) & 0xF) as usize;
        if nibble != 0 {
            acc = acc.add_aff(table.get(w, nibble));
        }
    }
    acc
}

/// Noir `std::hash::pedersen_hash([l, r])`（分隔符 0）：取 `l·G0 + r·G1 + 2·G_len` 的 x 坐标。
pub fn pedersen_hash2(l: Fe, r: Fe) -> Fe {
    let t = tables();
    let acc = msm_into(msm_into(Jac::infinity(), l, &t.g0), r, &t.g1);
    acc.add_aff(t.two_glen)
        .to_aff()
        .expect("MSM 非零系数 → 结果非无穷远")
        .x
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe_hex(f: Fe) -> String {
        hex::encode(f.to_be_bytes())
    }

    /// ② bb 的 9 个预计算点全部过曲线方程（y² = x³ + r − 17）——锁域算术与常量。
    #[test]
    fn bb_precomputed_generators_on_curve() {
        let mut all: [(&str, &str); 9] = [("", ""); 9];
        all[..8].copy_from_slice(&DEFAULT_DOMAIN_SEPARATORS);
        all[8] = PEDERSEN_HASH_LENGTH;
        for (x, y) in all {
            assert!(on_curve(parse_aff(x, y)), "生成器不在曲线上: x={x}");
        }
    }

    /// ① Noir stdlib 自带 golden（noir_stdlib/src/hash/mod.nr::assert_pedersen，bb 对齐产物）：
    /// `pedersen_hash_with_separator([1], 1)` 与 `([1, 2], 2)`——sep k → 生成器下标 k..k+N，
    /// length 标量 = N。
    #[test]
    fn noir_stdlib_golden_hashes() {
        let g1 = parse_aff(
            DEFAULT_DOMAIN_SEPARATORS[1].0,
            DEFAULT_DOMAIN_SEPARATORS[1].1,
        );
        let g2 = parse_aff(
            DEFAULT_DOMAIN_SEPARATORS[2].0,
            DEFAULT_DOMAIN_SEPARATORS[2].1,
        );
        let g3 = parse_aff(
            DEFAULT_DOMAIN_SEPARATORS[3].0,
            DEFAULT_DOMAIN_SEPARATORS[3].1,
        );
        let glen = parse_aff(PEDERSEN_HASH_LENGTH.0, PEDERSEN_HASH_LENGTH.1);
        // sep=1, N=1：1·G[1] + 1·G_len
        let v = mul_scalar(g1, &[1, 0, 0, 0])
            .add_aff(glen)
            .to_aff()
            .unwrap()
            .x;
        assert_eq!(
            fe_hex(v),
            "1b3f4b1a83092a13d8d1a59f7acb62aba15e7002f4440f2275edb99ebbc2305f"
        );
        // sep=2, N=2：1·G[2] + 2·G[3] + 2·G_len
        let v = mul_scalar(g2, &[1, 0, 0, 0])
            .add_aff(mul_scalar(g3, &[2, 0, 0, 0]).to_aff().unwrap())
            .add_aff(mul_scalar(glen, &[2, 0, 0, 0]).to_aff().unwrap())
            .to_aff()
            .unwrap()
            .x;
        assert_eq!(
            fe_hex(v),
            "26691c129448e9ace0c66d11f0a16d9014a9e8498ee78f4d69f0083168188255"
        );
    }

    /// ② 主用例自检：`pedersen_hash([0, 0])` = x(2·G_len)（Python 第三实现交叉，S-41）。
    #[test]
    fn hash_of_zero_zero_is_two_glen() {
        assert_eq!(
            fe_hex(pedersen_hash2(Fe::zero(), Fe::zero())),
            "27b1d0839a5b23baf12a8d195b18ac288fcf401afb2f70b8a4b529ede5fa9fed"
        );
    }

    /// ③ 4-bit 窗口表路径与朴素 double-and-add 全等（MSM 实现自检；确定性标量覆盖
    /// nibble 0/15、窗口边界与全肢非零）。
    #[test]
    fn windowed_msm_matches_naive_scalar_mul() {
        let g0 = parse_aff(
            DEFAULT_DOMAIN_SEPARATORS[0].0,
            DEFAULT_DOMAIN_SEPARATORS[0].1,
        );
        let t = WindowTable::build(g0);
        let samples: [[u64; 4]; 5] = [
            [0x0123_4567_89ab_cdef, 0x0f1e_2d3c_4b5a_6978, 1, 0],
            [
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_ffff,
                0x0fff_ffff_ffff_ffff,
            ],
            [0, 0, 0, 2],
            [0x8000_0000_0000_0000, 0, 0, 0],
            [0xffff_ffff_ffff_ffff, 0, 0, 0],
        ];
        for s in samples {
            assert!(cmp_ge(&MODULUS, &s), "样本标量必须小于模数（自检）");
            let fe = to_mont(&s);
            let want = mul_scalar(g0, &s).to_aff().expect("非零标量 → 非无穷远").x;
            let got = msm_into(Jac::infinity(), fe, &t)
                .to_aff()
                .expect("非零标量 → 非无穷远")
                .x;
            assert_eq!(fe_hex(got), fe_hex(want), "s={s:?}");
        }
    }

    /// ④ 窗口表最高窗口正确性：第 63 窗第 1 项 = 16^63·G = 2^252·G。
    #[test]
    fn high_window_matches_naive() {
        let g1 = parse_aff(
            DEFAULT_DOMAIN_SEPARATORS[1].0,
            DEFAULT_DOMAIN_SEPARATORS[1].1,
        );
        let t = WindowTable::build(g1);
        let want = mul_scalar(g1, &[0, 0, 0, 1u64 << 60]).to_aff().unwrap().x;
        let got = Jac::from_aff(t.get(63, 1)).to_aff().unwrap().x;
        assert_eq!(fe_hex(got), fe_hex(want));
    }
}
