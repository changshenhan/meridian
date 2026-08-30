//! 签名标量归约的大整数原语（S-43，TECH_SPEC §6.14 步 4）。
//!
//! 边界口径与 gen-witness / `formal_gen_to_prover.py` 同源：Noir 1.0 移除了 Field 模
//! 运算（`%` 编译报错，eddsa fork 测试亦注明 "fields can't use modulo"），EdDSA 签名
//! 标量 `s = (r + h·secret) mod SUBORDER` 的 mod-n 归约必须在电路线外的可信层做。
//! Python 侧（formal 管线）用大整数；本模块是同一归约的 Rust 第二实现（零新依赖：
//! u64 limb 手写乘法 + 二进制长除取模），跨实现锚 = fixture 的 s 与正式管线
//! `sig_s` 逐位相等（`scalar_golden_matches_formal_pipeline`）。
//!
//! 其余原语（十进制 ↔ 256-bit、BE32 ↔ 值）服务 Prover.toml 组装：Noir 的 Field
//! 标量入参以带引号十进制序列化（`formal_gen_to_prover.py` 同款，实测可用），而
//! 聚合器侧 `revocation_path` / `revocation_root` 是 BE Field 32B 外形。

/// BabyJubJub 子群阶（与 eddsa fork `eddsa_verify` 断言值、`formal_gen_to_prover.py`
/// 的 SUBORDER 同一常量；不一致则证明失败——电路 eddsa_verify 把关）。
pub const SUBORDER: [u64; 4] = [
    7454187305358665457,
    12339561404529962506,
    3965992003123030795,
    435874783350371333,
];

/// 256-bit 无符号（LE u64 limb；零依赖大整数的最小切片，只实现本模块需要的运算）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct U256 {
    pub limbs: [u64; 4],
}

impl U256 {
    pub const ZERO: U256 = U256 { limbs: [0; 4] };

    pub fn from_be_bytes(b: &[u8; 32]) -> U256 {
        let mut v = U256::ZERO;
        for (i, chunk) in b.chunks(8).enumerate() {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            v.limbs[3 - i] = u64::from_be_bytes(word);
        }
        v
    }

    /// LE 32B（低字节在 b[0]）。attestation_secret 的契约口径（§6.14：LE 不透明字节，
    /// 与 core attestation 坐标 LE 同一约定）。
    pub fn from_le_bytes(b: &[u8; 32]) -> U256 {
        let mut v = U256::ZERO;
        for (i, chunk) in b.chunks(8).enumerate() {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            v.limbs[i] = u64::from_le_bytes(word);
        }
        v
    }

    /// BE 32B（高位在 b[0]）；零填充满 32B（域元素外形）。
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        // limb[0] = 最低位 → 落大端尾部（S-41 教训：肢序反了=确定性垃圾，内部一致性
        // 测试可能全过，靠跨实现 golden 才抓得到）。
        for (i, limb) in self.limbs.iter().enumerate() {
            out[(3 - i) * 8..(4 - i) * 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    pub fn from_u64(v: u64) -> U256 {
        U256 {
            limbs: [v, 0, 0, 0],
        }
    }

    pub fn is_zero(self) -> bool {
        self.limbs == [0; 4]
    }

    /// 乘加：`self * mul + add`（无溢出安全：结果 ≤ 512-bit 用 [u64; 8] 承载）。
    fn mul_add_wide(self, mul: U256, add: U256) -> [u64; 8] {
        let mut out = [0u64; 8];
        // 仅 add 进低位（self 只经乘法路径进——否则多算一份 self）
        let mut carry = 0u128;
        for (o, a) in out.iter_mut().zip(add.limbs.iter()) {
            let s = *a as u128 + carry;
            *o = s as u64;
            carry = s >> 64;
        }
        out[4] = carry as u64;
        // self * mul 逐 limb 累加（学校乘法，128-bit 中转）
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let cur =
                    out[i + j] as u128 + (self.limbs[i] as u128) * (mul.limbs[j] as u128) + carry;
                out[i + j] = cur as u64;
                carry = cur >> 64;
            }
            // 进位链上推（out 高位初始只有 add 的进位，必为 0）
            let mut k = i + 4;
            while carry > 0 {
                let cur = out[k] as u128 + carry;
                out[k] = cur as u64;
                carry = cur >> 64;
                k += 1;
            }
        }
        out
    }

    /// 与 `mod` 相减（self ≥ mod 前提下逐 limb 借位）。
    fn sub_assign(&mut self, other: &U256) {
        let mut borrow = 0i128;
        for i in 0..4 {
            let d = self.limbs[i] as i128 - other.limbs[i] as i128 - borrow;
            if d < 0 {
                self.limbs[i] = (d + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                self.limbs[i] = d as u64;
                borrow = 0;
            }
        }
    }

    pub fn cmp_to(self, other: &U256) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                core::cmp::Ordering::Equal => continue,
                o => return o,
            }
        }
        core::cmp::Ordering::Equal
    }
}

/// 512-bit 值 mod 256-bit 模数：二进制长除（512 次移位-比较-减，无依赖、可审计；
/// 证明路径每笔只调 2 次，成本可忽略）。
fn wide_mod(v: [u64; 8], m: &U256) -> U256 {
    // 自高位向低位逐位左移进 256-bit 余数
    let mut rem = U256::ZERO;
    for bit in (0..512).rev() {
        // rem <<= 1 | v.bit(bit)
        let mut carry = (v[bit / 64] >> (bit % 64)) & 1;
        for limb in rem.limbs.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        // 移位后最高位溢出不可能：rem < m < 2^256，左移一位前 rem ≤ 2m-1 ……
        // 严格地：rem < m 恒成立（每步后立即条件减），故左移一位最多 2m-2 < 2^257，
        // 顶层 carry（进第 257 位）只在 m > 2^255 时可能出现——本场景 m = SUBORDER
        // < 2^254，不可能溢出。防御性断言保留。
        debug_assert_eq!(carry, 0);
        if rem.cmp_to(m) != core::cmp::Ordering::Less {
            rem.sub_assign(m);
        }
    }
    rem
}

/// `a + b·c mod m`（EdDSA 签名标量：`s = (r + h·secret) mod SUBORDER`）。
pub fn add_mul_mod(a: U256, b: U256, c: U256, m: &U256) -> U256 {
    wide_mod(b.mul_add_wide(c, a), m)
}

/// 十进制字符串 → U256（Prover.toml 的 Field 标量入参反向：oracle 返回值解析用不到，
/// 但 witness 自洽校验与测试需要；反复乘 10 加 digit）。
pub fn from_decimal(s: &str) -> Option<U256> {
    let s = s.trim();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut v = U256::ZERO;
    for b in s.bytes() {
        // v = v*10 + d：走 mul_add_mod 语义不合适（v 可能 ≥ 2^256? 不会——调用方保证
        // 值域），直接手写小步乘加。
        let mut carry = (b - b'0') as u64;
        for limb in v.limbs.iter_mut() {
            let cur = (*limb as u128) * 10 + carry as u128;
            *limb = cur as u64;
            carry = (cur >> 64) as u64;
        }
        if carry != 0 {
            return None; // 超 256-bit
        }
    }
    Some(v)
}

/// U256 → 十进制字符串（反复除 10 取余；Prover.toml Field 标量入参口径）。
pub fn to_decimal(v: U256) -> String {
    let mut digits = Vec::new();
    let mut cur = v;
    while !cur.is_zero() {
        // cur /= 10，余数即下一个（低位优先）数字
        let mut rem = 0u64;
        for limb in cur.limbs.iter_mut().rev() {
            let cur128 = *limb as u128 + ((rem as u128) << 64);
            *limb = (cur128 / 10) as u64;
            rem = (cur128 % 10) as u64;
        }
        digits.push(b'0' + rem as u8);
    }
    if digits.is_empty() {
        return "0".to_string();
    }
    digits.reverse();
    String::from_utf8(digits).expect("digits are ascii")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(x: u64) -> U256 {
        U256::from_u64(x)
    }

    #[test]
    fn suborder_limb_layout() {
        // 与 formal_gen_to_prover.py 的 SUBORDER 十进制常量同一值（Python 大整数拆 limb）。
        let m = U256 { limbs: SUBORDER };
        assert_eq!(
            to_decimal(m),
            "2736030358979909402780800718157159386076813972158567259200215660948447373041"
        );
    }

    #[test]
    fn scalar_golden_matches_formal_pipeline() {
        // fixture（gen-witness Prover.toml 场景：secret=4242，同 intent_hash → 同 r/h）：
        // r/h 取自 nargo execute 输出，s 与 circuits/Prover.toml（formal 管线 Python 产出）
        // 的 sig_s 逐位相等——Rust 归约 = Python 归约的第三实现锚（TECH_SPEC §6.14 步 4）。
        let r = U256::from_be_bytes(&hex32(
            "1794471fb5896bc97e6edacb5d3d1a419ae6443c4de516ce32b1e181ebd8b36b",
        ));
        let h = U256::from_be_bytes(&hex32(
            "258bd6b15eed6c6119c0f57a63c299df6529ed2dcf42094649cfb992532575c2",
        ));
        let secret = u(4242);
        let s = add_mul_mod(r, h, secret, &U256 { limbs: SUBORDER });
        assert_eq!(
            to_decimal(s),
            "438319869364143247086169670589956940845526874233616458434965585080515178769"
        );
    }

    #[test]
    fn add_mul_mod_matches_small_math() {
        // 小数值域（a + b·c < 2^128 < SUBORDER，不触发归约）与 u128 内建运算交叉。
        for a in [0u64, 1, 7, 12345, u64::MAX - 1] {
            for b in [0u64, 2, 99, u64::MAX] {
                for c in [0u64, 3, 555, u64::MAX] {
                    let m = U256 { limbs: SUBORDER };
                    let got = add_mul_mod(u(a), u(b), u(c), &m);
                    let want = a as u128 + (b as u128) * (c as u128); // < 2^128，u128 可承载
                    assert_eq!(got.limbs[0], want as u64, "a={a} b={b} c={c}");
                    assert_eq!(got.limbs[1], (want >> 64) as u64, "a={a} b={b} c={c}");
                    assert!(got.limbs[2..].iter().all(|l| *l == 0), "a={a} b={b} c={c}");
                }
            }
        }
    }

    #[test]
    fn add_mul_mod_reduces_below_modulus() {
        // 全 1 操作数：512-bit 乘积路径（无溢出）+ 归约正确性（结果 < m）。
        let m = U256 { limbs: SUBORDER };
        let f = U256 {
            limbs: [u64::MAX; 4],
        };
        let s = add_mul_mod(f, f, f, &m);
        assert_eq!(s.cmp_to(&m), core::cmp::Ordering::Less);
        // 同余交叉：a + b·c ≡ a + c·b（mod m，乘法交换律）
        let flipped = add_mul_mod(f, f, f, &m);
        assert_eq!(s, flipped);
        // 同余交叉：b·c（a=0）与 c·b（a=0）相等
        let bc = add_mul_mod(U256::ZERO, f, f, &m);
        let cb = add_mul_mod(U256::ZERO, f, f, &m);
        assert_eq!(bc, cb);
        // 恒等：x + 0·0 = x（mod m）
        assert_eq!(add_mul_mod(u(5), U256::ZERO, U256::ZERO, &m), u(5));
        // 归约：x + m·1 ≡ x（mod m）——m 恰为模数，乘积路径触发一次扣除
        assert_eq!(add_mul_mod(u(5), m, u(1), &m), u(5));
    }

    #[test]
    fn decimal_roundtrip_and_bounds() {
        let m = U256 { limbs: SUBORDER };
        let dec = "2736030358979909402780800718157159386076813972158567259200215660948447373040";
        let v = from_decimal(dec).expect("in-range decimal");
        assert_eq!(to_decimal(v), dec);
        // u64::MAX 十进制口径（跨实现锚点，同 bb_verify_e2e 的 decimal_to_be32 锚）
        assert_eq!(to_decimal(u(u64::MAX)), "18446744073709551615");
        assert_eq!(from_decimal("18446744073709551615"), Some(u(u64::MAX)));
        assert_eq!(to_decimal(U256::ZERO), "0");
        // 非法输入
        assert_eq!(from_decimal(""), None);
        assert_eq!(from_decimal("12a"), None);
        assert_eq!(from_decimal("-1"), None);
        // 2^256 - 1 可往返
        let max = U256 {
            limbs: [u64::MAX; 4],
        };
        assert_eq!(from_decimal(&to_decimal(max)), Some(max));
        // 模数 - 1 的往返（归约上界）
        let top = from_decimal(
            "2736030358979909402780800718157159386076813972158567259200215660948447373040",
        )
        .unwrap();
        assert_eq!(top.cmp_to(&m), core::cmp::Ordering::Less);
    }

    #[test]
    fn be_bytes_roundtrip_field_shaped() {
        // BE 32B 外形（聚合器 revocation_path / root 的口径）逐字节往返。
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8) ^ 0xA5;
        }
        assert_eq!(U256::from_be_bytes(&b).to_be_bytes(), b);
        // 零与全 1
        assert_eq!(U256::from_be_bytes(&[0u8; 32]), U256::ZERO);
        let f = U256::from_be_bytes(&[0xFF; 32]);
        assert_eq!(f.to_be_bytes(), [0xFF; 32]);
        // 十进制 ↔ BE 交叉：1 << 128（BE 32B 里 bit 128 落 byte 15：byte i 覆盖
        // bits [8·(31−i), 8·(32−i))）。
        let v = from_decimal("340282366920938463463374607431768211456").unwrap();
        let mut want = [0u8; 32];
        want[15] = 1;
        assert_eq!(v.to_be_bytes(), want);
        // LE 契约口径（attestation_secret）：低字节在前。
        let mut le = [0u8; 32];
        le[0] = 0x42;
        le[2] = 0x07;
        let v = U256::from_le_bytes(&le);
        assert_eq!(v.limbs[0], 0x0000_0000_0007_0042);
        assert_eq!(
            v,
            U256::from_be_bytes(
                &le.iter()
                    .rev()
                    .copied()
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("32b")
            )
        );
    }

    /// 测试辅助：hex → 32B（BE）。
    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let b = hex::decode(s).expect("hex");
        out.copy_from_slice(&b);
        out
    }
}
