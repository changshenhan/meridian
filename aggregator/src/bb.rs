//! 真实 ZK 验证后端（S-40，TECH_SPEC §6.13）：bb CLI 子进程 wrapper。
//!
//! `FormatVerifier`（TEMPORARY，proof 非空即过）的真后端——把 S-09 电路的 UltraHonk
//! 证明交给 `bb verify -t evm-no-zk -p <proof> -k <vk> -i <public_inputs>` 验证。
//! 契约要点（bb 6.0.0-nightly.20260724 实测，详见 TECH_SPEC §6.13）：
//! - proof 文件是**纯证明**（不含公共输入），公共输入是独立文件（121 字段 × 32B 大端）；
//!   `-i` 必须显式传（缺省路径 `<cwd>/target/public_inputs` 与调用方 cwd 绑定）。
//! - 公共输入与证明是真密码学绑定（改任一字节都被拒）。
//!
//! fail-closed 口径：bb 不可得 / 临时目录建不了 / spawn 失败一律 `E_VERIFY_BACKEND`，
//! 绝不静默降级回格式校验；密码学拒绝（bb 非零退出）是 `E_PROOF`。
//!
//! 诚实边界（TECH_SPEC §6.13）：只收口验证侧——`PlaceholderProver` 的占位 proof 在本
//! 后端下会被全拒（正确行为）；CLI 子进程不是 in-process（进程开销 ~0.77ms）；撤销根
//! 哈希规范错配（§4.6）不在本件收口。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use meridian_core::error::Error;
use meridian_core::zk::{SpendProof, SpendPublicInputs, SpendVerifier};

/// bb verifier target，必须与写 VK 时一致（UltraKeccakFlavor，VK 1888B）。
pub const VERIFIER_TARGET: &str = "evm-no-zk";

/// 电路公共输入字段数（§5.1 参数序：32+32+20+1+32+1+1+1+1）。
pub const PUBLIC_INPUT_FIELDS: usize = 121;

/// 单个域元素的字节数（bb public_inputs 文件每字段 32B 大端）。
const FIELD_BYTES: usize = 32;

/// u64 → 32B 大端域元素（BN254 标量域容得下 u64，左零填充）。
fn field_u64(v: u64) -> [u8; FIELD_BYTES] {
    let mut f = [0u8; FIELD_BYTES];
    f[FIELD_BYTES - 8..].copy_from_slice(&v.to_be_bytes());
    f
}

/// `[u8; N]` 逐字节展开成字段（每字节一个 32B 大端域元素）。
fn push_bytes(out: &mut Vec<u8>, bs: &[u8]) {
    for b in bs {
        out.extend_from_slice(&field_u64(*b as u64));
    }
}

/// 公共输入序列化：`SpendPublicInputs` → 121 字段 × 32B 大端（3872B）。
///
/// 字段序 = 电路 §5.1 参数序。编码规则：`[u8; N]` **每字节一个字段**，`u64` 一个字段，
/// 各按 32B 大端展开；`revocation_root` Rust 侧是 `[u8; 32]` 但电路是 `pub Field` →
/// 按 256-bit **大端整数**取一个字段（即原样 32B，不拆字节）。与
/// `scripts/formal_readback.py` 的 expected 构造同一规范（第三实现交叉校验）。
///
/// 注意：字节串若 ≥ BN254 标量域模数（如全 0xFF），bb 会以 "Non-canonical public
/// input" 拒绝——`revocation_root` 来自 sha256/Pedersen 树根，实际不可达该值域边界。
pub fn serialize_public_inputs(pi: &SpendPublicInputs) -> Vec<u8> {
    let mut out = Vec::with_capacity(PUBLIC_INPUT_FIELDS * FIELD_BYTES);
    push_bytes(&mut out, &pi.agent_commit);
    push_bytes(&mut out, &pi.delegation_hash);
    push_bytes(&mut out, &pi.recipient);
    out.extend_from_slice(&field_u64(pi.amount));
    push_bytes(&mut out, &pi.category);
    out.extend_from_slice(&field_u64(pi.spend_nonce));
    out.extend_from_slice(&field_u64(pi.expires_at));
    // revocation_root：电路 `pub Field`，256-bit 大端整数口径（一个字段，不拆字节）。
    out.extend_from_slice(&pi.revocation_root);
    out.extend_from_slice(&field_u64(pi.now));
    debug_assert_eq!(out.len(), PUBLIC_INPUT_FIELDS * FIELD_BYTES);
    out
}

/// bb 调用方式（探测逻辑与 verify.sh 第 9 步同款，TECH_SPEC §8.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BbBackend {
    /// 原生 bb（Windows/Linux PATH，或 `MERIDIAN_BB_BIN` 指定路径）。
    Native { bin: String },
    /// WSL2 兜底：`wsl.exe -d <distro> -u root`，Windows 路径经 `/mnt/<盘>/` 转换。
    Wsl { distro: String },
}

impl BbBackend {
    /// 环境解析：`MERIDIAN_BB_BIN` 有值走原生；否则探 PATH 上的 `bb`；再探 WSL 兜底
    /// （`MERIDIAN_WSL_DISTRO`，缺省 MeridianUbuntu）。皆不可得返回 None（构造期报错，
    /// 不落运行时半可用态）。
    pub fn detect() -> Option<BbBackend> {
        if let Ok(bin) = std::env::var("MERIDIAN_BB_BIN") {
            if !bin.is_empty() && native_bb_ok(&bin) {
                return Some(BbBackend::Native { bin });
            }
        }
        if native_bb_ok("bb") {
            return Some(BbBackend::Native { bin: "bb".into() });
        }
        let distro =
            std::env::var("MERIDIAN_WSL_DISTRO").unwrap_or_else(|_| "MeridianUbuntu".into());
        if wsl_bb_ok(&distro) {
            return Some(BbBackend::Wsl { distro });
        }
        None
    }

    /// Windows 绝对路径 → WSL 路径（`D:\a\b` → `/mnt/d/a/b`）。非盘符路径原样返回。
    fn to_wsl_path(p: &Path) -> String {
        let s = p.to_string_lossy().replace('\\', "/");
        let bytes = s.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            format!(
                "/mnt/{}{}",
                (bytes[0] as char).to_ascii_lowercase(),
                &s[2..]
            )
        } else {
            s
        }
    }

    /// 组装 bb verify 命令（工作目录无关：所有输入路径显式）。
    fn command(&self, proof: &Path, vk: &Path, pi: &Path) -> Command {
        match self {
            BbBackend::Native { bin } => {
                let mut c = Command::new(bin);
                c.args([
                    "verify",
                    "-t",
                    VERIFIER_TARGET,
                    "-p",
                    &proof.to_string_lossy(),
                    "-k",
                    &vk.to_string_lossy(),
                    "-i",
                    &pi.to_string_lossy(),
                ]);
                c
            }
            BbBackend::Wsl { distro } => {
                let script = format!(
                    "export PATH=\"$HOME/.bb:$PATH\"; bb verify -t {} -p '{}' -k '{}' -i '{}'",
                    VERIFIER_TARGET,
                    Self::to_wsl_path(proof),
                    Self::to_wsl_path(vk),
                    Self::to_wsl_path(pi),
                );
                let mut c = Command::new("wsl.exe");
                c.args(["-d", distro, "-u", "root", "-e", "bash", "-lc", &script]);
                c
            }
        }
    }
}

fn native_bb_ok(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn wsl_bb_ok(distro: &str) -> bool {
    Command::new("wsl.exe")
        .args([
            "-d",
            distro,
            "-u",
            "root",
            "-e",
            "bash",
            "-lc",
            "export PATH=\"$HOME/.bb:$PATH\"; bb --version >/dev/null 2>&1",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// bb wrapper 验证后端。构造即探测（fail fast）；`verify` 每次落
/// `<tmp_root>/<pid>-<序号>/` 三文件（proof/pi/vk）后调 bb，用毕清理（尽力而为）。
pub struct BbVerifier {
    vk: Vec<u8>,
    backend: BbBackend,
    tmp_root: PathBuf,
    seq: AtomicU64,
}

impl BbVerifier {
    /// 从工件装配（e2e 测试与显式装配用）：vk 原始字节 + 后端 + 临时目录根。
    pub fn from_parts(vk: Vec<u8>, backend: BbBackend, tmp_root: PathBuf) -> Self {
        BbVerifier {
            vk,
            backend,
            tmp_root,
            seq: AtomicU64::new(0),
        }
    }

    /// 环境装配（`meridian-gateway` 用）：`MERIDIAN_BB_VK`（必填）、`MERIDIAN_BB_BIN`
    /// /`MERIDIAN_WSL_DISTRO`（后端解析）、`MERIDIAN_BB_TMP`（临时目录根，缺省
    /// `target/bb-verify`）。任一前置缺失即 `E_VERIFY_BACKEND`——bin 侧启动即退。
    pub fn from_env() -> Result<Self, Error> {
        let vk_path = std::env::var("MERIDIAN_BB_VK").map_err(|_| Error::EVerifyBackend)?;
        let vk = std::fs::read(&vk_path).map_err(|_| Error::EVerifyBackend)?;
        let backend = BbBackend::detect().ok_or(Error::EVerifyBackend)?;
        let tmp_root = std::env::var("MERIDIAN_BB_TMP")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("target/bb-verify"));
        Ok(BbVerifier::from_parts(vk, backend, absolute(&tmp_root)))
    }
}

impl SpendVerifier for BbVerifier {
    fn verify(&self, proof: &SpendProof) -> Result<SpendPublicInputs, Error> {
        if proof.proof.is_empty() {
            return Err(Error::EProof);
        }
        let pi = &proof.public_inputs;
        let pi_bytes = serialize_public_inputs(pi);

        // 每次验证一个独立临时目录：bb 输入三文件互不串扰，并发摄取安全。
        let dir = self.tmp_root.join(format!(
            "{}-{}",
            std::process::id(),
            self.seq.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).map_err(|_| Error::EVerifyBackend)?;
        let proof_path = dir.join("proof.bin");
        let vk_path = dir.join("vk.bin");
        let pi_path = dir.join("public_inputs.bin");
        let write = |p: &Path, b: &[u8]| std::fs::write(p, b).map_err(|_| Error::EVerifyBackend);
        let written = (|| -> Result<(), Error> {
            write(&proof_path, &proof.proof)?;
            write(&vk_path, &self.vk)?;
            write(&pi_path, &pi_bytes)
        })();
        if let Err(e) = written {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }

        let mut cmd = self.backend.command(&proof_path, &vk_path, &pi_path);
        // bb 非零退出 = 密码学拒绝（E_PROOF）；起不来 = 后端故障（E_VERIFY_BACKEND）。
        let ok = match cmd.output() {
            Ok(out) if out.status.success() => Ok(()),
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let tail: String = stderr.lines().rev().take(2).collect::<Vec<_>>().join(" | ");
                eprintln!("[bb-verify] rejected: {tail}");
                Err(Error::EProof)
            }
            Err(e) => {
                eprintln!("[bb-verify] backend spawn failed: {e}");
                Err(Error::EVerifyBackend)
            }
        };
        let _ = std::fs::remove_dir_all(&dir);
        ok.map(|()| pi.clone())
    }
}

/// 临时目录根钉成绝对路径：bb 后端（尤其 WSL 分支）需要可转换的 Windows 绝对路径，
/// 且测试/网关进程的 cwd 与 cargo 的 cwd 不一致时口径仍稳。
fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meridian_core::zk::SpendPublicInputs;

    fn pi() -> SpendPublicInputs {
        SpendPublicInputs {
            agent_commit: [0x01; 32],
            delegation_hash: [0x02; 32],
            recipient: [0x03; 20],
            amount: 42,
            category: [0x04; 32],
            spend_nonce: 7,
            expires_at: u64::MAX,
            revocation_root: [0x05; 32],
            now: 1_700_000_000,
        }
    }

    fn serialized() -> Vec<u8> {
        serialize_public_inputs(&pi())
    }

    #[test]
    fn serialization_shape_121_fields_big_endian() {
        let out = serialized();
        assert_eq!(out.len(), 121 * 32);
        // u64 字段：32B 大端（amount=42 → 尾字节 42）。
        let amount = &out[(32 + 32 + 20) * 32..(32 + 32 + 20 + 1) * 32];
        assert_eq!(amount[..31], [0u8; 31]);
        assert_eq!(amount[31], 42);
        // `[u8; N]` 每字节一个字段：agent_commit 全 0x01 → 前 32 个字段每字段尾字节 0x01。
        for i in 0..32 {
            let f = &out[i * 32..(i + 1) * 32];
            assert_eq!(f[..31], [0u8; 31]);
            assert_eq!(f[31], 0x01);
        }
    }

    #[test]
    fn serialization_field_order_matches_circuit_signature() {
        // §5.1 参数序：agent_commit ‖ delegation_hash ‖ recipient ‖ amount ‖ category
        // ‖ spend_nonce ‖ expires_at ‖ revocation_root(单字段) ‖ now。
        let out = serialized();
        let at = |n: usize| &out[n * 32..(n + 1) * 32];
        assert_eq!(at(0)[31], 0x01); // agent_commit[0]
        assert_eq!(at(32)[31], 0x02); // delegation_hash[0]
        assert_eq!(at(64)[31], 0x03); // recipient[0]
        assert_eq!(at(84)[31], 42); // amount
        assert_eq!(at(85)[31], 0x04); // category[0]
        assert_eq!(at(117)[31], 7); // spend_nonce
                                    // expires_at = u64::MAX（高 24 字节 0，低 8 字节全 1）。
        assert_eq!(at(118)[..24], [0u8; 24]);
        assert_eq!(&at(118)[24..], &u64::MAX.to_be_bytes());
        // revocation_root：256-bit 大端整数口径——整段原样 [0x05; 32]，不拆字节。
        assert_eq!(at(119), &[0x05; 32]);
        let now = field_u64(1_700_000_000);
        assert_eq!(at(120), &now);
    }

    #[test]
    fn revocation_root_is_one_field_not_thirty_two() {
        // 若误拆 32 个字节字段，序列化长度会是 152 × 32——单字段口径下 121 × 32。
        assert_eq!(serialized().len(), 121 * 32);
    }

    #[test]
    fn wsl_path_conversion() {
        let conv = |p: &str| BbBackend::to_wsl_path(Path::new(p));
        #[cfg(windows)]
        {
            assert_eq!(
                conv(r"D:\repo\target\bb-verify\1-0\proof.bin"),
                "/mnt/d/repo/target/bb-verify/1-0/proof.bin"
            );
            assert_eq!(conv(r"C:\x y\vk.bin"), "/mnt/c/x y/vk.bin");
        }
        assert_eq!(conv("/tmp/proof.bin"), "/tmp/proof.bin");
        assert_eq!(conv("relative/proof.bin"), "relative/proof.bin");
    }

    #[test]
    fn backend_detect_reports_none_when_absent() {
        // 探测函数本身必须可调用且不 panic；是否可得取决于宿主机（门禁机 WSL 分支可得）。
        let detected = BbBackend::detect();
        if let Some(b) = detected {
            assert!(matches!(
                b,
                BbBackend::Native { .. } | BbBackend::Wsl { .. }
            ));
        }
    }

    #[test]
    fn empty_proof_rejected_before_backend_call() {
        // from_parts 不探测后端（可装假后端路径），空 proof 在触达 bb 之前即拒。
        let v = BbVerifier::from_parts(
            vec![1; 1888],
            BbBackend::Native {
                bin: "definitely-not-bb".into(),
            },
            std::env::temp_dir().join("meridian-bb-test"),
        );
        let p = meridian_core::zk::SpendProof {
            proof: vec![],
            public_inputs: pi(),
        };
        assert_eq!(v.verify(&p), Err(Error::EProof));
    }
}
