//! 真 prover（S-43，TECH_SPEC §6.14）：agent 侧 S-09 电路证明生成，`NoirProver`
//! 实现 core `SpendProver`——prove 侧 TEMPORARY 缝（`PlaceholderProver`）的真后端。
//!
//! 六步链路（§6.14）：Rust 只做纯字节逻辑与进程编排，**一切曲线数学（BJJ 标量乘、
//! Poseidon）留在 Noir**（S-05 教训守住）：
//!
//! 1. Rust `zk_intent_hash`（core dsa，第二实现）；
//! 2. Noir oracle（gen-witness 复用为曲线 oracle，`--prover-name ProverSDK` 独立
//!    toml，不碰正式管线 `Prover.toml`；撤销入参填零 = 空集，树输出弃用）；
//! 3. Rust 交叉校验（agent_commit / intent_hash，第三实现锚，镜像
//!    `formal_gen_to_prover.py`）；
//! 4. 签名标量归约 `s = (r + h·secret) mod SUBORDER`（`prover::scalar`，Rust 大整数）；
//! 5. 撤销 witness 自洽（聚合器 `noir_pedersen` 从 path + EMPTY 叶重算 == root，
//!    fail-closed）；
//! 6. 拼 `circuits/ProverSDK.toml` → `nargo execute`（电路自校验：断言 1-9 全过才有
//!    witness——§4.6 残余②「电路消费交叉锚」在此兑现）→ `bb prove`（flavor 与验证侧
//!    §6.13 一致）→ proof + 公共输入与 `serialize_public_inputs` 逐字节比对。
//!
//! fail-closed：工具链不可得 / witness 求解失败 / 任一交叉校验失配 = `E_PROVER`，
//! 绝不降级回占位证明。prove 全程进程级互斥（`ProverSDK.toml` 落在包目录，并发证明
//! 串行化——证明是重操作，可接受）。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};

use meridian_aggregator::bb::{serialize_public_inputs, VERIFIER_TARGET};
use meridian_aggregator::noir_pedersen::{pedersen_hash2, Fe};
use meridian_core::attestation::{agent_commit, AttestationPubKey};
use meridian_core::dsa::zk_intent_hash;
use meridian_core::error::Error;
use meridian_core::zk::{
    RevocationWitness, SpendProof, SpendProofRequest, SpendProver, SpendPublicInputs,
};
use sha2::{Digest, Sha256};

pub mod scalar;

use scalar::{add_mul_mod, to_decimal, SUBORDER, U256};

/// 电路撤销树深度（= 聚合器 `SPARSE_DEPTH`，电路 `REVOCATION_DEPTH`）。
const REVOCATION_DEPTH: usize = 256;

/// oracle 输出（gen-witness `WitnessOut` 的 prove 侧消费子集）。
struct OracleOut {
    agent_pub_x: [u8; 32],
    agent_pub_y: [u8; 32],
    sig_r: [u8; 32],
    sig_h: [u8; 32],
    sig_r8_x: [u8; 32],
    sig_r8_y: [u8; 32],
    intent_hash: [u8; 32],
}

/// 工具链调用方式（探测语义与聚合器 `bb::BbBackend` 同款三层：环境覆盖 → PATH →
/// WSL2 兜底；nargo 与 bb 必须同层可得，混层意味着装配错误）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Shell {
    /// 原生（Windows/Linux PATH 或环境变量覆盖）。
    Native { nargo: String, bb: String },
    /// WSL2 兜底：`wsl.exe -d <distro> -u root`，Windows 路径经 `/mnt/<盘>/` 转换。
    Wsl { distro: String },
}

impl Shell {
    /// 环境解析。皆不可得返回 None（构造期报 `E_PROVER`，不落运行时半可用态）。
    fn detect() -> Option<Shell> {
        let nargo_env = std::env::var("MERIDIAN_NARGO_BIN").ok();
        let bb_env = std::env::var("MERIDIAN_BB_BIN").ok();
        let nargo_native = |n: &str| !n.is_empty() && probe(n, "--version");
        let bb_native = |b: &str| !b.is_empty() && probe(b, "--version");
        if let (Some(n), Some(b)) = (&nargo_env, &bb_env) {
            if nargo_native(n) && bb_native(b) {
                return Some(Shell::Native {
                    nargo: n.clone(),
                    bb: b.clone(),
                });
            }
        }
        if nargo_native("nargo") && bb_native("bb") {
            return Some(Shell::Native {
                nargo: "nargo".into(),
                bb: "bb".into(),
            });
        }
        let distro =
            std::env::var("MERIDIAN_WSL_DISTRO").unwrap_or_else(|_| "MeridianUbuntu".into());
        if wsl_probe(&distro) {
            return Some(Shell::Wsl { distro });
        }
        None
    }

    /// 跑一条工具链命令（cwd = 包目录）。失败返回 stderr 尾部供诊断。
    fn run(&self, program: &str, args: &[&str], cwd: &Path) -> Result<std::process::Output, Error> {
        match self {
            Shell::Native { nargo, bb } => {
                let bin = match program {
                    "nargo" => nargo,
                    _ => bb,
                };
                Command::new(bin)
                    .args(args)
                    .current_dir(cwd)
                    .output()
                    .map_err(|e| {
                        eprintln!("[noir-prover] spawn {program} failed: {e}");
                        Error::EProver
                    })
            }
            Shell::Wsl { distro } => {
                let script = format!(
                    "export PATH=\"$HOME/.nargo/bin:$HOME/.bb:$PATH\"; cd '{}' && {} {}",
                    to_wsl_path(cwd),
                    program,
                    args.iter()
                        .map(|a| format!("'{}'", a.replace('\'', "'\\''")))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                Command::new("wsl.exe")
                    .args(["-d", distro, "-u", "root", "-e", "bash", "-lc", &script])
                    .output()
                    .map_err(|e| {
                        eprintln!("[noir-prover] spawn wsl {program} failed: {e}");
                        Error::EProver
                    })
            }
        }
    }

    fn tail_stderr(out: &std::process::Output) -> String {
        let s = String::from_utf8_lossy(&out.stderr);
        s.lines().rev().take(3).collect::<Vec<_>>().join(" | ")
    }
}

fn probe(bin: &str, flag: &str) -> bool {
    Command::new(bin)
        .arg(flag)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// oracle 字节入参 TOML 形态 = 逐字节 hex（gen-witness Prover.toml 同款）。
fn bytes_toml(bs: &[u8]) -> String {
    let items: Vec<String> = bs.iter().map(|b| format!("0x{b:02x}")).collect();
    format!("[{}]", items.join(", "))
}

/// attestation_secret 值域闸（§6.14 契约）：必须是合法 EdDSA 私钥标量（数值 < 子群阶
/// SUBORDER）。越界值进 oracle 会被 nargo 按 BN254 域模拒绝（Field 反序列化失败）——
/// prove / keygen 入口前置同一闸给出同一错误码（e2e 实证：`[0x42; 32]` 即越界）。
fn validate_attestation_secret(secret: &[u8; 32]) -> Result<(), Error> {
    let s = U256::from_le_bytes(secret);
    if s.cmp_to(&U256 { limbs: SUBORDER }) != core::cmp::Ordering::Less {
        eprintln!("[noir-prover] attestation_secret 越出 EdDSA 子群阶（非合法私钥标量）");
        return Err(Error::EProver);
    }
    Ok(())
}

fn wsl_probe(distro: &str) -> bool {
    Command::new("wsl.exe")
        .args([
            "-d",
            distro,
            "-u",
            "root",
            "-e",
            "bash",
            "-lc",
            "export PATH=\"$HOME/.nargo/bin:$HOME/.bb:$PATH\"; command -v nargo >/dev/null 2>&1 && command -v bb >/dev/null 2>&1",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Windows 绝对路径 → WSL 路径（`D:\a\b` → `/mnt/d/a/b`；与聚合器 bb 同款）。
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

/// 跑完/失败即清理的现场守卫：`ProverSDK.toml` 不留包目录（不进版本库的临时 witness）。
struct Cleanup {
    files: Vec<PathBuf>,
}

impl Cleanup {
    fn push(&mut self, p: PathBuf) {
        self.files.push(p);
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for f in &self.files {
            let _ = std::fs::remove_file(f);
        }
    }
}

/// 真 prover（S-43）。构造即探测工具链（fail fast）；`prove` 串行。
pub struct NoirProver {
    gen_witness_dir: PathBuf,
    circuits_dir: PathBuf,
    shell: Shell,
    lock: Mutex<()>,
}

impl NoirProver {
    /// 仓库布局装配（`<root>/gen-witness` + `<root>/circuits`）。
    pub fn from_repo_root(root: &Path) -> Result<Self, Error> {
        Self::from_dirs(&root.join("gen-witness"), &root.join("circuits"))
    }

    /// 显式目录装配。工具链不可得 = `E_PROVER`（构造期报错，不落半可用态）。
    pub fn from_dirs(gen_witness_dir: &Path, circuits_dir: &Path) -> Result<Self, Error> {
        match Shell::detect() {
            Some(shell) => Ok(NoirProver {
                gen_witness_dir: gen_witness_dir.to_path_buf(),
                circuits_dir: circuits_dir.to_path_buf(),
                shell,
                lock: Mutex::new(()),
            }),
            None => {
                eprintln!(
                    "[noir-prover] nargo/bb 工具链不可得（原生与 WSL 兜底皆无；\
                     MERIDIAN_NARGO_BIN / MERIDIAN_BB_BIN / MERIDIAN_WSL_DISTRO 可覆盖）"
                );
                Err(Error::EProver)
            }
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>, Error> {
        self.lock.lock().map_err(|_| Error::EProver)
    }

    /// 步 2：Noir oracle——gen-witness 出 EdDSA 挑战 + attestation 公钥（曲线数学全在
    /// Noir）。撤销入参填零 = 空集（叶 `encode_field(0) = 0 = EMPTY`），树输出弃用：
    /// 撤销 witness 来自聚合器（§6.14 步 5），gen-witness 的 `MAX_REVOKED = 2` 固定
    /// fixture 只服务正式管线。
    fn run_oracle(
        &self,
        req: &SpendProofRequest,
        cleanup: &mut Cleanup,
    ) -> Result<OracleOut, Error> {
        // attestation_secret = 标量的 LE 不透明字节（§6.14 契约口径）→ 数值（十进制）。
        let secret = to_decimal(U256::from_le_bytes(&req.attestation_secret));
        let toml = format!(
            "secret = \"{secret}\"\n\
             delegation_hash = {}\n\
             recipient = {}\n\
             amount = \"{}\"\n\
             category = {}\n\
             spend_nonce = \"{}\"\n\
             expires_at = \"{}\"\n\
             revoked_a = {}\n\
             revoked_b = {}\n",
            bytes_toml(&req.intent.delegation_hash),
            bytes_toml(&req.intent.recipient),
            req.intent.amount,
            bytes_toml(&req.intent.category),
            req.intent.spend_nonce,
            req.intent.expires_at,
            bytes_toml(&[0u8; 32]),
            bytes_toml(&[0u8; 32]),
        );
        // witness 显式命名 `oracle`：不覆盖正式管线工件（formal_zk 产 gen_witness.gz）。
        self.run_oracle_with(&toml, "oracle", cleanup)
    }

    /// keygen（S-46，§6.14 诚实边界 2 收口）：从 attestation_secret 派生 BabyJubJub
    /// attestation 公钥——复用 prove 链路步 2 的同一 oracle 入口（意图入参填零，只消费
    /// `agent_pub_x/y`，签名/撤销树输出弃用；`eddsa_to_pub` 是 prove 链路同一函数，零漂移），
    /// **曲线数学仍全在 Noir**（S-05 教训守住）。`SdkClient::with_noir` 装配后，`attest()`
    /// 的 agent_commit 与 `pay()` 证明公共输入 agent_commit 同一 secret 单一来源。
    pub fn attestation_pubkey(&self, secret: [u8; 32]) -> Result<AttestationPubKey, Error> {
        validate_attestation_secret(&secret)?;
        // 与 prove 共用进程级互斥：ProverSDK.toml 同一临时文件，不允许并发写。
        let _serial = self.lock()?;
        let mut cleanup = Cleanup { files: Vec::new() };
        let toml = format!(
            "secret = \"{}\"\n\
             delegation_hash = {}\n\
             recipient = {}\n\
             amount = \"0\"\n\
             category = {}\n\
             spend_nonce = \"0\"\n\
             expires_at = \"0\"\n\
             revoked_a = {}\n\
             revoked_b = {}\n",
            to_decimal(U256::from_le_bytes(&secret)),
            bytes_toml(&[0u8; 32]),
            bytes_toml(&[0u8; 20]),
            bytes_toml(&[0u8; 32]),
            bytes_toml(&[0u8; 32]),
            bytes_toml(&[0u8; 32]),
        );
        // witness 独立命名 `keygen`：不覆盖正式管线 / prove 链路工件。
        let oracle = self.run_oracle_with(&toml, "keygen", &mut cleanup)?;
        let pk = AttestationPubKey {
            // oracle 标量出参是 Field 的 32B 大端外形，AttestationPubKey 是 LE（电路
            // to_le_bytes 口径）——先翻转再出（`formal_gen_to_prover.py` 的 le32 同款）。
            x: le32(&oracle.agent_pub_x),
            y: le32(&oracle.agent_pub_y),
        };
        // 交叉校验：core 的 agent_commit（规范口径 sha256(x_le ‖ y_le)）必须与 oracle
        // 口径承诺一致——锁定 LE 翻转的肢序（S-41 坑②同源错位在此 fail-closed）。
        if agent_commit(&pk) != oracle_commit(&oracle) {
            eprintln!("[noir-prover] keygen 公钥承诺交叉校验失配（E_PROVER）");
            return Err(Error::EProver);
        }
        Ok(pk)
    }

    /// oracle 执行（步 2 共用体）：写包目录 `ProverSDK.toml` → `nargo execute <witness>`
    /// （`--prover-name ProverSDK` 独立 toml，不碰正式管线 `Prover.toml`）→ 解析
    /// `[return]` 节。witness 名由调用方给定（prove 链路 `oracle` / keygen `keygen`），
    /// 均不覆盖正式管线工件（formal_zk 产 gen_witness.gz）。
    fn run_oracle_with(
        &self,
        toml: &str,
        witness_name: &str,
        cleanup: &mut Cleanup,
    ) -> Result<OracleOut, Error> {
        let oracle_toml = self.gen_witness_dir.join("ProverSDK.toml");
        std::fs::write(&oracle_toml, toml).map_err(|e| {
            eprintln!("[noir-prover] write oracle ProverSDK.toml failed: {e}");
            Error::EProver
        })?;
        cleanup.push(oracle_toml);

        let out = self.shell.run(
            "nargo",
            &[
                "execute",
                witness_name,
                "--prover-name",
                "ProverSDK",
                "--overwrite-return",
            ],
            &self.gen_witness_dir,
        )?;
        if !out.status.success() {
            eprintln!(
                "[noir-prover] oracle execute failed: {}",
                Shell::tail_stderr(&out)
            );
            return Err(Error::EProver);
        }
        let src = std::fs::read_to_string(self.gen_witness_dir.join("ProverSDK.toml"))
            .map_err(|_| Error::EProver)?;
        let ret = TomlReturn::parse(&src)?;
        Ok(OracleOut {
            agent_pub_x: ret.scalar("agent_pub_x")?,
            agent_pub_y: ret.scalar("agent_pub_y")?,
            sig_r: ret.scalar("sig_r")?,
            sig_h: ret.scalar("sig_h")?,
            sig_r8_x: ret.scalar("sig_r8_x")?,
            sig_r8_y: ret.scalar("sig_r8_y")?,
            intent_hash: ret.byte_array("intent_hash")?,
        })
    }

    /// 步 6：拼 circuits witness → nargo execute（电路自校验）→ bb prove → 读回 proof。
    fn build_and_prove(
        &self,
        req: &SpendProofRequest,
        oracle: &OracleOut,
        cleanup: &mut Cleanup,
    ) -> Result<SpendProof, Error> {
        let intent = req.intent;
        let del = &req.sd.delegation;
        let fe_dec = |b: &[u8; 32]| to_decimal(U256::from_be_bytes(b));
        let bytes_toml = |bs: &[u8]| -> String {
            let items: Vec<String> = bs.iter().map(|b| format!("0x{b:02x}")).collect();
            format!("[{}]", items.join(", "))
        };
        // 类别白名单：Noir 数组定长 8，不足补零（电路用 categories_len 约束有效长度）。
        if del.categories.len() > 8 {
            eprintln!("[noir-prover] categories 超出电路容量 8");
            return Err(Error::EProver);
        }
        let mut cats = String::from("[");
        for c in &del.categories {
            cats.push_str(&bytes_toml(c));
            cats.push_str(", ");
        }
        for _ in del.categories.len()..8 {
            cats.push_str(&bytes_toml(&[0u8; 32]));
            cats.push_str(", ");
        }
        cats.push(']');
        // 撤销路径：BE Field 32B → 十进制（电路 `revocation_path: [Field; 256]`）。
        if req.revocation.path.len() != REVOCATION_DEPTH {
            eprintln!(
                "[noir-prover] revocation path 长度 {} != {REVOCATION_DEPTH}（占位口径不可进真后端）",
                req.revocation.path.len()
            );
            return Err(Error::EProver);
        }
        let path_items: Vec<String> = req
            .revocation
            .path
            .iter()
            .map(|p| format!("\"{}\"", fe_dec(p)))
            .collect();
        let toml = format!(
            "agent_commit = {}\n\
             delegation_hash = {}\n\
             recipient = {}\n\
             amount = \"{}\"\n\
             category = {}\n\
             spend_nonce = \"{}\"\n\
             expires_at = \"{}\"\n\
             revocation_root = \"{}\"\n\
             now = \"{}\"\n\
             agent_pub_x = \"{}\"\n\
             agent_pub_y = \"{}\"\n\
             sig_s = \"{}\"\n\
             sig_r8_x = \"{}\"\n\
             sig_r8_y = \"{}\"\n\
             max_per_spend = \"{}\"\n\
             categories = {cats}\n\
             categories_len = {}\n\
             not_before = {}\n\
             revocation_path = [{}]\n",
            bytes_toml(&oracle_commit(oracle)),
            bytes_toml(&intent.delegation_hash),
            bytes_toml(&intent.recipient),
            intent.amount,
            bytes_toml(&intent.category),
            intent.spend_nonce,
            intent.expires_at,
            fe_dec(&req.revocation.root),
            req.now,
            fe_dec(&oracle.agent_pub_x),
            fe_dec(&oracle.agent_pub_y),
            fe_dec(&sig_s(req, oracle)?),
            fe_dec(&oracle.sig_r8_x),
            fe_dec(&oracle.sig_r8_y),
            del.max_per_spend,
            del.categories.len(),
            del.not_before,
            path_items.join(", "),
        );
        let prov_toml = self.circuits_dir.join("ProverSDK.toml");
        std::fs::write(&prov_toml, &toml).map_err(|e| {
            eprintln!("[noir-prover] write circuits ProverSDK.toml failed: {e}");
            Error::EProver
        })?;
        cleanup.push(prov_toml);

        // 电路自校验：断言 1-9 全过才有 witness（任一断言失败 = 求解退出非零）。
        let out = self.shell.run(
            "nargo",
            &["execute", "sdkproof", "--prover-name", "ProverSDK"],
            &self.circuits_dir,
        )?;
        if !out.status.success() {
            eprintln!(
                "[noir-prover] circuit execute failed（witness 求解被电路断言拒绝）: {}",
                Shell::tail_stderr(&out)
            );
            return Err(Error::EProver);
        }
        // bb prove：flavor 与验证侧（§6.13）一致；witness 不覆盖正式管线工件。
        let out = self.shell.run(
            "bb",
            &[
                "prove",
                "-t",
                VERIFIER_TARGET,
                "-b",
                "target/spend_authorization.json",
                "-w",
                "target/sdkproof.gz",
                "-o",
                "target/sdkout",
            ],
            &self.circuits_dir,
        )?;
        if !out.status.success() {
            eprintln!(
                "[noir-prover] bb prove failed: {}",
                Shell::tail_stderr(&out)
            );
            return Err(Error::EProver);
        }
        let proof = std::fs::read(self.circuits_dir.join("target/sdkout/proof")).map_err(|e| {
            eprintln!("[noir-prover] read proof failed: {e}");
            Error::EProver
        })?;
        let pi = self.public_inputs(req, oracle)?;
        // 公共输入逐字节比对：Rust 装配口径 vs bb 从 witness 读出的口径——不一致即
        // E_PROVER（序列化器不许抄自己的答案，与 §6.13 e2e 的第三实现口径互补）。
        let bb_pi =
            std::fs::read(self.circuits_dir.join("target/sdkout/public_inputs")).map_err(|e| {
                eprintln!("[noir-prover] read bb public_inputs failed: {e}");
                Error::EProver
            })?;
        if bb_pi != serialize_public_inputs(&pi) {
            eprintln!("[noir-prover] bb public_inputs 与 Rust 装配不一致（E_PROVER）");
            return Err(Error::EProver);
        }
        Ok(SpendProof {
            proof,
            public_inputs: pi,
        })
    }

    /// 公共输入（Rust 装配；agent_commit 来自 oracle 公钥，撤销根来自聚合器 witness）。
    fn public_inputs(
        &self,
        req: &SpendProofRequest,
        oracle: &OracleOut,
    ) -> Result<SpendPublicInputs, Error> {
        Ok(SpendPublicInputs {
            agent_commit: oracle_commit(oracle),
            delegation_hash: req.intent.delegation_hash,
            recipient: req.intent.recipient,
            amount: req.intent.amount,
            category: req.intent.category,
            spend_nonce: req.intent.spend_nonce,
            expires_at: req.intent.expires_at,
            revocation_root: req.revocation.root,
            now: req.now,
        })
    }
}

impl SpendProver for NoirProver {
    fn prove(&self, req: &SpendProofRequest) -> Result<SpendProof, Error> {
        let _serial = self.lock()?;
        let mut cleanup = Cleanup { files: Vec::new() };
        let intent = req.intent;
        let del = &req.sd.delegation;

        // 步 0（廉价 fail-closed 前置）：请求自洽性——信封与委托同源、预算/窗口/nonce
        // 在电路断言域内（电路会再校验一遍，这里提前给出同一错误码的清晰失败）。
        if intent.delegation_hash != delegation_hash_of(req.sd) {
            eprintln!("[noir-prover] intent.delegation_hash 与 SignedDelegation 不一致");
            return Err(Error::EProver);
        }
        if intent.amount > del.max_per_spend
            || intent.spend_nonce == 0
            || intent.delegation_hash[0] == 0
            || del.not_before > req.now
            || req.now > intent.expires_at
        {
            eprintln!("[noir-prover] 请求越出电路断言域（预算/窗口/nonce/锚点非零）");
            return Err(Error::EProver);
        }
        // 占位口径（空 path / 全零 root）在一切重操作之前被拒——fail-closed 不降级。
        if req.revocation.path.len() != REVOCATION_DEPTH {
            eprintln!(
                "[noir-prover] revocation path 长度 {} != {REVOCATION_DEPTH}（占位口径不可进真后端）",
                req.revocation.path.len()
            );
            return Err(Error::EProver);
        }
        // attestation_secret 值域闸（§6.14 契约）：非法标量不进 oracle（fail-closed）。
        validate_attestation_secret(&req.attestation_secret)?;

        // 步 2：Noir oracle（曲线数学全在 Noir）。
        let oracle = self.run_oracle(req, &mut cleanup)?;

        // 步 3：Rust 交叉校验（第三实现锚，镜像 formal_gen_to_prover.py）。
        let commit = oracle_commit(&oracle);
        let ih = zk_intent_hash(
            commit,
            intent.delegation_hash,
            intent.recipient,
            intent.amount,
            intent.category,
            intent.spend_nonce,
            intent.expires_at,
        );
        if ih != oracle.intent_hash {
            eprintln!(
                "[noir-prover] intent_hash 交叉校验失配: rust={} oracle={}",
                hex::encode(ih),
                hex::encode(oracle.intent_hash)
            );
            return Err(Error::EProver);
        }

        // 步 5：撤销 witness 自洽（fail-closed）——EMPTY 叶 + 逐层兄弟重算 == root，
        // 方向约定 = 电路 compute_merkle_root（索引位 0 → H(当前 ‖ 兄弟)）。
        verify_revocation_witness(&intent.delegation_hash, &req.revocation)?;

        // 步 6：拼 witness + 电路自校验 + bb prove。
        self.build_and_prove(req, &oracle, &mut cleanup)
    }
}

/// 步 5：从 path + EMPTY 叶重算根（聚合器 `noir_pedersen`，S-41 复现的 Noir
/// pedersen_hash）并要求与 witness.root 逐字节相等。
fn verify_revocation_witness(index: &[u8; 32], w: &RevocationWitness) -> Result<(), Error> {
    if w.path.len() != REVOCATION_DEPTH {
        eprintln!(
            "[noir-prover] revocation path 长度 {} != {REVOCATION_DEPTH}",
            w.path.len()
        );
        return Err(Error::EProver);
    }
    let mut current = Fe::zero();
    for (d, sib) in w.path.iter().enumerate() {
        let bit = (index[d / 8] >> (d % 8)) & 1;
        let sib = Fe::from_be_bytes(sib);
        current = if bit == 0 {
            pedersen_hash2(current, sib)
        } else {
            pedersen_hash2(sib, current)
        };
    }
    if current.to_be_bytes() != w.root {
        eprintln!("[noir-prover] 撤销 witness 不自洽：path 重算根 != root（E_PROVER）");
        return Err(Error::EProver);
    }
    Ok(())
}

/// attestation 承诺 = sha256(pub_x_le ‖ pub_y_le)（电路 `agent_commit_ok` 同规范；
/// Rust 侧纯字节逻辑，attestation.rs 同款）。oracle 标量出参是 Field 的 32B 大端外形，
/// 电路吃 LE——先翻转再哈希（`formal_gen_to_prover.py` 的 `le32` 同款）。
fn oracle_commit(o: &OracleOut) -> [u8; 32] {
    let mut pk = [0u8; 64];
    pk[..32].copy_from_slice(&le32(&o.agent_pub_x));
    pk[32..].copy_from_slice(&le32(&o.agent_pub_y));
    let mut h = Sha256::new();
    h.update(pk);
    h.finalize().into()
}

/// Field 32B 大端外形 → LE 字节（电路 `to_le_bytes` 口径）。
fn le32(be: &[u8; 32]) -> [u8; 32] {
    let mut out = *be;
    out.reverse();
    out
}

/// 步 4：签名标量 `s = (r + h·secret) mod SUBORDER`（Rust 大整数，Python 管线同款归约）。
fn sig_s(req: &SpendProofRequest, o: &OracleOut) -> Result<[u8; 32], Error> {
    let r = U256::from_be_bytes(&o.sig_r);
    let h = U256::from_be_bytes(&o.sig_h);
    let secret = U256::from_le_bytes(&req.attestation_secret);
    let m = U256 { limbs: SUBORDER };
    let s = add_mul_mod(r, h, secret, &m);
    if s.cmp_to(&m) != core::cmp::Ordering::Less {
        return Err(Error::EProver);
    }
    Ok(s.to_be_bytes())
}

/// 委托哈希重算（`delegation_hash` 的薄封装，避免在热签名对象上引入歧义）。
fn delegation_hash_of(sd: &meridian_core::dsa::SignedDelegation) -> [u8; 32] {
    meridian_core::dsa::delegation_hash(&sd.delegation)
}

/// gen-witness `ProverSDK.toml` 的 `[return]` 节解析（nargo `--overwrite-return` 序列化
/// 形态：标量 = "0x + 64 hex"（Field 的 32B 大端），数组 = 同形态列表）。
struct TomlReturn<'a> {
    src: &'a str,
}

impl<'a> TomlReturn<'a> {
    fn parse(src: &'a str) -> Result<Self, Error> {
        let start = src
            .lines()
            .position(|l| l.trim() == "[return]")
            .ok_or_else(|| {
                eprintln!(
                    "[noir-prover] ProverSDK.toml 无 [return] 节（--overwrite-return 未生效？）"
                );
                Error::EProver
            })?;
        Ok(TomlReturn {
            src: &src[src
                .lines()
                .take(start + 1)
                .map(|l| l.len() + 1)
                .sum::<usize>()..],
        })
    }

    fn value(&self, key: &str) -> Result<String, Error> {
        let prefix = format!("{key} = ");
        let mut lines = self.src.lines();
        while let Some(line) = lines.next() {
            let Some(rest) = line.strip_prefix(&prefix) else {
                continue;
            };
            // 单行值直接取；数组值可能跨行（nargo 序列化长数组换行）——括号未闭合则
            // 继续吃行，以空格拼接（byte_array 的逗号切分与括号剥离对拼接形态不敏感）。
            let mut acc = rest.trim().to_string();
            while acc.matches('[').count() > acc.matches(']').count() {
                match lines.next() {
                    Some(l) => {
                        acc.push(' ');
                        acc.push_str(l.trim());
                    }
                    None => break,
                }
            }
            return Ok(acc);
        }
        eprintln!("[noir-prover] [return] 缺字段 {key}");
        Err(Error::EProver)
    }

    /// 标量 Field：0x + 64 hex（32B 大端）。
    fn scalar(&self, key: &str) -> Result<[u8; 32], Error> {
        let raw = self.value(key)?;
        let raw = raw.trim_matches('"');
        let hexs = raw.strip_prefix("0x").unwrap_or(raw);
        let b = hex::decode(hexs).map_err(|e| {
            eprintln!("[noir-prover] {key} hex 解析失败: {e}");
            Error::EProver
        })?;
        let mut out = [0u8; 32];
        if b.len() > 32 {
            eprintln!("[noir-prover] {key} 超过 32 字节");
            return Err(Error::EProver);
        }
        out[32 - b.len()..].copy_from_slice(&b);
        Ok(out)
    }

    /// `[u8; N]` 字节数组（每字节一个 Field，取每项低字节）。
    fn byte_array(&self, key: &str) -> Result<[u8; 32], Error> {
        let raw = self.value(key)?;
        let inner = raw
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .filter(|s| !s.trim().is_empty());
        let mut out = [0u8; 32];
        let mut n = 0usize;
        for item in inner {
            if n >= 32 {
                eprintln!("[noir-prover] {key} 超过 32 字节");
                return Err(Error::EProver);
            }
            let s = item.trim().trim_matches('"');
            let s = s.strip_prefix("0x").unwrap_or(s);
            let b = hex::decode(s).map_err(|e| {
                eprintln!("[noir-prover] {key} 项 hex 解析失败: {e}");
                Error::EProver
            })?;
            out[n] = *b.last().ok_or(Error::EProver)?;
            n += 1;
        }
        if n != 32 {
            eprintln!("[noir-prover] {key} 长度 {n} != 32");
            return Err(Error::EProver);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn witness(root: [u8; 32], path: Vec<[u8; 32]>) -> RevocationWitness {
        RevocationWitness { root, path }
    }

    /// 空树根（聚合器 `RevocationSet::default().sparse_root()` 口径的独立重算）。
    fn empty_root() -> [u8; 32] {
        let mut r = Fe::zero();
        for _ in 0..REVOCATION_DEPTH {
            r = pedersen_hash2(r, r);
        }
        r.to_be_bytes()
    }

    #[test]
    fn revocation_witness_self_consistent_for_empty_set() {
        // 空集 witness（path 全层 = empty_roots[d]）重算 == 聚合器 sparse_root。
        let set = meridian_aggregator::revocation::RevocationSet::new();
        let dh = [0x21u8; 32];
        let w: RevocationWitness = set.non_membership_witness(&dh).expect("未撤销").into();
        verify_revocation_witness(&dh, &w).expect("空集 witness 自洽");
        assert_eq!(w.root, empty_root());
        assert_eq!(w.root, set.sparse_root());
    }

    #[test]
    fn revocation_witness_self_consistent_with_real_revocation() {
        // 非空撤销集：路径重算 == 聚合器根（S-42 产出 → S-43 消费的同树锚）。
        let set = meridian_aggregator::revocation::RevocationSet::new();
        let mut revoked = [0u8; 32];
        revoked[0] = 0x01;
        set.insert(revoked);
        let dh = [0x22u8; 32];
        let w: RevocationWitness = set.non_membership_witness(&dh).expect("目标未撤销").into();
        verify_revocation_witness(&dh, &w).expect("非空集 witness 自洽");
        assert_eq!(w.root, set.sparse_root());
        // 已撤销目标：S-42 fail-closed 语义（prove 侧无绕过路径）。
        assert!(set.non_membership_witness(&revoked).is_none());
    }

    #[test]
    fn revocation_witness_tampered_sibling_rejected() {
        // 负向：任一层兄弟被篡改 → 重算根 != root → E_PROVER。
        let set = meridian_aggregator::revocation::RevocationSet::new();
        let mut revoked = [0u8; 32];
        revoked[5] = 0x7F;
        set.insert(revoked);
        let dh = [0x33u8; 32];
        let mut w: RevocationWitness = set.non_membership_witness(&dh).expect("目标未撤销").into();
        let last = w.path.len() - 1;
        w.path[last][0] ^= 0x01;
        assert_eq!(
            verify_revocation_witness(&dh, &w),
            Err(Error::EProver),
            "篡改路径必须被 witness 自洽校验拒绝"
        );
    }

    #[test]
    fn revocation_witness_wrong_length_rejected() {
        // 占位口径（path 为空）不可进真后端（TECH_SPEC §6.14）。
        let w = witness([0u8; 32], Vec::new());
        assert_eq!(
            verify_revocation_witness(&[0u8; 32], &w),
            Err(Error::EProver)
        );
    }

    #[test]
    fn attestation_secret_gate_rejects_out_of_suborder() {
        // 值域闸（S-46 起 prove / keygen 入口共用）：[0x42; 32] 远超 EdDSA 子群阶
        // （e2e 实证会被 nargo 按 BN254 域模拒）→ E_PROVER；小标量合法（0 < secret）。
        assert_eq!(
            validate_attestation_secret(&[0x42u8; 32]),
            Err(Error::EProver)
        );
        let mut s = [0u8; 32];
        s[0] = 0xEF;
        s[1] = 0xBE;
        s[2] = 0xAD;
        s[3] = 0xDE;
        assert!(validate_attestation_secret(&s).is_ok());
    }

    #[test]
    fn oracle_return_parser_shapes() {
        // [return] 节解析：标量 0x + 64 hex（32B 大端左零填充）、字节数组逐项取低字节；
        // 数组跨行（nargo 长数组序列化）必须累积到括号闭合。
        let item = |b: u8| {
            format!("\"0x00000000000000000000000000000000000000000000000000000000000000{b:02x}\"")
        };
        let items: Vec<String> = (0..32)
            .map(|i| item(if i < 2 { i + 1 } else { 0x03 }))
            .collect();
        let src = format!(
            "secret = \"0x...\"\n[return]\nagent_pub_x = \"0x00000000000000000000000000000000000000000000000000000000000000aa\"\nintent_hash = [\n  {},\n]\n",
            items.join(",\n  ")
        );
        let ret = TomlReturn::parse(&src).expect("parse");
        assert_eq!(ret.scalar("agent_pub_x").unwrap()[31], 0xAA);
        let ih = ret.byte_array("intent_hash").unwrap();
        assert_eq!(&ih[..2], &[0x01, 0x02]);
        assert_eq!(ih[31], 0x03);
        // 单行数组（nargo 常见形态）同口径。
        let one_line = format!("[return]\nintent_hash = [{}]\n", items.join(", "));
        let ret2 = TomlReturn::parse(&one_line).expect("parse");
        assert_eq!(ret2.byte_array("intent_hash").unwrap(), ih);
        assert_eq!(ret.scalar("missing"), Err(Error::EProver));
        assert!(TomlReturn::parse("no return here").is_err());
    }

    #[test]
    fn wsl_path_conversion() {
        #[cfg(windows)]
        {
            assert_eq!(
                to_wsl_path(Path::new(r"D:\repo\gen-witness")),
                "/mnt/d/repo/gen-witness"
            );
            assert_eq!(to_wsl_path(Path::new(r"C:\x y")), "/mnt/c/x y");
        }
        assert_eq!(to_wsl_path(Path::new("/tmp/x")), "/tmp/x");
        assert_eq!(to_wsl_path(Path::new("rel/x")), "rel/x");
    }

    #[test]
    fn shell_detect_reports_none_or_complete_layer() {
        // 探测可调用；可得时必为完整层（nargo 与 bb 同层）。
        let _ = Shell::detect();
    }
}
