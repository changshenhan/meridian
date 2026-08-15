//! TEMPORARY —— S-05 冒烟：生成 smoke 电路的 Prover.toml（CI 专用脚手架）。
//!
//! 与 noir_stdlib `std::ecdsa_secp256k1::verify_signature` 的契约对齐
//! （见 noir-src/noir_stdlib/src/ecdsa_secp256k1.nr，v1.0.0-beta.26）：
//!   · 公钥 x/y：大端 32 字节（SEC1 坐标，与 k256 一致）
//!   · 签名：r_be(32) || s_be(32)，且 s 必须为 low-s（BIP-62，否则验证返回 false）
//!   · message_hash：原始 32 字节，直接作为 prehash 验签对象
//!
//! 输出完全确定（密钥=7、message_hash=[0x3a;32]），CI 断言据此稳定。
//! 验证完成后删除；不进 SPEC / 文档。

use std::path::PathBuf;

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use k256::elliptic_curve::SecretKey;

/// Noir TOML 数组字面量：`[0x3a, 0x3a, ...]`。
fn hex_bytes(arr: &[u8]) -> String {
    let mut s = String::from("[");
    for (i, b) in arr.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&format!("0x{b:02x}"));
    }
    s.push(']');
    s
}

fn main() {
    let fbytes: k256::FieldBytes = [7u8; 32].into();
    let sk = SigningKey::from(&SecretKey::from_bytes(&fbytes).expect("valid key bytes"));
    let vk = VerifyingKey::from(&sk);
    let msg_hash: [u8; 32] = [0x3a; 32];

    // prehash 签名（对象即 msg_hash 原始字节）+ 归一化到 low-s（BIP-62）
    let sig: EcdsaSignature =
        sk.sign_prehash(&msg_hash).expect("secp256k1 signing cannot fail");
    let sig = sig.normalize_s().unwrap_or(sig);

    let ep = vk.to_encoded_point(false); // 非压缩 SEC1：0x04 || x_be || y_be
    let x: [u8; 32] = (*ep.x().expect("has x coordinate")).into();
    let y: [u8; 32] = (*ep.y().expect("has y coordinate")).into();
    let sb = sig.to_bytes();

    let prover = format!(
        "message_hash = {}\npub_key_x = {}\npub_key_y = {}\nmessage = 58\nsignature = {}\n",
        hex_bytes(&msg_hash),
        hex_bytes(&x),
        hex_bytes(&y),
        hex_bytes(&sb),
    );

    let out = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("Prover.toml"));
    std::fs::write(&out, prover).expect("write Prover.toml");
    eprintln!("wrote {}", out.display());
}
