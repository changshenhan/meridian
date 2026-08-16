// TEMPORARY —— S-05 管线冒烟脚手架（secp256k1 blackbox）。
// 目标：在 CI 上跑通 nargo prove → bb verify → 公共输入回读 全链路。
// 用 std::ecdsa_secp256k1 黑盒构造最小电路；验证完成后删除，不进 SPEC / 文档。
//
// 公共输入形态与正式电路（spend_authorization）一致（数组 + Field），
// 借此验证 pub 数组在 barretenberg 后端里的公共输入编码与回读解析。
// message 绑定到 message_hash 首字节：篡改任一公共输入都会让证明失败（绑定验证）。
//
// 链下签名由 circuits/smoke-gen 生成（k256，low-s，prehash 签名），写 Prover.toml。
use std::ecdsa_secp256k1::verify_signature;

pub fn main(
    signature: [u8; 64],
    message_hash: pub [u8; 32],
    pub_key_x: pub [u8; 32],
    pub_key_y: pub [u8; 32],
    message: pub Field,
) {
    // 验签：pub_key(x,y) 对 message_hash 的 prehash ECDSA 签名（大端 r||s，low-s）。
    assert(verify_signature(pub_key_x, pub_key_y, signature, message_hash));
    // 公共输入 ↔ 签名对象 的绑定锚点。
    assert(message == (message_hash[0] as Field));
}
