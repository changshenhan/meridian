//! 本地交付端点的 TLS 证书：rcgen 现场生成自签 CA + 叶证书。
//!
//! 模拟"收款方"的 TLS 端点。CA 的 DER 交给 tlsn 的 RootCertStore（客户端信任根），
//! 叶证书 + 私钥给本地 TLS 服务器。域名固定 `DELIVERY_DOMAIN`，叶证书 SAN 匹配。

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// 交付端点域名（叶证书 SAN；tlsn 客户端按它校验 server_name）。
pub const DELIVERY_DOMAIN: &str = "delivery.meridian.test";

/// 现场生成的证书三元组。
pub struct Certs {
    /// CA 证书 DER（tlsn RootCertStore 的信任根）。
    pub ca_der: CertificateDer<'static>,
    /// 叶证书 DER（服务器出示）。
    pub leaf_der: CertificateDer<'static>,
    /// 叶私钥（服务器握手用）。
    pub leaf_key: PrivateKeyDer<'static>,
}

pub fn generate() -> Result<Certs> {
    // --- CA：自签，BasicConstraints=CA，无 SAN ---
    let mut ca_params = CertificateParams::new(Vec::<String>::new())
        .context("ca params")?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Meridian Delivery Test CA");
    let ca_kp = KeyPair::generate().context("ca keygen")?;
    let ca_cert = ca_params
        .self_signed(&ca_kp)
        .context("ca self-sign")?;

    // --- 叶：SAN = DELIVERY_DOMAIN，由 CA 签发 ---
    let mut leaf_params = CertificateParams::new(vec![DELIVERY_DOMAIN.to_string()])
        .context("leaf params")?;
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, DELIVERY_DOMAIN);
    let leaf_kp = KeyPair::generate().context("leaf keygen")?;
    let leaf_cert = leaf_params
        .signed_by(&leaf_kp, &ca_cert, &ca_kp)
        .context("leaf sign")?;

    Ok(Certs {
        ca_der: CertificateDer::from(ca_cert.der().clone()),
        leaf_der: CertificateDer::from(leaf_cert.der().clone()),
        leaf_key: PrivateKeyDer::try_from(leaf_kp.serialize_der())
            .map_err(|e| anyhow::anyhow!("leaf key der: {e}"))?,
    })
}
