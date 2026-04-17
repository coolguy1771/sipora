//! Inbound TLS for SIP (TLS 1.3, optional mTLS). PEM paths and an optional OCSP response
//! DER are loaded by the binary. Automated ACME issuance is **not** implemented here;
//! operators typically use cert-manager, a reverse proxy, or out-of-band renewal.

use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub struct TlsTransport {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsTransport {
    /// Binds a TLS listener. Provide `mtls_client_ca_certs` (PEM-loaded DER certs) to require
    /// client certificates issued by those CAs; an empty slice keeps server-only TLS.
    pub async fn bind(
        addr: SocketAddr,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        mtls_client_ca_certs: &[CertificateDer<'static>],
        ocsp_response: Vec<u8>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config = build_tls_config(certs, key, mtls_client_ca_certs, ocsp_response)?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(addr).await?;
        tracing::info!(%addr, "TLS transport listening");
        Ok(Self { listener, acceptor })
    }

    pub async fn accept(
        &self,
    ) -> Result<
        (
            tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
            SocketAddr,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let (stream, addr) = self.listener.accept().await?;
        let tls_stream = self.acceptor.accept(stream).await?;
        Ok((tls_stream, addr))
    }
}

fn build_tls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    mtls_client_ca_certs: &[CertificateDer<'static>],
    ocsp_response: Vec<u8>,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let client_verifier: Arc<dyn ClientCertVerifier> = if mtls_client_ca_certs.is_empty() {
        WebPkiClientVerifier::no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        for ca in mtls_client_ca_certs {
            roots.add(ca.clone())?;
        }
        WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| format!("mTLS verifier: {e}"))?
    };

    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(client_verifier)
        .with_single_cert_with_ocsp(certs, key, ocsp_response)?;
    Ok(config)
}

pub fn load_certs_from_pem(pem_data: &[u8]) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut &*pem_data)
        .filter_map(|r| r.ok())
        .collect()
}

pub fn load_key_from_pem(pem_data: &[u8]) -> Option<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut &*pem_data).ok().flatten()
}
