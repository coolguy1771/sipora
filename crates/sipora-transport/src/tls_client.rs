//! Outbound TLS client pool for SIP over TLS (RFC 5630 / sips: URIs).
//!
//! [`TlsClientPool`] maintains one persistent TLS connection per remote `SocketAddr`.
//! On the first write to a target the pool dials, performs a TLS 1.3 handshake
//! (verified against the WebPKI root store), and caches the stream.  Subsequent
//! calls reuse the cached stream; a failed write evicts the entry so the next
//! call re-connects.

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

type Pool = Mutex<HashMap<SocketAddr, TlsStream<TcpStream>>>;

pub struct TlsClientPool {
    connector: TlsConnector,
    pool: Pool,
}

impl TlsClientPool {
    /// Creates a pool backed by Mozilla's WebPKI root certificates.
    pub fn new() -> Self {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Self {
            connector: TlsConnector::from(Arc::new(config)),
            pool: Mutex::new(HashMap::new()),
        }
    }

    /// Send `data` to `addr` using the SNI name `server_name`.
    ///
    /// Opens a new TLS connection if none is cached; evicts and retries once on
    /// write failure.
    pub async fn send(
        &self,
        addr: SocketAddr,
        server_name: &str,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let name = ServerName::try_from(server_name.to_owned())?;

        // Try cached connection first.
        {
            let mut pool = self.pool.lock().await;
            if let Some(stream) = pool.get_mut(&addr) {
                if stream.write_all(data).await.is_ok() {
                    return Ok(());
                }
                // Write failed — evict the stale entry.
                pool.remove(&addr);
            }
        }

        // Establish a fresh connection.
        let tcp = TcpStream::connect(addr).await?;
        let mut tls = self.connector.connect(name, tcp).await?;
        tls.write_all(data).await?;
        self.pool.lock().await.insert(addr, tls);
        Ok(())
    }

    /// Explicitly close and evict the connection to `addr`.
    pub async fn evict(&self, addr: SocketAddr) {
        self.pool.lock().await.remove(&addr);
    }
}

impl Default for TlsClientPool {
    fn default() -> Self {
        Self::new()
    }
}
