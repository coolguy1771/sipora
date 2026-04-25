//! Outbound TLS client pool for SIP over TLS (RFC 5630 / sips: URIs).
//!
//! [`TlsClientPool`] caches one TLS stream per `(SocketAddr, SNI hostname)` so different
//! server names to the same address do not share a session. Each key uses an inner async
//! mutex so at most one task connects for that key; the outer pool lock is not held across
//! I/O.

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

type TlsTcp = TlsStream<TcpStream>;
type ConnCell = Arc<tokio::sync::Mutex<Option<TlsTcp>>>;
type PoolKey = (SocketAddr, String);
type Pool = Mutex<HashMap<PoolKey, ConnCell>>;

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
    /// Opens a new TLS connection if none is cached for this `(addr, SNI)` pair. On write
    /// failure the entry is evicted and one reconnect attempt is made.
    pub async fn send(
        &self,
        addr: SocketAddr,
        server_name: &str,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let name = ServerName::try_from(server_name.to_owned())?;
        let key: PoolKey = (addr, server_name.to_owned());

        for _ in 0..2u8 {
            let cell = {
                let mut pool = self.pool.lock().await;
                pool.entry(key.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None)))
                    .clone()
            };

            let mut inner = cell.lock().await;
            if inner.is_none() {
                let tcp = TcpStream::connect(addr).await?;
                let tls = self.connector.connect(name.clone(), tcp).await?;
                *inner = Some(tls);
            }
            let stream = inner
                .as_mut()
                .ok_or_else(|| std::io::Error::other("TLS stream missing after connect"))?;
            let write_ok = stream.write_all(data).await.is_ok();
            let flush_ok = if write_ok {
                stream.flush().await.is_ok()
            } else {
                false
            };
            if write_ok && flush_ok {
                return Ok(());
            }
            *inner = None;
            drop(inner);
            self.pool.lock().await.remove(&key);
        }

        Err(std::io::Error::other("TLS send failed after retry").into())
    }

    /// Explicitly close and evict the connection for `addr` and `server_name`.
    pub async fn evict(&self, addr: SocketAddr, server_name: &str) {
        self.pool
            .lock()
            .await
            .remove(&(addr, server_name.to_owned()));
    }
}

impl Default for TlsClientPool {
    fn default() -> Self {
        Self::new()
    }
}
