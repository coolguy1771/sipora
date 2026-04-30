//! Outbound TCP SIP connections with a per-peer writer and reader dispatch.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use sipora_sip::parser::message::parse_sip_message;
use sipora_sip::types::message::SipMessage;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;

use crate::sip_tcp::read_one_message;

const SEND_QUEUE: usize = 256;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_PAUSE: Duration = Duration::from_millis(200);

/// Inbound SIP on a pooled TCP leg.
pub type TcpInboundTx = mpsc::Sender<(SocketAddr, SipMessage)>;

#[derive(Clone)]
pub struct TcpConnectionPool {
    inner: Arc<Inner>,
}

struct Inner {
    peers: Mutex<HashMap<SocketAddr, mpsc::Sender<Bytes>>>,
    inbound: TcpInboundTx,
    read_cap: usize,
}

impl TcpConnectionPool {
    pub fn new(inbound: TcpInboundTx, max_message_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                peers: Mutex::new(HashMap::new()),
                inbound,
                read_cap: max_message_bytes.clamp(4096, 1_048_576),
            }),
        }
    }

    pub async fn send(&self, addr: SocketAddr, payload: Bytes) -> io::Result<()> {
        let tx = self.ensure_sender(addr).await?;
        tx.send(payload)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tcp send queue closed"))
    }

    async fn ensure_sender(&self, addr: SocketAddr) -> io::Result<mpsc::Sender<Bytes>> {
        let mut g = self.inner.peers.lock().await;
        if let Some(tx) = g.get(&addr) {
            if !tx.is_closed() {
                return Ok(tx.clone());
            }
            g.remove(&addr);
        }
        let (tx, rx) = mpsc::channel(SEND_QUEUE);
        let inner = self.inner.clone();
        tokio::spawn(peer_loop(addr, rx, inner));
        g.insert(addr, tx.clone());
        Ok(tx)
    }

    pub async fn forget_peer(&self, addr: SocketAddr) {
        self.inner.peers.lock().await.remove(&addr);
    }
}

async fn connect_retry(addr: SocketAddr) -> TcpStream {
    loop {
        match TcpStream::connect(addr).await {
            Ok(s) => return s,
            Err(e) => {
                tracing::debug!(%addr, "tcp pool connect retry: {e}");
                tokio::time::sleep(RETRY_PAUSE).await;
            }
        }
    }
}

async fn write_all_timed(w: &mut OwnedWriteHalf, b: &[u8]) -> io::Result<()> {
    timeout(WRITE_TIMEOUT, w.write_all(b))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp write timeout"))??;
    timeout(WRITE_TIMEOUT, w.flush())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp flush timeout"))??;
    Ok(())
}

async fn reader_loop(addr: SocketAddr, mut rd: OwnedReadHalf, inbound: TcpInboundTx, cap: usize) {
    loop {
        let raw = match read_one_message(&mut rd, cap).await {
            Ok(r) => r,
            Err(e) => {
                tracing::trace!(%addr, "tcp pool read: {e}");
                break;
            }
        };
        let Ok((_, msg)) = parse_sip_message(&raw) else {
            continue;
        };
        if inbound.send((addr, msg)).await.is_err() {
            break;
        }
    }
}

async fn peer_loop(addr: SocketAddr, mut rx: mpsc::Receiver<Bytes>, pool: Arc<Inner>) {
    let first = match rx.recv().await {
        Some(b) => b,
        None => return,
    };
    let stream = connect_retry(addr).await;
    let (rd, mut wr) = stream.into_split();
    let inbound = pool.inbound.clone();
    let cap = pool.read_cap;
    let reader = tokio::spawn(reader_loop(addr, rd, inbound, cap));
    if write_all_timed(&mut wr, &first).await.is_err() {
        reader.abort();
        drop(wr);
        pool.peers.lock().await.remove(&addr);
        return;
    }
    loop {
        let next = match rx.recv().await {
            Some(b) => b,
            None => break,
        };
        if write_all_timed(&mut wr, &next).await.is_err() {
            break;
        }
    }
    reader.abort();
    drop(wr);
    pool.peers.lock().await.remove(&addr);
}
