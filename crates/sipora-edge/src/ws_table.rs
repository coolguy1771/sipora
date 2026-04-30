//! WebSocket SIP connections keyed by opaque id (NOTIFY / outbound).

use std::collections::HashMap;
use std::sync::Arc;

use sipora_sip::types::message::SipMessage;
use tokio::sync::{RwLock, mpsc};

/// Bounded outbound queue per WS connection (matches edge listener).
pub const WS_OUTBOUND_QUEUE: usize = 64;

pub type WsConnectionTable = Arc<RwLock<HashMap<String, mpsc::Sender<SipMessage>>>>;

pub fn new_ws_connection_table() -> WsConnectionTable {
    Arc::new(RwLock::new(HashMap::new()))
}
