//! SIP transaction helpers (timers, client/server invite and non-invite stubs).
//!
//! **Scope:** This module is not integrated into `sipora-proxy`, `sipora-edge`, or other
//! application binaries. Do not treat it as production RFC 3261 / RFC 6026 behavior until
//! it is wired, tested, and documented on a specific signaling path. See `AGENTS.md`.

pub mod client_invite;
pub mod client_non_invite;
pub mod manager;
pub mod server_invite;
pub mod server_non_invite;

use crate::types::header::Via;
use crate::types::message::Request;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    Calling,
    Trying,
    Proceeding,
    Completed,
    Confirmed,
    Accepted,
    Terminated,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionKey {
    pub branch: String,
    pub sent_by: String,
    pub method: String,
}

impl TransactionKey {
    pub fn from_request(req: &Request) -> Option<Self> {
        let vias = req.via();
        let via = vias.first()?;
        let branch = via.branch.clone();
        if branch.is_empty() || !branch.starts_with("z9hG4bK") {
            return None;
        }
        Some(Self {
            branch,
            sent_by: sent_by(via),
            method: req.method.as_str().to_owned(),
        })
    }
}

fn sent_by(via: &Via) -> String {
    match via.port {
        Some(port) => format!("{}:{port}", via.host),
        None => via.host.clone(),
    }
}

pub const TIMER_T1: Duration = Duration::from_millis(500);
pub const TIMER_T2: Duration = Duration::from_secs(4);
pub const TIMER_T4: Duration = Duration::from_secs(5);
pub const TIMER_B: Duration = Duration::from_secs(32);
pub const TIMER_D: Duration = Duration::from_secs(32);
pub const TIMER_F: Duration = Duration::from_secs(32);
pub const TIMER_H: Duration = Duration::from_secs(32);
pub const TIMER_I: Duration = Duration::from_secs(5);
pub const TIMER_J: Duration = Duration::from_secs(32);
pub const TIMER_K: Duration = Duration::from_secs(5);
pub const TIMER_L: Duration = TIMER_B;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::header::{Header, RportParam, Transport};
    use crate::types::message::SipVersion;
    use crate::types::method::Method;

    fn request_with_branch(branch: &str) -> Request {
        Request {
            method: Method::Invite,
            uri: "sip:bob@example.com".to_owned(),
            version: SipVersion::V2_0,
            headers: vec![Header::Via(Via {
                transport: Transport::Udp,
                host: "client.example.com".to_owned(),
                port: Some(5060),
                branch: branch.to_owned(),
                received: None,
                rport: RportParam::Absent,
                params: vec![],
            })],
            body: vec![],
        }
    }

    #[test]
    fn transaction_key_rejects_empty_branch() {
        let req = request_with_branch("");

        assert!(TransactionKey::from_request(&req).is_none());
    }

    #[test]
    fn transaction_key_rejects_branch_without_magic_cookie() {
        let req = request_with_branch("legacy-branch");

        assert!(TransactionKey::from_request(&req).is_none());
    }

    #[test]
    fn transaction_key_accepts_valid_branch() {
        let req = request_with_branch("z9hG4bK-abc123");
        let key = TransactionKey::from_request(&req)
            .expect("valid branch should produce a transaction key");
        assert_eq!(key.branch, "z9hG4bK-abc123");
        assert_eq!(key.sent_by, "client.example.com:5060");
        assert_eq!(key.method, "INVITE");
    }
}
