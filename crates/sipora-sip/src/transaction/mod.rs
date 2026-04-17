pub mod client_invite;
pub mod client_non_invite;
pub mod manager;
pub mod server_invite;
pub mod server_non_invite;

use crate::types::message::Request;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    Calling,
    Trying,
    Proceeding,
    Completed,
    Confirmed,
    Terminated,
}

#[derive(Debug, Clone)]
pub struct TransactionKey {
    pub branch: String,
    pub method: String,
}

impl TransactionKey {
    pub fn from_request(req: &Request) -> Option<Self> {
        let branch = req.via().first()?.branch.clone();
        Some(Self {
            branch,
            method: req.method.as_str().to_owned(),
        })
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
