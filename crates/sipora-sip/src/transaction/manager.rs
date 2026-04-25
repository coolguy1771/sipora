use super::TransactionKey;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
    ClientInvite,
    ClientNonInvite,
    ServerInvite,
    ServerNonInvite,
}

pub struct TransactionEntry {
    pub key: TransactionKey,
    pub tx_type: TransactionType,
    pub abort_handle: Option<tokio::task::AbortHandle>,
}

pub struct TransactionManager {
    transactions: HashMap<TransactionKey, TransactionEntry>,
}

impl TransactionManager {
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: TransactionKey, tx_type: TransactionType) {
        let entry = TransactionEntry {
            key: key.clone(),
            tx_type,
            abort_handle: None,
        };
        self.transactions.insert(key, entry);
    }

    pub fn insert_with_timer(
        &mut self,
        key: TransactionKey,
        tx_type: TransactionType,
        abort_handle: tokio::task::AbortHandle,
    ) {
        let entry = TransactionEntry {
            key: key.clone(),
            tx_type,
            abort_handle: Some(abort_handle),
        };
        self.transactions.insert(key, entry);
    }

    pub fn find(&self, key: &TransactionKey) -> Option<&TransactionEntry> {
        self.transactions.get(key)
    }

    pub fn remove(&mut self, key: &TransactionKey) -> Option<TransactionEntry> {
        let entry = self.transactions.remove(key)?;
        if let Some(handle) = &entry.abort_handle {
            handle.abort();
        }
        Some(entry)
    }

    pub fn has_transaction(&self, key: &TransactionKey) -> bool {
        self.find(key).is_some()
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::header::{Header, RportParam, Transport, Via};
    use crate::types::message::{Request, SipVersion};
    use crate::types::method::Method;

    fn request_from(host: &str, port: Option<u16>) -> Request {
        Request {
            method: Method::Invite,
            uri: "sip:bob@example.com".to_owned(),
            version: SipVersion::V2_0,
            headers: vec![Header::Via(Via {
                transport: Transport::Udp,
                host: host.to_owned(),
                port,
                branch: "z9hG4bK-collision".to_owned(),
                received: None,
                rport: RportParam::Absent,
                params: vec![],
            })],
            body: vec![],
        }
    }

    #[test]
    fn matching_key_includes_sent_by() {
        let key_a = TransactionKey::from_request(&request_from("a.example.com", Some(5060)))
            .expect("transaction key");
        let key_b = TransactionKey::from_request(&request_from("b.example.com", Some(5060)))
            .expect("transaction key");

        assert_ne!(key_a.sent_by, key_b.sent_by);
    }

    #[test]
    fn manager_keeps_colliding_branches_from_different_sent_by_values() {
        let mut manager = TransactionManager::new();
        let key_a = TransactionKey::from_request(&request_from("a.example.com", Some(5060)))
            .expect("transaction key");
        let key_b = TransactionKey::from_request(&request_from("b.example.com", Some(5060)))
            .expect("transaction key");

        manager.insert(key_a.clone(), TransactionType::ServerInvite);
        manager.insert(key_b.clone(), TransactionType::ServerInvite);

        assert_eq!(manager.len(), 2);
        assert!(manager.find(&key_a).is_some());
        assert!(manager.find(&key_b).is_some());
    }
}
