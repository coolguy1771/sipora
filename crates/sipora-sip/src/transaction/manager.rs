use super::TransactionKey;
use crate::types::message::Response;
use std::collections::HashMap;
use tokio::sync::mpsc;

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
    pub response_tx: mpsc::Sender<Response>,
}

pub struct TransactionManager {
    transactions: HashMap<String, TransactionEntry>,
}

impl TransactionManager {
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        key: TransactionKey,
        tx_type: TransactionType,
        response_tx: mpsc::Sender<Response>,
    ) {
        let lookup_key = format!("{}:{}", key.branch, key.method);
        let entry = TransactionEntry {
            key,
            tx_type,
            response_tx,
        };
        self.transactions.insert(lookup_key, entry);
    }

    pub fn find(&self, branch: &str, method: &str) -> Option<&TransactionEntry> {
        let lookup_key = format!("{branch}:{method}");
        self.transactions.get(&lookup_key)
    }

    pub fn remove(&mut self, branch: &str, method: &str) -> Option<TransactionEntry> {
        let lookup_key = format!("{branch}:{method}");
        self.transactions.remove(&lookup_key)
    }

    pub fn has_transaction(&self, branch: &str, method: &str) -> bool {
        self.find(branch, method).is_some()
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
