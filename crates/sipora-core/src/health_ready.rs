use crate::health::HealthCheck;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Ready flag for Kubernetes-style `/ready` probes.
#[derive(Clone)]
pub struct AtomicReady(pub Arc<AtomicBool>);

impl Default for AtomicReady {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicReady {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn set_ready(&self, v: bool) {
        self.0.store(v, Ordering::SeqCst);
    }
}

impl HealthCheck for AtomicReady {
    fn is_ready(&self) -> impl std::future::Future<Output = bool> + Send {
        let a = self.0.clone();
        async move { a.load(Ordering::SeqCst) }
    }
}
