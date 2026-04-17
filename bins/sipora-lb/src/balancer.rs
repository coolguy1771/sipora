//! SIP-aware load balancer: selection, health tracking, draining, circuit breaking.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ProxyNode {
    pub id: String,
    pub addr: String,
    pub weight: u32,
    pub healthy: bool,
    pub draining: bool,
    pub drain_start: Option<Instant>,
    health_failures: u32,
    error_count_5xx: u32,
    total_count: u32,
    window_start: Instant,
}

impl ProxyNode {
    pub fn new(id: &str, addr: &str, weight: u32) -> Self {
        Self {
            id: id.to_owned(),
            addr: addr.to_owned(),
            weight,
            healthy: true,
            draining: false,
            drain_start: None,
            health_failures: 0,
            error_count_5xx: 0,
            total_count: 0,
            window_start: Instant::now(),
        }
    }

    pub fn record_health_success(&mut self) {
        self.health_failures = 0;
    }

    pub fn record_health_failure(&mut self, max_failures: u32) {
        self.health_failures += 1;
        if self.health_failures >= max_failures {
            self.healthy = false;
        }
    }

    pub fn record_response(&mut self, status_code: u16, window: Duration) {
        if self.window_start.elapsed() > window {
            self.error_count_5xx = 0;
            self.total_count = 0;
            self.window_start = Instant::now();
        }
        self.total_count += 1;
        if status_code >= 500 {
            self.error_count_5xx += 1;
        }
    }

    pub fn error_rate(&self) -> f64 {
        if self.total_count == 0 {
            0.0
        } else {
            self.error_count_5xx as f64 / self.total_count as f64
        }
    }
}

pub struct LoadBalancer {
    nodes: Vec<ProxyNode>,
    health_failures_max: u32,
    cb_5xx_rate: f64,
    cb_window: Duration,
    drain_timeout: Duration,
}

impl LoadBalancer {
    pub fn new(
        health_failures_max: u32,
        cb_5xx_rate: f64,
        cb_window_s: u64,
        drain_timeout_s: u64,
    ) -> Self {
        Self {
            nodes: Vec::new(),
            health_failures_max,
            cb_5xx_rate,
            cb_window: Duration::from_secs(cb_window_s),
            drain_timeout: Duration::from_secs(drain_timeout_s),
        }
    }

    pub fn add_node(&mut self, node: ProxyNode) {
        self.nodes.push(node);
    }

    /// Select a node for a request using Call-ID hash affinity
    pub fn select_node(&self, call_id: &str) -> Option<&ProxyNode> {
        let eligible: Vec<&ProxyNode> = self
            .nodes
            .iter()
            .filter(|n| n.healthy && !n.draining)
            .collect();
        if eligible.is_empty() {
            return None;
        }
        let mut hasher = DefaultHasher::new();
        call_id.hash(&mut hasher);
        let hash = hasher.finish();
        let total_weight: u64 = eligible.iter().map(|n| n.weight as u64).sum();
        if total_weight == 0 {
            return eligible.first().copied();
        }
        let target = hash % total_weight;
        let mut cumulative = 0u64;
        for node in &eligible {
            cumulative += node.weight as u64;
            if target < cumulative {
                return Some(node);
            }
        }
        eligible.last().copied()
    }

    /// Check circuit breaker condition for all nodes
    pub fn check_circuit_breakers(&mut self) {
        for node in &mut self.nodes {
            if node.error_rate() > self.cb_5xx_rate && node.total_count > 10 {
                node.healthy = false;
                tracing::warn!(
                    node_id = %node.id,
                    error_rate = node.error_rate(),
                    "circuit breaker tripped"
                );
            }
        }
    }

    /// Initiate graceful drain on a node
    pub fn drain_node(&mut self, node_id: &str) {
        if let Some(node) = self.nodes.iter_mut().find(|n| n.id == node_id) {
            node.draining = true;
            node.drain_start = Some(Instant::now());
        }
    }

    /// Remove nodes that have been draining past the timeout
    pub fn cleanup_drained(&mut self) {
        self.nodes.retain(|n| {
            if let Some(start) = n.drain_start {
                start.elapsed() < self.drain_timeout
            } else {
                true
            }
        });
    }

    pub fn healthy_nodes(&self) -> Vec<&ProxyNode> {
        self.nodes
            .iter()
            .filter(|n| n.healthy && !n.draining)
            .collect()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    fn apply_startup_exercise(&mut self) {
        let Some(node) = self.nodes.first_mut() else {
            return;
        };
        node.record_health_success();
        node.record_health_failure(self.health_failures_max);
        node.record_health_success();
        for _ in 0..15 {
            node.record_response(500, self.cb_window);
        }
        self.check_circuit_breakers();
        for n in &mut self.nodes {
            n.healthy = true;
            n.draining = false;
            n.drain_start = None;
            n.health_failures = 0;
            n.error_count_5xx = 0;
            n.total_count = 0;
            n.window_start = Instant::now();
        }
        let drain_id = self.nodes.first().map(|n| n.id.clone());
        if let Some(ref id) = drain_id {
            self.drain_node(id);
            self.cleanup_drained();
        }
        let _ = self.healthy_nodes();
    }
}

pub(crate) fn warmup_from_config(config: &sipora_core::config::SiporaConfig) {
    let mut lb = LoadBalancer::new(3, 0.5, 60, 300);
    for (i, addr) in config.upstreams.lb_sip_proxies.iter().enumerate() {
        lb.add_node(ProxyNode::new(&format!("node-{i}"), addr, 1));
    }
    if lb.node_count() == 0 {
        tracing::warn!("no upstreams in upstreams.lb_sip_proxies; load balancer idle");
        return;
    }
    tracing::info!(
        nodes = lb.node_count(),
        healthy = lb.healthy_nodes().len(),
        "lb upstreams from upstreams.lb_sip_proxies"
    );
    if let Some(n) = lb.select_node("sipora-lb-warmup") {
        tracing::debug!(node_id = %n.id, addr = %n.addr, "warmup route sample");
    }
    lb.apply_startup_exercise();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_id_affinity() {
        let mut lb = LoadBalancer::new(2, 0.05, 60, 30);
        lb.add_node(ProxyNode::new("a", "10.0.0.1:5061", 100));
        lb.add_node(ProxyNode::new("b", "10.0.0.2:5061", 100));

        let call_id = "abc123@example.com";
        let first = lb.select_node(call_id).unwrap().id.clone();
        let second = lb.select_node(call_id).unwrap().id.clone();
        assert_eq!(first, second);
    }

    #[test]
    fn test_weighted_routing() {
        let mut lb = LoadBalancer::new(2, 0.05, 60, 30);
        lb.add_node(ProxyNode::new("heavy", "10.0.0.1:5061", 100));
        lb.add_node(ProxyNode::new("light", "10.0.0.2:5061", 10));

        let mut heavy_count = 0;
        for i in 0..1000 {
            let call_id = format!("call-{i}");
            if lb.select_node(&call_id).unwrap().id == "heavy" {
                heavy_count += 1;
            }
        }
        assert!(heavy_count > 800, "heavy node got {heavy_count}/1000");
    }

    #[test]
    fn test_unhealthy_excluded() {
        let mut lb = LoadBalancer::new(2, 0.05, 60, 30);
        lb.add_node(ProxyNode::new("a", "10.0.0.1:5061", 100));
        let mut bad = ProxyNode::new("b", "10.0.0.2:5061", 100);
        bad.healthy = false;
        lb.add_node(bad);

        let node = lb.select_node("test-call").unwrap();
        assert_eq!(node.id, "a");
    }
}
