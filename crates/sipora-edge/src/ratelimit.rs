use sipora_core::config::RateLimitConfig;
use sipora_core::redis_keys;

#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimitConfig,
}

#[derive(Debug)]
pub struct ThrottleResult {
    pub allowed: bool,
    pub current_count: u64,
    pub limit: u32,
    pub retry_after: Option<u64>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self { config }
    }

    pub fn limit_for_method(&self, method: &str) -> u32 {
        match method.to_uppercase().as_str() {
            "REGISTER" => self.config.register_rate,
            "INVITE" => self.config.invite_rate,
            _ => self.config.dialog_rate,
        }
    }

    pub fn rate_key(&self, ip: &str, method: &str) -> String {
        redis_keys::ratelimit_key(ip, method)
    }

    pub fn block_key(&self, ip: &str) -> String {
        redis_keys::block_key(ip)
    }

    pub fn violation_key(&self, ip: &str) -> String {
        redis_keys::violation_count_key(ip)
    }

    pub fn block_window_s(&self) -> u64 {
        self.config.block_window_s
    }

    pub fn block_threshold(&self) -> u32 {
        self.config.block_threshold
    }

    pub fn block_cooldown_s(&self) -> u64 {
        self.config.block_cooldown_s
    }

    pub fn lua_increment() -> &'static str {
        redis_keys::LUA_RATELIMIT_INCREMENT
    }

    pub fn lua_violation_check() -> &'static str {
        redis_keys::LUA_VIOLATION_CHECK_BLOCK
    }

    pub fn evaluate(&self, method: &str, current_count: u64) -> ThrottleResult {
        let limit = self.limit_for_method(method);
        let allowed = current_count <= limit as u64;
        let retry_after = if allowed {
            None
        } else {
            Some(self.config.block_cooldown_s)
        };
        ThrottleResult {
            allowed,
            current_count,
            limit,
            retry_after,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sipora_core::config::RateLimitConfig;

    fn test_config() -> RateLimitConfig {
        RateLimitConfig {
            register_rate: 20,
            invite_rate: 10,
            dialog_rate: 100,
            block_threshold: 5,
            block_window_s: 60,
            block_cooldown_s: 300,
        }
    }

    #[test]
    fn test_limit_for_method() {
        let rl = RateLimiter::new(test_config());
        assert_eq!(rl.limit_for_method("REGISTER"), 20);
        assert_eq!(rl.limit_for_method("INVITE"), 10);
        assert_eq!(rl.limit_for_method("BYE"), 100);
    }

    #[test]
    fn test_evaluate_allowed() {
        let rl = RateLimiter::new(test_config());
        let result = rl.evaluate("REGISTER", 15);
        assert!(result.allowed);
        assert!(result.retry_after.is_none());
    }

    #[test]
    fn test_evaluate_throttled() {
        let rl = RateLimiter::new(test_config());
        let result = rl.evaluate("REGISTER", 25);
        assert!(!result.allowed);
        assert_eq!(result.retry_after, Some(300));
    }
}
