use rand::Rng;
use sipora_core::redis_keys;

pub fn generate_nonce(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub struct NonceStore {
    ttl_s: u64,
}

impl NonceStore {
    pub fn new(ttl_s: u64) -> Self {
        Self { ttl_s }
    }

    pub fn key(&self, domain: &str, nonce: &str) -> String {
        redis_keys::nonce_key(domain, nonce)
    }

    pub fn ttl(&self) -> u64 {
        self.ttl_s
    }

    pub fn lua_check_delete() -> &'static str {
        redis_keys::LUA_NONCE_CHECK_DELETE
    }
}
