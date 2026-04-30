pub const LOCATION_KEY_PREFIX: &str = "location";
pub const NONCE_KEY_PREFIX: &str = "nonce";
pub const RATELIMIT_KEY_PREFIX: &str = "ratelimit";
pub const SESSION_KEY_PREFIX: &str = "session";

/// One-time REGISTER digest challenge nonce (see sipora-proxy).
pub fn register_digest_nonce_key(nonce: &str) -> String {
    format!("register_digest:{nonce}")
}

/// Last accepted nonce-count for a nonce (RFC 7616 nc replay prevention).
pub fn register_digest_nonce_nc_key(nonce: &str) -> String {
    format!("register_digest:{nonce}:nc")
}

/// Completed REGISTER (Call-ID + CSeq) for UDP idempotent 200 retransmits.
pub fn register_transaction_ok_key(call_id: &str, cseq: u32) -> String {
    format!("register_tx_ok:{call_id}:{cseq}")
}

/// Short-lived lock so concurrent REGISTERs with the same Call-ID + CSeq do not double-upsert.
pub fn register_commit_lock_key(call_id: &str, cseq: u32) -> String {
    format!("register_lock:{call_id}:{cseq}")
}

/// KEYS[1] = lock key, ARGV[1] = token set at acquire. Deletes only if value matches.
pub const LUA_REGISTER_COMMIT_LOCK_DELETE_IF_MATCH: &str = r#"
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
else
  return 0
end
"#;

pub fn location_key(domain: &str, user: &str) -> String {
    format!("{LOCATION_KEY_PREFIX}:{domain}:{user}")
}

/// Maps pub-GRUU `gr` token fragment to registered username at this domain.
pub fn pub_gruu_index_key(domain: &str, gr_token: &str) -> String {
    format!("gruu:{domain}:{gr_token}")
}

pub fn subscription_key(event: &str, domain: &str, user: &str, call_id: &str) -> String {
    format!("sub:{event}:{domain}:{user}:{call_id}")
}

pub fn subscription_aor_index(event: &str, domain: &str, user: &str) -> String {
    format!("subidx:{event}:{domain}:{user}")
}

/// Monotonic NOTIFY CSeq per dialog (`Call-ID`).
pub fn subscription_notify_cseq_key(call_id: &str) -> String {
    format!("subnotifycseq:{call_id}")
}

pub fn presence_doc_key(domain: &str, user: &str) -> String {
    format!("presence:{domain}:{user}")
}

pub fn presence_etag_key(domain: &str, user: &str) -> String {
    format!("presence_etag:{domain}:{user}")
}

pub fn push_pending_key(call_id: &str) -> String {
    format!("push_pending:{call_id}")
}

/// FIFO of Call-IDs with stashed INVITE bodies for push replay after REGISTER.
pub fn push_pending_index_key(domain: &str, user: &str) -> String {
    format!("push_pending_idx:{domain}:{user}")
}

/// Serialized REFER dialog state for the proxy (JSON blob).
pub fn refer_state_key(call_id: &str) -> String {
    format!("refer_state:{call_id}")
}

pub fn nonce_key(domain: &str, nonce: &str) -> String {
    format!("{NONCE_KEY_PREFIX}:{domain}:{nonce}")
}

pub fn ratelimit_key(ip: &str, method: &str) -> String {
    format!("{RATELIMIT_KEY_PREFIX}:{ip}:{method}")
}

pub fn session_key(call_id: &str) -> String {
    format!("{SESSION_KEY_PREFIX}:{call_id}")
}

pub fn block_key(ip: &str) -> String {
    format!("{RATELIMIT_KEY_PREFIX}:blocked:{ip}")
}

pub fn violation_count_key(ip: &str) -> String {
    format!("{RATELIMIT_KEY_PREFIX}:violations:{ip}")
}

/// Atomic nonce check-and-delete.
/// KEYS[1] = nonce key
/// Returns 1 if nonce existed (valid), 0 if not (reused or expired).
pub const LUA_NONCE_CHECK_DELETE: &str = r#"
local val = redis.call('GET', KEYS[1])
if val then
    redis.call('DEL', KEYS[1])
    return 1
else
    return 0
end
"#;

/// Atomic rate-limit increment with window TTL.
/// KEYS[1] = ratelimit key
/// ARGV[1] = window TTL in seconds
/// ARGV[2] = max allowed count
/// Returns current count. If count exceeds max, caller should throttle.
pub const LUA_RATELIMIT_INCREMENT: &str = r#"
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"#;

/// Atomic violation counter with auto-block.
/// KEYS[1] = violation count key
/// KEYS[2] = block key
/// ARGV[1] = block window in seconds
/// ARGV[2] = block threshold
/// ARGV[3] = block cooldown in seconds
/// Returns 1 if IP is now blocked, 0 if not.
pub const LUA_VIOLATION_CHECK_BLOCK: &str = r#"
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
if count >= tonumber(ARGV[2]) then
    redis.call('SETEX', KEYS[2], ARGV[3], '1')
    redis.call('DEL', KEYS[1])
    return 1
end
return 0
"#;
