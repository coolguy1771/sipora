-- SIP HTTP Digest HA1 (SHA-256) for RFC 7616 REGISTER verification in sipora-proxy.
-- Stored at provisioning time alongside Argon2 and MD5 HA1; cannot be derived from Argon2 alone.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS sip_digest_ha1_sha256 TEXT;

COMMENT ON COLUMN users.sip_digest_ha1_sha256 IS
    'SHA-256 hex HA1 = SHA-256(username:realm:password) for SIP digest; realm equals users.domain';

-- Speeds up SHA-256 credential lookup (lower(username), lower(domain), partial WHERE).
CREATE INDEX IF NOT EXISTS idx_users_username_domain_lower_sha256
    ON users (lower(username), lower(domain))
    WHERE enabled = true AND sip_digest_ha1_sha256 IS NOT NULL;
