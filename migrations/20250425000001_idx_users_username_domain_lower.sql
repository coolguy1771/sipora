-- Speeds up get_user_sip_digest_ha1 (lower(username), lower(domain), partial WHERE).
CREATE INDEX IF NOT EXISTS idx_users_username_domain_lower
    ON users (lower(username), lower(domain))
    WHERE enabled = true AND sip_digest_ha1 IS NOT NULL;
