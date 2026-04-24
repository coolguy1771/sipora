-- SIP HTTP Digest HA1 (MD5) for REGISTER verification in sipora-proxy.
-- Stored at provisioning time alongside Argon2; cannot be derived from Argon2 alone.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS sip_digest_ha1 TEXT;

COMMENT ON COLUMN users.sip_digest_ha1 IS
    'MD5 hex HA1 = MD5(username:realm:password) for SIP digest; realm equals users.domain';
