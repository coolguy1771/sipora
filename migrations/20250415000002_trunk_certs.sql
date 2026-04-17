CREATE TABLE trunk_certs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    trunk_id VARCHAR(255) NOT NULL UNIQUE,
    pem TEXT NOT NULL,
    fingerprint VARCHAR(128) NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_trunk_certs_trunk_id ON trunk_certs (trunk_id);
CREATE INDEX idx_trunk_certs_fingerprint ON trunk_certs (fingerprint);
