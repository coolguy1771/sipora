CREATE TABLE redirect_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    from_uri VARCHAR(512) NOT NULL,
    to_uri VARCHAR(512) NOT NULL,
    rule_type VARCHAR(50) NOT NULL DEFAULT 'temporary',
    q_value REAL NOT NULL DEFAULT 1.0,
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (rule_type IN ('permanent', 'temporary'))
);

CREATE INDEX idx_redirect_rules_from_uri ON redirect_rules (from_uri);
CREATE INDEX idx_redirect_rules_validity ON redirect_rules (valid_from, valid_until);
