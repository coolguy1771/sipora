CREATE TABLE cdr (
    id UUID NOT NULL DEFAULT uuid_generate_v4(),
    correlation_id UUID NOT NULL,
    leg CHAR(1) NOT NULL CHECK (leg IN ('A', 'B')),
    from_uri VARCHAR(512) NOT NULL,
    to_uri VARCHAR(512) NOT NULL,
    setup_at TIMESTAMPTZ NOT NULL,
    answered_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    duration_s INTEGER,
    result_code SMALLINT NOT NULL,
    codec VARCHAR(50),
    rtp_loss_pct REAL,
    rtp_jitter_ms REAL,
    srtp_cipher VARCHAR(100),
    media_ip INET,
    proxy_node VARCHAR(255),
    hash_chain TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, setup_at)
) PARTITION BY RANGE (setup_at);

CREATE INDEX idx_cdr_correlation_id ON cdr (correlation_id);
CREATE INDEX idx_cdr_from_uri ON cdr (from_uri);
CREATE INDEX idx_cdr_to_uri ON cdr (to_uri);
CREATE INDEX idx_cdr_setup_at ON cdr (setup_at);

-- Create initial partitions for current and next month
DO $$
DECLARE
    current_start DATE := date_trunc('month', CURRENT_DATE);
    next_start DATE := date_trunc('month', CURRENT_DATE + INTERVAL '1 month');
    after_next DATE := date_trunc('month', CURRENT_DATE + INTERVAL '2 months');
BEGIN
    EXECUTE format(
        'CREATE TABLE cdr_%s PARTITION OF cdr FOR VALUES FROM (%L) TO (%L)',
        to_char(current_start, 'YYYY_MM'),
        current_start,
        next_start
    );
    EXECUTE format(
        'CREATE TABLE cdr_%s PARTITION OF cdr FOR VALUES FROM (%L) TO (%L)',
        to_char(next_start, 'YYYY_MM'),
        next_start,
        after_next
    );
END $$;
