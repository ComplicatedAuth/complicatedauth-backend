CREATE TABLE rate_limit_buckets (
    policy text NOT NULL CHECK (policy ~ '^[a-z][a-z0-9_.]{0,127}$'),
    key_hash bytea NOT NULL CHECK (octet_length(key_hash) = 32),
    request_count integer NOT NULL CHECK (request_count > 0),
    window_started_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (policy, key_hash)
);
CREATE INDEX rate_limit_buckets_expiry_idx ON rate_limit_buckets(expires_at);
