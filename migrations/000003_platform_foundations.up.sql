CREATE TABLE idempotency_records (
    principal_type text NOT NULL CHECK (principal_type ~ '^[a-z][a-z0-9_]{0,62}$'),
    principal_uid text NOT NULL CHECK (length(principal_uid) BETWEEN 1 AND 255),
    operation text NOT NULL CHECK (operation ~ '^[a-z][a-z0-9_.]{0,127}$'),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 255),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    state text NOT NULL CHECK (state IN ('processing', 'completed')),
    lease_uid uuid NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    response_status integer CHECK (response_status BETWEEN 100 AND 599),
    response_headers jsonb,
    response_body bytea,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (principal_type, principal_uid, operation, idempotency_key),
    CHECK (
        (state = 'processing' AND response_status IS NULL AND response_headers IS NULL AND response_body IS NULL AND completed_at IS NULL)
        OR
        (state = 'completed' AND response_status IS NOT NULL AND response_headers IS NOT NULL AND response_body IS NOT NULL AND completed_at IS NOT NULL)
    )
);
CREATE INDEX idempotency_records_expiry_idx ON idempotency_records(expires_at);

CREATE TABLE background_jobs (
    uid uuid PRIMARY KEY,
    queue text NOT NULL CHECK (queue ~ '^[a-z][a-z0-9_]{0,62}$'),
    job_type text NOT NULL CHECK (job_type ~ '^[a-z][a-z0-9_.]{0,127}$'),
    deduplication_key text,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL DEFAULT now(),
    lease_uid uuid,
    lease_expires_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE(queue, deduplication_key)
);
CREATE INDEX background_jobs_available_idx
    ON background_jobs(queue, available_at, created_at)
    WHERE status IN ('pending', 'failed');
