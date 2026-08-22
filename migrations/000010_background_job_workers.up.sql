ALTER TABLE background_jobs
    DROP CONSTRAINT background_jobs_status_check;

UPDATE background_jobs
SET status = 'pending',
    lease_uid = NULL,
    lease_expires_at = NULL
WHERE status = 'failed';

ALTER TABLE background_jobs
    ADD COLUMN max_attempts integer NOT NULL DEFAULT 8 CHECK (max_attempts BETWEEN 1 AND 100),
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN dead_lettered_at timestamptz,
    ADD CONSTRAINT background_jobs_status_check
        CHECK (status IN ('pending', 'running', 'completed', 'dead_lettered')),
    ADD CONSTRAINT background_jobs_state_check
        CHECK (
            (status = 'pending' AND lease_uid IS NULL AND lease_expires_at IS NULL AND completed_at IS NULL AND dead_lettered_at IS NULL)
            OR
            (status = 'running' AND lease_uid IS NOT NULL AND lease_expires_at IS NOT NULL AND completed_at IS NULL AND dead_lettered_at IS NULL)
            OR
            (status = 'completed' AND lease_uid IS NULL AND lease_expires_at IS NULL AND completed_at IS NOT NULL AND dead_lettered_at IS NULL)
            OR
            (status = 'dead_lettered' AND lease_uid IS NULL AND lease_expires_at IS NULL AND completed_at IS NULL AND dead_lettered_at IS NOT NULL)
        );

DROP INDEX background_jobs_available_idx;
CREATE INDEX background_jobs_available_idx
    ON background_jobs(queue, available_at, created_at, uid)
    WHERE status IN ('pending', 'running');
