DROP INDEX background_jobs_available_idx;

ALTER TABLE background_jobs
    DROP CONSTRAINT background_jobs_state_check,
    DROP CONSTRAINT background_jobs_status_check;

UPDATE background_jobs
SET status = 'failed',
    lease_uid = NULL,
    lease_expires_at = NULL,
    completed_at = NULL
WHERE status = 'dead_lettered';

ALTER TABLE background_jobs
    DROP COLUMN dead_lettered_at,
    DROP COLUMN updated_at,
    DROP COLUMN max_attempts,
    ADD CONSTRAINT background_jobs_status_check
        CHECK (status IN ('pending', 'running', 'completed', 'failed'));

CREATE INDEX background_jobs_available_idx
    ON background_jobs(queue, available_at, created_at)
    WHERE status IN ('pending', 'failed');
