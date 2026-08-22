CREATE TYPE api_key_status AS ENUM ('active', 'revoked');
CREATE TABLE project_api_keys (
    uid uuid PRIMARY KEY,
    project_uid uuid NOT NULL REFERENCES projects(uid) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    prefix text NOT NULL UNIQUE,
    secret_hash bytea NOT NULL,
    status api_key_status NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX project_api_keys_project_idx ON project_api_keys(project_uid, created_at DESC);

ALTER TABLE audit_events DROP CONSTRAINT audit_events_actor_type_check;
UPDATE audit_events SET actor_type = 'system', actor_uid = NULL WHERE actor_type = 'service_account';
CREATE TYPE audit_actor_type AS ENUM ('tenant_member', 'project_user', 'api_key', 'system');
ALTER TABLE audit_events
    ALTER COLUMN actor_type TYPE audit_actor_type
    USING actor_type::audit_actor_type;

DROP TABLE project_service_credentials;
DROP TABLE project_service_accounts;
