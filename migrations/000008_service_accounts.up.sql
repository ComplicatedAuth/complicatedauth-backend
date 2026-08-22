CREATE TABLE project_service_accounts (
    uid uuid PRIMARY KEY,
    project_uid uuid NOT NULL REFERENCES projects(uid) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    status resource_status NOT NULL DEFAULT 'active',
    scopes text[] NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by_member_uid uuid REFERENCES tenant_members(uid) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    deleted_at timestamptz,
    CHECK (cardinality(scopes) BETWEEN 1 AND 4),
    CHECK (scopes <@ ARRAY[
        'project_users.read',
        'project_users.write',
        'authentication.perform',
        'sessions.manage'
    ]::text[])
);
CREATE INDEX project_service_accounts_project_created_idx
    ON project_service_accounts(project_uid, created_at DESC, uid DESC)
    WHERE deleted_at IS NULL;

CREATE TABLE project_service_credentials (
    uid uuid PRIMARY KEY,
    service_account_uid uuid NOT NULL REFERENCES project_service_accounts(uid) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    prefix text NOT NULL UNIQUE,
    fingerprint text NOT NULL UNIQUE,
    secret_hash bytea NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_by_member_uid uuid REFERENCES tenant_members(uid) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    revoked_by_member_uid uuid REFERENCES tenant_members(uid) ON DELETE SET NULL,
    revocation_reason text CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 200),
    CHECK (expires_at > created_at)
);
CREATE INDEX project_service_credentials_account_created_idx
    ON project_service_credentials(service_account_uid, created_at DESC, uid DESC);
CREATE INDEX project_service_credentials_active_expiry_idx
    ON project_service_credentials(expires_at)
    WHERE status = 'active';

ALTER TABLE audit_events
    ALTER COLUMN actor_type TYPE text USING actor_type::text;
DROP TYPE audit_actor_type;
ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_actor_type_check
    CHECK (actor_type IN ('tenant_member', 'project_user', 'service_account', 'system'));

DROP TABLE project_api_keys;
DROP TYPE api_key_status;
