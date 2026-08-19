CREATE TABLE project_user_login_attempts (
    uid uuid PRIMARY KEY,
    project_uid uuid NOT NULL REFERENCES projects(uid) ON DELETE CASCADE,
    project_user_uid uuid REFERENCES project_users(uid) ON DELETE CASCADE,
    login_secret_hash bytea NOT NULL UNIQUE,
    password_verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX project_user_login_attempts_active_idx
    ON project_user_login_attempts(project_uid, expires_at)
    WHERE consumed_at IS NULL;

ALTER TABLE webauthn_ceremonies
    ADD COLUMN login_attempt_uid uuid REFERENCES project_user_login_attempts(uid) ON DELETE CASCADE,
    ADD COLUMN credential_kind text NOT NULL DEFAULT 'passkey'
        CHECK (credential_kind IN ('passkey', 'security_key', 'hybrid'));

ALTER TABLE webauthn_credentials
    ADD COLUMN credential_kind text NOT NULL DEFAULT 'passkey'
        CHECK (credential_kind IN ('passkey', 'security_key')),
    ADD COLUMN attested boolean NOT NULL DEFAULT false;

CREATE TABLE biometric_credentials (
    uid uuid PRIMARY KEY,
    project_uid uuid NOT NULL REFERENCES projects(uid) ON DELETE CASCADE,
    project_user_uid uuid NOT NULL REFERENCES project_users(uid) ON DELETE CASCADE,
    provider_template_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(project_uid, project_user_uid),
    UNIQUE(project_uid, provider_template_id)
);
