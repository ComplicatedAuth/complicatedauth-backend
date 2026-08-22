ALTER TABLE tenant_member_sessions
    ADD COLUMN authentication_assurance text NOT NULL DEFAULT 'bootstrap'
        CHECK (authentication_assurance IN ('bootstrap', 'strong')),
    ADD COLUMN strongly_authenticated_at timestamptz,
    ADD CONSTRAINT tenant_member_sessions_assurance_state_check
        CHECK (
            (authentication_assurance='bootstrap' AND strongly_authenticated_at IS NULL)
            OR
            (authentication_assurance='strong' AND strongly_authenticated_at IS NOT NULL)
        );

CREATE TABLE tenant_member_login_attempts (
    uid uuid PRIMARY KEY,
    tenant_member_uid uuid REFERENCES tenant_members(uid) ON DELETE CASCADE,
    client_secret_hash bytea NOT NULL UNIQUE CHECK (octet_length(client_secret_hash) = 32),
    identity_key_hash bytea NOT NULL CHECK (octet_length(identity_key_hash) = 32),
    password_verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > created_at)
);
CREATE INDEX tenant_member_login_attempts_expiry_idx
    ON tenant_member_login_attempts(expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE tenant_member_webauthn_credentials (
    uid uuid PRIMARY KEY,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    tenant_member_uid uuid NOT NULL REFERENCES tenant_members(uid) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    credential_json jsonb NOT NULL,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    credential_kind text NOT NULL CHECK (credential_kind IN ('passkey', 'security_key')),
    attested boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);
CREATE UNIQUE INDEX tenant_member_webauthn_credentials_member_name_idx
    ON tenant_member_webauthn_credentials(tenant_member_uid, lower(name));
CREATE INDEX tenant_member_webauthn_credentials_member_created_idx
    ON tenant_member_webauthn_credentials(tenant_member_uid, created_at DESC, uid DESC);

CREATE TABLE tenant_member_webauthn_ceremonies (
    uid uuid PRIMARY KEY,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    tenant_member_uid uuid NOT NULL REFERENCES tenant_members(uid) ON DELETE CASCADE,
    login_attempt_uid uuid REFERENCES tenant_member_login_attempts(uid) ON DELETE CASCADE,
    tenant_member_session_uid uuid REFERENCES tenant_member_sessions(uid) ON DELETE CASCADE,
    ceremony_type text NOT NULL CHECK (ceremony_type IN ('registration', 'authentication')),
    credential_kind text NOT NULL CHECK (credential_kind IN ('passkey', 'security_key', 'hybrid')),
    credential_name text CHECK (credential_name IS NULL OR length(credential_name) BETWEEN 1 AND 100),
    session_data jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK ((login_attempt_uid IS NULL) <> (tenant_member_session_uid IS NULL)),
    CHECK (ceremony_type='registration' OR credential_name IS NULL),
    CHECK (ceremony_type='registration' OR login_attempt_uid IS NOT NULL)
);
CREATE INDEX tenant_member_webauthn_ceremonies_expiry_idx
    ON tenant_member_webauthn_ceremonies(expires_at)
    WHERE consumed_at IS NULL;
