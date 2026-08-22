CREATE TABLE oauth_applications (
    uid uuid PRIMARY KEY,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    client_id text NOT NULL UNIQUE CHECK (length(client_id) BETWEEN 20 AND 200),
    application_type text NOT NULL CHECK (application_type IN ('public', 'confidential')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);
CREATE INDEX oauth_applications_tenant_created_idx
    ON oauth_applications(tenant_uid, created_at DESC, uid DESC)
    WHERE deleted_at IS NULL;

CREATE TABLE oauth_application_redirect_uris (
    uid uuid PRIMARY KEY,
    application_uid uuid NOT NULL REFERENCES oauth_applications(uid) ON DELETE CASCADE,
    redirect_uri text NOT NULL CHECK (length(redirect_uri) BETWEEN 1 AND 2048),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(application_uid, redirect_uri)
);

CREATE TABLE oauth_client_secrets (
    uid uuid PRIMARY KEY,
    application_uid uuid NOT NULL REFERENCES oauth_applications(uid) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    prefix text NOT NULL UNIQUE CHECK (length(prefix) BETWEEN 8 AND 80),
    secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX oauth_client_secrets_application_idx
    ON oauth_client_secrets(application_uid, created_at DESC, uid DESC);

CREATE TABLE oauth_signing_keys (
    uid uuid PRIMARY KEY,
    kid text NOT NULL UNIQUE,
    algorithm text NOT NULL CHECK (algorithm = 'RS256'),
    status text NOT NULL CHECK (status IN ('active', 'retiring', 'retired')),
    public_jwk jsonb NOT NULL,
    private_key_ciphertext bytea NOT NULL,
    private_key_nonce bytea NOT NULL CHECK (octet_length(private_key_nonce) = 12),
    encryption_key_version text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz NOT NULL DEFAULT now(),
    publish_until timestamptz,
    retired_at timestamptz
);
CREATE UNIQUE INDEX oauth_signing_keys_one_active_idx
    ON oauth_signing_keys(status) WHERE status = 'active';
CREATE INDEX oauth_signing_keys_publication_idx
    ON oauth_signing_keys(status, publish_until);

CREATE TABLE oauth_authorization_requests (
    uid uuid PRIMARY KEY,
    request_secret_hash bytea NOT NULL UNIQUE CHECK (octet_length(request_secret_hash) = 32),
    application_uid uuid NOT NULL REFERENCES oauth_applications(uid) ON DELETE CASCADE,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    scopes text[] NOT NULL,
    state text NOT NULL CHECK (length(state) BETWEEN 1 AND 1024),
    nonce text CHECK (nonce IS NULL OR length(nonce) BETWEEN 1 AND 255),
    code_challenge text NOT NULL CHECK (length(code_challenge) BETWEEN 43 AND 128),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
    tenant_member_uid uuid REFERENCES tenant_members(uid) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    resolved_at timestamptz
);
CREATE INDEX oauth_authorization_requests_expiry_idx
    ON oauth_authorization_requests(expires_at) WHERE status = 'pending';

CREATE TABLE oauth_authorization_codes (
    uid uuid PRIMARY KEY,
    code_hash bytea NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    application_uid uuid NOT NULL REFERENCES oauth_applications(uid) ON DELETE CASCADE,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    tenant_member_uid uuid NOT NULL REFERENCES tenant_members(uid) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    scopes text[] NOT NULL,
    nonce text,
    code_challenge text NOT NULL,
    auth_time timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX oauth_authorization_codes_expiry_idx
    ON oauth_authorization_codes(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE oauth_consents (
    uid uuid PRIMARY KEY,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    tenant_member_uid uuid NOT NULL REFERENCES tenant_members(uid) ON DELETE CASCADE,
    application_uid uuid NOT NULL REFERENCES oauth_applications(uid) ON DELETE CASCADE,
    scopes text[] NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    UNIQUE(tenant_member_uid, application_uid)
);
CREATE INDEX oauth_consents_member_created_idx
    ON oauth_consents(tenant_member_uid, created_at DESC, uid DESC);

CREATE TABLE oauth_subjects (
    uid uuid PRIMARY KEY,
    application_uid uuid NOT NULL REFERENCES oauth_applications(uid) ON DELETE CASCADE,
    tenant_member_uid uuid NOT NULL REFERENCES tenant_members(uid) ON DELETE CASCADE,
    subject text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(application_uid, tenant_member_uid)
);

CREATE TABLE oauth_access_tokens (
    uid uuid PRIMARY KEY,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    jti uuid NOT NULL UNIQUE,
    application_uid uuid NOT NULL REFERENCES oauth_applications(uid) ON DELETE CASCADE,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    tenant_member_uid uuid NOT NULL REFERENCES tenant_members(uid) ON DELETE CASCADE,
    subject text NOT NULL,
    scopes text[] NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX oauth_access_tokens_expiry_idx
    ON oauth_access_tokens(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX oauth_access_tokens_member_idx
    ON oauth_access_tokens(tenant_member_uid, created_at DESC, uid DESC);
