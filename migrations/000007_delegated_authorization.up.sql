CREATE TABLE resource_servers (
    uid uuid PRIMARY KEY,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    identifier text NOT NULL CHECK (length(identifier) BETWEEN 1 AND 2048),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    policy_version bigint NOT NULL DEFAULT 1 CHECK (policy_version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    UNIQUE (tenant_uid, identifier)
);
CREATE INDEX resource_servers_tenant_created_idx
    ON resource_servers(tenant_uid, created_at DESC, uid DESC)
    WHERE deleted_at IS NULL;

CREATE TABLE resource_server_scopes (
    uid uuid PRIMARY KEY,
    resource_server_uid uuid NOT NULL REFERENCES resource_servers(uid) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    UNIQUE (resource_server_uid, name)
);
CREATE INDEX resource_server_scopes_server_created_idx
    ON resource_server_scopes(resource_server_uid, created_at DESC, uid DESC)
    WHERE deleted_at IS NULL;

CREATE TABLE oauth_application_grants (
    uid uuid PRIMARY KEY,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    application_uid uuid NOT NULL REFERENCES oauth_applications(uid) ON DELETE CASCADE,
    resource_server_uid uuid NOT NULL REFERENCES resource_servers(uid) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);
CREATE UNIQUE INDEX oauth_application_grants_active_relationship_idx
    ON oauth_application_grants(application_uid, resource_server_uid)
    WHERE deleted_at IS NULL;
CREATE INDEX oauth_application_grants_tenant_created_idx
    ON oauth_application_grants(tenant_uid, created_at DESC, uid DESC)
    WHERE deleted_at IS NULL;

CREATE TABLE oauth_application_grant_scopes (
    grant_uid uuid NOT NULL REFERENCES oauth_application_grants(uid) ON DELETE CASCADE,
    scope_uid uuid NOT NULL REFERENCES resource_server_scopes(uid) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (grant_uid, scope_uid)
);

ALTER TABLE oauth_authorization_requests
    ADD COLUMN resource_server_uid uuid REFERENCES resource_servers(uid) ON DELETE CASCADE;
ALTER TABLE oauth_authorization_codes
    ADD COLUMN resource_server_uid uuid REFERENCES resource_servers(uid) ON DELETE CASCADE;
ALTER TABLE oauth_access_tokens
    ADD COLUMN resource_server_uid uuid REFERENCES resource_servers(uid) ON DELETE CASCADE;
CREATE INDEX oauth_access_tokens_resource_idx
    ON oauth_access_tokens(resource_server_uid, expires_at)
    WHERE revoked_at IS NULL AND resource_server_uid IS NOT NULL;

ALTER TABLE oauth_consents
    DROP CONSTRAINT oauth_consents_tenant_member_uid_application_uid_key,
    ADD COLUMN resource_server_uid uuid REFERENCES resource_servers(uid) ON DELETE CASCADE,
    ADD CONSTRAINT oauth_consents_member_application_resource_key
        UNIQUE NULLS NOT DISTINCT (tenant_member_uid, application_uid, resource_server_uid);
