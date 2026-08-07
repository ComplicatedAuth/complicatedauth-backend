CREATE TYPE project_environment AS ENUM ('sandbox', 'production');
CREATE TYPE resource_status AS ENUM ('active', 'disabled');
CREATE TYPE api_key_status AS ENUM ('active', 'revoked');
CREATE TYPE ceremony_type AS ENUM ('registration', 'authentication');
CREATE TYPE audit_actor_type AS ENUM ('tenant_member', 'project_user', 'api_key', 'system');

CREATE TABLE tenants (
    uid uuid PRIMARY KEY,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    slug text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenant_members (
    uid uuid PRIMARY KEY,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    email text NOT NULL,
    email_normalized text NOT NULL UNIQUE,
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
    role text NOT NULL CHECK (role = 'owner'),
    password_hash text NOT NULL,
    status resource_status NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenant_member_sessions (
    uid uuid PRIMARY KEY,
    tenant_member_uid uuid NOT NULL REFERENCES tenant_members(uid) ON DELETE CASCADE,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    session_secret_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE INDEX tenant_member_sessions_member_idx ON tenant_member_sessions(tenant_member_uid);

CREATE TABLE projects (
    uid uuid PRIMARY KEY,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    environment project_environment NOT NULL,
    status resource_status NOT NULL DEFAULT 'active',
    rp_id text NOT NULL,
    rp_name text NOT NULL CHECK (length(rp_name) BETWEEN 1 AND 120),
    rp_id_locked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX projects_tenant_created_idx ON projects(tenant_uid, created_at DESC, uid DESC);

CREATE TABLE project_origins (
    uid uuid PRIMARY KEY,
    project_uid uuid NOT NULL REFERENCES projects(uid) ON DELETE CASCADE,
    origin text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(project_uid, origin)
);

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

CREATE TABLE project_users (
    uid uuid PRIMARY KEY,
    project_uid uuid NOT NULL REFERENCES projects(uid) ON DELETE CASCADE,
    email text NOT NULL,
    email_normalized text NOT NULL,
    email_verified_at timestamptz,
    status resource_status NOT NULL DEFAULT 'active',
    password_hash text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(project_uid, email_normalized)
);
CREATE INDEX project_users_project_created_idx ON project_users(project_uid, created_at DESC, uid DESC);

CREATE TABLE project_user_sessions (
    uid uuid PRIMARY KEY,
    project_uid uuid NOT NULL REFERENCES projects(uid) ON DELETE CASCADE,
    project_user_uid uuid NOT NULL REFERENCES project_users(uid) ON DELETE CASCADE,
    session_secret_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE INDEX project_user_sessions_user_idx ON project_user_sessions(project_user_uid);

CREATE TABLE webauthn_credentials (
    uid uuid PRIMARY KEY,
    project_uid uuid NOT NULL REFERENCES projects(uid) ON DELETE CASCADE,
    project_user_uid uuid NOT NULL REFERENCES project_users(uid) ON DELETE CASCADE,
    credential_id bytea NOT NULL,
    credential_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(project_uid, credential_id)
);
CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials(project_uid, project_user_uid);

CREATE TABLE webauthn_ceremonies (
    uid uuid PRIMARY KEY,
    project_uid uuid NOT NULL REFERENCES projects(uid) ON DELETE CASCADE,
    project_user_uid uuid REFERENCES project_users(uid) ON DELETE CASCADE,
    ceremony_type ceremony_type NOT NULL,
    session_data jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX webauthn_ceremonies_expiry_idx ON webauthn_ceremonies(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE audit_events (
    uid uuid PRIMARY KEY,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    project_uid uuid REFERENCES projects(uid) ON DELETE CASCADE,
    actor_type audit_actor_type NOT NULL,
    actor_uid uuid,
    action text NOT NULL,
    target_type text,
    target_uid uuid,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    source_ip inet,
    user_agent text,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_tenant_created_idx ON audit_events(tenant_uid, created_at DESC, uid DESC);
CREATE INDEX audit_events_project_created_idx ON audit_events(project_uid, created_at DESC, uid DESC);
