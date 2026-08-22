ALTER TABLE tenant_members
    DROP CONSTRAINT tenant_members_role_check,
    ADD CONSTRAINT tenant_members_role_check
        CHECK (role IN ('owner', 'admin', 'developer', 'support', 'viewer')),
    ADD COLUMN email_verified_at timestamptz;

CREATE INDEX tenant_members_tenant_created_idx
    ON tenant_members(tenant_uid, created_at DESC, uid DESC);

CREATE TABLE tenant_invitations (
    uid uuid PRIMARY KEY,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    email text NOT NULL,
    email_normalized text NOT NULL,
    role text NOT NULL CHECK (role IN ('admin', 'developer', 'support', 'viewer')),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked')),
    acceptance_token_hash bytea NOT NULL UNIQUE CHECK (octet_length(acceptance_token_hash) = 32),
    created_by_member_uid uuid REFERENCES tenant_members(uid) ON DELETE SET NULL,
    accepted_by_member_uid uuid REFERENCES tenant_members(uid) ON DELETE SET NULL,
    revoked_by_member_uid uuid REFERENCES tenant_members(uid) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    revoked_at timestamptz,
    CHECK (
        (status = 'pending' AND accepted_at IS NULL AND revoked_at IS NULL)
        OR (status = 'accepted' AND accepted_at IS NOT NULL AND accepted_by_member_uid IS NOT NULL AND revoked_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL AND accepted_at IS NULL)
    )
);
CREATE UNIQUE INDEX tenant_invitations_pending_email_idx
    ON tenant_invitations(tenant_uid, email_normalized)
    WHERE status = 'pending';
CREATE INDEX tenant_invitations_tenant_created_idx
    ON tenant_invitations(tenant_uid, created_at DESC, uid DESC);
CREATE INDEX tenant_invitations_expiry_idx
    ON tenant_invitations(expires_at)
    WHERE status = 'pending';
