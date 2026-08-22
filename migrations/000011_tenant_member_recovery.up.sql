CREATE TABLE tenant_member_email_verifications (
    uid uuid PRIMARY KEY,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    tenant_member_uid uuid NOT NULL REFERENCES tenant_members(uid) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR revoked_at IS NULL)
);
CREATE INDEX tenant_member_email_verifications_member_idx
    ON tenant_member_email_verifications(tenant_member_uid, created_at DESC);
CREATE INDEX tenant_member_email_verifications_expiry_idx
    ON tenant_member_email_verifications(expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE TABLE tenant_member_password_resets (
    uid uuid PRIMARY KEY,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    tenant_member_uid uuid NOT NULL REFERENCES tenant_members(uid) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR revoked_at IS NULL)
);
CREATE INDEX tenant_member_password_resets_member_idx
    ON tenant_member_password_resets(tenant_member_uid, created_at DESC);
CREATE INDEX tenant_member_password_resets_expiry_idx
    ON tenant_member_password_resets(expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE TABLE email_deliveries (
    uid uuid PRIMARY KEY,
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    template text NOT NULL CHECK (template IN ('tenant_email_verification', 'tenant_password_reset', 'tenant_invitation')),
    recipient_key_version text NOT NULL,
    recipient_nonce bytea NOT NULL,
    recipient_ciphertext bytea NOT NULL,
    payload_key_version text NOT NULL,
    payload_nonce bytea NOT NULL,
    payload_ciphertext bytea NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered')),
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz
);
CREATE INDEX email_deliveries_tenant_created_idx
    ON email_deliveries(tenant_uid, created_at DESC, uid DESC);
