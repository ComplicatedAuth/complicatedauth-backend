ALTER TABLE project_service_accounts
    DROP CONSTRAINT project_service_accounts_scopes_check,
    DROP CONSTRAINT project_service_accounts_scopes_check1,
    ADD CONSTRAINT project_service_accounts_scope_count_check
        CHECK (cardinality(scopes) BETWEEN 1 AND 6),
    ADD CONSTRAINT project_service_accounts_scope_values_check
        CHECK (scopes <@ ARRAY[
            'project_users.read',
            'project_users.write',
            'authentication.perform',
            'sessions.manage',
            'support_cases.read',
            'support_cases.write'
        ]::text[]);

CREATE TABLE support_cases (
    uid uuid PRIMARY KEY,
    case_reference text NOT NULL UNIQUE CHECK (case_reference ~ '^SC-[A-Z0-9]{12}$'),
    tenant_uid uuid NOT NULL REFERENCES tenants(uid) ON DELETE CASCADE,
    project_uid uuid REFERENCES projects(uid) ON DELETE CASCADE,
    category text NOT NULL CHECK (category IN ('bug', 'feedback', 'question')),
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'waiting_for_customer', 'resolved', 'closed')),
    priority text NOT NULL DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    reporter_type text NOT NULL CHECK (reporter_type IN ('tenant_member', 'project_user', 'service_account')),
    reporter_uid uuid NOT NULL,
    assignee_member_uid uuid REFERENCES tenant_members(uid) ON DELETE SET NULL,
    subject_key_version text NOT NULL,
    subject_nonce bytea NOT NULL,
    subject_ciphertext bytea NOT NULL,
    diagnostic_consent boolean NOT NULL DEFAULT false,
    diagnostics_key_version text,
    diagnostics_nonce bytea,
    diagnostics_ciphertext bytea,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    message_count integer NOT NULL DEFAULT 1 CHECK (message_count > 0),
    attachment_count integer NOT NULL DEFAULT 0 CHECK (attachment_count >= 0),
    attachment_bytes bigint NOT NULL DEFAULT 0 CHECK (attachment_bytes >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_message_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    closed_at timestamptz,
    retention_until timestamptz,
    CHECK (
        (diagnostics_key_version IS NULL AND diagnostics_nonce IS NULL AND diagnostics_ciphertext IS NULL)
        OR
        (diagnostic_consent AND diagnostics_key_version IS NOT NULL AND diagnostics_nonce IS NOT NULL AND diagnostics_ciphertext IS NOT NULL)
    )
);
CREATE INDEX support_cases_tenant_updated_idx
    ON support_cases(tenant_uid, updated_at DESC, uid DESC);
CREATE INDEX support_cases_project_updated_idx
    ON support_cases(project_uid, updated_at DESC, uid DESC)
    WHERE project_uid IS NOT NULL;
CREATE INDEX support_cases_inbox_idx
    ON support_cases(tenant_uid, status, priority, updated_at DESC, uid DESC);
CREATE INDEX support_cases_retention_idx
    ON support_cases(retention_until)
    WHERE retention_until IS NOT NULL;

CREATE TABLE support_case_messages (
    uid uuid PRIMARY KEY,
    case_uid uuid NOT NULL REFERENCES support_cases(uid) ON DELETE CASCADE,
    author_type text NOT NULL CHECK (author_type IN ('tenant_member', 'project_user', 'service_account', 'system')),
    author_uid uuid,
    visibility text NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'internal')),
    body_key_version text NOT NULL,
    body_nonce bytea NOT NULL,
    body_ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX support_case_messages_case_created_idx
    ON support_case_messages(case_uid, created_at ASC, uid ASC);

CREATE TABLE support_case_attachments (
    uid uuid PRIMARY KEY,
    case_uid uuid NOT NULL REFERENCES support_cases(uid) ON DELETE CASCADE,
    uploaded_by_type text NOT NULL CHECK (uploaded_by_type IN ('tenant_member', 'project_user', 'service_account')),
    uploaded_by_uid uuid NOT NULL,
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 100),
    byte_count integer NOT NULL CHECK (byte_count BETWEEN 1 AND 5242880),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    metadata_key_version text NOT NULL,
    metadata_nonce bytea NOT NULL,
    metadata_ciphertext bytea NOT NULL,
    content_key_version text NOT NULL,
    content_nonce bytea NOT NULL,
    content_ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX support_case_attachments_case_created_idx
    ON support_case_attachments(case_uid, created_at DESC, uid DESC);

CREATE TABLE support_case_external_references (
    uid uuid PRIMARY KEY,
    case_uid uuid NOT NULL REFERENCES support_cases(uid) ON DELETE CASCADE,
    provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9._-]{0,62}$'),
    external_id_hash bytea NOT NULL CHECK (octet_length(external_id_hash) = 32),
    payload_key_version text NOT NULL,
    payload_nonce bytea NOT NULL,
    payload_ciphertext bytea NOT NULL,
    created_by_member_uid uuid REFERENCES tenant_members(uid) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (case_uid, provider, external_id_hash)
);
CREATE INDEX support_case_external_references_case_created_idx
    ON support_case_external_references(case_uid, created_at DESC, uid DESC);

CREATE TABLE support_case_events (
    uid uuid PRIMARY KEY,
    case_uid uuid NOT NULL REFERENCES support_cases(uid) ON DELETE CASCADE,
    event_type text NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9_.]{0,127}$'),
    actor_type text NOT NULL CHECK (actor_type IN ('tenant_member', 'project_user', 'service_account', 'system')),
    actor_uid uuid,
    visibility text NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'internal')),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX support_case_events_case_created_idx
    ON support_case_events(case_uid, created_at ASC, uid ASC);

CREATE FUNCTION reject_support_case_event_update()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'support case events are immutable';
END;
$$;
CREATE TRIGGER support_case_events_immutable
    BEFORE UPDATE ON support_case_events
    FOR EACH ROW EXECUTE FUNCTION reject_support_case_event_update();
