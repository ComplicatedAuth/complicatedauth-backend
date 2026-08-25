ALTER TABLE project_service_accounts
    DROP CONSTRAINT project_service_accounts_scope_count_check,
    DROP CONSTRAINT project_service_accounts_scope_values_check,
    ADD CONSTRAINT project_service_accounts_scope_count_check
        CHECK (cardinality(scopes) BETWEEN 1 AND 7),
    ADD CONSTRAINT project_service_accounts_scope_values_check
        CHECK (scopes <@ ARRAY[
            'project_users.read',
            'project_users.write',
            'authentication.perform',
            'sessions.manage',
            'support_cases.read',
            'support_cases.write',
            'external_credentials.manage'
        ]::text[]);

ALTER TABLE project_service_credentials
    ADD COLUMN effective_scopes text[],
    ADD COLUMN external_subject text,
    ADD COLUMN external_integration_id text,
    ADD CONSTRAINT project_service_credentials_external_shape_check CHECK (
        (effective_scopes IS NULL AND external_subject IS NULL AND external_integration_id IS NULL)
        OR
        (
            effective_scopes IS NOT NULL
            AND external_subject IS NOT NULL
            AND external_integration_id IS NOT NULL
            AND
            cardinality(effective_scopes) BETWEEN 1 AND 6
            AND effective_scopes <@ ARRAY[
                'project_users.read',
                'project_users.write',
                'authentication.perform',
                'sessions.manage',
                'support_cases.read',
                'support_cases.write'
            ]::text[]
            AND length(external_subject) BETWEEN 1 AND 200
            AND length(external_integration_id) BETWEEN 1 AND 200
        )
    );

CREATE INDEX project_service_credentials_external_active_idx
    ON project_service_credentials(service_account_uid, external_subject, external_integration_id, created_at DESC)
    WHERE status = 'active' AND external_subject IS NOT NULL;
