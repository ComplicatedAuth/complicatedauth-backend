DROP INDEX project_service_credentials_external_active_idx;

ALTER TABLE project_service_credentials
    DROP CONSTRAINT project_service_credentials_external_shape_check,
    DROP COLUMN external_integration_id,
    DROP COLUMN external_subject,
    DROP COLUMN effective_scopes;

ALTER TABLE project_service_accounts
    DROP CONSTRAINT project_service_accounts_scope_count_check,
    DROP CONSTRAINT project_service_accounts_scope_values_check,
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
