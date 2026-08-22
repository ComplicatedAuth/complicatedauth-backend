DROP TRIGGER support_case_events_immutable ON support_case_events;
DROP FUNCTION reject_support_case_event_update();
DROP TABLE support_case_events;
DROP TABLE support_case_external_references;
DROP TABLE support_case_attachments;
DROP TABLE support_case_messages;
DROP TABLE support_cases;

ALTER TABLE project_service_accounts
    DROP CONSTRAINT project_service_accounts_scope_count_check,
    DROP CONSTRAINT project_service_accounts_scope_values_check,
    ADD CONSTRAINT project_service_accounts_scopes_check
        CHECK (cardinality(scopes) BETWEEN 1 AND 4),
    ADD CONSTRAINT project_service_accounts_scopes_check1
        CHECK (scopes <@ ARRAY[
            'project_users.read',
            'project_users.write',
            'authentication.perform',
            'sessions.manage'
        ]::text[]);
