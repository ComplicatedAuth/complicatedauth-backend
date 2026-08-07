BEGIN;
DROP TABLE IF EXISTS audit_events, webauthn_ceremonies, webauthn_credentials, project_user_sessions, project_users, project_api_keys, project_origins, projects, tenant_member_sessions, tenant_members, tenants CASCADE;
DROP TYPE IF EXISTS audit_actor_type, ceremony_type, api_key_status, resource_status, project_environment;
COMMIT;
