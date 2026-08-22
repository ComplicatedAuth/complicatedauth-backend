DROP TABLE IF EXISTS tenant_member_webauthn_ceremonies;
DROP TABLE IF EXISTS tenant_member_webauthn_credentials;
DROP TABLE IF EXISTS tenant_member_login_attempts;
ALTER TABLE tenant_member_sessions
    DROP CONSTRAINT IF EXISTS tenant_member_sessions_assurance_state_check,
    DROP COLUMN IF EXISTS strongly_authenticated_at,
    DROP COLUMN IF EXISTS authentication_assurance;
