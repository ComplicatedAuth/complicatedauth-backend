DROP TABLE IF EXISTS biometric_credentials;
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS attested, DROP COLUMN IF EXISTS credential_kind;
ALTER TABLE webauthn_ceremonies DROP COLUMN IF EXISTS credential_kind, DROP COLUMN IF EXISTS login_attempt_uid;
DROP TABLE IF EXISTS project_user_login_attempts;
