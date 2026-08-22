DROP TABLE IF EXISTS tenant_invitations;
DROP INDEX IF EXISTS tenant_members_tenant_created_idx;
ALTER TABLE tenant_members
    DROP COLUMN IF EXISTS email_verified_at,
    DROP CONSTRAINT IF EXISTS tenant_members_role_check,
    ADD CONSTRAINT tenant_members_role_check CHECK (role = 'owner');
