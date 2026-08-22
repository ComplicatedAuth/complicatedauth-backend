ALTER TABLE oauth_consents
    DROP CONSTRAINT oauth_consents_member_application_resource_key,
    DROP COLUMN resource_server_uid,
    ADD CONSTRAINT oauth_consents_tenant_member_uid_application_uid_key
        UNIQUE (tenant_member_uid, application_uid);

DROP INDEX oauth_access_tokens_resource_idx;
ALTER TABLE oauth_access_tokens DROP COLUMN resource_server_uid;
ALTER TABLE oauth_authorization_codes DROP COLUMN resource_server_uid;
ALTER TABLE oauth_authorization_requests DROP COLUMN resource_server_uid;

DROP TABLE oauth_application_grant_scopes;
DROP TABLE oauth_application_grants;
DROP TABLE resource_server_scopes;
DROP TABLE resource_servers;
