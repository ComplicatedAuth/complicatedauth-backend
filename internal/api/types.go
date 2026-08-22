package api

import "time"

type Tenant struct {
	UID  string `json:"uid"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}
type TenantMember struct {
	UID           string    `json:"uid"`
	Email         string    `json:"email"`
	DisplayName   string    `json:"display_name"`
	Role          string    `json:"role"`
	Status        string    `json:"status"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
}
type ConsoleSession struct {
	Tenant                  Tenant       `json:"tenant"`
	Member                  TenantMember `json:"member"`
	AuthenticationAssurance string       `json:"authentication_assurance"`
	ExpiresAt               time.Time    `json:"expires_at"`
}

type TenantMemberLoginAttempt struct {
	UID          string    `json:"uid"`
	ClientSecret string    `json:"client_secret,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type TenantMemberLoginProgress struct {
	Status                  string    `json:"status"`
	CredentialSetupRequired bool      `json:"credential_setup_required"`
	ExpiresAt               time.Time `json:"expires_at"`
}

type TenantMemberWebAuthnCredential struct {
	UID        string     `json:"uid"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	Attested   bool       `json:"attested"`
	Version    int64      `json:"version"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type TenantInvitation struct {
	UID        string     `json:"uid"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type TenantMemberSession struct {
	UID                     string    `json:"uid"`
	Current                 bool      `json:"current"`
	AuthenticationAssurance string    `json:"authentication_assurance"`
	CreatedAt               time.Time `json:"created_at"`
	LastSeenAt              time.Time `json:"last_seen_at"`
	ExpiresAt               time.Time `json:"expires_at"`
}

type OAuthApplication struct {
	UID             string    `json:"uid"`
	Name            string    `json:"name"`
	ClientID        string    `json:"client_id"`
	ApplicationType string    `json:"application_type"`
	Status          string    `json:"status"`
	Version         int64     `json:"version"`
	RedirectURIs    []string  `json:"redirect_uris"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type OAuthClientSecret struct {
	UID        string     `json:"uid"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	Secret     string     `json:"secret,omitempty"`
}

type OAuthAuthorizationRequest struct {
	ApplicationUID           string                    `json:"application_uid"`
	ApplicationName          string                    `json:"application_name"`
	ClientID                 string                    `json:"client_id"`
	RedirectURI              string                    `json:"redirect_uri"`
	Scopes                   []string                  `json:"scopes"`
	ScopeDetails             []OAuthAuthorizationScope `json:"scope_details"`
	ResourceServerUID        *string                   `json:"resource_server_uid,omitempty"`
	ResourceServerName       *string                   `json:"resource_server_name,omitempty"`
	ResourceServerIdentifier *string                   `json:"resource_server_identifier,omitempty"`
	ExpiresAt                time.Time                 `json:"expires_at"`
}

type OAuthAuthorizationScope struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

type OAuthConsent struct {
	UID                      string     `json:"uid"`
	ApplicationUID           string     `json:"application_uid"`
	ApplicationName          string     `json:"application_name"`
	ClientID                 string     `json:"client_id"`
	Scopes                   []string   `json:"scopes"`
	ResourceServerUID        *string    `json:"resource_server_uid,omitempty"`
	ResourceServerName       *string    `json:"resource_server_name,omitempty"`
	ResourceServerIdentifier *string    `json:"resource_server_identifier,omitempty"`
	Status                   string     `json:"status"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
	RevokedAt                *time.Time `json:"revoked_at,omitempty"`
}

type ResourceServer struct {
	UID           string    `json:"uid"`
	Name          string    `json:"name"`
	Identifier    string    `json:"identifier"`
	Status        string    `json:"status"`
	Version       int64     `json:"version"`
	PolicyVersion int64     `json:"policy_version"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type ResourceServerScope struct {
	UID         string    `json:"uid"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	Version     int64     `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type OAuthApplicationGrant struct {
	UID                      string    `json:"uid"`
	ApplicationUID           string    `json:"application_uid"`
	ResourceServerUID        string    `json:"resource_server_uid"`
	ResourceServerName       string    `json:"resource_server_name"`
	ResourceServerIdentifier string    `json:"resource_server_identifier"`
	Status                   string    `json:"status"`
	Version                  int64     `json:"version"`
	Scopes                   []string  `json:"scopes"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}

type OAuthAuthorizationPrincipal struct {
	Type    string `json:"type"`
	Subject string `json:"subject"`
}

type AuthorizationResource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type AuthorizationDecision struct {
	Allowed                  bool                        `json:"allowed"`
	Principal                OAuthAuthorizationPrincipal `json:"principal"`
	TenantUID                string                      `json:"tenant_uid"`
	ResourceServerUID        string                      `json:"resource_server_uid"`
	ResourceServerIdentifier string                      `json:"resource_server_identifier"`
	Resource                 AuthorizationResource       `json:"resource"`
	Operation                string                      `json:"operation"`
	Capabilities             []string                    `json:"capabilities"`
	PolicyVersion            string                      `json:"policy_version"`
	ValidUntil               time.Time                   `json:"valid_until"`
	DenialReason             *string                     `json:"denial_reason"`
}

type Origin struct {
	UID       string    `json:"uid"`
	Origin    string    `json:"origin"`
	CreatedAt time.Time `json:"created_at"`
}
type Project struct {
	UID                 string    `json:"uid"`
	Name                string    `json:"name"`
	Environment         string    `json:"environment"`
	Status              string    `json:"status"`
	RPID                string    `json:"rp_id"`
	RPName              string    `json:"rp_name"`
	RPIDLocked          bool      `json:"rp_id_locked"`
	Origins             []Origin  `json:"origins"`
	OriginCount         int       `json:"origin_count"`
	UserCount           int       `json:"user_count"`
	ServiceAccountCount int       `json:"service_account_count"`
	CreatedAt           time.Time `json:"created_at"`
}
type ProjectUser struct {
	UID           string    `json:"uid"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Status        string    `json:"status"`
	PasskeyCount  int       `json:"passkey_count"`
	CreatedAt     time.Time `json:"created_at"`
}
type AuditEvent struct {
	UID        string         `json:"uid"`
	Action     string         `json:"action"`
	ActorType  string         `json:"actor_type"`
	ActorUID   *string        `json:"actor_uid"`
	TargetType *string        `json:"target_type"`
	TargetUID  *string        `json:"target_uid"`
	Metadata   map[string]any `json:"metadata"`
	CreatedAt  time.Time      `json:"created_at"`
}
