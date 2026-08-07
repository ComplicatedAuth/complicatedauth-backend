package api

import "time"

type Tenant struct {
	UID  string `json:"uid"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}
type TenantMember struct {
	UID         string `json:"uid"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}
type ConsoleSession struct {
	Tenant    Tenant       `json:"tenant"`
	Member    TenantMember `json:"member"`
	ExpiresAt time.Time    `json:"expires_at"`
}

type Origin struct {
	UID       string    `json:"uid"`
	Origin    string    `json:"origin"`
	CreatedAt time.Time `json:"created_at"`
}
type Project struct {
	UID         string    `json:"uid"`
	Name        string    `json:"name"`
	Environment string    `json:"environment"`
	Status      string    `json:"status"`
	RPID        string    `json:"rp_id"`
	RPName      string    `json:"rp_name"`
	RPIDLocked  bool      `json:"rp_id_locked"`
	Origins     []Origin  `json:"origins"`
	OriginCount int       `json:"origin_count"`
	UserCount   int       `json:"user_count"`
	APIKeyCount int       `json:"api_key_count"`
	CreatedAt   time.Time `json:"created_at"`
}
type APIKey struct {
	UID        string     `json:"uid"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	Secret     string     `json:"secret,omitempty"`
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
