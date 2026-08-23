package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	security "github.com/complicatedauth/complicatedauth-backend/internal/auth"
)

const oauthResourcePrincipalKey contextKey = "oauthResourcePrincipal"

type oauthResourcePrincipal struct {
	TenantUID                string
	MemberUID                string
	Subject                  string
	ApplicationUID           string
	ResourceServerUID        string
	ResourceServerIdentifier string
	Scopes                   []string
	PolicyVersion            int64
	ExpiresAt                time.Time
}

func (s *Server) oauthResourceAuthorized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if value == "" || len(value) > 8192 {
			writeInvalidBearer(w)
			return
		}
		var p oauthResourcePrincipal
		err := s.db.QueryRow(r.Context(), `
			SELECT t.tenant_uid,t.tenant_member_uid,t.subject,t.application_uid,t.resource_server_uid,
			       rs.identifier,t.scopes,rs.policy_version,t.expires_at
			FROM oauth_access_tokens t
			JOIN tenant_members m ON m.uid=t.tenant_member_uid
			JOIN oauth_applications a ON a.uid=t.application_uid
			JOIN resource_servers rs ON rs.uid=t.resource_server_uid
			JOIN oauth_application_grants g ON g.application_uid=t.application_uid
			 AND g.resource_server_uid=t.resource_server_uid AND g.deleted_at IS NULL
			WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND t.expires_at>now()
			  AND m.status='active' AND a.status='active' AND a.deleted_at IS NULL
			  AND rs.status='active' AND rs.deleted_at IS NULL AND g.status='active'
		`, security.SessionHash(value)).Scan(
			&p.TenantUID, &p.MemberUID, &p.Subject, &p.ApplicationUID,
			&p.ResourceServerUID, &p.ResourceServerIdentifier, &p.Scopes,
			&p.PolicyVersion, &p.ExpiresAt,
		)
		if err != nil {
			writeInvalidBearer(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), oauthResourcePrincipalKey, p)))
	})
}

func mustOAuthResourcePrincipal(r *http.Request) oauthResourcePrincipal {
	return r.Context().Value(oauthResourcePrincipalKey).(oauthResourcePrincipal)
}

func (s *Server) createAuthorizationDecision(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Resource  AuthorizationResource `json:"resource"`
		Operation string                `json:"operation"`
		Context   map[string]any        `json:"context"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Resource.Type = strings.TrimSpace(in.Resource.Type)
	in.Resource.ID = strings.TrimSpace(in.Resource.ID)
	in.Operation = strings.TrimSpace(in.Operation)
	if in.Resource.Type == "" || len(in.Resource.Type) > 120 || in.Resource.ID == "" || len(in.Resource.ID) > 500 || !delegatedScopePattern.MatchString(in.Operation) {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "resource.type, resource.id, and a valid lowercase operation are required")
		return
	}
	contextBytes, err := json.Marshal(in.Context)
	if err != nil || len(contextBytes) > 8<<10 {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "context must be a JSON object no larger than 8 KiB")
		return
	}
	p := mustOAuthResourcePrincipal(r)
	capabilities, err := s.currentOAuthCapabilities(r.Context(), p)
	if err != nil {
		fail(w, r, http.StatusServiceUnavailable, "authorization_unavailable", "authorization decision is temporarily unavailable")
		return
	}
	var operationExists bool
	err = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM resource_server_scopes WHERE resource_server_uid=$1 AND name=$2 AND status='active' AND deleted_at IS NULL)`, p.ResourceServerUID, in.Operation).Scan(&operationExists)
	if err != nil {
		fail(w, r, http.StatusServiceUnavailable, "authorization_unavailable", "authorization decision is temporarily unavailable")
		return
	}
	allowed := operationExists && scopeContains(capabilities, in.Operation)
	var denialReason *string
	if !allowed {
		reason := "missing_capability"
		if !operationExists {
			reason = "unknown_operation"
		}
		denialReason = &reason
	}
	decision := AuthorizationDecision{
		Allowed:                  allowed,
		Principal:                OAuthAuthorizationPrincipal{Type: "tenant_member", Subject: p.Subject},
		TenantUID:                p.TenantUID,
		ResourceServerUID:        p.ResourceServerUID,
		ResourceServerIdentifier: p.ResourceServerIdentifier,
		Resource:                 in.Resource,
		Operation:                in.Operation,
		Capabilities:             capabilities,
		PolicyVersion:            fmt.Sprintf("scope-v1:%d", p.PolicyVersion),
		ValidUntil:               p.ExpiresAt,
		DenialReason:             denialReason,
	}
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, decision)
}

func (s *Server) currentOAuthCapabilities(ctx context.Context, p oauthResourcePrincipal) ([]string, error) {
	rows, err := s.db.Query(ctx, `
		SELECT scope.name
		FROM resource_server_scopes scope
		JOIN resource_servers resource ON resource.uid=scope.resource_server_uid
		JOIN oauth_application_grant_scopes assignment ON assignment.scope_uid=scope.uid
		JOIN oauth_application_grants grant_record ON grant_record.uid=assignment.grant_uid
		JOIN oauth_applications application ON application.uid=grant_record.application_uid
		JOIN tenant_members member ON member.uid=$3
		WHERE scope.resource_server_uid=$1 AND scope.status='active' AND scope.deleted_at IS NULL
		  AND scope.name=ANY($2::text[])
		  AND resource.status='active' AND resource.deleted_at IS NULL
		  AND grant_record.application_uid=$4 AND grant_record.resource_server_uid=$1
		  AND grant_record.status='active' AND grant_record.deleted_at IS NULL
		  AND application.status='active' AND application.deleted_at IS NULL
		  AND member.status='active'
		ORDER BY scope.name
	`, p.ResourceServerUID, p.Scopes, p.MemberUID, p.ApplicationUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	capabilities := []string{}
	for rows.Next() {
		var capability string
		if err = rows.Scan(&capability); err != nil {
			return nil, err
		}
		capabilities = append(capabilities, capability)
	}
	return capabilities, rows.Err()
}
