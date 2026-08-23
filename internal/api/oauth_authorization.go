package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	security "github.com/complicatedauth/complicatedauth-backend/internal/auth"
	"github.com/complicatedauth/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	pkceChallengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	pkceVerifierPattern  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

var oidcScopes = map[string]bool{"openid": true, "profile": true, "email": true}

type oauthResourceRecord struct {
	UID        string
	Name       string
	Identifier string
}

func (s *Server) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientID, redirectURI := query.Get("client_id"), query.Get("redirect_uri")
	var applicationUID, tenantUID string
	err := s.db.QueryRow(r.Context(), `
		SELECT a.uid,a.tenant_uid
		FROM oauth_applications a
		JOIN oauth_application_redirect_uris u ON u.application_uid=a.uid
		WHERE a.client_id=$1 AND a.status='active' AND a.deleted_at IS NULL AND u.redirect_uri=$2
	`, clientID, redirectURI).Scan(&applicationUID, &tenantUID)
	if err != nil {
		s.oauthAuthorizationPageError(w, http.StatusBadRequest, "invalid_request", "The client or exact redirect URI is invalid.")
		return
	}
	state := query.Get("state")
	keyHash := security.SecretHash(s.cfg.SecretHashKey, "oauth_authorize\x00"+clientID+"\x00"+s.clientIP(r))
	limit, limitErr := s.rateLimits.Take(r.Context(), "oauth_authorize", keyHash, 100, 15*time.Minute)
	if limitErr != nil {
		s.oauthAuthorizationRedirectError(w, r, redirectURI, state, "temporarily_unavailable", "Authorization is temporarily unavailable.")
		return
	}
	if !limit.Allowed {
		seconds := int64(limit.RetryAfter / time.Second)
		if limit.RetryAfter%time.Second != 0 {
			seconds++
		}
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
		s.oauthAuthorizationRedirectError(w, r, redirectURI, state, "temporarily_unavailable", "Too many authorization attempts; retry later.")
		return
	}
	if query.Get("response_type") != "code" {
		s.oauthAuthorizationRedirectError(w, r, redirectURI, state, "unsupported_response_type", "Only the authorization code response type is supported.")
		return
	}
	if state == "" || len(state) > 1024 {
		s.oauthAuthorizationRedirectError(w, r, redirectURI, "", "invalid_request", "state is required and must not exceed 1024 characters.")
		return
	}
	if responseMode := query.Get("response_mode"); responseMode != "" && responseMode != "query" {
		s.oauthAuthorizationRedirectError(w, r, redirectURI, state, "invalid_request", "Only query response mode is supported.")
		return
	}
	resourceIndicator := query.Get("resource")
	scopes, resourceServer, err := s.resolveAuthorizationScopes(r.Context(), s.db, tenantUID, applicationUID, query.Get("scope"), resourceIndicator)
	if err != nil {
		s.oauthAuthorizationRedirectError(w, r, redirectURI, state, "invalid_scope", err.Error())
		return
	}
	nonce := query.Get("nonce")
	if nonce == "" || len(nonce) > 255 {
		s.oauthAuthorizationRedirectError(w, r, redirectURI, state, "invalid_request", "nonce is required and must not exceed 255 characters.")
		return
	}
	challenge := query.Get("code_challenge")
	if query.Get("code_challenge_method") != "S256" || !pkceChallengePattern.MatchString(challenge) {
		s.oauthAuthorizationRedirectError(w, r, redirectURI, state, "invalid_request", "S256 PKCE with a valid code_challenge is required.")
		return
	}
	secret, err := security.RandomToken()
	if err != nil {
		s.oauthAuthorizationPageError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "Authorization is temporarily unavailable.")
		return
	}
	uid := uuid.NewString()
	requestToken := uid + "." + secret
	expiresAt := time.Now().Add(durationOr(s.cfg.OAuthAuthorizationTTL, 10*time.Minute))
	_, err = s.db.Exec(r.Context(), `
		INSERT INTO oauth_authorization_requests(
			uid,request_secret_hash,application_uid,tenant_uid,redirect_uri,scopes,
			state,nonce,code_challenge,expires_at,resource_server_uid
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, uid, security.SessionHash(requestToken), applicationUID, tenantUID, redirectURI, scopes, state, nonce, challenge, expiresAt, resourceServerUID(resourceServer))
	if err != nil {
		s.oauthAuthorizationPageError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "Authorization is temporarily unavailable.")
		return
	}
	destination, _ := url.Parse(s.cfg.ConsoleOrigin + "/oauth/authorize")
	destination.Fragment = "request=" + url.QueryEscape(requestToken)
	w.Header().Set("Location", destination.String())
	w.WriteHeader(http.StatusSeeOther)
}

func normalizeRequestedScopes(raw string) ([]string, []string, error) {
	values := strings.Fields(raw)
	if len(values) == 0 {
		return nil, nil, errors.New("scope must include openid")
	}
	seen := make(map[string]bool, len(values))
	custom := []string{}
	for _, value := range values {
		if seen[value] {
			return nil, nil, fmt.Errorf("scope %q is duplicated", value)
		}
		if !oidcScopes[value] {
			if !delegatedScopePattern.MatchString(value) || value == "offline_access" {
				return nil, nil, fmt.Errorf("scope %q is not supported", value)
			}
			custom = append(custom, value)
		}
		seen[value] = true
	}
	if !seen["openid"] {
		return nil, nil, errors.New("scope must include openid")
	}
	sort.Strings(values)
	sort.Strings(custom)
	return values, custom, nil
}

type oauthScopeQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Server) resolveAuthorizationScopes(ctx context.Context, queryer oauthScopeQueryer, tenantUID, applicationUID, raw, resourceIndicator string) ([]string, *oauthResourceRecord, error) {
	values, custom, err := normalizeRequestedScopes(raw)
	if err != nil {
		return nil, nil, err
	}
	if resourceIndicator == "" {
		if len(custom) > 0 {
			return nil, nil, errors.New("resource is required for delegated scopes")
		}
		return values, nil, nil
	}
	canonical, err := normalizeResourceIdentifier(resourceIndicator)
	if err != nil {
		return nil, nil, errors.New("resource must be an exact registered Resource Server identifier")
	}
	if len(custom) == 0 {
		return nil, nil, errors.New("at least one delegated scope is required when resource is supplied")
	}
	var resource oauthResourceRecord
	err = queryer.QueryRow(ctx, `
		SELECT r.uid,r.name,r.identifier
		FROM resource_servers r
		JOIN oauth_application_grants g ON g.resource_server_uid=r.uid
		WHERE r.tenant_uid=$1 AND r.identifier=$2 AND r.status='active' AND r.deleted_at IS NULL
		  AND g.application_uid=$3 AND g.status='active' AND g.deleted_at IS NULL
	`, tenantUID, canonical, applicationUID).Scan(&resource.UID, &resource.Name, &resource.Identifier)
	if err != nil {
		return nil, nil, errors.New("resource is not granted to this OAuth Application")
	}
	rows, err := queryer.Query(ctx, `
		SELECT s.name
		FROM oauth_application_grants g
		JOIN oauth_application_grant_scopes gs ON gs.grant_uid=g.uid
		JOIN resource_server_scopes s ON s.uid=gs.scope_uid
		WHERE g.application_uid=$1 AND g.resource_server_uid=$2 AND g.status='active' AND g.deleted_at IS NULL
		  AND s.status='active' AND s.deleted_at IS NULL AND s.name=ANY($3::text[])
	`, applicationUID, resource.UID, custom)
	if err != nil {
		return nil, nil, errors.New("delegated scopes could not be validated")
	}
	defer rows.Close()
	granted := map[string]bool{}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return nil, nil, errors.New("delegated scopes could not be validated")
		}
		granted[name] = true
	}
	for _, name := range custom {
		if !granted[name] {
			return nil, nil, fmt.Errorf("scope %q is not granted to this OAuth Application", name)
		}
	}
	return values, &resource, nil
}

func resourceServerUID(value *oauthResourceRecord) *string {
	if value == nil {
		return nil
	}
	return &value.UID
}

func (s *Server) oauthAuthorizationPageError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><meta charset="utf-8"><title>Authorization request rejected</title><main><h1>Authorization request rejected</h1><p>%s</p><p><code>%s</code></p></main></html>`, html.EscapeString(description), html.EscapeString(code))
}

func (s *Server) oauthAuthorizationRedirectError(w http.ResponseWriter, _ *http.Request, redirectURI, state, code, description string) {
	destination, err := url.Parse(redirectURI)
	if err != nil {
		s.oauthAuthorizationPageError(w, http.StatusBadRequest, code, description)
		return
	}
	query := destination.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	query.Set("iss", s.cfg.OAuthIssuer)
	destination.RawQuery = query.Encode()
	w.Header().Set("Location", destination.String())
	w.WriteHeader(http.StatusSeeOther)
}

func (s *Server) inspectOAuthAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RequestToken string `json:"request_token"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.RequestToken) < 40 || len(in.RequestToken) > 256 {
		fail(w, r, http.StatusUnauthorized, "invalid_authorization_request", "authorization request is invalid or expired")
		return
	}
	p := mustPrincipal(r)
	var result OAuthAuthorizationRequest
	var status string
	err := s.db.QueryRow(r.Context(), `
		SELECT a.uid,a.name,a.client_id,q.redirect_uri,q.scopes,r.uid,r.name,r.identifier,q.expires_at,q.status
		FROM oauth_authorization_requests q
		JOIN oauth_applications a ON a.uid=q.application_uid
		LEFT JOIN resource_servers r ON r.uid=q.resource_server_uid
		WHERE q.request_secret_hash=$1 AND q.tenant_uid=$2
		  AND a.status='active' AND a.deleted_at IS NULL
	`, security.SessionHash(in.RequestToken), p.TenantUID).Scan(
		&result.ApplicationUID, &result.ApplicationName, &result.ClientID,
		&result.RedirectURI, &result.Scopes, &result.ResourceServerUID,
		&result.ResourceServerName, &result.ResourceServerIdentifier,
		&result.ExpiresAt, &status,
	)
	if err != nil || status != "pending" || !result.ExpiresAt.After(time.Now()) {
		fail(w, r, http.StatusUnauthorized, "invalid_authorization_request", "authorization request is invalid or expired")
		return
	}
	result.ScopeDetails, err = s.oauthAuthorizationScopeDetails(r.Context(), result.Scopes, result.ResourceServerUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load authorization scope details")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) oauthAuthorizationScopeDetails(ctx context.Context, scopes []string, resourceServerUID *string) ([]OAuthAuthorizationScope, error) {
	core := map[string]OAuthAuthorizationScope{
		"openid":  {Name: "openid", DisplayName: "Identify you", Description: "Confirm your stable, pairwise identity for this application."},
		"profile": {Name: "profile", DisplayName: "View your profile", Description: "Share your display name."},
		"email":   {Name: "email", DisplayName: "View your email", Description: "Share your email address and verification status."},
	}
	details := make(map[string]OAuthAuthorizationScope, len(core))
	for name, detail := range core {
		details[name] = detail
	}
	if resourceServerUID != nil {
		rows, err := s.db.Query(ctx, `SELECT name,display_name,description FROM resource_server_scopes WHERE resource_server_uid=$1 AND name=ANY($2::text[]) AND status='active' AND deleted_at IS NULL`, *resourceServerUID, scopes)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var detail OAuthAuthorizationScope
			if err = rows.Scan(&detail.Name, &detail.DisplayName, &detail.Description); err != nil {
				return nil, err
			}
			details[detail.Name] = detail
		}
	}
	result := make([]OAuthAuthorizationScope, 0, len(scopes))
	for _, name := range scopes {
		detail, ok := details[name]
		if !ok {
			return nil, fmt.Errorf("scope %q is no longer available", name)
		}
		result = append(result, detail)
	}
	return result, nil
}

type oauthAuthorizationDecisionInput struct {
	RequestToken string `json:"request_token"`
	Decision     string `json:"decision"`
}

func (s *Server) decideOAuthAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	var in oauthAuthorizationDecisionInput
	if !decode(w, r, &in) {
		return
	}
	if (in.Decision != "approve" && in.Decision != "deny") || len(in.RequestToken) < 40 || len(in.RequestToken) > 256 {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "a valid request_token and approve or deny decision are required")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		fail(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required")
		return
	}
	p := mustPrincipal(r)
	requestTokenHash := security.SessionHash(in.RequestToken)
	canonical, _ := json.Marshal(struct {
		RequestTokenHash string `json:"request_token_hash"`
		Decision         string `json:"decision"`
	}{RequestTokenHash: base64.RawURLEncoding.EncodeToString(requestTokenHash), Decision: in.Decision})
	idemRequest := store.IdempotencyRequest{
		PrincipalType: "tenant_member", PrincipalUID: p.MemberUID,
		Operation: "oauth_authorization_requests.decide", Key: key,
		RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour,
	}
	claim, ok := s.beginIdempotentRequest(w, r, idemRequest)
	if !ok {
		return
	}

	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not resolve authorization request")
		return
	}
	defer tx.Rollback(r.Context())
	var requestUID, applicationUID, tenantUID, redirectURI, state, nonce, challenge, status string
	var resourceServerUID *string
	var scopes []string
	var expiresAt, authTime time.Time
	err = tx.QueryRow(r.Context(), `
		SELECT q.uid,q.application_uid,q.tenant_uid,q.redirect_uri,q.scopes,q.state,q.nonce,
		       q.code_challenge,q.status,q.expires_at,s.created_at,q.resource_server_uid
		FROM oauth_authorization_requests q
		JOIN oauth_applications a ON a.uid=q.application_uid
		JOIN tenant_member_sessions s ON s.uid=$3 AND s.tenant_member_uid=$4 AND s.revoked_at IS NULL
		WHERE q.request_secret_hash=$1 AND q.tenant_uid=$2
		  AND a.status='active' AND a.deleted_at IS NULL
		FOR UPDATE OF q
	`, requestTokenHash, p.TenantUID, p.SessionUID, p.MemberUID).Scan(
		&requestUID, &applicationUID, &tenantUID, &redirectURI, &scopes, &state, &nonce,
		&challenge, &status, &expiresAt, &authTime, &resourceServerUID,
	)
	if err != nil || status != "pending" || !expiresAt.After(time.Now()) {
		response := problemResponse(r, http.StatusConflict, "authorization_request_resolved", "authorization request is invalid, expired, or already resolved")
		if completeErr := s.idempotency.CompleteTx(r.Context(), tx, idemRequest, claim.LeaseUID, response); completeErr != nil || tx.Commit(r.Context()) != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not resolve authorization request")
			return
		}
		writeStoredResponse(w, response)
		return
	}
	if in.Decision == "deny" {
		destination := oauthCallbackURL(redirectURI, map[string]string{"error": "access_denied", "error_description": "The Tenant Member denied the authorization request.", "state": state, "iss": s.cfg.OAuthIssuer})
		_, err = tx.Exec(r.Context(), `UPDATE oauth_authorization_requests SET status='denied',tenant_member_uid=$2,resolved_at=now() WHERE uid=$1`, requestUID, p.MemberUID)
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid) VALUES($1,$2,'tenant_member',$3,'oauth_authorization.denied','oauth_application',$4)`, uuid.NewString(), tenantUID, p.MemberUID, applicationUID)
		}
		response := storedJSONResponse(http.StatusOK, map[string]string{"redirect_to": destination})
		if err != nil || s.idempotency.CompleteTx(r.Context(), tx, idemRequest, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not resolve authorization request")
			return
		}
		writeStoredResponse(w, response)
		return
	}
	if resourceServerUID != nil {
		var identifier string
		err = tx.QueryRow(r.Context(), `SELECT identifier FROM resource_servers WHERE uid=$1 AND tenant_uid=$2 AND status='active' AND deleted_at IS NULL`, *resourceServerUID, tenantUID).Scan(&identifier)
		if err == nil {
			_, _, err = s.resolveAuthorizationScopes(r.Context(), tx, tenantUID, applicationUID, strings.Join(scopes, " "), identifier)
		}
		if err != nil {
			response := problemResponse(r, http.StatusConflict, "authorization_grant_changed", "the Resource Server grant or delegated scopes changed; begin a new authorization request")
			if s.idempotency.CompleteTx(r.Context(), tx, idemRequest, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
				fail(w, r, http.StatusInternalServerError, "internal_error", "could not resolve authorization request")
				return
			}
			writeStoredResponse(w, response)
			return
		}
	}

	codeSecret, err := security.RandomToken()
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not approve authorization request")
		return
	}
	code := "ca_code_" + codeSecret
	codeUID := uuid.NewString()
	codeExpiresAt := time.Now().Add(durationOr(s.cfg.OAuthCodeTTL, 5*time.Minute))
	subjectSecret, err := security.RandomToken()
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not approve authorization request")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE oauth_authorization_requests SET status='approved',tenant_member_uid=$2,resolved_at=now() WHERE uid=$1`, requestUID, p.MemberUID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `
			INSERT INTO oauth_authorization_codes(
				uid,code_hash,application_uid,tenant_uid,tenant_member_uid,redirect_uri,
				scopes,nonce,code_challenge,auth_time,expires_at,resource_server_uid
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		`, codeUID, security.SessionHash(code), applicationUID, tenantUID, p.MemberUID, redirectURI, scopes, nonce, challenge, authTime, codeExpiresAt, resourceServerUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `
			INSERT INTO oauth_consents(uid,tenant_uid,tenant_member_uid,application_uid,scopes,resource_server_uid)
			VALUES($1,$2,$3,$4,$5,$6)
			ON CONFLICT ON CONSTRAINT oauth_consents_member_application_resource_key DO UPDATE
			SET scopes=EXCLUDED.scopes,status='active',updated_at=now(),revoked_at=NULL
		`, uuid.NewString(), tenantUID, p.MemberUID, applicationUID, scopes, resourceServerUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `
			INSERT INTO oauth_subjects(uid,application_uid,tenant_member_uid,subject)
			VALUES($1,$2,$3,$4) ON CONFLICT (application_uid,tenant_member_uid) DO NOTHING
		`, uuid.NewString(), applicationUID, p.MemberUID, "ca_sub_"+subjectSecret)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,'tenant_member',$3,'oauth_authorization.approved','oauth_application',$4,$5)`, uuid.NewString(), tenantUID, p.MemberUID, applicationUID, map[string]any{"scopes": scopes, "resource_server_uid": resourceServerUID})
	}
	destination := oauthCallbackURL(redirectURI, map[string]string{"code": code, "state": state, "iss": s.cfg.OAuthIssuer})
	response := storedJSONResponse(http.StatusOK, map[string]string{"redirect_to": destination})
	if err != nil || s.idempotency.CompleteTx(r.Context(), tx, idemRequest, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not approve authorization request")
		return
	}
	writeStoredResponse(w, response)
}

func oauthCallbackURL(raw string, values map[string]string) string {
	destination, _ := url.Parse(raw)
	query := destination.Query()
	for key, value := range values {
		if value != "" {
			query.Set(key, value)
		}
	}
	destination.RawQuery = query.Encode()
	return destination.String()
}

func storedJSONResponse(status int, value any) store.StoredHTTPResponse {
	body, _ := json.Marshal(value)
	body = append(body, '\n')
	return store.StoredHTTPResponse{Status: status, Headers: map[string][]string{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}, Body: body}
}

type oauthClientRecord struct {
	UID             string
	TenantUID       string
	ClientID        string
	ApplicationType string
}

func (s *Server) oauthToken(w http.ResponseWriter, r *http.Request) {
	form, ok := parseOAuthForm(w, r)
	if !ok {
		return
	}
	if singleFormValue(form, "grant_type") != "authorization_code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Only authorization_code is supported.")
		return
	}
	client, ok := s.authenticateOAuthClient(w, r, form)
	if !ok {
		return
	}
	code, redirectURI, verifier := singleFormValue(form, "code"), singleFormValue(form, "redirect_uri"), singleFormValue(form, "code_verifier")
	if code == "" || redirectURI == "" || !pkceVerifierPattern.MatchString(verifier) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code, exact redirect_uri, and a valid code_verifier are required.")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The authorization server is temporarily unavailable.")
		return
	}
	defer tx.Rollback(r.Context())
	var codeUID, applicationUID, tenantUID, memberUID, storedRedirectURI, nonce, challenge, subject string
	var resourceServerUID *string
	var scopes []string
	var expiresAt, authTime time.Time
	var consumedAt *time.Time
	var member TenantMember
	err = tx.QueryRow(r.Context(), `
		SELECT c.uid,c.application_uid,c.tenant_uid,c.tenant_member_uid,c.redirect_uri,c.scopes,
		       c.nonce,c.code_challenge,c.expires_at,c.consumed_at,c.auth_time,s.subject,c.resource_server_uid,
		       m.uid,m.email,m.display_name,m.role,m.status,m.email_verified_at IS NOT NULL,m.created_at
		FROM oauth_authorization_codes c
		JOIN oauth_applications a ON a.uid=c.application_uid
		JOIN oauth_subjects s ON s.application_uid=c.application_uid AND s.tenant_member_uid=c.tenant_member_uid
		JOIN tenant_members m ON m.uid=c.tenant_member_uid
		WHERE c.code_hash=$1 AND a.status='active' AND a.deleted_at IS NULL
		FOR UPDATE OF c
	`, security.SessionHash(code)).Scan(
		&codeUID, &applicationUID, &tenantUID, &memberUID, &storedRedirectURI, &scopes,
		&nonce, &challenge, &expiresAt, &consumedAt, &authTime, &subject, &resourceServerUID,
		&member.UID, &member.Email, &member.DisplayName, &member.Role, &member.Status, &member.EmailVerified, &member.CreatedAt,
	)
	verifierDigest := sha256.Sum256([]byte(verifier))
	computedChallenge := base64.RawURLEncoding.EncodeToString(verifierDigest[:])
	if err != nil || applicationUID != client.UID || tenantUID != client.TenantUID || storedRedirectURI != redirectURI || consumedAt != nil || !expiresAt.After(time.Now()) || member.Status != "active" || subtle.ConstantTimeCompare([]byte(challenge), []byte(computedChallenge)) != 1 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "The authorization code is invalid, expired, used, or bound to different client inputs.")
		return
	}
	audience := s.cfg.OAuthIssuer + "/oauth/userinfo"
	if resourceServerUID != nil {
		var identifier string
		err = tx.QueryRow(r.Context(), `SELECT identifier FROM resource_servers WHERE uid=$1 AND tenant_uid=$2 AND status='active' AND deleted_at IS NULL`, *resourceServerUID, tenantUID).Scan(&identifier)
		if err == nil {
			_, resource, resolveErr := s.resolveAuthorizationScopes(r.Context(), tx, tenantUID, applicationUID, strings.Join(scopes, " "), identifier)
			err = resolveErr
			if resource != nil {
				audience = resource.Identifier
			}
		}
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "The Resource Server grant or delegated scopes changed after authorization.")
			return
		}
	}
	now := time.Now()
	tokenExpiresAt := now.Add(durationOr(s.cfg.OAuthAccessTokenTTL, 10*time.Minute))
	jti := uuid.NewString()
	accessClaims := map[string]any{
		"iss": s.cfg.OAuthIssuer, "sub": subject, "aud": audience,
		"exp": tokenExpiresAt.Unix(), "iat": now.Unix(), "jti": jti,
		"client_id": client.ClientID, "scope": strings.Join(scopes, " "), "tenant_uid": tenantUID,
	}
	accessToken, err := s.signOAuthJWT(r.Context(), accessClaims)
	if err != nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "Token signing is temporarily unavailable.")
		return
	}
	idClaims := map[string]any{
		"iss": s.cfg.OAuthIssuer, "sub": subject, "aud": client.ClientID,
		"exp": tokenExpiresAt.Unix(), "iat": now.Unix(), "auth_time": authTime.Unix(), "nonce": nonce,
		"tenant_uid": tenantUID,
	}
	if scopeContains(scopes, "profile") {
		idClaims["name"] = member.DisplayName
	}
	if scopeContains(scopes, "email") {
		idClaims["email"] = member.Email
		idClaims["email_verified"] = member.EmailVerified
	}
	idToken, err := s.signOAuthJWT(r.Context(), idClaims)
	if err != nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "Token signing is temporarily unavailable.")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE oauth_authorization_codes SET consumed_at=$2 WHERE uid=$1 AND consumed_at IS NULL`, codeUID, now)
	if err == nil {
		_, err = tx.Exec(r.Context(), `
			INSERT INTO oauth_access_tokens(uid,token_hash,jti,application_uid,tenant_uid,tenant_member_uid,subject,scopes,created_at,expires_at,resource_server_uid)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		`, uuid.NewString(), security.SessionHash(accessToken), jti, applicationUID, tenantUID, memberUID, subject, scopes, now, tokenExpiresAt, resourceServerUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,'tenant_member',$3,'oauth_token.issued','oauth_application',$4,$5)`, uuid.NewString(), tenantUID, memberUID, applicationUID, map[string]any{"scopes": scopes, "jti": jti, "audience": audience})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The authorization server is temporarily unavailable.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken, "token_type": "Bearer",
		"expires_in": int64(tokenExpiresAt.Sub(now) / time.Second), "scope": strings.Join(scopes, " "), "id_token": idToken,
	})
}

func parseOAuthForm(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Content-Type must be application/x-www-form-urlencoded.")
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "The form body is invalid or too large.")
		return nil, false
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "The form body is invalid.")
		return nil, false
	}
	for _, values := range form {
		if len(values) != 1 {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "OAuth parameters must not be repeated.")
			return nil, false
		}
	}
	return form, true
}

func singleFormValue(form url.Values, name string) string {
	values := form[name]
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func (s *Server) authenticateOAuthClient(w http.ResponseWriter, r *http.Request, form url.Values) (oauthClientRecord, bool) {
	formClientID := singleFormValue(form, "client_id")
	basicClientID, basicSecret, hasBasic := r.BasicAuth()
	if hasBasic && formClientID != "" && formClientID != basicClientID {
		writeInvalidClient(w)
		return oauthClientRecord{}, false
	}
	clientID := formClientID
	if hasBasic {
		clientID = basicClientID
	}
	var client oauthClientRecord
	err := s.db.QueryRow(r.Context(), `SELECT uid,tenant_uid,client_id,application_type FROM oauth_applications WHERE client_id=$1 AND status='active' AND deleted_at IS NULL`, clientID).Scan(&client.UID, &client.TenantUID, &client.ClientID, &client.ApplicationType)
	if err != nil {
		writeInvalidClient(w)
		return oauthClientRecord{}, false
	}
	if client.ApplicationType == "public" {
		if hasBasic || singleFormValue(form, "client_secret") != "" {
			writeInvalidClient(w)
			return oauthClientRecord{}, false
		}
		return client, true
	}
	if !hasBasic || basicSecret == "" || singleFormValue(form, "client_secret") != "" {
		writeInvalidClient(w)
		return oauthClientRecord{}, false
	}
	prefix, _, ok := strings.Cut(basicSecret, ".")
	var secretUID string
	var storedHash []byte
	err = s.db.QueryRow(r.Context(), `SELECT uid,secret_hash FROM oauth_client_secrets WHERE application_uid=$1 AND prefix=$2 AND status='active' AND expires_at>now()`, client.UID, prefix).Scan(&secretUID, &storedHash)
	providedHash := security.SecretHash(s.cfg.SecretHashKey, basicSecret)
	if err != nil || !ok || subtle.ConstantTimeCompare(storedHash, providedHash) != 1 {
		writeInvalidClient(w)
		return oauthClientRecord{}, false
	}
	_, _ = s.db.Exec(r.Context(), `UPDATE oauth_client_secrets SET last_used_at=now() WHERE uid=$1`, secretUID)
	return client, true
}

func writeInvalidClient(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="oauth-token"`)
	writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func (s *Server) oauthUserInfo(w http.ResponseWriter, r *http.Request) {
	value := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if value == "" || len(value) > 8192 {
		writeInvalidBearer(w)
		return
	}
	var subject, email, displayName, status string
	var scopes []string
	var verified bool
	err := s.db.QueryRow(r.Context(), `
		SELECT t.subject,t.scopes,m.email,m.display_name,m.email_verified_at IS NOT NULL,m.status
		FROM oauth_access_tokens t JOIN tenant_members m ON m.uid=t.tenant_member_uid
		JOIN oauth_applications a ON a.uid=t.application_uid
		WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND t.expires_at>now()
		  AND t.resource_server_uid IS NULL
		  AND m.status='active' AND a.status='active' AND a.deleted_at IS NULL
	`, security.SessionHash(value)).Scan(&subject, &scopes, &email, &displayName, &verified, &status)
	if err != nil || status != "active" {
		writeInvalidBearer(w)
		return
	}
	result := map[string]any{"sub": subject}
	if scopeContains(scopes, "profile") {
		result["name"] = displayName
	}
	if scopeContains(scopes, "email") {
		result["email"] = email
		result["email_verified"] = verified
	}
	writeJSON(w, http.StatusOK, result)
}

func writeInvalidBearer(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "The access token is invalid, expired, or revoked.")
}

func (s *Server) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	form, ok := parseOAuthForm(w, r)
	if !ok {
		return
	}
	client, ok := s.authenticateOAuthClient(w, r, form)
	if !ok {
		return
	}
	token := singleFormValue(form, "token")
	if token == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token is required.")
		return
	}
	_, _ = s.db.Exec(r.Context(), `UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE application_uid=$1 AND token_hash=$2`, client.UID, security.SessionHash(token))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func scopeContains(scopes []string, wanted string) bool {
	for _, scope := range scopes {
		if scope == wanted {
			return true
		}
	}
	return false
}

func durationOr(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func scanOAuthConsent(row rowScanner) (OAuthConsent, error) {
	var consent OAuthConsent
	err := row.Scan(&consent.UID, &consent.ApplicationUID, &consent.ApplicationName, &consent.ClientID, &consent.Scopes, &consent.ResourceServerUID, &consent.ResourceServerName, &consent.ResourceServerIdentifier, &consent.Status, &consent.CreatedAt, &consent.UpdatedAt, &consent.RevokedAt)
	return consent, err
}

func (s *Server) listOAuthConsents(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	query := `SELECT c.uid,a.uid,a.name,a.client_id,c.scopes,r.uid,r.name,r.identifier,c.status,c.created_at,c.updated_at,c.revoked_at FROM oauth_consents c JOIN oauth_applications a ON a.uid=c.application_uid LEFT JOIN resource_servers r ON r.uid=c.resource_server_uid WHERE c.tenant_member_uid=$1 AND c.tenant_uid=$2`
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), query+` ORDER BY c.created_at DESC,c.uid DESC LIMIT $3`, p.MemberUID, p.TenantUID, limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), query+` AND (c.created_at,c.uid)<($3,$4::uuid) ORDER BY c.created_at DESC,c.uid DESC LIMIT $5`, p.MemberUID, p.TenantUID, cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load OAuth consents")
		return
	}
	defer rows.Close()
	items := make([]OAuthConsent, 0, limit)
	for rows.Next() {
		item, scanErr := scanOAuthConsent(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load OAuth consents")
			return
		}
		items = append(items, item)
	}
	var next *string
	if len(items) > limit {
		position := items[limit-1]
		items = items[:limit]
		value := nextCursor(position.CreatedAt, position.UID)
		next = &value
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func (s *Server) revokeOAuthConsent(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not revoke OAuth consent")
		return
	}
	defer tx.Rollback(r.Context())
	var applicationUID string
	var resourceServerUID *string
	err = tx.QueryRow(r.Context(), `UPDATE oauth_consents SET status='revoked',revoked_at=COALESCE(revoked_at,now()),updated_at=now() WHERE uid=$1 AND tenant_uid=$2 AND tenant_member_uid=$3 RETURNING application_uid,resource_server_uid`, r.PathValue("consent_uid"), p.TenantUID, p.MemberUID).Scan(&applicationUID, &resourceServerUID)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "oauth_consent_not_found", "OAuth consent was not found")
		return
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE application_uid=$1 AND tenant_member_uid=$2 AND resource_server_uid IS NOT DISTINCT FROM $3::uuid`, applicationUID, p.MemberUID, resourceServerUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid) VALUES($1,$2,'tenant_member',$3,'oauth_consent.revoked','oauth_application',$4)`, uuid.NewString(), p.TenantUID, p.MemberUID, applicationUID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not revoke OAuth consent")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
