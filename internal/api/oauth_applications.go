package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	security "github.com/dokosoko/complicatedauth-backend/internal/auth"
	"github.com/dokosoko/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	oauthClientSecretDefaultTTL = 90 * 24 * time.Hour
	oauthClientSecretMaximumTTL = 365 * 24 * time.Hour
	maxOAuthRedirectURIs        = 20
)

func scanOAuthApplication(row rowScanner) (OAuthApplication, error) {
	var application OAuthApplication
	err := row.Scan(
		&application.UID,
		&application.Name,
		&application.ClientID,
		&application.ApplicationType,
		&application.Status,
		&application.Version,
		&application.RedirectURIs,
		&application.CreatedAt,
		&application.UpdatedAt,
	)
	if application.RedirectURIs == nil {
		application.RedirectURIs = []string{}
	}
	return application, err
}

const oauthApplicationSelect = `
	SELECT a.uid,a.name,a.client_id,a.application_type,a.status,a.version,
		COALESCE(array_agg(r.redirect_uri ORDER BY r.redirect_uri) FILTER (WHERE r.uid IS NOT NULL),'{}'),
		a.created_at,a.updated_at
	FROM oauth_applications a
	LEFT JOIN oauth_application_redirect_uris r ON r.application_uid=a.uid
`

func (s *Server) loadOAuthApplication(ctx context.Context, tenantUID, applicationUID string) (OAuthApplication, error) {
	return scanOAuthApplication(s.db.QueryRow(ctx, oauthApplicationSelect+`
		WHERE a.tenant_uid=$1 AND a.uid=$2 AND a.deleted_at IS NULL
		GROUP BY a.uid
	`, tenantUID, applicationUID))
}

func (s *Server) listOAuthApplications(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	query := oauthApplicationSelect + ` WHERE a.tenant_uid=$1 AND a.deleted_at IS NULL`
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), query+` GROUP BY a.uid ORDER BY a.created_at DESC,a.uid DESC LIMIT $2`, p.TenantUID, limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), query+` AND (a.created_at,a.uid)<($2,$3::uuid) GROUP BY a.uid ORDER BY a.created_at DESC,a.uid DESC LIMIT $4`, p.TenantUID, cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load OAuth Applications")
		return
	}
	defer rows.Close()
	items := make([]OAuthApplication, 0, limit)
	for rows.Next() {
		item, scanErr := scanOAuthApplication(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load OAuth Applications")
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

func (s *Server) getOAuthApplication(w http.ResponseWriter, r *http.Request) {
	application, err := s.loadOAuthApplication(r.Context(), mustPrincipal(r).TenantUID, r.PathValue("application_uid"))
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "oauth_application_not_found", "OAuth Application was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load OAuth Application")
		return
	}
	setVersionETag(w, application.Version)
	writeJSON(w, http.StatusOK, application)
}

type createOAuthApplicationInput struct {
	Name            string   `json:"name"`
	ApplicationType string   `json:"application_type"`
	RedirectURIs    []string `json:"redirect_uris"`
}

func (s *Server) createOAuthApplication(w http.ResponseWriter, r *http.Request) {
	var in createOAuthApplicationInput
	if !decode(w, r, &in) {
		return
	}
	if err := normalizeOAuthApplicationInput(&in); err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		fail(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required")
		return
	}
	p := mustPrincipal(r)
	canonical, _ := json.Marshal(in)
	idemRequest := store.IdempotencyRequest{
		PrincipalType: "tenant_member", PrincipalUID: p.MemberUID,
		Operation: "oauth_applications.create", Key: key,
		RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour,
	}
	claim, ok := s.beginIdempotentRequest(w, r, idemRequest)
	if !ok {
		return
	}

	clientToken, err := security.RandomToken()
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create OAuth Application")
		return
	}
	now := time.Now()
	application := OAuthApplication{
		UID: uuid.NewString(), Name: in.Name, ClientID: "ca_client_" + clientToken,
		ApplicationType: in.ApplicationType, Status: "active", Version: 1,
		RedirectURIs: in.RedirectURIs, CreatedAt: now, UpdatedAt: now,
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create OAuth Application")
		return
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO oauth_applications(uid,tenant_uid,name,client_id,application_type,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$6)`, application.UID, p.TenantUID, application.Name, application.ClientID, application.ApplicationType, now)
	for _, redirectURI := range application.RedirectURIs {
		if err != nil {
			break
		}
		_, err = tx.Exec(r.Context(), `INSERT INTO oauth_application_redirect_uris(uid,application_uid,redirect_uri,created_at) VALUES($1,$2,$3,$4)`, uuid.NewString(), application.UID, redirectURI, now)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,'tenant_member',$3,'oauth_application.created','oauth_application',$4,$5)`, uuid.NewString(), p.TenantUID, p.MemberUID, application.UID, map[string]any{"application_type": application.ApplicationType})
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create OAuth Application")
		return
	}
	body, _ := json.Marshal(application)
	body = append(body, '\n')
	response := store.StoredHTTPResponse{
		Status: http.StatusCreated,
		Headers: map[string][]string{
			"Content-Type": {"application/json"}, "Cache-Control": {"no-store"},
			"Location": {"/v1/oauth/applications/" + application.UID}, "ETag": {versionETag(application.Version)},
		},
		Body: body,
	}
	if err = s.idempotency.CompleteTx(r.Context(), tx, idemRequest, claim.LeaseUID, response); err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create OAuth Application")
		return
	}
	writeStoredResponse(w, response)
}

func normalizeOAuthApplicationInput(in *createOAuthApplicationInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 120 {
		return errors.New("name must contain between 1 and 120 characters")
	}
	if in.ApplicationType != "public" && in.ApplicationType != "confidential" {
		return errors.New("application_type must be public or confidential")
	}
	redirects, err := normalizeRedirectURIs(in.RedirectURIs)
	if err != nil {
		return err
	}
	in.RedirectURIs = redirects
	return nil
}

func normalizeRedirectURIs(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > maxOAuthRedirectURIs {
		return nil, fmt.Errorf("redirect_uris must contain between 1 and %d exact URIs", maxOAuthRedirectURIs)
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return nil, fmt.Errorf("redirect URI %q must be absolute and must not contain credentials or a fragment", value)
		}
		hostname := parsed.Hostname()
		developmentHTTP := parsed.Scheme == "http" && (hostname == "localhost" || net.ParseIP(hostname) != nil)
		if parsed.Scheme != "https" && !developmentHTTP {
			return nil, fmt.Errorf("redirect URI %q must use HTTPS except for localhost or literal-IP development", value)
		}
		canonical := parsed.String()
		if _, exists := seen[canonical]; exists {
			return nil, fmt.Errorf("redirect URI %q is duplicated", canonical)
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	sort.Strings(result)
	return result, nil
}

func (s *Server) updateOAuthApplication(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name         *string   `json:"name"`
		Status       *string   `json:"status"`
		RedirectURIs *[]string `json:"redirect_uris"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Name == nil && in.Status == nil && in.RedirectURIs == nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "at least one field is required")
		return
	}
	if in.Name != nil {
		value := strings.TrimSpace(*in.Name)
		if value == "" || len(value) > 120 {
			fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "name must contain between 1 and 120 characters")
			return
		}
		in.Name = &value
	}
	if in.Status != nil && *in.Status != "active" && *in.Status != "disabled" {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "status must be active or disabled")
		return
	}
	if in.RedirectURIs != nil {
		values, err := normalizeRedirectURIs(*in.RedirectURIs)
		if err != nil {
			fail(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
			return
		}
		in.RedirectURIs = &values
	}
	expectedVersion, ok := requireIfMatch(w, r)
	if !ok {
		return
	}
	p := mustPrincipal(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update OAuth Application")
		return
	}
	defer tx.Rollback(r.Context())
	var currentName, currentStatus string
	var currentVersion int64
	err = tx.QueryRow(r.Context(), `SELECT name,status,version FROM oauth_applications WHERE tenant_uid=$1 AND uid=$2 AND deleted_at IS NULL FOR UPDATE`, p.TenantUID, r.PathValue("application_uid")).Scan(&currentName, &currentStatus, &currentVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "oauth_application_not_found", "OAuth Application was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update OAuth Application")
		return
	}
	if currentVersion != expectedVersion {
		w.Header().Set("ETag", versionETag(currentVersion))
		fail(w, r, http.StatusPreconditionFailed, "version_conflict", "OAuth Application changed; fetch the latest representation and retry")
		return
	}
	if in.Name != nil {
		currentName = *in.Name
	}
	if in.Status != nil {
		currentStatus = *in.Status
	}
	nextVersion := currentVersion + 1
	_, err = tx.Exec(r.Context(), `UPDATE oauth_applications SET name=$3,status=$4,version=$5,updated_at=now() WHERE tenant_uid=$1 AND uid=$2`, p.TenantUID, r.PathValue("application_uid"), currentName, currentStatus, nextVersion)
	if err == nil && in.RedirectURIs != nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM oauth_application_redirect_uris WHERE application_uid=$1`, r.PathValue("application_uid"))
		for _, redirectURI := range *in.RedirectURIs {
			if err != nil {
				break
			}
			_, err = tx.Exec(r.Context(), `INSERT INTO oauth_application_redirect_uris(uid,application_uid,redirect_uri) VALUES($1,$2,$3)`, uuid.NewString(), r.PathValue("application_uid"), redirectURI)
		}
	}
	if err == nil && currentStatus == "disabled" {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE application_uid=$1`, r.PathValue("application_uid"))
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,'tenant_member',$3,'oauth_application.updated','oauth_application',$4,$5)`, uuid.NewString(), p.TenantUID, p.MemberUID, r.PathValue("application_uid"), map[string]any{"version": nextVersion, "status": currentStatus})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update OAuth Application")
		return
	}
	application, err := s.loadOAuthApplication(r.Context(), p.TenantUID, r.PathValue("application_uid"))
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load OAuth Application")
		return
	}
	setVersionETag(w, application.Version)
	writeJSON(w, http.StatusOK, application)
}

func (s *Server) deleteOAuthApplication(w http.ResponseWriter, r *http.Request) {
	expectedVersion, ok := requireIfMatch(w, r)
	if !ok {
		return
	}
	p := mustPrincipal(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete OAuth Application")
		return
	}
	defer tx.Rollback(r.Context())
	var currentVersion int64
	err = tx.QueryRow(r.Context(), `SELECT version FROM oauth_applications WHERE tenant_uid=$1 AND uid=$2 AND deleted_at IS NULL FOR UPDATE`, p.TenantUID, r.PathValue("application_uid")).Scan(&currentVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "oauth_application_not_found", "OAuth Application was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete OAuth Application")
		return
	}
	if currentVersion != expectedVersion {
		w.Header().Set("ETag", versionETag(currentVersion))
		fail(w, r, http.StatusPreconditionFailed, "version_conflict", "OAuth Application changed; fetch the latest representation and retry")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE oauth_applications SET status='disabled',version=version+1,updated_at=now(),deleted_at=now() WHERE uid=$1`, r.PathValue("application_uid"))
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_client_secrets SET status='revoked',revoked_at=COALESCE(revoked_at,now()) WHERE application_uid=$1`, r.PathValue("application_uid"))
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE application_uid=$1`, r.PathValue("application_uid"))
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid) VALUES($1,$2,'tenant_member',$3,'oauth_application.deleted','oauth_application',$4)`, uuid.NewString(), p.TenantUID, p.MemberUID, r.PathValue("application_uid"))
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete OAuth Application")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func scanOAuthClientSecret(row rowScanner) (OAuthClientSecret, error) {
	var secret OAuthClientSecret
	err := row.Scan(&secret.UID, &secret.Name, &secret.Prefix, &secret.Status, &secret.CreatedAt, &secret.ExpiresAt, &secret.LastUsedAt, &secret.RevokedAt)
	return secret, err
}

func (s *Server) listOAuthClientSecrets(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	var exists bool
	if err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM oauth_applications WHERE uid=$1 AND tenant_uid=$2 AND deleted_at IS NULL)`, r.PathValue("application_uid"), p.TenantUID).Scan(&exists); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load client secrets")
		return
	}
	if !exists {
		fail(w, r, http.StatusNotFound, "oauth_application_not_found", "OAuth Application was not found")
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT uid,name,prefix,CASE WHEN status='active' AND expires_at<=now() THEN 'expired' ELSE status END,created_at,expires_at,last_used_at,revoked_at FROM oauth_client_secrets WHERE application_uid=$1 ORDER BY created_at DESC,uid DESC`, r.PathValue("application_uid"))
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load client secrets")
		return
	}
	defer rows.Close()
	items := []OAuthClientSecret{}
	for rows.Next() {
		item, scanErr := scanOAuthClientSecret(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load client secrets")
			return
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type createOAuthClientSecretInput struct {
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (s *Server) createOAuthClientSecret(w http.ResponseWriter, r *http.Request) {
	var in createOAuthClientSecretInput
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	now := time.Now()
	expiresAt := now.Add(oauthClientSecretDefaultTTL)
	if in.ExpiresAt != nil {
		expiresAt = in.ExpiresAt.UTC()
		in.ExpiresAt = &expiresAt
	}
	if in.Name == "" || len(in.Name) > 100 || !expiresAt.After(now.Add(5*time.Minute)) || expiresAt.After(now.Add(oauthClientSecretMaximumTTL)) {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "name is required and expires_at must be between 5 minutes and 365 days from now")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		fail(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required")
		return
	}
	p := mustPrincipal(r)
	canonical, _ := json.Marshal(struct {
		ApplicationUID string                       `json:"application_uid"`
		Input          createOAuthClientSecretInput `json:"input"`
	}{ApplicationUID: r.PathValue("application_uid"), Input: in})
	idemRequest := store.IdempotencyRequest{
		PrincipalType: "tenant_member", PrincipalUID: p.MemberUID,
		Operation: "oauth_client_secrets.create", Key: key,
		RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour,
	}
	claim, ok := s.beginIdempotentRequest(w, r, idemRequest)
	if !ok {
		return
	}
	randomSecret, err := security.RandomToken()
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create client secret")
		return
	}
	prefix := "ca_cs_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	secretValue := prefix + "." + randomSecret
	secret := OAuthClientSecret{UID: uuid.NewString(), Name: in.Name, Prefix: prefix, Status: "active", CreatedAt: now, ExpiresAt: expiresAt, Secret: secretValue}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create client secret")
		return
	}
	defer tx.Rollback(r.Context())
	var applicationType string
	err = tx.QueryRow(r.Context(), `SELECT application_type FROM oauth_applications WHERE uid=$1 AND tenant_uid=$2 AND status='active' AND deleted_at IS NULL FOR UPDATE`, r.PathValue("application_uid"), p.TenantUID).Scan(&applicationType)
	if errors.Is(err, pgx.ErrNoRows) {
		response := problemResponse(r, http.StatusNotFound, "oauth_application_not_found", "active OAuth Application was not found")
		if completeErr := s.idempotency.CompleteTx(r.Context(), tx, idemRequest, claim.LeaseUID, response); completeErr != nil || tx.Commit(r.Context()) != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not create client secret")
			return
		}
		writeStoredResponse(w, response)
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create client secret")
		return
	}
	if applicationType != "confidential" {
		response := problemResponse(r, http.StatusConflict, "public_client", "public OAuth Applications cannot have client secrets")
		if completeErr := s.idempotency.CompleteTx(r.Context(), tx, idemRequest, claim.LeaseUID, response); completeErr != nil || tx.Commit(r.Context()) != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not create client secret")
			return
		}
		writeStoredResponse(w, response)
		return
	}
	var activeCount int
	if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM oauth_client_secrets WHERE application_uid=$1 AND status='active' AND expires_at>now()`, r.PathValue("application_uid")).Scan(&activeCount); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create client secret")
		return
	}
	if activeCount >= 2 {
		response := problemResponse(r, http.StatusConflict, "client_secret_limit", "revoke an active client secret before creating another")
		if completeErr := s.idempotency.CompleteTx(r.Context(), tx, idemRequest, claim.LeaseUID, response); completeErr != nil || tx.Commit(r.Context()) != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not create client secret")
			return
		}
		writeStoredResponse(w, response)
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO oauth_client_secrets(uid,application_uid,name,prefix,secret_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, secret.UID, r.PathValue("application_uid"), secret.Name, secret.Prefix, security.SecretHash(s.cfg.SecretHashKey, secretValue), now, expiresAt)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid) VALUES($1,$2,'tenant_member',$3,'oauth_client_secret.created','oauth_client_secret',$4)`, uuid.NewString(), p.TenantUID, p.MemberUID, secret.UID)
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create client secret")
		return
	}
	body, _ := json.Marshal(secret)
	body = append(body, '\n')
	response := store.StoredHTTPResponse{Status: http.StatusCreated, Headers: map[string][]string{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}, "Location": {fmt.Sprintf("/v1/oauth/applications/%s/client-secrets/%s", r.PathValue("application_uid"), secret.UID)}}, Body: body}
	if err = s.idempotency.CompleteTx(r.Context(), tx, idemRequest, claim.LeaseUID, response); err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create client secret")
		return
	}
	writeStoredResponse(w, response)
}

func (s *Server) revokeOAuthClientSecret(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	command, err := s.db.Exec(r.Context(), `UPDATE oauth_client_secrets s SET status='revoked',revoked_at=COALESCE(s.revoked_at,now()) FROM oauth_applications a WHERE s.uid=$1 AND s.application_uid=$2 AND a.uid=s.application_uid AND a.tenant_uid=$3 AND a.deleted_at IS NULL`, r.PathValue("secret_uid"), r.PathValue("application_uid"), p.TenantUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not revoke client secret")
		return
	}
	if command.RowsAffected() == 0 {
		fail(w, r, http.StatusNotFound, "oauth_client_secret_not_found", "OAuth client secret was not found")
		return
	}
	s.audit(r.Context(), p.TenantUID, "", "tenant_member", p.MemberUID, "oauth_client_secret.revoked", "oauth_client_secret", r.PathValue("secret_uid"), nil, r)
	w.WriteHeader(http.StatusNoContent)
}

func versionETag(version int64) string {
	return `"` + strconv.FormatInt(version, 10) + `"`
}

func setVersionETag(w http.ResponseWriter, version int64) {
	w.Header().Set("ETag", versionETag(version))
}

func requireIfMatch(w http.ResponseWriter, r *http.Request) (int64, bool) {
	value := r.Header.Get("If-Match")
	if value == "" {
		fail(w, r, http.StatusPreconditionRequired, "if_match_required", "If-Match with the current resource ETag is required")
		return 0, false
	}
	if strings.HasPrefix(value, "W/") || len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		fail(w, r, http.StatusBadRequest, "invalid_if_match", "If-Match must contain one strong numeric ETag")
		return 0, false
	}
	version, err := strconv.ParseInt(value[1:len(value)-1], 10, 64)
	if err != nil || version < 1 {
		fail(w, r, http.StatusBadRequest, "invalid_if_match", "If-Match must contain one strong numeric ETag")
		return 0, false
	}
	return version, true
}
