package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	security "github.com/dokosoko/complicatedauth-backend/internal/auth"
	"github.com/dokosoko/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	serviceAccountLimit           = 20
	serviceCredentialActiveLimit  = 2
	serviceCredentialDefaultTTL   = 90 * 24 * time.Hour
	serviceCredentialMaximumTTL   = 365 * 24 * time.Hour
	serviceCredentialMinimumTTL   = 5 * time.Minute
	serviceScopeProjectUsersRead  = "project_users.read"
	serviceScopeProjectUsersWrite = "project_users.write"
	serviceScopeAuthentication    = "authentication.perform"
	serviceScopeSessionsManage    = "sessions.manage"
	serviceScopeSupportCasesRead  = "support_cases.read"
	serviceScopeSupportCasesWrite = "support_cases.write"
)

var validServiceAccountScopes = map[string]bool{
	serviceScopeProjectUsersRead:  true,
	serviceScopeProjectUsersWrite: true,
	serviceScopeAuthentication:    true,
	serviceScopeSessionsManage:    true,
	serviceScopeSupportCasesRead:  true,
	serviceScopeSupportCasesWrite: true,
}

type ServiceAccount struct {
	UID                string     `json:"uid"`
	Name               string     `json:"name"`
	Description        string     `json:"description"`
	Status             string     `json:"status"`
	Scopes             []string   `json:"scopes"`
	Environment        string     `json:"environment"`
	Version            int64      `json:"version"`
	CreatedByMemberUID *string    `json:"created_by_member_uid"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	DisabledAt         *time.Time `json:"disabled_at"`
}

type ServiceCredential struct {
	UID                string     `json:"uid"`
	ServiceAccountUID  string     `json:"service_account_uid"`
	Name               string     `json:"name"`
	Prefix             string     `json:"prefix"`
	Fingerprint        string     `json:"fingerprint"`
	Status             string     `json:"status"`
	CreatedByMemberUID *string    `json:"created_by_member_uid"`
	CreatedAt          time.Time  `json:"created_at"`
	ExpiresAt          time.Time  `json:"expires_at"`
	LastUsedAt         *time.Time `json:"last_used_at"`
	RevokedAt          *time.Time `json:"revoked_at"`
	RevokedByMemberUID *string    `json:"revoked_by_member_uid"`
	RevocationReason   *string    `json:"revocation_reason"`
	Secret             string     `json:"secret,omitempty"`
}

const serviceAccountSelect = `SELECT a.uid,a.name,a.description,a.status,a.scopes,a.version,p.environment,a.created_by_member_uid,a.created_at,a.updated_at,a.disabled_at
	FROM project_service_accounts a JOIN projects p ON p.uid=a.project_uid`

func scanServiceAccount(row rowScanner) (ServiceAccount, error) {
	var value ServiceAccount
	err := row.Scan(&value.UID, &value.Name, &value.Description, &value.Status, &value.Scopes, &value.Version, &value.Environment, &value.CreatedByMemberUID, &value.CreatedAt, &value.UpdatedAt, &value.DisabledAt)
	return value, err
}

func normalizeServiceAccountScopes(values []string) ([]string, error) {
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !validServiceAccountScopes[value] {
			return nil, fmt.Errorf("unsupported scope %q", value)
		}
		seen[value] = true
	}
	if len(seen) == 0 {
		return nil, errors.New("at least one scope is required")
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func (s *Server) listServiceAccounts(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	projectUID := r.PathValue("project_uid")
	if !s.ownsProject(r.Context(), p.TenantUID, projectUID) {
		fail(w, r, http.StatusNotFound, "project_not_found", "Project was not found")
		return
	}
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	query := serviceAccountSelect + ` WHERE a.project_uid=$1 AND a.deleted_at IS NULL`
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), query+` ORDER BY a.created_at DESC,a.uid DESC LIMIT $2`, projectUID, limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), query+` AND (a.created_at,a.uid)<($2,$3::uuid) ORDER BY a.created_at DESC,a.uid DESC LIMIT $4`, projectUID, cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load service accounts")
		return
	}
	defer rows.Close()
	items := make([]ServiceAccount, 0, limit)
	for rows.Next() {
		item, scanErr := scanServiceAccount(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load service accounts")
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

func (s *Server) loadServiceAccount(ctx context.Context, tenantUID, projectUID, accountUID string) (ServiceAccount, error) {
	return scanServiceAccount(s.db.QueryRow(ctx, serviceAccountSelect+` WHERE p.tenant_uid=$1 AND a.project_uid=$2 AND a.uid=$3 AND a.deleted_at IS NULL`, tenantUID, projectUID, accountUID))
}

func (s *Server) getServiceAccount(w http.ResponseWriter, r *http.Request) {
	value, err := s.loadServiceAccount(r.Context(), mustPrincipal(r).TenantUID, r.PathValue("project_uid"), r.PathValue("service_account_uid"))
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "service_account_not_found", "Service account was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load service account")
		return
	}
	setVersionETag(w, value.Version)
	writeJSON(w, http.StatusOK, value)
}

type createServiceAccountInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Scopes      []string `json:"scopes"`
}

func normalizeServiceAccountInput(in *createServiceAccountInput) error {
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	if in.Name == "" || len(in.Name) > 100 {
		return errors.New("name must contain between 1 and 100 characters")
	}
	if len(in.Description) > 500 {
		return errors.New("description must not exceed 500 characters")
	}
	var err error
	in.Scopes, err = normalizeServiceAccountScopes(in.Scopes)
	return err
}

func (s *Server) createServiceAccount(w http.ResponseWriter, r *http.Request) {
	var in createServiceAccountInput
	if !decode(w, r, &in) {
		return
	}
	if err := normalizeServiceAccountInput(&in); err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		fail(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required")
		return
	}
	p := mustPrincipal(r)
	projectUID := r.PathValue("project_uid")
	canonical, _ := json.Marshal(struct {
		ProjectUID string                    `json:"project_uid"`
		Input      createServiceAccountInput `json:"input"`
	}{projectUID, in})
	idem := store.IdempotencyRequest{PrincipalType: "tenant_member", PrincipalUID: p.MemberUID, Operation: "service_accounts.create", Key: key, RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour}
	claim, ok := s.beginIdempotentRequest(w, r, idem)
	if !ok {
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create service account")
		return
	}
	defer tx.Rollback(r.Context())
	var environment, projectStatus string
	err = tx.QueryRow(r.Context(), `SELECT environment,status FROM projects WHERE uid=$1 AND tenant_uid=$2 FOR UPDATE`, projectUID, p.TenantUID).Scan(&environment, &projectStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		s.completeServiceAccountProblem(w, r, tx, idem, claim, http.StatusNotFound, "project_not_found", "Project was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create service account")
		return
	}
	if projectStatus != "active" {
		s.completeServiceAccountProblem(w, r, tx, idem, claim, http.StatusConflict, "project_disabled", "enable the Project before creating a service account")
		return
	}
	var count int
	if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM project_service_accounts WHERE project_uid=$1 AND deleted_at IS NULL`, projectUID).Scan(&count); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create service account")
		return
	}
	if count >= serviceAccountLimit {
		s.completeServiceAccountProblem(w, r, tx, idem, claim, http.StatusConflict, "service_account_limit", "a Project may have at most 20 service accounts")
		return
	}
	now := time.Now().UTC()
	value := ServiceAccount{UID: uuid.NewString(), Name: in.Name, Description: in.Description, Status: "active", Scopes: in.Scopes, Environment: environment, Version: 1, CreatedByMemberUID: &p.MemberUID, CreatedAt: now, UpdatedAt: now}
	_, err = tx.Exec(r.Context(), `INSERT INTO project_service_accounts(uid,project_uid,name,description,scopes,created_by_member_uid,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$7)`, value.UID, projectUID, value.Name, value.Description, value.Scopes, p.MemberUID, now)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,project_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,$3,'tenant_member',$4,'service_account.created','service_account',$5,$6)`, uuid.NewString(), p.TenantUID, projectUID, p.MemberUID, value.UID, map[string]any{"scopes": value.Scopes})
	}
	response := storedResourceResponse(http.StatusCreated, fmt.Sprintf("/v1/projects/%s/service-accounts/%s", projectUID, value.UID), value.Version, value)
	if err != nil || s.idempotency.CompleteTx(r.Context(), tx, idem, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create service account")
		return
	}
	writeStoredResponse(w, response)
}

func (s *Server) completeServiceAccountProblem(w http.ResponseWriter, r *http.Request, tx pgx.Tx, idem store.IdempotencyRequest, claim store.IdempotencyClaim, status int, code, detail string) {
	response := problemResponse(r, status, code, detail)
	if s.idempotency.CompleteTx(r.Context(), tx, idem, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not persist service-account result")
		return
	}
	writeStoredResponse(w, response)
}

func (s *Server) updateServiceAccount(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        *string   `json:"name"`
		Description *string   `json:"description"`
		Status      *string   `json:"status"`
		Scopes      *[]string `json:"scopes"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Name == nil && in.Description == nil && in.Status == nil && in.Scopes == nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "at least one field is required")
		return
	}
	if in.Name != nil {
		value := strings.TrimSpace(*in.Name)
		if value == "" || len(value) > 100 {
			fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "name must contain between 1 and 100 characters")
			return
		}
		in.Name = &value
	}
	if in.Description != nil {
		value := strings.TrimSpace(*in.Description)
		if len(value) > 500 {
			fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "description must not exceed 500 characters")
			return
		}
		in.Description = &value
	}
	if in.Status != nil && *in.Status != "active" && *in.Status != "disabled" {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "status must be active or disabled")
		return
	}
	if in.Scopes != nil {
		values, err := normalizeServiceAccountScopes(*in.Scopes)
		if err != nil {
			fail(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
			return
		}
		in.Scopes = &values
	}
	expected, ok := requireIfMatch(w, r)
	if !ok {
		return
	}
	p := mustPrincipal(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update service account")
		return
	}
	defer tx.Rollback(r.Context())
	var name, description, status string
	var scopes []string
	var version int64
	err = tx.QueryRow(r.Context(), `SELECT a.name,a.description,a.status,a.scopes,a.version FROM project_service_accounts a JOIN projects p ON p.uid=a.project_uid WHERE a.uid=$1 AND a.project_uid=$2 AND p.tenant_uid=$3 AND a.deleted_at IS NULL FOR UPDATE OF a`, r.PathValue("service_account_uid"), r.PathValue("project_uid"), p.TenantUID).Scan(&name, &description, &status, &scopes, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "service_account_not_found", "Service account was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update service account")
		return
	}
	if version != expected {
		w.Header().Set("ETag", versionETag(version))
		fail(w, r, http.StatusPreconditionFailed, "version_conflict", "service account changed; fetch the latest representation and retry")
		return
	}
	if in.Name != nil {
		name = *in.Name
	}
	if in.Description != nil {
		description = *in.Description
	}
	if in.Status != nil {
		status = *in.Status
	}
	if in.Scopes != nil {
		scopes = *in.Scopes
	}
	_, err = tx.Exec(r.Context(), `UPDATE project_service_accounts SET name=$3,description=$4,status=$5::resource_status,scopes=$6,version=version+1,updated_at=now(),disabled_at=CASE WHEN $5::text='disabled' THEN COALESCE(disabled_at,now()) ELSE NULL END WHERE uid=$1 AND project_uid=$2`, r.PathValue("service_account_uid"), r.PathValue("project_uid"), name, description, status, scopes)
	if err == nil && status == "disabled" {
		_, err = tx.Exec(r.Context(), `UPDATE project_service_credentials SET status='revoked',revoked_at=COALESCE(revoked_at,now()),revoked_by_member_uid=$2,revocation_reason=COALESCE(revocation_reason,'service_account_disabled') WHERE service_account_uid=$1 AND status='active'`, r.PathValue("service_account_uid"), p.MemberUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,project_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,$3,'tenant_member',$4,'service_account.updated','service_account',$5,$6)`, uuid.NewString(), p.TenantUID, r.PathValue("project_uid"), p.MemberUID, r.PathValue("service_account_uid"), map[string]any{"status": status, "scopes": scopes})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		if err != nil {
			s.log.Error("service account update failed", "error", err)
		}
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update service account")
		return
	}
	value, err := s.loadServiceAccount(r.Context(), p.TenantUID, r.PathValue("project_uid"), r.PathValue("service_account_uid"))
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load updated service account")
		return
	}
	setVersionETag(w, value.Version)
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) deleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	expected, ok := requireIfMatch(w, r)
	if !ok {
		return
	}
	p := mustPrincipal(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, 500, "internal_error", "could not delete service account")
		return
	}
	defer tx.Rollback(r.Context())
	var version int64
	err = tx.QueryRow(r.Context(), `SELECT version FROM project_service_accounts a JOIN projects p ON p.uid=a.project_uid WHERE a.uid=$1 AND a.project_uid=$2 AND p.tenant_uid=$3 AND a.deleted_at IS NULL FOR UPDATE OF a`, r.PathValue("service_account_uid"), r.PathValue("project_uid"), p.TenantUID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, 404, "service_account_not_found", "Service account was not found")
		return
	}
	if err != nil {
		fail(w, r, 500, "internal_error", "could not delete service account")
		return
	}
	if version != expected {
		w.Header().Set("ETag", versionETag(version))
		fail(w, r, 412, "version_conflict", "service account changed; fetch the latest representation and retry")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE project_service_accounts SET status='disabled',version=version+1,updated_at=now(),disabled_at=COALESCE(disabled_at,now()),deleted_at=now() WHERE uid=$1`, r.PathValue("service_account_uid"))
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE project_service_credentials SET status='revoked',revoked_at=COALESCE(revoked_at,now()),revoked_by_member_uid=$2,revocation_reason=COALESCE(revocation_reason,'service_account_deleted') WHERE service_account_uid=$1 AND status='active'`, r.PathValue("service_account_uid"), p.MemberUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,project_uid,actor_type,actor_uid,action,target_type,target_uid) VALUES($1,$2,$3,'tenant_member',$4,'service_account.deleted','service_account',$5)`, uuid.NewString(), p.TenantUID, r.PathValue("project_uid"), p.MemberUID, r.PathValue("service_account_uid"))
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, 500, "internal_error", "could not delete service account")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

const serviceCredentialSelect = `SELECT c.uid,c.service_account_uid,c.name,c.prefix,c.fingerprint,CASE WHEN c.status='active' AND c.expires_at<=now() THEN 'expired' ELSE c.status END,c.created_by_member_uid,c.created_at,c.expires_at,c.last_used_at,c.revoked_at,c.revoked_by_member_uid,c.revocation_reason FROM project_service_credentials c`

func scanServiceCredential(row rowScanner) (ServiceCredential, error) {
	var value ServiceCredential
	err := row.Scan(&value.UID, &value.ServiceAccountUID, &value.Name, &value.Prefix, &value.Fingerprint, &value.Status, &value.CreatedByMemberUID, &value.CreatedAt, &value.ExpiresAt, &value.LastUsedAt, &value.RevokedAt, &value.RevokedByMemberUID, &value.RevocationReason)
	return value, err
}

func (s *Server) serviceAccountExists(ctx context.Context, tenantUID, projectUID, accountUID string) bool {
	var exists bool
	_ = s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM project_service_accounts a JOIN projects p ON p.uid=a.project_uid WHERE a.uid=$1 AND a.project_uid=$2 AND p.tenant_uid=$3 AND a.deleted_at IS NULL)`, accountUID, projectUID, tenantUID).Scan(&exists)
	return exists
}

func (s *Server) listServiceCredentials(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	if !s.serviceAccountExists(r.Context(), p.TenantUID, r.PathValue("project_uid"), r.PathValue("service_account_uid")) {
		fail(w, r, 404, "service_account_not_found", "Service account was not found")
		return
	}
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	query := serviceCredentialSelect + ` WHERE c.service_account_uid=$1`
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), query+` ORDER BY c.created_at DESC,c.uid DESC LIMIT $2`, r.PathValue("service_account_uid"), limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), query+` AND (c.created_at,c.uid)<($2,$3::uuid) ORDER BY c.created_at DESC,c.uid DESC LIMIT $4`, r.PathValue("service_account_uid"), cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, 500, "internal_error", "could not load service credentials")
		return
	}
	defer rows.Close()
	items := make([]ServiceCredential, 0, limit)
	for rows.Next() {
		item, scanErr := scanServiceCredential(rows)
		if scanErr != nil {
			fail(w, r, 500, "internal_error", "could not load service credentials")
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
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

func (s *Server) getServiceCredential(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	value, err := scanServiceCredential(s.db.QueryRow(r.Context(), serviceCredentialSelect+` JOIN project_service_accounts a ON a.uid=c.service_account_uid JOIN projects p ON p.uid=a.project_uid WHERE c.uid=$1 AND c.service_account_uid=$2 AND a.project_uid=$3 AND p.tenant_uid=$4 AND a.deleted_at IS NULL`, r.PathValue("credential_uid"), r.PathValue("service_account_uid"), r.PathValue("project_uid"), p.TenantUID))
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, 404, "service_credential_not_found", "Service credential was not found")
		return
	}
	if err != nil {
		fail(w, r, 500, "internal_error", "could not load service credential")
		return
	}
	writeJSON(w, 200, value)
}

type createServiceCredentialInput struct {
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (s *Server) createServiceCredential(w http.ResponseWriter, r *http.Request) {
	var in createServiceCredentialInput
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	now := time.Now().UTC()
	expiresAt := now.Add(serviceCredentialDefaultTTL)
	if in.ExpiresAt != nil {
		expiresAt = in.ExpiresAt.UTC()
		in.ExpiresAt = &expiresAt
	}
	if in.Name == "" || len(in.Name) > 100 || !expiresAt.After(now.Add(serviceCredentialMinimumTTL)) || expiresAt.After(now.Add(serviceCredentialMaximumTTL)) {
		fail(w, r, 422, "validation_failed", "name is required and expires_at must be between 5 minutes and 365 days from now")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		fail(w, r, 400, "idempotency_key_required", "Idempotency-Key is required")
		return
	}
	p := mustPrincipal(r)
	canonical, _ := json.Marshal(struct {
		ProjectUID string                       `json:"project_uid"`
		AccountUID string                       `json:"service_account_uid"`
		Input      createServiceCredentialInput `json:"input"`
	}{r.PathValue("project_uid"), r.PathValue("service_account_uid"), in})
	idem := store.IdempotencyRequest{PrincipalType: "tenant_member", PrincipalUID: p.MemberUID, Operation: "service_credentials.create", Key: key, RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour}
	claim, ok := s.beginIdempotentRequest(w, r, idem)
	if !ok {
		return
	}
	randomSecret, err := security.RandomToken()
	if err != nil {
		fail(w, r, 500, "internal_error", "could not create service credential")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, 500, "internal_error", "could not create service credential")
		return
	}
	defer tx.Rollback(r.Context())
	var environment, accountStatus, projectStatus string
	err = tx.QueryRow(r.Context(), `SELECT p.environment,a.status,p.status FROM project_service_accounts a JOIN projects p ON p.uid=a.project_uid WHERE a.uid=$1 AND a.project_uid=$2 AND p.tenant_uid=$3 AND a.deleted_at IS NULL FOR UPDATE OF a`, r.PathValue("service_account_uid"), r.PathValue("project_uid"), p.TenantUID).Scan(&environment, &accountStatus, &projectStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		s.completeServiceAccountProblem(w, r, tx, idem, claim, 404, "service_account_not_found", "Service account was not found")
		return
	}
	if err != nil {
		fail(w, r, 500, "internal_error", "could not create service credential")
		return
	}
	if accountStatus != "active" {
		s.completeServiceAccountProblem(w, r, tx, idem, claim, 409, "service_account_disabled", "enable the service account before issuing a credential")
		return
	}
	if projectStatus != "active" {
		s.completeServiceAccountProblem(w, r, tx, idem, claim, 409, "project_disabled", "enable the Project before issuing a credential")
		return
	}
	var count int
	if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM project_service_credentials WHERE service_account_uid=$1 AND status='active' AND expires_at>now()`, r.PathValue("service_account_uid")).Scan(&count); err != nil {
		fail(w, r, 500, "internal_error", "could not create service credential")
		return
	}
	if count >= serviceCredentialActiveLimit {
		s.completeServiceAccountProblem(w, r, tx, idem, claim, 409, "service_credential_limit", "revoke an active credential before issuing another")
		return
	}
	environmentToken := "test"
	if environment == "production" {
		environmentToken = "live"
	}
	prefix := "ca_sk_" + environmentToken + "_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	secretValue := prefix + "." + randomSecret
	digest := sha256.Sum256([]byte(secretValue))
	value := ServiceCredential{UID: uuid.NewString(), ServiceAccountUID: r.PathValue("service_account_uid"), Name: in.Name, Prefix: prefix, Fingerprint: "sha256:" + hex.EncodeToString(digest[:])[:24], Status: "active", CreatedByMemberUID: &p.MemberUID, CreatedAt: now, ExpiresAt: expiresAt, Secret: secretValue}
	_, err = tx.Exec(r.Context(), `INSERT INTO project_service_credentials(uid,service_account_uid,name,prefix,fingerprint,secret_hash,created_by_member_uid,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, value.UID, value.ServiceAccountUID, value.Name, value.Prefix, value.Fingerprint, security.SecretHash(s.cfg.SecretHashKey, secretValue), p.MemberUID, now, expiresAt)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,project_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,$3,'tenant_member',$4,'service_credential.created','service_credential',$5,$6)`, uuid.NewString(), p.TenantUID, r.PathValue("project_uid"), p.MemberUID, value.UID, map[string]any{"service_account_uid": value.ServiceAccountUID, "expires_at": expiresAt, "fingerprint": value.Fingerprint})
	}
	body, _ := json.Marshal(value)
	body = append(body, '\n')
	response := store.StoredHTTPResponse{Status: 201, Headers: map[string][]string{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}, "Location": {fmt.Sprintf("/v1/projects/%s/service-accounts/%s/credentials/%s", r.PathValue("project_uid"), value.ServiceAccountUID, value.UID)}}, Body: body}
	if err != nil || s.idempotency.CompleteTx(r.Context(), tx, idem, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, 500, "internal_error", "could not create service credential")
		return
	}
	writeStoredResponse(w, response)
}

func (s *Server) revokeServiceCredential(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	var changed bool
	err := s.db.QueryRow(r.Context(), `WITH target AS (
		SELECT c.uid,c.status FROM project_service_credentials c
		JOIN project_service_accounts a ON a.uid=c.service_account_uid
		JOIN projects p ON p.uid=a.project_uid
		WHERE c.uid=$1 AND c.service_account_uid=$2 AND a.project_uid=$3 AND p.tenant_uid=$4
	)
	UPDATE project_service_credentials c
	SET status='revoked',revoked_at=COALESCE(c.revoked_at,now()),revoked_by_member_uid=COALESCE(c.revoked_by_member_uid,$5),revocation_reason=COALESCE(c.revocation_reason,'revoked_by_member')
	FROM target WHERE c.uid=target.uid RETURNING target.status='active'`, r.PathValue("credential_uid"), r.PathValue("service_account_uid"), r.PathValue("project_uid"), p.TenantUID, p.MemberUID).Scan(&changed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, r, 404, "service_credential_not_found", "Service credential was not found")
			return
		}
		fail(w, r, 500, "internal_error", "could not revoke service credential")
		return
	}
	if changed {
		s.audit(r.Context(), p.TenantUID, r.PathValue("project_uid"), "tenant_member", p.MemberUID, "service_credential.revoked", "service_credential", r.PathValue("credential_uid"), map[string]any{"service_account_uid": r.PathValue("service_account_uid")}, r)
	}
	w.WriteHeader(http.StatusNoContent)
}
