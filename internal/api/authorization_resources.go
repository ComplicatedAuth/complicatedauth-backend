package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/complicatedauth/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var delegatedScopePattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,119}$`)

func scanResourceServer(row rowScanner) (ResourceServer, error) {
	var value ResourceServer
	err := row.Scan(&value.UID, &value.Name, &value.Identifier, &value.Status, &value.Version, &value.PolicyVersion, &value.CreatedAt, &value.UpdatedAt)
	return value, err
}

const resourceServerSelect = `SELECT uid,name,identifier,status,version,policy_version,created_at,updated_at FROM resource_servers`

func (s *Server) loadResourceServer(ctx context.Context, tenantUID, resourceServerUID string) (ResourceServer, error) {
	return scanResourceServer(s.db.QueryRow(ctx, resourceServerSelect+` WHERE tenant_uid=$1 AND uid=$2 AND deleted_at IS NULL`, tenantUID, resourceServerUID))
}

func (s *Server) listResourceServers(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	query := resourceServerSelect + ` WHERE tenant_uid=$1 AND deleted_at IS NULL`
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), query+` ORDER BY created_at DESC,uid DESC LIMIT $2`, p.TenantUID, limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), query+` AND (created_at,uid)<($2,$3::uuid) ORDER BY created_at DESC,uid DESC LIMIT $4`, p.TenantUID, cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Resource Servers")
		return
	}
	defer rows.Close()
	items := make([]ResourceServer, 0, limit)
	for rows.Next() {
		item, scanErr := scanResourceServer(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Resource Servers")
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

func (s *Server) getResourceServer(w http.ResponseWriter, r *http.Request) {
	value, err := s.loadResourceServer(r.Context(), mustPrincipal(r).TenantUID, r.PathValue("resource_server_uid"))
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "resource_server_not_found", "Resource Server was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Resource Server")
		return
	}
	setVersionETag(w, value.Version)
	writeJSON(w, http.StatusOK, value)
}

type createResourceServerInput struct {
	Name       string `json:"name"`
	Identifier string `json:"identifier"`
}

func normalizeResourceServerInput(in *createResourceServerInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 120 {
		return errors.New("name must contain between 1 and 120 characters")
	}
	identifier, err := normalizeResourceIdentifier(in.Identifier)
	if err != nil {
		return err
	}
	in.Identifier = identifier
	return nil
}

func normalizeResourceIdentifier(value string) (string, error) {
	value = strings.TrimSpace(value)
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return "", errors.New("identifier must be an absolute URI without credentials, query, or fragment")
	}
	developmentHTTP := parsed.Scheme == "http" && isLocalDevelopmentHostname(parsed.Hostname())
	if parsed.Scheme != "https" && !developmentHTTP {
		return "", errors.New("identifier must use HTTPS except for localhost or literal-IP development")
	}
	if len(parsed.String()) > 2048 {
		return "", errors.New("identifier must not exceed 2048 characters")
	}
	return parsed.String(), nil
}

func (s *Server) createResourceServer(w http.ResponseWriter, r *http.Request) {
	var in createResourceServerInput
	if !decode(w, r, &in) {
		return
	}
	if err := normalizeResourceServerInput(&in); err != nil {
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
	idem := store.IdempotencyRequest{PrincipalType: "tenant_member", PrincipalUID: p.MemberUID, Operation: "resource_servers.create", Key: key, RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour}
	claim, ok := s.beginIdempotentRequest(w, r, idem)
	if !ok {
		return
	}
	now := time.Now()
	value := ResourceServer{UID: uuid.NewString(), Name: in.Name, Identifier: in.Identifier, Status: "active", Version: 1, PolicyVersion: 1, CreatedAt: now, UpdatedAt: now}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create Resource Server")
		return
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO resource_servers(uid,tenant_uid,name,identifier,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5)`, value.UID, p.TenantUID, value.Name, value.Identifier, now)
	if err != nil {
		if strings.Contains(err.Error(), "resource_servers_tenant_uid_identifier_key") {
			fail(w, r, http.StatusConflict, "resource_server_identifier_exists", "a Resource Server with this identifier already exists")
		} else {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not create Resource Server")
		}
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,'tenant_member',$3,'resource_server.created','resource_server',$4,$5)`, uuid.NewString(), p.TenantUID, p.MemberUID, value.UID, map[string]any{"identifier": value.Identifier})
	response := storedResourceResponse(http.StatusCreated, "/v1/resource-servers/"+value.UID, value.Version, value)
	if err != nil || s.idempotency.CompleteTx(r.Context(), tx, idem, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create Resource Server")
		return
	}
	writeStoredResponse(w, response)
}

func storedResourceResponse(status int, location string, version int64, value any) store.StoredHTTPResponse {
	body, _ := json.Marshal(value)
	body = append(body, '\n')
	headers := map[string][]string{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}, "ETag": {versionETag(version)}}
	if location != "" {
		headers["Location"] = []string{location}
	}
	return store.StoredHTTPResponse{Status: status, Headers: headers, Body: body}
}

func (s *Server) updateResourceServer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   *string `json:"name"`
		Status *string `json:"status"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Name == nil && in.Status == nil {
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
	expected, ok := requireIfMatch(w, r)
	if !ok {
		return
	}
	p := mustPrincipal(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update Resource Server")
		return
	}
	defer tx.Rollback(r.Context())
	var name, status string
	var version int64
	err = tx.QueryRow(r.Context(), `SELECT name,status,version FROM resource_servers WHERE tenant_uid=$1 AND uid=$2 AND deleted_at IS NULL FOR UPDATE`, p.TenantUID, r.PathValue("resource_server_uid")).Scan(&name, &status, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "resource_server_not_found", "Resource Server was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update Resource Server")
		return
	}
	if version != expected {
		w.Header().Set("ETag", versionETag(version))
		fail(w, r, http.StatusPreconditionFailed, "version_conflict", "Resource Server changed; fetch the latest representation and retry")
		return
	}
	if in.Name != nil {
		name = *in.Name
	}
	if in.Status != nil {
		status = *in.Status
	}
	version++
	_, err = tx.Exec(r.Context(), `UPDATE resource_servers SET name=$3,status=$4,version=$5,policy_version=policy_version+1,updated_at=now() WHERE tenant_uid=$1 AND uid=$2`, p.TenantUID, r.PathValue("resource_server_uid"), name, status, version)
	if err == nil && status == "disabled" {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE resource_server_uid=$1`, r.PathValue("resource_server_uid"))
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,'tenant_member',$3,'resource_server.updated','resource_server',$4,$5)`, uuid.NewString(), p.TenantUID, p.MemberUID, r.PathValue("resource_server_uid"), map[string]any{"status": status, "version": version})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update Resource Server")
		return
	}
	value, err := s.loadResourceServer(r.Context(), p.TenantUID, r.PathValue("resource_server_uid"))
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Resource Server")
		return
	}
	setVersionETag(w, value.Version)
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) deleteResourceServer(w http.ResponseWriter, r *http.Request) {
	expected, ok := requireIfMatch(w, r)
	if !ok {
		return
	}
	p := mustPrincipal(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete Resource Server")
		return
	}
	defer tx.Rollback(r.Context())
	var version int64
	err = tx.QueryRow(r.Context(), `SELECT version FROM resource_servers WHERE tenant_uid=$1 AND uid=$2 AND deleted_at IS NULL FOR UPDATE`, p.TenantUID, r.PathValue("resource_server_uid")).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "resource_server_not_found", "Resource Server was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete Resource Server")
		return
	}
	if version != expected {
		w.Header().Set("ETag", versionETag(version))
		fail(w, r, http.StatusPreconditionFailed, "version_conflict", "Resource Server changed; fetch the latest representation and retry")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE resource_servers SET status='disabled',version=version+1,policy_version=policy_version+1,updated_at=now(),deleted_at=now() WHERE tenant_uid=$1 AND uid=$2`, p.TenantUID, r.PathValue("resource_server_uid"))
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE resource_server_uid=$1`, r.PathValue("resource_server_uid"))
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid) VALUES($1,$2,'tenant_member',$3,'resource_server.deleted','resource_server',$4)`, uuid.NewString(), p.TenantUID, p.MemberUID, r.PathValue("resource_server_uid"))
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete Resource Server")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func scanResourceServerScope(row rowScanner) (ResourceServerScope, error) {
	var value ResourceServerScope
	err := row.Scan(&value.UID, &value.Name, &value.DisplayName, &value.Description, &value.Status, &value.Version, &value.CreatedAt, &value.UpdatedAt)
	return value, err
}

const resourceServerScopeSelect = `SELECT uid,name,display_name,description,status,version,created_at,updated_at FROM resource_server_scopes`

func (s *Server) listResourceServerScopes(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	if _, err := s.loadResourceServer(r.Context(), p.TenantUID, r.PathValue("resource_server_uid")); errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "resource_server_not_found", "Resource Server was not found")
		return
	} else if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Resource Server")
		return
	}
	rows, err := s.db.Query(r.Context(), resourceServerScopeSelect+` WHERE resource_server_uid=$1 AND deleted_at IS NULL ORDER BY created_at DESC,uid DESC`, r.PathValue("resource_server_uid"))
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Resource Server scopes")
		return
	}
	defer rows.Close()
	items := []ResourceServerScope{}
	for rows.Next() {
		value, scanErr := scanResourceServerScope(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Resource Server scopes")
			return
		}
		items = append(items, value)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getResourceServerScope(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	value, err := scanResourceServerScope(s.db.QueryRow(r.Context(), resourceServerScopeSelect+` WHERE uid=$1 AND resource_server_uid=$2 AND deleted_at IS NULL AND EXISTS (SELECT 1 FROM resource_servers WHERE uid=$2 AND tenant_uid=$3 AND deleted_at IS NULL)`, r.PathValue("scope_uid"), r.PathValue("resource_server_uid"), p.TenantUID))
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "resource_server_scope_not_found", "Resource Server scope was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Resource Server scope")
		return
	}
	setVersionETag(w, value.Version)
	writeJSON(w, http.StatusOK, value)
}

type createResourceServerScopeInput struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

func normalizeResourceServerScopeInput(in *createResourceServerScopeInput) error {
	in.Name = strings.TrimSpace(in.Name)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.Description = strings.TrimSpace(in.Description)
	if !delegatedScopePattern.MatchString(in.Name) || oidcScopes[in.Name] || in.Name == "offline_access" {
		return errors.New("name must be a lowercase delegated scope token and must not reserve an OpenID scope")
	}
	if in.DisplayName == "" || len(in.DisplayName) > 120 {
		return errors.New("display_name must contain between 1 and 120 characters")
	}
	if len(in.Description) > 500 {
		return errors.New("description must not exceed 500 characters")
	}
	return nil
}

func (s *Server) createResourceServerScope(w http.ResponseWriter, r *http.Request) {
	var in createResourceServerScopeInput
	if !decode(w, r, &in) {
		return
	}
	if err := normalizeResourceServerScopeInput(&in); err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		fail(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required")
		return
	}
	p := mustPrincipal(r)
	canonical, _ := json.Marshal(struct {
		ResourceServerUID string                         `json:"resource_server_uid"`
		Input             createResourceServerScopeInput `json:"input"`
	}{ResourceServerUID: r.PathValue("resource_server_uid"), Input: in})
	idem := store.IdempotencyRequest{PrincipalType: "tenant_member", PrincipalUID: p.MemberUID, Operation: "resource_server_scopes.create", Key: key, RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour}
	claim, ok := s.beginIdempotentRequest(w, r, idem)
	if !ok {
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create Resource Server scope")
		return
	}
	defer tx.Rollback(r.Context())
	var serverStatus string
	err = tx.QueryRow(r.Context(), `SELECT status FROM resource_servers WHERE uid=$1 AND tenant_uid=$2 AND deleted_at IS NULL FOR UPDATE`, r.PathValue("resource_server_uid"), p.TenantUID).Scan(&serverStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "resource_server_not_found", "Resource Server was not found")
		return
	}
	if err != nil || serverStatus != "active" {
		fail(w, r, http.StatusConflict, "resource_server_inactive", "Resource Server must be active")
		return
	}
	now := time.Now()
	value := ResourceServerScope{UID: uuid.NewString(), Name: in.Name, DisplayName: in.DisplayName, Description: in.Description, Status: "active", Version: 1, CreatedAt: now, UpdatedAt: now}
	_, err = tx.Exec(r.Context(), `INSERT INTO resource_server_scopes(uid,resource_server_uid,name,display_name,description,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$6)`, value.UID, r.PathValue("resource_server_uid"), value.Name, value.DisplayName, value.Description, now)
	if err != nil {
		if strings.Contains(err.Error(), "resource_server_scopes_resource_server_uid_name_key") {
			fail(w, r, http.StatusConflict, "resource_server_scope_exists", "this scope name is already reserved for the Resource Server")
		} else {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not create Resource Server scope")
		}
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE resource_servers SET policy_version=policy_version+1,updated_at=now() WHERE uid=$1`, r.PathValue("resource_server_uid"))
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,'tenant_member',$3,'resource_server_scope.created','resource_server_scope',$4,$5)`, uuid.NewString(), p.TenantUID, p.MemberUID, value.UID, map[string]any{"name": value.Name, "resource_server_uid": r.PathValue("resource_server_uid")})
	}
	location := fmt.Sprintf("/v1/resource-servers/%s/scopes/%s", r.PathValue("resource_server_uid"), value.UID)
	response := storedResourceResponse(http.StatusCreated, location, value.Version, value)
	if err != nil || s.idempotency.CompleteTx(r.Context(), tx, idem, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create Resource Server scope")
		return
	}
	writeStoredResponse(w, response)
}

func (s *Server) updateResourceServerScope(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DisplayName *string `json:"display_name"`
		Description *string `json:"description"`
		Status      *string `json:"status"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.DisplayName == nil && in.Description == nil && in.Status == nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "at least one field is required")
		return
	}
	if in.DisplayName != nil {
		value := strings.TrimSpace(*in.DisplayName)
		if value == "" || len(value) > 120 {
			fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "display_name must contain between 1 and 120 characters")
			return
		}
		in.DisplayName = &value
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
	expected, ok := requireIfMatch(w, r)
	if !ok {
		return
	}
	p := mustPrincipal(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update Resource Server scope")
		return
	}
	defer tx.Rollback(r.Context())
	var displayName, description, status, name string
	var version int64
	err = tx.QueryRow(r.Context(), `SELECT s.display_name,s.description,s.status,s.version,s.name FROM resource_server_scopes s JOIN resource_servers r ON r.uid=s.resource_server_uid WHERE s.uid=$1 AND s.resource_server_uid=$2 AND s.deleted_at IS NULL AND r.tenant_uid=$3 AND r.deleted_at IS NULL FOR UPDATE OF s,r`, r.PathValue("scope_uid"), r.PathValue("resource_server_uid"), p.TenantUID).Scan(&displayName, &description, &status, &version, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "resource_server_scope_not_found", "Resource Server scope was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update Resource Server scope")
		return
	}
	if version != expected {
		w.Header().Set("ETag", versionETag(version))
		fail(w, r, http.StatusPreconditionFailed, "version_conflict", "Resource Server scope changed; fetch the latest representation and retry")
		return
	}
	if in.DisplayName != nil {
		displayName = *in.DisplayName
	}
	if in.Description != nil {
		description = *in.Description
	}
	if in.Status != nil {
		status = *in.Status
	}
	version++
	_, err = tx.Exec(r.Context(), `UPDATE resource_server_scopes SET display_name=$3,description=$4,status=$5,version=$6,updated_at=now() WHERE uid=$1 AND resource_server_uid=$2`, r.PathValue("scope_uid"), r.PathValue("resource_server_uid"), displayName, description, status, version)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE resource_servers SET policy_version=policy_version+1,updated_at=now() WHERE uid=$1`, r.PathValue("resource_server_uid"))
	}
	if err == nil && status == "disabled" {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE resource_server_uid=$1 AND scopes @> ARRAY[$2]::text[]`, r.PathValue("resource_server_uid"), name)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update Resource Server scope")
		return
	}
	value, err := scanResourceServerScope(s.db.QueryRow(r.Context(), resourceServerScopeSelect+` WHERE uid=$1 AND resource_server_uid=$2`, r.PathValue("scope_uid"), r.PathValue("resource_server_uid")))
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Resource Server scope")
		return
	}
	setVersionETag(w, value.Version)
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) deleteResourceServerScope(w http.ResponseWriter, r *http.Request) {
	expected, ok := requireIfMatch(w, r)
	if !ok {
		return
	}
	p := mustPrincipal(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete Resource Server scope")
		return
	}
	defer tx.Rollback(r.Context())
	var version int64
	var name string
	err = tx.QueryRow(r.Context(), `SELECT s.version,s.name FROM resource_server_scopes s JOIN resource_servers r ON r.uid=s.resource_server_uid WHERE s.uid=$1 AND s.resource_server_uid=$2 AND s.deleted_at IS NULL AND r.tenant_uid=$3 AND r.deleted_at IS NULL FOR UPDATE OF s,r`, r.PathValue("scope_uid"), r.PathValue("resource_server_uid"), p.TenantUID).Scan(&version, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "resource_server_scope_not_found", "Resource Server scope was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete Resource Server scope")
		return
	}
	if version != expected {
		w.Header().Set("ETag", versionETag(version))
		fail(w, r, http.StatusPreconditionFailed, "version_conflict", "Resource Server scope changed; fetch the latest representation and retry")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE resource_server_scopes SET status='disabled',version=version+1,updated_at=now(),deleted_at=now() WHERE uid=$1`, r.PathValue("scope_uid"))
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE resource_servers SET policy_version=policy_version+1,updated_at=now() WHERE uid=$1`, r.PathValue("resource_server_uid"))
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE resource_server_uid=$1 AND scopes @> ARRAY[$2]::text[]`, r.PathValue("resource_server_uid"), name)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete Resource Server scope")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func scanOAuthApplicationGrant(row rowScanner) (OAuthApplicationGrant, error) {
	var value OAuthApplicationGrant
	err := row.Scan(&value.UID, &value.ApplicationUID, &value.ResourceServerUID, &value.ResourceServerName, &value.ResourceServerIdentifier, &value.Status, &value.Version, &value.Scopes, &value.CreatedAt, &value.UpdatedAt)
	if value.Scopes == nil {
		value.Scopes = []string{}
	}
	return value, err
}

const oauthApplicationGrantSelect = `
	SELECT g.uid,g.application_uid,g.resource_server_uid,r.name,r.identifier,g.status,g.version,
		COALESCE(array_agg(s.name ORDER BY s.name) FILTER (WHERE s.uid IS NOT NULL),'{}'),g.created_at,g.updated_at
	FROM oauth_application_grants g
	JOIN resource_servers r ON r.uid=g.resource_server_uid
	LEFT JOIN oauth_application_grant_scopes gs ON gs.grant_uid=g.uid
	LEFT JOIN resource_server_scopes s ON s.uid=gs.scope_uid
`

func (s *Server) loadOAuthApplicationGrant(ctx context.Context, tenantUID, applicationUID, grantUID string) (OAuthApplicationGrant, error) {
	return scanOAuthApplicationGrant(s.db.QueryRow(ctx, oauthApplicationGrantSelect+` WHERE g.uid=$1 AND g.application_uid=$2 AND g.tenant_uid=$3 AND g.deleted_at IS NULL GROUP BY g.uid,r.uid`, grantUID, applicationUID, tenantUID))
}

func (s *Server) listOAuthApplicationGrants(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	rows, err := s.db.Query(r.Context(), oauthApplicationGrantSelect+` WHERE g.application_uid=$1 AND g.tenant_uid=$2 AND g.deleted_at IS NULL GROUP BY g.uid,r.uid ORDER BY g.created_at DESC,g.uid DESC`, r.PathValue("application_uid"), p.TenantUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load OAuth Application grants")
		return
	}
	defer rows.Close()
	items := []OAuthApplicationGrant{}
	for rows.Next() {
		value, scanErr := scanOAuthApplicationGrant(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load OAuth Application grants")
			return
		}
		items = append(items, value)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getOAuthApplicationGrant(w http.ResponseWriter, r *http.Request) {
	value, err := s.loadOAuthApplicationGrant(r.Context(), mustPrincipal(r).TenantUID, r.PathValue("application_uid"), r.PathValue("grant_uid"))
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "oauth_application_grant_not_found", "OAuth Application grant was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load OAuth Application grant")
		return
	}
	setVersionETag(w, value.Version)
	writeJSON(w, http.StatusOK, value)
}

type createOAuthApplicationGrantInput struct {
	ResourceServerUID string   `json:"resource_server_uid"`
	ScopeUIDs         []string `json:"scope_uids"`
}

func normalizeScopeUIDs(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 100 {
		return nil, errors.New("scope_uids must contain between 1 and 100 values")
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, err := uuid.Parse(value); err != nil || seen[value] {
			return nil, errors.New("scope_uids must contain unique UUIDs")
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func validateGrantResources(ctx context.Context, tx pgx.Tx, tenantUID, applicationUID, resourceServerUID string, scopeUIDs []string) error {
	var active bool
	err := tx.QueryRow(ctx, `SELECT a.status='active' AND r.status='active' FROM oauth_applications a JOIN resource_servers r ON r.uid=$2 AND r.tenant_uid=a.tenant_uid WHERE a.uid=$1 AND a.tenant_uid=$3 AND a.deleted_at IS NULL AND r.deleted_at IS NULL`, applicationUID, resourceServerUID, tenantUID).Scan(&active)
	if err != nil || !active {
		return errors.New("the OAuth Application and Resource Server must exist and be active")
	}
	var count int
	err = tx.QueryRow(ctx, `SELECT count(*) FROM resource_server_scopes WHERE resource_server_uid=$1 AND uid=ANY($2::uuid[]) AND status='active' AND deleted_at IS NULL`, resourceServerUID, scopeUIDs).Scan(&count)
	if err != nil || count != len(scopeUIDs) {
		return errors.New("every scope_uid must name an active scope on the Resource Server")
	}
	return nil
}

func (s *Server) createOAuthApplicationGrant(w http.ResponseWriter, r *http.Request) {
	var in createOAuthApplicationGrantInput
	if !decode(w, r, &in) {
		return
	}
	if _, err := uuid.Parse(in.ResourceServerUID); err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "resource_server_uid must be a UUID")
		return
	}
	values, err := normalizeScopeUIDs(in.ScopeUIDs)
	if err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
		return
	}
	in.ScopeUIDs = values
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		fail(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required")
		return
	}
	p := mustPrincipal(r)
	canonical, _ := json.Marshal(struct {
		ApplicationUID string                           `json:"application_uid"`
		Input          createOAuthApplicationGrantInput `json:"input"`
	}{ApplicationUID: r.PathValue("application_uid"), Input: in})
	idem := store.IdempotencyRequest{PrincipalType: "tenant_member", PrincipalUID: p.MemberUID, Operation: "oauth_application_grants.create", Key: key, RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour}
	claim, ok := s.beginIdempotentRequest(w, r, idem)
	if !ok {
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create OAuth Application grant")
		return
	}
	defer tx.Rollback(r.Context())
	if err = validateGrantResources(r.Context(), tx, p.TenantUID, r.PathValue("application_uid"), in.ResourceServerUID, in.ScopeUIDs); err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "invalid_grant_resources", err.Error())
		return
	}
	grantUID := uuid.NewString()
	_, err = tx.Exec(r.Context(), `INSERT INTO oauth_application_grants(uid,tenant_uid,application_uid,resource_server_uid) VALUES($1,$2,$3,$4)`, grantUID, p.TenantUID, r.PathValue("application_uid"), in.ResourceServerUID)
	if err != nil {
		if strings.Contains(err.Error(), "oauth_application_grants_active_relationship_idx") {
			fail(w, r, http.StatusConflict, "oauth_application_grant_exists", "this OAuth Application already has a grant for the Resource Server")
		} else {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not create OAuth Application grant")
		}
		return
	}
	for _, scopeUID := range in.ScopeUIDs {
		_, err = tx.Exec(r.Context(), `INSERT INTO oauth_application_grant_scopes(grant_uid,scope_uid) VALUES($1,$2)`, grantUID, scopeUID)
		if err != nil {
			break
		}
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE resource_servers SET policy_version=policy_version+1,updated_at=now() WHERE uid=$1`, in.ResourceServerUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,'tenant_member',$3,'oauth_application_grant.created','oauth_application_grant',$4,$5)`, uuid.NewString(), p.TenantUID, p.MemberUID, grantUID, map[string]any{"application_uid": r.PathValue("application_uid"), "resource_server_uid": in.ResourceServerUID})
	}
	value, loadErr := scanOAuthApplicationGrant(tx.QueryRow(r.Context(), oauthApplicationGrantSelect+` WHERE g.uid=$1 GROUP BY g.uid,r.uid`, grantUID))
	if loadErr != nil {
		err = loadErr
	}
	location := fmt.Sprintf("/v1/oauth/applications/%s/grants/%s", r.PathValue("application_uid"), grantUID)
	response := storedResourceResponse(http.StatusCreated, location, value.Version, value)
	if err != nil || s.idempotency.CompleteTx(r.Context(), tx, idem, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create OAuth Application grant")
		return
	}
	writeStoredResponse(w, response)
}

func (s *Server) updateOAuthApplicationGrant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Status    *string   `json:"status"`
		ScopeUIDs *[]string `json:"scope_uids"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Status == nil && in.ScopeUIDs == nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "at least one field is required")
		return
	}
	if in.Status != nil && *in.Status != "active" && *in.Status != "disabled" {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "status must be active or disabled")
		return
	}
	if in.ScopeUIDs != nil {
		values, err := normalizeScopeUIDs(*in.ScopeUIDs)
		if err != nil {
			fail(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
			return
		}
		in.ScopeUIDs = &values
	}
	expected, ok := requireIfMatch(w, r)
	if !ok {
		return
	}
	p := mustPrincipal(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update OAuth Application grant")
		return
	}
	defer tx.Rollback(r.Context())
	var resourceServerUID, status string
	var version int64
	err = tx.QueryRow(r.Context(), `SELECT resource_server_uid,status,version FROM oauth_application_grants WHERE uid=$1 AND application_uid=$2 AND tenant_uid=$3 AND deleted_at IS NULL FOR UPDATE`, r.PathValue("grant_uid"), r.PathValue("application_uid"), p.TenantUID).Scan(&resourceServerUID, &status, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "oauth_application_grant_not_found", "OAuth Application grant was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update OAuth Application grant")
		return
	}
	if version != expected {
		w.Header().Set("ETag", versionETag(version))
		fail(w, r, http.StatusPreconditionFailed, "version_conflict", "OAuth Application grant changed; fetch the latest representation and retry")
		return
	}
	if in.Status != nil {
		status = *in.Status
	}
	if in.ScopeUIDs != nil {
		if err = validateGrantResources(r.Context(), tx, p.TenantUID, r.PathValue("application_uid"), resourceServerUID, *in.ScopeUIDs); err != nil {
			fail(w, r, http.StatusUnprocessableEntity, "invalid_grant_resources", err.Error())
			return
		}
		_, err = tx.Exec(r.Context(), `DELETE FROM oauth_application_grant_scopes WHERE grant_uid=$1`, r.PathValue("grant_uid"))
		for _, scopeUID := range *in.ScopeUIDs {
			if err != nil {
				break
			}
			_, err = tx.Exec(r.Context(), `INSERT INTO oauth_application_grant_scopes(grant_uid,scope_uid) VALUES($1,$2)`, r.PathValue("grant_uid"), scopeUID)
		}
	}
	version++
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_application_grants SET status=$2,version=$3,updated_at=now() WHERE uid=$1`, r.PathValue("grant_uid"), status, version)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE resource_servers SET policy_version=policy_version+1,updated_at=now() WHERE uid=$1`, resourceServerUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE application_uid=$1 AND resource_server_uid=$2`, r.PathValue("application_uid"), resourceServerUID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update OAuth Application grant")
		return
	}
	value, err := s.loadOAuthApplicationGrant(r.Context(), p.TenantUID, r.PathValue("application_uid"), r.PathValue("grant_uid"))
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load OAuth Application grant")
		return
	}
	setVersionETag(w, value.Version)
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) deleteOAuthApplicationGrant(w http.ResponseWriter, r *http.Request) {
	expected, ok := requireIfMatch(w, r)
	if !ok {
		return
	}
	p := mustPrincipal(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete OAuth Application grant")
		return
	}
	defer tx.Rollback(r.Context())
	var resourceServerUID string
	var version int64
	err = tx.QueryRow(r.Context(), `SELECT resource_server_uid,version FROM oauth_application_grants WHERE uid=$1 AND application_uid=$2 AND tenant_uid=$3 AND deleted_at IS NULL FOR UPDATE`, r.PathValue("grant_uid"), r.PathValue("application_uid"), p.TenantUID).Scan(&resourceServerUID, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "oauth_application_grant_not_found", "OAuth Application grant was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete OAuth Application grant")
		return
	}
	if version != expected {
		w.Header().Set("ETag", versionETag(version))
		fail(w, r, http.StatusPreconditionFailed, "version_conflict", "OAuth Application grant changed; fetch the latest representation and retry")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE oauth_application_grants SET status='disabled',version=version+1,updated_at=now(),deleted_at=now() WHERE uid=$1`, r.PathValue("grant_uid"))
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE resource_servers SET policy_version=policy_version+1,updated_at=now() WHERE uid=$1`, resourceServerUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE application_uid=$1 AND resource_server_uid=$2`, r.PathValue("application_uid"), resourceServerUID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete OAuth Application grant")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
