package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	security "github.com/dokosoko/complicatedauth-backend/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Server) authorizedProject(r *http.Request) (string, string, bool) {
	projectUID := r.PathValue("project_uid")
	if apiProject, _ := r.Context().Value(contextKey("apiProjectUID")).(string); apiProject != "" {
		tenant, err := s.projectTenant(r.Context(), projectUID)
		return projectUID, tenant, err == nil && apiProject == projectUID
	}
	p, ok := r.Context().Value(principalKey).(principal)
	if !ok || !s.ownsProject(r.Context(), p.TenantUID, projectUID) {
		return projectUID, "", false
	}
	return projectUID, p.TenantUID, true
}
func (s *Server) projectTenant(ctx context.Context, projectUID string) (string, error) {
	var tenant string
	err := s.db.QueryRow(ctx, `SELECT tenant_uid FROM projects WHERE uid=$1`, projectUID).Scan(&tenant)
	return tenant, err
}

func (s *Server) listProjectUsers(w http.ResponseWriter, r *http.Request) {
	projectUID, _, ok := s.authorizedProject(r)
	if !ok {
		fail(w, r, 404, "not_found", "project not found")
		return
	}
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, 400, "invalid_pagination", err.Error())
		return
	}
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), `SELECT u.uid,u.email,(u.email_verified_at IS NOT NULL),u.status,u.created_at,(SELECT count(*) FROM webauthn_credentials c WHERE c.project_uid=u.project_uid AND c.project_user_uid=u.uid) FROM project_users u WHERE u.project_uid=$1 ORDER BY u.created_at DESC,u.uid DESC LIMIT $2`, projectUID, limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), `SELECT u.uid,u.email,(u.email_verified_at IS NOT NULL),u.status,u.created_at,(SELECT count(*) FROM webauthn_credentials c WHERE c.project_uid=u.project_uid AND c.project_user_uid=u.uid) FROM project_users u WHERE u.project_uid=$1 AND (u.created_at,u.uid)<($2,$3::uuid) ORDER BY u.created_at DESC,u.uid DESC LIMIT $4`, projectUID, cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, 500, "internal_error", "could not load users")
		return
	}
	defer rows.Close()
	items := []ProjectUser{}
	for rows.Next() {
		var u ProjectUser
		if rows.Scan(&u.UID, &u.Email, &u.EmailVerified, &u.Status, &u.CreatedAt, &u.PasskeyCount) == nil {
			items = append(items, u)
		}
	}
	var next any
	if len(items) > limit {
		position := items[limit-1]
		next = nextCursor(position.CreatedAt, position.UID)
		items = items[:limit]
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

func (s *Server) createProjectUser(w http.ResponseWriter, r *http.Request) {
	projectUID, tenantUID, ok := s.authorizedProject(r)
	if !ok {
		fail(w, r, 404, "not_found", "project not found")
		return
	}
	var in struct {
		Email, Password string
		EmailVerified   bool `json:"email_verified"`
	}
	if !decode(w, r, &in) {
		return
	}
	email := normalizeEmail(in.Email)
	if email == "" || !strings.Contains(email, "@") {
		fail(w, r, 422, "validation_failed", "valid email is required")
		return
	}
	var passwordHash any
	if in.Password != "" {
		hash, err := security.HashPassword(in.Password)
		if err != nil {
			fail(w, r, 422, "validation_failed", err.Error())
			return
		}
		passwordHash = hash
	}
	user := ProjectUser{UID: uuid.NewString(), Email: email, EmailVerified: in.EmailVerified, Status: "active", CreatedAt: time.Now().UTC()}
	var verified any
	if in.EmailVerified {
		verified = time.Now()
	}
	_, err := s.db.Exec(r.Context(), `INSERT INTO project_users(uid,project_uid,email,email_normalized,email_verified_at,password_hash) VALUES($1,$2,$3,$3,$4,$5)`, user.UID, projectUID, email, verified, passwordHash)
	if err != nil {
		if strings.Contains(err.Error(), "email_normalized") {
			fail(w, r, 409, "email_exists", "email already belongs to a user in this Project")
		} else {
			fail(w, r, 500, "internal_error", "could not create user")
		}
		return
	}
	actorType, actorUID := "api_key", contextString(r, "apiKeyUID")
	if p, ok := r.Context().Value(principalKey).(principal); ok {
		actorType, actorUID = "tenant_member", p.MemberUID
	}
	s.audit(r.Context(), tenantUID, projectUID, actorType, actorUID, "project_user.created", "project_user", user.UID, nil, r)
	writeJSON(w, 201, user)
}

func (s *Server) getProjectUserHandler(w http.ResponseWriter, r *http.Request) {
	projectUID, _, ok := s.authorizedProject(r)
	if !ok {
		fail(w, r, 404, "not_found", "user not found")
		return
	}
	user, err := s.loadProjectUser(r.Context(), projectUID, r.PathValue("user_uid"))
	if err != nil {
		fail(w, r, 404, "not_found", "user not found")
		return
	}
	rows, _ := s.db.Query(r.Context(), `SELECT uid,created_at FROM webauthn_credentials WHERE project_uid=$1 AND project_user_uid=$2 ORDER BY created_at`, projectUID, user.UID)
	passkeys := []map[string]any{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var uid string
			var created time.Time
			if rows.Scan(&uid, &created) == nil {
				passkeys = append(passkeys, map[string]any{"uid": uid, "created_at": created})
			}
		}
	}
	writeJSON(w, 200, map[string]any{"uid": user.UID, "email": user.Email, "email_verified": user.EmailVerified, "status": user.Status, "passkey_count": user.PasskeyCount, "created_at": user.CreatedAt, "passkeys": passkeys})
}

func (s *Server) updateProjectUser(w http.ResponseWriter, r *http.Request) {
	projectUID, tenantUID, ok := s.authorizedProject(r)
	userUID := r.PathValue("user_uid")
	if !ok {
		fail(w, r, 404, "not_found", "user not found")
		return
	}
	user, err := s.loadProjectUser(r.Context(), projectUID, userUID)
	if err != nil {
		fail(w, r, 404, "not_found", "user not found")
		return
	}
	var in struct {
		Email, Status *string
		EmailVerified *bool `json:"email_verified"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Email != nil {
		user.Email = normalizeEmail(*in.Email)
	}
	if in.Status != nil {
		user.Status = *in.Status
	}
	if user.Email == "" || !strings.Contains(user.Email, "@") || (user.Status != "active" && user.Status != "disabled") {
		fail(w, r, 422, "validation_failed", "email or status is invalid")
		return
	}
	var verified any
	if (in.EmailVerified != nil && *in.EmailVerified) || (in.EmailVerified == nil && user.EmailVerified) {
		verified = time.Now()
	}
	_, err = s.db.Exec(r.Context(), `UPDATE project_users SET email=$3,email_normalized=$3,status=$4,email_verified_at=$5,updated_at=now() WHERE uid=$1 AND project_uid=$2`, userUID, projectUID, user.Email, user.Status, verified)
	if err != nil {
		if strings.Contains(err.Error(), "email_normalized") {
			fail(w, r, 409, "email_exists", "email already belongs to a user in this Project")
		} else {
			fail(w, r, 500, "internal_error", "could not update user")
		}
		return
	}
	if user.Status == "disabled" {
		_, _ = s.db.Exec(r.Context(), `UPDATE project_user_sessions SET revoked_at=now() WHERE project_uid=$1 AND project_user_uid=$2 AND revoked_at IS NULL`, projectUID, userUID)
	}
	actorType, actorUID := requestActor(r)
	s.audit(r.Context(), tenantUID, projectUID, actorType, actorUID, "project_user.updated", "project_user", userUID, map[string]any{"status": user.Status}, r)
	user, _ = s.loadProjectUser(r.Context(), projectUID, userUID)
	writeJSON(w, 200, user)
}

func (s *Server) replaceProjectUserPassword(w http.ResponseWriter, r *http.Request) {
	projectUID, tenantUID, ok := s.authorizedProject(r)
	if !ok {
		fail(w, r, 404, "not_found", "user not found")
		return
	}
	var in struct{ Password string }
	if !decode(w, r, &in) {
		return
	}
	hash, err := security.HashPassword(in.Password)
	if err != nil {
		fail(w, r, 422, "validation_failed", err.Error())
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, 500, "internal_error", "could not replace password")
		return
	}
	defer tx.Rollback(r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE project_users SET password_hash=$3,updated_at=now() WHERE uid=$1 AND project_uid=$2`, r.PathValue("user_uid"), projectUID, hash)
	if err == nil && result.RowsAffected() == 1 {
		_, err = tx.Exec(r.Context(), `UPDATE project_user_sessions SET revoked_at=now() WHERE project_uid=$1 AND project_user_uid=$2 AND revoked_at IS NULL`, projectUID, r.PathValue("user_uid"))
	}
	if err != nil || result.RowsAffected() == 0 || tx.Commit(r.Context()) != nil {
		fail(w, r, 404, "not_found", "user not found")
		return
	}
	actorType, actorUID := "api_key", contextString(r, "apiKeyUID")
	if p, ok := r.Context().Value(principalKey).(principal); ok {
		actorType, actorUID = "tenant_member", p.MemberUID
	}
	s.audit(r.Context(), tenantUID, projectUID, actorType, actorUID, "project_user.password_replaced", "project_user", r.PathValue("user_uid"), nil, r)
	w.WriteHeader(204)
}
func (s *Server) revokeProjectUserSessions(w http.ResponseWriter, r *http.Request) {
	projectUID, tenantUID, ok := s.authorizedProject(r)
	if !ok {
		fail(w, r, 404, "not_found", "user not found")
		return
	}
	_, err := s.db.Exec(r.Context(), `UPDATE project_user_sessions SET revoked_at=now() WHERE project_uid=$1 AND project_user_uid=$2 AND revoked_at IS NULL`, projectUID, r.PathValue("user_uid"))
	if err != nil {
		fail(w, r, 500, "internal_error", "could not revoke sessions")
		return
	}
	actorType, actorUID := requestActor(r)
	s.audit(r.Context(), tenantUID, projectUID, actorType, actorUID, "project_user.sessions_revoked", "project_user", r.PathValue("user_uid"), nil, r)
	w.WriteHeader(204)
}
func (s *Server) deletePasskey(w http.ResponseWriter, r *http.Request) {
	projectUID, tenantUID, ok := s.authorizedProject(r)
	if !ok {
		fail(w, r, 404, "not_found", "passkey not found")
		return
	}
	result, err := s.db.Exec(r.Context(), `DELETE FROM webauthn_credentials WHERE uid=$1 AND project_uid=$2 AND project_user_uid=$3`, r.PathValue("credential_uid"), projectUID, r.PathValue("user_uid"))
	if err != nil || result.RowsAffected() == 0 {
		fail(w, r, 404, "not_found", "passkey not found")
		return
	}
	actorType, actorUID := requestActor(r)
	s.audit(r.Context(), tenantUID, projectUID, actorType, actorUID, "passkey.deleted", "passkey", r.PathValue("credential_uid"), nil, r)
	w.WriteHeader(204)
}

func (s *Server) loadProjectUser(ctx context.Context, projectUID, userUID string) (ProjectUser, error) {
	var u ProjectUser
	err := s.db.QueryRow(ctx, `SELECT u.uid,u.email,(u.email_verified_at IS NOT NULL),u.status,u.created_at,(SELECT count(*) FROM webauthn_credentials c WHERE c.project_uid=u.project_uid AND c.project_user_uid=u.uid) FROM project_users u WHERE u.uid=$1 AND u.project_uid=$2`, userUID, projectUID).Scan(&u.UID, &u.Email, &u.EmailVerified, &u.Status, &u.CreatedAt, &u.PasskeyCount)
	return u, err
}

func (s *Server) listActivity(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	projectUID := r.PathValue("project_uid")
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, 400, "invalid_pagination", err.Error())
		return
	}
	var rows pgx.Rows
	if projectUID != "" {
		if !s.ownsProject(r.Context(), p.TenantUID, projectUID) {
			fail(w, r, 404, "not_found", "project not found")
			return
		}
		if cursor == nil {
			rows, err = s.db.Query(r.Context(), `SELECT uid,action,actor_type,actor_uid,target_type,target_uid,metadata,created_at FROM audit_events WHERE tenant_uid=$1 AND project_uid=$2 ORDER BY created_at DESC,uid DESC LIMIT $3`, p.TenantUID, projectUID, limit+1)
		} else {
			rows, err = s.db.Query(r.Context(), `SELECT uid,action,actor_type,actor_uid,target_type,target_uid,metadata,created_at FROM audit_events WHERE tenant_uid=$1 AND project_uid=$2 AND (created_at,uid)<($3,$4::uuid) ORDER BY created_at DESC,uid DESC LIMIT $5`, p.TenantUID, projectUID, cursor.CreatedAt, cursor.UID, limit+1)
		}
	} else {
		if cursor == nil {
			rows, err = s.db.Query(r.Context(), `SELECT uid,action,actor_type,actor_uid,target_type,target_uid,metadata,created_at FROM audit_events WHERE tenant_uid=$1 ORDER BY created_at DESC,uid DESC LIMIT $2`, p.TenantUID, limit+1)
		} else {
			rows, err = s.db.Query(r.Context(), `SELECT uid,action,actor_type,actor_uid,target_type,target_uid,metadata,created_at FROM audit_events WHERE tenant_uid=$1 AND (created_at,uid)<($2,$3::uuid) ORDER BY created_at DESC,uid DESC LIMIT $4`, p.TenantUID, cursor.CreatedAt, cursor.UID, limit+1)
		}
	}
	if err != nil {
		fail(w, r, 500, "internal_error", "could not load activity")
		return
	}
	defer rows.Close()
	items := []AuditEvent{}
	for rows.Next() {
		var event AuditEvent
		if rows.Scan(&event.UID, &event.Action, &event.ActorType, &event.ActorUID, &event.TargetType, &event.TargetUID, &event.Metadata, &event.CreatedAt) == nil {
			items = append(items, event)
		}
	}
	var next any
	if len(items) > limit {
		position := items[limit-1]
		next = nextCursor(position.CreatedAt, position.UID)
		items = items[:limit]
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

func contextString(r *http.Request, key string) string {
	value, _ := r.Context().Value(contextKey(key)).(string)
	return value
}

func requestActor(r *http.Request) (string, string) {
	if p, ok := r.Context().Value(principalKey).(principal); ok {
		return "tenant_member", p.MemberUID
	}
	return "api_key", contextString(r, "apiKeyUID")
}
