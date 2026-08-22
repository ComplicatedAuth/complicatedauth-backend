package api

import (
	"net/http"
	"time"

	security "github.com/dokosoko/complicatedauth-backend/internal/auth"
	"github.com/google/uuid"
)

func (s *Server) runtimePassword(w http.ResponseWriter, r *http.Request) {
	projectUID := r.PathValue("project_uid")
	var in struct{ Email, Password string }
	if !decode(w, r, &in) {
		return
	}
	var userUID, hash, status string
	err := s.db.QueryRow(r.Context(), `SELECT uid,password_hash,status FROM project_users WHERE project_uid=$1 AND email_normalized=$2`, projectUID, normalizeEmail(in.Email)).Scan(&userUID, &hash, &status)
	valid, _ := security.VerifyPassword(hash, in.Password)
	if err != nil || !valid || status != "active" {
		fail(w, r, 401, "invalid_credentials", "email or password is incorrect")
		return
	}
	token, err := security.RandomToken()
	if err != nil {
		fail(w, r, 500, "internal_error", "could not create session")
		return
	}
	expires, idle := time.Now().Add(s.cfg.UserAbsoluteTTL), time.Now().Add(s.cfg.UserIdleTTL)
	_, err = s.db.Exec(r.Context(), `INSERT INTO project_user_sessions(uid,project_uid,project_user_uid,session_secret_hash,expires_at,idle_expires_at) VALUES($1,$2,$3,$4,$5,$6)`, uuid.NewString(), projectUID, userUID, security.SessionHash(token), expires, idle)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not create session")
		return
	}
	user, _ := s.loadProjectUser(r.Context(), projectUID, userUID)
	tenant, _ := s.projectTenant(r.Context(), projectUID)
	s.audit(r.Context(), tenant, projectUID, "service_account", contextString(r, "serviceAccountUID"), "project_user.password_authenticated", "project_user", userUID, map[string]any{"service_credential_uid": contextString(r, "serviceCredentialUID")}, r)
	writeJSON(w, 200, map[string]any{"session_reference": token, "expires_at": expires, "project_user": user})
}

func (s *Server) runtimeIntrospect(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SessionReference string `json:"session_reference"`
	}
	if !decode(w, r, &in) {
		return
	}
	user, expires, ok := s.resolveUserSession(r, in.SessionReference)
	if !ok {
		fail(w, r, 401, "invalid_session", "session is invalid or expired")
		return
	}
	writeJSON(w, 200, map[string]any{"active": true, "expires_at": expires, "project_user": user})
}
func (s *Server) runtimeRevoke(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SessionReference string `json:"session_reference"`
	}
	if !decode(w, r, &in) {
		return
	}
	result, err := s.db.Exec(r.Context(), `UPDATE project_user_sessions SET revoked_at=now() WHERE project_uid=$1 AND session_secret_hash=$2 AND revoked_at IS NULL`, r.PathValue("project_uid"), security.SessionHash(in.SessionReference))
	if err != nil || result.RowsAffected() == 0 {
		fail(w, r, 401, "invalid_session", "session is invalid")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) resolveUserSession(r *http.Request, token string) (ProjectUser, time.Time, bool) {
	projectUID := r.PathValue("project_uid")
	var userUID string
	var expires, idle time.Time
	err := s.db.QueryRow(r.Context(), `SELECT s.project_user_uid,s.expires_at,s.idle_expires_at FROM project_user_sessions s JOIN project_users u ON u.uid=s.project_user_uid JOIN projects p ON p.uid=s.project_uid WHERE s.project_uid=$1 AND s.session_secret_hash=$2 AND s.revoked_at IS NULL AND u.status='active' AND p.status='active'`, projectUID, security.SessionHash(token)).Scan(&userUID, &expires, &idle)
	if err != nil || time.Now().After(expires) || time.Now().After(idle) {
		return ProjectUser{}, time.Time{}, false
	}
	_, _ = s.db.Exec(r.Context(), `UPDATE project_user_sessions SET last_seen_at=now(),idle_expires_at=LEAST(expires_at,now()+interval '7 days') WHERE project_uid=$1 AND session_secret_hash=$2`, projectUID, security.SessionHash(token))
	user, err := s.loadProjectUser(r.Context(), projectUID, userUID)
	return user, expires, err == nil
}
