package api

import (
	"database/sql"
	"net/http"
	"time"

	security "github.com/dokosoko/complicatedauth-backend/internal/auth"
	"github.com/google/uuid"
)

const loginAttemptTTL = 5 * time.Minute

type loginAttemptState struct {
	UID              string
	UserUID          string
	PasswordVerified bool
	ExpiresAt        time.Time
}

func (s *Server) startProjectUserLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &in) {
		return
	}
	email := normalizeEmail(in.Email)
	if !s.takeRateLimit(w, r, "project_login_start", r.PathValue("project_uid")+"\x00"+s.clientIP(r), 50, 15*time.Minute) {
		return
	}
	var userUID *string
	var candidate string
	if err := s.db.QueryRow(r.Context(), `SELECT uid FROM project_users WHERE project_uid=$1 AND email_normalized=$2 AND status='active'`, r.PathValue("project_uid"), email).Scan(&candidate); err == nil {
		userUID = &candidate
	}
	token, err := security.RandomToken()
	if err != nil {
		fail(w, r, 500, "internal_error", "could not start login")
		return
	}
	expires := time.Now().Add(loginAttemptTTL)
	_, err = s.db.Exec(r.Context(), `INSERT INTO project_user_login_attempts(uid,project_uid,project_user_uid,login_secret_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, uuid.NewString(), r.PathValue("project_uid"), userUID, security.SessionHash(token), expires)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not start login")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"login_reference": token, "expires_at": expires})
}

func (s *Server) verifyProjectUserLoginPassword(w http.ResponseWriter, r *http.Request) {
	if !s.takeRateLimit(w, r, "project_login_password", r.PathValue("project_uid")+"\x00"+s.clientIP(r), 10, 15*time.Minute) {
		return
	}
	attempt, ok := s.resolveLoginAttempt(r)
	if !ok {
		fail(w, r, 401, "invalid_login", "login attempt is invalid or expired")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	var hash sql.NullString
	err := s.db.QueryRow(r.Context(), `SELECT password_hash FROM project_users WHERE uid=$1 AND project_uid=$2 AND status='active'`, attempt.UserUID, r.PathValue("project_uid")).Scan(&hash)
	valid, _ := security.VerifyPassword(hash.String, in.Password)
	if err != nil || !hash.Valid || !valid {
		fail(w, r, 401, "invalid_credentials", "credentials are incorrect")
		return
	}
	_, err = s.db.Exec(r.Context(), `UPDATE project_user_login_attempts SET password_verified_at=now() WHERE uid=$1 AND consumed_at IS NULL AND expires_at>now()`, attempt.UID)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not verify factor")
		return
	}
	writeJSON(w, 200, map[string]any{"status": "factor_verified", "factor": "password", "expires_at": attempt.ExpiresAt})
}

func (s *Server) resolveLoginAttempt(r *http.Request) (loginAttemptState, bool) {
	var state loginAttemptState
	var userUID *string
	var passwordVerified *time.Time
	err := s.db.QueryRow(r.Context(), `SELECT uid,project_user_uid,password_verified_at,expires_at FROM project_user_login_attempts WHERE project_uid=$1 AND login_secret_hash=$2 AND consumed_at IS NULL AND expires_at>now()`, r.PathValue("project_uid"), security.SessionHash(r.Header.Get("X-ComplicatedAuth-Login"))).Scan(&state.UID, &userUID, &passwordVerified, &state.ExpiresAt)
	if err != nil || userUID == nil {
		return loginAttemptState{}, false
	}
	state.UserUID = *userUID
	state.PasswordVerified = passwordVerified != nil
	return state, true
}

func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, attempt loginAttemptState, action string) {
	token, err := security.RandomToken()
	if err != nil {
		fail(w, r, 500, "internal_error", "could not create session")
		return
	}
	expires, idle := time.Now().Add(s.cfg.UserAbsoluteTTL), time.Now().Add(s.cfg.UserIdleTTL)
	tx, err := s.db.Begin(r.Context())
	if err == nil {
		var consumed string
		err = tx.QueryRow(r.Context(), `UPDATE project_user_login_attempts SET consumed_at=now() WHERE uid=$1 AND consumed_at IS NULL AND expires_at>now() RETURNING uid`, attempt.UID).Scan(&consumed)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO project_user_sessions(uid,project_uid,project_user_uid,session_secret_hash,expires_at,idle_expires_at) VALUES($1,$2,$3,$4,$5,$6)`, uuid.NewString(), r.PathValue("project_uid"), attempt.UserUID, security.SessionHash(token), expires, idle)
	}
	if err != nil {
		if tx != nil {
			_ = tx.Rollback(r.Context())
		}
		fail(w, r, 401, "invalid_login", "login attempt is invalid, expired, or already used")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		fail(w, r, 500, "internal_error", "could not create session")
		return
	}
	user, err := s.loadProjectUser(r.Context(), r.PathValue("project_uid"), attempt.UserUID)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not load authenticated user")
		return
	}
	tenant, _ := s.projectTenant(r.Context(), r.PathValue("project_uid"))
	s.audit(r.Context(), tenant, r.PathValue("project_uid"), "project_user", user.UID, action, "project_user", user.UID, nil, r)
	writeJSON(w, 200, map[string]any{"session_reference": token, "expires_at": expires, "project_user": user})
}
