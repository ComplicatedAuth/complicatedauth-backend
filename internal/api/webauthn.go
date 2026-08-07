package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	security "github.com/dokosoko/complicatedauth-backend/internal/auth"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

type webUser struct {
	UID, Email  string
	Credentials []webauthn.Credential
}

func (u webUser) WebAuthnID() []byte                         { return []byte(u.UID) }
func (u webUser) WebAuthnName() string                       { return u.Email }
func (u webUser) WebAuthnDisplayName() string                { return u.Email }
func (u webUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

func (s *Server) webAuthnForProject(ctx context.Context, projectUID string) (*webauthn.WebAuthn, error) {
	var rpID, rpName, status string
	if err := s.db.QueryRow(ctx, `SELECT rp_id,rp_name,status FROM projects WHERE uid=$1`, projectUID).Scan(&rpID, &rpName, &status); err != nil {
		return nil, err
	}
	if status != "active" {
		return nil, errors.New("project is disabled")
	}
	rows, err := s.db.Query(ctx, `SELECT origin FROM project_origins WHERE project_uid=$1 ORDER BY created_at`, projectUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	origins := []string{}
	for rows.Next() {
		var origin string
		if err = rows.Scan(&origin); err != nil {
			return nil, err
		}
		origins = append(origins, origin)
	}
	return webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: rpName, RPOrigins: origins, Timeouts: webauthn.TimeoutsConfig{Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute, TimeoutUVD: 5 * time.Minute}, Login: webauthn.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute, TimeoutUVD: 5 * time.Minute}}})
}

func (s *Server) loadWebUser(ctx context.Context, projectUID, userUID string) (webUser, error) {
	var u webUser
	if err := s.db.QueryRow(ctx, `SELECT uid,email FROM project_users WHERE uid=$1 AND project_uid=$2 AND status='active'`, userUID, projectUID).Scan(&u.UID, &u.Email); err != nil {
		return u, err
	}
	rows, err := s.db.Query(ctx, `SELECT credential_json FROM webauthn_credentials WHERE project_uid=$1 AND project_user_uid=$2`, projectUID, userUID)
	if err != nil {
		return u, err
	}
	defer rows.Close()
	u.Credentials = []webauthn.Credential{}
	for rows.Next() {
		var raw []byte
		var credential webauthn.Credential
		if err = rows.Scan(&raw); err != nil {
			return u, err
		}
		if err = json.Unmarshal(raw, &credential); err != nil {
			return u, err
		}
		u.Credentials = append(u.Credentials, credential)
	}
	return u, rows.Err()
}

func (s *Server) beginRegistration(w http.ResponseWriter, r *http.Request) {
	reference := r.Header.Get("X-ComplicatedAuth-Session")
	user, _, ok := s.resolveUserSession(r, reference)
	if !ok {
		fail(w, r, 401, "invalid_session", "active Project User session required")
		return
	}
	projectUID := r.PathValue("project_uid")
	wa, err := s.webAuthnForProject(r.Context(), projectUID)
	if err != nil {
		fail(w, r, 422, "webauthn_configuration", "Project WebAuthn configuration is invalid")
		return
	}
	wu, err := s.loadWebUser(r.Context(), projectUID, user.UID)
	if err != nil {
		fail(w, r, 404, "not_found", "Project User not found")
		return
	}
	options, session, err := wa.BeginRegistration(wu, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired))
	if err != nil {
		fail(w, r, 422, "webauthn_begin_failed", err.Error())
		return
	}
	sessionRaw, _ := json.Marshal(session)
	ceremonyUID := uuid.NewString()
	_, err = s.db.Exec(r.Context(), `INSERT INTO webauthn_ceremonies(uid,project_uid,project_user_uid,ceremony_type,session_data,expires_at) VALUES($1,$2,$3,'registration',$4,now()+interval '5 minutes')`, ceremonyUID, projectUID, user.UID, sessionRaw)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not store ceremony")
		return
	}
	writeJSON(w, 200, map[string]any{"ceremony_uid": ceremonyUID, "public_key": options.Response})
}

func (s *Server) finishRegistration(w http.ResponseWriter, r *http.Request) {
	reference := r.Header.Get("X-ComplicatedAuth-Session")
	user, _, ok := s.resolveUserSession(r, reference)
	if !ok {
		fail(w, r, 401, "invalid_session", "active Project User session required")
		return
	}
	var in struct {
		CeremonyUID string          `json:"ceremony_uid"`
		Credential  json.RawMessage `json:"credential"`
	}
	if !decode(w, r, &in) {
		return
	}
	projectUID := r.PathValue("project_uid")
	session, userUID, ok := s.consumeCeremony(r.Context(), projectUID, in.CeremonyUID, "registration")
	if !ok || userUID != user.UID {
		fail(w, r, 400, "invalid_ceremony", "ceremony is expired, consumed, or belongs to another user")
		return
	}
	wa, err := s.webAuthnForProject(r.Context(), projectUID)
	if err != nil {
		fail(w, r, 422, "webauthn_configuration", "Project WebAuthn configuration is invalid")
		return
	}
	wu, err := s.loadWebUser(r.Context(), projectUID, user.UID)
	if err != nil {
		fail(w, r, 404, "not_found", "Project User not found")
		return
	}
	credential, err := wa.FinishRegistration(wu, session, credentialRequest(r, in.Credential))
	if err != nil {
		fail(w, r, 400, "webauthn_verification_failed", err.Error())
		return
	}
	raw, _ := json.Marshal(credential)
	credentialUID := uuid.NewString()
	tx, err := s.db.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO webauthn_credentials(uid,project_uid,project_user_uid,credential_id,credential_json) VALUES($1,$2,$3,$4,$5)`, credentialUID, projectUID, user.UID, credential.ID, raw)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE projects SET rp_id_locked_at=COALESCE(rp_id_locked_at,now()) WHERE uid=$1`, projectUID)
	}
	if err != nil {
		if tx != nil {
			_ = tx.Rollback(r.Context())
		}
		fail(w, r, 409, "credential_exists", "credential is already registered in this Project")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		fail(w, r, 500, "internal_error", "could not save passkey")
		return
	}
	tenant, _ := s.projectTenant(r.Context(), projectUID)
	s.audit(r.Context(), tenant, projectUID, "project_user", user.UID, "passkey.registered", "passkey", credentialUID, nil, r)
	writeJSON(w, 201, map[string]any{"uid": credentialUID, "created_at": time.Now().UTC()})
}

func (s *Server) beginAuthentication(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email string }
	if r.ContentLength != 0 && !decode(w, r, &in) {
		return
	}
	projectUID := r.PathValue("project_uid")
	wa, err := s.webAuthnForProject(r.Context(), projectUID)
	if err != nil {
		fail(w, r, 422, "webauthn_configuration", "Project WebAuthn configuration is invalid")
		return
	}
	var options any
	var session *webauthn.SessionData
	var userUID any
	if normalizeEmail(in.Email) != "" {
		var uid string
		if err = s.db.QueryRow(r.Context(), `SELECT uid FROM project_users WHERE project_uid=$1 AND email_normalized=$2 AND status='active'`, projectUID, normalizeEmail(in.Email)).Scan(&uid); err != nil {
			fail(w, r, 400, "webauthn_begin_failed", "no passkeys are available")
			return
		}
		wu, loadErr := s.loadWebUser(r.Context(), projectUID, uid)
		if loadErr != nil {
			fail(w, r, 400, "webauthn_begin_failed", "no passkeys are available")
			return
		}
		assertion, sessionData, beginErr := wa.BeginLogin(wu)
		if beginErr != nil {
			fail(w, r, 400, "webauthn_begin_failed", "no passkeys are available")
			return
		}
		options, session, userUID = assertion.Response, sessionData, uid
	} else {
		assertion, sessionData, beginErr := wa.BeginDiscoverableLogin()
		if beginErr != nil {
			fail(w, r, 400, "webauthn_begin_failed", beginErr.Error())
			return
		}
		options, session = assertion.Response, sessionData
	}
	sessionRaw, _ := json.Marshal(session)
	ceremonyUID := uuid.NewString()
	_, err = s.db.Exec(r.Context(), `INSERT INTO webauthn_ceremonies(uid,project_uid,project_user_uid,ceremony_type,session_data,expires_at) VALUES($1,$2,$3,'authentication',$4,now()+interval '5 minutes')`, ceremonyUID, projectUID, userUID, sessionRaw)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not store ceremony")
		return
	}
	writeJSON(w, 200, map[string]any{"ceremony_uid": ceremonyUID, "public_key": options})
}

func (s *Server) finishAuthentication(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CeremonyUID string          `json:"ceremony_uid"`
		Credential  json.RawMessage `json:"credential"`
	}
	if !decode(w, r, &in) {
		return
	}
	projectUID := r.PathValue("project_uid")
	session, userUID, ok := s.consumeCeremony(r.Context(), projectUID, in.CeremonyUID, "authentication")
	if !ok {
		fail(w, r, 400, "invalid_ceremony", "ceremony is expired or already consumed")
		return
	}
	wa, err := s.webAuthnForProject(r.Context(), projectUID)
	if err != nil {
		fail(w, r, 422, "webauthn_configuration", "Project WebAuthn configuration is invalid")
		return
	}
	var credential *webauthn.Credential
	var authenticated webUser
	if userUID != "" {
		authenticated, err = s.loadWebUser(r.Context(), projectUID, userUID)
		if err == nil {
			credential, err = wa.FinishLogin(authenticated, session, credentialRequest(r, in.Credential))
		}
	} else {
		credential, err = wa.FinishDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
			var uid string
			queryErr := s.db.QueryRow(r.Context(), `SELECT project_user_uid FROM webauthn_credentials WHERE project_uid=$1 AND credential_id=$2`, projectUID, rawID).Scan(&uid)
			if queryErr != nil {
				return nil, queryErr
			}
			candidate, queryErr := s.loadWebUser(r.Context(), projectUID, uid)
			if queryErr != nil {
				return nil, queryErr
			}
			authenticated = candidate
			return candidate, nil
		}, session, credentialRequest(r, in.Credential))
	}
	if err != nil {
		fail(w, r, 400, "webauthn_verification_failed", err.Error())
		return
	}
	raw, _ := json.Marshal(credential)
	result, err := s.db.Exec(r.Context(), `UPDATE webauthn_credentials SET credential_json=$3,updated_at=now() WHERE project_uid=$1 AND project_user_uid=$2 AND credential_id=$4`, projectUID, authenticated.UID, raw, credential.ID)
	if err != nil || result.RowsAffected() != 1 {
		fail(w, r, 400, "credential_not_found", "credential does not belong to this Project User")
		return
	}
	token, _ := security.RandomToken()
	expires, idle := time.Now().Add(s.cfg.UserAbsoluteTTL), time.Now().Add(s.cfg.UserIdleTTL)
	_, err = s.db.Exec(r.Context(), `INSERT INTO project_user_sessions(uid,project_uid,project_user_uid,session_secret_hash,expires_at,idle_expires_at) VALUES($1,$2,$3,$4,$5,$6)`, uuid.NewString(), projectUID, authenticated.UID, security.SessionHash(token), expires, idle)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not create session")
		return
	}
	user, _ := s.loadProjectUser(r.Context(), projectUID, authenticated.UID)
	tenant, _ := s.projectTenant(r.Context(), projectUID)
	s.audit(r.Context(), tenant, projectUID, "project_user", user.UID, "project_user.passkey_authenticated", "project_user", user.UID, nil, r)
	writeJSON(w, 200, map[string]any{"session_reference": token, "expires_at": expires, "project_user": user})
}

func (s *Server) consumeCeremony(ctx context.Context, projectUID, ceremonyUID, kind string) (webauthn.SessionData, string, bool) {
	var raw []byte
	var userUID *string
	err := s.db.QueryRow(ctx, `UPDATE webauthn_ceremonies SET consumed_at=now() WHERE uid=$1 AND project_uid=$2 AND ceremony_type=$3 AND consumed_at IS NULL AND expires_at>now() RETURNING session_data,project_user_uid`, ceremonyUID, projectUID, kind).Scan(&raw, &userUID)
	if err != nil {
		return webauthn.SessionData{}, "", false
	}
	var session webauthn.SessionData
	if json.Unmarshal(raw, &session) != nil {
		return session, "", false
	}
	if userUID != nil {
		return session, *userUID, true
	}
	return session, "", true
}
func credentialRequest(original *http.Request, credential []byte) *http.Request {
	clone := original.Clone(original.Context())
	clone.Body = io.NopCloser(bytes.NewReader(credential))
	clone.ContentLength = int64(len(credential))
	clone.Header = original.Header.Clone()
	clone.Header.Set("Content-Type", "application/json")
	return clone
}
