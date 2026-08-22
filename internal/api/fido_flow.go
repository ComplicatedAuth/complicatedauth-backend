package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

var errCredentialNotAvailable = errors.New("credential is not available for this login")

func fidoMode(value string, enrollment bool) bool {
	if value == "passkey" || value == "security_key" {
		return true
	}
	return !enrollment && value == "hybrid"
}

func fidoHint(mode string) protocol.PublicKeyCredentialHints {
	switch mode {
	case "security_key":
		return protocol.PublicKeyCredentialHintSecurityKey
	case "hybrid":
		return protocol.PublicKeyCredentialHintHybrid
	default:
		return protocol.PublicKeyCredentialHintClientDevice
	}
}

func (s *Server) beginFidoLogin(w http.ResponseWriter, r *http.Request) {
	attempt, ok := s.resolveLoginAttempt(r)
	if !ok {
		fail(w, r, 401, "invalid_login", "login attempt is invalid or expired")
		return
	}
	var in struct {
		Mode string `json:"mode"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !fidoMode(in.Mode, false) {
		fail(w, r, 422, "validation_failed", "mode must be passkey, security_key, or hybrid")
		return
	}
	if in.Mode != "security_key" && !attempt.PasswordVerified {
		fail(w, r, 401, "additional_factor_required", "verify the password factor first")
		return
	}
	wa, err := s.webAuthnForProject(r.Context(), r.PathValue("project_uid"))
	if err != nil {
		fail(w, r, 422, "webauthn_configuration", "Project WebAuthn configuration is invalid")
		return
	}
	assertion, session, err := wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithAssertionPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{fidoHint(in.Mode)}),
	)
	if err != nil {
		fail(w, r, 400, "webauthn_begin_failed", "could not start authentication")
		return
	}
	sessionRaw, _ := json.Marshal(session)
	ceremonyUID := uuid.NewString()
	_, err = s.db.Exec(r.Context(), `INSERT INTO webauthn_ceremonies(uid,project_uid,project_user_uid,ceremony_type,session_data,expires_at,login_attempt_uid,credential_kind) VALUES($1,$2,$3,'authentication',$4,now()+interval '5 minutes',$5,$6)`, ceremonyUID, r.PathValue("project_uid"), attempt.UserUID, sessionRaw, attempt.UID, in.Mode)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not store ceremony")
		return
	}
	writeJSON(w, 200, map[string]any{"ceremony_uid": ceremonyUID, "public_key": assertion.Response})
}

func (s *Server) finishFidoLogin(w http.ResponseWriter, r *http.Request) {
	attempt, ok := s.resolveLoginAttempt(r)
	if !ok {
		fail(w, r, 401, "invalid_login", "login attempt is invalid or expired")
		return
	}
	var in struct {
		Mode        string          `json:"mode"`
		CeremonyUID string          `json:"ceremony_uid"`
		Credential  json.RawMessage `json:"credential"`
	}
	if !decode(w, r, &in) {
		return
	}
	session, userUID, mode, loginUID, ok := s.consumeFidoCeremony(r, in.CeremonyUID, "authentication")
	if !ok || loginUID != attempt.UID || userUID != attempt.UserUID || mode != in.Mode {
		fail(w, r, 400, "invalid_ceremony", "ceremony is expired, consumed, or does not match the login")
		return
	}
	if mode != "security_key" && !attempt.PasswordVerified {
		fail(w, r, 401, "additional_factor_required", "verify the password factor first")
		return
	}
	wa, err := s.webAuthnForProject(r.Context(), r.PathValue("project_uid"))
	if err != nil {
		fail(w, r, 422, "webauthn_configuration", "Project WebAuthn configuration is invalid")
		return
	}
	var authenticated webUser
	credential, err := wa.FinishDiscoverableLogin(func(rawID, _ []byte) (webauthn.User, error) {
		var credentialUserUID, kind string
		queryErr := s.db.QueryRow(r.Context(), `SELECT project_user_uid,credential_kind FROM webauthn_credentials WHERE project_uid=$1 AND credential_id=$2`, r.PathValue("project_uid"), rawID).Scan(&credentialUserUID, &kind)
		expectedKind := mode
		if expectedKind == "hybrid" {
			expectedKind = "passkey"
		}
		if queryErr != nil || credentialUserUID != attempt.UserUID || kind != expectedKind {
			return nil, errCredentialNotAvailable
		}
		authenticated, queryErr = s.loadWebUser(r.Context(), r.PathValue("project_uid"), credentialUserUID)
		return authenticated, queryErr
	}, session, credentialRequest(r, in.Credential))
	if err != nil {
		fail(w, r, 400, "webauthn_verification_failed", "credential verification failed")
		return
	}
	raw, _ := json.Marshal(credential)
	result, err := s.db.Exec(r.Context(), `UPDATE webauthn_credentials SET credential_json=$3,updated_at=now() WHERE project_uid=$1 AND project_user_uid=$2 AND credential_id=$4`, r.PathValue("project_uid"), authenticated.UID, raw, credential.ID)
	if err != nil || result.RowsAffected() != 1 {
		fail(w, r, 400, "credential_not_found", "credential does not belong to this Project User")
		return
	}
	s.completeLogin(w, r, attempt, "project_user."+mode+"_authenticated")
}

// beginFirstFidoEnrollment bootstraps the first FIDO credential only after a
// password has been verified in the same short-lived login attempt.
func (s *Server) beginFirstFidoEnrollment(w http.ResponseWriter, r *http.Request) {
	attempt, ok := s.resolveLoginAttempt(r)
	if !ok || !attempt.PasswordVerified {
		fail(w, r, 401, "additional_factor_required", "verify the password factor first")
		return
	}
	var in struct {
		Mode string `json:"mode"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !fidoMode(in.Mode, true) {
		fail(w, r, 422, "validation_failed", "mode must be passkey or security_key")
		return
	}
	var credentialCount int
	if err := s.db.QueryRow(r.Context(), `SELECT count(*) FROM webauthn_credentials WHERE project_uid=$1 AND project_user_uid=$2`, r.PathValue("project_uid"), attempt.UserUID).Scan(&credentialCount); err != nil {
		fail(w, r, 500, "internal_error", "could not inspect credentials")
		return
	}
	if credentialCount != 0 {
		fail(w, r, 409, "enrollment_not_allowed", "initial enrollment is available only before the first FIDO credential")
		return
	}
	wa, err := s.webAuthnForProject(r.Context(), r.PathValue("project_uid"))
	if err != nil {
		fail(w, r, 422, "webauthn_configuration", "Project WebAuthn configuration is invalid")
		return
	}
	user, err := s.loadWebUser(r.Context(), r.PathValue("project_uid"), attempt.UserUID)
	if err != nil {
		fail(w, r, 404, "not_found", "Project User not found")
		return
	}
	attachment := protocol.Platform
	attestation := protocol.PreferNoAttestation
	if in.Mode == "security_key" {
		attachment = protocol.CrossPlatform
		attestation = protocol.PreferDirectAttestation
	}
	options, session, err := wa.BeginRegistration(user,
		webauthn.WithExclusions(webauthn.Credentials(user.Credentials).CredentialDescriptors()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: attachment,
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			RequireResidentKey:      protocol.ResidentKeyRequired(),
			UserVerification:        protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(attestation),
		webauthn.WithPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{fidoHint(in.Mode)}),
	)
	if err != nil {
		fail(w, r, 422, "webauthn_begin_failed", "could not start initial enrollment")
		return
	}
	raw, _ := json.Marshal(session)
	ceremonyUID := uuid.NewString()
	_, err = s.db.Exec(r.Context(), `INSERT INTO webauthn_ceremonies(uid,project_uid,project_user_uid,ceremony_type,session_data,expires_at,login_attempt_uid,credential_kind) VALUES($1,$2,$3,'registration',$4,now()+interval '5 minutes',$5,$6)`, ceremonyUID, r.PathValue("project_uid"), attempt.UserUID, raw, attempt.UID, in.Mode)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not store ceremony")
		return
	}
	writeJSON(w, 200, map[string]any{"ceremony_uid": ceremonyUID, "public_key": options.Response})
}

func (s *Server) finishFirstFidoEnrollment(w http.ResponseWriter, r *http.Request) {
	attempt, ok := s.resolveLoginAttempt(r)
	if !ok || !attempt.PasswordVerified {
		fail(w, r, 401, "additional_factor_required", "verify the password factor first")
		return
	}
	var in struct {
		Mode        string          `json:"mode"`
		CeremonyUID string          `json:"ceremony_uid"`
		Credential  json.RawMessage `json:"credential"`
	}
	if !decode(w, r, &in) {
		return
	}
	session, userUID, mode, loginUID, ok := s.consumeFidoCeremony(r, in.CeremonyUID, "registration")
	if !ok || loginUID != attempt.UID || userUID != attempt.UserUID || mode != in.Mode || !fidoMode(mode, true) {
		fail(w, r, 400, "invalid_ceremony", "ceremony is expired, consumed, or does not match the login")
		return
	}
	wa, err := s.webAuthnForProject(r.Context(), r.PathValue("project_uid"))
	if err != nil {
		fail(w, r, 422, "webauthn_configuration", "Project WebAuthn configuration is invalid")
		return
	}
	user, err := s.loadWebUser(r.Context(), r.PathValue("project_uid"), attempt.UserUID)
	if err != nil {
		fail(w, r, 404, "not_found", "Project User not found")
		return
	}
	credential, err := wa.FinishRegistration(user, session, credentialRequest(r, in.Credential))
	if err != nil {
		fail(w, r, 400, "webauthn_verification_failed", "credential verification failed")
		return
	}
	attested := credential.AttestationType != "" && credential.AttestationType != "none" && credential.AttestationFormat != "none"
	if mode == "security_key" && !attested {
		fail(w, r, 400, "attestation_required", "security key did not provide attestation")
		return
	}
	raw, _ := json.Marshal(credential)
	tx, err := s.db.Begin(r.Context())
	if err == nil {
		var credentialCount int
		err = tx.QueryRow(r.Context(), `SELECT count(*) FROM webauthn_credentials WHERE project_uid=$1 AND project_user_uid=$2`, r.PathValue("project_uid"), attempt.UserUID).Scan(&credentialCount)
		if err == nil && credentialCount != 0 {
			err = errors.New("initial credential already exists")
		}
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO webauthn_credentials(uid,project_uid,project_user_uid,credential_id,credential_json,credential_kind,attested) VALUES($1,$2,$3,$4,$5,$6,$7)`, uuid.NewString(), r.PathValue("project_uid"), attempt.UserUID, credential.ID, raw, mode, attested)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE projects SET rp_id_locked_at=COALESCE(rp_id_locked_at,now()) WHERE uid=$1`, r.PathValue("project_uid"))
	}
	if err != nil {
		if tx != nil {
			_ = tx.Rollback(r.Context())
		}
		fail(w, r, 409, "credential_exists", "an initial credential is already registered")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		fail(w, r, 500, "internal_error", "could not save credential")
		return
	}
	s.completeLogin(w, r, attempt, "project_user."+mode+"_enrolled_and_authenticated")
}

func (s *Server) beginFidoEnrollment(w http.ResponseWriter, r *http.Request) {
	reference := r.Header.Get("X-ComplicatedAuth-Session")
	user, _, ok := s.resolveUserSession(r, reference)
	if !ok {
		fail(w, r, 401, "invalid_session", "active Project User session required")
		return
	}
	var in struct {
		Mode string `json:"mode"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !fidoMode(in.Mode, true) {
		fail(w, r, 422, "validation_failed", "mode must be passkey or security_key")
		return
	}
	wa, err := s.webAuthnForProject(r.Context(), r.PathValue("project_uid"))
	if err != nil {
		fail(w, r, 422, "webauthn_configuration", "Project WebAuthn configuration is invalid")
		return
	}
	wu, err := s.loadWebUser(r.Context(), r.PathValue("project_uid"), user.UID)
	if err != nil {
		fail(w, r, 404, "not_found", "Project User not found")
		return
	}
	attachment := protocol.Platform
	attestation := protocol.PreferNoAttestation
	if in.Mode == "security_key" {
		attachment = protocol.CrossPlatform
		attestation = protocol.PreferDirectAttestation
	}
	options, session, err := wa.BeginRegistration(wu,
		webauthn.WithExclusions(webauthn.Credentials(wu.Credentials).CredentialDescriptors()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: attachment,
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			RequireResidentKey:      protocol.ResidentKeyRequired(),
			UserVerification:        protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(attestation),
		webauthn.WithPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{fidoHint(in.Mode)}),
	)
	if err != nil {
		fail(w, r, 422, "webauthn_begin_failed", "could not start enrollment")
		return
	}
	raw, _ := json.Marshal(session)
	ceremonyUID := uuid.NewString()
	_, err = s.db.Exec(r.Context(), `INSERT INTO webauthn_ceremonies(uid,project_uid,project_user_uid,ceremony_type,session_data,expires_at,credential_kind) VALUES($1,$2,$3,'registration',$4,now()+interval '5 minutes',$5)`, ceremonyUID, r.PathValue("project_uid"), user.UID, raw, in.Mode)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not store ceremony")
		return
	}
	writeJSON(w, 200, map[string]any{"ceremony_uid": ceremonyUID, "public_key": options.Response})
}

func (s *Server) finishFidoEnrollment(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.resolveUserSession(r, r.Header.Get("X-ComplicatedAuth-Session"))
	if !ok {
		fail(w, r, 401, "invalid_session", "active Project User session required")
		return
	}
	var in struct {
		Mode        string          `json:"mode"`
		CeremonyUID string          `json:"ceremony_uid"`
		Credential  json.RawMessage `json:"credential"`
	}
	if !decode(w, r, &in) {
		return
	}
	session, userUID, mode, _, ok := s.consumeFidoCeremony(r, in.CeremonyUID, "registration")
	if !ok || userUID != user.UID || mode != in.Mode || !fidoMode(mode, true) {
		fail(w, r, 400, "invalid_ceremony", "ceremony is expired, consumed, or does not match the enrollment")
		return
	}
	wa, err := s.webAuthnForProject(r.Context(), r.PathValue("project_uid"))
	if err != nil {
		fail(w, r, 422, "webauthn_configuration", "Project WebAuthn configuration is invalid")
		return
	}
	wu, err := s.loadWebUser(r.Context(), r.PathValue("project_uid"), user.UID)
	if err != nil {
		fail(w, r, 404, "not_found", "Project User not found")
		return
	}
	credential, err := wa.FinishRegistration(wu, session, credentialRequest(r, in.Credential))
	if err != nil {
		fail(w, r, 400, "webauthn_verification_failed", "credential verification failed")
		return
	}
	attested := credential.AttestationType != "" && credential.AttestationType != "none" && credential.AttestationFormat != "none"
	if mode == "security_key" && !attested {
		fail(w, r, 400, "attestation_required", "security key did not provide attestation")
		return
	}
	raw, _ := json.Marshal(credential)
	credentialUID := uuid.NewString()
	tx, err := s.db.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO webauthn_credentials(uid,project_uid,project_user_uid,credential_id,credential_json,credential_kind,attested) VALUES($1,$2,$3,$4,$5,$6,$7)`, credentialUID, r.PathValue("project_uid"), user.UID, credential.ID, raw, mode, attested)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE projects SET rp_id_locked_at=COALESCE(rp_id_locked_at,now()) WHERE uid=$1`, r.PathValue("project_uid"))
	}
	if err != nil {
		if tx != nil {
			_ = tx.Rollback(r.Context())
		}
		fail(w, r, 409, "credential_exists", "credential is already registered in this Project")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		fail(w, r, 500, "internal_error", "could not save credential")
		return
	}
	writeJSON(w, 201, map[string]any{"uid": credentialUID, "kind": mode, "created_at": time.Now().UTC()})
}

func (s *Server) consumeFidoCeremony(r *http.Request, ceremonyUID, kind string) (webauthn.SessionData, string, string, string, bool) {
	var raw []byte
	var userUID *string
	var loginUID *string
	var mode string
	err := s.db.QueryRow(r.Context(), `UPDATE webauthn_ceremonies SET consumed_at=now() WHERE uid=$1 AND project_uid=$2 AND ceremony_type=$3 AND consumed_at IS NULL AND expires_at>now() RETURNING session_data,project_user_uid,credential_kind,login_attempt_uid`, ceremonyUID, r.PathValue("project_uid"), kind).Scan(&raw, &userUID, &mode, &loginUID)
	var session webauthn.SessionData
	if err != nil || userUID == nil || json.Unmarshal(raw, &session) != nil {
		return webauthn.SessionData{}, "", "", "", false
	}
	login := ""
	if loginUID != nil {
		login = *loginUID
	}
	return session, *userUID, mode, login, true
}
