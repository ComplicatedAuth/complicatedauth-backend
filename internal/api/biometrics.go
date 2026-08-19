package api

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

const maxSelfieBytes = 5 << 20

func (s *Server) verifyBiometricLogin(w http.ResponseWriter, r *http.Request) {
	attempt, ok := s.resolveLoginAttempt(r)
	if !ok {
		fail(w, r, 401, "invalid_login", "login attempt is invalid or expired")
		return
	}
	if !attempt.PasswordVerified {
		fail(w, r, 401, "additional_factor_required", "verify the password factor first")
		return
	}
	image, ok := readSelfie(w, r)
	if !ok {
		return
	}
	var templateID string
	err := s.db.QueryRow(r.Context(), `SELECT provider_template_id FROM biometric_credentials WHERE project_uid=$1 AND project_user_uid=$2`, r.PathValue("project_uid"), attempt.UserUID).Scan(&templateID)
	if err != nil {
		fail(w, r, 401, "invalid_credentials", "credentials are incorrect")
		return
	}
	matched, err := s.biometrics.Verify(r.Context(), templateID, image)
	if errors.Is(err, errBiometricProviderUnavailable) {
		fail(w, r, 503, "biometric_unavailable", "facial authentication is unavailable")
		return
	}
	if err != nil {
		fail(w, r, 502, "biometric_provider_failed", "facial verification could not be completed")
		return
	}
	if !matched {
		fail(w, r, 401, "invalid_credentials", "credentials are incorrect")
		return
	}
	s.completeLogin(w, r, attempt, "project_user.biometric_authenticated")
}

func (s *Server) enrollBiometric(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.resolveUserSession(r, r.Header.Get("X-ComplicatedAuth-Session"))
	if !ok {
		fail(w, r, 401, "invalid_session", "active Project User session required")
		return
	}
	image, ok := readSelfie(w, r)
	if !ok {
		return
	}
	subject := r.PathValue("project_uid") + ":" + user.UID
	templateID, err := s.biometrics.Enroll(r.Context(), subject, image)
	if errors.Is(err, errBiometricProviderUnavailable) {
		fail(w, r, 503, "biometric_unavailable", "facial enrollment is unavailable")
		return
	}
	if err != nil {
		fail(w, r, 502, "biometric_provider_failed", "facial enrollment could not be completed")
		return
	}
	var oldTemplate string
	_ = s.db.QueryRow(r.Context(), `SELECT provider_template_id FROM biometric_credentials WHERE project_uid=$1 AND project_user_uid=$2`, r.PathValue("project_uid"), user.UID).Scan(&oldTemplate)
	uid := uuid.NewString()
	created := time.Now().UTC()
	err = s.db.QueryRow(r.Context(), `INSERT INTO biometric_credentials(uid,project_uid,project_user_uid,provider_template_id,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5) ON CONFLICT(project_uid,project_user_uid) DO UPDATE SET provider_template_id=EXCLUDED.provider_template_id,updated_at=now() RETURNING uid,created_at`, uid, r.PathValue("project_uid"), user.UID, templateID, created).Scan(&uid, &created)
	if err != nil {
		_ = s.biometrics.Delete(r.Context(), templateID)
		fail(w, r, 500, "internal_error", "could not save facial enrollment")
		return
	}
	if oldTemplate != "" && oldTemplate != templateID {
		_ = s.biometrics.Delete(r.Context(), oldTemplate)
	}
	tenant, _ := s.projectTenant(r.Context(), r.PathValue("project_uid"))
	s.audit(r.Context(), tenant, r.PathValue("project_uid"), "project_user", user.UID, "biometric.enrolled", "biometric", uid, nil, r)
	writeJSON(w, 201, map[string]any{"uid": uid, "created_at": created})
}

func (s *Server) deleteBiometricEnrollment(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.resolveUserSession(r, r.Header.Get("X-ComplicatedAuth-Session"))
	if !ok {
		fail(w, r, 401, "invalid_session", "active Project User session required")
		return
	}
	var uid, templateID string
	err := s.db.QueryRow(r.Context(), `SELECT uid,provider_template_id FROM biometric_credentials WHERE project_uid=$1 AND project_user_uid=$2`, r.PathValue("project_uid"), user.UID).Scan(&uid, &templateID)
	if err != nil {
		fail(w, r, 404, "not_found", "facial enrollment not found")
		return
	}
	if err = s.biometrics.Delete(r.Context(), templateID); errors.Is(err, errBiometricProviderUnavailable) {
		fail(w, r, 503, "biometric_unavailable", "facial enrollment cannot be removed while the provider is unavailable")
		return
	} else if err != nil {
		fail(w, r, 502, "biometric_provider_failed", "facial enrollment could not be removed")
		return
	}
	_, err = s.db.Exec(r.Context(), `DELETE FROM biometric_credentials WHERE uid=$1`, uid)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not remove facial enrollment")
		return
	}
	tenant, _ := s.projectTenant(r.Context(), r.PathValue("project_uid"))
	s.audit(r.Context(), tenant, r.PathValue("project_uid"), "project_user", user.UID, "biometric.deleted", "biometric", uid, nil, r)
	w.WriteHeader(http.StatusNoContent)
}

func readSelfie(w http.ResponseWriter, r *http.Request) (selfie, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSelfieBytes+(1<<20))
	if err := r.ParseMultipartForm(maxSelfieBytes + (1 << 20)); err != nil {
		fail(w, r, 422, "invalid_selfie", "selfie must be a multipart image no larger than 5 MiB")
		return selfie{}, false
	}
	file, header, err := r.FormFile("selfie")
	if err != nil {
		fail(w, r, 422, "invalid_selfie", "selfie image is required")
		return selfie{}, false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSelfieBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxSelfieBytes {
		fail(w, r, 422, "invalid_selfie", "selfie must be between 1 byte and 5 MiB")
		return selfie{}, false
	}
	detected := http.DetectContentType(data)
	allowed := detected == "image/jpeg" || detected == "image/png" || detected == "image/webp"
	if !allowed || !strings.HasPrefix(header.Header.Get("Content-Type"), "image/") {
		fail(w, r, 422, "invalid_selfie", "selfie must be JPEG, PNG, or WebP")
		return selfie{}, false
	}
	return selfie{Data: data, ContentType: detected}, true
}
