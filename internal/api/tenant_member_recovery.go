package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	security "github.com/dokosoko/complicatedauth-backend/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	tenantEmailVerificationTTL = 24 * time.Hour
	tenantPasswordResetTTL     = 30 * time.Minute
)

func (s *Server) createTenantEmailVerificationRequest(w http.ResponseWriter, r *http.Request) {
	email, ok := s.acceptRecoveryEmail(w, r)
	if !ok {
		return
	}
	if !s.takeRateLimit(w, r, "tenant_email_verification_ip", s.clientIP(r), 20, time.Hour) ||
		!s.takeRateLimit(w, r, "tenant_email_verification_identity", email, 3, time.Hour) {
		return
	}
	var memberUID, tenantUID, displayName, tenantName string
	var alreadyVerified bool
	err := s.db.QueryRow(r.Context(), `
		SELECT m.uid,m.tenant_uid,m.display_name,t.name,m.email_verified_at IS NOT NULL
		FROM tenant_members m JOIN tenants t ON t.uid=m.tenant_uid
		WHERE m.email_normalized=$1 AND m.status='active'
	`, email).Scan(&memberUID, &tenantUID, &displayName, &tenantName, &alreadyVerified)
	if err == nil && !alreadyVerified {
		if err = s.issueTenantEmailVerification(r.Context(), memberUID, tenantUID, email, displayName, tenantName); err != nil {
			s.log.Error("email verification request failed", "error", err)
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (s *Server) issueTenantEmailVerification(ctx context.Context, memberUID, tenantUID, email, displayName, tenantName string) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var currentTenantUID string
	if err = tx.QueryRow(ctx, `SELECT tenant_uid FROM tenant_members WHERE uid=$1 AND status='active' FOR UPDATE`, memberUID).Scan(&currentTenantUID); err != nil || currentTenantUID != tenantUID {
		return err
	}
	err = s.insertTenantEmailVerification(ctx, tx, memberUID, tenantUID, email, displayName, tenantName)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Server) insertTenantEmailVerification(ctx context.Context, tx pgx.Tx, memberUID, tenantUID, email, displayName, tenantName string) error {
	token, err := security.RandomToken()
	if err != nil {
		return err
	}
	verificationUID := uuid.New()
	if _, err = tx.Exec(ctx, `UPDATE tenant_member_email_verifications SET revoked_at=clock_timestamp() WHERE tenant_member_uid=$1 AND consumed_at IS NULL AND revoked_at IS NULL`, memberUID); err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO tenant_member_email_verifications(uid,tenant_uid,tenant_member_uid,token_hash,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+$5*interval '1 second')`, verificationUID, tenantUID, memberUID, security.SessionHash(token), int64(tenantEmailVerificationTTL/time.Second))
	}
	if err == nil {
		link := s.cfg.ConsoleOrigin + "/verify-email#token=" + token
		err = s.scheduleEmailDelivery(ctx, tx, tenantUID, "tenant_email_verification", email, emailDeliveryPayload{DisplayName: displayName, TenantName: tenantName, Link: link})
	}
	return err
}

func (s *Server) verifyTenantEmail(w http.ResponseWriter, r *http.Request) {
	if !s.takeRateLimit(w, r, "tenant_email_verification_consume", s.clientIP(r), 20, 15*time.Minute) {
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Token) == "" {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "token is required")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), pgx.TxOptions{})
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not verify email")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	providedHash := security.SessionHash(in.Token)
	var verificationUID, tenantUID, memberUID, status string
	var storedHash []byte
	var expiresAt time.Time
	err = tx.QueryRow(r.Context(), `
		SELECT v.uid,v.tenant_uid,v.tenant_member_uid,m.status,v.token_hash,v.expires_at
		FROM tenant_member_email_verifications v
		JOIN tenant_members m ON m.uid=v.tenant_member_uid
		WHERE v.token_hash=$1 AND v.consumed_at IS NULL AND v.revoked_at IS NULL
		FOR UPDATE OF v,m
	`, providedHash).Scan(&verificationUID, &tenantUID, &memberUID, &status, &storedHash, &expiresAt)
	if err != nil || status != "active" || !expiresAt.After(time.Now()) || subtle.ConstantTimeCompare(storedHash, providedHash) != 1 {
		fail(w, r, http.StatusBadRequest, "invalid_email_verification", "email verification is invalid, expired, or already used")
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE tenant_member_email_verifications SET consumed_at=clock_timestamp() WHERE uid=$1`, verificationUID); err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE tenant_members SET email_verified_at=COALESCE(email_verified_at,clock_timestamp()),updated_at=clock_timestamp() WHERE uid=$1`, memberUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid) VALUES($1,$2,'tenant_member',$3,'tenant_member.email_verified','tenant_member',$3)`, uuid.New(), tenantUID, memberUID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not verify email")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createTenantPasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	email, ok := s.acceptRecoveryEmail(w, r)
	if !ok {
		return
	}
	if !s.takeRateLimit(w, r, "tenant_password_reset_ip", s.clientIP(r), 20, time.Hour) ||
		!s.takeRateLimit(w, r, "tenant_password_reset_identity", email, 3, time.Hour) {
		return
	}
	var memberUID, tenantUID, displayName, tenantName string
	err := s.db.QueryRow(r.Context(), `
		SELECT m.uid,m.tenant_uid,m.display_name,t.name
		FROM tenant_members m JOIN tenants t ON t.uid=m.tenant_uid
		WHERE m.email_normalized=$1 AND m.status='active'
	`, email).Scan(&memberUID, &tenantUID, &displayName, &tenantName)
	if err == nil {
		if err = s.issueTenantPasswordReset(r.Context(), memberUID, tenantUID, email, displayName, tenantName); err != nil {
			s.log.Error("password reset request failed", "error", err)
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (s *Server) issueTenantPasswordReset(ctx context.Context, memberUID, tenantUID, email, displayName, tenantName string) error {
	token, err := security.RandomToken()
	if err != nil {
		return err
	}
	resetUID := uuid.New()
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var currentTenantUID string
	if err = tx.QueryRow(ctx, `SELECT tenant_uid FROM tenant_members WHERE uid=$1 AND status='active' FOR UPDATE`, memberUID).Scan(&currentTenantUID); err != nil || currentTenantUID != tenantUID {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE tenant_member_password_resets SET revoked_at=clock_timestamp() WHERE tenant_member_uid=$1 AND consumed_at IS NULL AND revoked_at IS NULL`, memberUID); err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO tenant_member_password_resets(uid,tenant_uid,tenant_member_uid,token_hash,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+$5*interval '1 second')`, resetUID, tenantUID, memberUID, security.SessionHash(token), int64(tenantPasswordResetTTL/time.Second))
	}
	if err == nil {
		link := s.cfg.ConsoleOrigin + "/reset-password#token=" + token
		err = s.scheduleEmailDelivery(ctx, tx, tenantUID, "tenant_password_reset", email, emailDeliveryPayload{DisplayName: displayName, TenantName: tenantName, Link: link})
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Server) resetTenantMemberPassword(w http.ResponseWriter, r *http.Request) {
	if !s.takeRateLimit(w, r, "tenant_password_reset_consume", s.clientIP(r), 20, 15*time.Minute) {
		return
	}
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Token) == "" {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "token and password are required")
		return
	}
	passwordHash, err := security.HashPassword(in.Password)
	if err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
		return
	}
	tx, err := s.db.BeginTx(r.Context(), pgx.TxOptions{})
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not reset password")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	providedHash := security.SessionHash(in.Token)
	var resetUID, tenantUID, memberUID, status string
	var storedHash []byte
	var expiresAt time.Time
	err = tx.QueryRow(r.Context(), `
		SELECT p.uid,p.tenant_uid,p.tenant_member_uid,m.status,p.token_hash,p.expires_at
		FROM tenant_member_password_resets p
		JOIN tenant_members m ON m.uid=p.tenant_member_uid
		WHERE p.token_hash=$1 AND p.consumed_at IS NULL AND p.revoked_at IS NULL
		FOR UPDATE OF p,m
	`, providedHash).Scan(&resetUID, &tenantUID, &memberUID, &status, &storedHash, &expiresAt)
	if err != nil || status != "active" || !expiresAt.After(time.Now()) || subtle.ConstantTimeCompare(storedHash, providedHash) != 1 {
		fail(w, r, http.StatusBadRequest, "invalid_password_reset", "password reset is invalid, expired, or already used")
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE tenant_member_password_resets SET consumed_at=clock_timestamp() WHERE uid=$1`, resetUID); err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE tenant_member_password_resets SET revoked_at=clock_timestamp() WHERE tenant_member_uid=$1 AND uid<>$2 AND consumed_at IS NULL AND revoked_at IS NULL`, memberUID, resetUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE tenant_members SET password_hash=$2,updated_at=clock_timestamp() WHERE uid=$1`, memberUID, passwordHash)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE tenant_member_sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE tenant_member_uid=$1`, memberUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE tenant_member_login_attempts SET consumed_at=COALESCE(consumed_at,clock_timestamp()) WHERE tenant_member_uid=$1`, memberUID)
	}
	if err == nil {
		// Password recovery is also the explicit lost-authenticator recovery
		// boundary. The next login must bootstrap a new FIDO credential before
		// any management operation is authorized.
		_, err = tx.Exec(r.Context(), `DELETE FROM tenant_member_webauthn_credentials WHERE tenant_member_uid=$1`, memberUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE tenant_member_uid=$1`, memberUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_authorization_codes SET consumed_at=COALESCE(consumed_at,clock_timestamp()) WHERE tenant_member_uid=$1`, memberUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,'tenant_member',$3,'tenant_member.authentication_recovered','tenant_member',$3,$4)`, uuid.New(), tenantUID, memberUID, map[string]any{"password_replaced": true, "webauthn_credentials_removed": true})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not reset password")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "complicatedauth_session", Value: "", Path: "/", HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(0, 0)})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) acceptRecoveryEmail(w http.ResponseWriter, r *http.Request) (string, bool) {
	var in struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &in) {
		return "", false
	}
	email := normalizeEmail(in.Email)
	if email == "" || !strings.Contains(email, "@") {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "a valid email is required")
		return "", false
	}
	return email, true
}
