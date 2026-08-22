package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	security "github.com/dokosoko/complicatedauth-backend/internal/auth"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	tenantMemberLoginAttemptTTL = 5 * time.Minute
	maxTenantMemberCredentials  = 10
)

var tenantMemberDummyPasswordHash = func() string {
	hash, err := security.HashPassword("dummy password used only for timing parity")
	if err != nil {
		panic(err)
	}
	return hash
}()

var (
	errTenantMemberCredentialConflict = errors.New("Tenant Member WebAuthn credential conflicts with an existing resource")
	errTenantMemberCredentialLimit    = errors.New("Tenant Member WebAuthn credential limit reached")
	errTenantMemberCredentialMissing  = errors.New("Tenant Member WebAuthn credential is not available")
	errTenantMemberLoginConsumed      = errors.New("Tenant Member login attempt is no longer available")
)

type tenantMemberLoginAttemptState struct {
	UID              string
	TenantUID        string
	TenantName       string
	TenantSlug       string
	MemberUID        string
	Email            string
	DisplayName      string
	Role             string
	Status           string
	EmailVerified    bool
	MemberCreatedAt  time.Time
	PasswordHash     string
	IdentityKeyHash  []byte
	PasswordVerified bool
	ExpiresAt        time.Time
}

type tenantMemberWebUser struct {
	UID, Email, DisplayName string
	Credentials             []webauthn.Credential
}

func (u tenantMemberWebUser) WebAuthnID() []byte                         { return []byte(u.UID) }
func (u tenantMemberWebUser) WebAuthnName() string                       { return u.Email }
func (u tenantMemberWebUser) WebAuthnDisplayName() string                { return u.DisplayName }
func (u tenantMemberWebUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type tenantMemberCeremony struct {
	Session          webauthn.SessionData
	TenantUID        string
	MemberUID        string
	LoginAttemptUID  string
	MemberSessionUID string
	Kind             string
	Name             string
}

type createdTenantMemberSession struct {
	Token     string
	ExpiresAt time.Time
}

func (s *Server) createTenantMemberLoginAttempt(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &in) {
		return
	}
	email := normalizeEmail(in.Email)
	if email == "" || len(email) > 320 {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "email must be a valid address")
		return
	}
	if !s.takeRateLimit(w, r, "console_login_start_ip", s.clientIP(r), 50, 15*time.Minute) {
		return
	}

	var memberUID *string
	var candidate string
	if err := s.db.QueryRow(r.Context(), `
		SELECT uid FROM tenant_members WHERE email_normalized=$1 AND status='active'
	`, email).Scan(&candidate); err == nil {
		memberUID = &candidate
	}
	clientSecret, err := security.RandomToken()
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not start login")
		return
	}
	attempt := TenantMemberLoginAttempt{
		UID:          uuid.NewString(),
		ClientSecret: clientSecret,
		ExpiresAt:    time.Now().Add(tenantMemberLoginAttemptTTL),
	}
	identityKeyHash := security.SecretHash(s.cfg.SecretHashKey, "console_login_identity\x00"+email)
	_, err = s.db.Exec(r.Context(), `
		INSERT INTO tenant_member_login_attempts(
			uid,tenant_member_uid,client_secret_hash,identity_key_hash,expires_at
		) VALUES($1,$2,$3,$4,$5)
	`, attempt.UID, memberUID, security.SessionHash(clientSecret), identityKeyHash, attempt.ExpiresAt)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not start login")
		return
	}
	writeJSON(w, http.StatusCreated, attempt)
}

func (s *Server) resolveTenantMemberLoginAttempt(r *http.Request) (tenantMemberLoginAttemptState, bool) {
	if _, err := uuid.Parse(r.PathValue("login_attempt_uid")); err != nil {
		return tenantMemberLoginAttemptState{}, false
	}
	clientSecret := r.Header.Get("X-ComplicatedAuth-Login-Secret")
	if clientSecret == "" {
		return tenantMemberLoginAttemptState{}, false
	}
	var (
		attempt          tenantMemberLoginAttemptState
		memberUID        *string
		tenantUID        *string
		tenantName       *string
		tenantSlug       *string
		email            *string
		displayName      *string
		role             *string
		status           *string
		passwordHash     *string
		emailVerified    *bool
		memberCreatedAt  *time.Time
		passwordVerified *time.Time
	)
	err := s.db.QueryRow(r.Context(), `
		SELECT a.uid,a.tenant_member_uid,a.identity_key_hash,a.password_verified_at,a.expires_at,
		       t.uid,t.name,t.slug,m.email,m.display_name,m.role,m.status,m.password_hash,
		       m.email_verified_at IS NOT NULL,m.created_at
		FROM tenant_member_login_attempts a
		LEFT JOIN tenant_members m ON m.uid=a.tenant_member_uid
		LEFT JOIN tenants t ON t.uid=m.tenant_uid
		WHERE a.uid=$1 AND a.client_secret_hash=$2
		  AND a.consumed_at IS NULL AND a.expires_at>clock_timestamp()
	`, r.PathValue("login_attempt_uid"), security.SessionHash(clientSecret)).Scan(
		&attempt.UID, &memberUID, &attempt.IdentityKeyHash, &passwordVerified, &attempt.ExpiresAt,
		&tenantUID, &tenantName, &tenantSlug, &email, &displayName, &role, &status, &passwordHash,
		&emailVerified, &memberCreatedAt,
	)
	if err != nil {
		return tenantMemberLoginAttemptState{}, false
	}
	if memberUID != nil {
		attempt.MemberUID = *memberUID
		attempt.TenantUID = *tenantUID
		attempt.TenantName = *tenantName
		attempt.TenantSlug = *tenantSlug
		attempt.Email = *email
		attempt.DisplayName = *displayName
		attempt.Role = *role
		attempt.Status = *status
		attempt.PasswordHash = *passwordHash
		attempt.EmailVerified = *emailVerified
		attempt.MemberCreatedAt = *memberCreatedAt
	}
	attempt.PasswordVerified = passwordVerified != nil
	return attempt, true
}

func (s *Server) verifyTenantMemberLoginPassword(w http.ResponseWriter, r *http.Request) {
	attempt, ok := s.resolveTenantMemberLoginAttempt(r)
	if !ok {
		fail(w, r, http.StatusUnauthorized, "invalid_login", "login attempt is invalid or expired")
		return
	}
	if !s.takeRateLimit(w, r, "console_login_password_ip", s.clientIP(r), 20, 15*time.Minute) {
		return
	}
	identityKey := hex.EncodeToString(attempt.IdentityKeyHash)
	if !s.takeRateLimit(w, r, "console_login_password_identity", identityKey, 5, 15*time.Minute) {
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	passwordHash := attempt.PasswordHash
	if passwordHash == "" {
		passwordHash = tenantMemberDummyPasswordHash
	}
	valid, rehash := security.VerifyPassword(passwordHash, in.Password)
	if !valid || attempt.MemberUID == "" || attempt.Status != "active" {
		fail(w, r, http.StatusUnauthorized, "invalid_credentials", "email or password is incorrect")
		return
	}

	command, err := s.db.Exec(r.Context(), `
		UPDATE tenant_member_login_attempts
		SET password_verified_at=COALESCE(password_verified_at,clock_timestamp())
		WHERE uid=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()
	`, attempt.UID)
	if err != nil || command.RowsAffected() != 1 {
		fail(w, r, http.StatusUnauthorized, "invalid_login", "login attempt is invalid or expired")
		return
	}
	s.resetRateLimit(r, "console_login_password_identity", identityKey)
	if rehash {
		if next, hashErr := security.HashPassword(in.Password); hashErr == nil {
			_, _ = s.db.Exec(r.Context(), `UPDATE tenant_members SET password_hash=$2,updated_at=clock_timestamp() WHERE uid=$1`, attempt.MemberUID, next)
		}
	}
	var credentialCount int
	if err = s.db.QueryRow(r.Context(), `
		SELECT count(*) FROM tenant_member_webauthn_credentials WHERE tenant_member_uid=$1
	`, attempt.MemberUID).Scan(&credentialCount); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not inspect authentication credentials")
		return
	}
	writeJSON(w, http.StatusCreated, TenantMemberLoginProgress{
		Status:                  "password_verified",
		CredentialSetupRequired: credentialCount == 0,
		ExpiresAt:               attempt.ExpiresAt,
	})
}

func (s *Server) tenantMemberWebAuthn() (*webauthn.WebAuthn, error) {
	origin, err := url.Parse(s.cfg.ConsoleOrigin)
	if err != nil || origin.Hostname() == "" {
		return nil, errors.New("console origin is invalid")
	}
	return webauthn.New(&webauthn.Config{
		RPID:          origin.Hostname(),
		RPDisplayName: "ComplicatedAuth management console",
		RPOrigins:     []string{s.cfg.ConsoleOrigin},
		Timeouts: webauthn.TimeoutsConfig{
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: tenantMemberLoginAttemptTTL, TimeoutUVD: tenantMemberLoginAttemptTTL},
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: tenantMemberLoginAttemptTTL, TimeoutUVD: tenantMemberLoginAttemptTTL},
		},
	})
}

func (s *Server) loadTenantMemberWebUser(ctx context.Context, tenantUID, memberUID, kind string) (tenantMemberWebUser, error) {
	var user tenantMemberWebUser
	if err := s.db.QueryRow(ctx, `
		SELECT uid,email,display_name FROM tenant_members
		WHERE uid=$1 AND tenant_uid=$2 AND status='active'
	`, memberUID, tenantUID).Scan(&user.UID, &user.Email, &user.DisplayName); err != nil {
		return user, err
	}
	query := `SELECT credential_json FROM tenant_member_webauthn_credentials WHERE tenant_member_uid=$1 AND tenant_uid=$2`
	arguments := []any{memberUID, tenantUID}
	if kind != "" {
		query += ` AND credential_kind=$3`
		arguments = append(arguments, kind)
	}
	rows, err := s.db.Query(ctx, query, arguments...)
	if err != nil {
		return user, err
	}
	defer rows.Close()
	user.Credentials = []webauthn.Credential{}
	for rows.Next() {
		var raw []byte
		var credential webauthn.Credential
		if err = rows.Scan(&raw); err != nil {
			return user, err
		}
		if err = json.Unmarshal(raw, &credential); err != nil {
			return user, err
		}
		user.Credentials = append(user.Credentials, credential)
	}
	return user, rows.Err()
}

func tenantMemberCredentialKind(mode string) string {
	if mode == "hybrid" {
		return "passkey"
	}
	return mode
}

func (s *Server) beginTenantMemberWebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	attempt, ok := s.resolveTenantMemberLoginAttempt(r)
	if !ok || !attempt.PasswordVerified || attempt.MemberUID == "" {
		fail(w, r, http.StatusUnauthorized, "additional_factor_required", "verify the password factor first")
		return
	}
	var in struct {
		Mode string `json:"mode"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !fidoMode(in.Mode, false) {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "mode must be passkey, security_key, or hybrid")
		return
	}
	user, err := s.loadTenantMemberWebUser(r.Context(), attempt.TenantUID, attempt.MemberUID, tenantMemberCredentialKind(in.Mode))
	if err != nil || len(user.Credentials) == 0 {
		fail(w, r, http.StatusConflict, "credential_setup_required", "no matching credential is enrolled; complete initial setup")
		return
	}
	wa, err := s.tenantMemberWebAuthn()
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "webauthn_configuration", "management WebAuthn configuration is invalid")
		return
	}
	options, session, err := wa.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithAssertionPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{fidoHint(in.Mode)}),
	)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "webauthn_begin_failed", "could not start authentication")
		return
	}
	s.writeTenantMemberLoginCeremony(w, r, attempt, "authentication", in.Mode, "", session, options.Response)
}

func (s *Server) writeTenantMemberLoginCeremony(w http.ResponseWriter, r *http.Request, attempt tenantMemberLoginAttemptState, ceremonyType, kind, name string, session *webauthn.SessionData, publicKey any) {
	raw, err := json.Marshal(session)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not store WebAuthn ceremony")
		return
	}
	ceremonyUID := uuid.NewString()
	expiresAt := time.Now().Add(tenantMemberLoginAttemptTTL)
	_, err = s.db.Exec(r.Context(), `
		INSERT INTO tenant_member_webauthn_ceremonies(
			uid,tenant_uid,tenant_member_uid,login_attempt_uid,ceremony_type,
			credential_kind,credential_name,session_data,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9)
	`, ceremonyUID, attempt.TenantUID, attempt.MemberUID, attempt.UID, ceremonyType, kind, name, raw, expiresAt)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not store WebAuthn ceremony")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"uid": ceremonyUID, "expires_at": expiresAt, "public_key": publicKey,
	})
}

func (s *Server) finishTenantMemberWebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	attempt, ok := s.resolveTenantMemberLoginAttempt(r)
	if !ok || !attempt.PasswordVerified || attempt.MemberUID == "" {
		fail(w, r, http.StatusUnauthorized, "additional_factor_required", "verify the password factor first")
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
	ceremony, ok := s.consumeTenantMemberCeremony(r.Context(), in.CeremonyUID, "authentication")
	if !ok || ceremony.LoginAttemptUID != attempt.UID || ceremony.MemberUID != attempt.MemberUID || ceremony.Kind != in.Mode {
		fail(w, r, http.StatusBadRequest, "invalid_ceremony", "ceremony is expired, consumed, or does not match the login")
		return
	}
	user, err := s.loadTenantMemberWebUser(r.Context(), attempt.TenantUID, attempt.MemberUID, tenantMemberCredentialKind(in.Mode))
	if err != nil {
		fail(w, r, http.StatusBadRequest, "webauthn_verification_failed", "credential verification failed")
		return
	}
	wa, err := s.tenantMemberWebAuthn()
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "webauthn_configuration", "management WebAuthn configuration is invalid")
		return
	}
	credential, err := wa.FinishLogin(user, ceremony.Session, credentialRequest(r, in.Credential))
	if err != nil {
		fail(w, r, http.StatusBadRequest, "webauthn_verification_failed", "credential verification failed")
		return
	}
	createdSession, err := s.completeTenantMemberWebAuthnLogin(r.Context(), attempt, in.Mode, credential)
	if err != nil {
		if errors.Is(err, errTenantMemberCredentialMissing) || errors.Is(err, errTenantMemberLoginConsumed) {
			fail(w, r, http.StatusBadRequest, "credential_not_found", "credential is not available for this login")
		} else {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not create management session")
		}
		return
	}
	s.writeStrongTenantMemberSession(w, attempt, createdSession)
}

func (s *Server) completeTenantMemberWebAuthnLogin(ctx context.Context, attempt tenantMemberLoginAttemptState, mode string, credential *webauthn.Credential) (createdTenantMemberSession, error) {
	raw, err := json.Marshal(credential)
	if err != nil {
		return createdTenantMemberSession{}, err
	}
	token, err := security.RandomToken()
	if err != nil {
		return createdTenantMemberSession{}, err
	}
	expiresAt := time.Now().Add(s.cfg.MemberAbsoluteTTL)
	idleExpiresAt := time.Now().Add(s.cfg.MemberIdleTTL)
	sessionUID := uuid.NewString()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return createdTenantMemberSession{}, err
	}
	defer tx.Rollback(ctx)
	command, err := tx.Exec(ctx, `
		UPDATE tenant_member_webauthn_credentials
		SET credential_json=$4,updated_at=clock_timestamp(),last_used_at=clock_timestamp()
		WHERE tenant_uid=$1 AND tenant_member_uid=$2 AND credential_id=$3
		  AND credential_kind=$5
	`, attempt.TenantUID, attempt.MemberUID, credential.ID, raw, tenantMemberCredentialKind(mode))
	if err != nil || command.RowsAffected() != 1 {
		if err != nil {
			return createdTenantMemberSession{}, err
		}
		return createdTenantMemberSession{}, errTenantMemberCredentialMissing
	}
	command, err = tx.Exec(ctx, `
		UPDATE tenant_member_login_attempts SET consumed_at=clock_timestamp()
		WHERE uid=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()
	`, attempt.UID)
	if err != nil || command.RowsAffected() != 1 {
		if err != nil {
			return createdTenantMemberSession{}, err
		}
		return createdTenantMemberSession{}, errTenantMemberLoginConsumed
	}
	_, err = tx.Exec(ctx, `
		UPDATE tenant_member_sessions
		SET revoked_at=COALESCE(revoked_at,clock_timestamp())
		WHERE tenant_member_uid=$1 AND authentication_assurance='bootstrap' AND revoked_at IS NULL
	`, attempt.MemberUID)
	if err != nil {
		return createdTenantMemberSession{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO tenant_member_sessions(
			uid,tenant_member_uid,tenant_uid,session_secret_hash,expires_at,idle_expires_at,
			authentication_assurance,strongly_authenticated_at
		) VALUES($1,$2,$3,$4,$5,$6,'strong',clock_timestamp())
	`, sessionUID, attempt.MemberUID, attempt.TenantUID, security.SessionHash(token), expiresAt, idleExpiresAt)
	if err == nil {
		_, err = tx.Exec(ctx, `
			INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata)
			VALUES($1,$2,'tenant_member',$3,'tenant_member.strongly_authenticated','tenant_member',$3,$4)
		`, uuid.New(), attempt.TenantUID, attempt.MemberUID, map[string]any{"credential_kind": mode})
	}
	if err != nil {
		return createdTenantMemberSession{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return createdTenantMemberSession{}, err
	}
	return createdTenantMemberSession{Token: token, ExpiresAt: expiresAt}, nil
}

func (s *Server) beginInitialTenantMemberWebAuthnEnrollment(w http.ResponseWriter, r *http.Request) {
	attempt, ok := s.resolveTenantMemberLoginAttempt(r)
	if !ok || !attempt.PasswordVerified || attempt.MemberUID == "" {
		fail(w, r, http.StatusUnauthorized, "additional_factor_required", "verify the password factor first")
		return
	}
	var in struct {
		Name string `json:"name"`
		Mode string `json:"mode"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if !fidoMode(in.Mode, true) || len(in.Name) < 1 || len(in.Name) > 100 {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "name and a passkey or security_key mode are required")
		return
	}
	var count int
	if err := s.db.QueryRow(r.Context(), `SELECT count(*) FROM tenant_member_webauthn_credentials WHERE tenant_member_uid=$1`, attempt.MemberUID).Scan(&count); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not inspect authentication credentials")
		return
	}
	if count != 0 {
		fail(w, r, http.StatusConflict, "enrollment_not_allowed", "initial enrollment is available only before the first credential")
		return
	}
	s.beginTenantMemberRegistration(w, r, attempt, nil, in.Name, in.Mode)
}

func (s *Server) beginSessionTenantMemberWebAuthnEnrollment(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	var in struct {
		Name string `json:"name"`
		Mode string `json:"mode"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if !fidoMode(in.Mode, true) || len(in.Name) < 1 || len(in.Name) > 100 {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "name and a passkey or security_key mode are required")
		return
	}
	var count int
	if err := s.db.QueryRow(r.Context(), `SELECT count(*) FROM tenant_member_webauthn_credentials WHERE tenant_member_uid=$1`, p.MemberUID).Scan(&count); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not inspect authentication credentials")
		return
	}
	if count >= maxTenantMemberCredentials {
		fail(w, r, http.StatusConflict, "credential_limit_reached", "a Tenant Member may have at most 10 credentials")
		return
	}
	attempt := tenantMemberLoginAttemptState{TenantUID: p.TenantUID, MemberUID: p.MemberUID}
	s.beginTenantMemberRegistration(w, r, attempt, &p, in.Name, in.Mode)
}

func (s *Server) beginTenantMemberRegistration(w http.ResponseWriter, r *http.Request, attempt tenantMemberLoginAttemptState, p *principal, name, mode string) {
	user, err := s.loadTenantMemberWebUser(r.Context(), attempt.TenantUID, attempt.MemberUID, "")
	if err != nil {
		fail(w, r, http.StatusNotFound, "tenant_member_not_found", "Tenant Member was not found")
		return
	}
	wa, err := s.tenantMemberWebAuthn()
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "webauthn_configuration", "management WebAuthn configuration is invalid")
		return
	}
	attachment := protocol.Platform
	attestation := protocol.PreferNoAttestation
	if mode == "security_key" {
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
		webauthn.WithPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{fidoHint(mode)}),
	)
	if err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "webauthn_begin_failed", "could not start credential enrollment")
		return
	}
	if p == nil {
		s.writeTenantMemberLoginCeremony(w, r, attempt, "registration", mode, name, session, options.Response)
		return
	}
	raw, err := json.Marshal(session)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not store WebAuthn ceremony")
		return
	}
	ceremonyUID := uuid.NewString()
	expiresAt := time.Now().Add(tenantMemberLoginAttemptTTL)
	_, err = s.db.Exec(r.Context(), `
		INSERT INTO tenant_member_webauthn_ceremonies(
			uid,tenant_uid,tenant_member_uid,tenant_member_session_uid,ceremony_type,
			credential_kind,credential_name,session_data,expires_at
		) VALUES($1,$2,$3,$4,'registration',$5,$6,$7,$8)
	`, ceremonyUID, p.TenantUID, p.MemberUID, p.SessionUID, mode, name, raw, expiresAt)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not store WebAuthn ceremony")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"uid": ceremonyUID, "expires_at": expiresAt, "public_key": options.Response})
}

func (s *Server) finishInitialTenantMemberWebAuthnEnrollment(w http.ResponseWriter, r *http.Request) {
	attempt, ok := s.resolveTenantMemberLoginAttempt(r)
	if !ok || !attempt.PasswordVerified || attempt.MemberUID == "" {
		fail(w, r, http.StatusUnauthorized, "additional_factor_required", "verify the password factor first")
		return
	}
	credential, ceremony, ok := s.verifyTenantMemberRegistration(w, r, attempt.MemberUID, attempt.TenantUID, attempt.UID, "")
	if !ok {
		return
	}
	createdSession, err := s.persistInitialTenantMemberCredentialAndSession(r.Context(), attempt, ceremony, credential)
	if err != nil {
		if errors.Is(err, errTenantMemberCredentialConflict) {
			fail(w, r, http.StatusConflict, "credential_exists", "an initial credential is already registered")
		} else {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not save authentication credential")
		}
		return
	}
	s.writeStrongTenantMemberSession(w, attempt, createdSession)
}

func (s *Server) finishSessionTenantMemberWebAuthnEnrollment(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	credential, ceremony, ok := s.verifyTenantMemberRegistration(w, r, p.MemberUID, p.TenantUID, "", p.SessionUID)
	if !ok {
		return
	}
	record, err := s.persistSessionTenantMemberCredential(r.Context(), p, ceremony, credential)
	if err != nil {
		if errors.Is(err, errTenantMemberCredentialLimit) {
			fail(w, r, http.StatusConflict, "credential_limit_reached", "a Tenant Member may have at most 10 credentials")
		} else if errors.Is(err, errTenantMemberCredentialConflict) {
			fail(w, r, http.StatusConflict, "credential_exists", "credential name or authenticator is already registered")
		} else {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not save authentication credential")
		}
		return
	}
	setVersionETag(w, record.Version)
	writeJSON(w, http.StatusCreated, record)
}

func (s *Server) verifyTenantMemberRegistration(w http.ResponseWriter, r *http.Request, memberUID, tenantUID, loginUID, sessionUID string) (*webauthn.Credential, tenantMemberCeremony, bool) {
	var in struct {
		Mode        string          `json:"mode"`
		CeremonyUID string          `json:"ceremony_uid"`
		Credential  json.RawMessage `json:"credential"`
	}
	if !decode(w, r, &in) {
		return nil, tenantMemberCeremony{}, false
	}
	ceremony, ok := s.consumeTenantMemberCeremony(r.Context(), in.CeremonyUID, "registration")
	if !ok || ceremony.MemberUID != memberUID || ceremony.TenantUID != tenantUID || ceremony.Kind != in.Mode || ceremony.LoginAttemptUID != loginUID || ceremony.MemberSessionUID != sessionUID || !fidoMode(in.Mode, true) {
		fail(w, r, http.StatusBadRequest, "invalid_ceremony", "ceremony is expired, consumed, or does not match the enrollment")
		return nil, tenantMemberCeremony{}, false
	}
	user, err := s.loadTenantMemberWebUser(r.Context(), tenantUID, memberUID, "")
	if err != nil {
		fail(w, r, http.StatusNotFound, "tenant_member_not_found", "Tenant Member was not found")
		return nil, tenantMemberCeremony{}, false
	}
	wa, err := s.tenantMemberWebAuthn()
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "webauthn_configuration", "management WebAuthn configuration is invalid")
		return nil, tenantMemberCeremony{}, false
	}
	credential, err := wa.FinishRegistration(user, ceremony.Session, credentialRequest(r, in.Credential))
	if err != nil {
		fail(w, r, http.StatusBadRequest, "webauthn_verification_failed", "credential verification failed")
		return nil, tenantMemberCeremony{}, false
	}
	attested := credential.AttestationType != "" && credential.AttestationType != "none" && credential.AttestationFormat != "none"
	if in.Mode == "security_key" && !attested {
		fail(w, r, http.StatusBadRequest, "attestation_required", "security key did not provide attestation")
		return nil, tenantMemberCeremony{}, false
	}
	return credential, ceremony, true
}

func (s *Server) persistInitialTenantMemberCredentialAndSession(ctx context.Context, attempt tenantMemberLoginAttemptState, ceremony tenantMemberCeremony, credential *webauthn.Credential) (createdTenantMemberSession, error) {
	raw, err := json.Marshal(credential)
	if err != nil {
		return createdTenantMemberSession{}, err
	}
	token, err := security.RandomToken()
	if err != nil {
		return createdTenantMemberSession{}, err
	}
	expiresAt, idleExpiresAt := time.Now().Add(s.cfg.MemberAbsoluteTTL), time.Now().Add(s.cfg.MemberIdleTTL)
	sessionUID := uuid.NewString()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return createdTenantMemberSession{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT uid FROM tenant_members WHERE uid=$1 AND tenant_uid=$2 FOR UPDATE`, attempt.MemberUID, attempt.TenantUID); err != nil {
		return createdTenantMemberSession{}, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM tenant_member_webauthn_credentials WHERE tenant_member_uid=$1`, attempt.MemberUID).Scan(&count); err != nil || count != 0 {
		if err != nil {
			return createdTenantMemberSession{}, err
		}
		return createdTenantMemberSession{}, errTenantMemberCredentialConflict
	}
	credentialUID := uuid.NewString()
	attested := credential.AttestationType != "" && credential.AttestationType != "none" && credential.AttestationFormat != "none"
	_, err = tx.Exec(ctx, `
		INSERT INTO tenant_member_webauthn_credentials(
			uid,tenant_uid,tenant_member_uid,credential_id,credential_json,name,credential_kind,attested
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
	`, credentialUID, attempt.TenantUID, attempt.MemberUID, credential.ID, raw, ceremony.Name, ceremony.Kind, attested)
	if isUniqueViolation(err) {
		return createdTenantMemberSession{}, errTenantMemberCredentialConflict
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE tenant_member_login_attempts SET consumed_at=clock_timestamp() WHERE uid=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()`, attempt.UID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `
			UPDATE tenant_member_sessions
			SET revoked_at=COALESCE(revoked_at,clock_timestamp())
			WHERE tenant_member_uid=$1 AND authentication_assurance='bootstrap' AND revoked_at IS NULL
		`, attempt.MemberUID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `
			INSERT INTO tenant_member_sessions(
				uid,tenant_member_uid,tenant_uid,session_secret_hash,expires_at,idle_expires_at,
				authentication_assurance,strongly_authenticated_at
			) VALUES($1,$2,$3,$4,$5,$6,'strong',clock_timestamp())
		`, sessionUID, attempt.MemberUID, attempt.TenantUID, security.SessionHash(token), expiresAt, idleExpiresAt)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `
			INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata)
			VALUES($1,$2,'tenant_member',$3,'tenant_member.webauthn_credential.created','tenant_member_webauthn_credential',$4,$5)
		`, uuid.New(), attempt.TenantUID, attempt.MemberUID, credentialUID, map[string]any{"credential_kind": ceremony.Kind, "initial": true})
	}
	if err != nil {
		return createdTenantMemberSession{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return createdTenantMemberSession{}, err
	}
	return createdTenantMemberSession{Token: token, ExpiresAt: expiresAt}, nil
}

func (s *Server) persistSessionTenantMemberCredential(ctx context.Context, p principal, ceremony tenantMemberCeremony, credential *webauthn.Credential) (TenantMemberWebAuthnCredential, error) {
	raw, err := json.Marshal(credential)
	if err != nil {
		return TenantMemberWebAuthnCredential{}, err
	}
	now := time.Now().UTC()
	record := TenantMemberWebAuthnCredential{
		UID: uuid.NewString(), Name: ceremony.Name, Kind: ceremony.Kind,
		Attested: credential.AttestationType != "" && credential.AttestationType != "none" && credential.AttestationFormat != "none",
		Version:  1, CreatedAt: now, UpdatedAt: now,
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return TenantMemberWebAuthnCredential{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT uid FROM tenant_members WHERE uid=$1 AND tenant_uid=$2 FOR UPDATE`, p.MemberUID, p.TenantUID); err != nil {
		return TenantMemberWebAuthnCredential{}, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM tenant_member_webauthn_credentials WHERE tenant_member_uid=$1`, p.MemberUID).Scan(&count); err != nil || count >= maxTenantMemberCredentials {
		if err != nil {
			return TenantMemberWebAuthnCredential{}, err
		}
		return TenantMemberWebAuthnCredential{}, errTenantMemberCredentialLimit
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO tenant_member_webauthn_credentials(
			uid,tenant_uid,tenant_member_uid,credential_id,credential_json,name,credential_kind,attested,created_at,updated_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)
	`, record.UID, p.TenantUID, p.MemberUID, credential.ID, raw, record.Name, record.Kind, record.Attested, now)
	if isUniqueViolation(err) {
		return TenantMemberWebAuthnCredential{}, errTenantMemberCredentialConflict
	}
	if err == nil {
		_, err = tx.Exec(ctx, `
			UPDATE tenant_member_sessions
			SET authentication_assurance='strong',strongly_authenticated_at=COALESCE(strongly_authenticated_at,clock_timestamp())
			WHERE uid=$1 AND tenant_member_uid=$2 AND tenant_uid=$3
		`, p.SessionUID, p.MemberUID, p.TenantUID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `
			INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata)
			VALUES($1,$2,'tenant_member',$3,'tenant_member.webauthn_credential.created','tenant_member_webauthn_credential',$4,$5)
		`, uuid.New(), p.TenantUID, p.MemberUID, record.UID, map[string]any{"credential_kind": record.Kind, "initial": count == 0})
	}
	if err != nil {
		return TenantMemberWebAuthnCredential{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return TenantMemberWebAuthnCredential{}, err
	}
	return record, nil
}

func (s *Server) writeStrongTenantMemberSession(w http.ResponseWriter, attempt tenantMemberLoginAttemptState, created createdTenantMemberSession) {
	s.setMemberCookie(w, created.Token, created.ExpiresAt)
	writeJSON(w, http.StatusOK, ConsoleSession{
		Tenant: Tenant{UID: attempt.TenantUID, Name: attempt.TenantName, Slug: attempt.TenantSlug},
		Member: TenantMember{
			UID: attempt.MemberUID, Email: attempt.Email, DisplayName: attempt.DisplayName,
			Role: attempt.Role, Status: attempt.Status, EmailVerified: attempt.EmailVerified,
			CreatedAt: attempt.MemberCreatedAt,
		},
		AuthenticationAssurance: "strong",
		ExpiresAt:               created.ExpiresAt,
	})
}

func (s *Server) consumeTenantMemberCeremony(ctx context.Context, ceremonyUID, ceremonyType string) (tenantMemberCeremony, bool) {
	if _, err := uuid.Parse(ceremonyUID); err != nil {
		return tenantMemberCeremony{}, false
	}
	var raw []byte
	var loginUID, sessionUID, name *string
	var ceremony tenantMemberCeremony
	err := s.db.QueryRow(ctx, `
		UPDATE tenant_member_webauthn_ceremonies
		SET consumed_at=clock_timestamp()
		WHERE uid=$1 AND ceremony_type=$2 AND consumed_at IS NULL AND expires_at>clock_timestamp()
		RETURNING session_data,tenant_uid,tenant_member_uid,login_attempt_uid,
		          tenant_member_session_uid,credential_kind,credential_name
	`, ceremonyUID, ceremonyType).Scan(
		&raw, &ceremony.TenantUID, &ceremony.MemberUID, &loginUID,
		&sessionUID, &ceremony.Kind, &name,
	)
	if err != nil || json.Unmarshal(raw, &ceremony.Session) != nil {
		return tenantMemberCeremony{}, false
	}
	if loginUID != nil {
		ceremony.LoginAttemptUID = *loginUID
	}
	if sessionUID != nil {
		ceremony.MemberSessionUID = *sessionUID
	}
	if name != nil {
		ceremony.Name = *name
	}
	return ceremony, true
}

func scanTenantMemberWebAuthnCredential(row rowScanner) (TenantMemberWebAuthnCredential, error) {
	var record TenantMemberWebAuthnCredential
	err := row.Scan(&record.UID, &record.Name, &record.Kind, &record.Attested, &record.Version, &record.CreatedAt, &record.UpdatedAt, &record.LastUsedAt)
	return record, err
}

func (s *Server) listTenantMemberWebAuthnCredentials(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	rows, err := s.db.Query(r.Context(), `
		SELECT uid,name,credential_kind,attested,version,created_at,updated_at,last_used_at
		FROM tenant_member_webauthn_credentials
		WHERE tenant_uid=$1 AND tenant_member_uid=$2
		ORDER BY created_at DESC,uid DESC
	`, p.TenantUID, p.MemberUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load authentication credentials")
		return
	}
	defer rows.Close()
	items := make([]TenantMemberWebAuthnCredential, 0)
	for rows.Next() {
		item, scanErr := scanTenantMemberWebAuthnCredential(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load authentication credentials")
			return
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) updateTenantMemberWebAuthnCredential(w http.ResponseWriter, r *http.Request) {
	version, ok := requireIfMatch(w, r)
	if !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if len(in.Name) < 1 || len(in.Name) > 100 {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "name must contain between 1 and 100 characters")
		return
	}
	p := mustPrincipal(r)
	command, err := s.db.Exec(r.Context(), `
		UPDATE tenant_member_webauthn_credentials
		SET name=$5,version=version+1,updated_at=clock_timestamp()
		WHERE uid=$1 AND tenant_uid=$2 AND tenant_member_uid=$3 AND version=$4
	`, r.PathValue("credential_uid"), p.TenantUID, p.MemberUID, version, in.Name)
	if err != nil {
		if isUniqueViolation(err) {
			fail(w, r, http.StatusConflict, "credential_name_exists", "another credential already uses this name")
		} else {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not update authentication credential")
		}
		return
	}
	if command.RowsAffected() != 1 {
		var currentVersion int64
		err = s.db.QueryRow(r.Context(), `SELECT version FROM tenant_member_webauthn_credentials WHERE uid=$1 AND tenant_uid=$2 AND tenant_member_uid=$3`, r.PathValue("credential_uid"), p.TenantUID, p.MemberUID).Scan(&currentVersion)
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, r, http.StatusNotFound, "webauthn_credential_not_found", "WebAuthn credential was not found")
			return
		}
		setVersionETag(w, currentVersion)
		fail(w, r, http.StatusPreconditionFailed, "version_conflict", "credential changed; retrieve its latest representation")
		return
	}
	record, err := scanTenantMemberWebAuthnCredential(s.db.QueryRow(r.Context(), `
		SELECT uid,name,credential_kind,attested,version,created_at,updated_at,last_used_at
		FROM tenant_member_webauthn_credentials WHERE uid=$1
	`, r.PathValue("credential_uid")))
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load authentication credential")
		return
	}
	s.audit(r.Context(), p.TenantUID, "", "tenant_member", p.MemberUID, "tenant_member.webauthn_credential.updated", "tenant_member_webauthn_credential", record.UID, nil, r)
	setVersionETag(w, record.Version)
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) deleteTenantMemberWebAuthnCredential(w http.ResponseWriter, r *http.Request) {
	version, ok := requireIfMatch(w, r)
	if !ok {
		return
	}
	p := mustPrincipal(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not remove authentication credential")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `SELECT uid FROM tenant_members WHERE uid=$1 AND tenant_uid=$2 FOR UPDATE`, p.MemberUID, p.TenantUID); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not remove authentication credential")
		return
	}
	var currentVersion int64
	err = tx.QueryRow(r.Context(), `
		SELECT version FROM tenant_member_webauthn_credentials
		WHERE uid=$1 AND tenant_uid=$2 AND tenant_member_uid=$3
		FOR UPDATE
	`, r.PathValue("credential_uid"), p.TenantUID, p.MemberUID).Scan(&currentVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "webauthn_credential_not_found", "WebAuthn credential was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not remove authentication credential")
		return
	}
	if currentVersion != version {
		setVersionETag(w, currentVersion)
		fail(w, r, http.StatusPreconditionFailed, "version_conflict", "credential changed; retrieve its latest representation")
		return
	}
	var count int
	if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM tenant_member_webauthn_credentials WHERE tenant_member_uid=$1`, p.MemberUID).Scan(&count); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not remove authentication credential")
		return
	}
	if count <= 1 {
		fail(w, r, http.StatusConflict, "last_credential", "the final authentication credential cannot be removed; enroll a replacement first")
		return
	}
	command, err := tx.Exec(r.Context(), `
		DELETE FROM tenant_member_webauthn_credentials
		WHERE uid=$1 AND tenant_uid=$2 AND tenant_member_uid=$3
	`, r.PathValue("credential_uid"), p.TenantUID, p.MemberUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not remove authentication credential")
		return
	}
	if command.RowsAffected() != 1 {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not remove authentication credential")
		return
	}
	_, err = tx.Exec(r.Context(), `
		UPDATE tenant_member_sessions
		SET revoked_at=COALESCE(revoked_at,clock_timestamp())
		WHERE tenant_member_uid=$1 AND uid<>$2 AND revoked_at IS NULL
	`, p.MemberUID, p.SessionUID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `
			INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid)
			VALUES($1,$2,'tenant_member',$3,'tenant_member.webauthn_credential.deleted','tenant_member_webauthn_credential',$4)
		`, uuid.New(), p.TenantUID, p.MemberUID, r.PathValue("credential_uid"))
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not remove authentication credential")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func isUniqueViolation(err error) bool {
	var databaseError *pgconn.PgError
	return errors.As(err, &databaseError) && databaseError.Code == "23505"
}
