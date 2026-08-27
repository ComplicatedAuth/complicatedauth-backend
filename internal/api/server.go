package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	security "github.com/complicatedauth/complicatedauth-backend/internal/auth"
	"github.com/complicatedauth/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type contextKey string

const principalKey contextKey = "consolePrincipal"

type principal struct {
	TenantUID, MemberUID, SessionUID, Role string
	AuthenticationAssurance                string
}

type Server struct {
	cfg         Config
	db          *pgxpool.Pool
	log         *slog.Logger
	rateLimits  *store.RateLimiter
	idempotency *store.IdempotencyStore
	biometrics  biometricProvider
	email       emailSender
}

func New(cfg Config, db *pgxpool.Pool, logger *slog.Logger) *Server {
	return newServer(cfg, db, logger, configuredBiometricProvider(cfg))
}

func newServer(cfg Config, db *pgxpool.Pool, logger *slog.Logger, biometrics biometricProvider) *Server {
	return &Server{cfg: cfg, db: db, log: logger, rateLimits: store.NewRateLimiter(db), idempotency: store.NewIdempotencyStore(db), biometrics: biometrics, email: configuredEmailSender(cfg)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /health/ready", s.ready)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.oidcDiscovery)
	mux.HandleFunc("GET /oauth/jwks", s.oauthJWKS)
	mux.HandleFunc("GET /oauth/authorize", s.oauthAuthorize)
	mux.HandleFunc("POST /oauth/token", s.oauthToken)
	mux.HandleFunc("GET /oauth/userinfo", s.oauthUserInfo)
	mux.HandleFunc("POST /oauth/revoke", s.oauthRevoke)
	mux.Handle("POST /v1/console/auth/signup", s.csrf(http.HandlerFunc(s.signup)))
	mux.Handle("POST /v1/console/login-attempts", s.csrf(http.HandlerFunc(s.createTenantMemberLoginAttempt)))
	mux.Handle("POST /v1/console/login-attempts/{login_attempt_uid}/password-verifications", s.csrf(http.HandlerFunc(s.verifyTenantMemberLoginPassword)))
	mux.Handle("POST /v1/console/login-attempts/{login_attempt_uid}/webauthn-authentication-ceremonies", s.csrf(http.HandlerFunc(s.beginTenantMemberWebAuthnLogin)))
	mux.Handle("POST /v1/console/login-attempts/{login_attempt_uid}/webauthn-authentication-verifications", s.csrf(http.HandlerFunc(s.finishTenantMemberWebAuthnLogin)))
	mux.Handle("POST /v1/console/login-attempts/{login_attempt_uid}/webauthn-registration-ceremonies", s.csrf(http.HandlerFunc(s.beginInitialTenantMemberWebAuthnEnrollment)))
	mux.Handle("POST /v1/console/login-attempts/{login_attempt_uid}/webauthn-registration-verifications", s.csrf(http.HandlerFunc(s.finishInitialTenantMemberWebAuthnEnrollment)))
	mux.Handle("POST /v1/console/email-verification-requests", s.csrf(http.HandlerFunc(s.createTenantEmailVerificationRequest)))
	mux.Handle("POST /v1/console/email-verifications", s.csrf(http.HandlerFunc(s.verifyTenantEmail)))
	mux.Handle("POST /v1/console/password-reset-requests", s.csrf(http.HandlerFunc(s.createTenantPasswordResetRequest)))
	mux.Handle("POST /v1/console/password-resets", s.csrf(http.HandlerFunc(s.resetTenantMemberPassword)))
	mux.Handle("POST /v1/console/auth/logout", s.consoleSession(http.HandlerFunc(s.logout)))
	mux.Handle("GET /v1/console/auth/session", s.consoleSession(http.HandlerFunc(s.session)))
	mux.Handle("GET /v1/console/auth/sessions", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.listMemberSessions)))
	mux.Handle("DELETE /v1/console/auth/sessions/{session_uid}", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.revokeMemberSession)))
	mux.Handle("GET /v1/console/webauthn-credentials", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.listTenantMemberWebAuthnCredentials)))
	mux.Handle("POST /v1/console/webauthn-registration-ceremonies", s.consoleSession(http.HandlerFunc(s.beginSessionTenantMemberWebAuthnEnrollment)))
	mux.Handle("POST /v1/console/webauthn-registration-verifications", s.consoleSession(http.HandlerFunc(s.finishSessionTenantMemberWebAuthnEnrollment)))
	mux.Handle("PATCH /v1/console/webauthn-credentials/{credential_uid}", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.updateTenantMemberWebAuthnCredential)))
	mux.Handle("DELETE /v1/console/webauthn-credentials/{credential_uid}", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.deleteTenantMemberWebAuthnCredential)))

	mux.Handle("GET /v1/tenant/members", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.listTenantMembers)))
	mux.Handle("GET /v1/tenant/members/{member_uid}", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.getTenantMember)))
	mux.Handle("PATCH /v1/tenant/members/{member_uid}", s.consoleAuthorized(permissionManageTenant, http.HandlerFunc(s.updateTenantMember)))
	mux.Handle("DELETE /v1/tenant/members/{member_uid}", s.consoleAuthorized(permissionManageTenant, http.HandlerFunc(s.removeTenantMember)))
	mux.Handle("GET /v1/tenant/invitations", s.consoleAuthorized(permissionManageTenant, http.HandlerFunc(s.listTenantInvitations)))
	mux.Handle("POST /v1/tenant/invitations", s.consoleAuthorized(permissionManageTenant, http.HandlerFunc(s.createTenantInvitation)))
	mux.Handle("DELETE /v1/tenant/invitations/{invitation_uid}", s.consoleAuthorized(permissionManageTenant, http.HandlerFunc(s.revokeTenantInvitation)))
	mux.Handle("POST /v1/tenant/invitations/{invitation_uid}/accept", s.csrf(http.HandlerFunc(s.acceptTenantInvitation)))
	mux.Handle("GET /v1/oauth/applications", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.listOAuthApplications)))
	mux.Handle("POST /v1/oauth/applications", s.consoleAuthorized(permissionManageOAuth, http.HandlerFunc(s.createOAuthApplication)))
	mux.Handle("GET /v1/oauth/applications/{application_uid}", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.getOAuthApplication)))
	mux.Handle("PATCH /v1/oauth/applications/{application_uid}", s.consoleAuthorized(permissionManageOAuth, http.HandlerFunc(s.updateOAuthApplication)))
	mux.Handle("DELETE /v1/oauth/applications/{application_uid}", s.consoleAuthorized(permissionManageOAuth, http.HandlerFunc(s.deleteOAuthApplication)))
	mux.Handle("GET /v1/oauth/applications/{application_uid}/client-secrets", s.consoleAuthorized(permissionManageOAuth, http.HandlerFunc(s.listOAuthClientSecrets)))
	mux.Handle("POST /v1/oauth/applications/{application_uid}/client-secrets", s.consoleAuthorized(permissionManageOAuth, http.HandlerFunc(s.createOAuthClientSecret)))
	mux.Handle("DELETE /v1/oauth/applications/{application_uid}/client-secrets/{secret_uid}", s.consoleAuthorized(permissionManageOAuth, http.HandlerFunc(s.revokeOAuthClientSecret)))
	mux.Handle("POST /v1/oauth/authorization-requests/inspect", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.inspectOAuthAuthorizationRequest)))
	mux.Handle("POST /v1/oauth/authorization-requests/decision", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.decideOAuthAuthorizationRequest)))
	mux.Handle("GET /v1/oauth/consents", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.listOAuthConsents)))
	mux.Handle("DELETE /v1/oauth/consents/{consent_uid}", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.revokeOAuthConsent)))
	mux.Handle("GET /v1/resource-servers", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.listResourceServers)))
	mux.Handle("POST /v1/resource-servers", s.consoleAuthorized(permissionManageAuthorization, http.HandlerFunc(s.createResourceServer)))
	mux.Handle("GET /v1/resource-servers/{resource_server_uid}", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.getResourceServer)))
	mux.Handle("PATCH /v1/resource-servers/{resource_server_uid}", s.consoleAuthorized(permissionManageAuthorization, http.HandlerFunc(s.updateResourceServer)))
	mux.Handle("DELETE /v1/resource-servers/{resource_server_uid}", s.consoleAuthorized(permissionManageAuthorization, http.HandlerFunc(s.deleteResourceServer)))
	mux.Handle("GET /v1/resource-servers/{resource_server_uid}/scopes", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.listResourceServerScopes)))
	mux.Handle("POST /v1/resource-servers/{resource_server_uid}/scopes", s.consoleAuthorized(permissionManageAuthorization, http.HandlerFunc(s.createResourceServerScope)))
	mux.Handle("GET /v1/resource-servers/{resource_server_uid}/scopes/{scope_uid}", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.getResourceServerScope)))
	mux.Handle("PATCH /v1/resource-servers/{resource_server_uid}/scopes/{scope_uid}", s.consoleAuthorized(permissionManageAuthorization, http.HandlerFunc(s.updateResourceServerScope)))
	mux.Handle("DELETE /v1/resource-servers/{resource_server_uid}/scopes/{scope_uid}", s.consoleAuthorized(permissionManageAuthorization, http.HandlerFunc(s.deleteResourceServerScope)))
	mux.Handle("GET /v1/oauth/applications/{application_uid}/grants", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.listOAuthApplicationGrants)))
	mux.Handle("POST /v1/oauth/applications/{application_uid}/grants", s.consoleAuthorized(permissionManageAuthorization, http.HandlerFunc(s.createOAuthApplicationGrant)))
	mux.Handle("GET /v1/oauth/applications/{application_uid}/grants/{grant_uid}", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.getOAuthApplicationGrant)))
	mux.Handle("PATCH /v1/oauth/applications/{application_uid}/grants/{grant_uid}", s.consoleAuthorized(permissionManageAuthorization, http.HandlerFunc(s.updateOAuthApplicationGrant)))
	mux.Handle("DELETE /v1/oauth/applications/{application_uid}/grants/{grant_uid}", s.consoleAuthorized(permissionManageAuthorization, http.HandlerFunc(s.deleteOAuthApplicationGrant)))
	mux.Handle("POST /v1/authorization/decisions", s.oauthResourceAuthorized(http.HandlerFunc(s.createAuthorizationDecision)))
	mux.Handle("POST /v1/access/evaluations", s.oauthResourceAuthorized(http.HandlerFunc(s.createAccessEvaluation)))
	mux.Handle("POST /v1/external-platform/credentials/authorize", s.serviceCredential(serviceScopeExternalCredentialsManage, http.HandlerFunc(s.authorizeExternalCredentialOperation)))
	mux.Handle("POST /v1/external-platform/credentials", s.serviceCredential(serviceScopeExternalCredentialsManage, http.HandlerFunc(s.issueExternalCredential)))
	mux.Handle("POST /v1/external-platform/credentials/{credential_uid}/revoke", s.serviceCredential(serviceScopeExternalCredentialsManage, http.HandlerFunc(s.revokeExternalCredential)))

	mux.Handle("GET /v1/projects", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.listProjects)))
	mux.Handle("POST /v1/projects", s.consoleAuthorized(permissionManageProjects, http.HandlerFunc(s.createProject)))
	mux.Handle("GET /v1/projects/{project_uid}", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.getProjectHandler)))
	mux.Handle("PATCH /v1/projects/{project_uid}", s.consoleAuthorized(permissionManageProjects, http.HandlerFunc(s.updateProject)))
	mux.Handle("GET /v1/projects/{project_uid}/origins", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.listOrigins)))
	mux.Handle("POST /v1/projects/{project_uid}/origins", s.consoleAuthorized(permissionManageProjects, http.HandlerFunc(s.createOrigin)))
	mux.Handle("DELETE /v1/projects/{project_uid}/origins/{origin_uid}", s.consoleAuthorized(permissionManageProjects, http.HandlerFunc(s.deleteOrigin)))
	mux.Handle("GET /v1/projects/{project_uid}/service-accounts", s.consoleAuthorized(permissionManageCredentials, http.HandlerFunc(s.listServiceAccounts)))
	mux.Handle("POST /v1/projects/{project_uid}/service-accounts", s.consoleAuthorized(permissionManageCredentials, http.HandlerFunc(s.createServiceAccount)))
	mux.Handle("GET /v1/projects/{project_uid}/service-accounts/{service_account_uid}", s.consoleAuthorized(permissionManageCredentials, http.HandlerFunc(s.getServiceAccount)))
	mux.Handle("PATCH /v1/projects/{project_uid}/service-accounts/{service_account_uid}", s.consoleAuthorized(permissionManageCredentials, http.HandlerFunc(s.updateServiceAccount)))
	mux.Handle("DELETE /v1/projects/{project_uid}/service-accounts/{service_account_uid}", s.consoleAuthorized(permissionManageCredentials, http.HandlerFunc(s.deleteServiceAccount)))
	mux.Handle("GET /v1/projects/{project_uid}/service-accounts/{service_account_uid}/credentials", s.consoleAuthorized(permissionManageCredentials, http.HandlerFunc(s.listServiceCredentials)))
	mux.Handle("POST /v1/projects/{project_uid}/service-accounts/{service_account_uid}/credentials", s.consoleAuthorized(permissionManageCredentials, http.HandlerFunc(s.createServiceCredential)))
	mux.Handle("GET /v1/projects/{project_uid}/service-accounts/{service_account_uid}/credentials/{credential_uid}", s.consoleAuthorized(permissionManageCredentials, http.HandlerFunc(s.getServiceCredential)))
	mux.Handle("DELETE /v1/projects/{project_uid}/service-accounts/{service_account_uid}/credentials/{credential_uid}", s.consoleAuthorized(permissionManageCredentials, http.HandlerFunc(s.revokeServiceCredential)))
	mux.Handle("GET /v1/projects/{project_uid}/users", s.consoleOrServiceCredential(permissionRead, serviceScopeProjectUsersRead, http.HandlerFunc(s.listProjectUsers)))
	mux.Handle("POST /v1/projects/{project_uid}/users", s.consoleOrServiceCredential(permissionManageUsers, serviceScopeProjectUsersWrite, http.HandlerFunc(s.createProjectUser)))
	mux.Handle("GET /v1/projects/{project_uid}/users/{user_uid}", s.consoleOrServiceCredential(permissionRead, serviceScopeProjectUsersRead, http.HandlerFunc(s.getProjectUserHandler)))
	mux.Handle("PATCH /v1/projects/{project_uid}/users/{user_uid}", s.consoleOrServiceCredential(permissionManageUsers, serviceScopeProjectUsersWrite, http.HandlerFunc(s.updateProjectUser)))
	mux.Handle("PUT /v1/projects/{project_uid}/users/{user_uid}/password", s.consoleOrServiceCredential(permissionManageUsers, serviceScopeProjectUsersWrite, http.HandlerFunc(s.replaceProjectUserPassword)))
	mux.Handle("POST /v1/projects/{project_uid}/users/{user_uid}/sessions/revoke", s.consoleOrServiceCredential(permissionSupportUsers, serviceScopeSessionsManage, http.HandlerFunc(s.revokeProjectUserSessions)))
	mux.Handle("DELETE /v1/projects/{project_uid}/users/{user_uid}/passkeys/{credential_uid}", s.consoleOrServiceCredential(permissionManageUsers, serviceScopeProjectUsersWrite, http.HandlerFunc(s.deletePasskey)))
	mux.Handle("GET /v1/support/cases", s.consoleOrServiceCredential(permissionManageSupport, serviceScopeSupportCasesRead, http.HandlerFunc(s.listSupportCases)))
	mux.Handle("POST /v1/support-submissions", s.serviceCredential(serviceScopeSupportCasesWrite, http.HandlerFunc(s.createSupportSubmission)))
	mux.Handle("POST /v1/support/cases", s.consoleOrServiceCredential(permissionManageSupport, serviceScopeSupportCasesWrite, http.HandlerFunc(s.createSupportCase)))
	mux.Handle("GET /v1/support/cases/{case_uid}", s.consoleOrServiceCredential(permissionManageSupport, serviceScopeSupportCasesRead, http.HandlerFunc(s.getSupportCase)))
	mux.Handle("PATCH /v1/support/cases/{case_uid}", s.consoleOrServiceCredential(permissionManageSupport, serviceScopeSupportCasesWrite, http.HandlerFunc(s.updateSupportCase)))
	mux.Handle("GET /v1/support/cases/{case_uid}/messages", s.consoleOrServiceCredential(permissionManageSupport, serviceScopeSupportCasesRead, http.HandlerFunc(s.listSupportCaseMessages)))
	mux.Handle("POST /v1/support/cases/{case_uid}/messages", s.consoleOrServiceCredential(permissionManageSupport, serviceScopeSupportCasesWrite, http.HandlerFunc(s.createSupportCaseMessage)))
	mux.Handle("GET /v1/support/cases/{case_uid}/attachments", s.consoleOrServiceCredential(permissionManageSupport, serviceScopeSupportCasesRead, http.HandlerFunc(s.listSupportCaseAttachments)))
	mux.Handle("POST /v1/support/cases/{case_uid}/attachments", s.consoleOrServiceCredential(permissionManageSupport, serviceScopeSupportCasesWrite, http.HandlerFunc(s.createSupportCaseAttachment)))
	mux.Handle("GET /v1/support/cases/{case_uid}/attachments/{attachment_uid}", s.consoleOrServiceCredential(permissionManageSupport, serviceScopeSupportCasesRead, http.HandlerFunc(s.getSupportCaseAttachment)))
	mux.Handle("GET /v1/support/cases/{case_uid}/attachments/{attachment_uid}/content", s.consoleOrServiceCredential(permissionManageSupport, serviceScopeSupportCasesRead, http.HandlerFunc(s.downloadSupportCaseAttachment)))
	mux.Handle("GET /v1/support/cases/{case_uid}/events", s.consoleOrServiceCredential(permissionManageSupport, serviceScopeSupportCasesRead, http.HandlerFunc(s.listSupportCaseEvents)))
	mux.Handle("GET /v1/support/cases/{case_uid}/external-references", s.consoleAuthorized(permissionManageSupport, http.HandlerFunc(s.listSupportCaseExternalReferences)))
	mux.Handle("POST /v1/support/cases/{case_uid}/external-references", s.consoleAuthorized(permissionManageSupport, http.HandlerFunc(s.createSupportCaseExternalReference)))
	mux.Handle("DELETE /v1/support/cases/{case_uid}/external-references/{external_reference_uid}", s.consoleAuthorized(permissionManageSupport, http.HandlerFunc(s.deleteSupportCaseExternalReference)))
	mux.Handle("GET /v1/projects/{project_uid}/activity", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.listActivity)))
	mux.Handle("GET /v1/activity", s.consoleAuthorized(permissionRead, http.HandlerFunc(s.listActivity)))

	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/start", s.serviceCredential(serviceScopeAuthentication, http.HandlerFunc(s.startProjectUserLogin)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/password", s.serviceCredential(serviceScopeAuthentication, http.HandlerFunc(s.verifyProjectUserLoginPassword)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/fido/options", s.serviceCredential(serviceScopeAuthentication, http.HandlerFunc(s.beginFidoLogin)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/fido/verify", s.serviceCredential(serviceScopeAuthentication, http.HandlerFunc(s.finishFidoLogin)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/fido/enrollment/options", s.serviceCredential(serviceScopeAuthentication, http.HandlerFunc(s.beginFirstFidoEnrollment)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/fido/enrollment/verify", s.serviceCredential(serviceScopeAuthentication, http.HandlerFunc(s.finishFirstFidoEnrollment)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/biometric", s.serviceCredential(serviceScopeAuthentication, http.HandlerFunc(s.verifyBiometricLogin)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/fido/registration/options", s.serviceCredential(serviceScopeAuthentication, http.HandlerFunc(s.beginFidoEnrollment)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/fido/registration/verify", s.serviceCredential(serviceScopeAuthentication, http.HandlerFunc(s.finishFidoEnrollment)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/biometric/enrollment", s.serviceCredential(serviceScopeAuthentication, http.HandlerFunc(s.enrollBiometric)))
	mux.Handle("DELETE /v1/projects/{project_uid}/runtime/biometric/enrollment", s.serviceCredential(serviceScopeAuthentication, http.HandlerFunc(s.deleteBiometricEnrollment)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/sessions/introspect", s.serviceCredential(serviceScopeSessionsManage, http.HandlerFunc(s.runtimeIntrospect)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/sessions/revoke", s.serviceCredential(serviceScopeSessionsManage, http.HandlerFunc(s.runtimeRevoke)))
	return s.requestLog(s.securityHeaders(mux))
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.db.Ping(r.Context()); err != nil {
		fail(w, r, http.StatusServiceUnavailable, "not_ready", "database is not ready")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.NewString()
		}
		r = r.WithContext(context.WithValue(r.Context(), contextKey("requestID"), requestID))
		w.Header().Set("X-Request-ID", requestID)
		start := time.Now()
		next.ServeHTTP(w, r)
		s.log.Info("request", "request_id", requestID, "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(start).Milliseconds())
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		candidate := r.Header.Get("Origin")
		if candidate == "" {
			if ref := r.Header.Get("Referer"); ref != "" {
				if parsed, err := url.Parse(ref); err == nil {
					candidate = parsed.Scheme + "://" + parsed.Host
				}
			}
		}
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(s.cfg.ConsoleOrigin)) != 1 {
			fail(w, r, http.StatusForbidden, "csrf_rejected", "request origin is not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) consoleSession(next http.Handler) http.Handler {
	return s.csrf(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("complicatedauth_session")
		if err != nil {
			fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		var p principal
		var expires, idle time.Time
		err = s.db.QueryRow(r.Context(), `SELECT s.uid, s.tenant_uid, s.tenant_member_uid, m.role, s.authentication_assurance, s.expires_at, s.idle_expires_at
			FROM tenant_member_sessions s JOIN tenant_members m ON m.uid=s.tenant_member_uid
			WHERE s.session_secret_hash=$1 AND s.revoked_at IS NULL AND m.status='active'`, security.SessionHash(cookie.Value)).Scan(&p.SessionUID, &p.TenantUID, &p.MemberUID, &p.Role, &p.AuthenticationAssurance, &expires, &idle)
		if err != nil || time.Now().After(expires) || time.Now().After(idle) {
			fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		_, _ = s.db.Exec(r.Context(), `UPDATE tenant_member_sessions SET last_seen_at=now(), idle_expires_at=LEAST(expires_at, now()+$2::interval) WHERE uid=$1`, p.SessionUID, "24 hours")
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	}))
}

func (s *Server) serviceCredential(requiredScope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, value, found := strings.Cut(r.Header.Get("Authorization"), " ")
		if !found || !strings.EqualFold(scheme, "Bearer") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="complicatedauth"`)
			fail(w, r, http.StatusUnauthorized, "invalid_service_credential", "valid Project service credential required")
			return
		}
		idx := strings.LastIndex(value, ".")
		if idx < 1 {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			fail(w, r, http.StatusUnauthorized, "invalid_service_credential", "valid Project service credential required")
			return
		}
		prefix := value[:idx]
		var credentialUID, accountUID, projectUID, tenantUID string
		var stored []byte
		var scopes []string
		err := s.db.QueryRow(r.Context(), `SELECT c.uid,a.uid,a.project_uid,p.tenant_uid,c.secret_hash,COALESCE(c.effective_scopes,a.scopes) FROM project_service_credentials c JOIN project_service_accounts a ON a.uid=c.service_account_uid JOIN projects p ON p.uid=a.project_uid WHERE c.prefix=$1 AND c.status='active' AND c.expires_at>now() AND a.status='active' AND a.deleted_at IS NULL AND p.status='active'`, prefix).Scan(&credentialUID, &accountUID, &projectUID, &tenantUID, &stored, &scopes)
		got := security.SecretHash(s.cfg.SecretHashKey, value)
		pathProjectUID := r.PathValue("project_uid")
		if err != nil || subtle.ConstantTimeCompare(stored, got) != 1 || (pathProjectUID != "" && projectUID != pathProjectUID) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			fail(w, r, http.StatusUnauthorized, "invalid_service_credential", "valid Project service credential required")
			return
		}
		allowed := false
		for _, scope := range scopes {
			if scope == requiredScope {
				allowed = true
				break
			}
		}
		if !allowed {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", scope=%q`, requiredScope))
			fail(w, r, http.StatusForbidden, "insufficient_scope", "service account does not grant the required scope")
			return
		}
		_, _ = s.db.Exec(r.Context(), `UPDATE project_service_credentials SET last_used_at=now() WHERE uid=$1 AND (last_used_at IS NULL OR last_used_at<now()-interval '1 minute')`, credentialUID)
		ctx := context.WithValue(r.Context(), contextKey("serviceCredentialUID"), credentialUID)
		ctx = context.WithValue(ctx, contextKey("serviceAccountUID"), accountUID)
		ctx = context.WithValue(ctx, contextKey("serviceTenantUID"), tenantUID)
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, contextKey("serviceProjectUID"), projectUID)))
	})
}

func (s *Server) consoleAuthorized(permission string, next http.Handler) http.Handler {
	return s.consoleSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mustPrincipal(r).AuthenticationAssurance != "strong" {
			fail(w, r, http.StatusForbidden, "strong_authentication_required", "complete passkey setup before using the management API")
			return
		}
		if !roleAllows(mustPrincipal(r).Role, permission) {
			fail(w, r, http.StatusForbidden, "forbidden", "the Tenant Member role does not permit this operation")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func (s *Server) consoleOrServiceCredential(permission, requiredScope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, _, hasCredentials := strings.Cut(r.Header.Get("Authorization"), " ")
		if hasCredentials && strings.EqualFold(scheme, "Bearer") {
			s.serviceCredential(requiredScope, next).ServeHTTP(w, r)
			return
		}
		s.consoleAuthorized(permission, next).ServeHTTP(w, r)
	})
}

func (s *Server) signup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
		TenantName  string `json:"tenant_name"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Email = normalizeEmail(in.Email)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.TenantName = strings.TrimSpace(in.TenantName)
	if in.Email == "" || in.DisplayName == "" || in.TenantName == "" {
		fail(w, r, 422, "validation_failed", "all fields are required")
		return
	}
	passwordHash, err := security.HashPassword(in.Password)
	if err != nil {
		fail(w, r, 422, "validation_failed", err.Error())
		return
	}
	token, err := security.RandomToken()
	if err != nil {
		fail(w, r, 500, "internal_error", "could not create account")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, 500, "internal_error", "could not create account")
		return
	}
	defer tx.Rollback(r.Context())
	tenantUID, memberUID, sessionUID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	slug, err := uniqueSlug(r.Context(), tx, in.TenantName)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO tenants(uid,name,slug) VALUES($1,$2,$3)`, tenantUID, in.TenantName, slug)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO tenant_members(uid,tenant_uid,email,email_normalized,display_name,role,password_hash) VALUES($1,$2,$3,$4,$5,'owner',$6)`, memberUID, tenantUID, in.Email, in.Email, in.DisplayName, passwordHash)
	}
	expires, idle := time.Now().Add(s.cfg.MemberAbsoluteTTL), time.Now().Add(s.cfg.MemberIdleTTL)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO tenant_member_sessions(uid,tenant_member_uid,tenant_uid,session_secret_hash,expires_at,idle_expires_at) VALUES($1,$2,$3,$4,$5,$6)`, sessionUID, memberUID, tenantUID, security.SessionHash(token), expires, idle)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid) VALUES($1,$2,'tenant_member',$3,'tenant.created','tenant',$2)`, uuid.NewString(), tenantUID, memberUID)
	}
	if err == nil {
		err = s.insertTenantEmailVerification(r.Context(), tx, memberUID, tenantUID, in.Email, in.DisplayName, in.TenantName)
	}
	if err != nil {
		if strings.Contains(err.Error(), "email_normalized") {
			fail(w, r, 409, "email_exists", "an account with this email already exists")
		} else {
			fail(w, r, 500, "internal_error", "could not create account")
		}
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		fail(w, r, 500, "internal_error", "could not create account")
		return
	}
	s.setMemberCookie(w, token, expires)
	writeJSON(w, 201, ConsoleSession{Tenant: Tenant{tenantUID, in.TenantName, slug}, Member: TenantMember{UID: memberUID, Email: in.Email, DisplayName: in.DisplayName, Role: "owner", Status: "active", CreatedAt: time.Now()}, AuthenticationAssurance: "bootstrap", ExpiresAt: expires})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	_, _ = s.db.Exec(r.Context(), `UPDATE tenant_member_sessions SET revoked_at=now() WHERE uid=$1`, p.SessionUID)
	http.SetCookie(w, &http.Cookie{Name: "complicatedauth_session", Value: "", Path: "/", HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(0, 0)})
	w.WriteHeader(204)
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	var result ConsoleSession
	err := s.db.QueryRow(r.Context(), `SELECT t.uid,t.name,t.slug,m.uid,m.email,m.display_name,m.role,m.status,m.email_verified_at IS NOT NULL,m.created_at,s.authentication_assurance,s.expires_at FROM tenant_member_sessions s JOIN tenant_members m ON m.uid=s.tenant_member_uid JOIN tenants t ON t.uid=s.tenant_uid WHERE s.uid=$1`, p.SessionUID).Scan(&result.Tenant.UID, &result.Tenant.Name, &result.Tenant.Slug, &result.Member.UID, &result.Member.Email, &result.Member.DisplayName, &result.Member.Role, &result.Member.Status, &result.Member.EmailVerified, &result.Member.CreatedAt, &result.AuthenticationAssurance, &result.ExpiresAt)
	if err != nil {
		fail(w, r, 401, "unauthenticated", "authentication required")
		return
	}
	writeJSON(w, 200, result)
}

func (s *Server) setMemberCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: "complicatedauth_session", Value: token, Path: "/", HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, Expires: expires})
}

func (s *Server) takeRateLimit(w http.ResponseWriter, r *http.Request, policy, key string, limit int, window time.Duration) bool {
	keyHash := security.SecretHash(s.cfg.SecretHashKey, policy+"\x00"+key)
	result, err := s.rateLimits.Take(r.Context(), policy, keyHash, limit, window)
	if err != nil {
		s.log.Error("rate limit unavailable", "request_id", r.Context().Value(contextKey("requestID")), "policy", policy, "error", err)
		fail(w, r, http.StatusServiceUnavailable, "dependency_unavailable", "request safety dependency is unavailable")
		return false
	}
	if result.Allowed {
		return true
	}
	seconds := int64(result.RetryAfter / time.Second)
	if result.RetryAfter%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	fail(w, r, http.StatusTooManyRequests, "rate_limited", "too many attempts; retry later")
	return false
}

func (s *Server) resetRateLimit(r *http.Request, policy, key string) {
	keyHash := security.SecretHash(s.cfg.SecretHashKey, policy+"\x00"+key)
	if err := s.rateLimits.Reset(r.Context(), policy, keyHash); err != nil {
		s.log.Warn("rate limit reset failed", "request_id", r.Context().Value(contextKey("requestID")), "policy", policy, "error", err)
	}
}

var slugInvalid = regexp.MustCompile(`[^a-z0-9]+`)

func uniqueSlug(ctx context.Context, tx pgx.Tx, name string) (string, error) {
	base := strings.Trim(slugInvalid.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if base == "" {
		base = "tenant"
	}
	if len(base) > 50 {
		base = base[:50]
	}
	for i := 0; i < 1000; i++ {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d", base, i+1)
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE slug=$1)`, candidate).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}
	return "", errors.New("slug exhausted")
}
func normalizeEmail(v string) string { return strings.ToLower(strings.TrimSpace(v)) }
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteIP := net.ParseIP(host)
	for _, network := range s.cfg.TrustedProxies {
		if remoteIP == nil || !network.Contains(remoteIP) {
			continue
		}
		forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if len(forwarded) > 0 {
			if client := net.ParseIP(strings.TrimSpace(forwarded[0])); client != nil {
				return client.String()
			}
		}
	}
	return host
}
func mustPrincipal(r *http.Request) principal { return r.Context().Value(principalKey).(principal) }

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		fail(w, r, 400, "invalid_json", "request body is not valid JSON")
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status != 204 {
		_ = json.NewEncoder(w).Encode(value)
	}
}
func fail(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	id, _ := r.Context().Value(contextKey("requestID")).(string)
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message, "request_id": id}})
}
