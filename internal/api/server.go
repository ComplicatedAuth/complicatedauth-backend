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
	"strings"
	"sync"
	"time"

	security "github.com/dokosoko/complicatedauth-backend/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type contextKey string

const principalKey contextKey = "consolePrincipal"

type principal struct{ TenantUID, MemberUID, SessionUID string }
type attempt struct {
	Count int
	Reset time.Time
}

type Server struct {
	cfg           Config
	db            *pgxpool.Pool
	log           *slog.Logger
	loginMu       sync.Mutex
	loginAttempts map[string]attempt
	biometrics    biometricProvider
}

func New(cfg Config, db *pgxpool.Pool, logger *slog.Logger) *Server {
	return newServer(cfg, db, logger, configuredBiometricProvider(cfg))
}

func newServer(cfg Config, db *pgxpool.Pool, logger *slog.Logger, biometrics biometricProvider) *Server {
	return &Server{cfg: cfg, db: db, log: logger, loginAttempts: make(map[string]attempt), biometrics: biometrics}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /health/ready", s.ready)
	mux.Handle("POST /v1/console/auth/signup", s.csrf(http.HandlerFunc(s.signup)))
	mux.Handle("POST /v1/console/auth/login", s.csrf(http.HandlerFunc(s.login)))
	mux.Handle("POST /v1/console/auth/logout", s.console(http.HandlerFunc(s.logout)))
	mux.Handle("GET /v1/console/auth/session", s.console(http.HandlerFunc(s.session)))

	mux.Handle("GET /v1/projects", s.console(http.HandlerFunc(s.listProjects)))
	mux.Handle("POST /v1/projects", s.console(http.HandlerFunc(s.createProject)))
	mux.Handle("GET /v1/projects/{project_uid}", s.console(http.HandlerFunc(s.getProjectHandler)))
	mux.Handle("PATCH /v1/projects/{project_uid}", s.console(http.HandlerFunc(s.updateProject)))
	mux.Handle("GET /v1/projects/{project_uid}/origins", s.console(http.HandlerFunc(s.listOrigins)))
	mux.Handle("POST /v1/projects/{project_uid}/origins", s.console(http.HandlerFunc(s.createOrigin)))
	mux.Handle("DELETE /v1/projects/{project_uid}/origins/{origin_uid}", s.console(http.HandlerFunc(s.deleteOrigin)))
	mux.Handle("GET /v1/projects/{project_uid}/api-keys", s.console(http.HandlerFunc(s.listAPIKeys)))
	mux.Handle("POST /v1/projects/{project_uid}/api-keys", s.console(http.HandlerFunc(s.createAPIKey)))
	mux.Handle("PATCH /v1/projects/{project_uid}/api-keys/{key_uid}", s.console(http.HandlerFunc(s.renameAPIKey)))
	mux.Handle("POST /v1/projects/{project_uid}/api-keys/{key_uid}/rotate", s.console(http.HandlerFunc(s.rotateAPIKey)))
	mux.Handle("DELETE /v1/projects/{project_uid}/api-keys/{key_uid}", s.console(http.HandlerFunc(s.revokeAPIKey)))
	mux.Handle("GET /v1/projects/{project_uid}/users", s.consoleOrAPIKey(http.HandlerFunc(s.listProjectUsers)))
	mux.Handle("POST /v1/projects/{project_uid}/users", s.consoleOrAPIKey(http.HandlerFunc(s.createProjectUser)))
	mux.Handle("GET /v1/projects/{project_uid}/users/{user_uid}", s.consoleOrAPIKey(http.HandlerFunc(s.getProjectUserHandler)))
	mux.Handle("PATCH /v1/projects/{project_uid}/users/{user_uid}", s.consoleOrAPIKey(http.HandlerFunc(s.updateProjectUser)))
	mux.Handle("PUT /v1/projects/{project_uid}/users/{user_uid}/password", s.consoleOrAPIKey(http.HandlerFunc(s.replaceProjectUserPassword)))
	mux.Handle("POST /v1/projects/{project_uid}/users/{user_uid}/sessions/revoke", s.consoleOrAPIKey(http.HandlerFunc(s.revokeProjectUserSessions)))
	mux.Handle("DELETE /v1/projects/{project_uid}/users/{user_uid}/passkeys/{credential_uid}", s.consoleOrAPIKey(http.HandlerFunc(s.deletePasskey)))
	mux.Handle("GET /v1/projects/{project_uid}/activity", s.console(http.HandlerFunc(s.listActivity)))
	mux.Handle("GET /v1/activity", s.console(http.HandlerFunc(s.listActivity)))

	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/start", s.apiKey(http.HandlerFunc(s.startProjectUserLogin)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/password", s.apiKey(http.HandlerFunc(s.verifyProjectUserLoginPassword)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/fido/options", s.apiKey(http.HandlerFunc(s.beginFidoLogin)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/fido/verify", s.apiKey(http.HandlerFunc(s.finishFidoLogin)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/fido/enrollment/options", s.apiKey(http.HandlerFunc(s.beginFirstFidoEnrollment)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/fido/enrollment/verify", s.apiKey(http.HandlerFunc(s.finishFirstFidoEnrollment)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/login/biometric", s.apiKey(http.HandlerFunc(s.verifyBiometricLogin)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/fido/registration/options", s.apiKey(http.HandlerFunc(s.beginFidoEnrollment)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/fido/registration/verify", s.apiKey(http.HandlerFunc(s.finishFidoEnrollment)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/biometric/enrollment", s.apiKey(http.HandlerFunc(s.enrollBiometric)))
	mux.Handle("DELETE /v1/projects/{project_uid}/runtime/biometric/enrollment", s.apiKey(http.HandlerFunc(s.deleteBiometricEnrollment)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/sessions/introspect", s.apiKey(http.HandlerFunc(s.runtimeIntrospect)))
	mux.Handle("POST /v1/projects/{project_uid}/runtime/sessions/revoke", s.apiKey(http.HandlerFunc(s.runtimeRevoke)))
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

func (s *Server) console(next http.Handler) http.Handler {
	return s.csrf(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("complicatedauth_session")
		if err != nil {
			fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		var p principal
		var expires, idle time.Time
		err = s.db.QueryRow(r.Context(), `SELECT s.uid, s.tenant_uid, s.tenant_member_uid, s.expires_at, s.idle_expires_at
			FROM tenant_member_sessions s JOIN tenant_members m ON m.uid=s.tenant_member_uid
			WHERE s.session_secret_hash=$1 AND s.revoked_at IS NULL AND m.status='active'`, security.SessionHash(cookie.Value)).Scan(&p.SessionUID, &p.TenantUID, &p.MemberUID, &expires, &idle)
		if err != nil || time.Now().After(expires) || time.Now().After(idle) {
			fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		_, _ = s.db.Exec(r.Context(), `UPDATE tenant_member_sessions SET last_seen_at=now(), idle_expires_at=LEAST(expires_at, now()+$2::interval) WHERE uid=$1`, p.SessionUID, "24 hours")
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	}))
}

func (s *Server) apiKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		idx := strings.LastIndex(value, ".")
		if idx < 1 {
			fail(w, r, http.StatusUnauthorized, "invalid_api_key", "valid project API key required")
			return
		}
		prefix := value[:idx]
		var keyUID, projectUID string
		var stored []byte
		err := s.db.QueryRow(r.Context(), `SELECT uid, project_uid, secret_hash FROM project_api_keys WHERE prefix=$1 AND status='active'`, prefix).Scan(&keyUID, &projectUID, &stored)
		got := security.SecretHash(s.cfg.SecretHashKey, value)
		if err != nil || subtle.ConstantTimeCompare(stored, got) != 1 || projectUID != r.PathValue("project_uid") {
			fail(w, r, http.StatusUnauthorized, "invalid_api_key", "valid project API key required")
			return
		}
		_, _ = s.db.Exec(r.Context(), `UPDATE project_api_keys SET last_used_at=now() WHERE uid=$1`, keyUID)
		ctx := context.WithValue(r.Context(), contextKey("apiKeyUID"), keyUID)
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, contextKey("apiProjectUID"), projectUID)))
	})
}

func (s *Server) consoleOrAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			s.apiKey(next).ServeHTTP(w, r)
			return
		}
		s.console(next).ServeHTTP(w, r)
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
	writeJSON(w, 201, ConsoleSession{Tenant: Tenant{tenantUID, in.TenantName, slug}, Member: TenantMember{memberUID, in.Email, in.DisplayName, "owner"}, ExpiresAt: expires})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password string }
	if !decode(w, r, &in) {
		return
	}
	email := normalizeEmail(in.Email)
	key := s.clientIP(r) + ":" + email
	if s.loginLimited(key) {
		fail(w, r, 429, "rate_limited", "too many login attempts; try again later")
		return
	}
	var tenant Tenant
	var member TenantMember
	var hash, status string
	err := s.db.QueryRow(r.Context(), `SELECT t.uid,t.name,t.slug,m.uid,m.email,m.display_name,m.role,m.password_hash,m.status FROM tenant_members m JOIN tenants t ON t.uid=m.tenant_uid WHERE m.email_normalized=$1`, email).Scan(&tenant.UID, &tenant.Name, &tenant.Slug, &member.UID, &member.Email, &member.DisplayName, &member.Role, &hash, &status)
	valid, rehash := security.VerifyPassword(hash, in.Password)
	if err != nil || !valid || status != "active" {
		s.recordLoginFailure(key)
		fail(w, r, 401, "invalid_credentials", "email or password is incorrect")
		return
	}
	s.clearLoginFailures(key)
	if rehash {
		if next, e := security.HashPassword(in.Password); e == nil {
			_, _ = s.db.Exec(r.Context(), `UPDATE tenant_members SET password_hash=$2,updated_at=now() WHERE uid=$1`, member.UID, next)
		}
	}
	token, _ := security.RandomToken()
	expires, idle := time.Now().Add(s.cfg.MemberAbsoluteTTL), time.Now().Add(s.cfg.MemberIdleTTL)
	_, err = s.db.Exec(r.Context(), `INSERT INTO tenant_member_sessions(uid,tenant_member_uid,tenant_uid,session_secret_hash,expires_at,idle_expires_at) VALUES($1,$2,$3,$4,$5,$6)`, uuid.NewString(), member.UID, tenant.UID, security.SessionHash(token), expires, idle)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not create session")
		return
	}
	s.setMemberCookie(w, token, expires)
	s.audit(r.Context(), tenant.UID, "", "tenant_member", member.UID, "tenant_member.login", "tenant_member", member.UID, nil, r)
	writeJSON(w, 200, ConsoleSession{Tenant: tenant, Member: member, ExpiresAt: expires})
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
	err := s.db.QueryRow(r.Context(), `SELECT t.uid,t.name,t.slug,m.uid,m.email,m.display_name,m.role,s.expires_at FROM tenant_member_sessions s JOIN tenant_members m ON m.uid=s.tenant_member_uid JOIN tenants t ON t.uid=s.tenant_uid WHERE s.uid=$1`, p.SessionUID).Scan(&result.Tenant.UID, &result.Tenant.Name, &result.Tenant.Slug, &result.Member.UID, &result.Member.Email, &result.Member.DisplayName, &result.Member.Role, &result.ExpiresAt)
	if err != nil {
		fail(w, r, 401, "unauthenticated", "authentication required")
		return
	}
	writeJSON(w, 200, result)
}

func (s *Server) setMemberCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: "complicatedauth_session", Value: token, Path: "/", HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, Expires: expires})
}

func (s *Server) loginLimited(key string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	a, ok := s.loginAttempts[key]
	return ok && a.Count >= 5 && time.Now().Before(a.Reset)
}
func (s *Server) recordLoginFailure(key string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	a := s.loginAttempts[key]
	if time.Now().After(a.Reset) {
		a = attempt{Reset: time.Now().Add(15 * time.Minute)}
	}
	a.Count++
	s.loginAttempts[key] = a
}
func (s *Server) clearLoginFailures(key string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	delete(s.loginAttempts, key)
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
