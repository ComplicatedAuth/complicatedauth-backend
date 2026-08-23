package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateOrigin(t *testing.T) {
	tests := []struct {
		name, origin, rpID string
		valid              bool
	}{
		{"localhost development", "http://localhost:3000", "localhost", true},
		{"localhost subdomain development", "http://customer.localhost:3000", "customer.localhost", true},
		{"https exact", "https://example.com", "example.com", true},
		{"https subdomain", "https://app.example.com", "example.com", true},
		{"insecure remote", "http://example.com", "example.com", false},
		{"unrelated host", "https://attacker.test", "example.com", false},
		{"path rejected", "https://example.com/login", "example.com", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateOrigin(test.origin, test.rpID)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
		})
	}
}

func TestValidatePublicOrigin(t *testing.T) {
	tests := map[string]bool{
		"https://api.example.com":          true,
		"http://localhost:3000":            true,
		"http://console.localhost:3000":    true,
		"http://127.0.0.1:3000":            true,
		"http://192.0.2.10:3000":           false,
		"http://management.example.com":    false,
		"https://api.example.com/unwanted": false,
	}
	for origin, expected := range tests {
		if got := validatePublicOrigin("TEST_ORIGIN", origin) == nil; got != expected {
			t.Errorf("validatePublicOrigin(%q)=%v want %v", origin, got, expected)
		}
	}
}

func TestValidRPID(t *testing.T) {
	for value, expected := range map[string]bool{"localhost": true, "example.com": true, "app.example.com": true, "https://example.com": false, "127.0.0.1": false, "example": false} {
		if got := validRPID(value); got != expected {
			t.Errorf("validRPID(%q)=%v want %v", value, got, expected)
		}
	}
}

func TestLocalhostSubdomainsAreAcceptedByOAuthContracts(t *testing.T) {
	if got, err := normalizeResourceIdentifier("http://api.complicatedauth.localhost:38080"); err != nil || got != "http://api.complicatedauth.localhost:38080" {
		t.Fatalf("resource identifier=%q err=%v", got, err)
	}
	redirects, err := normalizeRedirectURIs([]string{"http://localhost:8080/oauth/callback"})
	if err != nil || len(redirects) != 1 || redirects[0] != "http://localhost:8080/oauth/callback" {
		t.Fatalf("redirects=%v err=%v", redirects, err)
	}
	for _, raw := range []string{"http://complicatedauth.localhost.example:38080", "http://localhost.example:38080"} {
		if _, err := normalizeResourceIdentifier(raw); err == nil {
			t.Fatalf("lookalike resource identifier %q was accepted", raw)
		}
		if _, err := normalizeRedirectURIs([]string{raw + "/oauth/callback"}); err == nil {
			t.Fatalf("lookalike redirect URI %q was accepted", raw)
		}
	}
}

func TestTrustedProxyParsingAndClientIP(t *testing.T) {
	proxies, err := parseTrustedProxies("10.0.0.0/8, 192.0.2.4")
	if err != nil || len(proxies) != 2 {
		t.Fatalf("parseTrustedProxies() len=%d err=%v", len(proxies), err)
	}
	server := &Server{cfg: Config{TrustedProxies: proxies}}
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "10.1.2.3:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.9, 10.1.2.3")
	if got := server.clientIP(request); got != "203.0.113.9" {
		t.Fatalf("trusted client IP=%q", got)
	}
	request.RemoteAddr = "198.51.100.8:1234"
	if got := server.clientIP(request); got != "198.51.100.8" {
		t.Fatalf("untrusted client IP=%q", got)
	}
	if _, err = parseTrustedProxies("not-an-address"); err == nil {
		t.Fatal("invalid trusted proxy value was accepted")
	}
}

func TestLegacySingleFactorRoutesAreNotRegistered(t *testing.T) {
	handler := New(Config{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
	paths := []string{
		"/v1/console/auth/login",
		"/v1/projects/00000000-0000-0000-0000-000000000000/runtime/password/authenticate",
		"/v1/projects/00000000-0000-0000-0000-000000000000/runtime/passkeys/authentication/options",
		"/v1/projects/00000000-0000-0000-0000-000000000000/runtime/passkeys/authentication/verify",
		"/v1/projects/00000000-0000-0000-0000-000000000000/runtime/passkeys/registration/options",
		"/v1/projects/00000000-0000-0000-0000-000000000000/runtime/passkeys/registration/verify",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
			if response.Code != http.StatusNotFound {
				t.Fatalf("status=%d want %d", response.Code, http.StatusNotFound)
			}
		})
	}
}
