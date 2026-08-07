package api

import (
	"net/http/httptest"
	"testing"
)

func TestValidateOrigin(t *testing.T) {
	tests := []struct {
		name, origin, rpID string
		valid              bool
	}{
		{"localhost development", "http://localhost:3000", "localhost", true},
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

func TestValidRPID(t *testing.T) {
	for value, expected := range map[string]bool{"localhost": true, "example.com": true, "app.example.com": true, "https://example.com": false, "127.0.0.1": false, "example": false} {
		if got := validRPID(value); got != expected {
			t.Errorf("validRPID(%q)=%v want %v", value, got, expected)
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
