package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL            string
	ListenAddress          string
	ConsoleOrigin          string
	CookieSecure           bool
	SecretHashKey          []byte
	MigrationsDir          string
	MemberAbsoluteTTL      time.Duration
	MemberIdleTTL          time.Duration
	UserAbsoluteTTL        time.Duration
	UserIdleTTL            time.Duration
	TrustedProxies         []*net.IPNet
	BiometricProviderURL   string
	BiometricProviderToken string
}

func ConfigFromEnv() (Config, error) {
	secure, _ := strconv.ParseBool(env("COOKIE_SECURE", "true"))
	key, err := base64.RawURLEncoding.DecodeString(os.Getenv("SECRET_HASH_KEY"))
	if err != nil || len(key) < 32 {
		return Config{}, errors.New("SECRET_HASH_KEY must be base64url-encoded and at least 32 bytes")
	}
	trustedProxies, err := parseTrustedProxies(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		DatabaseURL: os.Getenv("DATABASE_URL"), ListenAddress: env("LISTEN_ADDRESS", ":8080"),
		ConsoleOrigin: os.Getenv("CONSOLE_ORIGIN"), CookieSecure: secure, SecretHashKey: key,
		MigrationsDir: env("MIGRATIONS_DIR", "migrations"), MemberAbsoluteTTL: 7 * 24 * time.Hour,
		MemberIdleTTL: 24 * time.Hour, UserAbsoluteTTL: 30 * 24 * time.Hour, UserIdleTTL: 7 * 24 * time.Hour,
		TrustedProxies:         trustedProxies,
		BiometricProviderURL:   strings.TrimRight(os.Getenv("BIOMETRIC_PROVIDER_URL"), "/"),
		BiometricProviderToken: os.Getenv("BIOMETRIC_PROVIDER_TOKEN"),
	}
	if cfg.DatabaseURL == "" || cfg.ConsoleOrigin == "" {
		return Config{}, errors.New("DATABASE_URL and CONSOLE_ORIGIN are required")
	}
	return cfg, nil
}

func parseTrustedProxies(raw string) ([]*net.IPNet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	result := make([]*net.IPNet, 0)
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if ip := net.ParseIP(value); ip != nil {
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			result = append(result, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, network, parseErr := net.ParseCIDR(value)
		if parseErr != nil {
			return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS contains invalid address %q", value)
		}
		result = append(result, network)
	}
	return result, nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
