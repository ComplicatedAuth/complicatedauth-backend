package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	security "github.com/dokosoko/complicatedauth-backend/internal/auth"
)

type Config struct {
	DatabaseURL            string
	ListenAddress          string
	ConsoleOrigin          string
	OAuthIssuer            string
	CookieSecure           bool
	SecretHashKey          []byte
	DataEncryptionKeys     *security.EncryptionKeyring
	MigrationsDir          string
	MemberAbsoluteTTL      time.Duration
	MemberIdleTTL          time.Duration
	UserAbsoluteTTL        time.Duration
	UserIdleTTL            time.Duration
	OAuthAuthorizationTTL  time.Duration
	OAuthCodeTTL           time.Duration
	OAuthAccessTokenTTL    time.Duration
	OAuthSigningKeyMaxAge  time.Duration
	BackgroundJobWorkers   int
	BackgroundJobPoll      time.Duration
	BackgroundJobLease     time.Duration
	EmailSMTPAddress       string
	EmailFrom              string
	EmailSMTPUsername      string
	EmailSMTPPassword      string
	EmailSMTPStartTLS      bool
	EmailDeliveryTimeout   time.Duration
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
	encryptionKeys, err := security.ParseEncryptionKeyring(os.Getenv("DATA_ENCRYPTION_KEYS"))
	if err != nil {
		return Config{}, err
	}
	backgroundJobWorkers, err := positiveEnvInt("BACKGROUND_JOB_WORKERS", 2, 32)
	if err != nil {
		return Config{}, err
	}
	backgroundJobPoll, err := positiveEnvDuration("BACKGROUND_JOB_POLL_INTERVAL", time.Second)
	if err != nil {
		return Config{}, err
	}
	backgroundJobLease, err := positiveEnvDuration("BACKGROUND_JOB_LEASE_DURATION", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	if backgroundJobLease < 5*time.Second {
		return Config{}, errors.New("BACKGROUND_JOB_LEASE_DURATION must be at least 5s")
	}
	emailSMTPStartTLS, err := strconv.ParseBool(env("EMAIL_SMTP_STARTTLS", "true"))
	if err != nil {
		return Config{}, errors.New("EMAIL_SMTP_STARTTLS must be true or false")
	}
	emailDeliveryTimeout, err := positiveEnvDuration("EMAIL_DELIVERY_TIMEOUT", 15*time.Second)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		DatabaseURL: os.Getenv("DATABASE_URL"), ListenAddress: env("LISTEN_ADDRESS", ":8080"),
		ConsoleOrigin: os.Getenv("CONSOLE_ORIGIN"), OAuthIssuer: strings.TrimRight(os.Getenv("OAUTH_ISSUER"), "/"), CookieSecure: secure, SecretHashKey: key, DataEncryptionKeys: encryptionKeys,
		MigrationsDir: env("MIGRATIONS_DIR", "migrations"), MemberAbsoluteTTL: 7 * 24 * time.Hour,
		MemberIdleTTL: 24 * time.Hour, UserAbsoluteTTL: 30 * 24 * time.Hour, UserIdleTTL: 7 * 24 * time.Hour,
		OAuthAuthorizationTTL: 10 * time.Minute, OAuthCodeTTL: 5 * time.Minute,
		OAuthAccessTokenTTL: 10 * time.Minute, OAuthSigningKeyMaxAge: 30 * 24 * time.Hour,
		BackgroundJobWorkers: backgroundJobWorkers, BackgroundJobPoll: backgroundJobPoll, BackgroundJobLease: backgroundJobLease,
		EmailSMTPAddress: os.Getenv("EMAIL_SMTP_ADDRESS"), EmailFrom: os.Getenv("EMAIL_FROM"), EmailSMTPUsername: os.Getenv("EMAIL_SMTP_USERNAME"), EmailSMTPPassword: os.Getenv("EMAIL_SMTP_PASSWORD"), EmailSMTPStartTLS: emailSMTPStartTLS, EmailDeliveryTimeout: emailDeliveryTimeout,
		TrustedProxies:         trustedProxies,
		BiometricProviderURL:   strings.TrimRight(os.Getenv("BIOMETRIC_PROVIDER_URL"), "/"),
		BiometricProviderToken: os.Getenv("BIOMETRIC_PROVIDER_TOKEN"),
	}
	if cfg.DatabaseURL == "" || cfg.ConsoleOrigin == "" || cfg.OAuthIssuer == "" {
		return Config{}, errors.New("DATABASE_URL, CONSOLE_ORIGIN, and OAUTH_ISSUER are required")
	}
	if (cfg.EmailSMTPAddress == "") != (cfg.EmailFrom == "") {
		return Config{}, errors.New("EMAIL_SMTP_ADDRESS and EMAIL_FROM must be configured together")
	}
	if cfg.EmailSMTPUsername != "" && (!cfg.EmailSMTPStartTLS || cfg.EmailSMTPPassword == "") {
		return Config{}, errors.New("SMTP authentication requires EMAIL_SMTP_PASSWORD and EMAIL_SMTP_STARTTLS=true")
	}
	if err = validatePublicOrigin("CONSOLE_ORIGIN", cfg.ConsoleOrigin); err != nil {
		return Config{}, err
	}
	if err = validatePublicOrigin("OAUTH_ISSUER", cfg.OAuthIssuer); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func positiveEnvInt(name string, fallback, maximum int) (int, error) {
	raw := env(name, strconv.Itoa(fallback))
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > maximum {
		return 0, fmt.Errorf("%s must be an integer between 1 and %d", name, maximum)
	}
	return value, nil
}

func positiveEnvDuration(name string, fallback time.Duration) (time.Duration, error) {
	raw := env(name, fallback.String())
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return value, nil
}

func validatePublicOrigin(name, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return fmt.Errorf("%s must be an HTTP(S) origin without a path, credentials, query, or fragment", name)
	}
	hostname := parsed.Hostname()
	developmentHTTP := parsed.Scheme == "http" && isLocalDevelopmentHostname(hostname)
	if parsed.Scheme != "https" && !developmentHTTP {
		return fmt.Errorf("%s must use HTTPS except for loopback development origins", name)
	}
	return nil
}

func isLocalDevelopmentHostname(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
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
