package api

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	security "github.com/complicatedauth/complicatedauth-backend/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const oauthSigningKeyLockID int64 = 0x43415f4f41555448

type oauthSigningKey struct {
	KID        string
	PrivateKey *rsa.PrivateKey
}

type oauthJWK struct {
	KTY string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (s *Server) Initialize(ctx context.Context) error {
	if s.db == nil {
		return errors.New("database is required")
	}
	if s.cfg.DataEncryptionKeys == nil {
		return errors.New("data encryption keyring is required")
	}
	if s.cfg.OAuthIssuer == "" {
		return errors.New("OAuth issuer is required")
	}
	if err := s.ensureOAuthSigningKey(ctx, time.Now()); err != nil {
		return err
	}
	return s.ensureMaintenanceJob(ctx)
}

func (s *Server) ensureOAuthSigningKey(ctx context.Context, now time.Time) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin OAuth signing-key initialization: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, oauthSigningKeyLockID); err != nil {
		return fmt.Errorf("lock OAuth signing-key initialization: %w", err)
	}

	var activeUID string
	var createdAt time.Time
	err = tx.QueryRow(ctx, `SELECT uid,created_at FROM oauth_signing_keys WHERE status='active'`).Scan(&activeUID, &createdAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("load active OAuth signing key: %w", err)
	}
	maxAge := s.cfg.OAuthSigningKeyMaxAge
	if maxAge <= 0 {
		maxAge = 30 * 24 * time.Hour
	}
	if err == nil && createdAt.Add(maxAge).After(now) {
		return tx.Commit(ctx)
	}
	if err == nil {
		publicationWindow := s.cfg.OAuthAccessTokenTTL + 5*time.Minute
		if publicationWindow < 15*time.Minute {
			publicationWindow = 15 * time.Minute
		}
		if _, err = tx.Exec(ctx, `UPDATE oauth_signing_keys SET status='retiring',publish_until=$2 WHERE uid=$1 AND status='active'`, activeUID, now.Add(publicationWindow)); err != nil {
			return fmt.Errorf("retire OAuth signing key: %w", err)
		}
	}
	if err = s.insertOAuthSigningKey(ctx, tx, now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE oauth_signing_keys SET status='retired',retired_at=$1 WHERE status='retiring' AND publish_until<=$1`, now); err != nil {
		return fmt.Errorf("expire OAuth signing keys: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *Server) insertOAuthSigningKey(ctx context.Context, tx pgx.Tx, now time.Time) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate OAuth signing key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("encode OAuth signing key: %w", err)
	}
	uid, kid := uuid.NewString(), "ca_sig_"+uuid.NewString()
	encrypted, err := s.cfg.DataEncryptionKeys.Seal(privateDER, oauthSigningKeyContext(uid))
	if err != nil {
		return fmt.Errorf("encrypt OAuth signing key: %w", err)
	}
	publicJSON, err := json.Marshal(publicJWK(kid, &privateKey.PublicKey))
	if err != nil {
		return fmt.Errorf("encode OAuth public key: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO oauth_signing_keys(
			uid,kid,algorithm,status,public_jwk,private_key_ciphertext,
			private_key_nonce,encryption_key_version,created_at,activated_at
		) VALUES($1,$2,'RS256','active',$3,$4,$5,$6,$7,$7)
	`, uid, kid, publicJSON, encrypted.Ciphertext, encrypted.Nonce, encrypted.KeyVersion, now)
	if err != nil {
		return fmt.Errorf("persist OAuth signing key: %w", err)
	}
	return nil
}

func oauthSigningKeyContext(uid string) []byte {
	return []byte("oauth_signing_keys\x00" + uid)
}

func publicJWK(kid string, key *rsa.PublicKey) oauthJWK {
	exponent := make([]byte, 4)
	binary.BigEndian.PutUint32(exponent, uint32(key.E))
	exponent = exponent[firstNonZero(exponent):]
	return oauthJWK{
		KTY: "RSA",
		Use: "sig",
		Alg: "RS256",
		KID: kid,
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(exponent),
	}
}

func firstNonZero(value []byte) int {
	for i, item := range value {
		if item != 0 {
			return i
		}
	}
	return len(value) - 1
}

func (s *Server) activeOAuthSigningKey(ctx context.Context) (oauthSigningKey, error) {
	var uid, kid, version string
	var ciphertext, nonce []byte
	err := s.db.QueryRow(ctx, `
		SELECT uid,kid,encryption_key_version,private_key_ciphertext,private_key_nonce
		FROM oauth_signing_keys WHERE status='active'
	`).Scan(&uid, &kid, &version, &ciphertext, &nonce)
	if err != nil {
		return oauthSigningKey{}, fmt.Errorf("load OAuth signing key: %w", err)
	}
	plaintext, err := s.cfg.DataEncryptionKeys.Open(security.EncryptedValue{
		KeyVersion: version,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, oauthSigningKeyContext(uid))
	if err != nil {
		return oauthSigningKey{}, fmt.Errorf("decrypt OAuth signing key: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(plaintext)
	if err != nil {
		return oauthSigningKey{}, fmt.Errorf("parse OAuth signing key: %w", err)
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return oauthSigningKey{}, errors.New("OAuth signing key is not RSA")
	}
	return oauthSigningKey{KID: kid, PrivateKey: privateKey}, nil
}

func (s *Server) signOAuthJWT(ctx context.Context, claims any) (string, error) {
	key, err := s.activeOAuthSigningKey(ctx)
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
		Typ string `json:"typ"`
	}{Alg: "RS256", KID: key.KID, Typ: "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encodedHeader + "." + encodedPayload
	digest := crypto.SHA256.New()
	_, _ = digest.Write([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key.PrivateKey, crypto.SHA256, digest.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("sign OAuth token: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *Server) oidcDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.cfg.OAuthIssuer,
		"authorization_endpoint":                         s.cfg.OAuthIssuer + "/oauth/authorize",
		"token_endpoint":                                 s.cfg.OAuthIssuer + "/oauth/token",
		"userinfo_endpoint":                              s.cfg.OAuthIssuer + "/oauth/userinfo",
		"jwks_uri":                                       s.cfg.OAuthIssuer + "/oauth/jwks",
		"revocation_endpoint":                            s.cfg.OAuthIssuer + "/oauth/revoke",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code"},
		"subject_types_supported":                        []string{"pairwise"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"scopes_supported":                               []string{"openid", "profile", "email"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic"},
		"claims_supported":                               []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "name", "email", "email_verified", "tenant_uid"},
		"request_parameter_supported":                    false,
		"request_uri_parameter_supported":                false,
		"require_request_uri_registration":               false,
		"authorization_response_iss_parameter_supported": true,
	})
}

func (s *Server) oauthJWKS(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `
		SELECT public_jwk FROM oauth_signing_keys
		WHERE status='active' OR (status='retiring' AND publish_until>now())
		ORDER BY created_at DESC
	`)
	if err != nil {
		fail(w, r, http.StatusServiceUnavailable, "signing_keys_unavailable", "signing keys are temporarily unavailable")
		return
	}
	defer rows.Close()
	keys := make([]json.RawMessage, 0, 2)
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			fail(w, r, http.StatusServiceUnavailable, "signing_keys_unavailable", "signing keys are temporarily unavailable")
			return
		}
		keys = append(keys, json.RawMessage(raw))
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func decodeRSAJWK(jwk oauthJWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
		return nil, errors.New("invalid RSA exponent")
	}
	var padded [4]byte
	copy(padded[4-len(eBytes):], eBytes)
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(binary.BigEndian.Uint32(padded[:]))}, nil
}
