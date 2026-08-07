package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func RandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func SessionHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func SecretHash(key []byte, token string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(token))
	return mac.Sum(nil)
}
