package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var keyVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

type EncryptedValue struct {
	KeyVersion string
	Nonce      []byte
	Ciphertext []byte
}

type EncryptionKeyring struct {
	activeVersion string
	keys          map[string][]byte
}

// ParseEncryptionKeyring parses newest-first key entries in the form
// "version:base64url-key,older-version:base64url-key". The first key encrypts
// new values; every retained key may decrypt values written by that version.
func ParseEncryptionKeyring(raw string) (*EncryptionKeyring, error) {
	entries := strings.Split(strings.TrimSpace(raw), ",")
	if len(entries) == 1 && strings.TrimSpace(entries[0]) == "" {
		return nil, errors.New("DATA_ENCRYPTION_KEYS is required")
	}
	keys := make(map[string][]byte, len(entries))
	active := ""
	for _, entry := range entries {
		version, encoded, ok := strings.Cut(strings.TrimSpace(entry), ":")
		if !ok || !keyVersionPattern.MatchString(version) || encoded == "" {
			return nil, fmt.Errorf("invalid DATA_ENCRYPTION_KEYS entry %q", entry)
		}
		if _, exists := keys[version]; exists {
			return nil, fmt.Errorf("duplicate encryption key version %q", version)
		}
		key, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("encryption key %q must be exactly 32 base64url-encoded bytes", version)
		}
		if active == "" {
			active = version
		}
		keys[version] = append([]byte(nil), key...)
	}
	return &EncryptionKeyring{activeVersion: active, keys: keys}, nil
}

func (k *EncryptionKeyring) ActiveVersion() string {
	if k == nil {
		return ""
	}
	return k.activeVersion
}

func (k *EncryptionKeyring) Seal(plaintext, authenticatedContext []byte) (EncryptedValue, error) {
	if k == nil || k.activeVersion == "" {
		return EncryptedValue{}, errors.New("encryption keyring is not configured")
	}
	aead, err := newAEAD(k.keys[k.activeVersion])
	if err != nil {
		return EncryptedValue{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedValue{}, fmt.Errorf("generate encryption nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, authenticatedContext)
	return EncryptedValue{
		KeyVersion: k.activeVersion,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

func (k *EncryptionKeyring) Open(value EncryptedValue, authenticatedContext []byte) ([]byte, error) {
	if k == nil {
		return nil, errors.New("encryption keyring is not configured")
	}
	key, ok := k.keys[value.KeyVersion]
	if !ok {
		return nil, fmt.Errorf("encryption key version %q is unavailable", value.KeyVersion)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(value.Nonce) != aead.NonceSize() {
		return nil, errors.New("encrypted value has invalid nonce length")
	}
	plaintext, err := aead.Open(nil, value.Nonce, value.Ciphertext, authenticatedContext)
	if err != nil {
		return nil, errors.New("encrypted value authentication failed")
	}
	return plaintext, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
