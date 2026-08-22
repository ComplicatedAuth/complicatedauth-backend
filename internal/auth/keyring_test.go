package auth

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func encodedKey(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func TestEncryptionKeyringRotationAndAuthenticatedContext(t *testing.T) {
	oldRing, err := ParseEncryptionKeyring("v1:" + encodedKey(1))
	if err != nil {
		t.Fatal(err)
	}
	oldValue, err := oldRing.Seal([]byte("private material"), []byte("oauth-signing-key:key-1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldValue.Ciphertext, []byte("private material")) {
		t.Fatal("ciphertext contains plaintext")
	}

	rotated, err := ParseEncryptionKeyring("v2:" + encodedKey(2) + ",v1:" + encodedKey(1))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := rotated.Open(oldValue, []byte("oauth-signing-key:key-1"))
	if err != nil || string(opened) != "private material" {
		t.Fatalf("open old value after rotation: %q, %v", opened, err)
	}
	if _, err = rotated.Open(oldValue, []byte("oauth-signing-key:key-2")); err == nil {
		t.Fatal("expected authenticated-context mismatch to fail")
	}
	newValue, err := rotated.Seal([]byte("next"), []byte("context"))
	if err != nil {
		t.Fatal(err)
	}
	if newValue.KeyVersion != "v2" {
		t.Fatalf("new value used %q, want v2", newValue.KeyVersion)
	}
}

func TestParseEncryptionKeyringRejectsUnsafeConfiguration(t *testing.T) {
	for _, raw := range []string{
		"",
		"no-separator",
		"bad version:" + encodedKey(1),
		"v1:not-base64",
		"v1:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)),
		"v1:" + encodedKey(1) + ",v1:" + encodedKey(2),
	} {
		t.Run(strings.ReplaceAll(raw, "/", "_"), func(t *testing.T) {
			if _, err := ParseEncryptionKeyring(raw); err == nil {
				t.Fatalf("expected %q to fail", raw)
			}
		})
	}
}
