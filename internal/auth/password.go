package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      = 19 * 1024
	argonIterations  = 2
	argonParallelism = 1
	argonSaltLength  = 16
	argonKeyLength   = 32
)

var ErrInvalidPassword = errors.New("invalid password")

func ValidatePassword(password string) error {
	n := len([]rune(password))
	if n < 12 || n > 128 {
		return errors.New("password must contain between 12 and 128 characters")
	}
	return nil
}

func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func VerifyPassword(encoded, password string) (bool, bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, false
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return false, false
	}
	memory64, err1 := strconv.ParseUint(strings.TrimPrefix(params[0], "m="), 10, 32)
	iterations64, err2 := strconv.ParseUint(strings.TrimPrefix(params[1], "t="), 10, 32)
	parallel64, err3 := strconv.ParseUint(strings.TrimPrefix(params[2], "p="), 10, 8)
	salt, err4 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err5 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || len(want) == 0 {
		return false, false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(iterations64), uint32(memory64), uint8(parallel64), uint32(len(want)))
	valid := subtle.ConstantTimeCompare(got, want) == 1
	rehash := uint32(memory64) != argonMemory || uint32(iterations64) != argonIterations || uint8(parallel64) != argonParallelism
	return valid, valid && rehash
}
