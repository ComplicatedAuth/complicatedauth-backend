package auth

import "testing"

func TestPasswordRoundTrip(t *testing.T) {
	encoded, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	valid, rehash := VerifyPassword(encoded, "correct horse battery staple")
	if !valid || rehash {
		t.Fatalf("valid=%v rehash=%v", valid, rehash)
	}
	if valid, _ := VerifyPassword(encoded, "incorrect password"); valid {
		t.Fatal("incorrect password verified")
	}
}

func TestPasswordLength(t *testing.T) {
	if err := ValidatePassword("too short"); err == nil {
		t.Fatal("expected short password error")
	}
}
