package api

import (
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestTenantMemberCredentialAAGUID(t *testing.T) {
	want := "adce0002-35bc-c60a-648b-0b25f1f05503"
	credential := &webauthn.Credential{Authenticator: webauthn.Authenticator{AAGUID: []byte{
		0xad, 0xce, 0x00, 0x02, 0x35, 0xbc, 0xc6, 0x0a,
		0x64, 0x8b, 0x0b, 0x25, 0xf1, 0xf0, 0x55, 0x03,
	}}}
	if got := tenantMemberCredentialAAGUID(credential); got != want {
		t.Fatalf("tenantMemberCredentialAAGUID()=%q want=%q", got, want)
	}
}

func TestTenantMemberCredentialAAGUIDFallsBackToZero(t *testing.T) {
	const zero = "00000000-0000-0000-0000-000000000000"
	for _, credential := range []*webauthn.Credential{
		nil,
		{},
		{Authenticator: webauthn.Authenticator{AAGUID: []byte{0x01}}},
	} {
		if got := tenantMemberCredentialAAGUID(credential); got != zero {
			t.Fatalf("tenantMemberCredentialAAGUID()=%q want=%q", got, zero)
		}
	}
}

func TestTenantMemberEnrollmentModeOnlyAllowsPasskeys(t *testing.T) {
	if !tenantMemberEnrollmentMode("passkey") {
		t.Fatal("passkey enrollment should be allowed")
	}
	for _, mode := range []string{"", "security_key", "hybrid"} {
		if tenantMemberEnrollmentMode(mode) {
			t.Fatalf("mode %q should not be allowed for Tenant Member enrollment", mode)
		}
	}
}
