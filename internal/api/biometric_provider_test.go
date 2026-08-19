package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestHTTPBiometricProviderLifecycle(t *testing.T) {
	var deleted bool
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer provider-secret" {
			t.Fatal("provider request omitted bearer token")
		}
		status := http.StatusOK
		body := "{}"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/enrollments":
			if err := r.ParseMultipartForm(1 << 20); err != nil || r.FormValue("subject") != "project:user" {
				t.Fatalf("invalid enrollment request: %v", err)
			}
			raw, _ := json.Marshal(map[string]string{"template_id": "template-1"})
			body = string(raw)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/verifications":
			if err := r.ParseMultipartForm(1 << 20); err != nil || r.FormValue("template_id") != "template-1" {
				t.Fatalf("invalid verification request: %v", err)
			}
			raw, _ := json.Marshal(map[string]bool{"matched": true})
			body = string(raw)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/enrollments/template-1":
			deleted = true
			status = http.StatusNoContent
			body = ""
		default:
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})

	provider := &httpBiometricProvider{baseURL: "https://provider.test", token: "provider-secret", client: &http.Client{Transport: transport}}
	image := selfie{Data: []byte("image"), ContentType: "image/jpeg"}
	templateID, err := provider.Enroll(context.Background(), "project:user", image)
	if err != nil || templateID != "template-1" {
		t.Fatalf("Enroll() = %q, %v", templateID, err)
	}
	matched, err := provider.Verify(context.Background(), templateID, image)
	if err != nil || !matched {
		t.Fatalf("Verify() = %v, %v", matched, err)
	}
	if err = provider.Delete(context.Background(), templateID); err != nil || !deleted {
		t.Fatalf("Delete() = %v, deleted=%v", err, deleted)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func TestUnavailableBiometricProvider(t *testing.T) {
	provider := unavailableBiometricProvider{}
	_, err := provider.Enroll(context.Background(), "subject", selfie{})
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("Enroll() error = %v", err)
	}
}
