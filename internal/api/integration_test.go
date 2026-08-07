package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dokosoko/complicatedauth-backend/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresAcceptanceFlow(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	if !strings.Contains(databaseURL, "/complicatedauth_test") {
		t.Fatal("integration tests require a dedicated complicatedauth_test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	reset := func() {
		if _, resetErr := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); resetErr != nil {
			t.Fatal(resetErr)
		}
	}
	reset()
	defer reset()
	if err = store.Migrate(ctx, pool, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	cfg := Config{DatabaseURL: databaseURL, ConsoleOrigin: "http://console.test", SecretHashKey: bytes.Repeat([]byte{7}, 32), MemberAbsoluteTTL: 7 * 24 * time.Hour, MemberIdleTTL: 24 * time.Hour, UserAbsoluteTTL: 30 * 24 * time.Hour, UserIdleTTL: 7 * 24 * time.Hour}
	ts := httptest.NewServer(New(cfg, pool, testLogger()).Handler())
	defer ts.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	var session ConsoleSession
	requestJSON(t, client, "POST", ts.URL+"/v1/console/auth/signup", map[string]any{"email": "owner@example.com", "password": "correct horse battery staple", "display_name": "Alice Owner", "tenant_name": "Acme Corporation"}, "http://console.test", "", http.StatusCreated, &session)
	if session.Member.Role != "owner" {
		t.Fatalf("role=%q", session.Member.Role)
	}

	var project Project
	requestJSON(t, client, "POST", ts.URL+"/v1/projects", map[string]any{"name": "Acme Web App", "environment": "sandbox", "rp_id": "localhost", "rp_name": "Acme", "initial_origin": "http://localhost:3000"}, "http://console.test", "", http.StatusCreated, &project)
	if project.OriginCount != 1 || project.RPID != "localhost" {
		t.Fatalf("unexpected project: %+v", project)
	}

	var key APIKey
	requestJSON(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/api-keys", map[string]any{"name": "Test backend"}, "http://console.test", "", http.StatusCreated, &key)
	if key.Secret == "" {
		t.Fatal("create key did not return its one-time secret")
	}
	var keys struct {
		Items []APIKey `json:"items"`
	}
	requestJSON(t, client, "GET", ts.URL+"/v1/projects/"+project.UID+"/api-keys", nil, "", "", http.StatusOK, &keys)
	if len(keys.Items) != 1 || keys.Items[0].Secret != "" {
		t.Fatal("key list exposed or omitted key metadata")
	}

	var user ProjectUser
	requestJSON(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/users", map[string]any{"email": "user@example.com", "password": "another correct battery staple", "email_verified": true}, "http://console.test", "", http.StatusCreated, &user)
	requestJSON(t, client, "GET", ts.URL+"/v1/projects/"+project.UID+"/users/"+user.UID, nil, "", key.Secret, http.StatusOK, &ProjectUser{})
	requestJSON(t, client, "PATCH", ts.URL+"/v1/projects/"+project.UID+"/users/"+user.UID, map[string]any{"email_verified": false}, "", key.Secret, http.StatusOK, &ProjectUser{})
	var runtimeSession struct {
		SessionReference string      `json:"session_reference"`
		ProjectUser      ProjectUser `json:"project_user"`
	}
	requestJSON(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/runtime/password/authenticate", map[string]any{"email": "user@example.com", "password": "another correct battery staple"}, "", key.Secret, http.StatusOK, &runtimeSession)
	if runtimeSession.SessionReference == "" || runtimeSession.ProjectUser.UID != user.UID {
		t.Fatal("runtime session was not issued for the expected user")
	}
	var introspection struct {
		Active      bool        `json:"active"`
		ProjectUser ProjectUser `json:"project_user"`
	}
	requestJSON(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/runtime/sessions/introspect", map[string]any{"session_reference": runtimeSession.SessionReference}, "", key.Secret, http.StatusOK, &introspection)
	if !introspection.Active || introspection.ProjectUser.UID != user.UID {
		t.Fatal("session introspection failed")
	}

	var options struct {
		CeremonyUID string         `json:"ceremony_uid"`
		PublicKey   map[string]any `json:"public_key"`
	}
	requestWithSession(t, client, ts.URL+"/v1/projects/"+project.UID+"/runtime/passkeys/registration/options", key.Secret, runtimeSession.SessionReference, http.StatusOK, &options)
	if options.CeremonyUID == "" || options.PublicKey["challenge"] == nil {
		t.Fatal("WebAuthn registration options were not generated")
	}
	requestJSON(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/users/"+user.UID+"/sessions/revoke", nil, "", key.Secret, http.StatusNoContent, nil)
	requestJSON(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/runtime/sessions/introspect", map[string]any{"session_reference": runtimeSession.SessionReference}, "", key.Secret, http.StatusUnauthorized, nil)

	requestJSON(t, client, "PATCH", ts.URL+"/v1/projects/"+project.UID, map[string]any{"name": "CSRF attempt"}, "", "", http.StatusForbidden, nil)
	requestJSON(t, client, "DELETE", ts.URL+"/v1/projects/"+project.UID+"/origins/"+project.Origins[0].UID, nil, "http://console.test", "", http.StatusConflict, nil)

	var second Project
	requestJSON(t, client, "POST", ts.URL+"/v1/projects", map[string]any{"name": "Second App", "environment": "sandbox", "rp_id": "localhost", "rp_name": "Second", "initial_origin": "http://localhost:4000"}, "http://console.test", "", http.StatusCreated, &second)
	requestJSON(t, client, "POST", ts.URL+"/v1/projects/"+second.UID+"/users", map[string]any{"email": "user@example.com"}, "http://console.test", "", http.StatusCreated, &ProjectUser{})
	requestJSON(t, client, "GET", ts.URL+"/v1/projects/"+second.UID+"/users", nil, "", key.Secret, http.StatusUnauthorized, nil)
}

func requestJSON(t *testing.T, client *http.Client, method, target string, body any, origin, bearer string, status int, output any) {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	request, err := http.NewRequest(method, target, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		var problem any
		_ = json.NewDecoder(response.Body).Decode(&problem)
		t.Fatalf("%s %s status=%d want=%d body=%v", method, target, response.StatusCode, status, problem)
	}
	if output != nil && response.StatusCode != http.StatusNoContent {
		if err = json.NewDecoder(response.Body).Decode(output); err != nil {
			t.Fatal(err)
		}
	}
}

func requestWithSession(t *testing.T, client *http.Client, target, key, session string, status int, output any) {
	t.Helper()
	request, _ := http.NewRequest("POST", target, nil)
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("X-ComplicatedAuth-Session", session)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		t.Fatalf("status=%d want=%d", response.StatusCode, status)
	}
	if err = json.NewDecoder(response.Body).Decode(output); err != nil {
		t.Fatal(err)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
