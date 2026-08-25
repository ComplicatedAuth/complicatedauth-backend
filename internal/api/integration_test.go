package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	security "github.com/complicatedauth/complicatedauth-backend/internal/auth"
	"github.com/complicatedauth/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
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
	encryptionKeys, err := security.ParseEncryptionKeyring("test:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{DatabaseURL: databaseURL, ConsoleOrigin: "http://console.test", OAuthIssuer: "https://issuer.test", SecretHashKey: bytes.Repeat([]byte{7}, 32), DataEncryptionKeys: encryptionKeys, MemberAbsoluteTTL: 7 * 24 * time.Hour, MemberIdleTTL: 24 * time.Hour, UserAbsoluteTTL: 30 * 24 * time.Hour, UserIdleTTL: 7 * 24 * time.Hour, OAuthAuthorizationTTL: 10 * time.Minute, OAuthCodeTTL: 5 * time.Minute, OAuthAccessTokenTTL: 10 * time.Minute, OAuthSigningKeyMaxAge: 30 * 24 * time.Hour}
	apiServer := New(cfg, pool, testLogger())
	mailer := &recordingEmailSender{}
	apiServer.email = mailer
	if err = apiServer.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if err = New(cfg, pool, testLogger()).Initialize(ctx); err != nil {
		t.Fatalf("second replica initialization: %v", err)
	}
	var maintenanceJobCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM background_jobs WHERE queue='maintenance' AND deduplication_key='global'`).Scan(&maintenanceJobCount); err != nil || maintenanceJobCount != 1 {
		t.Fatalf("maintenance job count=%d err=%v", maintenanceJobCount, err)
	}
	var signingKeyCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM oauth_signing_keys WHERE status='active'`).Scan(&signingKeyCount); err != nil || signingKeyCount != 1 {
		t.Fatalf("active OAuth signing keys=%d err=%v", signingKeyCount, err)
	}
	ts := httptest.NewServer(apiServer.Handler())
	defer ts.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	serviceClient := &http.Client{}

	var session ConsoleSession
	requestJSON(t, client, "POST", ts.URL+"/v1/console/auth/signup", map[string]any{"email": "owner@example.com", "password": "correct horse battery staple", "display_name": "Alice Owner", "tenant_name": "Acme Corporation"}, "http://console.test", "", http.StatusCreated, &session)
	if session.Member.Role != "owner" {
		t.Fatalf("role=%q", session.Member.Role)
	}
	verificationMessage := processNextEmailJob(t, ctx, apiServer, pool)
	verificationToken := tokenFromEmail(t, verificationMessage, "/verify-email")
	requestJSON(t, client, "POST", ts.URL+"/v1/console/email-verifications", map[string]any{"token": verificationToken}, "http://console.test", "", http.StatusNoContent, nil)
	requestJSON(t, client, "POST", ts.URL+"/v1/console/email-verifications", map[string]any{"token": verificationToken}, "http://console.test", "", http.StatusBadRequest, nil)
	var verifiedSession ConsoleSession
	requestJSON(t, client, "GET", ts.URL+"/v1/console/auth/session", nil, "", "", http.StatusOK, &verifiedSession)
	if !verifiedSession.Member.EmailVerified {
		t.Fatal("email verification did not update the owner")
	}
	requestJSON(t, client, "GET", ts.URL+"/v1/projects", nil, "", "", http.StatusForbidden, nil)
	if _, err = pool.Exec(ctx, `UPDATE tenant_member_sessions SET authentication_assurance='strong',strongly_authenticated_at=clock_timestamp() WHERE tenant_member_uid=$1`, session.Member.UID); err != nil {
		t.Fatal(err)
	}
	requestJSON(t, &http.Client{}, "POST", ts.URL+"/v1/console/email-verification-requests", map[string]any{"email": "missing@example.com"}, "http://console.test", "", http.StatusAccepted, &map[string]bool{})
	if empty, claimErr := store.NewBackgroundJobStore(pool).Claim(ctx, "email", time.Minute); claimErr != nil || empty != nil {
		t.Fatalf("unknown verification request created delivery=%+v err=%v", empty, claimErr)
	}

	var publicApplication OAuthApplication
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/oauth/applications", map[string]any{"name": "Browser client", "application_type": "public", "redirect_uris": []string{"http://localhost:4444/callback"}}, "http://console.test", "", map[string]string{"Idempotency-Key": "oauth_public_app_123"}, http.StatusCreated, &publicApplication)
	var publicApplicationReplay OAuthApplication
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/oauth/applications", map[string]any{"redirect_uris": []string{"http://localhost:4444/callback"}, "application_type": "public", "name": "Browser client"}, "http://console.test", "", map[string]string{"Idempotency-Key": "oauth_public_app_123"}, http.StatusCreated, &publicApplicationReplay)
	if publicApplication.UID != publicApplicationReplay.UID || publicApplication.ClientID != publicApplicationReplay.ClientID {
		t.Fatalf("OAuth Application replay changed resource: first=%+v replay=%+v", publicApplication, publicApplicationReplay)
	}
	requestJSONWithHeaders(t, client, "PATCH", ts.URL+"/v1/oauth/applications/"+publicApplication.UID, map[string]any{"name": "No precondition"}, "http://console.test", "", nil, http.StatusPreconditionRequired, nil)
	requestJSONWithHeaders(t, client, "PATCH", ts.URL+"/v1/oauth/applications/"+publicApplication.UID, map[string]any{"name": "Stale"}, "http://console.test", "", map[string]string{"If-Match": `"99"`}, http.StatusPreconditionFailed, nil)
	requestJSONWithHeaders(t, client, "PATCH", ts.URL+"/v1/oauth/applications/"+publicApplication.UID, map[string]any{"name": "Browser client renamed"}, "http://console.test", "", map[string]string{"If-Match": `"1"`}, http.StatusOK, &publicApplication)
	if publicApplication.Version != 2 || publicApplication.Name != "Browser client renamed" {
		t.Fatalf("unexpected updated OAuth Application: %+v", publicApplication)
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/oauth/applications/"+publicApplication.UID+"/client-secrets", map[string]any{"name": "invalid"}, "http://console.test", "", map[string]string{"Idempotency-Key": "oauth_public_secret_123"}, http.StatusConflict, nil)

	var confidentialApplication OAuthApplication
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/oauth/applications", map[string]any{"name": "Server client", "application_type": "confidential", "redirect_uris": []string{"https://client.example/callback"}}, "http://console.test", "", map[string]string{"Idempotency-Key": "oauth_confidential_app_123"}, http.StatusCreated, &confidentialApplication)
	var clientSecret OAuthClientSecret
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/oauth/applications/"+confidentialApplication.UID+"/client-secrets", map[string]any{"name": "Primary"}, "http://console.test", "", map[string]string{"Idempotency-Key": "oauth_confidential_secret_123"}, http.StatusCreated, &clientSecret)
	if clientSecret.Secret == "" || !strings.HasPrefix(clientSecret.Secret, clientSecret.Prefix+".") {
		t.Fatalf("client secret ceremony did not return expected secret: %+v", clientSecret)
	}
	var replayedClientSecret OAuthClientSecret
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/oauth/applications/"+confidentialApplication.UID+"/client-secrets", map[string]any{"name": "Primary"}, "http://console.test", "", map[string]string{"Idempotency-Key": "oauth_confidential_secret_123"}, http.StatusCreated, &replayedClientSecret)
	if replayedClientSecret.UID != clientSecret.UID || replayedClientSecret.Secret != clientSecret.Secret {
		t.Fatalf("client secret replay changed secret: first=%+v replay=%+v", clientSecret, replayedClientSecret)
	}
	var clientSecrets struct {
		Items []OAuthClientSecret `json:"items"`
	}
	requestJSON(t, client, "GET", ts.URL+"/v1/oauth/applications/"+confidentialApplication.UID+"/client-secrets", nil, "", "", http.StatusOK, &clientSecrets)
	if len(clientSecrets.Items) != 1 || clientSecrets.Items[0].Secret != "" {
		t.Fatalf("client secret list exposed secret or omitted metadata: %+v", clientSecrets.Items)
	}

	verifier := strings.Repeat("a", 43)
	verifierDigest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(verifierDigest[:])
	authorizeURL := ts.URL + "/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {confidentialApplication.ClientID},
		"redirect_uri":          {"https://client.example/callback"},
		"scope":                 {"openid profile email"},
		"state":                 {"acceptance-state"},
		"nonce":                 {"acceptance-nonce"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	authorizeResponse, err := noRedirectClient.Get(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = authorizeResponse.Body.Close()
	if authorizeResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize status=%d", authorizeResponse.StatusCode)
	}
	consentLocation, err := url.Parse(authorizeResponse.Header.Get("Location"))
	if err != nil || consentLocation.Scheme+"://"+consentLocation.Host != cfg.ConsoleOrigin || consentLocation.Path != "/oauth/authorize" {
		t.Fatalf("unexpected consent location %q err=%v", authorizeResponse.Header.Get("Location"), err)
	}
	fragment, err := url.ParseQuery(consentLocation.Fragment)
	if err != nil || fragment.Get("request") == "" {
		t.Fatalf("consent redirect did not contain request handle in fragment: %q err=%v", consentLocation.Fragment, err)
	}
	requestToken := fragment.Get("request")
	var authorizationRequest OAuthAuthorizationRequest
	requestJSON(t, client, "POST", ts.URL+"/v1/oauth/authorization-requests/inspect", map[string]any{"request_token": requestToken}, cfg.ConsoleOrigin, "", http.StatusOK, &authorizationRequest)
	if authorizationRequest.ApplicationUID != confidentialApplication.UID || !scopeContains(authorizationRequest.Scopes, "openid") {
		t.Fatalf("unexpected authorization request: %+v", authorizationRequest)
	}
	var decision struct {
		RedirectTo string `json:"redirect_to"`
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/oauth/authorization-requests/decision", map[string]any{"request_token": requestToken, "decision": "approve"}, cfg.ConsoleOrigin, "", map[string]string{"Idempotency-Key": "oauth_decision_123"}, http.StatusOK, &decision)
	var replayedDecision struct {
		RedirectTo string `json:"redirect_to"`
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/oauth/authorization-requests/decision", map[string]any{"decision": "approve", "request_token": requestToken}, cfg.ConsoleOrigin, "", map[string]string{"Idempotency-Key": "oauth_decision_123"}, http.StatusOK, &replayedDecision)
	if decision.RedirectTo == "" || replayedDecision.RedirectTo != decision.RedirectTo {
		t.Fatalf("authorization decision did not replay exact redirect: first=%q replay=%q", decision.RedirectTo, replayedDecision.RedirectTo)
	}
	callback, err := url.Parse(decision.RedirectTo)
	if err != nil || callback.Scheme+"://"+callback.Host+callback.Path != "https://client.example/callback" || callback.Query().Get("state") != "acceptance-state" || callback.Query().Get("iss") != cfg.OAuthIssuer {
		t.Fatalf("unexpected OAuth callback %q err=%v", decision.RedirectTo, err)
	}
	code := callback.Query().Get("code")
	if code == "" {
		t.Fatal("authorization callback omitted code")
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
		IDToken     string `json:"id_token"`
	}
	requestOAuthForm(t, client, ts.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example/callback"},
		"code_verifier": {verifier},
	}, confidentialApplication.ClientID, clientSecret.Secret, http.StatusOK, &tokens)
	if tokens.AccessToken == "" || tokens.IDToken == "" || tokens.TokenType != "Bearer" || tokens.ExpiresIn < 1 {
		t.Fatalf("unexpected token response: %+v", tokens)
	}
	verifyIDToken(t, client, ts.URL, tokens.IDToken, confidentialApplication.ClientID, "acceptance-nonce")
	var userInfo map[string]any
	requestJSON(t, client, "GET", ts.URL+"/oauth/userinfo", nil, "", tokens.AccessToken, http.StatusOK, &userInfo)
	if userInfo["email"] != "owner@example.com" || userInfo["sub"] == "" {
		t.Fatalf("unexpected UserInfo: %+v", userInfo)
	}
	requestOAuthForm(t, client, ts.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example/callback"},
		"code_verifier": {verifier},
	}, confidentialApplication.ClientID, clientSecret.Secret, http.StatusBadRequest, nil)
	requestOAuthForm(t, client, ts.URL+"/oauth/revoke", url.Values{"token": {tokens.AccessToken}}, confidentialApplication.ClientID, clientSecret.Secret, http.StatusOK, nil)
	requestJSON(t, client, "GET", ts.URL+"/oauth/userinfo", nil, "", tokens.AccessToken, http.StatusUnauthorized, nil)
	var consents struct {
		Items []OAuthConsent `json:"items"`
	}
	requestJSON(t, client, "GET", ts.URL+"/v1/oauth/consents", nil, "", "", http.StatusOK, &consents)
	if len(consents.Items) != 1 || consents.Items[0].ApplicationUID != confidentialApplication.UID {
		t.Fatalf("unexpected OAuth consents: %+v", consents.Items)
	}
	requestJSON(t, client, "DELETE", ts.URL+"/v1/oauth/consents/"+consents.Items[0].UID, nil, cfg.ConsoleOrigin, "", http.StatusNoContent, nil)

	var resourceServer ResourceServer
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/resource-servers", map[string]any{"name": "Documents API", "identifier": "https://api.acme.example"}, cfg.ConsoleOrigin, "", map[string]string{"Idempotency-Key": "resource_server_documents_123"}, http.StatusCreated, &resourceServer)
	if resourceServer.Identifier != "https://api.acme.example" || resourceServer.PolicyVersion != 1 {
		t.Fatalf("unexpected Resource Server: %+v", resourceServer)
	}
	var readScope ResourceServerScope
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/resource-servers/"+resourceServer.UID+"/scopes", map[string]any{"name": "documents.read", "display_name": "Read documents", "description": "Read documents you can access."}, cfg.ConsoleOrigin, "", map[string]string{"Idempotency-Key": "resource_scope_read_123"}, http.StatusCreated, &readScope)
	var writeScope ResourceServerScope
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/resource-servers/"+resourceServer.UID+"/scopes", map[string]any{"name": "documents.write", "display_name": "Write documents"}, cfg.ConsoleOrigin, "", map[string]string{"Idempotency-Key": "resource_scope_write_123"}, http.StatusCreated, &writeScope)
	var applicationGrant OAuthApplicationGrant
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/oauth/applications/"+confidentialApplication.UID+"/grants", map[string]any{"resource_server_uid": resourceServer.UID, "scope_uids": []string{readScope.UID}}, cfg.ConsoleOrigin, "", map[string]string{"Idempotency-Key": "oauth_documents_grant_123"}, http.StatusCreated, &applicationGrant)
	if len(applicationGrant.Scopes) != 1 || applicationGrant.Scopes[0] != "documents.read" {
		t.Fatalf("unexpected OAuth Application grant: %+v", applicationGrant)
	}

	delegatedVerifier := strings.Repeat("b", 43)
	delegatedVerifierDigest := sha256.Sum256([]byte(delegatedVerifier))
	delegatedChallenge := base64.RawURLEncoding.EncodeToString(delegatedVerifierDigest[:])
	delegatedAuthorizeURL := ts.URL + "/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {confidentialApplication.ClientID},
		"redirect_uri":          {"https://client.example/callback"},
		"resource":              {resourceServer.Identifier},
		"scope":                 {"openid profile documents.read"},
		"state":                 {"delegated-state"},
		"nonce":                 {"delegated-nonce"},
		"code_challenge":        {delegatedChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	delegatedAuthorizeResponse, err := noRedirectClient.Get(delegatedAuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = delegatedAuthorizeResponse.Body.Close()
	if delegatedAuthorizeResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("delegated authorize status=%d", delegatedAuthorizeResponse.StatusCode)
	}
	delegatedConsentLocation, err := url.Parse(delegatedAuthorizeResponse.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	delegatedFragment, _ := url.ParseQuery(delegatedConsentLocation.Fragment)
	delegatedRequestToken := delegatedFragment.Get("request")
	var delegatedAuthorizationRequest OAuthAuthorizationRequest
	requestJSON(t, client, "POST", ts.URL+"/v1/oauth/authorization-requests/inspect", map[string]any{"request_token": delegatedRequestToken}, cfg.ConsoleOrigin, "", http.StatusOK, &delegatedAuthorizationRequest)
	if delegatedAuthorizationRequest.ResourceServerUID == nil || *delegatedAuthorizationRequest.ResourceServerUID != resourceServer.UID || delegatedAuthorizationRequest.ResourceServerIdentifier == nil || *delegatedAuthorizationRequest.ResourceServerIdentifier != resourceServer.Identifier {
		t.Fatalf("delegated consent omitted Resource Server: %+v", delegatedAuthorizationRequest)
	}
	var delegatedScopeDescription string
	for _, detail := range delegatedAuthorizationRequest.ScopeDetails {
		if detail.Name == "documents.read" {
			delegatedScopeDescription = detail.Description
		}
	}
	if delegatedScopeDescription != "Read documents you can access." {
		t.Fatalf("delegated consent omitted registered scope description: %+v", delegatedAuthorizationRequest.ScopeDetails)
	}
	var delegatedDecision struct {
		RedirectTo string `json:"redirect_to"`
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/oauth/authorization-requests/decision", map[string]any{"request_token": delegatedRequestToken, "decision": "approve"}, cfg.ConsoleOrigin, "", map[string]string{"Idempotency-Key": "oauth_delegated_decision_123"}, http.StatusOK, &delegatedDecision)
	delegatedCallback, err := url.Parse(delegatedDecision.RedirectTo)
	if err != nil || delegatedCallback.Query().Get("state") != "delegated-state" {
		t.Fatalf("unexpected delegated callback %q err=%v", delegatedDecision.RedirectTo, err)
	}
	var delegatedTokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	requestOAuthForm(t, client, ts.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {delegatedCallback.Query().Get("code")},
		"redirect_uri":  {"https://client.example/callback"},
		"code_verifier": {delegatedVerifier},
	}, confidentialApplication.ClientID, clientSecret.Secret, http.StatusOK, &delegatedTokens)
	requestJSON(t, client, "GET", ts.URL+"/oauth/userinfo", nil, "", delegatedTokens.AccessToken, http.StatusUnauthorized, nil)
	var allowedDecision AuthorizationDecision
	requestJSON(t, client, "POST", ts.URL+"/v1/authorization/decisions", map[string]any{"resource": map[string]any{"type": "document", "id": "doc_123"}, "operation": "documents.read", "context": map[string]any{"source": "acceptance"}}, "", delegatedTokens.AccessToken, http.StatusOK, &allowedDecision)
	if !allowedDecision.Allowed || allowedDecision.TenantUID != session.Tenant.UID || allowedDecision.ResourceServerUID != resourceServer.UID || allowedDecision.Principal.Subject == "" || allowedDecision.DenialReason != nil {
		t.Fatalf("unexpected allowed authorization decision: %+v", allowedDecision)
	}
	var deniedDecision AuthorizationDecision
	requestJSON(t, client, "POST", ts.URL+"/v1/authorization/decisions", map[string]any{"resource": map[string]any{"type": "document", "id": "doc_123"}, "operation": "documents.write"}, "", delegatedTokens.AccessToken, http.StatusOK, &deniedDecision)
	if deniedDecision.Allowed || deniedDecision.DenialReason == nil || *deniedDecision.DenialReason != "missing_capability" {
		t.Fatalf("unexpected denied authorization decision: %+v", deniedDecision)
	}
	accessEvaluationKey := "aeval_" + strings.Repeat("a", 32)
	var accessEvaluation struct {
		ID            string    `json:"id"`
		Grants        []string  `json:"grants"`
		ExpiresAt     time.Time `json:"expires_at"`
		PolicyVersion string    `json:"policy_version"`
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/access/evaluations", map[string]any{}, "", delegatedTokens.AccessToken, map[string]string{"Idempotency-Key": accessEvaluationKey, "X-External-Request-ID": "req_" + strings.Repeat("b", 32)}, http.StatusOK, &accessEvaluation)
	if accessEvaluation.ID != accessEvaluationKey || !scopeContains(accessEvaluation.Grants, "documents.read") || !strings.HasPrefix(accessEvaluation.PolicyVersion, "scope-v1:") || accessEvaluation.ExpiresAt.IsZero() {
		t.Fatalf("unexpected delegated access evaluation: %+v", accessEvaluation)
	}
	var replayedAccessEvaluation struct {
		ID string `json:"id"`
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/access/evaluations", map[string]any{}, "", delegatedTokens.AccessToken, map[string]string{"Idempotency-Key": accessEvaluationKey, "X-External-Request-ID": "req_" + strings.Repeat("c", 32)}, http.StatusOK, &replayedAccessEvaluation)
	if replayedAccessEvaluation.ID != accessEvaluation.ID {
		t.Fatal("access-evaluation retry did not replay the stable result")
	}
	requestJSONWithHeaders(t, client, "PATCH", ts.URL+"/v1/oauth/applications/"+confidentialApplication.UID+"/grants/"+applicationGrant.UID, map[string]any{"scope_uids": []string{readScope.UID, writeScope.UID}}, cfg.ConsoleOrigin, "", map[string]string{"If-Match": `"1"`}, http.StatusOK, &OAuthApplicationGrant{})
	requestJSON(t, client, "POST", ts.URL+"/v1/authorization/decisions", map[string]any{"resource": map[string]any{"type": "document", "id": "doc_123"}, "operation": "documents.read"}, "", delegatedTokens.AccessToken, http.StatusUnauthorized, nil)

	var invitation TenantInvitation
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/tenant/invitations", map[string]any{"email": "viewer@example.com", "role": "viewer"}, "http://console.test", "", map[string]string{"Idempotency-Key": "invite_acceptance_123"}, http.StatusCreated, &invitation)
	if invitation.Role != "viewer" {
		t.Fatalf("unexpected invitation: %+v", invitation)
	}
	invitationMessage := processNextEmailJob(t, ctx, apiServer, pool)
	invitationToken := tokenFromEmail(t, invitationMessage, "/accept-invitation/"+invitation.UID)
	var replayedInvitation TenantInvitation
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/tenant/invitations", map[string]any{"role": "viewer", "email": "viewer@example.com"}, "http://console.test", "", map[string]string{"Idempotency-Key": "invite_acceptance_123"}, http.StatusCreated, &replayedInvitation)
	if replayedInvitation.UID != invitation.UID {
		t.Fatalf("idempotent replay changed invitation: first=%+v replay=%+v", invitation, replayedInvitation)
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/tenant/invitations", map[string]any{"email": "different@example.com", "role": "viewer"}, "http://console.test", "", map[string]string{"Idempotency-Key": "invite_acceptance_123"}, http.StatusConflict, nil)

	viewerJar, _ := cookiejar.New(nil)
	viewerClient := &http.Client{Jar: viewerJar}
	var viewerSession ConsoleSession
	requestJSON(t, viewerClient, "POST", ts.URL+"/v1/tenant/invitations/"+invitation.UID+"/accept", map[string]any{"acceptance_token": invitationToken, "password": "viewer correct battery staple", "display_name": "Victor Viewer"}, "http://console.test", "", http.StatusCreated, &viewerSession)
	if viewerSession.Member.Role != "viewer" || !viewerSession.Member.EmailVerified {
		t.Fatalf("unexpected accepted member: %+v", viewerSession.Member)
	}
	if viewerSession.AuthenticationAssurance != "bootstrap" {
		t.Fatalf("invitation session assurance=%q", viewerSession.AuthenticationAssurance)
	}
	requestJSON(t, viewerClient, "GET", ts.URL+"/v1/projects", nil, "", "", http.StatusForbidden, nil)
	if _, err = pool.Exec(ctx, `UPDATE tenant_member_sessions SET authentication_assurance='strong',strongly_authenticated_at=clock_timestamp() WHERE tenant_member_uid=$1`, viewerSession.Member.UID); err != nil {
		t.Fatal(err)
	}
	requestJSON(t, viewerClient, "GET", ts.URL+"/v1/projects", nil, "", "", http.StatusOK, &struct {
		Items []Project `json:"items"`
	}{})
	requestJSON(t, viewerClient, "POST", ts.URL+"/v1/projects", map[string]any{"name": "Forbidden", "environment": "sandbox", "rp_id": "localhost", "rp_name": "Forbidden", "initial_origin": "http://localhost:9000"}, "http://console.test", "", http.StatusForbidden, nil)
	var members struct {
		Items []TenantMember `json:"items"`
	}
	requestJSON(t, client, "GET", ts.URL+"/v1/tenant/members", nil, "", "", http.StatusOK, &members)
	if len(members.Items) != 2 {
		t.Fatalf("members=%d want=2", len(members.Items))
	}
	requestJSON(t, client, "PATCH", ts.URL+"/v1/tenant/members/"+viewerSession.Member.UID, map[string]any{"role": "developer"}, "http://console.test", "", http.StatusOK, &TenantMember{})
	requestJSON(t, client, "PATCH", ts.URL+"/v1/tenant/members/"+session.Member.UID, map[string]any{"role": "admin"}, "http://console.test", "", http.StatusConflict, nil)
	var memberSessions struct {
		Items []TenantMemberSession `json:"items"`
	}
	requestJSON(t, viewerClient, "GET", ts.URL+"/v1/console/auth/sessions", nil, "", "", http.StatusOK, &memberSessions)
	if len(memberSessions.Items) != 1 || !memberSessions.Items[0].Current {
		t.Fatalf("unexpected member sessions: %+v", memberSessions.Items)
	}
	requestJSON(t, &http.Client{}, "POST", ts.URL+"/v1/console/password-reset-requests", map[string]any{"email": "viewer@example.com"}, "http://console.test", "", http.StatusAccepted, &map[string]bool{})
	requestJSON(t, &http.Client{}, "POST", ts.URL+"/v1/console/password-reset-requests", map[string]any{"email": "nobody@example.com"}, "http://console.test", "", http.StatusAccepted, &map[string]bool{})
	resetMessage := processNextEmailJob(t, ctx, apiServer, pool)
	resetToken := tokenFromEmail(t, resetMessage, "/reset-password")
	requestJSON(t, &http.Client{}, "POST", ts.URL+"/v1/console/password-resets", map[string]any{"token": resetToken, "password": "viewer replacement battery staple"}, "http://console.test", "", http.StatusNoContent, nil)
	requestJSON(t, viewerClient, "GET", ts.URL+"/v1/console/auth/session", nil, "", "", http.StatusUnauthorized, nil)
	var oldPasswordAttempt TenantMemberLoginAttempt
	requestJSON(t, &http.Client{}, "POST", ts.URL+"/v1/console/login-attempts", map[string]any{"email": "viewer@example.com"}, "http://console.test", "", http.StatusCreated, &oldPasswordAttempt)
	requestJSONWithHeaders(t, &http.Client{}, "POST", ts.URL+"/v1/console/login-attempts/"+oldPasswordAttempt.UID+"/password-verifications", map[string]any{"password": "viewer correct battery staple"}, "http://console.test", "", map[string]string{"X-ComplicatedAuth-Login-Secret": oldPasswordAttempt.ClientSecret}, http.StatusUnauthorized, nil)
	var replacementPasswordAttempt TenantMemberLoginAttempt
	requestJSON(t, &http.Client{}, "POST", ts.URL+"/v1/console/login-attempts", map[string]any{"email": "viewer@example.com"}, "http://console.test", "", http.StatusCreated, &replacementPasswordAttempt)
	var loginProgress TenantMemberLoginProgress
	requestJSONWithHeaders(t, &http.Client{}, "POST", ts.URL+"/v1/console/login-attempts/"+replacementPasswordAttempt.UID+"/password-verifications", map[string]any{"password": "viewer replacement battery staple"}, "http://console.test", "", map[string]string{"X-ComplicatedAuth-Login-Secret": replacementPasswordAttempt.ClientSecret}, http.StatusCreated, &loginProgress)
	if !loginProgress.CredentialSetupRequired {
		t.Fatal("password recovery did not require fresh WebAuthn enrollment")
	}

	var project Project
	requestJSON(t, client, "POST", ts.URL+"/v1/projects", map[string]any{"name": "Acme Web App", "environment": "sandbox", "rp_id": "localhost", "rp_name": "Acme", "initial_origin": "http://localhost:3000"}, "http://console.test", "", http.StatusCreated, &project)
	if project.OriginCount != 1 || project.RPID != "localhost" {
		t.Fatalf("unexpected project: %+v", project)
	}

	var serviceAccount ServiceAccount
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/service-accounts", map[string]any{"name": "Test backend", "description": "Acceptance workload", "scopes": []string{serviceScopeProjectUsersRead, serviceScopeProjectUsersWrite, serviceScopeAuthentication, serviceScopeSessionsManage, serviceScopeSupportCasesRead, serviceScopeSupportCasesWrite, serviceScopeExternalCredentialsManage}}, "http://console.test", "", map[string]string{"Idempotency-Key": "service_account_123"}, http.StatusCreated, &serviceAccount)
	if serviceAccount.Environment != "sandbox" || serviceAccount.Version != 1 {
		t.Fatalf("unexpected service account: %+v", serviceAccount)
	}
	var credential ServiceCredential
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/service-accounts/"+serviceAccount.UID+"/credentials", map[string]any{"name": "Acceptance deployment"}, "http://console.test", "", map[string]string{"Idempotency-Key": "service_credential_123"}, http.StatusCreated, &credential)
	if credential.Secret == "" || !strings.HasPrefix(credential.Secret, "ca_sk_test_") {
		t.Fatal("credential issuance did not return the sandbox one-time secret")
	}
	var replayedCredential ServiceCredential
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/service-accounts/"+serviceAccount.UID+"/credentials", map[string]any{"name": "Acceptance deployment"}, "http://console.test", "", map[string]string{"Idempotency-Key": "service_credential_123"}, http.StatusCreated, &replayedCredential)
	if replayedCredential.UID != credential.UID || replayedCredential.Secret != credential.Secret {
		t.Fatal("idempotent credential replay changed the one-time result")
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/service-accounts/"+serviceAccount.UID+"/credentials", map[string]any{"name": "Changed deployment"}, "http://console.test", "", map[string]string{"Idempotency-Key": "service_credential_123"}, http.StatusConflict, nil)
	var credentials struct {
		Items []ServiceCredential `json:"items"`
	}
	requestJSON(t, client, "GET", ts.URL+"/v1/projects/"+project.UID+"/service-accounts/"+serviceAccount.UID+"/credentials", nil, "", "", http.StatusOK, &credentials)
	if len(credentials.Items) != 1 || credentials.Items[0].Secret != "" || credentials.Items[0].Fingerprint == "" {
		t.Fatal("credential list exposed a secret or omitted safe metadata")
	}

	var user ProjectUser
	requestJSON(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/users", map[string]any{"email": "user@example.com", "password": "another correct battery staple", "email_verified": true}, "http://console.test", "", http.StatusCreated, &user)
	requestJSON(t, client, "GET", ts.URL+"/v1/projects/"+project.UID+"/users/"+user.UID, nil, "", credential.Secret, http.StatusOK, &ProjectUser{})
	requestJSON(t, client, "PATCH", ts.URL+"/v1/projects/"+project.UID+"/users/"+user.UID, map[string]any{"email_verified": false}, "", credential.Secret, http.StatusOK, &ProjectUser{})

	var externalAuthorization struct {
		Allowed bool `json:"allowed"`
	}
	externalAuthorizationRequest := map[string]any{
		"operation": "credentials.create", "subject": base64.RawURLEncoding.EncodeToString([]byte(cfg.OAuthIssuer)) + "." + base64.RawURLEncoding.EncodeToString([]byte(allowedDecision.Principal.Subject)),
		"external_customer_id": session.Tenant.UID, "installation_id": "",
		"deployment_id": "deployment_acceptance", "details": map[string]any{"integration_id": "customer-api-v1"},
	}
	requestJSON(t, serviceClient, "POST", ts.URL+"/v1/external-platform/credentials/authorize", externalAuthorizationRequest, "", credential.Secret, http.StatusOK, &externalAuthorization)
	if !externalAuthorization.Allowed {
		t.Fatal("active pairwise OAuth subject was denied external credential management")
	}
	externalAuthorizationRequest["external_customer_id"] = uuid.NewString()
	requestJSON(t, serviceClient, "POST", ts.URL+"/v1/external-platform/credentials/authorize", externalAuthorizationRequest, "", credential.Secret, http.StatusOK, &externalAuthorization)
	if externalAuthorization.Allowed {
		t.Fatal("external credential authorization accepted a different Tenant")
	}

	type externalCredentialResult struct {
		CredentialID string    `json:"credential_id"`
		Credential   string    `json:"credential"`
		ExpiresAt    time.Time `json:"expires_at"`
	}
	issueRequest := map[string]any{
		"deployment_id": "deployment_acceptance", "integration_id": "customer-api-v1",
		"environment_id": "sandbox", "access_instance_id": "", "subject": externalAuthorizationRequest["subject"],
		"scopes": []string{serviceScopeProjectUsersRead}, "idempotency_key": "external_credential_123", "ttl_seconds": 3600,
	}
	var externalCredential externalCredentialResult
	requestJSON(t, serviceClient, "POST", ts.URL+"/v1/external-platform/credentials", issueRequest, "", credential.Secret, http.StatusCreated, &externalCredential)
	if externalCredential.CredentialID == "" || !strings.HasPrefix(externalCredential.Credential, "ca_xk_test_") || !externalCredential.ExpiresAt.After(time.Now()) {
		t.Fatalf("unexpected external credential ceremony: %+v", externalCredential)
	}
	var replayedExternalCredential externalCredentialResult
	requestJSON(t, serviceClient, "POST", ts.URL+"/v1/external-platform/credentials", issueRequest, "", credential.Secret, http.StatusCreated, &replayedExternalCredential)
	if replayedExternalCredential != externalCredential {
		t.Fatalf("external credential replay changed the one-time result: first=%+v replay=%+v", externalCredential, replayedExternalCredential)
	}
	requestJSON(t, serviceClient, "GET", ts.URL+"/v1/projects/"+project.UID+"/users/"+user.UID, nil, "", externalCredential.Credential, http.StatusOK, &ProjectUser{})
	requestJSON(t, serviceClient, "POST", ts.URL+"/v1/external-platform/credentials", issueRequest, "", externalCredential.Credential, http.StatusForbidden, nil)

	rotationRequest := map[string]any{
		"deployment_id": "deployment_acceptance", "integration_id": "customer-api-v1",
		"environment_id": "sandbox", "access_instance_id": "", "subject": allowedDecision.Principal.Subject,
		"scopes": []string{serviceScopeProjectUsersRead}, "idempotency_key": "external_credential_rotation_123", "ttl_seconds": 3600,
		"rotated_from_credential_id": externalCredential.CredentialID,
	}
	var rotatedExternalCredential externalCredentialResult
	requestJSON(t, serviceClient, "POST", ts.URL+"/v1/external-platform/credentials", rotationRequest, "", credential.Secret, http.StatusCreated, &rotatedExternalCredential)
	if rotatedExternalCredential.CredentialID == externalCredential.CredentialID || rotatedExternalCredential.Credential == externalCredential.Credential {
		t.Fatal("external credential rotation reused the prior credential")
	}
	thirdRequest := map[string]any{
		"deployment_id": "deployment_acceptance", "integration_id": "customer-api-v1",
		"environment_id": "sandbox", "access_instance_id": "", "subject": allowedDecision.Principal.Subject,
		"scopes": []string{serviceScopeProjectUsersRead}, "idempotency_key": "external_credential_third_123", "ttl_seconds": 3600,
	}
	requestJSON(t, serviceClient, "POST", ts.URL+"/v1/external-platform/credentials", thirdRequest, "", credential.Secret, http.StatusConflict, nil)
	revokeRequest := map[string]any{"deployment_id": "deployment_acceptance", "subject": externalAuthorizationRequest["subject"]}
	requestJSON(t, serviceClient, "POST", ts.URL+"/v1/external-platform/credentials/"+externalCredential.CredentialID+"/revoke", revokeRequest, "", credential.Secret, http.StatusNoContent, nil)
	requestJSON(t, serviceClient, "POST", ts.URL+"/v1/external-platform/credentials/"+externalCredential.CredentialID+"/revoke", revokeRequest, "", credential.Secret, http.StatusNoContent, nil)
	requestJSON(t, serviceClient, "GET", ts.URL+"/v1/projects/"+project.UID+"/users/"+user.UID, nil, "", externalCredential.Credential, http.StatusUnauthorized, nil)
	requestJSON(t, serviceClient, "GET", ts.URL+"/v1/projects/"+project.UID+"/users/"+user.UID, nil, "", rotatedExternalCredential.Credential, http.StatusOK, &ProjectUser{})

	var supportCase SupportCase
	supportCreate := map[string]any{
		"category": "bug", "subject": "Login page loops", "message": "The browser returned to login twice.",
		"reporter_project_user_uid": user.UID, "diagnostic_consent": true,
		"diagnostics": map[string]any{"application_version": "1.2.3", "platform": "acceptance", "current_url": "https://app.example/login", "request_id": "req_acceptance"},
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/support/cases", supportCreate, "", credential.Secret, map[string]string{"Idempotency-Key": "support_case_123"}, http.StatusCreated, &supportCase)
	if supportCase.ProjectUID == nil || *supportCase.ProjectUID != project.UID || supportCase.Reporter.Type != "project_user" || supportCase.Reporter.UID != user.UID || supportCase.Diagnostics == nil || supportCase.Diagnostics.RequestID != "req_acceptance" || supportCase.Version != 1 {
		t.Fatalf("unexpected Support Case: %+v", supportCase)
	}
	var replayedSupportCase SupportCase
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/support/cases", supportCreate, "", credential.Secret, map[string]string{"Idempotency-Key": "support_case_123"}, http.StatusCreated, &replayedSupportCase)
	if replayedSupportCase.UID != supportCase.UID || replayedSupportCase.Reference != supportCase.Reference {
		t.Fatal("Support Case idempotent replay changed the resource")
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/support/cases", map[string]any{"category": "question", "subject": "Changed", "message": "Changed request", "diagnostic_consent": false}, "", credential.Secret, map[string]string{"Idempotency-Key": "support_case_123"}, http.StatusConflict, nil)
	var supportCases struct {
		Items []SupportCase `json:"items"`
	}
	requestJSON(t, client, "GET", ts.URL+"/v1/support/cases?status=open", nil, "", credential.Secret, http.StatusOK, &supportCases)
	if len(supportCases.Items) != 1 || supportCases.Items[0].Subject != supportCase.Subject {
		t.Fatalf("unexpected service-credential Support Case inbox: %+v", supportCases.Items)
	}
	supportSubmissionID := "support_submission_123456"
	supportSubmission := map[string]any{
		"submission_id": supportSubmissionID,
		"created_at":    time.Now().UTC(),
		"submission": map[string]any{
			"schema_version": "2026-08-25", "kind": "bug", "channel": "agent_api",
			"confirmed_at": time.Now().UTC(), "request_id": "external_report_123",
			"reporter": map[string]any{
				"principal":            map[string]any{"issuer": cfg.OAuthIssuer, "subject": allowedDecision.Principal.Subject},
				"external_customer_id": session.Tenant.UID, "allow_contact": false,
			},
			"provider":          map[string]any{"key": "example_connector", "name": "Example Connector", "version": "1.0"},
			"resource":          map[string]any{"type": "application", "id": "complicatedauth-console", "name": "ComplicatedAuth Console", "environment_id": "acceptance"},
			"related_resources": []map[string]any{{"type": "api", "id": "customer-auth-v1", "name": "Customer Auth API", "version": "v1", "state": "published", "revision": 1}},
			"extensions":        map[string]any{"example_connector": map[string]any{"catalog_digest": "sha256:acceptance"}},
			"bug":               map[string]any{"summary": "External login report", "description": "Login failed after redirect.", "severity": "high"},
		},
	}
	var submissionReceipt struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		ExternalID string `json:"external_id"`
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/support-submissions", supportSubmission, "", credential.Secret, map[string]string{"Idempotency-Key": supportSubmissionID, "X-External-Request-ID": "req_" + strings.Repeat("d", 32)}, http.StatusAccepted, &submissionReceipt)
	if submissionReceipt.ID == "" || submissionReceipt.Status != "accepted" || !strings.HasPrefix(submissionReceipt.ExternalID, "SC-") {
		t.Fatalf("unexpected support-submission receipt: %+v", submissionReceipt)
	}
	var replayedSubmissionReceipt struct {
		ID string `json:"id"`
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/support-submissions", supportSubmission, "", credential.Secret, map[string]string{"Idempotency-Key": supportSubmissionID, "X-External-Request-ID": "req_" + strings.Repeat("e", 32)}, http.StatusAccepted, &replayedSubmissionReceipt)
	if replayedSubmissionReceipt.ID != submissionReceipt.ID {
		t.Fatal("support-submission retry did not replay the created Support Case")
	}
	var externalSupportCase SupportCase
	requestJSON(t, client, "GET", ts.URL+"/v1/support/cases/"+submissionReceipt.ID, nil, "", credential.Secret, http.StatusOK, &externalSupportCase)
	if externalSupportCase.Priority != "high" || externalSupportCase.AttachmentCount != 1 || externalSupportCase.AttachmentBytes == 0 || externalSupportCase.ProjectUID == nil || *externalSupportCase.ProjectUID != project.UID {
		t.Fatalf("external support submission was not preserved as expected: %+v", externalSupportCase)
	}
	var externalAttachments struct {
		Items []SupportCaseAttachment `json:"items"`
	}
	requestJSON(t, client, "GET", ts.URL+"/v1/support/cases/"+submissionReceipt.ID+"/attachments", nil, "", credential.Secret, http.StatusOK, &externalAttachments)
	if len(externalAttachments.Items) != 1 || externalAttachments.Items[0].Filename != "external-support-submission.json" || externalAttachments.Items[0].MediaType != "application/json" {
		t.Fatalf("external support envelope attachment is incomplete: %+v", externalAttachments.Items)
	}
	externalEnvelopeRequest, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/support/cases/"+submissionReceipt.ID+"/attachments/"+externalAttachments.Items[0].UID+"/content", nil)
	if err != nil {
		t.Fatal(err)
	}
	externalEnvelopeRequest.Header.Set("Authorization", "Bearer "+credential.Secret)
	externalEnvelopeResponse, err := client.Do(externalEnvelopeRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer externalEnvelopeResponse.Body.Close()
	var preservedEnvelope map[string]any
	if externalEnvelopeResponse.StatusCode != http.StatusOK || json.NewDecoder(externalEnvelopeResponse.Body).Decode(&preservedEnvelope) != nil || preservedEnvelope["submission_id"] != supportSubmissionID {
		t.Fatalf("encrypted external support envelope did not round-trip: status=%d body=%+v", externalEnvelopeResponse.StatusCode, preservedEnvelope)
	}
	changedSubmission := map[string]any{}
	rawSubmission, _ := json.Marshal(supportSubmission)
	_ = json.Unmarshal(rawSubmission, &changedSubmission)
	changedSubmission["submission"].(map[string]any)["request_id"] = "changed_external_report"
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/support-submissions", changedSubmission, "", credential.Secret, map[string]string{"Idempotency-Key": supportSubmissionID, "X-External-Request-ID": "req_" + strings.Repeat("f", 32)}, http.StatusConflict, nil)
	var customerMessage SupportCaseMessage
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/support/cases/"+supportCase.UID+"/messages", map[string]any{"body": "It happened again.", "author_project_user_uid": user.UID}, "", credential.Secret, map[string]string{"Idempotency-Key": "support_message_customer"}, http.StatusCreated, &customerMessage)
	if customerMessage.Author.Type != "project_user" || customerMessage.Visibility != "public" {
		t.Fatalf("unexpected customer support message: %+v", customerMessage)
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/support/cases/"+supportCase.UID+"/messages", map[string]any{"body": "hidden", "visibility": "internal"}, "", credential.Secret, map[string]string{"Idempotency-Key": "support_message_forbidden"}, http.StatusForbidden, nil)
	var internalMessage SupportCaseMessage
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/support/cases/"+supportCase.UID+"/messages", map[string]any{"body": "Investigate the redirect state.", "visibility": "internal"}, "http://console.test", "", map[string]string{"Idempotency-Key": "support_message_internal"}, http.StatusCreated, &internalMessage)
	var customerMessages struct {
		Items []SupportCaseMessage `json:"items"`
	}
	requestJSON(t, client, "GET", ts.URL+"/v1/support/cases/"+supportCase.UID+"/messages", nil, "", credential.Secret, http.StatusOK, &customerMessages)
	if len(customerMessages.Items) != 2 {
		t.Fatalf("service credential saw internal Support Case messages: %+v", customerMessages.Items)
	}
	var operatorMessages struct {
		Items []SupportCaseMessage `json:"items"`
	}
	requestJSON(t, client, "GET", ts.URL+"/v1/support/cases/"+supportCase.UID+"/messages", nil, "", "", http.StatusOK, &operatorMessages)
	if len(operatorMessages.Items) != 3 {
		t.Fatalf("operator did not see complete Support Case correspondence: %+v", operatorMessages.Items)
	}
	attachmentContent := []byte("acceptance attachment\n")
	var attachment SupportCaseAttachment
	requestSupportAttachment(t, client, ts.URL+"/v1/support/cases/"+supportCase.UID+"/attachments", credential.Secret, "support_attachment_123", "diagnostics.txt", "text/plain", attachmentContent, user.UID, http.StatusCreated, &attachment)
	if attachment.Filename != "diagnostics.txt" || attachment.ByteCount != len(attachmentContent) || attachment.UploadedBy.Type != "project_user" {
		t.Fatalf("unexpected Support Case attachment: %+v", attachment)
	}
	download, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/support/cases/"+supportCase.UID+"/attachments/"+attachment.UID+"/content", nil)
	if err != nil {
		t.Fatal(err)
	}
	download.Header.Set("Authorization", "Bearer "+credential.Secret)
	downloadResponse, err := client.Do(download)
	if err != nil {
		t.Fatal(err)
	}
	downloaded, _ := io.ReadAll(downloadResponse.Body)
	downloadResponse.Body.Close()
	if downloadResponse.StatusCode != http.StatusOK || !bytes.Equal(downloaded, attachmentContent) || downloadResponse.Header.Get("Cache-Control") != "private, no-store" {
		t.Fatalf("unexpected attachment download status=%d headers=%v body=%q", downloadResponse.StatusCode, downloadResponse.Header, downloaded)
	}
	var externalReference SupportCaseExternalReference
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/support/cases/"+supportCase.UID+"/external-references", map[string]any{"provider": "example_tracker", "external_id": "BUG-123", "url": "https://tracker.example/cases/BUG-123", "label": "Engineering issue"}, "http://console.test", "", map[string]string{"Idempotency-Key": "support_external_123"}, http.StatusCreated, &externalReference)
	requestJSON(t, serviceClient, "GET", ts.URL+"/v1/support/cases/"+supportCase.UID+"/external-references", nil, "", credential.Secret, http.StatusUnauthorized, nil)
	requestJSON(t, client, "DELETE", ts.URL+"/v1/support/cases/"+supportCase.UID+"/external-references/"+externalReference.UID, nil, "http://console.test", "", http.StatusNoContent, nil)
	requestJSON(t, client, "DELETE", ts.URL+"/v1/support/cases/"+supportCase.UID+"/external-references/"+externalReference.UID, nil, "http://console.test", "", http.StatusNoContent, nil)
	var currentSupportCase SupportCase
	requestJSON(t, client, "GET", ts.URL+"/v1/support/cases/"+supportCase.UID, nil, "", "", http.StatusOK, &currentSupportCase)
	requestJSONWithHeaders(t, client, "PATCH", ts.URL+"/v1/support/cases/"+supportCase.UID, map[string]any{"priority": "urgent"}, "", credential.Secret, map[string]string{"If-Match": versionETag(currentSupportCase.Version)}, http.StatusForbidden, nil)
	requestJSONWithHeaders(t, client, "PATCH", ts.URL+"/v1/support/cases/"+supportCase.UID, map[string]any{"status": "in_progress", "priority": "high", "assignee_member_uid": session.Member.UID}, "http://console.test", "", map[string]string{"If-Match": versionETag(currentSupportCase.Version)}, http.StatusOK, &currentSupportCase)
	requestJSONWithHeaders(t, client, "PATCH", ts.URL+"/v1/support/cases/"+supportCase.UID, map[string]any{"status": "closed"}, "", credential.Secret, map[string]string{"If-Match": versionETag(currentSupportCase.Version)}, http.StatusOK, &currentSupportCase)
	if currentSupportCase.RetentionUntil == nil || currentSupportCase.Status != "closed" {
		t.Fatalf("closed Support Case omitted retention state: %+v", currentSupportCase)
	}
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/support/cases/"+supportCase.UID+"/messages", map[string]any{"body": "closed write"}, "", credential.Secret, map[string]string{"Idempotency-Key": "support_message_closed"}, http.StatusConflict, nil)
	requestJSONWithHeaders(t, client, "PATCH", ts.URL+"/v1/support/cases/"+supportCase.UID, map[string]any{"status": "open"}, "", credential.Secret, map[string]string{"If-Match": versionETag(currentSupportCase.Version)}, http.StatusOK, &currentSupportCase)
	if currentSupportCase.RetentionUntil != nil || currentSupportCase.ClosedAt != nil || currentSupportCase.Status != "open" {
		t.Fatalf("reopened Support Case retained terminal state: %+v", currentSupportCase)
	}
	var customerEvents struct {
		Items []SupportCaseEvent `json:"items"`
	}
	requestJSON(t, client, "GET", ts.URL+"/v1/support/cases/"+supportCase.UID+"/events?limit=100", nil, "", credential.Secret, http.StatusOK, &customerEvents)
	for _, event := range customerEvents.Items {
		if event.Visibility != "public" {
			t.Fatalf("service credential saw internal Support Case event: %+v", event)
		}
	}
	jobStore := store.NewBackgroundJobStore(pool)
	if _, err = pool.Exec(ctx, `UPDATE background_jobs SET available_at=clock_timestamp() WHERE deduplication_key=$1`, "support-case:"+supportCase.UID); err != nil {
		t.Fatal(err)
	}
	stalePurge, err := jobStore.Claim(ctx, "retention", time.Minute)
	if err != nil || stalePurge == nil {
		t.Fatalf("claim reopened Support Case purge=%+v err=%v", stalePurge, err)
	}
	result, err := apiServer.handleBackgroundJob(ctx, *stalePurge)
	if err != nil || result.rescheduleAt != nil {
		t.Fatalf("handle reopened Support Case purge result=%+v err=%v", result, err)
	}
	if err = jobStore.Complete(ctx, *stalePurge); err != nil {
		t.Fatal(err)
	}
	var retainedCases int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM support_cases WHERE uid=$1`, supportCase.UID).Scan(&retainedCases); err != nil || retainedCases != 1 {
		t.Fatalf("reopened Support Case count=%d err=%v", retainedCases, err)
	}

	requestJSONWithHeaders(t, client, "PATCH", ts.URL+"/v1/support/cases/"+supportCase.UID, map[string]any{"status": "closed"}, "", credential.Secret, map[string]string{"If-Match": versionETag(currentSupportCase.Version)}, http.StatusOK, &currentSupportCase)
	if _, err = pool.Exec(ctx, `UPDATE support_cases SET retention_until=clock_timestamp()-interval '1 second' WHERE uid=$1`, supportCase.UID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE background_jobs SET available_at=clock_timestamp()-interval '1 second' WHERE deduplication_key=$1`, "support-case:"+supportCase.UID); err != nil {
		t.Fatal(err)
	}
	duePurge, err := jobStore.Claim(ctx, "retention", time.Minute)
	if err != nil || duePurge == nil {
		t.Fatalf("claim due Support Case purge=%+v err=%v", duePurge, err)
	}
	result, err = apiServer.handleBackgroundJob(ctx, *duePurge)
	if err != nil || result.rescheduleAt != nil {
		t.Fatalf("handle due Support Case purge result=%+v err=%v", result, err)
	}
	if err = jobStore.Complete(ctx, *duePurge); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM support_cases WHERE uid=$1`, supportCase.UID).Scan(&retainedCases); err != nil || retainedCases != 0 {
		t.Fatalf("purged Support Case count=%d err=%v", retainedCases, err)
	}
	var purgeAuditEvents int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='support_case.purged' AND target_uid=$1 AND actor_type='system'`, supportCase.UID).Scan(&purgeAuditEvents); err != nil || purgeAuditEvents != 1 {
		t.Fatalf("Support Case purge audit count=%d err=%v", purgeAuditEvents, err)
	}
	runtimeSession := struct {
		SessionReference string      `json:"session_reference"`
		ProjectUser      ProjectUser `json:"project_user"`
	}{ProjectUser: user}
	runtimeSession.SessionReference, err = security.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	expires, idle := time.Now().Add(cfg.UserAbsoluteTTL), time.Now().Add(cfg.UserIdleTTL)
	if _, err = pool.Exec(ctx, `INSERT INTO project_user_sessions(uid,project_uid,project_user_uid,session_secret_hash,expires_at,idle_expires_at) VALUES($1,$2,$3,$4,$5,$6)`, uuid.NewString(), project.UID, user.UID, security.SessionHash(runtimeSession.SessionReference), expires, idle); err != nil {
		t.Fatal(err)
	}
	var loginAttempt struct {
		LoginReference string    `json:"login_reference"`
		ExpiresAt      time.Time `json:"expires_at"`
	}
	requestJSON(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/runtime/login/start", map[string]any{"email": "user@example.com"}, "", credential.Secret, http.StatusCreated, &loginAttempt)
	if loginAttempt.LoginReference == "" {
		t.Fatal("browser login attempt was not issued")
	}
	requestWithLogin(t, client, ts.URL+"/v1/projects/"+project.UID+"/runtime/login/fido/options", credential.Secret, loginAttempt.LoginReference, map[string]any{"mode": "passkey"}, http.StatusUnauthorized, nil)
	var factor struct {
		Status string `json:"status"`
		Factor string `json:"factor"`
	}
	requestWithLogin(t, client, ts.URL+"/v1/projects/"+project.UID+"/runtime/login/password", credential.Secret, loginAttempt.LoginReference, map[string]any{"password": "another correct battery staple"}, http.StatusOK, &factor)
	if factor.Status != "factor_verified" || factor.Factor != "password" {
		t.Fatalf("unexpected factor response: %+v", factor)
	}
	var loginOptions struct {
		CeremonyUID string         `json:"ceremony_uid"`
		PublicKey   map[string]any `json:"public_key"`
	}
	requestWithLogin(t, client, ts.URL+"/v1/projects/"+project.UID+"/runtime/login/fido/options", credential.Secret, loginAttempt.LoginReference, map[string]any{"mode": "passkey"}, http.StatusOK, &loginOptions)
	if loginOptions.CeremonyUID == "" || loginOptions.PublicKey["challenge"] == nil {
		t.Fatal("login WebAuthn options were not generated")
	}
	var introspection struct {
		Active      bool        `json:"active"`
		ProjectUser ProjectUser `json:"project_user"`
	}
	requestJSON(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/runtime/sessions/introspect", map[string]any{"session_reference": runtimeSession.SessionReference}, "", credential.Secret, http.StatusOK, &introspection)
	if !introspection.Active || introspection.ProjectUser.UID != user.UID {
		t.Fatal("session introspection failed")
	}

	var options struct {
		CeremonyUID string         `json:"ceremony_uid"`
		PublicKey   map[string]any `json:"public_key"`
	}
	requestWithSession(t, client, ts.URL+"/v1/projects/"+project.UID+"/runtime/fido/registration/options", credential.Secret, runtimeSession.SessionReference, map[string]any{"mode": "passkey"}, http.StatusOK, &options)
	if options.CeremonyUID == "" || options.PublicKey["challenge"] == nil {
		t.Fatal("WebAuthn registration options were not generated")
	}
	requestJSON(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/users/"+user.UID+"/sessions/revoke", nil, "", credential.Secret, http.StatusNoContent, nil)
	requestJSON(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/runtime/sessions/introspect", map[string]any{"session_reference": runtimeSession.SessionReference}, "", credential.Secret, http.StatusUnauthorized, nil)

	requestJSON(t, client, "PATCH", ts.URL+"/v1/projects/"+project.UID, map[string]any{"name": "CSRF attempt"}, "", "", http.StatusForbidden, nil)
	requestJSON(t, client, "DELETE", ts.URL+"/v1/projects/"+project.UID+"/origins/"+project.Origins[0].UID, nil, "http://console.test", "", http.StatusConflict, nil)
	var replacement ServiceCredential
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/service-accounts/"+serviceAccount.UID+"/credentials", map[string]any{"name": "Replacement deployment"}, "http://console.test", "", map[string]string{"Idempotency-Key": "service_credential_replacement"}, http.StatusCreated, &replacement)
	requestJSONWithHeaders(t, client, "POST", ts.URL+"/v1/projects/"+project.UID+"/service-accounts/"+serviceAccount.UID+"/credentials", map[string]any{"name": "Too many"}, "http://console.test", "", map[string]string{"Idempotency-Key": "service_credential_limit"}, http.StatusConflict, nil)
	requestJSON(t, client, "DELETE", ts.URL+"/v1/projects/"+project.UID+"/service-accounts/"+serviceAccount.UID+"/credentials/"+credential.UID, nil, "http://console.test", "", http.StatusNoContent, nil)
	requestJSON(t, client, "DELETE", ts.URL+"/v1/projects/"+project.UID+"/service-accounts/"+serviceAccount.UID+"/credentials/"+credential.UID, nil, "http://console.test", "", http.StatusNoContent, nil)
	requestJSON(t, client, "GET", ts.URL+"/v1/projects/"+project.UID+"/users", nil, "", credential.Secret, http.StatusUnauthorized, nil)
	requestJSON(t, client, "GET", ts.URL+"/v1/projects/"+project.UID+"/users", nil, "", replacement.Secret, http.StatusOK, &struct {
		Items []ProjectUser `json:"items"`
	}{})
	var restrictedAccount ServiceAccount
	requestJSONWithHeaders(t, client, "PATCH", ts.URL+"/v1/projects/"+project.UID+"/service-accounts/"+serviceAccount.UID, map[string]any{"scopes": []string{serviceScopeProjectUsersRead}}, "http://console.test", "", map[string]string{"If-Match": `"1"`}, http.StatusOK, &restrictedAccount)
	requestJSON(t, client, "PATCH", ts.URL+"/v1/projects/"+project.UID+"/users/"+user.UID, map[string]any{"email_verified": true}, "", replacement.Secret, http.StatusForbidden, nil)
	requestJSONWithHeaders(t, client, "PATCH", ts.URL+"/v1/projects/"+project.UID+"/service-accounts/"+serviceAccount.UID, map[string]any{"status": "disabled"}, "http://console.test", "", map[string]string{"If-Match": `"2"`}, http.StatusOK, &ServiceAccount{})
	requestJSON(t, client, "GET", ts.URL+"/v1/projects/"+project.UID+"/users", nil, "", replacement.Secret, http.StatusUnauthorized, nil)

	var second Project
	requestJSON(t, client, "POST", ts.URL+"/v1/projects", map[string]any{"name": "Second App", "environment": "sandbox", "rp_id": "localhost", "rp_name": "Second", "initial_origin": "http://localhost:4000"}, "http://console.test", "", http.StatusCreated, &second)
	requestJSON(t, client, "POST", ts.URL+"/v1/projects/"+second.UID+"/users", map[string]any{"email": "user@example.com"}, "http://console.test", "", http.StatusCreated, &ProjectUser{})
	requestJSON(t, client, "GET", ts.URL+"/v1/projects/"+second.UID+"/users", nil, "", credential.Secret, http.StatusUnauthorized, nil)

	if _, err = pool.Exec(ctx, `
		INSERT INTO idempotency_records(
			principal_type,principal_uid,operation,idempotency_key,request_hash,
			state,lease_uid,lease_expires_at,created_at,expires_at
		) VALUES('test','maintenance','cleanup','expired',$1,'processing',$2,
			clock_timestamp()-interval '2 hours',clock_timestamp()-interval '2 hours',
			clock_timestamp()-interval '1 hour')
	`, bytes.Repeat([]byte{9}, 32), uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `
		INSERT INTO rate_limit_buckets(policy,key_hash,request_count,window_started_at,expires_at)
		VALUES('maintenance_test',$1,1,clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour')
	`, bytes.Repeat([]byte{6}, 32)); err != nil {
		t.Fatal(err)
	}
	maintenanceJob, err := jobStore.Claim(ctx, "maintenance", time.Minute)
	if err != nil || maintenanceJob == nil || maintenanceJob.Type != "maintenance.cleanup" {
		t.Fatalf("claim maintenance job=%+v err=%v", maintenanceJob, err)
	}
	result, err = apiServer.handleBackgroundJob(ctx, *maintenanceJob)
	if err != nil || result.rescheduleAt == nil || !result.rescheduleAt.After(time.Now()) {
		t.Fatalf("handle maintenance job result=%+v err=%v", result, err)
	}
	if err = jobStore.Reschedule(ctx, *maintenanceJob, *result.rescheduleAt); err != nil {
		t.Fatal(err)
	}
	var expiredOperationalRows int
	if err = pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM idempotency_records WHERE principal_uid='maintenance')+
			(SELECT count(*) FROM rate_limit_buckets WHERE policy='maintenance_test')
	`).Scan(&expiredOperationalRows); err != nil || expiredOperationalRows != 0 {
		t.Fatalf("expired operational rows=%d err=%v", expiredOperationalRows, err)
	}
	var maintenanceStatus string
	var maintenanceAttempts int
	if err = pool.QueryRow(ctx, `SELECT status,attempts FROM background_jobs WHERE uid=$1`, maintenanceJob.UID).Scan(&maintenanceStatus, &maintenanceAttempts); err != nil || maintenanceStatus != "pending" || maintenanceAttempts != 0 {
		t.Fatalf("maintenance status=%q attempts=%d err=%v", maintenanceStatus, maintenanceAttempts, err)
	}
}

func requestJSON(t *testing.T, client *http.Client, method, target string, body any, origin, bearer string, status int, output any) {
	t.Helper()
	requestJSONWithHeaders(t, client, method, target, body, origin, bearer, nil, status, output)
}

type recordingEmailSender struct {
	messages []emailMessage
}

func (s *recordingEmailSender) Send(_ context.Context, message emailMessage) error {
	s.messages = append(s.messages, message)
	return nil
}

func processNextEmailJob(t *testing.T, ctx context.Context, server *Server, pool *pgxpool.Pool) emailMessage {
	t.Helper()
	jobStore := store.NewBackgroundJobStore(pool)
	job, err := jobStore.Claim(ctx, "email", time.Minute)
	if err != nil || job == nil {
		t.Fatalf("claim email delivery=%+v err=%v", job, err)
	}
	before := len(server.email.(*recordingEmailSender).messages)
	result, err := server.handleBackgroundJob(ctx, *job)
	if err != nil || result.rescheduleAt != nil {
		t.Fatalf("handle email delivery result=%+v err=%v", result, err)
	}
	if err = jobStore.Complete(ctx, *job); err != nil {
		t.Fatal(err)
	}
	messages := server.email.(*recordingEmailSender).messages
	if len(messages) != before+1 {
		t.Fatalf("email deliveries=%d want=%d", len(messages), before+1)
	}
	return messages[len(messages)-1]
}

func tokenFromEmail(t *testing.T, message emailMessage, expectedPath string) string {
	t.Helper()
	for _, line := range strings.Split(message.Text, "\n") {
		line = strings.TrimSpace(line)
		parsed, err := url.Parse(line)
		if err != nil || parsed.Path == "" || !strings.HasPrefix(parsed.Path, expectedPath) {
			continue
		}
		fragment, _ := url.ParseQuery(parsed.Fragment)
		if token := fragment.Get("token"); token != "" {
			return token
		}
	}
	t.Fatalf("email did not contain %s token: %+v", expectedPath, message)
	return ""
}

func requestJSONWithHeaders(t *testing.T, client *http.Client, method, target string, body any, origin, bearer string, headers map[string]string, status int, output any) {
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
	for name, value := range headers {
		request.Header.Set(name, value)
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

func requestSupportAttachment(t *testing.T, client *http.Client, target, bearer, idempotencyKey, filename, mediaType string, content []byte, uploaderProjectUserUID string, status int, output any) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", mime.FormatMediaType("form-data", map[string]string{"name": "file", "filename": filename}))
	header.Set("Content-Type", mediaType)
	part, err := writer.CreatePart(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = part.Write(content); err != nil {
		t.Fatal(err)
	}
	if uploaderProjectUserUID != "" {
		if err = writer.WriteField("uploader_project_user_uid", uploaderProjectUserUID); err != nil {
			t.Fatal(err)
		}
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, target, &body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Idempotency-Key", idempotencyKey)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		var problem any
		_ = json.NewDecoder(response.Body).Decode(&problem)
		t.Fatalf("POST %s status=%d want=%d body=%v", target, response.StatusCode, status, problem)
	}
	if output != nil {
		if err = json.NewDecoder(response.Body).Decode(output); err != nil {
			t.Fatal(err)
		}
	}
}

func requestOAuthForm(t *testing.T, client *http.Client, target string, form url.Values, clientID, clientSecret string, status int, output any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" || clientSecret != "" {
		request.SetBasicAuth(clientID, clientSecret)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		var problem any
		_ = json.NewDecoder(response.Body).Decode(&problem)
		t.Fatalf("POST %s status=%d want=%d body=%v", target, response.StatusCode, status, problem)
	}
	if output != nil {
		if err = json.NewDecoder(response.Body).Decode(output); err != nil {
			t.Fatal(err)
		}
	}
}

func verifyIDToken(t *testing.T, client *http.Client, serverURL, token, audience, nonce string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("ID token has %d segments", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
	}
	if err = json.Unmarshal(headerJSON, &header); err != nil || header.Alg != "RS256" || header.KID == "" {
		t.Fatalf("unexpected ID token header: %+v err=%v", header, err)
	}
	response, err := client.Get(serverURL + "/oauth/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var document struct {
		Keys []oauthJWK `json:"keys"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&document) != nil {
		t.Fatalf("could not load JWKS: status=%d", response.StatusCode)
	}
	var matching *oauthJWK
	for i := range document.Keys {
		if document.Keys[i].KID == header.KID {
			matching = &document.Keys[i]
			break
		}
	}
	if matching == nil {
		t.Fatalf("JWKS did not contain kid %q", header.KID)
	}
	publicKey, err := decodeRSAJWK(*matching)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("verify ID token signature: %v", err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err = json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["aud"] != audience || claims["nonce"] != nonce || claims["sub"] == "" {
		t.Fatalf("unexpected ID token claims: %+v", claims)
	}
}

func requestWithSession(t *testing.T, client *http.Client, target, key, session string, body any, status int, output any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	request, _ := http.NewRequest("POST", target, bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("X-ComplicatedAuth-Session", session)
	request.Header.Set("Content-Type", "application/json")
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

func requestWithLogin(t *testing.T, client *http.Client, target, key, login string, body any, status int, output any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	request, _ := http.NewRequest("POST", target, bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("X-ComplicatedAuth-Login", login)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		var problem any
		_ = json.NewDecoder(response.Body).Decode(&problem)
		t.Fatalf("status=%d want=%d body=%v", response.StatusCode, status, problem)
	}
	if output != nil {
		if err = json.NewDecoder(response.Body).Decode(output); err != nil {
			t.Fatal(err)
		}
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
