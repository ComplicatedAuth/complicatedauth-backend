package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	security "github.com/complicatedauth/complicatedauth-backend/internal/auth"
	"github.com/complicatedauth/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const externalCredentialActiveLimit = 2

type externalCredentialAuthorizationInput struct {
	Operation          string         `json:"operation"`
	Subject            string         `json:"subject"`
	ExternalCustomerID string         `json:"external_customer_id"`
	InstallationID     string         `json:"installation_id"`
	DeploymentID       string         `json:"deployment_id"`
	Details            map[string]any `json:"details"`
}

type externalCredentialIssueInput struct {
	DeploymentID            string   `json:"deployment_id"`
	IntegrationID           string   `json:"integration_id"`
	EnvironmentID           string   `json:"environment_id"`
	AccessInstanceID        string   `json:"access_instance_id"`
	Subject                 string   `json:"subject"`
	Scopes                  []string `json:"scopes"`
	IdempotencyKey          string   `json:"idempotency_key"`
	TTLSeconds              int      `json:"ttl_seconds"`
	RotatedFromCredentialID string   `json:"rotated_from_credential_id,omitempty"`
}

type externalCredentialRevokeInput struct {
	DeploymentID string `json:"deployment_id"`
	Subject      string `json:"subject"`
}

func serviceCredentialContext(r *http.Request) (credentialUID, accountUID, projectUID, tenantUID string) {
	credentialUID, _ = r.Context().Value(contextKey("serviceCredentialUID")).(string)
	accountUID, _ = r.Context().Value(contextKey("serviceAccountUID")).(string)
	projectUID, _ = r.Context().Value(contextKey("serviceProjectUID")).(string)
	tenantUID, _ = r.Context().Value(contextKey("serviceTenantUID")).(string)
	return
}

func validExternalCredentialIdentifier(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 200 && utf8.ValidString(value)
}

// externalOAuthSubject accepts either this provider's raw pairwise OAuth subject
// or DokoSoko's issuer-qualified actor identifier. The latter prevents subject
// collisions when an external platform serves more than one identity provider.
func (s *Server) externalOAuthSubject(value string) (string, bool) {
	if !validExternalCredentialIdentifier(value) {
		return "", false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return value, true
	}
	issuer, issuerErr := base64.RawURLEncoding.DecodeString(parts[0])
	subject, subjectErr := base64.RawURLEncoding.DecodeString(parts[1])
	if issuerErr != nil || subjectErr != nil {
		return value, true
	}
	if string(issuer) != s.cfg.OAuthIssuer || !validExternalCredentialIdentifier(string(subject)) {
		return "", false
	}
	return string(subject), true
}

func (s *Server) externalOAuthSubjectActive(r *http.Request, tenantUID, subject string) bool {
	var active bool
	err := s.db.QueryRow(r.Context(), `SELECT EXISTS(
		SELECT 1 FROM oauth_subjects o
		JOIN tenant_members m ON m.uid=o.tenant_member_uid
		WHERE o.subject=$1 AND m.tenant_uid=$2 AND m.status='active'
	)`, subject, tenantUID).Scan(&active)
	return err == nil && active
}

func (s *Server) authorizeExternalCredentialOperation(w http.ResponseWriter, r *http.Request) {
	var in externalCredentialAuthorizationInput
	if !decode(w, r, &in) {
		return
	}
	_, _, _, tenantUID := serviceCredentialContext(r)
	subject, subjectOK := s.externalOAuthSubject(in.Subject)
	allowedOperation := in.Operation == "credentials.create" || in.Operation == "credentials.revoke"
	allowed := allowedOperation &&
		subjectOK &&
		validExternalCredentialIdentifier(in.DeploymentID) &&
		in.ExternalCustomerID == tenantUID &&
		s.externalOAuthSubjectActive(r, tenantUID, subject)
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, map[string]bool{"allowed": allowed})
}

func externalCredentialScopes(requested, accountScopes []string) ([]string, error) {
	available := make(map[string]bool, len(accountScopes))
	for _, scope := range accountScopes {
		if scope != serviceScopeExternalCredentialsManage {
			available[scope] = true
		}
	}
	if len(available) == 0 {
		return nil, errors.New("the management service account has no delegable API scopes")
	}
	if len(requested) == 0 {
		requested = make([]string, 0, len(available))
		for scope := range available {
			requested = append(requested, scope)
		}
	}
	seen := make(map[string]bool, len(requested))
	for _, scope := range requested {
		scope = strings.TrimSpace(scope)
		if !available[scope] {
			return nil, fmt.Errorf("scope %q is not delegable by this management connection", scope)
		}
		seen[scope] = true
	}
	result := make([]string, 0, len(seen))
	for scope := range seen {
		result = append(result, scope)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeExternalCredentialIssue(in *externalCredentialIssueInput) error {
	if !validExternalCredentialIdentifier(in.DeploymentID) ||
		!validExternalCredentialIdentifier(in.IntegrationID) ||
		!validExternalCredentialIdentifier(in.EnvironmentID) ||
		!validExternalCredentialIdentifier(in.Subject) ||
		len(in.IdempotencyKey) < 16 || len(in.IdempotencyKey) > 200 ||
		in.IdempotencyKey != strings.TrimSpace(in.IdempotencyKey) ||
		in.AccessInstanceID != "" || len(in.Scopes) > 20 ||
		(in.TTLSeconds != 0 && (in.TTLSeconds < 300 || in.TTLSeconds > int(serviceCredentialMaximumTTL/time.Second))) {
		return errors.New("the external credential request is invalid")
	}
	if in.RotatedFromCredentialID != "" {
		if _, err := uuid.Parse(in.RotatedFromCredentialID); err != nil {
			return errors.New("rotated_from_credential_id is invalid")
		}
	}
	return nil
}

func (s *Server) issueExternalCredential(w http.ResponseWriter, r *http.Request) {
	var in externalCredentialIssueInput
	if !decode(w, r, &in) {
		return
	}
	subject, subjectOK := s.externalOAuthSubject(in.Subject)
	if !subjectOK {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "the external credential request is invalid")
		return
	}
	in.Subject = subject
	if err := normalizeExternalCredentialIssue(&in); err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
		return
	}
	_, accountUID, projectUID, tenantUID := serviceCredentialContext(r)
	canonical, _ := json.Marshal(struct {
		AccountUID string                       `json:"service_account_uid"`
		Input      externalCredentialIssueInput `json:"input"`
	}{accountUID, in})
	idem := store.IdempotencyRequest{
		PrincipalType: "service_account", PrincipalUID: accountUID,
		Operation: "external_credentials.create", Key: in.IdempotencyKey,
		RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour,
	}
	claim, ok := s.beginIdempotentRequest(w, r, idem)
	if !ok {
		return
	}

	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not issue external credential")
		return
	}
	defer tx.Rollback(r.Context())
	var environment, accountStatus, projectStatus string
	var accountScopes []string
	err = tx.QueryRow(r.Context(), `SELECT p.environment,a.status,p.status,a.scopes
		FROM project_service_accounts a JOIN projects p ON p.uid=a.project_uid
		WHERE a.uid=$1 AND a.project_uid=$2 AND p.tenant_uid=$3 AND a.deleted_at IS NULL
		FOR UPDATE OF a`, accountUID, projectUID, tenantUID).Scan(&environment, &accountStatus, &projectStatus, &accountScopes)
	if errors.Is(err, pgx.ErrNoRows) {
		s.completeServiceAccountProblem(w, r, tx, idem, claim, http.StatusForbidden, "management_connection_disabled", "the management service account is not active")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not issue external credential")
		return
	}
	if accountStatus != "active" || projectStatus != "active" || !slices.Contains(accountScopes, serviceScopeExternalCredentialsManage) {
		s.completeServiceAccountProblem(w, r, tx, idem, claim, http.StatusForbidden, "management_connection_disabled", "the management service account is not active")
		return
	}
	var subjectActive bool
	err = tx.QueryRow(r.Context(), `SELECT EXISTS(
		SELECT 1 FROM oauth_subjects o JOIN tenant_members m ON m.uid=o.tenant_member_uid
		WHERE o.subject=$1 AND m.tenant_uid=$2 AND m.status='active'
	)`, in.Subject, tenantUID).Scan(&subjectActive)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not issue external credential")
		return
	}
	if !subjectActive {
		s.completeServiceAccountProblem(w, r, tx, idem, claim, http.StatusForbidden, "subject_not_authorized", "the external subject is not an active Tenant Member")
		return
	}
	effectiveScopes, err := externalCredentialScopes(in.Scopes, accountScopes)
	if err != nil {
		s.completeServiceAccountProblem(w, r, tx, idem, claim, http.StatusUnprocessableEntity, "scope_not_delegable", err.Error())
		return
	}
	if in.RotatedFromCredentialID != "" {
		var priorActive bool
		err = tx.QueryRow(r.Context(), `SELECT status='active' AND expires_at>now()
			FROM project_service_credentials
			WHERE uid=$1 AND service_account_uid=$2 AND external_subject=$3 AND external_integration_id=$4`,
			in.RotatedFromCredentialID, accountUID, in.Subject, in.IntegrationID).Scan(&priorActive)
		if errors.Is(err, pgx.ErrNoRows) || !priorActive {
			s.completeServiceAccountProblem(w, r, tx, idem, claim, http.StatusConflict, "rotation_source_invalid", "the credential selected for rotation is not active for this subject and API")
			return
		}
		if err != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not issue external credential")
			return
		}
	}
	var activeCount int
	err = tx.QueryRow(r.Context(), `SELECT count(*) FROM project_service_credentials
		WHERE service_account_uid=$1 AND external_subject=$2 AND external_integration_id=$3
		AND status='active' AND expires_at>now()`, accountUID, in.Subject, in.IntegrationID).Scan(&activeCount)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not issue external credential")
		return
	}
	if activeCount >= externalCredentialActiveLimit {
		s.completeServiceAccountProblem(w, r, tx, idem, claim, http.StatusConflict, "external_credential_limit", "revoke an active credential before issuing another")
		return
	}

	randomSecret, err := security.RandomToken()
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not issue external credential")
		return
	}
	now := time.Now().UTC()
	ttl := serviceCredentialDefaultTTL
	if in.TTLSeconds > 0 {
		ttl = time.Duration(in.TTLSeconds) * time.Second
	}
	expiresAt := now.Add(ttl)
	environmentToken := "test"
	if environment == "production" {
		environmentToken = "live"
	}
	prefix := "ca_xk_" + environmentToken + "_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	secretValue := prefix + "." + randomSecret
	digest := sha256.Sum256([]byte(secretValue))
	credentialUID := uuid.NewString()
	name := truncateUTF8("External platform "+in.IntegrationID, 100)
	_, err = tx.Exec(r.Context(), `INSERT INTO project_service_credentials(
		uid,service_account_uid,name,prefix,fingerprint,secret_hash,created_at,expires_at,
		effective_scopes,external_subject,external_integration_id
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, credentialUID, accountUID, name, prefix,
		"sha256:"+hex.EncodeToString(digest[:])[:24], security.SecretHash(s.cfg.SecretHashKey, secretValue), now, expiresAt,
		effectiveScopes, in.Subject, in.IntegrationID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(
			uid,tenant_uid,project_uid,actor_type,actor_uid,action,target_type,target_uid,metadata
		) VALUES($1,$2,$3,'service_account',$4,'external_credential.created','service_credential',$5,$6)`,
			uuid.NewString(), tenantUID, projectUID, accountUID, credentialUID,
			map[string]any{"external_integration_id": in.IntegrationID, "expires_at": expiresAt, "scopes": effectiveScopes, "rotated_from_credential_id": in.RotatedFromCredentialID})
	}
	body, _ := json.Marshal(map[string]any{"credential_id": credentialUID, "credential": secretValue, "expires_at": expiresAt})
	body = append(body, '\n')
	response := store.StoredHTTPResponse{
		Status: http.StatusCreated,
		Headers: map[string][]string{
			"Content-Type":  {"application/json"},
			"Cache-Control": {"no-store"},
			"Location":      {"/v1/external-platform/credentials/" + credentialUID},
		},
		Body: body,
	}
	if err != nil || s.idempotency.CompleteTx(r.Context(), tx, idem, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		if err != nil {
			s.log.Error("external credential issuance failed", "error", err)
		}
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not issue external credential")
		return
	}
	writeStoredResponse(w, response)
}

func (s *Server) revokeExternalCredential(w http.ResponseWriter, r *http.Request) {
	var in externalCredentialRevokeInput
	if !decode(w, r, &in) {
		return
	}
	subject, subjectOK := s.externalOAuthSubject(in.Subject)
	if !validExternalCredentialIdentifier(in.DeploymentID) || !subjectOK {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "the external credential revoke request is invalid")
		return
	}
	in.Subject = subject
	_, accountUID, projectUID, tenantUID := serviceCredentialContext(r)
	credentialUID := r.PathValue("credential_uid")
	if _, err := uuid.Parse(credentialUID); err != nil {
		fail(w, r, http.StatusNotFound, "external_credential_not_found", "External credential was not found")
		return
	}
	var changed bool
	err := s.db.QueryRow(r.Context(), `WITH target AS (
		SELECT c.uid,c.status FROM project_service_credentials c
		JOIN project_service_accounts a ON a.uid=c.service_account_uid
		JOIN projects p ON p.uid=a.project_uid
		WHERE c.uid=$1 AND c.service_account_uid=$2 AND c.external_subject=$3
		AND a.project_uid=$4 AND p.tenant_uid=$5
	)
	UPDATE project_service_credentials c
	SET status='revoked',revoked_at=COALESCE(c.revoked_at,now()),
		revocation_reason=COALESCE(c.revocation_reason,'external_platform_revoke')
	FROM target WHERE c.uid=target.uid RETURNING target.status='active'`,
		credentialUID, accountUID, in.Subject, projectUID, tenantUID).Scan(&changed)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "external_credential_not_found", "External credential was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not revoke external credential")
		return
	}
	if changed {
		s.audit(r.Context(), tenantUID, projectUID, "service_account", accountUID, "external_credential.revoked", "service_credential", credentialUID, nil, r)
	}
	w.WriteHeader(http.StatusNoContent)
}
