package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/complicatedauth/complicatedauth-backend/internal/contract"
	"github.com/complicatedauth/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	accessEvaluationKeyPattern = regexp.MustCompile(`^aeval_[a-f0-9]{32}$`)
	externalRequestIDPattern   = regexp.MustCompile(`^req_[a-f0-9]{32}$`)
)

func (s *Server) createAccessEvaluation(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if !decode(w, r, &in) {
		return
	}
	if in == nil || len(in) != 0 {
		fail(w, r, http.StatusBadRequest, "invalid_access_evaluation", "request body must be an empty JSON object")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if !accessEvaluationKeyPattern.MatchString(key) {
		fail(w, r, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key must match the delegated access-evaluation format")
		return
	}
	if !externalRequestIDPattern.MatchString(r.Header.Get("X-External-Request-ID")) {
		fail(w, r, http.StatusBadRequest, "invalid_request_id", "X-External-Request-ID is invalid")
		return
	}

	p := mustOAuthResourcePrincipal(r)
	grants, err := s.currentOAuthCapabilities(r.Context(), p)
	if err != nil {
		fail(w, r, http.StatusServiceUnavailable, "authorization_unavailable", "access evaluation is temporarily unavailable")
		return
	}

	canonical, _ := json.Marshal(map[string]any{
		"tenant_uid": p.TenantUID, "member_uid": p.MemberUID, "subject": p.Subject,
		"application_uid": p.ApplicationUID, "resource_server_uid": p.ResourceServerUID,
		"resource_server_identifier": p.ResourceServerIdentifier, "grants": grants,
		"policy_version": p.PolicyVersion, "expires_at": p.ExpiresAt.UTC(),
	})
	idem := store.IdempotencyRequest{
		PrincipalType: "oauth_subject", PrincipalUID: p.ApplicationUID + ":" + p.Subject,
		Operation: "access_evaluations.create", Key: key,
		RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 15 * time.Minute,
	}
	claim, ok := s.beginIdempotentRequest(w, r, idem)
	if !ok {
		return
	}
	policyVersion := fmt.Sprintf("scope-v1:%d", p.PolicyVersion)
	response := storedJSONResponse(http.StatusOK, contract.AccessEvaluation{
		Id: key, Grants: grants, ExpiresAt: p.ExpiresAt.UTC(), PolicyVersion: &policyVersion,
	})
	response.Headers["Cache-Control"] = []string{"private, no-store"}
	if err = s.idempotency.Complete(r.Context(), idem, claim.LeaseUID, response); err != nil {
		s.log.Error("access evaluation completion failed", "error", err)
		fail(w, r, http.StatusServiceUnavailable, "authorization_unavailable", "access evaluation is temporarily unavailable")
		return
	}
	writeStoredResponse(w, response)
}

func (s *Server) createSupportSubmission(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil || actor.Operator || actor.ProjectUID == "" {
		fail(w, r, http.StatusUnauthorized, "invalid_service_credential", "valid Project service credential required")
		return
	}
	var in contract.SupportSubmissionRequest
	if !decode(w, r, &in) {
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 16 || len(key) > 200 || key != in.SubmissionId {
		fail(w, r, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key must equal submission_id and contain between 16 and 200 characters")
		return
	}
	if !externalRequestIDPattern.MatchString(r.Header.Get("X-External-Request-ID")) {
		fail(w, r, http.StatusBadRequest, "invalid_request_id", "X-External-Request-ID is invalid")
		return
	}
	if err = s.validateSupportSubmission(in, actor); err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
		return
	}
	canonical, err := json.Marshal(in)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_json", "support submission could not be encoded")
		return
	}
	idem := store.IdempotencyRequest{
		PrincipalType: actor.Type, PrincipalUID: actor.UID, Operation: "support_submissions.create", Key: key,
		RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour,
	}
	claim, ok := s.beginIdempotentRequest(w, r, idem)
	if !ok {
		return
	}

	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not accept support submission")
		return
	}
	defer tx.Rollback(r.Context())
	var projectStatus string
	if err = tx.QueryRow(r.Context(), `SELECT status FROM projects WHERE uid=$1 AND tenant_uid=$2 FOR UPDATE`, actor.ProjectUID, actor.TenantUID).Scan(&projectStatus); errors.Is(err, pgx.ErrNoRows) {
		s.completeSupportProblem(w, r, tx, idem, claim, http.StatusNotFound, "project_not_found", "Project was not found")
		return
	} else if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not accept support submission")
		return
	}
	if projectStatus != "active" {
		s.completeSupportProblem(w, r, tx, idem, claim, http.StatusConflict, "project_disabled", "enable the Project before accepting support submissions")
		return
	}
	var activeCount int
	if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM support_cases WHERE tenant_uid=$1 AND status<>'closed'`, actor.TenantUID).Scan(&activeCount); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not accept support submission")
		return
	}
	if activeCount >= supportCaseActiveLimit {
		s.completeSupportProblem(w, r, tx, idem, claim, http.StatusConflict, "support_case_limit", "resolve or close existing Support Cases before accepting another")
		return
	}

	now := time.Now().UTC()
	caseUID, messageUID, attachmentUID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	reference := "SC-" + strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))[:12]
	category := string(in.Submission.Kind)
	subjectText, bodyText, priority := externalSupportPresentation(in.Submission)
	subject, err := s.sealSupport([]byte(subjectText), "case-subject", actor.TenantUID, caseUID, caseUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not encrypt support submission")
		return
	}
	body, err := s.sealSupport([]byte(bodyText), "message-body", actor.TenantUID, caseUID, messageUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not encrypt support submission")
		return
	}
	metadataRaw, _ := json.Marshal(map[string]string{"filename": "external-support-submission.json"})
	metadata, err := s.sealSupport(metadataRaw, "attachment-metadata", actor.TenantUID, caseUID, attachmentUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not encrypt support submission")
		return
	}
	content, err := s.sealSupport(canonical, "attachment-content", actor.TenantUID, caseUID, attachmentUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not encrypt support submission")
		return
	}
	digest := sha256.Sum256(canonical)

	_, err = tx.Exec(r.Context(), `INSERT INTO support_cases(uid,case_reference,tenant_uid,project_uid,category,priority,reporter_type,reporter_uid,subject_key_version,subject_nonce,subject_ciphertext,diagnostic_consent,attachment_count,attachment_bytes,created_at,updated_at,last_message_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,false,1,$12,$13,$13,$13)`, caseUID, reference, actor.TenantUID, actor.ProjectUID, category, priority, actor.Type, actor.UID, subject.KeyVersion, subject.Nonce, subject.Ciphertext, len(canonical), now)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO support_case_messages(uid,case_uid,author_type,author_uid,visibility,body_key_version,body_nonce,body_ciphertext,created_at) VALUES($1,$2,$3,$4,'public',$5,$6,$7,$8)`, messageUID, caseUID, actor.Type, actor.UID, body.KeyVersion, body.Nonce, body.Ciphertext, now)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO support_case_attachments(uid,case_uid,uploaded_by_type,uploaded_by_uid,media_type,byte_count,sha256,metadata_key_version,metadata_nonce,metadata_ciphertext,content_key_version,content_nonce,content_ciphertext,created_at) VALUES($1,$2,$3,$4,'application/json',$5,$6,$7,$8,$9,$10,$11,$12,$13)`, attachmentUID, caseUID, actor.Type, actor.UID, len(canonical), hex.EncodeToString(digest[:]), metadata.KeyVersion, metadata.Nonce, metadata.Ciphertext, content.KeyVersion, content.Nonce, content.Ciphertext, now)
	}
	if err == nil {
		err = insertSupportEvent(r.Context(), tx, caseUID, "support_case.created", actor, "public", map[string]any{"category": category, "priority": priority, "intake": "external_support_submission"})
	}
	if err == nil {
		err = insertSupportEvent(r.Context(), tx, caseUID, "support_case.message_created", actor, "public", map[string]any{"message_uid": messageUID})
	}
	if err == nil {
		err = insertSupportEvent(r.Context(), tx, caseUID, "support_case.attachment_created", actor, "internal", map[string]any{"attachment_uid": attachmentUID, "media_type": "application/json", "byte_count": len(canonical)})
	}
	if err == nil {
		err = insertSupportAudit(r.Context(), tx, actor, actor.ProjectUID, "support_case.created", "support_case", caseUID, map[string]any{"reference": reference, "category": category, "intake": "external_support_submission"})
	}
	externalID := reference
	response := storedJSONResponse(http.StatusAccepted, contract.SupportSubmissionReceipt{Id: caseUID, Status: "accepted", ExternalId: &externalID})
	if err != nil || s.idempotency.CompleteTx(r.Context(), tx, idem, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		if err != nil {
			s.log.Error("support submission creation failed", "error", err)
		}
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not accept support submission")
		return
	}
	writeStoredResponse(w, response)
}

func (s *Server) validateSupportSubmission(in contract.SupportSubmissionRequest, actor supportActor) error {
	if in.SubmissionId == "" || len(in.SubmissionId) > 200 || strings.TrimSpace(in.SubmissionId) != in.SubmissionId {
		return errors.New("submission_id is invalid")
	}
	now := time.Now().UTC()
	if in.CreatedAt.IsZero() || in.CreatedAt.After(now.Add(5*time.Minute)) || in.Submission.ConfirmedAt.IsZero() || in.Submission.ConfirmedAt.After(now.Add(5*time.Minute)) {
		return errors.New("created_at and confirmed_at must be valid timestamps that are not in the future")
	}
	if string(in.Submission.SchemaVersion) != "2026-08-20" || string(in.Submission.Source) != "private_mcp" {
		return errors.New("schema_version or source is unsupported")
	}
	if strings.TrimSpace(in.Submission.RequestId) == "" {
		return errors.New("request_id is required")
	}
	reporter := in.Submission.Reporter
	issuer := strings.TrimSpace(reporter.Principal.Issuer)
	parsedIssuer, err := url.Parse(issuer)
	if err != nil || parsedIssuer.Scheme == "" || parsedIssuer.Host == "" || parsedIssuer.User != nil || parsedIssuer.RawQuery != "" || parsedIssuer.Fragment != "" || strings.TrimRight(issuer, "/") != s.cfg.OAuthIssuer {
		return errors.New("reporter principal issuer must match this ComplicatedAuth deployment")
	}
	if strings.TrimSpace(reporter.Principal.Subject) == "" {
		return errors.New("reporter principal subject is required")
	}
	if reporter.ExternalCustomerId != nil && *reporter.ExternalCustomerId != actor.TenantUID {
		return errors.New("external_customer_id must match the service credential Tenant")
	}
	if reporter.DisplayName != nil && len(*reporter.DisplayName) > 200 {
		return errors.New("reporter display_name is too long")
	}
	if reporter.Email != nil {
		email := string(*reporter.Email)
		parsed, parseErr := mail.ParseAddress(email)
		if parseErr != nil || parsed.Address != email || len(email) > 320 {
			return errors.New("reporter email is invalid")
		}
	}
	if !reporter.AllowContact && (nonEmptyStringPointer(reporter.DisplayName) || reporter.Email != nil) {
		return errors.New("contact fields require explicit allow_contact consent")
	}
	if strings.TrimSpace(in.Submission.Product.ProductId) == "" || strings.TrimSpace(in.Submission.Product.ProductName) == "" {
		return errors.New("product_id and product_name are required")
	}
	if in.Submission.Integration != nil {
		integration := in.Submission.Integration
		if strings.TrimSpace(integration.IntegrationId) == "" || strings.TrimSpace(integration.FamilyKey) == "" || strings.TrimSpace(integration.VersionKey) == "" || strings.TrimSpace(integration.DisplayName) == "" || strings.TrimSpace(integration.Lifecycle) == "" || integration.Revision < 1 {
			return errors.New("integration context is incomplete")
		}
	}
	switch string(in.Submission.Kind) {
	case "bug":
		if in.Submission.Bug == nil || in.Submission.Feedback != nil {
			return errors.New("kind bug requires bug and forbids feedback")
		}
		return validateExternalBug(*in.Submission.Bug)
	case "feedback":
		if in.Submission.Feedback == nil || in.Submission.Bug != nil {
			return errors.New("kind feedback requires feedback and forbids bug")
		}
		return validateExternalFeedback(*in.Submission.Feedback)
	default:
		return errors.New("kind must be bug or feedback")
	}
}

func validateExternalBug(bug contract.ExternalBugReport) error {
	if strings.TrimSpace(bug.Summary) == "" || len(bug.Summary) > 160 || strings.TrimSpace(bug.Description) == "" || len(bug.Description) > 10000 {
		return errors.New("bug summary or description is invalid")
	}
	if bug.ReproductionSteps != nil {
		if len(*bug.ReproductionSteps) > 20 {
			return errors.New("bug reproduction_steps has too many items")
		}
		for _, step := range *bug.ReproductionSteps {
			if strings.TrimSpace(step) == "" || len(step) > 1000 {
				return errors.New("bug reproduction step is invalid")
			}
		}
	}
	if exceedsStringPointer(bug.ExpectedBehavior, 4000) || exceedsStringPointer(bug.ActualBehavior, 4000) || exceedsStringPointer(bug.ErrorCode, 120) || exceedsStringPointer(bug.ErrorMessage, 8000) || exceedsStringPointer(bug.StackTrace, 16000) || exceedsStringPointer(bug.DiagnosticContext, 20000) || exceedsStringPointer(bug.RelatedTool, 160) || exceedsStringPointer(bug.IntegrationRunId, 160) {
		return errors.New("bug field exceeds its documented maximum length")
	}
	if bug.Severity != nil {
		valid := map[string]bool{"unknown": true, "low": true, "medium": true, "high": true, "critical": true}
		if !valid[string(*bug.Severity)] {
			return errors.New("bug severity is invalid")
		}
	}
	return nil
}

func validateExternalFeedback(feedback contract.ExternalFeedbackReport) error {
	if strings.TrimSpace(feedback.Message) == "" || len(feedback.Message) > 10000 || exceedsStringPointer(feedback.RelatedTool, 160) || exceedsStringPointer(feedback.IntegrationRunId, 160) {
		return errors.New("feedback field is invalid")
	}
	if feedback.Rating != nil && (*feedback.Rating < 1 || *feedback.Rating > 5) {
		return errors.New("feedback rating must be between 1 and 5")
	}
	if feedback.Category != nil {
		valid := map[string]bool{"general": true, "usability": true, "documentation": true, "performance": true, "feature_request": true, "other": true}
		if !valid[string(*feedback.Category)] {
			return errors.New("feedback category is invalid")
		}
	}
	return nil
}

func externalSupportPresentation(submission contract.ExternalSupportSubmission) (string, string, string) {
	priority := "normal"
	if submission.Bug != nil {
		subject := submission.Bug.Summary
		body := submission.Bug.Description
		if submission.Bug.Severity != nil {
			switch string(*submission.Bug.Severity) {
			case "critical":
				priority = "urgent"
			case "high":
				priority = "high"
			case "low":
				priority = "low"
			}
		}
		return subject, externalSupportMessage(body, submission), priority
	}
	subject := truncateUTF8("Feedback about "+submission.Product.ProductName, 200)
	return subject, externalSupportMessage(submission.Feedback.Message, submission), priority
}

func externalSupportMessage(body string, submission contract.ExternalSupportSubmission) string {
	contactAllowed := submission.Reporter.AllowContact
	if submission.Bug != nil && submission.Bug.AllowContact != nil {
		contactAllowed = contactAllowed && *submission.Bug.AllowContact
	}
	if submission.Feedback != nil && submission.Feedback.AllowContact != nil {
		contactAllowed = contactAllowed && *submission.Feedback.AllowContact
	}
	context := "\n\nExternal product: " + submission.Product.ProductName + " (" + submission.Product.ProductId + ")"
	if submission.Integration != nil {
		context += "\nIntegration: " + submission.Integration.DisplayName + " (" + submission.Integration.IntegrationId + ")"
	}
	if contactAllowed {
		if submission.Reporter.DisplayName != nil && *submission.Reporter.DisplayName != "" {
			context += "\nReporter: " + *submission.Reporter.DisplayName
		}
		if submission.Reporter.Email != nil {
			context += "\nContact: " + string(*submission.Reporter.Email)
		}
	}
	return truncateUTF8(body+context, 10000)
}

func nonEmptyStringPointer(value *string) bool {
	return value != nil && strings.TrimSpace(*value) != ""
}

func exceedsStringPointer(value *string, maximum int) bool {
	return value != nil && len(*value) > maximum
}

func truncateUTF8(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	value = value[:maximum]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
