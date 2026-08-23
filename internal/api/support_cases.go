package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	security "github.com/complicatedauth/complicatedauth-backend/internal/auth"
	"github.com/complicatedauth/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	supportCaseActiveLimit = 10000
	supportCaseRetention   = 365 * 24 * time.Hour
	supportMessageLimit    = 500
)

var (
	validSupportCategories = map[string]bool{"bug": true, "feedback": true, "question": true}
	validSupportStatuses   = map[string]bool{"open": true, "in_progress": true, "waiting_for_customer": true, "resolved": true, "closed": true}
	validSupportPriorities = map[string]bool{"low": true, "normal": true, "high": true, "urgent": true}
)

type SupportReporter struct {
	Type string `json:"type"`
	UID  string `json:"uid"`
}

type SupportDiagnostics struct {
	ApplicationVersion string     `json:"application_version,omitempty"`
	Platform           string     `json:"platform,omitempty"`
	Locale             string     `json:"locale,omitempty"`
	Timezone           string     `json:"timezone,omitempty"`
	CurrentURL         string     `json:"current_url,omitempty"`
	RequestID          string     `json:"request_id,omitempty"`
	OccurredAt         *time.Time `json:"occurred_at,omitempty"`
}

type SupportCase struct {
	UID               string              `json:"uid"`
	Reference         string              `json:"reference"`
	TenantUID         string              `json:"tenant_uid"`
	ProjectUID        *string             `json:"project_uid"`
	Category          string              `json:"category"`
	Subject           string              `json:"subject"`
	Status            string              `json:"status"`
	Priority          string              `json:"priority"`
	Reporter          SupportReporter     `json:"reporter"`
	AssigneeMemberUID *string             `json:"assignee_member_uid"`
	DiagnosticConsent bool                `json:"diagnostic_consent"`
	Diagnostics       *SupportDiagnostics `json:"diagnostics,omitempty"`
	Version           int64               `json:"version"`
	MessageCount      int                 `json:"message_count"`
	AttachmentCount   int                 `json:"attachment_count"`
	AttachmentBytes   int64               `json:"attachment_bytes"`
	CreatedAt         time.Time           `json:"created_at"`
	UpdatedAt         time.Time           `json:"updated_at"`
	LastMessageAt     time.Time           `json:"last_message_at"`
	ResolvedAt        *time.Time          `json:"resolved_at"`
	ClosedAt          *time.Time          `json:"closed_at"`
	RetentionUntil    *time.Time          `json:"retention_until"`
}

type encryptedSupportValue struct {
	KeyVersion string
	Nonce      []byte
	Ciphertext []byte
}

type supportCaseRecord struct {
	Value       SupportCase
	Subject     encryptedSupportValue
	Diagnostics *encryptedSupportValue
}

type supportActor struct {
	Type       string
	UID        string
	TenantUID  string
	ProjectUID string
	Operator   bool
}

type createSupportCaseInput struct {
	ProjectUID             *string             `json:"project_uid,omitempty"`
	Category               string              `json:"category"`
	Subject                string              `json:"subject"`
	Message                string              `json:"message"`
	Priority               *string             `json:"priority,omitempty"`
	ReporterProjectUserUID *string             `json:"reporter_project_user_uid,omitempty"`
	DiagnosticConsent      bool                `json:"diagnostic_consent"`
	Diagnostics            *SupportDiagnostics `json:"diagnostics,omitempty"`
}

type optionalNullableString struct {
	Set   bool
	Value *string
}

func (v *optionalNullableString) UnmarshalJSON(raw []byte) error {
	v.Set = true
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		v.Value = nil
		return nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	v.Value = &value
	return nil
}

const supportCaseSelect = `SELECT c.uid,c.case_reference,c.tenant_uid,c.project_uid,c.category,c.status,c.priority,c.reporter_type,c.reporter_uid,c.assignee_member_uid,
	c.subject_key_version,c.subject_nonce,c.subject_ciphertext,c.diagnostic_consent,c.diagnostics_key_version,c.diagnostics_nonce,c.diagnostics_ciphertext,
	c.version,c.message_count,c.attachment_count,c.attachment_bytes,c.created_at,c.updated_at,c.last_message_at,c.resolved_at,c.closed_at,c.retention_until FROM support_cases c`

func (s *Server) supportActor(r *http.Request) (supportActor, error) {
	if projectUID := contextString(r, "serviceProjectUID"); projectUID != "" {
		tenantUID := contextString(r, "serviceTenantUID")
		if tenantUID == "" {
			var err error
			tenantUID, err = s.projectTenant(r.Context(), projectUID)
			if err != nil {
				return supportActor{}, err
			}
		}
		return supportActor{Type: "service_account", UID: contextString(r, "serviceAccountUID"), TenantUID: tenantUID, ProjectUID: projectUID}, nil
	}
	p, ok := r.Context().Value(principalKey).(principal)
	if !ok {
		return supportActor{}, errors.New("support actor is unavailable")
	}
	return supportActor{Type: "tenant_member", UID: p.MemberUID, TenantUID: p.TenantUID, Operator: true}, nil
}

func supportContext(kind, tenantUID, caseUID, childUID string) []byte {
	return []byte("complicatedauth:support:v1:" + kind + ":" + tenantUID + ":" + caseUID + ":" + childUID)
}

func (s *Server) sealSupport(raw []byte, kind, tenantUID, caseUID, childUID string) (encryptedSupportValue, error) {
	value, err := s.cfg.DataEncryptionKeys.Seal(raw, supportContext(kind, tenantUID, caseUID, childUID))
	return encryptedSupportValue{KeyVersion: value.KeyVersion, Nonce: value.Nonce, Ciphertext: value.Ciphertext}, err
}

func (s *Server) openSupport(value encryptedSupportValue, kind, tenantUID, caseUID, childUID string) ([]byte, error) {
	return s.cfg.DataEncryptionKeys.Open(security.EncryptedValue{KeyVersion: value.KeyVersion, Nonce: value.Nonce, Ciphertext: value.Ciphertext}, supportContext(kind, tenantUID, caseUID, childUID))
}

func scanSupportCaseRecord(row rowScanner) (supportCaseRecord, error) {
	var record supportCaseRecord
	var diagnosticVersion *string
	var diagnosticNonce, diagnosticCiphertext []byte
	err := row.Scan(
		&record.Value.UID, &record.Value.Reference, &record.Value.TenantUID, &record.Value.ProjectUID, &record.Value.Category, &record.Value.Status, &record.Value.Priority,
		&record.Value.Reporter.Type, &record.Value.Reporter.UID, &record.Value.AssigneeMemberUID,
		&record.Subject.KeyVersion, &record.Subject.Nonce, &record.Subject.Ciphertext, &record.Value.DiagnosticConsent,
		&diagnosticVersion, &diagnosticNonce, &diagnosticCiphertext,
		&record.Value.Version, &record.Value.MessageCount, &record.Value.AttachmentCount, &record.Value.AttachmentBytes,
		&record.Value.CreatedAt, &record.Value.UpdatedAt, &record.Value.LastMessageAt, &record.Value.ResolvedAt, &record.Value.ClosedAt, &record.Value.RetentionUntil,
	)
	if err == nil && diagnosticVersion != nil {
		record.Diagnostics = &encryptedSupportValue{KeyVersion: *diagnosticVersion, Nonce: diagnosticNonce, Ciphertext: diagnosticCiphertext}
	}
	return record, err
}

func (s *Server) exposeSupportCase(record supportCaseRecord) (SupportCase, error) {
	subject, err := s.openSupport(record.Subject, "case-subject", record.Value.TenantUID, record.Value.UID, record.Value.UID)
	if err != nil {
		return SupportCase{}, err
	}
	record.Value.Subject = string(subject)
	if record.Diagnostics != nil {
		raw, openErr := s.openSupport(*record.Diagnostics, "case-diagnostics", record.Value.TenantUID, record.Value.UID, record.Value.UID)
		if openErr != nil {
			return SupportCase{}, openErr
		}
		var diagnostics SupportDiagnostics
		if json.Unmarshal(raw, &diagnostics) != nil {
			return SupportCase{}, errors.New("support diagnostics are invalid")
		}
		record.Value.Diagnostics = &diagnostics
	}
	return record.Value, nil
}

func normalizeSupportDiagnostics(value *SupportDiagnostics) error {
	if value == nil {
		return nil
	}
	value.ApplicationVersion = strings.TrimSpace(value.ApplicationVersion)
	value.Platform = strings.TrimSpace(value.Platform)
	value.Locale = strings.TrimSpace(value.Locale)
	value.Timezone = strings.TrimSpace(value.Timezone)
	value.CurrentURL = strings.TrimSpace(value.CurrentURL)
	value.RequestID = strings.TrimSpace(value.RequestID)
	if len(value.ApplicationVersion) > 100 || len(value.Platform) > 100 || len(value.Locale) > 32 || len(value.Timezone) > 64 || len(value.RequestID) > 255 || len(value.CurrentURL) > 2048 {
		return errors.New("diagnostic field exceeds its documented maximum length")
	}
	if value.CurrentURL != "" {
		parsed, err := url.Parse(value.CurrentURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && parsed.Hostname() == "localhost")) {
			return errors.New("diagnostics.current_url must be HTTPS, or localhost HTTP, without credentials, query, or fragment")
		}
	}
	if value.OccurredAt != nil {
		normalized := value.OccurredAt.UTC()
		value.OccurredAt = &normalized
		if normalized.After(time.Now().UTC().Add(5 * time.Minute)) {
			return errors.New("diagnostics.occurred_at cannot be in the future")
		}
	}
	return nil
}

func normalizeCreateSupportCase(in *createSupportCaseInput, actor supportActor) error {
	in.Category = strings.TrimSpace(in.Category)
	in.Subject = strings.TrimSpace(in.Subject)
	in.Message = strings.TrimSpace(in.Message)
	if !validSupportCategories[in.Category] {
		return errors.New("category must be bug, feedback, or question")
	}
	if len(in.Subject) < 1 || len(in.Subject) > 200 {
		return errors.New("subject must contain between 1 and 200 characters")
	}
	if len(in.Message) < 1 || len(in.Message) > 10000 {
		return errors.New("message must contain between 1 and 10000 characters")
	}
	if in.ProjectUID != nil {
		value := strings.TrimSpace(*in.ProjectUID)
		if _, err := uuid.Parse(value); err != nil {
			return errors.New("project_uid must be a UUID")
		}
		in.ProjectUID = &value
	}
	if in.ReporterProjectUserUID != nil {
		value := strings.TrimSpace(*in.ReporterProjectUserUID)
		if _, err := uuid.Parse(value); err != nil {
			return errors.New("reporter_project_user_uid must be a UUID")
		}
		in.ReporterProjectUserUID = &value
	}
	if in.Priority != nil {
		value := strings.TrimSpace(*in.Priority)
		if !validSupportPriorities[value] {
			return errors.New("priority must be low, normal, high, or urgent")
		}
		if !actor.Operator {
			return errors.New("service credentials cannot set operator priority")
		}
		in.Priority = &value
	}
	if err := normalizeSupportDiagnostics(in.Diagnostics); err != nil {
		return err
	}
	if in.Diagnostics != nil && !in.DiagnosticConsent {
		return errors.New("diagnostic_consent must be true when diagnostics are supplied")
	}
	return nil
}

func (s *Server) listSupportCases(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	status, category := r.URL.Query().Get("status"), r.URL.Query().Get("category")
	if status != "" && !validSupportStatuses[status] {
		fail(w, r, http.StatusBadRequest, "invalid_filter", "status filter is invalid")
		return
	}
	if category != "" && !validSupportCategories[category] {
		fail(w, r, http.StatusBadRequest, "invalid_filter", "category filter is invalid")
		return
	}
	var projectFilter any
	if actor.ProjectUID != "" {
		projectFilter = actor.ProjectUID
	} else if value := r.URL.Query().Get("project_uid"); value != "" {
		if _, parseErr := uuid.Parse(value); parseErr != nil {
			fail(w, r, http.StatusBadRequest, "invalid_filter", "project_uid filter must be a UUID")
			return
		}
		if !s.ownsProject(r.Context(), actor.TenantUID, value) {
			fail(w, r, http.StatusNotFound, "project_not_found", "Project was not found")
			return
		}
		projectFilter = value
	}
	query := supportCaseSelect + ` WHERE c.tenant_uid=$1 AND ($2::uuid IS NULL OR c.project_uid=$2::uuid) AND ($3::text='' OR c.status=$3) AND ($4::text='' OR c.category=$4)`
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), query+` ORDER BY c.updated_at DESC,c.uid DESC LIMIT $5`, actor.TenantUID, projectFilter, status, category, limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), query+` AND (c.updated_at,c.uid)<($5,$6::uuid) ORDER BY c.updated_at DESC,c.uid DESC LIMIT $7`, actor.TenantUID, projectFilter, status, category, cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load support cases")
		return
	}
	defer rows.Close()
	items := make([]SupportCase, 0, limit)
	for rows.Next() {
		record, scanErr := scanSupportCaseRecord(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load support cases")
			return
		}
		item, exposeErr := s.exposeSupportCase(record)
		if exposeErr != nil {
			fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not decrypt support case")
			return
		}
		items = append(items, item)
	}
	var next *string
	if len(items) > limit {
		position := items[limit-1]
		items = items[:limit]
		value := nextCursor(position.UpdatedAt, position.UID)
		next = &value
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func (s *Server) loadSupportCase(ctx context.Context, actor supportActor, caseUID string) (supportCaseRecord, error) {
	if actor.ProjectUID != "" {
		return scanSupportCaseRecord(s.db.QueryRow(ctx, supportCaseSelect+` WHERE c.uid=$1 AND c.tenant_uid=$2 AND c.project_uid=$3`, caseUID, actor.TenantUID, actor.ProjectUID))
	}
	return scanSupportCaseRecord(s.db.QueryRow(ctx, supportCaseSelect+` WHERE c.uid=$1 AND c.tenant_uid=$2`, caseUID, actor.TenantUID))
}

func (s *Server) lockSupportCase(ctx context.Context, tx pgx.Tx, actor supportActor, caseUID string) (supportCaseRecord, error) {
	if actor.ProjectUID != "" {
		return scanSupportCaseRecord(tx.QueryRow(ctx, supportCaseSelect+` WHERE c.uid=$1 AND c.tenant_uid=$2 AND c.project_uid=$3 FOR UPDATE OF c`, caseUID, actor.TenantUID, actor.ProjectUID))
	}
	return scanSupportCaseRecord(tx.QueryRow(ctx, supportCaseSelect+` WHERE c.uid=$1 AND c.tenant_uid=$2 FOR UPDATE OF c`, caseUID, actor.TenantUID))
}

func (s *Server) getSupportCase(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	record, err := s.loadSupportCase(r.Context(), actor, r.PathValue("case_uid"))
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "support_case_not_found", "Support Case was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load support case")
		return
	}
	value, err := s.exposeSupportCase(record)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not decrypt support case")
		return
	}
	setVersionETag(w, value.Version)
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) createSupportCase(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	var in createSupportCaseInput
	if !decode(w, r, &in) {
		return
	}
	if err = normalizeCreateSupportCase(&in, actor); err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
		return
	}
	projectUID := actor.ProjectUID
	if actor.Operator && in.ProjectUID != nil {
		projectUID = *in.ProjectUID
	}
	if !actor.Operator && in.ProjectUID != nil && *in.ProjectUID != actor.ProjectUID {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "project_uid must match the service credential Project")
		return
	}
	if in.ReporterProjectUserUID != nil && projectUID == "" {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "reporter_project_user_uid requires project_uid")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		fail(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required")
		return
	}
	canonical, _ := json.Marshal(struct {
		TenantUID  string                 `json:"tenant_uid"`
		ProjectUID string                 `json:"project_uid,omitempty"`
		Input      createSupportCaseInput `json:"input"`
	}{actor.TenantUID, projectUID, in})
	idem := store.IdempotencyRequest{PrincipalType: actor.Type, PrincipalUID: actor.UID, Operation: "support_cases.create", Key: key, RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour}
	claim, ok := s.beginIdempotentRequest(w, r, idem)
	if !ok {
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create support case")
		return
	}
	defer tx.Rollback(r.Context())
	if projectUID != "" {
		var status string
		err = tx.QueryRow(r.Context(), `SELECT status FROM projects WHERE uid=$1 AND tenant_uid=$2 FOR UPDATE`, projectUID, actor.TenantUID).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) {
			s.completeSupportProblem(w, r, tx, idem, claim, http.StatusNotFound, "project_not_found", "Project was not found")
			return
		}
		if err != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not create support case")
			return
		}
		if status != "active" {
			s.completeSupportProblem(w, r, tx, idem, claim, http.StatusConflict, "project_disabled", "enable the Project before creating a Support Case")
			return
		}
	} else {
		if _, err = tx.Exec(r.Context(), `SELECT 1 FROM tenants WHERE uid=$1 FOR UPDATE`, actor.TenantUID); err != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not create support case")
			return
		}
	}
	var activeCount int
	if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM support_cases WHERE tenant_uid=$1 AND status<>'closed'`, actor.TenantUID).Scan(&activeCount); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create support case")
		return
	}
	if activeCount >= supportCaseActiveLimit {
		s.completeSupportProblem(w, r, tx, idem, claim, http.StatusConflict, "support_case_limit", "resolve or close existing Support Cases before creating another")
		return
	}
	reporter := SupportReporter{Type: actor.Type, UID: actor.UID}
	if in.ReporterProjectUserUID != nil {
		var exists bool
		if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM project_users WHERE uid=$1 AND project_uid=$2)`, *in.ReporterProjectUserUID, projectUID).Scan(&exists); err != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not validate Support Case reporter")
			return
		}
		if !exists {
			s.completeSupportProblem(w, r, tx, idem, claim, http.StatusUnprocessableEntity, "invalid_reporter", "reporter Project User was not found in the Project")
			return
		}
		reporter = SupportReporter{Type: "project_user", UID: *in.ReporterProjectUserUID}
	}
	now := time.Now().UTC()
	caseUID, messageUID := uuid.NewString(), uuid.NewString()
	reference := "SC-" + strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))[:12]
	priority := "normal"
	if in.Priority != nil {
		priority = *in.Priority
	}
	subject, err := s.sealSupport([]byte(in.Subject), "case-subject", actor.TenantUID, caseUID, caseUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not encrypt support case")
		return
	}
	body, err := s.sealSupport([]byte(in.Message), "message-body", actor.TenantUID, caseUID, messageUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not encrypt support message")
		return
	}
	var diagnostics *encryptedSupportValue
	if in.Diagnostics != nil {
		raw, _ := json.Marshal(in.Diagnostics)
		sealed, sealErr := s.sealSupport(raw, "case-diagnostics", actor.TenantUID, caseUID, caseUID)
		if sealErr != nil {
			fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not encrypt support diagnostics")
			return
		}
		diagnostics = &sealed
	}
	var projectValue any
	if projectUID != "" {
		projectValue = projectUID
	}
	var diagnosticVersion any
	var diagnosticNonce, diagnosticCiphertext []byte
	if diagnostics != nil {
		diagnosticVersion, diagnosticNonce, diagnosticCiphertext = diagnostics.KeyVersion, diagnostics.Nonce, diagnostics.Ciphertext
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO support_cases(uid,case_reference,tenant_uid,project_uid,category,priority,reporter_type,reporter_uid,subject_key_version,subject_nonce,subject_ciphertext,diagnostic_consent,diagnostics_key_version,diagnostics_nonce,diagnostics_ciphertext,created_at,updated_at,last_message_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$16,$16)`, caseUID, reference, actor.TenantUID, projectValue, in.Category, priority, reporter.Type, reporter.UID, subject.KeyVersion, subject.Nonce, subject.Ciphertext, in.DiagnosticConsent, diagnosticVersion, diagnosticNonce, diagnosticCiphertext, now)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO support_case_messages(uid,case_uid,author_type,author_uid,visibility,body_key_version,body_nonce,body_ciphertext,created_at) VALUES($1,$2,$3,$4,'public',$5,$6,$7,$8)`, messageUID, caseUID, actor.Type, actor.UID, body.KeyVersion, body.Nonce, body.Ciphertext, now)
	}
	if err == nil {
		err = insertSupportEvent(r.Context(), tx, caseUID, "support_case.created", actor, "public", map[string]any{"category": in.Category, "priority": priority})
	}
	if err == nil {
		err = insertSupportEvent(r.Context(), tx, caseUID, "support_case.message_created", actor, "public", map[string]any{"message_uid": messageUID})
	}
	if err == nil {
		err = insertSupportAudit(r.Context(), tx, actor, projectUID, "support_case.created", "support_case", caseUID, map[string]any{"reference": reference, "category": in.Category})
	}
	value := SupportCase{UID: caseUID, Reference: reference, TenantUID: actor.TenantUID, Category: in.Category, Subject: in.Subject, Status: "open", Priority: priority, Reporter: reporter, DiagnosticConsent: in.DiagnosticConsent, Diagnostics: in.Diagnostics, Version: 1, MessageCount: 1, CreatedAt: now, UpdatedAt: now, LastMessageAt: now}
	if projectUID != "" {
		value.ProjectUID = &projectUID
	}
	response := storedResourceResponse(http.StatusCreated, "/v1/support/cases/"+caseUID, value.Version, value)
	if err != nil || s.idempotency.CompleteTx(r.Context(), tx, idem, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		if err != nil {
			s.log.Error("support case creation failed", "error", err)
		}
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create support case")
		return
	}
	writeStoredResponse(w, response)
}

func (s *Server) completeSupportProblem(w http.ResponseWriter, r *http.Request, tx pgx.Tx, idem store.IdempotencyRequest, claim store.IdempotencyClaim, status int, code, detail string) {
	response := problemResponse(r, status, code, detail)
	if s.idempotency.CompleteTx(r.Context(), tx, idem, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not persist Support Case result")
		return
	}
	writeStoredResponse(w, response)
}

func insertSupportEvent(ctx context.Context, tx pgx.Tx, caseUID, eventType string, actor supportActor, visibility string, payload map[string]any) error {
	_, err := tx.Exec(ctx, `INSERT INTO support_case_events(uid,case_uid,event_type,actor_type,actor_uid,visibility,payload) VALUES($1,$2,$3,$4,$5,$6,$7)`, uuid.NewString(), caseUID, eventType, actor.Type, actor.UID, visibility, payload)
	return err
}

func insertSupportAudit(ctx context.Context, tx pgx.Tx, actor supportActor, projectUID, action, targetType, targetUID string, metadata map[string]any) error {
	var project any
	if projectUID != "" {
		project = projectUID
	}
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(uid,tenant_uid,project_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, uuid.NewString(), actor.TenantUID, project, actor.Type, actor.UID, action, targetType, targetUID, metadata)
	return err
}

func supportStatusTransitionAllowed(from, to string) bool {
	if from == to {
		return true
	}
	allowed := map[string]map[string]bool{
		"open":                 {"in_progress": true, "waiting_for_customer": true, "resolved": true, "closed": true},
		"in_progress":          {"open": true, "waiting_for_customer": true, "resolved": true, "closed": true},
		"waiting_for_customer": {"open": true, "in_progress": true, "resolved": true, "closed": true},
		"resolved":             {"open": true, "closed": true},
		"closed":               {"open": true},
	}
	return allowed[from][to]
}

func (s *Server) updateSupportCase(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	var in struct {
		Subject           *string                `json:"subject"`
		Category          *string                `json:"category"`
		Status            *string                `json:"status"`
		Priority          *string                `json:"priority"`
		AssigneeMemberUID optionalNullableString `json:"assignee_member_uid"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Subject == nil && in.Category == nil && in.Status == nil && in.Priority == nil && !in.AssigneeMemberUID.Set {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "at least one field is required")
		return
	}
	if !actor.Operator && (in.Subject != nil || in.Category != nil || in.Priority != nil || in.AssigneeMemberUID.Set) {
		fail(w, r, http.StatusForbidden, "forbidden", "service credentials may only close or reopen a Support Case")
		return
	}
	if in.Subject != nil {
		value := strings.TrimSpace(*in.Subject)
		if len(value) < 1 || len(value) > 200 {
			fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "subject must contain between 1 and 200 characters")
			return
		}
		in.Subject = &value
	}
	if in.Category != nil && !validSupportCategories[*in.Category] {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "category must be bug, feedback, or question")
		return
	}
	if in.Status != nil {
		if !validSupportStatuses[*in.Status] {
			fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "status is invalid")
			return
		}
		if !actor.Operator && *in.Status != "open" && *in.Status != "closed" {
			fail(w, r, http.StatusForbidden, "forbidden", "service credentials may only close or reopen a Support Case")
			return
		}
	}
	if in.Priority != nil && !validSupportPriorities[*in.Priority] {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "priority must be low, normal, high, or urgent")
		return
	}
	if in.AssigneeMemberUID.Value != nil {
		value := strings.TrimSpace(*in.AssigneeMemberUID.Value)
		if _, parseErr := uuid.Parse(value); parseErr != nil {
			fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "assignee_member_uid must be a UUID or null")
			return
		}
		in.AssigneeMemberUID.Value = &value
	}
	expected, ok := requireIfMatch(w, r)
	if !ok {
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update support case")
		return
	}
	defer tx.Rollback(r.Context())
	record, err := s.lockSupportCase(r.Context(), tx, actor, r.PathValue("case_uid"))
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "support_case_not_found", "Support Case was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update support case")
		return
	}
	if record.Value.Version != expected {
		w.Header().Set("ETag", versionETag(record.Value.Version))
		fail(w, r, http.StatusPreconditionFailed, "version_conflict", "Support Case changed; fetch the latest representation and retry")
		return
	}
	if in.Status != nil && !supportStatusTransitionAllowed(record.Value.Status, *in.Status) {
		fail(w, r, http.StatusConflict, "invalid_status_transition", "the requested Support Case status transition is not allowed")
		return
	}
	if in.AssigneeMemberUID.Set && in.AssigneeMemberUID.Value != nil {
		var assignable bool
		if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM tenant_members WHERE uid=$1 AND tenant_uid=$2 AND status='active' AND role IN ('owner','admin','support'))`, *in.AssigneeMemberUID.Value, actor.TenantUID).Scan(&assignable); err != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not validate Support Case assignee")
			return
		}
		if !assignable {
			fail(w, r, http.StatusUnprocessableEntity, "invalid_assignee", "assignee must be an active owner, administrator, or support member")
			return
		}
	}
	changed := false
	now := time.Now().UTC()
	if in.Subject != nil {
		current, exposeErr := s.openSupport(record.Subject, "case-subject", record.Value.TenantUID, record.Value.UID, record.Value.UID)
		if exposeErr != nil {
			fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not decrypt support case")
			return
		}
		if string(current) != *in.Subject {
			record.Subject, err = s.sealSupport([]byte(*in.Subject), "case-subject", record.Value.TenantUID, record.Value.UID, record.Value.UID)
			changed = true
			if err == nil {
				err = insertSupportEvent(r.Context(), tx, record.Value.UID, "support_case.subject_changed", actor, "public", map[string]any{})
			}
		}
	}
	if in.Category != nil && record.Value.Category != *in.Category {
		old := record.Value.Category
		record.Value.Category = *in.Category
		changed = true
		if err == nil {
			err = insertSupportEvent(r.Context(), tx, record.Value.UID, "support_case.category_changed", actor, "public", map[string]any{"from": old, "to": *in.Category})
		}
	}
	if in.Priority != nil && record.Value.Priority != *in.Priority {
		old := record.Value.Priority
		record.Value.Priority = *in.Priority
		changed = true
		if err == nil {
			err = insertSupportEvent(r.Context(), tx, record.Value.UID, "support_case.priority_changed", actor, "internal", map[string]any{"from": old, "to": *in.Priority})
		}
	}
	if in.AssigneeMemberUID.Set {
		old := record.Value.AssigneeMemberUID
		if (old == nil) != (in.AssigneeMemberUID.Value == nil) || (old != nil && in.AssigneeMemberUID.Value != nil && *old != *in.AssigneeMemberUID.Value) {
			record.Value.AssigneeMemberUID = in.AssigneeMemberUID.Value
			changed = true
			if err == nil {
				err = insertSupportEvent(r.Context(), tx, record.Value.UID, "support_case.assignment_changed", actor, "public", map[string]any{"assignee_member_uid": in.AssigneeMemberUID.Value})
			}
		}
	}
	if in.Status != nil && record.Value.Status != *in.Status {
		old := record.Value.Status
		record.Value.Status = *in.Status
		changed = true
		if *in.Status == "resolved" {
			record.Value.ResolvedAt, record.Value.ClosedAt, record.Value.RetentionUntil = &now, nil, nil
		} else if *in.Status == "closed" {
			retention := now.Add(supportCaseRetention)
			record.Value.ClosedAt, record.Value.RetentionUntil = &now, &retention
		} else if old == "resolved" || old == "closed" {
			record.Value.ResolvedAt, record.Value.ClosedAt, record.Value.RetentionUntil = nil, nil, nil
		}
		if err == nil {
			err = insertSupportEvent(r.Context(), tx, record.Value.UID, "support_case.status_changed", actor, "public", map[string]any{"from": old, "to": *in.Status})
		}
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update support case")
		return
	}
	if !changed {
		value, exposeErr := s.exposeSupportCase(record)
		if exposeErr != nil {
			fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not decrypt support case")
			return
		}
		if tx.Commit(r.Context()) != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not update support case")
			return
		}
		setVersionETag(w, value.Version)
		writeJSON(w, http.StatusOK, value)
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE support_cases SET category=$2,status=$3,priority=$4,assignee_member_uid=$5,subject_key_version=$6,subject_nonce=$7,subject_ciphertext=$8,resolved_at=$9,closed_at=$10,retention_until=$11,version=version+1,updated_at=$12 WHERE uid=$1`, record.Value.UID, record.Value.Category, record.Value.Status, record.Value.Priority, record.Value.AssigneeMemberUID, record.Subject.KeyVersion, record.Subject.Nonce, record.Subject.Ciphertext, record.Value.ResolvedAt, record.Value.ClosedAt, record.Value.RetentionUntil, now)
	if err == nil && record.Value.Status == "closed" {
		_, err = tx.Exec(r.Context(), `INSERT INTO background_jobs(uid,queue,job_type,deduplication_key,payload,available_at) VALUES($1,'retention','support_case.purge',$2,$3,$4) ON CONFLICT(queue,deduplication_key) DO UPDATE SET status='pending',attempts=0,available_at=EXCLUDED.available_at,lease_uid=NULL,lease_expires_at=NULL,last_error=NULL,completed_at=NULL,dead_lettered_at=NULL,updated_at=clock_timestamp()`, uuid.NewString(), "support-case:"+record.Value.UID, map[string]any{"case_uid": record.Value.UID}, record.Value.RetentionUntil)
	}
	projectUID := ""
	if record.Value.ProjectUID != nil {
		projectUID = *record.Value.ProjectUID
	}
	if err == nil {
		err = insertSupportAudit(r.Context(), tx, actor, projectUID, "support_case.updated", "support_case", record.Value.UID, map[string]any{"status": record.Value.Status, "priority": record.Value.Priority})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		if err != nil {
			s.log.Error("support case update failed", "error", err)
		}
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update support case")
		return
	}
	value, err := s.exposeSupportCase(record)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not decrypt support case")
		return
	}
	value.Version++
	value.UpdatedAt = now
	setVersionETag(w, value.Version)
	writeJSON(w, http.StatusOK, value)
}
