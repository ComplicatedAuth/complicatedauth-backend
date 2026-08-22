package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	security "github.com/dokosoko/complicatedauth-backend/internal/auth"
	"github.com/dokosoko/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var supportReferenceProviderPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)

type SupportCaseExternalReference struct {
	UID                string    `json:"uid"`
	CaseUID            string    `json:"case_uid"`
	Provider           string    `json:"provider"`
	ExternalID         string    `json:"external_id"`
	URL                string    `json:"url,omitempty"`
	Label              string    `json:"label,omitempty"`
	CreatedByMemberUID *string   `json:"created_by_member_uid"`
	CreatedAt          time.Time `json:"created_at"`
}

type supportExternalReferenceRecord struct {
	Value   SupportCaseExternalReference
	Payload encryptedSupportValue
}

const supportExternalReferenceSelect = `SELECT x.uid,x.case_uid,x.provider,x.payload_key_version,x.payload_nonce,x.payload_ciphertext,x.created_by_member_uid,x.created_at FROM support_case_external_references x`

func scanSupportExternalReference(row rowScanner) (supportExternalReferenceRecord, error) {
	var record supportExternalReferenceRecord
	err := row.Scan(&record.Value.UID, &record.Value.CaseUID, &record.Value.Provider, &record.Payload.KeyVersion, &record.Payload.Nonce, &record.Payload.Ciphertext, &record.Value.CreatedByMemberUID, &record.Value.CreatedAt)
	return record, err
}

func (s *Server) exposeSupportExternalReference(record supportExternalReferenceRecord, tenantUID string) (SupportCaseExternalReference, error) {
	raw, err := s.openSupport(record.Payload, "external-reference", tenantUID, record.Value.CaseUID, record.Value.UID)
	if err != nil {
		return SupportCaseExternalReference{}, err
	}
	var payload struct {
		ExternalID string `json:"external_id"`
		URL        string `json:"url,omitempty"`
		Label      string `json:"label,omitempty"`
	}
	if json.Unmarshal(raw, &payload) != nil || payload.ExternalID == "" {
		return SupportCaseExternalReference{}, errors.New("support external reference is invalid")
	}
	record.Value.ExternalID, record.Value.URL, record.Value.Label = payload.ExternalID, payload.URL, payload.Label
	return record.Value, nil
}

func (s *Server) listSupportCaseExternalReferences(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil || !actor.Operator {
		fail(w, r, http.StatusForbidden, "forbidden", "Tenant support permission is required")
		return
	}
	if _, err = s.loadSupportCase(r.Context(), actor, r.PathValue("case_uid")); errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "support_case_not_found", "Support Case was not found")
		return
	} else if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load external references")
		return
	}
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	query := supportExternalReferenceSelect + ` WHERE x.case_uid=$1`
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), query+` ORDER BY x.created_at DESC,x.uid DESC LIMIT $2`, r.PathValue("case_uid"), limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), query+` AND (x.created_at,x.uid)<($2,$3::uuid) ORDER BY x.created_at DESC,x.uid DESC LIMIT $4`, r.PathValue("case_uid"), cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load external references")
		return
	}
	defer rows.Close()
	items := make([]SupportCaseExternalReference, 0, limit)
	for rows.Next() {
		record, scanErr := scanSupportExternalReference(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load external references")
			return
		}
		item, exposeErr := s.exposeSupportExternalReference(record, actor.TenantUID)
		if exposeErr != nil {
			fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not decrypt external reference")
			return
		}
		items = append(items, item)
	}
	var next *string
	if len(items) > limit {
		position := items[limit-1]
		items = items[:limit]
		value := nextCursor(position.CreatedAt, position.UID)
		next = &value
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func normalizeSupportExternalReference(provider, externalID, rawURL, label string) (string, string, string, string, error) {
	provider, externalID, rawURL, label = strings.TrimSpace(provider), strings.TrimSpace(externalID), strings.TrimSpace(rawURL), strings.TrimSpace(label)
	if !supportReferenceProviderPattern.MatchString(provider) {
		return "", "", "", "", errors.New("provider must be a lowercase integration identifier")
	}
	if len(externalID) < 1 || len(externalID) > 255 {
		return "", "", "", "", errors.New("external_id must contain between 1 and 255 characters")
	}
	if len(label) > 100 || len(rawURL) > 2048 {
		return "", "", "", "", errors.New("label or url exceeds its documented maximum length")
	}
	if rawURL != "" {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && parsed.Hostname() == "localhost")) {
			return "", "", "", "", errors.New("url must be HTTPS, or localhost HTTP, without credentials, query, or fragment")
		}
	}
	return provider, externalID, rawURL, label, nil
}

func (s *Server) createSupportCaseExternalReference(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil || !actor.Operator {
		fail(w, r, http.StatusForbidden, "forbidden", "Tenant support permission is required")
		return
	}
	var in struct {
		Provider   string `json:"provider"`
		ExternalID string `json:"external_id"`
		URL        string `json:"url,omitempty"`
		Label      string `json:"label,omitempty"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Provider, in.ExternalID, in.URL, in.Label, err = normalizeSupportExternalReference(in.Provider, in.ExternalID, in.URL, in.Label)
	if err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		fail(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required")
		return
	}
	canonical, _ := json.Marshal(struct {
		CaseUID string `json:"case_uid"`
		Input   any    `json:"input"`
	}{r.PathValue("case_uid"), in})
	idem := store.IdempotencyRequest{PrincipalType: actor.Type, PrincipalUID: actor.UID, Operation: "support_case_external_references.create", Key: key, RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour}
	claim, ok := s.beginIdempotentRequest(w, r, idem)
	if !ok {
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create external reference")
		return
	}
	defer tx.Rollback(r.Context())
	caseRecord, err := s.lockSupportCase(r.Context(), tx, actor, r.PathValue("case_uid"))
	if errors.Is(err, pgx.ErrNoRows) {
		s.completeSupportProblem(w, r, tx, idem, claim, http.StatusNotFound, "support_case_not_found", "Support Case was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create external reference")
		return
	}
	var count int
	if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM support_case_external_references WHERE case_uid=$1`, caseRecord.Value.UID).Scan(&count); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create external reference")
		return
	}
	if count >= 20 {
		s.completeSupportProblem(w, r, tx, idem, claim, http.StatusConflict, "external_reference_limit", "the Support Case has reached its external-reference limit")
		return
	}
	referenceUID, now := uuid.NewString(), time.Now().UTC()
	payloadRaw, _ := json.Marshal(map[string]string{"external_id": in.ExternalID, "url": in.URL, "label": in.Label})
	payload, err := s.sealSupport(payloadRaw, "external-reference", actor.TenantUID, caseRecord.Value.UID, referenceUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not encrypt external reference")
		return
	}
	digest := security.SecretHash(s.cfg.SecretHashKey, in.ExternalID)
	var inserted string
	err = tx.QueryRow(r.Context(), `INSERT INTO support_case_external_references(uid,case_uid,provider,external_id_hash,payload_key_version,payload_nonce,payload_ciphertext,created_by_member_uid,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(case_uid,provider,external_id_hash) DO NOTHING RETURNING uid`, referenceUID, caseRecord.Value.UID, in.Provider, digest, payload.KeyVersion, payload.Nonce, payload.Ciphertext, actor.UID, now).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		s.completeSupportProblem(w, r, tx, idem, claim, http.StatusConflict, "external_reference_exists", "that external reference is already linked to the Support Case")
		return
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE support_cases SET version=version+1,updated_at=$2 WHERE uid=$1`, caseRecord.Value.UID, now)
	}
	if err == nil {
		err = insertSupportEvent(r.Context(), tx, caseRecord.Value.UID, "support_case.external_reference_created", actor, "internal", map[string]any{"external_reference_uid": referenceUID, "provider": in.Provider})
	}
	projectUID := ""
	if caseRecord.Value.ProjectUID != nil {
		projectUID = *caseRecord.Value.ProjectUID
	}
	if err == nil {
		err = insertSupportAudit(r.Context(), tx, actor, projectUID, "support_case.external_reference_created", "support_case_external_reference", referenceUID, map[string]any{"case_uid": caseRecord.Value.UID, "provider": in.Provider})
	}
	memberUID := actor.UID
	value := SupportCaseExternalReference{UID: referenceUID, CaseUID: caseRecord.Value.UID, Provider: in.Provider, ExternalID: in.ExternalID, URL: in.URL, Label: in.Label, CreatedByMemberUID: &memberUID, CreatedAt: now}
	response := store.StoredHTTPResponse{Status: http.StatusCreated, Headers: map[string][]string{"Content-Type": {"application/json"}, "Location": {"/v1/support/cases/" + caseRecord.Value.UID + "/external-references/" + referenceUID}}, Body: appendJSON(value)}
	if err != nil || s.idempotency.CompleteTx(r.Context(), tx, idem, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		if err != nil {
			s.log.Error("support external reference creation failed", "error", err)
		}
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create external reference")
		return
	}
	writeStoredResponse(w, response)
}

func (s *Server) deleteSupportCaseExternalReference(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil || !actor.Operator {
		fail(w, r, http.StatusForbidden, "forbidden", "Tenant support permission is required")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete external reference")
		return
	}
	defer tx.Rollback(r.Context())
	caseRecord, err := s.lockSupportCase(r.Context(), tx, actor, r.PathValue("case_uid"))
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "support_case_not_found", "Support Case was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete external reference")
		return
	}
	var provider string
	err = tx.QueryRow(r.Context(), `DELETE FROM support_case_external_references WHERE uid=$1 AND case_uid=$2 RETURNING provider`, r.PathValue("external_reference_uid"), caseRecord.Value.UID).Scan(&provider)
	changed := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	if changed {
		_, err = tx.Exec(r.Context(), `UPDATE support_cases SET version=version+1,updated_at=now() WHERE uid=$1`, caseRecord.Value.UID)
	}
	if err == nil && changed {
		err = insertSupportEvent(r.Context(), tx, caseRecord.Value.UID, "support_case.external_reference_deleted", actor, "internal", map[string]any{"external_reference_uid": r.PathValue("external_reference_uid"), "provider": provider})
	}
	projectUID := ""
	if caseRecord.Value.ProjectUID != nil {
		projectUID = *caseRecord.Value.ProjectUID
	}
	if err == nil && changed {
		err = insertSupportAudit(r.Context(), tx, actor, projectUID, "support_case.external_reference_deleted", "support_case_external_reference", r.PathValue("external_reference_uid"), map[string]any{"case_uid": caseRecord.Value.UID, "provider": provider})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not delete external reference")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
