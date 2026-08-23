package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/complicatedauth/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type SupportCaseMessage struct {
	UID        string          `json:"uid"`
	CaseUID    string          `json:"case_uid"`
	Author     SupportReporter `json:"author"`
	Visibility string          `json:"visibility"`
	Body       string          `json:"body"`
	CreatedAt  time.Time       `json:"created_at"`
}

type supportMessageRecord struct {
	Value SupportCaseMessage
	Body  encryptedSupportValue
}

type SupportCaseEvent struct {
	UID        string          `json:"uid"`
	CaseUID    string          `json:"case_uid"`
	Type       string          `json:"type"`
	Actor      SupportReporter `json:"actor"`
	Visibility string          `json:"visibility"`
	Payload    map[string]any  `json:"payload"`
	CreatedAt  time.Time       `json:"created_at"`
}

const supportMessageSelect = `SELECT m.uid,m.case_uid,m.author_type,m.author_uid,m.visibility,m.body_key_version,m.body_nonce,m.body_ciphertext,m.created_at FROM support_case_messages m`

func scanSupportMessage(row rowScanner) (supportMessageRecord, error) {
	var value supportMessageRecord
	err := row.Scan(&value.Value.UID, &value.Value.CaseUID, &value.Value.Author.Type, &value.Value.Author.UID, &value.Value.Visibility, &value.Body.KeyVersion, &value.Body.Nonce, &value.Body.Ciphertext, &value.Value.CreatedAt)
	return value, err
}

func (s *Server) exposeSupportMessage(record supportMessageRecord, tenantUID string) (SupportCaseMessage, error) {
	body, err := s.openSupport(record.Body, "message-body", tenantUID, record.Value.CaseUID, record.Value.UID)
	if err != nil {
		return SupportCaseMessage{}, err
	}
	record.Value.Body = string(body)
	return record.Value, nil
}

func (s *Server) listSupportCaseMessages(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	if _, err = s.loadSupportCase(r.Context(), actor, r.PathValue("case_uid")); errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "support_case_not_found", "Support Case was not found")
		return
	} else if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load support messages")
		return
	}
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	query := supportMessageSelect + ` WHERE m.case_uid=$1 AND ($2::boolean OR m.visibility='public')`
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), query+` ORDER BY m.created_at ASC,m.uid ASC LIMIT $3`, r.PathValue("case_uid"), actor.Operator, limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), query+` AND (m.created_at,m.uid)>($3,$4::uuid) ORDER BY m.created_at ASC,m.uid ASC LIMIT $5`, r.PathValue("case_uid"), actor.Operator, cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load support messages")
		return
	}
	defer rows.Close()
	items := make([]SupportCaseMessage, 0, limit)
	for rows.Next() {
		record, scanErr := scanSupportMessage(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load support messages")
			return
		}
		item, exposeErr := s.exposeSupportMessage(record, actor.TenantUID)
		if exposeErr != nil {
			fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not decrypt support message")
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

func (s *Server) createSupportCaseMessage(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	var in struct {
		Body                 string  `json:"body"`
		Visibility           string  `json:"visibility,omitempty"`
		AuthorProjectUserUID *string `json:"author_project_user_uid,omitempty"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Body = strings.TrimSpace(in.Body)
	if len(in.Body) < 1 || len(in.Body) > 10000 {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "body must contain between 1 and 10000 characters")
		return
	}
	if in.Visibility == "" {
		in.Visibility = "public"
	}
	if in.Visibility != "public" && in.Visibility != "internal" {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "visibility must be public or internal")
		return
	}
	if !actor.Operator && in.Visibility != "public" {
		fail(w, r, http.StatusForbidden, "forbidden", "service credentials cannot create internal notes")
		return
	}
	if actor.Operator && in.AuthorProjectUserUID != nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "author_project_user_uid is only available to a Project service credential")
		return
	}
	if in.AuthorProjectUserUID != nil {
		value := strings.TrimSpace(*in.AuthorProjectUserUID)
		if _, parseErr := uuid.Parse(value); parseErr != nil {
			fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "author_project_user_uid must be a UUID")
			return
		}
		in.AuthorProjectUserUID = &value
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
	idem := store.IdempotencyRequest{PrincipalType: actor.Type, PrincipalUID: actor.UID, Operation: "support_case_messages.create", Key: key, RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour}
	claim, ok := s.beginIdempotentRequest(w, r, idem)
	if !ok {
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create support message")
		return
	}
	defer tx.Rollback(r.Context())
	caseRecord, err := s.lockSupportCase(r.Context(), tx, actor, r.PathValue("case_uid"))
	if errors.Is(err, pgx.ErrNoRows) {
		s.completeSupportProblem(w, r, tx, idem, claim, http.StatusNotFound, "support_case_not_found", "Support Case was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create support message")
		return
	}
	if caseRecord.Value.Status == "resolved" || caseRecord.Value.Status == "closed" {
		s.completeSupportProblem(w, r, tx, idem, claim, http.StatusConflict, "support_case_terminal", "reopen the Support Case before adding a message")
		return
	}
	if caseRecord.Value.MessageCount >= supportMessageLimit {
		s.completeSupportProblem(w, r, tx, idem, claim, http.StatusConflict, "support_message_limit", "the Support Case has reached its message limit")
		return
	}
	author := actor
	if in.AuthorProjectUserUID != nil {
		var exists bool
		if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM project_users WHERE uid=$1 AND project_uid=$2)`, *in.AuthorProjectUserUID, actor.ProjectUID).Scan(&exists); err != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not validate support message author")
			return
		}
		if !exists {
			s.completeSupportProblem(w, r, tx, idem, claim, http.StatusUnprocessableEntity, "invalid_author", "author Project User was not found in the Project")
			return
		}
		author = supportActor{Type: "project_user", UID: *in.AuthorProjectUserUID, TenantUID: actor.TenantUID, ProjectUID: actor.ProjectUID}
	}
	now, messageUID := time.Now().UTC(), uuid.NewString()
	body, err := s.sealSupport([]byte(in.Body), "message-body", actor.TenantUID, caseRecord.Value.UID, messageUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not encrypt support message")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO support_case_messages(uid,case_uid,author_type,author_uid,visibility,body_key_version,body_nonce,body_ciphertext,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, messageUID, caseRecord.Value.UID, author.Type, author.UID, in.Visibility, body.KeyVersion, body.Nonce, body.Ciphertext, now)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE support_cases SET message_count=message_count+1,version=version+1,last_message_at=$2,updated_at=$2 WHERE uid=$1`, caseRecord.Value.UID, now)
	}
	payload := map[string]any{"message_uid": messageUID}
	if author.Type != actor.Type || author.UID != actor.UID {
		payload["submitted_by_service_account_uid"] = actor.UID
	}
	if err == nil {
		err = insertSupportEvent(r.Context(), tx, caseRecord.Value.UID, "support_case.message_created", author, in.Visibility, payload)
	}
	projectUID := ""
	if caseRecord.Value.ProjectUID != nil {
		projectUID = *caseRecord.Value.ProjectUID
	}
	if err == nil {
		err = insertSupportAudit(r.Context(), tx, actor, projectUID, "support_case.message_created", "support_case_message", messageUID, map[string]any{"case_uid": caseRecord.Value.UID, "visibility": in.Visibility, "author_type": author.Type})
	}
	value := SupportCaseMessage{UID: messageUID, CaseUID: caseRecord.Value.UID, Author: SupportReporter{Type: author.Type, UID: author.UID}, Visibility: in.Visibility, Body: in.Body, CreatedAt: now}
	response := store.StoredHTTPResponse{Status: http.StatusCreated, Headers: map[string][]string{"Content-Type": {"application/json"}, "Location": {"/v1/support/cases/" + caseRecord.Value.UID + "/messages/" + messageUID}}, Body: appendJSON(value)}
	if err != nil || s.idempotency.CompleteTx(r.Context(), tx, idem, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		if err != nil {
			s.log.Error("support message creation failed", "error", err)
		}
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create support message")
		return
	}
	writeStoredResponse(w, response)
}

func appendJSON(value any) []byte {
	body, _ := json.Marshal(value)
	return append(body, '\n')
}

func (s *Server) listSupportCaseEvents(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	if _, err = s.loadSupportCase(r.Context(), actor, r.PathValue("case_uid")); errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "support_case_not_found", "Support Case was not found")
		return
	} else if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Support Case events")
		return
	}
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	query := `SELECT uid,case_uid,event_type,actor_type,actor_uid,visibility,payload,created_at FROM support_case_events WHERE case_uid=$1 AND ($2::boolean OR visibility='public')`
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), query+` ORDER BY created_at ASC,uid ASC LIMIT $3`, r.PathValue("case_uid"), actor.Operator, limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), query+` AND (created_at,uid)>($3,$4::uuid) ORDER BY created_at ASC,uid ASC LIMIT $5`, r.PathValue("case_uid"), actor.Operator, cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Support Case events")
		return
	}
	defer rows.Close()
	items := make([]SupportCaseEvent, 0, limit)
	for rows.Next() {
		var event SupportCaseEvent
		if rows.Scan(&event.UID, &event.CaseUID, &event.Type, &event.Actor.Type, &event.Actor.UID, &event.Visibility, &event.Payload, &event.CreatedAt) != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Support Case events")
			return
		}
		items = append(items, event)
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
