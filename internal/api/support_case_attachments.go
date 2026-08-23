package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/complicatedauth/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	supportAttachmentLimit      = 20
	supportAttachmentByteLimit  = 5 * 1024 * 1024
	supportAttachmentTotalLimit = 25 * 1024 * 1024
)

type SupportCaseAttachment struct {
	UID        string          `json:"uid"`
	CaseUID    string          `json:"case_uid"`
	Filename   string          `json:"filename"`
	MediaType  string          `json:"media_type"`
	ByteCount  int             `json:"byte_count"`
	SHA256     string          `json:"sha256"`
	UploadedBy SupportReporter `json:"uploaded_by"`
	CreatedAt  time.Time       `json:"created_at"`
}

type supportAttachmentRecord struct {
	Value    SupportCaseAttachment
	Metadata encryptedSupportValue
	Content  encryptedSupportValue
}

const supportAttachmentSelect = `SELECT a.uid,a.case_uid,a.uploaded_by_type,a.uploaded_by_uid,a.media_type,a.byte_count,a.sha256,a.metadata_key_version,a.metadata_nonce,a.metadata_ciphertext,a.content_key_version,a.content_nonce,a.content_ciphertext,a.created_at FROM support_case_attachments a`

func scanSupportAttachment(row rowScanner) (supportAttachmentRecord, error) {
	var value supportAttachmentRecord
	err := row.Scan(&value.Value.UID, &value.Value.CaseUID, &value.Value.UploadedBy.Type, &value.Value.UploadedBy.UID, &value.Value.MediaType, &value.Value.ByteCount, &value.Value.SHA256, &value.Metadata.KeyVersion, &value.Metadata.Nonce, &value.Metadata.Ciphertext, &value.Content.KeyVersion, &value.Content.Nonce, &value.Content.Ciphertext, &value.Value.CreatedAt)
	return value, err
}

func (s *Server) exposeSupportAttachment(record supportAttachmentRecord, tenantUID string) (SupportCaseAttachment, error) {
	raw, err := s.openSupport(record.Metadata, "attachment-metadata", tenantUID, record.Value.CaseUID, record.Value.UID)
	if err != nil {
		return SupportCaseAttachment{}, err
	}
	var metadata struct {
		Filename string `json:"filename"`
	}
	if json.Unmarshal(raw, &metadata) != nil || metadata.Filename == "" {
		return SupportCaseAttachment{}, errors.New("support attachment metadata is invalid")
	}
	record.Value.Filename = metadata.Filename
	return record.Value, nil
}

func (s *Server) listSupportCaseAttachments(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	if _, err = s.loadSupportCase(r.Context(), actor, r.PathValue("case_uid")); errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "support_case_not_found", "Support Case was not found")
		return
	} else if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load support attachments")
		return
	}
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	query := supportAttachmentSelect + ` WHERE a.case_uid=$1`
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), query+` ORDER BY a.created_at DESC,a.uid DESC LIMIT $2`, r.PathValue("case_uid"), limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), query+` AND (a.created_at,a.uid)<($2,$3::uuid) ORDER BY a.created_at DESC,a.uid DESC LIMIT $4`, r.PathValue("case_uid"), cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load support attachments")
		return
	}
	defer rows.Close()
	items := make([]SupportCaseAttachment, 0, limit)
	for rows.Next() {
		record, scanErr := scanSupportAttachment(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load support attachments")
			return
		}
		item, exposeErr := s.exposeSupportAttachment(record, actor.TenantUID)
		if exposeErr != nil {
			fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not decrypt support attachment metadata")
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

func normalizeSupportAttachment(filename, declared string, content []byte) (string, string, error) {
	filename = strings.TrimSpace(filename)
	if filename == "" || len(filename) > 255 || filename != filepath.Base(filename) || strings.ContainsAny(filename, "/\\\r\n\x00") {
		return "", "", errors.New("filename must be a safe basename of at most 255 characters")
	}
	declaredType, _, err := mime.ParseMediaType(declared)
	if err != nil {
		declaredType = ""
	}
	detected, _, _ := mime.ParseMediaType(http.DetectContentType(content))
	switch detected {
	case "image/png", "image/jpeg", "image/webp", "application/pdf":
		if declaredType != "" && declaredType != "application/octet-stream" && declaredType != detected {
			return "", "", errors.New("declared media type does not match attachment content")
		}
		return filename, detected, nil
	default:
		if !utf8.Valid(content) {
			return "", "", errors.New("attachment type is not allowed")
		}
		if declaredType == "application/json" {
			if !json.Valid(content) {
				return "", "", errors.New("attachment declared as JSON is invalid")
			}
			return filename, "application/json", nil
		}
		if declaredType != "" && declaredType != "text/plain" && declaredType != "application/octet-stream" {
			return "", "", errors.New("attachment type is not allowed")
		}
		return filename, "text/plain", nil
	}
}

func (s *Server) createSupportCaseAttachment(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, supportAttachmentByteLimit+1024*1024)
	if err = r.ParseMultipartForm(supportAttachmentByteLimit + 1024*1024); err != nil {
		fail(w, r, http.StatusRequestEntityTooLarge, "attachment_too_large", "multipart request exceeds the attachment limit")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "one file part is required")
		return
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, supportAttachmentByteLimit+1))
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_attachment", "could not read attachment")
		return
	}
	if len(content) == 0 || len(content) > supportAttachmentByteLimit {
		fail(w, r, http.StatusRequestEntityTooLarge, "attachment_too_large", "attachment must contain between 1 byte and 5 MiB")
		return
	}
	filename, mediaType, err := normalizeSupportAttachment(header.Filename, header.Header.Get("Content-Type"), content)
	if err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "invalid_attachment", err.Error())
		return
	}
	uploaderProjectUserUID := strings.TrimSpace(r.FormValue("uploader_project_user_uid"))
	if actor.Operator && uploaderProjectUserUID != "" {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "uploader_project_user_uid is only available to a Project service credential")
		return
	}
	if uploaderProjectUserUID != "" {
		if _, parseErr := uuid.Parse(uploaderProjectUserUID); parseErr != nil {
			fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "uploader_project_user_uid must be a UUID")
			return
		}
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		fail(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required")
		return
	}
	digest := sha256.Sum256(content)
	checksum := hex.EncodeToString(digest[:])
	canonical, _ := json.Marshal(map[string]any{"case_uid": r.PathValue("case_uid"), "filename": filename, "media_type": mediaType, "sha256": checksum, "uploader_project_user_uid": uploaderProjectUserUID})
	idem := store.IdempotencyRequest{PrincipalType: actor.Type, PrincipalUID: actor.UID, Operation: "support_case_attachments.create", Key: key, RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour}
	claim, ok := s.beginIdempotentRequest(w, r, idem)
	if !ok {
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create support attachment")
		return
	}
	defer tx.Rollback(r.Context())
	caseRecord, err := s.lockSupportCase(r.Context(), tx, actor, r.PathValue("case_uid"))
	if errors.Is(err, pgx.ErrNoRows) {
		s.completeSupportProblem(w, r, tx, idem, claim, http.StatusNotFound, "support_case_not_found", "Support Case was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create support attachment")
		return
	}
	if caseRecord.Value.Status == "resolved" || caseRecord.Value.Status == "closed" {
		s.completeSupportProblem(w, r, tx, idem, claim, http.StatusConflict, "support_case_terminal", "reopen the Support Case before adding an attachment")
		return
	}
	if caseRecord.Value.AttachmentCount >= supportAttachmentLimit || caseRecord.Value.AttachmentBytes+int64(len(content)) > supportAttachmentTotalLimit {
		s.completeSupportProblem(w, r, tx, idem, claim, http.StatusConflict, "support_attachment_limit", "the Support Case attachment count or total-byte limit would be exceeded")
		return
	}
	uploader := actor
	if uploaderProjectUserUID != "" {
		var exists bool
		if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM project_users WHERE uid=$1 AND project_uid=$2)`, uploaderProjectUserUID, actor.ProjectUID).Scan(&exists); err != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not validate support attachment uploader")
			return
		}
		if !exists {
			s.completeSupportProblem(w, r, tx, idem, claim, http.StatusUnprocessableEntity, "invalid_uploader", "uploader Project User was not found in the Project")
			return
		}
		uploader = supportActor{Type: "project_user", UID: uploaderProjectUserUID, TenantUID: actor.TenantUID, ProjectUID: actor.ProjectUID}
	}
	attachmentUID, now := uuid.NewString(), time.Now().UTC()
	metadataRaw, _ := json.Marshal(map[string]string{"filename": filename})
	metadata, err := s.sealSupport(metadataRaw, "attachment-metadata", actor.TenantUID, caseRecord.Value.UID, attachmentUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not encrypt support attachment metadata")
		return
	}
	sealedContent, err := s.sealSupport(content, "attachment-content", actor.TenantUID, caseRecord.Value.UID, attachmentUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not encrypt support attachment")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO support_case_attachments(uid,case_uid,uploaded_by_type,uploaded_by_uid,media_type,byte_count,sha256,metadata_key_version,metadata_nonce,metadata_ciphertext,content_key_version,content_nonce,content_ciphertext,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, attachmentUID, caseRecord.Value.UID, uploader.Type, uploader.UID, mediaType, len(content), checksum, metadata.KeyVersion, metadata.Nonce, metadata.Ciphertext, sealedContent.KeyVersion, sealedContent.Nonce, sealedContent.Ciphertext, now)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE support_cases SET attachment_count=attachment_count+1,attachment_bytes=attachment_bytes+$2,version=version+1,updated_at=$3 WHERE uid=$1`, caseRecord.Value.UID, len(content), now)
	}
	payload := map[string]any{"attachment_uid": attachmentUID, "media_type": mediaType, "byte_count": len(content), "sha256": checksum}
	if uploader.Type != actor.Type || uploader.UID != actor.UID {
		payload["submitted_by_service_account_uid"] = actor.UID
	}
	if err == nil {
		err = insertSupportEvent(r.Context(), tx, caseRecord.Value.UID, "support_case.attachment_created", uploader, "public", payload)
	}
	projectUID := ""
	if caseRecord.Value.ProjectUID != nil {
		projectUID = *caseRecord.Value.ProjectUID
	}
	if err == nil {
		err = insertSupportAudit(r.Context(), tx, actor, projectUID, "support_case.attachment_created", "support_case_attachment", attachmentUID, map[string]any{"case_uid": caseRecord.Value.UID, "media_type": mediaType, "byte_count": len(content), "sha256": checksum})
	}
	value := SupportCaseAttachment{UID: attachmentUID, CaseUID: caseRecord.Value.UID, Filename: filename, MediaType: mediaType, ByteCount: len(content), SHA256: checksum, UploadedBy: SupportReporter{Type: uploader.Type, UID: uploader.UID}, CreatedAt: now}
	response := store.StoredHTTPResponse{Status: http.StatusCreated, Headers: map[string][]string{"Content-Type": {"application/json"}, "Location": {"/v1/support/cases/" + caseRecord.Value.UID + "/attachments/" + attachmentUID}}, Body: appendJSON(value)}
	if err != nil || s.idempotency.CompleteTx(r.Context(), tx, idem, claim.LeaseUID, response) != nil || tx.Commit(r.Context()) != nil {
		if err != nil {
			s.log.Error("support attachment creation failed", "error", err)
		}
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create support attachment")
		return
	}
	writeStoredResponse(w, response)
}

func (s *Server) loadSupportAttachment(r *http.Request, actor supportActor) (supportAttachmentRecord, error) {
	caseRecord, err := s.loadSupportCase(r.Context(), actor, r.PathValue("case_uid"))
	if err != nil {
		return supportAttachmentRecord{}, err
	}
	return scanSupportAttachment(s.db.QueryRow(r.Context(), supportAttachmentSelect+` WHERE a.uid=$1 AND a.case_uid=$2`, r.PathValue("attachment_uid"), caseRecord.Value.UID))
}

func (s *Server) getSupportCaseAttachment(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	record, err := s.loadSupportAttachment(r, actor)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "support_attachment_not_found", "Support Case attachment was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load support attachment")
		return
	}
	value, err := s.exposeSupportAttachment(record, actor.TenantUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not decrypt support attachment metadata")
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) downloadSupportCaseAttachment(w http.ResponseWriter, r *http.Request) {
	actor, err := s.supportActor(r)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		return
	}
	record, err := s.loadSupportAttachment(r, actor)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "support_attachment_not_found", "Support Case attachment was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load support attachment")
		return
	}
	value, err := s.exposeSupportAttachment(record, actor.TenantUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not decrypt support attachment metadata")
		return
	}
	content, err := s.openSupport(record.Content, "attachment-content", actor.TenantUID, record.Value.CaseUID, record.Value.UID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "encryption_key_unavailable", "could not decrypt support attachment")
		return
	}
	w.Header().Set("Content-Type", value.MediaType)
	w.Header().Set("Content-Length", fmtInt(len(content)))
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": value.Filename}))
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func fmtInt(value int) string {
	return strconv.Itoa(value)
}
