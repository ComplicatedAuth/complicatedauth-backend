package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	security "github.com/dokosoko/complicatedauth-backend/internal/auth"
	"github.com/dokosoko/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const invitationTTL = 7 * 24 * time.Hour

type rowScanner interface {
	Scan(...any) error
}

func scanTenantMember(row rowScanner) (TenantMember, error) {
	var member TenantMember
	err := row.Scan(&member.UID, &member.Email, &member.DisplayName, &member.Role, &member.Status, &member.EmailVerified, &member.CreatedAt)
	return member, err
}

func (s *Server) loadTenantMember(ctx context.Context, tenantUID, memberUID string) (TenantMember, error) {
	return scanTenantMember(s.db.QueryRow(ctx, `
		SELECT uid,email,display_name,role,status,email_verified_at IS NOT NULL,created_at
		FROM tenant_members WHERE tenant_uid=$1 AND uid=$2
	`, tenantUID, memberUID))
}

func (s *Server) listTenantMembers(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), `
			SELECT uid,email,display_name,role,status,email_verified_at IS NOT NULL,created_at
			FROM tenant_members WHERE tenant_uid=$1
			ORDER BY created_at DESC,uid DESC LIMIT $2
		`, p.TenantUID, limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), `
			SELECT uid,email,display_name,role,status,email_verified_at IS NOT NULL,created_at
			FROM tenant_members WHERE tenant_uid=$1 AND (created_at,uid)<($2,$3::uuid)
			ORDER BY created_at DESC,uid DESC LIMIT $4
		`, p.TenantUID, cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Tenant Members")
		return
	}
	defer rows.Close()
	items := make([]TenantMember, 0, limit)
	for rows.Next() {
		member, scanErr := scanTenantMember(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Tenant Members")
			return
		}
		items = append(items, member)
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

func (s *Server) getTenantMember(w http.ResponseWriter, r *http.Request) {
	member, err := s.loadTenantMember(r.Context(), mustPrincipal(r).TenantUID, r.PathValue("member_uid"))
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "tenant_member_not_found", "Tenant Member was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Tenant Member")
		return
	}
	writeJSON(w, http.StatusOK, member)
}

func (s *Server) updateTenantMember(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Role   *string `json:"role"`
		Status *string `json:"status"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Role == nil && in.Status == nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "at least one field is required")
		return
	}
	if in.Role != nil && !validMemberRole(*in.Role) {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "role is invalid")
		return
	}
	if in.Status != nil && *in.Status != "active" && *in.Status != "disabled" {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "status must be active or disabled")
		return
	}
	p := mustPrincipal(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update Tenant Member")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `SELECT uid FROM tenant_members WHERE tenant_uid=$1 FOR UPDATE`, p.TenantUID); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update Tenant Member")
		return
	}
	var currentRole, currentStatus string
	err = tx.QueryRow(r.Context(), `SELECT role,status FROM tenant_members WHERE tenant_uid=$1 AND uid=$2`, p.TenantUID, r.PathValue("member_uid")).Scan(&currentRole, &currentStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "tenant_member_not_found", "Tenant Member was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update Tenant Member")
		return
	}
	if p.Role == "admin" && (currentRole == "owner" || (in.Role != nil && *in.Role == "owner")) {
		fail(w, r, http.StatusForbidden, "owner_required", "only an owner can change owner membership")
		return
	}
	nextRole, nextStatus := currentRole, currentStatus
	if in.Role != nil {
		nextRole = *in.Role
	}
	if in.Status != nil {
		nextStatus = *in.Status
	}
	if currentRole == "owner" && currentStatus == "active" && (nextRole != "owner" || nextStatus != "active") {
		var activeOwners int
		if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM tenant_members WHERE tenant_uid=$1 AND role='owner' AND status='active'`, p.TenantUID).Scan(&activeOwners); err != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not update Tenant Member")
			return
		}
		if activeOwners <= 1 {
			fail(w, r, http.StatusConflict, "last_owner", "the final active owner cannot be demoted or disabled")
			return
		}
	}
	_, err = tx.Exec(r.Context(), `UPDATE tenant_members SET role=$3,status=$4,updated_at=now() WHERE tenant_uid=$1 AND uid=$2`, p.TenantUID, r.PathValue("member_uid"), nextRole, nextStatus)
	if err == nil && nextStatus == "disabled" {
		_, err = tx.Exec(r.Context(), `UPDATE tenant_member_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE tenant_uid=$1 AND tenant_member_uid=$2`, p.TenantUID, r.PathValue("member_uid"))
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,'tenant_member',$3,'tenant_member.updated','tenant_member',$4,$5)`, uuid.NewString(), p.TenantUID, p.MemberUID, r.PathValue("member_uid"), map[string]any{"role": nextRole, "status": nextStatus})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not update Tenant Member")
		return
	}
	member, err := s.loadTenantMember(r.Context(), p.TenantUID, r.PathValue("member_uid"))
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load Tenant Member")
		return
	}
	writeJSON(w, http.StatusOK, member)
}

func (s *Server) removeTenantMember(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	targetUID := r.PathValue("member_uid")
	if targetUID == p.MemberUID {
		fail(w, r, http.StatusConflict, "self_removal_not_allowed", "use a separate membership-leave flow to remove yourself")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not remove Tenant Member")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `SELECT uid FROM tenant_members WHERE tenant_uid=$1 FOR UPDATE`, p.TenantUID); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not remove Tenant Member")
		return
	}
	var role, status string
	err = tx.QueryRow(r.Context(), `SELECT role,status FROM tenant_members WHERE tenant_uid=$1 AND uid=$2`, p.TenantUID, targetUID).Scan(&role, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusNotFound, "tenant_member_not_found", "Tenant Member was not found")
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not remove Tenant Member")
		return
	}
	if p.Role == "admin" && role == "owner" {
		fail(w, r, http.StatusForbidden, "owner_required", "only an owner can remove an owner")
		return
	}
	if role == "owner" && status == "active" {
		var owners int
		if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM tenant_members WHERE tenant_uid=$1 AND role='owner' AND status='active'`, p.TenantUID).Scan(&owners); err != nil || owners <= 1 {
			fail(w, r, http.StatusConflict, "last_owner", "the final active owner cannot be removed")
			return
		}
	}
	if _, err = tx.Exec(r.Context(), `DELETE FROM tenant_members WHERE tenant_uid=$1 AND uid=$2`, p.TenantUID, targetUID); err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid) VALUES($1,$2,'tenant_member',$3,'tenant_member.removed','tenant_member',$4)`, uuid.NewString(), p.TenantUID, p.MemberUID, targetUID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not remove Tenant Member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validMemberRole(role string) bool {
	return role == "owner" || role == "admin" || role == "developer" || role == "support" || role == "viewer"
}

func validInvitationRole(role string) bool {
	return role == "admin" || role == "developer" || role == "support" || role == "viewer"
}

func scanTenantInvitation(row rowScanner) (TenantInvitation, error) {
	var invitation TenantInvitation
	err := row.Scan(&invitation.UID, &invitation.Email, &invitation.Role, &invitation.Status, &invitation.CreatedAt, &invitation.ExpiresAt, &invitation.AcceptedAt, &invitation.RevokedAt)
	return invitation, err
}

func (s *Server) listTenantInvitations(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	query := `SELECT uid,email,role,CASE WHEN status='pending' AND expires_at<=now() THEN 'expired' ELSE status END,created_at,expires_at,accepted_at,revoked_at FROM tenant_invitations WHERE tenant_uid=$1`
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), query+` ORDER BY created_at DESC,uid DESC LIMIT $2`, p.TenantUID, limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), query+` AND (created_at,uid)<($2,$3::uuid) ORDER BY created_at DESC,uid DESC LIMIT $4`, p.TenantUID, cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load invitations")
		return
	}
	defer rows.Close()
	items := make([]TenantInvitation, 0, limit)
	for rows.Next() {
		invitation, scanErr := scanTenantInvitation(rows)
		if scanErr != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load invitations")
			return
		}
		items = append(items, invitation)
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

func (s *Server) createTenantInvitation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Email = normalizeEmail(in.Email)
	if in.Email == "" || !strings.Contains(in.Email, "@") || !validInvitationRole(in.Role) {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "a valid email and non-owner role are required")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		fail(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required")
		return
	}
	p := mustPrincipal(r)
	canonical, _ := json.Marshal(in)
	idemRequest := store.IdempotencyRequest{PrincipalType: "tenant_member", PrincipalUID: p.MemberUID, Operation: "tenant_invitations.create", Key: key, RequestHash: store.HashIdempotencyRequest(canonical), LeaseDuration: 30 * time.Second, Retention: 24 * time.Hour}
	claim, err := s.idempotency.Begin(r.Context(), idemRequest)
	if errors.Is(err, store.ErrIdempotencyConflict) {
		fail(w, r, http.StatusConflict, "idempotency_key_reused", "the idempotency key was already used with different inputs")
		return
	}
	if err != nil {
		fail(w, r, http.StatusServiceUnavailable, "dependency_unavailable", "idempotency coordination is unavailable")
		return
	}
	if claim.Replay != nil {
		writeStoredResponse(w, *claim.Replay)
		return
	}
	if claim.LeaseUID == uuid.Nil {
		seconds := int64(claim.RetryAfter / time.Second)
		if claim.RetryAfter%time.Second != 0 {
			seconds++
		}
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		fail(w, r, http.StatusConflict, "idempotency_in_progress", "an identical request is still being processed")
		return
	}

	token, err := security.RandomToken()
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create invitation")
		return
	}
	now, expiresAt, invitationUID := time.Now(), time.Now().Add(invitationTTL), uuid.NewString()
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create invitation")
		return
	}
	defer tx.Rollback(r.Context())
	var memberExists bool
	if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM tenant_members WHERE tenant_uid=$1 AND email_normalized=$2)`, p.TenantUID, in.Email).Scan(&memberExists); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create invitation")
		return
	}
	if memberExists {
		response := problemResponse(r, http.StatusConflict, "tenant_member_exists", "the email already belongs to this Tenant")
		if err = s.idempotency.CompleteTx(r.Context(), tx, idemRequest, claim.LeaseUID, response); err != nil || tx.Commit(r.Context()) != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not create invitation")
			return
		}
		writeStoredResponse(w, response)
		return
	}
	var inserted string
	err = tx.QueryRow(r.Context(), `INSERT INTO tenant_invitations(uid,tenant_uid,email,email_normalized,role,acceptance_token_hash,created_by_member_uid,expires_at) VALUES($1,$2,$3,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING RETURNING uid`, invitationUID, p.TenantUID, in.Email, in.Role, security.SessionHash(token), p.MemberUID, expiresAt).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		response := problemResponse(r, http.StatusConflict, "invitation_exists", "a pending invitation already exists for this email")
		if err = s.idempotency.CompleteTx(r.Context(), tx, idemRequest, claim.LeaseUID, response); err != nil || tx.Commit(r.Context()) != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not create invitation")
			return
		}
		writeStoredResponse(w, response)
		return
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create invitation")
		return
	}
	if _, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid,metadata) VALUES($1,$2,'tenant_member',$3,'tenant_invitation.created','tenant_invitation',$4,$5)`, uuid.NewString(), p.TenantUID, p.MemberUID, invitationUID, map[string]any{"role": in.Role}); err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create invitation")
		return
	}
	var tenantName string
	if err = tx.QueryRow(r.Context(), `SELECT name FROM tenants WHERE uid=$1`, p.TenantUID).Scan(&tenantName); err == nil {
		link := s.cfg.ConsoleOrigin + "/accept-invitation/" + invitationUID + "#token=" + token
		err = s.scheduleEmailDelivery(r.Context(), tx, p.TenantUID, "tenant_invitation", in.Email, emailDeliveryPayload{TenantName: tenantName, Link: link})
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create invitation")
		return
	}
	value := TenantInvitation{UID: invitationUID, Email: in.Email, Role: in.Role, Status: "pending", CreatedAt: now, ExpiresAt: expiresAt}
	body, _ := json.Marshal(value)
	body = append(body, '\n')
	response := store.StoredHTTPResponse{Status: http.StatusCreated, Headers: map[string][]string{"Content-Type": {"application/json"}, "Location": {"/v1/tenant/invitations/" + invitationUID}}, Body: body}
	if err = s.idempotency.CompleteTx(r.Context(), tx, idemRequest, claim.LeaseUID, response); err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not create invitation")
		return
	}
	writeStoredResponse(w, response)
}

func (s *Server) revokeTenantInvitation(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	command, err := s.db.Exec(r.Context(), `UPDATE tenant_invitations SET status='revoked',revoked_at=now(),revoked_by_member_uid=$3 WHERE tenant_uid=$1 AND uid=$2 AND status='pending' AND expires_at>now()`, p.TenantUID, r.PathValue("invitation_uid"), p.MemberUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not revoke invitation")
		return
	}
	if command.RowsAffected() == 0 {
		fail(w, r, http.StatusConflict, "invitation_not_pending", "invitation is missing, expired, or no longer pending")
		return
	}
	s.audit(r.Context(), p.TenantUID, "", "tenant_member", p.MemberUID, "tenant_invitation.revoked", "tenant_invitation", r.PathValue("invitation_uid"), nil, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) acceptTenantInvitation(w http.ResponseWriter, r *http.Request) {
	if !s.takeRateLimit(w, r, "tenant_invitation_accept", r.PathValue("invitation_uid")+"\x00"+s.clientIP(r), 10, 15*time.Minute) {
		return
	}
	var in struct {
		AcceptanceToken string `json:"acceptance_token"`
		Password        string `json:"password"`
		DisplayName     string `json:"display_name"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.AcceptanceToken == "" || in.DisplayName == "" {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", "acceptance_token, password, and display_name are required")
		return
	}
	passwordHash, err := security.HashPassword(in.Password)
	if err != nil {
		fail(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
		return
	}
	sessionToken, err := security.RandomToken()
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not accept invitation")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not accept invitation")
		return
	}
	defer tx.Rollback(r.Context())
	var tenant Tenant
	var email, role, status string
	var storedHash []byte
	var invitationExpires time.Time
	err = tx.QueryRow(r.Context(), `SELECT t.uid,t.name,t.slug,i.email,i.role,i.status,i.acceptance_token_hash,i.expires_at FROM tenant_invitations i JOIN tenants t ON t.uid=i.tenant_uid WHERE i.uid=$1 FOR UPDATE`, r.PathValue("invitation_uid")).Scan(&tenant.UID, &tenant.Name, &tenant.Slug, &email, &role, &status, &storedHash, &invitationExpires)
	providedHash := security.SessionHash(in.AcceptanceToken)
	if err != nil || status != "pending" || !invitationExpires.After(time.Now()) || subtle.ConstantTimeCompare(storedHash, providedHash) != 1 {
		fail(w, r, http.StatusUnauthorized, "invalid_invitation", "invitation is invalid, expired, or already used")
		return
	}
	memberUID, sessionUID := uuid.NewString(), uuid.NewString()
	var inserted string
	err = tx.QueryRow(r.Context(), `INSERT INTO tenant_members(uid,tenant_uid,email,email_normalized,display_name,role,password_hash,email_verified_at) VALUES($1,$2,$3,$3,$4,$5,$6,now()) ON CONFLICT (email_normalized) DO NOTHING RETURNING uid`, memberUID, tenant.UID, email, in.DisplayName, role, passwordHash).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, http.StatusConflict, "email_exists", "an account with this email already exists")
		return
	}
	expires, idle := time.Now().Add(s.cfg.MemberAbsoluteTTL), time.Now().Add(s.cfg.MemberIdleTTL)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE tenant_invitations SET status='accepted',accepted_at=now(),accepted_by_member_uid=$2 WHERE uid=$1`, r.PathValue("invitation_uid"), memberUID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO tenant_member_sessions(uid,tenant_member_uid,tenant_uid,session_secret_hash,expires_at,idle_expires_at) VALUES($1,$2,$3,$4,$5,$6)`, sessionUID, memberUID, tenant.UID, security.SessionHash(sessionToken), expires, idle)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,actor_type,actor_uid,action,target_type,target_uid) VALUES($1,$2,'tenant_member',$3,'tenant_invitation.accepted','tenant_member',$3)`, uuid.NewString(), tenant.UID, memberUID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not accept invitation")
		return
	}
	s.setMemberCookie(w, sessionToken, expires)
	writeJSON(w, http.StatusCreated, ConsoleSession{Tenant: tenant, Member: TenantMember{UID: memberUID, Email: email, DisplayName: in.DisplayName, Role: role, Status: "active", EmailVerified: true, CreatedAt: time.Now()}, AuthenticationAssurance: "bootstrap", ExpiresAt: expires})
}

func (s *Server) listMemberSessions(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	query := `SELECT uid,uid=$2,authentication_assurance,created_at,last_seen_at,expires_at FROM tenant_member_sessions WHERE tenant_member_uid=$1 AND tenant_uid=$3 AND revoked_at IS NULL AND expires_at>now() AND idle_expires_at>now()`
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), query+` ORDER BY created_at DESC,uid DESC LIMIT $4`, p.MemberUID, p.SessionUID, p.TenantUID, limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), query+` AND (created_at,uid)<($4,$5::uuid) ORDER BY created_at DESC,uid DESC LIMIT $6`, p.MemberUID, p.SessionUID, p.TenantUID, cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not load sessions")
		return
	}
	defer rows.Close()
	items := make([]TenantMemberSession, 0, limit)
	for rows.Next() {
		var item TenantMemberSession
		if err = rows.Scan(&item.UID, &item.Current, &item.AuthenticationAssurance, &item.CreatedAt, &item.LastSeenAt, &item.ExpiresAt); err != nil {
			fail(w, r, http.StatusInternalServerError, "internal_error", "could not load sessions")
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

func (s *Server) revokeMemberSession(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	command, err := s.db.Exec(r.Context(), `UPDATE tenant_member_sessions SET revoked_at=now() WHERE uid=$1 AND tenant_member_uid=$2 AND tenant_uid=$3 AND revoked_at IS NULL`, r.PathValue("session_uid"), p.MemberUID, p.TenantUID)
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "internal_error", "could not revoke session")
		return
	}
	if command.RowsAffected() == 0 {
		fail(w, r, http.StatusNotFound, "session_not_found", "active session was not found")
		return
	}
	if r.PathValue("session_uid") == p.SessionUID {
		http.SetCookie(w, &http.Cookie{Name: "complicatedauth_session", Value: "", Path: "/", HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(0, 0)})
	}
	w.WriteHeader(http.StatusNoContent)
}

func problemResponse(r *http.Request, status int, code, message string) store.StoredHTTPResponse {
	id, _ := r.Context().Value(contextKey("requestID")).(string)
	body, _ := json.Marshal(map[string]any{"error": map[string]any{"code": code, "message": message, "request_id": id}})
	body = append(body, '\n')
	return store.StoredHTTPResponse{Status: status, Headers: map[string][]string{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}, Body: body}
}

func writeStoredResponse(w http.ResponseWriter, response store.StoredHTTPResponse) {
	for name, values := range response.Headers {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.Status)
	_, _ = w.Write(response.Body)
}
