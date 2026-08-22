package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	limit, cursor, err := pagination(r)
	if err != nil {
		fail(w, r, 400, "invalid_pagination", err.Error())
		return
	}
	var rows pgx.Rows
	if cursor == nil {
		rows, err = s.db.Query(r.Context(), `SELECT uid,created_at FROM projects WHERE tenant_uid=$1 ORDER BY created_at DESC,uid DESC LIMIT $2`, p.TenantUID, limit+1)
	} else {
		rows, err = s.db.Query(r.Context(), `SELECT uid,created_at FROM projects WHERE tenant_uid=$1 AND (created_at,uid)<($2,$3::uuid) ORDER BY created_at DESC,uid DESC LIMIT $4`, p.TenantUID, cursor.CreatedAt, cursor.UID, limit+1)
	}
	if err != nil {
		fail(w, r, 500, "internal_error", "could not load projects")
		return
	}
	defer rows.Close()
	var items []Project
	var positions []pageCursor
	for rows.Next() {
		var uid string
		var createdAt time.Time
		if rows.Scan(&uid, &createdAt) != nil {
			continue
		}
		project, err := s.loadProject(r.Context(), p.TenantUID, uid)
		if err == nil {
			items = append(items, project)
			positions = append(positions, pageCursor{CreatedAt: createdAt, UID: uid})
		}
	}
	if items == nil {
		items = []Project{}
	}
	var next any
	if len(items) > limit {
		position := positions[limit-1]
		next = nextCursor(position.CreatedAt, position.UID)
		items = items[:limit]
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	var in struct {
		Name          string `json:"name"`
		Environment   string `json:"environment"`
		RPID          string `json:"rp_id"`
		RPName        string `json:"rp_name"`
		InitialOrigin string `json:"initial_origin"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.RPID = strings.ToLower(strings.TrimSpace(in.RPID))
	in.RPName = strings.TrimSpace(in.RPName)
	canonical, err := validateOrigin(in.InitialOrigin, in.RPID)
	if err != nil || in.Name == "" || in.RPName == "" || (in.Environment != "sandbox" && in.Environment != "production") || !validRPID(in.RPID) {
		fail(w, r, 422, "validation_failed", "project values, RP ID, or Origin are invalid")
		return
	}
	projectUID, originUID := uuid.NewString(), uuid.NewString()
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		fail(w, r, 500, "internal_error", "could not create project")
		return
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO projects(uid,tenant_uid,name,environment,rp_id,rp_name) VALUES($1,$2,$3,$4,$5,$6)`, projectUID, p.TenantUID, in.Name, in.Environment, in.RPID, in.RPName)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO project_origins(uid,project_uid,origin) VALUES($1,$2,$3)`, originUID, projectUID, canonical)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(uid,tenant_uid,project_uid,actor_type,actor_uid,action,target_type,target_uid) VALUES($1,$2,$3,'tenant_member',$4,'project.created','project',$3)`, uuid.NewString(), p.TenantUID, projectUID, p.MemberUID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, r, 500, "internal_error", "could not create project")
		return
	}
	project, err := s.loadProject(r.Context(), p.TenantUID, projectUID)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not load project")
		return
	}
	writeJSON(w, 201, project)
}

func (s *Server) getProjectHandler(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	project, err := s.loadProject(r.Context(), p.TenantUID, r.PathValue("project_uid"))
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, r, 404, "not_found", "project not found")
		return
	}
	if err != nil {
		fail(w, r, 500, "internal_error", "could not load project")
		return
	}
	writeJSON(w, 200, project)
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	project, err := s.loadProject(r.Context(), p.TenantUID, r.PathValue("project_uid"))
	if err != nil {
		fail(w, r, 404, "not_found", "project not found")
		return
	}
	var in struct {
		Name        *string `json:"name"`
		Environment *string `json:"environment"`
		Status      *string `json:"status"`
		RPID        *string `json:"rp_id"`
		RPName      *string `json:"rp_name"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Name != nil {
		project.Name = strings.TrimSpace(*in.Name)
	}
	if in.Environment != nil {
		project.Environment = *in.Environment
	}
	if in.Status != nil {
		project.Status = *in.Status
	}
	if in.RPName != nil {
		project.RPName = strings.TrimSpace(*in.RPName)
	}
	if in.RPID != nil {
		next := strings.ToLower(strings.TrimSpace(*in.RPID))
		if project.RPIDLocked && next != project.RPID {
			fail(w, r, 409, "rp_id_locked", "RP ID is permanently locked after the first passkey registration")
			return
		}
		project.RPID = next
	}
	if project.Name == "" || project.RPName == "" || (project.Environment != "sandbox" && project.Environment != "production") || (project.Status != "active" && project.Status != "disabled") || !validRPID(project.RPID) {
		fail(w, r, 422, "validation_failed", "project values are invalid")
		return
	}
	for _, origin := range project.Origins {
		if _, err := validateOrigin(origin.Origin, project.RPID); err != nil {
			fail(w, r, 422, "origin_rp_mismatch", "existing Origins are incompatible with this RP ID")
			return
		}
	}
	result, err := s.db.Exec(r.Context(), `UPDATE projects SET name=$3,environment=$4,status=$5,rp_id=$6,rp_name=$7,updated_at=now() WHERE uid=$1 AND tenant_uid=$2 AND (rp_id=$6 OR rp_id_locked_at IS NULL)`, project.UID, p.TenantUID, project.Name, project.Environment, project.Status, project.RPID, project.RPName)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not update project")
		return
	}
	if result.RowsAffected() == 0 {
		fail(w, r, 409, "rp_id_locked", "RP ID is permanently locked")
		return
	}
	s.audit(r.Context(), p.TenantUID, project.UID, "tenant_member", p.MemberUID, "project.updated", "project", project.UID, nil, r)
	project, _ = s.loadProject(r.Context(), p.TenantUID, project.UID)
	writeJSON(w, 200, project)
}

func (s *Server) loadProject(ctx context.Context, tenantUID, projectUID string) (Project, error) {
	var p Project
	err := s.db.QueryRow(ctx, `SELECT uid,name,environment,status,rp_id,rp_name,(rp_id_locked_at IS NOT NULL),created_at,(SELECT count(*) FROM project_origins WHERE project_uid=projects.uid),(SELECT count(*) FROM project_users WHERE project_uid=projects.uid),(SELECT count(*) FROM project_service_accounts WHERE project_uid=projects.uid AND status='active' AND deleted_at IS NULL) FROM projects WHERE uid=$1 AND tenant_uid=$2`, projectUID, tenantUID).Scan(&p.UID, &p.Name, &p.Environment, &p.Status, &p.RPID, &p.RPName, &p.RPIDLocked, &p.CreatedAt, &p.OriginCount, &p.UserCount, &p.ServiceAccountCount)
	if err != nil {
		return p, err
	}
	rows, err := s.db.Query(ctx, `SELECT uid,origin,created_at FROM project_origins WHERE project_uid=$1 ORDER BY created_at`, p.UID)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	p.Origins = []Origin{}
	for rows.Next() {
		var o Origin
		if err = rows.Scan(&o.UID, &o.Origin, &o.CreatedAt); err != nil {
			return p, err
		}
		p.Origins = append(p.Origins, o)
	}
	return p, rows.Err()
}

func (s *Server) listOrigins(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	project, err := s.loadProject(r.Context(), p.TenantUID, r.PathValue("project_uid"))
	if err != nil {
		fail(w, r, 404, "not_found", "project not found")
		return
	}
	writeJSON(w, 200, map[string]any{"items": project.Origins})
}
func (s *Server) createOrigin(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	project, err := s.loadProject(r.Context(), p.TenantUID, r.PathValue("project_uid"))
	if err != nil {
		fail(w, r, 404, "not_found", "project not found")
		return
	}
	var in struct{ Origin string }
	if !decode(w, r, &in) {
		return
	}
	canonical, err := validateOrigin(in.Origin, project.RPID)
	if err != nil {
		fail(w, r, 422, "invalid_origin", err.Error())
		return
	}
	origin := Origin{UID: uuid.NewString(), Origin: canonical, CreatedAt: time.Now().UTC()}
	_, err = s.db.Exec(r.Context(), `INSERT INTO project_origins(uid,project_uid,origin) VALUES($1,$2,$3)`, origin.UID, project.UID, origin.Origin)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			fail(w, r, 409, "origin_exists", "Origin is already configured")
		} else {
			fail(w, r, 500, "internal_error", "could not add Origin")
		}
		return
	}
	s.audit(r.Context(), p.TenantUID, project.UID, "tenant_member", p.MemberUID, "origin.created", "origin", origin.UID, map[string]any{"origin": origin.Origin}, r)
	writeJSON(w, 201, origin)
}
func (s *Server) deleteOrigin(w http.ResponseWriter, r *http.Request) {
	p := mustPrincipal(r)
	project, err := s.loadProject(r.Context(), p.TenantUID, r.PathValue("project_uid"))
	if err != nil {
		fail(w, r, 404, "not_found", "project not found")
		return
	}
	if len(project.Origins) <= 1 {
		fail(w, r, 409, "last_origin", "a Project must keep at least one Origin")
		return
	}
	result, err := s.db.Exec(r.Context(), `DELETE FROM project_origins WHERE uid=$1 AND project_uid=$2`, r.PathValue("origin_uid"), project.UID)
	if err != nil {
		fail(w, r, 500, "internal_error", "could not delete Origin")
		return
	}
	if result.RowsAffected() == 0 {
		fail(w, r, 404, "not_found", "Origin not found")
		return
	}
	s.audit(r.Context(), p.TenantUID, project.UID, "tenant_member", p.MemberUID, "origin.deleted", "origin", r.PathValue("origin_uid"), nil, r)
	w.WriteHeader(204)
}

func (s *Server) ownsProject(ctx context.Context, tenantUID, projectUID string) bool {
	var exists bool
	_ = s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE uid=$1 AND tenant_uid=$2)`, projectUID, tenantUID).Scan(&exists)
	return exists
}
func validRPID(v string) bool {
	if v == "localhost" {
		return true
	}
	if strings.ContainsAny(v, "/: ") || net.ParseIP(v) != nil {
		return false
	}
	return strings.Contains(v, ".") && !strings.HasPrefix(v, ".") && !strings.HasSuffix(v, ".")
}
func validateOrigin(raw, rpID string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("Origin must contain only scheme, host, and optional port")
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && isLocalDevelopmentHostname(host)) {
		return "", errors.New("Origin must use HTTPS except for localhost or loopback")
	}
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return "", errors.New("Origin host must equal or be a subdomain of the RP ID")
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}

func (s *Server) audit(ctx context.Context, tenantUID, projectUID, actorType, actorUID, action, targetType, targetUID string, metadata map[string]any, r *http.Request) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	raw, _ := json.Marshal(metadata)
	var project any
	if projectUID != "" {
		project = projectUID
	}
	var actor, target any
	if actorUID != "" {
		actor = actorUID
	}
	if targetUID != "" {
		target = targetUID
	}
	_, _ = s.db.Exec(ctx, `INSERT INTO audit_events(uid,tenant_uid,project_uid,actor_type,actor_uid,action,target_type,target_uid,metadata,source_ip,user_agent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, uuid.NewString(), tenantUID, project, actorType, actor, action, targetType, target, raw, s.clientIP(r), r.UserAgent())
}
