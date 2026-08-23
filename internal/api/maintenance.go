package api

import (
	"context"
	"fmt"
	"time"

	"github.com/complicatedauth/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
)

const (
	maintenanceCleanupBatch = 1000
	maintenanceInterval     = time.Hour
)

type maintenanceCleanup struct {
	name  string
	query string
}

func (s *Server) ensureMaintenanceJob(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO background_jobs(
			uid,queue,job_type,deduplication_key,payload,max_attempts
		) VALUES($1,'maintenance','maintenance.cleanup','global','{}',12)
		ON CONFLICT(queue,deduplication_key) DO NOTHING
	`, uuid.New())
	if err != nil {
		return fmt.Errorf("initialize maintenance cleanup job: %w", err)
	}
	return nil
}

// runMaintenanceCleanup removes only records whose protocol lifetime and
// documented diagnostic retention have ended. Each statement is a bounded,
// independently committed batch: partial completion is safe because every
// predicate is monotonic and every delete is idempotent.
func (s *Server) runMaintenanceCleanup(ctx context.Context) (backgroundJobResult, error) {
	deletedIdempotency, err := store.NewIdempotencyStore(s.db).DeleteExpired(ctx, maintenanceCleanupBatch)
	if err != nil {
		return backgroundJobResult{}, err
	}
	if deletedIdempotency > 0 {
		s.log.Info("maintenance records deleted", "record_type", "idempotency_records", "count", deletedIdempotency)
	}
	batchWasFull := deletedIdempotency == maintenanceCleanupBatch

	cleanups := []maintenanceCleanup{
		{
			name: "rate_limit_buckets",
			query: `WITH expired AS (
				SELECT policy,key_hash FROM rate_limit_buckets
				WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT $1
			) DELETE FROM rate_limit_buckets AS target USING expired
			WHERE target.policy=expired.policy AND target.key_hash=expired.key_hash`,
		},
		{
			name: "project_user_login_attempts",
			query: `WITH expired AS (
				SELECT uid FROM project_user_login_attempts
				WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT $1
			) DELETE FROM project_user_login_attempts AS target USING expired
			WHERE target.uid=expired.uid`,
		},
		{
			name: "webauthn_ceremonies",
			query: `WITH expired AS (
				SELECT uid FROM webauthn_ceremonies
				WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT $1
			) DELETE FROM webauthn_ceremonies AS target USING expired
			WHERE target.uid=expired.uid`,
		},
		{
			name: "tenant_member_login_attempts",
			query: `WITH expired AS (
				SELECT uid FROM tenant_member_login_attempts
				WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT $1
			) DELETE FROM tenant_member_login_attempts AS target USING expired
			WHERE target.uid=expired.uid`,
		},
		{
			name: "tenant_member_webauthn_ceremonies",
			query: `WITH expired AS (
				SELECT uid FROM tenant_member_webauthn_ceremonies
				WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT $1
			) DELETE FROM tenant_member_webauthn_ceremonies AS target USING expired
			WHERE target.uid=expired.uid`,
		},
		{
			name: "tenant_member_email_verifications",
			query: `WITH expired AS (
				SELECT uid FROM tenant_member_email_verifications
				WHERE expires_at<=clock_timestamp()-interval '7 days'
				   OR consumed_at<=clock_timestamp()-interval '7 days'
				   OR revoked_at<=clock_timestamp()-interval '7 days'
				ORDER BY created_at LIMIT $1
			) DELETE FROM tenant_member_email_verifications AS target USING expired
			WHERE target.uid=expired.uid`,
		},
		{
			name: "tenant_member_password_resets",
			query: `WITH expired AS (
				SELECT uid FROM tenant_member_password_resets
				WHERE expires_at<=clock_timestamp()-interval '7 days'
				   OR consumed_at<=clock_timestamp()-interval '7 days'
				   OR revoked_at<=clock_timestamp()-interval '7 days'
				ORDER BY created_at LIMIT $1
			) DELETE FROM tenant_member_password_resets AS target USING expired
			WHERE target.uid=expired.uid`,
		},
		{
			name: "tenant_member_sessions",
			query: `WITH expired AS (
				SELECT uid FROM tenant_member_sessions
				WHERE expires_at<=clock_timestamp()-interval '30 days'
				   OR idle_expires_at<=clock_timestamp()-interval '30 days'
				   OR revoked_at<=clock_timestamp()-interval '30 days'
				ORDER BY created_at LIMIT $1
			) DELETE FROM tenant_member_sessions AS target USING expired
			WHERE target.uid=expired.uid`,
		},
		{
			name: "project_user_sessions",
			query: `WITH expired AS (
				SELECT uid FROM project_user_sessions
				WHERE expires_at<=clock_timestamp()-interval '30 days'
				   OR idle_expires_at<=clock_timestamp()-interval '30 days'
				   OR revoked_at<=clock_timestamp()-interval '30 days'
				ORDER BY created_at LIMIT $1
			) DELETE FROM project_user_sessions AS target USING expired
			WHERE target.uid=expired.uid`,
		},
		{
			name: "oauth_authorization_requests",
			query: `WITH expired AS (
				SELECT uid FROM oauth_authorization_requests
				WHERE expires_at<=clock_timestamp()-interval '24 hours'
				   OR resolved_at<=clock_timestamp()-interval '24 hours'
				ORDER BY created_at LIMIT $1
			) DELETE FROM oauth_authorization_requests AS target USING expired
			WHERE target.uid=expired.uid`,
		},
		{
			name: "oauth_authorization_codes",
			query: `WITH expired AS (
				SELECT uid FROM oauth_authorization_codes
				WHERE expires_at<=clock_timestamp()-interval '24 hours'
				   OR consumed_at<=clock_timestamp()-interval '24 hours'
				ORDER BY created_at LIMIT $1
			) DELETE FROM oauth_authorization_codes AS target USING expired
			WHERE target.uid=expired.uid`,
		},
		{
			name: "oauth_access_tokens",
			query: `WITH expired AS (
				SELECT uid FROM oauth_access_tokens
				WHERE expires_at<=clock_timestamp()-interval '24 hours'
				   OR revoked_at<=clock_timestamp()-interval '24 hours'
				ORDER BY created_at LIMIT $1
			) DELETE FROM oauth_access_tokens AS target USING expired
			WHERE target.uid=expired.uid`,
		},
		{
			name: "tenant_invitations",
			query: `WITH expired AS (
				SELECT uid FROM tenant_invitations
				WHERE (status='accepted' AND accepted_at<=clock_timestamp()-interval '90 days')
				   OR (status='revoked' AND revoked_at<=clock_timestamp()-interval '90 days')
				   OR (status='pending' AND expires_at<=clock_timestamp()-interval '90 days')
				ORDER BY created_at LIMIT $1
			) DELETE FROM tenant_invitations AS target USING expired
			WHERE target.uid=expired.uid`,
		},
		{
			name: "email_deliveries",
			query: `WITH expired AS (
				SELECT uid FROM email_deliveries
				WHERE status='delivered' AND delivered_at<=clock_timestamp()-interval '30 days'
				ORDER BY delivered_at LIMIT $1
			) DELETE FROM email_deliveries AS target USING expired
			WHERE target.uid=expired.uid`,
		},
		{
			name: "background_jobs",
			query: `WITH expired AS (
				SELECT uid FROM background_jobs
				WHERE status='completed' AND completed_at<=clock_timestamp()-interval '7 days'
				ORDER BY completed_at LIMIT $1
			) DELETE FROM background_jobs AS target USING expired
			WHERE target.uid=expired.uid`,
		},
	}

	for _, cleanup := range cleanups {
		command, cleanupErr := s.db.Exec(ctx, cleanup.query, maintenanceCleanupBatch)
		if cleanupErr != nil {
			return backgroundJobResult{}, fmt.Errorf("clean up %s: %w", cleanup.name, cleanupErr)
		}
		if command.RowsAffected() > 0 {
			s.log.Info("maintenance records deleted", "record_type", cleanup.name, "count", command.RowsAffected())
		}
		if command.RowsAffected() == maintenanceCleanupBatch {
			batchWasFull = true
		}
	}

	nextDelay := maintenanceInterval
	if batchWasFull {
		// Drain a backlog promptly without turning cleanup into an unbounded
		// transaction or holding one worker lease for an arbitrary duration.
		nextDelay = time.Minute
	}
	var next time.Time
	if err = s.db.QueryRow(ctx, `SELECT clock_timestamp()+$1*interval '1 second'`, int64(nextDelay/time.Second)).Scan(&next); err != nil {
		return backgroundJobResult{}, fmt.Errorf("schedule next maintenance cleanup: %w", err)
	}
	return backgroundJobResult{rescheduleAt: &next}, nil
}
