package api

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/complicatedauth/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type backgroundJobResult struct {
	rescheduleAt *time.Time
}

// RunBackgroundJobs processes durable jobs until ctx is cancelled. Every API
// replica may run workers: PostgreSQL leases and SKIP LOCKED provide exclusive
// ownership, and stale leases are recoverable after a process exits.
func (s *Server) RunBackgroundJobs(ctx context.Context) {
	workers := s.cfg.BackgroundJobWorkers
	if workers < 1 {
		workers = 2
	}
	poll := s.cfg.BackgroundJobPoll
	if poll <= 0 {
		poll = time.Second
	}
	lease := s.cfg.BackgroundJobLease
	if lease <= 0 {
		lease = 30 * time.Second
	}

	jobStore := store.NewBackgroundJobStore(s.db)
	var group sync.WaitGroup
	for worker := range workers {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			s.runBackgroundJobWorker(ctx, jobStore, worker, poll, lease)
		}(worker + 1)
	}
	group.Wait()
}

func (s *Server) runBackgroundJobWorker(ctx context.Context, jobStore *store.BackgroundJobStore, worker int, poll, lease time.Duration) {
	queues := []string{"retention", "email", "maintenance"}
	nextQueue := worker % len(queues)
	for ctx.Err() == nil {
		var (
			job *store.BackgroundJob
			err error
		)
		for offset := range len(queues) {
			queue := queues[(nextQueue+offset)%len(queues)]
			job, err = jobStore.Claim(ctx, queue, lease)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				s.log.Error("background job claim failed", "queue", queue, "worker", worker, "error", err)
				continue
			}
			if job != nil {
				nextQueue = (nextQueue + offset + 1) % len(queues)
				break
			}
		}
		if job == nil {
			if !waitForBackgroundJob(ctx, poll) {
				return
			}
			continue
		}

		result, handleErr := s.handleBackgroundJob(ctx, *job)
		if handleErr != nil {
			nextAttempt := time.Now().Add(backgroundJobRetryDelay(job.Attempt))
			deadLettered, retryErr := jobStore.Retry(ctx, *job, nextAttempt, handleErr)
			if retryErr != nil {
				if !errors.Is(retryErr, store.ErrBackgroundJobLeaseLost) && ctx.Err() == nil {
					s.log.Error("background job retry failed", "job_uid", job.UID, "job_type", job.Type, "error", retryErr)
				}
				continue
			}
			if deadLettered {
				s.log.Error("background job dead-lettered", "job_uid", job.UID, "job_type", job.Type, "attempts", job.Attempt, "error", handleErr)
			} else {
				s.log.Warn("background job scheduled for retry", "job_uid", job.UID, "job_type", job.Type, "attempt", job.Attempt, "available_at", nextAttempt, "error", handleErr)
			}
			continue
		}
		if result.rescheduleAt != nil {
			if err = jobStore.Reschedule(ctx, *job, *result.rescheduleAt); err != nil && !errors.Is(err, store.ErrBackgroundJobLeaseLost) && ctx.Err() == nil {
				s.log.Error("background job reschedule failed", "job_uid", job.UID, "job_type", job.Type, "error", err)
			}
			continue
		}
		if err = jobStore.Complete(ctx, *job); err != nil && !errors.Is(err, store.ErrBackgroundJobLeaseLost) && ctx.Err() == nil {
			s.log.Error("background job completion failed", "job_uid", job.UID, "job_type", job.Type, "error", err)
		}
	}
}

func (s *Server) handleBackgroundJob(ctx context.Context, job store.BackgroundJob) (backgroundJobResult, error) {
	switch job.Type {
	case "support_case.purge":
		return s.purgeSupportCase(ctx, job)
	case "email.delivery":
		var payload struct {
			DeliveryUID string `json:"delivery_uid"`
		}
		if err := json.Unmarshal(job.Payload, &payload); err != nil {
			return backgroundJobResult{}, fmt.Errorf("decode email delivery payload: %w", err)
		}
		if _, err := uuid.Parse(payload.DeliveryUID); err != nil {
			return backgroundJobResult{}, errors.New("email delivery payload has an invalid delivery_uid")
		}
		return backgroundJobResult{}, s.deliverEmail(ctx, payload.DeliveryUID)
	case "maintenance.cleanup":
		return s.runMaintenanceCleanup(ctx)
	default:
		return backgroundJobResult{}, fmt.Errorf("unsupported background job type %q", job.Type)
	}
}

func (s *Server) purgeSupportCase(ctx context.Context, job store.BackgroundJob) (backgroundJobResult, error) {
	var payload struct {
		CaseUID string `json:"case_uid"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return backgroundJobResult{}, fmt.Errorf("decode support case purge payload: %w", err)
	}
	if _, err := uuid.Parse(payload.CaseUID); err != nil {
		return backgroundJobResult{}, errors.New("support case purge payload has an invalid case_uid")
	}

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return backgroundJobResult{}, fmt.Errorf("begin support case purge: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		tenantUID     string
		projectUID    *string
		caseReference string
		category      string
		status        string
		retention     *time.Time
		databaseNow   time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT tenant_uid, project_uid, case_reference, category, status,
		       retention_until, clock_timestamp()
		FROM support_cases
		WHERE uid=$1
		FOR UPDATE
	`, payload.CaseUID).Scan(&tenantUID, &projectUID, &caseReference, &category, &status, &retention, &databaseNow)
	if errors.Is(err, pgx.ErrNoRows) {
		if err = tx.Commit(ctx); err != nil {
			return backgroundJobResult{}, fmt.Errorf("commit missing support case purge: %w", err)
		}
		return backgroundJobResult{}, nil
	}
	if err != nil {
		return backgroundJobResult{}, fmt.Errorf("lock support case for purge: %w", err)
	}
	if status != "closed" || retention == nil {
		if err = tx.Commit(ctx); err != nil {
			return backgroundJobResult{}, fmt.Errorf("commit cancelled support case purge: %w", err)
		}
		return backgroundJobResult{}, nil
	}
	if retention.After(databaseNow) {
		if err = tx.Commit(ctx); err != nil {
			return backgroundJobResult{}, fmt.Errorf("commit deferred support case purge: %w", err)
		}
		return backgroundJobResult{rescheduleAt: retention}, nil
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_events(
			uid, tenant_uid, project_uid, actor_type, actor_uid,
			action, target_type, target_uid, metadata
		)
		VALUES($1,$2,$3,'system',NULL,'support_case.purged','support_case',$4,$5)
	`, uuid.New(), tenantUID, projectUID, payload.CaseUID, map[string]any{
		"case_reference":  caseReference,
		"category":        category,
		"retention_until": retention,
	})
	if err == nil {
		_, err = tx.Exec(ctx, `DELETE FROM support_cases WHERE uid=$1`, payload.CaseUID)
	}
	if err != nil {
		return backgroundJobResult{}, fmt.Errorf("purge support case: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return backgroundJobResult{}, fmt.Errorf("commit support case purge: %w", err)
	}
	s.log.Info("support case purged by retention policy", "case_uid", payload.CaseUID, "case_reference", caseReference)
	return backgroundJobResult{}, nil
}

func waitForBackgroundJob(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func backgroundJobRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 9 {
		attempt = 9
	}
	base := time.Second * time.Duration(1<<(attempt-1))
	if base > 5*time.Minute {
		base = 5 * time.Minute
	}
	var random [1]byte
	if _, err := crand.Read(random[:]); err != nil {
		return base
	}
	return base + time.Duration(int64(base)/4*int64(random[0])/255)
}
