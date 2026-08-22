package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrBackgroundJobLeaseLost       = errors.New("background job lease is no longer owned by this worker")
	ErrBackgroundJobNotFound        = errors.New("background job was not found")
	ErrBackgroundJobNotDeadLettered = errors.New("background job is not dead-lettered")
	backgroundJobQueue              = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
)

type BackgroundJobStore struct {
	db *pgxpool.Pool
}

type BackgroundJob struct {
	UID              uuid.UUID
	Queue            string
	Type             string
	DeduplicationKey *string
	Payload          json.RawMessage
	Attempt          int
	MaxAttempts      int
	LeaseUID         uuid.UUID
	LeaseExpiresAt   time.Time
	CreatedAt        time.Time
}

// BackgroundJobSummary is the intentionally payload-free representation used
// by the platform operator CLI. Job payloads can contain opaque identifiers
// that are not necessary for inspection and must not be dumped casually.
type BackgroundJobSummary struct {
	UID            uuid.UUID  `json:"uid"`
	Queue          string     `json:"queue"`
	Type           string     `json:"type"`
	Status         string     `json:"status"`
	Attempts       int        `json:"attempts"`
	MaxAttempts    int        `json:"max_attempts"`
	AvailableAt    time.Time  `json:"available_at"`
	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
	LastError      *string    `json:"last_error,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	DeadLetteredAt *time.Time `json:"dead_lettered_at,omitempty"`
}

type BackgroundJobListOptions struct {
	Status string
	Limit  int
}

type BackgroundJobReplay struct {
	JobUID uuid.UUID
	Actor  string
	Reason string
}

func NewBackgroundJobStore(db *pgxpool.Pool) *BackgroundJobStore {
	return &BackgroundJobStore{db: db}
}

// List returns bounded, payload-free operational metadata. It is deliberately
// not part of the customer API; background jobs are a deployment concern, not
// a public resource in the ComplicatedAuth contract.
func (s *BackgroundJobStore) List(ctx context.Context, options BackgroundJobListOptions) ([]BackgroundJobSummary, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("background job store database is required")
	}
	if options.Limit == 0 {
		options.Limit = 100
	}
	if options.Limit < 1 || options.Limit > 500 {
		return nil, errors.New("background job list limit must be between 1 and 500")
	}
	if options.Status != "" && options.Status != "pending" && options.Status != "running" && options.Status != "completed" && options.Status != "dead_lettered" {
		return nil, errors.New("background job status is invalid")
	}

	rows, err := s.db.Query(ctx, `
		SELECT uid,queue,job_type,status,attempts,max_attempts,available_at,
		       lease_expires_at,last_error,created_at,updated_at,completed_at,dead_lettered_at
		FROM background_jobs
		WHERE ($1='' OR status=$1)
		ORDER BY updated_at DESC,uid DESC
		LIMIT $2
	`, options.Status, options.Limit)
	if err != nil {
		return nil, fmt.Errorf("list background jobs: %w", err)
	}
	defer rows.Close()

	jobs := make([]BackgroundJobSummary, 0, options.Limit)
	for rows.Next() {
		var job BackgroundJobSummary
		if err = rows.Scan(
			&job.UID, &job.Queue, &job.Type, &job.Status, &job.Attempts,
			&job.MaxAttempts, &job.AvailableAt, &job.LeaseExpiresAt,
			&job.LastError, &job.CreatedAt, &job.UpdatedAt,
			&job.CompletedAt, &job.DeadLetteredAt,
		); err != nil {
			return nil, fmt.Errorf("scan background job: %w", err)
		}
		jobs = append(jobs, job)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("list background jobs: %w", err)
	}
	return jobs, nil
}

// Replay atomically records an immutable platform operator action and makes a
// dead-lettered job eligible from attempt one. Only an exhausted job may be
// replayed; pending, running, and completed work cannot be duplicated by this
// control surface.
func (s *BackgroundJobStore) Replay(ctx context.Context, replay BackgroundJobReplay) error {
	if s == nil || s.db == nil {
		return errors.New("background job store database is required")
	}
	actor := strings.TrimSpace(replay.Actor)
	reason := strings.TrimSpace(replay.Reason)
	if replay.JobUID == uuid.Nil {
		return errors.New("background job UID is required")
	}
	if actor == "" || len(actor) > 200 || actor != replay.Actor {
		return errors.New("operator actor must be between 1 and 200 trimmed characters")
	}
	if len(reason) < 10 || len(reason) > 1000 || reason != replay.Reason {
		return errors.New("operator reason must be between 10 and 1000 trimmed characters")
	}

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin background job replay: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var queue, jobType, status string
	var attempts, maxAttempts int
	var lastError *string
	err = tx.QueryRow(ctx, `
		SELECT queue,job_type,status,attempts,max_attempts,last_error
		FROM background_jobs WHERE uid=$1 FOR UPDATE
	`, replay.JobUID).Scan(&queue, &jobType, &status, &attempts, &maxAttempts, &lastError)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrBackgroundJobNotFound
	}
	if err != nil {
		return fmt.Errorf("lock background job for replay: %w", err)
	}
	if status != "dead_lettered" {
		return ErrBackgroundJobNotDeadLettered
	}

	metadata := map[string]any{
		"queue":          queue,
		"job_type":       jobType,
		"attempts":       attempts,
		"max_attempts":   maxAttempts,
		"had_last_error": lastError != nil,
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO platform_operator_actions(
			uid,actor,action,target_type,target_uid,reason,metadata
		) VALUES($1,$2,'background_job.replayed','background_job',$3,$4,$5)
	`, uuid.New(), actor, replay.JobUID, reason, metadata); err != nil {
		return fmt.Errorf("record background job replay: %w", err)
	}
	if _, err = tx.Exec(ctx, `
		UPDATE background_jobs
		SET status='pending',attempts=0,available_at=clock_timestamp(),
		    lease_uid=NULL,lease_expires_at=NULL,last_error=NULL,
		    completed_at=NULL,dead_lettered_at=NULL,updated_at=clock_timestamp()
		WHERE uid=$1
	`, replay.JobUID); err != nil {
		return fmt.Errorf("replay background job: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit background job replay: %w", err)
	}
	return nil
}

// Claim leases the oldest available job without blocking another replica.
// Expired leases are reclaimable, while an exhausted abandoned lease is moved
// to the dead-letter state before another job is selected.
func (s *BackgroundJobStore) Claim(ctx context.Context, queue string, leaseDuration time.Duration) (*BackgroundJob, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("background job store database is required")
	}
	if !backgroundJobQueue.MatchString(queue) {
		return nil, errors.New("background job queue is invalid")
	}
	if leaseDuration <= 0 {
		return nil, errors.New("background job lease duration must be positive")
	}
	leaseUID := uuid.New()
	leaseSeconds := durationSeconds(leaseDuration)

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin background job claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err = tx.Exec(ctx, `
		UPDATE background_jobs
		SET status='dead_lettered', lease_uid=NULL, lease_expires_at=NULL,
		    dead_lettered_at=clock_timestamp(), updated_at=clock_timestamp(),
		    last_error=COALESCE(last_error, 'worker lease expired after the maximum number of attempts')
		WHERE queue=$1
		  AND status='running'
		  AND lease_expires_at <= clock_timestamp()
		  AND attempts >= max_attempts
	`, queue); err != nil {
		return nil, fmt.Errorf("dead-letter exhausted background jobs: %w", err)
	}

	var job BackgroundJob
	err = tx.QueryRow(ctx, `
		WITH candidate AS (
			SELECT uid
			FROM background_jobs
			WHERE queue=$1
			  AND available_at <= clock_timestamp()
			  AND attempts < max_attempts
			  AND (
				status='pending'
				OR (status='running' AND lease_expires_at <= clock_timestamp())
			  )
			ORDER BY available_at ASC, created_at ASC, uid ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE background_jobs AS job
		SET status='running', attempts=job.attempts+1, lease_uid=$2,
		    lease_expires_at=clock_timestamp() + $3 * interval '1 second',
		    updated_at=clock_timestamp()
		FROM candidate
		WHERE job.uid=candidate.uid
		RETURNING job.uid, job.queue, job.job_type, job.deduplication_key,
		          job.payload, job.attempts, job.max_attempts, job.lease_uid,
		          job.lease_expires_at, job.created_at
	`, queue, leaseUID, leaseSeconds).Scan(
		&job.UID, &job.Queue, &job.Type, &job.DeduplicationKey, &job.Payload,
		&job.Attempt, &job.MaxAttempts, &job.LeaseUID, &job.LeaseExpiresAt, &job.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if err = tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit empty background job claim: %w", err)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim background job: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit background job claim: %w", err)
	}
	return &job, nil
}

func (s *BackgroundJobStore) Complete(ctx context.Context, job BackgroundJob) error {
	command, err := s.db.Exec(ctx, `
		UPDATE background_jobs
		SET status='completed', lease_uid=NULL, lease_expires_at=NULL,
		    completed_at=clock_timestamp(), updated_at=clock_timestamp(), last_error=NULL
		WHERE uid=$1 AND status='running' AND lease_uid=$2
	`, job.UID, job.LeaseUID)
	if err != nil {
		return fmt.Errorf("complete background job: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrBackgroundJobLeaseLost
	}
	return nil
}

// Retry releases a failed attempt. Once the configured bound is reached the
// job becomes dead-lettered and cannot be claimed again without an explicit
// operator action.
func (s *BackgroundJobStore) Retry(ctx context.Context, job BackgroundJob, availableAt time.Time, cause error) (bool, error) {
	message := "background job failed"
	if cause != nil {
		message = strings.TrimSpace(cause.Error())
		if message == "" {
			message = "background job failed"
		}
	}
	if len(message) > 2000 {
		message = message[:2000]
	}
	command, err := s.db.Exec(ctx, `
		UPDATE background_jobs
		SET status=CASE WHEN attempts >= max_attempts THEN 'dead_lettered' ELSE 'pending' END,
		    available_at=CASE WHEN attempts >= max_attempts THEN available_at ELSE $3 END,
		    lease_uid=NULL, lease_expires_at=NULL, completed_at=NULL,
		    dead_lettered_at=CASE WHEN attempts >= max_attempts THEN clock_timestamp() ELSE NULL END,
		    last_error=$4, updated_at=clock_timestamp()
		WHERE uid=$1 AND status='running' AND lease_uid=$2
	`, job.UID, job.LeaseUID, availableAt, message)
	if err != nil {
		return false, fmt.Errorf("retry background job: %w", err)
	}
	if command.RowsAffected() != 1 {
		return false, ErrBackgroundJobLeaseLost
	}
	return job.Attempt >= job.MaxAttempts, nil
}

// Reschedule releases a lease without consuming an attempt. It is for a job
// whose domain deadline moved, not for transient processing failures.
func (s *BackgroundJobStore) Reschedule(ctx context.Context, job BackgroundJob, availableAt time.Time) error {
	command, err := s.db.Exec(ctx, `
		UPDATE background_jobs
		SET status='pending', attempts=GREATEST(attempts-1, 0), available_at=$3,
		    lease_uid=NULL, lease_expires_at=NULL, completed_at=NULL,
		    dead_lettered_at=NULL, last_error=NULL, updated_at=clock_timestamp()
		WHERE uid=$1 AND status='running' AND lease_uid=$2
	`, job.UID, job.LeaseUID, availableAt)
	if err != nil {
		return fmt.Errorf("reschedule background job: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrBackgroundJobLeaseLost
	}
	return nil
}
