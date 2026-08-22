package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestBackgroundJobLeaseRecoveryRetryAndCompletion(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	if !strings.Contains(databaseURL, "/complicatedauth_test") {
		t.Fatal("integration tests require a dedicated complicatedauth_test database")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	schema := "background_jobs_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA %s`, schema)); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(ctx, fmt.Sprintf(`DROP SCHEMA %s CASCADE`, schema)) }()

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = Migrate(ctx, pool, "../../migrations"); err != nil {
		t.Fatal(err)
	}

	jobUID := uuid.New()
	if _, err = pool.Exec(ctx, `
		INSERT INTO background_jobs(uid, queue, job_type, payload, available_at, max_attempts)
		VALUES($1, 'retention', 'test.retry', '{"value":1}', clock_timestamp(), 2)
	`, jobUID); err != nil {
		t.Fatal(err)
	}
	jobStore := NewBackgroundJobStore(pool)
	first, err := jobStore.Claim(ctx, "retention", time.Minute)
	if err != nil || first == nil || first.UID != jobUID || first.Attempt != 1 {
		t.Fatalf("first claim=%+v err=%v", first, err)
	}
	contended, err := jobStore.Claim(ctx, "retention", time.Minute)
	if err != nil || contended != nil {
		t.Fatalf("contended claim=%+v err=%v", contended, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE background_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE uid=$1`, jobUID); err != nil {
		t.Fatal(err)
	}
	recovered, err := jobStore.Claim(ctx, "retention", time.Minute)
	if err != nil || recovered == nil || recovered.Attempt != 2 || recovered.LeaseUID == first.LeaseUID {
		t.Fatalf("recovered claim=%+v err=%v", recovered, err)
	}
	if err = jobStore.Complete(ctx, *first); !errors.Is(err, ErrBackgroundJobLeaseLost) {
		t.Fatalf("stale completion err=%v", err)
	}
	deadLettered, err := jobStore.Retry(ctx, *recovered, time.Now(), errors.New("synthetic failure"))
	if err != nil || !deadLettered {
		t.Fatalf("dead_lettered=%v err=%v", deadLettered, err)
	}
	var status, lastError string
	var deadLetteredAt *time.Time
	if err = pool.QueryRow(ctx, `SELECT status,last_error,dead_lettered_at FROM background_jobs WHERE uid=$1`, jobUID).Scan(&status, &lastError, &deadLetteredAt); err != nil {
		t.Fatal(err)
	}
	if status != "dead_lettered" || lastError != "synthetic failure" || deadLetteredAt == nil {
		t.Fatalf("status=%q last_error=%q dead_lettered_at=%v", status, lastError, deadLetteredAt)
	}
	deadJobs, err := jobStore.List(ctx, BackgroundJobListOptions{Status: "dead_lettered", Limit: 10})
	if err != nil || len(deadJobs) != 1 || deadJobs[0].UID != jobUID || deadJobs[0].LastError == nil {
		t.Fatalf("dead-letter list=%+v err=%v", deadJobs, err)
	}
	if err = jobStore.Replay(ctx, BackgroundJobReplay{
		JobUID: jobUID,
		Actor:  "on-call@example.com",
		Reason: "Dependency recovered after incident INC-42",
	}); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT status,attempts,last_error,dead_lettered_at FROM background_jobs WHERE uid=$1`, jobUID).Scan(&status, &recovered.Attempt, &deadJobs[0].LastError, &deadLetteredAt); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || recovered.Attempt != 0 || deadJobs[0].LastError != nil || deadLetteredAt != nil {
		t.Fatalf("replayed status=%q attempts=%d last_error=%v dead_lettered_at=%v", status, recovered.Attempt, deadJobs[0].LastError, deadLetteredAt)
	}
	var actionCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM platform_operator_actions WHERE target_uid=$1 AND action='background_job.replayed'`, jobUID).Scan(&actionCount); err != nil || actionCount != 1 {
		t.Fatalf("operator action count=%d err=%v", actionCount, err)
	}
	if err = jobStore.Replay(ctx, BackgroundJobReplay{
		JobUID: jobUID,
		Actor:  "on-call@example.com",
		Reason: "A duplicate operator request must be rejected",
	}); !errors.Is(err, ErrBackgroundJobNotDeadLettered) {
		t.Fatalf("duplicate replay err=%v", err)
	}
	if _, err = pool.Exec(ctx, `UPDATE platform_operator_actions SET reason='modified record' WHERE target_uid=$1`, jobUID); err == nil {
		t.Fatal("platform operator action was mutable")
	}
	if _, err = pool.Exec(ctx, `DELETE FROM background_jobs WHERE uid=$1`, jobUID); err != nil {
		t.Fatal(err)
	}

	completionUID := uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO background_jobs(uid,queue,job_type,payload) VALUES($1,'retention','test.complete','{}')`, completionUID); err != nil {
		t.Fatal(err)
	}
	completion, err := jobStore.Claim(ctx, "retention", time.Minute)
	if err != nil || completion == nil || completion.UID != completionUID {
		t.Fatalf("completion claim=%+v err=%v", completion, err)
	}
	deferredUntil := time.Now().Add(time.Hour)
	if err = jobStore.Reschedule(ctx, *completion, deferredUntil); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE background_jobs SET available_at=clock_timestamp() WHERE uid=$1`, completionUID); err != nil {
		t.Fatal(err)
	}
	completion, err = jobStore.Claim(ctx, "retention", time.Minute)
	if err != nil || completion == nil || completion.Attempt != 1 {
		t.Fatalf("rescheduled claim=%+v err=%v", completion, err)
	}
	if err = jobStore.Complete(ctx, *completion); err != nil {
		t.Fatal(err)
	}
	var completedAt *time.Time
	if err = pool.QueryRow(ctx, `SELECT status,completed_at FROM background_jobs WHERE uid=$1`, completionUID).Scan(&status, &completedAt); err != nil {
		t.Fatal(err)
	}
	if status != "completed" || completedAt == nil {
		t.Fatalf("status=%q completed_at=%v", status, completedAt)
	}
}
