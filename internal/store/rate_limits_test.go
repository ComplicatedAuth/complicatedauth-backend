package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRateLimiterIsSharedAndExpires(t *testing.T) {
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
	schema := "rate_limits_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

	firstReplica := NewRateLimiter(pool)
	secondReplica := NewRateLimiter(pool)
	key := HashIdempotencyRequest([]byte("not-a-raw-identifier"))
	var wait sync.WaitGroup
	results := make(chan RateLimitResult, 6)
	errorsByWorker := make(chan error, 6)
	for index := range 6 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			limiter := firstReplica
			if index%2 == 1 {
				limiter = secondReplica
			}
			result, takeErr := limiter.Take(ctx, "console_login_identity", key[:], 5, 15*time.Minute)
			results <- result
			errorsByWorker <- takeErr
		}()
	}
	wait.Wait()
	close(results)
	close(errorsByWorker)
	for takeErr := range errorsByWorker {
		if takeErr != nil {
			t.Fatal(takeErr)
		}
	}
	allowed, denied := 0, 0
	for result := range results {
		if result.Allowed {
			allowed++
		} else {
			denied++
			if result.RetryAfter <= 0 || result.Remaining != 0 {
				t.Fatalf("denied result=%+v", result)
			}
		}
	}
	if allowed != 5 || denied != 1 {
		t.Fatalf("allowed=%d denied=%d", allowed, denied)
	}

	if err = firstReplica.Reset(ctx, "console_login_identity", key[:]); err != nil {
		t.Fatal(err)
	}
	reset, err := secondReplica.Take(ctx, "console_login_identity", key[:], 5, 15*time.Minute)
	if err != nil || !reset.Allowed || reset.Remaining != 4 {
		t.Fatalf("reset result=%+v err=%v", reset, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE rate_limit_buckets SET expires_at=clock_timestamp() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	expired, err := firstReplica.Take(ctx, "console_login_identity", key[:], 5, 15*time.Minute)
	if err != nil || !expired.Allowed || expired.Remaining != 4 {
		t.Fatalf("expired result=%+v err=%v", expired, err)
	}
}
