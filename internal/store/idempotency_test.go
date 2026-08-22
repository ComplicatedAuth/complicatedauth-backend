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

func TestIdempotencyLifecycle(t *testing.T) {
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

	schema := "idempotency_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

	store := NewIdempotencyStore(pool)
	request := IdempotencyRequest{
		PrincipalType: "tenant_member",
		PrincipalUID:  uuid.NewString(),
		Operation:     "projects.create",
		Key:           "idem_acceptance_test",
		RequestHash:   HashIdempotencyRequest([]byte(`{"name":"Example"}`)),
		LeaseDuration: time.Minute,
		Retention:     24 * time.Hour,
	}
	claim, err := store.Begin(ctx, request)
	if err != nil || claim.LeaseUID == uuid.Nil || claim.Replay != nil || claim.RetryAfter != 0 {
		t.Fatalf("first claim=%+v err=%v", claim, err)
	}

	contended, err := store.Begin(ctx, request)
	if err != nil || contended.LeaseUID != uuid.Nil || contended.RetryAfter <= 0 {
		t.Fatalf("contended claim=%+v err=%v", contended, err)
	}

	mismatch := request
	mismatch.RequestHash = HashIdempotencyRequest([]byte(`{"name":"Different"}`))
	if _, err = store.Begin(ctx, mismatch); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("mismatched request err=%v", err)
	}

	response := StoredHTTPResponse{
		Status:  201,
		Headers: map[string][]string{"Content-Type": {"application/json"}, "Location": {"/v1/projects/example"}},
		Body:    []byte(`{"uid":"example"}`),
	}
	if err = store.Complete(ctx, request, claim.LeaseUID, response); err != nil {
		t.Fatal(err)
	}
	replay, err := store.Begin(ctx, request)
	if err != nil || replay.Replay == nil {
		t.Fatalf("replay claim=%+v err=%v", replay, err)
	}
	if replay.Replay.Status != response.Status || string(replay.Replay.Body) != string(response.Body) || replay.Replay.Headers["Location"][0] != response.Headers["Location"][0] {
		t.Fatalf("replay=%+v want=%+v", replay.Replay, response)
	}
	if err = store.Complete(ctx, request, uuid.New(), response); !errors.Is(err, ErrIdempotencyLeaseLost) {
		t.Fatalf("stale completion err=%v", err)
	}

	if _, err = pool.Exec(ctx, `UPDATE idempotency_records SET expires_at=clock_timestamp() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	reused, err := store.Begin(ctx, mismatch)
	if err != nil || reused.LeaseUID == uuid.Nil {
		t.Fatalf("reused claim=%+v err=%v", reused, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE idempotency_records SET expires_at=clock_timestamp() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.DeleteExpired(ctx, 10)
	if err != nil || deleted != 1 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
}

func TestValidateIdempotencyRequest(t *testing.T) {
	valid := IdempotencyRequest{
		PrincipalType: "service_account",
		PrincipalUID:  "principal_123",
		Operation:     "support_cases.create",
		Key:           "idem_123",
		RequestHash:   HashIdempotencyRequest(nil),
		LeaseDuration: time.Minute,
		Retention:     time.Hour,
	}
	if err := validateIdempotencyRequest(valid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*IdempotencyRequest)
	}{
		{name: "principal type", mutate: func(request *IdempotencyRequest) { request.PrincipalType = "Tenant Member" }},
		{name: "principal uid", mutate: func(request *IdempotencyRequest) { request.PrincipalUID = " principal" }},
		{name: "operation", mutate: func(request *IdempotencyRequest) { request.Operation = "CreateProject" }},
		{name: "key", mutate: func(request *IdempotencyRequest) { request.Key = "key\nvalue" }},
		{name: "lease", mutate: func(request *IdempotencyRequest) { request.LeaseDuration = 0 }},
		{name: "retention", mutate: func(request *IdempotencyRequest) { request.Retention = request.LeaseDuration }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if err := validateIdempotencyRequest(request); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
