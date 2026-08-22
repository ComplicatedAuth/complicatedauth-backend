package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrIdempotencyConflict   = errors.New("idempotency key was already used with a different request")
	ErrIdempotencyLeaseLost  = errors.New("idempotency lease is no longer owned by this request")
	idempotencyPrincipalType = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	idempotencyOperation     = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,127}$`)
)

type IdempotencyStore struct {
	db *pgxpool.Pool
}

type IdempotencyRequest struct {
	PrincipalType string
	PrincipalUID  string
	Operation     string
	Key           string
	RequestHash   [sha256.Size]byte
	LeaseDuration time.Duration
	Retention     time.Duration
}

type IdempotencyClaim struct {
	LeaseUID   uuid.UUID
	RetryAfter time.Duration
	Replay     *StoredHTTPResponse
}

type StoredHTTPResponse struct {
	Status  int
	Headers map[string][]string
	Body    []byte
}

func NewIdempotencyStore(db *pgxpool.Pool) *IdempotencyStore {
	return &IdempotencyStore{db: db}
}

// HashIdempotencyRequest returns the digest persisted with an idempotency key.
// Callers should hash a canonical representation that includes every input
// capable of changing the operation's result, including path parameters.
func HashIdempotencyRequest(canonicalRequest []byte) [sha256.Size]byte {
	return sha256.Sum256(canonicalRequest)
}

// Begin atomically claims a new request, returns an exact completed response,
// or reports how long the current owner retains its processing lease. A key is
// scoped by principal and operation, so unrelated tenants cannot collide.
func (s *IdempotencyStore) Begin(ctx context.Context, request IdempotencyRequest) (IdempotencyClaim, error) {
	if err := validateIdempotencyRequest(request); err != nil {
		return IdempotencyClaim{}, err
	}
	leaseUID := uuid.New()
	leaseSeconds := durationSeconds(request.LeaseDuration)
	retentionSeconds := durationSeconds(request.Retention)

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return IdempotencyClaim{}, fmt.Errorf("begin idempotency claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	command, err := tx.Exec(ctx, `
		INSERT INTO idempotency_records(
			principal_type, principal_uid, operation, idempotency_key,
			request_hash, state, lease_uid, lease_expires_at, expires_at
		)
		VALUES($1, $2, $3, $4, $5, 'processing', $6,
			clock_timestamp() + $7 * interval '1 second',
			clock_timestamp() + $8 * interval '1 second')
		ON CONFLICT DO NOTHING
	`, request.PrincipalType, request.PrincipalUID, request.Operation, request.Key,
		request.RequestHash[:], leaseUID, leaseSeconds, retentionSeconds)
	if err != nil {
		return IdempotencyClaim{}, fmt.Errorf("insert idempotency claim: %w", err)
	}
	if command.RowsAffected() == 1 {
		if err = tx.Commit(ctx); err != nil {
			return IdempotencyClaim{}, fmt.Errorf("commit idempotency claim: %w", err)
		}
		return IdempotencyClaim{LeaseUID: leaseUID}, nil
	}

	var (
		storedHash     []byte
		state          string
		leaseExpiresAt time.Time
		expiresAt      time.Time
		databaseNow    time.Time
		status         *int
		headersJSON    []byte
		body           []byte
	)
	err = tx.QueryRow(ctx, `
		SELECT request_hash, state, lease_expires_at, expires_at, clock_timestamp(),
		       response_status, response_headers, response_body
		FROM idempotency_records
		WHERE principal_type=$1 AND principal_uid=$2 AND operation=$3 AND idempotency_key=$4
		FOR UPDATE
	`, request.PrincipalType, request.PrincipalUID, request.Operation, request.Key).Scan(
		&storedHash, &state, &leaseExpiresAt, &expiresAt, &databaseNow, &status, &headersJSON, &body,
	)
	if err != nil {
		return IdempotencyClaim{}, fmt.Errorf("read idempotency claim: %w", err)
	}

	if expiresAt.After(databaseNow) && !equalDigest(storedHash, request.RequestHash) {
		return IdempotencyClaim{}, ErrIdempotencyConflict
	}
	if !expiresAt.After(databaseNow) || (state == "processing" && !leaseExpiresAt.After(databaseNow)) {
		_, err = tx.Exec(ctx, `
			UPDATE idempotency_records
			SET request_hash=$5, state='processing', lease_uid=$6,
			    lease_expires_at=clock_timestamp() + $7 * interval '1 second',
			    response_status=NULL, response_headers=NULL, response_body=NULL,
			    created_at=clock_timestamp(), completed_at=NULL,
			    expires_at=clock_timestamp() + $8 * interval '1 second'
			WHERE principal_type=$1 AND principal_uid=$2 AND operation=$3 AND idempotency_key=$4
		`, request.PrincipalType, request.PrincipalUID, request.Operation, request.Key,
			request.RequestHash[:], leaseUID, leaseSeconds, retentionSeconds)
		if err != nil {
			return IdempotencyClaim{}, fmt.Errorf("reclaim idempotency lease: %w", err)
		}
		if err = tx.Commit(ctx); err != nil {
			return IdempotencyClaim{}, fmt.Errorf("commit reclaimed idempotency lease: %w", err)
		}
		return IdempotencyClaim{LeaseUID: leaseUID}, nil
	}

	if state == "completed" {
		if status == nil || headersJSON == nil || body == nil {
			return IdempotencyClaim{}, errors.New("completed idempotency record has no stored response")
		}
		response := StoredHTTPResponse{Status: *status, Body: append([]byte(nil), body...)}
		if err = json.Unmarshal(headersJSON, &response.Headers); err != nil {
			return IdempotencyClaim{}, fmt.Errorf("decode idempotent response headers: %w", err)
		}
		if err = tx.Commit(ctx); err != nil {
			return IdempotencyClaim{}, fmt.Errorf("commit idempotent replay: %w", err)
		}
		return IdempotencyClaim{Replay: &response}, nil
	}

	retryAfter := leaseExpiresAt.Sub(databaseNow)
	if err = tx.Commit(ctx); err != nil {
		return IdempotencyClaim{}, fmt.Errorf("commit idempotency contention check: %w", err)
	}
	return IdempotencyClaim{RetryAfter: retryAfter}, nil
}

// Complete stores the exact HTTP result for later retries. Only the current
// lease owner may complete a claim, preventing a slow superseded worker from
// overwriting the response chosen by a newer attempt.
func (s *IdempotencyStore) Complete(ctx context.Context, request IdempotencyRequest, leaseUID uuid.UUID, response StoredHTTPResponse) error {
	if err := validateIdempotencyRequest(request); err != nil {
		return err
	}
	if leaseUID == uuid.Nil {
		return errors.New("idempotency lease UID is required")
	}
	if response.Status < 100 || response.Status > 599 {
		return errors.New("idempotent response status must be between 100 and 599")
	}
	if response.Headers == nil {
		response.Headers = map[string][]string{}
	}
	if response.Body == nil {
		response.Body = []byte{}
	}
	headersJSON, err := json.Marshal(response.Headers)
	if err != nil {
		return fmt.Errorf("encode idempotent response headers: %w", err)
	}
	return completeIdempotency(ctx, s.db, request, leaseUID, response, headersJSON)
}

// CompleteTx persists the replay result in the same transaction as the domain
// mutation. This closes the crash window in which a resource could commit but
// its idempotency result could be lost.
func (s *IdempotencyStore) CompleteTx(ctx context.Context, tx pgx.Tx, request IdempotencyRequest, leaseUID uuid.UUID, response StoredHTTPResponse) error {
	if err := validateIdempotencyRequest(request); err != nil {
		return err
	}
	if leaseUID == uuid.Nil {
		return errors.New("idempotency lease UID is required")
	}
	if response.Status < 100 || response.Status > 599 {
		return errors.New("idempotent response status must be between 100 and 599")
	}
	if response.Headers == nil {
		response.Headers = map[string][]string{}
	}
	if response.Body == nil {
		response.Body = []byte{}
	}
	headersJSON, err := json.Marshal(response.Headers)
	if err != nil {
		return fmt.Errorf("encode idempotent response headers: %w", err)
	}
	return completeIdempotency(ctx, tx, request, leaseUID, response, headersJSON)
}

type idempotencyExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func completeIdempotency(ctx context.Context, execer idempotencyExecer, request IdempotencyRequest, leaseUID uuid.UUID, response StoredHTTPResponse, headersJSON []byte) error {
	command, err := execer.Exec(ctx, `
		UPDATE idempotency_records
		SET state='completed', response_status=$6, response_headers=$7,
		    response_body=$8, completed_at=clock_timestamp()
		WHERE principal_type=$1 AND principal_uid=$2 AND operation=$3
		  AND idempotency_key=$4 AND lease_uid=$5 AND state='processing'
	`, request.PrincipalType, request.PrincipalUID, request.Operation, request.Key,
		leaseUID, response.Status, headersJSON, response.Body)
	if err != nil {
		return fmt.Errorf("complete idempotency claim: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyLeaseLost
	}
	return nil
}

// DeleteExpired removes a bounded batch and is intended for a background job.
func (s *IdempotencyStore) DeleteExpired(ctx context.Context, limit int) (int64, error) {
	if limit < 1 || limit > 10_000 {
		return 0, errors.New("cleanup limit must be between 1 and 10000")
	}
	command, err := s.db.Exec(ctx, `
		WITH expired AS (
			SELECT principal_type, principal_uid, operation, idempotency_key
			FROM idempotency_records
			WHERE expires_at <= clock_timestamp()
			ORDER BY expires_at
			LIMIT $1
		)
		DELETE FROM idempotency_records AS records
		USING expired
		WHERE records.principal_type=expired.principal_type
		  AND records.principal_uid=expired.principal_uid
		  AND records.operation=expired.operation
		  AND records.idempotency_key=expired.idempotency_key
	`, limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired idempotency records: %w", err)
	}
	return command.RowsAffected(), nil
}

func validateIdempotencyRequest(request IdempotencyRequest) error {
	if !idempotencyPrincipalType.MatchString(request.PrincipalType) {
		return errors.New("invalid idempotency principal type")
	}
	if len(request.PrincipalUID) < 1 || len(request.PrincipalUID) > 255 || strings.TrimSpace(request.PrincipalUID) != request.PrincipalUID {
		return errors.New("invalid idempotency principal UID")
	}
	if !idempotencyOperation.MatchString(request.Operation) {
		return errors.New("invalid idempotency operation")
	}
	if len(request.Key) < 1 || len(request.Key) > 255 || strings.TrimSpace(request.Key) != request.Key || strings.IndexFunc(request.Key, unicode.IsControl) >= 0 {
		return errors.New("invalid idempotency key")
	}
	if request.LeaseDuration <= 0 || request.LeaseDuration > 10*time.Minute {
		return errors.New("idempotency lease duration must be between 1ns and 10m")
	}
	if request.Retention <= request.LeaseDuration || request.Retention > 30*24*time.Hour {
		return errors.New("idempotency retention must exceed the lease and be at most 30 days")
	}
	return nil
}

func durationSeconds(duration time.Duration) int64 {
	seconds := int64(duration / time.Second)
	if duration%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		return 1
	}
	return seconds
}

func equalDigest(stored []byte, expected [sha256.Size]byte) bool {
	if len(stored) != sha256.Size {
		return false
	}
	var difference byte
	for index := range expected {
		difference |= stored[index] ^ expected[index]
	}
	return difference == 0
}
