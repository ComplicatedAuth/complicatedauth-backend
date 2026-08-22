package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var rateLimitPolicyPattern = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,127}$`)

type RateLimiter struct {
	db *pgxpool.Pool
}

type RateLimitResult struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter time.Duration
	ResetAt    time.Time
}

func NewRateLimiter(db *pgxpool.Pool) *RateLimiter {
	return &RateLimiter{db: db}
}

// Take atomically consumes one fixed-window allowance. keyHash must be a
// keyed digest rather than an email address, source IP, token, or other raw
// identifier. Denied attempts remain capped at limit+1 to avoid counter
// overflow under sustained abuse.
func (l *RateLimiter) Take(ctx context.Context, policy string, keyHash []byte, limit int, window time.Duration) (RateLimitResult, error) {
	if !rateLimitPolicyPattern.MatchString(policy) {
		return RateLimitResult{}, errors.New("invalid rate-limit policy")
	}
	if len(keyHash) != 32 {
		return RateLimitResult{}, errors.New("rate-limit key hash must be 32 bytes")
	}
	if limit < 1 || limit > 1_000_000 {
		return RateLimitResult{}, errors.New("rate-limit allowance must be between 1 and 1000000")
	}
	if window < time.Second || window > 7*24*time.Hour {
		return RateLimitResult{}, errors.New("rate-limit window must be between one second and seven days")
	}

	var count int
	var resetAt, databaseNow time.Time
	err := l.db.QueryRow(ctx, `
		INSERT INTO rate_limit_buckets(policy, key_hash, request_count, window_started_at, expires_at)
		VALUES($1, $2, 1, clock_timestamp(), clock_timestamp() + $4 * interval '1 second')
		ON CONFLICT (policy, key_hash) DO UPDATE SET
			request_count = CASE
				WHEN rate_limit_buckets.expires_at <= clock_timestamp() THEN 1
				ELSE LEAST(rate_limit_buckets.request_count + 1, $3 + 1)
			END,
			window_started_at = CASE
				WHEN rate_limit_buckets.expires_at <= clock_timestamp() THEN clock_timestamp()
				ELSE rate_limit_buckets.window_started_at
			END,
			expires_at = CASE
				WHEN rate_limit_buckets.expires_at <= clock_timestamp() THEN clock_timestamp() + $4 * interval '1 second'
				ELSE rate_limit_buckets.expires_at
			END
		RETURNING request_count, expires_at, clock_timestamp()
	`, policy, keyHash, limit, durationSeconds(window)).Scan(&count, &resetAt, &databaseNow)
	if err != nil {
		return RateLimitResult{}, fmt.Errorf("consume rate limit: %w", err)
	}
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}
	result := RateLimitResult{Allowed: count <= limit, Limit: limit, Remaining: remaining, ResetAt: resetAt}
	if !result.Allowed {
		result.RetryAfter = resetAt.Sub(databaseNow)
		if result.RetryAfter < 0 {
			result.RetryAfter = 0
		}
	}
	return result, nil
}

func (l *RateLimiter) Reset(ctx context.Context, policy string, keyHash []byte) error {
	if !rateLimitPolicyPattern.MatchString(policy) || len(keyHash) != 32 {
		return errors.New("invalid rate-limit reset key")
	}
	if _, err := l.db.Exec(ctx, `DELETE FROM rate_limit_buckets WHERE policy=$1 AND key_hash=$2`, policy, keyHash); err != nil {
		return fmt.Errorf("reset rate limit: %w", err)
	}
	return nil
}

func (l *RateLimiter) DeleteExpired(ctx context.Context, limit int) (int64, error) {
	if limit < 1 || limit > 10_000 {
		return 0, errors.New("cleanup limit must be between 1 and 10000")
	}
	command, err := l.db.Exec(ctx, `
		WITH expired AS (
			SELECT policy, key_hash
			FROM rate_limit_buckets
			WHERE expires_at <= clock_timestamp()
			ORDER BY expires_at
			LIMIT $1
		)
		DELETE FROM rate_limit_buckets AS buckets
		USING expired
		WHERE buckets.policy=expired.policy AND buckets.key_hash=expired.key_hash
	`, limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired rate limits: %w", err)
	}
	return command.RowsAffected(), nil
}
