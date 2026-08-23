// jobctl is the deployment-operator control surface for ComplicatedAuth's
// internal durable queue. It intentionally uses the database directly and is
// not registered in the customer-facing HTTP or OpenAPI contracts.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/complicatedauth/complicatedauth-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "jobctl:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return usageError()
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	jobs := store.NewBackgroundJobStore(pool)

	switch arguments[0] {
	case "list":
		return listJobs(ctx, jobs, arguments[1:])
	case "replay":
		return replayJob(ctx, jobs, arguments[1:])
	case "help", "-h", "--help":
		return usageError()
	default:
		return fmt.Errorf("unknown command %q; %w", arguments[0], usageError())
	}
}

func listJobs(ctx context.Context, jobs *store.BackgroundJobStore, arguments []string) error {
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	status := flags.String("status", "", "pending, running, completed, or dead_lettered")
	limit := flags.Int("limit", 100, "maximum records, from 1 to 500")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("list does not accept positional arguments")
	}
	items, err := jobs.List(ctx, store.BackgroundJobListOptions{Status: *status, Limit: *limit})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(items)
}

func replayJob(ctx context.Context, jobs *store.BackgroundJobStore, arguments []string) error {
	flags := flag.NewFlagSet("replay", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	jobUID := flags.String("job", "", "dead-lettered background job UUID")
	actor := flags.String("actor", "", "platform operator identity")
	reason := flags.String("reason", "", "incident or remediation reason, at least 10 characters")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("replay does not accept positional arguments")
	}
	parsedUID, err := uuid.Parse(*jobUID)
	if err != nil {
		return errors.New("--job must be a UUID")
	}
	if err = jobs.Replay(ctx, store.BackgroundJobReplay{
		JobUID: parsedUID,
		Actor:  *actor,
		Reason: *reason,
	}); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"job_uid": parsedUID,
		"status":  "pending",
	})
}

func usageError() error {
	return errors.New("usage: jobctl list [--status STATUS] [--limit N] | jobctl replay --job UUID --actor ID --reason TEXT")
}
