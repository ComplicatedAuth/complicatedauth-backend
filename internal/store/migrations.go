package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationLockID is an application-specific PostgreSQL advisory lock. All
// ComplicatedAuth replicas use it to serialize schema changes at startup.
const migrationLockID int64 = 0x436f6d7041757468

var (
	migrationNamePattern = regexp.MustCompile(`^[0-9]{6}_[a-z0-9]+(?:_[a-z0-9]+)*\.up\.sql$`)
	forwardSQLPattern    = regexp.MustCompile(`\.up\.sql$`)
)

type migrationFile struct {
	name     string
	contents []byte
	checksum string
}

// Migrate applies forward-only SQL migrations. Applied files are a durable
// part of the release history: changing or removing one causes startup to fail
// instead of silently accepting schema drift.
func Migrate(ctx context.Context, pool *pgxpool.Pool, dir string) error {
	migrations, err := loadMigrations(dir)
	if err != nil {
		return err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		// Advisory locks are session scoped. Always attempt to release the lock
		// before returning the connection to the pool, even when ctx is canceled.
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockID)
	}()

	if _, err = conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version text PRIMARY KEY,
			checksum text,
			applied_at timestamptz NOT NULL DEFAULT now()
		);
		ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum text
	`); err != nil {
		return fmt.Errorf("initialize migration history: %w", err)
	}

	byName := make(map[string]migrationFile, len(migrations))
	for _, migration := range migrations {
		byName[migration.name] = migration
	}

	rows, err := conn.Query(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("read migration history: %w", err)
	}
	applied := make(map[string]bool, len(migrations))
	for rows.Next() {
		var version string
		var storedChecksum *string
		if err = rows.Scan(&version, &storedChecksum); err != nil {
			rows.Close()
			return fmt.Errorf("scan migration history: %w", err)
		}
		migration, exists := byName[version]
		if !exists {
			rows.Close()
			return fmt.Errorf("applied migration %s is missing from the release", version)
		}
		if storedChecksum != nil && *storedChecksum != migration.checksum {
			rows.Close()
			return fmt.Errorf("applied migration %s was modified: checksum is %s, release has %s", version, *storedChecksum, migration.checksum)
		}
		applied[version] = true
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read migration history: %w", err)
	}
	rows.Close()

	// Older releases recorded only filenames. The first checksum-aware release
	// seals those exact bytes as the baseline; all later releases verify them.
	for _, migration := range migrations {
		if !applied[migration.name] {
			continue
		}
		if _, err = conn.Exec(ctx, `UPDATE schema_migrations SET checksum=$2 WHERE version=$1 AND checksum IS NULL`, migration.name, migration.checksum); err != nil {
			return fmt.Errorf("seal migration %s: %w", migration.name, err)
		}
	}
	if _, err = conn.Exec(ctx, `ALTER TABLE schema_migrations ALTER COLUMN checksum SET NOT NULL`); err != nil {
		return fmt.Errorf("require migration checksums: %w", err)
	}

	for _, migration := range migrations {
		if applied[migration.name] {
			continue
		}
		tx, beginErr := conn.Begin(ctx)
		if beginErr != nil {
			return fmt.Errorf("begin migration %s: %w", migration.name, beginErr)
		}
		if _, err = tx.Exec(ctx, string(migration.contents)); err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version, checksum) VALUES($1, $2)`, migration.name, migration.checksum)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", migration.name, err)
		}
		if err = tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", migration.name, err)
		}
	}
	return nil
}

func loadMigrations(dir string) ([]migrationFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	migrations := make([]migrationFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !forwardSQLPattern.MatchString(entry.Name()) {
			continue
		}
		if !migrationNamePattern.MatchString(entry.Name()) {
			return nil, fmt.Errorf("invalid forward migration filename %q; expected 000001_descriptive_name.up.sql", entry.Name())
		}
		contents, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
		if readErr != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), readErr)
		}
		digest := sha256.Sum256(contents)
		migrations = append(migrations, migrationFile{
			name:     entry.Name(),
			contents: contents,
			checksum: hex.EncodeToString(digest[:]),
		})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].name < migrations[j].name })
	for index := 1; index < len(migrations); index++ {
		if migrations[index-1].name[:6] == migrations[index].name[:6] {
			return nil, fmt.Errorf("duplicate migration version %s", migrations[index].name[:6])
		}
	}
	return migrations, nil
}
