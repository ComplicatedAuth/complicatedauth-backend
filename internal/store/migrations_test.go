package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLoadMigrationsOrdersAndChecksumsFiles(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "000002_second.up.sql", "SELECT 2;\n")
	writeMigration(t, dir, "000001_first.up.sql", "SELECT 1;\n")
	writeMigration(t, dir, "000001_first.down.sql", "SELECT 1;\n")

	migrations, err := loadMigrations(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) != 2 {
		t.Fatalf("len=%d want=2", len(migrations))
	}
	if migrations[0].name != "000001_first.up.sql" || migrations[1].name != "000002_second.up.sql" {
		t.Fatalf("unexpected order: %q, %q", migrations[0].name, migrations[1].name)
	}
	if len(migrations[0].checksum) != 64 {
		t.Fatalf("checksum length=%d want=64", len(migrations[0].checksum))
	}
	if migrations[0].checksum == migrations[1].checksum {
		t.Fatal("different migration contents produced the same checksum")
	}
}

func TestLoadMigrationsRejectsAmbiguousHistory(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  string
	}{
		{name: "malformed", files: []string{"3_bad.up.sql"}, want: "invalid forward migration filename"},
		{name: "duplicate version", files: []string{"000003_alpha.up.sql", "000003_beta.up.sql"}, want: "duplicate migration version 000003"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range test.files {
				writeMigration(t, dir, name, "SELECT 1;\n")
			}
			_, err := loadMigrations(dir)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestMigrateSerializesAndRejectsChangedHistory(t *testing.T) {
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

	schema := "migrations_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

	dir := t.TempDir()
	const name = "000001_initial.up.sql"
	writeMigration(t, dir, name, "CREATE TABLE widgets (uid uuid PRIMARY KEY);\n")
	var wait sync.WaitGroup
	errorsByWorker := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsByWorker <- Migrate(ctx, pool, dir)
		}()
	}
	wait.Wait()
	close(errorsByWorker)
	for migrationErr := range errorsByWorker {
		if migrationErr != nil {
			t.Fatalf("concurrent migration: %v", migrationErr)
		}
	}
	var applied int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil || applied != 1 {
		t.Fatalf("applied=%d err=%v", applied, err)
	}

	writeMigration(t, dir, name, "CREATE TABLE widgets (uid text PRIMARY KEY);\n")
	if err = Migrate(ctx, pool, dir); err == nil || !strings.Contains(err.Error(), "was modified") {
		t.Fatalf("modified history err=%v", err)
	}
	writeMigration(t, dir, name, "CREATE TABLE widgets (uid uuid PRIMARY KEY);\n")
	if err = os.Remove(filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, pool, dir); err == nil || !strings.Contains(err.Error(), "is missing from the release") {
		t.Fatalf("missing history err=%v", err)
	}
}

func writeMigration(t *testing.T, dir, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
