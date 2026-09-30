package postgres

import (
	"access-control/internal/accounts"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testRepository(t *testing.T) *Repository {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is required for PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal("invalid test database configuration")
	}
	bootstrap, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("cannot open test database")
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	name := "test_" + hex.EncodeToString(b)
	identifier := pgx.Identifier{name}.Sanitize()
	if _, err = bootstrap.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		bootstrap.Close()
		t.Fatal("cannot create isolated test schema:", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := &Repository{pool: pool}
	t.Cleanup(func() {
		pool.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := bootstrap.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		bootstrap.Close()
		if err != nil {
			t.Error("cleanup:", err)
		}
	})
	if err = r.migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestPostgresLifecycle(t *testing.T) {
	r := testRepository(t)
	ctx := context.Background()
	s := accounts.New(r)
	list, err := s.List(ctx)
	if err != nil || len(list) != 1 || list[0].Name != "ADMIN" || !list[0].Initial {
		t.Fatal(list, err)
	}
	if err = s.ChangePassword(ctx, "ADMIN", "", "AdminЯ", "AdminЯ"); err != nil {
		t.Fatal(err)
	}
	if err = r.migrate(ctx); err != nil {
		t.Fatal(err)
	} // restart must not reset ADMIN.
	if _, err = s.Authenticate(ctx, "ADMIN", "AdminЯ"); err != nil {
		t.Fatal(err)
	}
	name := "alice'; DROP TABLE users; --"
	if err = s.Add(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err = s.Add(ctx, name); err != accounts.ErrDuplicate {
		t.Fatal(err)
	}
	if err = s.Update(ctx, name, false, true); err != nil {
		t.Fatal(err)
	}
	if err = s.ChangePassword(ctx, name, "", "Latin", "Latin"); err == nil {
		t.Fatal("policy bypass")
	}
	if err = s.ChangePassword(ctx, name, "", "LatinЯ", "LatinЯ"); err != nil {
		t.Fatal(err)
	}
	u, err := r.Get(ctx, name)
	if err != nil || !strings.HasPrefix(u.PasswordHash, "$argon2id$") || strings.Contains(u.PasswordHash, "LatinЯ") {
		t.Fatal("bad storage", err)
	}
	exported, err := r.ListCredentials(ctx)
	if err != nil || len(exported) != 2 || exported[1].Name != name || exported[1].PasswordHash != u.PasswordHash {
		t.Fatal("credential export", err)
	}
	if err = s.ChangePassword(ctx, name, "wrong", "NewЯ", "NewЯ"); err != accounts.ErrPassword {
		t.Fatal(err)
	}
	// A separate pool reads the persisted record, not process memory.
	second, err := pgxpool.NewWithConfig(ctx, r.pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err = accounts.New(&Repository{pool: second}).Authenticate(ctx, name, "LatinЯ"); err != nil {
		t.Fatal(err)
	}
	if err = s.Update(ctx, name, true, true); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authenticate(ctx, name, "LatinЯ"); err != accounts.ErrBlocked {
		t.Fatal(err)
	}
	if _, err = r.pool.Exec(ctx, "UPDATE users SET blocked=true WHERE name='ADMIN'"); err == nil {
		t.Fatal("database allows admin block")
	}
}
func TestConcurrentPasswordChanges(t *testing.T) {
	r := testRepository(t)
	s := accounts.New(r)
	ctx := context.Background()
	if err := s.ChangePassword(ctx, "ADMIN", "", "original", "original"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, plain := range []string{"first", "second"} {
		wg.Add(1)
		go func(p string) { defer wg.Done(); results <- s.ChangePassword(ctx, "ADMIN", "original", p, p) }(plain)
	}
	wg.Wait()
	close(results)
	success, rejected := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if err == accounts.ErrPassword {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || rejected != 1 {
		t.Fatalf("lost update: success=%d rejected=%d", success, rejected)
	}
}
func TestDatabaseUnavailable(t *testing.T) {
	r := testRepository(t)
	r.Close()
	if _, err := r.List(context.Background()); err != accounts.ErrStorage {
		t.Fatal(err)
	}
}
