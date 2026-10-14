package accounts_test

import (
	"access-control/internal/accounts"
	"access-control/internal/testutil"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	repo := testutil.NewMemory()
	s := accounts.New(repo)
	if list, err := s.List(ctx); err != nil || len(list) != 1 || list[0].Name != "ADMIN" || !list[0].Initial {
		t.Fatal(list, err)
	}
	if _, err := s.Authenticate(ctx, "ADMIN", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(ctx, "ADMIN", "", "admin-secret", "different"); err == nil {
		t.Fatal("confirmation accepted")
	}
	if err := s.ChangePassword(ctx, "ADMIN", "", "admin-secret", "admin-secret"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, "alice"); err != accounts.ErrDuplicate {
		t.Fatal("duplicate", err)
	}
	if err := s.Update(ctx, "alice", false, true); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(ctx, "alice", "", "LatinOnly", "LatinOnly"); err == nil {
		t.Fatal("policy bypass")
	}
	if err := s.ChangePassword(ctx, "alice", "", "LatinКириллица", "LatinКириллица"); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(ctx, "alice", "wrong", "AbЯ", "AbЯ"); err != accounts.ErrPassword {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "alice", "LatinКириллица"); err != nil {
		t.Fatal(err)
	}
	u, _ := repo.Get(ctx, "alice")
	if !strings.HasPrefix(u.PasswordHash, "$argon2id$") {
		t.Fatal("missing argon hash")
	}
	raw, _ := json.Marshal(u)
	if strings.Contains(string(raw), u.PasswordHash) {
		t.Fatal("hash leak")
	}
	if err := s.Update(ctx, "alice", true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "alice", "LatinКириллица"); err != accounts.ErrBlocked {
		t.Fatal(err)
	}
	if err := s.Update(ctx, "ADMIN", true, false); err == nil {
		t.Fatal("admin blocked")
	}
}
