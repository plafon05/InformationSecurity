package filestore

import (
	"access-control/internal/accounts"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFirstRunAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Users) != 1 || doc.Users[0].Name != "ADMIN" || doc.Users[0].PasswordHash != "" || doc.Users[0].Blocked || doc.Users[0].Restricted {
		t.Fatalf("wrong initial file: %+v", doc)
	}
	ctx := context.Background()
	if err := r.Create(ctx, accounts.User{Name: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Update(ctx, "alice", func(u *accounts.User) error {
		u.PasswordHash = "stored-hash"
		u.Blocked = true
		u.Restricted = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	u, err := r.Get(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash != "stored-hash" || !u.Blocked || !u.Restricted {
		t.Fatalf("changes not persisted: %+v", u)
	}
}
