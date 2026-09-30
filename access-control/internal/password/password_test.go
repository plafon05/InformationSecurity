package password

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	plain := "LatinКириллица 🔒"
	one, err := Hash(plain)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Hash(plain)
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatal("salt reused")
	}
	if strings.Contains(one, plain) {
		t.Fatal("plaintext")
	}
	if ok, err := Verify(one, plain); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := Verify(one, "wrong"); err != nil || ok {
		t.Fatal(ok, err)
	}
	if ok, err := Verify("", ""); err != nil || !ok {
		t.Fatal("first login", ok, err)
	}
	if ok, _ := Verify("", "wrong"); ok {
		t.Fatal("empty hash bypass")
	}
	if _, err := Hash(""); err == nil {
		t.Fatal("empty new password")
	}
	if ok, _ := Verify(one, strings.Repeat("x", MaxLength+1)); ok {
		t.Fatal("oversized password")
	}
}
func TestMalformedHashes(t *testing.T) {
	for _, hash := range []string{"broken", "$argon2i$v=19$m=65536,t=3,p=1$a$b", "$argon2id$v=19$m=4294967295,t=3,p=1$a$b", "$argon2id$v=19$m=65536,t=0,p=1$a$b", "$argon2id$v=19$m=65536,t=3,p=0$a$b", "$argon2id$v=19$m=65536,t=3,p=1$?$?", strings.Repeat("a", 257)} {
		if ok, err := Verify(hash, "test"); ok || err == nil {
			t.Fatalf("accepted %q", hash)
		}
	}
}
