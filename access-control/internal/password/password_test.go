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
