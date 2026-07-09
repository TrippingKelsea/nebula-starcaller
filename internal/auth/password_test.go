package auth

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=2,p=4$") {
		t.Errorf("unexpected encoded format: %s", hash)
	}
	if err := VerifyPassword(hash, "correct horse battery staple"); err != nil {
		t.Errorf("VerifyPassword: %v", err)
	}
	if err := VerifyPassword(hash, "wrong password"); err != ErrPasswordMismatch {
		t.Errorf("expected mismatch, got %v", err)
	}
}

func TestHashesAreSalted(t *testing.T) {
	h1, _ := HashPassword("same")
	h2, _ := HashPassword("same")
	if h1 == h2 {
		t.Error("two hashes of same password produced identical output — salt is not random")
	}
}

func TestVerifyMalformedHash(t *testing.T) {
	cases := []string{
		"", "$argon2id$v=19$m=65536$salt$hash", "not-a-hash",
		"$argon2i$v=19$m=65536,t=2,p=4$aaaa$bbbb",  // wrong variant
		"$argon2id$v=1$m=65536,t=2,p=4$aaaa$bbbb", // wrong version
	}
	for _, c := range cases {
		if err := VerifyPassword(c, "x"); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}
