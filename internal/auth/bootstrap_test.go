package auth

import (
	"context"
	"testing"

	"github.com/TrippingKelsea/nebula-starcaller/internal/config"
	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
	storesqlite "github.com/TrippingKelsea/nebula-starcaller/internal/store/sqlite"
)

func newStore(t *testing.T) *storesqlite.Store {
	t.Helper()
	s, err := storesqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestBootstrapCreatesAdmin(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	err := EnsureBootstrap(ctx, s, config.Bootstrap{
		Username: "admin", Password: "correct horse", Email: "a@b.c",
	})
	if err != nil {
		t.Fatalf("EnsureBootstrap: %v", err)
	}
	u, err := s.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !u.ForceWebAuthnEnrollment {
		t.Error("bootstrap user should have force_webauthn set")
	}
	if !HasRole(u, domain.RoleAdmin) {
		t.Error("bootstrap user should be admin")
	}
}

func TestBootstrapIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_ = EnsureBootstrap(ctx, s, config.Bootstrap{Username: "admin", Password: "p"})
	// Second call with different creds should NOT create a new user
	_ = EnsureBootstrap(ctx, s, config.Bootstrap{Username: "eve", Password: "p"})
	n, _ := s.CountUsers(ctx)
	if n != 1 {
		t.Errorf("expected 1 user after two bootstrap calls, got %d", n)
	}
	if _, err := s.GetUserByUsername(ctx, "eve"); err == nil {
		t.Error("second bootstrap should not have created eve")
	}
}

func TestBootstrapRequiresCreds(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := EnsureBootstrap(ctx, s, config.Bootstrap{}); err == nil {
		t.Error("expected error when no users and no creds provided")
	}
}

func TestLoginRejectsBadCreds(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := EnsureBootstrap(ctx, s, config.Bootstrap{Username: "admin", Password: "right"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Login(ctx, s, "admin", "wrong"); err != ErrPasswordMismatch {
		t.Errorf("wrong password: expected mismatch, got %v", err)
	}
	if _, err := Login(ctx, s, "nobody", "any"); err != ErrPasswordMismatch {
		t.Errorf("unknown user: expected mismatch (no enumeration), got %v", err)
	}
	u, err := Login(ctx, s, "admin", "right")
	if err != nil || u.Username != "admin" {
		t.Errorf("valid login: u=%+v err=%v", u, err)
	}
	// LastLoginAt should have been updated
	got, _ := s.GetUserByUsername(ctx, "admin")
	if got.LastLoginAt == nil {
		t.Error("LastLoginAt not updated")
	}
}
