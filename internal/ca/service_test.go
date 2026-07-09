package ca

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TrippingKelsea/nebula-starcaller/internal/archive"
	archsqlite "github.com/TrippingKelsea/nebula-starcaller/internal/archive/sqlite"
	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
	"github.com/TrippingKelsea/nebula-starcaller/internal/nebulax"
	storesqlite "github.com/TrippingKelsea/nebula-starcaller/internal/store/sqlite"
)

func newSvc(t *testing.T) (*Service, *storesqlite.Store) {
	t.Helper()
	s, err := storesqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	a := archsqlite.New(s.DB())
	return &Service{Store: s, Archive: a, Runner: nebulax.NewFake()}, s
}

func TestCACreateHappy(t *testing.T) {
	ctx := context.Background()
	svc, s := newSvc(t)

	ca, err := svc.Create(ctx, CreateInput{
		Name: "starcaller-root", Curve: domain.CurveP256,
		Networks: []string{"10.0.0.0/16"},
		Groups: []string{"servers", "workstations"},
		Duration: 365 * 24 * time.Hour,
		DefaultCertTTL: 30 * 24 * time.Hour,
	}, "u1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ca.ID == "" || ca.Name != "starcaller-root" {
		t.Errorf("bad ca: %+v", ca)
	}
	// Cert PEM should look like a Nebula cert
	if !strings.Contains(ca.CertPEM, "NEBULA CERTIFICATE") {
		t.Errorf("cert PEM shape: %s", ca.CertPEM)
	}
	// Key should be archived and retrievable
	key, err := svc.LoadKey(ctx, ca)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if len(key) == 0 {
		t.Fatal("empty key")
	}
	// Groups declared should be registered
	groups, _ := s.ListGroups(ctx)
	if len(groups) != 2 {
		t.Errorf("expected 2 groups registered, got %d", len(groups))
	}
	// Audit event should exist
	events, _ := s.ListAudit(ctx, 10)
	if len(events) < 1 || events[0].Action != "ca.create" {
		t.Errorf("expected ca.create audit event, got %+v", events)
	}
}

func TestCACreateValidation(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		in   CreateInput
	}{
		{"no name", CreateInput{Networks: []string{"10.0.0.0/16"}}},
		{"no networks", CreateInput{Name: "x"}},
		{"ttl >= duration", CreateInput{
			Name: "x", Networks: []string{"10.0.0.0/16"},
			Duration: time.Hour, DefaultCertTTL: 2 * time.Hour,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newSvc(t)
			if _, err := svc.Create(ctx, tc.in, "u"); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestCADefaults(t *testing.T) {
	ctx := context.Background()
	svc, _ := newSvc(t)
	ca, err := svc.Create(ctx, CreateInput{
		Name: "with-defaults",
		Networks: []string{"10.0.0.0/16"},
	}, "u")
	if err != nil {
		t.Fatal(err)
	}
	if ca.Curve != domain.Curve25519 {
		t.Errorf("expected default curve 25519, got %q", ca.Curve)
	}
	if ca.Duration <= 0 {
		t.Errorf("default duration should be set: %v", ca.Duration)
	}
	if ca.DefaultCertTTL <= 0 {
		t.Errorf("default cert TTL should be set: %v", ca.DefaultCertTTL)
	}
}

func TestCARetire(t *testing.T) {
	ctx := context.Background()
	svc, _ := newSvc(t)
	ca, _ := svc.Create(ctx, CreateInput{Name: "r", Networks: []string{"10.0.0.0/16"}}, "u")
	if err := svc.Retire(ctx, ca.ID, "u"); err != nil {
		t.Fatal(err)
	}
	got, _ := svc.Get(ctx, ca.ID)
	if got.RetiredAt == nil {
		t.Error("expected retired_at set")
	}
}

func TestCACreateArchiveCleanupOnStoreFailure(t *testing.T) {
	// If store.CreateCA fails (e.g., duplicate name), the archived key should be cleaned up.
	ctx := context.Background()
	svc, s := newSvc(t)

	in := CreateInput{Name: "dup", Networks: []string{"10.0.0.0/16"}}
	if _, err := svc.Create(ctx, in, "u"); err != nil {
		t.Fatal(err)
	}
	// Second create with same name should fail with duplicate
	if _, err := svc.Create(ctx, in, "u"); err == nil {
		t.Fatal("expected duplicate error")
	}
	// Archive should only have one CA key (the first one)
	// Verify by counting archive rows via DB
	row := s.DB().QueryRow(`SELECT COUNT(*) FROM archive WHERE kind = ?`, string(archive.KindCAKey))
	var n int
	_ = row.Scan(&n)
	if n != 1 {
		t.Errorf("expected 1 archived key after failed duplicate create, got %d", n)
	}
}
