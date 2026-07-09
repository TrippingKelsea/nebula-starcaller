package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
	"github.com/TrippingKelsea/nebula-starcaller/internal/store"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestUserCRUD(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	n, err := s.CountUsers(ctx)
	if err != nil || n != 0 {
		t.Fatalf("CountUsers: n=%d err=%v", n, err)
	}

	u := domain.User{
		ID: "u1", Username: "alice", Email: "a@example.com",
		PasswordHash: "hash", Roles: []domain.Role{domain.RoleAdmin, domain.RoleOperator},
		ForceWebAuthnEnrollment: true,
		CreatedAt:               time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Duplicate
	if err := s.CreateUser(ctx, u); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate CreateUser: expected ErrDuplicate, got %v", err)
	}

	got, err := s.GetUserByID(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.Username != "alice" || len(got.Roles) != 2 || !got.ForceWebAuthnEnrollment {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	if _, err := s.GetUserByUsername(ctx, "alice"); err != nil {
		t.Errorf("GetUserByUsername: %v", err)
	}
	if _, err := s.GetUserByUsername(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	// Update
	got.Email = "alice@example.org"
	got.ForceWebAuthnEnrollment = false
	if err := s.UpdateUser(ctx, got); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	again, _ := s.GetUserByID(ctx, "u1")
	if again.Email != "alice@example.org" || again.ForceWebAuthnEnrollment {
		t.Errorf("update didn't persist: %+v", again)
	}

	users, err := s.ListUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Errorf("ListUsers: got %d users, err=%v", len(users), err)
	}

	n, _ = s.CountUsers(ctx)
	if n != 1 {
		t.Errorf("CountUsers after insert: %d", n)
	}
}

func TestSessionCRUD(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// Sessions have a foreign key to users
	if err := s.CreateUser(ctx, domain.User{ID: "u", Username: "u", PasswordHash: "h", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	sess := domain.Session{
		ID: "s1", UserID: "u",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		IP:        "1.2.3.4", UserAgent: "ua",
	}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetSession(ctx, "s1")
	if err != nil || got.UserID != "u" || got.IP != "1.2.3.4" {
		t.Errorf("GetSession: %+v err=%v", got, err)
	}

	if err := s.DeleteSession(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "s1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected NotFound after delete, got %v", err)
	}

	// Expired cleanup
	past := domain.Session{ID: "past", UserID: "u",
		CreatedAt: time.Now().Add(-2 * time.Hour).UTC(),
		ExpiresAt: time.Now().Add(-time.Hour).UTC()}
	future := domain.Session{ID: "future", UserID: "u",
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour).UTC()}
	_ = s.CreateSession(ctx, past)
	_ = s.CreateSession(ctx, future)
	if err := s.DeleteExpiredSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "past"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired session should be gone, got %v", err)
	}
	if _, err := s.GetSession(ctx, "future"); err != nil {
		t.Errorf("future session was wrongly deleted: %v", err)
	}
}

func TestCACRUD(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	ca := domain.CA{
		ID: "ca1", Name: "root", Description: "test",
		Curve: domain.CurveP256,
		Networks: []string{"10.0.0.0/16"},
		UnsafeNetworks: []string{"192.168.0.0/24"},
		Groups: []string{"servers", "workstations"},
		CertPEM: "PEM", KeyArchiveID: "arch1",
		Duration: 365 * 24 * time.Hour, DefaultCertTTL: 24 * time.Hour,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateCA(ctx, ca); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	got, err := s.GetCA(ctx, "ca1")
	if err != nil {
		t.Fatalf("GetCA: %v", err)
	}
	if got.Name != "root" || got.Curve != domain.CurveP256 ||
		len(got.Networks) != 1 || len(got.Groups) != 2 {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	// Duplicate name
	dup := ca
	dup.ID = "ca2"
	if err := s.CreateCA(ctx, dup); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate name: expected ErrDuplicate, got %v", err)
	}

	list, err := s.ListCAs(ctx)
	if err != nil || len(list) != 1 {
		t.Errorf("ListCAs: n=%d err=%v", len(list), err)
	}

	if err := s.RetireCA(ctx, "ca1"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetCA(ctx, "ca1")
	if got.RetiredAt == nil {
		t.Error("expected RetiredAt set")
	}
	if err := s.RetireCA(ctx, "ca1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("re-retire: expected ErrNotFound, got %v", err)
	}
}

func TestCertLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	setupCA(t, s)

	c := domain.Cert{
		ID: "c1", IssuingCAID: "ca", Name: "host1",
		Networks: []string{"10.0.0.5/16"},
		Groups: []string{"servers"},
		HostRole: domain.HostRoleHost,
		Platform: domain.Platform{OS: "linux", Arch: "amd64"},
		Fingerprint: "fp1",
		NotBefore: time.Now().UTC().Truncate(time.Second),
		NotAfter: time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
		CertArchiveID: "ac", KeyArchiveID: "ak", BundleArchiveID: "ab",
		IssuedBy: "u1", CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateCert(ctx, c); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetCert(ctx, "c1")
	if err != nil || got.Fingerprint != "fp1" || got.Platform.String() != "linux-amd64" {
		t.Errorf("GetCert: %+v err=%v", got, err)
	}

	// Second cert, to test list + supersede
	c2 := c
	c2.ID = "c2"
	c2.Fingerprint = "fp2"
	if err := s.CreateCert(ctx, c2); err != nil {
		t.Fatal(err)
	}

	all, _ := s.ListCerts(ctx, "ca")
	if len(all) != 2 {
		t.Errorf("ListCerts: got %d", len(all))
	}
	active, _ := s.ListActiveCerts(ctx, "ca")
	if len(active) != 2 {
		t.Errorf("ListActiveCerts: got %d", len(active))
	}

	if err := s.MarkSuperseded(ctx, "c1", "c2"); err != nil {
		t.Fatal(err)
	}
	active, _ = s.ListActiveCerts(ctx, "ca")
	if len(active) != 1 || active[0].ID != "c2" {
		t.Errorf("after supersede: active=%v", active)
	}

	if err := s.RevokeCert(ctx, "c2", "compromised"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeCert(ctx, "c2", "again"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("re-revoke: expected ErrNotFound, got %v", err)
	}
	got, _ = s.GetCert(ctx, "c2")
	if got.RevokedAt == nil || got.RevocationReason != "compromised" {
		t.Errorf("revoke didn't persist: %+v", got)
	}

	fps, err := s.ListRevokedFingerprints(ctx, "ca")
	if err != nil || len(fps) != 1 || fps[0] != "fp2" {
		t.Errorf("ListRevokedFingerprints: %v err=%v", fps, err)
	}
}

func TestGroupUpsert(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	g := domain.Group{Name: "servers", Description: "app servers", CreatedAt: time.Now().UTC().Truncate(time.Second)}
	if err := s.UpsertGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	// Upsert same name updates description
	g.Description = "renamed"
	if err := s.UpsertGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListGroups(ctx)
	if err != nil || len(list) != 1 || list[0].Description != "renamed" {
		t.Errorf("group upsert: %+v err=%v", list, err)
	}
}

func TestAudit(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for i := 0; i < 5; i++ {
		if err := s.AppendAudit(ctx, domain.AuditEvent{
			At: time.Now().UTC(), Actor: "u1", Action: "create",
			Subject: "res", Details: "{}", IP: "1.1.1.1",
		}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := s.ListAudit(ctx, 3)
	if err != nil || len(events) != 3 {
		t.Errorf("ListAudit: n=%d err=%v", len(events), err)
	}
	// Most recent first
	if events[0].ID <= events[2].ID {
		t.Errorf("expected DESC ordering: %d then %d", events[0].ID, events[2].ID)
	}
}

func TestWebAuthnCredentials(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.CreateUser(ctx, domain.User{ID: "u", Username: "u", PasswordHash: "h", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	c := domain.WebAuthnCredential{
		ID: "c1", UserID: "u",
		CredentialID: []byte{1, 2, 3}, PublicKey: []byte{4, 5, 6},
		AttestType: "none", AAGUID: []byte{},
		SignCount: 0, Name: "yubikey5",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.AddWebAuthnCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListWebAuthnCredentials(ctx, "u")
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v err=%v", list, err)
	}
	if err := s.UpdateWebAuthnSignCount(ctx, "c1", 42); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListWebAuthnCredentials(ctx, "u")
	if list[0].SignCount != 42 {
		t.Errorf("sign count not updated: %d", list[0].SignCount)
	}
	if err := s.DeleteWebAuthnCredential(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteWebAuthnCredential(ctx, "c1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("delete twice: expected NotFound, got %v", err)
	}
}

// setupCA is a shared helper for tests that need a CA row.
func setupCA(t *testing.T, s *Store) {
	t.Helper()
	if err := s.CreateCA(context.Background(), domain.CA{
		ID: "ca", Name: "ca", Curve: domain.Curve25519,
		Networks: []string{"10.0.0.0/16"},
		CertPEM: "P", KeyArchiveID: "K",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}
