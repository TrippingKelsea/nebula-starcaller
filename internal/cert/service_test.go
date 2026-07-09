package cert_test

import (
	"context"
	"strings"
	"testing"
	"time"

	archsqlite "github.com/TrippingKelsea/nebula-starcaller/internal/archive/sqlite"
	"github.com/TrippingKelsea/nebula-starcaller/internal/bundle"
	"github.com/TrippingKelsea/nebula-starcaller/internal/ca"
	"github.com/TrippingKelsea/nebula-starcaller/internal/cert"
	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
	"github.com/TrippingKelsea/nebula-starcaller/internal/nebulax"
	storesqlite "github.com/TrippingKelsea/nebula-starcaller/internal/store/sqlite"
)

func newSvc(t *testing.T) (*cert.Service, *ca.Service, *storesqlite.Store) {
	t.Helper()
	s, err := storesqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	a := archsqlite.New(s.DB())
	fake := nebulax.NewFake()
	casvc := &ca.Service{Store: s, Archive: a, Runner: fake}
	b := &bundle.Builder{Binaries: bundle.StubProvider{}}
	svc := &cert.Service{Store: s, Archive: a, Runner: fake, CAService: casvc, Bundle: b}
	return svc, casvc, s
}

func mkCA(t *testing.T, svc *ca.Service) domain.CA {
	t.Helper()
	c, err := svc.Create(context.Background(), ca.CreateInput{
		Name:           "root-" + strings.ReplaceAll(t.Name(), "/", "-"),
		Curve:          domain.CurveP256,
		Networks:       []string{"10.42.0.0/16"},
		Groups:         []string{"servers", "workstations"},
		Duration:       365 * 24 * time.Hour,
		DefaultCertTTL: 24 * time.Hour,
	}, "u")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIssueHappy(t *testing.T) {
	ctx := context.Background()
	svc, casvc, s := newSvc(t)
	caRec := mkCA(t, casvc)

	c, bundleBytes, err := svc.Issue(ctx, cert.IssueInput{
		CAID:     caRec.ID,
		Name:     "host-01",
		Networks: []string{"10.42.0.5/16"},
		Groups:   []string{"servers"},
		HostRole: domain.HostRoleHost,
		Platform: domain.Platform{OS: "linux", Arch: "amd64"},
		TTL:      12 * time.Hour,
	}, "u1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if c.Fingerprint == "" || c.IssuingCAID != caRec.ID {
		t.Errorf("bad cert: %+v", c)
	}
	if len(bundleBytes) == 0 {
		t.Error("empty bundle")
	}
	dl, err := svc.DownloadBundle(ctx, c.ID, "u1")
	if err != nil || len(dl) == 0 {
		t.Errorf("DownloadBundle: %v len=%d", err, len(dl))
	}
	events, _ := s.ListAudit(ctx, 10)
	var haveIssue, haveDownload bool
	for _, e := range events {
		if e.Action == "cert.issue" {
			haveIssue = true
		}
		if e.Action == "cert.download" {
			haveDownload = true
		}
	}
	if !haveIssue || !haveDownload {
		t.Errorf("expected cert.issue + cert.download audit events; got %+v", events)
	}
}

func TestIssueRejectsUnknownGroup(t *testing.T) {
	ctx := context.Background()
	svc, casvc, _ := newSvc(t)
	caRec := mkCA(t, casvc)
	if _, _, err := svc.Issue(ctx, cert.IssueInput{
		CAID: caRec.ID, Name: "h",
		Networks: []string{"10.42.0.5/16"},
		Groups:   []string{"unlisted-group"},
	}, "u"); err == nil {
		t.Fatal("expected error for unlisted group")
	}
}

func TestIssueRejectsOutOfNetwork(t *testing.T) {
	ctx := context.Background()
	svc, casvc, _ := newSvc(t)
	caRec := mkCA(t, casvc)
	if _, _, err := svc.Issue(ctx, cert.IssueInput{
		CAID: caRec.ID, Name: "h",
		Networks: []string{"192.168.5.0/24"},
	}, "u"); err == nil {
		t.Fatal("expected error for out-of-network CIDR")
	}
}

func TestIssueRejectsRetiredCA(t *testing.T) {
	ctx := context.Background()
	svc, casvc, _ := newSvc(t)
	caRec := mkCA(t, casvc)
	_ = casvc.Retire(ctx, caRec.ID, "u")
	if _, _, err := svc.Issue(ctx, cert.IssueInput{
		CAID: caRec.ID, Name: "h",
		Networks: []string{"10.42.0.5/16"},
	}, "u"); err == nil {
		t.Error("expected error for retired CA")
	}
}

func TestRevokeAndBlocklist(t *testing.T) {
	ctx := context.Background()
	svc, casvc, _ := newSvc(t)
	caRec := mkCA(t, casvc)
	c, _, _ := svc.Issue(ctx, cert.IssueInput{
		CAID: caRec.ID, Name: "h",
		Networks: []string{"10.42.0.5/16"},
	}, "u")

	bl, err := svc.Blocklist(ctx, caRec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bl != "pki:\n  blocklist: []\n" {
		t.Errorf("expected empty blocklist, got %q", bl)
	}

	if err := svc.Revoke(ctx, c.ID, "compromised", "u"); err != nil {
		t.Fatal(err)
	}
	bl, _ = svc.Blocklist(ctx, caRec.ID)
	if !strings.Contains(bl, c.Fingerprint) {
		t.Errorf("blocklist should contain fingerprint %q; got %q", c.Fingerprint, bl)
	}
}

func TestRotate(t *testing.T) {
	ctx := context.Background()
	svc, casvc, s := newSvc(t)
	caRec := mkCA(t, casvc)
	old, _, _ := svc.Issue(ctx, cert.IssueInput{
		CAID: caRec.ID, Name: "h",
		Networks: []string{"10.42.0.5/16"},
	}, "u")
	newCert, bundleBytes, err := svc.Rotate(ctx, old.ID, "u")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newCert.ID == old.ID {
		t.Error("rotated cert should have new ID")
	}
	if len(bundleBytes) == 0 {
		t.Error("empty rotated bundle")
	}
	oldFetch, _ := s.GetCert(ctx, old.ID)
	if oldFetch.SupersededBy != newCert.ID {
		t.Errorf("old cert should be superseded; got %+v", oldFetch)
	}
}

func TestRotateRejectsRevoked(t *testing.T) {
	ctx := context.Background()
	svc, casvc, _ := newSvc(t)
	caRec := mkCA(t, casvc)
	c, _, _ := svc.Issue(ctx, cert.IssueInput{
		CAID: caRec.ID, Name: "h",
		Networks: []string{"10.42.0.5/16"},
	}, "u")
	_ = svc.Revoke(ctx, c.ID, "reason", "u")
	if _, _, err := svc.Rotate(ctx, c.ID, "u"); err == nil {
		t.Error("expected rotate to fail for revoked cert")
	}
}

func TestListCerts(t *testing.T) {
	ctx := context.Background()
	svc, casvc, _ := newSvc(t)
	caRec := mkCA(t, casvc)
	for i := 0; i < 3; i++ {
		if _, _, err := svc.Issue(ctx, cert.IssueInput{
			CAID: caRec.ID, Name: "h",
			Networks: []string{"10.42.0.5/16"},
		}, "u"); err != nil {
			t.Fatal(err)
		}
	}
	list, err := svc.List(ctx, caRec.ID)
	if err != nil || len(list) != 3 {
		t.Errorf("List: n=%d err=%v", len(list), err)
	}
}
