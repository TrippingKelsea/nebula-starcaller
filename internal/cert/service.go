// Package cert is the client-cert lifecycle service layer.
package cert

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/TrippingKelsea/nebula-starcaller/internal/archive"
	"github.com/TrippingKelsea/nebula-starcaller/internal/bundle"
	"github.com/TrippingKelsea/nebula-starcaller/internal/ca"
	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
	"github.com/TrippingKelsea/nebula-starcaller/internal/nebulax"
	"github.com/TrippingKelsea/nebula-starcaller/internal/store"
)

type BundleBuilder interface {
	Build(ctx context.Context, in bundle.Input) ([]byte, error)
}

type Service struct {
	Store         store.Store
	Archive       archive.Archive
	Runner        nebulax.Runner
	CAService     *ca.Service
	Bundle        BundleBuilder
}

type IssueInput struct {
	CAID           string
	Name           string
	Networks       []string
	UnsafeNetworks []string
	Groups         []string
	HostRole       domain.HostRole
	Platform       domain.Platform
	TTL            time.Duration
}

func (s *Service) Issue(ctx context.Context, in IssueInput, actor string) (domain.Cert, []byte, error) {
	caRec, err := s.Store.GetCA(ctx, in.CAID)
	if err != nil {
		return domain.Cert{}, nil, err
	}
	if caRec.RetiredAt != nil {
		return domain.Cert{}, nil, errors.New("cert: cannot issue from retired CA")
	}
	if in.Name == "" {
		return domain.Cert{}, nil, errors.New("cert: name required")
	}
	if len(in.Networks) == 0 {
		return domain.Cert{}, nil, errors.New("cert: at least one network required")
	}
	if err := validateAgainstCA(caRec, in); err != nil {
		return domain.Cert{}, nil, err
	}
	ttl := in.TTL
	if ttl <= 0 {
		ttl = caRec.DefaultCertTTL
	}
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}

	caKey, err := s.CAService.LoadKey(ctx, caRec)
	if err != nil {
		return domain.Cert{}, nil, fmt.Errorf("load CA key: %w", err)
	}

	res, err := s.Runner.Sign(ctx, nebulax.SignReq{
		CACertPEM: []byte(caRec.CertPEM), CAKeyPEM: caKey,
		Name: in.Name, Networks: in.Networks,
		UnsafeNetworks: in.UnsafeNetworks, Groups: in.Groups,
		Duration: ttl,
	})
	if err != nil {
		return domain.Cert{}, nil, err
	}

	// Archive cert + key
	certID, err := s.Archive.Put(ctx, archive.Blob{
		Kind: archive.KindCertPEM, ContentType: "application/x-pem-file",
		Data: res.CertPEM,
	})
	if err != nil {
		return domain.Cert{}, nil, err
	}
	keyID, err := s.Archive.Put(ctx, archive.Blob{
		Kind: archive.KindCertKey, ContentType: "application/x-pem-file",
		Data: res.KeyPEM,
	})
	if err != nil {
		return domain.Cert{}, nil, err
	}

	// Build bundle
	trust := buildTrustBundle(caRec)
	bundleBytes, err := s.Bundle.Build(ctx, bundle.Input{
		HostName: in.Name, CertPEM: res.CertPEM, KeyPEM: res.KeyPEM,
		TrustBundle: trust, HostRole: in.HostRole, Platform: in.Platform,
		Networks: in.Networks, Groups: in.Groups,
	})
	if err != nil {
		return domain.Cert{}, nil, fmt.Errorf("build bundle: %w", err)
	}
	bundleID, err := s.Archive.Put(ctx, archive.Blob{
		Kind: archive.KindBundle, ContentType: "application/gzip",
		Data: bundleBytes,
	})
	if err != nil {
		return domain.Cert{}, nil, err
	}

	c := domain.Cert{
		ID: uuid.NewString(), IssuingCAID: caRec.ID, Name: in.Name,
		Networks: in.Networks, UnsafeNetworks: in.UnsafeNetworks,
		Groups: in.Groups, HostRole: in.HostRole, Platform: in.Platform,
		Fingerprint: res.Fingerprint,
		NotBefore: res.Info.NotBeforeTime(), NotAfter: res.Info.NotAfterTime(),
		CertArchiveID: certID, KeyArchiveID: keyID, BundleArchiveID: bundleID,
		IssuedBy: actor, CreatedAt: time.Now().UTC(),
	}
	// Fallback times if parse failed (e.g., fake runner produced blank)
	if c.NotBefore.IsZero() {
		c.NotBefore = time.Now().UTC()
	}
	if c.NotAfter.IsZero() {
		c.NotAfter = time.Now().Add(ttl).UTC()
	}
	if err := s.Store.CreateCert(ctx, c); err != nil {
		return domain.Cert{}, nil, err
	}

	// Register any new groups declared
	for _, g := range in.Groups {
		_ = s.Store.UpsertGroup(ctx, domain.Group{Name: g, CreatedAt: time.Now().UTC()})
	}

	_ = s.Store.AppendAudit(ctx, domain.AuditEvent{
		At: time.Now().UTC(), Actor: actor, Action: "cert.issue",
		Subject: c.ID,
		Details: fmt.Sprintf(`{"name":%q,"ca":%q}`, c.Name, caRec.Name),
	})
	return c, bundleBytes, nil
}

func (s *Service) Get(ctx context.Context, id string) (domain.Cert, error) {
	return s.Store.GetCert(ctx, id)
}

func (s *Service) List(ctx context.Context, caID string) ([]domain.Cert, error) {
	return s.Store.ListCerts(ctx, caID)
}

// DownloadBundle returns archived bundle bytes for a cert and logs the download.
func (s *Service) DownloadBundle(ctx context.Context, certID, actor string) ([]byte, error) {
	c, err := s.Store.GetCert(ctx, certID)
	if err != nil {
		return nil, err
	}
	b, err := s.Archive.Get(ctx, c.BundleArchiveID)
	if err != nil {
		return nil, err
	}
	_ = s.Store.AppendAudit(ctx, domain.AuditEvent{
		At: time.Now().UTC(), Actor: actor, Action: "cert.download",
		Subject: certID,
	})
	return b.Data, nil
}

func (s *Service) Revoke(ctx context.Context, id, reason, actor string) error {
	if err := s.Store.RevokeCert(ctx, id, reason); err != nil {
		return err
	}
	_ = s.Store.AppendAudit(ctx, domain.AuditEvent{
		At: time.Now().UTC(), Actor: actor, Action: "cert.revoke",
		Subject: id, Details: fmt.Sprintf(`{"reason":%q}`, reason),
	})
	return nil
}

// Rotate issues a new cert with the same identity and marks the old one superseded.
func (s *Service) Rotate(ctx context.Context, oldID string, actor string) (domain.Cert, []byte, error) {
	old, err := s.Store.GetCert(ctx, oldID)
	if err != nil {
		return domain.Cert{}, nil, err
	}
	if old.RevokedAt != nil {
		return domain.Cert{}, nil, errors.New("cert: cannot rotate revoked cert")
	}
	ttl := old.NotAfter.Sub(old.NotBefore)
	newCert, bundle, err := s.Issue(ctx, IssueInput{
		CAID: old.IssuingCAID, Name: old.Name,
		Networks: old.Networks, UnsafeNetworks: old.UnsafeNetworks,
		Groups: old.Groups, HostRole: old.HostRole, Platform: old.Platform,
		TTL: ttl,
	}, actor)
	if err != nil {
		return domain.Cert{}, nil, err
	}
	if err := s.Store.MarkSuperseded(ctx, old.ID, newCert.ID); err != nil {
		return domain.Cert{}, nil, err
	}
	_ = s.Store.AppendAudit(ctx, domain.AuditEvent{
		At: time.Now().UTC(), Actor: actor, Action: "cert.rotate",
		Subject: old.ID,
		Details: fmt.Sprintf(`{"new":%q}`, newCert.ID),
	})
	return newCert, bundle, nil
}

// Blocklist renders the `pki.blocklist` YAML snippet for a CA.
func (s *Service) Blocklist(ctx context.Context, caID string) (string, error) {
	fps, err := s.Store.ListRevokedFingerprints(ctx, caID)
	if err != nil {
		return "", err
	}
	if len(fps) == 0 {
		return "pki:\n  blocklist: []\n", nil
	}
	var b strings.Builder
	b.WriteString("pki:\n  blocklist:\n")
	for _, fp := range fps {
		b.WriteString("    - ")
		b.WriteString(fp)
		b.WriteString("\n")
	}
	return b.String(), nil
}

// validateAgainstCA checks that requested networks and groups fall within
// the CA's declared bounds. This is defense-in-depth; nebula-cert also rejects.
func validateAgainstCA(caRec domain.CA, in IssueInput) error {
	if len(caRec.Groups) > 0 {
		allowed := map[string]bool{}
		for _, g := range caRec.Groups {
			allowed[g] = true
		}
		for _, g := range in.Groups {
			if !allowed[g] {
				return fmt.Errorf("cert: group %q not permitted by CA", g)
			}
		}
	}
	// Network validation: the requested network's IP must lie within one of the
	// CA's networks. We accept if any requested CIDR is-subset-of any CA CIDR,
	// or the CA has no network constraint (empty).
	if len(caRec.Networks) == 0 {
		return nil
	}
	for _, want := range in.Networks {
		if !anyContainsCIDR(caRec.Networks, want) {
			return fmt.Errorf("cert: network %q not permitted by CA", want)
		}
	}
	return nil
}

// buildTrustBundle returns the CA cert PEM(s) that hosts should trust.
// For MVP, we ship only the issuing CA's cert. Multi-root trust bundles will
// concatenate additional CAs here in a future milestone.
func buildTrustBundle(caRec domain.CA) []byte {
	return []byte(caRec.CertPEM)
}
