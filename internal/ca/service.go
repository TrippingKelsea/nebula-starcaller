// Package ca is the CA-creation and management service layer.
package ca

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/TrippingKelsea/nebula-starcaller/internal/archive"
	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
	"github.com/TrippingKelsea/nebula-starcaller/internal/nebulax"
	"github.com/TrippingKelsea/nebula-starcaller/internal/store"
)

type Service struct {
	Store   store.Store
	Archive archive.Archive
	Runner  nebulax.Runner
}

type CreateInput struct {
	Name           string
	Description    string
	Curve          domain.Curve
	Networks       []string
	UnsafeNetworks []string
	Groups         []string
	Duration       time.Duration
	DefaultCertTTL time.Duration
}

func (s *Service) Create(ctx context.Context, in CreateInput, actor string) (domain.CA, error) {
	if in.Name == "" {
		return domain.CA{}, errors.New("ca: name required")
	}
	if in.Curve == "" {
		in.Curve = domain.Curve25519
	}
	if len(in.Networks) == 0 {
		return domain.CA{}, errors.New("ca: at least one network required")
	}
	if in.Duration <= 0 {
		in.Duration = 365 * 24 * time.Hour
	}
	if in.DefaultCertTTL <= 0 {
		in.DefaultCertTTL = 30 * 24 * time.Hour
	}
	if in.DefaultCertTTL >= in.Duration {
		return domain.CA{}, errors.New("ca: default_cert_ttl must be less than ca duration")
	}

	res, err := s.Runner.CA(ctx, nebulax.CAReq{
		Name: in.Name, Curve: string(in.Curve),
		Networks: in.Networks, UnsafeNetworks: in.UnsafeNetworks,
		Groups: in.Groups, Duration: in.Duration,
	})
	if err != nil {
		return domain.CA{}, err
	}

	keyID, err := s.Archive.Put(ctx, archive.Blob{
		Kind: archive.KindCAKey, ContentType: "application/x-pem-file",
		Data: res.KeyPEM,
	})
	if err != nil {
		return domain.CA{}, fmt.Errorf("archive ca key: %w", err)
	}

	ca := domain.CA{
		ID: uuid.NewString(), Name: in.Name, Description: in.Description,
		Curve: in.Curve, Networks: in.Networks,
		UnsafeNetworks: in.UnsafeNetworks, Groups: in.Groups,
		CertPEM: string(res.CertPEM), KeyArchiveID: keyID,
		Duration: in.Duration, DefaultCertTTL: in.DefaultCertTTL,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.Store.CreateCA(ctx, ca); err != nil {
		// Best effort: drop the archived key on failure.
		_ = s.Archive.Delete(ctx, keyID)
		return domain.CA{}, err
	}

	// Register any groups this CA declared into the shared registry.
	for _, g := range in.Groups {
		_ = s.Store.UpsertGroup(ctx, domain.Group{
			Name: g, CreatedAt: time.Now().UTC(),
		})
	}

	_ = s.Store.AppendAudit(ctx, domain.AuditEvent{
		At: time.Now().UTC(), Actor: actor, Action: "ca.create",
		Subject: ca.ID, Details: `{"name":"` + ca.Name + `"}`,
	})
	return ca, nil
}

func (s *Service) List(ctx context.Context) ([]domain.CA, error) { return s.Store.ListCAs(ctx) }

func (s *Service) Get(ctx context.Context, id string) (domain.CA, error) {
	return s.Store.GetCA(ctx, id)
}

func (s *Service) Retire(ctx context.Context, id, actor string) error {
	if err := s.Store.RetireCA(ctx, id); err != nil {
		return err
	}
	_ = s.Store.AppendAudit(ctx, domain.AuditEvent{
		At: time.Now().UTC(), Actor: actor, Action: "ca.retire", Subject: id,
	})
	return nil
}

// LoadKey retrieves the raw CA private key PEM from the archive. Callers
// must handle the material carefully — it is the CA signing key.
func (s *Service) LoadKey(ctx context.Context, ca domain.CA) ([]byte, error) {
	b, err := s.Archive.Get(ctx, ca.KeyArchiveID)
	if err != nil {
		return nil, err
	}
	return b.Data, nil
}
