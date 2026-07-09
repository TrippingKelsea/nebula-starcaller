// Package store defines the persistence interface for structured Starcaller
// state. Blob storage (keys, certs, bundles) lives in the archive package.
package store

import (
	"context"
	"errors"

	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrDuplicate  = errors.New("duplicate")
)

type Store interface {
	// Users
	CreateUser(ctx context.Context, u domain.User) error
	GetUserByID(ctx context.Context, id string) (domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (domain.User, error)
	CountUsers(ctx context.Context) (int, error)
	UpdateUser(ctx context.Context, u domain.User) error
	ListUsers(ctx context.Context) ([]domain.User, error)

	// WebAuthn credentials
	AddWebAuthnCredential(ctx context.Context, c domain.WebAuthnCredential) error
	ListWebAuthnCredentials(ctx context.Context, userID string) ([]domain.WebAuthnCredential, error)
	UpdateWebAuthnSignCount(ctx context.Context, id string, count uint32) error
	DeleteWebAuthnCredential(ctx context.Context, id string) error

	// Sessions
	CreateSession(ctx context.Context, s domain.Session) error
	GetSession(ctx context.Context, id string) (domain.Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteExpiredSessions(ctx context.Context) error

	// CAs
	CreateCA(ctx context.Context, ca domain.CA) error
	GetCA(ctx context.Context, id string) (domain.CA, error)
	ListCAs(ctx context.Context) ([]domain.CA, error)
	RetireCA(ctx context.Context, id string) error

	// Certs
	CreateCert(ctx context.Context, c domain.Cert) error
	GetCert(ctx context.Context, id string) (domain.Cert, error)
	ListCerts(ctx context.Context, caID string) ([]domain.Cert, error)
	ListActiveCerts(ctx context.Context, caID string) ([]domain.Cert, error)
	RevokeCert(ctx context.Context, id, reason string) error
	MarkSuperseded(ctx context.Context, id, byID string) error
	ListRevokedFingerprints(ctx context.Context, caID string) ([]string, error)

	// Groups
	UpsertGroup(ctx context.Context, g domain.Group) error
	ListGroups(ctx context.Context) ([]domain.Group, error)

	// Audit
	AppendAudit(ctx context.Context, e domain.AuditEvent) error
	ListAudit(ctx context.Context, limit int) ([]domain.AuditEvent, error)

	Close() error
}
