// Package domain holds pure data types used across services.
// No I/O, no dependencies on store/archive — types only.
package domain

import "time"

type Curve string

const (
	Curve25519 Curve = "25519"
	CurveP256  Curve = "P256"
)

// Role is a coarse-grained authorization role assigned to a user.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleApprover Role = "approver"
	RoleViewer   Role = "viewer"
)

// HostRole is the intended role of a host in the Nebula network.
// Drives config.yml template rendering in the bundle.
type HostRole string

const (
	HostRoleLighthouse HostRole = "lighthouse"
	HostRoleRelay      HostRole = "relay"
	HostRoleHost       HostRole = "host"
)

// Platform identifies the target OS/arch for a bundle's nebula binary.
type Platform struct {
	OS   string // linux, darwin, windows
	Arch string // amd64, arm64
}

func (p Platform) String() string { return p.OS + "-" + p.Arch }

type CA struct {
	ID              string
	Name            string
	Description     string
	Curve           Curve
	Networks        []string // CIDRs
	UnsafeNetworks  []string
	Groups          []string
	CertPEM         string
	KeyArchiveID    string    // reference into Archive
	Duration        time.Duration
	DefaultCertTTL  time.Duration
	CreatedAt       time.Time
	RetiredAt       *time.Time
}

type Cert struct {
	ID                string
	IssuingCAID       string
	Name              string
	Networks          []string
	UnsafeNetworks    []string
	Groups            []string
	HostRole          HostRole
	Platform          Platform
	Fingerprint       string
	NotBefore         time.Time
	NotAfter          time.Time
	CertArchiveID     string
	KeyArchiveID      string
	BundleArchiveID   string
	IssuedBy          string // user ID
	CreatedAt         time.Time
	RevokedAt         *time.Time
	RevocationReason  string
	SupersededBy      string
}

type User struct {
	ID                       string
	Username                 string
	Email                    string
	PasswordHash             string // argon2id-encoded
	Roles                    []Role
	ForceWebAuthnEnrollment  bool
	CreatedAt                time.Time
	LastLoginAt              *time.Time
}

// WebAuthnCredential is a stored WebAuthn public-key credential.
type WebAuthnCredential struct {
	ID           string
	UserID       string
	CredentialID []byte
	PublicKey    []byte
	AttestType   string
	AAGUID       []byte
	SignCount    uint32
	CloneWarning bool
	Name         string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
}

type Group struct {
	Name        string
	Description string
	CreatedAt   time.Time
}

// AuditEvent captures a single state-changing action.
type AuditEvent struct {
	ID        int64
	At        time.Time
	Actor     string // user ID or "system"
	Action    string
	Subject   string // resource ID acted upon
	Details   string // free-form JSON blob
	IP        string
	UserAgent string
}
