// Package sqlite is a SQLite-backed implementation of the store.Store interface.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
	"github.com/TrippingKelsea/nebula-starcaller/internal/store"
)

type Store struct {
	db *sql.DB
}

// Open opens (or creates) the database at dsn and applies schema.
// Use dsn = ":memory:" for tests. Otherwise a file path is fine —
// WAL mode is enabled automatically.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Pragmas: foreign keys, WAL, busy timeout
	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
	}
	if !strings.Contains(dsn, ":memory:") {
		pragmas = append(pragmas, "PRAGMA journal_mode = WAL")
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return nil, fmt.Errorf("pragma %q: %w", p, err)
		}
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DB exposes the underlying handle. Used by the archive package which
// shares the same file.
func (s *Store) DB() *sql.DB { return s.db }

// ---------- helpers ----------

func joinCSV(xs []string) string { return strings.Join(xs, ",") }

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func rolesToCSV(rs []domain.Role) string {
	ss := make([]string, len(rs))
	for i, r := range rs {
		ss[i] = string(r)
	}
	return joinCSV(ss)
}

func rolesFromCSV(s string) []domain.Role {
	parts := splitCSV(s)
	out := make([]domain.Role, len(parts))
	for i, p := range parts {
		out[i] = domain.Role(p)
	}
	return out
}

func nullableUnix(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Unix()
}

func fromUnixNullable(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(v.Int64, 0).UTC()
	return &t
}

// ---------- users ----------

func (s *Store) CreateUser(ctx context.Context, u domain.User) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user (id, username, email, password_hash, roles, force_webauthn, created_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		u.ID, u.Username, u.Email, u.PasswordHash,
		rolesToCSV(u.Roles), boolToInt(u.ForceWebAuthnEnrollment),
		u.CreatedAt.Unix(), nullableUnix(u.LastLoginAt),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrDuplicate
		}
	}
	return err
}

func (s *Store) GetUserByID(ctx context.Context, id string) (domain.User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx, userSelect+" WHERE id = ?", id))
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx, userSelect+" WHERE username = ?", username))
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user`).Scan(&n)
	return n, err
}

func (s *Store) UpdateUser(ctx context.Context, u domain.User) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE user SET email = ?, password_hash = ?, roles = ?, force_webauthn = ?, last_login_at = ?
		WHERE id = ?
	`,
		u.Email, u.PasswordHash, rolesToCSV(u.Roles),
		boolToInt(u.ForceWebAuthnEnrollment), nullableUnix(u.LastLoginAt),
		u.ID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.db.QueryContext(ctx, userSelect+" ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		u, err := s.scanUserRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

const userSelect = `SELECT id, username, email, password_hash, roles, force_webauthn, created_at, last_login_at FROM user`

type scanner interface {
	Scan(dest ...any) error
}

func (s *Store) scanUser(r scanner) (domain.User, error) {
	return scanUserFrom(r)
}

func (s *Store) scanUserRow(r *sql.Rows) (domain.User, error) {
	return scanUserFrom(r)
}

func scanUserFrom(r scanner) (domain.User, error) {
	var u domain.User
	var (
		roles       string
		forceWebAuthn int
		createdAt   int64
		lastLoginAt sql.NullInt64
	)
	err := r.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &roles, &forceWebAuthn, &createdAt, &lastLoginAt)
	if errors.Is(err, sql.ErrNoRows) {
		return u, store.ErrNotFound
	}
	if err != nil {
		return u, err
	}
	u.Roles = rolesFromCSV(roles)
	u.ForceWebAuthnEnrollment = forceWebAuthn == 1
	u.CreatedAt = time.Unix(createdAt, 0).UTC()
	u.LastLoginAt = fromUnixNullable(lastLoginAt)
	return u, nil
}

// ---------- webauthn credentials ----------

func (s *Store) AddWebAuthnCredential(ctx context.Context, c domain.WebAuthnCredential) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO webauthn_credential (id, user_id, credential_id, public_key, attest_type, aaguid, sign_count, clone_warning, name, created_at, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, c.ID, c.UserID, c.CredentialID, c.PublicKey, c.AttestType, c.AAGUID, c.SignCount, boolToInt(c.CloneWarning), c.Name, c.CreatedAt.Unix(), nullableUnix(c.LastUsedAt))
	return err
}

func (s *Store) ListWebAuthnCredentials(ctx context.Context, userID string) ([]domain.WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, credential_id, public_key, attest_type, aaguid, sign_count, clone_warning, name, created_at, last_used_at
		FROM webauthn_credential WHERE user_id = ? ORDER BY created_at
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.WebAuthnCredential
	for rows.Next() {
		var c domain.WebAuthnCredential
		var (
			clone      int
			createdAt  int64
			lastUsedAt sql.NullInt64
		)
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.AttestType, &c.AAGUID, &c.SignCount, &clone, &c.Name, &createdAt, &lastUsedAt); err != nil {
			return nil, err
		}
		c.CloneWarning = clone == 1
		c.CreatedAt = time.Unix(createdAt, 0).UTC()
		c.LastUsedAt = fromUnixNullable(lastUsedAt)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) UpdateWebAuthnSignCount(ctx context.Context, id string, count uint32) error {
	_, err := s.db.ExecContext(ctx, `UPDATE webauthn_credential SET sign_count = ?, last_used_at = ? WHERE id = ?`,
		count, time.Now().UTC().Unix(), id)
	return err
}

func (s *Store) DeleteWebAuthnCredential(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_credential WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ---------- sessions ----------

func (s *Store) CreateSession(ctx context.Context, sess domain.Session) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO session (id, user_id, created_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)
	`, sess.ID, sess.UserID, sess.CreatedAt.Unix(), sess.ExpiresAt.Unix(), sess.IP, sess.UserAgent)
	return err
}

func (s *Store) GetSession(ctx context.Context, id string) (domain.Session, error) {
	var sess domain.Session
	var createdAt, expiresAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, created_at, expires_at, ip, user_agent FROM session WHERE id = ?
	`, id).Scan(&sess.ID, &sess.UserID, &createdAt, &expiresAt, &sess.IP, &sess.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return sess, store.ErrNotFound
	}
	if err != nil {
		return sess, err
	}
	sess.CreatedAt = time.Unix(createdAt, 0).UTC()
	sess.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	return sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM session WHERE id = ?`, id)
	return err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM session WHERE expires_at < ?`, time.Now().UTC().Unix())
	return err
}

// ---------- CAs ----------

func (s *Store) CreateCA(ctx context.Context, ca domain.CA) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ca (id, name, description, curve, networks, unsafe_networks, groups_json, cert_pem, key_archive_id, duration_ns, default_cert_ttl_ns, created_at, retired_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		ca.ID, ca.Name, ca.Description, string(ca.Curve),
		joinCSV(ca.Networks), joinCSV(ca.UnsafeNetworks), joinCSV(ca.Groups),
		ca.CertPEM, ca.KeyArchiveID,
		int64(ca.Duration), int64(ca.DefaultCertTTL),
		ca.CreatedAt.Unix(), nullableUnix(ca.RetiredAt),
	)
	if err != nil && isUniqueViolation(err) {
		return store.ErrDuplicate
	}
	return err
}

func (s *Store) GetCA(ctx context.Context, id string) (domain.CA, error) {
	return scanCA(s.db.QueryRowContext(ctx, caSelect+" WHERE id = ?", id))
}

func (s *Store) ListCAs(ctx context.Context) ([]domain.CA, error) {
	rows, err := s.db.QueryContext(ctx, caSelect+" ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.CA
	for rows.Next() {
		ca, err := scanCA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ca)
	}
	return out, rows.Err()
}

func (s *Store) RetireCA(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE ca SET retired_at = ? WHERE id = ? AND retired_at IS NULL`,
		time.Now().UTC().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

const caSelect = `SELECT id, name, description, curve, networks, unsafe_networks, groups_json, cert_pem, key_archive_id, duration_ns, default_cert_ttl_ns, created_at, retired_at FROM ca`

func scanCA(r scanner) (domain.CA, error) {
	var (
		ca                        domain.CA
		curve                     string
		networks, unsafe, groups  string
		durationNS, ttlNS         int64
		createdAt                 int64
		retiredAt                 sql.NullInt64
	)
	err := r.Scan(&ca.ID, &ca.Name, &ca.Description, &curve, &networks, &unsafe, &groups, &ca.CertPEM, &ca.KeyArchiveID, &durationNS, &ttlNS, &createdAt, &retiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ca, store.ErrNotFound
	}
	if err != nil {
		return ca, err
	}
	ca.Curve = domain.Curve(curve)
	ca.Networks = splitCSV(networks)
	ca.UnsafeNetworks = splitCSV(unsafe)
	ca.Groups = splitCSV(groups)
	ca.Duration = time.Duration(durationNS)
	ca.DefaultCertTTL = time.Duration(ttlNS)
	ca.CreatedAt = time.Unix(createdAt, 0).UTC()
	ca.RetiredAt = fromUnixNullable(retiredAt)
	return ca, nil
}

// ---------- certs ----------

func (s *Store) CreateCert(ctx context.Context, c domain.Cert) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cert (id, issuing_ca_id, name, networks, unsafe_networks, groups_json, host_role, platform_os, platform_arch, fingerprint, not_before, not_after, cert_archive_id, key_archive_id, bundle_archive_id, issued_by, created_at, revoked_at, revocation_reason, superseded_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		c.ID, c.IssuingCAID, c.Name,
		joinCSV(c.Networks), joinCSV(c.UnsafeNetworks), joinCSV(c.Groups),
		string(c.HostRole), c.Platform.OS, c.Platform.Arch,
		c.Fingerprint, c.NotBefore.Unix(), c.NotAfter.Unix(),
		c.CertArchiveID, c.KeyArchiveID, c.BundleArchiveID,
		c.IssuedBy, c.CreatedAt.Unix(), nullableUnix(c.RevokedAt),
		c.RevocationReason, c.SupersededBy,
	)
	return err
}

func (s *Store) GetCert(ctx context.Context, id string) (domain.Cert, error) {
	return scanCert(s.db.QueryRowContext(ctx, certSelect+" WHERE id = ?", id))
}

func (s *Store) ListCerts(ctx context.Context, caID string) ([]domain.Cert, error) {
	return s.listCerts(ctx, certSelect+" WHERE issuing_ca_id = ? ORDER BY created_at DESC", caID)
}

func (s *Store) ListActiveCerts(ctx context.Context, caID string) ([]domain.Cert, error) {
	return s.listCerts(ctx,
		certSelect+" WHERE issuing_ca_id = ? AND revoked_at IS NULL AND superseded_by = '' ORDER BY created_at DESC",
		caID)
}

func (s *Store) listCerts(ctx context.Context, query string, args ...any) ([]domain.Cert, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Cert
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) RevokeCert(ctx context.Context, id, reason string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE cert SET revoked_at = ?, revocation_reason = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().UTC().Unix(), reason, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) MarkSuperseded(ctx context.Context, id, byID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE cert SET superseded_by = ? WHERE id = ?`, byID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) ListRevokedFingerprints(ctx context.Context, caID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT fingerprint FROM cert WHERE issuing_ca_id = ? AND revoked_at IS NOT NULL AND fingerprint != '' ORDER BY revoked_at`, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out = append(out, fp)
	}
	return out, rows.Err()
}

const certSelect = `SELECT id, issuing_ca_id, name, networks, unsafe_networks, groups_json, host_role, platform_os, platform_arch, fingerprint, not_before, not_after, cert_archive_id, key_archive_id, bundle_archive_id, issued_by, created_at, revoked_at, revocation_reason, superseded_by FROM cert`

func scanCert(r scanner) (domain.Cert, error) {
	var (
		c                          domain.Cert
		networks, unsafe, groups   string
		hostRole                   string
		notBefore, notAfter        int64
		createdAt                  int64
		revokedAt                  sql.NullInt64
	)
	err := r.Scan(&c.ID, &c.IssuingCAID, &c.Name, &networks, &unsafe, &groups, &hostRole, &c.Platform.OS, &c.Platform.Arch, &c.Fingerprint, &notBefore, &notAfter, &c.CertArchiveID, &c.KeyArchiveID, &c.BundleArchiveID, &c.IssuedBy, &createdAt, &revokedAt, &c.RevocationReason, &c.SupersededBy)
	if errors.Is(err, sql.ErrNoRows) {
		return c, store.ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c.Networks = splitCSV(networks)
	c.UnsafeNetworks = splitCSV(unsafe)
	c.Groups = splitCSV(groups)
	c.HostRole = domain.HostRole(hostRole)
	c.NotBefore = time.Unix(notBefore, 0).UTC()
	c.NotAfter = time.Unix(notAfter, 0).UTC()
	c.CreatedAt = time.Unix(createdAt, 0).UTC()
	c.RevokedAt = fromUnixNullable(revokedAt)
	return c, nil
}

// ---------- groups ----------

func (s *Store) UpsertGroup(ctx context.Context, g domain.Group) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO group_registry (name, description, created_at) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET description = excluded.description
	`, g.Name, g.Description, g.CreatedAt.Unix())
	return err
}

func (s *Store) ListGroups(ctx context.Context) ([]domain.Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, description, created_at FROM group_registry ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Group
	for rows.Next() {
		var g domain.Group
		var createdAt int64
		if err := rows.Scan(&g.Name, &g.Description, &createdAt); err != nil {
			return nil, err
		}
		g.CreatedAt = time.Unix(createdAt, 0).UTC()
		out = append(out, g)
	}
	return out, rows.Err()
}

// ---------- audit ----------

func (s *Store) AppendAudit(ctx context.Context, e domain.AuditEvent) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log (at, actor, action, subject, details, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)
	`, e.At.Unix(), e.Actor, e.Action, e.Subject, e.Details, e.IP, e.UserAgent)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]domain.AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, at, actor, action, subject, details, ip, user_agent FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AuditEvent
	for rows.Next() {
		var e domain.AuditEvent
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Subject, &e.Details, &e.IP, &e.UserAgent); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------- helpers ----------

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// isUniqueViolation checks for SQLite constraint failure. modernc.org/sqlite
// wraps errors with the extended result code as text ("UNIQUE constraint failed:").
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "constraint failed")
}
