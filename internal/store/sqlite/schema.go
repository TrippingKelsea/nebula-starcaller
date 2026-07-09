package sqlite

const schema = `
CREATE TABLE IF NOT EXISTS user (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	email TEXT NOT NULL DEFAULT '',
	password_hash TEXT NOT NULL,
	roles TEXT NOT NULL DEFAULT '',        -- comma-separated
	force_webauthn INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS webauthn_credential (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
	credential_id BLOB NOT NULL,
	public_key BLOB NOT NULL,
	attest_type TEXT NOT NULL DEFAULT '',
	aaguid BLOB NOT NULL DEFAULT '',
	sign_count INTEGER NOT NULL DEFAULT 0,
	clone_warning INTEGER NOT NULL DEFAULT 0,
	name TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	last_used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_webauthn_cred_user ON webauthn_credential(user_id);

CREATE TABLE IF NOT EXISTS session (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_session_expires ON session(expires_at);

CREATE TABLE IF NOT EXISTS ca (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	curve TEXT NOT NULL,
	networks TEXT NOT NULL DEFAULT '',
	unsafe_networks TEXT NOT NULL DEFAULT '',
	groups_json TEXT NOT NULL DEFAULT '',
	cert_pem TEXT NOT NULL,
	key_archive_id TEXT NOT NULL,
	duration_ns INTEGER NOT NULL DEFAULT 0,
	default_cert_ttl_ns INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	retired_at INTEGER
);

CREATE TABLE IF NOT EXISTS cert (
	id TEXT PRIMARY KEY,
	issuing_ca_id TEXT NOT NULL REFERENCES ca(id),
	name TEXT NOT NULL,
	networks TEXT NOT NULL DEFAULT '',
	unsafe_networks TEXT NOT NULL DEFAULT '',
	groups_json TEXT NOT NULL DEFAULT '',
	host_role TEXT NOT NULL DEFAULT '',
	platform_os TEXT NOT NULL DEFAULT '',
	platform_arch TEXT NOT NULL DEFAULT '',
	fingerprint TEXT NOT NULL,
	not_before INTEGER NOT NULL,
	not_after INTEGER NOT NULL,
	cert_archive_id TEXT NOT NULL,
	key_archive_id TEXT NOT NULL,
	bundle_archive_id TEXT NOT NULL,
	issued_by TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	revoked_at INTEGER,
	revocation_reason TEXT NOT NULL DEFAULT '',
	superseded_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cert_ca ON cert(issuing_ca_id);
CREATE INDEX IF NOT EXISTS idx_cert_ca_revoked ON cert(issuing_ca_id, revoked_at);
CREATE INDEX IF NOT EXISTS idx_cert_fp ON cert(fingerprint);

CREATE TABLE IF NOT EXISTS group_registry (
	name TEXT PRIMARY KEY,
	description TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	at INTEGER NOT NULL,
	actor TEXT NOT NULL DEFAULT '',
	action TEXT NOT NULL,
	subject TEXT NOT NULL DEFAULT '',
	details TEXT NOT NULL DEFAULT '',
	ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);

CREATE TABLE IF NOT EXISTS archive (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
	size INTEGER NOT NULL,
	data BLOB NOT NULL,
	created_at INTEGER NOT NULL
);
`
