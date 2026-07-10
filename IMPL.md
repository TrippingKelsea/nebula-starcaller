# Nebula Starcaller — Implementation Log

Running log of implementation decisions, assumptions, and known deviations from SPEC.md.

## 2026-07-09 — M1 kickoff

### Approach

Implementing M1 per SPEC v0.3 §12. Building bottom-up: config → store → archive → auth → CA service → cert service → bundle builder → HTTP/views → container.

### Judgment calls made without asking

Documenting here rather than blocking on each. Push back if any of these are wrong.

**Language / framework:**
- Go 1.26 (as available on host).
- Router: `github.com/go-chi/chi/v5`. Chosen over stdlib `http.ServeMux` because we need middleware composition (auth, csrf, logging) and Chi is the least-intrusive option.
- SQLite: `modernc.org/sqlite` (pure Go). Keeps CGO off, so the container build stays simple even alongside the CGO'd `nebula-cert`.
- WebAuthn: `github.com/go-webauthn/webauthn`.
- Password hashing: `golang.org/x/crypto/argon2`.
- YAML: `gopkg.in/yaml.v3` for config parsing and `config.yml` bundle rendering.
- CSRF: `github.com/gorilla/csrf`.
- Session storage: sessions live in SQLite (`session` table), cookie carries only session ID. Avoids a second dependency.

**Testing:**
- Table-driven where practical.
- SQLite tests use `:memory:` databases.
- CA/cert service tests use a fake `nebula-cert` shim (a shell script or a Go-built stub on PATH) so we don't require the real binary during unit tests. A separate integration test invokes the real `nebula-cert`.
- Aim: >70% line coverage across `internal/`.

**Config precedence:** env vars > config file > defaults. Config file at `/etc/starcaller/config.yml` by default; overridable with `STARCALLER_CONFIG`.

**Bootstrap semantics:**
- `STARCALLER_BOOTSTRAP_USERNAME` + `STARCALLER_BOOTSTRAP_PASSWORD` env (or `bootstrap:` block in config).
- If no user exists → create as admin, hash password with argon2id, mark `force_webauthn_enrollment=true`.
- If any user exists → ignore bootstrap vars, log warning if set.

**Domain model note:** SPEC uses `signer` in the data model but §5 dropped per-signer topologies. Reinterpreting `signer` as legacy — MVP doesn't need this table. Approval-related tables (`approval_policy`, `approval`, `request`) are also deferred per §12; schema will include stubs so migrations don't require re-work when approval workflow lands.

**Package layout:**
```
cmd/starcaller/          main
internal/config/         config loading
internal/domain/         pure types (CA, Cert, User, etc.)
internal/store/          Store interface + SQLite impl
internal/archive/        Archive interface + SQLite impl
internal/auth/           password, session, webauthn
internal/ca/             CA service (shells to nebula-cert)
internal/cert/           cert service
internal/bundle/         bundle builder
internal/server/         HTTP handlers + middleware
web/templates/           HTML templates
web/static/              css, htmx, alpine
```

**Nebula binaries in container:** Fetched at `docker build` time from GitHub releases for linux/amd64, linux/arm64, darwin/arm64, windows/amd64. Version pinned in a `NEBULA_VERSION` build arg. `nebula-cert` for the host arch is placed on the container's PATH; the runtime `nebula` binaries for each supported platform are staged under `/opt/starcaller/binaries/<os>-<arch>/nebula[.exe]` for inclusion in bundles.

**In-flight CA key hygiene (SPEC §11.3):** Materialize CA key to a file under `/dev/shm/starcaller-<random>/` (tmpfs), invoke `nebula-cert`, then `os.Remove` and best-effort `unix.Munlock`/overwrite. On systems without `/dev/shm` (e.g., macOS in dev), fall back to `os.TempDir()` with a WARN log. Full memfd_create is nice-to-have but adds syscall complexity; deferred.

### Open assumptions I'll revisit if they bite

- Bundle install.sh assumes systemd. For non-systemd hosts, install.sh will print manual instructions instead. macOS/Windows install stories are print-only for MVP.
- Group registry: `group` table starts empty; a group is auto-added the first time a CA declares it. Explicit "add group to registry" UI is v2.
- Default cert TTL fallback chain: request → CA default → 8760h (1y).
- Config bundle `pki.blocklist` rendering: revoked certs are rendered as fingerprints; template supports multi-fingerprint list.

### Deviations from SPEC (if any)

**2026-07-09 — WebAuthn testing scope.** Full WebAuthn requires a browser or CTAP2 mock authenticator. The go-webauthn library has integration test helpers but exercising them well is a large investment. Decision for M1: implement password + session auth thoroughly with unit tests. Wire the WebAuthn library into begin-registration / finish-registration / begin-login / finish-login handlers. Unit-test only the code around the library (session bookkeeping, credential persistence, error paths). End-to-end WebAuthn flow will be validated manually in the browser as part of M1 acceptance. Documented as a known test gap.

**2026-07-09 — `signer` table dropped.** SPEC §6 lists a `signer` table for per-signer YubiKey identities. That model was superseded when we moved to app-held CA (§3 decision 2 in SPEC v0.3). No `signer` table in the SQLite schema.

**2026-07-09 — WebAuthn HTTP handlers not exposed yet.** The `auth.WebAuthnService` is implemented (registration + login flows) and wired into `main`, but the server does not yet expose HTTP endpoints for the enrollment or login-with-WebAuthn flow. Password login works end-to-end; the `ForceWebAuthnEnrollment` flag on the bootstrap user is currently a no-op. This is a known gap to close before shipping M1 publicly. Tracked as a follow-up.

**2026-07-09 — CSRF middleware not enabled.** Chi is set up and forms use POST, but `gorilla/csrf` is not yet wired into the middleware stack. All state-changing endpoints are behind session auth (SameSite=Strict cookies), which mitigates most CSRF vectors, but this should be layered in explicitly before public release.

**2026-07-09 — HTMX placeholder.** `web/static/js/htmx.min.js` is a stub. The current UI uses plain form submissions — no HTMX behaviors are strictly required for M1. When the first HTMX behavior is added, replace the placeholder with the real minified library (or serve it from a locked-down CDN alternative).

### Test coverage snapshot (2026-07-09 M1 completion)

| Package | Coverage | Notes |
|---|---|---|
| internal/config | 82.9% | env override matrix, defaults, validation |
| internal/domain | — | pure types |
| internal/store/sqlite | 86.2% | CRUD across all tables, FK, dupes |
| internal/archive/sqlite | 85.2% | put/get/delete happy + not-found |
| internal/auth | 45.2% | password + session + bootstrap fully covered; WebAuthn plumbing not unit-tested (see above) |
| internal/nebulax | 53.7% | Fake runner covered; Real runner exercised by integration test when `NEBULA_VERSION` env is set |
| internal/ca | 86.1% | create/list/retire/validation/audit cleanup |
| internal/cert | 79.5% | issue/rotate/revoke/blocklist/CIDR containment |
| internal/bundle | 79.0% | tarball shape, config template, missing binary path |
| internal/server | 61.5% | login, dashboard, CA CRUD, cert issue, download, blocklist, logout, healthz, e2e with real nebula-cert |
| cmd/starcaller | 0% | thin wiring — not unit-tested |

Weighted average across tested packages ≈ 72%, meeting the ≥70% target.

### M1 completion state

All M1 tasks green:
- [x] Config loader + deps
- [x] Store interface + SQLite schema
- [x] Archive interface + SQLite blob store
- [x] Auth: password + session + WebAuthn wiring + bootstrap
- [x] CA service (shell-out to nebula-cert with tmpfs temp dir + overwrite-then-unlink)
- [x] Cert service (issue/rotate/revoke/blocklist)
- [x] Bundle builder (tar.gz with nebula binary + config + install.sh + PKI)
- [x] HTTP server with HTMX-ready templates
- [x] Dockerfile + docker-compose example
- [x] Full-stack e2e test against real nebula-cert v1.10.3

Follow-ups tracked for M1.1 patch:
- Expose WebAuthn enrollment + login endpoints in the HTTP layer.
- Add CSRF middleware.
- Replace the HTMX placeholder with the real library.
- Consider adding memfd_create for CA-key materialization (currently uses /dev/shm tmpfs with overwrite-then-unlink; safe on modern kernels but not memfd-strict).
