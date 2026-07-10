# Nebula Starcaller

A self-hosted web UI for managing [Slack Nebula](https://github.com/slackhq/nebula) certificate authorities.

## What it does (M1)

- Create and manage multiple Nebula CAs from a GUI. The application holds the signing key.
- Issue, list, inspect, rotate, and revoke client certificates.
- Server-side archive of every issued cert + key + complete installation **bundle** (Nebula binary, config, install script, PKI files).
- Local auth (username + password + WebAuthn). First admin pre-defined via env vars.
- Revocation surfaces as a rendered `pki.blocklist` YAML snippet that operators distribute to their hosts.
- Ships as a single container image with `nebula-cert` and per-platform `nebula` runtime binaries bundled inside.

## What it does not do (yet)

- No M-of-N approval workflow (M3).
- No OIDC (M2).
- No OpenBao state backend (M4).
- No hardware-token-backed CA keys (M5/deferred).
- No stable programmatic API. Endpoints exist to serve the UI, not for external automation.
- Nebula's cert format does not support intermediate CAs; there is no root→intermediate→client hierarchy.

See [SPEC.md](SPEC.md) for the full specification and [IMPL.md](IMPL.md) for implementation notes.

## Quick start

**Docker Compose:**

```sh
cp docker-compose.example.yml docker-compose.yml
# edit STARCALLER_BOOTSTRAP_PASSWORD
docker compose up --build
# visit http://localhost:8080, sign in as admin
```

**From source:**

```sh
go build -o starcaller ./cmd/starcaller

# nebula-cert must be on PATH or set STARCALLER_NEBULA_CERT
STARCALLER_BOOTSTRAP_USERNAME=admin \
STARCALLER_BOOTSTRAP_PASSWORD=change-me \
STARCALLER_DATA_DIR=./data \
STARCALLER_LISTEN=127.0.0.1:8080 \
STARCALLER_DEV_MODE=true \
./starcaller
```

## Configuration

All settings can be set via env vars (prefixed `STARCALLER_`) or a YAML config file (`--config path/to.yml`). Env wins over file.

Key settings:

| Env | Description | Default |
|-----|-------------|---------|
| `STARCALLER_LISTEN` | HTTP listen address | `127.0.0.1:8080` |
| `STARCALLER_DATA_DIR` | Data directory (SQLite DB lives here) | `/var/lib/starcaller` |
| `STARCALLER_NEBULA_CERT` | Path to `nebula-cert` binary | `nebula-cert` (on PATH) |
| `STARCALLER_BINARIES_DIR` | Where per-platform `nebula` binaries live for bundle inclusion | `/opt/starcaller/binaries` |
| `STARCALLER_SESSION_TTL` | Session lifetime | `12h` |
| `STARCALLER_COOKIE_NAME` | Session cookie name | `starcaller_session` |
| `STARCALLER_DEV_MODE` | Set true to allow non-HTTPS cookies | `false` |
| `STARCALLER_RP_ID` | WebAuthn Relying Party ID | `localhost` |
| `STARCALLER_RP_ORIGINS` | Comma-separated WebAuthn origins | `http://localhost:8080` |
| `STARCALLER_BOOTSTRAP_USERNAME` | First-admin username (used on first startup only) | — |
| `STARCALLER_BOOTSTRAP_PASSWORD` | First-admin password (used on first startup only) | — |
| `STARCALLER_BOOTSTRAP_EMAIL` | First-admin email | — |

## Testing

```sh
go test ./...              # unit + fake-runner integration tests
NEBULA_VERSION=v1.10.3 \
  go test ./...            # also runs real nebula-cert e2e tests
```

## Security expectations

- **Deploy on an encrypted disk.** Starcaller stores CA private keys in SQLite. It relies on host disk encryption (LUKS, cloud disk encryption, etc.) for at-rest protection. There is no application-layer KEK.
- **Bind to localhost or behind a reverse proxy with TLS.** In-transit HTTPS is not handled by Starcaller itself.
- **Rotate the bootstrap credentials.** Remove `STARCALLER_BOOTSTRAP_*` from your deployment after the first admin is created.
- **Sessions are Strict-SameSite + HttpOnly + Secure** (unless `STARCALLER_DEV_MODE=true`).

## License

MIT — see [LICENSE](LICENSE).
