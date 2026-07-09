# Nebula Starcaller — Specification

**Status:** Draft v0.3 — living document
**Last updated:** 2026-07-09

## 1. Purpose

Nebula Starcaller is a self-hosted web application for operating one or more [Slack Nebula](https://github.com/slackhq/nebula) certificate authorities. It exists to give teams a way to run their own Nebula PKI with the operational and security properties they would expect of a modern internal CA:

- CA keys managed by the application, backed by durable state.
- SSO for humans, MFA-enforced at the IdP.
- Multi-party approval workflows as an audit and governance layer.
- Server-side archival of every cert and config artifact issued.
- Pluggable state (SQLite by default, OpenBao when available).

Starcaller is the self-hosted analog of [Managed Nebula](https://nebula.defined.net/docs/) for teams that want to run the CA themselves.

## 2. Goals & non-goals

### 2.1 Goals

- Manage one or more Nebula CAs from a web UI. **The GUI is the product.** A programmatic API may follow later but is not an MVP goal.
- Serve as the CA — hold the signing key, perform the signing operation.
- Manage the full client lifecycle: issue, list, inspect, rotate, revoke.
- Manage Nebula-native constructs that live in certs (networks, unsafe networks, groups) and keep them consistent across the CAs Starcaller operates.
- Archive every issued cert, keypair, and a complete installable **bundle** (Nebula binary + certs + rendered config + install script) so operators can re-download them later.
- Ship as a container image with the `nebula-cert` binary bundled inside, plus a curated set of `nebula` runtime binaries for the client platforms we support.

### 2.2 Non-goals

- Not a general-purpose X.509 CA. Nebula's cert format is its own.
- Not a Nebula config/orchestration tool at runtime (Starcaller ships the initial config in the bundle; it does not push updates).
- Not a substitute for `nebula-cert` — Starcaller shells out to it, not around it.
- Not hardware-token-first. PKCS#11 / YubiKey-backed signing is deferred; the app holds the keys.
- **Not API-first for MVP.** The HTTP endpoints exist to serve the GUI, not as a stable programmatic surface. Automation-friendly APIs are a fast-follow, not MVP.
- **M-of-N approval workflow is deferred**, not MVP. The data model leaves room; the logic and UI come later.

## 3. Key design decisions

The following decisions were made after a design-time spike (see §11):

1. **No hierarchical CAs.** `nebula-cert sign` does not produce intermediate CAs — signed certs are always leaves with ECDH-only keys. Starcaller does not model a root→intermediate→client hierarchy.
2. **Starcaller is the signer.** The CA private key is held by the application and used directly by `nebula-cert sign`. This is a deliberate simplification over the earlier YubiKey-per-signer design — it removes hardware distribution logistics and lets the OIDC + approval layer carry the human-trust story.
3. **Quorum is a governance artifact, not a cryptographic multi-sig, and it is deferred.** When M-of-N approval lands, it will be enforced by Starcaller before it signs; the resulting Nebula cert has one signature (the CA's), and the approval record — who approved, when, from what session — is preserved in the audit log as the accountability trail. Data model reserves the shape; MVP does not implement the workflow.
4. **Multi-root as an available topology.** A network can trust multiple Starcaller-managed roots concurrently. This maps naturally onto Nebula's multi-CA trust bundle, and it's how Starcaller supports zero-downtime CA rotation.
5. **Revocation is a distributed blocklist, not a CRL.** Nebula does not have a runtime CRL protocol — revocation is expressed as a local `pki.blocklist` entry in each host's config, listing certificate fingerprints to reject. Starcaller tracks revocation state and renders an up-to-date blocklist for operators to distribute.
6. **Shell out to `nebula-cert`.** Do not vendor the Nebula cert package. Behavior stays identical to upstream.
7. **Server-side archival.** Every issued artifact — cert, keypair, rendered config bundle — is stored server-side, encrypted at rest, and re-downloadable by authorized users. This is a first-class feature, not a debugging convenience.
8. **Encryption at rest = host disk encryption.** No application-layer KEK / startup-passphrase dance. Deployments are expected to run on encrypted disks (LUKS, cloud provider disk encryption, etc.). This is a documented deployment requirement, not an app feature.
9. **Frontend is HTMX + Alpine served by Go templates.** Minimizes supply-chain surface, keeps the deploy story a single container.
10. **Groups and networks are first-class.** They live on the cert, so they belong in the domain model, not as free-form strings.

## 4. High-level architecture

```
                    ┌──────────────────────────────┐
                    │        Web browser           │
                    │  (HTMX + Alpine, no build)   │
                    └──────────────┬───────────────┘
                                   │  HTTPS (OIDC / local)
                    ┌──────────────▼───────────────┐
                    │      Starcaller (Go)         │
                    │                              │
                    │  ┌─────────┐  ┌───────────┐  │
                    │  │  HTTP   │  │  Approval │  │
                    │  │ handler │  │   engine  │  │
                    │  └────┬────┘  └─────┬─────┘  │
                    │       │             │        │
                    │  ┌────▼─────────────▼─────┐  │
                    │  │       CA service       │  │
                    │  └────┬──────────┬────────┘  │
                    │       │          │           │
                    │  ┌────▼─────┐ ┌──▼────────┐  │
                    │  │  Store   │ │  Archive  │  │
                    │  │ (iface)  │ │  (iface)  │  │
                    │  └────┬─────┘ └──┬────────┘  │
                    └───────┼──────────┼───────────┘
                            │          │
                ┌───────────┴──┐   ┌───┴──────────┐
        ┌───────▼───┐  ┌───────▼─┐ │              │
        │  SQLite   │  │ OpenBao │ ▼              ▼
        │  (local)  │  │         │ SQLite     OpenBao KV
        └───────────┘  └─────────┘ blob        (wrapped)

                Signing: shell out to nebula-cert with
                a CA keypair materialized to a temp file,
                zeroed after use.
```

The interfaces that matter:

- **Store** — persists CA metadata, cert records, requests, approvals, users, audit log.
- **Archive** — persists the artifacts themselves (private keys, cert PEMs, config bundles). Separated from `Store` because it holds the largest and most sensitive blobs, and it may want a different backend (e.g. store metadata in SQLite but archive in OpenBao).

Everything else (HTTP, templates, approval workflow, group management, blocklist rendering) sits on top of these.

## 5. Signing model

Starcaller supports **one signing topology** at MVP: the app-held CA. Signing works as follows:

1. A cert request arrives from the web UI.
2. Starcaller validates the request against the CA's constraints (networks, groups, TTL bounds).
3. Starcaller retrieves the CA keypair from the store, materializes it to a temp file (see §11.3), invokes `nebula-cert sign`, reads the result, wipes the temp file, and archives the cert + key + rendered bundle (§5a). The download is offered to the requester in-browser and remains available via the Archive.

Post-MVP, an approval policy (§5.2) may sit between steps 2 and 3.

### 5a. Root CA creation

Creating a CA is a first-class GUI workflow that mirrors `nebula-cert ca` and adds the fields Starcaller needs to manage it going forward. The CA-create form collects:

| Field | Nebula flag | Notes |
|---|---|---|
| Name | `-name` | Required. Human-readable and cert-encoded. |
| Curve | `-curve` | `25519` (default) or `P256`. |
| Networks | `-networks` | Required. Comma-separated CIDRs. Bounds subordinate certs. |
| Unsafe networks | `-unsafe-networks` | Optional. Bounds subordinate cert routing scope. |
| Groups | `-groups` | Optional. Bounds which groups subordinate certs may claim. Chosen from the group registry (§7). |
| CA duration | `-duration` | Default 1y. |
| Default cert TTL | (Starcaller-managed) | Default TTL applied to certs signed by this CA if the request doesn't specify. Must be < remaining CA lifetime. |
| Description | (Starcaller-managed) | Free text. Not encoded in the cert. |

On submit, Starcaller shells out to `nebula-cert ca` with the appropriate flags in a temp directory, reads the resulting `ca.crt` and `ca.key`, persists both to the Store (metadata) and Archive (key material), and wipes the temp directory.

### 5.1 Multi-root topology

Multiple CAs may coexist under Starcaller. A given Nebula network can trust any subset of them by listing multiple CA certs in its `pki.ca` bundle. This is used for:

- **Zero-downtime CA rotation** — stand up CA2, publish trust bundle with `[ca1, ca2]`, roll clients onto ca2-issued certs, drop ca1.
- **Isolated administrative domains** within one Starcaller — e.g. `prod` CA and `staging` CA operated by different teams.

### 5.2 Approval workflow (governance layer)

An approval policy is `{M, N, approver_set, ttl}`:

- `M` approvers required from the `approver_set` of size `N`.
- Approvals must arrive within `ttl` or the request expires.
- Approvers cannot approve their own requests (configurable).
- Approvers are OIDC users with the `approver` role.
- Each approval event captures: OIDC subject, email, session ID, timestamp, source IP, and the exact request payload the approver saw. This is the audit artifact.
- The final approval triggers the signing operation. The cert's cryptographic signature comes from the CA. The `approvals[]` list is stored alongside the cert record for later verification.

## 6. Data model

Tables (or KV keys, when running on OpenBao):

- **`ca`** — `id`, `name`, `curve`, `networks`, `unsafe_networks`, `groups`, `cert_pem`, `key_ref` (archive pointer), `duration`, `created_at`, `retired_at`.
- **`approval_policy`** — `ca_id`, `m`, `n`, `approver_role`, `ttl`, `allow_self_approve`. Optional per CA.
- **`cert`** — `id`, `issuing_ca_id`, `name`, `networks`, `unsafe_networks`, `groups`, `fingerprint`, `not_before`, `not_after`, `cert_ref` (archive pointer), `key_ref` (archive pointer, nullable — some flows may not retain the key), `config_bundle_ref` (archive pointer), `revoked_at`, `revocation_reason`, `superseded_by`.
- **`request`** — `id`, `ca_id`, `payload_json`, `state (pending|approved|rejected|issued|expired)`, `created_by`, `created_at`, `expires_at`.
- **`approval`** — `request_id`, `user_id`, `decision (approve|reject)`, `oidc_subject`, `email`, `session_id`, `source_ip`, `decided_at`, `payload_hash_seen`.
- **`group`** — canonical group name and description. Used for group management (§7).
- **`user`** — `id`, `subject` (OIDC) or `username` (local), `email`, `roles[]`, `webauthn_credentials[]`.
- **`api_token`** — `id`, `owner_user_id`, `name`, `hash`, `scopes[]`, `expires_at`, `revoked_at`.
- **`audit_log`** — append-only. Every state-changing action. Never garbage-collected.

## 7. Group and network management

Nebula CAs restrict which `-networks` and `-groups` a subordinate cert may claim. Starcaller treats these as **first-class managed state**:

- Groups have their own registry. Adding a group at network level makes it available to CA definitions.
- CA definitions declare which groups (from the registry) and networks (CIDRs) their subordinate certs may claim.
- On cert issuance, the requested groups and networks are validated against the CA's constraints. Nebula will also reject at sign time, but Starcaller checks up-front for a better UX.
- Adding a new group to a CA's permitted set requires the CA cert to be re-issued (the constraint is baked into the cert). Starcaller offers this as a "rotate CA" workflow: mint a new CA cert, publish alongside the old one via multi-root, migrate issued certs on rotation schedule, retire the old CA.
- **MVP:** group registry + per-CA declaration + issuance-time validation. CA rotation to add groups is v2.

## 8. Client lifecycle operations

For each issued cert:

- **Issue** — via the GUI, with name, networks, groups, TTL, lighthouse/relay flags. Cert, key, and complete bundle (§8a) are archived server-side. Signed bundle is offered as an immediate browser download and remains re-downloadable.
- **List / inspect** — rendered decode of the cert, cert metadata, links to bundle download.
- **Download bundle** — re-fetch the archived bundle. Every download is audit-logged (who, when, what).
- **Rotate** — re-issue with the same identity+groups but a fresh keypair and expiry. Old cert is marked `superseded_by`. New bundle is archived.
- **Revoke** — mark revoked in state, add fingerprint to the blocklist, log with reason.
- **Blocklist** — the CA detail view exposes the current list of revoked cert fingerprints for a CA, formatted for insertion into a Nebula host config's `pki.blocklist`. Downloadable as a YAML snippet. Operators distribute to their hosts; Starcaller does not push.

### 8a. Bundle format

A **bundle** is the complete artifact Starcaller produces when a host cert is signed. It is a `.tar.gz` archive with the following layout:

```
starcaller-<host>-<timestamp>/
├── README.md                    # what this is, how to install
├── install.sh                   # POSIX shell installer
├── nebula                       # nebula runtime binary (platform-specific)
├── nebula-cert                  # bundled for local inspection/rotation
├── config.yml                   # rendered host config
└── pki/
    ├── host.crt                 # this host's cert
    ├── host.key                 # this host's private key
    └── ca.crt                   # trust bundle (may contain multiple roots)
```

Per-file notes:

- **`nebula` binary** — the runtime, selected for the target platform declared at issuance. Starcaller ships a curated set (linux/amd64, linux/arm64, darwin/arm64, windows/amd64) built into the container image. Non-supported platforms get a bundle without a binary and a README note pointing at upstream releases.
- **`config.yml`** — rendered from a template using the CA's declared networks, the requester-selected role (lighthouse / relay / host), and any Starcaller-managed defaults (log level, listen port). Config is a starting point, not a runtime-managed artifact.
- **`install.sh`** — installs the binary to `/usr/local/bin/nebula`, drops `config.yml` and `pki/` under `/etc/nebula/`, installs a systemd unit, and prints next steps. Idempotent; safe to re-run for rotation.
- **`ca.crt`** — always the current, complete trust bundle for the CA at time of issuance. If the network has been rotated to multi-root, all trusted roots are concatenated here.

Bundles are archived alongside the cert record, addressed by the same cert ID. Rotation produces a new bundle; the old one remains downloadable and audit-logged.

## 9. Authentication

Two auth methods, both first-class:

### 9.1 OIDC (primary for humans)

- Standard OIDC code flow. Configurable IdP.
- Required claims: `sub`, `email`. Approval-eligible users must also present `amr` including `mfa` or an equivalent claim configured per CA policy.
- Roles: `admin`, `operator`, `approver`, `viewer`. Mapped from an OIDC group claim.
- Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`.

### 9.2 Local + WebAuthn (fallback / bootstrap)

- Username + password + WebAuthn credential.
- Used for the initial admin account and for air-gapped deployments.
- Password hashing: argon2id.

Machine automation is out of MVP scope (§2.2). If added later, it will use short-lived tokens scoped to the role model.

### 9.3 First-run bootstrap

Starcaller's first admin user is **pre-defined via configuration**, not created through a web installer. On first startup:

1. Starcaller reads `STARCALLER_BOOTSTRAP_USERNAME`, `STARCALLER_BOOTSTRAP_PASSWORD`, and optionally `STARCALLER_BOOTSTRAP_EMAIL` from the environment (or the config file).
2. If no users exist in the Store, the bootstrap user is created with role `admin`, password hashed with argon2id, and a flag set to force WebAuthn enrollment on first login.
3. If users already exist, the bootstrap variables are ignored (with a startup log line).
4. The bootstrap variables are read once and never referenced again — safe to remove from config after first login, and expected to be removed.

Rationale: pre-defined user closes the "open-signup-until-someone-registers" window that plagues self-hosted apps, and avoids a separate install wizard endpoint. It also means the first user's credentials are managed at deployment time by whatever mechanism deploys the container (systemd credentials, Docker secrets, k8s secrets, etc.).

## 10. State and archive backends

Two interfaces, each pluggable:

### 10.1 SQLite (default for both Store and Archive)

- `modernc.org/sqlite` (pure Go).
- WAL mode.
- Archive blobs are stored as `BLOB` columns in a dedicated `archive` table, addressed by opaque IDs referenced from `Store` records.
- **Encryption at rest is the operator's responsibility.** Deployment on an encrypted volume (LUKS, cloud disk encryption, etc.) is documented as a hard requirement. Starcaller does not attempt to add an application-layer encryption pass on top.

### 10.2 OpenBao

- KV v2 for structured Store data.
- KV v2 (with transit-engine wrapping) for Archive blobs.
- Authentication via AppRole, RoleID delivered by config, SecretID delivered via response-wrapping.
- Suitable when Starcaller runs alongside an existing OpenBao deployment.

Store and Archive can be independently configured — e.g. `Store=SQLite, Archive=OpenBao` is a valid combination for teams that want metadata local but sensitive material centrally managed.

## 11. Open questions & spikes still owed

### 11.1 Blocklist distribution

Revocation being local-config means operators need to actually distribute the blocklist. In-scope for Starcaller: render the blocklist and expose it via API. Out-of-scope: pushing to hosts. Should we generate a rendered `pki.blocklist` config snippet, a JSON list, or both? **Default:** both.

### 11.2 Approval payload canonicalization

Even though approvals aren't cryptographic signatures, the `payload_hash_seen` recorded per approval must be deterministic so we can prove the approver saw the exact request they approved. Define a canonical JSON serialization (RFC 8785 JCS or equivalent).

### 11.3 CA key at rest, before the disk-encryption boundary kicks in

Disk encryption protects the key while the disk is at rest. While Starcaller is running, the CA key sits in memory and briefly on disk (temp file during `nebula-cert sign` shell-out). Mitigations to spec:
- `memfd_create` / `tmpfs` for the temp file, never a plain disk file.
- Explicit zero-and-unlink after each sign.
- No dumps: `prctl(PR_SET_DUMPABLE, 0)`.

### 11.4 Archive size growth

Archiving every issued key + cert + bundle grows unboundedly. Need a retention policy: keep forever, or expire after N years / N generations of rotation? **Default proposal:** keep forever for certs and configs; make key retention configurable per CA (default: retain).

### 11.5 Bundled `nebula-cert` version pinning

The container ships a `nebula-cert` binary. We need a version-pin policy and a way to notify operators when the upstream releases a new version.

## 12. MVP scope

The first releasable version:

1. App-held CAs (single topology). Multi-root supported by having more than one.
2. SQLite for both Store and Archive.
3. Local auth (username + password + WebAuthn). Pre-defined first admin via env/config (§9.3).
4. GUI-only. No stable programmatic API surface.
5. Full client lifecycle: issue, list, inspect, rotate, revoke, blocklist rendering.
6. CA-create form with all fields listed in §5a (name, curve, networks, unsafe networks, groups, durations, description).
7. Server-side archival of complete bundles (§8a) with download.
8. Group registry read-only enforcement; no CA rotation for group changes.
9. Container image with bundled `nebula-cert` and per-platform `nebula` runtime binaries.

**Explicitly deferred out of MVP:**
- M-of-N approval workflow.
- OIDC auth.
- OpenBao Store/Archive backend.
- CA rotation for group registry changes.
- PKCS#11 / hardware-backed CA keys.
- Programmatic / automation-friendly API.

## 13. Roadmap

| Phase | Deliverables |
|-------|-------------|
| M0 | Repo scaffold, this spec (done). |
| M1 | MVP as defined in §12. |
| M2 | OIDC auth. |
| M3 | M-of-N approval workflow (§5.2). |
| M4 | OpenBao backend (Store and Archive). |
| M5 | Group registry with CA rotation workflow. |
| M6 | Programmatic API with token auth. |
| M7 | PKCS#11 / YubiKey-backed CA keys (deferred — not a near-term priority). |

## 14. Prior art referenced

- [jrcichra/nebula-admin-panel](https://github.com/jrcichra/nebula-admin-panel)
- [Managed Nebula](https://nebula.defined.net/docs/)
- [ryankurte/pki](https://github.com/ryankurte/pki)
- Vincent Bernat, [Offline PKI using 3 YubiKeys](https://vincent.bernat.ch/en/blog/2025-offline-pki-yubikeys)
- [Smallstep step-ca](https://smallstep.com/docs/step-ca/configuration/)
- [OpenBao PKI](https://openbao.org/docs/secrets/pki/) and [AppRole](https://openbao.org/docs/auth/approle/) docs.
