# Nebula Starcaller — Specification

**Status:** Draft v0.2 — living document
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

- Manage one or more Nebula CAs from a web UI, and expose the same operations via an API.
- Serve as the CA — hold the signing key, perform the signing operation.
- Enforce M-of-N approval policies per CA as a governance layer over signing.
- Manage the full client lifecycle: issue, list, inspect, rotate, revoke.
- Manage Nebula-native constructs that live in certs (networks, unsafe networks, groups) and keep them consistent across the CAs Starcaller operates.
- Archive every issued cert, keypair, and rendered config bundle so operators can re-download them later.
- Ship as a container image with the `nebula-cert` binary bundled inside.

### 2.2 Non-goals

- Not a general-purpose X.509 CA. Nebula's cert format is its own.
- Not a Nebula config/orchestration tool (that's a separate problem).
- Not a substitute for `nebula-cert` — Starcaller shells out to it, not around it.
- Not hardware-token-first. PKCS#11 / YubiKey-backed signing is deferred; the app holds the keys.

## 3. Key design decisions

The following decisions were made after a design-time spike (see §11):

1. **No hierarchical CAs.** `nebula-cert sign` does not produce intermediate CAs — signed certs are always leaves with ECDH-only keys. Starcaller does not model a root→intermediate→client hierarchy.
2. **Starcaller is the signer.** The CA private key is held by the application and used directly by `nebula-cert sign`. This is a deliberate simplification over the earlier YubiKey-per-signer design — it removes hardware distribution logistics and lets the OIDC + approval layer carry the human-trust story.
3. **Quorum is a governance artifact, not a cryptographic multi-sig.** M-of-N approval is enforced by Starcaller before it signs. The resulting Nebula cert has one signature (the CA's). The approval record — who approved, when, from what session — is preserved in the audit log as the load-bearing accountability trail.
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

1. A cert request arrives (from the web UI, API, or a machine token).
2. Starcaller validates the request against the CA's constraints (networks, groups, TTL bounds).
3. If the CA has an approval policy, the request enters the approval queue and is not signed until M distinct approvers have marked it approved through the UI. Their approval events are recorded in the audit log with their OIDC identity and session context.
4. Once approved (or immediately, if no policy), Starcaller retrieves the CA keypair from the store, materializes it to a temp file, invokes `nebula-cert sign`, reads the result, wipes the temp file, and returns the cert and key to the caller. The signed cert and its keypair are also written to the archive.

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

- **Issue** — `POST /api/certs` with name, networks, groups, TTL, requester. Enters approval flow if policy requires it; otherwise issued immediately. Cert, key, and rendered config bundle are archived server-side.
- **List / inspect** — including a rendered decode of the cert. Any authorized user can view.
- **Download** — re-fetch the archived cert / key / config bundle. Every download is audit-logged (who, when, what).
- **Rotate** — re-issue with the same identity+groups but a fresh keypair and expiry. Old cert is marked `superseded_by`.
- **Revoke** — mark revoked in state, add fingerprint to the blocklist, log with reason.
- **Blocklist** — `GET /api/blocklist/{ca_id}` returns the current list of revoked cert fingerprints for a CA, formatted for insertion into a Nebula host config's `pki.blocklist`. Operators are responsible for distributing this to their hosts; Starcaller does not push to hosts.

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

Machines (CI, provisioning tools) authenticate with short-lived API tokens minted by an operator. Token scopes mirror the role model.

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

1. App-held CAs (single topology).
2. SQLite for both Store and Archive.
3. Local auth (WebAuthn preferred, password fallback). OIDC in a fast-follow release.
4. Full client lifecycle including blocklist rendering.
5. Group registry read-only enforcement; no CA rotation.
6. Approval workflow (M-of-N as governance).
7. Server-side archival of certs, keys, config bundles, with download endpoint.
8. Container image with bundled `nebula-cert`.

Everything else in this spec is v2+ scope.

## 13. Roadmap

| Phase | Deliverables |
|-------|-------------|
| M0 | Repo scaffold, this spec (done). |
| M1 | MVP as defined in §12. |
| M2 | OIDC auth. |
| M3 | OpenBao backend (Store and Archive). |
| M4 | Group registry with CA rotation workflow. |
| M5 | PKCS#11 / YubiKey-backed CA keys (deferred — not a near-term priority). |

## 14. Prior art referenced

- [jrcichra/nebula-admin-panel](https://github.com/jrcichra/nebula-admin-panel)
- [Managed Nebula](https://nebula.defined.net/docs/)
- [ryankurte/pki](https://github.com/ryankurte/pki)
- Vincent Bernat, [Offline PKI using 3 YubiKeys](https://vincent.bernat.ch/en/blog/2025-offline-pki-yubikeys)
- [Smallstep step-ca](https://smallstep.com/docs/step-ca/configuration/)
- [OpenBao PKI](https://openbao.org/docs/secrets/pki/) and [AppRole](https://openbao.org/docs/auth/approle/) docs.
