# Nebula Starcaller — Specification

**Status:** Draft v0.1 — living document
**Last updated:** 2026-07-09

## 1. Purpose

Nebula Starcaller is a self-hosted web application for operating one or more [Slack Nebula](https://github.com/slackhq/nebula) certificate authorities. It exists to give teams a way to run their own Nebula PKI with the operational and security properties they would expect of a modern internal CA:

- Signing keys backed by hardware tokens (YubiKey PIV / PKCS#11).
- Multiple independent signers.
- Multi-party approval workflows on top of that.
- Pluggable, durable state.
- SSO for the humans, and clean automation paths for the machines.

Starcaller is not a replacement for [Managed Nebula](https://nebula.defined.net/docs/) — it is the self-hosted analog for teams that need to run the CA themselves.

## 2. Goals & non-goals

### 2.1 Goals

- Manage one or more Nebula CAs from a web UI, and expose the same operations via an API.
- Support hardware-backed signing keys via PKCS#11.
- Support multi-root topologies (see §5.1) and, on top of that, M-of-N approval policies (§5.2) and delegated app-held CAs with OIDC MFA gating (§5.3).
- Manage the full client lifecycle: issue, list, inspect, rotate, revoke.
- Manage Nebula-native constructs that live in certs (networks, unsafe networks, groups) and keep them consistent across the CAs Starcaller operates.
- Ship as a container image with a PKCS#11-enabled `nebula-cert` binary bundled inside.

### 2.2 Non-goals

- Not a general-purpose X.509 CA. Nebula's cert format is its own.
- Not a Nebula config/orchestration tool (that's a separate problem).
- Not a substitute for `nebula-cert` — Starcaller shells out to it, not around it.

## 3. Key design decisions

The following decisions were made after a design-time spike (see §11):

1. **No hierarchical CAs.** `nebula-cert sign` does not produce intermediate CAs — signed certs are always leaves with ECDH-only keys. Starcaller therefore does not attempt to model a root→intermediate→client hierarchy.
2. **Multi-root as the base topology.** Nebula supports listing multiple root certs in the `pki.ca` trust bundle. Starcaller uses this as the primitive for multi-signer setups.
3. **Shell out to `nebula-cert`.** Do not vendor the Nebula cert package. This keeps Starcaller's behavior identical to `nebula-cert` and offloads the CGO/PKCS#11 build complexity to the bundled binary.
4. **Single deployable, but pluggable state.** The default configuration is single-binary + SQLite. State is behind an interface so OpenBao can be swapped in.
5. **Frontend is HTMX + Alpine served by Go templates.** Minimizes supply-chain surface, keeps the deploy story a single container.
6. **Groups and networks are first-class.** They live on the cert, so they belong in the domain model, not as free-form strings.

## 4. High-level architecture

```
                    ┌──────────────────────────────┐
                    │        Web browser           │
                    │  (HTMX + Alpine, no build)   │
                    └──────────────┬───────────────┘
                                   │  HTTPS (mTLS/OIDC)
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
                    │  └────┬──────────────┬────┘  │
                    │       │              │       │
                    │  ┌────▼─────┐  ┌─────▼────┐  │
                    │  │  State   │  │ Signer   │  │
                    │  │ (iface)  │  │ (iface)  │  │
                    │  └────┬─────┘  └─────┬────┘  │
                    └───────┼──────────────┼───────┘
                            │              │
                ┌───────────┴──┐    ┌──────┴───────────┐
        ┌───────▼───┐  ┌───────▼──┐ │                  │
        │  SQLite   │  │ OpenBao  │ ▼                  ▼
        │  (local)  │  │   (KV)   │ nebula-cert     nebula-cert
        └───────────┘  └──────────┘  (shell out       (shell out
                                     w/ file key)     w/ PKCS#11)
```

The two interfaces that matter:

- **State**: `Store` — persists CAs, cert records, approval requests, users, audit log.
- **Signer**: `Signer` — issues a cert given a signed request. Concrete implementations: `FileKeySigner`, `PKCS11Signer`, `OpenBaoSigner` (future).

Everything else (HTTP, templates, approval workflow, group sync) sits on top of these.

## 5. Signer topologies

Starcaller supports three topologies. They are not mutually exclusive — a single Starcaller deployment can host CAs of any topology, and the topology is a per-CA property.

### 5.1 Multi-root (base)

Each signer generates a root CA. The root's private key lives on their YubiKey (PIV slot, PKCS#11-accessible). The root cert is registered with Starcaller.

The Nebula trust bundle for the network is the concatenation of all registered roots. Any registered root can sign any client cert; hosts trust all of them.

Properties:
- No shared secret. Compromise of one signer's YubiKey does not affect the others.
- Revoking a signer = removing their root from the bundle and rotating all certs they issued (Nebula does not have a widely-deployed CRL story — see §11.2).
- Simplest topology; the MVP target.

### 5.2 M-of-N approval on top of multi-root

A CA may declare an **approval policy**: `require M signatures from the set of N registered signers before a cert is issued`.

- Cert requests are POST'd to Starcaller and enter a queue as `PendingRequest`.
- Each approver reviews the request in the web UI, and clicks "approve." Their approval is itself a signature — the approver signs a canonical serialization of the request payload with a key on their YubiKey, and Starcaller records the signature.
- When M valid approver-signatures are collected, Starcaller shells out to `nebula-cert sign` using the CA's designated *issuing* root (which itself may be a YubiKey — the last approver's touch produces the cert signature).

Approval is a *governance* layer. The cryptographic signature on the resulting Nebula cert still comes from a single root. But no cert is issued unless M distinct humans participated.

Open design question: does the "final signer" always come from a fixed root, or is it the last approver's root? Fixed root is simpler but ties revocation to one YubiKey. **Default:** last approver signs — spreads risk, and every root in the set is equally valid to the trust bundle anyway.

### 5.3 App-held CA with OIDC MFA gating

For teams that cannot deploy YubiKeys to every operator, an alternate topology: the CA private key is stored *by Starcaller itself*, and the "signer" is an OIDC-authenticated human whose IdP is required to have enforced MFA (`amr` contains `mfa` or an equivalent claim, configured per CA).

Properties:
- Weaker than YubiKey-backed roots — the key is on the Starcaller host.
- Storage of the CA key uses the state layer's secure primitive: OpenBao transit encryption if OpenBao is configured; otherwise a KEK derived from a passphrase provided at startup (SQLite backend).
- Suitable for lower-trust deployments (homelabs, small teams, dev environments).

## 6. Data model

Tables (or KV keys, when running on OpenBao):

- **`ca`** — a signer identity. `id`, `name`, `topology (multi_root|app_held)`, `curve`, `networks`, `unsafe_networks`, `groups`, `cert_pem`, `key_ref` (PKCS#11 URI, OpenBao path, or app-held blob), `duration`, `created_at`, `revoked_at`.
- **`approval_policy`** — `ca_id`, `m`, `n_signer_set`. Optional per CA.
- **`signer`** — an enrolled human. `id`, `name`, `email`, `pkcs11_uri` (for approval signatures), `public_key`, `created_at`, `revoked_at`.
- **`cert`** — issued client cert. `id`, `issuing_ca_id`, `name`, `networks`, `unsafe_networks`, `groups`, `serial`, `not_before`, `not_after`, `cert_pem`, `pubkey_fingerprint`, `revoked_at`, `revocation_reason`.
- **`request`** — pending cert request. `id`, `ca_id`, `payload_canonical`, `state (pending|approved|rejected|issued|expired)`, `created_by`, `created_at`, `expires_at`.
- **`approval`** — `request_id`, `signer_id`, `signature`, `signed_at`.
- **`group`** — canonical group name and description. Used for group sync (§7).
- **`user`** — human operator (OIDC subject or local). `id`, `subject`, `email`, `role`.
- **`audit_log`** — append-only. Every state-changing action.

## 7. Group and network synchronization

Nebula CAs restrict which `-networks` and `-groups` a subordinate cert may claim. In a multi-root topology, each root has its own copy of these constraints — and if they drift, certs issued by different roots can end up with inconsistent membership.

Starcaller treats groups and networks as **CA-scoped state that can be declared network-wide**. On each cert issuance:

1. Requested groups/networks are validated against the issuing CA's own constraints (Nebula will reject the sign otherwise — this is defense-in-depth).
2. Optionally, Starcaller validates against a **network-wide group registry** — a set of groups declared on the Starcaller instance and enforced across all CAs it operates.
3. When a group is added/renamed at the registry level, Starcaller can offer to re-issue affected CAs (rotate the root) if the new group must be encoded into the CA's permissible-groups set. This is a heavyweight operation and is user-initiated.

**MVP scope:** the registry is read-only enforcement — declaring a new group at network level does *not* automatically rotate CAs. Rotation is v2.

## 8. Client lifecycle operations

For each issued cert:

- **Issue** — `POST /api/certs` with name, networks, groups, TTL, requester. Enters approval flow if policy requires it; otherwise issued immediately.
- **List / inspect** — including a rendered decode of the cert.
- **Rotate** — re-issue with the same identity+groups but a fresh keypair and expiry. Old cert is marked superseded.
- **Revoke** — mark revoked in state, generate/refresh the revocation blocklist (see §11.2 open question), log with reason.
- **Export** — the cert + trust bundle (with all roots for the network) as a tarball or as a rendered `config.yml` snippet.

## 9. Authentication

Two auth methods, both first-class:

### 9.1 OIDC (primary for humans)

- Standard OIDC code flow. Configurable IdP.
- Required claims: `sub`, `email`, and (per-CA policy) `amr` including `mfa` or equivalent.
- Roles: `admin`, `operator`, `approver`, `viewer`. Mapped from an OIDC group claim.
- Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`.

### 9.2 Local + WebAuthn (fallback / bootstrap)

- Username + password + WebAuthn credential.
- Used for the initial admin account and for air-gapped deployments.
- Password hashing: argon2id.

Machines authenticating for automation (issuing certs from CI, etc.) use short-lived API tokens minted by an operator. Token scopes mirror the role model.

## 10. State backends

Behind the `Store` interface:

### 10.1 SQLite (default)

- `modernc.org/sqlite` (pure Go — no CGO conflict with the bundled `nebula-cert`).
- WAL mode.
- All secrets at rest (app-held CA keys, approval-signature bookkeeping) encrypted with a KEK derived from a startup-provided passphrase (argon2id).

### 10.2 OpenBao

- KV v2 for structured data.
- Transit engine for wrapping/unwrapping app-held CA keys (never persisted unencrypted).
- Authentication via AppRole, RoleID delivered by config, SecretID delivered via response-wrapping.
- Suitable when Starcaller runs alongside an existing OpenBao deployment and the team wants a single source-of-truth for secrets.

## 11. Open questions & spikes still owed

### 11.1 M-of-N final-signer semantics

Whether the cert-issuing signature comes from a fixed CA root or the last approver's root. Default proposed: last approver. Needs a small prototype to confirm the UX makes sense.

### 11.2 Revocation

Nebula's on-wire revocation story is uneven; older docs recommend rotating certs rather than relying on a CRL. Before the revoke API stabilizes, we need to confirm what the current Nebula binary honors. If there is no runtime CRL check, "revoke" in Starcaller becomes an operational marker (removes the cert from the bundle, flags dependent hosts for rotation) rather than a cryptographic one.

### 11.3 PKCS#11 build

`nebula-cert` PKCS#11 support requires a CGO build with a build tag. Confirm the exact build recipe and bundle a working `nebula-cert` binary in the Starcaller container.

### 11.4 Approval-signature payload

Define the canonical serialization the approvers sign. Must include CA ID, requested name, networks, groups, TTL, and a request-scoped nonce so signatures cannot be replayed across requests.

### 11.5 App-held CA at-rest encryption when using SQLite

Startup passphrase is workable but operationally annoying. Alternatives: OS keyring, systemd credentials, sealed with a TPM. Pick one for MVP.

## 12. MVP scope

The first releasable version:

1. Multi-root topology only (no M-of-N, no app-held).
2. File-key signer only (no PKCS#11 yet — spiked in parallel).
3. SQLite state.
4. Local auth only (WebAuthn preferred, password fallback).
5. Full client lifecycle *except* CRL — revoke is a soft flag.
6. Group registry read-only; no rotation.
7. Container image with bundled `nebula-cert`.

Everything else in this spec is v2+ scope.

## 13. Roadmap

| Phase | Deliverables |
|-------|-------------|
| M0 | Repo scaffold, this spec (done). |
| M1 | MVP as defined in §12. |
| M2 | PKCS#11 signer. Multi-root becomes truly YubiKey-backed. |
| M3 | OIDC auth. |
| M4 | M-of-N approval workflow (§5.2). |
| M5 | OpenBao state backend. |
| M6 | App-held CA topology with OIDC MFA gating (§5.3). |
| M7 | Group registry rotation, CRL support (contingent on §11.2). |

## 14. Prior art referenced

- [jrcichra/nebula-admin-panel](https://github.com/jrcichra/nebula-admin-panel)
- [Managed Nebula](https://nebula.defined.net/docs/)
- [ryankurte/pki](https://github.com/ryankurte/pki)
- Vincent Bernat, [Offline PKI using 3 YubiKeys](https://vincent.bernat.ch/en/blog/2025-offline-pki-yubikeys)
- [Smallstep step-ca](https://smallstep.com/docs/step-ca/configuration/) — reference for the `kms: yubikey` pattern.
- [OpenBao PKI](https://openbao.org/docs/secrets/pki/) and [AppRole](https://openbao.org/docs/auth/approle/) docs.
