# Nebula Starcaller

A self-hosted web UI for managing [Slack Nebula](https://github.com/slackhq/nebula) certificate authorities, with first-class support for hardware-backed signing keys and multi-signer workflows.

## Goals

- **Hardware-first signing** — signing keys live on YubiKeys (PKCS#11 / PIV), never on disk.
- **Multi-signer** — a CA can require any of N enrolled YubiKey holders to sign new certs.
- **Hierarchical CAs** — root CA → intermediate CA → client cert, matching modern PKI hygiene.
- **Single binary** — Go backend with embedded HTMX/Alpine frontend. No Node build, no external DB required for small deployments.
- **Nebula-compatible** — issues certs using the same primitives as `nebula-cert`, no reinvented formats.

## Status

Early scaffold. Nothing works yet.

## Non-goals

- Not a replacement for Nebula's overlay network — this only manages the PKI side.
- Not a general-purpose X.509 CA. Nebula's cert format is its own.

## Prior art / inspiration

- [jrcichra/nebula-admin-panel](https://github.com/jrcichra/nebula-admin-panel) — earlier OSS attempt (Rust/React), no YubiKey or hierarchy.
- [Managed Nebula](https://nebula.defined.net/docs/) — commercial SaaS from the Nebula creators.
- [ryankurte/pki](https://github.com/ryankurte/pki) — YubiKey-backed root+intermediate PKI template.
- Vincent Bernat's [offline-pki](https://vincent.bernat.ch/en/blog/2025-offline-pki-yubikeys) — air-gapped 3-YubiKey design.

## License

MIT — see [LICENSE](LICENSE).
