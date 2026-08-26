# Changelog

This project follows semantic versioning while it is pre-1.0. This file and the
signed `vX.Y.Z` tags are the release record; Forgejo release objects are not
maintained, so their absence says nothing about whether a version shipped.

## 0.1.2 - 2026-08-25

### Fixed

- Accept any port on allowlisted loopback `http` redirect URIs, as RFC 8252
  §7.3 requires. Command-line clients bind an ephemeral local port per session,
  so a fixed `http://localhost:8787/callback` entry could never match and
  Dynamic Client Registration rejected them with `unregistered redirect_uri`.
  Scheme, host, path and query still match exactly, and `https` and
  private-use-scheme entries keep exact matching including the port.

## 0.1.1 - 2026-08-23

### Security

- Bound JWKS refresh traffic, authentication/OAuth caches, session state and
  rate-limit maps.
- Limit MCP request bodies before rmcp buffering and bind sessions to the
  verified subject.
- Verify destructive DAV targets are events and retain ETag protection.
- Require HTTPS for non-loopback service URLs and validate redirect allowlists
  at startup.
- Pseudonymize identity and DAV-resource correlation fields in logs and traces.
- Update `h2` to the RustSec-patched release.
- Refresh the pinned distroless runtime to the OpenSSL-patched Debian image.

### Operations

- Report version and build revision from `/health`.
- Add OCI metadata, public deployment examples and operator documentation.
- Add GitHub CI, GHCR publication, SBOM, image scanning and signed build
  provenance.

### Verified

- Rust 1.98: formatting, strict Clippy, 96 tests, `cargo audit`, `cargo deny`,
  a Linux/AMD64 image build, and zero HIGH or CRITICAL Trivy findings.
- The exact release image passed authenticated public MCP/CalDAV CRUD and
  free/busy acceptance, before and after production promotion.

## 0.1.0 - 2026-08-17

- Initial Stalwart CalDAV MCP server with OAuth discovery, PKCE proxying,
  durable streamable-HTTP sessions and eight calendar tools.
