# Changelog

This project follows semantic versioning while it is pre-1.0. Release notes are
also published with each signed source tag.

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

## 0.1.0 - 2026-08-17

- Initial Stalwart CalDAV MCP server with OAuth discovery, PKCE proxying,
  durable streamable-HTTP sessions and eight calendar tools.
