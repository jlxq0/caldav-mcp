# Changelog

This project follows semantic versioning while it is pre-1.0. This file and the
signed `vX.Y.Z` tags are the release record; Forgejo release objects are not
maintained, so their absence says nothing about whether a version shipped.

## 0.2.2 - 2026-08-27

### Fixed

- `CALDAV_MCP_TRUSTED_PROXY_HOPS` defaults to 2 rather than 1, which is the
  measured length of the chain reaching the pod: client, Caddy edge, Cilium
  gateway. 109 authenticated requests over eleven hours carried two entries,
  and the same conclusion follows independently from the edge configuration.
  At 1 the recorded client address is the gateway's, a well-formed value
  identifying the wrong party in a provenance field; at 2 against a shorter
  chain the field is left blank instead. A deployment not behind that edge must
  override, since a LAN-only gateway appends nothing.

## 0.2.1 - 2026-08-26

### Added

- One log line per authenticated request carrying the **number** of
  `X-Forwarded-For` entries the pod received and the configured
  `CALDAV_MCP_TRUSTED_PROXY_HOPS`, never the entries themselves. Both
  deployments set 0, which blanks the recorded client IP before the header is
  read; a value that is too low is worse, selecting an upstream proxy's address
  and recording it as the client's. The correct value is the entry count, and
  these two fields settle it from one real request.
- `caldav_mcp_initialize_admitted_total` and one log line per admitted
  `initialize` carrying the pseudonymous identity. 0.2.0 counted refusals only,
  which gives no rate and no baseline, so the counter added to investigate how
  many sessions an identity opens could not answer it. The per-identity count
  is in the log rather than in a metric label, where a hash would be unbounded
  cardinality. It counts requests the limiter admitted, which is not the same
  as sessions the MCP layer went on to create.

## 0.2.0 - 2026-08-26

### Fixed

- The `initialize` limiter refused correctly and reported nothing: no log line,
  no `Retry-After`, no error class, and `tool_calls_total` reading zero because
  the limiter sits in Axum middleware outside the MCP router. Eight failed
  connection attempts left no server-side record of any kind.
- Slots refill one at a time, so recovering from an exhausted allowance took
  four hours rather than the thirty minutes the window length implies. A user
  who waited out what they believed was the window received exactly one
  session, reconnected twice and was refused again. The refill is now one slot
  per minute, and the burst 24 rather than 8.

### Added

- `Retry-After` on the 429, taken from the bucket rather than re-derived from
  the configured period, and rounded up.
- A JSON error body with a stable class, so a client can distinguish too many
  sessions from a rejected write, and which states that slots refill one at a
  time.
- `caldav_mcp_initialize_refusals_total{scope}`, and a warning log naming which
  bucket refused and the pseudonymous identity it refused.
- `CALDAV_MCP_INITIALIZE_BURST` and `CALDAV_MCP_INITIALIZE_REFILL_SECONDS`.
- `get_event_raw`, returning a calendar object as stored with every `VEVENT`,
  so a recurring series' `RRULE`, `EXDATE`s and `RDATE`s are reachable —
  server-side expansion strips them, as RFC 4791 §9.6.5 requires.
- `is_override`, `exdates`, `rdates`, and `RECURRENCE-ID` verbatim as
  `recurrence_id_value`, `recurrence_id_tzid` and `recurrence_id_range` on
  every event.

### Fixed (calendar)

- `update_event` patched and reported the first `VEVENT` in a calendar object.
  For a recurring series whose override was stored first, it renamed a single
  occurrence, reported success, and returned `recurrence_rule: null` for a
  series that has one. It now selects the component with no `RECURRENCE-ID`.
- `RECURRENCE-ID` was rendered to a UTC instant, which cannot build an
  `EXDATE`; `RANGE=THISANDFUTURE` was dropped entirely, so a this-and-future
  override was presented as a single-instance one.

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
