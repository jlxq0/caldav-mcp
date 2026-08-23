# caldav-mcp

Rust (`axum` + `rmcp`) streamable-HTTP MCP server for Stalwart CalDAV.
Reuse the jmap-mcp HTTP/OAuth/DCR/streamable-HTTP shell. Replace the JMAP
client with CalDAV. Do not ship Node/Go. Do not invent a third auth story.
Do not wrap third-party CalDAV MCP servers.

## Public auth contract

- Self-host. Public URL is `https://caldav-mcp.your-domain.example/mcp`.
- Streamable HTTP. `initialize` creates a durable session.
- RFC 9728 resource = `{origin}/mcp`. Metadata at
  `/.well-known/oauth-protected-resource/mcp`.
- `RESOURCE_URL` env = origin **without** `/mcp`.
- Bring your own IdP (Logto or another OIDC provider).
- Validate inbound JWT (JWKS), forward that bearer verbatim to Stalwart.
- Never accept or store Basic credentials or app passwords.
- Never log tokens.

## Environment

```text
CALDAV_MCP_RESOURCE_URL=https://caldav-mcp.your-domain.example
CALDAV_MCP_AUTHORIZATION_SERVER=https://login.your-domain.example/oidc
CALDAV_MCP_STALWART_DAV_BASE_URL=https://dav.your-domain.example
CALDAV_MCP_DCR_CLIENT_ID=<your-dcr-client-id>
```

## Scope

- `whoami`
- list calendars
- list/search events in a time window
- create / update / delete events
- free/busy
- Default timezone `Asia/Singapore`

Keep the HTTP/OAuth/session/Dockerfile/CI identical in shape; only the backend
client + tool list change. Self-contained repo (no third shared-crate repo).

## Verification

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

## Known pitfalls

- Forgejo Actions can fail during `Set up job` when an immutable action commit
  is no longer advertised by the action mirror. Verify every pinned revision
  with `git ls-remote` and update the pin rather than retrying unchanged.
- Forgejo Runner does not apply the `default: stable` input declared by
  `dtolnay/rust-toolchain`. Always pass `toolchain: stable` explicitly.
- Stalwart `requireAudience` may accept only one resource indicator. Set
  `CALDAV_MCP_STALWART_AUDIENCE` to the audience the DAV server actually
  accepts, and keep RFC 9728 `resource` as `{origin}/mcp`.
- A cache “soft cap” that only removes expired entries is not a memory bound.
  Use a hard cap; fail closed for security state and deterministically evict
  only entries whose state is an optional cache optimisation.
- Unknown JWT `kid` values are attacker-controlled. JWKS refreshes must be
  single-flight, globally cooled down (including failed refreshes), and
  preceded by the signing-algorithm allowlist.
- `rmcp` buffers a full streamable-HTTP JSON-RPC body. Keep an explicit request
  body limit outside the rmcp service and bind each MCP session id to the
  verified token subject that created it.
- A same-origin DAV href does not prove the target is an event. Before a
  destructive method, reject collection-shaped paths and verify the resource
  parses as a `VEVENT`.
- A clean, previously verified lockfile can become vulnerable when RustSec
  publishes a new advisory. Keep `cargo audit` in CI and use the narrowest
  compatible transitive update when the patched release needs no API change.
- A security-critical allowlist that is absent must fail visibly at startup;
  silently turning it into an empty list makes every OAuth attempt fail later
  with a misleading client error and hides operator misconfiguration.
- Shared logs and traces are a data boundary. Emit domain-separated hashes for
  identities and DAV hrefs; never write clear emails, calendar paths, event
  content, session credentials, or bearer tokens to observability backends.
- A dependency-clean Rust lockfile does not cover operating-system libraries in
  the runtime image. Scan the final container and refresh its pinned base digest
  when the distro has shipped a fixed package.
- New stable Rust releases can add deny-by-default Clippy findings that older
  local toolchains do not report. Reproduce CI with its exact stable release;
  for findings emitted by dependency macros, use the narrowest documented lint
  allowance at the macro call site and explain why it is necessary.
- A Clippy lint introduced after the declared `rust-version` is itself unknown
  to older supported compilers and fails under `-D warnings`. Put a scoped
  `#[allow(unknown_lints)]` immediately before the version-specific allowance,
  then verify strict Clippy on both the minimum and current stable toolchains.
