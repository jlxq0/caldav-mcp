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
- An OAuth redirect allowlist matched by exact string equality cannot admit a
  native or command-line client at all: RFC 8252 §7.3 clients bind an ephemeral
  loopback port per session, so a fixed-port entry never matches and the
  failure surfaces as `unregistered redirect_uri` from DCR rather than as a
  server misconfiguration. Relax the port for loopback `http` entries only, and
  keep scheme, host, path and query exact; a port relaxation applied to `https`
  or private-use entries would admit a different origin.
- A guard written as `if a != x || b != x` is two conditions, and a test that
  exercises one side leaves the other free to be deleted with the suite still
  green. Assert per side. In `oauth_redirect.rs` the unpinned side was the
  allowlist entry's scheme: drop it and an `https://localhost:8443/callback`
  entry, whose host is loopback, port-relaxes into a cleartext
  `http://localhost:3118/callback` — an https→http downgrade on an entry the
  operator wrote expecting TLS.
- A test named after the deployment is a claim about the running system, and it
  rots silently. `deployed_allowlist_parses` asserted only that a string literal
  it declared itself parsed to nine entries, so the deployment was never an
  input and no drift could turn it red; the identical test in a sibling repo
  carried nine entries against a live seven and stayed green throughout. Either
  feed the test the running system or stop naming it after it: keep the
  snapshot, date it, record the command that reads the live value, and assert
  per entry so a substitution fails where a count cannot.
- `is_loopback_host` only ever sees `Url::host_str()` output, which the `url`
  crate has already normalised: `127.1`, `0177.0.0.1` and `2130706433` all
  arrive as `127.0.0.1`, and an IPv6 host always arrives bracketed. Which
  spellings the allowlist admits is therefore a dependency's behaviour, not
  this repo's, so it is pinned by test rather than assumed — a crate bump would
  change it with nothing else going red. An unbracketed `"::1"` arm was
  unreachable for the same reason and was removed; in a security predicate an
  unreachable arm reads as coverage that is not there. Do not add it back.
- `CHANGELOG.md` and the signed `vX.Y.Z` tags are this repo's release record.
  Do not create Forgejo release objects: nothing downstream reads them (Renovate
  tracks the container registry, ArgoCD reads the pinned digest, CI triggers on
  the tag), and a releases page carrying some versions and not others answers
  "did this ship?" with a confident no. Four of the seven Rust MCP servers have
  never had one and the three that did stopped after their first, so the page is
  maintained by nobody and read as if it were.
- The beta image version is derived by `bin/ci-version` from the newest stable
  git tag plus the commits since it, and never from `Cargo.toml`. A manifest
  carrying "the next version" between releases is a second source for a number
  git already knows, and two sources for one fact disagree silently because
  nothing compares them. `Cargo.toml` is read on a release tag only, where the
  guard exists because `/health` reports `CARGO_PKG_VERSION` and a tag naming a
  different number would be a lie the image cannot correct.
- The prerelease suffix must be digits. The platform's
  `clusters/fondue/*-beta/**` Renovate rule takes `-(beta|alpha)\.\d+$`, so a
  sha suffix parses as valid semver, is accepted everywhere in this repo, and is
  then unmatchable by the rule that maintains the deployment pin: no bump PR is
  ever opened and beta silently stops moving. That is how `caldav-mcp-beta` ran
  a pre-security-fix image for four days while reading Synced and Healthy.
- A beta must sort above the release it replaces. `0.1.2-beta.<ts>` sorts below
  `0.1.2`, so beta would read as older than production while running newer code;
  `bin/ci-version` bumps the base first for that reason.
- A calendar object for a recurring series holds the master `VEVENT` and one
  per override, in no guaranteed order — RFC 5545 does not require the master
  first. Anchoring on the first `BEGIN:VEVENT` made `update_event` rename a
  single occurrence while reporting the series renamed, and return
  `recurrence_rule: null` for a series that has one. Select the component with
  no `RECURRENCE-ID`; `master_event_start` is the one place that decides.
- `RECURRENCE-ID` rendered as a UTC instant cannot build an `EXDATE`. An
  exclusion has to carry the same value type and `TZID` the `RRULE` generates,
  so `Event` also carries `recurrence_id_value`, `recurrence_id_tzid` and
  `recurrence_id_range` verbatim. `RANGE=THISANDFUTURE` in particular means the
  override applies to that occurrence and every later one; dropping it, as the
  parser did, presents a this-and-future override as a single-instance one.
