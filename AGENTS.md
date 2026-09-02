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
- When breaking code to prove a test can fail, verify the *experiment* ran
  before reading its result. Twice in one session a mutation reported "no test
  died" for reasons that had nothing to do with the tests: a scripted
  `str.replace` whose pattern no longer matched after `cargo fmt` reflowed the
  line, and `cargo test --lib` on a crate with no library target, which exits
  101 and prints no `test result:` line at all. Assert the pattern matched, and
  treat a missing `test result:` line as a failed run rather than a clean one —
  a mutation that never applied looks exactly like a test suite that caught
  nothing.
- A limiter that is right and silent produces a user retrying blind against a
  correct rule, and every retry looks to them like the rule being broken. The
  `initialize` limiter refused correctly for hours while emitting nothing: no
  log line, no `Retry-After`, no error class, and `tool_calls_total` reading
  zero because the limiter is Axum middleware outside the MCP router, so a
  refusal never reaches the code that increments it. **A correct refusal that
  carries no information is the same object as a green that carries none.**
  Every limiter here logs which bucket refused, counts the refusal, and returns
  the wait taken from the bucket rather than re-derived from the configured
  period — those two agree only until someone changes the quota.
- Slots refill one at a time, so recovering from empty takes burst x refill and
  not one refill. Reporting the period as the retry hint tells a user to wait
  for a whole allowance they will not get: they come back, receive exactly one
  session, reconnect twice and are refused again. A wrong model of a limiter
  does not merely delay someone, it guarantees a second failure after the wait.
- The `initialize` burst and `session::MAX_SESSIONS` are coupled and stay
  coupled. At burst 8 it takes 32 identities to exhaust a 256-session pool, at
  24 about 10, at 32 exactly 8. Raising the burst alone does not remove the
  coupling, it spends it: a per-user refusal becomes a global exhaustion,
  invisible in the diff, breaking somebody other than the person who triggered
  it. **What makes the current burst safe is the identity population, not the
  number.** The bucket keys on the Logto `sub` and every agent on this machine
  resolves to one identity, so the distinct-identity count is a handful rather
  than ten. That is a property of today rather than of the design, and
  `CALDAV_MCP_INITIALIZE_BURST` puts it one command from mattering.
- **Read a Renovate rule against the manifest path, never against the
  repository.** `clusters/fondue/*-www/**` is the manual-merge rule, and this
  application's production path is `clusters/fondue/caldav-mcp`, so it falls
  through to the BASELINE rule with `automerge: true` and `platformAutomerge`.
  A minor bump therefore merges itself: `oddie-apps/platform#589` opened at
  14:30 on 2026-08-26 and merged at 14:32 with nobody involved. Two people
  described this path as gated by a human before anyone read the rule against
  it. A pattern that silently declines is invisible, and so is a merge nobody
  has to perform; this repository has the second.
- `audit::identity_hash` and `audit::token_hash` are the same function with
  different domains: `sha256(domain || ":" || value)[..8]`. **Only one of them
  is unreversible.** A bearer is high-entropy, so `token_hash` answers nothing;
  an email address comes from a small enumerable set, so `identity_hash`
  reverses against a candidate list in one script. Reproduced 2026-08-26:

      identity:julian@kampong.social       -> f5a076c6a6c82848
      identity:julian@lindner.earth        -> e511ab93d01ff206
      identity:caldav_test@kampong.social  -> 64ce710d59fb1d01

  That is deliberate and it is why `user_hash` is the field that separates two
  people on one server in a single grep. Read it as a pseudonym rather than an
  anonymiser, do not log the raw address instead, and do not mistake it for
  `token_hash` — that mis-reading is why nobody could say whose the tool calls
  were for several hours.
- **A rollout destroys this service's `kubectl` log history, and `--previous`
  does not help.** ArgoCD replaces the pod rather than restarting the
  container, so `--previous` has no prior container to read and returns
  nothing. On 2026-08-26 the v0.2.0 rollout erased the 58 tool-call lines that
  were the evidence base for the investigation that motivated the release, at
  the moment the release succeeded. `alloy` ships to Loki and holds fourteen
  days, which is where the history actually lives:

      sum by (uh) (count_over_time({namespace="caldav-mcp"}
        | regexp `"user_hash":"(?P<uh>[0-9a-f]+)"` [14d]))

- **Query those logs with `regexp`, not `| json`.** This service emits nested
  `tracing` JSON, so every field sits under `fields` and Loki's `json` parser
  produces `fields_user_hash`. A filter on `user_hash` therefore **matches
  nothing against lines that demonstrably exist**, and an identity that never
  appeared produces the identical empty set. A parser that cannot see a field
  and a field that was never written are the same result, which is the same
  shape as a 429 that names no limiter and a mutation that never applied. The
  `regexp` form does not depend on the parser. Cross-check any zero against a
  line you can see in `kubectl logs` before believing it.
- **When adding a counter for a bad outcome, ask whether anyone will need the
  denominator.** `caldav_mcp_initialize_refusals_total` was added to answer how
  many sessions an identity was opening, and could not: it counts only the
  refusals, so it gives no rate and no baseline. A night was spent on that
  question and the instrument built to investigate it was blind to it.
  `caldav_mcp_initialize_admitted_total` is the other half. Note what it counts
  and what it does not: requests the limiter **admitted**, which is not
  sessions rmcp went on to create, because the limiter is the last gate that
  can be observed from outside the MCP router. Per-identity counts go in the
  log line as `user_hash`, never as a metric label, where a hash is unbounded
  cardinality.
- **A `pending` commit status on the `docker` context can mean the job was
  never scheduled.** `docker` declares `needs: cargo`, so when `cargo` fails,
  `docker` never runs and **no task is ever created for it** under
  `/actions/tasks`. Its status sits at `pending` for a long and unpredictable
  interval before the server resolves it. Measured on `287a005c`, which has
  exactly two `docker` rows:

      15:11:32Z  CI / docker (pull_request)  pending
      16:00:54Z  CI / docker (pull_request)  failure

  **49 minutes in `pending`**, of which 34 were after `cargo` failed at
  `15:26:25Z`. Not permanent, which one version of this entry claimed, and not
  34 minutes, which the next one did: that figure was the delay after the
  dependency failed rather than the time spent pending. Long enough either way
  to be indistinguishable from a job queued behind the capacity-1 runner, which
  cost fifty minutes of waiting out of a correct reluctance to push and cancel
  an in-flight run. Before waiting on a `pending` status, check whether a task
  exists for that sha **and** whether the job it declares `needs:` on passed.
  Either alone is ambiguous; together they are decisive.
- **Read `/commits/{sha}/status`, not `/commits/{sha}/statuses`.** The plural
  endpoint returns every row ever written, and Forgejo's timestamps are
  second-resolution, so a job that skips writes `pending` and `success` in the
  same second and any reduction that picks one of a tie picks arbitrarily. Four
  repositories reported stranded `pending` statuses that way on 2026-08-26 and
  every one collapsed on the combined endpoint, which dedupes. The case above
  survives because its two rows are 49 minutes apart rather than tied, which is
  a property of the data and not of the reduction, and the combined endpoint
  returns the same answer for it.
- **`main` is protected: no direct pushes, `CI / cargo*` required, zero
  approvals.** The glob covers both event suffixes, `(push)` on a branch push
  and `(pull_request)` on a pull-request head, which are different contexts for
  the same job.

  **`CI / docker` is deliberately not required**, and the reason is not that it
  is unimportant. Its status is *derived* from `cargo` through `needs:`, so it
  carries no information `cargo` does not already carry, and it resolves up to
  half an hour late (above), which would gate every merge on a status that lags
  the work. `cargo` is the job that runs the gates: `fmt --check`, `clippy -D
  warnings`, `test --all-features --locked`, `audit`, and `deny`. Do not add
  `docker` to the required list while it depends on `cargo`.
- **`CALDAV_MCP_TRUSTED_PROXY_HOPS` is 2 here, and the topology is the reason
  rather than a product name.** Client → Caddy edge → Cilium gateway → pod: the
  edge configures no `trusted_proxies`, so it *replaces* `X-Forwarded-For` with
  its peer, and Cilium runs `gateway-api-xff-num-trusted-hops: 0`, so Envoy
  *appends* the downstream address. Two entries reach the pod, measured 109
  times out of 109 over eleven hours on 2026-08-27 and derived independently
  from `oddie-apps/edge-config`. A sibling service documented its own value as
  `Default 1 (Traefik)` and there is no Traefik on this cluster at all, which is
  what a constant encoding another system's behaviour looks like when the system
  is not named beside it.

  **A deployment not behind that edge must override.** The `home` gateway is
  LAN-only, so a backend there sees one entry, and a service moving between the
  two changes its own correct value with nothing reporting it.

  **Being wrong is asymmetric, and the default errs the recoverable way.**
  `parse_client_ip` returns `None` when the chain is shorter than the hop count,
  so too high blanks the field. Too low does not: it selects a proxy and writes
  a well-formed address identifying the wrong party into the provenance record,
  which is the value an incident acts on.

  **2 is safe only because the edge replaces the header rather than appending
  to it**, and that is a property of `oddie-apps/edge-config` rather than of
  this code. Caddy sets `trusted_proxies` nowhere, in the global block or in any
  of its 80 site blocks, so no client-supplied entry survives into the chain.
  Behind an *appending* proxy the same value would be dangerous rather than
  merely wrong: `len < hops` would never fire, and counting two in from the
  right would land on whatever the client sent. **Do not raise a hop count
  elsewhere by analogy with this one.** The trade is deliberate: at 0 this
  service's correctness did not depend on the edge at all, because it selected
  nothing whatever the header said; at 2 it has a real audit trail and depends
  on the edge continuing to replace. The reverse pointer is
  `oddie-apps/edge-config#39`.

  **Residual, and the 109-request measurement could not see it.** A caller
  reaching the Cilium gateway directly, bypassing the edge, supplies its own
  header; Envoy appends the caller's address, so the chain is two long, the
  `len < hops` guard never fires, and two hops selects the string the caller
  wrote. **No single hop count is correct for both paths**: the edge path wants
  2 and the direct path wants 1. The mitigation is that only one path is
  supposed to exist, which is a fact about the cluster that nothing in this
  repository can assert. **Measured 2026-08-27: the precondition is a stolen
  bearer plus code running inside the cluster, not LAN access.** The gateway's
  addresses time out from the LAN on 80 and 443 and answer 401 from a pod,
  because the `MetalLB` pool holding them is BGP-advertised across `sgp`, `lax`
  and `zrh` rather than L2, so nothing on the wifi has a route. My own earlier
  reading, that the public addresses shift the burden and one vantage cannot
  settle it, was the honest disposal of a weaker measurement and is superseded
  by this one. **The one line that would change it is a second `parentRef` on an
  HTTPRoute**; enumerated cluster-wide on 2026-08-27, 89 routes with none
  carrying more than one, so the property is unanimous rather than merely true
  of this service's eight, and the assertion belongs in `platform` as a manifest
  property rather than here. **Being on the edge-only list is not a statement
  that this hop count is right, and fixing this hop count is not a reason to
  come off it**: the list is about which routes must stay edge-only, and the two
  facts are independent despite being established in the same hour.

  **And "the pod" is two pods.** Production and beta run separate images from
  separate tags under separate manifests, so a measurement or a default reaching
  one says nothing about the other. On 2026-08-27 production ran `v0.2.2` with
  the corrected default while beta still ran a `v0.2.0-beta` image with the old
  one, which would have made deleting beta's override inherit 1 while deleting
  production's was safe.

  **And on that path the severity inverts.** 1 selects an infrastructure
  address, 2 selects whatever the caller typed, so the value that fixes the
  ordinary path is the one that turns a wrong-but-inert record into a
  caller-controlled one. "Set it to the edge-inclusive depth" reads as a
  complete instruction and is not. Applies identically to
  `carddav-mcp`, `jmap-mcp` and `webmail`, because the residual is in the
  topology rather than in any implementation.

  **The log line reports whether an address resolved, never the address.** So
  the acceptance for a hop-count change is the three fields together —
  `xff_entries`, `trusted_proxy_hops` and `client_ip_resolved` — from which the
  selected index is `entries - hops`. `resolved=true` alone does not
  distinguish 2 from 1, since both resolve; it distinguishes either from the
  blank that 0 produces.
- **An image tag minted by the beta loop is not a git ref.** `bin/ci-version`
  names the *container image*; nothing tags the repository. So
  `v0.2.3-beta.20260827043744` exists in the registry and not in
  `git ls-remote --tags`, and a contents lookup at that ref correctly reports
  `object does not exist`. A beta build's source is reachable through the
  `sha-<short>` image tag or through `/health`'s `revision`, never through the
  version its image was published under. The one exception is
  `v0.1.2-beta.20260826052605`, cut by hand before the loop existed.
- **`/repos/{r}/tags/{name}` is not an existence check, because its miss echoes
  your input.** A name it cannot find returns `{"message": "<the name you
  asked>"}`, and a name it finds returns `{"name": "<the tag>", ...}`. A
  fabricated string produces the identical shape, so any reduction that greps
  the response for the tag name reports every tag as present. Measured
  2026-08-27:

      v0.2.3-beta.20260827043744  ->  {"message": "v0.2.3-beta.20260827043744"}
      definitely-not-a-tag        ->  {"message": "definitely-not-a-tag"}
      v0.2.2                      ->  {"name": "v0.2.2", ...}

  Check `git ls-remote --tags` or read `.name` specifically, and resolve a
  file lookup by sha when the answer is load-bearing. This corrected a report
  that the contents API silently fails on tags: it does not, stable tags
  resolve, and the endpoint that lies is the one that looked like corroboration.
- **`ATTENDEE` without `ORGANIZER` invites nobody, and every signal says it
  worked.** RFC 6638 scheduling keys on `ORGANIZER`, so an object carrying
  attendees and no organizer is not a scheduling object and the server
  correctly emits no iTIP. The event appears on the calendar, `list_events`
  returns the attendee, and the create response echoes `attendees: [...]`
  beside `organizer: null`. `create_event` shipped that way and 360 log lines
  with zero scheduling events, measured with a control, is what found it.

  **The obvious test cannot catch it**: asserting on `create_event`'s response
  passes against the broken code, because the response is built from the same
  struct that omitted the field. Assert on the **stored object**, and prove it
  by removing the `ORGANIZER` line and watching the suite stay green, which it
  did at 124 passed.

  `ORGANIZER` is written only when there are attendees. Writing it on a solo
  event would make everything this tool creates a scheduling object, changing
  what later edits do rather than fixing what this one does. And attendees with
  no organizer available are **refused**, because a token carrying no email
  claim would otherwise recreate the original defect silently.

  **An update carries `ORGANIZER` through and does not add one.** So a series
  created after this fix notifies on edit and on attendee removal, and one
  created before it still notifies nobody. Backfilling on update would start
  sending mail about events that have never notified anyone, which is the
  irrecoverable direction, so it is deliberately not done.
- **`calendar-user-address-set` on this server advertises `mailto:{login
  name}`, which is not an address.** Stalwart builds it from the account's
  login name rather than from its addresses:

      crates/dav/src/principal/propfind.rs   vec![Href(format!("mailto:{}", account.name()))]
      crates/common/src/cache/principals.rs  impl AccountCache { fn name() -> &str { self.name.as_ref() } }
      crates/common/src/auth/mod.rs          AccountCache { name: Box<str>, addresses: Box<[EmailAddress]>, ... }

  `name` and `addresses` are separate fields and `name()` returns the first, so
  the set is always one element and that element is a login name. Verified
  identical at `main` and at `v0.16.19`, the deployed tag, on 2026-09-02. Every
  principal on this server has `name != emailAddress`, so the value is
  `mailto:julian` and its equivalents rather than a mailbox.

  **Consequences.** No client can pick an address from the set, so every client
  sends whatever address its own account was configured with, which is why two
  Macs on one principal send different organizers and why the iPhone needs no
  special explanation. Do not reach for `calendar-user-address-set` to discover
  a user's addresses, and do not read a one-element set as "this user has one
  address".

  **Recorded as a property of the server we run, not as a bug awaiting a
  patch.** Reporting it upstream is not available to us, so nobody is waiting
  for anything and the next person should work around it rather than expect it
  to change.

  **Unmeasured**: the live `PROPFIND`. All of the above reads the code that
  serves it, blocked on the CalDAV credential that `#16` and `#19` also wait
  on.
- There is no way to make a `PUT` quiet. Stalwart parses `Schedule-Reply: F`
  (`crates/dav-proto/src/parser/header.rs`) but consults it only in
  `crates/dav/src/calendar/delete.rs`; `update.rs` never reads it. Every
  occurrence operation — adding an `EXDATE`, dropping an override, setting
  `UNTIL` — is a `PUT`, so the header is accepted and ignored and the iTIP mail
  goes out. The only per-attendee switch that works on `PUT` is
  `SCHEDULE-AGENT=CLIENT`, which is persistent data that also silences every
  later legitimate update. So a write that would schedule refuses by default
  and names every `ATTENDEE`, and the caller opts in per call. Verified against
  `v0.16.14` on 2026-08-26 and re-verified unchanged at `v0.16.19` on
  2026-09-02 after the server was upgraded: `no_schedule_reply` is still read
  in `delete.rs` and nowhere else, with `update.rs` and `copy_move.rs` at zero
  occurrences.

  **A version cited in a finding is a claim that expires when the deployment
  moves**, and nothing reports the expiry. This one was written as "the
  deployed image" and stopped being that overnight while still reading as
  current. Cite the version *and* the date, and re-check at the running tag
  before relying on it, which is `docker manifest inspect -v` against the pod's
  `imageID` and then the same lines fetched at that tag rather than at `main`.
- Assume every `ATTENDEE` is mailed. `send_update_messages()` skips an attendee
  only when `email.is_local`, and `Email::new` sets that by exact membership of
  `local_addresses` — which `build_account_info` fills with the **authenticated
  account's own** addresses and its groups', each expanded across the domain's
  names, not with the domains the server hosts. `is_local_domain()` exists and
  is not what this uses. So a second mailbox on the same Stalwart is *not* local
  to the acting account and does receive an iMIP; the only address suppressed is
  the caller's own. Re-verified unchanged at `v0.16.19` on 2026-09-02:
  `send_update_messages` still requires `!self.email.is_local` and `Email::new`
  still sets it by exact membership. Read this before designing any experiment that puts an
  `ATTENDEE` in a fixture: expecting no mail for a same-server attendee makes a
  correct run look like a bug.
- **Stalwart matches an `EXDATE` by instant, not by literal form.** Measured
  2026-09-02 against the deployed server, one collection created and deleted for
  the purpose (`#16`, `issuecomment-17026`): a UTC instant excludes an
  occurrence of a zoned series, a date-time excludes one of an all-day series,
  and an `EXDATE` for the series' **first** occurrence removes it. Two refusals
  in `delete_occurrence` rested on the opposite and were removed rather than
  kept as belt and braces, because each was justified by a claim the run
  refuted. What still matters is the **instant**: `TZID=UTC:20260908T090000`
  against a `TZID=Asia/Singapore` series excludes nothing, because 09:00 UTC is
  a different moment.

  **The exclusion is shaped to the caller's value rather than to `DTSTART`'s
  parameters**, since a date under a `TZID=` head is malformed and no server can
  repair that.

  **And a wrong instant is still accepted with 201 and still does nothing**, so
  the hazard is confirmed and only its cause was misdescribed. A value the
  `RRULE` never generates is indistinguishable from a wrongly-zoned one, which
  is why an expander is the only possible pre-flight check.

  An `EXDATE` must still match the occurrence as the `RRULE` generates it: Take both from `DTSTART`
  rather than from the caller — a mismatch is accepted by the server and
  excludes nothing, which is a write that reports success and changes what the
  calendar shows not at all. Remove the matching override in the same `PUT`, or
  clients render an occurrence the series says does not exist.
