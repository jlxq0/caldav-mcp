# caldav-mcp

`caldav-mcp` is a self-hosted, streamable-HTTP MCP server for calendars on
[Stalwart](https://stalw.art/). It validates each caller's OIDC access token and
forwards that same bearer to Stalwart CalDAV. There are no stored passwords,
shared service credentials, Basic-auth fallbacks, or third-party CalDAV MCP
servers hidden behind it.

The public MCP endpoint is `https://<your-host>/mcp`. A running example exists
at `https://caldav-mcp.kampong.social/mcp`, but it is restricted to accounts in
that deployment's identity provider; it is not a public calendar service.

## Capabilities

- `whoami`
- `list_calendars`
- `list_events`
- `search_events`
- `create_event`
- `update_event`
- `delete_event`
- `free_busy`

Offset-free date-times default to `Asia/Singapore`. RFC 3339 offsets are
preserved as instants and rendered as UTC. All-day end dates are exclusive.
Updates preserve unmodified iCalendar properties and use ETags for optimistic
concurrency.

## How authentication works

```text
MCP client
  -> OAuth/PKCE through caldav-mcp
  -> your OIDC provider
  -> JWT access token scoped to https://<your-host>/mcp
  -> caldav-mcp validates issuer, audience, expiry and JWKS signature
  -> the same bearer is forwarded to Stalwart CalDAV
  -> Stalwart maps the token identity to that user's calendars
```

`caldav-mcp` is the RFC 9728 protected resource and an OAuth proxy for clients
that expect discovery or dynamic client registration. Logto is the reference
IdP, but any OIDC provider that issues compatible JWT access tokens can work.
See [the deployment guide](docs/deployment.md) and
[security model](docs/security-model.md) before exposing it to the internet.

## Quick start with Docker

1. Create an OIDC API resource for `https://caldav-mcp.your-domain.example/mcp`
   and a public PKCE client whose callback includes
   `https://caldav-mcp.your-domain.example/oauth/callback`.
2. Configure Stalwart's OIDC directory for the same issuer and identity claim.
3. Copy `.env.example` to `.env` and replace every placeholder.
4. Run:

```sh
docker run --rm --name caldav-mcp \
  --env-file .env \
  -p 3000:3000 \
  ghcr.io/jlxq0/caldav-mcp:<version>
```

Put an HTTPS reverse proxy in front of port 3000. Keep port 9090 private. Then
verify:

```sh
curl --fail https://caldav-mcp.your-domain.example/health
curl --fail \
  https://caldav-mcp.your-domain.example/.well-known/oauth-protected-resource/mcp
```

Release images are published at `ghcr.io/jlxq0/caldav-mcp:<version>` and
`forge.oddie.app/jlxq0/caldav-mcp:<version>`. Pin the resolved digest in
production.

## MCP client configuration

Clients with remote MCP support need only the URL; OAuth discovery happens
from the protected-resource response. For a JSON-based client:

```json
{
  "mcpServers": {
    "calendar": {
      "url": "https://caldav-mcp.your-domain.example/mcp"
    }
  }
}
```

The exact callback URI used by a client must appear in
`CALDAV_MCP_OAUTH_REDIRECT_URIS`. The provided example includes current Claude,
Cowork, Cursor, Grok Bot and localhost callbacks. Remove clients you do not
intend to support.

## Configuration

| Variable | Required | Default | Purpose |
|---|---:|---|---|
| `CALDAV_MCP_RESOURCE_URL` | yes | — | Public HTTPS origin, without `/mcp`. |
| `CALDAV_MCP_AUTHORIZATION_SERVER` | yes | — | Exact OIDC issuer URL. |
| `CALDAV_MCP_STALWART_DAV_BASE_URL` | yes | — | Public Stalwart DAV origin. |
| `CALDAV_MCP_OAUTH_REDIRECT_URIS` | yes | — | Comma-separated exact callback allowlist. Missing or empty configuration stops startup. |
| `CALDAV_MCP_DCR_CLIENT_ID` | no | disabled | Public PKCE client returned by the DCR compatibility endpoint. |
| `CALDAV_MCP_STALWART_AUDIENCE` | no | resource origin | Absolute resource indicator forwarded during OAuth and accepted by Stalwart. |
| `CALDAV_MCP_BIND_ADDR` | no | `0.0.0.0:3000` | Public HTTP listener behind TLS termination. |
| `CALDAV_MCP_METRICS_BIND_ADDR` | no | pod IP or `127.0.0.1:9090` | Private Prometheus listener. |
| `POD_IP` | no | — | Kubernetes downward-API pod IP used for the metrics listener. |
| `CALDAV_MCP_RATE_LIMIT_READS_PER_MIN` | no | `60` | Per-identity read-tool quota. |
| `CALDAV_MCP_RATE_LIMIT_WRITES_PER_MIN` | no | `30` | Per-identity write-tool quota. |
| `CALDAV_MCP_TRUSTED_PROXY_HOPS` | no | `1` | Trusted rightmost proxy hops when interpreting `X-Forwarded-For`. Use `0` without a proxy. |
| `CALDAV_MCP_STALWART_CONNECT_IP` | no | DNS | Optional IP override while retaining the DAV hostname for TLS and `Host`. |
| `CALDAV_MCP_LOGTO_CLIENT_ID` / `CALDAV_MCP_LOGTO_CLIENT_SECRET` | no | disabled | Opaque-token introspection fallback credentials. JWT validation needs neither. |
| `CALDAV_MCP_LOG_FORMAT` | no | compact | Set to `json` for structured logs. |
| `RUST_LOG` | no | service info, `rmcp` warnings | Standard tracing filter. Do not enable dependency trace logs in production without reviewing their fields. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | disabled | OTLP/gRPC trace exporter. |

Production URL configuration requires HTTPS. Cleartext HTTP is accepted only
for loopback development URLs. Redirect URIs are exact matches; only loopback
hosts may use `http://`.

## Operations

- `GET /health` is public and reports process health, version and build
  revision. It deliberately does not turn an IdP or DAV outage into a pod
  restart loop.
- `GET /metrics` is served on the separate metrics listener and must not be
  internet-exposed.
- `GET /token/introspect` is bearer-protected and returns only the caller's own
  identity, expiry and last-used envelope.
- Logs and traces contain pseudonymous identity/resource hashes, tool names,
  outcomes and latency. They never contain access tokens or calendar content.

See [examples/docker-compose.yml](examples/docker-compose.yml) and
[examples/kubernetes.yaml](examples/kubernetes.yaml) for deployment starting
points.

## Development

Rust 1.93 or later is required.

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo audit
cargo deny check bans licenses sources
```

## Release and deployment

Forge is canonical for source, tags, releases and the primary container image.
Changes land on `main`; a signed `vX.Y.Z` tag runs the Forge CI release build
and publishes `forge.oddie.app/jlxq0/caldav-mcp:vX.Y.Z`. The GitHub repository
and GHCR image are mirrors.

The maintained `kampong.social` beta and production deployments are defined in
the separate Forge `oddie-apps/platform` GitOps repository. They pin immutable
image digests, and ArgoCD reconciles those manifests to the cluster. A release
is exercised on beta with the authenticated verification sequence in
[the deployment guide](docs/deployment.md) before a separately reviewed
production promotion. This service is stateless and has no database migration
or seed step.

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Security
issues must follow [SECURITY.md](SECURITY.md), not the public issue tracker.

## License

MIT — see [LICENSE](LICENSE).
