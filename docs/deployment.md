# Deployment guide

This guide describes the contract a self-hosted deployment must satisfy. The
example manifests use placeholders and are not tied to the maintainers'
infrastructure.

## Prerequisites

- A public HTTPS origin dedicated to caldav-mcp.
- A Stalwart deployment with CalDAV and an OIDC-backed directory.
- An OIDC provider capable of JWT access tokens, PKCE and JWKS publication.
- A reverse proxy or ingress that preserves the public `Host` and sets
  `X-Forwarded-Proto: https`.

## OIDC provider

Create an API/resource whose indicator is your MCP URL, normally
`https://caldav-mcp.your-domain.example/mcp`. Tokens must include:

- an exact `iss` matching `CALDAV_MCP_AUTHORIZATION_SERVER`;
- an `aud` containing the MCP origin, MCP URL, or the explicitly configured
  Stalwart audience;
- `sub` and `exp`;
- the identity claim Stalwart uses to locate the user, commonly `username` or
  `email`.

Create a public browser/native client using authorization code plus PKCE. Do
not configure a client secret. Add
`https://caldav-mcp.your-domain.example/oauth/callback` to that client's
redirect URIs. Put its public client id in `CALDAV_MCP_DCR_CLIENT_ID` when your
MCP clients require the RFC 7591 compatibility endpoint.

The values in `CALDAV_MCP_OAUTH_REDIRECT_URIS` are the final MCP clients'
callbacks, not caldav-mcp's callback. Keep that allowlist as narrow as your
supported client set. Matching is exact apart from the port of a loopback
`http` entry, which RFC 8252 §7.3 requires the server to accept on any value —
one `http://localhost:8787/callback` entry therefore covers every ephemeral
port a command-line client picks.

## Stalwart

Configure Stalwart's OIDC directory with the same issuer and public JWKS.
Stalwart must accept the bearer audience requested through
`CALDAV_MCP_STALWART_AUDIENCE` and map its identity claim to the correct
account. Some Stalwart versions/configurations accept only one audience; use
the exact resource indicator Stalwart accepts and never borrow another
service's audience merely to make authentication succeed.

Prove this layer directly before adding MCP: a JWT minted for caldav-mcp should
receive a successful DAV discovery/`PROPFIND`, while expired, wrong-issuer and
wrong-audience tokens must fail.

## Container

The supported image is Linux AMD64 and runs as a non-root distroless user. It
has no shell and requires no writable filesystem.

```sh
cp .env.example .env
# edit .env
docker compose -f examples/docker-compose.yml up
```

For Kubernetes, copy `examples/kubernetes.yaml`, replace all placeholder
values, add your ingress/TLS resources and pin the image digest. The example
uses restricted security settings and keeps metrics off the public Service.

## Network policy

The process needs outbound HTTPS to the OIDC/JWKS endpoints and Stalwart DAV.
It needs no database, filesystem, cloud-storage or privileged access. A useful
default policy is:

- ingress to port 3000 only from the ingress controller and kubelet probes;
- ingress to port 9090 only from monitoring;
- egress to cluster DNS;
- egress to the configured OIDC and DAV destinations on TCP 443.

FQDN/IP policy syntax depends on the cluster CNI, so the generic example does
not guess it for you.

## Reverse proxy

Route every path on the public origin to port 3000, including `/mcp`,
`/.well-known/*`, `/authorize`, `/oauth/callback`, `/token`, `/register` and
`/health`. Do not publish the metrics listener. Set
`CALDAV_MCP_TRUSTED_PROXY_HOPS` to the exact number of trusted proxies between
the client and process; use `0` for direct connections.

## Verification

After deployment:

1. Check `/health` and both OAuth metadata documents.
2. Confirm unauthenticated `/mcp` returns 401 and a path-aware
   `WWW-Authenticate` header.
3. Complete OAuth from every supported MCP client.
4. Run `whoami` and `list_calendars`.
5. Create a uniquely named disposable event, then list, search, update and
   delete it using the returned href and ETag.
6. Run `free_busy` across the same window.
7. Confirm metrics advanced and logs contain no bearer or calendar content.

Keep the prior immutable digest available for rollback. A process-health probe
does not prove OIDC or DAV correctness; the authenticated smoke test is the
release gate.
