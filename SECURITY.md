# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.1 and later | Yes |
| 0.1.0 and earlier | No |

Security fixes are released from `main`. Operators should run the newest
published image by immutable digest.

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub private vulnerability reporting at
https://github.com/jlxq0/caldav-mcp/security/advisories/new. If that is
unavailable, email julian@lindner.earth with the affected version, realistic
impact, reproduction conditions, and any suggested remediation. Do not include
real access tokens, calendar content, or personal data.

You should receive an acknowledgement within 72 hours. We will coordinate
validation, remediation, release timing, and credit with the reporter. Please
allow a reasonable remediation window before public disclosure.

## System and Scope

This policy covers the Rust service, Docker image, CI/release definitions, and
generic deployment examples in this repository. The internet-facing service
provides OAuth discovery/proxy endpoints and a streamable-HTTP MCP endpoint,
validates OIDC JWT access tokens, maintains bounded in-memory MCP sessions, and
forwards each validated bearer to a configured Stalwart CalDAV origin.

Protected assets include bearer tokens, OAuth authorization codes and state,
user identity and session ownership, calendar/event data, DAV resource
integrity, and service availability.

## Threat Model and Trust Boundaries

OAuth parameters, HTTP headers and bodies, JWTs, MCP JSON-RPC messages, session
ids, tool arguments, DAV XML, iCalendar payloads, upstream redirects, and
network responses are attacker-controlled until validated.

The configured OIDC issuer/JWKS and Stalwart DAV origin are operator trust
anchors. Stalwart remains the authorization authority for calendar access.
Reverse proxies, the IdP, Stalwart, metrics collectors, and deployment secret
stores are separate operational boundaries.

## Security Invariants

- Only a valid bearer with the configured issuer, audience, expiry, signature
  algorithm, and JWKS key may reach MCP tools.
- The validated bearer is forwarded verbatim only to the configured Stalwart
  origin. Basic credentials and app passwords are never accepted or stored.
- A durable MCP session is usable only by the verified subject that created it.
- OAuth redirects are exact allowlist matches and state is single-use, expiring,
  unpredictable, and bounded.
- JWT/JWKS, OAuth, discovery, rate-limit, last-used, and session state remains
  bounded under attacker-controlled cardinality.
- Request bodies and untrusted upstream responses are bounded before buffering.
- DAV hrefs remain same-origin. Destructive operations must target a verified
  `VEVENT` and preserve concurrency preconditions.
- Logs, traces, metrics, and errors never contain raw tokens, authorization
  codes, event content, or clear user/resource identifiers.
- Production service URLs use HTTPS; cleartext is limited to loopback
  development.

## Reportable Findings and Severity Context

Report authentication or authorization bypass, cross-user session or calendar
access, bearer/code leakage, redirect or SSRF flaws, destructive action against
the wrong DAV resource, unbounded unauthenticated resource consumption,
request-smuggling or parsing differentials, and supply-chain compromise.

Severity depends on internet reachability, authentication requirements,
cross-user impact, data exposure or mutation, and whether default deployments
are affected. A practical unauthenticated availability attack or authenticated
cross-user access is reportable even without code execution.

## Out of Scope

The following are not vulnerabilities in this repository unless its code or
examples create or worsen the condition:

- General vulnerabilities in Stalwart, an OIDC provider, reverse proxy,
  orchestrator, or MCP client; report those upstream.
- An operator deliberately disabling TLS, exposing the private metrics port, or
  configuring an attacker-controlled issuer/DAV origin contrary to the
  documentation.
- Denial of service requiring control of the host, cluster, IdP, or Stalwart.
- Calendar spam or unwanted actions performed with the reporting user's own
  valid bearer and permissions.

No finding class is excluded merely because deployment configuration can
mitigate it.

## Known Limitations and Accepted Risk

Positive JWT validation may remain cached for up to 60 seconds after revocation.
Sessions are process-local and are lost on restart. `/health` reports process
health rather than IdP or DAV availability. These behaviors are documented and
are not findings by themselves, but bypassing their stated bounds or isolation
is reportable.

Deployment-specific IdP claims, Stalwart identity mapping, proxy trust, log
retention, network policy, and secret management must be assessed by each
operator.
