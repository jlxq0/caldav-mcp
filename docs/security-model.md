# Security model

## Trust boundaries

The internet-facing boundary is the Axum HTTP service. OAuth parameters,
headers, JWTs, MCP JSON-RPC bodies, session ids, tool arguments, DAV XML and
iCalendar data are untrusted. The configured OIDC issuer and Stalwart DAV
origin are operator trust anchors.

The server validates a bearer locally, binds each durable MCP session to the
verified subject that created it, applies per-identity rate limits, and then
forwards the same bearer to Stalwart. Stalwart remains the authority for which
calendars that identity may access.

## Security properties

- Basic credentials and app passwords are never accepted or stored.
- Raw bearer tokens are never logged and are never used as plaintext cache
  keys.
- JWT issuer, audience, expiry, signature algorithm and JWKS key are checked.
- Unknown JWKS keys cannot amplify refresh traffic without a global cooldown.
- OAuth redirect URIs are an exact startup-validated allowlist.
- In-memory authentication, OAuth, session and rate-limit state has hard caps.
- MCP request bodies are capped before rmcp buffers them.
- DAV hrefs must remain on the configured origin.
- Destructive event operations verify the target is a `VEVENT` and use ETag
  concurrency controls.
- Metrics use bounded labels; shared logs use pseudonymous identifiers and do
  not include event content.

## Operational assumptions

- TLS is terminated by a correctly configured trusted proxy.
- The operator protects IdP configuration and any optional introspection
  secret.
- Stalwart validates the same bearer and maps its identity claim correctly.
- Metrics and OTLP collectors are private infrastructure.
- A single process stores sessions in memory; restarting it requires clients
  to initialize a new session.

## Deliberate limitations

JWT validation caches positive results for at most 60 seconds, so revocation
may take up to that long to propagate without a process restart. `/health`
reports process health, not upstream dependency health. The server does not
provide calendar encryption, backup, IdP account recovery or Stalwart tenant
administration.

Deployment-specific reverse proxies, IdP policy, Stalwart configuration and
network controls are outside this repository, but mistakes at those boundaries
can invalidate the intended security model.
