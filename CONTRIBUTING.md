# Contributing

Contributions are welcome through either the
[GitHub mirror](https://github.com/jlxq0/caldav-mcp) or the canonical
[Forgejo repository](https://forge.oddie.app/jlxq0/caldav-mcp).

## Development

Use Rust 1.93 or later. Keep the server self-contained and retain the existing
streamable-HTTP, OAuth/JWT pass-through and Stalwart CalDAV architecture. Do
not add Basic credentials, app-password storage, another backend language or a
wrapper around a third-party CalDAV MCP server.

Before submitting a change:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo audit
cargo deny check bans licenses sources
```

Add regression tests for bug fixes. Keep environment-specific values in
configuration and never commit tokens, real calendar data or external email
addresses. Commits use `type(scope): description`.

## Pull requests

Explain the user-visible behavior, security impact and verification performed.
Changes to OAuth, JWT validation, session ownership, DAV href handling,
destructive tools, logging or dependency policy should describe the relevant
trust boundary explicitly.

Report vulnerabilities privately according to `SECURITY.md`.
