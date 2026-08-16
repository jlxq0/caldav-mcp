# caldav-mcp

Rust streamable-HTTP MCP server for per-user calendars on Stalwart CalDAV.
It validates inbound Logto JWTs, then forwards the same bearer verbatim to
Stalwart. It never accepts or stores Basic credentials or app passwords.

## Tools

- whoami
- list_calendars
- list_events
- search_events
- create_event
- update_event
- delete_event
- free_busy

Offset-free date-times use Asia/Singapore. RFC 3339 offsets are preserved as
instants and rendered as UTC. All-day end dates are exclusive.

## Required environment

    CALDAV_MCP_RESOURCE_URL=https://caldav-mcp.kampong.social
    CALDAV_MCP_AUTHORIZATION_SERVER=https://login.kampong.social/oidc
    CALDAV_MCP_STALWART_DAV_BASE_URL=https://dav.kampong.social
    CALDAV_MCP_DCR_CLIENT_ID=uw7dfhsvg6wq0p0eavk2i
    CALDAV_MCP_OAUTH_REDIRECT_URIS=https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback,https://www.cursor.com/agents/mcp/oauth/callback,cursor://anysphere.cursor-mcp/oauth/callback,grokbot://mcp/oauth/callback,http://localhost:8787/callback

The public MCP endpoint is https://caldav-mcp.kampong.social/mcp.

## Development

    cargo fmt --all --check
    cargo clippy --all-targets --all-features --locked -- -D warnings
    cargo test --all-features --locked
