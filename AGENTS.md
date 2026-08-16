# caldav-mcp

Copy `/Users/jl/Code/jlxq0/jmap-mcp` (live v0.2.8) HTTP/OAuth/DCR/streamable-HTTP shell. Replace the JMAP client with CalDAV against Stalwart. Language is **Rust (axum + rmcp)**. Do not ship Node/Go. Do not invent a third auth story. Do not wrap PhilflowIO/dav-mcp or dominik1001/caldav-mcp.

## Fondue contract (corrected 2026-08-17 — do not use stale Comté notes)

- Kubeconfig `~/.kube/fondue-admin.yaml`, context **`admin@fondue`**. NOT default. NOT `kubectl --context comte` (that Nexo note is stale). Read-only kubectl for logs/status only.
- Not Helm. Copy jmap-mcp / typst-mcp: **Kustomize + Argo Application**, `project: fondue`.
- `clusters/fondue/apps/caldav-mcp.yaml` → path `clusters/fondue/caldav-mcp/`
- Per-app: namespace (PSA restricted) + deployment + service + HTTPRoute + ExternalSecret named `forge-secret` (same 1P item as jmap: `matrix-mcp-www` / `forge-dockerconfigjson`) + **no PVC** (stateless).
- Image: `forge.oddie.app/jlxq0/caldav-mcp:vX.Y.Z` digest-pinned, Forgejo Actions, distroless nonroot uid 65532. `imagePullSecrets: [forge-secret]`.
- HTTPRoute parent `gateway/web` sectionName `http`, host `caldav-mcp.kampong.social`.
- Edge Caddy in `oddie-apps/edge-config`: bind anycast `.8` / `::8` (**not** `::4`), `reverse_proxy [2001:df7:2b40:1::102]:80`, `flush_interval -1`. Clone the `jmap-mcp.kampong.social` block.
- DNS in `clusters/fondue/dns-primary/zones/kampong.social.zone`: A `203.24.209.8`, AAAA `2001:df7:2b40::8`.
- Cilium CNP like `network-policies/jmap-mcp.yaml` (ingress host/remote-node + gateway→3000 + monitoring→9090; egress kube-dns + world:443). Add to `network-policies/kustomization.yaml`.
- Probe `GET /health` :3000. Gate: `curl http://[::102]/health -H "Host: caldav-mcp.kampong.social"` → 200.
- Do not `kubectl apply` around Argo.

## Copy-from (read these, then implement here)

- Shell: `/Users/jl/Code/jlxq0/jmap-mcp/src/{main,config,auth,session,oauth_metadata,oauth_proxy,oauth_redirect,logto_oidc,token_introspect,url_safety,rate_limit}.rs`
- CI/image: `/Users/jl/Code/jlxq0/jmap-mcp/{Dockerfile,.forgejo/workflows/ci.yml,deny.toml,rustfmt.toml,Cargo.toml}`
- Deploy twin: `/Users/jl/Code/oddie-apps/platform/clusters/fondue/jmap-mcp/` + `apps/jmap-mcp.yaml` + `network-policies/jmap-mcp.yaml`
- Caddy twin: `jmap-mcp.kampong.social` block in `/Users/jl/Code/oddie-apps/edge-config/caddy/Caddyfile`
- DNS twin: `/Users/jl/Code/oddie-apps/platform/clusters/fondue/dns-primary/zones/kampong.social.zone`
- DAV protocol knowledge (Basic in ksc_web; MCP must NOT use that credential path): `/Users/jl/Code/oddie-apps/ksc_web/lib/ksc/groupware/caldav/client.ex`
- Backend host already live: `https://dav.kampong.social` → Stalwart `/dav`, `/.well-known/caldav`, `/principals`

## OAuth shell (copy jmap-mcp v0.2.8 — Logto, not Entra, not MAS)

- Public URL always `https://caldav-mcp.kampong.social/mcp`
- Streamable HTTP. `initialize` creates a durable session. First `whoami` must not 429/expire.
- RFC 9728 resource = `{origin}/mcp` = `https://caldav-mcp.kampong.social/mcp`. Metadata at `/.well-known/oauth-protected-resource/mcp`. Live jmap shape: `{"resource":"https://jmap-mcp.kampong.social/mcp","authorization_servers":["https://jmap-mcp.kampong.social"],...}`
- `RESOURCE_URL` env = origin **without** `/mcp` (`https://caldav-mcp.kampong.social`). JWT aud/issuer/callback MAY stay origin. Grok Bot adds `/mcp` — accept both in `accepted_token_audiences`.
- DCR `/register` must 201 for this exact four-URI set in one body: `cursor://anysphere.cursor-mcp/oauth/callback`, `grokbot://mcp/oauth/callback`, `http://localhost:8787/callback`, `https://www.cursor.com/agents/mcp/oauth/callback`. Also keep the claude.ai / claude.com callbacks jmap-mcp already allowlists.
- Custom schemes first-class. NEVER `allow_insecure_uris`. NEVER log tokens.
- Logto only: `https://login.kampong.social/oidc`. No Hanso Entra. No MAS.
- Per-user. No shared app-password / Julian password in MCP env.
- Backend creds = same as jmap-mcp: validate inbound Logto JWT (JWKS), forward that bearer verbatim to Stalwart. jmap uses `https://jmap.kampong.social`; you use `https://dav.kampong.social`. If DAV rejects Bearer, STOP and report — do not fall back to Basic/app-password in env.
- Reuse jmap-mcp DCR client id `uw7dfhsvg6wq0p0eavk2i` and the same `OAUTH_REDIRECT_URIS` list from `platform/.../jmap-mcp/deployment.yaml` unless Logto requires a distinct public SPA (then STOP and name the Julian click).
- Logto API resource / aud indicator should be `https://caldav-mcp.kampong.social` (origin). If creating it needs Logto admin UI, STOP and report that blocker.

## Scope

- `whoami`
- list calendars
- list/search events in a time window
- create / update / delete events
- free/busy
- Default timezone `Asia/Singapore`

Keep the HTTP/OAuth/session/Dockerfile/CI identical in shape; only the backend client + tool list change. Self-contained repo (no third shared-crate repo).

## Deploy path (PRs, not kubectl-apply)

1. Implement + tag `v0.1.0` so CI pushes `forge.oddie.app/jlxq0/caldav-mcp:v0.1.0` (same `.forgejo/workflows/ci.yml` pattern; `FORGE_PUSH_TOKEN` is already a CI secret on sibling MCP repos).
2. Platform PR on `oddie-apps/platform`: copy `clusters/fondue/jmap-mcp/` → `caldav-mcp/`, `apps/caldav-mcp.yaml` (`project: fondue`), Cilium netpol + `network-policies/kustomization.yaml` entry, DNS A/AAAA. Pin image by tag+digest like jmap. Env: `CALDAV_MCP_RESOURCE_URL=https://caldav-mcp.kampong.social`, `CALDAV_MCP_AUTHORIZATION_SERVER=https://login.kampong.social/oidc`, `CALDAV_MCP_STALWART_DAV_BASE_URL=https://dav.kampong.social`, same DCR client + redirect URI list. Namespace `caldav-mcp` PSA restricted.
3. edge-config PR: Caddy vhost `caldav-mcp.kampong.social` cloned from `jmap-mcp.kampong.social` (bind `.8`/`::8`).
4. Push this repo to `https://forge.oddie.app/jlxq0/caldav-mcp.git` (origin already set). GitHub is NOT a git remote on jmap-mcp — do not add one.
5. Do not `kubectl apply`. Do not type in tmux `j:12` / HA. Do not clone Medical Records. Do not put secrets in git.

## Done when

- `curl http://[::102]/health -H "Host: caldav-mcp.kampong.social"` → 200
- `curl -sS https://caldav-mcp.kampong.social/.well-known/oauth-protected-resource/mcp` shows `resource=https://caldav-mcp.kampong.social/mcp`
- DCR `/register` with the four Cursor/Grok URIs returns 201
- `whoami` works as Julian (Logto JWT pass-through)
- list calendars works
- Platform + edge-config PRs opened
- Print one line: `CALDAV_READY` plus image tag, PR URLs, and any Julian blocker (Logto API resource / DNS / 1Password)

## Known Pitfalls

- Forgejo Actions can fail during `Set up job` with no step logs when an immutable action commit is no longer advertised by the Forgejo action mirror. Verify every pinned revision with `git ls-remote https://forge.oddie.app/{owner}/{repo}.git` before release; update the pin to an advertised immutable commit rather than retrying the workflow unchanged.
- Forgejo Runner does not apply the `default: stable` input declared by `dtolnay/rust-toolchain` when expanding the composite action. Always pass `toolchain: stable` explicitly or the action exits with `'toolchain' is a required input`.

## Probed facts (2026-08-17, do not re-derive)

- Stalwart DAV accepts Logto Bearer. No Basic/app-password fallback.
- Stalwart `requireAudience` currently accepts **only** `https://jmap-mcp.kampong.social`. Tokens with aud=`https://caldav-mcp.kampong.social` or `stalwart` → 401.
- Set `CALDAV_MCP_STALWART_AUDIENCE=https://jmap-mcp.kampong.social` (same knob jmap-mcp already has). RFC 9728 metadata still advertises `resource=https://caldav-mcp.kampong.social/mcp`. `accepted_token_audiences` must cover caldav origin, `{origin}/mcp`, and the jmap indicator.
- Clean per-app audience needs a Stalwart OIDC directory change — Julian blocker, do not edit mail server config.
- Logto API resource `caldav-mcp` indicator `https://caldav-mcp.kampong.social` already exists (id `aqml8k6qsudh4i3lydrgj`).
- DCR client `uw7dfhsvg6wq0p0eavk2i` is missing `https://caldav-mcp.kampong.social/oauth/callback`. Claude pane j:18 will add it via Management API. Do not invent a second client.
- Platform + edge-config PRs go to **Forgejo** (`forge.oddie.app/oddie-apps/{platform,edge-config}`), not GitHub. `gh` is the wrong host.
- Kubeconfig `~/.kube/fondue-admin.yaml`, context `admin@fondue`. Read-only. No kubectl-apply.

## Logto live state (2026-08-17 06:55 SGT, Claude j:18)

- TEMP verification app deleted (impersonation secret dead).
- DCR client `uw7dfhsvg6wq0p0eavk2i` now includes `https://caldav-mcp.kampong.social/oauth/callback` and `https://carddav-mcp.kampong.social/oauth/callback` (plus the original claude/cursor URIs).
- API resources: caldav-mcp `https://caldav-mcp.kampong.social` (id `aqml8k6qsudh4i3lydrgj`); carddav-mcp `https://carddav-mcp.kampong.social` (id `8livigfvix0yygkbue79q`).
- Still set `*_STALWART_AUDIENCE=https://jmap-mcp.kampong.social` until Stalwart OIDC audience is extended. Do not create another DCR client.
