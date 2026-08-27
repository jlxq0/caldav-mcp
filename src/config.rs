//! Process-level configuration.
//!
//! Config construction is split into a pure constructor (`Config::new`)
//! and an env-var wrapper (`Config::from_env`). Tests build Config directly
//! and never touch process-global env state — Rust 2024 makes `set_var`
//! unsafe (correctly: it's racy under multi-threaded test harnesses), and
//! we forbid `unsafe_code` at the crate root, so this split is the clean
//! way to keep both invariants.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use url::Url;

use crate::oauth_redirect;

/// Public URL of this MCP server, used as the OAuth `resource` identifier
/// (RFC 8707) and as the `resource` field in the protected-resource metadata
/// document (RFC 9728). Also the audience caldav-mcp requires on inbound
/// Logto access tokens.
const ENV_RESOURCE_URL: &str = "CALDAV_MCP_RESOURCE_URL";
/// Issuer URL of the authorization server (Logto) that mints tokens for this
/// resource, e.g. `https://login.kampong.social/oidc`.
const ENV_AUTH_SERVER_URL: &str = "CALDAV_MCP_AUTHORIZATION_SERVER";
/// Base URL of Stalwart's `CalDAV` service, e.g. `https://dav.kampong.social`.
const ENV_STALWART_DAV_BASE_URL: &str = "CALDAV_MCP_STALWART_DAV_BASE_URL";
/// Bind address, defaults to `0.0.0.0:3000` for container deployment.
const ENV_BIND_ADDR: &str = "CALDAV_MCP_BIND_ADDR";
/// Separate bind for the cluster-internal `/metrics` endpoint. Never binds
/// `0.0.0.0` unless an operator explicitly sets this var. See
/// [`resolve_metrics_bind_addr`].
const ENV_METRICS_BIND_ADDR: &str = "CALDAV_MCP_METRICS_BIND_ADDR";
/// Kubernetes downward-API pod IP. Injected via `fieldRef: status.podIP`.
/// Used to derive the metrics bind address.
const ENV_POD_IP: &str = "POD_IP";
/// Optional OAuth client id, only used for the opaque-token introspection
/// fallback path (when Logto is configured to issue non-JWT access tokens).
const ENV_INTROSPECTION_CLIENT_ID: &str = "CALDAV_MCP_LOGTO_CLIENT_ID";
/// Optional client secret paired with the id above.
const ENV_INTROSPECTION_CLIENT_SECRET: &str = "CALDAV_MCP_LOGTO_CLIENT_SECRET";

/// Pre-provisioned Logto `client_id` handed back by the RFC 7591 dynamic client
/// registration shim. Logto has no DCR endpoint, so claude.ai (which only
/// onboards via DCR) gets this static public-SPA client. When unset, the
/// `/register` endpoint and `registration_endpoint` advertisement are disabled.
const ENV_DCR_CLIENT_ID: &str = "CALDAV_MCP_DCR_CLIENT_ID";
/// Per-identity read quota (per minute).
const ENV_RATE_LIMIT_READS: &str = "CALDAV_MCP_RATE_LIMIT_READS_PER_MIN";
/// Per-identity write quota (per minute).
const ENV_RATE_LIMIT_WRITES: &str = "CALDAV_MCP_RATE_LIMIT_WRITES_PER_MIN";
/// Number of trusted proxies in front of caldav-mcp. Default 1 (Traefik).
/// Fresh MCP sessions one identity may open back to back.
const ENV_INITIALIZE_BURST: &str = "CALDAV_MCP_INITIALIZE_BURST";
/// Seconds between refilled `initialize` slots once the burst is spent.
const ENV_INITIALIZE_REFILL_SECONDS: &str = "CALDAV_MCP_INITIALIZE_REFILL_SECONDS";
const ENV_TRUSTED_PROXY_HOPS: &str = "CALDAV_MCP_TRUSTED_PROXY_HOPS";
/// Optional IP to connect to when reaching the Stalwart host, overriding DNS.
/// Used in-cluster to avoid hairpin NAT on the public `LoadBalancer`: we keep
/// `Host` = the public hostname (so TLS + `CalDAV` service URLs stay valid) but
/// dial the in-cluster Service `ClusterIP` on port 443.
const ENV_STALWART_CONNECT_IP: &str = "CALDAV_MCP_STALWART_CONNECT_IP";
/// JWT `aud` Stalwart's OIDC directory requires (`requireAudience`).
/// Must match the Logto API resource indicator accepted by Stalwart.
const ENV_STALWART_AUDIENCE: &str = "CALDAV_MCP_STALWART_AUDIENCE";

const DEFAULT_RATE_LIMIT_READS: u32 = 60;
const DEFAULT_RATE_LIMIT_WRITES: u32 = 30;
/// Proxies that append to `X-Forwarded-For` between a client and this pod.
///
/// **Two, and the topology is the reason rather than a product name.** The path
/// is client → Caddy edge → Cilium gateway → pod: the edge configures no
/// `trusted_proxies`, so it *replaces* the header with its peer (entry one, the
/// client), and Cilium runs `gateway-api-xff-num-trusted-hops: 0`, so Envoy
/// *appends* the downstream address (entry two, the edge). A constant encoding
/// another system's behaviour is worthless without that system named beside
/// it — a sibling service carried `Default 1 (Traefik)` and there is no Traefik
/// on this cluster at all.
///
/// Measured at the pod on 2026-08-27: 109 authenticated requests over eleven
/// hours, `xff_entries=2` on every one, and derived independently from
/// `oddie-apps/edge-config` rather than from the same instrument.
///
/// **A deployment not behind that edge must override this.** The `home`
/// gateway is LAN-only with no edge in front, so a backend there sees one
/// entry, and a service moving between the two changes its own correct value
/// with nothing reporting it.
///
/// Being wrong is asymmetric and this errs the recoverable way: `parse_client_ip`
/// returns `None` when the chain is shorter than the hop count, so 2 against a
/// one-entry chain blanks the field. Too low does not blank it: it selects a
/// proxy and records a well-formed address identifying the wrong party.
///
/// **The value holds only while the edge replaces `X-Forwarded-For` rather than
/// appending to it.** That is a property of `oddie-apps/edge-config`, not of
/// this code, so this number and the edge's `trusted_proxies` setting have to
/// be re-derived together. Reverse pointer: `oddie-apps/edge-config#39`.
///
/// **Residual, and the 109-request measurement could not see it.** A caller
/// that reaches the Cilium gateway directly, bypassing the edge, supplies its
/// own header; Envoy appends the caller's address, so the chain is two long,
/// `len < hops` never fires, and two hops selects the string the caller wrote.
/// **No single hop count is correct for both paths**: the edge path wants 2 and
/// the direct path wants 1, so choosing either forges one of them. The
/// mitigation is that only one path is supposed to exist, which is a fact about
/// the cluster that nothing here can assert. The yield is a forged address in a
/// provenance record rather than access, and it needs a stolen bearer first,
/// but a confident wrong value reads as settled where a blank reads as unknown.
/// Applies identically to `carddav-mcp`, `jmap-mcp` and `webmail`, because the
/// residual is in the topology rather than in any implementation.
const DEFAULT_TRUSTED_PROXY_HOPS: usize = 2;
/// Fallback Logto RFC 8707 resource / Stalwart `requireAudience` when
/// `CALDAV_MCP_STALWART_AUDIENCE` is unset: the MCP origin (`resource_url`).
/// Must be an absolute http(s) URI — never the bare string `stalwart`.

#[derive(Debug, Clone)]
pub struct Config {
    /// Our own public URL (e.g. `https://caldav-mcp.kampong.social`). Never
    /// trailing-slashed — RFC 8707 resource indicators are compared as
    /// strings.
    pub resource_url: String,
    /// Authorization server (Logto OIDC issuer). No trailing slash.
    pub authorization_server: String,
    /// Stalwart base URL for `CalDAV` service discovery. No trailing slash.
    pub stalwart_dav_base_url: String,
    /// TCP bind address for the public API (rmcp + health + .well-known).
    pub bind_addr: SocketAddr,
    /// TCP bind for the cluster-internal metrics endpoint.
    pub metrics_bind_addr: SocketAddr,
    /// Optional introspection credentials — only for the opaque-token
    /// fallback. The default JWKS path needs none.
    pub introspection: Option<IntrospectionCredentials>,
    /// Per-minute read quota. 0 is rejected at parse time.
    pub rate_limit_reads_per_min: u32,
    /// Per-minute write quota. 0 is rejected at parse time.
    pub rate_limit_writes_per_min: u32,
    /// Number of trusted proxies in front of caldav-mcp (X-Forwarded-For).
    pub trusted_proxy_hops: usize,
    /// Optional IP to dial for the Stalwart host (DNS override). `None` = use
    /// normal DNS resolution.
    pub stalwart_connect_ip: Option<String>,
    /// Optional static Logto `client_id` returned by the DCR shim (`/register`).
    /// `None` disables dynamic client registration advertisement.
    pub dcr_client_id: Option<String>,
    /// Exact OAuth redirect URIs accepted by the proxy and DCR shim.
    pub oauth_redirect_uris: Vec<String>,
    /// Fresh MCP sessions one identity may open back to back.
    pub initialize_burst: u32,
    /// Interval at which one `initialize` slot refills once the burst is
    /// spent. One slot at a time, never the whole burst at once — the
    /// `Retry-After` we return is derived from the bucket rather than from
    /// this value, because the two agree only until the quota changes.
    pub initialize_refill: Duration,
    /// Absolute-URI JWT audience Stalwart's OIDC directory requires.
    /// The OAuth proxy sends this as the RFC 8707 `resource` to Logto
    /// (Logto rejects non-URI indicators with `invalid_target`). Default
    /// is `resource_url` (the origin). Never `stalwart`.
    pub stalwart_audience: String,
}

#[derive(Clone)]
#[allow(dead_code)] // `client_secret` is a reserved fallback field.
pub struct IntrospectionCredentials {
    pub client_id: String,
    pub client_secret: String,
}

impl std::fmt::Debug for IntrospectionCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntrospectionCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

impl Config {
    /// Pure constructor. Validates URLs are absolute http(s) and strips
    /// trailing slashes. Used directly by tests; `from_env` wraps it.
    pub fn new(
        resource_url: impl Into<String>,
        authorization_server: impl Into<String>,
        stalwart_dav_base_url: impl Into<String>,
        bind_addr: SocketAddr,
    ) -> Result<Self> {
        let resource_url = strip_trailing_slash(resource_url.into());
        let authorization_server = strip_trailing_slash(authorization_server.into());
        let stalwart_dav_base_url = strip_trailing_slash(stalwart_dav_base_url.into());
        validate_url(&resource_url, ENV_RESOURCE_URL)?;
        validate_url(&authorization_server, ENV_AUTH_SERVER_URL)?;
        validate_url(&stalwart_dav_base_url, ENV_STALWART_DAV_BASE_URL)?;
        Ok(Self {
            resource_url: resource_url.clone(),
            authorization_server,
            stalwart_dav_base_url,
            bind_addr,
            metrics_bind_addr: SocketAddr::from(([127, 0, 0, 1], 9090)),
            introspection: None,
            rate_limit_reads_per_min: DEFAULT_RATE_LIMIT_READS,
            rate_limit_writes_per_min: DEFAULT_RATE_LIMIT_WRITES,
            trusted_proxy_hops: DEFAULT_TRUSTED_PROXY_HOPS,
            stalwart_connect_ip: None,
            dcr_client_id: None,
            oauth_redirect_uris: Vec::new(),
            initialize_burst: DEFAULT_INITIALIZE_BURST,
            initialize_refill: DEFAULT_INITIALIZE_REFILL,
            stalwart_audience: resource_url,
        })
    }

    /// Builder-style: attach optional introspection credentials.
    #[must_use]
    pub fn with_introspection(mut self, creds: IntrospectionCredentials) -> Self {
        self.introspection = Some(creds);
        self
    }

    /// Audiences we accept on inbound Logto access tokens: the origin
    /// (`CALDAV_MCP_RESOURCE_URL`), `{origin}/mcp` (RFC 9728 resource some
    /// clients put in `aud`), and `stalwart_audience` (the absolute URI
    /// sent to Logto / required by Stalwart).
    pub fn accepted_token_audiences(&self) -> Vec<String> {
        let mut v = vec![
            self.resource_url.clone(),
            crate::oauth_metadata::mcp_resource(&self.resource_url),
            self.stalwart_audience.clone(),
        ];
        v.sort();
        v.dedup();
        v
    }

    /// Load from environment variables. Missing required vars are fatal at
    /// startup — we refuse to boot rather than silently fall back to a
    /// development default in production.
    pub fn from_env() -> Result<Self> {
        let resource_url = require_env(ENV_RESOURCE_URL)?;
        let authorization_server = require_env(ENV_AUTH_SERVER_URL)?;
        let stalwart_dav_base_url = require_env(ENV_STALWART_DAV_BASE_URL)?;
        let bind_addr_str = std::env::var(ENV_BIND_ADDR).unwrap_or_else(|_| "0.0.0.0:3000".into());
        let bind_addr = SocketAddr::from_str(&bind_addr_str)
            .with_context(|| format!("invalid {ENV_BIND_ADDR}: {bind_addr_str}"))?;
        let explicit_addr = std::env::var(ENV_METRICS_BIND_ADDR).ok();
        let pod_ip = std::env::var(ENV_POD_IP).ok();
        let metrics_bind_addr =
            resolve_metrics_bind_addr(explicit_addr.as_deref(), pod_ip.as_deref())?;

        let mut cfg = Self::new(
            resource_url,
            authorization_server,
            stalwart_dav_base_url,
            bind_addr,
        )?;
        cfg.metrics_bind_addr = metrics_bind_addr;
        cfg.rate_limit_reads_per_min =
            parse_rate_limit(ENV_RATE_LIMIT_READS, DEFAULT_RATE_LIMIT_READS)?;
        cfg.rate_limit_writes_per_min =
            parse_rate_limit(ENV_RATE_LIMIT_WRITES, DEFAULT_RATE_LIMIT_WRITES)?;
        cfg.trusted_proxy_hops = parse_trusted_proxy_hops()?;
        cfg.stalwart_connect_ip = std::env::var(ENV_STALWART_CONNECT_IP)
            .ok()
            .filter(|s| !s.trim().is_empty());
        cfg.dcr_client_id = std::env::var(ENV_DCR_CLIENT_ID)
            .ok()
            .filter(|s| !s.trim().is_empty());
        cfg.oauth_redirect_uris = parse_redirect_uris_env()?;
        cfg.initialize_burst = parse_initialize_burst()?;
        cfg.initialize_refill = parse_initialize_refill()?;
        cfg.stalwart_audience = match std::env::var(ENV_STALWART_AUDIENCE)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
        {
            Some(raw) => {
                // RFC 8707: Logto rejects a non-URI resource with invalid_target.
                // The previous default `stalwart` is the Logto API *name*, not
                // an indicator — never send it.
                if raw == "stalwart" || !is_absolute_http_uri(&raw) {
                    anyhow::bail!(
                        "{ENV_STALWART_AUDIENCE} must be an absolute http(s) URI (RFC 8707 resource indicator); got {raw:?}. Do not use the bare string \"stalwart\"."
                    );
                }
                strip_trailing_slash(raw)
            }
            None => cfg.resource_url.clone(),
        };

        // Optional opaque-token introspection fallback credentials.
        if let (Ok(client_id), Ok(client_secret)) = (
            std::env::var(ENV_INTROSPECTION_CLIENT_ID),
            std::env::var(ENV_INTROSPECTION_CLIENT_SECRET),
        ) {
            cfg = cfg.with_introspection(IntrospectionCredentials {
                client_id,
                client_secret,
            });
        }
        Ok(cfg)
    }
}

/// Resolve the metrics listener bind address. Priority: explicit env →
/// `{POD_IP}:9090` → `127.0.0.1:9090`. Never returns `0.0.0.0` by default.
fn resolve_metrics_bind_addr(
    explicit_addr: Option<&str>,
    pod_ip: Option<&str>,
) -> Result<SocketAddr> {
    let addr_str: String = explicit_addr.map_or_else(
        || pod_ip.map_or_else(|| "127.0.0.1:9090".to_owned(), |ip| format!("{ip}:9090")),
        str::to_owned,
    );
    SocketAddr::from_str(&addr_str)
        .with_context(|| format!("invalid {ENV_METRICS_BIND_ADDR}: {addr_str}"))
}

fn require_env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("required env var {key} is not set"))
}

fn validate_url(url: &str, key: &str) -> Result<()> {
    parse_secure_http_url(url).with_context(|| {
        format!(
            "{key} must be an absolute HTTPS URL (HTTP is allowed only for loopback), got: {url}"
        )
    })?;
    Ok(())
}

/// RFC 8707 resource indicator: absolute http(s) URI. Rejects bare tokens
/// such as `stalwart` that Logto answers with `invalid_target`.
pub fn is_absolute_http_uri(url: &str) -> bool {
    parse_secure_http_url(url).is_ok()
}

fn parse_secure_http_url(value: &str) -> Result<Url> {
    let parsed = Url::parse(value).context("invalid URL")?;
    let host = parsed.host_str().context("URL has no host")?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        anyhow::bail!("cleartext HTTP is only allowed for loopback hosts");
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!("URL must not contain user info, a query, or a fragment");
    }
    Ok(parsed)
}

fn parse_rate_limit(key: &str, default: u32) -> Result<u32> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => {
            let v: u32 = raw
                .trim()
                .parse()
                .with_context(|| format!("{key} must be a positive integer, got: {raw}"))?;
            if v == 0 {
                anyhow::bail!("{key} must be > 0");
            }
            Ok(v)
        }
    }
}

fn parse_redirect_uris_env() -> Result<Vec<String>> {
    let raw = require_env(oauth_redirect::ENV_OAUTH_REDIRECT_URIS)?;
    oauth_redirect::parse_allowlist(&raw, oauth_redirect::ENV_OAUTH_REDIRECT_URIS)
}

/// Default `initialize` burst. Raised from 8 on 2026-08-26: eight was reached
/// by ordinary use, and the refusal was indistinguishable from a failure.
/// 24 covers the observed workload exactly. It is not 32 because that would
/// take the identities-needed-to-fill `session::MAX_SESSIONS` from 32 down to
/// 8, and moving the pool with it needs a per-session memory measurement that
/// is blocked on a credential.
pub const DEFAULT_INITIALIZE_BURST: u32 = 24;

/// Default refill: one slot per minute. **This is the change that matters.**
/// At the previous 30 minutes a user who waited out what they believed was the
/// window got exactly one session, reconnected twice and was refused again —
/// so a wrong model of the rule did not merely delay them, it guaranteed a
/// second failure. Four hours to recover from empty becomes 24 minutes.
pub const DEFAULT_INITIALIZE_REFILL: Duration = Duration::from_secs(60);

fn parse_initialize_burst() -> Result<u32> {
    std::env::var(ENV_INITIALIZE_BURST).map_or_else(
        |_| Ok(DEFAULT_INITIALIZE_BURST),
        |raw| {
            let value: u32 = raw.trim().parse().with_context(|| {
                format!("{ENV_INITIALIZE_BURST} must be a positive integer, got: {raw}")
            })?;
            if value == 0 {
                anyhow::bail!("{ENV_INITIALIZE_BURST} must be greater than zero");
            }
            Ok(value)
        },
    )
}

fn parse_initialize_refill() -> Result<Duration> {
    std::env::var(ENV_INITIALIZE_REFILL_SECONDS).map_or_else(
        |_| Ok(DEFAULT_INITIALIZE_REFILL),
        |raw| {
            let secs: u64 = raw.trim().parse().with_context(|| {
                format!("{ENV_INITIALIZE_REFILL_SECONDS} must be a positive integer number of seconds, got: {raw}")
            })?;
            if secs == 0 {
                anyhow::bail!("{ENV_INITIALIZE_REFILL_SECONDS} must be greater than zero");
            }
            Ok(Duration::from_secs(secs))
        },
    )
}

fn parse_trusted_proxy_hops() -> Result<usize> {
    std::env::var(ENV_TRUSTED_PROXY_HOPS).map_or_else(
        |_| Ok(DEFAULT_TRUSTED_PROXY_HOPS),
        |raw| {
            raw.trim().parse().with_context(|| {
                format!("{ENV_TRUSTED_PROXY_HOPS} must be a non-negative integer, got: {raw}")
            })
        },
    )
}

fn strip_trailing_slash(mut s: String) -> String {
    while s.ends_with('/') {
        s.pop();
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::new(
            "https://caldav-mcp.example.test/",
            "https://login.example.test/oidc",
            "https://mail.example.test",
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        )
        .unwrap()
    }

    #[test]
    fn strips_trailing_slash_on_resource_url() {
        assert_eq!(cfg().resource_url, "https://caldav-mcp.example.test");
    }

    #[test]
    fn rejects_non_http_url() {
        let err = Config::new(
            "caldav-mcp.example.test",
            "https://login.example.test",
            "https://mail.example.test",
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        );
        assert!(err.is_err());
    }

    #[test]
    fn accepted_audiences_include_origin_and_mcp_path() {
        let a = cfg().accepted_token_audiences();
        assert!(a.contains(&"https://caldav-mcp.example.test".to_owned()));
        assert!(a.contains(&"https://caldav-mcp.example.test/mcp".to_owned()));
        assert!(!a.iter().any(|x| x == "stalwart"));
        assert_eq!(cfg().stalwart_audience, "https://caldav-mcp.example.test");
    }

    #[test]
    fn rejects_bare_stalwart_as_rfc8707_resource() {
        assert!(!is_absolute_http_uri("stalwart"));
        assert!(!is_absolute_http_uri(""));
        assert!(!is_absolute_http_uri("caldav-mcp.kampong.social"));
        assert!(is_absolute_http_uri("https://caldav-mcp.kampong.social"));
        assert!(is_absolute_http_uri("https://dav.kampong.social"));
    }

    #[test]
    fn rejects_cleartext_remote_and_prefix_only_urls() {
        assert!(!is_absolute_http_uri("http://dav.example.test"));
        assert!(!is_absolute_http_uri("https://"));
        assert!(!is_absolute_http_uri("https://user@dav.example.test"));
        assert!(!is_absolute_http_uri("https://dav.example.test?secret=x"));
    }

    #[test]
    fn permits_cleartext_only_for_local_development() {
        assert!(is_absolute_http_uri("http://localhost:3000"));
        assert!(is_absolute_http_uri("http://127.0.0.1:3000"));
        assert!(is_absolute_http_uri("http://[::1]:3000"));
    }

    #[test]
    fn metrics_bind_prefers_explicit_then_pod_ip_then_localhost() {
        assert_eq!(
            resolve_metrics_bind_addr(Some("0.0.0.0:1234"), Some("10.0.0.5"))
                .unwrap()
                .to_string(),
            "0.0.0.0:1234"
        );
        assert_eq!(
            resolve_metrics_bind_addr(None, Some("10.0.0.5"))
                .unwrap()
                .to_string(),
            "10.0.0.5:9090"
        );
        assert_eq!(
            resolve_metrics_bind_addr(None, None).unwrap().to_string(),
            "127.0.0.1:9090"
        );
    }

    /// The default is the deployed topology: client, Caddy edge, Cilium
    /// gateway, pod. Two entries reach us, so two hops selects the one the
    /// edge wrote. At 1 the recorded client IP is the edge's, a well-formed
    /// address for the wrong party, which is worse than the blank field a
    /// wrong-but-too-high value produces.
    #[test]
    fn trusted_proxy_hops_defaults_to_the_deployed_chain_length() {
        assert_eq!(cfg().trusted_proxy_hops, 2);
    }

    /// The burst and refill are the numbers a user meets, so pin them rather
    /// than trusting that nobody edits a constant.
    #[test]
    fn initialize_quota_defaults_are_the_shipped_ones() {
        let c = cfg();
        assert_eq!(c.initialize_burst, 24);
        assert_eq!(c.initialize_refill, Duration::from_secs(60));
    }
}
