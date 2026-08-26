//! Shared redirect URI validation for the OAuth proxy and DCR shim.

use anyhow::{Context, Result};
use url::Url;

/// Comma-separated redirect URI allowlist for proxied OAuth clients. Entries
/// match exactly, except that a loopback `http` entry matches any port
/// (RFC 8252 §7.3).
pub const ENV_OAUTH_REDIRECT_URIS: &str = "CALDAV_MCP_OAUTH_REDIRECT_URIS";

pub fn parse_allowlist(raw: &str, key: &str) -> Result<Vec<String>> {
    let mut uris = Vec::new();
    for uri in raw.split(',').map(str::trim).filter(|uri| !uri.is_empty()) {
        validate_redirect_uri(uri, key)?;
        if !uris.iter().any(|allowed| allowed == uri) {
            uris.push(uri.to_owned());
        }
    }
    if uris.is_empty() {
        anyhow::bail!("{key} must contain at least one redirect URI");
    }
    Ok(uris)
}

pub fn is_allowed_redirect_uri(allowed: &[String], uri: &str) -> bool {
    if validate_redirect_uri(uri, "redirect_uri").is_err() {
        return false;
    }
    allowed
        .iter()
        .any(|entry| entry == uri || loopback_matches_ignoring_port(entry, uri))
}

/// RFC 8252 §7.3: for a loopback redirect the authorization server MUST allow
/// any port at request time, because a native client binds an ephemeral one.
/// The relaxation covers the port and nothing else — scheme, host, path and
/// query must still match the allowlist entry exactly, and it applies only to
/// cleartext loopback entries. An `https` or private-use entry keeps full
/// string equality, where the port is a meaningful part of the callback.
fn loopback_matches_ignoring_port(entry: &str, uri: &str) -> bool {
    let (Ok(entry), Ok(uri)) = (Url::parse(entry), Url::parse(uri)) else {
        return false;
    };
    if entry.scheme() != "http" || uri.scheme() != "http" {
        return false;
    }
    let (Some(entry_host), Some(uri_host)) = (entry.host_str(), uri.host_str()) else {
        return false;
    };
    is_loopback_host(entry_host)
        && entry_host == uri_host
        && entry.path() == uri.path()
        && entry.query() == uri.query()
}

/// Loopback hosts accepted for cleartext `http://` redirect URIs
/// (RFC 8252 §7.3). Anything else over `http` would put the authorization
/// code on the wire in cleartext.
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

fn validate_redirect_uri(uri: &str, key: &str) -> Result<()> {
    if uri.trim() != uri || uri.is_empty() {
        anyhow::bail!(
            "{key} entries must be non-empty absolute URLs without surrounding whitespace"
        );
    }
    let url = Url::parse(uri).with_context(|| format!("invalid {key} redirect URI: {uri}"))?;
    match url.scheme() {
        "https" => {
            if url.host_str().is_none() {
                anyhow::bail!("{key} https entries must include a host: {uri}");
            }
        }
        // RFC 8252 §7.3 loopback interface redirection. Native apps bind an
        // ephemeral local port, so this is the one case where cleartext is
        // acceptable — but only on a loopback host.
        "http" => {
            let host = url.host_str().unwrap_or_default();
            if !is_loopback_host(host) {
                anyhow::bail!(
                    "{key} http entries are only allowed on loopback hosts \
                     (localhost, 127.0.0.1, [::1]): {uri}"
                );
            }
        }
        // RFC 8252 §7.1 private-use ("custom") URI schemes, e.g.
        // `cursor://…` / `grokbot://…` used by native MCP clients. The exact
        // string allowlist in `is_allowed_redirect_uri` is the actual control
        // — an operator must list the URI explicitly — so this arm only
        // rejects structurally broken input.
        scheme => {
            if scheme.is_empty() {
                anyhow::bail!("{key} entries must have a scheme: {uri}");
            }
        }
    }
    if url.fragment().is_some() {
        anyhow::bail!("{key} entries must not contain URI fragments: {uri}");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("{key} entries must not contain user info: {uri}");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_matches_exact_redirect_uri_only() {
        let allowed = parse_allowlist("https://claude.ai/api/mcp/auth_callback", "TEST").unwrap();

        assert!(is_allowed_redirect_uri(
            &allowed,
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://claude.ai/api/mcp/auth_callback/"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://attacker.example/callback"
        ));
    }

    #[test]
    fn allowlist_rejects_fragments_and_userinfo() {
        assert!(parse_allowlist("https://claude.ai/cb#frag", "TEST").is_err());
        assert!(parse_allowlist("https://user@claude.ai/cb", "TEST").is_err());
        assert!(parse_allowlist("", "TEST").is_err());
        assert!(parse_allowlist(" , ", "TEST").is_err());
    }

    /// RFC 8252 §7.1 — native MCP clients (Cursor / Grok Bot desktop) register
    /// private-use scheme callbacks. They must survive `parse_allowlist` (which
    /// runs at startup over the env var) and then match exactly.
    #[test]
    fn allowlist_accepts_private_use_schemes() {
        let allowed = parse_allowlist(
            "cursor://anysphere.cursor-mcp/oauth/callback,grokbot://mcp/oauth/callback",
            "TEST",
        )
        .unwrap();

        assert!(is_allowed_redirect_uri(
            &allowed,
            "cursor://anysphere.cursor-mcp/oauth/callback"
        ));
        assert!(is_allowed_redirect_uri(
            &allowed,
            "grokbot://mcp/oauth/callback"
        ));
        // Still exact-match: a different private-use URI is not smuggled in.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "cursor://anysphere.cursor-mcp/oauth/callback/extra"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "evil://mcp/oauth/callback"
        ));
    }

    /// RFC 8252 §7.3 — loopback HTTP is allowed; any other cleartext host is
    /// not. This is a tightening: `http://` on an arbitrary host used to pass.
    #[test]
    fn http_is_loopback_only() {
        for uri in [
            "http://localhost:8787/callback",
            "http://127.0.0.1:8787/callback",
        ] {
            assert!(parse_allowlist(uri, "TEST").is_ok(), "should accept {uri}");
        }
        for uri in [
            "http://evil.example/callback",
            "http://localhost.evil.example/callback",
        ] {
            assert!(parse_allowlist(uri, "TEST").is_err(), "should reject {uri}");
        }
    }

    /// RFC 8252 §7.3 — a native client binds an ephemeral loopback port, so an
    /// allowlisted loopback entry must match whatever port the request carries.
    /// Everything else about the URI still has to match.
    #[test]
    fn loopback_entry_matches_any_port() {
        let allowed = parse_allowlist("http://localhost:8787/callback", "TEST").unwrap();

        assert!(is_allowed_redirect_uri(
            &allowed,
            "http://localhost:3118/callback"
        ));
        assert!(is_allowed_redirect_uri(
            &allowed,
            "http://localhost:8787/callback"
        ));
        assert!(is_allowed_redirect_uri(
            &allowed,
            "http://localhost/callback"
        ));
        // Path still matters.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://localhost:3118/other"
        ));
        // Host still matters: the port is relaxed, the host is not.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://127.0.0.1:3118/callback"
        ));
        // Query still matters.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://localhost:3118/callback?next=https://evil.example"
        ));
    }

    /// The port relaxation is loopback-`http`-only. Loosening it on an `https`
    /// or private-use entry would let a different origin through.
    #[test]
    fn non_loopback_entries_keep_exact_port_matching() {
        let allowed = parse_allowlist(
            "https://claude.ai/api/mcp/auth_callback,cursor://anysphere.cursor-mcp/oauth/callback",
            "TEST",
        )
        .unwrap();

        assert!(is_allowed_redirect_uri(
            &allowed,
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://claude.ai:8443/api/mcp/auth_callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://claude.ai/api/mcp/auth_callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "cursor://anysphere.cursor-mcp:8443/oauth/callback"
        ));
    }

    /// The relaxation reads the *requested* URI's scheme as well as the
    /// entry's. Checking only the entry would let `https://localhost:3118/…`
    /// match an `http://localhost:8787/…` entry — a different origin, and one
    /// no client of ours ever asks for.
    #[test]
    fn loopback_entry_does_not_match_a_different_requested_scheme() {
        let allowed = parse_allowlist("http://localhost:8787/callback", "TEST").unwrap();

        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://localhost:3118/callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://localhost:8787/callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "cursor://localhost/callback"
        ));

        // And the other direction: an `https` loopback entry must not be
        // downgraded to cleartext by a port-relaxed match.
        let tls_loopback = parse_allowlist("https://localhost:8443/callback", "TEST").unwrap();
        assert!(!is_allowed_redirect_uri(
            &tls_loopback,
            "http://localhost:3118/callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &tls_loopback,
            "https://localhost:3118/callback"
        ));
    }

    /// A loopback entry must not become a wildcard for other loopback spellings
    /// or for cleartext hosts that merely look local.
    #[test]
    fn loopback_relaxation_does_not_widen_hosts() {
        let allowed = parse_allowlist("http://127.0.0.1:8787/callback", "TEST").unwrap();

        assert!(is_allowed_redirect_uri(
            &allowed,
            "http://127.0.0.1:49152/callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://localhost:49152/callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://127.0.0.2:49152/callback"
        ));
        // Rejected before matching: cleartext on a non-loopback host never
        // passes `validate_redirect_uri`.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://127.0.0.1.evil.example:8787/callback"
        ));
    }

    /// A hand-copied snapshot of the allowlist the deployment was running on
    /// 2026-08-26, read off the running pod's container env rather than off a
    /// manifest or a chart:
    ///
    /// ```text
    /// kubectl -n caldav-mcp get pod -o jsonpath=\
    ///   '{range .items[*].spec.containers[?(@.name=="app")].env[*]}{.name}={.value}{"\n"}{end}' \
    ///   | grep REDIRECT
    /// ```
    ///
    /// **This test cannot detect drift, and must not be read as if it could.**
    /// `raw` is a literal, so the deployment is not an input and no change to
    /// it can turn this red. What the test pins is matcher *behaviour* against
    /// a shape production really had; the date says how old that claim is, and
    /// the command above is how to renew it.
    ///
    /// It replaces a test named `deployed_allowlist_parses` that asserted only
    /// `allowed.len() == 9` under the doc comment "the exact set the deployment
    /// ships". `typst-mcp` carried the identical test with nine entries against
    /// a live seven and stayed green the whole time. That is the failure being
    /// named here, not a bug that was fixed.
    #[test]
    fn production_allowlist_snapshot_behaves() {
        let raw = "https://claude.ai/api/mcp/auth_callback,\
                   https://claude.com/api/mcp/auth_callback,\
                   https://www.cursor.com/agents/mcp/oauth/callback,\
                   cursor://anysphere.cursor-mcp/oauth/callback,\
                   grokbot://mcp/oauth/callback,\
                   http://localhost:8787/callback,\
                   claude://claude.ai/oauth/callback,\
                   claude://oauth/callback,\
                   cowork://oauth/callback";
        let allowed = parse_allowlist(raw, ENV_OAUTH_REDIRECT_URIS).unwrap();
        assert_eq!(allowed.len(), 9);

        // Every entry the deployment carries is accepted as written. Asserting
        // this per entry rather than by count is what makes a substitution in
        // the snapshot fail the test; a count cannot see one.
        for uri in [
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
            "https://www.cursor.com/agents/mcp/oauth/callback",
            "cursor://anysphere.cursor-mcp/oauth/callback",
            "grokbot://mcp/oauth/callback",
            "http://localhost:8787/callback",
            "claude://claude.ai/oauth/callback",
            "claude://oauth/callback",
            "cowork://oauth/callback",
        ] {
            assert!(
                is_allowed_redirect_uri(&allowed, uri),
                "should accept {uri}"
            );
        }

        // The one deployed loopback entry is the one a CLI client uses, and it
        // must take whatever ephemeral port that client bound.
        assert!(is_allowed_redirect_uri(
            &allowed,
            "http://localhost:49152/callback"
        ));
        // The port relaxation stops at the port: not the path, and not the
        // scheme.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://localhost:49152/oauth/callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://localhost:49152/callback"
        ));
        // Nothing non-loopback in the deployed set gets a port relaxed.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://claude.ai:8443/api/mcp/auth_callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "cowork://oauth:8443/callback"
        ));
        // And the set is still an allowlist.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://attacker.example/callback"
        ));
    }

    /// Shapes the allowlist must keep parsing and matching, whether or not the
    /// deployment currently lists them: `https`, cleartext loopback, and the
    /// private-use schemes native MCP clients register. Makes no claim about
    /// production — see `production_allowlist_snapshot_behaves` for the
    /// snapshot, and note that it cannot detect drift either.
    #[test]
    fn allowlist_accepts_the_shapes_we_support() {
        let raw = "https://claude.ai/api/mcp/auth_callback,\
                   http://127.0.0.1:8787/callback,\
                   claude://oauth/callback";
        let allowed = parse_allowlist(raw, ENV_OAUTH_REDIRECT_URIS).unwrap();
        assert_eq!(allowed.len(), 3);

        assert!(is_allowed_redirect_uri(
            &allowed,
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(is_allowed_redirect_uri(
            &allowed,
            "http://127.0.0.1:49152/callback"
        ));
        assert!(is_allowed_redirect_uri(&allowed, "claude://oauth/callback"));

        // Duplicates collapse and surrounding whitespace is tolerated, because
        // an operator writes this env value by hand.
        let messy = parse_allowlist(
            " https://claude.ai/api/mcp/auth_callback , https://claude.ai/api/mcp/auth_callback ",
            ENV_OAUTH_REDIRECT_URIS,
        )
        .unwrap();
        assert_eq!(messy.len(), 1);
    }
}
