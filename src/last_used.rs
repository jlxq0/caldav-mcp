//! Per-bearer last-used tracking.
//!
//! Records, for each accepted bearer hash, the timestamp and (when
//! available) the caller's IP at the moment of the most recent
//! successful token validation. Exposed via [`crate::token_introspect`]
//! so a user can audit live state for their own bearer without
//! scraping operator-side logs.
//!
//! ## Storage
//!
//! In-memory only. A new pod starts with an empty map. Bounded to
//! [`MAX_ENTRIES`] distinct bearer hashes; when the cap is hit on a
//! fresh insert, the oldest entry is evicted (linear scan — fine at
//! this cardinality). Cardinality of distinct active bearers in
//! production is expected to be small (a few users, occasional
//! rotation), so the cap is generous and the eviction is rare.
//!
//! ## Why a separate module from `audit.rs`
//!
//! `audit.rs` writes structured events to stdout for Loki consumption,
//! never holds state, and intentionally never sees client IPs (audit
//! events ship to a shared log indexer; we don't want PII in there).
//! This module holds *per-user* state that only the bearer's owner
//! can read back via the introspect endpoint, so caller IP is fine
//! to retain in memory.
//!
//! ## Bearer hash key
//!
//! We key on the same short hex digest as [`crate::audit::token_hash`]
//! (`sha256(token)[..8]` → 16 hex chars). Collision probability at our
//! scale is negligible and it keeps the audit-log key and the
//! last-used key cross-referenceable.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Maximum number of distinct bearer hashes we hold last-used data
/// for. When exceeded on a fresh insert, the oldest entry is evicted.
const MAX_ENTRIES: usize = 1024;

/// A single bearer's last-used record. `at` is serialised as a Unix
/// epoch second integer for stability across timezone / formatting
/// dependencies.
#[derive(Debug, Clone, Serialize)]
pub struct LastUsedRecord {
    /// When the bearer was last presented and accepted by Logto validation.
    /// Serialised as `at_unix` (seconds since the Unix epoch).
    #[serde(rename = "at_unix", serialize_with = "ser_unix_secs")]
    pub at: SystemTime,
    /// Caller IP parsed from the `X-Forwarded-For` header (leftmost
    /// value). `None` when the header was absent or unparseable.
    pub ip: Option<IpAddr>,
}

fn ser_unix_secs<S: serde::Serializer>(t: &SystemTime, ser: S) -> Result<S::Ok, S::Error> {
    let secs: i64 = t
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0);
    ser.serialize_i64(secs)
}

/// In-memory `bearer-hash → last-used-record` map. Cheap to clone via
/// the inner `Arc` — see [`new`](LastUsedTracker::new).
#[derive(Debug, Default)]
pub struct LastUsedTracker {
    inner: RwLock<HashMap<String, LastUsedRecord>>,
}

impl LastUsedTracker {
    /// Construct a fresh tracker wrapped in [`Arc`] so it can be
    /// shared between the auth middleware (which writes) and the
    /// `/token/introspect` handler (which reads).
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record / refresh the entry for this bearer hash. When the map
    /// is at capacity and the key is new, drop the oldest entry
    /// first. Lock poisoning is recovered from in-place — a panic
    /// elsewhere should not cripple the introspect endpoint.
    pub fn record(&self, token_hash: &str, ip: Option<IpAddr>) {
        let now = SystemTime::now();
        let mut map = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= MAX_ENTRIES
            && !map.contains_key(token_hash)
            && let Some(oldest_key) = map.iter().min_by_key(|(_, r)| r.at).map(|(k, _)| k.clone())
        {
            map.remove(&oldest_key);
        }
        map.insert(token_hash.to_owned(), LastUsedRecord { at: now, ip });
    }

    /// Look up the most recent record for this bearer hash.
    pub fn get(&self, token_hash: &str) -> Option<LastUsedRecord> {
        let map = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(token_hash).cloned()
    }
}

/// Best-effort parser for the client IP from an `X-Forwarded-For`
/// header value.
///
/// `X-Forwarded-For` is the comma-separated chain of IPs each proxy
/// has *appended* on the way in. The leftmost entry is **claimed** by
/// the original client (and is therefore attacker-controllable on a
/// public service — any HTTP client can set the header to whatever it
/// wants before talking to us). Reading the leftmost entry produces
/// audit signals that an attacker holding a stolen bearer can trivially
/// spoof.
///
/// Instead, count `trusted_proxy_hops` entries in from the right. Each
/// trusted proxy on the path is expected to *append* the IP it saw
/// when the request arrived at it; the rightmost N entries are
/// therefore the ones we trust. The default of 1 trusted proxy assumes
/// a typical "ingress (Traefik / nginx / etc.) in front of the caldav-mcp
/// pod" deployment; override via `CALDAV_MCP_TRUSTED_PROXY_HOPS`.
///
/// Returns `None` when the header is absent, has fewer entries than
/// the trusted-hops count, or contains no parseable IP at the trusted
/// position.
/// How many entries the `X-Forwarded-For` chain actually carries.
///
/// The **count**, never the entries. `CALDAV_MCP_TRUSTED_PROXY_HOPS` has to
/// equal the number of proxies that appended on the way in, and getting it
/// wrong does not fail safe: too low selects an upstream proxy's address and
/// records it as the client's, which is a confident wrong value in a
/// provenance record rather than a missing one. Zero blanks the field
/// entirely, which is recoverable.
///
/// Logging the count settles the value from one real request without putting
/// a client address anywhere.
#[must_use]
pub fn count_xff_entries(xff: Option<&str>) -> usize {
    xff.map_or(0, |raw| {
        raw.split(',')
            .filter(|part| !part.trim().is_empty())
            .count()
    })
}

/// Classify each `X-Forwarded-For` entry as public or private, in order, and
/// never record the entry itself.
///
/// The count alone cannot separate a spoofable public first entry from a
/// private one appended by our own fabric, and that single distinction settles
/// four constants at once: this server's `trusted_proxy_hops`, webmail's depth,
/// Synapse's `x_forwarded`, and Mastodon's absence. Three of those record
/// nothing and cannot be checked after the fact.
///
/// The output is positional and carries no address: `"private,private"` for a
/// two-entry chain that never left the fabric. An address in a log is the thing
/// the rule against logging them exists to keep out, so the classification is
/// the whole payload.
///
/// An entry that does not parse is `unparseable` rather than assumed either
/// way. Ports (`203.0.113.7:41234`) and obfuscated identifiers land there, and
/// counting them as public would manufacture the finding this exists to test.
///
/// `public` means "not one of the private scopes below", not "routable". A
/// cross-engine review named the gap: CGNAT (`100.64.0.0/10`) and the
/// documentation ranges (`192.0.2.0/24`, `2001:db8::/32`) are labelled `public`
/// and none of them is publicly routable. Those are false positives and they
/// err in the recoverable direction: one makes somebody look at a chain that
/// turns out to be fine, where the opposite would hide the exact entry this
/// exists to catch. Read a `public` as "worth checking", not as "spoofed".
#[must_use]
pub fn classify_xff_entries(xff: Option<&str>) -> String {
    let Some(raw) = xff else {
        return String::new();
    };
    raw.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            // A bracketed v6 literal is legal in this header and does not parse
            // as an `IpAddr`, so strip the brackets before deciding.
            let bare = part
                .strip_prefix('[')
                .and_then(|r| r.strip_suffix(']'))
                .unwrap_or(part);
            match bare.parse::<IpAddr>() {
                Ok(ip) if is_private_scope(&ip) => "private",
                Ok(_) => "public",
                Err(_) => "unparseable",
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Private, loopback, link-local or unspecified, using only stable predicates.
///
/// `Ipv4Addr::is_global` and `Ipv6Addr::is_unique_local` are unstable, so the
/// v6 cases are the prefix tests they would perform: `fc00::/7` for unique-local
/// and `fe80::/10` for link-local.
const fn is_private_scope(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
        }
    }
}

#[must_use]
pub fn parse_client_ip(xff: Option<&str>, trusted_proxy_hops: usize) -> Option<IpAddr> {
    let raw = xff?;
    let parts: Vec<&str> = raw.split(',').map(str::trim).collect();
    let len = parts.len();
    if trusted_proxy_hops == 0 || len < trusted_proxy_hops {
        return None;
    }
    // The entry immediately upstream of the last `trusted_proxy_hops`
    // proxies is the real client IP — i.e., index `len - trusted_proxy_hops`.
    let idx = len - trusted_proxy_hops;
    parts.get(idx)?.parse::<IpAddr>().ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::Ipv4Addr;
    use std::thread::sleep;
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_private_chain_classifies_as_private_and_carries_no_address() {
        let out = classify_xff_entries(Some("10.0.1.5, 192.168.4.9"));
        assert_eq!(out, "private,private");
        assert!(
            !out.contains("10."),
            "an address reached the log line: {out}"
        );
        assert!(
            !out.contains("192."),
            "an address reached the log line: {out}"
        );
    }

    #[test]
    fn a_public_first_entry_is_named_public() {
        // The finding this exists to detect: something outside the fabric put a
        // routable address at the head of the chain.
        assert_eq!(
            classify_xff_entries(Some("203.0.113.7, 10.0.1.5")),
            "public,private"
        );
    }

    #[test]
    fn position_is_preserved_so_the_two_orders_are_distinguishable() {
        // Same two scopes, opposite order, each pinned to its exact string.
        //
        // Written first as a single `assert_ne!` between the two, which reads
        // as an order test and is not one: reversing the output reverses both
        // sides and they stay unequal, so it survived a mutation that reversed
        // the chain. It pinned only that the function is not set-valued. Which
        // end is public is the whole question, so both sides are named.
        assert_eq!(
            classify_xff_entries(Some("203.0.113.7, 10.0.1.5")),
            "public,private"
        );
        assert_eq!(
            classify_xff_entries(Some("10.0.1.5, 203.0.113.7")),
            "private,public"
        );
    }

    #[test]
    fn loopback_link_local_and_unspecified_are_private() {
        assert_eq!(
            classify_xff_entries(Some("127.0.0.1, 169.254.1.1, 0.0.0.0")),
            "private,private,private"
        );
    }

    #[test]
    fn v6_unique_local_and_link_local_are_private_and_a_routable_v6_is_not() {
        assert_eq!(classify_xff_entries(Some("fd00::1")), "private");
        assert_eq!(classify_xff_entries(Some("fe80::1")), "private");
        assert_eq!(classify_xff_entries(Some("[::1]")), "private");
        // Both conventions on purpose. Documentation ranges are the right test
        // data and are themselves non-routable, so on their own they assert the
        // caveat rather than the property; a genuinely routable address of each
        // family asserts the property.
        assert_eq!(classify_xff_entries(Some("2001:db8::1")), "public");
        assert_eq!(classify_xff_entries(Some("2606:4700:4700::1111")), "public");
        assert_eq!(classify_xff_entries(Some("8.8.8.8")), "public");
    }

    #[test]
    fn an_entry_that_does_not_parse_is_unparseable_rather_than_public() {
        // Counting a port-bearing or obfuscated entry as public would
        // manufacture the finding this measurement exists to test.
        assert_eq!(
            classify_xff_entries(Some("203.0.113.7:41234, _hidden, 10.0.1.5")),
            "unparseable,unparseable,private"
        );
    }

    #[test]
    fn an_absent_or_empty_header_yields_an_empty_string() {
        assert_eq!(classify_xff_entries(None), "");
        assert_eq!(classify_xff_entries(Some("")), "");
        assert_eq!(classify_xff_entries(Some(" , ")), "");
    }

    #[test]
    fn record_then_get_round_trip() {
        let t = LastUsedTracker::new();
        t.record("abc", Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        let r = t.get("abc").unwrap();
        assert_eq!(r.ip, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }

    #[test]
    fn record_overwrites_previous_entry_for_same_key() {
        let t = LastUsedTracker::new();
        t.record("k", None);
        sleep(Duration::from_millis(10));
        t.record("k", Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(
            t.get("k").unwrap().ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    #[test]
    fn get_returns_none_for_unknown_hash() {
        let t = LastUsedTracker::new();
        assert!(t.get("nope").is_none());
    }

    #[test]
    fn at_field_serialises_as_unix_seconds() {
        let t = LastUsedTracker::new();
        t.record("a", None);
        let r = t.get("a").unwrap();
        let json = serde_json::to_value(&r).unwrap();
        assert!(
            json.get("at_unix")
                .and_then(serde_json::Value::as_i64)
                .is_some(),
            "expected at_unix integer field, got: {json}"
        );
        // `ip` should be present and null.
        assert_eq!(json.get("ip").unwrap(), &serde_json::Value::Null);
    }

    #[test]
    fn parse_client_ip_with_one_trusted_hop_takes_rightmost() {
        // Single-entry XFF with one trusted hop → that's the IP Traefik saw.
        assert_eq!(
            parse_client_ip(Some("203.0.113.5"), 1),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)))
        );
        // The leftmost entry is the **claimed** client IP and may be
        // spoofed; with one trusted proxy in front, the rightmost is
        // the real one (Traefik appends what it saw).
        assert_eq!(
            parse_client_ip(Some("1.2.3.4, 10.0.0.1, 198.51.100.7"), 1),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );
        // Surrounding whitespace.
        assert_eq!(
            parse_client_ip(Some("  198.51.100.7  ,  10.0.0.1  "), 1),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    #[test]
    fn parse_client_ip_with_two_trusted_hops_takes_third_from_right() {
        // Clean chain (no spoof): client → trustedA → trustedB → us
        // produces exactly 2 entries, and the leftmost is the real
        // client IP (because trustedA appended what it saw of the
        // client, trustedB appended trustedA's IP, and we never put
        // ourselves into XFF).
        assert_eq!(
            parse_client_ip(Some("198.51.100.7, 10.0.0.1"), 2),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );
        // Spoofed: the client put `1.2.3.4` in XFF themselves. Now we
        // see 3 entries; the trusted ones are the last 2, so the real
        // client IP is the one at position `len - 2 = 1`.
        assert_eq!(
            parse_client_ip(Some("1.2.3.4, 198.51.100.7, 10.0.0.1"), 2),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );
    }

    #[test]
    fn parse_client_ip_returns_none_when_chain_shorter_than_trust() {
        // We expect 2 trusted hops but only got 1 entry: refuse to trust.
        assert_eq!(parse_client_ip(Some("198.51.100.7"), 2), None);
    }

    #[test]
    fn parse_client_ip_returns_none_when_no_proxies_trusted() {
        // Defence-in-depth: trust_hops=0 means "don't read XFF at all".
        assert_eq!(parse_client_ip(Some("198.51.100.7"), 0), None);
    }

    #[test]
    fn parse_client_ip_returns_none_for_garbage() {
        assert_eq!(parse_client_ip(None, 1), None);
        assert_eq!(parse_client_ip(Some(""), 1), None);
        assert_eq!(parse_client_ip(Some("not an ip"), 1), None);
        assert_eq!(parse_client_ip(Some(", , ,"), 1), None);
    }

    /// The count is what makes the configured hop value checkable, so it has
    /// to be the number of proxies that wrote an entry and not the number of
    /// commas.
    #[test]
    fn xff_entries_are_counted_without_reading_them() {
        assert_eq!(count_xff_entries(None), 0);
        assert_eq!(count_xff_entries(Some("")), 0);
        assert_eq!(count_xff_entries(Some("203.0.113.5")), 1);
        assert_eq!(count_xff_entries(Some("203.0.113.5, 198.51.100.7")), 2);
        // A trailing comma is not a proxy.
        assert_eq!(count_xff_entries(Some("203.0.113.5, 198.51.100.7,")), 2);
        // Nor is whitespace between them.
        assert_eq!(
            count_xff_entries(Some(" 203.0.113.5 ,  , 198.51.100.7 ")),
            2
        );
    }

    /// Being wrong is asymmetric, so the default errs toward the blank field.
    /// A chain shorter than the hop count yields `None` rather than reaching
    /// for whatever entry is there.
    #[test]
    fn a_chain_shorter_than_the_hop_count_blanks_rather_than_guesses() {
        assert_eq!(parse_client_ip(Some("203.0.113.5"), 2), None);
        assert_eq!(parse_client_ip(None, 2), None);
    }

    /// The deployed topology: client, then the edge, then the gateway appends.
    /// Two hops selects the entry the edge wrote, which is the client. One hop
    /// selects the edge itself and records it as the client, which is the
    /// failure this default exists to avoid.
    #[test]
    fn two_hops_selects_the_client_and_one_hop_selects_the_edge() {
        let chain = Some("203.0.113.5, 198.51.100.7");
        assert_eq!(
            parse_client_ip(chain, 2),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
            "two hops must select the entry the edge wrote"
        );
        assert_eq!(
            parse_client_ip(chain, 1),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
            "one hop selects the edge: a well-formed address for the wrong party"
        );
    }

    /// The residual the deployed measurement could not see, pinned so it is
    /// visible in the code rather than only in a comment.
    ///
    /// A caller reaching the Cilium gateway directly supplies its own header
    /// and Envoy appends its address, so the chain is two long and the guard
    /// never fires. **Two hops then selects the caller's own string.** One hop,
    /// which is the correct value for that path, selects the address Envoy
    /// appended. No single value is right for both paths; the mitigation is
    /// that only one path exists, which is a fact about the cluster.
    #[test]
    fn a_direct_caller_bypassing_the_edge_can_forge_the_recorded_address() {
        let forged = Some("9.9.9.9, 198.51.100.7");
        assert_eq!(
            parse_client_ip(forged, 2),
            Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
            "two hops takes the caller's own claim when the edge was bypassed"
        );
        assert_eq!(
            parse_client_ip(forged, 1),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
            "one hop is correct for the direct path and wrong for the edge path"
        );
    }
}
