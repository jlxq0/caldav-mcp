//! Logto access-token validation via JWKS + RS256.
//!
//! caldav-mcp validates Logto access tokens locally: fetch the
//! issuer's JWKS once, cache the decoding keys, and verify the JWT's
//! signature + `aud` + `exp` per request. This is a self-contained check
//! with no per-request round-trip.
//!
//! Pass-through model: the same validated JWT is then forwarded verbatim to
//! Stalwart as the `CalDAV` `Authorization: Bearer`. Stalwart validates it
//! against the same Logto issuer via its OIDC directory.
//!
//! Token must be a JWT issued for *our* resource indicator (the audience
//! check enforces RFC 8707 binding). Opaque tokens (no JWT header) are
//! rejected — Logto issues JWT access tokens for registered API resources,
//! which is how caldav-mcp's protected-resource metadata steers claude.ai.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::StreamExt;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, warn};

/// Maximum age of a cached positive validation. Bounded so a token
/// revocation (Logto session end) propagates in at most this window even
/// though local JWT verification can't see revocations directly.
#[allow(clippy::duration_suboptimal_units)]
const MAX_CACHE_TTL: Duration = Duration::from_secs(60);

/// Hard cap on the positive validation cache. This cache is only an
/// optimisation, so the earliest-expiring entry can be evicted safely.
const CACHE_CAP: usize = 256;

/// JWKS cache lifetime. Refetched on unknown `kid` regardless (key rotation).
/// `from_secs` not `from_hours`: the unit constructors are unstable on 1.93.
#[allow(clippy::duration_suboptimal_units)]
const JWKS_TTL: Duration = Duration::from_secs(3600);

/// Unknown key ids may indicate a key rotation, but must not turn arbitrary
/// bearer strings into one outbound JWKS request each. At most one unknown
/// key-triggered refresh is allowed in this interval.
#[allow(clippy::duration_suboptimal_units)]
const UNKNOWN_KID_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Bound the untrusted response read from the configured identity provider.
const MAX_JWKS_BYTES: usize = 1024 * 1024;

/// Claims we read off a Logto access token. Logto always emits `sub`, `aud`,
/// `iss`, `exp`, `iat`. `email`/`name`/`username` are present only when the
/// resource/app is configured to include user claims in the access token;
/// they're best-effort here and enriched from the `CalDAV` session elsewhere.
#[derive(Debug, Deserialize, Clone)]
struct LogtoAccessTokenClaims {
    sub: String,
    aud: AudField,
    exp: i64,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

/// `aud` can be a single string or an array. We check membership, not
/// equality.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum AudField {
    Single(String),
    Multi(Vec<String>),
}

impl AudField {
    fn matches(&self, expected: &str) -> bool {
        match self {
            Self::Single(s) => s == expected,
            Self::Multi(xs) => xs.iter().any(|s| s == expected),
        }
    }
}

/// What the auth layer hands to the rest of the application after a
/// successful validation.
#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity {
    /// Stable Logto user id (`sub`). Ownership/cache key.
    pub user_id: String,
    /// User's email, when the token carries it. Enriched from the `CalDAV`
    /// session's `username` for display when absent.
    pub email: Option<String>,
    /// Display name, when present.
    pub name: Option<String>,
    /// Token expiry (Unix epoch seconds). Surfaced via `/token/introspect`.
    pub exp: Option<i64>,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("JWKS fetch/transport error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JWKS endpoint returned non-2xx: {status}")]
    JwksUpstream { status: u16 },
    #[error("JWKS response exceeded {MAX_JWKS_BYTES} bytes")]
    JwksTooLarge,
    #[error("JWKS response was not valid JSON: {0}")]
    InvalidJwks(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct LogtoValidationClient {
    http: reqwest::Client,
    jwks_url: String,
    expected_audiences: Vec<String>,
    expected_issuer: String,
    jwks: Arc<RwLock<JwksCache>>,
    jwks_refresh_gate: Arc<tokio::sync::Mutex<()>>,
    cache: Arc<RwLock<HashMap<[u8; 32], CacheEntry>>>,
}

#[allow(clippy::missing_fields_in_debug)] // intentionally redacts cached token/JWKS state
impl std::fmt::Debug for LogtoValidationClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogtoValidationClient")
            .field("jwks_url", &self.jwks_url)
            .field("expected_audiences", &self.expected_audiences)
            .finish()
    }
}

#[derive(Default)]
struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
    last_refresh_attempt: Option<Instant>,
}

enum CachedKeyDecision {
    Use(DecodingKey),
    SkipRefresh,
    Refresh,
}

#[derive(Clone)]
struct CacheEntry {
    identity: AuthenticatedIdentity,
    expires_at: Instant,
}

impl LogtoValidationClient {
    /// Build a validation client. `authorization_server` is the Logto OIDC
    /// issuer base (`https://login.kampong.social/oidc`); the JWKS lives at
    /// `{issuer}/jwks` and the `iss` claim equals the issuer base exactly.
    pub fn new(authorization_server: &str, expected_audiences: Vec<String>) -> Result<Self> {
        anyhow::ensure!(
            !expected_audiences.is_empty(),
            "at least one expected JWT audience is required"
        );
        let issuer = authorization_server.trim_end_matches('/').to_owned();
        let jwks_url = format!("{issuer}/jwks");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent(concat!("caldav-mcp/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            http,
            jwks_url,
            expected_audiences,
            expected_issuer: issuer,
            jwks: Arc::new(RwLock::new(JwksCache::default())),
            jwks_refresh_gate: Arc::new(tokio::sync::Mutex::new(())),
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Validate a bearer token. `Ok(Some(identity))` on a valid JWT for our
    /// audience; `Ok(None)` if the token is expired, malformed, opaque, has
    /// the wrong audience/issuer, or fails signature verification. `Err`
    /// only for JWKS-fetch transport failures.
    pub async fn validate_token(
        &self,
        token: &str,
    ) -> Result<Option<AuthenticatedIdentity>, ValidationError> {
        let key = hash_token(token);
        if let Some(hit) = self.cache_lookup(&key) {
            debug!("token validation cache hit");
            return Ok(Some(hit));
        }

        let Ok(header) = decode_header(token) else {
            warn!("bearer is not a JWT (opaque token?); rejecting");
            return Ok(None);
        };
        let Some(kid) = header.kid.clone() else {
            warn!("JWT missing `kid`; rejecting");
            return Ok(None);
        };

        // Reject attacker-controlled algorithm choices before any outbound
        // key lookup. Otherwise a disallowed JWT can still trigger JWKS I/O.
        if !matches!(
            header.alg,
            Algorithm::ES384
                | Algorithm::ES256
                | Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::EdDSA
        ) {
            warn!(alg = ?header.alg, "unsupported token signing algorithm; rejecting");
            return Ok(None);
        }

        let Some(decoding_key) = self.decoding_key_for(&kid).await? else {
            warn!(%kid, "no JWKS key matched token kid; rejecting");
            return Ok(None);
        };

        // jsonwebtoken requires every entry in `validation.algorithms` to
        // share the key's family (mixing EC + RSA errors out), so we can't
        // hardcode a cross-family list. Use the token header's declared `alg`
        // — but only after allow-listing it to the asymmetric algorithms we
        // accept (rejects `none`/HMAC and blocks alg-confusion). The key is
        // already pinned by `kid` from the trusted JWKS and the signature is
        // verified against it below, and jsonwebtoken enforces key.family ==
        // alg.family, so a forged cross-family `alg` cannot validate.
        let mut validation = Validation::new(header.alg);
        let audiences: Vec<&str> = self.expected_audiences.iter().map(String::as_str).collect();
        validation.set_audience(&audiences);
        validation.set_issuer(&[&self.expected_issuer]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);

        let claims = match decode::<LogtoAccessTokenClaims>(token, &decoding_key, &validation) {
            Ok(data) => data.claims,
            Err(e) => {
                debug!(error = %e, "JWT validation failed; rejecting");
                return Ok(None);
            }
        };

        // Defence in depth: jsonwebtoken already enforced aud via Validation,
        // but re-check membership explicitly to be robust against future
        // Validation default changes.
        if !self
            .expected_audiences
            .iter()
            .any(|expected| claims.aud.matches(expected))
        {
            warn!("token audience does not include a recognised resource; rejecting");
            return Ok(None);
        }

        let identity = AuthenticatedIdentity {
            user_id: claims.sub.clone(),
            email: claims.email.clone().or_else(|| claims.username.clone()),
            name: claims.name.clone(),
            exp: Some(claims.exp),
        };
        let _ = claims.scope; // currently unused; reserved for scope gating.

        self.cache_insert(key, &identity, Some(claims.exp));
        Ok(Some(identity))
    }

    /// Drop a cached positive validation, forcing re-verification on the
    /// next presentation of this token (used when Stalwart reports the
    /// token is no longer good).
    pub fn drop_token(&self, token: &str) {
        let key = hash_token(token);
        if let Ok(mut g) = self.cache.write() {
            g.remove(&key);
        }
    }

    async fn decoding_key_for(&self, kid: &str) -> Result<Option<DecodingKey>, ValidationError> {
        match self.cached_key_decision(kid) {
            CachedKeyDecision::Use(key) => return Ok(Some(key)),
            CachedKeyDecision::SkipRefresh => return Ok(None),
            CachedKeyDecision::Refresh => {}
        }

        // Single-flight the slow path, then re-check after waiting because a
        // preceding request may already have refreshed the same key set.
        let _refresh_guard = self.jwks_refresh_gate.lock().await;
        match self.cached_key_decision(kid) {
            CachedKeyDecision::Use(key) => return Ok(Some(key)),
            CachedKeyDecision::SkipRefresh => return Ok(None),
            CachedKeyDecision::Refresh => {}
        }
        self.refresh_jwks().await?;
        Ok(self.jwks.read().ok().and_then(|g| g.keys.get(kid).cloned()))
    }

    fn cached_key_decision(&self, kid: &str) -> CachedKeyDecision {
        let Ok(g) = self.jwks.read() else {
            return CachedKeyDecision::Refresh;
        };
        if let Some(key) = g.keys.get(kid)
            && g.fetched_at.is_some_and(|t| t.elapsed() < JWKS_TTL)
        {
            return CachedKeyDecision::Use(key.clone());
        }
        if g.last_refresh_attempt
            .is_some_and(|t| t.elapsed() < UNKNOWN_KID_REFRESH_INTERVAL)
        {
            CachedKeyDecision::SkipRefresh
        } else {
            CachedKeyDecision::Refresh
        }
    }

    async fn refresh_jwks(&self) -> Result<(), ValidationError> {
        if let Ok(mut cache) = self.jwks.write() {
            cache.last_refresh_attempt = Some(Instant::now());
        }
        let resp = self.http.get(&self.jwks_url).send().await?;
        if !resp.status().is_success() {
            return Err(ValidationError::JwksUpstream {
                status: resp.status().as_u16(),
            });
        }
        if resp
            .content_length()
            .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
        {
            return Err(ValidationError::JwksTooLarge);
        }
        let mut body = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if body.len().saturating_add(chunk.len()) > MAX_JWKS_BYTES {
                return Err(ValidationError::JwksTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        let set: JwkSet = serde_json::from_slice(&body)?;
        let mut keys = HashMap::new();
        for jwk in &set.keys {
            if let Some(kid) = jwk.common.key_id.clone()
                && let Ok(key) = DecodingKey::from_jwk(jwk)
            {
                keys.insert(kid, key);
            }
        }
        if let Ok(mut g) = self.jwks.write() {
            g.keys = keys;
            g.fetched_at = Some(Instant::now());
        }
        Ok(())
    }

    fn cache_lookup(&self, key: &[u8; 32]) -> Option<AuthenticatedIdentity> {
        let guard = self.cache.read().ok()?;
        let result = guard
            .get(key)
            .and_then(|e| (e.expires_at > Instant::now()).then(|| e.identity.clone()));
        drop(guard);
        result
    }

    fn cache_insert(&self, key: [u8; 32], identity: &AuthenticatedIdentity, exp: Option<i64>) {
        let ttl = exp.map_or(MAX_CACHE_TTL, |exp| {
            let now = now_unix();
            let remaining = u64::try_from((exp - now).max(0)).unwrap_or(0);
            Duration::from_secs(remaining).min(MAX_CACHE_TTL)
        });
        let entry = CacheEntry {
            identity: identity.clone(),
            expires_at: Instant::now() + ttl,
        };
        let Ok(mut guard) = self.cache.write() else {
            return;
        };
        if guard.len() >= CACHE_CAP {
            let now = Instant::now();
            guard.retain(|_, e| e.expires_at > now);
        }
        if guard.len() >= CACHE_CAP
            && let Some(eviction_key) = guard
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| *key)
        {
            guard.remove(&eviction_key);
        }
        guard.insert(key, entry);
    }
}

fn hash_token(token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.finalize().into()
}

fn now_unix() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn unsigned_token(alg: &str, kid: &str) -> String {
        let header = format!(r#"{{"alg":"{alg}","kid":"{kid}"}}"#);
        format!("{}.e30.c2ln", URL_SAFE_NO_PAD.encode(header))
    }

    #[test]
    fn aud_single_and_multi_membership() {
        assert!(AudField::Single("https://x".into()).matches("https://x"));
        assert!(!AudField::Single("https://x".into()).matches("https://y"));
        let m = AudField::Multi(vec!["https://x".into(), "https://y".into()]);
        assert!(m.matches("https://y"));
        assert!(!m.matches("https://z"));
    }

    #[test]
    fn jwks_url_derived_from_issuer() {
        let c = LogtoValidationClient::new(
            "https://login.example.test/oidc/",
            vec!["https://res".into()],
        )
        .unwrap();
        assert_eq!(c.jwks_url, "https://login.example.test/oidc/jwks");
        assert_eq!(c.expected_issuer, "https://login.example.test/oidc");
    }

    #[tokio::test]
    async fn opaque_token_rejected() {
        let c = LogtoValidationClient::new(
            "https://login.example.test/oidc",
            vec!["https://res".into()],
        )
        .unwrap();
        // Not a JWT — decode_header fails, no network touched.
        assert!(c.validate_token("opaque-abc123").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn random_unknown_kids_cannot_amplify_jwks_requests() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oidc/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = LogtoValidationClient::new(
            &format!("{}/oidc", server.uri()),
            vec!["https://res".into()],
        )
        .unwrap();

        assert!(
            client
                .validate_token(&unsigned_token("RS256", "random-one"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            client
                .validate_token(&unsigned_token("RS256", "random-two"))
                .await
                .unwrap()
                .is_none()
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn disallowed_algorithm_is_rejected_before_jwks_lookup() {
        let server = MockServer::start().await;
        let client = LogtoValidationClient::new(
            &format!("{}/oidc", server.uri()),
            vec!["https://res".into()],
        )
        .unwrap();
        assert!(
            client
                .validate_token(&unsigned_token("HS256", "random"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn oversized_jwks_response_is_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oidc/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; MAX_JWKS_BYTES + 1]))
            .expect(1)
            .mount(&server)
            .await;
        let client = LogtoValidationClient::new(
            &format!("{}/oidc", server.uri()),
            vec!["https://res".into()],
        )
        .unwrap();

        assert!(matches!(
            client.decoding_key_for("missing").await,
            Err(ValidationError::JwksTooLarge)
        ));
        server.verify().await;
    }

    #[tokio::test]
    async fn failed_jwks_refresh_is_also_cooled_down() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oidc/jwks"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        let client = LogtoValidationClient::new(
            &format!("{}/oidc", server.uri()),
            vec!["https://res".into()],
        )
        .unwrap();

        assert!(matches!(
            client.decoding_key_for("random-one").await,
            Err(ValidationError::JwksUpstream { status: 503 })
        ));
        assert!(
            client
                .decoding_key_for("random-two")
                .await
                .unwrap()
                .is_none()
        );
        server.verify().await;
    }

    #[test]
    fn positive_validation_cache_has_a_hard_cap() {
        let client = LogtoValidationClient::new(
            "https://login.example.test/oidc",
            vec!["https://res".into()],
        )
        .unwrap();
        let identity = AuthenticatedIdentity {
            user_id: "user".into(),
            email: None,
            name: None,
            exp: None,
        };
        for i in 0..=CACHE_CAP {
            client.cache_insert(hash_token(&format!("token-{i}")), &identity, None);
        }
        assert_eq!(client.cache.read().unwrap().len(), CACHE_CAP);
    }
}
