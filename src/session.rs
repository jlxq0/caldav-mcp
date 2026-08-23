//! Session-management hardening (audit finding #13).
//!
//! Wraps `rmcp`'s `LocalSessionManager` with two complementary defences
//! against authenticated denial-of-service via session flooding:
//!
//! * **Idle TTL** — `LocalSessionManager` is constructed with a
//!   [`SessionConfig`] whose `keep_alive` is set to 30 minutes. rmcp's default
//!   is 5 minutes; we lengthen it so claude.ai's variable tool-call cadence
//!   (sometimes >5 min between calls within a long conversation) doesn't
//!   silently evict sessions and leave the connector wedged in a "connected
//!   but un-handshaken" state. The global [`MAX_SESSIONS`] cap remains the
//!   real defence against session flooding.
//!
//! * **Global session cap** — [`CappedSessionManager`] wraps the inner
//!   manager and rejects `create_session` once the live session count hits
//!   [`MAX_SESSIONS`]. New `initialize` requests receive an HTTP 503 / JSON-RPC
//!   error instead of growing memory without bound.
//!
//! Both mitigations are applied together in `build_router`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use futures::Stream;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::streamable_http_server::session::{
    RestoreOutcome, ServerSseMessage, SessionId, SessionManager,
    local::{LocalSessionManager, LocalSessionManagerError, SessionTransport},
};
use tracing::warn;

use crate::logto_oidc::AuthenticatedIdentity;

/// Maximum number of concurrent MCP sessions the server will hold.
///
/// Requests that would push the count beyond this limit receive an error
/// from `create_session`. Legitimate claude.ai usage peaks around one or
/// two sessions per user; 256 comfortably covers all expected concurrent
/// users while bounding the worst-case memory from a flooded attacker.
pub const MAX_SESSIONS: usize = 256;

/// Idle timeout applied to each session.
///
/// 30 minutes — longer than rmcp's 5-minute default. claude.ai's MCP
/// connector doesn't always heartbeat within a tight window, and an
/// evicted-too-fast session leaves the connector in a wedged state
/// (UI shows "connected" but every subsequent tool call sends a
/// stale session id, 404s, and silently drops). The global
/// [`MAX_SESSIONS`] cap remains the real defence against an
/// authenticated session flood.
// `Duration::from_mins` is unstable on our MSRV (Rust 1.93); use `from_secs`
// and suppress the clippy lint that would suggest the nicer-named constructor.
#[allow(unknown_lints)]
#[allow(clippy::duration_suboptimal_units)]
pub const SESSION_KEEP_ALIVE: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Debug)]
struct BoundIdentity {
    user_id: String,
    last_seen: Instant,
}

/// Associates every live MCP session id with the verified token subject that
/// created it. The rmcp manager intentionally treats session ids as bearer
/// capabilities; this additional boundary prevents a leaked id from being
/// used with a different valid account token.
#[derive(Clone, Debug, Default)]
pub struct SessionIdentityBindings {
    inner: Arc<RwLock<HashMap<String, BoundIdentity>>>,
}

impl SessionIdentityBindings {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn bind(&self, session_id: &str, user_id: &str) {
        let mut bindings = match self.inner.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        bindings.retain(|_, bound| now.duration_since(bound.last_seen) < SESSION_KEEP_ALIVE);
        if bindings.len() >= MAX_SESSIONS
            && let Some(oldest) = bindings
                .iter()
                .min_by_key(|(_, bound)| bound.last_seen)
                .map(|(id, _)| id.clone())
        {
            bindings.remove(&oldest);
        }
        bindings.insert(
            session_id.to_owned(),
            BoundIdentity {
                user_id: user_id.to_owned(),
                last_seen: now,
            },
        );
    }

    fn authorize(&self, session_id: &str, user_id: &str) -> bool {
        let mut bindings = match self.inner.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let Some(bound) = bindings.get_mut(session_id) else {
            drop(bindings);
            return false;
        };
        if now.duration_since(bound.last_seen) >= SESSION_KEEP_ALIVE {
            bindings.remove(session_id);
            drop(bindings);
            return false;
        }
        if bound.user_id != user_id {
            drop(bindings);
            return false;
        }
        bound.last_seen = now;
        drop(bindings);
        true
    }

    fn remove(&self, session_id: &str) {
        let mut bindings = match self.inner.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        bindings.remove(session_id);
    }
}

/// Enforce session ownership after bearer authentication and before rmcp sees
/// the request. A 404 is used for mismatches so session ids are not an account
/// membership oracle.
pub async fn bind_session_identity(
    State(bindings): State<SessionIdentityBindings>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(identity) = request.extensions().get::<AuthenticatedIdentity>() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "authenticated request missing identity extension\n",
        )
            .into_response();
    };
    let user_id = identity.user_id.clone();
    let requested_session = request
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let is_delete = request.method() == Method::DELETE;

    if let Some(session_id) = requested_session.as_deref()
        && !bindings.authorize(session_id, &user_id)
    {
        return StatusCode::NOT_FOUND.into_response();
    }

    let response = next.run(request).await;
    if let Some(session_id) = requested_session {
        if is_delete || response.status() == StatusCode::NOT_FOUND {
            bindings.remove(&session_id);
        }
    } else if let Some(session_id) = response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
    {
        bindings.bind(session_id, &user_id);
    }
    response
}

/// Build a `LocalSessionManager` with the tightened idle TTL.
///
/// This is Mitigation A from audit finding #13.
fn inner_manager() -> LocalSessionManager {
    // Both `LocalSessionManager` and `SessionConfig` are `#[non_exhaustive]`,
    // so struct literals are forbidden outside the crate.  We use
    // `Default::default()` to get a value, then mutate the public fields.
    let mut mgr = LocalSessionManager::default();
    mgr.session_config.keep_alive = Some(SESSION_KEEP_ALIVE);
    mgr
}

/// Error returned by [`CappedSessionManager`].
#[derive(Debug)]
pub enum CappedSessionError {
    Inner(LocalSessionManagerError),
    CapReached,
}

impl std::fmt::Display for CappedSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inner(e) => write!(f, "inner session manager error: {e}"),
            Self::CapReached => write!(
                f,
                "session cap reached ({MAX_SESSIONS} sessions active); try again later"
            ),
        }
    }
}

impl std::error::Error for CappedSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(e) => Some(e),
            Self::CapReached => None,
        }
    }
}

impl From<LocalSessionManagerError> for CappedSessionError {
    fn from(e: LocalSessionManagerError) -> Self {
        Self::Inner(e)
    }
}

impl From<CappedSessionError> for std::io::Error {
    fn from(e: CappedSessionError) -> Self {
        Self::other(e.to_string())
    }
}

/// A thin wrapper around [`LocalSessionManager`] that rejects new sessions
/// once [`MAX_SESSIONS`] are already live (Mitigation B, audit finding #13).
///
/// All methods except `create_session` are pure pass-throughs.
///
/// The cap is enforced atomically: concurrent `create_session` calls
/// serialize on `create_gate`, so the check-then-insert sequence
/// cannot be interleaved by another task. Without the gate, N parallel
/// initialize requests could each read `count = MAX_SESSIONS - 1`,
/// each see room, and each create a session — overshooting the cap
/// by up to N. The gate adds zero contention on the read-heavy
/// session-lookup paths (`has_session`, `accept_message`, etc.) because
/// they do not take it.
pub struct CappedSessionManager {
    inner: LocalSessionManager,
    create_gate: tokio::sync::Mutex<()>,
}

impl CappedSessionManager {
    /// Construct a new `CappedSessionManager` backed by a [`LocalSessionManager`]
    /// configured with the tightened idle TTL (Mitigation A + B combined).
    pub fn new() -> Self {
        Self {
            inner: inner_manager(),
            create_gate: tokio::sync::Mutex::new(()),
        }
    }
}

// Compile-time check that `CappedSessionManager` satisfies the `Send + Sync`
// bounds required by `StreamableHttpService::new`, which wraps the manager in
// an `Arc<M>` shared across threads.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    #[allow(dead_code)]
    const fn _check() {
        assert_send_sync::<CappedSessionManager>();
    }
};

impl SessionManager for CappedSessionManager {
    type Error = CappedSessionError;
    type Transport = SessionTransport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        // Serialize check-and-create so concurrent initializes cannot
        // all observe `count < MAX_SESSIONS` and then each insert. The
        // gate is held only across the count + inner.create_session
        // call (both fast). Other manager operations don't take it.
        let _create_guard = self.create_gate.lock().await;
        let count = self.inner.sessions.read().await.len();
        if count >= MAX_SESSIONS {
            warn!(
                count,
                limit = MAX_SESSIONS,
                "session cap reached; rejecting new initialize"
            );
            return Err(CappedSessionError::CapReached);
        }
        Ok(self.inner.create_session().await?)
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        Ok(self.inner.initialize_session(id, message).await?)
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        Ok(self.inner.close_session(id).await?)
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        Ok(self.inner.has_session(id).await?)
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(self.inner.create_stream(id, message).await?)
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        Ok(self.inner.accept_message(id, message).await?)
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(self.inner.create_standalone_stream(id).await?)
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(self.inner.resume(id, last_event_id).await?)
    }

    async fn restore_session(
        &self,
        id: SessionId,
    ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
        Ok(self.inner.restore_session(id).await?)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use axum::Router;
    use axum::http::header::HeaderValue;
    use axum::middleware;
    use axum::routing::post;
    use tower::ServiceExt;

    use super::*;

    #[test]
    fn session_is_available_only_to_its_verified_subject() {
        let bindings = SessionIdentityBindings::new();
        bindings.bind("session-1", "user-a");

        assert!(bindings.authorize("session-1", "user-a"));
        assert!(!bindings.authorize("session-1", "user-b"));
        assert!(!bindings.authorize("unknown", "user-a"));
    }

    #[test]
    fn removing_session_removes_identity_binding() {
        let bindings = SessionIdentityBindings::new();
        bindings.bind("session-1", "user-a");
        bindings.remove("session-1");
        assert!(!bindings.authorize("session-1", "user-a"));
    }

    #[tokio::test]
    async fn middleware_binds_initialize_response_and_rejects_other_subject() {
        let bindings = SessionIdentityBindings::new();
        let app = Router::new()
            .route(
                "/mcp",
                post(|| async {
                    let mut response = StatusCode::OK.into_response();
                    response
                        .headers_mut()
                        .insert("mcp-session-id", HeaderValue::from_static("session-1"));
                    response
                }),
            )
            .layer(middleware::from_fn_with_state(
                bindings,
                bind_session_identity,
            ));

        let mut initialize = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .body(Body::empty())
            .unwrap();
        initialize.extensions_mut().insert(AuthenticatedIdentity {
            user_id: "user-a".into(),
            email: None,
            name: None,
            exp: None,
        });
        assert_eq!(
            app.clone().oneshot(initialize).await.unwrap().status(),
            StatusCode::OK
        );

        let mut resumed = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("mcp-session-id", "session-1")
            .body(Body::empty())
            .unwrap();
        resumed.extensions_mut().insert(AuthenticatedIdentity {
            user_id: "user-a".into(),
            email: None,
            name: None,
            exp: None,
        });
        assert_eq!(
            app.clone().oneshot(resumed).await.unwrap().status(),
            StatusCode::OK
        );

        let mut stolen = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("mcp-session-id", "session-1")
            .body(Body::empty())
            .unwrap();
        stolen.extensions_mut().insert(AuthenticatedIdentity {
            user_id: "user-b".into(),
            email: None,
            name: None,
            exp: None,
        });
        assert_eq!(
            app.oneshot(stolen).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }
}
