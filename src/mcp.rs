//! MCP tool catalogue for Stalwart `CalDAV`.
//!
//! Axum validates the Logto access token before rmcp sees a request. Each tool
//! retrieves the raw validated bearer from request extensions and forwards it
//! verbatim to Stalwart.

use std::sync::Arc;
use std::time::Instant;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};
use tracing::{Instrument as _, Span};

use crate::audit::{self, outcome};
use crate::auth::AccessToken;
use crate::caldav_client::{
    BusyInterval, CaldavClient, CaldavError, Calendar, Event, EventPatch, NewEvent,
};
use crate::logto_oidc::{AuthenticatedIdentity, LogtoValidationClient};
use crate::rate_limit::{Category, Limiter};

const DEFAULT_TIMEZONE: &str = "Asia/Singapore";

#[derive(Clone)]
pub struct CaldavMcpService {
    caldav: CaldavClient,
    logto: LogtoValidationClient,
    rate_limiter: Arc<Limiter>,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for CaldavMcpService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaldavMcpService").finish()
    }
}

impl CaldavMcpService {
    pub fn new(
        caldav: CaldavClient,
        logto: LogtoValidationClient,
        rate_limiter: Arc<Limiter>,
    ) -> Self {
        Self {
            caldav,
            logto,
            rate_limiter,
            tool_router: Self::caldav_router(),
        }
    }

    fn rate_limit_check(
        &self,
        ctx: &RequestContext<RoleServer>,
        category: Category,
    ) -> Result<(), ErrorData> {
        let token = token_from_ctx(ctx).ok_or_else(missing_token_err)?;
        let identity = identity_from_ctx(ctx).ok_or_else(missing_identity_err)?;
        let bearer_hash = audit::token_hash(&token.0);
        self.rate_limiter
            .check(&bearer_hash, Some(identity.user_id.as_str()), category)
            .map_err(|_| {
                ErrorData::new(
                    rmcp::model::ErrorCode(audit::RATE_LIMITED_CODE),
                    "rate limit exceeded; try again in a minute".to_owned(),
                    None,
                )
            })
    }

    #[allow(clippy::unused_async)]
    async fn react_to_auth_expiry(
        &self,
        ctx: &RequestContext<RoleServer>,
        result: &mut Result<rmcp::model::CallToolResult, ErrorData>,
    ) {
        let Err(error) = result else { return };
        if error.code.0 != audit::AUTH_EXPIRED_CODE {
            return;
        }
        if let Some(AccessToken(token)) = token_from_ctx(ctx) {
            self.caldav.evict(&token);
            self.logto.drop_token(&token);
        }
        *error = ErrorData::new(
            rmcp::model::ErrorCode(audit::AUTH_EXPIRED_CODE),
            "Your caldav-mcp session has expired or Stalwart rejected the Logto bearer. \
             Disconnect and reconnect caldav-mcp to obtain a fresh session. No Basic \
             credential fallback is available."
                .to_owned(),
            None,
        );
    }
}

pub fn identity_from_ctx(ctx: &RequestContext<RoleServer>) -> Option<AuthenticatedIdentity> {
    let parts = ctx.extensions.get::<http::request::Parts>()?;
    parts.extensions.get::<AuthenticatedIdentity>().cloned()
}

pub fn token_from_ctx(ctx: &RequestContext<RoleServer>) -> Option<AccessToken> {
    let parts = ctx.extensions.get::<http::request::Parts>()?;
    parts.extensions.get::<AccessToken>().cloned()
}

fn structured_result<T: Serialize>(value: &T) -> Result<rmcp::model::CallToolResult, ErrorData> {
    let value = serde_json::to_value(value).map_err(|error| {
        ErrorData::internal_error(format!("serialize tool result: {error}"), None)
    })?;
    Ok(rmcp::model::CallToolResult::structured(value))
}

fn missing_identity_err() -> ErrorData {
    ErrorData::internal_error("no authenticated identity in request context", None)
}

fn missing_token_err() -> ErrorData {
    ErrorData::internal_error("no access token in request context", None)
}

fn map_caldav_err(error: CaldavError) -> ErrorData {
    match error {
        CaldavError::Unauthorized => ErrorData::new(
            rmcp::model::ErrorCode(audit::AUTH_EXPIRED_CODE),
            "Stalwart rejected the Logto bearer".to_owned(),
            None,
        ),
        CaldavError::InvalidHref
        | CaldavError::InvalidInput(_)
        | CaldavError::NotFound
        | CaldavError::Conflict => ErrorData::invalid_params(error.to_string(), None),
        other => ErrorData::internal_error(other.to_string(), None),
    }
}

fn make_tool_span(tool: &'static str, user: &str, resource: Option<&str>) -> Span {
    let user_hash = (!user.is_empty()).then(|| audit::identity_hash(user));
    let resource_hash = resource
        .map(audit::sanitize_resource_id)
        .map(audit::resource_hash);
    tracing::info_span!(
        "mcp.tool",
        tool,
        user_hash,
        resource_hash,
        outcome = tracing::field::Empty,
        latency_ms = tracing::field::Empty,
    )
}

fn emit_tool_audit(
    tool: &'static str,
    user: &str,
    resource: Option<&str>,
    started: Instant,
    result_count: Option<usize>,
    span: &Span,
    result: &Result<rmcp::model::CallToolResult, ErrorData>,
) {
    let (outcome_value, error_class) = match result {
        Ok(_) => (outcome::OK, None),
        Err(error) => {
            let outcome_value = if error.code.0 == audit::RATE_LIMITED_CODE {
                outcome::RATE_LIMITED
            } else {
                outcome::ERROR
            };
            (outcome_value, Some(audit::error_class(error)))
        }
    };
    span.record("outcome", outcome_value);
    span.record(
        "latency_ms",
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    );
    audit::tool_call(
        tool,
        user,
        resource,
        outcome_value,
        started,
        result_count,
        error_class,
    );
}

fn user_label(identity: Option<&AuthenticatedIdentity>) -> String {
    identity
        .and_then(|value| value.email.clone())
        .or_else(|| identity.map(|value| value.user_id.clone()))
        .unwrap_or_default()
}

fn default_timezone() -> String {
    DEFAULT_TIMEZONE.to_owned()
}

#[derive(Debug, Serialize)]
struct WhoamiResult {
    user_id: String,
    email: Option<String>,
    name: Option<String>,
    principal_href: String,
    calendar_home_href: String,
    default_timezone: &'static str,
}

#[derive(Debug, Serialize)]
struct CalendarsResult {
    calendars: Vec<Calendar>,
}

#[derive(Debug, Serialize)]
struct EventsResult {
    events: Vec<Event>,
}

#[derive(Debug, Serialize)]
struct EventResult {
    event: Event,
}

#[derive(Debug, Serialize)]
struct DeleteResult {
    deleted: bool,
    event_href: String,
}

#[derive(Debug, Serialize)]
struct FreeBusyResult {
    intervals: Vec<BusyInterval>,
    timezone: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListEventsParams {
    /// Calendar href returned by `list_calendars`.
    calendar_href: String,
    /// Inclusive window start: RFC 3339, local YYYY-MM-DDTHH:MM:SS, or YYYY-MM-DD.
    start: String,
    /// Exclusive window end: RFC 3339, local YYYY-MM-DDTHH:MM:SS, or YYYY-MM-DD.
    end: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SearchEventsParams {
    /// Calendar href returned by `list_calendars`.
    calendar_href: String,
    /// Inclusive window start.
    start: String,
    /// Exclusive window end.
    end: String,
    /// Case-insensitive text matched against summary, description, location, organizer, and attendees.
    query: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateEventParams {
    /// Calendar href returned by `list_calendars`.
    calendar_href: String,
    summary: String,
    /// RFC 3339, local YYYY-MM-DDTHH:MM:SS, or YYYY-MM-DD for an all-day event.
    start: String,
    /// Exclusive end. Use the following date for a one-day all-day event.
    end: String,
    /// IANA timezone for offset-free local timestamps.
    #[serde(default = "default_timezone")]
    timezone: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    attendees: Vec<String>,
    /// Optional RFC 5545 RRULE beginning with FREQ=.
    #[serde(default)]
    recurrence_rule: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateEventParams {
    /// Event href returned by `list_events` or `search_events`.
    event_href: String,
    /// `ETag` returned by `list_events`. If omitted, caldav-mcp fetches the current `ETag` first.
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
    /// IANA timezone for offset-free replacement timestamps.
    #[serde(default)]
    timezone: Option<String>,
    /// Empty string clears the field; omission preserves it.
    #[serde(default)]
    description: Option<String>,
    /// Empty string clears the field; omission preserves it.
    #[serde(default)]
    location: Option<String>,
    /// Empty array clears attendees; omission preserves them.
    #[serde(default)]
    attendees: Option<Vec<String>>,
    /// TENTATIVE, CONFIRMED, or CANCELLED.
    #[serde(default)]
    status: Option<String>,
    /// Empty string removes recurrence; omission preserves it.
    #[serde(default)]
    recurrence_rule: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DeleteEventParams {
    /// Event href returned by `list_events` or `search_events`.
    event_href: String,
    /// Optional `ETag` for optimistic concurrency.
    #[serde(default)]
    etag: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FreeBusyParams {
    /// Calendar hrefs to include. Empty means every calendar returned by `list_calendars`.
    #[serde(default)]
    calendar_hrefs: Vec<String>,
    /// Inclusive window start.
    start: String,
    /// Exclusive window end.
    end: String,
    /// Display timezone label for the result; event instants remain RFC 3339 UTC.
    #[serde(default = "default_timezone")]
    timezone: String,
}

#[tool_router(router = caldav_router)]
impl CaldavMcpService {
    #[tool(
        description = "Verify the authenticated Logto identity against Stalwart CalDAV and return the principal and calendar-home hrefs.",
        annotations(title = "Who am I", read_only_hint = true, idempotent_hint = true)
    )]
    async fn whoami(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let identity = identity_from_ctx(&ctx);
        let user = user_label(identity.as_ref());
        let span = make_tool_span("whoami", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let discovery = self
                .caldav
                .discover(&token.0)
                .await
                .map_err(map_caldav_err)?;
            let identity = identity.ok_or_else(missing_identity_err)?;
            structured_result(&WhoamiResult {
                user_id: identity.user_id,
                email: identity.email,
                name: identity.name.or(discovery.display_name),
                principal_href: discovery.principal_href,
                calendar_home_href: discovery.calendar_home_href,
                default_timezone: DEFAULT_TIMEZONE,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit("whoami", &user, None, started, None, &span, &result);
        result
    }

    #[tool(
        description = "List every VEVENT-capable calendar belonging to the authenticated user.",
        annotations(
            title = "List calendars",
            read_only_hint = true,
            idempotent_hint = true
        )
    )]
    async fn list_calendars(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let identity = identity_from_ctx(&ctx);
        let user = user_label(identity.as_ref());
        let span = make_tool_span("list_calendars", &user, None);
        let (mut result, count) = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let calendars = self
                .caldav
                .list_calendars(&token.0)
                .await
                .map_err(map_caldav_err)?;
            let count = calendars.len();
            Ok::<_, ErrorData>((structured_result(&CalendarsResult { calendars }), count))
        }
        .instrument(span.clone())
        .await
        .unwrap_or_else(|error| (Err(error), 0));
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "list_calendars",
            &user,
            None,
            started,
            Some(count),
            &span,
            &result,
        );
        result
    }

    #[tool(
        description = "List events in one calendar whose instances overlap a time window. Recurrences are expanded by the CalDAV server.",
        annotations(title = "List events", read_only_hint = true, idempotent_hint = true)
    )]
    async fn list_events(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListEventsParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let identity = identity_from_ctx(&ctx);
        let user = user_label(identity.as_ref());
        let resource = params.calendar_href.clone();
        let span = make_tool_span("list_events", &user, Some(&resource));
        let (mut result, count) = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let events = self
                .caldav
                .list_events(&token.0, &params.calendar_href, &params.start, &params.end)
                .await
                .map_err(map_caldav_err)?;
            let count = events.len();
            Ok::<_, ErrorData>((structured_result(&EventsResult { events }), count))
        }
        .instrument(span.clone())
        .await
        .unwrap_or_else(|error| (Err(error), 0));
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "list_events",
            &user,
            Some(&resource),
            started,
            Some(count),
            &span,
            &result,
        );
        result
    }

    #[tool(
        description = "Search event text within one calendar and a required time window.",
        annotations(title = "Search events", read_only_hint = true, idempotent_hint = true)
    )]
    async fn search_events(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SearchEventsParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let identity = identity_from_ctx(&ctx);
        let user = user_label(identity.as_ref());
        let resource = params.calendar_href.clone();
        let span = make_tool_span("search_events", &user, Some(&resource));
        let (mut result, count) = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            if params.query.trim().is_empty() {
                return Err(ErrorData::invalid_params("query must not be empty", None));
            }
            if params.query.len() > 1024 {
                return Err(ErrorData::invalid_params(
                    "query must not exceed 1024 bytes",
                    None,
                ));
            }
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let events = self
                .caldav
                .search_events(
                    &token.0,
                    &params.calendar_href,
                    &params.start,
                    &params.end,
                    &params.query,
                )
                .await
                .map_err(map_caldav_err)?;
            let count = events.len();
            Ok::<_, ErrorData>((structured_result(&EventsResult { events }), count))
        }
        .instrument(span.clone())
        .await
        .unwrap_or_else(|error| (Err(error), 0));
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "search_events",
            &user,
            Some(&resource),
            started,
            Some(count),
            &span,
            &result,
        );
        result
    }

    #[tool(
        description = "Create an event in a calendar. Offset-free date-times default to Asia/Singapore; all-day event ends are exclusive.",
        annotations(
            title = "Create event",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn create_event(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<CreateEventParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let identity = identity_from_ctx(&ctx);
        let user = user_label(identity.as_ref());
        let resource = params.calendar_href.clone();
        let span = make_tool_span("create_event", &user, Some(&resource));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            if params.summary.trim().is_empty() {
                return Err(ErrorData::invalid_params("summary must not be empty", None));
            }
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let event = self
                .caldav
                .create_event(
                    &token.0,
                    &params.calendar_href,
                    &NewEvent {
                        summary: params.summary,
                        start: params.start,
                        end: params.end,
                        timezone: params.timezone,
                        description: params.description,
                        location: params.location,
                        attendees: params.attendees,
                        recurrence_rule: params.recurrence_rule,
                    },
                )
                .await
                .map_err(map_caldav_err)?;
            structured_result(&EventResult { event })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "create_event",
            &user,
            Some(&resource),
            started,
            result.is_ok().then_some(1),
            &span,
            &result,
        );
        result
    }

    #[tool(
        description = "Patch an existing event while preserving unmodified iCalendar properties and alarms. Uses ETag concurrency control.",
        annotations(
            title = "Update event",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn update_event(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpdateEventParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let identity = identity_from_ctx(&ctx);
        let user = user_label(identity.as_ref());
        let resource = params.event_href.clone();
        let span = make_tool_span("update_event", &user, Some(&resource));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let event = self
                .caldav
                .update_event(
                    &token.0,
                    &params.event_href,
                    params.etag.as_deref(),
                    &EventPatch {
                        summary: params.summary,
                        start: params.start,
                        end: params.end,
                        timezone: params.timezone,
                        description: params.description,
                        location: params.location,
                        attendees: params.attendees,
                        status: params.status,
                        recurrence_rule: params.recurrence_rule,
                    },
                )
                .await
                .map_err(map_caldav_err)?;
            structured_result(&EventResult { event })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "update_event",
            &user,
            Some(&resource),
            started,
            result.is_ok().then_some(1),
            &span,
            &result,
        );
        result
    }

    #[tool(
        description = "Delete an event by href, optionally guarded by its ETag.",
        annotations(
            title = "Delete event",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true
        )
    )]
    async fn delete_event(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<DeleteEventParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let identity = identity_from_ctx(&ctx);
        let user = user_label(identity.as_ref());
        let resource = params.event_href.clone();
        let span = make_tool_span("delete_event", &user, Some(&resource));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            self.caldav
                .delete_event(&token.0, &params.event_href, params.etag.as_deref())
                .await
                .map_err(map_caldav_err)?;
            structured_result(&DeleteResult {
                deleted: true,
                event_href: params.event_href,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "delete_event",
            &user,
            Some(&resource),
            started,
            result.is_ok().then_some(1),
            &span,
            &result,
        );
        result
    }

    #[tool(
        description = "Return busy event intervals across selected calendars for a time window. Cancelled and transparent events are excluded.",
        annotations(title = "Free busy", read_only_hint = true, idempotent_hint = true)
    )]
    async fn free_busy(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<FreeBusyParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let identity = identity_from_ctx(&ctx);
        let user = user_label(identity.as_ref());
        let span = make_tool_span("free_busy", &user, None);
        let (mut result, count) = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            params.timezone.parse::<chrono_tz::Tz>().map_err(|_| {
                ErrorData::invalid_params(format!("unknown timezone {:?}", params.timezone), None)
            })?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let calendar_hrefs = if params.calendar_hrefs.is_empty() {
                self.caldav
                    .list_calendars(&token.0)
                    .await
                    .map_err(map_caldav_err)?
                    .into_iter()
                    .map(|calendar| calendar.href)
                    .collect()
            } else {
                params.calendar_hrefs
            };
            let intervals = self
                .caldav
                .free_busy(&token.0, &calendar_hrefs, &params.start, &params.end)
                .await
                .map_err(map_caldav_err)?;
            let count = intervals.len();
            Ok::<_, ErrorData>((
                structured_result(&FreeBusyResult {
                    intervals,
                    timezone: params.timezone,
                }),
                count,
            ))
        }
        .instrument(span.clone())
        .await
        .unwrap_or_else(|error| (Err(error), 0));
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "free_busy",
            &user,
            None,
            started,
            Some(count),
            &span,
            &result,
        );
        result
    }
}

// rmcp's macro emits an async trait method even though `get_info` itself has
// no asynchronous work. Rust 1.98's `unused_async_trait_impl` lint sees the
// generated method. Older supported compilers do not know that lint, so allow
// an unknown lint only at this macro boundary before naming the narrow Clippy
// allowance.
#[allow(unknown_lints)]
#[allow(clippy::unused_async_trait_impl)]
#[tool_handler(router = self.tool_router)]
impl ServerHandler for CaldavMcpService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "caldav-mcp manages the authenticated user's Stalwart calendars through CalDAV. \
             Call list_calendars before event tools and use the returned same-origin hrefs. \
             Times without an explicit offset default to Asia/Singapore. The Logto bearer is \
             forwarded to Stalwart; no Basic or shared credential path exists.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_timezone_is_singapore() {
        assert_eq!(default_timezone(), "Asia/Singapore");
    }
}
