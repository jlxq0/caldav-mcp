//! Minimal CalDAV/WebDAV client for Stalwart.
//!
//! The caller's validated Logto bearer is forwarded verbatim on every request.
//! No Basic credentials, app passwords, refresh tokens, or calendar data are
//! stored by this service.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone as _, Utc};
use chrono_tz::Tz;
use futures::StreamExt as _;
use reqwest::header::{ACCEPT, CONTENT_TYPE, ETAG, HeaderMap, HeaderName, HeaderValue, LOCATION};
use reqwest::{Method, StatusCode};
use roxmltree::{Document, Node};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

#[allow(unknown_lints)]
#[allow(clippy::duration_suboptimal_units)]
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
const DISCOVERY_CAP: usize = 256;
const MAX_REDIRECTS: usize = 4;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_WINDOW_DAYS: i64 = 366;
const MAX_SUMMARY_BYTES: usize = 1024;
const MAX_DESCRIPTION_BYTES: usize = 256 * 1024;
const MAX_LOCATION_BYTES: usize = 8 * 1024;
const MAX_ATTENDEES: usize = 200;
const MAX_RECURRENCE_RULE_BYTES: usize = 2048;
const MAX_FREE_BUSY_CALENDARS: usize = 256;
const DEFAULT_TIMEZONE: &str = "Asia/Singapore";

#[derive(Debug, Error)]
pub enum CaldavError {
    #[error("not authenticated to Stalwart (bearer rejected or expired)")]
    Unauthorized,
    #[error("CalDAV transport error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("CalDAV endpoint returned HTTP {status}")]
    Upstream { status: u16 },
    #[error("CalDAV resource was not found")]
    NotFound,
    #[error("CalDAV write conflict (ETag or resource precondition failed)")]
    Conflict,
    #[error("unsafe or cross-origin DAV href")]
    InvalidHref,
    #[error("invalid CalDAV input: {0}")]
    InvalidInput(String),
    #[error("invalid CalDAV XML: {0}")]
    Xml(String),
    #[error("CalDAV response exceeded the 16 MiB safety limit")]
    ResponseTooLarge,
    #[error("CalDAV response was not valid UTF-8")]
    InvalidEncoding,
    #[error("CalDAV discovery response omitted {0}")]
    MissingProperty(&'static str),
    /// The write would have made Stalwart send iTIP mail. There is no way to
    /// suppress it for a `PUT`: `Schedule-Reply: F` is parsed but only
    /// consulted on `DELETE`, and `SCHEDULE-AGENT=CLIENT` is persistent data
    /// that would also silence every later legitimate update. So the operation
    /// refuses and names everyone it would have written to.
    #[error(
        "this event has attendees, so the write would send them calendar mail that cannot be \
         recalled: {}. Assume every one of them is written to — the only address Stalwart \
         suppresses is the authenticated account's own. Pass send_scheduling_messages=true to \
         proceed",
        .0.join(", ")
    )]
    SchedulingRefused(Vec<String>),
}

#[derive(Clone, Debug, Serialize)]
pub struct Discovery {
    pub principal_href: String,
    pub calendar_home_href: String,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Calendar {
    pub href: String,
    pub name: String,
    pub color: Option<String>,
    pub ctag: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub href: String,
    pub etag: Option<String>,
    pub uid: Option<String>,
    pub summary: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub timezone: Option<String>,
    pub all_day: bool,
    pub description: Option<String>,
    pub location: Option<String>,
    pub status: Option<String>,
    pub transparency: Option<String>,
    pub organizer: Option<String>,
    pub attendees: Vec<String>,
    pub recurrence_rule: Option<String>,
    /// `RECURRENCE-ID` normalised to a UTC instant for display. **Not usable
    /// for building an `EXDATE`:** an exclusion has to carry the same value
    /// type and `TZID` the `RRULE` generates, and a UTC instant matches
    /// nothing when the series is floating or has a `TZID`. Use the three
    /// verbatim fields below for that.
    pub recurrence_id: Option<String>,
    /// `RECURRENCE-ID`'s value exactly as the server wrote it, e.g.
    /// `20260901T090000` or `20260901` for an all-day series.
    pub recurrence_id_value: Option<String>,
    /// The `TZID` parameter on `RECURRENCE-ID`, absent for UTC and floating
    /// values.
    pub recurrence_id_tzid: Option<String>,
    /// The `RANGE` parameter on `RECURRENCE-ID`, normally `THISANDFUTURE`.
    /// Surfaced rather than dropped: an override carrying it applies to the
    /// occurrence *and every later one*, and a caller that cannot see it
    /// treats a this-and-future override as a single-instance one.
    pub recurrence_id_range: Option<String>,
    /// True when this component is an override rather than the master. `href`
    /// is the master resource either way — every component of a series lives
    /// in one calendar object — so there is no separate `master_href`: a
    /// second field that can never differ from `href` is a second source that
    /// can only agree.
    pub is_override: bool,
    /// `EXDATE` entries on this component, verbatim. Absent from expanded
    /// instances, because RFC 4791 §9.6.5 requires the server to strip
    /// recurrence properties when expanding; fetch the object unexpanded to
    /// see them.
    pub exdates: Vec<RecurrenceDate>,
    /// `RDATE` entries on this component, verbatim. An `EXDATE` alone is
    /// ambiguous when a series also carries `RDATE`s, so both are surfaced.
    pub rdates: Vec<RecurrenceDate>,
}

/// One `EXDATE` or `RDATE` entry, kept in the form the server wrote it.
///
/// A rendered UTC instant is not interchangeable with this: an exclusion has
/// to match the occurrence as the `RRULE` generates it, same value type and
/// same `TZID`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RecurrenceDate {
    /// The value as written, e.g. `20260901T090000` or `20260901`.
    pub value: String,
    /// The `TZID` parameter, absent for UTC and floating values.
    pub tzid: Option<String>,
    /// True when the property carried `VALUE=DATE`, i.e. an all-day series.
    pub is_date: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BusyInterval {
    pub start: String,
    pub end: String,
    pub calendar_href: String,
    pub event_href: String,
    pub summary: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NewEvent {
    /// The authenticated principal, written as `ORGANIZER` when the event has
    /// attendees.
    ///
    /// RFC 6638 scheduling keys on `ORGANIZER`: an object carrying `ATTENDEE`
    /// and no `ORGANIZER` is not a scheduling object, so Stalwart correctly
    /// generates no iTIP and the event invites nobody. Every signal after the
    /// write says it worked, which is why this is a field rather than a
    /// convention.
    pub organizer: Option<String>,
    pub summary: String,
    pub start: String,
    pub end: String,
    pub timezone: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub attendees: Vec<String>,
    pub recurrence_rule: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct EventPatch {
    pub summary: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub timezone: Option<String>,
    pub description: Option<String>,
    pub location: Option<String>,
    pub attendees: Option<Vec<String>>,
    pub status: Option<String>,
    pub recurrence_rule: Option<String>,
}

#[derive(Clone)]
pub struct CaldavClient {
    http: reqwest::Client,
    base_url: Url,
    discoveries: Arc<RwLock<HashMap<[u8; 32], CachedDiscovery>>>,
}

#[derive(Clone)]
struct CachedDiscovery {
    value: Discovery,
    cached_at: Instant,
}

impl std::fmt::Debug for CaldavClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaldavClient")
            .field("base_url", &self.base_url.as_str())
            .finish_non_exhaustive()
    }
}

struct DavResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

#[derive(Clone, Debug)]
enum Temporal {
    Date(NaiveDate),
    Instant(DateTime<Utc>),
}

impl CaldavClient {
    pub fn new(stalwart_base: &str, connect_ip: Option<&str>) -> Result<Self> {
        let base_url = Url::parse(stalwart_base)
            .context("CALDAV_MCP_STALWART_DAV_BASE_URL is not a valid URL")?;
        if !matches!(base_url.scheme(), "http" | "https") || base_url.host_str().is_none() {
            anyhow::bail!("CALDAV_MCP_STALWART_DAV_BASE_URL must be an absolute http(s) URL");
        }
        if !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            anyhow::bail!(
                "CALDAV_MCP_STALWART_DAV_BASE_URL must not contain user info, a query, or a fragment"
            );
        }

        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("caldav-mcp/", env!("CARGO_PKG_VERSION")));
        if let Some(ip) = connect_ip {
            let host = base_url
                .host_str()
                .context("Stalwart DAV base URL has no host")?;
            let addr: std::net::IpAddr = ip
                .parse()
                .context("CALDAV_MCP_STALWART_CONNECT_IP is not a valid IP")?;
            let port = base_url.port_or_known_default().unwrap_or(443);
            builder = builder.resolve(host, std::net::SocketAddr::new(addr, port));
        }

        Ok(Self {
            http: builder.build().context("build CalDAV HTTP client")?,
            base_url,
            discoveries: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn discover(&self, token: &str) -> Result<Discovery, CaldavError> {
        let key = hash_token(token);
        if let Some(value) = self.discovery_lookup(&key) {
            return Ok(value);
        }

        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:current-user-principal/>
    <c:calendar-home-set/>
    <d:displayname/>
  </d:prop>
</d:propfind>"#;

        let mut last_status = None;
        for path in ["/.well-known/caldav", "/dav/"] {
            let url = self.path_url(path)?;
            let response = self
                .dav_request(
                    token,
                    propfind_method(),
                    url,
                    Some(body),
                    "application/xml",
                    &[("Depth", "0")],
                )
                .await?;
            if response.status == StatusCode::NOT_FOUND {
                last_status = Some(response.status.as_u16());
                continue;
            }
            if !response.status.is_success() {
                return Err(CaldavError::Upstream {
                    status: response.status.as_u16(),
                });
            }

            let document =
                Document::parse(&response.body).map_err(|e| CaldavError::Xml(e.to_string()))?;
            let principal_href = descendant_href(&document, "current-user-principal");
            let calendar_home_href = descendant_href(&document, "calendar-home-set");
            if let (Some(principal_href), Some(calendar_home_href)) =
                (principal_href.clone(), calendar_home_href)
            {
                let value = Discovery {
                    principal_href,
                    calendar_home_href,
                    display_name: first_text(&document, "displayname"),
                };
                self.discovery_insert(key, &value);
                return Ok(value);
            }

            let principal_href =
                principal_href.ok_or(CaldavError::MissingProperty("current-user-principal"))?;
            let principal_url = self.resolve_href(&principal_href)?;
            let principal_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop><c:calendar-home-set/><d:displayname/></d:prop>
</d:propfind>"#;
            let principal = self
                .dav_request(
                    token,
                    propfind_method(),
                    principal_url,
                    Some(principal_body),
                    "application/xml",
                    &[("Depth", "0")],
                )
                .await?;
            if !principal.status.is_success() {
                return Err(CaldavError::Upstream {
                    status: principal.status.as_u16(),
                });
            }
            let document =
                Document::parse(&principal.body).map_err(|e| CaldavError::Xml(e.to_string()))?;
            let value = Discovery {
                principal_href,
                calendar_home_href: descendant_href(&document, "calendar-home-set")
                    .ok_or(CaldavError::MissingProperty("calendar-home-set"))?,
                display_name: first_text(&document, "displayname"),
            };
            self.discovery_insert(key, &value);
            return Ok(value);
        }

        Err(CaldavError::Upstream {
            status: last_status.unwrap_or(404),
        })
    }

    pub async fn list_calendars(&self, token: &str) -> Result<Vec<Calendar>, CaldavError> {
        let discovery = self.discover(token).await?;
        let url = self.resolve_href(&discovery.calendar_home_href)?;
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"
 xmlns:cs="http://calendarserver.org/ns/" xmlns:x="http://apple.com/ns/ical/">
  <d:prop>
    <d:resourcetype/>
    <d:displayname/>
    <c:supported-calendar-component-set/>
    <cs:getctag/>
    <x:calendar-color/>
  </d:prop>
</d:propfind>"#;
        let response = self
            .dav_request(
                token,
                propfind_method(),
                url,
                Some(body),
                "application/xml",
                &[("Depth", "1")],
            )
            .await?;
        Self::require_success(&response)?;
        parse_calendars_xml(&response.body)
    }

    pub async fn list_events(
        &self,
        token: &str,
        calendar_href: &str,
        start: &str,
        end: &str,
    ) -> Result<Vec<Event>, CaldavError> {
        let start = parse_input_temporal(start, DEFAULT_TIMEZONE)?;
        let end = parse_input_temporal(end, DEFAULT_TIMEZONE)?;
        let (start_utc, end_utc) = temporal_range(&start, &end, DEFAULT_TIMEZONE)?;
        if end_utc <= start_utc {
            return Err(CaldavError::InvalidInput(
                "end must be later than start".to_owned(),
            ));
        }
        if end_utc - start_utc > chrono::Duration::days(MAX_WINDOW_DAYS) {
            return Err(CaldavError::InvalidInput(format!(
                "time window must not exceed {MAX_WINDOW_DAYS} days"
            )));
        }
        let start_dav = format_dav_utc(start_utc);
        let end_dav = format_dav_utc(end_utc);
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:getetag/>
    <c:calendar-data><c:expand start="{start_dav}" end="{end_dav}"/></c:calendar-data>
  </d:prop>
  <c:filter>
    <c:comp-filter name="VCALENDAR">
      <c:comp-filter name="VEVENT">
        <c:time-range start="{start_dav}" end="{end_dav}"/>
      </c:comp-filter>
    </c:comp-filter>
  </c:filter>
</c:calendar-query>"#
        );
        let url = self.resolve_href(calendar_href)?;
        let response = self
            .dav_request(
                token,
                report_method(),
                url,
                Some(&body),
                "application/xml",
                &[("Depth", "1")],
            )
            .await?;
        Self::require_success(&response)?;
        parse_events_xml(&response.body)
    }

    pub async fn search_events(
        &self,
        token: &str,
        calendar_href: &str,
        start: &str,
        end: &str,
        query: &str,
    ) -> Result<Vec<Event>, CaldavError> {
        let query = query.to_lowercase();
        let events = self.list_events(token, calendar_href, start, end).await?;
        Ok(events
            .into_iter()
            .filter(|event| {
                [
                    event.summary.as_deref(),
                    event.description.as_deref(),
                    event.location.as_deref(),
                    event.organizer.as_deref(),
                ]
                .into_iter()
                .flatten()
                .chain(event.attendees.iter().map(String::as_str))
                .any(|value| value.to_lowercase().contains(&query))
            })
            .collect())
    }

    pub async fn create_event(
        &self,
        token: &str,
        calendar_href: &str,
        event: &NewEvent,
    ) -> Result<Event, CaldavError> {
        validate_timezone(&event.timezone)?;
        let uid = generate_uid();
        let ics = build_new_ics(&uid, event)?;
        let mut calendar_url = self.resolve_href(calendar_href)?;
        if !calendar_url.path().ends_with('/') {
            let path = format!("{}/", calendar_url.path());
            calendar_url.set_path(&path);
        }
        let event_file_id = uid.strip_prefix("urn:uuid:").unwrap_or(&uid);
        let event_url = calendar_url
            .join(&format!("{event_file_id}.ics"))
            .map_err(|_| CaldavError::InvalidHref)?;
        self.ensure_same_origin(&event_url)?;
        let response = self
            .dav_request(
                token,
                Method::PUT,
                event_url.clone(),
                Some(&ics),
                "text/calendar; charset=utf-8",
                &[("If-None-Match", "*")],
            )
            .await?;
        match response.status {
            StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT => {}
            StatusCode::PRECONDITION_FAILED => return Err(CaldavError::Conflict),
            _ => Self::require_success(&response)?,
        }
        let href = event_url.path().to_owned();
        let mut parsed = parse_ical_event(&ics, &href)?;
        parsed.etag = response
            .headers
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        Ok(parsed)
    }

    /// The calendar object exactly as stored, with its `ETag`.
    ///
    /// `list_events` reports expanded instances, and RFC 4791 §9.6.5 requires
    /// a server to strip `RRULE`, `EXDATE` and `RDATE` when expanding, so the
    /// master's recurrence properties are unreachable through it. This is the
    /// unexpanded read those properties live in, and it is the same `GET`
    /// `update_event` already performs before patching.
    pub async fn get_event_raw(
        &self,
        token: &str,
        event_href: &str,
    ) -> Result<(String, Option<String>, Vec<Event>), CaldavError> {
        let url = self.resolve_event_href(event_href)?;
        let response = self
            .dav_request(token, Method::GET, url, None, "text/calendar", &[])
            .await?;
        match response.status {
            StatusCode::NOT_FOUND => return Err(CaldavError::NotFound),
            _ => Self::require_success(&response)?,
        }
        let etag = response
            .headers
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let components = parse_ical_events(&response.body, event_href)?;
        Ok((response.body, etag, components))
    }

    /// Exclude one occurrence from a recurring series: add its `EXDATE` to the
    /// master and drop its override, in one `PUT`.
    ///
    /// The `EXDATE`'s value type and `TZID` come from the master's `DTSTART`,
    /// not from the caller. `recurrence_id` is trusted as given — this does not
    /// expand the `RRULE` to check the occurrence exists, because we have no
    /// expander, and the tool description says so rather than implying a
    /// validation that does not happen.
    pub async fn delete_occurrence(
        &self,
        token: &str,
        event_href: &str,
        recurrence_id: &str,
        etag: Option<&str>,
        allow_scheduling: bool,
    ) -> Result<Exclusion, CaldavError> {
        let (ics, current_etag, _) = self.get_event_raw(token, event_href).await?;
        let exclusion = exclude_occurrence(&ics, recurrence_id, allow_scheduling)?;
        let Some(updated) = exclusion.ics.clone() else {
            return Ok(exclusion);
        };
        let effective_etag = etag.map(ToOwned::to_owned).or(current_etag);
        let mut headers = Vec::new();
        if let Some(ref value) = effective_etag {
            headers.push(("If-Match", normalize_etag(value)));
        }
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        let url = self.resolve_event_href(event_href)?;
        let response = self
            .dav_request(
                token,
                Method::PUT,
                url,
                Some(&updated),
                "text/calendar; charset=utf-8",
                &header_refs,
            )
            .await?;
        match response.status {
            StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT => Ok(exclusion),
            StatusCode::PRECONDITION_FAILED => Err(CaldavError::Conflict),
            StatusCode::NOT_FOUND => Err(CaldavError::NotFound),
            _ => {
                Self::require_success(&response)?;
                Ok(exclusion)
            }
        }
    }

    pub async fn update_event(
        &self,
        token: &str,
        event_href: &str,
        etag: Option<&str>,
        patch: &EventPatch,
    ) -> Result<Event, CaldavError> {
        let url = self.resolve_event_href(event_href)?;
        let current = self
            .dav_request(token, Method::GET, url.clone(), None, "text/calendar", &[])
            .await?;
        match current.status {
            StatusCode::NOT_FOUND => return Err(CaldavError::NotFound),
            _ => Self::require_success(&current)?,
        }

        let effective_etag = etag.map(ToOwned::to_owned).or_else(|| {
            current
                .headers
                .get(ETAG)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        });
        let updated_ics = patch_ics(&current.body, patch)?;
        let mut headers = Vec::new();
        if let Some(ref value) = effective_etag {
            headers.push(("If-Match", normalize_etag(value)));
        }
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        let response = self
            .dav_request(
                token,
                Method::PUT,
                url,
                Some(&updated_ics),
                "text/calendar; charset=utf-8",
                &header_refs,
            )
            .await?;
        match response.status {
            StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT => {}
            StatusCode::PRECONDITION_FAILED => return Err(CaldavError::Conflict),
            StatusCode::NOT_FOUND => return Err(CaldavError::NotFound),
            _ => Self::require_success(&response)?,
        }
        let mut event = parse_ical_event(&updated_ics, event_href)?;
        event.etag = response
            .headers
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        Ok(event)
    }

    pub async fn delete_event(
        &self,
        token: &str,
        event_href: &str,
        etag: Option<&str>,
    ) -> Result<(), CaldavError> {
        let url = self.resolve_event_href(event_href)?;
        // A same-origin href is not enough evidence that DELETE targets an
        // event: WebDAV DELETE on a collection can be recursive. Read and
        // parse the target as a VEVENT before issuing the destructive method.
        let current = self
            .dav_request(token, Method::GET, url.clone(), None, "text/calendar", &[])
            .await?;
        match current.status {
            StatusCode::NOT_FOUND => return Err(CaldavError::NotFound),
            _ => Self::require_success(&current)?,
        }
        parse_ical_event(&current.body, event_href)?;
        let effective_etag = etag.map(ToOwned::to_owned).or_else(|| {
            current
                .headers
                .get(ETAG)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        });
        let mut headers = Vec::new();
        if let Some(value) = effective_etag.as_deref() {
            headers.push(("If-Match", normalize_etag(value)));
        }
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        let response = self
            .dav_request(
                token,
                Method::DELETE,
                url,
                None,
                "text/calendar",
                &header_refs,
            )
            .await?;
        match response.status {
            StatusCode::OK | StatusCode::NO_CONTENT => Ok(()),
            StatusCode::NOT_FOUND => Err(CaldavError::NotFound),
            StatusCode::PRECONDITION_FAILED => Err(CaldavError::Conflict),
            _ => {
                Self::require_success(&response)?;
                Ok(())
            }
        }
    }

    pub async fn free_busy(
        &self,
        token: &str,
        calendar_hrefs: &[String],
        start: &str,
        end: &str,
    ) -> Result<Vec<BusyInterval>, CaldavError> {
        let mut seen = HashSet::new();
        let mut unique_hrefs = Vec::new();
        for calendar_href in calendar_hrefs {
            if seen.insert(calendar_href.as_str()) {
                unique_hrefs.push(calendar_href);
                if unique_hrefs.len() > MAX_FREE_BUSY_CALENDARS {
                    return Err(CaldavError::InvalidInput(format!(
                        "free_busy accepts at most {MAX_FREE_BUSY_CALENDARS} unique calendars"
                    )));
                }
            }
        }

        let mut busy = Vec::new();
        for calendar_href in unique_hrefs {
            let events = self.list_events(token, calendar_href, start, end).await?;
            for event in events {
                if event.status.as_deref() == Some("CANCELLED")
                    || event.transparency.as_deref() == Some("TRANSPARENT")
                {
                    continue;
                }
                let (Some(start), Some(end)) = (event.start.clone(), event.end.clone()) else {
                    continue;
                };
                busy.push(BusyInterval {
                    start,
                    end,
                    calendar_href: calendar_href.clone(),
                    event_href: event.href,
                    summary: event.summary,
                });
            }
        }
        busy.sort_by(|left, right| {
            left.start
                .cmp(&right.start)
                .then_with(|| left.end.cmp(&right.end))
        });
        Ok(busy)
    }

    pub fn evict(&self, token: &str) {
        let key = hash_token(token);
        if let Ok(mut guard) = self.discoveries.write() {
            guard.remove(&key);
        }
    }

    async fn dav_request(
        &self,
        token: &str,
        method: Method,
        mut url: Url,
        body: Option<&str>,
        content_type: &str,
        headers: &[(&str, &str)],
    ) -> Result<DavResponse, CaldavError> {
        self.ensure_same_origin(&url)?;
        for redirect_count in 0..=MAX_REDIRECTS {
            let mut request = self
                .http
                .request(method.clone(), url.clone())
                .bearer_auth(token)
                .header(ACCEPT, "application/xml, text/calendar, */*")
                .header(CONTENT_TYPE, content_type);
            for (name, value) in headers {
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| CaldavError::InvalidInput(e.to_string()))?;
                let value = HeaderValue::from_str(value)
                    .map_err(|e| CaldavError::InvalidInput(e.to_string()))?;
                request = request.header(name, value);
            }
            if let Some(body) = body {
                request = request.body(body.to_owned());
            }
            let response = request.send().await?;
            let status = response.status();
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                self.evict(token);
                return Err(CaldavError::Unauthorized);
            }
            if status.is_redirection() {
                if redirect_count == MAX_REDIRECTS {
                    return Err(CaldavError::Upstream {
                        status: status.as_u16(),
                    });
                }
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or(CaldavError::InvalidHref)?;
                url = url.join(location).map_err(|_| CaldavError::InvalidHref)?;
                self.ensure_same_origin(&url)?;
                continue;
            }
            let headers = response.headers().clone();
            if response
                .content_length()
                .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
            {
                return Err(CaldavError::ResponseTooLarge);
            }
            let mut bytes = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                    return Err(CaldavError::ResponseTooLarge);
                }
                bytes.extend_from_slice(&chunk);
            }
            let body = String::from_utf8(bytes).map_err(|_| CaldavError::InvalidEncoding)?;
            return Ok(DavResponse {
                status,
                headers,
                body,
            });
        }
        Err(CaldavError::InvalidHref)
    }

    fn require_success(response: &DavResponse) -> Result<(), CaldavError> {
        if response.status.is_success() {
            Ok(())
        } else {
            Err(CaldavError::Upstream {
                status: response.status.as_u16(),
            })
        }
    }

    fn path_url(&self, path: &str) -> Result<Url, CaldavError> {
        self.base_url
            .join(path)
            .map_err(|_| CaldavError::InvalidHref)
    }

    fn resolve_href(&self, href: &str) -> Result<Url, CaldavError> {
        if href.starts_with("//") {
            return Err(CaldavError::InvalidHref);
        }
        let url = self
            .base_url
            .join(href)
            .map_err(|_| CaldavError::InvalidHref)?;
        self.ensure_same_origin(&url)?;
        Ok(url)
    }

    fn resolve_event_href(&self, href: &str) -> Result<Url, CaldavError> {
        let url = self.resolve_href(href)?;
        if url.query().is_some()
            || url.path().ends_with('/')
            || url
                .path_segments()
                .and_then(Iterator::last)
                .is_none_or(str::is_empty)
        {
            return Err(CaldavError::InvalidHref);
        }
        Ok(url)
    }

    fn ensure_same_origin(&self, url: &Url) -> Result<(), CaldavError> {
        if url.scheme() == self.base_url.scheme()
            && url.host_str() == self.base_url.host_str()
            && url.port_or_known_default() == self.base_url.port_or_known_default()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
        {
            Ok(())
        } else {
            Err(CaldavError::InvalidHref)
        }
    }

    fn discovery_lookup(&self, key: &[u8; 32]) -> Option<Discovery> {
        let guard = self.discoveries.read().ok()?;
        let value = guard.get(key).and_then(|entry| {
            (entry.cached_at.elapsed() < DISCOVERY_TTL).then(|| entry.value.clone())
        });
        drop(guard);
        value
    }

    fn discovery_insert(&self, key: [u8; 32], value: &Discovery) {
        let Ok(mut guard) = self.discoveries.write() else {
            return;
        };
        if guard.len() >= DISCOVERY_CAP {
            guard.retain(|_, entry| entry.cached_at.elapsed() < DISCOVERY_TTL);
        }
        if guard.len() >= DISCOVERY_CAP
            && let Some(oldest) = guard
                .iter()
                .max_by_key(|(_, entry)| entry.cached_at.elapsed())
                .map(|(key, _)| *key)
        {
            guard.remove(&oldest);
        }
        guard.insert(
            key,
            CachedDiscovery {
                value: value.clone(),
                cached_at: Instant::now(),
            },
        );
    }
}

fn propfind_method() -> Method {
    Method::from_bytes(b"PROPFIND").unwrap_or(Method::GET)
}

fn report_method() -> Method {
    Method::from_bytes(b"REPORT").unwrap_or(Method::GET)
}

fn hash_token(token: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(token.as_bytes());
    digest.finalize().into()
}

fn first_text(document: &Document<'_>, local_name: &str) -> Option<String> {
    document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == local_name)
        .and_then(|node| node.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn descendant_href(document: &Document<'_>, property: &str) -> Option<String> {
    document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == property)
        .and_then(|node| {
            node.descendants()
                .find(|child| child.is_element() && child.tag_name().name() == "href")
        })
        .and_then(|node| node.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn response_property_text(response: Node<'_, '_>, local_name: &str) -> Option<String> {
    response
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == local_name)
        .and_then(|node| node.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_calendars_xml(xml: &str) -> Result<Vec<Calendar>, CaldavError> {
    let document = Document::parse(xml).map_err(|e| CaldavError::Xml(e.to_string()))?;
    let mut calendars = Vec::new();
    for response in document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "response")
    {
        let is_calendar = response
            .descendants()
            .any(|node| node.is_element() && node.tag_name().name() == "calendar");
        let supports_events = response.descendants().any(|node| {
            node.is_element()
                && node.tag_name().name() == "comp"
                && node
                    .attribute("name")
                    .is_some_and(|value| value.eq_ignore_ascii_case("VEVENT"))
        });
        if !is_calendar && !supports_events {
            continue;
        }
        let Some(href) = response_property_text(response, "href") else {
            continue;
        };
        calendars.push(Calendar {
            href,
            name: response_property_text(response, "displayname")
                .unwrap_or_else(|| "Calendar".to_owned()),
            color: response_property_text(response, "calendar-color")
                .map(|value| value.chars().take(7).collect()),
            ctag: response_property_text(response, "getctag"),
        });
    }
    calendars.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(calendars)
}

fn parse_events_xml(xml: &str) -> Result<Vec<Event>, CaldavError> {
    let document = Document::parse(xml).map_err(|e| CaldavError::Xml(e.to_string()))?;
    let mut events = Vec::new();
    for response in document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "response")
    {
        let Some(calendar_data) = response_property_text(response, "calendar-data") else {
            continue;
        };
        let href = response_property_text(response, "href").unwrap_or_default();
        let etag = response_property_text(response, "getetag");
        for mut event in parse_ical_events(&calendar_data, &href)? {
            event.etag.clone_from(&etag);
            events.push(event);
        }
    }
    events.sort_by(|left, right| left.start.cmp(&right.start));
    Ok(events)
}

fn parse_ical_events(ics: &str, href: &str) -> Result<Vec<Event>, CaldavError> {
    let lines = unfold_ical_lines(ics);
    let mut events = Vec::new();
    let mut current = Vec::new();
    let mut inside = false;
    for line in lines {
        if line.eq_ignore_ascii_case("BEGIN:VEVENT") {
            inside = true;
            current.clear();
            continue;
        }
        if line.eq_ignore_ascii_case("END:VEVENT") {
            if inside {
                events.push(event_from_lines(&current, href.to_owned())?);
            }
            inside = false;
            current.clear();
            continue;
        }
        if inside {
            current.push(line);
        }
    }
    Ok(events)
}

/// The master component of a calendar object, or the first one if every
/// component is an override. Never simply the first: see
/// [`master_event_start`] for what that cost.
fn parse_ical_event(ics: &str, href: &str) -> Result<Event, CaldavError> {
    let events = parse_ical_events(ics, href)?;
    events
        .iter()
        .find(|event| event.recurrence_id.is_none())
        .or_else(|| events.first())
        .cloned()
        .ok_or_else(|| CaldavError::InvalidInput("calendar object has no VEVENT".to_owned()))
}

/// `EXDATE`/`RDATE` entries, one per value: both properties may repeat and
/// each may carry a comma-separated list, and the parameters belong to the
/// property rather than to any one value.
/// Outcome of excluding one occurrence from a series.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exclusion {
    /// The calendar object to `PUT`, or `None` when the occurrence was already
    /// excluded and there is nothing to write.
    pub ics: Option<String>,
    /// True when an `EXDATE` for this occurrence was already present.
    pub already_excluded: bool,
    /// True when an override component for this occurrence was removed in the
    /// same write. Leaving it behind orphans it: clients show an occurrence
    /// the series says does not exist.
    pub removed_override: bool,
    /// The `EXDATE` entry as written, so the caller can see the value type and
    /// `TZID` it was given rather than the one it asked for.
    pub exdate: RecurrenceDate,
}

/// Add an `EXDATE` for one occurrence and drop its override, in one write.
///
/// `recurrence_id` is the occurrence's **original** start, verbatim, as
/// `RECURRENCE-ID` or the `RRULE` generates it — never a moved start and never
/// a rendered UTC instant. The value type and `TZID` are taken from the
/// master's `DTSTART` rather than from the caller, because RFC 5545 requires
/// an `EXDATE` to match the generated occurrence exactly and a mismatch is
/// accepted by the server and then excludes nothing.
fn exclude_occurrence(
    ics: &str,
    recurrence_id: &str,
    allow_scheduling: bool,
) -> Result<Exclusion, CaldavError> {
    let recurrence_id = recurrence_id.trim();
    if recurrence_id.is_empty() {
        return Err(CaldavError::InvalidInput(
            "recurrence_id must be the occurrence's original start, e.g. 20260901T090000"
                .to_owned(),
        ));
    }
    let mut lines = unfold_ical_lines(ics);
    if !allow_scheduling {
        let attendees = all_attendees(&lines);
        if !attendees.is_empty() {
            return Err(CaldavError::SchedulingRefused(attendees));
        }
    }
    let Some(master_start) = master_event_start(&lines) else {
        return Err(CaldavError::InvalidInput(
            "calendar object has no VEVENT".to_owned(),
        ));
    };
    let master = event_lines(&lines);
    let master_properties = direct_event_properties(&master);
    let Some((dtstart_head, _dtstart_value)) = master_properties.iter().find_map(|line| {
        let (head, value) = line.split_once(':')?;
        property_name(head)
            .eq_ignore_ascii_case("DTSTART")
            .then_some((head, value))
    }) else {
        return Err(CaldavError::InvalidInput(
            "series master has no DTSTART".to_owned(),
        ));
    };
    if master_properties.iter().all(|line| {
        line.split_once(':')
            .is_none_or(|(head, _)| !property_name(head).eq_ignore_ascii_case("RRULE"))
    }) && !master_properties.iter().any(|line| {
        line.split_once(':')
            .is_some_and(|(head, _)| property_name(head).eq_ignore_ascii_case("RDATE"))
    }) {
        return Err(CaldavError::InvalidInput(
            "event is not recurring: it has neither RRULE nor RDATE".to_owned(),
        ));
    }

    // `DTSTART`'s zone, for a date-time exclusion. Its value type is no longer
    // consulted: the exclusion is shaped to the caller's value, and Stalwart
    // matches by instant rather than by literal form.
    let tzid = parameter_value(dtstart_head, "TZID").map(ToOwned::to_owned);
    validate_exclusion_target(&lines, recurrence_id)?;

    let already_excluded = recurrence_dates(&master_properties, "EXDATE")
        .iter()
        .any(|date| date.value == recurrence_id);
    let removed_override = remove_override(&mut lines, recurrence_id);
    let target_is_date = recurrence_id.len() == 8 && !recurrence_id.contains('T');
    let exdate = RecurrenceDate {
        value: recurrence_id.to_owned(),
        tzid: if target_is_date { None } else { tzid.clone() },
        is_date: target_is_date,
    };
    if already_excluded && !removed_override {
        return Ok(Exclusion {
            ics: None,
            already_excluded,
            removed_override,
            exdate,
        });
    }
    if !already_excluded {
        // Shaped to the value the caller gave, not blindly to `DTSTART`'s
        // parameters. A date under a `TZID=` head is malformed iCalendar, and
        // that combination becomes reachable now that a value type differing
        // from `DTSTART` is no longer refused. Stalwart matches by instant, so
        // either well-formed shape excludes the right occurrence; what it
        // cannot do is repair a property that is not well formed.
        let head = match (&tzid, target_is_date) {
            (_, true) => "EXDATE;VALUE=DATE".to_owned(),
            (Some(tzid), false) => format!("EXDATE;TZID={tzid}"),
            (None, false) => "EXDATE".to_owned(),
        };
        let insertion = master_event_start(&lines).unwrap_or(master_start) + 1;
        lines.insert(insertion, format!("{head}:{recurrence_id}"));
    }
    replace_event_property(
        &mut lines,
        "DTSTAMP",
        vec![format!("DTSTAMP:{}", format_dav_utc(Utc::now()))],
    );
    increment_sequence(&mut lines);
    Ok(Exclusion {
        ics: Some(format!("{}\r\n", lines.join("\r\n"))),
        already_excluded,
        removed_override,
        exdate,
    })
}

/// The three ways an exclusion is wrong before it is written, each of which
/// the server would otherwise accept and then not act on.
/// The one way an exclusion is wrong before it is written that survived
/// measurement.
///
/// Two others did not, and both were removed on 2026-09-02 rather than kept as
/// belt and braces, because each was justified by a claim about the server that
/// the run refuted (`#16`, `issuecomment-17026`):
///
/// * **A value type differing from `DTSTART` was refused** on the grounds that
///   it "excludes nothing". It excludes: `EXDATE:20260903T000000Z` removes an
///   occurrence of an all-day series, and `EXDATE:20260908T010000Z` removes one
///   from a series whose `DTSTART` carries `TZID=Asia/Singapore`. **Stalwart
///   matches an exclusion by instant, not by literal form.**
/// * **The series' first occurrence was refused** on the grounds that "some
///   servers treat `DTSTART` as implicitly included". Not this one: an `EXDATE`
///   for the first occurrence removed it, leaving five of six.
///
/// What survives is not a claim about the server. `RANGE=THISANDFUTURE` names a
/// different operation, so excluding that occurrence is not the thing the
/// caller asked for whatever the server would do with it.
fn validate_exclusion_target(lines: &[String], recurrence_id: &str) -> Result<(), CaldavError> {
    if let Some(range) = override_range(lines, recurrence_id) {
        return Err(CaldavError::InvalidInput(format!(
            "the override for {recurrence_id} carries RANGE={range}, which applies to that \
             occurrence and every later one. Excluding it is not the same operation and is not \
             supported"
        )));
    }
    Ok(())
}

/// Every `ATTENDEE` in the object, master and overrides alike.
///
/// All of them, and assume all of them are mailed. `send_update_messages()`
/// skips only `email.is_local`, and `is_local` is exact membership of the
/// *authenticated account's own* address set — its addresses and its groups'
/// — not the domains the server hosts. Another mailbox on the same Stalwart is
/// not local to this account and does receive an iMIP. Naming too many is
/// recoverable; naming too few puts mail in a stranger's inbox.
fn all_attendees(lines: &[String]) -> Vec<String> {
    let mut attendees = Vec::new();
    for line in lines {
        let Some((head, value)) = line.split_once(':') else {
            continue;
        };
        if property_name(head).eq_ignore_ascii_case("ATTENDEE") {
            let address = strip_mailto(&unescape_ical(value));
            if !attendees.contains(&address) {
                attendees.push(address);
            }
        }
    }
    attendees
}

/// The `RANGE` parameter on the override for `recurrence_id`, if there is one.
fn override_range(lines: &[String], recurrence_id: &str) -> Option<String> {
    lines.iter().find_map(|line| {
        let (head, value) = line.split_once(':')?;
        (property_name(head).eq_ignore_ascii_case("RECURRENCE-ID") && value.trim() == recurrence_id)
            .then(|| parameter_value(head, "RANGE").map(str::to_uppercase))
            .flatten()
    })
}

/// Remove the `VEVENT` whose `RECURRENCE-ID` value is `recurrence_id`.
fn remove_override(lines: &mut Vec<String>, recurrence_id: &str) -> bool {
    let mut start = None;
    let mut matches = false;
    let mut index = 0;
    while index < lines.len() {
        if lines[index].eq_ignore_ascii_case("BEGIN:VEVENT") {
            start = Some(index);
            matches = false;
        } else if lines[index].eq_ignore_ascii_case("END:VEVENT") {
            if matches && let Some(start) = start {
                lines.drain(start..=index);
                return true;
            }
            start = None;
        } else if start.is_some()
            && let Some((head, value)) = lines[index].split_once(':')
            && property_name(head).eq_ignore_ascii_case("RECURRENCE-ID")
            && value.trim() == recurrence_id
        {
            matches = true;
        }
        index += 1;
    }
    false
}

fn recurrence_dates(lines: &[String], name: &str) -> Vec<RecurrenceDate> {
    let mut dates = Vec::new();
    for line in lines {
        let Some((head, value)) = line.split_once(':') else {
            continue;
        };
        if !property_name(head).eq_ignore_ascii_case(name) {
            continue;
        }
        let tzid = parameter_value(head, "TZID").map(ToOwned::to_owned);
        let is_date =
            parameter_value(head, "VALUE").is_some_and(|value| value.eq_ignore_ascii_case("DATE"));
        for entry in value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            dates.push(RecurrenceDate {
                value: entry.to_owned(),
                tzid: tzid.clone(),
                is_date: is_date || (entry.len() == 8 && !entry.contains('T')),
            });
        }
    }
    dates
}

fn event_from_lines(lines: &[String], href: String) -> Result<Event, CaldavError> {
    let direct_lines = direct_event_properties(lines);
    let lines = direct_lines.as_slice();
    let property = |name: &str| -> Option<(&str, &str)> {
        lines.iter().find_map(|line| {
            let (head, value) = line.split_once(':')?;
            property_name(head)
                .eq_ignore_ascii_case(name)
                .then_some((head, value))
        })
    };
    let values = |name: &str| -> Vec<String> {
        lines
            .iter()
            .filter_map(|line| {
                let (head, value) = line.split_once(':')?;
                property_name(head)
                    .eq_ignore_ascii_case(name)
                    .then(|| unescape_ical(value))
            })
            .collect()
    };

    let start_parsed = property("DTSTART")
        .map(|(head, value)| parse_ical_temporal(head, value))
        .transpose()?;
    let end_parsed = property("DTEND")
        .map(|(head, value)| parse_ical_temporal(head, value))
        .transpose()?;
    let timezone = property("DTSTART")
        .and_then(|(head, _)| parameter_value(head, "TZID"))
        .map(ToOwned::to_owned)
        .or_else(|| start_parsed.as_ref().and_then(temporal_timezone));
    let all_day = matches!(start_parsed, Some(Temporal::Date(_)));

    Ok(Event {
        href,
        etag: None,
        uid: property("UID").map(|(_, value)| unescape_ical(value)),
        summary: property("SUMMARY").map(|(_, value)| unescape_ical(value)),
        start: start_parsed.as_ref().map(render_temporal),
        end: end_parsed.as_ref().map(render_temporal),
        timezone,
        all_day,
        description: property("DESCRIPTION").map(|(_, value)| unescape_ical(value)),
        location: property("LOCATION").map(|(_, value)| unescape_ical(value)),
        status: property("STATUS").map(|(_, value)| value.to_uppercase()),
        transparency: property("TRANSP").map(|(_, value)| value.to_uppercase()),
        organizer: property("ORGANIZER").map(|(_, value)| strip_mailto(value)),
        attendees: values("ATTENDEE")
            .into_iter()
            .map(|value| strip_mailto(&value))
            .collect(),
        recurrence_rule: property("RRULE").map(|(_, value)| value.to_owned()),
        recurrence_id: property("RECURRENCE-ID")
            .map(|(head, value)| parse_ical_temporal(head, value))
            .transpose()?
            .as_ref()
            .map(render_temporal),
        recurrence_id_value: property("RECURRENCE-ID").map(|(_, value)| value.to_owned()),
        recurrence_id_tzid: property("RECURRENCE-ID")
            .and_then(|(head, _)| parameter_value(head, "TZID"))
            .map(ToOwned::to_owned),
        recurrence_id_range: property("RECURRENCE-ID")
            .and_then(|(head, _)| parameter_value(head, "RANGE"))
            .map(str::to_uppercase),
        is_override: property("RECURRENCE-ID").is_some(),
        exdates: recurrence_dates(lines, "EXDATE"),
        rdates: recurrence_dates(lines, "RDATE"),
    })
}

fn build_new_ics(uid: &str, event: &NewEvent) -> Result<String, CaldavError> {
    validate_event_content(
        &event.summary,
        event.description.as_deref(),
        event.location.as_deref(),
        &event.attendees,
        event.recurrence_rule.as_deref(),
    )?;
    let start = parse_input_temporal(&event.start, &event.timezone)?;
    let end = parse_input_temporal(&event.end, &event.timezone)?;
    validate_temporal_pair(&start, &end, &event.timezone)?;
    let mut lines = vec![
        "BEGIN:VCALENDAR".to_owned(),
        "VERSION:2.0".to_owned(),
        "PRODID:-//Oddie//caldav-mcp//EN".to_owned(),
        "CALSCALE:GREGORIAN".to_owned(),
        "BEGIN:VEVENT".to_owned(),
        format!("UID:{}", escape_ical(uid)),
        format!("DTSTAMP:{}", format_dav_utc(Utc::now())),
        temporal_property("DTSTART", &start),
        temporal_property("DTEND", &end),
        format!("SUMMARY:{}", escape_ical(&event.summary)),
    ];
    if let Some(description) = &event.description {
        lines.push(format!("DESCRIPTION:{}", escape_ical(description)));
    }
    if let Some(location) = &event.location {
        lines.push(format!("LOCATION:{}", escape_ical(location)));
    }
    if !event.attendees.is_empty() {
        // Only when there are attendees. Writing `ORGANIZER` on a solo event
        // would make every event this tool creates a scheduling object in
        // Stalwart's eyes, which changes what later edits do rather than
        // fixing what this one does.
        let organizer = event
            .organizer
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CaldavError::InvalidInput(
                    "cannot invite attendees without an organizer: the authenticated token \
                     carries no email claim, and an event with ATTENDEE and no ORGANIZER is not \
                     a scheduling object, so it would be created having invited nobody"
                        .to_owned(),
                )
            })?;
        validate_attendee(organizer)?;
        lines.push(format!("ORGANIZER:mailto:{}", escape_ical(organizer)));
    }
    for attendee in &event.attendees {
        validate_attendee(attendee)?;
        lines.push(format!("ATTENDEE:mailto:{}", escape_ical(attendee)));
    }
    if let Some(rule) = &event.recurrence_rule {
        validate_recurrence_rule(rule)?;
        lines.push(format!("RRULE:{}", rule.trim()));
    }
    lines.push("END:VEVENT".to_owned());
    lines.push("END:VCALENDAR".to_owned());
    Ok(format!("{}\r\n", lines.join("\r\n")))
}

#[allow(clippy::too_many_lines)]
fn patch_ics(ics: &str, patch: &EventPatch) -> Result<String, CaldavError> {
    let mut lines = unfold_ical_lines(ics);
    if !lines
        .iter()
        .any(|line| line.eq_ignore_ascii_case("BEGIN:VEVENT"))
    {
        return Err(CaldavError::InvalidInput(
            "calendar object has no VEVENT".to_owned(),
        ));
    }
    let timezone = patch.timezone.as_deref().unwrap_or(DEFAULT_TIMEZONE);
    validate_timezone(timezone)?;
    if let Some(summary) = &patch.summary
        && summary.len() > MAX_SUMMARY_BYTES
    {
        return Err(CaldavError::InvalidInput(format!(
            "summary exceeds {MAX_SUMMARY_BYTES} bytes"
        )));
    }
    validate_optional_length(
        "description",
        patch.description.as_deref(),
        MAX_DESCRIPTION_BYTES,
    )?;
    validate_optional_length("location", patch.location.as_deref(), MAX_LOCATION_BYTES)?;
    validate_optional_length(
        "recurrence_rule",
        patch.recurrence_rule.as_deref(),
        MAX_RECURRENCE_RULE_BYTES,
    )?;
    if patch
        .attendees
        .as_ref()
        .is_some_and(|values| values.len() > MAX_ATTENDEES)
    {
        return Err(CaldavError::InvalidInput(format!(
            "attendees exceeds {MAX_ATTENDEES} entries"
        )));
    }

    if let Some(summary) = &patch.summary {
        replace_event_property(
            &mut lines,
            "SUMMARY",
            vec![format!("SUMMARY:{}", escape_ical(summary))],
        );
    }
    if let Some(start) = &patch.start {
        let temporal = parse_input_temporal(start, timezone)?;
        replace_event_property(
            &mut lines,
            "DTSTART",
            vec![temporal_property("DTSTART", &temporal)],
        );
    }
    if let Some(end) = &patch.end {
        let temporal = parse_input_temporal(end, timezone)?;
        replace_event_property(
            &mut lines,
            "DTEND",
            vec![temporal_property("DTEND", &temporal)],
        );
    }
    if patch.start.is_some() || patch.end.is_some() {
        let event = event_from_lines(&event_lines(&lines), String::new())?;
        let start = event
            .start
            .ok_or_else(|| CaldavError::InvalidInput("event has no DTSTART".to_owned()))?;
        let end = event
            .end
            .ok_or_else(|| CaldavError::InvalidInput("event has no DTEND".to_owned()))?;
        let start = parse_input_temporal(&start, timezone)?;
        let end = parse_input_temporal(&end, timezone)?;
        validate_temporal_pair(&start, &end, timezone)?;
    }
    if let Some(description) = &patch.description {
        replace_event_property(
            &mut lines,
            "DESCRIPTION",
            vec![format!("DESCRIPTION:{}", escape_ical(description))],
        );
    }
    if let Some(location) = &patch.location {
        replace_event_property(
            &mut lines,
            "LOCATION",
            vec![format!("LOCATION:{}", escape_ical(location))],
        );
    }
    if let Some(attendees) = &patch.attendees {
        let mut values = Vec::with_capacity(attendees.len());
        for attendee in attendees {
            validate_attendee(attendee)?;
            values.push(format!("ATTENDEE:mailto:{}", escape_ical(attendee)));
        }
        replace_event_property(&mut lines, "ATTENDEE", values);
    }
    if let Some(status) = &patch.status {
        let status = status.to_uppercase();
        if !matches!(status.as_str(), "TENTATIVE" | "CONFIRMED" | "CANCELLED") {
            return Err(CaldavError::InvalidInput(
                "status must be TENTATIVE, CONFIRMED, or CANCELLED".to_owned(),
            ));
        }
        replace_event_property(&mut lines, "STATUS", vec![format!("STATUS:{status}")]);
    }
    if let Some(rule) = &patch.recurrence_rule {
        if rule.is_empty() {
            replace_event_property(&mut lines, "RRULE", Vec::new());
        } else {
            validate_recurrence_rule(rule)?;
            replace_event_property(&mut lines, "RRULE", vec![format!("RRULE:{}", rule.trim())]);
        }
    }
    replace_event_property(
        &mut lines,
        "DTSTAMP",
        vec![format!("DTSTAMP:{}", format_dav_utc(Utc::now()))],
    );
    increment_sequence(&mut lines);
    Ok(format!("{}\r\n", lines.join("\r\n")))
}

/// Index of the `BEGIN:VEVENT` line starting the master component — the one
/// with no `RECURRENCE-ID`.
///
/// A calendar object for a recurring series holds the master and one `VEVENT`
/// per override, in no guaranteed order (RFC 5545 does not require the master
/// to come first). Anchoring on the first `BEGIN:VEVENT` meant a `PUT` could
/// rename one occurrence while reporting that it had renamed the series, and
/// the caller saw a success with `recurrence_rule: null`.
///
/// Falls back to the first `VEVENT` when every component carries a
/// `RECURRENCE-ID`, which is a resource we cannot patch coherently anyway.
fn master_event_start(lines: &[String]) -> Option<usize> {
    let mut first = None;
    let mut current = None;
    let mut nested_depth = 0_u32;
    let mut has_recurrence_id = false;
    for (index, line) in lines.iter().enumerate() {
        if line.eq_ignore_ascii_case("BEGIN:VEVENT") {
            current = Some(index);
            first = first.or(Some(index));
            nested_depth = 0;
            has_recurrence_id = false;
            continue;
        }
        if line.eq_ignore_ascii_case("END:VEVENT") {
            if current.is_some() && !has_recurrence_id {
                return current;
            }
            current = None;
            continue;
        }
        if current.is_none() {
            continue;
        }
        if line.starts_with("BEGIN:") {
            nested_depth = nested_depth.saturating_add(1);
            continue;
        }
        if line.starts_with("END:") && nested_depth > 0 {
            nested_depth = nested_depth.saturating_sub(1);
            continue;
        }
        if nested_depth == 0
            && line
                .split_once(':')
                .is_some_and(|(head, _)| property_name(head).eq_ignore_ascii_case("RECURRENCE-ID"))
        {
            has_recurrence_id = true;
        }
    }
    first
}

fn event_lines(lines: &[String]) -> Vec<String> {
    let Some(start) = master_event_start(lines) else {
        return Vec::new();
    };
    let mut event = Vec::new();
    for line in lines.iter().skip(start + 1) {
        if line.eq_ignore_ascii_case("END:VEVENT") {
            break;
        }
        event.push(line.clone());
    }
    event
}

fn direct_event_properties(lines: &[String]) -> Vec<String> {
    let mut properties = Vec::new();
    let mut nested_depth = 0_u32;
    for line in lines {
        if line.starts_with("BEGIN:") {
            nested_depth = nested_depth.saturating_add(1);
            continue;
        }
        if line.starts_with("END:") && nested_depth > 0 {
            nested_depth = nested_depth.saturating_sub(1);
            continue;
        }
        if nested_depth == 0 {
            properties.push(line.clone());
        }
    }
    properties
}

fn replace_event_property(lines: &mut Vec<String>, name: &str, replacement: Vec<String>) {
    let Some(start) = master_event_start(lines) else {
        return;
    };
    let mut inside = false;
    let mut nested_depth = 0_u32;
    let mut insertion = None;
    let mut index = start;
    while index < lines.len() {
        if index == start && lines[index].eq_ignore_ascii_case("BEGIN:VEVENT") {
            inside = true;
            index += 1;
            continue;
        }
        if inside && lines[index].eq_ignore_ascii_case("END:VEVENT") {
            insertion = Some(index);
            break;
        }
        if inside && lines[index].starts_with("BEGIN:") {
            nested_depth = nested_depth.saturating_add(1);
            index += 1;
            continue;
        }
        if inside && lines[index].starts_with("END:") && nested_depth > 0 {
            nested_depth = nested_depth.saturating_sub(1);
            index += 1;
            continue;
        }
        if inside
            && nested_depth == 0
            && lines[index]
                .split_once(':')
                .is_some_and(|(head, _)| property_name(head).eq_ignore_ascii_case(name))
        {
            lines.remove(index);
            continue;
        }
        index += 1;
    }
    let insertion = insertion.unwrap_or(lines.len());
    for (offset, line) in replacement.into_iter().enumerate() {
        lines.insert(insertion + offset, line);
    }
}

fn increment_sequence(lines: &mut Vec<String>) {
    let current = event_lines(lines)
        .iter()
        .find_map(|line| {
            let (head, value) = line.split_once(':')?;
            property_name(head)
                .eq_ignore_ascii_case("SEQUENCE")
                .then(|| value.parse::<u64>().ok())
                .flatten()
        })
        .unwrap_or(0)
        .saturating_add(1);
    replace_event_property(lines, "SEQUENCE", vec![format!("SEQUENCE:{current}")]);
}

fn unfold_ical_lines(ics: &str) -> Vec<String> {
    let normalized = ics.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<String> = Vec::new();
    for line in normalized.split('\n') {
        if (line.starts_with(' ') || line.starts_with('\t')) && !lines.is_empty() {
            if let Some(previous) = lines.last_mut() {
                previous.push_str(&line[1..]);
            }
        } else if !line.is_empty() {
            lines.push(line.to_owned());
        }
    }
    lines
}

fn property_name(head: &str) -> &str {
    head.split(';').next().unwrap_or(head)
}

fn parameter_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split(';').skip(1).find_map(|parameter| {
        let (key, value) = parameter.split_once('=')?;
        key.eq_ignore_ascii_case(name)
            .then_some(value.trim_matches('"'))
    })
}

fn parse_ical_temporal(head: &str, value: &str) -> Result<Temporal, CaldavError> {
    let timezone = parameter_value(head, "TZID").unwrap_or(DEFAULT_TIMEZONE);
    if parameter_value(head, "VALUE").is_some_and(|value| value.eq_ignore_ascii_case("DATE"))
        || (value.len() == 8 && !value.contains('T'))
    {
        return NaiveDate::parse_from_str(value, "%Y%m%d")
            .map(Temporal::Date)
            .map_err(|_| CaldavError::InvalidInput(format!("invalid iCalendar date {value:?}")));
    }
    if let Some(value) = value.strip_suffix('Z') {
        return NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S")
            .map(|value| Temporal::Instant(value.and_utc()))
            .map_err(|_| {
                CaldavError::InvalidInput(format!("invalid UTC iCalendar timestamp {value:?}"))
            });
    }
    let naive = NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S").map_err(|_| {
        CaldavError::InvalidInput(format!("invalid local iCalendar timestamp {value:?}"))
    })?;
    Ok(Temporal::Instant(local_to_utc(naive, timezone)?))
}

fn parse_input_temporal(value: &str, timezone: &str) -> Result<Temporal, CaldavError> {
    let value = value.trim();
    if let Ok(date) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        return Ok(Temporal::Date(date));
    }
    if let Ok(timestamp) = DateTime::parse_from_rfc3339(value) {
        return Ok(Temporal::Instant(timestamp.with_timezone(&Utc)));
    }
    for format in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, format) {
            return Ok(Temporal::Instant(local_to_utc(naive, timezone)?));
        }
    }
    Err(CaldavError::InvalidInput(format!(
        "timestamp {value:?} must be RFC 3339, local YYYY-MM-DDTHH:MM:SS, or YYYY-MM-DD"
    )))
}

fn validate_temporal_pair(
    start: &Temporal,
    end: &Temporal,
    timezone: &str,
) -> Result<(), CaldavError> {
    if matches!(
        (start, end),
        (Temporal::Date(_), Temporal::Instant(_)) | (Temporal::Instant(_), Temporal::Date(_))
    ) {
        return Err(CaldavError::InvalidInput(
            "start and end must both be dates or both be date-times".to_owned(),
        ));
    }
    let (start, end) = temporal_range(start, end, timezone)?;
    if end <= start {
        return Err(CaldavError::InvalidInput(
            "end must be later than start".to_owned(),
        ));
    }
    Ok(())
}

fn temporal_range(
    start: &Temporal,
    end: &Temporal,
    timezone: &str,
) -> Result<(DateTime<Utc>, DateTime<Utc>), CaldavError> {
    Ok((
        temporal_to_utc(start, timezone)?,
        temporal_to_utc(end, timezone)?,
    ))
}

fn temporal_to_utc(value: &Temporal, timezone: &str) -> Result<DateTime<Utc>, CaldavError> {
    match value {
        Temporal::Instant(value) => Ok(*value),
        Temporal::Date(value) => local_to_utc(
            value
                .and_hms_opt(0, 0, 0)
                .ok_or_else(|| CaldavError::InvalidInput("invalid date".to_owned()))?,
            timezone,
        ),
    }
}

fn local_to_utc(value: NaiveDateTime, timezone: &str) -> Result<DateTime<Utc>, CaldavError> {
    let timezone: Tz = timezone
        .parse()
        .map_err(|_| CaldavError::InvalidInput(format!("unknown timezone {timezone:?}")))?;
    timezone
        .from_local_datetime(&value)
        .earliest()
        .map(|value| value.with_timezone(&Utc))
        .ok_or_else(|| {
            CaldavError::InvalidInput(format!(
                "local time {value} does not exist in timezone {timezone}"
            ))
        })
}

fn validate_timezone(timezone: &str) -> Result<(), CaldavError> {
    timezone
        .parse::<Tz>()
        .map(|_| ())
        .map_err(|_| CaldavError::InvalidInput(format!("unknown timezone {timezone:?}")))
}

fn temporal_property(name: &str, value: &Temporal) -> String {
    match value {
        Temporal::Date(value) => format!("{name};VALUE=DATE:{}", value.format("%Y%m%d")),
        Temporal::Instant(value) => format!("{name}:{}", format_dav_utc(*value)),
    }
}

fn render_temporal(value: &Temporal) -> String {
    match value {
        Temporal::Date(value) => value.format("%Y-%m-%d").to_string(),
        Temporal::Instant(value) => value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }
}

fn temporal_timezone(value: &Temporal) -> Option<String> {
    match value {
        Temporal::Date(_) => None,
        Temporal::Instant(_) => Some("UTC".to_owned()),
    }
}

fn format_dav_utc(value: DateTime<Utc>) -> String {
    value.format("%Y%m%dT%H%M%SZ").to_string()
}

fn escape_ical(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace("\r\n", "\\n")
        .replace(['\r', '\n'], "\\n")
}

fn unescape_ical(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        match chars.next() {
            Some('n' | 'N') => output.push('\n'),
            Some(next) => output.push(next),
            None => output.push('\\'),
        }
    }
    output
}

fn strip_mailto(value: &str) -> String {
    value
        .strip_prefix("mailto:")
        .or_else(|| value.strip_prefix("MAILTO:"))
        .unwrap_or(value)
        .to_owned()
}

fn validate_attendee(value: &str) -> Result<(), CaldavError> {
    let value = value.trim();
    let mut parts = value.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if value.is_empty()
        || value.len() > 320
        || local.is_empty()
        || domain.is_empty()
        || parts.next().is_some()
        || value.chars().any(char::is_whitespace)
        || value.contains(['\r', '\n', ':', ';', ',', '\\'])
    {
        return Err(CaldavError::InvalidInput(format!(
            "invalid attendee email {value:?}"
        )));
    }
    Ok(())
}

fn validate_event_content(
    summary: &str,
    description: Option<&str>,
    location: Option<&str>,
    attendees: &[String],
    recurrence_rule: Option<&str>,
) -> Result<(), CaldavError> {
    if summary.trim().is_empty() {
        return Err(CaldavError::InvalidInput(
            "summary must not be empty".to_owned(),
        ));
    }
    if summary.len() > MAX_SUMMARY_BYTES {
        return Err(CaldavError::InvalidInput(format!(
            "summary exceeds {MAX_SUMMARY_BYTES} bytes"
        )));
    }
    validate_optional_length("description", description, MAX_DESCRIPTION_BYTES)?;
    validate_optional_length("location", location, MAX_LOCATION_BYTES)?;
    if attendees.len() > MAX_ATTENDEES {
        return Err(CaldavError::InvalidInput(format!(
            "attendees exceeds {MAX_ATTENDEES} entries"
        )));
    }
    if let Some(rule) = recurrence_rule
        && rule.len() > MAX_RECURRENCE_RULE_BYTES
    {
        return Err(CaldavError::InvalidInput(format!(
            "recurrence_rule exceeds {MAX_RECURRENCE_RULE_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_optional_length(
    field: &str,
    value: Option<&str>,
    limit: usize,
) -> Result<(), CaldavError> {
    if value.is_some_and(|value| value.len() > limit) {
        return Err(CaldavError::InvalidInput(format!(
            "{field} exceeds {limit} bytes"
        )));
    }
    Ok(())
}

fn validate_recurrence_rule(value: &str) -> Result<(), CaldavError> {
    let value = value.trim();
    if value.contains(['\r', '\n']) || !value.starts_with("FREQ=") {
        return Err(CaldavError::InvalidInput(
            "recurrence_rule must be a single RFC 5545 RRULE beginning with FREQ=".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_etag(value: &str) -> String {
    let value = value.trim();
    if value.starts_with('"') || value.starts_with("W/\"") {
        value.to_owned()
    } else {
        format!("\"{value}\"")
    }
}

fn generate_uid() -> String {
    use rand::RngCore as _;

    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("urn:uuid:{}", hex::encode(bytes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn parses_calendar_multistatus() {
        let xml = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:response>
    <d:href>/dav/cal/julian/default/</d:href>
    <d:propstat><d:prop>
      <d:displayname>Personal</d:displayname>
      <d:resourcetype><d:collection/><c:calendar/></d:resourcetype>
      <c:supported-calendar-component-set><c:comp name="VEVENT"/></c:supported-calendar-component-set>
    </d:prop></d:propstat>
  </d:response>
</d:multistatus>"#;
        let calendars = parse_calendars_xml(xml).unwrap();
        assert_eq!(calendars.len(), 1);
        assert_eq!(calendars[0].name, "Personal");
        assert_eq!(calendars[0].href, "/dav/cal/julian/default/");
    }

    #[test]
    fn parses_folded_ical_event_and_timezone() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:one\r\nSUMMARY:A long \r\n title\r\nDTSTART;TZID=Asia/Singapore:20260817T090000\r\nDTEND;TZID=Asia/Singapore:20260817T100000\r\nATTENDEE;CN=Julian:mailto:julian@lindner.earth\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let event = parse_ical_event(ics, "/event.ics").unwrap();
        assert_eq!(event.summary.as_deref(), Some("A long title"));
        assert_eq!(event.start.as_deref(), Some("2026-08-17T01:00:00Z"));
        assert_eq!(event.timezone.as_deref(), Some("Asia/Singapore"));
        assert_eq!(event.attendees, vec!["julian@lindner.earth"]);
    }

    #[test]
    fn new_all_day_event_uses_exclusive_date_end() {
        let event = NewEvent {
            organizer: None,
            summary: "National Day".to_owned(),
            start: "2026-08-09".to_owned(),
            end: "2026-08-10".to_owned(),
            timezone: DEFAULT_TIMEZONE.to_owned(),
            description: None,
            location: None,
            attendees: Vec::new(),
            recurrence_rule: None,
        };
        let ics = build_new_ics("test@local", &event).unwrap();
        assert!(ics.contains("DTSTART;VALUE=DATE:20260809"));
        assert!(ics.contains("DTEND;VALUE=DATE:20260810"));
    }

    #[test]
    fn patch_preserves_alarm_and_increments_sequence() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:one\r\nSEQUENCE:2\r\nSUMMARY:Old\r\nDTSTART:20260817T010000Z\r\nDTEND:20260817T020000Z\r\nBEGIN:VALARM\r\nTRIGGER:-PT10M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let patched = patch_ics(
            ics,
            &EventPatch {
                summary: Some("New".to_owned()),
                ..EventPatch::default()
            },
        )
        .unwrap();
        assert!(patched.contains("SUMMARY:New"));
        assert!(patched.contains("SEQUENCE:3"));
        assert!(patched.contains("BEGIN:VALARM"));
    }

    #[test]
    fn patch_does_not_replace_nested_alarm_description() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:one\r\nSUMMARY:Old\r\nDTSTART:20260817T010000Z\r\nDTEND:20260817T020000Z\r\nBEGIN:VALARM\r\nDESCRIPTION:Reminder\r\nTRIGGER:-PT10M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let patched = patch_ics(
            ics,
            &EventPatch {
                description: Some("Meeting notes".to_owned()),
                ..EventPatch::default()
            },
        )
        .unwrap();
        assert!(patched.contains("DESCRIPTION:Meeting notes"));
        assert!(patched.contains("DESCRIPTION:Reminder"));
    }

    #[test]
    fn rejects_cross_origin_href() {
        let client = CaldavClient::new("https://dav.kampong.social", None).unwrap();
        assert!(matches!(
            client.resolve_href("https://evil.test/event.ics"),
            Err(CaldavError::InvalidHref)
        ));
    }

    #[test]
    fn rejects_same_origin_href_with_embedded_userinfo() {
        let client = CaldavClient::new("https://dav.kampong.social", None).unwrap();
        assert!(matches!(
            client.resolve_href("https://attacker@dav.kampong.social/event.ics"),
            Err(CaldavError::InvalidHref)
        ));
    }

    #[tokio::test]
    async fn rejects_oversized_event_window_before_request() {
        let client = CaldavClient::new("https://dav.kampong.social", None).unwrap();
        let result = client
            .list_events("token", "/dav/cal/u/default/", "2026-01-01", "2028-01-01")
            .await;
        assert!(matches!(result, Err(CaldavError::InvalidInput(_))));
    }

    #[test]
    fn normalizes_bare_etag() {
        assert_eq!(normalize_etag("abc"), "\"abc\"");
        assert_eq!(normalize_etag("\"abc\""), "\"abc\"");
        assert_eq!(normalize_etag("W/\"abc\""), "W/\"abc\"");
    }

    #[test]
    fn generated_uid_has_no_deployment_specific_domain() {
        let uid = generate_uid();
        assert!(uid.starts_with("urn:uuid:"));
        assert!(!uid.contains("kampong.social"));
    }

    #[test]
    fn discovery_cache_has_a_hard_cap() {
        let client = CaldavClient::new("https://dav.example.test", None).unwrap();
        let discovery = Discovery {
            principal_href: "/principals/u/".into(),
            calendar_home_href: "/dav/cal/u/".into(),
            display_name: None,
        };
        for i in 0..=DISCOVERY_CAP {
            client.discovery_insert(hash_token(&format!("token-{i}")), &discovery);
        }
        assert_eq!(client.discoveries.read().unwrap().len(), DISCOVERY_CAP);
    }

    #[tokio::test]
    async fn list_calendars_forwards_bearer_verbatim() {
        let server = MockServer::start().await;
        let discovery_xml = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:response><d:propstat><d:prop>
    <d:current-user-principal><d:href>/principals/u/</d:href></d:current-user-principal>
    <c:calendar-home-set><d:href>/dav/cal/u/</d:href></c:calendar-home-set>
  </d:prop></d:propstat></d:response>
</d:multistatus>"#;
        Mock::given(method("PROPFIND"))
            .and(path("/.well-known/caldav"))
            .and(header("authorization", "Bearer opaque-user-token"))
            .respond_with(ResponseTemplate::new(207).set_body_string(discovery_xml))
            .expect(1)
            .mount(&server)
            .await;
        let calendars_xml = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:response><d:href>/dav/cal/u/default/</d:href><d:propstat><d:prop>
    <d:displayname>Default</d:displayname>
    <d:resourcetype><d:collection/><c:calendar/></d:resourcetype>
    <c:supported-calendar-component-set><c:comp name="VEVENT"/></c:supported-calendar-component-set>
  </d:prop></d:propstat></d:response>
</d:multistatus>"#;
        Mock::given(method("PROPFIND"))
            .and(path("/dav/cal/u/"))
            .and(header("authorization", "Bearer opaque-user-token"))
            .and(header("depth", "1"))
            .respond_with(ResponseTemplate::new(207).set_body_string(calendars_xml))
            .expect(1)
            .mount(&server)
            .await;

        let client = CaldavClient::new(&server.uri(), None).unwrap();
        let calendars = client.list_calendars("opaque-user-token").await.unwrap();

        assert_eq!(calendars.len(), 1);
        assert_eq!(calendars[0].href, "/dav/cal/u/default/");
    }

    #[tokio::test]
    async fn create_event_uses_put_precondition_and_bearer() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path_regex(r"^/dav/cal/u/default/.+\.ics$"))
            .and(header("authorization", "Bearer per-user-token"))
            .and(header("if-none-match", "*"))
            .and(body_string_contains("SUMMARY:Planning"))
            .respond_with(ResponseTemplate::new(201).insert_header("etag", "\"new-tag\""))
            .expect(1)
            .mount(&server)
            .await;
        let client = CaldavClient::new(&server.uri(), None).unwrap();
        let event = client
            .create_event(
                "per-user-token",
                "/dav/cal/u/default/",
                &NewEvent {
                    organizer: None,
                    summary: "Planning".to_owned(),
                    start: "2026-08-18T09:00:00".to_owned(),
                    end: "2026-08-18T10:00:00".to_owned(),
                    timezone: "Asia/Singapore".to_owned(),
                    description: None,
                    location: None,
                    attendees: Vec::new(),
                    recurrence_rule: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(event.start.as_deref(), Some("2026-08-18T01:00:00Z"));
        assert_eq!(event.etag.as_deref(), Some("\"new-tag\""));
    }

    #[tokio::test]
    async fn delete_event_refuses_non_event_resource_before_delete() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dav/cal/u/not-an-event"))
            .respond_with(ResponseTemplate::new(200).set_body_string("collection listing"))
            .expect(1)
            .mount(&server)
            .await;
        let client = CaldavClient::new(&server.uri(), None).unwrap();

        let result = client
            .delete_event("token", "/dav/cal/u/not-an-event", None)
            .await;

        assert!(matches!(result, Err(CaldavError::InvalidInput(_))));
        server.verify().await;
    }

    #[tokio::test]
    async fn delete_event_verifies_vevent_and_preserves_normal_delete() {
        let server = MockServer::start().await;
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:one\r\nSUMMARY:Planning\r\nDTSTART:20260817T010000Z\r\nDTEND:20260817T020000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        Mock::given(method("GET"))
            .and(path("/dav/cal/u/default/event"))
            .and(header("authorization", "Bearer token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"current\"")
                    .set_body_string(ics),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/dav/cal/u/default/event"))
            .and(header("authorization", "Bearer token"))
            .and(header("if-match", "\"current\""))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let client = CaldavClient::new(&server.uri(), None).unwrap();

        client
            .delete_event("token", "/dav/cal/u/default/event", None)
            .await
            .unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn free_busy_deduplicates_calendar_hrefs() {
        let server = MockServer::start().await;
        let empty_multistatus = r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"/>"#;
        Mock::given(method("REPORT"))
            .and(path("/dav/cal/u/default/"))
            .respond_with(ResponseTemplate::new(207).set_body_string(empty_multistatus))
            .expect(1)
            .mount(&server)
            .await;
        let client = CaldavClient::new(&server.uri(), None).unwrap();
        let hrefs = vec![
            "/dav/cal/u/default/".to_owned(),
            "/dav/cal/u/default/".to_owned(),
        ];

        let result = client
            .free_busy("token", &hrefs, "2026-08-01", "2026-08-02")
            .await
            .unwrap();

        assert!(result.is_empty());
        server.verify().await;
    }

    #[tokio::test]
    async fn free_busy_rejects_too_many_unique_calendars_before_network() {
        let client = CaldavClient::new("https://dav.example.test", None).unwrap();
        let hrefs = (0..=MAX_FREE_BUSY_CALENDARS)
            .map(|i| format!("/dav/cal/u/{i}/"))
            .collect::<Vec<_>>();

        let result = client
            .free_busy("token", &hrefs, "2026-08-01", "2026-08-02")
            .await;

        assert!(matches!(result, Err(CaldavError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn dav_rejection_is_not_retried_with_basic_auth() {
        let server = MockServer::start().await;
        Mock::given(method("PROPFIND"))
            .and(path("/.well-known/caldav"))
            .and(header("authorization", "Bearer rejected-token"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;
        let client = CaldavClient::new(&server.uri(), None).unwrap();

        let result = client.discover("rejected-token").await;

        assert!(matches!(result, Err(CaldavError::Unauthorized)));
    }

    /// A calendar object for a recurring series holds the master and one
    /// `VEVENT` per override, and RFC 5545 does not require the master first.
    /// Patching whichever component came first renamed a single occurrence
    /// while reporting that the series had been renamed.
    #[test]
    fn patch_edits_the_master_when_an_override_is_written_first() {
        let ics = OVERRIDE_FIRST_SERIES;
        let patch = EventPatch {
            summary: Some("Renamed".to_owned()),
            ..Default::default()
        };
        let patched = patch_ics(ics, &patch).unwrap();
        let summaries: Vec<&str> = patched
            .lines()
            .filter_map(|line| line.strip_prefix("SUMMARY:"))
            .collect();
        assert_eq!(
            summaries,
            vec!["Override", "Renamed"],
            "the override must keep its own summary and the master must take the patch"
        );
        // The master's RRULE survives, and the override's RECURRENCE-ID is
        // untouched — a patch that hit the wrong component would move one.
        assert!(patched.contains("RRULE:FREQ=WEEKLY"));
        assert!(
            patched
                .contains("RECURRENCE-ID;TZID=Asia/Singapore;RANGE=THISANDFUTURE:20260901T090000")
        );
    }

    /// `update_event` returns this. Returning the override told the caller the
    /// series had no `recurrence_rule`, which is the answer that makes a
    /// client stop treating it as recurring.
    #[test]
    fn a_calendar_object_is_described_by_its_master_component() {
        let event = parse_ical_event(OVERRIDE_FIRST_SERIES, "/c/series.ics").unwrap();
        assert_eq!(event.summary.as_deref(), Some("Master"));
        assert_eq!(event.recurrence_rule.as_deref(), Some("FREQ=WEEKLY"));
        assert!(event.recurrence_id.is_none());
    }

    /// An `EXDATE` has to carry the same value type and `TZID` the `RRULE`
    /// generates. The rendered `recurrence_id` is a UTC instant, so it cannot
    /// be used to build one; the verbatim fields exist for that, and `RANGE`
    /// is surfaced because an override carrying it applies to every later
    /// occurrence too.
    #[test]
    fn recurrence_id_is_surfaced_verbatim_with_its_parameters() {
        let events = parse_ical_events(OVERRIDE_FIRST_SERIES, "/c/series.ics").unwrap();
        let override_instance = events
            .iter()
            .find(|event| event.recurrence_id.is_some())
            .unwrap();

        assert_eq!(
            override_instance.recurrence_id_value.as_deref(),
            Some("20260901T090000")
        );
        assert_eq!(
            override_instance.recurrence_id_tzid.as_deref(),
            Some("Asia/Singapore")
        );
        assert_eq!(
            override_instance.recurrence_id_range.as_deref(),
            Some("THISANDFUTURE")
        );
        // The rendered form is a different value, which is the whole reason
        // the verbatim ones are carried alongside it.
        assert_eq!(
            override_instance.recurrence_id.as_deref(),
            Some("2026-09-01T01:00:00Z")
        );
    }

    /// No `RANGE` means no `RANGE`, rather than a default that would silently
    /// widen a single-instance override.
    #[test]
    fn an_override_without_range_reports_none() {
        let ics = concat!(
            "BEGIN:VCALENDAR\r\n",
            "BEGIN:VEVENT\r\nUID:series\r\nSUMMARY:Master\r\n",
            "DTSTART;TZID=Asia/Singapore:20260801T090000\r\n",
            "DTEND;TZID=Asia/Singapore:20260801T100000\r\nRRULE:FREQ=WEEKLY\r\n",
            "END:VEVENT\r\n",
            "BEGIN:VEVENT\r\nUID:series\r\nSUMMARY:One off\r\n",
            "RECURRENCE-ID;VALUE=DATE:20260901\r\n",
            "DTSTART;VALUE=DATE:20260901\r\nDTEND;VALUE=DATE:20260902\r\n",
            "END:VEVENT\r\nEND:VCALENDAR\r\n"
        );
        let events = parse_ical_events(ics, "/c/series.ics").unwrap();
        let instance = events
            .iter()
            .find(|event| event.recurrence_id.is_some())
            .unwrap();
        assert_eq!(instance.recurrence_id_value.as_deref(), Some("20260901"));
        assert!(instance.recurrence_id_tzid.is_none());
        assert!(instance.recurrence_id_range.is_none());
    }

    const OVERRIDE_FIRST_SERIES: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "BEGIN:VEVENT\r\nUID:series\r\nSUMMARY:Override\r\n",
        "RECURRENCE-ID;TZID=Asia/Singapore;RANGE=THISANDFUTURE:20260901T090000\r\n",
        "DTSTART;TZID=Asia/Singapore:20260901T100000\r\n",
        "DTEND;TZID=Asia/Singapore:20260901T110000\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:series\r\nSUMMARY:Master\r\n",
        "DTSTART;TZID=Asia/Singapore:20260801T090000\r\n",
        "DTEND;TZID=Asia/Singapore:20260801T100000\r\nRRULE:FREQ=WEEKLY\r\n",
        "END:VEVENT\r\nEND:VCALENDAR\r\n"
    );

    /// `EXDATE` and `RDATE` may each repeat and each carry a comma-separated
    /// list, and the parameters belong to the property rather than to any one
    /// value. Flattening them without carrying `TZID` and `VALUE=DATE` down to
    /// each entry would produce exclusions that match nothing.
    #[test]
    fn recurrence_dates_are_flattened_with_their_parameters() {
        let lines = vec![
            "EXDATE;TZID=Asia/Singapore:20260901T090000,20260908T090000".to_owned(),
            "EXDATE;TZID=Asia/Singapore:20260915T090000".to_owned(),
            "RDATE;VALUE=DATE:20261001".to_owned(),
        ];
        let exdates = recurrence_dates(&lines, "EXDATE");
        assert_eq!(
            exdates
                .iter()
                .map(|date| date.value.as_str())
                .collect::<Vec<_>>(),
            vec!["20260901T090000", "20260908T090000", "20260915T090000"]
        );
        assert!(
            exdates
                .iter()
                .all(|date| date.tzid.as_deref() == Some("Asia/Singapore") && !date.is_date),
            "TZID belongs to every value of the property that carried it"
        );

        let rdates = recurrence_dates(&lines, "RDATE");
        assert_eq!(rdates.len(), 1);
        assert!(rdates[0].is_date);
        assert!(rdates[0].tzid.is_none());
    }

    /// A date-shaped value with no `VALUE=DATE` parameter is still a date.
    /// Reporting it as a date-time would make an all-day exclusion match
    /// nothing.
    #[test]
    fn a_bare_date_value_is_recognised_without_the_parameter() {
        let lines = vec!["EXDATE:20260901".to_owned()];
        let dates = recurrence_dates(&lines, "EXDATE");
        assert_eq!(dates.len(), 1);
        assert!(dates[0].is_date);
    }

    #[tokio::test]
    async fn get_event_raw_returns_the_master_with_its_recurrence_properties() {
        let server = MockServer::start().await;
        let ics = concat!(
            "BEGIN:VCALENDAR\r\n",
            "BEGIN:VEVENT\r\nUID:series\r\nSUMMARY:Master\r\n",
            "DTSTART;TZID=Asia/Singapore:20260801T090000\r\n",
            "DTEND;TZID=Asia/Singapore:20260801T100000\r\n",
            "RRULE:FREQ=WEEKLY\r\n",
            "EXDATE;TZID=Asia/Singapore:20260815T090000\r\n",
            "END:VEVENT\r\n",
            "BEGIN:VEVENT\r\nUID:series\r\nSUMMARY:Moved\r\n",
            "RECURRENCE-ID;TZID=Asia/Singapore:20260808T090000\r\n",
            "DTSTART;TZID=Asia/Singapore:20260808T140000\r\n",
            "DTEND;TZID=Asia/Singapore:20260808T150000\r\n",
            "END:VEVENT\r\nEND:VCALENDAR\r\n"
        );
        Mock::given(method("GET"))
            .and(path("/dav/cal/u/default/series.ics"))
            .and(header("authorization", "Bearer token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"v1\"")
                    .set_body_string(ics),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = CaldavClient::new(&server.uri(), None).unwrap();

        let (body, etag, components) = client
            .get_event_raw("token", "/dav/cal/u/default/series.ics")
            .await
            .unwrap();

        assert_eq!(body, ics);
        assert_eq!(etag.as_deref(), Some("\"v1\""));
        assert_eq!(components.len(), 2);

        let master = components.iter().find(|event| !event.is_override).unwrap();
        assert_eq!(master.recurrence_rule.as_deref(), Some("FREQ=WEEKLY"));
        assert_eq!(master.exdates.len(), 1);
        assert_eq!(master.exdates[0].value, "20260815T090000");
        assert_eq!(master.exdates[0].tzid.as_deref(), Some("Asia/Singapore"));

        let moved = components.iter().find(|event| event.is_override).unwrap();
        assert_eq!(
            moved.recurrence_id_value.as_deref(),
            Some("20260808T090000")
        );
        // The override's own start moved; the exclusion must key off the
        // RECURRENCE-ID, not the start.
        assert_ne!(moved.recurrence_id_value, moved.start);
        server.verify().await;
    }

    fn invited_event(organizer: Option<&str>) -> NewEvent {
        NewEvent {
            organizer: organizer.map(ToOwned::to_owned),
            summary: "Planning".to_owned(),
            start: "2026-09-01T09:00:00".to_owned(),
            end: "2026-09-01T10:00:00".to_owned(),
            timezone: "Asia/Singapore".to_owned(),
            description: None,
            location: None,
            attendees: vec!["lucy@kampong.social".to_owned()],
            recurrence_rule: None,
        }
    }

    /// **The assertion is on the stored object, not on the response.** An
    /// event carrying `ATTENDEE` and no `ORGANIZER` is not a scheduling object
    /// under RFC 6638, so the server generates no iTIP and it invites nobody,
    /// while the response still echoes the attendee back. Asserting on what
    /// `create_event` returns passes either way, because the response is built
    /// from the same struct that omitted the field.
    #[test]
    fn an_event_with_attendees_carries_an_organizer_in_the_stored_object() {
        let ics = build_new_ics("uid-1", &invited_event(Some("julian@kampong.social"))).unwrap();
        assert!(
            ics.contains("ORGANIZER:mailto:julian@kampong.social"),
            "stored object must carry ORGANIZER, got:\n{ics}"
        );

        // And it must survive the read path, since an ORGANIZER the parser
        // drops is the same defect one layer over.
        let parsed = parse_ical_event(&ics, "/c/e.ics").unwrap();
        assert_eq!(parsed.organizer.as_deref(), Some("julian@kampong.social"));
        assert_eq!(parsed.attendees, vec!["lucy@kampong.social"]);
    }

    /// A solo event stays a plain event. Writing `ORGANIZER` unconditionally
    /// would make everything this tool creates a scheduling object, which
    /// changes what later edits do rather than fixing what this one does.
    #[test]
    fn an_event_without_attendees_has_no_organizer() {
        let mut event = invited_event(Some("julian@kampong.social"));
        event.attendees.clear();
        let ics = build_new_ics("uid-2", &event).unwrap();
        assert!(!ics.contains("ORGANIZER"), "got:\n{ics}");
    }

    /// No email claim on the token means no valid organizer, and the failure
    /// this refuses is the silent one: an event created having invited nobody,
    /// reporting success, with the attendee echoed back.
    #[test]
    fn attendees_without_an_organizer_are_refused_rather_than_written() {
        for organizer in [None, Some(""), Some("   ")] {
            let error = build_new_ics("uid-3", &invited_event(organizer)).unwrap_err();
            assert!(
                error.to_string().contains("invited nobody"),
                "unexpected error for {organizer:?}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn create_event_puts_an_organizer_when_there_are_attendees() {
        let server = MockServer::start().await;
        Mock::given(method("PROPFIND"))
            .respond_with(ResponseTemplate::new(207).set_body_string(
                r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>/dav/cal/u/default/</d:href><d:propstat><d:prop><d:current-user-principal><d:href>/dav/principals/u/</d:href></d:current-user-principal><c:calendar-home-set><d:href>/dav/cal/u/</d:href></c:calendar-home-set></d:prop></d:propstat></d:response></d:multistatus>"#,
            ))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path_regex(r"^/dav/cal/u/default/.*\.ics$"))
            .and(body_string_contains(
                "ORGANIZER:mailto:julian@kampong.social",
            ))
            .and(body_string_contains("ATTENDEE:mailto:lucy@kampong.social"))
            .respond_with(ResponseTemplate::new(201).insert_header("etag", "\"v1\""))
            .expect(1)
            .mount(&server)
            .await;
        let client = CaldavClient::new(&server.uri(), None).unwrap();

        client
            .create_event(
                "token",
                "/dav/cal/u/default/",
                &invited_event(Some("julian@kampong.social")),
            )
            .await
            .unwrap();

        // wiremock fails verification on an unmatched request, so a PUT whose
        // body lacks ORGANIZER surfaces here rather than passing quietly.
        server.verify().await;
    }

    /// Answers half of "does updating an event with attendees notify them".
    /// It does, for an event this tool created after the fix, because the
    /// patch edits the master in place and passes `ORGANIZER` through, so the
    /// object stays a scheduling object and the server's organizer diff fires.
    /// For an event created *before* the fix there is no `ORGANIZER` to carry
    /// and the update still notifies nobody; backfilling one here would start
    /// sending mail about events that have never notified anyone, which is the
    /// irrecoverable direction, so it is deliberately not done.
    #[test]
    fn an_update_carries_the_organizer_through() {
        let ics = build_new_ics("uid-4", &invited_event(Some("julian@kampong.social"))).unwrap();
        let patch = EventPatch {
            summary: Some("Renamed".to_owned()),
            ..Default::default()
        };
        let patched = patch_ics(&ics, &patch).unwrap();
        assert!(patched.contains("ORGANIZER:mailto:julian@kampong.social"));
        assert!(patched.contains("SUMMARY:Renamed"));

        // And an object that never had one does not acquire one by being
        // edited.
        let unscheduled = concat!(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:old\r\nSUMMARY:Legacy\r\n",
            "DTSTART:20260901T010000Z\r\nDTEND:20260901T020000Z\r\n",
            "ATTENDEE:mailto:lucy@kampong.social\r\n",
            "END:VEVENT\r\nEND:VCALENDAR\r\n"
        );
        let patched = patch_ics(unscheduled, &patch).unwrap();
        assert!(
            !patched.contains("ORGANIZER"),
            "an update must not silently turn a quiet event into one that mails people"
        );
    }

    const WEEKLY_SERIES: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "BEGIN:VEVENT\r\nUID:series\r\nSUMMARY:Standup\r\nSEQUENCE:1\r\n",
        "DTSTART;TZID=Asia/Singapore:20260801T090000\r\n",
        "DTEND;TZID=Asia/Singapore:20260801T093000\r\n",
        "RRULE:FREQ=WEEKLY\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:series\r\nSUMMARY:Moved\r\n",
        "RECURRENCE-ID;TZID=Asia/Singapore:20260808T090000\r\n",
        "DTSTART;TZID=Asia/Singapore:20260808T140000\r\n",
        "DTEND;TZID=Asia/Singapore:20260808T143000\r\n",
        "END:VEVENT\r\nEND:VCALENDAR\r\n"
    );

    /// The exclusion has to carry the same value type and `TZID` the `RRULE`
    /// generates, which is `DTSTART`'s and never the caller's. And the
    /// override goes in the same write: left behind it is an orphan, an
    /// occurrence clients render for a date the series says does not exist.
    #[test]
    fn excluding_an_occurrence_writes_an_exdate_shaped_like_dtstart() {
        let exclusion = exclude_occurrence(WEEKLY_SERIES, "20260808T090000", false).unwrap();

        assert!(!exclusion.already_excluded);
        assert!(exclusion.removed_override);
        assert_eq!(exclusion.exdate.tzid.as_deref(), Some("Asia/Singapore"));
        assert!(!exclusion.exdate.is_date);

        let ics = exclusion.ics.unwrap();
        assert!(ics.contains("EXDATE;TZID=Asia/Singapore:20260808T090000"));
        assert!(
            !ics.contains("RECURRENCE-ID"),
            "the override must be gone, not orphaned"
        );
        assert!(ics.contains("SEQUENCE:2"));
    }

    /// A floating all-day series takes `VALUE=DATE`, because an `EXDATE`
    /// written as a date-time against a date `DTSTART` excludes nothing and
    /// the server accepts it.
    #[test]
    fn an_all_day_series_gets_a_value_date_exclusion() {
        let ics = concat!(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:daily\r\nSUMMARY:Leave\r\n",
            "DTSTART;VALUE=DATE:20260801\r\nDTEND;VALUE=DATE:20260802\r\n",
            "RRULE:FREQ=DAILY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        );
        let exclusion = exclude_occurrence(ics, "20260805", false).unwrap();
        assert!(exclusion.exdate.is_date);
        assert!(exclusion.exdate.tzid.is_none());
        assert!(
            exclusion
                .ics
                .unwrap()
                .contains("EXDATE;VALUE=DATE:20260805")
        );
    }

    /// Measured 2026-09-02 against the deployed Stalwart: a value type
    /// differing from `DTSTART` is **not** refused, because it excludes.
    /// `EXDATE:20260903T000000Z` removed an occurrence of an all-day series and
    /// `EXDATE:20260908T010000Z` removed one from a zoned series, so the server
    /// matches by instant rather than by literal form. The exclusion is instead
    /// shaped to the caller's value, since a date under a `TZID=` head would be
    /// malformed and no server can repair that.
    #[test]
    fn a_date_target_is_written_as_a_date_whatever_dtstart_carries() {
        let exclusion = exclude_occurrence(WEEKLY_SERIES, "20260808", false).unwrap();
        let ics = exclusion.ics.unwrap();
        assert!(
            ics.contains("EXDATE;VALUE=DATE:20260808"),
            "a date target must not be written under the series' TZID head:\n{ics}"
        );
        assert!(exclusion.exdate.is_date);
        assert!(exclusion.exdate.tzid.is_none());
    }

    /// Re-excluding an already excluded occurrence succeeds and writes
    /// nothing, rather than duplicating the `EXDATE` or erroring.
    #[test]
    fn excluding_twice_is_idempotent() {
        let first = exclude_occurrence(WEEKLY_SERIES, "20260808T090000", false).unwrap();
        let second = exclude_occurrence(&first.ics.unwrap(), "20260808T090000", false).unwrap();
        assert!(second.already_excluded);
        assert!(!second.removed_override);
        assert!(
            second.ics.is_none(),
            "nothing to write means no PUT, and no SEQUENCE bump"
        );
    }

    /// `Schedule-Reply: F` is inert on `PUT` and `SCHEDULE-AGENT=CLIENT` is
    /// persistent, so there is no way to make this write quiet. The only
    /// honest options are sending the mail and not touching the event.
    #[test]
    fn an_attended_series_refuses_and_names_every_attendee() {
        let ics = WEEKLY_SERIES
            .replace(
                "SUMMARY:Standup\r\n",
                "SUMMARY:Standup\r\nATTENDEE;CN=A:mailto:a@example.test\r\n",
            )
            .replace(
                "SUMMARY:Moved\r\n",
                "SUMMARY:Moved\r\nATTENDEE;CN=B:mailto:b@example.test\r\n",
            );
        let error = exclude_occurrence(&ics, "20260808T090000", false).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("a@example.test"), "got: {message}");
        assert!(
            message.contains("b@example.test"),
            "an attendee on an override is still someone who gets mail: {message}"
        );

        // And the opt-in is the only way through.
        let allowed = exclude_occurrence(&ics, "20260808T090000", true).unwrap();
        assert!(allowed.ics.is_some());
    }

    /// `RANGE=THISANDFUTURE` applies to the occurrence and every later one.
    /// Excluding it is a different operation, so it is rejected explicitly
    /// rather than silently treated as a single-instance exclusion.
    #[test]
    fn a_this_and_future_override_is_rejected_rather_than_excluded() {
        let ics = WEEKLY_SERIES.replace(
            "RECURRENCE-ID;TZID=Asia/Singapore:20260808T090000",
            "RECURRENCE-ID;TZID=Asia/Singapore;RANGE=THISANDFUTURE:20260808T090000",
        );
        let error = exclude_occurrence(&ics, "20260808T090000", false).unwrap_err();
        assert!(
            error.to_string().contains("THISANDFUTURE"),
            "unexpected error: {error}"
        );
    }

    /// Measured 2026-09-02: this server honours an `EXDATE` for the series'
    /// first occurrence, removing it and leaving five of six. The refusal that
    /// stood here rested on "some servers treat `DTSTART` as implicitly
    /// included", which is received wisdom about servers in general and not
    /// true of the one we run.
    #[test]
    fn the_first_occurrence_can_be_excluded() {
        let exclusion = exclude_occurrence(WEEKLY_SERIES, "20260801T090000", false).unwrap();
        let ics = exclusion.ics.unwrap();
        assert!(ics.contains("EXDATE;TZID=Asia/Singapore:20260801T090000"));
    }

    #[test]
    fn a_non_recurring_event_cannot_have_an_occurrence_excluded() {
        let ics = concat!(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:one\r\nSUMMARY:Once\r\n",
            "DTSTART;TZID=Asia/Singapore:20260801T090000\r\n",
            "DTEND;TZID=Asia/Singapore:20260801T093000\r\n",
            "END:VEVENT\r\nEND:VCALENDAR\r\n"
        );
        let error = exclude_occurrence(ics, "20260808T090000", false).unwrap_err();
        assert!(
            error.to_string().contains("not recurring"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn delete_occurrence_puts_the_excluded_series_with_if_match() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dav/cal/u/default/series.ics"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"v1\"")
                    .set_body_string(WEEKLY_SERIES),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/dav/cal/u/default/series.ics"))
            .and(header("if-match", "\"v1\""))
            .and(body_string_contains(
                "EXDATE;TZID=Asia/Singapore:20260808T090000",
            ))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let client = CaldavClient::new(&server.uri(), None).unwrap();

        let exclusion = client
            .delete_occurrence(
                "token",
                "/dav/cal/u/default/series.ics",
                "20260808T090000",
                None,
                false,
            )
            .await
            .unwrap();

        assert!(exclusion.removed_override);
        server.verify().await;
    }

    /// Already excluded means nothing to write, so there must be no `PUT` at
    /// all — not a no-op `PUT` that bumps `SEQUENCE` and, on an attended
    /// series, would send mail for a change that did not happen.
    #[tokio::test]
    async fn delete_occurrence_does_not_put_when_already_excluded() {
        let server = MockServer::start().await;
        let already = WEEKLY_SERIES.replace(
            "RRULE:FREQ=WEEKLY\r\n",
            "RRULE:FREQ=WEEKLY\r\nEXDATE;TZID=Asia/Singapore:20260815T090000\r\n",
        );
        Mock::given(method("GET"))
            .and(path("/dav/cal/u/default/series.ics"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"v1\"")
                    .set_body_string(already),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = CaldavClient::new(&server.uri(), None).unwrap();

        let exclusion = client
            .delete_occurrence(
                "token",
                "/dav/cal/u/default/series.ics",
                "20260815T090000",
                None,
                false,
            )
            .await
            .unwrap();

        assert!(exclusion.already_excluded);
        // wiremock fails verification on any unmatched request, so a PUT here
        // would surface rather than pass silently.
        server.verify().await;
    }
}
