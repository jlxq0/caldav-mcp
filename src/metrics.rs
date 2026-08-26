// `.expect` in metric registration is intentional: registration failure
// is a startup-only programming bug (duplicate name in the global
// registry), not a runtime input. We want a loud crash at boot, not
// silent degradation later.
#![allow(clippy::expect_used)]

//! Prometheus metrics — exposed on a separate cluster-internal listener
//! (port 9090) so the public caldav-mcp.example.com Service never
//! surfaces metrics.
//!
//! ## Label discipline
//!
//! Every label is low-cardinality. Never label by user, calendar/event href,
//! or token. Cardinality is bounded by:
//!
//! - tool name (8)
//! - outcome class (`ok`, `error`, `denied`, etc. — handful)
//! - introspect outcome (`active`, `inactive`, `error`)
//!
//! Per-user fan-out is what the audit log is for. Mixing it into
//! metrics breaks the Prometheus storage model and leaks user identity
//! to anyone who can reach the metrics endpoint.
//!
//! ## Why a single global registry
//!
//! `prometheus::default_registry()` is process-global, accessed from
//! the audit/auth/mcp call sites without plumbing state. The metrics
//! handles themselves live in `once_cell::sync::Lazy` statics inside
//! this module. Test-only behaviour: in `#[cfg(test)]` the counters
//! are still global but harmlessly increment; no test asserts on
//! their values.

use std::time::Duration;

use axum::http::header;
use axum::response::IntoResponse;
use prometheus::{
    Encoder, HistogramVec, IntCounterVec, TextEncoder, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry,
};
use std::sync::LazyLock;

/// Buckets tuned for tool-call latency: spans local parsing through remote
/// Stalwart discovery and `REPORT` calls.
const TOOL_LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Buckets for Logto token validation.
const INTROSPECT_LATENCY_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];

pub static TOOL_CALLS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        "caldav_mcp_tool_calls_total",
        "Total MCP tool calls served. Labels: tool, outcome.",
        &["tool", "outcome"],
        prometheus::default_registry()
    )
    .expect("register tool_calls_total once")
});

pub static TOOL_LATENCY_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    prometheus::register_histogram_vec_with_registry!(
        prometheus::HistogramOpts::new(
            "caldav_mcp_tool_latency_seconds",
            "Wall-clock latency of MCP tool calls, in seconds."
        )
        .buckets(TOOL_LATENCY_BUCKETS.to_vec()),
        &["tool"],
        prometheus::default_registry()
    )
    .expect("register tool_latency_seconds once")
});

pub static INTROSPECT_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        "caldav_mcp_introspect_total",
        "Total Logto token validations. Labels: outcome (active|inactive|error).",
        &["outcome"],
        prometheus::default_registry()
    )
    .expect("register introspect_total once")
});

pub static INTROSPECT_LATENCY_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        prometheus::HistogramOpts::new(
            "caldav_mcp_introspect_latency_seconds",
            "Logto token-validation latency, in seconds."
        )
        .buckets(INTROSPECT_LATENCY_BUCKETS.to_vec()),
        &["outcome"],
        prometheus::default_registry()
    )
    .expect("register introspect_latency_seconds once")
});

pub static INITIALIZE_REFUSALS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        "caldav_mcp_initialize_refusals_total",
        "MCP initialize requests refused by the per-identity session limiter. \
         Labels: scope (bearer|subject|bucket_capacity).",
        &["scope"],
        prometheus::default_registry()
    )
    .expect("register initialize_refusals_total once")
});

/// Initialize all metrics. Idempotent — `LazyLock` ensures
/// registration only happens once. Call this once at startup so the
/// scraped `/metrics` text always lists the families even before
/// any traffic.
pub fn init() {
    LazyLock::force(&TOOL_CALLS_TOTAL);
    LazyLock::force(&TOOL_LATENCY_SECONDS);
    LazyLock::force(&INTROSPECT_TOTAL);
    LazyLock::force(&INTROSPECT_LATENCY_SECONDS);
    LazyLock::force(&INITIALIZE_REFUSALS_TOTAL);
}

/// Record a finished tool call.
pub fn record_tool_call(tool: &str, outcome: &str, elapsed: Duration) {
    TOOL_CALLS_TOTAL.with_label_values(&[tool, outcome]).inc();
    TOOL_LATENCY_SECONDS
        .with_label_values(&[tool])
        .observe(elapsed.as_secs_f64());
}

/// Record an `initialize` refused by the session limiter.
///
/// The counter that did not exist. `tool_calls_total{outcome="rate_limited"}`
/// reads zero during exactly this failure, because the limiter sits in Axum
/// middleware outside the MCP router and a refusal never reaches the code that
/// increments it — a metric measuring a limiter that was not firing while the
/// one that was firing recorded nothing.
pub fn record_initialize_refusal(scope: &str) {
    INITIALIZE_REFUSALS_TOTAL.with_label_values(&[scope]).inc();
}

/// Record a finished introspection round-trip.
pub fn record_introspect(outcome: &str, elapsed: Duration) {
    INTROSPECT_TOTAL.with_label_values(&[outcome]).inc();
    INTROSPECT_LATENCY_SECONDS
        .with_label_values(&[outcome])
        .observe(elapsed.as_secs_f64());
}

/// Axum handler for `GET /metrics`. Returns the Prometheus text
/// format. Mounted only on the internal listener (port 9090); the
/// public Service does not expose this.
#[allow(clippy::unused_async)] // axum requires async handlers
pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buf = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buf) {
        tracing::warn!(error = %e, "failed to encode metrics");
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "encode error\n".to_owned(),
        )
            .into_response();
    }
    let body = String::from_utf8(buf).unwrap_or_default();
    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent() {
        init();
        init();
        init();
        // No assertion needed — if registration panics on the second
        // call, the test fails.
    }

    #[test]
    fn record_tool_call_advances_counter() {
        init();
        TOOL_CALLS_TOTAL
            .with_label_values(&["__test_tool", "ok"])
            .reset();
        record_tool_call("__test_tool", "ok", Duration::from_millis(50));
        record_tool_call("__test_tool", "ok", Duration::from_millis(70));
        assert_eq!(
            TOOL_CALLS_TOTAL
                .with_label_values(&["__test_tool", "ok"])
                .get(),
            2
        );
    }

    #[test]
    fn metrics_text_output_includes_registered_families() {
        // `prometheus::gather()` only returns CounterVec/HistogramVec
        // families that have at least one labelled child — so observe
        // once to materialise them before asserting.
        init();
        record_tool_call("__families_test", "ok", Duration::from_millis(1));
        record_introspect("active", Duration::from_millis(1));
        let mfs = prometheus::gather();
        let names: Vec<_> = mfs
            .iter()
            .map(prometheus::proto::MetricFamily::get_name)
            .collect();
        assert!(names.contains(&"caldav_mcp_tool_calls_total"));
        assert!(names.contains(&"caldav_mcp_introspect_total"));
    }
}
