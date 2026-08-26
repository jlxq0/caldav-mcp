//! Per-identity rate limiting (Phase 6.1).
//!
//! ## Why two keys
//!
//! Each tool call is checked against two independent token buckets:
//!
//! 1. `sha256(bearer)[..16]` — protects Logto/Stalwart from a leaked
//!    token: even if the same `sub` has multiple active tokens, a
//!    compromised one can only burn its own bucket before being denied.
//! 2. Logto `sub` — protects against the same user spinning up many
//!    tokens (e.g. claude.ai issuing a fresh one per session) and using
//!    the union of their per-token allowances to flood Stalwart.
//!
//! Either bucket exceeded → request denied. Both must allow.
//!
//! When `sub` is unavailable (the `/setup` browser flow doesn't go
//! through Logto validation), only the bearer-hash bucket applies.
//!
//! ## Why two quotas
//!
//! Reads (`list_joined_rooms`, `read_recent_messages`, `whoami`,
//! `verify_status`) are cheap and idempotent — high default quota.
//! Writes (`send_text_message` + future write tools) are more expensive
//! and side-effectful; tighter default.
//!
//! ## Memory bound
//!
//! Each bucket map has a hard cardinality cap and removes entries that have
//! been idle for an hour. If a map remains full of active identities, new
//! identities fail closed instead of allocating more memory or evicting a
//! live bucket that still carries rate-limit state.
//!
//! ## Quota knobs
//!
//! Configured at startup; no per-request override. Read from env in
//! `config.rs`:
//!
//! - `CALDAV_MCP_RATE_LIMIT_READS_PER_MIN` (default 60)
//! - `CALDAV_MCP_RATE_LIMIT_WRITES_PER_MIN` (default 30)

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

/// Maximum number of fresh MCP sessions a single bearer token or Logto
/// subject may open in a short burst. Legitimate Claude usage normally
/// needs one or two live sessions; this leaves headroom for reconnects
/// while preventing one authenticated identity from filling the global
/// session pool (`session::MAX_SESSIONS`).
pub const MAX_INITIALIZES_PER_IDENTITY: u32 = 8;

const MAX_BUCKETS_PER_MAP: usize = 4096;
#[allow(unknown_lints)]
#[allow(clippy::duration_suboptimal_units)]
const BUCKET_IDLE_TTL: Duration = Duration::from_secs(3600);

/// Limiter type alias — `governor`'s direct (non-keyed) variant; we
/// build one per identity and hand it out keyed by bearer-hash or sub.
type Bucket = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

#[derive(Debug)]
struct BucketEntry {
    bucket: Arc<Bucket>,
    last_seen: Instant,
}

type BucketMap = RwLock<HashMap<String, BucketEntry>>;

/// What kind of MCP tool this call is. Drives which quota applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Read,
    Write,
}

/// Returned when a request would exceed the configured quota.
#[derive(Debug, Clone, Copy)]
pub struct RateLimited;

#[derive(Debug)]
pub struct Limiter {
    reads_per_min: NonZeroU32,
    writes_per_min: NonZeroU32,
    bearer_read: BucketMap,
    bearer_write: BucketMap,
    sub_read: BucketMap,
    sub_write: BucketMap,
}

impl Limiter {
    /// New limiter with the given per-minute quotas. `0` quotas are
    /// rejected (`None`) — use a large quota to "effectively disable",
    /// don't pass `0`.
    #[must_use]
    pub fn new(reads_per_min: u32, writes_per_min: u32) -> Option<Self> {
        Some(Self {
            reads_per_min: NonZeroU32::new(reads_per_min)?,
            writes_per_min: NonZeroU32::new(writes_per_min)?,
            bearer_read: RwLock::new(HashMap::new()),
            bearer_write: RwLock::new(HashMap::new()),
            sub_read: RwLock::new(HashMap::new()),
            sub_write: RwLock::new(HashMap::new()),
        })
    }

    /// Check both per-bearer-hash and per-sub buckets. Returns `Ok(())`
    /// if both allow, `Err(RateLimited)` if either denies.
    pub fn check(
        &self,
        bearer_hash: &str,
        sub: Option<&str>,
        category: Category,
    ) -> Result<(), RateLimited> {
        let (bearer_map, sub_map, quota) = match category {
            Category::Read => (&self.bearer_read, &self.sub_read, self.reads_per_min),
            Category::Write => (&self.bearer_write, &self.sub_write, self.writes_per_min),
        };
        let bearer_bucket = get_or_insert(bearer_map, bearer_hash, quota)?;
        if bearer_bucket.check().is_err() {
            return Err(RateLimited);
        }
        if let Some(s) = sub {
            let sub_bucket = get_or_insert(sub_map, s, quota)?;
            if sub_bucket.check().is_err() {
                return Err(RateLimited);
            }
        }
        Ok(())
    }
}

fn get_or_insert(
    map: &BucketMap,
    key: &str,
    quota: NonZeroU32,
) -> Result<Arc<Bucket>, RateLimited> {
    // `governor::Quota::per_minute(n)` translates to one token every
    // (60/n) seconds with a burst of `n`.
    get_or_insert_with_quota(map, key, Quota::per_minute(quota))
}

fn get_or_insert_with_quota(
    map: &BucketMap,
    key: &str,
    quota: Quota,
) -> Result<Arc<Bucket>, RateLimited> {
    get_or_insert_capped(map, key, quota, MAX_BUCKETS_PER_MAP, BUCKET_IDLE_TTL)
}

fn get_or_insert_capped(
    map: &BucketMap,
    key: &str,
    quota: Quota,
    cap: usize,
    idle_ttl: Duration,
) -> Result<Arc<Bucket>, RateLimited> {
    let mut guard = match map.write() {
        Ok(g) => g,
        // Preserve existing entries after a panic; capacity checks below
        // still apply, so lock poisoning cannot disable rate limiting.
        Err(p) => p.into_inner(),
    };
    let now = Instant::now();
    if let Some(entry) = guard.get_mut(key) {
        entry.last_seen = now;
        return Ok(Arc::clone(&entry.bucket));
    }
    guard.retain(|_, entry| now.duration_since(entry.last_seen) < idle_ttl);
    if guard.len() >= cap {
        return Err(RateLimited);
    }
    let bucket = Arc::new(RateLimiter::direct(quota));
    guard.insert(
        key.to_owned(),
        BucketEntry {
            bucket: Arc::clone(&bucket),
            last_seen: now,
        },
    );
    drop(guard);
    Ok(bucket)
}

/// Rate limiter dedicated to fresh MCP session creation (the
/// `initialize` request without an `mcp-session-id` header). Tool-call
/// rate limits do not protect this path because rmcp allocates the
/// session before any tool handler runs, so the per-bucket charge
/// inside [`Limiter::check`] never fires for the initialize request.
///
/// Keyed by bearer-hash AND Logto subject the same way [`Limiter`] is:
/// a stolen token can't fan out more sessions than the bucket allows,
/// and the same `sub` can't accumulate sessions across rotated tokens
/// either.
#[derive(Debug)]
pub struct InitializeLimiter {
    quota: Quota,
    bearer: BucketMap,
    sub: BucketMap,
}

impl InitializeLimiter {
    /// New limiter that allows up to `burst` initialize calls back-to-back
    /// and then refills one token every `replenish_1_per`. Pairing the
    /// refill period with `session::SESSION_KEEP_ALIVE` means once an
    /// attacker has filled their slots they can only open a new one as
    /// fast as their existing ones idle out — exactly the timescale of
    /// the global session-pool cap.
    #[must_use]
    pub fn new(replenish_1_per: Duration, burst: u32) -> Self {
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::with_period(replenish_1_per)
            .unwrap_or_else(|| Quota::per_minute(NonZeroU32::MIN))
            .allow_burst(burst);
        Self {
            quota,
            bearer: RwLock::new(HashMap::new()),
            sub: RwLock::new(HashMap::new()),
        }
    }

    /// Check both per-bearer-hash and per-sub initialize buckets.
    ///
    /// Returns *which* bucket refused. A refusal that says only "refused" is
    /// the same object as the 429 that says only "later": it cannot separate
    /// one token reconnecting from one identity rotating tokens, and neither
    /// from the limiter's own bucket map filling, which is not a quota
    /// refusal at all.
    pub fn check(&self, bearer_hash: &str, sub: Option<&str>) -> Result<(), InitializeRefusal> {
        let bearer_bucket = get_or_insert_with_quota(&self.bearer, bearer_hash, self.quota)
            .map_err(|RateLimited| InitializeRefusal::BucketCapacity)?;
        if bearer_bucket.check().is_err() {
            return Err(InitializeRefusal::Bearer);
        }
        if let Some(s) = sub {
            let sub_bucket = get_or_insert_with_quota(&self.sub, s, self.quota)
                .map_err(|RateLimited| InitializeRefusal::BucketCapacity)?;
            if sub_bucket.check().is_err() {
                return Err(InitializeRefusal::Subject);
            }
        }
        Ok(())
    }
}

/// Which bucket refused an `initialize`.
///
/// The three are different diagnoses and were previously one value. `Subject`
/// is the shape a client minting a fresh token per session makes: every
/// attempt gets a new bearer bucket and the same subject bucket, so the
/// subject bucket is the one that runs out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitializeRefusal {
    /// Per-bearer-token bucket empty: one token reconnecting.
    Bearer,
    /// Per-subject bucket empty: one identity across rotated tokens.
    Subject,
    /// The limiter's own bucket map is at `MAX_BUCKETS_PER_MAP`. Not a quota
    /// refusal, and indistinguishable from one until now.
    BucketCapacity,
}

impl InitializeRefusal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::Subject => "subject",
            Self::BucketCapacity => "bucket_capacity",
        }
    }
}

#[cfg(test)]
#[allow(unknown_lints)]
#[allow(clippy::unwrap_used, clippy::duration_suboptimal_units)]
mod tests {
    use super::*;

    #[test]
    fn zero_quota_rejected() {
        assert!(Limiter::new(0, 1).is_none());
        assert!(Limiter::new(1, 0).is_none());
    }

    #[test]
    fn reads_and_writes_have_independent_buckets() {
        let l = Limiter::new(2, 2).unwrap();
        // Burn the read bucket.
        l.check("h", Some("s"), Category::Read).unwrap();
        l.check("h", Some("s"), Category::Read).unwrap();
        assert!(l.check("h", Some("s"), Category::Read).is_err());
        // Writes are unaffected.
        l.check("h", Some("s"), Category::Write).unwrap();
        l.check("h", Some("s"), Category::Write).unwrap();
        assert!(l.check("h", Some("s"), Category::Write).is_err());
    }

    #[test]
    fn distinct_bearers_dont_share_a_bucket() {
        let l = Limiter::new(1, 1).unwrap();
        l.check("h1", None, Category::Read).unwrap();
        // Same identity at the bearer-hash level → denied.
        assert!(l.check("h1", None, Category::Read).is_err());
        // Different bearer → fresh bucket.
        l.check("h2", None, Category::Read).unwrap();
    }

    #[test]
    fn sub_bucket_denies_across_bearers_for_same_user() {
        let l = Limiter::new(1, 1).unwrap();
        l.check("h1", Some("user-A"), Category::Read).unwrap();
        // Different bearer, same sub → sub bucket exhausted.
        assert!(l.check("h2", Some("user-A"), Category::Read).is_err());
    }

    #[test]
    fn no_sub_means_bearer_only() {
        let l = Limiter::new(1, 1).unwrap();
        // Without sub, the sub bucket is skipped; only bearer-hash
        // applies.
        l.check("h1", None, Category::Read).unwrap();
        assert!(l.check("h1", None, Category::Read).is_err());
        l.check("h2", None, Category::Read).unwrap();
    }

    #[test]
    fn initialize_limiter_denies_after_burst_on_bearer() {
        let l = InitializeLimiter::new(Duration::from_secs(60), 2);
        l.check("h", Some("s")).unwrap();
        l.check("h", Some("s")).unwrap();
        assert!(l.check("h", Some("s")).is_err());
    }

    #[test]
    fn initialize_limiter_denies_across_bearers_for_same_sub() {
        let l = InitializeLimiter::new(Duration::from_secs(60), 1);
        l.check("h1", Some("s")).unwrap();
        // Different bearer, same sub → sub bucket exhausted.
        assert!(l.check("h2", Some("s")).is_err());
    }

    #[test]
    fn initialize_limiter_no_sub_uses_bearer_only() {
        let l = InitializeLimiter::new(Duration::from_secs(60), 1);
        l.check("h", None).unwrap();
        assert!(l.check("h", None).is_err());
        // Different bearer → fresh bucket.
        l.check("h2", None).unwrap();
    }

    #[test]
    fn bucket_map_fails_closed_at_hard_cap() {
        let map = RwLock::new(HashMap::new());
        let quota = Quota::per_minute(NonZeroU32::MIN);
        get_or_insert_capped(&map, "one", quota, 2, Duration::from_secs(60)).unwrap();
        get_or_insert_capped(&map, "two", quota, 2, Duration::from_secs(60)).unwrap();
        assert!(get_or_insert_capped(&map, "three", quota, 2, Duration::from_secs(60)).is_err());
        assert_eq!(map.read().unwrap().len(), 2);
    }

    /// One token reconnecting exhausts its own bucket, and the log line has to
    /// say so: it is a different diagnosis from the same identity rotating
    /// tokens and the two were previously one value.
    #[test]
    fn a_refusal_names_the_bearer_bucket() {
        let l = InitializeLimiter::new(Duration::from_secs(60), 1);
        l.check("same-token", Some("user")).unwrap();
        assert_eq!(
            l.check("same-token", Some("user")),
            Err(InitializeRefusal::Bearer)
        );
    }

    /// The shape of the incident this was written for: a client minting a
    /// fresh token per session gets a new bearer bucket every time and the
    /// same subject bucket, so the subject bucket is what runs out. A refusal
    /// that cannot say `subject` cannot tell anyone that.
    #[test]
    fn a_refusal_names_the_subject_bucket() {
        let l = InitializeLimiter::new(Duration::from_secs(60), 1);
        l.check("token-one", Some("user")).unwrap();
        assert_eq!(
            l.check("token-two", Some("user")),
            Err(InitializeRefusal::Subject),
            "a fresh token must not be reported as its own bucket refusing"
        );
    }

    #[test]
    fn refusal_scopes_have_distinct_log_values() {
        for (refusal, expected) in [
            (InitializeRefusal::Bearer, "bearer"),
            (InitializeRefusal::Subject, "subject"),
            (InitializeRefusal::BucketCapacity, "bucket_capacity"),
        ] {
            assert_eq!(refusal.as_str(), expected);
        }
    }
}
