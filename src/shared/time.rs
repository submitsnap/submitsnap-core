use chrono::{DateTime, Duration, Utc};

/// Deadline `seconds` from now. TTLs come from validated configuration, so the cast cannot
/// overflow in practice; a saturated value still fails closed by expiring far in the future
/// rather than immediately.
pub fn expires_in(seconds: u64) -> DateTime<Utc> {
    let seconds = i64::try_from(seconds).unwrap_or(i64::MAX);
    Utc::now() + Duration::seconds(seconds)
}
