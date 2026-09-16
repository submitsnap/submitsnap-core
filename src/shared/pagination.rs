/// Page sizes every listing endpoint accepts. A request is clamped rather than rejected, so a
/// client cannot ask for an unbounded page.
pub const DEFAULT_PAGE_SIZE: u32 = 50;
pub const MAX_PAGE_SIZE: u32 = 100;

/// Turns requested page sizes into values a single query can serve.
pub fn page_bounds(limit: Option<u32>, offset: Option<u32>) -> (i64, i64) {
    let limit = limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
    let offset = offset.unwrap_or(0);

    (i64::from(limit), i64::from(offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_are_clamped_to_something_servable() {
        assert_eq!(page_bounds(None, None), (50, 0));
        assert_eq!(page_bounds(Some(0), Some(10)), (1, 10));
        assert_eq!(page_bounds(Some(10_000), None), (100, 0));
        assert_eq!(page_bounds(Some(25), Some(50)), (25, 50));
    }
}
