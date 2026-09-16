use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;

pub const ACCESS_TOKEN_COOKIE: &str = "access_token";
pub const REFRESH_TOKEN_COOKIE: &str = "refresh_token";

/// Cookies are scoped to the API prefix so they are never attached to unrelated paths on the
/// same host.
const COOKIE_PATH: &str = "/api/v1";

pub fn access_cookie(token: String, ttl_seconds: u64, secure: bool) -> Cookie<'static> {
    credential_cookie(ACCESS_TOKEN_COOKIE, token, ttl_seconds, secure)
}

pub fn refresh_cookie(token: String, ttl_seconds: u64, secure: bool) -> Cookie<'static> {
    credential_cookie(REFRESH_TOKEN_COOKIE, token, ttl_seconds, secure)
}

/// Expired cookies that overwrite the stored credentials on sign-out.
pub fn removal_cookies(secure: bool) -> [Cookie<'static>; 2] {
    [
        credential_cookie(ACCESS_TOKEN_COOKIE, String::new(), 0, secure),
        credential_cookie(REFRESH_TOKEN_COOKIE, String::new(), 0, secure),
    ]
}

/// Always `HttpOnly` (never readable by JavaScript), `SameSite=Lax` (not sent on cross-site
/// POST requests, which is the CSRF boundary), and `Secure` whenever the deployment is on
/// HTTPS. `Max-Age` of zero deletes the cookie.
fn credential_cookie(
    name: &'static str,
    value: String,
    ttl_seconds: u64,
    secure: bool,
) -> Cookie<'static> {
    Cookie::build((name, value))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .path(COOKIE_PATH)
        .max_age(Duration::seconds(
            i64::try_from(ttl_seconds).unwrap_or(i64::MAX),
        ))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_cookies_are_locked_down() {
        let cookie = access_cookie("token-value".into(), 900, true);

        assert!(cookie.http_only().unwrap_or(false));
        assert!(cookie.secure().unwrap_or(false));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        assert_eq!(cookie.path(), Some(COOKIE_PATH));
        assert_eq!(cookie.max_age(), Some(Duration::seconds(900)));
    }

    #[test]
    fn insecure_deployments_omit_the_secure_flag() {
        assert!(
            !access_cookie("token".into(), 900, false)
                .secure()
                .unwrap_or(false)
        );
    }

    #[test]
    fn removal_cookies_expire_immediately() {
        for cookie in removal_cookies(true) {
            assert_eq!(cookie.max_age(), Some(Duration::seconds(0)));
            assert_eq!(cookie.path(), Some(COOKIE_PATH));
        }
    }
}
