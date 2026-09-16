#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use serde_json::{Value, json};
use sqlx::PgPool;
use submitsnap_core::{
    app,
    modules::identity::IdentityService,
    shared::{config::AppConfig, queue::EmailQueue, state::AppState},
};
use tower::ServiceExt;

const JWT_SECRET: &str = "test-secret-that-is-at-least-32-characters";
const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Builds a configuration with generous limits so a test only trips a rate limiter when it
/// deliberately lowers one through [`config_with`].
pub fn config_with(extra: Vec<(&str, String)>) -> AppConfig {
    let mut settings: Vec<(String, String)> = vec![
        ("database_url".into(), "postgres://unused".into()),
        // Deliberately unreachable. Enqueue failures are non-fatal by design, so tests never
        // depend on a running Redis and never pollute a real queue.
        ("redis_url".into(), "redis://127.0.0.1:1".into()),
        ("jwt_secret".into(), JWT_SECRET.into()),
        ("rate_limit_per_minute".into(), "100000".into()),
        ("login_rate_limit_per_minute".into(), "100000".into()),
        ("register_rate_limit_per_hour".into(), "100000".into()),
        ("sensitive_rate_limit_per_hour".into(), "100000".into()),
    ];

    for (key, value) in extra {
        settings.retain(|(existing, _)| existing != key);
        settings.push((key.to_owned(), value));
    }

    AppConfig::from_settings(settings).expect("test configuration is valid")
}

pub fn test_config() -> Arc<AppConfig> {
    Arc::new(config_with(Vec::new()))
}

/// An identity service bound to the same database as the HTTP app, used by tests that need
/// the raw single-use token which would otherwise only travel inside an email.
pub fn identity_service(config: &Arc<AppConfig>, pool: PgPool) -> IdentityService {
    IdentityService::new(pool, email_queue(config), config.clone())
        .expect("identity service builds")
}

fn email_queue(config: &AppConfig) -> EmailQueue {
    EmailQueue::connect(&config.redis_url).expect("queue pool builds")
}

/// The HTTP application under test, driven in-process through `tower::ServiceExt::oneshot`.
pub struct TestApp {
    router: Router,
    pub config: Arc<AppConfig>,
}

impl TestApp {
    pub fn new(pool: PgPool) -> Self {
        Self::with_config(Vec::new(), pool)
    }

    pub fn with_config(extra: Vec<(&str, String)>, pool: PgPool) -> Self {
        let config = Arc::new(config_with(extra));
        let state = AppState::new(config.clone(), pool, email_queue(&config));

        Self {
            router: app(state).expect("app builds"),
            config,
        }
    }

    pub async fn send(&self, request: Request<Body>) -> Response {
        self.router
            .clone()
            .oneshot(request)
            .await
            .expect("router responds")
    }

    pub async fn post_json(&self, path: &str, body: Value) -> (StatusCode, Value) {
        read(
            self.send(json_request(Method::POST, path, Some(body), None))
                .await,
        )
        .await
    }

    pub async fn post_json_auth(
        &self,
        path: &str,
        body: Value,
        token: &str,
    ) -> (StatusCode, Value) {
        read(
            self.send(json_request(Method::POST, path, Some(body), Some(token)))
                .await,
        )
        .await
    }

    pub async fn post_auth(&self, path: &str, token: &str) -> (StatusCode, Value) {
        read(
            self.send(json_request(Method::POST, path, None, Some(token)))
                .await,
        )
        .await
    }

    pub async fn get_auth(&self, path: &str, token: &str) -> (StatusCode, Value) {
        read(
            self.send(json_request(Method::GET, path, None, Some(token)))
                .await,
        )
        .await
    }

    /// Signs in through the API endpoint and returns the full response body.
    pub async fn login(&self, email: &str, password: &str) -> (StatusCode, Value) {
        self.post_json(
            "/api/v1/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await
    }

    /// Registers an account and returns the created user body.
    pub async fn register(&self, email: &str, password: &str) -> (StatusCode, Value) {
        self.post_json(
            "/api/v1/auth/register",
            json!({ "email": email, "password": password }),
        )
        .await
    }
}

pub const PASSWORD: &str = "a-sufficiently-long-password";

pub fn json_request(
    method: Method,
    path: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .extension(ConnectInfo(SocketAddr::new(TEST_IP, 12345)));

    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }

    let body = body
        .map(|value| Body::from(value.to_string()))
        .unwrap_or_else(Body::empty);

    builder.body(body).expect("request builds")
}

/// Builds a request that authenticates with a browser cookie instead of a bearer token.
pub fn cookie_request(
    method: Method,
    path: &str,
    body: Option<Value>,
    cookie: &str,
) -> Request<Body> {
    let body = body
        .map(|value| Body::from(value.to_string()))
        .unwrap_or_else(Body::empty);

    Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .extension(ConnectInfo(SocketAddr::new(TEST_IP, 12345)))
        .body(body)
        .expect("request builds")
}

pub async fn read(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), MAX_BODY_BYTES)
        .await
        .expect("response body is readable");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    (status, body)
}

/// Extracts the `Set-Cookie` pairs from a response as a single request header value.
pub fn cookie_header(response: &Response) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn access_token(body: &Value) -> String {
    body["access_token"]
        .as_str()
        .expect("response carries an access token")
        .to_owned()
}

pub fn refresh_token(body: &Value) -> String {
    body["refresh_token"]
        .as_str()
        .expect("response carries a refresh token")
        .to_owned()
}

pub fn user_id(body: &Value) -> uuid::Uuid {
    body["id"]
        .as_str()
        .expect("body carries a user id")
        .parse()
        .expect("user id is a uuid")
}
