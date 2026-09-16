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
    dispatcher::Dispatcher,
    modules::{
        identity::IdentityService,
        organization::OrganizationService,
        webhook::{WebhookDeliverer, WebhookService},
    },
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

pub fn email_queue(config: &AppConfig) -> EmailQueue {
    EmailQueue::connect(&config.redis_url, &config.redis_key_prefix).expect("queue pool builds")
}

/// Matches the worker's own batch size, so a test cannot pass by draining more in one pass than
/// a real deployment would.
pub const DISPATCH_BATCH: i64 = 20;

/// The queue a test can actually talk to.
///
/// Most tests deliberately point at an unreachable Redis, because nothing they exercise should
/// depend on it. Dispatch does — an enqueue that fails is a failure, by design — so a test of
/// the dispatch path points at the real server under a prefix of its own and never sees another
/// test's jobs.
pub fn reachable_redis_config(extra: Vec<(&str, String)>) -> Arc<AppConfig> {
    let mut settings = extra;
    settings.push(("redis_url", "redis://127.0.0.1:6399".to_owned()));
    settings.push((
        "redis_key_prefix",
        format!("submitsnap-test-{}", uuid::Uuid::new_v4()),
    ));

    Arc::new(config_with(settings))
}

/// The same service graph the worker builds.
///
/// A test drives the real dispatch and delivery path rather than a stand-in, which is the only
/// way assertions about retries, signatures, and idempotency mean anything.
pub fn worker_graph(
    config: &Arc<AppConfig>,
    pool: PgPool,
) -> (Arc<Dispatcher>, WebhookDeliverer, EmailQueue) {
    let queue = email_queue(config);
    let identity = IdentityService::new(pool.clone(), queue.clone(), config.clone())
        .expect("identity service builds");
    let organizations = Arc::new(OrganizationService::new(pool.clone(), Arc::new(identity)));
    let webhooks = Arc::new(WebhookService::new(
        pool.clone(),
        organizations,
        config.webhook_allow_private_targets,
    ));

    let dispatcher = Arc::new(Dispatcher::new(
        pool.clone(),
        queue.clone(),
        webhooks,
        DISPATCH_BATCH,
    ));
    let deliverer = WebhookDeliverer::new(pool, config.webhook_timeout_seconds, DISPATCH_BATCH)
        .expect("deliverer builds");

    (dispatcher, deliverer, queue)
}

/// A `TestApp` whose service graph a test can also drive as a worker.
pub fn with_worker_config(extra: Vec<(&str, String)>, pool: PgPool) -> (TestApp, Arc<AppConfig>) {
    let config = reachable_redis_config(extra);
    let state = AppState::new(config.clone(), pool, email_queue(&config));

    let app = TestApp {
        router: app(state).expect("app builds"),
        config: config.clone(),
    };

    (app, config)
}

/// The service graph the app builds, exposed so a test can drive a service directly rather than
/// only through HTTP — which is the only way to exercise something the worker runs on a timer,
/// such as collecting abandoned uploads.
pub fn api_state(config: &Arc<AppConfig>, pool: PgPool) -> submitsnap_core::modules::ApiState {
    let state = AppState::new(config.clone(), pool, email_queue(config));

    submitsnap_core::modules::ApiState::new(
        state.database.clone(),
        state.queue.clone(),
        state.config.clone(),
        state.rate_limiters.clone(),
    )
    .expect("the service graph builds")
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

    pub async fn patch_json_auth(
        &self,
        path: &str,
        body: Value,
        token: &str,
    ) -> (StatusCode, Value) {
        read(
            self.send(json_request(Method::PATCH, path, Some(body), Some(token)))
                .await,
        )
        .await
    }

    pub async fn put_json_auth(&self, path: &str, body: Value, token: &str) -> (StatusCode, Value) {
        read(
            self.send(json_request(Method::PUT, path, Some(body), Some(token)))
                .await,
        )
        .await
    }

    pub async fn delete_json_auth(
        &self,
        path: &str,
        body: Value,
        token: &str,
    ) -> (StatusCode, Value) {
        read(
            self.send(json_request(Method::DELETE, path, Some(body), Some(token)))
                .await,
        )
        .await
    }

    pub async fn delete_auth(&self, path: &str, token: &str) -> (StatusCode, Value) {
        read(
            self.send(json_request(Method::DELETE, path, None, Some(token)))
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

/// Grants the administrator role directly, since there is deliberately no API that hands out
/// roles to unauthenticated callers.
pub async fn grant_admin_role(pool: &PgPool, user_id: uuid::Uuid) {
    sqlx::query(
        "INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = 'admin'",
    )
    .bind(user_id)
    .execute(pool)
    .await
    .expect("admin role is granted");
}

/// A CORS preflight request, used to check the allowed-origin behaviour.
pub fn preflight(origin: &str) -> Request<Body> {
    Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/v1/auth/login")
        .header(header::ORIGIN, origin)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
        .extension(ConnectInfo(SocketAddr::new(TEST_IP, 12345)))
        .body(Body::empty())
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
