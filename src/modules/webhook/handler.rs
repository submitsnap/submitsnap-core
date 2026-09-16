//! Webhook endpoints and their delivery log, under
//! `/api/v1/organizations/{organization_id}`.
//!
//! Authorization lives in the service, so a handler reads as "resolve, authorize, act".

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::{
    modules::{
        ApiState,
        auth::AuthenticatedUser,
        webhook::dto::{
            CreateWebhookEndpointRequest, DeliveryQuery, UpdateWebhookEndpointRequest,
            WebhookDeliveryListResponse, WebhookDeliveryResponse, WebhookEndpointListResponse,
            WebhookEndpointQuery, WebhookEndpointResponse, WebhookSecretResponse,
        },
    },
    shared::{
        error::{AppError, ErrorResponse},
        pagination::page_bounds,
    },
};

type EndpointPath = (Uuid, Uuid);

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{organization_id}/webhook-endpoints",
    tag = "webhooks",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("organization_id" = Uuid, Path, description = "Organization identifier")),
    request_body = CreateWebhookEndpointRequest,
    responses(
        (status = 201, description = "Created. The secret is returned here and never again.", body = WebhookSecretResponse),
        (status = 400, description = "The url or form_id is not acceptable", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such organization", body = ErrorResponse),
    )
)]
pub async fn create_endpoint(
    State(state): State<ApiState>,
    client: crate::shared::request::ClientInfo,
    user: AuthenticatedUser,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateWebhookEndpointRequest>,
) -> Result<(StatusCode, Json<WebhookSecretResponse>), AppError> {
    let (endpoint, secret) = state
        .webhooks
        .create(organization_id, &request, user.user.id, &client)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(WebhookSecretResponse {
            id: endpoint.id,
            url: endpoint.url,
            secret,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/webhook-endpoints",
    tag = "webhooks",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("organization_id" = Uuid, Path, description = "Organization identifier"), WebhookEndpointQuery),
    responses(
        (status = 200, description = "Page of endpoints, without their secrets", body = WebhookEndpointListResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Not a member", body = ErrorResponse),
        (status = 404, description = "No such organization", body = ErrorResponse),
    )
)]
pub async fn list_endpoints(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path(organization_id): Path<Uuid>,
    Query(query): Query<WebhookEndpointQuery>,
) -> Result<Json<WebhookEndpointListResponse>, AppError> {
    let (limit, offset) = page_bounds(query.limit, query.offset);
    let (endpoints, total) = state
        .webhooks
        .list(organization_id, user.user.id, limit, offset)
        .await?;

    Ok(Json(WebhookEndpointListResponse { endpoints, total }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/webhook-endpoints/{endpoint_id}",
    tag = "webhooks",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("endpoint_id" = Uuid, Path, description = "Endpoint identifier"),
    ),
    responses(
        (status = 200, description = "The endpoint, without its secret", body = WebhookEndpointResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Not a member", body = ErrorResponse),
        (status = 404, description = "No such endpoint", body = ErrorResponse),
    )
)]
pub async fn get_endpoint(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path((organization_id, endpoint_id)): Path<EndpointPath>,
) -> Result<Json<WebhookEndpointResponse>, AppError> {
    Ok(Json(
        state
            .webhooks
            .get(organization_id, endpoint_id, user.user.id)
            .await?,
    ))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{organization_id}/webhook-endpoints/{endpoint_id}",
    tag = "webhooks",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("endpoint_id" = Uuid, Path, description = "Endpoint identifier"),
    ),
    request_body = UpdateWebhookEndpointRequest,
    responses(
        (status = 200, description = "Updated", body = WebhookEndpointResponse),
        (status = 400, description = "The url or form_id is not acceptable", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such endpoint", body = ErrorResponse),
    )
)]
pub async fn update_endpoint(
    State(state): State<ApiState>,
    client: crate::shared::request::ClientInfo,
    user: AuthenticatedUser,
    Path((organization_id, endpoint_id)): Path<EndpointPath>,
    Json(request): Json<UpdateWebhookEndpointRequest>,
) -> Result<Json<WebhookEndpointResponse>, AppError> {
    Ok(Json(
        state
            .webhooks
            .update(
                organization_id,
                endpoint_id,
                &request,
                user.user.id,
                &client,
            )
            .await?,
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{organization_id}/webhook-endpoints/{endpoint_id}",
    tag = "webhooks",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("endpoint_id" = Uuid, Path, description = "Endpoint identifier"),
    ),
    responses(
        (status = 204, description = "Removed, along with its delivery log"),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such endpoint", body = ErrorResponse),
    )
)]
pub async fn delete_endpoint(
    State(state): State<ApiState>,
    client: crate::shared::request::ClientInfo,
    user: AuthenticatedUser,
    Path((organization_id, endpoint_id)): Path<EndpointPath>,
) -> Result<StatusCode, AppError> {
    state
        .webhooks
        .delete(organization_id, endpoint_id, user.user.id, &client)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{organization_id}/webhook-endpoints/{endpoint_id}/rotate-secret",
    tag = "webhooks",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("endpoint_id" = Uuid, Path, description = "Endpoint identifier"),
    ),
    responses(
        (status = 200, description = "New secret issued; the previous one stops verifying immediately", body = WebhookSecretResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such endpoint", body = ErrorResponse),
    )
)]
pub async fn rotate_secret(
    State(state): State<ApiState>,
    client: crate::shared::request::ClientInfo,
    user: AuthenticatedUser,
    Path((organization_id, endpoint_id)): Path<EndpointPath>,
) -> Result<Json<WebhookSecretResponse>, AppError> {
    let endpoint = state
        .webhooks
        .get(organization_id, endpoint_id, user.user.id)
        .await?;
    let secret = state
        .webhooks
        .rotate_secret(organization_id, endpoint_id, user.user.id, &client)
        .await?;

    Ok(Json(WebhookSecretResponse {
        id: endpoint.id,
        url: endpoint.url,
        secret,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/webhook-deliveries",
    tag = "webhooks",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("organization_id" = Uuid, Path, description = "Organization identifier"), DeliveryQuery),
    responses(
        (status = 200, description = "Page of deliveries, newest first", body = WebhookDeliveryListResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Not a member", body = ErrorResponse),
        (status = 404, description = "No such organization", body = ErrorResponse),
    )
)]
pub async fn list_deliveries(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path(organization_id): Path<Uuid>,
    Query(query): Query<DeliveryQuery>,
) -> Result<Json<WebhookDeliveryListResponse>, AppError> {
    let (limit, offset) = page_bounds(query.limit, query.offset);
    let (deliveries, total) = state
        .webhooks
        .list_deliveries(
            organization_id,
            user.user.id,
            &(&query).into(),
            limit,
            offset,
        )
        .await?;

    Ok(Json(WebhookDeliveryListResponse { deliveries, total }))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{organization_id}/webhook-deliveries/{delivery_id}/redeliver",
    tag = "webhooks",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("delivery_id" = Uuid, Path, description = "Delivery identifier"),
    ),
    responses(
        (status = 200, description = "Queued for another attempt now", body = WebhookDeliveryResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such delivery", body = ErrorResponse),
    )
)]
pub async fn redeliver(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path((organization_id, delivery_id)): Path<EndpointPath>,
) -> Result<Json<WebhookDeliveryResponse>, AppError> {
    Ok(Json(
        state
            .webhooks
            .redeliver(organization_id, delivery_id, user.user.id)
            .await?,
    ))
}
