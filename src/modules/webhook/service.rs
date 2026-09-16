//! Webhook endpoints, and the fan-out that decides a submission must be delivered somewhere.
//!
//! The module knows nothing about forms beyond an id and a rendered payload. Building the
//! payload is the dispatcher's job, which is what keeps this module from depending on the form
//! module at all.

use std::net::IpAddr;
use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    modules::{
        identity::events::{AuthEvent, AuthEventRepository, AuthEventType},
        organization::OrganizationService,
        webhook::{
            dto::{
                CreateWebhookEndpointRequest, UpdateWebhookEndpointRequest,
                WebhookDeliveryResponse, WebhookEndpointResponse,
            },
            error::WebhookError,
            model::{DeliveryFilters, WebhookDeliveryRecord, WebhookEndpointRecord},
            repository::{EndpointChanges, WebhookRepository},
        },
    },
    shared::{request::ClientInfo, tokens::generate_secret_token},
};

#[derive(Clone)]
pub struct WebhookService {
    repository: WebhookRepository,
    organizations: Arc<OrganizationService>,
    events: AuthEventRepository,
    allow_private_targets: bool,
}

impl WebhookService {
    pub fn new(
        database: PgPool,
        organizations: Arc<OrganizationService>,
        allow_private_targets: bool,
    ) -> Self {
        Self {
            repository: WebhookRepository::new(database.clone()),
            organizations,
            events: AuthEventRepository::new(database),
            allow_private_targets,
        }
    }

    /// Creates an endpoint and returns it with its secret, which is the only time the secret is
    /// ever handed out.
    pub async fn create(
        &self,
        organization_id: Uuid,
        request: &CreateWebhookEndpointRequest,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<(WebhookEndpointResponse, String), WebhookError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        check_url(&request.url, self.allow_private_targets)?;

        if let Some(form_id) = request.form_id {
            // A form from another organization must not be reachable by pairing ids.
            ensure_form_belongs_to(&self.repository, organization_id, form_id).await?;
        }

        let secret = generate_secret_token();
        let endpoint = self
            .repository
            .create_endpoint(
                organization_id,
                request.form_id,
                request.url.trim(),
                &secret,
                request.description.as_deref(),
            )
            .await?;

        self.audit(
            AuthEventType::WebhookEndpointCreated,
            organization_id,
            actor_id,
            endpoint.id,
            client,
        )
        .await;

        Ok((endpoint.into(), secret))
    }

    pub async fn list(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<WebhookEndpointResponse>, i64), WebhookError> {
        self.organizations.access(organization_id, actor_id).await?;

        let endpoints = self
            .repository
            .list_endpoints(organization_id, limit, offset)
            .await?;
        let total = self.repository.count_endpoints(organization_id).await?;

        Ok((endpoints.into_iter().map(Into::into).collect(), total))
    }

    pub async fn get(
        &self,
        organization_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
    ) -> Result<WebhookEndpointResponse, WebhookError> {
        self.organizations.access(organization_id, actor_id).await?;
        Ok(self.load(organization_id, id).await?.into())
    }

    pub async fn update(
        &self,
        organization_id: Uuid,
        id: Uuid,
        request: &UpdateWebhookEndpointRequest,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<WebhookEndpointResponse, WebhookError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        self.load(organization_id, id).await?;

        if let Some(url) = request.url.as_deref() {
            check_url(url, self.allow_private_targets)?;
        }
        if let Some(form_id) = request.form_id.flatten() {
            ensure_form_belongs_to(&self.repository, organization_id, form_id).await?;
        }

        let changes = EndpointChanges {
            url: request.url.as_deref().map(str::trim),
            description: request.description.as_ref().map(|value| value.as_deref()),
            enabled: request.enabled,
            form_id: request.form_id,
        };

        let endpoint = self
            .repository
            .update_endpoint(organization_id, id, &changes)
            .await?
            .ok_or(WebhookError::EndpointNotFound)?;

        self.audit(
            AuthEventType::WebhookEndpointUpdated,
            organization_id,
            actor_id,
            id,
            client,
        )
        .await;

        Ok(endpoint.into())
    }

    pub async fn delete(
        &self,
        organization_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<(), WebhookError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        if !self.repository.delete_endpoint(organization_id, id).await? {
            return Err(WebhookError::EndpointNotFound);
        }

        self.audit(
            AuthEventType::WebhookEndpointDeleted,
            organization_id,
            actor_id,
            id,
            client,
        )
        .await;

        Ok(())
    }

    /// Issues a new signing secret. The old signatures stop verifying immediately, which is the
    /// point: it is what an operator does when a secret has leaked.
    pub async fn rotate_secret(
        &self,
        organization_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<String, WebhookError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        self.load(organization_id, id).await?;

        let secret = generate_secret_token();
        if !self
            .repository
            .set_endpoint_secret(organization_id, id, &secret)
            .await?
        {
            return Err(WebhookError::EndpointNotFound);
        }

        self.audit(
            AuthEventType::WebhookEndpointUpdated,
            organization_id,
            actor_id,
            id,
            client,
        )
        .await;

        Ok(secret)
    }

    pub async fn list_deliveries(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        filters: &DeliveryFilters,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<WebhookDeliveryResponse>, i64), WebhookError> {
        self.organizations.access(organization_id, actor_id).await?;

        let deliveries = self
            .repository
            .list_deliveries(organization_id, filters, limit, offset)
            .await?;
        let total = self
            .repository
            .count_deliveries(organization_id, filters)
            .await?;

        Ok((deliveries.into_iter().map(Into::into).collect(), total))
    }

    /// Puts a delivery back in the queue right away, whatever its status was.
    ///
    /// The attempt count is left alone: redelivering is not an attempt that failed, and a
    /// receiver that was down for a day would otherwise be given up on instantly.
    pub async fn redeliver(
        &self,
        organization_id: Uuid,
        delivery_id: Uuid,
        actor_id: Uuid,
    ) -> Result<WebhookDeliveryResponse, WebhookError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        if !self
            .repository
            .requeue_delivery(organization_id, delivery_id)
            .await?
        {
            return Err(WebhookError::DeliveryNotFound);
        }

        self.repository
            .find_delivery(organization_id, delivery_id)
            .await?
            .ok_or(WebhookError::DeliveryNotFound)
            .map(Into::into)
    }

    /// Creates one delivery per enabled endpoint watching this form.
    ///
    /// Called by the outbox dispatcher. `payload` is already rendered, so every endpoint
    /// receives byte-identical bytes — which matters, because the signature covers exactly
    /// those bytes.
    pub async fn enqueue_deliveries(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        submission_id: Uuid,
        payload: &serde_json::Value,
    ) -> Result<u64, WebhookError> {
        self.repository
            .create_deliveries(organization_id, form_id, submission_id, payload)
            .await
    }

    async fn load(
        &self,
        organization_id: Uuid,
        id: Uuid,
    ) -> Result<WebhookEndpointRecord, WebhookError> {
        self.repository
            .find_endpoint(organization_id, id)
            .await?
            .ok_or(WebhookError::EndpointNotFound)
    }

    async fn audit(
        &self,
        event_type: AuthEventType,
        organization_id: Uuid,
        actor_id: Uuid,
        target_id: Uuid,
        client: &ClientInfo,
    ) {
        self.events
            .record(AuthEvent {
                user_id: None,
                actor_user_id: Some(actor_id),
                organization_id: Some(organization_id),
                target_id: Some(target_id),
                email: None,
                event_type,
                ip_address: client.ip_address,
                user_agent: client.user_agent.as_deref(),
            })
            .await;
    }
}

/// A webhook is fetched by this server, so an arbitrary scheme would be a request forgery tool
/// and a URL that is not absolute would fail at delivery time with nothing useful to show.
///
/// The host is checked as written, not as resolved. That catches the common mistake and keeps a
/// link-local address — where cloud instance credentials live — out of reach of an organization
/// administrator, but it is not a defence against a hostname that resolves somewhere private.
/// `WEBHOOK_ALLOW_PRIVATE_TARGETS` is the deliberate escape hatch for a receiver on the same
/// host or a private network.
fn check_url(url: &str, allow_private: bool) -> Result<(), WebhookError> {
    let url = url.trim();
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(WebhookError::Invalid(
            "url must be an absolute http or https address".to_owned(),
        ));
    };

    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(WebhookError::Invalid(
            "url must be an http or https address".to_owned(),
        ));
    }

    let host = host_of(rest);
    if host.is_empty() {
        return Err(WebhookError::Invalid("url must name a host".to_owned()));
    }

    // A literal address that is link-local or loopback is almost always a mistake, and the
    // link-local range is where cloud instance credentials live.
    if !allow_private
        && let Ok(address) = host.trim_matches(['[', ']']).parse::<IpAddr>()
        && is_forbidden_address(address)
    {
        return Err(WebhookError::Invalid(
            "url must not point at a loopback or link-local address".to_owned(),
        ));
    }

    Ok(())
}

/// Whether something must be watched so this form can exist at all. Refusing here is better
/// than a foreign key error, and much better than accepting it.
async fn ensure_form_belongs_to(
    repository: &WebhookRepository,
    organization_id: Uuid,
    form_id: Uuid,
) -> Result<(), WebhookError> {
    if repository.form_belongs_to(organization_id, form_id).await? {
        Ok(())
    } else {
        Err(WebhookError::Invalid(
            "form_id does not name a form in this organization".to_owned(),
        ))
    }
}

fn host_of(rest: &str) -> &str {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let after_userinfo = authority.rsplit('@').next().unwrap_or_default();

    // A bracketed IPv6 host keeps its brackets so a trailing port can be told apart; only the
    // brackets separate `2001:db8::1` from its `:8443`.
    if after_userinfo.starts_with('[') {
        return match after_userinfo.find(']') {
            Some(end) => &after_userinfo[..=end],
            None => after_userinfo,
        };
    }

    after_userinfo
        .split_once(':')
        .map(|(host, _)| host)
        .unwrap_or(after_userinfo)
}

fn is_forbidden_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

impl From<WebhookEndpointRecord> for WebhookEndpointResponse {
    fn from(endpoint: WebhookEndpointRecord) -> Self {
        Self {
            id: endpoint.id,
            organization_id: endpoint.organization_id,
            form_id: endpoint.form_id,
            url: endpoint.url,
            description: endpoint.description,
            enabled: endpoint.enabled,
            created_at: endpoint.created_at,
            updated_at: endpoint.updated_at,
        }
    }
}

impl From<WebhookDeliveryRecord> for WebhookDeliveryResponse {
    fn from(delivery: WebhookDeliveryRecord) -> Self {
        Self {
            id: delivery.id,
            endpoint_id: delivery.endpoint_id,
            submission_id: delivery.submission_id,
            status: delivery.status,
            attempts: delivery.attempts,
            response_status: delivery.response_status,
            last_error: delivery.last_error,
            next_attempt_at: delivery.next_attempt_at,
            created_at: delivery.created_at,
            delivered_at: delivery.delivered_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_absolute_http_urls_are_accepted() {
        assert!(check_url("https://example.com/hooks", false).is_ok());
        assert!(check_url("http://example.com:8080/hooks?x=1", false).is_ok());
        assert!(check_url("https://example.com", false).is_ok());

        assert!(check_url("ftp://example.com", false).is_err(), "scheme");
        assert!(
            check_url("example.com/hooks", false).is_err(),
            "not absolute"
        );
        assert!(check_url("https://", false).is_err(), "no host");
        assert!(check_url("file:///etc/passwd", false).is_err(), "scheme");
    }

    #[test]
    fn loopback_and_link_local_targets_are_refused() {
        assert!(check_url("http://127.0.0.1:9000/hooks", false).is_err());
        assert!(check_url("http://[::1]:9000/hooks", false).is_err());
        assert!(check_url("http://169.254.169.254/latest/meta-data/", false).is_err());
        assert!(check_url("http://0.0.0.0/hooks", false).is_err());

        // A hostname is not resolved here, so this is a check against the obvious mistake
        // rather than a defence against a determined one.
        assert!(check_url("https://hooks.example.com/9f8e7d", false).is_ok());
    }

    #[test]
    fn a_self_hosted_receiver_on_the_same_box_can_be_opted_into() {
        assert!(check_url("http://127.0.0.1:9000/hooks", true).is_ok());
        assert!(check_url("http://[::1]:9000/hooks", true).is_ok());

        // The escape hatch is only about addresses: an unusable URL is still unusable.
        assert!(check_url("ftp://127.0.0.1/hooks", true).is_err());
        assert!(check_url("127.0.0.1/hooks", true).is_err());
    }

    #[test]
    fn the_host_is_read_out_of_every_ordinary_authority() {
        assert_eq!(host_of("example.com/hooks"), "example.com");
        assert_eq!(host_of("example.com:8443/hooks"), "example.com");
        assert_eq!(host_of("user@example.com/hooks"), "example.com");
        assert_eq!(host_of("[2001:db8::1]:8443/hooks"), "[2001:db8::1]");
        assert_eq!(host_of("example.com/hooks?q=1#frag"), "example.com");
    }
}
