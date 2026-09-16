//! Form lifecycle and public ingestion.
//!
//! Two things are worth knowing about the shape of this module:
//!
//! * Access is resolved through [`OrganizationService::access`], so a form can never be reached
//!   across tenants and the authorization check is one call rather than a convention.
//! * Public ingestion deliberately does the cheapest checks first and touches the queue not at
//!   all. It is the one path whose latency a stranger feels.

use std::sync::Arc;

use serde_json::{Map, Value};
use sqlx::PgPool;
use uuid::Uuid;
use validator::ValidateEmail;

use crate::{
    modules::{
        form::{
            dto::{
                CreateFormRequest, FormResponse, PublicFormResponse, SubmissionAcceptedResponse,
                UpdateFormRequest,
            },
            error::FormError,
            model::{FormRecord, NewSubmission, SubmissionStatus},
            repository::{FormRepository, SubmissionRepository},
            validation::{FormSchema, HONEYPOT_FIELD, validate_schema, validate_submission},
        },
        identity::events::{AuthEvent, AuthEventRepository, AuthEventType},
        organization::OrganizationService,
    },
    shared::{ratelimit::FormLimiter, request::ClientInfo, tokens::generate_secret_token},
};

#[derive(Clone)]
pub struct FormService {
    forms: FormRepository,
    submissions: SubmissionRepository,
    organizations: Arc<OrganizationService>,
    events: AuthEventRepository,
    per_form_limiter: Arc<FormLimiter>,
    file_uploads_enabled: bool,
}

impl FormService {
    pub fn new(
        database: PgPool,
        organizations: Arc<OrganizationService>,
        per_form_limiter: Arc<FormLimiter>,
        file_uploads_enabled: bool,
    ) -> Self {
        Self {
            forms: FormRepository::new(database.clone()),
            submissions: SubmissionRepository::new(database.clone()),
            organizations,
            events: AuthEventRepository::new(database),
            per_form_limiter,
            file_uploads_enabled,
        }
    }

    /// Whether this deployment can accept file answers at all.
    pub fn file_uploads_enabled(&self) -> bool {
        self.file_uploads_enabled
    }

    pub async fn create(
        &self,
        organization_id: Uuid,
        request: &CreateFormRequest,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<FormResponse, FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        // A draft may hold a file field; publishing is what demands storage.
        self.check_schema(&request.schema, false)?;

        let form = self
            .forms
            .create(
                organization_id,
                request.name.trim(),
                &generate_secret_token(),
                &request.schema,
            )
            .await?;

        self.audit(
            AuthEventType::FormCreated,
            organization_id,
            actor_id,
            form.id,
            Some(&form.name),
            client,
        )
        .await;

        Ok(form.into())
    }

    pub async fn list(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<FormResponse>, i64), FormError> {
        // Reading only needs membership, which is why the role is not required to be a manager.
        self.organizations.access(organization_id, actor_id).await?;

        let forms = self.forms.list(organization_id, limit, offset).await?;
        let total = self.forms.count(organization_id).await?;

        Ok((forms.into_iter().map(Into::into).collect(), total))
    }

    pub async fn get(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        actor_id: Uuid,
    ) -> Result<FormResponse, FormError> {
        self.organizations.access(organization_id, actor_id).await?;
        Ok(self.load(organization_id, form_id).await?.into())
    }

    pub async fn update(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        request: &UpdateFormRequest,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<FormResponse, FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        let current = self.load(organization_id, form_id).await?;

        let name = match request.name.as_deref() {
            Some(name) => name.trim().to_owned(),
            None => current.name.clone(),
        };
        let schema = request
            .schema
            .clone()
            .unwrap_or_else(|| current.schema.0.clone());
        let notify_emails = request
            .notify_emails
            .clone()
            .unwrap_or_else(|| current.notify_emails.clone());
        let success_message = match &request.success_message {
            Some(value) => value.clone(),
            None => current.success_message.clone(),
        };
        let redirect_url = match &request.redirect_url {
            Some(value) => value.clone(),
            None => current.redirect_url.clone(),
        };
        let honeypot_enabled = request.honeypot_enabled.unwrap_or(current.honeypot_enabled);

        if name.is_empty() || name.chars().count() > 120 {
            return Err(FormError::InvalidSchema(
                "name must be between 1 and 120 characters".to_owned(),
            ));
        }

        // A published form must stay submittable, so the definition is checked on every write
        // and not only at creation.
        self.check_schema(&schema, current.status.accepts_submissions())?;
        check_redirect_url(redirect_url.as_deref())?;
        check_notify_emails(&notify_emails)?;

        let schema_changed = schema.fields != current.schema.0.fields;

        let updated = self
            .forms
            .replace_definition(
                organization_id,
                form_id,
                &name,
                &schema,
                schema_changed,
                &notify_emails,
                success_message.as_deref(),
                redirect_url.as_deref(),
                honeypot_enabled,
            )
            .await?;

        if !updated {
            return Err(FormError::NotFound);
        }

        self.audit(
            AuthEventType::FormUpdated,
            organization_id,
            actor_id,
            form_id,
            Some(&name),
            client,
        )
        .await;

        self.get(organization_id, form_id, actor_id).await
    }

    pub async fn delete(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<(), FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        let form = self.load(organization_id, form_id).await?;
        if !self.forms.delete(organization_id, form_id).await? {
            return Err(FormError::NotFound);
        }

        self.audit(
            AuthEventType::FormDeleted,
            organization_id,
            actor_id,
            form_id,
            Some(&form.name),
            client,
        )
        .await;

        Ok(())
    }

    pub async fn publish(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<FormResponse, FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        let form = self.load(organization_id, form_id).await?;
        // Re-checked here because publishing is the moment a definition starts accepting input.
        self.check_schema(&form.schema.0, true)?;

        self.forms
            .set_status(
                organization_id,
                form_id,
                crate::modules::form::model::FormStatus::Published,
            )
            .await?;

        self.audit(
            AuthEventType::FormPublished,
            organization_id,
            actor_id,
            form_id,
            Some(&form.name),
            client,
        )
        .await;

        self.get(organization_id, form_id, actor_id).await
    }

    pub async fn close(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<FormResponse, FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        let form = self.load(organization_id, form_id).await?;
        if !form.status.accepts_submissions() {
            return Err(FormError::InvalidSchema(
                "only a published form can be closed".to_owned(),
            ));
        }

        self.forms
            .set_status(
                organization_id,
                form_id,
                crate::modules::form::model::FormStatus::Closed,
            )
            .await?;

        self.audit(
            AuthEventType::FormClosed,
            organization_id,
            actor_id,
            form_id,
            Some(&form.name),
            client,
        )
        .await;

        self.get(organization_id, form_id, actor_id).await
    }

    /// Issues a new public handle, which instantly invalidates the old link. The answer to a
    /// form being spammed.
    pub async fn rotate_public_id(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<FormResponse, FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        let form = self.load(organization_id, form_id).await?;
        self.forms
            .set_public_id(organization_id, form_id, &generate_secret_token())
            .await?;

        self.audit(
            AuthEventType::FormPublicIdRotated,
            organization_id,
            actor_id,
            form_id,
            Some(&form.name),
            client,
        )
        .await;

        self.get(organization_id, form_id, actor_id).await
    }

    /// The public definition. A draft answers 404 rather than 403 so an unfinished form is not
    /// discoverable by anybody who happened to guess the link.
    pub async fn public_definition(
        &self,
        public_id: &str,
    ) -> Result<PublicFormResponse, FormError> {
        let form = self.load_published(public_id).await?;
        Ok(PublicFormResponse::new(&form))
    }

    /// The public hot path: resolve, validate, insert. No queue, no audit row, and no second
    /// lookup — the form row needed for validation is the one already fetched.
    pub async fn submit(
        &self,
        public_id: &str,
        payload: &Map<String, Value>,
        client: &ClientInfo,
        referer: Option<&str>,
    ) -> Result<SubmissionAcceptedResponse, FormError> {
        let form = self.load_published(public_id).await?;

        // Keyed by form rather than by caller: a flood aimed at one tenant should not consume
        // anybody else's budget, and a busy form is a legitimate thing.
        if self.per_form_limiter.check_key(&form.id).is_err() {
            return Err(FormError::TooManySubmissions);
        }

        let answers = validate_submission(&form.schema.0, payload)
            .map_err(|problems| FormError::InvalidSubmission(problems.join("; ")))?;

        // A bot that fills every input fills the honeypot too. The submission is accepted as
        // normal so it learns nothing, and filed as spam for the organization to ignore.
        let status = if form.honeypot_enabled && honeypot_was_filled(payload) {
            SubmissionStatus::Spam
        } else {
            SubmissionStatus::Unread
        };

        let data = Value::Object(answers);
        let id = self
            .submissions
            .insert(NewSubmission {
                organization_id: form.organization_id,
                form_id: form.id,
                schema_version: form.schema_version,
                data: &data,
                status,
                ip_address: client
                    .ip_address
                    .map(|address| address.to_string())
                    .as_deref(),
                user_agent: client.user_agent.as_deref(),
                referer,
            })
            .await?;

        Ok(SubmissionAcceptedResponse {
            id,
            success_message: form.success_message,
            redirect_url: form.redirect_url,
        })
    }

    async fn load(&self, organization_id: Uuid, form_id: Uuid) -> Result<FormRecord, FormError> {
        self.forms
            .find(organization_id, form_id)
            .await?
            .ok_or(FormError::NotFound)
    }

    /// Resolves a public handle, refusing the states that must not accept submissions. Draft is
    /// reported as missing on purpose; only a closed form explains itself.
    async fn load_published(&self, public_id: &str) -> Result<FormRecord, FormError> {
        let form = self
            .forms
            .find_by_public_id(public_id)
            .await?
            .ok_or(FormError::NotFound)?;

        match form.status {
            crate::modules::form::model::FormStatus::Published => Ok(form),
            crate::modules::form::model::FormStatus::Draft => Err(FormError::NotFound),
            crate::modules::form::model::FormStatus::Closed => Err(FormError::Closed),
        }
    }

    /// A definition is checked on every write, so a stored form is always renderable and always
    /// submittable.
    fn check_schema(
        &self,
        schema: &FormSchema,
        require_submittable: bool,
    ) -> Result<(), FormError> {
        validate_schema(schema)
            .map_err(|problems| FormError::InvalidSchema(problems.join("; ")))?;

        if require_submittable && schema.has_file_field() && !self.file_uploads_enabled {
            return Err(FormError::FileUploadsUnavailable);
        }

        Ok(())
    }

    async fn audit(
        &self,
        event_type: AuthEventType,
        organization_id: Uuid,
        actor_id: Uuid,
        target_id: Uuid,
        label: Option<&str>,
        client: &ClientInfo,
    ) {
        self.events
            .record(AuthEvent {
                user_id: None,
                actor_user_id: Some(actor_id),
                organization_id: Some(organization_id),
                target_id: Some(target_id),
                email: label,
                event_type,
                ip_address: client.ip_address,
                user_agent: client.user_agent.as_deref(),
            })
            .await;
    }
}

fn honeypot_was_filled(payload: &Map<String, Value>) -> bool {
    payload
        .get(HONEYPOT_FIELD)
        .map(|value| match value {
            Value::Null => false,
            Value::String(text) => !text.trim().is_empty(),
            _ => true,
        })
        .unwrap_or(false)
}

fn check_notify_emails(emails: &[String]) -> Result<(), FormError> {
    if emails.len() > 20 {
        return Err(FormError::InvalidSchema(
            "at most 20 notification addresses".to_owned(),
        ));
    }
    if let Some(bad) = emails.iter().find(|email| !email.validate_email()) {
        return Err(FormError::InvalidSchema(format!(
            "{bad} is not a valid email address"
        )));
    }

    Ok(())
}

fn check_redirect_url(url: Option<&str>) -> Result<(), FormError> {
    let Some(url) = url else {
        return Ok(());
    };
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(FormError::InvalidSchema(
            "redirect_url must be an http or https address".to_owned(),
        ));
    }

    Ok(())
}
