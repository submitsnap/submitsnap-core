//! Turning a stored submission into the two things a destination receives: an email, and a
//! webhook payload.
//!
//! Both render from the same source so they cannot disagree about what was submitted.

use serde_json::{Value, json};

use crate::{
    dispatcher::repository::NotificationSource,
    modules::webhook::model::SUBMISSION_RECEIVED_EVENT,
    shared::{outbox::MAX_BODY_BYTES, queue::EmailJob},
};

/// One email per recipient. A separate message each is what lets a bounce be attributed, and
/// keeps an address in `Cc` from being visible to the others.
pub fn notification_email(source: &NotificationSource, recipient: &str) -> EmailJob {
    EmailJob {
        to: recipient.to_owned(),
        subject: format!("New submission for \"{}\"", source.form_name),
        text_body: email_body(source),
    }
}

fn email_body(source: &NotificationSource) -> String {
    let mut body = format!("{} received a new submission.\n\n", source.form_name);

    for (key, value) in answers(source) {
        body.push_str(&format!("  {key}: {}\n", render_value(&value)));
    }

    body.push_str(&format!(
        "\nReceived {}.\n",
        source.created_at.format("%Y-%m-%d %H:%M UTC")
    ));

    truncate(&mut body, MAX_BODY_BYTES);
    body
}

/// The answers in the order the form declares them, so the email reads like the form. A key
/// that is no longer on the form is appended rather than dropped: it was still submitted.
fn answers(source: &NotificationSource) -> Vec<(String, Value)> {
    let Some(data) = source.data.0.as_object() else {
        return Vec::new();
    };

    let mut ordered: Vec<(String, Value)> = source
        .schema
        .0
        .fields
        .iter()
        .filter_map(|field| {
            let value = data.get(&field.key)?;
            Some((field.label.clone(), value.clone()))
        })
        .collect();

    let mut remaining: Vec<(String, Value)> = data
        .iter()
        .filter(|(key, _)| source.schema.0.field(key).is_none())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    remaining.sort_by(|left, right| left.0.cmp(&right.0));

    ordered.append(&mut remaining);
    ordered
}

/// The body every matching endpoint receives, byte for byte. The signature covers exactly
/// these bytes, so this is rendered once per submission rather than once per endpoint — the
/// delivery is identified by the `X-SubmitSnap-Delivery` header instead, because the rows do
/// not exist yet when this is rendered.
pub fn webhook_payload(source: &NotificationSource) -> Value {
    json!({
        "event": SUBMISSION_RECEIVED_EVENT,
        "form": {
            "id": source.form_id,
            "name": source.form_name,
        },
        "submission": {
            "id": source.submission_id,
            "status": source.status,
            "created_at": source.created_at,
            "data": source.data.0,
        },
    })
}

/// Answers are JSON, so a list arrives as one; flattening it is what a reader expects in an
/// email, and an object is left as JSON because there is no better rendering.
fn render_value(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(items) => items
            .iter()
            .map(render_value)
            .collect::<Vec<_>>()
            .join(", "),
        Value::Object(_) => value.to_string(),
    }
}

/// Cuts on a character boundary, so a message stops rather than panics.
fn truncate(text: &mut String, limit: usize) {
    if text.len() <= limit {
        return;
    }

    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push_str("\n\n[truncated]\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sqlx::types::Json;
    use uuid::Uuid;

    use crate::modules::form::validation::{FieldDefinition, FieldType, FormSchema};

    fn field(key: &str, label: &str) -> FieldDefinition {
        FieldDefinition {
            key: key.into(),
            field_type: FieldType::Text,
            label: label.into(),
            required: false,
            help: None,
            placeholder: None,
            min_length: None,
            max_length: None,
            min: None,
            max: None,
            options: None,
            max_bytes: None,
            accept: None,
        }
    }

    fn source(data: Value, fields: Vec<FieldDefinition>) -> NotificationSource {
        NotificationSource {
            organization_id: Uuid::nil(),
            form_id: Uuid::nil(),
            form_name: "Contact us".into(),
            schema: Json(FormSchema {
                title: "Contact us".into(),
                description: None,
                submit_label: None,
                fields,
            }),
            notify_emails: vec!["team@example.com".into()],
            submission_id: Uuid::nil(),
            data: Json(data),
            status: crate::modules::form::SubmissionStatus::Unread,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn answers_are_labelled_and_ordered_like_the_form() {
        let source = source(
            json!({ "message": "hello", "email": "a@b.co" }),
            vec![field("email", "Email address"), field("message", "Message")],
        );

        let body = email_body(&source);

        let email_at = body
            .find("Email address: a@b.co")
            .expect("the label is used");
        let message_at = body.find("Message: hello").expect("the label is used");
        assert!(email_at < message_at, "declaration order is kept");
    }

    #[test]
    fn an_answer_for_a_field_that_is_gone_is_still_shown() {
        let source = source(
            json!({ "email": "a@b.co", "referrer": "https://example.com" }),
            vec![field("email", "Email")],
        );

        let body = email_body(&source);
        assert!(body.contains("Email: a@b.co"));
        assert!(
            body.contains("referrer: https://example.com"),
            "a retired field is kept, not dropped: {body}"
        );
    }

    #[test]
    fn lists_are_flattened_and_empty_answers_are_blank() {
        let source = source(
            json!({ "topics": ["Sales", "Support"], "note": null }),
            vec![field("topics", "Topics"), field("note", "Note")],
        );

        let body = email_body(&source);
        assert!(body.contains("Topics: Sales, Support"), "{body}");
        assert!(body.contains("Note: \n"), "{body}");
    }

    #[test]
    fn a_huge_answer_is_truncated_rather_than_sent() {
        let source = source(
            json!({ "message": "x".repeat(MAX_BODY_BYTES * 2) }),
            vec![field("message", "Message")],
        );

        let body = email_body(&source);
        assert!(body.len() <= MAX_BODY_BYTES + 32, "{} bytes", body.len());
        assert!(body.ends_with("[truncated]\n"));
    }

    #[test]
    fn truncation_lands_on_a_character_boundary() {
        let mut text = "é".repeat(100);
        truncate(&mut text, 5);

        assert!(text.ends_with("[truncated]\n"));
        assert!(text.is_char_boundary(text.len()));
    }

    #[test]
    fn the_webhook_payload_carries_the_event_the_form_and_the_answers() {
        let source = source(json!({ "email": "a@b.co" }), vec![field("email", "Email")]);

        let payload = webhook_payload(&source);

        assert_eq!(payload["event"], "submission.received");
        assert_eq!(payload["form"]["name"], "Contact us");
        assert_eq!(payload["submission"]["data"]["email"], "a@b.co");
        assert_eq!(payload["submission"]["status"], "unread");
    }
}
