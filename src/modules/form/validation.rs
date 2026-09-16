//! The form definition contract and the payload validation built on it.
//!
//! Both validators report *every* problem they find rather than the first, so an author fixing
//! a definition and a client fixing a payload each get one pass instead of many.

use std::collections::HashSet;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use validator::ValidateEmail;

/// Keys beginning with this are reserved for client-side helpers, and are never stored as
/// answers. It is what lets a form carry a honeypot and a tracking field without the schema
/// having to declare them.
pub const RESERVED_PREFIX: char = '_';

/// The field the honeypot uses. A bot that fills everything fills this too.
pub const HONEYPOT_FIELD: &str = "_gotcha";

pub const MAX_FIELDS: usize = 50;
pub const MAX_KEY_LENGTH: usize = 64;
pub const MAX_OPTIONS: usize = 100;
pub const MAX_LABEL_LENGTH: usize = 200;
pub const MAX_TEXT_LENGTH: u32 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Text,
    Textarea,
    Email,
    Number,
    Date,
    Select,
    Checkbox,
    File,
}

impl FieldType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Textarea => "textarea",
            Self::Email => "email",
            Self::Number => "number",
            Self::Date => "date",
            Self::Select => "select",
            Self::Checkbox => "checkbox",
            Self::File => "file",
        }
    }
}

/// One question on a form. The type-specific fields are optional and only meaningful for the
/// types they belong to; the validator rejects the combinations that make no sense.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldDefinition {
    pub key: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    pub label: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub help: Option<String>,
    #[serde(default)]
    pub placeholder: Option<String>,
    #[serde(default)]
    pub min_length: Option<u32>,
    #[serde(default)]
    pub max_length: Option<u32>,
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
    /// Required for `select`.
    #[serde(default)]
    pub options: Option<Vec<String>>,
    /// `file` only: the largest object the upload endpoint will sign.
    #[serde(default)]
    pub max_bytes: Option<u64>,
    /// `file` only: permitted content types.
    #[serde(default)]
    pub accept: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FormSchema {
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub submit_label: Option<String>,
    pub fields: Vec<FieldDefinition>,
}

impl FormSchema {
    pub fn field(&self, key: &str) -> Option<&FieldDefinition> {
        self.fields.iter().find(|field| field.key == key)
    }

    pub fn has_file_field(&self) -> bool {
        self.fields
            .iter()
            .any(|field| field.field_type == FieldType::File)
    }
}

/// Checks a stored definition. A form that passes this is always renderable and always
/// submittable, which is what lets ingestion trust the schema without re-checking it.
pub fn validate_schema(schema: &FormSchema) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();

    if schema.title.trim().is_empty() {
        problems.push("title must not be empty".to_owned());
    }
    if schema.fields.is_empty() {
        problems.push("a form needs at least one field".to_owned());
    }
    if schema.fields.len() > MAX_FIELDS {
        problems.push(format!("a form may have at most {MAX_FIELDS} fields"));
    }

    let mut seen = HashSet::new();
    for field in &schema.fields {
        let named = format!("field {:?}", field.key);

        if !is_valid_key(&field.key) {
            problems.push(format!(
                "{named}: key must start with a lowercase letter and contain only lowercase \
                 letters, digits, and underscores, up to {MAX_KEY_LENGTH} characters"
            ));
        }
        if !seen.insert(field.key.as_str()) {
            problems.push(format!("{named}: key is used more than once"));
        }
        if field.key.starts_with(RESERVED_PREFIX) {
            problems.push(format!(
                "{named}: keys starting with {RESERVED_PREFIX} are reserved"
            ));
        }
        if field.label.trim().is_empty() || field.label.chars().count() > MAX_LABEL_LENGTH {
            problems.push(format!(
                "{named}: label must be between 1 and {MAX_LABEL_LENGTH} characters"
            ));
        }

        validate_field_rules(field, &named, &mut problems);
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

fn validate_field_rules(field: &FieldDefinition, named: &str, problems: &mut Vec<String>) {
    if let (Some(min), Some(max)) = (field.min_length, field.max_length)
        && min > max
    {
        problems.push(format!("{named}: min_length is greater than max_length"));
    }
    if let (Some(min), Some(max)) = (field.min, field.max)
        && min > max
    {
        problems.push(format!("{named}: min is greater than max"));
    }

    match field.field_type {
        FieldType::Select => match field.options.as_deref() {
            Some([]) => {
                problems.push(format!("{named}: a select needs at least one option"));
            }
            Some(options) if options.len() > MAX_OPTIONS => {
                problems.push(format!(
                    "{named}: a select may have at most {MAX_OPTIONS} options"
                ));
            }
            None => problems.push(format!("{named}: a select needs options")),
            Some(_) => {}
        },
        FieldType::File => {
            if field.max_bytes == Some(0) {
                problems.push(format!("{named}: max_bytes must be greater than zero"));
            }
        }
        FieldType::Text
        | FieldType::Textarea
        | FieldType::Email
        | FieldType::Number
        | FieldType::Date
        | FieldType::Checkbox => {
            if field.options.is_some() {
                problems.push(format!("{named}: options only apply to a select field"));
            }
        }
    }

    // `min`/`max` are numbers, so they only mean something for a number field. Saying so here
    // is better than quietly ignoring them on a date.
    if field.field_type != FieldType::Number && (field.min.is_some() || field.max.is_some()) {
        problems.push(format!("{named}: min and max only apply to a number field"));
    }
}

/// Validates a payload against the definition and returns the answers to store.
///
/// Keys beginning with [`RESERVED_PREFIX`] are dropped rather than stored, and every other key
/// must be declared: silently accepting undeclared answers would let a client put anything into
/// an organization's data.
pub fn validate_submission(
    schema: &FormSchema,
    payload: &Map<String, Value>,
) -> Result<Map<String, Value>, Vec<String>> {
    let mut problems = Vec::new();
    let mut answers = Map::new();

    for (key, value) in payload {
        if key.starts_with(RESERVED_PREFIX) {
            continue;
        }
        if let Some(field) = schema.field(key) {
            if let Some(accepted) = check_value(field, value, &mut problems) {
                answers.insert(key.clone(), accepted);
            }
        } else {
            problems.push(format!("{key:?} is not a field on this form"));
        }
    }

    for field in &schema.fields {
        if field.required && is_absent(payload.get(&field.key)) {
            problems.push(format!("{} is required", field.key));
        }
    }

    if problems.is_empty() {
        Ok(answers)
    } else {
        Err(problems)
    }
}

/// Checks one answer, returning the value to store when it is acceptable.
fn check_value(
    field: &FieldDefinition,
    value: &Value,
    problems: &mut Vec<String>,
) -> Option<Value> {
    let key = &field.key;

    if value.is_null() {
        if field.required {
            problems.push(format!("{key} is required"));
        }
        return None;
    }

    match field.field_type {
        FieldType::Text | FieldType::Textarea | FieldType::Email => {
            let Some(text) = value.as_str() else {
                problems.push(format!("{key} must be a string"));
                return None;
            };
            if field.required && text.trim().is_empty() {
                problems.push(format!("{key} is required"));
                return None;
            }
            if let Some(min) = field.min_length
                && (text.chars().count() as u32) < min
            {
                problems.push(format!("{key} must be at least {min} characters"));
            }
            let max = field.max_length.unwrap_or(MAX_TEXT_LENGTH);
            if text.chars().count() as u32 > max {
                problems.push(format!("{key} must be at most {max} characters"));
            }
            if field.field_type == FieldType::Email && !text.validate_email() {
                problems.push(format!("{key} must be a valid email address"));
            }
            Some(value.clone())
        }
        FieldType::Number => {
            let Some(number) = value.as_f64() else {
                problems.push(format!("{key} must be a number"));
                return None;
            };
            if let Some(min) = field.min
                && number < min
            {
                problems.push(format!("{key} must be at least {min}"));
            }
            if let Some(max) = field.max
                && number > max
            {
                problems.push(format!("{key} must be at most {max}"));
            }
            Some(value.clone())
        }
        FieldType::Date => {
            let Some(text) = value.as_str() else {
                problems.push(format!("{key} must be a date in YYYY-MM-DD form"));
                return None;
            };
            if NaiveDate::parse_from_str(text, "%Y-%m-%d").is_err() {
                problems.push(format!("{key} must be a date in YYYY-MM-DD form"));
                return None;
            }
            Some(value.clone())
        }
        FieldType::Select => {
            let Some(text) = value.as_str() else {
                problems.push(format!("{key} must be one of the listed options"));
                return None;
            };
            let options = field.options.as_deref().unwrap_or(&[]);
            if !options.iter().any(|option| option == text) {
                problems.push(format!("{key} must be one of the listed options"));
            }
            Some(value.clone())
        }
        FieldType::Checkbox => {
            if !value.is_boolean() {
                problems.push(format!("{key} must be true or false"));
                return None;
            }
            Some(value.clone())
        }
        FieldType::File => {
            let Some(text) = value.as_str() else {
                problems.push(format!("{key} must be an uploaded file reference"));
                return None;
            };
            if text.trim().is_empty() {
                problems.push(format!("{key} must not be empty"));
                return None;
            }
            Some(value.clone())
        }
    }
}

fn is_absent(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.trim().is_empty(),
        Some(_) => false,
    }
}

fn is_valid_key(key: &str) -> bool {
    if key.is_empty() || key.len() > MAX_KEY_LENGTH {
        return false;
    }

    let mut characters = key.chars();
    matches!(characters.next(), Some(first) if first.is_ascii_lowercase())
        && characters.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema(fields: Vec<FieldDefinition>) -> FormSchema {
        FormSchema {
            title: "Contact".into(),
            description: None,
            submit_label: None,
            fields,
        }
    }

    fn field(key: &str, field_type: FieldType) -> FieldDefinition {
        FieldDefinition {
            key: key.into(),
            field_type,
            label: key.into(),
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

    #[test]
    fn keys_must_look_like_keys() {
        assert!(is_valid_key("email"));
        assert!(is_valid_key("first_name_2"));
        assert!(!is_valid_key("Email"), "uppercase is rejected");
        assert!(!is_valid_key("2nd"), "a leading digit is rejected");
        assert!(!is_valid_key("first-name"), "hyphens are rejected");
        assert!(!is_valid_key(""), "an empty key is rejected");
        assert!(!is_valid_key(&"a".repeat(MAX_KEY_LENGTH + 1)));
    }

    #[test]
    fn a_definition_reports_every_problem_at_once() {
        let broken = schema(vec![
            field("Email", FieldType::Email),
            field("email", FieldType::Email),
            field("email", FieldType::Email),
            field("colour", FieldType::Select),
            field("_hidden", FieldType::Text),
        ]);

        let problems = validate_schema(&broken).unwrap_err();
        assert!(problems.iter().any(|p| p.contains("lowercase letter")));
        assert!(problems.iter().any(|p| p.contains("more than once")));
        assert!(problems.iter().any(|p| p.contains("needs options")));
        assert!(problems.iter().any(|p| p.contains("reserved")));
    }

    #[test]
    fn a_select_needs_options_and_an_empty_form_is_refused() {
        assert!(validate_schema(&schema(vec![])).is_err());

        let mut select = field("topic", FieldType::Select);
        select.options = Some(vec!["Sales".into()]);
        assert!(validate_schema(&schema(vec![select])).is_ok());
    }

    #[test]
    fn a_payload_is_checked_against_the_definition() {
        let mut email = field("email", FieldType::Email);
        email.required = true;
        let definition = schema(vec![email, field("age", FieldType::Number)]);

        let good = json!({ "email": "a@b.co", "age": 30 });
        assert!(validate_submission(&definition, good.as_object().unwrap()).is_ok());

        let bad = json!({ "email": "not-an-address", "age": "thirty", "extra": 1 });
        let problems = validate_submission(&definition, bad.as_object().unwrap()).unwrap_err();
        assert!(problems.iter().any(|p| p.contains("valid email")));
        assert!(problems.iter().any(|p| p.contains("must be a number")));
        assert!(problems.iter().any(|p| p.contains("not a field")));
    }

    #[test]
    fn reserved_keys_are_dropped_rather_than_stored() {
        let definition = schema(vec![field("email", FieldType::Email)]);
        let payload = json!({ "email": "a@b.co", "_gotcha": "spam", "_source": "landing" });

        let answers = validate_submission(&definition, payload.as_object().unwrap()).unwrap();

        assert_eq!(answers.len(), 1);
        assert!(answers.contains_key("email"));
    }

    #[test]
    fn a_missing_required_answer_is_reported() {
        let mut email = field("email", FieldType::Email);
        email.required = true;
        let definition = schema(vec![email]);

        for absent in [json!({}), json!({ "email": "" }), json!({ "email": "   " })] {
            let problems =
                validate_submission(&definition, absent.as_object().unwrap()).unwrap_err();
            assert!(
                problems.iter().any(|p| p.contains("required")),
                "{problems:?}"
            );
        }
    }

    #[test]
    fn select_answers_must_be_offered_options() {
        let mut topic = field("topic", FieldType::Select);
        topic.options = Some(vec!["Sales".into(), "Support".into()]);
        let definition = schema(vec![topic]);

        assert!(
            validate_submission(
                &definition,
                json!({ "topic": "Sales" }).as_object().unwrap()
            )
            .is_ok()
        );
        assert!(
            validate_submission(
                &definition,
                json!({ "topic": "Other" }).as_object().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn ranges_and_lengths_are_enforced() {
        let mut message = field("message", FieldType::Text);
        message.max_length = Some(5);
        let mut age = field("age", FieldType::Number);
        age.min = Some(18.0);
        let definition = schema(vec![message, age]);

        let problems = validate_submission(
            &definition,
            json!({ "message": "far too long", "age": 12 })
                .as_object()
                .unwrap(),
        )
        .unwrap_err();

        assert!(problems.iter().any(|p| p.contains("at most 5 characters")));
        assert!(problems.iter().any(|p| p.contains("at least 18")));
    }

    #[test]
    fn dates_must_parse() {
        let definition = schema(vec![field("when", FieldType::Date)]);

        assert!(
            validate_submission(
                &definition,
                json!({ "when": "2026-01-31" }).as_object().unwrap()
            )
            .is_ok()
        );
        assert!(
            validate_submission(
                &definition,
                json!({ "when": "31/01/2026" }).as_object().unwrap()
            )
            .is_err()
        );
    }
}
