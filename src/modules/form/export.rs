//! CSV and JSON encoding for the export.
//!
//! Kept apart from the handlers because the escaping rules are exactly the kind of thing that
//! deserves its own tests rather than being trusted by eye.

use axum::body::Bytes;

use crate::modules::form::model::SubmissionRecord;

/// One line of CSV, terminated so rows can be concatenated without a separator.
pub fn csv_row(columns: &[String], submission: &SubmissionRecord) -> String {
    let fields = columns.iter().map(|column| {
        let value = submission
            .data
            .0
            .get(column)
            .map(render)
            .unwrap_or_default();
        escape(&value)
    });

    let mut line = format!(
        "{},{},{}",
        escape(&submission.id.to_string()),
        escape(&submission.created_at.to_rfc3339()),
        escape(&status(&submission.status))
    );
    for field in fields {
        line.push(',');
        line.push_str(&field);
    }
    line.push('\n');

    line
}

pub fn csv_header(columns: &[String]) -> String {
    let mut header = String::from("id,created_at,status");
    for column in columns {
        header.push(',');
        header.push_str(&escape(column));
    }
    header.push('\n');

    header
}

/// One JSON object per line, which streams as easily as CSV and is still a valid array once
/// wrapped in brackets.
pub fn json_row(submission: &SubmissionRecord, separator: &str) -> String {
    let object = serde_json::json!({
        "id": submission.id,
        "created_at": submission.created_at,
        "status": status(&submission.status),
        "data": submission.data.0,
    });

    // `to_string` cannot fail for a value built entirely from owned primitives and a JSON
    // document that came out of the database.
    format!("{separator}{}", object)
}

pub fn bytes(text: String) -> Bytes {
    Bytes::from(text)
}

fn status(status: &crate::modules::form::model::SubmissionStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Renders one answer as a cell. Structured answers keep their JSON form rather than being
/// flattened, so nothing is silently lost.
fn render(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Bool(flag) => flag.to_string(),
        serde_json::Value::Number(number) => number.to_string(),
        other => other.to_string(),
    }
}

/// RFC 4180 quoting: a cell containing a comma, a quote, or a line break is wrapped in quotes,
/// and its quotes are doubled.
fn escape(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::form::model::SubmissionStatus;
    use chrono::TimeZone as _;
    use sqlx::types::Json;
    use uuid::Uuid;

    fn submission(data: serde_json::Value) -> SubmissionRecord {
        SubmissionRecord {
            id: Uuid::nil(),
            organization_id: Uuid::nil(),
            form_id: Uuid::nil(),
            schema_version: 1,
            data: Json(data),
            files: Json(serde_json::json!({})),
            status: SubmissionStatus::Unread,
            created_at: chrono::Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap(),
        }
    }

    #[test]
    fn cells_are_quoted_only_when_they_need_to_be() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("with,comma"), "\"with,comma\"");
        assert_eq!(escape("with\"quote"), "\"with\"\"quote\"");
        assert_eq!(escape("two\nlines"), "\"two\nlines\"");
    }

    #[test]
    fn a_row_follows_the_column_order() {
        let columns = vec!["email".to_owned(), "note".to_owned()];
        let row = csv_row(
            &columns,
            &submission(serde_json::json!({ "note": "hi, there", "email": "a@b.co" })),
        );

        assert!(row.ends_with("a@b.co,\"hi, there\"\n"), "{row}");
        assert!(row.starts_with(&Uuid::nil().to_string()));
        assert!(row.contains("unread"));
    }

    #[test]
    fn a_missing_answer_becomes_an_empty_cell() {
        let columns = vec!["email".to_owned(), "absent".to_owned()];
        let row = csv_row(
            &columns,
            &submission(serde_json::json!({ "email": "a@b.co" })),
        );

        assert!(row.contains("a@b.co,\n"), "{row}");
    }

    #[test]
    fn structured_answers_keep_their_shape() {
        let columns = vec!["tags".to_owned()];
        let row = csv_row(
            &columns,
            &submission(serde_json::json!({ "tags": ["a", "b"] })),
        );

        assert!(row.contains("\"[\"\"a\"\",\"\"b\"\"]\""), "{row}");
    }

    #[test]
    fn json_rows_are_one_object_each() {
        let first = json_row(&submission(serde_json::json!({ "email": "a@b.co" })), "");
        let second = json_row(&submission(serde_json::json!({ "email": "c@d.co" })), ",");

        assert!(first.starts_with('{'));
        assert!(second.starts_with(','));
        assert!(first.contains("\"email\":\"a@b.co\""));
        assert!(first.contains("\"status\":\"unread\""));
    }
}
