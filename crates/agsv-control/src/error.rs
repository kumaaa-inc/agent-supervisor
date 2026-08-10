use std::path::Path;

use agsv_core::CoreError;
use serde_json::{Value, json};

/// Stable error returned through the CLI envelope.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ControlError {
    pub code: &'static str,
    pub message: String,
    pub hint: Option<String>,
    pub details: Value,
}

impl ControlError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
            details: json!({}),
        }
    }

    pub(crate) fn with_details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }

    pub(crate) fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub(crate) fn io(action: &str, path: &Path, error: &impl std::fmt::Display) -> Self {
        Self::new(
            "io_error",
            format!("could not {action} {}: {error}", path.display()),
        )
        .with_details(json!({ "action": action, "path": path }))
    }

    pub(crate) fn invalid_request(message: impl Into<String>) -> Self {
        Self::new("invalid_request", message)
    }

    pub(crate) fn not_found(kind: &str, id: &str) -> Self {
        Self::new("not_found", format!("{kind} `{id}` was not found"))
            .with_details(json!({ "entity_kind": kind, "entity_id": id }))
    }

    pub(crate) fn unsupported(operation: &str, reason: &str) -> Self {
        Self::new(
            "unsupported_operation",
            format!("`{operation}` is not supported by the embedded v0.1 control plane: {reason}"),
        )
        .with_details(json!({ "operation": operation, "reason": reason }))
    }

    pub(crate) fn core(error: CoreError) -> Self {
        let CoreError::Validation(validation) = error else {
            return Self::new(
                "domain_error",
                format!("domain operation was rejected: {error}"),
            );
        };
        let field = validation.field;
        let mut details = json!({
            "field": &field,
            "validation_code": validation.code,
        });
        if let (Some(actual), Some(maximum), Some(overflow), Some(unit)) = (
            validation.actual,
            validation.maximum,
            validation.overflow,
            validation.unit,
        ) {
            details["unit"] = json!(unit);
            details["actual"] = json!(actual);
            details["maximum"] = json!(maximum);
            details["overflow"] = json!(overflow);
        }
        Self::new(
            "validation_error",
            format!(
                "protocol field `{}` was rejected: {}",
                field, validation.message
            ),
        )
        .with_details(details)
    }

    pub(crate) fn database(error: impl std::fmt::Display) -> Self {
        Self::new(
            "state_store_error",
            format!("durable state operation failed: {error}"),
        )
    }

    pub(crate) fn protocol(error: impl std::fmt::Display) -> Self {
        Self::new(
            "protocol_error",
            format!("protocol value was rejected: {error}"),
        )
    }
}

#[cfg(test)]
mod tests {
    use agsv_protocol::{ValidationCode, ValidationError, ValidationUnit};

    use super::{ControlError, CoreError};

    #[test]
    fn core_validation_preserves_typed_limit_details() {
        for (unit, expected_unit) in [
            (ValidationUnit::Characters, "characters"),
            (ValidationUnit::Items, "items"),
        ] {
            let error = ControlError::core(CoreError::Validation(
                ValidationError::new(
                    "message.acceptance_criteria[0]",
                    ValidationCode::OutOfRange,
                    "contains 65537 characters; maximum is 65536; exceeds by 1 character",
                )
                .with_limit(65_537, 65_536, unit),
            ));

            assert_eq!(error.code, "validation_error");
            assert!(error.message.contains("message.acceptance_criteria[0]"));
            assert!(error.message.contains("exceeds by 1 character"));
            assert_eq!(
                error.details,
                serde_json::json!({
                    "field": "message.acceptance_criteria[0]",
                    "validation_code": "out_of_range",
                    "unit": expected_unit,
                    "actual": 65_537,
                    "maximum": 65_536,
                    "overflow": 1,
                })
            );
        }
    }
}
