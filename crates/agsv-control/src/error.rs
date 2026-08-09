use std::path::Path;

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

    pub(crate) fn core(error: impl std::fmt::Display) -> Self {
        Self::new(
            "domain_error",
            format!("domain operation was rejected: {error}"),
        )
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
