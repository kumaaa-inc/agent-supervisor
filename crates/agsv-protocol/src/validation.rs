//! Shared validation primitives for protocol values.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// A stable, machine-readable validation failure.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ValidationError {
    /// The field or logical component that failed validation.
    pub field: String,
    /// A stable error code suitable for programmatic consumers.
    pub code: ValidationCode,
    /// A human-readable explanation.
    pub message: String,
}

impl ValidationError {
    /// Creates a validation error.
    #[must_use]
    pub fn new(field: impl Into<String>, code: ValidationCode, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            code,
            message: message.into(),
        }
    }

    /// Prepends a parent component to the failing field.
    #[must_use]
    pub fn at(mut self, parent: &str) -> Self {
        self.field = if self.field.is_empty() {
            parent.to_owned()
        } else {
            format!("{parent}.{}", self.field)
        };
        self
    }
}

impl Display for ValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {} ({:?})",
            self.field, self.message, self.code
        )
    }
}

impl Error for ValidationError {}

/// Stable categories for invalid protocol data.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCode {
    /// A required value was empty or absent.
    Required,
    /// The value used characters or a representation outside the protocol.
    InvalidFormat,
    /// The value exceeded a protocol bound.
    OutOfRange,
    /// Two fields contradict one another.
    Inconsistent,
    /// The wire version is not supported by this implementation.
    UnsupportedVersion,
}

/// Validation implemented by wire and persisted domain values.
pub trait Validate {
    /// Checks semantic invariants not expressible in the Rust type system.
    ///
    /// # Errors
    ///
    /// Returns the first stable validation failure.
    fn validate(&self) -> Result<(), ValidationError>;
}

pub(crate) fn validate_token(field: &str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new(
            field,
            ValidationCode::Required,
            "must not be empty",
        ));
    }
    if value.len() > 128 {
        return Err(ValidationError::new(
            field,
            ValidationCode::OutOfRange,
            "must contain at most 128 bytes",
        ));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
    }) {
        return Err(ValidationError::new(
            field,
            ValidationCode::InvalidFormat,
            "must use ASCII letters, digits, or - _ . : / @",
        ));
    }
    Ok(())
}

pub(crate) fn validate_text(
    field: &str,
    value: &str,
    maximum: usize,
) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::new(
            field,
            ValidationCode::Required,
            "must not be blank",
        ));
    }
    if value.len() > maximum {
        return Err(ValidationError::new(
            field,
            ValidationCode::OutOfRange,
            format!("must contain at most {maximum} bytes"),
        ));
    }
    Ok(())
}
