//! Shared validation primitives for protocol values.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Maximum evidence items attached to one message.
pub const MAX_EVIDENCE_ITEMS: usize = 64;
/// Maximum acceptance criteria on one implementation request.
pub const MAX_ACCEPTANCE_CRITERIA: usize = 64;
/// Maximum Unicode scalar values in request instructions or one acceptance criterion.
///
/// The CLI may duplicate the request body into both fields. At the JSON worst case of
/// six bytes per scalar, two maximum-sized values occupy 786,432 bytes and leave room
/// for the rest of the envelope below [`MAX_FRAME_BYTES`]. The serialized frame-byte
/// limit remains authoritative.
pub const MAX_REQUEST_TEXT_CHARACTERS: usize = 65_536;
/// Maximum evidence categories requested by one implementation request.
pub const MAX_EVIDENCE_REQUIREMENTS: usize = 16;
/// Maximum authorization capabilities snapshotted for one actor profile.
pub const MAX_ACTOR_CAPABILITIES: usize = 256;
/// Maximum resources named by one conflict notice.
pub const MAX_CONFLICT_RESOURCES: usize = 256;
/// Maximum actors, teams, requests, runs, or pending handoffs in one snapshot.
pub const MAX_DOMAIN_ENTITIES: usize = 10_000;
/// Maximum durable deliveries in one workspace snapshot.
pub const MAX_DELIVERIES: usize = 100_000;
/// Maximum acknowledgements retained for one delivery.
pub const MAX_ACKNOWLEDGEMENTS: usize = 10_000;
/// Maximum append-only audit events in one workspace snapshot.
pub const MAX_AUDIT_EVENTS: usize = 200_000;
/// Maximum serialized envelope size accepted after decoding.
pub const MAX_FRAME_BYTES: usize = 1_048_576;
/// Maximum serialized snapshot size accepted after decoding.
pub const MAX_SNAPSHOT_BYTES: usize = 67_108_864;

/// A stable, machine-readable validation failure.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ValidationError {
    /// The field or logical component that failed validation.
    pub field: String,
    /// A stable error code suitable for programmatic consumers.
    pub code: ValidationCode,
    /// A human-readable explanation.
    pub message: String,
    /// Observed collection or character count for bounded-value errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<usize>,
    /// Maximum permitted collection or character count for bounded-value errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<usize>,
    /// Amount by which the observed count exceeded the maximum.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overflow: Option<usize>,
    /// Unit used by the typed limit details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<ValidationUnit>,
}

impl ValidationError {
    /// Creates a validation error.
    #[must_use]
    pub fn new(field: impl Into<String>, code: ValidationCode, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            code,
            message: message.into(),
            actual: None,
            maximum: None,
            overflow: None,
            unit: None,
        }
    }

    /// Attaches typed limit details to an out-of-range failure.
    #[must_use]
    pub const fn with_limit(mut self, actual: usize, maximum: usize, unit: ValidationUnit) -> Self {
        self.actual = Some(actual);
        self.maximum = Some(maximum);
        self.overflow = Some(actual.saturating_sub(maximum));
        self.unit = Some(unit);
        self
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

/// Unit attached to typed validation limit details.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationUnit {
    /// Unicode scalar values counted with `str::chars`.
    Characters,
    /// Items in a bounded collection.
    Items,
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
    let actual = value.chars().count();
    if actual > maximum {
        let overflow = actual - maximum;
        let overflow_unit = if overflow == 1 {
            "character"
        } else {
            "characters"
        };
        return Err(ValidationError::new(
            field,
            ValidationCode::OutOfRange,
            format!(
                "contains {actual} characters; maximum is {maximum}; exceeds by {overflow} {overflow_unit}"
            ),
        )
        .with_limit(actual, maximum, ValidationUnit::Characters));
    }
    Ok(())
}

pub(crate) fn validate_count(
    field: &str,
    count: usize,
    maximum: usize,
) -> Result<(), ValidationError> {
    if count > maximum {
        let overflow = count - maximum;
        let overflow_unit = if overflow == 1 { "item" } else { "items" };
        return Err(ValidationError::new(
            field,
            ValidationCode::OutOfRange,
            format!(
                "contains {count} items; maximum is {maximum}; exceeds by {overflow} {overflow_unit}"
            ),
        )
        .with_limit(count, maximum, ValidationUnit::Items));
    }
    Ok(())
}
