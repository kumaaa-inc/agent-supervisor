//! Strongly typed stable identifiers and fencing counters.

use crate::validation::{ValidationCode, ValidationError, validate_token};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

macro_rules! string_id {
    ($name:ident, $field:literal) => {
        #[doc = concat!("A validated ", $field, ".")]
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String")]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a validated ", $field, ".")]
            ///
            /// # Errors
            ///
            /// Returns an error when the identifier is empty, too long, or contains
            /// characters outside the portable protocol alphabet.
            pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
                let value = value.into();
                validate_token($field, &value)?;
                Ok(Self(value))
            }

            /// Returns the wire representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ValidationError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = ValidationError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl JsonSchema for $name {
            fn inline_schema() -> bool {
                true
            }

            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }

            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                    "pattern": "^[A-Za-z0-9_.:/@-]+$"
                })
            }
        }
    };
}

string_id!(WorkspaceId, "workspace_id");
string_id!(TeamId, "team_id");
string_id!(ActorId, "actor_id");
string_id!(RunId, "run_id");
string_id!(RequestId, "request_id");
string_id!(MessageId, "message_id");
string_id!(DecisionId, "decision_id");
string_id!(EvidenceId, "evidence_id");
string_id!(HandoffId, "handoff_id");
string_id!(ActorProfileName, "actor_profile");
string_id!(TeamProfileName, "team_profile");
string_id!(CapabilityId, "capability");
string_id!(AssignmentPolicyId, "assignment_policy");
string_id!(ReviewSessionId, "review_session_id");
string_id!(ReviewAttemptRecordId, "review_attempt_record_id");
string_id!(ReviewCheckId, "review_check_id");
string_id!(ReviewEnvironmentId, "review_environment_id");
string_id!(ReviewToolId, "review_tool_id");
string_id!(ReviewBinaryId, "review_binary_id");
string_id!(ReviewEnvironmentKey, "review_environment_key");

macro_rules! epoch {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(
            Clone,
            Copy,
            Debug,
            Deserialize,
            Eq,
            Hash,
            Ord,
            PartialEq,
            PartialOrd,
            Serialize,
        )]
        #[serde(try_from = "u64")]
        pub struct $name(u64);

        impl $name {
            /// The initial valid epoch.
            pub const INITIAL: Self = Self(1);

            /// Creates a non-zero epoch.
            ///
            /// # Errors
            ///
            /// Returns an error for zero, which is reserved as an unset value.
            pub fn new(value: u64) -> Result<Self, ValidationError> {
                if value == 0 {
                    return Err(ValidationError::new(
                        stringify!($name),
                        ValidationCode::OutOfRange,
                        "must be greater than zero",
                    ));
                }
                Ok(Self(value))
            }

            /// Returns the numeric wire representation.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }

            /// Returns the next fencing value, if it can be represented.
            #[must_use]
            pub fn checked_next(self) -> Option<Self> {
                self.0.checked_add(1).map(Self)
            }
        }

        impl TryFrom<u64> for $name {
            type Error = ValidationError;

            fn try_from(value: u64) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for u64 {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                Display::fmt(&self.0, formatter)
            }
        }

        impl JsonSchema for $name {
            fn inline_schema() -> bool {
                true
            }

            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }

            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "integer",
                    "minimum": 1
                })
            }
        }
    };
}

epoch!(PrimaryEpoch, "Fences prior Primary leases.");
epoch!(TeamEpoch, "Fences prior team ownership generations.");
epoch!(
    ActorEpoch,
    "Fences prior processes registered with an actor id."
);
epoch!(AssignmentEpoch, "Fences prior request assignees.");
epoch!(PolicyRevision, "Fences work issued under an older policy.");

/// Milliseconds since the Unix epoch, supplied by the runtime boundary.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct TimestampMillis(pub u64);

/// An immutable full object id for a Git commit.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct GitSha(String);

impl GitSha {
    /// Creates a full SHA-1 (40 hex digits) or SHA-256 (64 hex digits) object id.
    ///
    /// # Errors
    ///
    /// Returns an error for abbreviated or non-hex object ids.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ValidationError::new(
                "git_sha",
                ValidationCode::InvalidFormat,
                "must be a full 40- or 64-digit hexadecimal object id",
            ));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Returns the normalized lowercase object id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for GitSha {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for GitSha {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for GitSha {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<GitSha> for String {
    fn from(value: GitSha) -> Self {
        value.0
    }
}

impl JsonSchema for GitSha {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "GitSha".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{GitSha, MessageId, PrimaryEpoch};

    #[test]
    fn ids_reject_non_portable_values_during_deserialization() {
        let result = serde_json::from_str::<MessageId>(r#""contains spaces""#);
        assert!(result.is_err());
    }

    #[test]
    fn epochs_reject_zero_during_deserialization() {
        let result = serde_json::from_str::<PrimaryEpoch>("0");
        assert!(result.is_err());
    }

    #[test]
    fn git_sha_is_full_and_normalized() {
        let uppercase = "ABCDEF0123456789ABCDEF0123456789ABCDEF01";
        let sha = GitSha::new(uppercase).expect("full SHA is valid");
        assert_eq!(sha.as_str(), uppercase.to_ascii_lowercase());
        assert!(GitSha::new("deadbeef").is_err());
    }
}
