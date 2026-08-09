use std::path::PathBuf;

use agsv_session::{SessionError, SessionHandle};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorRole {
    Primary,
    Implementation,
}

impl ActorRole {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Implementation => "implementation",
        }
    }

    pub(crate) fn from_str(value: &str) -> Result<Self, RuntimeError> {
        match value {
            "primary" => Ok(Self::Primary),
            "implementation" => Ok(Self::Implementation),
            other => Err(RuntimeError::Corrupt(format!(
                "unknown actor role {other:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorState {
    Starting,
    Online,
    Offline,
    Stopped,
}

impl ActorState {
    pub(crate) fn from_str(value: &str) -> Result<Self, RuntimeError> {
        match value {
            "starting" => Ok(Self::Starting),
            "online" => Ok(Self::Online),
            "offline" => Ok(Self::Offline),
            "stopped" => Ok(Self::Stopped),
            other => Err(RuntimeError::Corrupt(format!(
                "unknown actor state {other:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorRecord {
    pub workspace_id: String,
    pub actor_id: String,
    pub team_id: Option<String>,
    pub role: ActorRole,
    pub state: ActorState,
    pub actor_epoch: i64,
    pub backend: String,
    pub session: Option<SessionHandle>,
    pub heartbeat_at_ms: i64,
    pub lease_until_ms: i64,
}

/// Launch description kept outside provider-specific command syntax.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorSpec {
    pub actor_id: String,
    pub team_id: Option<String>,
    pub role: ActorRole,
    pub backend: String,
    pub session_name: String,
    pub runtime: String,
    pub working_directory: PathBuf,
    pub launch_idempotency_key: String,
    pub native_args: Vec<String>,
}

/// Authenticated actor and optional Primary fencing context for message insertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SenderContext {
    pub actor_id: String,
    pub actor_epoch: i64,
    pub primary_fencing_epoch: Option<i64>,
}

impl SenderContext {
    #[must_use]
    pub fn actor(actor_id: impl Into<String>, actor_epoch: i64) -> Self {
        Self {
            actor_id: actor_id.into(),
            actor_epoch,
            primary_fencing_epoch: None,
        }
    }

    #[must_use]
    pub const fn with_primary_fence(mut self, fencing_epoch: i64) -> Self {
        self.primary_fencing_epoch = Some(fencing_epoch);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonLease {
    pub workspace_id: String,
    pub instance_id: String,
    pub fencing_epoch: i64,
    pub lease_until_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrimaryLease {
    pub workspace_id: String,
    pub actor_id: String,
    pub actor_epoch: i64,
    pub fencing_epoch: i64,
    pub lease_until_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchIntentState {
    Prepared,
    Checkpointed,
    Launched,
    Attached,
}

impl LaunchIntentState {
    pub(crate) fn from_str(value: &str) -> Result<Self, RuntimeError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "checkpointed" => Ok(Self::Checkpointed),
            "launched" => Ok(Self::Launched),
            "attached" => Ok(Self::Attached),
            other => Err(RuntimeError::Corrupt(format!(
                "unknown launch intent state {other:?}"
            ))),
        }
    }
}

/// Crash-recovery record written before a session launch side effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchIntent {
    pub workspace_id: String,
    pub actor_id: String,
    pub idempotency_key: String,
    pub spec_fingerprint: String,
    pub canonical_working_directory: PathBuf,
    pub backend: String,
    pub session_name: String,
    pub state: LaunchIntentState,
    pub resume_token: Option<String>,
    pub session_external_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewMessage {
    pub workspace_id: String,
    pub message_id: String,
    pub idempotency_key: String,
    pub sender_actor_id: String,
    pub recipient_actor_id: Option<String>,
    pub recipient_team_id: Option<String>,
    pub kind: String,
    pub payload: Vec<u8>,
    pub available_at_ms: i64,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageRecord {
    pub workspace_id: String,
    pub message_id: String,
    pub idempotency_key: String,
    pub sender_actor_id: String,
    pub sender_actor_epoch: i64,
    pub primary_fencing_epoch: Option<i64>,
    pub recipient_actor_id: Option<String>,
    pub recipient_team_id: Option<String>,
    pub kind: String,
    pub payload: Vec<u8>,
    pub available_at_ms: i64,
    pub claimed_by_actor_id: Option<String>,
    pub claimant_actor_epoch: Option<i64>,
    pub delivery_epoch: i64,
    pub attempts: i64,
    pub claim_until_ms: Option<i64>,
    pub acknowledged_at_ms: Option<i64>,
    pub last_error: Option<String>,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedMessage {
    pub message: MessageRecord,
    pub delivery_epoch: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub sequence: i64,
    pub workspace_id: String,
    pub entity_kind: String,
    pub entity_id: String,
    pub event_type: String,
    pub detail: String,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconcileReport {
    pub actors_checked: usize,
    pub actors_marked_online: usize,
    pub actors_marked_offline: usize,
    pub expired_deliveries_released: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error("{entity_kind} {entity_id} was not found")]
    NotFound {
        entity_kind: &'static str,
        entity_id: String,
    },
    #[error("lease is held by {owner} until {lease_until_ms}")]
    LeaseHeld { owner: String, lease_until_ms: i64 },
    #[error("stale fencing epoch for {entity}")]
    StaleEpoch { entity: String },
    #[error("idempotency key {0} was reused for different content")]
    IdempotencyConflict(String),
    #[error("actor is not authorized for this operation: {0}")]
    Unauthorized(String),
    #[error("session backend {0} is not registered")]
    BackendNotRegistered(String),
    #[error("path is outside the authorized workspace: {0}")]
    WorkspaceScope(String),
    #[error("unsupported or inconsistent schema version: {0}")]
    SchemaVersion(String),
    #[error("invalid runtime state: {0}")]
    InvalidState(String),
    #[error("corrupt runtime state: {0}")]
    Corrupt(String),
    #[error("runtime service state is poisoned")]
    Poisoned,
}
