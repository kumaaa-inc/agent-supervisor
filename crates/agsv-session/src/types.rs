use std::path::PathBuf;

/// A backend-owned handle. The control plane treats its fields as opaque.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionHandle {
    pub backend: String,
    pub external_id: String,
    pub resume_token: Option<String>,
}

/// Provider-neutral launch parameters for one top-level orchestrator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchRequest {
    pub actor_id: String,
    pub session_name: String,
    pub runtime: String,
    pub working_directory: PathBuf,
    pub idempotency_key: String,
    pub native_args: Vec<String>,
}

/// Parameters needed to resume a previously launched top-level orchestrator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeRequest {
    pub actor_id: String,
    pub handle: SessionHandle,
    pub working_directory: PathBuf,
    pub idempotency_key: String,
    pub native_args: Vec<String>,
}

/// Portable lifecycle states exposed to the runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    Starting,
    Working,
    Idle,
    Blocked,
    Stopped { exit_code: Option<i32> },
    Missing,
    Unknown(String),
}

impl SessionStatus {
    #[must_use]
    pub const fn is_present(&self) -> bool {
        matches!(
            self,
            Self::Starting | Self::Working | Self::Idle | Self::Blocked | Self::Unknown(_)
        )
    }
}

/// A point-in-time backend observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSnapshot {
    pub handle: SessionHandle,
    pub status: SessionStatus,
    pub detail: Option<String>,
}

/// Failures crossing the session adapter boundary.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session backend is unavailable: {0}")]
    Unavailable(String),
    #[error("session {0} was not found")]
    NotFound(String),
    #[error("operation is not supported by backend {backend}: {operation}")]
    Unsupported {
        backend: String,
        operation: &'static str,
    },
    #[error("invalid command template: {0}")]
    InvalidTemplate(String),
    #[error("invalid backend output: {0}")]
    InvalidOutput(String),
    #[error("command failed with status {status:?}: {stderr}")]
    CommandFailed { status: Option<i32>, stderr: String },
    #[error("session backend state is poisoned")]
    Poisoned,
}

/// Lifecycle boundary implemented by fake, process, Herdr, and future backends.
pub trait SessionBackend: Send + Sync {
    fn name(&self) -> &str;
    fn launch(&self, request: &LaunchRequest) -> Result<SessionHandle, SessionError>;
    fn resume(&self, request: &ResumeRequest) -> Result<SessionHandle, SessionError>;
    fn status(&self, handle: &SessionHandle) -> Result<SessionSnapshot, SessionError>;
    fn send_message(&self, handle: &SessionHandle, message: &str) -> Result<(), SessionError>;
    fn stop(&self, handle: &SessionHandle) -> Result<(), SessionError>;
}
