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
    /// Full initial task text delivered only after the backend reports the
    /// newly started session ready. Delivery is intentionally at-least-once
    /// across incomplete-launch recovery.
    pub initial_prompt: Option<String>,
    /// Backend checkpoint recovered after a daemon crash, such as a Herdr pane ID.
    pub resume_token: Option<String>,
}

/// Durable progress emitted before a backend performs the next launch side effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchCheckpoint {
    pub resume_token: String,
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
    #[error("session backend timed out: {0}")]
    Timeout(String),
    #[error("session {0} was not found")]
    NotFound(String),
    #[error("backend {backend} rejected a foreign handle owned by {actual}")]
    ForeignHandle { backend: String, actual: String },
    #[error("session backend permission denied: {0}")]
    PermissionDenied(String),
    #[error("invalid session backend configuration: {0}")]
    InvalidConfiguration(String),
    #[error("failed to persist session launch checkpoint: {0}")]
    Checkpoint(String),
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
    fn launch_with_checkpoint(
        &self,
        request: &LaunchRequest,
        checkpoint: &mut dyn FnMut(&LaunchCheckpoint) -> Result<(), SessionError>,
    ) -> Result<SessionHandle, SessionError> {
        let _ = checkpoint;
        self.launch(request)
    }
    fn resume(&self, request: &ResumeRequest) -> Result<SessionHandle, SessionError>;
    fn status(&self, handle: &SessionHandle) -> Result<SessionSnapshot, SessionError>;
    fn send_message(&self, handle: &SessionHandle, message: &str) -> Result<(), SessionError>;
    fn stop(&self, handle: &SessionHandle) -> Result<(), SessionError>;
}

pub(crate) fn reject_foreign_handle(
    expected_backend: &str,
    handle: &SessionHandle,
) -> Result<(), SessionError> {
    if handle.backend == expected_backend {
        Ok(())
    } else {
        Err(SessionError::ForeignHandle {
            backend: expected_backend.to_owned(),
            actual: handle.backend.clone(),
        })
    }
}
