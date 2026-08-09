use std::process::Command;
use std::sync::Arc;

use crate::ControlError;
use crate::engine::BackendKind;
use crate::identity::sha256_hex;
use crate::store::SessionRecord;
use agsv_session::{
    HerdrAdapter, LaunchRequest, SessionBackend, SessionHandle, SessionStatus, SystemCommandRunner,
};

pub(crate) struct SessionDriver {
    kind: BackendKind,
}

impl SessionDriver {
    pub(crate) const fn new(kind: BackendKind) -> Self {
        Self { kind }
    }

    pub(crate) const fn name(&self) -> &'static str {
        match self.kind {
            BackendKind::Herdr => "herdr",
            BackendKind::Fake => "fake",
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn launch(
        &self,
        actor_id: &str,
        session_name: &str,
        working_directory: &std::path::Path,
        launch_key: &str,
        native_args: Vec<String>,
        resume_token: Option<String>,
        checkpoint: &mut dyn FnMut(&str) -> Result<(), ControlError>,
    ) -> Result<SessionHandle, ControlError> {
        match self.kind {
            BackendKind::Fake => {
                let digest = sha256_hex(launch_key);
                Ok(SessionHandle {
                    backend: "fake".to_owned(),
                    external_id: format!("fake-{}", &digest[..16]),
                    resume_token: Some(format!("fake-pane-{}", &digest[..16])),
                })
            }
            BackendKind::Herdr => Self::herdr()
                .launch_with_checkpoint(
                    &LaunchRequest {
                        actor_id: actor_id.to_owned(),
                        session_name: session_name.to_owned(),
                        runtime: "codex".to_owned(),
                        working_directory: working_directory.to_path_buf(),
                        idempotency_key: launch_key.to_owned(),
                        native_args,
                        resume_token,
                    },
                    &mut |value| {
                        checkpoint(&value.resume_token).map_err(|error| {
                            agsv_session::SessionError::Checkpoint(error.to_string())
                        })
                    },
                )
                .map_err(session_error),
        }
    }

    pub(crate) fn status(&self, record: &SessionRecord) -> Result<String, ControlError> {
        if self.kind == BackendKind::Fake {
            return Ok(record.status.clone());
        }
        let handle = handle(record)?;
        let snapshot = Self::herdr().status(&handle).map_err(session_error)?;
        Ok(status_name(&snapshot.status).to_owned())
    }

    pub(crate) fn notify(&self, record: &SessionRecord, message: &str) -> Result<(), ControlError> {
        if self.kind == BackendKind::Fake {
            return Ok(());
        }
        Self::herdr()
            .send_message(&handle(record)?, message)
            .map_err(session_error)
    }

    pub(crate) fn stop(&self, record: &SessionRecord) -> Result<(), ControlError> {
        if self.kind == BackendKind::Fake {
            return Ok(());
        }
        Self::herdr().stop(&handle(record)?).map_err(session_error)
    }

    pub(crate) fn diagnostics(&self) -> serde_json::Value {
        let backend = match self.kind {
            BackendKind::Herdr => command_version("herdr"),
            BackendKind::Fake => serde_json::json!({
                "available": true,
                "version": "built-in deterministic fake",
            }),
        };
        let codex = command_version("codex");
        serde_json::json!({
            "backend": self.name(),
            "backend_command": backend,
            "codex": codex,
        })
    }

    fn herdr() -> HerdrAdapter {
        HerdrAdapter::verified_v0_8(Arc::new(SystemCommandRunner))
    }
}

fn handle(record: &SessionRecord) -> Result<SessionHandle, ControlError> {
    let external_id = record.external_id.clone().ok_or_else(|| {
        ControlError::new(
            "session_incomplete",
            format!("actor `{}` has no backend session handle", record.actor_id),
        )
    })?;
    Ok(SessionHandle {
        backend: record.backend.clone(),
        external_id,
        resume_token: record.resume_token.clone(),
    })
}

fn status_name(status: &SessionStatus) -> &'static str {
    match status {
        SessionStatus::Starting => "starting",
        SessionStatus::Working => "working",
        SessionStatus::Idle => "idle",
        SessionStatus::Blocked => "blocked",
        SessionStatus::Stopped { .. } => "stopped",
        SessionStatus::Missing => "missing",
        SessionStatus::Unknown(_) => "unknown",
    }
}

#[allow(clippy::needless_pass_by_value)]
fn session_error(error: agsv_session::SessionError) -> ControlError {
    let code = match error {
        agsv_session::SessionError::Unsupported { .. } => "unsupported_operation",
        agsv_session::SessionError::NotFound(_) => "session_not_found",
        _ => "session_backend_error",
    };
    ControlError::new(code, error.to_string())
        .with_hint("run `agsv --json reconcile` after correcting the session backend")
}

fn command_version(program: &str) -> serde_json::Value {
    match Command::new(program).arg("--version").output() {
        Ok(output) => serde_json::json!({
            "available": output.status.success(),
            "version": String::from_utf8_lossy(&output.stdout).trim(),
            "error": String::from_utf8_lossy(&output.stderr).trim(),
        }),
        Err(error) => serde_json::json!({ "available": false, "error": error.to_string() }),
    }
}
