use std::process::Command;
use std::sync::Arc;

use crate::ControlError;
use crate::engine::BackendKind;
use crate::identity::sha256_hex;
use crate::store::SessionRecord;
use agsv_runtime::{AgentRuntime, RuntimeConfig, RuntimeLaunchRequest};
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
    pub(crate) fn launch_with_initial_prompt(
        &self,
        actor_id: &str,
        session_name: &str,
        working_directory: &std::path::Path,
        launch_key: &str,
        runtime: &dyn AgentRuntime,
        runtime_config: &RuntimeConfig,
        initial_prompt: Option<&str>,
        resume_token: Option<String>,
        checkpoint: &mut dyn FnMut(&str) -> Result<(), ControlError>,
    ) -> Result<SessionHandle, ControlError> {
        let invocation = runtime
            .launch_invocation(RuntimeLaunchRequest {
                config: runtime_config,
                initial_prompt,
            })
            .map_err(|error| {
                ControlError::new("runtime_adapter_error", error.to_string())
                    .with_details(serde_json::json!({ "runtime": runtime.id().as_str() }))
            })?;
        let request = LaunchRequest {
            actor_id: actor_id.to_owned(),
            session_name: session_name.to_owned(),
            runtime: invocation.program,
            working_directory: working_directory.to_path_buf(),
            idempotency_key: launch_key.to_owned(),
            native_args: invocation.arguments,
            initial_prompt: invocation.initial_prompt,
            resume_token,
        };
        match self.kind {
            BackendKind::Fake => {
                let digest = sha256_hex(&request.idempotency_key);
                Ok(SessionHandle {
                    backend: "fake".to_owned(),
                    external_id: format!("fake-{}", &digest[..16]),
                    resume_token: Some(format!("fake-pane-{}", &digest[..16])),
                })
            }
            BackendKind::Herdr => Self::herdr()
                .launch_with_checkpoint(&request, &mut |value| {
                    checkpoint(&value.resume_token)
                        .map_err(|error| agsv_session::SessionError::Checkpoint(error.to_string()))
                })
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
        if record.backend != self.name() {
            return Err(ControlError::new(
                "session_backend_error",
                format!(
                    "actor `{}` session backend `{}` does not match active backend `{}`",
                    record.actor_id,
                    record.backend,
                    self.name()
                ),
            ));
        }
        let handle = SessionHandle {
            backend: record.backend.clone(),
            external_id: record.external_id.clone().unwrap_or_default(),
            resume_token: record.resume_token.clone(),
        };
        Self::herdr()
            .stop_owned(&handle, Some(&record.working_directory))
            .map_err(session_error)
    }

    pub(crate) fn diagnostics(&self) -> serde_json::Value {
        let (backend, backend_runtime) = match self.kind {
            BackendKind::Herdr => (
                command_version("herdr"),
                command_probe("herdr", &["status", "server"]),
            ),
            BackendKind::Fake => (
                serde_json::json!({
                    "available": true,
                    "version": "built-in deterministic fake",
                }),
                serde_json::json!({
                    "reachable": true,
                    "detail": "built-in deterministic fake",
                }),
            ),
        };
        serde_json::json!({
            "backend": self.name(),
            "backend_command": backend,
            "backend_runtime": backend_runtime,
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

fn command_probe(program: &str, args: &[&str]) -> serde_json::Value {
    match Command::new(program).args(args).output() {
        Ok(output) => serde_json::json!({
            "reachable": output.status.success(),
            "detail": String::from_utf8_lossy(&output.stdout).trim(),
            "error": String::from_utf8_lossy(&output.stderr).trim(),
        }),
        Err(error) => serde_json::json!({ "reachable": false, "error": error.to_string() }),
    }
}
