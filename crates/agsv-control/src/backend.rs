use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use agsv_session::{
    HerdrAdapter, LaunchCheckpoint, LaunchRequest, ResumeRequest, SessionBackend, SessionError,
    SessionHandle, SessionStatus, SystemCommandRunner,
};
use serde_json::{Value, json};

use crate::ControlError;
use crate::caller::PrimaryNotificationEndpoint;
use crate::identity::sha256_hex;
use crate::store::SessionRecord;

type BackendBuilder = fn() -> Arc<dyn ManagedSessionBackend>;

#[derive(Clone, Copy)]
struct BackendFactory {
    id: &'static str,
    build: BackendBuilder,
}

impl BackendFactory {
    const fn new(id: &'static str, build: BackendBuilder) -> Self {
        Self { id, build }
    }
}

const HERDR_BACKEND_ID: &str = "herdr";
const FAKE_BACKEND_ID: &str = "fake";

static COMPILED_BACKENDS: [BackendFactory; 2] = [
    BackendFactory::new(HERDR_BACKEND_ID, build_herdr_backend),
    BackendFactory::new(FAKE_BACKEND_ID, build_fake_backend),
];

/// Control-plane behavior layered over the provider-neutral session lifecycle.
///
/// The extra hooks keep backend-specific ownership, diagnostics, and the
/// embedded fake's persisted-record behavior out of the integrated engine.
trait ManagedSessionBackend: SessionBackend {
    fn status_record(&self, record: &SessionRecord) -> Result<String, ControlError> {
        let snapshot = self.status(&handle(record)?).map_err(session_error)?;
        Ok(status_name(&snapshot.status).to_owned())
    }

    fn notify_record(&self, record: &SessionRecord, message: &str) -> Result<(), ControlError> {
        self.send_message(&handle(record)?, message)
            .map_err(session_error)
    }

    fn stop_record(&self, record: &SessionRecord) -> Result<(), ControlError> {
        self.stop(&handle(record)?).map_err(session_error)
    }

    fn diagnostics(&self) -> Value {
        json!({
            "backend": self.name(),
            "ready": true,
            "backend_command": {
                "available": true,
                "version": "built-in session backend",
            },
            "backend_runtime": {
                "reachable": true,
                "detail": "built-in session backend",
            },
            "codex": command_version("codex"),
        })
    }

    fn allows_insecure_actor_identity(&self) -> bool {
        false
    }

    fn primary_notification_handle(
        &self,
        _workspace_id: &str,
        _actor_id: &str,
        _actor_epoch: u64,
        _caller_handle: Option<&SessionHandle>,
    ) -> Result<SessionHandle, ControlError> {
        Err(ControlError::new(
            "session_backend_error",
            format!(
                "session backend `{}` cannot derive a Primary notification handle",
                self.name()
            ),
        ))
    }

    fn validate_expected_external_id(
        &self,
        _actor_id: &str,
        _context: &str,
        _expected: &str,
        _actual: Option<&str>,
    ) -> Result<(), ControlError> {
        Ok(())
    }

    fn validate_primary_notification_handle(
        &self,
        _actor_id: &str,
        _handle: &SessionHandle,
    ) -> Result<(), ControlError> {
        Ok(())
    }
}

/// Compiled session backend catalog plus the backend selected for fresh work.
///
/// Existing durable records are always dispatched through their own backend
/// identifier. This keeps opaque handles and launch checkpoints paired with
/// the adapter that created them even if configuration changes later.
pub(crate) struct SessionDriver {
    configured_backend: String,
    backends: BTreeMap<String, Arc<dyn ManagedSessionBackend>>,
}

impl SessionDriver {
    pub(crate) fn new(configured_backend: &str) -> Result<Self, ControlError> {
        Self::from_factories(configured_backend, &COMPILED_BACKENDS)
    }

    fn from_factories(
        configured_backend: &str,
        factories: &[BackendFactory],
    ) -> Result<Self, ControlError> {
        let configured_backend = normalize_backend_id(configured_backend);
        let mut backends = BTreeMap::new();
        for factory in factories {
            let backend = (factory.build)();
            if backend.name() != factory.id {
                return Err(ControlError::new(
                    "invalid_session_backend_registry",
                    format!(
                        "session backend factory `{}` built backend `{}`",
                        factory.id,
                        backend.name()
                    ),
                )
                .with_details(json!({
                    "factory_id": factory.id,
                    "backend_name": backend.name(),
                })));
            }
            if backends.insert(factory.id.to_owned(), backend).is_some() {
                return Err(ControlError::new(
                    "invalid_session_backend_registry",
                    format!("duplicate session backend factory `{}`", factory.id),
                ));
            }
        }
        if !backends.contains_key(&configured_backend) {
            return Err(unknown_backend(&configured_backend, backends.keys()));
        }
        Ok(Self {
            configured_backend,
            backends,
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.configured_backend
    }

    pub(crate) fn configured_backend(&self) -> &str {
        self.name()
    }

    pub(crate) fn allows_insecure_actor_identity(&self) -> bool {
        self.configured()
            .expect("the configured backend is validated during construction")
            .allows_insecure_actor_identity()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn launch_with_initial_prompt(
        &self,
        actor_id: &str,
        session_name: &str,
        working_directory: &Path,
        launch_key: &str,
        native_args: Vec<String>,
        initial_prompt: Option<String>,
        resume_token: Option<String>,
        checkpoint: &mut dyn FnMut(&str) -> Result<(), ControlError>,
    ) -> Result<SessionHandle, ControlError> {
        self.launch_with_initial_prompt_for(
            self.configured_backend(),
            actor_id,
            session_name,
            working_directory,
            launch_key,
            native_args,
            initial_prompt,
            resume_token,
            checkpoint,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn launch_with_initial_prompt_for(
        &self,
        backend_id: &str,
        actor_id: &str,
        session_name: &str,
        working_directory: &Path,
        launch_key: &str,
        native_args: Vec<String>,
        initial_prompt: Option<String>,
        resume_token: Option<String>,
        checkpoint: &mut dyn FnMut(&str) -> Result<(), ControlError>,
    ) -> Result<SessionHandle, ControlError> {
        let request = LaunchRequest {
            actor_id: actor_id.to_owned(),
            session_name: session_name.to_owned(),
            runtime: "codex".to_owned(),
            working_directory: working_directory.to_path_buf(),
            idempotency_key: launch_key.to_owned(),
            native_args,
            initial_prompt,
            resume_token,
        };
        self.launch_with_checkpoint(backend_id, &request, checkpoint)
    }

    pub(crate) fn launch_with_checkpoint(
        &self,
        backend_id: &str,
        request: &LaunchRequest,
        checkpoint: &mut dyn FnMut(&str) -> Result<(), ControlError>,
    ) -> Result<SessionHandle, ControlError> {
        let backend = self.backend(backend_id)?;
        let mut persist_checkpoint = |value: &LaunchCheckpoint| {
            checkpoint(&value.resume_token)
                .map_err(|error| SessionError::Checkpoint(error.to_string()))
        };
        let handle = backend
            .launch_with_checkpoint(request, &mut persist_checkpoint)
            .map_err(session_error)?;
        validate_returned_handle(backend.name(), &handle)?;
        Ok(handle)
    }

    #[cfg(test)]
    pub(crate) fn resume(
        &self,
        backend_id: &str,
        request: &ResumeRequest,
    ) -> Result<SessionHandle, ControlError> {
        let backend = self.backend(backend_id)?;
        reject_foreign_handle(backend.name(), &request.handle).map_err(session_error)?;
        let handle = backend.resume(request).map_err(session_error)?;
        validate_returned_handle(backend.name(), &handle)?;
        Ok(handle)
    }

    pub(crate) fn status(&self, record: &SessionRecord) -> Result<String, ControlError> {
        self.backend(&record.backend)?.status_record(record)
    }

    pub(crate) fn notify(&self, record: &SessionRecord, message: &str) -> Result<(), ControlError> {
        self.backend(&record.backend)?
            .notify_record(record, message)
    }

    pub(crate) fn stop(&self, record: &SessionRecord) -> Result<(), ControlError> {
        self.backend(&record.backend)?.stop_record(record)
    }

    pub(crate) fn diagnostics(&self) -> Value {
        self.configured()
            .expect("the configured backend is validated during construction")
            .diagnostics()
    }

    pub(crate) fn primary_notification_handle(
        &self,
        workspace_id: &str,
        actor_id: &str,
        actor_epoch: u64,
        caller_endpoint: Option<&PrimaryNotificationEndpoint<'_>>,
    ) -> Result<SessionHandle, ControlError> {
        let backend = self.configured()?;
        let caller_handle =
            caller_endpoint.and_then(|endpoint| endpoint.handle_for(backend.name()));
        let handle = backend.primary_notification_handle(
            workspace_id,
            actor_id,
            actor_epoch,
            caller_handle.as_ref(),
        )?;
        validate_returned_handle(backend.name(), &handle)?;
        Ok(handle)
    }

    pub(crate) fn validate_expected_external_id(
        &self,
        backend_id: &str,
        actor_id: &str,
        context: &str,
        expected: &str,
        actual: Option<&str>,
    ) -> Result<(), ControlError> {
        self.backend(backend_id)?
            .validate_expected_external_id(actor_id, context, expected, actual)
    }

    pub(crate) fn validate_primary_notification_handle(
        &self,
        actor_id: &str,
        record: &SessionRecord,
    ) -> Result<(), ControlError> {
        let backend = self.backend(&record.backend)?;
        backend.validate_primary_notification_handle(actor_id, &handle(record)?)
    }

    fn configured(&self) -> Result<&dyn ManagedSessionBackend, ControlError> {
        self.backend(&self.configured_backend)
    }

    fn backend(&self, backend_id: &str) -> Result<&dyn ManagedSessionBackend, ControlError> {
        let backend_id = normalize_backend_id(backend_id);
        self.backends
            .get(&backend_id)
            .map(Arc::as_ref)
            .ok_or_else(|| unknown_backend(&backend_id, self.backends.keys()))
    }
}

struct DeterministicFakeBackend;

impl SessionBackend for DeterministicFakeBackend {
    fn name(&self) -> &'static str {
        FAKE_BACKEND_ID
    }

    fn launch(&self, request: &LaunchRequest) -> Result<SessionHandle, SessionError> {
        Ok(fake_handle(&request.idempotency_key))
    }

    fn launch_with_checkpoint(
        &self,
        request: &LaunchRequest,
        checkpoint: &mut dyn FnMut(&LaunchCheckpoint) -> Result<(), SessionError>,
    ) -> Result<SessionHandle, SessionError> {
        let handle = fake_handle(&request.idempotency_key);
        checkpoint(&LaunchCheckpoint {
            resume_token: handle
                .resume_token
                .clone()
                .expect("the deterministic fake always has a resume token"),
        })?;
        Ok(handle)
    }

    fn resume(&self, request: &ResumeRequest) -> Result<SessionHandle, SessionError> {
        reject_foreign_handle(self.name(), &request.handle)?;
        Ok(request.handle.clone())
    }

    fn status(
        &self,
        handle: &SessionHandle,
    ) -> Result<agsv_session::SessionSnapshot, SessionError> {
        reject_foreign_handle(self.name(), handle)?;
        Ok(agsv_session::SessionSnapshot {
            handle: handle.clone(),
            status: SessionStatus::Idle,
            detail: None,
        })
    }

    fn send_message(&self, handle: &SessionHandle, _message: &str) -> Result<(), SessionError> {
        reject_foreign_handle(self.name(), handle)
    }

    fn stop(&self, handle: &SessionHandle) -> Result<(), SessionError> {
        reject_foreign_handle(self.name(), handle)
    }
}

impl ManagedSessionBackend for DeterministicFakeBackend {
    fn status_record(&self, record: &SessionRecord) -> Result<String, ControlError> {
        validate_record_backend(self.name(), record)?;
        Ok(record.status.clone())
    }

    fn notify_record(&self, record: &SessionRecord, _message: &str) -> Result<(), ControlError> {
        validate_record_backend(self.name(), record)
    }

    fn stop_record(&self, record: &SessionRecord) -> Result<(), ControlError> {
        validate_record_backend(self.name(), record)
    }

    fn diagnostics(&self) -> Value {
        json!({
            "backend": self.name(),
            "ready": true,
            "backend_command": {
                "available": true,
                "version": "built-in deterministic fake",
            },
            "backend_runtime": {
                "reachable": true,
                "detail": "built-in deterministic fake",
            },
            "codex": command_version("codex"),
        })
    }

    fn allows_insecure_actor_identity(&self) -> bool {
        true
    }

    fn primary_notification_handle(
        &self,
        workspace_id: &str,
        actor_id: &str,
        actor_epoch: u64,
        _caller_handle: Option<&SessionHandle>,
    ) -> Result<SessionHandle, ControlError> {
        let digest = sha256_hex(format!("{workspace_id}:{actor_id}:{actor_epoch}"));
        Ok(SessionHandle {
            backend: self.name().to_owned(),
            external_id: format!("fake-primary-{}", &digest[..16]),
            resume_token: None,
        })
    }
}

impl ManagedSessionBackend for HerdrAdapter {
    fn stop_record(&self, record: &SessionRecord) -> Result<(), ControlError> {
        self.stop_owned(&herdr_stop_handle(record), Some(&record.working_directory))
            .map_err(session_error)
    }

    fn diagnostics(&self) -> Value {
        let backend_command = command_version(HERDR_BACKEND_ID);
        let backend_runtime = command_probe(HERDR_BACKEND_ID, &["status", "server"]);
        let ready = backend_command["available"].as_bool() == Some(true)
            && backend_runtime["reachable"].as_bool() == Some(true);
        json!({
            "backend": self.name(),
            "ready": ready,
            "backend_command": backend_command,
            "backend_runtime": backend_runtime,
            "codex": command_version("codex"),
        })
    }

    fn primary_notification_handle(
        &self,
        _workspace_id: &str,
        actor_id: &str,
        _actor_epoch: u64,
        caller_handle: Option<&SessionHandle>,
    ) -> Result<SessionHandle, ControlError> {
        let handle = caller_handle.ok_or_else(|| {
            ControlError::new(
                "actor_identity_unavailable",
                format!(
                    "Primary actor `{actor_id}` has no caller endpoint for backend `{}`",
                    self.name()
                ),
            )
        })?;
        reject_foreign_handle(self.name(), handle).map_err(session_error)?;
        self.validate_primary_notification_handle(actor_id, handle)?;
        Ok(handle.clone())
    }

    fn validate_expected_external_id(
        &self,
        actor_id: &str,
        context: &str,
        expected: &str,
        actual: Option<&str>,
    ) -> Result<(), ControlError> {
        let Some(actual) = actual else {
            return Ok(());
        };
        if actual == expected {
            return Ok(());
        }
        Err(ControlError::new(
            "session_ownership_mismatch",
            format!("{context} external session id does not match the expected workspace actor"),
        )
        .with_details(json!({
            "actor_id": actor_id,
            "backend": self.name(),
            "expected_external_id": expected,
            "actual_external_id": actual,
            "context": context,
        })))
    }

    fn validate_primary_notification_handle(
        &self,
        actor_id: &str,
        handle: &SessionHandle,
    ) -> Result<(), ControlError> {
        if handle.resume_token.as_deref() == Some(handle.external_id.as_str()) {
            return Ok(());
        }
        Err(ControlError::new(
            "stale_notification_endpoint",
            format!(
                "Primary actor `{actor_id}` notification endpoint is not bound to its current generation"
            ),
        )
        .with_hint(
            "run `agsv --json context --bootstrap` in the active Primary pane, then retry with the same operation ID",
        ))
    }
}

fn build_herdr_backend() -> Arc<dyn ManagedSessionBackend> {
    Arc::new(HerdrAdapter::verified_v0_8(Arc::new(SystemCommandRunner)))
}

fn build_fake_backend() -> Arc<dyn ManagedSessionBackend> {
    Arc::new(DeterministicFakeBackend)
}

fn fake_handle(launch_key: &str) -> SessionHandle {
    let digest = sha256_hex(launch_key);
    SessionHandle {
        backend: FAKE_BACKEND_ID.to_owned(),
        external_id: format!("fake-{}", &digest[..16]),
        resume_token: Some(format!("fake-pane-{}", &digest[..16])),
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

fn herdr_stop_handle(record: &SessionRecord) -> SessionHandle {
    SessionHandle {
        backend: record.backend.clone(),
        external_id: record.external_id.clone().unwrap_or_default(),
        resume_token: record.resume_token.clone(),
    }
}

fn validate_record_backend(
    expected_backend: &str,
    record: &SessionRecord,
) -> Result<(), ControlError> {
    if record.backend == expected_backend {
        Ok(())
    } else {
        Err(ControlError::new(
            "session_backend_error",
            format!(
                "actor `{}` session backend `{}` does not match dispatched backend `{expected_backend}`",
                record.actor_id, record.backend
            ),
        ))
    }
}

fn validate_returned_handle(
    expected_backend: &str,
    handle: &SessionHandle,
) -> Result<(), ControlError> {
    reject_foreign_handle(expected_backend, handle).map_err(session_error)
}

fn reject_foreign_handle(
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

fn normalize_backend_id(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn unknown_backend<'a>(
    requested: &str,
    available: impl Iterator<Item = &'a String>,
) -> ControlError {
    let available = available.cloned().collect::<Vec<_>>();
    ControlError::new(
        "unknown_session_backend",
        format!("session backend `{requested}` is not compiled into this AGSV binary"),
    )
    .with_details(json!({
        "backend": requested,
        "available_backends": available,
    }))
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
fn session_error(error: SessionError) -> ControlError {
    let code = match error {
        SessionError::Unsupported { .. } => "unsupported_operation",
        SessionError::NotFound(_) => "session_not_found",
        _ => "session_backend_error",
    };
    ControlError::new(code, error.to_string())
        .with_hint("run `agsv --json reconcile` after correcting the session backend")
}

fn command_version(program: &str) -> Value {
    match Command::new(program).arg("--version").output() {
        Ok(output) => json!({
            "available": output.status.success(),
            "version": String::from_utf8_lossy(&output.stdout).trim(),
            "error": String::from_utf8_lossy(&output.stderr).trim(),
        }),
        Err(error) => json!({ "available": false, "error": error.to_string() }),
    }
}

fn command_probe(program: &str, args: &[&str]) -> Value {
    match Command::new(program).args(args).output() {
        Ok(output) => json!({
            "reachable": output.status.success(),
            "detail": String::from_utf8_lossy(&output.stdout).trim(),
            "error": String::from_utf8_lossy(&output.stderr).trim(),
        }),
        Err(error) => json!({ "reachable": false, "error": error.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use agsv_session::{
        HerdrAdapter, LaunchRequest, ResumeRequest, SessionBackend, SessionError, SessionHandle,
        SessionSnapshot, SessionStatus, SystemCommandRunner,
    };

    use super::{
        BackendFactory, ManagedSessionBackend, SessionDriver, build_fake_backend, herdr_stop_handle,
    };
    use crate::store::SessionRecord;

    const FIXTURE_BACKEND_ID: &str = "fixture";

    struct FixtureBackend;

    impl SessionBackend for FixtureBackend {
        fn name(&self) -> &'static str {
            FIXTURE_BACKEND_ID
        }

        fn launch(&self, request: &LaunchRequest) -> Result<SessionHandle, SessionError> {
            Ok(SessionHandle {
                backend: self.name().to_owned(),
                external_id: format!("fixture-{}", request.idempotency_key),
                resume_token: None,
            })
        }

        fn resume(&self, request: &ResumeRequest) -> Result<SessionHandle, SessionError> {
            Ok(request.handle.clone())
        }

        fn status(&self, handle: &SessionHandle) -> Result<SessionSnapshot, SessionError> {
            Ok(SessionSnapshot {
                handle: handle.clone(),
                status: SessionStatus::Working,
                detail: None,
            })
        }

        fn send_message(
            &self,
            _handle: &SessionHandle,
            _message: &str,
        ) -> Result<(), SessionError> {
            Ok(())
        }

        fn stop(&self, _handle: &SessionHandle) -> Result<(), SessionError> {
            Ok(())
        }
    }

    impl ManagedSessionBackend for FixtureBackend {}

    fn build_fixture_backend() -> Arc<dyn ManagedSessionBackend> {
        Arc::new(FixtureBackend)
    }

    fn fake_driver() -> SessionDriver {
        SessionDriver::from_factories("fake", &[BackendFactory::new("fake", build_fake_backend)])
            .unwrap()
    }

    fn launch_request(key: &str) -> LaunchRequest {
        LaunchRequest {
            actor_id: "actor-1".to_owned(),
            session_name: "session-one".to_owned(),
            runtime: "codex".to_owned(),
            working_directory: PathBuf::from("/workspace"),
            idempotency_key: key.to_owned(),
            native_args: vec!["--flag".to_owned()],
            initial_prompt: Some("ready".to_owned()),
            resume_token: None,
        }
    }

    fn record(status: &str) -> SessionRecord {
        SessionRecord {
            actor_id: "actor-1".to_owned(),
            team_id: Some("team-1".to_owned()),
            working_directory: PathBuf::from("/workspace"),
            backend: "fake".to_owned(),
            external_id: None,
            resume_token: None,
            status: status.to_owned(),
            launch_key: "launch-1".to_owned(),
            updated_at_ms: 1,
        }
    }

    #[test]
    fn registry_selects_a_second_compiled_fixture_by_identifier() {
        let driver = SessionDriver::from_factories(
            " FIXTURE ",
            &[BackendFactory::new(
                FIXTURE_BACKEND_ID,
                build_fixture_backend,
            )],
        )
        .unwrap();
        assert_eq!(driver.configured_backend(), FIXTURE_BACKEND_ID);

        let handle = driver
            .launch_with_checkpoint(FIXTURE_BACKEND_ID, &launch_request("second"), &mut |_| {
                Ok(())
            })
            .unwrap();
        assert_eq!(handle.backend, FIXTURE_BACKEND_ID);
        assert_eq!(handle.external_id, "fixture-second");
    }

    #[test]
    fn registry_rejects_unknown_and_mismatched_factories() {
        let unknown = SessionDriver::from_factories(
            "missing",
            &[BackendFactory::new(
                FIXTURE_BACKEND_ID,
                build_fixture_backend,
            )],
        )
        .err()
        .unwrap();
        assert_eq!(unknown.code, "unknown_session_backend");
        assert_eq!(unknown.details["backend"], "missing");
        assert_eq!(unknown.details["available_backends"][0], "fixture");

        let mismatched = SessionDriver::from_factories(
            "wrong",
            &[BackendFactory::new("wrong", build_fixture_backend)],
        )
        .err()
        .unwrap();
        assert_eq!(mismatched.code, "invalid_session_backend_registry");
        assert_eq!(mismatched.details["factory_id"], "wrong");
        assert_eq!(mismatched.details["backend_name"], "fixture");
    }

    #[test]
    fn fake_launch_and_checkpoint_are_stable_across_driver_instances() {
        let first_driver = fake_driver();
        let mut first_checkpoints = Vec::new();
        let first = first_driver
            .launch_with_checkpoint("fake", &launch_request("launch-one"), &mut |token| {
                first_checkpoints.push(token.to_owned());
                Ok(())
            })
            .unwrap();

        let second_driver = fake_driver();
        let mut second_checkpoints = Vec::new();
        let second = second_driver
            .launch_with_checkpoint("fake", &launch_request("launch-one"), &mut |token| {
                second_checkpoints.push(token.to_owned());
                Ok(())
            })
            .unwrap();
        let distinct = second_driver
            .launch_with_checkpoint("fake", &launch_request("launch-two"), &mut |_| Ok(()))
            .unwrap();

        assert_eq!(first, second);
        assert_ne!(first, distinct);
        assert_eq!(first_checkpoints, second_checkpoints);
        assert_eq!(first_checkpoints.as_slice(), first.resume_token.as_slice());
        assert!(first.external_id.starts_with("fake-"));
        assert!(first_checkpoints[0].starts_with("fake-pane-"));
    }

    #[test]
    fn fake_resume_status_notify_and_stop_are_deterministic_and_record_aware() {
        let driver = fake_driver();
        let handle = driver
            .launch_with_checkpoint("fake", &launch_request("lifecycle"), &mut |_| Ok(()))
            .unwrap();
        let resumed = driver
            .resume(
                "fake",
                &ResumeRequest {
                    actor_id: "actor-1".to_owned(),
                    handle: handle.clone(),
                    working_directory: PathBuf::from("/workspace"),
                    idempotency_key: "resume-one".to_owned(),
                    native_args: Vec::new(),
                },
            )
            .unwrap();
        assert_eq!(resumed, handle);

        let incomplete = record("blocked");
        assert_eq!(driver.status(&incomplete).unwrap(), "blocked");
        driver
            .notify(&incomplete, "wake from a persisted record")
            .unwrap();
        driver.stop(&incomplete).unwrap();

        let stopped = record("stopped");
        assert_eq!(driver.status(&stopped).unwrap(), "stopped");
        assert_eq!(driver.diagnostics()["ready"], true);
        assert!(driver.allows_insecure_actor_identity());
    }

    #[test]
    fn fake_primary_notification_handles_are_stable() {
        let first = fake_driver()
            .primary_notification_handle("workspace", "primary", 2, None)
            .unwrap();
        let second = fake_driver()
            .primary_notification_handle("workspace", "primary", 2, None)
            .unwrap();
        let next_epoch = fake_driver()
            .primary_notification_handle("workspace", "primary", 3, None)
            .unwrap();
        assert_eq!(first, second);
        assert_ne!(first, next_epoch);
        assert!(first.external_id.starts_with("fake-primary-"));
    }

    #[test]
    fn herdr_primary_notification_requires_a_compatible_caller_handle() {
        let backend = HerdrAdapter::verified_v0_8(Arc::new(SystemCommandRunner));
        let missing = backend
            .primary_notification_handle("workspace", "primary", 2, None)
            .unwrap_err();
        assert_eq!(missing.code, "actor_identity_unavailable");

        let foreign = SessionHandle {
            backend: "fake".to_owned(),
            external_id: "opaque-caller-endpoint".to_owned(),
            resume_token: Some("opaque-caller-endpoint".to_owned()),
        };
        let foreign = backend
            .primary_notification_handle("workspace", "primary", 2, Some(&foreign))
            .unwrap_err();
        assert_eq!(foreign.code, "session_backend_error");

        let compatible = SessionHandle {
            backend: "herdr".to_owned(),
            external_id: "opaque-caller-endpoint".to_owned(),
            resume_token: Some("opaque-caller-endpoint".to_owned()),
        };
        let selected = backend
            .primary_notification_handle("workspace", "primary", 2, Some(&compatible))
            .unwrap();
        assert_eq!(selected, compatible);
    }

    #[test]
    fn fake_record_dispatch_rejects_an_unknown_backend() {
        let driver = fake_driver();
        let mut foreign = record("idle");
        foreign.backend = "not-compiled".to_owned();
        let error = driver.status(&foreign).unwrap_err();
        assert_eq!(error.code, "unknown_session_backend");
    }

    #[test]
    fn fixture_default_record_methods_use_opaque_handles() {
        let driver = SessionDriver::from_factories(
            FIXTURE_BACKEND_ID,
            &[BackendFactory::new(
                FIXTURE_BACKEND_ID,
                build_fixture_backend,
            )],
        )
        .unwrap();
        let record = SessionRecord {
            actor_id: "actor-opaque".to_owned(),
            team_id: None,
            working_directory: PathBuf::from("/workspace"),
            backend: FIXTURE_BACKEND_ID.to_owned(),
            external_id: Some("opaque:$session/value".to_owned()),
            resume_token: Some("opaque:$resume/value".to_owned()),
            status: "persisted-status-is-not-used".to_owned(),
            launch_key: "fixture-launch".to_owned(),
            updated_at_ms: 1,
        };
        assert_eq!(driver.status(&record).unwrap(), "working");
        driver.notify(&record, "message").unwrap();
        driver.stop(&record).unwrap();
    }

    #[test]
    fn fake_launch_wrapper_uses_the_configured_backend() {
        let driver = fake_driver();
        let handle = driver
            .launch_with_initial_prompt(
                "actor-1",
                "session-one",
                Path::new("/workspace"),
                "configured-launch",
                Vec::new(),
                None,
                None,
                &mut |_| Ok(()),
            )
            .unwrap();
        assert_eq!(handle.backend, "fake");
    }

    #[test]
    fn herdr_stop_preserves_an_incomplete_launch_checkpoint() {
        let mut incomplete = record("launch_failed");
        incomplete.backend = "herdr".to_owned();
        incomplete.resume_token = Some("opaque-pane-checkpoint".to_owned());
        let handle = herdr_stop_handle(&incomplete);
        assert_eq!(handle.backend, "herdr");
        assert_eq!(handle.external_id, "");
        assert_eq!(
            handle.resume_token.as_deref(),
            Some("opaque-pane-checkpoint")
        );
    }

    #[test]
    fn persisted_launch_dispatch_ignores_the_fresh_backend_selection() {
        let driver = SessionDriver::new("herdr").unwrap();
        let handle = driver
            .launch_with_initial_prompt_for(
                "fake",
                "actor-1",
                "session-one",
                Path::new("/workspace"),
                "persisted-launch",
                Vec::new(),
                None,
                Some("persisted-checkpoint".to_owned()),
                &mut |_| Ok(()),
            )
            .unwrap();
        assert_eq!(driver.configured_backend(), "herdr");
        assert_eq!(handle.backend, "fake");
    }
}
