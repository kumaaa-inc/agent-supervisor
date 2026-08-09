use std::path::Path;
use std::sync::Arc;

use serde_json::Value;

use crate::process::{handle_values, launch_values};
use crate::{
    CommandOutput, CommandRunner, CommandTemplate, LaunchCheckpoint, LaunchRequest, ResumeRequest,
    SessionBackend, SessionError, SessionHandle, SessionSnapshot, SessionStatus,
    types::reject_foreign_handle,
};

/// Replaceable Herdr commands. Defaults cover only syntax verified against Herdr 0.8.0.
#[derive(Clone, Debug)]
pub struct HerdrTemplates {
    pub inspect: CommandTemplate,
    pub inspect_pane: CommandTemplate,
    pub create_tab: CommandTemplate,
    pub start_agent: CommandTemplate,
    pub resume: Option<CommandTemplate>,
    pub status: CommandTemplate,
    pub wait: CommandTemplate,
    pub message: CommandTemplate,
    pub stop: Option<CommandTemplate>,
}

impl Default for HerdrTemplates {
    fn default() -> Self {
        Self {
            inspect: CommandTemplate::new("herdr", ["agent", "get", "{session_id}"]),
            inspect_pane: CommandTemplate::new("herdr", ["pane", "get", "{resume_token}"]),
            create_tab: CommandTemplate::new(
                "herdr",
                [
                    "tab",
                    "create",
                    "--cwd",
                    "{cwd}",
                    "--label",
                    "{session_name}",
                    "--no-focus",
                ],
            ),
            start_agent: CommandTemplate::new(
                "herdr",
                [
                    "agent",
                    "start",
                    "{session_name}",
                    "--kind",
                    "{runtime}",
                    "--pane",
                    "{pane_id}",
                    "{native_args_with_separator}",
                ],
            ),
            resume: None,
            status: CommandTemplate::new("herdr", ["agent", "get", "{session_id}"]),
            wait: CommandTemplate::new(
                "herdr",
                ["agent", "wait", "{session_id}", "--timeout", "120000"],
            ),
            message: CommandTemplate::new(
                "herdr",
                ["agent", "prompt", "{session_id}", "{message}"],
            ),
            stop: Some(CommandTemplate::new(
                "herdr",
                ["pane", "close", "{resume_token}"],
            )),
        }
    }
}

/// Herdr session adapter. Herdr is a backend, not a runtime dependency.
pub struct HerdrAdapter {
    templates: HerdrTemplates,
    runner: Arc<dyn CommandRunner>,
}

impl HerdrAdapter {
    #[must_use]
    pub fn new(templates: HerdrTemplates, runner: Arc<dyn CommandRunner>) -> Self {
        Self { templates, runner }
    }

    #[must_use]
    pub fn verified_v0_8(runner: Arc<dyn CommandRunner>) -> Self {
        Self::new(HerdrTemplates::default(), runner)
    }

    fn checked_run(
        &self,
        invocation: &crate::CommandInvocation,
    ) -> Result<CommandOutput, SessionError> {
        let output = self.runner.run(invocation)?;
        if output.success() {
            Ok(output)
        } else {
            Err(classify_herdr_failure(output))
        }
    }

    fn inspect(&self, external_id: &str) -> Result<Option<SessionSnapshot>, SessionError> {
        let handle = SessionHandle {
            backend: self.name().to_owned(),
            external_id: external_id.to_owned(),
            resume_token: None,
        };
        let invocation = self
            .templates
            .inspect
            .render(&handle_values(&handle), &[], None)?;
        let output = self.runner.run(&invocation)?;
        if !output.success() {
            return match classify_herdr_failure(output) {
                SessionError::NotFound(_) => Ok(None),
                error => Err(error),
            };
        }
        Ok(Some(snapshot_from_json(handle, &output.stdout)?))
    }

    fn inspect_pane(
        &self,
        pane_id: &str,
        expected_working_directory: Option<&Path>,
    ) -> Result<bool, SessionError> {
        let handle = SessionHandle {
            backend: self.name().to_owned(),
            external_id: String::new(),
            resume_token: Some(pane_id.to_owned()),
        };
        let invocation = self
            .templates
            .inspect_pane
            .render(&handle_values(&handle), &[], None)?;
        let output = self.runner.run(&invocation)?;
        if !output.success() {
            return match classify_herdr_failure(output) {
                SessionError::NotFound(_) => Ok(false),
                error => Err(error),
            };
        }
        let value: Value = serde_json::from_str(&output.stdout)
            .map_err(|error| SessionError::InvalidOutput(error.to_string()))?;
        let observed = find_string(&value, &["pane_id"]).ok_or_else(|| {
            SessionError::InvalidOutput("pane inspection omitted pane_id".to_owned())
        })?;
        if observed != pane_id {
            return Err(SessionError::InvalidOutput(format!(
                "pane inspection returned {observed:?} for requested pane {pane_id:?}"
            )));
        }
        if let (Some(expected), Some(observed)) =
            (expected_working_directory, pane_working_directory(&value))
        {
            if Path::new(observed) != expected {
                return Err(SessionError::InvalidConfiguration(format!(
                    "refusing to close pane {pane_id:?}: working directory {observed:?} does not match AGSV session directory {:?}",
                    expected.display()
                )));
            }
        }
        Ok(true)
    }

    fn deliver_initial_prompt(
        &self,
        handle: &SessionHandle,
        initial_prompt: Option<&str>,
    ) -> Result<(), SessionError> {
        let Some(initial_prompt) = initial_prompt.filter(|prompt| !prompt.is_empty()) else {
            return Ok(());
        };
        let mut values = handle_values(handle);
        let wait = self.templates.wait.render(&values, &[], None)?;
        self.checked_run(&wait)?;
        values.insert("message", initial_prompt.to_owned());
        let mut invocation = self.templates.message.render(&values, &[], None)?;
        invocation.args.extend([
            "--wait".to_owned(),
            "--timeout".to_owned(),
            "120000".to_owned(),
        ]);
        self.checked_run(&invocation)?;
        Ok(())
    }

    fn launch_impl(
        &self,
        request: &LaunchRequest,
        checkpoint: &mut dyn FnMut(&LaunchCheckpoint) -> Result<(), SessionError>,
    ) -> Result<SessionHandle, SessionError> {
        validate_agent_name(&request.session_name)?;
        if let Some(snapshot) = self.inspect(&request.session_name)? {
            if snapshot.status.is_present() {
                if let Some(expected_pane) = request.resume_token.as_deref() {
                    verify_snapshot_pane(&snapshot, expected_pane)?;
                } else {
                    let observed_pane =
                        snapshot.handle.resume_token.as_deref().ok_or_else(|| {
                            SessionError::InvalidOutput(format!(
                                "agent {:?} inspection omitted pane_id",
                                snapshot.handle.external_id
                            ))
                        })?;
                    validate_pane_id(observed_pane)?;
                    if !self.inspect_pane(observed_pane, Some(&request.working_directory))? {
                        return Err(SessionError::NotFound(format!(
                            "agent {:?} referenced missing pane {observed_pane:?}",
                            snapshot.handle.external_id
                        )));
                    }
                }
                self.deliver_initial_prompt(&snapshot.handle, request.initial_prompt.as_deref())?;
                return Ok(snapshot.handle);
            }
        }

        let mut values = launch_values(request);
        let pane_id = if let Some(resume_token) = request
            .resume_token
            .as_deref()
            .filter(|token| !token.is_empty())
        {
            resume_token.to_owned()
        } else {
            let create =
                self.templates
                    .create_tab
                    .render(&values, &[], Some(&request.working_directory))?;
            let create_output = self.checked_run(&create)?;
            let pane_id = root_pane_id(&create_output.stdout)?;
            checkpoint(&LaunchCheckpoint {
                resume_token: pane_id.clone(),
            })?;
            pane_id
        };
        values.insert("pane_id", pane_id.clone());

        let start = self.templates.start_agent.render(
            &values,
            &request.native_args,
            Some(&request.working_directory),
        )?;
        let mut handle = SessionHandle {
            backend: self.name().to_owned(),
            external_id: request.session_name.clone(),
            resume_token: Some(pane_id),
        };
        match self.checked_run(&start) {
            Ok(_) => {}
            Err(timeout @ SessionError::Timeout(_)) => {
                match self.inspect(&request.session_name)? {
                    Some(snapshot) if snapshot.status.is_present() => {
                        verify_snapshot_pane(
                            &snapshot,
                            handle.resume_token.as_deref().expect("pane set above"),
                        )?;
                        handle = snapshot.handle;
                    }
                    Some(_) => return Err(timeout),
                    None => match self.checked_run(&start) {
                        Ok(_) => {}
                        Err(retry_timeout @ SessionError::Timeout(_)) => {
                            match self.inspect(&request.session_name)? {
                                Some(snapshot) if snapshot.status.is_present() => {
                                    verify_snapshot_pane(
                                        &snapshot,
                                        handle.resume_token.as_deref().expect("pane set above"),
                                    )?;
                                    handle = snapshot.handle;
                                }
                                _ => return Err(retry_timeout),
                            }
                        }
                        Err(error) => return Err(error),
                    },
                }
            }
            Err(error) => return Err(error),
        }
        self.deliver_initial_prompt(&handle, request.initial_prompt.as_deref())?;
        Ok(handle)
    }

    /// Closes exactly the pane recorded in an AGSV durable session handle.
    ///
    /// An optional working directory adds a second ownership check when Herdr's
    /// pane inspection response exposes its current directory. A missing pane
    /// or a close racing with another stop is treated as idempotent success.
    pub fn stop_owned(
        &self,
        handle: &SessionHandle,
        expected_working_directory: Option<&Path>,
    ) -> Result<(), SessionError> {
        reject_foreign_handle(self.name(), handle)?;
        let pane_id = handle.resume_token.as_deref().ok_or_else(|| {
            SessionError::InvalidConfiguration(
                "Herdr stop requires the persisted AGSV pane checkpoint".to_owned(),
            )
        })?;
        validate_pane_id(pane_id)?;
        if !handle.external_id.is_empty() {
            validate_agent_target(&handle.external_id)?;
            if let Some(snapshot) = self.inspect(&handle.external_id)? {
                verify_snapshot_pane(&snapshot, pane_id)?;
            }
        }
        if !self.inspect_pane(pane_id, expected_working_directory)? {
            return Ok(());
        }
        let template = self
            .templates
            .stop
            .as_ref()
            .ok_or_else(|| SessionError::Unsupported {
                backend: self.name().to_owned(),
                operation: "stop",
            })?;
        let invocation = template.render(&handle_values(handle), &[], None)?;
        let output = self.runner.run(&invocation)?;
        if output.success() {
            return Ok(());
        }
        match classify_herdr_failure(output) {
            SessionError::NotFound(_) => Ok(()),
            error => Err(error),
        }
    }
}

impl SessionBackend for HerdrAdapter {
    fn name(&self) -> &'static str {
        "herdr"
    }

    fn launch(&self, request: &LaunchRequest) -> Result<SessionHandle, SessionError> {
        self.launch_impl(request, &mut |_| Ok(()))
    }

    fn launch_with_checkpoint(
        &self,
        request: &LaunchRequest,
        checkpoint: &mut dyn FnMut(&LaunchCheckpoint) -> Result<(), SessionError>,
    ) -> Result<SessionHandle, SessionError> {
        self.launch_impl(request, checkpoint)
    }

    fn resume(&self, request: &ResumeRequest) -> Result<SessionHandle, SessionError> {
        reject_foreign_handle(self.name(), &request.handle)?;
        validate_agent_name(&request.handle.external_id)?;
        if let Some(snapshot) = self.inspect(&request.handle.external_id)? {
            if snapshot.status.is_present() {
                return Ok(request.handle.clone());
            }
        }
        let template = self
            .templates
            .resume
            .as_ref()
            .ok_or_else(|| SessionError::Unsupported {
                backend: self.name().to_owned(),
                operation: "resume missing Herdr session",
            })?;
        let mut values = handle_values(&request.handle);
        values.insert("actor_id", request.actor_id.clone());
        values.insert(
            "cwd",
            request.working_directory.to_string_lossy().into_owned(),
        );
        values.insert("idempotency_key", request.idempotency_key.clone());
        let invocation = template.render(
            &values,
            &request.native_args,
            Some(&request.working_directory),
        )?;
        self.checked_run(&invocation)?;
        Ok(request.handle.clone())
    }

    fn status(&self, handle: &SessionHandle) -> Result<SessionSnapshot, SessionError> {
        reject_foreign_handle(self.name(), handle)?;
        validate_agent_target(&handle.external_id)?;
        let invocation = self
            .templates
            .status
            .render(&handle_values(handle), &[], None)?;
        let output = self.runner.run(&invocation)?;
        if !output.success() {
            return match classify_herdr_failure(output) {
                SessionError::NotFound(detail) => Ok(SessionSnapshot {
                    handle: handle.clone(),
                    status: SessionStatus::Missing,
                    detail: Some(detail),
                }),
                error => Err(error),
            };
        }
        snapshot_from_json(handle.clone(), &output.stdout)
    }

    fn send_message(&self, handle: &SessionHandle, message: &str) -> Result<(), SessionError> {
        reject_foreign_handle(self.name(), handle)?;
        validate_agent_target(&handle.external_id)?;
        let mut values = handle_values(handle);
        values.insert("message", message.to_owned());
        let invocation = self.templates.message.render(&values, &[], None)?;
        self.checked_run(&invocation)?;
        Ok(())
    }

    fn stop(&self, handle: &SessionHandle) -> Result<(), SessionError> {
        self.stop_owned(handle, None)
    }
}

fn validate_agent_name(name: &str) -> Result<(), SessionError> {
    let mut bytes = name.bytes();
    let valid_first = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
    let valid_rest = bytes.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
    });
    if valid_first && valid_rest && name.len() <= 32 {
        Ok(())
    } else {
        Err(SessionError::InvalidConfiguration(format!(
            "Herdr agent name {name:?} must match [a-z][a-z0-9_-]{{0,31}}"
        )))
    }
}

fn validate_agent_target(target: &str) -> Result<(), SessionError> {
    validate_agent_name(target).or_else(|_| validate_pane_id(target))
}

fn validate_pane_id(pane_id: &str) -> Result<(), SessionError> {
    let safe = !pane_id.is_empty()
        && pane_id.len() <= 256
        && !pane_id.starts_with('-')
        && pane_id.trim() == pane_id
        && pane_id.bytes().all(|byte| byte.is_ascii_graphic());
    if safe {
        Ok(())
    } else {
        Err(SessionError::InvalidConfiguration(format!(
            "refusing unsafe Herdr pane checkpoint {pane_id:?}"
        )))
    }
}

fn verify_snapshot_pane(
    snapshot: &SessionSnapshot,
    expected_pane: &str,
) -> Result<(), SessionError> {
    match snapshot.handle.resume_token.as_deref() {
        Some(observed) if observed == expected_pane => Ok(()),
        Some(observed) => Err(SessionError::InvalidConfiguration(format!(
            "refusing Herdr operation: agent {:?} is in pane {observed:?}, not AGSV-owned pane {expected_pane:?}",
            snapshot.handle.external_id
        ))),
        None => Err(SessionError::InvalidOutput(format!(
            "agent {:?} inspection omitted pane_id",
            snapshot.handle.external_id
        ))),
    }
}

fn pane_working_directory(value: &Value) -> Option<&str> {
    [
        "/result/pane/cwd",
        "/result/pane/current_directory",
        "/result/cwd",
        "/result/current_directory",
    ]
    .into_iter()
    .find_map(|pointer| value.pointer(pointer).and_then(Value::as_str))
}

fn classify_herdr_failure(output: CommandOutput) -> SessionError {
    let parsed = serde_json::from_str::<Value>(&output.stderr).ok();
    let code = parsed
        .as_ref()
        .and_then(|value| find_string(value, &["code", "error_code"]))
        .map(str::to_owned);
    if let Some(code) = code {
        let normalized = code.to_ascii_lowercase();
        let detail = if output.stderr.trim().is_empty() {
            parsed
                .as_ref()
                .and_then(|value| find_string(value, &["message", "error_message"]))
                .unwrap_or(&code)
                .to_owned()
        } else {
            output.stderr.trim().to_owned()
        };
        if normalized == "not_found" || normalized.ends_with("_not_found") {
            return SessionError::NotFound(detail);
        }
        if normalized.contains("permission")
            || normalized.contains("forbidden")
            || normalized.contains("denied")
        {
            return SessionError::PermissionDenied(detail);
        }
        if normalized.contains("invalid") || normalized.contains("config") {
            return SessionError::InvalidConfiguration(detail);
        }
        if normalized.contains("timeout") {
            return SessionError::Timeout(detail);
        }
        if normalized.contains("unavailable") || normalized.contains("connection") {
            return SessionError::Unavailable(detail);
        }
    }
    SessionError::CommandFailed {
        status: output.status_code,
        stderr: output.stderr,
    }
}

fn root_pane_id(json: &str) -> Result<String, SessionError> {
    let value: Value = serde_json::from_str(json)
        .map_err(|error| SessionError::InvalidOutput(error.to_string()))?;
    value
        .pointer("/result/root_pane/pane_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| SessionError::InvalidOutput("missing result.root_pane.pane_id".to_owned()))
}

fn snapshot_from_json(
    mut handle: SessionHandle,
    json: &str,
) -> Result<SessionSnapshot, SessionError> {
    let value: Value = serde_json::from_str(json)
        .map_err(|error| SessionError::InvalidOutput(error.to_string()))?;
    if let Some(pane_id) = find_string(&value, &["pane_id"]) {
        handle.resume_token = Some(pane_id.to_owned());
    }
    let raw_status = find_string(&value, &["agent_status", "status", "state"])
        .unwrap_or("unknown")
        .to_ascii_lowercase();
    let status = match raw_status.as_str() {
        "starting" => SessionStatus::Starting,
        "working" | "running" => SessionStatus::Working,
        "idle" | "done" => SessionStatus::Idle,
        "blocked" => SessionStatus::Blocked,
        "stopped" | "exited" => SessionStatus::Stopped { exit_code: None },
        "missing" => SessionStatus::Missing,
        _ => SessionStatus::Unknown(raw_status),
    };
    Ok(SessionSnapshot {
        handle,
        status,
        detail: None,
    })
}

fn find_string<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| find_key_string(value, key))
}

fn find_key_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    match value {
        Value::Object(map) => {
            if let Some(found) = map.get(key).and_then(Value::as_str) {
                return Some(found);
            }
            map.values().find_map(|child| find_key_string(child, key))
        }
        Value::Array(values) => values.iter().find_map(|child| find_key_string(child, key)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use super::*;
    use crate::CommandInvocation;

    struct RecordingRunner {
        invocations: Mutex<Vec<CommandInvocation>>,
        outputs: Mutex<VecDeque<CommandOutput>>,
    }

    impl RecordingRunner {
        fn new(outputs: impl IntoIterator<Item = CommandOutput>) -> Self {
            Self {
                invocations: Mutex::new(Vec::new()),
                outputs: Mutex::new(outputs.into_iter().collect()),
            }
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, invocation: &CommandInvocation) -> Result<CommandOutput, SessionError> {
            self.invocations.lock().unwrap().push(invocation.clone());
            self.outputs
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| SessionError::Unavailable("no recorded output".into()))
        }
    }

    fn output(status_code: i32, stdout: &str) -> CommandOutput {
        CommandOutput {
            status_code: Some(status_code),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn error_output(status_code: i32, code: &str) -> CommandOutput {
        CommandOutput {
            status_code: Some(status_code),
            stdout: String::new(),
            stderr: format!(r#"{{"error":{{"code":"{code}"}}}}"#),
        }
    }

    fn detailed_error_output(status_code: i32, code: &str, message: &str) -> CommandOutput {
        CommandOutput {
            status_code: Some(status_code),
            stdout: String::new(),
            stderr: format!(r#"{{"error":{{"code":"{code}","message":"{message}"}}}}"#),
        }
    }

    #[test]
    fn launch_builds_verified_herdr_argv_and_parses_tolerant_json() {
        let runner = Arc::new(RecordingRunner::new([
            error_output(1, "agent_not_found"),
            output(
                0,
                r#"{"id":"1","result":{"type":"tab_create","root_pane":{"pane_id":"w1:p9","extra":true}}}"#,
            ),
            output(0, r#"{"result":{"type":"agent_start"}}"#),
            output(0, r#"{"result":{"type":"agent_wait"}}"#),
            output(0, r#"{"result":{"type":"agent_prompt"}}"#),
        ]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        let request = LaunchRequest {
            actor_id: "implementation-1".into(),
            session_name: "team-one".into(),
            runtime: "codex".into(),
            working_directory: PathBuf::from("/repo/team one"),
            idempotency_key: "launch-team-one".into(),
            native_args: vec!["--model".into(), "example".into()],
            initial_prompt: Some("Implement this safely.\nRun every test.".into()),
            resume_token: None,
        };

        let handle = backend.launch(&request).unwrap();
        assert_eq!(handle.external_id, "team-one");
        assert_eq!(handle.resume_token.as_deref(), Some("w1:p9"));
        let invocations = runner.invocations.lock().unwrap();
        assert_eq!(
            invocations[1].args,
            [
                "tab",
                "create",
                "--cwd",
                "/repo/team one",
                "--label",
                "team-one",
                "--no-focus",
            ]
        );
        assert_eq!(
            invocations[2].args,
            [
                "agent", "start", "team-one", "--kind", "codex", "--pane", "w1:p9", "--",
                "--model", "example",
            ]
        );
        assert_eq!(
            invocations[3].args,
            ["agent", "wait", "team-one", "--timeout", "120000"]
        );
        assert_eq!(
            invocations[4].args,
            [
                "agent",
                "prompt",
                "team-one",
                "Implement this safely.\nRun every test.",
                "--wait",
                "--timeout",
                "120000"
            ]
        );
    }

    #[test]
    fn short_start_timeout_retries_once_then_delivers_prompt() {
        let timeout = detailed_error_output(1, "timeout", "timed out waiting for agent startup");
        let runner = Arc::new(RecordingRunner::new([
            error_output(1, "agent_not_found"),
            output(0, r#"{"result":{"root_pane":{"pane_id":"w6:p4"}}}"#),
            timeout,
            error_output(1, "agent_not_found"),
            output(0, r#"{"result":{"type":"agent_start"}}"#),
            output(0, r#"{"result":{"type":"agent_wait"}}"#),
            output(0, r#"{"result":{"type":"agent_prompt"}}"#),
        ]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        let request = LaunchRequest {
            actor_id: "implementation-1".into(),
            session_name: "retry-worker".into(),
            runtime: "codex".into(),
            working_directory: PathBuf::from("/repo"),
            idempotency_key: "retry-launch".into(),
            native_args: vec!["--model".into(), "gpt-test".into()],
            initial_prompt: Some("large\nmultiline\nprompt".into()),
            resume_token: None,
        };

        let handle = backend.launch(&request).unwrap();
        assert_eq!(handle.resume_token.as_deref(), Some("w6:p4"));
        let invocations = runner.invocations.lock().unwrap();
        assert_eq!(invocations[2], invocations[4]);
        assert_eq!(
            invocations[2].args,
            [
                "agent",
                "start",
                "retry-worker",
                "--kind",
                "codex",
                "--pane",
                "w6:p4",
                "--",
                "--model",
                "gpt-test"
            ]
        );
        assert_eq!(
            invocations[5].args,
            ["agent", "wait", "retry-worker", "--timeout", "120000"]
        );
        assert_eq!(
            invocations[6].args,
            [
                "agent",
                "prompt",
                "retry-worker",
                "large\nmultiline\nprompt",
                "--wait",
                "--timeout",
                "120000"
            ]
        );
    }

    #[test]
    fn incomplete_launch_redelivers_prompt_to_matching_present_session() {
        let runner = Arc::new(RecordingRunner::new([
            output(
                0,
                r#"{"result":{"agent":{"status":"idle","pane_id":"w6:p4"}}}"#,
            ),
            output(0, r#"{"result":{"type":"agent_wait"}}"#),
            output(0, r#"{"result":{"type":"agent_prompt"}}"#),
        ]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        let request = LaunchRequest {
            actor_id: "implementation-1".into(),
            session_name: "recover-worker".into(),
            runtime: "codex".into(),
            working_directory: PathBuf::from("/repo"),
            idempotency_key: "recover-launch".into(),
            native_args: vec!["--model".into(), "gpt-test".into()],
            initial_prompt: Some("deliver me again".into()),
            resume_token: Some("w6:p4".into()),
        };

        let handle = backend.launch(&request).unwrap();
        assert_eq!(handle.resume_token.as_deref(), Some("w6:p4"));
        let invocations = runner.invocations.lock().unwrap();
        assert_eq!(invocations.len(), 3);
        assert_eq!(
            invocations[1].args,
            ["agent", "wait", "recover-worker", "--timeout", "120000"]
        );
        assert_eq!(
            invocations[2].args,
            [
                "agent",
                "prompt",
                "recover-worker",
                "deliver me again",
                "--wait",
                "--timeout",
                "120000"
            ]
        );
    }

    #[test]
    fn fresh_launch_refuses_same_name_agent_from_another_working_directory() {
        let runner = Arc::new(RecordingRunner::new([
            output(
                0,
                r#"{"result":{"agent":{"status":"idle","pane_id":"w7:p1"}}}"#,
            ),
            output(
                0,
                r#"{"result":{"pane":{"pane_id":"w7:p1","cwd":"/other/repository"}}}"#,
            ),
        ]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        let request = LaunchRequest {
            actor_id: "implementation-1".into(),
            session_name: "workspace-worker".into(),
            runtime: "codex".into(),
            working_directory: PathBuf::from("/expected/repository"),
            idempotency_key: "fresh-launch".into(),
            native_args: vec!["--model".into(), "gpt-test".into()],
            initial_prompt: Some("must not reach the foreign agent".into()),
            resume_token: None,
        };

        let error = backend.launch(&request).unwrap_err();
        assert!(matches!(error, SessionError::InvalidConfiguration(_)));
        let invocations = runner.invocations.lock().unwrap();
        assert_eq!(invocations.len(), 2);
        assert_eq!(invocations[1].args, ["pane", "get", "w7:p1"]);
    }

    #[test]
    fn timeout_classification_preserves_backend_detail() {
        let error = classify_herdr_failure(detailed_error_output(
            1,
            "timeout",
            "timed out waiting for agent startup",
        ));
        let SessionError::Timeout(detail) = error else {
            panic!("expected timeout classification");
        };
        assert!(detail.contains("timed out waiting for agent startup"));
        assert!(detail.contains("timeout"));
    }

    #[test]
    fn stop_closes_only_the_verified_owned_pane() {
        let runner = Arc::new(RecordingRunner::new([
            output(
                0,
                r#"{"result":{"agent":{"status":"idle","pane_id":"w1:p9"}}}"#,
            ),
            output(
                0,
                r#"{"result":{"pane":{"pane_id":"w1:p9","cwd":"/repo"}}}"#,
            ),
            output(0, r#"{"result":{"type":"pane_close"}}"#),
        ]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        let handle = SessionHandle {
            backend: "herdr".into(),
            external_id: "worker".into(),
            resume_token: Some("w1:p9".into()),
        };

        backend
            .stop_owned(&handle, Some(Path::new("/repo")))
            .unwrap();

        let invocations = runner.invocations.lock().unwrap();
        assert_eq!(invocations.len(), 3);
        assert_eq!(invocations[0].args, ["agent", "get", "worker"]);
        assert_eq!(invocations[1].args, ["pane", "get", "w1:p9"]);
        assert_eq!(invocations[2].args, ["pane", "close", "w1:p9"]);
    }

    #[test]
    fn stop_can_clean_checkpoint_when_launch_never_returned_external_id() {
        let runner = Arc::new(RecordingRunner::new([
            output(
                0,
                r#"{"result":{"pane":{"pane_id":"w6:p4","cwd":"/repo"}}}"#,
            ),
            output(0, r#"{"result":{"type":"pane_close"}}"#),
        ]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        let handle = SessionHandle {
            backend: "herdr".into(),
            external_id: String::new(),
            resume_token: Some("w6:p4".into()),
        };

        backend
            .stop_owned(&handle, Some(Path::new("/repo")))
            .unwrap();

        let invocations = runner.invocations.lock().unwrap();
        assert_eq!(invocations.len(), 2);
        assert_eq!(invocations[0].args, ["pane", "get", "w6:p4"]);
        assert_eq!(invocations[1].args, ["pane", "close", "w6:p4"]);
    }

    #[test]
    fn stop_rejects_agent_or_directory_that_does_not_own_checkpoint() {
        let agent_runner = Arc::new(RecordingRunner::new([output(
            0,
            r#"{"result":{"agent":{"status":"idle","pane_id":"w1:p8"}}}"#,
        )]));
        let backend = HerdrAdapter::verified_v0_8(agent_runner.clone());
        let handle = SessionHandle {
            backend: "herdr".into(),
            external_id: "worker".into(),
            resume_token: Some("w1:p9".into()),
        };
        assert!(matches!(
            backend.stop_owned(&handle, Some(Path::new("/repo"))),
            Err(SessionError::InvalidConfiguration(_))
        ));
        assert_eq!(agent_runner.invocations.lock().unwrap().len(), 1);

        let directory_runner = Arc::new(RecordingRunner::new([output(
            0,
            r#"{"result":{"pane":{"pane_id":"w1:p9","cwd":"/users/home"}}}"#,
        )]));
        let backend = HerdrAdapter::verified_v0_8(directory_runner.clone());
        let checkpoint_only = SessionHandle {
            external_id: String::new(),
            ..handle
        };
        assert!(matches!(
            backend.stop_owned(&checkpoint_only, Some(Path::new("/repo"))),
            Err(SessionError::InvalidConfiguration(_))
        ));
        assert_eq!(directory_runner.invocations.lock().unwrap().len(), 1);
    }

    #[test]
    fn stop_is_idempotent_when_owned_pane_is_already_missing() {
        let runner = Arc::new(RecordingRunner::new([error_output(1, "pane_not_found")]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        let handle = SessionHandle {
            backend: "herdr".into(),
            external_id: String::new(),
            resume_token: Some("w1:p9".into()),
        };

        backend.stop_owned(&handle, None).unwrap();

        let invocations = runner.invocations.lock().unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].args, ["pane", "get", "w1:p9"]);
    }

    #[test]
    fn stop_is_idempotent_when_pane_disappears_during_close() {
        let runner = Arc::new(RecordingRunner::new([
            output(0, r#"{"result":{"pane":{"pane_id":"w1:p9"}}}"#),
            error_output(1, "pane_not_found"),
        ]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        let handle = SessionHandle {
            backend: "herdr".into(),
            external_id: String::new(),
            resume_token: Some("w1:p9".into()),
        };

        backend.stop_owned(&handle, None).unwrap();

        let invocations = runner.invocations.lock().unwrap();
        assert_eq!(invocations.len(), 2);
        assert_eq!(invocations[1].args, ["pane", "close", "w1:p9"]);
    }

    #[test]
    fn stop_rejects_foreign_or_unsafe_checkpoint_before_invocation() {
        let runner = Arc::new(RecordingRunner::new([]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        for handle in [
            SessionHandle {
                backend: "other".into(),
                external_id: String::new(),
                resume_token: Some("w1:p9".into()),
            },
            SessionHandle {
                backend: "herdr".into(),
                external_id: String::new(),
                resume_token: Some("--all".into()),
            },
            SessionHandle {
                backend: "herdr".into(),
                external_id: String::new(),
                resume_token: None,
            },
        ] {
            assert!(backend.stop_owned(&handle, None).is_err());
        }
        assert!(runner.invocations.lock().unwrap().is_empty());
    }

    #[test]
    fn status_accepts_nested_pane_shape() {
        let runner = Arc::new(RecordingRunner::new([output(
            0,
            r#"{"status":"ok","result":{"pane":{"agent_status":"blocked","pane_id":"w2:p3"},"type":"pane_current"}}"#,
        )]));
        let backend = HerdrAdapter::verified_v0_8(runner);
        let snapshot = backend
            .status(&SessionHandle {
                backend: "herdr".into(),
                external_id: "worker".into(),
                resume_token: None,
            })
            .unwrap();

        assert_eq!(snapshot.status, SessionStatus::Blocked);
        assert_eq!(snapshot.handle.resume_token.as_deref(), Some("w2:p3"));
    }

    #[test]
    fn message_can_wake_an_unnamed_agent_by_bound_pane_id() {
        let runner = Arc::new(RecordingRunner::new([output(
            0,
            r#"{"result":{"type":"agent_prompt"}}"#,
        )]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        let handle = SessionHandle {
            backend: "herdr".into(),
            external_id: "w6:p1".into(),
            resume_token: Some("w6:p1".into()),
        };

        backend
            .send_message(&handle, "A durable AGSV message is waiting.")
            .unwrap();

        let invocations = runner.invocations.lock().unwrap();
        assert_eq!(
            invocations[0].args,
            [
                "agent",
                "prompt",
                "w6:p1",
                "A durable AGSV message is waiting.",
            ]
        );
    }

    #[test]
    fn bound_pane_wake_failure_is_returned_to_the_control_plane() {
        let runner = Arc::new(RecordingRunner::new([detailed_error_output(
            1,
            "agent_prompt_stalled",
            "target agent did not start a turn",
        )]));
        let backend = HerdrAdapter::verified_v0_8(runner);
        let handle = SessionHandle {
            backend: "herdr".into(),
            external_id: "w6:p1".into(),
            resume_token: Some("w6:p1".into()),
        };

        let error = backend
            .send_message(&handle, "A durable AGSV message is waiting.")
            .unwrap_err();

        let SessionError::CommandFailed { stderr, .. } = error else {
            panic!("expected the backend wake failure to be preserved");
        };
        assert!(stderr.contains("agent_prompt_stalled"));
        assert!(stderr.contains("target agent did not start a turn"));
    }

    #[test]
    fn existing_healthy_agent_is_not_duplicated() {
        let runner = Arc::new(RecordingRunner::new([
            output(
                0,
                r#"{"result":{"agent":{"status":"idle","pane_id":"w1:p2"}}}"#,
            ),
            output(
                0,
                r#"{"result":{"pane":{"pane_id":"w1:p2","cwd":"/repo"}}}"#,
            ),
        ]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        let request = LaunchRequest {
            actor_id: "a".into(),
            session_name: "existing".into(),
            runtime: "codex".into(),
            working_directory: PathBuf::from("/repo"),
            idempotency_key: "key".into(),
            native_args: Vec::new(),
            initial_prompt: None,
            resume_token: None,
        };

        let handle = backend.launch(&request).unwrap();
        assert_eq!(handle.external_id, "existing");
        assert_eq!(runner.invocations.lock().unwrap().len(), 2);
    }

    #[test]
    fn invalid_agent_name_is_rejected_before_tab_creation() {
        let runner = Arc::new(RecordingRunner::new([]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        let request = LaunchRequest {
            actor_id: "a".into(),
            session_name: "Invalid Name".into(),
            runtime: "codex".into(),
            working_directory: PathBuf::from("/repo"),
            idempotency_key: "key".into(),
            native_args: Vec::new(),
            initial_prompt: None,
            resume_token: None,
        };

        assert!(matches!(
            backend.launch(&request),
            Err(SessionError::InvalidConfiguration(_))
        ));
        assert!(runner.invocations.lock().unwrap().is_empty());
    }

    #[test]
    fn permission_failure_is_not_reported_as_missing() {
        let runner = Arc::new(RecordingRunner::new([error_output(1, "permission_denied")]));
        let backend = HerdrAdapter::verified_v0_8(runner);
        let error = backend
            .status(&SessionHandle {
                backend: "herdr".into(),
                external_id: "worker".into(),
                resume_token: None,
            })
            .unwrap_err();

        assert!(matches!(error, SessionError::PermissionDenied(_)));
    }

    #[test]
    fn pane_checkpoint_is_emitted_before_agent_start() {
        let runner = Arc::new(RecordingRunner::new([
            error_output(1, "agent_not_found"),
            output(0, r#"{"result":{"root_pane":{"pane_id":"w1:p4"}}}"#),
            output(0, r#"{"result":{"type":"agent_start"}}"#),
        ]));
        let backend = HerdrAdapter::verified_v0_8(runner);
        let request = LaunchRequest {
            actor_id: "actor".into(),
            session_name: "worker".into(),
            runtime: "codex".into(),
            working_directory: PathBuf::from("/repo"),
            idempotency_key: "launch".into(),
            native_args: Vec::new(),
            initial_prompt: None,
            resume_token: None,
        };
        let mut checkpoints = Vec::new();

        backend
            .launch_with_checkpoint(&request, &mut |checkpoint| {
                checkpoints.push(checkpoint.clone());
                Ok(())
            })
            .unwrap();

        assert_eq!(
            checkpoints,
            [LaunchCheckpoint {
                resume_token: "w1:p4".into()
            }]
        );
    }
}
