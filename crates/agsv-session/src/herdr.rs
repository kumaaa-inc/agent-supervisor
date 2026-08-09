use std::sync::Arc;

use serde_json::Value;

use crate::process::{handle_values, launch_values};
use crate::{
    CommandOutput, CommandRunner, CommandTemplate, LaunchRequest, ResumeRequest, SessionBackend,
    SessionError, SessionHandle, SessionSnapshot, SessionStatus,
};

/// Replaceable Herdr commands. Defaults cover only syntax verified against Herdr 0.8.0.
#[derive(Clone, Debug)]
pub struct HerdrTemplates {
    pub inspect: CommandTemplate,
    pub create_tab: CommandTemplate,
    pub start_agent: CommandTemplate,
    pub resume: Option<CommandTemplate>,
    pub status: CommandTemplate,
    pub message: CommandTemplate,
    pub stop: Option<CommandTemplate>,
}

impl Default for HerdrTemplates {
    fn default() -> Self {
        Self {
            inspect: CommandTemplate::new("herdr", ["agent", "get", "{session_id}"]),
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
            message: CommandTemplate::new(
                "herdr",
                ["agent", "prompt", "{session_id}", "{message}"],
            ),
            stop: None,
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
            Err(SessionError::CommandFailed {
                status: output.status_code,
                stderr: output.stderr,
            })
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
            return Ok(None);
        }
        Ok(Some(snapshot_from_json(handle, &output.stdout)?))
    }
}

impl SessionBackend for HerdrAdapter {
    fn name(&self) -> &'static str {
        "herdr"
    }

    fn launch(&self, request: &LaunchRequest) -> Result<SessionHandle, SessionError> {
        if let Some(snapshot) = self.inspect(&request.session_name)? {
            if snapshot.status.is_present() {
                return Ok(snapshot.handle);
            }
        }

        let mut values = launch_values(request);
        let create =
            self.templates
                .create_tab
                .render(&values, &[], Some(&request.working_directory))?;
        let create_output = self.checked_run(&create)?;
        let pane_id = root_pane_id(&create_output.stdout)?;
        values.insert("pane_id", pane_id.clone());

        let start = self.templates.start_agent.render(
            &values,
            &request.native_args,
            Some(&request.working_directory),
        )?;
        self.checked_run(&start)?;
        Ok(SessionHandle {
            backend: self.name().to_owned(),
            external_id: request.session_name.clone(),
            resume_token: Some(pane_id),
        })
    }

    fn resume(&self, request: &ResumeRequest) -> Result<SessionHandle, SessionError> {
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
        let invocation = self
            .templates
            .status
            .render(&handle_values(handle), &[], None)?;
        let output = self.runner.run(&invocation)?;
        if !output.success() {
            return Ok(SessionSnapshot {
                handle: handle.clone(),
                status: SessionStatus::Missing,
                detail: (!output.stderr.trim().is_empty()).then(|| output.stderr.trim().to_owned()),
            });
        }
        snapshot_from_json(handle.clone(), &output.stdout)
    }

    fn send_message(&self, handle: &SessionHandle, message: &str) -> Result<(), SessionError> {
        let mut values = handle_values(handle);
        values.insert("message", message.to_owned());
        let invocation = self.templates.message.render(&values, &[], None)?;
        self.checked_run(&invocation)?;
        Ok(())
    }

    fn stop(&self, handle: &SessionHandle) -> Result<(), SessionError> {
        let template = self
            .templates
            .stop
            .as_ref()
            .ok_or_else(|| SessionError::Unsupported {
                backend: self.name().to_owned(),
                operation: "stop",
            })?;
        let invocation = template.render(&handle_values(handle), &[], None)?;
        self.checked_run(&invocation)?;
        Ok(())
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

    #[test]
    fn launch_builds_verified_herdr_argv_and_parses_tolerant_json() {
        let runner = Arc::new(RecordingRunner::new([
            output(1, ""),
            output(
                0,
                r#"{"id":"1","result":{"type":"tab_create","root_pane":{"pane_id":"w1:p9","extra":true}}}"#,
            ),
            output(0, r#"{"result":{"type":"agent_start"}}"#),
        ]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        let request = LaunchRequest {
            actor_id: "implementation-1".into(),
            session_name: "team-one".into(),
            runtime: "codex".into(),
            working_directory: PathBuf::from("/repo/team one"),
            idempotency_key: "launch-team-one".into(),
            native_args: vec!["--model".into(), "example".into()],
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
    fn existing_healthy_agent_is_not_duplicated() {
        let runner = Arc::new(RecordingRunner::new([output(
            0,
            r#"{"result":{"agent":{"status":"idle","pane_id":"w1:p2"}}}"#,
        )]));
        let backend = HerdrAdapter::verified_v0_8(runner.clone());
        let request = LaunchRequest {
            actor_id: "a".into(),
            session_name: "existing".into(),
            runtime: "codex".into(),
            working_directory: PathBuf::from("/repo"),
            idempotency_key: "key".into(),
            native_args: Vec::new(),
        };

        let handle = backend.launch(&request).unwrap();
        assert_eq!(handle.external_id, "existing");
        assert_eq!(runner.invocations.lock().unwrap().len(), 1);
    }
}
