use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use crate::{
    LaunchRequest, ResumeRequest, SessionBackend, SessionError, SessionHandle, SessionSnapshot,
    SessionStatus,
};

/// A shell-free process invocation produced by a command template.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub current_directory: Option<PathBuf>,
}

/// Captured process output. Non-zero status is represented, not converted to I/O failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    #[must_use]
    pub const fn success(&self) -> bool {
        matches!(self.status_code, Some(0))
    }
}

/// Injectable process execution boundary.
pub trait CommandRunner: Send + Sync {
    fn run(&self, invocation: &CommandInvocation) -> Result<CommandOutput, SessionError>;
}

/// Production runner. It never invokes a shell.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, invocation: &CommandInvocation) -> Result<CommandOutput, SessionError> {
        let mut command = Command::new(&invocation.program);
        command.args(&invocation.args);
        if let Some(directory) = &invocation.current_directory {
            command.current_dir(directory);
        }
        let output = command
            .output()
            .map_err(|error| SessionError::Unavailable(error.to_string()))?;
        Ok(CommandOutput {
            status_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// A configurable argv template.
///
/// `{native_args}` must occupy a whole argument. The optional-argument form
/// `{native_args_with_separator}` inserts `--` only when native arguments exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandTemplate {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandTemplate {
    #[must_use]
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub(crate) fn render(
        &self,
        values: &BTreeMap<&str, String>,
        native_args: &[String],
        current_directory: Option<&Path>,
    ) -> Result<CommandInvocation, SessionError> {
        if self.program.trim().is_empty() {
            return Err(SessionError::InvalidTemplate(
                "program cannot be empty".to_owned(),
            ));
        }
        let program = render_scalar(&self.program, values)?;
        let mut args = Vec::new();
        for template in &self.args {
            if template == "{native_args}" {
                args.extend(native_args.iter().cloned());
            } else if template == "{native_args_with_separator}" {
                if !native_args.is_empty() {
                    args.push("--".to_owned());
                    args.extend(native_args.iter().cloned());
                }
            } else {
                args.push(render_scalar(template, values)?);
            }
        }
        Ok(CommandInvocation {
            program,
            args,
            current_directory: current_directory.map(Path::to_path_buf),
        })
    }
}

fn render_scalar(template: &str, values: &BTreeMap<&str, String>) -> Result<String, SessionError> {
    let mut rendered = template.to_owned();
    for (key, value) in values {
        rendered = rendered.replace(&format!("{{{key}}}"), value);
    }
    if rendered.contains('{') || rendered.contains('}') {
        return Err(SessionError::InvalidTemplate(format!(
            "unresolved placeholder in {template:?}"
        )));
    }
    Ok(rendered)
}

/// Command templates for direct process adapters such as Claude Code or Codex.
#[derive(Clone, Debug)]
pub struct ProcessTemplates {
    pub launch: CommandTemplate,
    pub resume: CommandTemplate,
    pub status: CommandTemplate,
    pub message: CommandTemplate,
    pub stop: Option<CommandTemplate>,
    pub status_words: BTreeMap<String, SessionStatus>,
}

/// A direct process adapter whose provider-specific syntax is supplied by configuration.
pub struct ConfiguredProcessBackend {
    name: String,
    templates: ProcessTemplates,
    runner: Arc<dyn CommandRunner>,
}

impl ConfiguredProcessBackend {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        templates: ProcessTemplates,
        runner: Arc<dyn CommandRunner>,
    ) -> Self {
        Self {
            name: name.into(),
            templates,
            runner,
        }
    }

    /// Convenience constructor for externally verified Claude Code templates.
    #[must_use]
    pub fn claude_code(templates: ProcessTemplates, runner: Arc<dyn CommandRunner>) -> Self {
        Self::new("claude-code", templates, runner)
    }

    /// Convenience constructor for externally verified Codex templates.
    #[must_use]
    pub fn codex(templates: ProcessTemplates, runner: Arc<dyn CommandRunner>) -> Self {
        Self::new("codex", templates, runner)
    }

    fn checked_run(&self, invocation: &CommandInvocation) -> Result<CommandOutput, SessionError> {
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
}

impl SessionBackend for ConfiguredProcessBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn launch(&self, request: &LaunchRequest) -> Result<SessionHandle, SessionError> {
        let values = launch_values(request);
        let invocation = self.templates.launch.render(
            &values,
            &request.native_args,
            Some(&request.working_directory),
        )?;
        let output = self.checked_run(&invocation)?;
        let external_id = output
            .stdout
            .lines()
            .find(|line| !line.trim().is_empty())
            .map(str::trim)
            .ok_or_else(|| {
                SessionError::InvalidOutput("launch did not return a session id".to_owned())
            })?;
        Ok(SessionHandle {
            backend: self.name.clone(),
            external_id: external_id.to_owned(),
            resume_token: output
                .stdout
                .lines()
                .nth(1)
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_owned),
        })
    }

    fn resume(&self, request: &ResumeRequest) -> Result<SessionHandle, SessionError> {
        let values = resume_values(request);
        let invocation = self.templates.resume.render(
            &values,
            &request.native_args,
            Some(&request.working_directory),
        )?;
        self.checked_run(&invocation)?;
        Ok(request.handle.clone())
    }

    fn status(&self, handle: &SessionHandle) -> Result<SessionSnapshot, SessionError> {
        let values = handle_values(handle);
        let invocation = self.templates.status.render(&values, &[], None)?;
        let output = self.runner.run(&invocation)?;
        let status = if output.success() {
            let word = output.stdout.trim().to_ascii_lowercase();
            self.templates
                .status_words
                .get(&word)
                .cloned()
                .unwrap_or(SessionStatus::Unknown(word))
        } else {
            SessionStatus::Missing
        };
        Ok(SessionSnapshot {
            handle: handle.clone(),
            status,
            detail: (!output.stderr.trim().is_empty()).then(|| output.stderr.trim().to_owned()),
        })
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
                backend: self.name.clone(),
                operation: "stop",
            })?;
        let invocation = template.render(&handle_values(handle), &[], None)?;
        self.checked_run(&invocation)?;
        Ok(())
    }
}

pub(crate) fn launch_values(request: &LaunchRequest) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("actor_id", request.actor_id.clone()),
        ("session_name", request.session_name.clone()),
        ("runtime", request.runtime.clone()),
        (
            "cwd",
            request.working_directory.to_string_lossy().into_owned(),
        ),
        ("idempotency_key", request.idempotency_key.clone()),
    ])
}

fn resume_values(request: &ResumeRequest) -> BTreeMap<&'static str, String> {
    let mut values = handle_values(&request.handle);
    values.insert("actor_id", request.actor_id.clone());
    values.insert(
        "cwd",
        request.working_directory.to_string_lossy().into_owned(),
    );
    values.insert("idempotency_key", request.idempotency_key.clone());
    values
}

pub(crate) fn handle_values(handle: &SessionHandle) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("session_id", handle.external_id.clone()),
        (
            "resume_token",
            handle.resume_token.clone().unwrap_or_default(),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_renders_argv_without_a_shell() {
        let template = CommandTemplate::new(
            "agent-bin",
            [
                "start",
                "--name",
                "{session_name}",
                "--cwd={cwd}",
                "--",
                "{native_args}",
            ],
        );
        let request = LaunchRequest {
            actor_id: "a1".into(),
            session_name: "team-one".into(),
            runtime: "codex".into(),
            working_directory: PathBuf::from("/tmp/path with spaces"),
            idempotency_key: "key-1".into(),
            native_args: vec!["--model".into(), "example model".into()],
        };

        let invocation = template
            .render(
                &launch_values(&request),
                &request.native_args,
                Some(&request.working_directory),
            )
            .unwrap();

        assert_eq!(invocation.program, "agent-bin");
        assert_eq!(
            invocation.args,
            [
                "start",
                "--name",
                "team-one",
                "--cwd=/tmp/path with spaces",
                "--",
                "--model",
                "example model",
            ]
        );
        assert_eq!(
            invocation.current_directory,
            Some(PathBuf::from("/tmp/path with spaces"))
        );
    }

    #[test]
    fn unknown_placeholder_is_rejected() {
        let template = CommandTemplate::new("tool", ["{not_known}"]);
        let error = template.render(&BTreeMap::new(), &[], None).unwrap_err();
        assert!(matches!(error, SessionError::InvalidTemplate(_)));
    }
}
