use std::process::Command;

use crate::{
    AdapterError, AgentRuntime, CapabilitySupport, InitialPromptDelivery, RuntimeCapabilities,
    RuntimeConfig, RuntimeDiagnostics, RuntimeId, RuntimeInvocation, RuntimeLaunchPolicy,
    RuntimeLaunchRequest, RuntimeResumeRequest,
};

const PI_RUNTIME_ID: &str = "pi";

// Pi does not start an agent turn from appended system instructions alone. The
// role text therefore stays exclusively at system level while this distinct
// user turn triggers the managed-session bootstrap after the pane is ready.
const PI_BOOTSTRAP_PROMPT: &str =
    "Begin the managed launch setup now. Follow the system instructions exactly.";

/// Adapter for the Pi coding-agent runtime.
///
/// Pi accepts provider-qualified model patterns, but its reasoning setting is
/// a suffix on that pattern rather than a separate configuration flag. This
/// adapter also deliberately elevates AGSV's generated role instructions with
/// `--append-system-prompt`: durable protocol rules must not look like ordinary
/// user work that a later message could supersede. A short, separate user turn
/// is still delivered after session readiness so interactive Pi actually
/// begins the launch bootstrap.
#[derive(Clone, Debug)]
pub struct PiAdapter {
    runtime_id: RuntimeId,
    program: String,
}

impl PiAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self::with_program(PI_RUNTIME_ID)
    }

    /// Creates an adapter that invokes a custom executable name or path.
    ///
    /// # Panics
    ///
    /// Panics only if the crate's built-in `pi` runtime identifier is invalid.
    #[must_use]
    pub fn with_program(program: impl Into<String>) -> Self {
        Self {
            runtime_id: RuntimeId::new(PI_RUNTIME_ID)
                .expect("the built-in Pi runtime identifier must be valid"),
            program: program.into(),
        }
    }

    fn configured_arguments(&self, config: &RuntimeConfig) -> Result<Vec<String>, AdapterError> {
        let configured_model = required_model(self.id(), config.model.as_deref())?;
        let (provider, model) = split_provider_model(configured_model);
        let model = model_with_optional_thinking(model, config.reasoning_effort.as_deref());
        let mut arguments = Vec::with_capacity(4);
        if let Some(provider) = provider {
            arguments.extend(["--provider".to_owned(), provider.to_owned()]);
        }
        arguments.extend(["--model".to_owned(), model]);
        Ok(arguments)
    }
}

impl Default for PiAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentRuntime for PiAdapter {
    fn id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    fn launch_invocation(
        &self,
        request: RuntimeLaunchRequest<'_>,
    ) -> Result<RuntimeInvocation, AdapterError> {
        let mut arguments = self.configured_arguments(request.config)?;
        let role_instructions = request
            .initial_prompt
            .filter(|prompt| !prompt.trim().is_empty());
        if let Some(role_instructions) = role_instructions {
            arguments.extend([
                "--append-system-prompt".to_owned(),
                role_instructions.to_owned(),
            ]);
        }
        Ok(RuntimeInvocation {
            program: self.program.clone(),
            arguments,
            initial_prompt: role_instructions.map(|_| PI_BOOTSTRAP_PROMPT.to_owned()),
        })
    }

    fn resume_invocation(
        &self,
        request: RuntimeResumeRequest<'_>,
    ) -> Result<RuntimeInvocation, AdapterError> {
        let session_id = request.session_id.trim();
        if session_id.is_empty() {
            return Err(AdapterError::MissingSessionId {
                runtime_id: self.id().clone(),
            });
        }
        let mut arguments = vec!["--session".to_owned(), session_id.to_owned()];
        arguments.extend(self.configured_arguments(request.config)?);
        Ok(RuntimeInvocation {
            program: self.program.clone(),
            arguments,
            initial_prompt: request.prompt.map(str::to_owned),
        })
    }

    fn diagnostics(&self) -> RuntimeDiagnostics {
        match Command::new(&self.program).arg("--version").output() {
            Ok(output) => {
                let version = non_empty(String::from_utf8_lossy(&output.stdout).trim());
                let error = non_empty(String::from_utf8_lossy(&output.stderr).trim());
                RuntimeDiagnostics {
                    runtime_id: self.id().clone(),
                    program: self.program.clone(),
                    available: output.status.success(),
                    version,
                    error,
                }
            }
            Err(error) => RuntimeDiagnostics {
                runtime_id: self.id().clone(),
                program: self.program.clone(),
                available: false,
                version: None,
                error: Some(error.to_string()),
            },
        }
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            launch: CapabilitySupport::Supported,
            resume: CapabilitySupport::Supported,
            model_selection: CapabilitySupport::Supported,
            reasoning_effort: CapabilitySupport::Supported,
            initial_prompt_delivery: InitialPromptDelivery::AfterSessionReady,
            // Pi's built-in tools can edit the workspace and execute commands,
            // but Pi does not enforce a native sandbox or command-approval gate.
            launch_policy: RuntimeLaunchPolicy {
                sandbox: None,
                approval: None,
                provider_enforcement: &["append_system_prompt"],
            },
        }
    }
}

fn required_model<'a>(
    runtime_id: &RuntimeId,
    model: Option<&'a str>,
) -> Result<&'a str, AdapterError> {
    model
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .ok_or_else(|| AdapterError::MissingConfiguration {
            runtime_id: runtime_id.clone(),
            field: "model",
        })
}

fn split_provider_model(model: &str) -> (Option<&str>, &str) {
    match model.split_once('/') {
        Some((provider, model)) if !provider.is_empty() && !model.is_empty() => {
            (Some(provider), model)
        }
        _ => (None, model),
    }
}

fn model_with_optional_thinking(model: &str, reasoning_effort: Option<&str>) -> String {
    reasoning_effort
        .map(str::trim)
        .filter(|effort| !effort.is_empty())
        .map_or_else(|| model.to_owned(), |effort| format!("{model}:{effort}"))
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}
