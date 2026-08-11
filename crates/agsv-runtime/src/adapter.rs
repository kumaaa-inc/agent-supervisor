use std::collections::BTreeMap;
use std::fmt;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;

use crate::PiAdapter;

/// Adapter-boundary identifier for a top-level orchestrator runtime.
///
/// Runtime identifiers deliberately live in this crate rather than in the
/// provider-neutral protocol or core domain. Input is normalized to lowercase
/// ASCII and must use kebab-case words.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuntimeId(String);

impl RuntimeId {
    /// Validates and normalizes a configured runtime identifier.
    pub fn new(value: impl AsRef<str>) -> Result<Self, AdapterError> {
        let original = value.as_ref();
        let normalized = original.trim().to_ascii_lowercase();
        let valid = !normalized.is_empty()
            && normalized.len() <= 64
            && normalized
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && normalized
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && normalized
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && !normalized.contains("--");
        if !valid {
            return Err(AdapterError::InvalidRuntimeId(original.to_owned()));
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for RuntimeId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RuntimeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RuntimeId {
    type Err = AdapterError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Provider-neutral model configuration supplied to a runtime adapter.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeConfig {
    pub model: Option<String>,
    pub reasoning_effort: Option<String>,
}

impl RuntimeConfig {
    #[must_use]
    pub fn new(model: impl Into<String>, reasoning_effort: impl Into<String>) -> Self {
        Self {
            model: Some(model.into()),
            reasoning_effort: Some(reasoning_effort.into()),
        }
    }
}

/// Inputs used to construct a fresh runtime invocation.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeLaunchRequest<'a> {
    pub config: &'a RuntimeConfig,
    pub initial_prompt: Option<&'a str>,
}

/// Inputs used to construct an invocation that resumes a runtime session.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeResumeRequest<'a> {
    pub config: &'a RuntimeConfig,
    pub session_id: &'a str,
    /// Optional follow-up delivered after the resumed session is ready.
    pub prompt: Option<&'a str>,
}

/// Provider-specific program and arguments produced at the adapter boundary.
///
/// `program` is also the runtime kind supplied to session backends such as
/// Herdr. The initial prompt remains separate from the argument vector so a
/// session backend can deliver it only after the new session reports ready.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeInvocation {
    pub program: String,
    pub arguments: Vec<String>,
    pub initial_prompt: Option<String>,
}

/// How a runtime expects the initial prompt to cross the session boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialPromptDelivery {
    Unsupported,
    CommandArgument,
    AfterSessionReady,
}

/// Static features reported by a runtime adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCapabilities {
    pub launch: CapabilitySupport,
    pub resume: CapabilitySupport,
    pub model_selection: CapabilitySupport,
    pub reasoning_effort: CapabilitySupport,
    pub initial_prompt_delivery: InitialPromptDelivery,
    pub launch_policy: RuntimeLaunchPolicy,
}

/// Provider-owned launch policy metadata exposed to diagnostics and control.
///
/// These values describe flags enforced by the runtime adapter without making
/// their provider-specific spelling part of protocol or core domain types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeLaunchPolicy {
    pub sandbox: Option<&'static str>,
    pub approval: Option<&'static str>,
    pub provider_enforcement: &'static [&'static str],
}

impl RuntimeLaunchPolicy {
    pub const NONE: Self = Self {
        sandbox: None,
        approval: None,
        provider_enforcement: &[],
    };
}

impl Default for RuntimeLaunchPolicy {
    fn default() -> Self {
        Self::NONE
    }
}

/// Whether a runtime supports an optional adapter capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilitySupport {
    Supported,
    Unsupported,
}

impl CapabilitySupport {
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// A point-in-time diagnostic probe of the selected runtime executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDiagnostics {
    pub runtime_id: RuntimeId,
    pub program: String,
    pub available: bool,
    pub version: Option<String>,
    pub error: Option<String>,
}

/// Provider adapter for one top-level orchestrator runtime.
pub trait AgentRuntime: Send + Sync {
    fn id(&self) -> &RuntimeId;
    fn launch_invocation(
        &self,
        request: RuntimeLaunchRequest<'_>,
    ) -> Result<RuntimeInvocation, AdapterError>;
    fn resume_invocation(
        &self,
        request: RuntimeResumeRequest<'_>,
    ) -> Result<RuntimeInvocation, AdapterError>;
    fn diagnostics(&self) -> RuntimeDiagnostics;
    fn capabilities(&self) -> RuntimeCapabilities;
}

/// Errors produced at the provider-adapter and registry boundary.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterError {
    #[error("invalid runtime identifier {0:?}")]
    InvalidRuntimeId(String),
    #[error("runtime {0} is not registered")]
    UnknownRuntime(RuntimeId),
    #[error("runtime {0} is already registered")]
    DuplicateRuntime(RuntimeId),
    #[error("runtime {runtime_id} requires a non-empty {field}")]
    MissingConfiguration {
        runtime_id: RuntimeId,
        field: &'static str,
    },
    #[error("runtime {runtime_id} requires a non-empty session identifier")]
    MissingSessionId { runtime_id: RuntimeId },
}

/// Compile-time and explicitly registered top-level runtime adapters.
///
/// The built-in factory table contains Codex and Pi and can be extended without
/// changing protocol, core, or control-plane branching. Tests and embedding
/// applications may register additional adapters before selection.
#[derive(Clone)]
pub struct RuntimeRegistry {
    adapters: BTreeMap<RuntimeId, Arc<dyn AgentRuntime>>,
    default_id: RuntimeId,
}

impl RuntimeRegistry {
    /// Creates the built-in registry with Codex as its default runtime.
    ///
    /// # Panics
    ///
    /// Panics only when the crate's compile-time factory table contains an
    /// invalid, duplicate, or mismatched runtime identifier.
    #[must_use]
    pub fn new() -> Self {
        let default_id = RuntimeId::new(DEFAULT_RUNTIME_ID)
            .expect("the compile-time default runtime identifier must be valid");
        let mut registry = Self {
            adapters: BTreeMap::new(),
            default_id,
        };
        for factory in BUILTIN_FACTORIES {
            let declared_id =
                RuntimeId::new(factory.id).expect("compile-time runtime identifiers must be valid");
            let adapter = (factory.create)();
            assert_eq!(
                adapter.id(),
                &declared_id,
                "compile-time runtime factory returned a mismatched adapter"
            );
            registry
                .register(adapter)
                .expect("compile-time runtime identifiers must be unique");
        }
        assert!(registry.adapters.contains_key(&registry.default_id));
        registry
    }

    /// Adds an adapter to this registry before it is selected by control code.
    pub fn register(&mut self, adapter: Arc<dyn AgentRuntime>) -> Result<(), AdapterError> {
        let runtime_id = adapter.id().clone();
        if self.adapters.contains_key(&runtime_id) {
            return Err(AdapterError::DuplicateRuntime(runtime_id));
        }
        self.adapters.insert(runtime_id, adapter);
        Ok(())
    }

    /// Selects the configured runtime, or Codex when no identifier is supplied.
    pub fn select(
        &self,
        configured_id: Option<&str>,
    ) -> Result<Arc<dyn AgentRuntime>, AdapterError> {
        let runtime_id =
            configured_id.map_or_else(|| Ok(self.default_id.clone()), RuntimeId::new)?;
        self.adapters
            .get(&runtime_id)
            .cloned()
            .ok_or(AdapterError::UnknownRuntime(runtime_id))
    }

    #[must_use]
    pub fn default_id(&self) -> &RuntimeId {
        &self.default_id
    }

    pub fn ids(&self) -> impl Iterator<Item = &RuntimeId> {
        self.adapters.keys()
    }
}

impl Default for RuntimeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

const DEFAULT_RUNTIME_ID: &str = "codex";

struct BuiltinFactory {
    id: &'static str,
    create: fn() -> Arc<dyn AgentRuntime>,
}

const BUILTIN_FACTORIES: &[BuiltinFactory] = &[
    BuiltinFactory {
        id: DEFAULT_RUNTIME_ID,
        create: codex_factory,
    },
    BuiltinFactory {
        id: "pi",
        create: pi_factory,
    },
];

fn codex_factory() -> Arc<dyn AgentRuntime> {
    Arc::new(CodexAdapter::default())
}

fn pi_factory() -> Arc<dyn AgentRuntime> {
    Arc::new(PiAdapter::default())
}

/// Built-in adapter preserving the zero-config Codex launch contract.
#[derive(Clone, Debug)]
pub struct CodexAdapter {
    runtime_id: RuntimeId,
    program: String,
}

impl CodexAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self::with_program(DEFAULT_RUNTIME_ID)
    }

    #[must_use]
    pub fn with_program(program: impl Into<String>) -> Self {
        Self {
            runtime_id: RuntimeId(DEFAULT_RUNTIME_ID.to_owned()),
            program: program.into(),
        }
    }

    fn configured_arguments(&self, config: &RuntimeConfig) -> Result<Vec<String>, AdapterError> {
        let model = required_config(self.id(), "model", config.model.as_deref())?;
        let reasoning_effort = required_config(
            self.id(),
            "reasoning_effort",
            config.reasoning_effort.as_deref(),
        )?;
        Ok(vec![
            "-m".to_owned(),
            model.to_owned(),
            "-c".to_owned(),
            format!("model_reasoning_effort=\"{reasoning_effort}\""),
            "--approve-for-me".to_owned(),
        ])
    }
}

impl Default for CodexAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentRuntime for CodexAdapter {
    fn id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    fn launch_invocation(
        &self,
        request: RuntimeLaunchRequest<'_>,
    ) -> Result<RuntimeInvocation, AdapterError> {
        Ok(RuntimeInvocation {
            program: self.program.clone(),
            arguments: self.configured_arguments(request.config)?,
            initial_prompt: request.initial_prompt.map(str::to_owned),
        })
    }

    fn resume_invocation(
        &self,
        request: RuntimeResumeRequest<'_>,
    ) -> Result<RuntimeInvocation, AdapterError> {
        if request.session_id.trim().is_empty() {
            return Err(AdapterError::MissingSessionId {
                runtime_id: self.id().clone(),
            });
        }
        let mut arguments = vec!["resume".to_owned(), request.session_id.to_owned()];
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
            launch_policy: RuntimeLaunchPolicy {
                sandbox: Some("workspace-write"),
                approval: Some("approve-for-me"),
                provider_enforcement: &["approve_for_me"],
            },
        }
    }
}

fn required_config<'a>(
    runtime_id: &RuntimeId,
    field: &'static str,
    value: Option<&'a str>,
) -> Result<&'a str, AdapterError> {
    value
        .filter(|configured| !configured.trim().is_empty())
        .ok_or_else(|| AdapterError::MissingConfiguration {
            runtime_id: runtime_id.clone(),
            field,
        })
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureAdapter {
        runtime_id: RuntimeId,
    }

    impl FixtureAdapter {
        fn new() -> Self {
            Self {
                runtime_id: RuntimeId::new("fixture-runtime").unwrap(),
            }
        }
    }

    impl AgentRuntime for FixtureAdapter {
        fn id(&self) -> &RuntimeId {
            &self.runtime_id
        }

        fn launch_invocation(
            &self,
            request: RuntimeLaunchRequest<'_>,
        ) -> Result<RuntimeInvocation, AdapterError> {
            Ok(RuntimeInvocation {
                program: self.id().to_string(),
                arguments: vec!["launch".to_owned()],
                initial_prompt: request.initial_prompt.map(str::to_owned),
            })
        }

        fn resume_invocation(
            &self,
            request: RuntimeResumeRequest<'_>,
        ) -> Result<RuntimeInvocation, AdapterError> {
            Ok(RuntimeInvocation {
                program: self.id().to_string(),
                arguments: vec!["resume".to_owned(), request.session_id.to_owned()],
                initial_prompt: request.prompt.map(str::to_owned),
            })
        }

        fn diagnostics(&self) -> RuntimeDiagnostics {
            RuntimeDiagnostics {
                runtime_id: self.id().clone(),
                program: self.id().to_string(),
                available: true,
                version: Some("fixture-1".to_owned()),
                error: None,
            }
        }

        fn capabilities(&self) -> RuntimeCapabilities {
            RuntimeCapabilities {
                launch: CapabilitySupport::Supported,
                resume: CapabilitySupport::Supported,
                model_selection: CapabilitySupport::Unsupported,
                reasoning_effort: CapabilitySupport::Unsupported,
                initial_prompt_delivery: InitialPromptDelivery::AfterSessionReady,
                launch_policy: RuntimeLaunchPolicy::NONE,
            }
        }
    }

    #[test]
    fn runtime_identifiers_are_validated_and_normalized() {
        assert_eq!(
            RuntimeId::new("  Claude-Code  ").unwrap().as_str(),
            "claude-code"
        );
        for invalid in ["", "two words", "-leading", "trailing-", "two--dashes"] {
            assert!(matches!(
                RuntimeId::new(invalid),
                Err(AdapterError::InvalidRuntimeId(_))
            ));
        }
    }

    #[test]
    fn registry_defaults_to_codex_and_selects_registered_fixture() {
        let mut registry = RuntimeRegistry::new();
        let default = registry.select(None).unwrap();
        assert_eq!(default.id().as_str(), "codex");

        registry.register(Arc::new(FixtureAdapter::new())).unwrap();
        let fixture = registry.select(Some(" FIXTURE-RUNTIME ")).unwrap();
        assert_eq!(fixture.id().as_str(), "fixture-runtime");
        assert_eq!(
            fixture.capabilities().launch_policy,
            RuntimeLaunchPolicy::NONE
        );
    }

    #[test]
    fn registry_rejects_unknown_and_duplicate_runtime_ids() {
        let mut registry = RuntimeRegistry::new();
        let unknown = registry
            .select(Some("missing-runtime"))
            .err()
            .expect("unknown runtime selection must fail");
        assert_eq!(
            unknown,
            AdapterError::UnknownRuntime(RuntimeId::new("missing-runtime").unwrap())
        );

        registry.register(Arc::new(FixtureAdapter::new())).unwrap();
        let duplicate = registry
            .register(Arc::new(FixtureAdapter::new()))
            .unwrap_err();
        assert_eq!(
            duplicate,
            AdapterError::DuplicateRuntime(RuntimeId::new("fixture-runtime").unwrap())
        );
    }

    #[test]
    fn codex_constructs_compatible_launch_and_resume_arguments() {
        let adapter = CodexAdapter::new();
        let config = RuntimeConfig::new("gpt-test", "max");
        let launch = adapter
            .launch_invocation(RuntimeLaunchRequest {
                config: &config,
                initial_prompt: Some("start here"),
            })
            .unwrap();
        assert_eq!(launch.program, "codex");
        assert_eq!(
            launch.arguments,
            [
                "-m",
                "gpt-test",
                "-c",
                "model_reasoning_effort=\"max\"",
                "--approve-for-me",
            ]
        );
        assert_eq!(launch.initial_prompt.as_deref(), Some("start here"));

        let resume = adapter
            .resume_invocation(RuntimeResumeRequest {
                config: &config,
                session_id: "session-123",
                prompt: Some("continue here"),
            })
            .unwrap();
        assert_eq!(
            resume.arguments,
            [
                "resume",
                "session-123",
                "-m",
                "gpt-test",
                "-c",
                "model_reasoning_effort=\"max\"",
                "--approve-for-me",
            ]
        );
        assert_eq!(resume.initial_prompt.as_deref(), Some("continue here"));
    }

    #[test]
    fn codex_forwards_xhigh_reasoning_effort_exactly() {
        let adapter = CodexAdapter::new();
        let config = RuntimeConfig::new("gpt-5.6-sol", "xhigh");
        let launch = adapter
            .launch_invocation(RuntimeLaunchRequest {
                config: &config,
                initial_prompt: None,
            })
            .unwrap();

        assert_eq!(
            launch.arguments,
            [
                "-m",
                "gpt-5.6-sol",
                "-c",
                "model_reasoning_effort=\"xhigh\"",
                "--approve-for-me",
            ]
        );
    }

    #[test]
    fn codex_reports_capabilities_and_deterministic_unavailable_diagnostics() {
        let adapter = CodexAdapter::with_program("agsv-codex-command-that-does-not-exist");
        assert_eq!(
            adapter.capabilities(),
            RuntimeCapabilities {
                launch: CapabilitySupport::Supported,
                resume: CapabilitySupport::Supported,
                model_selection: CapabilitySupport::Supported,
                reasoning_effort: CapabilitySupport::Supported,
                initial_prompt_delivery: InitialPromptDelivery::AfterSessionReady,
                launch_policy: RuntimeLaunchPolicy {
                    sandbox: Some("workspace-write"),
                    approval: Some("approve-for-me"),
                    provider_enforcement: &["approve_for_me"],
                },
            }
        );
        let diagnostics = adapter.diagnostics();
        assert!(!diagnostics.available);
        assert!(diagnostics.version.is_none());
        assert!(diagnostics.error.is_some());
    }

    #[test]
    fn codex_rejects_incomplete_configuration_and_resume_identity() {
        let adapter = CodexAdapter::new();
        let missing_effort = RuntimeConfig {
            model: Some("gpt-test".to_owned()),
            reasoning_effort: None,
        };
        assert!(matches!(
            adapter.launch_invocation(RuntimeLaunchRequest {
                config: &missing_effort,
                initial_prompt: None,
            }),
            Err(AdapterError::MissingConfiguration {
                field: "reasoning_effort",
                ..
            })
        ));

        let config = RuntimeConfig::new("gpt-test", "high");
        assert!(matches!(
            adapter.resume_invocation(RuntimeResumeRequest {
                config: &config,
                session_id: " ",
                prompt: None,
            }),
            Err(AdapterError::MissingSessionId { .. })
        ));
    }
}
