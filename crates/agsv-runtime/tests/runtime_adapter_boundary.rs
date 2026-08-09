use std::path::PathBuf;
use std::sync::Arc;

use agsv_runtime::{
    AdapterError, AgentRuntime, CapabilitySupport, InitialPromptDelivery, RuntimeCapabilities,
    RuntimeConfig, RuntimeDiagnostics, RuntimeId, RuntimeInvocation, RuntimeLaunchPolicy,
    RuntimeLaunchRequest, RuntimeRegistry, RuntimeResumeRequest,
};
use agsv_session::{FakeEvent, FakeSessionBackend, LaunchRequest, ResumeRequest, SessionBackend};

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
            arguments: vec!["fixture-launch".to_owned()],
            initial_prompt: request.initial_prompt.map(str::to_owned),
        })
    }

    fn resume_invocation(
        &self,
        request: RuntimeResumeRequest<'_>,
    ) -> Result<RuntimeInvocation, AdapterError> {
        Ok(RuntimeInvocation {
            program: self.id().to_string(),
            arguments: vec!["fixture-resume".to_owned(), request.session_id.to_owned()],
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
fn registered_fixture_drives_fake_backend_launch_and_resume() {
    let mut registry = RuntimeRegistry::new();
    registry.register(Arc::new(FixtureAdapter::new())).unwrap();
    let adapter = registry.select(Some("fixture-runtime")).unwrap();
    let config = RuntimeConfig::default();
    let working_directory = PathBuf::from("/fixture/worktree");

    let launch_invocation = adapter
        .launch_invocation(RuntimeLaunchRequest {
            config: &config,
            initial_prompt: Some("fixture initial prompt"),
        })
        .unwrap();
    let launch_request = LaunchRequest {
        actor_id: "fixture-actor".to_owned(),
        session_name: "fixture-session".to_owned(),
        runtime: launch_invocation.program.clone(),
        working_directory: working_directory.clone(),
        idempotency_key: "fixture-launch-key".to_owned(),
        native_args: launch_invocation.arguments.clone(),
        initial_prompt: launch_invocation.initial_prompt.clone(),
        resume_token: None,
    };
    assert_eq!(launch_request.runtime, "fixture-runtime");
    assert_eq!(launch_request.native_args, ["fixture-launch"]);
    assert_eq!(
        launch_request.initial_prompt.as_deref(),
        Some("fixture initial prompt")
    );

    let backend = FakeSessionBackend::new();
    let handle = backend.launch(&launch_request).unwrap();

    let resume_invocation = adapter
        .resume_invocation(RuntimeResumeRequest {
            config: &config,
            session_id: handle.external_id.as_str(),
            prompt: Some("fixture follow-up"),
        })
        .unwrap();
    let resume_request = ResumeRequest {
        actor_id: "fixture-actor".to_owned(),
        handle: handle.clone(),
        working_directory,
        idempotency_key: "fixture-resume-key".to_owned(),
        native_args: resume_invocation.arguments.clone(),
    };
    assert_eq!(
        resume_request.native_args,
        ["fixture-resume", handle.external_id.as_str()]
    );
    assert_eq!(
        resume_invocation.initial_prompt.as_deref(),
        Some("fixture follow-up")
    );

    let resumed = backend.resume(&resume_request).unwrap();
    assert_eq!(resumed, handle);
    assert_eq!(
        backend.events().unwrap(),
        [
            FakeEvent::Launched {
                actor_id: "fixture-actor".to_owned(),
                session_id: "fake-1".to_owned(),
            },
            FakeEvent::Resumed {
                actor_id: "fixture-actor".to_owned(),
                session_id: "fake-1".to_owned(),
            },
        ]
    );
}
