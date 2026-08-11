use std::path::PathBuf;

use agsv_runtime::{
    AdapterError, AgentRuntime, CapabilitySupport, InitialPromptDelivery, PiAdapter, RuntimeConfig,
    RuntimeLaunchPolicy, RuntimeLaunchRequest, RuntimeRegistry, RuntimeResumeRequest,
};
use agsv_session::{FakeEvent, FakeSessionBackend, LaunchRequest, ResumeRequest, SessionBackend};

const ROLE_INSTRUCTIONS: &str =
    "Implementation role instructions.\nBootstrap with the absolute AGSV command.";
const BOOTSTRAP_PROMPT: &str =
    "Begin the managed launch setup now. Follow the system instructions exactly.";

#[test]
fn pi_is_registered_and_codex_remains_the_default() {
    let registry = RuntimeRegistry::new();

    assert_eq!(registry.default_id().as_str(), "codex");
    assert_eq!(registry.select(None).unwrap().id().as_str(), "codex");
    assert_eq!(registry.select(Some(" PI ")).unwrap().id().as_str(), "pi");
    assert_eq!(
        registry
            .ids()
            .map(agsv_runtime::RuntimeId::as_str)
            .collect::<Vec<_>>(),
        ["codex", "pi"]
    );

    assert!(matches!(
        registry.select(Some("unknown-provider")),
        Err(AdapterError::UnknownRuntime(runtime_id))
            if runtime_id.as_str() == "unknown-provider"
    ));
}

#[test]
fn pi_launch_and_resume_round_trip_through_fake_backend() {
    let adapter = RuntimeRegistry::new().select(Some("pi")).unwrap();
    let config = RuntimeConfig::new("llamacpp/qwen3-coder", "high");
    let working_directory = PathBuf::from("/pi/worktree");

    let launch_invocation = adapter
        .launch_invocation(RuntimeLaunchRequest {
            config: &config,
            initial_prompt: Some(ROLE_INSTRUCTIONS),
        })
        .unwrap();
    assert_eq!(launch_invocation.program, "pi");
    assert_eq!(
        launch_invocation.arguments,
        [
            "--provider",
            "llamacpp",
            "--model",
            "qwen3-coder:high",
            "--append-system-prompt",
            ROLE_INSTRUCTIONS,
        ]
    );
    assert_eq!(
        launch_invocation.initial_prompt.as_deref(),
        Some(BOOTSTRAP_PROMPT)
    );
    assert_ne!(
        launch_invocation.initial_prompt.as_deref(),
        Some(ROLE_INSTRUCTIONS),
        "role instructions must not be duplicated as a user turn"
    );

    let launch_request = LaunchRequest {
        actor_id: "pi-actor".to_owned(),
        session_name: "pi-session".to_owned(),
        runtime: launch_invocation.program,
        working_directory: working_directory.clone(),
        idempotency_key: "pi-launch-key".to_owned(),
        native_args: launch_invocation.arguments,
        initial_prompt: launch_invocation.initial_prompt,
        resume_token: None,
    };
    let backend = FakeSessionBackend::new();
    let handle = backend.launch(&launch_request).unwrap();

    let resume_invocation = adapter
        .resume_invocation(RuntimeResumeRequest {
            config: &config,
            session_id: "019-session-id",
            prompt: Some("Process the durable inbox notification."),
        })
        .unwrap();
    assert_eq!(
        resume_invocation.arguments,
        [
            "--session",
            "019-session-id",
            "--provider",
            "llamacpp",
            "--model",
            "qwen3-coder:high",
        ]
    );
    assert_eq!(
        resume_invocation.initial_prompt.as_deref(),
        Some("Process the durable inbox notification.")
    );
    let resume_request = ResumeRequest {
        actor_id: "pi-actor".to_owned(),
        handle: handle.clone(),
        working_directory,
        idempotency_key: "pi-resume-key".to_owned(),
        native_args: resume_invocation.arguments,
    };
    assert_eq!(backend.resume(&resume_request).unwrap(), handle);
    assert_eq!(
        backend.events().unwrap(),
        [
            FakeEvent::Launched {
                actor_id: "pi-actor".to_owned(),
                session_id: "fake-1".to_owned(),
            },
            FakeEvent::Resumed {
                actor_id: "pi-actor".to_owned(),
                session_id: "fake-1".to_owned(),
            },
        ]
    );
}

#[test]
fn pi_reasoning_suffix_is_optional_and_capabilities_are_truthful() {
    let adapter = PiAdapter::with_program("agsv-pi-command-that-does-not-exist");
    let config = RuntimeConfig {
        model: Some("standalone-model".to_owned()),
        reasoning_effort: None,
    };
    let invocation = adapter
        .launch_invocation(RuntimeLaunchRequest {
            config: &config,
            initial_prompt: None,
        })
        .unwrap();

    assert_eq!(invocation.arguments, ["--model", "standalone-model"]);
    assert!(invocation.initial_prompt.is_none());
    assert_eq!(
        adapter.capabilities(),
        agsv_runtime::RuntimeCapabilities {
            launch: CapabilitySupport::Supported,
            resume: CapabilitySupport::Supported,
            model_selection: CapabilitySupport::Supported,
            reasoning_effort: CapabilitySupport::Supported,
            initial_prompt_delivery: InitialPromptDelivery::AfterSessionReady,
            launch_policy: RuntimeLaunchPolicy {
                sandbox: None,
                approval: None,
                provider_enforcement: &["append_system_prompt"],
            },
        }
    );

    let diagnostics = adapter.diagnostics();
    assert_eq!(diagnostics.runtime_id.as_str(), "pi");
    assert_eq!(diagnostics.program, "agsv-pi-command-that-does-not-exist");
    assert!(!diagnostics.available);
    assert!(diagnostics.version.is_none());
    assert!(diagnostics.error.is_some());
}

#[test]
fn pi_rejects_missing_model_and_resume_identity() {
    let adapter = PiAdapter::new();
    let missing_model = RuntimeConfig {
        model: None,
        reasoning_effort: Some("high".to_owned()),
    };
    assert!(matches!(
        adapter.launch_invocation(RuntimeLaunchRequest {
            config: &missing_model,
            initial_prompt: None,
        }),
        Err(AdapterError::MissingConfiguration { field: "model", .. })
    ));

    let config = RuntimeConfig {
        model: Some("llamacpp/qwen3-coder".to_owned()),
        reasoning_effort: None,
    };
    assert!(matches!(
        adapter.resume_invocation(RuntimeResumeRequest {
            config: &config,
            session_id: " ",
            prompt: None,
        }),
        Err(AdapterError::MissingSessionId { .. })
    ));
}
