use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::backend::SessionDriver;
use crate::base_staleness::BaseStalenessContext;
use crate::caller::{CallerBinding, CallerIdentityDriver, InsecureActorIdentity};
use crate::identity::sha256_hex;
use crate::presentation::{
    LabelContext, active_request_title, render_label_template,
    session_label as display_session_label,
};
use crate::review::{ReviewAttemptBudget, ReviewRunner, resolve_git_executable};
use crate::store::{
    ActorShutdownCommit, OperationLock, OperationLockMode, PresentationSyncState,
    SessionPresentationRecord, SessionRecord, StateStore, TeamWorktreeOwnership,
    TeamWorktreeRecord, TeamWorktreeStatus,
};
use crate::{ControlError, WorkspaceIdentity};
use agsv_core::{AckOutcome, ApplyOutcome, DeliveryRecord, Supervisor};
use agsv_protocol::{
    Acknowledgement, Actor, ActorEpoch, ActorId, ActorProfileName, ActorProfileSnapshot, ActorRef,
    ActorRole, ActorStatus, AssignmentEpoch, AssignmentPolicyId, BlockerNotice, Cancellation,
    Candidate, CandidateReady, CapabilityId, ConflictNotice, ConsultationRequest,
    ConsultationResponse, DecisionId, DeliveryRecipient, DeliverySnapshot, DependencyNotice,
    Envelope, EnvelopeHeader, EvidenceKind, FixRequest, GitSha, HUMAN_FACING_PRIMARY_CAPABILITY,
    HandoffAcceptance, HandoffId, HandoffOffer, IMPLEMENTATION_EXECUTION_CAPABILITY,
    ImplementationRequest, IntegrationAuthorization, IntegrationComplete,
    MAX_REQUEST_TEXT_CHARACTERS, Message, MessageId, MessageTarget, PROTOCOL_VERSION,
    PayloadDigest, PolicyRevision, PrimaryDirective, ProgressUpdate, QaOutcome, QaResult, Request,
    RequestId, RequestStatus, ReviewAttemptRecordId, ReviewAttemptStatus, ReviewCheckOutcome,
    ReviewDecision, ReviewEnvironmentKey, ReviewExecutionVariant, ReviewPlan, ReviewRecoveryState,
    ReviewSession, ReviewSessionId, ReviewSessionState, ReviewSessionStatus, ReviewVerdict,
    ReviewVerificationAttempt, RunControl, RunControlAction, RunId, Team, TeamEpoch, TeamId,
    TeamProfileName, TeamProfileSnapshot, TeamStatus, TimestampMillis, Validate,
    request_blocks_team_close,
};
use agsv_runtime::{
    AdapterError, AgentRuntime, InitialPromptDelivery, RuntimeConfig, RuntimeRegistry,
};
use agsv_session::{CapabilityOutcome, SessionLaunchHints, SessionPlacement, SplitDirection};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

static NEXT_OPERATION_CLAIM: AtomicU64 = AtomicU64::new(1);
#[cfg(test)]
static TEST_CRASH_POINTS: LazyLock<Mutex<BTreeSet<(String, String)>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));
#[cfg(test)]
static TEST_AUTHENTICATED_ACTORS: LazyLock<Mutex<BTreeMap<String, ActorRef>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
#[cfg(test)]
type AfterCallerFence = Arc<dyn Fn(&str) + Send + Sync>;
#[cfg(test)]
static TEST_AFTER_CALLER_FENCE: LazyLock<Mutex<BTreeMap<String, AfterCallerFence>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
#[cfg(test)]
static TEST_OPERATION_PHASES: LazyLock<Mutex<BTreeMap<(String, String), AfterCallerFence>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
// v0.1 stored NULL because Codex was its only runtime; legacy resolution must
// remain pinned to that history and never follow the current registry default.
const LEGACY_RUNTIME_ID: &str = "codex";
const LEGACY_PRIMARY_PROFILE: &str = "primary";
const LEGACY_IMPLEMENTATION_PROFILE: &str = "implementation";

#[derive(Clone, Copy)]
enum ReconciledActorStop {
    Surplus,
    TeamClose,
}

enum CallerMutationFence {
    Stopped(ActorRef),
    Superseded(ActorRef),
    SupersededPrimary(ActorRef),
}

struct OperationGuards {
    workspace: Option<OperationLock>,
    _primary: Option<OperationLock>,
    primary_exclusive: bool,
    _caller: Option<OperationLock>,
    _actors: Vec<OperationLock>,
    expire_primary: bool,
}

impl OperationGuards {
    fn release_workspace(&mut self) {
        drop(self.workspace.take());
    }
}

impl CallerMutationFence {
    fn error(&self) -> ControlError {
        match self {
            Self::Stopped(actor_ref) => terminal_actor_binding(actor_ref),
            Self::Superseded(actor_ref) => superseded_actor_binding(actor_ref),
            Self::SupersededPrimary(actor_ref) => superseded_primary_binding(actor_ref),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum TeamWorkingDirectoryState {
    Unrecorded,
    Removed,
    Present,
    RecordedAbsent,
    PresentMismatch,
    InspectionFailed,
}

#[derive(Clone, Debug, Serialize)]
struct TeamWorkingDirectoryDrift {
    code: String,
    detail: String,
}

#[derive(Clone, Debug, Serialize)]
struct TeamWorkingDirectoryObservation {
    recorded_path: Option<PathBuf>,
    state: TeamWorkingDirectoryState,
    exists: Option<bool>,
    head_sha: Option<GitSha>,
    matches_durable_state: Option<bool>,
    drift: Vec<TeamWorkingDirectoryDrift>,
}

struct TeamReportingContext {
    worktrees: BTreeMap<String, TeamWorktreeRecord>,
    sessions: BTreeMap<String, Vec<SessionRecord>>,
    all_sessions: Vec<SessionRecord>,
    git_worktree_paths: Result<BTreeSet<PathBuf>, String>,
}

/// Assignment policies implemented by the embedded control plane.
pub const SUPPORTED_ASSIGNMENT_POLICIES: &[&str] = &["first_healthy", "least_wip"];

/// Maximum number of capabilities persisted on one actor profile.
pub const MAX_PROFILE_CAPABILITIES: usize = agsv_protocol::MAX_ACTOR_CAPABILITIES;

trait RuntimeCatalog {
    fn select(&self, configured_id: Option<&str>) -> Result<Arc<dyn AgentRuntime>, AdapterError>;
    fn ids(&self) -> Vec<String>;
}

impl RuntimeCatalog for RuntimeRegistry {
    fn select(&self, configured_id: Option<&str>) -> Result<Arc<dyn AgentRuntime>, AdapterError> {
        RuntimeRegistry::select(self, configured_id)
    }

    fn ids(&self) -> Vec<String> {
        RuntimeRegistry::ids(self)
            .map(ToString::to_string)
            .collect()
    }
}

/// One validated project-defined top-level orchestrator profile.
#[derive(Clone, Debug)]
pub struct ActorProfileSettings {
    pub name: String,
    pub role: String,
    pub capabilities: BTreeSet<String>,
    pub launch: ActorLaunchSettings,
    pub role_file: PathBuf,
    pub role_instructions: String,
    pub role_source: String,
}

/// Whether an actor is bound from the caller's existing session or launched
/// through a configured runtime adapter.
#[derive(Clone, Debug)]
pub enum ActorLaunchSettings {
    Bound,
    Runtime {
        runtime: String,
        model: String,
        reasoning_effort: String,
    },
}

/// One validated project-defined persistent team profile.
#[derive(Clone, Debug)]
pub struct TeamProfileSettings {
    pub name: String,
    pub actor_profile: String,
    pub desired_instances: u32,
    pub assignment_policy: String,
}

/// One project-declared check executed by the control-plane review runner.
#[derive(Clone, Debug)]
pub struct ReviewCheckSettings {
    pub id: String,
    pub argv: Vec<String>,
    pub expected_exit_code: i32,
    pub relative_cwd: Option<PathBuf>,
    pub timeout_seconds: u32,
    pub required_absent_binaries: BTreeSet<String>,
}

/// One project-declared executable version probe captured with every run.
#[derive(Clone, Debug)]
pub struct ReviewToolVersionSettings {
    pub id: String,
    pub argv: Vec<String>,
}

/// Effective, trusted review-suite configuration resolved before checkout.
#[derive(Clone, Debug, Default)]
pub struct ReviewSettings {
    pub checks: Vec<ReviewCheckSettings>,
    pub tool_versions: Vec<ReviewToolVersionSettings>,
    pub optional_binaries: BTreeSet<String>,
    pub environment: BTreeMap<String, String>,
}

impl ReviewSettings {
    /// Validates one configured child-environment entry through the protocol's
    /// authoritative review-plan policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the key or value is not valid for a frozen review
    /// plan, including controller-owned and Git-isolation keys.
    pub fn validate_environment_entry(key: &str, value: &str) -> Result<(), ControlError> {
        let key = ReviewEnvironmentKey::new(key.to_owned()).map_err(ControlError::protocol)?;
        ReviewPlan::validate_declared_environment_entry(&key, value).map_err(ControlError::protocol)
    }
}

impl ActorProfileSettings {
    fn actor_role(&self) -> Result<ActorRole, ControlError> {
        ActorRole::new(self.role.clone()).map_err(ControlError::protocol)
    }

    fn snapshot(&self) -> Result<ActorProfileSnapshot, ControlError> {
        let capabilities = self
            .capabilities
            .iter()
            .map(|value| CapabilityId::new(value.clone()).map_err(ControlError::protocol))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let snapshot = ActorProfileSnapshot {
            name: ActorProfileName::new(self.name.clone()).map_err(ControlError::protocol)?,
            capabilities,
        };
        snapshot.validate().map_err(ControlError::protocol)?;
        Ok(snapshot)
    }

    fn runtime_launch(&self) -> Result<(&str, &str, &str), ControlError> {
        let ActorLaunchSettings::Runtime {
            runtime,
            model,
            reasoning_effort,
        } = &self.launch
        else {
            return Err(ControlError::new(
                "actor_profile_not_launchable",
                format!(
                    "actor profile `{}` is bound to an existing session and has no runtime launch configuration",
                    self.name
                ),
            )
            .with_details(json!({
                "actor_profile": self.name,
                "launch": { "applicable": false, "mode": "bound" },
            })));
        };
        Ok((runtime, model, reasoning_effort))
    }

    fn launch_summary(&self) -> Value {
        match &self.launch {
            ActorLaunchSettings::Bound => json!({
                "applicable": false,
                "mode": "bound",
            }),
            ActorLaunchSettings::Runtime {
                runtime,
                model,
                reasoning_effort,
            } => json!({
                "applicable": true,
                "mode": "runtime",
                "runtime": runtime,
                "model": model,
                "reasoning_effort": reasoning_effort,
            }),
        }
    }
}

impl TeamProfileSettings {
    fn snapshot(&self) -> Result<TeamProfileSnapshot, ControlError> {
        let snapshot = TeamProfileSnapshot {
            name: TeamProfileName::new(self.name.clone()).map_err(ControlError::protocol)?,
            actor_profile: ActorProfileName::new(self.actor_profile.clone())
                .map_err(ControlError::protocol)?,
            desired_instances: u16::try_from(self.desired_instances).map_err(|_| {
                ControlError::new(
                    "invalid_profile_configuration",
                    "team profile desired_instances exceeds the supported range",
                )
            })?,
            assignment_policy: AssignmentPolicyId::new(self.assignment_policy.clone())
                .map_err(ControlError::protocol)?,
        };
        snapshot.validate().map_err(ControlError::protocol)?;
        Ok(snapshot)
    }
}

/// Effective, already validated inputs supplied by the CLI configuration layer.
#[derive(Clone, Debug)]
pub struct ControlSettings {
    pub workspace: PathBuf,
    pub state_directory: PathBuf,
    pub config_source: String,
    pub integration_branch: Option<String>,
    pub backend: String,
    pub persist_profile_snapshots: bool,
    pub primary_profile: String,
    pub default_team_profile: String,
    pub agent_profiles: BTreeMap<String, ActorProfileSettings>,
    pub team_profiles: BTreeMap<String, TeamProfileSettings>,
    pub runtime_adapter_availability: BTreeMap<String, bool>,
    pub max_panes_per_tab: u16,
    pub place_first_implementation_with_primary: bool,
    pub tab_label_strategy: String,
    pub pane_label_template: String,
    pub split_direction: String,
    pub focus_new_sessions: bool,
    pub primary_lease_seconds: u32,
    pub actor_heartbeat_seconds: u32,
    pub review: ReviewSettings,
}

/// One invocation's embedded control-plane handle.
pub struct ControlPlane {
    settings: ControlSettings,
    identity: WorkspaceIdentity,
    store: StateStore,
    sessions: SessionDriver,
    profile_runtimes: BTreeMap<String, Arc<dyn AgentRuntime>>,
    caller_identity: CallerIdentityDriver,
    review: ReviewRunner,
    #[cfg(test)]
    test_authenticated_actor: Mutex<Option<ActorRef>>,
}

/// Preserves a confirmed sub-floor state store without opening its domain
/// snapshot through the current controller.
///
/// # Errors
///
/// Returns an error when the store is not sub-floor, the exact blocker digest
/// changed, recent coordination may still be live, or preservation fails.
pub fn preserve_subfloor_state(
    mut settings: ControlSettings,
    confirmed_blocker_digest: &str,
    operation_id: &str,
) -> Result<Value, ControlError> {
    validate_operation_id(operation_id)?;
    if confirmed_blocker_digest.len() != 64
        || !confirmed_blocker_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ControlError::new(
            "invalid_blocker_digest",
            "confirmed blocker digest must be a 64-character hexadecimal SHA-256 digest",
        ));
    }
    let git = resolve_git_executable()?;
    let identity = WorkspaceIdentity::discover_with_git(&settings.workspace, &git)?;
    settings.workspace = identity.root().to_path_buf();
    let sessions = SessionDriver::new(&settings.backend)?;
    StateStore::preserve_subfloor(
        &settings.state_directory,
        now_ms()?,
        confirmed_blocker_digest,
        operation_id,
        |record| sessions.status(record),
    )
}

/// Reads immutable decision history without opening or hydrating the mutable
/// domain snapshot.
///
/// This is the narrow reporting entry point used by `agsv decision list`.
/// Workspace discovery and schema admission remain identical to ordinary
/// control-plane startup, but the report queries only the indexed immutable
/// decision tables.
///
/// # Errors
///
/// Returns an error when workspace discovery or schema admission fails, when
/// the report arguments do not select exactly one supported filter, or when
/// immutable decision history fails validation.
pub fn decision_report(settings: &ControlSettings, request: &Value) -> Result<Value, ControlError> {
    let git = resolve_git_executable()?;
    let identity = WorkspaceIdentity::discover_with_git(&settings.workspace, &git)?;
    let initial = Supervisor::new(identity.workspace_id().clone(), PolicyRevision::INITIAL);
    let store = StateStore::open_decision_report(
        &settings.state_directory,
        identity.workspace_id().as_str(),
        &initial.snapshot(),
        now_ms()?,
    )?;
    query_decision_report(&store, request)
}

impl ControlPlane {
    /// Opens or initializes durable state without modifying the repository worktree.
    ///
    /// # Errors
    ///
    /// Returns an error when workspace discovery, path validation, or state
    /// initialization fails.
    pub fn open(settings: ControlSettings) -> Result<Self, ControlError> {
        Self::open_with_runtime_registry(settings, &RuntimeRegistry::new())
    }

    fn open_with_runtime_registry(
        mut settings: ControlSettings,
        registry: &impl RuntimeCatalog,
    ) -> Result<Self, ControlError> {
        let git = resolve_git_executable()?;
        let identity = WorkspaceIdentity::discover_with_git(&settings.workspace, &git)?;
        settings.workspace = identity.root().to_path_buf();
        if let Ok(value) = std::env::var("AGSV_SESSION_BACKEND") {
            settings.backend = value;
        }
        validate_profile_settings(&settings)?;
        for runtime in settings.runtime_adapter_availability.keys() {
            select_runtime(registry, runtime)?;
        }
        let profile_runtimes = settings
            .agent_profiles
            .iter()
            .map(|(name, profile)| {
                let ActorLaunchSettings::Runtime { runtime, .. } = &profile.launch else {
                    return Ok(None);
                };
                if settings.runtime_adapter_availability.get(runtime) == Some(&false) {
                    return Err(ControlError::new(
                        "runtime_adapter_disabled",
                        format!(
                            "actor profile `{name}` selects disabled runtime adapter `{runtime}`"
                        ),
                    )
                    .with_details(json!({
                        "actor_profile": name,
                        "configured_runtime": runtime,
                        "availability_field": format!("runtime_adapters.{runtime}"),
                        "available": false,
                    }))
                    .with_hint("enable the runtime adapter or select another runtime"));
                }
                select_runtime(registry, runtime).map(|runtime| Some((name.clone(), runtime)))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<BTreeMap<_, _>>();
        let initial = Supervisor::new(identity.workspace_id().clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            &settings.state_directory,
            identity.workspace_id().as_str(),
            &initial.snapshot(),
            now_ms()?,
        )?;
        let sessions = SessionDriver::new(&settings.backend)?;
        let caller_identity = CallerIdentityDriver::from_environment(
            sessions.name(),
            sessions.allows_insecure_actor_identity(),
        );
        let review = ReviewRunner::new_with_git(
            identity.repository_root(),
            store
                .path()
                .parent()
                .expect("state database always has a containing directory"),
            settings.review.clone(),
            git,
        )?;
        Ok(Self {
            settings,
            identity,
            store,
            sessions,
            profile_runtimes,
            caller_identity,
            review,
            #[cfg(test)]
            test_authenticated_actor: Mutex::new(None),
        })
    }

    /// Executes one stable CLI operation and returns its machine-readable payload.
    ///
    /// # Errors
    ///
    /// Returns a stable error when arguments, authorization, persistence,
    /// protocol transitions, Git evidence, or the session backend fails.
    pub fn execute(&self, operation: &str, request: &Value) -> Result<Value, ControlError> {
        prevalidate_before_authentication(operation, request)?;
        // Mutations and heartbeats share this workspace gate; shutdown alone is
        // exclusive so earlier admitted work finishes before its durable
        // terminal commit. Public inspection reads bypass the gate. A separate
        // actor-scoped guard still orders a stopped binding's own heartbeat or
        // bootstrap against its backend stop, while another actor can renew its
        // lease during that slow dispatch.
        let mut operation_guards = self.acquire_operation_guards(operation, request)?;
        let caller_fence = if operation == "decision.list" {
            None
        } else {
            self.caller_mutation_fence()?
        };
        #[cfg(test)]
        if let Some(observer) = TEST_AFTER_CALLER_FENCE
            .lock()
            .map_err(|_| ControlError::database("test caller-fence observer mutex poisoned"))?
            .get(self.identity.workspace_id().as_str())
            .cloned()
        {
            observer(operation);
        }
        if let Some(caller_fence) = caller_fence.as_ref() {
            let refuses_operation = match caller_fence {
                CallerMutationFence::Stopped(_) => {
                    mutation_operation(operation) && operation != "actor.shutdown"
                }
                CallerMutationFence::Superseded(_) | CallerMutationFence::SupersededPrimary(_) => {
                    !public_read_operation(operation)
                }
            };
            if refuses_operation {
                return Err(caller_fence.error());
            }
        }
        if caller_fence.is_none() && caller_authentication_required(operation, request) {
            self.caller_actor_ref(request.get("actor").and_then(Value::as_str))?;
        }
        if caller_fence.is_none() && !public_read_operation(operation) {
            self.expire_stale_actors(operation_guards.expire_primary)?;
        }
        if caller_fence.is_none() && caller_authentication_required(operation, request) {
            self.recover_expired_primary_binding(operation_guards.primary_exclusive)?;
        }
        if primary_operation(operation) {
            self.authenticate_primary()?;
        } else if operation == "review.show" {
            self.authenticate_primary_read_only()?;
        } else if actor_operation(operation) {
            self.authenticated_actor_ref(request.get("actor").and_then(Value::as_str))?;
        }
        let result = match operation {
            "start" => self.start(request),
            "stop" => self.stop(request),
            "status" => self.status(),
            "doctor" => self.doctor(),
            "attach" => Err(ControlError::unsupported(
                operation,
                "the selected session adapter has no non-interactive attach primitive",
            )),
            "events" => self.events(request),
            "context" => self.context(request),
            "reconcile" => self.reconcile(),
            "team.create" => self.team_create(request),
            "team.list" => self.team_list(),
            "team.show" => self.team_show(request),
            "team.update" => self.team_update(request),
            "team.pause" => self.team_status(request, TeamStatus::Paused, operation),
            "team.resume" => self.team_status(request, TeamStatus::Active, operation),
            "team.close" => self.team_close(request),
            "actor.list" => self.actor_list(request),
            "actor.show" => self.actor_show(request),
            "actor.stop" => self.actor_stop(request),
            "actor.shutdown" => self.actor_shutdown(request, &mut operation_guards),
            "actor.replace" => self.actor_replace(request),
            "run.create" => self.run_create(request),
            "run.list" => self.run_list(request),
            "run.show" => self.run_show(request),
            "run.pause" => self.run_transition(request, RunControlAction::Pause, operation),
            "run.resume" => self.run_transition(request, RunControlAction::Resume, operation),
            "run.cancel" => self.cancel_by_run(request),
            "request.create" => self.request_create(request),
            "request.list" => self.request_list(request),
            "request.show" => self.request_show(request),
            "request.claim" => self.request_claim(request),
            "request.block" => self.request_block(request),
            "request.complete" => self.request_complete(request),
            "request.cancel" => self.request_cancel(request),
            "message.send" => self.message_send(request),
            "message.inbox" => self.message_inbox(request),
            "message.ack" => self.message_ack(request),
            "decision.list" => self.decision_list(request),
            "decision.submit" => self.decision_submit(request),
            "review.begin" => self.review_begin(request),
            "review.verify" => self.review_verify(request),
            "review.show" => self.review_show(request),
            _ => Err(ControlError::unsupported(operation, "unknown operation")),
        }?;
        if (presentation_refresh_operation(operation)
            || (operation == "context" && context_bootstrap_requested(request)))
            && (caller_fence.is_none()
                || (operation == "context" && context_bootstrap_requested(request)))
        {
            let _ = self.refresh_all_presentations(force_presentation_refresh(operation, request));
        }
        Ok(result)
    }

    #[must_use]
    pub fn identity(&self) -> &WorkspaceIdentity {
        &self.identity
    }

    #[must_use]
    pub fn state_path(&self) -> &Path {
        self.store.path()
    }

    fn runtime_config(profile: &ActorProfileSettings) -> Result<RuntimeConfig, ControlError> {
        let (_, model, reasoning_effort) = profile.runtime_launch()?;
        Ok(RuntimeConfig::new(
            model.to_owned(),
            reasoning_effort.to_owned(),
        ))
    }

    fn runtime_for_profile(
        &self,
        profile: &ActorProfileSettings,
    ) -> Result<Arc<dyn AgentRuntime>, ControlError> {
        profile.runtime_launch()?;
        self.profile_runtimes
            .get(&profile.name)
            .cloned()
            .ok_or_else(|| {
                ControlError::new(
                    "actor_profile_unavailable",
                    format!(
                        "actor profile `{}` has no validated runtime adapter",
                        profile.name
                    ),
                )
            })
    }

    fn primary_profile(&self) -> Result<&ActorProfileSettings, ControlError> {
        selected_primary_profile(&self.settings)
    }

    fn selected_team_profile(&self) -> Result<&TeamProfileSettings, ControlError> {
        selected_team_profile(&self.settings)
    }

    fn team_profile(&self, name: &str) -> Result<&TeamProfileSettings, ControlError> {
        self.settings.team_profiles.get(name).ok_or_else(|| {
            ControlError::new(
                "unknown_team_profile",
                format!("team profile `{name}` is not configured"),
            )
            .with_details(json!({
                "team_profile": name,
                "available_team_profiles": self.settings.team_profiles.keys().collect::<Vec<_>>(),
            }))
            .with_hint("choose one of the configured team profiles")
        })
    }

    fn selected_team_actor_profile(&self) -> Result<&ActorProfileSettings, ControlError> {
        selected_team_actor_profile(&self.settings)
    }

    fn selected_team_runtime(&self) -> Result<Arc<dyn AgentRuntime>, ControlError> {
        self.runtime_for_profile(self.selected_team_actor_profile()?)
    }

    fn profiles_summary(&self) -> Value {
        let agent_profiles = self
            .settings
            .agent_profiles
            .iter()
            .map(|(name, profile)| {
                (
                    name.clone(),
                    json!({
                        "name": profile.name,
                        "role": profile.role,
                        "capabilities": profile.capabilities,
                        "launch": profile.launch_summary(),
                        "role_file": profile.role_file,
                        "role_source": profile.role_source,
                        "role_bytes": profile.role_instructions.len(),
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let team_profiles = self
            .settings
            .team_profiles
            .iter()
            .map(|(name, profile)| {
                (
                    name.clone(),
                    json!({
                        "name": profile.name,
                        "actor_profile": profile.actor_profile,
                        "desired_instances": profile.desired_instances,
                        "assignment_policy": profile.assignment_policy,
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        json!({
            "persist_snapshots": self.settings.persist_profile_snapshots,
            "selected_primary": self.settings.primary_profile,
            "selected_default_team": self.settings.default_team_profile,
            "agent_profiles": agent_profiles,
            "team_profiles": team_profiles,
            "runtime_adapters": self.settings.runtime_adapter_availability,
            "desired_instance_reconciliation": "enforced",
            "assignment_policy_enforcement": "enforced",
            "supported_assignment_policies": SUPPORTED_ASSIGNMENT_POLICIES,
        })
    }

    fn redacted_observability_summary(
        &self,
        supervisor: &Supervisor,
    ) -> Result<Value, ControlError> {
        let selected_primary = self.primary_profile()?;
        let selected_team = self.selected_team_profile()?;
        let selected_team_actor = self.selected_team_actor_profile()?;
        let selected_runtime = self.selected_team_runtime()?;
        let caller = self.doctor_caller_context()?;
        let all_profile_capabilities = self
            .settings
            .agent_profiles
            .iter()
            .map(|(name, profile)| {
                let runtime_id = match &profile.launch {
                    ActorLaunchSettings::Bound => None,
                    ActorLaunchSettings::Runtime { .. } => {
                        Some(self.runtime_for_profile(profile)?.id().to_string())
                    }
                };
                Ok::<_, ControlError>((
                    name.clone(),
                    json!({
                        "role": profile.role,
                        "capabilities": profile.capabilities,
                        "launch": profile.launch_summary(),
                        "runtime_id": runtime_id,
                    }),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, ControlError>>()?;
        let effective_assignment_policies = supervisor
            .snapshot()
            .teams
            .iter()
            .map(|team| {
                let (_, assignment_policy) = Self::effective_team_intent(team)?;
                Ok(json!({
                    "team_id": team.team_id,
                    "assignment_policy": assignment_policy,
                }))
            })
            .collect::<Result<Vec<_>, ControlError>>()?;
        let durable_session_owners = self
            .store
            .sessions()?
            .into_iter()
            .map(|session| {
                json!({
                    "actor_id": session.actor_id,
                    "team_id": session.team_id,
                    "backend": session.backend,
                    "runtime_id": session.runtime,
                    "status": session.status,
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({
            "selected_runtime_id": selected_runtime.id().as_str(),
            "configured_session_backend": self.sessions.configured_backend(),
            "durable_session_owners": durable_session_owners,
            "caller_identity": {
                "identity_backend": caller["identity_backend"],
                "required": caller["required"],
                "ready": caller["ready"],
            },
            "profile_capabilities": {
                "selected_primary": {
                    "profile": selected_primary.name,
                    "role": selected_primary.role,
                    "capabilities": selected_primary.capabilities,
                },
                "selected_default_team": {
                    "team_profile": selected_team.name,
                    "actor_profile": selected_team_actor.name,
                    "role": selected_team_actor.role,
                    "capabilities": selected_team_actor.capabilities,
                },
                "all": all_profile_capabilities,
            },
            "assignment_policies": {
                "selected_default": selected_team.assignment_policy,
                "supported": SUPPORTED_ASSIGNMENT_POLICIES,
                "effective_by_team": effective_assignment_policies,
            },
        }))
    }

    fn actor_profile(&self, actor: &Actor) -> Result<&ActorProfileSettings, ControlError> {
        let profile_name = if let Some(snapshot) = &actor.profile {
            snapshot.name.as_str()
        } else {
            match &actor.role {
                ActorRole::Primary => LEGACY_PRIMARY_PROFILE,
                ActorRole::Implementation => LEGACY_IMPLEMENTATION_PROFILE,
                ActorRole::Custom(_) => {
                    return Err(ControlError::new(
                        "actor_profile_missing",
                        format!(
                            "custom-role actor `{}` has no durable profile snapshot",
                            actor.actor_id
                        ),
                    ));
                }
            }
        };
        let configured = self
            .settings
            .agent_profiles
            .get(profile_name)
            .ok_or_else(|| {
                ControlError::new(
                    "actor_profile_unavailable",
                    format!(
                        "actor `{}` uses profile `{profile_name}`, which is not configured",
                        actor.actor_id
                    ),
                )
            })?;
        if let Some(snapshot) = &actor.profile {
            let configured_snapshot = configured.snapshot()?;
            if actor.role.as_str() != configured.role || snapshot != &configured_snapshot {
                return Err(ControlError::new(
                    "actor_profile_mismatch",
                    format!(
                        "actor `{}` profile metadata differs from current configuration",
                        actor.actor_id
                    ),
                )
                .with_details(json!({
                    "actor_id": actor.actor_id,
                    "persisted_profile": snapshot,
                    "persisted_role": actor.role,
                    "configured_profile": configured.name,
                    "configured_role": configured.role,
                    "configured_capabilities": configured.capabilities,
                })));
            }
        } else {
            let (expected_role, expected_capability) = match &actor.role {
                ActorRole::Primary => (ActorRole::Primary, HUMAN_FACING_PRIMARY_CAPABILITY),
                ActorRole::Implementation => (
                    ActorRole::Implementation,
                    IMPLEMENTATION_EXECUTION_CAPABILITY,
                ),
                ActorRole::Custom(_) => unreachable!("custom legacy actors were rejected above"),
            };
            validate_legacy_actor_profile(
                configured,
                profile_name,
                &expected_role,
                expected_capability,
            )?;
        }
        Ok(configured)
    }

    fn configured_team_control_profile(
        &self,
        requested_profile: Option<&str>,
    ) -> Result<(TeamProfileSettings, ActorProfileSettings, ProfileMode), ControlError> {
        let team_profile = match requested_profile {
            Some(name) => self.team_profile(name)?,
            None => self.selected_team_profile()?,
        };
        let actor_profile = self
            .settings
            .agent_profiles
            .get(&team_profile.actor_profile)
            .ok_or_else(|| {
                ControlError::new(
                    "invalid_profile_configuration",
                    format!(
                        "team profile `{}` references unknown actor profile `{}`",
                        team_profile.name, team_profile.actor_profile
                    ),
                )
            })?;
        Ok((
            team_profile.clone(),
            actor_profile.clone(),
            if self.settings.persist_profile_snapshots {
                ProfileMode::Snapshotted
            } else {
                ProfileMode::Legacy
            },
        ))
    }

    fn team_control_profile(
        &self,
        team: Option<&Team>,
        requested_profile: Option<&str>,
    ) -> Result<(TeamProfileSettings, ActorProfileSettings, ProfileMode), ControlError> {
        let Some(team) = team else {
            return self.configured_team_control_profile(requested_profile);
        };
        let Some(snapshot) = &team.profile else {
            if let Some(name) = requested_profile {
                if name != LEGACY_IMPLEMENTATION_PROFILE {
                    return Err(team_profile_mismatch(
                        &self.settings,
                        team,
                        LEGACY_IMPLEMENTATION_PROFILE,
                        name,
                    ));
                }
            }
            let actor_profile = self
                .settings
                .agent_profiles
                .get(LEGACY_IMPLEMENTATION_PROFILE)
                .ok_or_else(|| {
                    ControlError::new(
                        "actor_profile_unavailable",
                        format!(
                            "profileless team `{}` requires the legacy `{LEGACY_IMPLEMENTATION_PROFILE}` actor profile",
                            team.team_id
                        ),
                    )
                })?
                .clone();
            validate_legacy_actor_profile(
                &actor_profile,
                LEGACY_IMPLEMENTATION_PROFILE,
                &ActorRole::Implementation,
                IMPLEMENTATION_EXECUTION_CAPABILITY,
            )?;
            let desired_instances = u32::try_from(team.actors.len().max(1)).map_err(|_| {
                ControlError::new(
                    "invalid_profile_configuration",
                    "legacy team actor count exceeds the supported range",
                )
            })?;
            return Ok((
                TeamProfileSettings {
                    name: LEGACY_IMPLEMENTATION_PROFILE.to_owned(),
                    actor_profile: LEGACY_IMPLEMENTATION_PROFILE.to_owned(),
                    desired_instances,
                    assignment_policy: "first_healthy".to_owned(),
                },
                actor_profile,
                ProfileMode::Legacy,
            ));
        };
        if let Some(name) = requested_profile {
            if snapshot.name.as_str() != name {
                return Err(team_profile_mismatch(
                    &self.settings,
                    team,
                    snapshot.name.as_str(),
                    name,
                ));
            }
        }
        validate_assignment_policy(snapshot.assignment_policy.as_str())?;
        let actor_profile = self
            .settings
            .agent_profiles
            .get(snapshot.actor_profile.as_str())
            .ok_or_else(|| {
                ControlError::new(
                    "actor_profile_unavailable",
                    format!(
                        "team `{}` uses actor profile `{}`, which is not configured",
                        team.team_id, snapshot.actor_profile
                    ),
                )
            })?
            .clone();
        actor_profile.snapshot()?;
        Ok((
            TeamProfileSettings {
                name: snapshot.name.to_string(),
                actor_profile: snapshot.actor_profile.to_string(),
                desired_instances: u32::from(snapshot.desired_instances),
                assignment_policy: snapshot.assignment_policy.to_string(),
            },
            actor_profile,
            ProfileMode::Snapshotted,
        ))
    }

    fn select_request_actor<'a>(
        &self,
        supervisor: &'a Supervisor,
        team: &Team,
    ) -> Result<&'a Actor, ControlError> {
        let (desired_instances, policy) = Self::effective_team_intent(team)?;
        let desired = desired_actor_ids(team, desired_instances)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut first_profile_error = None;
        let mut candidates = Vec::new();
        for actor_id in team
            .actors
            .iter()
            .filter(|actor_id| desired.contains(*actor_id))
        {
            let Some(actor) = supervisor.actor(actor_id) else {
                continue;
            };
            if actor.status != ActorStatus::Healthy
                || !actor.has_capability(IMPLEMENTATION_EXECUTION_CAPABILITY)
            {
                continue;
            }
            match self.actor_profile(actor) {
                Ok(_) => candidates.push(actor),
                Err(error) if first_profile_error.is_none() => first_profile_error = Some(error),
                Err(_) => {}
            }
        }
        if candidates.is_empty() {
            return Err(first_profile_error.unwrap_or_else(|| {
                ControlError::new(
                    "no_healthy_actor",
                    "team has no healthy implementation actor",
                )
            }));
        }
        if policy == "first_healthy" {
            return Ok(candidates[0]);
        }
        let requests = supervisor.snapshot().requests;
        candidates
            .into_iter()
            .enumerate()
            .min_by_key(|(index, actor)| {
                let actor_ref = actor.actor_ref();
                let wip = requests
                    .iter()
                    .filter(|request| {
                        !request.status.is_terminal()
                            && request
                                .assignment
                                .as_ref()
                                .is_some_and(|assignment| assignment.actor == actor_ref)
                    })
                    .count();
                (wip, *index)
            })
            .map(|(_, actor)| actor)
            .ok_or_else(|| {
                ControlError::new(
                    "no_healthy_actor",
                    "team has no healthy implementation actor",
                )
            })
    }

    fn effective_team_intent(team: &Team) -> Result<(usize, String), ControlError> {
        if let Some(profile) = &team.profile {
            validate_assignment_policy(profile.assignment_policy.as_str())?;
            return Ok((
                usize::from(profile.desired_instances),
                profile.assignment_policy.to_string(),
            ));
        }
        Ok((team.actors.len().max(1), "first_healthy".to_owned()))
    }

    fn ensure_directive_delivery_capacity(
        supervisor: &Supervisor,
        envelope: &Envelope,
    ) -> Result<(), ControlError> {
        if !matches!(envelope.message, Message::Directive(_)) {
            return Ok(());
        }
        let team_id = envelope.team_id.as_ref().ok_or_else(|| {
            ControlError::invalid_request("message kind `directive` requires team context")
        })?;
        let team = supervisor
            .team(team_id)
            .ok_or_else(|| ControlError::not_found("team", team_id.as_str()))?;
        match team.status {
            TeamStatus::Closed => {
                return Err(ControlError::new(
                    "team_closed",
                    format!("closed team `{team_id}` cannot receive a directive"),
                )
                .with_details(json!({ "team_id": team_id, "status": team.status })));
            }
            TeamStatus::Retired => {
                return Err(ControlError::new(
                    "team_retired",
                    format!("retired team `{team_id}` cannot receive a directive"),
                )
                .with_details(json!({ "team_id": team_id, "status": team.status })));
            }
            TeamStatus::Active | TeamStatus::Paused | TeamStatus::Closing => {}
        }
        let (desired_instances, _) = Self::effective_team_intent(team)?;
        if desired_instances == 0 {
            return Err(ControlError::new(
                "team_zero_capacity",
                format!("team `{team_id}` has zero configured recipient capacity"),
            )
            .with_hint("increase the team profile's desired_instances before sending a directive")
            .with_details(json!({
                "team_id": team_id,
                "desired_instances": desired_instances,
            })));
        }
        if matches!(envelope.target, MessageTarget::Team(_))
            && !team
                .actors
                .iter()
                .take(desired_instances)
                .filter_map(|actor_id| supervisor.actor(actor_id))
                .any(|actor| actor.status != ActorStatus::Revoked)
        {
            return Err(ControlError::new(
                "team_recipient_unavailable",
                format!("team `{team_id}` has no durable logical recipient for this directive"),
            )
            .with_hint("run `agsv --json reconcile` to register desired actor capacity, then retry")
            .with_details(json!({
                "team_id": team_id,
                "desired_instances": desired_instances,
            })));
        }
        Ok(())
    }

    fn ensure_desired_team_actor(
        supervisor: &Supervisor,
        team_id: &TeamId,
        actor_id: &ActorId,
    ) -> Result<(), ControlError> {
        let team = supervisor
            .team(team_id)
            .ok_or_else(|| ControlError::not_found("team", team_id.as_str()))?;
        let (desired_instances, _) = Self::effective_team_intent(team)?;
        let desired_actor_ids = desired_actor_ids(team, desired_instances)?;
        if desired_actor_ids.contains(actor_id) {
            return Ok(());
        }
        Err(ControlError::new(
            "actor_not_desired",
            "surplus actor instances cannot be replaced or relaunched",
        )
        .with_details(json!({
            "team_id": team_id,
            "actor_id": actor_id,
            "desired_instances": desired_instances,
            "desired_actor_ids": desired_actor_ids,
        })))
    }

    #[allow(clippy::too_many_lines)]
    fn assignment_instance_summary(&self, supervisor: &Supervisor) -> Result<Value, ControlError> {
        let sessions = self
            .store
            .sessions()?
            .into_iter()
            .map(|session| (session.actor_id.clone(), session))
            .collect::<BTreeMap<_, _>>();
        let snapshot = supervisor.snapshot();
        let teams = snapshot
            .teams
            .iter()
            .map(|team| {
                let (configured_desired_instances, effective_assignment_policy) =
                    Self::effective_team_intent(team)?;
                let desired_instances = if matches!(
                    team.status,
                    TeamStatus::Closing | TeamStatus::Closed | TeamStatus::Retired
                ) {
                    0
                } else {
                    configured_desired_instances
                };
                let desired_actor_ids = desired_actor_ids(team, desired_instances)?;
                let desired = desired_actor_ids.iter().cloned().collect::<BTreeSet<_>>();
                let actors = team
                    .actors
                    .iter()
                    .filter_map(|actor_id| supervisor.actor(actor_id))
                    .map(|actor| {
                        let actor_ref = actor.actor_ref();
                        let assigned_nonterminal_request_ids = snapshot
                            .requests
                            .iter()
                            .filter(|request| {
                                !request.status.is_terminal()
                                    && request.assignment.as_ref().is_some_and(|assignment| {
                                        assignment.actor == actor_ref
                                    })
                            })
                            .map(|request| request.request_id.clone())
                            .collect::<Vec<_>>();
                        let session = sessions.get(actor.actor_id.as_str());
                        json!({
                            "actor_ref": actor_ref,
                            "status": actor.status,
                            "desired": desired.contains(&actor.actor_id),
                            "wip_count": assigned_nonterminal_request_ids.len(),
                            "assigned_nonterminal_request_ids": assigned_nonterminal_request_ids,
                            "session_state": session.map_or("missing", |record| record.status.as_str()),
                        })
                    })
                    .collect::<Vec<_>>();
                let missing_instances = desired_actor_ids
                    .iter()
                    .filter(|actor_id| {
                        let Some(actor) = supervisor.actor(actor_id) else {
                            return true;
                        };
                        let session = sessions.get(actor_id.as_str());
                        actor.status != ActorStatus::Healthy
                            || session.is_none_or(|record| {
                                record.external_id.is_none()
                                    || !session_is_present(record.status.as_str())
                            })
                    })
                    .count();
                let surplus_instances = team
                    .actors
                    .iter()
                    .skip(desired_instances)
                    .filter(|actor_id| {
                        let actor_is_running = supervisor
                            .actor(actor_id)
                            .is_some_and(|actor| actor.status != ActorStatus::Stopped);
                        let session_is_running = sessions.get(actor_id.as_str()).is_some_and(
                            |session| {
                                session.external_id.is_some()
                                    && !matches!(session.status.as_str(), "missing" | "stopped")
                            },
                        );
                        actor_is_running || session_is_running
                    })
                    .count();
                Ok(json!({
                    "team_id": team.team_id,
                    "team_status": team.status,
                    "effective_assignment_policy": effective_assignment_policy,
                    "configured_desired_instances": configured_desired_instances,
                    "desired_instances": desired_instances,
                    "desired_actor_ids": desired_actor_ids,
                    "actual_instances": team.actors.iter().filter(|actor_id| {
                        supervisor.actor(actor_id).is_some_and(|actor| actor.status != ActorStatus::Stopped)
                            || sessions.get(actor_id.as_str()).is_some_and(|session| {
                                session.external_id.is_some()
                                    && !matches!(session.status.as_str(), "missing" | "stopped")
                            })
                    }).count(),
                    "missing_instances": missing_instances,
                    "surplus_instances": surplus_instances,
                    "converged": missing_instances == 0 && surplus_instances == 0,
                    "actors": actors,
                }))
            })
            .collect::<Result<Vec<_>, ControlError>>()?;
        Ok(json!({ "teams": teams }))
    }

    fn start(&self, request: &Value) -> Result<Value, ControlError> {
        let args: StartArgs = decode(request)?;
        if args.foreground {
            return Err(ControlError::unsupported(
                "start --foreground",
                "v0.1 is an embedded control plane and does not run a foreground daemon",
            ));
        }
        let revision = self
            .store
            .set_controller(true, "controller.started", now_ms()?)?;
        Ok(json!({
            "mode": "embedded",
            "active": true,
            "revision": revision,
            "workspace_id": self.identity.workspace_id(),
            "config_source": self.settings.config_source,
            "state_path": self.store.path(),
        }))
    }

    fn stop(&self, request: &Value) -> Result<Value, ControlError> {
        let args: StopArgs = decode(request)?;
        let (_, supervisor, active) = self.store.load()?;
        if !active {
            return Ok(json!({ "mode": "embedded", "active": false, "already_stopped": true }));
        }
        let healthy = supervisor
            .snapshot()
            .actors
            .into_iter()
            .filter(|actor| actor.status == ActorStatus::Healthy)
            .map(|actor| actor.actor_id.to_string())
            .collect::<Vec<_>>();
        if !args.force && !healthy.is_empty() {
            return Err(ControlError::new(
                "active_actors",
                "controller has healthy actors; pass --force to stop the embedded controller marker",
            )
            .with_details(json!({ "healthy_actor_ids": healthy })));
        }
        let revision = self
            .store
            .set_controller(false, "controller.stopped", now_ms()?)?;
        Ok(json!({
            "mode": "embedded",
            "active": false,
            "revision": revision,
            "actors_left_running": healthy,
        }))
    }

    fn status(&self) -> Result<Value, ControlError> {
        let (revision, supervisor, active) = self.store.load()?;
        let observability_integrity = self.store.observability_integrity_health()?;
        let observed_at_ms = now_ms()?;
        let assignment_instances = self.assignment_instance_summary(&supervisor)?;
        let observability = self.redacted_observability_summary(&supervisor)?;
        let snapshot = supervisor.snapshot();
        let base_reporting = BaseStalenessContext::observe(
            self.review.git_executable(),
            self.identity.repository_root(),
            self.settings.integration_branch.as_deref(),
            observed_at_ms,
        );
        let team_reporting = self.team_reporting_context()?;
        let teams = snapshot
            .teams
            .iter()
            .map(|team| self.team_value(team, &supervisor, observed_at_ms, &team_reporting))
            .collect::<Result<Vec<_>, _>>()?;
        let request_bases = snapshot
            .requests
            .iter()
            .map(|request| {
                let message = self.store.message_body(
                    &request.specification.message_id,
                    &request.specification.payload_digest,
                )?;
                let Message::ImplementationRequest(specification) = message else {
                    return Err(ControlError::new(
                        "request_specification_missing",
                        "request specification message has an unexpected kind",
                    ));
                };
                let staleness = base_reporting.request_report(
                    specification.base_sha.as_str(),
                    request
                        .candidate
                        .as_ref()
                        .map(|candidate| candidate.sha.as_str()),
                );
                Ok(json!({
                    "request_id": request.request_id,
                    "base_sha": specification.base_sha,
                    "base_source": specification.base_source,
                    "staleness": staleness,
                }))
            })
            .collect::<Result<Vec<_>, ControlError>>()?;
        Ok(json!({
            "mode": "embedded",
            "active": active,
            "workspace_id": self.identity.workspace_id(),
            "workspace": self.identity.root(),
            "git_common_dir": self.identity.git_common_dir(),
            "config_source": self.settings.config_source,
            "profiles": self.profiles_summary(),
            "assignment_instances": assignment_instances,
            "observability": observability,
            "observability_integrity": observability_integrity,
            "state_path": self.store.path(),
            "revision": revision,
            "primary": snapshot.active_primary,
            "primary_epoch": snapshot.primary_epoch,
            "primary_lease": self.primary_lease_summary(&supervisor, observed_at_ms),
            "teams": teams,
            "request_bases": request_bases,
            "integration_target": base_reporting.target_report(),
            "presentation": self.presentation_diagnostics()?,
            "review": self.review_capability_summary(),
            "counts": {
                "teams": snapshot.teams.len(),
                "actors": snapshot.actors.len(),
                "runs": snapshot.runs.len(),
                "requests": snapshot.requests.len(),
                "deliveries": snapshot.deliveries.len(),
            },
        }))
    }

    #[allow(clippy::too_many_lines)]
    fn doctor(&self) -> Result<Value, ControlError> {
        let (_, supervisor, _) = self.store.verify_archive_integrity()?;
        let observability_integrity_health = self.store.observability_integrity_health()?;
        let (
            observability_integrity_verified,
            observability_integrity_report,
            observability_integrity_error,
        ) = match self.store.verify_observability_integrity() {
            Ok(report) => (true, Some(report), None),
            Err(error) => (
                false,
                None,
                Some(json!({
                    "code": error.code,
                    "message": error.message,
                    "hint": error.hint,
                    "details": error.details,
                })),
            ),
        };
        let observability_integrity_healthy = observability_integrity_health.checkpoint_matches
            && observability_integrity_health.incident.is_none()
            && observability_integrity_verified;
        let review_integrity = self.store.verify_review_integrity(|artifact| {
            self.review.verify_artifact(
                &artifact.source,
                &artifact.path,
                &artifact.digest,
                artifact.byte_count,
            )
        })?;
        let observed_at_ms = now_ms()?;
        let assignment_instances = self.assignment_instance_summary(&supervisor)?;
        let selected_actor_profile = self.selected_team_actor_profile()?;
        let (_, selected_model, selected_reasoning_effort) =
            selected_actor_profile.runtime_launch()?;
        let runtime = self.selected_team_runtime()?;
        let mut session = self.sessions.diagnostics();
        let runtime_diagnostics = runtime.diagnostics();
        let runtime_capabilities = runtime.capabilities();
        let runtime_id = runtime_diagnostics.runtime_id.to_string();
        let runtime_program = runtime_diagnostics.program.clone();
        let runtime_available = runtime_diagnostics.available;
        let runtime_command = json!({
            "available": runtime_available,
            "version": runtime_diagnostics.version.unwrap_or_default(),
            "error": runtime_diagnostics.error.unwrap_or_default(),
        });
        if let Some(object) = session.as_object_mut() {
            // Preserve the v0.1 provider-keyed diagnostic path without naming a
            // provider in control-plane source code.
            object.insert(runtime_id.clone(), runtime_command.clone());
        }
        let caller_context = self.doctor_caller_context()?;
        let backend_runtime_reachable = session
            .pointer("/backend_runtime/reachable")
            .and_then(Value::as_bool);
        let lifecycle_backend_ready = session["ready"].as_bool() == Some(true);
        let team_reporting = self.team_reporting_context()?;
        let teams = supervisor
            .snapshot()
            .teams
            .iter()
            .map(|team| self.team_value(team, &supervisor, observed_at_ms, &team_reporting))
            .collect::<Result<Vec<_>, _>>()?;
        let teams_without_nonterminal_work = teams
            .iter()
            .filter(|team| team["nonterminal_request_count"].as_u64() == Some(0))
            .cloned()
            .collect::<Vec<_>>();
        let healthy = lifecycle_backend_ready
            && runtime_available
            && backend_runtime_reachable == Some(true)
            && caller_context["ready"].as_bool() == Some(true)
            && observability_integrity_healthy;
        let mut launch_enforcement = vec![
            "runtime",
            "model",
            "reasoning_effort",
            "working_directory",
            "initial_prompt_delivery",
        ];
        if runtime_capabilities.launch_policy.sandbox.is_some() {
            launch_enforcement.push("sandbox");
        }
        let review_recovery = self.store.review_sessions_requiring_recovery(100)?;
        Ok(json!({
            "healthy": healthy,
            "mode": "embedded",
            "journal_mode": self.store.journal_mode()?,
            "config_source": self.settings.config_source,
            "profiles": self.profiles_summary(),
            "assignment_instances": assignment_instances,
            "state_path": self.store.path(),
            "lifecycle_backend": session.clone(),
            "session": session,
            "lifecycle_backend_ready": lifecycle_backend_ready,
            "backend_runtime_reachable": backend_runtime_reachable,
            "caller_identity": caller_context.clone(),
            "caller_context": caller_context,
            "runtime": {
                "id": runtime_id,
                "program": runtime_program,
                "command": runtime_command,
                "capabilities": {
                    "launch": runtime_capabilities.launch.is_supported(),
                    "resume": runtime_capabilities.resume.is_supported(),
                    "model_selection": runtime_capabilities.model_selection.is_supported(),
                    "reasoning_effort": runtime_capabilities.reasoning_effort.is_supported(),
                    "initial_prompt_delivery": initial_prompt_delivery_name(
                        runtime_capabilities.initial_prompt_delivery,
                    ),
                },
            },
            "teams": teams,
            "teams_without_nonterminal_work": teams_without_nonterminal_work,
            "observability_integrity": {
                "healthy": observability_integrity_healthy,
                "health": observability_integrity_health,
                "verified": observability_integrity_verified,
                "report": observability_integrity_report,
                "error": observability_integrity_error,
            },
            "presentation": self.presentation_diagnostics()?,
            "review": {
                "capabilities": self.review_capability_summary(),
                "recovery_required_sessions": review_recovery,
                "integrity": review_integrity,
            },
            "launch": {
                "runtime": runtime.id().as_str(),
                "model": selected_model,
                "reasoning_effort": selected_reasoning_effort,
                "initial_prompt_delivery": initial_prompt_delivery_name(
                    runtime_capabilities.initial_prompt_delivery,
                ),
                "sandbox": runtime_capabilities.launch_policy.sandbox,
                "approval": runtime_capabilities.launch_policy.approval,
            },
            "enforcement": {
                "core": ["capability_authorization", "state_transitions", "idempotency", "fencing", "exact_candidate_sha"],
                "control_plane": ["durable_session_actor_binding", "primary_caller_authentication", "authenticated_heartbeats", "lease_expiry", "exact_review_commit_and_tree", "standalone_review_object_database", "control_plane_review_execution", "immutable_review_records", "required_absent_path_profiles"],
                "launch": launch_enforcement,
                "runtime_adapter": ["launch_arguments", "resume_arguments", "diagnostics", "capabilities"],
                "provider": runtime_capabilities.launch_policy.provider_enforcement,
                "instructed_observed": ["provider_native_subagent_topology", "reviewer_judgment", "provider_process_pause"],
                "not_yet_enforced": ["decision_requires_passing_verification"],
            },
            "leases": {
                "primary_capability": HUMAN_FACING_PRIMARY_CAPABILITY,
                "primary_lease_seconds": self.settings.primary_lease_seconds,
                "primary": self.primary_lease_summary(&supervisor, observed_at_ms),
                "actor_heartbeat_seconds": self.settings.actor_heartbeat_seconds,
                "implementation_expiry_after_missed_heartbeats": 3,
            },
            "state_security": {
                "directory_mode": "0700",
                "database_mode": "0600",
            },
            "authentication_threat_model": CallerIdentityDriver::threat_model(),
        }))
    }

    fn review_capability_summary(&self) -> Value {
        let sandbox = self.review.sandbox_name();
        let process_containment = self.review.process_containment();
        json!({
            "configured": self.review.configured(),
            "checkout": {
                "exact_commit_and_tree": "control_plane_enforced",
                "standalone_object_database": "control_plane_enforced",
                "read_only_permissions": "control_plane_enforced",
            },
            "verification": {
                "executed_by_control_plane": true,
                "source_write_boundary": if self.review.sandbox_enforced() {
                    "os_enforced"
                } else {
                    "not_enforced"
                },
                "sandbox_backend": sandbox,
                "process_containment": process_containment,
                "process_containment_guarantee": match process_containment {
                    agsv_protocol::ReviewProcessContainment::PidNamespaceParentDeath =>
                        "all_descendants_terminated_on_timeout_or_controller_death",
                    agsv_protocol::ReviewProcessContainment::ProcessGroupOnly =>
                        "direct_process_group_only_detached_descendants_may_survive",
                    agsv_protocol::ReviewProcessContainment::None =>
                        "no_process_tree_containment",
                },
                "environment_evidence": "privacy_allowlisted_and_digest_bound",
                "required_absent_binaries": "controlled_path_profile",
            },
            "decision_gating": {
                "enforced": false,
                "planned_scope": "R6",
            },
        })
    }

    fn presentation_diagnostics(&self) -> Result<Value, ControlError> {
        let capabilities = self.sessions.configured_capabilities();
        Ok(json!({
            "label_capability": {
                "supported": capabilities.relabel_session,
            },
            "layout_capabilities": {
                "placement": capabilities.placement,
                "split_panes": capabilities.split_panes,
                "new_groups": capabilities.new_groups,
                "workspace_scoped_groups": capabilities.workspace_scoped_groups,
                "focus_control": capabilities.focus_control,
                "group_labels": capabilities.group_labels,
            },
            "layout_policy": {
                "max_panes_per_tab": self.settings.max_panes_per_tab,
                "place_first_implementation_with_primary": self.settings.place_first_implementation_with_primary,
                "tab_label_strategy": self.settings.tab_label_strategy,
                "pane_label_template": self.settings.pane_label_template,
                "split_direction": self.settings.split_direction,
                "focus_new_sessions": self.settings.focus_new_sessions,
            },
            "team_metadata": self.store.team_metadata()?,
            "effective_labels": self.store.session_presentations()?,
        }))
    }

    fn doctor_caller_context(&self) -> Result<Value, ControlError> {
        let binding = self
            .caller_identity
            .context()
            .binding()
            .map(|identity| self.store.actor_binding(identity.kind(), identity.value()))
            .transpose()?
            .flatten();
        let (_, supervisor, _) = self.store.load()?;
        let binding_ready = binding.as_ref().is_some_and(|binding| {
            supervisor
                .actor(&binding.actor.actor_id)
                .is_some_and(|actor| {
                    actor.epoch == binding.actor.actor_epoch
                        && actor.status == ActorStatus::Healthy
                        && (actor.team_id.is_some()
                            || supervisor.active_primary().as_ref() == Some(&binding.actor))
                })
        });
        Ok(self.caller_identity.diagnostics(
            binding.as_ref().map(|binding| &binding.actor),
            binding_ready,
        ))
    }

    fn events(&self, request: &Value) -> Result<Value, ControlError> {
        let args: EventsArgs = decode(request)?;
        if args.follow {
            return Err(ControlError::unsupported(
                "events --follow",
                "embedded invocations cannot maintain a truthful streaming subscription",
            ));
        }
        let (_, supervisor, _) = self.store.load()?;
        let observability = self.redacted_observability_summary(&supervisor)?;
        let snapshot = supervisor.snapshot();
        let request_outcomes = self
            .store
            .request_outcomes(&snapshot.requests, args.limit)?
            .into_iter()
            .map(|request| {
                json!({
                    "request_id": request.request_id,
                    "team_id": request.team_id,
                    "team_epoch": request.team_epoch,
                    "status": request.status,
                    "rejection_count": request.rejection_count,
                    "fix_cycle_depth": request.fix_cycle_depth,
                    "current_candidate": request.candidate,
                    "candidate_history": request.candidate_history,
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({
            "control_events": self.store.events(args.limit)?,
            "protocol_events": self.store.protocol_events(supervisor.audit_events(), args.limit)?,
            "request_outcomes": request_outcomes,
            "observability": observability,
        }))
    }

    fn context(&self, request: &Value) -> Result<Value, ControlError> {
        let args: ContextArgs = decode(request)?;
        let (_, _, active) = self.store.load()?;
        if !active {
            return Err(ControlError::new(
                "controller_inactive",
                "run `agsv start` before bootstrapping orchestrator context",
            ));
        }
        let actor_ref = if args.bootstrap {
            self.bootstrap_actor(args.actor.as_deref())?
        } else {
            self.resolve_actor_allow_stopped(args.actor.as_deref())?
                .actor_ref()
        };
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&actor_ref.actor_id)
            .ok_or_else(|| ControlError::not_found("actor", actor_ref.actor_id.as_str()))?;
        let inbox = readable_message_ids(&supervisor, actor, &actor_ref)?
            .into_iter()
            .map(|message_id| {
                let delivery = supervisor
                    .delivery(&message_id)
                    .ok_or_else(|| ControlError::not_found("delivery", message_id.as_str()))?;
                self.hydrated_envelope(&delivery.envelope, &delivery.payload_digest)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let profile = self.actor_profile(actor)?;
        let snapshot = supervisor.snapshot();
        Ok(json!({
            "actor": actor,
            "actor_ref": actor_ref,
            "role": profile.role_instructions,
            "role_source": profile.role_source,
            "profile": {
                "name": profile.name,
                "role": profile.role,
                "capabilities": profile.capabilities,
                "launch": profile.launch_summary(),
                "role_file": profile.role_file,
            },
            "primary_epoch": supervisor.primary_epoch(),
            "policy_revision": supervisor.policy_revision(),
            "team": actor.team_id.as_ref().and_then(|id| supervisor.team(id)),
            "assignments": snapshot.requests.into_iter().filter(|item| {
                item.assignment.as_ref().is_some_and(|assignment| assignment.actor == actor_ref)
            }).map(|item| self.hydrated_request_value(&item)).collect::<Result<Vec<_>, _>>()?,
            "inbox": inbox,
        }))
    }

    fn team_list(&self) -> Result<Value, ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        let observed_at_ms = now_ms()?;
        let team_reporting = self.team_reporting_context()?;
        let teams = supervisor
            .snapshot()
            .teams
            .iter()
            .map(|team| self.team_value(team, &supervisor, observed_at_ms, &team_reporting))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({ "teams": teams }))
    }

    fn team_show(&self, request: &Value) -> Result<Value, ControlError> {
        let args: IdArgs = decode(request)?;
        let id = TeamId::new(args.id.clone()).map_err(ControlError::protocol)?;
        let (_, supervisor, _) = self.store.load()?;
        let team = supervisor
            .team(&id)
            .ok_or_else(|| ControlError::not_found("team", &args.id))?;
        let observed_at_ms = now_ms()?;
        let team_reporting = self.team_reporting_context()?;
        let snapshot = supervisor.snapshot();
        let requests = snapshot
            .requests
            .into_iter()
            .filter(|item| item.team_id == id)
            .map(|item| self.hydrated_request_value(&item))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({
            "team": self.team_value(team, &supervisor, observed_at_ms, &team_reporting)?,
            "actors": snapshot.actors.into_iter()
                .filter(|actor| actor.team_id.as_ref() == Some(&id))
                .map(|actor| self.actor_value(&actor, observed_at_ms))
                .collect::<Result<Vec<_>, _>>()?,
            "requests": requests,
            "prior_generations": self.store.prior_team_generations(&id)?,
            "sessions": team_reporting.sessions.get(args.id.as_str()).cloned().unwrap_or_default(),
            "presentations": self.store.presentations_for_team(args.id.as_str())?,
        }))
    }

    fn team_update(&self, request: &Value) -> Result<Value, ControlError> {
        let args: TeamUpdateArgs = decode(request)?;
        self.idempotent("team.update", request, &args.operation_id, || {
            let team_id = TeamId::new(args.id.clone()).map_err(ControlError::protocol)?;
            let purpose = normalize_team_purpose(Some(&args.purpose))?;
            let (revision, supervisor, _) = self.store.load()?;
            let team = supervisor
                .team(&team_id)
                .ok_or_else(|| ControlError::not_found("team", &args.id))?;
            let observed_at_ms = now_ms()?;
            self.store
                .set_team_purpose(team_id.as_str(), &purpose, observed_at_ms)?;
            let worktree = self.store.team_worktree(team_id.as_str())?;
            Ok(json!({
                "team": self.team_value_without_directory_observation(
                    team,
                    &supervisor,
                    observed_at_ms,
                    worktree.as_ref(),
                )?,
                "revision": revision,
                "descriptive_only": true,
            }))
        })
    }

    fn team_value(
        &self,
        team: &Team,
        supervisor: &Supervisor,
        observed_at_ms: u64,
        reporting: &TeamReportingContext,
    ) -> Result<Value, ControlError> {
        let worktree = reporting.worktrees.get(team.team_id.as_str());
        let mut value = self.team_value_without_directory_observation(
            team,
            supervisor,
            observed_at_ms,
            worktree,
        )?;
        let working_directory = self.team_working_directory_observation(&team.team_id, reporting);
        let object = value
            .as_object_mut()
            .expect("protocol teams serialize as JSON objects");
        object.insert(
            "working_directory_exists".to_owned(),
            json!(working_directory.exists),
        );
        object.insert(
            "working_directory_head".to_owned(),
            json!(working_directory.head_sha.clone()),
        );
        object.insert(
            "working_directory_observation".to_owned(),
            json!(working_directory),
        );
        Ok(value)
    }

    fn team_value_without_directory_observation(
        &self,
        team: &Team,
        supervisor: &Supervisor,
        observed_at_ms: u64,
        worktree: Option<&TeamWorktreeRecord>,
    ) -> Result<Value, ControlError> {
        let mut value = serde_json::to_value(team).map_err(ControlError::database)?;
        let purpose = self
            .store
            .team_purpose(team.team_id.as_str())?
            .unwrap_or_default();
        let blocking_request_ids = team_close_blocking_request_ids(supervisor, &team.team_id);
        let activity = self
            .store
            .team_activity_summary(&team.team_id)?
            .ok_or_else(|| {
                ControlError::new(
                    "team_activity_summary_missing",
                    format!("team `{}` has no durable activity summary", team.team_id),
                )
            })?;
        let (configured_desired_instances, _) = Self::effective_team_intent(team)?;
        let effective_desired_instances = if matches!(
            team.status,
            TeamStatus::Closing | TeamStatus::Closed | TeamStatus::Retired
        ) {
            0
        } else {
            configured_desired_instances
        };
        let retained_owned_worktree = worktree.as_ref().is_some_and(|record| {
            record.ownership != TeamWorktreeOwnership::Attached
                && record.status == TeamWorktreeStatus::RetainedWithReason
        });
        let object = value
            .as_object_mut()
            .expect("protocol teams serialize as JSON objects");
        object.insert("purpose".to_owned(), Value::String(purpose));
        object.insert("worktree".to_owned(), json!(worktree));
        object.insert(
            "last_activity_at".to_owned(),
            json!(activity.last_activity_at),
        );
        object.insert(
            "inactive_for_ms".to_owned(),
            json!(observed_at_ms.saturating_sub(activity.last_activity_at.0)),
        );
        object.insert(
            "nonterminal_request_count".to_owned(),
            json!(activity.nonterminal_request_count),
        );
        object.insert("activity".to_owned(), json!(activity));
        object.insert(
            "blocking_request_ids".to_owned(),
            json!(blocking_request_ids),
        );
        object.insert(
            "configured_desired_instances".to_owned(),
            json!(configured_desired_instances),
        );
        object.insert(
            "effective_desired_instances".to_owned(),
            json!(effective_desired_instances),
        );
        object.insert(
            "retained_owned_worktree".to_owned(),
            json!(retained_owned_worktree),
        );
        Ok(value)
    }

    fn team_reporting_context(&self) -> Result<TeamReportingContext, ControlError> {
        let worktrees = self
            .store
            .team_worktrees()?
            .into_iter()
            .map(|record| (record.team_id.clone(), record))
            .collect();
        let all_sessions = self.store.sessions()?;
        let mut sessions = BTreeMap::<String, Vec<SessionRecord>>::new();
        for session in &all_sessions {
            if let Some(team_id) = session.team_id.clone() {
                sessions.entry(team_id).or_default().push(session.clone());
            }
        }
        Ok(TeamReportingContext {
            worktrees,
            sessions,
            all_sessions,
            git_worktree_paths: git_worktree_paths(
                self.review.git_executable(),
                self.identity.repository_root(),
            ),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn team_working_directory_observation(
        &self,
        team_id: &TeamId,
        reporting: &TeamReportingContext,
    ) -> TeamWorkingDirectoryObservation {
        let Some(record) = reporting.worktrees.get(team_id.as_str()) else {
            return TeamWorkingDirectoryObservation {
                recorded_path: None,
                state: TeamWorkingDirectoryState::Unrecorded,
                exists: None,
                head_sha: None,
                matches_durable_state: None,
                drift: Vec::new(),
            };
        };
        let path = record.working_directory.clone();
        let mut observation = TeamWorkingDirectoryObservation {
            recorded_path: Some(path.clone()),
            state: TeamWorkingDirectoryState::Present,
            exists: Some(true),
            head_sha: None,
            matches_durable_state: Some(true),
            drift: Vec::new(),
        };
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                observation.exists = Some(false);
                observation.head_sha = None;
                if record.status == TeamWorktreeStatus::Removed {
                    observation.state = TeamWorkingDirectoryState::Removed;
                } else {
                    observation.state = TeamWorkingDirectoryState::RecordedAbsent;
                    observation.matches_durable_state = Some(false);
                    observation.drift.push(TeamWorkingDirectoryDrift {
                        code: "recorded_path_absent".to_owned(),
                        detail: "the recorded working directory is absent or has moved".to_owned(),
                    });
                }
                return observation;
            }
            Err(error) => {
                observation.exists = None;
                observation.state = TeamWorkingDirectoryState::InspectionFailed;
                observation.matches_durable_state = None;
                observation.drift.push(TeamWorkingDirectoryDrift {
                    code: "path_inspection_failed".to_owned(),
                    detail: error.to_string(),
                });
                return observation;
            }
        };
        if record.status == TeamWorktreeStatus::Removed {
            observation.state = TeamWorkingDirectoryState::PresentMismatch;
            observation.matches_durable_state = Some(false);
            observation.drift.push(TeamWorkingDirectoryDrift {
                code: "recorded_removed_path_present".to_owned(),
                detail: "the directory is present although durable state records it as removed"
                    .to_owned(),
            });
        }
        if metadata.file_type().is_symlink() {
            observation.state = TeamWorkingDirectoryState::PresentMismatch;
            observation.matches_durable_state = Some(false);
            observation.drift.push(TeamWorkingDirectoryDrift {
                code: "recorded_path_symlink".to_owned(),
                detail: "the recorded working directory is now a symbolic link".to_owned(),
            });
            return observation;
        }
        let canonical = match fs::canonicalize(&path) {
            Ok(canonical) => canonical,
            Err(error) => {
                observation.state = TeamWorkingDirectoryState::PresentMismatch;
                observation.matches_durable_state = Some(false);
                observation.drift.push(TeamWorkingDirectoryDrift {
                    code: "path_canonicalization_failed".to_owned(),
                    detail: error.to_string(),
                });
                return observation;
            }
        };
        if canonical != path {
            observation.state = TeamWorkingDirectoryState::PresentMismatch;
            observation.matches_durable_state = Some(false);
            observation.drift.push(TeamWorkingDirectoryDrift {
                code: "recorded_path_mismatch".to_owned(),
                detail: format!(
                    "the recorded path resolves to a different location: {}",
                    canonical.display()
                ),
            });
        }
        match observed_git_identity(self.review.git_executable(), &canonical) {
            Ok((root, common_dir)) => {
                if root != canonical || common_dir != self.identity.git_common_dir() {
                    observation.state = TeamWorkingDirectoryState::PresentMismatch;
                    observation.matches_durable_state = Some(false);
                    observation.drift.push(TeamWorkingDirectoryDrift {
                        code: "git_identity_mismatch".to_owned(),
                        detail: format!(
                            "observed Git root {} and common directory {} do not match durable workspace identity",
                            root.display(),
                            common_dir.display()
                        ),
                    });
                }
            }
            Err(detail) => {
                observation.state = TeamWorkingDirectoryState::PresentMismatch;
                observation.matches_durable_state = Some(false);
                observation.drift.push(TeamWorkingDirectoryDrift {
                    code: "git_identity_unavailable".to_owned(),
                    detail,
                });
            }
        }
        match observed_git_head(self.review.git_executable(), &canonical) {
            Ok(head) => observation.head_sha = Some(head),
            Err(detail) => {
                observation.state = TeamWorkingDirectoryState::PresentMismatch;
                observation.matches_durable_state = Some(false);
                observation.drift.push(TeamWorkingDirectoryDrift {
                    code: "git_head_unavailable".to_owned(),
                    detail,
                });
            }
        }
        for session in reporting
            .sessions
            .get(team_id.as_str())
            .into_iter()
            .flatten()
        {
            if session.working_directory != path {
                observation.state = TeamWorkingDirectoryState::PresentMismatch;
                observation.matches_durable_state = Some(false);
                observation.drift.push(TeamWorkingDirectoryDrift {
                    code: "session_path_mismatch".to_owned(),
                    detail: format!(
                        "actor `{}` records working directory {}",
                        session.actor_id,
                        session.working_directory.display()
                    ),
                });
            }
        }
        match &reporting.git_worktree_paths {
            Ok(paths) if !paths.contains(&canonical) => {
                observation.state = TeamWorkingDirectoryState::PresentMismatch;
                observation.matches_durable_state = Some(false);
                observation.drift.push(TeamWorkingDirectoryDrift {
                    code: "git_worktree_registration_missing".to_owned(),
                    detail: "the present directory is not registered in this repository's worktree metadata"
                        .to_owned(),
                });
            }
            Ok(_) => {}
            Err(detail) => {
                observation.state = TeamWorkingDirectoryState::InspectionFailed;
                observation.matches_durable_state = None;
                observation.drift.push(TeamWorkingDirectoryDrift {
                    code: "git_worktree_list_unavailable".to_owned(),
                    detail: detail.clone(),
                });
            }
        }
        observation
    }

    fn hydrated_envelope(
        &self,
        header: &EnvelopeHeader,
        payload_digest: &PayloadDigest,
    ) -> Result<Envelope, ControlError> {
        let message = self
            .store
            .message_body(&header.message_id, payload_digest)?;
        Ok(header.with_message(message))
    }

    fn hydrated_delivery_value(&self, delivery: &DeliverySnapshot) -> Result<Value, ControlError> {
        let mut value = serde_json::to_value(delivery).map_err(ControlError::database)?;
        value
            .as_object_mut()
            .expect("protocol deliveries serialize as JSON objects")
            .insert(
                "envelope".to_owned(),
                serde_json::to_value(
                    self.hydrated_envelope(&delivery.envelope, &delivery.payload_digest)?,
                )
                .map_err(ControlError::database)?,
            );
        Ok(value)
    }

    fn hydrated_delivery_record_value(
        &self,
        delivery: &DeliveryRecord,
    ) -> Result<Value, ControlError> {
        let mut value = json!({
            "envelope": self.hydrated_envelope(
                &delivery.envelope,
                &delivery.payload_digest,
            )?,
            "message_kind": delivery.message_kind,
            "payload_digest": delivery.payload_digest,
            "causal": delivery.causal,
            "required_recipients": delivery.required_recipients,
            "acknowledgements": delivery.acknowledgements.values().collect::<Vec<_>>(),
            "undeliverable_recipients": delivery
                .undeliverable_recipients
                .iter()
                .map(|(recipient, reason)| json!({
                    "recipient": recipient,
                    "reason": reason,
                }))
                .collect::<Vec<_>>(),
            "retired": delivery.retired,
        });
        if let Some(reason) = &delivery.retirement_reason {
            value
                .as_object_mut()
                .expect("delivery records serialize as JSON objects")
                .insert(
                    "retirement_reason".to_owned(),
                    serde_json::to_value(reason).map_err(ControlError::database)?,
                );
        }
        Ok(value)
    }

    fn hydrated_request_value(&self, request: &Request) -> Result<Value, ControlError> {
        let mut value = serde_json::to_value(request).map_err(ControlError::database)?;
        let specification = self.store.request_specification(request)?.ok_or_else(|| {
            ControlError::new(
                "request_specification_missing",
                format!(
                    "request specification `{}` is not present in immutable storage",
                    request.request_id
                ),
            )
        })?;
        let object = value
            .as_object_mut()
            .expect("protocol requests serialize as JSON objects");
        object.insert(
            "specification".to_owned(),
            serde_json::to_value(specification).map_err(ControlError::database)?,
        );
        if let Some(decision_ref) = &request.decision {
            let message = self
                .store
                .message_body(&decision_ref.message_id, &decision_ref.payload_digest)?;
            let Message::ReviewDecision(decision) = message else {
                return Err(ControlError::new(
                    "decision_body_mismatch",
                    format!(
                        "message `{}` does not contain its referenced review decision",
                        decision_ref.message_id
                    ),
                ));
            };
            object.insert(
                "decision".to_owned(),
                serde_json::to_value(decision).map_err(ControlError::database)?,
            );
        }
        Ok(value)
    }

    fn reported_request_value(
        &self,
        request: &Request,
        base_reporting: &BaseStalenessContext,
    ) -> Result<Value, ControlError> {
        let mut value = self.hydrated_request_value(request)?;
        let base_sha = value["specification"]["base_sha"]
            .as_str()
            .ok_or_else(|| {
                ControlError::new(
                    "request_specification_missing",
                    "request specification does not expose its immutable base SHA",
                )
            })?
            .to_owned();
        let staleness = base_reporting.request_report(
            &base_sha,
            request
                .candidate
                .as_ref()
                .map(|candidate| candidate.sha.as_str()),
        );
        value
            .as_object_mut()
            .expect("protocol requests serialize as JSON objects")
            .insert("base_staleness".to_owned(), staleness);
        Ok(value)
    }

    fn committed_request_retry(
        &self,
        args: &RequestCreateArgs,
        instructions: &str,
        team_id: &TeamId,
    ) -> Result<Option<Envelope>, ControlError> {
        let request_id = RequestId::new(stable_id("request", &args.operation_id))
            .map_err(ControlError::protocol)?;
        let run_id =
            RunId::new(stable_id("run", &args.operation_id)).map_err(ControlError::protocol)?;
        let message_id = message_id(&args.operation_id, "request");
        let (_, existing_state, _) = self.store.load()?;
        let envelope = if let Some(delivery) = existing_state.delivery(&message_id) {
            self.hydrated_envelope(&delivery.envelope, &delivery.payload_digest)?
        } else if let Some(delivery) = self.store.archived_delivery(&message_id)? {
            self.hydrated_envelope(&delivery.envelope, &delivery.payload_digest)?
        } else {
            return Ok(None);
        };
        if retry_request_matches(args, instructions, team_id, &request_id, &run_id, &envelope) {
            Ok(Some(envelope))
        } else {
            Err(ControlError::new(
                "operation_id_conflict",
                format!(
                    "operation ID `{}` was already committed with different request input",
                    args.operation_id
                ),
            ))
        }
    }

    fn ensure_actor_presentation(
        &self,
        actor_ref: &ActorRef,
        backend_id: &str,
    ) -> Result<SessionPresentationRecord, ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&actor_ref.actor_id)
            .filter(|actor| actor.epoch == actor_ref.actor_epoch)
            .ok_or_else(|| {
                ControlError::new(
                    "stale_actor_epoch",
                    "cannot prepare presentation for a stale actor generation",
                )
            })?;
        let purpose = actor
            .team_id
            .as_ref()
            .map(|team_id| self.store.team_purpose(team_id.as_str()))
            .transpose()?
            .flatten()
            .unwrap_or_default();
        let session_label = display_session_label(&supervisor, &actor_ref.actor_id, &purpose)?;
        let active_titles = supervisor
            .snapshot()
            .requests
            .into_iter()
            .filter(|request| !request.status.is_terminal())
            .filter(|request| {
                request
                    .assignment
                    .as_ref()
                    .is_some_and(|assignment| assignment.actor == *actor_ref)
            })
            .map(|request| {
                self.store
                    .request_specification(&request)?
                    .map(|specification| specification.title)
                    .ok_or_else(|| {
                        ControlError::new(
                            "request_specification_missing",
                            format!(
                                "request specification `{}` is not present in immutable storage",
                                request.request_id
                            ),
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let active_title = active_request_title(&active_titles);
        let desired_label = render_label_template(
            &self.settings.pane_label_template,
            &LabelContext {
                session_label: &session_label,
                team_purpose: &purpose,
                active_request_title: &active_title,
            },
        )
        .unwrap_or_else(|_| session_label.clone());
        if supervisor.active_primary().as_ref() == Some(&actor.actor_ref()) {
            self.store.ensure_primary_presentation(
                actor_ref.actor_id.as_str(),
                &session_label,
                &desired_label,
                now_ms()?,
            )?;
        } else if self
            .store
            .session_presentation(actor_ref.actor_id.as_str())?
            .is_none()
        {
            let team_id = actor.team_id.as_ref().ok_or_else(|| {
                ControlError::invalid_request("Implementation actor has no team presentation")
            })?;
            let occupied = self.observed_group_sequences(backend_id)?;
            let reusable = self.reusable_group_sequences(backend_id)?;
            self.store.allocate_session_presentation(
                actor_ref.actor_id.as_str(),
                team_id.as_str(),
                &session_label,
                &desired_label,
                u32::from(self.settings.max_panes_per_tab),
                self.settings.place_first_implementation_with_primary,
                &occupied,
                &reusable,
                now_ms()?,
            )?;
        }
        self.store.update_presentation_labels(
            actor_ref.actor_id.as_str(),
            &session_label,
            &desired_label,
            now_ms()?,
        )
    }

    fn observed_group_sequences(&self, backend_id: &str) -> Result<Vec<u32>, ControlError> {
        let capabilities = self.sessions.capabilities_for(backend_id)?;
        if !capabilities.group_labels {
            return Ok(Vec::new());
        }
        let primary = self.active_primary_session()?;
        if primary.backend != backend_id {
            return Ok(Vec::new());
        }
        let labels = match self.sessions.group_labels(&primary)? {
            CapabilityOutcome::Supported(labels) => labels,
            CapabilityOutcome::Unsupported => return Ok(Vec::new()),
        };
        Ok(labels
            .into_iter()
            .filter_map(|label| label.trim().parse::<u32>().ok())
            .filter(|sequence| *sequence > 0)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }

    fn reusable_group_sequences(&self, backend_id: &str) -> Result<Vec<u32>, ControlError> {
        let mut reusable = BTreeSet::new();
        let placement_supported = self.sessions.capabilities_for(backend_id)?.placement;
        for presentation in self.store.session_presentations()? {
            let Some(slot) = presentation
                .slot
                .filter(|slot| slot.tab_sequence > 0 && slot.pane_index == 0)
            else {
                continue;
            };
            let Some(session) = self.store.session(&presentation.actor_id)? else {
                continue;
            };
            if session.backend == backend_id
                && session.external_id.is_some()
                && session_status_is_present(&session.status)
                && (!placement_supported
                    || self
                        .sessions
                        .placement_handle_for_record(&session)?
                        .is_some())
            {
                reusable.insert(slot.tab_sequence);
            }
        }
        Ok(reusable.into_iter().collect())
    }

    fn active_primary_session(&self) -> Result<SessionRecord, ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        let primary = active_primary_actor(&supervisor)?;
        self.store
            .session(primary.actor_id.as_str())?
            .ok_or_else(|| {
                ControlError::new(
                    "primary_session_not_found",
                    "the active Primary has no durable session anchor",
                )
            })
    }

    fn launch_hints(
        &self,
        actor_id: &ActorId,
        backend_id: &str,
    ) -> Result<SessionLaunchHints, ControlError> {
        let capabilities = self.sessions.capabilities_for(backend_id)?;
        if !capabilities.placement {
            return Ok(SessionLaunchHints::default());
        }
        let presentation = self
            .store
            .session_presentation(actor_id.as_str())?
            .ok_or_else(|| ControlError::not_found("session presentation", actor_id.as_str()))?;
        let slot = presentation.slot.ok_or_else(|| {
            ControlError::invalid_request("Implementation presentation has no layout slot")
        })?;
        let primary = self.active_primary_session()?;
        if primary.backend != backend_id {
            return Err(ControlError::new(
                "session_layout_anchor_mismatch",
                "the configured session backend cannot use the active Primary session as a layout anchor",
            ));
        }
        let primary_anchor = self
            .sessions
            .placement_handle_for_record(&primary)?
            .ok_or_else(|| {
                ControlError::new(
                    "session_layout_anchor_unavailable",
                    "the active Primary session has no backend-usable placement handle",
                )
            })?;
        let direction = match self.settings.split_direction.as_str() {
            "right" => SplitDirection::Right,
            "down" => SplitDirection::Down,
            _ => {
                return Err(ControlError::invalid_request(
                    "session_layout split_direction must be right or down",
                ));
            }
        };
        let placement = if slot.tab_sequence == 0 {
            SessionPlacement::Beside {
                anchor: primary_anchor.clone(),
                direction,
            }
        } else {
            let mut sibling = None;
            for candidate in self.store.session_presentations()? {
                if candidate.actor_id == presentation.actor_id
                    || candidate.slot.is_none_or(|candidate_slot| {
                        candidate_slot.tab_sequence != slot.tab_sequence
                    })
                {
                    continue;
                }
                let Some(session) = self.store.session(&candidate.actor_id)? else {
                    continue;
                };
                if session.backend == backend_id
                    && session.external_id.is_some()
                    && session_status_is_present(&session.status)
                    && let Some(anchor) = self.sessions.placement_handle_for_record(&session)?
                {
                    sibling = Some(anchor);
                    break;
                }
            }
            sibling.map_or_else(
                || {
                    Ok(SessionPlacement::NewGroup {
                        scope_anchor: primary_anchor,
                        label: slot.tab_sequence.to_string(),
                    })
                },
                |anchor| Ok(SessionPlacement::Beside { anchor, direction }),
            )?
        };
        Ok(SessionLaunchHints {
            placement: Some(placement),
            focus: self.settings.focus_new_sessions,
        })
    }

    fn refresh_actor_presentation(
        &self,
        actor_ref: &ActorRef,
        force: bool,
    ) -> Result<(), ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        let Some(actor) = supervisor
            .actor(&actor_ref.actor_id)
            .filter(|actor| actor.epoch == actor_ref.actor_epoch)
        else {
            return Ok(());
        };
        if actor.status != ActorStatus::Healthy {
            return Ok(());
        }
        let backend_id = self
            .store
            .session(actor_ref.actor_id.as_str())?
            .map_or_else(
                || self.sessions.name().to_owned(),
                |session| session.backend,
            );
        let presentation = self.ensure_actor_presentation(actor_ref, &backend_id)?;
        let Some(session) = self.store.session(actor_ref.actor_id.as_str())? else {
            self.store.mark_presentation_pending(
                actor_ref.actor_id.as_str(),
                Some("session_not_found"),
                now_ms()?,
            )?;
            return Ok(());
        };
        if session.external_id.is_none() || !session_status_is_present(&session.status) {
            self.store.mark_presentation_pending(
                actor_ref.actor_id.as_str(),
                Some(if session.external_id.is_none() {
                    "session_incomplete"
                } else {
                    "session_not_present"
                }),
                now_ms()?,
            )?;
            return Ok(());
        }
        if !force
            && presentation.sync_state == PresentationSyncState::Applied
            && presentation.applied_label.as_deref() == Some(&presentation.desired_label)
        {
            return Ok(());
        }
        match self.sessions.relabel(&session, &presentation.desired_label) {
            Ok(CapabilityOutcome::Supported(())) => {
                self.store.mark_presentation_applied(
                    actor_ref.actor_id.as_str(),
                    &presentation.desired_label,
                    now_ms()?,
                )?;
            }
            Ok(CapabilityOutcome::Unsupported) => {
                self.store.mark_presentation_pending(
                    actor_ref.actor_id.as_str(),
                    Some("unsupported"),
                    now_ms()?,
                )?;
            }
            Err(error) => {
                self.store.mark_presentation_pending(
                    actor_ref.actor_id.as_str(),
                    Some(error.code),
                    now_ms()?,
                )?;
            }
        }
        Ok(())
    }

    fn refresh_all_presentations(&self, force: bool) -> Result<(), ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        for actor in supervisor.snapshot().actors {
            let actor_ref = actor.actor_ref();
            if let Err(error) = self.refresh_actor_presentation(&actor_ref, force)
                && matches!(
                    self.store.session_presentation(actor_ref.actor_id.as_str()),
                    Ok(Some(_))
                )
                && let Ok(observed_at) = now_ms()
            {
                let _ = self.store.mark_presentation_pending(
                    actor_ref.actor_id.as_str(),
                    Some(error.code),
                    observed_at,
                );
            }
        }
        Ok(())
    }

    fn team_status(
        &self,
        request: &Value,
        status: TeamStatus,
        operation: &str,
    ) -> Result<Value, ControlError> {
        let args: MutationIdArgs = decode(request)?;
        self.idempotent(operation, request, &args.operation_id, || {
            let id = TeamId::new(args.id.clone()).map_err(ControlError::protocol)?;
            let (revision, ()) = self.store.mutate(
                operation,
                &json!({ "team_id": id, "status": status }),
                now_ms()?,
                |supervisor| {
                    supervisor
                        .set_team_status(&id, status)
                        .map_err(ControlError::core)
                },
            )?;
            let instance_reconciliation = if status == TeamStatus::Active {
                let reconciliation = self.reconcile_team_instances(&id)?;
                if reconciliation["complete"].as_bool() != Some(true) {
                    return Err(ControlError::new(
                        "instance_reconciliation_incomplete",
                        "team resumed but its desired actor instances have not converged",
                    )
                    .with_details(json!({ "instance_reconciliation": reconciliation }))
                    .with_hint(
                        "correct the reported actor or session failure, then retry with the same operation ID",
                    ));
                }
                Some(reconciliation)
            } else {
                None
            };
            Ok(json!({
                "team_id": id,
                "status": status,
                "scope": "protocol_admission",
                "provider_process_suspended": false,
                "revision": revision,
                "instance_reconciliation": instance_reconciliation,
            }))
        })
    }

    fn team_close(&self, request: &Value) -> Result<Value, ControlError> {
        let args: TeamCloseArgs = decode(request)?;
        self.idempotent("team.close", request, &args.operation_id, || {
            let team_id = TeamId::new(args.id.clone()).map_err(ControlError::protocol)?;
            let (_, before_close, _) = self.store.load()?;
            let team_epoch = before_close
                .team(&team_id)
                .ok_or_else(|| ControlError::not_found("team", team_id.as_str()))?
                .epoch;
            let (requested_revision, (blocking_request_ids, blocking_message_ids)) =
                self.store.mutate(
                    "team.close_requested",
                    &json!({
                        "team_id": team_id,
                        "team_epoch": team_epoch,
                        "when_idle": args.when_idle,
                    }),
                    now_ms()?,
                    |state| {
                        let team = state
                            .team(&team_id)
                            .ok_or_else(|| ControlError::not_found("team", team_id.as_str()))?;
                        if team.status == TeamStatus::Retired {
                            return Err(ControlError::new(
                                "team_retired",
                                "legacy retired teams cannot enter the v0.3 close lifecycle",
                            ));
                        }
                        let blocking = team_close_blocking_request_ids(state, &team_id);
                        if !blocking.is_empty() && !args.when_idle {
                            return Err(team_close_blocked(&team_id, &blocking));
                        }
                        let deferred_request_ids = if args.when_idle {
                            blocking.iter().cloned().collect::<BTreeSet<_>>()
                        } else {
                            BTreeSet::new()
                        };
                        let blocking_messages = state
                            .team_close_blocking_message_ids_except_request_lifecycle(
                                &team_id,
                                &deferred_request_ids,
                            );
                        if !blocking_messages.is_empty() {
                            return Err(team_close_unacknowledged_actions(
                                &team_id,
                                &blocking_messages,
                            ));
                        }
                        if !matches!(team.status, TeamStatus::Closing | TeamStatus::Closed) {
                            state
                                .set_team_status(&team_id, TeamStatus::Closing)
                                .map_err(ControlError::core)?;
                        }
                        Ok((blocking, blocking_messages))
                    },
                )?;
            let mut result = self.reconcile_closing_team(&team_id)?;
            let object = result
                .as_object_mut()
                .expect("team close reconciliation serializes as an object");
            object.insert(
                "close_requested_revision".to_owned(),
                json!(requested_revision),
            );
            object.insert("when_idle".to_owned(), json!(args.when_idle));
            object.insert(
                "blocking_request_ids_at_request".to_owned(),
                json!(blocking_request_ids),
            );
            object.insert(
                "blocking_message_ids_at_request".to_owned(),
                json!(blocking_message_ids),
            );
            Ok(result)
        })
    }

    #[allow(clippy::too_many_lines)]
    fn reconcile_closing_team(&self, team_id: &TeamId) -> Result<Value, ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        let team = supervisor
            .team(team_id)
            .ok_or_else(|| ControlError::not_found("team", team_id.as_str()))?
            .clone();
        if team.status == TeamStatus::Closed {
            let blocking_message_ids = supervisor.team_close_blocking_message_ids(team_id);
            if !blocking_message_ids.is_empty() {
                return Err(team_close_unacknowledged_actions(
                    team_id,
                    &blocking_message_ids,
                ));
            }
            let pending = team
                .actors
                .iter()
                .flat_map(|actor_id| supervisor.pending_acknowledgement_message_ids_for(actor_id))
                .collect::<BTreeSet<_>>();
            let retired_undeliverable_message_ids = if pending.is_empty() {
                Vec::new()
            } else {
                self.store
                    .mutate(
                        "team.closed_delivery_repair",
                        &json!({ "team_id": team_id }),
                        now_ms()?,
                        |state| {
                            state
                                .retire_obsolete_team_recipients(team_id)
                                .map_err(ControlError::core)
                        },
                    )?
                    .1
            };
            let worktree_cleanup = self.cleanup_team_worktree(team_id)?;
            return Ok(json!({
                "team_id": team_id,
                "status": TeamStatus::Closed,
                "blocking_request_ids": [],
                "blocking_message_ids": [],
                "retired_undeliverable_message_ids": retired_undeliverable_message_ids,
                "actor_stops": [],
                "failures": [],
                "worktree_cleanup": worktree_cleanup,
                "complete": true,
                "deferred": false,
                "already_closed": true,
            }));
        }
        if team.status != TeamStatus::Closing {
            return Err(ControlError::new(
                "team_not_closing",
                format!("team `{team_id}` is not in the closing lifecycle"),
            )
            .with_details(json!({ "team_id": team_id, "status": team.status })));
        }

        let blocking_request_ids = team_close_blocking_request_ids(&supervisor, team_id);
        if !blocking_request_ids.is_empty() {
            return Ok(json!({
                "team_id": team_id,
                "status": TeamStatus::Closing,
                "blocking_request_ids": blocking_request_ids,
                "blocking_message_ids": [],
                "retired_undeliverable_message_ids": [],
                "actor_stops": [],
                "failures": [],
                "worktree_cleanup": Value::Null,
                "complete": false,
                "deferred": true,
                "already_closed": false,
            }));
        }
        let blocking_message_ids = supervisor.team_close_blocking_message_ids(team_id);
        if !blocking_message_ids.is_empty() {
            return Ok(json!({
                "team_id": team_id,
                "status": TeamStatus::Closing,
                "blocking_request_ids": [],
                "blocking_message_ids": blocking_message_ids,
                "retired_undeliverable_message_ids": [],
                "actor_stops": [],
                "failures": [],
                "worktree_cleanup": Value::Null,
                "complete": false,
                "deferred": true,
                "already_closed": false,
            }));
        }

        let mut actor_stops = Vec::new();
        let mut failures = Vec::new();
        for actor_id in &team.actors {
            let _target_operation_lock = self
                .store
                .lock_actor_operations("actor", actor_id.as_str())?;
            let (_, current, _) = self.store.load()?;
            let Some(actor) = current.actor(actor_id) else {
                failures.push(json!({
                    "actor_id": actor_id,
                    "phase": "team_close_actor_lookup",
                    "error": "team references a missing actor",
                }));
                continue;
            };
            match self.stop_team_actor_if_ready(team_id, &actor.actor_ref()) {
                Ok(result) => actor_stops.push(result),
                Err(error) => failures.push(json!({
                    "actor_id": actor_id,
                    "phase": "team_close_stop",
                    "error": error.to_string(),
                    "error_code": error.code,
                    "details": error.details,
                })),
            }
        }

        let (_, stopped, _) = self.store.load()?;
        let actors_awaiting_stop = team
            .actors
            .iter()
            .filter(|actor_id| {
                stopped
                    .actor(actor_id)
                    .is_none_or(|actor| actor.status != ActorStatus::Stopped)
            })
            .cloned()
            .collect::<Vec<_>>();
        let sessions_awaiting_cleanup = self
            .store
            .sessions()?
            .into_iter()
            .filter(|session| session.team_id.as_deref() == Some(team_id.as_str()))
            .filter(|session| {
                session.external_id.is_some()
                    && !matches!(session.status.as_str(), "missing" | "stopped")
            })
            .map(|session| session.actor_id)
            .collect::<Vec<_>>();
        if !actors_awaiting_stop.is_empty() || !sessions_awaiting_cleanup.is_empty() {
            failures.push(json!({
                "phase": "team_close_convergence",
                "error": "team actors or backend sessions still require cleanup",
                "actors_awaiting_stop": actors_awaiting_stop,
                "sessions_awaiting_cleanup": sessions_awaiting_cleanup,
            }));
        }
        if !failures.is_empty() {
            return Ok(json!({
                "team_id": team_id,
                "status": TeamStatus::Closing,
                "blocking_request_ids": [],
                "blocking_message_ids": [],
                "retired_undeliverable_message_ids": [],
                "actor_stops": actor_stops,
                "failures": failures,
                "worktree_cleanup": Value::Null,
                "complete": false,
                "deferred": false,
                "already_closed": false,
            }));
        }

        if self.debug_crash_requested(
            "AGSV_DEV_FAIL_AFTER_TEAM_CLOSE_ACTOR_STOP_COMMIT",
            "team_close_actor_stop_commit",
        ) {
            return Err(ControlError::new(
                "simulated_team_close_actor_stop_crash",
                "debug-only failure after team-close actor stops committed",
            ));
        }
        let worktree_cleanup = self.cleanup_team_worktree(team_id)?;
        if self.debug_crash_requested(
            "AGSV_DEV_FAIL_AFTER_TEAM_CLOSE_WORKTREE_CLEANUP",
            "team_close_worktree_cleanup",
        ) {
            return Err(ControlError::new(
                "simulated_team_close_worktree_cleanup_crash",
                "debug-only failure after team-close worktree cleanup",
            ));
        }
        let (revision, retired_undeliverable_message_ids) = self.store.mutate(
            "team.closed",
            &json!({
                "team_id": team_id,
                "team_epoch": team.epoch,
                "worktree_cleanup": worktree_cleanup,
            }),
            now_ms()?,
            |state| {
                let blocking = team_close_blocking_request_ids(state, team_id);
                if !blocking.is_empty() {
                    return Err(team_close_blocked(team_id, &blocking));
                }
                let blocking_messages = state.team_close_blocking_message_ids(team_id);
                if !blocking_messages.is_empty() {
                    return Err(team_close_unacknowledged_actions(
                        team_id,
                        &blocking_messages,
                    ));
                }
                for actor_id in &team.actors {
                    let actor = state
                        .actor(actor_id)
                        .ok_or_else(|| ControlError::not_found("actor", actor_id.as_str()))?;
                    if actor.status != ActorStatus::Stopped {
                        return Err(ControlError::new(
                            "team_close_incomplete",
                            "team cannot close until every actor is stopped",
                        )
                        .with_details(json!({
                            "team_id": team_id,
                            "actor_id": actor_id,
                            "actor_status": actor.status,
                        })));
                    }
                }
                let retired = state
                    .retire_obsolete_team_recipients(team_id)
                    .map_err(ControlError::core)?;
                state
                    .set_team_status(team_id, TeamStatus::Closed)
                    .map_err(ControlError::core)?;
                Ok(retired)
            },
        )?;
        Ok(json!({
            "team_id": team_id,
            "team_epoch": team.epoch,
            "status": TeamStatus::Closed,
            "blocking_request_ids": [],
            "blocking_message_ids": [],
            "retired_undeliverable_message_ids": retired_undeliverable_message_ids,
            "actor_stops": actor_stops,
            "failures": [],
            "worktree_cleanup": worktree_cleanup,
            "revision": revision,
            "complete": true,
            "deferred": false,
            "already_closed": false,
        }))
    }

    fn actor_list(&self, request: &Value) -> Result<Value, ControlError> {
        let args: ActorListArgs = decode(request)?;
        let (_, supervisor, _) = self.store.load()?;
        let observed_at_ms = now_ms()?;
        let sessions = self
            .store
            .sessions()?
            .into_iter()
            .map(|record| (record.actor_id.clone(), record))
            .collect::<BTreeMap<_, _>>();
        let actors = supervisor
            .snapshot()
            .actors
            .into_iter()
            .filter(|actor| {
                args.team
                    .as_deref()
                    .is_none_or(|team| actor.team_id.as_ref().is_some_and(|id| id.as_str() == team))
            })
            .map(|actor| {
                let session = sessions.get(actor.actor_id.as_str());
                Ok(json!({
                    "actor": self.actor_value(&actor, observed_at_ms)?,
                    "session": session,
                }))
            })
            .collect::<Result<Vec<_>, ControlError>>()?;
        Ok(json!({ "actors": actors }))
    }

    fn actor_show(&self, request: &Value) -> Result<Value, ControlError> {
        let args: IdArgs = decode(request)?;
        let id = ActorId::new(args.id.clone()).map_err(ControlError::protocol)?;
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&id)
            .ok_or_else(|| ControlError::not_found("actor", &args.id))?;
        Ok(json!({
            "actor": self.actor_value(actor, now_ms()?)?,
            "session": self.store.session(&args.id)?,
        }))
    }

    fn actor_value(&self, actor: &Actor, observed_at_ms: u64) -> Result<Value, ControlError> {
        let summary = self
            .store
            .actor_generation_summary(&actor.actor_ref())?
            .ok_or_else(|| {
                ControlError::new(
                    "actor_generation_summary_missing",
                    format!(
                        "actor generation `{}@{}` has no durable summary",
                        actor.actor_id,
                        actor.epoch.get()
                    ),
                )
            })?;
        if summary.team_id != actor.team_id {
            return Err(ControlError::new(
                "actor_generation_summary_mismatch",
                format!(
                    "actor generation `{}@{}` conflicts with its durable team identity",
                    actor.actor_id,
                    actor.epoch.get()
                ),
            ));
        }
        let mut value = serde_json::to_value(actor).map_err(ControlError::database)?;
        let object = value
            .as_object_mut()
            .expect("protocol actors serialize as JSON objects");
        object.insert(
            "generation_started_at".to_owned(),
            json!(summary.generation_started_at),
        );
        object.insert(
            "generation_age_ms".to_owned(),
            json!(observed_at_ms.saturating_sub(summary.generation_started_at.0)),
        );
        object.insert(
            "completed_assignment_count".to_owned(),
            json!(summary.completed_assignment_count),
        );
        object.insert(
            "completed_assignments_by_team_epoch".to_owned(),
            json!(summary.completed_assignments_by_team_epoch),
        );
        object.insert("team_epoch".to_owned(), json!(summary.team_epoch));
        Ok(value)
    }

    fn run_list(&self, request: &Value) -> Result<Value, ControlError> {
        let args: TeamFilterArgs = decode(request)?;
        let (_, supervisor, _) = self.store.load()?;
        let mut runs = supervisor.snapshot().runs;
        runs.extend(
            self.store
                .archived_requests()?
                .into_iter()
                .map(|(_, run)| run),
        );
        runs.sort_by(|left, right| left.run_id.cmp(&right.run_id));
        let runs = runs
            .into_iter()
            .filter(|run| {
                args.team
                    .as_deref()
                    .is_none_or(|team| run.team_id.as_str() == team)
            })
            .collect::<Vec<_>>();
        Ok(json!({ "runs": runs }))
    }

    fn run_show(&self, request: &Value) -> Result<Value, ControlError> {
        let args: IdArgs = decode(request)?;
        let id = RunId::new(args.id.clone()).map_err(ControlError::protocol)?;
        let (_, supervisor, _) = self.store.load()?;
        if let Some(run) = supervisor.run(&id) {
            let request = supervisor
                .request(&run.request_id)
                .map(|request| self.hydrated_request_value(request))
                .transpose()?;
            return Ok(json!({ "run": run, "request": request }));
        }
        let (request, run) = self
            .store
            .archived_run(&id)?
            .ok_or_else(|| ControlError::not_found("run", &args.id))?;
        Ok(json!({
            "run": run,
            "request": self.hydrated_request_value(&request)?,
        }))
    }

    fn request_list(&self, request: &Value) -> Result<Value, ControlError> {
        let args: RequestListArgs = decode(request)?;
        let (_, supervisor, _) = self.store.load()?;
        let base_reporting = BaseStalenessContext::observe(
            self.review.git_executable(),
            self.identity.repository_root(),
            self.settings.integration_branch.as_deref(),
            now_ms()?,
        );
        let mut requests = supervisor.snapshot().requests;
        requests.extend(
            self.store
                .archived_requests()?
                .into_iter()
                .map(|(request, _)| request),
        );
        requests.sort_by(|left, right| left.request_id.cmp(&right.request_id));
        let requests = requests
            .into_iter()
            .filter(|item| {
                args.team
                    .as_deref()
                    .is_none_or(|team| item.team_id.as_str() == team)
                    && args
                        .state
                        .as_deref()
                        .is_none_or(|state| enum_name(item.status).eq_ignore_ascii_case(state))
            })
            .map(|request| self.reported_request_value(&request, &base_reporting))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({
            "requests": requests,
            "integration_target": base_reporting.target_report(),
        }))
    }

    fn request_show(&self, request: &Value) -> Result<Value, ControlError> {
        let args: IdArgs = decode(request)?;
        let id = RequestId::new(args.id.clone()).map_err(ControlError::protocol)?;
        let (_, supervisor, _) = self.store.load()?;
        let base_reporting = BaseStalenessContext::observe(
            self.review.git_executable(),
            self.identity.repository_root(),
            self.settings.integration_branch.as_deref(),
            now_ms()?,
        );
        if let Some(item) = supervisor.request(&id) {
            return Ok(json!({
                "request": self.reported_request_value(item, &base_reporting)?,
                "run": supervisor.run(&item.run_id),
                "integration_target": base_reporting.target_report(),
            }));
        }
        let (item, run) = self
            .store
            .archived_request(&id)?
            .ok_or_else(|| ControlError::not_found("request", &args.id))?;
        Ok(json!({
            "request": self.reported_request_value(&item, &base_reporting)?,
            "run": run,
            "integration_target": base_reporting.target_report(),
        }))
    }

    fn idempotent(
        &self,
        operation: &str,
        request: &Value,
        operation_id: &str,
        execute: impl FnOnce() -> Result<Value, ControlError>,
    ) -> Result<Value, ControlError> {
        validate_operation_id(operation_id)?;
        if let Some(result) = self
            .store
            .operation_result(operation_id, operation, request)?
        {
            return Ok(result);
        }
        let claim_token = format!(
            "{}-{}-{}",
            std::process::id(),
            now_ms()?,
            NEXT_OPERATION_CLAIM.fetch_add(1, Ordering::Relaxed)
        );
        self.store
            .claim_operation(operation_id, operation, request, &claim_token, now_ms()?)?;
        let result = execute().and_then(|result| {
            self.store
                .record_operation(operation_id, operation, request, &result, now_ms()?)
        });
        let release = self.store.release_operation(operation_id, &claim_token);
        match (result, release) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    fn notify_target(&self, target: &MessageTarget, message: &str) -> Result<(), ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        let actor_ids = match target {
            MessageTarget::Primary => vec![
                supervisor
                    .active_primary()
                    .ok_or_else(|| {
                        ControlError::new(
                            "primary_unavailable",
                            "there is no active Primary Orchestrator to wake",
                        )
                    })?
                    .actor_id,
            ],
            MessageTarget::Actor(actor_id) => vec![actor_id.clone()],
            MessageTarget::Team(team_id) => supervisor
                .team(team_id)
                .ok_or_else(|| ControlError::not_found("team", team_id.as_str()))?
                .actors
                .clone(),
            MessageTarget::Workspace => supervisor
                .snapshot()
                .actors
                .into_iter()
                .filter(|actor| actor.status == ActorStatus::Healthy)
                .map(|actor| actor.actor_id)
                .collect(),
        };
        let team_target = matches!(target, MessageTarget::Team(_));
        let mut notified = 0_u32;
        for actor_id in actor_ids {
            let actor = supervisor
                .actor(&actor_id)
                .ok_or_else(|| ControlError::not_found("actor", actor_id.as_str()))?;
            if actor.status != ActorStatus::Healthy {
                if team_target {
                    continue;
                }
                return Err(ControlError::new(
                    "actor_unavailable",
                    format!("target actor `{actor_id}` is not healthy"),
                )
                .with_hint("run `agsv --json reconcile`, then retry with the same operation ID"));
            }
            let session = self.store.session(actor_id.as_str())?.ok_or_else(|| {
                ControlError::new(
                    "session_not_found",
                    format!("target actor `{actor_id}` has no durable notification session"),
                )
                .with_hint(
                    "bootstrap the target actor context, then retry with the same operation ID",
                )
            })?;
            if supervisor.active_primary().as_ref() == Some(&actor.actor_ref()) {
                let expected_binding = format!("primary-binding:{}:", actor.epoch);
                if !session.launch_key.starts_with(&expected_binding) {
                    return Err(ControlError::new(
                        "stale_notification_endpoint",
                        format!(
                            "Primary actor `{actor_id}` notification endpoint is not bound to its current generation"
                        ),
                    )
                    .with_hint(
                        "run `agsv --json context --bootstrap` in the active Primary caller session, then retry with the same operation ID",
                    ));
                }
                self.sessions
                    .validate_primary_notification_handle(actor_id.as_str(), &session)?;
            }
            self.sessions.notify(&session, message)?;
            notified = notified.saturating_add(1);
        }
        if team_target && notified == 0 {
            return Err(ControlError::new(
                "no_healthy_actor",
                "target team has no healthy Implementation Orchestrator to wake",
            )
            .with_hint("run `agsv --json reconcile`, then retry with the same operation ID"));
        }
        Ok(())
    }

    fn wake_target_after_commit(&self, target: &MessageTarget, message: &str) -> Value {
        match self.notify_target(target, message) {
            Ok(()) => json!({
                "status": "woken",
                "reason": Value::Null,
            }),
            Err(error) => json!({
                "status": "deferred",
                "reason": {
                    "code": error.code,
                    "message": error.message,
                    "hint": error.hint,
                    "details": error.details,
                },
            }),
        }
    }

    fn wake_delivery_target_after_commit(
        &self,
        message_id: &MessageId,
        message: &str,
    ) -> Result<Value, ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        let delivery = supervisor
            .delivery(message_id)
            .ok_or_else(|| ControlError::not_found("message", message_id.as_str()))?;
        if delivery.retired {
            return Ok(json!({
                "status": "not_applicable",
                "reason": "delivery has no reachable generation-fenced recipient",
            }));
        }
        let unresolved = delivery.required_recipients.iter().filter(|recipient| {
            !delivery.acknowledgements.contains_key(*recipient)
                && !delivery.undeliverable_recipients.contains_key(*recipient)
        });
        let mut notified = 0_u32;
        let mut unresolved_count = 0_u32;
        let mut deferred_error = None;
        for recipient in unresolved {
            unresolved_count = unresolved_count.saturating_add(1);
            match recipient {
                DeliveryRecipient::Primary => {
                    match self.notify_target(&MessageTarget::Primary, message) {
                        Ok(()) => notified = notified.saturating_add(1),
                        Err(error) => return Ok(deferred_wake(&error)),
                    }
                }
                DeliveryRecipient::Actor(recipient) => {
                    let Some(actor) = supervisor
                        .actor(&recipient.actor_id)
                        .filter(|actor| actor.actor_ref() == recipient.actor)
                    else {
                        continue;
                    };
                    if actor.status != ActorStatus::Healthy {
                        deferred_error.get_or_insert_with(|| {
                            ControlError::new(
                                "actor_unavailable",
                                format!(
                                    "exact recipient actor `{}` is not healthy",
                                    recipient.actor_id
                                ),
                            )
                        });
                        continue;
                    }
                    match self
                        .notify_target(&MessageTarget::Actor(recipient.actor_id.clone()), message)
                    {
                        Ok(()) => notified = notified.saturating_add(1),
                        Err(error) => return Ok(deferred_wake(&error)),
                    }
                }
            }
        }
        if let Some(error) = deferred_error {
            return Ok(deferred_wake(&error));
        }
        if notified == 0 {
            return if unresolved_count == 0 {
                Ok(json!({
                    "status": "not_applicable",
                    "reason": "delivery has no unresolved generation-fenced recipient",
                }))
            } else {
                Ok(deferred_wake(&ControlError::new(
                    "exact_recipient_unavailable",
                    "an unresolved exact recipient generation is not currently reachable",
                )))
            };
        }
        Ok(json!({
            "status": "woken",
            "reason": Value::Null,
        }))
    }

    fn wake_request_target_after_commit(
        &self,
        request_id: &RequestId,
        target: &MessageTarget,
        message: &str,
    ) -> Result<Value, ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        let request = supervisor
            .request(request_id)
            .ok_or_else(|| ControlError::not_found("request", request_id.as_str()))?;
        if supervisor
            .team(&request.team_id)
            .is_some_and(|team| request.team_epoch < team.epoch)
        {
            return Ok(json!({
                "status": "not_applicable",
                "reason": "request belongs to a superseded team generation",
            }));
        }
        Ok(self.wake_target_after_commit(target, message))
    }

    fn ensure_primary_notification_session(
        &self,
        actor_ref: &ActorRef,
    ) -> Result<(), ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        let Some(_actor) = supervisor
            .actor(&actor_ref.actor_id)
            .filter(|actor| actor.epoch == actor_ref.actor_epoch)
        else {
            return Err(ControlError::new(
                "stale_actor_binding",
                "the Primary notification endpoint belongs to a stale actor generation",
            ));
        };
        if supervisor.active_primary().as_ref() != Some(actor_ref) {
            return Ok(());
        }
        let mut session = self.primary_notification_session(actor_ref, now_ms()?)?;
        if let Some(existing) = self.store.session(actor_ref.actor_id.as_str())? {
            if existing.actor_id == session.actor_id
                && existing.team_id == session.team_id
                && existing.working_directory == session.working_directory
                && existing.backend == session.backend
                && existing.runtime == session.runtime
                && existing.external_id == session.external_id
                && existing.resume_token == session.resume_token
                && existing.status == session.status
                && existing.launch_key == session.launch_key
            {
                return Ok(());
            }
            session.row_revision = existing.row_revision;
        }
        session.row_revision = self.store.upsert_session(&session)?;
        Ok(())
    }

    fn primary_notification_session(
        &self,
        actor_ref: &ActorRef,
        observed_at_ms: u64,
    ) -> Result<SessionRecord, ControlError> {
        let caller_endpoint = self
            .caller_identity
            .context()
            .primary_notification_endpoint();
        let handle = self.sessions.primary_notification_handle(
            self.identity.workspace_id().as_str(),
            actor_ref.actor_id.as_str(),
            actor_ref.actor_epoch.get(),
            caller_endpoint.as_ref(),
        )?;
        let external_id = handle.external_id;
        let resume_token = handle.resume_token;
        Ok(SessionRecord {
            actor_id: actor_ref.actor_id.to_string(),
            team_id: None,
            working_directory: self.identity.root().to_path_buf(),
            backend: self.sessions.name().to_owned(),
            runtime: None,
            external_id: Some(external_id.clone()),
            resume_token,
            status: "idle".to_owned(),
            launch_key: format!(
                "primary-binding:{}:{}",
                actor_ref.actor_epoch,
                sha256_hex(&external_id)
            ),
            updated_at_ms: observed_at_ms,
            row_revision: 0,
        })
    }
}

fn prevalidate_before_authentication(operation: &str, request: &Value) -> Result<(), ControlError> {
    if operation != "request.create" {
        return Ok(());
    }
    let args: RequestCreateArgs = decode(request)?;
    prevalidate_character_limit("request.title", &args.title, 256)?;
    if let Some(body) = &args.body {
        prevalidate_character_limit("request.body", body, MAX_REQUEST_TEXT_CHARACTERS)?;
    }
    Ok(())
}

fn prevalidate_character_limit(
    field: &str,
    value: &str,
    maximum: usize,
) -> Result<(), ControlError> {
    let actual = value.chars().count();
    if actual <= maximum {
        return Ok(());
    }
    let overflow = actual - maximum;
    let unit = if overflow == 1 {
        "character"
    } else {
        "characters"
    };
    Err(ControlError::new(
        "validation_error",
        format!("`{field}` exceeds the {maximum}-character maximum by {overflow} {unit}"),
    )
    .with_details(json!({
        "field": field,
        "validation_code": "out_of_range",
        "unit": "characters",
        "actual": actual,
        "maximum": maximum,
        "overflow": overflow,
    })))
}

fn retry_request_matches(
    args: &RequestCreateArgs,
    instructions: &str,
    team_id: &TeamId,
    request_id: &RequestId,
    run_id: &RunId,
    envelope: &Envelope,
) -> bool {
    envelope.team_id.as_ref() == Some(team_id)
        && envelope.request_id.as_ref() == Some(request_id)
        && envelope.run_id.as_ref() == Some(run_id)
        && matches!(
            &envelope.message,
            Message::ImplementationRequest(specification)
                if specification.title == args.title
                    && specification.instructions == instructions
                    && specification.base_source
                        == if args.base_sha.is_some() {
                            agsv_protocol::RequestBaseSource::Declared
                        } else {
                            agsv_protocol::RequestBaseSource::Derived
                        }
                    && args
                        .base_sha
                        .as_deref()
                        .is_none_or(|base_sha| specification.base_sha.as_str().eq_ignore_ascii_case(base_sha))
                    && specification.acceptance_criteria == [instructions]
                    && specification.evidence_requirements == [EvidenceKind::Git, EvidenceKind::Test]
        )
}

impl ControlPlane {
    fn bootstrap_actor(&self, requested: Option<&str>) -> Result<ActorRef, ControlError> {
        let actor_ref = if let Some(identity) = self.caller_identity.context().insecure_actor() {
            self.bootstrap_insecure_actor(identity, requested)?
        } else if let Some(binding) = self.caller_identity.context().binding() {
            self.bootstrap_bound_actor(binding, requested)?
        } else {
            return Err(identity_unavailable());
        };
        self.ensure_primary_notification_session(&actor_ref)?;
        Ok(actor_ref)
    }

    fn resolve_actor(&self, requested: Option<&str>) -> Result<Actor, ControlError> {
        let actor_ref = self.authenticated_actor_ref(requested)?;
        self.actor_for_ref(&actor_ref)
    }

    fn resolve_actor_allow_stopped(&self, requested: Option<&str>) -> Result<Actor, ControlError> {
        let actor_ref = self.caller_actor_ref(requested)?;
        let actor = self.actor_for_ref(&actor_ref)?;
        if actor.status == ActorStatus::Stopped {
            return Ok(actor);
        }
        self.heartbeat_actor(&actor_ref, "actor.authenticated")?;
        self.ensure_primary_notification_session(&actor_ref)?;
        self.actor_for_ref(&actor_ref)
    }

    fn actor_for_ref(&self, actor_ref: &ActorRef) -> Result<Actor, ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&actor_ref.actor_id)
            .filter(|actor| actor.epoch == actor_ref.actor_epoch)
            .cloned()
            .ok_or_else(|| superseded_binding(&supervisor, actor_ref))?;
        self.actor_profile(&actor)?;
        Ok(actor)
    }

    #[allow(clippy::too_many_lines)]
    fn bootstrap_bound_actor(
        &self,
        caller_binding: &CallerBinding,
        requested: Option<&str>,
    ) -> Result<ActorRef, ControlError> {
        if let Some(binding) = self
            .store
            .actor_binding(caller_binding.kind(), caller_binding.value())?
        {
            assert_actor(requested, &binding.actor.actor_id)?;
            let (_, supervisor, _) = self.store.load()?;
            if let Some(actor) = supervisor
                .actor(&binding.actor.actor_id)
                .filter(|actor| actor.epoch == binding.actor.actor_epoch)
            {
                if let Some(team_id) = &actor.team_id {
                    if actor.status == ActorStatus::Stopped {
                        Self::ensure_desired_team_actor(
                            &supervisor,
                            team_id,
                            &binding.actor.actor_id,
                        )?;
                        return self
                            .store
                            .bootstrap_stopped_implementation(
                                caller_binding.kind(),
                                caller_binding.value(),
                                &binding.actor,
                                team_id,
                                now_ms()?,
                            )
                            .map(|(_, actor_ref)| actor_ref);
                    }
                    self.heartbeat_actor(&binding.actor, "actor.bootstrapped")?;
                    return Ok(binding.actor);
                }
                if supervisor.active_primary().as_ref() == Some(&binding.actor) {
                    self.heartbeat_actor(&binding.actor, "actor.bootstrapped")?;
                    return Ok(binding.actor);
                }
                if supervisor.active_primary().is_none() {
                    if actor.status == ActorStatus::Stopped {
                        let profile = self.primary_profile()?.clone();
                        let configured_role = profile.actor_role()?;
                        let configured_snapshot = profile.snapshot()?;
                        let observed_at = now_ms()?;
                        return self
                            .store
                            .bootstrap_stopped_primary(
                                caller_binding.kind(),
                                caller_binding.value(),
                                &binding.actor,
                                observed_at,
                                |state| {
                                    let replacement = activate_primary_for_profile(
                                        state,
                                        &binding.actor.actor_id,
                                        &profile,
                                        &configured_role,
                                        &configured_snapshot,
                                        self.settings.persist_profile_snapshots,
                                    )?;
                                    state
                                        .heartbeat(&replacement, TimestampMillis(observed_at))
                                        .map_err(ControlError::core)?;
                                    let session = self
                                        .primary_notification_session(&replacement, observed_at)?;
                                    Ok((replacement, session))
                                },
                            )
                            .map(|(_, actor_ref)| actor_ref);
                    }
                    let actor_id = binding.actor.actor_id;
                    let actor_ref = self.activate_primary(&actor_id)?;
                    self.store.bind_actor(
                        caller_binding.kind(),
                        caller_binding.value(),
                        &actor_ref,
                        now_ms()?,
                    )?;
                    return Ok(actor_ref);
                }
                return Err(primary_lease_held(
                    &supervisor
                        .active_primary()
                        .expect("active Primary was checked")
                        .actor_id,
                ));
            }
            return Err(ControlError::new(
                "stale_actor_binding",
                "the caller session is bound to a stale actor generation",
            ));
        }

        if let Some(session) = self.store.sessions()?.into_iter().find(|session| {
            self.caller_identity
                .context()
                .matches_persisted_session(&session.backend, session.resume_token.as_deref())
        }) {
            let actor_id = ActorId::new(session.actor_id).map_err(ControlError::protocol)?;
            assert_actor(requested, &actor_id)?;
            let (_, supervisor, _) = self.store.load()?;
            let actor_ref = supervisor
                .actor(&actor_id)
                .ok_or_else(|| ControlError::not_found("actor", actor_id.as_str()))?
                .actor_ref();
            // The outer invocation is still holding the stable unbound caller
            // key. Add the resolved actor key before publishing the binding so
            // target-side stop or replacement cannot cross that key transition.
            let _actor_operation_lock = self
                .store
                .lock_actor_operations("actor", actor_ref.actor_id.as_str())?;
            self.store.bind_actor(
                caller_binding.kind(),
                caller_binding.value(),
                &actor_ref,
                now_ms()?,
            )?;
            self.heartbeat_actor(&actor_ref, "actor.bootstrapped")?;
            return Ok(actor_ref);
        }

        let (_, supervisor, _) = self.store.load()?;
        if let Some(primary) = supervisor.active_primary() {
            return Err(ControlError::new(
                "primary_lease_held",
                format!(
                    "active Primary `{}` is bound to another session",
                    primary.actor_id
                ),
            )
            .with_hint("use the active Primary caller session, or wait for and verify lease expiry before bootstrapping a replacement"));
        }
        let actor_id = match requested {
            Some(value) => ActorId::new(value.to_owned()).map_err(ControlError::protocol)?,
            None => primary_actor_id(caller_binding.value())?,
        };
        let actor_ref = self.activate_primary(&actor_id)?;
        self.store.bind_actor(
            caller_binding.kind(),
            caller_binding.value(),
            &actor_ref,
            now_ms()?,
        )?;
        Ok(actor_ref)
    }

    fn bootstrap_insecure_actor(
        &self,
        identity: &InsecureActorIdentity,
        requested: Option<&str>,
    ) -> Result<ActorRef, ControlError> {
        let value = identity.actor_id().ok_or_else(identity_unavailable)?;
        let actor_id = ActorId::new(value.to_owned()).map_err(ControlError::protocol)?;
        assert_actor(requested, &actor_id)?;
        let (_, supervisor, _) = self.store.load()?;
        if let Some(actor) = supervisor.actor(&actor_id) {
            if actor.team_id.is_none() && supervisor.active_primary().is_none() {
                return self.activate_primary(&actor_id);
            }
            let actor_ref = actor.actor_ref();
            self.heartbeat_actor(&actor_ref, "actor.bootstrapped")?;
            return Ok(actor_ref);
        }
        if identity.role() != Some("primary") {
            return Err(ControlError::new(
                "unknown_implementation_actor",
                format!(
                    "implementation actor `{actor_id}` is not registered; create its team first"
                ),
            ));
        }
        if let Some(primary) = supervisor.active_primary() {
            return Err(ControlError::new(
                "primary_lease_held",
                format!(
                    "active Primary `{}` is bound to another actor",
                    primary.actor_id
                ),
            ));
        }
        self.activate_primary(&actor_id)
    }

    fn activate_primary(&self, actor_id: &ActorId) -> Result<ActorRef, ControlError> {
        let profile = self.primary_profile()?.clone();
        let configured_role = profile.actor_role()?;
        let configured_snapshot = profile.snapshot()?;
        let observed_at = now_ms()?;
        let (_, actor_ref) = self.store.mutate(
            "primary.bootstrapped",
            &json!({ "actor_id": actor_id, "profile": profile.name }),
            observed_at,
            |state| {
                if let Some(active) = state.active_primary()
                    && active.actor_id != *actor_id
                {
                    return Err(primary_lease_held(&active.actor_id));
                }
                let actor_ref = activate_primary_for_profile(
                    state,
                    actor_id,
                    &profile,
                    &configured_role,
                    &configured_snapshot,
                    self.settings.persist_profile_snapshots,
                )?;
                state
                    .heartbeat(&actor_ref, TimestampMillis(observed_at))
                    .map_err(ControlError::core)?;
                Ok(actor_ref)
            },
        )?;
        Ok(actor_ref)
    }

    fn authenticated_actor_ref(&self, requested: Option<&str>) -> Result<ActorRef, ControlError> {
        let actor_ref = self.caller_actor_ref(requested)?;
        self.ensure_actor_binding_is_mutable(&actor_ref)?;
        self.heartbeat_actor(&actor_ref, "actor.authenticated")?;
        self.ensure_primary_notification_session(&actor_ref)?;
        Ok(actor_ref)
    }

    fn caller_actor_ref(&self, requested: Option<&str>) -> Result<ActorRef, ControlError> {
        #[cfg(test)]
        if let Some(actor_ref) = self.test_actor_override() {
            assert_actor(requested, &actor_ref.actor_id)?;
            return Ok(actor_ref);
        }
        let actor_ref = if let Some(identity) = self.caller_identity.context().insecure_actor() {
            let value = identity.actor_id().ok_or_else(identity_unavailable)?;
            let actor_id = ActorId::new(value.to_owned()).map_err(ControlError::protocol)?;
            let (_, supervisor, _) = self.store.load()?;
            supervisor
                .actor(&actor_id)
                .ok_or_else(|| ControlError::not_found("actor", actor_id.as_str()))?
                .actor_ref()
        } else if let Some(caller_binding) = self.caller_identity.context().binding() {
            if let Some(binding) = self
                .store
                .actor_binding(caller_binding.kind(), caller_binding.value())?
            {
                binding.actor
            } else {
                return Err(ControlError::new(
                    "actor_session_unbound",
                    "the current caller session is not bound to an AGSV actor",
                )
                .with_hint("run `agsv --json context --bootstrap` in this caller session"));
            }
        } else {
            return Err(identity_unavailable());
        };
        assert_actor(requested, &actor_ref.actor_id)?;
        Ok(actor_ref)
    }

    fn caller_operation_scope(&self) -> Option<(String, String)> {
        #[cfg(test)]
        if let Some(actor_ref) = self.test_actor_override() {
            return Some(("actor".to_owned(), actor_ref.actor_id.as_str().to_owned()));
        }
        if let Some(binding) = self.caller_identity.context().binding() {
            return Some((binding.kind().to_owned(), binding.value().to_owned()));
        }
        self.caller_identity
            .context()
            .insecure_actor()
            .and_then(InsecureActorIdentity::actor_id)
            .map(|actor_id| ("actor".to_owned(), actor_id.to_owned()))
    }

    fn acquire_operation_guards(
        &self,
        operation: &str,
        request: &Value,
    ) -> Result<OperationGuards, ControlError> {
        let workspace_mode = workspace_operation_lock_mode(operation, request);
        #[cfg(test)]
        if workspace_mode.is_some() {
            self.observe_test_operation_phase("before_workspace_lock", operation)?;
        }
        let workspace = workspace_mode
            .map(|mode| self.store.lock_operations(mode))
            .transpose()?;
        let (primary_mode, expire_primary) =
            self.primary_authority_lock_mode(operation, request)?;
        #[cfg(test)]
        if primary_mode.is_some() {
            self.observe_test_operation_phase("before_primary_lock", operation)?;
        }
        let primary = primary_mode
            .map(|mode| self.store.lock_primary_operations(mode))
            .transpose()?;
        let caller_scope = caller_linearization_operation(operation, request)
            .then(|| self.caller_operation_scope())
            .flatten();
        #[cfg(test)]
        if caller_scope.is_some() {
            self.observe_test_operation_phase("before_caller_lock", operation)?;
        }
        let caller = caller_scope
            .as_ref()
            .map(|(kind, value)| self.store.lock_actor_operations(kind, value))
            .transpose()?;
        let mut actor_scopes = self.actor_identity_operation_scopes(operation, request)?;
        if let Some((kind, value)) = caller_scope.as_ref()
            && kind == "actor"
        {
            actor_scopes.remove(value);
        }
        let actors = actor_scopes
            .into_iter()
            .map(|actor_id| self.store.lock_actor_operations("actor", &actor_id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(OperationGuards {
            workspace,
            _primary: primary,
            primary_exclusive: primary_mode == Some(OperationLockMode::Exclusive),
            _caller: caller,
            _actors: actors,
            expire_primary,
        })
    }

    #[cfg(test)]
    fn observe_test_operation_phase(&self, phase: &str, subject: &str) -> Result<(), ControlError> {
        if let Some(observer) = TEST_OPERATION_PHASES
            .lock()
            .map_err(|_| ControlError::database("test operation-phase observer mutex poisoned"))?
            .get(&(self.identity.workspace_id().to_string(), phase.to_owned()))
            .cloned()
        {
            observer(subject);
        }
        Ok(())
    }

    fn primary_authority_lock_mode(
        &self,
        operation: &str,
        request: &Value,
    ) -> Result<(Option<OperationLockMode>, bool), ControlError> {
        if public_read_operation(operation) {
            return Ok((None, false));
        }
        let caller = match self.caller_actor_ref(None) {
            Ok(actor_ref) => Some(actor_ref),
            Err(error)
                if matches!(
                    error.code,
                    "actor_identity_unavailable" | "actor_session_unbound" | "not_found"
                ) =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        let (caller_is_primary, caller_can_recover_expired_primary) =
            if let Some(actor_ref) = caller.as_ref() {
                let (_, state, _) = self.store.load()?;
                let observed_at = now_ms()?;
                let actor = state.actor(&actor_ref.actor_id).filter(|actor| {
                    actor.epoch == actor_ref.actor_epoch && actor.team_id.is_none()
                });
                let caller_is_primary = actor.is_some();
                let can_recover = actor.is_some_and(|actor| {
                    (actor.status == ActorStatus::Stale && state.active_primary().is_none())
                        || (state.active_primary().as_ref() == Some(actor_ref)
                            && self.actor_expired(actor, observed_at))
                });
                (caller_is_primary, can_recover)
            } else {
                (false, false)
            };
        if operation == "context" && context_bootstrap_requested(request) {
            let may_reacquire_primary = caller_is_primary || caller.is_none();
            return Ok((
                may_reacquire_primary.then_some(OperationLockMode::Exclusive),
                may_reacquire_primary,
            ));
        }
        if operation == "actor.shutdown" && caller_is_primary {
            return Ok((Some(OperationLockMode::Exclusive), true));
        }
        if caller_can_recover_expired_primary
            || (caller_is_primary && caller_authentication_required(operation, request))
        {
            return Ok((Some(OperationLockMode::Exclusive), true));
        }
        Ok((
            (primary_operation(operation) || operation == "review.show" || caller_is_primary)
                .then_some(OperationLockMode::Shared),
            caller_is_primary,
        ))
    }

    fn actor_identity_operation_scopes(
        &self,
        operation: &str,
        request: &Value,
    ) -> Result<BTreeSet<String>, ControlError> {
        if !caller_linearization_operation(operation, request) {
            return Ok(BTreeSet::new());
        }
        let mut actor_ids = BTreeSet::new();
        match self.caller_actor_ref(None) {
            Ok(actor_ref) => {
                actor_ids.insert(actor_ref.actor_id.to_string());
            }
            Err(error)
                if matches!(
                    error.code,
                    "actor_identity_unavailable" | "actor_session_unbound" | "not_found"
                ) => {}
            Err(error) => return Err(error),
        }
        if matches!(operation, "actor.stop" | "actor.replace")
            && let Some(actor_id) = request.get("id").and_then(Value::as_str)
        {
            actor_ids.insert(actor_id.to_owned());
        }
        Ok(actor_ids)
    }

    #[cfg(test)]
    fn test_actor_override(&self) -> Option<ActorRef> {
        self.test_authenticated_actor
            .lock()
            .expect("local test authenticated-actor mutex must remain available")
            .clone()
            .or_else(|| {
                TEST_AUTHENTICATED_ACTORS
                    .lock()
                    .expect("test authenticated-actor mutex must remain available")
                    .get(self.identity.workspace_id().as_str())
                    .cloned()
            })
    }

    fn ensure_actor_binding_is_mutable(&self, actor_ref: &ActorRef) -> Result<(), ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        let Some(actor) = supervisor.actor(&actor_ref.actor_id) else {
            return Err(superseded_binding(&supervisor, actor_ref));
        };
        if actor.epoch != actor_ref.actor_epoch {
            return Err(superseded_binding(&supervisor, actor_ref));
        }
        if actor.status == ActorStatus::Stopped {
            return Err(terminal_actor_binding(actor_ref));
        }
        if actor.team_id.is_none()
            && (actor.status == ActorStatus::Revoked
                || supervisor.active_primary().is_some()
                    && supervisor.active_primary().as_ref() != Some(actor_ref))
        {
            return Err(superseded_primary_binding(actor_ref));
        }
        Ok(())
    }

    fn caller_mutation_fence(&self) -> Result<Option<CallerMutationFence>, ControlError> {
        let actor_ref = match self.caller_actor_ref(None) {
            Ok(actor_ref) => actor_ref,
            Err(error)
                if matches!(
                    error.code,
                    "actor_identity_unavailable" | "actor_session_unbound" | "not_found"
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let (_, supervisor, _) = self.store.load()?;
        let fence = match supervisor.actor(&actor_ref.actor_id) {
            Some(actor)
                if actor.team_id.is_none()
                    && (actor.epoch != actor_ref.actor_epoch
                        || actor.status == ActorStatus::Revoked
                        || supervisor.active_primary().is_some()
                            && supervisor.active_primary().as_ref() != Some(&actor_ref)) =>
            {
                CallerMutationFence::SupersededPrimary(actor_ref)
            }
            Some(actor)
                if actor.epoch == actor_ref.actor_epoch && actor.status == ActorStatus::Stopped =>
            {
                CallerMutationFence::Stopped(actor_ref)
            }
            Some(actor) if actor.epoch != actor_ref.actor_epoch => {
                CallerMutationFence::Superseded(actor_ref)
            }
            None => CallerMutationFence::Superseded(actor_ref),
            Some(_) => return Ok(None),
        };
        Ok(Some(fence))
    }

    fn recover_expired_primary_binding(
        &self,
        primary_authority_exclusive: bool,
    ) -> Result<Option<ActorRef>, ControlError> {
        let Some(caller_binding) = self.caller_identity.context().binding() else {
            return Ok(None);
        };
        let Some(binding) = self
            .store
            .actor_binding(caller_binding.kind(), caller_binding.value())?
        else {
            return Ok(None);
        };
        let (_, supervisor, _) = self.store.load()?;
        let Some(actor) = supervisor
            .actor(&binding.actor.actor_id)
            .filter(|actor| actor.epoch == binding.actor.actor_epoch)
        else {
            return Err(superseded_binding(&supervisor, &binding.actor));
        };
        if actor.team_id.is_some() || !actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY) {
            return Ok(None);
        }
        if supervisor.active_primary().as_ref() == Some(&binding.actor)
            || actor.status == ActorStatus::Stopped
        {
            return Ok(None);
        }
        if supervisor.active_primary().is_some() || actor.status != ActorStatus::Stale {
            return Err(superseded_primary_binding(&binding.actor));
        }
        if !primary_authority_exclusive {
            return Err(ControlError::new(
                "primary_lease_expired",
                "the authenticated Primary lease expired while the command was being admitted",
            )
            .with_hint(
                "retry the command; if it carries --operation-id, reuse the same operation ID",
            )
            .with_details(json!({ "actor": binding.actor })));
        }
        let profile = self.primary_profile()?.clone();
        let configured_role = profile.actor_role()?;
        let configured_snapshot = profile.snapshot()?;
        let observed_at = now_ms()?;
        self.store
            .recover_expired_primary(
                caller_binding.kind(),
                caller_binding.value(),
                &binding.actor,
                observed_at,
                |state| {
                    let replacement = activate_primary_for_profile(
                        state,
                        &binding.actor.actor_id,
                        &profile,
                        &configured_role,
                        &configured_snapshot,
                        self.settings.persist_profile_snapshots,
                    )?;
                    state
                        .heartbeat(&replacement, TimestampMillis(observed_at))
                        .map_err(ControlError::core)?;
                    let session = self.primary_notification_session(&replacement, observed_at)?;
                    Ok((replacement, session))
                },
            )
            .map(|(_, actor_ref)| Some(actor_ref))
            .map_err(|error| {
                if error.code == "stale_actor_binding" {
                    superseded_primary_binding(&binding.actor)
                } else {
                    error
                }
            })
    }

    fn authenticate_primary(&self) -> Result<ActorRef, ControlError> {
        let actor_ref = self.authenticated_actor_ref(None)?;
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&actor_ref.actor_id)
            .filter(|actor| actor.epoch == actor_ref.actor_epoch)
            .ok_or_else(|| superseded_binding(&supervisor, &actor_ref))?;
        self.actor_profile(actor)?;
        if !actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
            || supervisor.active_primary().as_ref() != Some(&actor_ref)
        {
            return Err(ControlError::new(
                "primary_authentication_required",
                "this command requires the authenticated active Primary session",
            )
            .with_hint(
                "use the active Primary caller session; if its lease expired, retry the command and reuse any operation ID it carries",
            ));
        }
        Ok(actor_ref)
    }

    fn authenticate_primary_read_only(&self) -> Result<ActorRef, ControlError> {
        let actor_ref = self.caller_actor_ref(None)?;
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&actor_ref.actor_id)
            .filter(|actor| actor.epoch == actor_ref.actor_epoch)
            .ok_or_else(|| superseded_binding(&supervisor, &actor_ref))?;
        self.actor_profile(actor)?;
        let current_primary = supervisor.active_primary();
        let exact_active = current_primary.as_ref() == Some(&actor_ref);
        let terminal_without_replacement =
            actor.status == ActorStatus::Stopped && current_primary.is_none();
        if !actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
            || !(exact_active || terminal_without_replacement)
        {
            return Err(ControlError::new(
                "primary_authentication_required",
                "this command requires the authenticated current or stopped Primary session",
            )
            .with_hint("use the current Primary caller session"));
        }
        Ok(actor_ref)
    }

    fn heartbeat_actor(&self, actor_ref: &ActorRef, operation: &str) -> Result<(), ControlError> {
        let observed_at = now_ms()?;
        self.store.mutate(
            operation,
            &json!({ "actor_id": actor_ref.actor_id }),
            observed_at,
            |state| {
                let actor = state.actor(&actor_ref.actor_id).ok_or_else(|| {
                    ControlError::not_found("actor", actor_ref.actor_id.as_str())
                })?;
                if actor.team_id.is_none()
                    && actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
                {
                    if state.active_primary().as_ref() != Some(actor_ref) {
                        return Err(if state.active_primary().is_some() {
                            superseded_primary_binding(actor_ref)
                        } else {
                            ControlError::new(
                                "primary_lease_expired",
                                "the authenticated Primary lease is no longer active",
                            )
                            .with_hint(
                                "retry the command from its durable caller session; debug fixtures must explicitly bootstrap a new generation",
                            )
                            .with_details(json!({ "actor": actor_ref }))
                        });
                    }
                    if self.actor_expired(actor, observed_at) {
                        return Err(ControlError::new(
                            "primary_lease_expired",
                            "the authenticated Primary lease expired before it could be renewed",
                        )
                        .with_hint(
                            "retry the command; if it carries --operation-id, reuse the same operation ID",
                        )
                        .with_details(json!({
                            "actor": actor_ref,
                            "last_heartbeat_at_ms": actor.last_heartbeat_at.map(|timestamp| timestamp.0),
                            "observed_at_ms": observed_at,
                            "primary_lease_seconds": self.settings.primary_lease_seconds,
                        })));
                    }
                }
                state
                    .heartbeat(actor_ref, TimestampMillis(observed_at))
                    .map_err(super::ControlError::core)
            },
        )?;
        Ok(())
    }

    fn primary_lease_summary(&self, supervisor: &Supervisor, observed_at_ms: u64) -> Value {
        let actor_ref = supervisor.active_primary();
        let last_heartbeat_at_ms = actor_ref
            .as_ref()
            .and_then(|actor_ref| supervisor.actor(&actor_ref.actor_id))
            .and_then(|actor| actor.last_heartbeat_at)
            .map(|timestamp| timestamp.0);
        let lease_ms = u64::from(self.settings.primary_lease_seconds).saturating_mul(1_000);
        let expires_at_ms = last_heartbeat_at_ms.map(|last| last.saturating_add(lease_ms));
        let remaining_ms = expires_at_ms.map_or(0, |expiry| expiry.saturating_sub(observed_at_ms));
        json!({
            "active": actor_ref.is_some(),
            "actor_ref": actor_ref,
            "last_heartbeat_at_ms": last_heartbeat_at_ms,
            "expires_at_ms": expires_at_ms,
            "remaining_ms": remaining_ms,
        })
    }

    fn expire_stale_actors(&self, include_primary: bool) -> Result<(), ControlError> {
        let observed_at = now_ms()?;
        let (_, supervisor, _) = self.store.load()?;
        if !supervisor.snapshot().actors.iter().any(|actor| {
            (include_primary || actor.team_id.is_some()) && self.actor_expired(actor, observed_at)
        }) {
            return Ok(());
        }
        self.store.mutate(
            "actor.leases_expired",
            &json!({ "observed_at_ms": observed_at }),
            observed_at,
            |state| {
                let expired = state
                    .snapshot()
                    .actors
                    .into_iter()
                    .filter(|actor| {
                        (include_primary || actor.team_id.is_some())
                            && self.actor_expired(actor, observed_at)
                    })
                    .map(|actor| actor.actor_ref())
                    .collect::<Vec<_>>();
                for actor_ref in expired {
                    state
                        .set_actor_status(&actor_ref, ActorStatus::Stale)
                        .map_err(ControlError::core)?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    fn actor_expired(&self, actor: &Actor, observed_at: u64) -> bool {
        if actor.status != ActorStatus::Healthy {
            return false;
        }
        let ttl_seconds = if actor.team_id.is_none() {
            u64::from(self.settings.primary_lease_seconds)
        } else {
            u64::from(self.settings.actor_heartbeat_seconds).saturating_mul(3)
        };
        let ttl_ms = ttl_seconds.saturating_mul(1_000);
        actor
            .last_heartbeat_at
            .is_none_or(|last| observed_at.saturating_sub(last.0) >= ttl_ms)
    }

    fn insecure_debug_identity_selected(&self) -> bool {
        self.caller_identity.insecure_debug_selected()
    }

    fn debug_crash_requested(&self, environment_variable: &str, crash_point: &str) -> bool {
        if !cfg!(debug_assertions) {
            return false;
        }
        if self.insecure_debug_identity_selected()
            && std::env::var(environment_variable).as_deref() == Ok("1")
        {
            return true;
        }
        #[cfg(test)]
        {
            return TEST_CRASH_POINTS
                .lock()
                .expect("test crash-point mutex must remain available")
                .remove(&(
                    self.identity.workspace_id().to_string(),
                    crash_point.to_owned(),
                ));
        }
        #[cfg(not(test))]
        {
            let _ = crash_point;
            false
        }
    }

    #[cfg(test)]
    fn arm_test_crash(&self, crash_point: &str) {
        TEST_CRASH_POINTS
            .lock()
            .expect("test crash-point mutex must remain available")
            .insert((
                self.identity.workspace_id().to_string(),
                crash_point.to_owned(),
            ));
    }

    #[cfg(test)]
    fn set_test_authenticated_actor(&self, actor_ref: ActorRef) {
        TEST_AUTHENTICATED_ACTORS
            .lock()
            .expect("test authenticated-actor mutex must remain available")
            .insert(self.identity.workspace_id().to_string(), actor_ref);
    }

    #[cfg(test)]
    fn set_test_authenticated_actor_local(&self, actor_ref: ActorRef) {
        *self
            .test_authenticated_actor
            .lock()
            .expect("local test authenticated-actor mutex must remain available") = Some(actor_ref);
    }

    #[cfg(test)]
    fn set_test_caller_binding(&mut self, kind: &'static str, value: &str) {
        self.caller_identity = CallerIdentityDriver::test_bound(self.sessions.name(), kind, value);
    }

    #[cfg(test)]
    fn set_after_caller_fence(&self, observer: impl Fn(&str) + Send + Sync + 'static) {
        TEST_AFTER_CALLER_FENCE
            .lock()
            .expect("test caller-fence observer mutex must remain available")
            .insert(self.identity.workspace_id().to_string(), Arc::new(observer));
    }

    #[cfg(test)]
    fn clear_after_caller_fence(&self) {
        TEST_AFTER_CALLER_FENCE
            .lock()
            .expect("test caller-fence observer mutex must remain available")
            .remove(self.identity.workspace_id().as_str());
    }

    #[cfg(test)]
    fn set_operation_phase_observer(
        &self,
        phase: &str,
        observer: impl Fn(&str) + Send + Sync + 'static,
    ) {
        TEST_OPERATION_PHASES
            .lock()
            .expect("test operation-phase observer mutex must remain available")
            .insert(
                (self.identity.workspace_id().to_string(), phase.to_owned()),
                Arc::new(observer),
            );
    }

    #[cfg(test)]
    fn clear_operation_phase_observer(&self, phase: &str) {
        TEST_OPERATION_PHASES
            .lock()
            .expect("test operation-phase observer mutex must remain available")
            .remove(&(self.identity.workspace_id().to_string(), phase.to_owned()));
    }

    #[allow(clippy::too_many_lines)]
    fn team_create(&self, request: &Value) -> Result<Value, ControlError> {
        let args: TeamCreateArgs = decode(request)?;
        self.idempotent("team.create", request, &args.operation_id, || {
            let (_, supervisor, active) = self.store.load()?;
            if !active {
                return Err(ControlError::new(
                    "controller_inactive",
                    "run `agsv start` before creating a team",
                ));
            }
            if supervisor.active_primary().is_none() {
                return Err(ControlError::new(
                    "primary_required",
                    "run `agsv context --bootstrap` from the Primary before creating a team",
                ));
            }
            let team_id = TeamId::new(format!("team-{}", slug(&args.name)))
                .map_err(ControlError::protocol)?;
            let purpose = normalize_team_purpose(args.purpose.as_deref())?;
            if supervisor.team(&team_id).is_some_and(|team| {
                matches!(team.status, TeamStatus::Paused | TeamStatus::Closing)
            }) {
                return Err(ControlError::new(
                    "team_inactive",
                    "paused or closing teams do not launch actor instances",
                ));
            }
            let (selected_team, selected_actor, profile_mode) = self
                .team_control_profile(supervisor.team(&team_id), args.profile.as_deref())?;
            let configured_role = selected_actor.actor_role()?;
            let actor_snapshot = selected_actor.snapshot()?;
            let team_snapshot = selected_team.snapshot()?;
            let previous_team_epoch = supervisor.team(&team_id).and_then(|team| {
                matches!(team.status, TeamStatus::Closed | TeamStatus::Retired)
                    .then_some(team.epoch)
            });
            if let Some(team) = supervisor
                .team(&team_id)
                .filter(|team| matches!(team.status, TeamStatus::Closed | TeamStatus::Retired))
            {
                self.store.prepare_team_recreation(team, now_ms()?)?;
                if self.debug_crash_requested(
                    "AGSV_DEV_FAIL_AFTER_TEAM_RECREATION_PREPARE",
                    "team_recreation_prepare",
                ) {
                    return Err(ControlError::new(
                        "simulated_team_recreation_prepare_crash",
                        "debug-only failure after terminal generation archival",
                    ));
                }
            }
            let team_epoch = if let Some(epoch) = previous_team_epoch {
                epoch.checked_next().ok_or_else(|| {
                    ControlError::new("epoch_exhausted", "team generation exhausted u64")
                })?
            } else {
                supervisor
                    .team(&team_id)
                    .map_or(agsv_protocol::TeamEpoch::INITIAL, |team| team.epoch)
            };
            let working_directory = self.ensure_team_directory_with_ownership(
                &team_id,
                args.working_directory.as_deref(),
                args.adopt_working_directory,
            )?;
            let desired_instances = if profile_mode == ProfileMode::Snapshotted {
                u16::try_from(selected_team.desired_instances).map_err(|_| {
                    ControlError::new(
                        "invalid_profile_configuration",
                        "team profile desired_instances exceeds the supported range",
                    )
                })?
            } else {
                args.orchestrators
            };
            let actor_ids = if let Some(team) = supervisor.team(&team_id) {
                desired_actor_ids(team, usize::from(desired_instances))?
            } else {
                (1..=desired_instances)
                    .map(|index| ActorId::new(format!("impl-{}-{index}", slug(&args.name))))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(ControlError::protocol)?
            };
            for actor_id in &actor_ids {
                if let Some(session) = self.store.session(actor_id.as_str())? {
                    if session.working_directory != working_directory
                        && previous_team_epoch.is_none()
                    {
                        return Err(ControlError::new(
                            "working_directory_conflict",
                            format!(
                                "healthy team actor `{actor_id}` is already scoped to {}",
                                session.working_directory.display()
                            ),
                        ));
                    }
                }
            }
            let (_, newly_registered) = self.store.mutate(
                "team.created",
                &json!({
                    "team_id": team_id,
                    "team_epoch": team_epoch,
                    "previous_team_epoch": previous_team_epoch,
                    "working_directory": working_directory,
                    "orchestrators": desired_instances,
                    "team_profile": selected_team.name,
                    "actor_profile": selected_actor.name,
                    "purpose": purpose,
                }),
                now_ms()?,
                |state| {
                    let mut newly_registered = Vec::new();
                    let profile_mode = ensure_team_profile(
                        state,
                        &team_id,
                        &selected_team,
                        &selected_actor,
                        &team_snapshot,
                        profile_mode == ProfileMode::Snapshotted,
                    )?;
                    for actor_id in &actor_ids {
                        if let Some(actor) = state.actor(actor_id) {
                            validate_actor_profile(
                                actor,
                                &configured_role,
                                match profile_mode {
                                    ProfileMode::Legacy => None,
                                    ProfileMode::Snapshotted => Some(&actor_snapshot),
                                },
                            )?;
                            if actor.team_id.as_ref() != Some(&team_id) {
                                return Err(ControlError::new(
                                    "actor_team_mismatch",
                                    format!(
                                        "actor `{actor_id}` is not owned by team `{team_id}`"
                                    ),
                                ));
                            }
                            if state
                                .team(&team_id)
                                .is_some_and(|team| !team.actors.contains(actor_id))
                            {
                                newly_registered.push(ensure_team_actor(
                                    state,
                                    &team_id,
                                    actor_id,
                                    &configured_role,
                                    &actor_snapshot,
                                    profile_mode,
                                )?);
                            }
                        } else {
                            newly_registered.push(ensure_team_actor(
                                state,
                                &team_id,
                                actor_id,
                                &configured_role,
                                &actor_snapshot,
                                profile_mode,
                            )?);
                        }
                    }
                    if state.team(&team_id).is_none_or(|team| team.epoch != team_epoch) {
                        return Err(ControlError::new(
                            "team_generation_mismatch",
                            "team recreation did not commit the expected generation",
                        ));
                    }
                    Ok(newly_registered)
                },
            )?;
            self.store
                .set_team_purpose(team_id.as_str(), &purpose, now_ms()?)?;
            if previous_team_epoch.is_some() {
                for actor_id in &actor_ids {
                    if let Some(mut session) = self.store.session(actor_id.as_str())? {
                        session.working_directory.clone_from(&working_directory);
                        session.external_id = None;
                        session.resume_token = None;
                        "missing".clone_into(&mut session.status);
                        session.launch_key = stable_id(
                            "reconcile-seed",
                            &format!("{team_id}:{team_epoch}:{actor_id}"),
                        );
                        session.updated_at_ms = now_ms()?;
                        session.row_revision = self.store.upsert_session(&session)?;
                    }
                }
            }
            if self.debug_crash_requested(
                "AGSV_DEV_FAIL_AFTER_TEAM_CREATE_COMMIT",
                "team_create_commit",
            ) {
                return Err(ControlError::new(
                    "simulated_team_create_crash",
                    "debug-only failure after the team-create state commit",
                ));
            }
            let instance_reconciliation = self.reconcile_team_instances_in(
                &team_id,
                Some(&working_directory),
                &newly_registered,
            )?;
            if instance_reconciliation["complete"].as_bool() != Some(true) {
                return Err(ControlError::new(
                    "instance_reconciliation_incomplete",
                    "team was created but its desired actor instances have not converged",
                )
                .with_details(json!({ "instance_reconciliation": instance_reconciliation }))
                .with_hint(
                    "correct the reported actor or session failure, then retry with the same operation ID",
                ));
            }
            let (revision, supervisor, _) = self.store.load()?;
            let team = supervisor
                .team(&team_id)
                .ok_or_else(|| ControlError::not_found("team", team_id.as_str()))?;
            let (effective_desired, _) = Self::effective_team_intent(team)?;
            let actor_refs = desired_actor_ids(team, effective_desired)?
                .into_iter()
                .map(|actor_id| {
                    supervisor
                        .actor(&actor_id)
                        .map(Actor::actor_ref)
                        .ok_or_else(|| ControlError::not_found("actor", actor_id.as_str()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let sessions = actor_refs
                .iter()
                .map(|actor_ref| {
                    self.store
                        .session(actor_ref.actor_id.as_str())?
                        .ok_or_else(|| {
                            ControlError::not_found("session", actor_ref.actor_id.as_str())
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let reused = instance_reconciliation["launched"].as_u64() == Some(0)
                && instance_reconciliation["replaced"].as_u64() == Some(0);
            Ok(json!({
                "team_id": team_id,
                "team_epoch": team.epoch,
                "previous_team_epoch": previous_team_epoch,
                "working_directory": working_directory,
                "worktree": self.store.team_worktree(team_id.as_str())?,
                "actors": actor_refs,
                "sessions": sessions,
                "team_profile": {
                    "name": selected_team.name,
                    "actor_profile": selected_team.actor_profile,
                    "desired_instances": selected_team.desired_instances,
                    "assignment_policy": selected_team.assignment_policy,
                },
                "purpose": purpose,
                "presentations": self.store.presentations_for_team(team_id.as_str())?,
                "revision": revision,
                "reused": reused,
                "instance_reconciliation": instance_reconciliation,
            }))
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    fn ensure_actor_session(
        &self,
        actor_ref: &ActorRef,
        team_id: &TeamId,
        working_directory: &Path,
        actor_profile: &ActorProfileSettings,
        runtime: &dyn AgentRuntime,
        launch_key: &str,
    ) -> Result<(SessionRecord, bool), ControlError> {
        let mut existing_session = self.store.session(actor_ref.actor_id.as_str())?;
        if let Some(existing) = existing_session.as_mut() {
            let expected_name = session_name(self.identity.workspace_id().as_str(), actor_ref);
            self.validate_session_record(
                existing,
                actor_ref,
                team_id,
                working_directory,
                Some(&expected_name),
                runtime,
            )?;
            if existing.external_id.is_some() {
                let status = self.sessions.status(existing)?;
                if session_is_present(&status) {
                    *existing =
                        self.persist_observed_session_status(existing, &status, now_ms()?)?;
                    if session_is_present(&existing.status) {
                        self.bind_launched_actor(actor_ref, existing)?;
                        return Ok((existing.clone(), true));
                    }
                }
            }
        }
        let prompt = implementation_prompt(
            &actor_profile.role_instructions,
            &actor_profile.role,
            actor_ref,
            team_id,
        )?;
        let runtime_config = Self::runtime_config(actor_profile)?;
        let expected_name = session_name(self.identity.workspace_id().as_str(), actor_ref);
        let launch_backend = existing_session.as_ref().map_or_else(
            || self.sessions.name().to_owned(),
            |session| session.backend.clone(),
        );
        let existing_row_revision = existing_session
            .as_ref()
            .map_or(0, |session| session.row_revision);
        let mut pending = SessionRecord {
            actor_id: actor_ref.actor_id.to_string(),
            team_id: Some(team_id.to_string()),
            working_directory: working_directory.to_path_buf(),
            backend: launch_backend.clone(),
            runtime: Some(runtime.id().to_string()),
            external_id: None,
            resume_token: existing_session.and_then(|session| session.resume_token),
            status: "launching".to_owned(),
            launch_key: launch_key.to_owned(),
            updated_at_ms: now_ms()?,
            row_revision: existing_row_revision,
        };
        pending.row_revision = self.store.upsert_session(&pending)?;
        let recovered_token = pending.resume_token.clone();
        if recovered_token.is_none()
            || self
                .store
                .session_presentation(actor_ref.actor_id.as_str())?
                .is_some()
        {
            self.ensure_actor_presentation(actor_ref, &launch_backend)?;
        }
        let hints = if recovered_token.is_some() {
            SessionLaunchHints::default()
        } else {
            self.launch_hints(&actor_ref.actor_id, &launch_backend)?
        };
        let launch = {
            let mut checkpoint = |token: &str| {
                pending = self.persist_session_checkpoint(&pending, token, now_ms()?)?;
                self.bind_launched_actor(actor_ref, &pending)
            };
            self.sessions.launch_with_initial_prompt_for_and_hints(
                &launch_backend,
                actor_ref.actor_id.as_str(),
                &expected_name,
                working_directory,
                launch_key,
                runtime,
                &runtime_config,
                Some(prompt.as_str()),
                recovered_token,
                &hints,
                &mut checkpoint,
            )
        };
        match launch {
            Ok(handle) => {
                self.validate_launched_handle(actor_ref, &expected_name, &handle)?;
                let mut record = SessionRecord {
                    external_id: Some(handle.external_id),
                    resume_token: handle.resume_token,
                    status: "idle".to_owned(),
                    ..pending
                };
                record.row_revision = self.store.upsert_session(&record)?;
                self.bind_launched_actor(actor_ref, &record)?;
                Ok((record, false))
            }
            Err(error) => {
                if error.code == "session_revision_conflict" {
                    return Err(error);
                }
                let mut failed = SessionRecord {
                    status: "launch_failed".to_owned(),
                    updated_at_ms: now_ms()?,
                    ..pending
                };
                failed.row_revision = self.store.upsert_session(&failed)?;
                let _ = self.store.mutate(
                    "actor.launch_failed",
                    &json!({ "actor_id": actor_ref.actor_id, "error": error.to_string() }),
                    now_ms()?,
                    |state| {
                        state
                            .set_actor_status(actor_ref, ActorStatus::Stale)
                            .map_err(ControlError::core)
                    },
                );
                Err(error)
            }
        }
    }

    fn existing_team_working_directory(
        &self,
        team_id: &TeamId,
    ) -> Result<Option<PathBuf>, ControlError> {
        let worktree = self.store.team_worktree(team_id.as_str())?;
        if worktree
            .as_ref()
            .is_some_and(|record| record.status == TeamWorktreeStatus::Removed)
        {
            return Ok(None);
        }
        let mut directory = worktree
            .as_ref()
            .map(|record| {
                fs::canonicalize(&record.working_directory).map_err(|error| {
                    ControlError::io(
                        "canonicalize durable team worktree",
                        &record.working_directory,
                        &error,
                    )
                })
            })
            .transpose()?;
        for session in self
            .store
            .sessions()?
            .into_iter()
            .filter(|session| session.team_id.as_deref() == Some(team_id.as_str()))
        {
            let canonical = fs::canonicalize(&session.working_directory).map_err(|error| {
                ControlError::io(
                    "canonicalize durable team working directory",
                    &session.working_directory,
                    &error,
                )
            })?;
            if directory
                .as_ref()
                .is_some_and(|expected: &PathBuf| expected != &canonical)
            {
                return Err(ControlError::new(
                    "working_directory_conflict",
                    format!(
                        "team `{team_id}` has durable sessions in different working directories"
                    ),
                )
                .with_details(json!({
                    "team_id": team_id,
                    "expected_working_directory": directory,
                    "conflicting_actor_id": session.actor_id,
                    "conflicting_working_directory": canonical,
                })));
            }
            directory = Some(canonical);
        }
        if let Some(path) = directory.as_deref() {
            self.validate_team_worktree_path(team_id, path).map(Some)
        } else {
            Ok(None)
        }
    }

    fn request_base_directory(&self, team_id: &TeamId) -> Result<PathBuf, ControlError> {
        let mut directory = None;
        for session in self
            .store
            .sessions()?
            .into_iter()
            .filter(|session| session.team_id.as_deref() == Some(team_id.as_str()))
        {
            let canonical = fs::canonicalize(&session.working_directory).map_err(|error| {
                ControlError::io(
                    "canonicalize durable team working directory",
                    &session.working_directory,
                    &error,
                )
            })?;
            let identity =
                WorkspaceIdentity::discover_with_git(&canonical, self.review.git_executable())?;
            if identity.git_common_dir() != self.identity.git_common_dir() {
                return Err(ControlError::new(
                    "wrong_git_workspace",
                    "team working directory does not share this workspace's Git common directory",
                )
                .with_details(json!({ "path": canonical })));
            }
            if directory
                .as_ref()
                .is_some_and(|expected: &PathBuf| expected != &canonical)
            {
                return Err(ControlError::new(
                    "working_directory_conflict",
                    format!(
                        "team `{team_id}` has durable sessions in different working directories"
                    ),
                ));
            }
            directory = Some(canonical);
        }
        Ok(directory.unwrap_or_else(|| self.identity.root().to_path_buf()))
    }

    #[allow(clippy::too_many_lines)]
    fn register_and_launch_desired_actor(
        &self,
        team_id: &TeamId,
        actor_id: &ActorId,
        working_directory: &Path,
        actor_profile: &ActorProfileSettings,
        profile_mode: ProfileMode,
        allowed_existing_actor: Option<&ActorRef>,
    ) -> Result<(ActorRef, SessionRecord, bool), ControlError> {
        let (_, current, _) = self.store.load()?;
        let team_epoch = current
            .team(team_id)
            .ok_or_else(|| ControlError::not_found("team", team_id.as_str()))?
            .epoch;
        let actor_epoch = current
            .actor(actor_id)
            .map_or(ActorEpoch::INITIAL, |actor| actor.epoch);
        let operation_id =
            reconciliation_launch_operation_id(team_id, team_epoch, actor_id, actor_epoch);
        let operation_request = json!({
            "team_id": team_id,
            "team_epoch": team_epoch,
            "actor_id": actor_id,
            "actor_epoch": actor_epoch,
            "working_directory": working_directory,
            "actor_profile": actor_profile.name,
        });
        let result = self.idempotent(
            "actor.reconcile_launch",
            &operation_request,
            &operation_id,
            || {
                let configured_role = actor_profile.actor_role()?;
                let actor_snapshot = actor_profile.snapshot()?;
                let observed_at = now_ms()?;
                let (_, (actor_ref, registered)) = self.store.mutate(
                    "actor.reconciled_registered",
                    &json!({ "team_id": team_id, "actor_id": actor_id }),
                    observed_at,
                    |state| {
                        let team = state
                            .team(team_id)
                            .ok_or_else(|| ControlError::not_found("team", team_id.as_str()))?;
                        if team.status != TeamStatus::Active {
                            return Err(ControlError::new(
                                "team_inactive",
                                "cannot launch an actor for an inactive team",
                            ));
                        }
                        if let Some(actor) = state.actor(actor_id) {
                            validate_actor_profile(
                                actor,
                                &configured_role,
                                match profile_mode {
                                    ProfileMode::Legacy => None,
                                    ProfileMode::Snapshotted => Some(&actor_snapshot),
                                },
                            )?;
                            if actor.team_id.as_ref() != Some(team_id)
                                || !matches!(
                                    actor.status,
                                    ActorStatus::Starting
                                        | ActorStatus::Stale
                                        | ActorStatus::Healthy
                                )
                            {
                                return Err(ControlError::new(
                                    "actor_requires_replacement",
                                    format!("actor `{actor_id}` must be replaced before relaunch"),
                                ));
                            }
                            return Ok((actor.actor_ref(), false));
                        }
                        let actor_ref = ensure_team_actor(
                            state,
                            team_id,
                            actor_id,
                            &configured_role,
                            &actor_snapshot,
                            profile_mode,
                        )?;
                        state
                            .heartbeat(&actor_ref, TimestampMillis(observed_at))
                            .map_err(ControlError::core)?;
                        Ok((actor_ref, true))
                    },
                )?;
                if self.debug_crash_requested(
                    "AGSV_DEV_FAIL_AFTER_RECONCILE_REGISTRATION_COMMIT",
                    "reconcile_registration_commit",
                ) {
                    return Err(ControlError::new(
                        "simulated_reconcile_registration_crash",
                        "debug-only failure after the desired actor registration commit",
                    ));
                }
                if !registered && allowed_existing_actor != Some(&actor_ref) {
                    let resumable_initial_launch = self
                        .store
                        .session(actor_id.as_str())?
                        .is_some_and(|session| {
                            session.launch_key == operation_id
                                && session.external_id.is_none()
                                && matches!(
                                    session.status.as_str(),
                                    "launching" | "launch_failed"
                                )
                        });
                    if !resumable_initial_launch {
                        return Err(ControlError::new(
                            "actor_requires_replacement",
                            format!(
                                "actor `{actor_id}` must advance its epoch before a new session is launched"
                            ),
                        ));
                    }
                }
                let runtime = self.runtime_for_profile(actor_profile)?;
                if allowed_existing_actor == Some(&actor_ref)
                    && let Some(mut prior_generation) =
                        self.store.session(actor_ref.actor_id.as_str())?
                    && prior_generation.status == "stopped"
                {
                    self.validate_session_record(
                        &mut prior_generation,
                        &actor_ref,
                        team_id,
                        working_directory,
                        None,
                        runtime.as_ref(),
                    )?;
                    prior_generation.external_id = None;
                    prior_generation.resume_token = None;
                    "missing".clone_into(&mut prior_generation.status);
                    operation_id.clone_into(&mut prior_generation.launch_key);
                    prior_generation.updated_at_ms = now_ms()?;
                    prior_generation.row_revision =
                        self.store.upsert_session(&prior_generation)?;
                }
                let (session, reused) = self.ensure_actor_session(
                    &actor_ref,
                    team_id,
                    working_directory,
                    actor_profile,
                    runtime.as_ref(),
                    &operation_id,
                )?;
                self.heartbeat_actor(&actor_ref, "actor.reconciled_launch_started")?;
                Ok(json!({
                    "actor_ref": actor_ref,
                    "session": session,
                    "reused": reused,
                }))
            },
        )?;
        let actor_ref =
            serde_json::from_value(result["actor_ref"].clone()).map_err(ControlError::database)?;
        let session =
            serde_json::from_value(result["session"].clone()).map_err(ControlError::database)?;
        let reused = result["reused"].as_bool().ok_or_else(|| {
            ControlError::database("cached actor reconciliation result has no reused flag")
        })?;
        Ok((actor_ref, session, reused))
    }

    fn ensure_replacement_session(
        &self,
        actor: &Actor,
        team_id: &TeamId,
        working_directory: &Path,
        actor_profile: &ActorProfileSettings,
    ) -> Result<SessionRecord, ControlError> {
        if let Some(session) = self.store.session(actor.actor_id.as_str())? {
            return Ok(session);
        }
        let runtime = self.runtime_for_profile(actor_profile)?;
        let mut session = SessionRecord {
            actor_id: actor.actor_id.to_string(),
            team_id: Some(team_id.to_string()),
            working_directory: working_directory.to_path_buf(),
            backend: self.sessions.name().to_owned(),
            runtime: Some(runtime.id().to_string()),
            external_id: None,
            resume_token: None,
            status: "missing".to_owned(),
            launch_key: stable_id("reconcile-seed", &format!("{team_id}:{}", actor.actor_id)),
            updated_at_ms: now_ms()?,
            row_revision: 0,
        };
        session.row_revision = self.store.upsert_session(&session)?;
        Ok(session)
    }

    fn replacement_operation_id(&self, actor: &Actor) -> Result<String, ControlError> {
        if let Some(session) = self.store.session(actor.actor_id.as_str())?
            && matches!(
                session.status.as_str(),
                "replacement_pending" | "launching" | "launch_failed"
            )
            && let Some(value) = session.launch_key.strip_prefix("replacement:")
            && let Some((operation_id, _)) = value.rsplit_once(':')
        {
            return Ok(operation_id.to_owned());
        }
        Ok(stable_id(
            "reconcile-replace",
            &format!(
                "{}:{}:{}",
                actor.team_id.as_ref().map_or("", TeamId::as_str),
                actor.actor_id,
                actor.epoch
            ),
        ))
    }

    fn stop_surplus_actor_if_idle(
        &self,
        team_id: &TeamId,
        actor_ref: &ActorRef,
        desired_instances: usize,
    ) -> Result<Value, ControlError> {
        self.stop_actor_for_reconciliation(
            team_id,
            actor_ref,
            desired_instances,
            ReconciledActorStop::Surplus,
        )
    }

    fn stop_team_actor_if_ready(
        &self,
        team_id: &TeamId,
        actor_ref: &ActorRef,
    ) -> Result<Value, ControlError> {
        self.stop_actor_for_reconciliation(team_id, actor_ref, 0, ReconciledActorStop::TeamClose)
    }

    fn ensure_surplus_deliveries_acknowledged(
        state: &Supervisor,
        actor_ref: &ActorRef,
    ) -> Result<(), ControlError> {
        let pending = state.pending_acknowledgement_message_ids_for(&actor_ref.actor_id);
        if pending.is_empty() {
            return Ok(());
        }
        Err(ControlError::new(
            "surplus_unacknowledged_messages",
            "surplus actor retains unread durable deliveries and was not stopped",
        )
        .with_details(json!({
            "actor_ref": actor_ref,
            "unacknowledged_message_ids": pending,
        })))
    }

    fn stop_actor_for_reconciliation(
        &self,
        team_id: &TeamId,
        actor_ref: &ActorRef,
        desired_instances: usize,
        reason: ReconciledActorStop,
    ) -> Result<Value, ControlError> {
        let (operation_prefix, operation, event, blocked_code, blocked_message) = match reason {
            ReconciledActorStop::Surplus => (
                "reconcile-surplus-stop",
                "actor.reconcile_surplus_stop",
                "actor.reconciled_surplus_stopped",
                "surplus_wip",
                "surplus actor retains nonterminal work and was not stopped",
            ),
            ReconciledActorStop::TeamClose => (
                "reconcile-team-close-stop",
                "actor.reconcile_team_close_stop",
                "actor.reconciled_team_close_stopped",
                "team_close_blocked",
                "team actor retains work that requires the team and was not stopped",
            ),
        };
        let operation_id = stable_id(
            operation_prefix,
            &format!(
                "{team_id}:{}:{}:{desired_instances}",
                actor_ref.actor_id, actor_ref.actor_epoch
            ),
        );
        let operation_request = json!({
            "team_id": team_id,
            "actor_ref": actor_ref,
            "desired_instances": desired_instances,
        });
        self.idempotent(operation, &operation_request, &operation_id, || {
            let (revision, already_stopped) =
                self.store
                    .mutate(event, &operation_request, now_ms()?, |state| {
                        let actor = state.actor(&actor_ref.actor_id).ok_or_else(|| {
                            ControlError::not_found("actor", actor_ref.actor_id.as_str())
                        })?;
                        if actor.team_id.as_ref() != Some(team_id)
                            || actor.actor_ref() != *actor_ref
                        {
                            return Err(ControlError::new(
                                "stale_actor",
                                "surplus shutdown must target the exact current team actor",
                            )
                            .with_details(json!({
                                "team_id": team_id,
                                "expected_actor_ref": actor_ref,
                                "current_actor_ref": actor.actor_ref(),
                                "current_team_id": actor.team_id,
                            })));
                        }
                        let assigned = match reason {
                            ReconciledActorStop::Surplus => {
                                nonterminal_request_ids(state, actor_ref)
                            }
                            ReconciledActorStop::TeamClose => {
                                team_close_blocking_request_ids_for_actor(state, actor_ref)
                            }
                        };
                        if !assigned.is_empty() {
                            return Err(ControlError::new(blocked_code, blocked_message)
                                .with_details(json!({
                                    "actor_ref": actor_ref,
                                    "assigned_nonterminal_request_ids": assigned,
                                })));
                        }
                        if matches!(reason, ReconciledActorStop::Surplus) {
                            Self::ensure_surplus_deliveries_acknowledged(state, actor_ref)?;
                        }
                        let already_stopped = actor.status == ActorStatus::Stopped;
                        if !already_stopped {
                            state
                                .set_actor_status(actor_ref, ActorStatus::Stopped)
                                .map_err(ControlError::core)?;
                        }
                        Ok(already_stopped)
                    })?;

            let mut session_cleaned = false;
            if let Some(mut session) = self.store.session(actor_ref.actor_id.as_str())? {
                let backend_cleanup_required = session.external_id.is_some()
                    && !matches!(session.status.as_str(), "missing" | "stopped");
                if backend_cleanup_required {
                    self.sessions.stop(&session)?;
                }
                if session.status != "stopped" {
                    "stopped".clone_into(&mut session.status);
                    session.updated_at_ms = now_ms()?;
                    session.row_revision = self.store.upsert_session(&session)?;
                    session_cleaned = true;
                }
            }
            Ok(json!({
                "actor_ref": actor_ref,
                "status": "stopped",
                "revision": revision,
                "actor_stopped": !already_stopped,
                "session_cleaned": session_cleaned,
            }))
        })
    }

    fn reconcile_team_instances(&self, team_id: &TeamId) -> Result<Value, ControlError> {
        self.reconcile_team_instances_in(team_id, None, &[])
    }

    #[allow(clippy::too_many_lines)]
    fn reconcile_team_instances_in(
        &self,
        team_id: &TeamId,
        preferred_working_directory: Option<&Path>,
        newly_registered: &[ActorRef],
    ) -> Result<Value, ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        let team = supervisor
            .team(team_id)
            .ok_or_else(|| ControlError::not_found("team", team_id.as_str()))?
            .clone();
        let (desired_instances, effective_assignment_policy) = Self::effective_team_intent(&team)?;
        if matches!(team.status, TeamStatus::Closing | TeamStatus::Closed) {
            let lifecycle_close = self.reconcile_closing_team(team_id)?;
            let (_, current, _) = self.store.load()?;
            let summary = self.assignment_instance_summary(&current)?;
            let state = find_team_instance_summary(&summary, team_id);
            return Ok(json!({
                "team_id": team_id,
                "team_status": lifecycle_close["status"],
                "configured_desired_instances": desired_instances,
                "desired_instances": 0,
                "effective_assignment_policy": effective_assignment_policy,
                "launched": 0,
                "replaced": 0,
                "reused": 0,
                "stopped": lifecycle_close["actor_stops"].as_array().map_or(0, Vec::len),
                "failures": lifecycle_close["failures"],
                "complete": lifecycle_close["complete"],
                "deferred": lifecycle_close["deferred"],
                "state": state,
                "lifecycle_close": lifecycle_close,
            }));
        }
        let desired_ids = desired_actor_ids(&team, desired_instances)?;
        if team.status != TeamStatus::Active {
            let summary = self.assignment_instance_summary(&supervisor)?;
            let state = find_team_instance_summary(&summary, team_id);
            return Ok(json!({
                "team_id": team_id,
                "team_status": team.status,
                "desired_instances": desired_instances,
                "effective_assignment_policy": effective_assignment_policy,
                "launched": 0,
                "replaced": 0,
                "reused": 0,
                "stopped": 0,
                "failures": [],
                "complete": true,
                "deferred": true,
                "state": state,
            }));
        }
        let (team_profile, actor_profile, profile_mode) =
            self.team_control_profile(Some(&team), None)?;
        debug_assert_eq!(team_profile.assignment_policy, effective_assignment_policy);
        for actor_id in &team.actors {
            let actor = supervisor
                .actor(actor_id)
                .ok_or_else(|| ControlError::not_found("actor", actor_id.as_str()))?;
            self.actor_profile(actor)?;
        }
        let mut launched = 0_u64;
        let mut replaced = 0_u64;
        let mut reused = 0_u64;
        let mut stopped = 0_u64;
        let mut failures = Vec::new();

        let existing_working_directory = self.existing_team_working_directory(team_id)?;
        let working_directory = if desired_ids.is_empty() {
            None
        } else if let Some(preferred) = preferred_working_directory {
            let preferred = self.ensure_team_directory(team_id, Some(preferred))?;
            if let Some(existing) = existing_working_directory
                && existing != preferred
            {
                return Err(ControlError::new(
                    "working_directory_conflict",
                    format!(
                        "team `{team_id}` already has durable sessions in a different working directory"
                    ),
                )
                .with_details(json!({
                    "team_id": team_id,
                    "expected_working_directory": preferred,
                    "existing_working_directory": existing,
                })));
            }
            Some(preferred)
        } else if let Some(existing) = existing_working_directory {
            Some(existing)
        } else {
            Some(self.ensure_team_directory(team_id, None)?)
        };
        for actor_id in &desired_ids {
            let _target_operation_lock = self
                .store
                .lock_actor_operations("actor", actor_id.as_str())?;
            let (_, current, _) = self.store.load()?;
            let Some(current_team) = current.team(team_id) else {
                return Err(ControlError::not_found("team", team_id.as_str()));
            };
            if current_team.status != TeamStatus::Active {
                failures.push(json!({
                    "actor_id": actor_id,
                    "phase": "team_status",
                    "error": "team became inactive during instance reconciliation",
                }));
                break;
            }
            let Some(mut actor) = current.actor(actor_id).cloned() else {
                let directory = working_directory
                    .as_deref()
                    .expect("non-empty desired actor set has a working directory");
                match self.register_and_launch_desired_actor(
                    team_id,
                    actor_id,
                    directory,
                    &actor_profile,
                    profile_mode,
                    None,
                ) {
                    Ok((_, _, actor_reused)) => {
                        if actor_reused {
                            reused += 1;
                        } else {
                            launched += 1;
                        }
                    }
                    Err(error) => failures.push(json!({
                        "actor_id": actor_id,
                        "phase": "missing_launch",
                        "error": error.to_string(),
                    })),
                }
                continue;
            };
            if let Err(error) = self.actor_profile(&actor) {
                failures.push(json!({
                    "actor_id": actor_id,
                    "phase": "actor_profile",
                    "error": error.to_string(),
                }));
                continue;
            }
            let mut session = self.store.session(actor_id.as_str())?;
            let actor_ref = actor.actor_ref();
            if session
                .as_ref()
                .is_some_and(SessionRecord::replacement_intent_in_progress)
            {
                let operation_id = self.replacement_operation_id(&actor)?;
                match self.actor_replace(&json!({
                    "id": actor_id,
                    "reason": "stale desired instance",
                    "operation_id": operation_id,
                })) {
                    Ok(result) => {
                        let resulting_ref: ActorRef =
                            serde_json::from_value(result["actor"].clone())
                                .map_err(ControlError::database)?;
                        if resulting_ref.actor_epoch != actor_ref.actor_epoch {
                            replaced += 1;
                        }
                        if result["reused"].as_bool() == Some(true) {
                            reused += 1;
                        } else {
                            launched += 1;
                        }
                    }
                    Err(error) => failures.push(json!({
                        "actor_id": actor_id,
                        "phase": "replacement_resume",
                        "error": error.to_string(),
                        "error_code": error.code,
                        "details": error.details,
                    })),
                }
                continue;
            }
            let newly_registered_actor = newly_registered.contains(&actor_ref);
            let internally_managed_launch = session.as_ref().is_some_and(|record| {
                record.launch_key
                    == reconciliation_launch_operation_id(
                        team_id,
                        current_team.epoch,
                        actor_id,
                        actor_ref.actor_epoch,
                    )
                    && record.external_id.is_none()
                    && matches!(record.status.as_str(), "launching" | "launch_failed")
            });
            if (actor.status == ActorStatus::Healthy && newly_registered_actor)
                || (matches!(
                    actor.status,
                    ActorStatus::Starting | ActorStatus::Stale | ActorStatus::Healthy
                ) && internally_managed_launch)
            {
                let directory = working_directory
                    .as_deref()
                    .expect("non-empty desired actor set has a working directory");
                match self.register_and_launch_desired_actor(
                    team_id,
                    actor_id,
                    directory,
                    &actor_profile,
                    profile_mode,
                    newly_registered_actor.then_some(&actor_ref),
                ) {
                    Ok((_, _, actor_reused)) => {
                        if actor_reused {
                            reused += 1;
                        } else {
                            launched += 1;
                        }
                    }
                    Err(error) => failures.push(json!({
                        "actor_id": actor_id,
                        "phase": "missing_launch",
                        "error": error.to_string(),
                    })),
                }
                continue;
            }
            if matches!(
                actor.status,
                ActorStatus::Starting | ActorStatus::Stale | ActorStatus::Healthy
            ) {
                if let Some(record) = session.as_mut()
                    && record.external_id.is_none()
                    && matches!(record.status.as_str(), "launching" | "launch_failed")
                {
                    match self.recover_incomplete_session(record) {
                        Ok(()) => {
                            reused += 1;
                            continue;
                        }
                        Err(error) => {
                            failures.push(json!({
                                "actor_id": actor_id,
                                "phase": "resume_launch",
                                "error": error.to_string(),
                            }));
                            continue;
                        }
                    }
                }
                if let Some(record) = session.as_mut() {
                    let runtime = self.runtime_for_profile(&actor_profile)?;
                    let directory = working_directory
                        .as_deref()
                        .expect("non-empty desired actor set has a working directory");
                    if let Err(error) = self.validate_session_record(
                        record,
                        &actor.actor_ref(),
                        team_id,
                        directory,
                        Some(&session_name(
                            self.identity.workspace_id().as_str(),
                            &actor.actor_ref(),
                        )),
                        runtime.as_ref(),
                    ) {
                        failures.push(json!({
                            "actor_id": actor_id,
                            "phase": "session_validation",
                            "error": error.to_string(),
                        }));
                        continue;
                    }
                    match self.sessions.status(record) {
                        Ok(status)
                            if record.external_id.is_some() && session_is_present(&status) =>
                        {
                            *record =
                                self.persist_observed_session_status(record, &status, now_ms()?)?;
                            if session_is_present(&record.status) {
                                self.bind_launched_actor(&actor.actor_ref(), record)?;
                                self.heartbeat_actor(
                                    &actor.actor_ref(),
                                    "actor.reconciled_desired",
                                )?;
                                reused += 1;
                                continue;
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            failures.push(json!({
                                "actor_id": actor_id,
                                "phase": "session_status",
                                "error": error.to_string(),
                            }));
                            continue;
                        }
                    }
                }
                if actor.status == ActorStatus::Healthy {
                    let actor_ref = actor.actor_ref();
                    let (_, ()) = self.store.mutate(
                        "actor.reconciled_stale",
                        &json!({ "actor_id": actor_id, "reason": "desired session missing" }),
                        now_ms()?,
                        |state| {
                            state
                                .set_actor_status(&actor_ref, ActorStatus::Stale)
                                .map_err(ControlError::core)
                        },
                    )?;
                    let (_, refreshed, _) = self.store.load()?;
                    actor = refreshed
                        .actor(actor_id)
                        .ok_or_else(|| ControlError::not_found("actor", actor_id.as_str()))?
                        .clone();
                }
            }
            let directory = working_directory
                .as_deref()
                .expect("non-empty desired actor set has a working directory");
            if let Err(error) =
                self.ensure_replacement_session(&actor, team_id, directory, &actor_profile)
            {
                failures.push(json!({
                    "actor_id": actor_id,
                    "phase": "replacement_session",
                    "error": error.to_string(),
                }));
                continue;
            }
            let operation_id = self.replacement_operation_id(&actor)?;
            match self.actor_replace(&json!({
                "id": actor_id,
                "reason": "stale desired instance",
                "operation_id": operation_id,
            })) {
                Ok(_) => {
                    replaced += 1;
                    launched += 1;
                }
                Err(error) => failures.push(json!({
                    "actor_id": actor_id,
                    "phase": "stale_replace",
                    "error": error.to_string(),
                })),
            }
        }

        let (_, desired_state, _) = self.store.load()?;
        let desired_summary = self.assignment_instance_summary(&desired_state)?;
        let desired_team_state = find_team_instance_summary(&desired_summary, team_id);
        let desired_capacity_ready =
            failures.is_empty() && desired_team_state["missing_instances"].as_u64() == Some(0);
        for actor_id in team.actors.iter().skip(desired_instances) {
            let _target_operation_lock = self
                .store
                .lock_actor_operations("actor", actor_id.as_str())?;
            let (_, current, _) = self.store.load()?;
            let Some(actor) = current.actor(actor_id) else {
                continue;
            };
            let session_requires_cleanup =
                self.store
                    .session(actor_id.as_str())?
                    .is_some_and(|session| {
                        session.external_id.is_some()
                            && !matches!(session.status.as_str(), "missing" | "stopped")
                    });
            if actor.status == ActorStatus::Stopped && !session_requires_cleanup {
                continue;
            }
            if !desired_capacity_ready {
                failures.push(json!({
                    "actor_id": actor_id,
                    "phase": "surplus_shrink_deferred",
                    "error": "desired actor capacity is not healthy; surplus actor was retained",
                }));
                continue;
            }
            let actor_ref = actor.actor_ref();
            match self.stop_surplus_actor_if_idle(team_id, &actor_ref, desired_instances) {
                Ok(result) => {
                    if result["actor_stopped"].as_bool() == Some(true)
                        || result["session_cleaned"].as_bool() == Some(true)
                    {
                        stopped += 1;
                    }
                }
                Err(error) if error.code == "surplus_wip" => failures.push(json!({
                    "actor_id": actor_id,
                    "phase": "surplus_wip",
                    "error": error.to_string(),
                    "assigned_nonterminal_request_ids": error.details["assigned_nonterminal_request_ids"],
                })),
                Err(error) => failures.push(json!({
                    "actor_id": actor_id,
                    "phase": "surplus_stop",
                    "error": error.to_string(),
                    "error_code": error.code,
                    "details": error.details,
                })),
            }
        }

        let (_, supervisor, _) = self.store.load()?;
        let summary = self.assignment_instance_summary(&supervisor)?;
        let state = find_team_instance_summary(&summary, team_id);
        let converged = state["converged"].as_bool() == Some(true);
        let complete = failures.is_empty() && converged;
        Ok(json!({
            "team_id": team_id,
            "team_status": team.status,
            "desired_instances": desired_instances,
            "effective_assignment_policy": effective_assignment_policy,
            "launched": launched,
            "replaced": replaced,
            "reused": reused,
            "stopped": stopped,
            "failures": failures,
            "complete": complete,
            "deferred": false,
            "state": state,
        }))
    }

    fn ensure_team_directory(
        &self,
        team_id: &TeamId,
        explicit: Option<&Path>,
    ) -> Result<PathBuf, ControlError> {
        self.ensure_team_directory_with_ownership(team_id, explicit, false)
    }

    #[allow(clippy::too_many_lines)]
    fn ensure_team_directory_with_ownership(
        &self,
        team_id: &TeamId,
        explicit: Option<&Path>,
        adopt_existing: bool,
    ) -> Result<PathBuf, ControlError> {
        if adopt_existing && explicit.is_none() {
            return Err(ControlError::invalid_request(
                "--adopt-working-directory requires --working-directory",
            ));
        }
        if let Some(existing) = self.store.team_worktree(team_id.as_str())? {
            if let Some(path) = explicit {
                let requested = self.absolute_team_worktree_target(path, false)?;
                if requested != existing.working_directory {
                    return Err(ControlError::new(
                        "team_worktree_conflict",
                        "team already has a different durable worktree path",
                    )
                    .with_details(json!({
                        "team_id": team_id,
                        "durable_working_directory": existing.working_directory,
                        "requested_working_directory": requested,
                    })));
                }
            }
            if existing.status == TeamWorktreeStatus::Removed {
                return Err(ControlError::new(
                    "team_worktree_removed",
                    "a removed team worktree cannot be recreated under the same team identity",
                ));
            }
            if existing.working_directory.exists() {
                let canonical =
                    self.validate_team_worktree_path(team_id, &existing.working_directory)?;
                if existing.ownership == TeamWorktreeOwnership::Created
                    && existing.status != TeamWorktreeStatus::Active
                {
                    self.store.update_team_worktree_status(
                        team_id.as_str(),
                        &canonical,
                        existing.ownership,
                        TeamWorktreeStatus::Active,
                        None,
                        None,
                        now_ms()?,
                    )?;
                }
                return Ok(canonical);
            }
            if existing.ownership != TeamWorktreeOwnership::Created {
                return Err(ControlError::new(
                    "team_worktree_missing",
                    "an attached or adopted worktree is missing and cannot be recreated implicitly",
                )
                .with_details(json!({
                    "team_id": team_id,
                    "working_directory": existing.working_directory,
                    "ownership": existing.ownership,
                })));
            }
            self.store.update_team_worktree_status(
                team_id.as_str(),
                &existing.working_directory,
                existing.ownership,
                TeamWorktreeStatus::Creating,
                None,
                None,
                now_ms()?,
            )?;
            return self.create_recorded_team_worktree(team_id, &existing.working_directory);
        }

        let target = if let Some(path) = explicit {
            self.absolute_team_worktree_target(path, !path.exists())?
        } else {
            let worktrees = self.settings.state_directory.join("worktrees");
            reject_managed_symlink(&worktrees)?;
            fs::create_dir_all(&worktrees).map_err(|error| {
                ControlError::io("create managed worktree directory", &worktrees, &error)
            })?;
            reject_managed_symlink(&worktrees)?;
            let worktrees = fs::canonicalize(&worktrees).map_err(|error| {
                ControlError::io(
                    "canonicalize managed worktree directory",
                    &worktrees,
                    &error,
                )
            })?;
            worktrees.join(team_id.as_str())
        };
        reject_managed_symlink(&target)?;
        let created_at = now_ms()?;
        if target.exists() {
            let canonical = self.validate_team_worktree_path(team_id, &target)?;
            let ownership = if adopt_existing {
                TeamWorktreeOwnership::Adopted
            } else {
                TeamWorktreeOwnership::Attached
            };
            let status = if ownership == TeamWorktreeOwnership::Attached {
                TeamWorktreeStatus::AttachedNotOwned
            } else {
                TeamWorktreeStatus::Active
            };
            self.store.insert_team_worktree(&TeamWorktreeRecord {
                team_id: team_id.to_string(),
                working_directory: canonical.clone(),
                ownership,
                status,
                reason: None,
                error_code: None,
                created_at_ms: created_at,
                updated_at_ms: created_at,
            })?;
            return Ok(canonical);
        }

        self.store.insert_team_worktree(&TeamWorktreeRecord {
            team_id: team_id.to_string(),
            working_directory: target.clone(),
            ownership: TeamWorktreeOwnership::Created,
            status: TeamWorktreeStatus::Creating,
            reason: None,
            error_code: None,
            created_at_ms: created_at,
            updated_at_ms: created_at,
        })?;
        self.create_recorded_team_worktree(team_id, &target)
    }

    fn absolute_team_worktree_target(
        &self,
        path: &Path,
        create_parent: bool,
    ) -> Result<PathBuf, ControlError> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.identity.root().join(path)
        };
        let file_name = absolute.file_name().ok_or_else(|| {
            ControlError::new(
                "unsafe_working_directory",
                "team working directory must name a non-root path",
            )
        })?;
        let parent = absolute.parent().ok_or_else(|| {
            ControlError::new(
                "unsafe_working_directory",
                "team working directory has no parent",
            )
        })?;
        if create_parent {
            fs::create_dir_all(parent)
                .map_err(|error| ControlError::io("create team worktree parent", parent, &error))?;
        }
        let parent = fs::canonicalize(parent).map_err(|error| {
            ControlError::io("canonicalize team worktree parent", parent, &error)
        })?;
        Ok(parent.join(file_name))
    }

    fn validate_team_worktree_path(
        &self,
        team_id: &TeamId,
        path: &Path,
    ) -> Result<PathBuf, ControlError> {
        reject_managed_symlink(path)?;
        let path_present = match fs::symlink_metadata(path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(ControlError::io(
                    "inspect team working directory",
                    path,
                    &error,
                ));
            }
        };
        let canonical = if path_present {
            fs::canonicalize(path).map_err(|error| {
                ControlError::io("canonicalize team working directory", path, &error)
            })?
        } else {
            let file_name = path.file_name().ok_or_else(|| {
                ControlError::new(
                    "unsafe_working_directory",
                    "team working directory must name a non-root path",
                )
            })?;
            let parent = path.parent().ok_or_else(|| {
                ControlError::new(
                    "unsafe_working_directory",
                    "team working directory has no parent",
                )
            })?;
            let canonical = fs::canonicalize(parent)
                .map_err(|error| {
                    ControlError::io("canonicalize team worktree parent", parent, &error)
                })?
                .join(file_name);
            if canonical != path {
                return Err(ControlError::new(
                    "unsafe_working_directory",
                    "a new team working directory must have a canonical parent path",
                )
                .with_details(json!({ "path": path, "canonical_path": canonical })));
            }
            canonical
        };
        if path_present {
            let identity =
                WorkspaceIdentity::discover_with_git(&canonical, self.review.git_executable())?;
            if identity.git_common_dir() != self.identity.git_common_dir() {
                return Err(ControlError::new(
                    "wrong_git_workspace",
                    "team working directory does not share this workspace's Git common directory",
                )
                .with_details(json!({ "path": canonical })));
            }
            if identity.root() != canonical {
                return Err(ControlError::new(
                    "unsafe_working_directory",
                    "team working directory must be the root of its isolated Git worktree",
                )
                .with_details(json!({ "path": canonical, "worktree_root": identity.root() })));
            }
        }
        if canonical == self.identity.root() || canonical == self.identity.repository_root() {
            return Err(ControlError::new(
                "unsafe_working_directory",
                "an implementation team must not use the Primary or repository-root worktree",
            )
            .with_details(json!({ "path": canonical })));
        }
        if let Some(conflict) = self.store.team_worktrees()?.into_iter().find(|record| {
            record.team_id != team_id.as_str() && record.working_directory == canonical
        }) {
            return Err(ControlError::new(
                "team_worktree_conflict",
                "team worktree already has a different durable owner",
            )
            .with_details(json!({
                "path": canonical,
                "conflicting_team_id": conflict.team_id,
            })));
        }
        if let Some(conflict) = self.conflicting_session_for_worktree(team_id, &canonical)? {
            return Err(ControlError::new(
                "working_directory_conflict",
                format!(
                    "team worktree is already attached to actor `{}`",
                    conflict.actor_id
                ),
            )
            .with_details(json!({
                "path": canonical,
                "actor_id": conflict.actor_id,
                "team_id": conflict.team_id,
            })));
        }
        Ok(canonical)
    }

    fn conflicting_session_for_worktree(
        &self,
        team_id: &TeamId,
        working_directory: &Path,
    ) -> Result<Option<SessionRecord>, ControlError> {
        for session in self.store.sessions()? {
            if session.team_id.as_deref() == Some(team_id.as_str()) {
                continue;
            }
            if session.working_directory == working_directory
                || canonicalize_durable_path_allow_missing(&session.working_directory)?
                    == working_directory
            {
                return Ok(Some(session));
            }
        }
        Ok(None)
    }

    fn create_recorded_team_worktree(
        &self,
        team_id: &TeamId,
        target: &Path,
    ) -> Result<PathBuf, ControlError> {
        let target = self.validate_team_worktree_path(team_id, target)?;
        let output = control_git_command(self.review.git_executable(), self.identity.root())
            .args(["worktree", "add", "--detach"])
            .arg(&target)
            .arg("HEAD")
            .output()
            .map_err(|error| ControlError::io("create isolated Git worktree", &target, &error))?;
        if !output.status.success() {
            let reason = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            self.store.update_team_worktree_status(
                team_id.as_str(),
                &target,
                TeamWorktreeOwnership::Created,
                TeamWorktreeStatus::RetainedWithReason,
                Some(&reason),
                Some("worktree_create_failed"),
                now_ms()?,
            )?;
            return Err(ControlError::new(
                "worktree_create_failed",
                format!("Git could not create the isolated worktree: {reason}"),
            ));
        }
        let canonical = self.validate_team_worktree_path(team_id, &target)?;
        self.store.update_team_worktree_status(
            team_id.as_str(),
            &canonical,
            TeamWorktreeOwnership::Created,
            TeamWorktreeStatus::Active,
            None,
            None,
            now_ms()?,
        )?;
        Ok(canonical)
    }

    #[allow(clippy::too_many_lines)]
    fn cleanup_team_worktree(&self, team_id: &TeamId) -> Result<Value, ControlError> {
        let Some(record) = self.store.team_worktree(team_id.as_str())? else {
            return Ok(json!({
                "team_id": team_id,
                "status": "attached_not_owned",
                "reason": "no durable owned-worktree record exists",
            }));
        };
        if record.ownership == TeamWorktreeOwnership::Attached {
            let attached = self.store.update_team_worktree_status(
                team_id.as_str(),
                &record.working_directory,
                record.ownership,
                TeamWorktreeStatus::AttachedNotOwned,
                record.reason.as_deref(),
                None,
                now_ms()?,
            )?;
            return serde_json::to_value(attached).map_err(ControlError::database);
        }
        if record.status == TeamWorktreeStatus::Removed {
            return serde_json::to_value(record).map_err(ControlError::database);
        }

        let path = record.working_directory.clone();
        let path_present = match fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return self.retain_team_worktree(
                    &record,
                    "worktree_metadata_failed",
                    &format!("could not inspect the recorded worktree path: {error}"),
                );
            }
        };
        if path_present {
            let canonical = match self.validate_team_worktree_path(team_id, &path) {
                Ok(canonical) if canonical == path => canonical,
                Ok(canonical) => {
                    return self.retain_team_worktree(
                        &record,
                        "worktree_identity_mismatch",
                        &format!(
                            "recorded worktree path resolved to a different path: {}",
                            canonical.display()
                        ),
                    );
                }
                Err(error) => {
                    return self.retain_team_worktree(&record, error.code, &error.to_string());
                }
            };
            let dirty = control_git_command(self.review.git_executable(), &canonical)
                .args(["status", "--porcelain=v1", "--untracked-files=all"])
                .output()
                .map_err(|error| {
                    ControlError::io("inspect worktree changes", &canonical, &error)
                })?;
            if !dirty.status.success() {
                return self.retain_team_worktree(
                    &record,
                    "worktree_status_failed",
                    String::from_utf8_lossy(&dirty.stderr).trim(),
                );
            }
            if !dirty.stdout.is_empty() {
                return self.retain_team_worktree(
                    &record,
                    "worktree_dirty",
                    "worktree has tracked, staged, or untracked changes",
                );
            }

            let unreachable = control_git_command(self.review.git_executable(), &canonical)
                // `--all` also includes the current worktree's pseudo-ref,
                // which would make every detached HEAD appear reachable from
                // itself. Limit the negative set to durable refs under
                // `refs/` so a candidate held only by this worktree is kept.
                .args(["rev-list", "HEAD", "--not", "--glob=refs/*"])
                .output()
                .map_err(|error| {
                    ControlError::io("inspect worktree commit reachability", &canonical, &error)
                })?;
            if !unreachable.status.success() {
                return self.retain_team_worktree(
                    &record,
                    "worktree_reachability_failed",
                    String::from_utf8_lossy(&unreachable.stderr).trim(),
                );
            }
            let unreachable_shas = String::from_utf8_lossy(&unreachable.stdout)
                .lines()
                .filter(|line| !line.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if !unreachable_shas.is_empty() {
                return self.retain_team_worktree(
                    &record,
                    "worktree_unreachable_commits",
                    &format!(
                        "worktree contains commits unreachable from every ref: {}",
                        unreachable_shas.join(", ")
                    ),
                );
            }

            let removal = match control_git_command(
                self.review.git_executable(),
                self.identity.repository_root(),
            )
            .args(["worktree", "remove"])
            .arg(&canonical)
            .output()
            {
                Ok(removal) => removal,
                Err(error) => {
                    return self.retain_team_worktree(
                        &record,
                        "worktree_remove_failed",
                        &format!("could not execute git worktree remove: {error}"),
                    );
                }
            };
            if !removal.status.success() {
                return self.retain_team_worktree(
                    &record,
                    "worktree_remove_failed",
                    String::from_utf8_lossy(&removal.stderr).trim(),
                );
            }
            match fs::symlink_metadata(&canonical) {
                Ok(_) => {
                    return self.retain_team_worktree(
                        &record,
                        "worktree_remove_failed",
                        "git worktree remove returned without removing the directory",
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return self.retain_team_worktree(
                        &record,
                        "worktree_remove_failed",
                        &format!("could not verify worktree removal: {error}"),
                    );
                }
            }
        }

        let listing = match control_git_command(
            self.review.git_executable(),
            self.identity.repository_root(),
        )
        .args(["worktree", "list", "--porcelain", "-z"])
        .output()
        {
            Ok(listing) => listing,
            Err(error) => {
                return self.retain_team_worktree(
                    &record,
                    "worktree_list_failed",
                    &format!("could not inspect Git worktree metadata: {error}"),
                );
            }
        };
        if !listing.status.success() {
            return self.retain_team_worktree(
                &record,
                "worktree_list_failed",
                String::from_utf8_lossy(&listing.stderr).trim(),
            );
        }
        let Some(path_text) = path.to_str() else {
            return self.retain_team_worktree(
                &record,
                "worktree_metadata_unverifiable",
                "recorded worktree path is not valid UTF-8 and cannot be matched safely",
            );
        };
        let metadata_present = listing.stdout.split(|byte| *byte == 0).any(|field| {
            std::str::from_utf8(field)
                .ok()
                .and_then(|field| field.strip_prefix("worktree "))
                == Some(path_text)
        });
        if metadata_present {
            // The path is absent, so filesystem identity cannot be revalidated here.
            // Git's registered-worktree link check fences unrelated occupants.
            let stale_removal = match control_git_command(
                self.review.git_executable(),
                self.identity.repository_root(),
            )
            .args(["worktree", "remove"])
            .arg(&path)
            .output()
            {
                Ok(removal) => removal,
                Err(error) => {
                    return self.retain_team_worktree(
                        &record,
                        "worktree_remove_failed",
                        &format!(
                            "could not execute exact cleanup for the absent worktree: {error}"
                        ),
                    );
                }
            };
            if !stale_removal.status.success() {
                return self.retain_team_worktree(
                    &record,
                    "worktree_remove_failed",
                    String::from_utf8_lossy(&stale_removal.stderr).trim(),
                );
            }
            let relisted = match control_git_command(
                self.review.git_executable(),
                self.identity.repository_root(),
            )
            .args(["worktree", "list", "--porcelain", "-z"])
            .output()
            {
                Ok(listing) => listing,
                Err(error) => {
                    return self.retain_team_worktree(
                        &record,
                        "worktree_list_failed",
                        &format!("could not verify exact Git metadata cleanup: {error}"),
                    );
                }
            };
            if !relisted.status.success() {
                return self.retain_team_worktree(
                    &record,
                    "worktree_list_failed",
                    String::from_utf8_lossy(&relisted.stderr).trim(),
                );
            }
            let metadata_still_present = relisted.stdout.split(|byte| *byte == 0).any(|field| {
                std::str::from_utf8(field)
                    .ok()
                    .and_then(|field| field.strip_prefix("worktree "))
                    == Some(path_text)
            });
            if metadata_still_present {
                return self.retain_team_worktree(
                    &record,
                    "worktree_metadata_retained",
                    "Git returned success without removing the exact absent-worktree entry",
                );
            }
        }
        let removed = self.store.update_team_worktree_status(
            team_id.as_str(),
            &record.working_directory,
            record.ownership,
            TeamWorktreeStatus::Removed,
            None,
            None,
            now_ms()?,
        )?;
        serde_json::to_value(removed).map_err(ControlError::database)
    }

    fn retain_team_worktree(
        &self,
        record: &TeamWorktreeRecord,
        error_code: &str,
        reason: &str,
    ) -> Result<Value, ControlError> {
        let reason = if reason.trim().is_empty() {
            "Git refused to remove the owned worktree"
        } else {
            reason.trim()
        };
        let retained = self.store.update_team_worktree_status(
            &record.team_id,
            &record.working_directory,
            record.ownership,
            TeamWorktreeStatus::RetainedWithReason,
            Some(reason),
            Some(error_code),
            now_ms()?,
        )?;
        serde_json::to_value(retained).map_err(ControlError::database)
    }

    fn bind_launched_actor(
        &self,
        actor_ref: &ActorRef,
        session: &SessionRecord,
    ) -> Result<(), ControlError> {
        let Some(binding) = CallerIdentityDriver::binding_for_launched_session(
            &session.backend,
            session.resume_token.as_deref(),
        ) else {
            return Ok(());
        };
        self.store
            .bind_actor(binding.kind(), binding.value(), actor_ref, now_ms()?)
    }

    fn mutate_matching_session(
        &self,
        expected: &SessionRecord,
        compare_runtime: bool,
        mut apply: impl FnMut(&mut SessionRecord) -> Result<bool, ControlError>,
    ) -> Result<SessionRecord, ControlError> {
        let actor_id = expected.actor_id.clone();
        self.store.mutate_session(&actor_id, |current| {
            if current.actor_id != expected.actor_id
                || current.team_id != expected.team_id
                || current.working_directory != expected.working_directory
                || current.backend != expected.backend
                || (compare_runtime && current.runtime != expected.runtime)
                || current.external_id != expected.external_id
                || current.launch_key != expected.launch_key
            {
                return Err(ControlError::new(
                    "session_revision_conflict",
                    format!("durable session `{actor_id}` changed ownership while updating"),
                )
                .with_details(json!({
                    "actor_id": actor_id.as_str(),
                    "expected_revision": expected.row_revision,
                    "actual_revision": current.row_revision,
                    "reason": "session_ownership_changed",
                }))
                .with_hint("reload the durable session and retry the operation"));
            }
            apply(current)
        })
    }

    fn persist_observed_session_status(
        &self,
        expected: &SessionRecord,
        status: &str,
        observed_at_ms: u64,
    ) -> Result<SessionRecord, ControlError> {
        self.mutate_matching_session(expected, true, |current| {
            if current.status == "stopped" {
                return Err(ControlError::new(
                    "session_revision_conflict",
                    format!(
                        "durable session `{}` became terminal while updating status",
                        current.actor_id
                    ),
                )
                .with_hint("reload the durable session and retry the operation"));
            }
            if current.updated_at_ms > observed_at_ms
                || (current.row_revision > expected.row_revision
                    && current.status != expected.status)
            {
                return Ok(false);
            }
            if current.status == status && current.updated_at_ms == observed_at_ms {
                return Ok(false);
            }
            status.clone_into(&mut current.status);
            current.updated_at_ms = current.updated_at_ms.max(observed_at_ms);
            Ok(true)
        })
    }

    fn persist_session_checkpoint(
        &self,
        expected: &SessionRecord,
        token: &str,
        observed_at_ms: u64,
    ) -> Result<SessionRecord, ControlError> {
        self.mutate_matching_session(expected, true, |current| {
            if current.external_id.is_some()
                || !matches!(current.status.as_str(), "launching" | "launch_failed")
            {
                return Err(ControlError::new(
                    "session_revision_conflict",
                    format!(
                        "durable session `{}` no longer owns the checkpointed launch",
                        current.actor_id
                    ),
                )
                .with_hint("reload the durable session and retry the operation"));
            }
            if current.updated_at_ms > observed_at_ms
                || (current.row_revision > expected.row_revision
                    && current.resume_token != expected.resume_token)
            {
                return Ok(false);
            }
            if current.resume_token.as_deref() == Some(token)
                && current.updated_at_ms == observed_at_ms
            {
                return Ok(false);
            }
            current.resume_token = Some(token.to_owned());
            current.updated_at_ms = current.updated_at_ms.max(observed_at_ms);
            Ok(true)
        })
    }

    fn validate_session_record(
        &self,
        session: &mut SessionRecord,
        actor_ref: &ActorRef,
        team_id: &TeamId,
        expected_directory: &Path,
        expected_external_name: Option<&str>,
        runtime: &dyn AgentRuntime,
    ) -> Result<(), ControlError> {
        let persisted_session = session.clone();
        let backfill_runtime = Self::validate_session_runtime(session, runtime)?;
        let actual_directory = fs::canonicalize(&session.working_directory).map_err(|error| {
            ControlError::io(
                "canonicalize durable session working directory",
                &session.working_directory,
                &error,
            )
        })?;
        let expected_directory = fs::canonicalize(expected_directory).map_err(|error| {
            ControlError::io(
                "canonicalize expected session working directory",
                expected_directory,
                &error,
            )
        })?;
        let directory_identity =
            WorkspaceIdentity::discover_with_git(&actual_directory, self.review.git_executable())?;
        let conflicting_owner = self.store.sessions()?.into_iter().find(|other| {
            other.team_id != session.team_id
                && fs::canonicalize(&other.working_directory).ok().as_deref()
                    == Some(actual_directory.as_path())
        });
        let expected_team = Some(team_id.as_str());
        if session.actor_id != actor_ref.actor_id.as_str()
            || session.team_id.as_deref() != expected_team
            || actual_directory != expected_directory
            || directory_identity.git_common_dir() != self.identity.git_common_dir()
            || directory_identity.root() != actual_directory
            || actual_directory == self.identity.root()
            || conflicting_owner.is_some()
        {
            return Err(ControlError::new(
                "session_ownership_mismatch",
                "the durable backend session does not belong to the expected actor and worktree",
            )
            .with_details(json!({
                "expected": {
                    "actor_id": actor_ref.actor_id,
                    "team_id": team_id,
                    "working_directory": expected_directory,
                    "configured_backend": self.sessions.name(),
                    "runtime": runtime.id().as_str(),
                },
                "actual": {
                    "actor_id": session.actor_id,
                    "team_id": session.team_id,
                    "working_directory": actual_directory,
                    "backend": session.backend,
                    "runtime": session.runtime,
                    "git_common_dir": directory_identity.git_common_dir(),
                    "conflicting_actor_id": conflicting_owner.map(|owner| owner.actor_id),
                },
            })));
        }
        if let Some(expected) = expected_external_name {
            let self_bootstrapped = session.launch_key
                == format!(
                    "self-bootstrap:{}:{}",
                    actor_ref.actor_epoch.get().saturating_sub(1),
                    actor_ref.actor_epoch
                );
            if !self_bootstrapped {
                self.sessions.validate_expected_external_id(
                    &session.backend,
                    actor_ref.actor_id.as_str(),
                    "recovered session",
                    expected,
                    session.external_id.as_deref(),
                )?;
            }
        }
        if backfill_runtime {
            let desired_runtime = session
                .runtime
                .clone()
                .expect("legacy runtime validation backfilled the selected runtime");
            *session = self.mutate_matching_session(&persisted_session, false, |current| {
                if current
                    .runtime
                    .as_deref()
                    .is_some_and(|value| value != desired_runtime)
                {
                    return Err(ControlError::new(
                        "session_runtime_mismatch",
                        format!(
                            "durable session runtime changed while backfilling `{desired_runtime}`"
                        ),
                    ));
                }
                if current.runtime.as_deref() == Some(desired_runtime.as_str()) {
                    return Ok(false);
                }
                current.runtime = Some(desired_runtime.clone());
                Ok(true)
            })?;
        }
        Ok(())
    }

    fn validate_session_runtime(
        session: &mut SessionRecord,
        runtime: &dyn AgentRuntime,
    ) -> Result<bool, ControlError> {
        let migrated_legacy_row = session.runtime.is_none();
        let durable_runtime = session
            .runtime
            .clone()
            .unwrap_or_else(|| LEGACY_RUNTIME_ID.to_owned());
        let selected_runtime = runtime.id().as_str();
        if durable_runtime != selected_runtime {
            return Err(ControlError::new(
                "session_runtime_mismatch",
                format!(
                    "durable session runtime `{durable_runtime}` does not match selected runtime `{selected_runtime}`"
                ),
            )
            .with_details(json!({
                "actor_id": session.actor_id,
                "durable_runtime": durable_runtime,
                "selected_runtime": selected_runtime,
                "legacy_runtime_defaulted": migrated_legacy_row,
            }))
            .with_hint(
                "restore the runtime that owns this session before reusing or recovering it",
            ));
        }
        if migrated_legacy_row {
            session.runtime = Some(durable_runtime);
        }
        Ok(migrated_legacy_row)
    }

    fn validate_launched_handle(
        &self,
        actor_ref: &ActorRef,
        expected_name: &str,
        handle: &agsv_session::SessionHandle,
    ) -> Result<(), ControlError> {
        self.sessions.validate_expected_external_id(
            &handle.backend,
            actor_ref.actor_id.as_str(),
            "launched session",
            expected_name,
            Some(&handle.external_id),
        )
    }

    fn validate_implementation_session_record(
        &self,
        session: &mut SessionRecord,
        actor: &Actor,
    ) -> Result<(), ControlError> {
        let Some(team_id) = actor.team_id.as_ref() else {
            return Ok(());
        };
        let profile = self.actor_profile(actor)?;
        let runtime = self.runtime_for_profile(profile)?;
        let actor_ref = actor.actor_ref();
        let expected_name = session_name(self.identity.workspace_id().as_str(), &actor_ref);
        let expected_directory = session.working_directory.clone();
        self.validate_session_record(
            session,
            &actor_ref,
            team_id,
            &expected_directory,
            Some(&expected_name),
            runtime.as_ref(),
        )
    }

    #[allow(clippy::too_many_lines)]
    fn reconcile(&self) -> Result<Value, ControlError> {
        let mut checked = 0_u64;
        let mut online = 0_u64;
        let mut offline = 0_u64;
        let mut failures = Vec::new();
        let (_, preflight_supervisor, _) = self.store.load()?;
        let mut conflicted_teams = BTreeMap::new();
        let preflight_snapshot = preflight_supervisor.snapshot();
        let team_reporting = self.team_reporting_context()?;
        let mut working_directory_drift = Vec::new();
        for team in &preflight_snapshot.teams {
            if team_reporting
                .worktrees
                .get(team.team_id.as_str())
                .is_some_and(|record| record.ownership != TeamWorktreeOwnership::Attached)
            {
                let observation =
                    self.team_working_directory_observation(&team.team_id, &team_reporting);
                if !observation.drift.is_empty() {
                    working_directory_drift.push(json!({
                        "team_id": team.team_id,
                        "observation": observation,
                    }));
                }
            }
            if matches!(team.status, TeamStatus::Closing | TeamStatus::Closed) {
                continue;
            }
            if let Err(error) = self.existing_team_working_directory(&team.team_id) {
                let failure = json!({
                    "team_id": team.team_id,
                    "phase": "working_directory_preflight",
                    "error": error.to_string(),
                    "error_code": error.code,
                    "details": error.details,
                });
                failures.push(failure.clone());
                conflicted_teams.insert(team.team_id.clone(), failure);
            }
        }
        for mut session in team_reporting.all_sessions.clone() {
            checked += 1;
            if session
                .team_id
                .as_deref()
                .and_then(|value| TeamId::new(value.to_owned()).ok())
                .is_some_and(|team_id| conflicted_teams.contains_key(&team_id))
            {
                continue;
            }
            let actor_id =
                ActorId::new(session.actor_id.clone()).map_err(ControlError::protocol)?;
            let (_, supervisor, _) = self.store.load()?;
            let actor = supervisor.actor(&actor_id).cloned();
            let lifecycle_teardown = actor
                .as_ref()
                .and_then(|actor| actor.team_id.as_ref())
                .and_then(|team_id| supervisor.team(team_id))
                .is_some_and(|team| {
                    matches!(team.status, TeamStatus::Closing | TeamStatus::Closed)
                });
            if lifecycle_teardown {
                continue;
            }
            let active_desired = actor
                .as_ref()
                .and_then(|actor| actor.team_id.as_ref())
                .and_then(|team_id| supervisor.team(team_id))
                .is_some_and(|team| {
                    team.status == TeamStatus::Active
                        && Self::effective_team_intent(team)
                            .and_then(|(desired, _)| desired_actor_ids(team, desired))
                            .is_ok_and(|ids| ids.contains(&actor_id))
                });
            if session.replacement_intent_in_progress() {
                continue;
            }
            let internally_managed_launch = active_desired
                && actor
                    .as_ref()
                    .and_then(|actor| actor.team_id.as_ref())
                    .is_some_and(|team_id| {
                        session.launch_key
                            == reconciliation_launch_operation_id(
                                team_id,
                                supervisor.team(team_id).expect("actor team exists").epoch,
                                &actor_id,
                                actor.as_ref().expect("actor checked above").epoch,
                            )
                    })
                && session.external_id.is_none()
                && matches!(session.status.as_str(), "launching" | "launch_failed");
            if internally_managed_launch {
                continue;
            }
            if actor
                .as_ref()
                .is_some_and(|actor| actor.status == ActorStatus::Stopped)
                && session.status == "stopped"
            {
                continue;
            }
            if session.external_id.is_none()
                && matches!(session.status.as_str(), "launching" | "launch_failed")
                && actor.as_ref().is_some_and(|actor| {
                    matches!(
                        actor.status,
                        ActorStatus::Starting | ActorStatus::Stale | ActorStatus::Healthy
                    )
                })
                && active_desired
            {
                if let Err(error) = self.recover_incomplete_session(&mut session) {
                    failures.push(json!({
                        "actor_id": session.actor_id,
                        "phase": "resume_launch",
                        "error": error.to_string(),
                    }));
                    continue;
                }
            }
            if let Some(actor) = actor.as_ref()
                && actor.team_id.is_some()
                && let Err(error) = self.validate_implementation_session_record(&mut session, actor)
            {
                failures.push(json!({
                    "actor_id": session.actor_id,
                    "phase": "session_validation",
                    "error": error.to_string(),
                }));
                continue;
            }
            let status = match self.sessions.status(&session) {
                Ok(status) => status,
                Err(error) => {
                    failures.push(json!({
                        "actor_id": session.actor_id,
                        "phase": "session_status",
                        "error": error.to_string(),
                    }));
                    continue;
                }
            };
            session = self.persist_observed_session_status(&session, &status, now_ms()?)?;
            let durable_status = session.status.clone();
            let Some(actor) = actor else {
                continue;
            };
            let actor_ref = actor.actor_ref();
            if session_is_present(&durable_status)
                && ((actor.team_id.is_none() && actor.status == ActorStatus::Healthy)
                    || (active_desired
                        && matches!(
                            actor.status,
                            ActorStatus::Starting | ActorStatus::Stale | ActorStatus::Healthy
                        )))
            {
                let _ = self.store.mutate(
                    "actor.reconciled_online",
                    &json!({ "actor_id": actor_id, "session_status": durable_status }),
                    now_ms()?,
                    |state| {
                        state
                            .heartbeat(&actor_ref, TimestampMillis(now_ms()?))
                            .map_err(ControlError::core)
                    },
                )?;
                online += 1;
            } else if !session_is_present(&durable_status) && actor.status == ActorStatus::Healthy {
                let _ = self.store.mutate(
                    "actor.reconciled_stale",
                    &json!({ "actor_id": actor_id, "session_status": durable_status }),
                    now_ms()?,
                    |state| {
                        state
                            .set_actor_status(&actor_ref, ActorStatus::Stale)
                            .map_err(ControlError::core)
                    },
                )?;
                offline += 1;
            }
        }
        let (_, supervisor, _) = self.store.load()?;
        let team_ids = supervisor
            .snapshot()
            .teams
            .into_iter()
            .map(|team| team.team_id)
            .collect::<Vec<_>>();
        let assignment_instances = self.assignment_instance_summary(&supervisor)?;
        let mut instance_reconciliation = Vec::new();
        for team_id in team_ids {
            if let Some(failure) = conflicted_teams.get(&team_id) {
                let team = supervisor
                    .team(&team_id)
                    .ok_or_else(|| ControlError::not_found("team", team_id.as_str()))?;
                let (desired_instances, effective_assignment_policy) =
                    Self::effective_team_intent(team)?;
                instance_reconciliation.push(json!({
                    "team_id": team_id,
                    "team_status": team.status,
                    "desired_instances": desired_instances,
                    "effective_assignment_policy": effective_assignment_policy,
                    "launched": 0,
                    "replaced": 0,
                    "reused": 0,
                    "stopped": 0,
                    "failures": [failure],
                    "complete": false,
                    "deferred": true,
                    "state": find_team_instance_summary(&assignment_instances, &team_id),
                }));
                continue;
            }
            match self.reconcile_team_instances(&team_id) {
                Ok(result) => instance_reconciliation.push(result),
                Err(error) => failures.push(json!({
                    "team_id": team_id,
                    "phase": "instance_reconciliation",
                    "error": error.to_string(),
                })),
            }
        }
        let instances_complete = instance_reconciliation
            .iter()
            .all(|result| result["complete"].as_bool() == Some(true));
        let complete = failures.is_empty() && instances_complete;
        Ok(json!({
            "sessions_checked": checked,
            "actors_marked_online": online,
            "actors_marked_stale": offline,
            "working_directory_drift": working_directory_drift,
            "failures": failures,
            "instance_reconciliation": instance_reconciliation,
            "complete": complete,
        }))
    }

    fn recover_incomplete_session(&self, session: &mut SessionRecord) -> Result<(), ControlError> {
        let actor_id = ActorId::new(session.actor_id.clone()).map_err(ControlError::protocol)?;
        let team_id = session
            .team_id
            .as_ref()
            .ok_or_else(|| ControlError::invalid_request("implementation session has no team"))
            .and_then(|value| TeamId::new(value.clone()).map_err(ControlError::protocol))?;
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&actor_id)
            .ok_or_else(|| ControlError::not_found("actor", actor_id.as_str()))?;
        let actor_profile = self.actor_profile(actor)?.clone();
        let runtime = self.runtime_for_profile(&actor_profile)?;
        let actor_ref = actor.actor_ref();
        let expected_name = session_name(self.identity.workspace_id().as_str(), &actor_ref);
        let expected_directory = session.working_directory.clone();
        self.validate_session_record(
            session,
            &actor_ref,
            &team_id,
            &expected_directory,
            Some(&expected_name),
            runtime.as_ref(),
        )?;
        let prompt = implementation_prompt(
            &actor_profile.role_instructions,
            &actor_profile.role,
            &actor_ref,
            &team_id,
        )?;
        let runtime_config = Self::runtime_config(&actor_profile)?;
        let launch_directory = session.working_directory.clone();
        let backend_id = session.backend.clone();
        let launch_key = session.launch_key.clone();
        let recovered_token = session.resume_token.clone();
        if recovered_token.is_none()
            || self
                .store
                .session_presentation(actor_ref.actor_id.as_str())?
                .is_some()
        {
            self.ensure_actor_presentation(&actor_ref, &backend_id)?;
        }
        let hints = if recovered_token.is_some() {
            SessionLaunchHints::default()
        } else {
            self.launch_hints(&actor_id, &backend_id)?
        };
        let handle = {
            let mut checkpoint = |token: &str| {
                *session = self.persist_session_checkpoint(session, token, now_ms()?)?;
                self.bind_launched_actor(&actor_ref, session)
            };
            self.sessions.launch_with_initial_prompt_for_and_hints(
                &backend_id,
                actor_id.as_str(),
                &expected_name,
                &launch_directory,
                &launch_key,
                runtime.as_ref(),
                &runtime_config,
                Some(prompt.as_str()),
                recovered_token,
                &hints,
                &mut checkpoint,
            )?
        };
        self.validate_launched_handle(&actor_ref, &expected_name, &handle)?;
        session.external_id = Some(handle.external_id);
        session.resume_token = handle.resume_token;
        "idle".clone_into(&mut session.status);
        session.updated_at_ms = now_ms()?;
        session.row_revision = self.store.upsert_session(session)?;
        self.bind_launched_actor(&actor_ref, session)?;
        let _ = self.store.mutate(
            "actor.launch_recovered",
            &json!({ "actor_id": actor_id }),
            now_ms()?,
            |state| {
                state
                    .heartbeat(&actor_ref, TimestampMillis(now_ms()?))
                    .map_err(ControlError::core)
            },
        )?;
        Ok(())
    }
}

impl ControlPlane {
    fn actor_shutdown(
        &self,
        request: &Value,
        guards: &mut OperationGuards,
    ) -> Result<Value, ControlError> {
        let args: ShutdownArgs = decode(request)?;
        validate_operation_id(&args.operation_id)?;
        let actor_ref = self.caller_actor_ref(args.actor.as_deref())?;
        if let Some(result) =
            self.store
                .operation_result(&args.operation_id, "actor.shutdown", request)?
        {
            let recorded_actor: ActorRef =
                serde_json::from_value(result["actor"].clone()).map_err(ControlError::database)?;
            if recorded_actor != actor_ref {
                return Err(ControlError::new(
                    "operation_identity_mismatch",
                    "the shutdown result belongs to a different actor generation",
                ));
            }
            return Ok(result);
        }
        self.ensure_actor_binding_is_mutable(&actor_ref)?;
        self.heartbeat_actor(&actor_ref, "actor.authenticated")?;
        let claim_token = format!(
            "{}-{}-{}",
            std::process::id(),
            now_ms()?,
            NEXT_OPERATION_CLAIM.fetch_add(1, Ordering::Relaxed)
        );
        self.store.claim_operation(
            &args.operation_id,
            "actor.shutdown",
            request,
            &claim_token,
            now_ms()?,
        )?;
        let declared = self.store.declare_actor_shutdown(
            &actor_ref,
            args.reason.as_deref(),
            &args.operation_id,
            &claim_token,
            request,
            now_ms()?,
        );
        let declared = match declared {
            Ok(declared) => declared,
            Err(error) => {
                let _ = self
                    .store
                    .release_operation(&args.operation_id, &claim_token);
                return Err(error);
            }
        };
        match declared {
            ActorShutdownCommit::Applied { result, session } => {
                // The declaration and replay record are already durable. A backend may
                // terminate this process synchronously, so no write may follow this call.
                // Let newly arriving unrelated mutations and heartbeats proceed now;
                // the caller and actor guards still fence bootstrap/terminal reuse.
                guards.release_workspace();
                let _ = self.sessions.stop(&session);
                Ok(result)
            }
            ActorShutdownCommit::Replayed(result) => Ok(result),
        }
    }

    fn actor_stop(&self, request: &Value) -> Result<Value, ControlError> {
        let args: ReasonedIdArgs = decode(request)?;
        self.idempotent("actor.stop", request, &args.operation_id, || {
            let id = ActorId::new(args.id.clone()).map_err(ControlError::protocol)?;
            let (_, supervisor, _) = self.store.load()?;
            let actor_ref = supervisor
                .actor(&id)
                .ok_or_else(|| ControlError::not_found("actor", &args.id))?
                .actor_ref();
            if let Some(mut session) = self.store.session(&args.id)? {
                self.sessions.stop(&session)?;
                "stopped".clone_into(&mut session.status);
                session.updated_at_ms = now_ms()?;
                session.row_revision = self.store.upsert_session(&session)?;
            }
            let (revision, ()) = self.store.mutate(
                "actor.stopped",
                &json!({ "actor_id": id, "reason": args.reason }),
                now_ms()?,
                |state| {
                    state
                        .set_actor_status(&actor_ref, ActorStatus::Stopped)
                        .map_err(ControlError::core)
                },
            )?;
            Ok(json!({ "actor_id": id, "status": "stopped", "revision": revision }))
        })
    }
    #[allow(clippy::too_many_lines)]
    fn actor_replace(&self, request: &Value) -> Result<Value, ControlError> {
        let args: ReasonedIdArgs = decode(request)?;
        self.idempotent("actor.replace", request, &args.operation_id, || {
            let id = ActorId::new(args.id.clone()).map_err(ControlError::protocol)?;
            let (current_revision, supervisor, _) = self.store.load()?;
            let actor = supervisor
                .actor(&id)
                .ok_or_else(|| ControlError::not_found("actor", &args.id))?;
            let actor_profile = self.actor_profile(actor)?.clone();
            let runtime = self.runtime_for_profile(&actor_profile)?;
            let team_id = actor.team_id.clone().ok_or_else(|| {
                ControlError::unsupported(
                    "actor.replace",
                    "the Primary is replaced by bootstrap fencing",
                )
            })?;
            Self::ensure_desired_team_actor(&supervisor, &team_id, &id)?;
            let mut prior_session = self.store.session(&args.id)?.ok_or_else(|| {
                ControlError::new(
                    "session_not_found",
                    "replacement needs the actor working directory",
                )
            })?;
            let recovered_source_epoch =
                replacement_source_epoch(&prior_session.launch_key, &args.operation_id);
            if recovered_source_epoch.is_none() && prior_session.replacement_intent_in_progress() {
                return Err(ControlError::new(
                    "actor_replacement_in_progress",
                    format!("actor `{id}` already has an active replacement intent"),
                )
                .with_hint("retry the original actor launch or replacement operation ID"));
            }
            let runtime_backfill =
                Self::validate_session_runtime(&mut prior_session, runtime.as_ref())?.then(|| {
                    prior_session
                        .runtime
                        .clone()
                        .expect("validated legacy runtime was backfilled in memory")
                });
            if actor.status == ActorStatus::Healthy && recovered_source_epoch.is_none() {
                return Err(ControlError::new(
                    "actor_still_healthy",
                    "refusing to fence a healthy implementation actor; stop or reconcile it first",
                )
                .with_hint("run `agsv actor stop`, verify status, then retry replacement"));
            }

            let source_epoch = recovered_source_epoch.unwrap_or(actor.epoch.get());
            let intent_key = replacement_intent_key(&args.operation_id, source_epoch);
            let mut pending = if recovered_source_epoch.is_some() {
                prior_session
            } else {
                let expected_name =
                    session_name(self.identity.workspace_id().as_str(), &actor.actor_ref());
                let prior_directory = prior_session.working_directory.clone();
                self.validate_session_record(
                    &mut prior_session,
                    &actor.actor_ref(),
                    &team_id,
                    &prior_directory,
                    Some(&expected_name),
                    runtime.as_ref(),
                )?;
                self.store
                    .claim_replacement_intent(id.as_str(), &intent_key, now_ms()?)?
            };
            if let Some(runtime) = runtime_backfill {
                pending = self.mutate_matching_session(&pending, false, |current| {
                    if current
                        .runtime
                        .as_deref()
                        .is_some_and(|value| value != runtime)
                    {
                        return Err(ControlError::new(
                            "session_runtime_mismatch",
                            format!(
                                "durable session runtime changed while backfilling `{runtime}`"
                            ),
                        ));
                    }
                    if current.runtime.as_deref() == Some(runtime.as_str()) {
                        return Ok(false);
                    }
                    current.runtime = Some(runtime.clone());
                    Ok(true)
                })?;
            }

            if pending.status == "replacement_pending" {
                // Either persisted token can represent backend-owned launch state. Cleanup
                // must succeed through that persisted backend before the checkpoint is
                // discarded or the actor generation advances.
                if pending.external_id.is_some() || pending.resume_token.is_some() {
                    self.sessions.stop(&pending)?;
                }
                self.sessions.name().clone_into(&mut pending.backend);
                pending.external_id = None;
                pending.resume_token = None;
                "launching".clone_into(&mut pending.status);
                pending.updated_at_ms = now_ms()?;
                pending.row_revision = self.store.upsert_session(&pending)?;
            }

            let (revision, actor_ref) = if actor.epoch.get() == source_epoch {
                self.store.mutate(
                    "actor.replaced",
                    &json!({ "actor_id": id, "reason": args.reason }),
                    now_ms()?,
                    |state| {
                        Self::ensure_desired_team_actor(state, &team_id, &id)?;
                        state
                            .replace_implementation(&team_id, id.clone())
                            .map_err(ControlError::core)
                    },
                )?
            } else if source_epoch.checked_add(1) == Some(actor.epoch.get()) {
                (current_revision, actor.actor_ref())
            } else {
                return Err(ControlError::new(
                    "stale_replacement_intent",
                    "the durable replacement intent does not match the current actor generation",
                )
                .with_details(json!({
                    "actor_id": id,
                    "source_actor_epoch": source_epoch,
                    "current_actor_epoch": actor.epoch,
                })));
            };
            if self.insecure_debug_identity_selected()
                && std::env::var("AGSV_DEV_FAIL_AFTER_REPLACEMENT_COMMIT").as_deref() == Ok("1")
            {
                return Err(ControlError::new(
                    "simulated_replacement_crash",
                    "debug-only failure after the replacement generation commit",
                ));
            }

            let expected_name = session_name(self.identity.workspace_id().as_str(), &actor_ref);
            let pending_directory = pending.working_directory.clone();
            self.validate_session_record(
                &mut pending,
                &actor_ref,
                &team_id,
                &pending_directory,
                None,
                runtime.as_ref(),
            )?;
            if pending.status == "idle" && pending.external_id.is_some() {
                self.validate_session_record(
                    &mut pending,
                    &actor_ref,
                    &team_id,
                    &pending_directory,
                    Some(&expected_name),
                    runtime.as_ref(),
                )?;
                let status = self.sessions.status(&pending)?;
                if matches!(
                    status.as_str(),
                    "starting" | "working" | "idle" | "blocked" | "unknown"
                ) {
                    self.bind_launched_actor(&actor_ref, &pending)?;
                    self.heartbeat_actor(&actor_ref, "actor.replacement_recovered")?;
                    return Ok(json!({
                        "actor": actor_ref,
                        "session": pending,
                        "revision": revision,
                        "reused": true,
                    }));
                }
                pending.external_id = None;
                pending.resume_token = None;
            }
            "launching".clone_into(&mut pending.status);
            pending.updated_at_ms = now_ms()?;
            let prompt = implementation_prompt(
                &actor_profile.role_instructions,
                &actor_profile.role,
                &actor_ref,
                &team_id,
            )?;
            let runtime_config = Self::runtime_config(&actor_profile)?;
            pending.row_revision = self.store.upsert_session(&pending)?;
            let launch_directory = pending.working_directory.clone();
            let backend_id = pending.backend.clone();
            let launch_key_value = pending.launch_key.clone();
            let recovered_token = pending.resume_token.clone();
            if recovered_token.is_none()
                || self
                    .store
                    .session_presentation(actor_ref.actor_id.as_str())?
                    .is_some()
            {
                self.ensure_actor_presentation(&actor_ref, &backend_id)?;
            }
            let hints = if recovered_token.is_some() {
                SessionLaunchHints::default()
            } else {
                self.launch_hints(&actor_ref.actor_id, &backend_id)?
            };
            let launch = {
                let mut checkpoint = |token: &str| {
                    pending = self.persist_session_checkpoint(&pending, token, now_ms()?)?;
                    self.bind_launched_actor(&actor_ref, &pending)
                };
                self.sessions.launch_with_initial_prompt_for_and_hints(
                    &backend_id,
                    actor_ref.actor_id.as_str(),
                    &expected_name,
                    &launch_directory,
                    &launch_key_value,
                    runtime.as_ref(),
                    &runtime_config,
                    Some(prompt.as_str()),
                    recovered_token,
                    &hints,
                    &mut checkpoint,
                )
            };
            let handle = match launch {
                Ok(handle) => handle,
                Err(error) => {
                    if error.code == "session_revision_conflict" {
                        return Err(error);
                    }
                    "launch_failed".clone_into(&mut pending.status);
                    pending.updated_at_ms = now_ms()?;
                    pending.row_revision = self.store.upsert_session(&pending)?;
                    let _ = self.store.mutate(
                        "actor.replacement_launch_failed",
                        &json!({ "actor_id": actor_ref.actor_id, "error": error.to_string() }),
                        now_ms()?,
                        |state| {
                            state
                                .set_actor_status(&actor_ref, ActorStatus::Stale)
                                .map_err(ControlError::core)
                        },
                    );
                    return Err(error);
                }
            };
            self.validate_launched_handle(&actor_ref, &expected_name, &handle)?;
            let mut session = SessionRecord {
                external_id: Some(handle.external_id),
                resume_token: handle.resume_token,
                status: "idle".to_owned(),
                updated_at_ms: now_ms()?,
                ..pending
            };
            session.row_revision = self.store.upsert_session(&session)?;
            self.bind_launched_actor(&actor_ref, &session)?;
            let _ = self.store.mutate(
                "actor.replacement_started",
                &json!({ "actor_id": actor_ref.actor_id }),
                now_ms()?,
                |state| {
                    state
                        .heartbeat(&actor_ref, TimestampMillis(now_ms()?))
                        .map_err(ControlError::core)
                },
            )?;
            Ok(json!({
                "actor": actor_ref,
                "session": session,
                "revision": revision,
                "reused": false,
            }))
        })
    }
    fn run_create(&self, request: &Value) -> Result<Value, ControlError> {
        let args: RunCreateArgs = decode(request)?;
        self.idempotent("run.create", request, &args.operation_id, || {
            let request_id = args.request.as_deref().ok_or_else(|| {
                ControlError::unsupported(
                    "run.create",
                    "a run is created atomically by `request create`; pass --request to reuse it",
                )
            })?;
            let id = RequestId::new(request_id.to_owned()).map_err(ControlError::protocol)?;
            let (_, supervisor, _) = self.store.load()?;
            let item = supervisor
                .request(&id)
                .ok_or_else(|| ControlError::not_found("request", request_id))?;
            if item.team_id.as_str() != args.team {
                return Err(ControlError::invalid_request(
                    "request does not belong to the selected team",
                ));
            }
            Ok(json!({ "run": supervisor.run(&item.run_id), "reused": true }))
        })
    }
    fn run_transition(
        &self,
        request: &Value,
        action: RunControlAction,
        operation: &str,
    ) -> Result<Value, ControlError> {
        let args: MutationIdArgs = decode(request)?;
        self.idempotent(operation, request, &args.operation_id, || {
            let run_id = RunId::new(args.id.clone()).map_err(ControlError::protocol)?;
            let (_, supervisor, _) = self.store.load()?;
            let run = supervisor
                .run(&run_id)
                .ok_or_else(|| ControlError::not_found("run", &args.id))?;
            let request_id = run.request_id.clone();
            let primary = active_primary_actor(&supervisor)?;
            let target = MessageTarget::Actor(
                run.assignment
                    .as_ref()
                    .ok_or_else(|| ControlError::invalid_request("run is unassigned"))?
                    .actor
                    .actor_id
                    .clone(),
            );
            let (envelope, _) = request_envelope(
                &supervisor,
                &request_id,
                primary,
                target.clone(),
                Message::RunControl(RunControl { action }),
                message_id(&args.operation_id, "run-control"),
            )?;
            let (revision, outcome) = self.store.mutate(
                operation,
                &json!({ "run_id": run_id, "action": action }),
                now_ms()?,
                |state| apply_envelope_with_archive(&self.store, state, envelope.clone()),
            )?;
            let wake = self.wake_request_target_after_commit(
                &request_id,
                &target,
                &format!("AGSV run `{run_id}` changed state; read your durable inbox."),
            )?;
            let (_, updated, _) = self.store.load()?;
            let status = updated
                .run(&run_id)
                .ok_or_else(|| ControlError::not_found("run", run_id.as_str()))?
                .status;
            Ok(json!({
                "run_id": run_id,
                "status": status,
                "outcome": apply_name(outcome),
                "revision": revision,
                "wake_deferred": wake["status"] == "deferred",
                "wake": wake,
            }))
        })
    }
    fn cancel_by_run(&self, request: &Value) -> Result<Value, ControlError> {
        let args: ReasonedIdArgs = decode(request)?;
        let run_id = RunId::new(args.id.clone()).map_err(ControlError::protocol)?;
        let (_, supervisor, _) = self.store.load()?;
        let run = supervisor
            .run(&run_id)
            .ok_or_else(|| ControlError::not_found("run", &args.id))?;
        self.cancel_request(
            "run.cancel",
            request,
            &args.operation_id,
            &run.request_id,
            args.reason.as_deref().unwrap_or("run cancelled"),
        )
    }
    #[allow(clippy::too_many_lines)]
    fn request_create(&self, request: &Value) -> Result<Value, ControlError> {
        let args: RequestCreateArgs = decode(request)?;
        self.idempotent("request.create", request, &args.operation_id, || {
            let team_id = TeamId::new(args.team.clone()).map_err(ControlError::protocol)?;
            let request_id = RequestId::new(stable_id("request", &args.operation_id))
                .map_err(ControlError::protocol)?;
            let run_id =
                RunId::new(stable_id("run", &args.operation_id)).map_err(ControlError::protocol)?;
            let instructions = args.body.clone().unwrap_or_else(|| args.title.clone());
            let stable_message_id = message_id(&args.operation_id, "request");
            let retry_envelope = self.committed_request_retry(&args, &instructions, &team_id)?;
            let (_, supervisor, _) = self.store.load()?;
            let (base_sha, base_source) = match retry_envelope.as_ref() {
                Some(Envelope {
                    message: Message::ImplementationRequest(specification),
                    ..
                }) => (specification.base_sha.clone(), specification.base_source),
                Some(_) => unreachable!("committed_request_retry validates the payload kind"),
                None => match args.base_sha.as_deref() {
                    Some(value) => (
                        validate_declared_base_sha(
                            self.review.git_executable(),
                            self.identity.repository_root(),
                            value,
                        )?,
                        agsv_protocol::RequestBaseSource::Declared,
                    ),
                    None => (
                        git_sha_for(
                            self.review.git_executable(),
                            &self.request_base_directory(&team_id)?,
                        )?,
                        agsv_protocol::RequestBaseSource::Derived,
                    ),
                },
            };
            let request_team_epoch = if let Some(envelope) = &retry_envelope {
                envelope.team_epoch
            } else {
                supervisor.team(&team_id).map(|team| team.epoch)
            };
            let (revision, (outcome, target)) = self.store.mutate(
                "request.created",
                &json!({
                    "request_id": request_id,
                    "run_id": run_id,
                    "team_id": team_id,
                    "team_epoch": request_team_epoch,
                }),
                now_ms()?,
                |state| {
                    if let Some(envelope) = retry_envelope.clone() {
                        let target = envelope.target.clone();
                        let outcome = apply_envelope_with_archive(&self.store, state, envelope)?;
                        return Ok((outcome, target));
                    }
                    let primary = active_primary_actor(state)?;
                    let team = state
                        .team(&team_id)
                        .ok_or_else(|| ControlError::not_found("team", &args.team))?;
                    if team.status != TeamStatus::Active {
                        return Err(ControlError::new(
                            "team_inactive",
                            format!(
                                "team `{team_id}` is `{}` and cannot receive new work",
                                enum_name(team.status)
                            ),
                        )
                        .with_details(json!({
                            "team_id": team_id,
                            "team_status": team.status,
                        })));
                    }
                    let actor = self.select_request_actor(state, team)?;
                    let target = MessageTarget::Actor(actor.actor_id.clone());
                    let envelope = make_envelope(
                        state,
                        primary,
                        target.clone(),
                        Some(team_id.clone()),
                        Some(run_id.clone()),
                        Some(request_id.clone()),
                        None,
                        Message::ImplementationRequest(ImplementationRequest {
                            title: args.title.clone(),
                            instructions: instructions.clone(),
                            base_sha: base_sha.clone(),
                            base_source,
                            acceptance_criteria: vec![instructions.clone()],
                            evidence_requirements: vec![EvidenceKind::Git, EvidenceKind::Test],
                        }),
                        stable_message_id.clone(),
                    )?;
                    let outcome = apply_envelope_with_archive(&self.store, state, envelope)?;
                    Ok((outcome, target))
                },
            )?;
            if self.debug_crash_requested(
                "AGSV_DEV_FAIL_AFTER_REQUEST_CREATE_COMMIT",
                "request_create_commit",
            ) {
                return Err(ControlError::new(
                    "simulated_request_create_crash",
                    "debug-only failure after the request assignment commit",
                ));
            }
            self.notify_target(
                &target,
                &format!("New durable AGSV request `{request_id}` is waiting in your inbox."),
            )?;
            let (_, updated, _) = self.store.load()?;
            let request = updated
                .request(&request_id)
                .map(|request| self.hydrated_request_value(request))
                .transpose()?;
            Ok(json!({
                "request": request,
                "run": updated.run(&run_id),
                "outcome": apply_name(outcome),
                "revision": revision,
            }))
        })
    }
    fn request_claim(&self, request: &Value) -> Result<Value, ControlError> {
        let args: RequestClaimArgs = decode(request)?;
        self.idempotent("request.claim", request, &args.operation_id, || {
            let request_id = RequestId::new(args.id.clone()).map_err(ControlError::protocol)?;
            let actor = self.resolve_actor(args.actor.as_deref())?;
            if !actor.has_capability(IMPLEMENTATION_EXECUTION_CAPABILITY) {
                return Err(ControlError::new(
                    "implementation_authentication_required",
                    "request claim requires an authenticated Implementation Orchestrator",
                ));
            }
            let (_, supervisor, _) = self.store.load()?;
            let item = supervisor
                .request(&request_id)
                .ok_or_else(|| ControlError::not_found("request", &args.id))?;
            let assignment = item.assignment.as_ref().ok_or_else(|| {
                ControlError::new("unassigned_request", "request has no current assignment")
            })?;
            if assignment.actor != actor.actor_ref() {
                return Err(ControlError::new(
                    "claim_conflict",
                    format!(
                        "request is assigned to actor generation `{}:{}`",
                        assignment.actor.actor_id, assignment.actor.actor_epoch
                    ),
                ));
            }
            Ok(json!({
                "request_id": request_id,
                "assignment": assignment,
                "outcome": "already_assigned",
                "claimed": false,
            }))
        })
    }
    fn request_block(&self, request: &Value) -> Result<Value, ControlError> {
        let args: RequestBlockArgs = decode(request)?;
        self.idempotent("request.block", request, &args.operation_id, || {
            let request_id = RequestId::new(args.id.clone()).map_err(ControlError::protocol)?;
            let (_, supervisor, _) = self.store.load()?;
            let actor = self.resolve_actor(None)?;
            let target = MessageTarget::Primary;
            let (envelope, run_id) = request_envelope(
                &supervisor,
                &request_id,
                actor.actor_ref(),
                target.clone(),
                Message::Blocker(BlockerNotice {
                    summary: args.reason,
                    needs_primary: true,
                    evidence: Vec::new(),
                }),
                message_id(&args.operation_id, "block"),
            )?;
            let (revision, outcome) = self.store.mutate(
                "request.blocked",
                &json!({ "request_id": request_id }),
                now_ms()?,
                |state| apply_envelope_with_archive(&self.store, state, envelope.clone()),
            )?;
            self.notify_target(
                &target,
                &format!(
                    "AGSV request `{request_id}` is blocked and needs Primary attention; read your durable inbox."
                ),
            )?;
            Ok(json!({ "request_id": request_id, "run_id": run_id, "outcome": apply_name(outcome), "revision": revision }))
        })
    }
    fn request_complete(&self, request: &Value) -> Result<Value, ControlError> {
        let args: RequestCompleteArgs = decode(request)?;
        self.idempotent("request.complete", request, &args.operation_id, || {
            let request_id = RequestId::new(args.id.clone()).map_err(ControlError::protocol)?;
            let sha = GitSha::new(args.candidate_sha).map_err(ControlError::protocol)?;
            let (_, supervisor, _) = self.store.load()?;
            let actor = self.resolve_actor(None)?;
            let item = supervisor
                .request(&request_id)
                .ok_or_else(|| ControlError::not_found("request", &args.id))?;
            let candidate_directory = self
                .store
                .session(actor.actor_id.as_str())?
                .ok_or_else(|| {
                    ControlError::new(
                        "session_not_found",
                        "candidate evidence requires the assigned actor's isolated worktree",
                    )
                })?
                .working_directory;
            verify_candidate_head(
                self.review.git_executable(),
                &candidate_directory,
                &item.specification.base_sha,
                &sha,
            )?;
            let candidate = Candidate {
                request_id: request_id.clone(),
                team_id: item.team_id.clone(),
                sha,
                created_by: actor.actor_ref(),
                created_by_profile: actor.profile.as_ref().map(|profile| profile.name.clone()),
            };
            let target = MessageTarget::Primary;
            let (envelope, run_id) = request_envelope(
                &supervisor,
                &request_id,
                actor.actor_ref(),
                target.clone(),
                Message::CandidateReady(CandidateReady {
                    candidate: candidate.clone(),
                    summary: args.evidence.unwrap_or_else(|| "candidate ready".to_owned()),
                    evidence: Vec::new(),
                }),
                message_id(&args.operation_id, "candidate"),
            )?;
            let (revision, outcome) = self.store.mutate(
                "candidate.ready",
                &json!({ "request_id": request_id, "candidate": candidate }),
                now_ms()?,
                |state| apply_envelope_with_archive(&self.store, state, envelope.clone()),
            )?;
            self.notify_target(
                &target,
                &format!(
                    "AGSV candidate for request `{request_id}` is ready for Primary review; read your durable inbox."
                ),
            )?;
            Ok(json!({ "request_id": request_id, "run_id": run_id, "candidate": candidate, "outcome": apply_name(outcome), "revision": revision }))
        })
    }
    fn request_cancel(&self, request: &Value) -> Result<Value, ControlError> {
        let args: ReasonedIdArgs = decode(request)?;
        let id = RequestId::new(args.id.clone()).map_err(ControlError::protocol)?;
        self.cancel_request(
            "request.cancel",
            request,
            &args.operation_id,
            &id,
            args.reason.as_deref().unwrap_or("request cancelled"),
        )
    }
    #[allow(clippy::too_many_lines)]
    fn message_send(&self, request: &Value) -> Result<Value, ControlError> {
        let args: MessageSendArgs = decode(request)?;
        validate_operation_id(&args.operation_id)?;
        if let Some(mut result) =
            self.store
                .operation_result(&args.operation_id, "message.send", request)?
        {
            let message_id = result
                .get("message_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ControlError::database(
                        "recorded message-send result lacks its stable message identifier",
                    )
                })?;
            let message_id =
                MessageId::new(message_id.to_owned()).map_err(ControlError::protocol)?;
            let wake = self.wake_delivery_target_after_commit(
                &message_id,
                &format!("New durable AGSV message `{message_id}` is waiting in your inbox."),
            )?;
            result["wake_deferred"] = json!(wake["status"] == "deferred");
            result["wake"] = wake;
            return Ok(result);
        }
        self.idempotent("message.send", request, &args.operation_id, || {
            let (_, supervisor, _) = self.store.load()?;
            let sender = self.resolve_actor(None)?;
            let kind = args.kind.to_ascii_lowercase().replace('-', "_");
            args.validate_for(&kind)?;
            let stable_message_id = message_id(&args.operation_id, "send");
            let existing = if let Some(delivery) = supervisor.delivery(&stable_message_id) {
                Some((
                    delivery.envelope.clone(),
                    delivery.payload_digest.clone(),
                ))
            } else {
                self.store
                    .archived_delivery(&stable_message_id)?
                    .map(|delivery| (delivery.envelope, delivery.payload_digest))
            };
            if let Some((existing_header, existing_digest)) = existing {
                if existing_header.sender != sender.actor_ref() {
                    return Err(ControlError::new(
                        "message_retry_sender_mismatch",
                        "only the original authenticated actor generation may retry this message",
                    ));
                }
                let envelope = self.hydrated_envelope(&existing_header, &existing_digest)?;
                validate_message_retry(&args, &kind, &envelope, &supervisor)?;
                let sent_message = envelope.message.clone();
                let (revision, outcome) = self.store.mutate(
                    "message.sent",
                    &json!({ "message_id": stable_message_id, "kind": kind }),
                    now_ms()?,
                    |state| apply_envelope_with_archive(&self.store, state, envelope.clone()),
                )?;
                let wake = self.wake_delivery_target_after_commit(
                    &stable_message_id,
                    &format!(
                        "New durable AGSV `{kind}` message `{stable_message_id}` is waiting in your inbox."
                    ),
                )?;
                return Ok(json!({
                    "message_id": stable_message_id,
                    "message": sent_message,
                    "outcome": apply_name(outcome),
                    "revision": revision,
                    "wake_deferred": wake["status"] == "deferred",
                    "wake": wake,
                }));
            }
            let requested_target = args
                .to
                .as_deref()
                .map(|value| resolve_target(&supervisor, value))
                .transpose()?;
            let request_id = args
                .request
                .as_deref()
                .map(|value| RequestId::new(value.to_owned()).map_err(ControlError::protocol))
                .transpose()?;
            let (message, target) = match kind.as_str() {
                "progress" => {
                    let target = assert_target(
                        requested_target.as_ref(),
                        MessageTarget::Primary,
                        "progress",
                    )?;
                    (
                        Message::Progress(ProgressUpdate {
                            summary: args.required_body(&kind)?.to_owned(),
                            percent_complete: None,
                            evidence: Vec::new(),
                        }),
                        target,
                    )
                }
                "blocker" => {
                    let target = assert_target(
                        requested_target.as_ref(),
                        MessageTarget::Primary,
                        "blocker",
                    )?;
                    (
                        Message::Blocker(BlockerNotice {
                            summary: args.required_body(&kind)?.to_owned(),
                            needs_primary: true,
                            evidence: Vec::new(),
                        }),
                        target,
                    )
                }
                "directive" => {
                    let target = requested_target.clone().ok_or_else(|| {
                        ControlError::invalid_request(
                            "message kind `directive` requires --to",
                        )
                    })?;
                    (
                        Message::Directive(PrimaryDirective {
                            decision: args.decision.clone().expect("validated decision"),
                            rationale: args.rationale.clone().expect("validated rationale"),
                        }),
                        target,
                    )
                }
                "consultation" | "consultation_request" => {
                    let target = required_team_target(requested_target.clone(), &kind)?;
                    let MessageTarget::Team(target_team_id) = &target else {
                        unreachable!("required_team_target returns a team")
                    };
                    (
                        Message::ConsultationRequest(ConsultationRequest {
                            consultation_id: message_id(&args.operation_id, "send"),
                            target_team_id: target_team_id.clone(),
                            subject: args
                                .subject
                                .clone()
                                .unwrap_or_else(|| "cross-team consultation".to_owned()),
                            question: args.required_body(&kind)?.to_owned(),
                            evidence: Vec::new(),
                        }),
                        target,
                    )
                }
                "consultation_response" => {
                    let consultation_id = MessageId::new(
                        args.consultation_id
                            .clone()
                            .expect("validated consultation id"),
                    )
                    .map_err(ControlError::protocol)?;
                    let consultation = supervisor.delivery(&consultation_id).ok_or_else(|| {
                        ControlError::not_found("consultation", consultation_id.as_str())
                    })?;
                    let consultation_message = self
                        .store
                        .message_body(&consultation_id, &consultation.payload_digest)?;
                    let Message::ConsultationRequest(request) = &consultation_message else {
                        return Err(ControlError::invalid_request(format!(
                            "--consultation-id `{consultation_id}` does not identify a consultation_request"
                        )));
                    };
                    let responding_team_id = sender.team_id.clone().ok_or_else(|| {
                        ControlError::invalid_request(
                            "consultation_response requires an authenticated implementation actor",
                        )
                    })?;
                    if responding_team_id != request.target_team_id {
                        return Err(ControlError::invalid_request(format!(
                            "authenticated actor team `{responding_team_id}` was not asked to answer consultation `{consultation_id}`"
                        )));
                    }
                    let requester = supervisor
                        .actor(&consultation.envelope.sender.actor_id)
                        .ok_or_else(|| {
                            ControlError::not_found(
                                "consultation requester",
                                consultation.envelope.sender.actor_id.as_str(),
                            )
                        })?;
                    let derived_target = if requester
                        .has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
                        && requester.team_id.is_none()
                    {
                        MessageTarget::Primary
                    } else {
                        MessageTarget::Actor(requester.actor_id.clone())
                    };
                    let target = assert_target(
                        requested_target.as_ref(),
                        derived_target,
                        "consultation_response",
                    )?;
                    (
                        Message::ConsultationResponse(ConsultationResponse {
                            consultation_id,
                            responding_team_id,
                            response: args.required_body(&kind)?.to_owned(),
                            evidence: Vec::new(),
                        }),
                        target,
                    )
                }
                "dependency_notice" => {
                    let blocked_request_id = request_id
                        .clone()
                        .expect("validated blocked request context");
                    let depends_on_request_id = RequestId::new(
                        args.depends_on_request
                            .clone()
                            .expect("validated dependency request"),
                    )
                    .map_err(ControlError::protocol)?;
                    let dependency = supervisor.request(&depends_on_request_id).ok_or_else(|| {
                        ControlError::not_found("request", depends_on_request_id.as_str())
                    })?;
                    let provider_team_id = dependency.team_id.clone();
                    let target = assert_target(
                        requested_target.as_ref(),
                        MessageTarget::Team(provider_team_id.clone()),
                        "dependency_notice",
                    )?;
                    (
                        Message::DependencyNotice(DependencyNotice {
                            blocked_request_id,
                            depends_on_request_id,
                            provider_team_id,
                            description: args.required_body(&kind)?.to_owned(),
                        }),
                        target,
                    )
                }
                "conflict_notice" => {
                    let target = required_team_target(requested_target.clone(), &kind)?;
                    let MessageTarget::Team(other_team_id) = &target else {
                        unreachable!("required_team_target returns a team")
                    };
                    (
                        Message::ConflictNotice(ConflictNotice {
                            other_team_id: other_team_id.clone(),
                            resources: args.resources.clone(),
                            description: args.required_body(&kind)?.to_owned(),
                        }),
                        target,
                    )
                }
                "handoff_offer" => {
                    let id = request_id.clone().expect("validated request context");
                    let item = supervisor
                        .request(&id)
                        .ok_or_else(|| ControlError::not_found("request", id.as_str()))?;
                    let target = required_team_target(requested_target.clone(), &kind)?;
                    let MessageTarget::Team(to_team_id) = &target else {
                        unreachable!("required_team_target returns a team")
                    };
                    (
                        Message::HandoffOffer(HandoffOffer {
                            handoff_id: handoff_id(&args.operation_id),
                            request_id: id,
                            from_team_id: item.team_id.clone(),
                            to_team_id: to_team_id.clone(),
                            candidate: item.candidate.clone(),
                            reason: args.required_body(&kind)?.to_owned(),
                        }),
                        target,
                    )
                }
                "handoff_acceptance" => {
                    let id = HandoffId::new(
                        args.handoff_id
                            .clone()
                            .expect("validated handoff transaction"),
                    )
                    .map_err(ControlError::protocol)?;
                    let pending = supervisor
                        .snapshot()
                        .pending_handoffs
                        .into_iter()
                        .find(|pending| pending.offer.handoff_id == id)
                        .ok_or_else(|| ControlError::not_found("handoff", id.as_str()))?;
                    let target = assert_target(
                        requested_target.as_ref(),
                        MessageTarget::Team(pending.offer.from_team_id.clone()),
                        "handoff_acceptance",
                    )?;
                    (
                        Message::HandoffAcceptance(HandoffAcceptance {
                            handoff_id: id,
                            request_id: pending.offer.request_id,
                            from_team_id: pending.offer.from_team_id,
                            to_team_id: pending.offer.to_team_id,
                            accepted_by: sender.actor_ref(),
                        }),
                        target,
                    )
                }
                "qa_result" => {
                    let id = request_id.clone().expect("validated request context");
                    let item = supervisor
                        .request(&id)
                        .ok_or_else(|| ControlError::not_found("request", id.as_str()))?;
                    let candidate = item.candidate.clone().ok_or_else(|| {
                        ControlError::invalid_request("qa_result requires a current candidate")
                    })?;
                    let outcome = match args.outcome.as_deref() {
                        Some("passed") => QaOutcome::Passed,
                        Some("failed") => QaOutcome::Failed,
                        _ => unreachable!("validated QA outcome"),
                    };
                    let target = assert_target(
                        requested_target.as_ref(),
                        MessageTarget::Primary,
                        "qa_result",
                    )?;
                    (
                        Message::QaResult(QaResult {
                            candidate,
                            outcome,
                            summary: args.required_body(&kind)?.to_owned(),
                            evidence: Vec::new(),
                        }),
                        target,
                    )
                }
                "integration_complete" => {
                    let id = request_id.clone().expect("validated request context");
                    let item = supervisor
                        .request(&id)
                        .ok_or_else(|| ControlError::not_found("request", id.as_str()))?;
                    let authorization = item.integration_authorization.clone().ok_or_else(|| {
                        ControlError::invalid_request(
                            "integration_complete requires durable integration authorization",
                        )
                    })?;
                    let assignment = item.assignment.as_ref().ok_or_else(|| {
                        ControlError::invalid_request("integration request is unassigned")
                    })?;
                    let target = assert_target(
                        requested_target.as_ref(),
                        MessageTarget::Actor(assignment.actor.actor_id.clone()),
                        "integration_complete",
                    )?;
                    (
                        Message::IntegrationComplete(IntegrationComplete {
                            decision_id: authorization.decision_id,
                            candidate: authorization.candidate,
                            evidence: Vec::new(),
                        }),
                        target,
                    )
                }
                "fix_request" => {
                    let id = request_id.as_ref().ok_or_else(|| {
                        ControlError::invalid_request("fix_request requires --request")
                    })?;
                    let item = supervisor
                        .request(id)
                        .ok_or_else(|| ControlError::not_found("request", id.as_str()))?;
                    let candidate = item.candidate.clone().ok_or_else(|| {
                        ControlError::invalid_request("request has no candidate")
                    })?;
                    let decision = item.decision.as_ref().ok_or_else(|| {
                        ControlError::invalid_request("request has no rejected decision")
                    })?;
                    let assignment = item.assignment.as_ref().ok_or_else(|| {
                        ControlError::invalid_request("request is unassigned")
                    })?;
                    let target = assert_target(
                        requested_target.as_ref(),
                        MessageTarget::Actor(assignment.actor.actor_id.clone()),
                        "fix_request",
                    )?;
                    (
                        Message::FixRequest(FixRequest {
                            decision_id: decision.decision_id.clone(),
                            candidate,
                            instructions: args.required_body(&kind)?.to_owned(),
                        }),
                        target,
                    )
                }
                _ => {
                    return Err(ControlError::unsupported(
                        "message.send",
                        "supported kinds are progress, blocker, directive, consultation_request, consultation_response, dependency_notice, conflict_notice, handoff_offer, handoff_acceptance, qa_result, integration_complete, and fix_request",
                    ));
                }
            };
            let envelope = if let Message::HandoffAcceptance(acceptance) = &message {
                let item = supervisor.request(&acceptance.request_id).ok_or_else(|| {
                    ControlError::not_found("request", acceptance.request_id.as_str())
                })?;
                let assignment_epoch = supervisor
                    .snapshot()
                    .pending_handoffs
                    .into_iter()
                    .find(|pending| pending.offer.handoff_id == acceptance.handoff_id)
                    .map(|pending| pending.assignment_epoch)
                    .ok_or_else(|| {
                        ControlError::not_found("handoff", acceptance.handoff_id.as_str())
                    })?;
                make_envelope(
                    &supervisor,
                    sender.actor_ref(),
                    target,
                    Some(acceptance.to_team_id.clone()),
                    Some(item.run_id.clone()),
                    Some(acceptance.request_id.clone()),
                    Some(assignment_epoch),
                    message,
                    message_id(&args.operation_id, "send"),
                )?
            } else if let Some(id) = &request_id {
                request_envelope(
                    &supervisor,
                    id,
                    sender.actor_ref(),
                    target,
                    message,
                    message_id(&args.operation_id, "send"),
                )?
                .0
            } else {
                let context_team = match sender.team_id.clone() {
                    Some(team_id) => Some(team_id),
                    None => args
                        .team
                        .as_deref()
                        .map(|value| TeamId::new(value.to_owned()).map_err(ControlError::protocol))
                        .transpose()?,
                };
                make_envelope(
                    &supervisor,
                    sender.actor_ref(),
                    target,
                    context_team,
                    None,
                    None,
                    None,
                    message,
                    message_id(&args.operation_id, "send"),
                )?
            };
            Self::ensure_directive_delivery_capacity(&supervisor, &envelope)?;
            let message_id = envelope.message_id.clone();
            let sent_message = envelope.message.clone();
            let (revision, outcome) = self.store.mutate(
                "message.sent",
                &json!({ "message_id": message_id, "kind": kind }),
                now_ms()?,
                |state| apply_envelope_with_archive(&self.store, state, envelope.clone()),
            )?;
            let wake = self.wake_delivery_target_after_commit(
                &message_id,
                &format!(
                    "New durable AGSV `{kind}` message `{message_id}` is waiting in your inbox."
                ),
            )?;
            Ok(json!({
                "message_id": message_id,
                "message": sent_message,
                "outcome": apply_name(outcome),
                "revision": revision,
                "wake_deferred": wake["status"] == "deferred",
                "wake": wake,
            }))
        })
    }
    fn message_inbox(&self, request: &Value) -> Result<Value, ControlError> {
        let args: MessageInboxArgs = decode(request)?;
        let authenticated = self.resolve_actor_allow_stopped(args.actor.as_deref())?;
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&authenticated.actor_id)
            .filter(|actor| actor.epoch == authenticated.epoch)
            .ok_or_else(|| superseded_binding(&supervisor, &authenticated.actor_ref()))?;
        let actor_ref = actor.actor_ref();
        let deliveries = if args.include_acked {
            let mut deliveries = supervisor.snapshot().deliveries;
            deliveries.extend(self.store.archived_deliveries()?);
            deliveries.sort_by(|left, right| {
                left.envelope
                    .sent_at
                    .cmp(&right.envelope.sent_at)
                    .then_with(|| left.envelope.message_id.cmp(&right.envelope.message_id))
            });
            deliveries
                .into_iter()
                .filter(|delivery| {
                    delivery_visible_to_exact_actor_generation(delivery, actor, &supervisor)
                })
                .map(|delivery| self.hydrated_delivery_value(&delivery))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            readable_message_ids(&supervisor, actor, &actor_ref)?
                .into_iter()
                .map(|message_id| {
                    let delivery = supervisor
                        .delivery(&message_id)
                        .ok_or_else(|| ControlError::not_found("delivery", message_id.as_str()))?;
                    self.hydrated_delivery_record_value(delivery)
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        Ok(json!({ "actor": actor_ref, "deliveries": deliveries }))
    }
    fn message_ack(&self, request: &Value) -> Result<Value, ControlError> {
        let args: MessageAckArgs = decode(request)?;
        self.idempotent("message.ack", request, &args.operation_id, || {
            let message_id = MessageId::new(args.id.clone()).map_err(ControlError::protocol)?;
            let actor = self.resolve_actor(args.actor.as_deref())?;
            let acknowledgement = Acknowledgement {
                workspace_id: self.identity.workspace_id().clone(),
                message_id: message_id.clone(),
                actor: actor.actor_ref(),
                acknowledged_at: TimestampMillis(now_ms()?),
            };
            let (revision, outcome) = self.store.mutate(
                "message.acknowledged",
                &json!({ "message_id": message_id, "actor_id": actor.actor_id }),
                now_ms()?,
                |state| {
                    acknowledge_with_archive(&self.store, state, acknowledgement.clone())
                },
            )?;
            Ok(json!({ "message_id": message_id, "outcome": ack_name(outcome), "revision": revision }))
        })
    }
    fn decision_list(&self, request: &Value) -> Result<Value, ControlError> {
        query_decision_report(&self.store, request)
    }
    #[allow(clippy::too_many_lines)]
    fn decision_submit(&self, request: &Value) -> Result<Value, ControlError> {
        let args: DecisionSubmitArgs = decode(request)?;
        self.idempotent("decision.submit", request, &args.operation_id, || {
            let request_id =
                RequestId::new(args.request.clone()).map_err(ControlError::protocol)?;
            let sha = GitSha::new(args.candidate_sha).map_err(ControlError::protocol)?;
            let (loaded_revision, supervisor, _) = self.store.load()?;
            let primary = active_primary_actor(&supervisor)?;
            let item = supervisor
                .request(&request_id)
                .ok_or_else(|| ControlError::not_found("request", &args.request))?;
            let candidate = item.candidate.clone().ok_or_else(|| {
                ControlError::invalid_request("request has no candidate ready for review")
            })?;
            if candidate.sha != sha {
                return Err(ControlError::new(
                    "candidate_mismatch",
                    "decision candidate SHA does not match the durable candidate",
                ));
            }
            let decision_id = DecisionId::new(stable_id("decision", &args.operation_id))
                .map_err(ControlError::protocol)?;
            let verdict = match args.decision.as_str() {
                "accepted" => ReviewVerdict::Accepted,
                "rejected" => ReviewVerdict::Rejected,
                _ => {
                    return Err(ControlError::invalid_request(
                        "decision must be accepted or rejected",
                    ));
                }
            };
            if args.close_team && verdict != ReviewVerdict::Accepted {
                return Err(ControlError::invalid_request(
                    "--close-team is valid only for an accepted decision",
                ));
            }
            let team_id = item.team_id.clone();
            let rationale = args.summary.clone().unwrap_or_else(|| enum_name(verdict));
            let proposed_decision = ReviewDecision {
                decision_id: decision_id.clone(),
                candidate: candidate.clone(),
                verdict,
                reviewer: primary.clone(),
                policy_revision: supervisor.policy_revision(),
                rationale: rationale.clone(),
                evidence: Vec::new(),
            };
            let stored_close_decision = if args.close_team {
                item.decision
                    .as_ref()
                    .map(|stored| {
                        let message = self
                            .store
                            .message_body(&stored.message_id, &stored.payload_digest)?;
                        let Message::ReviewDecision(stored) = message else {
                            return Err(ControlError::new(
                                "decision_body_mismatch",
                                "the committed close-team decision reference does not contain a review decision",
                            ));
                        };
                        Ok(stored)
                    })
                    .transpose()?
                    .filter(|stored| {
                        stored.decision_id == decision_id
                            && stored.candidate == candidate
                            && stored.verdict == verdict
                            && stored.rationale == rationale
                            && stored.evidence.is_empty()
                    })
            } else {
                None
            };
            let stored_close_authorization =
                stored_close_decision
                    .as_ref()
                    .and_then(|stored_decision| {
                        item.integration_authorization.as_ref().filter(|authorization| {
                            authorization.decision_id == decision_id
                                && authorization.candidate == candidate
                                && authorization.authorized_by == stored_decision.reviewer
                        })
                    });
            let committed_close_replay =
                stored_close_decision.is_some() && stored_close_authorization.is_some();
            let decision = stored_close_decision.unwrap_or(proposed_decision);
            let target_actor_id = item
                .assignment
                .as_ref()
                .ok_or_else(|| ControlError::invalid_request("request is unassigned"))?
                .actor
                .actor_id
                .clone();
            let target = MessageTarget::Actor(target_actor_id.clone());
            let (review_envelope, _) = request_envelope(
                &supervisor,
                &request_id,
                primary.clone(),
                target.clone(),
                Message::ReviewDecision(decision.clone()),
                message_id(&args.operation_id, "decision"),
            )?;
            let authorization = stored_close_authorization.cloned().or_else(|| {
                (verdict == ReviewVerdict::Accepted).then(|| IntegrationAuthorization {
                    decision_id: decision_id.clone(),
                    candidate: candidate.clone(),
                    authorized_by: primary.clone(),
                })
            });
            if args.close_team && !committed_close_replay {
                let team = supervisor
                    .team(&team_id)
                    .ok_or_else(|| ControlError::not_found("team", team_id.as_str()))?;
                if matches!(team.status, TeamStatus::Closed | TeamStatus::Retired) {
                    return Err(ControlError::new(
                        "team_closed",
                        "a closed or retired team cannot receive another review decision",
                    )
                    .with_details(json!({ "team_id": team_id, "status": team.status })));
                }
                let other_blocking = team_close_blocking_request_ids(&supervisor, &team_id)
                    .into_iter()
                    .filter(|blocking| blocking != &request_id)
                    .collect::<Vec<_>>();
                if !other_blocking.is_empty() {
                    return Err(team_close_blocked(&team_id, &other_blocking));
                }
            }
            let revision = if committed_close_replay {
                loaded_revision
            } else {
                self.store
                    .mutate(
                        "decision.submitted",
                        &json!({
                            "request_id": request_id,
                            "decision_id": decision.decision_id,
                            "candidate_sha": decision.candidate.sha,
                            "verdict": decision.verdict,
                            "close_team": args.close_team,
                            "team_id": team_id,
                        }),
                        now_ms()?,
                        |state| {
                            apply_envelope_with_archive(
                                &self.store,
                                state,
                                review_envelope.clone(),
                            )?;
                            if let Some(authorization) = &authorization {
                                let auth_envelope = request_envelope(
                                    state,
                                    &request_id,
                                    primary.clone(),
                                    target.clone(),
                                    Message::IntegrationAuthorization(authorization.clone()),
                                    message_id(&args.operation_id, "authorization"),
                                )?
                                .0;
                                apply_envelope_with_archive(&self.store, state, auth_envelope)?;
                            }
                            if args.close_team {
                                let blocking = team_close_blocking_request_ids(state, &team_id);
                                if !blocking.is_empty() {
                                    return Err(team_close_blocked(&team_id, &blocking));
                                }
                                let blocking_messages =
                                    state.team_close_blocking_message_ids(&team_id);
                                if !blocking_messages.is_empty() {
                                    return Err(team_close_unacknowledged_actions(
                                        &team_id,
                                        &blocking_messages,
                                    ));
                                }
                                let team = state.team(&team_id).ok_or_else(|| {
                                    ControlError::not_found("team", team_id.as_str())
                                })?;
                                if !matches!(team.status, TeamStatus::Closing | TeamStatus::Closed)
                                {
                                    state
                                        .set_team_status(&team_id, TeamStatus::Closing)
                                        .map_err(ControlError::core)?;
                                }
                            }
                            Ok(())
                        },
                    )?
                    .0
            };
            let wake = self.wake_request_target_after_commit(
                &request_id,
                &target,
                &format!(
                    "AGSV review decision `{decision_id}` for request `{request_id}` is waiting in your inbox."
                ),
            )?;
            let team_close = args
                .close_team
                .then(|| self.reconcile_closing_team(&team_id))
                .transpose()?;
            if args.close_team
                && self.debug_crash_requested(
                    "AGSV_DEV_FAIL_AFTER_DECISION_CLOSE_COMMIT",
                    "decision_close_commit",
                )
            {
                return Err(ControlError::new(
                    "simulated_decision_close_crash",
                    "debug-only failure after the accepted decision closed its team",
                ));
            }
            Ok(json!({
                "decision": decision,
                "integration_authorization": authorization,
                "team_close": team_close,
                "revision": revision,
                "wake_deferred": wake["status"] == "deferred",
                "wake": wake,
            }))
        })
    }

    // Keep the exact-candidate checks, durable state transitions, crash seams,
    // and checkout recovery in one auditable orchestration pipeline.
    #[allow(clippy::too_many_lines)]
    fn review_begin(&self, request: &Value) -> Result<Value, ControlError> {
        let args: ReviewBeginArgs = decode(request)?;
        self.idempotent("review.begin", request, &args.operation_id, || {
            let request_id =
                RequestId::new(args.request.clone()).map_err(ControlError::protocol)?;
            let candidate_sha =
                GitSha::new(args.candidate_sha.clone()).map_err(ControlError::protocol)?;
            let (domain_revision, supervisor, _) = self.store.load()?;
            let item = supervisor
                .request(&request_id)
                .ok_or_else(|| ControlError::not_found("request", request_id.as_str()))?;
            if item.status != RequestStatus::CandidateReady {
                return Err(ControlError::new(
                    "candidate_not_ready",
                    "review sessions may begin only for a request awaiting review",
                )
                .with_details(json!({
                    "request_id": request_id,
                    "request_status": item.status,
                })));
            }
            let candidate = item.candidate.as_ref().ok_or_else(|| {
                ControlError::new(
                    "candidate_not_ready",
                    "request has no current candidate ready for review",
                )
            })?;
            if candidate.sha != candidate_sha {
                return Err(ControlError::new(
                    "candidate_mismatch",
                    "review candidate SHA does not match the request's current candidate",
                )
                .with_details(json!({
                    "request_id": request_id,
                    "candidate_sha": candidate_sha,
                    "current_candidate_sha": candidate.sha,
                })));
            }

            let mut stored = if let Some(existing) = self
                .store
                .review_session_for_candidate(&request_id, &candidate_sha)?
            {
                existing
            } else {
                let tree = self.review.resolve_tree(&candidate_sha)?;
                let plan = self.review.plan(supervisor.policy_revision())?;
                let session_id = ReviewSessionId::new(stable_id(
                    "review",
                    &format!("{request_id}:{candidate_sha}"),
                ))
                .map_err(ControlError::protocol)?;
                let checkout_path = self.review.checkout_path(&session_id);
                let checkout_path = checkout_path.to_str().ok_or_else(|| {
                    ControlError::new(
                        "unsafe_review_path",
                        "review checkout path must be valid UTF-8",
                    )
                })?;
                let created_at = TimestampMillis(now_ms()?);
                let session = ReviewSession {
                    session_id,
                    workspace_id: self.identity.workspace_id().clone(),
                    request_id: request_id.clone(),
                    tree,
                    checkout_path: checkout_path.to_owned(),
                    plan,
                    state: ReviewSessionState::new(
                        ReviewSessionStatus::Preparing,
                        ReviewRecoveryState::NotRequired,
                    )
                    .map_err(ControlError::protocol)?,
                    created_at,
                    updated_at: created_at,
                };
                self.store
                    .begin_review_session(&args.operation_id, domain_revision, &session)?
            };

            if stored.session.state.status == ReviewSessionStatus::Ready
                && self.review.verify_checkout(&stored.session).is_err()
            {
                let invalid = ReviewSessionState::new(
                    ReviewSessionStatus::Invalid,
                    ReviewRecoveryState::RecreateRequired,
                )
                .map_err(ControlError::protocol)?;
                stored = self.store.transition_review_session(
                    &stored.session.session_id,
                    stored.session.state,
                    invalid,
                    Some("durable checkout identity no longer matches"),
                    TimestampMillis(now_ms()?),
                )?;
            }
            if stored.session.state.status == ReviewSessionStatus::Invalid {
                let preparing = ReviewSessionState::new(
                    ReviewSessionStatus::Preparing,
                    ReviewRecoveryState::NotRequired,
                )
                .map_err(ControlError::protocol)?;
                stored = self.store.transition_review_session(
                    &stored.session.session_id,
                    stored.session.state,
                    preparing,
                    None,
                    TimestampMillis(now_ms()?),
                )?;
            }
            if self.debug_crash_requested(
                "AGSV_DEV_FAIL_AFTER_REVIEW_BEGIN_INTENT",
                "review_begin_intent",
            ) {
                return Err(ControlError::new(
                    "injected_crash",
                    "injected crash after durable review begin intent",
                ));
            }
            if stored.session.state.status == ReviewSessionStatus::Preparing {
                if let Err(error) = self.review.prepare_checkout(&stored.session) {
                    let invalid = ReviewSessionState::new(
                        ReviewSessionStatus::Invalid,
                        ReviewRecoveryState::RecreateRequired,
                    )
                    .map_err(ControlError::protocol)?;
                    let _ = self.store.transition_review_session(
                        &stored.session.session_id,
                        stored.session.state,
                        invalid,
                        Some(&format!("{}: {}", error.code, error.message)),
                        TimestampMillis(now_ms()?),
                    );
                    return Err(error);
                }
                if self
                    .debug_crash_requested("AGSV_DEV_FAIL_AFTER_REVIEW_CHECKOUT", "review_checkout")
                {
                    return Err(ControlError::new(
                        "injected_crash",
                        "injected crash after exact review checkout creation",
                    ));
                }
                let ready = ReviewSessionState::new(
                    ReviewSessionStatus::Ready,
                    ReviewRecoveryState::NotRequired,
                )
                .map_err(ControlError::protocol)?;
                stored = self.store.transition_review_session(
                    &stored.session.session_id,
                    stored.session.state,
                    ready,
                    None,
                    TimestampMillis(now_ms()?),
                )?;
            }
            self.review.verify_checkout(&stored.session)?;
            Ok(json!({
                "session": stored.session,
                "checkout": {
                    "isolated_object_database": true,
                    "source_permissions_read_only": true,
                    "tree_identity_verified": true,
                },
            }))
        })
    }

    #[allow(clippy::too_many_lines)]
    fn review_verify(&self, request: &Value) -> Result<Value, ControlError> {
        let args: ReviewVerifyArgs = decode(request)?;
        self.idempotent("review.verify", request, &args.operation_id, || {
            let session_id =
                ReviewSessionId::new(args.session.clone()).map_err(ControlError::protocol)?;
            let mut stored = self
                .store
                .review_session(&session_id)?
                .ok_or_else(|| ControlError::not_found("review session", session_id.as_str()))?;
            if stored.session.state.status != ReviewSessionStatus::Ready {
                return Err(ControlError::new(
                    "review_session_not_ready",
                    "review verification requires a ready exact-candidate session",
                ));
            }
            self.review.verify_checkout(&stored.session)?;
            let sandbox = self.review.sandbox_name();

            let existing_operation = self
                .store
                .review_verification_attempts_for_operation(&session_id, &args.operation_id)?;
            if let Some(terminal) = existing_operation
                .iter()
                .find(|record| record.attempt.status != ReviewAttemptStatus::Running)
            {
                if stored.session.state.recovery == ReviewRecoveryState::ResumeRequired {
                    let recovered = ReviewSessionState::new(
                        ReviewSessionStatus::Ready,
                        ReviewRecoveryState::NotRequired,
                    )
                    .map_err(ControlError::protocol)?;
                    stored = self.store.transition_review_session(
                        &session_id,
                        stored.session.state,
                        recovered,
                        stored.last_error.as_deref(),
                        TimestampMillis(now_ms()?),
                    )?;
                }
                return self.review_verification_result(
                    &stored.session,
                    &terminal.attempt,
                    sandbox,
                );
            }

            if let Some(running) = existing_operation.first() {
                let results = self
                    .store
                    .review_check_results(&session_id, review_record_limit(&stored.session)?)?
                    .into_iter()
                    .filter(|result| result.attempt_sequence == running.attempt.attempt_sequence)
                    .collect::<Vec<_>>();
                return self.interrupt_review_attempt(
                    &args.operation_id,
                    &stored.session,
                    &running.attempt,
                    &results,
                    "the prior controller execution ended without terminal evidence; retry with a new operation id",
                    sandbox,
                );
            }

            let attempt_sequence = self.store.next_review_attempt_sequence(&session_id)?;
            let started_at = TimestampMillis(now_ms()?);
            let running = ReviewVerificationAttempt {
                record_id: ReviewAttemptRecordId::new(stable_id(
                    "review-attempt-running",
                    &format!("{session_id}:{}", args.operation_id),
                ))
                .map_err(ControlError::protocol)?,
                workspace_id: stored.session.workspace_id.clone(),
                session_id: session_id.clone(),
                request_id: stored.session.request_id.clone(),
                candidate_sha: stored.session.tree.candidate_sha.clone(),
                attempt_sequence,
                plan: stored.session.plan.identity.clone(),
                status: ReviewAttemptStatus::Running,
                started_at,
                finished_at: None,
                recorded_at: started_at,
            };
            stored
                .session
                .validate_attempt_record(&running)
                .map_err(ControlError::protocol)?;
            self.store
                .append_review_verification_attempt(&args.operation_id, &running)?;
            if stored.session.state.recovery == ReviewRecoveryState::NotRequired {
                let recovering = ReviewSessionState::new(
                    ReviewSessionStatus::Ready,
                    ReviewRecoveryState::ResumeRequired,
                )
                .map_err(ControlError::protocol)?;
                stored = self.store.transition_review_session(
                    &session_id,
                    stored.session.state,
                    recovering,
                    None,
                    TimestampMillis(now_ms()?),
                )?;
            }
            if self.debug_crash_requested(
                "AGSV_DEV_FAIL_AFTER_REVIEW_VERIFY_INTENT",
                "review_verify_intent",
            ) {
                return Err(ControlError::new(
                    "injected_crash",
                    "injected crash after durable review verification intent",
                ));
            }

            let mut results = Vec::new();
            let artifact_budget = ReviewAttemptBudget::new();

            for check in &stored.session.plan.checks {
                let variants = std::iter::once(ReviewExecutionVariant::Normal).chain(
                    (!check.required_absent_binaries.is_empty())
                        .then_some(ReviewExecutionVariant::RequiredAbsent),
                );
                for variant in variants {
                    if self.debug_crash_requested(
                        "AGSV_DEV_FAIL_BEFORE_REVIEW_CHECK",
                        "review_check_intent",
                    ) {
                        return Err(ControlError::new(
                            "injected_crash",
                            "injected crash before control-plane review check execution",
                        ));
                    }
                    let fail_after_child_spawn = self.debug_crash_requested(
                        "AGSV_DEV_FAIL_AFTER_REVIEW_CHILD_SPAWN",
                        "review_child_spawned",
                    );
                    let evidence = match self.review.execute_check(
                        &stored.session,
                        running.attempt_sequence,
                        check,
                        variant,
                        &artifact_budget,
                        fail_after_child_spawn,
                    ) {
                        Ok(evidence) => evidence,
                        Err(error) if error.code == "injected_crash" => return Err(error),
                        Err(error) => {
                            return self.interrupt_review_attempt(
                                &args.operation_id,
                                &stored.session,
                                &running,
                                &results,
                                &format!("{}: {}", error.code, error.message),
                                sandbox,
                            );
                        }
                    };
                    if self.debug_crash_requested(
                        "AGSV_DEV_FAIL_AFTER_REVIEW_CHECK_SPOOL",
                        "review_check_spooled",
                    ) {
                        return Err(ControlError::new(
                            "injected_crash",
                            "injected crash after review output was durably spooled",
                        ));
                    }
                    self.store.append_review_environment_record(
                        &evidence.path_digest,
                        &evidence.environment,
                    )?;
                    if self.debug_crash_requested(
                        "AGSV_DEV_FAIL_AFTER_REVIEW_ENVIRONMENT",
                        "review_environment_committed",
                    ) {
                        return Err(ControlError::new(
                            "injected_crash",
                            "injected crash after durable review environment evidence",
                        ));
                    }
                    let result = self.store.append_review_check_result(&evidence.result)?;
                    results.push(result);
                    if self.debug_crash_requested(
                        "AGSV_DEV_FAIL_AFTER_REVIEW_CHECK_RESULT",
                        "review_check_result_committed",
                    ) {
                        return Err(ControlError::new(
                            "injected_crash",
                            "injected crash after durable review check result",
                        ));
                    }
                }
            }

            let status = if results
                .iter()
                .all(|result| result.outcome == ReviewCheckOutcome::Passed)
            {
                ReviewAttemptStatus::Passed
            } else {
                ReviewAttemptStatus::Failed
            };
            let finished_at = TimestampMillis(now_ms()?);
            let terminal = ReviewVerificationAttempt {
                record_id: ReviewAttemptRecordId::new(stable_id(
                    "review-attempt-terminal",
                    &format!("{session_id}:{}", args.operation_id),
                ))
                .map_err(ControlError::protocol)?,
                status,
                finished_at: Some(finished_at),
                recorded_at: finished_at,
                ..running
            };
            stored
                .session
                .validate_attempt_results(&terminal, &results)
                .map_err(ControlError::protocol)?;
            self.store
                .append_review_verification_attempt(&args.operation_id, &terminal)?;
            if self.debug_crash_requested(
                "AGSV_DEV_FAIL_AFTER_REVIEW_TERMINAL",
                "review_terminal_committed",
            ) {
                return Err(ControlError::new(
                    "injected_crash",
                    "injected crash after durable terminal review result",
                ));
            }
            let recovered = ReviewSessionState::new(
                ReviewSessionStatus::Ready,
                ReviewRecoveryState::NotRequired,
            )
            .map_err(ControlError::protocol)?;
            stored = self.store.transition_review_session(
                &session_id,
                stored.session.state,
                recovered,
                None,
                TimestampMillis(now_ms()?),
            )?;
            self.review_verification_result(&stored.session, &terminal, sandbox)
        })
    }

    fn review_show(&self, request: &Value) -> Result<Value, ControlError> {
        let args: ReviewShowArgs = decode(request)?;
        if let Some(session_id) = args.session {
            let session_id = ReviewSessionId::new(session_id).map_err(ControlError::protocol)?;
            let records = self.store.review_session_records(&session_id, args.limit)?;
            return Ok(json!({ "reviews": [records], "limit": args.limit }));
        }
        let candidate_sha = args.candidate_sha.ok_or_else(|| {
            ControlError::invalid_request("review.show requires session or candidate_sha")
        })?;
        let candidate_sha = GitSha::new(candidate_sha).map_err(ControlError::protocol)?;
        let sessions = self
            .store
            .review_sessions_for_candidate(&candidate_sha, args.limit)?;
        let mut reviews = Vec::with_capacity(sessions.len());
        for session in sessions {
            reviews.push(
                self.store
                    .review_session_records(&session.session.session_id, args.limit)?,
            );
        }
        Ok(json!({
            "candidate_sha": candidate_sha,
            "reviews": reviews,
            "limit": args.limit,
        }))
    }

    fn review_verification_result(
        &self,
        session: &ReviewSession,
        terminal: &ReviewVerificationAttempt,
        sandbox: &str,
    ) -> Result<Value, ControlError> {
        let results = self
            .store
            .review_check_results(&session.session_id, review_record_limit(session)?)?
            .into_iter()
            .filter(|result| result.attempt_sequence == terminal.attempt_sequence)
            .collect::<Vec<_>>();
        session
            .validate_attempt_results(terminal, &results)
            .map_err(ControlError::protocol)?;
        Ok(json!({
            "session_id": session.session_id,
            "candidate_sha": session.tree.candidate_sha,
            "tree_sha": session.tree.tree_sha,
            "attempt": terminal,
            "check_results": results,
            "sandbox": {
                "backend": sandbox,
                "source_write_boundary": if self.review.sandbox_enforced() {
                    "os_enforced"
                } else {
                    "not_enforced"
                },
                "process_containment": self.review.process_containment(),
            },
            "decision_gating": false,
        }))
    }

    fn interrupt_review_attempt(
        &self,
        operation_id: &str,
        session: &ReviewSession,
        running: &ReviewVerificationAttempt,
        results: &[agsv_protocol::ReviewCheckResult],
        reason: &str,
        sandbox: &str,
    ) -> Result<Value, ControlError> {
        let finished_at = TimestampMillis(now_ms()?);
        let terminal = ReviewVerificationAttempt {
            record_id: ReviewAttemptRecordId::new(stable_id(
                "review-attempt-terminal",
                &format!("{}:{operation_id}", session.session_id),
            ))
            .map_err(ControlError::protocol)?,
            status: ReviewAttemptStatus::Interrupted,
            finished_at: Some(finished_at),
            recorded_at: finished_at,
            ..running.clone()
        };
        session
            .validate_attempt_results(&terminal, results)
            .map_err(ControlError::protocol)?;
        self.store
            .append_review_verification_attempt(operation_id, &terminal)?;
        let recovered =
            ReviewSessionState::new(ReviewSessionStatus::Ready, ReviewRecoveryState::NotRequired)
                .map_err(ControlError::protocol)?;
        self.store.transition_review_session(
            &session.session_id,
            session.state,
            recovered,
            Some(reason),
            TimestampMillis(now_ms()?),
        )?;
        let mut result = self.review_verification_result(session, &terminal, sandbox)?;
        result["interruption_reason"] = json!(reason);
        Ok(result)
    }

    fn cancel_request(
        &self,
        operation: &str,
        request: &Value,
        operation_id: &str,
        request_id: &RequestId,
        reason: &str,
    ) -> Result<Value, ControlError> {
        self.idempotent(operation, request, operation_id, || {
            let (_, supervisor, _) = self.store.load()?;
            let primary = active_primary_actor(&supervisor)?;
            let item = supervisor
                .request(request_id)
                .ok_or_else(|| ControlError::not_found("request", request_id.as_str()))?;
            let target = MessageTarget::Actor(
                item.assignment
                    .as_ref()
                    .ok_or_else(|| ControlError::invalid_request("request is unassigned"))?
                    .actor
                    .actor_id
                    .clone(),
            );
            let (envelope, run_id) = request_envelope(
                &supervisor,
                request_id,
                primary,
                target.clone(),
                Message::Cancellation(Cancellation {
                    reason: reason.to_owned(),
                }),
                message_id(operation_id, "cancel"),
            )?;
            let (revision, outcome) = self.store.mutate(
                operation,
                &json!({ "request_id": request_id, "reason": reason }),
                now_ms()?,
                |state| apply_envelope_with_archive(&self.store, state, envelope.clone()),
            )?;
            let wake = self.wake_request_target_after_commit(
                request_id,
                &target,
                &format!("AGSV request `{request_id}` was cancelled; read your durable inbox."),
            )?;
            Ok(json!({
                "request_id": request_id,
                "run_id": run_id,
                "outcome": apply_name(outcome),
                "revision": revision,
                "wake_deferred": wake["status"] == "deferred",
                "wake": wake,
            }))
        })
    }
}

#[derive(Deserialize)]
struct StartArgs {
    #[serde(default)]
    foreground: bool,
}

#[derive(Deserialize)]
struct StopArgs {
    #[serde(default)]
    force: bool,
}

#[derive(Deserialize)]
struct EventsArgs {
    #[serde(default)]
    follow: bool,
    #[serde(default = "default_event_limit")]
    limit: u32,
}

#[derive(Deserialize)]
struct ContextArgs {
    #[serde(default)]
    bootstrap: bool,
    actor: Option<String>,
}

#[derive(Deserialize)]
struct IdArgs {
    id: String,
}

#[derive(Deserialize)]
struct MutationIdArgs {
    id: String,
    operation_id: String,
}

#[derive(Deserialize)]
struct ActorListArgs {
    team: Option<String>,
}

#[derive(Deserialize)]
struct TeamFilterArgs {
    team: Option<String>,
}

#[derive(Deserialize)]
struct RequestListArgs {
    team: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
struct TeamCreateArgs {
    name: String,
    profile: Option<String>,
    purpose: Option<String>,
    working_directory: Option<PathBuf>,
    #[serde(default)]
    adopt_working_directory: bool,
    #[serde(default = "default_orchestrators")]
    orchestrators: u16,
    operation_id: String,
}

#[derive(Deserialize)]
struct TeamCloseArgs {
    id: String,
    #[serde(default)]
    when_idle: bool,
    operation_id: String,
}

#[derive(Deserialize)]
struct TeamUpdateArgs {
    id: String,
    purpose: String,
    operation_id: String,
}

#[derive(Deserialize)]
struct ReasonedIdArgs {
    id: String,
    reason: Option<String>,
    operation_id: String,
}

#[derive(Deserialize)]
struct ShutdownArgs {
    actor: Option<String>,
    reason: Option<String>,
    operation_id: String,
}

#[derive(Deserialize)]
struct RunCreateArgs {
    team: String,
    request: Option<String>,
    operation_id: String,
}

#[derive(Deserialize)]
struct RequestCreateArgs {
    team: String,
    title: String,
    body: Option<String>,
    base_sha: Option<String>,
    operation_id: String,
}

#[derive(Deserialize)]
struct RequestClaimArgs {
    id: String,
    actor: Option<String>,
    operation_id: String,
}

#[derive(Deserialize)]
struct RequestBlockArgs {
    id: String,
    reason: String,
    operation_id: String,
}

#[derive(Deserialize)]
struct RequestCompleteArgs {
    id: String,
    candidate_sha: String,
    evidence: Option<String>,
    operation_id: String,
}

#[derive(Deserialize)]
struct MessageSendArgs {
    to: Option<String>,
    kind: String,
    body: Option<String>,
    team: Option<String>,
    request: Option<String>,
    decision: Option<String>,
    rationale: Option<String>,
    consultation_id: Option<String>,
    subject: Option<String>,
    depends_on_request: Option<String>,
    #[serde(default)]
    resources: Vec<String>,
    handoff_id: Option<String>,
    outcome: Option<String>,
    operation_id: String,
}

impl MessageSendArgs {
    fn validate_for(&self, kind: &str) -> Result<(), ControlError> {
        let kind = match kind {
            "consultation" => "consultation_request",
            value => value,
        };
        let allowed = match kind {
            "progress" | "blocker" | "fix_request" | "handoff_offer" => {
                &["--to", "--body", "--request"][..]
            }
            "consultation_request" => &["--to", "--body", "--team", "--subject"][..],
            "directive" => &["--to", "--team", "--request", "--decision", "--rationale"][..],
            "consultation_response" => &["--to", "--body", "--consultation-id"][..],
            "dependency_notice" => &["--to", "--body", "--request", "--depends-on-request"][..],
            "conflict_notice" => &["--to", "--body", "--resource"][..],
            "handoff_acceptance" => &["--to", "--handoff-id"][..],
            "qa_result" => &["--to", "--body", "--request", "--outcome"][..],
            "integration_complete" => &["--to", "--request"][..],
            _ => return Ok(()),
        };
        let present = [
            ("--to", self.to.is_some()),
            ("--body", self.body.is_some()),
            ("--team", self.team.is_some()),
            ("--request", self.request.is_some()),
            ("--decision", self.decision.is_some()),
            ("--rationale", self.rationale.is_some()),
            ("--consultation-id", self.consultation_id.is_some()),
            ("--subject", self.subject.is_some()),
            ("--depends-on-request", self.depends_on_request.is_some()),
            ("--resource", !self.resources.is_empty()),
            ("--handoff-id", self.handoff_id.is_some()),
            ("--outcome", self.outcome.is_some()),
        ];
        for (flag, is_present) in present {
            if is_present && !allowed.contains(&flag) {
                return Err(ControlError::invalid_request(format!(
                    "{flag} is not valid for message kind `{kind}`"
                )));
            }
        }

        let required = match kind {
            "progress" | "blocker" | "fix_request" => &["--body", "--request"][..],
            "handoff_offer" => &["--to", "--body", "--request"][..],
            "consultation_request" | "conflict_notice" => &["--to", "--body"][..],
            "directive" => &["--to", "--decision", "--rationale"][..],
            "consultation_response" => &["--body", "--consultation-id"][..],
            "dependency_notice" => &["--body", "--request", "--depends-on-request"][..],
            "handoff_acceptance" => &["--handoff-id"][..],
            "qa_result" => &["--body", "--request", "--outcome"][..],
            "integration_complete" => &["--request"][..],
            _ => &[][..],
        };
        for flag in required {
            let is_present = present
                .iter()
                .find_map(|(candidate, is_present)| (candidate == flag).then_some(*is_present))
                .unwrap_or(false);
            if !is_present {
                return Err(ControlError::invalid_request(format!(
                    "message kind `{kind}` requires {flag}"
                )));
            }
        }
        if kind == "conflict_notice" && self.resources.is_empty() {
            return Err(ControlError::invalid_request(
                "message kind `conflict_notice` requires at least one --resource",
            ));
        }
        if kind == "directive" && self.request.is_some() == self.team.is_some() {
            return Err(ControlError::invalid_request(
                "message kind `directive` requires exactly one of --request or --team",
            ));
        }
        if kind == "qa_result" && !matches!(self.outcome.as_deref(), Some("passed" | "failed")) {
            return Err(ControlError::invalid_request(
                "--outcome for qa_result must be `passed` or `failed`",
            ));
        }
        Ok(())
    }

    fn required_body(&self, kind: &str) -> Result<&str, ControlError> {
        self.body.as_deref().ok_or_else(|| {
            ControlError::invalid_request(format!("message kind `{kind}` requires --body"))
        })
    }
}

fn validate_message_retry(
    args: &MessageSendArgs,
    kind: &str,
    envelope: &Envelope,
    supervisor: &Supervisor,
) -> Result<(), ControlError> {
    let kind = if kind == "consultation" {
        "consultation_request"
    } else {
        kind
    };
    let target_matches = args
        .to
        .as_deref()
        .map(|target| resolve_target(supervisor, target))
        .transpose()?
        .is_none_or(|target| target == envelope.target);
    let request_matches = args.request.as_deref().is_none_or(|request_id| {
        envelope
            .request_id
            .as_ref()
            .is_some_and(|stored| stored.as_str() == request_id)
    });
    let team_matches = args.team.as_deref().is_none_or(|team_id| {
        envelope
            .team_id
            .as_ref()
            .is_some_and(|stored| stored.as_str() == team_id)
    });
    let directive_scope_matches = kind != "directive"
        || match (
            args.request.as_deref(),
            args.team.as_deref(),
            envelope.request_id.as_ref(),
            envelope.team_id.as_ref(),
        ) {
            (Some(asserted), None, Some(stored), _) => asserted == stored.as_str(),
            (None, Some(asserted), None, Some(stored)) => asserted == stored.as_str(),
            _ => false,
        };
    let message_matches = match (kind, &envelope.message) {
        ("progress", Message::Progress(message)) => {
            args.body.as_deref() == Some(message.summary.as_str())
        }
        ("blocker", Message::Blocker(message)) => {
            args.body.as_deref() == Some(message.summary.as_str())
        }
        ("directive", Message::Directive(message)) => {
            args.decision.as_deref() == Some(message.decision.as_str())
                && args.rationale.as_deref() == Some(message.rationale.as_str())
        }
        ("consultation_request", Message::ConsultationRequest(message)) => {
            args.body.as_deref() == Some(message.question.as_str())
                && args.subject.as_deref().unwrap_or("cross-team consultation") == message.subject
        }
        ("consultation_response", Message::ConsultationResponse(message)) => {
            args.body.as_deref() == Some(message.response.as_str())
                && args.consultation_id.as_deref() == Some(message.consultation_id.as_str())
        }
        ("dependency_notice", Message::DependencyNotice(message)) => {
            args.body.as_deref() == Some(message.description.as_str())
                && args.depends_on_request.as_deref()
                    == Some(message.depends_on_request_id.as_str())
        }
        ("conflict_notice", Message::ConflictNotice(message)) => {
            args.body.as_deref() == Some(message.description.as_str())
                && args.resources == message.resources
        }
        ("handoff_offer", Message::HandoffOffer(message)) => {
            args.body.as_deref() == Some(message.reason.as_str())
                && args.request.as_deref() == Some(message.request_id.as_str())
        }
        ("handoff_acceptance", Message::HandoffAcceptance(message)) => {
            args.handoff_id.as_deref() == Some(message.handoff_id.as_str())
        }
        ("qa_result", Message::QaResult(message)) => {
            args.body.as_deref() == Some(message.summary.as_str())
                && args.outcome.as_deref() == Some(enum_name(message.outcome).as_str())
        }
        ("integration_complete", Message::IntegrationComplete(_)) => true,
        ("fix_request", Message::FixRequest(message)) => {
            args.body.as_deref() == Some(message.instructions.as_str())
        }
        _ => false,
    };
    if target_matches
        && request_matches
        && team_matches
        && directive_scope_matches
        && message_matches
    {
        return Ok(());
    }
    Err(ControlError::new(
        "operation_id_conflict",
        format!(
            "operation ID `{}` was already committed with different message input",
            args.operation_id
        ),
    ))
}

#[derive(Deserialize)]
struct MessageInboxArgs {
    actor: Option<String>,
    #[serde(default)]
    include_acked: bool,
}

#[derive(Deserialize)]
struct MessageAckArgs {
    id: String,
    actor: Option<String>,
    operation_id: String,
}

#[derive(Deserialize)]
struct DecisionSubmitArgs {
    request: String,
    candidate_sha: String,
    decision: String,
    summary: Option<String>,
    #[serde(default)]
    close_team: bool,
    operation_id: String,
}

#[derive(Deserialize)]
struct DecisionListArgs {
    request: Option<String>,
    candidate_sha: Option<String>,
    team: Option<String>,
    #[serde(default = "default_decision_limit")]
    limit: u32,
}

#[derive(Deserialize)]
struct ReviewBeginArgs {
    request: String,
    candidate_sha: String,
    operation_id: String,
}

#[derive(Deserialize)]
struct ReviewVerifyArgs {
    session: String,
    operation_id: String,
}

#[derive(Deserialize)]
struct ReviewShowArgs {
    session: Option<String>,
    candidate_sha: Option<String>,
    limit: u32,
}

const fn default_event_limit() -> u32 {
    100
}

const fn default_decision_limit() -> u32 {
    100
}

const fn default_orchestrators() -> u16 {
    1
}

fn decode<T: for<'de> Deserialize<'de>>(value: &Value) -> Result<T, ControlError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        ControlError::invalid_request(format!("invalid command arguments: {error}"))
    })
}

fn query_decision_report(store: &StateStore, request: &Value) -> Result<Value, ControlError> {
    let args: DecisionListArgs = decode(request)?;
    if !(1..=1_000).contains(&args.limit) {
        return Err(ControlError::invalid_request(
            "decision list limit must be between 1 and 1000",
        ));
    }
    let selected_filters = usize::from(args.request.is_some())
        + usize::from(args.candidate_sha.is_some())
        + usize::from(args.team.is_some());
    if selected_filters != 1 {
        return Err(ControlError::invalid_request(
            "decision list requires exactly one of request, candidate_sha, or team",
        ));
    }

    let decisions = if let Some(request_id) = args.request {
        let request_id = RequestId::new(request_id).map_err(ControlError::protocol)?;
        store.decisions_by_request(&request_id, args.limit)?
    } else if let Some(candidate_sha) = args.candidate_sha {
        let candidate_sha = GitSha::new(candidate_sha).map_err(ControlError::protocol)?;
        store.decisions_by_candidate_sha(&candidate_sha, args.limit)?
    } else {
        let team_id = TeamId::new(args.team.expect("exactly one filter was selected"))
            .map_err(ControlError::protocol)?;
        store.decisions_by_team(&team_id, args.limit)?
    };
    Ok(json!({ "decisions": decisions }))
}

fn primary_operation(operation: &str) -> bool {
    matches!(
        operation,
        "stop"
            | "reconcile"
            | "team.create"
            | "team.update"
            | "team.pause"
            | "team.resume"
            | "team.close"
            | "actor.stop"
            | "actor.replace"
            | "run.create"
            | "run.pause"
            | "run.resume"
            | "run.cancel"
            | "request.create"
            | "request.cancel"
            | "decision.submit"
            | "review.begin"
            | "review.verify"
    )
}

fn presentation_refresh_operation(operation: &str) -> bool {
    matches!(
        operation,
        "reconcile"
            | "team.create"
            | "team.update"
            | "team.pause"
            | "team.resume"
            | "team.close"
            | "actor.replace"
            | "run.create"
            | "run.pause"
            | "run.resume"
            | "run.cancel"
            | "request.create"
            | "request.claim"
            | "request.block"
            | "request.complete"
            | "request.cancel"
            | "message.send"
            | "decision.submit"
    )
}

fn context_bootstrap_requested(request: &Value) -> bool {
    request
        .get("bootstrap")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn public_read_operation(operation: &str) -> bool {
    // Decision history is an explicit immutable report. Like status and
    // doctor, it must not renew actors, expire leases, or enter mutation
    // admission merely because a caller reads it.
    matches!(operation, "status" | "doctor" | "decision.list")
}

fn caller_linearization_operation(operation: &str, _request: &Value) -> bool {
    !public_read_operation(operation)
}

fn workspace_operation_lock_mode(operation: &str, _request: &Value) -> Option<OperationLockMode> {
    if operation == "actor.shutdown" {
        Some(OperationLockMode::Exclusive)
    } else if !public_read_operation(operation) {
        Some(OperationLockMode::Shared)
    } else {
        None
    }
}

fn force_presentation_refresh(operation: &str, request: &Value) -> bool {
    matches!(
        operation,
        "reconcile" | "team.create" | "team.resume" | "actor.replace"
    ) || (operation == "context" && context_bootstrap_requested(request))
}

fn actor_operation(operation: &str) -> bool {
    matches!(
        operation,
        "request.claim" | "request.block" | "request.complete" | "message.send" | "message.ack"
    )
}

fn caller_authentication_required(operation: &str, request: &Value) -> bool {
    primary_operation(operation)
        || operation == "review.show"
        || actor_operation(operation)
        || matches!(operation, "actor.shutdown" | "message.inbox")
        || (operation == "context" && !context_bootstrap_requested(request))
}

fn mutation_operation(operation: &str) -> bool {
    matches!(
        operation,
        "start"
            | "stop"
            | "reconcile"
            | "team.create"
            | "team.update"
            | "team.pause"
            | "team.resume"
            | "team.close"
            | "actor.stop"
            | "actor.shutdown"
            | "actor.replace"
            | "run.create"
            | "run.pause"
            | "run.resume"
            | "run.cancel"
            | "request.create"
            | "request.claim"
            | "request.block"
            | "request.complete"
            | "request.cancel"
            | "message.send"
            | "message.ack"
            | "decision.submit"
            | "review.begin"
            | "review.verify"
    )
}

fn assert_actor(requested: Option<&str>, authenticated: &ActorId) -> Result<(), ControlError> {
    if requested.is_none_or(|value| value == authenticated.as_str()) {
        Ok(())
    } else {
        Err(ControlError::new(
            "actor_identity_mismatch",
            format!("--actor is only an assertion; the authenticated caller is `{authenticated}`"),
        ))
    }
}

fn identity_unavailable() -> ControlError {
    ControlError::new(
        "actor_identity_unavailable",
        "could not authenticate the current orchestrator from a durable caller binding",
    )
    .with_hint(
        "run `agsv --json context --bootstrap` inside a supported caller session; deterministic fixture tests may explicitly enable insecure debug identity",
    )
}

fn terminal_actor_binding(actor_ref: &ActorRef) -> ControlError {
    ControlError::new(
        "actor_binding_stopped",
        "this caller binding belongs to a stopped actor generation",
    )
    .with_hint("run `agsv --json context --bootstrap` to acquire a fresh fenced generation")
    .with_details(json!({
        "actor": actor_ref,
        "status": "stopped",
        "reason": "actor_generation_stopped",
    }))
}

fn superseded_actor_binding(actor_ref: &ActorRef) -> ControlError {
    ControlError::new(
        "stale_actor_binding",
        "this caller binding belongs to a superseded actor generation",
    )
    .with_hint("use the current actor generation's caller session")
    .with_details(json!({
        "actor": actor_ref,
        "status": "stale",
        "reason": "team_generation_superseded",
    }))
}

fn superseded_primary_binding(actor_ref: &ActorRef) -> ControlError {
    ControlError::new(
        "stale_actor_binding",
        "this caller binding belongs to a superseded Primary generation",
    )
    .with_hint("use the active Primary caller session; superseded bindings cannot be recovered")
    .with_details(json!({
        "actor": actor_ref,
        "status": "stale",
        "reason": "primary_generation_superseded",
    }))
}

fn superseded_binding(supervisor: &Supervisor, actor_ref: &ActorRef) -> ControlError {
    if supervisor
        .actor(&actor_ref.actor_id)
        .is_some_and(|actor| actor.team_id.is_none())
    {
        superseded_primary_binding(actor_ref)
    } else {
        superseded_actor_binding(actor_ref)
    }
}

fn primary_lease_held(actor_id: &ActorId) -> ControlError {
    ControlError::new(
        "primary_lease_held",
        format!("active Primary `{actor_id}` is bound to another session"),
    )
    .with_hint(
        "use the active Primary caller session, or wait for and verify lease expiry before bootstrapping a replacement",
    )
}

fn primary_actor_id(binding_value: &str) -> Result<ActorId, ControlError> {
    let mut safe = binding_value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    safe.truncate(96);
    if safe.trim_matches('-').is_empty() {
        sha256_hex(binding_value)[..24].clone_into(&mut safe);
    }
    ActorId::new(format!("primary-{safe}")).map_err(ControlError::protocol)
}

fn selected_primary_profile(
    settings: &ControlSettings,
) -> Result<&ActorProfileSettings, ControlError> {
    settings
        .agent_profiles
        .get(&settings.primary_profile)
        .ok_or_else(|| {
            ControlError::new(
                "invalid_profile_configuration",
                format!(
                    "selected Primary profile `{}` is not configured",
                    settings.primary_profile
                ),
            )
        })
}

fn selected_team_profile(settings: &ControlSettings) -> Result<&TeamProfileSettings, ControlError> {
    settings
        .team_profiles
        .get(&settings.default_team_profile)
        .ok_or_else(|| {
            ControlError::new(
                "invalid_profile_configuration",
                format!(
                    "selected default team profile `{}` is not configured",
                    settings.default_team_profile
                ),
            )
        })
}

fn team_profile_mismatch(
    settings: &ControlSettings,
    team: &Team,
    persisted: &str,
    requested: &str,
) -> ControlError {
    ControlError::new(
        "team_profile_mismatch",
        format!(
            "team `{}` already uses team profile `{persisted}` and cannot be recreated with `{requested}`",
            team.team_id
        ),
    )
    .with_details(json!({
        "team_id": team.team_id,
        "persisted_team_profile": persisted,
        "requested_team_profile": requested,
        "requested_team_profile_configured": settings.team_profiles.contains_key(requested),
        "available_team_profiles": settings.team_profiles.keys().collect::<Vec<_>>(),
    }))
    .with_hint("retry with the persisted team profile or choose a different team name")
}

fn selected_team_actor_profile(
    settings: &ControlSettings,
) -> Result<&ActorProfileSettings, ControlError> {
    let team = selected_team_profile(settings)?;
    settings
        .agent_profiles
        .get(&team.actor_profile)
        .ok_or_else(|| {
            ControlError::new(
                "invalid_profile_configuration",
                format!(
                    "team profile `{}` references unknown actor profile `{}`",
                    team.name, team.actor_profile
                ),
            )
        })
}

fn validate_profile_settings(settings: &ControlSettings) -> Result<(), ControlError> {
    if settings.agent_profiles.is_empty() || settings.team_profiles.is_empty() {
        return Err(ControlError::new(
            "invalid_profile_configuration",
            "at least one actor profile and one team profile are required",
        ));
    }
    for (name, profile) in &settings.agent_profiles {
        if name != &profile.name {
            return Err(ControlError::new(
                "invalid_profile_configuration",
                format!("actor profile key `{name}` does not match its name"),
            ));
        }
        profile.actor_role()?;
        profile.snapshot()?;
    }
    for (name, profile) in &settings.team_profiles {
        if name != &profile.name {
            return Err(ControlError::new(
                "invalid_profile_configuration",
                format!("team profile key `{name}` does not match its name"),
            ));
        }
        profile.snapshot()?;
        validate_assignment_policy(&profile.assignment_policy)?;
        if !settings.agent_profiles.contains_key(&profile.actor_profile) {
            return Err(ControlError::new(
                "invalid_profile_configuration",
                format!(
                    "team profile `{name}` references unknown actor profile `{}`",
                    profile.actor_profile
                ),
            ));
        }
    }
    let primary = selected_primary_profile(settings)?;
    if !primary
        .capabilities
        .contains(HUMAN_FACING_PRIMARY_CAPABILITY)
    {
        return Err(ControlError::new(
            "invalid_profile_configuration",
            format!(
                "selected Primary profile `{}` lacks `{HUMAN_FACING_PRIMARY_CAPABILITY}`",
                primary.name
            ),
        ));
    }
    if !matches!(primary.launch, ActorLaunchSettings::Bound) {
        return Err(ControlError::new(
            "invalid_profile_configuration",
            format!(
                "selected Primary profile `{}` must be bound to the caller session",
                primary.name
            ),
        )
        .with_details(json!({
            "actor_profile": primary.name,
            "required_launch": { "applicable": false, "mode": "bound" },
        })));
    }
    for team_profile in settings.team_profiles.values() {
        let actor_profile = settings
            .agent_profiles
            .get(&team_profile.actor_profile)
            .expect("team actor profile existence checked above");
        if !matches!(actor_profile.launch, ActorLaunchSettings::Runtime { .. }) {
            return Err(ControlError::new(
                "invalid_profile_configuration",
                format!(
                    "team profile `{}` requires a runtime-launchable actor profile",
                    team_profile.name
                ),
            )
            .with_details(json!({
                "team_profile": team_profile.name,
                "actor_profile": actor_profile.name,
                "required_launch": { "applicable": true, "mode": "runtime" },
            })));
        }
    }
    let implementation = selected_team_actor_profile(settings)?;
    if !settings.persist_profile_snapshots
        && (primary.role != ActorRole::Primary.as_str()
            || implementation.role != ActorRole::Implementation.as_str())
    {
        return Err(ControlError::new(
            "invalid_profile_configuration",
            "legacy-compatible profile snapshots require the primary and implementation roles",
        ));
    }
    Ok(())
}

/// Verifies that an assignment policy is implemented by this control plane.
///
/// # Errors
///
/// Returns a stable configuration error containing the supported policy list.
pub fn validate_assignment_policy(value: &str) -> Result<(), ControlError> {
    if SUPPORTED_ASSIGNMENT_POLICIES.contains(&value) {
        Ok(())
    } else {
        Err(ControlError::new(
            "unsupported_assignment_policy",
            format!("assignment policy `{value}` is not supported"),
        )
        .with_details(json!({
            "assignment_policy": value,
            "available_assignment_policies": SUPPORTED_ASSIGNMENT_POLICIES,
        })))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProfileMode {
    Legacy,
    Snapshotted,
}

fn validate_legacy_actor_profile(
    profile: &ActorProfileSettings,
    expected_name: &str,
    expected_role: &ActorRole,
    expected_capability: &str,
) -> Result<(), ControlError> {
    if profile.name == expected_name
        && profile.role == expected_role.as_str()
        && profile.capabilities.len() == 1
        && profile.capabilities.contains(expected_capability)
    {
        return Ok(());
    }
    Err(ControlError::new(
        "actor_profile_mismatch",
        format!(
            "configured actor profile `{}` is incompatible with profileless legacy `{expected_name}` metadata",
            profile.name
        ),
    )
    .with_details(json!({
        "configured_profile": profile.name,
        "configured_role": profile.role,
        "configured_capabilities": profile.capabilities,
        "expected_profile": expected_name,
        "expected_role": expected_role,
        "expected_capabilities": [expected_capability],
    })))
}

fn validate_legacy_team_profile(
    team_profile: &TeamProfileSettings,
    actor_profile: &ActorProfileSettings,
) -> Result<(), ControlError> {
    if team_profile.name != LEGACY_IMPLEMENTATION_PROFILE
        || team_profile.actor_profile != LEGACY_IMPLEMENTATION_PROFILE
    {
        return Err(ControlError::new(
            "team_profile_mismatch",
            format!(
                "configured team profile `{}` is incompatible with profileless legacy team metadata",
                team_profile.name
            ),
        )
        .with_details(json!({
            "configured_team_profile": team_profile.name,
            "configured_actor_profile": team_profile.actor_profile,
            "expected_team_profile": LEGACY_IMPLEMENTATION_PROFILE,
            "expected_actor_profile": LEGACY_IMPLEMENTATION_PROFILE,
        })));
    }
    validate_legacy_actor_profile(
        actor_profile,
        LEGACY_IMPLEMENTATION_PROFILE,
        &ActorRole::Implementation,
        IMPLEMENTATION_EXECUTION_CAPABILITY,
    )
}

fn activate_primary_for_profile(
    state: &mut Supervisor,
    actor_id: &ActorId,
    profile: &ActorProfileSettings,
    configured_role: &ActorRole,
    configured_snapshot: &ActorProfileSnapshot,
    snapshot_new_entities: bool,
) -> Result<ActorRef, ControlError> {
    let existing_has_snapshot = state.actor(actor_id).map(|actor| actor.profile.is_some());
    let use_legacy = existing_has_snapshot == Some(false)
        || (existing_has_snapshot.is_none() && !snapshot_new_entities);
    if use_legacy {
        validate_legacy_actor_profile(
            profile,
            LEGACY_PRIMARY_PROFILE,
            &ActorRole::Primary,
            HUMAN_FACING_PRIMARY_CAPABILITY,
        )?;
        state
            .activate_primary(actor_id.clone())
            .map_err(ControlError::core)
    } else {
        state
            .activate_primary_with_profile(
                actor_id.clone(),
                configured_role.clone(),
                configured_snapshot.clone(),
            )
            .map_err(ControlError::core)
    }
}

fn ensure_team_profile(
    state: &mut Supervisor,
    team_id: &TeamId,
    team_profile: &TeamProfileSettings,
    actor_profile: &ActorProfileSettings,
    configured_snapshot: &TeamProfileSnapshot,
    snapshot_new_entities: bool,
) -> Result<ProfileMode, ControlError> {
    let existing_has_snapshot = state.team(team_id).map(|team| team.profile.is_some());
    let use_legacy = existing_has_snapshot == Some(false)
        || (existing_has_snapshot.is_none() && !snapshot_new_entities);
    if use_legacy {
        validate_legacy_team_profile(team_profile, actor_profile)?;
        state
            .create_team(team_id.clone())
            .map_err(ControlError::core)?;
        Ok(ProfileMode::Legacy)
    } else {
        state
            .create_team_with_profile(team_id.clone(), configured_snapshot.clone())
            .map_err(ControlError::core)?;
        Ok(ProfileMode::Snapshotted)
    }
}

fn ensure_team_actor(
    state: &mut Supervisor,
    team_id: &TeamId,
    actor_id: &ActorId,
    configured_role: &ActorRole,
    configured_snapshot: &ActorProfileSnapshot,
    profile_mode: ProfileMode,
) -> Result<ActorRef, ControlError> {
    let configured_profile = match profile_mode {
        ProfileMode::Legacy => None,
        ProfileMode::Snapshotted => Some(configured_snapshot),
    };
    if let Some(actor) = state.actor(actor_id) {
        validate_actor_profile(actor, configured_role, configured_profile)?;
        if actor.team_id.as_ref() == Some(team_id) && actor.status == ActorStatus::Healthy {
            return Ok(actor.actor_ref());
        }
        let is_prior_terminal_generation = actor.team_id.as_ref() == Some(team_id)
            && matches!(actor.status, ActorStatus::Stopped | ActorStatus::Revoked)
            && state
                .team(team_id)
                .is_some_and(|team| !team.actors.contains(actor_id));
        if is_prior_terminal_generation {
            return match profile_mode {
                ProfileMode::Legacy => state
                    .register_implementation(team_id, actor_id.clone())
                    .map_err(ControlError::core),
                ProfileMode::Snapshotted => state
                    .register_implementation_with_profile(
                        team_id,
                        actor_id.clone(),
                        configured_role.clone(),
                        configured_snapshot.clone(),
                    )
                    .map_err(ControlError::core),
            };
        }
        return match profile_mode {
            ProfileMode::Legacy => state
                .replace_implementation(team_id, actor_id.clone())
                .map_err(ControlError::core),
            ProfileMode::Snapshotted => state
                .replace_implementation_with_profile(
                    team_id,
                    actor_id.clone(),
                    configured_role.clone(),
                    configured_snapshot.clone(),
                )
                .map_err(ControlError::core),
        };
    }
    match profile_mode {
        ProfileMode::Legacy => state
            .register_implementation(team_id, actor_id.clone())
            .map_err(ControlError::core),
        ProfileMode::Snapshotted => state
            .register_implementation_with_profile(
                team_id,
                actor_id.clone(),
                configured_role.clone(),
                configured_snapshot.clone(),
            )
            .map_err(ControlError::core),
    }
}

fn validate_actor_profile(
    actor: &Actor,
    configured_role: &ActorRole,
    configured_profile: Option<&ActorProfileSnapshot>,
) -> Result<(), ControlError> {
    if &actor.role == configured_role
        && actor.profile.as_ref() == configured_profile
        && actor.team_id.is_some()
    {
        return Ok(());
    }
    Err(ControlError::new(
        "actor_profile_mismatch",
        format!(
            "actor `{}` is already registered with different profile metadata",
            actor.actor_id
        ),
    )
    .with_details(json!({
        "actor_id": actor.actor_id,
        "persisted_role": actor.role,
        "persisted_profile": actor.profile,
        "configured_role": configured_role,
        "configured_profile": configured_profile,
    })))
}

/// Verifies that a configured top-level runtime exists in the compile-time registry.
///
/// # Errors
///
/// Returns a stable configuration error for invalid or unregistered runtime identifiers.
pub fn validate_runtime(value: &str) -> Result<(), ControlError> {
    let registry = RuntimeRegistry::new();
    select_runtime(&registry, value).map(|_| ())
}

fn select_runtime(
    registry: &impl RuntimeCatalog,
    value: &str,
) -> Result<Arc<dyn AgentRuntime>, ControlError> {
    registry.select(Some(value)).map_err(|error| {
        let code = match &error {
            AdapterError::InvalidRuntimeId(_) => "invalid_runtime",
            AdapterError::UnknownRuntime(_) => "runtime_not_registered",
            _ => "runtime_registry_error",
        };
        ControlError::new(code, error.to_string()).with_details(json!({
            "configured_runtime": value,
            "available_runtimes": registry.ids(),
        }))
    })
}

fn now_ms() -> Result<u64, ControlError> {
    #[cfg(debug_assertions)]
    if let Ok(overridden) = std::env::var("AGSV_DEV_NOW_MS") {
        return overridden.parse::<u64>().map_err(|error| {
            ControlError::new(
                "clock_error",
                format!("AGSV_DEV_NOW_MS must be an unsigned millisecond timestamp: {error}"),
            )
        });
    }
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ControlError::new("clock_error", error.to_string()))?;
    u64::try_from(duration.as_millis())
        .map_err(|error| ControlError::new("clock_error", error.to_string()))
}

fn validate_operation_id(value: &str) -> Result<(), ControlError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:/@-".contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(ControlError::invalid_request(
            "operation_id must use 1-128 portable identifier characters",
        ))
    }
}

fn stable_id(prefix: &str, value: &str) -> String {
    let hash = sha256_hex(value);
    format!("{prefix}-{}", &hash[..24])
}

fn review_record_limit(session: &ReviewSession) -> Result<u32, ControlError> {
    let maximum_records = session
        .plan
        .checks
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(8))
        .ok_or_else(|| ControlError::new("review_record_limit", "review record limit overflow"))?;
    u32::try_from(maximum_records)
        .map_err(|_| ControlError::new("review_record_limit", "review record limit exceeds u32"))
}

fn enum_name<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|item| item.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn slug(value: &str) -> String {
    let mut slug = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    slug = slug.trim_matches('-').chars().collect();
    if slug.is_empty() {
        stable_id("team", value)
    } else {
        slug.truncate(80);
        slug
    }
}

fn desired_actor_ids(team: &Team, desired_instances: usize) -> Result<Vec<ActorId>, ControlError> {
    let mut actor_ids = team
        .actors
        .iter()
        .take(desired_instances)
        .cloned()
        .collect::<Vec<_>>();
    let team_stem = team
        .team_id
        .as_str()
        .strip_prefix("team-")
        .unwrap_or_else(|| team.team_id.as_str());
    for index in (actor_ids.len() + 1)..=desired_instances {
        actor_ids.push(
            ActorId::new(format!("impl-{}-{index}", slug(team_stem)))
                .map_err(ControlError::protocol)?,
        );
    }
    Ok(actor_ids)
}

fn reconciliation_launch_operation_id(
    team_id: &TeamId,
    team_epoch: TeamEpoch,
    actor_id: &ActorId,
    actor_epoch: ActorEpoch,
) -> String {
    stable_id(
        "reconcile-launch",
        &format!("{team_id}:{team_epoch}:{actor_id}:{actor_epoch}"),
    )
}

fn nonterminal_request_ids(supervisor: &Supervisor, actor_ref: &ActorRef) -> Vec<RequestId> {
    supervisor
        .snapshot()
        .requests
        .into_iter()
        .filter(|request| {
            !request.status.is_terminal()
                && request
                    .assignment
                    .as_ref()
                    .is_some_and(|assignment| assignment.actor == *actor_ref)
        })
        .map(|request| request.request_id)
        .collect()
}

fn team_close_blocking_request_ids(supervisor: &Supervisor, team_id: &TeamId) -> Vec<RequestId> {
    supervisor
        .snapshot()
        .requests
        .into_iter()
        .filter(|request| request.team_id == *team_id && request_blocks_team_close(request.status))
        .map(|request| request.request_id)
        .collect()
}

fn team_close_blocking_request_ids_for_actor(
    supervisor: &Supervisor,
    actor_ref: &ActorRef,
) -> Vec<RequestId> {
    supervisor
        .snapshot()
        .requests
        .into_iter()
        .filter(|request| {
            request_blocks_team_close(request.status)
                && request
                    .assignment
                    .as_ref()
                    .is_some_and(|assignment| assignment.actor == *actor_ref)
        })
        .map(|request| request.request_id)
        .collect()
}

fn team_close_blocked(team_id: &TeamId, blocking: &[RequestId]) -> ControlError {
    ControlError::new(
        "team_close_blocked",
        format!("team `{team_id}` still has requests that may require team action"),
    )
    .with_details(json!({
        "team_id": team_id,
        "blocking_request_ids": blocking,
    }))
    .with_hint(
        "finish or cancel the blocking requests, or retry `team close --when-idle` to record close intent",
    )
}

fn team_close_unacknowledged_actions(team_id: &TeamId, blocking: &[MessageId]) -> ControlError {
    ControlError::new(
        "team_close_unacknowledged_actions",
        format!("team `{team_id}` has unread messages that still require team action"),
    )
    .with_details(json!({
        "team_id": team_id,
        "unacknowledged_action_message_ids": blocking,
    }))
    .with_hint("have the target actor read and acknowledge these messages before closing the team")
}

fn find_team_instance_summary(summary: &Value, team_id: &TeamId) -> Value {
    summary["teams"]
        .as_array()
        .and_then(|teams| {
            teams
                .iter()
                .find(|team| team["team_id"].as_str() == Some(team_id.as_str()))
        })
        .cloned()
        .unwrap_or(Value::Null)
}

fn normalize_team_purpose(value: Option<&str>) -> Result<String, ControlError> {
    let Some(value) = value else {
        return Ok(String::new());
    };
    let value = value.trim();
    let valid = !value.is_empty()
        && value.len() <= 256
        && value.chars().all(|character| !character.is_control());
    if valid {
        Ok(value.to_owned())
    } else {
        Err(ControlError::invalid_request(
            "team purpose must contain 1-256 UTF-8 bytes and no control characters",
        ))
    }
}

fn session_status_is_present(status: &str) -> bool {
    matches!(
        status,
        "starting" | "working" | "idle" | "blocked" | "unknown"
    )
}

fn session_name(workspace_id: &str, actor: &ActorRef) -> String {
    let mut name = actor.actor_id.as_str().to_ascii_lowercase();
    name.retain(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'));
    if !name.starts_with(|character: char| character.is_ascii_lowercase()) {
        name.insert_str(0, "a-");
    }
    let digest = sha256_hex(format!(
        "{workspace_id}\0{}\0{}",
        actor.actor_id, actor.actor_epoch
    ));
    name.truncate(15);
    format!("{name}-{}", &digest[..16])
}

fn session_is_present(status: &str) -> bool {
    matches!(
        status,
        "starting" | "working" | "idle" | "blocked" | "unknown"
    )
}

fn replacement_intent_key(operation_id: &str, source_epoch: u64) -> String {
    format!("replacement:{operation_id}:{source_epoch}")
}

fn replacement_source_epoch(launch_key: &str, operation_id: &str) -> Option<u64> {
    let value = launch_key.strip_prefix("replacement:")?;
    let (stored_operation, epoch) = value.rsplit_once(':')?;
    (stored_operation == operation_id)
        .then(|| epoch.parse::<u64>().ok())
        .flatten()
}

fn active_primary_actor(supervisor: &Supervisor) -> Result<ActorRef, ControlError> {
    supervisor.active_primary().ok_or_else(|| {
        ControlError::new(
            "primary_required",
            "no active Primary; run `agsv context --bootstrap` from the Primary",
        )
    })
}

fn message_id(operation_id: &str, suffix: &str) -> MessageId {
    MessageId::new(stable_id("message", &format!("{operation_id}:{suffix}")))
        .expect("stable generated message IDs are valid")
}

fn handoff_id(operation_id: &str) -> HandoffId {
    HandoffId::new(stable_id("handoff", operation_id))
        .expect("stable generated handoff IDs are valid")
}

#[allow(clippy::too_many_arguments)]
fn make_envelope(
    supervisor: &Supervisor,
    sender: ActorRef,
    target: MessageTarget,
    team_id: Option<TeamId>,
    run_id: Option<RunId>,
    request_id: Option<RequestId>,
    assignment_epoch: Option<AssignmentEpoch>,
    message: Message,
    message_id: MessageId,
) -> Result<Envelope, ControlError> {
    let team_epoch = team_id
        .as_ref()
        .map(|id| {
            supervisor
                .team(id)
                .map(|team| team.epoch)
                .ok_or_else(|| ControlError::not_found("team", id.as_str()))
        })
        .transpose()?;
    Ok(Envelope {
        protocol_version: PROTOCOL_VERSION,
        message_id,
        workspace_id: supervisor.workspace_id().clone(),
        sender,
        target,
        team_id,
        run_id,
        request_id,
        policy_revision: supervisor.policy_revision(),
        primary_epoch: supervisor.primary_epoch(),
        team_epoch,
        assignment_epoch,
        sent_at: TimestampMillis(now_ms()?),
        message,
    })
}

fn request_envelope(
    supervisor: &Supervisor,
    request_id: &RequestId,
    sender: ActorRef,
    target: MessageTarget,
    message: Message,
    message_id: MessageId,
) -> Result<(Envelope, RunId), ControlError> {
    let request = supervisor
        .request(request_id)
        .ok_or_else(|| ControlError::not_found("request", request_id.as_str()))?;
    let assignment_epoch = supervisor
        .actor(&sender.actor_id)
        .filter(|actor| {
            actor.team_id.is_some() && actor.has_capability(IMPLEMENTATION_EXECUTION_CAPABILITY)
        })
        .and_then(|_| {
            request
                .assignment
                .as_ref()
                .map(|assignment| assignment.epoch)
        });
    let run_id = request.run_id.clone();
    let historical_team_epoch = request.team_epoch;
    let mut envelope = make_envelope(
        supervisor,
        sender,
        target,
        Some(request.team_id.clone()),
        Some(run_id.clone()),
        Some(request_id.clone()),
        assignment_epoch,
        message,
        message_id,
    )?;
    if !matches!(envelope.message, Message::HandoffAcceptance(_))
        && !request_blocks_team_close(request.status)
    {
        envelope.team_epoch = Some(historical_team_epoch);
    }
    Ok((envelope, run_id))
}

fn apply_envelope(
    supervisor: &mut Supervisor,
    mut envelope: Envelope,
) -> Result<ApplyOutcome, ControlError> {
    if let Some(existing) = supervisor.delivery(&envelope.message_id) {
        envelope.sent_at = existing.envelope.sent_at;
    }
    supervisor.apply(envelope).map_err(ControlError::core)
}

fn apply_envelope_with_archive(
    store: &StateStore,
    supervisor: &mut Supervisor,
    mut envelope: Envelope,
) -> Result<ApplyOutcome, ControlError> {
    if let Some(archived) = store.archived_delivery(&envelope.message_id)? {
        envelope.sent_at = archived.envelope.sent_at;
        return supervisor
            .classify_archived_retry(&envelope, &archived)
            .map_err(ControlError::core);
    }
    apply_envelope(supervisor, envelope)
}

fn acknowledge(
    supervisor: &mut Supervisor,
    mut acknowledgement: Acknowledgement,
) -> Result<AckOutcome, ControlError> {
    if let Some(existing) = supervisor
        .delivery(&acknowledgement.message_id)
        .and_then(|delivery| {
            delivery
                .acknowledgements
                .values()
                .find(|existing| existing.actor == acknowledgement.actor)
        })
    {
        acknowledgement.acknowledged_at = existing.acknowledged_at;
    }
    supervisor
        .acknowledge(acknowledgement)
        .map_err(ControlError::core)
}

fn acknowledge_with_archive(
    store: &StateStore,
    supervisor: &mut Supervisor,
    mut acknowledgement: Acknowledgement,
) -> Result<AckOutcome, ControlError> {
    if let Some(archived) = store.archived_delivery(&acknowledgement.message_id)? {
        let existing = archived
            .acknowledgements
            .iter()
            .find(|existing| existing.actor == acknowledgement.actor);
        if let Some(existing) = existing {
            acknowledgement.acknowledged_at = existing.acknowledged_at;
        }
        return supervisor
            .classify_archived_ack(&acknowledgement, &archived)
            .map_err(ControlError::core);
    }
    acknowledge(supervisor, acknowledgement)
}

fn control_git_command(git: &Path, directory: &Path) -> Command {
    let mut command = Command::new(git);
    command.arg("-C").arg(directory);
    neutralize_control_git_environment(&mut command);
    command
}

fn neutralize_control_git_environment(command: &mut Command) {
    command
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LC_ALL", "C");
}

fn reporting_git_output(git: &Path, directory: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = control_git_command(git, directory)
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err(if detail.is_empty() {
            format!("git {} exited with {}", args.join(" "), output.status)
        } else {
            detail
        })
    }
}

fn observed_git_path(git: &Path, directory: &Path, args: &[&str]) -> Result<PathBuf, String> {
    let output = reporting_git_output(git, directory, args)?;
    let value = String::from_utf8(output)
        .map_err(|error| format!("Git returned a non-UTF-8 path: {error}"))?;
    let value = value.trim();
    if value.is_empty() {
        return Err("Git returned an empty path".to_owned());
    }
    let path = PathBuf::from(value);
    let path = if path.is_absolute() {
        path
    } else {
        directory.join(path)
    };
    fs::canonicalize(&path).map_err(|error| {
        format!(
            "could not canonicalize Git path {}: {error}",
            path.display()
        )
    })
}

fn observed_git_identity(git: &Path, directory: &Path) -> Result<(PathBuf, PathBuf), String> {
    Ok((
        observed_git_path(git, directory, &["rev-parse", "--show-toplevel"])?,
        observed_git_path(git, directory, &["rev-parse", "--git-common-dir"])?,
    ))
}

fn observed_git_head(git: &Path, directory: &Path) -> Result<GitSha, String> {
    let output = reporting_git_output(git, directory, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let value = String::from_utf8(output)
        .map_err(|error| format!("Git returned a non-UTF-8 commit ID: {error}"))?;
    GitSha::new(value.trim().to_owned()).map_err(|error| error.to_string())
}

fn git_worktree_paths(git: &Path, repository_root: &Path) -> Result<BTreeSet<PathBuf>, String> {
    let output = reporting_git_output(
        git,
        repository_root,
        &["worktree", "list", "--porcelain", "-z"],
    )?;
    let output = String::from_utf8(output)
        .map_err(|error| format!("Git returned non-UTF-8 worktree metadata: {error}"))?;
    Ok(output
        .split('\0')
        .filter_map(|field| field.strip_prefix("worktree "))
        .map(PathBuf::from)
        .collect())
}

fn git_sha_for(git: &Path, directory: &Path) -> Result<GitSha, ControlError> {
    let output = control_git_command(git, directory)
        .args(["rev-parse", "HEAD^{commit}"])
        .output()
        .map_err(|error| ControlError::io("resolve Git HEAD", directory, &error))?;
    if !output.status.success() {
        return Err(ControlError::new(
            "git_error",
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    GitSha::new(String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .map_err(ControlError::protocol)
}

fn validate_declared_base_sha(
    git: &Path,
    repository: &Path,
    value: &str,
) -> Result<GitSha, ControlError> {
    if value.len() < 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ControlError::new(
            "base_sha_abbreviated",
            "declared base must be a full 40- or 64-character object id",
        ));
    }
    let sha = GitSha::new(value.to_owned()).map_err(|_| {
        ControlError::new(
            "base_sha_invalid",
            "declared base must be a full 40- or 64-character hexadecimal object id",
        )
    })?;
    let output = control_git_command(git, repository)
        .args(["cat-file", "-t"])
        .arg(sha.as_str())
        .output()
        .map_err(|error| ControlError::io("validate declared base object", repository, &error))?;
    if !output.status.success() {
        return Err(ControlError::new(
            "base_sha_unknown",
            format!("declared base `{sha}` does not exist in the workspace repository"),
        ));
    }
    let kind = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if kind != "commit" {
        return Err(ControlError::new(
            "base_sha_not_commit",
            format!("declared base `{sha}` resolves to `{kind}`, not a commit"),
        ));
    }
    Ok(sha)
}

fn verify_candidate_head(
    git: &Path,
    directory: &Path,
    base_sha: &GitSha,
    sha: &GitSha,
) -> Result<(), ControlError> {
    let output = control_git_command(git, directory)
        .args(["cat-file", "-e"])
        .arg(format!("{}^{{commit}}", sha.as_str()))
        .output()
        .map_err(|error| ControlError::io("verify candidate commit", directory, &error))?;
    if !output.status.success() {
        return Err(ControlError::new(
            "candidate_not_found",
            format!(
                "candidate {} is not a commit in {}",
                sha,
                directory.display()
            ),
        ));
    }
    let head = git_sha_for(git, directory)?;
    if &head != sha {
        return Err(ControlError::new(
            "candidate_not_worktree_head",
            format!("candidate {sha} is not the current HEAD {head} of the assigned worktree"),
        )
        .with_details(json!({ "candidate_sha": sha, "head_sha": head, "path": directory })));
    }
    let ancestry = control_git_command(git, directory)
        .args(["merge-base", "--is-ancestor"])
        .arg(base_sha.as_str())
        .arg(sha.as_str())
        .status()
        .map_err(|error| ControlError::io("verify candidate ancestry", directory, &error))?;
    if !ancestry.success() {
        return Err(ControlError::new(
            "candidate_base_mismatch",
            format!("candidate {sha} does not descend from request base {base_sha}"),
        ));
    }
    Ok(())
}

fn resolve_target(supervisor: &Supervisor, value: &str) -> Result<MessageTarget, ControlError> {
    if value.eq_ignore_ascii_case("primary") {
        return Ok(MessageTarget::Primary);
    }
    if value.eq_ignore_ascii_case("workspace") {
        return Ok(MessageTarget::Workspace);
    }
    if let Ok(actor_id) = ActorId::new(value.to_owned()) {
        if supervisor.actor(&actor_id).is_some() {
            return Ok(MessageTarget::Actor(actor_id));
        }
    }
    let team_id = TeamId::new(value.to_owned()).map_err(ControlError::protocol)?;
    if supervisor.team(&team_id).is_some() {
        Ok(MessageTarget::Team(team_id))
    } else {
        Err(ControlError::not_found("message target", value))
    }
}

fn assert_target(
    requested: Option<&MessageTarget>,
    derived: MessageTarget,
    kind: &str,
) -> Result<MessageTarget, ControlError> {
    if requested.is_some_and(|target| target != &derived) {
        return Err(ControlError::invalid_request(format!(
            "--to does not match the durable target derived for `{kind}`"
        ))
        .with_details(json!({ "requested_target": requested, "derived_target": derived })));
    }
    Ok(derived)
}

fn required_team_target(
    requested: Option<MessageTarget>,
    kind: &str,
) -> Result<MessageTarget, ControlError> {
    match requested {
        Some(target @ MessageTarget::Team(_)) => Ok(target),
        Some(_) => Err(ControlError::invalid_request(format!(
            "message kind `{kind}` requires --to to identify a team"
        ))),
        None => Err(ControlError::invalid_request(format!(
            "message kind `{kind}` requires --to"
        ))),
    }
}

fn target_matches(
    target: &MessageTarget,
    actor: &Actor,
    active_primary: Option<&ActorRef>,
) -> bool {
    match target {
        MessageTarget::Primary => active_primary == Some(&actor.actor_ref()),
        MessageTarget::Team(team_id) => actor.team_id.as_ref() == Some(team_id),
        MessageTarget::Actor(actor_id) => actor.actor_id == *actor_id,
        MessageTarget::Workspace => true,
    }
}

fn delivery_visible_to_exact_actor_generation(
    delivery: &DeliverySnapshot,
    actor: &Actor,
    supervisor: &Supervisor,
) -> bool {
    if !target_matches(
        &delivery.envelope.target,
        actor,
        supervisor.active_primary().as_ref(),
    ) {
        return false;
    }
    if matches!(
        delivery.envelope.target,
        MessageTarget::Primary | MessageTarget::Workspace
    ) && delivery
        .required_recipients
        .contains(&DeliveryRecipient::Primary)
        && actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
        && actor.team_id.is_none()
        && supervisor.active_primary().as_ref() == Some(&actor.actor_ref())
    {
        delivery
            .required_recipients
            .contains(&DeliveryRecipient::Primary)
    } else {
        let current_team_epoch = actor
            .team_id
            .as_ref()
            .and_then(|team_id| supervisor.team(team_id))
            .map(|team| team.epoch);
        delivery.required_recipients.iter().any(|recipient| {
            matches!(recipient, DeliveryRecipient::Actor(candidate)
                if candidate.actor == actor.actor_ref()
                    && Some(candidate.team_epoch) == current_team_epoch)
        })
    }
}

fn readable_message_ids(
    supervisor: &Supervisor,
    actor: &Actor,
    actor_ref: &ActorRef,
) -> Result<Vec<MessageId>, ControlError> {
    if actor.status == ActorStatus::Stopped {
        // A stopped Primary no longer owns the logical Primary mailbox. Direct
        // actor history remains available through include-acked inspection.
        return Ok(Vec::new());
    }
    supervisor
        .unacknowledged_message_ids_for(actor_ref)
        .map_err(ControlError::core)
}

fn deferred_wake(error: &ControlError) -> Value {
    json!({
        "status": "deferred",
        "reason": {
            "code": error.code,
            "message": error.message,
            "hint": error.hint,
            "details": error.details,
        },
    })
}

const fn apply_name(outcome: ApplyOutcome) -> &'static str {
    match outcome {
        ApplyOutcome::Applied => "applied",
        ApplyOutcome::Duplicate => "duplicate",
    }
}

const fn ack_name(outcome: AckOutcome) -> &'static str {
    match outcome {
        AckOutcome::Acknowledged => "acknowledged",
        AckOutcome::Duplicate => "duplicate",
    }
}

const fn initial_prompt_delivery_name(delivery: InitialPromptDelivery) -> &'static str {
    match delivery {
        InitialPromptDelivery::Unsupported => "unsupported",
        InitialPromptDelivery::CommandArgument => "command_argument",
        InitialPromptDelivery::AfterSessionReady => "after_session_ready",
    }
}

fn implementation_prompt(
    role: &str,
    profile_role: &str,
    actor: &ActorRef,
    team: &TeamId,
) -> Result<String, ControlError> {
    let executable = std::env::current_exe().map_err(|error| {
        ControlError::new(
            "executable_discovery_failed",
            format!("could not resolve the current AGSV executable: {error}"),
        )
    })?;
    if !executable.is_absolute() {
        return Err(ControlError::new(
            "executable_discovery_failed",
            "the current AGSV executable path is not absolute",
        ));
    }
    let executable = executable.to_str().ok_or_else(|| {
        ControlError::new(
            "executable_discovery_failed",
            "the current AGSV executable path is not valid UTF-8",
        )
    })?;
    let command = shell_single_quote(executable);
    let scope = if profile_role == ActorRole::Implementation.as_str() {
        "Stay within this top-level Implementation Orchestrator role.".to_owned()
    } else {
        format!("Stay within the configured top-level `{profile_role}` actor role.")
    };
    Ok(format!(
        "{role}\n\nYou are actor `{}` for team `{team}`. The AGSV control command for every invocation in this session is {command}; use that absolute, safely quoted path rather than assuming `agsv` is on PATH. From this managed worktree, first run `{command} --json context --bootstrap`, then read your authenticated inbox once with `{command} --json message inbox` and acknowledge handled messages without an `--actor` override. If the inbox is empty, reply only in this managed session turn that you are ready and end the launch turn immediately; do not send a protocol message without request context, inspect the repository, sleep, or poll until AGSV sends a durable inbox notification. Linked worktrees share the workspace through their Git common-directory identity, so do not add a Primary `--workspace` path. {scope}",
        actor.actor_id,
    ))
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn reject_managed_symlink(path: &Path) -> Result<(), ControlError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ControlError::new(
            "unsafe_path",
            format!(
                "managed worktree path must not be a symlink: {}",
                path.display()
            ),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ControlError::io(
            "inspect managed worktree path",
            path,
            &error,
        )),
    }
}

fn canonicalize_durable_path_allow_missing(path: &Path) -> Result<PathBuf, ControlError> {
    if !path.is_absolute() {
        return Err(ControlError::new(
            "unsafe_working_directory",
            "durable session working directory must be absolute",
        )
        .with_details(json!({ "working_directory": path })));
    }
    match fs::canonicalize(path) {
        Ok(canonical) => return Ok(canonical),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) => {}
        Err(error) => {
            return Err(ControlError::io(
                "canonicalize durable session working directory",
                path,
                &error,
            ));
        }
    }

    let mut canonical = PathBuf::new();
    let mut missing_suffix = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => canonical.push(prefix.as_os_str()),
            Component::RootDir => canonical.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if missing_suffix.pop().is_none() && (!canonical.pop() || !canonical.is_absolute())
                {
                    return Err(ControlError::new(
                        "unsafe_working_directory",
                        "durable session working directory escapes its filesystem root",
                    )
                    .with_details(json!({ "working_directory": path })));
                }
            }
            Component::Normal(segment) if !missing_suffix.is_empty() => {
                missing_suffix.push(segment.to_os_string());
            }
            Component::Normal(segment) => {
                let candidate = canonical.join(segment);
                match fs::canonicalize(&candidate) {
                    Ok(resolved) => canonical = resolved,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                        ) =>
                    {
                        missing_suffix.push(segment.to_os_string());
                    }
                    Err(error) => {
                        return Err(ControlError::io(
                            "canonicalize durable session working directory",
                            &candidate,
                            &error,
                        ));
                    }
                }
            }
        }
    }
    for segment in missing_suffix {
        canonical.push(segment);
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{
        ActorLaunchSettings, ActorProfileSettings, ControlPlane, ControlSettings,
        LEGACY_IMPLEMENTATION_PROFILE, LEGACY_RUNTIME_ID, MessageSendArgs, ProfileMode,
        ReviewCheckSettings, ReviewSettings, ReviewToolVersionSettings, RuntimeCatalog,
        TeamProfileSettings, activate_primary_for_profile, apply_envelope, ensure_team_actor,
        ensure_team_profile, implementation_prompt, now_ms, session_name, sha256_hex,
        shell_single_quote, validate_message_retry,
    };
    use crate::backend::{
        LAYOUT_FAILURE_BACKEND_ID, PERSISTED_SHUTDOWN_BACKEND_ID, SessionDriver,
        clear_before_fake_stop, clear_concurrent_before_fake_stop, fake_stop_count,
        persisted_shutdown_stop_count, reset_fake_stop_count, reset_persisted_shutdown_stop_count,
        set_before_fake_stop, set_concurrent_before_fake_stop,
    };
    use crate::caller::CallerBinding;
    use crate::store::{
        ActorShutdownCommit, SessionRecord, StateStore, TeamWorktreeOwnership, TeamWorktreeStatus,
    };
    use agsv_core::{ApplyOutcome, Supervisor};
    use agsv_protocol::{
        Acknowledgement, ActorDeliveryRecipient, ActorEpoch, ActorId, ActorRef, ActorStatus,
        AuditEvent, AuditEventKind, Cancellation, Candidate, CandidateReady, CausalMessage,
        ConflictNotice, ConsultationRequest, DecisionId, DeliveryRecipient,
        DeliveryRetirementReason, DeliverySnapshot, Envelope, EnvelopeHeader, EvidenceKind, GitSha,
        ImplementationRequest, IntegrationComplete, Message, MessageId, MessageTarget,
        PROTOCOL_VERSION, PayloadDigest, PolicyRevision, PrimaryDirective, PrimaryEpoch,
        ProgressUpdate, RequestId, ReviewDecision, ReviewRecoveryState, ReviewSessionId,
        ReviewSessionStatus, ReviewVerdict, RunControlAction, RunId, TeamEpoch, TeamId, TeamStatus,
        TimestampMillis, WorkspaceId,
    };
    use agsv_runtime::{
        AdapterError, AgentRuntime, CapabilitySupport, InitialPromptDelivery, RuntimeCapabilities,
        RuntimeDiagnostics, RuntimeId, RuntimeInvocation, RuntimeLaunchPolicy,
        RuntimeLaunchRequest, RuntimeRegistry, RuntimeResumeRequest,
    };
    use agsv_session::{SessionPlacement, SplitDirection};
    use rusqlite::Connection;
    use serde_json::json;

    fn actor_delivery_recipient(actor: ActorRef, team_epoch: TeamEpoch) -> DeliveryRecipient {
        DeliveryRecipient::Actor(ActorDeliveryRecipient { actor, team_epoch })
    }

    struct FixtureRuntime {
        id: RuntimeId,
        launch_count: AtomicU64,
    }

    impl FixtureRuntime {
        fn new() -> Self {
            Self::with_id("fixture-runtime")
        }

        fn with_id(id: &str) -> Self {
            Self {
                id: RuntimeId::new(id).unwrap(),
                launch_count: AtomicU64::new(0),
            }
        }

        fn launch_count(&self) -> u64 {
            self.launch_count.load(Ordering::Relaxed)
        }
    }

    impl AgentRuntime for FixtureRuntime {
        fn id(&self) -> &RuntimeId {
            &self.id
        }

        fn launch_invocation(
            &self,
            request: RuntimeLaunchRequest<'_>,
        ) -> Result<RuntimeInvocation, AdapterError> {
            self.launch_count.fetch_add(1, Ordering::Relaxed);
            Ok(RuntimeInvocation {
                program: self.id.to_string(),
                arguments: vec!["fixture-launch".to_owned()],
                initial_prompt: request.initial_prompt.map(str::to_owned),
            })
        }

        fn resume_invocation(
            &self,
            request: RuntimeResumeRequest<'_>,
        ) -> Result<RuntimeInvocation, AdapterError> {
            Ok(RuntimeInvocation {
                program: self.id.to_string(),
                arguments: vec!["fixture-resume".to_owned(), request.session_id.to_owned()],
                initial_prompt: request.prompt.map(str::to_owned),
            })
        }

        fn diagnostics(&self) -> RuntimeDiagnostics {
            RuntimeDiagnostics {
                runtime_id: self.id.clone(),
                program: self.id.to_string(),
                available: true,
                version: Some("fixture".to_owned()),
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

    struct FixtureDefaultRegistry {
        inner: RuntimeRegistry,
        default_id: RuntimeId,
    }

    impl FixtureDefaultRegistry {
        fn new() -> Self {
            let mut inner = RuntimeRegistry::new();
            let fixture = Arc::new(FixtureRuntime::new());
            let default_id = fixture.id().clone();
            inner.register(fixture).unwrap();
            Self { inner, default_id }
        }
    }

    impl RuntimeCatalog for FixtureDefaultRegistry {
        fn select(
            &self,
            configured_id: Option<&str>,
        ) -> Result<Arc<dyn AgentRuntime>, AdapterError> {
            self.inner
                .select(configured_id.or(Some(self.default_id.as_str())))
        }

        fn ids(&self) -> Vec<String> {
            self.inner.ids().map(ToString::to_string).collect()
        }
    }

    fn legacy_settings(root: PathBuf, state_directory: PathBuf, runtime: &str) -> ControlSettings {
        let primary = ActorProfileSettings {
            name: "primary".to_owned(),
            role: "primary".to_owned(),
            capabilities: BTreeSet::from(["human_facing_primary".to_owned()]),
            launch: ActorLaunchSettings::Bound,
            role_file: PathBuf::from("roles/primary.md"),
            role_instructions: "primary".to_owned(),
            role_source: "builtin".to_owned(),
        };
        let implementation = ActorProfileSettings {
            name: "implementation".to_owned(),
            role: "implementation".to_owned(),
            capabilities: BTreeSet::from(["implementation_execution".to_owned()]),
            launch: ActorLaunchSettings::Runtime {
                runtime: runtime.to_owned(),
                model: "gpt-test".to_owned(),
                reasoning_effort: "max".to_owned(),
            },
            role_file: PathBuf::from("roles/implementation.md"),
            role_instructions: "implementation".to_owned(),
            role_source: "builtin".to_owned(),
        };
        ControlSettings {
            workspace: root,
            state_directory,
            config_source: "builtin".to_owned(),
            integration_branch: None,
            backend: "fake".to_owned(),
            persist_profile_snapshots: false,
            primary_profile: "primary".to_owned(),
            default_team_profile: "implementation".to_owned(),
            agent_profiles: BTreeMap::from([
                (primary.name.clone(), primary),
                (implementation.name.clone(), implementation),
            ]),
            team_profiles: BTreeMap::from([(
                "implementation".to_owned(),
                TeamProfileSettings {
                    name: "implementation".to_owned(),
                    actor_profile: "implementation".to_owned(),
                    desired_instances: 1,
                    assignment_policy: "first_healthy".to_owned(),
                },
            )]),
            runtime_adapter_availability: BTreeMap::new(),
            max_panes_per_tab: 2,
            place_first_implementation_with_primary: true,
            tab_label_strategy: "sequence".to_owned(),
            pane_label_template: "{session_label}".to_owned(),
            split_direction: "right".to_owned(),
            focus_new_sessions: false,
            primary_lease_seconds: 3_600,
            actor_heartbeat_seconds: 300,
            review: ReviewSettings::default(),
        }
    }

    fn profiled_settings(
        root: PathBuf,
        state_directory: PathBuf,
        runtime: &str,
        desired_instances: u32,
        assignment_policy: &str,
    ) -> ControlSettings {
        let mut settings = legacy_settings(root, state_directory, runtime);
        settings.persist_profile_snapshots = true;
        let team = settings
            .team_profiles
            .get_mut(LEGACY_IMPLEMENTATION_PROFILE)
            .unwrap();
        team.desired_instances = desired_instances;
        team.assignment_policy = assignment_policy.to_owned();
        settings
    }

    struct FixtureRuntimeCatalog {
        runtime: Arc<FixtureRuntime>,
    }

    impl RuntimeCatalog for FixtureRuntimeCatalog {
        fn select(
            &self,
            configured_id: Option<&str>,
        ) -> Result<Arc<dyn AgentRuntime>, AdapterError> {
            let requested = configured_id.unwrap_or_else(|| self.runtime.id().as_str());
            let requested = RuntimeId::new(requested)
                .map_err(|error| AdapterError::InvalidRuntimeId(error.to_string()))?;
            if &requested == self.runtime.id() {
                Ok(self.runtime.clone())
            } else {
                Err(AdapterError::UnknownRuntime(requested))
            }
        }

        fn ids(&self) -> Vec<String> {
            vec![self.runtime.id().to_string()]
        }
    }

    fn open_fixture_plane(
        settings: ControlSettings,
        runtime: &Arc<FixtureRuntime>,
    ) -> ControlPlane {
        ControlPlane::open_with_runtime_registry(
            settings,
            &FixtureRuntimeCatalog {
                runtime: runtime.clone(),
            },
        )
        .unwrap()
    }

    #[test]
    fn stale_session_observations_do_not_resurrect_status_or_checkpoint() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let linked = temporary.path().join("linked");
        init_test_repository(&root, &linked);
        let runtime = Arc::new(FixtureRuntime::new());
        let plane = open_fixture_plane(
            legacy_settings(
                root.clone(),
                temporary.path().join("state"),
                runtime.id().as_str(),
            ),
            &runtime,
        );

        let mut status_observation = SessionRecord {
            actor_id: "impl-stale-status".to_owned(),
            team_id: Some("team-stale-observation".to_owned()),
            working_directory: root.clone(),
            backend: "fake".to_owned(),
            runtime: Some(runtime.id().to_string()),
            external_id: Some("external-stale-status".to_owned()),
            resume_token: Some("resume-stale-status".to_owned()),
            status: "launching".to_owned(),
            launch_key: "launch-stale-status".to_owned(),
            updated_at_ms: 10,
            row_revision: 0,
        };
        status_observation.row_revision = plane.store.upsert_session(&status_observation).unwrap();
        let mut newer_status = status_observation.clone();
        newer_status.status = "working".to_owned();
        newer_status.updated_at_ms = 30;
        newer_status.row_revision = plane.store.upsert_session(&newer_status).unwrap();

        let persisted = plane
            .persist_observed_session_status(&status_observation, "idle", 20)
            .unwrap();
        assert_eq!(persisted.status, "working");
        assert_eq!(persisted.updated_at_ms, 30);
        assert_eq!(persisted.row_revision, newer_status.row_revision);

        let mut checkpoint_observation = SessionRecord {
            actor_id: "impl-stale-checkpoint".to_owned(),
            team_id: Some("team-stale-observation".to_owned()),
            working_directory: root,
            backend: "fake".to_owned(),
            runtime: Some(runtime.id().to_string()),
            external_id: None,
            resume_token: None,
            status: "launching".to_owned(),
            launch_key: "launch-stale-checkpoint".to_owned(),
            updated_at_ms: 10,
            row_revision: 0,
        };
        checkpoint_observation.row_revision =
            plane.store.upsert_session(&checkpoint_observation).unwrap();
        let mut newer_checkpoint = checkpoint_observation.clone();
        newer_checkpoint.resume_token = Some("newer-checkpoint".to_owned());
        newer_checkpoint.updated_at_ms = 30;
        newer_checkpoint.row_revision = plane.store.upsert_session(&newer_checkpoint).unwrap();

        let persisted = plane
            .persist_session_checkpoint(&checkpoint_observation, "stale-checkpoint", 20)
            .unwrap();
        assert_eq!(persisted.resume_token.as_deref(), Some("newer-checkpoint"));
        assert_eq!(persisted.updated_at_ms, 30);
        assert_eq!(persisted.row_revision, newer_checkpoint.row_revision);
    }

    fn activate_test_primary(plane: &ControlPlane, actor_id: &str) -> ActorRef {
        plane.start(&json!({})).unwrap();
        plane
            .store
            .mutate("test.primary", &json!({}), 1, |state| {
                let primary = state
                    .activate_primary(ActorId::new(actor_id).unwrap())
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&primary, TimestampMillis(1))
                    .map_err(super::ControlError::core)?;
                Ok(primary)
            })
            .unwrap()
            .1
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn self_shutdown_is_durable_before_backend_stop_terminal_and_exactly_replayable() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let linked = temporary.path().join("linked");
        init_test_repository(&root, &linked);
        let runtime = Arc::new(FixtureRuntime::new());
        let plane = open_fixture_plane(
            legacy_settings(root, temporary.path().join("state"), runtime.id().as_str()),
            &runtime,
        );
        let primary = activate_test_primary(&plane, "primary-self-shutdown");
        let observed_at = super::now_ms().unwrap();
        plane
            .store
            .mutate("test.primary_current", &json!({}), observed_at, |state| {
                state
                    .heartbeat(&primary, TimestampMillis(observed_at))
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        create_profiled_test_team(&plane, &linked, "create-shutdown-expiry-fixture");
        plane
            .store
            .bind_actor("test_pane", "primary-shutdown", &primary, now_ms().unwrap())
            .unwrap();
        plane.set_test_authenticated_actor(primary.clone());
        plane.ensure_primary_notification_session(&primary).unwrap();
        let primary_session_revision = plane
            .store
            .session(primary.actor_id.as_str())
            .unwrap()
            .unwrap()
            .row_revision;
        reset_fake_stop_count();
        let mismatch = plane
            .execute(
                "actor.shutdown",
                &json!({
                    "actor": "primary-someone-else",
                    "operation_id": "mismatched-self-shutdown",
                }),
            )
            .unwrap_err();
        assert_eq!(mismatch.code, "actor_identity_mismatch");
        assert_eq!(fake_stop_count(), 0);
        assert_eq!(
            plane
                .store
                .load()
                .unwrap()
                .1
                .actor(&primary.actor_id)
                .unwrap()
                .status,
            ActorStatus::Healthy
        );
        let store = plane.store.clone();
        let observed_actor = primary.clone();
        let request = json!({
            "reason": "the Primary is handing control back to the supervisor",
            "operation_id": "primary-self-shutdown-a",
        });
        let observed_request = request.clone();
        set_before_fake_stop(move |record| {
            let (revision, supervisor, controller_active) = store.load().unwrap();
            assert!(
                controller_active,
                "actor shutdown must not stop the controller"
            );
            assert_eq!(
                supervisor.actor(&observed_actor.actor_id).unwrap().status,
                ActorStatus::Stopped
            );
            assert!(supervisor.active_primary().is_none());
            assert_eq!(record.status, "stopped");
            assert_eq!(record.row_revision, primary_session_revision + 1);
            let durable_session = store.session(record.actor_id.as_str()).unwrap().unwrap();
            assert_eq!(durable_session.status, "stopped");
            assert_eq!(durable_session.row_revision, record.row_revision);
            let replay = store
                .operation_result(
                    "primary-self-shutdown-a",
                    "actor.shutdown",
                    &observed_request,
                )
                .unwrap()
                .expect("the replay result must commit before the backend stop");
            assert_eq!(replay["revision"], revision);
        });

        let result = plane.execute("actor.shutdown", &request).unwrap();
        clear_before_fake_stop();
        assert_eq!(fake_stop_count(), 1);
        assert_eq!(result["status"], "stopped");
        assert_eq!(result["session_status"], "stopped");
        assert_eq!(result["controller_active"], true);
        assert_eq!(result["backend_stop"], "requested_after_commit");
        let revision = result["revision"].as_u64().unwrap();

        let replay = plane.execute("actor.shutdown", &request).unwrap();
        assert_eq!(replay, result);
        assert_eq!(fake_stop_count(), 1);
        assert_eq!(plane.store.load().unwrap().0, revision);

        // Reproduce the narrow race in which a second invocation checked for
        // a result before the first transaction committed, then acquired its
        // claim only after that commit. The store must replay from inside the
        // same immediate transaction and must not expose a session for another
        // backend stop.
        let replay_claim = "post-commit-replay-claim";
        plane
            .store
            .claim_operation(
                "primary-self-shutdown-a",
                "actor.shutdown",
                &request,
                replay_claim,
                now_ms().unwrap(),
            )
            .unwrap();
        let raced_replay = plane
            .store
            .declare_actor_shutdown(
                &primary,
                Some("the Primary is handing control back to the supervisor"),
                "primary-self-shutdown-a",
                replay_claim,
                &request,
                now_ms().unwrap(),
            )
            .unwrap();
        match raced_replay {
            ActorShutdownCommit::Replayed(raced_replay) => assert_eq!(raced_replay, result),
            ActorShutdownCommit::Applied { .. } => {
                panic!("an already committed shutdown must replay without backend work")
            }
        }
        let replay_claim_count = Connection::open(plane.store.path())
            .unwrap()
            .query_row(
                "SELECT count(*) FROM operation_claims
                 WHERE operation_id = 'primary-self-shutdown-a'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(replay_claim_count, 0);
        assert_eq!(fake_stop_count(), 1);
        assert_eq!(plane.store.load().unwrap().0, revision);

        // A different operation ID that crossed the mutable precheck must be
        // fenced by the transaction's re-read of the terminal actor status.
        let raced_request = json!({ "operation_id": "primary-self-shutdown-raced" });
        let raced_claim = "post-terminal-distinct-claim";
        plane
            .store
            .claim_operation(
                "primary-self-shutdown-raced",
                "actor.shutdown",
                &raced_request,
                raced_claim,
                now_ms().unwrap(),
            )
            .unwrap();
        let raced_error = plane
            .store
            .declare_actor_shutdown(
                &primary,
                None,
                "primary-self-shutdown-raced",
                raced_claim,
                &raced_request,
                now_ms().unwrap(),
            )
            .unwrap_err();
        assert_eq!(raced_error.code, "actor_binding_stopped");
        plane
            .store
            .release_operation("primary-self-shutdown-raced", raced_claim)
            .unwrap();
        assert_eq!(fake_stop_count(), 1);
        assert_eq!(plane.store.load().unwrap().0, revision);

        let conflict = plane
            .execute(
                "actor.shutdown",
                &json!({
                    "reason": "different input",
                    "operation_id": "primary-self-shutdown-a",
                }),
            )
            .unwrap_err();
        assert_eq!(conflict.code, "operation_id_conflict");
        assert_eq!(fake_stop_count(), 1);
        assert_eq!(plane.store.load().unwrap().0, revision);
        let second_declaration = plane
            .execute(
                "actor.shutdown",
                &json!({ "operation_id": "primary-self-shutdown-b" }),
            )
            .unwrap_err();
        assert_eq!(second_declaration.code, "actor_binding_stopped");
        assert_eq!(fake_stop_count(), 1);
        assert_eq!(plane.store.load().unwrap().0, revision);

        let (_, stopped_supervisor, _) = plane.store.load().unwrap();
        let mut stopped_snapshot = stopped_supervisor.snapshot();
        let expiring_actor_id = {
            let expiring = stopped_snapshot
                .actors
                .iter_mut()
                .find(|actor| actor.team_id.is_some())
                .expect("the expiry fixture implementation must exist");
            expiring.last_heartbeat_at = Some(TimestampMillis(1));
            expiring.actor_id.clone()
        };
        Connection::open(plane.store.path())
            .unwrap()
            .execute(
                "UPDATE domain_state SET snapshot_json = ?1",
                [serde_json::to_string(&stopped_snapshot).unwrap()],
            )
            .unwrap();

        let refused = plane.execute("start", &json!({})).unwrap_err();
        assert_eq!(refused.code, "actor_binding_stopped");
        assert_eq!(refused.details["actor"], json!(primary));
        assert_eq!(plane.store.load().unwrap().0, revision);
        assert_eq!(
            plane
                .store
                .load()
                .unwrap()
                .1
                .actor(&expiring_actor_id)
                .unwrap()
                .status,
            ActorStatus::Healthy,
            "terminal refusal must run before unrelated lease expiration"
        );

        let status = plane.execute("status", &json!({})).unwrap();
        assert_eq!(status["revision"], revision);
        let context = plane.execute("context", &json!({})).unwrap();
        assert_eq!(context["actor_ref"], json!(primary));
        assert_eq!(context["actor"]["status"], "stopped");
        assert_eq!(plane.store.load().unwrap().0, revision);
        let stopped_session_revision = plane
            .store
            .session(primary.actor_id.as_str())
            .unwrap()
            .unwrap()
            .row_revision;

        StateStore::interrupt_primary_bootstrap_before_commit();
        let interrupted = plane
            .bootstrap_bound_actor(
                &CallerBinding::test("test_pane", "primary-shutdown"),
                Some(primary.actor_id.as_str()),
            )
            .unwrap_err();
        assert_eq!(interrupted.code, "test_primary_bootstrap_interrupted");
        let (_, still_stopped, _) = plane.store.load().unwrap();
        assert_eq!(plane.store.load().unwrap().0, revision);
        assert_eq!(
            still_stopped.actor(&primary.actor_id).unwrap().status,
            ActorStatus::Stopped
        );
        assert_eq!(
            plane
                .store
                .actor_binding("test_pane", "primary-shutdown")
                .unwrap()
                .unwrap()
                .actor,
            primary
        );
        assert_eq!(
            plane
                .store
                .session(primary.actor_id.as_str())
                .unwrap()
                .unwrap()
                .status,
            "stopped"
        );
        assert_eq!(
            plane
                .store
                .session(primary.actor_id.as_str())
                .unwrap()
                .unwrap()
                .row_revision,
            stopped_session_revision
        );
        let replacement = plane
            .bootstrap_bound_actor(
                &CallerBinding::test("test_pane", "primary-shutdown"),
                Some(primary.actor_id.as_str()),
            )
            .unwrap();
        assert!(replacement.actor_epoch > primary.actor_epoch);
        let (_, restarted, _) = plane.store.load().unwrap();
        assert_eq!(restarted.active_primary(), Some(replacement.clone()));
        assert_eq!(
            plane
                .store
                .actor_binding("test_pane", "primary-shutdown")
                .unwrap()
                .unwrap()
                .actor,
            replacement
        );
        let restarted_session = plane
            .store
            .session(replacement.actor_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(restarted_session.status, "idle");
        assert_eq!(restarted_session.row_revision, stopped_session_revision + 1);
    }

    #[test]
    fn stopped_primary_is_superseded_for_every_authenticated_read_after_takeover() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let linked = temporary.path().join("linked");
        init_test_repository(&root, &linked);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-stopped-primary-takeover",
        ));
        let settings = legacy_settings(root, temporary.path().join("state"), runtime.id().as_str());
        let mut old_plane = open_fixture_plane(settings.clone(), &runtime);
        let old_primary = activate_test_primary(&old_plane, "primary-stopped-before-takeover");
        let observed_at = now_ms().unwrap();
        old_plane
            .store
            .mutate(
                "test.stopped_primary_takeover.current",
                &json!({ "primary": old_primary }),
                observed_at,
                |state| {
                    state
                        .heartbeat(&old_primary, TimestampMillis(observed_at))
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap();
        old_plane
            .store
            .bind_actor("test_pane", "stopped-primary-a", &old_primary, observed_at)
            .unwrap();
        old_plane.set_test_caller_binding("test_pane", "stopped-primary-a");
        old_plane
            .ensure_primary_notification_session(&old_primary)
            .unwrap();
        old_plane
            .execute(
                "actor.shutdown",
                &json!({ "operation_id": "shutdown-primary-before-takeover" }),
            )
            .unwrap();
        let stopped_revision = old_plane.store.load().unwrap().0;
        let stopped_context = old_plane.execute("context", &json!({})).unwrap();
        assert_eq!(stopped_context["actor_ref"], json!(old_primary));
        assert_eq!(stopped_context["actor"]["status"], "stopped");
        assert_eq!(old_plane.store.load().unwrap().0, stopped_revision);

        let mut replacement_plane = open_fixture_plane(settings, &runtime);
        replacement_plane.set_test_caller_binding("test_pane", "stopped-primary-b");
        let replacement = replacement_plane
            .execute("context", &json!({ "bootstrap": true }))
            .unwrap();
        assert_ne!(
            replacement["actor_ref"]["actor_id"],
            json!(old_primary.actor_id)
        );
        let revision_before_refusals = old_plane.store.load().unwrap().0;

        for (operation, request) in [
            ("context", json!({})),
            ("message.inbox", json!({})),
            ("review.show", json!({ "candidate_sha": "a".repeat(40) })),
        ] {
            let refusal = old_plane.execute(operation, &request).unwrap_err();
            assert_eq!(refusal.code, "stale_actor_binding", "{operation}");
            assert_eq!(
                refusal.details["reason"], "primary_generation_superseded",
                "{operation}"
            );
            assert!(
                refusal
                    .hint
                    .as_deref()
                    .is_some_and(|hint| hint.contains("active Primary caller session")),
                "{operation} refusal must identify the valid recovery session"
            );
        }
        assert_eq!(old_plane.store.load().unwrap().0, revision_before_refusals);
        assert_eq!(
            old_plane.store.load().unwrap().1.active_primary(),
            Some(serde_json::from_value(replacement["actor_ref"].clone()).unwrap())
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn implementation_shutdown_preserves_controller_and_bootstrap_advances_binding_atomically() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::new());
        let plane = open_fixture_plane(
            legacy_settings(root, temporary.path().join("state"), runtime.id().as_str()),
            &runtime,
        );
        let primary = activate_test_primary(&plane, "primary-implementation-shutdown");
        let observed_at = super::now_ms().unwrap();
        plane
            .store
            .mutate("test.primary_current", &json!({}), observed_at, |state| {
                state
                    .heartbeat(&primary, TimestampMillis(observed_at))
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        create_profiled_test_team(&plane, &team_root, "create-implementation-shutdown");
        let (_, supervisor, _) = plane.store.load().unwrap();
        let team_id = TeamId::new("team-workers").unwrap();
        let shutdown_team_epoch = supervisor.team(&team_id).unwrap().epoch;
        let implementation = supervisor
            .actor(&ActorId::new("impl-workers-1").unwrap())
            .unwrap()
            .actor_ref();
        plane
            .store
            .bind_actor(
                "test_pane",
                "implementation-shutdown",
                &implementation,
                observed_at,
            )
            .unwrap();
        plane.set_test_authenticated_actor(implementation.clone());
        let implementation_session_revision = plane
            .store
            .session(implementation.actor_id.as_str())
            .unwrap()
            .unwrap()
            .row_revision;
        let shutdown = plane
            .execute(
                "actor.shutdown",
                &json!({
                    "operation_id": "implementation-self-shutdown-a",
                    "reason": "implementation handoff complete",
                }),
            )
            .unwrap();
        assert_eq!(shutdown["controller_active"], true);
        let (_, stopped, controller_active) = plane.store.load().unwrap();
        assert!(controller_active);
        assert!(stopped.active_primary().is_some());
        assert_eq!(
            stopped.actor(&implementation.actor_id).unwrap().status,
            ActorStatus::Stopped
        );
        let stopped_session_revision = plane
            .store
            .session(implementation.actor_id.as_str())
            .unwrap()
            .unwrap()
            .row_revision;
        assert_eq!(
            stopped_session_revision,
            implementation_session_revision + 1
        );

        let replacement = plane
            .bootstrap_bound_actor(
                &CallerBinding::test("test_pane", "implementation-shutdown"),
                Some(implementation.actor_id.as_str()),
            )
            .unwrap();
        assert!(replacement.actor_epoch > implementation.actor_epoch);
        assert_eq!(
            plane
                .store
                .actor_binding("test_pane", "implementation-shutdown")
                .unwrap()
                .unwrap()
                .actor,
            replacement
        );
        let replacement_session = plane
            .store
            .session(replacement.actor_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(replacement_session.status, "idle");
        assert_eq!(
            replacement_session.row_revision,
            stopped_session_revision + 1
        );
        let (_, running, controller_active) = plane.store.load().unwrap();
        assert!(controller_active);
        let bootstrap_team_epoch = running.team(&team_id).unwrap().epoch;
        assert!(bootstrap_team_epoch > shutdown_team_epoch);
        assert_eq!(
            running.actor(&replacement.actor_id).unwrap().status,
            ActorStatus::Healthy
        );
        assert!(running.active_primary().is_some());
        plane.set_test_authenticated_actor(primary.clone());
        let events = plane.events(&json!({ "limit": 100 })).unwrap();
        let control_events = events["control_events"].as_array().unwrap();
        for (operation, actor, team_epoch) in [
            ("actor.shutdown", &implementation, shutdown_team_epoch),
            (
                "actor.self_bootstrapped",
                &replacement,
                bootstrap_team_epoch,
            ),
        ] {
            assert!(
                control_events.iter().any(|event| {
                    event["operation"] == operation
                        && (event["detail"]["actor"] == json!(actor))
                        && event["detail"]["team_id"] == json!(team_id)
                        && event["detail"]["team_epoch"] == json!(team_epoch)
                }),
                "direct {operation} event must expose its owning team generation"
            );
        }

        // The old pane may outlive a failed backend stop while another pane
        // replaces its actor generation. Its superseded binding must remain
        // fenced before even unauthenticated state mutations such as `start`.
        let replacement_revision = plane.store.load().unwrap().0;
        plane.set_test_authenticated_actor(implementation.clone());
        let stale_refusal = plane.execute("start", &json!({})).unwrap_err();
        assert_eq!(stale_refusal.code, "stale_actor_binding");
        assert_eq!(stale_refusal.details["actor"], json!(implementation));
        assert_eq!(
            stale_refusal.details["reason"],
            "team_generation_superseded"
        );
        assert_eq!(plane.store.load().unwrap().0, replacement_revision);
        let readable_status = plane.execute("status", &json!({})).unwrap();
        assert_eq!(readable_status["revision"], replacement_revision);
        assert_eq!(plane.store.load().unwrap().0, replacement_revision);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn persisted_session_match_requires_explicit_bootstrap_before_authentication() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::new());
        let mut settings =
            legacy_settings(root, temporary.path().join("state"), runtime.id().as_str());
        settings.actor_heartbeat_seconds = 0;
        let mut plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-explicit-bootstrap");
        create_profiled_test_team(&plane, &team_root, "create-explicit-bootstrap-team");
        let implementation = plane
            .store
            .load()
            .unwrap()
            .1
            .actor(&ActorId::new("impl-workers-1").unwrap())
            .unwrap()
            .actor_ref();
        let mut persisted = plane
            .store
            .session(implementation.actor_id.as_str())
            .unwrap()
            .unwrap();
        persisted.backend = "herdr".to_owned();
        persisted.resume_token = Some("matching-unbound-pane".to_owned());
        plane.store.upsert_session(&persisted).unwrap();
        plane.set_test_caller_binding("herdr_pane", "matching-unbound-pane");
        let (revision, before_state, before_controller_active) = plane.store.load().unwrap();
        let before_snapshot = serde_json::to_value(before_state.snapshot()).unwrap();
        let before_sessions = serde_json::to_value(plane.store.sessions().unwrap()).unwrap();
        let before_events = serde_json::to_value(plane.store.events(100).unwrap()).unwrap();

        let context_refusal = plane.execute("context", &json!({})).unwrap_err();
        assert_eq!(context_refusal.code, "actor_session_unbound");
        let shutdown_refusal = plane
            .execute(
                "actor.shutdown",
                &json!({ "operation_id": "unbound-matching-shutdown" }),
            )
            .unwrap_err();
        assert_eq!(shutdown_refusal.code, "actor_session_unbound");
        let (after_revision, after_state, after_controller_active) = plane.store.load().unwrap();
        assert_eq!(after_revision, revision);
        assert_eq!(after_controller_active, before_controller_active);
        assert_eq!(
            serde_json::to_value(after_state.snapshot()).unwrap(),
            before_snapshot
        );
        assert_eq!(
            serde_json::to_value(plane.store.sessions().unwrap()).unwrap(),
            before_sessions
        );
        assert_eq!(
            serde_json::to_value(plane.store.events(100).unwrap()).unwrap(),
            before_events
        );
        assert_eq!(
            plane
                .store
                .load()
                .unwrap()
                .1
                .actor(&implementation.actor_id)
                .unwrap()
                .status,
            ActorStatus::Healthy
        );
        assert_eq!(
            plane
                .store
                .session(implementation.actor_id.as_str())
                .unwrap()
                .unwrap()
                .status,
            "idle"
        );
        assert!(
            plane
                .store
                .actor_binding("herdr_pane", "matching-unbound-pane")
                .unwrap()
                .is_none()
        );

        let bootstrapped = plane
            .bootstrap_bound_actor(
                &CallerBinding::test("herdr_pane", "matching-unbound-pane"),
                Some(implementation.actor_id.as_str()),
            )
            .unwrap();
        assert_eq!(bootstrapped, implementation);
        assert_eq!(
            plane
                .store
                .actor_binding("herdr_pane", "matching-unbound-pane")
                .unwrap()
                .unwrap()
                .actor,
            implementation
        );
        let context = plane.execute("context", &json!({})).unwrap();
        assert_eq!(context["actor_ref"], json!(implementation));
    }

    #[test]
    fn shutdown_linearizes_against_already_admitted_mutations_and_backend_dispatch() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::new());
        let settings = legacy_settings(root, temporary.path().join("state"), runtime.id().as_str());
        let plane = open_fixture_plane(settings.clone(), &runtime);
        let primary = activate_test_primary(&plane, "primary-shutdown-linearization");
        let observed_at = now_ms().unwrap();
        plane
            .store
            .mutate("test.primary_current", &json!({}), observed_at, |state| {
                state
                    .heartbeat(&primary, TimestampMillis(observed_at))
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        plane.set_test_authenticated_actor(primary.clone());
        plane.ensure_primary_notification_session(&primary).unwrap();

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let entered_observer = entered.clone();
        let release_observer = release.clone();
        plane.set_after_caller_fence(move |operation| {
            if operation == "start" {
                entered_observer.wait();
                release_observer.wait();
            }
        });

        let start_plane = open_fixture_plane(settings.clone(), &runtime);
        let start_thread = thread::spawn(move || start_plane.execute("start", &json!({})));
        entered.wait();

        let shutdown_plane = open_fixture_plane(settings, &runtime);
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let shutdown_thread = thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = shutdown_plane.execute(
                "actor.shutdown",
                &json!({ "operation_id": "linearized-self-shutdown" }),
            );
            done_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        let premature = done_rx.recv_timeout(Duration::from_millis(250));
        let shutdown_waited = matches!(&premature, Err(mpsc::RecvTimeoutError::Timeout));
        release.wait();
        let start_result = start_thread.join().unwrap().unwrap();
        let shutdown_result = match premature {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => done_rx.recv().unwrap(),
            Err(error) => panic!("shutdown result channel failed: {error}"),
        }
        .unwrap();
        shutdown_thread.join().unwrap();
        plane.clear_after_caller_fence();

        assert!(
            shutdown_waited,
            "shutdown must wait until the already-admitted mutation completes"
        );
        assert!(
            start_result["revision"].as_u64().unwrap()
                < shutdown_result["revision"].as_u64().unwrap()
        );
        assert_eq!(
            plane.store.load().unwrap().0,
            shutdown_result["revision"].as_u64().unwrap(),
            "no mutation may commit after the stopped declaration"
        );
        assert_eq!(
            plane
                .store
                .session(primary.actor_id.as_str())
                .unwrap()
                .unwrap()
                .status,
            "stopped"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn read_only_commands_complete_during_unrelated_slow_backend_dispatch() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::new());
        let settings = legacy_settings(root, temporary.path().join("state"), runtime.id().as_str());
        let plane = open_fixture_plane(settings.clone(), &runtime);
        let primary = activate_test_primary(&plane, "primary-slow-actor-stop");
        let observed_at = now_ms().unwrap();
        plane
            .store
            .mutate("test.primary_current", &json!({}), observed_at, |state| {
                state
                    .heartbeat(&primary, TimestampMillis(observed_at))
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        create_profiled_test_team(&plane, &team_root, "create-slow-stop-team");
        let implementation = plane
            .store
            .load()
            .unwrap()
            .1
            .actor(&ActorId::new("impl-workers-1").unwrap())
            .unwrap()
            .actor_ref();
        let implementation_session = plane
            .store
            .session(implementation.actor_id.as_str())
            .unwrap()
            .unwrap();

        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let release_rx = Arc::new(Mutex::new(release_rx));
        set_concurrent_before_fake_stop(&implementation_session, {
            let release_rx = release_rx.clone();
            move |record| {
                let _ = entered_tx.send(record.actor_id.clone());
                let _ = release_rx
                    .lock()
                    .expect("fake-stop release mutex must remain available")
                    .recv();
            }
        });

        let stop_plane = open_fixture_plane(settings.clone(), &runtime);
        stop_plane.set_test_authenticated_actor_local(primary.clone());
        let stopped_actor = implementation.actor_id.to_string();
        let (stop_tx, stop_rx) = mpsc::sync_channel(1);
        let stop_thread = thread::spawn(move || {
            let result = stop_plane.execute(
                "actor.stop",
                &json!({
                    "id": stopped_actor,
                    "operation_id": "slow-unrelated-actor-stop",
                }),
            );
            let _ = stop_tx.send(result);
        });
        assert_eq!(
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            implementation.actor_id.as_str()
        );
        let revision_while_backend_blocked = plane.store.load().unwrap().0;

        let read_plane = open_fixture_plane(settings, &runtime);
        read_plane.set_test_authenticated_actor_local(primary);
        let (read_tx, read_rx) = mpsc::sync_channel(1);
        let read_thread = thread::spawn(move || {
            let result = read_plane.execute("status", &json!({})).and_then(|status| {
                read_plane.execute("doctor", &json!({})).and_then(|doctor| {
                    read_plane
                        .execute(
                            "decision.list",
                            &json!({ "team": "team-slow-stop-team", "limit": 100 }),
                        )
                        .map(|decisions| (status, doctor, decisions))
                })
            });
            let _ = read_tx.send(result);
        });
        let reads_before_release = read_rx.recv_timeout(Duration::from_secs(2));
        let reads_completed_before_release = reads_before_release.is_ok();
        let stop_finished_before_release = stop_rx.try_recv().is_ok();
        let revision_after_reads = plane.store.load().unwrap().0;

        let _ = release_tx.send(());
        let stop_result = stop_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        stop_thread.join().unwrap();
        let reads = match reads_before_release {
            Ok(result) => result,
            Err(_) => read_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        };
        read_thread.join().unwrap();
        clear_concurrent_before_fake_stop(&implementation_session);

        let (status, _doctor, decisions) = reads.unwrap();
        stop_result.unwrap();
        assert_eq!(decisions["decisions"], json!([]));
        assert_eq!(status["revision"], revision_while_backend_blocked);
        assert_eq!(revision_after_reads, revision_while_backend_blocked);
        assert!(
            reads_completed_before_release,
            "read-only commands must complete before the unrelated backend is released"
        );
        assert!(
            !stop_finished_before_release,
            "the fixture must still be blocked when read-only commands finish"
        );
        assert!(
            plane.store.load().unwrap().0 > revision_while_backend_blocked,
            "actor.stop should mutate only after its backend dispatch is released"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn another_actor_heartbeats_while_shutdown_stop_blocks_only_same_actor_bootstrap() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::new());
        let settings = profiled_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime.id().as_str(),
            2,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings.clone(), &runtime);
        activate_test_primary(&plane, "primary-concurrent-shutdown-heartbeat");
        create_profiled_test_team(&plane, &team_root, "create-two-heartbeat-actors");
        let (_, supervisor, _) = plane.store.load().unwrap();
        let implementation_a = supervisor
            .actor(&ActorId::new("impl-workers-1").unwrap())
            .unwrap()
            .actor_ref();
        let implementation_b = supervisor
            .actor(&ActorId::new("impl-workers-2").unwrap())
            .unwrap()
            .actor_ref();
        let implementation_a_session = plane
            .store
            .session(implementation_a.actor_id.as_str())
            .unwrap()
            .unwrap();
        let original_external_id = implementation_a_session.external_id.clone();
        plane
            .store
            .bind_actor(
                "test_pane",
                "shutdown-a",
                &implementation_a,
                now_ms().unwrap(),
            )
            .unwrap();
        plane
            .store
            .bind_actor(
                "test_pane",
                "heartbeat-b",
                &implementation_b,
                now_ms().unwrap(),
            )
            .unwrap();
        thread::sleep(Duration::from_millis(2));

        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let release_rx = Arc::new(Mutex::new(release_rx));
        let stop_observation_count = Arc::new(AtomicU64::new(0));
        set_concurrent_before_fake_stop(&implementation_a_session, {
            let release_rx = release_rx.clone();
            let stop_observation_count = stop_observation_count.clone();
            move |record| {
                if stop_observation_count.fetch_add(1, Ordering::SeqCst) != 0 {
                    return;
                }
                let _ = entered_tx.send(record.actor_id.clone());
                let _ = release_rx
                    .lock()
                    .expect("fake-stop release mutex must remain available")
                    .recv();
            }
        });

        // A heartbeat that has acquired shared workspace admission must drain
        // before shutdown can take exclusive admission and commit.
        let (pre_context_entered_tx, pre_context_entered_rx) = mpsc::sync_channel(1);
        let (pre_context_release_tx, pre_context_release_rx) = mpsc::sync_channel(1);
        let pre_context_release_rx = Arc::new(Mutex::new(pre_context_release_rx));
        plane.set_after_caller_fence({
            let pre_context_release_rx = pre_context_release_rx.clone();
            move |operation| {
                if operation == "context" {
                    let _ = pre_context_entered_tx.send(());
                    let _ = pre_context_release_rx
                        .lock()
                        .expect("pre-context release mutex must remain available")
                        .recv();
                }
            }
        });
        let (shutdown_attempt_tx, shutdown_attempt_rx) = mpsc::sync_channel(1);
        plane.set_operation_phase_observer("before_workspace_lock", move |operation| {
            if operation == "actor.shutdown" {
                let _ = shutdown_attempt_tx.send(());
            }
        });
        let mut pre_context_plane = open_fixture_plane(settings.clone(), &runtime);
        pre_context_plane.set_test_caller_binding("test_pane", "heartbeat-b");
        let (pre_context_tx, pre_context_rx) = mpsc::sync_channel(1);
        let pre_context_thread = thread::spawn(move || {
            let result = pre_context_plane.execute("context", &json!({}));
            let _ = pre_context_tx.send(result);
        });
        pre_context_entered_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();

        let mut shutdown_plane = open_fixture_plane(settings.clone(), &runtime);
        shutdown_plane.set_test_caller_binding("test_pane", "shutdown-a");
        let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(1);
        let shutdown_thread = thread::spawn(move || {
            let result = shutdown_plane.execute(
                "actor.shutdown",
                &json!({ "operation_id": "blocked-shutdown-a" }),
            );
            let _ = shutdown_tx.send(result);
        });
        shutdown_attempt_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        assert!(
            matches!(entered_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "shutdown must not commit while a pre-admitted heartbeat is held"
        );
        let _ = pre_context_release_tx.send(());
        pre_context_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        pre_context_thread.join().unwrap();
        plane.clear_after_caller_fence();
        plane.clear_operation_phase_observer("before_workspace_lock");
        let heartbeat_before = plane
            .store
            .load()
            .unwrap()
            .1
            .actor(&implementation_b.actor_id)
            .unwrap()
            .last_heartbeat_at
            .unwrap();
        assert_eq!(
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            implementation_a.actor_id.as_str()
        );
        let (_, stopped, _) = plane.store.load().unwrap();
        assert_eq!(
            stopped.actor(&implementation_a.actor_id).unwrap().status,
            ActorStatus::Stopped
        );
        assert_eq!(
            plane
                .store
                .session(implementation_a.actor_id.as_str())
                .unwrap()
                .unwrap()
                .status,
            "stopped"
        );
        let shutdown_revision = plane.store.load().unwrap().0;

        let (bootstrap_attempt_tx, bootstrap_attempt_rx) = mpsc::sync_channel(1);
        plane.set_operation_phase_observer("before_caller_lock", move |operation| {
            if operation == "context" {
                let _ = bootstrap_attempt_tx.send(());
            }
        });
        let mut bootstrap_plane = open_fixture_plane(settings.clone(), &runtime);
        bootstrap_plane.set_test_caller_binding("test_pane", "shutdown-a");
        let (bootstrap_tx, bootstrap_rx) = mpsc::sync_channel(1);
        let bootstrap_thread = thread::spawn(move || {
            let result = bootstrap_plane.execute("context", &json!({ "bootstrap": true }));
            let _ = bootstrap_tx.send(result);
        });
        bootstrap_attempt_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        plane.clear_operation_phase_observer("before_caller_lock");
        assert_eq!(plane.store.load().unwrap().0, shutdown_revision);
        assert_eq!(
            plane
                .store
                .actor_binding("test_pane", "shutdown-a")
                .unwrap()
                .unwrap()
                .actor,
            implementation_a
        );
        assert_eq!(
            plane
                .store
                .session(implementation_a.actor_id.as_str())
                .unwrap()
                .unwrap()
                .status,
            "stopped"
        );
        assert!(
            plane
                .store
                .events(100)
                .unwrap()
                .iter()
                .all(|event| event.operation != "actor.self_bootstrapped")
        );

        let reconcile_plane = open_fixture_plane(settings.clone(), &runtime);
        let (reconcile_started_tx, reconcile_started_rx) = mpsc::sync_channel(1);
        let (reconcile_tx, reconcile_rx) = mpsc::sync_channel(1);
        let reconcile_thread = thread::spawn(move || {
            let _ = reconcile_started_tx.send(());
            let result =
                reconcile_plane.reconcile_team_instances(&TeamId::new("team-workers").unwrap());
            let _ = reconcile_tx.send(result);
        });
        reconcile_started_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        let premature_reconcile = reconcile_rx.recv_timeout(Duration::from_millis(250));
        let premature_reconcile_debug = format!("{premature_reconcile:?}");
        let reconcile_finished_before_release = premature_reconcile.is_ok();

        let mut heartbeat_plane = open_fixture_plane(settings, &runtime);
        heartbeat_plane.set_test_caller_binding("test_pane", "heartbeat-b");
        let (heartbeat_tx, heartbeat_rx) = mpsc::sync_channel(1);
        let heartbeat_thread = thread::spawn(move || {
            let result = heartbeat_plane.execute("context", &json!({}));
            let _ = heartbeat_tx.send(result);
        });
        let heartbeat_before_release = heartbeat_rx.recv_timeout(Duration::from_secs(2));
        let heartbeat_completed_before_release = heartbeat_before_release.is_ok();
        let bootstrap_finished_before_release = bootstrap_rx.try_recv().is_ok();

        let _ = release_tx.send(());
        let shutdown_result = shutdown_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        shutdown_thread.join().unwrap();
        clear_concurrent_before_fake_stop(&implementation_a_session);
        let bootstrap_result = bootstrap_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let reconcile_result = match premature_reconcile {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                reconcile_rx.recv_timeout(Duration::from_secs(5)).unwrap()
            }
            Err(error) => panic!("reconcile result channel failed: {error}"),
        };
        bootstrap_thread.join().unwrap();
        reconcile_thread.join().unwrap();
        let heartbeat_result = match heartbeat_before_release {
            Ok(result) => result,
            Err(_) => heartbeat_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        };
        heartbeat_thread.join().unwrap();

        shutdown_result.unwrap();
        let heartbeat_context = heartbeat_result.unwrap();
        assert_eq!(heartbeat_context["actor_ref"], json!(implementation_b));
        assert!(
            heartbeat_completed_before_release,
            "another actor's context heartbeat must complete during shutdown backend dispatch"
        );
        assert!(
            !bootstrap_finished_before_release,
            "the stopped actor must not reuse its handle before backend stop returns"
        );
        assert!(
            !reconcile_finished_before_release,
            "reconcile must not replace the stopped actor while its backend stop is in flight: {premature_reconcile_debug}"
        );
        reconcile_result.unwrap();
        let bootstrap_reused_stopped_session = match bootstrap_result {
            Ok(bootstrap_context) => {
                let replacement: ActorRef =
                    serde_json::from_value(bootstrap_context["actor_ref"].clone()).unwrap();
                assert!(replacement.actor_epoch > implementation_a.actor_epoch);
                true
            }
            Err(error) => {
                assert_eq!(error.code, "stale_actor_binding");
                false
            }
        };
        let (_, final_state, _) = plane.store.load().unwrap();
        let final_implementation_a = final_state.actor(&implementation_a.actor_id).unwrap();
        assert!(final_implementation_a.epoch > implementation_a.actor_epoch);
        assert_eq!(final_implementation_a.status, ActorStatus::Healthy);
        assert!(
            final_state
                .actor(&implementation_b.actor_id)
                .unwrap()
                .last_heartbeat_at
                .unwrap()
                > heartbeat_before
        );
        let final_implementation_a_session = plane
            .store
            .session(implementation_a.actor_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(final_implementation_a_session.status, "idle");
        assert!(final_implementation_a_session.external_id.is_some());
        if bootstrap_reused_stopped_session {
            assert_eq!(
                final_implementation_a_session.external_id,
                original_external_id
            );
        }
        assert!(stop_observation_count.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn primary_reacquisition_waits_for_already_admitted_primary_work() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::new());
        let settings = legacy_settings(root, temporary.path().join("state"), runtime.id().as_str());
        let plane = open_fixture_plane(settings.clone(), &runtime);
        let primary = activate_test_primary(&plane, "primary-authority-fence");

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let entered_observer = entered.clone();
        let release_observer = release.clone();
        plane.set_after_caller_fence(move |operation| {
            if operation == "start" {
                entered_observer.wait();
                release_observer.wait();
            }
        });

        let old_primary_plane = open_fixture_plane(settings.clone(), &runtime);
        old_primary_plane.set_test_authenticated_actor_local(primary.clone());
        let old_primary_thread =
            thread::spawn(move || old_primary_plane.execute("start", &json!({})));
        entered.wait();

        let mut replacement_plane = open_fixture_plane(settings, &runtime);
        replacement_plane.set_test_caller_binding("test_pane", "replacement-primary-pane");
        let (replacement_tx, replacement_rx) = mpsc::sync_channel(1);
        let replacement_thread = thread::spawn(move || {
            let result = replacement_plane.execute("context", &json!({ "bootstrap": true }));
            let _ = replacement_tx.send(result);
        });
        let premature = replacement_rx.recv_timeout(Duration::from_millis(250));
        let replacement_waited = matches!(premature, Err(mpsc::RecvTimeoutError::Timeout));

        release.wait();
        old_primary_thread.join().unwrap().unwrap();
        let replacement = match premature {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                replacement_rx.recv_timeout(Duration::from_secs(5)).unwrap()
            }
            Err(error) => panic!("replacement Primary result channel failed: {error}"),
        }
        .unwrap();
        replacement_thread.join().unwrap();
        plane.clear_after_caller_fence();

        assert!(
            replacement_waited,
            "Primary reacquisition must not overlap already-admitted Primary work"
        );
        let replacement_ref: ActorRef =
            serde_json::from_value(replacement["actor_ref"].clone()).unwrap();
        assert_ne!(replacement_ref.actor_id, primary.actor_id);
        let (_, state, _) = plane.store.load().unwrap();
        assert_eq!(state.active_primary(), Some(replacement_ref));
        assert_eq!(
            state.actor(&primary.actor_id).unwrap().status,
            ActorStatus::Stale
        );
    }

    #[test]
    fn self_shutdown_dispatches_the_persisted_backend_without_refreshing_configuration() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::new());
        let mut plane = open_fixture_plane(
            legacy_settings(root, temporary.path().join("state"), runtime.id().as_str()),
            &runtime,
        );
        let primary = activate_test_primary(&plane, "primary-persisted-shutdown-backend");
        let observed_at = now_ms().unwrap();
        plane
            .store
            .mutate("test.primary_current", &json!({}), observed_at, |state| {
                state
                    .heartbeat(&primary, TimestampMillis(observed_at))
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        plane.set_test_authenticated_actor(primary.clone());
        plane.ensure_primary_notification_session(&primary).unwrap();
        let mut persisted = plane
            .store
            .session(primary.actor_id.as_str())
            .unwrap()
            .unwrap();
        PERSISTED_SHUTDOWN_BACKEND_ID.clone_into(&mut persisted.backend);
        persisted.external_id = Some("persisted-backend-owned-handle".to_owned());
        persisted.resume_token = None;
        plane.store.upsert_session(&persisted).unwrap();

        // Fresh work is configured for `fake`, while the durable session row
        // belongs to the distinct persisted-backend fixture.
        plane.sessions = SessionDriver::shutdown_dispatch_test_driver();
        reset_fake_stop_count();
        reset_persisted_shutdown_stop_count();
        plane
            .execute(
                "actor.shutdown",
                &json!({ "operation_id": "persisted-backend-self-shutdown" }),
            )
            .unwrap();

        assert_eq!(fake_stop_count(), 0);
        assert_eq!(persisted_shutdown_stop_count(), 1);
        let stopped = plane
            .store
            .session(primary.actor_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(stopped.backend, PERSISTED_SHUTDOWN_BACKEND_ID);
        assert_eq!(stopped.external_id, persisted.external_id);
        assert_eq!(stopped.status, "stopped");
    }

    fn create_profiled_test_team(
        plane: &ControlPlane,
        working_directory: &Path,
        operation_id: &str,
    ) -> serde_json::Value {
        plane
            .team_create(&json!({
                "name": "workers",
                "working_directory": working_directory,
                "orchestrators": 1,
                "operation_id": operation_id,
            }))
            .unwrap()
    }

    fn create_candidate_ready_test_request(
        plane: &ControlPlane,
        team_id: &TeamId,
        working_directory: &Path,
        operation_prefix: &str,
    ) -> (RequestId, Candidate) {
        let created = plane
            .request_create(&json!({
                "team": team_id,
                "title": format!("{operation_prefix} candidate"),
                "operation_id": format!("{operation_prefix}-create"),
            }))
            .unwrap();
        let request_id = RequestId::new(
            created["request"]["request_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let request = supervisor.request(&request_id).unwrap();
        let actor_ref = request.assignment.as_ref().unwrap().actor.clone();
        let actor = supervisor.actor(&actor_ref.actor_id).unwrap();
        let candidate = Candidate {
            request_id: request_id.clone(),
            team_id: team_id.clone(),
            sha: super::git_sha_for(&test_git(), working_directory).unwrap(),
            created_by: actor_ref.clone(),
            created_by_profile: actor.profile.as_ref().map(|profile| profile.name.clone()),
        };
        let envelope = super::request_envelope(
            &supervisor,
            &request_id,
            actor_ref,
            MessageTarget::Primary,
            Message::CandidateReady(CandidateReady {
                candidate: candidate.clone(),
                summary: format!("{operation_prefix} candidate is ready"),
                evidence: Vec::new(),
            }),
            MessageId::new(format!("{operation_prefix}-candidate-ready")).unwrap(),
        )
        .unwrap()
        .0;
        plane
            .store
            .mutate(
                &format!("test.{operation_prefix}_candidate_ready"),
                &json!({}),
                super::now_ms().unwrap(),
                |state| apply_envelope(state, envelope.clone()),
            )
            .unwrap();
        (request_id, candidate)
    }

    fn submit_test_candidate(
        plane: &ControlPlane,
        request_id: &RequestId,
        candidate_sha: GitSha,
        operation: &str,
    ) -> Candidate {
        let (_, supervisor, _) = plane.store.load().unwrap();
        let request = supervisor.request(request_id).unwrap();
        let actor_ref = request.assignment.as_ref().unwrap().actor.clone();
        let actor = supervisor.actor(&actor_ref.actor_id).unwrap();
        let candidate = Candidate {
            request_id: request_id.clone(),
            team_id: request.team_id.clone(),
            sha: candidate_sha,
            created_by: actor_ref.clone(),
            created_by_profile: actor.profile.as_ref().map(|profile| profile.name.clone()),
        };
        let envelope = super::request_envelope(
            &supervisor,
            request_id,
            actor_ref,
            MessageTarget::Primary,
            Message::CandidateReady(CandidateReady {
                candidate: candidate.clone(),
                summary: format!("{operation} candidate"),
                evidence: Vec::new(),
            }),
            MessageId::new(format!("{operation}-candidate-ready")).unwrap(),
        )
        .unwrap()
        .0;
        plane
            .store
            .mutate(
                &format!("test.{operation}_candidate"),
                &json!({}),
                super::now_ms().unwrap(),
                |state| apply_envelope(state, envelope.clone()),
            )
            .unwrap();
        candidate
    }

    fn create_completed_test_request(
        plane: &ControlPlane,
        team_id: &TeamId,
        working_directory: &Path,
        operation_prefix: &str,
    ) -> RequestId {
        let (request_id, candidate) = create_candidate_ready_test_request(
            plane,
            team_id,
            working_directory,
            operation_prefix,
        );
        plane
            .decision_submit(&json!({
                "request": request_id,
                "candidate_sha": candidate.sha,
                "decision": "accepted",
                "summary": format!("{operation_prefix} candidate is accepted"),
                "operation_id": format!("{operation_prefix}-accept"),
            }))
            .unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let request = supervisor.request(&request_id).unwrap();
        let authorization = request.integration_authorization.clone().unwrap();
        let target =
            MessageTarget::Actor(request.assignment.as_ref().unwrap().actor.actor_id.clone());
        let envelope = super::request_envelope(
            &supervisor,
            &request_id,
            supervisor.active_primary().unwrap(),
            target,
            Message::IntegrationComplete(IntegrationComplete {
                decision_id: authorization.decision_id,
                candidate: authorization.candidate,
                evidence: Vec::new(),
            }),
            MessageId::new(format!("{operation_prefix}-integration-complete")).unwrap(),
        )
        .unwrap()
        .0;
        plane
            .store
            .mutate(
                &format!("test.{operation_prefix}_integration_complete"),
                &json!({}),
                super::now_ms().unwrap(),
                |state| apply_envelope(state, envelope.clone()),
            )
            .unwrap();
        let (_, completed, _) = plane.store.load().unwrap();
        assert_eq!(
            completed.request(&request_id).unwrap().status,
            agsv_protocol::RequestStatus::Completed
        );
        request_id
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn team_and_actor_reports_expose_activity_work_age_and_worktree_evidence() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("visibility-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-team-visibility"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-team-visibility");
        create_profiled_test_team(&plane, &attached, "create-team-visibility");
        let team_id = TeamId::new("team-workers").unwrap();
        let expected_head = super::git_sha_for(&test_git(), &attached).unwrap();

        let listed = plane.team_list().unwrap();
        let listed_team = &listed["teams"][0];
        assert_eq!(listed_team["team_id"], team_id.as_str());
        assert!(listed_team["last_activity_at"].as_u64().is_some());
        assert_eq!(listed_team["nonterminal_request_count"], 0);
        assert_eq!(listed_team["working_directory_exists"], true);
        assert_eq!(
            listed_team["working_directory_head"],
            expected_head.as_str()
        );
        assert_eq!(
            listed_team["working_directory_observation"]["state"],
            "present"
        );
        assert_eq!(
            listed_team["working_directory_observation"]["matches_durable_state"],
            true
        );

        let actors = plane.actor_list(&json!({ "team": team_id })).unwrap();
        let actor = &actors["actors"][0]["actor"];
        assert!(actor["generation_started_at"].as_u64().is_some());
        assert!(actor["generation_age_ms"].as_u64().is_some());
        assert_eq!(actor["completed_assignment_count"], 0);
        let actor_id = actor["actor_id"].as_str().unwrap().to_owned();
        let actor_shown = plane.actor_show(&json!({ "id": actor_id })).unwrap();
        assert_eq!(
            actor_shown["actor"]["generation_started_at"],
            actor["generation_started_at"]
        );
        let team_shown = plane.team_show(&json!({ "id": team_id })).unwrap();
        assert_eq!(team_shown["actors"][0]["completed_assignment_count"], 0);

        let created = plane
            .request_create(&json!({
                "team": team_id,
                "title": "visible nonterminal work",
                "operation_id": "create-visible-nonterminal-work",
            }))
            .unwrap();
        let request_id = created["request"]["request_id"].as_str().unwrap();
        let with_work = plane.team_show(&json!({ "id": team_id })).unwrap();
        assert_eq!(with_work["team"]["nonterminal_request_count"], 1);
        plane
            .request_cancel(&json!({
                "id": request_id,
                "reason": "exercise terminal visibility",
                "operation_id": "cancel-visible-nonterminal-work",
            }))
            .unwrap();
        let without_work = plane.team_show(&json!({ "id": team_id })).unwrap();
        assert_eq!(without_work["team"]["nonterminal_request_count"], 0);

        create_completed_test_request(&plane, &team_id, &attached, "visible-completion");
        let completed_actor = plane.actor_show(&json!({ "id": actor_id })).unwrap();
        assert_eq!(completed_actor["actor"]["completed_assignment_count"], 1);

        let status = plane.status().unwrap();
        assert_eq!(
            status["observability_integrity"]["checkpoint_matches"],
            true
        );
        assert!(status["observability_integrity"]["incident"].is_null());
        let revision_before_doctor = plane.store.load().unwrap().0;
        let doctor = plane.doctor().unwrap();
        assert!(doctor.get("close_candidates").is_none());
        assert_eq!(
            doctor["teams_without_nonterminal_work"][0]["team_id"],
            team_id.as_str()
        );
        assert!(
            doctor["teams_without_nonterminal_work"][0]["inactive_for_ms"]
                .as_u64()
                .is_some()
        );
        assert_eq!(doctor["observability_integrity"]["healthy"], true);
        assert_eq!(doctor["observability_integrity"]["verified"], true);
        assert_eq!(doctor["observability_integrity"]["report"]["teams"], 1);
        assert_eq!(
            doctor["observability_integrity"]["report"]["actor_generations"],
            2
        );
        assert_eq!(
            doctor["observability_integrity"]["report"]["completed_assignments"],
            1
        );
        assert_eq!(plane.store.load().unwrap().0, revision_before_doctor);

        let moved = temporary.path().join("visibility-worktree-moved");
        fs::rename(&attached, &moved).unwrap();
        let missing_list = plane.team_list().unwrap();
        let missing = &missing_list["teams"][0];
        assert_eq!(missing["working_directory_exists"], false);
        assert!(missing["working_directory_head"].is_null());
        assert_eq!(
            missing["working_directory_observation"]["state"],
            "recorded_absent"
        );
        assert_eq!(
            missing["working_directory_observation"]["drift"][0]["code"],
            "recorded_path_absent"
        );
        let missing_show = plane.team_show(&json!({ "id": team_id })).unwrap();
        assert_eq!(missing_show["team"]["working_directory_exists"], false);
        assert!(moved.exists());
    }

    #[test]
    fn status_and_doctor_remain_reachable_when_observability_manifest_is_missing() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("unused-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-observability-health",
        ));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        Connection::open(plane.store.path())
            .unwrap()
            .execute_batch(
                "DROP TRIGGER observability_manifest_no_delete;
                 DELETE FROM observability_manifest;",
            )
            .unwrap();

        let status = plane.execute("status", &json!({})).unwrap();
        assert_eq!(
            status["observability_integrity"]["checkpoint_matches"],
            false
        );
        assert_eq!(
            status["observability_integrity"]["incident"]["condition"],
            "manifest_missing"
        );

        let doctor = plane.execute("doctor", &json!({})).unwrap();
        assert_eq!(doctor["healthy"], false);
        assert_eq!(doctor["observability_integrity"]["healthy"], false);
        assert_eq!(doctor["observability_integrity"]["verified"], false);
        assert_eq!(
            doctor["observability_integrity"]["health"]["incident"]["condition"],
            "manifest_missing"
        );
        assert!(doctor["observability_integrity"]["report"].is_null());
        assert!(
            doctor["observability_integrity"]["error"]["code"]
                .as_str()
                .is_some()
        );

        Connection::open(plane.store.path())
            .unwrap()
            .execute_batch(
                "INSERT INTO observability_manifest
                 (workspace_id, fact_count, fact_head_sha256,
                  updated_revision, updated_at_ms)
                 SELECT workspace_id, 0, NULL, revision, updated_at_ms FROM domain_state;",
            )
            .unwrap();
        let realigned_status = plane.execute("status", &json!({})).unwrap();
        assert_eq!(
            realigned_status["observability_integrity"]["checkpoint_matches"],
            true
        );
        assert_eq!(
            realigned_status["observability_integrity"]["incident"]["condition"],
            "manifest_missing"
        );
        let realigned_doctor = plane.execute("doctor", &json!({})).unwrap();
        assert_eq!(
            realigned_doctor["observability_integrity"]["healthy"],
            false
        );
        assert_eq!(
            realigned_doctor["observability_integrity"]["verified"],
            true
        );
        assert_eq!(
            realigned_doctor["observability_integrity"]["health"]["incident"]["condition"],
            "manifest_missing"
        );
    }

    fn configured_review_settings() -> ReviewSettings {
        ReviewSettings {
            checks: vec![ReviewCheckSettings {
                id: "git-head".to_owned(),
                argv: vec![
                    "git".to_owned(),
                    "rev-parse".to_owned(),
                    "--verify".to_owned(),
                    "HEAD".to_owned(),
                ],
                expected_exit_code: 0,
                relative_cwd: None,
                timeout_seconds: 30,
                required_absent_binaries: BTreeSet::from(["codex".to_owned()]),
            }],
            tool_versions: vec![ReviewToolVersionSettings {
                id: "git".to_owned(),
                argv: vec!["git".to_owned(), "--version".to_owned()],
            }],
            optional_binaries: BTreeSet::from(["codex".to_owned()]),
            environment: BTreeMap::new(),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn review_session_binds_exact_tree_executes_and_reads_required_absent_evidence() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("review-team-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-review"));
        let mut settings = profiled_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        settings.review = configured_review_settings();
        let inherited_environment_key = "R4_TEST_INHERITED_VALUE";
        settings
            .review
            .environment
            .insert(inherited_environment_key.to_owned(), "{inherit}".to_owned());
        settings
            .review
            .environment
            .insert("LANG".to_owned(), "POSIX".to_owned());
        settings
            .review
            .environment
            .insert("LC_ALL".to_owned(), "POSIX".to_owned());
        settings.review.checks.push(ReviewCheckSettings {
            id: "child-environment".to_owned(),
            argv: vec![
                "sh".to_owned(),
                "-c".to_owned(),
                "printf '%s|%s|%s\\n' \"$LANG\" \"$LC_ALL\" \"$TMPDIR\"".to_owned(),
            ],
            expected_exit_code: 0,
            relative_cwd: None,
            timeout_seconds: 30,
            required_absent_binaries: BTreeSet::new(),
        });
        settings
            .review
            .tool_versions
            .push(ReviewToolVersionSettings {
                id: "shell".to_owned(),
                argv: vec![
                    "sh".to_owned(),
                    "-c".to_owned(),
                    "printf 'fixture-shell 1\\n'".to_owned(),
                ],
            });
        let mut plane = open_fixture_plane(settings, &runtime);
        plane
            .review
            .set_test_inherited_environment(inherited_environment_key, "supplied-by-test");
        activate_test_primary(&plane, "primary-review");
        create_profiled_test_team(&plane, &attached, "create-review-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let (request_id, candidate) =
            create_candidate_ready_test_request(&plane, &team_id, &attached, "review");

        let begin_request = json!({
            "request": request_id,
            "candidate_sha": candidate.sha,
            "operation_id": "begin-exact-review",
        });
        let begun = plane.review_begin(&begin_request).unwrap();
        assert_eq!(begun, plane.review_begin(&begin_request).unwrap());
        let session_id = begun["session"]["session_id"].as_str().unwrap();
        assert_eq!(
            begun["session"]["tree"]["candidate_sha"],
            json!(candidate.sha)
        );
        assert_eq!(
            begun["session"]["plan"]["declared_environment"][inherited_environment_key],
            "{inherit}"
        );
        let checkout = PathBuf::from(begun["session"]["checkout_path"].as_str().unwrap());
        assert!(!checkout.starts_with(&root));
        assert!(checkout.join(".git").is_dir());
        let head = Command::new("git")
            .arg("-C")
            .arg(&checkout)
            .args(["rev-parse", "HEAD^{commit}"])
            .output()
            .unwrap();
        assert!(head.status.success());
        assert_eq!(
            String::from_utf8_lossy(&head.stdout).trim(),
            candidate.sha.as_str()
        );

        let objects_info = checkout.join(".git/objects/info");
        let info_mode = fs::metadata(&objects_info).unwrap().permissions().mode();
        fs::set_permissions(&objects_info, fs::Permissions::from_mode(info_mode | 0o200)).unwrap();
        fs::write(
            objects_info.join("alternates"),
            root.join(".git/objects").to_string_lossy().as_bytes(),
        )
        .unwrap();
        fs::set_permissions(&objects_info, fs::Permissions::from_mode(info_mode)).unwrap();
        let alternates_error = plane
            .review_verify(&json!({
                "session": session_id,
                "operation_id": "verify-review-forged-alternates",
            }))
            .unwrap_err();
        assert_eq!(alternates_error.code, "review_checkout_not_isolated");
        fs::set_permissions(&objects_info, fs::Permissions::from_mode(info_mode | 0o200)).unwrap();
        fs::remove_file(objects_info.join("alternates")).unwrap();
        fs::set_permissions(&objects_info, fs::Permissions::from_mode(info_mode)).unwrap();

        let objects = checkout.join(".git/objects");
        let objects_mode = fs::metadata(&objects).unwrap().permissions().mode();
        fs::set_permissions(&objects, fs::Permissions::from_mode(objects_mode | 0o200)).unwrap();
        let forged_directory = objects.join("zz");
        fs::create_dir(&forged_directory).unwrap();
        std::os::unix::fs::symlink("/dev/null", forged_directory.join("forged-object")).unwrap();
        fs::set_permissions(&objects, fs::Permissions::from_mode(objects_mode)).unwrap();
        let object_symlink_error = plane
            .review_verify(&json!({
                "session": session_id,
                "operation_id": "verify-review-forged-object-symlink",
            }))
            .unwrap_err();
        assert_eq!(object_symlink_error.code, "review_checkout_not_isolated");
        fs::set_permissions(&objects, fs::Permissions::from_mode(objects_mode | 0o200)).unwrap();
        fs::remove_file(forged_directory.join("forged-object")).unwrap();
        fs::remove_dir(forged_directory).unwrap();
        fs::set_permissions(&objects, fs::Permissions::from_mode(objects_mode)).unwrap();

        let status = plane.status().unwrap();
        assert_eq!(status["review"]["configured"], true);
        assert_eq!(status["review"]["decision_gating"]["enforced"], false);
        let doctor = plane.doctor().unwrap();
        assert_eq!(doctor["review"]["capabilities"]["configured"], true);
        assert!(
            doctor["enforcement"]["not_yet_enforced"]
                .as_array()
                .unwrap()
                .contains(&json!("decision_requires_passing_verification"))
        );

        let verify_request = json!({
            "session": session_id,
            "operation_id": "verify-exact-review",
        });
        let verified = plane.review_verify(&verify_request).unwrap();
        assert_eq!(verified["attempt"]["status"], "passed", "{verified:#}");
        assert_eq!(verified["decision_gating"], false);
        assert_eq!(
            verified["sandbox"]["source_write_boundary"],
            if plane.review.sandbox_enforced() {
                "os_enforced"
            } else {
                "not_enforced"
            }
        );
        assert_eq!(
            verified["check_results"]
                .as_array()
                .unwrap()
                .iter()
                .map(|result| result["variant"].as_str().unwrap())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["normal", "required_absent"])
        );
        assert_eq!(verified, plane.review_verify(&verify_request).unwrap());

        let shown = plane
            .review_show(&json!({
                "candidate_sha": candidate.sha,
                "limit": 100,
            }))
            .unwrap();
        assert_eq!(shown["reviews"].as_array().unwrap().len(), 1);
        let environments = shown["reviews"][0]["environments"].as_array().unwrap();
        assert!(environments.iter().all(|environment| {
            environment["environment"]["execution_environment"]
                .get(inherited_environment_key)
                .is_none()
        }));
        let required_absent = environments
            .iter()
            .find(|environment| environment["environment"]["variant"] == "required_absent")
            .unwrap();
        assert!(
            required_absent["environment"]["binary_observations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|observation| {
                    observation["binary_id"] == "codex"
                        && observation["presence"] == "absent_from_controlled_path"
                })
        );
        assert_eq!(
            required_absent["environment"]["candidate_sha"],
            json!(candidate.sha)
        );
        let child_environment = environments
            .iter()
            .find(|environment| {
                environment["environment"]["check_id"] == "child-environment"
                    && environment["environment"]["variant"] == "normal"
            })
            .unwrap();
        assert_eq!(
            child_environment["environment"]["execution_environment"]["lang"],
            "POSIX"
        );
        assert_eq!(
            child_environment["environment"]["execution_environment"]["lc_all"],
            "POSIX"
        );
        let expected_tmpdir = checkout.parent().unwrap().join("tmp");
        assert_eq!(
            child_environment["environment"]["execution_environment"]["tmpdir"],
            expected_tmpdir.to_string_lossy().as_ref()
        );
        let child_output = shown["reviews"][0]["check_results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|result| result["check_id"] == "child-environment")
            .unwrap();
        let child_output_reference = child_output["stdout"]["reference"].as_str().unwrap();
        assert_eq!(
            fs::read_to_string(checkout.parent().unwrap().join(child_output_reference)).unwrap(),
            format!("POSIX|POSIX|{}\n", expected_tmpdir.display())
        );
        let artifact_reference = shown["reviews"][0]["check_results"][0]["stdout"]["reference"]
            .as_str()
            .unwrap();
        fs::write(
            checkout.parent().unwrap().join(artifact_reference),
            b"truncated",
        )
        .unwrap();
        let integrity_error = plane.doctor().unwrap_err();
        assert_eq!(integrity_error.code, "review_artifact_integrity_mismatch");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn review_checkout_identity_dirty_and_read_only_guards_are_independently_measured() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("review-guard-worktree");
        init_test_repository(&root, &attached);
        fs::write(attached.join("candidate.txt"), "candidate\n").unwrap();
        run_git(&attached, &["add", "candidate.txt"]);
        run_git(&attached, &["commit", "-q", "-m", "candidate"]);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-review-guards"));
        let mut settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        settings.review = configured_review_settings();
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-review-guards");
        create_profiled_test_team(&plane, &attached, "create-review-guard-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let (request_id, candidate) =
            create_candidate_ready_test_request(&plane, &team_id, &attached, "review-guards");
        let begun = plane
            .review_begin(&json!({
                "request": request_id,
                "candidate_sha": candidate.sha,
                "operation_id": "begin-review-guards",
            }))
            .unwrap();
        let session_id =
            ReviewSessionId::new(begun["session"]["session_id"].as_str().unwrap().to_owned())
                .unwrap();
        let session = plane
            .store
            .review_session(&session_id)
            .unwrap()
            .unwrap()
            .session;
        let checkout = PathBuf::from(&session.checkout_path);

        make_test_tree_writable(checkout.parent().unwrap());
        run_git(&checkout, &["reset", "--hard", "HEAD^"]);
        let identity = plane.review.verify_checkout(&session).unwrap_err();
        assert_eq!(identity.code, "review_checkout_identity_mismatch");
        run_git(&checkout, &["reset", "--hard", candidate.sha.as_str()]);
        make_test_tree_read_only(&checkout);
        plane.review.verify_checkout(&session).unwrap();

        let readme = checkout.join("README.md");
        let mode = fs::metadata(&readme).unwrap().permissions().mode();
        fs::set_permissions(&readme, fs::Permissions::from_mode(mode | 0o200)).unwrap();
        fs::write(&readme, "bose\n").unwrap();
        let dirty = plane.review.verify_checkout(&session).unwrap_err();
        assert_eq!(dirty.code, "review_checkout_dirty");
        make_test_tree_writable(&checkout);
        run_git(&checkout, &["reset", "--hard", candidate.sha.as_str()]);
        make_test_tree_read_only(&checkout);
        plane.review.verify_checkout(&session).unwrap();

        let readme = checkout.join("README.md");
        let mode = fs::metadata(&readme).unwrap().permissions().mode();
        fs::set_permissions(&readme, fs::Permissions::from_mode(mode | 0o200)).unwrap();
        let writable = plane.review.verify_checkout(&session).unwrap_err();
        assert_eq!(writable.code, "review_checkout_writable");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn required_absent_execution_uses_a_fixture_controlled_path() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("review-required-absent-worktree");
        init_test_repository(&root, &attached);
        let source_bin = temporary.path().join("source-bin");
        fs::create_dir(&source_bin).unwrap();
        std::os::unix::fs::symlink("/bin/sh", source_bin.join("required-tool")).unwrap();
        let forbidden = source_bin.join("forbidden-tool");
        fs::write(&forbidden, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&forbidden, fs::Permissions::from_mode(0o700)).unwrap();
        let controlled_path = std::env::join_paths([source_bin])
            .unwrap()
            .to_string_lossy()
            .into_owned();

        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-review-required-absent",
        ));
        let mut settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        settings.review = ReviewSettings {
            checks: vec![ReviewCheckSettings {
                id: "fixture-path".to_owned(),
                argv: vec![
                    "required-tool".to_owned(),
                    "-c".to_owned(),
                    "exit 0".to_owned(),
                ],
                expected_exit_code: 0,
                relative_cwd: None,
                timeout_seconds: 30,
                required_absent_binaries: BTreeSet::from(["forbidden-tool".to_owned()]),
            }],
            tool_versions: vec![ReviewToolVersionSettings {
                id: "fixture-tool".to_owned(),
                argv: vec![
                    "required-tool".to_owned(),
                    "-c".to_owned(),
                    "printf 'fixture-tool 1\\n'".to_owned(),
                ],
            }],
            optional_binaries: BTreeSet::from(["forbidden-tool".to_owned()]),
            environment: BTreeMap::new(),
        };
        let mut plane = open_fixture_plane(settings, &runtime);
        plane.review.set_test_controlled_path(controlled_path);
        activate_test_primary(&plane, "primary-review-required-absent");
        create_profiled_test_team(&plane, &attached, "create-review-required-absent-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let (request_id, candidate) = create_candidate_ready_test_request(
            &plane,
            &team_id,
            &attached,
            "review-required-absent",
        );
        let begun = plane
            .review_begin(&json!({
                "request": request_id,
                "candidate_sha": candidate.sha,
                "operation_id": "begin-review-required-absent",
            }))
            .unwrap();
        let verified = plane
            .review_verify(&json!({
                "session": begun["session"]["session_id"],
                "operation_id": "verify-review-required-absent",
            }))
            .unwrap();
        assert_eq!(verified["attempt"]["status"], "passed", "{verified:#}");
        let shown = plane
            .review_show(&json!({
                "session": begun["session"]["session_id"],
                "limit": 100,
            }))
            .unwrap();
        let environments = shown["reviews"][0]["environments"].as_array().unwrap();
        for (variant, expected_presence) in [
            ("normal", "present"),
            ("required_absent", "absent_from_controlled_path"),
        ] {
            let environment = environments
                .iter()
                .find(|environment| environment["environment"]["variant"] == variant)
                .unwrap();
            let observation = environment["environment"]["binary_observations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|observation| observation["binary_id"] == "forbidden-tool")
                .unwrap();
            assert_eq!(observation["presence"], expected_presence);
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn review_verify_recovers_running_attempt_after_child_spawn_crash() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("review-crash-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-review-crash"));
        let mut settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        settings.review = configured_review_settings();
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-review-crash");
        create_profiled_test_team(&plane, &attached, "create-review-crash-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let (request_id, candidate) =
            create_candidate_ready_test_request(&plane, &team_id, &attached, "review-crash");
        let begun = plane
            .review_begin(&json!({
                "request": request_id,
                "candidate_sha": candidate.sha,
                "operation_id": "begin-review-crash",
            }))
            .unwrap();
        let verify_request = json!({
            "session": begun["session"]["session_id"],
            "operation_id": "verify-review-crash",
        });
        if !plane.review.sandbox_enforced() {
            return;
        }
        plane.arm_test_crash("review_child_spawned");
        let crashed = plane.review_verify(&verify_request).unwrap_err();
        assert_eq!(crashed.code, "injected_crash");
        let session_id =
            ReviewSessionId::new(begun["session"]["session_id"].as_str().unwrap().to_owned())
                .unwrap();
        assert_eq!(
            plane
                .store
                .review_session(&session_id)
                .unwrap()
                .unwrap()
                .session
                .state
                .recovery,
            ReviewRecoveryState::ResumeRequired
        );
        let interrupted = plane.review_verify(&verify_request).unwrap();
        assert_eq!(interrupted["attempt"]["status"], "interrupted");
        assert!(
            interrupted["interruption_reason"]
                .as_str()
                .unwrap()
                .contains("ended without terminal evidence")
        );
        assert_eq!(
            plane
                .store
                .review_verification_attempts_for_operation(&session_id, "verify-review-crash",)
                .unwrap()
                .len(),
            2
        );
        let recovered = plane
            .review_verify(&json!({
                "session": begun["session"]["session_id"],
                "operation_id": "verify-review-crash-retry",
            }))
            .unwrap();
        assert_eq!(recovered["attempt"]["status"], "passed");
    }

    #[test]
    fn review_begin_recovers_checkout_after_crash_before_ready_transition() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("review-begin-crash-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-review-begin-crash",
        ));
        let mut settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        settings.review = configured_review_settings();
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-review-begin-crash");
        create_profiled_test_team(&plane, &attached, "create-review-begin-crash-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let (request_id, candidate) =
            create_candidate_ready_test_request(&plane, &team_id, &attached, "review-begin-crash");
        let request = json!({
            "request": request_id,
            "candidate_sha": candidate.sha,
            "operation_id": "begin-review-checkout-crash",
        });
        plane.arm_test_crash("review_checkout");
        let crashed = plane.review_begin(&request).unwrap_err();
        assert_eq!(crashed.code, "injected_crash");
        let stored = plane
            .store
            .review_session_for_candidate(&request_id, &candidate.sha)
            .unwrap()
            .unwrap();
        assert_eq!(stored.session.state.status, ReviewSessionStatus::Preparing);
        let checkout = PathBuf::from(&stored.session.checkout_path);
        assert!(checkout.join(".git").is_dir());

        let recovered = plane.review_begin(&request).unwrap();
        assert_eq!(recovered["session"]["state"]["status"], json!("ready"));
        assert_eq!(recovered["session"]["checkout_path"], json!(checkout));
        assert!(!checkout.with_file_name("source.invalid-1").exists());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn review_timeout_records_containment_and_preserves_raw_output_evidence() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("review-timeout-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-review-timeout"));
        let script = concat!(
            "import os,subprocess,sys,time;",
            "sentinel=os.path.join(os.environ['TMPDIR'],'grandchild-sentinel');",
            "writer=\"import os,time;[(os.write(1,b'z'*1024),time.sleep(.01)) for _ in range(300)]\";",
            "marker=\"import pathlib,sys,time;time.sleep(3);pathlib.Path(sys.argv[1]).write_text('late')\";",
            "subprocess.Popen([sys.executable,'-c',writer],start_new_session=True);",
            "subprocess.Popen([sys.executable,'-c',marker,sentinel],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);",
            "os.write(1,b'\\xff'+b'x'*524288);",
            "time.sleep(5)",
        );
        let mut settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        settings.review = ReviewSettings {
            checks: vec![ReviewCheckSettings {
                id: "timeout-process-tree".to_owned(),
                argv: vec!["python3".to_owned(), "-c".to_owned(), script.to_owned()],
                expected_exit_code: 0,
                relative_cwd: None,
                timeout_seconds: 1,
                required_absent_binaries: BTreeSet::new(),
            }],
            tool_versions: vec![ReviewToolVersionSettings {
                id: "python".to_owned(),
                argv: vec!["python3".to_owned(), "--version".to_owned()],
            }],
            optional_binaries: BTreeSet::new(),
            environment: BTreeMap::new(),
        };
        let plane = open_fixture_plane(settings, &runtime);
        if !plane.review.sandbox_enforced()
            || Command::new("python3").arg("--version").output().is_err()
        {
            return;
        }
        activate_test_primary(&plane, "primary-review-timeout");
        create_profiled_test_team(&plane, &attached, "create-review-timeout-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let (request_id, candidate) =
            create_candidate_ready_test_request(&plane, &team_id, &attached, "review-timeout");
        let begun = plane
            .review_begin(&json!({
                "request": request_id,
                "candidate_sha": candidate.sha,
                "operation_id": "begin-review-timeout",
            }))
            .unwrap();
        let checkout = PathBuf::from(begun["session"]["checkout_path"].as_str().unwrap());
        let verification_started = Instant::now();
        let result = plane
            .review_verify(&json!({
                "session": begun["session"]["session_id"],
                "operation_id": "verify-review-timeout",
            }))
            .unwrap();
        assert!(verification_started.elapsed() < Duration::from_secs(2));
        assert_eq!(result["attempt"]["status"], "failed", "{result:#}");
        let check = &result["check_results"][0];
        assert_eq!(check["outcome"], "execution_error");
        assert_eq!(check["actual_exit_code"], json!(null));
        assert_eq!(check["termination"], "timed_out");
        let fully_contained = plane.review.process_containment()
            == agsv_protocol::ReviewProcessContainment::PidNamespaceParentDeath;
        assert_eq!(check["process_tree_may_outlive"], !fully_contained);
        let stdout = &check["stdout"];
        let reference = stdout["reference"].as_str().unwrap();
        let bytes = fs::read(checkout.parent().unwrap().join(reference)).unwrap();
        assert!(bytes.len() >= 524_289);
        assert!(bytes.len() <= 1024 * 1024);
        assert_eq!(stdout["byte_count"], bytes.len());
        assert_eq!(stdout["truncated"], false);
        assert_eq!(stdout["digest"]["sha256"], sha256_hex(&bytes));
        assert_eq!(bytes[0], 0xff);
        thread::sleep(Duration::from_secs(3));
        assert_eq!(
            checkout
                .parent()
                .unwrap()
                .join("tmp/grandchild-sentinel")
                .exists(),
            !fully_contained
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn review_detached_silent_output_holder_is_not_reported_as_an_output_limit() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("review-incomplete-output-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-review-incomplete-output",
        ));
        let script = concat!(
            "import os,subprocess,sys;",
            "sentinel=os.path.join(os.environ['TMPDIR'],'detached-exit-sentinel');",
            "child=\"import pathlib,sys,time;time.sleep(3);pathlib.Path(sys.argv[1]).write_text('late')\";",
            "subprocess.Popen([sys.executable,'-c',child,sentinel],start_new_session=True);",
            "os.write(1,b'ok')",
        );
        let mut settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        settings.review = ReviewSettings {
            checks: vec![ReviewCheckSettings {
                id: "incomplete-output-capture".to_owned(),
                argv: vec!["python3".to_owned(), "-c".to_owned(), script.to_owned()],
                expected_exit_code: 0,
                relative_cwd: None,
                timeout_seconds: 10,
                required_absent_binaries: BTreeSet::new(),
            }],
            tool_versions: vec![ReviewToolVersionSettings {
                id: "python".to_owned(),
                argv: vec!["python3".to_owned(), "--version".to_owned()],
            }],
            optional_binaries: BTreeSet::new(),
            environment: BTreeMap::new(),
        };
        let plane = open_fixture_plane(settings, &runtime);
        if !plane.review.sandbox_enforced()
            || Command::new("python3").arg("--version").output().is_err()
        {
            return;
        }
        activate_test_primary(&plane, "primary-review-incomplete-output");
        create_profiled_test_team(&plane, &attached, "create-review-incomplete-output-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let (request_id, candidate) = create_candidate_ready_test_request(
            &plane,
            &team_id,
            &attached,
            "review-incomplete-output",
        );
        let begun = plane
            .review_begin(&json!({
                "request": request_id,
                "candidate_sha": candidate.sha,
                "operation_id": "begin-review-incomplete-output",
            }))
            .unwrap();
        let checkout = PathBuf::from(begun["session"]["checkout_path"].as_str().unwrap());
        let verification_started = Instant::now();
        let result = plane
            .review_verify(&json!({
                "session": begun["session"]["session_id"],
                "operation_id": "verify-review-incomplete-output",
            }))
            .unwrap();
        let fully_contained = plane.review.process_containment()
            == agsv_protocol::ReviewProcessContainment::PidNamespaceParentDeath;
        let check = &result["check_results"][0];
        if fully_contained {
            assert_eq!(result["attempt"]["status"], "passed", "{result:#}");
            assert_eq!(check["outcome"], "passed");
            assert_eq!(check["termination"], "exited");
            assert_eq!(check["process_tree_may_outlive"], false);
        } else {
            assert!(verification_started.elapsed() < Duration::from_secs(2));
            assert_eq!(result["attempt"]["status"], "failed", "{result:#}");
            assert_eq!(check["outcome"], "execution_error");
            assert_eq!(check["termination"], "output_capture_incomplete");
            assert_eq!(check["process_tree_may_outlive"], true);
        }
        assert_eq!(check["actual_exit_code"], 0);
        assert_eq!(check["stdout"]["byte_count"], 2);
        assert_eq!(check["stdout"]["truncated"], false);
        thread::sleep(Duration::from_secs(3));
        assert!(
            checkout
                .parent()
                .unwrap()
                .join("tmp/detached-exit-sentinel")
                .exists()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn review_output_limit_and_signal_are_durable_execution_errors() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("review-output-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-review-output"));
        let mut settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        settings.review = ReviewSettings {
            checks: vec![
                ReviewCheckSettings {
                    id: "bounded-output".to_owned(),
                    argv: vec![
                        "python3".to_owned(),
                        "-c".to_owned(),
                        "import os;os.write(1,b'x'*2097152)".to_owned(),
                    ],
                    expected_exit_code: 0,
                    relative_cwd: None,
                    timeout_seconds: 10,
                    required_absent_binaries: BTreeSet::new(),
                },
                ReviewCheckSettings {
                    id: "signaled".to_owned(),
                    argv: vec![
                        "python3".to_owned(),
                        "-c".to_owned(),
                        "import os,signal;os.kill(os.getpid(),signal.SIGTERM)".to_owned(),
                    ],
                    expected_exit_code: 0,
                    relative_cwd: None,
                    timeout_seconds: 10,
                    required_absent_binaries: BTreeSet::new(),
                },
            ],
            tool_versions: vec![ReviewToolVersionSettings {
                id: "python".to_owned(),
                argv: vec!["python3".to_owned(), "--version".to_owned()],
            }],
            optional_binaries: BTreeSet::new(),
            environment: BTreeMap::new(),
        };
        let plane = open_fixture_plane(settings, &runtime);
        if Command::new("python3").arg("--version").output().is_err() {
            return;
        }
        activate_test_primary(&plane, "primary-review-output");
        create_profiled_test_team(&plane, &attached, "create-review-output-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let (request_id, candidate) =
            create_candidate_ready_test_request(&plane, &team_id, &attached, "review-output");
        let begun = plane
            .review_begin(&json!({
                "request": request_id,
                "candidate_sha": candidate.sha,
                "operation_id": "begin-review-output",
            }))
            .unwrap();
        let result = plane
            .review_verify(&json!({
                "session": begun["session"]["session_id"],
                "operation_id": "verify-review-output",
            }))
            .unwrap();
        assert_eq!(result["attempt"]["status"], "failed", "{result:#}");
        let results = result["check_results"].as_array().unwrap();
        let bounded = results
            .iter()
            .find(|result| result["check_id"] == "bounded-output")
            .unwrap();
        assert_eq!(bounded["outcome"], "execution_error");
        assert_eq!(bounded["termination"], "output_limit_exceeded");
        assert_eq!(bounded["actual_exit_code"], json!(null));
        assert_eq!(bounded["stdout"]["byte_count"], 1_048_576);
        assert_eq!(bounded["stdout"]["truncated"], true);
        let signaled = results
            .iter()
            .find(|result| result["check_id"] == "signaled")
            .unwrap();
        assert_eq!(signaled["outcome"], "execution_error");
        assert_eq!(signaled["termination"], "signaled");
        assert_eq!(signaled["actual_exit_code"], json!(null));
        assert_eq!(signaled["process_tree_may_outlive"], false);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn review_os_sandbox_denies_source_git_symlink_and_outside_writes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("review-hostile-worktree");
        let victim = temporary.path().join("outside-victim.txt");
        fs::write(&victim, "outside remains unchanged\n").unwrap();
        init_test_repository(&root, &attached);
        std::os::unix::fs::symlink(&victim, attached.join("escape-link")).unwrap();
        run_git(&attached, &["add", "escape-link"]);
        run_git(&attached, &["commit", "-q", "-m", "hostile review fixture"]);
        let root_config_before = fs::read(root.join(".git/config")).unwrap();
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-review-hostile"));
        let script = concat!(
            "import os,pathlib,sys;",
            "exec(\"failures=[]\\n",
            "def must_be_denied(name,action):\\n",
            " try: action()\\n",
            " except OSError: return\\n",
            " failures.append(name)\\n",
            "source=pathlib.Path('README.md')\\n",
            "must_be_denied('chmod',lambda:os.chmod(source,0o600))\\n",
            "must_be_denied('tracked',lambda:source.write_bytes(b'tampered'))\\n",
            "must_be_denied('untracked',lambda:pathlib.Path('untracked.txt').write_text('bad'))\\n",
            "must_be_denied('git-config',lambda:pathlib.Path('.git/config').write_text('bad'))\\n",
            "must_be_denied('symlink',lambda:pathlib.Path('escape-link').write_text('bad'))\\n",
            "must_be_denied('outside',lambda:pathlib.Path(sys.argv[1]).write_text('bad'))\\n",
            "print(','.join(failures) if failures else 'all writes denied')\\n",
            "raise SystemExit(9 if failures else 0)\")",
        );
        let mut settings = profiled_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        settings.review = ReviewSettings {
            checks: vec![ReviewCheckSettings {
                id: "hostile-write-probe".to_owned(),
                argv: vec![
                    "python3".to_owned(),
                    "-c".to_owned(),
                    script.to_owned(),
                    victim.to_string_lossy().into_owned(),
                ],
                expected_exit_code: 0,
                relative_cwd: None,
                timeout_seconds: 30,
                required_absent_binaries: BTreeSet::new(),
            }],
            tool_versions: vec![ReviewToolVersionSettings {
                id: "python".to_owned(),
                argv: vec!["python3".to_owned(), "--version".to_owned()],
            }],
            optional_binaries: BTreeSet::new(),
            environment: BTreeMap::new(),
        };
        let plane = open_fixture_plane(settings, &runtime);
        if !plane.review.sandbox_enforced()
            || Command::new("python3").arg("--version").output().is_err()
        {
            return;
        }
        activate_test_primary(&plane, "primary-review-hostile");
        create_profiled_test_team(&plane, &attached, "create-review-hostile-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let (request_id, candidate) =
            create_candidate_ready_test_request(&plane, &team_id, &attached, "review-hostile");
        let begun = plane
            .review_begin(&json!({
                "request": request_id,
                "candidate_sha": candidate.sha,
                "operation_id": "begin-review-hostile",
            }))
            .unwrap();
        let checkout = PathBuf::from(begun["session"]["checkout_path"].as_str().unwrap());
        let result = plane
            .review_verify(&json!({
                "session": begun["session"]["session_id"],
                "operation_id": "verify-review-hostile",
            }))
            .unwrap();
        assert_eq!(result["attempt"]["status"], "passed", "{result:#}");
        assert_eq!(
            fs::read_to_string(checkout.join("README.md")).unwrap(),
            "base\n"
        );
        assert!(!checkout.join("untracked.txt").exists());
        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "outside remains unchanged\n"
        );
        assert_eq!(
            fs::read(root.join(".git/config")).unwrap(),
            root_config_before
        );
        run_git(&root, &["fsck", "--no-dangling"]);
        let status = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["status", "--porcelain=v1", "--untracked-files=all"])
            .output()
            .unwrap();
        assert!(status.status.success());
        assert!(status.stdout.is_empty());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn review_child_cannot_forge_controller_output_evidence() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("review-evidence-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-review-evidence"));
        let script = concat!(
            "target=\"$TEST_ARTIFACTS/../evidence/attempt-1/forge-output/normal/stdout.bin\"; ",
            "printf forged >\"$target\" 2>/dev/null || true; ",
            "printf 'captured-by-controller\\n'",
        );
        let mut settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        settings.review = ReviewSettings {
            checks: vec![ReviewCheckSettings {
                id: "forge-output".to_owned(),
                argv: vec!["sh".to_owned(), "-c".to_owned(), script.to_owned()],
                expected_exit_code: 0,
                relative_cwd: None,
                timeout_seconds: 30,
                required_absent_binaries: BTreeSet::new(),
            }],
            tool_versions: vec![ReviewToolVersionSettings {
                id: "shell".to_owned(),
                argv: vec![
                    "sh".to_owned(),
                    "-c".to_owned(),
                    "printf 'fixture-shell 1\\n'".to_owned(),
                ],
            }],
            optional_binaries: BTreeSet::new(),
            environment: BTreeMap::from([("TEST_ARTIFACTS".to_owned(), "{artifacts}".to_owned())]),
        };
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-review-evidence");
        create_profiled_test_team(&plane, &attached, "create-review-evidence-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let (request_id, candidate) =
            create_candidate_ready_test_request(&plane, &team_id, &attached, "review-evidence");
        let begun = plane
            .review_begin(&json!({
                "request": request_id,
                "candidate_sha": candidate.sha,
                "operation_id": "begin-review-evidence",
            }))
            .unwrap();
        let verified = plane
            .review_verify(&json!({
                "session": begun["session"]["session_id"],
                "operation_id": "verify-review-evidence",
            }))
            .unwrap();
        let shown = plane
            .review_show(&json!({
                "session": begun["session"]["session_id"],
                "limit": 100,
            }))
            .unwrap();
        let review = &shown["reviews"][0];
        if plane.review.sandbox_enforced() {
            assert_eq!(verified["attempt"]["status"], "passed", "{verified:#}");
            let result = &review["check_results"][0];
            let reference = result["stdout"]["reference"].as_str().unwrap();
            assert!(reference.starts_with("evidence/"));
            assert!(!reference.starts_with("artifacts/"));
            let session_root = PathBuf::from(begun["session"]["checkout_path"].as_str().unwrap())
                .parent()
                .unwrap()
                .to_path_buf();
            assert_eq!(
                fs::read(session_root.join(reference)).unwrap(),
                b"captured-by-controller\n"
            );
            plane.doctor().unwrap();
        } else {
            assert_eq!(verified["attempt"]["status"], "interrupted");
            assert_eq!(review["check_results"].as_array().unwrap().len(), 0);
            let reason = verified["interruption_reason"].as_str().unwrap();
            assert!(reason.contains("review_output_conflict"), "{verified:#}");
        }
    }

    fn create_liveness_test_plane(
        case: &str,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        ControlPlane,
        TeamId,
        ActorRef,
        ActorRef,
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id(&format!(
            "fixture-runtime-liveness-{case}"
        )));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        let primary = activate_test_primary(&plane, &format!("primary-liveness-{case}"));
        create_profiled_test_team(&plane, &team_root, &format!("create-liveness-{case}"));
        let observed_at = super::now_ms().unwrap();
        plane
            .store
            .mutate(
                &format!("test.{case}.primary_current"),
                &json!({ "primary": primary }),
                observed_at,
                |state| {
                    state
                        .heartbeat(&primary, TimestampMillis(observed_at))
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap();
        let team_id = TeamId::new("team-workers").unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let implementation = supervisor
            .actor(&ActorId::new("impl-workers-1").unwrap())
            .unwrap()
            .actor_ref();
        (
            temporary,
            team_root,
            plane,
            team_id,
            primary,
            implementation,
        )
    }

    fn mark_test_actor_stale(plane: &ControlPlane, actor_ref: &ActorRef, case: &str) {
        plane
            .store
            .mutate(
                &format!("test.{case}.actor_stale"),
                &json!({ "actor": actor_ref }),
                super::now_ms().unwrap(),
                |state| {
                    state
                        .set_actor_status(actor_ref, ActorStatus::Stale)
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap();
    }

    fn replace_test_implementation(
        plane: &ControlPlane,
        team_id: &TeamId,
        actor_ref: &ActorRef,
        case: &str,
    ) -> ActorRef {
        plane
            .store
            .mutate(
                &format!("test.{case}.actor_replaced"),
                &json!({ "actor": actor_ref }),
                super::now_ms().unwrap(),
                |state| {
                    state
                        .replace_implementation(team_id, actor_ref.actor_id.clone())
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap()
            .1
    }

    fn assert_stale_envelope_is_fenced(plane: &ControlPlane, envelope: &Envelope, case: &str) {
        let error = plane
            .store
            .mutate(
                &format!("test.{case}.stale_envelope"),
                &json!({ "message_id": envelope.message_id }),
                super::now_ms().unwrap(),
                |state| apply_envelope(state, envelope.clone()),
            )
            .unwrap_err();
        assert_eq!(error.code, "domain_error");
        assert!(error.message.contains("StaleTeamEpoch"), "{error}");
    }

    #[test]
    fn decision_submit_queues_for_a_stale_current_actor_and_preserves_replacement_fencing() {
        let (_temporary, team_root, plane, team_id, primary, implementation) =
            create_liveness_test_plane("decision");
        let (request_id, candidate) =
            create_candidate_ready_test_request(&plane, &team_id, &team_root, "stale-decision");
        let (fenced_request_id, fenced_candidate) =
            create_candidate_ready_test_request(&plane, &team_id, &team_root, "fenced-decision");
        let (_, before_stale, _) = plane.store.load().unwrap();
        let fenced_envelope = super::request_envelope(
            &before_stale,
            &fenced_request_id,
            primary,
            MessageTarget::Actor(implementation.actor_id.clone()),
            Message::ReviewDecision(ReviewDecision {
                decision_id: DecisionId::new("decision-fenced-after-replacement").unwrap(),
                candidate: fenced_candidate,
                verdict: ReviewVerdict::Accepted,
                reviewer: before_stale.active_primary().unwrap(),
                policy_revision: before_stale.policy_revision(),
                rationale: "must retain the old team fence".to_owned(),
                evidence: Vec::new(),
            }),
            MessageId::new("message-fenced-decision-after-replacement").unwrap(),
        )
        .unwrap()
        .0;

        mark_test_actor_stale(&plane, &implementation, "decision");
        let decided = plane
            .decision_submit(&json!({
                "request": request_id,
                "candidate_sha": candidate.sha,
                "decision": "accepted",
                "summary": "quiet is not replacement",
                "operation_id": "accept-stale-current-actor",
            }))
            .unwrap();

        assert_eq!(decided["wake_deferred"], true);
        let (_, after_decision, _) = plane.store.load().unwrap();
        assert_eq!(
            after_decision
                .actor(&implementation.actor_id)
                .unwrap()
                .status,
            ActorStatus::Stale
        );
        assert_eq!(
            after_decision.request(&request_id).unwrap().status,
            agsv_protocol::RequestStatus::IntegrationAuthorized
        );
        for suffix in ["decision", "authorization"] {
            assert!(
                after_decision
                    .delivery(&super::message_id("accept-stale-current-actor", suffix))
                    .is_some()
            );
        }

        let replacement =
            replace_test_implementation(&plane, &team_id, &implementation, "decision");
        assert_ne!(replacement, implementation);
        assert_stale_envelope_is_fenced(&plane, &fenced_envelope, "decision");
        let (_, after_fence, _) = plane.store.load().unwrap();
        assert_eq!(
            after_fence.request(&fenced_request_id).unwrap().status,
            agsv_protocol::RequestStatus::CandidateReady
        );
    }

    #[test]
    fn request_cancel_queues_for_a_stale_current_actor_and_preserves_replacement_fencing() {
        let (_temporary, _team_root, plane, team_id, primary, implementation) =
            create_liveness_test_plane("cancel");
        let cancelled = plane
            .request_create(&json!({
                "team": team_id,
                "title": "cancel while assigned actor is quiet",
                "operation_id": "create-stale-cancel-request",
            }))
            .unwrap();
        let request_id = RequestId::new(
            cancelled["request"]["request_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap();
        let fenced = plane
            .request_create(&json!({
                "team": team_id,
                "title": "retain cancellation replacement fence",
                "operation_id": "create-fenced-cancel-request",
            }))
            .unwrap();
        let fenced_request_id =
            RequestId::new(fenced["request"]["request_id"].as_str().unwrap().to_owned()).unwrap();
        let (_, before_stale, _) = plane.store.load().unwrap();
        let fenced_envelope = super::request_envelope(
            &before_stale,
            &fenced_request_id,
            primary,
            MessageTarget::Actor(implementation.actor_id.clone()),
            Message::Cancellation(Cancellation {
                reason: "must retain the old team fence".to_owned(),
            }),
            MessageId::new("message-fenced-cancel-after-replacement").unwrap(),
        )
        .unwrap()
        .0;

        mark_test_actor_stale(&plane, &implementation, "cancel");
        let result = plane
            .request_cancel(&json!({
                "id": request_id,
                "reason": "quiet actor still owns the durable assignment",
                "operation_id": "cancel-stale-current-actor",
            }))
            .unwrap();

        assert_eq!(result["wake_deferred"], true);
        let (_, after_cancel, _) = plane.store.load().unwrap();
        assert_eq!(
            after_cancel.request(&request_id).unwrap().status,
            agsv_protocol::RequestStatus::Cancelled
        );
        assert!(
            after_cancel
                .delivery(&super::message_id("cancel-stale-current-actor", "cancel"))
                .is_some()
        );

        let replacement = replace_test_implementation(&plane, &team_id, &implementation, "cancel");
        assert_ne!(replacement, implementation);
        assert_stale_envelope_is_fenced(&plane, &fenced_envelope, "cancel");
        let (_, after_fence, _) = plane.store.load().unwrap();
        assert_eq!(
            after_fence.request(&fenced_request_id).unwrap().status,
            agsv_protocol::RequestStatus::Assigned
        );
    }

    #[test]
    fn run_pause_and_resume_queue_for_a_stale_current_actor() {
        let (_temporary, _team_root, plane, team_id, _primary, implementation) =
            create_liveness_test_plane("run-control");
        let created = plane
            .request_create(&json!({
                "team": team_id,
                "title": "pause and resume while actor is quiet",
                "operation_id": "create-stale-run-control-request",
            }))
            .unwrap();
        let run_id = created["run"]["run_id"].as_str().unwrap().to_owned();
        mark_test_actor_stale(&plane, &implementation, "run-control");

        let paused = plane
            .run_transition(
                &json!({
                    "id": run_id,
                    "operation_id": "pause-stale-current-actor",
                }),
                RunControlAction::Pause,
                "run.pause",
            )
            .unwrap();
        assert_eq!(paused["wake_deferred"], true);
        let (_, after_pause, _) = plane.store.load().unwrap();
        assert_eq!(
            after_pause
                .run(&RunId::new(run_id.clone()).unwrap())
                .unwrap()
                .status,
            agsv_protocol::RunStatus::Paused
        );

        let resumed = plane
            .run_transition(
                &json!({
                    "id": run_id,
                    "operation_id": "resume-stale-current-actor",
                }),
                RunControlAction::Resume,
                "run.resume",
            )
            .unwrap();
        assert_eq!(resumed["wake_deferred"], true);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn message_send_queues_for_a_stale_current_team_and_preserves_epoch_and_caller_fences() {
        let (_temporary, _team_root, plane, team_id, primary, implementation) =
            create_liveness_test_plane("message");
        let actor_request = plane
            .request_create(&json!({
                "team": team_id,
                "title": "exercise stale caller fencing",
                "operation_id": "create-message-caller-fence-request",
            }))
            .unwrap();
        let actor_request_id = actor_request["request"]["request_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let (_, before_stale, _) = plane.store.load().unwrap();
        let fenced_message_id = MessageId::new("message-consultation-after-replacement").unwrap();
        let fenced_envelope = super::make_envelope(
            &before_stale,
            primary.clone(),
            MessageTarget::Team(team_id.clone()),
            Some(team_id.clone()),
            None,
            None,
            None,
            Message::ConsultationRequest(ConsultationRequest {
                consultation_id: fenced_message_id.clone(),
                target_team_id: team_id.clone(),
                subject: "replacement fence".to_owned(),
                question: "must retain the old team epoch".to_owned(),
                evidence: Vec::new(),
            }),
            fenced_message_id,
        )
        .unwrap();

        mark_test_actor_stale(&plane, &implementation, "message");
        plane.set_test_authenticated_actor(primary);
        let send_request = json!({
            "kind": "consultation_request",
            "to": team_id,
            "subject": "quiet team",
            "body": "durably queue this message without a live wake",
            "operation_id": "send-to-stale-current-team",
        });
        let sent = plane.message_send(&send_request).unwrap();

        assert_eq!(sent["wake_deferred"], true);
        let sent_message_id = super::message_id("send-to-stale-current-team", "send");
        let (_, after_send, _) = plane.store.load().unwrap();
        let delivery = after_send.delivery(&sent_message_id).unwrap();
        assert_eq!(
            delivery.envelope.target,
            MessageTarget::Team(team_id.clone())
        );
        assert_eq!(
            delivery.required_recipients,
            BTreeSet::from([actor_delivery_recipient(
                implementation.clone(),
                TeamEpoch::INITIAL,
            )])
        );
        assert!(delivery.acknowledgements.is_empty());
        assert_eq!(
            after_send.actor(&implementation.actor_id).unwrap().status,
            ActorStatus::Stale
        );
        plane
            .heartbeat_actor(&implementation, "test.message_target_returned")
            .unwrap();
        let (_, after_heartbeat, _) = plane.store.load().unwrap();
        assert!(
            after_heartbeat
                .unacknowledged_message_ids_for(&implementation)
                .unwrap()
                .contains(&sent_message_id),
            "the next heartbeat must expose the queued team delivery"
        );
        let retried = plane.message_send(&send_request).unwrap();
        assert_eq!(retried["wake"]["status"], "woken", "{retried:#}");
        assert_eq!(retried["message_id"], sent["message_id"]);

        let replacement = replace_test_implementation(&plane, &team_id, &implementation, "message");
        assert_ne!(replacement, implementation);
        let observed_at = super::now_ms().unwrap();
        plane
            .store
            .mutate(
                "test.message.post_replacement_roundtrip",
                &json!({ "actor": replacement }),
                observed_at,
                |state| {
                    state
                        .heartbeat(&replacement, TimestampMillis(observed_at))
                        .map_err(super::ControlError::core)
                },
            )
            .expect("the next store mutation restores the disposed prior-generation directive");
        let old_heartbeat = plane
            .heartbeat_actor(&implementation, "test.superseded_message_recipient")
            .unwrap_err();
        assert_eq!(old_heartbeat.code, "domain_error");
        assert!(old_heartbeat.message.contains("StaleActorEpoch"));
        let (_, after_replacement, _) = plane.store.load().unwrap();
        assert!(matches!(
            after_replacement.unacknowledged_message_ids_for(&implementation),
            Err(agsv_core::CoreError::StaleActorEpoch { .. })
        ));
        assert!(
            after_replacement
                .unacknowledged_message_ids_for(&replacement)
                .unwrap()
                .is_empty(),
            "removing exact recipient generations would leak the old inbox to its replacement"
        );
        assert!(
            after_replacement
                .delivery(&sent_message_id)
                .unwrap()
                .retired
        );
        assert_stale_envelope_is_fenced(&plane, &fenced_envelope, "message");

        plane.set_test_authenticated_actor(implementation);
        let stale_caller = plane
            .message_send(&json!({
                "kind": "progress",
                "request": actor_request_id,
                "body": "a replaced actor generation must not send",
                "operation_id": "send-from-replaced-actor",
            }))
            .unwrap_err();
        assert_eq!(stale_caller.code, "stale_actor_binding");
        assert_eq!(stale_caller.details["reason"], "team_generation_superseded");
        let (_, after_caller_fence, _) = plane.store.load().unwrap();
        assert!(
            after_caller_fence
                .delivery(&super::message_id("send-from-replaced-actor", "send"))
                .is_none()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn multi_recipient_retry_and_include_acked_remain_generation_fenced() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-multi-recipient-generation-fence",
        ));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            2,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        let primary = activate_test_primary(&plane, "primary-multi-recipient-fence");
        let observed_at = super::now_ms().unwrap();
        plane
            .store
            .mutate(
                "test.multi_recipient.primary_current",
                &json!({ "primary": primary }),
                observed_at,
                |state| {
                    state
                        .heartbeat(&primary, TimestampMillis(observed_at))
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap();
        plane
            .team_create(&json!({
                "name": "workers",
                "working_directory": team_root,
                "orchestrators": 2,
                "operation_id": "create-multi-recipient-fence-team",
            }))
            .unwrap();
        let team_id = TeamId::new("team-workers").unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let first = supervisor
            .actor(&ActorId::new("impl-workers-1").unwrap())
            .unwrap()
            .actor_ref();
        let second = supervisor
            .actor(&ActorId::new("impl-workers-2").unwrap())
            .unwrap()
            .actor_ref();
        plane.set_test_authenticated_actor(primary.clone());
        let send_request = json!({
            "kind": "consultation_request",
            "to": team_id,
            "subject": "generation-fenced broadcast",
            "body": "ack one recipient, then replace the other",
            "operation_id": "multi-recipient-generation-fence",
        });
        let initial_result = plane.message_send(&send_request).unwrap();
        assert_eq!(initial_result["wake"]["status"], "woken");
        let message_id = super::message_id("multi-recipient-generation-fence", "send");
        let (_, queued, _) = plane.store.load().unwrap();
        assert_eq!(
            queued.delivery(&message_id).unwrap().required_recipients,
            BTreeSet::from([
                actor_delivery_recipient(first.clone(), TeamEpoch::INITIAL),
                actor_delivery_recipient(second.clone(), TeamEpoch::INITIAL),
            ])
        );

        plane.set_test_authenticated_actor(first.clone());
        let visible_before_ack = plane
            .message_inbox(&json!({ "include_acked": true }))
            .unwrap();
        assert!(
            visible_before_ack["deliveries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|delivery| delivery["envelope"]["message_id"] == json!(message_id))
        );
        plane
            .message_ack(&json!({
                "id": message_id,
                "operation_id": "ack-first-multi-recipient",
            }))
            .unwrap();

        mark_test_actor_stale(&plane, &second, "multi-recipient-fence");
        let replacement =
            replace_test_implementation(&plane, &team_id, &second, "multi-recipient-fence");
        let (_, resolved, _) = plane.store.load().unwrap();
        let resolved_delivery = resolved
            .delivery(&message_id)
            .expect("requestless consultation remains hot until its correlated response");
        assert!(resolved_delivery.retired);
        assert_eq!(resolved_delivery.acknowledgements.len(), 1);
        assert_eq!(resolved_delivery.undeliverable_recipients.len(), 1);
        assert_eq!(
            resolved_delivery
                .undeliverable_recipients
                .values()
                .next()
                .unwrap(),
            &DeliveryRetirementReason::TeamGenerationSuperseded {
                team_id: team_id.clone(),
                team_epoch: TeamEpoch::INITIAL,
            }
        );

        plane.set_test_authenticated_actor(primary);
        let retried = plane.message_send(&send_request).unwrap();
        assert_eq!(retried["message_id"], initial_result["message_id"]);
        assert_eq!(retried["wake"]["status"], "not_applicable");

        for current_actor in [first, replacement] {
            plane.set_test_authenticated_actor(current_actor.clone());
            let include_acked = plane
                .message_inbox(&json!({ "include_acked": true }))
                .unwrap();
            assert!(
                include_acked["deliveries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|delivery| delivery["envelope"]["message_id"] != json!(message_id)),
                "current actor {current_actor:?} must not inherit prior-TeamEpoch history"
            );
        }
        plane.set_test_authenticated_actor(second);
        assert_eq!(
            plane
                .message_inbox(&json!({ "include_acked": true }))
                .unwrap_err()
                .code,
            "stale_actor_binding"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn workspace_archive_retry_wake_and_primary_history_are_generation_fenced() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-workspace-recipient",
        ));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            2,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        let primary = activate_test_primary(&plane, "primary-workspace-recipient");
        let observed_at = super::now_ms().unwrap();
        plane
            .store
            .mutate(
                "test.workspace_recipient.primary_current",
                &json!({ "primary": primary }),
                observed_at,
                |state| {
                    state
                        .heartbeat(&primary, TimestampMillis(observed_at))
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap();
        plane.ensure_primary_notification_session(&primary).unwrap();
        plane
            .team_create(&json!({
                "name": "workers",
                "working_directory": team_root,
                "orchestrators": 2,
                "operation_id": "create-workspace-recipient-team",
            }))
            .unwrap();
        let team_id = TeamId::new("team-workers").unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let first = supervisor
            .actor(&ActorId::new("impl-workers-1").unwrap())
            .unwrap()
            .actor_ref();
        let second = supervisor
            .actor(&ActorId::new("impl-workers-2").unwrap())
            .unwrap()
            .actor_ref();
        let message = Message::ConflictNotice(ConflictNotice {
            other_team_id: TeamId::new("team-fixture-peer").unwrap(),
            resources: vec!["fixture-resource".to_owned()],
            description: "fixture-only workspace routing".to_owned(),
        });
        let message_id = MessageId::new("workspace-recipient-archive-fixture").unwrap();
        let envelope = super::make_envelope(
            &supervisor,
            first.clone(),
            MessageTarget::Workspace,
            Some(team_id.clone()),
            None,
            None,
            None,
            message.clone(),
            message_id.clone(),
        )
        .unwrap();
        let message_json = serde_json::to_string(&message).unwrap();
        let payload_digest = PayloadDigest::new(sha256_hex(message_json.as_bytes())).unwrap();
        let acknowledgements = vec![
            Acknowledgement {
                workspace_id: supervisor.workspace_id().clone(),
                message_id: message_id.clone(),
                actor: primary.clone(),
                acknowledged_at: TimestampMillis(envelope.sent_at.0 + 1),
            },
            Acknowledgement {
                workspace_id: supervisor.workspace_id().clone(),
                message_id: message_id.clone(),
                actor: first.clone(),
                acknowledged_at: TimestampMillis(envelope.sent_at.0 + 2),
            },
            Acknowledgement {
                workspace_id: supervisor.workspace_id().clone(),
                message_id: message_id.clone(),
                actor: second.clone(),
                acknowledged_at: TimestampMillis(envelope.sent_at.0 + 3),
            },
        ];
        let delivery = DeliverySnapshot {
            envelope: EnvelopeHeader::from(&envelope),
            message_kind: message.kind(),
            payload_digest: payload_digest.clone(),
            causal: CausalMessage::ConflictNotice {
                other_team_id: TeamId::new("team-fixture-peer").unwrap(),
            },
            required_recipients: BTreeSet::from([
                DeliveryRecipient::Primary,
                actor_delivery_recipient(first.clone(), TeamEpoch::INITIAL),
                actor_delivery_recipient(second.clone(), TeamEpoch::INITIAL),
            ]),
            acknowledgements: acknowledgements.clone(),
            undeliverable_recipients: Vec::new(),
            retirement_reason: None,
            retired: true,
        };
        let delivery_json = serde_json::to_string(&delivery).unwrap();
        let delivery_digest = sha256_hex(delivery_json.as_bytes());
        let mut audits = vec![AuditEvent {
            sequence: 10_000,
            occurred_at: envelope.sent_at,
            team_id: Some(team_id.clone()),
            team_epoch: Some(TeamEpoch::INITIAL),
            kind: AuditEventKind::MessageAccepted {
                message_id: message_id.clone(),
                message_kind: message.kind(),
                payload_digest: Some(payload_digest.clone()),
            },
        }];
        audits.extend(
            acknowledgements
                .iter()
                .enumerate()
                .map(|(index, acknowledgement)| AuditEvent {
                    sequence: 10_001 + u64::try_from(index).unwrap(),
                    occurred_at: acknowledgement.acknowledged_at,
                    team_id: Some(team_id.clone()),
                    team_epoch: Some(TeamEpoch::INITIAL),
                    kind: AuditEventKind::MessageAcknowledged {
                        message_id: message_id.clone(),
                        actor_id: acknowledgement.actor.actor_id.clone(),
                    },
                }),
        );
        let connection = Connection::open(plane.store.path()).unwrap();
        let sent_at_sql = i64::try_from(envelope.sent_at.0).unwrap();
        connection
            .execute(
                "INSERT INTO message_bodies
                 (workspace_id, message_id, message_kind, content_sha256, body_json, created_at_ms)
                 VALUES (?1, ?2, 'conflict_notice', ?3, ?4, ?5)",
                rusqlite::params![
                    supervisor.workspace_id().as_str(),
                    message_id.as_str(),
                    payload_digest.as_str(),
                    message_json,
                    sent_at_sql,
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO delivery_archive
                 (workspace_id, message_id, request_id, sender_actor_id, sender_actor_epoch,
                  message_kind, sent_at_ms, decision_id, candidate_sha, consultation_id,
                  delivery_sha256, delivery_json, archived_revision, archived_at_ms)
                 VALUES (?1, ?2, NULL, ?3, ?4, 'conflict_notice', ?5,
                         NULL, NULL, NULL, ?6, ?7, 1, ?5)",
                rusqlite::params![
                    supervisor.workspace_id().as_str(),
                    message_id.as_str(),
                    first.actor_id.as_str(),
                    i64::try_from(first.actor_epoch.get()).unwrap(),
                    sent_at_sql,
                    delivery_digest,
                    delivery_json,
                ],
            )
            .unwrap();
        let mut previous_digest = None;
        for audit in audits {
            let audit_json = serde_json::to_string(&audit).unwrap();
            let audit_digest = sha256_hex(audit_json.as_bytes());
            connection
                .execute(
                    "INSERT INTO protocol_audit_archive
                     (workspace_id, sequence, message_id, event_sha256, previous_sha256,
                      event_json, archived_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        supervisor.workspace_id().as_str(),
                        i64::try_from(audit.sequence).unwrap(),
                        message_id.as_str(),
                        audit_digest,
                        previous_digest.as_deref(),
                        audit_json,
                        sent_at_sql,
                    ],
                )
                .unwrap();
            previous_digest = Some(audit_digest);
        }
        drop(connection);

        assert_eq!(
            plane
                .store
                .mutate(
                    "test.workspace_recipient.retry",
                    &json!({ "message_id": message_id }),
                    super::now_ms().unwrap(),
                    |state| super::apply_envelope_with_archive(
                        &plane.store,
                        state,
                        envelope.clone()
                    ),
                )
                .unwrap()
                .1,
            ApplyOutcome::Duplicate
        );
        plane
            .notify_target(&MessageTarget::Workspace, "read the workspace fixture")
            .unwrap();
        plane
            .notify_target(&MessageTarget::Workspace, "read the workspace fixture")
            .unwrap();

        for actor in [&primary, &first, &second] {
            plane.set_test_authenticated_actor(actor.clone());
            let inbox = plane
                .message_inbox(&json!({ "include_acked": true }))
                .unwrap();
            assert!(
                inbox["deliveries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|item| { item["envelope"]["message_id"] == json!(message_id) })
            );
        }
        plane.set_test_authenticated_actor(primary.clone());
        let duplicate_ack = plane
            .message_ack(&json!({
                "id": message_id,
                "operation_id": "ack-workspace-recipient-fixture",
            }))
            .unwrap();
        assert_eq!(duplicate_ack["outcome"], "duplicate");

        mark_test_actor_stale(&plane, &second, "workspace-recipient");
        let replacement =
            replace_test_implementation(&plane, &team_id, &second, "workspace-recipient");
        for current_actor in [first, replacement] {
            plane.set_test_authenticated_actor(current_actor);
            let inbox = plane
                .message_inbox(&json!({ "include_acked": true }))
                .unwrap();
            assert!(
                inbox["deliveries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|item| { item["envelope"]["message_id"] != json!(message_id) })
            );
        }
        plane.set_test_authenticated_actor(primary);
        let primary_after_team_replacement = plane
            .message_inbox(&json!({ "include_acked": true }))
            .unwrap();
        assert!(
            primary_after_team_replacement["deliveries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["envelope"]["message_id"] == json!(message_id))
        );
    }

    #[test]
    fn progress_to_an_expired_primary_is_visible_after_primary_reacquisition() {
        let (_temporary, _team_root, plane, team_id, primary, implementation) =
            create_liveness_test_plane("primary-reacquisition-inbox");
        let created = plane
            .request_create(&json!({
                "team": team_id,
                "title": "report while the Primary is quiet",
                "operation_id": "create-primary-reacquisition-inbox-request",
            }))
            .unwrap();
        let request_id = created["request"]["request_id"].as_str().unwrap();
        plane
            .store
            .mutate(
                "test.expire_primary_before_progress",
                &json!({}),
                1,
                |state| {
                    state
                        .set_actor_status(&primary, ActorStatus::Stale)
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap();
        let (_, expired, _) = plane.store.load().unwrap();
        assert!(expired.active_primary().is_none());

        plane.set_test_authenticated_actor(implementation);
        let sent = plane
            .message_send(&json!({
                "kind": "progress",
                "request": request_id,
                "body": "durable progress survives the quiet Primary lease",
                "operation_id": "progress-before-primary-reacquisition",
            }))
            .unwrap();
        assert_eq!(sent["wake"]["status"], "deferred");
        assert_eq!(sent["wake"]["reason"]["code"], "primary_unavailable");
        let message_id = MessageId::new(sent["message_id"].as_str().unwrap().to_owned()).unwrap();
        let (_, queued, _) = plane.store.load().unwrap();
        assert_eq!(
            queued
                .delivery(&message_id)
                .expect("progress delivery is durable")
                .required_recipients,
            BTreeSet::from([agsv_protocol::DeliveryRecipient::Primary])
        );

        let replacement = plane.activate_primary(&primary.actor_id).unwrap();
        assert_ne!(replacement, primary);
        plane.set_test_authenticated_actor(replacement.clone());
        let inbox = plane.message_inbox(&json!({})).unwrap();
        assert_eq!(inbox["actor"], json!(replacement));
        assert!(
            inbox["deliveries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|delivery| delivery["envelope"]["message_id"] == json!(message_id)),
            "the reacquired logical Primary slot reads progress committed while no lease was active"
        );
    }

    #[test]
    fn post_commit_wake_errors_are_recorded_as_deferred() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let linked = temporary.path().join("linked-worktree");
        init_test_repository(&root, &linked);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-live-notification-failure",
        ));
        let settings = legacy_settings(root, temporary.path().join("state"), runtime.id().as_str());
        let plane = open_fixture_plane(settings, &runtime);
        let team_id = TeamId::new("team-live-notification-failure").unwrap();
        let actor_id = ActorId::new("impl-live-notification-failure-1").unwrap();
        let observed_at = super::now_ms().unwrap();
        let (_, primary) = plane
            .store
            .mutate(
                "test.live_notification_target",
                &json!({}),
                observed_at,
                |state| {
                    let primary = state
                        .activate_primary(ActorId::new("primary-live-notification").unwrap())
                        .map_err(super::ControlError::core)?;
                    state
                        .heartbeat(&primary, TimestampMillis(observed_at))
                        .map_err(super::ControlError::core)?;
                    state
                        .create_team(team_id.clone())
                        .map_err(super::ControlError::core)?;
                    let actor = state
                        .register_implementation(&team_id, actor_id.clone())
                        .map_err(super::ControlError::core)?;
                    state
                        .heartbeat(&actor, TimestampMillis(observed_at))
                        .map_err(super::ControlError::core)?;
                    Ok(primary)
                },
            )
            .unwrap();
        assert!(plane.store.session(actor_id.as_str()).unwrap().is_none());
        plane.set_test_authenticated_actor(primary);

        let request = json!({
            "kind": "directive",
            "to": actor_id,
            "team": team_id,
            "decision": "commit before attempting a wake",
            "rationale": "notification availability cannot change durable acceptance",
            "operation_id": "post-commit-wake-deferred",
        });
        let sent = plane.message_send(&request).unwrap();

        assert_eq!(sent["wake"]["status"], "deferred");
        assert_eq!(sent["wake"]["reason"]["code"], "session_not_found");
        let message_id = super::message_id("post-commit-wake-deferred", "send");
        let (_, current, _) = plane.store.load().unwrap();
        assert!(current.delivery(&message_id).is_some());
        assert_eq!(plane.message_send(&request).unwrap(), sent);
    }

    #[test]
    fn primary_heartbeat_cas_refuses_to_revive_an_expired_lease() {
        let (_temporary, _team_root, mut plane, _team_id, primary, _implementation) =
            create_liveness_test_plane("primary-lease-cas");
        plane.settings.primary_lease_seconds = 0;
        let (_, before_attempt, _) = plane.store.load().unwrap();
        let original_heartbeat = before_attempt
            .actor(&primary.actor_id)
            .expect("Primary exists")
            .last_heartbeat_at;

        let error = plane
            .heartbeat_actor(&primary, "test.primary_privileged_command")
            .unwrap_err();
        assert_eq!(error.code, "primary_lease_expired");
        let (_, before_expiry_reconcile, _) = plane.store.load().unwrap();
        let actor = before_expiry_reconcile
            .actor(&primary.actor_id)
            .expect("Primary remains present until normal expiry reconciliation");
        assert_eq!(actor.last_heartbeat_at, original_heartbeat);
        assert_eq!(
            before_expiry_reconcile.active_primary(),
            Some(primary.clone())
        );

        plane.expire_stale_actors(true).unwrap();
        let (_, expired, _) = plane.store.load().unwrap();
        assert!(expired.active_primary().is_none());
        assert_eq!(
            expired.actor(&primary.actor_id).unwrap().status,
            ActorStatus::Stale
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn bound_expired_primary_recovers_for_inbox_and_replays_mutation_exactly() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-bound-primary-recovery",
        ));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let mut plane = open_fixture_plane(settings, &runtime);
        let primary = activate_test_primary(&plane, "primary-bound-recovery");
        let observed_at = now_ms().unwrap();
        plane
            .store
            .mutate(
                "test.bound_primary_recovery.current",
                &json!({ "primary": primary }),
                observed_at,
                |state| {
                    state
                        .heartbeat(&primary, TimestampMillis(observed_at))
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap();
        create_profiled_test_team(&plane, &team_root, "create-bound-primary-recovery-team");
        plane
            .store
            .bind_actor("test_pane", "bound-primary-recovery", &primary, observed_at)
            .unwrap();
        plane.set_test_caller_binding("test_pane", "bound-primary-recovery");

        let pause_request = json!({
            "id": "team-workers",
            "operation_id": "pause-before-primary-recovery",
        });
        let initial_pause = plane.execute("team.pause", &pause_request).unwrap();
        mark_test_actor_stale(&plane, &primary, "bound-primary-recovery");
        let (_, expired, _) = plane.store.load().unwrap();
        assert!(expired.active_primary().is_none());
        assert_eq!(
            expired.actor(&primary.actor_id).unwrap().status,
            ActorStatus::Stale
        );
        let expired_revision = plane.store.load().unwrap().0;
        let expired_session = plane
            .store
            .session(primary.actor_id.as_str())
            .unwrap()
            .unwrap();
        let expired_session_revision = expired_session.row_revision;
        let expired_session_json = serde_json::to_value(&expired_session).unwrap();
        StateStore::interrupt_primary_bootstrap_before_commit();
        let interrupted = plane.execute("message.inbox", &json!({})).unwrap_err();
        assert_eq!(interrupted.code, "test_primary_bootstrap_interrupted");
        let (_, after_interruption, _) = plane.store.load().unwrap();
        assert_eq!(plane.store.load().unwrap().0, expired_revision);
        assert!(after_interruption.active_primary().is_none());
        assert_eq!(
            after_interruption
                .actor(&primary.actor_id)
                .unwrap()
                .actor_ref(),
            primary
        );
        assert_eq!(
            plane
                .store
                .actor_binding("test_pane", "bound-primary-recovery")
                .unwrap()
                .unwrap()
                .actor,
            primary
        );
        let after_interruption_session = plane
            .store
            .session(primary.actor_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(&after_interruption_session).unwrap(),
            expired_session_json
        );
        assert_eq!(
            after_interruption_session.row_revision, expired_session_revision,
            "the interrupted transaction must roll back the session CAS token"
        );

        let inbox = plane.execute("message.inbox", &json!({})).unwrap();
        let recovered: ActorRef = serde_json::from_value(inbox["actor"].clone()).unwrap();
        assert_eq!(recovered.actor_id, primary.actor_id);
        assert!(recovered.actor_epoch > primary.actor_epoch);
        assert_eq!(
            plane
                .store
                .actor_binding("test_pane", "bound-primary-recovery")
                .unwrap()
                .unwrap()
                .actor,
            recovered
        );
        assert_eq!(
            plane
                .store
                .session(primary.actor_id.as_str())
                .unwrap()
                .unwrap()
                .row_revision,
            expired_session_revision.checked_add(1).unwrap(),
            "successful Primary recovery must advance the session CAS token exactly once"
        );

        let replayed_pause = plane.execute("team.pause", &pause_request).unwrap();
        assert_eq!(replayed_pause, initial_pause);
        let (_, recovered_state, _) = plane.store.load().unwrap();
        assert_eq!(recovered_state.active_primary(), Some(recovered.clone()));
        assert_eq!(
            recovered_state.actor(&recovered.actor_id).unwrap().status,
            ActorStatus::Healthy
        );
        assert_eq!(
            plane
                .store
                .events(100)
                .unwrap()
                .into_iter()
                .filter(|event| event.operation == "team.pause")
                .count(),
            1,
            "the recovered retry must use the original idempotent result"
        );
        assert_eq!(
            plane
                .store
                .events(100)
                .unwrap()
                .into_iter()
                .filter(|event| event.operation == "primary.lease_recovered")
                .count(),
            1,
            "the interrupted transaction must not retain a partial recovery event"
        );
    }

    #[test]
    fn superseded_primary_binding_is_refused_with_a_recovery_hint() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let linked = temporary.path().join("linked-worktree");
        init_test_repository(&root, &linked);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-superseded-primary-binding",
        ));
        let settings = legacy_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime.id().as_str(),
        );
        let mut plane = open_fixture_plane(settings, &runtime);
        let primary = activate_test_primary(&plane, "primary-superseded-binding");
        let observed_at = now_ms().unwrap();
        plane
            .store
            .mutate(
                "test.superseded_primary_binding.current",
                &json!({ "primary": primary }),
                observed_at,
                |state| {
                    state
                        .heartbeat(&primary, TimestampMillis(observed_at))
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap();
        create_profiled_test_team(&plane, &linked, "create-superseded-primary-binding-team");
        plane
            .store
            .bind_actor(
                "test_pane",
                "superseded-primary-binding",
                &primary,
                observed_at,
            )
            .unwrap();
        plane.set_test_caller_binding("test_pane", "superseded-primary-binding");
        let cached_request = json!({
            "id": "team-workers",
            "operation_id": "cached-before-primary-supersession",
        });
        plane.execute("team.pause", &cached_request).unwrap();
        mark_test_actor_stale(&plane, &primary, "superseded-primary-binding");
        let replacement = plane.activate_primary(&primary.actor_id).unwrap();
        assert!(replacement.actor_epoch > primary.actor_epoch);
        let revision = plane.store.load().unwrap().0;

        for (operation, request) in [
            ("message.inbox", json!({})),
            ("context", json!({ "bootstrap": true })),
            ("team.pause", cached_request),
        ] {
            let refusal = plane.execute(operation, &request).unwrap_err();
            assert_eq!(refusal.code, "stale_actor_binding");
            assert_eq!(refusal.details["reason"], "primary_generation_superseded");
            assert!(
                refusal
                    .hint
                    .as_deref()
                    .is_some_and(|hint| hint.contains("active Primary caller session")),
                "{operation} refusal must explain the only valid recovery path"
            );
        }
        assert_eq!(plane.store.load().unwrap().0, revision);
        assert_eq!(
            plane
                .store
                .actor_binding("test_pane", "superseded-primary-binding")
                .unwrap()
                .unwrap()
                .actor,
            primary,
            "a superseded caller must never be rebound to the active generation"
        );
        assert_eq!(
            plane.store.load().unwrap().1.active_primary(),
            Some(replacement)
        );
    }

    #[test]
    fn exact_stale_primary_binding_cannot_recover_over_a_different_active_primary() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let linked = temporary.path().join("linked-worktree");
        init_test_repository(&root, &linked);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-exact-stale-primary-binding",
        ));
        let settings = legacy_settings(root, temporary.path().join("state"), runtime.id().as_str());
        let mut plane = open_fixture_plane(settings, &runtime);
        let stale_primary = activate_test_primary(&plane, "primary-exact-stale-binding");
        let observed_at = now_ms().unwrap();
        plane
            .store
            .bind_actor(
                "test_pane",
                "exact-stale-primary-binding",
                &stale_primary,
                observed_at,
            )
            .unwrap();
        plane.set_test_caller_binding("test_pane", "exact-stale-primary-binding");
        mark_test_actor_stale(&plane, &stale_primary, "exact-stale-primary-binding");

        let active_primary = plane
            .activate_primary(&ActorId::new("primary-different-active-binding").unwrap())
            .unwrap();
        assert_ne!(active_primary.actor_id, stale_primary.actor_id);

        let (revision_before, state_before, _) = plane.store.load().unwrap();
        let stale_actor_before = state_before
            .actor(&stale_primary.actor_id)
            .expect("the exact bound Primary generation remains durable")
            .clone();
        let active_actor_before = state_before
            .actor(&active_primary.actor_id)
            .expect("the different active Primary remains durable")
            .clone();
        let primary_epoch_before = state_before.primary_epoch();
        assert_eq!(stale_actor_before.actor_ref(), stale_primary);
        assert_eq!(stale_actor_before.status, ActorStatus::Stale);
        assert_eq!(state_before.active_primary(), Some(active_primary.clone()));
        assert!(matches!(
            plane.caller_mutation_fence().unwrap(),
            Some(super::CallerMutationFence::SupersededPrimary(actor_ref))
                if actor_ref == stale_primary
        ));

        let direct_refusal = plane.recover_expired_primary_binding(true).unwrap_err();
        assert_eq!(direct_refusal.code, "stale_actor_binding");
        assert_eq!(
            direct_refusal.details["reason"],
            "primary_generation_superseded"
        );
        assert!(
            direct_refusal
                .hint
                .as_deref()
                .is_some_and(|hint| hint.contains("active Primary caller session")),
            "the recovery fence must identify the valid active Primary session"
        );

        let inbox_refusal = plane.execute("message.inbox", &json!({})).unwrap_err();
        assert_eq!(inbox_refusal.code, "stale_actor_binding");
        assert_eq!(
            inbox_refusal.details["reason"],
            "primary_generation_superseded"
        );
        assert_eq!(inbox_refusal.details["actor"], json!(stale_primary));
        assert_eq!(inbox_refusal.details["status"], "stale");
        assert!(
            inbox_refusal
                .hint
                .as_deref()
                .is_some_and(|hint| hint.contains("active Primary caller session")),
            "ordinary authenticated admission must direct the caller to the active Primary session"
        );

        let (revision_after, state_after, _) = plane.store.load().unwrap();
        assert_eq!(revision_after, revision_before);
        assert_eq!(state_after.primary_epoch(), primary_epoch_before);
        assert_eq!(state_after.active_primary(), Some(active_primary.clone()));
        assert_eq!(
            state_after.actor(&stale_primary.actor_id),
            Some(&stale_actor_before),
            "the exact stale generation must not be revoked or replaced"
        );
        assert_eq!(
            state_after.actor(&active_primary.actor_id),
            Some(&active_actor_before),
            "refusal must not renew or otherwise change the active lease"
        );
        assert_eq!(
            plane
                .store
                .actor_binding("test_pane", "exact-stale-primary-binding")
                .unwrap()
                .unwrap()
                .actor,
            stale_primary,
            "refusal must not rebind the stale caller to the active Primary"
        );
    }

    #[test]
    fn concurrent_heartbeat_retry_preserves_the_newest_observation() {
        let (_temporary, _team_root, plane, _team_id, primary, _implementation) =
            create_liveness_test_plane("primary-heartbeat-monotonic");
        let (_, initial, _) = plane.store.load().unwrap();
        let baseline = initial
            .actor(&primary.actor_id)
            .and_then(|actor| actor.last_heartbeat_at)
            .expect("test Primary has a heartbeat")
            .0;
        let older = TimestampMillis(baseline.saturating_add(10));
        let newer = TimestampMillis(baseline.saturating_add(20));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let attempts = Arc::new(AtomicU64::new(0));
        let old_store = plane.store.clone();
        let old_primary = primary.clone();
        let old_entered = Arc::clone(&entered);
        let old_release = Arc::clone(&release);
        let old_attempts = Arc::clone(&attempts);
        let older_thread = std::thread::spawn(move || {
            old_store
                .mutate(
                    "test.concurrent_older_heartbeat",
                    &json!({}),
                    older.0,
                    |state| {
                        if old_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                            old_entered.wait();
                            old_release.wait();
                        }
                        state
                            .heartbeat(&old_primary, older)
                            .map_err(super::ControlError::core)
                    },
                )
                .unwrap();
        });

        entered.wait();
        plane
            .store
            .mutate(
                "test.concurrent_newer_heartbeat",
                &json!({}),
                newer.0,
                |state| {
                    state
                        .heartbeat(&primary, newer)
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap();
        release.wait();
        older_thread.join().unwrap();

        assert!(attempts.load(Ordering::SeqCst) >= 2);
        let (_, current, _) = plane.store.load().unwrap();
        assert_eq!(
            current
                .actor(&primary.actor_id)
                .expect("Primary remains current")
                .last_heartbeat_at,
            Some(newer)
        );
    }

    #[test]
    fn session_names_preserve_uniqueness_after_truncation() {
        let actor = ActorRef {
            actor_id: ActorId::new("impl-a-very-long-team-name-that-needs-truncation-1").unwrap(),
            actor_epoch: ActorEpoch::INITIAL,
        };
        let second_actor = ActorRef {
            actor_id: ActorId::new("impl-a-very-long-team-name-that-needs-truncation-2").unwrap(),
            actor_epoch: ActorEpoch::INITIAL,
        };
        let replacement_actor = ActorRef {
            actor_id: actor.actor_id.clone(),
            actor_epoch: ActorEpoch::new(2).unwrap(),
        };
        let first = session_name("workspace-one", &actor);
        let second = session_name("workspace-one", &second_actor);
        let replacement = session_name("workspace-one", &replacement_actor);
        let other_workspace = session_name("workspace-two", &actor);

        assert_ne!(first, second);
        assert_ne!(first, replacement);
        assert_ne!(first, other_workspace);
        assert!(first.len() <= 32);
        assert!(second.len() <= 32);
        assert!(replacement.len() <= 32);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn layout_hints_anchor_default_packing_to_the_durable_primary_session() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        fs::create_dir(&root).unwrap();
        run_git(&root, &["init", "-q"]);
        let mut settings = legacy_settings(root.clone(), temporary.path().join("state"), "codex");
        settings.backend = "herdr".to_owned();
        let mut plane = ControlPlane::open(settings).unwrap();
        plane.sessions = SessionDriver::checkpoint_recovery_test_driver();
        let team_id = TeamId::new("team-layout").unwrap();
        let (_, (primary, actors)) = plane
            .store
            .mutate("test.setup", &json!({}), 1, |state| {
                let primary = state
                    .activate_primary(ActorId::new("primary-layout").unwrap())
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&primary, TimestampMillis(1))
                    .map_err(super::ControlError::core)?;
                state
                    .create_team(team_id.clone())
                    .map_err(super::ControlError::core)?;
                let actors = (1..=3)
                    .map(|index| {
                        state
                            .register_implementation(
                                &team_id,
                                ActorId::new(format!("impl-layout-{index}")).unwrap(),
                            )
                            .map_err(super::ControlError::core)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((primary, actors))
            })
            .unwrap();
        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: primary.actor_id.to_string(),
                team_id: None,
                working_directory: root.clone(),
                backend: LAYOUT_FAILURE_BACKEND_ID.to_owned(),
                runtime: None,
                external_id: Some("w6:p1".to_owned()),
                resume_token: Some("w6:p1".to_owned()),
                status: "idle".to_owned(),
                launch_key: "primary-layout".to_owned(),
                updated_at_ms: 2,
                row_revision: 0,
            })
            .unwrap();
        let first = plane
            .store
            .allocate_session_presentation(
                actors[0].actor_id.as_str(),
                team_id.as_str(),
                "agsv:layout",
                "agsv:layout",
                2,
                true,
                &[],
                &[],
                3,
            )
            .unwrap();
        let second = plane
            .store
            .allocate_session_presentation(
                actors[1].actor_id.as_str(),
                team_id.as_str(),
                "agsv:layout:2",
                "agsv:layout:2",
                2,
                true,
                &[],
                &[],
                4,
            )
            .unwrap();
        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: actors[1].actor_id.to_string(),
                team_id: Some(team_id.to_string()),
                working_directory: root,
                backend: LAYOUT_FAILURE_BACKEND_ID.to_owned(),
                runtime: Some(plane.selected_team_runtime().unwrap().id().to_string()),
                external_id: Some("layout-worker-two".to_owned()),
                resume_token: Some("w6:p2".to_owned()),
                status: "idle".to_owned(),
                launch_key: "layout-two".to_owned(),
                updated_at_ms: 5,
                row_revision: 0,
            })
            .unwrap();
        let third = plane
            .store
            .allocate_session_presentation(
                actors[2].actor_id.as_str(),
                team_id.as_str(),
                "agsv:layout:3",
                "agsv:layout:3",
                2,
                true,
                &[],
                &[1],
                6,
            )
            .unwrap();
        assert_eq!(
            first.slot.unwrap(),
            crate::store::PresentationSlot {
                tab_sequence: 0,
                pane_index: 1,
            }
        );
        assert_eq!(second.slot.unwrap().tab_sequence, 1);
        assert_eq!(third.slot.unwrap().tab_sequence, 1);

        let first_hints = plane
            .launch_hints(&actors[0].actor_id, LAYOUT_FAILURE_BACKEND_ID)
            .unwrap();
        let SessionPlacement::Beside { anchor, direction } = first_hints.placement.unwrap() else {
            panic!("first implementation must be beside Primary");
        };
        assert_eq!(anchor.resume_token.as_deref(), Some("w6:p1"));
        assert_eq!(direction, SplitDirection::Right);
        assert!(!first_hints.focus);

        let second_hints = plane
            .launch_hints(&actors[1].actor_id, LAYOUT_FAILURE_BACKEND_ID)
            .unwrap();
        let SessionPlacement::NewGroup {
            scope_anchor,
            label,
        } = second_hints.placement.unwrap()
        else {
            panic!("second implementation must create a managed group");
        };
        assert_eq!(scope_anchor.resume_token.as_deref(), Some("w6:p1"));
        assert_eq!(label, "1");

        let third_hints = plane
            .launch_hints(&actors[2].actor_id, LAYOUT_FAILURE_BACKEND_ID)
            .unwrap();
        let SessionPlacement::Beside { anchor, .. } = third_hints.placement.unwrap() else {
            panic!("third implementation must pack beside its sibling");
        };
        assert_eq!(anchor.resume_token.as_deref(), Some("w6:p2"));
        assert_eq!(
            plane.store.load().unwrap().1.snapshot().teams[0]
                .epoch
                .get(),
            1
        );

        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: actors[2].actor_id.to_string(),
                team_id: Some(team_id.to_string()),
                working_directory: plane.identity.root().to_path_buf(),
                backend: LAYOUT_FAILURE_BACKEND_ID.to_owned(),
                runtime: Some(plane.selected_team_runtime().unwrap().id().to_string()),
                external_id: Some("layout-worker-three".to_owned()),
                resume_token: Some("w6:p3".to_owned()),
                status: "idle".to_owned(),
                launch_key: "layout-three".to_owned(),
                updated_at_ms: 7,
                row_revision: 0,
            })
            .unwrap();
        let mut stopped_root = plane
            .store
            .session(actors[1].actor_id.as_str())
            .unwrap()
            .unwrap();
        stopped_root.status = "stopped".to_owned();
        stopped_root.updated_at_ms = 8;
        plane.store.upsert_session(&stopped_root).unwrap();

        let reusable = plane
            .reusable_group_sequences(LAYOUT_FAILURE_BACKEND_ID)
            .unwrap();
        assert!(reusable.is_empty());
        let after_dead_root = plane
            .store
            .allocate_session_presentation(
                "impl-layout-after-dead-root",
                team_id.as_str(),
                "agsv:layout:4",
                "agsv:layout:4",
                2,
                true,
                &[],
                &reusable,
                9,
            )
            .unwrap();
        assert_eq!(
            after_dead_root.slot,
            Some(crate::store::PresentationSlot {
                tab_sequence: 2,
                pane_index: 0,
            })
        );
    }

    #[test]
    fn implementation_bootstrap_uses_absolute_quoted_executable_without_workspace_override() {
        assert_eq!(
            shell_single_quote("/tmp/Agent Supervisor/it's-agsv"),
            "'/tmp/Agent Supervisor/it'\"'\"'s-agsv'"
        );
        let prompt = implementation_prompt(
            "role",
            "implementation",
            &ActorRef {
                actor_id: ActorId::new("impl-test").unwrap(),
                actor_epoch: ActorEpoch::INITIAL,
            },
            &TeamId::new("team-test").unwrap(),
        )
        .unwrap();
        let executable = std::env::current_exe().unwrap();
        assert!(executable.is_absolute());
        assert!(prompt.contains(executable.to_str().unwrap()));
        assert!(prompt.contains("--json context --bootstrap"));
        assert!(prompt.contains("end the launch turn immediately"));
        assert!(!prompt.contains(" --workspace "));
    }

    #[test]
    fn codex_launch_uses_non_conflicting_automatic_approval_arguments() {
        let runtime = RuntimeRegistry::new().select(Some("codex")).unwrap();
        let config = agsv_runtime::RuntimeConfig::new("gpt-test", "max");
        let invocation = runtime
            .launch_invocation(RuntimeLaunchRequest {
                config: &config,
                initial_prompt: None,
            })
            .unwrap();
        assert_eq!(
            invocation.arguments,
            [
                "-m",
                "gpt-test",
                "-c",
                "model_reasoning_effort=\"max\"",
                "--approve-for-me",
            ]
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn explicit_zero_desired_instances_create_no_capacity_and_remain_converged() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-zero"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            0,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        let primary = activate_test_primary(&plane, "primary-zero");
        let observed_at = super::now_ms().unwrap();
        plane
            .store
            .mutate(
                "test.zero_primary_current",
                &json!({}),
                observed_at,
                |state| {
                    state
                        .heartbeat(&primary, TimestampMillis(observed_at))
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap();

        let created = create_profiled_test_team(&plane, &team_root, "create-zero");
        assert_eq!(created["team_profile"]["desired_instances"], 0);
        assert_eq!(created["actors"], json!([]));
        assert_eq!(created["sessions"], json!([]));
        assert_eq!(runtime.launch_count(), 0);

        let reconciled = plane.reconcile().unwrap();
        assert_eq!(reconciled["complete"], true);
        assert_eq!(
            reconciled["instance_reconciliation"][0]["desired_instances"],
            0
        );
        assert_eq!(
            reconciled["instance_reconciliation"][0]["state"]["converged"],
            true
        );
        let (_, supervisor, _) = plane.store.load().unwrap();
        assert!(
            supervisor
                .team(&TeamId::new("team-workers").unwrap())
                .unwrap()
                .actors
                .is_empty()
        );
        plane.set_test_authenticated_actor(primary);
        let refused = plane
            .message_send(&json!({
                "kind": "directive",
                "to": "team-workers",
                "team": "team-workers",
                "decision": "do not queue without capacity",
                "rationale": "there is no logical acknowledgement recipient",
                "operation_id": "zero-capacity-directive-refused",
            }))
            .unwrap_err();
        assert_eq!(refused.code, "team_zero_capacity");
        let (_, after_refusal, _) = plane.store.load().unwrap();
        assert!(
            after_refusal
                .delivery(&super::message_id(
                    "zero-capacity-directive-refused",
                    "send"
                ))
                .is_none(),
            "capacity admission is checked before the durable commit point"
        );
        assert!(
            plane
                .store
                .sessions()
                .unwrap()
                .iter()
                .all(|session| session.team_id.is_none()),
            "zero desired instances create no implementation sessions"
        );

        plane
            .team_close(&json!({
                "id": "team-workers",
                "operation_id": "close-zero-capacity-directive-team",
            }))
            .unwrap();
        let closed_refusal = plane
            .message_send(&json!({
                "kind": "directive",
                "to": "team-workers",
                "team": "team-workers",
                "decision": "do not queue after close",
                "rationale": "a closed team cannot acknowledge new directives",
                "operation_id": "closed-team-directive-refused",
            }))
            .unwrap_err();
        assert_eq!(closed_refusal.code, "team_closed");
        let (_, after_closed_refusal, _) = plane.store.load().unwrap();
        assert!(
            after_closed_refusal
                .delivery(&super::message_id("closed-team-directive-refused", "send"))
                .is_none()
        );
    }

    #[test]
    fn team_create_commit_crash_reconciles_without_duplicate_session() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-create-crash"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings.clone(), &runtime);
        activate_test_primary(&plane, "primary-create-crash");
        let request = json!({
            "name": "workers",
            "orchestrators": 1,
            "operation_id": "create-crash-recovery",
        });

        plane.arm_test_crash("team_create_commit");
        let error = plane.team_create(&request).unwrap_err();
        assert_eq!(error.code, "simulated_team_create_crash");
        assert_eq!(runtime.launch_count(), 0);
        let team_id = TeamId::new("team-workers").unwrap();
        let actor_id = ActorId::new("impl-workers-1").unwrap();
        let (_, crashed, _) = plane.store.load().unwrap();
        assert_eq!(
            crashed.team(&team_id).unwrap().actors.as_slice(),
            std::slice::from_ref(&actor_id)
        );
        let source_ref = crashed.actor(&actor_id).unwrap().actor_ref();
        assert_eq!(source_ref.actor_epoch, ActorEpoch::INITIAL);
        assert!(plane.store.sessions().unwrap().is_empty());
        plane
            .store
            .claim_operation(
                "create-crash-recovery",
                "team.create",
                &request,
                "crashed-team-create-owner",
                0,
            )
            .unwrap();
        drop(plane);
        let plane = open_fixture_plane(settings, &runtime);

        let recovered = plane.reconcile().unwrap();
        assert_eq!(recovered["complete"], true);
        assert_eq!(recovered["instance_reconciliation"][0]["replaced"], 1);
        assert_eq!(recovered["instance_reconciliation"][0]["launched"], 1);
        assert_eq!(runtime.launch_count(), 1);
        let (_, recovered_state, _) = plane.store.load().unwrap();
        let recovered_ref = recovered_state.actor(&actor_id).unwrap().actor_ref();
        assert_eq!(recovered_ref.actor_epoch.get(), 2);
        assert_ne!(recovered_ref, source_ref);
        assert_eq!(recovered_state.team(&team_id).unwrap().actors.len(), 1);
        let sessions = plane.store.sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].actor_id, actor_id.as_str());
        assert_eq!(sessions[0].status, "idle");

        let retry = plane.team_create(&request).unwrap();
        assert_eq!(retry["instance_reconciliation"]["replaced"], 0);
        assert_eq!(retry["instance_reconciliation"]["launched"], 0);
        assert_eq!(retry["reused"], true);
        assert_eq!(runtime.launch_count(), 1);

        let cached = plane.team_create(&request).unwrap();
        assert_eq!(cached, retry);
        assert_eq!(runtime.launch_count(), 1);
        assert_eq!(plane.store.sessions().unwrap().len(), 1);
        let repeated = plane.reconcile().unwrap();
        assert_eq!(repeated["complete"], true);
        assert_eq!(repeated["instance_reconciliation"][0]["launched"], 0);
        assert_eq!(repeated["instance_reconciliation"][0]["replaced"], 0);
        assert_eq!(runtime.launch_count(), 1);
    }

    #[test]
    fn declared_base_sha_validation_distinguishes_format_object_and_commit() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let worktree = temporary.path().join("team-worktree");
        init_test_repository(&root, &worktree);
        let commit = super::git_sha_for(&test_git(), &root).unwrap();
        assert_eq!(
            super::validate_declared_base_sha(&test_git(), &root, &commit.as_str()[..7])
                .unwrap_err()
                .code,
            "base_sha_abbreviated"
        );
        assert_eq!(
            super::validate_declared_base_sha(&test_git(), &root, &"f".repeat(40))
                .unwrap_err()
                .code,
            "base_sha_unknown"
        );
        let tree = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["rev-parse", "HEAD^{tree}"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        assert_eq!(
            super::validate_declared_base_sha(&test_git(), &root, tree.trim())
                .unwrap_err()
                .code,
            "base_sha_not_commit"
        );
        assert_eq!(
            super::validate_declared_base_sha(&test_git(), &root, commit.as_str()).unwrap(),
            commit
        );
    }

    #[test]
    fn declared_base_validation_uses_the_injected_git_executable() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let worktree = temporary.path().join("team-worktree");
        init_test_repository(&root, &worktree);
        let commit = super::git_sha_for(&test_git(), &root).unwrap();
        let (git, marker) = pinned_git_fixture(temporary.path());

        assert_eq!(
            super::validate_declared_base_sha(&git, &root, commit.as_str()).unwrap(),
            commit
        );
        assert!(fs::read_to_string(marker).unwrap().contains("cat-file -t"));
    }

    #[test]
    fn control_git_command_pins_the_program_and_neutralizes_repository_environment() {
        let mut command = Command::new("/controller/pinned/git");
        command.arg("-C").arg("/workspace");
        for key in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
        ] {
            command.env(key, "/hostile/override");
        }

        super::neutralize_control_git_environment(&mut command);

        assert_eq!(command.get_program(), "/controller/pinned/git");
        assert_eq!(command.get_args().collect::<Vec<_>>(), ["-C", "/workspace"]);
        let environment = command
            .get_envs()
            .map(|(key, value)| (key.to_owned(), value.map(ToOwned::to_owned)))
            .collect::<BTreeMap<_, _>>();
        for key in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
            "GIT_CONFIG_SYSTEM",
        ] {
            assert!(!environment.contains_key(std::ffi::OsStr::new(key)));
        }
        assert_eq!(
            environment[std::ffi::OsStr::new("GIT_CONFIG_GLOBAL")].as_deref(),
            Some(std::ffi::OsStr::new("/dev/null"))
        );
        assert_eq!(
            environment[std::ffi::OsStr::new("GIT_CONFIG_NOSYSTEM")].as_deref(),
            Some(std::ffi::OsStr::new("1"))
        );
        assert_eq!(
            environment[std::ffi::OsStr::new("GIT_TERMINAL_PROMPT")].as_deref(),
            Some(std::ffi::OsStr::new("0"))
        );
        assert_eq!(
            environment[std::ffi::OsStr::new("GIT_OPTIONAL_LOCKS")].as_deref(),
            Some(std::ffi::OsStr::new("0"))
        );
        assert_eq!(
            environment[std::ffi::OsStr::new("LC_ALL")].as_deref(),
            Some(std::ffi::OsStr::new("C"))
        );
        assert_eq!(environment.len(), 5);
    }

    #[test]
    fn completion_rejects_a_candidate_that_does_not_descend_from_declared_base() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let worktree = temporary.path().join("team-worktree");
        init_test_repository(&root, &worktree);
        let base = super::git_sha_for(&test_git(), &root).unwrap();
        run_git(&root, &["checkout", "--orphan", "unrelated"]);
        run_git(&root, &["rm", "-rf", "."]);
        fs::write(root.join("UNRELATED.md"), "unrelated\n").unwrap();
        run_git(&root, &["add", "UNRELATED.md"]);
        run_git(&root, &["commit", "-q", "-m", "unrelated"]);
        let candidate = super::git_sha_for(&test_git(), &root).unwrap();
        let (git, marker) = pinned_git_fixture(temporary.path());
        let error = super::verify_candidate_head(&git, &root, &base, &candidate).unwrap_err();
        assert_eq!(error.code, "candidate_base_mismatch");
        let invocations = fs::read_to_string(marker).unwrap();
        assert!(invocations.contains("cat-file -e"));
        assert!(invocations.contains("rev-parse HEAD^{commit}"));
        assert!(invocations.contains("merge-base --is-ancestor"));
    }

    #[test]
    fn request_create_uses_declared_base_without_worktree_lookup_and_reports_source() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-declared-base"));
        let settings = profiled_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-declared-base");
        create_profiled_test_team(&plane, &team_root, "create-declared-base");
        let base = super::git_sha_for(&test_git(), &root).unwrap();
        let created = plane
            .request_create(&json!({
                "team": "team-workers",
                "title": "declared base",
                "base_sha": base,
                "operation_id": "declared-base-request",
            }))
            .unwrap();
        assert_eq!(
            created["request"]["specification"]["base_source"],
            "declared"
        );
        assert_eq!(
            created["request"]["specification"]["base_sha"],
            base.as_str()
        );
        let status = plane.status().unwrap();
        assert_eq!(status["request_bases"][0]["base_source"], "declared");
        let derived = plane
            .request_create(&json!({
                "team": "team-workers",
                "title": "derived base",
                "operation_id": "derived-base-request",
            }))
            .unwrap();
        assert_eq!(
            derived["request"]["specification"]["base_source"],
            "derived"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn explicit_request_reports_show_live_base_staleness_without_touching_hot_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        let git = test_git();
        init_test_repository(&root, &team_root);
        run_git(&root, &["branch", "-m", "integration/custom"]);
        let base = super::git_sha_for(&git, &root).unwrap();

        fs::write(root.join("shared.rs"), "integration\n").unwrap();
        run_git(&root, &["add", "shared.rs"]);
        run_git_with_date(
            &root,
            &["commit", "-q", "-m", "integration shared"],
            "1700000100 +0000",
        );
        fs::write(root.join("touched-then-reverted.rs"), "temporary\n").unwrap();
        run_git(&root, &["add", "touched-then-reverted.rs"]);
        run_git_with_date(
            &root,
            &["commit", "-q", "-m", "touch temporary"],
            "1700000200 +0000",
        );
        fs::remove_file(root.join("touched-then-reverted.rs")).unwrap();
        run_git(&root, &["add", "touched-then-reverted.rs"]);
        run_git_with_date(
            &root,
            &["commit", "-q", "-m", "revert temporary"],
            "1700000300 +0000",
        );
        let target = super::git_sha_for(&git, &root).unwrap();

        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-base-staleness"));
        let settings = profiled_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let mut plane = open_fixture_plane(settings, &runtime);
        let primary = activate_test_primary(&plane, "primary-base-staleness");
        plane.set_test_authenticated_actor(primary);
        create_profiled_test_team(&plane, &team_root, "create-base-staleness-team");
        let team_id = TeamId::new("team-workers").unwrap();
        crate::base_staleness::reset_git_comparison_count();
        let created = plane
            .request_create(&json!({
                "team": team_id,
                "title": "base staleness",
                "base_sha": base,
                "operation_id": "create-base-staleness-request",
            }))
            .unwrap();
        assert_eq!(crate::base_staleness::git_comparison_count(), 0);
        let request_id = RequestId::new(
            created["request"]["request_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap();

        crate::base_staleness::reset_git_comparison_count();
        plane.store.load().unwrap();
        plane
            .store
            .mutate("test.base_staleness_noop", &json!({}), 1, |_| Ok(()))
            .unwrap();
        assert_eq!(crate::base_staleness::git_comparison_count(), 0);

        let listed_without_candidate = plane.request_list(&json!({})).unwrap();
        assert_eq!(
            listed_without_candidate["integration_target"]["head_sha"],
            target.as_str()
        );
        assert_eq!(
            listed_without_candidate["requests"][0]["base_staleness"]["commits_behind"],
            3
        );
        assert_eq!(
            listed_without_candidate["requests"][0]["base_staleness"]["overlap"]["state"],
            "candidate_not_available"
        );
        let list_comparisons = crate::base_staleness::git_comparison_count();
        assert!(list_comparisons > 0);

        let shown_without_candidate = plane.request_show(&json!({ "id": request_id })).unwrap();
        assert_eq!(
            shown_without_candidate["integration_target"]["branch"],
            "integration/custom"
        );
        assert_eq!(
            shown_without_candidate["integration_target"]["source"],
            "workspace_primary_branch"
        );
        assert_eq!(
            shown_without_candidate["integration_target"]["head_sha"],
            target.as_str()
        );
        assert_eq!(
            shown_without_candidate["request"]["base_staleness"]["state"],
            "behind"
        );
        assert_eq!(
            shown_without_candidate["request"]["base_staleness"]["commits_behind"],
            3
        );
        assert_eq!(
            shown_without_candidate["request"]["base_staleness"]["behind_since_ms"],
            1_700_000_100_000_u64
        );
        assert_eq!(
            shown_without_candidate["request"]["base_staleness"]["behind_for_ms"],
            shown_without_candidate["integration_target"]["observed_at_ms"]
                .as_u64()
                .unwrap()
                - 1_700_000_100_000_u64
        );
        assert_eq!(
            shown_without_candidate["request"]["base_staleness"]["overlap"]["state"],
            "candidate_not_available"
        );
        assert!(
            shown_without_candidate["request"]["base_staleness"]["overlap"]
                .get("touches_same_files")
                .is_none()
        );
        let show_comparisons = crate::base_staleness::git_comparison_count();
        assert!(show_comparisons > list_comparisons);
        let status_without_candidate = plane.status().unwrap();
        assert_eq!(
            status_without_candidate["request_bases"][0]["staleness"]["overlap"]["state"],
            "candidate_not_available"
        );
        let status_comparisons = crate::base_staleness::git_comparison_count();
        assert!(status_comparisons > show_comparisons);
        eprintln!(
            "base-staleness comparison counts: create=0 load_mutate=0 list={list_comparisons} show_cumulative={show_comparisons} status_cumulative={status_comparisons}"
        );

        fs::write(team_root.join("shared.rs"), "candidate\n").unwrap();
        fs::write(team_root.join("touched-then-reverted.rs"), "candidate\n").unwrap();
        run_git(
            &team_root,
            &["add", "shared.rs", "touched-then-reverted.rs"],
        );
        run_git_with_date(
            &team_root,
            &["commit", "-q", "-m", "candidate"],
            "1700000400 +0000",
        );
        submit_test_candidate(
            &plane,
            &request_id,
            super::git_sha_for(&git, &team_root).unwrap(),
            "base-staleness",
        );

        let shown = plane.request_show(&json!({ "id": request_id })).unwrap();
        let overlap = &shown["request"]["base_staleness"]["overlap"];
        assert_eq!(overlap["state"], "comparable");
        assert_eq!(overlap["touches_same_files"], true);
        assert_eq!(overlap["shared_path_count"], 2);
        assert_eq!(
            overlap["shared_paths"],
            json!(["shared.rs", "touched-then-reverted.rs"])
        );
        let status = plane.status().unwrap();
        assert_eq!(status["integration_target"]["head_sha"], target.as_str());
        assert_eq!(status["request_bases"][0]["staleness"]["commits_behind"], 3);
        assert_eq!(status["request_bases"][0]["staleness"]["overlap"], *overlap);
        assert_eq!(super::git_sha_for(&git, &root).unwrap(), target);
        assert_eq!(shown["request"]["specification"]["base_sha"], base.as_str());

        let incorporated_created = plane
            .request_create(&json!({
                "team": team_id,
                "title": "candidate incorporates integration",
                "base_sha": base,
                "operation_id": "create-incorporated-target-request",
            }))
            .unwrap();
        let incorporated_request_id = RequestId::new(
            incorporated_created["request"]["request_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap();
        run_git(&team_root, &["reset", "--hard", base.as_str()]);
        fs::write(team_root.join("candidate-only.rs"), "candidate only\n").unwrap();
        run_git(&team_root, &["add", "candidate-only.rs"]);
        run_git_with_date(
            &team_root,
            &["commit", "-q", "-m", "candidate-only work"],
            "1700000500 +0000",
        );
        run_git_with_date(
            &team_root,
            &[
                "merge",
                "--no-ff",
                "--no-edit",
                "-m",
                "merge integration target",
                target.as_str(),
            ],
            "1700000600 +0000",
        );
        submit_test_candidate(
            &plane,
            &incorporated_request_id,
            super::git_sha_for(&git, &team_root).unwrap(),
            "incorporated-target",
        );
        let incorporated = plane
            .request_show(&json!({ "id": incorporated_request_id }))
            .unwrap();
        assert_eq!(
            incorporated["request"]["base_staleness"]["overlap"]["state"],
            "comparable"
        );
        assert_eq!(
            incorporated["request"]["base_staleness"]["overlap"]["touches_same_files"],
            false
        );
        assert_eq!(
            incorporated["request"]["base_staleness"]["overlap"]["shared_paths"],
            json!([])
        );

        run_git(
            &root,
            &["branch", "configured/older-integration", base.as_str()],
        );
        plane.settings.integration_branch = Some("configured/older-integration".to_owned());
        let configured = plane.request_show(&json!({ "id": request_id })).unwrap();
        assert_eq!(configured["integration_target"]["source"], "configured");
        assert_eq!(configured["integration_target"]["head_sha"], base.as_str());
        assert_eq!(configured["request"]["base_staleness"]["state"], "current");

        let ahead_created = plane
            .request_create(&json!({
                "team": team_id,
                "title": "base ahead of comparison target",
                "base_sha": target,
                "operation_id": "create-base-ahead-request",
            }))
            .unwrap();
        let ahead_request_id = ahead_created["request"]["request_id"].as_str().unwrap();
        let ahead = plane
            .request_show(&json!({ "id": ahead_request_id }))
            .unwrap();
        assert_eq!(ahead["request"]["base_staleness"]["state"], "base_ahead");
        assert!(ahead["request"]["base_staleness"]["commits_behind"].is_null());

        run_git(&root, &["checkout", "--orphan", "divergent-local"]);
        run_git(&root, &["rm", "-rf", "."]);
        fs::write(root.join("divergent.txt"), "divergent\n").unwrap();
        run_git(&root, &["add", "divergent.txt"]);
        run_git_with_date(
            &root,
            &["commit", "-q", "-m", "divergent integration"],
            "1700000700 +0000",
        );
        plane.settings.integration_branch = Some("divergent-local".to_owned());
        let diverged = plane.request_show(&json!({ "id": request_id })).unwrap();
        assert_eq!(diverged["request"]["base_staleness"]["state"], "diverged");
        assert!(diverged["request"]["base_staleness"]["commits_behind"].is_null());

        plane.settings.integration_branch = Some("missing/local-branch".to_owned());
        let missing = plane.request_show(&json!({ "id": request_id })).unwrap();
        assert_eq!(missing["integration_target"]["state"], "unavailable");
        assert_eq!(
            missing["integration_target"]["reason"],
            "integration_branch_unresolved"
        );
        assert_eq!(missing["request"]["base_staleness"]["state"], "unavailable");

        plane.settings.integration_branch = None;
        run_git(&root, &["checkout", "--detach", "-q"]);
        let detached = plane.request_show(&json!({ "id": request_id })).unwrap();
        assert_eq!(detached["integration_target"]["state"], "not_configured");
        assert_eq!(
            detached["integration_target"]["reason"],
            "primary_worktree_has_no_attached_branch"
        );
        assert_eq!(
            detached["request"]["base_staleness"]["state"],
            "unavailable"
        );
        let detached_status = plane.status().unwrap();
        assert_eq!(
            detached_status["integration_target"]["state"],
            "not_configured"
        );
        assert_eq!(
            detached_status["request_bases"][0]["staleness"]["state"],
            "unavailable"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn request_create_commit_crash_preserves_assignment_on_retry() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-request-crash"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            2,
            "least_wip",
        );
        let plane = open_fixture_plane(settings.clone(), &runtime);
        activate_test_primary(&plane, "primary-request-crash");
        create_profiled_test_team(&plane, &team_root, "create-request-crash");
        assert_eq!(runtime.launch_count(), 2);
        let operation_id = "request-crash-recovery";
        let request = json!({
            "team": "team-workers",
            "title": "preserve the durable assignment",
            "body": "retry notification without selecting another actor",
            "operation_id": operation_id,
        });

        plane.arm_test_crash("request_create_commit");
        let error = plane.request_create(&request).unwrap_err();
        assert_eq!(error.code, "simulated_request_create_crash");
        let request_id = RequestId::new(super::stable_id("request", operation_id)).unwrap();
        let (_, crashed, _) = plane.store.load().unwrap();
        let original_assignment = crashed
            .request(&request_id)
            .unwrap()
            .assignment
            .as_ref()
            .unwrap()
            .actor
            .clone();
        assert_eq!(original_assignment.actor_id.as_str(), "impl-workers-1");
        assert_eq!(crashed.snapshot().requests.len(), 1);
        assert_eq!(crashed.snapshot().deliveries.len(), 1);
        assert_eq!(
            crashed.snapshot().deliveries[0].envelope.target,
            MessageTarget::Actor(original_assignment.actor_id.clone())
        );
        assert_eq!(
            plane
                .select_request_actor(
                    &crashed,
                    crashed.team(&TeamId::new("team-workers").unwrap()).unwrap(),
                )
                .unwrap()
                .actor_id
                .as_str(),
            "impl-workers-2"
        );
        let mut changed_request = request.clone();
        changed_request["body"] = json!("changed input after the durable commit");
        let conflict = plane.request_create(&changed_request).unwrap_err();
        assert_eq!(conflict.code, "operation_id_conflict");
        let (_, after_conflict, _) = plane.store.load().unwrap();
        assert_eq!(after_conflict.snapshot().requests.len(), 1);
        assert_eq!(after_conflict.snapshot().deliveries.len(), 1);
        plane
            .store
            .claim_operation(
                operation_id,
                "request.create",
                &request,
                "crashed-request-create-owner",
                0,
            )
            .unwrap();
        drop(plane);
        let plane = open_fixture_plane(settings, &runtime);

        let reconciled = plane.reconcile().unwrap();
        assert_eq!(reconciled["complete"], true);
        assert_eq!(runtime.launch_count(), 2);
        let retry = plane.request_create(&request).unwrap();
        assert_eq!(retry["outcome"], "duplicate");
        assert_eq!(
            retry["request"]["assignment"]["actor"],
            serde_json::to_value(&original_assignment).unwrap()
        );
        let cached = plane.request_create(&request).unwrap();
        assert_eq!(cached, retry);
        let (_, recovered, _) = plane.store.load().unwrap();
        assert_eq!(recovered.snapshot().requests.len(), 1);
        assert_eq!(recovered.snapshot().deliveries.len(), 1);
        assert_eq!(
            recovered.snapshot().deliveries[0].envelope.target,
            MessageTarget::Actor(ActorId::new("impl-workers-1").unwrap())
        );
        assert_eq!(
            recovered
                .request(&request_id)
                .unwrap()
                .assignment
                .as_ref()
                .unwrap()
                .actor,
            original_assignment
        );
        assert_eq!(runtime.launch_count(), 2);
    }

    #[test]
    fn reconcile_registration_commit_crash_recovers_without_orphan_session() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-registration-crash",
        ));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings.clone(), &runtime);
        activate_test_primary(&plane, "primary-registration-crash");
        let team_id = TeamId::new("team-workers").unwrap();
        let actor_id = ActorId::new("impl-workers-1").unwrap();
        let team_profile = plane.selected_team_profile().unwrap().snapshot().unwrap();
        plane
            .store
            .mutate("test.registration_crash_team", &json!({}), 1, |state| {
                state
                    .create_team_with_profile(team_id.clone(), team_profile.clone())
                    .map_err(super::ControlError::core)
            })
            .unwrap();

        plane.arm_test_crash("reconcile_registration_commit");
        let crashed = plane.reconcile().unwrap();
        assert_eq!(crashed["complete"], false);
        assert_eq!(runtime.launch_count(), 0);
        assert_eq!(crashed["instance_reconciliation"][0]["complete"], false);
        assert_eq!(
            crashed["instance_reconciliation"][0]["failures"][0]["phase"],
            "missing_launch"
        );
        assert!(
            crashed["instance_reconciliation"][0]["failures"][0]["error"]
                .as_str()
                .unwrap()
                .contains("debug-only failure after the desired actor registration commit")
        );
        let (_, registered, _) = plane.store.load().unwrap();
        let source_ref = registered.actor(&actor_id).unwrap().actor_ref();
        assert_eq!(source_ref.actor_epoch, ActorEpoch::INITIAL);
        assert_eq!(
            registered.team(&team_id).unwrap().actors.as_slice(),
            std::slice::from_ref(&actor_id)
        );
        assert!(plane.store.sessions().unwrap().is_empty());
        let working_directory = plane.ensure_team_directory(&team_id, None).unwrap();
        let operation_id = super::reconciliation_launch_operation_id(
            &team_id,
            TeamEpoch::INITIAL,
            &actor_id,
            ActorEpoch::INITIAL,
        );
        let operation_request = json!({
            "team_id": team_id,
            "actor_id": actor_id,
            "working_directory": working_directory,
            "actor_profile": plane.selected_team_actor_profile().unwrap().name,
        });
        plane
            .store
            .claim_operation(
                &operation_id,
                "actor.reconcile_launch",
                &operation_request,
                "crashed-reconcile-launch-owner",
                0,
            )
            .unwrap();
        drop(plane);
        let plane = open_fixture_plane(settings, &runtime);

        let recovered = plane.reconcile().unwrap();
        assert_eq!(recovered["complete"], true);
        assert_eq!(recovered["instance_reconciliation"][0]["replaced"], 1);
        assert_eq!(recovered["instance_reconciliation"][0]["launched"], 1);
        assert_eq!(runtime.launch_count(), 1);
        let (_, recovered_state, _) = plane.store.load().unwrap();
        let recovered_ref = recovered_state.actor(&actor_id).unwrap().actor_ref();
        assert_eq!(recovered_ref.actor_epoch.get(), 2);
        assert_ne!(recovered_ref, source_ref);
        assert_eq!(recovered_state.team(&team_id).unwrap().actors.len(), 1);
        let sessions = plane.store.sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].actor_id, actor_id.as_str());
        assert_eq!(sessions[0].status, "idle");

        let repeated = plane.reconcile().unwrap();
        assert_eq!(repeated["complete"], true);
        assert_eq!(repeated["instance_reconciliation"][0]["launched"], 0);
        assert_eq!(repeated["instance_reconciliation"][0]["replaced"], 0);
        assert_eq!(runtime.launch_count(), 1);
        assert_eq!(plane.store.sessions().unwrap().len(), 1);
    }

    #[test]
    fn status_and_events_share_redacted_runtime_policy_context() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-observability"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "least_wip",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-observability");
        create_profiled_test_team(&plane, &team_root, "create-observability");

        let status = plane.status().unwrap();
        let events = plane.events(&json!({})).unwrap();
        let doctor = plane.doctor().unwrap();
        assert_eq!(status["observability"], events["observability"]);
        let observability = &status["observability"];
        assert_eq!(observability["selected_runtime_id"], runtime.id().as_str());
        assert_eq!(observability["configured_session_backend"], "fake");
        assert_eq!(
            observability["durable_session_owners"],
            json!([{
                "actor_id": "impl-workers-1",
                "team_id": "team-workers",
                "backend": "fake",
                "runtime_id": runtime.id().as_str(),
                "status": "idle",
            }])
        );
        assert_eq!(
            observability["caller_identity"]["identity_backend"],
            doctor["caller_identity"]["identity_backend"]
        );
        assert_eq!(
            observability["caller_identity"]["ready"],
            doctor["caller_identity"]["ready"]
        );
        assert_eq!(
            observability["profile_capabilities"]["selected_primary"]["capabilities"],
            json!(["human_facing_primary"])
        );
        assert_eq!(
            observability["profile_capabilities"]["selected_default_team"]["capabilities"],
            json!(["implementation_execution"])
        );
        assert_eq!(
            observability["profile_capabilities"]["all"]["implementation"]["runtime_id"],
            runtime.id().as_str()
        );
        assert_eq!(
            observability["assignment_policies"]["selected_default"],
            "least_wip"
        );
        assert_eq!(
            observability["assignment_policies"]["effective_by_team"][0],
            json!({
                "team_id": "team-workers",
                "assignment_policy": "least_wip",
            })
        );
        assert!(observability["caller_identity"].get("actor").is_none());
        assert!(observability["caller_identity"].get("binding").is_none());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn events_merge_archived_and_hot_request_outcomes_with_a_bounded_limit() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let seed = temporary.path().join("seed-worktree");
        init_test_repository(&root, &seed);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-archived-request-outcomes",
        ));
        let plane = open_fixture_plane(
            legacy_settings(root, temporary.path().join("state"), runtime.id().as_str()),
            &runtime,
        );
        let primary = activate_test_primary(&plane, "primary-request-outcomes");
        let team_id = TeamId::new("team-request-outcomes").unwrap();
        let (_, (team_epoch, implementation)) = plane
            .store
            .mutate("test.request_outcomes.setup", &json!({}), 2, |state| {
                let team_epoch = state
                    .create_team(team_id.clone())
                    .map_err(super::ControlError::core)?;
                let implementation = state
                    .register_implementation(
                        &team_id,
                        ActorId::new("implementation-request-outcomes").unwrap(),
                    )
                    .map_err(super::ControlError::core)?;
                Ok((team_epoch, implementation))
            })
            .unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let workspace_id = supervisor.workspace_id().clone();
        let policy_revision = supervisor.policy_revision();
        let primary_epoch = supervisor.primary_epoch();

        let archived_request_id = RequestId::new("request-outcome-archived").unwrap();
        let archived_run_id = RunId::new("run-outcome-archived").unwrap();
        let archived_request_message_id =
            MessageId::new("message-outcome-archived-request").unwrap();
        let archived_request = Envelope {
            protocol_version: PROTOCOL_VERSION,
            message_id: archived_request_message_id.clone(),
            workspace_id: workspace_id.clone(),
            sender: primary.clone(),
            target: MessageTarget::Actor(implementation.actor_id.clone()),
            team_id: Some(team_id.clone()),
            run_id: Some(archived_run_id.clone()),
            request_id: Some(archived_request_id.clone()),
            policy_revision,
            primary_epoch,
            team_epoch: Some(team_epoch),
            assignment_epoch: None,
            sent_at: TimestampMillis(10),
            message: Message::ImplementationRequest(ImplementationRequest {
                title: "Archived lifecycle outcome".to_owned(),
                instructions: "Retire this request after cancellation.".to_owned(),
                base_sha: GitSha::new("0".repeat(40)).unwrap(),
                base_source: agsv_protocol::RequestBaseSource::Derived,
                acceptance_criteria: vec!["the outcome remains observable".to_owned()],
                evidence_requirements: Vec::new(),
            }),
        };
        plane
            .store
            .mutate("test.request_outcomes.created", &json!({}), 3, |state| {
                state
                    .apply(archived_request.clone())
                    .map(|_| ())
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        plane
            .store
            .mutate("test.request_outcomes.ack", &json!({}), 4, |state| {
                state
                    .acknowledge(Acknowledgement {
                        workspace_id: workspace_id.clone(),
                        message_id: archived_request_message_id.clone(),
                        actor: implementation.clone(),
                        acknowledged_at: TimestampMillis(11),
                    })
                    .map(|_| ())
                    .map_err(super::ControlError::core)
            })
            .unwrap();

        let cancellation_message_id = MessageId::new("message-outcome-cancelled").unwrap();
        let cancellation = Envelope {
            protocol_version: PROTOCOL_VERSION,
            message_id: cancellation_message_id.clone(),
            workspace_id: workspace_id.clone(),
            sender: primary.clone(),
            target: MessageTarget::Actor(implementation.actor_id.clone()),
            team_id: Some(team_id.clone()),
            run_id: Some(archived_run_id),
            request_id: Some(archived_request_id.clone()),
            policy_revision,
            primary_epoch,
            team_epoch: Some(team_epoch),
            assignment_epoch: None,
            sent_at: TimestampMillis(12),
            message: Message::Cancellation(Cancellation {
                reason: "outcome fixture complete".to_owned(),
            }),
        };
        plane
            .store
            .mutate("test.request_outcomes.cancelled", &json!({}), 5, |state| {
                state
                    .apply(cancellation.clone())
                    .map(|_| ())
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        plane
            .store
            .mutate("test.request_outcomes.cancel_ack", &json!({}), 6, |state| {
                state
                    .acknowledge(Acknowledgement {
                        workspace_id: workspace_id.clone(),
                        message_id: cancellation_message_id.clone(),
                        actor: implementation.clone(),
                        acknowledged_at: TimestampMillis(13),
                    })
                    .map(|_| ())
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        let (_, compacted, _) = plane.store.load().unwrap();
        assert!(compacted.request(&archived_request_id).is_none());
        assert!(
            plane
                .store
                .archived_request(&archived_request_id)
                .unwrap()
                .is_some()
        );

        let hot_request_id = RequestId::new("request-outcome-hot").unwrap();
        let hot_request = Envelope {
            protocol_version: PROTOCOL_VERSION,
            message_id: MessageId::new("message-outcome-hot-request").unwrap(),
            workspace_id,
            sender: primary,
            target: MessageTarget::Actor(implementation.actor_id),
            team_id: Some(team_id),
            run_id: Some(RunId::new("run-outcome-hot").unwrap()),
            request_id: Some(hot_request_id.clone()),
            policy_revision,
            primary_epoch,
            team_epoch: Some(team_epoch),
            assignment_epoch: None,
            sent_at: TimestampMillis(14),
            message: Message::ImplementationRequest(ImplementationRequest {
                title: "Hot lifecycle outcome".to_owned(),
                instructions: "Keep this request active.".to_owned(),
                base_sha: GitSha::new("0".repeat(40)).unwrap(),
                base_source: agsv_protocol::RequestBaseSource::Derived,
                acceptance_criteria: vec!["remain in the hot snapshot".to_owned()],
                evidence_requirements: Vec::new(),
            }),
        };
        plane
            .store
            .mutate("test.request_outcomes.hot", &json!({}), 7, |state| {
                state
                    .apply(hot_request.clone())
                    .map(|_| ())
                    .map_err(super::ControlError::core)
            })
            .unwrap();

        let events = plane.events(&json!({ "limit": 2 })).unwrap();
        let outcomes = events["request_outcomes"].as_array().unwrap();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0]["request_id"], archived_request_id.as_str());
        assert_eq!(outcomes[0]["status"], "cancelled");
        assert_eq!(outcomes[0]["rejection_count"], 0);
        assert_eq!(outcomes[0]["fix_cycle_depth"], 0);
        assert_eq!(outcomes[0]["candidate_history"], json!([]));
        assert_eq!(outcomes[1]["request_id"], hot_request_id.as_str());

        let hot_only = plane.events(&json!({ "limit": 1 })).unwrap();
        assert_eq!(hot_only["request_outcomes"].as_array().unwrap().len(), 1);
        assert_eq!(
            hot_only["request_outcomes"][0]["request_id"],
            hot_request_id.as_str()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn engine_acceptance_matrix_covers_profiles_runtimes_backends_policies_and_recovery() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let implementation_root = temporary.path().join("implementation-worktree");
        let research_root = temporary.path().join("research-worktree");
        init_test_repository(&root, &implementation_root);
        run_git(
            &root,
            &[
                "worktree",
                "add",
                "--detach",
                research_root.to_str().unwrap(),
                "HEAD",
            ],
        );
        let implementation_root = fs::canonicalize(implementation_root).unwrap();
        let research_root = fs::canonicalize(research_root).unwrap();
        let runtime_a = Arc::new(FixtureRuntime::with_id("fixture-runtime-matrix-a"));
        let runtime_b = Arc::new(FixtureRuntime::with_id("fixture-runtime-matrix-b"));
        let mut registry = RuntimeRegistry::new();
        registry.register(runtime_a.clone()).unwrap();
        registry.register(runtime_b.clone()).unwrap();

        let mut settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime_a.id().as_str(),
            2,
            "least_wip",
        );
        let mut research_profile = settings.agent_profiles[LEGACY_IMPLEMENTATION_PROFILE].clone();
        research_profile.name = "researcher".to_owned();
        research_profile.role = "research".to_owned();
        research_profile.capabilities.insert("research".to_owned());
        let ActorLaunchSettings::Runtime { runtime, .. } = &mut research_profile.launch else {
            panic!("implementation fixture profile must be launchable");
        };
        *runtime = runtime_b.id().to_string();
        research_profile.role_file = PathBuf::from("roles/researcher.md");
        research_profile.role_instructions = "research role".to_owned();
        settings
            .agent_profiles
            .insert(research_profile.name.clone(), research_profile.clone());
        let research_team_profile = TeamProfileSettings {
            name: "research".to_owned(),
            actor_profile: research_profile.name.clone(),
            desired_instances: 1,
            assignment_policy: "first_healthy".to_owned(),
        };
        settings.team_profiles.insert(
            research_team_profile.name.clone(),
            research_team_profile.clone(),
        );

        let implementation_profile = settings.agent_profiles[LEGACY_IMPLEMENTATION_PROFILE].clone();
        let implementation_team_profile =
            settings.team_profiles[LEGACY_IMPLEMENTATION_PROFILE].clone();
        let mut plane = ControlPlane::open_with_runtime_registry(settings, &registry).unwrap();
        plane.sessions = SessionDriver::checkpoint_recovery_test_driver();
        activate_test_primary(&plane, "primary-matrix");
        let implementation_team = TeamId::new("team-matrix").unwrap();
        let research_team = TeamId::new("team-research").unwrap();
        let first_id = ActorId::new("impl-matrix-1").unwrap();
        let second_id = ActorId::new("impl-matrix-2").unwrap();
        let researcher_id = ActorId::new("research-matrix-1").unwrap();
        let implementation_role = implementation_profile.actor_role().unwrap();
        let implementation_snapshot = implementation_profile.snapshot().unwrap();
        let research_role = research_profile.actor_role().unwrap();
        let research_snapshot = research_profile.snapshot().unwrap();
        let implementation_team_snapshot = implementation_team_profile.snapshot().unwrap();
        let research_team_snapshot = research_team_profile.snapshot().unwrap();
        let (_, (first_ref, second_ref, researcher_ref)) = plane
            .store
            .mutate("test.acceptance_matrix", &json!({}), 1, |state| {
                state
                    .create_team_with_profile(
                        implementation_team.clone(),
                        implementation_team_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)?;
                let first = state
                    .register_implementation_with_profile(
                        &implementation_team,
                        first_id.clone(),
                        implementation_role.clone(),
                        implementation_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)?;
                let second = state
                    .register_implementation_with_profile(
                        &implementation_team,
                        second_id.clone(),
                        implementation_role.clone(),
                        implementation_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)?;
                state
                    .create_team_with_profile(research_team.clone(), research_team_snapshot.clone())
                    .map_err(super::ControlError::core)?;
                let researcher = state
                    .register_implementation_with_profile(
                        &research_team,
                        researcher_id.clone(),
                        research_role.clone(),
                        research_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)?;
                Ok((first, second, researcher))
            })
            .unwrap();
        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: first_id.to_string(),
                team_id: Some(implementation_team.to_string()),
                working_directory: implementation_root.clone(),
                backend: "fake".to_owned(),
                runtime: Some(runtime_a.id().to_string()),
                external_id: Some("fake-matrix-first".to_owned()),
                resume_token: Some("fake-matrix-first".to_owned()),
                status: "idle".to_owned(),
                launch_key: "matrix-first-live".to_owned(),
                updated_at_ms: 2,
                row_revision: 0,
            })
            .unwrap();
        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: second_id.to_string(),
                team_id: Some(implementation_team.to_string()),
                working_directory: implementation_root.clone(),
                backend: LAYOUT_FAILURE_BACKEND_ID.to_owned(),
                runtime: Some(runtime_a.id().to_string()),
                external_id: None,
                resume_token: Some("matrix-second-checkpoint".to_owned()),
                status: "launch_failed".to_owned(),
                launch_key: "matrix-second-recovery".to_owned(),
                updated_at_ms: 3,
                row_revision: 0,
            })
            .unwrap();
        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: researcher_id.to_string(),
                team_id: Some(research_team.to_string()),
                working_directory: research_root,
                backend: "fake".to_owned(),
                runtime: Some(runtime_b.id().to_string()),
                external_id: None,
                resume_token: Some("matrix-research-checkpoint".to_owned()),
                status: "launch_failed".to_owned(),
                launch_key: "matrix-research-recovery".to_owned(),
                updated_at_ms: 4,
                row_revision: 0,
            })
            .unwrap();

        let reconciled = plane.reconcile().unwrap();
        assert_eq!(reconciled["complete"], true);
        assert_eq!(reconciled["sessions_checked"], 3);
        assert_eq!(runtime_a.launch_count(), 1);
        assert_eq!(runtime_b.launch_count(), 1);
        let implementation_result = reconciled["instance_reconciliation"]
            .as_array()
            .unwrap()
            .iter()
            .find(|result| result["team_id"] == implementation_team.as_str())
            .unwrap();
        assert_eq!(implementation_result["desired_instances"], 2);
        assert_eq!(
            implementation_result["effective_assignment_policy"],
            "least_wip"
        );
        assert_eq!(implementation_result["complete"], true);
        let research_result = reconciled["instance_reconciliation"]
            .as_array()
            .unwrap()
            .iter()
            .find(|result| result["team_id"] == research_team.as_str())
            .unwrap();
        assert_eq!(
            research_result["effective_assignment_policy"],
            "first_healthy"
        );
        assert_eq!(research_result["complete"], true);
        let (_, supervisor, _) = plane.store.load().unwrap();
        assert_eq!(
            supervisor.actor(&researcher_id).unwrap().role.as_str(),
            "research"
        );
        assert_eq!(supervisor.actor(&first_id).unwrap().actor_ref(), first_ref);
        assert_eq!(
            supervisor.actor(&second_id).unwrap().actor_ref(),
            second_ref
        );
        assert_eq!(
            supervisor.actor(&researcher_id).unwrap().actor_ref(),
            researcher_ref
        );
        let sessions = plane.store.sessions().unwrap();
        assert_eq!(sessions.len(), 3);
        assert!(sessions.iter().all(|session| session.status == "idle"));
        assert_eq!(
            sessions
                .iter()
                .find(|session| session.actor_id == second_id.as_str())
                .unwrap()
                .backend,
            LAYOUT_FAILURE_BACKEND_ID
        );
        assert_eq!(
            sessions
                .iter()
                .find(|session| session.actor_id == researcher_id.as_str())
                .unwrap()
                .runtime
                .as_deref(),
            Some(runtime_b.id().as_str())
        );

        let mut least_wip_assignments = Vec::new();
        for index in 1..=3 {
            let created = plane
                .request_create(&json!({
                    "team": implementation_team,
                    "title": format!("matrix work {index}"),
                    "operation_id": format!("matrix-request-{index}"),
                }))
                .unwrap();
            least_wip_assignments.push(
                created["request"]["assignment"]["actor"]["actor_id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
        }
        assert_eq!(
            least_wip_assignments,
            ["impl-matrix-1", "impl-matrix-2", "impl-matrix-1"]
        );
        let research_request = plane
            .request_create(&json!({
                "team": research_team,
                "title": "first healthy research",
                "operation_id": "matrix-research-request",
            }))
            .unwrap();
        assert_eq!(
            research_request["request"]["assignment"]["actor"]["actor_id"],
            researcher_id.as_str()
        );
        let status = plane.status().unwrap();
        let owners = status["observability"]["durable_session_owners"]
            .as_array()
            .unwrap();
        assert!(owners.iter().any(|owner| {
            owner["backend"] == LAYOUT_FAILURE_BACKEND_ID
                && owner["runtime_id"] == runtime_a.id().as_str()
        }));
        assert!(owners.iter().any(|owner| {
            owner["backend"] == "fake" && owner["runtime_id"] == runtime_b.id().as_str()
        }));
        assert_eq!(
            status["observability"]["profile_capabilities"]["all"]["researcher"]["role"],
            "research"
        );

        let repeated = plane.reconcile().unwrap();
        assert_eq!(repeated["complete"], true);
        assert_eq!(runtime_a.launch_count(), 1);
        assert_eq!(runtime_b.launch_count(), 1);
        assert_eq!(plane.store.sessions().unwrap().len(), 3);
    }

    #[test]
    fn reconcile_launches_one_missing_desired_slot_once() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-missing-slot"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            2,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        let team_id = TeamId::new("team-workers").unwrap();
        let first_id = ActorId::new("impl-workers-1").unwrap();
        let team_profile = plane.selected_team_profile().unwrap().snapshot().unwrap();
        let actor_profile = plane.selected_team_actor_profile().unwrap().clone();
        plane
            .store
            .mutate("test.missing_slot_team", &json!({}), 1, |state| {
                state
                    .create_team_with_profile(team_id.clone(), team_profile.clone())
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        plane
            .register_and_launch_desired_actor(
                &team_id,
                &first_id,
                &team_root,
                &actor_profile,
                ProfileMode::Snapshotted,
                None,
            )
            .unwrap();
        assert_eq!(runtime.launch_count(), 1);

        let first = plane.reconcile().unwrap();
        assert_eq!(first["complete"], true);
        assert_eq!(first["instance_reconciliation"][0]["launched"], 1);
        assert_eq!(first["instance_reconciliation"][0]["replaced"], 0);
        assert_eq!(runtime.launch_count(), 2);
        let (_, supervisor, _) = plane.store.load().unwrap();
        assert_eq!(supervisor.team(&team_id).unwrap().actors.len(), 2);
        assert!(
            supervisor
                .actor(&ActorId::new("impl-workers-2").unwrap())
                .is_some()
        );
        assert_eq!(
            plane
                .store
                .sessions()
                .unwrap()
                .into_iter()
                .filter(|session| session.team_id.as_deref() == Some(team_id.as_str()))
                .count(),
            2
        );

        let second = plane.reconcile().unwrap();
        assert_eq!(second["complete"], true);
        assert_eq!(second["instance_reconciliation"][0]["launched"], 0);
        assert_eq!(second["instance_reconciliation"][0]["replaced"], 0);
        assert_eq!(runtime.launch_count(), 2);
        let (_, supervisor, _) = plane.store.load().unwrap();
        assert_eq!(supervisor.team(&team_id).unwrap().actors.len(), 2);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn abandoned_ordinary_launch_is_superseded_by_idempotent_fenced_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-superseded-launch"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-superseded-launch");
        create_profiled_test_team(&plane, &team_root, "create-superseded-launch");
        assert_eq!(runtime.launch_count(), 1);

        let team_id = TeamId::new("team-workers").unwrap();
        let actor_id = ActorId::new("impl-workers-1").unwrap();
        let created = plane
            .request_create(&json!({
                "team": team_id,
                "title": "preserve replacement assignment fences",
                "operation_id": "create-superseded-launch-request",
            }))
            .unwrap();
        let request_id = RequestId::new(
            created["request"]["request_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap();
        let (_, before, _) = plane.store.load().unwrap();
        let source_ref = before.actor(&actor_id).unwrap().actor_ref();
        let source_team_epoch = before.team(&team_id).unwrap().epoch;
        let source_request = before.request(&request_id).unwrap();
        let source_run_id = source_request.run_id.clone();
        let source_assignment = source_request.assignment.clone().unwrap();

        let mut abandoned = plane.store.session(actor_id.as_str()).unwrap().unwrap();
        abandoned.status = "launch_failed".to_owned();
        abandoned.launch_key = super::reconciliation_launch_operation_id(
            &team_id,
            source_team_epoch,
            &actor_id,
            source_ref.actor_epoch,
        );
        abandoned.external_id = None;
        abandoned.resume_token = Some("fake-pane-checkpoint-only".to_owned());
        abandoned.updated_at_ms = 2;
        plane.store.upsert_session(&abandoned).unwrap();
        reset_fake_stop_count();

        let healthy_refusal = plane
            .actor_replace(&json!({
                "id": actor_id,
                "reason": "a launch marker alone cannot fence a healthy actor",
                "operation_id": "refuse-healthy-superseded-launch",
            }))
            .unwrap_err();
        assert_eq!(healthy_refusal.code, "actor_still_healthy");
        assert_eq!(fake_stop_count(), 0);
        let refused_session = plane.store.session(actor_id.as_str()).unwrap().unwrap();
        assert_eq!(refused_session.launch_key, abandoned.launch_key);
        assert_eq!(refused_session.external_id, None);
        assert_eq!(refused_session.resume_token, abandoned.resume_token);

        plane
            .store
            .mutate("test.superseded_launch_stale", &json!({}), 3, |state| {
                state
                    .set_actor_status(&source_ref, ActorStatus::Stale)
                    .map_err(super::ControlError::core)
            })
            .unwrap();

        let replacement_request = json!({
            "id": actor_id,
            "reason": "supersede abandoned ordinary launch",
            "operation_id": "replace-superseded-launch",
        });
        let observed_store = plane.store.clone();
        let observed_source = source_ref.clone();
        let expected_intent = super::replacement_intent_key(
            "replace-superseded-launch",
            source_ref.actor_epoch.get(),
        );
        let expected_checkpoint = abandoned.resume_token.clone();
        set_before_fake_stop(move |record| {
            assert_eq!(record.external_id, None);
            assert_eq!(record.resume_token, expected_checkpoint);
            assert_eq!(record.status, "replacement_pending");
            assert_eq!(record.launch_key, expected_intent);
            let (_, during_cleanup, _) = observed_store.load().unwrap();
            assert_eq!(
                during_cleanup
                    .actor(&observed_source.actor_id)
                    .unwrap()
                    .actor_ref(),
                observed_source
            );
        });
        let replaced = plane.actor_replace(&replacement_request).unwrap();
        clear_before_fake_stop();
        assert_eq!(fake_stop_count(), 1);
        assert_eq!(runtime.launch_count(), 2);
        let replacement_ref: ActorRef = serde_json::from_value(replaced["actor"].clone()).unwrap();
        assert_eq!(
            replacement_ref.actor_epoch,
            source_ref.actor_epoch.checked_next().unwrap()
        );
        let (_, after, _) = plane.store.load().unwrap();
        assert_eq!(after.actor(&actor_id).unwrap().actor_ref(), replacement_ref);
        assert_eq!(
            after.team(&team_id).unwrap().epoch,
            source_team_epoch.checked_next().unwrap()
        );
        let assignment = after
            .request(&request_id)
            .unwrap()
            .assignment
            .as_ref()
            .unwrap();
        assert_eq!(assignment.actor, replacement_ref);
        assert_eq!(
            assignment.epoch,
            source_assignment.epoch.checked_next().unwrap()
        );
        assert_eq!(
            after.run(&source_run_id).unwrap().assignment.as_ref(),
            Some(assignment)
        );
        let session = plane.store.session(actor_id.as_str()).unwrap().unwrap();
        assert_eq!(session.status, "idle");
        assert_eq!(
            session.launch_key,
            super::replacement_intent_key(
                "replace-superseded-launch",
                source_ref.actor_epoch.get()
            )
        );

        let retried = plane.actor_replace(&replacement_request).unwrap();
        assert_eq!(retried, replaced);
        assert_eq!(fake_stop_count(), 1);
        assert_eq!(runtime.launch_count(), 2);

        let stale_heartbeat = plane
            .store
            .mutate(
                "test.superseded_launch_stale_heartbeat",
                &json!({}),
                4,
                |state| {
                    state
                        .heartbeat(&source_ref, TimestampMillis(4))
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap_err();
        assert_eq!(stale_heartbeat.code, "domain_error");
    }

    #[test]
    fn replacement_cleanup_failure_preserves_checkpoint_and_generation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-cleanup-failure"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-cleanup-failure");
        create_profiled_test_team(&plane, &team_root, "create-cleanup-failure");

        let team_id = TeamId::new("team-workers").unwrap();
        let actor_id = ActorId::new("impl-workers-1").unwrap();
        let (_, before, _) = plane.store.load().unwrap();
        let source_ref = before.actor(&actor_id).unwrap().actor_ref();
        let source_team_epoch = before.team(&team_id).unwrap().epoch;
        let mut abandoned = plane.store.session(actor_id.as_str()).unwrap().unwrap();
        abandoned.backend = "herdr".to_owned();
        abandoned.status = "launch_failed".to_owned();
        abandoned.launch_key = super::reconciliation_launch_operation_id(
            &team_id,
            source_team_epoch,
            &actor_id,
            source_ref.actor_epoch,
        );
        abandoned.external_id = None;
        abandoned.resume_token = Some("--unsafe-checkpoint".to_owned());
        plane.store.upsert_session(&abandoned).unwrap();
        plane
            .store
            .mutate("test.cleanup_failure_stale", &json!({}), 3, |state| {
                state
                    .set_actor_status(&source_ref, ActorStatus::Stale)
                    .map_err(super::ControlError::core)
            })
            .unwrap();

        let replacement_request = json!({
            "id": actor_id,
            "reason": "unsafe cleanup observation must fail closed",
            "operation_id": "replace-cleanup-failure",
        });
        for _ in 0..2 {
            let error = plane.actor_replace(&replacement_request).unwrap_err();
            assert_eq!(error.code, "session_backend_error");
            let (_, preserved, _) = plane.store.load().unwrap();
            assert_eq!(preserved.actor(&actor_id).unwrap().actor_ref(), source_ref);
            assert_eq!(preserved.team(&team_id).unwrap().epoch, source_team_epoch);
            let session = plane.store.session(actor_id.as_str()).unwrap().unwrap();
            assert_eq!(session.backend, "herdr");
            assert_eq!(session.external_id, None);
            assert_eq!(session.resume_token.as_deref(), Some("--unsafe-checkpoint"));
            assert_eq!(session.status, "replacement_pending");
            assert_eq!(
                session.launch_key,
                super::replacement_intent_key(
                    "replace-cleanup-failure",
                    source_ref.actor_epoch.get()
                )
            );
        }
        assert_eq!(runtime.launch_count(), 1);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn reconcile_resumes_owned_replacement_without_reviving_source_generation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-owned-replacement"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-owned-replacement");
        create_profiled_test_team(&plane, &team_root, "create-owned-replacement");
        assert_eq!(runtime.launch_count(), 1);

        let team_id = TeamId::new("team-workers").unwrap();
        let actor_id = ActorId::new("impl-workers-1").unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let source_ref = supervisor.actor(&actor_id).unwrap().actor_ref();
        plane
            .store
            .mutate("test.owned_replacement_stale", &json!({}), 2, |state| {
                state
                    .set_actor_status(&source_ref, ActorStatus::Stale)
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        let operation_id = "resume-owned-replacement";
        let intent_key = super::replacement_intent_key(operation_id, source_ref.actor_epoch.get());
        let mut pending = plane
            .store
            .claim_replacement_intent(actor_id.as_str(), &intent_key, 3)
            .unwrap();
        assert_eq!(pending.status, "replacement_pending");
        assert!(pending.external_id.is_some());
        plane.sessions.stop(&pending).unwrap();
        pending.external_id = None;
        pending.resume_token = None;
        pending.status = "launching".to_owned();
        pending.updated_at_ms = 4;
        plane.store.upsert_session(&pending).unwrap();
        let replacement_request = json!({
            "id": actor_id,
            "reason": "stale desired instance",
            "operation_id": operation_id,
        });
        plane
            .store
            .claim_operation(
                operation_id,
                "actor.replace",
                &replacement_request,
                "crashed-automatic-replacement",
                0,
            )
            .unwrap();

        let reconciled = plane.reconcile().unwrap();
        assert_eq!(reconciled["complete"], true);
        assert_eq!(reconciled["instance_reconciliation"][0]["replaced"], 1);
        assert_eq!(reconciled["instance_reconciliation"][0]["launched"], 1);
        assert_eq!(runtime.launch_count(), 2);
        let (_, supervisor, _) = plane.store.load().unwrap();
        let replacement_ref = supervisor.actor(&actor_id).unwrap().actor_ref();
        assert_eq!(
            replacement_ref.actor_epoch.get(),
            source_ref.actor_epoch.get() + 1
        );
        assert_eq!(
            supervisor.actor(&actor_id).unwrap().status,
            ActorStatus::Healthy
        );
        let session = plane.store.session(actor_id.as_str()).unwrap().unwrap();
        assert_eq!(session.status, "idle");
        assert_eq!(session.launch_key, intent_key);
        assert!(session.external_id.is_some());
        assert!(
            plane
                .store
                .operation_result(operation_id, "actor.replace", &replacement_request)
                .unwrap()
                .is_some()
        );
        let stale_heartbeat = plane
            .store
            .mutate(
                "test.owned_replacement_old_heartbeat",
                &json!({}),
                5,
                |state| {
                    state
                        .heartbeat(&source_ref, TimestampMillis(5))
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap_err();
        assert_eq!(stale_heartbeat.code, "domain_error");

        let repeated = plane.reconcile().unwrap();
        assert_eq!(repeated["complete"], true);
        assert_eq!(repeated["instance_reconciliation"][0]["replaced"], 0);
        assert_eq!(repeated["instance_reconciliation"][0]["launched"], 0);
        assert_eq!(runtime.launch_count(), 2);
        let (_, supervisor, _) = plane.store.load().unwrap();
        assert_eq!(
            supervisor.actor(&actor_id).unwrap().actor_ref(),
            replacement_ref
        );
        assert_eq!(supervisor.team(&team_id).unwrap().actors.len(), 1);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn reconcile_preflights_conflicting_team_worktrees_before_session_side_effects() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let first_worktree = temporary.path().join("team-worktree-one");
        let second_worktree = temporary.path().join("team-worktree-two");
        init_test_repository(&root, &first_worktree);
        run_git(
            &root,
            &[
                "worktree",
                "add",
                "--detach",
                second_worktree.to_str().unwrap(),
                "HEAD",
            ],
        );
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-preflight"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            2,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        let team_id = TeamId::new("team-workers").unwrap();
        let first_id = ActorId::new("impl-workers-1").unwrap();
        let second_id = ActorId::new("impl-workers-2").unwrap();
        let team_profile = plane.selected_team_profile().unwrap().snapshot().unwrap();
        let actor_profile = plane.selected_team_actor_profile().unwrap().clone();
        let actor_role = actor_profile.actor_role().unwrap();
        let actor_snapshot = actor_profile.snapshot().unwrap();
        let (_, (first_ref, second_ref)) = plane
            .store
            .mutate("test.conflicting_worktrees", &json!({}), 1, |state| {
                state
                    .create_team_with_profile(team_id.clone(), team_profile.clone())
                    .map_err(super::ControlError::core)?;
                let first = state
                    .register_implementation_with_profile(
                        &team_id,
                        first_id.clone(),
                        actor_role.clone(),
                        actor_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)?;
                let second = state
                    .register_implementation_with_profile(
                        &team_id,
                        second_id.clone(),
                        actor_role.clone(),
                        actor_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)?;
                state
                    .set_actor_status(&first, ActorStatus::Stale)
                    .map_err(super::ControlError::core)?;
                state
                    .set_actor_status(&second, ActorStatus::Stale)
                    .map_err(super::ControlError::core)?;
                Ok((first, second))
            })
            .unwrap();
        for (actor_ref, working_directory) in [
            (&first_ref, first_worktree.as_path()),
            (&second_ref, second_worktree.as_path()),
        ] {
            plane
                .store
                .upsert_session(&SessionRecord {
                    actor_id: actor_ref.actor_id.to_string(),
                    team_id: Some(team_id.to_string()),
                    working_directory: working_directory.to_path_buf(),
                    backend: "fake".to_owned(),
                    runtime: Some(runtime.id().to_string()),
                    external_id: None,
                    resume_token: Some(format!("checkpoint-{}", actor_ref.actor_id)),
                    status: "launch_failed".to_owned(),
                    launch_key: format!("test-launch-{}", actor_ref.actor_id),
                    updated_at_ms: 1,
                    row_revision: 0,
                })
                .unwrap();
        }
        let (revision_before, _, _) = plane.store.load().unwrap();

        let reconciled = plane.reconcile().unwrap();
        assert_eq!(reconciled["complete"], false);
        assert!(
            reconciled["failures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|failure| failure["phase"] == "working_directory_preflight")
        );
        assert_eq!(reconciled["instance_reconciliation"][0]["complete"], false);
        assert_eq!(reconciled["instance_reconciliation"][0]["launched"], 0);
        assert_eq!(runtime.launch_count(), 0);
        let (revision_after, supervisor, _) = plane.store.load().unwrap();
        assert_eq!(revision_after, revision_before);
        assert_eq!(
            supervisor.actor(&first_id).unwrap().status,
            ActorStatus::Stale
        );
        assert_eq!(
            supervisor.actor(&second_id).unwrap().status,
            ActorStatus::Stale
        );
        for actor_id in [&first_id, &second_id] {
            let session = plane.store.session(actor_id.as_str()).unwrap().unwrap();
            assert_eq!(session.status, "launch_failed");
            assert!(session.external_id.is_none());
        }
    }

    #[test]
    fn reconcile_preflights_primary_worktree_before_session_side_effects() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let linked = temporary.path().join("unused-linked-worktree");
        init_test_repository(&root, &linked);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-unsafe-preflight"));
        let settings = profiled_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        let team_id = TeamId::new("team-workers").unwrap();
        let actor_id = ActorId::new("impl-workers-1").unwrap();
        let team_profile = plane.selected_team_profile().unwrap().snapshot().unwrap();
        let actor_profile = plane.selected_team_actor_profile().unwrap().clone();
        let actor_role = actor_profile.actor_role().unwrap();
        let actor_snapshot = actor_profile.snapshot().unwrap();
        let (_, actor_ref) = plane
            .store
            .mutate("test.unsafe_worktree", &json!({}), 1, |state| {
                state
                    .create_team_with_profile(team_id.clone(), team_profile.clone())
                    .map_err(super::ControlError::core)?;
                let actor = state
                    .register_implementation_with_profile(
                        &team_id,
                        actor_id.clone(),
                        actor_role.clone(),
                        actor_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)?;
                state
                    .set_actor_status(&actor, ActorStatus::Stale)
                    .map_err(super::ControlError::core)?;
                Ok(actor)
            })
            .unwrap();
        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: actor_id.to_string(),
                team_id: Some(team_id.to_string()),
                working_directory: root,
                backend: "fake".to_owned(),
                runtime: Some(runtime.id().to_string()),
                external_id: None,
                resume_token: Some("checkpoint-unsafe-worktree".to_owned()),
                status: "launch_failed".to_owned(),
                launch_key: "test-unsafe-launch".to_owned(),
                updated_at_ms: 1,
                row_revision: 0,
            })
            .unwrap();
        let (revision_before, _, _) = plane.store.load().unwrap();

        let reconciled = plane.reconcile().unwrap();
        assert_eq!(reconciled["complete"], false);
        assert!(reconciled["failures"].as_array().unwrap().iter().any(
            |failure| failure["error_code"] == "unsafe_working_directory"
                && failure["phase"] == "working_directory_preflight"
        ));
        assert_eq!(runtime.launch_count(), 0);
        let (revision_after, supervisor, _) = plane.store.load().unwrap();
        assert_eq!(revision_after, revision_before);
        assert_eq!(supervisor.actor(&actor_id).unwrap().actor_ref(), actor_ref);
        assert_eq!(
            supervisor.actor(&actor_id).unwrap().status,
            ActorStatus::Stale
        );
        let session = plane.store.session(actor_id.as_str()).unwrap().unwrap();
        assert_eq!(session.status, "launch_failed");
        assert!(session.external_id.is_none());
    }

    #[test]
    fn zero_desired_preflights_surplus_worktree_before_stopping_actor() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let linked = temporary.path().join("unused-linked-worktree");
        init_test_repository(&root, &linked);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-zero-preflight"));
        let settings = profiled_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime.id().as_str(),
            0,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        let team_id = TeamId::new("team-workers").unwrap();
        let actor_id = ActorId::new("impl-workers-1").unwrap();
        let team_profile = plane.selected_team_profile().unwrap().snapshot().unwrap();
        let actor_profile = plane.selected_team_actor_profile().unwrap().clone();
        let actor_role = actor_profile.actor_role().unwrap();
        let actor_snapshot = actor_profile.snapshot().unwrap();
        let (_, actor_ref) = plane
            .store
            .mutate("test.zero_unsafe_worktree", &json!({}), 1, |state| {
                state
                    .create_team_with_profile(team_id.clone(), team_profile.clone())
                    .map_err(super::ControlError::core)?;
                state
                    .register_implementation_with_profile(
                        &team_id,
                        actor_id.clone(),
                        actor_role.clone(),
                        actor_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        let session = SessionRecord {
            actor_id: actor_id.to_string(),
            team_id: Some(team_id.to_string()),
            working_directory: root,
            backend: "fake".to_owned(),
            runtime: Some(runtime.id().to_string()),
            external_id: Some("unsafe-zero-session".to_owned()),
            resume_token: None,
            status: "idle".to_owned(),
            launch_key: "test-zero-unsafe-launch".to_owned(),
            updated_at_ms: 1,
            row_revision: 0,
        };
        plane.store.upsert_session(&session).unwrap();
        let (revision_before, _, _) = plane.store.load().unwrap();

        let error = plane.reconcile_team_instances(&team_id).unwrap_err();
        assert_eq!(error.code, "unsafe_working_directory");
        assert_eq!(runtime.launch_count(), 0);
        let (revision_after, supervisor, _) = plane.store.load().unwrap();
        assert_eq!(revision_after, revision_before);
        assert_eq!(supervisor.actor(&actor_id).unwrap().actor_ref(), actor_ref);
        assert_eq!(
            supervisor.actor(&actor_id).unwrap().status,
            ActorStatus::Healthy
        );
        let preserved = plane.store.session(actor_id.as_str()).unwrap().unwrap();
        assert_eq!(preserved.status, session.status);
        assert_eq!(preserved.external_id, session.external_id);
        assert_eq!(preserved.working_directory, session.working_directory);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn surplus_wip_is_retained_then_stopped_once_after_becoming_terminal() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-surplus-wip"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "least_wip",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-surplus-wip");
        create_profiled_test_team(&plane, &team_root, "create-surplus-wip");
        let team_id = TeamId::new("team-workers").unwrap();
        for (operation_id, title) in [
            ("desired-wip-one", "desired actor work one"),
            ("desired-wip-two", "desired actor work two"),
        ] {
            let assigned = plane
                .request_create(&json!({
                    "team": team_id,
                    "title": title,
                    "operation_id": operation_id,
                }))
                .unwrap();
            assert_eq!(
                assigned["request"]["assignment"]["actor"]["actor_id"],
                "impl-workers-1"
            );
        }
        let surplus_id = ActorId::new("impl-workers-2").unwrap();
        let actor_profile = plane.selected_team_actor_profile().unwrap().clone();
        let actor_role = actor_profile.actor_role().unwrap();
        let actor_snapshot = actor_profile.snapshot().unwrap();
        let (_, surplus_ref) = plane
            .store
            .mutate("test.surplus_actor", &json!({}), 2, |state| {
                let actor = state
                    .register_implementation_with_profile(
                        &team_id,
                        surplus_id.clone(),
                        actor_role.clone(),
                        actor_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&actor, TimestampMillis(2))
                    .map_err(super::ControlError::core)?;
                Ok(actor)
            })
            .unwrap();
        let surplus_launch_key = "test-surplus-launch";
        plane
            .ensure_actor_session(
                &surplus_ref,
                &team_id,
                &team_root,
                &actor_profile,
                plane.runtime_for_profile(&actor_profile).unwrap().as_ref(),
                surplus_launch_key,
            )
            .unwrap();
        assert_eq!(runtime.launch_count(), 2);
        let replacement = plane
            .actor_replace(&json!({
                "id": surplus_id,
                "reason": "must not revive draining surplus capacity",
                "operation_id": "replace-surplus-rejected",
            }))
            .unwrap_err();
        assert_eq!(replacement.code, "actor_not_desired");
        let (_, after_rejected_replacement, _) = plane.store.load().unwrap();
        assert_eq!(
            after_rejected_replacement
                .actor(&surplus_id)
                .unwrap()
                .actor_ref(),
            surplus_ref
        );
        assert_eq!(runtime.launch_count(), 2);
        let (_, preliminary, _) = plane.store.load().unwrap();
        assert!(super::nonterminal_request_ids(&preliminary, &surplus_ref).is_empty());

        let request_id = RequestId::new("request-surplus-wip").unwrap();
        let run_id = RunId::new("run-surplus-wip").unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let envelope = super::make_envelope(
            &supervisor,
            super::active_primary_actor(&supervisor).unwrap(),
            MessageTarget::Actor(surplus_id.clone()),
            Some(team_id.clone()),
            Some(run_id),
            Some(request_id.clone()),
            None,
            Message::ImplementationRequest(ImplementationRequest {
                title: "surplus work".to_owned(),
                instructions: "keep the assigned surplus actor alive".to_owned(),
                base_sha: super::git_sha_for(&test_git(), &team_root).unwrap(),
                base_source: agsv_protocol::RequestBaseSource::Derived,
                acceptance_criteria: vec!["retain WIP".to_owned()],
                evidence_requirements: vec![EvidenceKind::Test],
            }),
            MessageId::new("message-surplus-wip").unwrap(),
        )
        .unwrap();
        plane
            .store
            .mutate("test.assign_surplus", &json!({}), 3, |state| {
                apply_envelope(state, envelope.clone())
            })
            .unwrap();
        let guarded = plane
            .stop_surplus_actor_if_idle(&team_id, &surplus_ref, 1)
            .unwrap_err();
        assert_eq!(guarded.code, "surplus_wip");
        assert_eq!(
            guarded.details["assigned_nonterminal_request_ids"],
            json!([request_id])
        );
        let (_, after_guard, _) = plane.store.load().unwrap();
        assert_eq!(
            after_guard.actor(&surplus_id).unwrap().status,
            ActorStatus::Healthy
        );

        let retained = plane.reconcile().unwrap();
        assert_eq!(retained["complete"], false);
        assert_eq!(retained["instance_reconciliation"][0]["complete"], false);
        assert!(
            retained["instance_reconciliation"][0]["failures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|failure| failure["phase"] == "surplus_wip")
        );
        let (_, supervisor, _) = plane.store.load().unwrap();
        assert_eq!(
            supervisor.actor(&surplus_id).unwrap().status,
            ActorStatus::Healthy
        );
        assert_eq!(
            plane
                .store
                .session(surplus_id.as_str())
                .unwrap()
                .unwrap()
                .status,
            "idle"
        );
        let newly_assigned = plane
            .request_create(&json!({
                "team": team_id,
                "title": "new desired-slot work",
                "body": "do not assign new work to draining surplus capacity",
                "operation_id": "request-after-surplus-wip",
            }))
            .unwrap();
        assert_eq!(
            newly_assigned["request"]["assignment"]["actor"]["actor_id"],
            "impl-workers-1"
        );

        plane
            .request_cancel(&json!({
                "id": request_id,
                "reason": "surplus work completed elsewhere",
                "operation_id": "cancel-surplus-wip",
            }))
            .unwrap();
        plane.set_test_authenticated_actor(surplus_ref.clone());
        for (message_id, operation_id) in [
            ("message-surplus-wip".to_owned(), "ack-surplus-request"),
            (
                super::message_id("cancel-surplus-wip", "cancel").to_string(),
                "ack-surplus-cancellation",
            ),
        ] {
            plane
                .message_ack(&json!({
                    "id": message_id,
                    "operation_id": operation_id,
                }))
                .unwrap();
        }
        let stopped = plane.reconcile().unwrap();
        assert_eq!(stopped["complete"], true);
        assert_eq!(stopped["instance_reconciliation"][0]["stopped"], 1);
        let (_, supervisor, _) = plane.store.load().unwrap();
        assert!(supervisor.request(&request_id).is_none());
        assert!(
            plane
                .store
                .archived_request(&request_id)
                .unwrap()
                .expect("fully acknowledged terminal request is archived")
                .0
                .status
                .is_terminal()
        );
        assert_eq!(
            supervisor.actor(&surplus_id).unwrap().status,
            ActorStatus::Stopped
        );
        assert_eq!(
            plane
                .store
                .session(surplus_id.as_str())
                .unwrap()
                .unwrap()
                .status,
            "stopped"
        );

        let repeated = plane.reconcile().unwrap();
        assert_eq!(repeated["complete"], true);
        assert_eq!(repeated["instance_reconciliation"][0]["stopped"], 0);
        assert_eq!(runtime.launch_count(), 2);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn surplus_actor_waits_for_its_frozen_directive_acknowledgement() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-surplus-directive"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        let primary = activate_test_primary(&plane, "primary-surplus-directive");
        let observed_at = super::now_ms().unwrap();
        plane
            .store
            .mutate(
                "test.surplus_directive_primary_current",
                &json!({}),
                observed_at,
                |state| {
                    state
                        .heartbeat(&primary, TimestampMillis(observed_at))
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap();
        create_profiled_test_team(&plane, &team_root, "create-surplus-directive");
        let team_id = TeamId::new("team-workers").unwrap();
        let surplus_id = ActorId::new("impl-workers-2").unwrap();
        let actor_profile = plane.selected_team_actor_profile().unwrap().clone();
        let actor_role = actor_profile.actor_role().unwrap();
        let actor_snapshot = actor_profile.snapshot().unwrap();
        let (_, surplus_ref) = plane
            .store
            .mutate("test.surplus_directive_actor", &json!({}), 2, |state| {
                state
                    .register_implementation_with_profile(
                        &team_id,
                        surplus_id.clone(),
                        actor_role.clone(),
                        actor_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        plane
            .ensure_actor_session(
                &surplus_ref,
                &team_id,
                &team_root,
                &actor_profile,
                plane.runtime_for_profile(&actor_profile).unwrap().as_ref(),
                "test-surplus-directive-launch",
            )
            .unwrap();
        plane.set_test_authenticated_actor(primary);
        let sent = plane
            .message_send(&json!({
                "kind": "directive",
                "to": surplus_id,
                "team": team_id,
                "decision": "ack before draining this slot",
                "rationale": "a frozen recipient must not become permanently unreachable",
                "operation_id": "surplus-pending-directive",
            }))
            .unwrap();
        let message_id = MessageId::new(sent["message_id"].as_str().unwrap().to_owned()).unwrap();

        let blocked = plane
            .stop_surplus_actor_if_idle(&team_id, &surplus_ref, 1)
            .unwrap_err();
        assert_eq!(blocked.code, "surplus_unacknowledged_messages");
        assert_eq!(
            blocked.details["unacknowledged_message_ids"],
            json!([message_id])
        );
        let (_, guarded, _) = plane.store.load().unwrap();
        assert_eq!(
            guarded.actor(&surplus_ref.actor_id).unwrap().status,
            ActorStatus::Healthy
        );

        plane.set_test_authenticated_actor(surplus_ref.clone());
        plane
            .message_ack(&json!({
                "id": message_id,
                "operation_id": "ack-surplus-pending-directive",
            }))
            .unwrap();
        let stopped = plane
            .stop_surplus_actor_if_idle(&team_id, &surplus_ref, 1)
            .unwrap();
        assert_eq!(stopped["status"], "stopped");
        let (_, final_state, _) = plane.store.load().unwrap();
        assert_eq!(
            final_state.actor(&surplus_ref.actor_id).unwrap().status,
            ActorStatus::Stopped
        );
        assert!(final_state.delivery(&message_id).is_none());
        assert!(
            plane
                .store
                .archived_delivery(&message_id)
                .unwrap()
                .expect("acknowledged requestless directive is archived")
                .retired
        );
    }

    #[test]
    fn stopped_surplus_with_a_present_session_retries_backend_cleanup() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-surplus-cleanup"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-surplus-cleanup");
        create_profiled_test_team(&plane, &team_root, "create-surplus-cleanup");
        let team_id = TeamId::new("team-workers").unwrap();
        let surplus_id = ActorId::new("impl-workers-2").unwrap();
        let actor_profile = plane.selected_team_actor_profile().unwrap().clone();
        let actor_role = actor_profile.actor_role().unwrap();
        let actor_snapshot = actor_profile.snapshot().unwrap();
        let (_, surplus_ref) = plane
            .store
            .mutate("test.surplus_cleanup_actor", &json!({}), 2, |state| {
                state
                    .register_implementation_with_profile(
                        &team_id,
                        surplus_id.clone(),
                        actor_role.clone(),
                        actor_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        plane
            .ensure_actor_session(
                &surplus_ref,
                &team_id,
                &team_root,
                &actor_profile,
                plane.runtime_for_profile(&actor_profile).unwrap().as_ref(),
                "test-surplus-cleanup-launch",
            )
            .unwrap();
        plane
            .store
            .mutate("test.surplus_domain_fenced", &json!({}), 3, |state| {
                state
                    .set_actor_status(&surplus_ref, ActorStatus::Stopped)
                    .map_err(super::ControlError::core)
            })
            .unwrap();

        let (_, supervisor, _) = plane.store.load().unwrap();
        let summary = plane.assignment_instance_summary(&supervisor).unwrap();
        assert_eq!(summary["teams"][0]["surplus_instances"], 1);
        assert_eq!(summary["teams"][0]["actual_instances"], 2);
        assert_eq!(summary["teams"][0]["converged"], false);

        let cleaned = plane.reconcile().unwrap();
        assert_eq!(cleaned["complete"], true);
        assert_eq!(cleaned["instance_reconciliation"][0]["stopped"], 1);
        assert_eq!(
            plane
                .store
                .session(surplus_id.as_str())
                .unwrap()
                .unwrap()
                .status,
            "stopped"
        );
        let repeated = plane.reconcile().unwrap();
        assert_eq!(repeated["complete"], true);
        assert_eq!(repeated["instance_reconciliation"][0]["stopped"], 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn reconcile_reuses_live_stale_actor_replaces_dead_actor_and_resumes_paused_team() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-lifecycle"));
        let settings = profiled_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime.id().as_str(),
            2,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-lifecycle");
        create_profiled_test_team(&plane, &team_root, "create-lifecycle");
        assert_eq!(runtime.launch_count(), 2);

        let team_id = TeamId::new("team-workers").unwrap();
        let first_id = ActorId::new("impl-workers-1").unwrap();
        let second_id = ActorId::new("impl-workers-2").unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let first_ref = supervisor.actor(&first_id).unwrap().actor_ref();
        let second_epoch = supervisor.actor(&second_id).unwrap().epoch;
        plane
            .store
            .mutate("test.stale_live", &json!({}), 2, |state| {
                state
                    .set_actor_status(&first_ref, ActorStatus::Stale)
                    .map_err(super::ControlError::core)
            })
            .unwrap();

        let live_reconcile = plane.reconcile().unwrap();
        assert_eq!(live_reconcile["complete"], true);
        assert_eq!(runtime.launch_count(), 2);
        let (_, supervisor, _) = plane.store.load().unwrap();
        let reused_first = supervisor.actor(&first_id).unwrap();
        assert_eq!(reused_first.status, ActorStatus::Healthy);
        assert_eq!(reused_first.epoch, first_ref.actor_epoch);

        let mut dead_session = plane.store.session(first_id.as_str()).unwrap().unwrap();
        dead_session.status = "missing".to_owned();
        plane.store.upsert_session(&dead_session).unwrap();
        let first_ref = reused_first.actor_ref();
        plane
            .store
            .mutate("test.stale_dead", &json!({}), 3, |state| {
                state
                    .set_actor_status(&first_ref, ActorStatus::Stale)
                    .map_err(super::ControlError::core)
            })
            .unwrap();

        let replaced = plane.reconcile().unwrap();
        assert_eq!(replaced["complete"], true);
        assert_eq!(runtime.launch_count(), 3);
        let (_, supervisor, _) = plane.store.load().unwrap();
        assert_eq!(supervisor.actor(&first_id).unwrap().epoch.get(), 2);
        assert_eq!(supervisor.actor(&second_id).unwrap().epoch, second_epoch);
        assert_eq!(
            supervisor.actor(&second_id).unwrap().status,
            ActorStatus::Healthy
        );

        plane
            .team_status(
                &json!({
                    "id": team_id,
                    "operation_id": "pause-lifecycle",
                }),
                TeamStatus::Paused,
                "team.pause",
            )
            .unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let second_ref = supervisor.actor(&second_id).unwrap().actor_ref();
        plane
            .store
            .mutate("test.pause_stale", &json!({}), 4, |state| {
                state
                    .set_actor_status(&second_ref, ActorStatus::Stale)
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        let mut paused_session = plane.store.session(second_id.as_str()).unwrap().unwrap();
        paused_session.status = "missing".to_owned();
        plane.store.upsert_session(&paused_session).unwrap();

        let paused = plane.reconcile().unwrap();
        assert_eq!(paused["complete"], true);
        assert_eq!(paused["instance_reconciliation"][0]["deferred"], true);
        assert_eq!(runtime.launch_count(), 3);
        let resumed = plane
            .team_status(
                &json!({
                    "id": team_id,
                    "operation_id": "resume-lifecycle",
                }),
                TeamStatus::Active,
                "team.resume",
            )
            .unwrap();
        assert_eq!(resumed["instance_reconciliation"]["complete"], true);
        assert_eq!(runtime.launch_count(), 4);
        let (_, supervisor, _) = plane.store.load().unwrap();
        assert_eq!(supervisor.actor(&second_id).unwrap().epoch.get(), 2);

        let other_worktree = temporary.path().join("other-team-worktree");
        run_git(
            &root,
            &[
                "worktree",
                "add",
                "--detach",
                other_worktree.to_str().unwrap(),
                "HEAD",
            ],
        );
        let mut conflicting = plane.store.session(second_id.as_str()).unwrap().unwrap();
        conflicting.working_directory = other_worktree;
        plane.store.upsert_session(&conflicting).unwrap();
        let conflict = plane.existing_team_working_directory(&team_id).unwrap_err();
        assert_eq!(conflict.code, "working_directory_conflict");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn fresh_team_create_fences_a_healthy_actor_with_a_dead_backend_session() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-create-fencing"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            2,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-create-fencing");
        create_profiled_test_team(&plane, &team_root, "create-fencing-initial");
        assert_eq!(runtime.launch_count(), 2);

        let team_id = TeamId::new("team-workers").unwrap();
        let first_id = ActorId::new("impl-workers-1").unwrap();
        let second_id = ActorId::new("impl-workers-2").unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let old_first_ref = supervisor.actor(&first_id).unwrap().actor_ref();
        let peer_ref = supervisor.actor(&second_id).unwrap().actor_ref();
        assert_eq!(
            supervisor.actor(&first_id).unwrap().status,
            ActorStatus::Healthy
        );
        let mut dead_session = plane.store.session(first_id.as_str()).unwrap().unwrap();
        dead_session.status = "missing".to_owned();
        plane.store.upsert_session(&dead_session).unwrap();

        let fresh_request = json!({
            "name": "workers",
            "working_directory": team_root,
            "orchestrators": 1,
            "operation_id": "create-fencing-fresh",
        });
        let recreated = plane.team_create(&fresh_request).unwrap();
        assert_eq!(recreated["reused"], false);
        assert_eq!(recreated["instance_reconciliation"]["replaced"], 1);
        assert_eq!(recreated["instance_reconciliation"]["launched"], 1);
        assert_eq!(runtime.launch_count(), 3);
        let (_, supervisor, _) = plane.store.load().unwrap();
        let new_first_ref = supervisor.actor(&first_id).unwrap().actor_ref();
        assert_eq!(
            new_first_ref.actor_epoch.get(),
            old_first_ref.actor_epoch.get() + 1
        );
        assert_eq!(supervisor.actor(&second_id).unwrap().actor_ref(), peer_ref);
        assert_eq!(supervisor.team(&team_id).unwrap().actors.len(), 2);

        let old_heartbeat = plane
            .store
            .mutate("test.old_generation_heartbeat", &json!({}), 4, |state| {
                state
                    .heartbeat(&old_first_ref, TimestampMillis(4))
                    .map_err(super::ControlError::core)
            })
            .unwrap_err();
        assert_eq!(old_heartbeat.code, "domain_error");

        let retried = plane.team_create(&fresh_request).unwrap();
        assert_eq!(retried, recreated);
        assert_eq!(runtime.launch_count(), 3);
        let another = plane
            .team_create(&json!({
                "name": "workers",
                "working_directory": team_root,
                "orchestrators": 2,
                "operation_id": "create-fencing-another",
            }))
            .unwrap();
        assert_eq!(another["reused"], true);
        assert_eq!(runtime.launch_count(), 3);
        let (_, supervisor, _) = plane.store.load().unwrap();
        assert_eq!(
            supervisor.actor(&first_id).unwrap().actor_ref(),
            new_first_ref
        );
        assert_eq!(supervisor.actor(&second_id).unwrap().actor_ref(), peer_ref);
        assert_eq!(supervisor.team(&team_id).unwrap().actors.len(), 2);
    }

    #[test]
    fn reconciliation_rejects_profile_drift_before_registering_a_missing_sibling() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-profile-drift"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            2,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings.clone(), &runtime);
        let team_id = TeamId::new("team-workers").unwrap();
        let first_id = ActorId::new("impl-workers-1").unwrap();
        let team_profile = plane.selected_team_profile().unwrap().snapshot().unwrap();
        let actor_profile = plane.selected_team_actor_profile().unwrap().clone();
        let actor_role = actor_profile.actor_role().unwrap();
        let actor_snapshot = actor_profile.snapshot().unwrap();
        plane
            .store
            .mutate("test.profile_drift_setup", &json!({}), 1, |state| {
                state
                    .create_team_with_profile(team_id.clone(), team_profile.clone())
                    .map_err(super::ControlError::core)?;
                state
                    .register_implementation_with_profile(
                        &team_id,
                        first_id.clone(),
                        actor_role.clone(),
                        actor_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)?;
                Ok(())
            })
            .unwrap();

        let mut drifted_settings = settings;
        drifted_settings
            .agent_profiles
            .get_mut(LEGACY_IMPLEMENTATION_PROFILE)
            .unwrap()
            .capabilities
            .insert("review".to_owned());
        let drifted = open_fixture_plane(drifted_settings, &runtime);
        let error = drifted.reconcile_team_instances(&team_id).unwrap_err();
        assert_eq!(error.code, "actor_profile_mismatch");
        let (_, supervisor, _) = drifted.store.load().unwrap();
        assert_eq!(supervisor.team(&team_id).unwrap().actors, vec![first_id]);
        assert!(
            supervisor
                .actor(&ActorId::new("impl-workers-2").unwrap())
                .is_none()
        );
    }

    #[test]
    fn unsupported_assignment_policy_is_rejected_when_control_plane_opens() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-policy"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "review_quorum",
        );
        let mut registry = RuntimeRegistry::new();
        registry.register(runtime).unwrap();
        let Err(error) = ControlPlane::open_with_runtime_registry(settings, &registry) else {
            panic!("unsupported assignment policy should fail");
        };
        assert_eq!(error.code, "unsupported_assignment_policy");
        assert_eq!(
            error.details["available_assignment_policies"],
            json!(["first_healthy", "least_wip"])
        );
    }

    #[test]
    fn disabled_runtime_adapter_is_rejected_before_state_is_created() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-disabled"));
        let state_directory = temporary.path().join("state");
        let mut settings = legacy_settings(root, state_directory.clone(), runtime.id().as_str());
        settings
            .runtime_adapter_availability
            .insert(runtime.id().to_string(), false);
        let registry = FixtureRuntimeCatalog {
            runtime: runtime.clone(),
        };

        let Err(error) = ControlPlane::open_with_runtime_registry(settings, &registry) else {
            panic!("disabled runtime adapter should fail closed");
        };
        assert_eq!(error.code, "runtime_adapter_disabled");
        assert_eq!(error.details["actor_profile"], "implementation");
        assert_eq!(error.details["configured_runtime"], runtime.id().as_str());
        assert_eq!(error.details["available"], false);
        assert!(!state_directory.exists());
    }

    #[test]
    fn legacy_checkpoint_backfills_codex_and_rejects_changed_registry_default() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);

        let registry = FixtureDefaultRegistry::new();
        assert_eq!(
            RuntimeCatalog::select(&registry, None)
                .unwrap()
                .id()
                .as_str(),
            "fixture-runtime"
        );
        let mut settings = legacy_settings(
            root.clone(),
            temporary.path().join("state"),
            LEGACY_RUNTIME_ID,
        );
        let original =
            ControlPlane::open_with_runtime_registry(settings.clone(), &registry).unwrap();
        let team_id = TeamId::new("team-runtime-recovery").unwrap();
        let actor_id = ActorId::new("impl-runtime-recovery-1").unwrap();
        let (_, actor_ref) = original
            .store
            .mutate("test.setup", &json!({}), 1, |state| {
                state
                    .create_team(team_id.clone())
                    .map_err(super::ControlError::core)?;
                let actor = state
                    .register_implementation(&team_id, actor_id.clone())
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&actor, TimestampMillis(1))
                    .map_err(super::ControlError::core)?;
                Ok(actor)
            })
            .unwrap();
        original
            .store
            .upsert_session(&SessionRecord {
                actor_id: actor_id.to_string(),
                team_id: Some(team_id.to_string()),
                working_directory: team_root.clone(),
                backend: "fake".to_owned(),
                // v0.1 rows had no runtime column and always belonged to Codex,
                // independently of the current registry default.
                runtime: None,
                external_id: None,
                resume_token: Some("checkpoint-legacy-runtime".to_owned()),
                status: "launch_failed".to_owned(),
                launch_key: "launch-runtime-recovery".to_owned(),
                updated_at_ms: 1,
                row_revision: 0,
            })
            .unwrap();
        let mut legacy = original.store.session(actor_id.as_str()).unwrap().unwrap();
        let original_runtime = original.selected_team_runtime().unwrap();
        original
            .validate_session_record(
                &mut legacy,
                &actor_ref,
                &team_id,
                &team_root,
                None,
                original_runtime.as_ref(),
            )
            .unwrap();
        assert_eq!(legacy.runtime.as_deref(), Some(LEGACY_RUNTIME_ID));
        assert_eq!(
            original
                .store
                .session(actor_id.as_str())
                .unwrap()
                .unwrap()
                .runtime
                .as_deref(),
            Some(LEGACY_RUNTIME_ID)
        );

        for profile in settings.agent_profiles.values_mut() {
            if let ActorLaunchSettings::Runtime { runtime, .. } = &mut profile.launch {
                *runtime = "fixture-runtime".to_owned();
            }
        }
        let switched = ControlPlane::open_with_runtime_registry(settings, &registry).unwrap();
        let mut session = switched.store.session(actor_id.as_str()).unwrap().unwrap();
        let error = switched
            .recover_incomplete_session(&mut session)
            .unwrap_err();

        assert_eq!(error.code, "session_runtime_mismatch");
        assert_eq!(error.details["durable_runtime"], LEGACY_RUNTIME_ID);
        assert_eq!(error.details["selected_runtime"], "fixture-runtime");
        assert_eq!(error.details["legacy_runtime_defaulted"], false);
        let durable = switched.store.session(actor_id.as_str()).unwrap().unwrap();
        assert_eq!(durable.runtime.as_deref(), Some(LEGACY_RUNTIME_ID));
        assert_eq!(
            durable.resume_token.as_deref(),
            Some("checkpoint-legacy-runtime")
        );
    }

    #[test]
    fn profileless_team_profile_identity_survives_live_profile_rename() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let seed = temporary.path().join("seed-worktree");
        init_test_repository(&root, &seed);
        let mut settings = legacy_settings(
            root,
            temporary.path().join("state-profileless-rename"),
            LEGACY_RUNTIME_ID,
        );
        let original = ControlPlane::open(settings.clone()).unwrap();
        let team_id = TeamId::new("team-profileless-rename").unwrap();
        original
            .store
            .mutate("test.profileless_team", &json!({}), 1, |state| {
                state
                    .create_team(team_id.clone())
                    .map_err(super::ControlError::core)
            })
            .unwrap();

        let mut replacement = settings
            .team_profiles
            .remove(LEGACY_IMPLEMENTATION_PROFILE)
            .unwrap();
        replacement.name = "replacement".to_owned();
        settings.default_team_profile.clone_from(&replacement.name);
        settings
            .team_profiles
            .insert(replacement.name.clone(), replacement);
        let reopened = ControlPlane::open(settings).unwrap();
        let (_, supervisor, _) = reopened.store.load().unwrap();
        let team = supervisor.team(&team_id).unwrap();

        let (persisted, _, mode) = reopened
            .team_control_profile(Some(team), Some(LEGACY_IMPLEMENTATION_PROFILE))
            .unwrap();
        assert_eq!(persisted.name, LEGACY_IMPLEMENTATION_PROFILE);
        assert_eq!(mode, ProfileMode::Legacy);

        let mismatch = reopened
            .team_control_profile(Some(team), Some("missing-profile"))
            .unwrap_err();
        assert_eq!(mismatch.code, "team_profile_mismatch");
        assert_eq!(
            mismatch.details["persisted_team_profile"],
            LEGACY_IMPLEMENTATION_PROFILE
        );
        assert_eq!(
            mismatch.details["requested_team_profile"],
            "missing-profile"
        );
        assert_eq!(mismatch.details["requested_team_profile_configured"], false);
        assert_eq!(
            mismatch.details["available_team_profiles"],
            json!(["replacement"])
        );
    }

    #[test]
    fn snapshotted_team_profile_identity_survives_live_profile_rename() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let seed = temporary.path().join("seed-worktree");
        init_test_repository(&root, &seed);
        let mut settings = profiled_settings(
            root,
            temporary.path().join("state-snapshotted-rename"),
            LEGACY_RUNTIME_ID,
            1,
            "first_healthy",
        );
        let original = ControlPlane::open(settings.clone()).unwrap();
        let team_id = TeamId::new("team-snapshotted-rename").unwrap();
        let snapshot = settings.team_profiles[LEGACY_IMPLEMENTATION_PROFILE]
            .snapshot()
            .unwrap();
        original
            .store
            .mutate("test.snapshotted_team", &json!({}), 1, |state| {
                state
                    .create_team_with_profile(team_id.clone(), snapshot.clone())
                    .map_err(super::ControlError::core)
            })
            .unwrap();

        let mut replacement = settings
            .team_profiles
            .remove(LEGACY_IMPLEMENTATION_PROFILE)
            .unwrap();
        replacement.name = "replacement".to_owned();
        settings.default_team_profile.clone_from(&replacement.name);
        settings
            .team_profiles
            .insert(replacement.name.clone(), replacement);
        let reopened = ControlPlane::open(settings).unwrap();
        let (_, supervisor, _) = reopened.store.load().unwrap();
        let team = supervisor.team(&team_id).unwrap();

        let (persisted, _, mode) = reopened
            .team_control_profile(Some(team), Some(LEGACY_IMPLEMENTATION_PROFILE))
            .unwrap();
        assert_eq!(persisted.name, LEGACY_IMPLEMENTATION_PROFILE);
        assert_eq!(persisted.snapshot().unwrap(), snapshot);
        assert_eq!(mode, ProfileMode::Snapshotted);

        let mismatch = reopened
            .team_control_profile(Some(team), Some("missing-profile"))
            .unwrap_err();
        assert_eq!(mismatch.code, "team_profile_mismatch");
        assert_eq!(
            mismatch.details["persisted_team_profile"],
            LEGACY_IMPLEMENTATION_PROFILE
        );
        assert_eq!(
            mismatch.details["requested_team_profile"],
            "missing-profile"
        );
        assert_eq!(mismatch.details["requested_team_profile_configured"], false);
        assert_eq!(
            mismatch.details["available_team_profiles"],
            json!(["replacement"])
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn recovery_uses_persisted_actor_runtime_after_default_team_profile_changes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);

        let runtime_a = Arc::new(FixtureRuntime::with_id("fixture-runtime-a"));
        let runtime_b = Arc::new(FixtureRuntime::with_id("fixture-runtime-b"));
        let mut registry = RuntimeRegistry::new();
        registry.register(runtime_a.clone()).unwrap();
        registry.register(runtime_b.clone()).unwrap();

        let mut settings = legacy_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime_a.id().as_str(),
        );
        settings.persist_profile_snapshots = true;
        let mut actor_profile_b = settings.agent_profiles[LEGACY_IMPLEMENTATION_PROFILE].clone();
        actor_profile_b.name = "implementation-b".to_owned();
        let ActorLaunchSettings::Runtime { runtime, .. } = &mut actor_profile_b.launch else {
            panic!("implementation actor profiles must be runtime-launched");
        };
        *runtime = runtime_b.id().to_string();
        settings
            .agent_profiles
            .insert(actor_profile_b.name.clone(), actor_profile_b.clone());
        let team_profile_b = TeamProfileSettings {
            name: "implementation-b".to_owned(),
            actor_profile: actor_profile_b.name.clone(),
            desired_instances: 1,
            assignment_policy: "first_healthy".to_owned(),
        };
        settings
            .team_profiles
            .insert(team_profile_b.name.clone(), team_profile_b);

        let original =
            ControlPlane::open_with_runtime_registry(settings.clone(), &registry).unwrap();
        let team_id = TeamId::new("team-profile-runtime-recovery").unwrap();
        let actor_id = ActorId::new("impl-profile-runtime-recovery-1").unwrap();
        let actor_profile_a = settings.agent_profiles[LEGACY_IMPLEMENTATION_PROFILE].clone();
        let team_profile_a = settings.team_profiles[LEGACY_IMPLEMENTATION_PROFILE].clone();
        let actor_snapshot_a = actor_profile_a.snapshot().unwrap();
        let actor_role_a = actor_profile_a.actor_role().unwrap();
        let team_snapshot_a = team_profile_a.snapshot().unwrap();
        original
            .store
            .mutate("test.setup", &json!({}), 1, |state| {
                state
                    .create_team_with_profile(team_id.clone(), team_snapshot_a.clone())
                    .map_err(super::ControlError::core)?;
                let actor = state
                    .register_implementation_with_profile(
                        &team_id,
                        actor_id.clone(),
                        actor_role_a.clone(),
                        actor_snapshot_a.clone(),
                    )
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&actor, TimestampMillis(1))
                    .map_err(super::ControlError::core)?;
                Ok(actor)
            })
            .unwrap();
        original
            .store
            .upsert_session(&SessionRecord {
                actor_id: actor_id.to_string(),
                team_id: Some(team_id.to_string()),
                working_directory: team_root,
                backend: "fake".to_owned(),
                runtime: Some(runtime_a.id().to_string()),
                external_id: None,
                resume_token: Some("checkpoint-profile-runtime-a".to_owned()),
                status: "launch_failed".to_owned(),
                launch_key: "launch-profile-runtime-recovery".to_owned(),
                updated_at_ms: 1,
                row_revision: 0,
            })
            .unwrap();

        settings.default_team_profile = "implementation-b".to_owned();
        let switched = ControlPlane::open_with_runtime_registry(settings, &registry).unwrap();
        assert_eq!(
            switched.selected_team_runtime().unwrap().id(),
            runtime_b.id()
        );
        let (_, supervisor, _) = switched.store.load().unwrap();
        let persisted_actor = supervisor.actor(&actor_id).unwrap();
        let persisted_profile = switched.actor_profile(persisted_actor).unwrap();
        assert_eq!(persisted_profile.name, LEGACY_IMPLEMENTATION_PROFILE);
        assert_eq!(
            switched
                .runtime_for_profile(persisted_profile)
                .unwrap()
                .id(),
            runtime_a.id()
        );

        let mut session = switched.store.session(actor_id.as_str()).unwrap().unwrap();
        switched.recover_incomplete_session(&mut session).unwrap();

        assert_eq!(runtime_a.launch_count(), 1);
        assert_eq!(runtime_b.launch_count(), 0);
        let durable = switched.store.session(actor_id.as_str()).unwrap().unwrap();
        assert_eq!(durable.runtime.as_deref(), Some(runtime_a.id().as_str()));
        assert_eq!(durable.status, "idle");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn explicit_profiles_preserve_legacy_entities_and_snapshot_only_new_entities() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let linked = temporary.path().join("linked-worktree");
        init_test_repository(&root, &linked);

        let mut settings = legacy_settings(
            root,
            temporary.path().join("state-profile-migration"),
            LEGACY_RUNTIME_ID,
        );
        let original = ControlPlane::open(settings.clone()).unwrap();
        let primary_id = ActorId::new("primary-profileless").unwrap();
        let legacy_team_id = TeamId::new("team-profileless").unwrap();
        let legacy_actor_id = ActorId::new("impl-profileless-1").unwrap();
        original
            .store
            .mutate("test.seed_profileless", &json!({}), 1, |state| {
                let primary = state
                    .activate_primary(primary_id.clone())
                    .map_err(super::ControlError::core)?;
                state
                    .set_actor_status(&primary, ActorStatus::Stale)
                    .map_err(super::ControlError::core)?;
                state
                    .create_team(legacy_team_id.clone())
                    .map_err(super::ControlError::core)?;
                let implementation = state
                    .register_implementation(&legacy_team_id, legacy_actor_id.clone())
                    .map_err(super::ControlError::core)?;
                state
                    .set_actor_status(&implementation, ActorStatus::Stale)
                    .map_err(super::ControlError::core)
            })
            .unwrap();

        settings.persist_profile_snapshots = true;
        let switched = ControlPlane::open(settings.clone()).unwrap();
        let primary_profile = switched.primary_profile().unwrap().clone();
        let primary_role = primary_profile.actor_role().unwrap();
        let primary_snapshot = primary_profile.snapshot().unwrap();
        let team_profile = switched.selected_team_profile().unwrap().clone();
        let actor_profile = switched.selected_team_actor_profile().unwrap().clone();
        let actor_role = actor_profile.actor_role().unwrap();
        let actor_snapshot = actor_profile.snapshot().unwrap();
        let team_snapshot = team_profile.snapshot().unwrap();
        let legacy_registered_id = ActorId::new("impl-profileless-2").unwrap();
        let new_team_id = TeamId::new("team-snapshotted").unwrap();
        let new_actor_id = ActorId::new("impl-snapshotted-1").unwrap();
        let (_, result) = switched
            .store
            .mutate("test.migrate_profileless", &json!({}), 2, |state| {
                let primary = activate_primary_for_profile(
                    state,
                    &primary_id,
                    &primary_profile,
                    &primary_role,
                    &primary_snapshot,
                    true,
                )?;
                let legacy_mode = ensure_team_profile(
                    state,
                    &legacy_team_id,
                    &team_profile,
                    &actor_profile,
                    &team_snapshot,
                    true,
                )?;
                let replaced = ensure_team_actor(
                    state,
                    &legacy_team_id,
                    &legacy_actor_id,
                    &actor_role,
                    &actor_snapshot,
                    legacy_mode,
                )?;
                let registered = ensure_team_actor(
                    state,
                    &legacy_team_id,
                    &legacy_registered_id,
                    &actor_role,
                    &actor_snapshot,
                    legacy_mode,
                )?;
                let reused = ensure_team_actor(
                    state,
                    &legacy_team_id,
                    &legacy_actor_id,
                    &actor_role,
                    &actor_snapshot,
                    legacy_mode,
                )?;
                let new_mode = ensure_team_profile(
                    state,
                    &new_team_id,
                    &team_profile,
                    &actor_profile,
                    &team_snapshot,
                    true,
                )?;
                let snapshotted = ensure_team_actor(
                    state,
                    &new_team_id,
                    &new_actor_id,
                    &actor_role,
                    &actor_snapshot,
                    new_mode,
                )?;
                Ok((
                    primary,
                    legacy_mode,
                    replaced,
                    registered,
                    reused,
                    new_mode,
                    snapshotted,
                ))
            })
            .unwrap();
        assert_eq!(result.1, ProfileMode::Legacy);
        assert_eq!(result.2, result.4);
        assert_eq!(result.5, ProfileMode::Snapshotted);

        let (_, supervisor, _) = switched.store.load().unwrap();
        assert!(
            supervisor
                .actor(&result.0.actor_id)
                .unwrap()
                .profile
                .is_none()
        );
        assert!(supervisor.team(&legacy_team_id).unwrap().profile.is_none());
        assert!(
            supervisor
                .actor(&result.2.actor_id)
                .unwrap()
                .profile
                .is_none()
        );
        assert!(
            supervisor
                .actor(&result.3.actor_id)
                .unwrap()
                .profile
                .is_none()
        );
        assert_eq!(
            supervisor.team(&new_team_id).unwrap().profile.as_ref(),
            Some(&team_snapshot)
        );
        assert_eq!(
            supervisor
                .actor(&result.6.actor_id)
                .unwrap()
                .profile
                .as_ref(),
            Some(&actor_snapshot)
        );
        switched
            .actor_profile(supervisor.actor(&result.0.actor_id).unwrap())
            .unwrap();
        switched
            .actor_profile(supervisor.actor(&result.2.actor_id).unwrap())
            .unwrap();
        assert!(
            switched
                .select_request_actor(&supervisor, supervisor.team(&legacy_team_id).unwrap())
                .is_ok()
        );

        switched
            .store
            .upsert_session(&SessionRecord {
                actor_id: legacy_actor_id.to_string(),
                team_id: Some(legacy_team_id.to_string()),
                working_directory: linked,
                backend: "fake".to_owned(),
                runtime: Some("fixture-runtime".to_owned()),
                external_id: Some("fake-profile-migration".to_owned()),
                resume_token: Some("fake-profile-migration-pane".to_owned()),
                status: "idle".to_owned(),
                launch_key: "launch-profile-migration".to_owned(),
                updated_at_ms: 2,
                row_revision: 0,
            })
            .unwrap();
        let reconcile = switched.reconcile().unwrap();
        assert_eq!(reconcile["complete"], false);
        assert_eq!(reconcile["actors_marked_online"], 0);
        assert_eq!(reconcile["failures"][0]["phase"], "session_validation");
        assert!(
            reconcile["failures"][0]["error"]
                .as_str()
                .unwrap()
                .contains("fixture-runtime")
        );

        switched
            .store
            .mutate("test.stale_profileless_primary", &json!({}), 3, |state| {
                state
                    .set_actor_status(&result.0, ActorStatus::Stale)
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        let mut incompatible = settings;
        incompatible
            .agent_profiles
            .get_mut(LEGACY_IMPLEMENTATION_PROFILE)
            .unwrap()
            .capabilities
            .insert("review".to_owned());
        incompatible
            .agent_profiles
            .get_mut("primary")
            .unwrap()
            .capabilities
            .insert("review".to_owned());
        let incompatible = ControlPlane::open(incompatible).unwrap();
        let (_, supervisor, _) = incompatible.store.load().unwrap();
        let primary_error = incompatible
            .actor_profile(supervisor.actor(&primary_id).unwrap())
            .unwrap_err();
        assert_eq!(primary_error.code, "actor_profile_mismatch");
        let implementation_error = incompatible
            .actor_profile(supervisor.actor(&legacy_actor_id).unwrap())
            .unwrap_err();
        assert_eq!(implementation_error.code, "actor_profile_mismatch");
        let selection_error = incompatible
            .select_request_actor(&supervisor, supervisor.team(&legacy_team_id).unwrap())
            .unwrap_err();
        assert_eq!(selection_error.code, "actor_profile_mismatch");
        let reconcile = incompatible.reconcile().unwrap();
        assert_eq!(reconcile["complete"], false);
        assert_eq!(reconcile["failures"][0]["phase"], "session_validation");
        assert!(
            reconcile["failures"][0]["error"]
                .as_str()
                .unwrap()
                .contains("profileless legacy")
        );
        let incompatible_primary = incompatible.primary_profile().unwrap().clone();
        let incompatible_role = incompatible_primary.actor_role().unwrap();
        let incompatible_snapshot = incompatible_primary.snapshot().unwrap();
        let activation_error = incompatible
            .store
            .mutate("test.reject_profile_upgrade", &json!({}), 4, |state| {
                activate_primary_for_profile(
                    state,
                    &primary_id,
                    &incompatible_primary,
                    &incompatible_role,
                    &incompatible_snapshot,
                    true,
                )
            })
            .unwrap_err();
        assert_eq!(activation_error.code, "actor_profile_mismatch");
        let (_, supervisor, _) = incompatible.store.load().unwrap();
        assert!(supervisor.active_primary().is_none());
        assert!(supervisor.actor(&primary_id).unwrap().profile.is_none());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn missing_session_wake_failure_retries_without_duplicate_request_state() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        fs::create_dir(&root).unwrap();
        run_git(&root, &["init", "-q"]);
        run_git(&root, &["config", "user.name", "AGSV Test"]);
        run_git(
            &root,
            &["config", "user.email", "agsv-test@example.invalid"],
        );
        fs::write(root.join("README.md"), "base\n").unwrap();
        run_git(&root, &["add", "README.md"]);
        run_git(&root, &["commit", "-q", "-m", "base"]);

        let settings = profiled_settings(
            root.clone(),
            temporary.path().join("state"),
            "codex",
            2,
            "least_wip",
        );
        let plane = ControlPlane::open(settings).unwrap();
        let team_id = TeamId::new("team-retry").unwrap();
        let first_id = ActorId::new("impl-retry-1").unwrap();
        let second_id = ActorId::new("impl-retry-2").unwrap();
        let team_profile = plane.selected_team_profile().unwrap().snapshot().unwrap();
        let actor_profile = plane.selected_team_actor_profile().unwrap().clone();
        let actor_role = actor_profile.actor_role().unwrap();
        let actor_snapshot = actor_profile.snapshot().unwrap();
        let (_, (first_ref, second_ref)) = plane
            .store
            .mutate("test.setup", &json!({}), 1, |state| {
                let primary = state
                    .activate_primary(ActorId::new("primary-test").unwrap())
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&primary, TimestampMillis(1))
                    .map_err(super::ControlError::core)?;
                state
                    .create_team_with_profile(team_id.clone(), team_profile.clone())
                    .map_err(super::ControlError::core)?;
                let first = state
                    .register_implementation_with_profile(
                        &team_id,
                        first_id.clone(),
                        actor_role.clone(),
                        actor_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&first, TimestampMillis(1))
                    .map_err(super::ControlError::core)?;
                let second = state
                    .register_implementation_with_profile(
                        &team_id,
                        second_id.clone(),
                        actor_role.clone(),
                        actor_snapshot.clone(),
                    )
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&second, TimestampMillis(1))
                    .map_err(super::ControlError::core)?;
                Ok((first, second))
            })
            .unwrap();
        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: second_ref.actor_id.to_string(),
                team_id: Some(team_id.to_string()),
                working_directory: root.clone(),
                backend: "fake".to_owned(),
                runtime: Some(plane.selected_team_runtime().unwrap().id().to_string()),
                external_id: Some("fake-second-worker".to_owned()),
                resume_token: Some("fake-second-pane".to_owned()),
                status: "idle".to_owned(),
                launch_key: "test-second-launch".to_owned(),
                updated_at_ms: 2,
                row_revision: 0,
            })
            .unwrap();
        let request = json!({
            "team": team_id,
            "title": "retry wake-up",
            "body": "deliver exactly once and retry only the wake-up",
            "operation_id": "request-retry-wake-up",
        });

        let error = plane.request_create(&request).unwrap_err();
        assert_eq!(error.code, "session_not_found");
        let (_, after_failure, _) = plane.store.load().unwrap();
        assert_eq!(after_failure.snapshot().requests.len(), 1);
        assert_eq!(after_failure.snapshot().deliveries.len(), 1);
        assert_eq!(
            after_failure.snapshot().requests[0]
                .assignment
                .as_ref()
                .unwrap()
                .actor,
            first_ref
        );
        assert_eq!(
            after_failure.snapshot().deliveries[0].envelope.target,
            MessageTarget::Actor(first_id.clone())
        );

        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: first_ref.actor_id.to_string(),
                team_id: Some(team_id.to_string()),
                working_directory: root,
                backend: "fake".to_owned(),
                runtime: Some(plane.selected_team_runtime().unwrap().id().to_string()),
                external_id: Some("fake-worker".to_owned()),
                resume_token: Some("fake-pane".to_owned()),
                status: "idle".to_owned(),
                launch_key: "test-launch".to_owned(),
                updated_at_ms: 2,
                row_revision: 0,
            })
            .unwrap();

        let retried = plane.request_create(&request).unwrap();
        assert_eq!(retried["outcome"], "duplicate");
        let (_, after_retry, _) = plane.store.load().unwrap();
        assert_eq!(after_retry.snapshot().requests.len(), 1);
        assert_eq!(after_retry.snapshot().deliveries.len(), 1);
        assert_eq!(
            after_retry.snapshot().deliveries[0].envelope.target,
            MessageTarget::Actor(first_id)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn primary_wake_failure_retries_without_duplicate_protocol_state() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        fs::create_dir(&root).unwrap();
        run_git(&root, &["init", "-q"]);
        run_git(&root, &["config", "user.name", "AGSV Test"]);
        run_git(
            &root,
            &["config", "user.email", "agsv-test@example.invalid"],
        );
        fs::write(root.join("README.md"), "base\n").unwrap();
        run_git(&root, &["add", "README.md"]);
        run_git(&root, &["commit", "-q", "-m", "base"]);
        let settings = legacy_settings(root.clone(), temporary.path().join("state"), "codex");
        let plane = ControlPlane::open(settings).unwrap();
        let team_id = TeamId::new("team-primary-wake").unwrap();
        let (_, (primary, implementation)) = plane
            .store
            .mutate("test.setup", &json!({}), 1, |state| {
                let primary = state
                    .activate_primary(ActorId::new("primary-test").unwrap())
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&primary, TimestampMillis(1))
                    .map_err(super::ControlError::core)?;
                state
                    .create_team(team_id.clone())
                    .map_err(super::ControlError::core)?;
                let implementation = state
                    .register_implementation(&team_id, ActorId::new("impl-primary-wake-1").unwrap())
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&implementation, TimestampMillis(1))
                    .map_err(super::ControlError::core)?;
                Ok((primary, implementation))
            })
            .unwrap();
        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: implementation.actor_id.to_string(),
                team_id: Some(team_id.to_string()),
                working_directory: root,
                backend: "fake".to_owned(),
                runtime: Some(plane.selected_team_runtime().unwrap().id().to_string()),
                external_id: Some("fake-worker".to_owned()),
                resume_token: Some("fake-worker-pane".to_owned()),
                status: "idle".to_owned(),
                launch_key: "test-launch".to_owned(),
                updated_at_ms: 2,
                row_revision: 0,
            })
            .unwrap();
        let created = plane
            .request_create(&json!({
                "team": team_id,
                "title": "exercise reverse notification",
                "body": "send durable progress to Primary",
                "operation_id": "request-primary-wake",
            }))
            .unwrap();
        let request_id = RequestId::new(
            created["request"]["request_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let envelope = super::request_envelope(
            &supervisor,
            &request_id,
            implementation,
            MessageTarget::Primary,
            Message::Progress(ProgressUpdate {
                summary: "needs Primary attention".to_owned(),
                percent_complete: Some(50),
                evidence: Vec::new(),
            }),
            MessageId::new("message-primary-wake").unwrap(),
        )
        .unwrap()
        .0;
        let (_, outcome) = plane
            .store
            .mutate("message.sent", &json!({}), 3, |state| {
                apply_envelope(state, envelope.clone())
            })
            .unwrap();
        assert_eq!(outcome, ApplyOutcome::Applied);

        let error = plane
            .notify_target(&MessageTarget::Primary, "read your durable inbox")
            .unwrap_err();
        assert_eq!(error.code, "session_not_found");
        let (_, after_failure, _) = plane.store.load().unwrap();
        assert_eq!(after_failure.snapshot().deliveries.len(), 2);

        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: primary.actor_id.to_string(),
                team_id: None,
                working_directory: plane.identity.root().to_path_buf(),
                backend: "fake".to_owned(),
                runtime: None,
                external_id: Some("fake-stale-primary".to_owned()),
                resume_token: None,
                status: "idle".to_owned(),
                launch_key: "primary-binding:999:stale".to_owned(),
                updated_at_ms: 3,
                row_revision: 0,
            })
            .unwrap();
        let error = plane
            .notify_target(&MessageTarget::Primary, "read your durable inbox")
            .unwrap_err();
        assert_eq!(error.code, "stale_notification_endpoint");

        plane.ensure_primary_notification_session(&primary).unwrap();
        let (_, outcome) = plane
            .store
            .mutate("message.sent", &json!({}), 4, |state| {
                apply_envelope(state, envelope.clone())
            })
            .unwrap();
        assert_eq!(outcome, ApplyOutcome::Duplicate);
        plane
            .notify_target(&MessageTarget::Primary, "read your durable inbox")
            .unwrap();
        let (_, after_retry, _) = plane.store.load().unwrap();
        assert_eq!(after_retry.snapshot().deliveries.len(), 2);
        let session = plane
            .store
            .session(primary.actor_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(session.team_id, None);
        assert_eq!(session.backend, "fake");
        assert!(
            session
                .external_id
                .as_deref()
                .is_some_and(|value| value.starts_with("fake-primary-"))
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn reconcile_recovers_through_the_persisted_backend() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        fs::create_dir(&root).unwrap();
        run_git(&root, &["init", "-q"]);
        run_git(&root, &["config", "user.name", "AGSV Test"]);
        run_git(
            &root,
            &["config", "user.email", "agsv-test@example.invalid"],
        );
        fs::write(root.join("README.md"), "base\n").unwrap();
        run_git(&root, &["add", "README.md"]);
        run_git(&root, &["commit", "-q", "-m", "base"]);
        let implementation_worktree = temporary.path().join("implementation-worktree");
        run_git(
            &root,
            &[
                "worktree",
                "add",
                "--detach",
                implementation_worktree.to_str().unwrap(),
                "HEAD",
            ],
        );
        let implementation_worktree = fs::canonicalize(implementation_worktree).unwrap();

        let mut settings = legacy_settings(root, temporary.path().join("state"), "codex");
        settings.backend = "herdr".to_owned();
        let plane = ControlPlane::open(settings).unwrap();
        let team_id = TeamId::new("team-reconcile").unwrap();
        let actor_id = ActorId::new("impl-reconcile-1").unwrap();
        let (_, actor_ref) = plane
            .store
            .mutate("test.setup", &json!({}), 1, |state| {
                let primary = state
                    .activate_primary(ActorId::new("primary-test").unwrap())
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&primary, TimestampMillis(1))
                    .map_err(super::ControlError::core)?;
                state
                    .create_team(team_id.clone())
                    .map_err(super::ControlError::core)?;
                let actor = state
                    .register_implementation(&team_id, actor_id.clone())
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&actor, TimestampMillis(1))
                    .map_err(super::ControlError::core)?;
                Ok(actor)
            })
            .unwrap();
        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: actor_ref.actor_id.to_string(),
                team_id: Some(team_id.to_string()),
                working_directory: implementation_worktree,
                backend: "fake".to_owned(),
                runtime: Some(plane.selected_team_runtime().unwrap().id().to_string()),
                external_id: None,
                resume_token: Some("persisted-fake-checkpoint".to_owned()),
                status: "launch_failed".to_owned(),
                launch_key: "persisted-fake-reconcile".to_owned(),
                updated_at_ms: 2,
                row_revision: 0,
            })
            .unwrap();

        let reconciled = plane.reconcile().unwrap();
        assert_eq!(reconciled["sessions_checked"], 1);
        assert_eq!(reconciled["actors_marked_online"], 1);
        assert_eq!(reconciled["complete"], true);
        assert_eq!(reconciled["failures"].as_array().unwrap().len(), 0);
        let session = plane
            .store
            .session(actor_ref.actor_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(plane.sessions.configured_backend(), "herdr");
        assert_eq!(session.backend, "fake");
        assert_eq!(session.status, "idle");
        assert!(
            session
                .external_id
                .as_deref()
                .is_some_and(|value| value.starts_with("fake-"))
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn checkpointed_reconcile_skips_failing_layout_lookup_without_a_presentation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        fs::create_dir(&root).unwrap();
        run_git(&root, &["init", "-q"]);
        run_git(&root, &["config", "user.name", "AGSV Test"]);
        run_git(
            &root,
            &["config", "user.email", "agsv-test@example.invalid"],
        );
        fs::write(root.join("README.md"), "base\n").unwrap();
        run_git(&root, &["add", "README.md"]);
        run_git(&root, &["commit", "-q", "-m", "base"]);
        let implementation_worktree = temporary.path().join("implementation-worktree");
        run_git(
            &root,
            &[
                "worktree",
                "add",
                "--detach",
                implementation_worktree.to_str().unwrap(),
                "HEAD",
            ],
        );
        let implementation_worktree = fs::canonicalize(implementation_worktree).unwrap();

        let settings = legacy_settings(root.clone(), temporary.path().join("state"), "codex");
        let mut plane = ControlPlane::open(settings).unwrap();
        plane.sessions = SessionDriver::checkpoint_recovery_test_driver();
        let team_id = TeamId::new("team-checkpoint-layout").unwrap();
        let actor_id = ActorId::new("impl-checkpoint-layout-1").unwrap();
        let (_, (primary, actor_ref)) = plane
            .store
            .mutate("test.setup", &json!({}), 1, |state| {
                let primary = state
                    .activate_primary(ActorId::new("primary-checkpoint-layout").unwrap())
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&primary, TimestampMillis(1))
                    .map_err(super::ControlError::core)?;
                state
                    .create_team(team_id.clone())
                    .map_err(super::ControlError::core)?;
                let actor = state
                    .register_implementation(&team_id, actor_id.clone())
                    .map_err(super::ControlError::core)?;
                state
                    .heartbeat(&actor, TimestampMillis(1))
                    .map_err(super::ControlError::core)?;
                Ok((primary, actor))
            })
            .unwrap();
        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: primary.actor_id.to_string(),
                team_id: None,
                working_directory: root,
                backend: LAYOUT_FAILURE_BACKEND_ID.to_owned(),
                runtime: None,
                external_id: Some("primary-layout-anchor".to_owned()),
                resume_token: Some("primary-layout-anchor".to_owned()),
                status: "idle".to_owned(),
                launch_key: "primary-layout-anchor".to_owned(),
                updated_at_ms: 2,
                row_revision: 0,
            })
            .unwrap();
        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: actor_ref.actor_id.to_string(),
                team_id: Some(team_id.to_string()),
                working_directory: implementation_worktree,
                backend: LAYOUT_FAILURE_BACKEND_ID.to_owned(),
                runtime: Some(plane.selected_team_runtime().unwrap().id().to_string()),
                external_id: None,
                resume_token: Some("persisted-layout-checkpoint".to_owned()),
                status: "launch_failed".to_owned(),
                launch_key: "persisted-layout-recovery".to_owned(),
                updated_at_ms: 3,
                row_revision: 0,
            })
            .unwrap();
        assert!(
            plane
                .store
                .session_presentation(actor_ref.actor_id.as_str())
                .unwrap()
                .is_none()
        );
        let lookup_error = plane
            .observed_group_sequences(LAYOUT_FAILURE_BACKEND_ID)
            .unwrap_err();
        assert_eq!(lookup_error.code, "session_backend_error");

        let reconciled = plane.reconcile().unwrap();
        assert_eq!(reconciled["sessions_checked"], 2);
        assert_eq!(reconciled["complete"], true);
        assert_eq!(reconciled["failures"].as_array().unwrap().len(), 0);
        assert_eq!(plane.sessions.configured_backend(), "fake");
        let session = plane
            .store
            .session(actor_ref.actor_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(session.backend, LAYOUT_FAILURE_BACKEND_ID);
        assert_eq!(session.status, "idle");
        assert_eq!(
            session.resume_token.as_deref(),
            Some("persisted-layout-checkpoint")
        );
        assert!(
            plane
                .store
                .session_presentation(actor_ref.actor_id.as_str())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ordinary_team_close_does_not_deadlock_after_integration_completion() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("completed-team-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-completed-close"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-completed-close");
        create_profiled_test_team(&plane, &attached, "create-completed-close-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let completed_request_id =
            create_completed_test_request(&plane, &team_id, &attached, "ordinary-close-completed");

        let closed = plane
            .team_close(&json!({
                "id": team_id,
                "operation_id": "close-team-after-completed-request",
            }))
            .unwrap();

        assert_eq!(closed["status"], "closed");
        assert_eq!(closed["complete"], true);
        assert_eq!(closed["blocking_request_ids_at_request"], json!([]));
        let (_, supervisor, _) = plane.store.load().unwrap();
        assert_eq!(
            supervisor.request(&completed_request_id).unwrap().status,
            agsv_protocol::RequestStatus::Completed
        );
        assert_eq!(
            supervisor.team(&team_id).unwrap().status,
            TeamStatus::Closed
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn closed_team_name_recreates_once_after_preparation_crash_and_preserves_generation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("recreated-team-worktree");
        let next_attached = temporary.path().join("recreated-team-worktree-two");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-team-recreation"));
        let settings = profiled_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-team-recreation");
        plane
            .team_create(&json!({
                "name": "workers",
                "working_directory": attached,
                "orchestrators": 1,
                "purpose": "generation one purpose",
                "operation_id": "create-team-generation-one",
            }))
            .unwrap();
        let team_id = TeamId::new("team-workers").unwrap();
        let old_request = create_completed_test_request(
            &plane,
            &team_id,
            &attached,
            "complete-team-generation-one",
        );
        let (_, before_close, _) = plane.store.load().unwrap();
        let old_team_epoch = before_close.team(&team_id).unwrap().epoch;
        let old_actor = before_close
            .request(&old_request)
            .unwrap()
            .assignment
            .as_ref()
            .unwrap()
            .actor
            .clone();
        let old_message_id = before_close
            .snapshot()
            .deliveries
            .into_iter()
            .find(|delivery| delivery.envelope.request_id.as_ref() == Some(&old_request))
            .unwrap()
            .envelope
            .message_id;
        plane
            .store
            .mutate(
                "test.actor_event_generation_one",
                &json!({ "actor_id": old_actor.actor_id }),
                now_ms().unwrap(),
                |_| Ok(()),
            )
            .unwrap();
        plane
            .store
            .mutate(
                "test.message_event_generation_one",
                &json!({ "message_id": old_message_id }),
                now_ms().unwrap(),
                |_| Ok(()),
            )
            .unwrap();
        plane
            .team_close(&json!({
                "id": team_id,
                "operation_id": "close-team-generation-one",
            }))
            .unwrap();
        run_git(
            &root,
            &[
                "worktree",
                "add",
                "--detach",
                next_attached.to_str().unwrap(),
                "HEAD",
            ],
        );

        let recreate = json!({
            "name": "workers",
            "working_directory": next_attached,
            "orchestrators": 1,
            "purpose": "generation two purpose",
            "operation_id": "create-team-generation-two",
        });
        plane.arm_test_crash("team_recreation_prepare");
        let interrupted = plane.team_create(&recreate).unwrap_err();
        assert_eq!(
            interrupted.code, "simulated_team_recreation_prepare_crash",
            "removing the preparation boundary leaves its retry behavior untested"
        );
        let (_, still_closed, _) = plane.store.load().unwrap();
        assert_eq!(still_closed.team(&team_id).unwrap().epoch, old_team_epoch);
        assert_eq!(
            still_closed.team(&team_id).unwrap().status,
            TeamStatus::Closed
        );
        assert_eq!(
            plane
                .store
                .archived_team_generation(&team_id, old_team_epoch)
                .unwrap()
                .unwrap()
                .status,
            TeamStatus::Closed
        );

        let created = plane.team_create(&recreate).unwrap();
        let next_team_epoch = old_team_epoch.checked_next().unwrap();
        assert_eq!(created["team_epoch"], json!(next_team_epoch));
        assert_eq!(created["previous_team_epoch"], json!(old_team_epoch));
        let (_, recreated, _) = plane.store.load().unwrap();
        let team = recreated.team(&team_id).unwrap();
        assert_eq!(team.epoch, next_team_epoch);
        assert_eq!(team.status, TeamStatus::Active);
        let actor = recreated.actor(&old_actor.actor_id).unwrap();
        assert_eq!(actor.epoch, old_actor.actor_epoch.checked_next().unwrap());
        assert!(team.actors.contains(&actor.actor_id));
        assert_eq!(runtime.launch_count(), 2);
        let current_session = plane
            .store
            .session(actor.actor_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(current_session.status, "idle");
        assert_eq!(
            current_session.working_directory,
            fs::canonicalize(&next_attached).unwrap()
        );
        assert_eq!(
            plane
                .store
                .team_purpose(team_id.as_str())
                .unwrap()
                .as_deref(),
            Some("generation two purpose")
        );
        assert_eq!(
            plane.team_create(&recreate).unwrap(),
            created,
            "removing operation-result replay would advance the generation twice"
        );
        assert_eq!(runtime.launch_count(), 2);
        let new_request = plane
            .request_create(&json!({
                "team": team_id,
                "title": "generation two request",
                "operation_id": "request-team-generation-two",
            }))
            .unwrap();
        assert_eq!(new_request["request"]["team_epoch"], json!(next_team_epoch));
        let (_, final_state, _) = plane.store.load().unwrap();
        let new_request_id: RequestId =
            serde_json::from_value(new_request["request"]["request_id"].clone()).unwrap();
        let new_message_id = final_state
            .snapshot()
            .deliveries
            .into_iter()
            .find(|delivery| delivery.envelope.request_id.as_ref() == Some(&new_request_id))
            .unwrap()
            .envelope
            .message_id;
        plane
            .store
            .mutate(
                "test.actor_event_generation_two",
                &json!({ "actor_id": actor.actor_id }),
                now_ms().unwrap(),
                |_| Ok(()),
            )
            .unwrap();
        plane
            .store
            .mutate(
                "test.message_event_generation_two",
                &json!({ "message_id": new_message_id }),
                now_ms().unwrap(),
                |_| Ok(()),
            )
            .unwrap();
        assert_eq!(
            final_state.request(&old_request).unwrap().team_epoch,
            old_team_epoch
        );
        let shown = plane.team_show(&json!({ "id": team_id })).unwrap();
        let prior = shown["prior_generations"].as_array().unwrap();
        assert_eq!(prior.len(), 1);
        assert_eq!(prior[0]["team"]["epoch"], json!(old_team_epoch));
        assert_eq!(prior[0]["team"]["status"], "closed");
        assert_eq!(prior[0]["actors"][0]["actor"], json!(old_actor));
        assert_eq!(prior[0]["actors"][0]["team_epoch"], json!(old_team_epoch));
        assert_eq!(prior[0]["metadata"]["purpose"], "generation one purpose");
        assert_eq!(
            prior[0]["worktree"]["working_directory"],
            json!(fs::canonicalize(&attached).unwrap()),
            "removing generation-keyed worktree history would rewrite the prior path"
        );
        assert!(prior[0]["activity"]["activity_sequence"].as_u64().unwrap() > 0);
        assert_eq!(
            prior[0]["activity"]["nonterminal_request_count"], 0,
            "removing the archived activity head would make the generation boundary unreportable"
        );
        assert_eq!(prior[0]["activity"]["team_epoch"], json!(old_team_epoch));
        assert_eq!(shown["actors"][0]["team_epoch"], json!(next_team_epoch));
        assert_eq!(
            shown["team"]["activity"]["team_epoch"],
            json!(next_team_epoch)
        );

        let events = plane.events(&json!({ "limit": 100 })).unwrap();
        let control_events = events["control_events"].as_array().unwrap();
        for event in control_events.iter().filter(|event| {
            event["detail"]["team_id"] == json!(team_id)
                || event["detail"]["team"] == json!(team_id)
        }) {
            assert!(
                event["detail"]["team_epoch"].as_u64().is_some(),
                "removing automatic control-event attribution leaves a team fact ambiguous: {event}"
            );
        }
        assert!(control_events.iter().any(|event| {
            event["operation"] == "team.created"
                && event["detail"]["team_epoch"] == json!(old_team_epoch)
        }));
        for (operation, epoch) in [
            ("test.actor_event_generation_one", old_team_epoch),
            ("test.message_event_generation_one", old_team_epoch),
            ("test.actor_event_generation_two", next_team_epoch),
            ("test.message_event_generation_two", next_team_epoch),
        ] {
            assert!(
                control_events.iter().any(|event| {
                    event["operation"] == operation
                        && event["detail"]["team_id"] == json!(team_id)
                        && event["detail"]["team_epoch"] == json!(epoch)
                }),
                "removing actor/message attribution leaves {operation} ambiguous"
            );
        }
        assert!(control_events.iter().any(|event| {
            event["operation"] == "team.closed"
                && event["detail"]["team_epoch"] == json!(old_team_epoch)
        }));
        assert!(control_events.iter().any(|event| {
            event["operation"] == "team.created"
                && event["detail"]["team_epoch"] == json!(next_team_epoch)
        }));
        let protocol_events = events["protocol_events"].as_array().unwrap();
        assert!(
            protocol_events
                .iter()
                .any(|event| event["team_epoch"] == json!(old_team_epoch))
        );
        assert!(
            protocol_events
                .iter()
                .any(|event| event["team_epoch"] == json!(next_team_epoch))
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn team_close_refuses_unread_requestless_and_request_directives_until_ack() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("disposed-directive-team-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-disposed-directive-close",
        ));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        let primary = activate_test_primary(&plane, "primary-disposed-directive-close");
        let observed_at = super::now_ms().unwrap();
        plane
            .store
            .mutate(
                "test.disposed_directive_primary_current",
                &json!({}),
                observed_at,
                |state| {
                    state
                        .heartbeat(&primary, TimestampMillis(observed_at))
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap();
        create_profiled_test_team(&plane, &attached, "create-disposed-directive-close-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let request_id =
            create_completed_test_request(&plane, &team_id, &attached, "disposed-directive-close");
        let (_, before_directives, _) = plane.store.load().unwrap();
        let actor_id = before_directives
            .request(&request_id)
            .unwrap()
            .assignment
            .as_ref()
            .unwrap()
            .actor
            .actor_id
            .clone();

        plane.set_test_authenticated_actor(primary.clone());
        plane
            .message_ack(&json!({
                "id": "disposed-directive-close-candidate-ready",
                "operation_id": "ack-disposed-directive-close-candidate",
            }))
            .unwrap();
        let requestless = plane
            .message_send(&json!({
                "kind": "directive",
                "to": team_id,
                "team": team_id,
                "decision": "acknowledge this decision before close",
                "rationale": "the requestless directive still expects future team action",
                "operation_id": "requestless-directive-before-close",
            }))
            .unwrap();
        let request_scoped = plane
            .message_send(&json!({
                "kind": "directive",
                "to": actor_id,
                "request": request_id,
                "decision": "acknowledge the request decision before close",
                "rationale": "request scope does not make an unread directive obsolete",
                "operation_id": "request-directive-before-close",
            }))
            .unwrap();
        let requestless_id =
            MessageId::new(requestless["message_id"].as_str().unwrap().to_owned()).unwrap();
        let request_scoped_id =
            MessageId::new(request_scoped["message_id"].as_str().unwrap().to_owned()).unwrap();

        let refused = plane
            .team_close(&json!({
                "id": team_id,
                "operation_id": "close-team-with-unread-directives",
            }))
            .unwrap_err();

        assert_eq!(refused.code, "team_close_unacknowledged_actions");
        let blockers = refused.details["unacknowledged_action_message_ids"]
            .as_array()
            .unwrap();
        assert!(blockers.contains(&json!(requestless_id.clone())));
        assert!(blockers.contains(&json!(request_scoped_id.clone())));
        let (_, before_ack, _) = plane.store.load().unwrap();
        assert_eq!(
            before_ack.team(&team_id).unwrap().status,
            TeamStatus::Active
        );

        plane.set_test_authenticated_actor(
            before_ack
                .actor(&actor_id)
                .expect("directive recipient exists")
                .actor_ref(),
        );
        for (message_id, operation_id) in [
            (&requestless_id, "ack-requestless-directive-before-close"),
            (&request_scoped_id, "ack-request-directive-before-close"),
        ] {
            plane
                .message_ack(&json!({
                    "id": message_id,
                    "operation_id": operation_id,
                }))
                .unwrap();
        }

        let closed = plane
            .team_close(&json!({
                "id": team_id,
                "operation_id": "close-team-with-unread-directives",
            }))
            .unwrap();

        assert_eq!(closed["status"], "closed");
        let disposed = closed["retired_undeliverable_message_ids"]
            .as_array()
            .unwrap();
        assert!(!disposed.contains(&json!(requestless_id.clone())));
        assert!(!disposed.contains(&json!(request_scoped_id.clone())));
        let (_, current, _) = plane.store.load().unwrap();
        assert!(
            current
                .pending_acknowledgement_message_ids_for(&actor_id)
                .is_empty()
        );
        for message_id in [requestless_id, request_scoped_id] {
            assert!(current.delivery(&message_id).is_none());
            let archived = plane
                .store
                .archived_delivery(&message_id)
                .unwrap()
                .expect("acknowledged directive is eligible for compact archival");
            assert!(archived.retired);
            assert_eq!(archived.acknowledgements.len(), 1);
            assert!(archived.undeliverable_recipients.is_empty());
        }
        plane.store.verify_archive_integrity().unwrap();
    }

    #[test]
    fn accepted_decision_close_ignores_an_already_completed_peer_request() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("completed-peer-team-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-completed-peer-close",
        ));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-completed-peer-close");
        create_profiled_test_team(&plane, &attached, "create-completed-peer-close-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let (closing_request_id, closing_candidate) = create_candidate_ready_test_request(
            &plane,
            &team_id,
            &attached,
            "decision-close-target",
        );
        let completed_peer_id = create_completed_test_request(
            &plane,
            &team_id,
            &attached,
            "decision-close-completed-peer",
        );

        let decided = plane
            .decision_submit(&json!({
                "request": closing_request_id,
                "candidate_sha": closing_candidate.sha,
                "decision": "accepted",
                "summary": "accepted after peer integration completed",
                "close_team": true,
                "operation_id": "accept-and-close-after-completed-peer",
            }))
            .unwrap();

        assert_eq!(decided["team_close"]["status"], "closed");
        assert_eq!(decided["team_close"]["complete"], true);
        let (_, supervisor, _) = plane.store.load().unwrap();
        assert_eq!(
            supervisor.request(&completed_peer_id).unwrap().status,
            agsv_protocol::RequestStatus::Completed
        );
        assert_eq!(
            supervisor.team(&team_id).unwrap().status,
            TeamStatus::Closed
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn accepted_decision_close_is_atomic_when_an_unread_directive_blocks_it() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("blocked-decision-close-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-blocked-decision-close",
        ));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        let primary = activate_test_primary(&plane, "primary-blocked-decision-close");
        let observed_at = super::now_ms().unwrap();
        plane
            .store
            .mutate(
                "test.blocked_decision_close_primary_current",
                &json!({}),
                observed_at,
                |state| {
                    state
                        .heartbeat(&primary, TimestampMillis(observed_at))
                        .map_err(super::ControlError::core)
                },
            )
            .unwrap();
        create_profiled_test_team(&plane, &attached, "create-blocked-decision-close-team");
        let team_id = TeamId::new("team-workers").unwrap();
        let (request_id, candidate) = create_candidate_ready_test_request(
            &plane,
            &team_id,
            &attached,
            "blocked-decision-close",
        );
        let (_, before_directive, _) = plane.store.load().unwrap();
        let actor_ref = before_directive
            .request(&request_id)
            .unwrap()
            .assignment
            .as_ref()
            .unwrap()
            .actor
            .clone();
        plane.set_test_authenticated_actor(primary);
        let directive = plane
            .message_send(&json!({
                "kind": "directive",
                "to": team_id,
                "team": team_id,
                "decision": "read this before accepting and closing",
                "rationale": "an action instruction cannot be discarded by the decision path",
                "operation_id": "directive-blocking-decision-close",
            }))
            .unwrap();
        let directive_id =
            MessageId::new(directive["message_id"].as_str().unwrap().to_owned()).unwrap();
        let decision_request = json!({
            "request": request_id,
            "candidate_sha": candidate.sha,
            "decision": "accepted",
            "summary": "accept only after the directive is read",
            "close_team": true,
            "operation_id": "decision-close-blocked-by-directive",
        });

        let refused = plane.decision_submit(&decision_request).unwrap_err();
        assert_eq!(refused.code, "team_close_unacknowledged_actions");
        assert_eq!(
            refused.details["unacknowledged_action_message_ids"],
            json!([directive_id.clone()])
        );
        let (_, after_refusal, _) = plane.store.load().unwrap();
        let request = after_refusal.request(&request_id).unwrap();
        assert_eq!(request.status, agsv_protocol::RequestStatus::CandidateReady);
        assert!(request.decision.is_none());
        assert!(request.integration_authorization.is_none());
        assert_eq!(
            after_refusal.team(&team_id).unwrap().status,
            TeamStatus::Active
        );
        assert!(
            after_refusal
                .delivery(&super::message_id(
                    "decision-close-blocked-by-directive",
                    "decision"
                ))
                .is_none()
        );

        plane.set_test_authenticated_actor(actor_ref);
        plane
            .message_ack(&json!({
                "id": directive_id,
                "operation_id": "ack-directive-blocking-decision-close",
            }))
            .unwrap();
        let accepted = plane.decision_submit(&decision_request).unwrap();
        assert_eq!(accepted["team_close"]["status"], "closed");
        assert_eq!(accepted["team_close"]["complete"], true);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn ordinary_team_close_crash_boundaries_reconcile_without_repeated_side_effects() {
        for (crash_point, expected_error, cleanup_before_crash) in [
            (
                "team_close_actor_stop_commit",
                "simulated_team_close_actor_stop_crash",
                false,
            ),
            (
                "team_close_worktree_cleanup",
                "simulated_team_close_worktree_cleanup_crash",
                true,
            ),
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("repository");
            let seed = temporary.path().join("seed-worktree");
            init_test_repository(&root, &seed);
            let case_id = crash_point.replace('_', "-");
            let runtime = Arc::new(FixtureRuntime::with_id(&format!(
                "fixture-runtime-{case_id}"
            )));
            let settings = profiled_settings(
                root.clone(),
                temporary.path().join("state"),
                runtime.id().as_str(),
                1,
                "first_healthy",
            );
            let plane = open_fixture_plane(settings, &runtime);
            activate_test_primary(&plane, &format!("primary-{case_id}"));
            let created = plane
                .team_create(&json!({
                    "name": "workers",
                    "orchestrators": 1,
                    "operation_id": format!("create-{case_id}"),
                }))
                .unwrap();
            let target = PathBuf::from(created["working_directory"].as_str().unwrap());
            let team_id = TeamId::new("team-workers").unwrap();
            let actor_id = ActorId::new("impl-workers-1").unwrap();
            assert!(target.exists());
            assert_eq!(runtime.launch_count(), 1);

            reset_fake_stop_count();
            plane.arm_test_crash(crash_point);
            let error = plane
                .team_close(&json!({
                    "id": team_id,
                    "operation_id": format!("close-{case_id}"),
                }))
                .unwrap_err();
            assert_eq!(error.code, expected_error);
            assert_eq!(fake_stop_count(), 1);
            assert_eq!(runtime.launch_count(), 1);
            let (_, crashed, _) = plane.store.load().unwrap();
            assert_eq!(crashed.team(&team_id).unwrap().status, TeamStatus::Closing);
            assert_eq!(
                crashed.actor(&actor_id).unwrap().status,
                ActorStatus::Stopped
            );
            assert_eq!(
                plane
                    .store
                    .session(actor_id.as_str())
                    .unwrap()
                    .unwrap()
                    .status,
                "stopped"
            );
            let crashed_worktree = plane
                .store
                .team_worktree(team_id.as_str())
                .unwrap()
                .unwrap();
            assert_eq!(
                crashed_worktree.status,
                if cleanup_before_crash {
                    TeamWorktreeStatus::Removed
                } else {
                    TeamWorktreeStatus::Active
                }
            );
            assert_eq!(target.exists(), !cleanup_before_crash);

            if cleanup_before_crash {
                let refused = plane
                    .ensure_team_directory_with_ownership(&team_id, Some(&target), false)
                    .unwrap_err();
                assert_eq!(refused.code, "team_worktree_removed");
                run_git(
                    &root,
                    &[
                        "worktree",
                        "add",
                        "--detach",
                        target.to_str().unwrap(),
                        "HEAD",
                    ],
                );
                let identity = super::WorkspaceIdentity::discover(&target).unwrap();
                assert_eq!(identity.root(), target);
                assert_eq!(identity.git_common_dir(), plane.identity.git_common_dir());
                assert_eq!(
                    plane
                        .validate_team_worktree_path(&team_id, &target)
                        .unwrap(),
                    target
                );
            }

            let recovered = plane.reconcile().unwrap();
            assert_eq!(recovered["complete"], true);
            assert_eq!(fake_stop_count(), 1);
            assert_eq!(runtime.launch_count(), 1);
            let (_, closed, _) = plane.store.load().unwrap();
            assert_eq!(closed.team(&team_id).unwrap().status, TeamStatus::Closed);
            assert_eq!(
                closed.actor(&actor_id).unwrap().status,
                ActorStatus::Stopped
            );
            let removed_worktree = plane
                .store
                .team_worktree(team_id.as_str())
                .unwrap()
                .unwrap();
            assert_eq!(removed_worktree.status, TeamWorktreeStatus::Removed);

            if cleanup_before_crash {
                assert_eq!(removed_worktree, crashed_worktree);
                assert!(target.exists());
            } else {
                assert!(!target.exists());
                let refused = plane
                    .ensure_team_directory_with_ownership(&team_id, Some(&target), false)
                    .unwrap_err();
                assert_eq!(refused.code, "team_worktree_removed");
                run_git(
                    &root,
                    &[
                        "worktree",
                        "add",
                        "--detach",
                        target.to_str().unwrap(),
                        "HEAD",
                    ],
                );
            }

            let replacement_identity = super::WorkspaceIdentity::discover(&target).unwrap();
            assert_eq!(replacement_identity.root(), target);
            assert_eq!(
                replacement_identity.git_common_dir(),
                plane.identity.git_common_dir()
            );
            let repeated = plane.reconcile().unwrap();
            assert_eq!(repeated["complete"], true);
            assert_eq!(fake_stop_count(), 1);
            assert_eq!(runtime.launch_count(), 1);
            assert!(target.exists());
            assert_eq!(
                super::WorkspaceIdentity::discover(&target)
                    .unwrap()
                    .git_common_dir(),
                plane.identity.git_common_dir()
            );
            assert_eq!(
                plane
                    .store
                    .team_worktree(team_id.as_str())
                    .unwrap()
                    .unwrap(),
                removed_worktree
            );
            let (_, repeated_state, _) = plane.store.load().unwrap();
            assert_eq!(
                repeated_state.actor(&actor_id).unwrap().status,
                ActorStatus::Stopped
            );
            assert_eq!(
                plane
                    .store
                    .session(actor_id.as_str())
                    .unwrap()
                    .unwrap()
                    .status,
                "stopped"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn deferred_team_close_names_blockers_recovers_cleanup_and_never_relaunches() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("attached-team-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-team-close-drain"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-team-close-drain");
        create_profiled_test_team(&plane, &attached, "create-team-close-drain");
        let team_id = TeamId::new("team-workers").unwrap();
        let actor_id = ActorId::new("impl-workers-1").unwrap();
        let created = plane
            .request_create(&json!({
                "team": team_id,
                "title": "finish before close",
                "operation_id": "create-team-close-blocker",
            }))
            .unwrap();
        let request_id = RequestId::new(
            created["request"]["request_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap();

        let blocked = plane
            .team_close(&json!({
                "id": team_id,
                "when_idle": false,
                "operation_id": "close-blocked-team-now",
            }))
            .unwrap_err();
        assert_eq!(blocked.code, "team_close_blocked");
        assert_eq!(blocked.details["blocking_request_ids"], json!([request_id]));

        let deferred = plane
            .team_close(&json!({
                "id": team_id,
                "when_idle": true,
                "operation_id": "close-blocked-team-when-idle",
            }))
            .unwrap();
        assert_eq!(deferred["status"], "closing");
        assert_eq!(deferred["complete"], false);
        assert_eq!(deferred["deferred"], true);
        assert_eq!(deferred["blocking_request_ids"], json!([request_id]));
        let new_work = plane
            .request_create(&json!({
                "team": team_id,
                "title": "must not be assigned",
                "operation_id": "request-after-close-intent",
            }))
            .unwrap_err();
        assert_eq!(new_work.code, "team_inactive");

        plane
            .request_cancel(&json!({
                "id": request_id,
                "reason": "team close may now drain",
                "operation_id": "cancel-team-close-blocker",
            }))
            .unwrap();
        let (_, before_recovery, _) = plane.store.load().unwrap();
        let actor_ref = before_recovery.actor(&actor_id).unwrap().actor_ref();
        plane
            .store
            .mutate("test.team_close_domain_stopped", &json!({}), 4, |state| {
                state
                    .set_actor_status(&actor_ref, ActorStatus::Stopped)
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        assert_eq!(
            plane
                .store
                .session(actor_id.as_str())
                .unwrap()
                .unwrap()
                .status,
            "idle"
        );

        reset_fake_stop_count();
        let recovered = plane.reconcile().unwrap();
        assert_eq!(recovered["complete"], true);
        assert_eq!(fake_stop_count(), 1);
        let (_, closed, _) = plane.store.load().unwrap();
        assert_eq!(closed.team(&team_id).unwrap().status, TeamStatus::Closed);
        assert_eq!(
            closed.actor(&actor_id).unwrap().status,
            ActorStatus::Stopped
        );
        assert_eq!(
            plane
                .store
                .session(actor_id.as_str())
                .unwrap()
                .unwrap()
                .status,
            "stopped"
        );
        let worktree = plane
            .store
            .team_worktree(team_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(worktree.ownership, TeamWorktreeOwnership::Attached);
        assert_eq!(worktree.status, TeamWorktreeStatus::AttachedNotOwned);
        assert!(attached.exists());
        assert_eq!(runtime.launch_count(), 1);

        let repeated = plane.reconcile().unwrap();
        assert_eq!(repeated["complete"], true);
        assert_eq!(fake_stop_count(), 1);
        assert_eq!(runtime.launch_count(), 1);
        let shown = plane.team_show(&json!({ "id": team_id })).unwrap();
        assert_eq!(shown["team"]["status"], "closed");
        assert_eq!(shown["team"]["effective_desired_instances"], 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn accepted_decision_can_close_team_and_audit_candidate_outcomes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let attached = temporary.path().join("decision-team-worktree");
        init_test_repository(&root, &attached);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-decision-close"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-decision-close");
        create_profiled_test_team(&plane, &attached, "create-decision-close");
        let team_id = TeamId::new("team-workers").unwrap();
        let created = plane
            .request_create(&json!({
                "team": team_id,
                "title": "candidate closes its team",
                "operation_id": "create-decision-close-request",
            }))
            .unwrap();
        let request_id = RequestId::new(
            created["request"]["request_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let request = supervisor.request(&request_id).unwrap();
        let actor_ref = request.assignment.as_ref().unwrap().actor.clone();
        let actor = supervisor.actor(&actor_ref.actor_id).unwrap();
        let candidate = Candidate {
            request_id: request_id.clone(),
            team_id: team_id.clone(),
            sha: super::git_sha_for(&test_git(), &attached).unwrap(),
            created_by: actor_ref.clone(),
            created_by_profile: actor.profile.as_ref().map(|profile| profile.name.clone()),
        };
        let envelope = super::request_envelope(
            &supervisor,
            &request_id,
            actor_ref,
            MessageTarget::Primary,
            Message::CandidateReady(CandidateReady {
                candidate: candidate.clone(),
                summary: "candidate is ready".to_owned(),
                evidence: Vec::new(),
            }),
            MessageId::new("message-decision-close-candidate").unwrap(),
        )
        .unwrap()
        .0;
        plane
            .store
            .mutate("test.candidate_ready", &json!({}), 3, |state| {
                apply_envelope(state, envelope.clone())
            })
            .unwrap();

        plane
            .decision_submit(&json!({
                "request": request_id,
                "candidate_sha": candidate.sha,
                "decision": "rejected",
                "summary": "one fix cycle is required",
                "operation_id": "reject-first-decision-close-candidate",
            }))
            .unwrap();
        fs::write(attached.join("candidate-v2.txt"), "replacement candidate\n").unwrap();
        run_git(&attached, &["add", "candidate-v2.txt"]);
        run_git(&attached, &["commit", "-q", "-m", "replacement candidate"]);
        let (_, supervisor, _) = plane.store.load().unwrap();
        let request = supervisor.request(&request_id).unwrap();
        let actor_ref = request.assignment.as_ref().unwrap().actor.clone();
        let actor = supervisor.actor(&actor_ref.actor_id).unwrap();
        let replacement_candidate = Candidate {
            request_id: request_id.clone(),
            team_id: team_id.clone(),
            sha: super::git_sha_for(&test_git(), &attached).unwrap(),
            created_by: actor_ref.clone(),
            created_by_profile: actor.profile.as_ref().map(|profile| profile.name.clone()),
        };
        let replacement_envelope = super::request_envelope(
            &supervisor,
            &request_id,
            actor_ref,
            MessageTarget::Primary,
            Message::CandidateReady(CandidateReady {
                candidate: replacement_candidate.clone(),
                summary: "replacement candidate is ready".to_owned(),
                evidence: Vec::new(),
            }),
            MessageId::new("message-decision-close-replacement-candidate").unwrap(),
        )
        .unwrap()
        .0;
        plane
            .store
            .mutate("test.replacement_candidate_ready", &json!({}), 4, |state| {
                apply_envelope(state, replacement_envelope.clone())
            })
            .unwrap();

        let other_created = plane
            .request_create(&json!({
                "team": team_id,
                "title": "already authorized peer request",
                "operation_id": "create-peer-authorized-request",
            }))
            .unwrap();
        let other_request_id = RequestId::new(
            other_created["request"]["request_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap();
        let (_, supervisor, _) = plane.store.load().unwrap();
        let other_request = supervisor.request(&other_request_id).unwrap();
        let other_actor_ref = other_request.assignment.as_ref().unwrap().actor.clone();
        let other_actor = supervisor.actor(&other_actor_ref.actor_id).unwrap();
        let other_candidate = Candidate {
            request_id: other_request_id.clone(),
            team_id: team_id.clone(),
            sha: super::git_sha_for(&test_git(), &attached).unwrap(),
            created_by: other_actor_ref.clone(),
            created_by_profile: other_actor
                .profile
                .as_ref()
                .map(|profile| profile.name.clone()),
        };
        let other_envelope = super::request_envelope(
            &supervisor,
            &other_request_id,
            other_actor_ref,
            MessageTarget::Primary,
            Message::CandidateReady(CandidateReady {
                candidate: other_candidate.clone(),
                summary: "peer candidate is ready".to_owned(),
                evidence: Vec::new(),
            }),
            MessageId::new("message-peer-candidate-ready").unwrap(),
        )
        .unwrap()
        .0;
        plane
            .store
            .mutate("test.peer_candidate_ready", &json!({}), 5, |state| {
                apply_envelope(state, other_envelope.clone())
            })
            .unwrap();
        plane
            .decision_submit(&json!({
                "request": other_request_id,
                "candidate_sha": other_candidate.sha,
                "decision": "accepted",
                "summary": "peer candidate is authorized",
                "operation_id": "authorize-peer-candidate",
            }))
            .unwrap();

        let decision_request = json!({
            "request": request_id,
            "candidate_sha": replacement_candidate.sha,
            "decision": "accepted",
            "summary": "accepted and complete",
            "close_team": true,
            "operation_id": "accept-and-close-team",
        });
        plane.arm_test_crash("decision_close_commit");
        let crashed = plane.decision_submit(&decision_request).unwrap_err();
        assert_eq!(crashed.code, "simulated_decision_close_crash");
        let (_, after_crash, _) = plane.store.load().unwrap();
        assert_eq!(
            after_crash.team(&team_id).unwrap().status,
            TeamStatus::Closed
        );
        let closed_actor = after_crash
            .request(&request_id)
            .unwrap()
            .assignment
            .as_ref()
            .unwrap()
            .actor
            .clone();
        let closed_actor_id = closed_actor.actor_id.clone();
        for message_id in [
            super::message_id("accept-and-close-team", "decision"),
            super::message_id("accept-and-close-team", "authorization"),
        ] {
            let delivery = after_crash
                .delivery(&message_id)
                .expect("close-generated delivery remains queryable until request completion");
            assert!(delivery.retired);
            assert_eq!(
                delivery
                    .undeliverable_recipients
                    .get(&actor_delivery_recipient(
                        closed_actor.clone(),
                        after_crash.team(&team_id).unwrap().epoch,
                    )),
                Some(&DeliveryRetirementReason::TeamClosed {
                    team_id: team_id.clone(),
                    team_epoch: after_crash.team(&team_id).unwrap().epoch,
                })
            );
        }
        assert!(
            after_crash
                .pending_acknowledgement_message_ids_for(&closed_actor_id)
                .is_empty(),
            "synchronous decision close leaves no actor acknowledgement pinned"
        );
        assert!(
            plane
                .store
                .operation_result(
                    "accept-and-close-team",
                    "decision.submit",
                    &decision_request
                )
                .unwrap()
                .is_none()
        );
        let (_, before_peer_completion, _) = plane.store.load().unwrap();
        let other_request = before_peer_completion.request(&other_request_id).unwrap();
        let other_authorization = other_request.integration_authorization.clone().unwrap();
        let integration_envelope = super::request_envelope(
            &before_peer_completion,
            &other_request_id,
            before_peer_completion.active_primary().unwrap(),
            MessageTarget::Actor(
                other_request
                    .assignment
                    .as_ref()
                    .unwrap()
                    .actor
                    .actor_id
                    .clone(),
            ),
            Message::IntegrationComplete(IntegrationComplete {
                decision_id: other_authorization.decision_id,
                candidate: other_authorization.candidate,
                evidence: Vec::new(),
            }),
            MessageId::new("message-peer-integration-complete").unwrap(),
        )
        .unwrap()
        .0;
        plane
            .store
            .mutate("test.peer_integration_complete", &json!({}), 6, |state| {
                apply_envelope(state, integration_envelope.clone())
            })
            .unwrap();
        let (_, after_peer_completion, _) = plane.store.load().unwrap();
        let completed_delivery = after_peer_completion
            .delivery(&MessageId::new("message-peer-integration-complete").unwrap())
            .expect("closed-team integration completion remains queryable");
        assert!(completed_delivery.retired);
        assert_eq!(
            completed_delivery
                .undeliverable_recipients
                .get(&actor_delivery_recipient(
                    closed_actor,
                    after_peer_completion.team(&team_id).unwrap().epoch,
                )),
            Some(&DeliveryRetirementReason::TeamClosed {
                team_id: team_id.clone(),
                team_epoch: after_peer_completion.team(&team_id).unwrap().epoch,
            })
        );
        let peer_completed = plane.team_show(&json!({ "id": team_id })).unwrap();
        assert_eq!(peer_completed["team"]["blocking_request_ids"], json!([]));
        let original_reviewer = after_crash
            .request(&request_id)
            .unwrap()
            .decision
            .as_ref()
            .unwrap()
            .reviewer
            .clone();
        let replacement_primary =
            activate_test_primary(&plane, "primary-decision-close-replacement");
        assert_ne!(replacement_primary, original_reviewer);
        let decided = plane.decision_submit(&decision_request).unwrap();
        assert_eq!(decided["team_close"]["status"], "closed");
        assert_eq!(decided["team_close"]["complete"], true);
        assert_eq!(decided["decision"]["reviewer"], json!(original_reviewer));
        let repeated = plane.decision_submit(&decision_request).unwrap();
        assert_eq!(repeated, decided);
        assert_eq!(runtime.launch_count(), 1);

        let shown = plane.request_show(&json!({ "id": request_id })).unwrap();
        assert_eq!(shown["request"]["rejection_count"], 1);
        assert_eq!(shown["request"]["fix_cycle_depth"], 1);
        assert_eq!(
            shown["request"]["candidate_history"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            shown["request"]["candidate_history"][0]["created_by_profile"],
            "implementation"
        );
        let audit = plane.events(&json!({ "limit": 100 })).unwrap();
        let outcome = audit["request_outcomes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|outcome| outcome["request_id"].as_str() == Some(request_id.as_str()))
            .unwrap();
        assert_eq!(outcome["rejection_count"], 1);
        assert_eq!(outcome["fix_cycle_depth"], 1);
        assert_eq!(
            outcome["candidate_history"][0]["created_by_profile"],
            "implementation"
        );
    }

    #[test]
    fn new_worktree_path_is_validated_before_git_side_effects() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let seed = temporary.path().join("seed-worktree");
        init_test_repository(&root, &seed);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-worktree-create-preflight",
        ));
        let settings = profiled_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        let nested = root.join("nested");
        fs::create_dir(&nested).unwrap();
        let target = nested.join("..").join("unsafe-new-worktree");

        let error = plane
            .create_recorded_team_worktree(&TeamId::new("team-workers").unwrap(), &target)
            .unwrap_err();

        assert_eq!(error.code, "unsafe_working_directory");
        assert!(!root.join("unsafe-new-worktree").exists());
        let listed = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["worktree", "list", "--porcelain"])
            .output()
            .unwrap();
        assert!(listed.status.success());
        assert!(!String::from_utf8_lossy(&listed.stdout).contains("unsafe-new-worktree"));
    }

    #[test]
    fn missing_durable_session_path_is_fenced_before_worktree_creation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let seed = temporary.path().join("seed-worktree");
        init_test_repository(&root, &seed);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-missing-session-worktree-fence",
        ));
        let settings = profiled_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        let target = temporary.path().join("missing-shared-worktree");
        let aliased_parent = temporary.path().join("aliased-session-parent");
        std::os::unix::fs::symlink(temporary.path(), &aliased_parent).unwrap();
        let durable_session_target = aliased_parent.join("missing-shared-worktree");
        let legacy_team = TeamId::new("team-legacy").unwrap();
        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: "impl-legacy-1".to_owned(),
                team_id: Some(legacy_team.to_string()),
                working_directory: durable_session_target,
                backend: "fake".to_owned(),
                runtime: Some(runtime.id().to_string()),
                external_id: Some("missing-session-worktree-fence".to_owned()),
                resume_token: Some("missing-session-worktree-fence".to_owned()),
                status: "missing".to_owned(),
                launch_key: "missing-session-worktree-fence".to_owned(),
                updated_at_ms: 1,
                row_revision: 0,
            })
            .unwrap();
        assert!(plane.store.team_worktrees().unwrap().is_empty());

        let error = plane
            .ensure_team_directory_with_ownership(
                &TeamId::new("team-workers").unwrap(),
                Some(&target),
                false,
            )
            .unwrap_err();

        assert_eq!(error.code, "working_directory_conflict");
        assert_eq!(error.details["actor_id"], "impl-legacy-1");
        assert!(!target.exists());
        let listed = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["worktree", "list", "--porcelain"])
            .output()
            .unwrap();
        assert!(listed.status.success());
        assert!(!String::from_utf8_lossy(&listed.stdout).contains(target.to_str().unwrap()));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn reconcile_reports_owned_worktree_absence_and_identity_drift_without_repair() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let seed = temporary.path().join("seed-worktree");
        init_test_repository(&root, &seed);
        let runtime = Arc::new(FixtureRuntime::with_id(
            "fixture-runtime-worktree-drift-report",
        ));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-worktree-drift-report");
        let owned = temporary.path().join("owned-worktree-drift");
        plane
            .team_create(&json!({
                "name": "workers",
                "working_directory": owned,
                "orchestrators": 1,
                "operation_id": "create-owned-worktree-drift",
            }))
            .unwrap();
        let team_id = TeamId::new("team-workers").unwrap();
        let durable_before = plane
            .store
            .team_worktree(team_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(durable_before.ownership, TeamWorktreeOwnership::Created);
        let moved = temporary.path().join("externally-moved-owned-worktree");
        fs::rename(&owned, &moved).unwrap();
        let revision_before = plane.store.load().unwrap().0;

        let absent = plane.reconcile().unwrap();
        assert_eq!(absent["complete"], false);
        let absent_drift = absent["working_directory_drift"]
            .as_array()
            .unwrap()
            .iter()
            .find(|drift| drift["team_id"] == team_id.as_str())
            .unwrap();
        assert_eq!(absent_drift["observation"]["state"], "recorded_absent");
        assert_eq!(
            absent_drift["observation"]["drift"][0]["code"],
            "recorded_path_absent"
        );
        assert!(!owned.exists());
        assert!(moved.exists());
        assert_eq!(plane.store.load().unwrap().0, revision_before);
        assert_eq!(
            plane
                .store
                .team_worktree(team_id.as_str())
                .unwrap()
                .unwrap(),
            durable_before
        );

        fs::rename(&moved, &owned).unwrap();
        let git_file = owned.join(".git");
        let saved_git_file = owned.join(".git.saved");
        fs::rename(&git_file, &saved_git_file).unwrap();
        fs::create_dir(&git_file).unwrap();
        let identity_drift = plane.reconcile().unwrap();
        let present_drift = identity_drift["working_directory_drift"]
            .as_array()
            .unwrap()
            .iter()
            .find(|drift| drift["team_id"] == team_id.as_str())
            .unwrap();
        assert_eq!(present_drift["observation"]["state"], "present_mismatch");
        assert!(
            present_drift["observation"]["drift"]
                .as_array()
                .unwrap()
                .iter()
                .any(|drift| drift["code"] == "git_identity_unavailable")
        );
        assert!(owned.exists());
        assert_eq!(plane.store.load().unwrap().0, revision_before);

        fs::remove_dir(&git_file).unwrap();
        fs::rename(saved_git_file, git_file).unwrap();
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn managed_explicit_and_adopted_worktrees_are_owned_and_removed() {
        for explicit_missing in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("repository");
            let seed = temporary.path().join("seed-worktree");
            init_test_repository(&root, &seed);
            let runtime = Arc::new(FixtureRuntime::with_id(if explicit_missing {
                "fixture-runtime-explicit-owned"
            } else {
                "fixture-runtime-managed-owned"
            }));
            let settings = profiled_settings(
                root,
                temporary.path().join("state"),
                runtime.id().as_str(),
                1,
                "first_healthy",
            );
            let plane = open_fixture_plane(settings, &runtime);
            activate_test_primary(&plane, "primary-owned-worktree");
            let mut create = json!({
                "name": "workers",
                "orchestrators": 1,
                "operation_id": if explicit_missing {
                    "create-explicit-owned"
                } else {
                    "create-managed-owned"
                },
            });
            if explicit_missing {
                create["working_directory"] =
                    json!(temporary.path().join("explicit-missing-worktree"));
            }
            let created = plane.team_create(&create).unwrap();
            let target = PathBuf::from(created["working_directory"].as_str().unwrap());
            assert!(target.exists());
            assert_eq!(created["worktree"]["ownership"], "created");
            assert_eq!(created["worktree"]["status"], "active");
            let closed = plane
                .team_close(&json!({
                    "id": "team-workers",
                    "operation_id": if explicit_missing {
                        "close-explicit-owned"
                    } else {
                        "close-managed-owned"
                    },
                }))
                .unwrap();
            assert_eq!(closed["status"], "closed");
            assert_eq!(closed["worktree_cleanup"]["status"], "removed");
            assert!(!target.exists());
        }

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let adopted = temporary.path().join("adopted-worktree");
        init_test_repository(&root, &adopted);
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-adopted-owned"));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-adopted-worktree");
        let created = plane
            .team_create(&json!({
                "name": "workers",
                "working_directory": adopted,
                "adopt_working_directory": true,
                "orchestrators": 1,
                "operation_id": "create-adopted-owned",
            }))
            .unwrap();
        assert_eq!(created["worktree"]["ownership"], "adopted");
        let closed = plane
            .team_close(&json!({
                "id": "team-workers",
                "operation_id": "close-adopted-owned",
            }))
            .unwrap();
        assert_eq!(closed["worktree_cleanup"]["status"], "removed");
        assert!(!adopted.exists());
    }

    #[test]
    fn owned_cleanup_never_prunes_an_unrelated_missing_worktree_entry() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let unrelated = temporary.path().join("unrelated-user-worktree");
        init_test_repository(&root, &unrelated);
        let moved_unrelated = temporary
            .path()
            .join("temporarily-unavailable-user-worktree");
        fs::rename(&unrelated, &moved_unrelated).unwrap();
        let runtime = Arc::new(FixtureRuntime::with_id("fixture-runtime-no-global-prune"));
        let settings = profiled_settings(
            root.clone(),
            temporary.path().join("state"),
            runtime.id().as_str(),
            1,
            "first_healthy",
        );
        let plane = open_fixture_plane(settings, &runtime);
        activate_test_primary(&plane, "primary-no-global-prune");
        let owned = temporary.path().join("owned-worktree");
        plane
            .team_create(&json!({
                "name": "workers",
                "working_directory": owned,
                "orchestrators": 1,
                "operation_id": "create-no-global-prune",
            }))
            .unwrap();
        let moved_owned = temporary.path().join("externally-absent-owned-worktree");
        fs::rename(&owned, &moved_owned).unwrap();
        let closed = plane
            .team_close(&json!({
                "id": "team-workers",
                "operation_id": "close-no-global-prune",
            }))
            .unwrap();
        assert_eq!(closed["worktree_cleanup"]["status"], "removed");
        assert!(moved_owned.exists());
        let listed = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["worktree", "list", "--porcelain"])
            .output()
            .unwrap();
        assert!(listed.status.success());
        assert!(
            String::from_utf8_lossy(&listed.stdout).contains(unrelated.to_str().unwrap()),
            "closing one owned team must preserve another missing worktree's administrative entry"
        );
        assert!(
            !String::from_utf8_lossy(&listed.stdout).contains(owned.to_str().unwrap()),
            "closing must remove only the exact absent owned-worktree entry"
        );
        fs::rename(moved_unrelated, unrelated).unwrap();
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn owned_worktree_removal_refusals_are_durable_visible_and_audited() {
        for (case, expected_error) in [
            ("dirty", "worktree_dirty"),
            ("unreachable", "worktree_unreachable_commits"),
            ("locked", "worktree_remove_failed"),
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("repository");
            let seed = temporary.path().join("seed-worktree");
            init_test_repository(&root, &seed);
            let runtime = Arc::new(FixtureRuntime::with_id(&format!(
                "fixture-runtime-worktree-refusal-{case}"
            )));
            let settings = profiled_settings(
                root.clone(),
                temporary.path().join("state"),
                runtime.id().as_str(),
                1,
                "first_healthy",
            );
            let plane = open_fixture_plane(settings, &runtime);
            activate_test_primary(&plane, "primary-worktree-refusal");
            let target = temporary.path().join(format!("{case}-owned-worktree"));
            plane
                .team_create(&json!({
                    "name": "workers",
                    "working_directory": target,
                    "orchestrators": 1,
                    "operation_id": format!("create-{case}-refusal"),
                }))
                .unwrap();
            match case {
                "dirty" => fs::write(target.join("untracked.txt"), "retain me\n").unwrap(),
                "unreachable" => {
                    fs::write(target.join("candidate.txt"), "unique commit\n").unwrap();
                    run_git(&target, &["add", "candidate.txt"]);
                    run_git(&target, &["commit", "-q", "-m", "unique candidate"]);
                }
                "locked" => run_git(&root, &["worktree", "lock", target.to_str().unwrap()]),
                _ => unreachable!(),
            }

            let closed = plane
                .team_close(&json!({
                    "id": "team-workers",
                    "operation_id": format!("close-{case}-refusal"),
                }))
                .unwrap();
            assert_eq!(closed["status"], "closed");
            assert_eq!(
                closed["worktree_cleanup"]["status"], "retained_with_reason",
                "removal refusal case `{case}` unexpectedly removed the worktree"
            );
            assert_eq!(closed["worktree_cleanup"]["error_code"], expected_error);
            assert!(
                closed["worktree_cleanup"]["reason"]
                    .as_str()
                    .is_some_and(|reason| !reason.is_empty())
            );
            assert!(target.exists());
            let shown = plane.team_show(&json!({ "id": "team-workers" })).unwrap();
            assert_eq!(shown["team"]["retained_owned_worktree"], true);
            assert_eq!(shown["team"]["worktree"]["error_code"], expected_error);
            let audit = plane.events(&json!({ "limit": 100 })).unwrap();
            let close_event = audit["control_events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|event| event["operation"] == "team.closed")
                .unwrap();
            assert_eq!(
                close_event["detail"]["worktree_cleanup"]["error_code"],
                expected_error
            );
        }
    }

    fn run_git(root: &Path, args: &[&str]) {
        let output = clean_test_git_command(root).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn run_git_with_date(root: &Path, args: &[&str], date: &str) {
        let output = clean_test_git_command(root)
            .args(args)
            .env("GIT_AUTHOR_DATE", date)
            .env("GIT_COMMITTER_DATE", date)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn clean_test_git_command(root: &Path) -> Command {
        super::control_git_command(&test_git(), root)
    }

    fn test_git() -> PathBuf {
        crate::review::resolve_git_executable().unwrap()
    }

    fn pinned_git_fixture(root: &Path) -> (PathBuf, PathBuf) {
        let executable = root.join("pinned-git");
        let marker = root.join("pinned-git-invocations");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\nexec {} \"$@\"\n",
            super::shell_single_quote(&marker.to_string_lossy()),
            super::shell_single_quote(&test_git().to_string_lossy()),
        );
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        (executable, marker)
    }

    fn make_test_tree_writable(path: &Path) {
        let metadata = fs::symlink_metadata(path).unwrap();
        if metadata.file_type().is_symlink() {
            return;
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                make_test_tree_writable(&entry.unwrap().path());
            }
        }
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | if metadata.is_dir() { 0o700 } else { 0o600 });
        fs::set_permissions(path, permissions).unwrap();
    }

    fn make_test_tree_read_only(path: &Path) {
        let metadata = fs::symlink_metadata(path).unwrap();
        if metadata.file_type().is_symlink() {
            return;
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                make_test_tree_read_only(&entry.unwrap().path());
            }
        }
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() & !0o222);
        fs::set_permissions(path, permissions).unwrap();
    }

    fn init_test_repository(root: &Path, linked_worktree: &Path) {
        fs::create_dir(root).unwrap();
        run_git(root, &["init", "-q"]);
        run_git(root, &["config", "user.name", "AGSV Test"]);
        run_git(root, &["config", "user.email", "agsv-test@example.invalid"]);
        fs::write(root.join("README.md"), "base\n").unwrap();
        run_git(root, &["add", "README.md"]);
        run_git(root, &["commit", "-q", "-m", "base"]);
        run_git(
            root,
            &[
                "worktree",
                "add",
                "--detach",
                linked_worktree.to_str().unwrap(),
                "HEAD",
            ],
        );
    }

    #[test]
    fn retry_canonicalizes_runtime_timestamp_without_weakening_content_check() {
        let workspace_id = WorkspaceId::new("workspace-test").unwrap();
        let mut supervisor = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let primary = supervisor
            .activate_primary(ActorId::new("primary-test").unwrap())
            .unwrap();
        let team_id = TeamId::new("team-test").unwrap();
        let team_epoch = supervisor.create_team(team_id.clone()).unwrap();
        let implementation = supervisor
            .register_implementation(&team_id, ActorId::new("impl-test").unwrap())
            .unwrap();
        let envelope = Envelope {
            protocol_version: PROTOCOL_VERSION,
            message_id: MessageId::new("message-retry").unwrap(),
            workspace_id,
            sender: primary,
            target: MessageTarget::Actor(implementation.actor_id),
            team_id: Some(team_id),
            run_id: Some(RunId::new("run-retry").unwrap()),
            request_id: Some(RequestId::new("request-retry").unwrap()),
            policy_revision: PolicyRevision::INITIAL,
            primary_epoch: PrimaryEpoch::INITIAL,
            team_epoch: Some(team_epoch),
            assignment_epoch: None,
            sent_at: TimestampMillis(1),
            message: Message::ImplementationRequest(ImplementationRequest {
                title: "retry".to_owned(),
                instructions: "retry the exact command".to_owned(),
                base_sha: GitSha::new("0".repeat(40)).unwrap(),
                base_source: agsv_protocol::RequestBaseSource::Derived,
                acceptance_criteria: vec!["same result".to_owned()],
                evidence_requirements: vec![EvidenceKind::Git],
            }),
        };
        assert_eq!(
            apply_envelope(&mut supervisor, envelope.clone()).unwrap(),
            ApplyOutcome::Applied
        );
        let mut retry = envelope.clone();
        retry.sent_at = TimestampMillis(2);
        assert_eq!(
            apply_envelope(&mut supervisor, retry).unwrap(),
            ApplyOutcome::Duplicate
        );
        let mut conflict = envelope;
        conflict.sent_at = TimestampMillis(3);
        let Message::ImplementationRequest(specification) = &mut conflict.message else {
            unreachable!();
        };
        specification.instructions = "different content".to_owned();
        assert!(apply_envelope(&mut supervisor, conflict).is_err());
    }

    #[test]
    fn committed_message_retry_rejects_changed_semantic_input() {
        let workspace_id = WorkspaceId::new("workspace-retry-input").unwrap();
        let mut supervisor = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let envelope = Envelope {
            protocol_version: PROTOCOL_VERSION,
            message_id: MessageId::new("message-retry-input").unwrap(),
            workspace_id,
            sender: ActorRef {
                actor_id: ActorId::new("impl-retry-input").unwrap(),
                actor_epoch: ActorEpoch::INITIAL,
            },
            target: MessageTarget::Primary,
            team_id: Some(TeamId::new("team-retry-input").unwrap()),
            run_id: Some(RunId::new("run-retry-input").unwrap()),
            request_id: Some(RequestId::new("request-retry-input").unwrap()),
            policy_revision: PolicyRevision::INITIAL,
            primary_epoch: PrimaryEpoch::INITIAL,
            team_epoch: None,
            assignment_epoch: None,
            sent_at: TimestampMillis(1),
            message: Message::Progress(ProgressUpdate {
                summary: "same progress".to_owned(),
                percent_complete: None,
                evidence: Vec::new(),
            }),
        };
        let mut args = MessageSendArgs {
            to: None,
            kind: "progress".to_owned(),
            body: Some("same progress".to_owned()),
            team: None,
            request: Some("request-retry-input".to_owned()),
            decision: None,
            rationale: None,
            consultation_id: None,
            subject: None,
            depends_on_request: None,
            resources: Vec::new(),
            handoff_id: None,
            outcome: None,
            operation_id: "operation-retry-input".to_owned(),
        };
        validate_message_retry(&args, "progress", &envelope, &supervisor).unwrap();

        args.body = Some("changed progress".to_owned());
        let error = validate_message_retry(&args, "progress", &envelope, &supervisor).unwrap_err();
        assert_eq!(error.code, "operation_id_conflict");

        args.body = Some("same progress".to_owned());
        args.to = Some("workspace".to_owned());
        let error = validate_message_retry(&args, "progress", &envelope, &supervisor).unwrap_err();
        assert_eq!(error.code, "operation_id_conflict");

        let team_id = TeamId::new("team-retry-input").unwrap();
        supervisor.create_team(team_id.clone()).unwrap();
        let directive_envelope = Envelope {
            message_id: MessageId::new("directive-retry-input").unwrap(),
            target: MessageTarget::Team(team_id.clone()),
            team_id: Some(team_id.clone()),
            team_epoch: Some(agsv_protocol::TeamEpoch::INITIAL),
            message: Message::Directive(PrimaryDirective {
                decision: "keep request scope".to_owned(),
                rationale: "scope is part of the durable decision".to_owned(),
            }),
            ..envelope
        };
        let mut directive_args = MessageSendArgs {
            to: Some(team_id.to_string()),
            kind: "directive".to_owned(),
            body: None,
            team: None,
            request: Some("request-retry-input".to_owned()),
            decision: Some("keep request scope".to_owned()),
            rationale: Some("scope is part of the durable decision".to_owned()),
            consultation_id: None,
            subject: None,
            depends_on_request: None,
            resources: Vec::new(),
            handoff_id: None,
            outcome: None,
            operation_id: "operation-directive-retry-input".to_owned(),
        };
        directive_args.validate_for("directive").unwrap();
        validate_message_retry(
            &directive_args,
            "directive",
            &directive_envelope,
            &supervisor,
        )
        .unwrap();

        directive_args.request = None;
        directive_args.team = Some(team_id.to_string());
        directive_args.validate_for("directive").unwrap();
        let error = validate_message_retry(
            &directive_args,
            "directive",
            &directive_envelope,
            &supervisor,
        )
        .unwrap_err();
        assert_eq!(error.code, "operation_id_conflict");
    }
}
