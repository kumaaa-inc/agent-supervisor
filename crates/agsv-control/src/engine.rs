use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::backend::SessionDriver;
use crate::caller::{CallerBinding, CallerIdentityDriver, InsecureActorIdentity};
use crate::identity::sha256_hex;
use crate::presentation::{
    LabelContext, active_request_title, render_label_template,
    session_label as display_session_label,
};
use crate::store::{PresentationSyncState, SessionPresentationRecord, SessionRecord, StateStore};
use crate::{ControlError, WorkspaceIdentity};
use agsv_core::{AckOutcome, ApplyOutcome, Supervisor};
use agsv_protocol::{
    Acknowledgement, Actor, ActorId, ActorProfileName, ActorProfileSnapshot, ActorRef, ActorRole,
    ActorStatus, AssignmentEpoch, AssignmentPolicyId, BlockerNotice, Cancellation, Candidate,
    CandidateReady, CapabilityId, ConflictNotice, ConsultationRequest, ConsultationResponse,
    DecisionId, DependencyNotice, Envelope, EvidenceKind, FixRequest, GitSha,
    HUMAN_FACING_PRIMARY_CAPABILITY, HandoffAcceptance, HandoffId, HandoffOffer,
    IMPLEMENTATION_EXECUTION_CAPABILITY, ImplementationRequest, IntegrationAuthorization,
    IntegrationComplete, Message, MessageId, MessageTarget, PROTOCOL_VERSION, PolicyRevision,
    ProgressUpdate, QaOutcome, QaResult, RequestId, ReviewDecision, ReviewVerdict, RunControl,
    RunControlAction, RunId, Team, TeamId, TeamProfileName, TeamProfileSnapshot, TeamStatus,
    TimestampMillis, Validate,
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
// v0.1 stored NULL because Codex was its only runtime; legacy resolution must
// remain pinned to that history and never follow the current registry default.
const LEGACY_RUNTIME_ID: &str = "codex";
const LEGACY_PRIMARY_PROFILE: &str = "primary";
const LEGACY_IMPLEMENTATION_PROFILE: &str = "implementation";

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
    pub runtime: String,
    pub model: String,
    pub reasoning_effort: String,
    pub role_file: PathBuf,
    pub role_instructions: String,
    pub role_source: String,
}

/// One validated project-defined persistent team profile.
#[derive(Clone, Debug)]
pub struct TeamProfileSettings {
    pub name: String,
    pub actor_profile: String,
    pub desired_instances: u32,
    pub assignment_policy: String,
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
    pub backend: String,
    pub persist_profile_snapshots: bool,
    pub primary_profile: String,
    pub default_team_profile: String,
    pub agent_profiles: BTreeMap<String, ActorProfileSettings>,
    pub team_profiles: BTreeMap<String, TeamProfileSettings>,
    pub max_panes_per_tab: u16,
    pub place_first_implementation_with_primary: bool,
    pub tab_label_strategy: String,
    pub pane_label_template: String,
    pub split_direction: String,
    pub focus_new_sessions: bool,
    pub primary_lease_seconds: u32,
    pub actor_heartbeat_seconds: u32,
}

/// One invocation's embedded control-plane handle.
pub struct ControlPlane {
    settings: ControlSettings,
    identity: WorkspaceIdentity,
    store: StateStore,
    sessions: SessionDriver,
    profile_runtimes: BTreeMap<String, Arc<dyn AgentRuntime>>,
    caller_identity: CallerIdentityDriver,
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
        let identity = WorkspaceIdentity::discover(&settings.workspace)?;
        settings.workspace = identity.root().to_path_buf();
        if let Ok(value) = std::env::var("AGSV_SESSION_BACKEND") {
            settings.backend = value;
        }
        validate_profile_settings(&settings)?;
        let profile_runtimes = settings
            .agent_profiles
            .iter()
            .map(|(name, profile)| {
                select_runtime(registry, &profile.runtime).map(|runtime| (name.clone(), runtime))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
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
        Ok(Self {
            settings,
            identity,
            store,
            sessions,
            profile_runtimes,
            caller_identity,
        })
    }

    /// Executes one stable CLI operation and returns its machine-readable payload.
    ///
    /// # Errors
    ///
    /// Returns a stable error when arguments, authorization, persistence,
    /// protocol transitions, Git evidence, or the session backend fails.
    pub fn execute(&self, operation: &str, request: &Value) -> Result<Value, ControlError> {
        self.expire_stale_actors()?;
        if primary_operation(operation) {
            self.authenticate_primary()?;
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
            "actor.list" => self.actor_list(request),
            "actor.show" => self.actor_show(request),
            "actor.stop" => self.actor_stop(request),
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
            "decision.submit" => self.decision_submit(request),
            _ => Err(ControlError::unsupported(operation, "unknown operation")),
        }?;
        if presentation_refresh_operation(operation) {
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

    fn runtime_config(profile: &ActorProfileSettings) -> RuntimeConfig {
        RuntimeConfig::new(profile.model.clone(), profile.reasoning_effort.clone())
    }

    fn runtime_for_profile(
        &self,
        profile: &ActorProfileSettings,
    ) -> Result<Arc<dyn AgentRuntime>, ControlError> {
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
                        "runtime": profile.runtime,
                        "model": profile.model,
                        "reasoning_effort": profile.reasoning_effort,
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
                let runtime = self.runtime_for_profile(profile)?;
                Ok((
                    name.clone(),
                    json!({
                        "role": profile.role,
                        "capabilities": profile.capabilities,
                        "runtime_id": runtime.id().as_str(),
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

    fn team_control_profile(
        &self,
        team: Option<&Team>,
    ) -> Result<(TeamProfileSettings, ActorProfileSettings, ProfileMode), ControlError> {
        let Some(team) = team else {
            return Ok((
                self.selected_team_profile()?.clone(),
                self.selected_team_actor_profile()?.clone(),
                if self.settings.persist_profile_snapshots {
                    ProfileMode::Snapshotted
                } else {
                    ProfileMode::Legacy
                },
            ));
        };
        let Some(snapshot) = &team.profile else {
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
                let (desired_instances, effective_assignment_policy) =
                    Self::effective_team_intent(team)?;
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
        let assignment_instances = self.assignment_instance_summary(&supervisor)?;
        let observability = self.redacted_observability_summary(&supervisor)?;
        let snapshot = supervisor.snapshot();
        let teams = snapshot
            .teams
            .iter()
            .map(|team| self.team_value(team))
            .collect::<Result<Vec<_>, _>>()?;
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
            "state_path": self.store.path(),
            "revision": revision,
            "primary": snapshot.active_primary,
            "primary_epoch": snapshot.primary_epoch,
            "teams": teams,
            "presentation": self.presentation_diagnostics()?,
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
        let (_, supervisor, _) = self.store.load()?;
        let assignment_instances = self.assignment_instance_summary(&supervisor)?;
        let selected_actor_profile = self.selected_team_actor_profile()?;
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
        let (_, supervisor, _) = self.store.load()?;
        let teams = supervisor
            .snapshot()
            .teams
            .iter()
            .map(|team| self.team_value(team))
            .collect::<Result<Vec<_>, _>>()?;
        let healthy = lifecycle_backend_ready
            && runtime_available
            && backend_runtime_reachable == Some(true)
            && caller_context["ready"].as_bool() == Some(true);
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
            "presentation": self.presentation_diagnostics()?,
            "launch": {
                "runtime": runtime.id().as_str(),
                "model": selected_actor_profile.model,
                "reasoning_effort": selected_actor_profile.reasoning_effort,
                "initial_prompt_delivery": initial_prompt_delivery_name(
                    runtime_capabilities.initial_prompt_delivery,
                ),
                "sandbox": runtime_capabilities.launch_policy.sandbox,
                "approval": runtime_capabilities.launch_policy.approval,
            },
            "enforcement": {
                "core": ["capability_authorization", "state_transitions", "idempotency", "fencing", "exact_candidate_sha"],
                "control_plane": ["durable_session_actor_binding", "primary_caller_authentication", "authenticated_heartbeats", "lease_expiry"],
                "launch": launch_enforcement,
                "runtime_adapter": ["launch_arguments", "resume_arguments", "diagnostics", "capabilities"],
                "provider": runtime_capabilities.launch_policy.provider_enforcement,
                "instructed_observed": ["provider_native_subagent_topology", "fresh_review", "read_only_review", "provider_process_pause"],
            },
            "leases": {
                "primary_capability": HUMAN_FACING_PRIMARY_CAPABILITY,
                "primary_lease_seconds": self.settings.primary_lease_seconds,
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
        Ok(json!({
            "control_events": self.store.events(args.limit)?,
            "protocol_events": supervisor.audit_events(),
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
            self.resolve_actor(args.actor.as_deref())?.actor_ref()
        };
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&actor_ref.actor_id)
            .ok_or_else(|| ControlError::not_found("actor", actor_ref.actor_id.as_str()))?;
        let inbox = supervisor
            .unacknowledged_for(&actor_ref)
            .map_err(ControlError::core)?;
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
                "runtime": profile.runtime,
                "model": profile.model,
                "reasoning_effort": profile.reasoning_effort,
                "role_file": profile.role_file,
            },
            "primary_epoch": supervisor.primary_epoch(),
            "policy_revision": supervisor.policy_revision(),
            "team": actor.team_id.as_ref().and_then(|id| supervisor.team(id)),
            "assignments": snapshot.requests.into_iter().filter(|item| {
                item.assignment.as_ref().is_some_and(|assignment| assignment.actor == actor_ref)
            }).collect::<Vec<_>>(),
            "inbox": inbox,
        }))
    }

    fn team_list(&self) -> Result<Value, ControlError> {
        let (_, supervisor, _) = self.store.load()?;
        let teams = supervisor
            .snapshot()
            .teams
            .iter()
            .map(|team| self.team_value(team))
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
        let snapshot = supervisor.snapshot();
        Ok(json!({
            "team": self.team_value(team)?,
            "actors": snapshot.actors.into_iter().filter(|actor| actor.team_id.as_ref() == Some(&id)).collect::<Vec<_>>(),
            "requests": snapshot.requests.into_iter().filter(|item| item.team_id == id).collect::<Vec<_>>(),
            "sessions": self.store.sessions()?.into_iter().filter(|item| item.team_id.as_deref() == Some(args.id.as_str())).collect::<Vec<_>>(),
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
            self.store
                .set_team_purpose(team_id.as_str(), &purpose, now_ms()?)?;
            Ok(json!({
                "team": self.team_value(team)?,
                "revision": revision,
                "descriptive_only": true,
            }))
        })
    }

    fn team_value(&self, team: &Team) -> Result<Value, ControlError> {
        let mut value = serde_json::to_value(team).map_err(ControlError::database)?;
        let purpose = self
            .store
            .team_purpose(team.team_id.as_str())?
            .unwrap_or_default();
        value
            .as_object_mut()
            .expect("protocol teams serialize as JSON objects")
            .insert("purpose".to_owned(), Value::String(purpose));
        Ok(value)
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
        let active_title = active_request_title(&supervisor, actor_ref);
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

    fn actor_list(&self, request: &Value) -> Result<Value, ControlError> {
        let args: ActorListArgs = decode(request)?;
        let (_, supervisor, _) = self.store.load()?;
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
                json!({ "actor": actor, "session": session })
            })
            .collect::<Vec<_>>();
        Ok(json!({ "actors": actors }))
    }

    fn actor_show(&self, request: &Value) -> Result<Value, ControlError> {
        let args: IdArgs = decode(request)?;
        let id = ActorId::new(args.id.clone()).map_err(ControlError::protocol)?;
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&id)
            .ok_or_else(|| ControlError::not_found("actor", &args.id))?;
        Ok(json!({ "actor": actor, "session": self.store.session(&args.id)? }))
    }

    fn run_list(&self, request: &Value) -> Result<Value, ControlError> {
        let args: TeamFilterArgs = decode(request)?;
        let (_, supervisor, _) = self.store.load()?;
        let runs = supervisor
            .snapshot()
            .runs
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
        let run = supervisor
            .run(&id)
            .ok_or_else(|| ControlError::not_found("run", &args.id))?;
        Ok(json!({ "run": run, "request": supervisor.request(&run.request_id) }))
    }

    fn request_list(&self, request: &Value) -> Result<Value, ControlError> {
        let args: RequestListArgs = decode(request)?;
        let (_, supervisor, _) = self.store.load()?;
        let requests = supervisor
            .snapshot()
            .requests
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
            .collect::<Vec<_>>();
        Ok(json!({ "requests": requests }))
    }

    fn request_show(&self, request: &Value) -> Result<Value, ControlError> {
        let args: IdArgs = decode(request)?;
        let id = RequestId::new(args.id.clone()).map_err(ControlError::protocol)?;
        let (_, supervisor, _) = self.store.load()?;
        let item = supervisor
            .request(&id)
            .ok_or_else(|| ControlError::not_found("request", &args.id))?;
        Ok(json!({ "request": item, "run": supervisor.run(&item.run_id) }))
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
        self.store.upsert_session(&SessionRecord {
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
            updated_at_ms: now_ms()?,
        })
    }
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
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&actor_ref.actor_id)
            .filter(|actor| actor.epoch == actor_ref.actor_epoch)
            .cloned()
            .ok_or_else(|| {
                ControlError::new(
                    "stale_actor_binding",
                    "the authenticated session is bound to a stale actor generation",
                )
            })?;
        self.actor_profile(&actor)?;
        Ok(actor)
    }

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
                if actor.team_id.is_some()
                    || supervisor.active_primary().as_ref() == Some(&binding.actor)
                {
                    self.heartbeat_actor(&binding.actor, "actor.bootstrapped")?;
                    return Ok(binding.actor);
                }
                if supervisor.active_primary().is_none() {
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
            } else if let Some(session) = self.store.sessions()?.into_iter().find(|session| {
                self.caller_identity
                    .context()
                    .matches_persisted_session(&session.backend, session.resume_token.as_deref())
            }) {
                let actor_id = ActorId::new(session.actor_id).map_err(ControlError::protocol)?;
                let (_, supervisor, _) = self.store.load()?;
                let actor_ref = supervisor
                    .actor(&actor_id)
                    .ok_or_else(|| ControlError::not_found("actor", actor_id.as_str()))?
                    .actor_ref();
                self.store.bind_actor(
                    caller_binding.kind(),
                    caller_binding.value(),
                    &actor_ref,
                    now_ms()?,
                )?;
                actor_ref
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
        self.heartbeat_actor(&actor_ref, "actor.authenticated")?;
        self.ensure_primary_notification_session(&actor_ref)?;
        Ok(actor_ref)
    }

    fn authenticate_primary(&self) -> Result<ActorRef, ControlError> {
        let actor_ref = self.authenticated_actor_ref(None)?;
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&actor_ref.actor_id)
            .filter(|actor| actor.epoch == actor_ref.actor_epoch)
            .ok_or_else(|| ControlError::new("stale_actor_binding", "actor generation is stale"))?;
        self.actor_profile(actor)?;
        if !actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
            || supervisor.active_primary().as_ref() != Some(&actor_ref)
        {
            return Err(ControlError::new(
                "primary_authentication_required",
                "this command requires the authenticated active Primary session",
            ));
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
                state
                    .heartbeat(actor_ref, TimestampMillis(observed_at))
                    .map_err(ControlError::core)
            },
        )?;
        Ok(())
    }

    fn expire_stale_actors(&self) -> Result<(), ControlError> {
        let observed_at = now_ms()?;
        let (_, supervisor, _) = self.store.load()?;
        if !supervisor
            .snapshot()
            .actors
            .iter()
            .any(|actor| self.actor_expired(actor, observed_at))
        {
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
                    .filter(|actor| self.actor_expired(actor, observed_at))
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
            if supervisor
                .team(&team_id)
                .is_some_and(|team| team.status != TeamStatus::Active)
            {
                return Err(ControlError::new(
                    "team_inactive",
                    "paused or retired teams do not launch actor instances",
                ));
            }
            let (selected_team, selected_actor, profile_mode) =
                self.team_control_profile(supervisor.team(&team_id))?;
            let configured_role = selected_actor.actor_role()?;
            let actor_snapshot = selected_actor.snapshot()?;
            let team_snapshot = selected_team.snapshot()?;
            let working_directory = if let Some(explicit) = args.working_directory.as_deref() {
                self.ensure_team_directory(&team_id, Some(explicit))?
            } else if let Some(existing) = self.existing_team_working_directory(&team_id)? {
                existing
            } else {
                self.ensure_team_directory(&team_id, None)?
            };
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
                    if session.working_directory != working_directory {
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
                    Ok(newly_registered)
                },
            )?;
            self.store
                .set_team_purpose(team_id.as_str(), &purpose, now_ms()?)?;
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
                "working_directory": working_directory,
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
                    status.clone_into(&mut existing.status);
                    existing.updated_at_ms = now_ms()?;
                    self.store.upsert_session(existing)?;
                    self.bind_launched_actor(actor_ref, existing)?;
                    return Ok((existing.clone(), true));
                }
            }
        }
        let prompt = implementation_prompt(
            &actor_profile.role_instructions,
            &actor_profile.role,
            actor_ref,
            team_id,
        )?;
        let runtime_config = Self::runtime_config(actor_profile);
        let expected_name = session_name(self.identity.workspace_id().as_str(), actor_ref);
        let launch_backend = existing_session.as_ref().map_or_else(
            || self.sessions.name().to_owned(),
            |session| session.backend.clone(),
        );
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
        };
        self.store.upsert_session(&pending)?;
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
                pending.resume_token = Some(token.to_owned());
                pending.updated_at_ms = now_ms()?;
                self.store.upsert_session(&pending)?;
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
                let record = SessionRecord {
                    external_id: Some(handle.external_id),
                    resume_token: handle.resume_token,
                    status: "idle".to_owned(),
                    ..pending
                };
                self.store.upsert_session(&record)?;
                self.bind_launched_actor(actor_ref, &record)?;
                Ok((record, false))
            }
            Err(error) => {
                let failed = SessionRecord {
                    status: "launch_failed".to_owned(),
                    updated_at_ms: now_ms()?,
                    ..pending
                };
                self.store.upsert_session(&failed)?;
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
        directory
            .as_deref()
            .map(|path| self.ensure_team_directory(team_id, Some(path)))
            .transpose()
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
            let identity = WorkspaceIdentity::discover(&canonical)?;
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
        let operation_id = reconciliation_launch_operation_id(team_id, actor_id);
        let operation_request = json!({
            "team_id": team_id,
            "actor_id": actor_id,
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
        let session = SessionRecord {
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
        };
        self.store.upsert_session(&session)?;
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
        let operation_id = stable_id(
            "reconcile-surplus-stop",
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
        self.idempotent(
            "actor.reconcile_surplus_stop",
            &operation_request,
            &operation_id,
            || {
                let (revision, already_stopped) = self.store.mutate(
                    "actor.reconciled_surplus_stopped",
                    &operation_request,
                    now_ms()?,
                    |state| {
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
                        let assigned = nonterminal_request_ids(state, actor_ref);
                        if !assigned.is_empty() {
                            return Err(ControlError::new(
                                "surplus_wip",
                                "surplus actor retains nonterminal work and was not stopped",
                            )
                            .with_details(json!({
                                "actor_ref": actor_ref,
                                "assigned_nonterminal_request_ids": assigned,
                            })));
                        }
                        let already_stopped = actor.status == ActorStatus::Stopped;
                        if !already_stopped {
                            state
                                .set_actor_status(actor_ref, ActorStatus::Stopped)
                                .map_err(ControlError::core)?;
                        }
                        Ok(already_stopped)
                    },
                )?;

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
                        self.store.upsert_session(&session)?;
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
            },
        )
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
        let (team_profile, actor_profile, profile_mode) = self.team_control_profile(Some(&team))?;
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
                record.launch_key == reconciliation_launch_operation_id(team_id, actor_id)
                    && record.external_id.is_none()
                    && matches!(record.status.as_str(), "launching" | "launch_failed")
            });
            if (actor.status == ActorStatus::Healthy && session.is_none() && newly_registered_actor)
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
                            status.clone_into(&mut record.status);
                            record.updated_at_ms = now_ms()?;
                            self.store.upsert_session(record)?;
                            self.bind_launched_actor(&actor.actor_ref(), record)?;
                            self.heartbeat_actor(&actor.actor_ref(), "actor.reconciled_desired")?;
                            reused += 1;
                            continue;
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
        if let Some(path) = explicit {
            let canonical = fs::canonicalize(path).map_err(|error| {
                ControlError::io("canonicalize team working directory", path, &error)
            })?;
            let identity = WorkspaceIdentity::discover(&canonical)?;
            if identity.git_common_dir() != self.identity.git_common_dir() {
                return Err(ControlError::new(
                    "wrong_git_workspace",
                    "team working directory does not share this workspace's Git common directory",
                )
                .with_details(json!({ "path": canonical })));
            }
            let worktree_root = identity.root().to_path_buf();
            if worktree_root == self.identity.root() {
                return Err(ControlError::new(
                    "unsafe_working_directory",
                    "an implementation team must not write in the Primary worktree",
                )
                .with_details(json!({ "path": worktree_root })));
            }
            if let Some(conflict) = self.store.sessions()?.into_iter().find(|session| {
                session.working_directory == worktree_root
                    && session.team_id.as_deref() != Some(team_id.as_str())
            }) {
                return Err(ControlError::new(
                    "working_directory_conflict",
                    format!(
                        "team worktree is already owned by actor `{}`",
                        conflict.actor_id
                    ),
                )
                .with_details(json!({
                    "path": worktree_root,
                    "actor_id": conflict.actor_id,
                    "team_id": conflict.team_id,
                })));
            }
            return Ok(worktree_root);
        }
        let worktrees = self.settings.state_directory.join("worktrees");
        reject_managed_symlink(&worktrees)?;
        fs::create_dir_all(&worktrees).map_err(|error| {
            ControlError::io("create managed worktree directory", &worktrees, &error)
        })?;
        reject_managed_symlink(&worktrees)?;
        let target = worktrees.join(team_id.as_str());
        reject_managed_symlink(&target)?;
        if target.exists() {
            let canonical_target = fs::canonicalize(&target).map_err(|error| {
                ControlError::io("canonicalize managed worktree", &target, &error)
            })?;
            let identity = WorkspaceIdentity::discover(&canonical_target)?;
            if identity.git_common_dir() != self.identity.git_common_dir() {
                return Err(ControlError::new(
                    "unsafe_path",
                    "existing managed worktree path belongs to another Git repository",
                ));
            }
            if identity.root() != canonical_target {
                return Err(ControlError::new(
                    "unsafe_path",
                    "managed team path must be the root of its isolated Git worktree",
                ));
            }
            return Ok(canonical_target);
        }
        let output = Command::new("git")
            .arg("-C")
            .arg(self.identity.root())
            .args(["worktree", "add", "--detach"])
            .arg(&target)
            .arg("HEAD")
            .output()
            .map_err(|error| ControlError::io("create isolated Git worktree", &target, &error))?;
        if !output.status.success() {
            return Err(ControlError::new(
                "worktree_create_failed",
                format!(
                    "Git could not create the isolated worktree: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            ));
        }
        fs::canonicalize(&target)
            .map_err(|error| ControlError::io("canonicalize managed worktree", &target, &error))
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

    fn validate_session_record(
        &self,
        session: &mut SessionRecord,
        actor_ref: &ActorRef,
        team_id: &TeamId,
        expected_directory: &Path,
        expected_external_name: Option<&str>,
        runtime: &dyn AgentRuntime,
    ) -> Result<(), ControlError> {
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
        let directory_identity = WorkspaceIdentity::discover(&actual_directory)?;
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
            self.sessions.validate_expected_external_id(
                &session.backend,
                actor_ref.actor_id.as_str(),
                "recovered session",
                expected,
                session.external_id.as_deref(),
            )?;
        }
        if backfill_runtime {
            self.store.upsert_session(session)?;
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
        for team in preflight_supervisor.snapshot().teams {
            if let Err(error) = self.existing_team_working_directory(&team.team_id) {
                let failure = json!({
                    "team_id": team.team_id,
                    "phase": "working_directory_preflight",
                    "error": error.to_string(),
                    "error_code": error.code,
                    "details": error.details,
                });
                failures.push(failure.clone());
                conflicted_teams.insert(team.team_id, failure);
            }
        }
        for mut session in self.store.sessions()? {
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
                        session.launch_key == reconciliation_launch_operation_id(team_id, &actor_id)
                    })
                && session.external_id.is_none()
                && matches!(session.status.as_str(), "launching" | "launch_failed");
            if internally_managed_launch {
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
            session.status.clone_from(&status);
            session.updated_at_ms = now_ms()?;
            self.store.upsert_session(&session)?;
            let Some(actor) = actor else {
                continue;
            };
            let actor_ref = actor.actor_ref();
            if session_is_present(&status)
                && ((actor.team_id.is_none() && actor.status == ActorStatus::Healthy)
                    || (active_desired
                        && matches!(
                            actor.status,
                            ActorStatus::Starting | ActorStatus::Stale | ActorStatus::Healthy
                        )))
            {
                let _ = self.store.mutate(
                    "actor.reconciled_online",
                    &json!({ "actor_id": actor_id, "session_status": status }),
                    now_ms()?,
                    |state| {
                        state
                            .heartbeat(&actor_ref, TimestampMillis(now_ms()?))
                            .map_err(ControlError::core)
                    },
                )?;
                online += 1;
            } else if !session_is_present(&status) && actor.status == ActorStatus::Healthy {
                let _ = self.store.mutate(
                    "actor.reconciled_stale",
                    &json!({ "actor_id": actor_id, "session_status": status }),
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
        let runtime_config = RuntimeConfig::new(
            actor_profile.model.clone(),
            actor_profile.reasoning_effort.clone(),
        );
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
                session.resume_token = Some(token.to_owned());
                session.updated_at_ms = now_ms()?;
                self.store.upsert_session(session)?;
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
        self.store.upsert_session(session)?;
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
                self.store.upsert_session(&session)?;
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
            if recovered_source_epoch.is_none() && prior_session.replacement_in_progress() {
                return Err(ControlError::new(
                    "actor_replacement_in_progress",
                    format!("actor `{id}` already has an active launch or replacement intent"),
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
                pending.runtime = Some(runtime);
                self.store.upsert_session(&pending)?;
            }

            if pending.status == "replacement_pending" {
                if pending.external_id.is_some() {
                    self.sessions.stop(&pending)?;
                }
                self.sessions.name().clone_into(&mut pending.backend);
                pending.external_id = None;
                pending.resume_token = None;
                "launching".clone_into(&mut pending.status);
                pending.updated_at_ms = now_ms()?;
                self.store.upsert_session(&pending)?;
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
            let runtime_config = RuntimeConfig::new(
                actor_profile.model.clone(),
                actor_profile.reasoning_effort.clone(),
            );
            self.store.upsert_session(&pending)?;
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
                    pending.resume_token = Some(token.to_owned());
                    pending.updated_at_ms = now_ms()?;
                    self.store.upsert_session(&pending)?;
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
                    "launch_failed".clone_into(&mut pending.status);
                    pending.updated_at_ms = now_ms()?;
                    self.store.upsert_session(&pending)?;
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
            let session = SessionRecord {
                external_id: Some(handle.external_id),
                resume_token: handle.resume_token,
                status: "idle".to_owned(),
                updated_at_ms: now_ms()?,
                ..pending
            };
            self.store.upsert_session(&session)?;
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
                |state| apply_envelope(state, envelope.clone()),
            )?;
            self.notify_target(
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
            let base_sha = git_sha_for(&self.request_base_directory(&team_id)?)?;
            let (revision, (outcome, target)) = self.store.mutate(
                "request.created",
                &json!({ "request_id": request_id, "run_id": run_id, "team_id": team_id }),
                now_ms()?,
                |state| {
                    if let Some(existing) = state.delivery(&stable_message_id) {
                        let envelope = existing.envelope.clone();
                        let target = envelope.target.clone();
                        let outcome = apply_envelope(state, envelope)?;
                        return Ok((outcome, target));
                    }
                    let primary = active_primary_actor(state)?;
                    let team = state
                        .team(&team_id)
                        .ok_or_else(|| ControlError::not_found("team", &args.team))?;
                    if team.status != TeamStatus::Active {
                        return Err(ControlError::new(
                            "team_inactive",
                            "team must be active to receive work",
                        ));
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
                            acceptance_criteria: vec![instructions.clone()],
                            evidence_requirements: vec![EvidenceKind::Git, EvidenceKind::Test],
                        }),
                        stable_message_id.clone(),
                    )?;
                    let outcome = apply_envelope(state, envelope)?;
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
            Ok(json!({
                "request": updated.request(&request_id),
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
                |state| apply_envelope(state, envelope.clone()),
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
            verify_candidate_head(&candidate_directory, &item.specification.base_sha, &sha)?;
            let candidate = Candidate {
                request_id: request_id.clone(),
                team_id: item.team_id.clone(),
                sha,
                created_by: actor.actor_ref(),
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
                |state| apply_envelope(state, envelope.clone()),
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
        self.idempotent("message.send", request, &args.operation_id, || {
            let (_, supervisor, _) = self.store.load()?;
            let sender = self.resolve_actor(None)?;
            let kind = args.kind.to_ascii_lowercase().replace('-', "_");
            args.validate_for(&kind)?;
            let stable_message_id = message_id(&args.operation_id, "send");
            if let Some(existing) = supervisor.delivery(&stable_message_id) {
                if existing.envelope.sender != sender.actor_ref() {
                    return Err(ControlError::new(
                        "message_retry_sender_mismatch",
                        "only the original authenticated actor generation may retry this message",
                    ));
                }
                let envelope = existing.envelope.clone();
                let target = envelope.target.clone();
                let sent_message = envelope.message.clone();
                let (revision, outcome) = self.store.mutate(
                    "message.sent",
                    &json!({ "message_id": stable_message_id, "kind": kind }),
                    now_ms()?,
                    |state| apply_envelope(state, envelope.clone()),
                )?;
                self.notify_target(
                    &target,
                    &format!(
                        "New durable AGSV `{kind}` message `{stable_message_id}` is waiting in your inbox."
                    ),
                )?;
                return Ok(json!({
                    "message_id": stable_message_id,
                    "message": sent_message,
                    "outcome": apply_name(outcome),
                    "revision": revision,
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
                    let Message::ConsultationRequest(request) = &consultation.envelope.message else {
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
                        "supported kinds are progress, blocker, consultation_request, consultation_response, dependency_notice, conflict_notice, handoff_offer, handoff_acceptance, qa_result, integration_complete, and fix_request",
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
            let message_id = envelope.message_id.clone();
            let sent_message = envelope.message.clone();
            let target = envelope.target.clone();
            let (revision, outcome) = self.store.mutate(
                "message.sent",
                &json!({ "message_id": message_id, "kind": kind }),
                now_ms()?,
                |state| apply_envelope(state, envelope.clone()),
            )?;
            self.notify_target(
                &target,
                &format!(
                    "New durable AGSV `{kind}` message `{message_id}` is waiting in your inbox."
                ),
            )?;
            Ok(json!({
                "message_id": message_id,
                "message": sent_message,
                "outcome": apply_name(outcome),
                "revision": revision,
            }))
        })
    }
    fn message_inbox(&self, request: &Value) -> Result<Value, ControlError> {
        let args: MessageInboxArgs = decode(request)?;
        let authenticated = self.resolve_actor(args.actor.as_deref())?;
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&authenticated.actor_id)
            .filter(|actor| actor.epoch == authenticated.epoch)
            .ok_or_else(|| ControlError::new("stale_actor_binding", "actor generation is stale"))?;
        let actor_ref = actor.actor_ref();
        let deliveries = if args.include_acked {
            supervisor
                .snapshot()
                .deliveries
                .into_iter()
                .filter(|delivery| {
                    target_matches(
                        &delivery.envelope.target,
                        actor,
                        supervisor.active_primary().as_ref(),
                    )
                })
                .collect::<Vec<_>>()
        } else {
            supervisor
                .unacknowledged_for(&actor_ref)
                .map_err(ControlError::core)?
                .into_iter()
                .map(|envelope| json!({ "envelope": envelope, "acknowledgements": [] }))
                .map(|value| serde_json::from_value(value).map_err(ControlError::database))
                .collect::<Result<Vec<agsv_protocol::DeliverySnapshot>, _>>()?
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
                |state| acknowledge(state, acknowledgement.clone()),
            )?;
            Ok(json!({ "message_id": message_id, "outcome": ack_name(outcome), "revision": revision }))
        })
    }
    fn decision_submit(&self, request: &Value) -> Result<Value, ControlError> {
        let args: DecisionSubmitArgs = decode(request)?;
        self.idempotent("decision.submit", request, &args.operation_id, || {
            let request_id =
                RequestId::new(args.request.clone()).map_err(ControlError::protocol)?;
            let sha = GitSha::new(args.candidate_sha).map_err(ControlError::protocol)?;
            let (_, supervisor, _) = self.store.load()?;
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
            let decision = ReviewDecision {
                decision_id: decision_id.clone(),
                candidate: candidate.clone(),
                verdict,
                reviewer: primary.clone(),
                policy_revision: supervisor.policy_revision(),
                rationale: args.summary.unwrap_or_else(|| enum_name(verdict)),
                evidence: Vec::new(),
            };
            let target = MessageTarget::Actor(
                item.assignment
                    .as_ref()
                    .ok_or_else(|| ControlError::invalid_request("request is unassigned"))?
                    .actor
                    .actor_id
                    .clone(),
            );
            let (review_envelope, _) = request_envelope(
                &supervisor,
                &request_id,
                primary.clone(),
                target.clone(),
                Message::ReviewDecision(decision.clone()),
                message_id(&args.operation_id, "decision"),
            )?;
            let authorization =
                (verdict == ReviewVerdict::Accepted).then(|| IntegrationAuthorization {
                    decision_id: decision_id.clone(),
                    candidate: candidate.clone(),
                    authorized_by: primary.clone(),
                });
            let (revision, ()) = self.store.mutate(
                "decision.submitted",
                &json!({ "request_id": request_id, "decision": decision }),
                now_ms()?,
                |state| {
                    apply_envelope(state, review_envelope.clone())?;
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
                        apply_envelope(state, auth_envelope)?;
                    }
                    Ok(())
                },
            )?;
            self.notify_target(
                &target,
                &format!(
                    "AGSV review decision `{decision_id}` for request `{request_id}` is waiting in your inbox."
                ),
            )?;
            Ok(json!({
                "decision": decision,
                "integration_authorization": authorization,
                "revision": revision,
            }))
        })
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
                Message::Cancellation(Cancellation { reason: reason.to_owned() }),
                message_id(operation_id, "cancel"),
            )?;
            let (revision, outcome) = self.store.mutate(
                operation,
                &json!({ "request_id": request_id, "reason": reason }),
                now_ms()?,
                |state| apply_envelope(state, envelope.clone()),
            )?;
            self.notify_target(
                &target,
                &format!("AGSV request `{request_id}` was cancelled; read your durable inbox."),
            )?;
            Ok(json!({ "request_id": request_id, "run_id": run_id, "outcome": apply_name(outcome), "revision": revision }))
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
    purpose: Option<String>,
    working_directory: Option<PathBuf>,
    #[serde(default = "default_orchestrators")]
    orchestrators: u16,
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
    operation_id: String,
}

const fn default_event_limit() -> u32 {
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

fn primary_operation(operation: &str) -> bool {
    matches!(
        operation,
        "stop"
            | "reconcile"
            | "team.create"
            | "team.update"
            | "team.pause"
            | "team.resume"
            | "actor.stop"
            | "actor.replace"
            | "run.create"
            | "run.pause"
            | "run.resume"
            | "run.cancel"
            | "request.create"
            | "request.cancel"
            | "decision.submit"
    )
}

fn presentation_refresh_operation(operation: &str) -> bool {
    matches!(
        operation,
        "context"
            | "reconcile"
            | "team.create"
            | "team.update"
            | "team.pause"
            | "team.resume"
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

fn force_presentation_refresh(operation: &str, request: &Value) -> bool {
    matches!(
        operation,
        "reconcile" | "team.create" | "team.resume" | "actor.replace"
    ) || (operation == "context"
        && request
            .get("bootstrap")
            .and_then(Value::as_bool)
            .unwrap_or(false))
}

fn actor_operation(operation: &str) -> bool {
    matches!(
        operation,
        "request.claim"
            | "request.block"
            | "request.complete"
            | "message.send"
            | "message.inbox"
            | "message.ack"
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

fn reconciliation_launch_operation_id(team_id: &TeamId, actor_id: &ActorId) -> String {
    stable_id("reconcile-launch", &format!("{team_id}:{actor_id}"))
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
    let envelope = make_envelope(
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

fn acknowledge(
    supervisor: &mut Supervisor,
    mut acknowledgement: Acknowledgement,
) -> Result<AckOutcome, ControlError> {
    if let Some(existing) = supervisor
        .delivery(&acknowledgement.message_id)
        .and_then(|delivery| {
            delivery
                .acknowledgements
                .get(&acknowledgement.actor.actor_id)
        })
    {
        acknowledgement.acknowledged_at = existing.acknowledged_at;
    }
    supervisor
        .acknowledge(acknowledgement)
        .map_err(ControlError::core)
}

fn git_sha_for(directory: &Path) -> Result<GitSha, ControlError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
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

fn verify_candidate_head(
    directory: &Path,
    base_sha: &GitSha,
    sha: &GitSha,
) -> Result<(), ControlError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
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
    let head = git_sha_for(directory)?;
    if &head != sha {
        return Err(ControlError::new(
            "candidate_not_worktree_head",
            format!("candidate {sha} is not the current HEAD {head} of the assigned worktree"),
        )
        .with_details(json!({ "candidate_sha": sha, "head_sha": head, "path": directory })));
    }
    let ancestry = Command::new("git")
        .arg("-C")
        .arg(directory)
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    use super::{
        ActorProfileSettings, ControlPlane, ControlSettings, LEGACY_IMPLEMENTATION_PROFILE,
        LEGACY_RUNTIME_ID, ProfileMode, RuntimeCatalog, TeamProfileSettings,
        activate_primary_for_profile, apply_envelope, ensure_team_actor, ensure_team_profile,
        implementation_prompt, session_name, shell_single_quote,
    };
    use crate::backend::{LAYOUT_FAILURE_BACKEND_ID, SessionDriver};
    use crate::store::SessionRecord;
    use agsv_core::{ApplyOutcome, Supervisor};
    use agsv_protocol::{
        ActorEpoch, ActorId, ActorRef, ActorStatus, Envelope, EvidenceKind, GitSha,
        ImplementationRequest, Message, MessageId, MessageTarget, PROTOCOL_VERSION, PolicyRevision,
        PrimaryEpoch, ProgressUpdate, RequestId, RunId, TeamId, TeamStatus, TimestampMillis,
        WorkspaceId,
    };
    use agsv_runtime::{
        AdapterError, AgentRuntime, CapabilitySupport, InitialPromptDelivery, RuntimeCapabilities,
        RuntimeDiagnostics, RuntimeId, RuntimeInvocation, RuntimeLaunchPolicy,
        RuntimeLaunchRequest, RuntimeRegistry, RuntimeResumeRequest,
    };
    use agsv_session::{SessionPlacement, SplitDirection};
    use serde_json::json;

    struct FixtureRuntime {
        id: RuntimeId,
        launch_count: AtomicU64,
        launch_block: Option<Arc<LaunchBlock>>,
    }

    struct LaunchBlock {
        target_launch: u64,
        entered: Barrier,
        release: Barrier,
    }

    impl LaunchBlock {
        fn new(target_launch: u64) -> Self {
            Self {
                target_launch,
                entered: Barrier::new(2),
                release: Barrier::new(2),
            }
        }
    }

    struct LaunchReleaseGuard(Arc<LaunchBlock>);

    impl Drop for LaunchReleaseGuard {
        fn drop(&mut self) {
            self.0.release.wait();
        }
    }

    impl FixtureRuntime {
        fn new() -> Self {
            Self::with_id("fixture-runtime")
        }

        fn with_id(id: &str) -> Self {
            Self {
                id: RuntimeId::new(id).unwrap(),
                launch_count: AtomicU64::new(0),
                launch_block: None,
            }
        }

        fn with_blocked_launch(id: &str, launch_block: Arc<LaunchBlock>) -> Self {
            Self {
                id: RuntimeId::new(id).unwrap(),
                launch_count: AtomicU64::new(0),
                launch_block: Some(launch_block),
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
            let launch_number = self.launch_count.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(block) = &self.launch_block
                && launch_number == block.target_launch
            {
                block.entered.wait();
                block.release.wait();
            }
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
            runtime: runtime.to_owned(),
            model: "gpt-test".to_owned(),
            reasoning_effort: "max".to_owned(),
            role_file: PathBuf::from("roles/primary.md"),
            role_instructions: "primary".to_owned(),
            role_source: "builtin".to_owned(),
        };
        let implementation = ActorProfileSettings {
            name: "implementation".to_owned(),
            role: "implementation".to_owned(),
            capabilities: BTreeSet::from(["implementation_execution".to_owned()]),
            runtime: runtime.to_owned(),
            model: "gpt-test".to_owned(),
            reasoning_effort: "max".to_owned(),
            role_file: PathBuf::from("roles/implementation.md"),
            role_instructions: "implementation".to_owned(),
            role_source: "builtin".to_owned(),
        };
        ControlSettings {
            workspace: root,
            state_directory,
            config_source: "builtin".to_owned(),
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
            max_panes_per_tab: 2,
            place_first_implementation_with_primary: true,
            tab_label_strategy: "sequence".to_owned(),
            pane_label_template: "{session_label}".to_owned(),
            split_direction: "right".to_owned(),
            focus_new_sessions: false,
            primary_lease_seconds: 3_600,
            actor_heartbeat_seconds: 300,
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
        activate_test_primary(&plane, "primary-zero");

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
        assert!(plane.store.sessions().unwrap().is_empty());
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
        let operation_id = super::reconciliation_launch_operation_id(&team_id, &actor_id);
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
        research_profile.runtime = runtime_b.id().to_string();
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
    fn blocked_desired_launch_rejects_concurrent_reconcile_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        let team_root = temporary.path().join("team-worktree");
        init_test_repository(&root, &team_root);
        let launch_block = Arc::new(LaunchBlock::new(2));
        let runtime = Arc::new(FixtureRuntime::with_blocked_launch(
            LEGACY_RUNTIME_ID,
            launch_block.clone(),
        ));
        let settings = profiled_settings(
            root,
            temporary.path().join("state"),
            runtime.id().as_str(),
            2,
            "first_healthy",
        );
        let setup = open_fixture_plane(settings.clone(), &runtime);
        let team_id = TeamId::new("team-workers").unwrap();
        let first_id = ActorId::new("impl-workers-1").unwrap();
        let second_id = ActorId::new("impl-workers-2").unwrap();
        let team_profile = setup.selected_team_profile().unwrap().snapshot().unwrap();
        let actor_profile = setup.selected_team_actor_profile().unwrap().clone();
        setup
            .store
            .mutate("test.launch_replace_race_team", &json!({}), 1, |state| {
                state
                    .create_team_with_profile(team_id.clone(), team_profile.clone())
                    .map_err(super::ControlError::core)
            })
            .unwrap();
        let (first_ref, _, _) = setup
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

        let launch_plane = open_fixture_plane(settings.clone(), &runtime);
        let replace_plane = open_fixture_plane(settings, &runtime);
        let launch_thread = std::thread::spawn(move || launch_plane.reconcile());
        launch_block.entered.wait();
        let release_guard = LaunchReleaseGuard(launch_block.clone());

        let mut pending = replace_plane
            .store
            .session(second_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(pending.status, "launching");
        assert_eq!(
            pending.launch_key,
            super::reconciliation_launch_operation_id(&team_id, &second_id)
        );
        assert!(!pending.launch_key.starts_with("replacement:"));
        pending.runtime = None;
        replace_plane.store.upsert_session(&pending).unwrap();
        let (_, during_launch, _) = replace_plane.store.load().unwrap();
        let second_ref = during_launch.actor(&second_id).unwrap().actor_ref();
        assert_eq!(second_ref.actor_epoch, ActorEpoch::INITIAL);
        replace_plane
            .store
            .mutate("test.launch_replace_race_stale", &json!({}), 2, |state| {
                state
                    .set_actor_status(&second_ref, ActorStatus::Stale)
                    .map_err(super::ControlError::core)
            })
            .unwrap();

        let replacement = replace_plane.actor_replace(&json!({
            "id": second_id,
            "reason": "concurrent reconcile observed a stale desired actor",
            "operation_id": "concurrent-reconcile-replacement",
        }));
        let preserved_pending = replace_plane
            .store
            .session(second_id.as_str())
            .unwrap()
            .unwrap();
        drop(release_guard);
        let reconciled = launch_thread.join().unwrap().unwrap();

        let replacement = replacement.unwrap_err();
        assert_eq!(replacement.code, "actor_replacement_in_progress");
        assert_eq!(preserved_pending.status, "launching");
        assert_eq!(preserved_pending.launch_key, pending.launch_key);
        assert_eq!(preserved_pending.runtime, None);
        assert_eq!(preserved_pending.external_id, pending.external_id);
        assert_eq!(preserved_pending.resume_token, pending.resume_token);
        assert_eq!(preserved_pending.updated_at_ms, pending.updated_at_ms);
        assert_eq!(reconciled["complete"], true);
        assert_eq!(reconciled["instance_reconciliation"][0]["launched"], 1);
        assert_eq!(reconciled["instance_reconciliation"][0]["replaced"], 0);
        assert_eq!(runtime.launch_count(), 2);
        let (_, supervisor, _) = replace_plane.store.load().unwrap();
        assert_eq!(supervisor.actor(&first_id).unwrap().actor_ref(), first_ref);
        assert_eq!(
            supervisor.actor(&second_id).unwrap().actor_ref(),
            second_ref
        );
        assert_eq!(
            supervisor.actor(&second_id).unwrap().status,
            ActorStatus::Healthy
        );
        let session = replace_plane
            .store
            .session(second_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(session.status, "idle");
        assert_eq!(session.launch_key, pending.launch_key);
        assert_eq!(runtime.launch_count(), 2);
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
                base_sha: super::git_sha_for(&team_root).unwrap(),
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
        let stopped = plane.reconcile().unwrap();
        assert_eq!(stopped["complete"], true);
        assert_eq!(stopped["instance_reconciliation"][0]["stopped"], 1);
        let (_, supervisor, _) = plane.store.load().unwrap();
        assert!(
            supervisor
                .request(&request_id)
                .unwrap()
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
            profile.runtime = "fixture-runtime".to_owned();
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
        actor_profile_b.runtime = runtime_b.id().to_string();
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

    fn run_git(root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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
}
