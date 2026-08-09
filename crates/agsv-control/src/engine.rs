use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::backend::SessionDriver;
use crate::caller::{CallerBinding, CallerIdentityDriver, InsecureActorIdentity};
use crate::identity::sha256_hex;
use crate::store::{SessionRecord, StateStore};
use crate::{ControlError, WorkspaceIdentity};
use agsv_core::{AckOutcome, ApplyOutcome, Supervisor};
use agsv_protocol::{
    Acknowledgement, Actor, ActorId, ActorRef, ActorRole, ActorStatus, AssignmentEpoch,
    BlockerNotice, Cancellation, Candidate, CandidateReady, ConflictNotice, ConsultationRequest,
    ConsultationResponse, DecisionId, DependencyNotice, Envelope, EvidenceKind, FixRequest, GitSha,
    HandoffAcceptance, HandoffId, HandoffOffer, ImplementationRequest, IntegrationAuthorization,
    IntegrationComplete, Message, MessageId, MessageTarget, PROTOCOL_VERSION, PolicyRevision,
    ProgressUpdate, QaOutcome, QaResult, RequestId, ReviewDecision, ReviewVerdict, RunControl,
    RunControlAction, RunId, TeamId, TeamStatus, TimestampMillis,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

static NEXT_OPERATION_CLAIM: AtomicU64 = AtomicU64::new(1);

/// Effective, already validated inputs supplied by the CLI configuration layer.
#[derive(Clone, Debug)]
pub struct ControlSettings {
    pub workspace: PathBuf,
    pub state_directory: PathBuf,
    pub config_source: String,
    pub primary_role: String,
    pub implementation_role: String,
    pub backend: String,
    pub model: String,
    pub reasoning_effort: String,
    pub primary_lease_seconds: u32,
    pub actor_heartbeat_seconds: u32,
}

/// One invocation's embedded control-plane handle.
pub struct ControlPlane {
    settings: ControlSettings,
    identity: WorkspaceIdentity,
    store: StateStore,
    sessions: SessionDriver,
    caller_identity: CallerIdentityDriver,
}

impl ControlPlane {
    /// Opens or initializes durable state without modifying the repository worktree.
    ///
    /// # Errors
    ///
    /// Returns an error when workspace discovery, path validation, or state
    /// initialization fails.
    pub fn open(mut settings: ControlSettings) -> Result<Self, ControlError> {
        let identity = WorkspaceIdentity::discover(&settings.workspace)?;
        settings.workspace = identity.root().to_path_buf();
        if let Ok(value) = std::env::var("AGSV_SESSION_BACKEND") {
            settings.backend = value;
        }
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
        match operation {
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
        }
    }

    #[must_use]
    pub fn identity(&self) -> &WorkspaceIdentity {
        &self.identity
    }

    #[must_use]
    pub fn state_path(&self) -> &Path {
        self.store.path()
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
        let snapshot = supervisor.snapshot();
        Ok(json!({
            "mode": "embedded",
            "active": active,
            "workspace_id": self.identity.workspace_id(),
            "workspace": self.identity.root(),
            "git_common_dir": self.identity.git_common_dir(),
            "config_source": self.settings.config_source,
            "state_path": self.store.path(),
            "revision": revision,
            "primary": snapshot.active_primary,
            "primary_epoch": snapshot.primary_epoch,
            "counts": {
                "teams": snapshot.teams.len(),
                "actors": snapshot.actors.len(),
                "runs": snapshot.runs.len(),
                "requests": snapshot.requests.len(),
                "deliveries": snapshot.deliveries.len(),
            },
        }))
    }

    fn doctor(&self) -> Result<Value, ControlError> {
        let session = self.sessions.diagnostics();
        let caller_context = self.doctor_caller_context()?;
        let backend_runtime_reachable = session
            .pointer("/backend_runtime/reachable")
            .and_then(Value::as_bool);
        let lifecycle_backend_ready = session["ready"].as_bool() == Some(true);
        let healthy = lifecycle_backend_ready
            && session["codex"]["available"].as_bool() == Some(true)
            && caller_context["ready"].as_bool() == Some(true);
        Ok(json!({
            "healthy": healthy,
            "mode": "embedded",
            "journal_mode": self.store.journal_mode()?,
            "config_source": self.settings.config_source,
            "state_path": self.store.path(),
            "lifecycle_backend": session.clone(),
            "session": session,
            "lifecycle_backend_ready": lifecycle_backend_ready,
            "backend_runtime_reachable": backend_runtime_reachable,
            "caller_identity": caller_context.clone(),
            "caller_context": caller_context,
            "launch": {
                "runtime": "codex",
                "model": self.settings.model,
                "reasoning_effort": self.settings.reasoning_effort,
                "sandbox": "workspace-write",
                "approval": "approve-for-me",
            },
            "enforcement": {
                "core": ["authorization", "state_transitions", "idempotency", "fencing", "exact_candidate_sha"],
                "control_plane": ["durable_session_actor_binding", "primary_caller_authentication", "authenticated_heartbeats", "lease_expiry"],
                "launch": ["runtime", "model", "reasoning_effort", "working_directory", "sandbox"],
                "provider": ["approve_for_me"],
                "instructed_observed": ["provider_native_subagent_topology", "fresh_review", "read_only_review", "provider_process_pause"],
            },
            "leases": {
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
                        && (actor.role != ActorRole::Primary
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
        Ok(json!({
            "control_events": self.store.events(args.limit)?,
            "protocol_events": supervisor.audit_events(),
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
        let role = match actor.role {
            ActorRole::Primary => &self.settings.primary_role,
            ActorRole::Implementation => &self.settings.implementation_role,
        };
        let snapshot = supervisor.snapshot();
        Ok(json!({
            "actor": actor,
            "actor_ref": actor_ref,
            "role": role,
            "role_source": self.settings.config_source,
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
        Ok(json!({ "teams": supervisor.snapshot().teams }))
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
            "team": team,
            "actors": snapshot.actors.into_iter().filter(|actor| actor.team_id.as_ref() == Some(&id)).collect::<Vec<_>>(),
            "requests": snapshot.requests.into_iter().filter(|item| item.team_id == id).collect::<Vec<_>>(),
            "sessions": self.store.sessions()?.into_iter().filter(|item| item.team_id.as_deref() == Some(args.id.as_str())).collect::<Vec<_>>(),
        }))
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
            Ok(json!({
                "team_id": id,
                "status": status,
                "scope": "protocol_admission",
                "provider_process_suspended": false,
                "revision": revision,
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
            if actor.role == ActorRole::Primary {
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
        let Some(actor) = supervisor
            .actor(&actor_ref.actor_id)
            .filter(|actor| actor.epoch == actor_ref.actor_epoch)
        else {
            return Err(ControlError::new(
                "stale_actor_binding",
                "the Primary notification endpoint belongs to a stale actor generation",
            ));
        };
        if actor.role != ActorRole::Primary {
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
        supervisor
            .actor(&actor_ref.actor_id)
            .filter(|actor| actor.epoch == actor_ref.actor_epoch)
            .cloned()
            .ok_or_else(|| {
                ControlError::new(
                    "stale_actor_binding",
                    "the authenticated session is bound to a stale actor generation",
                )
            })
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
                if actor.role != ActorRole::Primary
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
            if actor.role == ActorRole::Primary && supervisor.active_primary().is_none() {
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
        let observed_at = now_ms()?;
        let (_, actor_ref) = self.store.mutate(
            "primary.bootstrapped",
            &json!({ "actor_id": actor_id }),
            observed_at,
            |state| {
                if let Some(active) = state.active_primary()
                    && active.actor_id != *actor_id
                {
                    return Err(primary_lease_held(&active.actor_id));
                }
                let actor_ref = state
                    .activate_primary(actor_id.clone())
                    .map_err(ControlError::core)?;
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
        if actor.role != ActorRole::Primary
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
        let ttl_seconds = match actor.role {
            ActorRole::Primary => u64::from(self.settings.primary_lease_seconds),
            ActorRole::Implementation => {
                u64::from(self.settings.actor_heartbeat_seconds).saturating_mul(3)
            }
        };
        let ttl_ms = ttl_seconds.saturating_mul(1_000);
        actor
            .last_heartbeat_at
            .is_none_or(|last| observed_at.saturating_sub(last.0) >= ttl_ms)
    }

    fn insecure_debug_identity_selected(&self) -> bool {
        self.caller_identity.insecure_debug_selected()
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
            let working_directory =
                self.ensure_team_directory(&team_id, args.working_directory.as_deref())?;
            let actor_ids = (1..=args.orchestrators)
                .map(|index| ActorId::new(format!("impl-{}-{index}", slug(&args.name))))
                .collect::<Result<Vec<_>, _>>()
                .map_err(ControlError::protocol)?;
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
            let (revision, actor_refs) = self.store.mutate(
                "team.created",
                &json!({
                    "team_id": team_id,
                    "working_directory": working_directory,
                    "orchestrators": args.orchestrators,
                }),
                now_ms()?,
                |state| {
                    state
                        .create_team(team_id.clone())
                        .map_err(ControlError::core)?;
                    let actor_refs = actor_ids
                        .iter()
                        .map(|actor_id| {
                            if let Some(actor) = state.actor(actor_id) {
                                if actor.role == ActorRole::Implementation
                                    && actor.team_id.as_ref() == Some(&team_id)
                                    && actor.status == ActorStatus::Healthy
                                {
                                    return Ok(actor.actor_ref());
                                }
                                state
                                    .replace_implementation(&team_id, actor_id.clone())
                                    .map_err(ControlError::core)
                            } else {
                                state
                                    .register_implementation(&team_id, actor_id.clone())
                                    .map_err(ControlError::core)
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let observed_at = TimestampMillis(now_ms()?);
                    for actor_ref in &actor_refs {
                        state
                            .heartbeat(actor_ref, observed_at)
                            .map_err(ControlError::core)?;
                    }
                    Ok(actor_refs)
                },
            )?;

            let mut sessions = Vec::new();
            let mut reused = true;
            for actor_ref in &actor_refs {
                let existing_session = self.store.session(actor_ref.actor_id.as_str())?;
                if let Some(existing) = existing_session.as_ref() {
                    let expected_name =
                        session_name(self.identity.workspace_id().as_str(), actor_ref);
                    self.validate_session_record(
                        existing,
                        actor_ref,
                        &team_id,
                        &working_directory,
                        Some(&expected_name),
                    )?;
                    if existing.external_id.is_some() {
                        let status = self.sessions.status(existing)?;
                        if matches!(
                            status.as_str(),
                            "starting" | "working" | "idle" | "blocked" | "unknown"
                        ) {
                            self.bind_launched_actor(actor_ref, existing)?;
                            sessions.push(existing.clone());
                            continue;
                        }
                    }
                }
                let launch_key = format!(
                    "{}:{}:{}",
                    args.operation_id, actor_ref.actor_id, actor_ref.actor_epoch
                );
                reused = false;
                let prompt =
                    implementation_prompt(&self.settings.implementation_role, actor_ref, &team_id)?;
                let native_args = codex_args(&self.settings);
                let session_name = session_name(self.identity.workspace_id().as_str(), actor_ref);
                let mut pending = SessionRecord {
                    actor_id: actor_ref.actor_id.to_string(),
                    team_id: Some(team_id.to_string()),
                    working_directory: working_directory.clone(),
                    backend: self.sessions.name().to_owned(),
                    external_id: None,
                    resume_token: existing_session
                        .as_ref()
                        .filter(|session| session.backend == self.sessions.name())
                        .and_then(|session| session.resume_token.clone()),
                    status: "launching".to_owned(),
                    launch_key: launch_key.clone(),
                    updated_at_ms: now_ms()?,
                };
                self.store.upsert_session(&pending)?;
                let recovered_token = pending.resume_token.clone();
                let launch = {
                    let mut checkpoint = |token: &str| {
                        pending.resume_token = Some(token.to_owned());
                        pending.updated_at_ms = now_ms()?;
                        self.store.upsert_session(&pending)?;
                        self.bind_launched_actor(actor_ref, &pending)
                    };
                    self.sessions.launch_with_initial_prompt(
                        actor_ref.actor_id.as_str(),
                        &session_name,
                        &working_directory,
                        &launch_key,
                        native_args,
                        Some(prompt),
                        recovered_token,
                        &mut checkpoint,
                    )
                };
                match launch {
                    Ok(handle) => {
                        self.validate_launched_handle(actor_ref, &session_name, &handle)?;
                        let record = SessionRecord {
                            external_id: Some(handle.external_id),
                            resume_token: handle.resume_token,
                            status: "idle".to_owned(),
                            ..pending
                        };
                        self.store.upsert_session(&record)?;
                        self.bind_launched_actor(actor_ref, &record)?;
                        sessions.push(record);
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
                        return Err(error);
                    }
                }
            }
            Ok(json!({
                "team_id": team_id,
                "working_directory": working_directory,
                "actors": actor_refs,
                "sessions": sessions,
                "revision": revision,
                "reused": reused,
            }))
        })
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
        session: &SessionRecord,
        actor_ref: &ActorRef,
        team_id: &TeamId,
        expected_directory: &Path,
        expected_external_name: Option<&str>,
    ) -> Result<(), ControlError> {
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
                },
                "actual": {
                    "actor_id": session.actor_id,
                    "team_id": session.team_id,
                    "working_directory": actual_directory,
                    "backend": session.backend,
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
        Ok(())
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

    fn reconcile(&self) -> Result<Value, ControlError> {
        let mut checked = 0_u64;
        let mut online = 0_u64;
        let mut offline = 0_u64;
        let mut failures = Vec::new();
        for mut session in self.store.sessions()? {
            checked += 1;
            if session.external_id.is_none()
                && matches!(session.status.as_str(), "launching" | "launch_failed")
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
            let actor_id =
                ActorId::new(session.actor_id.clone()).map_err(ControlError::protocol)?;
            let (_, supervisor, _) = self.store.load()?;
            let Some(actor) = supervisor.actor(&actor_id) else {
                continue;
            };
            let actor_ref = actor.actor_ref();
            if matches!(
                status.as_str(),
                "starting" | "working" | "idle" | "blocked" | "unknown"
            ) {
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
            } else if actor.status == ActorStatus::Healthy {
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
        Ok(json!({
            "sessions_checked": checked,
            "actors_marked_online": online,
            "actors_marked_stale": offline,
            "failures": failures,
            "complete": failures.is_empty(),
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
        let actor_ref = supervisor
            .actor(&actor_id)
            .ok_or_else(|| ControlError::not_found("actor", actor_id.as_str()))?
            .actor_ref();
        let expected_name = session_name(self.identity.workspace_id().as_str(), &actor_ref);
        self.validate_session_record(
            session,
            &actor_ref,
            &team_id,
            &session.working_directory,
            Some(&expected_name),
        )?;
        let prompt =
            implementation_prompt(&self.settings.implementation_role, &actor_ref, &team_id)?;
        let launch_directory = session.working_directory.clone();
        let backend_id = session.backend.clone();
        let launch_key = session.launch_key.clone();
        let recovered_token = session.resume_token.clone();
        let handle = {
            let mut checkpoint = |token: &str| {
                session.resume_token = Some(token.to_owned());
                session.updated_at_ms = now_ms()?;
                self.store.upsert_session(session)?;
                self.bind_launched_actor(&actor_ref, session)
            };
            self.sessions.launch_with_initial_prompt_for(
                &backend_id,
                actor_id.as_str(),
                &expected_name,
                &launch_directory,
                &launch_key,
                codex_args(&self.settings),
                Some(prompt),
                recovered_token,
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
            let team_id = actor.team_id.clone().ok_or_else(|| {
                ControlError::unsupported(
                    "actor.replace",
                    "the Primary is replaced by bootstrap fencing",
                )
            })?;
            let prior_session = self.store.session(&args.id)?.ok_or_else(|| {
                ControlError::new(
                    "session_not_found",
                    "replacement needs the actor working directory",
                )
            })?;
            let recovered_source_epoch =
                replacement_source_epoch(&prior_session.launch_key, &args.operation_id);
            if recovered_source_epoch.is_none()
                && prior_session.launch_key.starts_with("replacement:")
                && matches!(
                    prior_session.status.as_str(),
                    "replacement_pending" | "launching" | "launch_failed"
                )
            {
                return Err(ControlError::new(
                    "actor_replacement_in_progress",
                    format!("actor `{id}` already has a durable replacement intent"),
                )
                .with_hint("retry the original actor replacement operation ID"));
            }
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
                self.validate_session_record(
                    &prior_session,
                    &actor.actor_ref(),
                    &team_id,
                    &prior_session.working_directory,
                    Some(&expected_name),
                )?;
                self.store
                    .claim_replacement_intent(id.as_str(), &intent_key, now_ms()?)?
            };

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
            self.validate_session_record(
                &pending,
                &actor_ref,
                &team_id,
                &pending.working_directory,
                None,
            )?;
            if pending.status == "idle" && pending.external_id.is_some() {
                self.validate_session_record(
                    &pending,
                    &actor_ref,
                    &team_id,
                    &pending.working_directory,
                    Some(&expected_name),
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
            let prompt =
                implementation_prompt(&self.settings.implementation_role, &actor_ref, &team_id)?;
            self.store.upsert_session(&pending)?;
            let launch_directory = pending.working_directory.clone();
            let backend_id = pending.backend.clone();
            let launch_key_value = pending.launch_key.clone();
            let recovered_token = pending.resume_token.clone();
            let launch = {
                let mut checkpoint = |token: &str| {
                    pending.resume_token = Some(token.to_owned());
                    pending.updated_at_ms = now_ms()?;
                    self.store.upsert_session(&pending)?;
                    self.bind_launched_actor(&actor_ref, &pending)
                };
                self.sessions.launch_with_initial_prompt_for(
                    &backend_id,
                    actor_ref.actor_id.as_str(),
                    &expected_name,
                    &launch_directory,
                    &launch_key_value,
                    codex_args(&self.settings),
                    Some(prompt),
                    recovered_token,
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
            let (_, supervisor, _) = self.store.load()?;
            let primary = active_primary_actor(&supervisor)?;
            let team = supervisor
                .team(&team_id)
                .ok_or_else(|| ControlError::not_found("team", &args.team))?;
            if team.status != TeamStatus::Active {
                return Err(ControlError::new(
                    "team_inactive",
                    "team must be active to receive work",
                ));
            }
            let actor = team
                .actors
                .iter()
                .filter_map(|id| supervisor.actor(id))
                .find(|actor| actor.status == ActorStatus::Healthy)
                .ok_or_else(|| {
                    ControlError::new(
                        "no_healthy_actor",
                        "team has no healthy implementation actor",
                    )
                })?;
            let request_id = RequestId::new(stable_id("request", &args.operation_id))
                .map_err(ControlError::protocol)?;
            let run_id =
                RunId::new(stable_id("run", &args.operation_id)).map_err(ControlError::protocol)?;
            let base_sha = git_sha_for(
                self.store
                    .session(actor.actor_id.as_str())?
                    .as_ref()
                    .map_or(self.identity.root(), |session| {
                        session.working_directory.as_path()
                    }),
            )?;
            let instructions = args.body.clone().unwrap_or_else(|| args.title.clone());
            let message = Message::ImplementationRequest(ImplementationRequest {
                title: args.title,
                instructions: instructions.clone(),
                base_sha,
                acceptance_criteria: vec![instructions],
                evidence_requirements: vec![EvidenceKind::Git, EvidenceKind::Test],
            });
            let target = MessageTarget::Actor(actor.actor_id.clone());
            let envelope = make_envelope(
                &supervisor,
                primary,
                target.clone(),
                Some(team_id.clone()),
                Some(run_id.clone()),
                Some(request_id.clone()),
                None,
                message,
                message_id(&args.operation_id, "request"),
            )?;
            let (revision, outcome) = self.store.mutate(
                "request.created",
                &json!({ "request_id": request_id, "run_id": run_id, "team_id": team_id }),
                now_ms()?,
                |state| apply_envelope(state, envelope.clone()),
            )?;
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
            if actor.role != ActorRole::Implementation {
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
                    let derived_target = if requester.role == ActorRole::Primary {
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
                let context_team = if sender.role == ActorRole::Implementation {
                    sender.team_id.clone()
                } else {
                    args.team
                        .as_deref()
                        .map(|value| TeamId::new(value.to_owned()).map_err(ControlError::protocol))
                        .transpose()?
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
                .filter(|delivery| target_matches(&delivery.envelope.target, actor))
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
    working_directory: Option<PathBuf>,
    #[serde(default = "default_orchestrators")]
    orchestrators: u16,
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
        .filter(|actor| actor.role == ActorRole::Implementation)
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

fn target_matches(target: &MessageTarget, actor: &Actor) -> bool {
    match target {
        MessageTarget::Primary => actor.role == ActorRole::Primary,
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

fn codex_args(settings: &ControlSettings) -> Vec<String> {
    vec![
        "-m".to_owned(),
        settings.model.clone(),
        "-c".to_owned(),
        format!("model_reasoning_effort=\"{}\"", settings.reasoning_effort),
        "--approve-for-me".to_owned(),
    ]
}

fn implementation_prompt(
    role: &str,
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
    Ok(format!(
        "{role}\n\nYou are actor `{}` for team `{team}`. The AGSV control command for every invocation in this session is {command}; use that absolute, safely quoted path rather than assuming `agsv` is on PATH. From this managed worktree, first run `{command} --json context --bootstrap`, then read your authenticated inbox once with `{command} --json message inbox` and acknowledge handled messages without an `--actor` override. If the inbox is empty, reply only in this managed session turn that you are ready and end the launch turn immediately; do not send a protocol message without request context, inspect the repository, sleep, or poll until AGSV sends a durable inbox notification. Linked worktrees share the workspace through their Git common-directory identity, so do not add a Primary `--workspace` path. Stay within this top-level Implementation Orchestrator role.",
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
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::{
        ControlPlane, ControlSettings, apply_envelope, codex_args, implementation_prompt,
        session_name, shell_single_quote,
    };
    use crate::store::SessionRecord;
    use agsv_core::{ApplyOutcome, Supervisor};
    use agsv_protocol::{
        ActorEpoch, ActorId, ActorRef, Envelope, EvidenceKind, GitSha, ImplementationRequest,
        Message, MessageId, MessageTarget, PROTOCOL_VERSION, PolicyRevision, PrimaryEpoch,
        ProgressUpdate, RequestId, RunId, TeamId, TimestampMillis, WorkspaceId,
    };
    use serde_json::json;

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
    fn implementation_bootstrap_uses_absolute_quoted_executable_without_workspace_override() {
        assert_eq!(
            shell_single_quote("/tmp/Agent Supervisor/it's-agsv"),
            "'/tmp/Agent Supervisor/it'\"'\"'s-agsv'"
        );
        let prompt = implementation_prompt(
            "role",
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
        let settings = ControlSettings {
            workspace: PathBuf::from("/workspace"),
            state_directory: PathBuf::from("/state"),
            config_source: "builtin".to_owned(),
            primary_role: "primary".to_owned(),
            implementation_role: "implementation".to_owned(),
            backend: "herdr".to_owned(),
            model: "gpt-test".to_owned(),
            reasoning_effort: "max".to_owned(),
            primary_lease_seconds: 3_600,
            actor_heartbeat_seconds: 300,
        };

        assert_eq!(
            codex_args(&settings),
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

        let settings = ControlSettings {
            workspace: root.clone(),
            state_directory: temporary.path().join("state"),
            config_source: "builtin".to_owned(),
            primary_role: "primary".to_owned(),
            implementation_role: "implementation".to_owned(),
            backend: "fake".to_owned(),
            model: "gpt-test".to_owned(),
            reasoning_effort: "max".to_owned(),
            primary_lease_seconds: 3_600,
            actor_heartbeat_seconds: 300,
        };
        let plane = ControlPlane::open(settings).unwrap();
        let team_id = TeamId::new("team-retry").unwrap();
        let actor_id = ActorId::new("impl-retry-1").unwrap();
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

        plane
            .store
            .upsert_session(&SessionRecord {
                actor_id: actor_ref.actor_id.to_string(),
                team_id: Some(team_id.to_string()),
                working_directory: root,
                backend: "fake".to_owned(),
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
        let settings = ControlSettings {
            workspace: root.clone(),
            state_directory: temporary.path().join("state"),
            config_source: "builtin".to_owned(),
            primary_role: "primary".to_owned(),
            implementation_role: "implementation".to_owned(),
            backend: "fake".to_owned(),
            model: "gpt-test".to_owned(),
            reasoning_effort: "max".to_owned(),
            primary_lease_seconds: 3_600,
            actor_heartbeat_seconds: 300,
        };
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

        let settings = ControlSettings {
            workspace: root,
            state_directory: temporary.path().join("state"),
            config_source: "builtin".to_owned(),
            primary_role: "primary".to_owned(),
            implementation_role: "implementation".to_owned(),
            backend: "herdr".to_owned(),
            model: "gpt-test".to_owned(),
            reasoning_effort: "max".to_owned(),
            primary_lease_seconds: 3_600,
            actor_heartbeat_seconds: 300,
        };
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
