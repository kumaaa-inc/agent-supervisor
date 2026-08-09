use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::backend::SessionDriver;
use crate::identity::sha256_hex;
use crate::store::{SessionRecord, StateStore};
use crate::{ControlError, WorkspaceIdentity};
use agsv_core::{
    AckOutcome, ApplyOutcome, RequestEvent, RunEvent, Supervisor, transition_request,
    transition_run,
};
use agsv_protocol::{
    Acknowledgement, Actor, ActorId, ActorRef, ActorRole, ActorStatus, AssignmentEpoch,
    BlockerNotice, Cancellation, Candidate, CandidateReady, ConsultationRequest, DecisionId,
    Envelope, EvidenceKind, FixRequest, GitSha, ImplementationRequest, IntegrationAuthorization,
    Message, MessageId, MessageTarget, PROTOCOL_VERSION, PolicyRevision, ProgressUpdate, RequestId,
    ReviewDecision, ReviewVerdict, RunId, TeamId, TeamStatus, TimestampMillis,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Runtime backend selected by project config or `AGSV_SESSION_BACKEND`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Herdr,
    Fake,
}

/// Effective, already validated inputs supplied by the CLI configuration layer.
#[derive(Clone, Debug)]
pub struct ControlSettings {
    pub workspace: PathBuf,
    pub state_directory: PathBuf,
    pub config_source: String,
    pub primary_role: String,
    pub implementation_role: String,
    pub backend: BackendKind,
    pub model: String,
    pub reasoning_effort: String,
}

/// One invocation's embedded control-plane handle.
pub struct ControlPlane {
    settings: ControlSettings,
    identity: WorkspaceIdentity,
    store: StateStore,
    sessions: SessionDriver,
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
            settings.backend = parse_backend(&value)?;
        }
        let initial = Supervisor::new(identity.workspace_id().clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            &settings.state_directory,
            identity.workspace_id().as_str(),
            &initial.snapshot(),
            now_ms()?,
        )?;
        let sessions = SessionDriver::new(settings.backend);
        Ok(Self {
            settings,
            identity,
            store,
            sessions,
        })
    }

    /// Executes one stable CLI operation and returns its machine-readable payload.
    ///
    /// # Errors
    ///
    /// Returns a stable error when arguments, authorization, persistence,
    /// protocol transitions, Git evidence, or the session backend fails.
    pub fn execute(&self, operation: &str, request: &Value) -> Result<Value, ControlError> {
        match operation {
            "start" => self.start(request),
            "stop" => self.stop(request),
            "status" => self.status(),
            "doctor" => self.doctor(),
            "attach" => Err(ControlError::unsupported(
                operation,
                "the session adapter has no non-interactive attach primitive; use Herdr directly",
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
            "run.pause" => self.run_transition(request, RunEvent::Pause, operation),
            "run.resume" => self.run_transition(request, RunEvent::Resume, operation),
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
        Ok(json!({
            "healthy": true,
            "mode": "embedded",
            "journal_mode": self.store.journal_mode()?,
            "config_source": self.settings.config_source,
            "state_path": self.store.path(),
            "session": self.sessions.diagnostics(),
            "launch": {
                "runtime": "codex",
                "model": self.settings.model,
                "reasoning_effort": self.settings.reasoning_effort,
                "sandbox": "workspace-write",
                "approval": "approve-for-me",
            },
            "enforcement": {
                "core": ["authorization", "state_transitions", "idempotency", "fencing", "exact_candidate_sha"],
                "launch": ["runtime", "model", "reasoning_effort", "working_directory", "sandbox"],
                "provider": ["approve_for_me"],
                "instructed_observed": ["provider_native_subagent_topology", "fresh_review", "read_only_review"],
            },
        }))
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
            Ok(json!({ "team_id": id, "status": status, "revision": revision }))
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
        let result = execute()?;
        self.store
            .record_operation(operation_id, operation, request, &result, now_ms()?)
    }
}

impl ControlPlane {
    fn bootstrap_actor(&self, requested: Option<&str>) -> Result<ActorRef, ControlError> {
        let actor_id = self.discover_actor_id(requested)?;
        let (_, supervisor, _) = self.store.load()?;
        if let Some(actor) = supervisor.actor(&actor_id) {
            let actor_ref = actor.actor_ref();
            let (_, ()) = self.store.mutate(
                "actor.bootstrapped",
                &json!({ "actor_id": actor_id }),
                now_ms()?,
                |state| {
                    state
                        .heartbeat(&actor_ref, TimestampMillis(now_ms()?))
                        .map_err(ControlError::core)
                },
            )?;
            return Ok(actor_ref);
        }
        let role = std::env::var("AGSV_ACTOR_ROLE").unwrap_or_else(|_| "primary".to_owned());
        if role != "primary" {
            return Err(ControlError::new(
                "unknown_implementation_actor",
                format!(
                    "implementation actor `{actor_id}` is not registered; create its team first"
                ),
            ));
        }
        let (_, actor_ref) = self.store.mutate(
            "primary.bootstrapped",
            &json!({ "actor_id": actor_id }),
            now_ms()?,
            |state| {
                state
                    .activate_primary(actor_id.clone())
                    .map_err(ControlError::core)
            },
        )?;
        Ok(actor_ref)
    }

    fn resolve_actor(&self, requested: Option<&str>) -> Result<Actor, ControlError> {
        let id = self.discover_actor_id(requested)?;
        let (_, supervisor, _) = self.store.load()?;
        supervisor
            .actor(&id)
            .cloned()
            .ok_or_else(|| ControlError::not_found("actor", id.as_str()))
    }

    fn discover_actor_id(&self, requested: Option<&str>) -> Result<ActorId, ControlError> {
        if let Some(value) = requested {
            return ActorId::new(value.to_owned()).map_err(ControlError::protocol);
        }
        if let Ok(value) = std::env::var("AGSV_ACTOR_ID") {
            return ActorId::new(value).map_err(ControlError::protocol);
        }
        if let Ok(pane_id) = std::env::var("HERDR_PANE_ID") {
            if let Some(session) = self
                .store
                .sessions()?
                .into_iter()
                .find(|session| session.resume_token.as_deref() == Some(pane_id.as_str()))
            {
                return ActorId::new(session.actor_id).map_err(ControlError::protocol);
            }
            let safe = pane_id
                .chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() {
                        character
                    } else {
                        '-'
                    }
                })
                .collect::<String>();
            return ActorId::new(format!("primary-{safe}")).map_err(ControlError::protocol);
        }
        Err(ControlError::new(
            "actor_identity_unavailable",
            "could not discover the current orchestrator; run inside Herdr or set AGSV_ACTOR_ID and AGSV_ACTOR_ROLE",
        ))
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
            let working_directory = self.ensure_team_directory(
                &team_id,
                args.working_directory.as_deref(),
            )?;
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
                    actor_ids
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
                        .collect::<Result<Vec<_>, _>>()
                },
            )?;

            let mut sessions = Vec::new();
            let mut reused = true;
            for actor_ref in &actor_refs {
                if let Some(existing) = self.store.session(actor_ref.actor_id.as_str())? {
                    let status = self.sessions.status(&existing)?;
                    if matches!(status.as_str(), "starting" | "working" | "idle" | "blocked" | "unknown") {
                        sessions.push(existing);
                        continue;
                    }
                }
                let launch_key = format!(
                    "{}:{}:{}",
                    args.operation_id, actor_ref.actor_id, actor_ref.actor_epoch
                );
                reused = false;
                let prompt = format!(
                    "{}\n\nYou are actor `{}` for team `{}`. First run `agsv --workspace {} --json context --bootstrap`, then read and acknowledge your durable inbox. Stay within this top-level Implementation Orchestrator role.",
                    self.settings.implementation_role,
                    actor_ref.actor_id,
                    team_id,
                    self.identity.root().display(),
                );
                let native_args = vec![
                    "-m".to_owned(),
                    self.settings.model.clone(),
                    "-c".to_owned(),
                    format!(
                        "model_reasoning_effort=\"{}\"",
                        self.settings.reasoning_effort
                    ),
                    "--sandbox".to_owned(),
                    "workspace-write".to_owned(),
                    "--approve-for-me".to_owned(),
                    prompt,
                ];
                let session_name = session_name(actor_ref.actor_id.as_str());
                let pending = SessionRecord {
                    actor_id: actor_ref.actor_id.to_string(),
                    team_id: Some(team_id.to_string()),
                    working_directory: working_directory.clone(),
                    backend: self.sessions.name().to_owned(),
                    external_id: None,
                    resume_token: None,
                    status: "launching".to_owned(),
                    launch_key: launch_key.clone(),
                    updated_at_ms: now_ms()?,
                };
                self.store.upsert_session(&pending)?;
                match self.sessions.launch(
                    actor_ref.actor_id.as_str(),
                    &session_name,
                    &working_directory,
                    &launch_key,
                    native_args,
                ) {
                    Ok(handle) => {
                        let record = SessionRecord {
                            external_id: Some(handle.external_id),
                            resume_token: handle.resume_token,
                            status: "idle".to_owned(),
                            ..pending
                        };
                        self.store.upsert_session(&record)?;
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
            return Ok(canonical);
        }
        let worktrees = self.settings.state_directory.join("worktrees");
        fs::create_dir_all(&worktrees).map_err(|error| {
            ControlError::io("create managed worktree directory", &worktrees, &error)
        })?;
        let target = worktrees.join(team_id.as_str());
        if target.exists() {
            let identity = WorkspaceIdentity::discover(&target)?;
            if identity.git_common_dir() != self.identity.git_common_dir() {
                return Err(ControlError::new(
                    "unsafe_path",
                    "existing managed worktree path belongs to another Git repository",
                ));
            }
            return fs::canonicalize(&target).map_err(|error| {
                ControlError::io("canonicalize managed worktree", &target, &error)
            });
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

    fn reconcile(&self) -> Result<Value, ControlError> {
        let mut checked = 0_u64;
        let mut online = 0_u64;
        let mut offline = 0_u64;
        for mut session in self.store.sessions()? {
            checked += 1;
            let status = self.sessions.status(&session)?;
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
            "partial_failures_reconciled": true,
        }))
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
    fn actor_replace(&self, request: &Value) -> Result<Value, ControlError> {
        let args: ReasonedIdArgs = decode(request)?;
        self.idempotent("actor.replace", request, &args.operation_id, || {
            let id = ActorId::new(args.id.clone()).map_err(ControlError::protocol)?;
            let (_, supervisor, _) = self.store.load()?;
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
            let (revision, actor_ref) = self.store.mutate(
                "actor.replaced",
                &json!({ "actor_id": id, "reason": args.reason }),
                now_ms()?,
                |state| {
                    state
                        .replace_implementation(&team_id, id.clone())
                        .map_err(ControlError::core)
                },
            )?;
            let launch_key = format!("{}:{}", args.operation_id, actor_ref.actor_epoch);
            let prompt = implementation_prompt(
                &self.settings.implementation_role,
                &actor_ref,
                &team_id,
                self.identity.root(),
            );
            let handle = self.sessions.launch(
                actor_ref.actor_id.as_str(),
                &session_name(&format!(
                    "{}-r{}",
                    actor_ref.actor_id, actor_ref.actor_epoch
                )),
                &prior_session.working_directory,
                &launch_key,
                codex_args(&self.settings, prompt),
            )?;
            let session = SessionRecord {
                actor_id: args.id,
                team_id: Some(team_id.to_string()),
                working_directory: prior_session.working_directory,
                backend: self.sessions.name().to_owned(),
                external_id: Some(handle.external_id),
                resume_token: handle.resume_token,
                status: "idle".to_owned(),
                launch_key,
                updated_at_ms: now_ms()?,
            };
            self.store.upsert_session(&session)?;
            Ok(json!({ "actor": actor_ref, "session": session, "revision": revision }))
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
        event: RunEvent,
        operation: &str,
    ) -> Result<Value, ControlError> {
        let args: MutationIdArgs = decode(request)?;
        self.idempotent(operation, request, &args.operation_id, || {
            let run_id = RunId::new(args.id.clone()).map_err(ControlError::protocol)?;
            let (revision, status) = self.store.mutate(
                operation,
                &json!({ "run_id": run_id }),
                now_ms()?,
                |state| transition_run_in_snapshot(state, &run_id, event),
            )?;
            Ok(json!({ "run_id": run_id, "status": status, "revision": revision }))
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
            let envelope = make_envelope(
                &supervisor,
                primary,
                MessageTarget::Actor(actor.actor_id.clone()),
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
            if let Some(session) = self.store.session(actor.actor_id.as_str())? {
                let _ = self.sessions.notify(
                    &session,
                    &format!("New durable AGSV request `{request_id}` is waiting in your inbox."),
                );
            }
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
            let actor_id = ActorId::new(args.actor.clone()).map_err(ControlError::protocol)?;
            let (_, supervisor, _) = self.store.load()?;
            let item = supervisor
                .request(&request_id)
                .ok_or_else(|| ControlError::not_found("request", &args.id))?;
            let assignment = item.assignment.as_ref().ok_or_else(|| {
                ControlError::new("unassigned_request", "request has no current assignment")
            })?;
            if assignment.actor.actor_id != actor_id {
                return Err(ControlError::new(
                    "claim_conflict",
                    format!("request is assigned to `{}`", assignment.actor.actor_id),
                ));
            }
            Ok(json!({ "request_id": request_id, "assignment": assignment, "claimed": true }))
        })
    }
    fn request_block(&self, request: &Value) -> Result<Value, ControlError> {
        let args: RequestBlockArgs = decode(request)?;
        self.idempotent("request.block", request, &args.operation_id, || {
            let request_id = RequestId::new(args.id.clone()).map_err(ControlError::protocol)?;
            let (_, supervisor, _) = self.store.load()?;
            let actor = self.resolve_actor(None)?;
            let (envelope, run_id) = request_envelope(
                &supervisor,
                &request_id,
                actor.actor_ref(),
                MessageTarget::Primary,
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
                .map_or_else(|| self.identity.root().to_path_buf(), |session| session.working_directory);
            verify_commit(&candidate_directory, &sha)?;
            let candidate = Candidate {
                request_id: request_id.clone(),
                team_id: item.team_id.clone(),
                sha,
                created_by: actor.actor_ref(),
            };
            let (envelope, run_id) = request_envelope(
                &supervisor,
                &request_id,
                actor.actor_ref(),
                MessageTarget::Primary,
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
            let target = resolve_target(&supervisor, &args.to)?;
            let request_id = args
                .request
                .as_deref()
                .map(|value| RequestId::new(value.to_owned()).map_err(ControlError::protocol))
                .transpose()?;
            let kind = args.kind.to_ascii_lowercase().replace('-', "_");
            let message = match kind.as_str() {
                "progress" => Message::Progress(ProgressUpdate {
                    summary: args.body,
                    percent_complete: None,
                    evidence: Vec::new(),
                }),
                "blocker" => Message::Blocker(BlockerNotice {
                    summary: args.body,
                    needs_primary: true,
                    evidence: Vec::new(),
                }),
                "consultation" | "consultation_request" => {
                    let MessageTarget::Team(target_team_id) = &target else {
                        return Err(ControlError::invalid_request(
                            "consultation_request must target a team",
                        ));
                    };
                    Message::ConsultationRequest(ConsultationRequest {
                        consultation_id: message_id(&args.operation_id, "consultation"),
                        target_team_id: target_team_id.clone(),
                        subject: "cross-team consultation".to_owned(),
                        question: args.body,
                        evidence: Vec::new(),
                    })
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
                    Message::FixRequest(FixRequest {
                        decision_id: decision.decision_id.clone(),
                        candidate,
                        instructions: args.body,
                    })
                }
                _ => {
                    return Err(ControlError::unsupported(
                        "message.send",
                        "supported kinds are progress, blocker, consultation_request, and fix_request",
                    ));
                }
            };
            let envelope = if let Some(id) = &request_id {
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
            let (revision, outcome) = self.store.mutate(
                "message.sent",
                &json!({ "message_id": message_id, "kind": kind }),
                now_ms()?,
                |state| apply_envelope(state, envelope.clone()),
            )?;
            Ok(json!({ "message_id": message_id, "outcome": apply_name(outcome), "revision": revision }))
        })
    }
    fn message_inbox(&self, request: &Value) -> Result<Value, ControlError> {
        let args: MessageInboxArgs = decode(request)?;
        let id = ActorId::new(args.actor.clone()).map_err(ControlError::protocol)?;
        let (_, supervisor, _) = self.store.load()?;
        let actor = supervisor
            .actor(&id)
            .ok_or_else(|| ControlError::not_found("actor", &args.actor))?;
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
                target,
                Message::Cancellation(Cancellation { reason: reason.to_owned() }),
                message_id(operation_id, "cancel"),
            )?;
            let (revision, outcome) = self.store.mutate(
                operation,
                &json!({ "request_id": request_id, "reason": reason }),
                now_ms()?,
                |state| apply_envelope(state, envelope.clone()),
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
    actor: String,
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
    to: String,
    kind: String,
    body: String,
    team: Option<String>,
    request: Option<String>,
    operation_id: String,
}

#[derive(Deserialize)]
struct MessageInboxArgs {
    actor: String,
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

fn parse_backend(value: &str) -> Result<BackendKind, ControlError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "herdr" => Ok(BackendKind::Herdr),
        "fake" => Ok(BackendKind::Fake),
        _ => Err(ControlError::invalid_request(
            "AGSV_SESSION_BACKEND must be `herdr` or `fake`",
        )),
    }
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

fn session_name(actor_id: &str) -> String {
    let mut name = actor_id.to_ascii_lowercase();
    name.retain(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'));
    if !name.starts_with(|character: char| character.is_ascii_lowercase()) {
        name.insert_str(0, "a-");
    }
    name.truncate(32);
    name
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
    envelope: Envelope,
) -> Result<ApplyOutcome, ControlError> {
    supervisor.apply(envelope).map_err(ControlError::core)
}

fn acknowledge(
    supervisor: &mut Supervisor,
    acknowledgement: Acknowledgement,
) -> Result<AckOutcome, ControlError> {
    supervisor
        .acknowledge(acknowledgement)
        .map_err(ControlError::core)
}

fn restore_domain(snapshot: agsv_protocol::DomainSnapshot) -> Result<Supervisor, ControlError> {
    Supervisor::from_snapshot(snapshot).map_err(ControlError::core)
}

fn transition_run_in_snapshot(
    supervisor: &mut Supervisor,
    run_id: &RunId,
    event: RunEvent,
) -> Result<agsv_protocol::RunStatus, ControlError> {
    let mut snapshot = supervisor.snapshot();
    let run = snapshot
        .runs
        .iter_mut()
        .find(|run| &run.run_id == run_id)
        .ok_or_else(|| ControlError::not_found("run", run_id.as_str()))?;
    run.status = transition_run(run.status, event).map_err(ControlError::core)?;
    let status = run.status;
    if event == RunEvent::Resume {
        let request = snapshot
            .requests
            .iter_mut()
            .find(|request| request.run_id == *run_id)
            .ok_or_else(|| ControlError::new("invalid_snapshot", "run has no request"))?;
        request.status =
            transition_request(request.status, RequestEvent::Start).map_err(ControlError::core)?;
    }
    *supervisor = restore_domain(snapshot)?;
    Ok(status)
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

fn verify_commit(directory: &Path, sha: &GitSha) -> Result<(), ControlError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(["cat-file", "-e"])
        .arg(format!("{}^{{commit}}", sha.as_str()))
        .output()
        .map_err(|error| ControlError::io("verify candidate commit", directory, &error))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(ControlError::new(
            "candidate_not_found",
            format!(
                "candidate {} is not a commit in {}",
                sha,
                directory.display()
            ),
        ))
    }
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

fn codex_args(settings: &ControlSettings, prompt: String) -> Vec<String> {
    vec![
        "-m".to_owned(),
        settings.model.clone(),
        "-c".to_owned(),
        format!("model_reasoning_effort=\"{}\"", settings.reasoning_effort),
        "--sandbox".to_owned(),
        "workspace-write".to_owned(),
        "--approve-for-me".to_owned(),
        prompt,
    ]
}

fn implementation_prompt(role: &str, actor: &ActorRef, team: &TeamId, workspace: &Path) -> String {
    format!(
        "{role}\n\nYou are actor `{}` for team `{team}`. First run `agsv --workspace {} --json context --bootstrap`, then read and acknowledge your durable inbox. Stay within this top-level Implementation Orchestrator role.",
        actor.actor_id,
        workspace.display(),
    )
}
