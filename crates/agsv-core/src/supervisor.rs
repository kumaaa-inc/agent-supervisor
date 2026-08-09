//! Workspace aggregate enforcing authorization, fencing, and idempotency.

use crate::CoreError;
use crate::transitions::{
    RequestEvent, RunEvent, transition_actor, transition_request, transition_run, transition_team,
};
use agsv_protocol::{
    Acknowledgement, Actor, ActorEpoch, ActorId, ActorRef, ActorRole, ActorStatus, Assignment,
    AssignmentEpoch, AuditEvent, AuditEventKind, Candidate, DeliverySnapshot, DomainSnapshot,
    Envelope, HandoffAcceptance, HandoffId, HandoffOffer, IntegrationAuthorization, Message,
    MessageId, MessageTarget, PendingHandoffSnapshot, PolicyRevision, PrimaryEpoch, Request,
    RequestId, RequestStatus, ReviewDecision, ReviewVerdict, Run, RunId, RunStatus, Team,
    TeamEpoch, TeamId, TeamStatus, TimestampMillis, Validate, WorkspaceId,
};
use std::collections::{BTreeMap, BTreeSet};

/// Result of accepting a durable envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    /// The message was newly authorized and applied.
    Applied,
    /// The exact same message id and content had already been applied.
    Duplicate,
}

/// Result of acknowledging a mailbox message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AckOutcome {
    /// A new acknowledgement was recorded.
    Acknowledged,
    /// This logical actor already acknowledged the message.
    Duplicate,
}

/// Durable delivery state for an accepted envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryRecord {
    /// Immutable accepted envelope.
    pub envelope: Envelope,
    /// At most one acknowledgement per logical actor.
    pub acknowledgements: BTreeMap<ActorId, Acknowledgement>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingHandoff {
    offer: HandoffOffer,
    offered_by: ActorRef,
    assignment_epoch: AssignmentEpoch,
}

/// Provider-independent state and invariants for one repository workspace.
#[derive(Clone, Debug)]
pub struct Supervisor {
    workspace_id: WorkspaceId,
    policy_revision: PolicyRevision,
    primary_epoch: PrimaryEpoch,
    active_primary: Option<ActorId>,
    actors: BTreeMap<ActorId, Actor>,
    teams: BTreeMap<TeamId, Team>,
    requests: BTreeMap<RequestId, Request>,
    runs: BTreeMap<RunId, Run>,
    mailbox: BTreeMap<MessageId, DeliveryRecord>,
    handoffs: BTreeMap<HandoffId, PendingHandoff>,
    audit: Vec<AuditEvent>,
}

impl Supervisor {
    /// Creates an empty workspace aggregate.
    #[must_use]
    pub fn new(workspace_id: WorkspaceId, policy_revision: PolicyRevision) -> Self {
        Self {
            workspace_id,
            policy_revision,
            primary_epoch: PrimaryEpoch::INITIAL,
            active_primary: None,
            actors: BTreeMap::new(),
            teams: BTreeMap::new(),
            requests: BTreeMap::new(),
            runs: BTreeMap::new(),
            mailbox: BTreeMap::new(),
            handoffs: BTreeMap::new(),
            audit: Vec::new(),
        }
    }

    /// Reconstructs an aggregate from a persisted snapshot without replaying
    /// historical commands.
    ///
    /// All entity ids, workspace scopes, bidirectional references, current
    /// assignment/actor generations, durable deliveries, acknowledgements,
    /// pending handoffs, and audit links are validated before state is returned.
    /// Fencing values and audit sequence numbers are preserved exactly.
    ///
    /// # Errors
    ///
    /// Returns an invalid-snapshot or protocol validation error without creating
    /// a partially initialized aggregate.
    pub fn from_snapshot(snapshot: DomainSnapshot) -> Result<Self, CoreError> {
        let DomainSnapshot {
            workspace_id,
            policy_revision,
            primary_epoch,
            active_primary,
            actors,
            teams,
            requests,
            runs,
            deliveries,
            pending_handoffs,
            audit_events,
        } = snapshot;

        let actors = restore_actors(&workspace_id, actors)?;
        validate_active_primary(active_primary.as_ref(), &actors)?;
        let teams = restore_teams(&workspace_id, teams, &actors)?;
        validate_actor_team_links(&actors, &teams)?;
        let requests = restore_requests(&workspace_id, requests, &actors, &teams)?;
        let runs = restore_runs(&workspace_id, runs, &requests, &teams)?;
        validate_request_run_links(&requests, &runs)?;
        let mailbox =
            restore_deliveries(&workspace_id, deliveries, &actors, &teams, &requests, &runs)?;
        let handoffs = restore_handoffs(pending_handoffs, &actors, &teams, &requests)?;
        validate_audit(&audit_events, &mailbox)?;

        Ok(Self {
            workspace_id,
            policy_revision,
            primary_epoch,
            active_primary: active_primary.map(|actor| actor.actor_id),
            actors,
            teams,
            requests,
            runs,
            mailbox,
            handoffs,
            audit: audit_events,
        })
    }

    /// Returns the workspace id.
    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    /// Returns the current policy fence.
    #[must_use]
    pub const fn policy_revision(&self) -> PolicyRevision {
        self.policy_revision
    }

    /// Returns the current Primary lease fence.
    #[must_use]
    pub const fn primary_epoch(&self) -> PrimaryEpoch {
        self.primary_epoch
    }

    /// Returns the active Primary actor generation, if any.
    #[must_use]
    pub fn active_primary(&self) -> Option<ActorRef> {
        self.active_primary
            .as_ref()
            .and_then(|id| self.actors.get(id))
            .map(Actor::actor_ref)
    }

    /// Activates or idempotently reuses the sole Primary lease.
    ///
    /// Replacing or restarting the active Primary advances the Primary fence and
    /// marks the previous actor generation stale.
    ///
    /// # Errors
    ///
    /// Returns an error if a monotonic epoch is exhausted.
    pub fn activate_primary(&mut self, actor_id: ActorId) -> Result<ActorRef, CoreError> {
        if self
            .actors
            .get(&actor_id)
            .is_some_and(|actor| actor.role != ActorRole::Primary)
        {
            return Err(CoreError::AlreadyExists("actor id"));
        }
        if let Some(actor) = self.actors.get(&actor_id).filter(|actor| {
            self.active_primary.as_ref() == Some(&actor_id) && actor.status == ActorStatus::Healthy
        }) {
            return Ok(actor.actor_ref());
        }

        if let Some(previous) = self.active_primary.clone() {
            self.primary_epoch = self
                .primary_epoch
                .checked_next()
                .ok_or(CoreError::EpochExhausted)?;
            if let Some(actor) = self.actors.get_mut(&previous) {
                actor.status = transition_actor(actor.status, ActorStatus::Stale)?;
            }
        }

        let actor_epoch = self.next_actor_epoch(&actor_id)?;
        let actor = Actor {
            actor_id: actor_id.clone(),
            workspace_id: self.workspace_id.clone(),
            team_id: None,
            role: ActorRole::Primary,
            epoch: actor_epoch,
            status: ActorStatus::Healthy,
            last_heartbeat_at: None,
        };
        self.actors.insert(actor_id.clone(), actor);
        self.active_primary = Some(actor_id.clone());
        Ok(ActorRef {
            actor_id,
            actor_epoch,
        })
    }

    /// Creates a team or returns its existing epoch when already present.
    ///
    /// # Errors
    ///
    /// Returns an error if the id belongs to a retired team.
    pub fn create_team(&mut self, team_id: TeamId) -> Result<TeamEpoch, CoreError> {
        if let Some(team) = self.teams.get(&team_id) {
            return if team.status == TeamStatus::Retired {
                Err(CoreError::AlreadyExists("retired team"))
            } else {
                Ok(team.epoch)
            };
        }
        self.teams.insert(
            team_id.clone(),
            Team {
                team_id,
                workspace_id: self.workspace_id.clone(),
                epoch: TeamEpoch::INITIAL,
                status: TeamStatus::Active,
                actors: Vec::new(),
            },
        );
        Ok(TeamEpoch::INITIAL)
    }

    /// Changes a team lifecycle state using the explicit state machine.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown team or illegal transition.
    pub fn set_team_status(
        &mut self,
        team_id: &TeamId,
        status: TeamStatus,
    ) -> Result<(), CoreError> {
        let team = self
            .teams
            .get_mut(team_id)
            .ok_or_else(|| CoreError::UnknownTeam(team_id.clone()))?;
        team.status = transition_team(team.status, status)?;
        Ok(())
    }

    /// Applies a validated lifecycle transition to the current actor generation.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown or stale actor generation, or for an
    /// illegal lifecycle transition.
    pub fn set_actor_status(
        &mut self,
        actor_ref: &ActorRef,
        status: ActorStatus,
    ) -> Result<(), CoreError> {
        let actor = self
            .actors
            .get_mut(&actor_ref.actor_id)
            .ok_or_else(|| CoreError::UnknownActor(actor_ref.actor_id.clone()))?;
        if actor.epoch != actor_ref.actor_epoch {
            return Err(CoreError::StaleActorEpoch {
                expected: actor.epoch,
                actual: actor_ref.actor_epoch,
            });
        }
        actor.status = transition_actor(actor.status, status)?;
        Ok(())
    }

    /// Records an actor heartbeat and returns a starting or stale generation to
    /// healthy presence.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown, fenced, or stopped actor generation.
    pub fn heartbeat(
        &mut self,
        actor_ref: &ActorRef,
        observed_at: TimestampMillis,
    ) -> Result<(), CoreError> {
        self.set_actor_status(actor_ref, ActorStatus::Healthy)?;
        self.actors
            .get_mut(&actor_ref.actor_id)
            .ok_or_else(|| CoreError::UnknownActor(actor_ref.actor_id.clone()))?
            .last_heartbeat_at = Some(observed_at);
        Ok(())
    }

    /// Registers the first healthy implementation actor for a team.
    ///
    /// Repeating registration for the same healthy actor is idempotent. Actor
    /// replacement must use [`Self::replace_implementation`] so all relevant
    /// fences advance together.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown/inactive team or a conflicting actor id.
    pub fn register_implementation(
        &mut self,
        team_id: &TeamId,
        actor_id: ActorId,
    ) -> Result<ActorRef, CoreError> {
        let team = self
            .teams
            .get(team_id)
            .ok_or_else(|| CoreError::UnknownTeam(team_id.clone()))?;
        if team.status != TeamStatus::Active {
            return Err(CoreError::Unauthorized("register actor for inactive team"));
        }
        if let Some(actor) = self.actors.get(&actor_id) {
            if actor.role == ActorRole::Implementation
                && actor.team_id.as_ref() == Some(team_id)
                && actor.status == ActorStatus::Healthy
            {
                return Ok(actor.actor_ref());
            }
            return Err(CoreError::AlreadyExists("actor id"));
        }

        let actor = Actor {
            actor_id: actor_id.clone(),
            workspace_id: self.workspace_id.clone(),
            team_id: Some(team_id.clone()),
            role: ActorRole::Implementation,
            epoch: ActorEpoch::INITIAL,
            status: ActorStatus::Healthy,
            last_heartbeat_at: None,
        };
        self.actors.insert(actor_id.clone(), actor);
        self.teams
            .get_mut(team_id)
            .ok_or_else(|| CoreError::UnknownTeam(team_id.clone()))?
            .actors
            .push(actor_id.clone());
        Ok(ActorRef {
            actor_id,
            actor_epoch: ActorEpoch::INITIAL,
        })
    }

    /// Replaces a team's implementation actor and advances team, actor, and all
    /// active assignment fences atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown/inactive team or exhausted epoch.
    pub fn replace_implementation(
        &mut self,
        team_id: &TeamId,
        actor_id: ActorId,
    ) -> Result<ActorRef, CoreError> {
        let team = self
            .teams
            .get(team_id)
            .ok_or_else(|| CoreError::UnknownTeam(team_id.clone()))?;
        if team.status != TeamStatus::Active {
            return Err(CoreError::Unauthorized("replace actor for inactive team"));
        }
        if self.actors.get(&actor_id).is_some_and(|actor| {
            actor.role != ActorRole::Implementation || actor.team_id.as_ref() != Some(team_id)
        }) {
            return Err(CoreError::AlreadyExists("actor id"));
        }
        let next_team_epoch = team.epoch.checked_next().ok_or(CoreError::EpochExhausted)?;
        let next_actor_epoch = self.next_actor_epoch(&actor_id)?;
        let mut assignment_updates = Vec::new();
        for request in self
            .requests
            .values()
            .filter(|request| request.team_id == *team_id && !request.status.is_terminal())
        {
            let assignment = request
                .assignment
                .as_ref()
                .ok_or(CoreError::NotAssignedActor)?;
            let next_assignment_epoch = assignment
                .epoch
                .checked_next()
                .ok_or(CoreError::EpochExhausted)?;
            if !self.runs.contains_key(&request.run_id) {
                return Err(CoreError::UnknownRun(request.run_id.clone()));
            }
            assignment_updates.push((
                request.request_id.clone(),
                request.run_id.clone(),
                next_assignment_epoch,
            ));
        }

        let prior_actor_ids = team.actors.clone();
        for old_id in prior_actor_ids {
            if let Some(old_actor) = self.actors.get_mut(&old_id) {
                if old_actor.status != ActorStatus::Stopped {
                    old_actor.status = transition_actor(old_actor.status, ActorStatus::Stale)?;
                }
            }
        }

        let actor = Actor {
            actor_id: actor_id.clone(),
            workspace_id: self.workspace_id.clone(),
            team_id: Some(team_id.clone()),
            role: ActorRole::Implementation,
            epoch: next_actor_epoch,
            status: ActorStatus::Healthy,
            last_heartbeat_at: None,
        };
        self.actors.insert(actor_id.clone(), actor);
        let team = self
            .teams
            .get_mut(team_id)
            .ok_or_else(|| CoreError::UnknownTeam(team_id.clone()))?;
        team.epoch = next_team_epoch;
        if !team.actors.contains(&actor_id) {
            team.actors.push(actor_id.clone());
        }

        let actor_ref = ActorRef {
            actor_id,
            actor_epoch: next_actor_epoch,
        };
        for (request_id, run_id, next_assignment_epoch) in assignment_updates {
            if let Some(assignment) = self
                .requests
                .get_mut(&request_id)
                .and_then(|request| request.assignment.as_mut())
            {
                assignment.epoch = next_assignment_epoch;
                assignment.actor = actor_ref.clone();
                if let Some(run) = self.runs.get_mut(&run_id) {
                    run.assignment = Some(assignment.clone());
                }
            }
            self.handoffs
                .retain(|_, pending| pending.offer.request_id != request_id);
        }
        Ok(actor_ref)
    }

    /// Accepts and applies a durable typed message.
    ///
    /// Duplicate detection precedes live fence checks after static validation,
    /// allowing retry of a previously accepted command after ownership changes.
    ///
    /// # Errors
    ///
    /// Returns a stable validation, authorization, fencing, or transition error.
    pub fn apply(&mut self, envelope: Envelope) -> Result<ApplyOutcome, CoreError> {
        envelope.validate()?;
        if envelope.workspace_id != self.workspace_id {
            return Err(CoreError::WrongWorkspace {
                expected: self.workspace_id.clone(),
                actual: envelope.workspace_id,
            });
        }
        if let Some(existing) = self.mailbox.get(&envelope.message_id) {
            return if existing.envelope == envelope {
                Ok(ApplyOutcome::Duplicate)
            } else {
                Err(CoreError::DuplicateMessageConflict)
            };
        }
        self.ensure_audit_capacity()?;
        let sender = self.authorize_envelope(&envelope)?;
        self.apply_message(&envelope, &sender)?;

        let message_id = envelope.message_id.clone();
        let message_kind = envelope.message.kind();
        let occurred_at = envelope.sent_at;
        self.mailbox.insert(
            message_id.clone(),
            DeliveryRecord {
                envelope,
                acknowledgements: BTreeMap::new(),
            },
        );
        self.append_audit(
            occurred_at,
            AuditEventKind::MessageAccepted {
                message_id,
                message_kind,
            },
        );
        Ok(ApplyOutcome::Applied)
    }

    /// Records an explicit acknowledgement from an eligible target actor.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown messages, stale actors, or actors outside the
    /// original routing target.
    pub fn acknowledge(
        &mut self,
        acknowledgement: Acknowledgement,
    ) -> Result<AckOutcome, CoreError> {
        if acknowledgement.workspace_id != self.workspace_id {
            return Err(CoreError::WrongWorkspace {
                expected: self.workspace_id.clone(),
                actual: acknowledgement.workspace_id,
            });
        }
        let actor = self.current_actor(&acknowledgement.actor)?.clone();
        if actor.status != ActorStatus::Healthy {
            return Err(CoreError::ActorNotHealthy(actor.actor_id));
        }
        let envelope = self
            .mailbox
            .get(&acknowledgement.message_id)
            .ok_or(CoreError::UnknownMessage)?
            .envelope
            .clone();
        if !self.target_matches(&envelope.target, &actor) {
            return Err(CoreError::AckNotAuthorized);
        }
        let delivery = self
            .mailbox
            .get(&acknowledgement.message_id)
            .ok_or(CoreError::UnknownMessage)?;
        if delivery
            .acknowledgements
            .contains_key(&acknowledgement.actor.actor_id)
        {
            return Ok(AckOutcome::Duplicate);
        }
        self.ensure_audit_capacity()?;
        let message_id = acknowledgement.message_id.clone();
        let actor_id = acknowledgement.actor.actor_id.clone();
        let occurred_at = acknowledgement.acknowledged_at;
        self.mailbox
            .get_mut(&message_id)
            .ok_or(CoreError::UnknownMessage)?
            .acknowledgements
            .insert(actor_id.clone(), acknowledgement);
        self.append_audit(
            occurred_at,
            AuditEventKind::MessageAcknowledged {
                message_id,
                actor_id,
            },
        );
        Ok(AckOutcome::Acknowledged)
    }

    /// Returns unacknowledged envelopes currently routed to an actor generation.
    ///
    /// # Errors
    ///
    /// Returns an error if the actor generation is unknown, stale, or unhealthy.
    pub fn unacknowledged_for(&self, actor_ref: &ActorRef) -> Result<Vec<&Envelope>, CoreError> {
        let actor = self.current_actor(actor_ref)?;
        if actor.status != ActorStatus::Healthy {
            return Err(CoreError::ActorNotHealthy(actor.actor_id.clone()));
        }
        Ok(self
            .mailbox
            .values()
            .filter(|delivery| {
                self.target_matches(&delivery.envelope.target, actor)
                    && !delivery.acknowledgements.contains_key(&actor.actor_id)
            })
            .map(|delivery| &delivery.envelope)
            .collect())
    }

    /// Returns one request.
    #[must_use]
    pub fn request(&self, request_id: &RequestId) -> Option<&Request> {
        self.requests.get(request_id)
    }

    /// Returns one run.
    #[must_use]
    pub fn run(&self, run_id: &RunId) -> Option<&Run> {
        self.runs.get(run_id)
    }

    /// Returns one actor.
    #[must_use]
    pub fn actor(&self, actor_id: &ActorId) -> Option<&Actor> {
        self.actors.get(actor_id)
    }

    /// Returns one team.
    #[must_use]
    pub fn team(&self, team_id: &TeamId) -> Option<&Team> {
        self.teams.get(team_id)
    }

    /// Returns one accepted delivery record.
    #[must_use]
    pub fn delivery(&self, message_id: &MessageId) -> Option<&DeliveryRecord> {
        self.mailbox.get(message_id)
    }

    /// Returns the append-only audit log.
    #[must_use]
    pub fn audit_events(&self) -> &[AuditEvent] {
        &self.audit
    }

    /// Produces the serializable provider-independent persistence snapshot.
    #[must_use]
    pub fn snapshot(&self) -> DomainSnapshot {
        DomainSnapshot {
            workspace_id: self.workspace_id.clone(),
            policy_revision: self.policy_revision,
            primary_epoch: self.primary_epoch,
            active_primary: self.active_primary(),
            actors: self.actors.values().cloned().collect(),
            teams: self.teams.values().cloned().collect(),
            requests: self.requests.values().cloned().collect(),
            runs: self.runs.values().cloned().collect(),
            deliveries: self
                .mailbox
                .values()
                .map(|delivery| DeliverySnapshot {
                    envelope: delivery.envelope.clone(),
                    acknowledgements: delivery.acknowledgements.values().cloned().collect(),
                })
                .collect(),
            pending_handoffs: self
                .handoffs
                .values()
                .map(|pending| PendingHandoffSnapshot {
                    offer: pending.offer.clone(),
                    offered_by: pending.offered_by.clone(),
                    assignment_epoch: pending.assignment_epoch,
                })
                .collect(),
            audit_events: self.audit.clone(),
        }
    }

    fn next_actor_epoch(&self, actor_id: &ActorId) -> Result<ActorEpoch, CoreError> {
        self.actors
            .get(actor_id)
            .map_or(Ok(ActorEpoch::INITIAL), |actor| {
                actor.epoch.checked_next().ok_or(CoreError::EpochExhausted)
            })
    }

    fn authorize_envelope(&self, envelope: &Envelope) -> Result<Actor, CoreError> {
        if envelope.policy_revision != self.policy_revision {
            return Err(CoreError::StalePolicyRevision {
                expected: self.policy_revision,
                actual: envelope.policy_revision,
            });
        }
        if envelope.primary_epoch != self.primary_epoch {
            return Err(CoreError::StalePrimaryEpoch {
                expected: self.primary_epoch,
                actual: envelope.primary_epoch,
            });
        }
        let actor = self.current_actor(&envelope.sender)?.clone();
        if actor.status != ActorStatus::Healthy {
            return Err(CoreError::ActorNotHealthy(actor.actor_id));
        }
        match actor.role {
            ActorRole::Primary => {
                if self.active_primary.as_ref() != Some(&actor.actor_id) {
                    return Err(CoreError::NotActivePrimary(actor.actor_id));
                }
            }
            ActorRole::Implementation => {
                if actor.team_id != envelope.team_id {
                    return Err(CoreError::WrongTeam);
                }
            }
        }
        if let Some(team_id) = &envelope.team_id {
            let team = self
                .teams
                .get(team_id)
                .ok_or_else(|| CoreError::UnknownTeam(team_id.clone()))?;
            if envelope.team_epoch != Some(team.epoch) {
                return Err(CoreError::StaleTeamEpoch {
                    expected: team.epoch,
                    actual: envelope.team_epoch.expect("validated team epoch"),
                });
            }
            if actor.role == ActorRole::Implementation && team.status != TeamStatus::Active {
                return Err(CoreError::Unauthorized("message from inactive team"));
            }
        }
        Ok(actor)
    }

    fn current_actor(&self, actor_ref: &ActorRef) -> Result<&Actor, CoreError> {
        let actor = self
            .actors
            .get(&actor_ref.actor_id)
            .ok_or_else(|| CoreError::UnknownActor(actor_ref.actor_id.clone()))?;
        if actor.epoch != actor_ref.actor_epoch {
            return Err(CoreError::StaleActorEpoch {
                expected: actor.epoch,
                actual: actor_ref.actor_epoch,
            });
        }
        Ok(actor)
    }

    fn require_primary(actor: &Actor, action: &'static str) -> Result<(), CoreError> {
        if actor.role == ActorRole::Primary {
            Ok(())
        } else {
            Err(CoreError::Unauthorized(action))
        }
    }

    fn require_implementation(actor: &Actor, action: &'static str) -> Result<(), CoreError> {
        if actor.role == ActorRole::Implementation {
            Ok(())
        } else {
            Err(CoreError::Unauthorized(action))
        }
    }

    fn apply_message(&mut self, envelope: &Envelope, actor: &Actor) -> Result<(), CoreError> {
        match &envelope.message {
            Message::ImplementationRequest(specification) => {
                self.apply_implementation_request(envelope, actor, specification.clone())
            }
            Message::Progress(_) => {
                Self::require_implementation(actor, "report progress")?;
                Self::require_primary_target(&envelope.target)?;
                self.ensure_current_assignment(envelope, actor)?;
                self.transition_context(envelope, RequestEvent::Start, RunEvent::Resume)
            }
            Message::Blocker(_) => {
                Self::require_implementation(actor, "report blocker")?;
                Self::require_primary_target(&envelope.target)?;
                self.ensure_current_assignment(envelope, actor)?;
                self.transition_context(envelope, RequestEvent::Block, RunEvent::Block)
            }
            Message::CandidateReady(ready) => {
                Self::require_implementation(actor, "submit candidate")?;
                Self::require_primary_target(&envelope.target)?;
                self.ensure_current_assignment(envelope, actor)?;
                self.apply_candidate(envelope, actor, ready.candidate.clone())
            }
            Message::ReviewDecision(decision) => {
                Self::require_primary(actor, "submit review decision")?;
                self.apply_review(envelope, actor, decision.clone())
            }
            Message::FixRequest(fix) => self.apply_fix_request(envelope, actor, fix),
            Message::QaResult(result) => {
                Self::require_implementation(actor, "report QA")?;
                Self::require_primary_target(&envelope.target)?;
                self.ensure_current_assignment(envelope, actor)?;
                let request = self.request_context(envelope)?;
                Self::ensure_candidate(request, &result.candidate)
            }
            Message::IntegrationAuthorization(authorization) => {
                Self::require_primary(actor, "authorize integration")?;
                self.ensure_assignee_target(envelope)?;
                self.apply_integration_authorization(envelope, actor, authorization.clone())
            }
            Message::Cancellation(_) => self.apply_cancellation(envelope, actor),
            Message::ConsultationRequest(consultation) => {
                self.ensure_active_target_team(&consultation.target_team_id, &envelope.target)
            }
            Message::ConsultationResponse(response) => {
                Self::require_implementation(actor, "answer consultation")?;
                if actor.team_id.as_ref() != Some(&response.responding_team_id) {
                    return Err(CoreError::WrongTeam);
                }
                Ok(())
            }
            Message::DependencyNotice(notice) => {
                if !self.requests.contains_key(&notice.blocked_request_id) {
                    return Err(CoreError::UnknownRequest(notice.blocked_request_id.clone()));
                }
                if !self.requests.contains_key(&notice.depends_on_request_id) {
                    return Err(CoreError::UnknownRequest(
                        notice.depends_on_request_id.clone(),
                    ));
                }
                self.ensure_known_team(&notice.provider_team_id).map(|_| ())
            }
            Message::ConflictNotice(notice) => {
                self.ensure_known_team(&notice.other_team_id)?;
                if actor.team_id.as_ref() == Some(&notice.other_team_id) {
                    return Err(CoreError::WrongTeam);
                }
                Ok(())
            }
            Message::HandoffOffer(offer) => {
                Self::require_implementation(actor, "offer handoff")?;
                self.ensure_current_assignment(envelope, actor)?;
                self.apply_handoff_offer(envelope, actor, offer.clone())
            }
            Message::HandoffAcceptance(acceptance) => {
                Self::require_implementation(actor, "accept handoff")?;
                self.apply_handoff_acceptance(envelope, actor, acceptance)
            }
            Message::IntegrationComplete(complete) => {
                self.apply_integration_complete(envelope, actor, complete)
            }
        }
    }

    fn apply_fix_request(
        &self,
        envelope: &Envelope,
        actor: &Actor,
        fix: &agsv_protocol::FixRequest,
    ) -> Result<(), CoreError> {
        Self::require_primary(actor, "request fixes")?;
        self.ensure_assignee_target(envelope)?;
        let request = self.request_context(envelope)?;
        Self::ensure_candidate(request, &fix.candidate)?;
        let decision = request
            .decision
            .as_ref()
            .ok_or(CoreError::DecisionMismatch)?;
        if decision.decision_id != fix.decision_id
            || decision.verdict != ReviewVerdict::Rejected
            || request.status != RequestStatus::ChangesRequested
        {
            return Err(CoreError::DecisionMismatch);
        }
        Ok(())
    }

    fn apply_cancellation(&mut self, envelope: &Envelope, actor: &Actor) -> Result<(), CoreError> {
        Self::require_primary(actor, "cancel request")?;
        self.ensure_assignee_target(envelope)?;
        let request_id = envelope
            .request_id
            .clone()
            .ok_or(CoreError::WrongRequestContext)?;
        self.transition_context(envelope, RequestEvent::Cancel, RunEvent::Cancel)?;
        self.handoffs
            .retain(|_, pending| pending.offer.request_id != request_id);
        Ok(())
    }

    fn apply_integration_complete(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        complete: &agsv_protocol::IntegrationComplete,
    ) -> Result<(), CoreError> {
        Self::require_primary(actor, "report integration complete")?;
        self.ensure_assignee_target(envelope)?;
        let request = self.request_context(envelope)?;
        Self::ensure_candidate(request, &complete.candidate)?;
        let authorization = request
            .integration_authorization
            .as_ref()
            .ok_or(CoreError::DecisionMismatch)?;
        if authorization.decision_id != complete.decision_id {
            return Err(CoreError::DecisionMismatch);
        }
        self.transition_context(envelope, RequestEvent::Complete, RunEvent::Complete)
    }

    fn apply_implementation_request(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        specification: agsv_protocol::ImplementationRequest,
    ) -> Result<(), CoreError> {
        Self::require_primary(actor, "create implementation request")?;
        let (request_id, run_id) = context_ids(envelope)?;
        if self.requests.contains_key(&request_id) || self.runs.contains_key(&run_id) {
            return Err(CoreError::AlreadyExists("request or run"));
        }
        let team_id = envelope.team_id.clone().ok_or(CoreError::WrongTeam)?;
        let team = self.ensure_known_team(&team_id)?;
        if team.status != TeamStatus::Active {
            return Err(CoreError::Unauthorized("assign work to inactive team"));
        }
        let MessageTarget::Actor(target_actor_id) = &envelope.target else {
            return Err(CoreError::WrongTarget);
        };
        let target_actor = self
            .actors
            .get(target_actor_id)
            .ok_or_else(|| CoreError::UnknownActor(target_actor_id.clone()))?;
        if target_actor.role != ActorRole::Implementation
            || target_actor.team_id.as_ref() != Some(&team_id)
            || target_actor.status != ActorStatus::Healthy
        {
            return Err(CoreError::Unauthorized("assign request to target actor"));
        }
        if envelope.assignment_epoch.is_some() {
            return Err(CoreError::StaleAssignmentEpoch {
                expected: AssignmentEpoch::INITIAL,
                actual: envelope.assignment_epoch,
            });
        }
        let assignment = Assignment {
            actor: target_actor.actor_ref(),
            epoch: AssignmentEpoch::INITIAL,
        };
        let request = Request {
            request_id: request_id.clone(),
            workspace_id: self.workspace_id.clone(),
            team_id: team_id.clone(),
            run_id: run_id.clone(),
            specification,
            status: transition_request(RequestStatus::Open, RequestEvent::Assign)?,
            assignment: Some(assignment.clone()),
            candidate: None,
            decision: None,
            integration_authorization: None,
        };
        let run = Run {
            run_id: run_id.clone(),
            workspace_id: self.workspace_id.clone(),
            team_id,
            request_id: request_id.clone(),
            status: transition_run(RunStatus::Pending, RunEvent::Start)?,
            assignment: Some(assignment),
        };
        self.requests.insert(request_id, request);
        self.runs.insert(run_id, run);
        Ok(())
    }

    fn apply_candidate(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        candidate: Candidate,
    ) -> Result<(), CoreError> {
        let request = self.request_context(envelope)?;
        if candidate.team_id != request.team_id || candidate.created_by != actor.actor_ref() {
            return Err(CoreError::Unauthorized("submit candidate identity"));
        }
        match (&request.candidate, request.status) {
            (Some(previous), RequestStatus::ChangesRequested) => {
                if previous.sha == candidate.sha {
                    return Err(CoreError::CandidateMustChange);
                }
            }
            (Some(previous), _) if previous != &candidate => {
                return Err(CoreError::CandidateMismatch {
                    expected: Some(previous.sha.clone()),
                    actual: candidate.sha,
                });
            }
            _ => {}
        }
        let next_request = transition_request(request.status, RequestEvent::SubmitCandidate)?;
        let request_id = request.request_id.clone();
        let run_id = request.run_id.clone();
        let run = self
            .runs
            .get(&run_id)
            .ok_or(CoreError::UnknownRun(run_id.clone()))?;
        let next_run = transition_run(run.status, RunEvent::SubmitCandidate)?;

        let request = self
            .requests
            .get_mut(&request_id)
            .expect("request checked above");
        request.status = next_request;
        request.candidate = Some(candidate);
        request.decision = None;
        request.integration_authorization = None;
        self.runs
            .get_mut(&run_id)
            .expect("run checked above")
            .status = next_run;
        let current_candidate = self
            .requests
            .get(&request_id)
            .and_then(|request| request.candidate.clone());
        self.handoffs.retain(|_, pending| {
            pending.offer.request_id != request_id
                || pending
                    .offer
                    .candidate
                    .as_ref()
                    .is_none_or(|candidate| Some(candidate) == current_candidate.as_ref())
        });
        Ok(())
    }

    fn apply_review(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        decision: ReviewDecision,
    ) -> Result<(), CoreError> {
        if decision.reviewer != actor.actor_ref()
            || decision.policy_revision != self.policy_revision
        {
            return Err(CoreError::Unauthorized("review identity"));
        }
        self.ensure_assignee_target(envelope)?;
        let request = self.request_context(envelope)?;
        Self::ensure_candidate(request, &decision.candidate)?;
        let (request_event, run_event) = match decision.verdict {
            ReviewVerdict::Accepted => (RequestEvent::AcceptCandidate, RunEvent::AcceptCandidate),
            ReviewVerdict::Rejected => (RequestEvent::RejectCandidate, RunEvent::RejectCandidate),
        };
        let next_request = transition_request(request.status, request_event)?;
        let run_id = request.run_id.clone();
        let run = self
            .runs
            .get(&run_id)
            .ok_or(CoreError::UnknownRun(run_id.clone()))?;
        let next_run = transition_run(run.status, run_event)?;
        let request_id = request.request_id.clone();
        let verdict = decision.verdict;
        let request = self
            .requests
            .get_mut(&request_id)
            .expect("request checked above");
        request.status = next_request;
        request.decision = Some(decision);
        request.integration_authorization = None;
        self.runs
            .get_mut(&run_id)
            .expect("run checked above")
            .status = next_run;
        if verdict == ReviewVerdict::Accepted {
            self.handoffs
                .retain(|_, pending| pending.offer.request_id != request_id);
        }
        Ok(())
    }

    fn apply_integration_authorization(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        authorization: IntegrationAuthorization,
    ) -> Result<(), CoreError> {
        if authorization.authorized_by != actor.actor_ref() {
            return Err(CoreError::Unauthorized(
                "integration authorization identity",
            ));
        }
        let request = self.request_context(envelope)?;
        Self::ensure_candidate(request, &authorization.candidate)?;
        let decision = request
            .decision
            .as_ref()
            .ok_or(CoreError::DecisionMismatch)?;
        if decision.decision_id != authorization.decision_id
            || decision.verdict != ReviewVerdict::Accepted
        {
            return Err(CoreError::DecisionMismatch);
        }
        let next_request = transition_request(request.status, RequestEvent::AuthorizeIntegration)?;
        let run_id = request.run_id.clone();
        let run = self
            .runs
            .get(&run_id)
            .ok_or(CoreError::UnknownRun(run_id.clone()))?;
        let next_run = transition_run(run.status, RunEvent::AuthorizeIntegration)?;
        let request_id = request.request_id.clone();
        let request = self
            .requests
            .get_mut(&request_id)
            .expect("request checked above");
        request.status = next_request;
        request.integration_authorization = Some(authorization);
        self.runs
            .get_mut(&run_id)
            .expect("run checked above")
            .status = next_run;
        Ok(())
    }

    fn transition_context(
        &mut self,
        envelope: &Envelope,
        request_event: RequestEvent,
        run_event: RunEvent,
    ) -> Result<(), CoreError> {
        let request = self.request_context(envelope)?;
        let request_id = request.request_id.clone();
        let run_id = request.run_id.clone();
        let next_request = transition_request(request.status, request_event)?;
        let run = self
            .runs
            .get(&run_id)
            .ok_or(CoreError::UnknownRun(run_id.clone()))?;
        let next_run = transition_run(run.status, run_event)?;
        self.requests
            .get_mut(&request_id)
            .expect("request checked above")
            .status = next_request;
        self.runs
            .get_mut(&run_id)
            .expect("run checked above")
            .status = next_run;
        Ok(())
    }

    fn ensure_current_assignment(
        &self,
        envelope: &Envelope,
        actor: &Actor,
    ) -> Result<(), CoreError> {
        let request = self.request_context(envelope)?;
        let assignment = request
            .assignment
            .as_ref()
            .ok_or(CoreError::NotAssignedActor)?;
        if envelope.assignment_epoch != Some(assignment.epoch) {
            return Err(CoreError::StaleAssignmentEpoch {
                expected: assignment.epoch,
                actual: envelope.assignment_epoch,
            });
        }
        if assignment.actor != actor.actor_ref() {
            return Err(CoreError::NotAssignedActor);
        }
        Ok(())
    }

    fn require_primary_target(target: &MessageTarget) -> Result<(), CoreError> {
        if target == &MessageTarget::Primary {
            Ok(())
        } else {
            Err(CoreError::WrongTarget)
        }
    }

    fn ensure_assignee_target(&self, envelope: &Envelope) -> Result<(), CoreError> {
        let request = self.request_context(envelope)?;
        let assignment = request
            .assignment
            .as_ref()
            .ok_or(CoreError::NotAssignedActor)?;
        if matches!(
            &envelope.target,
            MessageTarget::Actor(actor_id) if actor_id == &assignment.actor.actor_id
        ) || envelope.target == MessageTarget::Team(request.team_id.clone())
        {
            Ok(())
        } else {
            Err(CoreError::WrongTarget)
        }
    }

    fn request_context(&self, envelope: &Envelope) -> Result<&Request, CoreError> {
        let (request_id, run_id) = context_ids(envelope)?;
        let request = self
            .requests
            .get(&request_id)
            .ok_or_else(|| CoreError::UnknownRequest(request_id.clone()))?;
        if request.run_id != run_id {
            return Err(CoreError::WrongRequestContext);
        }
        let run = self
            .runs
            .get(&run_id)
            .ok_or_else(|| CoreError::UnknownRun(run_id.clone()))?;
        if run.request_id != request_id {
            return Err(CoreError::WrongRequestContext);
        }
        Ok(request)
    }

    fn ensure_candidate(request: &Request, candidate: &Candidate) -> Result<(), CoreError> {
        if request.candidate.as_ref() == Some(candidate) {
            Ok(())
        } else {
            Err(CoreError::CandidateMismatch {
                expected: request.candidate.as_ref().map(|value| value.sha.clone()),
                actual: candidate.sha.clone(),
            })
        }
    }

    fn apply_handoff_offer(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        offer: HandoffOffer,
    ) -> Result<(), CoreError> {
        let request = self.request_context(envelope)?;
        if offer.request_id != request.request_id
            || offer.from_team_id != request.team_id
            || actor.team_id.as_ref() != Some(&offer.from_team_id)
        {
            return Err(CoreError::WrongTeam);
        }
        if matches!(
            request.status,
            RequestStatus::Accepted
                | RequestStatus::IntegrationAuthorized
                | RequestStatus::Cancelled
                | RequestStatus::Completed
        ) {
            return Err(CoreError::Unauthorized(
                "handoff request in final review state",
            ));
        }
        self.ensure_active_target_team(&offer.to_team_id, &envelope.target)?;
        if let Some(candidate) = &offer.candidate {
            Self::ensure_candidate(request, candidate)?;
        }
        if self.handoffs.contains_key(&offer.handoff_id)
            || self
                .handoffs
                .values()
                .any(|pending| pending.offer.request_id == offer.request_id)
        {
            return Err(CoreError::AlreadyExists("handoff"));
        }
        let assignment_epoch = request
            .assignment
            .as_ref()
            .ok_or(CoreError::NotAssignedActor)?
            .epoch;
        self.handoffs.insert(
            offer.handoff_id.clone(),
            PendingHandoff {
                offer,
                offered_by: actor.actor_ref(),
                assignment_epoch,
            },
        );
        Ok(())
    }

    fn apply_handoff_acceptance(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        acceptance: &HandoffAcceptance,
    ) -> Result<(), CoreError> {
        if acceptance.accepted_by != actor.actor_ref()
            || actor.team_id.as_ref() != Some(&acceptance.to_team_id)
            || envelope.team_id.as_ref() != Some(&acceptance.to_team_id)
        {
            return Err(CoreError::Unauthorized("handoff acceptance identity"));
        }
        if envelope.target != MessageTarget::Team(acceptance.from_team_id.clone())
            && envelope.target != MessageTarget::Primary
        {
            return Err(CoreError::WrongTarget);
        }
        let pending = self
            .handoffs
            .get(&acceptance.handoff_id)
            .ok_or(CoreError::UnknownHandoff)?
            .clone();
        if pending.offer.request_id != acceptance.request_id
            || pending.offer.from_team_id != acceptance.from_team_id
            || pending.offer.to_team_id != acceptance.to_team_id
        {
            return Err(CoreError::UnknownHandoff);
        }
        let request = self.request_context(envelope)?;
        if request.team_id != acceptance.from_team_id {
            return Err(CoreError::WrongTeam);
        }
        if let Some(candidate) = &pending.offer.candidate {
            if request.candidate.as_ref() != Some(candidate) {
                return Err(CoreError::CandidateMismatch {
                    expected: request
                        .candidate
                        .as_ref()
                        .map(|current| current.sha.clone()),
                    actual: candidate.sha.clone(),
                });
            }
        }
        let assignment = request
            .assignment
            .as_ref()
            .ok_or(CoreError::NotAssignedActor)?;
        if assignment.epoch != pending.assignment_epoch
            || envelope.assignment_epoch != Some(assignment.epoch)
            || assignment.actor != pending.offered_by
        {
            return Err(CoreError::StaleAssignmentEpoch {
                expected: assignment.epoch,
                actual: envelope.assignment_epoch,
            });
        }
        let next_epoch = assignment
            .epoch
            .checked_next()
            .ok_or(CoreError::EpochExhausted)?;
        let next_assignment = Assignment {
            actor: actor.actor_ref(),
            epoch: next_epoch,
        };
        let request_id = request.request_id.clone();
        let run_id = request.run_id.clone();
        let request = self
            .requests
            .get_mut(&request_id)
            .expect("request checked above");
        request.team_id = acceptance.to_team_id.clone();
        request.assignment = Some(next_assignment.clone());
        let run = self.runs.get_mut(&run_id).expect("run checked above");
        run.team_id = acceptance.to_team_id.clone();
        run.assignment = Some(next_assignment);
        self.handoffs.remove(&acceptance.handoff_id);
        Ok(())
    }

    fn ensure_known_team(&self, team_id: &TeamId) -> Result<&Team, CoreError> {
        self.teams
            .get(team_id)
            .ok_or_else(|| CoreError::UnknownTeam(team_id.clone()))
    }

    fn ensure_active_target_team(
        &self,
        team_id: &TeamId,
        target: &MessageTarget,
    ) -> Result<(), CoreError> {
        let team = self.ensure_known_team(team_id)?;
        if team.status != TeamStatus::Active {
            return Err(CoreError::Unauthorized("target inactive team"));
        }
        if target != &MessageTarget::Team(team_id.clone()) {
            return Err(CoreError::WrongTarget);
        }
        Ok(())
    }

    fn target_matches(&self, target: &MessageTarget, actor: &Actor) -> bool {
        match target {
            MessageTarget::Primary => {
                actor.role == ActorRole::Primary
                    && self.active_primary.as_ref() == Some(&actor.actor_id)
            }
            MessageTarget::Team(team_id) => actor.team_id.as_ref() == Some(team_id),
            MessageTarget::Actor(actor_id) => actor_id == &actor.actor_id,
            MessageTarget::Workspace => true,
        }
    }

    fn ensure_audit_capacity(&self) -> Result<(), CoreError> {
        u64::try_from(self.audit.len()).map_err(|_| CoreError::EpochExhausted)?;
        if self.audit.len() == usize::MAX {
            return Err(CoreError::EpochExhausted);
        }
        Ok(())
    }

    fn append_audit(&mut self, occurred_at: TimestampMillis, kind: AuditEventKind) {
        let sequence = u64::try_from(self.audit.len()).expect("capacity checked") + 1;
        self.audit.push(AuditEvent {
            sequence,
            occurred_at,
            kind,
        });
    }
}

impl TryFrom<DomainSnapshot> for Supervisor {
    type Error = CoreError;

    fn try_from(snapshot: DomainSnapshot) -> Result<Self, Self::Error> {
        Self::from_snapshot(snapshot)
    }
}

fn restore_actors(
    workspace_id: &WorkspaceId,
    actors: Vec<Actor>,
) -> Result<BTreeMap<ActorId, Actor>, CoreError> {
    let mut restored = BTreeMap::new();
    for (index, actor) in actors.into_iter().enumerate() {
        actor.validate()?;
        if actor.workspace_id != *workspace_id {
            return Err(invalid_snapshot(
                format!("actors[{index}].workspace_id"),
                "actor belongs to another workspace",
            ));
        }
        if restored.insert(actor.actor_id.clone(), actor).is_some() {
            return Err(invalid_snapshot(
                format!("actors[{index}].actor_id"),
                "duplicate actor id",
            ));
        }
    }
    Ok(restored)
}

fn validate_active_primary(
    active_primary: Option<&ActorRef>,
    actors: &BTreeMap<ActorId, Actor>,
) -> Result<(), CoreError> {
    if let Some(actor_ref) = active_primary {
        let actor = actors.get(&actor_ref.actor_id).ok_or_else(|| {
            invalid_snapshot("active_primary.actor_id", "active Primary actor is missing")
        })?;
        if actor.role != ActorRole::Primary || actor.actor_ref() != *actor_ref {
            return Err(invalid_snapshot(
                "active_primary",
                "active Primary role or actor epoch is inconsistent",
            ));
        }
    }
    for actor in actors
        .values()
        .filter(|actor| actor.role == ActorRole::Primary && actor.status == ActorStatus::Healthy)
    {
        if active_primary.is_none_or(|active| active.actor_id != actor.actor_id) {
            return Err(invalid_snapshot(
                "active_primary",
                "a healthy Primary actor must hold the active lease",
            ));
        }
    }
    Ok(())
}

fn restore_teams(
    workspace_id: &WorkspaceId,
    teams: Vec<Team>,
    actors: &BTreeMap<ActorId, Actor>,
) -> Result<BTreeMap<TeamId, Team>, CoreError> {
    let mut restored = BTreeMap::new();
    for (index, team) in teams.into_iter().enumerate() {
        if team.workspace_id != *workspace_id {
            return Err(invalid_snapshot(
                format!("teams[{index}].workspace_id"),
                "team belongs to another workspace",
            ));
        }
        let mut actor_ids = BTreeSet::new();
        for actor_id in &team.actors {
            if !actor_ids.insert(actor_id) {
                return Err(invalid_snapshot(
                    format!("teams[{index}].actors"),
                    "duplicate actor id in team",
                ));
            }
            let actor = actors.get(actor_id).ok_or_else(|| {
                invalid_snapshot(
                    format!("teams[{index}].actors"),
                    "team references an unknown actor",
                )
            })?;
            if actor.role != ActorRole::Implementation
                || actor.team_id.as_ref() != Some(&team.team_id)
            {
                return Err(invalid_snapshot(
                    format!("teams[{index}].actors"),
                    "team actor role or reverse team link is inconsistent",
                ));
            }
        }
        if restored.insert(team.team_id.clone(), team).is_some() {
            return Err(invalid_snapshot(
                format!("teams[{index}].team_id"),
                "duplicate team id",
            ));
        }
    }
    Ok(restored)
}

fn validate_actor_team_links(
    actors: &BTreeMap<ActorId, Actor>,
    teams: &BTreeMap<TeamId, Team>,
) -> Result<(), CoreError> {
    for actor in actors
        .values()
        .filter(|actor| actor.role == ActorRole::Implementation)
    {
        let team_id = actor.team_id.as_ref().ok_or_else(|| {
            invalid_snapshot("actors.team_id", "Implementation actor has no team")
        })?;
        let team = teams.get(team_id).ok_or_else(|| {
            invalid_snapshot("actors.team_id", "Implementation actor team is missing")
        })?;
        if !team.actors.contains(&actor.actor_id) {
            return Err(invalid_snapshot(
                "actors.team_id",
                "Implementation actor is absent from its team actor list",
            ));
        }
    }
    Ok(())
}

fn restore_requests(
    workspace_id: &WorkspaceId,
    requests: Vec<Request>,
    actors: &BTreeMap<ActorId, Actor>,
    teams: &BTreeMap<TeamId, Team>,
) -> Result<BTreeMap<RequestId, Request>, CoreError> {
    let mut restored = BTreeMap::new();
    let mut decision_ids = BTreeSet::new();
    for (index, request) in requests.into_iter().enumerate() {
        validate_request(index, workspace_id, &request, actors, teams)?;
        if let Some(decision) = &request.decision {
            if !decision_ids.insert(decision.decision_id.clone()) {
                return Err(invalid_snapshot(
                    format!("requests[{index}].decision.decision_id"),
                    "duplicate current decision id",
                ));
            }
        }
        if restored
            .insert(request.request_id.clone(), request)
            .is_some()
        {
            return Err(invalid_snapshot(
                format!("requests[{index}].request_id"),
                "duplicate request id",
            ));
        }
    }
    Ok(restored)
}

fn validate_request(
    index: usize,
    workspace_id: &WorkspaceId,
    request: &Request,
    actors: &BTreeMap<ActorId, Actor>,
    teams: &BTreeMap<TeamId, Team>,
) -> Result<(), CoreError> {
    let path = format!("requests[{index}]");
    if request.workspace_id != *workspace_id {
        return Err(invalid_snapshot(
            format!("{path}.workspace_id"),
            "request belongs to another workspace",
        ));
    }
    if !teams.contains_key(&request.team_id) {
        return Err(invalid_snapshot(
            format!("{path}.team_id"),
            "request team is missing",
        ));
    }
    request.specification.validate()?;
    validate_request_assignment(&path, request, actors)?;
    validate_request_candidate(&path, request, actors, teams)?;
    validate_request_review_state(&path, request, actors)?;
    Ok(())
}

fn validate_request_assignment(
    path: &str,
    request: &Request,
    actors: &BTreeMap<ActorId, Actor>,
) -> Result<(), CoreError> {
    match (&request.assignment, request.status) {
        (None, RequestStatus::Open) => Ok(()),
        (None, _) => Err(invalid_snapshot(
            format!("{path}.assignment"),
            "non-open request has no active assignment",
        )),
        (Some(_), RequestStatus::Open) => Err(invalid_snapshot(
            format!("{path}.assignment"),
            "open request unexpectedly has an assignment",
        )),
        (Some(assignment), _) => {
            let actor = actors.get(&assignment.actor.actor_id).ok_or_else(|| {
                invalid_snapshot(
                    format!("{path}.assignment.actor"),
                    "assignment actor is missing",
                )
            })?;
            if actor.actor_ref() != assignment.actor
                || actor.role != ActorRole::Implementation
                || actor.team_id.as_ref() != Some(&request.team_id)
            {
                return Err(invalid_snapshot(
                    format!("{path}.assignment.actor"),
                    "assignment actor generation, role, or team is inconsistent",
                ));
            }
            Ok(())
        }
    }
}

fn validate_request_candidate(
    path: &str,
    request: &Request,
    actors: &BTreeMap<ActorId, Actor>,
    teams: &BTreeMap<TeamId, Team>,
) -> Result<(), CoreError> {
    let Some(candidate) = &request.candidate else {
        if request.decision.is_some() || request.integration_authorization.is_some() {
            return Err(invalid_snapshot(
                format!("{path}.candidate"),
                "decision or authorization exists without a candidate",
            ));
        }
        if matches!(
            request.status,
            RequestStatus::CandidateReady
                | RequestStatus::ChangesRequested
                | RequestStatus::Accepted
                | RequestStatus::IntegrationAuthorized
                | RequestStatus::Completed
        ) {
            return Err(invalid_snapshot(
                format!("{path}.candidate"),
                "request state requires a candidate",
            ));
        }
        return Ok(());
    };
    if candidate.request_id != request.request_id || !teams.contains_key(&candidate.team_id) {
        return Err(invalid_snapshot(
            format!("{path}.candidate"),
            "candidate request or team reference is inconsistent",
        ));
    }
    let creator = actors.get(&candidate.created_by.actor_id).ok_or_else(|| {
        invalid_snapshot(
            format!("{path}.candidate.created_by"),
            "candidate creator is missing",
        )
    })?;
    if creator.role != ActorRole::Implementation
        || creator.team_id.as_ref() != Some(&candidate.team_id)
    {
        return Err(invalid_snapshot(
            format!("{path}.candidate.created_by"),
            "candidate creator role or team is inconsistent",
        ));
    }
    Ok(())
}

fn validate_request_review_state(
    path: &str,
    request: &Request,
    actors: &BTreeMap<ActorId, Actor>,
) -> Result<(), CoreError> {
    if let Some(decision) = &request.decision {
        decision.validate()?;
        if request.candidate.as_ref() != Some(&decision.candidate) {
            return Err(invalid_snapshot(
                format!("{path}.decision.candidate"),
                "decision does not bind the current exact candidate",
            ));
        }
        validate_primary_history_ref(&decision.reviewer, actors, &format!("{path}.decision"))?;
    }
    if let Some(authorization) = &request.integration_authorization {
        if request.candidate.as_ref() != Some(&authorization.candidate)
            || request.decision.as_ref().is_none_or(|decision| {
                decision.decision_id != authorization.decision_id
                    || decision.verdict != ReviewVerdict::Accepted
            })
        {
            return Err(invalid_snapshot(
                format!("{path}.integration_authorization"),
                "authorization does not bind the accepted current candidate",
            ));
        }
        validate_primary_history_ref(
            &authorization.authorized_by,
            actors,
            &format!("{path}.integration_authorization"),
        )?;
    }
    validate_status_review_shape(path, request)
}

fn validate_status_review_shape(path: &str, request: &Request) -> Result<(), CoreError> {
    let verdict = request.decision.as_ref().map(|decision| decision.verdict);
    let valid = match request.status {
        RequestStatus::CandidateReady => {
            request.decision.is_none() && request.integration_authorization.is_none()
        }
        RequestStatus::ChangesRequested => {
            verdict == Some(ReviewVerdict::Rejected) && request.integration_authorization.is_none()
        }
        RequestStatus::Accepted => {
            verdict == Some(ReviewVerdict::Accepted) && request.integration_authorization.is_none()
        }
        RequestStatus::IntegrationAuthorized | RequestStatus::Completed => {
            verdict == Some(ReviewVerdict::Accepted) && request.integration_authorization.is_some()
        }
        RequestStatus::Open
        | RequestStatus::Assigned
        | RequestStatus::InProgress
        | RequestStatus::Blocked
        | RequestStatus::Cancelled => true,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid_snapshot(
            format!("{path}.status"),
            "request status contradicts its review or authorization state",
        ))
    }
}

fn validate_primary_history_ref(
    actor_ref: &ActorRef,
    actors: &BTreeMap<ActorId, Actor>,
    path: &str,
) -> Result<(), CoreError> {
    if actors
        .get(&actor_ref.actor_id)
        .is_some_and(|actor| actor.role == ActorRole::Primary)
    {
        Ok(())
    } else {
        Err(invalid_snapshot(
            path,
            "historical Primary actor is missing or has the wrong role",
        ))
    }
}

fn restore_runs(
    workspace_id: &WorkspaceId,
    runs: Vec<Run>,
    requests: &BTreeMap<RequestId, Request>,
    teams: &BTreeMap<TeamId, Team>,
) -> Result<BTreeMap<RunId, Run>, CoreError> {
    let mut restored = BTreeMap::new();
    for (index, run) in runs.into_iter().enumerate() {
        if run.workspace_id != *workspace_id {
            return Err(invalid_snapshot(
                format!("runs[{index}].workspace_id"),
                "run belongs to another workspace",
            ));
        }
        if !teams.contains_key(&run.team_id) || !requests.contains_key(&run.request_id) {
            return Err(invalid_snapshot(
                format!("runs[{index}]"),
                "run request or team is missing",
            ));
        }
        if restored.insert(run.run_id.clone(), run).is_some() {
            return Err(invalid_snapshot(
                format!("runs[{index}].run_id"),
                "duplicate run id",
            ));
        }
    }
    Ok(restored)
}

fn validate_request_run_links(
    requests: &BTreeMap<RequestId, Request>,
    runs: &BTreeMap<RunId, Run>,
) -> Result<(), CoreError> {
    for request in requests.values() {
        let run = runs
            .get(&request.run_id)
            .ok_or_else(|| invalid_snapshot("requests.run_id", "request run is missing"))?;
        if run.request_id != request.request_id
            || run.team_id != request.team_id
            || run.assignment != request.assignment
            || !run_status_matches_request(run.status, request.status)
        {
            return Err(invalid_snapshot(
                "requests.run_id",
                "request and run state are inconsistent",
            ));
        }
    }
    for run in runs.values() {
        if requests
            .get(&run.request_id)
            .is_none_or(|request| request.run_id != run.run_id)
        {
            return Err(invalid_snapshot(
                "runs.request_id",
                "run and request reverse links are inconsistent",
            ));
        }
    }
    Ok(())
}

const fn run_status_matches_request(run: RunStatus, request: RequestStatus) -> bool {
    match request {
        RequestStatus::Open => matches!(run, RunStatus::Pending),
        RequestStatus::Assigned | RequestStatus::InProgress => {
            matches!(run, RunStatus::Active | RunStatus::Paused)
        }
        RequestStatus::Blocked => matches!(run, RunStatus::Blocked | RunStatus::Paused),
        RequestStatus::CandidateReady => matches!(run, RunStatus::AwaitingReview),
        RequestStatus::ChangesRequested => matches!(run, RunStatus::RevisionRequested),
        RequestStatus::Accepted => matches!(run, RunStatus::Accepted),
        RequestStatus::IntegrationAuthorized => matches!(run, RunStatus::Authorized),
        RequestStatus::Cancelled => matches!(run, RunStatus::Cancelled),
        RequestStatus::Completed => matches!(run, RunStatus::Completed),
    }
}

fn restore_deliveries(
    workspace_id: &WorkspaceId,
    deliveries: Vec<DeliverySnapshot>,
    actors: &BTreeMap<ActorId, Actor>,
    teams: &BTreeMap<TeamId, Team>,
    requests: &BTreeMap<RequestId, Request>,
    runs: &BTreeMap<RunId, Run>,
) -> Result<BTreeMap<MessageId, DeliveryRecord>, CoreError> {
    let mut restored = BTreeMap::new();
    for (index, delivery) in deliveries.into_iter().enumerate() {
        validate_historical_envelope(
            index,
            workspace_id,
            &delivery.envelope,
            actors,
            teams,
            requests,
            runs,
        )?;
        let mut acknowledgements = BTreeMap::new();
        for acknowledgement in delivery.acknowledgements {
            validate_historical_ack(
                index,
                workspace_id,
                &delivery.envelope,
                &acknowledgement,
                actors,
            )?;
            if acknowledgements
                .insert(acknowledgement.actor.actor_id.clone(), acknowledgement)
                .is_some()
            {
                return Err(invalid_snapshot(
                    format!("deliveries[{index}].acknowledgements"),
                    "duplicate acknowledgement actor",
                ));
            }
        }
        let message_id = delivery.envelope.message_id.clone();
        if restored
            .insert(
                message_id,
                DeliveryRecord {
                    envelope: delivery.envelope,
                    acknowledgements,
                },
            )
            .is_some()
        {
            return Err(invalid_snapshot(
                format!("deliveries[{index}].envelope.message_id"),
                "duplicate message id",
            ));
        }
    }
    Ok(restored)
}

fn validate_historical_envelope(
    index: usize,
    workspace_id: &WorkspaceId,
    envelope: &Envelope,
    actors: &BTreeMap<ActorId, Actor>,
    teams: &BTreeMap<TeamId, Team>,
    requests: &BTreeMap<RequestId, Request>,
    runs: &BTreeMap<RunId, Run>,
) -> Result<(), CoreError> {
    envelope.validate()?;
    let path = format!("deliveries[{index}].envelope");
    if envelope.workspace_id != *workspace_id || !actors.contains_key(&envelope.sender.actor_id) {
        return Err(invalid_snapshot(
            path,
            "delivery workspace or sender is inconsistent",
        ));
    }
    if envelope
        .team_id
        .as_ref()
        .is_some_and(|team_id| !teams.contains_key(team_id))
        || matches!(&envelope.target, MessageTarget::Team(team_id) if !teams.contains_key(team_id))
        || matches!(&envelope.target, MessageTarget::Actor(actor_id) if !actors.contains_key(actor_id))
    {
        return Err(invalid_snapshot(
            format!("deliveries[{index}].envelope.target"),
            "delivery references an unknown actor or team",
        ));
    }
    if let Some(request_id) = &envelope.request_id {
        let request = requests.get(request_id).ok_or_else(|| {
            invalid_snapshot(
                format!("deliveries[{index}].envelope.request_id"),
                "delivery request is missing",
            )
        })?;
        if let Some(run_id) = &envelope.run_id {
            if request.run_id != *run_id {
                return Err(invalid_snapshot(
                    format!("deliveries[{index}].envelope.run_id"),
                    "delivery request and run are inconsistent",
                ));
            }
        }
    }
    if envelope
        .run_id
        .as_ref()
        .is_some_and(|run_id| !runs.contains_key(run_id))
    {
        return Err(invalid_snapshot(
            format!("deliveries[{index}].envelope.run_id"),
            "delivery run is missing",
        ));
    }
    Ok(())
}

fn validate_historical_ack(
    index: usize,
    workspace_id: &WorkspaceId,
    envelope: &Envelope,
    acknowledgement: &Acknowledgement,
    actors: &BTreeMap<ActorId, Actor>,
) -> Result<(), CoreError> {
    if acknowledgement.workspace_id != *workspace_id
        || acknowledgement.message_id != envelope.message_id
    {
        return Err(invalid_snapshot(
            format!("deliveries[{index}].acknowledgements"),
            "acknowledgement workspace or message is inconsistent",
        ));
    }
    let actor = actors.get(&acknowledgement.actor.actor_id).ok_or_else(|| {
        invalid_snapshot(
            format!("deliveries[{index}].acknowledgements.actor"),
            "acknowledging actor is missing",
        )
    })?;
    if !historical_target_matches(&envelope.target, actor) {
        return Err(invalid_snapshot(
            format!("deliveries[{index}].acknowledgements.actor"),
            "acknowledging actor is outside the delivery target",
        ));
    }
    Ok(())
}

fn historical_target_matches(target: &MessageTarget, actor: &Actor) -> bool {
    match target {
        MessageTarget::Primary => actor.role == ActorRole::Primary,
        MessageTarget::Team(team_id) => actor.team_id.as_ref() == Some(team_id),
        MessageTarget::Actor(actor_id) => actor_id == &actor.actor_id,
        MessageTarget::Workspace => true,
    }
}

fn restore_handoffs(
    handoffs: Vec<PendingHandoffSnapshot>,
    actors: &BTreeMap<ActorId, Actor>,
    teams: &BTreeMap<TeamId, Team>,
    requests: &BTreeMap<RequestId, Request>,
) -> Result<BTreeMap<HandoffId, PendingHandoff>, CoreError> {
    let mut restored = BTreeMap::new();
    let mut handoff_requests = BTreeSet::new();
    for (index, handoff) in handoffs.into_iter().enumerate() {
        handoff.offer.validate()?;
        let request = requests.get(&handoff.offer.request_id).ok_or_else(|| {
            invalid_snapshot(
                format!("pending_handoffs[{index}].offer.request_id"),
                "handoff request is missing",
            )
        })?;
        let assignment = request.assignment.as_ref().ok_or_else(|| {
            invalid_snapshot(
                format!("pending_handoffs[{index}].assignment_epoch"),
                "handoff request has no assignment",
            )
        })?;
        if !handoff_requests.insert(request.request_id.clone())
            || matches!(
                request.status,
                RequestStatus::Accepted
                    | RequestStatus::IntegrationAuthorized
                    | RequestStatus::Cancelled
                    | RequestStatus::Completed
            )
        {
            return Err(invalid_snapshot(
                format!("pending_handoffs[{index}].offer.request_id"),
                "request has multiple or ineligible pending handoffs",
            ));
        }
        if request.team_id != handoff.offer.from_team_id
            || !teams.contains_key(&handoff.offer.to_team_id)
            || assignment.actor != handoff.offered_by
            || assignment.epoch != handoff.assignment_epoch
            || actors
                .get(&handoff.offered_by.actor_id)
                .is_none_or(|actor| actor.actor_ref() != handoff.offered_by)
            || handoff
                .offer
                .candidate
                .as_ref()
                .is_some_and(|candidate| request.candidate.as_ref() != Some(candidate))
        {
            return Err(invalid_snapshot(
                format!("pending_handoffs[{index}]"),
                "handoff teams, actor, assignment, or candidate are inconsistent",
            ));
        }
        let handoff_id = handoff.offer.handoff_id.clone();
        if restored
            .insert(
                handoff_id,
                PendingHandoff {
                    offer: handoff.offer,
                    offered_by: handoff.offered_by,
                    assignment_epoch: handoff.assignment_epoch,
                },
            )
            .is_some()
        {
            return Err(invalid_snapshot(
                format!("pending_handoffs[{index}].offer.handoff_id"),
                "duplicate handoff id",
            ));
        }
    }
    Ok(restored)
}

fn validate_audit(
    audit: &[AuditEvent],
    mailbox: &BTreeMap<MessageId, DeliveryRecord>,
) -> Result<(), CoreError> {
    let mut accepted = BTreeSet::new();
    let mut acknowledged = BTreeSet::new();
    for (index, event) in audit.iter().enumerate() {
        let expected = u64::try_from(index)
            .map_err(|_| CoreError::EpochExhausted)?
            .checked_add(1)
            .ok_or(CoreError::EpochExhausted)?;
        if event.sequence != expected {
            return Err(invalid_snapshot(
                format!("audit_events[{index}].sequence"),
                "audit sequence is not contiguous",
            ));
        }
        match &event.kind {
            AuditEventKind::MessageAccepted {
                message_id,
                message_kind,
            } => {
                let delivery = mailbox.get(message_id).ok_or_else(|| {
                    invalid_snapshot(
                        format!("audit_events[{index}].message_id"),
                        "accepted audit message is missing",
                    )
                })?;
                if delivery.envelope.message.kind() != *message_kind
                    || !accepted.insert(message_id.clone())
                {
                    return Err(invalid_snapshot(
                        format!("audit_events[{index}]"),
                        "accepted audit kind is wrong or duplicated",
                    ));
                }
            }
            AuditEventKind::MessageAcknowledged {
                message_id,
                actor_id,
            } => {
                let delivery = mailbox.get(message_id).ok_or_else(|| {
                    invalid_snapshot(
                        format!("audit_events[{index}].message_id"),
                        "acknowledged audit message is missing",
                    )
                })?;
                if !accepted.contains(message_id)
                    || !delivery.acknowledgements.contains_key(actor_id)
                    || !acknowledged.insert((message_id.clone(), actor_id.clone()))
                {
                    return Err(invalid_snapshot(
                        format!("audit_events[{index}]"),
                        "acknowledgement audit link is missing, premature, or duplicated",
                    ));
                }
            }
        }
    }
    for (message_id, delivery) in mailbox {
        if !accepted.contains(message_id)
            || delivery
                .acknowledgements
                .keys()
                .any(|actor_id| !acknowledged.contains(&(message_id.clone(), actor_id.clone())))
        {
            return Err(invalid_snapshot(
                "audit_events",
                "delivery or acknowledgement has no matching audit event",
            ));
        }
    }
    Ok(())
}

fn invalid_snapshot(path: impl Into<String>, reason: &'static str) -> CoreError {
    CoreError::InvalidSnapshot {
        path: path.into(),
        reason,
    }
}

fn context_ids(envelope: &Envelope) -> Result<(RequestId, RunId), CoreError> {
    let request_id = envelope
        .request_id
        .clone()
        .ok_or(CoreError::WrongRequestContext)?;
    let run_id = envelope
        .run_id
        .clone()
        .ok_or(CoreError::WrongRequestContext)?;
    Ok((request_id, run_id))
}
