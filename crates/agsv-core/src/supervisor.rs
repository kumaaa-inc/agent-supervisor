//! Workspace aggregate enforcing authorization, fencing, and idempotency.

use crate::CoreError;
use crate::transitions::{
    RequestEvent, RunEvent, transition_actor, transition_request, transition_run, transition_team,
};
use agsv_protocol::{
    Acknowledgement, Actor, ActorEpoch, ActorId, ActorProfileSnapshot, ActorRef, ActorRole,
    ActorStatus, Assignment, AssignmentEpoch, AuditEvent, AuditEventKind, Candidate, CausalMessage,
    DeliveryRecipient, DeliverySnapshot, DomainSnapshot, Envelope, EnvelopeHeader,
    HUMAN_FACING_PRIMARY_CAPABILITY, HandoffAcceptance, HandoffId, HandoffOffer, HandoffOfferRef,
    HistoryCheckpoint, IMPLEMENTATION_EXECUTION_CAPABILITY, IntegrationAuthorization,
    MAX_ACKNOWLEDGEMENTS, MAX_AUDIT_EVENTS, MAX_DELIVERIES, MAX_DOMAIN_ENTITIES, MAX_FRAME_BYTES,
    MAX_SNAPSHOT_BYTES, Message, MessageId, MessageKind, MessageTarget, PayloadDigest,
    PendingHandoffSnapshot, PolicyRevision, PrimaryEpoch, Request, RequestId,
    RequestSpecificationRef, RequestStatus, ReviewDecision, ReviewDecisionRef, ReviewVerdict, Run,
    RunControlAction, RunId, RunStatus, Team, TeamEpoch, TeamId, TeamProfileSnapshot, TeamStatus,
    TimestampMillis, Validate, WorkspaceId,
};
use sha2::{Digest, Sha256};
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
    /// Immutable text-free accepted envelope header.
    pub envelope: EnvelopeHeader,
    /// Stable full-payload kind.
    pub message_kind: MessageKind,
    /// SHA-256 digest of the full accepted payload.
    pub payload_digest: PayloadDigest,
    /// Text-free facts used for causal replay.
    pub causal: CausalMessage,
    /// Frozen logical recipient requirements.
    pub required_recipients: BTreeSet<DeliveryRecipient>,
    /// At most one acknowledgement per logical recipient.
    pub acknowledgements: BTreeMap<DeliveryRecipient, Acknowledgement>,
    /// Fully acknowledged terminal/coordination history hidden from live inboxes.
    pub retired: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingHandoff {
    offer: HandoffOfferRef,
    offered_by: ActorRef,
    assignment_epoch: AssignmentEpoch,
}

/// Full accepted payload waiting for a state-store transaction to archive it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBulkContent {
    /// Stable accepted message identifier.
    pub message_id: MessageId,
    /// SHA-256 digest used by the compact snapshot.
    pub payload_digest: PayloadDigest,
    /// Full validated protocol payload.
    pub message: Message,
}

/// Bounded provenance for a request referenced by one archived terminal cycle.
///
/// The archive adapter derives this from an independently verified request row
/// and its accepted implementation-request audit event. It lets compact replay
/// prove cross-request dependency ordering without hydrating the referenced
/// request's complete history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchivedRequestReference {
    /// Stable referenced request identifier.
    pub request_id: RequestId,
    /// Team that owned the referenced request when it was created.
    pub team_id: TeamId,
    /// Global audit sequence of its accepted implementation request.
    pub creation_audit_sequence: u64,
}

/// Bounded cross-group fence validation for compact accepted messages.
///
/// Callers feed every archived delivery followed by every hot delivery in one
/// merged global accepted-audit order. The accumulator retains at most one
/// fence per current logical actor/team plus the last Primary lease, avoiding
/// whole-history materialization while still detecting regressions split across
/// independently replayed terminal cycles or across the archive/hot boundary.
#[derive(Clone, Debug)]
pub struct ArchivedFenceValidator {
    workspace_id: WorkspaceId,
    policy_revision: PolicyRevision,
    primary_epoch: PrimaryEpoch,
    active_primary: Option<ActorRef>,
    actors: BTreeMap<ActorId, Actor>,
    teams: BTreeMap<TeamId, Team>,
    previous_audit_sequence: u64,
    last_primary_epoch: Option<PrimaryEpoch>,
    last_primary_actor: Option<ActorId>,
    actor_epochs: BTreeMap<ActorId, ActorEpoch>,
    team_epochs: BTreeMap<TeamId, TeamEpoch>,
}

impl ArchivedFenceValidator {
    /// Validates the next compact delivery in merged global accepted-audit order.
    ///
    /// # Errors
    ///
    /// Returns an invalid-snapshot or protocol validation error when audit
    /// order, workspace, sender, routing, policy, actor/team generation, or
    /// Primary lease facts conflict with current durable topology or regress
    /// relative to an earlier archived group.
    pub fn validate_next(
        &mut self,
        accepted_audit_sequence: u64,
        delivery: &DeliverySnapshot,
    ) -> Result<(), CoreError> {
        if accepted_audit_sequence == 0 || accepted_audit_sequence <= self.previous_audit_sequence {
            return Err(invalid_snapshot(
                "archived_audit.sequence",
                "accepted audit sequence is zero, duplicated, or unordered",
            ));
        }
        self.previous_audit_sequence = accepted_audit_sequence;
        delivery
            .payload_digest
            .validate()
            .map_err(|error| error.at("archived_delivery.payload_digest"))?;
        if delivery.message_kind != delivery.causal.kind() {
            return Err(invalid_snapshot(
                "archived_delivery.causal",
                "causal message kind contradicts the archived payload kind",
            ));
        }
        validate_causal_content_ref(0, delivery)?;
        delivery
            .envelope
            .with_message(replay_message(&delivery.causal))
            .validate()?;
        if delivery.envelope.workspace_id != self.workspace_id
            || delivery.envelope.policy_revision != self.policy_revision
            || delivery.envelope.primary_epoch > self.primary_epoch
        {
            return Err(invalid_snapshot(
                "archived_delivery.envelope",
                "workspace, policy, or Primary fence is inconsistent",
            ));
        }
        self.validate_primary_fence(delivery)?;
        self.validate_actor_and_team_fences(delivery)
    }

    fn validate_primary_fence(&mut self, delivery: &DeliverySnapshot) -> Result<(), CoreError> {
        let epoch = delivery.envelope.primary_epoch;
        if self
            .last_primary_epoch
            .is_some_and(|previous| epoch < previous)
        {
            return Err(invalid_snapshot(
                "archived_delivery.envelope.primary_epoch",
                "accepted Primary epochs regress across archive groups",
            ));
        }
        if self.last_primary_epoch != Some(epoch) {
            self.last_primary_epoch = Some(epoch);
            self.last_primary_actor = None;
        }
        let actor = self
            .actors
            .get(&delivery.envelope.sender.actor_id)
            .ok_or_else(|| {
                invalid_snapshot(
                    "archived_delivery.envelope.sender",
                    "historical sender is missing",
                )
            })?;
        if actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY) && actor.team_id.is_none() {
            if epoch == self.primary_epoch
                && self.active_primary.as_ref() != Some(&delivery.envelope.sender)
            {
                return Err(invalid_snapshot(
                    "archived_delivery.envelope.sender",
                    "current-epoch Primary sender is not the active Primary",
                ));
            }
            if self
                .last_primary_actor
                .as_ref()
                .is_some_and(|existing| existing != &actor.actor_id)
            {
                return Err(invalid_snapshot(
                    "archived_delivery.envelope.primary_epoch",
                    "multiple Primary actors used the same lease epoch across archive groups",
                ));
            }
            self.last_primary_actor = Some(actor.actor_id.clone());
        }
        Ok(())
    }

    fn validate_actor_and_team_fences(
        &mut self,
        delivery: &DeliverySnapshot,
    ) -> Result<(), CoreError> {
        let actor = self
            .actors
            .get(&delivery.envelope.sender.actor_id)
            .expect("sender checked above");
        if delivery.envelope.sender.actor_epoch > actor.epoch
            || self
                .actor_epochs
                .get(&actor.actor_id)
                .is_some_and(|previous| delivery.envelope.sender.actor_epoch < *previous)
        {
            return Err(invalid_snapshot(
                "archived_delivery.envelope.sender.actor_epoch",
                "accepted actor epoch is impossible or regresses across archive groups",
            ));
        }
        self.actor_epochs
            .insert(actor.actor_id.clone(), delivery.envelope.sender.actor_epoch);
        if actor.team_id.is_some() && actor.team_id != delivery.envelope.team_id {
            return Err(invalid_snapshot(
                "archived_delivery.envelope.team_id",
                "team actor used another team context",
            ));
        }
        if let Some(team_id) = &delivery.envelope.team_id {
            let team = self.teams.get(team_id).ok_or_else(|| {
                invalid_snapshot(
                    "archived_delivery.envelope.team_id",
                    "historical team is missing",
                )
            })?;
            let epoch = delivery.envelope.team_epoch.ok_or_else(|| {
                invalid_snapshot(
                    "archived_delivery.envelope.team_epoch",
                    "team fence is missing",
                )
            })?;
            if epoch > team.epoch
                || self
                    .team_epochs
                    .get(team_id)
                    .is_some_and(|previous| epoch < *previous)
            {
                return Err(invalid_snapshot(
                    "archived_delivery.envelope.team_epoch",
                    "accepted team epoch is impossible or regresses across archive groups",
                ));
            }
            self.team_epochs.insert(team_id.clone(), epoch);
        }
        Ok(())
    }
}

struct ReplacementAssignmentPlan {
    active: Vec<(RequestId, RunId, AssignmentEpoch)>,
    terminal: Vec<(RequestId, RunId)>,
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
    history_checkpoint: HistoryCheckpoint,
    pending_bulk_content: Vec<PendingBulkContent>,
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
            history_checkpoint: HistoryCheckpoint::default(),
            pending_bulk_content: Vec::new(),
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
        validate_snapshot_quota(&snapshot)?;
        let DomainSnapshot {
            workspace_id,
            policy_revision,
            primary_epoch,
            active_primary,
            history_checkpoint,
            actors,
            teams,
            requests,
            runs,
            deliveries,
            pending_handoffs,
            audit_events,
        } = snapshot;

        let history_checkpoint = restore_history_checkpoint(history_checkpoint, &audit_events)?;
        let actors = restore_actors(&workspace_id, actors)?;
        validate_active_primary(active_primary.as_ref(), &actors)?;
        let teams = restore_teams(&workspace_id, teams, &actors)?;
        validate_actor_team_links(&actors, &teams)?;
        let requests = restore_requests(&workspace_id, policy_revision, requests, &actors, &teams)?;
        let runs = restore_runs(&workspace_id, runs, &requests, &teams)?;
        validate_request_run_links(&requests, &runs)?;
        let mailbox =
            restore_deliveries(&workspace_id, deliveries, &actors, &teams, &requests, &runs)?;
        let handoffs = restore_handoffs(pending_handoffs, &actors, &teams, &requests)?;
        validate_audit(&audit_events, &mailbox, &history_checkpoint)?;
        validate_causal_history(CausalHistory {
            policy_revision,
            primary_epoch,
            active_primary: active_primary.as_ref(),
            audit: &audit_events,
            mailbox: &mailbox,
            actors: &actors,
            teams: &teams,
            requests: &requests,
            runs: &runs,
            handoffs: &handoffs,
            external_requests: None,
            require_completed_consultations: false,
        })?;

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
            history_checkpoint,
            pending_bulk_content: Vec::new(),
        })
    }

    /// Alias for [`Self::from_snapshot`] for callers that prefer an explicit
    /// fallible-constructor name.
    ///
    /// # Errors
    ///
    /// Returns the same structural, causal, validation, or quota error as
    /// [`Self::from_snapshot`].
    pub fn try_from_snapshot(snapshot: DomainSnapshot) -> Result<Self, CoreError> {
        Self::from_snapshot(snapshot)
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
        self.activate_primary_inner(actor_id, ActorRole::Primary, None)
    }

    /// Activates the sole Primary lease using a configured actor profile.
    ///
    /// The arbitrary role is descriptive only. The snapshotted profile must
    /// explicitly carry `human_facing_primary` before any lease state changes.
    ///
    /// # Errors
    ///
    /// Returns an authorization error for a profile without the capability, or
    /// a conflict when an existing logical actor has different immutable
    /// profile metadata.
    pub fn activate_primary_with_profile(
        &mut self,
        actor_id: ActorId,
        role: ActorRole,
        profile: ActorProfileSnapshot,
    ) -> Result<ActorRef, CoreError> {
        self.activate_primary_inner(actor_id, role, Some(profile))
    }

    fn activate_primary_inner(
        &mut self,
        actor_id: ActorId,
        role: ActorRole,
        profile: Option<ActorProfileSnapshot>,
    ) -> Result<ActorRef, CoreError> {
        if self.actors.len() >= MAX_DOMAIN_ENTITIES && !self.actors.contains_key(&actor_id) {
            return Err(quota("actors", MAX_DOMAIN_ENTITIES));
        }
        let proposed = healthy_actor(
            &self.workspace_id,
            actor_id.clone(),
            None,
            role.clone(),
            profile.clone(),
            ActorEpoch::INITIAL,
        );
        proposed.validate()?;
        if !proposed.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY) {
            return Err(CoreError::Unauthorized(
                "activate Primary without human_facing_primary capability",
            ));
        }
        if self.actors.get(&actor_id).is_some_and(|actor| {
            actor.role != role || actor.profile != profile || actor.team_id.is_some()
        }) {
            return Err(CoreError::AlreadyExists("actor id"));
        }
        if let Some(actor) = self.actors.get(&actor_id).filter(|actor| {
            self.active_primary.as_ref() == Some(&actor_id) && actor.status == ActorStatus::Healthy
        }) {
            return Ok(actor.actor_ref());
        }

        let actor_epoch = self.next_actor_epoch(&actor_id)?;
        let replacement = if let Some(previous) = self.active_primary.clone() {
            let previous_actor = self
                .actors
                .get(&previous)
                .ok_or_else(|| CoreError::UnknownActor(previous.clone()))?;
            let status = transition_actor(previous_actor.status, ActorStatus::Revoked)?;
            let epoch = self
                .primary_epoch
                .checked_next()
                .ok_or(CoreError::EpochExhausted)?;
            Some((previous, status, epoch))
        } else {
            None
        };

        if let Some((previous, status, epoch)) = replacement {
            self.actors
                .get_mut(&previous)
                .ok_or_else(|| CoreError::UnknownActor(previous.clone()))?
                .status = status;
            self.primary_epoch = epoch;
        }
        let actor = healthy_actor(
            &self.workspace_id,
            actor_id.clone(),
            None,
            role,
            profile,
            actor_epoch,
        );
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
    /// Returns an error if the id belongs to a closed or legacy retired team.
    pub fn create_team(&mut self, team_id: TeamId) -> Result<TeamEpoch, CoreError> {
        self.create_team_inner(team_id, None)
    }

    /// Creates a team with immutable configured profile metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the team exists with different profile metadata or
    /// the profile snapshot is invalid.
    pub fn create_team_with_profile(
        &mut self,
        team_id: TeamId,
        profile: TeamProfileSnapshot,
    ) -> Result<TeamEpoch, CoreError> {
        self.create_team_inner(team_id, Some(profile))
    }

    fn create_team_inner(
        &mut self,
        team_id: TeamId,
        profile: Option<TeamProfileSnapshot>,
    ) -> Result<TeamEpoch, CoreError> {
        if let Some(team) = self.teams.get(&team_id) {
            return if team.profile != profile {
                Err(CoreError::AlreadyExists("team profile"))
            } else if matches!(team.status, TeamStatus::Closed | TeamStatus::Retired) {
                Err(CoreError::AlreadyExists("closed team"))
            } else {
                Ok(team.epoch)
            };
        }
        if let Some(profile) = &profile {
            profile.validate()?;
        }
        if self.teams.len() >= MAX_DOMAIN_ENTITIES {
            return Err(quota("teams", MAX_DOMAIN_ENTITIES));
        }
        self.teams.insert(
            team_id.clone(),
            Team {
                team_id,
                workspace_id: self.workspace_id.clone(),
                epoch: TeamEpoch::INITIAL,
                status: TeamStatus::Active,
                actors: Vec::new(),
                profile,
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
            .get(&actor_ref.actor_id)
            .ok_or_else(|| CoreError::UnknownActor(actor_ref.actor_id.clone()))?;
        if actor.epoch != actor_ref.actor_epoch {
            return Err(CoreError::StaleActorEpoch {
                expected: actor.epoch,
                actual: actor_ref.actor_epoch,
            });
        }
        if actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
            && actor.team_id.is_none()
            && status == ActorStatus::Healthy
            && self.active_primary.as_ref() != Some(&actor.actor_id)
        {
            return Err(CoreError::Unauthorized(
                "activate Primary before marking it healthy",
            ));
        }
        let next_status = transition_actor(actor.status, status)?;
        let clears_primary = self.active_primary.as_ref() == Some(&actor.actor_id)
            && next_status != ActorStatus::Healthy;
        let next_primary_epoch = if clears_primary {
            Some(
                self.primary_epoch
                    .checked_next()
                    .ok_or(CoreError::EpochExhausted)?,
            )
        } else {
            None
        };
        self.actors
            .get_mut(&actor_ref.actor_id)
            .ok_or_else(|| CoreError::UnknownActor(actor_ref.actor_id.clone()))?
            .status = next_status;
        if let Some(epoch) = next_primary_epoch {
            self.primary_epoch = epoch;
            self.active_primary = None;
        }
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
        if self.actors.get(&actor_ref.actor_id).is_some_and(|actor| {
            actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
                && actor.team_id.is_none()
                && self.active_primary.as_ref() != Some(&actor.actor_id)
        }) {
            return Err(CoreError::Unauthorized(
                "heartbeat without active Primary lease",
            ));
        }
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
        self.register_implementation_inner(team_id, actor_id, ActorRole::Implementation, None)
    }

    /// Registers a configured actor for a team.
    ///
    /// # Errors
    ///
    /// Returns an error when the team-profile association or an
    /// existing logical actor's immutable profile metadata is inconsistent.
    pub fn register_implementation_with_profile(
        &mut self,
        team_id: &TeamId,
        actor_id: ActorId,
        role: ActorRole,
        profile: ActorProfileSnapshot,
    ) -> Result<ActorRef, CoreError> {
        self.register_implementation_inner(team_id, actor_id, role, Some(profile))
    }

    fn register_implementation_inner(
        &mut self,
        team_id: &TeamId,
        actor_id: ActorId,
        role: ActorRole,
        profile: Option<ActorProfileSnapshot>,
    ) -> Result<ActorRef, CoreError> {
        if self.actors.len() >= MAX_DOMAIN_ENTITIES && !self.actors.contains_key(&actor_id) {
            return Err(quota("actors", MAX_DOMAIN_ENTITIES));
        }
        let team = self
            .teams
            .get(team_id)
            .ok_or_else(|| CoreError::UnknownTeam(team_id.clone()))?;
        if team.status != TeamStatus::Active {
            return Err(CoreError::Unauthorized("register actor for inactive team"));
        }
        ensure_team_profile_actor(team, profile.as_ref())?;
        let proposed = healthy_actor(
            &self.workspace_id,
            actor_id.clone(),
            Some(team_id.clone()),
            role.clone(),
            profile.clone(),
            ActorEpoch::INITIAL,
        );
        proposed.validate()?;
        if let Some(actor) = self.actors.get(&actor_id) {
            if actor.role == role
                && actor.profile == profile
                && actor.team_id.as_ref() == Some(team_id)
                && actor.status == ActorStatus::Healthy
            {
                return Ok(actor.actor_ref());
            }
            return Err(CoreError::AlreadyExists("actor id"));
        }
        if team.actors.len() >= MAX_DOMAIN_ENTITIES {
            return Err(quota("team actors", MAX_DOMAIN_ENTITIES));
        }

        let actor = healthy_actor(
            &self.workspace_id,
            actor_id.clone(),
            Some(team_id.clone()),
            role,
            profile,
            ActorEpoch::INITIAL,
        );
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
    /// Returns an error for an unknown actor, unknown/inactive team, or exhausted epoch.
    pub fn replace_implementation(
        &mut self,
        team_id: &TeamId,
        actor_id: ActorId,
    ) -> Result<ActorRef, CoreError> {
        let team = self
            .teams
            .get(team_id)
            .ok_or_else(|| CoreError::UnknownTeam(team_id.clone()))?;
        let metadata = self
            .actors
            .get(&actor_id)
            .or_else(|| {
                team.actors
                    .iter()
                    .find_map(|candidate| self.actors.get(candidate))
            })
            .map(|actor| (actor.role.clone(), actor.profile.clone()));
        let (role, profile) = metadata.unwrap_or((ActorRole::Implementation, None));
        self.replace_implementation_inner(team_id, actor_id, role, profile)
    }

    /// Replaces a configured team actor while preserving an exact
    /// profile snapshot across the new actor generation.
    ///
    /// # Errors
    ///
    /// Returns an error when supplied metadata differs from the logical actor
    /// or team profile already persisted.
    pub fn replace_implementation_with_profile(
        &mut self,
        team_id: &TeamId,
        actor_id: ActorId,
        role: ActorRole,
        profile: ActorProfileSnapshot,
    ) -> Result<ActorRef, CoreError> {
        self.replace_implementation_inner(team_id, actor_id, role, Some(profile))
    }

    fn replace_implementation_inner(
        &mut self,
        team_id: &TeamId,
        actor_id: ActorId,
        role: ActorRole,
        profile: Option<ActorProfileSnapshot>,
    ) -> Result<ActorRef, CoreError> {
        let team = self
            .teams
            .get(team_id)
            .ok_or_else(|| CoreError::UnknownTeam(team_id.clone()))?;
        if team.status != TeamStatus::Active {
            return Err(CoreError::Unauthorized("replace actor for inactive team"));
        }
        let replaced_actor_id = Self::replacement_source_actor_id(team, &actor_id)?;
        ensure_team_profile_actor(team, profile.as_ref())?;
        let proposed = healthy_actor(
            &self.workspace_id,
            actor_id.clone(),
            Some(team_id.clone()),
            role.clone(),
            profile.clone(),
            ActorEpoch::INITIAL,
        );
        proposed.validate()?;
        if self.actors.get(&actor_id).is_some_and(|actor| {
            actor.role != role
                || actor.profile != profile
                || actor.team_id.as_ref() != Some(team_id)
        }) {
            return Err(CoreError::AlreadyExists("actor id"));
        }
        if self.actors.len() >= MAX_DOMAIN_ENTITIES && !self.actors.contains_key(&actor_id) {
            return Err(quota("actors", MAX_DOMAIN_ENTITIES));
        }
        if team.actors.len() >= MAX_DOMAIN_ENTITIES && !team.actors.contains(&actor_id) {
            return Err(quota("team actors", MAX_DOMAIN_ENTITIES));
        }
        let next_team_epoch = team.epoch.checked_next().ok_or(CoreError::EpochExhausted)?;
        let next_actor_epoch = self.next_actor_epoch(&actor_id)?;
        let replaced_actor_status = self
            .actors
            .get(&replaced_actor_id)
            .filter(|actor| actor.status != ActorStatus::Stopped)
            .map(|actor| transition_actor(actor.status, ActorStatus::Revoked))
            .transpose()?;
        let assignment_plan =
            self.replacement_assignment_plan(team_id, Some(&replaced_actor_id), &actor_id)?;

        if let Some(replaced_actor_status) = replaced_actor_status {
            self.actors
                .get_mut(&replaced_actor_id)
                .expect("replacement actor checked above")
                .status = replaced_actor_status;
        }

        let actor = healthy_actor(
            &self.workspace_id,
            actor_id.clone(),
            Some(team_id.clone()),
            role,
            profile,
            next_actor_epoch,
        );
        self.actors.insert(actor_id.clone(), actor);
        let team = self
            .teams
            .get_mut(team_id)
            .expect("replacement team checked above");
        team.epoch = next_team_epoch;
        if !team.actors.contains(&actor_id) {
            team.actors.push(actor_id.clone());
        }

        let actor_ref = ActorRef {
            actor_id,
            actor_epoch: next_actor_epoch,
        };
        for (request_id, run_id, next_assignment_epoch) in assignment_plan.active {
            let assignment = self
                .requests
                .get_mut(&request_id)
                .and_then(|request| request.assignment.as_mut())
                .expect("replacement assignment checked above");
            assignment.epoch = next_assignment_epoch;
            assignment.actor = actor_ref.clone();
            self.runs
                .get_mut(&run_id)
                .expect("replacement run checked above")
                .assignment = Some(assignment.clone());
            self.handoffs
                .retain(|_, pending| pending.offer.request_id != request_id);
        }
        for (request_id, run_id) in assignment_plan.terminal {
            let assignment = self
                .requests
                .get_mut(&request_id)
                .and_then(|request| request.assignment.as_mut())
                .expect("terminal replacement assignment checked above");
            assignment.actor = actor_ref.clone();
            self.runs
                .get_mut(&run_id)
                .expect("terminal replacement run checked above")
                .assignment = Some(assignment.clone());
        }
        Ok(actor_ref)
    }

    fn replacement_source_actor_id(team: &Team, actor_id: &ActorId) -> Result<ActorId, CoreError> {
        if team.actors.contains(actor_id) {
            Ok(actor_id.clone())
        } else {
            Err(CoreError::UnknownActor(actor_id.clone()))
        }
    }

    fn replacement_assignment_plan(
        &self,
        team_id: &TeamId,
        replaced_actor_id: Option<&ActorId>,
        replacement_actor_id: &ActorId,
    ) -> Result<ReplacementAssignmentPlan, CoreError> {
        let Some(replaced_actor_id) = replaced_actor_id else {
            return Ok(ReplacementAssignmentPlan {
                active: Vec::new(),
                terminal: Vec::new(),
            });
        };
        let mut plan = ReplacementAssignmentPlan {
            active: Vec::new(),
            terminal: Vec::new(),
        };
        for request in self
            .requests
            .values()
            .filter(|request| request.team_id == *team_id)
        {
            let assignment = request
                .assignment
                .as_ref()
                .ok_or(CoreError::NotAssignedActor)?;
            if assignment.actor.actor_id != *replaced_actor_id {
                continue;
            }
            if !self.runs.contains_key(&request.run_id) {
                return Err(CoreError::UnknownRun(request.run_id.clone()));
            }
            if request.status.is_terminal() {
                if replaced_actor_id == replacement_actor_id {
                    plan.terminal
                        .push((request.request_id.clone(), request.run_id.clone()));
                }
            } else {
                let next_epoch = assignment
                    .epoch
                    .checked_next()
                    .ok_or(CoreError::EpochExhausted)?;
                plan.active.push((
                    request.request_id.clone(),
                    request.run_id.clone(),
                    next_epoch,
                ));
            }
        }
        Ok(plan)
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
        validate_envelope_quota(&envelope)?;
        envelope.validate()?;
        if envelope.workspace_id != self.workspace_id {
            return Err(CoreError::WrongWorkspace {
                expected: self.workspace_id.clone(),
                actual: envelope.workspace_id,
            });
        }
        let payload_digest = digest_message(&envelope.message)?;
        let header = EnvelopeHeader::from(&envelope);
        let message_kind = envelope.message.kind();
        let causal = causal_message(&envelope.message_id, &payload_digest, &envelope.message);
        if let Some(existing) = self.mailbox.get(&envelope.message_id) {
            return if existing.envelope == header
                && existing.message_kind == message_kind
                && existing.payload_digest == payload_digest
                && existing.causal == causal
            {
                Ok(ApplyOutcome::Duplicate)
            } else {
                Err(CoreError::DuplicateMessageConflict)
            };
        }
        if self.mailbox.len() >= MAX_DELIVERIES {
            return Err(quota("deliveries", MAX_DELIVERIES));
        }
        self.ensure_audit_capacity()?;
        let sender = self.authorize_envelope(&envelope)?;
        let required_recipients = self.required_recipients(&envelope.target);
        self.apply_message(&envelope, &sender, &payload_digest)?;

        let message_id = envelope.message_id.clone();
        let occurred_at = envelope.sent_at;
        let bulk_message = envelope.message;
        self.mailbox.insert(
            message_id.clone(),
            DeliveryRecord {
                envelope: header,
                message_kind,
                payload_digest: payload_digest.clone(),
                causal,
                required_recipients,
                acknowledgements: BTreeMap::new(),
                retired: false,
            },
        );
        self.pending_bulk_content.push(PendingBulkContent {
            message_id: message_id.clone(),
            payload_digest: payload_digest.clone(),
            message: bulk_message,
        });
        self.append_audit(
            occurred_at,
            AuditEventKind::MessageAccepted {
                message_id,
                message_kind,
                payload_digest: Some(payload_digest),
            },
        );
        self.retire_fully_acknowledged();
        Ok(ApplyOutcome::Applied)
    }

    /// Classifies a retry against one digest-verified external archive row.
    ///
    /// This keeps retired message tombstones out of the in-memory aggregate:
    /// the state store looks up at most the incoming message id and calls this
    /// before normal [`Self::apply`] when an archived row exists.
    ///
    /// # Errors
    ///
    /// Returns the same static/workspace validation errors as [`Self::apply`],
    /// [`CoreError::UnknownMessage`] when the supplied archive row has another
    /// id, or [`CoreError::DuplicateMessageConflict`] for a non-exact retry.
    pub fn classify_archived_retry(
        &self,
        envelope: &Envelope,
        archived: &DeliverySnapshot,
    ) -> Result<ApplyOutcome, CoreError> {
        validate_envelope_quota(envelope)?;
        envelope.validate()?;
        if envelope.workspace_id != self.workspace_id {
            return Err(CoreError::WrongWorkspace {
                expected: self.workspace_id.clone(),
                actual: envelope.workspace_id.clone(),
            });
        }
        if envelope.message_id != archived.envelope.message_id {
            return Err(CoreError::UnknownMessage);
        }
        let payload_digest = digest_message(&envelope.message)?;
        let causal = causal_message(&envelope.message_id, &payload_digest, &envelope.message);
        if archived.envelope == EnvelopeHeader::from(envelope)
            && archived.message_kind == envelope.message.kind()
            && archived.payload_digest == payload_digest
            && archived.causal == causal
        {
            Ok(ApplyOutcome::Duplicate)
        } else {
            Err(CoreError::DuplicateMessageConflict)
        }
    }

    /// Classifies an acknowledgement retry against one verified archived row.
    ///
    /// Exact retries remain idempotent after actor replacement. A changed actor
    /// generation or timestamp for the same frozen logical recipient conflicts,
    /// matching the live-delivery acknowledgement semantics.
    ///
    /// # Errors
    ///
    /// Returns workspace/message errors, duplicate acknowledgement conflicts,
    /// current-actor fencing errors for a previously unknown recipient, or
    /// [`CoreError::AckNotAuthorized`] because archived delivery is retired.
    pub fn classify_archived_ack(
        &self,
        acknowledgement: &Acknowledgement,
        archived: &DeliverySnapshot,
    ) -> Result<AckOutcome, CoreError> {
        if acknowledgement.workspace_id != self.workspace_id {
            return Err(CoreError::WrongWorkspace {
                expected: self.workspace_id.clone(),
                actual: acknowledgement.workspace_id.clone(),
            });
        }
        if acknowledgement.message_id != archived.envelope.message_id {
            return Err(CoreError::UnknownMessage);
        }
        let recipient =
            Self::recipient_for_actor(&archived.envelope.target, &acknowledgement.actor);
        let existing = archived.acknowledgements.iter().find(|existing| {
            Self::recipient_for_actor(&archived.envelope.target, &existing.actor) == recipient
        });
        if let Some(existing) = existing {
            return if existing == acknowledgement {
                Ok(AckOutcome::Duplicate)
            } else {
                Err(CoreError::DuplicateAcknowledgementConflict)
            };
        }
        let actor = self.current_actor(&acknowledgement.actor)?;
        if actor.status != ActorStatus::Healthy {
            return Err(CoreError::ActorNotHealthy(actor.actor_id.clone()));
        }
        Err(CoreError::AckNotAuthorized)
    }

    /// Creates a bounded validator for archived and then hot compact deliveries
    /// streamed in one merged global accepted-audit order.
    #[must_use]
    pub fn archived_fence_validator(&self) -> ArchivedFenceValidator {
        ArchivedFenceValidator {
            workspace_id: self.workspace_id.clone(),
            policy_revision: self.policy_revision,
            primary_epoch: self.primary_epoch,
            active_primary: self.active_primary(),
            actors: self.actors.clone(),
            teams: self.teams.clone(),
            previous_audit_sequence: 0,
            last_primary_epoch: None,
            last_primary_actor: None,
            actor_epochs: BTreeMap::new(),
            team_epochs: BTreeMap::new(),
        }
    }

    /// Validates one atomically archived terminal request cycle.
    ///
    /// The supplied deliveries and audit events must be the complete history
    /// scoped to `request`. Cross-request dependency facts are represented by
    /// independently verified compact references, so validation remains
    /// bounded by one terminal cycle rather than total workspace history.
    ///
    /// # Errors
    ///
    /// Returns an invalid-snapshot, validation, or quota error when request/run
    /// links, delivery structure, audit provenance, lifecycle replay, or an
    /// external dependency reference is incomplete or inconsistent.
    pub fn validate_archived_terminal_cycle(
        &self,
        request: &Request,
        run: &Run,
        deliveries: &[DeliverySnapshot],
        audit_events: &[AuditEvent],
        referenced_requests: &[ArchivedRequestReference],
    ) -> Result<(), CoreError> {
        if !request.status.is_terminal() {
            return Err(invalid_snapshot(
                "archived_request.status",
                "archived request cycle is not terminal",
            ));
        }
        validate_archived_group_quota(deliveries, audit_events)?;
        if deliveries.iter().any(|delivery| {
            if delivery.envelope.request_id.is_none() && delivery.envelope.run_id.is_none() {
                return !matches!(delivery.causal, CausalMessage::ConsultationResponse { .. });
            }
            delivery.envelope.request_id.as_ref() != Some(&request.request_id)
                || delivery.envelope.run_id.as_ref() != Some(&run.run_id)
        }) {
            return Err(invalid_snapshot(
                "archived_deliveries.envelope.request_id",
                "terminal cycle contains unrelated request, run, or requestless history",
            ));
        }

        let requests = restore_requests(
            &self.workspace_id,
            self.policy_revision,
            vec![request.clone()],
            &self.actors,
            &self.teams,
        )?;
        let runs = restore_runs(
            &self.workspace_id,
            vec![run.clone()],
            &requests,
            &self.teams,
        )?;
        validate_request_run_links(&requests, &runs)?;
        let mailbox = restore_deliveries(
            &self.workspace_id,
            deliveries.to_vec(),
            &self.actors,
            &self.teams,
            &requests,
            &runs,
        )?;
        validate_archived_audit(audit_events, &mailbox)?;
        let external_requests = restore_archived_request_references(
            referenced_requests,
            &request.request_id,
            &self.teams,
        )?;
        let active_primary = self.active_primary();
        let handoffs = BTreeMap::new();
        validate_causal_history(CausalHistory {
            policy_revision: self.policy_revision,
            primary_epoch: self.primary_epoch,
            active_primary: active_primary.as_ref(),
            audit: audit_events,
            mailbox: &mailbox,
            actors: &self.actors,
            teams: &self.teams,
            requests: &requests,
            runs: &runs,
            handoffs: &handoffs,
            external_requests: Some(&external_requests),
            require_completed_consultations: true,
        })
    }

    /// Validates a complete archived requestless history group.
    ///
    /// Store adapters use this for a completed consultation request/response
    /// pair or for independently stateless requestless coordination messages.
    /// An unanswered consultation is rejected because it must remain hot until
    /// its correlated response can be archived in the same group.
    ///
    /// # Errors
    ///
    /// Returns an invalid-snapshot, validation, or quota error for forged
    /// delivery, audit, routing, fencing, or consultation-correlation facts.
    pub fn validate_archived_requestless_history(
        &self,
        deliveries: &[DeliverySnapshot],
        audit_events: &[AuditEvent],
    ) -> Result<(), CoreError> {
        validate_archived_group_quota(deliveries, audit_events)?;
        if deliveries.iter().any(|delivery| {
            delivery.envelope.request_id.is_some() || delivery.envelope.run_id.is_some()
        }) {
            return Err(invalid_snapshot(
                "archived_deliveries.envelope.request_id",
                "requestless archive group contains request-scoped history",
            ));
        }
        let requests = BTreeMap::new();
        let runs = BTreeMap::new();
        let handoffs = BTreeMap::new();
        let mailbox = restore_deliveries(
            &self.workspace_id,
            deliveries.to_vec(),
            &self.actors,
            &self.teams,
            &requests,
            &runs,
        )?;
        validate_archived_audit(audit_events, &mailbox)?;
        let active_primary = self.active_primary();
        validate_causal_history(CausalHistory {
            policy_revision: self.policy_revision,
            primary_epoch: self.primary_epoch,
            active_primary: active_primary.as_ref(),
            audit: audit_events,
            mailbox: &mailbox,
            actors: &self.actors,
            teams: &self.teams,
            requests: &requests,
            runs: &runs,
            handoffs: &handoffs,
            external_requests: None,
            require_completed_consultations: true,
        })
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
        let delivery = self
            .mailbox
            .get(&acknowledgement.message_id)
            .ok_or(CoreError::UnknownMessage)?;
        let recipient =
            Self::recipient_for_actor(&delivery.envelope.target, &acknowledgement.actor);
        if let Some(existing) = delivery.acknowledgements.get(&recipient) {
            return if existing == &acknowledgement {
                Ok(AckOutcome::Duplicate)
            } else {
                Err(CoreError::DuplicateAcknowledgementConflict)
            };
        }
        let actor = self.current_actor(&acknowledgement.actor)?.clone();
        if actor.status != ActorStatus::Healthy {
            return Err(CoreError::ActorNotHealthy(actor.actor_id));
        }
        let envelope = delivery.envelope.clone();
        if delivery.retired
            || !delivery.required_recipients.contains(&recipient)
            || !self.target_matches(&envelope.target, &actor)
        {
            return Err(CoreError::AckNotAuthorized);
        }
        if delivery.acknowledgements.len() >= MAX_ACKNOWLEDGEMENTS {
            return Err(quota("acknowledgements", MAX_ACKNOWLEDGEMENTS));
        }
        self.ensure_audit_capacity()?;
        let message_id = acknowledgement.message_id.clone();
        let actor_id = acknowledgement.actor.actor_id.clone();
        let occurred_at = acknowledgement.acknowledged_at;
        self.mailbox
            .get_mut(&message_id)
            .ok_or(CoreError::UnknownMessage)?
            .acknowledgements
            .insert(recipient, acknowledgement);
        self.append_audit(
            occurred_at,
            AuditEventKind::MessageAcknowledged {
                message_id,
                actor_id,
            },
        );
        self.retire_fully_acknowledged();
        Ok(AckOutcome::Acknowledged)
    }

    /// Returns compact message ids currently routed to an actor generation.
    ///
    /// # Errors
    ///
    /// Returns an error if the actor generation is unknown, stale, or unhealthy.
    pub fn unacknowledged_message_ids_for(
        &self,
        actor_ref: &ActorRef,
    ) -> Result<Vec<MessageId>, CoreError> {
        let actor = self.current_actor(actor_ref)?;
        if actor.status != ActorStatus::Healthy {
            return Err(CoreError::ActorNotHealthy(actor.actor_id.clone()));
        }
        Ok(self
            .mailbox
            .values()
            .filter(|delivery| {
                let recipient = Self::recipient_for_actor(&delivery.envelope.target, actor_ref);
                !delivery.retired
                    && delivery.required_recipients.contains(&recipient)
                    && self.target_matches(&delivery.envelope.target, actor)
                    && !delivery.acknowledgements.contains_key(&recipient)
            })
            .map(|delivery| delivery.envelope.message_id.clone())
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

    /// Takes full accepted payloads waiting for transactional archival.
    ///
    /// Restored supervisors start with an empty queue. The state store should call
    /// this only while staging the same transaction that persists [`Self::snapshot`].
    pub fn take_pending_bulk_content(&mut self) -> Vec<PendingBulkContent> {
        std::mem::take(&mut self.pending_bulk_content)
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
            history_checkpoint: self.history_checkpoint.clone(),
            actors: self.actors.values().cloned().collect(),
            teams: self.teams.values().cloned().collect(),
            requests: self.requests.values().cloned().collect(),
            runs: self.runs.values().cloned().collect(),
            deliveries: self
                .mailbox
                .values()
                .map(|delivery| DeliverySnapshot {
                    envelope: delivery.envelope.clone(),
                    message_kind: delivery.message_kind,
                    payload_digest: delivery.payload_digest.clone(),
                    causal: delivery.causal.clone(),
                    required_recipients: delivery.required_recipients.clone(),
                    acknowledgements: delivery.acknowledgements.values().cloned().collect(),
                    retired: delivery.retired,
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
        if actor.team_id.is_some() && actor.team_id != envelope.team_id {
            return Err(CoreError::WrongTeam);
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
            if actor.team_id.is_some()
                && matches!(
                    team.status,
                    TeamStatus::Paused | TeamStatus::Closed | TeamStatus::Retired
                )
            {
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

    fn require_primary(&self, actor: &Actor, action: &'static str) -> Result<(), CoreError> {
        if actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
            && actor.team_id.is_none()
            && self.active_primary.as_ref() == Some(&actor.actor_id)
        {
            Ok(())
        } else {
            Err(CoreError::Unauthorized(action))
        }
    }

    fn require_implementation(actor: &Actor, action: &'static str) -> Result<(), CoreError> {
        if actor.has_capability(IMPLEMENTATION_EXECUTION_CAPABILITY) {
            Ok(())
        } else {
            Err(CoreError::Unauthorized(action))
        }
    }

    fn require_consultation_requester(&self, actor: &Actor) -> Result<(), CoreError> {
        if actor.team_id.is_some() && actor.has_capability(IMPLEMENTATION_EXECUTION_CAPABILITY) {
            Ok(())
        } else {
            self.require_primary(actor, "request consultation")
        }
    }

    // This exhaustive dispatcher intentionally keeps every wire variant beside
    // the compact semantic facts derived from it.
    #[allow(clippy::too_many_lines)]
    fn apply_message(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        payload_digest: &PayloadDigest,
    ) -> Result<(), CoreError> {
        if envelope.request_id.is_some()
            && !matches!(envelope.message, Message::ImplementationRequest(_))
        {
            self.request_context(envelope)?;
        }
        match &envelope.message {
            Message::ImplementationRequest(specification) => self.apply_implementation_request(
                envelope,
                actor,
                RequestSpecificationRef {
                    message_id: envelope.message_id.clone(),
                    payload_digest: payload_digest.clone(),
                    base_sha: specification.base_sha.clone(),
                },
            ),
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
                self.require_primary(actor, "submit review decision")?;
                self.apply_review(
                    envelope,
                    actor,
                    ReviewDecisionRef {
                        message_id: envelope.message_id.clone(),
                        payload_digest: payload_digest.clone(),
                        decision_id: decision.decision_id.clone(),
                        candidate: decision.candidate.clone(),
                        verdict: decision.verdict,
                        reviewer: decision.reviewer.clone(),
                        policy_revision: decision.policy_revision,
                    },
                )
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
                self.require_primary(actor, "authorize integration")?;
                self.ensure_assignee_target(envelope)?;
                self.apply_integration_authorization(envelope, actor, authorization.clone())
            }
            Message::Cancellation(_) => self.apply_cancellation(envelope, actor),
            Message::RunControl(control) => self.apply_run_control(envelope, actor, control.action),
            Message::ConsultationRequest(consultation) => {
                self.apply_consultation_request(envelope, actor, consultation)
            }
            Message::ConsultationResponse(response) => {
                self.apply_consultation_response(envelope, actor, response)
            }
            Message::DependencyNotice(notice) => {
                self.apply_dependency_notice(envelope, actor, notice)
            }
            Message::ConflictNotice(notice) => {
                Self::require_implementation(actor, "report conflict")?;
                let sender_team_id = actor.team_id.as_ref().ok_or(CoreError::WrongTeam)?;
                if sender_team_id == &notice.other_team_id {
                    return Err(CoreError::WrongTeam);
                }
                self.ensure_active_target_team(&notice.other_team_id, &envelope.target)
            }
            Message::HandoffOffer(offer) => {
                Self::require_implementation(actor, "offer handoff")?;
                self.ensure_current_assignment(envelope, actor)?;
                self.apply_handoff_offer(
                    envelope,
                    actor,
                    HandoffOfferRef {
                        message_id: envelope.message_id.clone(),
                        payload_digest: payload_digest.clone(),
                        handoff_id: offer.handoff_id.clone(),
                        request_id: offer.request_id.clone(),
                        from_team_id: offer.from_team_id.clone(),
                        to_team_id: offer.to_team_id.clone(),
                        candidate: offer.candidate.clone(),
                    },
                )
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

    fn apply_consultation_request(
        &self,
        envelope: &Envelope,
        actor: &Actor,
        consultation: &agsv_protocol::ConsultationRequest,
    ) -> Result<(), CoreError> {
        self.require_consultation_requester(actor)?;
        if consultation.consultation_id != envelope.message_id {
            return Err(CoreError::WrongRequestContext);
        }
        if actor.team_id.as_ref() == Some(&consultation.target_team_id) {
            return Err(CoreError::WrongTeam);
        }
        self.ensure_active_target_team(&consultation.target_team_id, &envelope.target)
    }

    fn apply_consultation_response(
        &self,
        envelope: &Envelope,
        actor: &Actor,
        response: &agsv_protocol::ConsultationResponse,
    ) -> Result<(), CoreError> {
        Self::require_implementation(actor, "answer consultation")?;
        if actor.team_id.as_ref() != Some(&response.responding_team_id) {
            return Err(CoreError::WrongTeam);
        }
        let (request_envelope, target_team_id) = self
            .mailbox
            .values()
            .find_map(|delivery| match &delivery.causal {
                CausalMessage::ConsultationRequest {
                    consultation_id,
                    target_team_id,
                } if consultation_id == &response.consultation_id => {
                    Some((&delivery.envelope, target_team_id))
                }
                _ => None,
            })
            .ok_or(CoreError::UnknownMessage)?;
        if target_team_id != &response.responding_team_id {
            return Err(CoreError::WrongTeam);
        }
        let expected_target = if self
            .actors
            .get(&request_envelope.sender.actor_id)
            .is_some_and(|requester| {
                requester.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
                    && requester.team_id.is_none()
            }) {
            MessageTarget::Primary
        } else {
            MessageTarget::Actor(request_envelope.sender.actor_id.clone())
        };
        if envelope.target != expected_target {
            return Err(CoreError::WrongTarget);
        }
        Ok(())
    }

    fn apply_dependency_notice(
        &self,
        envelope: &Envelope,
        actor: &Actor,
        notice: &agsv_protocol::DependencyNotice,
    ) -> Result<(), CoreError> {
        Self::require_implementation(actor, "declare dependency")?;
        self.ensure_current_assignment(envelope, actor)?;
        let blocked = self.request_context(envelope)?;
        if blocked.request_id != notice.blocked_request_id {
            return Err(CoreError::WrongRequestContext);
        }
        let dependency = self
            .requests
            .get(&notice.depends_on_request_id)
            .ok_or_else(|| CoreError::UnknownRequest(notice.depends_on_request_id.clone()))?;
        if dependency.team_id != notice.provider_team_id {
            return Err(CoreError::WrongTeam);
        }
        self.ensure_active_target_team(&notice.provider_team_id, &envelope.target)
    }

    fn apply_fix_request(
        &self,
        envelope: &Envelope,
        actor: &Actor,
        fix: &agsv_protocol::FixRequest,
    ) -> Result<(), CoreError> {
        self.require_primary(actor, "request fixes")?;
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
        self.require_primary(actor, "cancel request")?;
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

    fn apply_run_control(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        action: RunControlAction,
    ) -> Result<(), CoreError> {
        self.require_primary(actor, "control run")?;
        self.ensure_assignee_target(envelope)?;
        if envelope.assignment_epoch.is_some() {
            return Err(CoreError::Unauthorized(
                "Primary run control cannot carry an executor assignment fence",
            ));
        }
        let request = self.request_context(envelope)?;
        let request_id = request.request_id.clone();
        let run_id = request.run_id.clone();
        let next_request = match action {
            RunControlAction::Pause => request.status,
            RunControlAction::Resume => transition_request(request.status, RequestEvent::Start)?,
        };
        let run = self
            .runs
            .get(&run_id)
            .ok_or_else(|| CoreError::UnknownRun(run_id.clone()))?;
        let run_event = match action {
            RunControlAction::Pause => RunEvent::Pause,
            RunControlAction::Resume => RunEvent::Resume,
        };
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

    fn apply_integration_complete(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        complete: &agsv_protocol::IntegrationComplete,
    ) -> Result<(), CoreError> {
        self.require_primary(actor, "report integration complete")?;
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
        specification: RequestSpecificationRef,
    ) -> Result<(), CoreError> {
        self.require_primary(actor, "create implementation request")?;
        let (request_id, run_id) = context_ids(envelope)?;
        if self.requests.len() >= MAX_DOMAIN_ENTITIES || self.runs.len() >= MAX_DOMAIN_ENTITIES {
            return Err(quota("requests or runs", MAX_DOMAIN_ENTITIES));
        }
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
        if !target_actor.has_capability(IMPLEMENTATION_EXECUTION_CAPABILITY)
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
            rejection_count: 0,
            fix_cycle_depth: 0,
            candidate_history: Vec::new(),
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
        if candidate.team_id != request.team_id
            || candidate.created_by != actor.actor_ref()
            || candidate.created_by_profile
                != actor.profile.as_ref().map(|profile| profile.name.clone())
        {
            return Err(CoreError::Unauthorized("submit candidate identity"));
        }
        let rejected_rework = is_rejected_candidate_rework(request);
        let is_new_candidate = request.candidate.as_ref() != Some(&candidate);
        // A request restored with the all-default metric shape predates this
        // observational instrumentation. Keep that shape compatible instead
        // of manufacturing a partial history from only future events.
        let track_candidate = is_new_candidate
            && (request.candidate.is_none() || !request.candidate_history.is_empty());
        match &request.candidate {
            Some(previous) if rejected_rework => {
                if previous.sha == candidate.sha {
                    return Err(CoreError::CandidateMustChange);
                }
            }
            Some(previous) if previous != &candidate => {
                return Err(CoreError::CandidateMismatch {
                    expected: Some(previous.sha.clone()),
                    actual: candidate.sha,
                });
            }
            _ => {}
        }
        if track_candidate && request.candidate_history.len() >= MAX_DOMAIN_ENTITIES {
            return Err(quota("candidate history", MAX_DOMAIN_ENTITIES));
        }
        let next_fix_cycle_depth = if rejected_rework && track_candidate {
            Some(
                request
                    .fix_cycle_depth
                    .checked_add(1)
                    .ok_or(CoreError::EpochExhausted)?,
            )
        } else {
            None
        };
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
        if track_candidate {
            request.candidate_history.push(candidate.clone());
        }
        if let Some(depth) = next_fix_cycle_depth {
            request.fix_cycle_depth = depth;
        }
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
        decision: ReviewDecisionRef,
    ) -> Result<(), CoreError> {
        if self.mailbox.values().any(|delivery| {
            matches!(
                &delivery.causal,
                CausalMessage::ReviewDecision(existing)
                    if existing.decision_id == decision.decision_id
            )
        }) {
            return Err(CoreError::AlreadyExists("decision id"));
        }
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
        let next_rejection_count = if decision.verdict == ReviewVerdict::Rejected
            && !request.candidate_history.is_empty()
        {
            Some(
                request
                    .rejection_count
                    .checked_add(1)
                    .ok_or(CoreError::EpochExhausted)?,
            )
        } else {
            None
        };
        let request_id = request.request_id.clone();
        let verdict = decision.verdict;
        let request = self
            .requests
            .get_mut(&request_id)
            .expect("request checked above");
        request.status = next_request;
        if let Some(count) = next_rejection_count {
            request.rejection_count = count;
        }
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
        let team_matches = match &envelope.message {
            Message::HandoffAcceptance(acceptance) => {
                request.team_id == acceptance.from_team_id
                    && envelope.team_id.as_ref() == Some(&acceptance.to_team_id)
            }
            _ => envelope.team_id.as_ref() == Some(&request.team_id),
        };
        if !team_matches {
            return Err(CoreError::WrongTeam);
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
        offer: HandoffOfferRef,
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
        if self.ensure_known_team(&acceptance.to_team_id)?.status != TeamStatus::Active {
            return Err(CoreError::Unauthorized("assign work to inactive team"));
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
                actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
                    && self.active_primary.as_ref() == Some(&actor.actor_id)
            }
            MessageTarget::Team(team_id) => actor.team_id.as_ref() == Some(team_id),
            MessageTarget::Actor(actor_id) => actor_id == &actor.actor_id,
            MessageTarget::Workspace => true,
        }
    }

    fn required_recipients(&self, target: &MessageTarget) -> BTreeSet<DeliveryRecipient> {
        match target {
            MessageTarget::Primary => BTreeSet::from([DeliveryRecipient::Primary]),
            MessageTarget::Actor(actor_id) => {
                BTreeSet::from([DeliveryRecipient::Actor(actor_id.clone())])
            }
            MessageTarget::Team(team_id) => self
                .actors
                .values()
                .filter(|actor| {
                    actor.status == ActorStatus::Healthy && actor.team_id.as_ref() == Some(team_id)
                })
                .map(|actor| DeliveryRecipient::Actor(actor.actor_id.clone()))
                .collect(),
            MessageTarget::Workspace => self
                .actors
                .values()
                .filter(|actor| actor.status == ActorStatus::Healthy)
                .map(|actor| DeliveryRecipient::Actor(actor.actor_id.clone()))
                .collect(),
        }
    }

    fn recipient_for_actor(target: &MessageTarget, actor: &ActorRef) -> DeliveryRecipient {
        if matches!(target, MessageTarget::Primary) {
            DeliveryRecipient::Primary
        } else {
            DeliveryRecipient::Actor(actor.actor_id.clone())
        }
    }

    fn retire_fully_acknowledged(&mut self) {
        for delivery in self
            .mailbox
            .values_mut()
            .filter(|delivery| !delivery.retired)
        {
            let fully_acknowledged = !delivery.required_recipients.is_empty()
                && delivery
                    .required_recipients
                    .iter()
                    .all(|recipient| delivery.acknowledgements.contains_key(recipient));
            let eligible = delivery
                .envelope
                .request_id
                .as_ref()
                .is_none_or(|request_id| {
                    self.requests
                        .get(request_id)
                        .is_some_and(|request| request.status.is_terminal())
                });
            if fully_acknowledged && eligible {
                delivery.retired = true;
            }
        }
    }

    fn ensure_audit_capacity(&self) -> Result<(), CoreError> {
        if self.audit.len() >= MAX_AUDIT_EVENTS {
            return Err(quota("audit_events", MAX_AUDIT_EVENTS));
        }
        self.history_checkpoint
            .audit_event_count
            .checked_add(1)
            .ok_or(CoreError::EpochExhausted)?;
        Ok(())
    }

    fn append_audit(&mut self, occurred_at: TimestampMillis, kind: AuditEventKind) {
        let sequence = self
            .history_checkpoint
            .audit_event_count
            .checked_add(1)
            .expect("capacity checked");
        let event = AuditEvent {
            sequence,
            occurred_at,
            kind,
        };
        self.history_checkpoint.audit_event_count = sequence;
        self.history_checkpoint.audit_head_sha256 = Some(
            digest_audit_event(&event).expect("AuditEvent always serializes to canonical JSON"),
        );
        self.audit.push(event);
    }
}

impl TryFrom<DomainSnapshot> for Supervisor {
    type Error = CoreError;

    fn try_from(snapshot: DomainSnapshot) -> Result<Self, Self::Error> {
        Self::from_snapshot(snapshot)
    }
}

fn healthy_actor(
    workspace_id: &WorkspaceId,
    actor_id: ActorId,
    team_id: Option<TeamId>,
    role: ActorRole,
    profile: Option<ActorProfileSnapshot>,
    epoch: ActorEpoch,
) -> Actor {
    Actor {
        actor_id,
        workspace_id: workspace_id.clone(),
        team_id,
        role,
        profile,
        epoch,
        status: ActorStatus::Healthy,
        last_heartbeat_at: None,
    }
}

fn ensure_team_profile_actor(
    team: &Team,
    actor_profile: Option<&ActorProfileSnapshot>,
) -> Result<(), CoreError> {
    if match (&team.profile, actor_profile) {
        (None, None) => true,
        (Some(team_profile), Some(actor_profile)) => {
            team_profile.actor_profile == actor_profile.name
        }
        (None, Some(_)) | (Some(_), None) => false,
    } {
        Ok(())
    } else {
        Err(CoreError::AlreadyExists("team actor profile"))
    }
}

fn team_profile_matches_actor(team: &Team, actor: &Actor) -> bool {
    match (&team.profile, &actor.profile) {
        (None, None) => true,
        (Some(team_profile), Some(actor_profile)) => {
            team_profile.actor_profile == actor_profile.name
        }
        (None, Some(_)) | (Some(_), None) => false,
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
        if !actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
            || actor.actor_ref() != *actor_ref
            || actor.status != ActorStatus::Healthy
            || actor.team_id.is_some()
        {
            return Err(invalid_snapshot(
                "active_primary",
                "active Primary capability, topology, actor epoch, or health is inconsistent",
            ));
        }
    }
    for actor in actors.values().filter(|actor| {
        actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
            && actor.team_id.is_none()
            && actor.status == ActorStatus::Healthy
    }) {
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
        team.validate()
            .map_err(|error| error.at(&format!("teams[{index}]")))?;
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
            if actor.team_id.as_ref() != Some(&team.team_id)
                || !team_profile_matches_actor(&team, actor)
            {
                return Err(invalid_snapshot(
                    format!("teams[{index}].actors"),
                    "team actor profile or reverse team link is inconsistent",
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
    for actor in actors.values().filter(|actor| actor.team_id.is_some()) {
        let team_id = actor.team_id.as_ref().expect("filtered actors have a team");
        let team = teams
            .get(team_id)
            .ok_or_else(|| invalid_snapshot("actors.team_id", "actor team is missing"))?;
        if !team.actors.contains(&actor.actor_id) || !team_profile_matches_actor(team, actor) {
            return Err(invalid_snapshot(
                "actors.team_id",
                "team actor profile or reverse link is inconsistent",
            ));
        }
    }
    Ok(())
}

fn restore_requests(
    workspace_id: &WorkspaceId,
    policy_revision: PolicyRevision,
    requests: Vec<Request>,
    actors: &BTreeMap<ActorId, Actor>,
    teams: &BTreeMap<TeamId, Team>,
) -> Result<BTreeMap<RequestId, Request>, CoreError> {
    let mut restored = BTreeMap::new();
    let mut decision_ids = BTreeSet::new();
    for (index, request) in requests.into_iter().enumerate() {
        validate_request(
            index,
            workspace_id,
            policy_revision,
            &request,
            actors,
            teams,
        )?;
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
    policy_revision: PolicyRevision,
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
    request
        .specification
        .payload_digest
        .validate()
        .map_err(|error| error.at(&format!("{path}.specification.payload_digest")))?;
    validate_request_assignment(&path, request, actors)?;
    validate_request_candidate(&path, request, actors, teams)?;
    validate_request_review_state(&path, policy_revision, request, actors)?;
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
                || !actor.has_capability(IMPLEMENTATION_EXECUTION_CAPABILITY)
                || actor.team_id.as_ref() != Some(&request.team_id)
            {
                return Err(invalid_snapshot(
                    format!("{path}.assignment.actor"),
                    "assignment actor generation, capability, or team is inconsistent",
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
    let legacy_metrics = request_metrics_are_legacy_default(request);
    let Some(candidate) = &request.candidate else {
        if request.decision.is_some()
            || request.integration_authorization.is_some()
            || !legacy_metrics
        {
            return Err(invalid_snapshot(
                format!("{path}.candidate"),
                "review state or outcome metrics exist without a candidate",
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
    validate_candidate_provenance(
        &format!("{path}.candidate"),
        &request.request_id,
        candidate,
        actors,
        teams,
    )?;
    if legacy_metrics {
        return Ok(());
    }
    if request.candidate_history.is_empty() {
        return Err(invalid_snapshot(
            format!("{path}.candidate_history"),
            "instrumented candidate history is empty",
        ));
    }
    if request.candidate_history.last() != Some(candidate) {
        return Err(invalid_snapshot(
            format!("{path}.candidate_history"),
            "candidate history does not end at the current candidate",
        ));
    }
    for (index, historical) in request.candidate_history.iter().enumerate() {
        validate_candidate_provenance(
            &format!("{path}.candidate_history[{index}]"),
            &request.request_id,
            historical,
            actors,
            teams,
        )?;
    }
    if request
        .candidate_history
        .windows(2)
        .any(|pair| pair[0].sha == pair[1].sha)
    {
        return Err(invalid_snapshot(
            format!("{path}.candidate_history"),
            "successive rejected candidates must use different commits",
        ));
    }
    let expected_fix_cycle_depth = u64::try_from(request.candidate_history.len() - 1)
        .map_err(|_| CoreError::EpochExhausted)?;
    if request.fix_cycle_depth != expected_fix_cycle_depth {
        return Err(invalid_snapshot(
            format!("{path}.fix_cycle_depth"),
            "fix-cycle depth does not match candidate history",
        ));
    }
    let current_is_rejected = request
        .decision
        .as_ref()
        .is_some_and(|decision| decision.verdict == ReviewVerdict::Rejected);
    let expected_rejection_count = expected_fix_cycle_depth
        .checked_add(u64::from(current_is_rejected))
        .ok_or(CoreError::EpochExhausted)?;
    if request.rejection_count != expected_rejection_count {
        return Err(invalid_snapshot(
            format!("{path}.rejection_count"),
            "rejection count does not match candidate review history",
        ));
    }
    Ok(())
}

fn validate_candidate_provenance(
    path: &str,
    request_id: &RequestId,
    candidate: &Candidate,
    actors: &BTreeMap<ActorId, Actor>,
    teams: &BTreeMap<TeamId, Team>,
) -> Result<(), CoreError> {
    if &candidate.request_id != request_id || !teams.contains_key(&candidate.team_id) {
        return Err(invalid_snapshot(
            path,
            "candidate request or team reference is inconsistent",
        ));
    }
    let creator = actors.get(&candidate.created_by.actor_id).ok_or_else(|| {
        invalid_snapshot(format!("{path}.created_by"), "candidate creator is missing")
    })?;
    if !creator.has_capability(IMPLEMENTATION_EXECUTION_CAPABILITY)
        || creator.team_id.as_ref() != Some(&candidate.team_id)
        || candidate.created_by.actor_epoch > creator.epoch
    {
        return Err(invalid_snapshot(
            format!("{path}.created_by"),
            "candidate creator generation, capability, or team is inconsistent",
        ));
    }
    if let Some(created_by_profile) = &candidate.created_by_profile {
        if creator.profile.as_ref().map(|profile| &profile.name) != Some(created_by_profile) {
            return Err(invalid_snapshot(
                format!("{path}.created_by_profile"),
                "candidate creator profile attribution is inconsistent",
            ));
        }
    }
    Ok(())
}

fn validate_request_review_state(
    path: &str,
    policy_revision: PolicyRevision,
    request: &Request,
    actors: &BTreeMap<ActorId, Actor>,
) -> Result<(), CoreError> {
    if let Some(decision) = &request.decision {
        decision
            .payload_digest
            .validate()
            .map_err(|error| error.at(&format!("{path}.decision.payload_digest")))?;
        if decision.policy_revision != policy_revision {
            return Err(invalid_snapshot(
                format!("{path}.decision.policy_revision"),
                "current decision was issued under another policy revision",
            ));
        }
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
    if actors.get(&actor_ref.actor_id).is_some_and(|actor| {
        actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY) && actor.team_id.is_none()
    }) {
        Ok(())
    } else {
        Err(invalid_snapshot(
            path,
            "historical Primary actor is missing or lacks the active-lease topology",
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

// Restoration is an audit boundary: digest, causal, acknowledgement, recipient,
// retirement, and uniqueness checks remain in one visibly ordered pipeline.
#[allow(clippy::too_many_lines)]
fn restore_deliveries(
    workspace_id: &WorkspaceId,
    deliveries: Vec<DeliverySnapshot>,
    actors: &BTreeMap<ActorId, Actor>,
    teams: &BTreeMap<TeamId, Team>,
    requests: &BTreeMap<RequestId, Request>,
    runs: &BTreeMap<RunId, Run>,
) -> Result<BTreeMap<MessageId, DeliveryRecord>, CoreError> {
    let context = HistoricalDeliveryContext {
        workspace_id,
        actors,
        teams,
        requests,
        runs,
    };
    let mut restored = BTreeMap::new();
    for (index, delivery) in deliveries.into_iter().enumerate() {
        delivery
            .payload_digest
            .validate()
            .map_err(|error| error.at(&format!("deliveries[{index}].payload_digest")))?;
        if delivery.message_kind != delivery.causal.kind() {
            return Err(invalid_snapshot(
                format!("deliveries[{index}].causal"),
                "causal message kind contradicts the archived payload kind",
            ));
        }
        validate_causal_content_ref(index, &delivery)?;
        validate_historical_envelope(index, &delivery.envelope, &delivery.causal, context)?;
        validate_historical_required_recipients(
            index,
            &delivery.envelope.target,
            &delivery.required_recipients,
            actors,
        )?;
        let mut acknowledgements = BTreeMap::new();
        for acknowledgement in delivery.acknowledgements {
            let recipient = recipient_for_historical_ack(&delivery.envelope, &acknowledgement);
            validate_historical_ack(
                index,
                workspace_id,
                &delivery.envelope,
                &delivery.required_recipients,
                &recipient,
                &acknowledgement,
                actors,
            )?;
            if acknowledgements
                .insert(recipient, acknowledgement)
                .is_some()
            {
                return Err(invalid_snapshot(
                    format!("deliveries[{index}].acknowledgements"),
                    "duplicate acknowledgement actor",
                ));
            }
        }
        let message_id = delivery.envelope.message_id.clone();
        let fully_acknowledged = !delivery.required_recipients.is_empty()
            && delivery
                .required_recipients
                .iter()
                .all(|recipient| acknowledgements.contains_key(recipient));
        let retirement_eligible = delivery
            .envelope
            .request_id
            .as_ref()
            .is_none_or(|request_id| {
                requests
                    .get(request_id)
                    .is_some_and(|request| request.status.is_terminal())
            });
        if delivery.retired != (fully_acknowledged && retirement_eligible) {
            return Err(invalid_snapshot(
                format!("deliveries[{index}].retired"),
                "retired state contradicts acknowledgements or request lifecycle",
            ));
        }
        if restored
            .insert(
                message_id,
                DeliveryRecord {
                    envelope: delivery.envelope,
                    message_kind: delivery.message_kind,
                    payload_digest: delivery.payload_digest,
                    causal: delivery.causal,
                    required_recipients: delivery.required_recipients,
                    acknowledgements,
                    retired: delivery.retired,
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

fn validate_historical_required_recipients(
    index: usize,
    target: &MessageTarget,
    required: &BTreeSet<DeliveryRecipient>,
    actors: &BTreeMap<ActorId, Actor>,
) -> Result<(), CoreError> {
    let deterministic = match target {
        MessageTarget::Primary => Some(BTreeSet::from([DeliveryRecipient::Primary])),
        MessageTarget::Actor(actor_id) => {
            Some(BTreeSet::from([DeliveryRecipient::Actor(actor_id.clone())]))
        }
        MessageTarget::Team(_) | MessageTarget::Workspace => None,
    };
    if deterministic
        .as_ref()
        .is_some_and(|expected| required != expected)
    {
        return Err(invalid_snapshot(
            format!("deliveries[{index}].required_recipients"),
            "deterministic target has a forged recipient set",
        ));
    }
    if deterministic.is_some() {
        return Ok(());
    }

    // Historical eligibility cannot be reconstructed after membership/status
    // changes. Preserve the frozen (possibly empty) set, but every entry must
    // be a logical actor that still belongs to the archived route.
    for recipient in required {
        let DeliveryRecipient::Actor(actor_id) = recipient else {
            return Err(invalid_snapshot(
                format!("deliveries[{index}].required_recipients"),
                "team or workspace delivery requires logical actor recipients",
            ));
        };
        let actor = actors.get(actor_id).ok_or_else(|| {
            invalid_snapshot(
                format!("deliveries[{index}].required_recipients"),
                "required recipient actor is missing",
            )
        })?;
        if !historical_target_matches(target, actor) {
            return Err(invalid_snapshot(
                format!("deliveries[{index}].required_recipients"),
                "required recipient is outside the archived target",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct HistoricalDeliveryContext<'a> {
    workspace_id: &'a WorkspaceId,
    actors: &'a BTreeMap<ActorId, Actor>,
    teams: &'a BTreeMap<TeamId, Team>,
    requests: &'a BTreeMap<RequestId, Request>,
    runs: &'a BTreeMap<RunId, Run>,
}

fn validate_historical_envelope(
    index: usize,
    envelope: &EnvelopeHeader,
    causal: &CausalMessage,
    context: HistoricalDeliveryContext<'_>,
) -> Result<(), CoreError> {
    envelope.with_message(replay_message(causal)).validate()?;
    let path = format!("deliveries[{index}].envelope");
    if envelope.workspace_id != *context.workspace_id
        || !context.actors.contains_key(&envelope.sender.actor_id)
    {
        return Err(invalid_snapshot(
            path,
            "delivery workspace or sender is inconsistent",
        ));
    }
    if envelope
        .team_id
        .as_ref()
        .is_some_and(|team_id| !context.teams.contains_key(team_id))
        || matches!(&envelope.target, MessageTarget::Team(team_id) if !context.teams.contains_key(team_id))
        || matches!(&envelope.target, MessageTarget::Actor(actor_id) if !context.actors.contains_key(actor_id))
    {
        return Err(invalid_snapshot(
            format!("deliveries[{index}].envelope.target"),
            "delivery references an unknown actor or team",
        ));
    }
    if let Some(request_id) = &envelope.request_id {
        let request = context.requests.get(request_id).ok_or_else(|| {
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
        .is_some_and(|run_id| !context.runs.contains_key(run_id))
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
    envelope: &EnvelopeHeader,
    required_recipients: &BTreeSet<DeliveryRecipient>,
    recipient: &DeliveryRecipient,
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
    if !required_recipients.contains(recipient)
        || acknowledgement.actor.actor_epoch > actor.epoch
        || !historical_target_matches(&envelope.target, actor)
    {
        return Err(invalid_snapshot(
            format!("deliveries[{index}].acknowledgements.actor"),
            "acknowledging actor is outside the delivery target",
        ));
    }
    Ok(())
}

fn recipient_for_historical_ack(
    envelope: &EnvelopeHeader,
    acknowledgement: &Acknowledgement,
) -> DeliveryRecipient {
    if matches!(envelope.target, MessageTarget::Primary) {
        DeliveryRecipient::Primary
    } else {
        DeliveryRecipient::Actor(acknowledgement.actor.actor_id.clone())
    }
}

fn validate_causal_content_ref(index: usize, delivery: &DeliverySnapshot) -> Result<(), CoreError> {
    let valid = match &delivery.causal {
        CausalMessage::ReviewDecision(reference) => {
            reference.message_id == delivery.envelope.message_id
                && reference.payload_digest == delivery.payload_digest
        }
        CausalMessage::HandoffOffer(reference) => {
            reference.message_id == delivery.envelope.message_id
                && reference.payload_digest == delivery.payload_digest
        }
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid_snapshot(
            format!("deliveries[{index}].causal"),
            "causal content reference contradicts its archived delivery",
        ))
    }
}

fn historical_target_matches(target: &MessageTarget, actor: &Actor) -> bool {
    match target {
        MessageTarget::Primary => {
            actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY) && actor.team_id.is_none()
        }
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
        handoff
            .offer
            .payload_digest
            .validate()
            .map_err(|error| error.at(&format!("pending_handoffs[{index}].offer")))?;
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

fn validate_archived_group_quota(
    deliveries: &[DeliverySnapshot],
    audit_events: &[AuditEvent],
) -> Result<(), CoreError> {
    if deliveries.len() > MAX_DELIVERIES {
        return Err(quota("archived cycle deliveries", MAX_DELIVERIES));
    }
    if audit_events.len() > MAX_AUDIT_EVENTS {
        return Err(quota("archived cycle audit events", MAX_AUDIT_EVENTS));
    }
    if deliveries
        .iter()
        .any(|delivery| delivery.acknowledgements.len() > MAX_ACKNOWLEDGEMENTS)
    {
        return Err(quota(
            "archived cycle acknowledgements",
            MAX_ACKNOWLEDGEMENTS,
        ));
    }
    Ok(())
}

fn restore_archived_request_references(
    references: &[ArchivedRequestReference],
    archived_request_id: &RequestId,
    teams: &BTreeMap<TeamId, Team>,
) -> Result<BTreeMap<RequestId, ReplayExternalRequest>, CoreError> {
    if references.len() > MAX_DOMAIN_ENTITIES {
        return Err(quota(
            "archived dependency request references",
            MAX_DOMAIN_ENTITIES,
        ));
    }
    let mut restored = BTreeMap::new();
    for (index, reference) in references.iter().enumerate() {
        if &reference.request_id == archived_request_id
            || reference.creation_audit_sequence == 0
            || !teams.contains_key(&reference.team_id)
        {
            return Err(invalid_snapshot(
                format!("archived_request_references[{index}]"),
                "dependency reference is self-referential, unsequenced, or has an unknown team",
            ));
        }
        if restored
            .insert(
                reference.request_id.clone(),
                ReplayExternalRequest {
                    team_id: reference.team_id.clone(),
                    creation_audit_sequence: reference.creation_audit_sequence,
                },
            )
            .is_some()
        {
            return Err(invalid_snapshot(
                format!("archived_request_references[{index}].request_id"),
                "duplicate dependency request reference",
            ));
        }
    }
    Ok(restored)
}

fn restore_history_checkpoint(
    mut checkpoint: HistoryCheckpoint,
    hot_audit: &[AuditEvent],
) -> Result<HistoryCheckpoint, CoreError> {
    if checkpoint.is_empty() && !hot_audit.is_empty() {
        checkpoint.audit_event_count =
            u64::try_from(hot_audit.len()).map_err(|_| CoreError::EpochExhausted)?;
        checkpoint.audit_head_sha256 = Some(digest_audit_event(
            hot_audit.last().expect("non-empty audit has a final event"),
        )?);
    }
    if checkpoint.archived_request_count != checkpoint.archived_run_count
        || checkpoint.archived_audit_event_count > checkpoint.audit_event_count
        || checkpoint.archived_delivery_count > checkpoint.archived_audit_event_count
        || checkpoint.archived_request_count > checkpoint.archived_delivery_count
    {
        return Err(invalid_snapshot(
            "history_checkpoint",
            "archive counts are internally inconsistent",
        ));
    }
    let hot_count = u64::try_from(hot_audit.len()).map_err(|_| CoreError::EpochExhausted)?;
    if checkpoint.archived_audit_event_count.checked_add(hot_count)
        != Some(checkpoint.audit_event_count)
    {
        return Err(invalid_snapshot(
            "history_checkpoint.audit_event_count",
            "global audit count does not equal archived plus hot events",
        ));
    }
    if checkpoint.audit_event_count == 0 {
        if checkpoint.audit_head_sha256.is_some() {
            return Err(invalid_snapshot(
                "history_checkpoint.audit_head_sha256",
                "empty audit history has a head digest",
            ));
        }
    } else {
        let head = checkpoint.audit_head_sha256.as_ref().ok_or_else(|| {
            invalid_snapshot(
                "history_checkpoint.audit_head_sha256",
                "non-empty audit history lacks a head digest",
            )
        })?;
        head.validate()
            .map_err(|error| error.at("history_checkpoint.audit_head_sha256"))?;
        if let Some(event) = hot_audit.last() {
            if event.sequence == checkpoint.audit_event_count && digest_audit_event(event)? != *head
            {
                return Err(invalid_snapshot(
                    "history_checkpoint.audit_head_sha256",
                    "hot final audit event contradicts the global head digest",
                ));
            }
        }
    }
    Ok(checkpoint)
}

fn validate_audit(
    audit: &[AuditEvent],
    mailbox: &BTreeMap<MessageId, DeliveryRecord>,
    checkpoint: &HistoryCheckpoint,
) -> Result<(), CoreError> {
    validate_audit_links(audit, mailbox, Some(checkpoint.audit_event_count))
}

fn validate_archived_audit(
    audit: &[AuditEvent],
    mailbox: &BTreeMap<MessageId, DeliveryRecord>,
) -> Result<(), CoreError> {
    validate_audit_links(audit, mailbox, None)
}

fn validate_audit_links(
    audit: &[AuditEvent],
    mailbox: &BTreeMap<MessageId, DeliveryRecord>,
    maximum_sequence: Option<u64>,
) -> Result<(), CoreError> {
    let mut accepted = BTreeSet::new();
    let mut acknowledged = BTreeSet::new();
    let mut previous_sequence = 0;
    for (index, event) in audit.iter().enumerate() {
        if event.sequence == 0
            || event.sequence <= previous_sequence
            || maximum_sequence.is_some_and(|maximum| event.sequence > maximum)
        {
            return Err(invalid_snapshot(
                format!("audit_events[{index}].sequence"),
                "audit sequence is zero, duplicated, unordered, or beyond the global count",
            ));
        }
        previous_sequence = event.sequence;
        match &event.kind {
            AuditEventKind::MessageAccepted {
                message_id,
                message_kind,
                payload_digest,
            } => {
                let delivery = mailbox.get(message_id).ok_or_else(|| {
                    invalid_snapshot(
                        format!("audit_events[{index}].message_id"),
                        "accepted audit message is missing",
                    )
                })?;
                if delivery.message_kind != *message_kind
                    || payload_digest.as_ref() != Some(&delivery.payload_digest)
                    || event.occurred_at != delivery.envelope.sent_at
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
                let recipient = if matches!(delivery.envelope.target, MessageTarget::Primary) {
                    DeliveryRecipient::Primary
                } else {
                    DeliveryRecipient::Actor(actor_id.clone())
                };
                let acknowledgement = delivery.acknowledgements.get(&recipient);
                if !accepted.contains(message_id)
                    || acknowledgement.is_none_or(|acknowledgement| {
                        acknowledgement.actor.actor_id != *actor_id
                            || event.occurred_at != acknowledgement.acknowledged_at
                    })
                    || !acknowledged.insert((message_id.clone(), recipient))
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
                .any(|recipient| !acknowledged.contains(&(message_id.clone(), recipient.clone())))
        {
            return Err(invalid_snapshot(
                "audit_events",
                "delivery or acknowledgement has no matching audit event",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct ReplayConsultation {
    requester: ActorRef,
    requester_is_primary: bool,
    target_team_id: TeamId,
}

#[derive(Clone, Debug)]
struct ReplayExternalRequest {
    team_id: TeamId,
    creation_audit_sequence: u64,
}

#[derive(Default)]
struct CausalReplay {
    requests: BTreeMap<RequestId, Request>,
    runs: BTreeMap<RunId, Run>,
    handoffs: BTreeMap<HandoffId, PendingHandoff>,
    consultations: BTreeMap<MessageId, ReplayConsultation>,
    decision_ids: BTreeSet<agsv_protocol::DecisionId>,
    primary_actors: BTreeMap<PrimaryEpoch, ActorId>,
    actor_epochs: BTreeMap<ActorId, ActorEpoch>,
    team_epochs: BTreeMap<TeamId, TeamEpoch>,
    last_primary_epoch: Option<PrimaryEpoch>,
    snapshot_active_primary: Option<ActorRef>,
    external_requests: BTreeMap<RequestId, ReplayExternalRequest>,
    current_audit_sequence: u64,
}

#[derive(Clone, Copy)]
struct CausalHistory<'a> {
    policy_revision: PolicyRevision,
    primary_epoch: PrimaryEpoch,
    active_primary: Option<&'a ActorRef>,
    audit: &'a [AuditEvent],
    mailbox: &'a BTreeMap<MessageId, DeliveryRecord>,
    actors: &'a BTreeMap<ActorId, Actor>,
    teams: &'a BTreeMap<TeamId, Team>,
    requests: &'a BTreeMap<RequestId, Request>,
    runs: &'a BTreeMap<RunId, Run>,
    handoffs: &'a BTreeMap<HandoffId, PendingHandoff>,
    external_requests: Option<&'a BTreeMap<RequestId, ReplayExternalRequest>>,
    require_completed_consultations: bool,
}

fn validate_causal_history(history: CausalHistory<'_>) -> Result<(), CoreError> {
    let mut replay = CausalReplay {
        snapshot_active_primary: history.active_primary.cloned(),
        external_requests: history.external_requests.cloned().unwrap_or_default(),
        ..CausalReplay::default()
    };
    for event in history.audit {
        if let AuditEventKind::MessageAccepted { message_id, .. } = &event.kind {
            replay.current_audit_sequence = event.sequence;
            let delivery = history
                .mailbox
                .get(message_id)
                .ok_or_else(|| invalid_snapshot("audit_events", "audit delivery is missing"))?;
            let envelope = delivery
                .envelope
                .with_message(replay_message(&delivery.causal));
            replay.apply(
                &envelope,
                &delivery.payload_digest,
                history.policy_revision,
                history.primary_epoch,
                history.actors,
                history.teams,
            )?;
        }
    }
    replay.finish(
        history.requests,
        history.runs,
        history.handoffs,
        history.require_completed_consultations,
    )
}

impl CausalReplay {
    // Compact replay deliberately mirrors every Message variant in one match so
    // omissions and variant-specific fence checks are reviewable together.
    #[allow(clippy::too_many_lines)]
    fn apply(
        &mut self,
        envelope: &Envelope,
        payload_digest: &PayloadDigest,
        policy_revision: PolicyRevision,
        primary_epoch: PrimaryEpoch,
        actors: &BTreeMap<ActorId, Actor>,
        teams: &BTreeMap<TeamId, Team>,
    ) -> Result<(), CoreError> {
        let actor =
            self.authorize_history(envelope, policy_revision, primary_epoch, actors, teams)?;
        if envelope.request_id.is_some()
            && !matches!(envelope.message, Message::ImplementationRequest(_))
        {
            self.request_context(envelope)?;
        }
        match &envelope.message {
            Message::ImplementationRequest(specification) => self.create_request(
                envelope,
                actor,
                RequestSpecificationRef {
                    message_id: envelope.message_id.clone(),
                    payload_digest: payload_digest.clone(),
                    base_sha: specification.base_sha.clone(),
                },
                actors,
            ),
            Message::Progress(_) => {
                require_history_capability(actor, IMPLEMENTATION_EXECUTION_CAPABILITY, "progress")?;
                require_history_target(&envelope.target, &MessageTarget::Primary)?;
                self.ensure_assignment(envelope, actor)?;
                self.transition(envelope, RequestEvent::Start, RunEvent::Resume)
            }
            Message::Blocker(_) => {
                require_history_capability(actor, IMPLEMENTATION_EXECUTION_CAPABILITY, "blocker")?;
                require_history_target(&envelope.target, &MessageTarget::Primary)?;
                self.ensure_assignment(envelope, actor)?;
                self.transition(envelope, RequestEvent::Block, RunEvent::Block)
            }
            Message::CandidateReady(ready) => {
                require_history_capability(
                    actor,
                    IMPLEMENTATION_EXECUTION_CAPABILITY,
                    "candidate",
                )?;
                require_history_target(&envelope.target, &MessageTarget::Primary)?;
                self.ensure_assignment(envelope, actor)?;
                self.submit_candidate(envelope, actor, &ready.candidate)
            }
            Message::ReviewDecision(decision) => {
                require_history_primary(actor, "review")?;
                self.review(
                    envelope,
                    actor,
                    ReviewDecisionRef {
                        message_id: envelope.message_id.clone(),
                        payload_digest: payload_digest.clone(),
                        decision_id: decision.decision_id.clone(),
                        candidate: decision.candidate.clone(),
                        verdict: decision.verdict,
                        reviewer: decision.reviewer.clone(),
                        policy_revision: decision.policy_revision,
                    },
                )
            }
            Message::FixRequest(fix) => {
                require_history_primary(actor, "fix request")?;
                self.validate_fix(envelope, fix)
            }
            Message::QaResult(result) => {
                require_history_capability(actor, IMPLEMENTATION_EXECUTION_CAPABILITY, "QA")?;
                require_history_target(&envelope.target, &MessageTarget::Primary)?;
                self.ensure_assignment(envelope, actor)?;
                let request = self.request_context(envelope)?;
                ensure_replay_candidate(request, &result.candidate)
            }
            Message::IntegrationAuthorization(authorization) => {
                require_history_primary(actor, "authorization")?;
                self.authorize_integration(envelope, actor, authorization.clone())
            }
            Message::Cancellation(_) => {
                require_history_primary(actor, "cancellation")?;
                self.require_assignee_target(envelope)?;
                let request_id = required_request_id(envelope)?;
                self.transition(envelope, RequestEvent::Cancel, RunEvent::Cancel)?;
                self.handoffs
                    .retain(|_, handoff| handoff.offer.request_id != request_id);
                Ok(())
            }
            Message::RunControl(control) => {
                require_history_primary(actor, "run control")?;
                self.control_run(envelope, control.action)
            }
            Message::ConsultationRequest(request) => self.consult(envelope, actor, request, teams),
            Message::ConsultationResponse(response) => {
                self.respond_to_consult(envelope, actor, response)
            }
            Message::DependencyNotice(notice) => self.dependency(envelope, actor, notice, teams),
            Message::ConflictNotice(notice) => {
                require_history_capability(actor, IMPLEMENTATION_EXECUTION_CAPABILITY, "conflict")?;
                let sender_team_id = actor.team_id.as_ref().ok_or_else(|| {
                    invalid_snapshot(
                        "deliveries.envelope.sender",
                        "accepted conflict sender has no team",
                    )
                })?;
                if sender_team_id == &notice.other_team_id {
                    return Err(invalid_snapshot("deliveries", "self-conflict was accepted"));
                }
                require_history_target(
                    &envelope.target,
                    &MessageTarget::Team(notice.other_team_id.clone()),
                )?;
                require_known_history_team(teams, &notice.other_team_id)
            }
            Message::HandoffOffer(offer) => self.offer_handoff(
                envelope,
                actor,
                &HandoffOfferRef {
                    message_id: envelope.message_id.clone(),
                    payload_digest: payload_digest.clone(),
                    handoff_id: offer.handoff_id.clone(),
                    request_id: offer.request_id.clone(),
                    from_team_id: offer.from_team_id.clone(),
                    to_team_id: offer.to_team_id.clone(),
                    candidate: offer.candidate.clone(),
                },
                teams,
            ),
            Message::HandoffAcceptance(acceptance) => {
                self.accept_handoff(envelope, actor, acceptance)
            }
            Message::IntegrationComplete(complete) => {
                self.complete_integration(envelope, actor, complete)
            }
        }
    }

    fn authorize_history<'a>(
        &mut self,
        envelope: &Envelope,
        policy_revision: PolicyRevision,
        primary_epoch: PrimaryEpoch,
        actors: &'a BTreeMap<ActorId, Actor>,
        teams: &BTreeMap<TeamId, Team>,
    ) -> Result<&'a Actor, CoreError> {
        if envelope.policy_revision != policy_revision || envelope.primary_epoch > primary_epoch {
            return Err(invalid_snapshot(
                "deliveries.envelope",
                "accepted message has a stale policy or impossible Primary fence",
            ));
        }
        if self
            .last_primary_epoch
            .is_some_and(|previous| envelope.primary_epoch < previous)
        {
            return Err(invalid_snapshot(
                "audit_events",
                "accepted Primary epochs regress in audit order",
            ));
        }
        self.last_primary_epoch = Some(envelope.primary_epoch);
        let actor = actors.get(&envelope.sender.actor_id).ok_or_else(|| {
            invalid_snapshot("deliveries.envelope.sender", "historical sender is missing")
        })?;
        if envelope.sender.actor_epoch > actor.epoch
            || self
                .actor_epochs
                .get(&actor.actor_id)
                .is_some_and(|previous| envelope.sender.actor_epoch < *previous)
        {
            return Err(invalid_snapshot(
                "deliveries.envelope.sender.actor_epoch",
                "accepted actor epoch is impossible or regresses",
            ));
        }
        self.actor_epochs
            .insert(actor.actor_id.clone(), envelope.sender.actor_epoch);
        if actor.team_id.is_some() && actor.team_id != envelope.team_id {
            return Err(invalid_snapshot(
                "deliveries.envelope.team_id",
                "team actor used another team context",
            ));
        }
        self.validate_history_team_fence(envelope, teams)?;
        if actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY) && actor.team_id.is_none() {
            if envelope.primary_epoch == primary_epoch
                && self.snapshot_active_primary.as_ref() != Some(&envelope.sender)
            {
                return Err(invalid_snapshot(
                    "deliveries.envelope.sender",
                    "current-epoch Primary sender is not the active Primary",
                ));
            }
            match self.primary_actors.get(&envelope.primary_epoch) {
                Some(existing) if existing != &actor.actor_id => {
                    return Err(invalid_snapshot(
                        "deliveries.envelope.primary_epoch",
                        "multiple Primary actors used the same lease epoch",
                    ));
                }
                None => {
                    self.primary_actors
                        .insert(envelope.primary_epoch, actor.actor_id.clone());
                }
                Some(_) => {}
            }
        }
        Ok(actor)
    }

    fn validate_history_team_fence(
        &mut self,
        envelope: &Envelope,
        teams: &BTreeMap<TeamId, Team>,
    ) -> Result<(), CoreError> {
        if let Some(team_id) = &envelope.team_id {
            let team = teams.get(team_id).ok_or_else(|| {
                invalid_snapshot("deliveries.envelope.team_id", "historical team is missing")
            })?;
            let epoch = envelope.team_epoch.ok_or_else(|| {
                invalid_snapshot("deliveries.envelope.team_epoch", "team fence is missing")
            })?;
            if epoch > team.epoch
                || self
                    .team_epochs
                    .get(team_id)
                    .is_some_and(|previous| epoch < *previous)
            {
                return Err(invalid_snapshot(
                    "deliveries.envelope.team_epoch",
                    "accepted team epoch is impossible or regresses",
                ));
            }
            self.team_epochs.insert(team_id.clone(), epoch);
        }
        Ok(())
    }

    fn create_request(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        specification: RequestSpecificationRef,
        actors: &BTreeMap<ActorId, Actor>,
    ) -> Result<(), CoreError> {
        require_history_primary(actor, "implementation request")?;
        let (request_id, run_id) = context_ids(envelope)?;
        let team_id = envelope.team_id.clone().ok_or(CoreError::WrongTeam)?;
        let MessageTarget::Actor(target_id) = &envelope.target else {
            return Err(invalid_snapshot(
                "deliveries.envelope.target",
                "implementation request was not targeted to an actor",
            ));
        };
        let target = actors.get(target_id).ok_or_else(|| {
            invalid_snapshot("deliveries.envelope.target", "assigned actor is missing")
        })?;
        if !target.has_capability(IMPLEMENTATION_EXECUTION_CAPABILITY)
            || target.team_id.as_ref() != Some(&team_id)
        {
            return Err(invalid_snapshot(
                "deliveries.envelope.target",
                "assigned actor capability or team is inconsistent",
            ));
        }
        if envelope.assignment_epoch.is_some()
            || self.requests.contains_key(&request_id)
            || self.runs.contains_key(&run_id)
        {
            return Err(invalid_snapshot(
                "deliveries",
                "implementation request reused ids or supplied an assignment fence",
            ));
        }
        let assignment = Assignment {
            actor: target.actor_ref(),
            epoch: AssignmentEpoch::INITIAL,
        };
        self.requests.insert(
            request_id.clone(),
            Request {
                request_id: request_id.clone(),
                workspace_id: envelope.workspace_id.clone(),
                team_id: team_id.clone(),
                run_id: run_id.clone(),
                specification,
                status: RequestStatus::Assigned,
                assignment: Some(assignment.clone()),
                candidate: None,
                decision: None,
                integration_authorization: None,
                rejection_count: 0,
                fix_cycle_depth: 0,
                candidate_history: Vec::new(),
            },
        );
        self.runs.insert(
            run_id.clone(),
            Run {
                run_id,
                workspace_id: envelope.workspace_id.clone(),
                team_id,
                request_id,
                status: RunStatus::Active,
                assignment: Some(assignment),
            },
        );
        Ok(())
    }

    fn request_context(&self, envelope: &Envelope) -> Result<&Request, CoreError> {
        let (request_id, run_id) = context_ids(envelope)?;
        let request = self.requests.get(&request_id).ok_or_else(|| {
            invalid_snapshot(
                "deliveries.envelope.request_id",
                "request was not created yet",
            )
        })?;
        if request.run_id != run_id
            || self
                .runs
                .get(&run_id)
                .is_none_or(|run| run.request_id != request_id)
        {
            return Err(invalid_snapshot(
                "deliveries.envelope.run_id",
                "request and run provenance are inconsistent",
            ));
        }
        let team_matches = match &envelope.message {
            Message::HandoffAcceptance(acceptance) => {
                request.team_id == acceptance.from_team_id
                    && envelope.team_id.as_ref() == Some(&acceptance.to_team_id)
            }
            _ => envelope.team_id.as_ref() == Some(&request.team_id),
        };
        if !team_matches {
            return Err(invalid_snapshot(
                "deliveries.envelope.team_id",
                "request-scoped message used the wrong team context",
            ));
        }
        Ok(request)
    }

    fn ensure_assignment(&mut self, envelope: &Envelope, actor: &Actor) -> Result<(), CoreError> {
        let request_id = required_request_id(envelope)?;
        let supplied = envelope.assignment_epoch.ok_or_else(|| {
            invalid_snapshot(
                "deliveries.envelope.assignment_epoch",
                "executor message lacks assignment fence",
            )
        })?;
        let request = self.request_context(envelope)?;
        let assignment = request
            .assignment
            .as_ref()
            .ok_or(CoreError::NotAssignedActor)?;
        if supplied < assignment.epoch
            || actor.team_id.as_ref() != Some(&request.team_id)
            || (supplied == assignment.epoch && assignment.actor.actor_id != actor.actor_id)
        {
            return Err(invalid_snapshot(
                "deliveries.envelope.assignment_epoch",
                "accepted executor assignment is stale or belongs to another actor",
            ));
        }
        if supplied > assignment.epoch || assignment.actor != envelope.sender {
            let next = Assignment {
                actor: envelope.sender.clone(),
                epoch: supplied,
            };
            self.requests
                .get_mut(&request_id)
                .ok_or_else(|| CoreError::UnknownRequest(request_id.clone()))?
                .assignment = Some(next.clone());
            let run_id = self.requests[&request_id].run_id.clone();
            self.runs
                .get_mut(&run_id)
                .ok_or(CoreError::UnknownRun(run_id))?
                .assignment = Some(next);
        }
        Ok(())
    }

    fn transition(
        &mut self,
        envelope: &Envelope,
        request_event: RequestEvent,
        run_event: RunEvent,
    ) -> Result<(), CoreError> {
        let request = self.request_context(envelope)?;
        let request_id = request.request_id.clone();
        let run_id = request.run_id.clone();
        let request_status = transition_request(request.status, request_event).map_err(|_| {
            invalid_snapshot("audit_events", "request transition provenance is illegal")
        })?;
        let run = self
            .runs
            .get(&run_id)
            .ok_or_else(|| CoreError::UnknownRun(run_id.clone()))?;
        let run_status = transition_run(run.status, run_event).map_err(|_| {
            invalid_snapshot("audit_events", "run transition provenance is illegal")
        })?;
        self.requests
            .get_mut(&request_id)
            .ok_or_else(|| CoreError::UnknownRequest(request_id.clone()))?
            .status = request_status;
        self.runs
            .get_mut(&run_id)
            .ok_or(CoreError::UnknownRun(run_id))?
            .status = run_status;
        Ok(())
    }

    fn submit_candidate(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        candidate: &Candidate,
    ) -> Result<(), CoreError> {
        let request = self.request_context(envelope)?;
        if candidate.request_id != request.request_id
            || candidate.team_id != request.team_id
            || candidate.created_by != envelope.sender
            || actor.actor_id != envelope.sender.actor_id
            || candidate
                .created_by_profile
                .as_ref()
                .is_some_and(|profile| {
                    actor.profile.as_ref().map(|snapshot| &snapshot.name) != Some(profile)
                })
        {
            return Err(invalid_snapshot(
                "deliveries.message.candidate",
                "candidate provenance is inconsistent",
            ));
        }
        let rejected_rework = is_rejected_candidate_rework(request);
        let is_new_candidate = request.candidate.as_ref() != Some(candidate);
        if let Some(previous) = &request.candidate {
            if rejected_rework && previous.sha == candidate.sha {
                return Err(invalid_snapshot(
                    "deliveries.message.candidate.sha",
                    "rejected candidate was not changed",
                ));
            }
            if !rejected_rework && previous != candidate {
                return Err(invalid_snapshot(
                    "deliveries.message.candidate",
                    "candidate changed outside a rejected review cycle",
                ));
            }
        }
        if is_new_candidate && request.candidate_history.len() >= MAX_DOMAIN_ENTITIES {
            return Err(invalid_snapshot(
                "deliveries.message.candidate",
                "candidate history exceeds its quota",
            ));
        }
        let next_fix_cycle_depth = if rejected_rework && is_new_candidate {
            Some(
                request
                    .fix_cycle_depth
                    .checked_add(1)
                    .ok_or(CoreError::EpochExhausted)?,
            )
        } else {
            None
        };
        self.transition(
            envelope,
            RequestEvent::SubmitCandidate,
            RunEvent::SubmitCandidate,
        )?;
        let request_id = candidate.request_id.clone();
        let request = self
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| CoreError::UnknownRequest(request_id.clone()))?;
        if is_new_candidate {
            request.candidate_history.push(candidate.clone());
        }
        if let Some(depth) = next_fix_cycle_depth {
            request.fix_cycle_depth = depth;
        }
        request.candidate = Some(candidate.clone());
        request.decision = None;
        request.integration_authorization = None;
        self.handoffs.retain(|_, handoff| {
            handoff.offer.request_id != request_id
                || handoff
                    .offer
                    .candidate
                    .as_ref()
                    .is_none_or(|offered| offered == candidate)
        });
        Ok(())
    }

    fn review(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        decision: ReviewDecisionRef,
    ) -> Result<(), CoreError> {
        self.require_assignee_target(envelope)?;
        if decision.reviewer != envelope.sender
            || actor.actor_id != envelope.sender.actor_id
            || decision.policy_revision != envelope.policy_revision
            || !self.decision_ids.insert(decision.decision_id.clone())
        {
            return Err(invalid_snapshot(
                "deliveries.message.review_decision",
                "review identity, policy, or decision id is inconsistent",
            ));
        }
        let request = self.request_context(envelope)?;
        ensure_replay_candidate(request, &decision.candidate)?;
        let (request_event, run_event) = match decision.verdict {
            ReviewVerdict::Accepted => (RequestEvent::AcceptCandidate, RunEvent::AcceptCandidate),
            ReviewVerdict::Rejected => (RequestEvent::RejectCandidate, RunEvent::RejectCandidate),
        };
        let next_rejection_count = if decision.verdict == ReviewVerdict::Rejected {
            Some(
                request
                    .rejection_count
                    .checked_add(1)
                    .ok_or(CoreError::EpochExhausted)?,
            )
        } else {
            None
        };
        self.transition(envelope, request_event, run_event)?;
        let request_id = required_request_id(envelope)?;
        let verdict = decision.verdict;
        let request = self
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| CoreError::UnknownRequest(request_id.clone()))?;
        if let Some(count) = next_rejection_count {
            request.rejection_count = count;
        }
        request.decision = Some(decision);
        request.integration_authorization = None;
        if verdict == ReviewVerdict::Accepted {
            self.handoffs
                .retain(|_, handoff| handoff.offer.request_id != request_id);
        }
        Ok(())
    }

    fn validate_fix(
        &self,
        envelope: &Envelope,
        fix: &agsv_protocol::FixRequest,
    ) -> Result<(), CoreError> {
        self.require_assignee_target(envelope)?;
        let request = self.request_context(envelope)?;
        ensure_replay_candidate(request, &fix.candidate)?;
        if request.decision.as_ref().is_none_or(|decision| {
            decision.decision_id != fix.decision_id || decision.verdict != ReviewVerdict::Rejected
        }) || request.status != RequestStatus::ChangesRequested
        {
            return Err(invalid_snapshot(
                "deliveries.message.fix_request",
                "fix request lacks its rejected decision",
            ));
        }
        Ok(())
    }

    fn control_run(
        &mut self,
        envelope: &Envelope,
        action: RunControlAction,
    ) -> Result<(), CoreError> {
        self.require_assignee_target(envelope)?;
        if envelope.assignment_epoch.is_some() {
            return Err(invalid_snapshot(
                "deliveries.envelope.assignment_epoch",
                "Primary run control carried an executor assignment fence",
            ));
        }
        let request = self.request_context(envelope)?;
        let request_id = request.request_id.clone();
        let run_id = request.run_id.clone();
        let request_status = match action {
            RunControlAction::Pause => request.status,
            RunControlAction::Resume => transition_request(request.status, RequestEvent::Start)
                .map_err(|_| {
                    invalid_snapshot("audit_events", "run resume request provenance is illegal")
                })?,
        };
        let run = self
            .runs
            .get(&run_id)
            .ok_or_else(|| CoreError::UnknownRun(run_id.clone()))?;
        let event = match action {
            RunControlAction::Pause => RunEvent::Pause,
            RunControlAction::Resume => RunEvent::Resume,
        };
        let run_status = transition_run(run.status, event)
            .map_err(|_| invalid_snapshot("audit_events", "run control provenance is illegal"))?;
        self.requests
            .get_mut(&request_id)
            .ok_or_else(|| CoreError::UnknownRequest(request_id.clone()))?
            .status = request_status;
        self.runs
            .get_mut(&run_id)
            .ok_or(CoreError::UnknownRun(run_id))?
            .status = run_status;
        Ok(())
    }

    fn authorize_integration(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        authorization: IntegrationAuthorization,
    ) -> Result<(), CoreError> {
        self.require_assignee_target(envelope)?;
        if authorization.authorized_by != envelope.sender
            || actor.actor_id != envelope.sender.actor_id
        {
            return Err(invalid_snapshot(
                "deliveries.message.integration_authorization",
                "authorization identity is inconsistent",
            ));
        }
        let request = self.request_context(envelope)?;
        ensure_replay_candidate(request, &authorization.candidate)?;
        if request.decision.as_ref().is_none_or(|decision| {
            decision.decision_id != authorization.decision_id
                || decision.verdict != ReviewVerdict::Accepted
        }) {
            return Err(invalid_snapshot(
                "deliveries.message.integration_authorization",
                "authorization lacks its accepted decision",
            ));
        }
        self.transition(
            envelope,
            RequestEvent::AuthorizeIntegration,
            RunEvent::AuthorizeIntegration,
        )?;
        let request_id = authorization.candidate.request_id.clone();
        self.requests
            .get_mut(&request_id)
            .ok_or(CoreError::UnknownRequest(request_id))?
            .integration_authorization = Some(authorization);
        Ok(())
    }

    fn complete_integration(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        complete: &agsv_protocol::IntegrationComplete,
    ) -> Result<(), CoreError> {
        require_history_primary(actor, "integration complete")?;
        self.require_assignee_target(envelope)?;
        let request = self.request_context(envelope)?;
        ensure_replay_candidate(request, &complete.candidate)?;
        if request
            .integration_authorization
            .as_ref()
            .is_none_or(|authorization| authorization.decision_id != complete.decision_id)
        {
            return Err(invalid_snapshot(
                "deliveries",
                "integration completion lacks matching authorization",
            ));
        }
        self.transition(envelope, RequestEvent::Complete, RunEvent::Complete)
    }

    fn require_assignee_target(&self, envelope: &Envelope) -> Result<(), CoreError> {
        let request = self.request_context(envelope)?;
        let assignment = request
            .assignment
            .as_ref()
            .ok_or(CoreError::NotAssignedActor)?;
        let valid = matches!(
            &envelope.target,
            MessageTarget::Actor(actor_id) if actor_id == &assignment.actor.actor_id
        ) || envelope.target == MessageTarget::Team(request.team_id.clone());
        if valid {
            Ok(())
        } else {
            Err(invalid_snapshot(
                "deliveries.envelope.target",
                "Primary request message was not routed to its assignee",
            ))
        }
    }

    fn consult(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        request: &agsv_protocol::ConsultationRequest,
        teams: &BTreeMap<TeamId, Team>,
    ) -> Result<(), CoreError> {
        require_history_consultation_requester(actor)?;
        if request.consultation_id != envelope.message_id
            || actor.team_id.as_ref() == Some(&request.target_team_id)
            || self.consultations.contains_key(&request.consultation_id)
        {
            return Err(invalid_snapshot(
                "deliveries.message.consultation_request",
                "consultation id or requester/target relation is inconsistent",
            ));
        }
        require_history_target(
            &envelope.target,
            &MessageTarget::Team(request.target_team_id.clone()),
        )?;
        require_known_history_team(teams, &request.target_team_id)?;
        self.consultations.insert(
            request.consultation_id.clone(),
            ReplayConsultation {
                requester: envelope.sender.clone(),
                requester_is_primary: actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
                    && actor.team_id.is_none(),
                target_team_id: request.target_team_id.clone(),
            },
        );
        Ok(())
    }

    fn respond_to_consult(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        response: &agsv_protocol::ConsultationResponse,
    ) -> Result<(), CoreError> {
        require_history_capability(
            actor,
            IMPLEMENTATION_EXECUTION_CAPABILITY,
            "consultation response",
        )?;
        let request = self
            .consultations
            .get(&response.consultation_id)
            .ok_or_else(|| {
                invalid_snapshot(
                    "deliveries.message.consultation_response",
                    "consultation response has no accepted request",
                )
            })?;
        let expected_target = if request.requester_is_primary {
            MessageTarget::Primary
        } else {
            MessageTarget::Actor(request.requester.actor_id.clone())
        };
        if response.responding_team_id != request.target_team_id
            || actor.team_id.as_ref() != Some(&response.responding_team_id)
        {
            return Err(invalid_snapshot(
                "deliveries.message.consultation_response",
                "consultation responder is not the requested team",
            ));
        }
        require_history_target(&envelope.target, &expected_target)?;
        self.consultations.remove(&response.consultation_id);
        Ok(())
    }

    fn dependency(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        notice: &agsv_protocol::DependencyNotice,
        teams: &BTreeMap<TeamId, Team>,
    ) -> Result<(), CoreError> {
        require_history_capability(actor, IMPLEMENTATION_EXECUTION_CAPABILITY, "dependency")?;
        self.ensure_assignment(envelope, actor)?;
        let blocked = self.request_context(envelope)?;
        let dependency_team =
            if let Some(dependency) = self.requests.get(&notice.depends_on_request_id) {
                &dependency.team_id
            } else {
                let dependency = self
                    .external_requests
                    .get(&notice.depends_on_request_id)
                    .filter(|dependency| {
                        dependency.creation_audit_sequence < self.current_audit_sequence
                    })
                    .ok_or_else(|| {
                        invalid_snapshot(
                            "deliveries.message.dependency_notice",
                            "dependency request was not created before this notice",
                        )
                    })?;
                &dependency.team_id
            };
        if blocked.request_id != notice.blocked_request_id
            || *dependency_team != notice.provider_team_id
        {
            return Err(invalid_snapshot(
                "deliveries.message.dependency_notice",
                "dependency requests or provider team are inconsistent",
            ));
        }
        require_history_target(
            &envelope.target,
            &MessageTarget::Team(notice.provider_team_id.clone()),
        )?;
        require_known_history_team(teams, &notice.provider_team_id)
    }

    fn offer_handoff(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        offer: &HandoffOfferRef,
        teams: &BTreeMap<TeamId, Team>,
    ) -> Result<(), CoreError> {
        require_history_capability(actor, IMPLEMENTATION_EXECUTION_CAPABILITY, "handoff offer")?;
        self.ensure_assignment(envelope, actor)?;
        let request = self.request_context(envelope)?;
        if offer.request_id != request.request_id
            || offer.from_team_id != request.team_id
            || actor.team_id.as_ref() != Some(&offer.from_team_id)
            || self.handoffs.contains_key(&offer.handoff_id)
            || self
                .handoffs
                .values()
                .any(|pending| pending.offer.request_id == offer.request_id)
        {
            return Err(invalid_snapshot(
                "deliveries.message.handoff_offer",
                "handoff offer identity or ownership is inconsistent",
            ));
        }
        require_history_target(
            &envelope.target,
            &MessageTarget::Team(offer.to_team_id.clone()),
        )?;
        require_known_history_team(teams, &offer.to_team_id)?;
        if let Some(candidate) = &offer.candidate {
            ensure_replay_candidate(request, candidate)?;
        }
        let assignment = request
            .assignment
            .as_ref()
            .ok_or(CoreError::NotAssignedActor)?;
        self.handoffs.insert(
            offer.handoff_id.clone(),
            PendingHandoff {
                offer: offer.clone(),
                offered_by: envelope.sender.clone(),
                assignment_epoch: assignment.epoch,
            },
        );
        Ok(())
    }

    fn accept_handoff(
        &mut self,
        envelope: &Envelope,
        actor: &Actor,
        acceptance: &HandoffAcceptance,
    ) -> Result<(), CoreError> {
        require_history_capability(
            actor,
            IMPLEMENTATION_EXECUTION_CAPABILITY,
            "handoff acceptance",
        )?;
        let pending = self
            .handoffs
            .get(&acceptance.handoff_id)
            .ok_or_else(|| invalid_snapshot("deliveries", "handoff acceptance has no offer"))?
            .clone();
        let request = self.request_context(envelope)?;
        let assignment = request
            .assignment
            .as_ref()
            .ok_or(CoreError::NotAssignedActor)?;
        if acceptance.accepted_by != envelope.sender
            || actor.team_id.as_ref() != Some(&acceptance.to_team_id)
            || pending.offer.request_id != acceptance.request_id
            || pending.offer.from_team_id != acceptance.from_team_id
            || pending.offer.to_team_id != acceptance.to_team_id
            || assignment.actor != pending.offered_by
            || assignment.epoch != pending.assignment_epoch
            || envelope.assignment_epoch != Some(assignment.epoch)
        {
            return Err(invalid_snapshot(
                "deliveries.message.handoff_acceptance",
                "handoff acceptance does not match its offer or assignment",
            ));
        }
        require_history_target(
            &envelope.target,
            &MessageTarget::Team(acceptance.from_team_id.clone()),
        )?;
        let next_epoch = assignment
            .epoch
            .checked_next()
            .ok_or(CoreError::EpochExhausted)?;
        let next_assignment = Assignment {
            actor: envelope.sender.clone(),
            epoch: next_epoch,
        };
        let request_id = request.request_id.clone();
        let run_id = request.run_id.clone();
        let request = self
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| CoreError::UnknownRequest(request_id.clone()))?;
        request.team_id = acceptance.to_team_id.clone();
        request.assignment = Some(next_assignment.clone());
        let run = self
            .runs
            .get_mut(&run_id)
            .ok_or(CoreError::UnknownRun(run_id))?;
        run.team_id = acceptance.to_team_id.clone();
        run.assignment = Some(next_assignment);
        self.handoffs.remove(&acceptance.handoff_id);
        Ok(())
    }

    fn finish(
        mut self,
        requests: &BTreeMap<RequestId, Request>,
        runs: &BTreeMap<RunId, Run>,
        handoffs: &BTreeMap<HandoffId, PendingHandoff>,
        require_completed_consultations: bool,
    ) -> Result<(), CoreError> {
        if self.requests.len() != requests.len() || self.runs.len() != runs.len() {
            return Err(invalid_snapshot(
                "requests",
                "persisted requests or runs lack complete accepted-message provenance",
            ));
        }
        for (request_id, current) in requests {
            let replayed = self
                .requests
                .get_mut(request_id)
                .ok_or_else(|| invalid_snapshot("requests", "request lacks its creation event"))?;
            replayed.assignment.clone_from(&current.assignment);
            if request_metrics_are_legacy_default(current) {
                replayed.rejection_count = 0;
                replayed.fix_cycle_depth = 0;
                replayed.candidate_history.clear();
            }
            let replayed_run = self
                .runs
                .get_mut(&current.run_id)
                .ok_or_else(|| invalid_snapshot("runs", "run lacks its creation event"))?;
            replayed_run.assignment.clone_from(&current.assignment);
            let current_run = runs
                .get(&current.run_id)
                .ok_or_else(|| invalid_snapshot("runs", "request run is missing"))?;
            if replayed != current || replayed_run != current_run {
                return Err(invalid_snapshot(
                    "requests",
                    "persisted request state lacks complete transition provenance",
                ));
            }
        }
        self.handoffs.retain(|_, pending| {
            requests
                .get(&pending.offer.request_id)
                .and_then(|request| request.assignment.as_ref())
                .is_some_and(|assignment| {
                    assignment.actor == pending.offered_by
                        && assignment.epoch == pending.assignment_epoch
                })
        });
        if &self.handoffs != handoffs {
            return Err(invalid_snapshot(
                "pending_handoffs",
                "persisted handoff state lacks complete message provenance",
            ));
        }
        if require_completed_consultations && !self.consultations.is_empty() {
            return Err(invalid_snapshot(
                "deliveries.message.consultation_request",
                "unanswered consultation must remain in hot history",
            ));
        }
        Ok(())
    }
}

fn require_history_capability(
    actor: &Actor,
    capability: &str,
    action: &'static str,
) -> Result<(), CoreError> {
    if actor.has_capability(capability) {
        Ok(())
    } else {
        Err(invalid_snapshot("deliveries.envelope.sender", action))
    }
}

fn require_history_primary(actor: &Actor, action: &'static str) -> Result<(), CoreError> {
    if actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY) && actor.team_id.is_none() {
        Ok(())
    } else {
        Err(invalid_snapshot("deliveries.envelope.sender", action))
    }
}

fn require_history_consultation_requester(actor: &Actor) -> Result<(), CoreError> {
    if actor.team_id.is_some() && actor.has_capability(IMPLEMENTATION_EXECUTION_CAPABILITY) {
        Ok(())
    } else {
        require_history_primary(actor, "consultation request")
    }
}

fn require_history_target(
    actual: &MessageTarget,
    expected: &MessageTarget,
) -> Result<(), CoreError> {
    if actual == expected {
        Ok(())
    } else {
        Err(invalid_snapshot(
            "deliveries.envelope.target",
            "accepted message used an unauthorized route",
        ))
    }
}

fn require_known_history_team(
    teams: &BTreeMap<TeamId, Team>,
    team_id: &TeamId,
) -> Result<(), CoreError> {
    if teams.contains_key(team_id) {
        Ok(())
    } else {
        Err(invalid_snapshot(
            "deliveries.envelope.target",
            "accepted message targeted an unknown team",
        ))
    }
}

fn ensure_replay_candidate(request: &Request, candidate: &Candidate) -> Result<(), CoreError> {
    if request.candidate.as_ref() == Some(candidate) {
        Ok(())
    } else {
        Err(invalid_snapshot(
            "deliveries.message.candidate",
            "message does not bind the current exact candidate",
        ))
    }
}

fn is_rejected_candidate_rework(request: &Request) -> bool {
    request.decision.as_ref().is_some_and(|decision| {
        decision.verdict == ReviewVerdict::Rejected
            && request.candidate.as_ref() == Some(&decision.candidate)
    })
}

fn request_metrics_are_legacy_default(request: &Request) -> bool {
    request.rejection_count == 0
        && request.fix_cycle_depth == 0
        && request.candidate_history.is_empty()
}

fn required_request_id(envelope: &Envelope) -> Result<RequestId, CoreError> {
    envelope.request_id.clone().ok_or_else(|| {
        invalid_snapshot(
            "deliveries.envelope.request_id",
            "request-scoped message lacks a request id",
        )
    })
}

fn invalid_snapshot(path: impl Into<String>, reason: &'static str) -> CoreError {
    CoreError::InvalidSnapshot {
        path: path.into(),
        reason,
    }
}

fn digest_message(message: &Message) -> Result<PayloadDigest, CoreError> {
    let bytes = serde_json::to_vec(message)
        .map_err(|_| quota("serialized message bytes", MAX_FRAME_BYTES))?;
    Ok(digest_bytes(&bytes))
}

fn digest_audit_event(event: &AuditEvent) -> Result<PayloadDigest, CoreError> {
    let bytes = serde_json::to_vec(event)
        .map_err(|_| invalid_snapshot("audit_events", "audit event cannot be serialized"))?;
    Ok(digest_bytes(&bytes))
}

fn digest_bytes(bytes: &[u8]) -> PayloadDigest {
    let digest = Sha256::digest(bytes);
    let mut value = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing hexadecimal to String cannot fail");
    }
    PayloadDigest { sha256: value }
}

fn causal_message(
    message_id: &MessageId,
    payload_digest: &PayloadDigest,
    message: &Message,
) -> CausalMessage {
    match message {
        Message::ImplementationRequest(specification) => CausalMessage::ImplementationRequest {
            base_sha: specification.base_sha.clone(),
        },
        Message::Progress(_) => CausalMessage::Progress,
        Message::Blocker(_) => CausalMessage::Blocker,
        Message::CandidateReady(ready) => CausalMessage::CandidateReady {
            candidate: ready.candidate.clone(),
        },
        Message::ReviewDecision(decision) => CausalMessage::ReviewDecision(ReviewDecisionRef {
            message_id: message_id.clone(),
            payload_digest: payload_digest.clone(),
            decision_id: decision.decision_id.clone(),
            candidate: decision.candidate.clone(),
            verdict: decision.verdict,
            reviewer: decision.reviewer.clone(),
            policy_revision: decision.policy_revision,
        }),
        Message::FixRequest(fix) => CausalMessage::FixRequest {
            decision_id: fix.decision_id.clone(),
            candidate: fix.candidate.clone(),
        },
        Message::QaResult(result) => CausalMessage::QaResult {
            candidate: result.candidate.clone(),
            outcome: result.outcome,
        },
        Message::IntegrationAuthorization(authorization) => {
            CausalMessage::IntegrationAuthorization(authorization.clone())
        }
        Message::Cancellation(_) => CausalMessage::Cancellation,
        Message::RunControl(control) => CausalMessage::RunControl {
            action: control.action,
        },
        Message::ConsultationRequest(request) => CausalMessage::ConsultationRequest {
            consultation_id: request.consultation_id.clone(),
            target_team_id: request.target_team_id.clone(),
        },
        Message::ConsultationResponse(response) => CausalMessage::ConsultationResponse {
            consultation_id: response.consultation_id.clone(),
            responding_team_id: response.responding_team_id.clone(),
        },
        Message::DependencyNotice(notice) => CausalMessage::DependencyNotice {
            blocked_request_id: notice.blocked_request_id.clone(),
            depends_on_request_id: notice.depends_on_request_id.clone(),
            provider_team_id: notice.provider_team_id.clone(),
        },
        Message::ConflictNotice(notice) => CausalMessage::ConflictNotice {
            other_team_id: notice.other_team_id.clone(),
        },
        Message::HandoffOffer(offer) => CausalMessage::HandoffOffer(HandoffOfferRef {
            message_id: message_id.clone(),
            payload_digest: payload_digest.clone(),
            handoff_id: offer.handoff_id.clone(),
            request_id: offer.request_id.clone(),
            from_team_id: offer.from_team_id.clone(),
            to_team_id: offer.to_team_id.clone(),
            candidate: offer.candidate.clone(),
        }),
        Message::HandoffAcceptance(acceptance) => {
            CausalMessage::HandoffAcceptance(acceptance.clone())
        }
        Message::IntegrationComplete(complete) => CausalMessage::IntegrationComplete {
            decision_id: complete.decision_id.clone(),
            candidate: complete.candidate.clone(),
        },
    }
}

// Keep this inverse variant table exhaustive and adjacent; splitting it would
// make causal projection coverage harder to audit.
#[allow(clippy::too_many_lines)]
fn replay_message(causal: &CausalMessage) -> Message {
    let archived = || "archived compact payload".to_owned();
    match causal {
        CausalMessage::ImplementationRequest { base_sha } => {
            Message::ImplementationRequest(agsv_protocol::ImplementationRequest {
                title: archived(),
                instructions: archived(),
                base_sha: base_sha.clone(),
                acceptance_criteria: vec![archived()],
                evidence_requirements: Vec::new(),
            })
        }
        CausalMessage::Progress => Message::Progress(agsv_protocol::ProgressUpdate {
            summary: archived(),
            percent_complete: None,
            evidence: Vec::new(),
        }),
        CausalMessage::Blocker => Message::Blocker(agsv_protocol::BlockerNotice {
            summary: archived(),
            needs_primary: true,
            evidence: Vec::new(),
        }),
        CausalMessage::CandidateReady { candidate } => {
            Message::CandidateReady(agsv_protocol::CandidateReady {
                candidate: candidate.clone(),
                summary: archived(),
                evidence: Vec::new(),
            })
        }
        CausalMessage::ReviewDecision(decision) => Message::ReviewDecision(ReviewDecision {
            decision_id: decision.decision_id.clone(),
            candidate: decision.candidate.clone(),
            verdict: decision.verdict,
            reviewer: decision.reviewer.clone(),
            policy_revision: decision.policy_revision,
            rationale: archived(),
            evidence: Vec::new(),
        }),
        CausalMessage::FixRequest {
            decision_id,
            candidate,
        } => Message::FixRequest(agsv_protocol::FixRequest {
            decision_id: decision_id.clone(),
            candidate: candidate.clone(),
            instructions: archived(),
        }),
        CausalMessage::QaResult { candidate, outcome } => {
            Message::QaResult(agsv_protocol::QaResult {
                candidate: candidate.clone(),
                outcome: *outcome,
                summary: archived(),
                evidence: Vec::new(),
            })
        }
        CausalMessage::IntegrationAuthorization(value) => {
            Message::IntegrationAuthorization(value.clone())
        }
        CausalMessage::Cancellation => {
            Message::Cancellation(agsv_protocol::Cancellation { reason: archived() })
        }
        CausalMessage::RunControl { action } => {
            Message::RunControl(agsv_protocol::RunControl { action: *action })
        }
        CausalMessage::ConsultationRequest {
            consultation_id,
            target_team_id,
        } => Message::ConsultationRequest(agsv_protocol::ConsultationRequest {
            consultation_id: consultation_id.clone(),
            target_team_id: target_team_id.clone(),
            subject: archived(),
            question: archived(),
            evidence: Vec::new(),
        }),
        CausalMessage::ConsultationResponse {
            consultation_id,
            responding_team_id,
        } => Message::ConsultationResponse(agsv_protocol::ConsultationResponse {
            consultation_id: consultation_id.clone(),
            responding_team_id: responding_team_id.clone(),
            response: archived(),
            evidence: Vec::new(),
        }),
        CausalMessage::DependencyNotice {
            blocked_request_id,
            depends_on_request_id,
            provider_team_id,
        } => Message::DependencyNotice(agsv_protocol::DependencyNotice {
            blocked_request_id: blocked_request_id.clone(),
            depends_on_request_id: depends_on_request_id.clone(),
            provider_team_id: provider_team_id.clone(),
            description: archived(),
        }),
        CausalMessage::ConflictNotice { other_team_id } => {
            Message::ConflictNotice(agsv_protocol::ConflictNotice {
                other_team_id: other_team_id.clone(),
                resources: vec![archived()],
                description: archived(),
            })
        }
        CausalMessage::HandoffOffer(offer) => Message::HandoffOffer(HandoffOffer {
            handoff_id: offer.handoff_id.clone(),
            request_id: offer.request_id.clone(),
            from_team_id: offer.from_team_id.clone(),
            to_team_id: offer.to_team_id.clone(),
            candidate: offer.candidate.clone(),
            reason: archived(),
        }),
        CausalMessage::HandoffAcceptance(value) => Message::HandoffAcceptance(value.clone()),
        CausalMessage::IntegrationComplete {
            decision_id,
            candidate,
        } => Message::IntegrationComplete(agsv_protocol::IntegrationComplete {
            decision_id: decision_id.clone(),
            candidate: candidate.clone(),
            evidence: Vec::new(),
        }),
    }
}

fn validate_envelope_quota(envelope: &Envelope) -> Result<(), CoreError> {
    let bytes = serde_json::to_vec(envelope)
        .map_err(|_| quota("serialized envelope bytes", MAX_FRAME_BYTES))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(quota("serialized envelope bytes", MAX_FRAME_BYTES));
    }
    Ok(())
}

fn validate_snapshot_quota(snapshot: &DomainSnapshot) -> Result<(), CoreError> {
    for (resource, count, maximum) in [
        ("actors", snapshot.actors.len(), MAX_DOMAIN_ENTITIES),
        ("teams", snapshot.teams.len(), MAX_DOMAIN_ENTITIES),
        ("requests", snapshot.requests.len(), MAX_DOMAIN_ENTITIES),
        ("runs", snapshot.runs.len(), MAX_DOMAIN_ENTITIES),
        (
            "pending handoffs",
            snapshot.pending_handoffs.len(),
            MAX_DOMAIN_ENTITIES,
        ),
        ("deliveries", snapshot.deliveries.len(), MAX_DELIVERIES),
        (
            "audit events",
            snapshot.audit_events.len(),
            MAX_AUDIT_EVENTS,
        ),
    ] {
        if count > maximum {
            return Err(quota(resource, maximum));
        }
    }
    if snapshot
        .teams
        .iter()
        .any(|team| team.actors.len() > MAX_DOMAIN_ENTITIES)
        || snapshot
            .requests
            .iter()
            .any(|request| request.candidate_history.len() > MAX_DOMAIN_ENTITIES)
        || snapshot
            .deliveries
            .iter()
            .any(|delivery| delivery.acknowledgements.len() > MAX_ACKNOWLEDGEMENTS)
    {
        return Err(quota("nested snapshot collection", MAX_DOMAIN_ENTITIES));
    }
    let bytes = serde_json::to_vec(snapshot)
        .map_err(|_| quota("serialized snapshot bytes", MAX_SNAPSHOT_BYTES))?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(quota("serialized snapshot bytes", MAX_SNAPSHOT_BYTES));
    }
    Ok(())
}

const fn quota(resource: &'static str, maximum: usize) -> CoreError {
    CoreError::QuotaExceeded { resource, maximum }
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
