use agsv_core::{AckOutcome, ApplyOutcome, CoreError, Supervisor};
use agsv_protocol::{
    Acknowledgement, ActorEpoch, ActorId, ActorProfileName, ActorProfileSnapshot, ActorRef,
    ActorRole, ActorStatus, AssignmentEpoch, AssignmentPolicyId, Cancellation, Candidate,
    CandidateReady, CapabilityId, ConflictNotice, ConsultationRequest, ConsultationResponse,
    DecisionId, DependencyNotice, DomainSnapshot, Envelope, GitSha,
    HUMAN_FACING_PRIMARY_CAPABILITY, HandoffAcceptance, HandoffId, HandoffOffer,
    IMPLEMENTATION_EXECUTION_CAPABILITY, ImplementationRequest, IntegrationAuthorization,
    MAX_DOMAIN_ENTITIES, Message, MessageId, MessageTarget, PolicyRevision, PrimaryEpoch,
    ProgressUpdate, RequestId, RequestStatus, ReviewDecision, ReviewVerdict, RunControl,
    RunControlAction, RunId, RunStatus, TeamId, TeamProfileName, TeamProfileSnapshot,
    TimestampMillis, WorkspaceId,
};

const SHA_0: &str = "0000000000000000000000000000000000000000";
const SHA_1: &str = "1111111111111111111111111111111111111111";
const SHA_2: &str = "2222222222222222222222222222222222222222";

fn actor_profile(name: &str, capabilities: &[&str]) -> ActorProfileSnapshot {
    ActorProfileSnapshot {
        name: ActorProfileName::new(name).expect("valid actor profile name"),
        capabilities: capabilities
            .iter()
            .map(|capability| CapabilityId::new(*capability).expect("valid capability"))
            .collect(),
    }
}

fn team_profile(
    name: &str,
    actor_profile_name: &str,
    desired_instances: u16,
    assignment_policy: &str,
) -> TeamProfileSnapshot {
    TeamProfileSnapshot {
        name: TeamProfileName::new(name).expect("valid team profile name"),
        actor_profile: ActorProfileName::new(actor_profile_name).expect("valid actor profile name"),
        desired_instances,
        assignment_policy: AssignmentPolicyId::new(assignment_policy)
            .expect("valid assignment policy"),
    }
}

struct Fixture {
    supervisor: Supervisor,
    primary: ActorRef,
    implementation: ActorRef,
    workspace: WorkspaceId,
    team: TeamId,
    request: RequestId,
    run: RunId,
}

impl Fixture {
    fn new() -> Self {
        let workspace = WorkspaceId::new("workspace").expect("valid id");
        let team = TeamId::new("team-one").expect("valid id");
        let mut supervisor = Supervisor::new(workspace.clone(), PolicyRevision::INITIAL);
        let primary = supervisor
            .activate_primary(ActorId::new("primary").expect("valid id"))
            .expect("primary activates");
        supervisor.create_team(team.clone()).expect("team creates");
        let implementation = supervisor
            .register_implementation(&team, ActorId::new("implementation-one").expect("valid id"))
            .expect("implementation registers");
        Self {
            supervisor,
            primary,
            implementation,
            workspace,
            team,
            request: RequestId::new("request-one").expect("valid id"),
            run: RunId::new("run-one").expect("valid id"),
        }
    }

    fn request_envelope(&self, message_id: &str) -> Envelope {
        Envelope {
            protocol_version: 1,
            message_id: MessageId::new(message_id).expect("valid id"),
            workspace_id: self.workspace.clone(),
            sender: self.primary.clone(),
            target: MessageTarget::Actor(self.implementation.actor_id.clone()),
            team_id: Some(self.team.clone()),
            run_id: Some(self.run.clone()),
            request_id: Some(self.request.clone()),
            policy_revision: self.supervisor.policy_revision(),
            primary_epoch: self.supervisor.primary_epoch(),
            team_epoch: Some(self.supervisor.team(&self.team).expect("team exists").epoch),
            assignment_epoch: None,
            sent_at: TimestampMillis(1),
            message: Message::ImplementationRequest(ImplementationRequest {
                title: "Implement the protocol".to_owned(),
                instructions: "Build the requested provider-neutral behavior.".to_owned(),
                base_sha: GitSha::new(SHA_0).expect("valid sha"),
                acceptance_criteria: vec!["All checks pass".to_owned()],
                evidence_requirements: Vec::new(),
            }),
        }
    }

    fn send_request(&mut self) {
        let envelope = self.request_envelope("create-request");
        assert_eq!(self.supervisor.apply(envelope), Ok(ApplyOutcome::Applied));
    }

    fn implementation_envelope(
        &self,
        message_id: &str,
        sender: ActorRef,
        team: &TeamId,
        assignment_epoch: AssignmentEpoch,
        message: Message,
    ) -> Envelope {
        Envelope {
            protocol_version: 1,
            message_id: MessageId::new(message_id).expect("valid id"),
            workspace_id: self.workspace.clone(),
            sender,
            target: MessageTarget::Primary,
            team_id: Some(team.clone()),
            run_id: Some(self.run.clone()),
            request_id: Some(self.request.clone()),
            policy_revision: self.supervisor.policy_revision(),
            primary_epoch: self.supervisor.primary_epoch(),
            team_epoch: Some(self.supervisor.team(team).expect("team exists").epoch),
            assignment_epoch: Some(assignment_epoch),
            sent_at: TimestampMillis(2),
            message,
        }
    }

    fn primary_envelope(&self, message_id: &str, message: Message) -> Envelope {
        let request = self
            .supervisor
            .request(&self.request)
            .expect("request exists");
        Envelope {
            protocol_version: 1,
            message_id: MessageId::new(message_id).expect("valid id"),
            workspace_id: self.workspace.clone(),
            sender: self.primary.clone(),
            target: MessageTarget::Actor(
                request
                    .assignment
                    .as_ref()
                    .expect("request assigned")
                    .actor
                    .actor_id
                    .clone(),
            ),
            team_id: Some(request.team_id.clone()),
            run_id: Some(self.run.clone()),
            request_id: Some(self.request.clone()),
            policy_revision: self.supervisor.policy_revision(),
            primary_epoch: self.supervisor.primary_epoch(),
            team_epoch: Some(
                self.supervisor
                    .team(&request.team_id)
                    .expect("team exists")
                    .epoch,
            ),
            assignment_epoch: None,
            sent_at: TimestampMillis(3),
            message,
        }
    }

    fn candidate(&self, sha: &str, creator: ActorRef, team: TeamId) -> Candidate {
        Candidate {
            request_id: self.request.clone(),
            team_id: team,
            sha: GitSha::new(sha).expect("valid sha"),
            created_by: creator,
        }
    }

    fn submit_candidate(&mut self, message_id: &str, candidate: Candidate) -> ApplyOutcome {
        let envelope = self.implementation_envelope(
            message_id,
            self.implementation.clone(),
            &self.team,
            AssignmentEpoch::INITIAL,
            Message::CandidateReady(CandidateReady {
                candidate,
                summary: "candidate ready".to_owned(),
                evidence: Vec::new(),
            }),
        );
        self.supervisor
            .apply(envelope)
            .expect("candidate message applies")
    }

    fn review_candidate(
        &mut self,
        message_id: &str,
        decision_id: &str,
        candidate: Candidate,
        verdict: ReviewVerdict,
    ) -> ReviewDecision {
        let decision = ReviewDecision {
            decision_id: DecisionId::new(decision_id).expect("valid id"),
            candidate,
            verdict,
            reviewer: self.primary.clone(),
            policy_revision: self.supervisor.policy_revision(),
            rationale: "review completed against the current policy".to_owned(),
            evidence: Vec::new(),
        };
        let envelope = self.primary_envelope(message_id, Message::ReviewDecision(decision.clone()));
        assert_eq!(self.supervisor.apply(envelope), Ok(ApplyOutcome::Applied));
        decision
    }
}

fn progress(summary: &str) -> Message {
    Message::Progress(ProgressUpdate {
        summary: summary.to_owned(),
        percent_complete: Some(50),
        evidence: Vec::new(),
    })
}

fn populated_snapshot() -> DomainSnapshot {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let team_two = TeamId::new("team-two").expect("valid id");
    fixture
        .supervisor
        .create_team(team_two.clone())
        .expect("team creates");
    fixture
        .supervisor
        .register_implementation(
            &team_two,
            ActorId::new("implementation-two").expect("valid id"),
        )
        .expect("implementation registers");
    let mut offer = fixture.implementation_envelope(
        "pending-handoff",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::HandoffOffer(HandoffOffer {
            handoff_id: HandoffId::new("pending-handoff").expect("valid id"),
            request_id: fixture.request.clone(),
            from_team_id: fixture.team.clone(),
            to_team_id: team_two.clone(),
            candidate: None,
            reason: "transfer subsystem ownership".to_owned(),
        }),
    );
    offer.target = MessageTarget::Team(team_two);
    assert_eq!(fixture.supervisor.apply(offer), Ok(ApplyOutcome::Applied));
    assert_eq!(
        fixture.supervisor.acknowledge(Acknowledgement {
            workspace_id: fixture.workspace,
            message_id: MessageId::new("create-request").expect("valid id"),
            actor: fixture.implementation,
            acknowledged_at: TimestampMillis(5),
        }),
        Ok(AckOutcome::Acknowledged)
    );
    fixture.supervisor.snapshot()
}

fn assert_invalid_snapshot(snapshot: DomainSnapshot) {
    assert!(matches!(
        Supervisor::from_snapshot(snapshot),
        Err(CoreError::InvalidSnapshot { .. })
    ));
}

#[test]
fn delivery_and_acknowledgement_are_idempotent_and_detect_conflicts() {
    let mut fixture = Fixture::new();
    let envelope = fixture.request_envelope("stable-message");
    assert_eq!(
        fixture.supervisor.apply(envelope.clone()),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(
        fixture.supervisor.apply(envelope.clone()),
        Ok(ApplyOutcome::Duplicate)
    );
    assert_eq!(fixture.supervisor.audit_events().len(), 1);

    let mut conflict = envelope.clone();
    if let Message::ImplementationRequest(specification) = &mut conflict.message {
        specification.title = "Different payload".to_owned();
    }
    assert_eq!(
        fixture.supervisor.apply(conflict),
        Err(CoreError::DuplicateMessageConflict)
    );

    assert_eq!(
        fixture
            .supervisor
            .unacknowledged_for(&fixture.implementation)
            .expect("actor is current")
            .len(),
        1
    );
    let acknowledgement = Acknowledgement {
        workspace_id: fixture.workspace.clone(),
        message_id: envelope.message_id,
        actor: fixture.implementation.clone(),
        acknowledged_at: TimestampMillis(4),
    };
    assert_eq!(
        fixture.supervisor.acknowledge(acknowledgement.clone()),
        Ok(AckOutcome::Acknowledged)
    );
    assert_eq!(
        fixture.supervisor.acknowledge(acknowledgement),
        Ok(AckOutcome::Duplicate)
    );
    assert!(
        fixture
            .supervisor
            .unacknowledged_for(&fixture.implementation)
            .expect("actor is current")
            .is_empty()
    );
    assert_eq!(fixture.supervisor.audit_events().len(), 2);
}

#[test]
fn authorization_and_all_fencing_layers_reject_stale_commands() {
    let mut fixture = Fixture::new();
    fixture.send_request();

    let unauthorized = fixture.implementation_envelope(
        "unauthorized-cancel",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::Cancellation(Cancellation {
            reason: "implementation cannot decide this".to_owned(),
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(unauthorized),
        Err(CoreError::Unauthorized("cancel request"))
    );

    let old_team_epoch = fixture.supervisor.team(&fixture.team).expect("team").epoch;
    let replacement = fixture
        .supervisor
        .replace_implementation(
            &fixture.team,
            ActorId::new("implementation-two").expect("valid id"),
        )
        .expect("replacement succeeds");
    let assignment = fixture
        .supervisor
        .request(&fixture.request)
        .expect("request")
        .assignment
        .as_ref()
        .expect("assignment")
        .clone();
    assert_eq!(assignment.epoch.get(), 2);

    let mut stale_team = fixture.implementation_envelope(
        "stale-team",
        replacement.clone(),
        &fixture.team,
        assignment.epoch,
        progress("new executor"),
    );
    stale_team.team_epoch = Some(old_team_epoch);
    assert!(matches!(
        fixture.supervisor.apply(stale_team),
        Err(CoreError::StaleTeamEpoch { .. })
    ));

    let mut stale_actor = replacement.clone();
    stale_actor.actor_epoch = ActorEpoch::new(2).expect("valid epoch");
    let stale_actor = fixture.implementation_envelope(
        "stale-actor",
        stale_actor,
        &fixture.team,
        assignment.epoch,
        progress("stale actor generation"),
    );
    assert!(matches!(
        fixture.supervisor.apply(stale_actor),
        Err(CoreError::StaleActorEpoch { .. })
    ));

    let stale_assignment = fixture.implementation_envelope(
        "stale-assignment",
        replacement,
        &fixture.team,
        AssignmentEpoch::INITIAL,
        progress("stale assignment"),
    );
    assert!(matches!(
        fixture.supervisor.apply(stale_assignment),
        Err(CoreError::StaleAssignmentEpoch { .. })
    ));

    let old_primary_epoch = fixture.supervisor.primary_epoch();
    let old_primary = fixture.primary.clone();
    fixture.primary = fixture
        .supervisor
        .activate_primary(ActorId::new("new-primary").expect("valid id"))
        .expect("primary replacement succeeds");
    let mut stale_primary = fixture.primary_envelope(
        "stale-primary",
        Message::Cancellation(Cancellation {
            reason: "late command".to_owned(),
        }),
    );
    stale_primary.sender = old_primary;
    stale_primary.primary_epoch = old_primary_epoch;
    assert!(matches!(
        fixture.supervisor.apply(stale_primary),
        Err(CoreError::StalePrimaryEpoch { .. })
    ));

    let mut stale_policy = fixture.primary_envelope(
        "stale-policy",
        Message::Cancellation(Cancellation {
            reason: "old policy".to_owned(),
        }),
    );
    stale_policy.policy_revision = PolicyRevision::new(2).expect("valid revision");
    assert!(matches!(
        fixture.supervisor.apply(stale_policy),
        Err(CoreError::StalePolicyRevision { .. })
    ));
}

#[test]
fn rejection_invalidates_review_and_authorization_is_exact_sha_only() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let candidate_one =
        fixture.candidate(SHA_1, fixture.implementation.clone(), fixture.team.clone());
    assert_eq!(
        fixture.submit_candidate("candidate-one", candidate_one.clone()),
        ApplyOutcome::Applied
    );
    fixture.review_candidate(
        "reject-one",
        "decision-one",
        candidate_one.clone(),
        ReviewVerdict::Rejected,
    );
    assert_eq!(
        fixture
            .supervisor
            .request(&fixture.request)
            .expect("request")
            .status,
        RequestStatus::ChangesRequested
    );

    let same_candidate = fixture.implementation_envelope(
        "same-candidate",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::CandidateReady(CandidateReady {
            candidate: candidate_one.clone(),
            summary: "unchanged candidate".to_owned(),
            evidence: Vec::new(),
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(same_candidate),
        Err(CoreError::CandidateMustChange)
    );

    let candidate_two =
        fixture.candidate(SHA_2, fixture.implementation.clone(), fixture.team.clone());
    assert_eq!(
        fixture.submit_candidate("candidate-two", candidate_two.clone()),
        ApplyOutcome::Applied
    );
    assert!(
        fixture
            .supervisor
            .request(&fixture.request)
            .expect("request")
            .decision
            .is_none(),
        "new candidate invalidates the rejected decision"
    );

    let acceptance = fixture.review_candidate(
        "accept-two",
        "decision-two",
        candidate_two.clone(),
        ReviewVerdict::Accepted,
    );

    let wrong_sha_authorization = fixture.primary_envelope(
        "authorize-wrong-sha",
        Message::IntegrationAuthorization(IntegrationAuthorization {
            decision_id: acceptance.decision_id.clone(),
            candidate: candidate_one,
            authorized_by: fixture.primary.clone(),
        }),
    );
    assert!(matches!(
        fixture.supervisor.apply(wrong_sha_authorization),
        Err(CoreError::CandidateMismatch { .. })
    ));

    let authorize = fixture.primary_envelope(
        "authorize-two",
        Message::IntegrationAuthorization(IntegrationAuthorization {
            decision_id: acceptance.decision_id,
            candidate: candidate_two,
            authorized_by: fixture.primary.clone(),
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(authorize),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(
        fixture
            .supervisor
            .request(&fixture.request)
            .expect("request")
            .status,
        RequestStatus::IntegrationAuthorized
    );
}

#[test]
fn two_phase_handoff_advances_assignment_and_fences_old_owner() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let team_two = TeamId::new("team-two").expect("valid id");
    fixture
        .supervisor
        .create_team(team_two.clone())
        .expect("team creates");
    let implementation_two = fixture
        .supervisor
        .register_implementation(
            &team_two,
            ActorId::new("implementation-two").expect("valid id"),
        )
        .expect("implementation registers");
    let handoff_id = HandoffId::new("handoff-one").expect("valid id");

    let mut offer = fixture.implementation_envelope(
        "handoff-offer",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::HandoffOffer(HandoffOffer {
            handoff_id: handoff_id.clone(),
            request_id: fixture.request.clone(),
            from_team_id: fixture.team.clone(),
            to_team_id: team_two.clone(),
            candidate: None,
            reason: "team two owns the affected subsystem".to_owned(),
        }),
    );
    offer.target = MessageTarget::Team(team_two.clone());
    assert_eq!(fixture.supervisor.apply(offer), Ok(ApplyOutcome::Applied));

    let mut acceptance = fixture.implementation_envelope(
        "handoff-accept",
        implementation_two.clone(),
        &team_two,
        AssignmentEpoch::INITIAL,
        Message::HandoffAcceptance(HandoffAcceptance {
            handoff_id,
            request_id: fixture.request.clone(),
            from_team_id: fixture.team.clone(),
            to_team_id: team_two.clone(),
            accepted_by: implementation_two.clone(),
        }),
    );
    acceptance.target = MessageTarget::Team(fixture.team.clone());
    assert_eq!(
        fixture.supervisor.apply(acceptance),
        Ok(ApplyOutcome::Applied)
    );
    let assignment = fixture
        .supervisor
        .request(&fixture.request)
        .expect("request")
        .assignment
        .as_ref()
        .expect("assignment");
    assert_eq!(assignment.actor, implementation_two);
    assert_eq!(assignment.epoch.get(), 2);

    let old_owner = fixture.implementation_envelope(
        "old-owner-progress",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        progress("late work from old owner"),
    );
    assert!(matches!(
        fixture.supervisor.apply(old_owner),
        Err(CoreError::WrongTeam)
    ));

    let new_owner = fixture.implementation_envelope(
        "new-owner-progress",
        implementation_two,
        &team_two,
        AssignmentEpoch::new(2).expect("valid epoch"),
        progress("new owner resumed work"),
    );
    assert_eq!(
        fixture.supervisor.apply(new_owner),
        Ok(ApplyOutcome::Applied)
    );
}

#[test]
fn snapshot_is_serializable_without_provider_specific_state() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let value = serde_json::to_value(fixture.supervisor.snapshot()).expect("snapshot serializes");
    assert_eq!(value["workspace_id"], "workspace");
    assert_eq!(value["active_primary"]["actor_id"], "primary");
    assert_eq!(value["deliveries"].as_array().map(Vec::len), Some(1));
    assert_eq!(value["audit_events"].as_array().map(Vec::len), Some(1));
    assert!(value.get("provider").is_none());
    assert!(value.get("session_id").is_none());
}

#[test]
fn populated_snapshot_round_trip_preserves_mailbox_handoff_fences_and_audit() {
    let snapshot = populated_snapshot();
    let duplicate = snapshot
        .deliveries
        .first()
        .expect("delivery exists")
        .envelope
        .clone();
    let encoded = serde_json::to_vec(&snapshot).expect("snapshot serializes");
    let decoded = serde_json::from_slice(&encoded).expect("snapshot deserializes");
    let mut restored = Supervisor::from_snapshot(decoded).expect("snapshot restores");

    assert_eq!(restored.snapshot(), snapshot);
    assert_eq!(restored.apply(duplicate), Ok(ApplyOutcome::Duplicate));
    assert_eq!(restored.snapshot().audit_events.len(), 3);
    assert_eq!(restored.snapshot().pending_handoffs.len(), 1);
}

#[test]
fn restore_rejects_duplicate_and_inconsistent_entity_references() {
    let snapshot = populated_snapshot();

    let mut duplicate_actor = snapshot.clone();
    duplicate_actor
        .actors
        .push(duplicate_actor.actors[0].clone());
    assert_invalid_snapshot(duplicate_actor);

    let mut wrong_workspace = snapshot.clone();
    wrong_workspace.requests[0].workspace_id =
        WorkspaceId::new("other-workspace").expect("valid id");
    assert_invalid_snapshot(wrong_workspace);

    let mut broken_team_link = snapshot.clone();
    broken_team_link
        .teams
        .iter_mut()
        .find(|team| team.team_id.as_str() == "team-one")
        .expect("team exists")
        .actors
        .clear();
    assert_invalid_snapshot(broken_team_link);

    let mut broken_request_run = snapshot.clone();
    broken_request_run.requests[0].run_id = RunId::new("missing-run").expect("valid id");
    assert_invalid_snapshot(broken_request_run);
}

#[test]
fn restore_rejects_corrupt_delivery_handoff_and_audit_links() {
    let snapshot = populated_snapshot();

    let mut duplicate_delivery = snapshot.clone();
    duplicate_delivery
        .deliveries
        .push(duplicate_delivery.deliveries[0].clone());
    assert_invalid_snapshot(duplicate_delivery);

    let mut broken_handoff = snapshot.clone();
    broken_handoff.pending_handoffs[0].assignment_epoch =
        AssignmentEpoch::new(2).expect("valid epoch");
    assert_invalid_snapshot(broken_handoff);

    let mut broken_audit = snapshot.clone();
    broken_audit.audit_events[0].sequence = 99;
    assert_invalid_snapshot(broken_audit);
}

#[test]
fn acknowledgement_retry_is_exact_and_survives_actor_replacement() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let acknowledgement = Acknowledgement {
        workspace_id: fixture.workspace.clone(),
        message_id: MessageId::new("create-request").expect("valid id"),
        actor: fixture.implementation.clone(),
        acknowledged_at: TimestampMillis(10),
    };
    assert_eq!(
        fixture.supervisor.acknowledge(acknowledgement.clone()),
        Ok(AckOutcome::Acknowledged)
    );

    let mut changed = acknowledgement.clone();
    changed.acknowledged_at = TimestampMillis(11);
    assert_eq!(
        fixture.supervisor.acknowledge(changed),
        Err(CoreError::DuplicateAcknowledgementConflict)
    );

    fixture
        .supervisor
        .replace_implementation(
            &fixture.team,
            ActorId::new("replacement").expect("valid id"),
        )
        .expect("replacement succeeds");
    assert_eq!(
        fixture.supervisor.acknowledge(acknowledgement),
        Ok(AckOutcome::Duplicate),
        "an exact durable retry precedes live generation fences"
    );
}

#[test]
fn revoked_actor_cannot_heartbeat_but_timeout_stale_actor_can_recover() {
    let mut fixture = Fixture::new();
    fixture
        .supervisor
        .set_actor_status(&fixture.implementation, ActorStatus::Stale)
        .expect("healthy actor may time out");
    fixture
        .supervisor
        .heartbeat(&fixture.implementation, TimestampMillis(1))
        .expect("timeout-stale actor may recover");

    fixture
        .supervisor
        .replace_implementation(
            &fixture.team,
            ActorId::new("replacement").expect("valid id"),
        )
        .expect("replacement succeeds");
    assert!(matches!(
        fixture
            .supervisor
            .heartbeat(&fixture.implementation, TimestampMillis(2)),
        Err(CoreError::InvalidTransition { .. })
    ));
    assert_eq!(
        fixture
            .supervisor
            .actor(&fixture.implementation.actor_id)
            .expect("old actor remains as a tombstone")
            .status,
        ActorStatus::Revoked
    );
}

#[test]
fn primary_stop_fences_the_lease_and_epoch_exhaustion_is_failure_atomic() {
    let mut fixture = Fixture::new();
    let prior_epoch = fixture.supervisor.primary_epoch();
    fixture
        .supervisor
        .set_actor_status(&fixture.primary, ActorStatus::Stopped)
        .expect("active Primary stops");
    assert!(fixture.supervisor.active_primary().is_none());
    assert_eq!(
        fixture.supervisor.primary_epoch().get(),
        prior_epoch.get() + 1
    );
    assert!(matches!(
        fixture
            .supervisor
            .heartbeat(&fixture.primary, TimestampMillis(2)),
        Err(CoreError::Unauthorized(_))
    ));

    let mut snapshot = Supervisor::new(
        WorkspaceId::new("atomic-workspace").expect("valid id"),
        PolicyRevision::INITIAL,
    );
    snapshot
        .activate_primary(ActorId::new("atomic-primary").expect("valid id"))
        .expect("primary activates");
    let mut snapshot = snapshot.snapshot();
    snapshot.primary_epoch = PrimaryEpoch::new(u64::MAX).expect("valid max epoch");
    let mut restored = Supervisor::from_snapshot(snapshot).expect("snapshot restores");
    let before = restored.snapshot();
    assert_eq!(
        restored.activate_primary(ActorId::new("next-primary").expect("valid id")),
        Err(CoreError::EpochExhausted)
    );
    assert_eq!(restored.snapshot(), before);
}

#[test]
fn restore_requires_a_healthy_active_primary() {
    let fixture = Fixture::new();
    let mut snapshot = fixture.supervisor.snapshot();
    let primary = snapshot
        .actors
        .iter_mut()
        .find(|actor| actor.actor_id == fixture.primary.actor_id)
        .expect("primary exists");
    primary.status = ActorStatus::Stale;
    assert_invalid_snapshot(snapshot);
}

#[test]
fn request_context_is_bound_to_the_current_team() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let other_team = TeamId::new("other-team").expect("valid id");
    fixture
        .supervisor
        .create_team(other_team.clone())
        .expect("team creates");
    fixture
        .supervisor
        .register_implementation(
            &other_team,
            ActorId::new("other-implementation").expect("valid id"),
        )
        .expect("actor registers");

    let mut wrong_team = fixture.primary_envelope(
        "wrong-request-team",
        Message::Cancellation(Cancellation {
            reason: "wrong team context".to_owned(),
        }),
    );
    wrong_team.team_id = Some(other_team.clone());
    wrong_team.team_epoch = Some(
        fixture
            .supervisor
            .team(&other_team)
            .expect("team exists")
            .epoch,
    );
    assert_eq!(
        fixture.supervisor.apply(wrong_team),
        Err(CoreError::WrongTeam)
    );

    let mut partial_context = fixture.implementation_envelope(
        "partial-context",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::ConflictNotice(ConflictNotice {
            other_team_id: other_team,
            resources: vec!["shared-resource".to_owned()],
            description: "potential collision".to_owned(),
        }),
    );
    partial_context.run_id = None;
    assert!(matches!(
        fixture.supervisor.apply(partial_context),
        Err(CoreError::Validation(_))
    ));
}

#[test]
fn cross_team_consultation_response_is_correlated_and_routed() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let provider_team = TeamId::new("provider-team").expect("valid id");
    fixture
        .supervisor
        .create_team(provider_team.clone())
        .expect("team creates");
    let provider = fixture
        .supervisor
        .register_implementation(
            &provider_team,
            ActorId::new("provider-implementation").expect("valid id"),
        )
        .expect("actor registers");

    let consultation_id = MessageId::new("consultation-one").expect("valid id");
    let mut consultation = fixture.implementation_envelope(
        consultation_id.as_str(),
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::ConsultationRequest(ConsultationRequest {
            consultation_id: consultation_id.clone(),
            target_team_id: provider_team.clone(),
            subject: "shared contract".to_owned(),
            question: "Which interface is stable?".to_owned(),
            evidence: Vec::new(),
        }),
    );
    consultation.target = MessageTarget::Team(provider_team.clone());
    assert_eq!(
        fixture.supervisor.apply(consultation),
        Ok(ApplyOutcome::Applied)
    );

    let response = Envelope {
        protocol_version: 1,
        message_id: MessageId::new("consultation-response").expect("valid id"),
        workspace_id: fixture.workspace.clone(),
        sender: provider.clone(),
        target: MessageTarget::Actor(fixture.implementation.actor_id.clone()),
        team_id: Some(provider_team.clone()),
        run_id: None,
        request_id: None,
        policy_revision: fixture.supervisor.policy_revision(),
        primary_epoch: fixture.supervisor.primary_epoch(),
        team_epoch: Some(
            fixture
                .supervisor
                .team(&provider_team)
                .expect("team exists")
                .epoch,
        ),
        assignment_epoch: None,
        sent_at: TimestampMillis(5),
        message: Message::ConsultationResponse(ConsultationResponse {
            consultation_id: consultation_id.clone(),
            responding_team_id: provider_team.clone(),
            response: "Use interface v1".to_owned(),
            evidence: Vec::new(),
        }),
    };
    assert_eq!(
        fixture.supervisor.apply(response.clone()),
        Ok(ApplyOutcome::Applied)
    );
    let mut wrong_route = response.clone();
    wrong_route.message_id = MessageId::new("wrong-route-response").expect("valid id");
    wrong_route.target = MessageTarget::Primary;
    assert_eq!(
        fixture.supervisor.apply(wrong_route),
        Err(CoreError::WrongTarget)
    );
    let mut uncorrelated = response;
    uncorrelated.message_id = MessageId::new("uncorrelated-response").expect("valid id");
    if let Message::ConsultationResponse(response) = &mut uncorrelated.message {
        response.consultation_id = MessageId::new("missing-consultation").expect("valid id");
    }
    assert_eq!(
        fixture.supervisor.apply(uncorrelated),
        Err(CoreError::UnknownMessage)
    );
    let snapshot = fixture.supervisor.snapshot();
    assert_eq!(
        Supervisor::from_snapshot(snapshot.clone())
            .expect("coordination history restores")
            .snapshot(),
        snapshot
    );
}

#[test]
fn primary_consultation_response_stays_on_primary_route_after_replacement() {
    let mut fixture = Fixture::new();
    let original_primary = fixture.primary.clone();
    let provider_team = TeamId::new("replacement-provider-team").expect("valid id");
    fixture
        .supervisor
        .create_team(provider_team.clone())
        .expect("team creates");
    let provider = fixture
        .supervisor
        .register_implementation(
            &provider_team,
            ActorId::new("replacement-provider").expect("valid id"),
        )
        .expect("provider registers");
    let consultation_id = MessageId::new("primary-consultation").expect("valid id");
    let consultation = Envelope {
        protocol_version: 1,
        message_id: consultation_id.clone(),
        workspace_id: fixture.workspace.clone(),
        sender: original_primary.clone(),
        target: MessageTarget::Team(provider_team.clone()),
        team_id: Some(provider_team.clone()),
        run_id: None,
        request_id: None,
        policy_revision: fixture.supervisor.policy_revision(),
        primary_epoch: fixture.supervisor.primary_epoch(),
        team_epoch: Some(
            fixture
                .supervisor
                .team(&provider_team)
                .expect("team exists")
                .epoch,
        ),
        assignment_epoch: None,
        sent_at: TimestampMillis(4),
        message: Message::ConsultationRequest(ConsultationRequest {
            consultation_id: consultation_id.clone(),
            target_team_id: provider_team.clone(),
            subject: "durable Primary route".to_owned(),
            question: "Where should the response go after replacement?".to_owned(),
            evidence: Vec::new(),
        }),
    };
    assert_eq!(
        fixture.supervisor.apply(consultation),
        Ok(ApplyOutcome::Applied)
    );

    fixture.primary = fixture
        .supervisor
        .activate_primary(ActorId::new("replacement-primary").expect("valid id"))
        .expect("replacement acquires the lease");
    let response = Envelope {
        protocol_version: 1,
        message_id: MessageId::new("primary-consultation-response").expect("valid id"),
        workspace_id: fixture.workspace.clone(),
        sender: provider,
        target: MessageTarget::Primary,
        team_id: Some(provider_team.clone()),
        run_id: None,
        request_id: None,
        policy_revision: fixture.supervisor.policy_revision(),
        primary_epoch: fixture.supervisor.primary_epoch(),
        team_epoch: Some(
            fixture
                .supervisor
                .team(&provider_team)
                .expect("team exists")
                .epoch,
        ),
        assignment_epoch: None,
        sent_at: TimestampMillis(5),
        message: Message::ConsultationResponse(ConsultationResponse {
            consultation_id,
            responding_team_id: provider_team,
            response: "Route to the current Primary lease".to_owned(),
            evidence: Vec::new(),
        }),
    };
    let mut stale_actor_route = response.clone();
    stale_actor_route.message_id =
        MessageId::new("stale-primary-consultation-response").expect("valid id");
    stale_actor_route.target = MessageTarget::Actor(original_primary.actor_id);
    assert_eq!(
        fixture.supervisor.apply(stale_actor_route),
        Err(CoreError::WrongTarget)
    );
    assert_eq!(
        fixture.supervisor.apply(response),
        Ok(ApplyOutcome::Applied)
    );

    let snapshot = fixture.supervisor.snapshot();
    assert_eq!(
        Supervisor::from_snapshot(snapshot.clone())
            .expect("Primary consultation route replays after replacement")
            .snapshot(),
        snapshot
    );
}

#[test]
fn cross_team_dependency_and_conflict_payloads_match_their_routes() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let provider_team = TeamId::new("provider-team").expect("valid id");
    fixture
        .supervisor
        .create_team(provider_team.clone())
        .expect("team creates");
    let provider = fixture
        .supervisor
        .register_implementation(
            &provider_team,
            ActorId::new("provider-implementation").expect("valid id"),
        )
        .expect("actor registers");

    let provider_request = RequestId::new("provider-request").expect("valid id");
    let provider_run = RunId::new("provider-run").expect("valid id");
    let mut create_provider = fixture.request_envelope("create-provider-request");
    create_provider.request_id = Some(provider_request.clone());
    create_provider.run_id = Some(provider_run);
    create_provider.team_id = Some(provider_team.clone());
    create_provider.team_epoch = Some(
        fixture
            .supervisor
            .team(&provider_team)
            .expect("team exists")
            .epoch,
    );
    create_provider.target = MessageTarget::Actor(provider.actor_id.clone());
    assert_eq!(
        fixture.supervisor.apply(create_provider),
        Ok(ApplyOutcome::Applied)
    );

    let mut dependency = fixture.implementation_envelope(
        "dependency",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::DependencyNotice(DependencyNotice {
            blocked_request_id: fixture.request.clone(),
            depends_on_request_id: provider_request,
            provider_team_id: provider_team.clone(),
            description: "waiting for provider output".to_owned(),
        }),
    );
    dependency.target = MessageTarget::Team(provider_team.clone());
    let mut wrong_dependency = dependency.clone();
    wrong_dependency.message_id = MessageId::new("wrong-dependency").expect("valid id");
    if let Message::DependencyNotice(notice) = &mut wrong_dependency.message {
        notice.provider_team_id = fixture.team.clone();
    }
    assert_eq!(
        fixture.supervisor.apply(wrong_dependency),
        Err(CoreError::WrongTeam)
    );
    assert_eq!(
        fixture.supervisor.apply(dependency),
        Ok(ApplyOutcome::Applied)
    );

    let mut conflict = fixture.implementation_envelope(
        "conflict",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::ConflictNotice(ConflictNotice {
            other_team_id: provider_team.clone(),
            resources: vec!["schema.json".to_owned()],
            description: "both teams need to edit the schema".to_owned(),
        }),
    );
    conflict.target = MessageTarget::Team(provider_team);
    let mut wrong_conflict = conflict.clone();
    wrong_conflict.message_id = MessageId::new("wrong-conflict").expect("valid id");
    wrong_conflict.target = MessageTarget::Primary;
    assert_eq!(
        fixture.supervisor.apply(wrong_conflict),
        Err(CoreError::WrongTarget)
    );
    assert_eq!(
        fixture.supervisor.apply(conflict),
        Ok(ApplyOutcome::Applied)
    );
    let snapshot = fixture.supervisor.snapshot();
    assert_eq!(
        Supervisor::from_snapshot(snapshot.clone())
            .expect("coordination history restores")
            .snapshot(),
        snapshot
    );
}

#[test]
fn decision_ids_are_workspace_unique_across_review_cycles_and_restore() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let candidate_one =
        fixture.candidate(SHA_1, fixture.implementation.clone(), fixture.team.clone());
    fixture.submit_candidate("candidate-one", candidate_one.clone());
    fixture.review_candidate(
        "review-one",
        "shared-decision",
        candidate_one,
        ReviewVerdict::Rejected,
    );
    let candidate_two =
        fixture.candidate(SHA_2, fixture.implementation.clone(), fixture.team.clone());
    fixture.submit_candidate("candidate-two", candidate_two.clone());
    let duplicate = ReviewDecision {
        decision_id: DecisionId::new("shared-decision").expect("valid id"),
        candidate: candidate_two.clone(),
        verdict: ReviewVerdict::Accepted,
        reviewer: fixture.primary.clone(),
        policy_revision: fixture.supervisor.policy_revision(),
        rationale: "second review".to_owned(),
        evidence: Vec::new(),
    };
    let duplicate_envelope =
        fixture.primary_envelope("duplicate-decision", Message::ReviewDecision(duplicate));
    assert_eq!(
        fixture.supervisor.apply(duplicate_envelope),
        Err(CoreError::AlreadyExists("decision id"))
    );

    let accepted = fixture.review_candidate(
        "review-two",
        "second-decision",
        candidate_two,
        ReviewVerdict::Accepted,
    );
    let mut snapshot = fixture.supervisor.snapshot();
    let shared = DecisionId::new("shared-decision").expect("valid id");
    let delivery = snapshot
        .deliveries
        .iter_mut()
        .find(|delivery| delivery.envelope.message_id.as_str() == "review-two")
        .expect("second review delivery exists");
    if let Message::ReviewDecision(decision) = &mut delivery.envelope.message {
        decision.decision_id = shared.clone();
    }
    let current = snapshot.requests[0]
        .decision
        .as_mut()
        .expect("current decision exists");
    assert_eq!(current.decision_id, accepted.decision_id);
    current.decision_id = shared;
    assert_invalid_snapshot(snapshot);
}

#[test]
fn restore_rejects_old_policy_decisions_and_forged_or_truncated_history() {
    let mut reviewed = Fixture::new();
    reviewed.send_request();
    let candidate = reviewed.candidate(
        SHA_1,
        reviewed.implementation.clone(),
        reviewed.team.clone(),
    );
    reviewed.submit_candidate("candidate", candidate.clone());
    reviewed.review_candidate("review", "decision", candidate, ReviewVerdict::Accepted);

    let mut old_policy = reviewed.supervisor.snapshot();
    old_policy.policy_revision = PolicyRevision::new(2).expect("valid policy");
    assert_invalid_snapshot(old_policy);

    let mut truncated = reviewed.supervisor.snapshot();
    truncated
        .deliveries
        .retain(|delivery| delivery.envelope.message_id.as_str() != "candidate");
    truncated.audit_events.retain(|event| event.sequence != 2);
    for (index, event) in truncated.audit_events.iter_mut().enumerate() {
        event.sequence = u64::try_from(index).expect("small index") + 1;
    }
    assert_invalid_snapshot(truncated);

    let snapshot = populated_snapshot();
    let implementation = snapshot
        .actors
        .iter()
        .find(|actor| actor.team_id.is_some())
        .expect("implementation exists")
        .actor_ref();
    let mut forged_sender = snapshot.clone();
    forged_sender
        .deliveries
        .iter_mut()
        .find(|delivery| matches!(delivery.envelope.message, Message::ImplementationRequest(_)))
        .expect("request delivery exists")
        .envelope
        .sender = implementation;
    assert_invalid_snapshot(forged_sender);

    let mut forged_route = snapshot.clone();
    forged_route
        .deliveries
        .iter_mut()
        .find(|delivery| matches!(delivery.envelope.message, Message::ImplementationRequest(_)))
        .expect("request delivery exists")
        .envelope
        .target = MessageTarget::Primary;
    assert_invalid_snapshot(forged_route);

    let mut forged_fence = snapshot.clone();
    forged_fence.deliveries[0].envelope.primary_epoch = PrimaryEpoch::new(2).expect("valid epoch");
    assert_invalid_snapshot(forged_fence);

    let mut forged_audit_time = snapshot.clone();
    forged_audit_time.audit_events[0].occurred_at = TimestampMillis(999);
    assert_invalid_snapshot(forged_audit_time);

    let mut forged_ack_epoch = snapshot;
    let acknowledgement = forged_ack_epoch
        .deliveries
        .iter_mut()
        .find_map(|delivery| delivery.acknowledgements.first_mut())
        .expect("acknowledgement exists");
    acknowledgement.actor.actor_epoch = ActorEpoch::new(2).expect("valid actor epoch");
    assert_invalid_snapshot(forged_ack_epoch);
}

#[test]
fn snapshot_collection_quota_is_checked_before_reconstruction() {
    let fixture = Fixture::new();
    let mut snapshot = fixture.supervisor.snapshot();
    let actor = snapshot.actors[0].clone();
    snapshot.actors = vec![actor; MAX_DOMAIN_ENTITIES + 1];
    assert!(matches!(
        Supervisor::from_snapshot(snapshot),
        Err(CoreError::QuotaExceeded {
            resource: "actors",
            maximum: MAX_DOMAIN_ENTITIES,
        })
    ));
}

#[test]
fn primary_run_control_pauses_resumes_and_round_trips_causally() {
    let mut fixture = Fixture::new();
    fixture.send_request();

    let pause = fixture.primary_envelope(
        "pause-run",
        Message::RunControl(RunControl {
            action: RunControlAction::Pause,
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(pause.clone()),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(fixture.supervisor.apply(pause), Ok(ApplyOutcome::Duplicate));
    assert_eq!(
        fixture
            .supervisor
            .run(&fixture.run)
            .expect("run exists")
            .status,
        RunStatus::Paused
    );
    assert_eq!(
        fixture
            .supervisor
            .request(&fixture.request)
            .expect("request exists")
            .status,
        RequestStatus::Assigned
    );
    let paused = fixture.supervisor.snapshot();
    assert_eq!(
        Supervisor::from_snapshot(paused.clone())
            .expect("paused snapshot restores from message provenance")
            .snapshot(),
        paused
    );

    let resume = fixture.primary_envelope(
        "resume-run",
        Message::RunControl(RunControl {
            action: RunControlAction::Resume,
        }),
    );
    assert_eq!(fixture.supervisor.apply(resume), Ok(ApplyOutcome::Applied));
    assert_eq!(
        fixture
            .supervisor
            .run(&fixture.run)
            .expect("run exists")
            .status,
        RunStatus::Active
    );
    assert_eq!(
        fixture
            .supervisor
            .request(&fixture.request)
            .expect("request exists")
            .status,
        RequestStatus::InProgress
    );
    let resumed = fixture.supervisor.snapshot();
    assert_eq!(
        Supervisor::try_from_snapshot(resumed.clone())
            .expect("resumed snapshot restores from message provenance")
            .snapshot(),
        resumed
    );
}

#[test]
fn run_control_rejects_non_primary_wrong_route_and_assignment_fence() {
    let mut fixture = Fixture::new();
    fixture.send_request();

    let implementation = fixture.implementation_envelope(
        "implementation-pause",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::RunControl(RunControl {
            action: RunControlAction::Pause,
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(implementation),
        Err(CoreError::Unauthorized("control run"))
    );

    let mut wrong_route = fixture.primary_envelope(
        "wrong-route-pause",
        Message::RunControl(RunControl {
            action: RunControlAction::Pause,
        }),
    );
    wrong_route.target = MessageTarget::Primary;
    assert_eq!(
        fixture.supervisor.apply(wrong_route),
        Err(CoreError::WrongTarget)
    );

    let mut executor_fence = fixture.primary_envelope(
        "fenced-pause",
        Message::RunControl(RunControl {
            action: RunControlAction::Pause,
        }),
    );
    executor_fence.assignment_epoch = Some(AssignmentEpoch::INITIAL);
    assert_eq!(
        fixture.supervisor.apply(executor_fence),
        Err(CoreError::Unauthorized(
            "Primary run control cannot carry an executor assignment fence"
        ))
    );
}

#[test]
fn configured_roles_gain_no_legacy_privilege_without_capabilities() {
    let workspace = WorkspaceId::new("profile-workspace").expect("valid id");
    let mut supervisor = Supervisor::new(workspace, PolicyRevision::INITIAL);
    let actor_id = ActorId::new("configured-primary-role").expect("valid id");
    let before = supervisor.snapshot();

    assert_eq!(
        supervisor.activate_primary_with_profile(
            actor_id.clone(),
            ActorRole::Primary,
            actor_profile("no-privilege", &[]),
        ),
        Err(CoreError::Unauthorized(
            "activate Primary without human_facing_primary capability"
        ))
    );
    assert_eq!(supervisor.snapshot(), before);

    let role = ActorRole::new("research").expect("custom role is valid");
    assert_eq!(serde_json::to_value(&role).unwrap(), "research");
    let decoded: ActorRole = serde_json::from_value(serde_json::json!("research")).unwrap();
    assert_eq!(decoded, role);
}

#[test]
fn arbitrary_role_with_primary_capability_can_hold_and_replace_the_lease() {
    let workspace = WorkspaceId::new("capability-workspace").expect("valid id");
    let mut supervisor = Supervisor::new(workspace, PolicyRevision::INITIAL);
    let first = supervisor
        .activate_primary_with_profile(
            ActorId::new("research-primary").expect("valid id"),
            ActorRole::new("research").expect("valid role"),
            actor_profile("research-primary", &[HUMAN_FACING_PRIMARY_CAPABILITY]),
        )
        .expect("capability authorizes activation");
    let first_primary_epoch = supervisor.primary_epoch();

    let second = supervisor
        .activate_primary_with_profile(
            ActorId::new("release-primary").expect("valid id"),
            ActorRole::new("release-coordination").expect("valid role"),
            actor_profile("release-primary", &[HUMAN_FACING_PRIMARY_CAPABILITY]),
        )
        .expect("the existing replacement invariant fences the prior holder");

    assert_eq!(supervisor.active_primary(), Some(second));
    assert_eq!(
        supervisor
            .actor(&first.actor_id)
            .expect("prior actor remains as a tombstone")
            .status,
        ActorStatus::Revoked
    );
    assert_eq!(
        supervisor.primary_epoch().get(),
        first_primary_epoch.get() + 1
    );
    let snapshot = supervisor.snapshot();
    assert_eq!(
        Supervisor::from_snapshot(snapshot.clone())
            .expect("configured capability snapshot restores")
            .snapshot(),
        snapshot
    );
}

#[test]
fn configured_primary_must_reacquire_its_lease_before_becoming_healthy() {
    let workspace = WorkspaceId::new("configured-lease-workspace").expect("valid id");
    let actor_id = ActorId::new("research-primary").expect("valid id");
    let role = ActorRole::new("research").expect("valid role");
    let profile = actor_profile("research-primary", &[HUMAN_FACING_PRIMARY_CAPABILITY]);
    let mut supervisor = Supervisor::new(workspace, PolicyRevision::INITIAL);
    let actor = supervisor
        .activate_primary_with_profile(actor_id.clone(), role.clone(), profile.clone())
        .expect("configured Primary activates");
    let primary_epoch = supervisor.primary_epoch();

    supervisor
        .set_actor_status(&actor, ActorStatus::Stale)
        .expect("staling the active holder clears its lease");
    assert_eq!(supervisor.active_primary(), None);
    assert_eq!(supervisor.primary_epoch().get(), primary_epoch.get() + 1);
    assert_eq!(
        supervisor.heartbeat(&actor, TimestampMillis(10)),
        Err(CoreError::Unauthorized(
            "heartbeat without active Primary lease"
        ))
    );
    assert_eq!(
        supervisor.set_actor_status(&actor, ActorStatus::Healthy),
        Err(CoreError::Unauthorized(
            "activate Primary before marking it healthy"
        ))
    );
    assert_eq!(
        supervisor
            .actor(&actor_id)
            .expect("stale actor remains")
            .status,
        ActorStatus::Stale
    );

    let mut forged = supervisor.snapshot();
    forged
        .actors
        .iter_mut()
        .find(|candidate| candidate.actor_id == actor_id)
        .expect("actor exists")
        .status = ActorStatus::Healthy;
    assert!(matches!(
        Supervisor::from_snapshot(forged),
        Err(CoreError::InvalidSnapshot {
            path,
            reason: "a healthy Primary actor must hold the active lease",
        }) if path == "active_primary"
    ));

    let reactivated = supervisor
        .activate_primary_with_profile(actor_id, role, profile)
        .expect("explicit activation reacquires the lease");
    assert_eq!(reactivated.actor_epoch.get(), actor.actor_epoch.get() + 1);
    assert_eq!(supervisor.active_primary(), Some(reactivated.clone()));
    supervisor
        .heartbeat(&reactivated, TimestampMillis(11))
        .expect("active configured Primary can heartbeat");
}

#[test]
fn team_actor_capability_combinations_do_not_claim_the_primary_lease() {
    let workspace = WorkspaceId::new("mixed-capability-workspace").expect("valid id");
    let team_id = TeamId::new("mixed-capability-team").expect("valid id");
    let request_id = RequestId::new("mixed-capability-request").expect("valid id");
    let run_id = RunId::new("mixed-capability-run").expect("valid id");
    let mut supervisor = Supervisor::new(workspace.clone(), PolicyRevision::INITIAL);
    let primary = supervisor
        .activate_primary(ActorId::new("legacy-primary").expect("valid id"))
        .expect("primary activates");
    supervisor
        .create_team_with_profile(
            team_id.clone(),
            team_profile("mixed", "mixed", 1, "first_healthy"),
        )
        .expect("team profile persists");
    let team_actor = supervisor
        .register_implementation_with_profile(
            &team_id,
            ActorId::new("mixed-actor").expect("valid id"),
            ActorRole::new("research").expect("valid role"),
            actor_profile(
                "mixed",
                &[
                    HUMAN_FACING_PRIMARY_CAPABILITY,
                    IMPLEMENTATION_EXECUTION_CAPABILITY,
                ],
            ),
        )
        .expect("capability combinations are policy-neutral");

    let request = Envelope {
        protocol_version: 1,
        message_id: MessageId::new("mixed-request").expect("valid id"),
        workspace_id: workspace.clone(),
        sender: primary,
        target: MessageTarget::Actor(team_actor.actor_id.clone()),
        team_id: Some(team_id.clone()),
        run_id: Some(run_id.clone()),
        request_id: Some(request_id.clone()),
        policy_revision: supervisor.policy_revision(),
        primary_epoch: supervisor.primary_epoch(),
        team_epoch: Some(supervisor.team(&team_id).expect("team exists").epoch),
        assignment_epoch: None,
        sent_at: TimestampMillis(1),
        message: Message::ImplementationRequest(ImplementationRequest {
            title: "exercise mixed profile".to_owned(),
            instructions: "prove topology does not erase other capabilities".to_owned(),
            base_sha: GitSha::new(SHA_0).expect("valid sha"),
            acceptance_criteria: vec!["progress is accepted".to_owned()],
            evidence_requirements: Vec::new(),
        }),
    };
    assert_eq!(supervisor.apply(request), Ok(ApplyOutcome::Applied));

    let team_epoch = supervisor.team(&team_id).expect("team exists").epoch;
    let progress = Envelope {
        protocol_version: 1,
        message_id: MessageId::new("mixed-progress").expect("valid id"),
        workspace_id: workspace.clone(),
        sender: team_actor.clone(),
        target: MessageTarget::Primary,
        team_id: Some(team_id.clone()),
        run_id: Some(run_id.clone()),
        request_id: Some(request_id.clone()),
        policy_revision: supervisor.policy_revision(),
        primary_epoch: supervisor.primary_epoch(),
        team_epoch: Some(team_epoch),
        assignment_epoch: Some(AssignmentEpoch::INITIAL),
        sent_at: TimestampMillis(2),
        message: progress("mixed actor remains an executor"),
    };
    assert_eq!(supervisor.apply(progress), Ok(ApplyOutcome::Applied));

    let privileged = Envelope {
        protocol_version: 1,
        message_id: MessageId::new("mixed-pause").expect("valid id"),
        workspace_id: workspace,
        sender: team_actor,
        target: MessageTarget::Actor(
            ActorId::new("mixed-actor").expect("same valid logical actor id"),
        ),
        team_id: Some(team_id),
        run_id: Some(run_id),
        request_id: Some(request_id),
        policy_revision: supervisor.policy_revision(),
        primary_epoch: supervisor.primary_epoch(),
        team_epoch: Some(team_epoch),
        assignment_epoch: None,
        sent_at: TimestampMillis(3),
        message: Message::RunControl(RunControl {
            action: RunControlAction::Pause,
        }),
    };
    assert_eq!(
        supervisor.apply(privileged),
        Err(CoreError::Unauthorized("control run"))
    );

    let snapshot = supervisor.snapshot();
    assert_eq!(
        Supervisor::from_snapshot(snapshot.clone())
            .expect("causal replay distinguishes capability from lease topology")
            .snapshot(),
        snapshot
    );
}

#[test]
fn empty_configured_role_cannot_request_a_legacy_consultation() {
    let workspace = WorkspaceId::new("empty-capability-workspace").expect("valid id");
    let team_id = TeamId::new("research-team").expect("valid id");
    let target_team = TeamId::new("consultation-target").expect("valid id");
    let mut supervisor = Supervisor::new(workspace.clone(), PolicyRevision::INITIAL);
    supervisor
        .activate_primary(ActorId::new("legacy-primary").expect("valid id"))
        .expect("legacy primary activates");
    supervisor
        .create_team_with_profile(
            team_id.clone(),
            team_profile("research", "research", 1, "first_healthy"),
        )
        .expect("profiled team exists");
    supervisor
        .create_team(target_team.clone())
        .expect("target team exists");
    let research = supervisor
        .register_implementation_with_profile(
            &team_id,
            ActorId::new("research-one").expect("valid id"),
            ActorRole::new("research").expect("valid role"),
            actor_profile("research", &[]),
        )
        .expect("empty capability profile can be persisted");
    let consultation_id = MessageId::new("research-consultation").expect("valid id");
    let consultation = Envelope {
        protocol_version: 1,
        message_id: consultation_id.clone(),
        workspace_id: workspace,
        sender: research,
        target: MessageTarget::Team(target_team.clone()),
        team_id: Some(team_id.clone()),
        run_id: None,
        request_id: None,
        policy_revision: supervisor.policy_revision(),
        primary_epoch: supervisor.primary_epoch(),
        team_epoch: Some(supervisor.team(&team_id).expect("team exists").epoch),
        assignment_epoch: None,
        sent_at: TimestampMillis(1),
        message: Message::ConsultationRequest(ConsultationRequest {
            consultation_id,
            target_team_id: target_team,
            subject: "legacy privilege fallback".to_owned(),
            question: "does an empty profile inherit legacy privileges?".to_owned(),
            evidence: Vec::new(),
        }),
    };

    assert_eq!(
        supervisor.apply(consultation),
        Err(CoreError::Unauthorized("request consultation"))
    );
}

#[test]
fn configured_team_profiles_persist_without_enforcing_r4_policy() {
    let workspace = WorkspaceId::new("team-profile-workspace").expect("valid id");
    let team_id = TeamId::new("research-team").expect("valid id");
    let actor_id = ActorId::new("research-one").expect("valid id");
    let mut supervisor = Supervisor::new(workspace.clone(), PolicyRevision::INITIAL);
    let selected_team_profile = team_profile("research", "research", 0, "least_wip");
    supervisor
        .create_team_with_profile(team_id.clone(), selected_team_profile.clone())
        .expect("zero desired instances is declarative and valid");
    let research_profile = actor_profile("research", &[]);
    let research = supervisor
        .register_implementation_with_profile(
            &team_id,
            actor_id.clone(),
            ActorRole::new("research").expect("valid role"),
            research_profile.clone(),
        )
        .expect("non-executor team profile can be persisted before R4");
    assert_eq!(
        supervisor.register_implementation_with_profile(
            &team_id,
            actor_id.clone(),
            ActorRole::new("research").expect("valid role"),
            research_profile,
        ),
        Ok(research.clone())
    );
    assert_eq!(
        supervisor.register_implementation_with_profile(
            &team_id,
            actor_id.clone(),
            ActorRole::new("research").expect("valid role"),
            actor_profile("other-profile", &[]),
        ),
        Err(CoreError::AlreadyExists("team actor profile"))
    );

    let primary = supervisor
        .activate_primary(ActorId::new("legacy-primary").expect("valid id"))
        .expect("legacy primary remains compatible");
    let request = Envelope {
        protocol_version: 1,
        message_id: MessageId::new("research-assignment").expect("valid id"),
        workspace_id: workspace,
        sender: primary,
        target: MessageTarget::Actor(actor_id),
        team_id: Some(team_id.clone()),
        run_id: Some(RunId::new("research-run").expect("valid id")),
        request_id: Some(RequestId::new("research-request").expect("valid id")),
        policy_revision: supervisor.policy_revision(),
        primary_epoch: supervisor.primary_epoch(),
        team_epoch: Some(supervisor.team(&team_id).expect("team exists").epoch),
        assignment_epoch: None,
        sent_at: TimestampMillis(1),
        message: Message::ImplementationRequest(ImplementationRequest {
            title: "should not assign".to_owned(),
            instructions: "research has no execution capability".to_owned(),
            base_sha: GitSha::new(SHA_0).expect("valid sha"),
            acceptance_criteria: vec!["must be rejected".to_owned()],
            evidence_requirements: Vec::new(),
        }),
    };
    assert_eq!(
        supervisor.apply(request),
        Err(CoreError::Unauthorized("assign request to target actor"))
    );

    let snapshot = supervisor.snapshot();
    let team = snapshot
        .teams
        .iter()
        .find(|team| team.team_id == team_id)
        .expect("team persists");
    assert_eq!(team.profile, Some(selected_team_profile));
    assert_eq!(
        Supervisor::from_snapshot(snapshot.clone())
            .expect("profiled team restores")
            .snapshot(),
        snapshot
    );
}

#[test]
fn profileless_v01_snapshot_keeps_legacy_authorization_and_shape() {
    let fixture = Fixture::new();
    let snapshot = fixture.supervisor.snapshot();
    assert!(snapshot.actors.iter().all(|actor| actor.profile.is_none()));
    assert!(snapshot.teams.iter().all(|team| team.profile.is_none()));

    let encoded = serde_json::to_value(&snapshot).expect("legacy snapshot serializes");
    assert!(
        encoded["actors"]
            .as_array()
            .expect("actors array")
            .iter()
            .all(|actor| actor.get("profile").is_none())
    );
    assert!(
        encoded["teams"]
            .as_array()
            .expect("teams array")
            .iter()
            .all(|team| team.get("profile").is_none())
    );
    let decoded: DomainSnapshot = serde_json::from_value(encoded).expect("v0.1 JSON decodes");
    let restored = Supervisor::from_snapshot(decoded).expect("v0.1 snapshot restores");
    assert!(
        restored
            .actor(&fixture.primary.actor_id)
            .expect("primary exists")
            .has_capability(HUMAN_FACING_PRIMARY_CAPABILITY)
    );
    assert!(
        restored
            .actor(&fixture.implementation.actor_id)
            .expect("implementation exists")
            .has_capability(IMPLEMENTATION_EXECUTION_CAPABILITY)
    );
}
