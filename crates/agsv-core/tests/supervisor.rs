use std::collections::BTreeSet;

use agsv_core::{AckOutcome, ApplyOutcome, ArchivedRequestReference, CoreError, Supervisor};
use agsv_protocol::{
    Acknowledgement, ActorEpoch, ActorId, ActorProfileName, ActorProfileSnapshot, ActorRef,
    ActorRole, ActorStatus, AssignmentEpoch, AssignmentPolicyId, BlockerNotice, Cancellation,
    Candidate, CandidateReady, CapabilityId, CausalMessage, ConflictNotice, ConsultationRequest,
    ConsultationResponse, DecisionId, DeliveryRecipient, DeliveryRetirementReason,
    DependencyNotice, DomainSnapshot, Envelope, GitSha, HUMAN_FACING_PRIMARY_CAPABILITY,
    HandoffAcceptance, HandoffId, HandoffOffer, HistoryCheckpoint,
    IMPLEMENTATION_EXECUTION_CAPABILITY, ImplementationRequest, IntegrationAuthorization,
    IntegrationComplete, MAX_AUDIT_EVENTS, MAX_DELIVERIES, MAX_DOMAIN_ENTITIES, Message, MessageId,
    MessageKind, MessageTarget, PayloadDigest, PolicyRevision, PrimaryDirective, PrimaryEpoch,
    ProgressUpdate, RequestId, RequestStatus, ReviewDecision, ReviewVerdict, RunControl,
    RunControlAction, RunId, RunStatus, TeamId, TeamProfileName, TeamProfileSnapshot, TeamStatus,
    TimestampMillis, UndeliverableRecipient, WorkspaceId,
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

    fn new_profiled() -> Self {
        let workspace = WorkspaceId::new("profiled-workspace").expect("valid id");
        let team = TeamId::new("profiled-team").expect("valid id");
        let mut supervisor = Supervisor::new(workspace.clone(), PolicyRevision::INITIAL);
        let primary = supervisor
            .activate_primary(ActorId::new("profiled-primary").expect("valid id"))
            .expect("primary activates");
        supervisor
            .create_team_with_profile(
                team.clone(),
                team_profile("implementation", "implementation", 1, "first_healthy"),
            )
            .expect("profiled team creates");
        let implementation = supervisor
            .register_implementation_with_profile(
                &team,
                ActorId::new("profiled-implementation").expect("valid id"),
                ActorRole::Implementation,
                actor_profile("implementation", &[IMPLEMENTATION_EXECUTION_CAPABILITY]),
            )
            .expect("profiled implementation registers");
        Self {
            supervisor,
            primary,
            implementation,
            workspace,
            team,
            request: RequestId::new("profiled-request").expect("valid id"),
            run: RunId::new("profiled-run").expect("valid id"),
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
            created_by_profile: None,
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

fn directive(decision: &str, rationale: &str) -> Message {
    Message::Directive(PrimaryDirective {
        decision: decision.to_owned(),
        rationale: rationale.to_owned(),
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

fn request_delivery_mut(snapshot: &mut DomainSnapshot) -> &mut agsv_protocol::DeliverySnapshot {
    snapshot
        .deliveries
        .iter_mut()
        .find(|delivery| {
            matches!(
                delivery.causal,
                agsv_protocol::CausalMessage::ImplementationRequest { .. }
            )
        })
        .expect("Actor-target request delivery exists")
}

fn progress_delivery_mut(snapshot: &mut DomainSnapshot) -> &mut agsv_protocol::DeliverySnapshot {
    snapshot
        .deliveries
        .iter_mut()
        .find(|delivery| matches!(delivery.causal, agsv_protocol::CausalMessage::Progress))
        .expect("Primary-target progress delivery exists")
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
            .unacknowledged_message_ids_for(&fixture.implementation)
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
            .unacknowledged_message_ids_for(&fixture.implementation)
            .expect("actor is current")
            .is_empty()
    );
    assert_eq!(fixture.supervisor.audit_events().len(), 2);
}

#[test]
fn request_scoped_directive_is_a_durable_decision_with_generic_acknowledgement() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let envelope = fixture.primary_envelope(
        "request-directive",
        directive(
            "keep the protocol kind provider-neutral",
            "runtime-specific names belong behind adapters",
        ),
    );

    assert_eq!(
        fixture.supervisor.apply(envelope.clone()),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(
        fixture.supervisor.apply(envelope.clone()),
        Ok(ApplyOutcome::Duplicate)
    );
    let delivery = fixture
        .supervisor
        .delivery(&envelope.message_id)
        .expect("directive delivery exists");
    assert_eq!(delivery.message_kind, MessageKind::Directive);
    assert_eq!(delivery.causal, CausalMessage::Directive);
    assert_eq!(
        delivery.required_recipients,
        std::collections::BTreeSet::from([DeliveryRecipient::Actor(
            fixture.implementation.actor_id.clone(),
        )])
    );
    assert_eq!(
        fixture.supervisor.request(&fixture.request).unwrap().status,
        RequestStatus::Assigned,
        "a directive records a decision without changing request lifecycle"
    );

    let pending = fixture.supervisor.take_pending_bulk_content();
    let directive_content = pending
        .iter()
        .find(|content| content.message_id == envelope.message_id)
        .expect("full directive content is retained for archive/read surfaces");
    assert_eq!(directive_content.message, envelope.message);
    assert_eq!(
        fixture.supervisor.acknowledge(Acknowledgement {
            workspace_id: fixture.workspace.clone(),
            message_id: envelope.message_id.clone(),
            actor: fixture.implementation.clone(),
            acknowledged_at: TimestampMillis(4),
        }),
        Ok(AckOutcome::Acknowledged)
    );
    assert_eq!(
        fixture.supervisor.acknowledge(Acknowledgement {
            workspace_id: fixture.workspace.clone(),
            message_id: envelope.message_id.clone(),
            actor: fixture.implementation.clone(),
            acknowledged_at: TimestampMillis(4),
        }),
        Ok(AckOutcome::Duplicate)
    );

    let snapshot = fixture.supervisor.snapshot();
    let restored = Supervisor::from_snapshot(snapshot).expect("directive causal history restores");
    assert_eq!(
        restored
            .delivery(&envelope.message_id)
            .expect("restored directive exists")
            .causal,
        CausalMessage::Directive
    );

    let mut conflicting = envelope;
    let Message::Directive(changed) = &mut conflicting.message else {
        unreachable!("fixture is a directive")
    };
    changed.rationale.push_str(" with a changed rationale");
    assert_eq!(
        fixture.supervisor.apply(conflicting),
        Err(CoreError::DuplicateMessageConflict)
    );
}

#[test]
fn team_scoped_directive_reaches_a_stale_current_team_and_archives_after_ack() {
    let mut fixture = Fixture::new();
    fixture
        .supervisor
        .set_actor_status(&fixture.implementation, ActorStatus::Stale)
        .expect("implementation may become quiet");
    let message_id = MessageId::new("team-directive").expect("valid id");
    let envelope = Envelope {
        protocol_version: 1,
        message_id: message_id.clone(),
        workspace_id: fixture.workspace.clone(),
        sender: fixture.primary.clone(),
        target: MessageTarget::Team(fixture.team.clone()),
        team_id: Some(fixture.team.clone()),
        run_id: None,
        request_id: None,
        policy_revision: fixture.supervisor.policy_revision(),
        primary_epoch: fixture.supervisor.primary_epoch(),
        team_epoch: Some(
            fixture
                .supervisor
                .team(&fixture.team)
                .expect("team exists")
                .epoch,
        ),
        assignment_epoch: None,
        sent_at: TimestampMillis(4),
        message: directive(
            "reserve control schema version 7",
            "the parallel retention track owns version 6",
        ),
    };

    assert_eq!(
        fixture.supervisor.apply(envelope.clone()),
        Ok(ApplyOutcome::Applied),
        "durable directives do not require a live recipient"
    );
    assert_eq!(
        fixture
            .supervisor
            .delivery(&message_id)
            .expect("directive delivery exists")
            .required_recipients,
        std::collections::BTreeSet::from([DeliveryRecipient::Actor(
            fixture.implementation.actor_id.clone(),
        )]),
        "a stale current actor remains a frozen acknowledgement recipient"
    );
    assert!(matches!(
        fixture
            .supervisor
            .unacknowledged_message_ids_for(&fixture.implementation),
        Err(CoreError::ActorNotHealthy(_))
    ));
    fixture
        .supervisor
        .heartbeat(&fixture.implementation, TimestampMillis(5))
        .expect("quiet current actor may return");
    assert!(
        fixture
            .supervisor
            .unacknowledged_message_ids_for(&fixture.implementation)
            .expect("healthy actor can read its inbox")
            .contains(&message_id)
    );
    assert_eq!(
        fixture.supervisor.acknowledge(Acknowledgement {
            workspace_id: fixture.workspace.clone(),
            message_id: message_id.clone(),
            actor: fixture.implementation.clone(),
            acknowledged_at: TimestampMillis(6),
        }),
        Ok(AckOutcome::Acknowledged)
    );

    let snapshot = fixture.supervisor.snapshot();
    assert_eq!(snapshot.deliveries.len(), 1);
    assert!(snapshot.deliveries[0].retired);
    assert_eq!(snapshot.deliveries[0].causal, CausalMessage::Directive);
    assert_eq!(
        fixture
            .supervisor
            .validate_archived_requestless_history(&snapshot.deliveries, &snapshot.audit_events),
        Ok(())
    );
    Supervisor::from_snapshot(snapshot).expect("retired team directive restores");
}

#[test]
fn team_directive_waits_for_replacement_of_a_stopped_desired_slot() {
    let mut fixture = Fixture::new_profiled();
    fixture
        .supervisor
        .set_actor_status(&fixture.implementation, ActorStatus::Stopped)
        .expect("desired actor may stop before a directive arrives");
    let message_id = MessageId::new("stopped-slot-directive").expect("valid message");
    let envelope = Envelope {
        protocol_version: 1,
        message_id: message_id.clone(),
        workspace_id: fixture.workspace.clone(),
        sender: fixture.primary.clone(),
        target: MessageTarget::Team(fixture.team.clone()),
        team_id: Some(fixture.team.clone()),
        run_id: None,
        request_id: None,
        policy_revision: fixture.supervisor.policy_revision(),
        primary_epoch: fixture.supervisor.primary_epoch(),
        team_epoch: Some(
            fixture
                .supervisor
                .team(&fixture.team)
                .expect("team exists")
                .epoch,
        ),
        assignment_epoch: None,
        sent_at: TimestampMillis(4),
        message: directive(
            "apply after relaunch",
            "the desired logical slot still exists while its generation is stopped",
        ),
    };
    assert_eq!(
        fixture.supervisor.apply(envelope),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(
        fixture
            .supervisor
            .delivery(&message_id)
            .expect("directive delivery exists")
            .required_recipients,
        BTreeSet::from([DeliveryRecipient::Actor(
            fixture.implementation.actor_id.clone(),
        )])
    );

    let replacement = fixture
        .supervisor
        .replace_implementation(&fixture.team, fixture.implementation.actor_id.clone())
        .expect("stopped desired slot is replaced");
    assert_ne!(replacement, fixture.implementation);
    assert!(
        fixture
            .supervisor
            .unacknowledged_message_ids_for(&replacement)
            .expect("replacement reads its logical slot inbox")
            .contains(&message_id)
    );
    assert_eq!(
        fixture.supervisor.acknowledge(Acknowledgement {
            workspace_id: fixture.workspace,
            message_id: message_id.clone(),
            actor: replacement,
            acknowledged_at: TimestampMillis(5),
        }),
        Ok(AckOutcome::Acknowledged)
    );
    assert!(
        fixture
            .supervisor
            .delivery(&message_id)
            .expect("directive remains in compact history")
            .retired
    );
}

#[test]
fn team_close_keeps_unread_directive_as_an_explicit_blocker() {
    let mut fixture = Fixture::new_profiled();
    let message_id = MessageId::new("close-disposed-directive").expect("valid message");
    let envelope = Envelope {
        protocol_version: 1,
        message_id: message_id.clone(),
        workspace_id: fixture.workspace.clone(),
        sender: fixture.primary.clone(),
        target: MessageTarget::Team(fixture.team.clone()),
        team_id: Some(fixture.team.clone()),
        run_id: None,
        request_id: None,
        policy_revision: fixture.supervisor.policy_revision(),
        primary_epoch: fixture.supervisor.primary_epoch(),
        team_epoch: Some(
            fixture
                .supervisor
                .team(&fixture.team)
                .expect("team exists")
                .epoch,
        ),
        assignment_epoch: None,
        sent_at: TimestampMillis(4),
        message: directive(
            "do not close before acknowledgement",
            "the decision still expects future team action",
        ),
    };
    assert_eq!(
        fixture.supervisor.apply(envelope),
        Ok(ApplyOutcome::Applied)
    );
    fixture
        .supervisor
        .set_team_status(&fixture.team, TeamStatus::Closing)
        .expect("team starts closing");
    assert_eq!(
        fixture
            .supervisor
            .team_close_blocking_message_ids(&fixture.team),
        vec![message_id.clone()]
    );
    assert_eq!(
        fixture
            .supervisor
            .retire_obsolete_team_recipients(&fixture.team)
            .expect("only obsolete outcomes are disposed"),
        Vec::<MessageId>::new()
    );
    let delivery = fixture
        .supervisor
        .delivery(&message_id)
        .expect("action-requiring directive remains live");
    assert!(!delivery.retired);
    assert!(delivery.undeliverable_recipients.is_empty());
    assert!(
        fixture
            .supervisor
            .pending_acknowledgement_message_ids_for(&fixture.implementation.actor_id)
            .contains(&message_id)
    );

    let mut forged = fixture.supervisor.snapshot();
    forged
        .teams
        .iter_mut()
        .find(|team| team.team_id == fixture.team)
        .expect("team exists")
        .status = TeamStatus::Closed;
    let delivery = forged
        .deliveries
        .iter_mut()
        .find(|delivery| delivery.envelope.message_id == message_id)
        .expect("directive exists");
    delivery.undeliverable_recipients = vec![UndeliverableRecipient {
        recipient: DeliveryRecipient::Actor(fixture.implementation.actor_id.clone()),
        reason: DeliveryRetirementReason::TeamClosed {
            team_id: fixture.team.clone(),
        },
    }];
    delivery.retired = true;
    assert_invalid_snapshot(forged);
}

#[test]
fn primary_directive_enforces_authority_and_scope_fences() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let request_directive = fixture.primary_envelope(
        "fenced-directive",
        directive(
            "use one close predicate",
            "uniform policy avoids special cases",
        ),
    );

    let mut unauthorized = request_directive.clone();
    unauthorized.message_id = MessageId::new("unauthorized-directive").expect("valid id");
    unauthorized.sender = fixture.implementation.clone();
    assert!(matches!(
        fixture.supervisor.apply(unauthorized),
        Err(CoreError::Unauthorized("issue Primary directive"))
    ));

    let mut wrong_target = request_directive.clone();
    wrong_target.message_id = MessageId::new("wrong-target-directive").expect("valid id");
    wrong_target.target = MessageTarget::Primary;
    assert_eq!(
        fixture.supervisor.apply(wrong_target),
        Err(CoreError::WrongTarget)
    );

    let mut stale_policy = request_directive.clone();
    stale_policy.message_id = MessageId::new("stale-policy-directive").expect("valid id");
    stale_policy.policy_revision = PolicyRevision::new(2).expect("valid policy revision");
    assert!(matches!(
        fixture.supervisor.apply(stale_policy),
        Err(CoreError::StalePolicyRevision { .. })
    ));

    let mut stale_primary = request_directive.clone();
    stale_primary.message_id = MessageId::new("stale-primary-directive").expect("valid id");
    stale_primary.primary_epoch = PrimaryEpoch::new(2).expect("valid Primary epoch");
    assert!(matches!(
        fixture.supervisor.apply(stale_primary),
        Err(CoreError::StalePrimaryEpoch { .. })
    ));

    let mut stale_actor = request_directive.clone();
    stale_actor.message_id = MessageId::new("stale-actor-directive").expect("valid id");
    stale_actor.sender.actor_epoch = ActorEpoch::new(2).expect("valid actor epoch");
    assert!(matches!(
        fixture.supervisor.apply(stale_actor),
        Err(CoreError::StaleActorEpoch { .. })
    ));

    let mut unknown_request = request_directive.clone();
    unknown_request.message_id = MessageId::new("unknown-request-directive").expect("valid id");
    unknown_request.request_id = Some(RequestId::new("request-missing").expect("valid id"));
    assert!(matches!(
        fixture.supervisor.apply(unknown_request),
        Err(CoreError::UnknownRequest(_))
    ));

    let mut stale_team = request_directive;
    stale_team.message_id = MessageId::new("stale-team-directive").expect("valid id");
    fixture
        .supervisor
        .replace_implementation(&fixture.team, fixture.implementation.actor_id.clone())
        .expect("replacement advances actor, assignment, and team fences");
    assert!(matches!(
        fixture.supervisor.apply(stale_team),
        Err(CoreError::StaleTeamEpoch { .. })
    ));
}

#[test]
fn zero_capacity_team_cannot_accept_or_replay_a_primary_directive() {
    let mut fixture = Fixture::new_profiled();
    fixture.send_request();
    let directive_envelope = fixture.primary_envelope(
        "profiled-directive",
        directive(
            "retain one recipient slot",
            "a durable decision must remain acknowledgeable",
        ),
    );
    assert_eq!(
        fixture.supervisor.apply(directive_envelope),
        Ok(ApplyOutcome::Applied)
    );

    let mut zero_capacity = fixture.supervisor.snapshot();
    zero_capacity
        .teams
        .iter_mut()
        .find(|team| team.team_id == fixture.team)
        .expect("profiled team exists")
        .profile
        .as_mut()
        .expect("profile persists")
        .desired_instances = 0;
    assert_invalid_snapshot(zero_capacity);

    let workspace = WorkspaceId::new("zero-capacity-directive").expect("valid workspace");
    let team_id = TeamId::new("zero-capacity-team").expect("valid team");
    let mut supervisor = Supervisor::new(workspace.clone(), PolicyRevision::INITIAL);
    let primary = supervisor
        .activate_primary(ActorId::new("zero-capacity-primary").expect("valid actor"))
        .expect("Primary activates");
    supervisor
        .create_team_with_profile(
            team_id.clone(),
            team_profile("disabled", "implementation", 0, "first_healthy"),
        )
        .expect("zero capacity is a valid team intent");
    let envelope = Envelope {
        protocol_version: 1,
        message_id: MessageId::new("zero-capacity-directive").expect("valid message"),
        workspace_id: workspace,
        sender: primary,
        target: MessageTarget::Team(team_id.clone()),
        team_id: Some(team_id.clone()),
        run_id: None,
        request_id: None,
        policy_revision: supervisor.policy_revision(),
        primary_epoch: supervisor.primary_epoch(),
        team_epoch: Some(supervisor.team(&team_id).expect("team exists").epoch),
        assignment_epoch: None,
        sent_at: TimestampMillis(1),
        message: directive("do not queue", "there is no acknowledgement capacity"),
    };
    assert_eq!(
        supervisor.apply(envelope),
        Err(CoreError::Unauthorized("direct zero-capacity team"))
    );
}

#[test]
fn team_directive_replay_rejects_empty_or_surplus_recipient_sets() {
    let mut fixture = Fixture::new_profiled();
    let message_id = MessageId::new("recipient-fenced-directive").expect("valid message");
    let envelope = Envelope {
        protocol_version: 1,
        message_id: message_id.clone(),
        workspace_id: fixture.workspace.clone(),
        sender: fixture.primary.clone(),
        target: MessageTarget::Team(fixture.team.clone()),
        team_id: Some(fixture.team.clone()),
        run_id: None,
        request_id: None,
        policy_revision: fixture.supervisor.policy_revision(),
        primary_epoch: fixture.supervisor.primary_epoch(),
        team_epoch: Some(
            fixture
                .supervisor
                .team(&fixture.team)
                .expect("team exists")
                .epoch,
        ),
        assignment_epoch: None,
        sent_at: TimestampMillis(4),
        message: directive(
            "freeze the desired logical slot",
            "archive replay must not invent surplus recipients",
        ),
    };
    assert_eq!(
        fixture.supervisor.apply(envelope),
        Ok(ApplyOutcome::Applied)
    );
    let snapshot = fixture.supervisor.snapshot();

    let mut empty = snapshot.clone();
    empty
        .deliveries
        .iter_mut()
        .find(|delivery| delivery.envelope.message_id == message_id)
        .expect("directive exists")
        .required_recipients
        .clear();
    assert_invalid_snapshot(empty);

    let surplus_id = ActorId::new("profiled-implementation-surplus").expect("valid actor");
    let mut surplus = snapshot;
    let mut surplus_actor = surplus
        .actors
        .iter()
        .find(|actor| actor.actor_id == fixture.implementation.actor_id)
        .expect("desired actor exists")
        .clone();
    surplus_actor.actor_id = surplus_id.clone();
    surplus.actors.push(surplus_actor);
    surplus
        .teams
        .iter_mut()
        .find(|team| team.team_id == fixture.team)
        .expect("team exists")
        .actors
        .push(surplus_id.clone());
    surplus
        .deliveries
        .iter_mut()
        .find(|delivery| delivery.envelope.message_id == message_id)
        .expect("directive exists")
        .required_recipients = BTreeSet::from([DeliveryRecipient::Actor(surplus_id)]);
    assert_invalid_snapshot(surplus);
}

#[test]
fn archived_retry_classifiers_preserve_exact_message_and_ack_semantics() {
    let mut fixture = Fixture::new();
    let envelope = fixture.request_envelope("archived-retry");
    assert_eq!(
        fixture.supervisor.apply(envelope.clone()),
        Ok(ApplyOutcome::Applied)
    );
    let acknowledgement = Acknowledgement {
        workspace_id: fixture.workspace.clone(),
        message_id: envelope.message_id.clone(),
        actor: fixture.implementation.clone(),
        acknowledged_at: TimestampMillis(4),
    };
    assert_eq!(
        fixture.supervisor.acknowledge(acknowledgement.clone()),
        Ok(AckOutcome::Acknowledged)
    );
    assert_eq!(
        fixture.supervisor.apply(fixture.primary_envelope(
            "archive-retry-cancellation",
            Message::Cancellation(Cancellation {
                reason: "make request history archivable".to_owned(),
            }),
        )),
        Ok(ApplyOutcome::Applied)
    );
    let archived = fixture
        .supervisor
        .snapshot()
        .deliveries
        .into_iter()
        .find(|delivery| delivery.envelope.message_id == envelope.message_id)
        .expect("retired request delivery exists");
    assert!(archived.retired);
    assert_eq!(
        fixture
            .supervisor
            .classify_archived_retry(&envelope, &archived),
        Ok(ApplyOutcome::Duplicate)
    );
    let mut changed_message = envelope;
    let Message::ImplementationRequest(specification) = &mut changed_message.message else {
        unreachable!("fixture request")
    };
    specification.instructions.push_str(" changed");
    assert_eq!(
        fixture
            .supervisor
            .classify_archived_retry(&changed_message, &archived),
        Err(CoreError::DuplicateMessageConflict)
    );
    assert_eq!(
        fixture
            .supervisor
            .classify_archived_ack(&acknowledgement, &archived),
        Ok(AckOutcome::Duplicate)
    );
    let mut changed_ack = acknowledgement;
    changed_ack.acknowledged_at = TimestampMillis(5);
    assert_eq!(
        fixture
            .supervisor
            .classify_archived_ack(&changed_ack, &archived),
        Err(CoreError::DuplicateAcknowledgementConflict)
    );
}

#[test]
fn archived_terminal_cycle_validator_replays_compact_provenance() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    assert_eq!(
        fixture.supervisor.acknowledge(Acknowledgement {
            workspace_id: fixture.workspace.clone(),
            message_id: MessageId::new("create-request").expect("valid id"),
            actor: fixture.implementation.clone(),
            acknowledged_at: TimestampMillis(4),
        }),
        Ok(AckOutcome::Acknowledged)
    );
    let cancellation = fixture.primary_envelope(
        "archived-cycle-cancel",
        Message::Cancellation(Cancellation {
            reason: "finish a bounded archived cycle".to_owned(),
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(cancellation.clone()),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(
        fixture.supervisor.acknowledge(Acknowledgement {
            workspace_id: fixture.workspace.clone(),
            message_id: cancellation.message_id,
            actor: fixture.implementation.clone(),
            acknowledged_at: TimestampMillis(5),
        }),
        Ok(AckOutcome::Acknowledged)
    );

    let snapshot = fixture.supervisor.snapshot();
    let request = snapshot.requests.first().expect("request exists");
    let run = snapshot.runs.first().expect("run exists");
    let deliveries = snapshot
        .deliveries
        .iter()
        .filter(|delivery| delivery.envelope.request_id.as_ref() == Some(&request.request_id))
        .cloned()
        .collect::<Vec<_>>();
    let message_ids = deliveries
        .iter()
        .map(|delivery| delivery.envelope.message_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let audit = snapshot
        .audit_events
        .iter()
        .filter(|event| match &event.kind {
            agsv_protocol::AuditEventKind::MessageAccepted { message_id, .. }
            | agsv_protocol::AuditEventKind::MessageAcknowledged { message_id, .. } => {
                message_ids.contains(message_id)
            }
        })
        .cloned()
        .collect::<Vec<_>>();
    assert!(deliveries.iter().all(|delivery| delivery.retired));
    assert_eq!(
        fixture
            .supervisor
            .validate_archived_terminal_cycle(request, run, &deliveries, &audit, &[],),
        Ok(())
    );

    let mut forged_request = request.clone();
    forged_request.specification.payload_digest =
        PayloadDigest::new("f".repeat(64)).expect("valid digest");
    assert!(matches!(
        fixture.supervisor.validate_archived_terminal_cycle(
            &forged_request,
            run,
            &deliveries,
            &audit,
            &[],
        ),
        Err(CoreError::InvalidSnapshot { .. })
    ));
    assert!(matches!(
        fixture.supervisor.validate_archived_terminal_cycle(
            request,
            run,
            &deliveries,
            &audit[..audit.len() - 1],
            &[],
        ),
        Err(CoreError::InvalidSnapshot { .. })
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn archived_terminal_cycle_validates_external_dependency_creation_order() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let provider_team = TeamId::new("dependency-provider-team").expect("valid id");
    fixture
        .supervisor
        .create_team(provider_team.clone())
        .expect("team creates");
    let provider = fixture
        .supervisor
        .register_implementation(
            &provider_team,
            ActorId::new("dependency-provider").expect("valid id"),
        )
        .expect("provider registers");
    let provider_request_id = RequestId::new("provider-request").expect("valid id");
    let provider_run_id = RunId::new("provider-run").expect("valid id");
    let mut provider_request = fixture.request_envelope("create-provider-request");
    provider_request.target = MessageTarget::Actor(provider.actor_id.clone());
    provider_request.team_id = Some(provider_team.clone());
    provider_request.team_epoch = Some(
        fixture
            .supervisor
            .team(&provider_team)
            .expect("team exists")
            .epoch,
    );
    provider_request.request_id = Some(provider_request_id.clone());
    provider_request.run_id = Some(provider_run_id);
    assert_eq!(
        fixture.supervisor.apply(provider_request),
        Ok(ApplyOutcome::Applied)
    );

    let mut dependency = fixture.implementation_envelope(
        "archived-dependency",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::DependencyNotice(DependencyNotice {
            blocked_request_id: fixture.request.clone(),
            depends_on_request_id: provider_request_id.clone(),
            provider_team_id: provider_team.clone(),
            description: "requires provider output".to_owned(),
        }),
    );
    dependency.target = MessageTarget::Team(provider_team.clone());
    assert_eq!(
        fixture.supervisor.apply(dependency.clone()),
        Ok(ApplyOutcome::Applied)
    );
    let cancellation = fixture.primary_envelope(
        "cancel-dependent-request",
        Message::Cancellation(Cancellation {
            reason: "close dependent cycle".to_owned(),
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(cancellation.clone()),
        Ok(ApplyOutcome::Applied)
    );
    for (message_id, actor, acknowledged_at) in [
        (
            MessageId::new("create-request").expect("valid id"),
            fixture.implementation.clone(),
            TimestampMillis(5),
        ),
        (dependency.message_id, provider, TimestampMillis(6)),
        (
            cancellation.message_id,
            fixture.implementation.clone(),
            TimestampMillis(7),
        ),
    ] {
        assert_eq!(
            fixture.supervisor.acknowledge(Acknowledgement {
                workspace_id: fixture.workspace.clone(),
                message_id,
                actor,
                acknowledged_at,
            }),
            Ok(AckOutcome::Acknowledged)
        );
    }

    let snapshot = fixture.supervisor.snapshot();
    let request = snapshot
        .requests
        .iter()
        .find(|request| request.request_id == fixture.request)
        .expect("archived request exists");
    let run = snapshot
        .runs
        .iter()
        .find(|run| run.run_id == fixture.run)
        .expect("archived run exists");
    let deliveries = snapshot
        .deliveries
        .iter()
        .filter(|delivery| delivery.envelope.request_id.as_ref() == Some(&fixture.request))
        .cloned()
        .collect::<Vec<_>>();
    let message_ids = deliveries
        .iter()
        .map(|delivery| delivery.envelope.message_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let audit = snapshot
        .audit_events
        .iter()
        .filter(|event| {
            message_ids.contains(match &event.kind {
                agsv_protocol::AuditEventKind::MessageAccepted { message_id, .. }
                | agsv_protocol::AuditEventKind::MessageAcknowledged { message_id, .. } => {
                    message_id
                }
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    let creation_audit_sequence = snapshot
        .audit_events
        .iter()
        .find_map(|event| match &event.kind {
            agsv_protocol::AuditEventKind::MessageAccepted { message_id, .. }
                if message_id.as_str() == "create-provider-request" =>
            {
                Some(event.sequence)
            }
            _ => None,
        })
        .expect("provider creation audit exists");
    let reference = ArchivedRequestReference {
        request_id: provider_request_id,
        team_id: provider_team,
        creation_audit_sequence,
    };
    assert_eq!(
        fixture.supervisor.validate_archived_terminal_cycle(
            request,
            run,
            &deliveries,
            &audit,
            std::slice::from_ref(&reference),
        ),
        Ok(())
    );
    assert!(matches!(
        fixture
            .supervisor
            .validate_archived_terminal_cycle(request, run, &deliveries, &audit, &[],),
        Err(CoreError::InvalidSnapshot { .. })
    ));
    let dependency_sequence = audit
        .iter()
        .find_map(|event| match &event.kind {
            agsv_protocol::AuditEventKind::MessageAccepted { message_id, .. }
                if message_id.as_str() == "archived-dependency" =>
            {
                Some(event.sequence)
            }
            _ => None,
        })
        .expect("dependency audit exists");
    let forged_reference = ArchivedRequestReference {
        creation_audit_sequence: dependency_sequence,
        ..reference
    };
    assert!(matches!(
        fixture.supervisor.validate_archived_terminal_cycle(
            request,
            run,
            &deliveries,
            &audit,
            &[forged_reference],
        ),
        Err(CoreError::InvalidSnapshot { .. })
    ));
}

#[test]
fn archived_fence_validator_rejects_regressions_across_independent_groups() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let replacement = fixture
        .supervisor
        .replace_implementation(&fixture.team, fixture.implementation.actor_id.clone())
        .expect("same-id replacement advances actor and team fences");
    let assignment = fixture
        .supervisor
        .request(&fixture.request)
        .and_then(|request| request.assignment.as_ref())
        .expect("request remains assigned")
        .clone();
    let progress = fixture.implementation_envelope(
        "global-fence-progress",
        replacement,
        &fixture.team,
        assignment.epoch,
        progress("validate cross-group fences"),
    );
    assert_eq!(
        fixture.supervisor.apply(progress),
        Ok(ApplyOutcome::Applied)
    );
    let delivery = fixture
        .supervisor
        .snapshot()
        .deliveries
        .into_iter()
        .find(|delivery| delivery.envelope.message_id.as_str() == "global-fence-progress")
        .expect("progress delivery exists");

    let mut actor_regression = fixture.supervisor.archived_fence_validator();
    actor_regression
        .validate_next(1, &delivery)
        .expect("current actor and team fences validate");
    let mut stale_actor = delivery.clone();
    stale_actor.envelope.sender.actor_epoch = ActorEpoch::INITIAL;
    assert!(matches!(
        actor_regression.validate_next(2, &stale_actor),
        Err(CoreError::InvalidSnapshot { .. })
    ));

    let mut team_regression = fixture.supervisor.archived_fence_validator();
    team_regression
        .validate_next(1, &delivery)
        .expect("current team fence validates");
    let mut stale_team = delivery;
    stale_team.envelope.team_epoch = Some(agsv_protocol::TeamEpoch::INITIAL);
    assert!(matches!(
        team_regression.validate_next(2, &stale_team),
        Err(CoreError::InvalidSnapshot { .. })
    ));

    let mut primary_fixture = Fixture::new();
    let old_request = primary_fixture.request_envelope("old-primary-request");
    assert_eq!(
        primary_fixture.supervisor.apply(old_request),
        Ok(ApplyOutcome::Applied)
    );
    let current_primary = primary_fixture
        .supervisor
        .activate_primary(ActorId::new("replacement-primary").expect("valid id"))
        .expect("Primary replacement activates");
    let mut current_request = primary_fixture.request_envelope("new-primary-request");
    current_request.sender = current_primary;
    current_request.primary_epoch = primary_fixture.supervisor.primary_epoch();
    current_request.request_id = Some(RequestId::new("new-primary-request").expect("valid id"));
    current_request.run_id = Some(RunId::new("new-primary-run").expect("valid id"));
    assert_eq!(
        primary_fixture.supervisor.apply(current_request),
        Ok(ApplyOutcome::Applied)
    );
    let snapshot = primary_fixture.supervisor.snapshot();
    let old = snapshot
        .deliveries
        .iter()
        .find(|delivery| delivery.envelope.message_id.as_str() == "old-primary-request")
        .expect("old Primary delivery exists");
    let mut forged_current = snapshot
        .deliveries
        .iter()
        .find(|delivery| delivery.envelope.message_id.as_str() == "new-primary-request")
        .expect("current Primary delivery exists")
        .clone();
    forged_current.envelope.primary_epoch = old.envelope.primary_epoch;
    let mut primary_conflict = primary_fixture.supervisor.archived_fence_validator();
    primary_conflict
        .validate_next(1, old)
        .expect("historical Primary group validates alone");
    assert!(matches!(
        primary_conflict.validate_next(2, &forged_current),
        Err(CoreError::InvalidSnapshot { .. })
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn archived_requestless_validator_requires_a_correlated_consultation_pair() {
    let mut fixture = Fixture::new();
    let provider_team = TeamId::new("archive-provider-team").expect("valid id");
    fixture
        .supervisor
        .create_team(provider_team.clone())
        .expect("team creates");
    let provider = fixture
        .supervisor
        .register_implementation(
            &provider_team,
            ActorId::new("archive-provider").expect("valid id"),
        )
        .expect("provider registers");
    let consultation_id = MessageId::new("archived-consultation").expect("valid id");
    let request = Envelope {
        protocol_version: 1,
        message_id: consultation_id.clone(),
        workspace_id: fixture.workspace.clone(),
        sender: fixture.primary.clone(),
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
            subject: "bounded archive".to_owned(),
            question: "can the pair be replayed independently?".to_owned(),
            evidence: Vec::new(),
        }),
    };
    assert_eq!(fixture.supervisor.apply(request), Ok(ApplyOutcome::Applied));
    assert_eq!(
        fixture.supervisor.acknowledge(Acknowledgement {
            workspace_id: fixture.workspace.clone(),
            message_id: consultation_id.clone(),
            actor: provider.clone(),
            acknowledged_at: TimestampMillis(5),
        }),
        Ok(AckOutcome::Acknowledged)
    );
    let response_id = MessageId::new("archived-consultation-response").expect("valid id");
    let response = Envelope {
        protocol_version: 1,
        message_id: response_id.clone(),
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
        sent_at: TimestampMillis(6),
        message: Message::ConsultationResponse(ConsultationResponse {
            consultation_id,
            responding_team_id: provider_team,
            response: "yes".to_owned(),
            evidence: Vec::new(),
        }),
    };
    assert_eq!(
        fixture.supervisor.apply(response),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(
        fixture.supervisor.acknowledge(Acknowledgement {
            workspace_id: fixture.workspace.clone(),
            message_id: response_id,
            actor: fixture.primary.clone(),
            acknowledged_at: TimestampMillis(7),
        }),
        Ok(AckOutcome::Acknowledged)
    );

    let snapshot = fixture.supervisor.snapshot();
    assert_eq!(
        fixture
            .supervisor
            .validate_archived_requestless_history(&snapshot.deliveries, &snapshot.audit_events),
        Ok(())
    );
    let request_id = snapshot.deliveries[0].envelope.message_id.clone();
    let request_only_deliveries = snapshot
        .deliveries
        .iter()
        .filter(|delivery| delivery.envelope.message_id == request_id)
        .cloned()
        .collect::<Vec<_>>();
    let request_only_audit = snapshot
        .audit_events
        .iter()
        .filter(|event| match &event.kind {
            agsv_protocol::AuditEventKind::MessageAccepted { message_id, .. }
            | agsv_protocol::AuditEventKind::MessageAcknowledged { message_id, .. } => {
                message_id == &request_id
            }
        })
        .cloned()
        .collect::<Vec<_>>();
    assert!(matches!(
        fixture
            .supervisor
            .validate_archived_requestless_history(&request_only_deliveries, &request_only_audit,),
        Err(CoreError::InvalidSnapshot { .. })
    ));
}

#[test]
fn compact_snapshot_excludes_bulk_text_and_restoration_has_no_pending_bulk() {
    const SENTINEL: &str = "sentinel-bulk-text-must-not-enter-domain-snapshot";
    let mut fixture = Fixture::new();
    let mut envelope = fixture.request_envelope("compact-sentinel");
    let Message::ImplementationRequest(specification) = &mut envelope.message else {
        unreachable!("fixture creates an implementation request")
    };
    specification.title = format!("title-{SENTINEL}");
    specification.instructions = format!("instructions-{SENTINEL}");
    specification.acceptance_criteria = vec![format!("criterion-{SENTINEL}")];

    assert_eq!(
        fixture.supervisor.apply(envelope),
        Ok(ApplyOutcome::Applied)
    );
    let snapshot = fixture.supervisor.snapshot();
    let encoded = serde_json::to_string(&snapshot).expect("snapshot serializes");
    assert!(!encoded.contains(SENTINEL));
    assert_eq!(
        snapshot.requests[0].specification.message_id.as_str(),
        "compact-sentinel"
    );
    assert_eq!(
        snapshot.requests[0].specification.payload_digest,
        snapshot.deliveries[0].payload_digest
    );

    let pending = fixture.supervisor.take_pending_bulk_content();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message_id.as_str(), "compact-sentinel");
    assert_eq!(
        pending[0].payload_digest,
        snapshot.deliveries[0].payload_digest
    );
    let Message::ImplementationRequest(specification) = &pending[0].message else {
        panic!("pending bulk retains the accepted wire payload")
    };
    assert!(specification.instructions.contains(SENTINEL));

    let mut restored = Supervisor::from_snapshot(snapshot).expect("compact snapshot restores");
    assert!(restored.take_pending_bulk_content().is_empty());
}

#[test]
fn request_delivery_retires_only_after_acknowledgement_and_terminal_transition() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let request_message_id = MessageId::new("create-request").expect("valid id");
    let request = fixture.request_envelope("create-request");
    assert_eq!(
        fixture.supervisor.acknowledge(Acknowledgement {
            workspace_id: fixture.workspace.clone(),
            message_id: request_message_id.clone(),
            actor: fixture.implementation.clone(),
            acknowledged_at: TimestampMillis(4),
        }),
        Ok(AckOutcome::Acknowledged)
    );
    assert!(
        !fixture
            .supervisor
            .delivery(&request_message_id)
            .expect("request delivery exists")
            .retired,
        "an active request keeps fully acknowledged causal history live"
    );

    let cancellation = fixture.primary_envelope(
        "terminal-cancellation",
        Message::Cancellation(Cancellation {
            reason: "finish the retirement test".to_owned(),
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(cancellation),
        Ok(ApplyOutcome::Applied)
    );
    assert!(
        fixture
            .supervisor
            .delivery(&request_message_id)
            .expect("request delivery remains as compact history")
            .retired
    );
    assert_eq!(
        fixture.supervisor.apply(request.clone()),
        Ok(ApplyOutcome::Duplicate),
        "retired compact history remains an idempotency tombstone"
    );
    let mut conflicting_retry = request;
    let Message::ImplementationRequest(specification) = &mut conflicting_retry.message else {
        unreachable!("fixture creates an implementation request")
    };
    specification.instructions.push_str(" conflict");
    assert_eq!(
        fixture.supervisor.apply(conflicting_retry),
        Err(CoreError::DuplicateMessageConflict)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn retired_team_delivery_freezes_recipients_and_keeps_compact_replay_history() {
    let mut fixture = Fixture::new();
    let provider_team = TeamId::new("frozen-provider-team").expect("valid id");
    fixture
        .supervisor
        .create_team(provider_team.clone())
        .expect("team creates");
    let original_provider = fixture
        .supervisor
        .register_implementation(
            &provider_team,
            ActorId::new("original-provider").expect("valid id"),
        )
        .expect("provider registers");
    let consultation_id = MessageId::new("frozen-consultation").expect("valid id");
    let consultation = Envelope {
        protocol_version: 1,
        message_id: consultation_id.clone(),
        workspace_id: fixture.workspace.clone(),
        sender: fixture.primary.clone(),
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
            subject: "freeze recipient set".to_owned(),
            question: "does later membership reopen this delivery?".to_owned(),
            evidence: Vec::new(),
        }),
    };
    assert_eq!(
        fixture.supervisor.apply(consultation.clone()),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(
        fixture
            .supervisor
            .delivery(&consultation_id)
            .expect("delivery exists")
            .required_recipients,
        [DeliveryRecipient::Actor(original_provider.actor_id.clone())]
            .into_iter()
            .collect()
    );
    assert_eq!(
        fixture.supervisor.acknowledge(Acknowledgement {
            workspace_id: fixture.workspace.clone(),
            message_id: consultation_id.clone(),
            actor: original_provider,
            acknowledged_at: TimestampMillis(5),
        }),
        Ok(AckOutcome::Acknowledged)
    );
    assert!(
        fixture
            .supervisor
            .delivery(&consultation_id)
            .expect("delivery remains archived")
            .retired
    );

    let future_provider = fixture
        .supervisor
        .register_implementation(
            &provider_team,
            ActorId::new("future-provider").expect("valid id"),
        )
        .expect("future provider registers");
    assert!(
        fixture
            .supervisor
            .unacknowledged_message_ids_for(&future_provider)
            .expect("future provider is healthy")
            .is_empty()
    );

    let snapshot = fixture.supervisor.snapshot();
    assert_eq!(snapshot.deliveries.len(), 1);
    assert_eq!(snapshot.audit_events.len(), 2);
    assert!(snapshot.deliveries[0].retired);
    let mut restored = Supervisor::from_snapshot(snapshot).expect("retired history replays");
    assert_eq!(
        restored.apply(consultation.clone()),
        Ok(ApplyOutcome::Duplicate)
    );
    let mut conflict = consultation;
    let Message::ConsultationRequest(request) = &mut conflict.message else {
        unreachable!("consultation payload")
    };
    request.question.push_str(" changed");
    assert_eq!(
        restored.apply(conflict),
        Err(CoreError::DuplicateMessageConflict)
    );
}

#[test]
fn recipientless_live_delivery_and_undisposed_snapshot_are_refused() {
    let mut fixture = Fixture::new();
    let empty_team = TeamId::new("empty-recipient-team").expect("valid id");
    fixture
        .supervisor
        .create_team(empty_team.clone())
        .expect("empty team creates");
    let consultation_id = MessageId::new("empty-recipient-consultation").expect("valid id");
    let consultation = Envelope {
        protocol_version: 1,
        message_id: consultation_id.clone(),
        workspace_id: fixture.workspace.clone(),
        sender: fixture.primary.clone(),
        target: MessageTarget::Team(empty_team.clone()),
        team_id: Some(empty_team.clone()),
        run_id: None,
        request_id: None,
        policy_revision: fixture.supervisor.policy_revision(),
        primary_epoch: fixture.supervisor.primary_epoch(),
        team_epoch: Some(
            fixture
                .supervisor
                .team(&empty_team)
                .expect("team exists")
                .epoch,
        ),
        assignment_epoch: None,
        sent_at: TimestampMillis(4),
        message: Message::ConsultationRequest(ConsultationRequest {
            consultation_id: consultation_id.clone(),
            target_team_id: empty_team.clone(),
            subject: "empty recipient set".to_owned(),
            question: "must this fail closed?".to_owned(),
            evidence: Vec::new(),
        }),
    };
    assert_eq!(
        fixture.supervisor.apply(consultation.clone()),
        Err(CoreError::Unauthorized(
            "deliver message without a durable recipient"
        ))
    );
    assert!(fixture.supervisor.delivery(&consultation_id).is_none());

    let original_actor = fixture
        .supervisor
        .register_implementation(
            &empty_team,
            ActorId::new("original-empty-recipient").expect("valid id"),
        )
        .expect("logical recipient registers");
    assert_eq!(
        fixture.supervisor.apply(consultation),
        Ok(ApplyOutcome::Applied)
    );
    let delivery = fixture
        .supervisor
        .delivery(&consultation_id)
        .expect("delivery exists");
    assert_eq!(
        delivery.required_recipients,
        BTreeSet::from([DeliveryRecipient::Actor(original_actor.actor_id.clone())])
    );
    let mut undisposed_snapshot = fixture.supervisor.snapshot();
    undisposed_snapshot
        .deliveries
        .iter_mut()
        .find(|delivery| delivery.envelope.message_id == consultation_id)
        .expect("delivery exists")
        .required_recipients
        .clear();
    assert_invalid_snapshot(undisposed_snapshot);

    let future_actor = fixture
        .supervisor
        .register_implementation(
            &empty_team,
            ActorId::new("late-empty-recipient").expect("valid id"),
        )
        .expect("future actor registers");
    assert!(
        fixture
            .supervisor
            .unacknowledged_message_ids_for(&future_actor)
            .expect("new live delivery remains frozen to its original recipient")
            .is_empty()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn terminal_team_outcome_has_total_recipient_or_disposition_plan_and_archives() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let candidate = fixture.candidate(SHA_1, fixture.implementation.clone(), fixture.team.clone());
    assert_eq!(
        fixture.submit_candidate("terminal-outcome-candidate", candidate.clone()),
        ApplyOutcome::Applied
    );
    assert_eq!(
        fixture.supervisor.acknowledge(Acknowledgement {
            workspace_id: fixture.workspace.clone(),
            message_id: MessageId::new("terminal-outcome-candidate").expect("valid id"),
            actor: fixture.primary.clone(),
            acknowledged_at: TimestampMillis(4),
        }),
        Ok(AckOutcome::Acknowledged)
    );
    let decision = fixture.review_candidate(
        "terminal-outcome-review",
        "terminal-outcome-decision",
        candidate.clone(),
        ReviewVerdict::Accepted,
    );
    let authorization = fixture.primary_envelope(
        "terminal-outcome-authorization",
        Message::IntegrationAuthorization(IntegrationAuthorization {
            decision_id: decision.decision_id.clone(),
            candidate: candidate.clone(),
            authorized_by: fixture.primary.clone(),
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(authorization),
        Ok(ApplyOutcome::Applied)
    );
    fixture
        .supervisor
        .set_team_status(&fixture.team, TeamStatus::Closing)
        .expect("team starts closing");
    fixture
        .supervisor
        .retire_obsolete_team_recipients(&fixture.team)
        .expect("nonblocking request history receives close dispositions");
    fixture
        .supervisor
        .set_actor_status(&fixture.implementation, ActorStatus::Stopped)
        .expect("logical recipient stops");
    fixture
        .supervisor
        .set_team_status(&fixture.team, TeamStatus::Closed)
        .expect("team closes");

    let closed_snapshot = fixture.supervisor.snapshot();
    for terminal_status in [TeamStatus::Closed, TeamStatus::Retired] {
        for recipient_status in [ActorStatus::Stopped, ActorStatus::Revoked] {
            let mut terminal_snapshot = closed_snapshot.clone();
            terminal_snapshot
                .teams
                .iter_mut()
                .find(|team| team.team_id == fixture.team)
                .expect("team exists")
                .status = terminal_status;
            terminal_snapshot
                .actors
                .iter_mut()
                .find(|actor| actor.actor_id == fixture.implementation.actor_id)
                .expect("actor exists")
                .status = recipient_status;
            let mut supervisor =
                Supervisor::from_snapshot(terminal_snapshot).expect("terminal state restores");
            let message_id = match (terminal_status, recipient_status) {
                (TeamStatus::Closed, ActorStatus::Stopped) => "closed-stopped-integration-complete",
                (TeamStatus::Closed, ActorStatus::Revoked) => "closed-empty-integration-complete",
                (TeamStatus::Retired, ActorStatus::Stopped) => {
                    "retired-stopped-integration-complete"
                }
                (TeamStatus::Retired, ActorStatus::Revoked) => "retired-empty-integration-complete",
                _ => unreachable!("loop contains only terminal compatibility states"),
            };
            let mut complete = fixture.primary_envelope(
                message_id,
                Message::IntegrationComplete(IntegrationComplete {
                    decision_id: decision.decision_id.clone(),
                    candidate: candidate.clone(),
                    evidence: Vec::new(),
                }),
            );
            complete.target = MessageTarget::Team(fixture.team.clone());
            let complete_id = complete.message_id.clone();
            assert_eq!(supervisor.apply(complete), Ok(ApplyOutcome::Applied));
            let delivery = supervisor
                .delivery(&complete_id)
                .expect("completion delivery exists");
            let reason = DeliveryRetirementReason::TeamClosed {
                team_id: fixture.team.clone(),
            };
            if recipient_status == ActorStatus::Stopped {
                let recipient = DeliveryRecipient::Actor(fixture.implementation.actor_id.clone());
                assert_eq!(
                    delivery.required_recipients,
                    BTreeSet::from([recipient.clone()])
                );
                assert_eq!(
                    delivery.undeliverable_recipients.get(&recipient),
                    Some(&reason)
                );
                assert_eq!(delivery.retirement_reason, None);
            } else {
                assert!(delivery.required_recipients.is_empty());
                assert!(delivery.undeliverable_recipients.is_empty());
                assert_eq!(delivery.retirement_reason, Some(reason));
            }
            assert!(delivery.retired);
            assert_eq!(
                supervisor
                    .request(&fixture.request)
                    .expect("request exists")
                    .status,
                RequestStatus::Completed
            );

            let snapshot = supervisor.snapshot();
            if terminal_status == TeamStatus::Closed && recipient_status == ActorStatus::Revoked {
                let mut forged = snapshot.clone();
                forged
                    .deliveries
                    .iter_mut()
                    .find(|delivery| delivery.envelope.message_id == complete_id)
                    .expect("completion delivery exists")
                    .retirement_reason = Some(DeliveryRetirementReason::TeamClosed {
                    team_id: TeamId::new("forged-team").expect("valid id"),
                });
                assert_invalid_snapshot(forged);
            }
            let restored = Supervisor::from_snapshot(snapshot.clone()).expect("outcome replays");
            assert_eq!(restored.snapshot(), snapshot);
            let request = snapshot.requests.first().expect("request exists");
            let run = snapshot.runs.first().expect("run exists");
            let deliveries = snapshot
                .deliveries
                .iter()
                .filter(|delivery| delivery.envelope.request_id.as_ref() == Some(&fixture.request))
                .cloned()
                .collect::<Vec<_>>();
            let message_ids = deliveries
                .iter()
                .map(|delivery| delivery.envelope.message_id.clone())
                .collect::<BTreeSet<_>>();
            let audit = snapshot
                .audit_events
                .iter()
                .filter(|event| match &event.kind {
                    agsv_protocol::AuditEventKind::MessageAccepted { message_id, .. }
                    | agsv_protocol::AuditEventKind::MessageAcknowledged { message_id, .. } => {
                        message_ids.contains(message_id)
                    }
                })
                .cloned()
                .collect::<Vec<_>>();
            assert!(deliveries.iter().all(|delivery| delivery.retired));
            assert_eq!(
                supervisor
                    .validate_archived_terminal_cycle(request, run, &deliveries, &audit, &[],),
                Ok(())
            );
        }
    }
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
        .replace_implementation(&fixture.team, fixture.implementation.actor_id.clone())
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

    let stale_actor = fixture.implementation_envelope(
        "stale-actor",
        fixture.implementation.clone(),
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
#[allow(clippy::too_many_lines)]
fn replacing_one_of_two_team_actors_preserves_its_peer_and_owned_assignment() {
    let mut fixture = Fixture::new();
    let original = fixture.implementation.clone();
    let peer = fixture
        .supervisor
        .register_implementation(
            &fixture.team,
            ActorId::new("implementation-peer").expect("valid id"),
        )
        .expect("peer registers");
    fixture.send_request();

    let peer_request = RequestId::new("request-peer").expect("valid id");
    let peer_run = RunId::new("run-peer").expect("valid id");
    let mut peer_request_envelope = fixture.request_envelope("create-peer-request");
    peer_request_envelope.target = MessageTarget::Actor(peer.actor_id.clone());
    peer_request_envelope.request_id = Some(peer_request.clone());
    peer_request_envelope.run_id = Some(peer_run.clone());
    peer_request_envelope.sent_at = TimestampMillis(2);
    assert_eq!(
        fixture.supervisor.apply(peer_request_envelope),
        Ok(ApplyOutcome::Applied)
    );

    let handoff_target = TeamId::new("replacement-handoff-target").expect("valid id");
    fixture
        .supervisor
        .create_team(handoff_target.clone())
        .expect("handoff target team creates");
    fixture
        .supervisor
        .register_implementation(
            &handoff_target,
            ActorId::new("replacement-handoff-recipient").expect("valid id"),
        )
        .expect("handoff target has a durable logical recipient");
    let mut original_handoff = fixture.implementation_envelope(
        "original-handoff-before-replacement",
        original.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::HandoffOffer(HandoffOffer {
            handoff_id: HandoffId::new("original-replacement-handoff").expect("valid id"),
            request_id: fixture.request.clone(),
            from_team_id: fixture.team.clone(),
            to_team_id: handoff_target.clone(),
            candidate: None,
            reason: "track cleanup for the replaced actor".to_owned(),
        }),
    );
    original_handoff.target = MessageTarget::Team(handoff_target.clone());
    assert_eq!(
        fixture.supervisor.apply(original_handoff),
        Ok(ApplyOutcome::Applied)
    );
    let mut peer_handoff = fixture.implementation_envelope(
        "peer-handoff-before-replacement",
        peer.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::HandoffOffer(HandoffOffer {
            handoff_id: HandoffId::new("peer-replacement-handoff").expect("valid id"),
            request_id: peer_request.clone(),
            from_team_id: fixture.team.clone(),
            to_team_id: handoff_target.clone(),
            candidate: None,
            reason: "preserve the peer actor's handoff".to_owned(),
        }),
    );
    peer_handoff.target = MessageTarget::Team(handoff_target);
    peer_handoff.request_id = Some(peer_request.clone());
    peer_handoff.run_id = Some(peer_run.clone());
    assert_eq!(
        fixture.supervisor.apply(peer_handoff),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(fixture.supervisor.snapshot().pending_handoffs.len(), 2);

    let prior_team_epoch = fixture
        .supervisor
        .team(&fixture.team)
        .expect("team exists")
        .epoch;
    let peer_before = fixture
        .supervisor
        .actor(&peer.actor_id)
        .expect("peer exists")
        .clone();
    let peer_assignment_before = fixture
        .supervisor
        .request(&peer_request)
        .and_then(|request| request.assignment.clone())
        .expect("peer request is assigned");
    let peer_run_assignment_before = fixture
        .supervisor
        .run(&peer_run)
        .and_then(|run| run.assignment.clone())
        .expect("peer run is assigned");

    fixture
        .supervisor
        .set_actor_status(&original, ActorStatus::Stale)
        .expect("original actor becomes stale");
    let replacement = fixture
        .supervisor
        .replace_implementation(&fixture.team, original.actor_id.clone())
        .expect("targeted replacement succeeds");

    assert_eq!(
        replacement.actor_epoch,
        original
            .actor_epoch
            .checked_next()
            .expect("actor epoch advances")
    );
    assert_eq!(
        fixture
            .supervisor
            .team(&fixture.team)
            .expect("team exists")
            .epoch,
        prior_team_epoch
            .checked_next()
            .expect("team epoch advances")
    );
    assert_eq!(
        fixture
            .supervisor
            .actor(&peer.actor_id)
            .expect("peer remains registered"),
        &peer_before
    );
    assert_eq!(
        fixture
            .supervisor
            .request(&peer_request)
            .and_then(|request| request.assignment.as_ref()),
        Some(&peer_assignment_before)
    );
    assert_eq!(
        fixture
            .supervisor
            .run(&peer_run)
            .and_then(|run| run.assignment.as_ref()),
        Some(&peer_run_assignment_before)
    );

    let replaced_assignment = fixture
        .supervisor
        .request(&fixture.request)
        .and_then(|request| request.assignment.as_ref())
        .expect("original request remains assigned");
    assert_eq!(replaced_assignment.actor, replacement);
    assert_eq!(
        replaced_assignment.epoch,
        AssignmentEpoch::new(2).expect("valid epoch")
    );
    assert_eq!(
        fixture
            .supervisor
            .run(&fixture.run)
            .and_then(|run| run.assignment.as_ref()),
        Some(replaced_assignment)
    );
    let pending_handoffs = fixture.supervisor.snapshot().pending_handoffs;
    assert_eq!(pending_handoffs.len(), 1);
    assert_eq!(pending_handoffs[0].offer.request_id, peer_request);

    let snapshot = fixture.supervisor.snapshot();
    let mut restored = Supervisor::from_snapshot(snapshot.clone()).expect("snapshot restores");
    assert_eq!(restored.snapshot(), snapshot);

    let stale_actor = fixture.implementation_envelope(
        "stale-replaced-actor",
        original,
        &fixture.team,
        AssignmentEpoch::INITIAL,
        progress("late progress from the replaced generation"),
    );
    assert!(matches!(
        restored.apply(stale_actor),
        Err(CoreError::StaleActorEpoch { .. })
    ));
    let stale_assignment = fixture.implementation_envelope(
        "stale-replaced-assignment",
        replacement,
        &fixture.team,
        AssignmentEpoch::INITIAL,
        progress("late progress under the replaced assignment"),
    );
    assert!(matches!(
        restored.apply(stale_assignment),
        Err(CoreError::StaleAssignmentEpoch { .. })
    ));
    assert_eq!(restored.snapshot(), snapshot);

    let mut peer_progress = fixture.implementation_envelope(
        "peer-progress-after-replacement",
        peer,
        &fixture.team,
        peer_assignment_before.epoch,
        progress("peer continues with its unchanged assignment"),
    );
    peer_progress.request_id = Some(peer_request);
    peer_progress.run_id = Some(peer_run);
    assert_eq!(restored.apply(peer_progress), Ok(ApplyOutcome::Applied));
}

#[test]
fn replacing_an_actor_outside_the_team_fails_without_mutating_member_work() {
    let mut fixture = Fixture::new();
    let peer = fixture
        .supervisor
        .register_implementation(
            &fixture.team,
            ActorId::new("implementation-peer").expect("valid id"),
        )
        .expect("peer registers");
    fixture.send_request();

    let peer_request = RequestId::new("request-peer").expect("valid id");
    let peer_run = RunId::new("run-peer").expect("valid id");
    let mut peer_request_envelope = fixture.request_envelope("create-peer-request");
    peer_request_envelope.target = MessageTarget::Actor(peer.actor_id.clone());
    peer_request_envelope.request_id = Some(peer_request);
    peer_request_envelope.run_id = Some(peer_run);
    peer_request_envelope.sent_at = TimestampMillis(2);
    assert_eq!(
        fixture.supervisor.apply(peer_request_envelope),
        Ok(ApplyOutcome::Applied)
    );

    let before = fixture.supervisor.snapshot();
    let outside_actor = ActorId::new("implementation-outside-team").expect("valid id");
    assert_eq!(
        fixture
            .supervisor
            .replace_implementation(&fixture.team, outside_actor.clone()),
        Err(CoreError::UnknownActor(outside_actor))
    );
    assert_eq!(fixture.supervisor.snapshot(), before);
}

#[test]
fn same_id_replacement_refreshes_terminal_actor_ref_without_advancing_assignment() {
    let mut fixture = Fixture::new();
    let original = fixture.implementation.clone();
    fixture.send_request();
    let cancellation = fixture.primary_envelope(
        "cancel-before-same-id-replacement",
        Message::Cancellation(Cancellation {
            reason: "terminal assignment must remain restorable".to_owned(),
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(cancellation),
        Ok(ApplyOutcome::Applied)
    );
    fixture
        .supervisor
        .set_actor_status(&original, ActorStatus::Stale)
        .expect("original actor becomes stale");

    let replacement = fixture
        .supervisor
        .replace_implementation(&fixture.team, original.actor_id)
        .expect("same-id replacement succeeds");
    let request = fixture
        .supervisor
        .request(&fixture.request)
        .expect("request remains recorded");
    let assignment = request
        .assignment
        .as_ref()
        .expect("assignment remains recorded");
    assert_eq!(request.status, RequestStatus::Cancelled);
    assert_eq!(assignment.actor, replacement);
    assert_eq!(assignment.epoch, AssignmentEpoch::INITIAL);
    assert_eq!(
        fixture
            .supervisor
            .run(&fixture.run)
            .and_then(|run| run.assignment.as_ref()),
        Some(assignment)
    );

    let snapshot = fixture.supervisor.snapshot();
    assert_eq!(
        Supervisor::from_snapshot(snapshot.clone())
            .expect("terminal assignment snapshot restores")
            .snapshot(),
        snapshot
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn closing_teams_drain_existing_work_but_refuse_new_ownership_and_never_revive() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    fixture
        .supervisor
        .set_team_status(&fixture.team, TeamStatus::Closing)
        .expect("active team begins closing");
    assert_eq!(
        fixture
            .supervisor
            .team(&fixture.team)
            .expect("team exists")
            .status,
        TeamStatus::Closing
    );
    assert_eq!(
        fixture.supervisor.create_team(fixture.team.clone()),
        Ok(agsv_protocol::TeamEpoch::INITIAL),
        "idempotent create does not revive or replace closing state"
    );
    assert_eq!(
        fixture.supervisor.register_implementation(
            &fixture.team,
            ActorId::new("closing-new-actor").expect("valid id")
        ),
        Err(CoreError::Unauthorized("register actor for inactive team"))
    );
    assert_eq!(
        fixture
            .supervisor
            .replace_implementation(&fixture.team, fixture.implementation.actor_id.clone()),
        Err(CoreError::Unauthorized("replace actor for inactive team"))
    );

    let mut new_request = fixture.request_envelope("closing-new-request");
    new_request.request_id = Some(RequestId::new("closing-new-request").expect("valid id"));
    new_request.run_id = Some(RunId::new("closing-new-run").expect("valid id"));
    assert_eq!(
        fixture.supervisor.apply(new_request),
        Err(CoreError::Unauthorized("assign work to inactive team"))
    );

    let progress_envelope = fixture.implementation_envelope(
        "closing-progress",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        progress("finishing already assigned work"),
    );
    assert_eq!(
        fixture.supervisor.apply(progress_envelope),
        Ok(ApplyOutcome::Applied)
    );
    let candidate = fixture.candidate(SHA_1, fixture.implementation.clone(), fixture.team.clone());
    assert_eq!(
        fixture.submit_candidate("closing-candidate", candidate),
        ApplyOutcome::Applied
    );
    let cancellation = fixture.primary_envelope(
        "closing-cancellation",
        Message::Cancellation(Cancellation {
            reason: "finish the closing team's remaining request".to_owned(),
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(cancellation),
        Ok(ApplyOutcome::Applied)
    );
    assert!(
        fixture
            .supervisor
            .team_close_blocking_message_ids(&fixture.team)
            .is_empty()
    );
    assert!(
        !fixture
            .supervisor
            .retire_obsolete_team_recipients(&fixture.team)
            .expect("close disposes unread outcomes for terminal work")
            .is_empty()
    );

    fixture
        .supervisor
        .set_team_status(&fixture.team, TeamStatus::Closed)
        .expect("closing team becomes closed");
    assert_eq!(
        fixture.supervisor.create_team(fixture.team.clone()),
        Err(CoreError::AlreadyExists("closed team"))
    );
    let closed_message = fixture.implementation_envelope(
        "closed-progress",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        progress("closed actors cannot send"),
    );
    assert_eq!(
        fixture.supervisor.apply(closed_message),
        Err(CoreError::Unauthorized("message from inactive team"))
    );
    let snapshot = fixture.supervisor.snapshot();
    assert_eq!(
        Supervisor::from_snapshot(snapshot.clone())
            .expect("closed team snapshot restores")
            .snapshot(),
        snapshot
    );

    let mut legacy_retired = snapshot;
    legacy_retired.teams[0].status = TeamStatus::Retired;
    assert!(Supervisor::from_snapshot(legacy_retired).is_ok());
}

#[test]
fn candidate_outcome_metrics_are_idempotent_and_causally_validated() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let candidate_one =
        fixture.candidate(SHA_1, fixture.implementation.clone(), fixture.team.clone());
    fixture.submit_candidate("metric-candidate-one", candidate_one.clone());
    let initial = fixture
        .supervisor
        .request(&fixture.request)
        .expect("request exists");
    assert_eq!(initial.rejection_count, 0);
    assert_eq!(initial.fix_cycle_depth, 0);
    assert_eq!(initial.candidate_history, vec![candidate_one.clone()]);

    fixture.submit_candidate("metric-candidate-one-repeat", candidate_one.clone());
    assert_eq!(
        fixture
            .supervisor
            .request(&fixture.request)
            .expect("request exists")
            .candidate_history,
        vec![candidate_one.clone()]
    );

    let rejection = ReviewDecision {
        decision_id: DecisionId::new("metric-rejection").expect("valid id"),
        candidate: candidate_one.clone(),
        verdict: ReviewVerdict::Rejected,
        reviewer: fixture.primary.clone(),
        policy_revision: fixture.supervisor.policy_revision(),
        rationale: "candidate requires a fix".to_owned(),
        evidence: Vec::new(),
    };
    let rejection_envelope =
        fixture.primary_envelope("metric-rejection", Message::ReviewDecision(rejection));
    assert_eq!(
        fixture.supervisor.apply(rejection_envelope.clone()),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(
        fixture.supervisor.apply(rejection_envelope),
        Ok(ApplyOutcome::Duplicate)
    );
    assert_eq!(
        fixture
            .supervisor
            .request(&fixture.request)
            .expect("request exists")
            .rejection_count,
        1
    );

    let candidate_two =
        fixture.candidate(SHA_2, fixture.implementation.clone(), fixture.team.clone());
    fixture.submit_candidate("metric-candidate-two", candidate_two.clone());
    let reworked = fixture
        .supervisor
        .request(&fixture.request)
        .expect("request exists");
    assert_eq!(reworked.rejection_count, 1);
    assert_eq!(reworked.fix_cycle_depth, 1);
    assert_eq!(
        reworked.candidate_history,
        vec![candidate_one, candidate_two]
    );

    let snapshot = fixture.supervisor.snapshot();
    assert_eq!(
        Supervisor::from_snapshot(snapshot.clone())
            .expect("instrumented outcome history replays")
            .snapshot(),
        snapshot
    );

    let mut legacy = snapshot.clone();
    legacy.requests[0].rejection_count = 0;
    legacy.requests[0].fix_cycle_depth = 0;
    legacy.requests[0].candidate_history.clear();
    assert_eq!(
        Supervisor::from_snapshot(legacy.clone())
            .expect("legacy all-default metrics remain accepted")
            .snapshot(),
        legacy
    );

    let mut forged_count = snapshot.clone();
    forged_count.requests[0].rejection_count += 1;
    assert_invalid_snapshot(forged_count);
    let mut forged_history = snapshot;
    forged_history.requests[0].candidate_history.pop();
    assert_invalid_snapshot(forged_history);
}

#[test]
fn candidate_profile_attribution_matches_the_authenticated_actor() {
    let mut fixture = Fixture::new_profiled();
    fixture.send_request();
    let expected_profile = ActorProfileName::new("implementation").expect("valid profile name");
    let mut candidate =
        fixture.candidate(SHA_1, fixture.implementation.clone(), fixture.team.clone());
    let missing_profile = fixture.implementation_envelope(
        "missing-candidate-profile",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::CandidateReady(CandidateReady {
            candidate: candidate.clone(),
            summary: "missing configured attribution".to_owned(),
            evidence: Vec::new(),
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(missing_profile),
        Err(CoreError::Unauthorized("submit candidate identity"))
    );

    candidate.created_by_profile = Some(expected_profile.clone());
    assert_eq!(
        fixture.submit_candidate("profiled-candidate", candidate.clone()),
        ApplyOutcome::Applied
    );
    let request = fixture
        .supervisor
        .request(&fixture.request)
        .expect("request exists");
    assert_eq!(
        request
            .candidate
            .as_ref()
            .and_then(|current| current.created_by_profile.as_ref()),
        Some(&expected_profile)
    );
    assert_eq!(request.candidate_history, vec![candidate]);

    let snapshot = fixture.supervisor.snapshot();
    assert_eq!(
        Supervisor::from_snapshot(snapshot.clone())
            .expect("profile attribution replays")
            .snapshot(),
        snapshot
    );
    let mut forged = snapshot.clone();
    forged.requests[0]
        .candidate
        .as_mut()
        .expect("candidate exists")
        .created_by_profile =
        Some(ActorProfileName::new("forged-profile").expect("valid profile name"));
    assert_invalid_snapshot(forged);

    let mut legacy = snapshot;
    legacy.requests[0]
        .candidate
        .as_mut()
        .expect("candidate exists")
        .created_by_profile = None;
    for historical in &mut legacy.requests[0].candidate_history {
        historical.created_by_profile = None;
    }
    for delivery in &mut legacy.deliveries {
        if let CausalMessage::CandidateReady { candidate } = &mut delivery.causal {
            candidate.created_by_profile = None;
        }
    }
    assert_eq!(
        Supervisor::from_snapshot(legacy.clone())
            .expect("legacy candidate without profile attribution restores")
            .snapshot(),
        legacy
    );
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
#[allow(clippy::too_many_lines)]
fn rejected_candidate_replacement_after_progress_preserves_assignment_fences_and_replays() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let rejected_candidate =
        fixture.candidate(SHA_1, fixture.implementation.clone(), fixture.team.clone());
    assert_eq!(
        fixture.submit_candidate("rework-candidate-one", rejected_candidate.clone()),
        ApplyOutcome::Applied
    );
    fixture.review_candidate(
        "rework-reject-one",
        "rework-decision-one",
        rejected_candidate.clone(),
        ReviewVerdict::Rejected,
    );

    let progress = fixture.implementation_envelope(
        "rework-progress",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        progress("implementing the requested revision"),
    );
    assert_eq!(
        fixture.supervisor.apply(progress),
        Ok(ApplyOutcome::Applied)
    );
    let request = fixture
        .supervisor
        .request(&fixture.request)
        .expect("request remains available");
    assert_eq!(request.status, RequestStatus::InProgress);
    assert_eq!(request.candidate.as_ref(), Some(&rejected_candidate));
    assert_eq!(
        request.decision.as_ref().map(|decision| decision.verdict),
        Some(ReviewVerdict::Rejected)
    );
    assert_eq!(
        fixture
            .supervisor
            .run(&fixture.run)
            .expect("run exists")
            .status,
        RunStatus::Active
    );
    let in_progress_snapshot = fixture.supervisor.snapshot();
    assert_eq!(
        Supervisor::from_snapshot(in_progress_snapshot.clone())
            .expect("rejected in-progress history restores")
            .snapshot(),
        in_progress_snapshot
    );

    let unchanged_completion = fixture.implementation_envelope(
        "rework-unchanged-completion",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::CandidateReady(CandidateReady {
            candidate: rejected_candidate.clone(),
            summary: "rejected candidate cannot be resubmitted".to_owned(),
            evidence: Vec::new(),
        }),
    );
    let before_unchanged = fixture.supervisor.snapshot();
    assert_eq!(
        fixture.supervisor.apply(unchanged_completion),
        Err(CoreError::CandidateMustChange)
    );
    assert_eq!(fixture.supervisor.snapshot(), before_unchanged);

    let current_actor = fixture
        .supervisor
        .replace_implementation(&fixture.team, fixture.implementation.actor_id.clone())
        .expect("same-id replacement advances active fences");
    let current_assignment = fixture
        .supervisor
        .request(&fixture.request)
        .and_then(|request| request.assignment.as_ref())
        .expect("request remains assigned")
        .clone();
    assert_eq!(current_assignment.actor, current_actor);
    assert_eq!(
        current_assignment.epoch,
        AssignmentEpoch::new(2).expect("valid assignment epoch")
    );

    let replacement_candidate =
        fixture.candidate(SHA_2, current_actor.clone(), fixture.team.clone());
    let stale_actor_completion = fixture.implementation_envelope(
        "rework-stale-actor-completion",
        fixture.implementation.clone(),
        &fixture.team,
        current_assignment.epoch,
        Message::CandidateReady(CandidateReady {
            candidate: rejected_candidate.clone(),
            summary: "stale actor cannot complete rework".to_owned(),
            evidence: Vec::new(),
        }),
    );
    let before_stale_actor = fixture.supervisor.snapshot();
    assert!(matches!(
        fixture.supervisor.apply(stale_actor_completion),
        Err(CoreError::StaleActorEpoch { .. })
    ));
    assert_eq!(fixture.supervisor.snapshot(), before_stale_actor);

    let stale_assignment_completion = fixture.implementation_envelope(
        "rework-stale-assignment-completion",
        current_actor.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::CandidateReady(CandidateReady {
            candidate: replacement_candidate.clone(),
            summary: "stale assignment cannot complete rework".to_owned(),
            evidence: Vec::new(),
        }),
    );
    let before_stale_assignment = fixture.supervisor.snapshot();
    assert!(matches!(
        fixture.supervisor.apply(stale_assignment_completion),
        Err(CoreError::StaleAssignmentEpoch { .. })
    ));
    assert_eq!(fixture.supervisor.snapshot(), before_stale_assignment);

    let peer = fixture
        .supervisor
        .register_implementation(
            &fixture.team,
            ActorId::new("implementation-rework-peer").expect("valid id"),
        )
        .expect("peer registers");
    let peer_candidate = fixture.candidate(SHA_2, peer.clone(), fixture.team.clone());
    let non_assignee_completion = fixture.implementation_envelope(
        "rework-non-assignee-completion",
        peer,
        &fixture.team,
        current_assignment.epoch,
        Message::CandidateReady(CandidateReady {
            candidate: peer_candidate,
            summary: "non-assignee cannot complete rework".to_owned(),
            evidence: Vec::new(),
        }),
    );
    let before_non_assignee = fixture.supervisor.snapshot();
    assert_eq!(
        fixture.supervisor.apply(non_assignee_completion),
        Err(CoreError::NotAssignedActor)
    );
    assert_eq!(fixture.supervisor.snapshot(), before_non_assignee);

    let completion = fixture.implementation_envelope(
        "rework-candidate-two",
        current_actor,
        &fixture.team,
        current_assignment.epoch,
        Message::CandidateReady(CandidateReady {
            candidate: replacement_candidate.clone(),
            summary: "replacement candidate completes rework".to_owned(),
            evidence: Vec::new(),
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(completion.clone()),
        Ok(ApplyOutcome::Applied)
    );
    let completed_rework = fixture
        .supervisor
        .request(&fixture.request)
        .expect("request remains available");
    assert_eq!(completed_rework.status, RequestStatus::CandidateReady);
    assert_eq!(
        completed_rework.candidate.as_ref(),
        Some(&replacement_candidate)
    );
    assert!(completed_rework.decision.is_none());
    assert_eq!(
        fixture
            .supervisor
            .run(&fixture.run)
            .expect("run exists")
            .status,
        RunStatus::AwaitingReview
    );

    let after_completion = fixture.supervisor.snapshot();
    assert_eq!(
        fixture.supervisor.apply(completion),
        Ok(ApplyOutcome::Duplicate)
    );
    assert_eq!(fixture.supervisor.snapshot(), after_completion);
    assert_eq!(
        Supervisor::from_snapshot(after_completion.clone())
            .expect("completed rework history restores")
            .snapshot(),
        after_completion
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn rejected_candidate_replacement_after_progress_then_blocker_replays() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let rejected_candidate =
        fixture.candidate(SHA_1, fixture.implementation.clone(), fixture.team.clone());
    assert_eq!(
        fixture.submit_candidate("blocked-rework-candidate-one", rejected_candidate.clone()),
        ApplyOutcome::Applied
    );
    fixture.review_candidate(
        "blocked-rework-reject-one",
        "blocked-rework-decision-one",
        rejected_candidate.clone(),
        ReviewVerdict::Rejected,
    );

    let progress = fixture.implementation_envelope(
        "blocked-rework-progress",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        progress("revision work has started"),
    );
    assert_eq!(
        fixture.supervisor.apply(progress),
        Ok(ApplyOutcome::Applied)
    );

    let blocker = fixture.implementation_envelope(
        "blocked-rework-notice",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::Blocker(BlockerNotice {
            summary: "revision is waiting on scoped coordination".to_owned(),
            needs_primary: true,
            evidence: Vec::new(),
        }),
    );
    assert_eq!(fixture.supervisor.apply(blocker), Ok(ApplyOutcome::Applied));
    let blocked_request = fixture
        .supervisor
        .request(&fixture.request)
        .expect("blocked rework request remains available");
    assert_eq!(blocked_request.status, RequestStatus::Blocked);
    assert_eq!(
        blocked_request.candidate.as_ref(),
        Some(&rejected_candidate)
    );
    assert_eq!(
        blocked_request
            .decision
            .as_ref()
            .map(|decision| decision.verdict),
        Some(ReviewVerdict::Rejected)
    );
    assert_eq!(
        fixture
            .supervisor
            .run(&fixture.run)
            .expect("run exists")
            .status,
        RunStatus::Blocked
    );
    let blocked_snapshot = fixture.supervisor.snapshot();
    assert_eq!(
        Supervisor::from_snapshot(blocked_snapshot.clone())
            .expect("blocked rejected history restores")
            .snapshot(),
        blocked_snapshot
    );

    let replacement_candidate =
        fixture.candidate(SHA_2, fixture.implementation.clone(), fixture.team.clone());
    let completion = fixture.implementation_envelope(
        "blocked-rework-candidate-two",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        Message::CandidateReady(CandidateReady {
            candidate: replacement_candidate.clone(),
            summary: "replacement candidate completes blocked rework".to_owned(),
            evidence: Vec::new(),
        }),
    );
    assert_eq!(
        fixture.supervisor.apply(completion),
        Ok(ApplyOutcome::Applied)
    );
    let completed_rework = fixture
        .supervisor
        .request(&fixture.request)
        .expect("completed rework request remains available");
    assert_eq!(completed_rework.status, RequestStatus::CandidateReady);
    assert_eq!(
        completed_rework.candidate.as_ref(),
        Some(&replacement_candidate)
    );
    assert!(completed_rework.decision.is_none());
    let completed_snapshot = fixture.supervisor.snapshot();
    assert_eq!(
        Supervisor::from_snapshot(completed_snapshot.clone())
            .expect("completed blocked rework history restores")
            .snapshot(),
        completed_snapshot
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
    let duplicate = Fixture::new().request_envelope("create-request");
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
fn restore_requires_exact_recipients_for_actor_and_primary_targets() {
    let mut fixture = Fixture::new();
    fixture.send_request();
    let progress = fixture.implementation_envelope(
        "primary-target-progress",
        fixture.implementation.clone(),
        &fixture.team,
        AssignmentEpoch::INITIAL,
        progress("exercise the Primary recipient route"),
    );
    assert_eq!(
        fixture.supervisor.apply(progress),
        Ok(ApplyOutcome::Applied)
    );
    let snapshot = fixture.supervisor.snapshot();

    let mut missing_actor = snapshot.clone();
    request_delivery_mut(&mut missing_actor)
        .required_recipients
        .clear();
    assert_invalid_snapshot(missing_actor);
    let mut mismatched_actor = snapshot.clone();
    request_delivery_mut(&mut mismatched_actor).required_recipients =
        [DeliveryRecipient::Primary].into_iter().collect();
    assert_invalid_snapshot(mismatched_actor);

    let mut missing_primary = snapshot.clone();
    progress_delivery_mut(&mut missing_primary)
        .required_recipients
        .clear();
    assert_invalid_snapshot(missing_primary);
    let mut mismatched_primary = snapshot;
    progress_delivery_mut(&mut mismatched_primary).required_recipients =
        [DeliveryRecipient::Actor(
            fixture.implementation.actor_id.clone(),
        )]
        .into_iter()
        .collect();
    assert_invalid_snapshot(mismatched_primary);
}

#[test]
fn restore_binds_current_epoch_primary_sender_to_active_primary() {
    let mut fixture = Fixture::new();
    let prior_primary = fixture.primary.clone();
    fixture.primary = fixture
        .supervisor
        .activate_primary(ActorId::new("current-primary").expect("valid id"))
        .expect("replacement Primary activates");
    fixture.send_request();
    let snapshot = fixture.supervisor.snapshot();
    Supervisor::from_snapshot(snapshot.clone()).expect("valid current Primary history restores");

    let mut forged = snapshot;
    forged
        .deliveries
        .iter_mut()
        .find(|delivery| {
            matches!(
                delivery.causal,
                agsv_protocol::CausalMessage::ImplementationRequest { .. }
            )
        })
        .expect("current-epoch Primary delivery exists")
        .envelope
        .sender = prior_primary;
    assert_invalid_snapshot(forged);
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
        .replace_implementation(&fixture.team, fixture.implementation.actor_id.clone())
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
        .set_actor_status(&fixture.implementation, ActorStatus::Revoked)
        .expect("healthy actor may be revoked");
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
fn heartbeat_timestamps_are_monotonic_across_retried_observations() {
    let mut fixture = Fixture::new();
    fixture
        .supervisor
        .heartbeat(&fixture.implementation, TimestampMillis(20))
        .expect("newer heartbeat records");
    fixture
        .supervisor
        .heartbeat(&fixture.implementation, TimestampMillis(10))
        .expect("an older retried observation remains idempotent");
    assert_eq!(
        fixture
            .supervisor
            .actor(&fixture.implementation.actor_id)
            .expect("actor exists")
            .last_heartbeat_at,
        Some(TimestampMillis(20))
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
    if let agsv_protocol::CausalMessage::ReviewDecision(decision) = &mut delivery.causal {
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
        .find(|delivery| {
            matches!(
                delivery.causal,
                agsv_protocol::CausalMessage::ImplementationRequest { .. }
            )
        })
        .expect("request delivery exists")
        .envelope
        .sender = implementation;
    assert_invalid_snapshot(forged_sender);

    let mut forged_route = snapshot.clone();
    forged_route
        .deliveries
        .iter_mut()
        .find(|delivery| {
            matches!(
                delivery.causal,
                agsv_protocol::CausalMessage::ImplementationRequest { .. }
            )
        })
        .expect("request delivery exists")
        .envelope
        .target = MessageTarget::Primary;
    assert_invalid_snapshot(forged_route);

    let mut forged_fence = snapshot.clone();
    forged_fence.deliveries[0].envelope.primary_epoch = PrimaryEpoch::new(2).expect("valid epoch");
    assert_invalid_snapshot(forged_fence);

    let mut forged_digest = snapshot.clone();
    forged_digest.deliveries[0].payload_digest =
        PayloadDigest::new("f".repeat(64)).expect("valid digest syntax");
    assert_invalid_snapshot(forged_digest);

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
fn checkpoint_keeps_restore_bounded_beyond_live_collection_quotas() {
    let fixture = Fixture::new();
    let archived_audit = u64::try_from(MAX_AUDIT_EVENTS).expect("constant fits u64") + 1;
    let archived_deliveries = u64::try_from(MAX_DELIVERIES).expect("constant fits u64") + 1;
    let archived_requests = u64::try_from(MAX_DOMAIN_ENTITIES).expect("constant fits u64") + 1;
    let archived_head = PayloadDigest::new("a".repeat(64)).expect("valid digest");
    let mut snapshot = fixture.supervisor.snapshot();
    snapshot.history_checkpoint = HistoryCheckpoint {
        audit_event_count: archived_audit,
        audit_head_sha256: Some(archived_head.clone()),
        archived_delivery_count: archived_deliveries,
        archived_request_count: archived_requests,
        archived_run_count: archived_requests,
        archived_audit_event_count: archived_audit,
        archive_commit_count: 1,
        archive_head_sha256: Some(PayloadDigest::new("b".repeat(64)).expect("valid archive head")),
    };

    let mut restored =
        Supervisor::from_snapshot(snapshot.clone()).expect("bounded hot state restores");
    assert_eq!(
        restored.apply(fixture.request_envelope("post-checkpoint-request")),
        Ok(ApplyOutcome::Applied)
    );
    assert_eq!(restored.audit_events()[0].sequence, archived_audit + 1);
    let after = restored.snapshot();
    assert_eq!(
        after.history_checkpoint.audit_event_count,
        archived_audit + 1
    );
    assert_ne!(
        after.history_checkpoint.audit_head_sha256,
        Some(archived_head)
    );
    Supervisor::from_snapshot(after.clone()).expect("sparse hot audit restores");

    let mut forged_count = after.clone();
    forged_count.history_checkpoint.archived_audit_event_count -= 1;
    assert_invalid_snapshot(forged_count);
    let mut forged_head = after;
    forged_head.history_checkpoint.audit_head_sha256 =
        Some(PayloadDigest::new("f".repeat(64)).expect("valid digest"));
    assert_invalid_snapshot(forged_head);

    let mut missing_archive_head = fixture.supervisor.snapshot();
    missing_archive_head.history_checkpoint = snapshot.history_checkpoint.clone();
    missing_archive_head.history_checkpoint.archive_head_sha256 = None;
    assert_invalid_snapshot(missing_archive_head);
    let mut impossible_commit_count = snapshot;
    impossible_commit_count
        .history_checkpoint
        .archive_commit_count = archived_deliveries + archived_requests + archived_audit + 1;
    assert_invalid_snapshot(impossible_commit_count);
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
fn teamless_mixed_capability_primary_cannot_report_conflicts() {
    let workspace = WorkspaceId::new("teamless-conflict-workspace").expect("valid id");
    let sender_team = TeamId::new("conflict-sender-team").expect("valid id");
    let other_team = TeamId::new("conflict-other-team").expect("valid id");
    let mut supervisor = Supervisor::new(workspace.clone(), PolicyRevision::INITIAL);
    let capabilities = [
        HUMAN_FACING_PRIMARY_CAPABILITY,
        IMPLEMENTATION_EXECUTION_CAPABILITY,
    ];
    let primary = supervisor
        .activate_primary_with_profile(
            ActorId::new("mixed-primary").expect("valid id"),
            ActorRole::new("research").expect("valid role"),
            actor_profile("mixed-primary", &capabilities),
        )
        .expect("mixed-capability Primary activates without a team");
    supervisor
        .create_team_with_profile(
            sender_team.clone(),
            team_profile("mixed", "mixed", 1, "first_healthy"),
        )
        .expect("sender team profile persists");
    supervisor
        .create_team(other_team.clone())
        .expect("other team exists");
    supervisor
        .register_implementation(
            &other_team,
            ActorId::new("conflict-other-recipient").expect("valid id"),
        )
        .expect("other team has a durable logical recipient");
    let team_actor = supervisor
        .register_implementation_with_profile(
            &sender_team,
            ActorId::new("mixed-team-actor").expect("valid id"),
            ActorRole::new("research").expect("valid role"),
            actor_profile("mixed", &capabilities),
        )
        .expect("team actor can carry the same capability combination");

    let teamless_conflict = Envelope {
        protocol_version: 1,
        message_id: MessageId::new("teamless-conflict").expect("valid id"),
        workspace_id: workspace,
        sender: primary,
        target: MessageTarget::Team(other_team.clone()),
        team_id: None,
        run_id: None,
        request_id: None,
        policy_revision: supervisor.policy_revision(),
        primary_epoch: supervisor.primary_epoch(),
        team_epoch: None,
        assignment_epoch: None,
        sent_at: TimestampMillis(1),
        message: Message::ConflictNotice(ConflictNotice {
            other_team_id: other_team,
            resources: vec!["schema.json".to_owned()],
            description: "teamless actors cannot represent one side of a conflict".to_owned(),
        }),
    };
    let before = supervisor.snapshot();
    assert_eq!(
        supervisor.apply(teamless_conflict.clone()),
        Err(CoreError::WrongTeam)
    );
    assert_eq!(
        supervisor.snapshot(),
        before,
        "rejection must not mutate state"
    );

    let mut legal_conflict = teamless_conflict.clone();
    legal_conflict.sender = team_actor;
    legal_conflict.team_id = Some(sender_team.clone());
    legal_conflict.team_epoch = Some(
        supervisor
            .team(&sender_team)
            .expect("sender team exists")
            .epoch,
    );
    assert_eq!(supervisor.apply(legal_conflict), Ok(ApplyOutcome::Applied));

    let mut forged = supervisor.snapshot();
    forged
        .deliveries
        .first_mut()
        .expect("legal conflict delivery exists")
        .envelope = (&teamless_conflict).into();
    assert!(matches!(
        Supervisor::from_snapshot(forged),
        Err(CoreError::InvalidSnapshot {
            path,
            reason: "accepted conflict sender has no team",
        }) if path == "deliveries.envelope.sender"
    ));
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
