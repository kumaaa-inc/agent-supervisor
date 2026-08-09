//! Serializable provider-independent protocol and persisted-state types.

use crate::PROTOCOL_VERSION;
use crate::ids::{
    ActorEpoch, ActorId, AssignmentEpoch, DecisionId, EvidenceId, GitSha, HandoffId, MessageId,
    PolicyRevision, PrimaryEpoch, RequestId, RunId, TeamEpoch, TeamId, TimestampMillis,
    WorkspaceId,
};
use crate::validation::{
    MAX_ACCEPTANCE_CRITERIA, MAX_ACKNOWLEDGEMENTS, MAX_AUDIT_EVENTS, MAX_CONFLICT_RESOURCES,
    MAX_DELIVERIES, MAX_DOMAIN_ENTITIES, MAX_EVIDENCE_ITEMS, MAX_EVIDENCE_REQUIREMENTS, Validate,
    ValidationCode, ValidationError, validate_count, validate_text,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A currently registered actor generation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ActorRef {
    /// Stable logical actor identifier.
    pub actor_id: ActorId,
    /// Process-generation fence for the actor identifier.
    pub actor_epoch: ActorEpoch,
}

/// The provider-independent responsibility of an actor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorRole {
    /// The single human-facing owner of intent and approval.
    Primary,
    /// A top-level implementation orchestrator assigned to one team.
    Implementation,
}

/// Durable actor lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorStatus {
    /// Registered but not yet healthy.
    Starting,
    /// Eligible to send and acknowledge protocol messages.
    Healthy,
    /// Superseded or beyond its heartbeat tolerance.
    Stale,
    /// Permanently fenced actor generation that cannot heartbeat back.
    Revoked,
    /// Deliberately stopped and terminal for this actor generation.
    Stopped,
}

/// A durable actor record without provider-specific session identifiers.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Actor {
    /// Stable actor identifier.
    pub actor_id: ActorId,
    /// Workspace in which this actor participates.
    pub workspace_id: WorkspaceId,
    /// Owning team for implementation actors; absent for the Primary.
    pub team_id: Option<TeamId>,
    /// Protocol responsibility.
    pub role: ActorRole,
    /// Process-generation fence.
    pub epoch: ActorEpoch,
    /// Current lifecycle state.
    pub status: ActorStatus,
    /// Last heartbeat observed by the runtime boundary.
    pub last_heartbeat_at: Option<TimestampMillis>,
}

impl Actor {
    /// Returns the fenced reference carried in envelopes.
    #[must_use]
    pub fn actor_ref(&self) -> ActorRef {
        ActorRef {
            actor_id: self.actor_id.clone(),
            actor_epoch: self.epoch,
        }
    }
}

impl Validate for Actor {
    fn validate(&self) -> Result<(), ValidationError> {
        match (self.role, &self.team_id) {
            (ActorRole::Primary, None) | (ActorRole::Implementation, Some(_)) => Ok(()),
            (ActorRole::Primary, Some(_)) => Err(ValidationError::new(
                "team_id",
                ValidationCode::Inconsistent,
                "a Primary actor cannot belong to a team",
            )),
            (ActorRole::Implementation, None) => Err(ValidationError::new(
                "team_id",
                ValidationCode::Required,
                "an Implementation actor must belong to a team",
            )),
        }
    }
}

/// Durable team lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamStatus {
    /// Eligible to receive work.
    Active,
    /// Temporarily unable to receive new work.
    Paused,
    /// Terminal team state.
    Retired,
}

/// A provider-independent implementation team.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Team {
    /// Stable team identifier.
    pub team_id: TeamId,
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// Team ownership fence.
    pub epoch: TeamEpoch,
    /// Current lifecycle state.
    pub status: TeamStatus,
    /// Registered logical implementation actors.
    #[schemars(length(max = MAX_DOMAIN_ENTITIES))]
    pub actors: Vec<ActorId>,
}

/// The sole active assignment for a request.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Assignment {
    /// Currently assigned actor generation.
    pub actor: ActorRef,
    /// Monotonic assignment fence.
    pub epoch: AssignmentEpoch,
}

/// Durable request lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    /// Known but not assigned.
    Open,
    /// Assigned to exactly one implementation actor.
    Assigned,
    /// Implementation is actively progressing.
    InProgress,
    /// Progress requires another party or decision.
    Blocked,
    /// An exact commit is ready for review.
    CandidateReady,
    /// A prior candidate was rejected and must be replaced.
    ChangesRequested,
    /// The current exact candidate was accepted.
    Accepted,
    /// Integration of the accepted exact candidate was authorized.
    IntegrationAuthorized,
    /// Work was cancelled.
    Cancelled,
    /// Authorized integration was reported complete.
    Completed,
}

impl RequestStatus {
    /// Whether no further protocol transition is allowed.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Cancelled | Self::Completed)
    }
}

/// Durable run lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Waiting for an assignment.
    Pending,
    /// Implementation is active.
    Active,
    /// Explicitly paused.
    Paused,
    /// Waiting on a blocker.
    Blocked,
    /// Waiting for review of an exact candidate.
    AwaitingReview,
    /// A replacement candidate is required.
    RevisionRequested,
    /// The exact candidate was accepted.
    Accepted,
    /// Integration was authorized for the exact candidate.
    Authorized,
    /// Work was cancelled.
    Cancelled,
    /// Work and its authorized integration are complete.
    Completed,
}

/// A run binds a team and request to an active assignment.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Run {
    /// Stable run identifier.
    pub run_id: RunId,
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// Current owning team.
    pub team_id: TeamId,
    /// Work request executed by this run.
    pub request_id: RequestId,
    /// Current lifecycle state.
    pub status: RunStatus,
    /// Current fenced assignment, when assigned.
    pub assignment: Option<Assignment>,
}

/// A cryptographically addressed evidence item.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Evidence {
    /// Stable evidence identifier.
    pub evidence_id: EvidenceId,
    /// Semantic category.
    pub kind: EvidenceKind,
    /// Content digest used to verify the external artifact.
    pub digest: EvidenceDigest,
    /// Provider-neutral local path or external reference.
    #[schemars(length(min = 1, max = 2_048))]
    pub reference: String,
    /// Short description of what the evidence proves.
    #[schemars(length(min = 1, max = 4_096))]
    pub summary: String,
}

impl Validate for Evidence {
    fn validate(&self) -> Result<(), ValidationError> {
        self.digest.validate().map_err(|error| error.at("digest"))?;
        validate_text("reference", &self.reference, 2_048)?;
        validate_text("summary", &self.summary, 4_096)
    }
}

/// Evidence category, independent of any hosting provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A Git commit or tree.
    Git,
    /// Test or check output.
    Test,
    /// Static analysis or review finding.
    Review,
    /// Build artifact or file.
    Artifact,
    /// Runtime log or trace.
    Log,
    /// Other content-addressed evidence.
    Other,
}

/// Supported digest algorithms for evidence artifacts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    /// SHA-256.
    Sha256,
    /// BLAKE3 with its default 256-bit output.
    Blake3,
}

/// Digest and algorithm for an evidence artifact.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct EvidenceDigest {
    /// Hash algorithm.
    pub algorithm: DigestAlgorithm,
    /// Lowercase or uppercase 256-bit hexadecimal digest.
    pub value: String,
}

impl Validate for EvidenceDigest {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.value.len() != 64 || !self.value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ValidationError::new(
                "value",
                ValidationCode::InvalidFormat,
                "must be a 64-digit hexadecimal digest",
            ));
        }
        Ok(())
    }
}

/// Immutable identity of a reviewable implementation result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Candidate {
    /// Request completed by the candidate.
    pub request_id: RequestId,
    /// Team that owns the candidate.
    pub team_id: TeamId,
    /// Exact full Git commit object id.
    pub sha: GitSha,
    /// Fenced actor generation that produced the candidate.
    pub created_by: ActorRef,
}

/// Work requested by the active Primary.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ImplementationRequest {
    /// Human-readable short title.
    #[schemars(length(min = 1, max = 256))]
    pub title: String,
    /// Complete implementation instructions.
    #[schemars(length(min = 1, max = 65_536))]
    pub instructions: String,
    /// Exact commit from which work should begin.
    pub base_sha: GitSha,
    /// Verifiable completion criteria.
    #[schemars(length(min = 1, max = MAX_ACCEPTANCE_CRITERIA), inner(length(min = 1, max = 4_096)))]
    pub acceptance_criteria: Vec<String>,
    /// Evidence categories the implementation must return.
    #[schemars(length(max = MAX_EVIDENCE_REQUIREMENTS))]
    pub evidence_requirements: Vec<EvidenceKind>,
}

impl Validate for ImplementationRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("title", &self.title, 256)?;
        validate_text("instructions", &self.instructions, 65_536)?;
        if self.acceptance_criteria.is_empty() {
            return Err(ValidationError::new(
                "acceptance_criteria",
                ValidationCode::Required,
                "must contain at least one criterion",
            ));
        }
        validate_count(
            "acceptance_criteria",
            self.acceptance_criteria.len(),
            MAX_ACCEPTANCE_CRITERIA,
        )?;
        validate_count(
            "evidence_requirements",
            self.evidence_requirements.len(),
            MAX_EVIDENCE_REQUIREMENTS,
        )?;
        for (index, criterion) in self.acceptance_criteria.iter().enumerate() {
            validate_text(&format!("acceptance_criteria[{index}]"), criterion, 4_096)?;
        }
        Ok(())
    }
}

/// Periodic implementation progress.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProgressUpdate {
    /// Short progress summary.
    #[schemars(length(min = 1, max = 8_192))]
    pub summary: String,
    /// Optional estimated completion percentage.
    #[schemars(range(max = 100))]
    pub percent_complete: Option<u8>,
    /// Content-addressed supporting evidence.
    #[schemars(length(max = MAX_EVIDENCE_ITEMS))]
    pub evidence: Vec<Evidence>,
}

impl Validate for ProgressUpdate {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("summary", &self.summary, 8_192)?;
        if self.percent_complete.is_some_and(|value| value > 100) {
            return Err(ValidationError::new(
                "percent_complete",
                ValidationCode::OutOfRange,
                "must be between 0 and 100",
            ));
        }
        validate_evidence(&self.evidence)
    }
}

/// A blocker requiring coordination or a decision.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct BlockerNotice {
    /// Description of the blocker.
    #[schemars(length(min = 1, max = 8_192))]
    pub summary: String,
    /// Whether direct Primary input is requested.
    pub needs_primary: bool,
    /// Supporting evidence.
    #[schemars(length(max = MAX_EVIDENCE_ITEMS))]
    pub evidence: Vec<Evidence>,
}

impl Validate for BlockerNotice {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("summary", &self.summary, 8_192)?;
        validate_evidence(&self.evidence)
    }
}

/// Submission of an immutable candidate for fresh review.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct CandidateReady {
    /// Exact candidate identity.
    pub candidate: Candidate,
    /// Short completion summary.
    #[schemars(length(min = 1, max = 8_192))]
    pub summary: String,
    /// Evidence supporting the completion claim.
    #[schemars(length(max = MAX_EVIDENCE_ITEMS))]
    pub evidence: Vec<Evidence>,
}

impl Validate for CandidateReady {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("summary", &self.summary, 8_192)?;
        validate_evidence(&self.evidence)
    }
}

/// Review result for an exact candidate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    /// The exact candidate satisfies the review policy.
    Accepted,
    /// The exact candidate requires changes.
    Rejected,
}

/// The Primary's decision about an exact candidate.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewDecision {
    /// Stable decision identifier.
    pub decision_id: DecisionId,
    /// Exact candidate reviewed.
    pub candidate: Candidate,
    /// Accepted or rejected.
    pub verdict: ReviewVerdict,
    /// Fenced Primary generation issuing the decision.
    pub reviewer: ActorRef,
    /// Policy revision used by the review.
    pub policy_revision: PolicyRevision,
    /// Human-readable decision rationale.
    #[schemars(length(min = 1, max = 16_384))]
    pub rationale: String,
    /// Content-addressed review evidence.
    #[schemars(length(max = MAX_EVIDENCE_ITEMS))]
    pub evidence: Vec<Evidence>,
}

impl Validate for ReviewDecision {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("rationale", &self.rationale, 16_384)?;
        validate_evidence(&self.evidence)
    }
}

/// Instructions for replacing a rejected exact candidate.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct FixRequest {
    /// Rejected decision that prompted this request.
    pub decision_id: DecisionId,
    /// Rejected exact candidate.
    pub candidate: Candidate,
    /// Required changes.
    #[schemars(length(min = 1, max = 32_768))]
    pub instructions: String,
}

impl Validate for FixRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("instructions", &self.instructions, 32_768)
    }
}

/// QA outcome for an exact candidate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QaOutcome {
    /// The stated QA checks passed.
    Passed,
    /// One or more stated QA checks failed.
    Failed,
}

/// Provider-independent QA evidence.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct QaResult {
    /// Exact candidate checked.
    pub candidate: Candidate,
    /// Aggregate outcome.
    pub outcome: QaOutcome,
    /// Short QA summary.
    #[schemars(length(min = 1, max = 8_192))]
    pub summary: String,
    /// Content-addressed QA evidence.
    #[schemars(length(max = MAX_EVIDENCE_ITEMS))]
    pub evidence: Vec<Evidence>,
}

impl Validate for QaResult {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("summary", &self.summary, 8_192)?;
        validate_evidence(&self.evidence)
    }
}

/// Authorization to integrate one accepted exact candidate.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct IntegrationAuthorization {
    /// Accepted decision authorizing integration.
    pub decision_id: DecisionId,
    /// The only exact candidate authorized for integration.
    pub candidate: Candidate,
    /// Fenced Primary generation granting authorization.
    pub authorized_by: ActorRef,
}

/// Cancellation of a request or run.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Cancellation {
    /// Human-readable reason.
    #[schemars(length(min = 1, max = 8_192))]
    pub reason: String,
}

impl Validate for Cancellation {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("reason", &self.reason, 8_192)
    }
}

/// Scoped cross-team question.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ConsultationRequest {
    /// Stable consultation identifier, also usable for correlation.
    pub consultation_id: MessageId,
    /// Team being asked.
    pub target_team_id: TeamId,
    /// Short subject.
    #[schemars(length(min = 1, max = 256))]
    pub subject: String,
    /// Concrete question.
    #[schemars(length(min = 1, max = 16_384))]
    pub question: String,
    /// Supporting evidence.
    #[schemars(length(max = MAX_EVIDENCE_ITEMS))]
    pub evidence: Vec<Evidence>,
}

impl Validate for ConsultationRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("subject", &self.subject, 256)?;
        validate_text("question", &self.question, 16_384)?;
        validate_evidence(&self.evidence)
    }
}

/// Scoped answer to a cross-team consultation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ConsultationResponse {
    /// Consultation being answered.
    pub consultation_id: MessageId,
    /// Answering team.
    pub responding_team_id: TeamId,
    /// Concrete answer.
    #[schemars(length(min = 1, max = 16_384))]
    pub response: String,
    /// Supporting evidence.
    #[schemars(length(max = MAX_EVIDENCE_ITEMS))]
    pub evidence: Vec<Evidence>,
}

impl Validate for ConsultationResponse {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("response", &self.response, 16_384)?;
        validate_evidence(&self.evidence)
    }
}

/// Cross-team dependency declaration.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DependencyNotice {
    /// Request that is waiting.
    pub blocked_request_id: RequestId,
    /// Request whose output is required.
    pub depends_on_request_id: RequestId,
    /// Team expected to provide the dependency.
    pub provider_team_id: TeamId,
    /// Description of the required contract or artifact.
    #[schemars(length(min = 1, max = 8_192))]
    pub description: String,
}

impl Validate for DependencyNotice {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.blocked_request_id == self.depends_on_request_id {
            return Err(ValidationError::new(
                "depends_on_request_id",
                ValidationCode::Inconsistent,
                "a request cannot depend on itself",
            ));
        }
        validate_text("description", &self.description, 8_192)
    }
}

/// Potential or observed collision between teams.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ConflictNotice {
    /// Other team involved in the conflict.
    pub other_team_id: TeamId,
    /// Provider-neutral paths or logical resources in conflict.
    #[schemars(length(min = 1, max = MAX_CONFLICT_RESOURCES), inner(length(min = 1, max = 2_048)))]
    pub resources: Vec<String>,
    /// Description of the collision and its impact.
    #[schemars(length(min = 1, max = 8_192))]
    pub description: String,
}

impl Validate for ConflictNotice {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.resources.is_empty() {
            return Err(ValidationError::new(
                "resources",
                ValidationCode::Required,
                "must identify at least one conflicting resource",
            ));
        }
        validate_count("resources", self.resources.len(), MAX_CONFLICT_RESOURCES)?;
        for (index, resource) in self.resources.iter().enumerate() {
            validate_text(&format!("resources[{index}]"), resource, 2_048)?;
        }
        validate_text("description", &self.description, 8_192)
    }
}

/// Phase one of a request ownership handoff.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct HandoffOffer {
    /// Stable handoff transaction identifier.
    pub handoff_id: HandoffId,
    /// Request whose ownership is offered.
    pub request_id: RequestId,
    /// Current owning team.
    pub from_team_id: TeamId,
    /// Proposed new owning team.
    pub to_team_id: TeamId,
    /// Current exact candidate, if one exists.
    pub candidate: Option<Candidate>,
    /// Reason and expectations for the handoff.
    #[schemars(length(min = 1, max = 8_192))]
    pub reason: String,
}

impl Validate for HandoffOffer {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.from_team_id == self.to_team_id {
            return Err(ValidationError::new(
                "to_team_id",
                ValidationCode::Inconsistent,
                "handoff teams must be different",
            ));
        }
        validate_text("reason", &self.reason, 8_192)
    }
}

/// Phase two acceptance of a request ownership handoff.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct HandoffAcceptance {
    /// Offered handoff transaction.
    pub handoff_id: HandoffId,
    /// Request whose ownership is accepted.
    pub request_id: RequestId,
    /// Prior owning team.
    pub from_team_id: TeamId,
    /// Accepting team.
    pub to_team_id: TeamId,
    /// Fenced actor generation accepting the new assignment.
    pub accepted_by: ActorRef,
}

impl Validate for HandoffAcceptance {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.from_team_id == self.to_team_id {
            return Err(ValidationError::new(
                "to_team_id",
                ValidationCode::Inconsistent,
                "handoff teams must be different",
            ));
        }
        Ok(())
    }
}

/// Report that an authorized integration was completed externally.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct IntegrationComplete {
    /// Authorization used by the external integration tooling.
    pub decision_id: DecisionId,
    /// Exact candidate integrated.
    pub candidate: Candidate,
    /// Content-addressed integration evidence.
    #[schemars(length(max = MAX_EVIDENCE_ITEMS))]
    pub evidence: Vec<Evidence>,
}

impl Validate for IntegrationComplete {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_evidence(&self.evidence)
    }
}

/// Stable kind identifiers used by audit and filtering APIs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// Primary creates and assigns implementation work.
    ImplementationRequest,
    /// Assigned implementation reports progress.
    Progress,
    /// Assigned implementation reports a blocker.
    Blocker,
    /// Assigned implementation supplies an exact candidate.
    CandidateReady,
    /// Primary accepts or rejects the exact candidate.
    ReviewDecision,
    /// Primary specifies changes after rejection.
    FixRequest,
    /// Assigned implementation reports QA for the exact candidate.
    QaResult,
    /// Primary authorizes exact-SHA integration.
    IntegrationAuthorization,
    /// Primary cancels the request and run.
    Cancellation,
    /// A team asks another team a scoped question.
    ConsultationRequest,
    /// A team answers a scoped question.
    ConsultationResponse,
    /// A team declares a dependency on another request.
    DependencyNotice,
    /// A team reports a cross-team collision.
    ConflictNotice,
    /// Current owner proposes a handoff.
    HandoffOffer,
    /// Proposed owner accepts a handoff.
    HandoffAcceptance,
    /// External tooling reports authorized integration complete.
    IntegrationComplete,
}

/// Typed protocol payloads.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum Message {
    /// Primary creates and assigns implementation work.
    ImplementationRequest(ImplementationRequest),
    /// Assigned implementation reports progress.
    Progress(ProgressUpdate),
    /// Assigned implementation reports a blocker.
    Blocker(BlockerNotice),
    /// Assigned implementation supplies an exact candidate.
    CandidateReady(CandidateReady),
    /// Primary accepts or rejects the exact candidate.
    ReviewDecision(ReviewDecision),
    /// Primary specifies changes after rejection.
    FixRequest(FixRequest),
    /// Assigned implementation reports QA for the exact candidate.
    QaResult(QaResult),
    /// Primary authorizes exact-SHA integration without performing it.
    IntegrationAuthorization(IntegrationAuthorization),
    /// Primary cancels the request and run.
    Cancellation(Cancellation),
    /// A team asks another team a scoped question.
    ConsultationRequest(ConsultationRequest),
    /// A team answers a scoped question.
    ConsultationResponse(ConsultationResponse),
    /// A team declares a dependency on another request.
    DependencyNotice(DependencyNotice),
    /// A team reports a cross-team collision.
    ConflictNotice(ConflictNotice),
    /// Current owner proposes a handoff.
    HandoffOffer(HandoffOffer),
    /// Proposed owner accepts a handoff.
    HandoffAcceptance(HandoffAcceptance),
    /// External tooling reports an authorized integration complete.
    IntegrationComplete(IntegrationComplete),
}

impl Message {
    /// Returns the stable payload kind.
    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        match self {
            Self::ImplementationRequest(_) => MessageKind::ImplementationRequest,
            Self::Progress(_) => MessageKind::Progress,
            Self::Blocker(_) => MessageKind::Blocker,
            Self::CandidateReady(_) => MessageKind::CandidateReady,
            Self::ReviewDecision(_) => MessageKind::ReviewDecision,
            Self::FixRequest(_) => MessageKind::FixRequest,
            Self::QaResult(_) => MessageKind::QaResult,
            Self::IntegrationAuthorization(_) => MessageKind::IntegrationAuthorization,
            Self::Cancellation(_) => MessageKind::Cancellation,
            Self::ConsultationRequest(_) => MessageKind::ConsultationRequest,
            Self::ConsultationResponse(_) => MessageKind::ConsultationResponse,
            Self::DependencyNotice(_) => MessageKind::DependencyNotice,
            Self::ConflictNotice(_) => MessageKind::ConflictNotice,
            Self::HandoffOffer(_) => MessageKind::HandoffOffer,
            Self::HandoffAcceptance(_) => MessageKind::HandoffAcceptance,
            Self::IntegrationComplete(_) => MessageKind::IntegrationComplete,
        }
    }

    /// Whether normal handling requires request and run envelope context.
    #[must_use]
    pub const fn requires_request_context(&self) -> bool {
        matches!(
            self,
            Self::ImplementationRequest(_)
                | Self::Progress(_)
                | Self::Blocker(_)
                | Self::CandidateReady(_)
                | Self::ReviewDecision(_)
                | Self::FixRequest(_)
                | Self::QaResult(_)
                | Self::IntegrationAuthorization(_)
                | Self::Cancellation(_)
                | Self::DependencyNotice(_)
                | Self::HandoffOffer(_)
                | Self::HandoffAcceptance(_)
                | Self::IntegrationComplete(_)
        )
    }

    /// Returns the exact candidate bound into this message, if any.
    #[must_use]
    pub const fn candidate(&self) -> Option<&Candidate> {
        match self {
            Self::CandidateReady(value) => Some(&value.candidate),
            Self::ReviewDecision(value) => Some(&value.candidate),
            Self::FixRequest(value) => Some(&value.candidate),
            Self::QaResult(value) => Some(&value.candidate),
            Self::IntegrationAuthorization(value) => Some(&value.candidate),
            Self::IntegrationComplete(value) => Some(&value.candidate),
            Self::HandoffOffer(value) => value.candidate.as_ref(),
            Self::ImplementationRequest(_)
            | Self::Progress(_)
            | Self::Blocker(_)
            | Self::Cancellation(_)
            | Self::ConsultationRequest(_)
            | Self::ConsultationResponse(_)
            | Self::DependencyNotice(_)
            | Self::ConflictNotice(_)
            | Self::HandoffAcceptance(_) => None,
        }
    }
}

impl Validate for Message {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::ImplementationRequest(value) => value.validate(),
            Self::Progress(value) => value.validate(),
            Self::Blocker(value) => value.validate(),
            Self::CandidateReady(value) => value.validate(),
            Self::ReviewDecision(value) => value.validate(),
            Self::FixRequest(value) => value.validate(),
            Self::QaResult(value) => value.validate(),
            Self::IntegrationAuthorization(_) => Ok(()),
            Self::Cancellation(value) => value.validate(),
            Self::ConsultationRequest(value) => value.validate(),
            Self::ConsultationResponse(value) => value.validate(),
            Self::DependencyNotice(value) => value.validate(),
            Self::ConflictNotice(value) => value.validate(),
            Self::HandoffOffer(value) => value.validate(),
            Self::HandoffAcceptance(value) => value.validate(),
            Self::IntegrationComplete(value) => value.validate(),
        }
    }
}

/// Durable routing target.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "scope", content = "id", rename_all = "snake_case")]
pub enum MessageTarget {
    /// The active Primary generation.
    Primary,
    /// Any current implementation actor for a team.
    Team(TeamId),
    /// One logical actor (its current generation is checked at delivery).
    Actor(ActorId),
    /// All current actors in the workspace.
    Workspace,
}

/// Durable, deduplicated protocol envelope.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Envelope {
    /// Wire protocol version.
    pub protocol_version: u32,
    /// Globally stable idempotency key within the workspace.
    pub message_id: MessageId,
    /// Workspace scope.
    pub workspace_id: WorkspaceId,
    /// Fenced sender.
    pub sender: ActorRef,
    /// Durable routing target.
    pub target: MessageTarget,
    /// Team context. For implementation senders this is their team; for Primary
    /// messages it is the team affected by the command.
    pub team_id: Option<TeamId>,
    /// Run context for request-scoped messages.
    pub run_id: Option<RunId>,
    /// Request context for request-scoped messages.
    pub request_id: Option<RequestId>,
    /// Policy fence.
    pub policy_revision: PolicyRevision,
    /// Active Primary lease fence.
    pub primary_epoch: PrimaryEpoch,
    /// Team ownership fence when a team context is present.
    pub team_epoch: Option<TeamEpoch>,
    /// Assignment fence for messages from the assigned executor.
    pub assignment_epoch: Option<AssignmentEpoch>,
    /// Runtime-supplied event time.
    pub sent_at: TimestampMillis,
    /// Typed payload.
    pub message: Message,
}

impl Validate for Envelope {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ValidationError::new(
                "protocol_version",
                ValidationCode::UnsupportedVersion,
                format!("expected protocol version {PROTOCOL_VERSION}"),
            ));
        }
        match (&self.team_id, self.team_epoch) {
            (Some(_), Some(_)) | (None, None) => {}
            (Some(_), None) => {
                return Err(ValidationError::new(
                    "team_epoch",
                    ValidationCode::Required,
                    "team context requires a team epoch",
                ));
            }
            (None, Some(_)) => {
                return Err(ValidationError::new(
                    "team_epoch",
                    ValidationCode::Inconsistent,
                    "team epoch requires a team context",
                ));
            }
        }
        match (&self.request_id, &self.run_id) {
            (Some(_), Some(_)) | (None, None) => {}
            (Some(_), None) => {
                return Err(ValidationError::new(
                    "run_id",
                    ValidationCode::Required,
                    "request context requires a run id",
                ));
            }
            (None, Some(_)) => {
                return Err(ValidationError::new(
                    "request_id",
                    ValidationCode::Required,
                    "run context requires a request id",
                ));
            }
        }
        if self.message.requires_request_context()
            && (self.request_id.is_none() || self.run_id.is_none())
        {
            return Err(ValidationError::new(
                "request_id",
                ValidationCode::Required,
                "this message requires request and run context",
            ));
        }
        if self.assignment_epoch.is_some() && self.request_id.is_none() {
            return Err(ValidationError::new(
                "assignment_epoch",
                ValidationCode::Inconsistent,
                "assignment epoch requires request context",
            ));
        }
        if let (Some(request_id), Some(candidate)) = (&self.request_id, self.message.candidate()) {
            if candidate.request_id != *request_id {
                return Err(ValidationError::new(
                    "message.candidate.request_id",
                    ValidationCode::Inconsistent,
                    "candidate does not match envelope request",
                ));
            }
        }
        self.message.validate().map_err(|error| error.at("message"))
    }
}

/// Explicit durable acknowledgement of a delivered envelope.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Acknowledgement {
    /// Workspace containing the original message.
    pub workspace_id: WorkspaceId,
    /// Message being acknowledged.
    pub message_id: MessageId,
    /// Fenced actor generation acknowledging receipt.
    pub actor: ActorRef,
    /// Runtime-supplied acknowledgement time.
    pub acknowledged_at: TimestampMillis,
}

/// Top-level frames accepted by the durable mailbox.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "frame", content = "body", rename_all = "snake_case")]
pub enum WireFrame {
    /// A typed envelope.
    Envelope(Box<Envelope>),
    /// An explicit acknowledgement.
    Acknowledgement(Acknowledgement),
}

/// Persisted durable delivery and its acknowledgements.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DeliverySnapshot {
    /// Immutable accepted envelope.
    pub envelope: Envelope,
    /// At most one acknowledgement per logical actor.
    #[schemars(length(max = MAX_ACKNOWLEDGEMENTS))]
    pub acknowledgements: Vec<Acknowledgement>,
}

/// Persisted phase-one ownership handoff state.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct PendingHandoffSnapshot {
    /// Original offer.
    pub offer: HandoffOffer,
    /// Fenced actor that made the offer.
    pub offered_by: ActorRef,
    /// Assignment fence current when the offer was made.
    pub assignment_epoch: AssignmentEpoch,
}

/// Append-only, serializable audit record.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AuditEvent {
    /// Monotonic sequence within a workspace.
    pub sequence: u64,
    /// Runtime-supplied event time.
    pub occurred_at: TimestampMillis,
    /// Durable event details.
    pub kind: AuditEventKind,
}

/// Provider-independent audit event details.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum AuditEventKind {
    /// An envelope was accepted and applied.
    MessageAccepted {
        /// Accepted message id.
        message_id: MessageId,
        /// Stable payload kind.
        message_kind: MessageKind,
    },
    /// An eligible target acknowledged a message.
    MessageAcknowledged {
        /// Acknowledged message id.
        message_id: MessageId,
        /// Logical actor that acknowledged it.
        actor_id: ActorId,
    },
}

/// Persisted request state derived from accepted protocol messages.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Request {
    /// Stable request identifier.
    pub request_id: RequestId,
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// Current owning team.
    pub team_id: TeamId,
    /// Associated run.
    pub run_id: RunId,
    /// Original immutable work specification.
    pub specification: ImplementationRequest,
    /// Current lifecycle state.
    pub status: RequestStatus,
    /// Sole active assignment.
    pub assignment: Option<Assignment>,
    /// Current immutable candidate, replaced only after a rejection.
    pub candidate: Option<Candidate>,
    /// Decision for the current candidate, if reviewed.
    pub decision: Option<ReviewDecision>,
    /// Exact-SHA integration authorization, if granted.
    pub integration_authorization: Option<IntegrationAuthorization>,
}

/// State snapshot schema for persistence and external inspection.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DomainSnapshot {
    /// Workspace represented by the snapshot.
    pub workspace_id: WorkspaceId,
    /// Current policy fence.
    pub policy_revision: PolicyRevision,
    /// Current Primary lease fence.
    pub primary_epoch: PrimaryEpoch,
    /// Active Primary actor generation, if a lease is active.
    pub active_primary: Option<ActorRef>,
    /// Actors known to the workspace.
    #[schemars(length(max = MAX_DOMAIN_ENTITIES))]
    pub actors: Vec<Actor>,
    /// Teams known to the workspace.
    #[schemars(length(max = MAX_DOMAIN_ENTITIES))]
    pub teams: Vec<Team>,
    /// Requests known to the workspace.
    #[schemars(length(max = MAX_DOMAIN_ENTITIES))]
    pub requests: Vec<Request>,
    /// Runs known to the workspace.
    #[schemars(length(max = MAX_DOMAIN_ENTITIES))]
    pub runs: Vec<Run>,
    /// Durable accepted messages, including explicit acknowledgements.
    #[schemars(length(max = MAX_DELIVERIES))]
    pub deliveries: Vec<DeliverySnapshot>,
    /// Pending phase-one ownership handoffs.
    #[schemars(length(max = MAX_DOMAIN_ENTITIES))]
    pub pending_handoffs: Vec<PendingHandoffSnapshot>,
    /// Append-only audit history.
    #[schemars(length(max = MAX_AUDIT_EVENTS))]
    pub audit_events: Vec<AuditEvent>,
}

fn validate_evidence(evidence: &[Evidence]) -> Result<(), ValidationError> {
    validate_count("evidence", evidence.len(), MAX_EVIDENCE_ITEMS)?;
    for (index, item) in evidence.iter().enumerate() {
        item.validate()
            .map_err(|error| error.at(&format!("evidence[{index}]")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ConflictNotice, Envelope, ImplementationRequest, Message, MessageTarget, ProgressUpdate,
    };
    use crate::{
        ActorEpoch, ActorId, GitSha, MessageId, PolicyRevision, PrimaryEpoch, TimestampMillis,
        Validate, WorkspaceId,
    };

    #[test]
    fn envelope_requires_context_for_request_messages() {
        let envelope = Envelope {
            protocol_version: 1,
            message_id: MessageId::new("message-1").expect("valid id"),
            workspace_id: WorkspaceId::new("workspace-1").expect("valid id"),
            sender: super::ActorRef {
                actor_id: ActorId::new("actor-1").expect("valid id"),
                actor_epoch: ActorEpoch::INITIAL,
            },
            target: MessageTarget::Primary,
            team_id: None,
            run_id: None,
            request_id: None,
            policy_revision: PolicyRevision::INITIAL,
            primary_epoch: PrimaryEpoch::INITIAL,
            team_epoch: None,
            assignment_epoch: None,
            sent_at: TimestampMillis(1),
            message: Message::Progress(ProgressUpdate {
                summary: "working".to_owned(),
                percent_complete: Some(20),
                evidence: Vec::new(),
            }),
        };

        assert!(envelope.validate().is_err());
    }

    #[test]
    fn runtime_collection_and_percentage_bounds_match_the_protocol() {
        let progress = ProgressUpdate {
            summary: "working".to_owned(),
            percent_complete: Some(101),
            evidence: Vec::new(),
        };
        assert!(progress.validate().is_err());

        let request = ImplementationRequest {
            title: "bounded request".to_owned(),
            instructions: "perform the work".to_owned(),
            base_sha: GitSha::new("0".repeat(40)).expect("valid sha"),
            acceptance_criteria: vec!["criterion".to_owned(); 65],
            evidence_requirements: Vec::new(),
        };
        assert!(request.validate().is_err());

        let conflict = ConflictNotice {
            other_team_id: crate::TeamId::new("other-team").expect("valid id"),
            resources: vec!["resource".to_owned(); 257],
            description: "bounded conflict".to_owned(),
        };
        assert!(conflict.validate().is_err());
    }
}
