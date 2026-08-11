//! Serializable provider-independent protocol and persisted-state types.

use crate::PROTOCOL_VERSION;
use crate::ids::{
    ActorEpoch, ActorId, ActorProfileName, AssignmentEpoch, AssignmentPolicyId, CapabilityId,
    DecisionId, EvidenceId, GitSha, HandoffId, MessageId, PolicyRevision, PrimaryEpoch, RequestId,
    RunId, TeamEpoch, TeamId, TeamProfileName, TimestampMillis, WorkspaceId,
};
use crate::validation::{
    MAX_ACCEPTANCE_CRITERIA, MAX_ACKNOWLEDGEMENTS, MAX_ACTOR_CAPABILITIES, MAX_AUDIT_EVENTS,
    MAX_CONFLICT_RESOURCES, MAX_DELIVERIES, MAX_DOMAIN_ENTITIES, MAX_EVIDENCE_ITEMS,
    MAX_EVIDENCE_REQUIREMENTS, MAX_REQUEST_TEXT_CHARACTERS, Validate, ValidationCode,
    ValidationError, validate_count, validate_text,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

/// A currently registered actor generation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ActorRef {
    /// Stable logical actor identifier.
    pub actor_id: ActorId,
    /// Process-generation fence for the actor identifier.
    pub actor_epoch: ActorEpoch,
}

/// The provider-independent, project-defined responsibility of an actor.
///
/// The two named variants preserve source compatibility for v0.1 callers.
/// Every additional role is represented by [`Self::Custom`] without changing
/// the protocol type for each new project-defined responsibility.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ActorRole {
    /// The single human-facing owner of intent and approval.
    Primary,
    /// A top-level implementation orchestrator assigned to one team.
    Implementation,
    /// Any additional project-defined responsibility.
    Custom(String),
}

impl ActorRole {
    /// Creates a validated role while preserving the v0.1 role spellings.
    ///
    /// # Errors
    ///
    /// Returns an error when the role is blank, has surrounding whitespace or
    /// control characters, or exceeds the persisted length bound.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        validate_actor_role(&value)?;
        Ok(match value.as_str() {
            "primary" => Self::Primary,
            "implementation" => Self::Implementation,
            _ => Self::Custom(value),
        })
    }

    /// Returns the stable JSON representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Primary => "primary",
            Self::Implementation => "implementation",
            Self::Custom(value) => value,
        }
    }

    fn validate(&self) -> Result<(), ValidationError> {
        validate_actor_role(self.as_str())?;
        if let Self::Custom(value) = self
            && matches!(value.as_str(), "primary" | "implementation")
        {
            return Err(ValidationError::new(
                "actor_role",
                ValidationCode::Inconsistent,
                "legacy role spellings must use their canonical representation",
            ));
        }
        Ok(())
    }
}

impl Display for ActorRole {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ActorRole {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ActorRole {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for ActorRole {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ActorRole {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for ActorRole {
    fn schema_name() -> Cow<'static, str> {
        "ActorRole".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A provider-independent, project-defined actor responsibility.",
            "type": "string",
            "minLength": 1,
            "maxLength": 128
        })
    }
}

fn validate_actor_role(value: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::new(
            "actor_role",
            ValidationCode::Required,
            "must not be empty",
        ));
    }
    if value.len() > 128 {
        return Err(ValidationError::new(
            "actor_role",
            ValidationCode::OutOfRange,
            "must contain at most 128 bytes",
        ));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ValidationError::new(
            "actor_role",
            ValidationCode::InvalidFormat,
            "must contain no surrounding whitespace or control characters",
        ));
    }
    Ok(())
}

/// Capability that permits the sole active human-facing Primary lease and
/// the existing Primary-authorized protocol operations.
pub const HUMAN_FACING_PRIMARY_CAPABILITY: &str = "human_facing_primary";

/// Capability that permits assignment and the existing implementation
/// execution protocol operations.
pub const IMPLEMENTATION_EXECUTION_CAPABILITY: &str = "implementation_execution";

/// Provider-neutral authorization metadata frozen onto an actor generation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ActorProfileSnapshot {
    /// Selected project actor profile.
    pub name: ActorProfileName,
    /// Extensible set of policy capabilities. Unknown values are preserved.
    #[schemars(length(max = MAX_ACTOR_CAPABILITIES))]
    pub capabilities: BTreeSet<CapabilityId>,
}

impl ActorProfileSnapshot {
    /// Returns whether this configured profile carries a capability.
    #[must_use]
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities
            .iter()
            .any(|candidate| candidate.as_str() == capability)
    }
}

impl Validate for ActorProfileSnapshot {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_count(
            "capabilities",
            self.capabilities.len(),
            MAX_ACTOR_CAPABILITIES,
        )
    }
}

/// Provider-neutral team profile metadata frozen when a team is created.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct TeamProfileSnapshot {
    /// Selected project team profile.
    pub name: TeamProfileName,
    /// Actor profile used for the team's orchestrators.
    pub actor_profile: ActorProfileName,
    /// Desired persistent instances. Zero declaratively disables the profile.
    #[schemars(range(max = 1_024))]
    pub desired_instances: u16,
    /// Configured assignment policy interpreted by the control-plane policy engine.
    pub assignment_policy: AssignmentPolicyId,
}

impl Validate for TeamProfileSnapshot {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.desired_instances > 1_024 {
            return Err(ValidationError::new(
                "desired_instances",
                ValidationCode::OutOfRange,
                "must be at most 1024",
            ));
        }
        Ok(())
    }
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
    /// Owning team when registered to one. An active Primary lease holder must
    /// remain teamless.
    pub team_id: Option<TeamId>,
    /// Descriptive project responsibility. Configured authorization comes from
    /// the profile capability snapshot, not this string.
    pub role: ActorRole,
    /// Selected profile and capability snapshot. Absence is reserved for
    /// persisted v0.1 state and enables only the two legacy role mappings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ActorProfileSnapshot>,
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

    /// Returns whether this actor carries an authorization capability.
    ///
    /// Configured profiles use their capability set exclusively. The role
    /// fallback exists only for profile-less v0.1 snapshots.
    #[must_use]
    pub fn has_capability(&self, capability: &str) -> bool {
        self.profile.as_ref().map_or_else(
            || match capability {
                HUMAN_FACING_PRIMARY_CAPABILITY => self.role == ActorRole::Primary,
                IMPLEMENTATION_EXECUTION_CAPABILITY => self.role == ActorRole::Implementation,
                _ => false,
            },
            |profile| profile.has_capability(capability),
        )
    }
}

impl Validate for Actor {
    fn validate(&self) -> Result<(), ValidationError> {
        self.role.validate().map_err(|error| error.at("role"))?;
        if let Some(profile) = &self.profile {
            profile.validate().map_err(|error| error.at("profile"))?;
        }
        if self.profile.is_none() {
            match (&self.role, &self.team_id) {
                (ActorRole::Primary, None) | (ActorRole::Implementation, Some(_)) => Ok(()),
                (ActorRole::Primary, Some(_)) => Err(ValidationError::new(
                    "team_id",
                    ValidationCode::Inconsistent,
                    "a legacy Primary actor cannot belong to a team",
                )),
                (ActorRole::Implementation, None) => Err(ValidationError::new(
                    "team_id",
                    ValidationCode::Required,
                    "a legacy Implementation actor must belong to a team",
                )),
                (ActorRole::Custom(_), _) => Err(ValidationError::new(
                    "profile",
                    ValidationCode::Required,
                    "a custom role requires configured profile metadata",
                )),
            }
        } else {
            Ok(())
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
    /// No longer receives new work and will close after blocking requests drain.
    Closing,
    /// Terminal state for a team that completed its close lifecycle.
    Closed,
    /// Legacy terminal team state retained for persisted v0.1 compatibility.
    Retired,
}

/// A provider-independent orchestrator team.
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
    /// Registered logical team actors.
    #[schemars(length(max = MAX_DOMAIN_ENTITIES))]
    pub actors: Vec<ActorId>,
    /// Selected team profile snapshot. Absence is reserved for v0.1 state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<TeamProfileSnapshot>,
}

impl Validate for Team {
    fn validate(&self) -> Result<(), ValidationError> {
        if let Some(profile) = &self.profile {
            profile.validate().map_err(|error| error.at("profile"))?;
        }
        validate_count("actors", self.actors.len(), MAX_DOMAIN_ENTITIES)
    }
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

/// Returns whether a request prevents its owning team from closing.
///
/// This intentionally differs from [`RequestStatus::is_terminal`]: accepted
/// and integration-authorized work no longer need an implementation team even
/// before reaching terminal completion. Completed and cancelled work also do
/// not block closing, while a candidate awaiting review still does. Team-close
/// policy must use this predicate instead of request terminality.
#[must_use]
pub const fn request_blocks_team_close(status: RequestStatus) -> bool {
    !matches!(
        status,
        RequestStatus::Accepted
            | RequestStatus::IntegrationAuthorized
            | RequestStatus::Cancelled
            | RequestStatus::Completed
    )
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
    /// Configured actor profile that produced the candidate. Absence represents
    /// a profile-less legacy actor or persisted pre-attribution candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by_profile: Option<ActorProfileName>,
}

/// Work requested by the active Primary.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ImplementationRequest {
    /// Human-readable short title.
    #[schemars(length(min = 1, max = 256))]
    pub title: String,
    /// Complete implementation instructions.
    #[schemars(length(min = 1, max = MAX_REQUEST_TEXT_CHARACTERS))]
    pub instructions: String,
    /// Exact commit from which work should begin.
    pub base_sha: GitSha,
    /// Verifiable completion criteria.
    #[schemars(length(min = 1, max = MAX_ACCEPTANCE_CRITERIA), inner(length(min = 1, max = MAX_REQUEST_TEXT_CHARACTERS)))]
    pub acceptance_criteria: Vec<String>,
    /// Evidence categories the implementation must return.
    #[schemars(length(max = MAX_EVIDENCE_REQUIREMENTS))]
    pub evidence_requirements: Vec<EvidenceKind>,
}

impl Validate for ImplementationRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("title", &self.title, 256)?;
        validate_text(
            "instructions",
            &self.instructions,
            MAX_REQUEST_TEXT_CHARACTERS,
        )?;
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
            validate_text(
                &format!("acceptance_criteria[{index}]"),
                criterion,
                MAX_REQUEST_TEXT_CHARACTERS,
            )?;
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

/// Primary-authenticated control applied to a request's run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunControlAction {
    /// Pause active execution without changing the request lifecycle state.
    Pause,
    /// Resume execution and move the request back to in-progress work.
    Resume,
}

/// Typed request-scoped run lifecycle command.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct RunControl {
    /// Requested run lifecycle operation.
    pub action: RunControlAction,
}

/// A Primary decision that durably constrains a team's work.
///
/// The envelope supplies the affected team, optional request/run scope, fenced
/// Primary identity, and logical addressee. This payload holds only the binding
/// decision and the concise rationale for it.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct PrimaryDirective {
    /// Concrete decision that the addressed team or actor must follow.
    #[schemars(length(min = 1, max = 8_192))]
    pub decision: String,
    /// Concise reason the decision was made.
    #[schemars(length(min = 1, max = 16_384))]
    pub rationale: String,
}

impl Validate for PrimaryDirective {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("decision", &self.decision, 8_192)?;
        validate_text("rationale", &self.rationale, 16_384)
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
    /// Primary pauses or resumes a request's run.
    RunControl,
    /// Primary records and delivers a binding team or request decision.
    Directive,
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

/// Required close-time handling for unread deliveries to a team actor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TeamCloseDeliveryDisposition {
    /// The message records an outcome already committed elsewhere and may be
    /// retired when the recipient becomes unreachable.
    ObsoleteOutcome,
    /// The message's remaining work is represented by its request lifecycle;
    /// once that request no longer blocks close, the delivery is obsolete.
    RequestLifecycle,
    /// The message asks the recipient to do or consider future work and must
    /// block close until it is acknowledged.
    ActionRequired,
}

impl MessageKind {
    /// Classifies unread team-recipient delivery at the close boundary.
    ///
    /// This exhaustive match is the protocol interface between durable message
    /// semantics and team lifecycle. Outcome/report messages have already taken
    /// effect in durable state; instruction/coordination messages still require
    /// the team's attention before it can safely disappear.
    #[must_use]
    pub const fn team_close_disposition(self) -> TeamCloseDeliveryDisposition {
        match self {
            Self::Progress
            | Self::Blocker
            | Self::CandidateReady
            | Self::ReviewDecision
            | Self::QaResult
            | Self::IntegrationAuthorization
            | Self::Cancellation
            | Self::ConsultationResponse
            | Self::HandoffAcceptance
            | Self::IntegrationComplete => TeamCloseDeliveryDisposition::ObsoleteOutcome,
            Self::ImplementationRequest | Self::FixRequest | Self::RunControl => {
                TeamCloseDeliveryDisposition::RequestLifecycle
            }
            Self::Directive
            | Self::ConsultationRequest
            | Self::DependencyNotice
            | Self::ConflictNotice
            | Self::HandoffOffer => TeamCloseDeliveryDisposition::ActionRequired,
        }
    }
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
    /// Primary pauses or resumes a request's run.
    RunControl(RunControl),
    /// Primary records and delivers a binding team or request decision.
    Directive(PrimaryDirective),
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
            Self::RunControl(_) => MessageKind::RunControl,
            Self::Directive(_) => MessageKind::Directive,
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
                | Self::RunControl(_)
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
            | Self::RunControl(_)
            | Self::Directive(_)
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
            Self::IntegrationAuthorization(_) | Self::RunControl(_) => Ok(()),
            Self::Cancellation(value) => value.validate(),
            Self::Directive(value) => value.validate(),
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
        if matches!(self.message, Message::Directive(_)) && self.team_id.is_none() {
            return Err(ValidationError::new(
                "team_id",
                ValidationCode::Required,
                "a Primary directive requires team context",
            ));
        }
        if matches!(self.message, Message::Directive(_)) && self.assignment_epoch.is_some() {
            return Err(ValidationError::new(
                "assignment_epoch",
                ValidationCode::Inconsistent,
                "a Primary directive is fenced by Primary, policy, team, and request context",
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

/// SHA-256 digest of canonical serialized protocol bulk content.
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct PayloadDigest {
    /// Lowercase 256-bit hexadecimal SHA-256 digest.
    #[schemars(length(equal = 64), regex(pattern = "^[0-9a-f]{64}$"))]
    pub sha256: String,
}

impl PayloadDigest {
    /// Creates a validated SHA-256 payload digest.
    ///
    /// # Errors
    ///
    /// Returns an invalid-format error unless the value is exactly 64 lowercase
    /// hexadecimal digits.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let digest = Self {
            sha256: value.into(),
        };
        digest.validate()?;
        Ok(digest)
    }

    /// Returns the lowercase hexadecimal representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.sha256
    }
}

impl Validate for PayloadDigest {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(ValidationError::new(
                "sha256",
                ValidationCode::InvalidFormat,
                "must be exactly 64 lowercase hexadecimal digits",
            ));
        }
        Ok(())
    }
}

/// Text-free immutable envelope metadata retained in the hot snapshot.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct EnvelopeHeader {
    /// Wire protocol version.
    pub protocol_version: u32,
    /// Globally stable idempotency key within the workspace.
    pub message_id: MessageId,
    /// Workspace scope.
    pub workspace_id: WorkspaceId,
    /// Fenced sender.
    pub sender: ActorRef,
    /// Frozen logical routing target.
    pub target: MessageTarget,
    /// Team context.
    pub team_id: Option<TeamId>,
    /// Run context.
    pub run_id: Option<RunId>,
    /// Request context.
    pub request_id: Option<RequestId>,
    /// Policy fence.
    pub policy_revision: PolicyRevision,
    /// Active Primary lease fence.
    pub primary_epoch: PrimaryEpoch,
    /// Team ownership fence.
    pub team_epoch: Option<TeamEpoch>,
    /// Assignment fence.
    pub assignment_epoch: Option<AssignmentEpoch>,
    /// Runtime-supplied event time.
    pub sent_at: TimestampMillis,
}

impl EnvelopeHeader {
    /// Reconstructs a wire envelope after its digest-verified message is hydrated.
    #[must_use]
    pub fn with_message(&self, message: Message) -> Envelope {
        Envelope {
            protocol_version: self.protocol_version,
            message_id: self.message_id.clone(),
            workspace_id: self.workspace_id.clone(),
            sender: self.sender.clone(),
            target: self.target.clone(),
            team_id: self.team_id.clone(),
            run_id: self.run_id.clone(),
            request_id: self.request_id.clone(),
            policy_revision: self.policy_revision,
            primary_epoch: self.primary_epoch,
            team_epoch: self.team_epoch,
            assignment_epoch: self.assignment_epoch,
            sent_at: self.sent_at,
            message,
        }
    }
}

impl From<&Envelope> for EnvelopeHeader {
    fn from(envelope: &Envelope) -> Self {
        Self {
            protocol_version: envelope.protocol_version,
            message_id: envelope.message_id.clone(),
            workspace_id: envelope.workspace_id.clone(),
            sender: envelope.sender.clone(),
            target: envelope.target.clone(),
            team_id: envelope.team_id.clone(),
            run_id: envelope.run_id.clone(),
            request_id: envelope.request_id.clone(),
            policy_revision: envelope.policy_revision,
            primary_epoch: envelope.primary_epoch,
            team_epoch: envelope.team_epoch,
            assignment_epoch: envelope.assignment_epoch,
            sent_at: envelope.sent_at,
        }
    }
}

/// Compact reference to an accepted implementation specification.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct RequestSpecificationRef {
    /// Message that supplied the full specification.
    pub message_id: MessageId,
    /// SHA-256 digest of the full [`Message::ImplementationRequest`] payload.
    pub payload_digest: PayloadDigest,
    /// Exact commit from which work should begin; required by candidate verification.
    pub base_sha: GitSha,
}

/// Compact reference to an accepted review decision.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewDecisionRef {
    /// Message that supplied the full rationale and evidence.
    pub message_id: MessageId,
    /// SHA-256 digest of the full [`Message::ReviewDecision`] payload.
    pub payload_digest: PayloadDigest,
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
}

/// Text-free phase-one handoff facts retained in the hot snapshot.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct HandoffOfferRef {
    /// Message that supplied the full handoff reason.
    pub message_id: MessageId,
    /// SHA-256 digest of the full [`Message::HandoffOffer`] payload.
    pub payload_digest: PayloadDigest,
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
}

/// Text-free message facts required to replay authorization and state transitions.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", content = "facts", rename_all = "snake_case")]
pub enum CausalMessage {
    /// Primary creates and assigns work from the referenced specification.
    ImplementationRequest { base_sha: GitSha },
    /// Assigned implementation resumed progress.
    Progress,
    /// Assigned implementation reported a blocker.
    Blocker,
    /// Assigned implementation supplied an exact candidate.
    CandidateReady { candidate: Candidate },
    /// Primary reviewed an exact candidate.
    ReviewDecision(ReviewDecisionRef),
    /// Primary requested fixes for a rejected decision.
    FixRequest {
        decision_id: DecisionId,
        candidate: Candidate,
    },
    /// Assigned implementation reported QA for a candidate.
    QaResult {
        candidate: Candidate,
        outcome: QaOutcome,
    },
    /// Primary authorized exact-candidate integration.
    IntegrationAuthorization(IntegrationAuthorization),
    /// Primary cancelled request execution.
    Cancellation,
    /// Primary controlled the run lifecycle.
    RunControl { action: RunControlAction },
    /// Primary recorded and delivered a binding decision.
    Directive,
    /// A scoped consultation was opened.
    ConsultationRequest {
        consultation_id: MessageId,
        target_team_id: TeamId,
    },
    /// A scoped consultation was answered.
    ConsultationResponse {
        consultation_id: MessageId,
        responding_team_id: TeamId,
    },
    /// A cross-team dependency was declared.
    DependencyNotice {
        blocked_request_id: RequestId,
        depends_on_request_id: RequestId,
        provider_team_id: TeamId,
    },
    /// A cross-team conflict was declared.
    ConflictNotice { other_team_id: TeamId },
    /// Phase-one handoff facts.
    HandoffOffer(HandoffOfferRef),
    /// Phase-two handoff acceptance facts.
    HandoffAcceptance(HandoffAcceptance),
    /// Externally completed integration facts.
    IntegrationComplete {
        decision_id: DecisionId,
        candidate: Candidate,
    },
}

impl CausalMessage {
    /// Returns the corresponding stable wire-message kind.
    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        match self {
            Self::ImplementationRequest { .. } => MessageKind::ImplementationRequest,
            Self::Progress => MessageKind::Progress,
            Self::Blocker => MessageKind::Blocker,
            Self::CandidateReady { .. } => MessageKind::CandidateReady,
            Self::ReviewDecision(_) => MessageKind::ReviewDecision,
            Self::FixRequest { .. } => MessageKind::FixRequest,
            Self::QaResult { .. } => MessageKind::QaResult,
            Self::IntegrationAuthorization(_) => MessageKind::IntegrationAuthorization,
            Self::Cancellation => MessageKind::Cancellation,
            Self::RunControl { .. } => MessageKind::RunControl,
            Self::Directive => MessageKind::Directive,
            Self::ConsultationRequest { .. } => MessageKind::ConsultationRequest,
            Self::ConsultationResponse { .. } => MessageKind::ConsultationResponse,
            Self::DependencyNotice { .. } => MessageKind::DependencyNotice,
            Self::ConflictNotice { .. } => MessageKind::ConflictNotice,
            Self::HandoffOffer(_) => MessageKind::HandoffOffer,
            Self::HandoffAcceptance(_) => MessageKind::HandoffAcceptance,
            Self::IntegrationComplete { .. } => MessageKind::IntegrationComplete,
        }
    }
}

/// Frozen logical acknowledgement requirement for one accepted message.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "scope", content = "actor_id", rename_all = "snake_case")]
pub enum DeliveryRecipient {
    /// The logical active-Primary slot, independent of actor replacement.
    Primary,
    /// One logical actor identifier.
    Actor(ActorId),
}

/// Durable reason one frozen logical recipient no longer needs to acknowledge.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DeliveryRetirementReason {
    /// The recipient's team closed before it acknowledged the delivery.
    TeamClosed {
        /// Team whose terminal lifecycle made the recipient unreachable.
        team_id: TeamId,
    },
}

/// Durable disposition for one frozen recipient that became unreachable.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct UndeliverableRecipient {
    /// Frozen logical recipient whose acknowledgement was waived.
    pub recipient: DeliveryRecipient,
    /// Auditable reason delivery to this recipient became impossible.
    pub reason: DeliveryRetirementReason,
}

/// Persisted compact accepted-message history and delivery state.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DeliverySnapshot {
    /// Immutable text-free envelope header.
    pub envelope: EnvelopeHeader,
    /// Stable full-payload kind.
    pub message_kind: MessageKind,
    /// SHA-256 digest of the full serialized [`Message`].
    pub payload_digest: PayloadDigest,
    /// Text-free semantic facts used for causal replay.
    pub causal: CausalMessage,
    /// Frozen logical recipients whose acknowledgements are required.
    #[schemars(length(max = MAX_ACKNOWLEDGEMENTS))]
    pub required_recipients: BTreeSet<DeliveryRecipient>,
    /// At most one acknowledgement per frozen logical recipient.
    #[schemars(length(max = MAX_ACKNOWLEDGEMENTS))]
    pub acknowledgements: Vec<Acknowledgement>,
    /// Frozen recipients durably waived because delivery became impossible.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = MAX_ACKNOWLEDGEMENTS))]
    pub undeliverable_recipients: Vec<UndeliverableRecipient>,
    /// Delivery-level terminal disposition when no logical recipient remains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retirement_reason: Option<DeliveryRetirementReason>,
    /// Whether fully resolved history is no longer visible in a live inbox.
    pub retired: bool,
}

/// Persisted compact phase-one ownership handoff state.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct PendingHandoffSnapshot {
    /// Text-free original offer facts.
    pub offer: HandoffOfferRef,
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
        /// SHA-256 payload digest duplicated into audit provenance.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        payload_digest: Option<PayloadDigest>,
    },
    /// An eligible target acknowledged a message.
    MessageAcknowledged {
        /// Acknowledged message id.
        message_id: MessageId,
        /// Logical actor that acknowledged it.
        actor_id: ActorId,
    },
}

/// Bounded bridge between the hot snapshot and externally archived compact history.
///
/// Ordinary restore compares these totals and rolling head with an atomically
/// updated archive manifest in work independent of archive size. Explicit
/// integrity diagnostics stream-verify the external append-only rows and commit
/// chain without rehydrating them into the hot domain snapshot.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct HistoryCheckpoint {
    /// Total audit events accepted over the workspace lifetime, hot and archived.
    pub audit_event_count: u64,
    /// SHA-256 of the canonical serialized final audit event, when any exists.
    pub audit_head_sha256: Option<PayloadDigest>,
    /// Compact delivery rows externalized from the hot snapshot.
    pub archived_delivery_count: u64,
    /// Terminal request rows externalized from the hot snapshot.
    pub archived_request_count: u64,
    /// Terminal run rows externalized from the hot snapshot.
    pub archived_run_count: u64,
    /// Audit rows externalized from the hot snapshot.
    pub archived_audit_event_count: u64,
    /// Number of non-empty atomic commits in the external archive chain.
    pub archive_commit_count: u64,
    /// SHA-256 rolling head of the external archive commit chain.
    pub archive_head_sha256: Option<PayloadDigest>,
}

impl HistoryCheckpoint {
    /// Returns whether no history or external archive is represented.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
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
    /// Compact reference to the original immutable work specification.
    pub specification: RequestSpecificationRef,
    /// Current lifecycle state.
    pub status: RequestStatus,
    /// Sole active assignment.
    pub assignment: Option<Assignment>,
    /// Current immutable candidate, replaced only after a rejection.
    pub candidate: Option<Candidate>,
    /// Compact decision facts for the current candidate, if reviewed.
    pub decision: Option<ReviewDecisionRef>,
    /// Exact-SHA integration authorization, if granted.
    pub integration_authorization: Option<IntegrationAuthorization>,
    /// Number of distinct rejected review decisions observed for this request.
    #[serde(default)]
    pub rejection_count: u64,
    /// Number of changed candidates submitted after a rejected review.
    #[serde(default)]
    pub fix_cycle_depth: u64,
    /// Ordered history of initial and changed post-rejection candidates.
    #[serde(default)]
    #[schemars(length(max = MAX_DOMAIN_ENTITIES))]
    pub candidate_history: Vec<Candidate>,
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
    /// Verified totals connecting bounded hot state to external compact history.
    #[serde(default, skip_serializing_if = "HistoryCheckpoint::is_empty")]
    pub history_checkpoint: HistoryCheckpoint,
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
        Actor, ActorProfileSnapshot, ActorRole, ConflictNotice, Envelope,
        HUMAN_FACING_PRIMARY_CAPABILITY, ImplementationRequest, Message, MessageTarget,
        PrimaryDirective, ProgressUpdate, TeamCloseDeliveryDisposition, TeamProfileSnapshot,
    };
    use crate::{
        ActorEpoch, ActorId, ActorProfileName, ActorStatus, AssignmentPolicyId, GitSha,
        MAX_REQUEST_TEXT_CHARACTERS, MessageId, MessageKind, PolicyRevision, PrimaryEpoch,
        TeamEpoch, TeamId, TeamProfileName, TimestampMillis, Validate, ValidationCode,
        ValidationUnit, WorkspaceId,
    };
    use std::collections::BTreeSet;

    #[test]
    fn actor_roles_round_trip_as_open_json_strings() {
        for value in [
            "primary",
            "implementation",
            "research",
            "release coordination",
        ] {
            let role = ActorRole::new(value).expect("role is valid");
            assert_eq!(role.as_str(), value);
            assert_eq!(
                serde_json::to_value(&role).expect("role serializes"),
                serde_json::json!(value)
            );
            assert_eq!(
                serde_json::from_value::<ActorRole>(serde_json::json!(value))
                    .expect("role deserializes"),
                role
            );
        }
        assert!(ActorRole::new(" research ").is_err());
    }

    #[test]
    fn configured_empty_capabilities_do_not_inherit_legacy_role_privileges() {
        let actor = Actor {
            actor_id: ActorId::new("researcher").expect("valid id"),
            workspace_id: WorkspaceId::new("workspace").expect("valid id"),
            team_id: Some(TeamId::new("research-team").expect("valid id")),
            role: ActorRole::Primary,
            profile: Some(ActorProfileSnapshot {
                name: ActorProfileName::new("research").expect("valid profile"),
                capabilities: BTreeSet::new(),
            }),
            epoch: ActorEpoch::INITIAL,
            status: ActorStatus::Healthy,
            last_heartbeat_at: None,
        };

        actor
            .validate()
            .expect("configured topology is policy-neutral");
        assert!(!actor.has_capability(HUMAN_FACING_PRIMARY_CAPABILITY));
    }

    #[test]
    fn team_profile_accepts_zero_instances_and_bounds_future_reconciliation() {
        let profile = |desired_instances| TeamProfileSnapshot {
            name: TeamProfileName::new("research").expect("valid profile"),
            actor_profile: ActorProfileName::new("research").expect("valid actor profile"),
            desired_instances,
            assignment_policy: AssignmentPolicyId::new("least_wip").expect("valid policy"),
        };

        profile(0).validate().expect("zero declaratively disables");
        profile(1_024).validate().expect("maximum is accepted");
        assert!(profile(1_025).validate().is_err());
    }

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
    fn directive_wire_kind_and_team_or_request_scope_are_explicit() {
        let envelope = Envelope {
            protocol_version: 1,
            message_id: MessageId::new("directive-1").expect("valid id"),
            workspace_id: WorkspaceId::new("workspace-1").expect("valid id"),
            sender: super::ActorRef {
                actor_id: ActorId::new("primary-1").expect("valid id"),
                actor_epoch: ActorEpoch::INITIAL,
            },
            target: MessageTarget::Team(TeamId::new("team-1").expect("valid id")),
            team_id: Some(TeamId::new("team-1").expect("valid id")),
            run_id: None,
            request_id: None,
            policy_revision: PolicyRevision::INITIAL,
            primary_epoch: PrimaryEpoch::INITIAL,
            team_epoch: Some(TeamEpoch::INITIAL),
            assignment_epoch: None,
            sent_at: TimestampMillis(1),
            message: Message::Directive(PrimaryDirective {
                decision: "reserve schema version 7 for this team".to_owned(),
                rationale: "parallel migrations require one durable owner".to_owned(),
            }),
        };

        envelope
            .validate()
            .expect("team-scoped directive validates");
        let encoded = serde_json::to_value(&envelope).expect("directive serializes");
        assert_eq!(encoded["message"]["kind"], "directive");
        assert_eq!(
            encoded["message"]["payload"]["decision"],
            "reserve schema version 7 for this team"
        );

        let mut request_scoped = envelope.clone();
        request_scoped.request_id = Some(crate::RequestId::new("request-1").expect("valid id"));
        request_scoped.run_id = Some(crate::RunId::new("run-1").expect("valid id"));
        request_scoped
            .validate()
            .expect("request-scoped directive validates");

        let mut executor_fenced = request_scoped;
        executor_fenced.assignment_epoch = Some(crate::AssignmentEpoch::INITIAL);
        assert!(executor_fenced.validate().is_err());

        let mut unscoped = envelope.clone();
        unscoped.team_id = None;
        unscoped.team_epoch = None;
        assert!(unscoped.validate().is_err());

        let mut incomplete_request_scope = envelope.clone();
        incomplete_request_scope.request_id =
            Some(crate::RequestId::new("request-without-run").expect("valid request id"));
        assert!(incomplete_request_scope.validate().is_err());

        let mut empty_decision = envelope;
        let Message::Directive(directive) = &mut empty_decision.message else {
            unreachable!("fixture is a directive")
        };
        directive.decision.clear();
        assert!(empty_decision.validate().is_err());
    }

    #[test]
    fn team_close_delivery_classification_is_exhaustive_and_explicit() {
        for kind in [
            MessageKind::Progress,
            MessageKind::Blocker,
            MessageKind::CandidateReady,
            MessageKind::ReviewDecision,
            MessageKind::QaResult,
            MessageKind::IntegrationAuthorization,
            MessageKind::Cancellation,
            MessageKind::ConsultationResponse,
            MessageKind::HandoffAcceptance,
            MessageKind::IntegrationComplete,
        ] {
            assert_eq!(
                kind.team_close_disposition(),
                TeamCloseDeliveryDisposition::ObsoleteOutcome
            );
        }
        for kind in [
            MessageKind::ImplementationRequest,
            MessageKind::FixRequest,
            MessageKind::RunControl,
        ] {
            assert_eq!(
                kind.team_close_disposition(),
                TeamCloseDeliveryDisposition::RequestLifecycle
            );
        }
        for kind in [
            MessageKind::Directive,
            MessageKind::ConsultationRequest,
            MessageKind::DependencyNotice,
            MessageKind::ConflictNotice,
            MessageKind::HandoffOffer,
        ] {
            assert_eq!(
                kind.team_close_disposition(),
                TeamCloseDeliveryDisposition::ActionRequired
            );
        }
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

    #[test]
    fn request_text_bounds_report_exact_field_actual_maximum_and_overflow() {
        let request = |instructions: String, criterion: String| ImplementationRequest {
            title: "bounded request".to_owned(),
            instructions,
            base_sha: GitSha::new("0".repeat(40)).expect("valid sha"),
            acceptance_criteria: vec![criterion],
            evidence_requirements: Vec::new(),
        };
        request(
            "i".repeat(MAX_REQUEST_TEXT_CHARACTERS),
            "c".repeat(MAX_REQUEST_TEXT_CHARACTERS),
        )
        .validate()
        .expect("the exact character bound is accepted");

        let instruction_error = request(
            "i".repeat(MAX_REQUEST_TEXT_CHARACTERS + 1),
            "criterion".to_owned(),
        )
        .validate()
        .expect_err("one excess instruction character is rejected");
        assert_eq!(instruction_error.field, "instructions");
        assert_eq!(instruction_error.code, ValidationCode::OutOfRange);
        assert_eq!(
            instruction_error.actual,
            Some(MAX_REQUEST_TEXT_CHARACTERS + 1)
        );
        assert_eq!(instruction_error.maximum, Some(MAX_REQUEST_TEXT_CHARACTERS));
        assert_eq!(instruction_error.overflow, Some(1));
        assert_eq!(instruction_error.unit, Some(ValidationUnit::Characters));
        assert_eq!(
            instruction_error.message,
            "contains 65537 characters; maximum is 65536; exceeds by 1 character"
        );

        let criterion_error = request(
            "instructions".to_owned(),
            "c".repeat(MAX_REQUEST_TEXT_CHARACTERS + 2),
        )
        .validate()
        .expect_err("an oversized criterion is rejected");
        assert_eq!(criterion_error.field, "acceptance_criteria[0]");
        assert_eq!(
            criterion_error.actual,
            Some(MAX_REQUEST_TEXT_CHARACTERS + 2)
        );
        assert_eq!(criterion_error.maximum, Some(MAX_REQUEST_TEXT_CHARACTERS));
        assert_eq!(criterion_error.overflow, Some(2));
        assert_eq!(criterion_error.unit, Some(ValidationUnit::Characters));
        assert_eq!(
            criterion_error.message,
            "contains 65538 characters; maximum is 65536; exceeds by 2 characters"
        );
    }
}
