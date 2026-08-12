//! Serializable provider-independent protocol and persisted-state types.

use crate::PROTOCOL_VERSION;
use crate::ids::{
    ActorEpoch, ActorId, ActorProfileName, AssignmentEpoch, AssignmentPolicyId, CapabilityId,
    DecisionId, EvidenceId, GitSha, HandoffId, MessageId, PolicyRevision, PrimaryEpoch, RequestId,
    ReviewAttemptRecordId, ReviewBinaryId, ReviewCheckId, ReviewEnvironmentId,
    ReviewEnvironmentKey, ReviewSessionId, ReviewToolId, RunId, TeamEpoch, TeamId, TeamProfileName,
    TimestampMillis, WorkspaceId,
};
use crate::validation::{
    MAX_ACCEPTANCE_CRITERIA, MAX_ACKNOWLEDGEMENTS, MAX_ACTOR_CAPABILITIES, MAX_AUDIT_EVENTS,
    MAX_CONFLICT_RESOURCES, MAX_DELIVERIES, MAX_DOMAIN_ENTITIES, MAX_EVIDENCE_ITEMS,
    MAX_EVIDENCE_REQUIREMENTS, MAX_REQUEST_TEXT_CHARACTERS, MAX_REVIEW_ARGUMENT_CHARACTERS,
    MAX_REVIEW_ARGUMENTS, MAX_REVIEW_ITEMS, MAX_REVIEW_PATH_CHARACTERS, MAX_REVIEW_TIMEOUT_SECONDS,
    MAX_REVIEW_VERSION_CHARACTERS, Validate, ValidationCode, ValidationError, ValidationUnit,
    validate_count, validate_text,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::path::{Component, Path};
use std::str::FromStr;

/// A currently registered actor generation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
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

/// Provider-neutral reporting view of one team's current durable activity.
///
/// This derived record is deliberately not part of [`DomainSnapshot`]. The
/// state store updates it transactionally with the durable mutation that
/// produced the activity, while the aggregate snapshot remains the source of
/// truth for request lifecycle state.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct TeamActivitySummary {
    /// Workspace containing the team.
    pub workspace_id: WorkspaceId,
    /// Team being reported.
    pub team_id: TeamId,
    /// Exact current team generation represented by this projection.
    pub team_epoch: TeamEpoch,
    /// Time of the most recent explicit team-lifecycle or request, run,
    /// delivery, acknowledgement, or handoff mutation attributed to the team.
    /// Actor heartbeat, status expiry, reconciliation-only actor bookkeeping,
    /// and policy-wide bookkeeping do not advance this timestamp.
    pub last_activity_at: TimestampMillis,
    /// Exact number of requests owned by the team whose status is not terminal.
    pub nonterminal_request_count: u64,
}

/// Provider-neutral reporting view of one exact actor generation.
///
/// A replacement generation has a distinct [`ActorRef`], resets the age anchor
/// and starts with no completed assignments. Completion is credited once to
/// the exact assigned generation only when a request transitions to
/// [`RequestStatus::Completed`].
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ActorGenerationSummary {
    /// Workspace containing the actor generation.
    pub workspace_id: WorkspaceId,
    /// Exact logical actor and process-generation fence being reported.
    pub actor: ActorRef,
    /// Owning team, or none for a teamless actor such as the active Primary.
    pub team_id: Option<TeamId>,
    /// Exact owning team generation, paired with `team_id`.
    pub team_epoch: Option<TeamEpoch>,
    /// Time at which this exact actor generation was first durably persisted.
    pub generation_started_at: TimestampMillis,
    /// Requests that transitioned exactly once to completed while assigned to
    /// this exact actor generation.
    pub completed_assignment_count: u64,
    /// Immutable completion credits partitioned by the exact team generation
    /// that owned each request when it completed.
    pub completed_assignments_by_team_epoch: Vec<ActorTeamEpochCompletionSummary>,
}

/// Completion count for one exact actor and owning team generation pair.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ActorTeamEpochCompletionSummary {
    /// Exact owning team generation recorded by completed requests.
    pub team_epoch: TeamEpoch,
    /// Number of immutable completion records for this pair.
    pub completed_assignment_count: u64,
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
    /// Exact team ownership generation that owns this run.
    pub team_epoch: TeamEpoch,
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
    /// Whether the Primary declared the base or AGSV derived it from the worktree.
    #[serde(default)]
    pub base_source: RequestBaseSource,
    /// Verifiable completion criteria.
    #[schemars(length(min = 1, max = MAX_ACCEPTANCE_CRITERIA), inner(length(min = 1, max = MAX_REQUEST_TEXT_CHARACTERS)))]
    pub acceptance_criteria: Vec<String>,
    /// Evidence categories the implementation must return.
    #[schemars(length(max = MAX_EVIDENCE_REQUIREMENTS))]
    pub evidence_requirements: Vec<EvidenceKind>,
}

/// Provenance of a request's effective base commit.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestBaseSource {
    /// The Primary supplied the exact base commit.
    Declared,
    /// AGSV derived the base from the assigned team's worktree.
    #[default]
    Derived,
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

/// Exact commit and tree object reviewed in an isolated checkout.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewTreeIdentity {
    /// Immutable candidate commit selected for review.
    pub candidate_sha: GitSha,
    /// Git tree object resolved from the candidate at session creation.
    pub tree_sha: GitSha,
}

/// Frozen policy and configuration identity for a review plan.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewPlanIdentity {
    /// Policy revision current when the plan was loaded from trusted configuration.
    pub policy_revision: PolicyRevision,
    /// SHA-256 of the canonical trusted review configuration.
    pub config_digest: PayloadDigest,
}

impl Validate for ReviewPlanIdentity {
    fn validate(&self) -> Result<(), ValidationError> {
        self.config_digest
            .validate()
            .map_err(|error| error.at("config_digest"))
    }
}

/// One configured provider-neutral review check.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewCheck {
    /// Stable configured check identifier.
    pub check_id: ReviewCheckId,
    /// Exact argument vector executed without a shell.
    #[schemars(length(min = 1, max = MAX_REVIEW_ARGUMENTS), inner(length(max = MAX_REVIEW_ARGUMENT_CHARACTERS)))]
    pub argv: Vec<String>,
    /// Checkout-relative working directory, or the checkout root when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = MAX_REVIEW_PATH_CHARACTERS))]
    pub relative_cwd: Option<String>,
    /// Hard wall-clock timeout for the process.
    #[schemars(range(min = 1, max = MAX_REVIEW_TIMEOUT_SECONDS))]
    pub timeout_seconds: u32,
    /// Process exit code that represents success.
    #[schemars(range(min = 0, max = 255))]
    pub expected_exit_code: i32,
    /// Binaries required to be unresolvable from the controller-constructed
    /// `PATH` in the required-absent execution variant.
    #[schemars(length(max = MAX_REVIEW_ITEMS))]
    pub required_absent_binaries: BTreeSet<ReviewBinaryId>,
}

impl Validate for ReviewCheck {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_review_argv("argv", &self.argv)?;
        if let Some(relative_cwd) = &self.relative_cwd {
            validate_relative_review_path("relative_cwd", relative_cwd)?;
        }
        if !(1..=MAX_REVIEW_TIMEOUT_SECONDS).contains(&self.timeout_seconds) {
            return Err(ValidationError::new(
                "timeout_seconds",
                ValidationCode::OutOfRange,
                format!("must be between 1 and {MAX_REVIEW_TIMEOUT_SECONDS} seconds"),
            ));
        }
        validate_exit_code("expected_exit_code", self.expected_exit_code)?;
        validate_count(
            "required_absent_binaries",
            self.required_absent_binaries.len(),
            MAX_REVIEW_ITEMS,
        )
    }
}

/// Configured command used to identify one tool version.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewToolVersionProbe {
    /// Stable tool identifier.
    pub tool_id: ReviewToolId,
    /// Exact argument vector executed without a shell.
    #[schemars(length(min = 1, max = MAX_REVIEW_ARGUMENTS), inner(length(max = MAX_REVIEW_ARGUMENT_CHARACTERS)))]
    pub argv: Vec<String>,
}

impl Validate for ReviewToolVersionProbe {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_review_argv("argv", &self.argv)
    }
}

/// Trusted, frozen suite executed for an exact candidate.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewPlan {
    /// Policy and configuration identity shared by every derived record.
    pub identity: ReviewPlanIdentity,
    /// Ordered configured checks.
    #[schemars(length(min = 1, max = MAX_REVIEW_ITEMS))]
    pub checks: Vec<ReviewCheck>,
    /// Ordered tool-version probes captured for each execution profile.
    #[schemars(length(min = 1, max = MAX_REVIEW_ITEMS))]
    pub tool_version_probes: Vec<ReviewToolVersionProbe>,
    /// Provider-neutral environment values or explicit placeholder values.
    /// Controller-owned and Git isolation variables cannot be declared or
    /// inherited here.
    #[schemars(schema_with = "review_declared_environment_schema")]
    pub declared_environment: BTreeMap<ReviewEnvironmentKey, String>,
    /// SHA-256 of the canonical declared-environment map.
    pub declared_environment_digest: PayloadDigest,
    /// Binaries whose presence or absence is recorded when available.
    #[schemars(length(max = MAX_REVIEW_ITEMS))]
    pub optional_binaries: BTreeSet<ReviewBinaryId>,
}

impl ReviewPlan {
    /// Validates one declared child-environment entry using the same protocol
    /// policy enforced for a frozen review plan.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error when the key is controller-owned or
    /// reserved for Git isolation, or when the value exceeds protocol bounds.
    pub fn validate_declared_environment_entry(
        key: &ReviewEnvironmentKey,
        value: &str,
    ) -> Result<(), ValidationError> {
        validate_declared_environment_key(key)?;
        validate_review_value(
            &format!("declared_environment[{key}]"),
            value,
            MAX_REVIEW_ARGUMENT_CHARACTERS,
        )
    }
}

impl Validate for ReviewPlan {
    fn validate(&self) -> Result<(), ValidationError> {
        self.identity
            .validate()
            .map_err(|error| error.at("identity"))?;
        if self.checks.is_empty() {
            return Err(ValidationError::new(
                "checks",
                ValidationCode::Required,
                "must contain at least one configured check",
            ));
        }
        validate_count("checks", self.checks.len(), MAX_REVIEW_ITEMS)?;
        if self.tool_version_probes.is_empty() {
            return Err(ValidationError::new(
                "tool_version_probes",
                ValidationCode::Required,
                "must contain at least one configured tool-version probe",
            ));
        }
        validate_count(
            "tool_version_probes",
            self.tool_version_probes.len(),
            MAX_REVIEW_ITEMS,
        )?;
        validate_count(
            "declared_environment",
            self.declared_environment.len(),
            MAX_REVIEW_ITEMS,
        )?;
        self.declared_environment_digest
            .validate()
            .map_err(|error| error.at("declared_environment_digest"))?;
        validate_count(
            "optional_binaries",
            self.optional_binaries.len(),
            MAX_REVIEW_ITEMS,
        )?;
        let mut check_ids = BTreeSet::new();
        for (index, check) in self.checks.iter().enumerate() {
            check
                .validate()
                .map_err(|error| error.at(&format!("checks[{index}]")))?;
            if !check_ids.insert(&check.check_id) {
                return Err(ValidationError::new(
                    format!("checks[{index}].check_id"),
                    ValidationCode::Inconsistent,
                    "configured check identifiers must be unique",
                ));
            }
        }
        let mut tool_ids = BTreeSet::new();
        for (index, probe) in self.tool_version_probes.iter().enumerate() {
            probe
                .validate()
                .map_err(|error| error.at(&format!("tool_version_probes[{index}]")))?;
            if !tool_ids.insert(&probe.tool_id) {
                return Err(ValidationError::new(
                    format!("tool_version_probes[{index}].tool_id"),
                    ValidationCode::Inconsistent,
                    "tool-version probe identifiers must be unique",
                ));
            }
        }
        for (key, value) in &self.declared_environment {
            Self::validate_declared_environment_entry(key, value)?;
        }
        validate_tool_probe_coverage(&self.checks, &self.tool_version_probes)?;
        Ok(())
    }
}

/// Durable lifecycle state of a reusable exact-SHA review session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewSessionStatus {
    /// Checkout and tree identity are being prepared.
    Preparing,
    /// Checkout is verified and may execute repeated attempts.
    Ready,
    /// Checkout or immutable identity cannot be trusted until recreated.
    Invalid,
}

/// Crash-recovery action required before a review session can continue.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewRecoveryState {
    /// No recovery action is pending.
    NotRequired,
    /// An interrupted verification attempt must be reconciled or resumed.
    ResumeRequired,
    /// The exact checkout must be recreated and reverified.
    RecreateRequired,
}

/// Validated combination of durable session and recovery states.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewSessionState {
    /// Current reusable-session lifecycle state.
    pub status: ReviewSessionStatus,
    /// Recovery work required before normal use.
    pub recovery: ReviewRecoveryState,
}

impl ReviewSessionState {
    /// Creates a legal session and recovery state combination.
    ///
    /// # Errors
    ///
    /// Returns an inconsistency error for combinations that cannot represent a
    /// durable review-session state.
    pub fn new(
        status: ReviewSessionStatus,
        recovery: ReviewRecoveryState,
    ) -> Result<Self, ValidationError> {
        let state = Self { status, recovery };
        state.validate()?;
        Ok(state)
    }

    /// Returns whether a lifecycle update is legal and idempotent.
    #[must_use]
    pub fn allows_transition_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        matches!(
            (self.status, self.recovery, next.status, next.recovery),
            (
                ReviewSessionStatus::Preparing,
                ReviewRecoveryState::NotRequired,
                ReviewSessionStatus::Ready,
                ReviewRecoveryState::NotRequired
            ) | (
                ReviewSessionStatus::Preparing,
                ReviewRecoveryState::NotRequired,
                ReviewSessionStatus::Invalid,
                ReviewRecoveryState::RecreateRequired
            ) | (
                ReviewSessionStatus::Ready,
                ReviewRecoveryState::NotRequired,
                ReviewSessionStatus::Ready,
                ReviewRecoveryState::ResumeRequired
            ) | (
                ReviewSessionStatus::Ready,
                ReviewRecoveryState::ResumeRequired,
                ReviewSessionStatus::Ready,
                ReviewRecoveryState::NotRequired
            ) | (
                ReviewSessionStatus::Ready,
                _,
                ReviewSessionStatus::Invalid,
                ReviewRecoveryState::RecreateRequired
            ) | (
                ReviewSessionStatus::Invalid,
                ReviewRecoveryState::RecreateRequired,
                ReviewSessionStatus::Preparing,
                ReviewRecoveryState::NotRequired
            )
        )
    }
}

impl Validate for ReviewSessionState {
    fn validate(&self) -> Result<(), ValidationError> {
        if matches!(
            (self.status, self.recovery),
            (
                ReviewSessionStatus::Preparing | ReviewSessionStatus::Ready,
                ReviewRecoveryState::NotRequired
            ) | (
                ReviewSessionStatus::Ready,
                ReviewRecoveryState::ResumeRequired
            ) | (
                ReviewSessionStatus::Invalid,
                ReviewRecoveryState::RecreateRequired
            )
        ) {
            Ok(())
        } else {
            Err(ValidationError::new(
                "recovery",
                ValidationCode::Inconsistent,
                "recovery state is inconsistent with review session status",
            ))
        }
    }
}

/// Durable exact-SHA review session and its frozen trusted plan.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewSession {
    /// Stable session identifier used by review commands.
    pub session_id: ReviewSessionId,
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// Request whose candidate is reviewed.
    pub request_id: RequestId,
    /// Exact commit and resolved tree identity.
    pub tree: ReviewTreeIdentity,
    /// Provider-neutral absolute path of the isolated checkout.
    #[schemars(length(min = 1, max = MAX_REVIEW_PATH_CHARACTERS))]
    pub checkout_path: String,
    /// Trusted configuration frozen at begin time.
    pub plan: ReviewPlan,
    /// Reusable session and recovery state.
    pub state: ReviewSessionState,
    /// Session creation time.
    pub created_at: TimestampMillis,
    /// Last durable state-change time.
    pub updated_at: TimestampMillis,
}

impl Validate for ReviewSession {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_absolute_review_path("checkout_path", &self.checkout_path)?;
        self.plan.validate().map_err(|error| error.at("plan"))?;
        self.state.validate().map_err(|error| error.at("state"))?;
        if self.updated_at < self.created_at {
            return Err(ValidationError::new(
                "updated_at",
                ValidationCode::Inconsistent,
                "must not precede created_at",
            ));
        }
        Ok(())
    }
}

/// Append-only lifecycle fact for one logical verification attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAttemptStatus {
    /// Verification began and has no terminal fact yet.
    Running,
    /// Every configured check and required variant passed.
    Passed,
    /// At least one configured check or required variant failed.
    Failed,
    /// Execution stopped before a conclusive aggregate result.
    Interrupted,
}

impl ReviewAttemptStatus {
    /// Returns whether an append-only status fact may follow this status.
    #[must_use]
    pub const fn allows_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Running,
                Self::Passed | Self::Failed | Self::Interrupted
            )
        ) || matches!(
            (self, next),
            (Self::Running, Self::Running)
                | (Self::Passed, Self::Passed)
                | (Self::Failed, Self::Failed)
                | (Self::Interrupted, Self::Interrupted)
        )
    }
}

/// Append-only state record for a logical review verification attempt.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewVerificationAttempt {
    /// Unique immutable status-record identifier.
    pub record_id: ReviewAttemptRecordId,
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// Review session being executed.
    pub session_id: ReviewSessionId,
    /// Request whose candidate is verified.
    pub request_id: RequestId,
    /// Exact candidate commit verified by the session.
    pub candidate_sha: GitSha,
    /// Monotonic logical attempt sequence within the session.
    #[schemars(range(min = 1))]
    pub attempt_sequence: u64,
    /// Frozen trusted plan identity.
    pub plan: ReviewPlanIdentity,
    /// Append-only status represented by this record.
    pub status: ReviewAttemptStatus,
    /// Time the logical attempt began.
    pub started_at: TimestampMillis,
    /// Terminal time, absent only from a running status fact.
    pub finished_at: Option<TimestampMillis>,
    /// Time this immutable status fact was recorded.
    pub recorded_at: TimestampMillis,
}

impl Validate for ReviewVerificationAttempt {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.attempt_sequence == 0 {
            return Err(ValidationError::new(
                "attempt_sequence",
                ValidationCode::OutOfRange,
                "must be greater than zero",
            ));
        }
        self.plan.validate().map_err(|error| error.at("plan"))?;
        match (self.status, self.finished_at) {
            (ReviewAttemptStatus::Running, None) => {}
            (ReviewAttemptStatus::Running, Some(_)) => {
                return Err(ValidationError::new(
                    "finished_at",
                    ValidationCode::Inconsistent,
                    "a running attempt cannot have a terminal timestamp",
                ));
            }
            (_, Some(finished_at)) if finished_at >= self.started_at => {}
            (_, Some(_)) => {
                return Err(ValidationError::new(
                    "finished_at",
                    ValidationCode::Inconsistent,
                    "must not precede started_at",
                ));
            }
            (_, None) => {
                return Err(ValidationError::new(
                    "finished_at",
                    ValidationCode::Required,
                    "a terminal attempt status requires a terminal timestamp",
                ));
            }
        }
        if self.recorded_at < self.started_at
            || self
                .finished_at
                .is_some_and(|finished_at| self.recorded_at < finished_at)
        {
            return Err(ValidationError::new(
                "recorded_at",
                ValidationCode::Inconsistent,
                "must not precede attempt timestamps",
            ));
        }
        Ok(())
    }
}

/// Execution profile used for one configured check result.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ReviewExecutionVariant {
    /// Check executed with the normal declared environment.
    Normal,
    /// Check executed with its required-absent binaries unresolvable from the
    /// controller-constructed `PATH`.
    RequiredAbsent,
}

/// Process-tree containment established for one check execution profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewProcessContainment {
    /// A process-ID namespace is coupled to parent death so terminating its
    /// supervising process also terminates descendants that detach themselves.
    PidNamespaceParentDeath,
    /// Only a process group is supervised. Descendants that create another
    /// session or process group may outlive a timeout or controller exit.
    ProcessGroupOnly,
    /// No process-tree containment was established.
    None,
}

/// Content-addressed persisted prefix of stdout, stderr, or another
/// control-owned output artifact.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewOutputArtifact {
    /// SHA-256 digest of the exact persisted prefix bytes.
    pub digest: PayloadDigest,
    /// Exact persisted-prefix byte count represented by the digest.
    pub byte_count: u64,
    /// Whether output exceeded the controller capture cap and bytes after the
    /// persisted prefix were discarded.
    #[serde(default)]
    pub truncated: bool,
    /// Optional provider-neutral path relative to control-owned artifact storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = MAX_REVIEW_PATH_CHARACTERS))]
    pub reference: Option<String>,
}

impl Validate for ReviewOutputArtifact {
    fn validate(&self) -> Result<(), ValidationError> {
        self.digest.validate().map_err(|error| error.at("digest"))?;
        if let Some(reference) = &self.reference {
            validate_relative_review_path("reference", reference)?;
        }
        Ok(())
    }
}

/// Outcome of one configured check execution variant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewCheckOutcome {
    /// Actual exit code matched the configured expected exit code.
    Passed,
    /// Process exited with another code.
    Failed,
    /// Process could not produce an exit code, including a timeout.
    ExecutionError,
}

/// Observed reason one configured check execution stopped.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewCheckTermination {
    /// Process exited normally and produced an exit code.
    Exited,
    /// Process was terminated by a signal and produced no exit code.
    Signaled,
    /// Controller stopped waiting after the configured timeout.
    TimedOut,
    /// Controller terminated execution after its aggregate output limit was
    /// exceeded.
    OutputLimitExceeded,
    /// Parent termination was observed, but output capture was abandoned
    /// because a detached descendant kept a pipe open. The parent exit code is
    /// preserved when available and remains absent when the parent was signaled.
    OutputCaptureIncomplete,
}

/// Immutable result of one configured check execution variant.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewCheckResult {
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// Review session that owns the attempt.
    pub session_id: ReviewSessionId,
    /// Request whose candidate was checked.
    pub request_id: RequestId,
    /// Exact candidate commit checked.
    pub candidate_sha: GitSha,
    /// Logical attempt sequence within the session.
    #[schemars(range(min = 1))]
    pub attempt_sequence: u64,
    /// Frozen trusted plan identity.
    pub plan: ReviewPlanIdentity,
    /// Configured check identity.
    pub check_id: ReviewCheckId,
    /// Normal or required-absent execution profile.
    pub variant: ReviewExecutionVariant,
    /// Exact environment profile used for execution.
    pub environment_id: ReviewEnvironmentId,
    /// Derived execution outcome.
    pub outcome: ReviewCheckOutcome,
    /// Observed reason process execution stopped.
    pub termination: ReviewCheckTermination,
    /// Success exit code frozen from the configured check.
    #[schemars(range(min = 0, max = 255))]
    pub expected_exit_code: i32,
    /// Process exit code, absent when execution could not produce one. An
    /// incomplete-capture result preserves the observed parent code when
    /// available and leaves it absent when the parent was signaled.
    pub actual_exit_code: Option<i32>,
    /// Whether detached descendants may still be running after forced
    /// termination or incomplete output capture.
    /// This is never true for fully contained process trees.
    pub process_tree_may_outlive: bool,
    /// Content-addressed stdout bytes.
    pub stdout: ReviewOutputArtifact,
    /// Content-addressed stderr bytes.
    pub stderr: ReviewOutputArtifact,
    /// Time process execution began.
    pub started_at: TimestampMillis,
    /// Time process execution ended or was abandoned.
    pub finished_at: TimestampMillis,
}

impl Validate for ReviewCheckResult {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.attempt_sequence == 0 {
            return Err(ValidationError::new(
                "attempt_sequence",
                ValidationCode::OutOfRange,
                "must be greater than zero",
            ));
        }
        self.plan.validate().map_err(|error| error.at("plan"))?;
        validate_exit_code("expected_exit_code", self.expected_exit_code)?;
        if let Some(actual) = self.actual_exit_code {
            validate_exit_code("actual_exit_code", actual)?;
        }
        let exit_shape_is_valid = matches!(
            (self.termination, self.actual_exit_code),
            (ReviewCheckTermination::Exited, Some(_),)
                | (ReviewCheckTermination::OutputCaptureIncomplete, _)
                | (
                    ReviewCheckTermination::Signaled
                        | ReviewCheckTermination::TimedOut
                        | ReviewCheckTermination::OutputLimitExceeded,
                    None,
                )
        );
        if !exit_shape_is_valid {
            return Err(ValidationError::new(
                "actual_exit_code",
                ValidationCode::Inconsistent,
                "actual exit code is inconsistent with the termination reason",
            ));
        }
        let outcome_shape_is_valid = match self.outcome {
            ReviewCheckOutcome::Passed => {
                self.termination == ReviewCheckTermination::Exited
                    && self.actual_exit_code == Some(self.expected_exit_code)
            }
            ReviewCheckOutcome::Failed => {
                self.termination == ReviewCheckTermination::Exited
                    && self
                        .actual_exit_code
                        .is_some_and(|actual| actual != self.expected_exit_code)
            }
            ReviewCheckOutcome::ExecutionError => {
                matches!(
                    self.termination,
                    ReviewCheckTermination::Signaled
                        | ReviewCheckTermination::TimedOut
                        | ReviewCheckTermination::OutputLimitExceeded
                        | ReviewCheckTermination::OutputCaptureIncomplete
                )
            }
        };
        if !outcome_shape_is_valid {
            return Err(ValidationError::new(
                "termination",
                ValidationCode::Inconsistent,
                "termination reason is inconsistent with the check outcome",
            ));
        }
        let survivor_shape_is_valid = match self.termination {
            ReviewCheckTermination::Exited | ReviewCheckTermination::Signaled => {
                !self.process_tree_may_outlive
            }
            ReviewCheckTermination::OutputCaptureIncomplete => self.process_tree_may_outlive,
            ReviewCheckTermination::TimedOut | ReviewCheckTermination::OutputLimitExceeded => true,
        };
        if !survivor_shape_is_valid {
            return Err(ValidationError::new(
                "process_tree_may_outlive",
                ValidationCode::Inconsistent,
                "survivor risk is inconsistent with the termination reason",
            ));
        }
        self.stdout.validate().map_err(|error| error.at("stdout"))?;
        self.stderr.validate().map_err(|error| error.at("stderr"))?;
        let output_was_truncated = self.stdout.truncated || self.stderr.truncated;
        let truncation_shape_is_valid = match self.termination {
            ReviewCheckTermination::OutputLimitExceeded => output_was_truncated,
            ReviewCheckTermination::TimedOut => true,
            ReviewCheckTermination::Exited
            | ReviewCheckTermination::Signaled
            | ReviewCheckTermination::OutputCaptureIncomplete => !output_was_truncated,
        };
        if !truncation_shape_is_valid {
            return Err(ValidationError::new(
                "termination",
                ValidationCode::Inconsistent,
                "output-limit termination requires truncated output, while exited, signaled, or incomplete-capture execution forbids it",
            ));
        }
        if self.finished_at < self.started_at {
            return Err(ValidationError::new(
                "finished_at",
                ValidationCode::Inconsistent,
                "must not precede started_at",
            ));
        }
        Ok(())
    }
}

/// Observed version and executable identity for one configured tool probe.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewToolVersion {
    /// Stable configured tool identifier.
    pub tool_id: ReviewToolId,
    /// Fully resolved executable path used for the probe.
    #[schemars(length(min = 1, max = MAX_REVIEW_PATH_CHARACTERS))]
    pub resolved_executable: String,
    /// SHA-256 of the executable bytes.
    pub executable_digest: PayloadDigest,
    /// Exit code returned by the version probe.
    #[schemars(range(min = 0, max = 255))]
    pub probe_exit_code: i32,
    /// Provider-neutral normalized version text.
    #[schemars(length(min = 1, max = MAX_REVIEW_VERSION_CHARACTERS))]
    pub version: String,
    /// Content-addressed probe stdout.
    pub stdout: ReviewOutputArtifact,
    /// Content-addressed probe stderr.
    pub stderr: ReviewOutputArtifact,
}

impl Validate for ReviewToolVersion {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_absolute_review_path("resolved_executable", &self.resolved_executable)?;
        self.executable_digest
            .validate()
            .map_err(|error| error.at("executable_digest"))?;
        validate_exit_code("probe_exit_code", self.probe_exit_code)?;
        validate_text("version", &self.version, MAX_REVIEW_VERSION_CHARACTERS)?;
        validate_review_value("version", &self.version, MAX_REVIEW_VERSION_CHARACTERS)?;
        self.stdout.validate().map_err(|error| error.at("stdout"))?;
        self.stderr.validate().map_err(|error| error.at("stderr"))
    }
}

/// Presence observation for one configured binary under the controlled
/// execution `PATH`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewBinaryPresence {
    /// Binary resolved from the controlled execution `PATH`.
    Present,
    /// Binary did not resolve from the controlled execution `PATH`. This does
    /// not claim the binary is absent elsewhere on the host.
    AbsentFromControlledPath,
}

/// Immutable binary presence and executable identity observation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewBinaryObservation {
    /// Stable configured binary identifier.
    pub binary_id: ReviewBinaryId,
    /// Presence observed in the execution profile.
    pub presence: ReviewBinaryPresence,
    /// Fully resolved path when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = MAX_REVIEW_PATH_CHARACTERS))]
    pub resolved_executable: Option<String>,
    /// SHA-256 of executable bytes when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_digest: Option<PayloadDigest>,
}

impl Validate for ReviewBinaryObservation {
    fn validate(&self) -> Result<(), ValidationError> {
        match (
            self.presence,
            self.resolved_executable.as_ref(),
            self.executable_digest.as_ref(),
        ) {
            (ReviewBinaryPresence::Present, Some(path), Some(digest)) => {
                validate_absolute_review_path("resolved_executable", path)?;
                digest
                    .validate()
                    .map_err(|error| error.at("executable_digest"))
            }
            (ReviewBinaryPresence::AbsentFromControlledPath, None, None) => Ok(()),
            _ => Err(ValidationError::new(
                "presence",
                ValidationCode::Inconsistent,
                "binary presence under the controlled PATH must match executable path and digest fields",
            )),
        }
    }
}

/// Immutable environment evidence for one check execution profile.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ReviewEnvironmentRecord {
    /// Stable environment record identifier.
    pub environment_id: ReviewEnvironmentId,
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// Review session that owns the attempt.
    pub session_id: ReviewSessionId,
    /// Request whose candidate was checked.
    pub request_id: RequestId,
    /// Exact candidate commit checked.
    pub candidate_sha: GitSha,
    /// Logical attempt sequence within the session.
    #[schemars(range(min = 1))]
    pub attempt_sequence: u64,
    /// Frozen trusted plan identity.
    pub plan: ReviewPlanIdentity,
    /// Configured check identity using this environment.
    pub check_id: ReviewCheckId,
    /// Normal or required-absent execution profile.
    pub variant: ReviewExecutionVariant,
    /// Process-tree containment established for this execution profile.
    pub process_containment: ReviewProcessContainment,
    /// Time the environment evidence was captured.
    pub recorded_at: TimestampMillis,
    /// SHA-256 of the canonical declared-environment map.
    pub declared_environment_digest: PayloadDigest,
    /// Privacy-allowlisted actual execution facts such as OS, architecture,
    /// AGSV version, checkout identity, PATH profile, controller-owned temporary
    /// directory, optional developer directory, the digest of expanded declared
    /// child values, and safe locale values. This must never contain an ambient
    /// environment dump or the expanded declared values themselves.
    #[schemars(schema_with = "review_execution_environment_schema")]
    pub execution_environment: BTreeMap<ReviewEnvironmentKey, String>,
    /// SHA-256 of the canonical privacy-allowlisted execution environment map.
    pub execution_environment_digest: PayloadDigest,
    /// Version and executable identity for configured tool probes.
    #[schemars(length(max = MAX_REVIEW_ITEMS))]
    pub tool_versions: Vec<ReviewToolVersion>,
    /// Controlled-`PATH` observations for optional and required-absent binaries.
    #[schemars(length(max = MAX_REVIEW_ITEMS))]
    pub binary_observations: Vec<ReviewBinaryObservation>,
    /// Binaries required to be absent from the controlled `PATH` for this
    /// profile.
    #[schemars(length(max = MAX_REVIEW_ITEMS))]
    pub required_absent_binaries: BTreeSet<ReviewBinaryId>,
}

impl ReviewEnvironmentRecord {
    fn validate_execution_environment(&self) -> Result<(), ValidationError> {
        validate_count(
            "execution_environment",
            self.execution_environment.len(),
            MAX_REVIEW_ITEMS,
        )?;
        self.execution_environment_digest
            .validate()
            .map_err(|error| error.at("execution_environment_digest"))?;
        for (key, value) in &self.execution_environment {
            validate_execution_environment_key(key)?;
            let field = format!("execution_environment[{key}]");
            if matches!(key.as_str(), "tmpdir" | "developer_dir") {
                validate_absolute_review_path(&field, value)?;
            } else {
                validate_review_value(&field, value, MAX_REVIEW_ARGUMENT_CHARACTERS)?;
            }
            if matches!(key.as_str(), "path_digest" | "declared_values_digest") {
                PayloadDigest::new(value.clone()).map_err(|error| error.at(&field))?;
            }
        }
        for required_key in [
            "os",
            "arch",
            "agsv_version",
            "cwd_identity",
            "declared_values_digest",
            "tmpdir",
        ] {
            if !self
                .execution_environment
                .keys()
                .any(|key| key.as_str() == required_key)
            {
                return Err(ValidationError::new(
                    "execution_environment",
                    ValidationCode::Required,
                    "must include os, arch, agsv_version, cwd_identity, declared_values_digest, and tmpdir",
                ));
            }
        }
        if !self
            .execution_environment
            .keys()
            .any(|key| matches!(key.as_str(), "path_digest" | "path_profile"))
        {
            return Err(ValidationError::new(
                "execution_environment",
                ValidationCode::Required,
                "must include path_digest or path_profile",
            ));
        }
        Ok(())
    }
}

impl Validate for ReviewEnvironmentRecord {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.attempt_sequence == 0 {
            return Err(ValidationError::new(
                "attempt_sequence",
                ValidationCode::OutOfRange,
                "must be greater than zero",
            ));
        }
        self.plan.validate().map_err(|error| error.at("plan"))?;
        self.declared_environment_digest
            .validate()
            .map_err(|error| error.at("declared_environment_digest"))?;
        self.validate_execution_environment()?;
        validate_count("tool_versions", self.tool_versions.len(), MAX_REVIEW_ITEMS)?;
        validate_count(
            "binary_observations",
            self.binary_observations.len(),
            MAX_REVIEW_ITEMS,
        )?;
        validate_count(
            "required_absent_binaries",
            self.required_absent_binaries.len(),
            MAX_REVIEW_ITEMS,
        )?;
        let mut tool_ids = BTreeSet::new();
        for (index, tool) in self.tool_versions.iter().enumerate() {
            tool.validate()
                .map_err(|error| error.at(&format!("tool_versions[{index}]")))?;
            if !tool_ids.insert(&tool.tool_id) {
                return Err(ValidationError::new(
                    format!("tool_versions[{index}].tool_id"),
                    ValidationCode::Inconsistent,
                    "tool-version observations must be unique",
                ));
            }
        }
        let mut observations = BTreeMap::new();
        for (index, observation) in self.binary_observations.iter().enumerate() {
            observation
                .validate()
                .map_err(|error| error.at(&format!("binary_observations[{index}]")))?;
            if observations
                .insert(&observation.binary_id, observation.presence)
                .is_some()
            {
                return Err(ValidationError::new(
                    format!("binary_observations[{index}].binary_id"),
                    ValidationCode::Inconsistent,
                    "binary observations must be unique",
                ));
            }
        }
        match self.variant {
            ReviewExecutionVariant::Normal if self.required_absent_binaries.is_empty() => Ok(()),
            ReviewExecutionVariant::RequiredAbsent
                if !self.required_absent_binaries.is_empty()
                    && self.required_absent_binaries.iter().all(|binary_id| {
                        observations.get(binary_id)
                            == Some(&ReviewBinaryPresence::AbsentFromControlledPath)
                    }) =>
            {
                Ok(())
            }
            _ => Err(ValidationError::new(
                "required_absent_binaries",
                ValidationCode::Inconsistent,
                "execution variant and required-absent observations are inconsistent",
            )),
        }
    }
}

impl ReviewSession {
    /// Validates one append-only attempt fact against this exact session.
    ///
    /// # Errors
    ///
    /// Returns an error when the record is malformed or belongs to another
    /// workspace, request, candidate, session, or trusted plan.
    pub fn validate_attempt_record(
        &self,
        attempt: &ReviewVerificationAttempt,
    ) -> Result<(), ValidationError> {
        self.validate()?;
        attempt.validate()?;
        self.validate_child_identity(
            &attempt.workspace_id,
            &attempt.session_id,
            &attempt.request_id,
            &attempt.candidate_sha,
            &attempt.plan,
        )
    }

    /// Validates the aggregate status against immutable per-check results.
    ///
    /// Passed attempts require every normal and configured required-absent
    /// variant to pass. Failed and interrupted attempts may retain a partial
    /// result set, but it must explain the aggregate status without duplicates.
    ///
    /// # Errors
    ///
    /// Returns an error for a running fact, a foreign result, duplicate
    /// execution identities, or an aggregate status unsupported by the results.
    pub fn validate_attempt_results(
        &self,
        attempt: &ReviewVerificationAttempt,
        results: &[ReviewCheckResult],
    ) -> Result<(), ValidationError> {
        self.validate_attempt_record(attempt)?;
        if attempt.status == ReviewAttemptStatus::Running {
            return Err(ValidationError::new(
                "status",
                ValidationCode::Inconsistent,
                "aggregate result validation requires a terminal attempt fact",
            ));
        }
        let expected = self
            .plan
            .checks
            .iter()
            .flat_map(|check| {
                let required_absent = (!check.required_absent_binaries.is_empty()).then_some((
                    check.check_id.clone(),
                    ReviewExecutionVariant::RequiredAbsent,
                ));
                std::iter::once((check.check_id.clone(), ReviewExecutionVariant::Normal))
                    .chain(required_absent)
            })
            .collect::<BTreeSet<_>>();
        let mut observed = BTreeSet::new();
        let mut all_passed = true;
        let mut any_failed = false;
        let Some(attempt_finished_at) = attempt.finished_at else {
            return Err(ValidationError::new(
                "finished_at",
                ValidationCode::Required,
                "terminal attempt fact requires a terminal timestamp",
            ));
        };
        for (index, result) in results.iter().enumerate() {
            self.validate_check_result(result)
                .map_err(|error| error.at(&format!("results[{index}]")))?;
            if result.attempt_sequence != attempt.attempt_sequence {
                return Err(ValidationError::new(
                    format!("results[{index}].attempt_sequence"),
                    ValidationCode::Inconsistent,
                    "does not match the terminal attempt fact",
                ));
            }
            if result.started_at < attempt.started_at || result.finished_at > attempt_finished_at {
                return Err(ValidationError::new(
                    format!("results[{index}].started_at"),
                    ValidationCode::Inconsistent,
                    "check timestamps must fall within the logical attempt",
                ));
            }
            if !observed.insert((result.check_id.clone(), result.variant)) {
                return Err(ValidationError::new(
                    format!("results[{index}]"),
                    ValidationCode::Inconsistent,
                    "duplicate check execution result",
                ));
            }
            all_passed &= result.outcome == ReviewCheckOutcome::Passed;
            any_failed |= result.outcome != ReviewCheckOutcome::Passed;
        }
        if !observed.is_subset(&expected) {
            return Err(ValidationError::new(
                "results",
                ValidationCode::Inconsistent,
                "contains an execution absent from the frozen review plan",
            ));
        }
        let status_is_explained = match attempt.status {
            ReviewAttemptStatus::Passed => observed == expected && all_passed,
            ReviewAttemptStatus::Failed => any_failed,
            ReviewAttemptStatus::Interrupted => observed != expected || !all_passed,
            ReviewAttemptStatus::Running => false,
        };
        if !status_is_explained {
            return Err(ValidationError::new(
                "status",
                ValidationCode::Inconsistent,
                "attempt status is not supported by its immutable check results",
            ));
        }
        Ok(())
    }

    /// Validates one check result against this exact session and frozen check.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, foreign, or configuration-inconsistent
    /// results.
    pub fn validate_check_result(&self, result: &ReviewCheckResult) -> Result<(), ValidationError> {
        self.validate()?;
        result.validate()?;
        self.validate_child_identity(
            &result.workspace_id,
            &result.session_id,
            &result.request_id,
            &result.candidate_sha,
            &result.plan,
        )?;
        let check = self.review_check(&result.check_id)?;
        if result.expected_exit_code != check.expected_exit_code {
            return Err(ValidationError::new(
                "expected_exit_code",
                ValidationCode::Inconsistent,
                "does not match the frozen configured check",
            ));
        }
        if result.variant == ReviewExecutionVariant::RequiredAbsent
            && check.required_absent_binaries.is_empty()
        {
            return Err(ValidationError::new(
                "variant",
                ValidationCode::Inconsistent,
                "check has no configured required-absent execution variant",
            ));
        }
        Ok(())
    }

    /// Validates one environment profile against this exact session and check.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, foreign, incomplete, or
    /// configuration-inconsistent environment evidence.
    pub fn validate_environment_record(
        &self,
        environment: &ReviewEnvironmentRecord,
    ) -> Result<(), ValidationError> {
        self.validate()?;
        environment.validate()?;
        self.validate_child_identity(
            &environment.workspace_id,
            &environment.session_id,
            &environment.request_id,
            &environment.candidate_sha,
            &environment.plan,
        )?;
        if environment.declared_environment_digest != self.plan.declared_environment_digest {
            return Err(ValidationError::new(
                "declared_environment_digest",
                ValidationCode::Inconsistent,
                "does not match the frozen declared environment",
            ));
        }
        let check = self.review_check(&environment.check_id)?;
        let expected_required_absent = match environment.variant {
            ReviewExecutionVariant::Normal => BTreeSet::new(),
            ReviewExecutionVariant::RequiredAbsent => check.required_absent_binaries.clone(),
        };
        if environment.required_absent_binaries != expected_required_absent {
            return Err(ValidationError::new(
                "required_absent_binaries",
                ValidationCode::Inconsistent,
                "does not match the frozen configured check variant",
            ));
        }
        let expected_tools = self
            .plan
            .tool_version_probes
            .iter()
            .map(|probe| &probe.tool_id)
            .collect::<BTreeSet<_>>();
        let observed_tools = environment
            .tool_versions
            .iter()
            .map(|tool| &tool.tool_id)
            .collect::<BTreeSet<_>>();
        if observed_tools != expected_tools {
            return Err(ValidationError::new(
                "tool_versions",
                ValidationCode::Inconsistent,
                "must exactly cover the frozen tool-version probes",
            ));
        }
        let allowed_binaries = self
            .plan
            .optional_binaries
            .iter()
            .chain(check.required_absent_binaries.iter())
            .collect::<BTreeSet<_>>();
        if environment
            .binary_observations
            .iter()
            .any(|observation| !allowed_binaries.contains(&observation.binary_id))
        {
            return Err(ValidationError::new(
                "binary_observations",
                ValidationCode::Inconsistent,
                "contains a binary absent from the frozen review plan",
            ));
        }
        Ok(())
    }

    /// Validates that a check result used the referenced environment profile.
    ///
    /// # Errors
    ///
    /// Returns an error when either record is invalid or their attempt, check,
    /// variant, plan, or environment identifiers differ.
    pub fn validate_execution_pair(
        &self,
        result: &ReviewCheckResult,
        environment: &ReviewEnvironmentRecord,
    ) -> Result<(), ValidationError> {
        self.validate_check_result(result)?;
        self.validate_environment_record(environment)?;
        if result.environment_id != environment.environment_id
            || result.attempt_sequence != environment.attempt_sequence
            || result.check_id != environment.check_id
            || result.variant != environment.variant
        {
            return Err(ValidationError::new(
                "environment_id",
                ValidationCode::Inconsistent,
                "check result and environment profile do not describe one execution",
            ));
        }
        if environment.recorded_at > result.started_at {
            return Err(ValidationError::new(
                "recorded_at",
                ValidationCode::Inconsistent,
                "execution environment must be captured before the check starts",
            ));
        }
        let fully_contained =
            environment.process_containment == ReviewProcessContainment::PidNamespaceParentDeath;
        if fully_contained && result.process_tree_may_outlive {
            return Err(ValidationError::new(
                "process_tree_may_outlive",
                ValidationCode::Inconsistent,
                "a fully contained process tree cannot be recorded as potentially surviving",
            ));
        }
        if result.termination == ReviewCheckTermination::OutputCaptureIncomplete && fully_contained
        {
            return Err(ValidationError::new(
                "termination",
                ValidationCode::Inconsistent,
                "fully contained execution cannot abandon capture for a surviving descendant",
            ));
        }
        if matches!(
            result.termination,
            ReviewCheckTermination::TimedOut | ReviewCheckTermination::OutputLimitExceeded
        ) && !fully_contained
            && !result.process_tree_may_outlive
        {
            return Err(ValidationError::new(
                "process_tree_may_outlive",
                ValidationCode::Inconsistent,
                "forced termination without full containment may leave descendants",
            ));
        }
        Ok(())
    }

    fn validate_child_identity(
        &self,
        workspace_id: &WorkspaceId,
        session_id: &ReviewSessionId,
        request_id: &RequestId,
        candidate_sha: &GitSha,
        plan: &ReviewPlanIdentity,
    ) -> Result<(), ValidationError> {
        if workspace_id != &self.workspace_id
            || session_id != &self.session_id
            || request_id != &self.request_id
            || candidate_sha != &self.tree.candidate_sha
            || plan != &self.plan.identity
        {
            return Err(ValidationError::new(
                "session_id",
                ValidationCode::Inconsistent,
                "record does not match the exact session, candidate, or plan identity",
            ));
        }
        Ok(())
    }

    fn review_check(&self, check_id: &ReviewCheckId) -> Result<&ReviewCheck, ValidationError> {
        self.plan
            .checks
            .iter()
            .find(|check| &check.check_id == check_id)
            .ok_or_else(|| {
                ValidationError::new(
                    "check_id",
                    ValidationCode::Inconsistent,
                    "check is absent from the frozen review plan",
                )
            })
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
    ImplementationRequest {
        base_sha: GitSha,
        #[serde(default)]
        base_source: RequestBaseSource,
    },
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
#[serde(tag = "scope", content = "actor", rename_all = "snake_case")]
pub enum DeliveryRecipient {
    /// The logical active-Primary slot, independent of actor replacement.
    Primary,
    /// One exact actor generation.
    Actor(ActorDeliveryRecipient),
}

/// Exact actor and team generation that owned one frozen delivery.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ActorDeliveryRecipient {
    /// Exact actor generation that owned the delivery.
    pub actor: ActorRef,
    /// Exact team generation that contained that actor recipient.
    pub team_epoch: TeamEpoch,
}

impl std::ops::Deref for ActorDeliveryRecipient {
    type Target = ActorRef;

    fn deref(&self) -> &Self::Target {
        &self.actor
    }
}

/// Durable reason one frozen logical recipient no longer needs to acknowledge.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DeliveryRetirementReason {
    /// The recipient's team closed before it acknowledged the delivery.
    TeamClosed {
        /// Team whose terminal lifecycle made the recipient unreachable.
        team_id: TeamId,
        /// Exact terminal ownership generation of the team.
        team_epoch: TeamEpoch,
    },
    /// The exact recipient's team generation was superseded.
    TeamGenerationSuperseded {
        /// Team whose generation advanced past the frozen recipient.
        team_id: TeamId,
        /// Prior team generation in which the actor was a recipient.
        team_epoch: TeamEpoch,
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
    /// Team context of the accepted protocol fact, when team-scoped.
    pub team_id: Option<TeamId>,
    /// Exact team ownership generation of `team_id`, when team-scoped.
    pub team_epoch: Option<TeamEpoch>,
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

/// Rolling trust anchor for externally persisted observability facts.
///
/// Ordinary restore compares this compact count and head with the store's
/// atomically updated manifest. Explicit integrity diagnostics stream and
/// recompute the provider-neutral fact chain without hydrating it into the hot
/// domain snapshot.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ObservabilityCheckpoint {
    /// Total append-only observability facts accepted for the workspace.
    pub fact_count: u64,
    /// SHA-256 rolling head of the canonical observability fact chain.
    pub head_sha256: Option<PayloadDigest>,
}

impl ObservabilityCheckpoint {
    /// Returns whether no external observability facts are represented.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

impl Validate for ObservabilityCheckpoint {
    fn validate(&self) -> Result<(), ValidationError> {
        match (self.fact_count, self.head_sha256.as_ref()) {
            (0, None) => Ok(()),
            (0, Some(_)) => Err(ValidationError::new(
                "head_sha256",
                ValidationCode::Inconsistent,
                "an empty observability chain cannot have a head digest",
            )),
            (_, None) => Err(ValidationError::new(
                "head_sha256",
                ValidationCode::Required,
                "a non-empty observability chain requires a head digest",
            )),
            (_, Some(head)) => head.validate().map_err(|error| error.at("head_sha256")),
        }
    }
}

/// Rolling trust anchor for immutable archived team generations.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct TeamGenerationCheckpoint {
    /// Total archived team-generation records.
    pub record_count: u64,
    /// SHA-256 rolling head of the generation record chain.
    pub head_sha256: Option<PayloadDigest>,
}

impl TeamGenerationCheckpoint {
    /// Returns whether no team generation is archived.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

impl Validate for TeamGenerationCheckpoint {
    fn validate(&self) -> Result<(), ValidationError> {
        match (self.record_count, self.head_sha256.as_ref()) {
            (0, None) => Ok(()),
            (0, Some(_)) => Err(ValidationError::new(
                "head_sha256",
                ValidationCode::Inconsistent,
                "an empty team-generation chain cannot have a head digest",
            )),
            (_, None) => Err(ValidationError::new(
                "head_sha256",
                ValidationCode::Required,
                "a non-empty team-generation chain requires a head digest",
            )),
            (_, Some(head)) => head.validate().map_err(|error| error.at("head_sha256")),
        }
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
    /// Exact team ownership generation that owns this request.
    pub team_epoch: TeamEpoch,
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
    /// Rolling trust anchor for externally persisted observability facts.
    #[serde(default, skip_serializing_if = "ObservabilityCheckpoint::is_empty")]
    pub observability_checkpoint: ObservabilityCheckpoint,
    /// Rolling trust anchor for immutable archived team generations.
    #[serde(default, skip_serializing_if = "TeamGenerationCheckpoint::is_empty")]
    pub team_generation_checkpoint: TeamGenerationCheckpoint,
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

fn validate_review_argv(field: &str, argv: &[String]) -> Result<(), ValidationError> {
    if argv.is_empty() {
        return Err(ValidationError::new(
            field,
            ValidationCode::Required,
            "must contain an executable name",
        ));
    }
    validate_count(field, argv.len(), MAX_REVIEW_ARGUMENTS)?;
    for (index, argument) in argv.iter().enumerate() {
        let path = format!("{field}[{index}]");
        validate_review_value(&path, argument, MAX_REVIEW_ARGUMENT_CHARACTERS)?;
        if index == 0 && argument.trim().is_empty() {
            return Err(ValidationError::new(
                path,
                ValidationCode::Required,
                "executable name must not be blank",
            ));
        }
    }
    Ok(())
}

fn validate_review_value(field: &str, value: &str, maximum: usize) -> Result<(), ValidationError> {
    let actual = value.chars().count();
    if actual > maximum {
        return Err(ValidationError::new(
            field,
            ValidationCode::OutOfRange,
            format!("contains {actual} characters; maximum is {maximum}"),
        )
        .with_limit(actual, maximum, ValidationUnit::Characters));
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::new(
            field,
            ValidationCode::InvalidFormat,
            "must not contain control characters",
        ));
    }
    Ok(())
}

fn validate_exit_code(field: &str, value: i32) -> Result<(), ValidationError> {
    if (0..=255).contains(&value) {
        Ok(())
    } else {
        Err(ValidationError::new(
            field,
            ValidationCode::OutOfRange,
            "must be between 0 and 255",
        ))
    }
}

fn validate_path_text(field: &str, value: &str) -> Result<(), ValidationError> {
    validate_text(field, value, MAX_REVIEW_PATH_CHARACTERS)?;
    if value.chars().any(char::is_control) {
        return Err(ValidationError::new(
            field,
            ValidationCode::InvalidFormat,
            "must not contain control characters",
        ));
    }
    Ok(())
}

fn validate_relative_review_path(field: &str, value: &str) -> Result<(), ValidationError> {
    validate_path_text(field, value)?;
    if Path::new(value).components().any(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir
        )
    }) {
        return Err(ValidationError::new(
            field,
            ValidationCode::InvalidFormat,
            "must be a checkout-relative path without parent traversal",
        ));
    }
    Ok(())
}

fn validate_absolute_review_path(field: &str, value: &str) -> Result<(), ValidationError> {
    validate_path_text(field, value)?;
    if !Path::new(value).is_absolute() {
        return Err(ValidationError::new(
            field,
            ValidationCode::InvalidFormat,
            "must be an absolute path",
        ));
    }
    Ok(())
}

fn validate_declared_environment_key(key: &ReviewEnvironmentKey) -> Result<(), ValidationError> {
    let key_text = key.as_str();
    if !key_text.bytes().enumerate().all(|(index, byte)| {
        byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
    }) {
        return Err(ValidationError::new(
            format!("declared_environment[{key}]"),
            ValidationCode::InvalidFormat,
            "key must be a portable environment variable name",
        ));
    }
    if matches!(key_text, "HOME" | "PATH" | "PWD")
        || key_text.starts_with("AGSV_")
        || key_text.starts_with("GIT_")
    {
        return Err(ValidationError::new(
            format!("declared_environment[{key}]"),
            ValidationCode::InvalidFormat,
            "key is reserved for controller and Git isolation and cannot be declared or inherited",
        ));
    }
    Ok(())
}

fn validate_tool_probe_coverage(
    checks: &[ReviewCheck],
    probes: &[ReviewToolVersionProbe],
) -> Result<(), ValidationError> {
    let probed_programs = probes
        .iter()
        .map(|probe| probe.argv[0].as_str())
        .collect::<BTreeSet<_>>();
    for (index, check) in checks.iter().enumerate() {
        if !probed_programs.contains(check.argv[0].as_str()) {
            return Err(ValidationError::new(
                format!("checks[{index}].argv[0]"),
                ValidationCode::Inconsistent,
                "check executable must have a matching tool-version probe",
            ));
        }
    }
    Ok(())
}

fn review_declared_environment_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "maxProperties": MAX_REVIEW_ITEMS,
        "propertyNames": {
            "maxLength": 128,
            "pattern": "^(?!(?:HOME|PATH|PWD)$)(?!AGSV_)(?!GIT_)[A-Za-z_][A-Za-z0-9_]*$",
        },
        "additionalProperties": {
            "type": "string",
            "maxLength": MAX_REVIEW_ARGUMENT_CHARACTERS,
        },
    })
}

fn review_execution_environment_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let value_schema = schemars::json_schema!({
        "type": "string",
        "maxLength": MAX_REVIEW_ARGUMENT_CHARACTERS,
    });
    let digest_schema = schemars::json_schema!({
        "type": "string",
        "pattern": "^[0-9a-f]{64}$",
    });
    let path_schema = schemars::json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_REVIEW_PATH_CHARACTERS,
        "pattern": "^/",
    });
    schemars::json_schema!({
        "type": "object",
        "maxProperties": MAX_REVIEW_ITEMS,
        "properties": {
            "os": value_schema.clone(),
            "arch": value_schema.clone(),
            "agsv_version": value_schema.clone(),
            "cwd_identity": value_schema.clone(),
            "path_digest": digest_schema.clone(),
            "path_profile": value_schema.clone(),
            "declared_values_digest": digest_schema,
            "tmpdir": path_schema.clone(),
            "developer_dir": path_schema,
            "locale": value_schema.clone(),
            "language": value_schema.clone(),
            "lang": value_schema.clone(),
            "lc_all": value_schema,
        },
        "required": [
            "os",
            "arch",
            "agsv_version",
            "cwd_identity",
            "declared_values_digest",
            "tmpdir",
        ],
        "anyOf": [
            { "required": ["path_digest"] },
            { "required": ["path_profile"] },
        ],
        "additionalProperties": false,
    })
}

fn validate_execution_environment_key(key: &ReviewEnvironmentKey) -> Result<(), ValidationError> {
    if matches!(
        key.as_str(),
        "os" | "arch"
            | "agsv_version"
            | "cwd_identity"
            | "path_digest"
            | "path_profile"
            | "declared_values_digest"
            | "tmpdir"
            | "developer_dir"
            | "locale"
            | "language"
            | "lang"
            | "lc_all"
    ) {
        Ok(())
    } else {
        Err(ValidationError::new(
            format!("execution_environment[{key}]"),
            ValidationCode::InvalidFormat,
            "key is outside the privacy-safe execution environment allowlist",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::RequestBaseSource;
    use super::{
        Actor, ActorGenerationSummary, ActorProfileSnapshot, ActorRole,
        ActorTeamEpochCompletionSummary, ConflictNotice, Envelope, HUMAN_FACING_PRIMARY_CAPABILITY,
        ImplementationRequest, Message, MessageTarget, ObservabilityCheckpoint, PrimaryDirective,
        ProgressUpdate, ReviewAttemptStatus, ReviewBinaryObservation, ReviewBinaryPresence,
        ReviewCheck, ReviewCheckOutcome, ReviewCheckResult, ReviewCheckTermination,
        ReviewEnvironmentRecord, ReviewExecutionVariant, ReviewOutputArtifact, ReviewPlan,
        ReviewPlanIdentity, ReviewProcessContainment, ReviewRecoveryState, ReviewSession,
        ReviewSessionState, ReviewSessionStatus, ReviewToolVersion, ReviewToolVersionProbe,
        ReviewTreeIdentity, ReviewVerificationAttempt, TeamActivitySummary,
        TeamCloseDeliveryDisposition, TeamProfileSnapshot,
    };
    use crate::{
        ActorEpoch, ActorId, ActorProfileName, ActorStatus, AssignmentPolicyId, GitSha,
        MAX_REQUEST_TEXT_CHARACTERS, MessageId, MessageKind, PayloadDigest, PolicyRevision,
        PrimaryEpoch, RequestId, ReviewAttemptRecordId, ReviewBinaryId, ReviewCheckId,
        ReviewEnvironmentId, ReviewEnvironmentKey, ReviewSessionId, ReviewToolId, TeamEpoch,
        TeamId, TeamProfileName, TimestampMillis, Validate, ValidationCode, ValidationUnit,
        WorkspaceId,
    };
    use std::collections::{BTreeMap, BTreeSet};

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
    fn visibility_summaries_preserve_team_and_actor_generation_identity() {
        let workspace_id = WorkspaceId::new("workspace").expect("valid workspace");
        let team_id = TeamId::new("team").expect("valid team");
        let actor = super::ActorRef {
            actor_id: ActorId::new("implementation").expect("valid actor"),
            actor_epoch: ActorEpoch::new(7).expect("nonzero actor epoch"),
        };
        let team = TeamActivitySummary {
            workspace_id: workspace_id.clone(),
            team_id: team_id.clone(),
            team_epoch: TeamEpoch::new(5).expect("nonzero team epoch"),
            last_activity_at: TimestampMillis(101),
            nonterminal_request_count: 3,
        };
        let generation = ActorGenerationSummary {
            workspace_id,
            actor: actor.clone(),
            team_id: Some(team_id),
            team_epoch: Some(TeamEpoch::new(5).expect("nonzero team epoch")),
            generation_started_at: TimestampMillis(41),
            completed_assignment_count: 2,
            completed_assignments_by_team_epoch: vec![ActorTeamEpochCompletionSummary {
                team_epoch: TeamEpoch::new(6).expect("nonzero team epoch"),
                completed_assignment_count: 2,
            }],
        };

        let team_json = serde_json::to_value(team).expect("team summary serializes");
        assert_eq!(team_json["last_activity_at"], serde_json::json!(101));
        assert_eq!(team_json["nonterminal_request_count"], serde_json::json!(3));
        assert_eq!(team_json["team_epoch"], serde_json::json!(5));
        let generation_json =
            serde_json::to_value(generation).expect("generation summary serializes");
        assert_eq!(generation_json["actor"]["actor_id"], "implementation");
        assert_eq!(
            generation_json["actor"]["actor_epoch"],
            serde_json::json!(7)
        );
        assert_eq!(generation_json["team_epoch"], serde_json::json!(5));
        assert_eq!(
            generation_json["generation_started_at"],
            serde_json::json!(41)
        );
        assert_eq!(
            generation_json["completed_assignment_count"],
            serde_json::json!(2)
        );
        assert_eq!(
            generation_json["completed_assignments_by_team_epoch"],
            serde_json::json!([{"team_epoch": 6, "completed_assignment_count": 2}])
        );
    }

    #[test]
    fn observability_checkpoint_binds_empty_and_nonempty_chain_shapes() {
        let empty = ObservabilityCheckpoint::default();
        assert!(empty.is_empty());
        empty.validate().expect("empty checkpoint validates");

        let missing_head = ObservabilityCheckpoint {
            fact_count: 1,
            head_sha256: None,
        };
        let missing_error = missing_head.validate().expect_err("head is required");
        assert_eq!(missing_error.field, "head_sha256");
        assert_eq!(missing_error.code, ValidationCode::Required);

        let impossible_head = ObservabilityCheckpoint {
            fact_count: 0,
            head_sha256: Some(PayloadDigest::new("a".repeat(64)).expect("valid digest")),
        };
        let impossible_error = impossible_head
            .validate()
            .expect_err("empty chain cannot have a head");
        assert_eq!(impossible_error.field, "head_sha256");
        assert_eq!(impossible_error.code, ValidationCode::Inconsistent);

        let populated = ObservabilityCheckpoint {
            fact_count: 7,
            head_sha256: Some(PayloadDigest::new("b".repeat(64)).expect("valid digest")),
        };
        assert!(!populated.is_empty());
        populated
            .validate()
            .expect("populated checkpoint validates");
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
            base_source: RequestBaseSource::Derived,
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
            base_source: RequestBaseSource::Derived,
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

    fn review_digest(digit: char) -> PayloadDigest {
        PayloadDigest::new(digit.to_string().repeat(64)).expect("valid digest")
    }

    fn review_output(digit: char, reference: &str) -> ReviewOutputArtifact {
        ReviewOutputArtifact {
            digest: review_digest(digit),
            byte_count: 12,
            truncated: false,
            reference: Some(reference.to_owned()),
        }
    }

    fn review_plan() -> ReviewPlan {
        ReviewPlan {
            identity: ReviewPlanIdentity {
                policy_revision: PolicyRevision::INITIAL,
                config_digest: review_digest('a'),
            },
            checks: vec![ReviewCheck {
                check_id: ReviewCheckId::new("cargo-test").expect("valid check id"),
                argv: vec!["cargo".to_owned(), "test".to_owned(), "--locked".to_owned()],
                relative_cwd: Some("crates/agsv-protocol".to_owned()),
                timeout_seconds: 600,
                expected_exit_code: 0,
                required_absent_binaries: BTreeSet::from([
                    ReviewBinaryId::new("optional-cli").expect("valid binary id")
                ]),
            }],
            tool_version_probes: vec![ReviewToolVersionProbe {
                tool_id: ReviewToolId::new("cargo").expect("valid tool id"),
                argv: vec!["cargo".to_owned(), "--version".to_owned()],
            }],
            declared_environment: BTreeMap::from([(
                ReviewEnvironmentKey::new("PATH_PROFILE").expect("valid environment key"),
                "review-tools-only".to_owned(),
            )]),
            declared_environment_digest: review_digest('b'),
            optional_binaries: BTreeSet::from([
                ReviewBinaryId::new("cargo-nextest").expect("valid binary id")
            ]),
        }
    }

    fn review_session() -> ReviewSession {
        ReviewSession {
            session_id: ReviewSessionId::new("review-session-1").expect("valid session id"),
            workspace_id: WorkspaceId::new("workspace-1").expect("valid workspace id"),
            request_id: RequestId::new("request-1").expect("valid request id"),
            tree: ReviewTreeIdentity {
                candidate_sha: GitSha::new("1".repeat(40)).expect("valid candidate sha"),
                tree_sha: GitSha::new("2".repeat(40)).expect("valid tree sha"),
            },
            checkout_path: "/tmp/agsv-review/session-1".to_owned(),
            plan: review_plan(),
            state: ReviewSessionState::new(
                ReviewSessionStatus::Ready,
                ReviewRecoveryState::NotRequired,
            )
            .expect("valid session state"),
            created_at: TimestampMillis(10),
            updated_at: TimestampMillis(11),
        }
    }

    fn required_absent_environment(session: &ReviewSession) -> ReviewEnvironmentRecord {
        let check = &session.plan.checks[0];
        ReviewEnvironmentRecord {
            environment_id: ReviewEnvironmentId::new("environment-1")
                .expect("valid environment id"),
            workspace_id: session.workspace_id.clone(),
            session_id: session.session_id.clone(),
            request_id: session.request_id.clone(),
            candidate_sha: session.tree.candidate_sha.clone(),
            attempt_sequence: 1,
            plan: session.plan.identity.clone(),
            check_id: check.check_id.clone(),
            variant: ReviewExecutionVariant::RequiredAbsent,
            process_containment: ReviewProcessContainment::ProcessGroupOnly,
            recorded_at: TimestampMillis(20),
            declared_environment_digest: session.plan.declared_environment_digest.clone(),
            execution_environment: BTreeMap::from([
                (
                    ReviewEnvironmentKey::new("os").expect("valid key"),
                    "macos".to_owned(),
                ),
                (
                    ReviewEnvironmentKey::new("arch").expect("valid key"),
                    "aarch64".to_owned(),
                ),
                (
                    ReviewEnvironmentKey::new("agsv_version").expect("valid key"),
                    "0.3.0".to_owned(),
                ),
                (
                    ReviewEnvironmentKey::new("cwd_identity").expect("valid key"),
                    "tree:2222222222222222222222222222222222222222".to_owned(),
                ),
                (
                    ReviewEnvironmentKey::new("declared_values_digest").expect("valid key"),
                    review_digest('7').as_str().to_owned(),
                ),
                (
                    ReviewEnvironmentKey::new("path_profile").expect("valid key"),
                    "required-absent".to_owned(),
                ),
                (
                    ReviewEnvironmentKey::new("tmpdir").expect("valid key"),
                    "/private/tmp/agsv-review/session-1".to_owned(),
                ),
                (
                    ReviewEnvironmentKey::new("developer_dir").expect("valid key"),
                    "/Applications/Xcode.app/Contents/Developer".to_owned(),
                ),
            ]),
            execution_environment_digest: review_digest('c'),
            tool_versions: vec![ReviewToolVersion {
                tool_id: ReviewToolId::new("cargo").expect("valid tool id"),
                resolved_executable: "/usr/bin/cargo".to_owned(),
                executable_digest: review_digest('d'),
                probe_exit_code: 0,
                version: "cargo 1.85.0".to_owned(),
                stdout: review_output('e', "environment/cargo.stdout"),
                stderr: review_output('f', "environment/cargo.stderr"),
            }],
            binary_observations: vec![ReviewBinaryObservation {
                binary_id: ReviewBinaryId::new("optional-cli").expect("valid binary id"),
                presence: ReviewBinaryPresence::AbsentFromControlledPath,
                resolved_executable: None,
                executable_digest: None,
            }],
            required_absent_binaries: check.required_absent_binaries.clone(),
        }
    }

    fn required_absent_result(
        session: &ReviewSession,
        environment: &ReviewEnvironmentRecord,
    ) -> ReviewCheckResult {
        ReviewCheckResult {
            workspace_id: session.workspace_id.clone(),
            session_id: session.session_id.clone(),
            request_id: session.request_id.clone(),
            candidate_sha: session.tree.candidate_sha.clone(),
            attempt_sequence: 1,
            plan: session.plan.identity.clone(),
            check_id: session.plan.checks[0].check_id.clone(),
            variant: ReviewExecutionVariant::RequiredAbsent,
            environment_id: environment.environment_id.clone(),
            outcome: ReviewCheckOutcome::Passed,
            termination: ReviewCheckTermination::Exited,
            expected_exit_code: 0,
            actual_exit_code: Some(0),
            process_tree_may_outlive: false,
            stdout: review_output('1', "checks/cargo-test.stdout"),
            stderr: review_output('2', "checks/cargo-test.stderr"),
            started_at: TimestampMillis(20),
            finished_at: TimestampMillis(21),
        }
    }

    #[test]
    fn review_plan_rejects_empty_or_unbounded_configuration() {
        let mut plan = review_plan();
        plan.validate().expect("bounded exact argv plan is valid");

        plan.checks[0].argv.clear();
        assert_eq!(
            plan.validate()
                .expect_err("empty program is rejected")
                .field,
            "checks[0].argv"
        );
        let mut control_character = review_plan();
        control_character.declared_environment.insert(
            ReviewEnvironmentKey::new("unsafe").expect("valid key"),
            "line\nbreak".to_owned(),
        );
        assert_eq!(
            control_character
                .validate()
                .expect_err("control characters are rejected")
                .field,
            "declared_environment[unsafe]"
        );
        let mut traversal = review_plan();
        traversal.checks[0].relative_cwd = Some("../outside".to_owned());
        assert_eq!(
            traversal
                .validate()
                .expect_err("checkout traversal is rejected")
                .field,
            "checks[0].relative_cwd"
        );
        let mut no_timeout = review_plan();
        no_timeout.checks[0].timeout_seconds = 0;
        assert_eq!(
            no_timeout
                .validate()
                .expect_err("unbounded execution is rejected")
                .field,
            "checks[0].timeout_seconds"
        );
        let mut missing_probe = review_plan();
        missing_probe.tool_version_probes[0].argv[0] = "rustc".to_owned();
        assert_eq!(
            missing_probe
                .validate()
                .expect_err("each check program needs a matching probe")
                .field,
            "checks[0].argv[0]"
        );
        let mut invalid_environment_key = review_plan();
        invalid_environment_key.declared_environment.insert(
            ReviewEnvironmentKey::new("UNSAFE-NAME").expect("portable protocol id"),
            "placeholder".to_owned(),
        );
        assert_eq!(
            invalid_environment_key
                .validate()
                .expect_err("declared environment keys are portable variable names")
                .field,
            "declared_environment[UNSAFE-NAME]"
        );
    }

    #[test]
    fn declared_environment_rejects_controller_and_git_reserved_keys() {
        for (key, value) in [
            ("HOME", "/tmp/forged-home"),
            ("PATH", "{inherit}"),
            ("PWD", "{inherit}"),
            ("AGSV_STATE_DIR", "{inherit}"),
            ("GIT_CONFIG_COUNT", "{inherit}"),
        ] {
            let mut plan = review_plan();
            plan.declared_environment.insert(
                ReviewEnvironmentKey::new(key).expect("portable environment key"),
                value.to_owned(),
            );
            let error = plan
                .validate()
                .expect_err("controller and Git isolation keys are reserved");
            assert_eq!(error.field, format!("declared_environment[{key}]"));
            assert_eq!(error.code, ValidationCode::InvalidFormat);
        }
    }

    #[test]
    fn controlled_path_absence_is_named_truthfully() {
        let session = review_session();
        let environment = required_absent_environment(&session);
        assert_eq!(
            serde_json::to_value(&environment.binary_observations[0])
                .expect("observation serializes")["presence"],
            serde_json::json!("absent_from_controlled_path")
        );
    }

    #[test]
    fn review_output_artifact_records_bounded_prefix_truncation() {
        let artifact = review_output('8', "checks/bounded.stdout");
        let mut legacy = serde_json::to_value(&artifact).expect("artifact serializes");
        legacy
            .as_object_mut()
            .expect("artifact is an object")
            .remove("truncated");
        let decoded: ReviewOutputArtifact =
            serde_json::from_value(legacy).expect("legacy artifact deserializes");
        assert!(!decoded.truncated);

        let mut capped = artifact;
        capped.truncated = true;
        capped
            .validate()
            .expect("truncated prefix is valid evidence");
        assert_eq!(
            serde_json::to_value(capped).expect("artifact serializes")["truncated"],
            serde_json::json!(true)
        );
    }

    #[test]
    fn check_termination_and_process_containment_record_survivor_risk() {
        let session = review_session();
        let environment = required_absent_environment(&session);
        let result = required_absent_result(&session, &environment);
        session
            .validate_execution_pair(&result, &environment)
            .expect("a normal exit under process-group containment is valid");

        let mut timed_out = result.clone();
        timed_out.outcome = ReviewCheckOutcome::ExecutionError;
        timed_out.termination = ReviewCheckTermination::TimedOut;
        timed_out.actual_exit_code = None;
        timed_out.process_tree_may_outlive = true;
        session
            .validate_execution_pair(&timed_out, &environment)
            .expect("a process-group timeout may leave detached descendants");

        let mut timed_out_with_open_pipe = timed_out.clone();
        timed_out_with_open_pipe.stdout.truncated = true;
        session
            .validate_execution_pair(&timed_out_with_open_pipe, &environment)
            .expect("a timed-out descendant writer may leave a truncated captured prefix");

        let mut fully_contained = environment.clone();
        fully_contained.process_containment = ReviewProcessContainment::PidNamespaceParentDeath;
        assert_eq!(
            session
                .validate_execution_pair(&timed_out, &fully_contained)
                .expect_err("a fully contained process tree cannot outlive")
                .field,
            "process_tree_may_outlive"
        );

        let mut signaled = result.clone();
        signaled.outcome = ReviewCheckOutcome::ExecutionError;
        signaled.termination = ReviewCheckTermination::Signaled;
        signaled.actual_exit_code = None;
        signaled
            .validate()
            .expect("a signaled process is an execution error without an exit code");

        let mut passed_without_exit = signaled.clone();
        passed_without_exit.outcome = ReviewCheckOutcome::Passed;
        assert_eq!(
            passed_without_exit
                .validate()
                .expect_err("a passing check must exit normally")
                .field,
            "termination"
        );

        signaled.process_tree_may_outlive = true;
        assert_eq!(
            signaled
                .validate()
                .expect_err("a signaled process cannot record survivor risk")
                .field,
            "process_tree_may_outlive"
        );
    }

    #[test]
    fn weak_timeout_cannot_hide_detached_descendant_risk() {
        let session = review_session();
        let environment = required_absent_environment(&session);
        let mut timed_out = required_absent_result(&session, &environment);
        timed_out.outcome = ReviewCheckOutcome::ExecutionError;
        timed_out.termination = ReviewCheckTermination::TimedOut;
        timed_out.actual_exit_code = None;
        timed_out.process_tree_may_outlive = false;
        assert_eq!(
            session
                .validate_execution_pair(&timed_out, &environment)
                .expect_err("weak containment cannot suppress timeout survivor risk")
                .field,
            "process_tree_may_outlive"
        );

        let mut fully_contained = environment;
        fully_contained.process_containment = ReviewProcessContainment::PidNamespaceParentDeath;
        session
            .validate_execution_pair(&timed_out, &fully_contained)
            .expect("full containment makes a false survivor-risk flag truthful");
    }

    #[test]
    fn output_termination_binds_truncation_and_containment_evidence() {
        let session = review_session();
        let environment = required_absent_environment(&session);
        let result = required_absent_result(&session, &environment);
        let mut fully_contained = environment.clone();
        fully_contained.process_containment = ReviewProcessContainment::PidNamespaceParentDeath;

        let mut execution_error = result.clone();
        execution_error.outcome = ReviewCheckOutcome::ExecutionError;
        execution_error.termination = ReviewCheckTermination::Signaled;
        execution_error.actual_exit_code = None;

        let mut output_limited = execution_error.clone();
        output_limited.termination = ReviewCheckTermination::OutputLimitExceeded;
        output_limited.stdout.truncated = true;
        output_limited.process_tree_may_outlive = true;
        session
            .validate_execution_pair(&output_limited, &environment)
            .expect("forced output-limit termination records weak-containment survivor risk");

        let mut fully_contained_output_limit = output_limited.clone();
        fully_contained_output_limit.process_tree_may_outlive = false;
        session
            .validate_execution_pair(&fully_contained_output_limit, &fully_contained)
            .expect("full containment removes output-limit survivor risk");

        let mut incomplete_capture = result.clone();
        incomplete_capture.outcome = ReviewCheckOutcome::ExecutionError;
        incomplete_capture.termination = ReviewCheckTermination::OutputCaptureIncomplete;
        incomplete_capture.process_tree_may_outlive = true;
        session
            .validate_execution_pair(&incomplete_capture, &environment)
            .expect("an observed parent exit can retain its code when capture is abandoned");

        let mut signaled_incomplete_capture = incomplete_capture.clone();
        signaled_incomplete_capture.actual_exit_code = None;
        session
            .validate_execution_pair(&signaled_incomplete_capture, &environment)
            .expect("capture abandonment can follow a signaled parent without an exit code");

        let mut truncated_incomplete_capture = incomplete_capture.clone();
        truncated_incomplete_capture.stderr.truncated = true;
        assert_eq!(
            truncated_incomplete_capture
                .validate()
                .expect_err("cap excess takes precedence over incomplete capture")
                .field,
            "termination"
        );

        incomplete_capture.process_tree_may_outlive = false;
        assert_eq!(
            incomplete_capture
                .validate()
                .expect_err("incomplete capture records possible detached descendants")
                .field,
            "process_tree_may_outlive"
        );

        let mut fully_contained_incomplete = result.clone();
        fully_contained_incomplete.outcome = ReviewCheckOutcome::ExecutionError;
        fully_contained_incomplete.termination = ReviewCheckTermination::OutputCaptureIncomplete;
        fully_contained_incomplete.process_tree_may_outlive = true;
        assert_eq!(
            session
                .validate_execution_pair(&fully_contained_incomplete, &fully_contained)
                .expect_err("full containment rejects surviving-pipe capture abandonment")
                .field,
            "process_tree_may_outlive"
        );

        output_limited
            .validate()
            .expect("output-limit termination binds the persisted truncated prefix");

        let mut missing_truncation = execution_error;
        missing_truncation.termination = ReviewCheckTermination::OutputLimitExceeded;
        assert_eq!(
            missing_truncation
                .validate()
                .expect_err("output-limit termination needs a truncated stream")
                .field,
            "termination"
        );

        let mut unexplained_truncation = result.clone();
        unexplained_truncation.stderr.truncated = true;
        assert_eq!(
            unexplained_truncation
                .validate()
                .expect_err("truncation needs output-limit termination")
                .field,
            "termination"
        );
    }

    #[test]
    fn review_session_state_encodes_reusable_recovery_transitions() {
        let preparing = ReviewSessionState::new(
            ReviewSessionStatus::Preparing,
            ReviewRecoveryState::NotRequired,
        )
        .expect("valid preparing state");
        let ready =
            ReviewSessionState::new(ReviewSessionStatus::Ready, ReviewRecoveryState::NotRequired)
                .expect("valid ready state");
        let resume = ReviewSessionState::new(
            ReviewSessionStatus::Ready,
            ReviewRecoveryState::ResumeRequired,
        )
        .expect("valid recoverable state");
        let invalid = ReviewSessionState::new(
            ReviewSessionStatus::Invalid,
            ReviewRecoveryState::RecreateRequired,
        )
        .expect("valid invalid state");

        assert!(preparing.allows_transition_to(ready));
        assert!(ready.allows_transition_to(resume));
        assert!(resume.allows_transition_to(ready));
        assert!(ready.allows_transition_to(invalid));
        assert!(invalid.allows_transition_to(preparing));
        assert!(
            ReviewSessionState::new(
                ReviewSessionStatus::Invalid,
                ReviewRecoveryState::ResumeRequired
            )
            .is_err()
        );
        assert!(!ready.allows_transition_to(preparing));
    }

    #[test]
    fn append_only_attempt_facts_validate_status_and_timestamps() {
        let session = review_session();
        let mut attempt = ReviewVerificationAttempt {
            record_id: ReviewAttemptRecordId::new("attempt-record-running")
                .expect("valid record id"),
            workspace_id: session.workspace_id.clone(),
            session_id: session.session_id.clone(),
            request_id: session.request_id.clone(),
            candidate_sha: session.tree.candidate_sha.clone(),
            attempt_sequence: 1,
            plan: session.plan.identity.clone(),
            status: ReviewAttemptStatus::Running,
            started_at: TimestampMillis(12),
            finished_at: None,
            recorded_at: TimestampMillis(12),
        };
        session
            .validate_attempt_record(&attempt)
            .expect("running fact is valid");
        attempt.record_id =
            ReviewAttemptRecordId::new("attempt-record-passed").expect("valid record id");
        attempt.status = ReviewAttemptStatus::Passed;
        attempt.finished_at = Some(TimestampMillis(20));
        attempt.recorded_at = TimestampMillis(20);
        session
            .validate_attempt_record(&attempt)
            .expect("terminal append-only fact is valid");
        assert!(ReviewAttemptStatus::Running.allows_transition_to(ReviewAttemptStatus::Passed));
        assert!(!ReviewAttemptStatus::Passed.allows_transition_to(ReviewAttemptStatus::Running));

        attempt.finished_at = None;
        assert_eq!(
            attempt
                .validate()
                .expect_err("terminal fact needs finished_at")
                .field,
            "finished_at"
        );
    }

    #[test]
    fn check_result_and_environment_bind_exact_candidate_plan_and_variant() {
        let session = review_session();
        let environment = required_absent_environment(&session);
        let result = required_absent_result(&session, &environment);
        session
            .validate_execution_pair(&result, &environment)
            .expect("exact candidate, plan, check, variant, and environment bind");
        let mut normal_result = result.clone();
        normal_result.variant = ReviewExecutionVariant::Normal;
        normal_result.environment_id =
            ReviewEnvironmentId::new("environment-normal").expect("valid environment id");
        let attempt = ReviewVerificationAttempt {
            record_id: ReviewAttemptRecordId::new("attempt-record-passed")
                .expect("valid record id"),
            workspace_id: session.workspace_id.clone(),
            session_id: session.session_id.clone(),
            request_id: session.request_id.clone(),
            candidate_sha: session.tree.candidate_sha.clone(),
            attempt_sequence: 1,
            plan: session.plan.identity.clone(),
            status: ReviewAttemptStatus::Passed,
            started_at: TimestampMillis(19),
            finished_at: Some(TimestampMillis(22)),
            recorded_at: TimestampMillis(22),
        };
        session
            .validate_attempt_results(&attempt, &[normal_result, result.clone()])
            .expect("passed attempt covers normal and required-absent variants");
        let mut outside_attempt = result.clone();
        outside_attempt.started_at = TimestampMillis(18);
        assert_eq!(
            session
                .validate_attempt_results(&attempt, &[outside_attempt])
                .expect_err("check timestamps stay within their attempt")
                .field,
            "results[0].started_at"
        );
        assert!(
            session
                .validate_attempt_results(&attempt, std::slice::from_ref(&result))
                .is_err()
        );

        let encoded = serde_json::to_value(&environment).expect("environment serializes");
        let text = encoded.to_string();
        assert!(!text.contains("provider_id"));
        assert!(!text.contains("backend_id"));
        assert_eq!(
            encoded["candidate_sha"],
            serde_json::json!(session.tree.candidate_sha.as_str())
        );

        let mut forged_candidate = result.clone();
        forged_candidate.candidate_sha =
            GitSha::new("9".repeat(40)).expect("valid forged candidate sha");
        assert!(session.validate_check_result(&forged_candidate).is_err());
        let mut late_environment = environment.clone();
        late_environment.recorded_at = TimestampMillis(21);
        assert_eq!(
            session
                .validate_execution_pair(&result, &late_environment)
                .expect_err("environment evidence precedes process execution")
                .field,
            "recorded_at"
        );
        let mut forged_absence = environment;
        forged_absence.binary_observations[0].presence = ReviewBinaryPresence::Present;
        assert!(forged_absence.validate().is_err());
        let mut malformed_path_digest = required_absent_environment(&session);
        malformed_path_digest
            .execution_environment
            .remove(&ReviewEnvironmentKey::new("path_profile").expect("valid environment key"));
        malformed_path_digest.execution_environment.insert(
            ReviewEnvironmentKey::new("path_digest").expect("valid environment key"),
            "not-a-digest".to_owned(),
        );
        assert_eq!(
            malformed_path_digest
                .validate()
                .expect_err("PATH digests are lowercase SHA-256")
                .field,
            "execution_environment[path_digest].sha256"
        );
        let mut ambient_secret = required_absent_environment(&session);
        ambient_secret.execution_environment.insert(
            ReviewEnvironmentKey::new("secret_token").expect("portable but unsafe key"),
            "must-not-persist".to_owned(),
        );
        assert_eq!(
            ambient_secret
                .validate()
                .expect_err("actual environment is allowlisted")
                .field,
            "execution_environment[secret_token]"
        );
    }

    #[test]
    fn execution_environment_requires_expanded_declared_values_digest() {
        let session = review_session();
        let key =
            ReviewEnvironmentKey::new("declared_values_digest").expect("valid environment key");
        let mut missing = required_absent_environment(&session);
        missing.execution_environment.remove(&key);
        assert_eq!(
            missing
                .validate()
                .expect_err("expanded declared child environment must be bound")
                .field,
            "execution_environment"
        );

        let mut malformed = required_absent_environment(&session);
        malformed
            .execution_environment
            .insert(key, "not-a-digest".to_owned());
        assert_eq!(
            malformed
                .validate()
                .expect_err("declared-values digest is lowercase SHA-256")
                .field,
            "execution_environment[declared_values_digest].sha256"
        );
    }

    #[test]
    fn execution_environment_requires_tmpdir_and_allows_optional_developer_dir() {
        let session = review_session();
        let tmpdir = ReviewEnvironmentKey::new("tmpdir").expect("valid environment key");
        let developer_dir =
            ReviewEnvironmentKey::new("developer_dir").expect("valid environment key");
        let mut missing = required_absent_environment(&session);
        missing.execution_environment.remove(&tmpdir);
        assert_eq!(
            missing
                .validate()
                .expect_err("the exact controller-owned temporary directory is required")
                .field,
            "execution_environment"
        );

        let mut relative_tmpdir = required_absent_environment(&session);
        relative_tmpdir
            .execution_environment
            .insert(tmpdir, "relative/tmp".to_owned());
        assert_eq!(
            relative_tmpdir
                .validate()
                .expect_err("tmpdir records an absolute child-environment path")
                .field,
            "execution_environment[tmpdir]"
        );

        let mut without_developer_dir = required_absent_environment(&session);
        without_developer_dir
            .execution_environment
            .remove(&developer_dir);
        without_developer_dir
            .validate()
            .expect("developer_dir remains an optional privacy-allowlisted fact");
    }
}
