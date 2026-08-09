//! Provider-independent core failures.

use agsv_protocol::{
    ActorEpoch, ActorId, AssignmentEpoch, GitSha, PolicyRevision, PrimaryEpoch, RequestId, RunId,
    TeamEpoch, TeamId, ValidationError, WorkspaceId,
};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// A stable failure raised before durable state is mutated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreError {
    /// Static protocol validation failed.
    Validation(ValidationError),
    /// The envelope belongs to another workspace.
    WrongWorkspace {
        /// Workspace owned by the aggregate.
        expected: WorkspaceId,
        /// Workspace carried by the command.
        actual: WorkspaceId,
    },
    /// The message id was already used for different content.
    DuplicateMessageConflict,
    /// No actor is registered with this id.
    UnknownActor(ActorId),
    /// The actor process generation is stale.
    StaleActorEpoch {
        /// Current generation.
        expected: ActorEpoch,
        /// Supplied generation.
        actual: ActorEpoch,
    },
    /// The actor is registered but not healthy.
    ActorNotHealthy(ActorId),
    /// No Primary lease is active.
    NoActivePrimary,
    /// A non-active Primary attempted a Primary-only operation.
    NotActivePrimary(ActorId),
    /// The active Primary lease fence did not match.
    StalePrimaryEpoch {
        /// Current fence.
        expected: PrimaryEpoch,
        /// Supplied fence.
        actual: PrimaryEpoch,
    },
    /// The policy fence did not match.
    StalePolicyRevision {
        /// Current policy.
        expected: PolicyRevision,
        /// Supplied policy.
        actual: PolicyRevision,
    },
    /// No team exists with this id.
    UnknownTeam(TeamId),
    /// The team ownership fence did not match.
    StaleTeamEpoch {
        /// Current fence.
        expected: TeamEpoch,
        /// Supplied fence.
        actual: TeamEpoch,
    },
    /// Team context did not match the actor or request.
    WrongTeam,
    /// No request exists with this id.
    UnknownRequest(RequestId),
    /// No run exists with this id.
    UnknownRun(RunId),
    /// Request and run envelope context disagree with durable state.
    WrongRequestContext,
    /// The assignment fence did not match.
    StaleAssignmentEpoch {
        /// Current fence.
        expected: AssignmentEpoch,
        /// Supplied fence, if any.
        actual: Option<AssignmentEpoch>,
    },
    /// The sender is not the sole current assignee.
    NotAssignedActor,
    /// The actor role is not allowed to perform this operation.
    Unauthorized(&'static str),
    /// The message routing target is inconsistent with the operation.
    WrongTarget,
    /// The requested state transition is not legal.
    InvalidTransition {
        /// Domain entity type.
        entity: &'static str,
        /// Current state.
        from: String,
        /// Requested event.
        event: &'static str,
    },
    /// A stable id was already created with different semantics.
    AlreadyExists(&'static str),
    /// A message references a different immutable candidate.
    CandidateMismatch {
        /// Current candidate SHA, if one exists.
        expected: Option<GitSha>,
        /// Supplied candidate SHA.
        actual: GitSha,
    },
    /// A rejected candidate must be replaced by a different commit.
    CandidateMustChange,
    /// The decision does not match the current candidate or review cycle.
    DecisionMismatch,
    /// No matching pending handoff transaction exists.
    UnknownHandoff,
    /// The message being acknowledged is not in the mailbox.
    UnknownMessage,
    /// The actor is outside the message's routing target.
    AckNotAuthorized,
    /// A monotonic fence or audit sequence exhausted `u64`.
    EpochExhausted,
    /// Persisted aggregate state failed structural or referential validation.
    InvalidSnapshot {
        /// Logical location of the corruption.
        path: String,
        /// Stable explanation of the violated invariant.
        reason: &'static str,
    },
}

impl Display for CoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for CoreError {}

impl From<ValidationError> for CoreError {
    fn from(value: ValidationError) -> Self {
        Self::Validation(value)
    }
}
