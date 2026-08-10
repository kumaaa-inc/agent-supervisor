//! Explicit pure state machines used by the aggregate.

use crate::CoreError;
use agsv_protocol::{ActorStatus, RequestStatus, RunStatus, TeamStatus};

/// Events accepted by the request state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestEvent {
    /// Establish the sole active assignment.
    Assign,
    /// Begin or resume implementation.
    Start,
    /// Record a blocker.
    Block,
    /// Submit an exact candidate.
    SubmitCandidate,
    /// Reject the current exact candidate.
    RejectCandidate,
    /// Accept the current exact candidate.
    AcceptCandidate,
    /// Authorize integration of the accepted exact candidate.
    AuthorizeIntegration,
    /// Report authorized integration complete.
    Complete,
    /// Cancel work.
    Cancel,
}

impl RequestEvent {
    const fn name(self) -> &'static str {
        match self {
            Self::Assign => "assign",
            Self::Start => "start",
            Self::Block => "block",
            Self::SubmitCandidate => "submit_candidate",
            Self::RejectCandidate => "reject_candidate",
            Self::AcceptCandidate => "accept_candidate",
            Self::AuthorizeIntegration => "authorize_integration",
            Self::Complete => "complete",
            Self::Cancel => "cancel",
        }
    }
}

/// Applies a request event without mutating any state.
///
/// Repeating an event that has already reached its direct result is idempotent.
///
/// # Errors
///
/// Returns an explicit invalid-transition error for all other pairs.
pub fn transition_request(
    current: RequestStatus,
    event: RequestEvent,
) -> Result<RequestStatus, CoreError> {
    let next = match (current, event) {
        (RequestStatus::Open | RequestStatus::Assigned, RequestEvent::Assign) => {
            RequestStatus::Assigned
        }
        (
            RequestStatus::Assigned
            | RequestStatus::InProgress
            | RequestStatus::Blocked
            | RequestStatus::ChangesRequested,
            RequestEvent::Start,
        ) => RequestStatus::InProgress,
        (
            RequestStatus::Assigned
            | RequestStatus::InProgress
            | RequestStatus::Blocked
            | RequestStatus::ChangesRequested,
            RequestEvent::Block,
        ) => RequestStatus::Blocked,
        (
            RequestStatus::Assigned
            | RequestStatus::InProgress
            | RequestStatus::Blocked
            | RequestStatus::ChangesRequested
            | RequestStatus::CandidateReady,
            RequestEvent::SubmitCandidate,
        ) => RequestStatus::CandidateReady,
        (
            RequestStatus::CandidateReady | RequestStatus::ChangesRequested,
            RequestEvent::RejectCandidate,
        ) => RequestStatus::ChangesRequested,
        (
            RequestStatus::CandidateReady | RequestStatus::Accepted,
            RequestEvent::AcceptCandidate,
        ) => RequestStatus::Accepted,
        (
            RequestStatus::Accepted | RequestStatus::IntegrationAuthorized,
            RequestEvent::AuthorizeIntegration,
        ) => RequestStatus::IntegrationAuthorized,
        (
            RequestStatus::IntegrationAuthorized | RequestStatus::Completed,
            RequestEvent::Complete,
        ) => RequestStatus::Completed,
        (RequestStatus::Cancelled, RequestEvent::Cancel) => RequestStatus::Cancelled,
        (state, RequestEvent::Cancel) if !state.is_terminal() => RequestStatus::Cancelled,
        _ => {
            return Err(CoreError::InvalidTransition {
                entity: "request",
                from: format!("{current:?}"),
                event: event.name(),
            });
        }
    };
    Ok(next)
}

/// Events accepted by the run state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunEvent {
    /// Assign and activate the run.
    Start,
    /// Pause active work.
    Pause,
    /// Resume paused or blocked work.
    Resume,
    /// Record a blocker.
    Block,
    /// Wait for candidate review.
    SubmitCandidate,
    /// Request a replacement candidate.
    RejectCandidate,
    /// Accept the current candidate.
    AcceptCandidate,
    /// Authorize external integration.
    AuthorizeIntegration,
    /// Report completion.
    Complete,
    /// Cancel the run.
    Cancel,
}

impl RunEvent {
    const fn name(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Block => "block",
            Self::SubmitCandidate => "submit_candidate",
            Self::RejectCandidate => "reject_candidate",
            Self::AcceptCandidate => "accept_candidate",
            Self::AuthorizeIntegration => "authorize_integration",
            Self::Complete => "complete",
            Self::Cancel => "cancel",
        }
    }
}

/// Applies a run event without mutating state.
///
/// # Errors
///
/// Returns an explicit invalid-transition error for illegal pairs.
pub fn transition_run(current: RunStatus, event: RunEvent) -> Result<RunStatus, CoreError> {
    let next = match (current, event) {
        (RunStatus::Pending | RunStatus::Active, RunEvent::Start)
        | (
            RunStatus::Paused
            | RunStatus::Blocked
            | RunStatus::RevisionRequested
            | RunStatus::Active,
            RunEvent::Resume,
        ) => RunStatus::Active,
        (RunStatus::Active | RunStatus::Paused, RunEvent::Pause) => RunStatus::Paused,
        (RunStatus::Active | RunStatus::Blocked, RunEvent::Block) => RunStatus::Blocked,
        (
            RunStatus::Active
            | RunStatus::Blocked
            | RunStatus::AwaitingReview
            | RunStatus::RevisionRequested,
            RunEvent::SubmitCandidate,
        ) => RunStatus::AwaitingReview,
        (RunStatus::AwaitingReview | RunStatus::RevisionRequested, RunEvent::RejectCandidate) => {
            RunStatus::RevisionRequested
        }
        (RunStatus::AwaitingReview | RunStatus::Accepted, RunEvent::AcceptCandidate) => {
            RunStatus::Accepted
        }
        (RunStatus::Accepted | RunStatus::Authorized, RunEvent::AuthorizeIntegration) => {
            RunStatus::Authorized
        }
        (RunStatus::Authorized | RunStatus::Completed, RunEvent::Complete) => RunStatus::Completed,
        (RunStatus::Cancelled, RunEvent::Cancel) => RunStatus::Cancelled,
        (state, RunEvent::Cancel)
            if !matches!(state, RunStatus::Cancelled | RunStatus::Completed) =>
        {
            RunStatus::Cancelled
        }
        _ => {
            return Err(CoreError::InvalidTransition {
                entity: "run",
                from: format!("{current:?}"),
                event: event.name(),
            });
        }
    };
    Ok(next)
}

/// Applies an actor lifecycle transition.
///
/// # Errors
///
/// Returns an explicit invalid-transition error for illegal pairs.
pub fn transition_actor(current: ActorStatus, next: ActorStatus) -> Result<ActorStatus, CoreError> {
    if current == next {
        return Ok(current);
    }
    if matches!(
        (current, next),
        (
            ActorStatus::Starting | ActorStatus::Stale,
            ActorStatus::Healthy | ActorStatus::Revoked | ActorStatus::Stopped
        ) | (
            ActorStatus::Healthy,
            ActorStatus::Stale | ActorStatus::Revoked | ActorStatus::Stopped
        ) | (ActorStatus::Revoked, ActorStatus::Stopped)
    ) {
        return Ok(next);
    }
    Err(CoreError::InvalidTransition {
        entity: "actor",
        from: format!("{current:?}"),
        event: match next {
            ActorStatus::Starting => "starting",
            ActorStatus::Healthy => "healthy",
            ActorStatus::Stale => "stale",
            ActorStatus::Revoked => "revoked",
            ActorStatus::Stopped => "stopped",
        },
    })
}

/// Applies a team lifecycle transition.
///
/// # Errors
///
/// Returns an explicit invalid-transition error for illegal pairs.
pub fn transition_team(current: TeamStatus, next: TeamStatus) -> Result<TeamStatus, CoreError> {
    if current == next {
        return Ok(current);
    }
    if matches!(
        (current, next),
        (TeamStatus::Active, TeamStatus::Paused | TeamStatus::Closing)
            | (TeamStatus::Paused, TeamStatus::Active | TeamStatus::Closing)
            | (TeamStatus::Closing, TeamStatus::Closed)
    ) {
        return Ok(next);
    }
    Err(CoreError::InvalidTransition {
        entity: "team",
        from: format!("{current:?}"),
        event: match next {
            TeamStatus::Active => "active",
            TeamStatus::Paused => "paused",
            TeamStatus::Closing => "closing",
            TeamStatus::Closed => "closed",
            TeamStatus::Retired => "retired",
        },
    })
}

#[cfg(test)]
mod tests {
    use super::{RequestEvent, transition_actor, transition_request, transition_team};
    use agsv_protocol::{ActorStatus, RequestStatus, TeamStatus, request_blocks_team_close};

    #[test]
    fn request_transition_matrix_rejects_every_terminal_escape() {
        let events = [
            RequestEvent::Assign,
            RequestEvent::Start,
            RequestEvent::Block,
            RequestEvent::SubmitCandidate,
            RequestEvent::RejectCandidate,
            RequestEvent::AcceptCandidate,
            RequestEvent::AuthorizeIntegration,
            RequestEvent::Cancel,
        ];

        for terminal in [RequestStatus::Cancelled, RequestStatus::Completed] {
            for event in events {
                let result = transition_request(terminal, event);
                if terminal == RequestStatus::Cancelled && event == RequestEvent::Cancel {
                    assert_eq!(result, Ok(RequestStatus::Cancelled));
                } else {
                    assert!(
                        result.is_err(),
                        "{terminal:?} unexpectedly accepted {event:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn direct_result_transitions_are_idempotent() {
        assert_eq!(
            transition_request(RequestStatus::CandidateReady, RequestEvent::SubmitCandidate),
            Ok(RequestStatus::CandidateReady)
        );
        assert_eq!(
            transition_request(RequestStatus::Accepted, RequestEvent::AcceptCandidate),
            Ok(RequestStatus::Accepted)
        );
    }

    #[test]
    fn team_close_lifecycle_and_legacy_retired_state_are_terminal() {
        for start in [TeamStatus::Active, TeamStatus::Paused] {
            assert_eq!(
                transition_team(start, TeamStatus::Closing),
                Ok(TeamStatus::Closing)
            );
        }
        assert_eq!(
            transition_team(TeamStatus::Closing, TeamStatus::Closed),
            Ok(TeamStatus::Closed)
        );
        for terminal in [TeamStatus::Closed, TeamStatus::Retired] {
            for next in [
                TeamStatus::Active,
                TeamStatus::Paused,
                TeamStatus::Closing,
                TeamStatus::Closed,
                TeamStatus::Retired,
            ] {
                if next == terminal {
                    assert_eq!(transition_team(terminal, next), Ok(terminal));
                } else {
                    assert!(transition_team(terminal, next).is_err());
                }
            }
        }
        assert!(transition_team(TeamStatus::Active, TeamStatus::Retired).is_err());
        assert!(transition_team(TeamStatus::Paused, TeamStatus::Closed).is_err());
        assert!(transition_team(TeamStatus::Closing, TeamStatus::Active).is_err());
    }

    #[test]
    fn close_blocking_policy_is_distinct_from_request_terminality() {
        for status in [
            RequestStatus::Accepted,
            RequestStatus::IntegrationAuthorized,
            RequestStatus::Cancelled,
        ] {
            assert!(!request_blocks_team_close(status), "{status:?}");
        }
        for status in [
            RequestStatus::Open,
            RequestStatus::Assigned,
            RequestStatus::InProgress,
            RequestStatus::Blocked,
            RequestStatus::CandidateReady,
            RequestStatus::ChangesRequested,
            RequestStatus::Completed,
        ] {
            assert!(request_blocks_team_close(status), "{status:?}");
        }
        assert!(RequestStatus::Completed.is_terminal());
        assert!(request_blocks_team_close(RequestStatus::Completed));
    }

    #[test]
    fn stopped_actor_generation_cannot_heartbeat_back_to_healthy() {
        assert!(transition_actor(ActorStatus::Stopped, ActorStatus::Healthy).is_err());
        assert_eq!(
            transition_actor(ActorStatus::Stale, ActorStatus::Healthy),
            Ok(ActorStatus::Healthy)
        );
    }
}
