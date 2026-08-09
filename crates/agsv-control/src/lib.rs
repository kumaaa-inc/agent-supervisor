//! Embedded durable control plane for Agent Supervisor.
#![forbid(unsafe_code)]

mod backend;
mod engine;
mod error;
mod identity;
mod store;

pub use engine::{
    ActorProfileSettings, BackendKind, ControlPlane, ControlSettings, MAX_PROFILE_CAPABILITIES,
    SUPPORTED_ASSIGNMENT_POLICIES, TeamProfileSettings, validate_assignment_policy,
    validate_runtime,
};
pub use error::ControlError;
pub use identity::{WorkspaceIdentity, default_state_directory};
