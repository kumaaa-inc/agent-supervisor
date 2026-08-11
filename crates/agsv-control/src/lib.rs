//! Embedded durable control plane for Agent Supervisor.
#![forbid(unsafe_code)]

mod backend;
mod caller;
mod engine;
mod error;
mod identity;
mod presentation;
mod review;
mod store;

pub use engine::{
    ActorProfileSettings, ControlPlane, ControlSettings, MAX_PROFILE_CAPABILITIES,
    ReviewCheckSettings, ReviewSettings, ReviewToolVersionSettings, SUPPORTED_ASSIGNMENT_POLICIES,
    TeamProfileSettings, validate_assignment_policy, validate_runtime,
};
pub use error::ControlError;
pub use identity::{WorkspaceIdentity, default_state_directory};
