//! Embedded durable control plane for Agent Supervisor.
#![forbid(unsafe_code)]

mod backend;
mod engine;
mod error;
mod identity;
mod store;

pub use engine::{BackendKind, ControlPlane, ControlSettings};
pub use error::ControlError;
pub use identity::{WorkspaceIdentity, default_state_directory};
