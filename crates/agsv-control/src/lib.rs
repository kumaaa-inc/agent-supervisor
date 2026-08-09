//! Embedded durable control plane for Agent Supervisor.
#![forbid(unsafe_code)]

mod backend;
mod caller;
mod engine;
mod error;
mod identity;
mod presentation;
mod store;

pub use engine::{ControlPlane, ControlSettings};
pub use error::ControlError;
pub use identity::{WorkspaceIdentity, default_state_directory};
