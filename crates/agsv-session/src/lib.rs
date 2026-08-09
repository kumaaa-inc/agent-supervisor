#![allow(clippy::missing_errors_doc)]

//! Replaceable session backends for top-level orchestrators.
//!
//! The runtime depends only on [`SessionBackend`]. Process and Herdr support live
//! behind adapters so provider commands and identifiers do not enter the durable
//! control-plane model.

mod fake;
mod herdr;
mod process;
mod types;

pub use fake::{FakeEvent, FakeSessionBackend};
pub use herdr::{HerdrAdapter, HerdrTemplates};
pub use process::{
    CommandInvocation, CommandOutput, CommandRunner, CommandTemplate, ConfiguredProcessBackend,
    ProcessTemplates, SystemCommandRunner,
};
pub use types::{
    LaunchRequest, ResumeRequest, SessionBackend, SessionError, SessionHandle, SessionSnapshot,
    SessionStatus,
};
