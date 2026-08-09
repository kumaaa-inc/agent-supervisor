#![allow(clippy::missing_errors_doc)]

//! Durable local control plane for Agent Supervisor.
//!
//! [`SqliteStore`] owns persistent coordination state. [`RuntimeService`] is a
//! single-instance service abstraction that couples that state to a replaceable
//! [`agsv_session::SessionBackend`] without making Herdr architectural.

mod service;
mod store;
mod types;

pub use service::RuntimeService;
pub use store::SqliteStore;
pub use types::{
    ActorRecord, ActorRole, ActorSpec, ActorState, AuditEvent, ClaimedMessage, DaemonLease,
    MessageRecord, NewMessage, PrimaryLease, ReconcileReport, RuntimeError,
};
