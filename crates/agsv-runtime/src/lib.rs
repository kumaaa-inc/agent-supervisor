#![allow(clippy::missing_errors_doc)]

//! Durable local control plane for Agent Supervisor.
//!
//! [`SqliteStore`] owns persistent coordination state. [`RuntimeService`] is a
//! single-instance service abstraction that couples that state to a replaceable
//! [`agsv_session::SessionBackend`] without making Herdr architectural.

mod adapter;
mod service;
mod store;
mod types;

pub use adapter::{
    AdapterError, AgentRuntime, CapabilitySupport, CodexAdapter, InitialPromptDelivery,
    RuntimeCapabilities, RuntimeConfig, RuntimeDiagnostics, RuntimeId, RuntimeInvocation,
    RuntimeLaunchPolicy, RuntimeLaunchRequest, RuntimeRegistry, RuntimeResumeRequest,
};
pub use service::{BackendRegistry, RuntimeService};
pub use store::SqliteStore;
pub use types::{
    ActorRecord, ActorRole, ActorSpec, ActorState, AuditEvent, ClaimedMessage, DaemonLease,
    LaunchIntent, LaunchIntentState, MessageRecord, NewMessage, PrimaryLease, ReconcileReport,
    RuntimeError, SenderContext,
};
