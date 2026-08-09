//! Provider-independent Agent Supervisor domain logic.
//!
//! Core validates serialized-size quotas after decoding. Transport and mailbox
//! adapters must additionally enforce [`agsv_protocol::MAX_FRAME_BYTES`] before
//! allocating or deserializing an untrusted frame, and bound queued bytes on
//! disk independently of the per-workspace domain limits.
#![forbid(unsafe_code)]

mod error;
mod supervisor;
mod transitions;

pub use agsv_protocol::{AuditEvent, AuditEventKind, PROTOCOL_VERSION};
pub use error::*;
pub use supervisor::*;
pub use transitions::*;
