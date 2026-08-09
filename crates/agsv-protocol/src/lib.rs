//! Stable domain and wire types for Agent Supervisor.
//!
//! This crate is the source of truth for external JSON Schemas. It deliberately
//! contains no runtime or provider adapter identifiers.
#![forbid(unsafe_code)]

mod ids;
mod model;
mod schema;
mod validation;

pub use ids::*;
pub use model::*;
pub use schema::*;
pub use validation::*;

/// Protocol version implemented by this crate.
pub const PROTOCOL_VERSION: u32 = 1;
