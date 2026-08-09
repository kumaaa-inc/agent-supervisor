//! JSON Schema roots generated from the Rust protocol source of truth.

use crate::{DomainSnapshot, WireFrame};
use schemars::{Schema, schema_for};

/// Generates the external wire-frame schema.
#[must_use]
pub fn wire_schema() -> Schema {
    schema_for!(WireFrame)
}

/// Generates the persisted domain snapshot schema.
#[must_use]
pub fn domain_schema() -> Schema {
    schema_for!(DomainSnapshot)
}

#[cfg(test)]
mod tests {
    use super::{domain_schema, wire_schema};

    #[test]
    fn committed_schemas_match_rust_types() {
        let wire: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/agsv-wire-v0.1.schema.json"
        )))
        .expect("committed wire schema is JSON");
        let domain: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/agsv-domain-v0.1.schema.json"
        )))
        .expect("committed domain schema is JSON");

        assert_eq!(
            wire,
            serde_json::to_value(wire_schema()).expect("schema serializes")
        );
        assert_eq!(
            domain,
            serde_json::to_value(domain_schema()).expect("schema serializes")
        );
    }
}
