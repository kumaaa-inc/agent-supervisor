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

    #[test]
    fn generated_schemas_publish_runtime_bounds() {
        let wire = serde_json::to_value(wire_schema()).expect("schema serializes");
        let domain = serde_json::to_value(domain_schema()).expect("schema serializes");

        assert_eq!(
            wire.pointer("/$defs/ProgressUpdate/properties/percent_complete/maximum"),
            Some(&serde_json::json!(100))
        );
        assert_eq!(
            wire.pointer("/$defs/ImplementationRequest/properties/acceptance_criteria/minItems"),
            Some(&serde_json::json!(1))
        );
        assert_eq!(
            wire.pointer("/$defs/ImplementationRequest/properties/acceptance_criteria/maxItems"),
            Some(&serde_json::json!(64))
        );
        assert_eq!(
            wire.pointer("/$defs/ImplementationRequest/properties/instructions/maxLength"),
            Some(&serde_json::json!(65_536))
        );
        assert_eq!(
            wire.pointer(
                "/$defs/ImplementationRequest/properties/acceptance_criteria/items/maxLength"
            ),
            Some(&serde_json::json!(65_536))
        );
        assert_eq!(
            domain.pointer("/properties/deliveries/maxItems"),
            Some(&serde_json::json!(100_000))
        );
        assert_eq!(
            domain.pointer("/$defs/ActorProfileSnapshot/properties/capabilities/maxItems"),
            Some(&serde_json::json!(256))
        );
        assert_eq!(
            domain.pointer("/$defs/TeamProfileSnapshot/properties/desired_instances/minimum"),
            Some(&serde_json::json!(0))
        );
        assert_eq!(
            domain.pointer("/$defs/TeamProfileSnapshot/properties/desired_instances/maximum"),
            Some(&serde_json::json!(1_024))
        );
        assert_eq!(
            domain.pointer("/$defs/PayloadDigest/properties/sha256/pattern"),
            Some(&serde_json::json!("^[0-9a-f]{64}$"))
        );
        assert_eq!(
            domain.pointer("/properties/history_checkpoint/$ref"),
            Some(&serde_json::json!("#/$defs/HistoryCheckpoint"))
        );
        assert_eq!(
            domain.pointer("/$defs/HistoryCheckpoint/properties/audit_event_count/format"),
            Some(&serde_json::json!("uint64"))
        );
    }
}
