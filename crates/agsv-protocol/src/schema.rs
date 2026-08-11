//! JSON Schema roots generated from the Rust protocol source of truth.

use crate::{
    DomainSnapshot, ReviewCheckResult, ReviewEnvironmentRecord, ReviewSession,
    ReviewVerificationAttempt, WireFrame,
};
use schemars::{JsonSchema, Schema, schema_for};

#[derive(JsonSchema)]
#[allow(dead_code)]
struct ReviewRecordsSchema {
    session: ReviewSession,
    verification_attempt: ReviewVerificationAttempt,
    check_result: ReviewCheckResult,
    environment_record: ReviewEnvironmentRecord,
}

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

/// Generates the durable exact-SHA review-record schema.
#[must_use]
pub fn review_schema() -> Schema {
    schema_for!(ReviewRecordsSchema)
}

#[cfg(test)]
mod tests {
    use super::{domain_schema, review_schema, wire_schema};

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
        let review: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/agsv-review-v0.1.schema.json"
        )))
        .expect("committed review schema is JSON");

        assert_eq!(
            wire,
            serde_json::to_value(wire_schema()).expect("schema serializes")
        );
        assert_eq!(
            domain,
            serde_json::to_value(domain_schema()).expect("schema serializes")
        );
        assert_eq!(
            review,
            serde_json::to_value(review_schema()).expect("schema serializes")
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
        assert_eq!(
            domain.pointer("/$defs/HistoryCheckpoint/properties/archive_commit_count/format"),
            Some(&serde_json::json!("uint64"))
        );
        assert_eq!(
            domain.pointer("/$defs/HistoryCheckpoint/properties/archive_head_sha256/anyOf/0/$ref"),
            Some(&serde_json::json!("#/$defs/PayloadDigest"))
        );
    }

    #[test]
    fn generated_review_schema_publishes_runtime_bounds() {
        let review = serde_json::to_value(review_schema()).expect("schema serializes");

        assert_eq!(
            review.pointer("/$defs/ReviewCheck/properties/argv/minItems"),
            Some(&serde_json::json!(1))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewCheck/properties/timeout_seconds/maximum"),
            Some(&serde_json::json!(86_400))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewPlan/properties/tool_version_probes/minItems"),
            Some(&serde_json::json!(1))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewOutputArtifact/properties/truncated/type"),
            Some(&serde_json::json!("boolean"))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewOutputArtifact/properties/truncated/default"),
            Some(&serde_json::json!(false))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewVerificationAttempt/properties/attempt_sequence/minimum"),
            Some(&serde_json::json!(1))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewEnvironmentRecord/properties/execution_environment/type"),
            Some(&serde_json::json!("object"))
        );
        assert_eq!(
            review.pointer(
                "/$defs/ReviewEnvironmentRecord/properties/execution_environment/additionalProperties"
            ),
            Some(&serde_json::json!(false))
        );
        assert_eq!(
            review.pointer(
                "/$defs/ReviewEnvironmentRecord/properties/execution_environment/properties/declared_values_digest/pattern"
            ),
            Some(&serde_json::json!("^[0-9a-f]{64}$"))
        );
        assert_eq!(
            review.pointer(
                "/$defs/ReviewEnvironmentRecord/properties/execution_environment/required/4"
            ),
            Some(&serde_json::json!("declared_values_digest"))
        );
        assert_eq!(
            review.pointer(
                "/$defs/ReviewEnvironmentRecord/properties/execution_environment_digest/$ref"
            ),
            Some(&serde_json::json!("#/$defs/PayloadDigest"))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewExecutionVariant/oneOf/1/const"),
            Some(&serde_json::json!("required_absent"))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewProcessContainment/oneOf/0/const"),
            Some(&serde_json::json!("pid_namespace_parent_death"))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewProcessContainment/oneOf/1/const"),
            Some(&serde_json::json!("process_group_only"))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewProcessContainment/oneOf/2/const"),
            Some(&serde_json::json!("none"))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewEnvironmentRecord/properties/process_containment/$ref"),
            Some(&serde_json::json!("#/$defs/ReviewProcessContainment"))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewCheckTermination/oneOf/2/const"),
            Some(&serde_json::json!("timed_out"))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewCheckTermination/oneOf/4/const"),
            Some(&serde_json::json!("output_capture_incomplete"))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewCheckResult/properties/termination/$ref"),
            Some(&serde_json::json!("#/$defs/ReviewCheckTermination"))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewCheckResult/properties/process_tree_may_outlive/type"),
            Some(&serde_json::json!("boolean"))
        );
    }

    #[test]
    fn generated_review_schema_restricts_declared_environment_and_absence_evidence() {
        let review = serde_json::to_value(review_schema()).expect("schema serializes");

        assert_eq!(
            review
                .pointer("/$defs/ReviewPlan/properties/declared_environment/propertyNames/pattern"),
            Some(&serde_json::json!(
                "^(?!(?:HOME|PATH|PWD)$)(?!AGSV_)(?!GIT_)[A-Za-z_][A-Za-z0-9_]*$"
            ))
        );
        assert_eq!(
            review.pointer(
                "/$defs/ReviewPlan/properties/declared_environment/additionalProperties/maxLength"
            ),
            Some(&serde_json::json!(8_192))
        );
        assert_eq!(
            review.pointer("/$defs/ReviewBinaryPresence/oneOf/1/const"),
            Some(&serde_json::json!("absent_from_controlled_path"))
        );
        assert_eq!(
            review.pointer(
                "/$defs/ReviewEnvironmentRecord/properties/execution_environment/properties/tmpdir/maxLength"
            ),
            Some(&serde_json::json!(4_096))
        );
        assert_eq!(
            review.pointer(
                "/$defs/ReviewEnvironmentRecord/properties/execution_environment/properties/developer_dir/maxLength"
            ),
            Some(&serde_json::json!(4_096))
        );
        assert_eq!(
            review.pointer(
                "/$defs/ReviewEnvironmentRecord/properties/execution_environment/required/5"
            ),
            Some(&serde_json::json!("tmpdir"))
        );
    }
}
