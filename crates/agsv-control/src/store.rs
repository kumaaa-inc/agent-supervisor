use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::Duration;

use crate::ControlError;
use crate::identity::sha256_hex;
use agsv_core::{ArchivedFenceValidator, ArchivedRequestReference, PendingBulkContent, Supervisor};
use agsv_protocol::{
    ActorEpoch, ActorId, ActorRef, ActorStatus, AuditEvent, AuditEventKind, CausalMessage,
    DeliverySnapshot, DomainSnapshot, Evidence, GitSha, ImplementationRequest, MAX_AUDIT_EVENTS,
    MAX_DELIVERIES, Message, MessageId, PayloadDigest, Request, RequestId, ReviewAttemptStatus,
    ReviewCheckOutcome, ReviewCheckResult, ReviewCheckTermination, ReviewDecision,
    ReviewEnvironmentRecord, ReviewExecutionVariant, ReviewOutputArtifact, ReviewPlan,
    ReviewProcessContainment, ReviewRecoveryState, ReviewSession, ReviewSessionId,
    ReviewSessionState, ReviewSessionStatus, ReviewVerificationAttempt, Run, TeamStatus,
    TimestampMillis, Validate,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MIGRATION: &str = r"
CREATE TABLE IF NOT EXISTS domain_state (
  workspace_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL,
  snapshot_json TEXT NOT NULL,
  snapshot_format INTEGER NOT NULL DEFAULT 2,
  controller_active INTEGER NOT NULL DEFAULT 0,
  updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS control_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  operation TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  occurred_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS control_events_workspace_sequence
  ON control_events(workspace_id, sequence);
CREATE TABLE IF NOT EXISTS operation_results (
  workspace_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, operation_id)
);
CREATE TABLE IF NOT EXISTS operation_claims (
  workspace_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  claim_token TEXT NOT NULL,
  claimed_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, operation_id)
);
CREATE TABLE IF NOT EXISTS sessions (
  workspace_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  team_id TEXT,
  working_directory TEXT NOT NULL,
  backend TEXT NOT NULL,
  runtime TEXT,
  external_id TEXT,
  resume_token TEXT,
  status TEXT NOT NULL,
  launch_key TEXT NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, actor_id)
);
CREATE TABLE IF NOT EXISTS actor_bindings (
  workspace_id TEXT NOT NULL,
  binding_kind TEXT NOT NULL,
  binding_hash TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  actor_epoch INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  last_authenticated_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, binding_kind, binding_hash)
);
CREATE INDEX IF NOT EXISTS actor_bindings_actor
  ON actor_bindings(workspace_id, actor_id, actor_epoch);
CREATE TABLE IF NOT EXISTS team_metadata (
  workspace_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, team_id)
);
CREATE TABLE IF NOT EXISTS session_presentations (
  workspace_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  team_id TEXT,
  session_label TEXT NOT NULL,
  desired_label TEXT NOT NULL,
  tab_sequence INTEGER,
  pane_index INTEGER,
  applied_label TEXT,
  sync_state TEXT NOT NULL,
  last_error TEXT,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, actor_id),
  UNIQUE(workspace_id, tab_sequence, pane_index),
  CHECK ((tab_sequence IS NULL) = (pane_index IS NULL)),
  CHECK (tab_sequence IS NULL OR tab_sequence >= 0),
  CHECK (pane_index IS NULL OR pane_index >= 0)
);
CREATE TABLE IF NOT EXISTS team_worktrees (
  workspace_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  working_directory TEXT NOT NULL CHECK (substr(working_directory, 1, 1) = '/'),
  ownership TEXT NOT NULL CHECK (ownership IN ('created', 'adopted', 'attached')),
  status TEXT NOT NULL CHECK (status IN (
    'creating', 'active', 'removed', 'retained_with_reason', 'attached_not_owned'
  )),
  reason TEXT,
  error_code TEXT,
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
  PRIMARY KEY(workspace_id, team_id),
  UNIQUE(workspace_id, working_directory)
);
";
const RETENTION_MIGRATION: &str = r"
CREATE TABLE IF NOT EXISTS request_specifications (
  workspace_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  specification_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, request_id)
);
CREATE TABLE IF NOT EXISTS message_bodies (
  workspace_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  message_kind TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  body_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, message_id)
);
CREATE TABLE IF NOT EXISTS decision_rationales (
  workspace_id TEXT NOT NULL,
  decision_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  candidate_sha TEXT NOT NULL,
  reviewer_actor_id TEXT NOT NULL,
  reviewer_actor_epoch INTEGER NOT NULL,
  decided_at_ms INTEGER NOT NULL,
  content_sha256 TEXT NOT NULL,
  rationale TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, decision_id)
);
CREATE TABLE IF NOT EXISTS evidence_records (
  workspace_id TEXT NOT NULL,
  evidence_id TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS delivery_archive (
  workspace_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  request_id TEXT,
  sender_actor_id TEXT NOT NULL,
  sender_actor_epoch INTEGER NOT NULL,
  message_kind TEXT NOT NULL,
  sent_at_ms INTEGER NOT NULL,
  decision_id TEXT,
  candidate_sha TEXT,
  consultation_id TEXT,
  delivery_sha256 TEXT NOT NULL,
  delivery_json TEXT NOT NULL,
  archived_revision INTEGER NOT NULL,
  archived_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, message_id)
);
CREATE TABLE IF NOT EXISTS terminal_request_archive (
  workspace_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  creation_audit_sequence INTEGER NOT NULL,
  request_sha256 TEXT NOT NULL,
  request_json TEXT NOT NULL,
  run_sha256 TEXT NOT NULL,
  run_json TEXT NOT NULL,
  archived_revision INTEGER NOT NULL,
  archived_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, request_id),
  UNIQUE(workspace_id, run_id)
);
CREATE TABLE IF NOT EXISTS protocol_audit_archive (
  workspace_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  message_id TEXT NOT NULL,
  event_sha256 TEXT NOT NULL,
  previous_sha256 TEXT,
  event_json TEXT NOT NULL,
  archived_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, sequence)
);
CREATE TABLE IF NOT EXISTS control_event_archive (
  sequence INTEGER PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  operation TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  occurred_at_ms INTEGER NOT NULL,
  archived_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS control_event_archive_workspace_sequence
  ON control_event_archive(workspace_id, sequence);
CREATE TABLE IF NOT EXISTS presentation_slot_reservations (
  workspace_id TEXT NOT NULL,
  tab_sequence INTEGER NOT NULL,
  pane_index INTEGER NOT NULL,
  first_actor_id TEXT NOT NULL,
  allocated_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, tab_sequence, pane_index),
  CHECK (tab_sequence >= 0),
  CHECK (pane_index >= 0)
);
CREATE TABLE IF NOT EXISTS session_presentation_archive (
  workspace_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  actor_epoch INTEGER NOT NULL,
  team_id TEXT,
  content_sha256 TEXT NOT NULL,
  presentation_json TEXT NOT NULL,
  archived_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, actor_id, actor_epoch)
);
CREATE TABLE IF NOT EXISTS team_metadata_archive (
  workspace_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  archived_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, team_id)
);
CREATE TABLE IF NOT EXISTS archive_commits (
  workspace_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  previous_sha256 TEXT,
  commit_sha256 TEXT NOT NULL,
  commit_json TEXT NOT NULL,
  committed_revision INTEGER NOT NULL,
  committed_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, sequence)
);
CREATE TABLE IF NOT EXISTS archive_commit_entries (
  workspace_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  commit_sequence INTEGER NOT NULL,
  entry_ordinal INTEGER NOT NULL,
  content_sha256 TEXT NOT NULL,
  PRIMARY KEY(workspace_id, kind, key),
  UNIQUE(workspace_id, commit_sequence, entry_ordinal)
);
CREATE TABLE IF NOT EXISTS archive_manifest (
  workspace_id TEXT PRIMARY KEY,
  commit_count INTEGER NOT NULL,
  commit_head_sha256 TEXT,
  delivery_count INTEGER NOT NULL,
  request_count INTEGER NOT NULL,
  run_count INTEGER NOT NULL,
  audit_event_count INTEGER NOT NULL,
  updated_revision INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE TRIGGER IF NOT EXISTS request_specifications_no_update
BEFORE UPDATE ON request_specifications BEGIN
  SELECT RAISE(ABORT, 'request_specifications is append-only');
END;
CREATE TRIGGER IF NOT EXISTS request_specifications_no_delete
BEFORE DELETE ON request_specifications BEGIN
  SELECT RAISE(ABORT, 'request_specifications is append-only');
END;
CREATE TRIGGER IF NOT EXISTS message_bodies_no_update
BEFORE UPDATE ON message_bodies BEGIN
  SELECT RAISE(ABORT, 'message_bodies is append-only');
END;
CREATE TRIGGER IF NOT EXISTS message_bodies_no_delete
BEFORE DELETE ON message_bodies BEGIN
  SELECT RAISE(ABORT, 'message_bodies is append-only');
END;
CREATE TRIGGER IF NOT EXISTS decision_rationales_no_update
BEFORE UPDATE ON decision_rationales BEGIN
  SELECT RAISE(ABORT, 'decision_rationales is append-only');
END;
CREATE TRIGGER IF NOT EXISTS decision_rationales_no_delete
BEFORE DELETE ON decision_rationales BEGIN
  SELECT RAISE(ABORT, 'decision_rationales is append-only');
END;
CREATE TRIGGER IF NOT EXISTS evidence_records_no_update
BEFORE UPDATE ON evidence_records BEGIN
  SELECT RAISE(ABORT, 'evidence_records is append-only');
END;
CREATE TRIGGER IF NOT EXISTS evidence_records_no_delete
BEFORE DELETE ON evidence_records BEGIN
  SELECT RAISE(ABORT, 'evidence_records is append-only');
END;
CREATE TRIGGER IF NOT EXISTS delivery_archive_no_update
BEFORE UPDATE ON delivery_archive BEGIN
  SELECT RAISE(ABORT, 'delivery_archive is append-only');
END;
CREATE TRIGGER IF NOT EXISTS delivery_archive_no_delete
BEFORE DELETE ON delivery_archive BEGIN
  SELECT RAISE(ABORT, 'delivery_archive is append-only');
END;
CREATE TRIGGER IF NOT EXISTS terminal_request_archive_no_update
BEFORE UPDATE ON terminal_request_archive BEGIN
  SELECT RAISE(ABORT, 'terminal_request_archive is append-only');
END;
CREATE TRIGGER IF NOT EXISTS terminal_request_archive_no_delete
BEFORE DELETE ON terminal_request_archive BEGIN
  SELECT RAISE(ABORT, 'terminal_request_archive is append-only');
END;
CREATE TRIGGER IF NOT EXISTS protocol_audit_archive_no_update
BEFORE UPDATE ON protocol_audit_archive BEGIN
  SELECT RAISE(ABORT, 'protocol_audit_archive is append-only');
END;
CREATE TRIGGER IF NOT EXISTS protocol_audit_archive_no_delete
BEFORE DELETE ON protocol_audit_archive BEGIN
  SELECT RAISE(ABORT, 'protocol_audit_archive is append-only');
END;
CREATE TRIGGER IF NOT EXISTS control_event_archive_no_update
BEFORE UPDATE ON control_event_archive BEGIN
  SELECT RAISE(ABORT, 'control_event_archive is append-only');
END;
CREATE TRIGGER IF NOT EXISTS control_event_archive_no_delete
BEFORE DELETE ON control_event_archive BEGIN
  SELECT RAISE(ABORT, 'control_event_archive is append-only');
END;
CREATE TRIGGER IF NOT EXISTS presentation_slot_reservations_no_update
BEFORE UPDATE ON presentation_slot_reservations BEGIN
  SELECT RAISE(ABORT, 'presentation_slot_reservations is append-only');
END;
CREATE TRIGGER IF NOT EXISTS presentation_slot_reservations_no_delete
BEFORE DELETE ON presentation_slot_reservations BEGIN
  SELECT RAISE(ABORT, 'presentation_slot_reservations is append-only');
END;
CREATE TRIGGER IF NOT EXISTS session_presentation_archive_no_update
BEFORE UPDATE ON session_presentation_archive BEGIN
  SELECT RAISE(ABORT, 'session_presentation_archive is append-only');
END;
CREATE TRIGGER IF NOT EXISTS session_presentation_archive_no_delete
BEFORE DELETE ON session_presentation_archive BEGIN
  SELECT RAISE(ABORT, 'session_presentation_archive is append-only');
END;
CREATE TRIGGER IF NOT EXISTS team_metadata_archive_no_update
BEFORE UPDATE ON team_metadata_archive BEGIN
  SELECT RAISE(ABORT, 'team_metadata_archive is append-only');
END;
CREATE TRIGGER IF NOT EXISTS team_metadata_archive_no_delete
BEFORE DELETE ON team_metadata_archive BEGIN
  SELECT RAISE(ABORT, 'team_metadata_archive is append-only');
END;
CREATE TRIGGER IF NOT EXISTS archive_commits_no_update
BEFORE UPDATE ON archive_commits BEGIN
  SELECT RAISE(ABORT, 'archive_commits is append-only');
END;
CREATE TRIGGER IF NOT EXISTS archive_commits_no_delete
BEFORE DELETE ON archive_commits BEGIN
  SELECT RAISE(ABORT, 'archive_commits is append-only');
END;
CREATE TRIGGER IF NOT EXISTS archive_commit_entries_no_update
BEFORE UPDATE ON archive_commit_entries BEGIN
  SELECT RAISE(ABORT, 'archive_commit_entries is append-only');
END;
CREATE TRIGGER IF NOT EXISTS archive_commit_entries_no_delete
BEFORE DELETE ON archive_commit_entries BEGIN
  SELECT RAISE(ABORT, 'archive_commit_entries is append-only');
END;
";
const RETENTION_INDEX_MIGRATION: &str = r"
DROP INDEX IF EXISTS delivery_archive_request;
CREATE INDEX IF NOT EXISTS delivery_archive_request
  ON delivery_archive(workspace_id, request_id, sent_at_ms, message_id);
CREATE INDEX IF NOT EXISTS delivery_archive_actor_time
  ON delivery_archive(workspace_id, sender_actor_id, sender_actor_epoch, sent_at_ms, message_id);
CREATE INDEX IF NOT EXISTS delivery_archive_candidate_time
  ON delivery_archive(workspace_id, candidate_sha, sent_at_ms, message_id);
CREATE INDEX IF NOT EXISTS delivery_archive_decision_time
  ON delivery_archive(workspace_id, decision_id, sent_at_ms, message_id);
CREATE INDEX IF NOT EXISTS delivery_archive_consultation_time
  ON delivery_archive(workspace_id, consultation_id, sent_at_ms, message_id);
CREATE INDEX IF NOT EXISTS decision_rationales_candidate_time
  ON decision_rationales(workspace_id, candidate_sha, decided_at_ms, decision_id);
CREATE INDEX IF NOT EXISTS decision_rationales_request_time
  ON decision_rationales(workspace_id, request_id, decided_at_ms, decision_id);
CREATE INDEX IF NOT EXISTS decision_rationales_reviewer_time
  ON decision_rationales(workspace_id, reviewer_actor_id, reviewer_actor_epoch,
                         decided_at_ms, decision_id);
CREATE INDEX IF NOT EXISTS protocol_audit_archive_message_sequence
  ON protocol_audit_archive(workspace_id, message_id, sequence);
CREATE INDEX IF NOT EXISTS terminal_request_archive_team_creation
  ON terminal_request_archive(workspace_id, team_id, creation_audit_sequence, request_id);
CREATE INDEX IF NOT EXISTS terminal_request_archive_outcome_window
  ON terminal_request_archive(workspace_id, archived_revision DESC, request_id DESC);
";
const REVIEW_MIGRATION: &str = r"
CREATE TABLE IF NOT EXISTS review_sessions (
  workspace_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  begin_operation_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  candidate_sha TEXT NOT NULL,
  tree_sha TEXT NOT NULL,
  checkout_path TEXT NOT NULL CHECK (substr(checkout_path, 1, 1) = '/'),
  plan_sha256 TEXT NOT NULL,
  record_sha256 TEXT NOT NULL,
  record_json TEXT NOT NULL,
  policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
  status TEXT NOT NULL CHECK (status IN ('preparing', 'ready', 'invalid')),
  recovery TEXT NOT NULL CHECK (recovery IN (
    'not_required', 'resume_required', 'recreate_required'
  )),
  last_error TEXT,
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
  PRIMARY KEY(workspace_id, session_id),
  UNIQUE(workspace_id, begin_operation_id),
  UNIQUE(workspace_id, request_id, candidate_sha),
  UNIQUE(workspace_id, checkout_path)
);
CREATE INDEX IF NOT EXISTS review_sessions_candidate
  ON review_sessions(workspace_id, request_id, candidate_sha, session_id);
CREATE INDEX IF NOT EXISTS review_sessions_candidate_sha
  ON review_sessions(workspace_id, candidate_sha, updated_at_ms DESC, session_id DESC);
CREATE INDEX IF NOT EXISTS review_sessions_recovery
  ON review_sessions(workspace_id, recovery, updated_at_ms, session_id);

CREATE TABLE IF NOT EXISTS review_verification_attempts (
  workspace_id TEXT NOT NULL,
  attempt_record_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  candidate_sha TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK (sequence > 0),
  verify_operation_id TEXT NOT NULL,
  plan_sha256 TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'running', 'passed', 'failed', 'interrupted'
  )),
  attempt_sha256 TEXT NOT NULL,
  attempt_json TEXT NOT NULL,
  started_at_ms INTEGER NOT NULL CHECK (started_at_ms >= 0),
  finished_at_ms INTEGER,
  recorded_at_ms INTEGER NOT NULL CHECK (recorded_at_ms >= started_at_ms),
  PRIMARY KEY(workspace_id, attempt_record_id),
  CHECK (
    (status = 'running' AND finished_at_ms IS NULL) OR
    (status != 'running' AND finished_at_ms >= started_at_ms)
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS review_attempts_one_running
  ON review_verification_attempts(workspace_id, session_id, sequence)
  WHERE status = 'running';
CREATE UNIQUE INDEX IF NOT EXISTS review_attempts_one_terminal
  ON review_verification_attempts(workspace_id, session_id, sequence)
  WHERE status != 'running';
CREATE INDEX IF NOT EXISTS review_attempts_candidate_sequence
  ON review_verification_attempts(
    workspace_id, request_id, candidate_sha, sequence DESC,
    recorded_at_ms DESC, attempt_record_id DESC
  );
CREATE INDEX IF NOT EXISTS review_attempts_session_sequence
  ON review_verification_attempts(
    workspace_id, session_id, sequence DESC,
    recorded_at_ms DESC, attempt_record_id DESC
  );
CREATE INDEX IF NOT EXISTS review_attempts_operation
  ON review_verification_attempts(
    workspace_id, verify_operation_id, sequence, status
  );

CREATE TABLE IF NOT EXISTS review_check_results (
  workspace_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  candidate_sha TEXT NOT NULL,
  attempt_sequence INTEGER NOT NULL CHECK (attempt_sequence > 0),
  check_id TEXT NOT NULL,
  variant TEXT NOT NULL CHECK (variant IN ('normal', 'required_absent')),
  environment_id TEXT NOT NULL,
  expected_exit_code INTEGER NOT NULL CHECK (expected_exit_code BETWEEN 0 AND 255),
  actual_exit_code INTEGER CHECK (actual_exit_code BETWEEN 0 AND 255),
  outcome TEXT NOT NULL CHECK (outcome IN ('passed', 'failed', 'execution_error')),
  termination TEXT NOT NULL CHECK (termination IN (
    'exited', 'signaled', 'timed_out', 'output_limit_exceeded',
    'output_capture_incomplete'
  )),
  process_tree_may_outlive INTEGER NOT NULL CHECK (process_tree_may_outlive IN (0, 1)),
  stdout_sha256 TEXT NOT NULL,
  stderr_sha256 TEXT NOT NULL,
  stdout_bytes INTEGER NOT NULL CHECK (stdout_bytes >= 0),
  stderr_bytes INTEGER NOT NULL CHECK (stderr_bytes >= 0),
  stdout_truncated INTEGER NOT NULL CHECK (stdout_truncated IN (0, 1)),
  stderr_truncated INTEGER NOT NULL CHECK (stderr_truncated IN (0, 1)),
  stdout_artifact_ref TEXT,
  stderr_artifact_ref TEXT,
  result_sha256 TEXT NOT NULL,
  result_json TEXT NOT NULL,
  started_at_ms INTEGER NOT NULL CHECK (started_at_ms >= 0),
  finished_at_ms INTEGER NOT NULL CHECK (finished_at_ms >= started_at_ms),
  PRIMARY KEY(workspace_id, session_id, attempt_sequence, variant, check_id)
);
CREATE INDEX IF NOT EXISTS review_check_results_candidate
  ON review_check_results(
    workspace_id, request_id, candidate_sha, attempt_sequence DESC, variant, check_id
  );
CREATE INDEX IF NOT EXISTS review_check_results_session
  ON review_check_results(
    workspace_id, session_id, attempt_sequence DESC, variant, check_id
  );

CREATE TABLE IF NOT EXISTS review_environment_records (
  workspace_id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  candidate_sha TEXT NOT NULL,
  attempt_sequence INTEGER NOT NULL CHECK (attempt_sequence > 0),
  check_id TEXT NOT NULL,
  variant TEXT NOT NULL CHECK (variant IN ('normal', 'required_absent')),
  process_containment TEXT NOT NULL CHECK (process_containment IN (
    'pid_namespace_parent_death', 'process_group_only', 'none'
  )),
  path_sha256 TEXT NOT NULL,
  record_sha256 TEXT NOT NULL,
  record_json TEXT NOT NULL,
  recorded_at_ms INTEGER NOT NULL CHECK (recorded_at_ms >= 0),
  PRIMARY KEY(workspace_id, environment_id),
  UNIQUE(workspace_id, session_id, attempt_sequence, check_id, variant)
);
CREATE INDEX IF NOT EXISTS review_environment_candidate
  ON review_environment_records(
    workspace_id, request_id, candidate_sha, recorded_at_ms DESC, environment_id
  );
CREATE INDEX IF NOT EXISTS review_environment_session
  ON review_environment_records(
    workspace_id, session_id, attempt_sequence DESC, check_id, variant
  );

CREATE TRIGGER IF NOT EXISTS review_sessions_immutable_identity
BEFORE UPDATE ON review_sessions
WHEN NEW.workspace_id != OLD.workspace_id
  OR NEW.session_id != OLD.session_id
  OR NEW.begin_operation_id != OLD.begin_operation_id
  OR NEW.request_id != OLD.request_id
  OR NEW.candidate_sha != OLD.candidate_sha
  OR NEW.tree_sha != OLD.tree_sha
  OR NEW.checkout_path != OLD.checkout_path
  OR NEW.plan_sha256 != OLD.plan_sha256
  OR NEW.policy_revision != OLD.policy_revision
  OR NEW.created_at_ms != OLD.created_at_ms
BEGIN
  SELECT RAISE(ABORT, 'review session immutable identity cannot change');
END;
CREATE TRIGGER IF NOT EXISTS review_sessions_no_delete
BEFORE DELETE ON review_sessions BEGIN
  SELECT RAISE(ABORT, 'review_sessions is durable');
END;
CREATE TRIGGER IF NOT EXISTS review_verification_attempts_no_update
BEFORE UPDATE ON review_verification_attempts BEGIN
  SELECT RAISE(ABORT, 'review_verification_attempts is append-only');
END;
CREATE TRIGGER IF NOT EXISTS review_verification_attempts_no_delete
BEFORE DELETE ON review_verification_attempts BEGIN
  SELECT RAISE(ABORT, 'review_verification_attempts is append-only');
END;
CREATE TRIGGER IF NOT EXISTS review_check_results_no_update
BEFORE UPDATE ON review_check_results BEGIN
  SELECT RAISE(ABORT, 'review_check_results is append-only');
END;
CREATE TRIGGER IF NOT EXISTS review_check_results_no_delete
BEFORE DELETE ON review_check_results BEGIN
  SELECT RAISE(ABORT, 'review_check_results is append-only');
END;
CREATE TRIGGER IF NOT EXISTS review_environment_records_no_update
BEFORE UPDATE ON review_environment_records BEGIN
  SELECT RAISE(ABORT, 'review_environment_records is append-only');
END;
CREATE TRIGGER IF NOT EXISTS review_environment_records_no_delete
BEFORE DELETE ON review_environment_records BEGIN
  SELECT RAISE(ABORT, 'review_environment_records is append-only');
END;
";
// Schema 9 is the fresh-create union of lifecycle schema 7, retention schema 8,
// and durable isolated-review sessions plus immutable verification records.
// Older stores are preserved verbatim rather than migrated or admitted without
// the integrity tables required by this shape.
const CONTROL_SCHEMA_VERSION: i64 = 9;
const OPERATION_CLAIM_TTL_MS: u64 = 5 * 60 * 1_000;
const LIVE_CONTROL_EVENT_LIMIT: i64 = 1_000;
const SCHEMA_PRESERVATION_MARKER: &str = "control.schema-preservation.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SchemaPreservationPlan {
    schema_version: i64,
    preserved_directory: String,
    filenames: Vec<String>,
}

const ARCHIVE_DELIVERY_KIND: &str = "delivery";
const ARCHIVE_REQUEST_KIND: &str = "terminal_request";
const ARCHIVE_AUDIT_KIND: &str = "protocol_audit";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct ArchiveCommitEntry {
    kind: String,
    key: String,
    content_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ArchiveCommit {
    sequence: u64,
    previous_sha256: Option<String>,
    entries: Vec<ArchiveCommitEntry>,
    committed_revision: u64,
    committed_at_ms: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ArchiveManifest {
    commit_count: u64,
    commit_head_sha256: Option<String>,
    delivery_count: u64,
    request_count: u64,
    run_count: u64,
    audit_event_count: u64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
struct StoreWork {
    vm_steps: u64,
    archive_digests: u64,
}

#[cfg(test)]
thread_local! {
    static STORE_WORK_ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static STORE_VM_STEPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static STORE_ARCHIVE_DIGESTS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn measure_store_work<T>(work: impl FnOnce() -> T) -> (T, StoreWork) {
    STORE_VM_STEPS.with(|count| count.set(0));
    STORE_ARCHIVE_DIGESTS.with(|count| count.set(0));
    STORE_WORK_ACTIVE.with(|active| active.set(true));
    let result = work();
    STORE_WORK_ACTIVE.with(|active| active.set(false));
    let measured = StoreWork {
        vm_steps: STORE_VM_STEPS.with(std::cell::Cell::get),
        archive_digests: STORE_ARCHIVE_DIGESTS.with(std::cell::Cell::get),
    };
    (result, measured)
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct StoredEvent {
    pub sequence: i64,
    pub revision: u64,
    pub operation: String,
    pub detail: Value,
    pub occurred_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SessionRecord {
    pub actor_id: String,
    pub team_id: Option<String>,
    pub working_directory: PathBuf,
    pub backend: String,
    /// Selected top-level runtime. `None` is reserved for Primary notification
    /// endpoints, which are not launched through a runtime adapter.
    pub runtime: Option<String>,
    pub external_id: Option<String>,
    pub resume_token: Option<String>,
    pub status: String,
    pub launch_key: String,
    pub updated_at_ms: u64,
}

impl SessionRecord {
    pub(crate) fn replacement_intent_in_progress(&self) -> bool {
        self.launch_key.starts_with("replacement:")
            && matches!(
                self.status.as_str(),
                "replacement_pending" | "launching" | "launch_failed"
            )
    }

    pub(crate) fn replacement_in_progress(&self) -> bool {
        matches!(self.status.as_str(), "launching" | "launch_failed")
            || self.replacement_intent_in_progress()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ActorBinding {
    pub actor: ActorRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct TeamMetadataRecord {
    pub team_id: String,
    pub purpose: String,
    pub updated_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TeamWorktreeOwnership {
    Created,
    Adopted,
    Attached,
}

impl TeamWorktreeOwnership {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Adopted => "adopted",
            Self::Attached => "attached",
        }
    }

    fn from_database(value: &str) -> rusqlite::Result<Self> {
        match value {
            "created" => Ok(Self::Created),
            "adopted" => Ok(Self::Adopted),
            "attached" => Ok(Self::Attached),
            other => Err(invalid_team_worktree_text(
                2,
                format!("unknown team worktree ownership {other:?}"),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TeamWorktreeStatus {
    Creating,
    Active,
    Removed,
    RetainedWithReason,
    AttachedNotOwned,
}

impl TeamWorktreeStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Active => "active",
            Self::Removed => "removed",
            Self::RetainedWithReason => "retained_with_reason",
            Self::AttachedNotOwned => "attached_not_owned",
        }
    }

    fn from_database(value: &str) -> rusqlite::Result<Self> {
        match value {
            "creating" => Ok(Self::Creating),
            "active" => Ok(Self::Active),
            "removed" => Ok(Self::Removed),
            "retained_with_reason" => Ok(Self::RetainedWithReason),
            "attached_not_owned" => Ok(Self::AttachedNotOwned),
            other => Err(invalid_team_worktree_text(
                3,
                format!("unknown team worktree status {other:?}"),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct TeamWorktreeRecord {
    pub team_id: String,
    pub working_directory: PathBuf,
    pub ownership: TeamWorktreeOwnership,
    pub status: TeamWorktreeStatus,
    pub reason: Option<String>,
    pub error_code: Option<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct PresentationSlot {
    pub tab_sequence: u32,
    pub pane_index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PresentationSyncState {
    Pending,
    Applied,
}

impl PresentationSyncState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
        }
    }

    fn from_database(value: &str) -> rusqlite::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "applied" => Ok(Self::Applied),
            other => Err(rusqlite::Error::FromSqlConversionFailure(
                7,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown presentation sync state {other:?}"),
                )),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SessionPresentationRecord {
    pub actor_id: String,
    pub team_id: Option<String>,
    pub session_label: String,
    pub desired_label: String,
    pub slot: Option<PresentationSlot>,
    pub applied_label: Option<String>,
    pub sync_state: PresentationSyncState,
    pub last_error: Option<String>,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct StoredReviewSession {
    pub begin_operation_id: String,
    pub session: ReviewSession,
    pub last_error: Option<String>,
}

struct StoredReviewSessionRow {
    session_id: String,
    begin_operation_id: String,
    request_id: String,
    candidate_sha: String,
    tree_sha: String,
    checkout_path: String,
    plan_sha256: String,
    record_sha256: String,
    record_json: String,
    policy_revision: i64,
    status: String,
    recovery: String,
    last_error: Option<String>,
    created_at_ms: i64,
    updated_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct StoredReviewVerificationAttempt {
    pub verify_operation_id: String,
    pub attempt: ReviewVerificationAttempt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct StoredReviewEnvironmentRecord {
    pub path_digest: PayloadDigest,
    pub environment: ReviewEnvironmentRecord,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct StoredReviewSessionRecords {
    pub session: StoredReviewSession,
    pub attempts: Vec<StoredReviewVerificationAttempt>,
    pub check_results: Vec<ReviewCheckResult>,
    pub environments: Vec<StoredReviewEnvironmentRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ReviewArtifactExpectation {
    pub source: String,
    pub path: PathBuf,
    pub digest: PayloadDigest,
    pub byte_count: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub(crate) struct ReviewIntegrityReport {
    pub sessions: u64,
    pub attempt_records: u64,
    pub environments: u64,
    pub check_results: u64,
    pub referenced_artifacts: u64,
}

struct StoredReviewAttemptRow {
    record_id: String,
    session_id: String,
    request_id: String,
    candidate_sha: String,
    attempt_sequence: i64,
    verify_operation_id: String,
    plan_sha256: String,
    status: String,
    record_sha256: String,
    record_json: String,
    started_at_ms: i64,
    finished_at_ms: Option<i64>,
    recorded_at_ms: i64,
}

struct StoredReviewCheckResultRow {
    session_id: String,
    request_id: String,
    candidate_sha: String,
    attempt_sequence: i64,
    check_id: String,
    variant: String,
    environment_id: String,
    expected_exit_code: i64,
    actual_exit_code: Option<i64>,
    outcome: String,
    termination: String,
    process_tree_may_outlive: bool,
    stdout_sha256: String,
    stderr_sha256: String,
    stdout_bytes: i64,
    stderr_bytes: i64,
    stdout_truncated: bool,
    stderr_truncated: bool,
    stdout_artifact_ref: Option<String>,
    stderr_artifact_ref: Option<String>,
    record_sha256: String,
    record_json: String,
    started_at_ms: i64,
    finished_at_ms: i64,
}

struct StoredReviewEnvironmentRow {
    environment_id: String,
    session_id: String,
    request_id: String,
    candidate_sha: String,
    attempt_sequence: i64,
    check_id: String,
    variant: String,
    process_containment: String,
    path_sha256: String,
    record_sha256: String,
    record_json: String,
    recorded_at_ms: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct StateStore {
    path: PathBuf,
    workspace_id: String,
}

impl StateStore {
    pub(crate) fn open(
        directory: &Path,
        workspace_id: &str,
        initial: &DomainSnapshot,
        now_ms: u64,
    ) -> Result<Self, ControlError> {
        let directory = prepare_directory(directory)?;
        let path = directory.join("control.sqlite3");
        reject_symlink(&path)?;
        if let Some(error) = recover_schema_preservation(&directory)? {
            return Err(error);
        }
        let existed = path.exists();
        if existed {
            let version = inspect_schema_version(&path)?;
            match version {
                older if (0..CONTROL_SCHEMA_VERSION).contains(&older) => {
                    ensure_legacy_store_is_quiescent(&path)?;
                    return preserve_legacy_store(&directory, older, now_ms);
                }
                CONTROL_SCHEMA_VERSION => {}
                future if future > CONTROL_SCHEMA_VERSION => {
                    return Err(ControlError::new(
                        "unsupported_state_schema",
                        format!(
                            "control database schema {future} is newer than supported schema {CONTROL_SCHEMA_VERSION}"
                        ),
                    )
                    .with_hint("use an AGSV binary that supports this state schema"));
                }
                other => {
                    return Err(ControlError::new(
                        "unsupported_state_schema",
                        format!("control database schema {other} is not supported"),
                    ));
                }
            }
        }
        let store = Self {
            path,
            workspace_id: workspace_id.to_owned(),
        };
        let mut connection = store.connect()?;
        if !existed {
            initialize_schema(&mut connection)?;
            let snapshot_json = serde_json::to_string(initial).map_err(ControlError::database)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(ControlError::database)?;
            transaction
                .execute(
                    "INSERT INTO domain_state
                     (workspace_id, revision, snapshot_json, snapshot_format,
                      controller_active, updated_at_ms)
                     VALUES (?1, 0, ?2, 2, 0, ?3)",
                    params![workspace_id, snapshot_json, to_i64(now_ms)?],
                )
                .map_err(ControlError::database)?;
            transaction
                .execute(
                    "INSERT INTO archive_manifest
                     (workspace_id, commit_count, commit_head_sha256, delivery_count,
                      request_count, run_count, audit_event_count,
                      updated_revision, updated_at_ms)
                     VALUES (?1, 0, NULL, 0, 0, 0, 0, 0, ?2)",
                    params![workspace_id, to_i64(now_ms)?],
                )
                .map_err(ControlError::database)?;
            transaction.commit().map_err(ControlError::database)?;
        }
        store.load()?;
        Ok(store)
    }

    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn journal_mode(&self) -> Result<String, ControlError> {
        self.connect()?
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(ControlError::database)
    }

    pub(crate) fn load(&self) -> Result<(u64, Supervisor, bool), ControlError> {
        let connection = self.connect()?;
        self.load_from_connection(&connection)
    }

    fn load_from_connection(
        &self,
        connection: &Connection,
    ) -> Result<(u64, Supervisor, bool), ControlError> {
        let (revision, json, format, active) = connection
            .query_row(
                "SELECT revision, snapshot_json, snapshot_format, controller_active FROM domain_state
                 WHERE workspace_id = ?1",
                [&self.workspace_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                },
            )
            .map_err(ControlError::database)?;
        let revision = u64::try_from(revision)
            .map_err(|error| ControlError::database(format!("invalid revision: {error}")))?;
        if format != 2 {
            return Err(ControlError::new(
                "unsupported_snapshot_format",
                format!(
                    "workspace snapshot format {format} is not supported; expected compact format 2"
                ),
            ));
        }
        let snapshot: DomainSnapshot =
            serde_json::from_str(&json).map_err(ControlError::database)?;
        let supervisor = restore_supervisor(snapshot)?;
        verify_archive_manifest_checkpoint(connection, &self.workspace_id, &supervisor.snapshot())?;
        verify_hot_archive_disjointness(connection, &self.workspace_id, &supervisor.snapshot())?;
        Ok((revision, supervisor, active))
    }

    pub(crate) fn verify_archive_integrity(&self) -> Result<(u64, Supervisor, bool), ControlError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(ControlError::database)?;
        let loaded = self.load_from_connection(&transaction)?;
        let snapshot = loaded.1.snapshot();
        verify_archive_commit_chain(&transaction, &self.workspace_id, &snapshot)?;
        verify_compact_archive_checkpoint(&transaction, &self.workspace_id, &snapshot)?;
        transaction.commit().map_err(ControlError::database)?;
        Ok(loaded)
    }

    /// Streams the complete durable review history inside one `SQLite` read
    /// snapshot. The caller verifies each referenced artifact without this
    /// diagnostic retaining paths or review rows in aggregate memory.
    pub(crate) fn verify_review_integrity(
        &self,
        mut verify_artifact: impl FnMut(&ReviewArtifactExpectation) -> Result<(), ControlError>,
    ) -> Result<ReviewIntegrityReport, ControlError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(ControlError::database)?;
        let report = verify_review_rows(
            &transaction,
            &self.workspace_id,
            &self.review_checkout_root(),
            self,
            &mut verify_artifact,
        )?;
        transaction.commit().map_err(ControlError::database)?;
        Ok(report)
    }

    pub(crate) fn mutate<T>(
        &self,
        operation: &str,
        detail: &Value,
        now_ms: u64,
        mut apply: impl FnMut(&mut Supervisor) -> Result<T, ControlError>,
    ) -> Result<(u64, T), ControlError> {
        for attempt in 0..64_u32 {
            let (revision, mut supervisor, _) = self.load()?;
            let result = apply(&mut supervisor)?;
            let pending_bulk = supervisor.take_pending_bulk_content();
            let snapshot = supervisor.snapshot();
            restore_supervisor(snapshot.clone())?;
            let detail_json = serde_json::to_string(detail).map_err(ControlError::database)?;
            let mut connection = self.connect()?;
            let transaction =
                match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
                    Ok(transaction) => transaction,
                    Err(error) if is_busy(&error) => {
                        backoff(attempt);
                        continue;
                    }
                    Err(error) => return Err(ControlError::database(error)),
                };
            let current_revision = transaction
                .query_row(
                    "SELECT revision FROM domain_state WHERE workspace_id = ?1",
                    [&self.workspace_id],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(ControlError::database)?;
            if current_revision != to_i64(revision)? {
                drop(transaction);
                backoff(attempt);
                continue;
            }
            let next = revision.checked_add(1).ok_or_else(|| {
                ControlError::new("revision_exhausted", "state revision exhausted u64")
            })?;
            let mut hot_snapshot = snapshot;
            persist_bulk_and_archive_history(
                &transaction,
                &self.workspace_id,
                &mut hot_snapshot,
                &pending_bulk,
                next,
                now_ms,
            )?;
            let snapshot_json =
                serde_json::to_string(&hot_snapshot).map_err(ControlError::database)?;
            let updated = transaction
                .execute(
                    "UPDATE domain_state SET revision = ?1, snapshot_json = ?2,
                     snapshot_format = 2, updated_at_ms = ?3
                     WHERE workspace_id = ?4 AND revision = ?5",
                    params![
                        to_i64(next)?,
                        snapshot_json,
                        to_i64(now_ms)?,
                        self.workspace_id,
                        to_i64(revision)?
                    ],
                )
                .map_err(ControlError::database)?;
            if updated == 0 {
                drop(transaction);
                backoff(attempt);
                continue;
            }
            transaction
                .execute(
                    "INSERT INTO control_events
                     (workspace_id, revision, operation, detail_json, occurred_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        self.workspace_id,
                        to_i64(next)?,
                        operation,
                        detail_json,
                        to_i64(now_ms)?
                    ],
                )
                .map_err(ControlError::database)?;
            compact_control_events(&transaction, &self.workspace_id, now_ms)?;
            transaction.commit().map_err(ControlError::database)?;
            return Ok((next, result));
        }
        Err(ControlError::new(
            "concurrent_update_exhausted",
            "state changed too often to complete the compare-and-swap mutation",
        )
        .with_hint("retry the command with the same operation ID"))
    }

    pub(crate) fn set_controller(
        &self,
        active: bool,
        operation: &str,
        now_ms: u64,
    ) -> Result<u64, ControlError> {
        let detail = json!({ "active": active });
        let detail_json = serde_json::to_string(&detail).map_err(ControlError::database)?;
        for attempt in 0..64_u32 {
            let (revision, _, _) = self.load()?;
            let mut connection = self.connect()?;
            let transaction =
                match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
                    Ok(transaction) => transaction,
                    Err(error) if is_busy(&error) => {
                        backoff(attempt);
                        continue;
                    }
                    Err(error) => return Err(ControlError::database(error)),
                };
            let next = revision.checked_add(1).ok_or_else(|| {
                ControlError::new("revision_exhausted", "state revision exhausted u64")
            })?;
            let updated = transaction
                .execute(
                    "UPDATE domain_state SET revision = ?1, controller_active = ?2,
                     updated_at_ms = ?3
                     WHERE workspace_id = ?4 AND revision = ?5",
                    params![
                        to_i64(next)?,
                        active,
                        to_i64(now_ms)?,
                        self.workspace_id,
                        to_i64(revision)?
                    ],
                )
                .map_err(ControlError::database)?;
            if updated == 0 {
                drop(transaction);
                backoff(attempt);
                continue;
            }
            transaction
                .execute(
                    "INSERT INTO control_events
                     (workspace_id, revision, operation, detail_json, occurred_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        self.workspace_id,
                        to_i64(next)?,
                        operation,
                        detail_json,
                        to_i64(now_ms)?
                    ],
                )
                .map_err(ControlError::database)?;
            compact_control_events(&transaction, &self.workspace_id, now_ms)?;
            transaction.commit().map_err(ControlError::database)?;
            return Ok(next);
        }
        Err(ControlError::new(
            "concurrent_update_exhausted",
            "state changed too often to update the embedded controller marker",
        ))
    }

    pub(crate) fn operation_result(
        &self,
        operation_id: &str,
        operation: &str,
        request: &Value,
    ) -> Result<Option<Value>, ControlError> {
        let request_hash = value_hash(request)?;
        let connection = self.connect()?;
        let existing = connection
            .query_row(
                "SELECT operation, request_hash, result_json FROM operation_results
                 WHERE workspace_id = ?1 AND operation_id = ?2",
                params![self.workspace_id, operation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(ControlError::database)?;
        match existing {
            None => Ok(None),
            Some((old_operation, old_hash, result))
                if old_operation == operation && old_hash == request_hash =>
            {
                let mut value = serde_json::from_str(&result).map_err(ControlError::database)?;
                hydrate_bulk_markers(&connection, &self.workspace_id, &mut value)?;
                Ok(Some(value))
            }
            Some((old_operation, _, _)) => Err(ControlError::new(
                "operation_id_conflict",
                format!(
                    "operation ID `{operation_id}` was already used by `{old_operation}` with different input"
                ),
            )),
        }
    }

    pub(crate) fn claim_operation(
        &self,
        operation_id: &str,
        operation: &str,
        request: &Value,
        claim_token: &str,
        now_ms: u64,
    ) -> Result<(), ControlError> {
        let request_hash = value_hash(request)?;
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        let existing = transaction
            .query_row(
                "SELECT operation, request_hash, claim_token, claimed_at_ms
                 FROM operation_claims WHERE workspace_id = ?1 AND operation_id = ?2",
                params![self.workspace_id, operation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(ControlError::database)?;
        match existing {
            None => {
                transaction
                    .execute(
                        "INSERT INTO operation_claims
                         (workspace_id, operation_id, operation, request_hash, claim_token, claimed_at_ms)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            self.workspace_id,
                            operation_id,
                            operation,
                            request_hash,
                            claim_token,
                            to_i64(now_ms)?
                        ],
                    )
                    .map_err(ControlError::database)?;
            }
            Some((old_operation, old_hash, _, _))
                if old_operation != operation || old_hash != request_hash =>
            {
                return Err(ControlError::new(
                    "operation_id_conflict",
                    format!(
                        "operation ID `{operation_id}` is already claimed by `{old_operation}` with different input"
                    ),
                ));
            }
            Some((_, _, old_token, claimed_at)) => {
                let claimed_at = u64::try_from(claimed_at).map_err(ControlError::database)?;
                if now_ms.saturating_sub(claimed_at) < OPERATION_CLAIM_TTL_MS {
                    return Err(ControlError::new(
                        "operation_in_progress",
                        format!("operation `{operation_id}` is already in progress"),
                    )
                    .with_details(json!({ "claim_token": old_token, "claimed_at_ms": claimed_at }))
                    .with_hint(
                        "retry with the same operation ID after the active command finishes",
                    ));
                }
                transaction
                    .execute(
                        "UPDATE operation_claims SET claim_token = ?1, claimed_at_ms = ?2
                         WHERE workspace_id = ?3 AND operation_id = ?4",
                        params![
                            claim_token,
                            to_i64(now_ms)?,
                            self.workspace_id,
                            operation_id
                        ],
                    )
                    .map_err(ControlError::database)?;
            }
        }
        transaction.commit().map_err(ControlError::database)
    }

    pub(crate) fn release_operation(
        &self,
        operation_id: &str,
        claim_token: &str,
    ) -> Result<(), ControlError> {
        self.connect()?
            .execute(
                "DELETE FROM operation_claims
                 WHERE workspace_id = ?1 AND operation_id = ?2 AND claim_token = ?3",
                params![self.workspace_id, operation_id, claim_token],
            )
            .map_err(ControlError::database)?;
        Ok(())
    }

    pub(crate) fn record_operation(
        &self,
        operation_id: &str,
        operation: &str,
        request: &Value,
        result: &Value,
        now_ms: u64,
    ) -> Result<Value, ControlError> {
        let request_hash = value_hash(request)?;
        let connection = self.connect()?;
        let mut compact_result = result.clone();
        dehydrate_operation_result(&connection, &self.workspace_id, &mut compact_result)?;
        let result_json = serde_json::to_string(&compact_result).map_err(ControlError::database)?;
        let inserted = connection
            .execute(
                "INSERT OR IGNORE INTO operation_results
                 (workspace_id, operation_id, operation, request_hash, result_json, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    self.workspace_id,
                    operation_id,
                    operation,
                    request_hash,
                    result_json,
                    to_i64(now_ms)?
                ],
            )
            .map_err(ControlError::database)?;
        if inserted == 1 {
            Ok(result.clone())
        } else {
            self.operation_result(operation_id, operation, request)?
                .ok_or_else(|| ControlError::database("operation result disappeared"))
        }
    }

    #[must_use]
    pub(crate) fn review_checkout_root(&self) -> PathBuf {
        self.path
            .parent()
            .expect("state database always has a containing directory")
            .join("reviews")
    }

    /// Begins an exact-candidate review session or returns the identical prior
    /// result of the same stable operation. Immutable identity conflicts fail
    /// closed rather than adopting a different checkout or plan.
    pub(crate) fn begin_review_session(
        &self,
        begin_operation_id: &str,
        expected_domain_revision: u64,
        session: &ReviewSession,
    ) -> Result<StoredReviewSession, ControlError> {
        validate_review_session(self, session)?;
        let initial = ReviewSessionState::new(
            ReviewSessionStatus::Preparing,
            ReviewRecoveryState::NotRequired,
        )
        .map_err(invalid_review_session)?;
        if session.state != initial || session.created_at != session.updated_at {
            return Err(ControlError::new(
                "invalid_review_session",
                "a new review session must begin in preparing/not-required state with equal timestamps",
            ));
        }
        if begin_operation_id.is_empty() {
            return Err(ControlError::new(
                "invalid_review_session",
                "a review session requires a stable begin operation ID",
            ));
        }
        let record_json = canonical_json(session)?;
        let record_sha256 = sha256_hex(record_json.as_bytes());
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        if let Some(existing) = resolve_existing_review_begin(
            &transaction,
            &self.workspace_id,
            begin_operation_id,
            session,
            self,
        )? {
            transaction.commit().map_err(ControlError::database)?;
            return Ok(existing);
        }
        verify_review_begin_revision(
            &transaction,
            &self.workspace_id,
            expected_domain_revision,
            session,
        )?;
        let inserted = insert_review_session(
            &transaction,
            &self.workspace_id,
            begin_operation_id,
            session,
            &record_sha256,
            &record_json,
        )?;
        if inserted == 1 {
            append_review_control_event(
                &transaction,
                &self.workspace_id,
                "review.session.preparing",
                &review_session_event_detail(session, begin_operation_id),
                session.created_at,
            )?;
            let stored = StoredReviewSession {
                begin_operation_id: begin_operation_id.to_owned(),
                session: session.clone(),
                last_error: None,
            };
            transaction.commit().map_err(ControlError::database)?;
            return Ok(stored);
        }
        Err(review_session_conflict(
            &session.session_id,
            "session or checkout identity already belongs to another review",
        ))
    }

    pub(crate) fn review_session(
        &self,
        session_id: &ReviewSessionId,
    ) -> Result<Option<StoredReviewSession>, ControlError> {
        review_session_for_id(&self.connect()?, &self.workspace_id, session_id, self)
    }

    pub(crate) fn review_session_for_candidate(
        &self,
        request_id: &RequestId,
        candidate_sha: &GitSha,
    ) -> Result<Option<StoredReviewSession>, ControlError> {
        let connection = self.connect()?;
        review_session_for_candidate_on(
            &connection,
            &self.workspace_id,
            request_id,
            candidate_sha,
            self,
        )
    }

    pub(crate) fn review_sessions_for_candidate(
        &self,
        candidate_sha: &GitSha,
        limit: u32,
    ) -> Result<Vec<StoredReviewSession>, ControlError> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare(
                "SELECT session_id, begin_operation_id, request_id, candidate_sha,
                        tree_sha, checkout_path, plan_sha256, record_sha256,
                        record_json, policy_revision, status, recovery, last_error,
                        created_at_ms, updated_at_ms
                 FROM review_sessions
                 WHERE workspace_id = ?1 AND candidate_sha = ?2
                 ORDER BY updated_at_ms DESC, session_id DESC LIMIT ?3",
            )
            .map_err(ControlError::database)?;
        statement
            .query_map(
                params![self.workspace_id, candidate_sha.as_str(), limit],
                stored_review_session_row,
            )
            .map_err(ControlError::database)?
            .map(|row| {
                validate_stored_review_session(
                    row.map_err(ControlError::database)?,
                    &self.workspace_id,
                    self,
                )
            })
            .collect()
    }

    pub(crate) fn review_sessions_requiring_recovery(
        &self,
        limit: u32,
    ) -> Result<Vec<StoredReviewSession>, ControlError> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare(
                "SELECT session_id, begin_operation_id, request_id, candidate_sha,
                        tree_sha, checkout_path, plan_sha256, record_sha256,
                        record_json, policy_revision, status, recovery, last_error,
                        created_at_ms, updated_at_ms
                 FROM review_sessions
                 WHERE workspace_id = ?1
                   AND recovery IN ('resume_required', 'recreate_required')
                 ORDER BY updated_at_ms, session_id LIMIT ?2",
            )
            .map_err(ControlError::database)?;
        statement
            .query_map(params![self.workspace_id, limit], stored_review_session_row)
            .map_err(ControlError::database)?
            .map(|row| {
                validate_stored_review_session(
                    row.map_err(ControlError::database)?,
                    &self.workspace_id,
                    self,
                )
            })
            .collect()
    }

    pub(crate) fn transition_review_session(
        &self,
        session_id: &ReviewSessionId,
        expected: ReviewSessionState,
        next: ReviewSessionState,
        last_error: Option<&str>,
        updated_at: TimestampMillis,
    ) -> Result<StoredReviewSession, ControlError> {
        expected.validate().map_err(invalid_review_session)?;
        next.validate().map_err(invalid_review_session)?;
        validate_review_last_error(last_error)?;
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        let existing =
            review_session_for_id(&transaction, &self.workspace_id, session_id, self)?
                .ok_or_else(|| ControlError::not_found("review session", session_id.as_str()))?;
        if existing.session.state == next && existing.last_error.as_deref() == last_error {
            transaction.commit().map_err(ControlError::database)?;
            return Ok(existing);
        }
        if existing.session.state != expected {
            return Err(review_session_conflict(
                session_id,
                "durable state changed before the requested recovery transition",
            ));
        }
        if !expected.allows_transition_to(next) {
            return Err(ControlError::new(
                "invalid_review_session_transition",
                format!(
                    "review session `{session_id}` cannot apply the requested state transition"
                ),
            ));
        }
        if updated_at < existing.session.updated_at {
            return Err(ControlError::new(
                "invalid_review_session_transition",
                "review session update timestamp precedes its durable timestamp",
            ));
        }
        let previous_updated_at = existing.session.updated_at;
        let mut updated = existing.session;
        updated.state = next;
        updated.updated_at = updated_at;
        validate_review_session(self, &updated)?;
        let record_json = canonical_json(&updated)?;
        let record_sha256 = sha256_hex(record_json.as_bytes());
        let changed = transaction
            .execute(
                "UPDATE review_sessions
                 SET status = ?1, recovery = ?2, last_error = ?3,
                     record_sha256 = ?4, record_json = ?5, updated_at_ms = ?6
                 WHERE workspace_id = ?7 AND session_id = ?8
                   AND status = ?9 AND recovery = ?10 AND updated_at_ms = ?11",
                params![
                    review_session_status_text(next.status),
                    review_recovery_state_text(next.recovery),
                    last_error,
                    record_sha256,
                    record_json,
                    to_i64(updated_at.0)?,
                    self.workspace_id,
                    session_id.as_str(),
                    review_session_status_text(expected.status),
                    review_recovery_state_text(expected.recovery),
                    to_i64(previous_updated_at.0)?,
                ],
            )
            .map_err(ControlError::database)?;
        if changed != 1 {
            return Err(review_session_conflict(
                session_id,
                "durable state changed concurrently",
            ));
        }
        append_review_control_event(
            &transaction,
            &self.workspace_id,
            review_session_event_operation(next),
            &review_session_transition_event_detail(&updated, last_error.is_some()),
            updated_at,
        )?;
        transaction.commit().map_err(ControlError::database)?;
        Ok(StoredReviewSession {
            begin_operation_id: existing.begin_operation_id,
            session: updated,
            last_error: last_error.map(str::to_owned),
        })
    }

    pub(crate) fn append_review_verification_attempt(
        &self,
        verify_operation_id: &str,
        attempt: &ReviewVerificationAttempt,
    ) -> Result<StoredReviewVerificationAttempt, ControlError> {
        if verify_operation_id.is_empty() {
            return Err(ControlError::new(
                "invalid_review_attempt",
                "a verification attempt requires a stable operation ID",
            ));
        }
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        let session =
            review_session_for_id(&transaction, &self.workspace_id, &attempt.session_id, self)?
                .ok_or_else(|| {
                    ControlError::not_found("review session", attempt.session_id.as_str())
                })?;
        session
            .session
            .validate_attempt_record(attempt)
            .map_err(invalid_review_attempt)?;
        if let Some(existing) = review_attempt_for_record_id(
            &transaction,
            &self.workspace_id,
            attempt.record_id.as_str(),
            &session.session,
        )? {
            if existing.attempt == *attempt && existing.verify_operation_id == verify_operation_id {
                validate_terminal_review_results(
                    &transaction,
                    &self.workspace_id,
                    &session.session,
                    &existing.attempt,
                )?;
                transaction.commit().map_err(ControlError::database)?;
                return Ok(existing);
            }
            return Err(review_attempt_conflict(
                attempt,
                "attempt record ID was reused with different content",
            ));
        }
        validate_new_review_attempt(
            &transaction,
            &self.workspace_id,
            verify_operation_id,
            &session.session,
            attempt,
        )?;
        let attempt_json = canonical_json(attempt)?;
        let attempt_sha256 = sha256_hex(attempt_json.as_bytes());
        transaction
            .execute(
                "INSERT INTO review_verification_attempts
                 (workspace_id, attempt_record_id, session_id, request_id,
                  candidate_sha, sequence, verify_operation_id, plan_sha256,
                  status, attempt_sha256, attempt_json, started_at_ms,
                  finished_at_ms, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                         ?12, ?13, ?14)",
                params![
                    self.workspace_id,
                    attempt.record_id.as_str(),
                    attempt.session_id.as_str(),
                    attempt.request_id.as_str(),
                    attempt.candidate_sha.as_str(),
                    to_i64(attempt.attempt_sequence)?,
                    verify_operation_id,
                    attempt.plan.config_digest.as_str(),
                    review_attempt_status_text(attempt.status),
                    attempt_sha256,
                    attempt_json,
                    to_i64(attempt.started_at.0)?,
                    attempt
                        .finished_at
                        .map(|timestamp| to_i64(timestamp.0))
                        .transpose()?,
                    to_i64(attempt.recorded_at.0)?,
                ],
            )
            .map_err(ControlError::database)?;
        append_review_control_event(
            &transaction,
            &self.workspace_id,
            review_attempt_event_operation(attempt.status),
            &review_attempt_event_detail(attempt, verify_operation_id),
            attempt.recorded_at,
        )?;
        transaction.commit().map_err(ControlError::database)?;
        Ok(StoredReviewVerificationAttempt {
            verify_operation_id: verify_operation_id.to_owned(),
            attempt: attempt.clone(),
        })
    }

    pub(crate) fn review_verification_attempts_for_operation(
        &self,
        session_id: &ReviewSessionId,
        verify_operation_id: &str,
    ) -> Result<Vec<StoredReviewVerificationAttempt>, ControlError> {
        if verify_operation_id.is_empty() {
            return Err(ControlError::new(
                "invalid_review_attempt",
                "a verification attempt requires a stable operation ID",
            ));
        }
        let connection = self.connect()?;
        let session = review_session_for_id(&connection, &self.workspace_id, session_id, self)?
            .ok_or_else(|| ControlError::not_found("review session", session_id.as_str()))?;
        let attempts = review_attempts_for_operation(
            &connection,
            &self.workspace_id,
            verify_operation_id,
            &session.session,
        )?;
        let valid_shape = matches!(attempts.as_slice(),
            [running] if running.attempt.status == ReviewAttemptStatus::Running
        ) || matches!(attempts.as_slice(), [running, terminal]
            if running.attempt.status == ReviewAttemptStatus::Running
                && terminal.attempt.status != ReviewAttemptStatus::Running
                && same_review_attempt_identity(&running.attempt, &terminal.attempt)
                && running
                    .attempt
                    .status
                    .allows_transition_to(terminal.attempt.status)
        );
        if !attempts.is_empty() && !valid_shape {
            return Err(ControlError::new(
                "review_attempt_operation_conflict",
                format!(
                    "verification operation `{verify_operation_id}` has conflicting durable facts"
                ),
            ));
        }
        if let Some(terminal) = attempts
            .iter()
            .find(|record| record.attempt.status != ReviewAttemptStatus::Running)
        {
            validate_terminal_review_results(
                &connection,
                &self.workspace_id,
                &session.session,
                &terminal.attempt,
            )?;
        }
        Ok(attempts)
    }

    pub(crate) fn next_review_attempt_sequence(
        &self,
        session_id: &ReviewSessionId,
    ) -> Result<u64, ControlError> {
        let connection = self.connect()?;
        if review_session_for_id(&connection, &self.workspace_id, session_id, self)?.is_none() {
            return Err(ControlError::not_found(
                "review session",
                session_id.as_str(),
            ));
        }
        let maximum = connection
            .query_row(
                "SELECT MAX(sequence) FROM review_verification_attempts
                 WHERE workspace_id = ?1 AND session_id = ?2",
                params![self.workspace_id, session_id.as_str()],
                |row| row.get::<_, Option<i64>>(0),
            )
            .map_err(ControlError::database)?
            .unwrap_or(0);
        u64::try_from(maximum)
            .map_err(ControlError::database)?
            .checked_add(1)
            .ok_or_else(|| ControlError::database("review attempt sequence overflow"))
    }

    pub(crate) fn append_review_environment_record(
        &self,
        path_digest: &PayloadDigest,
        environment: &ReviewEnvironmentRecord,
    ) -> Result<StoredReviewEnvironmentRecord, ControlError> {
        path_digest.validate().map_err(invalid_review_environment)?;
        validate_review_path_digest(environment, path_digest)?;
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        let session = review_session_for_id(
            &transaction,
            &self.workspace_id,
            &environment.session_id,
            self,
        )?
        .ok_or_else(|| {
            ControlError::not_found("review session", environment.session_id.as_str())
        })?;
        session
            .session
            .validate_environment_record(environment)
            .map_err(invalid_review_environment)?;
        validate_review_environment_digest(environment)?;
        let running = ensure_running_review_attempt(
            &transaction,
            &self.workspace_id,
            &session.session,
            environment.attempt_sequence,
        )?;
        if environment.recorded_at < running.started_at {
            return Err(ControlError::new(
                "invalid_review_environment",
                "review environment capture precedes its running attempt",
            ));
        }
        if let Some(existing) = review_environment_for_id(
            &transaction,
            &self.workspace_id,
            environment.environment_id.as_str(),
            &session.session,
        )? {
            if existing.environment == *environment && existing.path_digest == *path_digest {
                transaction.commit().map_err(ControlError::database)?;
                return Ok(existing);
            }
            return Err(review_environment_conflict(
                environment,
                "environment ID was reused with different content",
            ));
        }
        let record_json = canonical_json(environment)?;
        let record_sha256 = sha256_hex(record_json.as_bytes());
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO review_environment_records
                 (workspace_id, environment_id, session_id, request_id,
                  candidate_sha, attempt_sequence, check_id, variant,
                  process_containment, path_sha256, record_sha256, record_json,
                  recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                         ?13)",
                params![
                    self.workspace_id,
                    environment.environment_id.as_str(),
                    environment.session_id.as_str(),
                    environment.request_id.as_str(),
                    environment.candidate_sha.as_str(),
                    to_i64(environment.attempt_sequence)?,
                    environment.check_id.as_str(),
                    review_execution_variant_text(environment.variant),
                    review_process_containment_text(environment.process_containment),
                    path_digest.as_str(),
                    record_sha256,
                    record_json,
                    to_i64(environment.recorded_at.0)?,
                ],
            )
            .map_err(ControlError::database)?;
        if inserted != 1 {
            return Err(review_environment_conflict(
                environment,
                "check execution variant already has another environment record",
            ));
        }
        append_review_control_event(
            &transaction,
            &self.workspace_id,
            "review.environment.recorded",
            &review_environment_event_detail(environment, path_digest),
            environment.recorded_at,
        )?;
        transaction.commit().map_err(ControlError::database)?;
        Ok(StoredReviewEnvironmentRecord {
            path_digest: path_digest.clone(),
            environment: environment.clone(),
        })
    }

    pub(crate) fn append_review_check_result(
        &self,
        result: &ReviewCheckResult,
    ) -> Result<ReviewCheckResult, ControlError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        let session =
            review_session_for_id(&transaction, &self.workspace_id, &result.session_id, self)?
                .ok_or_else(|| {
                    ControlError::not_found("review session", result.session_id.as_str())
                })?;
        session
            .session
            .validate_check_result(result)
            .map_err(invalid_review_check_result)?;
        let running = ensure_running_review_attempt(
            &transaction,
            &self.workspace_id,
            &session.session,
            result.attempt_sequence,
        )?;
        if result.started_at < running.started_at {
            return Err(ControlError::new(
                "invalid_review_check_result",
                "review check execution precedes its running attempt",
            ));
        }
        let environment = review_environment_for_id(
            &transaction,
            &self.workspace_id,
            result.environment_id.as_str(),
            &session.session,
        )?
        .ok_or_else(|| {
            ControlError::not_found("review environment", result.environment_id.as_str())
        })?;
        session
            .session
            .validate_execution_pair(result, &environment.environment)
            .map_err(invalid_review_check_result)?;
        let result_json = canonical_json(result)?;
        let result_sha256 = sha256_hex(result_json.as_bytes());
        let inserted = insert_review_check_result(
            &transaction,
            &self.workspace_id,
            result,
            &result_sha256,
            &result_json,
        )?;
        if inserted == 1 {
            append_review_control_event(
                &transaction,
                &self.workspace_id,
                "review.check.recorded",
                &review_check_result_event_detail(result),
                result.finished_at,
            )?;
            transaction.commit().map_err(ControlError::database)?;
            return Ok(result.clone());
        }
        let existing = review_check_result_for_key(
            &transaction,
            &self.workspace_id,
            result,
            &session.session,
        )?;
        match existing {
            Some(existing) if existing == *result => {
                transaction.commit().map_err(ControlError::database)?;
                Ok(existing)
            }
            _ => Err(review_check_result_conflict(result)),
        }
    }

    pub(crate) fn review_check_results(
        &self,
        session_id: &ReviewSessionId,
        limit: u32,
    ) -> Result<Vec<ReviewCheckResult>, ControlError> {
        let connection = self.connect()?;
        let session = review_session_for_id(&connection, &self.workspace_id, session_id, self)?
            .ok_or_else(|| ControlError::not_found("review session", session_id.as_str()))?;
        query_review_check_results(
            &connection,
            "WHERE workspace_id = ?1 AND session_id = ?2
             ORDER BY attempt_sequence DESC, variant, check_id LIMIT ?3",
            params![self.workspace_id, session_id.as_str(), limit],
            &session.session,
        )
    }

    pub(crate) fn review_session_records(
        &self,
        session_id: &ReviewSessionId,
        limit: u32,
    ) -> Result<StoredReviewSessionRecords, ControlError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction().map_err(ControlError::database)?;
        let session = review_session_for_id(&transaction, &self.workspace_id, session_id, self)?
            .ok_or_else(|| ControlError::not_found("review session", session_id.as_str()))?;
        let attempts = query_review_attempts(
            &transaction,
            "WHERE workspace_id = ?1 AND session_id = ?2
             ORDER BY sequence DESC, recorded_at_ms DESC, attempt_record_id DESC LIMIT ?3",
            params![self.workspace_id, session_id.as_str(), limit],
            &session.session,
        )?;
        let check_results = query_review_check_results(
            &transaction,
            "WHERE workspace_id = ?1 AND session_id = ?2
             ORDER BY attempt_sequence DESC, variant, check_id LIMIT ?3",
            params![self.workspace_id, session_id.as_str(), limit],
            &session.session,
        )?;
        let environments = query_review_environments(
            &transaction,
            "WHERE workspace_id = ?1 AND session_id = ?2
             ORDER BY attempt_sequence DESC, check_id, variant LIMIT ?3",
            params![self.workspace_id, session_id.as_str(), limit],
            &session.session,
        )?;
        for terminal in attempts
            .iter()
            .filter(|record| record.attempt.status != ReviewAttemptStatus::Running)
        {
            validate_terminal_review_results(
                &transaction,
                &self.workspace_id,
                &session.session,
                &terminal.attempt,
            )?;
        }
        transaction.commit().map_err(ControlError::database)?;
        Ok(StoredReviewSessionRecords {
            session,
            attempts,
            check_results,
            environments,
        })
    }

    pub(crate) fn session(&self, actor_id: &str) -> Result<Option<SessionRecord>, ControlError> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT actor_id, team_id, working_directory, backend, runtime, external_id,
                 resume_token, status, launch_key, updated_at_ms FROM sessions
                 WHERE workspace_id = ?1 AND actor_id = ?2",
                params![self.workspace_id, actor_id],
                session_from_row,
            )
            .optional()
            .map_err(ControlError::database)
    }

    pub(crate) fn sessions(&self) -> Result<Vec<SessionRecord>, ControlError> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare(
                "SELECT actor_id, team_id, working_directory, backend, runtime, external_id,
                 resume_token, status, launch_key, updated_at_ms FROM sessions
                 WHERE workspace_id = ?1 ORDER BY actor_id",
            )
            .map_err(ControlError::database)?;
        statement
            .query_map([&self.workspace_id], session_from_row)
            .map_err(ControlError::database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(ControlError::database)
    }

    pub(crate) fn upsert_session(&self, session: &SessionRecord) -> Result<(), ControlError> {
        let connection = self.connect()?;
        connection
            .execute(
                "INSERT INTO sessions
                 (workspace_id, actor_id, team_id, working_directory, backend, runtime, external_id,
                  resume_token, status, launch_key, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(workspace_id, actor_id) DO UPDATE SET
                  team_id=excluded.team_id, working_directory=excluded.working_directory,
                  backend=excluded.backend, runtime=excluded.runtime,
                  external_id=excluded.external_id,
                  resume_token=excluded.resume_token, status=excluded.status,
                  launch_key=excluded.launch_key, updated_at_ms=excluded.updated_at_ms",
                params![
                    self.workspace_id,
                    session.actor_id,
                    session.team_id,
                    session.working_directory.to_string_lossy(),
                    session.backend,
                    session.runtime,
                    session.external_id,
                    session.resume_token,
                    session.status,
                    session.launch_key,
                    to_i64(session.updated_at_ms)?
                ],
            )
            .map_err(ControlError::database)?;
        Ok(())
    }

    pub(crate) fn set_team_purpose(
        &self,
        team_id: &str,
        purpose: &str,
        now_ms: u64,
    ) -> Result<(), ControlError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        let archived = transaction
            .query_row(
                "SELECT 1 FROM team_metadata_archive
                 WHERE workspace_id = ?1 AND team_id = ?2",
                params![self.workspace_id, team_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(ControlError::database)?
            .is_some();
        if archived {
            return Err(ControlError::new(
                "team_metadata_archived",
                format!("team `{team_id}` is retired and its metadata is immutable"),
            ));
        }
        transaction
            .execute(
                "INSERT INTO team_metadata (workspace_id, team_id, purpose, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(workspace_id, team_id) DO UPDATE SET
                  purpose=excluded.purpose, updated_at_ms=excluded.updated_at_ms",
                params![self.workspace_id, team_id, purpose, to_i64(now_ms)?],
            )
            .map_err(ControlError::database)?;
        transaction.commit().map_err(ControlError::database)
    }

    pub(crate) fn team_purpose(&self, team_id: &str) -> Result<Option<String>, ControlError> {
        self.connect()?
            .query_row(
                "SELECT purpose FROM (
                   SELECT purpose, 0 AS archived FROM team_metadata
                   WHERE workspace_id = ?1 AND team_id = ?2
                   UNION ALL
                   SELECT purpose, 1 AS archived FROM team_metadata_archive
                   WHERE workspace_id = ?1 AND team_id = ?2
                 ) ORDER BY archived LIMIT 1",
                params![self.workspace_id, team_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControlError::database)
    }

    pub(crate) fn team_metadata(&self) -> Result<Vec<TeamMetadataRecord>, ControlError> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare(
                "SELECT team_id, purpose, updated_at_ms FROM (
                   SELECT team_id, purpose, updated_at_ms, 0 AS archived
                   FROM team_metadata WHERE workspace_id = ?1
                   UNION ALL
                   SELECT team_id, purpose, updated_at_ms, 1 AS archived
                   FROM team_metadata_archive WHERE workspace_id = ?1
                     AND NOT EXISTS (
                       SELECT 1 FROM team_metadata AS live
                       WHERE live.workspace_id = team_metadata_archive.workspace_id
                         AND live.team_id = team_metadata_archive.team_id
                     )
                 ) ORDER BY team_id, archived",
            )
            .map_err(ControlError::database)?;
        statement
            .query_map([&self.workspace_id], team_metadata_from_row)
            .map_err(ControlError::database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(ControlError::database)
    }

    pub(crate) fn team_worktree(
        &self,
        team_id: &str,
    ) -> Result<Option<TeamWorktreeRecord>, ControlError> {
        team_worktree_for(&self.connect()?, &self.workspace_id, team_id)
    }

    pub(crate) fn team_worktrees(&self) -> Result<Vec<TeamWorktreeRecord>, ControlError> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare(
                "SELECT team_id, working_directory, ownership, status, reason, error_code,
                        created_at_ms, updated_at_ms
                 FROM team_worktrees WHERE workspace_id = ?1 ORDER BY team_id",
            )
            .map_err(ControlError::database)?;
        statement
            .query_map([&self.workspace_id], team_worktree_from_row)
            .map_err(ControlError::database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(ControlError::database)
    }

    // These mutations intentionally commit outside the Supervisor CAS. Engine
    // ordering records intent before side effects and idempotently rechecks
    // this durable row on retry.
    /// Persists a team-worktree ownership intent without overwriting an
    /// existing durable path or ownership decision.
    pub(crate) fn insert_team_worktree(
        &self,
        record: &TeamWorktreeRecord,
    ) -> Result<TeamWorktreeRecord, ControlError> {
        validate_team_worktree_record(record)?;
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        if let Some(existing) =
            team_worktree_for(&transaction, &self.workspace_id, &record.team_id)?
        {
            ensure_same_team_worktree_identity(&existing, record)?;
            transaction.commit().map_err(ControlError::database)?;
            return Ok(existing);
        }
        if let Some(existing_team_id) = transaction
            .query_row(
                "SELECT team_id FROM team_worktrees
                 WHERE workspace_id = ?1 AND working_directory = ?2",
                params![
                    self.workspace_id,
                    record.working_directory.to_string_lossy()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(ControlError::database)?
        {
            return Err(ControlError::new(
                "team_worktree_conflict",
                "team working directory already has a different durable owner",
            )
            .with_details(json!({
                "team_id": record.team_id,
                "conflicting_team_id": existing_team_id,
                "working_directory": record.working_directory,
            })));
        }
        transaction
            .execute(
                "INSERT INTO team_worktrees
                 (workspace_id, team_id, working_directory, ownership, status, reason,
                  error_code, created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    self.workspace_id,
                    record.team_id,
                    record.working_directory.to_string_lossy(),
                    record.ownership.as_str(),
                    record.status.as_str(),
                    record.reason,
                    record.error_code,
                    to_i64(record.created_at_ms)?,
                    to_i64(record.updated_at_ms)?,
                ],
            )
            .map_err(ControlError::database)?;
        let inserted = team_worktree_for(&transaction, &self.workspace_id, &record.team_id)?
            .ok_or_else(|| ControlError::database("inserted team worktree disappeared"))?;
        transaction.commit().map_err(ControlError::database)?;
        Ok(inserted)
    }

    /// Updates a team-worktree lifecycle outcome while fencing the durable
    /// path and ownership that authorized the operation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn update_team_worktree_status(
        &self,
        team_id: &str,
        working_directory: &Path,
        ownership: TeamWorktreeOwnership,
        status: TeamWorktreeStatus,
        reason: Option<&str>,
        error_code: Option<&str>,
        now_ms: u64,
    ) -> Result<TeamWorktreeRecord, ControlError> {
        let proposed = TeamWorktreeRecord {
            team_id: team_id.to_owned(),
            working_directory: working_directory.to_path_buf(),
            ownership,
            status,
            reason: reason.map(str::to_owned),
            error_code: error_code.map(str::to_owned),
            created_at_ms: 0,
            updated_at_ms: now_ms,
        };
        validate_team_worktree_identity(&proposed)?;
        validate_team_worktree_ownership_status(ownership, status)?;
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        let existing = team_worktree_for(&transaction, &self.workspace_id, team_id)?
            .ok_or_else(|| ControlError::not_found("team worktree", team_id))?;
        ensure_same_team_worktree_identity(&existing, &proposed)?;
        if existing.status == status
            && existing.reason.as_deref() == reason
            && existing.error_code.as_deref() == error_code
        {
            transaction.commit().map_err(ControlError::database)?;
            return Ok(existing);
        }
        if now_ms < existing.updated_at_ms {
            return Err(ControlError::new(
                "stale_team_worktree_update",
                "team worktree outcome is older than the durable record",
            )
            .with_details(json!({
                "team_id": team_id,
                "durable_updated_at_ms": existing.updated_at_ms,
                "proposed_updated_at_ms": now_ms,
            })));
        }
        if existing.status == TeamWorktreeStatus::Removed && status != TeamWorktreeStatus::Removed {
            return Err(ControlError::new(
                "invalid_team_worktree_transition",
                "a removed team worktree cannot return to an active lifecycle state",
            ));
        }
        transaction
            .execute(
                "UPDATE team_worktrees
                 SET status = ?1, reason = ?2, error_code = ?3, updated_at_ms = ?4
                 WHERE workspace_id = ?5 AND team_id = ?6",
                params![
                    status.as_str(),
                    reason,
                    error_code,
                    to_i64(now_ms)?,
                    self.workspace_id,
                    team_id,
                ],
            )
            .map_err(ControlError::database)?;
        let updated = team_worktree_for(&transaction, &self.workspace_id, team_id)?
            .ok_or_else(|| ControlError::database("updated team worktree disappeared"))?;
        transaction.commit().map_err(ControlError::database)?;
        Ok(updated)
    }

    pub(crate) fn ensure_primary_presentation(
        &self,
        actor_id: &str,
        session_label: &str,
        desired_label: &str,
        now_ms: u64,
    ) -> Result<SessionPresentationRecord, ControlError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        if let Some(existing) = presentation_for_actor(&transaction, &self.workspace_id, actor_id)?
        {
            transaction.commit().map_err(ControlError::database)?;
            return Ok(existing);
        }
        transaction
            .execute(
                "INSERT INTO session_presentations
                 (workspace_id, actor_id, team_id, session_label, desired_label,
                  tab_sequence, pane_index, applied_label, sync_state, last_error, updated_at_ms)
                 VALUES (?1, ?2, NULL, ?3, ?4, NULL, NULL, NULL, ?5, NULL, ?6)",
                params![
                    self.workspace_id,
                    actor_id,
                    session_label,
                    desired_label,
                    PresentationSyncState::Pending.as_str(),
                    to_i64(now_ms)?
                ],
            )
            .map_err(ControlError::database)?;
        let record = presentation_for_actor(&transaction, &self.workspace_id, actor_id)?
            .ok_or_else(|| ControlError::database("primary presentation disappeared"))?;
        transaction.commit().map_err(ControlError::database)?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn allocate_session_presentation(
        &self,
        actor_id: &str,
        team_id: &str,
        session_label: &str,
        desired_label: &str,
        max_panes: u32,
        place_first: bool,
        occupied_sequences: &[u32],
        reusable_sequences: &[u32],
        now_ms: u64,
    ) -> Result<SessionPresentationRecord, ControlError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        if let Some(existing) = presentation_for_actor(&transaction, &self.workspace_id, actor_id)?
        {
            transaction.commit().map_err(ControlError::database)?;
            return Ok(existing);
        }
        if max_panes == 0 {
            return Err(ControlError::invalid_request(
                "presentation max_panes must be greater than zero",
            ));
        }
        if occupied_sequences.contains(&0) || reusable_sequences.contains(&0) {
            return Err(ControlError::invalid_request(
                "occupied and reusable presentation sequences must be positive",
            ));
        }

        let occupied_sequences = occupied_sequences.iter().copied().collect::<BTreeSet<_>>();
        let reusable_sequences = reusable_sequences.iter().copied().collect::<BTreeSet<_>>();
        let slot = choose_presentation_slot(
            &transaction,
            &self.workspace_id,
            max_panes,
            place_first,
            &occupied_sequences,
            &reusable_sequences,
        )?;
        transaction
            .execute(
                "INSERT INTO presentation_slot_reservations
                 (workspace_id, tab_sequence, pane_index, first_actor_id, allocated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    self.workspace_id,
                    i64::from(slot.tab_sequence),
                    i64::from(slot.pane_index),
                    actor_id,
                    to_i64(now_ms)?
                ],
            )
            .map_err(ControlError::database)?;
        transaction
            .execute(
                "INSERT INTO session_presentations
                 (workspace_id, actor_id, team_id, session_label, desired_label,
                  tab_sequence, pane_index, applied_label, sync_state, last_error, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, NULL, ?9)",
                params![
                    self.workspace_id,
                    actor_id,
                    team_id,
                    session_label,
                    desired_label,
                    i64::from(slot.tab_sequence),
                    i64::from(slot.pane_index),
                    PresentationSyncState::Pending.as_str(),
                    to_i64(now_ms)?
                ],
            )
            .map_err(ControlError::database)?;
        let record = presentation_for_actor(&transaction, &self.workspace_id, actor_id)?
            .ok_or_else(|| ControlError::database("allocated presentation disappeared"))?;
        transaction.commit().map_err(ControlError::database)?;
        Ok(record)
    }

    pub(crate) fn update_presentation_labels(
        &self,
        actor_id: &str,
        session_label: &str,
        desired_label: &str,
        now_ms: u64,
    ) -> Result<SessionPresentationRecord, ControlError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        let existing = presentation_for_actor(&transaction, &self.workspace_id, actor_id)?
            .ok_or_else(|| ControlError::not_found("session presentation", actor_id))?;
        if existing.session_label != session_label || existing.desired_label != desired_label {
            transaction
                .execute(
                    "UPDATE session_presentations
                     SET session_label = ?1, desired_label = ?2, sync_state = ?3,
                         last_error = NULL, updated_at_ms = ?4
                     WHERE workspace_id = ?5 AND actor_id = ?6",
                    params![
                        session_label,
                        desired_label,
                        PresentationSyncState::Pending.as_str(),
                        to_i64(now_ms)?,
                        self.workspace_id,
                        actor_id
                    ],
                )
                .map_err(ControlError::database)?;
        }
        let record = presentation_for_actor(&transaction, &self.workspace_id, actor_id)?
            .ok_or_else(|| ControlError::database("updated presentation disappeared"))?;
        transaction.commit().map_err(ControlError::database)?;
        Ok(record)
    }

    pub(crate) fn session_presentation(
        &self,
        actor_id: &str,
    ) -> Result<Option<SessionPresentationRecord>, ControlError> {
        presentation_for_actor(&self.connect()?, &self.workspace_id, actor_id)
    }

    pub(crate) fn session_presentations(
        &self,
    ) -> Result<Vec<SessionPresentationRecord>, ControlError> {
        let connection = self.connect()?;
        query_presentations(
            &connection,
            "SELECT actor_id, team_id, session_label, desired_label, tab_sequence, pane_index,
                    applied_label, sync_state, last_error, updated_at_ms
             FROM session_presentations WHERE workspace_id = ?1
             ORDER BY CASE WHEN tab_sequence IS NULL THEN 0 ELSE 1 END,
                      tab_sequence, pane_index, actor_id",
            &self.workspace_id,
        )
    }

    pub(crate) fn presentations_for_team(
        &self,
        team_id: &str,
    ) -> Result<Vec<SessionPresentationRecord>, ControlError> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare(
                "SELECT actor_id, team_id, session_label, desired_label, tab_sequence, pane_index,
                        applied_label, sync_state, last_error, updated_at_ms
                 FROM session_presentations WHERE workspace_id = ?1 AND team_id = ?2
                 ORDER BY tab_sequence, pane_index, actor_id",
            )
            .map_err(ControlError::database)?;
        statement
            .query_map(params![self.workspace_id, team_id], presentation_from_row)
            .map_err(ControlError::database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(ControlError::database)
    }

    pub(crate) fn mark_presentation_applied(
        &self,
        actor_id: &str,
        label: &str,
        now_ms: u64,
    ) -> Result<SessionPresentationRecord, ControlError> {
        self.update_presentation_sync(actor_id, Some(label), None, now_ms)
    }

    pub(crate) fn mark_presentation_pending(
        &self,
        actor_id: &str,
        error: Option<&str>,
        now_ms: u64,
    ) -> Result<SessionPresentationRecord, ControlError> {
        self.update_presentation_sync(actor_id, None, error, now_ms)
    }

    fn update_presentation_sync(
        &self,
        actor_id: &str,
        applied_label: Option<&str>,
        error: Option<&str>,
        now_ms: u64,
    ) -> Result<SessionPresentationRecord, ControlError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        let existing = presentation_for_actor(&transaction, &self.workspace_id, actor_id)?
            .ok_or_else(|| ControlError::not_found("session presentation", actor_id))?;
        let (applied_label, sync_state, last_error) = if let Some(label) = applied_label {
            let state = if existing.desired_label == label {
                PresentationSyncState::Applied
            } else {
                PresentationSyncState::Pending
            };
            (Some(label), state, None)
        } else {
            (
                existing.applied_label.as_deref(),
                PresentationSyncState::Pending,
                error,
            )
        };
        transaction
            .execute(
                "UPDATE session_presentations
                 SET applied_label = ?1, sync_state = ?2, last_error = ?3, updated_at_ms = ?4
                 WHERE workspace_id = ?5 AND actor_id = ?6",
                params![
                    applied_label,
                    sync_state.as_str(),
                    last_error,
                    to_i64(now_ms)?,
                    self.workspace_id,
                    actor_id
                ],
            )
            .map_err(ControlError::database)?;
        let record = presentation_for_actor(&transaction, &self.workspace_id, actor_id)?
            .ok_or_else(|| ControlError::database("presentation sync record disappeared"))?;
        transaction.commit().map_err(ControlError::database)?;
        Ok(record)
    }

    pub(crate) fn claim_replacement_intent(
        &self,
        actor_id: &str,
        intent_key: &str,
        now_ms: u64,
    ) -> Result<SessionRecord, ControlError> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        let mut session = transaction
            .query_row(
                "SELECT actor_id, team_id, working_directory, backend, runtime, external_id,
                 resume_token, status, launch_key, updated_at_ms FROM sessions
                 WHERE workspace_id = ?1 AND actor_id = ?2",
                params![self.workspace_id, actor_id],
                session_from_row,
            )
            .optional()
            .map_err(ControlError::database)?
            .ok_or_else(|| ControlError::not_found("session", actor_id))?;
        if session.launch_key == intent_key {
            transaction.commit().map_err(ControlError::database)?;
            return Ok(session);
        }
        if session.replacement_in_progress() {
            return Err(ControlError::new(
                "actor_replacement_in_progress",
                format!("actor `{actor_id}` already has an active launch or replacement intent"),
            )
            .with_hint("retry the original actor launch or replacement operation ID"));
        }
        "replacement_pending".clone_into(&mut session.status);
        intent_key.clone_into(&mut session.launch_key);
        session.updated_at_ms = now_ms;
        transaction
            .execute(
                "UPDATE sessions SET status = ?1, launch_key = ?2, updated_at_ms = ?3
                 WHERE workspace_id = ?4 AND actor_id = ?5",
                params![
                    session.status,
                    session.launch_key,
                    to_i64(now_ms)?,
                    self.workspace_id,
                    actor_id
                ],
            )
            .map_err(ControlError::database)?;
        transaction.commit().map_err(ControlError::database)?;
        Ok(session)
    }

    pub(crate) fn bind_actor(
        &self,
        binding_kind: &str,
        binding_value: &str,
        actor: &ActorRef,
        now_ms: u64,
    ) -> Result<(), ControlError> {
        let binding_hash = binding_hash(binding_kind, binding_value);
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ControlError::database)?;
        let existing = transaction
            .query_row(
                "SELECT actor_id, actor_epoch FROM actor_bindings
                 WHERE workspace_id = ?1 AND binding_kind = ?2 AND binding_hash = ?3",
                params![self.workspace_id, binding_kind, binding_hash],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(ControlError::database)?;
        if let Some((actor_id, actor_epoch)) = existing {
            if actor_id != actor.actor_id.as_str() {
                return Err(ControlError::new(
                    "actor_binding_conflict",
                    "the current session is already bound to another actor",
                ));
            }
            let actor_epoch = u64::try_from(actor_epoch).map_err(ControlError::database)?;
            if actor_epoch > actor.actor_epoch.get() {
                return Err(ControlError::new(
                    "stale_actor_binding",
                    "the current session binding is newer than the requested actor generation",
                ));
            }
            transaction
                .execute(
                    "UPDATE actor_bindings SET actor_epoch = ?1, last_authenticated_at_ms = ?2
                     WHERE workspace_id = ?3 AND binding_kind = ?4 AND binding_hash = ?5",
                    params![
                        to_i64(actor.actor_epoch.get())?,
                        to_i64(now_ms)?,
                        self.workspace_id,
                        binding_kind,
                        binding_hash
                    ],
                )
                .map_err(ControlError::database)?;
            transaction.commit().map_err(ControlError::database)?;
            return Ok(());
        }
        transaction
            .execute(
                "INSERT INTO actor_bindings
                 (workspace_id, binding_kind, binding_hash, actor_id, actor_epoch,
                  created_at_ms, last_authenticated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                params![
                    self.workspace_id,
                    binding_kind,
                    binding_hash,
                    actor.actor_id.as_str(),
                    to_i64(actor.actor_epoch.get())?,
                    to_i64(now_ms)?
                ],
            )
            .map_err(ControlError::database)?;
        transaction.commit().map_err(ControlError::database)
    }

    pub(crate) fn actor_binding(
        &self,
        binding_kind: &str,
        binding_value: &str,
    ) -> Result<Option<ActorBinding>, ControlError> {
        let connection = self.connect()?;
        let raw = connection
            .query_row(
                "SELECT actor_id, actor_epoch FROM actor_bindings
                 WHERE workspace_id = ?1 AND binding_kind = ?2 AND binding_hash = ?3",
                params![
                    self.workspace_id,
                    binding_kind,
                    binding_hash(binding_kind, binding_value)
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(ControlError::database)?;
        raw.map(|(actor_id, actor_epoch)| {
            let actor_epoch = u64::try_from(actor_epoch).map_err(ControlError::database)?;
            Ok(ActorBinding {
                actor: ActorRef {
                    actor_id: ActorId::new(actor_id).map_err(ControlError::protocol)?,
                    actor_epoch: ActorEpoch::new(actor_epoch).map_err(ControlError::protocol)?,
                },
            })
        })
        .transpose()
    }

    pub(crate) fn events(&self, limit: u32) -> Result<Vec<StoredEvent>, ControlError> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare(
                "SELECT sequence, revision, operation, detail_json, occurred_at_ms FROM (
                   SELECT sequence, revision, operation, detail_json, occurred_at_ms FROM (
                     SELECT sequence, revision, operation, detail_json, occurred_at_ms
                     FROM control_events WHERE workspace_id = ?1
                     UNION ALL
                     SELECT sequence, revision, operation, detail_json, occurred_at_ms
                     FROM control_event_archive WHERE workspace_id = ?1
                   ) ORDER BY sequence DESC LIMIT ?2
                 ) ORDER BY sequence",
            )
            .map_err(ControlError::database)?;
        let rows = statement
            .query_map(params![self.workspace_id, limit], |row| {
                let revision = row.get::<_, i64>(1)?;
                let occurred = row.get::<_, i64>(4)?;
                Ok((
                    row.get::<_, i64>(0)?,
                    revision,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    occurred,
                ))
            })
            .map_err(ControlError::database)?;
        rows.map(|row| {
            let (sequence, revision, operation, detail, occurred) =
                row.map_err(ControlError::database)?;
            Ok(StoredEvent {
                sequence,
                revision: u64::try_from(revision).map_err(ControlError::database)?,
                operation,
                detail: serde_json::from_str(&detail).map_err(ControlError::database)?,
                occurred_at_ms: u64::try_from(occurred).map_err(ControlError::database)?,
            })
        })
        .collect()
    }

    /// Returns a bounded lifecycle-outcome window without hydrating archived
    /// message bodies or scanning terminal history. Hot requests are retained
    /// first in the snapshot's canonical order; the remaining budget is filled
    /// from the most recently appended terminal archive rows and returned
    /// oldest-to-newest. Both hot inspection and archive hydration are bounded
    /// by `limit`.
    pub(crate) fn request_outcomes(
        &self,
        hot_requests: &[Request],
        limit: u32,
    ) -> Result<Vec<Request>, ControlError> {
        let limit = usize::try_from(limit).map_err(ControlError::database)?;
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut hot_ids = BTreeSet::new();
        let mut hot = Vec::with_capacity(limit.min(hot_requests.len()));
        for request in hot_requests.iter().take(limit) {
            if request.workspace_id.as_str() != self.workspace_id {
                return Err(ControlError::new(
                    "request_outcome_workspace_mismatch",
                    format!(
                        "hot request `{}` belongs to a different workspace",
                        request.request_id
                    ),
                ));
            }
            if !hot_ids.insert(request.request_id.clone()) {
                return Err(request_outcome_id_conflict(&request.request_id));
            }
            hot.push(request.clone());
        }
        let archive_limit = limit.saturating_sub(hot.len());

        let connection = self.connect()?;
        for request_id in &hot_ids {
            let archived = connection
                .query_row(
                    "SELECT 1 FROM terminal_request_archive
                     WHERE workspace_id = ?1 AND request_id = ?2",
                    params![self.workspace_id, request_id.as_str()],
                    |_| Ok(()),
                )
                .optional()
                .map_err(ControlError::database)?;
            if archived.is_some() {
                return Err(request_outcome_id_conflict(request_id));
            }
        }
        if archive_limit == 0 {
            return Ok(hot);
        }

        let mut statement = connection
            .prepare(
                "SELECT request_id, run_id, request_sha256, request_json,
                        run_sha256, run_json
                 FROM terminal_request_archive
                 WHERE workspace_id = ?1
                 ORDER BY archived_revision DESC, request_id DESC LIMIT ?2",
            )
            .map_err(ControlError::database)?;
        let rows = statement
            .query_map(
                params![
                    self.workspace_id,
                    i64::try_from(archive_limit).map_err(ControlError::database)?
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .map_err(ControlError::database)?;
        let mut archived = rows
            .map(|row| {
                let (request_id, run_id, request_digest, request_json, run_digest, run_json) =
                    row.map_err(ControlError::database)?;
                verify_digest("archived request", &request_digest, request_json.as_bytes())?;
                verify_digest("archived run", &run_digest, run_json.as_bytes())?;
                let request: Request =
                    serde_json::from_str(&request_json).map_err(ControlError::database)?;
                let run: Run = serde_json::from_str(&run_json).map_err(ControlError::database)?;
                validate_terminal_request_archive_binding(
                    &self.workspace_id,
                    &request_id,
                    &run_id,
                    &request,
                    &run,
                )?;
                if hot_ids.contains(&request.request_id) {
                    return Err(request_outcome_id_conflict(&request.request_id));
                }
                Ok(request)
            })
            .collect::<Result<Vec<_>, ControlError>>()?;
        archived.reverse();
        archived.extend(hot);
        Ok(archived)
    }

    pub(crate) fn protocol_events(
        &self,
        hot_events: &[AuditEvent],
        limit: u32,
    ) -> Result<Vec<AuditEvent>, ControlError> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare(
                "SELECT sequence, message_id, event_sha256, event_json
                 FROM protocol_audit_archive WHERE workspace_id = ?1
                 ORDER BY sequence DESC LIMIT ?2",
            )
            .map_err(ControlError::database)?;
        let rows = statement
            .query_map(params![self.workspace_id, limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(ControlError::database)?;
        let mut events = hot_events.to_vec();
        for row in rows {
            let (sequence, message_id, digest, json) = row.map_err(ControlError::database)?;
            verify_digest("archived protocol audit event", &digest, json.as_bytes())?;
            let event: AuditEvent = serde_json::from_str(&json).map_err(ControlError::database)?;
            if sequence != to_i64(event.sequence)?
                || message_id != audit_message_id(&event).as_str()
            {
                return Err(ControlError::new(
                    "protocol_audit_archive_key_mismatch",
                    format!(
                        "protocol audit SQL key {sequence}/{message_id} conflicts with immutable JSON"
                    ),
                ));
            }
            events.push(event);
        }
        events.sort_by_key(|event| std::cmp::Reverse(event.sequence));
        events.truncate(usize::try_from(limit).map_err(ControlError::database)?);
        events.sort_by_key(|event| event.sequence);
        Ok(events)
    }

    /// Fetches one full protocol payload on explicit demand and verifies it
    /// against the digest retained in the compact domain snapshot.
    pub(crate) fn message_body(
        &self,
        message_id: &MessageId,
        expected_digest: &PayloadDigest,
    ) -> Result<Message, ControlError> {
        hydrate_message_body(
            &self.connect()?,
            &self.workspace_id,
            message_id.as_str(),
            Some(expected_digest.as_str()),
        )?
        .ok_or_else(|| {
            ControlError::new(
                "message_body_missing",
                format!("message body `{message_id}` is not present in immutable storage"),
            )
        })
    }

    pub(crate) fn request_specification(
        &self,
        request: &Request,
    ) -> Result<Option<ImplementationRequest>, ControlError> {
        let specification: Option<ImplementationRequest> = read_verified_json(
            &self.connect()?,
            "request_specifications",
            "request_id",
            request.request_id.as_str(),
            "content_sha256",
            "specification_json",
            &self.workspace_id,
        )?;
        let Some(specification) = specification else {
            return Ok(None);
        };
        let message = self.message_body(
            &request.specification.message_id,
            &request.specification.payload_digest,
        )?;
        let Message::ImplementationRequest(accepted) = message else {
            return Err(ControlError::new(
                "request_specification_body_mismatch",
                format!(
                    "request `{}` specification message has a different payload kind",
                    request.request_id
                ),
            ));
        };
        if accepted != specification || accepted.base_sha != request.specification.base_sha {
            return Err(ControlError::new(
                "request_specification_reference_mismatch",
                format!(
                    "request `{}` specification conflicts with its accepted message digest",
                    request.request_id
                ),
            ));
        }
        Ok(Some(specification))
    }

    /// Explicit immutable-text fetch used by future audit/reporting commands.
    #[allow(dead_code)]
    pub(crate) fn decision_rationale(
        &self,
        decision_id: &str,
    ) -> Result<Option<String>, ControlError> {
        read_verified_raw(
            &self.connect()?,
            "decision_rationales",
            "decision_id",
            decision_id,
            "content_sha256",
            "rationale",
            &self.workspace_id,
            None,
        )
    }

    /// Explicit content-addressed evidence fetch; ordinary state loads never
    /// deserialize these records.
    #[allow(dead_code)]
    pub(crate) fn evidence_record(
        &self,
        evidence_id: &str,
    ) -> Result<Option<Evidence>, ControlError> {
        read_verified_json(
            &self.connect()?,
            "evidence_records",
            "evidence_id",
            evidence_id,
            "content_sha256",
            "evidence_json",
            &self.workspace_id,
        )
    }

    /// Fetches one compact archived delivery with its archive digest checked.
    pub(crate) fn archived_delivery(
        &self,
        message_id: &MessageId,
    ) -> Result<Option<DeliverySnapshot>, ControlError> {
        read_archived_delivery(&self.connect()?, &self.workspace_id, message_id)
    }

    pub(crate) fn archived_deliveries(&self) -> Result<Vec<DeliverySnapshot>, ControlError> {
        let connection = self.connect()?;
        let message_ids = {
            let mut statement = connection
                .prepare(
                    "SELECT message_id FROM delivery_archive
                     WHERE workspace_id = ?1 ORDER BY sent_at_ms, message_id",
                )
                .map_err(ControlError::database)?;
            statement
                .query_map([&self.workspace_id], |row| row.get::<_, String>(0))
                .map_err(ControlError::database)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(ControlError::database)?
        };
        message_ids
            .into_iter()
            .map(|message_id| {
                let message_id = MessageId::new(message_id).map_err(ControlError::protocol)?;
                read_archived_delivery(&connection, &self.workspace_id, &message_id)?.ok_or_else(
                    || ControlError::not_found("archived delivery", message_id.as_str()),
                )
            })
            .collect()
    }

    /// Fetches one terminal request/run pair and verifies both compact records.
    pub(crate) fn archived_request(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<(Request, Run)>, ControlError> {
        let row = self
            .connect()?
            .query_row(
                "SELECT run_id, request_sha256, request_json, run_sha256, run_json
                 FROM terminal_request_archive WHERE workspace_id = ?1 AND request_id = ?2",
                params![self.workspace_id, request_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(ControlError::database)?;
        row.map(
            |(run_id, request_digest, request_json, run_digest, run_json)| {
                verify_digest("archived request", &request_digest, request_json.as_bytes())?;
                verify_digest("archived run", &run_digest, run_json.as_bytes())?;
                let request: Request =
                    serde_json::from_str(&request_json).map_err(ControlError::database)?;
                let run: Run = serde_json::from_str(&run_json).map_err(ControlError::database)?;
                validate_terminal_request_archive_binding(
                    &self.workspace_id,
                    request_id.as_str(),
                    &run_id,
                    &request,
                    &run,
                )?;
                Ok((request, run))
            },
        )
        .transpose()
    }

    pub(crate) fn archived_requests(&self) -> Result<Vec<(Request, Run)>, ControlError> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare(
                "SELECT request_id, run_id, request_sha256, request_json, run_sha256, run_json
                 FROM terminal_request_archive
                 WHERE workspace_id = ?1 ORDER BY archived_revision, request_id",
            )
            .map_err(ControlError::database)?;
        let rows = statement
            .query_map([&self.workspace_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(ControlError::database)?;
        rows.map(|row| {
            let (request_id, run_id, request_digest, request_json, run_digest, run_json) =
                row.map_err(ControlError::database)?;
            verify_digest("archived request", &request_digest, request_json.as_bytes())?;
            verify_digest("archived run", &run_digest, run_json.as_bytes())?;
            let request: Request =
                serde_json::from_str(&request_json).map_err(ControlError::database)?;
            let run: Run = serde_json::from_str(&run_json).map_err(ControlError::database)?;
            validate_terminal_request_archive_binding(
                &self.workspace_id,
                &request_id,
                &run_id,
                &request,
                &run,
            )?;
            Ok((request, run))
        })
        .collect()
    }

    pub(crate) fn archived_run(
        &self,
        run_id: &agsv_protocol::RunId,
    ) -> Result<Option<(Request, Run)>, ControlError> {
        let connection = self.connect()?;
        let row = connection
            .query_row(
                "SELECT request_id, request_sha256, request_json, run_sha256, run_json
                 FROM terminal_request_archive WHERE workspace_id = ?1 AND run_id = ?2",
                params![self.workspace_id, run_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(ControlError::database)?;
        row.map(
            |(request_id, request_digest, request_json, run_digest, run_json)| {
                verify_digest("archived request", &request_digest, request_json.as_bytes())?;
                verify_digest("archived run", &run_digest, run_json.as_bytes())?;
                let request: Request =
                    serde_json::from_str(&request_json).map_err(ControlError::database)?;
                let run: Run = serde_json::from_str(&run_json).map_err(ControlError::database)?;
                validate_terminal_request_archive_binding(
                    &self.workspace_id,
                    &request_id,
                    run_id.as_str(),
                    &request,
                    &run,
                )?;
                Ok((request, run))
            },
        )
        .transpose()
    }

    /// Returns retired review decisions for an exact candidate in durable
    /// decision-time order. Full rationale/evidence is hydrated only here and
    /// verified against the original accepted-message digest.
    #[allow(dead_code)]
    pub(crate) fn archived_decisions_by_candidate_sha(
        &self,
        candidate_sha: &GitSha,
    ) -> Result<Vec<ReviewDecision>, ControlError> {
        let connection = self.connect()?;
        let rows = {
            let mut statement = connection
                .prepare(
                    "SELECT rationale.message_id, body.content_sha256,
                            rationale.decision_id, rationale.rationale
                     FROM decision_rationales AS rationale
                     JOIN delivery_archive AS delivery
                       ON delivery.workspace_id = rationale.workspace_id
                      AND delivery.message_id = rationale.message_id
                     JOIN message_bodies AS body
                       ON body.workspace_id = rationale.workspace_id
                      AND body.message_id = rationale.message_id
                     WHERE rationale.workspace_id = ?1 AND rationale.candidate_sha = ?2
                     ORDER BY rationale.decided_at_ms, rationale.decision_id",
                )
                .map_err(ControlError::database)?;
            statement
                .query_map(params![self.workspace_id, candidate_sha.as_str()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(ControlError::database)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(ControlError::database)?
        };
        rows.into_iter()
            .map(|(message_id, payload_digest, decision_id, rationale)| {
                let message = hydrate_message_body(
                    &connection,
                    &self.workspace_id,
                    &message_id,
                    Some(&payload_digest),
                )?
                .ok_or_else(|| missing_bulk("message_bodies", &message_id))?;
                let Message::ReviewDecision(decision) = message else {
                    return Err(ControlError::new(
                        "archived_decision_body_mismatch",
                        format!(
                            "archived decision message `{message_id}` has a different payload kind"
                        ),
                    ));
                };
                if decision.decision_id.as_str() != decision_id
                    || decision.candidate.sha != *candidate_sha
                    || decision.rationale != rationale
                {
                    return Err(ControlError::new(
                        "archived_decision_metadata_mismatch",
                        format!(
                            "archived decision `{decision_id}` conflicts with its immutable indexes"
                        ),
                    ));
                }
                Ok(decision)
            })
            .collect()
    }

    fn connect(&self) -> Result<Connection, ControlError> {
        let connection = Connection::open(&self.path).map_err(ControlError::database)?;
        #[cfg(test)]
        connection
            .progress_handler(
                1,
                Some(|| {
                    STORE_WORK_ACTIVE.with(|active| {
                        if active.get() {
                            STORE_VM_STEPS.with(|count| count.set(count.get() + 1));
                        }
                    });
                    false
                }),
            )
            .map_err(ControlError::database)?;
        set_mode(&self.path, 0o600, "secure state database")?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(ControlError::database)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(ControlError::database)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(ControlError::database)?;
        Ok(connection)
    }
}

fn restore_supervisor(snapshot: DomainSnapshot) -> Result<Supervisor, ControlError> {
    Supervisor::from_snapshot(snapshot).map_err(ControlError::core)
}

fn verify_review_rows(
    connection: &Connection,
    workspace_id: &str,
    review_root: &Path,
    store: &StateStore,
    verify_artifact: &mut impl FnMut(&ReviewArtifactExpectation) -> Result<(), ControlError>,
) -> Result<ReviewIntegrityReport, ControlError> {
    let mut report = ReviewIntegrityReport::default();
    let mut last_session_id = String::new();
    loop {
        let row = connection
            .query_row(
                "SELECT session_id, begin_operation_id, request_id, candidate_sha,
                        tree_sha, checkout_path, plan_sha256, record_sha256,
                        record_json, policy_revision, status, recovery, last_error,
                        created_at_ms, updated_at_ms
                 FROM review_sessions
                 WHERE workspace_id = ?1 AND session_id > ?2
                 ORDER BY session_id LIMIT 1",
                params![workspace_id, last_session_id],
                stored_review_session_row,
            )
            .optional()
            .map_err(ControlError::database)?;
        let Some(row) = row else {
            break;
        };
        last_session_id.clone_from(&row.session_id);
        let stored = validate_stored_review_session(row, workspace_id, store)?;
        report.sessions = checked_review_count(report.sessions, 1)?;
        verify_review_attempt_history(
            connection,
            workspace_id,
            review_root,
            &stored.session,
            &mut report,
            verify_artifact,
        )?;
    }
    verify_review_row_counts(connection, workspace_id, report)?;
    Ok(report)
}

fn verify_review_attempt_history(
    connection: &Connection,
    workspace_id: &str,
    review_root: &Path,
    session: &ReviewSession,
    report: &mut ReviewIntegrityReport,
    verify_artifact: &mut impl FnMut(&ReviewArtifactExpectation) -> Result<(), ControlError>,
) -> Result<(), ControlError> {
    let mut prior_sequence = 0_u64;
    loop {
        let sequence = connection
            .query_row(
                "SELECT MIN(sequence) FROM review_verification_attempts
                 WHERE workspace_id = ?1 AND session_id = ?2 AND sequence > ?3",
                params![
                    workspace_id,
                    session.session_id.as_str(),
                    to_i64(prior_sequence)?
                ],
                |row| row.get::<_, Option<i64>>(0),
            )
            .map_err(ControlError::database)?;
        let Some(sequence) = sequence else {
            break;
        };
        let sequence = u64::try_from(sequence).map_err(ControlError::database)?;
        if sequence
            != prior_sequence.checked_add(1).ok_or_else(|| {
                ControlError::new(
                    "review_integrity_overflow",
                    "review attempt sequence overflow",
                )
            })?
        {
            return Err(ControlError::new(
                "review_attempt_sequence_gap",
                format!(
                    "review session `{}` has a gap before attempt {sequence}",
                    session.session_id
                ),
            ));
        }
        let attempts = review_attempts_for_sequence(
            connection,
            workspace_id,
            &session.session_id,
            sequence,
            session,
        )?;
        verify_review_attempt_group(session, &attempts)?;
        report.attempt_records = checked_review_count(
            report.attempt_records,
            u64::try_from(attempts.len()).map_err(ControlError::database)?,
        )?;
        verify_review_execution_group(
            connection,
            workspace_id,
            review_root,
            session,
            sequence,
            &attempts[0].attempt,
            attempts.get(1).map(|attempt| &attempt.attempt),
            report,
            verify_artifact,
        )?;
        prior_sequence = sequence;
    }
    Ok(())
}

fn verify_review_attempt_group(
    session: &ReviewSession,
    attempts: &[StoredReviewVerificationAttempt],
) -> Result<(), ControlError> {
    let valid = matches!(attempts,
        [running] if running.attempt.status == ReviewAttemptStatus::Running
    ) || matches!(attempts, [running, terminal]
        if running.attempt.status == ReviewAttemptStatus::Running
            && terminal.attempt.status != ReviewAttemptStatus::Running
            && running.verify_operation_id == terminal.verify_operation_id
            && same_review_attempt_identity(&running.attempt, &terminal.attempt)
            && running
                .attempt
                .status
                .allows_transition_to(terminal.attempt.status)
    );
    if valid {
        Ok(())
    } else {
        Err(ControlError::new(
            "review_attempt_history_invalid",
            format!(
                "review session `{}` has malformed append-only attempt facts",
                session.session_id
            ),
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_review_execution_group(
    connection: &Connection,
    workspace_id: &str,
    review_root: &Path,
    session: &ReviewSession,
    attempt_sequence: u64,
    running: &ReviewVerificationAttempt,
    terminal: Option<&ReviewVerificationAttempt>,
    report: &mut ReviewIntegrityReport,
    verify_artifact: &mut impl FnMut(&ReviewArtifactExpectation) -> Result<(), ControlError>,
) -> Result<(), ControlError> {
    let execution_limit = review_execution_limit(session)?;
    let environments = query_review_environments(
        connection,
        "WHERE workspace_id = ?1 AND session_id = ?2 AND attempt_sequence = ?3
         ORDER BY variant, check_id LIMIT ?4",
        params![
            workspace_id,
            session.session_id.as_str(),
            to_i64(attempt_sequence)?,
            execution_limit,
        ],
        session,
    )?;
    let results = query_review_check_results(
        connection,
        "WHERE workspace_id = ?1 AND session_id = ?2 AND attempt_sequence = ?3
         ORDER BY variant, check_id LIMIT ?4",
        params![
            workspace_id,
            session.session_id.as_str(),
            to_i64(attempt_sequence)?,
            execution_limit,
        ],
        session,
    )?;
    let maximum =
        usize::try_from(execution_limit.saturating_sub(1)).map_err(ControlError::database)?;
    if environments.len() > maximum || results.len() > maximum {
        return Err(ControlError::new(
            "review_execution_history_oversized",
            format!(
                "review session `{}` attempt {attempt_sequence} exceeds its frozen plan",
                session.session_id
            ),
        ));
    }
    let environments_by_id = environments
        .iter()
        .map(|stored| {
            (
                stored.environment.environment_id.as_str(),
                &stored.environment,
            )
        })
        .collect::<BTreeMap<_, _>>();
    for environment in &environments {
        if environment.environment.recorded_at < running.started_at {
            return Err(ControlError::new(
                "invalid_review_environment",
                "review environment capture precedes its running attempt",
            ));
        }
        verify_review_environment_artifacts(
            review_root,
            &environment.environment,
            report,
            verify_artifact,
        )?;
    }
    for result in &results {
        if result.started_at < running.started_at {
            return Err(ControlError::new(
                "invalid_review_check_result",
                "review check execution precedes its running attempt",
            ));
        }
        let environment = environments_by_id
            .get(result.environment_id.as_str())
            .ok_or_else(|| {
                ControlError::new(
                    "review_environment_missing",
                    format!(
                        "review result `{}` references missing environment `{}`",
                        result.check_id, result.environment_id
                    ),
                )
            })?;
        session
            .validate_execution_pair(result, environment)
            .map_err(invalid_review_check_result)?;
        verify_review_result_artifacts(review_root, result, report, verify_artifact)?;
    }
    if let Some(terminal) = terminal {
        session
            .validate_attempt_results(terminal, &results)
            .map_err(invalid_review_attempt)?;
    }
    report.environments = checked_review_count(
        report.environments,
        u64::try_from(environments.len()).map_err(ControlError::database)?,
    )?;
    report.check_results = checked_review_count(
        report.check_results,
        u64::try_from(results.len()).map_err(ControlError::database)?,
    )?;
    Ok(())
}

fn review_execution_limit(session: &ReviewSession) -> Result<u32, ControlError> {
    let expected = session
        .plan
        .checks
        .iter()
        .map(|check| usize::from(!check.required_absent_binaries.is_empty()))
        .sum::<usize>();
    let normal = session.plan.checks.len();
    normal
        .checked_add(expected)
        .and_then(|count| count.checked_add(1))
        .and_then(|count| u32::try_from(count).ok())
        .ok_or_else(|| ControlError::database("review execution count overflow"))
}

fn verify_review_environment_artifacts(
    review_root: &Path,
    environment: &ReviewEnvironmentRecord,
    report: &mut ReviewIntegrityReport,
    verify_artifact: &mut impl FnMut(&ReviewArtifactExpectation) -> Result<(), ControlError>,
) -> Result<(), ControlError> {
    for tool in &environment.tool_versions {
        verify_review_artifact(
            review_root,
            &environment.session_id,
            format!("tool.{}.stdout", tool.tool_id),
            &tool.stdout,
            report,
            verify_artifact,
        )?;
        verify_review_artifact(
            review_root,
            &environment.session_id,
            format!("tool.{}.stderr", tool.tool_id),
            &tool.stderr,
            report,
            verify_artifact,
        )?;
    }
    Ok(())
}

fn verify_review_result_artifacts(
    review_root: &Path,
    result: &ReviewCheckResult,
    report: &mut ReviewIntegrityReport,
    verify_artifact: &mut impl FnMut(&ReviewArtifactExpectation) -> Result<(), ControlError>,
) -> Result<(), ControlError> {
    let prefix = format!(
        "attempt.{}.check.{}.{}",
        result.attempt_sequence,
        result.check_id,
        review_execution_variant_text(result.variant)
    );
    verify_review_artifact(
        review_root,
        &result.session_id,
        format!("{prefix}.stdout"),
        &result.stdout,
        report,
        verify_artifact,
    )?;
    verify_review_artifact(
        review_root,
        &result.session_id,
        format!("{prefix}.stderr"),
        &result.stderr,
        report,
        verify_artifact,
    )
}

fn verify_review_artifact(
    review_root: &Path,
    session_id: &ReviewSessionId,
    source: String,
    artifact: &ReviewOutputArtifact,
    report: &mut ReviewIntegrityReport,
    verify_artifact: &mut impl FnMut(&ReviewArtifactExpectation) -> Result<(), ControlError>,
) -> Result<(), ControlError> {
    let Some(reference) = artifact.reference.as_deref() else {
        return Ok(());
    };
    let path = review_root.join(session_id.as_str()).join(reference);
    let expectation = ReviewArtifactExpectation {
        source,
        path,
        digest: artifact.digest.clone(),
        byte_count: artifact.byte_count,
    };
    verify_artifact(&expectation)?;
    report.referenced_artifacts = checked_review_count(report.referenced_artifacts, 1)?;
    Ok(())
}

fn checked_review_count(current: u64, added: u64) -> Result<u64, ControlError> {
    current.checked_add(added).ok_or_else(|| {
        ControlError::new(
            "review_integrity_overflow",
            "review integrity count overflow",
        )
    })
}

fn verify_review_row_counts(
    connection: &Connection,
    workspace_id: &str,
    observed: ReviewIntegrityReport,
) -> Result<(), ControlError> {
    for (table, count) in [
        ("review_sessions", observed.sessions),
        ("review_verification_attempts", observed.attempt_records),
        ("review_environment_records", observed.environments),
        ("review_check_results", observed.check_results),
    ] {
        let query = format!("SELECT COUNT(*) FROM {table} WHERE workspace_id = ?1");
        let durable = connection
            .query_row(&query, [workspace_id], |row| row.get::<_, i64>(0))
            .map_err(ControlError::database)?;
        let durable = u64::try_from(durable).map_err(ControlError::database)?;
        if durable != count {
            return Err(ControlError::new(
                "review_integrity_coverage_mismatch",
                format!("{table} contains unowned or unverified rows"),
            )
            .with_details(json!({
                "table": table,
                "durable": durable,
                "verified": count,
            })));
        }
    }
    Ok(())
}

fn stored_review_session_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredReviewSessionRow> {
    Ok(StoredReviewSessionRow {
        session_id: row.get(0)?,
        begin_operation_id: row.get(1)?,
        request_id: row.get(2)?,
        candidate_sha: row.get(3)?,
        tree_sha: row.get(4)?,
        checkout_path: row.get(5)?,
        plan_sha256: row.get(6)?,
        record_sha256: row.get(7)?,
        record_json: row.get(8)?,
        policy_revision: row.get(9)?,
        status: row.get(10)?,
        recovery: row.get(11)?,
        last_error: row.get(12)?,
        created_at_ms: row.get(13)?,
        updated_at_ms: row.get(14)?,
    })
}

fn stored_review_attempt_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredReviewAttemptRow> {
    Ok(StoredReviewAttemptRow {
        record_id: row.get(0)?,
        session_id: row.get(1)?,
        request_id: row.get(2)?,
        candidate_sha: row.get(3)?,
        attempt_sequence: row.get(4)?,
        verify_operation_id: row.get(5)?,
        plan_sha256: row.get(6)?,
        status: row.get(7)?,
        record_sha256: row.get(8)?,
        record_json: row.get(9)?,
        started_at_ms: row.get(10)?,
        finished_at_ms: row.get(11)?,
        recorded_at_ms: row.get(12)?,
    })
}

fn query_review_attempts<P: rusqlite::Params>(
    connection: &Connection,
    suffix: &str,
    params: P,
    session: &ReviewSession,
) -> Result<Vec<StoredReviewVerificationAttempt>, ControlError> {
    let query = format!(
        "SELECT attempt_record_id, session_id, request_id, candidate_sha,
                sequence, verify_operation_id, plan_sha256, status,
                attempt_sha256, attempt_json, started_at_ms, finished_at_ms,
                recorded_at_ms
         FROM review_verification_attempts {suffix}"
    );
    let mut statement = connection.prepare(&query).map_err(ControlError::database)?;
    statement
        .query_map(params, stored_review_attempt_row)
        .map_err(ControlError::database)?
        .map(|row| validate_stored_review_attempt(row.map_err(ControlError::database)?, session))
        .collect()
}

fn review_attempt_for_record_id(
    connection: &Connection,
    workspace_id: &str,
    record_id: &str,
    session: &ReviewSession,
) -> Result<Option<StoredReviewVerificationAttempt>, ControlError> {
    query_review_attempts(
        connection,
        "WHERE workspace_id = ?1 AND attempt_record_id = ?2 LIMIT 1",
        params![workspace_id, record_id],
        session,
    )
    .map(|mut attempts| attempts.pop())
}

fn review_attempts_for_operation(
    connection: &Connection,
    workspace_id: &str,
    operation_id: &str,
    session: &ReviewSession,
) -> Result<Vec<StoredReviewVerificationAttempt>, ControlError> {
    query_review_attempts(
        connection,
        "WHERE workspace_id = ?1 AND verify_operation_id = ?2
         ORDER BY sequence,
                  CASE status WHEN 'running' THEN 0 ELSE 1 END,
                  recorded_at_ms, attempt_record_id LIMIT 3",
        params![workspace_id, operation_id],
        session,
    )
}

fn review_attempts_for_sequence(
    connection: &Connection,
    workspace_id: &str,
    session_id: &ReviewSessionId,
    attempt_sequence: u64,
    session: &ReviewSession,
) -> Result<Vec<StoredReviewVerificationAttempt>, ControlError> {
    query_review_attempts(
        connection,
        "WHERE workspace_id = ?1 AND session_id = ?2 AND sequence = ?3
         ORDER BY recorded_at_ms, attempt_record_id LIMIT 3",
        params![workspace_id, session_id.as_str(), to_i64(attempt_sequence)?],
        session,
    )
}

fn validate_new_review_attempt(
    connection: &Connection,
    workspace_id: &str,
    verify_operation_id: &str,
    session: &ReviewSession,
    attempt: &ReviewVerificationAttempt,
) -> Result<(), ControlError> {
    let ready =
        ReviewSessionState::new(ReviewSessionStatus::Ready, ReviewRecoveryState::NotRequired)
            .map_err(invalid_review_session)?;
    let may_append = match attempt.status {
        ReviewAttemptStatus::Running => session.state == ready,
        _ => session.state.status == ReviewSessionStatus::Ready,
    };
    if !may_append {
        return Err(ControlError::new(
            "review_session_not_ready",
            format!(
                "review session `{}` is not ready for this verification fact",
                attempt.session_id
            ),
        ));
    }
    let operation_records =
        review_attempts_for_operation(connection, workspace_id, verify_operation_id, session)?;
    let prior = review_attempts_for_sequence(
        connection,
        workspace_id,
        &attempt.session_id,
        attempt.attempt_sequence,
        session,
    )?;
    match attempt.status {
        ReviewAttemptStatus::Running if prior.is_empty() && operation_records.is_empty() => {}
        ReviewAttemptStatus::Running => {
            return Err(review_attempt_conflict(
                attempt,
                "logical attempt or verification operation already has a running fact",
            ));
        }
        _ if prior.len() == 1
            && prior[0].attempt.status == ReviewAttemptStatus::Running
            && same_review_attempt_identity(&prior[0].attempt, attempt)
            && prior[0].attempt.status.allows_transition_to(attempt.status)
            && operation_records.len() == 1
            && operation_records[0] == prior[0] => {}
        _ => {
            return Err(review_attempt_conflict(
                attempt,
                "terminal fact requires exactly one matching running fact",
            ));
        }
    }
    validate_terminal_review_results(connection, workspace_id, session, attempt)
}

fn validate_terminal_review_results(
    connection: &Connection,
    workspace_id: &str,
    session: &ReviewSession,
    attempt: &ReviewVerificationAttempt,
) -> Result<(), ControlError> {
    if attempt.status == ReviewAttemptStatus::Running {
        return Ok(());
    }
    let maximum_results = session
        .plan
        .checks
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .and_then(|count| u32::try_from(count).ok())
        .ok_or_else(|| ControlError::database("review result count overflow"))?;
    let results = query_review_check_results(
        connection,
        "WHERE workspace_id = ?1 AND session_id = ?2 AND attempt_sequence = ?3
         ORDER BY variant, check_id LIMIT ?4",
        params![
            workspace_id,
            attempt.session_id.as_str(),
            to_i64(attempt.attempt_sequence)?,
            maximum_results,
        ],
        session,
    )?;
    session
        .validate_attempt_results(attempt, &results)
        .map_err(invalid_review_attempt)
}

fn validate_stored_review_attempt(
    row: StoredReviewAttemptRow,
    session: &ReviewSession,
) -> Result<StoredReviewVerificationAttempt, ControlError> {
    verify_digest(
        "review verification attempt",
        &row.record_sha256,
        row.record_json.as_bytes(),
    )?;
    let attempt: ReviewVerificationAttempt =
        serde_json::from_str(&row.record_json).map_err(ControlError::database)?;
    session
        .validate_attempt_record(&attempt)
        .map_err(invalid_review_attempt)?;
    let finished_at = row
        .finished_at_ms
        .map(|timestamp| u64::try_from(timestamp).map(TimestampMillis))
        .transpose()
        .map_err(ControlError::database)?;
    if attempt.record_id.as_str() != row.record_id
        || attempt.session_id.as_str() != row.session_id
        || attempt.request_id.as_str() != row.request_id
        || attempt.candidate_sha.as_str() != row.candidate_sha
        || attempt.attempt_sequence
            != u64::try_from(row.attempt_sequence).map_err(ControlError::database)?
        || attempt.plan.config_digest.as_str() != row.plan_sha256
        || review_attempt_status_text(attempt.status) != row.status
        || attempt.started_at.0
            != u64::try_from(row.started_at_ms).map_err(ControlError::database)?
        || attempt.finished_at != finished_at
        || attempt.recorded_at.0
            != u64::try_from(row.recorded_at_ms).map_err(ControlError::database)?
        || row.verify_operation_id.is_empty()
    {
        return Err(ControlError::new(
            "review_attempt_index_mismatch",
            format!(
                "review attempt record `{}` conflicts with its durable identity columns",
                row.record_id
            ),
        ));
    }
    Ok(StoredReviewVerificationAttempt {
        verify_operation_id: row.verify_operation_id,
        attempt,
    })
}

fn ensure_running_review_attempt(
    connection: &Connection,
    workspace_id: &str,
    session: &ReviewSession,
    attempt_sequence: u64,
) -> Result<ReviewVerificationAttempt, ControlError> {
    let attempts = review_attempts_for_sequence(
        connection,
        workspace_id,
        &session.session_id,
        attempt_sequence,
        session,
    )?;
    attempts
        .into_iter()
        .find(|attempt| attempt.attempt.status == ReviewAttemptStatus::Running)
        .map(|attempt| attempt.attempt)
        .ok_or_else(|| {
            ControlError::new(
                "review_attempt_not_running",
                format!(
                    "review session `{}` attempt {attempt_sequence} has no running fact",
                    session.session_id
                ),
            )
        })
}

fn stored_review_environment_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredReviewEnvironmentRow> {
    Ok(StoredReviewEnvironmentRow {
        environment_id: row.get(0)?,
        session_id: row.get(1)?,
        request_id: row.get(2)?,
        candidate_sha: row.get(3)?,
        attempt_sequence: row.get(4)?,
        check_id: row.get(5)?,
        variant: row.get(6)?,
        process_containment: row.get(7)?,
        path_sha256: row.get(8)?,
        record_sha256: row.get(9)?,
        record_json: row.get(10)?,
        recorded_at_ms: row.get(11)?,
    })
}

fn query_review_environments<P: rusqlite::Params>(
    connection: &Connection,
    suffix: &str,
    params: P,
    session: &ReviewSession,
) -> Result<Vec<StoredReviewEnvironmentRecord>, ControlError> {
    let query = format!(
        "SELECT environment_id, session_id, request_id, candidate_sha,
                attempt_sequence, check_id, variant, process_containment,
                path_sha256, record_sha256, record_json, recorded_at_ms
         FROM review_environment_records {suffix}"
    );
    let mut statement = connection.prepare(&query).map_err(ControlError::database)?;
    statement
        .query_map(params, stored_review_environment_row)
        .map_err(ControlError::database)?
        .map(|row| {
            validate_stored_review_environment(row.map_err(ControlError::database)?, session)
        })
        .collect()
}

fn review_environment_for_id(
    connection: &Connection,
    workspace_id: &str,
    environment_id: &str,
    session: &ReviewSession,
) -> Result<Option<StoredReviewEnvironmentRecord>, ControlError> {
    query_review_environments(
        connection,
        "WHERE workspace_id = ?1 AND environment_id = ?2 LIMIT 1",
        params![workspace_id, environment_id],
        session,
    )
    .map(|mut records| records.pop())
}

fn validate_stored_review_environment(
    row: StoredReviewEnvironmentRow,
    session: &ReviewSession,
) -> Result<StoredReviewEnvironmentRecord, ControlError> {
    verify_digest(
        "review environment record",
        &row.record_sha256,
        row.record_json.as_bytes(),
    )?;
    let environment: ReviewEnvironmentRecord =
        serde_json::from_str(&row.record_json).map_err(ControlError::database)?;
    session
        .validate_environment_record(&environment)
        .map_err(invalid_review_environment)?;
    validate_review_environment_digest(&environment)?;
    let path_digest = PayloadDigest::new(row.path_sha256).map_err(invalid_review_environment)?;
    validate_review_path_digest(&environment, &path_digest)?;
    if environment.environment_id.as_str() != row.environment_id
        || environment.session_id.as_str() != row.session_id
        || environment.request_id.as_str() != row.request_id
        || environment.candidate_sha.as_str() != row.candidate_sha
        || environment.attempt_sequence
            != u64::try_from(row.attempt_sequence).map_err(ControlError::database)?
        || environment.check_id.as_str() != row.check_id
        || review_execution_variant_text(environment.variant) != row.variant
        || review_process_containment_text(environment.process_containment)
            != row.process_containment
        || environment.recorded_at.0
            != u64::try_from(row.recorded_at_ms).map_err(ControlError::database)?
    {
        return Err(ControlError::new(
            "review_environment_index_mismatch",
            format!(
                "review environment `{}` conflicts with its durable identity columns",
                row.environment_id
            ),
        ));
    }
    Ok(StoredReviewEnvironmentRecord {
        path_digest,
        environment,
    })
}

fn stored_review_check_result_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredReviewCheckResultRow> {
    Ok(StoredReviewCheckResultRow {
        session_id: row.get(0)?,
        request_id: row.get(1)?,
        candidate_sha: row.get(2)?,
        attempt_sequence: row.get(3)?,
        check_id: row.get(4)?,
        variant: row.get(5)?,
        environment_id: row.get(6)?,
        expected_exit_code: row.get(7)?,
        actual_exit_code: row.get(8)?,
        outcome: row.get(9)?,
        termination: row.get(10)?,
        process_tree_may_outlive: row.get(11)?,
        stdout_sha256: row.get(12)?,
        stderr_sha256: row.get(13)?,
        stdout_bytes: row.get(14)?,
        stderr_bytes: row.get(15)?,
        stdout_truncated: row.get(16)?,
        stderr_truncated: row.get(17)?,
        stdout_artifact_ref: row.get(18)?,
        stderr_artifact_ref: row.get(19)?,
        record_sha256: row.get(20)?,
        record_json: row.get(21)?,
        started_at_ms: row.get(22)?,
        finished_at_ms: row.get(23)?,
    })
}

fn query_review_check_results<P: rusqlite::Params>(
    connection: &Connection,
    suffix: &str,
    params: P,
    session: &ReviewSession,
) -> Result<Vec<ReviewCheckResult>, ControlError> {
    let query = format!(
        "SELECT session_id, request_id, candidate_sha, attempt_sequence,
                check_id, variant, environment_id, expected_exit_code,
                actual_exit_code, outcome, termination, process_tree_may_outlive,
                stdout_sha256, stderr_sha256, stdout_bytes, stderr_bytes,
                stdout_truncated, stderr_truncated, stdout_artifact_ref,
                stderr_artifact_ref, result_sha256, result_json,
                started_at_ms, finished_at_ms
         FROM review_check_results {suffix}"
    );
    let mut statement = connection.prepare(&query).map_err(ControlError::database)?;
    let rows = statement
        .query_map(params, stored_review_check_result_row)
        .map_err(ControlError::database)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(ControlError::database)?;
    rows.into_iter()
        .map(|row| {
            let result = validate_stored_review_check_result(&row, session)?;
            let environment = review_environment_for_id(
                connection,
                session.workspace_id.as_str(),
                result.environment_id.as_str(),
                session,
            )?
            .ok_or_else(|| {
                ControlError::not_found("review environment", result.environment_id.as_str())
            })?;
            session
                .validate_execution_pair(&result, &environment.environment)
                .map_err(invalid_review_check_result)?;
            Ok(result)
        })
        .collect()
}

fn insert_review_check_result(
    connection: &Connection,
    workspace_id: &str,
    result: &ReviewCheckResult,
    result_sha256: &str,
    result_json: &str,
) -> Result<usize, ControlError> {
    connection
        .execute(
            "INSERT OR IGNORE INTO review_check_results
             (workspace_id, session_id, request_id, candidate_sha,
              attempt_sequence, check_id, variant, environment_id,
              expected_exit_code, actual_exit_code, outcome, termination,
              process_tree_may_outlive, stdout_sha256, stderr_sha256,
              stdout_bytes, stderr_bytes, stdout_truncated, stderr_truncated,
              stdout_artifact_ref, stderr_artifact_ref, result_sha256,
              result_json, started_at_ms, finished_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                     ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21,
                     ?22, ?23, ?24, ?25)",
            params![
                workspace_id,
                result.session_id.as_str(),
                result.request_id.as_str(),
                result.candidate_sha.as_str(),
                to_i64(result.attempt_sequence)?,
                result.check_id.as_str(),
                review_execution_variant_text(result.variant),
                result.environment_id.as_str(),
                i64::from(result.expected_exit_code),
                result.actual_exit_code.map(i64::from),
                review_check_outcome_text(result.outcome),
                review_check_termination_text(result.termination),
                result.process_tree_may_outlive,
                result.stdout.digest.as_str(),
                result.stderr.digest.as_str(),
                to_i64(result.stdout.byte_count)?,
                to_i64(result.stderr.byte_count)?,
                result.stdout.truncated,
                result.stderr.truncated,
                result.stdout.reference,
                result.stderr.reference,
                result_sha256,
                result_json,
                to_i64(result.started_at.0)?,
                to_i64(result.finished_at.0)?,
            ],
        )
        .map_err(ControlError::database)
}

fn review_check_result_for_key(
    connection: &Connection,
    workspace_id: &str,
    result: &ReviewCheckResult,
    session: &ReviewSession,
) -> Result<Option<ReviewCheckResult>, ControlError> {
    query_review_check_results(
        connection,
        "WHERE workspace_id = ?1 AND session_id = ?2 AND attempt_sequence = ?3
           AND variant = ?4 AND check_id = ?5 LIMIT 1",
        params![
            workspace_id,
            result.session_id.as_str(),
            to_i64(result.attempt_sequence)?,
            review_execution_variant_text(result.variant),
            result.check_id.as_str(),
        ],
        session,
    )
    .map(|mut results| results.pop())
}

fn validate_stored_review_check_result(
    row: &StoredReviewCheckResultRow,
    session: &ReviewSession,
) -> Result<ReviewCheckResult, ControlError> {
    verify_digest(
        "review check result",
        &row.record_sha256,
        row.record_json.as_bytes(),
    )?;
    let result: ReviewCheckResult =
        serde_json::from_str(&row.record_json).map_err(ControlError::database)?;
    session
        .validate_check_result(&result)
        .map_err(invalid_review_check_result)?;
    if result.session_id.as_str() != row.session_id
        || result.request_id.as_str() != row.request_id
        || result.candidate_sha.as_str() != row.candidate_sha
        || result.attempt_sequence
            != u64::try_from(row.attempt_sequence).map_err(ControlError::database)?
        || result.check_id.as_str() != row.check_id
        || review_execution_variant_text(result.variant) != row.variant
        || result.environment_id.as_str() != row.environment_id
        || i64::from(result.expected_exit_code) != row.expected_exit_code
        || result.actual_exit_code.map(i64::from) != row.actual_exit_code
        || review_check_outcome_text(result.outcome) != row.outcome
        || review_check_termination_text(result.termination) != row.termination
        || result.process_tree_may_outlive != row.process_tree_may_outlive
        || result.stdout.digest.as_str() != row.stdout_sha256
        || result.stderr.digest.as_str() != row.stderr_sha256
        || result.stdout.byte_count
            != u64::try_from(row.stdout_bytes).map_err(ControlError::database)?
        || result.stderr.byte_count
            != u64::try_from(row.stderr_bytes).map_err(ControlError::database)?
        || result.stdout.truncated != row.stdout_truncated
        || result.stderr.truncated != row.stderr_truncated
        || result.stdout.reference != row.stdout_artifact_ref
        || result.stderr.reference != row.stderr_artifact_ref
        || result.started_at.0
            != u64::try_from(row.started_at_ms).map_err(ControlError::database)?
        || result.finished_at.0
            != u64::try_from(row.finished_at_ms).map_err(ControlError::database)?
    {
        return Err(ControlError::new(
            "review_check_result_index_mismatch",
            format!(
                "review check result `{}` conflicts with its durable identity columns",
                row.check_id
            ),
        ));
    }
    Ok(result)
}

fn review_session_for_id(
    connection: &Connection,
    workspace_id: &str,
    session_id: &ReviewSessionId,
    store: &StateStore,
) -> Result<Option<StoredReviewSession>, ControlError> {
    connection
        .query_row(
            "SELECT session_id, begin_operation_id, request_id, candidate_sha,
                    tree_sha, checkout_path, plan_sha256, record_sha256,
                    record_json, policy_revision, status, recovery, last_error,
                    created_at_ms, updated_at_ms
             FROM review_sessions WHERE workspace_id = ?1 AND session_id = ?2",
            params![workspace_id, session_id.as_str()],
            stored_review_session_row,
        )
        .optional()
        .map_err(ControlError::database)?
        .map(|row| validate_stored_review_session(row, workspace_id, store))
        .transpose()
}

fn review_session_for_operation(
    connection: &Connection,
    workspace_id: &str,
    operation_id: &str,
    store: &StateStore,
) -> Result<Option<StoredReviewSession>, ControlError> {
    connection
        .query_row(
            "SELECT session_id, begin_operation_id, request_id, candidate_sha,
                    tree_sha, checkout_path, plan_sha256, record_sha256,
                    record_json, policy_revision, status, recovery, last_error,
                    created_at_ms, updated_at_ms
             FROM review_sessions
             WHERE workspace_id = ?1 AND begin_operation_id = ?2",
            params![workspace_id, operation_id],
            stored_review_session_row,
        )
        .optional()
        .map_err(ControlError::database)?
        .map(|row| validate_stored_review_session(row, workspace_id, store))
        .transpose()
}

fn resolve_existing_review_begin(
    connection: &Connection,
    workspace_id: &str,
    operation_id: &str,
    proposed: &ReviewSession,
    store: &StateStore,
) -> Result<Option<StoredReviewSession>, ControlError> {
    if let Some(existing) =
        review_session_for_operation(connection, workspace_id, operation_id, store)?
    {
        return if same_review_session_begin(&existing.session, proposed) {
            Ok(Some(existing))
        } else {
            Err(review_session_conflict(
                &proposed.session_id,
                "begin operation ID was reused with different immutable review input",
            ))
        };
    }
    let existing = review_session_for_candidate_on(
        connection,
        workspace_id,
        &proposed.request_id,
        &proposed.tree.candidate_sha,
        store,
    )?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    if same_review_session_begin(&existing.session, proposed) {
        Ok(Some(existing))
    } else {
        Err(ControlError::new(
            "review_session_already_exists",
            format!(
                "candidate already belongs to review session `{}`",
                existing.session.session_id
            ),
        )
        .with_details(json!({
            "session_id": existing.session.session_id,
            "request_id": existing.session.request_id,
            "candidate_sha": existing.session.tree.candidate_sha,
        }))
        .with_hint("reuse the existing exact-candidate review session"))
    }
}

fn verify_review_begin_revision(
    connection: &Connection,
    workspace_id: &str,
    expected: u64,
    session: &ReviewSession,
) -> Result<(), ControlError> {
    let actual = connection
        .query_row(
            "SELECT revision FROM domain_state WHERE workspace_id = ?1",
            [workspace_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(ControlError::database)?;
    let actual = u64::try_from(actual).map_err(ControlError::database)?;
    if actual == expected {
        Ok(())
    } else {
        Err(ControlError::new(
            "review_session_revision_conflict",
            "domain state changed after the review candidate was validated",
        )
        .with_details(json!({
            "expected_revision": expected,
            "actual_revision": actual,
            "request_id": session.request_id,
            "candidate_sha": session.tree.candidate_sha,
        }))
        .with_hint("reload the request and current candidate, then retry review.begin"))
    }
}

fn insert_review_session(
    connection: &Connection,
    workspace_id: &str,
    operation_id: &str,
    session: &ReviewSession,
    record_sha256: &str,
    record_json: &str,
) -> Result<usize, ControlError> {
    connection
        .execute(
            "INSERT OR IGNORE INTO review_sessions
             (workspace_id, session_id, begin_operation_id, request_id,
              candidate_sha, tree_sha, checkout_path, plan_sha256,
              record_sha256, record_json, policy_revision, status, recovery,
              last_error, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                     ?12, ?13, NULL, ?14, ?15)",
            params![
                workspace_id,
                session.session_id.as_str(),
                operation_id,
                session.request_id.as_str(),
                session.tree.candidate_sha.as_str(),
                session.tree.tree_sha.as_str(),
                session.checkout_path,
                session.plan.identity.config_digest.as_str(),
                record_sha256,
                record_json,
                to_i64(session.plan.identity.policy_revision.get())?,
                review_session_status_text(session.state.status),
                review_recovery_state_text(session.state.recovery),
                to_i64(session.created_at.0)?,
                to_i64(session.updated_at.0)?,
            ],
        )
        .map_err(ControlError::database)
}

fn review_session_for_candidate_on(
    connection: &Connection,
    workspace_id: &str,
    request_id: &RequestId,
    candidate_sha: &GitSha,
    store: &StateStore,
) -> Result<Option<StoredReviewSession>, ControlError> {
    connection
        .query_row(
            "SELECT session_id, begin_operation_id, request_id, candidate_sha,
                    tree_sha, checkout_path, plan_sha256, record_sha256,
                    record_json, policy_revision, status, recovery, last_error,
                    created_at_ms, updated_at_ms
             FROM review_sessions
             WHERE workspace_id = ?1 AND request_id = ?2 AND candidate_sha = ?3",
            params![workspace_id, request_id.as_str(), candidate_sha.as_str()],
            stored_review_session_row,
        )
        .optional()
        .map_err(ControlError::database)?
        .map(|row| validate_stored_review_session(row, workspace_id, store))
        .transpose()
}

fn validate_stored_review_session(
    row: StoredReviewSessionRow,
    workspace_id: &str,
    store: &StateStore,
) -> Result<StoredReviewSession, ControlError> {
    verify_digest(
        "review session record",
        &row.record_sha256,
        row.record_json.as_bytes(),
    )?;
    let session: ReviewSession =
        serde_json::from_str(&row.record_json).map_err(ControlError::database)?;
    validate_review_session(store, &session)?;
    let created_at_ms = u64::try_from(row.created_at_ms).map_err(ControlError::database)?;
    let updated_at_ms = u64::try_from(row.updated_at_ms).map_err(ControlError::database)?;
    if session.workspace_id.as_str() != workspace_id
        || session.session_id.as_str() != row.session_id
        || session.request_id.as_str() != row.request_id
        || session.tree.candidate_sha.as_str() != row.candidate_sha
        || session.tree.tree_sha.as_str() != row.tree_sha
        || session.checkout_path != row.checkout_path
        || session.plan.identity.config_digest.as_str() != row.plan_sha256
        || session.plan.identity.policy_revision.get()
            != u64::try_from(row.policy_revision).map_err(ControlError::database)?
        || review_session_status_text(session.state.status) != row.status
        || review_recovery_state_text(session.state.recovery) != row.recovery
        || session.created_at.0 != created_at_ms
        || session.updated_at.0 != updated_at_ms
    {
        return Err(ControlError::new(
            "review_session_index_mismatch",
            format!(
                "review session `{}` conflicts with its durable identity columns",
                row.session_id
            ),
        ));
    }
    if row.begin_operation_id.is_empty() {
        return Err(ControlError::new(
            "invalid_review_session",
            format!(
                "review session `{}` has no begin operation ID",
                row.session_id
            ),
        ));
    }
    validate_review_last_error(row.last_error.as_deref())?;
    Ok(StoredReviewSession {
        begin_operation_id: row.begin_operation_id,
        session,
        last_error: row.last_error,
    })
}

fn validate_review_session(
    store: &StateStore,
    session: &ReviewSession,
) -> Result<(), ControlError> {
    session.validate().map_err(invalid_review_session)?;
    validate_review_plan_digests(&session.plan)?;
    if session.workspace_id.as_str() != store.workspace_id {
        return Err(ControlError::new(
            "review_session_workspace_mismatch",
            format!(
                "review session `{}` belongs to a different workspace",
                session.session_id
            ),
        ));
    }
    validate_review_checkout_path(
        &store.review_checkout_root(),
        Path::new(&session.checkout_path),
    )
}

fn validate_review_plan_digests(plan: &ReviewPlan) -> Result<(), ControlError> {
    validate_review_json_digest(
        "declared environment",
        &plan.declared_environment,
        &plan.declared_environment_digest,
    )?;
    let digest_input = json!({
        "checks": plan.checks,
        "tool_version_probes": plan.tool_version_probes,
        "declared_environment": plan.declared_environment,
        "optional_binaries": plan.optional_binaries,
    });
    validate_review_json_digest(
        "review plan configuration",
        &digest_input,
        &plan.identity.config_digest,
    )
}

fn validate_review_environment_digest(
    environment: &ReviewEnvironmentRecord,
) -> Result<(), ControlError> {
    validate_review_json_digest(
        "execution environment",
        &environment.execution_environment,
        &environment.execution_environment_digest,
    )
}

fn validate_review_json_digest(
    label: &str,
    value: &impl Serialize,
    expected: &PayloadDigest,
) -> Result<(), ControlError> {
    let canonical = canonical_json(value)?;
    let actual = sha256_hex(canonical.as_bytes());
    if actual == expected.as_str() {
        Ok(())
    } else {
        Err(ControlError::new(
            "review_content_digest_mismatch",
            format!("{label} does not match its canonical SHA-256 digest"),
        )
        .with_details(json!({
            "expected": expected,
            "actual": actual,
        })))
    }
}

fn validate_review_path_digest(
    environment: &ReviewEnvironmentRecord,
    path_digest: &PayloadDigest,
) -> Result<(), ControlError> {
    let recorded = environment
        .execution_environment
        .iter()
        .find_map(|(key, value)| (key.as_str() == "path_digest").then_some(value));
    if recorded.is_some_and(|recorded| recorded == path_digest.as_str()) {
        Ok(())
    } else {
        Err(ControlError::new(
            "review_environment_path_mismatch",
            format!(
                "review environment `{}` does not bind its exact PATH digest",
                environment.environment_id
            ),
        ))
    }
}

fn validate_review_last_error(last_error: Option<&str>) -> Result<(), ControlError> {
    if last_error.is_some_and(|error| {
        error.trim().is_empty()
            || error.chars().count() > 4_096
            || error.chars().any(char::is_control)
    }) {
        Err(ControlError::new(
            "invalid_review_session",
            "review session error text must be non-empty printable text of at most 4096 characters",
        ))
    } else {
        Ok(())
    }
}

fn same_review_session_begin(existing: &ReviewSession, proposed: &ReviewSession) -> bool {
    existing.session_id == proposed.session_id
        && existing.workspace_id == proposed.workspace_id
        && existing.request_id == proposed.request_id
        && existing.tree == proposed.tree
        && existing.checkout_path == proposed.checkout_path
        && existing.plan == proposed.plan
        && existing.created_at == proposed.created_at
}

fn same_review_attempt_identity(
    running: &ReviewVerificationAttempt,
    terminal: &ReviewVerificationAttempt,
) -> bool {
    running.workspace_id == terminal.workspace_id
        && running.session_id == terminal.session_id
        && running.request_id == terminal.request_id
        && running.candidate_sha == terminal.candidate_sha
        && running.attempt_sequence == terminal.attempt_sequence
        && running.plan == terminal.plan
        && running.started_at == terminal.started_at
}

fn review_session_conflict(session_id: &ReviewSessionId, message: &str) -> ControlError {
    ControlError::new(
        "review_session_conflict",
        format!("review session `{session_id}` conflicts: {message}"),
    )
}

fn invalid_review_session(error: impl Display) -> ControlError {
    ControlError::new("invalid_review_session", error.to_string())
}

fn invalid_review_attempt(error: impl Display) -> ControlError {
    ControlError::new("invalid_review_attempt", error.to_string())
}

fn invalid_review_check_result(error: impl Display) -> ControlError {
    ControlError::new("invalid_review_check_result", error.to_string())
}

fn invalid_review_environment(error: impl Display) -> ControlError {
    ControlError::new("invalid_review_environment", error.to_string())
}

fn review_attempt_conflict(attempt: &ReviewVerificationAttempt, message: &str) -> ControlError {
    ControlError::new(
        "review_attempt_conflict",
        format!(
            "review attempt {} record `{}` conflicts: {message}",
            attempt.attempt_sequence, attempt.record_id
        ),
    )
}

fn review_check_result_conflict(result: &ReviewCheckResult) -> ControlError {
    ControlError::new(
        "review_check_result_conflict",
        format!(
            "review check `{}` attempt {} variant `{}` already has different immutable content",
            result.check_id,
            result.attempt_sequence,
            review_execution_variant_text(result.variant)
        ),
    )
}

fn review_environment_conflict(
    environment: &ReviewEnvironmentRecord,
    message: &str,
) -> ControlError {
    ControlError::new(
        "review_environment_conflict",
        format!(
            "review environment `{}` conflicts: {message}",
            environment.environment_id
        ),
    )
}

const fn review_attempt_status_text(status: ReviewAttemptStatus) -> &'static str {
    match status {
        ReviewAttemptStatus::Running => "running",
        ReviewAttemptStatus::Passed => "passed",
        ReviewAttemptStatus::Failed => "failed",
        ReviewAttemptStatus::Interrupted => "interrupted",
    }
}

const fn review_execution_variant_text(variant: ReviewExecutionVariant) -> &'static str {
    match variant {
        ReviewExecutionVariant::Normal => "normal",
        ReviewExecutionVariant::RequiredAbsent => "required_absent",
    }
}

const fn review_check_outcome_text(outcome: ReviewCheckOutcome) -> &'static str {
    match outcome {
        ReviewCheckOutcome::Passed => "passed",
        ReviewCheckOutcome::Failed => "failed",
        ReviewCheckOutcome::ExecutionError => "execution_error",
    }
}

const fn review_check_termination_text(termination: ReviewCheckTermination) -> &'static str {
    match termination {
        ReviewCheckTermination::Exited => "exited",
        ReviewCheckTermination::Signaled => "signaled",
        ReviewCheckTermination::TimedOut => "timed_out",
        ReviewCheckTermination::OutputLimitExceeded => "output_limit_exceeded",
        ReviewCheckTermination::OutputCaptureIncomplete => "output_capture_incomplete",
    }
}

const fn review_process_containment_text(containment: ReviewProcessContainment) -> &'static str {
    match containment {
        ReviewProcessContainment::PidNamespaceParentDeath => "pid_namespace_parent_death",
        ReviewProcessContainment::ProcessGroupOnly => "process_group_only",
        ReviewProcessContainment::None => "none",
    }
}

const fn review_session_status_text(status: ReviewSessionStatus) -> &'static str {
    match status {
        ReviewSessionStatus::Preparing => "preparing",
        ReviewSessionStatus::Ready => "ready",
        ReviewSessionStatus::Invalid => "invalid",
    }
}

const fn review_recovery_state_text(recovery: ReviewRecoveryState) -> &'static str {
    match recovery {
        ReviewRecoveryState::NotRequired => "not_required",
        ReviewRecoveryState::ResumeRequired => "resume_required",
        ReviewRecoveryState::RecreateRequired => "recreate_required",
    }
}

fn persist_bulk_and_archive_history(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    snapshot: &mut DomainSnapshot,
    pending_bulk: &[PendingBulkContent],
    revision: u64,
    now_ms: u64,
) -> Result<(), ControlError> {
    for pending in pending_bulk {
        let delivery = snapshot
            .deliveries
            .iter()
            .find(|delivery| delivery.envelope.message_id == pending.message_id);
        persist_message_body(transaction, workspace_id, pending, delivery, now_ms)?;
    }
    validate_compact_bulk_references(transaction, workspace_id, snapshot)?;
    let commit_entries =
        archive_compact_history(transaction, workspace_id, snapshot, revision, now_ms)?;
    archive_terminal_presentation_metadata(transaction, workspace_id, snapshot, now_ms)?;
    verify_hot_archive_disjointness(transaction, workspace_id, snapshot)?;
    append_archive_commit(
        transaction,
        workspace_id,
        snapshot,
        commit_entries,
        revision,
        now_ms,
    )
}

#[allow(clippy::too_many_lines)]
fn validate_compact_bulk_references(
    connection: &Connection,
    workspace_id: &str,
    snapshot: &DomainSnapshot,
) -> Result<(), ControlError> {
    let mut messages = BTreeMap::new();
    for delivery in &snapshot.deliveries {
        let message = hydrate_message_body(
            connection,
            workspace_id,
            delivery.envelope.message_id.as_str(),
            Some(delivery.payload_digest.as_str()),
        )?
        .ok_or_else(|| missing_bulk("message_bodies", delivery.envelope.message_id.as_str()))?;
        if message.kind() != delivery.message_kind || message.kind() != delivery.causal.kind() {
            return Err(ControlError::new(
                "compact_message_kind_mismatch",
                format!(
                    "compact delivery `{}` conflicts with its immutable message kind",
                    delivery.envelope.message_id
                ),
            ));
        }
        validate_message_owned_bulk(
            connection,
            workspace_id,
            delivery.envelope.request_id.as_ref(),
            &message,
        )?;
        messages.insert(delivery.envelope.message_id.clone(), message);
    }
    for request in &snapshot.requests {
        let specification = messages
            .get(&request.specification.message_id)
            .ok_or_else(|| {
                ControlError::new(
                    "request_specification_delivery_missing",
                    format!(
                        "request `{}` references missing message `{}`",
                        request.request_id, request.specification.message_id
                    ),
                )
            })?;
        let Message::ImplementationRequest(specification) = specification else {
            return Err(ControlError::new(
                "request_specification_body_mismatch",
                format!(
                    "request `{}` specification message has a different payload kind",
                    request.request_id
                ),
            ));
        };
        let delivery = snapshot
            .deliveries
            .iter()
            .find(|delivery| delivery.envelope.message_id == request.specification.message_id)
            .expect("message map was built from deliveries");
        if delivery.payload_digest != request.specification.payload_digest
            || specification.base_sha != request.specification.base_sha
            || delivery.envelope.request_id.as_ref() != Some(&request.request_id)
        {
            return Err(ControlError::new(
                "request_specification_reference_mismatch",
                format!(
                    "request `{}` compact specification reference is inconsistent",
                    request.request_id
                ),
            ));
        }
        if let Some(decision_ref) = &request.decision {
            let decision = messages.get(&decision_ref.message_id).ok_or_else(|| {
                ControlError::new(
                    "review_decision_delivery_missing",
                    format!(
                        "request `{}` references missing decision message `{}`",
                        request.request_id, decision_ref.message_id
                    ),
                )
            })?;
            let Message::ReviewDecision(decision) = decision else {
                return Err(ControlError::new(
                    "review_decision_body_mismatch",
                    format!(
                        "request `{}` decision message has a different payload kind",
                        request.request_id
                    ),
                ));
            };
            let delivery = snapshot
                .deliveries
                .iter()
                .find(|delivery| delivery.envelope.message_id == decision_ref.message_id)
                .expect("message map was built from deliveries");
            if delivery.payload_digest != decision_ref.payload_digest
                || decision.decision_id != decision_ref.decision_id
                || decision.candidate != decision_ref.candidate
                || decision.verdict != decision_ref.verdict
                || decision.reviewer != decision_ref.reviewer
                || decision.policy_revision != decision_ref.policy_revision
            {
                return Err(ControlError::new(
                    "review_decision_reference_mismatch",
                    format!(
                        "request `{}` compact decision reference is inconsistent",
                        request.request_id
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_message_owned_bulk(
    connection: &Connection,
    workspace_id: &str,
    request_id: Option<&RequestId>,
    message: &Message,
) -> Result<(), ControlError> {
    if let Message::ImplementationRequest(specification) = message {
        let request_id = request_id.ok_or_else(|| {
            ControlError::new(
                "request_specification_context_missing",
                "implementation request immutable body has no request context",
            )
        })?;
        let stored: ImplementationRequest = read_verified_json(
            connection,
            "request_specifications",
            "request_id",
            request_id.as_str(),
            "content_sha256",
            "specification_json",
            workspace_id,
        )?
        .ok_or_else(|| missing_bulk("request_specifications", request_id.as_str()))?;
        if stored != *specification {
            return Err(immutable_conflict(
                "request_specifications",
                request_id.as_str(),
            ));
        }
    }
    if let Message::ReviewDecision(decision) = message {
        let stored = read_verified_raw(
            connection,
            "decision_rationales",
            "decision_id",
            decision.decision_id.as_str(),
            "content_sha256",
            "rationale",
            workspace_id,
            None,
        )?
        .ok_or_else(|| missing_bulk("decision_rationales", decision.decision_id.as_str()))?;
        if stored != decision.rationale {
            return Err(immutable_conflict(
                "decision_rationales",
                decision.decision_id.as_str(),
            ));
        }
    }
    let value = serde_json::to_value(message).map_err(ControlError::database)?;
    validate_evidence_rows(connection, workspace_id, &value)
}

fn validate_evidence_rows(
    connection: &Connection,
    workspace_id: &str,
    value: &Value,
) -> Result<(), ControlError> {
    match value {
        Value::Array(values) => {
            for value in values {
                validate_evidence_rows(connection, workspace_id, value)?;
            }
        }
        Value::Object(object) => {
            if let Some(Value::Array(evidence)) = object.get("evidence") {
                for item in evidence {
                    let typed: Evidence =
                        serde_json::from_value(item.clone()).map_err(ControlError::database)?;
                    let stored: Evidence = read_verified_json(
                        connection,
                        "evidence_records",
                        "evidence_id",
                        typed.evidence_id.as_str(),
                        "content_sha256",
                        "evidence_json",
                        workspace_id,
                    )?
                    .ok_or_else(|| missing_bulk("evidence_records", typed.evidence_id.as_str()))?;
                    if stored != typed {
                        return Err(immutable_conflict(
                            "evidence_records",
                            typed.evidence_id.as_str(),
                        ));
                    }
                }
            }
            for child in object.values() {
                validate_evidence_rows(connection, workspace_id, child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn archive_terminal_presentation_metadata(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    snapshot: &DomainSnapshot,
    now_ms: u64,
) -> Result<(), ControlError> {
    for actor in snapshot
        .actors
        .iter()
        .filter(|actor| actor.status == ActorStatus::Stopped)
    {
        let presentation = transaction
            .query_row(
                "SELECT presentation.actor_id, presentation.team_id,
                        presentation.session_label, presentation.desired_label,
                        presentation.tab_sequence, presentation.pane_index,
                        presentation.applied_label, presentation.sync_state,
                        presentation.last_error, presentation.updated_at_ms
                 FROM session_presentations AS presentation
                 JOIN sessions AS session
                   ON session.workspace_id = presentation.workspace_id
                  AND session.actor_id = presentation.actor_id
                 WHERE presentation.workspace_id = ?1 AND presentation.actor_id = ?2
                   AND session.status = 'stopped'",
                params![workspace_id, actor.actor_id.as_str()],
                presentation_from_row,
            )
            .optional()
            .map_err(ControlError::database)?;
        let Some(presentation) = presentation else {
            continue;
        };
        let presentation_json =
            serde_json::to_string(&presentation).map_err(ControlError::database)?;
        let digest = sha256_hex(presentation_json.as_bytes());
        transaction
            .execute(
                "INSERT OR IGNORE INTO session_presentation_archive
                 (workspace_id, actor_id, actor_epoch, team_id, content_sha256,
                  presentation_json, archived_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    workspace_id,
                    actor.actor_id.as_str(),
                    to_i64(actor.epoch.get())?,
                    presentation.team_id,
                    digest,
                    presentation_json,
                    to_i64(now_ms)?
                ],
            )
            .map_err(ControlError::database)?;
        let existing: (String, String) = transaction
            .query_row(
                "SELECT content_sha256, presentation_json
                 FROM session_presentation_archive
                 WHERE workspace_id = ?1 AND actor_id = ?2 AND actor_epoch = ?3",
                params![
                    workspace_id,
                    actor.actor_id.as_str(),
                    to_i64(actor.epoch.get())?
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(ControlError::database)?;
        if existing != (digest, presentation_json) {
            return Err(immutable_conflict(
                "session_presentation_archive",
                actor.actor_id.as_str(),
            ));
        }
        transaction
            .execute(
                "DELETE FROM session_presentations
                 WHERE workspace_id = ?1 AND actor_id = ?2",
                params![workspace_id, actor.actor_id.as_str()],
            )
            .map_err(ControlError::database)?;
    }

    for team in snapshot
        .teams
        .iter()
        .filter(|team| matches!(team.status, TeamStatus::Closed | TeamStatus::Retired))
    {
        let metadata = transaction
            .query_row(
                "SELECT purpose, updated_at_ms FROM team_metadata
                 WHERE workspace_id = ?1 AND team_id = ?2",
                params![workspace_id, team.team_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(ControlError::database)?;
        let Some((purpose, updated_at_ms)) = metadata else {
            continue;
        };
        transaction
            .execute(
                "INSERT OR IGNORE INTO team_metadata_archive
                 (workspace_id, team_id, purpose, updated_at_ms, archived_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    workspace_id,
                    team.team_id.as_str(),
                    purpose,
                    updated_at_ms,
                    to_i64(now_ms)?
                ],
            )
            .map_err(ControlError::database)?;
        let existing: (String, i64) = transaction
            .query_row(
                "SELECT purpose, updated_at_ms FROM team_metadata_archive
                 WHERE workspace_id = ?1 AND team_id = ?2",
                params![workspace_id, team.team_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(ControlError::database)?;
        if existing != (purpose, updated_at_ms) {
            return Err(immutable_conflict(
                "team_metadata_archive",
                team.team_id.as_str(),
            ));
        }
        transaction
            .execute(
                "DELETE FROM team_metadata WHERE workspace_id = ?1 AND team_id = ?2",
                params![workspace_id, team.team_id.as_str()],
            )
            .map_err(ControlError::database)?;
    }
    Ok(())
}

fn persist_message_body(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    pending: &PendingBulkContent,
    delivery: Option<&DeliverySnapshot>,
    now_ms: u64,
) -> Result<(), ControlError> {
    let full_json = serde_json::to_string(&pending.message).map_err(ControlError::database)?;
    verify_digest(
        "pending message body",
        pending.payload_digest.as_str(),
        full_json.as_bytes(),
    )?;
    let mut body = serde_json::to_value(&pending.message).map_err(ControlError::database)?;

    if let Message::ImplementationRequest(specification) = &pending.message {
        let request_id = delivery
            .and_then(|delivery| delivery.envelope.request_id.as_ref())
            .ok_or_else(|| {
                ControlError::new(
                    "bulk_content_missing_request",
                    format!(
                        "implementation request message `{}` has no compact request context",
                        pending.message_id
                    ),
                )
            })?;
        let specification_json =
            serde_json::to_string(specification).map_err(ControlError::database)?;
        let specification_digest = sha256_hex(specification_json.as_bytes());
        insert_immutable_row(
            transaction,
            "request_specifications",
            "request_id",
            request_id.as_str(),
            "content_sha256",
            &specification_digest,
            "specification_json",
            &specification_json,
            workspace_id,
            now_ms,
        )?;
        body["payload"] = bulk_marker(
            "request_specification",
            request_id.as_str(),
            &specification_digest,
        );
    }

    if let Message::ReviewDecision(decision) = &pending.message {
        let delivery = delivery.ok_or_else(|| {
            ControlError::new(
                "bulk_content_missing_delivery",
                format!(
                    "review decision message `{}` has no compact delivery",
                    pending.message_id
                ),
            )
        })?;
        let request_id = delivery.envelope.request_id.as_ref().ok_or_else(|| {
            ControlError::new(
                "bulk_content_missing_request",
                format!(
                    "review decision message `{}` has no request context",
                    pending.message_id
                ),
            )
        })?;
        let rationale_digest = sha256_hex(decision.rationale.as_bytes());
        insert_decision_rationale(
            transaction,
            workspace_id,
            decision.decision_id.as_str(),
            pending.message_id.as_str(),
            request_id.as_str(),
            decision.candidate.sha.as_str(),
            decision.reviewer.actor_id.as_str(),
            decision.reviewer.actor_epoch.get(),
            delivery.envelope.sent_at.0,
            &rationale_digest,
            &decision.rationale,
            now_ms,
        )?;
        body["payload"]["rationale"] = bulk_marker(
            "decision_rationale",
            decision.decision_id.as_str(),
            &rationale_digest,
        );
    }

    externalize_evidence(transaction, workspace_id, &mut body, now_ms)?;
    let body_json = serde_json::to_string(&body).map_err(ControlError::database)?;
    let kind_json = serde_json::to_string(&pending.message.kind())
        .map_err(ControlError::database)?
        .trim_matches('"')
        .to_owned();
    insert_immutable_message(
        transaction,
        workspace_id,
        pending.message_id.as_str(),
        &kind_json,
        pending.payload_digest.as_str(),
        &body_json,
        now_ms,
    )
}

fn externalize_evidence(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    value: &mut Value,
    now_ms: u64,
) -> Result<(), ControlError> {
    match value {
        Value::Array(values) => {
            for value in values {
                externalize_evidence(transaction, workspace_id, value, now_ms)?;
            }
        }
        Value::Object(object) => {
            if let Some(Value::Array(evidence)) = object.get_mut("evidence") {
                for item in evidence {
                    let typed: Evidence =
                        serde_json::from_value(item.clone()).map_err(ControlError::database)?;
                    let evidence_json =
                        serde_json::to_string(&typed).map_err(ControlError::database)?;
                    let evidence_digest = sha256_hex(evidence_json.as_bytes());
                    insert_immutable_row(
                        transaction,
                        "evidence_records",
                        "evidence_id",
                        typed.evidence_id.as_str(),
                        "content_sha256",
                        &evidence_digest,
                        "evidence_json",
                        &evidence_json,
                        workspace_id,
                        now_ms,
                    )?;
                    *item = bulk_marker("evidence", typed.evidence_id.as_str(), &evidence_digest);
                }
            }
            for child in object.values_mut() {
                externalize_evidence(transaction, workspace_id, child, now_ms)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn bulk_marker(kind: &str, id: &str, digest: &str) -> Value {
    json!({ "$agsv_bulk_ref": kind, "id": id, "sha256": digest })
}

#[allow(clippy::too_many_arguments)]
fn insert_immutable_row(
    transaction: &rusqlite::Transaction<'_>,
    table: &str,
    id_column: &str,
    id: &str,
    digest_column: &str,
    digest: &str,
    content_column: &str,
    content: &str,
    workspace_id: &str,
    now_ms: u64,
) -> Result<(), ControlError> {
    let insert = format!(
        "INSERT OR IGNORE INTO {table}
         (workspace_id, {id_column}, {digest_column}, {content_column}, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)"
    );
    transaction
        .execute(
            &insert,
            params![workspace_id, id, digest, content, to_i64(now_ms)?],
        )
        .map_err(ControlError::database)?;
    let select = format!(
        "SELECT {digest_column}, {content_column} FROM {table}
         WHERE workspace_id = ?1 AND {id_column} = ?2"
    );
    let existing: (String, String) = transaction
        .query_row(&select, params![workspace_id, id], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(ControlError::database)?;
    if existing != (digest.to_owned(), content.to_owned()) {
        return Err(immutable_conflict(table, id));
    }
    Ok(())
}

fn insert_immutable_message(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    message_id: &str,
    message_kind: &str,
    digest: &str,
    body_json: &str,
    now_ms: u64,
) -> Result<(), ControlError> {
    transaction
        .execute(
            "INSERT OR IGNORE INTO message_bodies
             (workspace_id, message_id, message_kind, content_sha256, body_json, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                workspace_id,
                message_id,
                message_kind,
                digest,
                body_json,
                to_i64(now_ms)?
            ],
        )
        .map_err(ControlError::database)?;
    let existing: (String, String, String) = transaction
        .query_row(
            "SELECT message_kind, content_sha256, body_json FROM message_bodies
             WHERE workspace_id = ?1 AND message_id = ?2",
            params![workspace_id, message_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(ControlError::database)?;
    if existing
        != (
            message_kind.to_owned(),
            digest.to_owned(),
            body_json.to_owned(),
        )
    {
        return Err(immutable_conflict("message_bodies", message_id));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_decision_rationale(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    decision_id: &str,
    message_id: &str,
    request_id: &str,
    candidate_sha: &str,
    reviewer_actor_id: &str,
    reviewer_actor_epoch: u64,
    decided_at_ms: u64,
    digest: &str,
    rationale: &str,
    now_ms: u64,
) -> Result<(), ControlError> {
    transaction
        .execute(
            "INSERT OR IGNORE INTO decision_rationales
             (workspace_id, decision_id, message_id, request_id, candidate_sha,
              reviewer_actor_id, reviewer_actor_epoch, decided_at_ms,
              content_sha256, rationale, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                workspace_id,
                decision_id,
                message_id,
                request_id,
                candidate_sha,
                reviewer_actor_id,
                to_i64(reviewer_actor_epoch)?,
                to_i64(decided_at_ms)?,
                digest,
                rationale,
                to_i64(now_ms)?
            ],
        )
        .map_err(ControlError::database)?;
    let existing: (String, String, String, String, i64, i64, String, String) = transaction
        .query_row(
            "SELECT message_id, request_id, candidate_sha, reviewer_actor_id,
                    reviewer_actor_epoch, decided_at_ms, content_sha256, rationale
             FROM decision_rationales WHERE workspace_id = ?1 AND decision_id = ?2",
            params![workspace_id, decision_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .map_err(ControlError::database)?;
    if existing
        != (
            message_id.to_owned(),
            request_id.to_owned(),
            candidate_sha.to_owned(),
            reviewer_actor_id.to_owned(),
            to_i64(reviewer_actor_epoch)?,
            to_i64(decided_at_ms)?,
            digest.to_owned(),
            rationale.to_owned(),
        )
    {
        return Err(immutable_conflict("decision_rationales", decision_id));
    }
    Ok(())
}

fn immutable_conflict(table: &str, id: &str) -> ControlError {
    ControlError::new(
        "immutable_content_conflict",
        format!("immutable {table} ID `{id}` was reused with different content"),
    )
}

#[allow(clippy::too_many_lines)]
fn archive_compact_history(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    snapshot: &mut DomainSnapshot,
    revision: u64,
    now_ms: u64,
) -> Result<Vec<ArchiveCommitEntry>, ControlError> {
    let archivable_requests: BTreeSet<RequestId> = snapshot
        .requests
        .iter()
        .filter(|request| request.status.is_terminal())
        .filter(|request| {
            !snapshot
                .pending_handoffs
                .iter()
                .any(|handoff| handoff.offer.request_id == request.request_id)
        })
        .filter(|request| {
            let mut deliveries = snapshot.deliveries.iter().filter(|delivery| {
                delivery.envelope.request_id.as_ref() == Some(&request.request_id)
            });
            deliveries.clone().next().is_some() && deliveries.all(|delivery| delivery.retired)
        })
        .map(|request| request.request_id.clone())
        .collect();
    let consultation_requests = snapshot
        .deliveries
        .iter()
        .filter(|delivery| delivery.retired)
        .filter_map(|delivery| match &delivery.causal {
            CausalMessage::ConsultationRequest {
                consultation_id, ..
            } => Some(consultation_id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let consultation_responses = snapshot
        .deliveries
        .iter()
        .filter(|delivery| delivery.retired)
        .filter_map(|delivery| match &delivery.causal {
            CausalMessage::ConsultationResponse {
                consultation_id, ..
            } => Some(consultation_id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let completed_consultations = consultation_requests
        .intersection(&consultation_responses)
        .cloned()
        .collect::<BTreeSet<_>>();
    let archived_message_ids: BTreeSet<MessageId> = snapshot
        .deliveries
        .iter()
        .filter(|delivery| {
            if !delivery.retired {
                return false;
            }
            if let Some(request_id) = &delivery.envelope.request_id {
                return archivable_requests.contains(request_id);
            }
            match &delivery.causal {
                CausalMessage::ConsultationRequest {
                    consultation_id, ..
                }
                | CausalMessage::ConsultationResponse {
                    consultation_id, ..
                } => completed_consultations.contains(consultation_id),
                _ => true,
            }
        })
        .map(|delivery| delivery.envelope.message_id.clone())
        .collect();

    let mut commit_entries = Vec::new();
    for delivery in snapshot
        .deliveries
        .iter()
        .filter(|delivery| archived_message_ids.contains(&delivery.envelope.message_id))
    {
        commit_entries.push(insert_delivery_archive(
            transaction,
            workspace_id,
            delivery,
            revision,
            now_ms,
        )?);
    }

    let audit_digests = snapshot
        .audit_events
        .iter()
        .map(|event| Ok((event.sequence, canonical_digest(event)?)))
        .collect::<Result<BTreeMap<_, _>, ControlError>>()?;
    for event in &snapshot.audit_events {
        if archived_message_ids.contains(audit_message_id(event)) {
            let event_json = serde_json::to_string(event).map_err(ControlError::database)?;
            let digest = audit_digests
                .get(&event.sequence)
                .expect("audit digest was computed for every event");
            let previous_digest = if event.sequence == 1 {
                None
            } else if let Some(previous) = audit_digests.get(&(event.sequence - 1)) {
                Some(previous.clone())
            } else {
                transaction
                    .query_row(
                        "SELECT event_sha256 FROM protocol_audit_archive
                         WHERE workspace_id = ?1 AND sequence = ?2",
                        params![workspace_id, to_i64(event.sequence - 1)?],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(ControlError::database)?
                    .ok_or_else(|| {
                        ControlError::new(
                            "protocol_audit_predecessor_missing",
                            format!(
                                "protocol audit event {} has no global predecessor",
                                event.sequence
                            ),
                        )
                    })?
                    .into()
            };
            commit_entries.push(insert_protocol_audit_archive(
                transaction,
                workspace_id,
                event,
                digest,
                previous_digest.as_deref(),
                &event_json,
                now_ms,
            )?);
        }
    }

    for request in snapshot
        .requests
        .iter()
        .filter(|request| archivable_requests.contains(&request.request_id))
    {
        let run = snapshot
            .runs
            .iter()
            .find(|run| run.run_id == request.run_id)
            .ok_or_else(|| {
                ControlError::new(
                    "archive_missing_run",
                    format!(
                        "terminal request `{}` has no matching run",
                        request.request_id
                    ),
                )
            })?;
        commit_entries.push(insert_terminal_request_archive(
            transaction,
            workspace_id,
            request,
            run,
            revision,
            now_ms,
        )?);
    }

    snapshot
        .deliveries
        .retain(|delivery| !archived_message_ids.contains(&delivery.envelope.message_id));
    snapshot
        .audit_events
        .retain(|event| !archived_message_ids.contains(audit_message_id(event)));
    snapshot
        .requests
        .retain(|request| !archivable_requests.contains(&request.request_id));
    snapshot
        .runs
        .retain(|run| !archivable_requests.contains(&run.request_id));
    Ok(commit_entries)
}

type DeliveryArchiveIdentity = (
    String,
    i64,
    String,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    String,
);

fn insert_delivery_archive(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    delivery: &DeliverySnapshot,
    revision: u64,
    now_ms: u64,
) -> Result<ArchiveCommitEntry, ControlError> {
    let delivery_json = serde_json::to_string(delivery).map_err(ControlError::database)?;
    let digest = sha256_hex(delivery_json.as_bytes());
    let (decision_id, candidate_sha) = delivery_decision_candidate(delivery);
    let consultation_id = delivery_consultation_id(delivery);
    let message_kind = serde_json::to_string(&delivery.message_kind)
        .map_err(ControlError::database)?
        .trim_matches('"')
        .to_owned();
    transaction
        .execute(
            "INSERT INTO delivery_archive
             (workspace_id, message_id, request_id, sender_actor_id, sender_actor_epoch,
              message_kind, sent_at_ms, decision_id, candidate_sha, consultation_id,
              delivery_sha256, delivery_json, archived_revision, archived_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                workspace_id,
                delivery.envelope.message_id.as_str(),
                delivery.envelope.request_id.as_ref().map(RequestId::as_str),
                delivery.envelope.sender.actor_id.as_str(),
                to_i64(delivery.envelope.sender.actor_epoch.get())?,
                message_kind,
                to_i64(delivery.envelope.sent_at.0)?,
                decision_id,
                candidate_sha,
                consultation_id,
                digest,
                delivery_json,
                to_i64(revision)?,
                to_i64(now_ms)?
            ],
        )
        .map_err(ControlError::database)?;
    let existing: DeliveryArchiveIdentity = transaction
        .query_row(
            "SELECT sender_actor_id, sender_actor_epoch, message_kind, sent_at_ms,
                    decision_id, candidate_sha, consultation_id,
                    delivery_sha256, delivery_json
             FROM delivery_archive
             WHERE workspace_id = ?1 AND message_id = ?2",
            params![workspace_id, delivery.envelope.message_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .map_err(ControlError::database)?;
    if existing
        != (
            delivery.envelope.sender.actor_id.to_string(),
            to_i64(delivery.envelope.sender.actor_epoch.get())?,
            message_kind,
            to_i64(delivery.envelope.sent_at.0)?,
            decision_id.map(str::to_owned),
            candidate_sha.map(str::to_owned),
            consultation_id.map(str::to_owned),
            digest.clone(),
            delivery_json,
        )
    {
        return Err(immutable_conflict(
            "delivery_archive",
            delivery.envelope.message_id.as_str(),
        ));
    }
    Ok(ArchiveCommitEntry {
        kind: ARCHIVE_DELIVERY_KIND.to_owned(),
        key: delivery.envelope.message_id.to_string(),
        content_sha256: digest,
    })
}

fn delivery_decision_candidate(delivery: &DeliverySnapshot) -> (Option<&str>, Option<&str>) {
    match &delivery.causal {
        CausalMessage::CandidateReady { candidate } | CausalMessage::QaResult { candidate, .. } => {
            (None, Some(candidate.sha.as_str()))
        }
        CausalMessage::ReviewDecision(decision) => (
            Some(decision.decision_id.as_str()),
            Some(decision.candidate.sha.as_str()),
        ),
        CausalMessage::FixRequest {
            decision_id,
            candidate,
        }
        | CausalMessage::IntegrationComplete {
            decision_id,
            candidate,
        } => (Some(decision_id.as_str()), Some(candidate.sha.as_str())),
        CausalMessage::IntegrationAuthorization(authorization) => (
            Some(authorization.decision_id.as_str()),
            Some(authorization.candidate.sha.as_str()),
        ),
        _ => (None, None),
    }
}

fn delivery_consultation_id(delivery: &DeliverySnapshot) -> Option<&str> {
    match &delivery.causal {
        CausalMessage::ConsultationRequest {
            consultation_id, ..
        }
        | CausalMessage::ConsultationResponse {
            consultation_id, ..
        } => Some(consultation_id.as_str()),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_delivery_archive_binding(
    workspace_id: &str,
    message_id: &str,
    request_id: Option<&str>,
    sender_actor_id: &str,
    sender_actor_epoch: i64,
    message_kind: &str,
    sent_at_ms: i64,
    decision_id: Option<&str>,
    candidate_sha: Option<&str>,
    consultation_id: Option<&str>,
    delivery: &DeliverySnapshot,
) -> Result<(), ControlError> {
    let (decoded_decision_id, decoded_candidate_sha) = delivery_decision_candidate(delivery);
    let decoded_consultation_id = delivery_consultation_id(delivery);
    let decoded_kind = serde_json::to_string(&delivery.message_kind)
        .map_err(ControlError::database)?
        .trim_matches('"')
        .to_owned();
    if delivery.envelope.workspace_id.as_str() != workspace_id
        || delivery.envelope.message_id.as_str() != message_id
        || delivery.envelope.request_id.as_ref().map(RequestId::as_str) != request_id
        || delivery.envelope.sender.actor_id.as_str() != sender_actor_id
        || to_i64(delivery.envelope.sender.actor_epoch.get())? != sender_actor_epoch
        || decoded_kind != message_kind
        || to_i64(delivery.envelope.sent_at.0)? != sent_at_ms
        || decoded_decision_id != decision_id
        || decoded_candidate_sha != candidate_sha
        || decoded_consultation_id != consultation_id
    {
        return Err(ControlError::new(
            "delivery_archive_index_mismatch",
            format!(
                "delivery archive indexes for message `{message_id}` conflict with immutable JSON"
            ),
        ));
    }
    Ok(())
}

fn read_archived_delivery(
    connection: &Connection,
    workspace_id: &str,
    message_id: &MessageId,
) -> Result<Option<DeliverySnapshot>, ControlError> {
    let row = connection
        .query_row(
            "SELECT request_id, sender_actor_id, sender_actor_epoch, message_kind,
                    sent_at_ms, decision_id, candidate_sha, consultation_id,
                    delivery_sha256, delivery_json
             FROM delivery_archive WHERE workspace_id = ?1 AND message_id = ?2",
            params![workspace_id, message_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            },
        )
        .optional()
        .map_err(ControlError::database)?;
    row.map(
        |(
            request_id,
            sender_actor_id,
            sender_actor_epoch,
            message_kind,
            sent_at_ms,
            decision_id,
            candidate_sha,
            consultation_id,
            digest,
            json,
        )| {
            verify_digest("archived delivery", &digest, json.as_bytes())?;
            let delivery: DeliverySnapshot =
                serde_json::from_str(&json).map_err(ControlError::database)?;
            validate_delivery_archive_binding(
                workspace_id,
                message_id.as_str(),
                request_id.as_deref(),
                &sender_actor_id,
                sender_actor_epoch,
                &message_kind,
                sent_at_ms,
                decision_id.as_deref(),
                candidate_sha.as_deref(),
                consultation_id.as_deref(),
                &delivery,
            )?;
            validate_archived_delivery_audit(connection, workspace_id, &delivery)?;
            Ok(delivery)
        },
    )
    .transpose()
}

fn validate_terminal_request_archive_binding(
    workspace_id: &str,
    request_id: &str,
    run_id: &str,
    request: &Request,
    run: &Run,
) -> Result<(), ControlError> {
    if request.workspace_id.as_str() != workspace_id
        || run.workspace_id.as_str() != workspace_id
        || request.request_id.as_str() != request_id
        || run.request_id != request.request_id
        || request.run_id != run.run_id
        || run.run_id.as_str() != run_id
    {
        return Err(ControlError::new(
            "terminal_request_archive_index_mismatch",
            format!(
                "terminal request archive indexes for request `{request_id}` conflict with immutable JSON"
            ),
        ));
    }
    Ok(())
}

fn request_outcome_id_conflict(request_id: &RequestId) -> ControlError {
    ControlError::new(
        "request_outcome_id_conflict",
        format!("request outcome ID `{request_id}` is not unique across hot and archive state"),
    )
}

fn insert_protocol_audit_archive(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    event: &AuditEvent,
    digest: &str,
    previous_digest: Option<&str>,
    event_json: &str,
    now_ms: u64,
) -> Result<ArchiveCommitEntry, ControlError> {
    transaction
        .execute(
            "INSERT INTO protocol_audit_archive
             (workspace_id, sequence, message_id, event_sha256, previous_sha256,
              event_json, archived_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                workspace_id,
                to_i64(event.sequence)?,
                audit_message_id(event).as_str(),
                digest,
                previous_digest,
                event_json,
                to_i64(now_ms)?
            ],
        )
        .map_err(ControlError::database)?;
    let existing: (String, String, Option<String>, String) = transaction
        .query_row(
            "SELECT message_id, event_sha256, previous_sha256, event_json
             FROM protocol_audit_archive
             WHERE workspace_id = ?1 AND sequence = ?2",
            params![workspace_id, to_i64(event.sequence)?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(ControlError::database)?;
    if existing
        != (
            audit_message_id(event).to_string(),
            digest.to_owned(),
            previous_digest.map(str::to_owned),
            event_json.to_owned(),
        )
    {
        return Err(immutable_conflict(
            "protocol_audit_archive",
            &event.sequence.to_string(),
        ));
    }
    Ok(ArchiveCommitEntry {
        kind: ARCHIVE_AUDIT_KIND.to_owned(),
        key: event.sequence.to_string(),
        content_sha256: digest.to_owned(),
    })
}

fn insert_terminal_request_archive(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    request: &Request,
    run: &Run,
    revision: u64,
    now_ms: u64,
) -> Result<ArchiveCommitEntry, ControlError> {
    let request_json = serde_json::to_string(request).map_err(ControlError::database)?;
    let run_json = serde_json::to_string(run).map_err(ControlError::database)?;
    let request_digest = sha256_hex(request_json.as_bytes());
    let run_digest = sha256_hex(run_json.as_bytes());
    let content_digest = terminal_request_content_digest(&request_digest, &run_digest);
    let creation_audit_sequence =
        request_creation_audit_sequence(transaction, workspace_id, request.request_id.as_str())?;
    transaction
        .execute(
            "INSERT INTO terminal_request_archive
             (workspace_id, request_id, run_id, team_id, creation_audit_sequence,
              request_sha256, request_json, run_sha256, run_json,
              archived_revision, archived_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                workspace_id,
                request.request_id.as_str(),
                run.run_id.as_str(),
                request.team_id.as_str(),
                to_i64(creation_audit_sequence)?,
                request_digest,
                request_json,
                run_digest,
                run_json,
                to_i64(revision)?,
                to_i64(now_ms)?
            ],
        )
        .map_err(ControlError::database)?;
    let existing: (String, i64, String, String, String, String) = transaction
        .query_row(
            "SELECT team_id, creation_audit_sequence, request_sha256, request_json,
                    run_sha256, run_json
             FROM terminal_request_archive WHERE workspace_id = ?1 AND request_id = ?2",
            params![workspace_id, request.request_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .map_err(ControlError::database)?;
    if existing
        != (
            request.team_id.to_string(),
            to_i64(creation_audit_sequence)?,
            request_digest,
            request_json,
            run_digest,
            run_json,
        )
    {
        return Err(immutable_conflict(
            "terminal_request_archive",
            request.request_id.as_str(),
        ));
    }
    Ok(ArchiveCommitEntry {
        kind: ARCHIVE_REQUEST_KIND.to_owned(),
        key: request.request_id.to_string(),
        content_sha256: content_digest,
    })
}

fn terminal_request_content_digest(request_digest: &str, run_digest: &str) -> String {
    sha256_hex(format!("{request_digest}\0{run_digest}"))
}

fn request_creation_audit_sequence(
    connection: &Connection,
    workspace_id: &str,
    request_id: &str,
) -> Result<u64, ControlError> {
    let message_id = connection
        .query_row(
            "SELECT message_id FROM delivery_archive
             WHERE workspace_id = ?1 AND request_id = ?2
               AND message_kind = 'implementation_request'",
            params![workspace_id, request_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(ControlError::database)?;
    let rows = {
        let mut statement = connection
            .prepare(
                "SELECT sequence, event_sha256, event_json
                 FROM protocol_audit_archive
                 WHERE workspace_id = ?1 AND message_id = ?2 ORDER BY sequence",
            )
            .map_err(ControlError::database)?;
        statement
            .query_map(params![workspace_id, message_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(ControlError::database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(ControlError::database)?
    };
    let mut accepted = None;
    for (sequence, digest, json) in rows {
        verify_digest("request creation audit", &digest, json.as_bytes())?;
        let event: AuditEvent = serde_json::from_str(&json).map_err(ControlError::database)?;
        if sequence != to_i64(event.sequence)? {
            return Err(ControlError::new(
                "protocol_audit_archive_key_mismatch",
                format!("request creation audit sequence {sequence} conflicts with JSON"),
            ));
        }
        if matches!(event.kind, AuditEventKind::MessageAccepted { .. })
            && accepted.replace(event.sequence).is_some()
        {
            return Err(ControlError::new(
                "request_creation_audit_conflict",
                format!("request `{request_id}` has multiple accepted creation audits"),
            ));
        }
    }
    accepted.ok_or_else(|| {
        ControlError::new(
            "request_creation_audit_missing",
            format!("request `{request_id}` has no accepted creation audit"),
        )
    })
}

fn audit_message_id(event: &AuditEvent) -> &MessageId {
    match &event.kind {
        AuditEventKind::MessageAccepted { message_id, .. }
        | AuditEventKind::MessageAcknowledged { message_id, .. } => message_id,
    }
}

fn canonical_digest(value: &impl Serialize) -> Result<String, ControlError> {
    let json = serde_json::to_vec(value).map_err(ControlError::database)?;
    Ok(sha256_hex(json))
}

fn archive_count(
    connection: &Connection,
    table: &str,
    workspace_id: &str,
) -> Result<u64, ControlError> {
    let count = connection
        .query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE workspace_id = ?1"),
            [workspace_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(ControlError::database)?;
    u64::try_from(count).map_err(ControlError::database)
}

fn read_archive_manifest(
    connection: &Connection,
    workspace_id: &str,
) -> Result<ArchiveManifest, ControlError> {
    connection
        .query_row(
            "SELECT commit_count, commit_head_sha256, delivery_count, request_count,
                    run_count, audit_event_count
             FROM archive_manifest WHERE workspace_id = ?1",
            [workspace_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(ControlError::database)
        .and_then(
            |(commit_count, commit_head_sha256, delivery, request, run, audit)| {
                Ok(ArchiveManifest {
                    commit_count: u64::try_from(commit_count).map_err(ControlError::database)?,
                    commit_head_sha256,
                    delivery_count: u64::try_from(delivery).map_err(ControlError::database)?,
                    request_count: u64::try_from(request).map_err(ControlError::database)?,
                    run_count: u64::try_from(run).map_err(ControlError::database)?,
                    audit_event_count: u64::try_from(audit).map_err(ControlError::database)?,
                })
            },
        )
}

fn checkpoint_manifest(snapshot: &DomainSnapshot) -> ArchiveManifest {
    let checkpoint = &snapshot.history_checkpoint;
    ArchiveManifest {
        commit_count: checkpoint.archive_commit_count,
        commit_head_sha256: checkpoint
            .archive_head_sha256
            .as_ref()
            .map(|digest| digest.as_str().to_owned()),
        delivery_count: checkpoint.archived_delivery_count,
        request_count: checkpoint.archived_request_count,
        run_count: checkpoint.archived_run_count,
        audit_event_count: checkpoint.archived_audit_event_count,
    }
}

fn verify_archive_manifest_checkpoint(
    connection: &Connection,
    workspace_id: &str,
    snapshot: &DomainSnapshot,
) -> Result<(), ControlError> {
    let stored = read_archive_manifest(connection, workspace_id)?;
    let expected = checkpoint_manifest(snapshot);
    if stored != expected {
        return Err(ControlError::new(
            "archive_manifest_checkpoint_mismatch",
            "compact history checkpoint does not match the atomic archive manifest",
        )
        .with_details(json!({
            "checkpoint_commit_count": expected.commit_count,
            "manifest_commit_count": stored.commit_count,
        })));
    }
    Ok(())
}

fn verify_hot_archive_disjointness(
    connection: &Connection,
    workspace_id: &str,
    snapshot: &DomainSnapshot,
) -> Result<(), ControlError> {
    for delivery in &snapshot.deliveries {
        let archived = connection
            .query_row(
                "SELECT 1 FROM delivery_archive
                 WHERE workspace_id = ?1 AND message_id = ?2",
                params![workspace_id, delivery.envelope.message_id.as_str()],
                |_| Ok(()),
            )
            .optional()
            .map_err(ControlError::database)?;
        if archived.is_some() {
            return Err(ControlError::new(
                "hot_archive_delivery_overlap",
                format!(
                    "message `{}` exists in both hot state and immutable archive",
                    delivery.envelope.message_id
                ),
            ));
        }
    }
    for request in &snapshot.requests {
        let archived_request = connection
            .query_row(
                "SELECT 1 FROM terminal_request_archive
                 WHERE workspace_id = ?1 AND request_id = ?2",
                params![workspace_id, request.request_id.as_str()],
                |_| Ok(()),
            )
            .optional()
            .map_err(ControlError::database)?;
        let archived_run = connection
            .query_row(
                "SELECT 1 FROM terminal_request_archive
                 WHERE workspace_id = ?1 AND run_id = ?2",
                params![workspace_id, request.run_id.as_str()],
                |_| Ok(()),
            )
            .optional()
            .map_err(ControlError::database)?;
        if archived_request.is_some() || archived_run.is_some() {
            return Err(ControlError::new(
                "hot_archive_request_overlap",
                format!(
                    "request `{}` or run `{}` exists in both hot state and immutable archive",
                    request.request_id, request.run_id
                ),
            ));
        }
    }
    for event in &snapshot.audit_events {
        let archived = connection
            .query_row(
                "SELECT 1 FROM protocol_audit_archive
                 WHERE workspace_id = ?1 AND sequence = ?2",
                params![workspace_id, to_i64(event.sequence)?],
                |_| Ok(()),
            )
            .optional()
            .map_err(ControlError::database)?;
        if archived.is_some() {
            return Err(ControlError::new(
                "hot_archive_audit_overlap",
                format!(
                    "protocol audit sequence {} exists in both hot state and immutable archive",
                    event.sequence
                ),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn append_archive_commit(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    snapshot: &mut DomainSnapshot,
    mut entries: Vec<ArchiveCommitEntry>,
    revision: u64,
    now_ms: u64,
) -> Result<(), ControlError> {
    verify_archive_manifest_checkpoint(transaction, workspace_id, snapshot)?;
    if entries.is_empty() {
        return Ok(());
    }
    entries.sort();
    if entries
        .windows(2)
        .any(|pair| pair[0].kind == pair[1].kind && pair[0].key == pair[1].key)
    {
        return Err(ControlError::new(
            "archive_commit_entry_conflict",
            "one archive commit contains duplicate immutable row entries",
        ));
    }
    let checkpoint = &mut snapshot.history_checkpoint;
    let sequence = checkpoint
        .archive_commit_count
        .checked_add(1)
        .ok_or_else(|| {
            ControlError::new(
                "archive_commit_exhausted",
                "archive commit count exhausted u64",
            )
        })?;
    let previous_sha256 = checkpoint
        .archive_head_sha256
        .as_ref()
        .map(|digest| digest.as_str().to_owned());
    let commit = ArchiveCommit {
        sequence,
        previous_sha256: previous_sha256.clone(),
        entries,
        committed_revision: revision,
        committed_at_ms: now_ms,
    };
    let commit_json = serde_json::to_string(&commit).map_err(ControlError::database)?;
    let commit_sha256 = sha256_hex(commit_json.as_bytes());
    transaction
        .execute(
            "INSERT INTO archive_commits
             (workspace_id, sequence, previous_sha256, commit_sha256, commit_json,
              committed_revision, committed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                workspace_id,
                to_i64(sequence)?,
                previous_sha256,
                commit_sha256,
                commit_json,
                to_i64(revision)?,
                to_i64(now_ms)?
            ],
        )
        .map_err(ControlError::database)?;
    for (ordinal, entry) in commit.entries.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO archive_commit_entries
                 (workspace_id, kind, key, commit_sequence, entry_ordinal, content_sha256)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    workspace_id,
                    entry.kind,
                    entry.key,
                    to_i64(sequence)?,
                    to_i64(u64::try_from(ordinal).map_err(ControlError::database)?)?,
                    entry.content_sha256
                ],
            )
            .map_err(ControlError::database)?;
    }

    let mut delivery_delta = 0_u64;
    let mut request_delta = 0_u64;
    let mut audit_delta = 0_u64;
    for entry in &commit.entries {
        match entry.kind.as_str() {
            ARCHIVE_DELIVERY_KIND => delivery_delta += 1,
            ARCHIVE_REQUEST_KIND => request_delta += 1,
            ARCHIVE_AUDIT_KIND => audit_delta += 1,
            _ => unreachable!("archive entries are created only for known row kinds"),
        }
    }
    checkpoint.archived_delivery_count = checkpoint
        .archived_delivery_count
        .checked_add(delivery_delta)
        .ok_or_else(|| {
            ControlError::new(
                "archive_count_exhausted",
                "delivery archive count exhausted u64",
            )
        })?;
    checkpoint.archived_request_count = checkpoint
        .archived_request_count
        .checked_add(request_delta)
        .ok_or_else(|| {
            ControlError::new(
                "archive_count_exhausted",
                "request archive count exhausted u64",
            )
        })?;
    checkpoint.archived_run_count = checkpoint
        .archived_run_count
        .checked_add(request_delta)
        .ok_or_else(|| {
            ControlError::new("archive_count_exhausted", "run archive count exhausted u64")
        })?;
    checkpoint.archived_audit_event_count = checkpoint
        .archived_audit_event_count
        .checked_add(audit_delta)
        .ok_or_else(|| {
            ControlError::new(
                "archive_count_exhausted",
                "audit archive count exhausted u64",
            )
        })?;
    checkpoint.archive_commit_count = sequence;
    checkpoint.archive_head_sha256 =
        Some(PayloadDigest::new(commit_sha256.clone()).map_err(ControlError::protocol)?);

    let updated = transaction
        .execute(
            "UPDATE archive_manifest
             SET commit_count = ?1, commit_head_sha256 = ?2, delivery_count = ?3,
                 request_count = ?4, run_count = ?5, audit_event_count = ?6,
                 updated_revision = ?7, updated_at_ms = ?8
             WHERE workspace_id = ?9 AND commit_count = ?10
               AND commit_head_sha256 IS ?11",
            params![
                to_i64(checkpoint.archive_commit_count)?,
                commit_sha256,
                to_i64(checkpoint.archived_delivery_count)?,
                to_i64(checkpoint.archived_request_count)?,
                to_i64(checkpoint.archived_run_count)?,
                to_i64(checkpoint.archived_audit_event_count)?,
                to_i64(revision)?,
                to_i64(now_ms)?,
                workspace_id,
                to_i64(sequence - 1)?,
                previous_sha256
            ],
        )
        .map_err(ControlError::database)?;
    if updated != 1 {
        return Err(ControlError::new(
            "archive_manifest_concurrent_update",
            "archive manifest changed before the atomic commit was recorded",
        ));
    }
    verify_archive_manifest_checkpoint(transaction, workspace_id, snapshot)
}

#[allow(clippy::too_many_lines)]
fn verify_archive_commit_chain(
    connection: &Connection,
    workspace_id: &str,
    snapshot: &DomainSnapshot,
) -> Result<(), ControlError> {
    let mut statement = connection
        .prepare(
            "SELECT sequence, previous_sha256, commit_sha256, commit_json,
                    committed_revision, committed_at_ms
             FROM archive_commits WHERE workspace_id = ?1 ORDER BY sequence",
        )
        .map_err(ControlError::database)?;
    let mut rows = statement
        .query([workspace_id])
        .map_err(ControlError::database)?;
    let mut expected_sequence = 1_u64;
    let mut previous_sha256 = None;
    let mut observed = ArchiveManifest::default();
    while let Some(row) = rows.next().map_err(ControlError::database)? {
        let sequence = unsigned_from_sql(row.get(0).map_err(ControlError::database)?, 0)
            .map_err(ControlError::database)?;
        let stored_previous = row
            .get::<_, Option<String>>(1)
            .map_err(ControlError::database)?;
        let digest = row.get::<_, String>(2).map_err(ControlError::database)?;
        let json = row.get::<_, String>(3).map_err(ControlError::database)?;
        let revision = unsigned_from_sql(row.get(4).map_err(ControlError::database)?, 4)
            .map_err(ControlError::database)?;
        let committed_at_ms = unsigned_from_sql(row.get(5).map_err(ControlError::database)?, 5)
            .map_err(ControlError::database)?;
        verify_digest("archive commit", &digest, json.as_bytes())?;
        let commit: ArchiveCommit = serde_json::from_str(&json).map_err(ControlError::database)?;
        if sequence != expected_sequence
            || commit.sequence != sequence
            || stored_previous != previous_sha256
            || commit.previous_sha256 != stored_previous
            || commit.committed_revision != revision
            || commit.committed_at_ms != committed_at_ms
            || commit.entries.is_empty()
        {
            return Err(ControlError::new(
                "archive_commit_chain_invalid",
                format!("archive commit {sequence} conflicts with its chain or SQL indexes"),
            ));
        }
        if commit.entries.windows(2).any(|pair| {
            pair[0] >= pair[1] || (pair[0].kind == pair[1].kind && pair[0].key == pair[1].key)
        }) {
            return Err(ControlError::new(
                "archive_commit_entries_invalid",
                format!("archive commit {sequence} entries are duplicated or unordered"),
            ));
        }
        for (ordinal, entry) in commit.entries.iter().enumerate() {
            verify_archive_commit_entry(
                connection,
                workspace_id,
                sequence,
                u64::try_from(ordinal).map_err(ControlError::database)?,
                entry,
            )?;
            match entry.kind.as_str() {
                ARCHIVE_DELIVERY_KIND => observed.delivery_count += 1,
                ARCHIVE_REQUEST_KIND => {
                    observed.request_count += 1;
                    observed.run_count += 1;
                }
                ARCHIVE_AUDIT_KIND => observed.audit_event_count += 1,
                _ => unreachable!("entry validation rejects unknown kinds"),
            }
        }
        observed.commit_count += 1;
        previous_sha256 = Some(digest);
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            ControlError::new(
                "archive_commit_exhausted",
                "archive commit count exhausted u64",
            )
        })?;
    }
    observed.commit_head_sha256 = previous_sha256;
    let normalized_entry_count = archive_count(connection, "archive_commit_entries", workspace_id)?;
    let observed_entry_count = observed
        .delivery_count
        .checked_add(observed.request_count)
        .and_then(|count| count.checked_add(observed.audit_event_count))
        .ok_or_else(|| {
            ControlError::new(
                "archive_count_exhausted",
                "archive commit entry count exhausted u64",
            )
        })?;
    if normalized_entry_count != observed_entry_count {
        return Err(ControlError::new(
            "archive_commit_entry_count_mismatch",
            "normalized archive commit entries are incomplete or contain orphan rows",
        ));
    }
    if observed != checkpoint_manifest(snapshot) {
        return Err(ControlError::new(
            "archive_commit_checkpoint_mismatch",
            "verified archive commit chain does not match the compact history checkpoint",
        ));
    }
    Ok(())
}

fn verify_archive_commit_entry(
    connection: &Connection,
    workspace_id: &str,
    commit_sequence: u64,
    entry_ordinal: u64,
    entry: &ArchiveCommitEntry,
) -> Result<(), ControlError> {
    PayloadDigest::new(entry.content_sha256.clone()).map_err(ControlError::protocol)?;
    let normalized = connection
        .query_row(
            "SELECT commit_sequence, entry_ordinal, content_sha256
             FROM archive_commit_entries
             WHERE workspace_id = ?1 AND kind = ?2 AND key = ?3",
            params![workspace_id, entry.kind, entry.key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(ControlError::database)?;
    if normalized
        != Some((
            to_i64(commit_sequence)?,
            to_i64(entry_ordinal)?,
            entry.content_sha256.clone(),
        ))
    {
        return Err(ControlError::new(
            "archive_commit_entry_index_mismatch",
            format!(
                "archive commit entry `{}/{}` conflicts with its normalized index",
                entry.kind, entry.key
            ),
        ));
    }
    let stored_digest = match entry.kind.as_str() {
        ARCHIVE_DELIVERY_KIND => connection
            .query_row(
                "SELECT delivery_sha256 FROM delivery_archive
                 WHERE workspace_id = ?1 AND message_id = ?2",
                params![workspace_id, entry.key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(ControlError::database)?,
        ARCHIVE_REQUEST_KIND => connection
            .query_row(
                "SELECT request_sha256, run_sha256 FROM terminal_request_archive
                 WHERE workspace_id = ?1 AND request_id = ?2",
                params![workspace_id, entry.key],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(ControlError::database)?
            .map(|(request, run)| terminal_request_content_digest(&request, &run)),
        ARCHIVE_AUDIT_KIND => {
            let sequence = entry.key.parse::<u64>().map_err(ControlError::database)?;
            connection
                .query_row(
                    "SELECT event_sha256 FROM protocol_audit_archive
                     WHERE workspace_id = ?1 AND sequence = ?2",
                    params![workspace_id, to_i64(sequence)?],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(ControlError::database)?
        }
        _ => {
            return Err(ControlError::new(
                "archive_commit_entry_kind_invalid",
                format!(
                    "archive commit references unknown row kind `{}`",
                    entry.kind
                ),
            ));
        }
    };
    if stored_digest.as_deref() != Some(entry.content_sha256.as_str()) {
        return Err(ControlError::new(
            "archive_commit_entry_mismatch",
            format!(
                "archive commit entry `{}/{}` does not match its immutable row digest",
                entry.kind, entry.key
            ),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn verify_compact_archive_checkpoint(
    connection: &Connection,
    workspace_id: &str,
    snapshot: &DomainSnapshot,
) -> Result<(), ControlError> {
    let verifier = restore_supervisor(snapshot.clone())?;
    let checkpoint = &snapshot.history_checkpoint;
    let delivery_count = archive_count(connection, "delivery_archive", workspace_id)?;
    let request_count = archive_count(connection, "terminal_request_archive", workspace_id)?;
    let audit_count = archive_count(connection, "protocol_audit_archive", workspace_id)?;
    if delivery_count != checkpoint.archived_delivery_count
        || request_count != checkpoint.archived_request_count
        || request_count != checkpoint.archived_run_count
        || audit_count != checkpoint.archived_audit_event_count
    {
        return Err(ControlError::new(
            "history_checkpoint_count_mismatch",
            "compact history checkpoint does not match immutable archive row counts",
        ));
    }

    let hot_delivery_ids = snapshot
        .deliveries
        .iter()
        .map(|delivery| delivery.envelope.message_id.clone())
        .collect::<BTreeSet<_>>();
    let mut statement = connection
        .prepare(
            "SELECT message_id, request_id, sender_actor_id, sender_actor_epoch,
                    message_kind, sent_at_ms, decision_id, candidate_sha, consultation_id,
                    delivery_sha256, delivery_json
             FROM delivery_archive WHERE workspace_id = ?1 ORDER BY message_id",
        )
        .map_err(ControlError::database)?;
    let mut rows = statement
        .query([workspace_id])
        .map_err(ControlError::database)?;
    while let Some(row) = rows.next().map_err(ControlError::database)? {
        let message_id = row.get::<_, String>(0).map_err(ControlError::database)?;
        let request_id = row
            .get::<_, Option<String>>(1)
            .map_err(ControlError::database)?;
        let sender_actor_id = row.get::<_, String>(2).map_err(ControlError::database)?;
        let sender_actor_epoch = row.get::<_, i64>(3).map_err(ControlError::database)?;
        let message_kind = row.get::<_, String>(4).map_err(ControlError::database)?;
        let sent_at_ms = row.get::<_, i64>(5).map_err(ControlError::database)?;
        let decision_id = row
            .get::<_, Option<String>>(6)
            .map_err(ControlError::database)?;
        let candidate_sha = row
            .get::<_, Option<String>>(7)
            .map_err(ControlError::database)?;
        let consultation_id = row
            .get::<_, Option<String>>(8)
            .map_err(ControlError::database)?;
        let digest = row.get::<_, String>(9).map_err(ControlError::database)?;
        let json = row.get::<_, String>(10).map_err(ControlError::database)?;
        verify_digest("archived delivery", &digest, json.as_bytes())?;
        let delivery: DeliverySnapshot =
            serde_json::from_str(&json).map_err(ControlError::database)?;
        validate_delivery_archive_binding(
            workspace_id,
            &message_id,
            request_id.as_deref(),
            &sender_actor_id,
            sender_actor_epoch,
            &message_kind,
            sent_at_ms,
            decision_id.as_deref(),
            candidate_sha.as_deref(),
            consultation_id.as_deref(),
            &delivery,
        )?;
        validate_archived_delivery_audit(connection, workspace_id, &delivery)?;
        if hot_delivery_ids.contains(&delivery.envelope.message_id) {
            return Err(immutable_conflict("delivery_archive", &message_id));
        }
    }

    let hot_request_ids = snapshot
        .requests
        .iter()
        .map(|request| request.request_id.clone())
        .collect::<BTreeSet<_>>();
    let hot_run_ids = snapshot
        .runs
        .iter()
        .map(|run| run.run_id.clone())
        .collect::<BTreeSet<_>>();
    let mut statement = connection
        .prepare(
            "SELECT request_id, run_id, request_sha256, request_json, run_sha256, run_json
             FROM terminal_request_archive WHERE workspace_id = ?1 ORDER BY request_id",
        )
        .map_err(ControlError::database)?;
    let mut rows = statement
        .query([workspace_id])
        .map_err(ControlError::database)?;
    while let Some(row) = rows.next().map_err(ControlError::database)? {
        let request_id = row.get::<_, String>(0).map_err(ControlError::database)?;
        let run_id = row.get::<_, String>(1).map_err(ControlError::database)?;
        let request_digest = row.get::<_, String>(2).map_err(ControlError::database)?;
        let request_json = row.get::<_, String>(3).map_err(ControlError::database)?;
        let run_digest = row.get::<_, String>(4).map_err(ControlError::database)?;
        let run_json = row.get::<_, String>(5).map_err(ControlError::database)?;
        verify_digest("archived request", &request_digest, request_json.as_bytes())?;
        verify_digest("archived run", &run_digest, run_json.as_bytes())?;
        let request: Request =
            serde_json::from_str(&request_json).map_err(ControlError::database)?;
        let run: Run = serde_json::from_str(&run_json).map_err(ControlError::database)?;
        validate_terminal_request_archive_binding(
            workspace_id,
            &request_id,
            &run_id,
            &request,
            &run,
        )?;
        if hot_request_ids.contains(&request.request_id) || hot_run_ids.contains(&run.run_id) {
            return Err(immutable_conflict("terminal_request_archive", &request_id));
        }
    }

    verify_protocol_audit_checkpoint(connection, workspace_id, snapshot, &verifier)?;
    validate_archived_causal_history(connection, workspace_id, snapshot, &verifier)
}

fn archived_delivery_ids(
    connection: &Connection,
    workspace_id: &str,
    predicate: &str,
    value: &str,
) -> Result<Vec<MessageId>, ControlError> {
    let count_query = format!(
        "SELECT COUNT(*) FROM delivery_archive
         WHERE workspace_id = ?1 AND {predicate} = ?2"
    );
    let count = connection
        .query_row(&count_query, params![workspace_id, value], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(ControlError::database)?;
    if count > i64::try_from(MAX_DELIVERIES).map_err(ControlError::database)? {
        return Err(archived_group_limit_error(
            "deliveries",
            count,
            MAX_DELIVERIES,
        ));
    }
    let query = format!(
        "SELECT message_id FROM delivery_archive
         WHERE workspace_id = ?1 AND {predicate} = ?2 ORDER BY sent_at_ms, message_id"
    );
    let mut statement = connection.prepare(&query).map_err(ControlError::database)?;
    statement
        .query_map(params![workspace_id, value], |row| row.get::<_, String>(0))
        .map_err(ControlError::database)?
        .map(|row| {
            MessageId::new(row.map_err(ControlError::database)?).map_err(ControlError::protocol)
        })
        .collect()
}

fn archived_audit_events_for_deliveries(
    connection: &Connection,
    workspace_id: &str,
    deliveries: &[DeliverySnapshot],
) -> Result<Vec<AuditEvent>, ControlError> {
    let mut events = Vec::new();
    for delivery in deliveries {
        let mut statement = connection
            .prepare(
                "SELECT sequence, message_id, event_sha256, event_json
                 FROM protocol_audit_archive
                 WHERE workspace_id = ?1 AND message_id = ?2 ORDER BY sequence",
            )
            .map_err(ControlError::database)?;
        let rows = statement
            .query_map(
                params![workspace_id, delivery.envelope.message_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .map_err(ControlError::database)?;
        for row in rows {
            let (sequence, message_id, digest, json) = row.map_err(ControlError::database)?;
            verify_digest("archived protocol audit event", &digest, json.as_bytes())?;
            let event: AuditEvent = serde_json::from_str(&json).map_err(ControlError::database)?;
            if sequence != to_i64(event.sequence)?
                || message_id != delivery.envelope.message_id.as_str()
                || audit_message_id(&event) != &delivery.envelope.message_id
            {
                return Err(ControlError::new(
                    "protocol_audit_archive_key_mismatch",
                    format!("archived audit sequence {sequence} conflicts with its delivery"),
                ));
            }
            if events.len() >= MAX_AUDIT_EVENTS {
                return Err(archived_group_limit_error(
                    "audit events",
                    i64::try_from(events.len() + 1).map_err(ControlError::database)?,
                    MAX_AUDIT_EVENTS,
                ));
            }
            events.push(event);
        }
    }
    events.sort_by_key(|event| event.sequence);
    Ok(events)
}

fn archived_group_limit_error(kind: &str, actual: i64, maximum: usize) -> ControlError {
    ControlError::new(
        "archived_history_group_limit_exceeded",
        format!("archived history group contains {actual} {kind}; maximum is {maximum}"),
    )
    .with_details(json!({
        "entity_kind": kind,
        "actual": actual,
        "maximum": maximum,
    }))
}

fn load_archived_deliveries(
    connection: &Connection,
    workspace_id: &str,
    message_ids: impl IntoIterator<Item = MessageId>,
) -> Result<Vec<DeliverySnapshot>, ControlError> {
    message_ids
        .into_iter()
        .map(|message_id| {
            read_archived_delivery(connection, workspace_id, &message_id)?
                .ok_or_else(|| ControlError::not_found("archived delivery", message_id.as_str()))
        })
        .collect()
}

fn archived_request_reference(
    connection: &Connection,
    workspace_id: &str,
    snapshot: &DomainSnapshot,
    request_id: &RequestId,
) -> Result<ArchivedRequestReference, ControlError> {
    if let Some(request) = snapshot
        .requests
        .iter()
        .find(|request| &request.request_id == request_id)
    {
        let creation_message = snapshot
            .deliveries
            .iter()
            .find(|delivery| {
                delivery.envelope.request_id.as_ref() == Some(request_id)
                    && delivery.message_kind == agsv_protocol::MessageKind::ImplementationRequest
            })
            .ok_or_else(|| {
                ControlError::new(
                    "archived_dependency_creation_missing",
                    format!("referenced hot request `{request_id}` lacks its creation delivery"),
                )
            })?;
        let creation_audit_sequence = snapshot
            .audit_events
            .iter()
            .find_map(|event| match &event.kind {
                AuditEventKind::MessageAccepted { message_id, .. }
                    if message_id == &creation_message.envelope.message_id =>
                {
                    Some(event.sequence)
                }
                _ => None,
            })
            .ok_or_else(|| {
                ControlError::new(
                    "archived_dependency_creation_audit_missing",
                    format!("referenced hot request `{request_id}` lacks accepted provenance"),
                )
            })?;
        return Ok(ArchivedRequestReference {
            request_id: request_id.clone(),
            team_id: request.team_id.clone(),
            creation_audit_sequence,
        });
    }
    let (team_id, creation_sequence, request_digest, request_json) = connection
        .query_row(
            "SELECT team_id, creation_audit_sequence, request_sha256, request_json
             FROM terminal_request_archive WHERE workspace_id = ?1 AND request_id = ?2",
            params![workspace_id, request_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .map_err(ControlError::database)?;
    verify_digest(
        "archived dependency request",
        &request_digest,
        request_json.as_bytes(),
    )?;
    let request: Request = serde_json::from_str(&request_json).map_err(ControlError::database)?;
    if request.request_id != *request_id
        || request.team_id.as_str() != team_id
        || creation_sequence < 1
    {
        return Err(ControlError::new(
            "archived_dependency_reference_mismatch",
            format!("archived dependency reference `{request_id}` conflicts with immutable JSON"),
        ));
    }
    Ok(ArchivedRequestReference {
        request_id: request_id.clone(),
        team_id: request.team_id,
        creation_audit_sequence: u64::try_from(creation_sequence)
            .map_err(ControlError::database)?,
    })
}

#[allow(clippy::too_many_lines)]
fn validate_archived_causal_history(
    connection: &Connection,
    workspace_id: &str,
    hot_snapshot: &DomainSnapshot,
    verifier: &Supervisor,
) -> Result<(), ControlError> {
    let orphan_request_delivery = connection
        .query_row(
            "SELECT delivery.message_id
             FROM delivery_archive AS delivery
             LEFT JOIN terminal_request_archive AS terminal
               ON terminal.workspace_id = delivery.workspace_id
              AND terminal.request_id = delivery.request_id
             WHERE delivery.workspace_id = ?1 AND delivery.request_id IS NOT NULL
               AND terminal.request_id IS NULL LIMIT 1",
            [workspace_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(ControlError::database)?;
    if let Some(message_id) = orphan_request_delivery {
        return Err(ControlError::new(
            "archived_delivery_terminal_owner_missing",
            format!("request-scoped archived delivery `{message_id}` has no terminal cycle owner"),
        ));
    }
    let mut cursor = String::new();
    loop {
        let row = connection
            .query_row(
                "SELECT request_id, run_id, team_id, creation_audit_sequence,
                        request_sha256, request_json, run_sha256, run_json
                 FROM terminal_request_archive
                 WHERE workspace_id = ?1 AND request_id > ?2
                 ORDER BY request_id LIMIT 1",
                params![workspace_id, cursor],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(ControlError::database)?;
        let Some((request_id, run_id, team_id, creation_sequence, rd, rj, ud, uj)) = row else {
            break;
        };
        verify_digest("archived request", &rd, rj.as_bytes())?;
        verify_digest("archived run", &ud, uj.as_bytes())?;
        let request: Request = serde_json::from_str(&rj).map_err(ControlError::database)?;
        let run: Run = serde_json::from_str(&uj).map_err(ControlError::database)?;
        validate_terminal_request_archive_binding(
            workspace_id,
            &request_id,
            &run_id,
            &request,
            &run,
        )?;
        if request.team_id.as_str() != team_id
            || creation_sequence
                != to_i64(request_creation_audit_sequence(
                    connection,
                    workspace_id,
                    &request_id,
                )?)?
        {
            return Err(ControlError::new(
                "terminal_request_archive_index_mismatch",
                format!("terminal request `{request_id}` query indexes conflict with history"),
            ));
        }
        let mut message_ids =
            archived_delivery_ids(connection, workspace_id, "request_id", &request_id)?;
        let scoped =
            load_archived_deliveries(connection, workspace_id, message_ids.iter().cloned())?;
        let consultation_ids = scoped
            .iter()
            .filter_map(|delivery| match &delivery.causal {
                CausalMessage::ConsultationRequest {
                    consultation_id, ..
                } => Some(consultation_id.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        for consultation_id in consultation_ids {
            let response_ids = archived_delivery_ids(
                connection,
                workspace_id,
                "consultation_id",
                consultation_id.as_str(),
            )?;
            for response_id in response_ids {
                if !message_ids.contains(&response_id) {
                    if message_ids.len() >= MAX_DELIVERIES {
                        return Err(archived_group_limit_error(
                            "deliveries",
                            i64::try_from(message_ids.len() + 1).map_err(ControlError::database)?,
                            MAX_DELIVERIES,
                        ));
                    }
                    message_ids.push(response_id);
                }
            }
        }
        let deliveries = load_archived_deliveries(connection, workspace_id, message_ids)?;
        let audit_events =
            archived_audit_events_for_deliveries(connection, workspace_id, &deliveries)?;
        let dependency_ids = deliveries
            .iter()
            .filter_map(|delivery| match &delivery.causal {
                CausalMessage::DependencyNotice {
                    depends_on_request_id,
                    ..
                } => Some(depends_on_request_id.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let references = dependency_ids
            .iter()
            .map(|request_id| {
                archived_request_reference(connection, workspace_id, hot_snapshot, request_id)
            })
            .collect::<Result<Vec<_>, _>>()?;
        verifier
            .validate_archived_terminal_cycle(
                &request,
                &run,
                &deliveries,
                &audit_events,
                &references,
            )
            .map_err(ControlError::core)?;
        cursor = request_id;
    }

    validate_archived_requestless_groups(connection, workspace_id, verifier)
}

fn validate_archived_requestless_groups(
    connection: &Connection,
    workspace_id: &str,
    verifier: &Supervisor,
) -> Result<(), ControlError> {
    let mut cursor = String::new();
    loop {
        let consultation_id = connection
            .query_row(
                "SELECT consultation_id FROM delivery_archive
                 WHERE workspace_id = ?1 AND request_id IS NULL
                   AND consultation_id IS NOT NULL AND consultation_id > ?2
                 ORDER BY consultation_id LIMIT 1",
                params![workspace_id, cursor],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(ControlError::database)?;
        let Some(consultation_id) = consultation_id else {
            break;
        };
        let scoped_exists = connection
            .query_row(
                "SELECT 1 FROM delivery_archive
                 WHERE workspace_id = ?1 AND consultation_id = ?2
                   AND request_id IS NOT NULL
                   AND message_kind = 'consultation_request' LIMIT 1",
                params![workspace_id, consultation_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(ControlError::database)?
            .is_some();
        if !scoped_exists {
            let message_ids = archived_delivery_ids(
                connection,
                workspace_id,
                "consultation_id",
                &consultation_id,
            )?;
            let deliveries = load_archived_deliveries(connection, workspace_id, message_ids)?;
            let audit_events =
                archived_audit_events_for_deliveries(connection, workspace_id, &deliveries)?;
            verifier
                .validate_archived_requestless_history(&deliveries, &audit_events)
                .map_err(ControlError::core)?;
        }
        cursor = consultation_id;
    }

    let mut cursor = String::new();
    loop {
        let message_id = connection
            .query_row(
                "SELECT message_id FROM delivery_archive
                 WHERE workspace_id = ?1 AND request_id IS NULL
                   AND consultation_id IS NULL AND message_id > ?2
                 ORDER BY message_id LIMIT 1",
                params![workspace_id, cursor],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(ControlError::database)?;
        let Some(message_id) = message_id else {
            break;
        };
        cursor.clone_from(&message_id);
        let message_id = MessageId::new(message_id).map_err(ControlError::protocol)?;
        let deliveries = load_archived_deliveries(connection, workspace_id, [message_id])?;
        let audit_events =
            archived_audit_events_for_deliveries(connection, workspace_id, &deliveries)?;
        verifier
            .validate_archived_requestless_history(&deliveries, &audit_events)
            .map_err(ControlError::core)?;
    }
    Ok(())
}

fn validate_archived_delivery_audit(
    connection: &Connection,
    workspace_id: &str,
    delivery: &DeliverySnapshot,
) -> Result<(), ControlError> {
    let mut expected_acknowledgements = delivery
        .acknowledgements
        .iter()
        .map(|acknowledgement| {
            (
                acknowledgement.actor.actor_id.clone(),
                acknowledgement.acknowledged_at,
            )
        })
        .collect::<BTreeMap<_, _>>();
    if expected_acknowledgements.len() != delivery.acknowledgements.len() {
        return Err(ControlError::new(
            "archived_delivery_acknowledgement_conflict",
            format!(
                "archived delivery `{}` has duplicate logical acknowledgement actors",
                delivery.envelope.message_id
            ),
        ));
    }
    let mut accepted = false;
    let mut statement = connection
        .prepare(
            "SELECT sequence, message_id, event_sha256, event_json
             FROM protocol_audit_archive
             WHERE workspace_id = ?1 AND message_id = ?2 ORDER BY sequence",
        )
        .map_err(ControlError::database)?;
    let mut rows = statement
        .query(params![workspace_id, delivery.envelope.message_id.as_str()])
        .map_err(ControlError::database)?;
    while let Some(row) = rows.next().map_err(ControlError::database)? {
        let sequence = row.get::<_, i64>(0).map_err(ControlError::database)?;
        let message_id = row.get::<_, String>(1).map_err(ControlError::database)?;
        let digest = row.get::<_, String>(2).map_err(ControlError::database)?;
        let json = row.get::<_, String>(3).map_err(ControlError::database)?;
        verify_digest("archived protocol audit event", &digest, json.as_bytes())?;
        let event: AuditEvent = serde_json::from_str(&json).map_err(ControlError::database)?;
        if sequence != to_i64(event.sequence)?
            || message_id != delivery.envelope.message_id.as_str()
            || audit_message_id(&event) != &delivery.envelope.message_id
        {
            return Err(ControlError::new(
                "protocol_audit_archive_key_mismatch",
                format!(
                    "protocol audit row {sequence} conflicts with archived delivery `{}`",
                    delivery.envelope.message_id
                ),
            ));
        }
        match event.kind {
            AuditEventKind::MessageAccepted {
                message_kind,
                payload_digest,
                ..
            } => {
                if accepted
                    || message_kind != delivery.message_kind
                    || payload_digest.as_ref() != Some(&delivery.payload_digest)
                    || event.occurred_at != delivery.envelope.sent_at
                {
                    return Err(ControlError::new(
                        "archived_delivery_acceptance_mismatch",
                        format!(
                            "accepted audit provenance conflicts with archived delivery `{}`",
                            delivery.envelope.message_id
                        ),
                    ));
                }
                accepted = true;
            }
            AuditEventKind::MessageAcknowledged { actor_id, .. } => {
                let expected = expected_acknowledgements.remove(&actor_id);
                if expected != Some(event.occurred_at) {
                    return Err(ControlError::new(
                        "archived_delivery_acknowledgement_mismatch",
                        format!(
                            "acknowledgement audit provenance conflicts with archived delivery `{}`",
                            delivery.envelope.message_id
                        ),
                    ));
                }
            }
        }
    }
    if !accepted || !expected_acknowledgements.is_empty() {
        return Err(ControlError::new(
            "archived_delivery_audit_incomplete",
            format!(
                "archived delivery `{}` lacks complete accepted/acknowledged provenance",
                delivery.envelope.message_id
            ),
        ));
    }
    Ok(())
}

type ArchivedAuditRow = (u64, String, String, Option<String>, String);

fn next_archived_audit_row(
    rows: &mut rusqlite::Rows<'_>,
) -> Result<Option<ArchivedAuditRow>, ControlError> {
    rows.next()
        .map_err(ControlError::database)?
        .map(|row| {
            let sequence = row.get::<_, i64>(0).map_err(ControlError::database)?;
            Ok((
                u64::try_from(sequence).map_err(ControlError::database)?,
                row.get(1).map_err(ControlError::database)?,
                row.get(2).map_err(ControlError::database)?,
                row.get(3).map_err(ControlError::database)?,
                row.get(4).map_err(ControlError::database)?,
            ))
        })
        .transpose()
}

#[allow(clippy::too_many_lines)]
fn verify_protocol_audit_checkpoint(
    connection: &Connection,
    workspace_id: &str,
    snapshot: &DomainSnapshot,
    verifier: &Supervisor,
) -> Result<(), ControlError> {
    let checkpoint = &snapshot.history_checkpoint;
    let mut statement = connection
        .prepare(
            "SELECT sequence, message_id, event_sha256, previous_sha256, event_json
             FROM protocol_audit_archive WHERE workspace_id = ?1 ORDER BY sequence",
        )
        .map_err(ControlError::database)?;
    let mut rows = statement
        .query([workspace_id])
        .map_err(ControlError::database)?;
    let mut archived = next_archived_audit_row(&mut rows)?;
    let mut hot = snapshot.audit_events.iter().peekable();
    let mut previous_digest: Option<String> = None;
    let mut fences = verifier.archived_fence_validator();
    for expected_sequence in 1..=checkpoint.audit_event_count {
        let archived_matches = archived
            .as_ref()
            .is_some_and(|(sequence, ..)| *sequence == expected_sequence);
        let hot_matches = hot
            .peek()
            .is_some_and(|event| event.sequence == expected_sequence);
        if archived_matches == hot_matches {
            return Err(ControlError::new(
                "protocol_audit_history_gap",
                format!(
                    "global protocol audit sequence {expected_sequence} is missing or duplicated"
                ),
            ));
        }
        let (digest, event) = if archived_matches {
            let (stored_sequence, stored_message_id, stored_digest, stored_previous, json) =
                archived.take().expect("matching archive row exists");
            verify_digest(
                "archived protocol audit event",
                &stored_digest,
                json.as_bytes(),
            )?;
            let event: AuditEvent = serde_json::from_str(&json).map_err(ControlError::database)?;
            if stored_sequence != event.sequence
                || stored_message_id != audit_message_id(&event).as_str()
                || stored_previous != previous_digest
            {
                return Err(ControlError::new(
                    "protocol_audit_archive_chain_invalid",
                    format!(
                        "archived protocol audit event {stored_sequence} conflicts with its key or predecessor"
                    ),
                ));
            }
            let archived_delivery_exists = connection
                .query_row(
                    "SELECT 1 FROM delivery_archive
                     WHERE workspace_id = ?1 AND message_id = ?2",
                    params![workspace_id, audit_message_id(&event).as_str()],
                    |_| Ok(()),
                )
                .optional()
                .map_err(ControlError::database)?
                .is_some();
            if !archived_delivery_exists {
                return Err(ControlError::new(
                    "protocol_audit_delivery_missing",
                    format!(
                        "archived protocol audit event {stored_sequence} has no archived delivery"
                    ),
                ));
            }
            archived = next_archived_audit_row(&mut rows)?;
            (stored_digest, event)
        } else {
            let event = hot.next().expect("matching hot audit event exists").clone();
            (canonical_digest(&event)?, event)
        };
        if matches!(event.kind, AuditEventKind::MessageAccepted { .. }) {
            validate_archived_fence_event(
                connection,
                workspace_id,
                snapshot,
                &mut fences,
                &event,
                archived_matches,
            )?;
        }
        previous_digest = Some(digest);
    }
    if archived.is_some() || hot.next().is_some() {
        return Err(ControlError::new(
            "protocol_audit_history_overflow",
            "protocol audit rows extend beyond the compact history checkpoint",
        ));
    }
    if previous_digest.as_deref()
        != checkpoint
            .audit_head_sha256
            .as_ref()
            .map(PayloadDigest::as_str)
    {
        return Err(ControlError::new(
            "protocol_audit_head_mismatch",
            "global protocol audit digest head does not match the compact history checkpoint",
        ));
    }
    Ok(())
}

fn validate_archived_fence_event(
    connection: &Connection,
    workspace_id: &str,
    snapshot: &DomainSnapshot,
    fences: &mut ArchivedFenceValidator,
    event: &AuditEvent,
    archived: bool,
) -> Result<(), ControlError> {
    let message_id = audit_message_id(event);
    if archived {
        let delivery = read_archived_delivery(connection, workspace_id, message_id)?
            .ok_or_else(|| ControlError::not_found("archived delivery", message_id.as_str()))?;
        return fences
            .validate_next(event.sequence, &delivery)
            .map_err(ControlError::core);
    }
    let delivery = snapshot
        .deliveries
        .iter()
        .find(|delivery| &delivery.envelope.message_id == message_id)
        .ok_or_else(|| ControlError::not_found("hot delivery", message_id.as_str()))?;
    fences
        .validate_next(event.sequence, delivery)
        .map_err(ControlError::core)
}

#[cfg(test)]
#[allow(clippy::too_many_lines)]
fn hydrate_compact_history(
    connection: &Connection,
    workspace_id: &str,
    snapshot: &mut DomainSnapshot,
) -> Result<(), ControlError> {
    let mut archived_deliveries = connection
        .prepare(
            "SELECT message_id, request_id, sender_actor_id, sender_actor_epoch,
                    message_kind, sent_at_ms, decision_id, candidate_sha, consultation_id,
                    delivery_sha256, delivery_json
             FROM delivery_archive
             WHERE workspace_id = ?1 ORDER BY message_id",
        )
        .map_err(ControlError::database)?;
    let rows = archived_deliveries
        .query_map([workspace_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
            ))
        })
        .map_err(ControlError::database)?;
    let mut delivery_ids: BTreeSet<MessageId> = snapshot
        .deliveries
        .iter()
        .map(|delivery| delivery.envelope.message_id.clone())
        .collect();
    for row in rows {
        let (
            message_id,
            request_id,
            sender_actor_id,
            sender_actor_epoch,
            message_kind,
            sent_at_ms,
            decision_id,
            candidate_sha,
            consultation_id,
            digest,
            json,
        ) = row.map_err(ControlError::database)?;
        verify_digest("archived delivery", &digest, json.as_bytes())?;
        let delivery: DeliverySnapshot =
            serde_json::from_str(&json).map_err(ControlError::database)?;
        validate_delivery_archive_binding(
            workspace_id,
            &message_id,
            request_id.as_deref(),
            &sender_actor_id,
            sender_actor_epoch,
            &message_kind,
            sent_at_ms,
            decision_id.as_deref(),
            candidate_sha.as_deref(),
            consultation_id.as_deref(),
            &delivery,
        )?;
        if !delivery_ids.insert(delivery.envelope.message_id.clone()) {
            return Err(immutable_conflict(
                "delivery_archive",
                delivery.envelope.message_id.as_str(),
            ));
        }
        snapshot.deliveries.push(delivery);
    }

    let mut archived_requests = connection
        .prepare(
            "SELECT request_id, run_id, request_sha256, request_json, run_sha256, run_json
             FROM terminal_request_archive WHERE workspace_id = ?1 ORDER BY request_id",
        )
        .map_err(ControlError::database)?;
    let rows = archived_requests
        .query_map([workspace_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(ControlError::database)?;
    let mut request_ids: BTreeSet<RequestId> = snapshot
        .requests
        .iter()
        .map(|request| request.request_id.clone())
        .collect();
    let mut run_ids = snapshot
        .runs
        .iter()
        .map(|run| run.run_id.clone())
        .collect::<BTreeSet<_>>();
    for row in rows {
        let (request_id, run_id, request_digest, request_json, run_digest, run_json) =
            row.map_err(ControlError::database)?;
        verify_digest("archived request", &request_digest, request_json.as_bytes())?;
        verify_digest("archived run", &run_digest, run_json.as_bytes())?;
        let request: Request =
            serde_json::from_str(&request_json).map_err(ControlError::database)?;
        let run: Run = serde_json::from_str(&run_json).map_err(ControlError::database)?;
        validate_terminal_request_archive_binding(
            workspace_id,
            &request_id,
            &run_id,
            &request,
            &run,
        )?;
        if !request_ids.insert(request.request_id.clone()) || !run_ids.insert(run.run_id.clone()) {
            return Err(immutable_conflict(
                "terminal_request_archive",
                request.request_id.as_str(),
            ));
        }
        snapshot.requests.push(request);
        snapshot.runs.push(run);
    }

    let mut archived_audit = connection
        .prepare(
            "SELECT sequence, event_sha256, previous_sha256, event_json
             FROM protocol_audit_archive WHERE workspace_id = ?1 ORDER BY sequence",
        )
        .map_err(ControlError::database)?;
    let rows = archived_audit
        .query_map([workspace_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(ControlError::database)?;
    let mut audit_sequences = snapshot
        .audit_events
        .iter()
        .map(|event| event.sequence)
        .collect::<BTreeSet<_>>();
    let mut archive_links = BTreeMap::new();
    for row in rows {
        let (stored_sequence, digest, previous_digest, json) =
            row.map_err(ControlError::database)?;
        verify_digest("archived protocol audit event", &digest, json.as_bytes())?;
        let event: AuditEvent = serde_json::from_str(&json).map_err(ControlError::database)?;
        if stored_sequence != to_i64(event.sequence)? {
            return Err(ControlError::new(
                "protocol_audit_archive_key_mismatch",
                format!(
                    "protocol audit SQL sequence {stored_sequence} conflicts with event sequence {}",
                    event.sequence
                ),
            ));
        }
        if !audit_sequences.insert(event.sequence) {
            return Err(immutable_conflict(
                "protocol_audit_archive",
                &event.sequence.to_string(),
            ));
        }
        archive_links.insert(event.sequence, previous_digest);
        snapshot.audit_events.push(event);
    }
    snapshot
        .deliveries
        .sort_by(|left, right| left.envelope.message_id.cmp(&right.envelope.message_id));
    snapshot
        .requests
        .sort_by(|left, right| left.request_id.cmp(&right.request_id));
    snapshot
        .runs
        .sort_by(|left, right| left.run_id.cmp(&right.run_id));
    snapshot.audit_events.sort_by_key(|event| event.sequence);
    for (index, event) in snapshot.audit_events.iter().enumerate() {
        if let Some(stored_previous) = archive_links.get(&event.sequence) {
            let expected = index
                .checked_sub(1)
                .map(|previous| canonical_digest(&snapshot.audit_events[previous]))
                .transpose()?;
            if stored_previous.as_deref() != expected.as_deref() {
                return Err(ControlError::new(
                    "protocol_audit_archive_chain_invalid",
                    format!(
                        "archived protocol audit event {} has an invalid predecessor digest",
                        event.sequence
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn hydrate_message_body(
    connection: &Connection,
    workspace_id: &str,
    message_id: &str,
    expected_digest: Option<&str>,
) -> Result<Option<Message>, ControlError> {
    let row = connection
        .query_row(
            "SELECT content_sha256, body_json FROM message_bodies
             WHERE workspace_id = ?1 AND message_id = ?2",
            params![workspace_id, message_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(ControlError::database)?;
    row.map(|(stored_digest, body_json)| {
        if expected_digest.is_some_and(|expected| expected != stored_digest) {
            return Err(ControlError::new(
                "message_body_digest_mismatch",
                format!("message body `{message_id}` does not match its compact reference"),
            ));
        }
        let mut body: Value = serde_json::from_str(&body_json).map_err(ControlError::database)?;
        hydrate_bulk_markers(connection, workspace_id, &mut body)?;
        let message: Message = serde_json::from_value(body).map_err(ControlError::database)?;
        let canonical = serde_json::to_vec(&message).map_err(ControlError::database)?;
        verify_digest("hydrated message body", &stored_digest, &canonical)?;
        Ok(message)
    })
    .transpose()
}

#[allow(clippy::too_many_lines)]
fn dehydrate_operation_result(
    connection: &Connection,
    workspace_id: &str,
    value: &mut Value,
) -> Result<(), ControlError> {
    if value.get("$agsv_bulk_ref").is_some() {
        let mut verified = value.clone();
        hydrate_bulk_markers(connection, workspace_id, &mut verified)?;
        return Ok(());
    }
    match value {
        Value::Array(values) => {
            for value in values {
                dehydrate_operation_result(connection, workspace_id, value)?;
            }
        }
        Value::Object(object) => {
            if let Some(message_id) = object
                .get("message_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                && let Some(message) = object.get_mut("message")
                && message.get("$agsv_bulk_ref").is_none()
            {
                let row = connection
                    .query_row(
                        "SELECT content_sha256 FROM message_bodies
                         WHERE workspace_id = ?1 AND message_id = ?2",
                        params![workspace_id, message_id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(ControlError::database)?
                    .ok_or_else(|| missing_bulk("message_bodies", &message_id))?;
                let hydrated =
                    hydrate_message_body(connection, workspace_id, &message_id, Some(&row))?
                        .ok_or_else(|| missing_bulk("message_bodies", &message_id))?;
                if *message != serde_json::to_value(hydrated).map_err(ControlError::database)? {
                    return Err(ControlError::new(
                        "operation_result_bulk_mismatch",
                        format!(
                            "operation result message `{message_id}` differs from immutable content"
                        ),
                    ));
                }
                *message = bulk_marker("message_body", &message_id, &row);
            }

            if let Some(request_id) = object
                .get("request_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                && let Some(specification) = object.get_mut("specification")
                && specification.get("message_id").is_none()
                && specification.get("$agsv_bulk_ref").is_none()
            {
                let (digest, raw) = read_raw_and_digest(
                    connection,
                    "request_specifications",
                    "request_id",
                    &request_id,
                    "content_sha256",
                    "specification_json",
                    workspace_id,
                )?
                .ok_or_else(|| missing_bulk("request_specifications", &request_id))?;
                let stored: Value = serde_json::from_str(&raw).map_err(ControlError::database)?;
                if *specification != stored {
                    return Err(ControlError::new(
                        "operation_result_bulk_mismatch",
                        format!(
                            "operation result request `{request_id}` differs from immutable specification"
                        ),
                    ));
                }
                *specification = bulk_marker("request_specification", &request_id, &digest);
            }

            if let Some(decision_id) = object
                .get("decision_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                && let Some(Value::String(rationale)) = object.get_mut("rationale")
            {
                let (digest, stored) = read_raw_and_digest(
                    connection,
                    "decision_rationales",
                    "decision_id",
                    &decision_id,
                    "content_sha256",
                    "rationale",
                    workspace_id,
                )?
                .ok_or_else(|| missing_bulk("decision_rationales", &decision_id))?;
                if *rationale != stored {
                    return Err(ControlError::new(
                        "operation_result_bulk_mismatch",
                        format!(
                            "operation result decision `{decision_id}` differs from immutable rationale"
                        ),
                    ));
                }
                object.insert(
                    "rationale".to_owned(),
                    bulk_marker("decision_rationale", &decision_id, &digest),
                );
            }

            if let Some(Value::Array(evidence)) = object.get_mut("evidence") {
                for item in evidence {
                    if item.get("$agsv_bulk_ref").is_some() {
                        let mut verified = item.clone();
                        hydrate_bulk_markers(connection, workspace_id, &mut verified)?;
                        continue;
                    }
                    let evidence_id = item
                        .get("evidence_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            ControlError::new(
                                "operation_result_evidence_invalid",
                                "operation result evidence has no stable evidence_id",
                            )
                        })?
                        .to_owned();
                    let (digest, raw) = read_raw_and_digest(
                        connection,
                        "evidence_records",
                        "evidence_id",
                        &evidence_id,
                        "content_sha256",
                        "evidence_json",
                        workspace_id,
                    )?
                    .ok_or_else(|| missing_bulk("evidence_records", &evidence_id))?;
                    let stored: Value =
                        serde_json::from_str(&raw).map_err(ControlError::database)?;
                    if *item != stored {
                        return Err(ControlError::new(
                            "operation_result_bulk_mismatch",
                            format!(
                                "operation result evidence `{evidence_id}` differs from immutable content"
                            ),
                        ));
                    }
                    *item = bulk_marker("evidence", &evidence_id, &digest);
                }
            }
            for child in object.values_mut() {
                dehydrate_operation_result(connection, workspace_id, child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn hydrate_bulk_markers(
    connection: &Connection,
    workspace_id: &str,
    value: &mut Value,
) -> Result<(), ControlError> {
    if let Value::Object(object) = value {
        if let (Some(Value::String(kind)), Some(Value::String(id)), Some(Value::String(expected))) = (
            object.get("$agsv_bulk_ref"),
            object.get("id"),
            object.get("sha256"),
        ) {
            *value = match kind.as_str() {
                "request_specification" => read_verified_value(
                    connection,
                    "request_specifications",
                    "request_id",
                    id,
                    "content_sha256",
                    "specification_json",
                    workspace_id,
                    Some(expected),
                )?,
                "decision_rationale" => Value::String(
                    read_verified_raw(
                        connection,
                        "decision_rationales",
                        "decision_id",
                        id,
                        "content_sha256",
                        "rationale",
                        workspace_id,
                        Some(expected),
                    )?
                    .ok_or_else(|| missing_bulk(kind, id))?,
                ),
                "evidence" => read_verified_value(
                    connection,
                    "evidence_records",
                    "evidence_id",
                    id,
                    "content_sha256",
                    "evidence_json",
                    workspace_id,
                    Some(expected),
                )?,
                "message_body" => serde_json::to_value(
                    hydrate_message_body(connection, workspace_id, id, Some(expected))?
                        .ok_or_else(|| missing_bulk(kind, id))?,
                )
                .map_err(ControlError::database)?,
                _ => {
                    return Err(ControlError::new(
                        "unknown_bulk_reference",
                        format!("unknown immutable bulk reference kind `{kind}`"),
                    ));
                }
            };
            return Ok(());
        }
    }
    match value {
        Value::Array(values) => {
            for value in values {
                hydrate_bulk_markers(connection, workspace_id, value)?;
            }
        }
        Value::Object(object) => {
            for value in object.values_mut() {
                hydrate_bulk_markers(connection, workspace_id, value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn read_raw_and_digest(
    connection: &Connection,
    table: &str,
    id_column: &str,
    id: &str,
    digest_column: &str,
    content_column: &str,
    workspace_id: &str,
) -> Result<Option<(String, String)>, ControlError> {
    let query = format!(
        "SELECT {digest_column}, {content_column} FROM {table}
         WHERE workspace_id = ?1 AND {id_column} = ?2"
    );
    connection
        .query_row(&query, params![workspace_id, id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .optional()
        .map_err(ControlError::database)
}

#[allow(clippy::too_many_arguments)]
fn read_verified_raw(
    connection: &Connection,
    table: &str,
    id_column: &str,
    id: &str,
    digest_column: &str,
    content_column: &str,
    workspace_id: &str,
    expected_digest: Option<&str>,
) -> Result<Option<String>, ControlError> {
    let row = read_raw_and_digest(
        connection,
        table,
        id_column,
        id,
        digest_column,
        content_column,
        workspace_id,
    )?;
    row.map(|(digest, content)| {
        if expected_digest.is_some_and(|expected| expected != digest) {
            return Err(ControlError::new(
                "bulk_reference_digest_mismatch",
                format!("immutable {table} ID `{id}` does not match its reference digest"),
            ));
        }
        verify_digest(table, &digest, content.as_bytes())?;
        Ok(content)
    })
    .transpose()
}

#[allow(clippy::too_many_arguments)]
fn read_verified_value(
    connection: &Connection,
    table: &str,
    id_column: &str,
    id: &str,
    digest_column: &str,
    content_column: &str,
    workspace_id: &str,
    expected_digest: Option<&str>,
) -> Result<Value, ControlError> {
    let raw = read_verified_raw(
        connection,
        table,
        id_column,
        id,
        digest_column,
        content_column,
        workspace_id,
        expected_digest,
    )?
    .ok_or_else(|| missing_bulk(table, id))?;
    serde_json::from_str(&raw).map_err(ControlError::database)
}

fn read_verified_json<T: DeserializeOwned>(
    connection: &Connection,
    table: &str,
    id_column: &str,
    id: &str,
    digest_column: &str,
    content_column: &str,
    workspace_id: &str,
) -> Result<Option<T>, ControlError> {
    read_verified_raw(
        connection,
        table,
        id_column,
        id,
        digest_column,
        content_column,
        workspace_id,
        None,
    )?
    .map(|raw| serde_json::from_str(&raw).map_err(ControlError::database))
    .transpose()
}

fn missing_bulk(kind: &str, id: &str) -> ControlError {
    ControlError::new(
        "bulk_content_missing",
        format!("immutable {kind} ID `{id}` is missing"),
    )
}

fn verify_digest(label: &str, expected: &str, content: &[u8]) -> Result<(), ControlError> {
    #[cfg(test)]
    if label == "archive commit" || label.starts_with("archived ") {
        STORE_WORK_ACTIVE.with(|active| {
            if active.get() {
                STORE_ARCHIVE_DIGESTS.with(|count| count.set(count.get() + 1));
            }
        });
    }
    let actual = sha256_hex(content);
    if actual != expected {
        return Err(ControlError::new(
            "bulk_content_digest_mismatch",
            format!("{label} digest verification failed"),
        )
        .with_details(json!({ "expected": expected, "actual": actual })));
    }
    Ok(())
}

fn initialize_schema(connection: &mut Connection) -> Result<(), ControlError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(ControlError::database)?;
    transaction
        .execute_batch(MIGRATION)
        .map_err(ControlError::database)?;
    transaction
        .execute_batch(RETENTION_MIGRATION)
        .map_err(ControlError::database)?;
    transaction
        .execute_batch(RETENTION_INDEX_MIGRATION)
        .map_err(ControlError::database)?;
    transaction
        .execute_batch(REVIEW_MIGRATION)
        .map_err(ControlError::database)?;
    transaction
        .pragma_update(None, "user_version", CONTROL_SCHEMA_VERSION)
        .map_err(ControlError::database)?;
    transaction.commit().map_err(ControlError::database)
}

fn inspect_schema_version(path: &Path) -> Result<i64, ControlError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(ControlError::database)?;
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(ControlError::database)
}

fn ensure_legacy_store_is_quiescent(path: &Path) -> Result<(), ControlError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| legacy_quiescence_unknown(path, &error))?;
    let controller_active = if column_exists(&connection, "domain_state", "controller_active")
        .map_err(|error| legacy_quiescence_unknown(path, &error))?
    {
        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM domain_state WHERE controller_active != 0)",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| legacy_quiescence_unknown(path, &error))?
    } else {
        false
    };
    let live_session = if column_exists(&connection, "sessions", "status")
        .map_err(|error| legacy_quiescence_unknown(path, &error))?
    {
        connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM sessions WHERE status NOT IN ('missing', 'stopped')
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| legacy_quiescence_unknown(path, &error))?
    } else {
        false
    };
    if controller_active || live_session {
        return Err(ControlError::new(
            "state_schema_in_use",
            "older AGSV state is still active and was left untouched",
        )
        .with_details(json!({
            "path": path,
            "controller_active": controller_active,
            "live_session": live_session,
        }))
        .with_hint(
            "stop or drain the older AGSV controller and every live session, then rerun this command",
        ));
    }
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> rusqlite::Result<bool> {
    connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
}

fn column_exists(connection: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    if !table_exists(connection, table)? {
        return Ok(false);
    }
    connection
        .query_row(
            "SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2",
            params![table, column],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
}

fn legacy_quiescence_unknown(path: &Path, error: &impl std::fmt::Display) -> ControlError {
    ControlError::new(
        "state_schema_quiescence_unknown",
        format!(
            "could not establish that older AGSV state at {} is quiescent: {error}",
            path.display()
        ),
    )
    .with_details(json!({ "path": path }))
    .with_hint("stop or drain the older AGSV controller and every session, then rerun")
}

fn preserve_legacy_store(
    directory: &Path,
    schema_version: i64,
    now_ms: u64,
) -> Result<StateStore, ControlError> {
    let preserved_directory = format!("control.schema-v{schema_version}-preserved-{now_ms}");
    let target = directory.join(&preserved_directory);
    reject_symlink(&target)?;
    if target.exists() {
        return Err(ControlError::new(
            "state_schema_preservation_collision",
            format!(
                "preserved state destination already exists: {}",
                target.display()
            ),
        )
        .with_hint("inspect or move the colliding preservation directory, then rerun"));
    }
    let filenames = [
        "control.sqlite3-wal",
        "control.sqlite3-shm",
        "control.sqlite3",
    ]
    .into_iter()
    .filter(|filename| directory.join(filename).exists())
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let plan = SchemaPreservationPlan {
        schema_version,
        preserved_directory,
        filenames,
    };
    write_schema_preservation_marker(directory, &plan)?;
    complete_schema_preservation(directory, &plan)?;
    Err(schema_preserved_error(directory, &plan))
}

fn recover_schema_preservation(directory: &Path) -> Result<Option<ControlError>, ControlError> {
    let marker_path = directory.join(SCHEMA_PRESERVATION_MARKER);
    reject_symlink(&marker_path)?;
    if !marker_path.exists() {
        return Ok(None);
    }
    let marker = fs::read(&marker_path).map_err(|error| {
        ControlError::io("read schema preservation marker", &marker_path, &error)
    })?;
    let plan: SchemaPreservationPlan = serde_json::from_slice(&marker).map_err(|error| {
        ControlError::new(
            "state_schema_preservation_marker_invalid",
            format!("schema preservation marker is invalid: {error}"),
        )
        .with_details(json!({ "path": marker_path }))
        .with_hint("inspect the marker and preserved state before retrying")
    })?;
    validate_schema_preservation_plan(&plan)?;
    complete_schema_preservation(directory, &plan)?;
    Ok(Some(schema_preserved_error(directory, &plan)))
}

fn write_schema_preservation_marker(
    directory: &Path,
    plan: &SchemaPreservationPlan,
) -> Result<(), ControlError> {
    validate_schema_preservation_plan(plan)?;
    let marker_path = directory.join(SCHEMA_PRESERVATION_MARKER);
    let bytes = serde_json::to_vec(plan).map_err(ControlError::database)?;
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
        .map_err(|error| {
            ControlError::io("create schema preservation marker", &marker_path, &error)
        })?;
    marker.write_all(&bytes).map_err(|error| {
        ControlError::io("write schema preservation marker", &marker_path, &error)
    })?;
    marker.sync_all().map_err(|error| {
        ControlError::io("sync schema preservation marker", &marker_path, &error)
    })?;
    sync_directory(directory)?;
    Ok(())
}

fn validate_schema_preservation_plan(plan: &SchemaPreservationPlan) -> Result<(), ControlError> {
    let expected_prefix = format!("control.schema-v{}-preserved-", plan.schema_version);
    let suffix = plan
        .preserved_directory
        .strip_prefix(&expected_prefix)
        .unwrap_or_default();
    let valid_directory = (0..CONTROL_SCHEMA_VERSION).contains(&plan.schema_version)
        && plan.preserved_directory.starts_with(&expected_prefix)
        && !suffix.is_empty()
        && suffix.chars().all(|character| character.is_ascii_digit());
    let allowed = [
        "control.sqlite3-wal",
        "control.sqlite3-shm",
        "control.sqlite3",
    ];
    let canonical_files = allowed
        .iter()
        .filter(|name| plan.filenames.iter().any(|candidate| candidate == **name))
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let valid_files = plan
        .filenames
        .last()
        .is_some_and(|name| name == "control.sqlite3")
        && plan
            .filenames
            .iter()
            .all(|name| allowed.contains(&name.as_str()))
        && plan.filenames == canonical_files;
    if !valid_directory || !valid_files {
        return Err(ControlError::new(
            "state_schema_preservation_marker_invalid",
            "schema preservation marker contains unsafe paths or unsupported state files",
        )
        .with_hint("inspect the marker and preserved state before retrying"));
    }
    Ok(())
}

fn complete_schema_preservation(
    directory: &Path,
    plan: &SchemaPreservationPlan,
) -> Result<(), ControlError> {
    validate_schema_preservation_plan(plan)?;
    let target = directory.join(&plan.preserved_directory);
    reject_symlink(&target)?;
    if !target.exists() {
        fs::create_dir(&target).map_err(|error| {
            ControlError::io("create preserved state directory", &target, &error)
        })?;
        set_mode(&target, 0o700, "secure preserved state directory")?;
        sync_directory(directory)?;
    } else if !target.is_dir() {
        return Err(ControlError::new(
            "state_schema_preservation_collision",
            format!(
                "preserved state destination is not a directory: {}",
                target.display()
            ),
        ));
    } else {
        set_mode(&target, 0o700, "secure preserved state directory")?;
    }
    for filename in &plan.filenames {
        let source = directory.join(filename);
        let destination = target.join(filename);
        reject_symlink(&source)?;
        reject_symlink(&destination)?;
        match (source.exists(), destination.exists()) {
            (true, false) => {
                sync_file(&source)?;
                fs::rename(&source, &destination).map_err(|error| {
                    ControlError::io("preserve older schema state", &source, &error)
                })?;
                sync_file(&destination)?;
                sync_directory(&target)?;
                sync_directory(directory)?;
            }
            (false, true) => {}
            (true, true) => {
                return Err(ControlError::new(
                    "state_schema_preservation_collision",
                    format!(
                        "state file exists at both source and preserved destinations: {}",
                        source.display()
                    ),
                ));
            }
            (false, false) => {
                return Err(ControlError::new(
                    "state_schema_preservation_incomplete",
                    format!("state file is missing during preservation: {filename}"),
                )
                .with_hint(
                    "inspect the preservation marker and backup directory before retrying",
                ));
            }
        }
    }
    for filename in [
        "control.sqlite3-wal",
        "control.sqlite3-shm",
        "control.sqlite3",
    ] {
        if directory.join(filename).exists() {
            return Err(ControlError::new(
                "state_schema_preservation_incomplete",
                format!("unexpected state file appeared during preservation: {filename}"),
            )
            .with_hint("stop every older AGSV process and inspect the preserved state"));
        }
    }
    let marker_path = directory.join(SCHEMA_PRESERVATION_MARKER);
    fs::remove_file(&marker_path).map_err(|error| {
        ControlError::io("remove schema preservation marker", &marker_path, &error)
    })?;
    sync_directory(directory)?;
    Ok(())
}

fn schema_preserved_error(directory: &Path, plan: &SchemaPreservationPlan) -> ControlError {
    let preserved_path = directory.join(&plan.preserved_directory);
    ControlError::new(
        "state_schema_preserved",
        format!(
            "older AGSV schema {} state was preserved at {}; no durable state was migrated",
            plan.schema_version,
            preserved_path.display()
        ),
    )
    .with_details(json!({
        "schema_version": plan.schema_version,
        "preserved_path": preserved_path,
    }))
    .with_hint(format!(
        "rerun the same command to initialize fresh schema-{CONTROL_SCHEMA_VERSION} state; use the matching older AGSV binary to inspect or export the preserved copy"
    ))
}

fn sync_file(path: &Path) -> Result<(), ControlError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| ControlError::io("sync state file", path, &error))
}

fn sync_directory(path: &Path) -> Result<(), ControlError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| ControlError::io("sync state directory", path, &error))
}

fn append_review_control_event(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    operation: &str,
    detail: &Value,
    occurred_at: TimestampMillis,
) -> Result<(), ControlError> {
    let revision = transaction
        .query_row(
            "SELECT revision FROM domain_state WHERE workspace_id = ?1",
            [workspace_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(ControlError::database)?;
    transaction
        .execute(
            "INSERT INTO control_events
             (workspace_id, revision, operation, detail_json, occurred_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                workspace_id,
                revision,
                operation,
                canonical_json(detail)?,
                to_i64(occurred_at.0)?,
            ],
        )
        .map_err(ControlError::database)?;
    compact_control_events(transaction, workspace_id, occurred_at.0)
}

fn review_session_event_operation(state: ReviewSessionState) -> &'static str {
    match (state.status, state.recovery) {
        (ReviewSessionStatus::Preparing, _) => "review.session.preparing",
        (ReviewSessionStatus::Ready, ReviewRecoveryState::NotRequired) => "review.session.ready",
        (ReviewSessionStatus::Ready, _) => "review.session.recovery_required",
        (ReviewSessionStatus::Invalid, _) => "review.session.invalid",
    }
}

fn review_session_event_detail(session: &ReviewSession, begin_operation_id: &str) -> Value {
    json!({
        "session_id": session.session_id.as_str(),
        "request_id": session.request_id.as_str(),
        "candidate_sha": session.tree.candidate_sha.as_str(),
        "tree_sha": session.tree.tree_sha.as_str(),
        "plan_sha256": session.plan.identity.config_digest.as_str(),
        "policy_revision": session.plan.identity.policy_revision.get(),
        "begin_operation_id": begin_operation_id,
        "status": review_session_status_text(session.state.status),
        "recovery": review_recovery_state_text(session.state.recovery),
    })
}

fn review_session_transition_event_detail(session: &ReviewSession, has_error: bool) -> Value {
    json!({
        "session_id": session.session_id.as_str(),
        "request_id": session.request_id.as_str(),
        "candidate_sha": session.tree.candidate_sha.as_str(),
        "status": review_session_status_text(session.state.status),
        "recovery": review_recovery_state_text(session.state.recovery),
        "has_error": has_error,
    })
}

fn review_attempt_event_operation(status: ReviewAttemptStatus) -> &'static str {
    match status {
        ReviewAttemptStatus::Running => "review.attempt.running",
        ReviewAttemptStatus::Passed => "review.attempt.passed",
        ReviewAttemptStatus::Failed => "review.attempt.failed",
        ReviewAttemptStatus::Interrupted => "review.attempt.interrupted",
    }
}

fn review_attempt_event_detail(
    attempt: &ReviewVerificationAttempt,
    verify_operation_id: &str,
) -> Value {
    json!({
        "session_id": attempt.session_id.as_str(),
        "request_id": attempt.request_id.as_str(),
        "candidate_sha": attempt.candidate_sha.as_str(),
        "attempt_record_id": attempt.record_id.as_str(),
        "attempt_sequence": attempt.attempt_sequence,
        "verify_operation_id": verify_operation_id,
        "plan_sha256": attempt.plan.config_digest.as_str(),
        "status": review_attempt_status_text(attempt.status),
    })
}

fn review_environment_event_detail(
    environment: &ReviewEnvironmentRecord,
    path_digest: &PayloadDigest,
) -> Value {
    json!({
        "session_id": environment.session_id.as_str(),
        "request_id": environment.request_id.as_str(),
        "candidate_sha": environment.candidate_sha.as_str(),
        "attempt_sequence": environment.attempt_sequence,
        "environment_id": environment.environment_id.as_str(),
        "check_id": environment.check_id.as_str(),
        "variant": review_execution_variant_text(environment.variant),
        "process_containment": review_process_containment_text(environment.process_containment),
        "path_sha256": path_digest.as_str(),
        "execution_environment_sha256": environment.execution_environment_digest.as_str(),
    })
}

fn review_check_result_event_detail(result: &ReviewCheckResult) -> Value {
    json!({
        "session_id": result.session_id.as_str(),
        "request_id": result.request_id.as_str(),
        "candidate_sha": result.candidate_sha.as_str(),
        "attempt_sequence": result.attempt_sequence,
        "environment_id": result.environment_id.as_str(),
        "check_id": result.check_id.as_str(),
        "variant": review_execution_variant_text(result.variant),
        "outcome": review_check_outcome_text(result.outcome),
        "termination": review_check_termination_text(result.termination),
        "process_tree_may_outlive": result.process_tree_may_outlive,
        "stdout_sha256": result.stdout.digest.as_str(),
        "stderr_sha256": result.stderr.digest.as_str(),
        "stdout_truncated": result.stdout.truncated,
        "stderr_truncated": result.stderr.truncated,
    })
}

fn compact_control_events(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    archived_at_ms: u64,
) -> Result<(), ControlError> {
    let live_floor = transaction
        .query_row(
            "SELECT sequence FROM control_events
             WHERE workspace_id = ?1
             ORDER BY sequence DESC LIMIT 1 OFFSET ?2",
            params![workspace_id, LIVE_CONTROL_EVENT_LIMIT - 1],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(ControlError::database)?;
    let Some(live_floor) = live_floor else {
        return Ok(());
    };
    transaction
        .execute(
            "INSERT OR IGNORE INTO control_event_archive
             (sequence, workspace_id, revision, operation, detail_json,
              occurred_at_ms, archived_at_ms)
             SELECT sequence, workspace_id, revision, operation, detail_json,
                    occurred_at_ms, ?1
             FROM control_events
             WHERE workspace_id = ?2 AND sequence < ?3",
            params![to_i64(archived_at_ms)?, workspace_id, live_floor],
        )
        .map_err(ControlError::database)?;
    let conflict = transaction
        .query_row(
            "SELECT 1
             FROM control_events AS live
             JOIN control_event_archive AS archived
               ON archived.sequence = live.sequence
             WHERE live.workspace_id = ?1 AND live.sequence < ?2
               AND (archived.workspace_id != live.workspace_id
                    OR archived.revision != live.revision
                    OR archived.operation != live.operation
                    OR archived.detail_json != live.detail_json
                    OR archived.occurred_at_ms != live.occurred_at_ms)
             LIMIT 1",
            params![workspace_id, live_floor],
            |_| Ok(()),
        )
        .optional()
        .map_err(ControlError::database)?
        .is_some();
    if conflict {
        return Err(ControlError::new(
            "control_event_archive_conflict",
            "an archived control event conflicts with the live append-only event",
        ));
    }
    transaction
        .execute(
            "DELETE FROM control_events
             WHERE workspace_id = ?1 AND sequence < ?2
               AND EXISTS (
                 SELECT 1 FROM control_event_archive AS archived
                 WHERE archived.sequence = control_events.sequence
                   AND archived.workspace_id = control_events.workspace_id
                   AND archived.revision = control_events.revision
                   AND archived.operation = control_events.operation
                   AND archived.detail_json = control_events.detail_json
                   AND archived.occurred_at_ms = control_events.occurred_at_ms
               )",
            params![workspace_id, live_floor],
        )
        .map_err(ControlError::database)?;
    Ok(())
}

fn session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRecord> {
    let updated = row.get::<_, i64>(9)?;
    Ok(SessionRecord {
        actor_id: row.get(0)?,
        team_id: row.get(1)?,
        working_directory: PathBuf::from(row.get::<_, String>(2)?),
        backend: row.get(3)?,
        runtime: row.get(4)?,
        external_id: row.get(5)?,
        resume_token: row.get(6)?,
        status: row.get(7)?,
        launch_key: row.get(8)?,
        updated_at_ms: u64::try_from(updated).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                9,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
    })
}

fn team_metadata_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TeamMetadataRecord> {
    Ok(TeamMetadataRecord {
        team_id: row.get(0)?,
        purpose: row.get(1)?,
        updated_at_ms: unsigned_from_sql(row.get(2)?, 2)?,
    })
}

fn team_worktree_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TeamWorktreeRecord> {
    let ownership = row.get::<_, String>(2)?;
    let status = row.get::<_, String>(3)?;
    let record = TeamWorktreeRecord {
        team_id: row.get(0)?,
        working_directory: PathBuf::from(row.get::<_, String>(1)?),
        ownership: TeamWorktreeOwnership::from_database(&ownership)?,
        status: TeamWorktreeStatus::from_database(&status)?,
        reason: row.get(4)?,
        error_code: row.get(5)?,
        created_at_ms: unsigned_from_sql(row.get(6)?, 6)?,
        updated_at_ms: unsigned_from_sql(row.get(7)?, 7)?,
    };
    validate_team_worktree_record(&record)
        .map_err(|error| invalid_team_worktree_text(1, error.to_string()))?;
    Ok(record)
}

fn team_worktree_for(
    connection: &Connection,
    workspace_id: &str,
    team_id: &str,
) -> Result<Option<TeamWorktreeRecord>, ControlError> {
    connection
        .query_row(
            "SELECT team_id, working_directory, ownership, status, reason, error_code,
                    created_at_ms, updated_at_ms
             FROM team_worktrees WHERE workspace_id = ?1 AND team_id = ?2",
            params![workspace_id, team_id],
            team_worktree_from_row,
        )
        .optional()
        .map_err(ControlError::database)
}

fn validate_team_worktree_record(record: &TeamWorktreeRecord) -> Result<(), ControlError> {
    validate_team_worktree_identity(record)?;
    validate_team_worktree_ownership_status(record.ownership, record.status)?;
    if record.updated_at_ms < record.created_at_ms {
        return Err(ControlError::new(
            "invalid_team_worktree_record",
            "team worktree update timestamp precedes its creation timestamp",
        ));
    }
    Ok(())
}

fn validate_team_worktree_identity(record: &TeamWorktreeRecord) -> Result<(), ControlError> {
    if record.team_id.is_empty() {
        return Err(ControlError::new(
            "invalid_team_worktree_record",
            "team worktree requires a team ID",
        ));
    }
    if !record.working_directory.is_absolute()
        || record
            .working_directory
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ControlError::new(
            "unsafe_working_directory",
            "team worktree path must be absolute and lexically normalized",
        )
        .with_details(json!({ "working_directory": record.working_directory })));
    }
    let normalized = record.working_directory.components().collect::<PathBuf>();
    if normalized.as_os_str().as_encoded_bytes()
        != record.working_directory.as_os_str().as_encoded_bytes()
    {
        return Err(ControlError::new(
            "unsafe_working_directory",
            "team worktree path must be absolute and lexically normalized",
        )
        .with_details(json!({ "working_directory": record.working_directory })));
    }
    Ok(())
}

fn validate_team_worktree_ownership_status(
    ownership: TeamWorktreeOwnership,
    status: TeamWorktreeStatus,
) -> Result<(), ControlError> {
    let valid = match ownership {
        TeamWorktreeOwnership::Attached => status == TeamWorktreeStatus::AttachedNotOwned,
        TeamWorktreeOwnership::Created => status != TeamWorktreeStatus::AttachedNotOwned,
        TeamWorktreeOwnership::Adopted => !matches!(
            status,
            TeamWorktreeStatus::Creating | TeamWorktreeStatus::AttachedNotOwned
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(ControlError::new(
            "invalid_team_worktree_record",
            "team worktree ownership and lifecycle status are incompatible",
        )
        .with_details(json!({
            "ownership": ownership,
            "status": status,
        })))
    }
}

fn ensure_same_team_worktree_identity(
    existing: &TeamWorktreeRecord,
    proposed: &TeamWorktreeRecord,
) -> Result<(), ControlError> {
    if existing.team_id == proposed.team_id
        && existing.working_directory == proposed.working_directory
        && existing.ownership == proposed.ownership
    {
        return Ok(());
    }
    Err(ControlError::new(
        "team_worktree_conflict",
        "refusing to overwrite a different durable team worktree path or ownership",
    )
    .with_details(json!({
        "existing": {
            "team_id": existing.team_id,
            "working_directory": existing.working_directory,
            "ownership": existing.ownership,
        },
        "proposed": {
            "team_id": proposed.team_id,
            "working_directory": proposed.working_directory,
            "ownership": proposed.ownership,
        },
    })))
}

fn invalid_team_worktree_text(column: usize, message: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            message,
        )),
    )
}

fn presentation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionPresentationRecord> {
    let tab_sequence = row.get::<_, Option<i64>>(4)?;
    let pane_index = row.get::<_, Option<i64>>(5)?;
    let slot = match (tab_sequence, pane_index) {
        (Some(tab_sequence), Some(pane_index)) => Some(PresentationSlot {
            tab_sequence: u32_from_sql(tab_sequence, 4)?,
            pane_index: u32_from_sql(pane_index, 5)?,
        }),
        (None, None) => None,
        _ => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Integer,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "presentation slot is only partially populated",
                )),
            ));
        }
    };
    let sync_state = row.get::<_, String>(7)?;
    Ok(SessionPresentationRecord {
        actor_id: row.get(0)?,
        team_id: row.get(1)?,
        session_label: row.get(2)?,
        desired_label: row.get(3)?,
        slot,
        applied_label: row.get(6)?,
        sync_state: PresentationSyncState::from_database(&sync_state)?,
        last_error: row.get(8)?,
        updated_at_ms: unsigned_from_sql(row.get(9)?, 9)?,
    })
}

fn presentation_for_actor(
    connection: &Connection,
    workspace_id: &str,
    actor_id: &str,
) -> Result<Option<SessionPresentationRecord>, ControlError> {
    connection
        .query_row(
            "SELECT actor_id, team_id, session_label, desired_label, tab_sequence, pane_index,
                    applied_label, sync_state, last_error, updated_at_ms
             FROM session_presentations WHERE workspace_id = ?1 AND actor_id = ?2",
            params![workspace_id, actor_id],
            presentation_from_row,
        )
        .optional()
        .map_err(ControlError::database)
}

fn query_presentations(
    connection: &Connection,
    query: &str,
    workspace_id: &str,
) -> Result<Vec<SessionPresentationRecord>, ControlError> {
    let mut statement = connection.prepare(query).map_err(ControlError::database)?;
    statement
        .query_map([workspace_id], presentation_from_row)
        .map_err(ControlError::database)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(ControlError::database)
}

fn choose_presentation_slot(
    transaction: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    max_panes: u32,
    place_first: bool,
    externally_occupied_sequences: &BTreeSet<u32>,
    reusable_sequences: &BTreeSet<u32>,
) -> Result<PresentationSlot, ControlError> {
    if place_first {
        for pane_index in 1..max_panes {
            if !presentation_slot_occupied(transaction, workspace_id, 0, pane_index)? {
                return Ok(PresentationSlot {
                    tab_sequence: 0,
                    pane_index,
                });
            }
        }
    }

    for &tab_sequence in reusable_sequences {
        let has_launchable_root = transaction
            .query_row(
                "SELECT 1 FROM session_presentations
                 WHERE workspace_id = ?1 AND tab_sequence = ?2 AND pane_index = 0
                       AND team_id IS NOT NULL",
                params![workspace_id, i64::from(tab_sequence)],
                |_| Ok(()),
            )
            .optional()
            .map_err(ControlError::database)?
            .is_some();
        if !has_launchable_root {
            continue;
        }
        for pane_index in 1..max_panes {
            if !presentation_slot_occupied(transaction, workspace_id, tab_sequence, pane_index)? {
                return Ok(PresentationSlot {
                    tab_sequence,
                    pane_index,
                });
            }
        }
    }

    let mut reserved_sequences = externally_occupied_sequences.clone();
    let mut statement = transaction
        .prepare(
            "SELECT DISTINCT tab_sequence FROM presentation_slot_reservations
             WHERE workspace_id = ?1 AND tab_sequence > 0",
        )
        .map_err(ControlError::database)?;
    let stored_sequences = statement
        .query_map([workspace_id], |row| row.get::<_, i64>(0))
        .map_err(ControlError::database)?;
    for sequence in stored_sequences {
        reserved_sequences.insert(
            u32::try_from(sequence.map_err(ControlError::database)?)
                .map_err(ControlError::database)?,
        );
    }
    drop(statement);

    let mut tab_sequence = 1_u32;
    while reserved_sequences.contains(&tab_sequence) {
        tab_sequence = tab_sequence.checked_add(1).ok_or_else(|| {
            ControlError::new(
                "presentation_layout_exhausted",
                "presentation tab sequence exhausted u32",
            )
        })?;
    }
    Ok(PresentationSlot {
        tab_sequence,
        pane_index: 0,
    })
}

fn presentation_slot_occupied(
    connection: &Connection,
    workspace_id: &str,
    tab_sequence: u32,
    pane_index: u32,
) -> Result<bool, ControlError> {
    connection
        .query_row(
            "SELECT 1 FROM presentation_slot_reservations
             WHERE workspace_id = ?1 AND tab_sequence = ?2 AND pane_index = ?3",
            params![workspace_id, i64::from(tab_sequence), i64::from(pane_index)],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(ControlError::database)
}

fn unsigned_from_sql(value: i64, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn u32_from_sql(value: i64, index: usize) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn prepare_directory(path: &Path) -> Result<PathBuf, ControlError> {
    if path.exists() {
        reject_symlink(path)?;
        if !path.is_dir() {
            return Err(ControlError::new(
                "unsafe_path",
                format!("state path is not a directory: {}", path.display()),
            ));
        }
    } else {
        fs::create_dir_all(path)
            .map_err(|error| ControlError::io("create state directory", path, &error))?;
    }
    set_mode(path, 0o700, "secure state directory")?;
    fs::canonicalize(path)
        .map_err(|error| ControlError::io("canonicalize state directory", path, &error))
}

fn set_mode(path: &Path, mode: u32, action: &str) -> Result<(), ControlError> {
    let mut permissions = fs::metadata(path)
        .map_err(|error| ControlError::io("inspect permissions for", path, &error))?
        .permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).map_err(|error| ControlError::io(action, path, &error))
}

fn reject_symlink(path: &Path) -> Result<(), ControlError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ControlError::new(
            "unsafe_path",
            format!(
                "managed state path must not be a symlink: {}",
                path.display()
            ),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ControlError::io("inspect managed state path", path, &error)),
    }
}

fn value_hash(value: &Value) -> Result<String, ControlError> {
    let bytes = serde_json::to_vec(value).map_err(ControlError::database)?;
    Ok(sha256_hex(bytes))
}

fn canonical_json(value: &impl Serialize) -> Result<String, ControlError> {
    let value = serde_json::to_value(value).map_err(ControlError::database)?;
    let mut output = String::new();
    write_canonical_json(&value, &mut output)?;
    Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut String) -> Result<(), ControlError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => {
            output.push_str(&serde_json::to_string(value).map_err(ControlError::database)?);
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key).map_err(ControlError::database)?);
                output.push(':');
                write_canonical_json(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn validate_review_checkout_path(root: &Path, checkout_path: &Path) -> Result<(), ControlError> {
    let normalized = checkout_path.components().collect::<PathBuf>();
    if !checkout_path.is_absolute()
        || checkout_path == root
        || !checkout_path.starts_with(root)
        || normalized.as_os_str().as_encoded_bytes() != checkout_path.as_os_str().as_encoded_bytes()
        || checkout_path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ControlError::new(
            "unsafe_review_checkout",
            format!(
                "review checkout must be a normalized absolute child of {}",
                root.display()
            ),
        )
        .with_details(json!({ "checkout_path": checkout_path })));
    }

    let mut existing = checkout_path;
    let mut missing = Vec::new();
    let canonical_ancestor = loop {
        match fs::symlink_metadata(existing) {
            Ok(_) => {
                break fs::canonicalize(existing).map_err(|error| {
                    ControlError::io("canonicalize review checkout ancestor", existing, &error)
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = existing.file_name().ok_or_else(|| {
                    ControlError::new(
                        "unsafe_review_checkout",
                        "review checkout has no existing canonical ancestor",
                    )
                })?;
                missing.push(name.to_os_string());
                existing = existing.parent().ok_or_else(|| {
                    ControlError::new(
                        "unsafe_review_checkout",
                        "review checkout has no existing canonical ancestor",
                    )
                })?;
            }
            Err(error) => {
                return Err(ControlError::io(
                    "inspect review checkout ancestor",
                    existing,
                    &error,
                ));
            }
        }
    };
    let mut reconstructed = canonical_ancestor;
    for name in missing.into_iter().rev() {
        reconstructed.push(name);
    }
    if reconstructed != checkout_path {
        return Err(ControlError::new(
            "unsafe_review_checkout",
            "review checkout path traverses a symlink or non-canonical ancestor",
        )
        .with_details(json!({
            "checkout_path": checkout_path,
            "canonical_path": reconstructed,
        })));
    }
    Ok(())
}

fn binding_hash(kind: &str, value: &str) -> String {
    sha256_hex(format!("{kind}\0{value}"))
}

fn to_i64(value: u64) -> Result<i64, ControlError> {
    i64::try_from(value)
        .map_err(|error| ControlError::database(format!("integer overflow: {error}")))
}

fn is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(
                code.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}

fn backoff(attempt: u32) {
    thread::sleep(Duration::from_millis(u64::from(attempt.min(10) + 1)));
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    use super::{
        CONTROL_SCHEMA_VERSION, PresentationSlot, PresentationSyncState, SchemaPreservationPlan,
        SessionRecord, StateStore, TeamWorktreeOwnership, TeamWorktreeRecord, TeamWorktreeStatus,
    };
    use agsv_core::{ApplyOutcome, Supervisor};
    use agsv_protocol::{
        Acknowledgement, ActorEpoch, ActorId, ActorRef, ActorStatus, AssignmentEpoch, Cancellation,
        Candidate, CandidateReady, ConsultationRequest, ConsultationResponse, DecisionId,
        DigestAlgorithm, Envelope, Evidence, EvidenceDigest, EvidenceId, EvidenceKind, GitSha,
        ImplementationRequest, Message, MessageId, MessageTarget, PayloadDigest, PolicyRevision,
        RequestId, RequestStatus, ReviewAttemptRecordId, ReviewAttemptStatus, ReviewCheck,
        ReviewCheckId, ReviewCheckOutcome, ReviewCheckResult, ReviewCheckTermination,
        ReviewDecision, ReviewEnvironmentId, ReviewEnvironmentKey, ReviewEnvironmentRecord,
        ReviewExecutionVariant, ReviewOutputArtifact, ReviewPlan, ReviewPlanIdentity,
        ReviewProcessContainment, ReviewRecoveryState, ReviewSession, ReviewSessionId,
        ReviewSessionState, ReviewSessionStatus, ReviewToolId, ReviewToolVersion,
        ReviewToolVersionProbe, ReviewTreeIdentity, ReviewVerdict, ReviewVerificationAttempt,
        TeamId, TeamStatus, TimestampMillis, WorkspaceId,
    };
    use rusqlite::{Connection, params};

    const LEGACY_SCHEMA_FIXTURE: &str = r"
CREATE TABLE domain_state (
  workspace_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL,
  snapshot_json TEXT NOT NULL,
  controller_active INTEGER NOT NULL DEFAULT 0,
  updated_at_ms INTEGER NOT NULL
);
CREATE TABLE sessions (
  workspace_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  status TEXT NOT NULL
);
";
    const BULK_SENTINEL: &str = "SECRET-BULK-SENTINEL-DO-NOT-DUPLICATE";

    fn populated_supervisor(workspace: &str) -> (Supervisor, Envelope, ActorRef, TeamId) {
        let workspace_id = WorkspaceId::new(workspace).unwrap();
        let team_id = TeamId::new("team-retention").unwrap();
        let mut supervisor = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let primary = supervisor
            .activate_primary(ActorId::new("primary-retention").unwrap())
            .unwrap();
        supervisor.create_team(team_id.clone()).unwrap();
        let implementation = supervisor
            .register_implementation(&team_id, ActorId::new("implementation-retention").unwrap())
            .unwrap();
        let envelope = Envelope {
            protocol_version: 1,
            message_id: MessageId::new("message-retention-request").unwrap(),
            workspace_id,
            sender: primary,
            target: MessageTarget::Actor(implementation.actor_id.clone()),
            team_id: Some(team_id.clone()),
            run_id: Some(agsv_protocol::RunId::new("run-retention").unwrap()),
            request_id: Some(agsv_protocol::RequestId::new("request-retention").unwrap()),
            policy_revision: supervisor.policy_revision(),
            primary_epoch: supervisor.primary_epoch(),
            team_epoch: Some(supervisor.team(&team_id).unwrap().epoch),
            assignment_epoch: None,
            sent_at: TimestampMillis(10),
            message: Message::ImplementationRequest(ImplementationRequest {
                title: "Retention fixture".to_owned(),
                instructions: BULK_SENTINEL.to_owned(),
                base_sha: GitSha::new("0000000000000000000000000000000000000000").unwrap(),
                acceptance_criteria: vec![BULK_SENTINEL.to_owned()],
                evidence_requirements: Vec::new(),
            }),
        };
        (supervisor, envelope, implementation, team_id)
    }

    fn review_digest(byte: char) -> PayloadDigest {
        PayloadDigest::new(byte.to_string().repeat(64)).unwrap()
    }

    fn review_json_digest(value: &impl serde::Serialize) -> PayloadDigest {
        let canonical = super::canonical_json(value).unwrap();
        PayloadDigest::new(super::sha256_hex(canonical.as_bytes())).unwrap()
    }

    fn review_bytes_digest(bytes: &[u8]) -> PayloadDigest {
        PayloadDigest::new(super::sha256_hex(bytes)).unwrap()
    }

    fn review_session_fixture(store: &StateStore, workspace_id: &WorkspaceId) -> ReviewSession {
        let checks = vec![ReviewCheck {
            check_id: ReviewCheckId::new("cargo-test").unwrap(),
            argv: vec!["cargo".to_owned(), "test".to_owned()],
            relative_cwd: None,
            timeout_seconds: 60,
            expected_exit_code: 0,
            required_absent_binaries: BTreeSet::new(),
        }];
        let tool_version_probes = vec![ReviewToolVersionProbe {
            tool_id: ReviewToolId::new("cargo").unwrap(),
            argv: vec!["cargo".to_owned(), "--version".to_owned()],
        }];
        let declared_environment =
            BTreeMap::from([(ReviewEnvironmentKey::new("locale").unwrap(), "C".to_owned())]);
        let optional_binaries = BTreeSet::new();
        let config_digest = review_json_digest(&serde_json::json!({
            "checks": &checks,
            "tool_version_probes": &tool_version_probes,
            "declared_environment": &declared_environment,
            "optional_binaries": &optional_binaries,
        }));
        let declared_environment_digest = review_json_digest(&declared_environment);
        ReviewSession {
            session_id: ReviewSessionId::new("review-session-fixture").unwrap(),
            workspace_id: workspace_id.clone(),
            request_id: RequestId::new("request-review-fixture").unwrap(),
            tree: ReviewTreeIdentity {
                candidate_sha: GitSha::new("1".repeat(40)).unwrap(),
                tree_sha: GitSha::new("2".repeat(40)).unwrap(),
            },
            checkout_path: store
                .review_checkout_root()
                .join("review-session-fixture")
                .display()
                .to_string(),
            plan: ReviewPlan {
                identity: ReviewPlanIdentity {
                    policy_revision: PolicyRevision::INITIAL,
                    config_digest,
                },
                checks,
                tool_version_probes,
                declared_environment,
                declared_environment_digest,
                optional_binaries,
            },
            state: ReviewSessionState::new(
                ReviewSessionStatus::Preparing,
                ReviewRecoveryState::NotRequired,
            )
            .unwrap(),
            created_at: TimestampMillis(10),
            updated_at: TimestampMillis(10),
        }
    }

    fn review_attempt_fixture(
        session: &ReviewSession,
        record_id: &str,
        status: ReviewAttemptStatus,
    ) -> ReviewVerificationAttempt {
        let finished_at = (status != ReviewAttemptStatus::Running).then_some(TimestampMillis(22));
        ReviewVerificationAttempt {
            record_id: ReviewAttemptRecordId::new(record_id).unwrap(),
            workspace_id: session.workspace_id.clone(),
            session_id: session.session_id.clone(),
            request_id: session.request_id.clone(),
            candidate_sha: session.tree.candidate_sha.clone(),
            attempt_sequence: 1,
            plan: session.plan.identity.clone(),
            status,
            started_at: TimestampMillis(20),
            finished_at,
            recorded_at: finished_at.unwrap_or(TimestampMillis(20)),
        }
    }

    fn review_environment_fixture(session: &ReviewSession) -> ReviewEnvironmentRecord {
        let execution_environment = BTreeMap::from([
            (ReviewEnvironmentKey::new("os").unwrap(), "macos".to_owned()),
            (
                ReviewEnvironmentKey::new("arch").unwrap(),
                "aarch64".to_owned(),
            ),
            (
                ReviewEnvironmentKey::new("agsv_version").unwrap(),
                "0.3.0".to_owned(),
            ),
            (
                ReviewEnvironmentKey::new("cwd_identity").unwrap(),
                format!("tree:{}", session.tree.tree_sha),
            ),
            (
                ReviewEnvironmentKey::new("path_digest").unwrap(),
                review_digest('f').as_str().to_owned(),
            ),
            (
                ReviewEnvironmentKey::new("declared_values_digest").unwrap(),
                session.plan.declared_environment_digest.as_str().to_owned(),
            ),
        ]);
        let execution_environment_digest = review_json_digest(&execution_environment);
        ReviewEnvironmentRecord {
            environment_id: ReviewEnvironmentId::new("review-environment-fixture").unwrap(),
            workspace_id: session.workspace_id.clone(),
            session_id: session.session_id.clone(),
            request_id: session.request_id.clone(),
            candidate_sha: session.tree.candidate_sha.clone(),
            attempt_sequence: 1,
            plan: session.plan.identity.clone(),
            check_id: session.plan.checks[0].check_id.clone(),
            variant: ReviewExecutionVariant::Normal,
            process_containment: ReviewProcessContainment::ProcessGroupOnly,
            recorded_at: TimestampMillis(20),
            declared_environment_digest: session.plan.declared_environment_digest.clone(),
            execution_environment,
            execution_environment_digest,
            tool_versions: vec![ReviewToolVersion {
                tool_id: ReviewToolId::new("cargo").unwrap(),
                resolved_executable: "/usr/bin/cargo".to_owned(),
                executable_digest: review_digest('4'),
                probe_exit_code: 0,
                version: "cargo 1.0.0".to_owned(),
                stdout: ReviewOutputArtifact {
                    digest: review_bytes_digest(b"cargo 1"),
                    byte_count: 7,
                    truncated: false,
                    reference: Some("environment/cargo.stdout".to_owned()),
                },
                stderr: ReviewOutputArtifact {
                    digest: review_bytes_digest(b""),
                    byte_count: 0,
                    truncated: false,
                    reference: Some("environment/cargo.stderr".to_owned()),
                },
            }],
            binary_observations: Vec::new(),
            required_absent_binaries: BTreeSet::new(),
        }
    }

    fn review_result_fixture(
        session: &ReviewSession,
        environment: &ReviewEnvironmentRecord,
    ) -> ReviewCheckResult {
        ReviewCheckResult {
            workspace_id: session.workspace_id.clone(),
            session_id: session.session_id.clone(),
            request_id: session.request_id.clone(),
            candidate_sha: session.tree.candidate_sha.clone(),
            attempt_sequence: 1,
            plan: session.plan.identity.clone(),
            check_id: session.plan.checks[0].check_id.clone(),
            variant: ReviewExecutionVariant::Normal,
            environment_id: environment.environment_id.clone(),
            outcome: ReviewCheckOutcome::Passed,
            termination: ReviewCheckTermination::Exited,
            expected_exit_code: 0,
            actual_exit_code: Some(0),
            process_tree_may_outlive: false,
            stdout: ReviewOutputArtifact {
                digest: review_bytes_digest(b"success"),
                byte_count: 7,
                truncated: false,
                reference: Some("outputs/stdout".to_owned()),
            },
            stderr: ReviewOutputArtifact {
                digest: review_bytes_digest(b""),
                byte_count: 0,
                truncated: false,
                reference: Some("outputs/stderr".to_owned()),
            },
            started_at: TimestampMillis(20),
            finished_at: TimestampMillis(21),
        }
    }

    fn verify_review_artifact_file(
        expectation: &super::ReviewArtifactExpectation,
    ) -> Result<(), crate::ControlError> {
        let bytes = fs::read(&expectation.path).map_err(|error| {
            crate::ControlError::new(
                "review_artifact_missing",
                format!(
                    "{} artifact is not readable at {}: {error}",
                    expectation.source,
                    expectation.path.display()
                ),
            )
        })?;
        let actual_bytes = u64::try_from(bytes.len()).unwrap();
        if actual_bytes != expectation.byte_count {
            return Err(crate::ControlError::new(
                "review_artifact_size_mismatch",
                format!(
                    "{} artifact has {actual_bytes} bytes; expected {}",
                    expectation.source, expectation.byte_count
                ),
            ));
        }
        let actual_digest = review_bytes_digest(&bytes);
        if actual_digest != expectation.digest {
            return Err(crate::ControlError::new(
                "review_artifact_digest_mismatch",
                format!("{} artifact does not match its SHA-256", expectation.source),
            ));
        }
        Ok(())
    }

    fn insert_unrelated_review_rows(store: &StateStore, workspace_id: &WorkspaceId) {
        let connection = Connection::open(store.path()).unwrap();
        connection
            .execute(
                "WITH digits(value) AS (
                   VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)
                 ), records(value) AS (
                   SELECT a.value * 1000 + b.value * 100 + c.value * 10 + d.value
                   FROM digits a CROSS JOIN digits b CROSS JOIN digits c CROSS JOIN digits d
                 )
                 INSERT INTO review_sessions
                   (workspace_id, session_id, begin_operation_id, request_id,
                    candidate_sha, tree_sha, checkout_path, plan_sha256,
                    record_sha256, record_json, policy_revision, status, recovery,
                    last_error, created_at_ms, updated_at_ms)
                 SELECT ?1, printf('unrelated-session-%05d', value),
                        printf('unrelated-operation-%05d', value),
                        printf('unrelated-request-%05d', value), ?2, ?3,
                        printf('%s/unrelated-%05d', ?4, value), ?5, ?6, '{}',
                        1, 'preparing', 'not_required', NULL, value, value
                 FROM records",
                params![
                    workspace_id.as_str(),
                    "9".repeat(40),
                    "8".repeat(40),
                    store.review_checkout_root().display().to_string(),
                    "7".repeat(64),
                    "6".repeat(64),
                ],
            )
            .unwrap();
        connection
            .execute(
                "WITH digits(value) AS (
                   VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)
                 ), records(value) AS (
                   SELECT a.value * 1000 + b.value * 100 + c.value * 10 + d.value
                   FROM digits a CROSS JOIN digits b CROSS JOIN digits c CROSS JOIN digits d
                 )
                 INSERT INTO review_environment_records
                   (workspace_id, environment_id, session_id, request_id,
                    candidate_sha, attempt_sequence, check_id, variant,
                    process_containment, path_sha256, record_sha256, record_json,
                    recorded_at_ms)
                 SELECT ?1, printf('environment-%05d', value),
                        printf('session-%05d', value), printf('request-%05d', value),
                        ?2, 1, 'check', 'normal', 'process_group_only', ?3, ?4,
                        '{}', value
                 FROM records",
                params![
                    workspace_id.as_str(),
                    "1".repeat(40),
                    "2".repeat(64),
                    "3".repeat(64),
                ],
            )
            .unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM review_environment_records",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            10_000
        );
    }

    fn table_columns(connection: &Connection, table: &str) -> BTreeSet<(String, String, i64, i64)> {
        let mut statement = connection
            .prepare("SELECT name, type, \"notnull\", pk FROM pragma_table_info(?1)")
            .unwrap();
        statement
            .query_map([table], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap()
    }

    #[allow(clippy::too_many_lines)]
    fn assert_current_schema_union(connection: &Connection) {
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, CONTROL_SCHEMA_VERSION);
        assert_eq!(
            table_columns(connection, "domain_state"),
            BTreeSet::from([
                ("controller_active".to_owned(), "INTEGER".to_owned(), 1, 0),
                ("revision".to_owned(), "INTEGER".to_owned(), 1, 0),
                ("snapshot_format".to_owned(), "INTEGER".to_owned(), 1, 0),
                ("snapshot_json".to_owned(), "TEXT".to_owned(), 1, 0),
                ("updated_at_ms".to_owned(), "INTEGER".to_owned(), 1, 0),
                ("workspace_id".to_owned(), "TEXT".to_owned(), 0, 1),
            ])
        );
        assert_eq!(
            table_columns(connection, "sessions"),
            BTreeSet::from([
                ("actor_id".to_owned(), "TEXT".to_owned(), 1, 2),
                ("backend".to_owned(), "TEXT".to_owned(), 1, 0),
                ("external_id".to_owned(), "TEXT".to_owned(), 0, 0),
                ("launch_key".to_owned(), "TEXT".to_owned(), 1, 0),
                ("resume_token".to_owned(), "TEXT".to_owned(), 0, 0),
                ("runtime".to_owned(), "TEXT".to_owned(), 0, 0),
                ("status".to_owned(), "TEXT".to_owned(), 1, 0),
                ("team_id".to_owned(), "TEXT".to_owned(), 0, 0),
                ("updated_at_ms".to_owned(), "INTEGER".to_owned(), 1, 0),
                ("working_directory".to_owned(), "TEXT".to_owned(), 1, 0,),
                ("workspace_id".to_owned(), "TEXT".to_owned(), 1, 1),
            ])
        );
        assert_eq!(
            table_columns(connection, "team_metadata"),
            BTreeSet::from([
                ("purpose".to_owned(), "TEXT".to_owned(), 1, 0),
                ("team_id".to_owned(), "TEXT".to_owned(), 1, 2),
                ("updated_at_ms".to_owned(), "INTEGER".to_owned(), 1, 0),
                ("workspace_id".to_owned(), "TEXT".to_owned(), 1, 1),
            ])
        );
        assert_eq!(
            table_columns(connection, "session_presentations"),
            BTreeSet::from([
                ("actor_id".to_owned(), "TEXT".to_owned(), 1, 2),
                ("applied_label".to_owned(), "TEXT".to_owned(), 0, 0),
                ("desired_label".to_owned(), "TEXT".to_owned(), 1, 0),
                ("last_error".to_owned(), "TEXT".to_owned(), 0, 0),
                ("pane_index".to_owned(), "INTEGER".to_owned(), 0, 0),
                ("session_label".to_owned(), "TEXT".to_owned(), 1, 0),
                ("sync_state".to_owned(), "TEXT".to_owned(), 1, 0),
                ("tab_sequence".to_owned(), "INTEGER".to_owned(), 0, 0),
                ("team_id".to_owned(), "TEXT".to_owned(), 0, 0),
                ("updated_at_ms".to_owned(), "INTEGER".to_owned(), 1, 0),
                ("workspace_id".to_owned(), "TEXT".to_owned(), 1, 1),
            ])
        );
        assert_eq!(
            table_columns(connection, "team_worktrees"),
            BTreeSet::from([
                ("created_at_ms".to_owned(), "INTEGER".to_owned(), 1, 0),
                ("error_code".to_owned(), "TEXT".to_owned(), 0, 0),
                ("ownership".to_owned(), "TEXT".to_owned(), 1, 0),
                ("reason".to_owned(), "TEXT".to_owned(), 0, 0),
                ("status".to_owned(), "TEXT".to_owned(), 1, 0),
                ("team_id".to_owned(), "TEXT".to_owned(), 1, 2),
                ("updated_at_ms".to_owned(), "INTEGER".to_owned(), 1, 0),
                ("working_directory".to_owned(), "TEXT".to_owned(), 1, 0),
                ("workspace_id".to_owned(), "TEXT".to_owned(), 1, 1),
            ])
        );
        let presentation_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'session_presentations'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        for constraint in [
            "UNIQUE(workspace_id, tab_sequence, pane_index)",
            "CHECK ((tab_sequence IS NULL) = (pane_index IS NULL))",
            "CHECK (tab_sequence IS NULL OR tab_sequence >= 0)",
            "CHECK (pane_index IS NULL OR pane_index >= 0)",
        ] {
            assert!(
                presentation_sql.contains(constraint),
                "missing presentation constraint {constraint:?}: {presentation_sql}"
            );
        }
        let retention_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN (
                   'request_specifications', 'message_bodies', 'decision_rationales',
                   'evidence_records', 'delivery_archive', 'terminal_request_archive',
                   'protocol_audit_archive', 'control_event_archive',
                   'presentation_slot_reservations', 'session_presentation_archive',
                   'team_metadata_archive', 'archive_commits', 'archive_commit_entries',
                   'archive_manifest'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let misleading_checkpoints: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'archive_checkpoints'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retention_tables, 14);
        assert_eq!(misleading_checkpoints, 0);
        let review_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN (
                   'review_sessions', 'review_verification_attempts',
                   'review_check_results', 'review_environment_records'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(review_tables, 4);
        assert!(table_columns(connection, "review_sessions").contains(&(
            "checkout_path".to_owned(),
            "TEXT".to_owned(),
            1,
            0,
        )));
        assert!(
            table_columns(connection, "review_verification_attempts").contains(&(
                "attempt_record_id".to_owned(),
                "TEXT".to_owned(),
                1,
                2,
            ))
        );
        let result_columns = table_columns(connection, "review_check_results");
        for column in [
            "termination",
            "process_tree_may_outlive",
            "stdout_truncated",
            "stderr_truncated",
        ] {
            assert!(
                result_columns
                    .iter()
                    .any(|(name, _, not_null, _)| name == column && *not_null == 1),
                "review check result column `{column}` must be durable and required"
            );
        }
        assert!(
            table_columns(connection, "review_environment_records")
                .iter()
                .any(|(name, _, not_null, _)| { name == "process_containment" && *not_null == 1 })
        );
        assert!(
            table_columns(connection, "session_presentation_archive").contains(&(
                "actor_epoch".to_owned(),
                "INTEGER".to_owned(),
                1,
                3,
            ))
        );
    }

    #[test]
    fn schema_v5_is_preserved_with_wal_then_rerun_creates_fresh_current_schema() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("control.sqlite3");
        let legacy = Connection::open(&database).unwrap();
        legacy.execute_batch(LEGACY_SCHEMA_FIXTURE).unwrap();
        legacy.pragma_update(None, "journal_mode", "WAL").unwrap();
        legacy.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        legacy.pragma_update(None, "user_version", 5).unwrap();
        legacy
            .execute(
                "INSERT INTO domain_state
                 (workspace_id, revision, snapshot_json, controller_active, updated_at_ms)
                 VALUES ('workspace-preserve-v5', 41, 'EXACT-LEGACY-SNAPSHOT', 0, 9)",
                [],
            )
            .unwrap();
        legacy
            .execute(
                "INSERT INTO sessions (workspace_id, actor_id, status)
                 VALUES ('workspace-preserve-v5', 'impl-stopped', 'stopped')",
                [],
            )
            .unwrap();
        let main_before = fs::read(&database).unwrap();
        let wal = directory.path().join("control.sqlite3-wal");
        let shm = directory.path().join("control.sqlite3-shm");
        let wal_before = fs::read(&wal).unwrap();
        assert!(shm.exists());

        let workspace_id = WorkspaceId::new("workspace-preserve-v5").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL).snapshot();
        let error =
            StateStore::open(directory.path(), workspace_id.as_str(), &initial, 1_234).unwrap_err();
        assert_eq!(error.code, "state_schema_preserved");
        assert!(error.hint.as_deref().unwrap().contains("rerun"));
        let preserved = fs::canonicalize(directory.path())
            .unwrap()
            .join("control.schema-v5-preserved-1234");
        assert_eq!(
            error.details["preserved_path"],
            preserved.display().to_string()
        );
        assert!(!database.exists());
        assert_eq!(
            fs::read(preserved.join("control.sqlite3")).unwrap(),
            main_before
        );
        assert_eq!(
            fs::read(preserved.join("control.sqlite3-wal")).unwrap(),
            wal_before
        );
        assert!(preserved.join("control.sqlite3-shm").exists());
        drop(legacy);

        let preserved_connection = Connection::open(preserved.join("control.sqlite3")).unwrap();
        let exact: (i64, String) = preserved_connection
            .query_row(
                "SELECT revision, snapshot_json FROM domain_state",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(exact, (41, "EXACT-LEGACY-SNAPSHOT".to_owned()));
        drop(preserved_connection);

        let store =
            StateStore::open(directory.path(), workspace_id.as_str(), &initial, 1_235).unwrap();
        assert_eq!(store.load().unwrap().0, 0);
        assert_current_schema_union(&Connection::open(database).unwrap());
    }

    #[test]
    fn prior_schema_without_archive_manifest_is_preserved_then_rerun_creates_current_schema() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("control.sqlite3");
        let prior_schema_version = CONTROL_SCHEMA_VERSION - 1;
        let workspace_id = WorkspaceId::new("workspace-preserve-prior-schema").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL).snapshot();
        let snapshot_json = serde_json::to_string(&initial).unwrap();
        let mut rejected = Connection::open(&database).unwrap();
        super::initialize_schema(&mut rejected).unwrap();
        rejected.pragma_update(None, "journal_mode", "WAL").unwrap();
        rejected
            .pragma_update(None, "wal_autocheckpoint", 0)
            .unwrap();
        rejected
            .execute_batch(
                "DROP TABLE archive_commit_entries;
                 DROP TABLE archive_commits;
                 DROP TABLE archive_manifest;
                 DROP TABLE review_check_results;
                 DROP TABLE review_environment_records;
                 DROP TABLE review_verification_attempts;
                 DROP TABLE review_sessions;",
            )
            .unwrap();
        rejected
            .pragma_update(None, "user_version", prior_schema_version)
            .unwrap();
        rejected
            .execute(
                "INSERT INTO domain_state
                 (workspace_id, revision, snapshot_json, snapshot_format,
                  controller_active, updated_at_ms)
                 VALUES (?1, 29, ?2, 2, 0, 91)",
                params![workspace_id.as_str(), snapshot_json],
            )
            .unwrap();
        rejected
            .execute(
                "INSERT INTO control_events
                 (workspace_id, revision, operation, detail_json, occurred_at_ms)
                 VALUES (?1, 29, 'prior-schema.fixture', '{\"retained\":true}', 91)",
                [workspace_id.as_str()],
            )
            .unwrap();
        let wal = directory.path().join("control.sqlite3-wal");
        let shm = directory.path().join("control.sqlite3-shm");
        let main_before = fs::read(&database).unwrap();
        let wal_before = fs::read(&wal).unwrap();
        assert!(shm.exists());

        let error =
            StateStore::open(directory.path(), workspace_id.as_str(), &initial, 2_345).unwrap_err();
        let preserved = fs::canonicalize(directory.path()).unwrap().join(format!(
            "control.schema-v{prior_schema_version}-preserved-2345"
        ));
        assert_eq!(error.code, "state_schema_preserved");
        assert_eq!(error.details["schema_version"], prior_schema_version);
        assert_eq!(
            error.details["preserved_path"],
            preserved.display().to_string()
        );
        assert!(error.hint.as_deref().unwrap().contains(&format!(
            "initialize fresh schema-{CONTROL_SCHEMA_VERSION} state"
        )));
        assert!(!database.exists());
        assert_eq!(
            fs::read(preserved.join("control.sqlite3")).unwrap(),
            main_before
        );
        assert_eq!(
            fs::read(preserved.join("control.sqlite3-wal")).unwrap(),
            wal_before
        );
        assert!(preserved.join("control.sqlite3-shm").exists());
        drop(rejected);

        let preserved_connection = Connection::open(preserved.join("control.sqlite3")).unwrap();
        assert_eq!(
            preserved_connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            prior_schema_version
        );
        assert!(!super::table_exists(&preserved_connection, "archive_manifest").unwrap());
        assert!(!super::table_exists(&preserved_connection, "archive_commits").unwrap());
        assert!(!super::table_exists(&preserved_connection, "archive_commit_entries").unwrap());
        assert!(!super::table_exists(&preserved_connection, "review_sessions").unwrap());
        let preserved_state: (i64, String) = preserved_connection
            .query_row(
                "SELECT revision, snapshot_json FROM domain_state WHERE workspace_id = ?1",
                [workspace_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(preserved_state, (29, snapshot_json));
        drop(preserved_connection);

        let store =
            StateStore::open(directory.path(), workspace_id.as_str(), &initial, 2_346).unwrap();
        assert_eq!(store.load().unwrap().0, 0);
        assert_current_schema_union(&Connection::open(database).unwrap());
    }

    #[test]
    fn schema_v0_without_activity_columns_is_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("control.sqlite3");
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE domain_state (workspace_id TEXT PRIMARY KEY, payload TEXT);
                 INSERT INTO domain_state VALUES ('legacy-zero', 'opaque');
                 PRAGMA user_version = 0;",
            )
            .unwrap();
        drop(connection);
        let before = fs::read(&database).unwrap();
        let workspace_id = WorkspaceId::new("workspace-preserve-v0").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL).snapshot();
        let error =
            StateStore::open(directory.path(), workspace_id.as_str(), &initial, 22).unwrap_err();
        assert_eq!(error.code, "state_schema_preserved");
        let preserved = directory.path().join("control.schema-v0-preserved-22");
        assert_eq!(fs::read(preserved.join("control.sqlite3")).unwrap(), before);
        assert!(!database.exists());
    }

    #[test]
    fn active_legacy_state_and_future_schema_are_left_untouched() {
        for (version, active_sql, expected_code) in [
            (
                5,
                "INSERT INTO domain_state VALUES ('legacy-active', 1, '{}', 1, 1)",
                "state_schema_in_use",
            ),
            (
                5,
                "INSERT INTO sessions VALUES ('legacy-active', 'impl-live', 'idle')",
                "state_schema_in_use",
            ),
            (CONTROL_SCHEMA_VERSION + 1, "", "unsupported_state_schema"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let database = directory.path().join("control.sqlite3");
            let connection = Connection::open(&database).unwrap();
            connection.execute_batch(LEGACY_SCHEMA_FIXTURE).unwrap();
            if !active_sql.is_empty() {
                connection.execute(active_sql, []).unwrap();
            }
            connection
                .pragma_update(None, "user_version", version)
                .unwrap();
            drop(connection);
            let before = fs::read(&database).unwrap();
            let workspace_id = WorkspaceId::new(format!("workspace-schema-{version}")).unwrap();
            let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL).snapshot();
            let error = StateStore::open(directory.path(), workspace_id.as_str(), &initial, 30)
                .unwrap_err();
            assert_eq!(error.code, expected_code);
            assert_eq!(fs::read(&database).unwrap(), before);
            assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("preserved")
            }));
        }
    }

    #[test]
    fn preservation_destination_collision_leaves_legacy_state_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("control.sqlite3");
        let connection = Connection::open(&database).unwrap();
        connection.execute_batch(LEGACY_SCHEMA_FIXTURE).unwrap();
        connection.pragma_update(None, "user_version", 5).unwrap();
        drop(connection);
        let before = fs::read(&database).unwrap();
        fs::create_dir(directory.path().join("control.schema-v5-preserved-90")).unwrap();
        let workspace_id = WorkspaceId::new("workspace-preserve-collision").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL).snapshot();
        let error =
            StateStore::open(directory.path(), workspace_id.as_str(), &initial, 90).unwrap_err();
        assert_eq!(error.code, "state_schema_preservation_collision");
        assert_eq!(fs::read(database).unwrap(), before);
        assert!(
            !directory
                .path()
                .join(super::SCHEMA_PRESERVATION_MARKER)
                .exists()
        );
    }

    #[test]
    fn preservation_marker_recovers_a_sidecar_first_partial_move() {
        let directory = tempfile::tempdir().unwrap();
        let main = directory.path().join("control.sqlite3");
        let wal = directory.path().join("control.sqlite3-wal");
        fs::write(&main, b"legacy-main").unwrap();
        fs::write(&wal, b"legacy-wal").unwrap();
        let plan = SchemaPreservationPlan {
            schema_version: 5,
            preserved_directory: "control.schema-v5-preserved-77".to_owned(),
            filenames: vec![
                "control.sqlite3-wal".to_owned(),
                "control.sqlite3".to_owned(),
            ],
        };
        super::write_schema_preservation_marker(directory.path(), &plan).unwrap();
        let preserved = directory.path().join(&plan.preserved_directory);
        fs::create_dir(&preserved).unwrap();
        fs::rename(&wal, preserved.join("control.sqlite3-wal")).unwrap();

        let workspace_id = WorkspaceId::new("workspace-marker-recovery").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL).snapshot();
        let error =
            StateStore::open(directory.path(), workspace_id.as_str(), &initial, 78).unwrap_err();
        assert_eq!(error.code, "state_schema_preserved");
        assert_eq!(
            fs::read(preserved.join("control.sqlite3")).unwrap(),
            b"legacy-main"
        );
        assert_eq!(
            fs::read(preserved.join("control.sqlite3-wal")).unwrap(),
            b"legacy-wal"
        );
        assert!(
            !directory
                .path()
                .join(super::SCHEMA_PRESERVATION_MARKER)
                .exists()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn fresh_current_schema_round_trips_runtime_and_presentation_union() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-fresh-v5").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        store
            .upsert_session(&SessionRecord {
                actor_id: "primary-fresh".to_owned(),
                team_id: None,
                working_directory: PathBuf::from("/workspace"),
                backend: "fixture".to_owned(),
                runtime: None,
                external_id: Some("primary-external".to_owned()),
                resume_token: Some("primary-checkpoint".to_owned()),
                status: "idle".to_owned(),
                launch_key: "primary-launch".to_owned(),
                updated_at_ms: 2,
            })
            .unwrap();
        store
            .upsert_session(&SessionRecord {
                actor_id: "impl-fresh".to_owned(),
                team_id: Some("team-fresh".to_owned()),
                working_directory: PathBuf::from("/workspace/team-fresh"),
                backend: "fixture".to_owned(),
                runtime: Some("fixture-runtime-a".to_owned()),
                external_id: Some("impl-external".to_owned()),
                resume_token: Some("impl-checkpoint".to_owned()),
                status: "idle".to_owned(),
                launch_key: "impl-launch".to_owned(),
                updated_at_ms: 3,
            })
            .unwrap();
        let before = store.session("impl-fresh").unwrap().unwrap();
        store
            .ensure_primary_presentation("primary-fresh", "Primary", "Primary", 4)
            .unwrap();
        store
            .allocate_session_presentation(
                "impl-fresh",
                "team-fresh",
                "Implementation",
                "Implementation · task",
                2,
                true,
                &[],
                &[],
                5,
            )
            .unwrap();
        store
            .mark_presentation_applied("impl-fresh", "Implementation · task", 6)
            .unwrap();
        let after = store.session("impl-fresh").unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(after).unwrap(),
            serde_json::to_value(before).unwrap()
        );
        assert_eq!(
            store.session("primary-fresh").unwrap().unwrap().runtime,
            None
        );
        let schema_version_before: i64 = Connection::open(store.path())
            .unwrap()
            .pragma_query_value(None, "schema_version", |row| row.get(0))
            .unwrap();

        let reopened = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            7,
        )
        .unwrap();
        assert_eq!(
            reopened
                .session("impl-fresh")
                .unwrap()
                .unwrap()
                .runtime
                .as_deref(),
            Some("fixture-runtime-a")
        );
        assert_eq!(
            reopened
                .session_presentation("impl-fresh")
                .unwrap()
                .unwrap()
                .sync_state,
            PresentationSyncState::Applied
        );
        let connection = Connection::open(directory.path().join("control.sqlite3")).unwrap();
        let schema_version_after: i64 = connection
            .pragma_query_value(None, "schema_version", |row| row.get(0))
            .unwrap();
        assert_eq!(schema_version_after, schema_version_before);
        assert_current_schema_union(&connection);
    }

    #[test]
    fn review_begin_fences_domain_revision_and_event_append_is_atomic() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-review-begin-fence").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        let preparing = review_session_fixture(&store, &workspace_id);
        assert_eq!(
            store
                .begin_review_session("review-begin-stale", 1, &preparing)
                .unwrap_err()
                .code,
            "review_session_revision_conflict"
        );
        assert!(
            store
                .review_session(&preparing.session_id)
                .unwrap()
                .is_none()
        );
        assert!(store.events(10).unwrap().is_empty());

        let created = store
            .begin_review_session("review-begin-operation", 0, &preparing)
            .unwrap();
        let (revision, ()) = store
            .mutate("domain.advance", &serde_json::json!({}), 11, |_| Ok(()))
            .unwrap();
        assert_eq!(revision, 1);
        assert_eq!(
            store
                .begin_review_session("review-begin-operation", 0, &preparing)
                .unwrap(),
            created,
            "an exact operation retry returns its durable session even after the domain advances"
        );

        let mut stale = preparing.clone();
        stale.session_id = ReviewSessionId::new("review-session-stale").unwrap();
        stale.request_id = RequestId::new("request-review-stale").unwrap();
        stale.tree.candidate_sha = GitSha::new("3".repeat(40)).unwrap();
        stale.checkout_path = store
            .review_checkout_root()
            .join(stale.session_id.as_str())
            .display()
            .to_string();
        assert_eq!(
            store
                .begin_review_session("review-begin-stale-new", 0, &stale)
                .unwrap_err()
                .code,
            "review_session_revision_conflict"
        );
        assert!(store.review_session(&stale.session_id).unwrap().is_none());

        let connection = Connection::open(store.path()).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER abort_review_begin_event
                 BEFORE INSERT ON control_events
                 WHEN NEW.operation = 'review.session.preparing'
                 BEGIN SELECT RAISE(ABORT, 'injected review event failure'); END;",
            )
            .unwrap();
        let mut event_failure = stale;
        event_failure.session_id = ReviewSessionId::new("review-session-event-failure").unwrap();
        event_failure.request_id = RequestId::new("request-review-event-failure").unwrap();
        event_failure.tree.candidate_sha = GitSha::new("4".repeat(40)).unwrap();
        event_failure.checkout_path = store
            .review_checkout_root()
            .join(event_failure.session_id.as_str())
            .display()
            .to_string();
        assert_eq!(
            store
                .begin_review_session("review-begin-event-failure", 1, &event_failure)
                .unwrap_err()
                .code,
            "state_store_error"
        );
        assert!(
            store
                .review_session(&event_failure.session_id)
                .unwrap()
                .is_none(),
            "the session insert rolls back when its durable event cannot be appended"
        );
        assert_eq!(
            store
                .events(10)
                .unwrap()
                .into_iter()
                .map(|event| event.operation)
                .collect::<Vec<_>>(),
            vec!["review.session.preparing", "domain.advance"]
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn incomplete_output_capture_preserves_observed_exit_code_and_prefix_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-review-incomplete-capture").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        let preparing = review_session_fixture(&store, &workspace_id);
        store
            .begin_review_session("review-incomplete-begin", 0, &preparing)
            .unwrap();
        let ready_state =
            ReviewSessionState::new(ReviewSessionStatus::Ready, ReviewRecoveryState::NotRequired)
                .unwrap();
        let ready = store
            .transition_review_session(
                &preparing.session_id,
                preparing.state,
                ready_state,
                None,
                TimestampMillis(11),
            )
            .unwrap();
        let running = review_attempt_fixture(
            &ready.session,
            "review-incomplete-running",
            ReviewAttemptStatus::Running,
        );
        store
            .append_review_verification_attempt("review-incomplete-verify", &running)
            .unwrap();
        let environment = review_environment_fixture(&ready.session);
        store
            .append_review_environment_record(&review_digest('f'), &environment)
            .unwrap();
        let mut result = review_result_fixture(&ready.session, &environment);
        result.outcome = ReviewCheckOutcome::ExecutionError;
        result.termination = ReviewCheckTermination::OutputCaptureIncomplete;
        result.actual_exit_code = Some(0);
        result.process_tree_may_outlive = true;

        let mut conflated_with_truncation = result.clone();
        conflated_with_truncation.stdout.truncated = true;
        assert_eq!(
            store
                .append_review_check_result(&conflated_with_truncation)
                .unwrap_err()
                .code,
            "invalid_review_check_result"
        );

        assert_eq!(store.append_review_check_result(&result).unwrap(), result);
        let failed = review_attempt_fixture(
            &ready.session,
            "review-incomplete-failed",
            ReviewAttemptStatus::Failed,
        );
        store
            .append_review_verification_attempt("review-incomplete-verify", &failed)
            .unwrap();

        let mut signaled_running = review_attempt_fixture(
            &ready.session,
            "review-incomplete-signaled-running",
            ReviewAttemptStatus::Running,
        );
        signaled_running.attempt_sequence = 2;
        store
            .append_review_verification_attempt(
                "review-incomplete-signaled-verify",
                &signaled_running,
            )
            .unwrap();
        let mut signaled_environment = review_environment_fixture(&ready.session);
        signaled_environment.environment_id =
            ReviewEnvironmentId::new("review-environment-signaled").unwrap();
        signaled_environment.attempt_sequence = 2;
        store
            .append_review_environment_record(&review_digest('f'), &signaled_environment)
            .unwrap();
        let mut signaled_result = result.clone();
        signaled_result.attempt_sequence = 2;
        signaled_result.environment_id = signaled_environment.environment_id;
        signaled_result.actual_exit_code = None;
        store.append_review_check_result(&signaled_result).unwrap();
        let mut signaled_failed = review_attempt_fixture(
            &ready.session,
            "review-incomplete-signaled-failed",
            ReviewAttemptStatus::Failed,
        );
        signaled_failed.attempt_sequence = 2;
        store
            .append_review_verification_attempt(
                "review-incomplete-signaled-verify",
                &signaled_failed,
            )
            .unwrap();
        assert_eq!(
            store
                .review_check_results(&ready.session.session_id, 10)
                .unwrap(),
            vec![signaled_result, result],
            "non-truncated persisted prefixes retain an exit code when the parent produced one"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn review_records_are_idempotent_append_only_and_recoverable_by_exact_identity() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-review-records").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        let preparing = review_session_fixture(&store, &workspace_id);
        let created = store
            .begin_review_session("review-begin-operation", 0, &preparing)
            .unwrap();
        assert_eq!(created.session, preparing);
        let mut forged_plan_digest = preparing.clone();
        forged_plan_digest.plan.declared_environment_digest = review_digest('0');
        assert_eq!(
            store
                .begin_review_session("review-begin-forged-plan", 0, &forged_plan_digest)
                .unwrap_err()
                .code,
            "review_content_digest_mismatch"
        );
        assert_eq!(
            store
                .begin_review_session("review-begin-operation", 0, &preparing)
                .unwrap(),
            created
        );

        let preparing_state = preparing.state;
        let ready_state =
            ReviewSessionState::new(ReviewSessionStatus::Ready, ReviewRecoveryState::NotRequired)
                .unwrap();
        let ready = store
            .transition_review_session(
                &preparing.session_id,
                preparing_state,
                ready_state,
                None,
                TimestampMillis(11),
            )
            .unwrap();
        assert_eq!(ready.session.state, ready_state);
        assert_eq!(ready.session.updated_at, TimestampMillis(11));
        assert_eq!(
            store
                .begin_review_session("review-begin-operation", 0, &preparing)
                .unwrap(),
            ready,
            "retry after a crash between session transition and generic operation result reuses durable state"
        );
        let mut conflicting_begin = preparing.clone();
        conflicting_begin.tree.tree_sha = GitSha::new("4".repeat(40)).unwrap();
        assert_eq!(
            store
                .begin_review_session("review-begin-operation", 0, &conflicting_begin)
                .unwrap_err()
                .code,
            "review_session_conflict"
        );
        assert_eq!(
            store
                .begin_review_session("review-begin-operation-retry", 0, &preparing)
                .unwrap(),
            ready,
            "the same exact candidate identity reuses its one review session"
        );
        assert_eq!(
            store
                .review_session_for_candidate(&preparing.request_id, &preparing.tree.candidate_sha)
                .unwrap()
                .unwrap(),
            ready
        );
        assert_eq!(
            store
                .review_sessions_for_candidate(&preparing.tree.candidate_sha, 1)
                .unwrap(),
            vec![ready.clone()]
        );
        assert_eq!(
            store
                .next_review_attempt_sequence(&preparing.session_id)
                .unwrap(),
            1
        );
        assert!(
            store
                .review_verification_attempts_for_operation(
                    &preparing.session_id,
                    "review-verify-operation"
                )
                .unwrap()
                .is_empty()
        );

        let resume_state = ReviewSessionState::new(
            ReviewSessionStatus::Ready,
            ReviewRecoveryState::ResumeRequired,
        )
        .unwrap();
        store
            .transition_review_session(
                &preparing.session_id,
                ready_state,
                resume_state,
                Some("verification process interrupted"),
                TimestampMillis(12),
            )
            .unwrap();
        assert_eq!(
            store.review_sessions_requiring_recovery(1).unwrap()[0]
                .session
                .session_id,
            preparing.session_id
        );
        let ready = store
            .transition_review_session(
                &preparing.session_id,
                resume_state,
                ready_state,
                None,
                TimestampMillis(13),
            )
            .unwrap();

        let running = review_attempt_fixture(
            &ready.session,
            "review-attempt-running",
            ReviewAttemptStatus::Running,
        );
        let stored_running = store
            .append_review_verification_attempt("review-verify-operation", &running)
            .unwrap();
        assert_eq!(
            store
                .append_review_verification_attempt("review-verify-operation", &running)
                .unwrap(),
            stored_running
        );
        assert_eq!(
            store
                .append_review_verification_attempt("review-verify-operation-other", &running)
                .unwrap_err()
                .code,
            "review_attempt_conflict"
        );
        assert_eq!(
            store
                .review_verification_attempts_for_operation(
                    &preparing.session_id,
                    "review-verify-operation"
                )
                .unwrap(),
            vec![stored_running.clone()]
        );
        let premature_passed = review_attempt_fixture(
            &ready.session,
            "review-attempt-passed",
            ReviewAttemptStatus::Passed,
        );
        assert_eq!(
            store
                .append_review_verification_attempt("review-verify-operation", &premature_passed,)
                .unwrap_err()
                .code,
            "invalid_review_attempt"
        );
        let environment = review_environment_fixture(&ready.session);
        let mut forged_environment_digest = environment.clone();
        forged_environment_digest.execution_environment_digest = review_digest('0');
        assert_eq!(
            store
                .append_review_environment_record(&review_digest('f'), &forged_environment_digest,)
                .unwrap_err()
                .code,
            "review_content_digest_mismatch"
        );
        let stored_environment = store
            .append_review_environment_record(&review_digest('f'), &environment)
            .unwrap();
        assert_eq!(
            store
                .append_review_environment_record(&review_digest('f'), &environment)
                .unwrap(),
            stored_environment
        );
        assert_eq!(
            store
                .append_review_environment_record(&review_digest('0'), &environment)
                .unwrap_err()
                .code,
            "review_environment_path_mismatch"
        );
        let mut conflicting_environment = environment.clone();
        conflicting_environment.recorded_at = TimestampMillis(21);
        assert_eq!(
            store
                .append_review_environment_record(&review_digest('f'), &conflicting_environment,)
                .unwrap_err()
                .code,
            "review_environment_conflict"
        );
        let result = review_result_fixture(&ready.session, &environment);
        assert_eq!(store.append_review_check_result(&result).unwrap(), result);
        assert_eq!(store.append_review_check_result(&result).unwrap(), result);
        let mut conflicting_result = result.clone();
        conflicting_result.stdout.digest = review_digest('8');
        assert_eq!(
            store
                .append_review_check_result(&conflicting_result)
                .unwrap_err()
                .code,
            "review_check_result_conflict"
        );

        let resume_state = ReviewSessionState::new(
            ReviewSessionStatus::Ready,
            ReviewRecoveryState::ResumeRequired,
        )
        .unwrap();
        let resume = store
            .transition_review_session(
                &preparing.session_id,
                ready_state,
                resume_state,
                Some("verification process interrupted again"),
                TimestampMillis(23),
            )
            .unwrap();
        let blocked_running = review_attempt_fixture(
            &resume.session,
            "review-attempt-blocked-running",
            ReviewAttemptStatus::Running,
        );
        assert_eq!(
            store
                .append_review_verification_attempt(
                    "review-verify-operation-blocked",
                    &blocked_running,
                )
                .unwrap_err()
                .code,
            "review_session_not_ready"
        );
        let mut passed = premature_passed;
        passed.finished_at = Some(TimestampMillis(24));
        passed.recorded_at = TimestampMillis(24);
        let stored_passed = store
            .append_review_verification_attempt("review-verify-operation", &passed)
            .unwrap();
        assert_eq!(
            store
                .append_review_verification_attempt("review-verify-operation", &passed)
                .unwrap(),
            stored_passed
        );
        assert_eq!(
            store
                .review_verification_attempts_for_operation(
                    &preparing.session_id,
                    "review-verify-operation"
                )
                .unwrap(),
            vec![stored_running, stored_passed.clone()]
        );
        let ready = store
            .transition_review_session(
                &preparing.session_id,
                resume_state,
                ready_state,
                None,
                TimestampMillis(25),
            )
            .unwrap();
        assert_eq!(
            store
                .next_review_attempt_sequence(&preparing.session_id)
                .unwrap(),
            2
        );
        let aggregate = store
            .review_session_records(&preparing.session_id, 10)
            .unwrap();
        assert_eq!(aggregate.session.session.state, ready_state);
        assert_eq!(aggregate.attempts.len(), 2);
        assert_eq!(
            aggregate.attempts[0].attempt.status,
            ReviewAttemptStatus::Passed
        );
        assert_eq!(aggregate.check_results, vec![result]);
        assert_eq!(aggregate.environments, vec![stored_environment]);

        let failed = review_attempt_fixture(
            &ready.session,
            "review-attempt-conflicting-terminal",
            ReviewAttemptStatus::Failed,
        );
        assert_eq!(
            store
                .append_review_verification_attempt("review-verify-operation", &failed)
                .unwrap_err()
                .code,
            "review_attempt_conflict"
        );
        let invalid_state = ReviewSessionState::new(
            ReviewSessionStatus::Invalid,
            ReviewRecoveryState::RecreateRequired,
        )
        .unwrap();
        store
            .transition_review_session(
                &preparing.session_id,
                ready_state,
                invalid_state,
                Some("checkout identity changed"),
                TimestampMillis(26),
            )
            .unwrap();
        store
            .transition_review_session(
                &preparing.session_id,
                invalid_state,
                preparing_state,
                None,
                TimestampMillis(27),
            )
            .unwrap();
        store
            .transition_review_session(
                &preparing.session_id,
                preparing_state,
                ready_state,
                None,
                TimestampMillis(28),
            )
            .unwrap();
        assert_eq!(
            store
                .events(20)
                .unwrap()
                .into_iter()
                .map(|event| event.operation)
                .collect::<Vec<_>>(),
            vec![
                "review.session.preparing",
                "review.session.ready",
                "review.session.recovery_required",
                "review.session.ready",
                "review.attempt.running",
                "review.environment.recorded",
                "review.check.recorded",
                "review.session.recovery_required",
                "review.attempt.passed",
                "review.session.ready",
                "review.session.invalid",
                "review.session.preparing",
                "review.session.ready",
            ],
            "only committed lifecycle facts emit one append-only event in transaction order"
        );
        let connection = Connection::open(store.path()).unwrap();
        assert!(
            connection
                .execute(
                    "UPDATE review_sessions SET checkout_path = checkout_path || '-forged'",
                    [],
                )
                .unwrap_err()
                .to_string()
                .contains("immutable identity")
        );
        assert!(
            connection
                .execute("DELETE FROM review_sessions", [])
                .unwrap_err()
                .to_string()
                .contains("durable")
        );
        assert!(
            connection
                .execute("DELETE FROM review_verification_attempts", [])
                .unwrap_err()
                .to_string()
                .contains("append-only")
        );
        assert!(
            connection
                .execute("DELETE FROM review_check_results", [])
                .unwrap_err()
                .to_string()
                .contains("append-only")
        );
        assert!(
            connection
                .execute(
                    "UPDATE review_environment_records SET variant = 'normal'",
                    [],
                )
                .unwrap_err()
                .to_string()
                .contains("append-only")
        );
        drop(connection);

        fs::create_dir_all(store.review_checkout_root()).unwrap();
        let outside = directory.path().join("outside-review-root");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, store.review_checkout_root().join("alias")).unwrap();
        let mut unsafe_session = preparing;
        unsafe_session.session_id = ReviewSessionId::new("review-session-unsafe").unwrap();
        unsafe_session.request_id = RequestId::new("request-review-unsafe").unwrap();
        unsafe_session.tree.candidate_sha = GitSha::new("3".repeat(40)).unwrap();
        unsafe_session.checkout_path = store
            .review_checkout_root()
            .join("alias/review-session-unsafe")
            .display()
            .to_string();
        assert_eq!(
            store
                .begin_review_session("review-begin-unsafe", 0, &unsafe_session)
                .unwrap_err()
                .code,
            "unsafe_review_checkout"
        );

        let connection = Connection::open(store.path()).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER review_check_results_no_delete;
                 DELETE FROM review_check_results;",
            )
            .unwrap();
        assert_eq!(
            store
                .review_verification_attempts_for_operation(
                    &ready.session.session_id,
                    "review-verify-operation",
                )
                .unwrap_err()
                .code,
            "invalid_review_attempt",
            "terminal status is revalidated against its immutable results on read"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn review_integrity_diagnostic_streams_rows_and_verifies_external_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-review-integrity").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        let preparing = review_session_fixture(&store, &workspace_id);
        store
            .begin_review_session("review-integrity-begin", 0, &preparing)
            .unwrap();
        let ready_state =
            ReviewSessionState::new(ReviewSessionStatus::Ready, ReviewRecoveryState::NotRequired)
                .unwrap();
        let ready = store
            .transition_review_session(
                &preparing.session_id,
                preparing.state,
                ready_state,
                None,
                TimestampMillis(11),
            )
            .unwrap();
        let running = review_attempt_fixture(
            &ready.session,
            "review-integrity-running",
            ReviewAttemptStatus::Running,
        );
        store
            .append_review_verification_attempt("review-integrity-verify", &running)
            .unwrap();
        let environment = review_environment_fixture(&ready.session);
        store
            .append_review_environment_record(&review_digest('f'), &environment)
            .unwrap();
        let result = review_result_fixture(&ready.session, &environment);
        store.append_review_check_result(&result).unwrap();
        let terminal = review_attempt_fixture(
            &ready.session,
            "review-integrity-passed",
            ReviewAttemptStatus::Passed,
        );
        store
            .append_review_verification_attempt("review-integrity-verify", &terminal)
            .unwrap();

        let checkout = PathBuf::from(&ready.session.checkout_path);
        fs::create_dir_all(checkout.join("environment")).unwrap();
        fs::create_dir_all(checkout.join("outputs")).unwrap();
        let tool_stdout = checkout.join("environment/cargo.stdout");
        let tool_stderr = checkout.join("environment/cargo.stderr");
        let check_stdout = checkout.join("outputs/stdout");
        let check_stderr = checkout.join("outputs/stderr");
        fs::write(&tool_stdout, b"cargo 1").unwrap();
        fs::write(&tool_stderr, b"").unwrap();
        fs::write(&check_stdout, b"success").unwrap();
        fs::write(&check_stderr, b"").unwrap();

        assert_eq!(
            store
                .verify_review_integrity(verify_review_artifact_file)
                .unwrap(),
            super::ReviewIntegrityReport {
                sessions: 1,
                attempt_records: 2,
                environments: 1,
                check_results: 1,
                referenced_artifacts: 4,
            }
        );

        fs::remove_file(&check_stderr).unwrap();
        assert_eq!(
            store
                .verify_review_integrity(verify_review_artifact_file)
                .unwrap_err()
                .code,
            "review_artifact_missing"
        );
        fs::write(&check_stderr, b"").unwrap();

        fs::write(&tool_stdout, b"cargo").unwrap();
        assert_eq!(
            store
                .verify_review_integrity(verify_review_artifact_file)
                .unwrap_err()
                .code,
            "review_artifact_size_mismatch"
        );
        fs::write(&tool_stdout, b"cargo 1").unwrap();

        fs::write(&tool_stdout, b"success").unwrap();
        fs::write(&check_stdout, b"cargo 1").unwrap();
        assert_eq!(
            store
                .verify_review_integrity(verify_review_artifact_file)
                .unwrap_err()
                .code,
            "review_artifact_digest_mismatch",
            "equal-sized artifacts cannot be swapped between typed evidence references"
        );
        fs::write(&tool_stdout, b"cargo 1").unwrap();
        fs::write(&check_stdout, b"success").unwrap();

        let connection = Connection::open(store.path()).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER review_environment_records_no_update;
                 DROP TRIGGER review_check_results_no_update;
                 UPDATE review_environment_records SET process_containment = 'none';",
            )
            .unwrap();
        assert_eq!(
            store
                .verify_review_integrity(verify_review_artifact_file)
                .unwrap_err()
                .code,
            "review_environment_index_mismatch"
        );
        connection
            .execute(
                "UPDATE review_environment_records
                 SET process_containment = 'process_group_only'",
                [],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE review_check_results
                 SET termination = 'timed_out', process_tree_may_outlive = 1,
                     stdout_truncated = 1",
                [],
            )
            .unwrap();
        assert_eq!(
            store
                .verify_review_integrity(verify_review_artifact_file)
                .unwrap_err()
                .code,
            "review_check_result_index_mismatch"
        );
        connection
            .execute(
                "UPDATE review_check_results
                 SET termination = 'exited', process_tree_may_outlive = 0,
                     stdout_truncated = 0, result_json = '{}'",
                [],
            )
            .unwrap();
        assert_eq!(
            store
                .verify_review_integrity(verify_review_artifact_file)
                .unwrap_err()
                .code,
            "bulk_content_digest_mismatch",
            "typed review rows remain digest-bound during the explicit streaming diagnostic"
        );
    }

    #[test]
    fn review_history_is_not_consulted_by_ordinary_load_or_mutate() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-review-hot-path-work").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        let review = review_session_fixture(&store, &workspace_id);
        store
            .begin_review_session("review-hot-path-session", 0, &review)
            .unwrap();
        let (_, small_load) = super::measure_store_work(|| store.load().unwrap());
        let (_, small_mutate) = super::measure_store_work(|| {
            store
                .mutate("review.work.small", &serde_json::json!({}), 2, |_| Ok(()))
                .unwrap()
        });
        let (small_candidate, small_candidate_work) = super::measure_store_work(|| {
            store
                .review_sessions_for_candidate(&review.tree.candidate_sha, 10)
                .unwrap()
        });

        insert_unrelated_review_rows(&store, &workspace_id);

        let (_, large_load) = super::measure_store_work(|| store.load().unwrap());
        let (_, large_mutate) = super::measure_store_work(|| {
            store
                .mutate("review.work.large", &serde_json::json!({}), 3, |_| Ok(()))
                .unwrap()
        });
        let (large_candidate, large_candidate_work) = super::measure_store_work(|| {
            store
                .review_sessions_for_candidate(&review.tree.candidate_sha, 10)
                .unwrap()
        });
        println!(
            "review hot-path work: load small={small_load:?} large={large_load:?}; \
             mutate small={small_mutate:?} large={large_mutate:?}; \
             candidate small={small_candidate_work:?} large={large_candidate_work:?}"
        );
        assert_eq!(small_load.archive_digests, 0);
        assert_eq!(large_load.archive_digests, 0);
        assert_eq!(small_mutate.archive_digests, 0);
        assert_eq!(large_mutate.archive_digests, 0);
        assert!(large_load.vm_steps <= small_load.vm_steps + 64);
        assert!(large_mutate.vm_steps <= small_mutate.vm_steps + 128);
        assert_eq!(small_candidate, large_candidate);
        assert_eq!(large_candidate.len(), 1);
        assert_eq!(small_candidate_work.archive_digests, 0);
        assert_eq!(large_candidate_work.archive_digests, 0);
        assert!(large_candidate_work.vm_steps <= small_candidate_work.vm_steps + 64);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn team_worktree_crud_is_idempotent_and_fences_path_and_ownership() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-team-worktrees").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        let intent = TeamWorktreeRecord {
            team_id: "team-created".to_owned(),
            working_directory: PathBuf::from("/workspace/team-created"),
            ownership: TeamWorktreeOwnership::Created,
            status: TeamWorktreeStatus::Creating,
            reason: None,
            error_code: None,
            created_at_ms: 2,
            updated_at_ms: 2,
        };
        assert_eq!(store.insert_team_worktree(&intent).unwrap(), intent);
        assert_eq!(store.insert_team_worktree(&intent).unwrap(), intent);

        let active = store
            .update_team_worktree_status(
                "team-created",
                &intent.working_directory,
                TeamWorktreeOwnership::Created,
                TeamWorktreeStatus::Active,
                None,
                None,
                3,
            )
            .unwrap();
        assert_eq!(active.status, TeamWorktreeStatus::Active);
        assert_eq!(active.updated_at_ms, 3);
        let repeated = store
            .update_team_worktree_status(
                "team-created",
                &intent.working_directory,
                TeamWorktreeOwnership::Created,
                TeamWorktreeStatus::Active,
                None,
                None,
                30,
            )
            .unwrap();
        assert_eq!(
            repeated, active,
            "an exact outcome retry does not drift time"
        );

        let retained = store
            .update_team_worktree_status(
                "team-created",
                &intent.working_directory,
                TeamWorktreeOwnership::Created,
                TeamWorktreeStatus::RetainedWithReason,
                Some("unique commits remain"),
                Some("worktree_unreachable_commits"),
                4,
            )
            .unwrap();
        assert_eq!(retained.reason.as_deref(), Some("unique commits remain"));
        assert_eq!(
            retained.error_code.as_deref(),
            Some("worktree_unreachable_commits")
        );

        let wrong_path = store
            .update_team_worktree_status(
                "team-created",
                PathBuf::from("/workspace/other").as_path(),
                TeamWorktreeOwnership::Created,
                TeamWorktreeStatus::Removed,
                None,
                None,
                5,
            )
            .unwrap_err();
        assert_eq!(wrong_path.code, "team_worktree_conflict");
        let wrong_ownership = store
            .update_team_worktree_status(
                "team-created",
                &intent.working_directory,
                TeamWorktreeOwnership::Adopted,
                TeamWorktreeStatus::Active,
                None,
                None,
                5,
            )
            .unwrap_err();
        assert_eq!(wrong_ownership.code, "team_worktree_conflict");

        let duplicate_path = TeamWorktreeRecord {
            team_id: "team-other".to_owned(),
            ownership: TeamWorktreeOwnership::Adopted,
            status: TeamWorktreeStatus::Active,
            created_at_ms: 5,
            updated_at_ms: 5,
            ..intent.clone()
        };
        let conflict = store.insert_team_worktree(&duplicate_path).unwrap_err();
        assert_eq!(conflict.code, "team_worktree_conflict");

        let removed = store
            .update_team_worktree_status(
                "team-created",
                &intent.working_directory,
                TeamWorktreeOwnership::Created,
                TeamWorktreeStatus::Removed,
                None,
                None,
                6,
            )
            .unwrap();
        assert_eq!(removed.status, TeamWorktreeStatus::Removed);
        let resurrection = store
            .update_team_worktree_status(
                "team-created",
                &intent.working_directory,
                TeamWorktreeOwnership::Created,
                TeamWorktreeStatus::Active,
                None,
                None,
                7,
            )
            .unwrap_err();
        assert_eq!(resurrection.code, "invalid_team_worktree_transition");

        let unsafe_record = TeamWorktreeRecord {
            team_id: "team-relative".to_owned(),
            working_directory: PathBuf::from("relative/team"),
            ownership: TeamWorktreeOwnership::Created,
            status: TeamWorktreeStatus::Creating,
            reason: None,
            error_code: None,
            created_at_ms: 8,
            updated_at_ms: 8,
        };
        assert_eq!(
            store.insert_team_worktree(&unsafe_record).unwrap_err().code,
            "unsafe_working_directory"
        );
        assert_eq!(
            store.team_worktree("team-created").unwrap().unwrap(),
            removed
        );
        assert_eq!(store.team_worktrees().unwrap(), vec![removed]);
    }

    #[test]
    fn team_purpose_round_trips_and_lists_in_stable_order() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-presentation-records").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();

        store
            .set_team_purpose("team-one", "First purpose", 2)
            .unwrap();
        store
            .set_team_purpose("team-two", "Second purpose", 3)
            .unwrap();
        store
            .set_team_purpose("team-one", "Updated purpose", 4)
            .unwrap();
        assert_eq!(
            store.team_purpose("team-one").unwrap().as_deref(),
            Some("Updated purpose")
        );
        assert_eq!(
            store
                .team_metadata()
                .unwrap()
                .into_iter()
                .map(|metadata| (metadata.team_id, metadata.purpose))
                .collect::<Vec<_>>(),
            [
                ("team-one".to_owned(), "Updated purpose".to_owned()),
                ("team-two".to_owned(), "Second purpose".to_owned()),
            ]
        );
    }

    #[test]
    fn presentations_round_trip_without_changing_allocated_slots() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-presentation-records").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        let primary = store
            .ensure_primary_presentation("primary-one", "Primary", "AGSV Primary", 5)
            .unwrap();
        assert_eq!(primary.slot, None);
        let initial_record = store
            .allocate_session_presentation(
                "impl-one",
                "team-one",
                "Worker",
                "Worker · task",
                2,
                true,
                &[],
                &[],
                6,
            )
            .unwrap();
        assert_eq!(
            initial_record.slot,
            Some(PresentationSlot {
                tab_sequence: 0,
                pane_index: 1,
            })
        );
        let retried = store
            .allocate_session_presentation(
                "impl-one",
                "different-team",
                "Different",
                "Different desired label",
                1,
                false,
                &[7],
                &[8],
                7,
            )
            .unwrap();
        assert_eq!(retried, initial_record);

        let updated = store
            .update_presentation_labels("impl-one", "Renamed", "Renamed · task", 8)
            .unwrap();
        assert_eq!(updated.slot, initial_record.slot);
        assert_eq!(updated.session_label, "Renamed");
        assert_eq!(updated.sync_state, PresentationSyncState::Pending);
        let applied = store
            .mark_presentation_applied("impl-one", "Renamed · task", 9)
            .unwrap();
        assert_eq!(applied.sync_state, PresentationSyncState::Applied);
        assert_eq!(applied.applied_label.as_deref(), Some("Renamed · task"));
        let pending = store
            .mark_presentation_pending("impl-one", Some("temporarily unavailable"), 10)
            .unwrap();
        assert_eq!(pending.sync_state, PresentationSyncState::Pending);
        assert_eq!(
            pending.last_error.as_deref(),
            Some("temporarily unavailable")
        );
        assert_eq!(pending.slot, initial_record.slot);
        assert_eq!(
            store.presentations_for_team("team-one").unwrap(),
            vec![pending.clone()]
        );
        assert_eq!(
            store.session_presentation("impl-one").unwrap(),
            Some(pending)
        );
    }

    #[test]
    fn allocation_uses_default_order_and_only_explicit_reusable_groups() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-default-layout").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();

        let allocate = |actor_id: &str, reusable_sequences: &[u32], now_ms| {
            store
                .allocate_session_presentation(
                    actor_id,
                    "team-layout",
                    actor_id,
                    actor_id,
                    2,
                    true,
                    &[],
                    reusable_sequences,
                    now_ms,
                )
                .unwrap()
                .slot
                .unwrap()
        };
        assert_eq!(
            allocate("impl-1", &[], 2),
            PresentationSlot {
                tab_sequence: 0,
                pane_index: 1
            }
        );
        assert_eq!(
            allocate("impl-2", &[], 3),
            PresentationSlot {
                tab_sequence: 1,
                pane_index: 0
            }
        );
        assert_eq!(
            allocate("impl-3", &[1], 4),
            PresentationSlot {
                tab_sequence: 1,
                pane_index: 1
            }
        );
        assert_eq!(
            allocate("impl-4", &[1], 5),
            PresentationSlot {
                tab_sequence: 2,
                pane_index: 0
            }
        );
    }

    #[test]
    fn configured_primary_tab_capacity_is_filled_before_new_groups() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-primary-capacity").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();

        let allocate = |actor_id: &str, now_ms| {
            store
                .allocate_session_presentation(
                    actor_id,
                    "team-layout",
                    actor_id,
                    actor_id,
                    4,
                    true,
                    &[],
                    &[],
                    now_ms,
                )
                .unwrap()
                .slot
                .unwrap()
        };
        assert_eq!(
            [
                allocate("impl-1", 2),
                allocate("impl-2", 3),
                allocate("impl-3", 4),
                allocate("impl-4", 5),
            ],
            [
                PresentationSlot {
                    tab_sequence: 0,
                    pane_index: 1,
                },
                PresentationSlot {
                    tab_sequence: 0,
                    pane_index: 2,
                },
                PresentationSlot {
                    tab_sequence: 0,
                    pane_index: 3,
                },
                PresentationSlot {
                    tab_sequence: 1,
                    pane_index: 0,
                },
            ]
        );
    }

    #[test]
    fn allocation_skips_external_sequences_and_never_reuses_unapproved_rows() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-layout-collisions").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        let first = store
            .allocate_session_presentation("impl-a", "team-a", "A", "A", 2, false, &[1, 3], &[], 2)
            .unwrap();
        assert_eq!(
            first.slot,
            Some(PresentationSlot {
                tab_sequence: 2,
                pane_index: 0
            })
        );
        let second = store
            .allocate_session_presentation("impl-b", "team-b", "B", "B", 2, false, &[1, 3], &[], 3)
            .unwrap();
        assert_eq!(
            second.slot,
            Some(PresentationSlot {
                tab_sequence: 4,
                pane_index: 0
            })
        );
        let reused = store
            .allocate_session_presentation("impl-c", "team-c", "C", "C", 2, false, &[1, 3], &[2], 4)
            .unwrap();
        assert_eq!(
            reused.slot,
            Some(PresentationSlot {
                tab_sequence: 2,
                pane_index: 1
            })
        );
    }

    #[test]
    fn concurrent_allocations_are_unique_and_restart_safe() {
        const CLIENTS: usize = 8;
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-concurrent-layout").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = Arc::new(
            StateStore::open(
                directory.path(),
                workspace_id.as_str(),
                &initial.snapshot(),
                1,
            )
            .unwrap(),
        );
        let barrier = Arc::new(Barrier::new(CLIENTS));
        let records = std::thread::scope(|scope| {
            (0..CLIENTS)
                .map(|index| {
                    let store = Arc::clone(&store);
                    let barrier = Arc::clone(&barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        store
                            .allocate_session_presentation(
                                &format!("impl-{index}"),
                                "team-concurrent",
                                &format!("Worker {index}"),
                                &format!("Worker {index}"),
                                1,
                                false,
                                &[],
                                &[],
                                u64::try_from(index + 2).unwrap(),
                            )
                            .unwrap()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        let slots = records
            .iter()
            .map(|record| record.slot.unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(slots.len(), CLIENTS);
        assert_eq!(
            slots,
            (1..=u32::try_from(CLIENTS).unwrap())
                .map(|tab_sequence| PresentationSlot {
                    tab_sequence,
                    pane_index: 0,
                })
                .collect()
        );

        drop(store);
        let reopened = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            100,
        )
        .unwrap();
        let next = reopened
            .allocate_session_presentation(
                "impl-after-restart",
                "team-concurrent",
                "After restart",
                "After restart",
                1,
                false,
                &[],
                &[],
                101,
            )
            .unwrap();
        assert_eq!(
            next.slot,
            Some(PresentationSlot {
                tab_sequence: u32::try_from(CLIENTS + 1).unwrap(),
                pane_index: 0,
            })
        );
    }

    #[test]
    fn actor_bindings_namespace_identity_and_fence_epoch_rollbacks() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-bindings").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        let first = ActorRef {
            actor_id: ActorId::new("primary-one").unwrap(),
            actor_epoch: ActorEpoch::INITIAL,
        };
        let replacement = ActorRef {
            actor_id: first.actor_id.clone(),
            actor_epoch: ActorEpoch::new(2).unwrap(),
        };
        let other = ActorRef {
            actor_id: ActorId::new("primary-two").unwrap(),
            actor_epoch: ActorEpoch::INITIAL,
        };

        store.bind_actor("identity-a", "secret", &first, 2).unwrap();
        store
            .bind_actor("identity-a", "secret", &replacement, 3)
            .unwrap();
        assert_eq!(
            store
                .actor_binding("identity-a", "secret")
                .unwrap()
                .unwrap()
                .actor,
            replacement
        );

        let rollback = store
            .bind_actor("identity-a", "secret", &first, 4)
            .unwrap_err();
        assert_eq!(rollback.code, "stale_actor_binding");
        let conflict = store
            .bind_actor("identity-a", "secret", &other, 5)
            .unwrap_err();
        assert_eq!(conflict.code, "actor_binding_conflict");

        store.bind_actor("identity-b", "secret", &other, 6).unwrap();
        assert_eq!(
            store
                .actor_binding("identity-b", "secret")
                .unwrap()
                .unwrap()
                .actor,
            other
        );
    }

    #[test]
    fn replacement_intent_is_durable_and_rejects_a_second_writer() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-replacement-intent").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        store
            .upsert_session(&SessionRecord {
                actor_id: "impl-one".to_owned(),
                team_id: Some("team-one".to_owned()),
                working_directory: PathBuf::from("/workspace/team-one"),
                backend: "fake".to_owned(),
                runtime: Some("fixture-runtime".to_owned()),
                external_id: Some("fake-old".to_owned()),
                resume_token: Some("pane-old".to_owned()),
                status: "stopped".to_owned(),
                launch_key: "create-team:impl-one:1".to_owned(),
                updated_at_ms: 1,
            })
            .unwrap();

        let claimed = store
            .claim_replacement_intent("impl-one", "replacement:operation-one:1", 2)
            .unwrap();
        assert_eq!(claimed.status, "replacement_pending");
        assert_eq!(claimed.runtime.as_deref(), Some("fixture-runtime"));
        assert_eq!(claimed.external_id.as_deref(), Some("fake-old"));
        let retried = store
            .claim_replacement_intent("impl-one", "replacement:operation-one:1", 3)
            .unwrap();
        assert_eq!(retried.launch_key, "replacement:operation-one:1");
        assert_eq!(retried.runtime.as_deref(), Some("fixture-runtime"));
        assert_eq!(retried.resume_token.as_deref(), Some("pane-old"));

        let competing = store
            .claim_replacement_intent("impl-one", "replacement:operation-two:1", 4)
            .unwrap_err();
        assert_eq!(competing.code, "actor_replacement_in_progress");
        assert_eq!(
            store
                .session("impl-one")
                .unwrap()
                .unwrap()
                .runtime
                .as_deref(),
            Some("fixture-runtime")
        );
    }

    #[test]
    fn active_initial_launch_blocks_replacement_intent_regardless_of_launch_key() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-initial-launch-intent").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();

        for (index, status) in ["launching", "launch_failed"].into_iter().enumerate() {
            let launch_key = format!("reconcile-launch-slot-two-{index}");
            store
                .upsert_session(&SessionRecord {
                    actor_id: "impl-two".to_owned(),
                    team_id: Some("team-one".to_owned()),
                    working_directory: PathBuf::from("/workspace/team-one"),
                    backend: "fake".to_owned(),
                    runtime: Some("fixture-runtime".to_owned()),
                    external_id: None,
                    resume_token: None,
                    status: status.to_owned(),
                    launch_key: launch_key.clone(),
                    updated_at_ms: u64::try_from(index + 1).unwrap(),
                })
                .unwrap();

            let error = store
                .claim_replacement_intent("impl-two", "replacement:competing-operation:1", 10)
                .unwrap_err();
            assert_eq!(error.code, "actor_replacement_in_progress");
            let preserved = store.session("impl-two").unwrap().unwrap();
            assert_eq!(preserved.status, status);
            assert_eq!(preserved.launch_key, launch_key);
        }
    }

    #[test]
    fn compact_hot_snapshot_externalizes_bulk_and_operation_results_hydrate_exactly() {
        let directory = tempfile::tempdir().unwrap();
        let (initial, envelope, _, _) = populated_supervisor("workspace-bulk-retention");
        let workspace_id = initial.workspace_id().clone();
        let message_id = envelope.message_id.clone();
        let sent_message = envelope.message.clone();
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        store
            .mutate("message.sent", &serde_json::json!({}), 2, |state| {
                assert_eq!(state.apply(envelope.clone()), Ok(ApplyOutcome::Applied));
                Ok(())
            })
            .unwrap();

        let (_, restored, _) = store.load().unwrap();
        let delivery = restored.delivery(&message_id).unwrap();
        let hydrated = store
            .message_body(&message_id, &delivery.payload_digest)
            .unwrap();
        assert_eq!(hydrated, sent_message);

        let result = serde_json::json!({
            "message_id": message_id,
            "message": sent_message,
            "revision": 1,
        });
        let request = serde_json::json!({ "operation": "send" });
        assert_eq!(
            store
                .record_operation("operation-bulk", "message.send", &request, &result, 3)
                .unwrap(),
            result
        );
        assert_eq!(
            store
                .operation_result("operation-bulk", "message.send", &request)
                .unwrap(),
            Some(result)
        );

        let connection = Connection::open(store.path()).unwrap();
        let hot: String = connection
            .query_row("SELECT snapshot_json FROM domain_state", [], |row| {
                row.get(0)
            })
            .unwrap();
        let body: String = connection
            .query_row("SELECT body_json FROM message_bodies", [], |row| row.get(0))
            .unwrap();
        let result_json: String = connection
            .query_row("SELECT result_json FROM operation_results", [], |row| {
                row.get(0)
            })
            .unwrap();
        let specification: String = connection
            .query_row(
                "SELECT specification_json FROM request_specifications",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!hot.contains(BULK_SENTINEL));
        assert!(!body.contains(BULK_SENTINEL));
        assert!(!result_json.contains(BULK_SENTINEL));
        assert!(specification.contains(BULK_SENTINEL));
    }

    #[test]
    fn immutable_body_conflicts_and_digest_forgery_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let (initial, envelope, _, _) = populated_supervisor("workspace-digest-retention");
        let workspace_id = initial.workspace_id().clone();
        let message_id = envelope.message_id.clone();
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        store
            .mutate("message.sent", &serde_json::json!({}), 2, |state| {
                state
                    .apply(envelope.clone())
                    .map(|_| ())
                    .map_err(crate::ControlError::core)
            })
            .unwrap();
        let connection = Connection::open(store.path()).unwrap();
        let request_id = envelope.request_id.clone().unwrap();
        let (original_spec_digest, original_spec_json): (String, String) = connection
            .query_row(
                "SELECT content_sha256, specification_json FROM request_specifications
                 WHERE request_id = ?1",
                [request_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let forged_spec_json = serde_json::to_string(&ImplementationRequest {
            title: "forged accepted input".to_owned(),
            instructions: "forged".to_owned(),
            base_sha: GitSha::new("0000000000000000000000000000000000000000").unwrap(),
            acceptance_criteria: Vec::new(),
            evidence_requirements: Vec::new(),
        })
        .unwrap();
        connection
            .execute_batch("DROP TRIGGER request_specifications_no_update")
            .unwrap();
        connection
            .execute(
                "UPDATE request_specifications SET content_sha256 = ?1, specification_json = ?2
                 WHERE request_id = ?3",
                params![
                    crate::identity::sha256_hex(forged_spec_json.as_bytes()),
                    forged_spec_json,
                    request_id.as_str()
                ],
            )
            .unwrap();
        let (_, restored, _) = store.load().unwrap();
        let error = store
            .request_specification(restored.request(&request_id).unwrap())
            .unwrap_err();
        assert_eq!(error.code, "bulk_reference_digest_mismatch");
        connection
            .execute(
                "UPDATE request_specifications SET content_sha256 = ?1, specification_json = ?2
                 WHERE request_id = ?3",
                params![
                    original_spec_digest,
                    original_spec_json,
                    request_id.as_str()
                ],
            )
            .unwrap();
        let append_only = connection.execute(
            "UPDATE message_bodies SET body_json = '{}' WHERE message_id = ?1",
            [message_id.as_str()],
        );
        assert!(append_only.is_err());
        connection
            .execute_batch("DROP TRIGGER message_bodies_no_update")
            .unwrap();
        connection
            .execute(
                "UPDATE message_bodies SET content_sha256 = ?1 WHERE message_id = ?2",
                params!["0".repeat(64), message_id.as_str()],
            )
            .unwrap();
        let (_, restored, _) = store.load().unwrap();
        let expected = &restored.delivery(&message_id).unwrap().payload_digest;
        let error = store.message_body(&message_id, expected).unwrap_err();
        assert_eq!(error.code, "message_body_digest_mismatch");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn unanswered_consultation_stays_hot_until_retired_response_pair_exists() {
        let directory = tempfile::tempdir().unwrap();
        let (initial, template, implementation, team_id) =
            populated_supervisor("workspace-consultation-retention");
        let workspace_id = initial.workspace_id().clone();
        let primary = template.sender;
        let team_epoch = initial.team(&team_id).unwrap().epoch;
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        let consultation_id = MessageId::new("message-consultation-request").unwrap();
        let request = Envelope {
            protocol_version: 1,
            message_id: consultation_id.clone(),
            workspace_id: workspace_id.clone(),
            sender: primary.clone(),
            target: MessageTarget::Team(team_id.clone()),
            team_id: Some(team_id.clone()),
            run_id: None,
            request_id: None,
            policy_revision: initial.policy_revision(),
            primary_epoch: initial.primary_epoch(),
            team_epoch: Some(team_epoch),
            assignment_epoch: None,
            sent_at: TimestampMillis(10),
            message: Message::ConsultationRequest(ConsultationRequest {
                consultation_id: consultation_id.clone(),
                target_team_id: team_id.clone(),
                subject: "retention pairing".to_owned(),
                question: "does the unanswered request stay hot?".to_owned(),
                evidence: Vec::new(),
            }),
        };
        store
            .mutate("message.sent", &serde_json::json!({}), 2, |state| {
                state
                    .apply(request.clone())
                    .map(|_| ())
                    .map_err(crate::ControlError::core)
            })
            .unwrap();
        store
            .mutate("message.ack", &serde_json::json!({}), 3, |state| {
                state
                    .acknowledge(Acknowledgement {
                        workspace_id: workspace_id.clone(),
                        message_id: consultation_id.clone(),
                        actor: implementation.clone(),
                        acknowledged_at: TimestampMillis(11),
                    })
                    .map(|_| ())
                    .map_err(crate::ControlError::core)
            })
            .unwrap();
        let (_, waiting, _) = store.load().unwrap();
        assert!(waiting.delivery(&consultation_id).is_some());
        assert_eq!(
            Connection::open(store.path())
                .unwrap()
                .query_row("SELECT COUNT(*) FROM delivery_archive", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );

        let response_id = MessageId::new("message-consultation-response").unwrap();
        let response = Envelope {
            protocol_version: 1,
            message_id: response_id.clone(),
            workspace_id: workspace_id.clone(),
            sender: implementation.clone(),
            target: MessageTarget::Primary,
            team_id: Some(team_id.clone()),
            run_id: None,
            request_id: None,
            policy_revision: initial.policy_revision(),
            primary_epoch: initial.primary_epoch(),
            team_epoch: Some(team_epoch),
            assignment_epoch: None,
            sent_at: TimestampMillis(12),
            message: Message::ConsultationResponse(ConsultationResponse {
                consultation_id: consultation_id.clone(),
                responding_team_id: team_id,
                response: "yes, until this response is retired".to_owned(),
                evidence: Vec::new(),
            }),
        };
        store
            .mutate("message.sent", &serde_json::json!({}), 4, |state| {
                state
                    .apply(response.clone())
                    .map(|_| ())
                    .map_err(crate::ControlError::core)
            })
            .unwrap();
        store
            .mutate("message.ack", &serde_json::json!({}), 5, |state| {
                state
                    .acknowledge(Acknowledgement {
                        workspace_id: workspace_id.clone(),
                        message_id: response_id.clone(),
                        actor: primary.clone(),
                        acknowledged_at: TimestampMillis(13),
                    })
                    .map(|_| ())
                    .map_err(crate::ControlError::core)
            })
            .unwrap();
        let (_, bounded, _) = store.load().unwrap();
        assert!(bounded.snapshot().deliveries.is_empty());
        assert!(store.archived_delivery(&consultation_id).unwrap().is_some());
        assert!(store.archived_delivery(&response_id).unwrap().is_some());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn delivery_and_terminal_request_archive_only_after_safe_acknowledgement() {
        let directory = tempfile::tempdir().unwrap();
        let (initial, request_envelope, implementation, team_id) =
            populated_supervisor("workspace-terminal-retention");
        let workspace_id = initial.workspace_id().clone();
        let primary = request_envelope.sender.clone();
        let request_id = request_envelope.request_id.clone().unwrap();
        let run_id = request_envelope.run_id.clone().unwrap();
        let request_message_id = request_envelope.message_id.clone();
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        store
            .mutate("request.created", &serde_json::json!({}), 2, |state| {
                state
                    .apply(request_envelope.clone())
                    .map(|_| ())
                    .map_err(crate::ControlError::core)
            })
            .unwrap();
        store
            .mutate("message.ack", &serde_json::json!({}), 3, |state| {
                state
                    .acknowledge(Acknowledgement {
                        workspace_id: workspace_id.clone(),
                        message_id: request_message_id.clone(),
                        actor: implementation.clone(),
                        acknowledged_at: TimestampMillis(20),
                    })
                    .map(|_| ())
                    .map_err(crate::ControlError::core)
            })
            .unwrap();
        let connection = Connection::open(store.path()).unwrap();
        let archived_while_open: i64 = connection
            .query_row("SELECT COUNT(*) FROM delivery_archive", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(archived_while_open, 0);
        drop(connection);

        let cancellation_id = MessageId::new("message-retention-cancel").unwrap();
        let cancellation = Envelope {
            protocol_version: 1,
            message_id: cancellation_id.clone(),
            workspace_id: workspace_id.clone(),
            sender: primary,
            target: MessageTarget::Actor(implementation.actor_id.clone()),
            team_id: Some(team_id.clone()),
            run_id: Some(run_id),
            request_id: Some(request_id.clone()),
            policy_revision: initial.policy_revision(),
            primary_epoch: initial.primary_epoch(),
            team_epoch: Some(initial.team(&team_id).unwrap().epoch),
            assignment_epoch: None,
            sent_at: TimestampMillis(30),
            message: Message::Cancellation(Cancellation {
                reason: "fixture complete".to_owned(),
            }),
        };
        store
            .mutate("request.cancelled", &serde_json::json!({}), 4, |state| {
                state
                    .apply(cancellation.clone())
                    .map(|_| ())
                    .map_err(crate::ControlError::core)
            })
            .unwrap();
        let connection = Connection::open(store.path()).unwrap();
        let (archived_delivery, archived_request): (i64, i64) = (
            connection
                .query_row("SELECT COUNT(*) FROM delivery_archive", [], |row| {
                    row.get(0)
                })
                .unwrap(),
            connection
                .query_row("SELECT COUNT(*) FROM terminal_request_archive", [], |row| {
                    row.get(0)
                })
                .unwrap(),
        );
        assert_eq!((archived_delivery, archived_request), (0, 0));
        drop(connection);

        let barrier = Arc::new(Barrier::new(2));
        let total_attempts = Arc::new(AtomicUsize::new(0));
        let threads = (0..2_u64)
            .map(|thread_index| {
                let store = store.clone();
                let barrier = Arc::clone(&barrier);
                let attempts = Arc::new(AtomicUsize::new(0));
                let total_attempts = Arc::clone(&total_attempts);
                let workspace_id = workspace_id.clone();
                let cancellation_id = cancellation_id.clone();
                let implementation = implementation.clone();
                std::thread::spawn(move || {
                    store
                        .mutate(
                            &format!("message.concurrent_ack.{thread_index}"),
                            &serde_json::json!({}),
                            5 + thread_index,
                            |state| {
                                total_attempts.fetch_add(1, Ordering::SeqCst);
                                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                                    state
                                        .acknowledge(Acknowledgement {
                                            workspace_id: workspace_id.clone(),
                                            message_id: cancellation_id.clone(),
                                            actor: implementation.clone(),
                                            acknowledged_at: TimestampMillis(40),
                                        })
                                        .map_err(crate::ControlError::core)?;
                                    barrier.wait();
                                }
                                Ok(())
                            },
                        )
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(total_attempts.load(Ordering::SeqCst), 3);
        let connection = Connection::open(store.path()).unwrap();
        let hot_json: String = connection
            .query_row("SELECT snapshot_json FROM domain_state", [], |row| {
                row.get(0)
            })
            .unwrap();
        let hot: serde_json::Value = serde_json::from_str(&hot_json).unwrap();
        assert_eq!(hot["deliveries"].as_array().unwrap().len(), 0);
        assert_eq!(hot["requests"].as_array().unwrap().len(), 0);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM delivery_archive", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM terminal_request_archive", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
        drop(connection);
        let (_, bounded, _) = store.load().unwrap();
        assert!(bounded.snapshot().deliveries.is_empty());
        assert!(bounded.request(&request_id).is_none());
        assert!(
            store
                .archived_delivery(&request_message_id)
                .unwrap()
                .is_some()
        );
        assert!(store.archived_request(&request_id).unwrap().is_some());
        assert_eq!(
            store
                .archived_request(&request_id)
                .unwrap()
                .unwrap()
                .0
                .status,
            RequestStatus::Cancelled
        );
        let archived_outcomes = store.request_outcomes(&[], 10).unwrap();
        assert_eq!(archived_outcomes.len(), 1);
        assert_eq!(archived_outcomes[0].request_id, request_id);
        assert_eq!(archived_outcomes[0].status, RequestStatus::Cancelled);

        let mut hot_outcome = archived_outcomes[0].clone();
        hot_outcome.request_id = RequestId::new("request-retention-hot").unwrap();
        hot_outcome.run_id = agsv_protocol::RunId::new("run-retention-hot").unwrap();
        let merged = store
            .request_outcomes(std::slice::from_ref(&hot_outcome), 2)
            .unwrap();
        assert_eq!(
            merged
                .iter()
                .map(|request| request.request_id.as_str())
                .collect::<Vec<_>>(),
            vec![request_id.as_str(), hot_outcome.request_id.as_str()]
        );
        assert_eq!(
            store
                .request_outcomes(std::slice::from_ref(&hot_outcome), 1)
                .unwrap()[0]
                .request_id,
            hot_outcome.request_id
        );
        assert_eq!(
            store
                .request_outcomes(&archived_outcomes, 1)
                .unwrap_err()
                .code,
            "request_outcome_id_conflict"
        );
        let protocol_events = store.protocol_events(bounded.audit_events(), 10).unwrap();
        assert_eq!(protocol_events.len(), 4);
        assert_eq!(
            protocol_events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        let (revision_before_reuse, _, _) = store.load().unwrap();
        let reuse = store
            .mutate(
                "request.reused_archived_ids",
                &serde_json::json!({}),
                41,
                |state| {
                    state
                        .apply(request_envelope.clone())
                        .map(|_| ())
                        .map_err(crate::ControlError::core)
                },
            )
            .unwrap_err();
        assert_eq!(reuse.code, "hot_archive_delivery_overlap");
        let (revision_after_reuse, after_reuse, _) = store.load().unwrap();
        assert_eq!(revision_after_reuse, revision_before_reuse);
        assert!(after_reuse.snapshot().deliveries.is_empty());
        assert!(after_reuse.snapshot().requests.is_empty());
        let mut explicit_full_history = bounded.snapshot();
        super::hydrate_compact_history(
            &Connection::open(store.path()).unwrap(),
            workspace_id.as_str(),
            &mut explicit_full_history,
        )
        .unwrap();
        assert_eq!(explicit_full_history.deliveries.len(), 2);
        let connection = Connection::open(store.path()).unwrap();
        connection
            .execute_batch("DROP TRIGGER protocol_audit_archive_no_update")
            .unwrap();
        connection
            .execute(
                "UPDATE protocol_audit_archive SET sequence = 99
                 WHERE sequence = (SELECT MIN(sequence) FROM protocol_audit_archive)",
                [],
            )
            .unwrap();
        store.load().unwrap();
        let error = store.verify_archive_integrity().unwrap_err();
        assert_eq!(error.code, "archive_commit_entry_mismatch");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn completed_cycles_keep_hot_snapshot_bounded_while_archives_grow() {
        let directory = tempfile::tempdir().unwrap();
        let (initial, template, implementation, team_id) =
            populated_supervisor("workspace-bounded-retention");
        let workspace_id = initial.workspace_id().clone();
        let primary = template.sender.clone();
        let team_epoch = initial.team(&team_id).unwrap().epoch;
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        store
            .mutate(
                "retention.work_probe.anchor",
                &serde_json::json!({}),
                2,
                |state| {
                    state
                        .apply(template.clone())
                        .map(|_| ())
                        .map_err(crate::ControlError::core)
                },
            )
            .unwrap();
        let mut first_bytes = 0_i64;
        let mut small_load_work = None;
        let mut small_mutate_work = None;
        let mut small_verify_work = None;
        let mut small_outcome_work = None;
        let mut small_outcome_count = 0;
        let mut small_hot_request_ids = None;
        for cycle in 1..=8_u64 {
            let request_id =
                agsv_protocol::RequestId::new(format!("request-bounded-{cycle}")).unwrap();
            let run_id = agsv_protocol::RunId::new(format!("run-bounded-{cycle}")).unwrap();
            let request_message_id =
                MessageId::new(format!("message-bounded-request-{cycle}")).unwrap();
            let request = Envelope {
                protocol_version: 1,
                message_id: request_message_id.clone(),
                workspace_id: workspace_id.clone(),
                sender: primary.clone(),
                target: MessageTarget::Actor(implementation.actor_id.clone()),
                team_id: Some(team_id.clone()),
                run_id: Some(run_id.clone()),
                request_id: Some(request_id.clone()),
                policy_revision: initial.policy_revision(),
                primary_epoch: initial.primary_epoch(),
                team_epoch: Some(team_epoch),
                assignment_epoch: None,
                sent_at: TimestampMillis(cycle * 100),
                message: Message::ImplementationRequest(ImplementationRequest {
                    title: format!("Bounded cycle {cycle}"),
                    instructions: BULK_SENTINEL.repeat(20),
                    base_sha: GitSha::new("0000000000000000000000000000000000000000").unwrap(),
                    acceptance_criteria: vec!["archive after acknowledgement".to_owned()],
                    evidence_requirements: Vec::new(),
                }),
            };
            store
                .mutate(
                    "request.created",
                    &serde_json::json!({}),
                    cycle * 10,
                    |state| {
                        state
                            .apply(request.clone())
                            .map(|_| ())
                            .map_err(crate::ControlError::core)
                    },
                )
                .unwrap();
            store
                .mutate(
                    "message.ack",
                    &serde_json::json!({}),
                    cycle * 10 + 1,
                    |state| {
                        state
                            .acknowledge(Acknowledgement {
                                workspace_id: workspace_id.clone(),
                                message_id: request_message_id.clone(),
                                actor: implementation.clone(),
                                acknowledged_at: TimestampMillis(cycle * 100 + 1),
                            })
                            .map(|_| ())
                            .map_err(crate::ControlError::core)
                    },
                )
                .unwrap();
            let cancellation_id =
                MessageId::new(format!("message-bounded-cancel-{cycle}")).unwrap();
            let cancellation = Envelope {
                protocol_version: 1,
                message_id: cancellation_id.clone(),
                workspace_id: workspace_id.clone(),
                sender: primary.clone(),
                target: MessageTarget::Actor(implementation.actor_id.clone()),
                team_id: Some(team_id.clone()),
                run_id: Some(run_id),
                request_id: Some(request_id),
                policy_revision: initial.policy_revision(),
                primary_epoch: initial.primary_epoch(),
                team_epoch: Some(team_epoch),
                assignment_epoch: None,
                sent_at: TimestampMillis(cycle * 100 + 2),
                message: Message::Cancellation(Cancellation {
                    reason: "bounded retention cycle".to_owned(),
                }),
            };
            store
                .mutate(
                    "request.cancelled",
                    &serde_json::json!({}),
                    cycle * 10 + 2,
                    |state| {
                        state
                            .apply(cancellation.clone())
                            .map(|_| ())
                            .map_err(crate::ControlError::core)
                    },
                )
                .unwrap();
            store
                .mutate(
                    "message.ack",
                    &serde_json::json!({}),
                    cycle * 10 + 3,
                    |state| {
                        state
                            .acknowledge(Acknowledgement {
                                workspace_id: workspace_id.clone(),
                                message_id: cancellation_id.clone(),
                                actor: implementation.clone(),
                                acknowledged_at: TimestampMillis(cycle * 100 + 3),
                            })
                            .map(|_| ())
                            .map_err(crate::ControlError::core)
                    },
                )
                .unwrap();
            if cycle == 1 {
                first_bytes = Connection::open(store.path())
                    .unwrap()
                    .query_row(
                        "SELECT length(snapshot_json) FROM domain_state",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let (_, work) = super::measure_store_work(|| store.load().unwrap());
                small_load_work = Some(work);
                let (_, work) =
                    super::measure_store_work(|| store.verify_archive_integrity().unwrap());
                small_verify_work = Some(work);
                let (_, small_supervisor, _) = store.load().unwrap();
                let small_hot = small_supervisor.snapshot();
                small_hot_request_ids = Some(
                    small_hot
                        .requests
                        .iter()
                        .map(|request| request.request_id.clone())
                        .collect::<Vec<_>>(),
                );
                let (outcomes, work) = super::measure_store_work(|| {
                    store.request_outcomes(&small_hot.requests, 10).unwrap()
                });
                small_outcome_count = outcomes.len();
                small_outcome_work = Some(work);
                let (_, work) = super::measure_store_work(|| {
                    store
                        .mutate(
                            "retention.work_probe.small",
                            &serde_json::json!({}),
                            cycle * 10 + 4,
                            |_| Ok(()),
                        )
                        .unwrap()
                });
                small_mutate_work = Some(work);
            }
        }
        let cycle_count = u64::try_from(agsv_protocol::MAX_DOMAIN_ENTITIES).unwrap() + 1;
        let (_, mut bounded, _) = store.load().unwrap();
        let mut connection = Connection::open(store.path()).unwrap();
        let transaction = connection.transaction().unwrap();
        for cycle in 9..=cycle_count {
            let request_id =
                agsv_protocol::RequestId::new(format!("request-bounded-{cycle}")).unwrap();
            let run_id = agsv_protocol::RunId::new(format!("run-bounded-{cycle}")).unwrap();
            let request_message_id =
                MessageId::new(format!("message-bounded-request-{cycle}")).unwrap();
            let request = Envelope {
                protocol_version: 1,
                message_id: request_message_id.clone(),
                workspace_id: workspace_id.clone(),
                sender: primary.clone(),
                target: MessageTarget::Actor(implementation.actor_id.clone()),
                team_id: Some(team_id.clone()),
                run_id: Some(run_id.clone()),
                request_id: Some(request_id.clone()),
                policy_revision: bounded.policy_revision(),
                primary_epoch: bounded.primary_epoch(),
                team_epoch: Some(team_epoch),
                assignment_epoch: None,
                sent_at: TimestampMillis(cycle * 100),
                message: Message::ImplementationRequest(ImplementationRequest {
                    title: format!("Bounded cycle {cycle}"),
                    instructions: format!("unique retained instructions {cycle}"),
                    base_sha: GitSha::new("0000000000000000000000000000000000000000").unwrap(),
                    acceptance_criteria: vec![format!("cycle {cycle} is queryable")],
                    evidence_requirements: Vec::new(),
                }),
            };
            assert_eq!(bounded.apply(request), Ok(ApplyOutcome::Applied));
            bounded
                .acknowledge(Acknowledgement {
                    workspace_id: workspace_id.clone(),
                    message_id: request_message_id,
                    actor: implementation.clone(),
                    acknowledged_at: TimestampMillis(cycle * 100 + 1),
                })
                .unwrap();
            let cancellation_id =
                MessageId::new(format!("message-bounded-cancel-{cycle}")).unwrap();
            let cancellation = Envelope {
                protocol_version: 1,
                message_id: cancellation_id.clone(),
                workspace_id: workspace_id.clone(),
                sender: primary.clone(),
                target: MessageTarget::Actor(implementation.actor_id.clone()),
                team_id: Some(team_id.clone()),
                run_id: Some(run_id),
                request_id: Some(request_id),
                policy_revision: bounded.policy_revision(),
                primary_epoch: bounded.primary_epoch(),
                team_epoch: Some(team_epoch),
                assignment_epoch: None,
                sent_at: TimestampMillis(cycle * 100 + 2),
                message: Message::Cancellation(Cancellation {
                    reason: format!("bounded retention cycle {cycle}"),
                }),
            };
            assert_eq!(bounded.apply(cancellation), Ok(ApplyOutcome::Applied));
            bounded
                .acknowledge(Acknowledgement {
                    workspace_id: workspace_id.clone(),
                    message_id: cancellation_id.clone(),
                    actor: implementation.clone(),
                    acknowledged_at: TimestampMillis(cycle * 100 + 3),
                })
                .unwrap();
            let pending_bulk = bounded.take_pending_bulk_content();
            let mut compact = bounded.snapshot();
            for pending in &pending_bulk {
                let delivery = compact
                    .deliveries
                    .iter()
                    .find(|delivery| delivery.envelope.message_id == pending.message_id);
                super::persist_message_body(
                    &transaction,
                    workspace_id.as_str(),
                    pending,
                    delivery,
                    cycle * 100 + 3,
                )
                .unwrap();
            }
            super::validate_compact_bulk_references(&transaction, workspace_id.as_str(), &compact)
                .unwrap();
            let entries = super::archive_compact_history(
                &transaction,
                workspace_id.as_str(),
                &mut compact,
                cycle * 4 + 2,
                cycle * 100 + 3,
            )
            .unwrap();
            super::append_archive_commit(
                &transaction,
                workspace_id.as_str(),
                &mut compact,
                entries,
                cycle * 4 + 2,
                cycle * 100 + 3,
            )
            .unwrap();
            bounded = super::restore_supervisor(compact).unwrap();
        }
        let final_snapshot = bounded.snapshot();
        let final_json = serde_json::to_string(&final_snapshot).unwrap();
        transaction
            .execute(
                "UPDATE domain_state SET revision = ?1, snapshot_json = ?2, updated_at_ms = ?3
                 WHERE workspace_id = ?4",
                params![
                    i64::try_from(cycle_count * 4 + 2).unwrap(),
                    final_json,
                    i64::try_from(cycle_count * 100 + 3).unwrap(),
                    workspace_id.as_str()
                ],
            )
            .unwrap();
        transaction.commit().unwrap();
        drop(connection);

        let ((_, restored, _), large_load_work) =
            super::measure_store_work(|| store.load().unwrap());
        let (_, large_verify_work) =
            super::measure_store_work(|| store.verify_archive_integrity().unwrap());
        let (_, large_mutate_work) = super::measure_store_work(|| {
            store
                .mutate(
                    "retention.work_probe.large",
                    &serde_json::json!({}),
                    cycle_count * 100 + 4,
                    |_| Ok(()),
                )
                .unwrap()
        });
        let small_load_work = small_load_work.unwrap();
        let small_mutate_work = small_mutate_work.unwrap();
        let small_verify_work = small_verify_work.unwrap();
        let small_outcome_work = small_outcome_work.unwrap();
        println!(
            "archive work: load small={small_load_work:?} large={large_load_work:?}; \
             mutate small={small_mutate_work:?} large={large_mutate_work:?}; \
             full_verify small={small_verify_work:?} large={large_verify_work:?}"
        );
        assert_eq!(small_load_work.archive_digests, 0);
        assert_eq!(large_load_work.archive_digests, 0);
        assert_eq!(small_mutate_work.archive_digests, 0);
        assert_eq!(large_mutate_work.archive_digests, 0);
        assert!(large_load_work.vm_steps <= small_load_work.vm_steps + 256);
        assert!(large_mutate_work.vm_steps <= small_mutate_work.vm_steps + 512);
        assert!(large_verify_work.archive_digests > small_verify_work.archive_digests * 1_000);
        assert!(large_verify_work.vm_steps > small_verify_work.vm_steps * 1_000);
        let hot = restored.snapshot();
        assert_eq!(hot.requests.len(), 1);
        assert_eq!(hot.runs.len(), 1);
        assert_eq!(hot.deliveries.len(), 1);
        assert_eq!(hot.audit_events.len(), 1);
        assert_eq!(
            small_hot_request_ids.unwrap(),
            hot.requests
                .iter()
                .map(|request| request.request_id.clone())
                .collect::<Vec<_>>()
        );
        let (bounded_outcomes, large_outcome_work) =
            super::measure_store_work(|| store.request_outcomes(&hot.requests, 10).unwrap());
        println!(
            "request outcome work: small={small_outcome_work:?} \
             large={large_outcome_work:?}"
        );
        assert_eq!(small_outcome_count, 2);
        assert_eq!(bounded_outcomes.len(), 10);
        assert_eq!(small_outcome_work.archive_digests, 2);
        assert_eq!(large_outcome_work.archive_digests, 18);
        assert!(large_outcome_work.vm_steps <= small_outcome_work.vm_steps + 128);
        assert_eq!(
            bounded_outcomes.first().unwrap().request_id.as_str(),
            format!("request-bounded-{}", cycle_count - 8)
        );
        assert_eq!(
            bounded_outcomes[8].request_id.as_str(),
            format!("request-bounded-{cycle_count}")
        );
        assert_eq!(
            bounded_outcomes.last().unwrap().request_id,
            hot.requests[0].request_id
        );
        let connection = Connection::open(store.path()).unwrap();
        let query_plan = connection
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT request_id, run_id, request_sha256, request_json,
                        run_sha256, run_json
                 FROM terminal_request_archive
                 WHERE workspace_id = ?1
                 ORDER BY archived_revision DESC, request_id DESC LIMIT ?2",
            )
            .unwrap()
            .query_map(params![workspace_id.as_str(), 9_i64], |row| {
                row.get::<_, String>(3)
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(query_plan.iter().any(|detail| {
            detail.contains("USING INDEX terminal_request_archive_outcome_window")
        }));
        let final_bytes: i64 = connection
            .query_row(
                "SELECT length(snapshot_json) FROM domain_state",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let delivery_archive: i64 = connection
            .query_row("SELECT COUNT(*) FROM delivery_archive", [], |row| {
                row.get(0)
            })
            .unwrap();
        let request_archive: i64 = connection
            .query_row("SELECT COUNT(*) FROM terminal_request_archive", [], |row| {
                row.get(0)
            })
            .unwrap();
        println!(
            "bounded hot snapshot bytes: cycle_1={first_bytes}, cycle_10001={final_bytes}; archives: deliveries={delivery_archive}, requests={request_archive}"
        );
        assert!(final_bytes <= first_bytes + 512);
        assert_eq!(delivery_archive, i64::try_from(cycle_count * 2).unwrap());
        assert_eq!(request_archive, i64::try_from(cycle_count).unwrap());
        let audit_archive: i64 = connection
            .query_row("SELECT COUNT(*) FROM protocol_audit_archive", [], |row| {
                row.get(0)
            })
            .unwrap();
        let specification_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM request_specifications", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(audit_archive, i64::try_from(cycle_count * 4).unwrap());
        assert_eq!(specification_count, i64::try_from(cycle_count + 1).unwrap());
        connection
            .execute_batch("DROP TRIGGER protocol_audit_archive_no_update")
            .unwrap();
        connection
            .execute(
                "UPDATE protocol_audit_archive SET previous_sha256 = ?1
                 WHERE sequence = (SELECT MAX(sequence) FROM protocol_audit_archive)",
                ["0".repeat(64)],
            )
            .unwrap();
        drop(connection);
        store.load().unwrap();
        let (_, tampered_mutate_work) = super::measure_store_work(|| {
            store
                .mutate(
                    "retention.work_probe.tampered",
                    &serde_json::json!({}),
                    cycle_count * 100 + 5,
                    |_| Ok(()),
                )
                .unwrap()
        });
        assert_eq!(tampered_mutate_work.archive_digests, 0);
        assert!(tampered_mutate_work.vm_steps <= large_mutate_work.vm_steps + 512);
        assert_eq!(
            store.verify_archive_integrity().unwrap_err().code,
            "protocol_audit_archive_chain_invalid"
        );
    }

    #[test]
    fn forged_oversized_archive_group_is_rejected_before_materialization() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-oversized-archive-group").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        let connection = Connection::open(store.path()).unwrap();
        connection
            .execute_batch(&format!(
                "WITH digits(value) AS (
                   VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)
                 ), numbers(value) AS (
                   SELECT a.value + 10*b.value + 100*c.value + 1000*d.value
                          + 10000*e.value + 100000*f.value
                   FROM digits a, digits b, digits c, digits d, digits e, digits f
                 )
                 INSERT INTO delivery_archive
                 (workspace_id, message_id, request_id, sender_actor_id, sender_actor_epoch,
                  message_kind, sent_at_ms, decision_id, candidate_sha, consultation_id,
                  delivery_sha256, delivery_json, archived_revision, archived_at_ms)
                 SELECT 'workspace-oversized-archive-group', printf('message-forged-%06d', value),
                        'request-forged-group', 'actor-forged', 1, 'cancellation', value,
                        NULL, NULL, NULL, 'forged', '{{}}', 1, 1
                 FROM numbers WHERE value <= {}",
                agsv_protocol::MAX_DELIVERIES
            ))
            .unwrap();
        let error = super::archived_delivery_ids(
            &connection,
            workspace_id.as_str(),
            "request_id",
            "request-forged-group",
        )
        .unwrap_err();
        assert_eq!(error.code, "archived_history_group_limit_exceeded");
        assert_eq!(
            error.details["actual"],
            serde_json::json!(agsv_protocol::MAX_DELIVERIES + 1)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn retired_decision_is_queryable_with_full_rationale_by_candidate_sha() {
        let directory = tempfile::tempdir().unwrap();
        let (initial, request_envelope, implementation, team_id) =
            populated_supervisor("workspace-decision-retention");
        let workspace_id = initial.workspace_id().clone();
        let primary = request_envelope.sender.clone();
        let request_id = request_envelope.request_id.clone().unwrap();
        let run_id = request_envelope.run_id.clone().unwrap();
        let team_epoch = initial.team(&team_id).unwrap().epoch;
        let candidate_sha = GitSha::new("1111111111111111111111111111111111111111").unwrap();
        let candidate = Candidate {
            request_id: request_id.clone(),
            team_id: team_id.clone(),
            sha: candidate_sha.clone(),
            created_by: implementation.clone(),
            created_by_profile: None,
        };
        let evidence = Evidence {
            evidence_id: EvidenceId::new("evidence-retention").unwrap(),
            kind: EvidenceKind::Review,
            digest: EvidenceDigest {
                algorithm: DigestAlgorithm::Sha256,
                value: "2222222222222222222222222222222222222222222222222222222222222222"
                    .to_owned(),
            },
            reference: "artifact://retention/review".to_owned(),
            summary: "retained decision evidence".to_owned(),
        };
        let decision = ReviewDecision {
            decision_id: DecisionId::new("decision-retention").unwrap(),
            candidate: candidate.clone(),
            verdict: ReviewVerdict::Accepted,
            reviewer: primary.clone(),
            policy_revision: initial.policy_revision(),
            rationale: "R1 durable rationale retained after terminal cleanup".to_owned(),
            evidence: vec![evidence.clone()],
        };
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        let apply = |store: &StateStore, operation: &str, now, envelope: &Envelope| {
            store
                .mutate(operation, &serde_json::json!({}), now, |state| {
                    state
                        .apply(envelope.clone())
                        .map(|_| ())
                        .map_err(crate::ControlError::core)
                })
                .unwrap();
        };
        let ack = |store: &StateStore, now, message_id: &MessageId, actor: &ActorRef| {
            store
                .mutate("message.ack", &serde_json::json!({}), now, |state| {
                    state
                        .acknowledge(Acknowledgement {
                            workspace_id: workspace_id.clone(),
                            message_id: message_id.clone(),
                            actor: actor.clone(),
                            acknowledged_at: TimestampMillis(now),
                        })
                        .map(|_| ())
                        .map_err(crate::ControlError::core)
                })
                .unwrap();
        };
        apply(&store, "request.created", 2, &request_envelope);
        ack(&store, 3, &request_envelope.message_id, &implementation);

        let candidate_envelope = Envelope {
            protocol_version: 1,
            message_id: MessageId::new("message-candidate-retention").unwrap(),
            workspace_id: workspace_id.clone(),
            sender: implementation.clone(),
            target: MessageTarget::Primary,
            team_id: Some(team_id.clone()),
            run_id: Some(run_id.clone()),
            request_id: Some(request_id.clone()),
            policy_revision: initial.policy_revision(),
            primary_epoch: initial.primary_epoch(),
            team_epoch: Some(team_epoch),
            assignment_epoch: Some(AssignmentEpoch::INITIAL),
            sent_at: TimestampMillis(20),
            message: Message::CandidateReady(CandidateReady {
                candidate,
                summary: "candidate retained".to_owned(),
                evidence: Vec::new(),
            }),
        };
        apply(&store, "candidate.ready", 4, &candidate_envelope);
        ack(&store, 5, &candidate_envelope.message_id, &primary);

        let decision_envelope = Envelope {
            protocol_version: 1,
            message_id: MessageId::new("message-decision-retention").unwrap(),
            workspace_id: workspace_id.clone(),
            sender: primary.clone(),
            target: MessageTarget::Actor(implementation.actor_id.clone()),
            team_id: Some(team_id.clone()),
            run_id: Some(run_id.clone()),
            request_id: Some(request_id.clone()),
            policy_revision: initial.policy_revision(),
            primary_epoch: initial.primary_epoch(),
            team_epoch: Some(team_epoch),
            assignment_epoch: None,
            sent_at: TimestampMillis(30),
            message: Message::ReviewDecision(decision.clone()),
        };
        apply(&store, "decision.submitted", 6, &decision_envelope);
        ack(&store, 7, &decision_envelope.message_id, &implementation);

        let cancellation = Envelope {
            protocol_version: 1,
            message_id: MessageId::new("message-decision-cycle-cancel").unwrap(),
            workspace_id: workspace_id.clone(),
            sender: primary,
            target: MessageTarget::Actor(implementation.actor_id.clone()),
            team_id: Some(team_id),
            run_id: Some(run_id),
            request_id: Some(request_id),
            policy_revision: initial.policy_revision(),
            primary_epoch: initial.primary_epoch(),
            team_epoch: Some(team_epoch),
            assignment_epoch: None,
            sent_at: TimestampMillis(40),
            message: Message::Cancellation(Cancellation {
                reason: "terminal retention fixture".to_owned(),
            }),
        };
        apply(&store, "request.cancelled", 8, &cancellation);
        ack(&store, 9, &cancellation.message_id, &implementation);

        assert_eq!(
            store
                .archived_decisions_by_candidate_sha(&candidate_sha)
                .unwrap(),
            vec![decision]
        );
        assert_eq!(
            store
                .decision_rationale("decision-retention")
                .unwrap()
                .as_deref(),
            Some("R1 durable rationale retained after terminal cleanup")
        );
        assert_eq!(
            store.evidence_record("evidence-retention").unwrap(),
            Some(evidence)
        );
        let connection = Connection::open(store.path()).unwrap();
        let indexed: (String, String, String, i64) = connection
            .query_row(
                "SELECT delivery.candidate_sha, delivery.decision_id,
                        delivery.sender_actor_id, delivery.sent_at_ms
                 FROM delivery_archive AS delivery
                 WHERE delivery.message_kind = 'review_decision'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            indexed,
            (
                candidate_sha.to_string(),
                "decision-retention".to_owned(),
                "primary-retention".to_owned(),
                30,
            )
        );
    }

    #[test]
    fn control_events_archive_union_preserves_full_sequence() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_id = WorkspaceId::new("workspace-event-retention").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        let mut connection = Connection::open(store.path()).unwrap();
        let transaction = connection.transaction().unwrap();
        for revision in 1..=1_005_i64 {
            transaction
                .execute(
                    "INSERT INTO control_events
                     (workspace_id, revision, operation, detail_json, occurred_at_ms)
                     VALUES (?1, ?2, 'fixture', '{}', ?2)",
                    params![workspace_id.as_str(), revision],
                )
                .unwrap();
        }
        super::compact_control_events(&transaction, workspace_id.as_str(), 2_000).unwrap();
        transaction.commit().unwrap();
        let live: i64 = connection
            .query_row("SELECT COUNT(*) FROM control_events", [], |row| row.get(0))
            .unwrap();
        let archived: i64 = connection
            .query_row("SELECT COUNT(*) FROM control_event_archive", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((live, archived), (1_000, 5));
        let events = store.events(1_005).unwrap();
        assert_eq!(events.len(), 1_005);
        assert_eq!(events.first().unwrap().revision, 1);
        assert_eq!(events.last().unwrap().revision, 1_005);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn terminal_presentation_archival_requires_stopped_session_and_never_reuses_slot() {
        let directory = tempfile::tempdir().unwrap();
        let (initial, _, implementation, team_id) =
            populated_supervisor("workspace-presentation-retention");
        let workspace_id = initial.workspace_id().clone();
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        store
            .upsert_session(&SessionRecord {
                actor_id: implementation.actor_id.to_string(),
                team_id: Some(team_id.to_string()),
                working_directory: PathBuf::from("/workspace/retention"),
                backend: "fixture".to_owned(),
                runtime: Some("fixture-runtime".to_owned()),
                external_id: Some("live-session".to_owned()),
                resume_token: None,
                status: "idle".to_owned(),
                launch_key: "launch-retention".to_owned(),
                updated_at_ms: 2,
            })
            .unwrap();
        let first = store
            .allocate_session_presentation(
                implementation.actor_id.as_str(),
                team_id.as_str(),
                "Implementation",
                "Implementation retained evidence",
                1,
                false,
                &[],
                &[],
                3,
            )
            .unwrap();
        store
            .mutate("actor.stopped", &serde_json::json!({}), 4, |state| {
                state
                    .set_actor_status(&implementation, ActorStatus::Stopped)
                    .map_err(crate::ControlError::core)
            })
            .unwrap();
        assert!(
            store
                .session_presentation(implementation.actor_id.as_str())
                .unwrap()
                .is_some()
        );

        let mut stopped = store
            .session(implementation.actor_id.as_str())
            .unwrap()
            .unwrap();
        stopped.status = "stopped".to_owned();
        stopped.updated_at_ms = 5;
        store.upsert_session(&stopped).unwrap();
        store
            .mutate("archive.safe", &serde_json::json!({}), 6, |_| Ok(()))
            .unwrap();
        assert!(
            store
                .session_presentation(implementation.actor_id.as_str())
                .unwrap()
                .is_none()
        );
        let connection = Connection::open(store.path()).unwrap();
        let archived_json: String = connection
            .query_row(
                "SELECT presentation_json FROM session_presentation_archive",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(archived_json.contains("retained evidence"));
        let reservations: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM presentation_slot_reservations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reservations, 1);
        drop(connection);

        let (_, replacement) = store
            .mutate("actor.replaced", &serde_json::json!({}), 7, |state| {
                state
                    .replace_implementation(&team_id, implementation.actor_id.clone())
                    .map_err(crate::ControlError::core)
            })
            .unwrap();
        let mut replacement_session = stopped;
        replacement_session.status = "idle".to_owned();
        replacement_session.external_id = Some("replacement-session".to_owned());
        replacement_session.updated_at_ms = 8;
        store.upsert_session(&replacement_session).unwrap();
        let second = store
            .allocate_session_presentation(
                replacement.actor_id.as_str(),
                team_id.as_str(),
                "Implementation",
                "Replacement",
                1,
                false,
                &[],
                &[],
                9,
            )
            .unwrap();
        assert_ne!(first.slot, second.slot);

        store
            .set_team_purpose(team_id.as_str(), "retained team purpose", 10)
            .unwrap();
        store
            .mutate("team.closed", &serde_json::json!({}), 11, |state| {
                state
                    .set_team_status(&team_id, TeamStatus::Closing)
                    .and_then(|()| state.set_team_status(&team_id, TeamStatus::Closed))
                    .map_err(crate::ControlError::core)
            })
            .unwrap();
        assert_eq!(
            store.team_purpose(team_id.as_str()).unwrap().as_deref(),
            Some("retained team purpose")
        );
        let update_error = store
            .set_team_purpose(team_id.as_str(), "shadowing live purpose", 12)
            .unwrap_err();
        assert_eq!(update_error.code, "team_metadata_archived");
        let connection = Connection::open(store.path()).unwrap();
        let archived_purpose: String = connection
            .query_row("SELECT purpose FROM team_metadata_archive", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(archived_purpose, "retained team purpose");
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM team_metadata WHERE workspace_id = ?1 AND team_id = ?2",
                    params![workspace_id.as_str(), team_id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }
}
