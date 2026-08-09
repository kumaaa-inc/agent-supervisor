use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use crate::ControlError;
use crate::identity::sha256_hex;
use agsv_core::Supervisor;
use agsv_protocol::{ActorEpoch, ActorId, ActorRef, DomainSnapshot};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MIGRATION: &str = r"
CREATE TABLE IF NOT EXISTS domain_state (
  workspace_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL,
  snapshot_json TEXT NOT NULL,
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
";
const OPERATION_CLAIMS_MIGRATION: &str = r"
CREATE TABLE IF NOT EXISTS operation_claims (
  workspace_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  claim_token TEXT NOT NULL,
  claimed_at_ms INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, operation_id)
);
";
const ACTOR_BINDINGS_MIGRATION: &str = r"
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
";
const PRESENTATION_MIGRATION: &str = r"
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
";
// Schema version 4 is reserved by the runtime-identity migration on the
// integration branch. Presentation metadata is the next independent slice.
const CONTROL_SCHEMA_VERSION: i64 = 5;
const OPERATION_CLAIM_TTL_MS: u64 = 5 * 60 * 1_000;

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
    pub external_id: Option<String>,
    pub resume_token: Option<String>,
    pub status: String,
    pub launch_key: String,
    pub updated_at_ms: u64,
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
        let store = Self {
            path,
            workspace_id: workspace_id.to_owned(),
        };
        let mut connection = store.connect()?;
        migrate(&mut connection)?;
        let snapshot_json = serde_json::to_string(initial).map_err(ControlError::database)?;
        connection
            .execute(
                "INSERT OR IGNORE INTO domain_state
                 (workspace_id, revision, snapshot_json, controller_active, updated_at_ms)
                 VALUES (?1, 0, ?2, 0, ?3)",
                params![workspace_id, snapshot_json, to_i64(now_ms)?],
            )
            .map_err(ControlError::database)?;
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
        let (revision, json, active) = connection
            .query_row(
                "SELECT revision, snapshot_json, controller_active FROM domain_state
                 WHERE workspace_id = ?1",
                [&self.workspace_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )
            .map_err(ControlError::database)?;
        let revision = u64::try_from(revision)
            .map_err(|error| ControlError::database(format!("invalid revision: {error}")))?;
        let snapshot: DomainSnapshot =
            serde_json::from_str(&json).map_err(ControlError::database)?;
        let supervisor = restore_supervisor(snapshot)?;
        Ok((revision, supervisor, active))
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
            let snapshot = supervisor.snapshot();
            restore_supervisor(snapshot.clone())?;
            let snapshot_json = serde_json::to_string(&snapshot).map_err(ControlError::database)?;
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
            let next = revision.checked_add(1).ok_or_else(|| {
                ControlError::new("revision_exhausted", "state revision exhausted u64")
            })?;
            let updated = transaction
                .execute(
                    "UPDATE domain_state SET revision = ?1, snapshot_json = ?2, updated_at_ms = ?3
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
            let (revision, supervisor, _) = self.load()?;
            let snapshot_json =
                serde_json::to_string(&supervisor.snapshot()).map_err(ControlError::database)?;
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
                    "UPDATE domain_state SET revision = ?1, snapshot_json = ?2,
                     controller_active = ?3, updated_at_ms = ?4
                     WHERE workspace_id = ?5 AND revision = ?6",
                    params![
                        to_i64(next)?,
                        snapshot_json,
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
                serde_json::from_str(&result)
                    .map(Some)
                    .map_err(ControlError::database)
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
        let result_json = serde_json::to_string(result).map_err(ControlError::database)?;
        let connection = self.connect()?;
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

    pub(crate) fn session(&self, actor_id: &str) -> Result<Option<SessionRecord>, ControlError> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT actor_id, team_id, working_directory, backend, external_id,
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
                "SELECT actor_id, team_id, working_directory, backend, external_id,
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
                 (workspace_id, actor_id, team_id, working_directory, backend, external_id,
                  resume_token, status, launch_key, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(workspace_id, actor_id) DO UPDATE SET
                  team_id=excluded.team_id, working_directory=excluded.working_directory,
                  backend=excluded.backend, external_id=excluded.external_id,
                  resume_token=excluded.resume_token, status=excluded.status,
                  launch_key=excluded.launch_key, updated_at_ms=excluded.updated_at_ms",
                params![
                    self.workspace_id,
                    session.actor_id,
                    session.team_id,
                    session.working_directory.to_string_lossy(),
                    session.backend,
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
        self.connect()?
            .execute(
                "INSERT INTO team_metadata (workspace_id, team_id, purpose, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(workspace_id, team_id) DO UPDATE SET
                  purpose=excluded.purpose, updated_at_ms=excluded.updated_at_ms",
                params![self.workspace_id, team_id, purpose, to_i64(now_ms)?],
            )
            .map_err(ControlError::database)?;
        Ok(())
    }

    pub(crate) fn team_purpose(&self, team_id: &str) -> Result<Option<String>, ControlError> {
        self.connect()?
            .query_row(
                "SELECT purpose FROM team_metadata
                 WHERE workspace_id = ?1 AND team_id = ?2",
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
                "SELECT team_id, purpose, updated_at_ms FROM team_metadata
                 WHERE workspace_id = ?1 ORDER BY team_id",
            )
            .map_err(ControlError::database)?;
        statement
            .query_map([&self.workspace_id], team_metadata_from_row)
            .map_err(ControlError::database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(ControlError::database)
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
                "SELECT actor_id, team_id, working_directory, backend, external_id,
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
        if session.launch_key.starts_with("replacement:")
            && matches!(
                session.status.as_str(),
                "replacement_pending" | "launching" | "launch_failed"
            )
        {
            return Err(ControlError::new(
                "actor_replacement_in_progress",
                format!("actor `{actor_id}` already has a durable replacement intent"),
            )
            .with_hint("retry the original actor replacement operation ID"));
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
                   SELECT sequence, revision, operation, detail_json, occurred_at_ms
                   FROM control_events WHERE workspace_id = ?1 ORDER BY sequence DESC LIMIT ?2
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

    fn connect(&self) -> Result<Connection, ControlError> {
        let connection = Connection::open(&self.path).map_err(ControlError::database)?;
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

fn migrate(connection: &mut Connection) -> Result<(), ControlError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(ControlError::database)?;
    let version: i64 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(ControlError::database)?;
    match version {
        0 => {
            transaction
                .execute_batch(MIGRATION)
                .map_err(ControlError::database)?;
            add_session_runtime_column(&transaction)?;
            transaction
                .pragma_update(None, "user_version", CONTROL_SCHEMA_VERSION)
                .map_err(ControlError::database)?;
        }
        1 => {
            transaction
                .execute_batch(OPERATION_CLAIMS_MIGRATION)
                .map_err(ControlError::database)?;
            transaction
                .execute_batch(ACTOR_BINDINGS_MIGRATION)
                .map_err(ControlError::database)?;
            add_session_runtime_column(&transaction)?;
            transaction
                .execute_batch(PRESENTATION_MIGRATION)
                .map_err(ControlError::database)?;
            transaction
                .pragma_update(None, "user_version", CONTROL_SCHEMA_VERSION)
                .map_err(ControlError::database)?;
        }
        2 => {
            transaction
                .execute_batch(ACTOR_BINDINGS_MIGRATION)
                .map_err(ControlError::database)?;
            add_session_runtime_column(&transaction)?;
            transaction
                .execute_batch(PRESENTATION_MIGRATION)
                .map_err(ControlError::database)?;
            transaction
                .pragma_update(None, "user_version", CONTROL_SCHEMA_VERSION)
                .map_err(ControlError::database)?;
        }
        3 => {
            add_session_runtime_column(&transaction)?;
            transaction
                .execute_batch(PRESENTATION_MIGRATION)
                .map_err(ControlError::database)?;
            transaction
                .pragma_update(None, "user_version", CONTROL_SCHEMA_VERSION)
                .map_err(ControlError::database)?;
        }
        4 => {
            transaction
                .execute_batch(PRESENTATION_MIGRATION)
                .map_err(ControlError::database)?;
            transaction
                .pragma_update(None, "user_version", CONTROL_SCHEMA_VERSION)
                .map_err(ControlError::database)?;
        }
        CONTROL_SCHEMA_VERSION => {}
        future if future > CONTROL_SCHEMA_VERSION => {
            return Err(ControlError::new(
                "unsupported_state_schema",
                format!(
                    "control database schema {future} is newer than supported schema {CONTROL_SCHEMA_VERSION}"
                ),
            ));
        }
        other => {
            return Err(ControlError::new(
                "unsupported_state_schema",
                format!("control database schema {other} has no supported migration path"),
            ));
        }
    }
    transaction.commit().map_err(ControlError::database)
}

fn add_session_runtime_column(transaction: &rusqlite::Transaction<'_>) -> Result<(), ControlError> {
    let present = transaction
        .query_row(
            "SELECT 1 FROM pragma_table_info('sessions') WHERE name = 'runtime'",
            [],
            |_| Ok(()),
        )
        .optional()
        .map_err(ControlError::database)?
        .is_some();
    if !present {
        transaction
            .execute("ALTER TABLE sessions ADD COLUMN runtime TEXT", [])
            .map_err(ControlError::database)?;
    }
    Ok(())
}

fn session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRecord> {
    let updated = row.get::<_, i64>(8)?;
    Ok(SessionRecord {
        actor_id: row.get(0)?,
        team_id: row.get(1)?,
        working_directory: PathBuf::from(row.get::<_, String>(2)?),
        backend: row.get(3)?,
        external_id: row.get(4)?,
        resume_token: row.get(5)?,
        status: row.get(6)?,
        launch_key: row.get(7)?,
        updated_at_ms: u64::try_from(updated).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                8,
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
            "SELECT DISTINCT tab_sequence FROM session_presentations
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
            "SELECT 1 FROM session_presentations
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
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};

    use super::{
        CONTROL_SCHEMA_VERSION, MIGRATION, PRESENTATION_MIGRATION, PresentationSlot,
        PresentationSyncState, SessionRecord, StateStore,
    };
    use agsv_core::Supervisor;
    use agsv_protocol::{ActorEpoch, ActorId, ActorRef, PolicyRevision, WorkspaceId};
    use rusqlite::{Connection, params};

    #[test]
    fn schema_v2_migrates_operation_claims_and_adds_actor_bindings() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("control.sqlite3");
        let connection = Connection::open(&database).unwrap();
        let legacy_schema = MIGRATION
            .replace("  runtime TEXT,\n", "")
            .replace(PRESENTATION_MIGRATION, "");
        connection.execute_batch(&legacy_schema).unwrap();
        connection
            .execute_batch(
                "DROP INDEX actor_bindings_actor;
                 DROP TABLE actor_bindings;
                 PRAGMA user_version = 2;",
            )
            .unwrap();
        drop(connection);

        let workspace_id = WorkspaceId::new("workspace-migration").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            1,
        )
        .unwrap();
        assert!(
            store
                .actor_binding("fixture_identity", "pane")
                .unwrap()
                .is_none()
        );

        let connection = Connection::open(database).unwrap();
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, CONTROL_SCHEMA_VERSION);
        let claims: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'operation_claims'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let bindings: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'actor_bindings'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let presentations: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'session_presentations'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let has_runtime: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'runtime'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((claims, bindings, presentations, has_runtime), (1, 1, 1, 1));
    }

    #[test]
    fn schema_v3_migrates_to_v5_without_changing_existing_state() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("control.sqlite3");
        let workspace_id = WorkspaceId::new("workspace-v3-to-v5").unwrap();
        let mut supervisor = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        supervisor
            .create_team(agsv_protocol::TeamId::new("team-preserved").unwrap())
            .unwrap();
        let snapshot = supervisor.snapshot();
        let snapshot_json = serde_json::to_string(&snapshot).unwrap();

        let connection = Connection::open(&database).unwrap();
        // Reconcile this synthetic fixture with R1's real v4 migration during semantic rebase.
        let without_runtime = MIGRATION.replace("  runtime TEXT,\n", "");
        assert_ne!(without_runtime, MIGRATION, "runtime DDL fixture drifted");
        let legacy_schema = without_runtime.replace(PRESENTATION_MIGRATION, "");
        assert_ne!(
            legacy_schema, without_runtime,
            "presentation DDL fixture drifted"
        );
        connection.execute_batch(&legacy_schema).unwrap();
        connection
            .execute(
                "INSERT INTO domain_state
                 (workspace_id, revision, snapshot_json, controller_active, updated_at_ms)
                 VALUES (?1, 7, ?2, 1, 9)",
                params![workspace_id.as_str(), snapshot_json],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sessions
                 (workspace_id, actor_id, team_id, working_directory, backend, external_id,
                  resume_token, status, launch_key, updated_at_ms)
                 VALUES (?1, 'impl-preserved', 'team-preserved', '/worktree', 'fixture',
                         'external-preserved', 'resume-preserved', 'idle', 'launch-preserved', 10)",
                [workspace_id.as_str()],
            )
            .unwrap();
        connection.pragma_update(None, "user_version", 3).unwrap();
        drop(connection);

        let store =
            StateStore::open(directory.path(), workspace_id.as_str(), &snapshot, 11).unwrap();
        let (revision, restored, active) = store.load().unwrap();
        assert_eq!(revision, 7);
        assert_eq!(restored.snapshot(), snapshot);
        assert!(active);
        let session = store.session("impl-preserved").unwrap().unwrap();
        assert_eq!(session.external_id.as_deref(), Some("external-preserved"));
        assert!(store.session_presentations().unwrap().is_empty());
        assert!(store.team_metadata().unwrap().is_empty());

        let connection = Connection::open(database).unwrap();
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let runtime: Option<String> = connection
            .query_row(
                "SELECT runtime FROM sessions WHERE actor_id = 'impl-preserved'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, CONTROL_SCHEMA_VERSION);
        assert_eq!(runtime, None);
    }

    #[test]
    fn schema_v4_runtime_identity_migrates_to_v5_presentation_union() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("control.sqlite3");
        let workspace_id = WorkspaceId::new("workspace-v4-to-v5").unwrap();
        let initial = Supervisor::new(workspace_id.clone(), PolicyRevision::INITIAL);
        let connection = Connection::open(&database).unwrap();
        // Reconcile this synthetic fixture with R1's real v4 migration during semantic rebase.
        let runtime_schema = MIGRATION.replace(PRESENTATION_MIGRATION, "");
        assert_ne!(
            runtime_schema, MIGRATION,
            "presentation DDL fixture drifted"
        );
        connection.execute_batch(&runtime_schema).unwrap();
        connection
            .execute(
                "INSERT INTO sessions
                 (workspace_id, actor_id, team_id, working_directory, backend, runtime,
                  external_id, resume_token, status, launch_key, updated_at_ms)
                 VALUES (?1, 'impl-runtime', 'team-runtime', '/worktree', 'fixture', 'codex',
                         'external-runtime', 'resume-runtime', 'idle', 'launch-runtime', 10)",
                [workspace_id.as_str()],
            )
            .unwrap();
        connection.pragma_update(None, "user_version", 4).unwrap();
        drop(connection);

        let store = StateStore::open(
            directory.path(),
            workspace_id.as_str(),
            &initial.snapshot(),
            11,
        )
        .unwrap();
        assert_eq!(
            store.session("impl-runtime").unwrap().unwrap().status,
            "idle"
        );
        assert!(store.session_presentations().unwrap().is_empty());

        let connection = Connection::open(database).unwrap();
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let runtime: String = connection
            .query_row(
                "SELECT runtime FROM sessions WHERE actor_id = 'impl-runtime'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let presentation_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name IN ('team_metadata', 'session_presentations')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, CONTROL_SCHEMA_VERSION);
        assert_eq!(runtime, "codex");
        assert_eq!(presentation_tables, 2);
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
        assert_eq!(claimed.external_id.as_deref(), Some("fake-old"));
        assert_eq!(
            store
                .claim_replacement_intent("impl-one", "replacement:operation-one:1", 3)
                .unwrap()
                .launch_key,
            "replacement:operation-one:1"
        );

        let competing = store
            .claim_replacement_intent("impl-one", "replacement:operation-two:1", 4)
            .unwrap_err();
        assert_eq!(competing.code, "actor_replacement_in_progress");
    }
}
