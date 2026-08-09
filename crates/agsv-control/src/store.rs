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
const CONTROL_SCHEMA_VERSION: i64 = 3;
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
            transaction
                .pragma_update(None, "user_version", CONTROL_SCHEMA_VERSION)
                .map_err(ControlError::database)?;
        }
        2 => {
            transaction
                .execute_batch(ACTOR_BINDINGS_MIGRATION)
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
    use std::path::PathBuf;

    use super::{CONTROL_SCHEMA_VERSION, MIGRATION, SessionRecord, StateStore};
    use agsv_core::Supervisor;
    use agsv_protocol::{ActorEpoch, ActorId, ActorRef, PolicyRevision, WorkspaceId};
    use rusqlite::Connection;

    #[test]
    fn schema_v2_migrates_operation_claims_and_adds_actor_bindings() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("control.sqlite3");
        let connection = Connection::open(&database).unwrap();
        connection.execute_batch(MIGRATION).unwrap();
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
        assert_eq!((claims, bindings), (1, 1));
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
