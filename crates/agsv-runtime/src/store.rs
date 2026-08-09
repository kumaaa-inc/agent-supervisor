use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};

use crate::{
    ActorRecord, ActorRole, ActorState, AuditEvent, ClaimedMessage, DaemonLease, LaunchIntent,
    LaunchIntentState, MessageRecord, NewMessage, PrimaryLease, RuntimeError, SenderContext,
};

const MIGRATION_BOOTSTRAP: &str = r"
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at_ms INTEGER NOT NULL
);
";

const MIGRATION_1: &str = r"
CREATE TABLE daemon_leases (
    workspace_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    lease_until_ms INTEGER NOT NULL,
    heartbeat_at_ms INTEGER NOT NULL
);

CREATE TABLE actors (
    workspace_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    team_id TEXT,
    role TEXT NOT NULL,
    state TEXT NOT NULL,
    actor_epoch INTEGER NOT NULL,
    backend TEXT NOT NULL,
    session_external_id TEXT,
    session_resume_token TEXT,
    heartbeat_at_ms INTEGER NOT NULL,
    lease_until_ms INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, actor_id)
);

CREATE TABLE primary_leases (
    workspace_id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL,
    actor_epoch INTEGER NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    lease_until_ms INTEGER NOT NULL
);

CREATE TABLE messages (
    workspace_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    sender_actor_id TEXT NOT NULL,
    recipient_actor_id TEXT,
    recipient_team_id TEXT,
    kind TEXT NOT NULL,
    payload BLOB NOT NULL,
    available_at_ms INTEGER NOT NULL,
    claimed_by_actor_id TEXT,
    claimant_actor_epoch INTEGER,
    delivery_epoch INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    claim_until_ms INTEGER,
    acknowledged_at_ms INTEGER,
    last_error TEXT,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, message_id),
    UNIQUE (workspace_id, idempotency_key)
);

CREATE INDEX messages_inbox_idx ON messages (
    workspace_id, acknowledged_at_ms, available_at_ms, claim_until_ms, created_at_ms
);

CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id TEXT NOT NULL,
    entity_kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE INDEX audit_workspace_sequence_idx ON audit_events (workspace_id, sequence);
";

const MIGRATION_2: &str = r"
ALTER TABLE messages ADD COLUMN sender_actor_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN primary_fencing_epoch INTEGER;

CREATE TABLE launch_intents (
    workspace_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    spec_fingerprint TEXT NOT NULL,
    canonical_working_directory TEXT NOT NULL,
    backend TEXT NOT NULL,
    session_name TEXT NOT NULL,
    state TEXT NOT NULL,
    resume_token TEXT,
    session_external_id TEXT,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, idempotency_key)
);

CREATE INDEX launch_intents_actor_idx ON launch_intents (workspace_id, actor_id, updated_at_ms);
";

const CURRENT_SCHEMA_VERSION: i64 = 2;

/// Cloneable handle that opens one configured `SQLite` connection per operation.
#[derive(Clone, Debug)]
pub struct SqliteStore {
    path: PathBuf,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let store = Self {
            path: path.as_ref().to_path_buf(),
        };
        let mut connection = store.connect()?;
        migrate(&mut connection)?;
        Ok(store)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn journal_mode(&self) -> Result<String, RuntimeError> {
        let connection = self.connect()?;
        connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(Into::into)
    }

    pub fn acquire_daemon_lease(
        &self,
        workspace_id: &str,
        instance_id: &str,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<DaemonLease, RuntimeError> {
        require_positive_ttl(ttl_ms)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT instance_id, fencing_epoch, lease_until_ms FROM daemon_leases WHERE workspace_id = ?1",
                [workspace_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
            )
            .optional()?;
        let lease_until_ms = now_ms.saturating_add(ttl_ms);
        let fencing_epoch = match existing {
            Some((owner, epoch, lease_until)) if owner == instance_id && lease_until > now_ms => {
                epoch
            }
            Some((owner, _, lease_until)) if lease_until > now_ms => {
                return Err(RuntimeError::LeaseHeld {
                    owner,
                    lease_until_ms: lease_until,
                });
            }
            Some((_, epoch, _)) => epoch + 1,
            None => 1,
        };
        transaction.execute(
            "INSERT INTO daemon_leases (workspace_id, instance_id, fencing_epoch, lease_until_ms, heartbeat_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(workspace_id) DO UPDATE SET instance_id = excluded.instance_id,
             fencing_epoch = excluded.fencing_epoch, lease_until_ms = excluded.lease_until_ms,
             heartbeat_at_ms = excluded.heartbeat_at_ms",
            params![workspace_id, instance_id, fencing_epoch, lease_until_ms, now_ms],
        )?;
        append_audit(
            &transaction,
            workspace_id,
            "daemon",
            instance_id,
            "lease_acquired",
            &format!("fencing_epoch={fencing_epoch}"),
            now_ms,
        )?;
        transaction.commit()?;
        Ok(DaemonLease {
            workspace_id: workspace_id.to_owned(),
            instance_id: instance_id.to_owned(),
            fencing_epoch,
            lease_until_ms,
        })
    }

    pub fn heartbeat_daemon(
        &self,
        lease: &DaemonLease,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<DaemonLease, RuntimeError> {
        require_positive_ttl(ttl_ms)?;
        let lease_until_ms = now_ms.saturating_add(ttl_ms);
        let connection = self.connect()?;
        let updated = connection.execute(
            "UPDATE daemon_leases SET heartbeat_at_ms = ?1, lease_until_ms = ?2
             WHERE workspace_id = ?3 AND instance_id = ?4 AND fencing_epoch = ?5
             AND lease_until_ms > ?1",
            params![
                now_ms,
                lease_until_ms,
                lease.workspace_id,
                lease.instance_id,
                lease.fencing_epoch
            ],
        )?;
        if updated != 1 {
            return Err(RuntimeError::StaleEpoch {
                entity: format!("daemon {}", lease.instance_id),
            });
        }
        Ok(DaemonLease {
            lease_until_ms,
            ..lease.clone()
        })
    }

    pub fn validate_daemon_lease(
        &self,
        lease: &DaemonLease,
        now_ms: i64,
    ) -> Result<(), RuntimeError> {
        let connection = self.connect()?;
        let valid = connection.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM daemon_leases WHERE workspace_id = ?1 AND instance_id = ?2
               AND fencing_epoch = ?3 AND lease_until_ms > ?4
             )",
            params![
                lease.workspace_id,
                lease.instance_id,
                lease.fencing_epoch,
                now_ms
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if valid {
            Ok(())
        } else {
            Err(RuntimeError::StaleEpoch {
                entity: format!("daemon {}", lease.instance_id),
            })
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_actor(
        &self,
        workspace_id: &str,
        actor_id: &str,
        team_id: Option<&str>,
        role: ActorRole,
        backend: &str,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<ActorRecord, RuntimeError> {
        self.register_actor_inner(
            None,
            workspace_id,
            actor_id,
            team_id,
            role,
            backend,
            now_ms,
            ttl_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_actor_fenced(
        &self,
        daemon_lease: &DaemonLease,
        workspace_id: &str,
        actor_id: &str,
        team_id: Option<&str>,
        role: ActorRole,
        backend: &str,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<ActorRecord, RuntimeError> {
        self.register_actor_inner(
            Some(daemon_lease),
            workspace_id,
            actor_id,
            team_id,
            role,
            backend,
            now_ms,
            ttl_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn register_actor_inner(
        &self,
        daemon_lease: Option<&DaemonLease>,
        workspace_id: &str,
        actor_id: &str,
        team_id: Option<&str>,
        role: ActorRole,
        backend: &str,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<ActorRecord, RuntimeError> {
        require_positive_ttl(ttl_ms)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(lease) = daemon_lease {
            validate_daemon_in_transaction(&transaction, lease, now_ms)?;
        }
        let previous_epoch = transaction
            .query_row(
                "SELECT actor_epoch FROM actors WHERE workspace_id = ?1 AND actor_id = ?2",
                params![workspace_id, actor_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let actor_epoch = previous_epoch.map_or(1, |epoch| epoch + 1);
        let lease_until_ms = now_ms.saturating_add(ttl_ms);
        transaction.execute(
            "INSERT INTO actors (workspace_id, actor_id, team_id, role, state, actor_epoch, backend,
              session_external_id, session_resume_token, heartbeat_at_ms, lease_until_ms)
             VALUES (?1, ?2, ?3, ?4, 'starting', ?5, ?6, NULL, NULL, ?7, ?8)
             ON CONFLICT(workspace_id, actor_id) DO UPDATE SET team_id = excluded.team_id,
              role = excluded.role, state = excluded.state, actor_epoch = excluded.actor_epoch,
              backend = excluded.backend, session_external_id = NULL, session_resume_token = NULL,
              heartbeat_at_ms = excluded.heartbeat_at_ms, lease_until_ms = excluded.lease_until_ms",
            params![
                workspace_id,
                actor_id,
                team_id,
                role.as_str(),
                actor_epoch,
                backend,
                now_ms,
                lease_until_ms
            ],
        )?;
        append_audit(
            &transaction,
            workspace_id,
            "actor",
            actor_id,
            "registered",
            &format!("actor_epoch={actor_epoch}"),
            now_ms,
        )?;
        let actor = actor_by_id(&transaction, workspace_id, actor_id)?.ok_or_else(|| {
            RuntimeError::NotFound {
                entity_kind: "actor",
                entity_id: actor_id.to_owned(),
            }
        })?;
        transaction.commit()?;
        Ok(actor)
    }

    pub fn attach_session(
        &self,
        workspace_id: &str,
        actor_id: &str,
        actor_epoch: i64,
        session: &agsv_session::SessionHandle,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<ActorRecord, RuntimeError> {
        self.attach_session_inner(
            None,
            workspace_id,
            actor_id,
            actor_epoch,
            None,
            session,
            now_ms,
            ttl_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn attach_launched_session(
        &self,
        daemon_lease: &DaemonLease,
        workspace_id: &str,
        actor_id: &str,
        actor_epoch: i64,
        launch_idempotency_key: &str,
        session: &agsv_session::SessionHandle,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<ActorRecord, RuntimeError> {
        self.attach_session_inner(
            Some(daemon_lease),
            workspace_id,
            actor_id,
            actor_epoch,
            Some(launch_idempotency_key),
            session,
            now_ms,
            ttl_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn attach_session_inner(
        &self,
        daemon_lease: Option<&DaemonLease>,
        workspace_id: &str,
        actor_id: &str,
        actor_epoch: i64,
        launch_idempotency_key: Option<&str>,
        session: &agsv_session::SessionHandle,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<ActorRecord, RuntimeError> {
        require_positive_ttl(ttl_ms)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(lease) = daemon_lease {
            validate_daemon_in_transaction(&transaction, lease, now_ms)?;
        }
        let actor = actor_by_id(&transaction, workspace_id, actor_id)?.ok_or_else(|| {
            RuntimeError::NotFound {
                entity_kind: "actor",
                entity_id: actor_id.to_owned(),
            }
        })?;
        if actor.backend != session.backend {
            return Err(RuntimeError::InvalidState(format!(
                "actor backend {} does not match session backend {}",
                actor.backend, session.backend
            )));
        }
        if actor.actor_epoch != actor_epoch || actor.lease_until_ms <= now_ms {
            return Err(RuntimeError::StaleEpoch {
                entity: format!("actor {actor_id}"),
            });
        }
        let updated = transaction.execute(
            "UPDATE actors SET state = 'online', backend = ?1, session_external_id = ?2,
             session_resume_token = ?3, heartbeat_at_ms = ?4, lease_until_ms = ?5
             WHERE workspace_id = ?6 AND actor_id = ?7 AND actor_epoch = ?8",
            params![
                session.backend,
                session.external_id,
                session.resume_token,
                now_ms,
                now_ms.saturating_add(ttl_ms),
                workspace_id,
                actor_id,
                actor_epoch
            ],
        )?;
        ensure_epoch_update(updated, "actor", actor_id)?;
        if let Some(idempotency_key) = launch_idempotency_key {
            let intent_updated = transaction.execute(
                "UPDATE launch_intents SET state = 'attached', updated_at_ms = ?1
                 WHERE workspace_id = ?2 AND idempotency_key = ?3 AND actor_id = ?4
                 AND backend = ?5 AND session_external_id = ?6",
                params![
                    now_ms,
                    workspace_id,
                    idempotency_key,
                    actor_id,
                    session.backend,
                    session.external_id
                ],
            )?;
            ensure_epoch_update(intent_updated, "launch intent", idempotency_key)?;
        }
        append_audit(
            &transaction,
            workspace_id,
            "actor",
            actor_id,
            "session_attached",
            &format!("backend={}", session.backend),
            now_ms,
        )?;
        let actor = actor_by_id(&transaction, workspace_id, actor_id)?.ok_or_else(|| {
            RuntimeError::NotFound {
                entity_kind: "actor",
                entity_id: actor_id.to_owned(),
            }
        })?;
        transaction.commit()?;
        Ok(actor)
    }

    pub fn heartbeat_actor(
        &self,
        workspace_id: &str,
        actor_id: &str,
        actor_epoch: i64,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<(), RuntimeError> {
        require_positive_ttl(ttl_ms)?;
        let connection = self.connect()?;
        let updated = connection.execute(
            "UPDATE actors SET state = 'online', heartbeat_at_ms = ?1, lease_until_ms = ?2
             WHERE workspace_id = ?3 AND actor_id = ?4 AND actor_epoch = ?5
             AND state = 'online' AND lease_until_ms > ?1",
            params![
                now_ms,
                now_ms.saturating_add(ttl_ms),
                workspace_id,
                actor_id,
                actor_epoch
            ],
        )?;
        ensure_epoch_update(updated, "actor", actor_id)
    }

    pub fn mark_actor_offline(
        &self,
        workspace_id: &str,
        actor_id: &str,
        actor_epoch: i64,
        now_ms: i64,
    ) -> Result<(), RuntimeError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE actors SET state = 'offline' WHERE workspace_id = ?1 AND actor_id = ?2 AND actor_epoch = ?3",
            params![workspace_id, actor_id, actor_epoch],
        )?;
        ensure_epoch_update(updated, "actor", actor_id)?;
        append_audit(
            &transaction,
            workspace_id,
            "actor",
            actor_id,
            "offline",
            "session absent or heartbeat expired",
            now_ms,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn actor(
        &self,
        workspace_id: &str,
        actor_id: &str,
    ) -> Result<Option<ActorRecord>, RuntimeError> {
        let connection = self.connect()?;
        actor_by_id(&connection, workspace_id, actor_id)
    }

    pub fn actors(&self, workspace_id: &str) -> Result<Vec<ActorRecord>, RuntimeError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT workspace_id, actor_id, team_id, role, state, actor_epoch, backend,
             session_external_id, session_resume_token, heartbeat_at_ms, lease_until_ms
             FROM actors WHERE workspace_id = ?1 ORDER BY actor_id",
        )?;
        let rows = statement.query_map([workspace_id], actor_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(actor_from_raw)
            .collect()
    }

    pub fn acquire_primary_lease(
        &self,
        workspace_id: &str,
        actor_id: &str,
        actor_epoch: i64,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<PrimaryLease, RuntimeError> {
        require_positive_ttl(ttl_ms)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actor = actor_by_id(&transaction, workspace_id, actor_id)?.ok_or_else(|| {
            RuntimeError::NotFound {
                entity_kind: "actor",
                entity_id: actor_id.to_owned(),
            }
        })?;
        if actor.actor_epoch != actor_epoch
            || actor.role != ActorRole::Primary
            || actor.lease_until_ms <= now_ms
        {
            return Err(RuntimeError::StaleEpoch {
                entity: format!("primary actor {actor_id}"),
            });
        }
        let existing = transaction
            .query_row(
                "SELECT actor_id, actor_epoch, fencing_epoch, lease_until_ms FROM primary_leases WHERE workspace_id = ?1",
                [workspace_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?)),
            )
            .optional()?;
        let fencing_epoch = match existing {
            Some((owner, owner_epoch, fence, lease_until))
                if owner == actor_id && owner_epoch == actor_epoch && lease_until > now_ms =>
            {
                fence
            }
            Some((owner, _, _, lease_until)) if lease_until > now_ms => {
                return Err(RuntimeError::LeaseHeld {
                    owner,
                    lease_until_ms: lease_until,
                });
            }
            Some((_, _, fence, _)) => fence + 1,
            None => 1,
        };
        let lease_until_ms = now_ms.saturating_add(ttl_ms);
        transaction.execute(
            "INSERT INTO primary_leases (workspace_id, actor_id, actor_epoch, fencing_epoch, lease_until_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(workspace_id) DO UPDATE SET actor_id = excluded.actor_id,
             actor_epoch = excluded.actor_epoch, fencing_epoch = excluded.fencing_epoch,
             lease_until_ms = excluded.lease_until_ms",
            params![workspace_id, actor_id, actor_epoch, fencing_epoch, lease_until_ms],
        )?;
        append_audit(
            &transaction,
            workspace_id,
            "primary_lease",
            actor_id,
            "acquired",
            &format!("fencing_epoch={fencing_epoch}"),
            now_ms,
        )?;
        transaction.commit()?;
        Ok(PrimaryLease {
            workspace_id: workspace_id.to_owned(),
            actor_id: actor_id.to_owned(),
            actor_epoch,
            fencing_epoch,
            lease_until_ms,
        })
    }

    pub fn prepare_launch(
        &self,
        daemon_lease: &DaemonLease,
        intent: &LaunchIntent,
        now_ms: i64,
    ) -> Result<LaunchIntent, RuntimeError> {
        if daemon_lease.workspace_id != intent.workspace_id {
            return Err(RuntimeError::Unauthorized(
                "daemon lease belongs to another workspace".to_owned(),
            ));
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_daemon_in_transaction(&transaction, daemon_lease, now_ms)?;
        if let Some(existing) =
            launch_intent_by_key(&transaction, &intent.workspace_id, &intent.idempotency_key)?
        {
            if same_launch_intent(&existing, intent) {
                transaction.commit()?;
                return Ok(existing);
            }
            return Err(RuntimeError::IdempotencyConflict(
                intent.idempotency_key.clone(),
            ));
        }
        transaction.execute(
            "INSERT INTO launch_intents (workspace_id, actor_id, idempotency_key,
             spec_fingerprint, canonical_working_directory, backend, session_name, state,
             resume_token, session_external_id, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'prepared', ?8, ?9, ?10, ?10)",
            params![
                intent.workspace_id,
                intent.actor_id,
                intent.idempotency_key,
                intent.spec_fingerprint,
                intent.canonical_working_directory.to_string_lossy(),
                intent.backend,
                intent.session_name,
                intent.resume_token,
                intent.session_external_id,
                now_ms
            ],
        )?;
        append_audit(
            &transaction,
            &intent.workspace_id,
            "launch_intent",
            &intent.idempotency_key,
            "prepared",
            &format!("fingerprint={}", intent.spec_fingerprint),
            now_ms,
        )?;
        let prepared =
            launch_intent_by_key(&transaction, &intent.workspace_id, &intent.idempotency_key)?
                .ok_or_else(|| RuntimeError::NotFound {
                    entity_kind: "launch intent",
                    entity_id: intent.idempotency_key.clone(),
                })?;
        transaction.commit()?;
        Ok(prepared)
    }

    pub fn checkpoint_launch(
        &self,
        daemon_lease: &DaemonLease,
        idempotency_key: &str,
        resume_token: &str,
        now_ms: i64,
    ) -> Result<(), RuntimeError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_daemon_in_transaction(&transaction, daemon_lease, now_ms)?;
        let existing =
            launch_intent_by_key(&transaction, &daemon_lease.workspace_id, idempotency_key)?
                .ok_or_else(|| RuntimeError::NotFound {
                    entity_kind: "launch intent",
                    entity_id: idempotency_key.to_owned(),
                })?;
        if matches!(
            existing.state,
            LaunchIntentState::Checkpointed
                | LaunchIntentState::Launched
                | LaunchIntentState::Attached
        ) {
            if existing.resume_token.as_deref() == Some(resume_token) {
                transaction.commit()?;
                return Ok(());
            }
            return Err(RuntimeError::IdempotencyConflict(
                idempotency_key.to_owned(),
            ));
        }
        transaction.execute(
            "UPDATE launch_intents SET state = 'checkpointed', resume_token = ?1,
             updated_at_ms = ?2 WHERE workspace_id = ?3 AND idempotency_key = ?4",
            params![
                resume_token,
                now_ms,
                daemon_lease.workspace_id,
                idempotency_key
            ],
        )?;
        append_audit(
            &transaction,
            &daemon_lease.workspace_id,
            "launch_intent",
            idempotency_key,
            "checkpointed",
            "backend launch checkpoint persisted",
            now_ms,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn record_launch_result(
        &self,
        daemon_lease: &DaemonLease,
        idempotency_key: &str,
        session: &agsv_session::SessionHandle,
        now_ms: i64,
    ) -> Result<(), RuntimeError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_daemon_in_transaction(&transaction, daemon_lease, now_ms)?;
        let existing =
            launch_intent_by_key(&transaction, &daemon_lease.workspace_id, idempotency_key)?
                .ok_or_else(|| RuntimeError::NotFound {
                    entity_kind: "launch intent",
                    entity_id: idempotency_key.to_owned(),
                })?;
        if existing.backend != session.backend {
            return Err(RuntimeError::InvalidState(format!(
                "launch intent backend {} does not match session backend {}",
                existing.backend, session.backend
            )));
        }
        if matches!(
            existing.state,
            LaunchIntentState::Launched | LaunchIntentState::Attached
        ) {
            let same = existing.session_external_id.as_deref()
                == Some(session.external_id.as_str())
                && existing.resume_token == session.resume_token;
            if same {
                transaction.commit()?;
                return Ok(());
            }
            return Err(RuntimeError::IdempotencyConflict(
                idempotency_key.to_owned(),
            ));
        }
        transaction.execute(
            "UPDATE launch_intents SET state = 'launched', session_external_id = ?1,
             resume_token = ?2, updated_at_ms = ?3
             WHERE workspace_id = ?4 AND idempotency_key = ?5",
            params![
                session.external_id,
                session.resume_token,
                now_ms,
                daemon_lease.workspace_id,
                idempotency_key
            ],
        )?;
        append_audit(
            &transaction,
            &daemon_lease.workspace_id,
            "launch_intent",
            idempotency_key,
            "launched",
            &format!("backend={}", session.backend),
            now_ms,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn launch_intent(
        &self,
        workspace_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<LaunchIntent>, RuntimeError> {
        let connection = self.connect()?;
        launch_intent_by_key(&connection, workspace_id, idempotency_key)
    }

    pub fn send_message(
        &self,
        message: &NewMessage,
        sender: &SenderContext,
        now_ms: i64,
    ) -> Result<MessageRecord, RuntimeError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorize_message(&transaction, message, sender, now_ms)?;
        if let Some(existing) = message_by_idempotency(
            &transaction,
            &message.workspace_id,
            &message.idempotency_key,
        )? {
            if same_message(&existing, message, sender) {
                transaction.commit()?;
                return Ok(existing);
            }
            return Err(RuntimeError::IdempotencyConflict(
                message.idempotency_key.clone(),
            ));
        }
        transaction.execute(
            "INSERT INTO messages (workspace_id, message_id, idempotency_key, sender_actor_id,
             sender_actor_epoch, primary_fencing_epoch, recipient_actor_id, recipient_team_id,
             kind, payload, available_at_ms, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                message.workspace_id,
                message.message_id,
                message.idempotency_key,
                message.sender_actor_id,
                sender.actor_epoch,
                sender.primary_fencing_epoch,
                message.recipient_actor_id,
                message.recipient_team_id,
                message.kind,
                message.payload,
                message.available_at_ms,
                message.created_at_ms
            ],
        )?;
        append_audit(
            &transaction,
            &message.workspace_id,
            "message",
            &message.message_id,
            "enqueued",
            &format!("kind={}", message.kind),
            message.created_at_ms,
        )?;
        let inserted = message_by_id(&transaction, &message.workspace_id, &message.message_id)?
            .ok_or_else(|| RuntimeError::NotFound {
                entity_kind: "message",
                entity_id: message.message_id.clone(),
            })?;
        transaction.commit()?;
        Ok(inserted)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn claim_message(
        &self,
        workspace_id: &str,
        actor_id: &str,
        actor_epoch: i64,
        now_ms: i64,
        claim_ttl_ms: i64,
    ) -> Result<Option<ClaimedMessage>, RuntimeError> {
        require_positive_ttl(claim_ttl_ms)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actor = active_actor(&transaction, workspace_id, actor_id, actor_epoch, now_ms)?;
        let message_id = transaction
            .query_row(
                "SELECT message_id FROM messages
                 WHERE workspace_id = ?1 AND acknowledged_at_ms IS NULL AND available_at_ms <= ?2
                   AND (claimed_by_actor_id IS NULL OR claim_until_ms <= ?2)
                   AND (
                     recipient_actor_id = ?3
                     OR (recipient_actor_id IS NULL AND recipient_team_id = ?4)
                     OR (recipient_actor_id IS NULL AND recipient_team_id IS NULL)
                   )
                 ORDER BY created_at_ms, message_id LIMIT 1",
                params![workspace_id, now_ms, actor_id, actor.team_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(message_id) = message_id else {
            transaction.commit()?;
            return Ok(None);
        };
        let claim_until_ms = now_ms.saturating_add(claim_ttl_ms);
        let updated = transaction.execute(
            "UPDATE messages SET claimed_by_actor_id = ?1, claimant_actor_epoch = ?2,
             delivery_epoch = delivery_epoch + 1, attempts = attempts + 1, claim_until_ms = ?3
             WHERE workspace_id = ?4 AND message_id = ?5 AND acknowledged_at_ms IS NULL
               AND (claimed_by_actor_id IS NULL OR claim_until_ms <= ?6)",
            params![
                actor_id,
                actor_epoch,
                claim_until_ms,
                workspace_id,
                message_id,
                now_ms
            ],
        )?;
        if updated != 1 {
            return Err(RuntimeError::InvalidState(
                "message claim lost atomic update".to_owned(),
            ));
        }
        append_audit(
            &transaction,
            workspace_id,
            "message",
            &message_id,
            "claimed",
            &format!("actor={actor_id}"),
            now_ms,
        )?;
        let message = message_by_id(&transaction, workspace_id, &message_id)?.ok_or_else(|| {
            RuntimeError::NotFound {
                entity_kind: "message",
                entity_id: message_id.clone(),
            }
        })?;
        let delivery_epoch = message.delivery_epoch;
        transaction.commit()?;
        Ok(Some(ClaimedMessage {
            message,
            delivery_epoch,
        }))
    }

    pub fn acknowledge_message(
        &self,
        workspace_id: &str,
        message_id: &str,
        actor_id: &str,
        actor_epoch: i64,
        delivery_epoch: i64,
        now_ms: i64,
    ) -> Result<(), RuntimeError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        active_actor(&transaction, workspace_id, actor_id, actor_epoch, now_ms)?;
        let updated = transaction.execute(
            "UPDATE messages SET acknowledged_at_ms = ?1
             WHERE workspace_id = ?2 AND message_id = ?3 AND claimed_by_actor_id = ?4
             AND claimant_actor_epoch = ?5 AND delivery_epoch = ?6 AND acknowledged_at_ms IS NULL
             AND claim_until_ms > ?1",
            params![
                now_ms,
                workspace_id,
                message_id,
                actor_id,
                actor_epoch,
                delivery_epoch
            ],
        )?;
        if updated == 0 {
            let existing =
                message_by_id(&transaction, workspace_id, message_id)?.ok_or_else(|| {
                    RuntimeError::NotFound {
                        entity_kind: "message",
                        entity_id: message_id.to_owned(),
                    }
                })?;
            let idempotent = existing.acknowledged_at_ms.is_some()
                && existing.claimed_by_actor_id.as_deref() == Some(actor_id)
                && existing.claimant_actor_epoch == Some(actor_epoch)
                && existing.delivery_epoch == delivery_epoch;
            if !idempotent {
                return Err(RuntimeError::StaleEpoch {
                    entity: format!("message delivery {message_id}"),
                });
            }
        } else {
            append_audit(
                &transaction,
                workspace_id,
                "message",
                message_id,
                "acknowledged",
                &format!("actor={actor_id}"),
                now_ms,
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn retry_message(
        &self,
        workspace_id: &str,
        message_id: &str,
        actor_id: &str,
        actor_epoch: i64,
        delivery_epoch: i64,
        now_ms: i64,
        delay_ms: i64,
        error: &str,
    ) -> Result<(), RuntimeError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        active_actor(&transaction, workspace_id, actor_id, actor_epoch, now_ms)?;
        let updated = transaction.execute(
            "UPDATE messages SET claimed_by_actor_id = NULL, claimant_actor_epoch = NULL,
             claim_until_ms = NULL, available_at_ms = ?1, last_error = ?2
             WHERE workspace_id = ?3 AND message_id = ?4 AND claimed_by_actor_id = ?5
             AND claimant_actor_epoch = ?6 AND delivery_epoch = ?7 AND acknowledged_at_ms IS NULL
             AND claim_until_ms > ?8",
            params![
                now_ms.saturating_add(delay_ms.max(0)),
                error,
                workspace_id,
                message_id,
                actor_id,
                actor_epoch,
                delivery_epoch,
                now_ms
            ],
        )?;
        ensure_epoch_update(updated, "message delivery", message_id)?;
        append_audit(
            &transaction,
            workspace_id,
            "message",
            message_id,
            "retry_scheduled",
            error,
            now_ms,
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Marks stale actors offline and releases expired unacknowledged deliveries.
    pub fn reconcile_expired(
        &self,
        workspace_id: &str,
        now_ms: i64,
    ) -> Result<(usize, usize), RuntimeError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actors = transaction.execute(
            "UPDATE actors SET state = 'offline'
             WHERE workspace_id = ?1 AND state IN ('starting', 'online') AND lease_until_ms <= ?2",
            params![workspace_id, now_ms],
        )?;
        let deliveries = transaction.execute(
            "UPDATE messages SET claimed_by_actor_id = NULL, claimant_actor_epoch = NULL,
             claim_until_ms = NULL, available_at_ms = ?2
             WHERE workspace_id = ?1 AND acknowledged_at_ms IS NULL
             AND claimed_by_actor_id IS NOT NULL AND claim_until_ms <= ?2",
            params![workspace_id, now_ms],
        )?;
        if actors > 0 || deliveries > 0 {
            append_audit(
                &transaction,
                workspace_id,
                "workspace",
                workspace_id,
                "reconciled",
                &format!("actors={actors},deliveries={deliveries}"),
                now_ms,
            )?;
        }
        transaction.commit()?;
        Ok((actors, deliveries))
    }

    pub fn pending_message_count(&self, workspace_id: &str) -> Result<usize, RuntimeError> {
        let connection = self.connect()?;
        let count = connection.query_row(
            "SELECT COUNT(*) FROM messages WHERE workspace_id = ?1 AND acknowledged_at_ms IS NULL",
            [workspace_id],
            |row| row.get::<_, i64>(0),
        )?;
        usize::try_from(count).map_err(|_| RuntimeError::Corrupt("negative message count".into()))
    }

    pub fn audit_events(&self, workspace_id: &str) -> Result<Vec<AuditEvent>, RuntimeError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT sequence, workspace_id, entity_kind, entity_id, event_type, detail, created_at_ms
             FROM audit_events WHERE workspace_id = ?1 ORDER BY sequence",
        )?;
        let rows = statement.query_map([workspace_id], |row| {
            Ok(AuditEvent {
                sequence: row.get(0)?,
                workspace_id: row.get(1)?,
                entity_kind: row.get(2)?,
                entity_id: row.get(3)?,
                event_type: row.get(4)?,
                detail: row.get(5)?,
                created_at_ms: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    fn connect(&self) -> Result<Connection, RuntimeError> {
        let connection = Connection::open(&self.path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        Ok(connection)
    }
}

#[allow(clippy::too_many_lines)]
fn migrate(connection: &mut Connection) -> Result<(), RuntimeError> {
    // The immediate transaction is acquired before schema inspection so concurrent first-open
    // callers cannot both decide to initialize the database.
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATION_BOOTSTRAP)?;
    let mut versions = {
        let mut statement =
            transaction.prepare("SELECT version FROM schema_migrations ORDER BY version")?;
        let rows = statement.query_map([], |row| row.get::<_, i64>(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    if versions.is_empty() {
        let unexpected_tables = transaction.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
             AND name NOT IN ('schema_migrations', 'sqlite_sequence')",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if unexpected_tables != 0 {
            return Err(RuntimeError::SchemaVersion(
                "schema_migrations is empty but runtime tables already exist".to_owned(),
            ));
        }
        transaction.execute_batch(MIGRATION_1)?;
        transaction.execute(
            "INSERT INTO schema_migrations (version, applied_at_ms) VALUES (1, 0)",
            [],
        )?;
        versions.push(1);
    }
    validate_versions(&versions)?;
    verify_tables(
        &transaction,
        &[
            "daemon_leases",
            "actors",
            "primary_leases",
            "messages",
            "audit_events",
        ],
    )?;
    verify_columns(
        &transaction,
        "daemon_leases",
        &[
            "workspace_id",
            "instance_id",
            "fencing_epoch",
            "lease_until_ms",
            "heartbeat_at_ms",
        ],
    )?;
    verify_columns(
        &transaction,
        "actors",
        &[
            "workspace_id",
            "actor_id",
            "team_id",
            "role",
            "state",
            "actor_epoch",
            "backend",
            "session_external_id",
            "session_resume_token",
            "heartbeat_at_ms",
            "lease_until_ms",
        ],
    )?;
    verify_columns(
        &transaction,
        "primary_leases",
        &[
            "workspace_id",
            "actor_id",
            "actor_epoch",
            "fencing_epoch",
            "lease_until_ms",
        ],
    )?;
    verify_columns(
        &transaction,
        "messages",
        &[
            "workspace_id",
            "message_id",
            "idempotency_key",
            "sender_actor_id",
            "recipient_actor_id",
            "recipient_team_id",
            "kind",
            "payload",
            "available_at_ms",
            "claimed_by_actor_id",
            "claimant_actor_epoch",
            "delivery_epoch",
            "attempts",
            "claim_until_ms",
            "acknowledged_at_ms",
            "last_error",
            "created_at_ms",
        ],
    )?;
    verify_columns(
        &transaction,
        "audit_events",
        &[
            "sequence",
            "workspace_id",
            "entity_kind",
            "entity_id",
            "event_type",
            "detail",
            "created_at_ms",
        ],
    )?;
    if versions.last().copied() == Some(1) {
        transaction.execute_batch(MIGRATION_2)?;
        transaction.execute(
            "INSERT INTO schema_migrations (version, applied_at_ms) VALUES (2, 0)",
            [],
        )?;
        versions.push(2);
    }
    validate_versions(&versions)?;
    verify_tables(&transaction, &["launch_intents"])?;
    verify_columns(
        &transaction,
        "messages",
        &["sender_actor_epoch", "primary_fencing_epoch"],
    )?;
    verify_columns(
        &transaction,
        "launch_intents",
        &[
            "workspace_id",
            "actor_id",
            "idempotency_key",
            "spec_fingerprint",
            "canonical_working_directory",
            "backend",
            "session_name",
            "state",
            "resume_token",
            "session_external_id",
            "created_at_ms",
            "updated_at_ms",
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

fn validate_versions(versions: &[i64]) -> Result<(), RuntimeError> {
    if versions
        .iter()
        .any(|version| *version > CURRENT_SCHEMA_VERSION)
    {
        return Err(RuntimeError::SchemaVersion(format!(
            "database is newer than supported version {CURRENT_SCHEMA_VERSION}: {versions:?}"
        )));
    }
    let expected: Vec<i64> = (1..=versions.last().copied().unwrap_or(0)).collect();
    if versions != expected {
        return Err(RuntimeError::SchemaVersion(format!(
            "migration history is not contiguous: {versions:?}"
        )));
    }
    Ok(())
}

fn verify_tables(connection: &Connection, tables: &[&str]) -> Result<(), RuntimeError> {
    for table in tables {
        let exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get::<_, bool>(0),
        )?;
        if !exists {
            return Err(RuntimeError::SchemaVersion(format!(
                "migration history is incomplete: missing table {table}"
            )));
        }
    }
    Ok(())
}

fn verify_columns(
    connection: &Connection,
    table: &str,
    required_columns: &[&str],
) -> Result<(), RuntimeError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = rows.collect::<Result<Vec<_>, _>>()?;
    for required in required_columns {
        if !columns.iter().any(|column| column == required) {
            return Err(RuntimeError::SchemaVersion(format!(
                "{table} is missing required column {required}"
            )));
        }
    }
    Ok(())
}

fn require_positive_ttl(ttl_ms: i64) -> Result<(), RuntimeError> {
    if ttl_ms <= 0 {
        Err(RuntimeError::InvalidState(
            "lease TTL must be positive".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn validate_daemon_in_transaction(
    transaction: &Transaction<'_>,
    lease: &DaemonLease,
    now_ms: i64,
) -> Result<(), RuntimeError> {
    let valid = transaction.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM daemon_leases WHERE workspace_id = ?1 AND instance_id = ?2
           AND fencing_epoch = ?3 AND lease_until_ms > ?4
         )",
        params![
            lease.workspace_id,
            lease.instance_id,
            lease.fencing_epoch,
            now_ms
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if valid {
        Ok(())
    } else {
        Err(RuntimeError::StaleEpoch {
            entity: format!("daemon {}", lease.instance_id),
        })
    }
}

fn ensure_epoch_update(updated: usize, kind: &str, id: &str) -> Result<(), RuntimeError> {
    if updated == 1 {
        Ok(())
    } else {
        Err(RuntimeError::StaleEpoch {
            entity: format!("{kind} {id}"),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn append_audit(
    transaction: &Transaction<'_>,
    workspace_id: &str,
    entity_kind: &str,
    entity_id: &str,
    event_type: &str,
    detail: &str,
    created_at_ms: i64,
) -> Result<(), rusqlite::Error> {
    transaction.execute(
        "INSERT INTO audit_events (workspace_id, entity_kind, entity_id, event_type, detail, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![workspace_id, entity_kind, entity_id, event_type, detail, created_at_ms],
    )?;
    Ok(())
}

type RawActor = (
    String,
    String,
    Option<String>,
    String,
    String,
    i64,
    String,
    Option<String>,
    Option<String>,
    i64,
    i64,
);

fn actor_from_row(row: &Row<'_>) -> Result<RawActor, rusqlite::Error> {
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
        row.get(9)?,
        row.get(10)?,
    ))
}

fn actor_from_raw(raw: RawActor) -> Result<ActorRecord, RuntimeError> {
    let session = raw.7.map(|external_id| agsv_session::SessionHandle {
        backend: raw.6.clone(),
        external_id,
        resume_token: raw.8,
    });
    Ok(ActorRecord {
        workspace_id: raw.0,
        actor_id: raw.1,
        team_id: raw.2,
        role: ActorRole::from_str(&raw.3)?,
        state: ActorState::from_str(&raw.4)?,
        actor_epoch: raw.5,
        backend: raw.6,
        session,
        heartbeat_at_ms: raw.9,
        lease_until_ms: raw.10,
    })
}

fn actor_by_id(
    connection: &Connection,
    workspace_id: &str,
    actor_id: &str,
) -> Result<Option<ActorRecord>, RuntimeError> {
    let raw = connection
        .query_row(
            "SELECT workspace_id, actor_id, team_id, role, state, actor_epoch, backend,
             session_external_id, session_resume_token, heartbeat_at_ms, lease_until_ms
             FROM actors WHERE workspace_id = ?1 AND actor_id = ?2",
            params![workspace_id, actor_id],
            actor_from_row,
        )
        .optional()?;
    raw.map(actor_from_raw).transpose()
}

fn active_actor(
    connection: &Connection,
    workspace_id: &str,
    actor_id: &str,
    actor_epoch: i64,
    now_ms: i64,
) -> Result<ActorRecord, RuntimeError> {
    let actor =
        actor_by_id(connection, workspace_id, actor_id)?.ok_or_else(|| RuntimeError::NotFound {
            entity_kind: "actor",
            entity_id: actor_id.to_owned(),
        })?;
    if actor.actor_epoch != actor_epoch
        || actor.state != ActorState::Online
        || actor.lease_until_ms <= now_ms
    {
        return Err(RuntimeError::StaleEpoch {
            entity: format!("actor {actor_id}"),
        });
    }
    Ok(actor)
}

fn authorize_message(
    connection: &Connection,
    message: &NewMessage,
    sender: &SenderContext,
    now_ms: i64,
) -> Result<(), RuntimeError> {
    if message.sender_actor_id != sender.actor_id {
        return Err(RuntimeError::Unauthorized(
            "message sender does not match authenticated actor".to_owned(),
        ));
    }
    let actor = active_actor(
        connection,
        &message.workspace_id,
        &sender.actor_id,
        sender.actor_epoch,
        now_ms,
    )?;
    match actor.role {
        ActorRole::Primary => {
            let fencing_epoch = sender.primary_fencing_epoch.ok_or_else(|| {
                RuntimeError::Unauthorized("Primary message requires fencing epoch".to_owned())
            })?;
            let valid = connection.query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM primary_leases WHERE workspace_id = ?1 AND actor_id = ?2
                   AND actor_epoch = ?3 AND fencing_epoch = ?4 AND lease_until_ms > ?5
                 )",
                params![
                    message.workspace_id,
                    sender.actor_id,
                    sender.actor_epoch,
                    fencing_epoch,
                    now_ms
                ],
                |row| row.get::<_, bool>(0),
            )?;
            if !valid {
                return Err(RuntimeError::StaleEpoch {
                    entity: format!("primary lease for {}", sender.actor_id),
                });
            }
        }
        ActorRole::Implementation => {
            if sender.primary_fencing_epoch.is_some() {
                return Err(RuntimeError::Unauthorized(
                    "implementation actor cannot present a Primary fence".to_owned(),
                ));
            }
        }
    }

    if let Some(recipient_actor_id) = &message.recipient_actor_id {
        let recipient = actor_by_id(connection, &message.workspace_id, recipient_actor_id)?
            .ok_or_else(|| RuntimeError::NotFound {
                entity_kind: "recipient actor",
                entity_id: recipient_actor_id.clone(),
            })?;
        if let Some(recipient_team_id) = &message.recipient_team_id {
            if recipient.team_id.as_ref() != Some(recipient_team_id) {
                return Err(RuntimeError::Unauthorized(
                    "recipient actor does not belong to the requested team".to_owned(),
                ));
            }
        }
        if actor.role == ActorRole::Implementation
            && recipient.role != ActorRole::Primary
            && recipient.team_id != actor.team_id
        {
            return Err(RuntimeError::Unauthorized(
                "implementation actor cannot send outside its team except to Primary".to_owned(),
            ));
        }
    } else if let Some(recipient_team_id) = &message.recipient_team_id {
        if actor.role == ActorRole::Implementation
            && actor.team_id.as_ref() != Some(recipient_team_id)
        {
            return Err(RuntimeError::Unauthorized(
                "implementation actor cannot send to another team".to_owned(),
            ));
        }
    } else if actor.role != ActorRole::Primary {
        return Err(RuntimeError::Unauthorized(
            "workspace broadcast requires Primary authorization".to_owned(),
        ));
    }
    Ok(())
}

type RawLaunchIntent = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);

fn launch_intent_from_row(row: &Row<'_>) -> Result<RawLaunchIntent, rusqlite::Error> {
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
        row.get(9)?,
    ))
}

fn launch_intent_from_raw(raw: RawLaunchIntent) -> Result<LaunchIntent, RuntimeError> {
    Ok(LaunchIntent {
        workspace_id: raw.0,
        actor_id: raw.1,
        idempotency_key: raw.2,
        spec_fingerprint: raw.3,
        canonical_working_directory: PathBuf::from(raw.4),
        backend: raw.5,
        session_name: raw.6,
        state: LaunchIntentState::from_str(&raw.7)?,
        resume_token: raw.8,
        session_external_id: raw.9,
    })
}

fn launch_intent_by_key(
    connection: &Connection,
    workspace_id: &str,
    idempotency_key: &str,
) -> Result<Option<LaunchIntent>, RuntimeError> {
    let raw = connection
        .query_row(
            "SELECT workspace_id, actor_id, idempotency_key, spec_fingerprint,
             canonical_working_directory, backend, session_name, state, resume_token,
             session_external_id FROM launch_intents
             WHERE workspace_id = ?1 AND idempotency_key = ?2",
            params![workspace_id, idempotency_key],
            launch_intent_from_row,
        )
        .optional()?;
    raw.map(launch_intent_from_raw).transpose()
}

fn same_launch_intent(existing: &LaunchIntent, proposed: &LaunchIntent) -> bool {
    existing.actor_id == proposed.actor_id
        && existing.spec_fingerprint == proposed.spec_fingerprint
        && existing.canonical_working_directory == proposed.canonical_working_directory
        && existing.backend == proposed.backend
        && existing.session_name == proposed.session_name
}

type RawMessage = (
    String,
    String,
    String,
    String,
    i64,
    Option<i64>,
    Option<String>,
    Option<String>,
    String,
    Vec<u8>,
    i64,
    Option<String>,
    Option<i64>,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    Option<String>,
    i64,
);

fn message_from_row(row: &Row<'_>) -> Result<RawMessage, rusqlite::Error> {
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
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
        row.get(17)?,
        row.get(18)?,
    ))
}

fn message_from_raw(raw: RawMessage) -> MessageRecord {
    MessageRecord {
        workspace_id: raw.0,
        message_id: raw.1,
        idempotency_key: raw.2,
        sender_actor_id: raw.3,
        sender_actor_epoch: raw.4,
        primary_fencing_epoch: raw.5,
        recipient_actor_id: raw.6,
        recipient_team_id: raw.7,
        kind: raw.8,
        payload: raw.9,
        available_at_ms: raw.10,
        claimed_by_actor_id: raw.11,
        claimant_actor_epoch: raw.12,
        delivery_epoch: raw.13,
        attempts: raw.14,
        claim_until_ms: raw.15,
        acknowledged_at_ms: raw.16,
        last_error: raw.17,
        created_at_ms: raw.18,
    }
}

const MESSAGE_COLUMNS: &str = "workspace_id, message_id, idempotency_key, sender_actor_id,
 sender_actor_epoch, primary_fencing_epoch, recipient_actor_id, recipient_team_id, kind, payload,
 available_at_ms, claimed_by_actor_id, claimant_actor_epoch, delivery_epoch, attempts,
 claim_until_ms, acknowledged_at_ms, last_error, created_at_ms";

fn message_by_id(
    connection: &Connection,
    workspace_id: &str,
    message_id: &str,
) -> Result<Option<MessageRecord>, RuntimeError> {
    let sql = format!(
        "SELECT {MESSAGE_COLUMNS} FROM messages WHERE workspace_id = ?1 AND message_id = ?2"
    );
    let raw = connection
        .query_row(&sql, params![workspace_id, message_id], message_from_row)
        .optional()?;
    Ok(raw.map(message_from_raw))
}

fn message_by_idempotency(
    connection: &Connection,
    workspace_id: &str,
    idempotency_key: &str,
) -> Result<Option<MessageRecord>, RuntimeError> {
    let sql = format!(
        "SELECT {MESSAGE_COLUMNS} FROM messages WHERE workspace_id = ?1 AND idempotency_key = ?2"
    );
    let raw = connection
        .query_row(
            &sql,
            params![workspace_id, idempotency_key],
            message_from_row,
        )
        .optional()?;
    Ok(raw.map(message_from_raw))
}

fn same_message(existing: &MessageRecord, new: &NewMessage, sender: &SenderContext) -> bool {
    existing.message_id == new.message_id
        && existing.sender_actor_id == new.sender_actor_id
        && existing.sender_actor_epoch == sender.actor_epoch
        && existing.primary_fencing_epoch == sender.primary_fencing_epoch
        && existing.recipient_actor_id == new.recipient_actor_id
        && existing.recipient_team_id == new.recipient_team_id
        && existing.kind == new.kind
        && existing.payload == new.payload
}
