use std::sync::{Arc, Mutex};

use agsv_session::{LaunchRequest, SessionBackend, SessionStatus};

use crate::{
    ActorRecord, ActorSpec, ActorState, DaemonLease, ReconcileReport, RuntimeError, SqliteStore,
};

/// Local single-instance service boundary guarded by a durable fencing lease.
pub struct RuntimeService {
    workspace_id: String,
    instance_id: String,
    store: SqliteStore,
    backend: Arc<dyn SessionBackend>,
    daemon_lease: Mutex<Option<DaemonLease>>,
}

impl RuntimeService {
    #[must_use]
    pub fn new(
        workspace_id: impl Into<String>,
        instance_id: impl Into<String>,
        store: SqliteStore,
        backend: Arc<dyn SessionBackend>,
    ) -> Self {
        Self {
            workspace_id: workspace_id.into(),
            instance_id: instance_id.into(),
            store,
            backend,
            daemon_lease: Mutex::new(None),
        }
    }

    #[must_use]
    pub fn store(&self) -> &SqliteStore {
        &self.store
    }

    pub fn start(&self, now_ms: i64, ttl_ms: i64) -> Result<DaemonLease, RuntimeError> {
        let lease = self.store.acquire_daemon_lease(
            &self.workspace_id,
            &self.instance_id,
            now_ms,
            ttl_ms,
        )?;
        *self
            .daemon_lease
            .lock()
            .map_err(|_| RuntimeError::Poisoned)? = Some(lease.clone());
        Ok(lease)
    }

    pub fn heartbeat(&self, now_ms: i64, ttl_ms: i64) -> Result<DaemonLease, RuntimeError> {
        let mut guard = self
            .daemon_lease
            .lock()
            .map_err(|_| RuntimeError::Poisoned)?;
        let current = guard.as_ref().ok_or_else(|| {
            RuntimeError::InvalidState("runtime service has not acquired its lease".to_owned())
        })?;
        let renewed = self.store.heartbeat_daemon(current, now_ms, ttl_ms)?;
        *guard = Some(renewed.clone());
        Ok(renewed)
    }

    pub fn launch_actor(
        &self,
        spec: &ActorSpec,
        now_ms: i64,
        presence_ttl_ms: i64,
    ) -> Result<ActorRecord, RuntimeError> {
        self.require_started(now_ms)?;
        if let Some(existing) = self.store.actor(&self.workspace_id, &spec.actor_id)? {
            let healthy = existing.state == ActorState::Online
                && existing.lease_until_ms > now_ms
                && existing
                    .session
                    .as_ref()
                    .map(|session| self.backend.status(session))
                    .transpose()?
                    .is_some_and(|snapshot| snapshot.status.is_present());
            if healthy {
                return Ok(existing);
            }
        }

        let actor = self.store.register_actor(
            &self.workspace_id,
            &spec.actor_id,
            spec.team_id.as_deref(),
            spec.role,
            self.backend.name(),
            now_ms,
            presence_ttl_ms,
        )?;
        let handle = self.backend.launch(&LaunchRequest {
            actor_id: spec.actor_id.clone(),
            session_name: spec.session_name.clone(),
            runtime: spec.runtime.clone(),
            working_directory: spec.working_directory.clone(),
            idempotency_key: spec.launch_idempotency_key.clone(),
            native_args: spec.native_args.clone(),
        })?;
        self.store.attach_session(
            &self.workspace_id,
            &spec.actor_id,
            actor.actor_epoch,
            &handle,
            now_ms,
            presence_ttl_ms,
        )
    }

    pub fn reconcile(
        &self,
        now_ms: i64,
        presence_ttl_ms: i64,
    ) -> Result<ReconcileReport, RuntimeError> {
        self.require_started(now_ms)?;
        let (_, deliveries) = self.store.reconcile_expired(&self.workspace_id, now_ms)?;
        let mut report = ReconcileReport {
            expired_deliveries_released: deliveries,
            ..ReconcileReport::default()
        };
        for actor in self.store.actors(&self.workspace_id)? {
            report.actors_checked += 1;
            let Some(session) = actor.session else {
                continue;
            };
            match self.backend.status(&session) {
                Ok(snapshot) if snapshot.status.is_present() => {
                    self.store.heartbeat_actor(
                        &self.workspace_id,
                        &actor.actor_id,
                        actor.actor_epoch,
                        now_ms,
                        presence_ttl_ms,
                    )?;
                    report.actors_marked_online += 1;
                }
                Ok(snapshot)
                    if matches!(
                        snapshot.status,
                        SessionStatus::Missing | SessionStatus::Stopped { .. }
                    ) =>
                {
                    self.store.mark_actor_offline(
                        &self.workspace_id,
                        &actor.actor_id,
                        actor.actor_epoch,
                        now_ms,
                    )?;
                    report.actors_marked_offline += 1;
                }
                Ok(_) => {}
                Err(agsv_session::SessionError::NotFound(_)) => {
                    self.store.mark_actor_offline(
                        &self.workspace_id,
                        &actor.actor_id,
                        actor.actor_epoch,
                        now_ms,
                    )?;
                    report.actors_marked_offline += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(report)
    }

    fn require_started(&self, now_ms: i64) -> Result<(), RuntimeError> {
        let guard = self
            .daemon_lease
            .lock()
            .map_err(|_| RuntimeError::Poisoned)?;
        let lease = guard.as_ref().ok_or_else(|| {
            RuntimeError::InvalidState("runtime service has not acquired its lease".to_owned())
        })?;
        self.store.validate_daemon_lease(lease, now_ms)
    }
}
