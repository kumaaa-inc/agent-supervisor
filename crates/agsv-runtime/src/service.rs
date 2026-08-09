use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agsv_session::{LaunchRequest, SessionBackend, SessionError, SessionHandle, SessionStatus};
use sha2::{Digest, Sha256};

use crate::{
    ActorRecord, ActorSpec, ActorState, DaemonLease, LaunchIntent, LaunchIntentState,
    ReconcileReport, RuntimeError, SqliteStore,
};

/// Named session backends available to a runtime service.
#[derive(Clone, Default)]
pub struct BackendRegistry {
    backends: BTreeMap<String, Arc<dyn SessionBackend>>,
}

impl BackendRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, backend: Arc<dyn SessionBackend>) -> Result<(), RuntimeError> {
        let name = backend.name().to_owned();
        if self.backends.insert(name.clone(), backend).is_some() {
            return Err(RuntimeError::InvalidState(format!(
                "session backend {name} is already registered"
            )));
        }
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Arc<dyn SessionBackend>, RuntimeError> {
        self.backends
            .get(name)
            .cloned()
            .ok_or_else(|| RuntimeError::BackendNotRegistered(name.to_owned()))
    }
}

/// Local single-instance service boundary guarded by a durable fencing lease.
pub struct RuntimeService {
    workspace_id: String,
    instance_id: String,
    workspace_root: PathBuf,
    store: SqliteStore,
    backends: BackendRegistry,
    daemon_lease: Mutex<Option<DaemonLease>>,
}

impl RuntimeService {
    pub fn new(
        workspace_id: impl Into<String>,
        instance_id: impl Into<String>,
        workspace_root: impl AsRef<Path>,
        store: SqliteStore,
        backends: BackendRegistry,
    ) -> Result<Self, RuntimeError> {
        let workspace_root = std::fs::canonicalize(workspace_root.as_ref()).map_err(|error| {
            RuntimeError::WorkspaceScope(format!(
                "cannot canonicalize {}: {error}",
                workspace_root.as_ref().display()
            ))
        })?;
        Ok(Self {
            workspace_id: workspace_id.into(),
            instance_id: instance_id.into(),
            workspace_root,
            store,
            backends,
            daemon_lease: Mutex::new(None),
        })
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

    #[allow(clippy::too_many_lines)]
    pub fn launch_actor(
        &self,
        spec: &ActorSpec,
        now_ms: i64,
        presence_ttl_ms: i64,
    ) -> Result<ActorRecord, RuntimeError> {
        let daemon_lease = self.require_started(now_ms)?;
        let backend = self.backends.get(&spec.backend)?;
        let canonical_working_directory = self.authorized_directory(&spec.working_directory)?;
        let spec_fingerprint = fingerprint_spec(spec, &canonical_working_directory);
        let proposed_intent = LaunchIntent {
            workspace_id: self.workspace_id.clone(),
            actor_id: spec.actor_id.clone(),
            idempotency_key: spec.launch_idempotency_key.clone(),
            spec_fingerprint,
            canonical_working_directory: canonical_working_directory.clone(),
            backend: spec.backend.clone(),
            session_name: spec.session_name.clone(),
            state: LaunchIntentState::Prepared,
            resume_token: None,
            session_external_id: None,
        };
        let intent = self
            .store
            .prepare_launch(&daemon_lease, &proposed_intent, now_ms)?;

        if let Some(existing) = self.store.actor(&self.workspace_id, &spec.actor_id)? {
            let healthy = existing.backend == spec.backend
                && existing.state == ActorState::Online
                && existing.lease_until_ms > now_ms
                && existing
                    .session
                    .as_ref()
                    .map(|session| backend.status(session))
                    .transpose()?
                    .is_some_and(|snapshot| snapshot.status.is_present());
            if healthy {
                return Ok(existing);
            }
        }

        let actor = self.store.register_actor_fenced(
            &daemon_lease,
            &self.workspace_id,
            &spec.actor_id,
            spec.team_id.as_deref(),
            spec.role,
            &spec.backend,
            now_ms,
            presence_ttl_ms,
        )?;

        let recovered_handle =
            intent
                .session_external_id
                .as_ref()
                .map(|external_id| SessionHandle {
                    backend: intent.backend.clone(),
                    external_id: external_id.clone(),
                    resume_token: intent.resume_token.clone(),
                });
        let handle = if let Some(handle) = recovered_handle {
            let snapshot = backend.status(&handle)?;
            if snapshot.status.is_present() {
                handle
            } else {
                self.launch_backend(
                    &daemon_lease,
                    spec,
                    &canonical_working_directory,
                    intent.resume_token,
                    now_ms,
                    backend.as_ref(),
                )?
            }
        } else {
            self.launch_backend(
                &daemon_lease,
                spec,
                &canonical_working_directory,
                intent.resume_token,
                now_ms,
                backend.as_ref(),
            )?
        };
        self.store.record_launch_result(
            &daemon_lease,
            &spec.launch_idempotency_key,
            &handle,
            now_ms,
        )?;
        // This transaction revalidates the daemon fence after the external launch side effect.
        self.store.attach_launched_session(
            &daemon_lease,
            &self.workspace_id,
            &spec.actor_id,
            actor.actor_epoch,
            &spec.launch_idempotency_key,
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
            if actor.state != ActorState::Online || actor.lease_until_ms <= now_ms {
                continue;
            }
            let Some(session) = actor.session else {
                continue;
            };
            let backend = self.backends.get(&actor.backend)?;
            match backend.status(&session) {
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
                Err(SessionError::NotFound(_)) => {
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

    fn launch_backend(
        &self,
        daemon_lease: &DaemonLease,
        spec: &ActorSpec,
        canonical_working_directory: &Path,
        resume_token: Option<String>,
        now_ms: i64,
        backend: &dyn SessionBackend,
    ) -> Result<SessionHandle, RuntimeError> {
        let request = LaunchRequest {
            actor_id: spec.actor_id.clone(),
            session_name: spec.session_name.clone(),
            runtime: spec.runtime.clone(),
            working_directory: canonical_working_directory.to_path_buf(),
            idempotency_key: spec.launch_idempotency_key.clone(),
            native_args: spec.native_args.clone(),
            initial_prompt: None,
            resume_token,
        };
        let mut checkpoint = |progress: &agsv_session::LaunchCheckpoint| {
            self.store
                .checkpoint_launch(
                    daemon_lease,
                    &spec.launch_idempotency_key,
                    &progress.resume_token,
                    now_ms,
                )
                .map_err(|error| SessionError::Checkpoint(error.to_string()))
        };
        backend
            .launch_with_checkpoint(&request, &mut checkpoint)
            .map_err(Into::into)
    }

    fn authorized_directory(&self, requested: &Path) -> Result<PathBuf, RuntimeError> {
        let canonical = std::fs::canonicalize(requested).map_err(|error| {
            RuntimeError::WorkspaceScope(format!(
                "cannot canonicalize {}: {error}",
                requested.display()
            ))
        })?;
        if canonical.starts_with(&self.workspace_root) {
            Ok(canonical)
        } else {
            Err(RuntimeError::WorkspaceScope(format!(
                "{} is outside {}",
                canonical.display(),
                self.workspace_root.display()
            )))
        }
    }

    fn require_started(&self, now_ms: i64) -> Result<DaemonLease, RuntimeError> {
        let guard = self
            .daemon_lease
            .lock()
            .map_err(|_| RuntimeError::Poisoned)?;
        let lease = guard.as_ref().ok_or_else(|| {
            RuntimeError::InvalidState("runtime service has not acquired its lease".to_owned())
        })?;
        self.store.validate_daemon_lease(lease, now_ms)?;
        Ok(lease.clone())
    }
}

fn fingerprint_spec(spec: &ActorSpec, canonical_working_directory: &Path) -> String {
    let mut hasher = Sha256::new();
    for value in [
        spec.actor_id.as_bytes(),
        spec.team_id.as_deref().unwrap_or("").as_bytes(),
        spec.role.as_str().as_bytes(),
        spec.backend.as_bytes(),
        spec.session_name.as_bytes(),
        spec.runtime.as_bytes(),
        canonical_working_directory.as_os_str().as_encoded_bytes(),
    ] {
        hash_field(&mut hasher, value);
    }
    for argument in &spec.native_args {
        hash_field(&mut hasher, argument.as_bytes());
    }
    let digest = hasher.finalize();
    let mut fingerprint = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut fingerprint, "{byte:02x}").expect("writing to a String cannot fail");
    }
    fingerprint
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value);
}
