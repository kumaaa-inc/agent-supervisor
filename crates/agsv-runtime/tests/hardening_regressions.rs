use std::path::Path;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use agsv_runtime::{
    ActorRole, ActorSpec, BackendRegistry, LaunchIntentState, NewMessage, RuntimeError,
    RuntimeService, SenderContext, SqliteStore,
};
use agsv_session::{
    FakeSessionBackend, LaunchCheckpoint, LaunchRequest, ResumeRequest, SessionBackend,
    SessionError, SessionHandle, SessionSnapshot, SessionStatus,
};
use tempfile::TempDir;

const WORKSPACE: &str = "workspace-hardening";
const TTL: i64 = 10_000;

fn open_store(directory: &TempDir) -> SqliteStore {
    SqliteStore::open(directory.path().join("runtime.sqlite3")).unwrap()
}

fn register_online(
    store: &SqliteStore,
    actor_id: &str,
    team_id: Option<&str>,
    role: ActorRole,
    backend: &str,
) -> i64 {
    let actor = store
        .register_actor(WORKSPACE, actor_id, team_id, role, backend, 0, TTL)
        .unwrap();
    store
        .attach_session(
            WORKSPACE,
            actor_id,
            actor.actor_epoch,
            &SessionHandle {
                backend: backend.into(),
                external_id: format!("session-{actor_id}"),
                resume_token: None,
            },
            0,
            TTL,
        )
        .unwrap();
    actor.actor_epoch
}

fn primary_sender(store: &SqliteStore) -> SenderContext {
    let epoch = register_online(store, "primary", None, ActorRole::Primary, "fake");
    let lease = store
        .acquire_primary_lease(WORKSPACE, "primary", epoch, 0, TTL)
        .unwrap();
    SenderContext::actor("primary", epoch).with_primary_fence(lease.fencing_epoch)
}

fn message(
    id: &str,
    sender: &str,
    recipient_actor: Option<&str>,
    recipient_team: Option<&str>,
) -> NewMessage {
    NewMessage {
        workspace_id: WORKSPACE.into(),
        message_id: id.into(),
        idempotency_key: format!("key-{id}"),
        sender_actor_id: sender.into(),
        recipient_actor_id: recipient_actor.map(str::to_owned),
        recipient_team_id: recipient_team.map(str::to_owned),
        kind: "test".into(),
        payload: id.as_bytes().to_vec(),
        available_at_ms: 0,
        created_at_ms: 0,
    }
}

fn actor_spec(root: &Path, backend: &str) -> ActorSpec {
    ActorSpec {
        actor_id: "worker".into(),
        team_id: Some("team-a".into()),
        role: ActorRole::Implementation,
        backend: backend.into(),
        session_name: "worker".into(),
        runtime: "codex".into(),
        working_directory: root.to_path_buf(),
        launch_idempotency_key: "launch-worker".into(),
        native_args: Vec::new(),
    }
}

fn registry(backend: Arc<dyn SessionBackend>) -> BackendRegistry {
    let mut registry = BackendRegistry::new();
    registry.register(backend).unwrap();
    registry
}

#[test]
fn message_insertion_authenticates_sender_fence_and_team_scope() {
    let directory = tempfile::tempdir().unwrap();
    let store = open_store(&directory);
    let primary = primary_sender(&store);
    let team_a_epoch = register_online(
        &store,
        "team-a-worker",
        Some("team-a"),
        ActorRole::Implementation,
        "fake",
    );
    register_online(
        &store,
        "team-b-worker",
        Some("team-b"),
        ActorRole::Implementation,
        "fake",
    );

    assert!(matches!(
        store.send_message(
            &message("ghost", "ghost", Some("primary"), None),
            &SenderContext::actor("ghost", 1),
            1
        ),
        Err(RuntimeError::NotFound { .. })
    ));
    assert!(matches!(
        store.send_message(
            &message("forged", "primary", None, Some("team-a")),
            &SenderContext::actor("primary", primary.actor_epoch).with_primary_fence(999),
            1
        ),
        Err(RuntimeError::StaleEpoch { .. })
    ));
    assert!(matches!(
        store.send_message(
            &message("stale-actor", "team-a-worker", Some("primary"), None),
            &SenderContext::actor("team-a-worker", team_a_epoch - 1),
            1
        ),
        Err(RuntimeError::StaleEpoch { .. })
    ));
    assert!(matches!(
        store.send_message(
            &message("cross-team", "team-a-worker", None, Some("team-b")),
            &SenderContext::actor("team-a-worker", team_a_epoch),
            1
        ),
        Err(RuntimeError::Unauthorized(_))
    ));
    assert!(matches!(
        store.send_message(
            &message("impersonated", "primary", None, Some("team-a")),
            &SenderContext::actor("team-a-worker", team_a_epoch),
            1
        ),
        Err(RuntimeError::Unauthorized(_))
    ));

    store
        .send_message(
            &message("candidate", "team-a-worker", Some("primary"), None),
            &SenderContext::actor("team-a-worker", team_a_epoch),
            1,
        )
        .unwrap();
    assert_eq!(store.pending_message_count(WORKSPACE).unwrap(), 1);
}

#[test]
#[allow(clippy::too_many_lines)]
fn expired_leases_and_claims_cannot_be_resurrected() {
    let directory = tempfile::tempdir().unwrap();
    let store = open_store(&directory);
    let first = store
        .acquire_daemon_lease(WORKSPACE, "daemon", 0, 5)
        .unwrap();
    assert!(matches!(
        store.heartbeat_daemon(&first, 5, 5),
        Err(RuntimeError::StaleEpoch { .. })
    ));
    let reacquired = store
        .acquire_daemon_lease(WORKSPACE, "daemon", 5, 5)
        .unwrap();
    assert_eq!(reacquired.fencing_epoch, first.fencing_epoch + 1);

    let actor = store
        .register_actor(
            WORKSPACE,
            "expiring",
            Some("team-a"),
            ActorRole::Implementation,
            "fake",
            0,
            5,
        )
        .unwrap();
    assert!(matches!(
        store.attach_session(
            WORKSPACE,
            "expiring",
            actor.actor_epoch,
            &SessionHandle {
                backend: "fake".into(),
                external_id: "late".into(),
                resume_token: None,
            },
            5,
            5
        ),
        Err(RuntimeError::StaleEpoch { .. })
    ));
    let online = store
        .register_actor(
            WORKSPACE,
            "online-expiring",
            Some("team-a"),
            ActorRole::Implementation,
            "fake",
            0,
            5,
        )
        .unwrap();
    store
        .attach_session(
            WORKSPACE,
            "online-expiring",
            online.actor_epoch,
            &SessionHandle {
                backend: "fake".into(),
                external_id: "online-expiring".into(),
                resume_token: None,
            },
            0,
            5,
        )
        .unwrap();
    assert!(matches!(
        store.heartbeat_actor(WORKSPACE, "online-expiring", online.actor_epoch, 5, 5),
        Err(RuntimeError::StaleEpoch { .. })
    ));

    let receiver_epoch = register_online(
        &store,
        "receiver",
        Some("team-a"),
        ActorRole::Implementation,
        "fake",
    );
    let sender = primary_sender(&store);
    store
        .send_message(
            &message("expiring-claim", "primary", None, Some("team-a")),
            &sender,
            1,
        )
        .unwrap();
    let claim = store
        .claim_message(WORKSPACE, "receiver", receiver_epoch, 1, 5)
        .unwrap()
        .unwrap();
    assert!(matches!(
        store.acknowledge_message(
            WORKSPACE,
            &claim.message.message_id,
            "receiver",
            receiver_epoch,
            claim.delivery_epoch,
            6
        ),
        Err(RuntimeError::StaleEpoch { .. })
    ));
    assert!(matches!(
        store.retry_message(
            WORKSPACE,
            &claim.message.message_id,
            "receiver",
            receiver_epoch,
            claim.delivery_epoch,
            6,
            0,
            "too late"
        ),
        Err(RuntimeError::StaleEpoch { .. })
    ));

    let primary_epoch = sender.actor_epoch;
    let first_primary_fence = sender.primary_fencing_epoch.unwrap();
    store
        .heartbeat_actor(WORKSPACE, "primary", primary_epoch, TTL - 1, TTL)
        .unwrap();
    let reacquired_primary = store
        .acquire_primary_lease(WORKSPACE, "primary", primary_epoch, TTL, 5)
        .unwrap();
    assert_eq!(reacquired_primary.fencing_epoch, first_primary_fence + 1);
}

#[test]
fn launch_intent_recovers_checkpoint_and_fingerprints_spec() {
    let directory = tempfile::tempdir().unwrap();
    let store = open_store(&directory);
    let backend = Arc::new(CheckpointBackend::default());
    let service = RuntimeService::new(
        WORKSPACE,
        "daemon",
        directory.path(),
        store.clone(),
        registry(backend.clone()),
    )
    .unwrap();
    service.start(0, 100).unwrap();
    let spec = actor_spec(directory.path(), "checkpoint");

    assert!(matches!(
        service.launch_actor(&spec, 1, TTL),
        Err(RuntimeError::Session(SessionError::Unavailable(_)))
    ));
    let checkpointed = store
        .launch_intent(WORKSPACE, &spec.launch_idempotency_key)
        .unwrap()
        .unwrap();
    assert_eq!(checkpointed.state, LaunchIntentState::Checkpointed);
    assert_eq!(checkpointed.resume_token.as_deref(), Some("pane-1"));

    let actor = service.launch_actor(&spec, 2, TTL).unwrap();
    assert_eq!(
        actor.session.unwrap().resume_token.as_deref(),
        Some("pane-1")
    );
    assert_eq!(
        backend.resume_tokens.lock().unwrap().as_slice(),
        [None, Some("pane-1".into())]
    );
    assert_eq!(
        store
            .launch_intent(WORKSPACE, &spec.launch_idempotency_key)
            .unwrap()
            .unwrap()
            .state,
        LaunchIntentState::Attached
    );

    let mut changed = spec;
    changed.runtime = "different-runtime".into();
    assert!(matches!(
        service.launch_actor(&changed, 3, TTL),
        Err(RuntimeError::IdempotencyConflict(_))
    ));
}

#[cfg(unix)]
#[test]
fn canonical_workspace_scope_rejects_symlink_escape() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().join("workspace");
    let outside = directory.path().join("outside");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    symlink(&outside, workspace.join("escape")).unwrap();
    let store = open_store(&directory);
    let backend = Arc::new(FakeSessionBackend::new());
    let service =
        RuntimeService::new(WORKSPACE, "daemon", &workspace, store, registry(backend)).unwrap();
    service.start(0, 100).unwrap();
    let mut spec = actor_spec(&workspace, "fake");
    spec.working_directory = workspace.join("escape");

    assert!(matches!(
        service.launch_actor(&spec, 1, TTL),
        Err(RuntimeError::WorkspaceScope(_))
    ));
}

#[test]
fn stolen_daemon_fence_blocks_post_launch_commit() {
    let directory = tempfile::tempdir().unwrap();
    let store = open_store(&directory);
    let backend = Arc::new(FenceStealingBackend {
        store: store.clone(),
    });
    let service = RuntimeService::new(
        WORKSPACE,
        "daemon-a",
        directory.path(),
        store.clone(),
        registry(backend),
    )
    .unwrap();
    service.start(0, 5).unwrap();

    let error = service
        .launch_actor(&actor_spec(directory.path(), "fence-stealer"), 1, TTL)
        .unwrap_err();
    assert!(matches!(error, RuntimeError::StaleEpoch { .. }));
    assert!(store.actor(WORKSPACE, "worker").unwrap().is_some());
    assert!(
        store
            .actor(WORKSPACE, "worker")
            .unwrap()
            .unwrap()
            .session
            .is_none()
    );
}

#[test]
fn persisted_backend_controls_reconciliation() {
    let directory = tempfile::tempdir().unwrap();
    let store = open_store(&directory);
    register_online(
        &store,
        "worker",
        Some("team-a"),
        ActorRole::Implementation,
        "not-registered",
    );
    let fake = Arc::new(FakeSessionBackend::new());
    let service =
        RuntimeService::new(WORKSPACE, "daemon", directory.path(), store, registry(fake)).unwrap();
    service.start(0, 100).unwrap();

    assert!(matches!(
        service.reconcile(1, TTL),
        Err(RuntimeError::BackendNotRegistered(name)) if name == "not-registered"
    ));
}

#[test]
fn migrations_serialize_first_open_and_reject_bad_histories() {
    let directory = tempfile::tempdir().unwrap();
    let path = Arc::new(directory.path().join("concurrent.sqlite3"));
    let barrier = Arc::new(Barrier::new(9));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let path = path.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            SqliteStore::open(path.as_ref())
        }));
    }
    barrier.wait();
    for worker in workers {
        assert!(worker.join().unwrap().is_ok());
    }

    let newer_path = directory.path().join("newer.sqlite3");
    SqliteStore::open(&newer_path).unwrap();
    rusqlite::Connection::open(&newer_path)
        .unwrap()
        .execute(
            "INSERT INTO schema_migrations (version, applied_at_ms) VALUES (99, 0)",
            [],
        )
        .unwrap();
    assert!(matches!(
        SqliteStore::open(&newer_path),
        Err(RuntimeError::SchemaVersion(_))
    ));

    let incomplete_path = directory.path().join("incomplete.sqlite3");
    let incomplete = rusqlite::Connection::open(&incomplete_path).unwrap();
    incomplete
        .execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at_ms INTEGER NOT NULL);
             INSERT INTO schema_migrations (version, applied_at_ms) VALUES (1, 0);",
        )
        .unwrap();
    drop(incomplete);
    assert!(matches!(
        SqliteStore::open(&incomplete_path),
        Err(RuntimeError::SchemaVersion(_))
    ));
}

#[derive(Default)]
struct CheckpointBackend {
    resume_tokens: Mutex<Vec<Option<String>>>,
}

impl SessionBackend for CheckpointBackend {
    fn name(&self) -> &'static str {
        "checkpoint"
    }

    fn launch(&self, _request: &LaunchRequest) -> Result<SessionHandle, SessionError> {
        Err(SessionError::Unavailable(
            "checkpoint-aware launch required".into(),
        ))
    }

    fn launch_with_checkpoint(
        &self,
        request: &LaunchRequest,
        checkpoint: &mut dyn FnMut(&LaunchCheckpoint) -> Result<(), SessionError>,
    ) -> Result<SessionHandle, SessionError> {
        let mut tokens = self.resume_tokens.lock().unwrap();
        tokens.push(request.resume_token.clone());
        if tokens.len() == 1 {
            drop(tokens);
            checkpoint(&LaunchCheckpoint {
                resume_token: "pane-1".into(),
            })?;
            return Err(SessionError::Unavailable("simulated crash".into()));
        }
        Ok(SessionHandle {
            backend: self.name().into(),
            external_id: request.session_name.clone(),
            resume_token: request.resume_token.clone(),
        })
    }

    fn resume(&self, request: &ResumeRequest) -> Result<SessionHandle, SessionError> {
        Ok(request.handle.clone())
    }

    fn status(&self, handle: &SessionHandle) -> Result<SessionSnapshot, SessionError> {
        Ok(SessionSnapshot {
            handle: handle.clone(),
            status: SessionStatus::Idle,
            detail: None,
        })
    }

    fn send_message(&self, _handle: &SessionHandle, _message: &str) -> Result<(), SessionError> {
        Ok(())
    }

    fn stop(&self, _handle: &SessionHandle) -> Result<(), SessionError> {
        Ok(())
    }
}

struct FenceStealingBackend {
    store: SqliteStore,
}

impl SessionBackend for FenceStealingBackend {
    fn name(&self) -> &'static str {
        "fence-stealer"
    }

    fn launch(&self, request: &LaunchRequest) -> Result<SessionHandle, SessionError> {
        self.store
            .acquire_daemon_lease(WORKSPACE, "daemon-b", 5, 100)
            .map_err(|error| SessionError::Unavailable(error.to_string()))?;
        Ok(SessionHandle {
            backend: self.name().into(),
            external_id: request.session_name.clone(),
            resume_token: None,
        })
    }

    fn resume(&self, request: &ResumeRequest) -> Result<SessionHandle, SessionError> {
        Ok(request.handle.clone())
    }

    fn status(&self, handle: &SessionHandle) -> Result<SessionSnapshot, SessionError> {
        Ok(SessionSnapshot {
            handle: handle.clone(),
            status: SessionStatus::Idle,
            detail: None,
        })
    }

    fn send_message(&self, _handle: &SessionHandle, _message: &str) -> Result<(), SessionError> {
        Ok(())
    }

    fn stop(&self, _handle: &SessionHandle) -> Result<(), SessionError> {
        Ok(())
    }
}
