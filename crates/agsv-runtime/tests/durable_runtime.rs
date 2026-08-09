use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use agsv_runtime::{
    ActorRole, ActorSpec, BackendRegistry, NewMessage, RuntimeError, RuntimeService, SenderContext,
    SqliteStore,
};
use agsv_session::{FakeEvent, FakeSessionBackend, SessionHandle};
use tempfile::TempDir;

const WORKSPACE: &str = "workspace-1";
const ACTOR_TTL: i64 = 10_000;

fn open_store(directory: &TempDir) -> SqliteStore {
    SqliteStore::open(directory.path().join("runtime.sqlite3")).unwrap()
}

fn register_online(
    store: &SqliteStore,
    actor_id: &str,
    team_id: Option<&str>,
    role: ActorRole,
) -> i64 {
    let actor = store
        .register_actor(WORKSPACE, actor_id, team_id, role, "fake", 0, ACTOR_TTL)
        .unwrap();
    store
        .attach_session(
            WORKSPACE,
            actor_id,
            actor.actor_epoch,
            &SessionHandle {
                backend: "fake".into(),
                external_id: format!("session-{actor_id}"),
                resume_token: None,
            },
            0,
            ACTOR_TTL,
        )
        .unwrap();
    actor.actor_epoch
}

fn register_primary_sender(store: &SqliteStore) -> SenderContext {
    let primary_epoch = register_online(store, "primary", None, ActorRole::Primary);
    let lease = store
        .acquire_primary_lease(WORKSPACE, "primary", primary_epoch, 0, ACTOR_TTL)
        .unwrap();
    SenderContext::actor("primary", primary_epoch).with_primary_fence(lease.fencing_epoch)
}

fn message(
    sequence: usize,
    sender: &str,
    recipient_actor: Option<&str>,
    recipient_team: Option<&str>,
) -> NewMessage {
    NewMessage {
        workspace_id: WORKSPACE.into(),
        message_id: format!("message-{sequence:03}"),
        idempotency_key: format!("send-{sequence:03}"),
        sender_actor_id: sender.into(),
        recipient_actor_id: recipient_actor.map(str::to_owned),
        recipient_team_id: recipient_team.map(str::to_owned),
        kind: "implementation_request".into(),
        payload: format!("payload-{sequence}").into_bytes(),
        available_at_ms: 0,
        created_at_ms: i64::try_from(sequence).unwrap(),
    }
}

#[test]
fn crash_restart_releases_expired_delivery_and_rejects_stale_ack() {
    let directory = tempfile::tempdir().unwrap();
    let store = open_store(&directory);
    assert_eq!(store.journal_mode().unwrap(), "wal");
    let first_epoch = register_online(
        &store,
        "implementation-1",
        Some("team-a"),
        ActorRole::Implementation,
    );
    let second_epoch = register_online(
        &store,
        "implementation-2",
        Some("team-a"),
        ActorRole::Implementation,
    );
    let primary_sender = register_primary_sender(&store);
    let inserted = store
        .send_message(
            &message(1, "primary", None, Some("team-a")),
            &primary_sender,
            1,
        )
        .unwrap();
    let duplicate = store
        .send_message(
            &message(1, "primary", None, Some("team-a")),
            &primary_sender,
            1,
        )
        .unwrap();
    assert_eq!(inserted, duplicate);
    assert_eq!(inserted.sender_actor_epoch, primary_sender.actor_epoch);
    assert_eq!(
        inserted.primary_fencing_epoch,
        primary_sender.primary_fencing_epoch
    );

    let first_claim = store
        .claim_message(WORKSPACE, "implementation-1", first_epoch, 10, 40)
        .unwrap()
        .unwrap();
    assert_eq!(first_claim.message.attempts, 1);
    drop(store);

    let restarted = open_store(&directory);
    let (_, released) = restarted.reconcile_expired(WORKSPACE, 60).unwrap();
    assert_eq!(released, 1);
    let second_claim = restarted
        .claim_message(WORKSPACE, "implementation-2", second_epoch, 60, 40)
        .unwrap()
        .unwrap();
    assert_eq!(
        second_claim.message.message_id,
        first_claim.message.message_id
    );
    assert_eq!(second_claim.message.attempts, 2);
    assert_eq!(second_claim.delivery_epoch, first_claim.delivery_epoch + 1);

    let stale = restarted.acknowledge_message(
        WORKSPACE,
        &first_claim.message.message_id,
        "implementation-1",
        first_epoch,
        first_claim.delivery_epoch,
        61,
    );
    assert!(matches!(stale, Err(RuntimeError::StaleEpoch { .. })));
    restarted
        .acknowledge_message(
            WORKSPACE,
            &second_claim.message.message_id,
            "implementation-2",
            second_epoch,
            second_claim.delivery_epoch,
            62,
        )
        .unwrap();
    // Acknowledgement itself is idempotent.
    restarted
        .acknowledge_message(
            WORKSPACE,
            &second_claim.message.message_id,
            "implementation-2",
            second_epoch,
            second_claim.delivery_epoch,
            63,
        )
        .unwrap();
    assert_eq!(restarted.pending_message_count(WORKSPACE).unwrap(), 0);
}

#[test]
fn concurrent_clients_claim_each_message_once() {
    let directory = tempfile::tempdir().unwrap();
    let store = open_store(&directory);
    let actor_one_epoch = register_online(
        &store,
        "implementation-1",
        Some("team-shared"),
        ActorRole::Implementation,
    );
    let actor_two_epoch = register_online(
        &store,
        "implementation-2",
        Some("team-shared"),
        ActorRole::Implementation,
    );
    let primary_sender = register_primary_sender(&store);
    for sequence in 0..40 {
        store
            .send_message(
                &message(sequence, "primary", None, Some("team-shared")),
                &primary_sender,
                1,
            )
            .unwrap();
    }

    let barrier = Arc::new(Barrier::new(3));
    let acknowledged = Arc::new(Mutex::new(Vec::new()));
    let mut threads = Vec::new();
    for (actor_id, actor_epoch) in [
        ("implementation-1", actor_one_epoch),
        ("implementation-2", actor_two_epoch),
    ] {
        let client = store.clone();
        let barrier = barrier.clone();
        let acknowledged = acknowledged.clone();
        threads.push(thread::spawn(move || {
            barrier.wait();
            for tick in 0..10_000 {
                if client.pending_message_count(WORKSPACE).unwrap() == 0 {
                    break;
                }
                let now_ms = 100 + tick;
                if let Some(claim) = client
                    .claim_message(WORKSPACE, actor_id, actor_epoch, now_ms, 5_000)
                    .unwrap()
                {
                    client
                        .acknowledge_message(
                            WORKSPACE,
                            &claim.message.message_id,
                            actor_id,
                            actor_epoch,
                            claim.delivery_epoch,
                            now_ms,
                        )
                        .unwrap();
                    acknowledged.lock().unwrap().push(claim.message.message_id);
                } else {
                    thread::yield_now();
                }
            }
        }));
    }
    barrier.wait();
    for worker in threads {
        worker.join().unwrap();
    }

    let ids = acknowledged.lock().unwrap();
    assert_eq!(ids.len(), 40);
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), 40);
    assert_eq!(store.pending_message_count(WORKSPACE).unwrap(), 0);
}

#[test]
fn explicit_retry_obeys_delay_and_advances_delivery_epoch() {
    let directory = tempfile::tempdir().unwrap();
    let store = open_store(&directory);
    let actor_epoch = register_online(
        &store,
        "implementation-1",
        Some("team-a"),
        ActorRole::Implementation,
    );
    let primary_sender = register_primary_sender(&store);
    store
        .send_message(
            &message(50, "primary", None, Some("team-a")),
            &primary_sender,
            1,
        )
        .unwrap();
    let first = store
        .claim_message(WORKSPACE, "implementation-1", actor_epoch, 10, 100)
        .unwrap()
        .unwrap();
    store
        .retry_message(
            WORKSPACE,
            &first.message.message_id,
            "implementation-1",
            actor_epoch,
            first.delivery_epoch,
            11,
            20,
            "temporary backend failure",
        )
        .unwrap();
    assert!(
        store
            .claim_message(WORKSPACE, "implementation-1", actor_epoch, 30, 100)
            .unwrap()
            .is_none()
    );
    let retried = store
        .claim_message(WORKSPACE, "implementation-1", actor_epoch, 31, 100)
        .unwrap()
        .unwrap();
    assert_eq!(retried.delivery_epoch, first.delivery_epoch + 1);
    assert_eq!(retried.message.attempts, 2);
    assert_eq!(
        retried.message.last_error.as_deref(),
        Some("temporary backend failure")
    );
}

#[test]
fn daemon_and_primary_leases_are_fenced_across_restart() {
    let directory = tempfile::tempdir().unwrap();
    let store = open_store(&directory);
    let first = store
        .acquire_daemon_lease(WORKSPACE, "daemon-a", 0, 50)
        .unwrap();
    assert!(matches!(
        store.acquire_daemon_lease(WORKSPACE, "daemon-b", 20, 50),
        Err(RuntimeError::LeaseHeld { .. })
    ));
    let second = store
        .acquire_daemon_lease(WORKSPACE, "daemon-b", 51, 50)
        .unwrap();
    assert_eq!(second.fencing_epoch, first.fencing_epoch + 1);
    assert!(matches!(
        store.heartbeat_daemon(&first, 52, 50),
        Err(RuntimeError::StaleEpoch { .. })
    ));

    let primary_epoch = register_online(&store, "primary", None, ActorRole::Primary);
    let lease = store
        .acquire_primary_lease(WORKSPACE, "primary", primary_epoch, 100, 100)
        .unwrap();
    let renewed = store
        .acquire_primary_lease(WORKSPACE, "primary", primary_epoch, 110, 100)
        .unwrap();
    assert_eq!(lease.fencing_epoch, renewed.fencing_epoch);
}

fn actor_spec(
    repository: &Path,
    actor_id: &str,
    team_id: Option<&str>,
    role: ActorRole,
) -> ActorSpec {
    ActorSpec {
        actor_id: actor_id.into(),
        team_id: team_id.map(str::to_owned),
        role,
        backend: "fake".into(),
        session_name: actor_id.into(),
        runtime: if role == ActorRole::Primary {
            "claude".into()
        } else {
            "codex".into()
        },
        working_directory: repository.to_path_buf(),
        launch_idempotency_key: format!("launch-{actor_id}"),
        native_args: Vec::new(),
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn fake_backend_runs_primary_with_two_implementation_teams() {
    let directory = tempfile::tempdir().unwrap();
    let store = open_store(&directory);
    let backend = Arc::new(FakeSessionBackend::new());
    let mut backends = BackendRegistry::new();
    backends.register(backend.clone()).unwrap();
    let service = RuntimeService::new(
        WORKSPACE,
        "daemon",
        directory.path(),
        store.clone(),
        backends,
    )
    .unwrap();
    service.start(0, 1_000).unwrap();

    let primary = service
        .launch_actor(
            &actor_spec(directory.path(), "primary", None, ActorRole::Primary),
            1,
            ACTOR_TTL,
        )
        .unwrap();
    let team_a = service
        .launch_actor(
            &actor_spec(
                directory.path(),
                "implementation-a",
                Some("team-a"),
                ActorRole::Implementation,
            ),
            2,
            ACTOR_TTL,
        )
        .unwrap();
    let team_b = service
        .launch_actor(
            &actor_spec(
                directory.path(),
                "implementation-b",
                Some("team-b"),
                ActorRole::Implementation,
            ),
            3,
            ACTOR_TTL,
        )
        .unwrap();
    // Healthy launch is discovered instead of duplicated.
    service
        .launch_actor(
            &actor_spec(
                directory.path(),
                "implementation-a",
                Some("team-a"),
                ActorRole::Implementation,
            ),
            4,
            ACTOR_TTL,
        )
        .unwrap();
    let primary_lease = store
        .acquire_primary_lease(WORKSPACE, "primary", primary.actor_epoch, 5, 1_000)
        .unwrap();
    let primary_sender = SenderContext::actor("primary", primary.actor_epoch)
        .with_primary_fence(primary_lease.fencing_epoch);

    store
        .send_message(
            &message(100, "primary", None, Some("team-a")),
            &primary_sender,
            6,
        )
        .unwrap();
    store
        .send_message(
            &message(101, "primary", None, Some("team-b")),
            &primary_sender,
            6,
        )
        .unwrap();
    for actor in [&team_a, &team_b] {
        let claimed = store
            .claim_message(WORKSPACE, &actor.actor_id, actor.actor_epoch, 10, 100)
            .unwrap()
            .unwrap();
        store
            .acknowledge_message(
                WORKSPACE,
                &claimed.message.message_id,
                &actor.actor_id,
                actor.actor_epoch,
                claimed.delivery_epoch,
                11,
            )
            .unwrap();
    }

    for (sequence, actor) in [(200, &team_a), (201, &team_b)] {
        let mut candidate = message(sequence, &actor.actor_id, Some("primary"), None);
        candidate.kind = "candidate_ready".into();
        candidate.payload = format!("sha-{sequence:040}").into_bytes();
        store
            .send_message(
                &candidate,
                &SenderContext::actor(&actor.actor_id, actor.actor_epoch),
                12,
            )
            .unwrap();
    }
    for _ in 0..2 {
        let candidate = store
            .claim_message(WORKSPACE, "primary", primary.actor_epoch, 20, 100)
            .unwrap()
            .unwrap();
        assert_eq!(candidate.message.kind, "candidate_ready");
        store
            .acknowledge_message(
                WORKSPACE,
                &candidate.message.message_id,
                "primary",
                primary.actor_epoch,
                candidate.delivery_epoch,
                21,
            )
            .unwrap();
    }
    let report = service.reconcile(30, ACTOR_TTL).unwrap();
    assert_eq!(report.actors_checked, 3);
    assert_eq!(report.actors_marked_online, 3);
    assert_eq!(store.pending_message_count(WORKSPACE).unwrap(), 0);

    let launches = backend
        .events()
        .unwrap()
        .into_iter()
        .filter(|event| matches!(event, FakeEvent::Launched { .. }))
        .count();
    assert_eq!(launches, 3);
    assert!(
        store
            .audit_events(WORKSPACE)
            .unwrap()
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
    );
}
