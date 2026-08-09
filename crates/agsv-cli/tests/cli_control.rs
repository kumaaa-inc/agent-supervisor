use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use serde_json::Value;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    state: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let serial = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("agsv-control-e2e-{}-{serial}", std::process::id()));
        let state = root.with_extension("state");
        fs::create_dir(&root).unwrap();
        run_git(&root, &["init"]);
        run_git(&root, &["config", "user.name", "AGSV Test"]);
        run_git(&root, &["config", "user.email", "agsv@example.invalid"]);
        fs::write(root.join("README.md"), "base\n").unwrap();
        run_git(&root, &["add", "README.md"]);
        run_git(&root, &["commit", "-m", "base"]);
        Self { root, state }
    }

    fn agsv(&self, actor: Option<(&str, &str)>, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agsv"));
        command
            .arg("--workspace")
            .arg(&self.root)
            .arg("--json")
            .env("AGSV_STATE_HOME", &self.state)
            .env("AGSV_SESSION_BACKEND", "fake");
        if let Some((id, role)) = actor {
            command
                .env("AGSV_ACTOR_ID", id)
                .env("AGSV_ACTOR_ROLE", role);
        }
        command.args(args).output().unwrap()
    }

    fn ok(&self, actor: Option<(&str, &str)>, args: &[&str]) -> Value {
        let output = self.agsv(actor, args);
        assert!(
            output.status.success(),
            "command {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["data"].clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).unwrap();
        }
        if self.state.exists() {
            fs::remove_dir_all(&self.state).unwrap();
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn fake_primary_two_team_review_and_recovery_flow() {
    let fixture = Fixture::new();
    fixture.ok(None, &["start"]);
    fixture.ok(
        Some(("primary-e2e", "primary")),
        &["context", "--bootstrap"],
    );
    let alpha = fixture.ok(
        Some(("primary-e2e", "primary")),
        &["team", "create", "alpha", "--operation-id", "team-alpha"],
    );
    let beta = fixture.ok(
        Some(("primary-e2e", "primary")),
        &["team", "create", "beta", "--operation-id", "team-beta"],
    );
    let alpha_dir = PathBuf::from(alpha["working_directory"].as_str().unwrap());
    assert_ne!(
        alpha_dir,
        PathBuf::from(beta["working_directory"].as_str().unwrap())
    );

    let created = fixture.ok(
        Some(("primary-e2e", "primary")),
        &[
            "request",
            "create",
            "--team",
            "team-alpha",
            "--title",
            "implement feature",
            "--body",
            "change the feature and return test evidence",
            "--operation-id",
            "request-feature",
        ],
    );
    let request_id = created["request"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &["context", "--bootstrap"],
    );
    fixture.ok(
        Some(("impl-beta-1", "implementation")),
        &["context", "--bootstrap"],
    );
    fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &[
            "message",
            "send",
            "--to",
            "primary",
            "--kind",
            "progress",
            "--body",
            "implementation underway",
            "--request",
            &request_id,
            "--operation-id",
            "progress-feature-1",
        ],
    );

    let sha1 = commit(
        &alpha_dir,
        "feature.txt",
        "candidate one\n",
        "candidate one",
    );
    fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &[
            "request",
            "complete",
            &request_id,
            "--candidate-sha",
            &sha1,
            "--evidence",
            "tests pass",
            "--operation-id",
            "candidate-feature-1",
        ],
    );
    fixture.ok(
        Some(("primary-e2e", "primary")),
        &[
            "decision",
            "submit",
            "--request",
            &request_id,
            "--candidate-sha",
            &sha1,
            "--decision",
            "rejected",
            "--summary",
            "needs a fix",
            "--operation-id",
            "review-feature-1",
        ],
    );
    fixture.ok(
        Some(("primary-e2e", "primary")),
        &[
            "message",
            "send",
            "--to",
            "impl-alpha-1",
            "--kind",
            "fix_request",
            "--body",
            "apply the requested fix",
            "--request",
            &request_id,
            "--operation-id",
            "fix-feature-1",
        ],
    );

    let sha2 = commit(
        &alpha_dir,
        "feature.txt",
        "candidate two\n",
        "candidate two",
    );
    fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &[
            "request",
            "complete",
            &request_id,
            "--candidate-sha",
            &sha2,
            "--evidence",
            "tests pass after fix",
            "--operation-id",
            "candidate-feature-2",
        ],
    );
    let accepted = fixture.ok(
        Some(("primary-e2e", "primary")),
        &[
            "decision",
            "submit",
            "--request",
            &request_id,
            "--candidate-sha",
            &sha2,
            "--decision",
            "accepted",
            "--summary",
            "approved",
            "--operation-id",
            "review-feature-2",
        ],
    );
    assert_eq!(
        accepted["integration_authorization"]["candidate"]["sha"],
        sha2
    );

    fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &[
            "message",
            "send",
            "--to",
            "team-beta",
            "--kind",
            "consultation_request",
            "--body",
            "check the shared interface",
            "--operation-id",
            "consult-beta-1",
        ],
    );
    let beta_inbox = fixture.ok(
        Some(("impl-beta-1", "implementation")),
        &["message", "inbox", "--actor", "impl-beta-1"],
    );
    let consultation = beta_inbox["deliveries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|delivery| delivery["envelope"]["message"]["kind"] == "consultation_request")
        .expect("consultation should be delivered");
    let consultation_id = consultation["envelope"]["message_id"].as_str().unwrap();
    fixture.ok(
        Some(("impl-beta-1", "implementation")),
        &[
            "message",
            "ack",
            consultation_id,
            "--actor",
            "impl-beta-1",
            "--operation-id",
            "ack-consult-beta-1",
        ],
    );

    let recovered = fixture.ok(None, &["request", "show", &request_id]);
    assert_eq!(recovered["request"]["status"], "integration_authorized");
    assert_eq!(recovered["request"]["candidate"]["sha"], sha2);
}

#[test]
fn concurrent_bootstrap_mutations_use_cas_without_lost_state() {
    const CLIENTS: usize = 8;
    let fixture = Fixture::new();
    fixture.ok(None, &["start"]);
    let barrier = Arc::new(Barrier::new(CLIENTS));
    let outputs = std::thread::scope(|scope| {
        let handles = (0..CLIENTS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let root = fixture.root.clone();
                let state = fixture.state.clone();
                scope.spawn(move || {
                    barrier.wait();
                    Command::new(env!("CARGO_BIN_EXE_agsv"))
                        .arg("--workspace")
                        .arg(root)
                        .arg("--json")
                        .env("AGSV_STATE_HOME", state)
                        .env("AGSV_SESSION_BACKEND", "fake")
                        .env("AGSV_ACTOR_ID", "primary-cas")
                        .env("AGSV_ACTOR_ROLE", "primary")
                        .args(["context", "--bootstrap"])
                        .output()
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(outputs.iter().all(|output| output.status.success()));
    let status = fixture.ok(None, &["status"]);
    assert!(status["revision"].as_u64().unwrap() > CLIENTS as u64);
    assert_eq!(status["primary"]["actor_id"], "primary-cas");
}

fn run_git(directory: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn commit(directory: &Path, file: &str, contents: &str, message: &str) -> String {
    fs::write(directory.join(file), contents).unwrap();
    run_git(directory, &["add", file]);
    run_git(directory, &["commit", "-m", message]);
    run_git(directory, &["rev-parse", "HEAD"])
}
