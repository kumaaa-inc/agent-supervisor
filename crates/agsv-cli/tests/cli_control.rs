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
        self.agsv_with_env(actor, args, &[])
    }

    fn agsv_with_env(
        &self,
        actor: Option<(&str, &str)>,
        args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agsv"));
        command
            .arg("--workspace")
            .arg(&self.root)
            .arg("--json")
            .env("AGSV_STATE_HOME", &self.state)
            .env("AGSV_SESSION_BACKEND", "fake")
            .env_remove("HERDR_PANE_ID")
            .env_remove("AGSV_ACTOR_ID")
            .env_remove("AGSV_ACTOR_ROLE")
            .env_remove("AGSV_DEV_ALLOW_INSECURE_ACTOR");
        if let Some((id, role)) = actor {
            command
                .env("AGSV_DEV_ALLOW_INSECURE_ACTOR", "1")
                .env("AGSV_ACTOR_ID", id)
                .env("AGSV_ACTOR_ROLE", role);
        }
        command.envs(extra_env.iter().copied());
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

    fn error(&self, actor: Option<(&str, &str)>, args: &[&str]) -> Value {
        let output = self.agsv(actor, args);
        assert!(
            !output.status.success(),
            "command {args:?} unexpectedly succeeded: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"].clone()
    }

    fn agsv_from_current(
        &self,
        current: &Path,
        actor: Option<(&str, &str)>,
        args: &[&str],
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agsv"));
        command
            .current_dir(current)
            .arg("--json")
            .env("AGSV_STATE_HOME", &self.state)
            .env("AGSV_SESSION_BACKEND", "fake")
            .env_remove("HERDR_PANE_ID")
            .env_remove("AGSV_ACTOR_ID")
            .env_remove("AGSV_ACTOR_ROLE")
            .env_remove("AGSV_DEV_ALLOW_INSECURE_ACTOR");
        if let Some((id, role)) = actor {
            command
                .env("AGSV_DEV_ALLOW_INSECURE_ACTOR", "1")
                .env("AGSV_ACTOR_ID", id)
                .env("AGSV_ACTOR_ROLE", role);
        }
        command.args(args).output().unwrap()
    }

    fn agsv_in_pane(&self, pane_id: &str, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_agsv"))
            .arg("--workspace")
            .arg(&self.root)
            .arg("--json")
            .env("AGSV_STATE_HOME", &self.state)
            .env("AGSV_SESSION_BACKEND", "fake")
            .env("HERDR_PANE_ID", pane_id)
            .env_remove("AGSV_ACTOR_ID")
            .env_remove("AGSV_ACTOR_ROLE")
            .env_remove("AGSV_DEV_ALLOW_INSECURE_ACTOR")
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let linked = self.root.with_extension("linked-worktree");
        if linked.exists() {
            fs::remove_dir_all(linked).unwrap();
        }
        if self.root.exists() {
            fs::remove_dir_all(&self.root).unwrap();
        }
        if self.state.exists() {
            fs::remove_dir_all(&self.state).unwrap();
        }
    }
}

fn error_code(output: &Output) -> String {
    serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"]
        .as_str()
        .unwrap()
        .to_owned()
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
    let beta_dir = PathBuf::from(beta["working_directory"].as_str().unwrap());
    assert_ne!(alpha_dir, beta_dir);

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
    let run_id = created["run"]["run_id"].as_str().unwrap().to_owned();
    let paused = fixture.ok(
        Some(("primary-e2e", "primary")),
        &["run", "pause", &run_id, "--operation-id", "pause-feature"],
    );
    assert_eq!(paused["status"], "paused");
    let resumed = fixture.ok(
        Some(("primary-e2e", "primary")),
        &["run", "resume", &run_id, "--operation-id", "resume-feature"],
    );
    assert_eq!(resumed["status"], "active");
    fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &["context", "--bootstrap"],
    );
    fixture.ok(
        Some(("impl-beta-1", "implementation")),
        &["context", "--bootstrap"],
    );
    let claim = fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &[
            "request",
            "claim",
            &request_id,
            "--operation-id",
            "claim-feature",
        ],
    );
    assert_eq!(claim["outcome"], "already_assigned");
    assert_eq!(claim["claimed"], false);
    let foreign_sha = commit(
        &beta_dir,
        "foreign.txt",
        "other team's commit\n",
        "foreign candidate",
    );
    let foreign = fixture.agsv(
        Some(("impl-alpha-1", "implementation")),
        &[
            "request",
            "complete",
            &request_id,
            "--candidate-sha",
            &foreign_sha,
            "--operation-id",
            "candidate-foreign",
        ],
    );
    assert!(!foreign.status.success());
    let foreign_error: Value = serde_json::from_slice(&foreign.stderr).unwrap();
    assert_eq!(
        foreign_error["error"]["code"],
        "candidate_not_worktree_head"
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
        &["message", "inbox"],
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
            "--operation-id",
            "ack-consult-beta-1",
        ],
    );

    let recovered = fixture.ok(None, &["request", "show", &request_id]);
    assert_eq!(recovered["request"]["status"], "integration_authorized");
    assert_eq!(recovered["request"]["candidate"]["sha"], sha2);
}

#[test]
#[allow(clippy::too_many_lines)]
fn typed_cross_team_handoff_qa_and_integration_flow() {
    let fixture = Fixture::new();
    fixture.ok(None, &["start"]);
    fixture.ok(
        Some(("primary-typed", "primary")),
        &["context", "--bootstrap"],
    );
    fixture.ok(
        Some(("primary-typed", "primary")),
        &["team", "create", "alpha", "--operation-id", "typed-alpha"],
    );
    let beta = fixture.ok(
        Some(("primary-typed", "primary")),
        &["team", "create", "beta", "--operation-id", "typed-beta"],
    );
    let beta_dir = PathBuf::from(beta["working_directory"].as_str().unwrap());
    fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &["context", "--bootstrap"],
    );
    fixture.ok(
        Some(("impl-beta-1", "implementation")),
        &["context", "--bootstrap"],
    );

    let alpha_request = fixture.ok(
        Some(("primary-typed", "primary")),
        &[
            "request",
            "create",
            "--team",
            "team-alpha",
            "--title",
            "handoff work",
            "--operation-id",
            "typed-request-alpha",
        ],
    )["request"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let beta_request = fixture.ok(
        Some(("primary-typed", "primary")),
        &[
            "request",
            "create",
            "--team",
            "team-beta",
            "--title",
            "provider work",
            "--operation-id",
            "typed-request-beta",
        ],
    )["request"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let consultation = fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &[
            "message",
            "send",
            "--kind",
            "consultation-request",
            "--to",
            "team-beta",
            "--subject",
            "shared API",
            "--body",
            "Which result shape should alpha consume?",
            "--operation-id",
            "typed-consultation",
        ],
    );
    let consultation_id = consultation["message_id"].as_str().unwrap();
    let consultation_retry = fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &[
            "message",
            "send",
            "--kind",
            "consultation-request",
            "--to",
            "team-beta",
            "--subject",
            "shared API",
            "--body",
            "Which result shape should alpha consume?",
            "--operation-id",
            "typed-consultation",
        ],
    );
    assert_eq!(consultation_retry["message_id"], consultation["message_id"]);
    fixture.ok(
        Some(("impl-beta-1", "implementation")),
        &[
            "message",
            "send",
            "--kind",
            "consultation-response",
            "--consultation-id",
            consultation_id,
            "--body",
            "Consume the stable v1 shape.",
            "--operation-id",
            "typed-consultation-response",
        ],
    );
    let alpha_inbox = fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &["message", "inbox", "--actor", "impl-alpha-1"],
    );
    assert!(
        alpha_inbox["deliveries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|delivery| delivery["envelope"]["message"]["kind"] == "consultation_response")
    );

    fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &[
            "message",
            "send",
            "--kind",
            "dependency-notice",
            "--request",
            &alpha_request,
            "--depends-on-request",
            &beta_request,
            "--body",
            "Alpha needs beta's generated contract.",
            "--operation-id",
            "typed-dependency",
        ],
    );
    let wrong_dependency_target = fixture.error(
        Some(("impl-alpha-1", "implementation")),
        &[
            "message",
            "send",
            "--kind",
            "dependency-notice",
            "--to",
            "team-alpha",
            "--request",
            &alpha_request,
            "--depends-on-request",
            &beta_request,
            "--body",
            "Assert the wrong provider route.",
            "--operation-id",
            "typed-dependency-wrong-target",
        ],
    );
    assert_eq!(wrong_dependency_target["code"], "invalid_request");
    assert!(
        wrong_dependency_target["message"]
            .as_str()
            .unwrap()
            .contains("does not match the durable target")
    );
    fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &[
            "message",
            "send",
            "--kind",
            "conflict-notice",
            "--to",
            "team-beta",
            "--resource",
            "src/shared.rs",
            "--body",
            "Both teams may edit the shared module.",
            "--operation-id",
            "typed-conflict",
        ],
    );
    let missing_resource = fixture.error(
        Some(("impl-alpha-1", "implementation")),
        &[
            "message",
            "send",
            "--kind",
            "conflict-notice",
            "--to",
            "team-beta",
            "--body",
            "Missing the required resource.",
            "--operation-id",
            "typed-conflict-invalid",
        ],
    );
    assert_eq!(missing_resource["code"], "invalid_request");
    assert!(
        missing_resource["message"]
            .as_str()
            .unwrap()
            .contains("requires at least one --resource")
    );

    let offer = fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &[
            "message",
            "send",
            "--kind",
            "handoff-offer",
            "--request",
            &alpha_request,
            "--to",
            "team-beta",
            "--body",
            "Beta now owns the shared contract.",
            "--operation-id",
            "typed-handoff-offer",
        ],
    );
    let handoff_id = offer["message"]["payload"]["handoff_id"].as_str().unwrap();
    let wrong_acceptor = fixture.error(
        Some(("impl-alpha-1", "implementation")),
        &[
            "message",
            "send",
            "--kind",
            "handoff-acceptance",
            "--handoff-id",
            handoff_id,
            "--operation-id",
            "typed-handoff-wrong-acceptor",
        ],
    );
    assert_eq!(wrong_acceptor["code"], "domain_error");
    fixture.ok(
        Some(("impl-beta-1", "implementation")),
        &[
            "message",
            "send",
            "--kind",
            "handoff-acceptance",
            "--handoff-id",
            handoff_id,
            "--operation-id",
            "typed-handoff-acceptance",
        ],
    );
    let handed_off = fixture.ok(None, &["request", "show", &alpha_request]);
    assert_eq!(handed_off["request"]["team_id"], "team-beta");
    assert_eq!(
        handed_off["request"]["assignment"]["actor"]["actor_id"],
        "impl-beta-1"
    );
    assert_eq!(handed_off["request"]["assignment"]["epoch"], 2);
    assert_eq!(
        fixture.error(
            Some(("impl-alpha-1", "implementation")),
            &[
                "message",
                "send",
                "--kind",
                "progress",
                "--to",
                "primary",
                "--body",
                "stale owner",
                "--request",
                &alpha_request,
                "--operation-id",
                "typed-stale-progress",
            ],
        )["code"],
        "domain_error"
    );
    fixture.ok(
        Some(("impl-beta-1", "implementation")),
        &[
            "message",
            "send",
            "--kind",
            "progress",
            "--to",
            "primary",
            "--body",
            "new owner active",
            "--request",
            &alpha_request,
            "--operation-id",
            "typed-new-owner-progress",
        ],
    );

    let beta_sha = commit(
        &beta_dir,
        "provider.txt",
        "provider candidate\n",
        "provider candidate",
    );
    fixture.ok(
        Some(("impl-beta-1", "implementation")),
        &[
            "request",
            "complete",
            &beta_request,
            "--candidate-sha",
            &beta_sha,
            "--operation-id",
            "typed-beta-candidate",
        ],
    );
    assert_eq!(
        fixture.error(
            Some(("impl-alpha-1", "implementation")),
            &[
                "message",
                "send",
                "--kind",
                "qa-result",
                "--request",
                &beta_request,
                "--outcome",
                "passed",
                "--body",
                "wrong team QA",
                "--operation-id",
                "typed-qa-illegal",
            ],
        )["code"],
        "domain_error"
    );
    let qa = fixture.ok(
        Some(("impl-beta-1", "implementation")),
        &[
            "message",
            "send",
            "--kind",
            "qa-result",
            "--request",
            &beta_request,
            "--outcome",
            "passed",
            "--body",
            "All QA checks passed.",
            "--operation-id",
            "typed-qa-legal",
        ],
    );
    assert_eq!(qa["message"]["payload"]["candidate"]["sha"], beta_sha);
    fixture.ok(
        Some(("primary-typed", "primary")),
        &[
            "decision",
            "submit",
            "--request",
            &beta_request,
            "--candidate-sha",
            &beta_sha,
            "--decision",
            "accepted",
            "--operation-id",
            "typed-beta-accept",
        ],
    );
    assert_eq!(
        fixture.error(
            Some(("impl-beta-1", "implementation")),
            &[
                "message",
                "send",
                "--kind",
                "integration-complete",
                "--request",
                &beta_request,
                "--operation-id",
                "typed-integration-illegal",
            ],
        )["code"],
        "domain_error"
    );
    let integrated = fixture.ok(
        Some(("primary-typed", "primary")),
        &[
            "message",
            "send",
            "--kind",
            "integration-complete",
            "--request",
            &beta_request,
            "--operation-id",
            "typed-integration-legal",
        ],
    );
    assert_eq!(
        integrated["message"]["payload"]["candidate"]["sha"],
        beta_sha
    );
    assert_eq!(
        fixture.ok(None, &["request", "show", &beta_request])["request"]["status"],
        "completed"
    );
}

#[test]
fn zero_config_linked_worktree_uses_shared_identity_and_state_without_workspace_flag() {
    let fixture = Fixture::new();
    let linked = fixture.root.with_extension("linked-worktree");
    run_git(
        &fixture.root,
        &[
            "worktree",
            "add",
            "--detach",
            linked.to_str().unwrap(),
            "HEAD",
        ],
    );

    let started = fixture.ok(None, &["start"]);
    fixture.ok(
        Some(("primary-linked", "primary")),
        &["context", "--bootstrap"],
    );
    fixture.ok(
        Some(("primary-linked", "primary")),
        &[
            "team",
            "create",
            "linked",
            "--working-directory",
            linked.to_str().unwrap(),
            "--operation-id",
            "team-linked",
        ],
    );
    let request = fixture.ok(
        Some(("primary-linked", "primary")),
        &[
            "request",
            "create",
            "--team",
            "team-linked",
            "--title",
            "linked work",
            "--operation-id",
            "request-linked",
        ],
    );

    let bootstrap = fixture.agsv_from_current(
        &linked,
        Some(("impl-linked-1", "implementation")),
        &["context", "--bootstrap"],
    );
    assert!(
        bootstrap.status.success(),
        "{}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );
    let context = serde_json::from_slice::<Value>(&bootstrap.stdout).unwrap();
    assert_eq!(context["data"]["actor_ref"]["actor_id"], "impl-linked-1");
    assert_eq!(
        context["data"]["inbox"][0]["request_id"],
        request["request"]["request_id"]
    );

    let linked_status = fixture.agsv_from_current(&linked, None, &["status"]);
    assert!(linked_status.status.success());
    let linked_status = serde_json::from_slice::<Value>(&linked_status.stdout).unwrap();
    assert_eq!(
        linked_status["data"]["workspace_id"],
        started["workspace_id"]
    );
    assert_eq!(linked_status["data"]["state_path"], started["state_path"]);
}

#[test]
fn actor_assertions_cannot_impersonate_and_primary_commands_require_primary() {
    let fixture = Fixture::new();
    fixture.ok(None, &["start"]);
    fixture.ok(
        Some(("primary-auth", "primary")),
        &["context", "--bootstrap"],
    );
    fixture.ok(
        Some(("primary-auth", "primary")),
        &[
            "team",
            "create",
            "alpha",
            "--operation-id",
            "team-auth-alpha",
        ],
    );
    fixture.ok(
        Some(("primary-auth", "primary")),
        &["team", "create", "beta", "--operation-id", "team-auth-beta"],
    );

    let inbox = fixture.agsv(
        Some(("impl-beta-1", "implementation")),
        &["message", "inbox", "--actor", "impl-alpha-1"],
    );
    assert_eq!(error_code(&inbox), "actor_identity_mismatch");

    let ack = fixture.agsv(
        Some(("impl-beta-1", "implementation")),
        &[
            "message",
            "ack",
            "message-not-relevant",
            "--actor",
            "impl-alpha-1",
            "--operation-id",
            "forged-ack",
        ],
    );
    assert_eq!(error_code(&ack), "actor_identity_mismatch");

    let primary_only = fixture.agsv(
        Some(("impl-beta-1", "implementation")),
        &[
            "team",
            "pause",
            "team-alpha",
            "--operation-id",
            "forged-pause",
        ],
    );
    assert_eq!(error_code(&primary_only), "primary_authentication_required");
    let admission_pause = fixture.ok(
        Some(("primary-auth", "primary")),
        &[
            "team",
            "pause",
            "team-beta",
            "--operation-id",
            "primary-pause",
        ],
    );
    assert_eq!(admission_pause["scope"], "protocol_admission");
    assert_eq!(admission_pause["provider_process_suspended"], false);

    let arbitrary_env = Command::new(env!("CARGO_BIN_EXE_agsv"))
        .arg("--workspace")
        .arg(&fixture.root)
        .arg("--json")
        .env("AGSV_STATE_HOME", &fixture.state)
        .env("AGSV_SESSION_BACKEND", "fake")
        .env("AGSV_ACTOR_ID", "impl-alpha-1")
        .env_remove("HERDR_PANE_ID")
        .env_remove("AGSV_DEV_ALLOW_INSECURE_ACTOR")
        .args(["message", "inbox"])
        .output()
        .unwrap();
    assert_eq!(error_code(&arbitrary_env), "actor_identity_unavailable");
}

#[test]
fn another_herdr_pane_cannot_take_a_healthy_primary_lease() {
    let fixture = Fixture::new();
    fixture.ok(None, &["start"]);
    let barrier = Arc::new(Barrier::new(2));
    let contenders = std::thread::scope(|scope| {
        ["primary-pane-one", "primary-pane-two"]
            .into_iter()
            .map(|pane| {
                let barrier = Arc::clone(&barrier);
                let fixture = &fixture;
                scope.spawn(move || {
                    barrier.wait();
                    fixture.agsv_in_pane(pane, &["context", "--bootstrap"])
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        contenders
            .iter()
            .filter(|output| output.status.success())
            .count(),
        1
    );
    assert!(
        contenders
            .iter()
            .filter(|output| !output.status.success())
            .all(|output| error_code(output) == "primary_lease_held")
    );

    let third = fixture.agsv_in_pane("primary-pane-three", &["context", "--bootstrap"]);
    assert_eq!(error_code(&third), "primary_lease_held");
    let status = fixture.agsv_in_pane("primary-pane-one", &["status"]);
    assert!(status.status.success());
    let primary =
        serde_json::from_slice::<Value>(&status.stdout).unwrap()["data"]["primary"]["actor_id"]
            .as_str()
            .unwrap()
            .to_owned();
    assert!(matches!(
        primary.as_str(),
        "primary-primary-pane-one" | "primary-primary-pane-two"
    ));
}

#[test]
fn same_herdr_pane_reacquires_an_expired_primary_with_a_new_fence() {
    let fixture = Fixture::new();
    fixture.ok(None, &["init"]);
    fs::write(
        fixture.root.join(".agent-supervisor/config.local.toml"),
        "[policy]\nprimary_lease_seconds = 2\nactor_heartbeat_seconds = 1\n",
    )
    .unwrap();
    fixture.ok(None, &["start"]);

    let first = fixture.agsv_in_pane("primary-reacquire", &["context", "--bootstrap"]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first = serde_json::from_slice::<Value>(&first.stdout).unwrap();
    assert_eq!(first["data"]["actor_ref"]["actor_epoch"], 1);

    std::thread::sleep(std::time::Duration::from_millis(2_100));
    let reacquired = fixture.agsv_in_pane("primary-reacquire", &["context", "--bootstrap"]);
    assert!(
        reacquired.status.success(),
        "{}",
        String::from_utf8_lossy(&reacquired.stderr)
    );
    let reacquired = serde_json::from_slice::<Value>(&reacquired.stdout).unwrap();
    assert_eq!(reacquired["data"]["actor_ref"]["actor_epoch"], 2);
    assert_eq!(reacquired["data"]["primary_epoch"], 2);
}

#[test]
fn actor_replacement_recovers_after_generation_commit_without_a_second_writer() {
    let fixture = Fixture::new();
    fixture.ok(None, &["start"]);
    fixture.ok(
        Some(("primary-replacement", "primary")),
        &["context", "--bootstrap"],
    );
    fixture.ok(
        Some(("primary-replacement", "primary")),
        &[
            "team",
            "create",
            "replacement",
            "--operation-id",
            "create-replacement-team",
        ],
    );
    fixture.ok(
        Some(("primary-replacement", "primary")),
        &[
            "actor",
            "stop",
            "impl-replacement-1",
            "--reason",
            "test replacement",
            "--operation-id",
            "stop-replacement-actor",
        ],
    );

    let first = fixture.agsv_with_env(
        Some(("primary-replacement", "primary")),
        &[
            "actor",
            "replace",
            "impl-replacement-1",
            "--reason",
            "test replacement",
            "--operation-id",
            "replace-recovery",
        ],
        &[("AGSV_DEV_FAIL_AFTER_REPLACEMENT_COMMIT", "1")],
    );
    assert_eq!(error_code(&first), "simulated_replacement_crash");

    let competing = fixture.agsv(
        Some(("primary-replacement", "primary")),
        &[
            "actor",
            "replace",
            "impl-replacement-1",
            "--reason",
            "competing replacement",
            "--operation-id",
            "replace-competing",
        ],
    );
    assert_eq!(error_code(&competing), "actor_replacement_in_progress");

    let recovered = fixture.ok(
        Some(("primary-replacement", "primary")),
        &[
            "actor",
            "replace",
            "impl-replacement-1",
            "--reason",
            "test replacement",
            "--operation-id",
            "replace-recovery",
        ],
    );
    assert_eq!(recovered["actor"]["actor_epoch"], 2);
    assert_eq!(recovered["session"]["status"], "idle");
    assert_eq!(recovered["reused"], false);
}

#[cfg(unix)]
#[test]
fn state_directory_and_database_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let started = fixture.ok(None, &["start"]);
    let database = PathBuf::from(started["state_path"].as_str().unwrap());
    assert_eq!(
        fs::metadata(&database).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(database.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn configured_primary_lease_heartbeats_and_fences_after_expiry() {
    let fixture = Fixture::new();
    fixture.ok(None, &["init"]);
    fs::write(
        fixture.root.join(".agent-supervisor/config.local.toml"),
        "[policy]\nprimary_lease_seconds = 2\nactor_heartbeat_seconds = 1\n",
    )
    .unwrap();
    fixture.ok(None, &["start"]);
    let bootstrapped = fixture.ok(
        Some(("primary-lease", "primary")),
        &["context", "--bootstrap"],
    );
    assert_eq!(bootstrapped["actor_ref"]["actor_epoch"], 1);

    std::thread::sleep(std::time::Duration::from_millis(1_100));
    fixture.ok(Some(("primary-lease", "primary")), &["context"]);
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let renewed = fixture.ok(None, &["status"]);
    assert_eq!(renewed["primary"]["actor_id"], "primary-lease");

    std::thread::sleep(std::time::Duration::from_millis(1_050));
    let expired = fixture.ok(None, &["status"]);
    assert!(expired["primary"].is_null());
    assert_eq!(expired["primary_epoch"], 2);

    let fenced = fixture.agsv(Some(("primary-lease", "primary")), &["reconcile"]);
    assert!(!fenced.status.success());

    let reacquired = fixture.ok(
        Some(("primary-lease", "primary")),
        &["context", "--bootstrap"],
    );
    assert_eq!(reacquired["actor_ref"]["actor_epoch"], 2);
    fixture.ok(
        Some(("primary-lease", "primary")),
        &[
            "team",
            "create",
            "heartbeat",
            "--operation-id",
            "team-heartbeat",
        ],
    );
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let within_grace = fixture.ok(None, &["actor", "show", "impl-heartbeat-1"]);
    assert_eq!(within_grace["actor"]["status"], "healthy");
    std::thread::sleep(std::time::Duration::from_millis(2_050));
    let missed_three = fixture.ok(None, &["actor", "show", "impl-heartbeat-1"]);
    assert_eq!(missed_three["actor"]["status"], "stale");

    let doctor = fixture.ok(None, &["doctor"]);
    assert_eq!(doctor["session"]["backend_command"]["available"], true);
    assert_eq!(doctor["leases"]["primary_lease_seconds"], 2);
    assert_eq!(doctor["leases"]["actor_heartbeat_seconds"], 1);
    assert_eq!(
        doctor["leases"]["implementation_expiry_after_missed_heartbeats"],
        3
    );

    let herdr_doctor = Command::new(env!("CARGO_BIN_EXE_agsv"))
        .arg("--workspace")
        .arg(&fixture.root)
        .arg("--json")
        .env("AGSV_STATE_HOME", &fixture.state)
        .env("AGSV_SESSION_BACKEND", "herdr")
        .env_remove("HERDR_ENV")
        .env_remove("HERDR_PANE_ID")
        .args(["doctor"])
        .output()
        .unwrap();
    assert!(herdr_doctor.status.success());
    let herdr_doctor = serde_json::from_slice::<Value>(&herdr_doctor.stdout).unwrap();
    assert_eq!(herdr_doctor["data"]["healthy"], false);
    assert_eq!(herdr_doctor["data"]["caller_context"]["ready"], false);
    assert_eq!(
        herdr_doctor["data"]["caller_context"]["pane_present"],
        false
    );
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
                        .env("AGSV_DEV_ALLOW_INSECURE_ACTOR", "1")
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
