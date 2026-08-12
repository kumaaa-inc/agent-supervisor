use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use serde_json::{Value, json};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    state: PathBuf,
}

fn stable_actor_reports(mut actors: Value) -> Value {
    for actor in actors.as_array_mut().into_iter().flatten() {
        actor
            .as_object_mut()
            .expect("actor reports are JSON objects")
            .remove("generation_age_ms");
    }
    actors
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
            .env("AGSV_CONFIG_HOME", self.state.with_extension("config"))
            .env("AGSV_SESSION_BACKEND", "fake")
            .env_remove("HERDR_PANE_ID")
            .env_remove("AGSV_ACTOR_ID")
            .env_remove("AGSV_ACTOR_ROLE")
            .env_remove("AGSV_DEV_ALLOW_INSECURE_ACTOR")
            .env_remove("AGSV_DEV_NOW_MS");
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

    fn ok_with_env(
        &self,
        actor: Option<(&str, &str)>,
        args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> Value {
        let output = self.agsv_with_env(actor, args, extra_env);
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
            .env("AGSV_CONFIG_HOME", self.state.with_extension("config"))
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
        self.agsv_in_pane_with_env(pane_id, args, &[])
    }

    fn agsv_in_pane_with_env(
        &self,
        pane_id: &str,
        args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agsv"));
        command
            .arg("--workspace")
            .arg(&self.root)
            .arg("--json")
            .env("AGSV_STATE_HOME", &self.state)
            .env("AGSV_CONFIG_HOME", self.state.with_extension("config"))
            .env("AGSV_SESSION_BACKEND", "fake")
            .env("HERDR_PANE_ID", pane_id)
            .env_remove("AGSV_ACTOR_ID")
            .env_remove("AGSV_ACTOR_ROLE")
            .env_remove("AGSV_DEV_ALLOW_INSECURE_ACTOR")
            .env_remove("AGSV_DEV_NOW_MS");
        command.envs(extra_env.iter().copied());
        command.args(args).output().unwrap()
    }

    fn agsv_in_pane_cleared(&self, pane_id: &str, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agsv"));
        command
            .env_clear()
            .arg("--workspace")
            .arg(&self.root)
            .arg("--json")
            .env("PATH", "/usr/bin:/bin")
            .env("TMPDIR", std::env::temp_dir())
            .env("AGSV_STATE_HOME", &self.state)
            .env("AGSV_CONFIG_HOME", self.state.with_extension("config"))
            .env("AGSV_SESSION_BACKEND", "fake")
            .env("HERDR_ENV", "1")
            .env("HERDR_PANE_ID", pane_id)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(args);
        command.output().unwrap()
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
fn team_close_cli_requires_primary_and_exposes_terminal_state() {
    let fixture = Fixture::new();
    fixture.ok(None, &["start"]);
    fixture.ok(
        Some(("primary-close-cli", "primary")),
        &["context", "--bootstrap"],
    );
    let created = fixture.ok(
        Some(("primary-close-cli", "primary")),
        &[
            "team",
            "create",
            "alpha",
            "--operation-id",
            "create-close-cli-team",
        ],
    );
    let working_directory = PathBuf::from(created["working_directory"].as_str().unwrap());
    assert!(working_directory.exists());
    let unauthorized = fixture.error(
        Some(("impl-alpha-1", "implementation")),
        &[
            "team",
            "close",
            "team-alpha",
            "--operation-id",
            "implementation-must-not-close-team",
        ],
    );
    assert_eq!(unauthorized["code"], "primary_authentication_required");

    let closed = fixture.ok(
        Some(("primary-close-cli", "primary")),
        &[
            "team",
            "close",
            "team-alpha",
            "--operation-id",
            "primary-closes-team",
        ],
    );
    assert_eq!(closed["status"], "closed");
    assert_eq!(closed["worktree_cleanup"]["status"], "removed");
    assert!(!working_directory.exists());
    let shown = fixture.ok(None, &["team", "show", "team-alpha"]);
    assert_eq!(shown["team"]["status"], "closed");
    assert_eq!(shown["team"]["effective_desired_instances"], 0);
}

#[test]
#[allow(clippy::too_many_lines)]
fn request_body_limit_is_character_based_and_overflow_is_structured() {
    const REQUEST_TEXT_LIMIT: usize = 65_536;

    let fixture = Fixture::new();
    fixture.ok(None, &["start"]);
    fixture.ok(
        Some(("primary-request-limit", "primary")),
        &["context", "--bootstrap"],
    );
    fixture.ok(
        Some(("primary-request-limit", "primary")),
        &[
            "team",
            "create",
            "request-limit",
            "--operation-id",
            "team-request-limit",
        ],
    );

    let exact_body = "a".repeat(REQUEST_TEXT_LIMIT);
    let exact = fixture.ok(
        Some(("primary-request-limit", "primary")),
        &[
            "request",
            "create",
            "--team",
            "team-request-limit",
            "--title",
            "maximum request body",
            "--body",
            &exact_body,
            "--operation-id",
            "request-body-maximum",
        ],
    );
    assert!(exact["request"]["request_id"].is_string());

    let unicode_body = "界".repeat(30_000);
    assert!(unicode_body.len() > REQUEST_TEXT_LIMIT);
    assert!(unicode_body.chars().count() < REQUEST_TEXT_LIMIT);
    fixture.ok(
        Some(("primary-request-limit", "primary")),
        &[
            "request",
            "create",
            "--team",
            "team-request-limit",
            "--title",
            "unicode request body",
            "--body",
            &unicode_body,
            "--operation-id",
            "request-body-unicode",
        ],
    );

    let before = fixture.ok(None, &["status"]);
    let requests_before = fixture.ok(None, &["request", "list"])["requests"].clone();
    let overflow_body = "b".repeat(REQUEST_TEXT_LIMIT + 1);
    let overflow = fixture.error(
        Some(("primary-request-limit", "primary")),
        &[
            "request",
            "create",
            "--team",
            "team-request-limit",
            "--title",
            "overflowing request body",
            "--body",
            &overflow_body,
            "--operation-id",
            "request-body-overflow",
        ],
    );
    assert_eq!(overflow["code"], "validation_error");
    assert_eq!(overflow["details"]["field"], "request.body");
    assert_eq!(overflow["details"]["validation_code"], "out_of_range");
    assert_eq!(overflow["details"]["unit"], "characters");
    assert_eq!(overflow["details"]["actual"], REQUEST_TEXT_LIMIT + 1);
    assert_eq!(overflow["details"]["maximum"], REQUEST_TEXT_LIMIT);
    assert_eq!(overflow["details"]["overflow"], 1);
    let message = overflow["message"].as_str().unwrap();
    assert!(message.contains("request.body"));
    assert!(message.ends_with("by 1 character"));

    let overflow_title = "t".repeat(257);
    let title_error = fixture.error(
        Some(("primary-request-limit", "primary")),
        &[
            "request",
            "create",
            "--team",
            "team-request-limit",
            "--title",
            &overflow_title,
            "--body",
            "valid body",
            "--operation-id",
            "request-title-overflow",
        ],
    );
    assert_eq!(title_error["code"], "validation_error");
    assert_eq!(title_error["details"]["field"], "request.title");
    assert_eq!(title_error["details"]["actual"], 257);
    assert_eq!(title_error["details"]["maximum"], 256);
    assert_eq!(title_error["details"]["overflow"], 1);

    let after = fixture.ok(None, &["status"]);
    let requests_after = fixture.ok(None, &["request", "list"])["requests"].clone();
    assert_eq!(after["revision"], before["revision"]);
    assert_eq!(requests_after, requests_before);
}

#[test]
#[allow(clippy::too_many_lines)]
fn purpose_labels_layout_and_fake_capabilities_are_observable_without_identity_drift() {
    let fixture = Fixture::new();
    let configuration_directory = fixture.root.join(".agent-supervisor");
    fs::create_dir(&configuration_directory).unwrap();
    fs::write(
        configuration_directory.join("config.local.toml"),
        "[session_layout]\npane_label_template = \"{session_label} / {active_request_title}\"\n",
    )
    .unwrap();

    fixture.ok(None, &["start"]);
    fixture.ok(
        Some(("primary-presentations", "primary")),
        &["context", "--bootstrap"],
    );
    fixture.ok(
        Some(("primary-presentations", "primary")),
        &[
            "team",
            "create",
            "alpha",
            "--purpose",
            "runtime adapters",
            "--orchestrators",
            "3",
            "--operation-id",
            "team-alpha-presentations",
        ],
    );

    let created = fixture.ok(None, &["team", "show", "team-alpha"]);
    assert_eq!(created["team"]["purpose"], "runtime adapters");
    let presentations = created["presentations"].as_array().unwrap();
    assert_eq!(presentations.len(), 3);
    assert_eq!(presentations[0]["slot"]["tab_sequence"], 0);
    assert_eq!(presentations[0]["slot"]["pane_index"], 1);
    assert_eq!(presentations[1]["slot"]["tab_sequence"], 1);
    assert_eq!(presentations[1]["slot"]["pane_index"], 0);
    assert_eq!(presentations[2]["slot"]["tab_sequence"], 1);
    assert_eq!(presentations[2]["slot"]["pane_index"], 1);
    assert_eq!(
        presentations[0]["session_label"],
        "agsv:alpha · runtime adapters"
    );
    assert_eq!(
        presentations[1]["session_label"],
        "agsv:alpha:2 · runtime adapters"
    );
    assert_eq!(
        presentations[2]["session_label"],
        "agsv:alpha:3 · runtime adapters"
    );
    assert_eq!(presentations[0]["sync_state"], "pending");
    assert_eq!(presentations[0]["last_error"], "unsupported");

    fixture.ok(
        Some(("primary-presentations", "primary")),
        &[
            "request",
            "create",
            "--team",
            "team-alpha",
            "--title",
            "ship fixtures",
            "--operation-id",
            "request-alpha-presentations",
        ],
    );
    let assigned = fixture.ok(None, &["team", "show", "team-alpha"]);
    assert!(
        assigned["presentations"][0]["desired_label"]
            .as_str()
            .unwrap()
            .ends_with("/ ship fixtures")
    );
    assert!(
        !assigned["presentations"][1]["desired_label"]
            .as_str()
            .unwrap()
            .contains("ship fixtures")
    );

    let actors_before = stable_actor_reports(assigned["actors"].clone());
    let sessions_before = assigned["sessions"].clone();
    let team_epoch_before = assigned["team"]["epoch"].clone();
    fixture.ok(
        Some(("primary-presentations", "primary")),
        &[
            "team",
            "update",
            "team-alpha",
            "--purpose",
            "layout policy",
            "--operation-id",
            "team-alpha-purpose-update",
        ],
    );
    let updated = fixture.ok(None, &["team", "show", "team-alpha"]);
    assert_eq!(updated["team"]["purpose"], "layout policy");
    assert_eq!(updated["team"]["epoch"], team_epoch_before);
    assert_eq!(
        stable_actor_reports(updated["actors"].clone()),
        actors_before
    );
    assert_eq!(updated["sessions"], sessions_before);
    assert!(
        updated["presentations"][0]["session_label"]
            .as_str()
            .unwrap()
            .contains("layout policy")
    );

    let listed = fixture.ok(None, &["team", "list"]);
    assert_eq!(listed["teams"][0]["purpose"], "layout policy");
    let status = fixture.ok(None, &["status"]);
    assert_eq!(status["teams"][0]["purpose"], "layout policy");
    assert_eq!(
        status["presentation"]["layout_policy"]["max_panes_per_tab"],
        2
    );
    let doctor = fixture.ok(None, &["doctor"]);
    assert_eq!(
        doctor["presentation"]["label_capability"]["supported"],
        false
    );
    assert_eq!(
        doctor["presentation"]["layout_capabilities"]["placement"],
        false
    );
    assert_eq!(doctor["lifecycle_backend_ready"], true);
    assert_eq!(doctor["backend_runtime_reachable"], true);
    assert_eq!(doctor["caller_identity"]["ready"], true);
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
    let primary = fixture.ok(
        Some(("primary-e2e", "primary")),
        &["actor", "show", "primary-e2e"],
    );
    assert_eq!(primary["session"]["team_id"], Value::Null);
    assert!(
        primary["session"]["external_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("fake-primary-"))
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
    fixture.ok(
        Some(("impl-alpha-1", "implementation")),
        &[
            "message",
            "send",
            "--kind",
            "progress",
            "--body",
            "rejected candidate fix is underway",
            "--request",
            &request_id,
            "--operation-id",
            "progress-after-rejection",
        ],
    );
    let in_progress = fixture.ok(None, &["request", "show", &request_id]);
    assert_eq!(in_progress["request"]["status"], "in_progress");
    assert_eq!(in_progress["request"]["candidate"]["sha"], sha1);

    let sha2 = commit(
        &alpha_dir,
        "feature.txt",
        "candidate two\n",
        "candidate two",
    );
    let replacement = fixture.ok(
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
    let replacement_retry = fixture.ok(
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
    assert_eq!(replacement_retry, replacement);
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
fn primary_directives_support_request_and_team_scope_and_remain_readable_after_ack() {
    let fixture = Fixture::new();
    fixture.ok(None, &["start"]);
    fixture.ok(
        Some(("primary-directive", "primary")),
        &["context", "--bootstrap"],
    );
    fixture.ok(
        Some(("primary-directive", "primary")),
        &[
            "team",
            "create",
            "directive",
            "--operation-id",
            "create-directive-team",
        ],
    );
    fixture.ok(
        Some(("impl-directive-1", "implementation")),
        &["context", "--bootstrap"],
    );
    let request_id = fixture.ok(
        Some(("primary-directive", "primary")),
        &[
            "request",
            "create",
            "--team",
            "team-directive",
            "--title",
            "Apply a durable decision",
            "--operation-id",
            "create-directive-request",
        ],
    )["request"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let missing_scope = fixture.error(
        Some(("primary-directive", "primary")),
        &[
            "message",
            "send",
            "--kind",
            "directive",
            "--to",
            "team-directive",
            "--decision",
            "Reject an implicit scope",
            "--rationale",
            "Every durable decision needs one exact scope",
            "--operation-id",
            "directive-missing-scope",
        ],
    );
    assert_eq!(missing_scope["code"], "invalid_request");
    assert!(
        missing_scope["message"]
            .as_str()
            .unwrap()
            .contains("exactly one of --request or --team")
    );
    let duplicate_scope = fixture.error(
        Some(("primary-directive", "primary")),
        &[
            "message",
            "send",
            "--kind",
            "directive",
            "--to",
            "team-directive",
            "--request",
            &request_id,
            "--team",
            "team-directive",
            "--decision",
            "Reject an ambiguous scope",
            "--rationale",
            "A request envelope also carries its team but remains request-scoped",
            "--operation-id",
            "directive-duplicate-scope",
        ],
    );
    assert_eq!(duplicate_scope["code"], "invalid_request");

    let request_directive = fixture.ok(
        Some(("primary-directive", "primary")),
        &[
            "message",
            "send",
            "--kind",
            "directive",
            "--to",
            "impl-directive-1",
            "--request",
            &request_id,
            "--decision",
            "Keep the protocol surface provider-neutral",
            "--rationale",
            "Backend details belong behind runtime adapters",
            "--operation-id",
            "request-directive",
        ],
    );
    assert_eq!(request_directive["message"]["kind"], "directive");
    assert_eq!(request_directive["wake_deferred"], false);
    let request_message_id = request_directive["message_id"].as_str().unwrap().to_owned();

    let team_directive = fixture.ok(
        Some(("primary-directive", "primary")),
        &[
            "message",
            "send",
            "--kind",
            "directive",
            "--to",
            "team-directive",
            "--team",
            "team-directive",
            "--decision",
            "Use one shared schema version",
            "--rationale",
            "Parallel migrations need a single durable owner",
            "--operation-id",
            "team-directive",
        ],
    );
    assert_eq!(team_directive["message"]["kind"], "directive");
    let team_message_id = team_directive["message_id"].as_str().unwrap().to_owned();

    let inbox = fixture.ok(
        Some(("impl-directive-1", "implementation")),
        &["message", "inbox"],
    );
    let deliveries = inbox["deliveries"].as_array().unwrap();
    assert!(deliveries.iter().any(|delivery| {
        delivery["envelope"]["message_id"] == request_message_id
            && delivery["envelope"]["request_id"] == request_id
            && delivery["envelope"]["message"]["payload"]["decision"]
                == "Keep the protocol surface provider-neutral"
    }));
    assert!(deliveries.iter().any(|delivery| {
        delivery["envelope"]["message_id"] == team_message_id
            && delivery["envelope"]["team_id"] == "team-directive"
            && delivery["envelope"]["request_id"].is_null()
    }));

    for (message_id, operation_id) in [
        (&request_message_id, "ack-request-directive"),
        (&team_message_id, "ack-team-directive"),
    ] {
        fixture.ok(
            Some(("impl-directive-1", "implementation")),
            &["message", "ack", message_id, "--operation-id", operation_id],
        );
    }
    let history = fixture.ok(
        Some(("impl-directive-1", "implementation")),
        &["message", "inbox", "--include-acked"],
    );
    let deliveries = history["deliveries"].as_array().unwrap();
    assert!(deliveries.iter().any(|delivery| {
        delivery["envelope"]["message_id"] == request_message_id
            && delivery["envelope"]["message"]["payload"]["rationale"]
                == "Backend details belong behind runtime adapters"
    }));
    assert!(deliveries.iter().any(|delivery| {
        delivery["envelope"]["message_id"] == team_message_id
            && delivery["envelope"]["message"]["payload"]["rationale"]
                == "Parallel migrations need a single durable owner"
    }));
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
        .env("AGSV_CONFIG_HOME", fixture.state.with_extension("config"))
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
fn insecure_actor_auth_is_exact_fake_only_and_backend_selection_is_stable() {
    let fixture = Fixture::new();
    fixture.ok(None, &["start"]);
    let cases = [
        (
            "live backend rejects insecure actor environment",
            "herdr",
            Some("1"),
            Some("primary-herdr-env"),
            Some("primary"),
            None,
            "actor_identity_unavailable",
        ),
        (
            "insecure switch must be exact",
            "fake",
            Some("true"),
            Some("primary-nonexact-switch"),
            Some("primary"),
            None,
            "actor_identity_unavailable",
        ),
        (
            "missing insecure actor does not fall back to pane identity",
            "fake",
            Some("1"),
            None,
            Some("primary"),
            Some("available-but-not-a-fallback"),
            "actor_identity_unavailable",
        ),
        (
            "unknown backend is rejected during selection",
            "not-registered",
            None,
            None,
            None,
            None,
            "unknown_session_backend",
        ),
    ];

    for (case, backend, switch, actor_id, actor_role, pane_id, expected_error) in cases {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agsv"));
        command
            .arg("--workspace")
            .arg(&fixture.root)
            .arg("--json")
            .env("AGSV_STATE_HOME", &fixture.state)
            .env("AGSV_CONFIG_HOME", fixture.state.with_extension("config"))
            .env("AGSV_SESSION_BACKEND", backend)
            .env_remove("AGSV_DEV_ALLOW_INSECURE_ACTOR")
            .env_remove("AGSV_ACTOR_ID")
            .env_remove("AGSV_ACTOR_ROLE")
            .env_remove("HERDR_ENV")
            .env_remove("HERDR_PANE_ID");
        if let Some(value) = switch {
            command.env("AGSV_DEV_ALLOW_INSECURE_ACTOR", value);
        }
        if let Some(value) = actor_id {
            command.env("AGSV_ACTOR_ID", value);
        }
        if let Some(value) = actor_role {
            command.env("AGSV_ACTOR_ROLE", value);
        }
        if let Some(value) = pane_id {
            command.env("HERDR_ENV", "1").env("HERDR_PANE_ID", value);
        }

        let output = command.args(["context", "--bootstrap"]).output().unwrap();
        assert!(
            !output.status.success(),
            "{case}: backend {backend:?} unexpectedly authenticated: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(error_code(&output), expected_error, "{case}");
    }
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
    fixture.ok_with_env(None, &["start"], &[("AGSV_DEV_NOW_MS", "1000")]);

    let first = fixture.agsv_in_pane_with_env(
        "primary-reacquire",
        &["context", "--bootstrap"],
        &[("AGSV_DEV_NOW_MS", "1000")],
    );
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first = serde_json::from_slice::<Value>(&first.stdout).unwrap();
    assert_eq!(first["data"]["actor_ref"]["actor_epoch"], 1);

    let reacquired = fixture.agsv_in_pane_with_env(
        "primary-reacquire",
        &["context", "--bootstrap"],
        &[("AGSV_DEV_NOW_MS", "3100")],
    );
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
fn cleared_environment_self_shutdown_is_terminal_readable_and_freshly_bootstrappable() {
    let fixture = Fixture::new();
    let pane = "primary-self-shutdown-pane";
    let run = |args: &[&str]| fixture.agsv_in_pane_cleared(pane, args);

    let started = run(&["start"]);
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    let first = run(&["context", "--bootstrap"]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first = serde_json::from_slice::<Value>(&first.stdout).unwrap();
    let actor_id = first["data"]["actor_ref"]["actor_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let first_epoch = first["data"]["actor_ref"]["actor_epoch"].as_u64().unwrap();

    let shutdown = run(&[
        "actor",
        "shutdown",
        "--reason",
        "cleared environment handoff",
        "--operation-id",
        "cleared-self-shutdown-a",
    ]);
    assert!(
        shutdown.status.success(),
        "{}",
        String::from_utf8_lossy(&shutdown.stderr)
    );
    let shutdown = serde_json::from_slice::<Value>(&shutdown.stdout).unwrap();
    assert_eq!(shutdown["data"]["actor"]["actor_id"], actor_id);
    assert_eq!(shutdown["data"]["status"], "stopped");
    assert_eq!(shutdown["data"]["session_status"], "stopped");
    assert_eq!(shutdown["data"]["controller_active"], true);

    for args in [vec!["status"], vec!["doctor"], vec!["context"]] {
        let read = run(&args);
        assert!(
            read.status.success(),
            "read-only command {args:?} failed: {}",
            String::from_utf8_lossy(&read.stderr)
        );
    }
    let stopped_context = run(&["context"]);
    let stopped_context = serde_json::from_slice::<Value>(&stopped_context.stdout).unwrap();
    assert_eq!(stopped_context["data"]["actor"]["status"], "stopped");

    let refused = run(&["start"]);
    assert_eq!(error_code(&refused), "actor_binding_stopped");
    let refused = serde_json::from_slice::<Value>(&refused.stderr).unwrap();
    assert_eq!(refused["error"]["details"]["actor"]["actor_id"], actor_id);
    assert_eq!(
        refused["error"]["details"]["actor"]["actor_epoch"],
        first_epoch
    );

    let next = run(&["context", "--bootstrap"]);
    assert!(
        next.status.success(),
        "{}",
        String::from_utf8_lossy(&next.stderr)
    );
    let next = serde_json::from_slice::<Value>(&next.stdout).unwrap();
    assert_eq!(next["data"]["actor_ref"]["actor_id"], actor_id);
    assert!(next["data"]["actor_ref"]["actor_epoch"].as_u64().unwrap() > first_epoch);
    assert_eq!(next["data"]["actor"]["status"], "healthy");
    let start_after_bootstrap = run(&["start"]);
    assert!(
        start_after_bootstrap.status.success(),
        "{}",
        String::from_utf8_lossy(&start_after_bootstrap.stderr)
    );
}

#[test]
fn controller_stop_plus_primary_shutdown_is_strictly_quiescent_for_subfloor_admission() {
    use rusqlite::Connection;

    let fixture = Fixture::new();
    let pane = "primary-quiescent-shutdown-pane";
    let run = |args: &[&str]| fixture.agsv_in_pane_cleared(pane, args);
    assert!(run(&["start"]).status.success());
    assert!(run(&["context", "--bootstrap"]).status.success());
    assert!(run(&["stop", "--force"]).status.success());
    let shutdown = run(&[
        "actor",
        "shutdown",
        "--operation-id",
        "quiescent-primary-shutdown-a",
    ]);
    assert!(
        shutdown.status.success(),
        "{}",
        String::from_utf8_lossy(&shutdown.stderr)
    );
    let identity = agsv_control::WorkspaceIdentity::discover(&fixture.root).unwrap();
    let database = fixture
        .state
        .join("workspaces")
        .join(identity.hash())
        .join("control.sqlite3");
    let connection = Connection::open(&database).unwrap();
    let (controller_active, snapshot_json): (bool, String) = connection
        .query_row(
            "SELECT controller_active, snapshot_json FROM domain_state",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(!controller_active);
    let snapshot: Value = serde_json::from_str(&snapshot_json).unwrap();
    assert_eq!(snapshot["active_primary"], Value::Null);
    assert_eq!(snapshot["actors"][0]["status"], "stopped");
    let session_status: String = connection
        .query_row("SELECT status FROM sessions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(session_status, "stopped");
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA user_version = 5;")
        .unwrap();
    drop(connection);

    let preserved = run(&["status"]);
    assert_eq!(error_code(&preserved), "state_schema_preserved");
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

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn cleared_environment_cli_preserves_backend_missing_v02_store() {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    use agsv_core::Supervisor;
    use agsv_protocol::{ActorId, PolicyRevision, TimestampMillis};
    use rusqlite::{Connection, params};

    let fixture = Fixture::new();
    let identity = agsv_control::WorkspaceIdentity::discover(&fixture.root).unwrap();
    let state_directory = fixture.state.join("workspaces").join(identity.hash());
    fs::create_dir_all(&state_directory).unwrap();
    let mut legacy = Supervisor::new(identity.workspace_id().clone(), PolicyRevision::INITIAL);
    let primary = legacy
        .activate_primary(ActorId::new("primary-v02").unwrap())
        .unwrap();
    legacy.heartbeat(&primary, TimestampMillis(1)).unwrap();
    let snapshot_json = serde_json::to_string(&legacy.snapshot()).unwrap();
    let database = state_directory.join("control.sqlite3");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE domain_state (
               workspace_id TEXT PRIMARY KEY,
               revision INTEGER NOT NULL,
               snapshot_json TEXT NOT NULL,
               controller_active INTEGER NOT NULL DEFAULT 0,
               updated_at_ms INTEGER NOT NULL
             );
             CREATE TABLE sessions (
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
             PRAGMA user_version = 5;",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO domain_state VALUES (?1, 7, ?2, 0, 1)",
            params![identity.workspace_id().as_str(), snapshot_json],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO sessions VALUES
             (?1, 'primary-v02', NULL, '/workspace', 'herdr', NULL,
              'primary-v02', 'w1:p1', 'idle', 'primary-v02-launch', 1)",
            [identity.workspace_id().as_str()],
        )
        .unwrap();
    drop(connection);

    let fake_bin = fixture.root.join("fake-bin");
    fs::create_dir(&fake_bin).unwrap();
    let fake_herdr = fake_bin.join("herdr");
    fs::write(
        &fake_herdr,
        "#!/bin/sh\nprintf x >> \"$FAKE_HERDR_CALLS\"\nprintf '{\"code\":\"pane_not_found\"}\\n' >&2\nexit 1\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_herdr).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&fake_herdr, permissions).unwrap();
    let calls = fixture.root.join("herdr-calls");
    let path = format!("{}:/usr/bin:/bin", fake_bin.display());
    let run = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agsv"));
        command
            .env_clear()
            .arg("--workspace")
            .arg(&fixture.root)
            .arg("--json")
            .env("PATH", &path)
            .env("TMPDIR", std::env::temp_dir())
            .env("AGSV_STATE_HOME", &fixture.state)
            .env("AGSV_CONFIG_HOME", fixture.state.with_extension("config"))
            .env("AGSV_SESSION_BACKEND", "fake")
            .env("AGSV_DEV_NOW_MS", "86400001")
            .env("FAKE_HERDR_CALLS", &calls)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(args)
            .output()
            .unwrap()
    };
    let snapshot = || {
        fs::read_dir(&state_directory)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().into_owned();
                let metadata = entry.metadata().unwrap();
                let content = metadata.is_file().then(|| fs::read(entry.path()).unwrap());
                (name, content)
            })
            .collect::<BTreeMap<_, _>>()
    };

    let before = snapshot();
    let refusal = run(&["status"]);
    assert!(!refusal.status.success());
    let refusal = serde_json::from_slice::<Value>(&refusal.stderr).unwrap();
    assert_eq!(
        refusal["error"]["code"],
        "state_schema_confirmation_required"
    );
    let blocker_digest = refusal["error"]["details"]["blocker_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(snapshot(), before);
    assert!(!calls.exists());

    let wrong = run(&[
        "state",
        "preserve-subfloor",
        "--confirm-blocker-digest",
        &"0".repeat(64),
        "--operation-id",
        "cli-preserve-wrong",
    ]);
    assert!(!wrong.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&wrong.stderr).unwrap()["error"]["code"],
        "state_schema_confirmation_required"
    );
    assert_eq!(snapshot(), before);
    assert!(!calls.exists());

    let applied = run(&[
        "state",
        "preserve-subfloor",
        "--confirm-blocker-digest",
        &blocker_digest,
        "--operation-id",
        "cli-preserve-v02",
    ]);
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let applied = serde_json::from_slice::<Value>(&applied.stdout).unwrap();
    assert_eq!(applied["data"]["outcome"], "applied");
    assert_eq!(fs::read(&calls).unwrap(), b"xx");
    let preserved = PathBuf::from(applied["data"]["preserved_path"].as_str().unwrap());
    assert_eq!(
        fs::read(preserved.join("control.sqlite3")).unwrap(),
        before["control.sqlite3"].clone().unwrap()
    );

    let initialized = run(&["status"]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let current = Connection::open(&database).unwrap();
    let provenance: (i64, String) = current
        .query_row(
            "SELECT COUNT(*), detail_json FROM control_events
             WHERE operation = 'state.schema_admitted'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(provenance.0, 1);
    let provenance: Value = serde_json::from_str(&provenance.1).unwrap();
    assert_eq!(
        provenance["admission"]["backend_observations"][0]["status"],
        "missing"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn configured_primary_lease_heartbeats_and_fences_after_expiry() {
    let fixture = Fixture::new();
    fixture.ok(None, &["init"]);
    fs::write(
        fixture.root.join(".agent-supervisor/config.local.toml"),
        "[policy]\nprimary_lease_seconds = 2\nactor_heartbeat_seconds = 1\n",
    )
    .unwrap();
    fixture.ok_with_env(None, &["start"], &[("AGSV_DEV_NOW_MS", "1000")]);
    let bootstrapped = fixture.ok_with_env(
        Some(("primary-lease", "primary")),
        &["context", "--bootstrap"],
        &[("AGSV_DEV_NOW_MS", "1000")],
    );
    assert_eq!(bootstrapped["actor_ref"]["actor_epoch"], 1);
    let initial = fixture.ok_with_env(None, &["status"], &[("AGSV_DEV_NOW_MS", "1000")]);
    assert_eq!(initial["primary_lease"]["active"], true);
    assert_eq!(
        initial["primary_lease"]["actor_ref"]["actor_id"],
        "primary-lease"
    );
    assert_eq!(initial["primary_lease"]["remaining_ms"], 2_000);

    fixture.ok_with_env(
        Some(("primary-lease", "primary")),
        &[
            "team",
            "create",
            "heartbeat",
            "--operation-id",
            "team-heartbeat",
        ],
        &[("AGSV_DEV_NOW_MS", "1000")],
    );
    let directive = fixture.ok_with_env(
        Some(("primary-lease", "primary")),
        &[
            "message",
            "send",
            "--kind",
            "directive",
            "--to",
            "team-heartbeat",
            "--team",
            "team-heartbeat",
            "--decision",
            "renew the lease through the polymorphic message command",
            "--rationale",
            "authenticated Primary work must retain its fenced lease",
            "--operation-id",
            "directive-heartbeat",
        ],
        &[("AGSV_DEV_NOW_MS", "2500")],
    );
    assert_eq!(directive["wake"]["status"], "woken");

    let within_grace = fixture.ok_with_env(
        None,
        &["actor", "show", "impl-heartbeat-1"],
        &[("AGSV_DEV_NOW_MS", "3999")],
    );
    assert_eq!(within_grace["actor"]["status"], "healthy");
    let renewed = fixture.ok_with_env(None, &["status"], &[("AGSV_DEV_NOW_MS", "4000")]);
    assert_eq!(renewed["primary"]["actor_id"], "primary-lease");
    assert_eq!(renewed["primary_lease"]["active"], true);
    assert_eq!(renewed["primary_lease"]["remaining_ms"], 500);

    let missed_three = fixture.ok_with_env(
        None,
        &["actor", "show", "impl-heartbeat-1"],
        &[("AGSV_DEV_NOW_MS", "4000")],
    );
    assert_eq!(missed_three["actor"]["status"], "stale");

    let fenced = fixture.agsv_with_env(
        Some(("primary-lease", "primary")),
        &["reconcile"],
        &[("AGSV_DEV_NOW_MS", "4600")],
    );
    assert!(!fenced.status.success());
    let expired = fixture.ok_with_env(None, &["status"], &[("AGSV_DEV_NOW_MS", "4600")]);
    assert!(expired["primary"].is_null());
    assert_eq!(expired["primary_epoch"], 2);
    assert_eq!(expired["primary_lease"]["active"], false);
    assert_eq!(expired["primary_lease"]["remaining_ms"], 0);
    assert!(expired["primary_lease"]["expires_at_ms"].is_null());

    let reacquired = fixture.ok_with_env(
        Some(("primary-lease", "primary")),
        &["context", "--bootstrap"],
        &[("AGSV_DEV_NOW_MS", "4700")],
    );
    assert_eq!(reacquired["actor_ref"]["actor_epoch"], 2);
    let doctor = fixture.ok_with_env(None, &["doctor"], &[("AGSV_DEV_NOW_MS", "4800")]);
    assert_eq!(doctor["leases"]["primary"]["active"], true);
    assert_eq!(
        doctor["leases"]["primary"]["actor_ref"]["actor_id"],
        "primary-lease"
    );
    assert_eq!(doctor["leases"]["primary"]["remaining_ms"], 1_900);

    assert_eq!(doctor["session"]["backend_command"]["available"], true);
    assert_eq!(doctor["runtime"]["id"], "codex");
    assert_eq!(doctor["launch"]["runtime"], "codex");
    assert_eq!(doctor["launch"]["sandbox"], "workspace-write");
    assert_eq!(doctor["launch"]["approval"], "approve-for-me");
    assert!(
        doctor["enforcement"]["launch"]
            .as_array()
            .is_some_and(|values| values.contains(&json!("sandbox")))
    );
    assert_eq!(doctor["enforcement"]["provider"], json!(["approve_for_me"]));
    assert_eq!(doctor["runtime"]["capabilities"]["resume"], true);
    assert_eq!(
        doctor["session"]["codex"]["available"],
        doctor["runtime"]["command"]["available"]
    );
    assert_eq!(doctor["lifecycle_backend"]["backend"], "fake");
    assert_eq!(doctor["lifecycle_backend_ready"], true);
    assert_eq!(
        doctor["caller_identity"]["identity_backend"],
        "insecure_debug"
    );
    assert_eq!(doctor["caller_identity"]["ready"], true);
    assert_eq!(doctor["leases"]["primary_lease_seconds"], 2);
    assert_eq!(doctor["leases"]["actor_heartbeat_seconds"], 1);
    assert_eq!(
        doctor["leases"]["implementation_expiry_after_missed_heartbeats"],
        3
    );
}

#[test]
fn doctor_reports_lifecycle_and_caller_readiness_independently() {
    let fixture = Fixture::new();
    let unbound_pane_id = "doctor-unbound-pane-secret";
    let independent_doctor = Command::new(env!("CARGO_BIN_EXE_agsv"))
        .arg("--workspace")
        .arg(&fixture.root)
        .arg("--json")
        .env("AGSV_STATE_HOME", &fixture.state)
        .env("AGSV_CONFIG_HOME", fixture.state.with_extension("config"))
        .env("AGSV_SESSION_BACKEND", "fake")
        .env("HERDR_PANE_ID", unbound_pane_id)
        .env_remove("HERDR_ENV")
        .env_remove("AGSV_DEV_ALLOW_INSECURE_ACTOR")
        .env_remove("AGSV_ACTOR_ID")
        .env_remove("AGSV_ACTOR_ROLE")
        .args(["doctor"])
        .output()
        .unwrap();
    assert!(independent_doctor.status.success());
    let independent_doctor = serde_json::from_slice::<Value>(&independent_doctor.stdout).unwrap();
    assert_eq!(independent_doctor["data"]["lifecycle_backend_ready"], true);
    assert_eq!(
        independent_doctor["data"]["caller_identity"]["identity_backend"],
        "herdr"
    );
    assert_eq!(
        independent_doctor["data"]["caller_identity"]["ready"],
        false
    );
    assert_eq!(independent_doctor["data"]["healthy"], false);
    assert!(!independent_doctor.to_string().contains(unbound_pane_id));

    let herdr_doctor = Command::new(env!("CARGO_BIN_EXE_agsv"))
        .arg("--workspace")
        .arg(&fixture.root)
        .arg("--json")
        .env("AGSV_STATE_HOME", &fixture.state)
        .env("AGSV_CONFIG_HOME", fixture.state.with_extension("config"))
        .env("AGSV_SESSION_BACKEND", "herdr")
        .env_remove("HERDR_ENV")
        .env_remove("HERDR_PANE_ID")
        .args(["doctor"])
        .output()
        .unwrap();
    assert!(herdr_doctor.status.success());
    let herdr_doctor = serde_json::from_slice::<Value>(&herdr_doctor.stdout).unwrap();
    assert_eq!(herdr_doctor["data"]["healthy"], false);
    assert_eq!(
        herdr_doctor["data"]["lifecycle_backend"]["backend"],
        "herdr"
    );
    assert_eq!(
        herdr_doctor["data"]["caller_identity"]["identity_backend"],
        "herdr"
    );
    assert_eq!(herdr_doctor["data"]["caller_context"]["ready"], false);
    assert_eq!(
        herdr_doctor["data"]["caller_context"]["pane_present"],
        false
    );
}

#[test]
fn configured_primary_capability_is_independent_of_role_and_second_holder_is_fenced() {
    let fixture = Fixture::new();
    fixture.ok(None, &["init"]);
    let path = fixture.root.join(".agent-supervisor/config.toml");
    let configured = fs::read_to_string(&path)
        .unwrap()
        .replacen("role = \"primary\"", "role = \"research\"", 1)
        .replacen(
            "capabilities = [\"human_facing_primary\"]",
            "capabilities = [\"human_facing_primary\", \"implementation_execution\"]",
            1,
        );
    fs::write(&path, configured).unwrap();

    fixture.ok(None, &["start"]);
    let first = fixture.ok(
        Some(("research-primary-one", "primary")),
        &["context", "--bootstrap"],
    );
    assert_eq!(first["actor"]["role"], "research");
    assert_eq!(first["actor"]["profile"]["name"], "primary");
    assert_eq!(first["profile"]["role"], "research");
    assert_eq!(
        first["profile"]["capabilities"],
        json!(["human_facing_primary", "implementation_execution"])
    );

    let second = fixture.agsv(
        Some(("research-primary-two", "primary")),
        &["context", "--bootstrap"],
    );
    assert!(!second.status.success());
    assert_eq!(error_code(&second), "primary_lease_held");

    let status = fixture.ok(None, &["status"]);
    assert_eq!(status["primary"]["actor_id"], "research-primary-one");
    assert_eq!(status["profiles"]["selected_primary"], "primary");
    assert_eq!(
        status["profiles"]["agent_profiles"]["primary"]["role"],
        "research"
    );
    let doctor = fixture.ok(None, &["doctor"]);
    assert_eq!(
        doctor["leases"]["primary_capability"],
        "human_facing_primary"
    );
    assert_eq!(doctor["profiles"]["selected_primary"], "primary");

    fixture.ok(
        Some(("research-primary-one", "primary")),
        &[
            "team",
            "create",
            "dual-capability",
            "--operation-id",
            "team-dual-capability",
        ],
    );
    let created = fixture.ok(
        Some(("research-primary-one", "primary")),
        &[
            "request",
            "create",
            "--team",
            "team-dual-capability",
            "--title",
            "verify Primary assignment fencing",
            "--operation-id",
            "request-dual-capability",
        ],
    );
    let run_id = created["run"]["run_id"].as_str().unwrap();
    let paused = fixture.ok(
        Some(("research-primary-one", "primary")),
        &[
            "run",
            "pause",
            run_id,
            "--operation-id",
            "pause-dual-capability",
        ],
    );
    assert_eq!(paused["status"], "paused");
}

#[test]
fn configured_research_team_profile_persists_without_primary_or_execution_privilege() {
    let fixture = Fixture::new();
    fixture.ok(None, &["init"]);
    let path = fixture.root.join(".agent-supervisor/config.toml");
    let configured = fs::read_to_string(&path).unwrap().replace(
        "role = \"implementation\"\ncapabilities = [\"implementation_execution\"]",
        "role = \"research\"\ncapabilities = []",
    );
    fs::write(&path, configured).unwrap();

    fixture.ok(None, &["start"]);
    fixture.ok(
        Some(("primary-research-team", "primary")),
        &["context", "--bootstrap"],
    );
    let created = fixture.ok(
        Some(("primary-research-team", "primary")),
        &[
            "team",
            "create",
            "research",
            "--operation-id",
            "team-research-profile",
        ],
    );
    assert_eq!(
        created["team_profile"]["assignment_policy"],
        "first_healthy"
    );

    let context = fixture.ok(
        Some(("impl-research-1", "implementation")),
        &["context", "--bootstrap"],
    );
    assert_eq!(context["actor"]["role"], "research");
    assert_eq!(context["actor"]["profile"]["name"], "implementation");
    assert_eq!(context["profile"]["role"], "research");
    assert_eq!(context["profile"]["capabilities"], json!([]));

    let create_request = fixture.error(
        Some(("primary-research-team", "primary")),
        &[
            "request",
            "create",
            "--team",
            "team-research",
            "--title",
            "must not assign",
            "--operation-id",
            "research-no-execution",
        ],
    );
    assert_eq!(create_request["code"], "no_healthy_actor");

    let primary_action = fixture.error(
        Some(("impl-research-1", "implementation")),
        &[
            "team",
            "create",
            "forbidden",
            "--operation-id",
            "research-no-primary",
        ],
    );
    assert_eq!(primary_action["code"], "primary_authentication_required");
}

#[test]
#[allow(clippy::too_many_lines)]
fn team_create_selects_named_profiles_and_reports_durable_choice() {
    let fixture = Fixture::new();
    fixture.ok(None, &["init"]);
    let path = fixture.root.join(".agent-supervisor/config.toml");
    let mut configured = fs::read_to_string(&path).unwrap();
    configured.push_str(
        "\n[team_profiles.research]\nactor_profile = \"implementation\"\ndesired_instances = 1\nassignment_policy = \"least_wip\"\n",
    );
    fs::write(&path, configured).unwrap();

    fixture.ok(None, &["start"]);
    fixture.ok(
        Some(("primary-team-profile", "primary")),
        &["context", "--bootstrap"],
    );

    let unknown = fixture.error(
        Some(("primary-team-profile", "primary")),
        &[
            "team",
            "create",
            "unknown",
            "--profile",
            "missing",
            "--operation-id",
            "team-profile-unknown",
        ],
    );
    assert_eq!(unknown["code"], "unknown_team_profile");
    assert_eq!(unknown["details"]["team_profile"], "missing");
    assert_eq!(
        unknown["details"]["available_team_profiles"],
        json!(["implementation", "research"])
    );
    assert!(
        fixture.ok(None, &["team", "list"])["teams"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let default_team = fixture.ok(
        Some(("primary-team-profile", "primary")),
        &[
            "team",
            "create",
            "default-profile",
            "--operation-id",
            "team-profile-default",
        ],
    );
    assert_eq!(default_team["team_profile"]["name"], "implementation");
    assert_eq!(
        default_team["team_profile"]["assignment_policy"],
        "first_healthy"
    );

    let research_team = fixture.ok(
        Some(("primary-team-profile", "primary")),
        &[
            "team",
            "create",
            "research-profile",
            "--profile",
            "research",
            "--operation-id",
            "team-profile-research",
        ],
    );
    assert_eq!(research_team["team_profile"]["name"], "research");
    assert_eq!(
        research_team["team_profile"]["assignment_policy"],
        "least_wip"
    );

    let shown_default = fixture.ok(None, &["team", "show", "team-default-profile"]);
    let shown_research = fixture.ok(None, &["team", "show", "team-research-profile"]);
    assert_eq!(shown_default["team"]["profile"]["name"], "implementation");
    assert_eq!(shown_research["team"]["profile"]["name"], "research");

    let status = fixture.ok(None, &["status"]);
    let teams = status["teams"].as_array().unwrap();
    assert_eq!(teams.len(), 2);
    assert!(teams.iter().any(|team| {
        team["team_id"] == "team-default-profile" && team["profile"]["name"] == "implementation"
    }));
    assert!(teams.iter().any(|team| {
        team["team_id"] == "team-research-profile" && team["profile"]["name"] == "research"
    }));

    let events = fixture.ok(None, &["events", "--limit", "100"]);
    let created_profiles = events["control_events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["operation"] == "team.created")
        .map(|event| event["detail"]["team_profile"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(created_profiles.contains(&"implementation"));
    assert!(created_profiles.contains(&"research"));

    let mismatch = fixture.error(
        Some(("primary-team-profile", "primary")),
        &[
            "team",
            "create",
            "default-profile",
            "--profile",
            "research",
            "--operation-id",
            "team-profile-mismatch",
        ],
    );
    assert_eq!(mismatch["code"], "team_profile_mismatch");
    assert_eq!(
        mismatch["details"]["persisted_team_profile"],
        "implementation"
    );
    assert_eq!(mismatch["details"]["requested_team_profile"], "research");
}

#[test]
#[allow(clippy::too_many_lines)]
fn desired_instances_and_least_wip_assignment_survive_cli_reopen() {
    let fixture = Fixture::new();
    fixture.ok(None, &["init"]);
    let config_path = fixture.root.join(".agent-supervisor/config.toml");
    let configured = fs::read_to_string(&config_path)
        .unwrap()
        .replace("desired_instances = 1", "desired_instances = 2")
        .replace(
            "assignment_policy = \"first_healthy\"",
            "assignment_policy = \"least_wip\"",
        );
    fs::write(&config_path, configured).unwrap();

    fixture.ok(None, &["start"]);
    fixture.ok(
        Some(("primary-scheduling", "primary")),
        &["context", "--bootstrap"],
    );
    let create_args = [
        "team",
        "create",
        "scheduling",
        "--operation-id",
        "team-scheduling",
    ];
    let created = fixture.ok(Some(("primary-scheduling", "primary")), &create_args);
    assert_eq!(created["actors"].as_array().unwrap().len(), 2);
    assert_eq!(created["sessions"].as_array().unwrap().len(), 2);
    assert_eq!(created["team_profile"]["desired_instances"], 2);
    assert_eq!(created["team_profile"]["assignment_policy"], "least_wip");
    let worktree = created["working_directory"].as_str().unwrap();
    assert!(
        created["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|session| { session["working_directory"].as_str() == Some(worktree) })
    );

    let retried = fixture.ok(Some(("primary-scheduling", "primary")), &create_args);
    assert_eq!(retried, created, "same-operation retry is byte-stable");
    let actors = fixture.ok(
        Some(("primary-scheduling", "primary")),
        &["actor", "list", "--team", "team-scheduling"],
    );
    assert_eq!(actors["actors"].as_array().unwrap().len(), 2);

    let create_request = |operation_id: &str, title: &str| {
        fixture.ok(
            Some(("primary-scheduling", "primary")),
            &[
                "request",
                "create",
                "--team",
                "team-scheduling",
                "--title",
                title,
                "--operation-id",
                operation_id,
            ],
        )
    };
    let first = create_request("least-wip-one", "first scheduled request");
    let second = create_request("least-wip-two", "second scheduled request");
    let third = create_request("least-wip-three", "third scheduled request");
    assert_eq!(
        first["request"]["assignment"]["actor"]["actor_id"],
        "impl-scheduling-1"
    );
    assert_eq!(
        second["request"]["assignment"]["actor"]["actor_id"],
        "impl-scheduling-2"
    );
    assert_eq!(
        third["request"]["assignment"]["actor"]["actor_id"],
        "impl-scheduling-1"
    );

    let status = fixture.ok(Some(("primary-scheduling", "primary")), &["status"]);
    let scheduling = status["assignment_instances"]["teams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|team| team["team_id"] == "team-scheduling")
        .unwrap();
    assert_eq!(scheduling["effective_assignment_policy"], "least_wip");
    assert_eq!(scheduling["desired_instances"], 2);
    assert_eq!(scheduling["actors"][0]["wip_count"], 2);
    assert_eq!(scheduling["actors"][1]["wip_count"], 1);
    assert_eq!(scheduling["converged"], true);
    assert_eq!(status["observability"]["selected_runtime_id"], "codex");
    assert_eq!(
        status["observability"]["configured_session_backend"],
        "fake"
    );
    assert_eq!(
        status["observability"]["caller_identity"]["identity_backend"],
        "insecure_debug"
    );
    assert_eq!(
        status["observability"]["profile_capabilities"]["selected_default_team"]["capabilities"],
        json!(["implementation_execution"])
    );
    assert_eq!(
        status["observability"]["assignment_policies"]["effective_by_team"][0]["assignment_policy"],
        "least_wip"
    );

    let events = fixture.ok(Some(("primary-scheduling", "primary")), &["events"]);
    assert_eq!(events["observability"]["selected_runtime_id"], "codex");
    assert_eq!(
        events["observability"]["configured_session_backend"],
        "fake"
    );
    assert_eq!(
        events["observability"]["assignment_policies"]["selected_default"],
        "least_wip"
    );

    let doctor = fixture.ok(Some(("primary-scheduling", "primary")), &["doctor"]);
    assert_eq!(
        doctor["assignment_instances"]["teams"][0]["effective_assignment_policy"],
        "least_wip"
    );
    let reconciled = fixture.ok(Some(("primary-scheduling", "primary")), &["reconcile"]);
    assert_eq!(reconciled["complete"], true);
    assert_eq!(
        reconciled["instance_reconciliation"][0]["desired_instances"],
        2
    );
    assert_eq!(reconciled["instance_reconciliation"][0]["launched"], 0);
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
                        .env("AGSV_STATE_HOME", &state)
                        .env("AGSV_CONFIG_HOME", state.with_extension("config"))
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
