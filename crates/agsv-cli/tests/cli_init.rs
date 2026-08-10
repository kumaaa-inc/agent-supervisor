use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use serde_json::{Value, json};

static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

const V01_PROJECT_CONFIG: &str = r#"schema_version = 1

[workspace]
primary_role = ".agent-supervisor/roles/primary-orchestrator.md"
implementation_role = ".agent-supervisor/roles/implementation-orchestrator.md"

[runtime]
backend = "herdr"
state_directory = ".agent-supervisor/runtime"

[implementation]
runtime = "codex"
model = "legacy-model"
reasoning_effort = "high"

[policy]
primary_lease_seconds = 3600
actor_heartbeat_seconds = 300
"#;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let serial = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agsv-init-functional-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("test directory should be created");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("test directory should be removed");
        let state = self.0.with_extension("state");
        if state.exists() {
            fs::remove_dir_all(state).expect("test state directory should be removed");
        }
    }
}

fn agsv(workspace: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agsv"))
        .arg("--workspace")
        .arg(workspace)
        .arg("--json")
        .env("AGSV_STATE_HOME", workspace.with_extension("state"))
        .env("AGSV_SESSION_BACKEND", "fake")
        .env_remove("HERDR_PANE_ID")
        .env_remove("AGSV_ACTOR_ID")
        .env_remove("AGSV_ACTOR_ROLE")
        .env_remove("AGSV_DEV_ALLOW_INSECURE_ACTOR")
        .args(args)
        .output()
        .expect("agsv should execute")
}

fn agsv_as(workspace: &Path, actor: &str, role: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agsv"))
        .arg("--workspace")
        .arg(workspace)
        .arg("--json")
        .env("AGSV_STATE_HOME", workspace.with_extension("state"))
        .env("AGSV_SESSION_BACKEND", "fake")
        .env_remove("HERDR_PANE_ID")
        .env("AGSV_DEV_ALLOW_INSECURE_ACTOR", "1")
        .env("AGSV_ACTOR_ID", actor)
        .env("AGSV_ACTOR_ROLE", role)
        .args(args)
        .output()
        .expect("agsv should execute")
}

fn git_init(workspace: &Path) {
    let output = Command::new("git")
        .arg("init")
        .arg(workspace)
        .output()
        .expect("git init should execute");
    assert!(output.status.success());
    for args in [
        &["config", "user.name", "AGSV Test"][..],
        &["config", "user.email", "agsv@example.invalid"][..],
        &["commit", "--allow-empty", "-m", "base"][..],
    ] {
        let output = Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(args)
            .output()
            .expect("Git fixture setup should execute");
        assert!(output.status.success());
    }
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout should be one JSON envelope")
}

fn stderr_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stderr).expect("stderr should be one JSON envelope")
}

#[test]
fn init_is_idempotent_and_preserves_role_edits() {
    let root = TestDir::new();
    fs::write(root.0.join(".gitignore"), "target\n").expect("fixture should be written");

    let first = agsv(&root.0, &["init"]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_json = stdout_json(&first);
    assert_eq!(first_json["schema_version"], "agsv.cli.v1");
    assert_eq!(first_json["ok"], true);
    assert_eq!(first_json["command"], "init");
    assert_eq!(
        first_json["data"]["created"].as_array().map(Vec::len),
        Some(3)
    );
    let materialized_config = fs::read_to_string(agent_config(&root.0)).unwrap();
    assert!(materialized_config.contains("[agent_profiles.primary]"));
    assert!(materialized_config.contains("[agent_profiles.implementation]"));
    assert!(materialized_config.contains("[team_profiles.implementation]"));
    assert!(materialized_config.contains("assignment_policy = \"first_healthy\""));
    assert!(materialized_config.contains("[session_layout]"));
    assert!(materialized_config.contains("max_panes_per_tab = 2"));
    assert!(materialized_config.contains("pane_label_template = \"{session_label}\""));

    let role = root
        .0
        .join(".agent-supervisor/roles/primary-orchestrator.md");
    fs::write(&role, "custom project role\n").expect("role edit should be written");

    let second = agsv(&root.0, &["init"]);
    assert!(second.status.success());
    assert_eq!(stdout_json(&second)["data"]["changed"], false);
    assert_eq!(fs::read_to_string(role).unwrap(), "custom project role\n");

    let ignore = fs::read_to_string(root.0.join(".gitignore")).unwrap();
    assert_eq!(
        ignore
            .matches(".agent-supervisor/config.local.toml")
            .count(),
        1
    );
    assert_eq!(ignore.matches(".agent-supervisor/runtime/").count(), 1);

    let validate = agsv(&root.0, &["config", "validate"]);
    assert!(validate.status.success());
    assert_eq!(stdout_json(&validate)["data"]["valid"], true);
}

#[test]
fn embedded_control_plane_starts_and_lists_teams() {
    let root = TestDir::new();
    git_init(&root.0);
    let start = agsv(&root.0, &["start"]);
    assert!(start.status.success());
    assert_eq!(stdout_json(&start)["data"]["mode"], "embedded");
    let bootstrap = agsv_as(
        &root.0,
        "primary-test",
        "primary",
        &["context", "--bootstrap"],
    );
    assert!(bootstrap.status.success());

    let create = agsv_as(
        &root.0,
        "primary-test",
        "primary",
        &[
            "team",
            "create",
            "team-a",
            "--operation-id",
            "team-create-a",
        ],
    );
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    assert_eq!(stdout_json(&create)["data"]["team_id"], "team-team-a");
    let list = agsv(&root.0, &["team", "list"]);
    assert!(list.status.success());
    assert_eq!(
        stdout_json(&list)["data"]["teams"][0]["team_id"],
        "team-team-a"
    );
}

#[test]
fn usage_errors_are_json_when_requested() {
    let root = TestDir::new();
    let output = agsv(
        &root.0,
        &[
            "request",
            "complete",
            "request-a",
            "--candidate-sha",
            "short",
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    let envelope = stderr_json(&output);
    assert_eq!(envelope["schema_version"], "agsv.cli.v1");
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["command"], "cli");
    assert_eq!(envelope["error"]["code"], "usage_error");
}

#[test]
fn concurrent_init_processes_produce_one_complete_result() {
    const CLIENTS: usize = 12;
    let root = TestDir::new();
    fs::write(root.0.join(".gitignore"), "target").expect("fixture should be written");
    let barrier = Arc::new(Barrier::new(CLIENTS));

    let outputs = std::thread::scope(|scope| {
        let handles = (0..CLIENTS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let workspace = root.0.clone();
                scope.spawn(move || {
                    barrier.wait();
                    agsv(&workspace, &["init"])
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("init thread should not panic"))
            .collect::<Vec<_>>()
    });

    for output in outputs {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let ignore = fs::read_to_string(root.0.join(".gitignore")).unwrap();
    assert_eq!(
        ignore,
        "target\n.agent-supervisor/config.local.toml\n.agent-supervisor/runtime/\n"
    );
    assert!(fs::read_dir(&root.0).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp.")
    }));
    assert!(agsv(&root.0, &["config", "validate"]).status.success());
}

#[test]
fn zero_config_validation_is_read_only_and_uses_builtins() {
    let root = TestDir::new();
    git_init(&root.0);

    let show = agsv(&root.0, &["config", "show"]);
    assert!(show.status.success());
    let shown = stdout_json(&show);
    assert_eq!(shown["data"]["source"], "builtin");
    assert_eq!(
        shown["data"]["config"]["policy"]["primary_lease_seconds"],
        3_600
    );
    assert_eq!(
        shown["data"]["config"]["policy"]["actor_heartbeat_seconds"],
        300
    );
    assert_eq!(shown["data"]["profiles"]["selected_primary"], "primary");
    assert_eq!(
        shown["data"]["profiles"]["selected_default_team"],
        "implementation"
    );
    assert_eq!(shown["data"]["profiles"]["persist_snapshots"], false);
    assert_eq!(
        shown["data"]["profiles"]["agent_profiles"]["primary"]["capabilities"][0],
        "human_facing_primary"
    );
    assert_eq!(
        shown["data"]["profiles"]["team_profiles"]["implementation"]["assignment_policy"],
        "first_healthy"
    );
    assert_eq!(shown["data"]["roles"]["primary"]["source"], "builtin");
    assert_eq!(
        shown["data"]["roles"]["implementation"]["source"],
        "builtin"
    );
    assert_eq!(
        shown["data"]["config"]["session_layout"]["max_panes_per_tab"],
        2
    );
    assert_eq!(
        shown["data"]["config"]["session_layout"]["place_first_implementation_with_primary"],
        true
    );
    assert_eq!(
        shown["data"]["config"]["session_layout"]["tab_label_strategy"],
        "sequence"
    );
    assert_eq!(
        shown["data"]["config"]["session_layout"]["pane_label_template"],
        "{session_label}"
    );
    assert_eq!(
        shown["data"]["config"]["session_layout"]["split_direction"],
        "right"
    );
    assert_eq!(
        shown["data"]["config"]["session_layout"]["focus_new_sessions"],
        false
    );

    let validate = agsv(&root.0, &["config", "validate"]);
    assert!(validate.status.success());
    assert_eq!(
        stdout_json(&validate)["data"]["effective"]["source"],
        "builtin"
    );

    let status = agsv(&root.0, &["status"]);
    assert!(status.status.success());
    assert_eq!(stdout_json(&status)["data"]["config_source"], "builtin");
    assert!(!root.0.join(".agent-supervisor").exists());
    assert!(!root.0.join("control.sqlite3").exists());
}

#[test]
fn zero_config_doctor_is_truthful_without_codex_or_herdr_on_path() {
    let root = TestDir::new();
    git_init(&root.0);
    let output = Command::new(env!("CARGO_BIN_EXE_agsv"))
        .arg("--workspace")
        .arg(&root.0)
        .arg("--json")
        .arg("doctor")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("AGSV_STATE_HOME", root.0.with_extension("state"))
        .env_remove("AGSV_SESSION_BACKEND")
        .env_remove("HERDR_ENV")
        .env_remove("HERDR_PANE_ID")
        .env_remove("AGSV_DEV_ALLOW_INSECURE_ACTOR")
        .env_remove("AGSV_ACTOR_ID")
        .env_remove("AGSV_ACTOR_ROLE")
        .output()
        .expect("agsv doctor should execute with a sanitized PATH");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let doctor = stdout_json(&output);
    assert_eq!(doctor["data"]["healthy"], false);
    assert_eq!(doctor["data"]["runtime"]["id"], "codex");
    assert_eq!(doctor["data"]["runtime"]["command"]["available"], false);
    assert_eq!(doctor["data"]["lifecycle_backend"]["backend"], "herdr");
    assert_eq!(
        doctor["data"]["lifecycle_backend"]["backend_command"]["available"],
        false
    );
    assert_eq!(
        doctor["data"]["caller_identity"]["identity_backend"],
        "herdr"
    );
    assert_eq!(doctor["data"]["caller_identity"]["ready"], false);
    assert!(!root.0.join(".agent-supervisor").exists());
    assert!(!root.0.join("control.sqlite3").exists());
}

#[test]
fn zero_config_legacy_local_overrides_bridge_into_builtin_profiles_without_repo_writes() {
    let root = TestDir::new();
    git_init(&root.0);
    let agent_dir = root.0.join(".agent-supervisor");
    let roles_dir = agent_dir.join("roles");
    fs::create_dir_all(&roles_dir).expect("local override fixture directory should be created");
    let primary_role = "Custom local Primary instructions.\n";
    let implementation_role = "Custom local implementation instructions.\n";
    fs::write(roles_dir.join("local-primary.md"), primary_role)
        .expect("local Primary role fixture should be written");
    fs::write(
        roles_dir.join("local-implementation.md"),
        implementation_role,
    )
    .expect("local implementation role fixture should be written");
    fs::write(
        agent_dir.join("config.local.toml"),
        r#"[workspace]
primary_role = ".agent-supervisor/roles/local-primary.md"
implementation_role = ".agent-supervisor/roles/local-implementation.md"

[implementation]
runtime = "codex"
model = "legacy-local-model"
reasoning_effort = "high"
"#,
    )
    .expect("legacy local override fixture should be written");

    let show = agsv(&root.0, &["config", "show"]);
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    let shown = stdout_json(&show);
    assert_eq!(shown["data"]["source"], "builtin");
    assert_eq!(shown["data"]["local_override"], true);
    assert_eq!(shown["data"]["profiles"]["persist_snapshots"], false);
    assert_eq!(
        shown["data"]["roles"]["primary"]["source"],
        ".agent-supervisor/roles/local-primary.md"
    );
    assert_eq!(
        shown["data"]["roles"]["primary"]["bytes"],
        primary_role.len()
    );
    assert_eq!(
        shown["data"]["roles"]["implementation"]["source"],
        ".agent-supervisor/roles/local-implementation.md"
    );
    assert_eq!(
        shown["data"]["roles"]["implementation"]["bytes"],
        implementation_role.len()
    );
    assert_eq!(
        shown["data"]["profiles"]["agent_profiles"]["implementation"]["model"],
        "legacy-local-model"
    );
    assert_eq!(
        shown["data"]["profiles"]["agent_profiles"]["implementation"]["reasoning_effort"],
        "high"
    );

    let doctor = agsv(&root.0, &["doctor"]);
    assert!(
        doctor.status.success(),
        "{}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    let doctor = stdout_json(&doctor);
    assert_eq!(doctor["data"]["launch"]["runtime"], "codex");
    assert_eq!(doctor["data"]["launch"]["model"], "legacy-local-model");
    assert_eq!(doctor["data"]["launch"]["reasoning_effort"], "high");
    assert_eq!(
        doctor["data"]["profiles"]["agent_profiles"]["primary"]["role_source"],
        ".agent-supervisor/roles/local-primary.md"
    );
    assert_eq!(
        doctor["data"]["profiles"]["agent_profiles"]["implementation"]["role_source"],
        ".agent-supervisor/roles/local-implementation.md"
    );

    assert!(!agent_dir.join("config.toml").exists());
    assert!(!agent_dir.join("runtime").exists());
    assert!(!root.0.join("control.sqlite3").exists());
}

#[test]
fn v01_project_config_synthesizes_legacy_profiles_and_launch_settings() {
    let root = TestDir::new();
    git_init(&root.0);
    assert!(agsv(&root.0, &["init"]).status.success());
    fs::write(agent_config(&root.0), V01_PROJECT_CONFIG)
        .expect("legacy config fixture should be written");

    let validate = agsv(&root.0, &["config", "validate"]);
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let shown = stdout_json(&agsv(&root.0, &["config", "show"]));
    assert_eq!(shown["data"]["source"], "project");
    assert_eq!(shown["data"]["profiles"]["persist_snapshots"], false);
    assert_eq!(
        shown["data"]["config"]["agent_profiles"]["implementation"]["runtime"],
        "codex"
    );
    assert_eq!(
        shown["data"]["config"]["agent_profiles"]["implementation"]["model"],
        "legacy-model"
    );
    assert_eq!(
        shown["data"]["config"]["team_profiles"]["implementation"]["assignment_policy"],
        "first_healthy"
    );

    let doctor = agsv(&root.0, &["doctor"]);
    assert!(
        doctor.status.success(),
        "{}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    let doctor = stdout_json(&doctor);
    assert_eq!(doctor["data"]["launch"]["runtime"], "codex");
    assert_eq!(doctor["data"]["launch"]["model"], "legacy-model");
    assert_eq!(doctor["data"]["launch"]["reasoning_effort"], "high");
}

#[test]
fn explicit_profiles_round_trip_arbitrary_roles_capabilities_and_team_intent() {
    let root = TestDir::new();
    git_init(&root.0);
    assert!(agsv(&root.0, &["init"]).status.success());
    let research_role = root.0.join(".agent-supervisor/roles/research.md");
    fs::write(&research_role, "Gather and verify evidence.\n")
        .expect("research role fixture should be written");
    fs::write(
        agent_config(&root.0),
        r#"schema_version = 1

[workspace]
primary_role = ".agent-supervisor/roles/primary-orchestrator.md"
implementation_role = ".agent-supervisor/roles/implementation-orchestrator.md"
primary_profile = "primary"
default_team_profile = "research"

[runtime]
backend = "herdr"
state_directory = ".agent-supervisor/runtime"

[agent_profiles.primary]
role = "primary"
capabilities = ["human_facing_primary", "review/quorum"]
runtime = "codex"
model = "gpt-5.6-sol"
reasoning_effort = "max"
role_file = ".agent-supervisor/roles/primary-orchestrator.md"

[agent_profiles.research]
role = "research"
provider = "codex"
model = "gpt-5.6-terra"
reasoning_effort = "high"
role_file = ".agent-supervisor/roles/research.md"

[team_profiles.research]
actor_profile = "research"
desired_instances = 3
assignment_policy = "least_wip"

[team_profiles.disabled_research]
actor_profile = "research"
desired_instances = 0
assignment_policy = "first_healthy"

[policy]
primary_lease_seconds = 3600
actor_heartbeat_seconds = 300
"#,
    )
    .expect("profile config fixture should be written");

    let show = agsv(&root.0, &["config", "show"]);
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    let shown = stdout_json(&show);
    assert_eq!(shown["data"]["profiles"]["persist_snapshots"], true);
    assert_eq!(
        shown["data"]["profiles"]["selected_default_team"],
        "research"
    );
    assert_eq!(
        shown["data"]["profiles"]["agent_profiles"]["research"]["role"],
        "research"
    );
    assert_eq!(
        shown["data"]["profiles"]["agent_profiles"]["research"]["capabilities"],
        serde_json::json!([])
    );
    assert!(
        shown["data"]["profiles"]["agent_profiles"]["primary"]["capabilities"]
            .as_array()
            .is_some_and(|capabilities| capabilities.contains(&serde_json::json!("review/quorum")))
    );
    assert_eq!(
        shown["data"]["profiles"]["team_profiles"]["research"]["desired_instances"],
        3
    );
    assert_eq!(
        shown["data"]["profiles"]["team_profiles"]["research"]["assignment_policy"],
        "least_wip"
    );
    assert_eq!(
        shown["data"]["profiles"]["team_profiles"]["disabled_research"]["desired_instances"],
        0
    );
    assert_eq!(
        shown["data"]["roles"]["research"]["source"],
        ".agent-supervisor/roles/research.md"
    );

    let doctor = stdout_json(&agsv(&root.0, &["doctor"]));
    assert_eq!(doctor["data"]["launch"]["model"], "gpt-5.6-terra");
    assert_eq!(doctor["data"]["launch"]["reasoning_effort"], "high");
}

#[test]
#[allow(clippy::too_many_lines)]
fn profile_validation_reports_runtime_references_capabilities_and_role_files() {
    let root = TestDir::new();
    assert!(agsv(&root.0, &["init"]).status.success());
    let local = root.0.join(".agent-supervisor/config.local.toml");

    fs::write(
        &local,
        "[agent_profiles.implementation]\nruntime = \"missing-runtime\"\n",
    )
    .expect("unknown runtime fixture should be written");
    let unknown_runtime = stderr_json(&agsv(&root.0, &["config", "validate"]));
    assert_eq!(unknown_runtime["error"]["code"], "invalid_config");
    assert_eq!(
        unknown_runtime["error"]["details"]["field"],
        "agent_profiles.implementation.runtime"
    );
    assert_eq!(
        unknown_runtime["error"]["details"]["adapter_details"]["available_runtimes"][0],
        "codex"
    );

    fs::write(
        &local,
        "[workspace]\nprimary_profile = \"implementation\"\n",
    )
    .expect("unauthorized Primary fixture should be written");
    let unauthorized = stderr_json(&agsv(&root.0, &["config", "validate"]));
    assert_eq!(unauthorized["error"]["code"], "invalid_config");
    assert_eq!(
        unauthorized["error"]["details"]["required_capability"],
        "human_facing_primary"
    );

    fs::write(
        &local,
        "[agent_profiles.implementation]\nrole_file = \"../outside.md\"\n",
    )
    .expect("invalid role path fixture should be written");
    let invalid_path = stderr_json(&agsv(&root.0, &["config", "validate"]));
    assert_eq!(invalid_path["error"]["code"], "invalid_config");
    assert_eq!(
        invalid_path["error"]["details"]["field"],
        "agent_profiles.implementation.role_file"
    );

    fs::write(
        &local,
        "[agent_profiles.implementation]\nrole_file = \".agent-supervisor/roles/missing.md\"\n",
    )
    .expect("missing role fixture should be written");
    let missing_role = stderr_json(&agsv(&root.0, &["config", "validate"]));
    assert_eq!(missing_role["error"]["code"], "unsafe_path");
    assert!(
        missing_role["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("missing.md"))
    );

    fs::write(&local, "[agent_profiles.research]\nrole = \"research\"\n")
        .expect("incomplete profile fixture should be written");
    let missing_fields = stderr_json(&agsv(&root.0, &["config", "validate"]));
    assert_eq!(missing_fields["error"]["code"], "invalid_config");
    assert!(
        missing_fields["error"]["details"]["missing_fields"]
            .as_array()
            .is_some_and(|fields| fields.len() == 4)
    );

    fs::write(
        &local,
        "[team_profiles.research]\nactor_profile = \"missing\"\ndesired_instances = 2\nassignment_policy = \"least_wip\"\n",
    )
    .expect("unknown actor profile fixture should be written");
    let missing_actor = stderr_json(&agsv(&root.0, &["config", "validate"]));
    assert_eq!(missing_actor["error"]["code"], "invalid_config");
    assert_eq!(
        missing_actor["error"]["details"]["actor_profile"],
        "missing"
    );

    fs::write(
        &local,
        "[team_profiles.implementation]\ndesired_instances = 1025\n",
    )
    .expect("invalid desired count fixture should be written");
    let invalid_count = stderr_json(&agsv(&root.0, &["config", "validate"]));
    assert_eq!(invalid_count["error"]["code"], "invalid_config");
    assert_eq!(invalid_count["error"]["details"]["maximum"], 1_024);

    fs::write(
        &local,
        "[agent_profiles.implementation]\ncapabilities = [\"review?quorum\"]\n",
    )
    .expect("invalid capability token fixture should be written");
    let invalid_capability = stderr_json(&agsv(&root.0, &["config", "validate"]));
    assert_eq!(invalid_capability["error"]["code"], "invalid_config");
    assert_eq!(
        invalid_capability["error"]["details"]["field"],
        "agent_profiles.implementation.capabilities"
    );
    assert_eq!(
        invalid_capability["error"]["details"]["allowed_pattern"],
        "^[A-Za-z0-9_.:/@-]+$"
    );

    fs::write(
        &local,
        "[team_profiles.implementation]\nassignment_policy = \"least wip\"\n",
    )
    .expect("invalid assignment policy fixture should be written");
    let invalid_policy = stderr_json(&agsv(&root.0, &["config", "validate"]));
    assert_eq!(invalid_policy["error"]["code"], "invalid_config");
    assert_eq!(
        invalid_policy["error"]["details"]["field"],
        "team_profiles.implementation.assignment_policy"
    );
    assert_eq!(
        invalid_policy["error"]["details"]["allowed_pattern"],
        "^[A-Za-z0-9_.:/@-]+$"
    );

    fs::write(
        &local,
        "[team_profiles.implementation]\nassignment_policy = \"review_quorum\"\n",
    )
    .expect("unsupported assignment policy fixture should be written");
    let unsupported_policy = stderr_json(&agsv(&root.0, &["config", "validate"]));
    assert_eq!(unsupported_policy["error"]["code"], "invalid_config");
    assert_eq!(
        unsupported_policy["error"]["details"]["field"],
        "team_profiles.implementation.assignment_policy"
    );
    assert_eq!(
        unsupported_policy["error"]["details"]["assignment_policy"],
        "review_quorum"
    );
    assert_eq!(
        unsupported_policy["error"]["details"]["available_assignment_policies"],
        json!(["first_healthy", "least_wip"])
    );

    let capabilities = (0..257)
        .map(|index| format!("\"capability-{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    fs::write(
        &local,
        format!("[agent_profiles.implementation]\ncapabilities = [{capabilities}]\n"),
    )
    .expect("excess capability fixture should be written");
    let excess_capabilities = stderr_json(&agsv(&root.0, &["config", "validate"]));
    assert_eq!(excess_capabilities["error"]["code"], "invalid_config");
    assert_eq!(
        excess_capabilities["error"]["details"]["field"],
        "agent_profiles.implementation.capabilities"
    );
    assert_eq!(excess_capabilities["error"]["details"]["value"], 257);
    assert_eq!(excess_capabilities["error"]["details"]["maximum"], 256);
}

#[test]
fn local_config_overrides_are_typed_merged_and_validated() {
    let root = TestDir::new();
    assert!(agsv(&root.0, &["init"]).status.success());
    let local = root.0.join(".agent-supervisor/config.local.toml");
    fs::write(
        &local,
        "[policy]\nprimary_lease_seconds = 60\nactor_heartbeat_seconds = 15\n\
         [session_layout]\nmax_panes_per_tab = 4\npane_label_template = \"{session_label} · {team_purpose} · {active_request_title}\"\nsplit_direction = \"down\"\nfocus_new_sessions = true\n",
    )
    .expect("local override should be written");

    let show = agsv(&root.0, &["config", "show"]);
    assert!(show.status.success());
    let shown = stdout_json(&show);
    assert_eq!(shown["data"]["source"], "project");
    assert_eq!(shown["data"]["local_override"], true);
    assert_eq!(
        shown["data"]["config"]["policy"]["primary_lease_seconds"],
        60
    );
    assert_eq!(
        shown["data"]["config"]["session_layout"]["max_panes_per_tab"],
        4
    );
    assert_eq!(
        shown["data"]["config"]["session_layout"]["split_direction"],
        "down"
    );
    assert_eq!(
        shown["data"]["config"]["session_layout"]["focus_new_sessions"],
        true
    );
    assert_eq!(
        shown["data"]["config"]["session_layout"]["place_first_implementation_with_primary"],
        true
    );
    assert_eq!(
        shown["data"]["config"]["session_layout"]["pane_label_template"],
        "{session_label} · {team_purpose} · {active_request_title}"
    );

    fs::write(
        &local,
        "[policy]\nprimary_lease_seconds = 10\nactor_heartbeat_seconds = 10\n",
    )
    .expect("invalid override should be written");
    let invalid_range = agsv(&root.0, &["config", "validate"]);
    assert_eq!(
        stderr_json(&invalid_range)["error"]["code"],
        "invalid_config"
    );

    fs::write(&local, "[policy]\nprimary_lease_seconds = \"slow\"\n")
        .expect("wrong type should be written");
    let invalid_type = agsv(&root.0, &["config", "validate"]);
    assert_eq!(
        stderr_json(&invalid_type)["error"]["code"],
        "invalid_config"
    );

    fs::write(&local, "[workspace]\nprimary_role = \"../outside.md\"\n")
        .expect("escaping path should be written");
    let invalid_path = agsv(&root.0, &["config", "validate"]);
    assert_eq!(
        stderr_json(&invalid_path)["error"]["code"],
        "invalid_config"
    );

    fs::write(&local, "[runtime]\nstate_directory = \"/tmp/agsv\"\n")
        .expect("absolute state path should be written");
    let invalid_state_path = agsv(&root.0, &["config", "validate"]);
    assert_eq!(
        stderr_json(&invalid_state_path)["error"]["code"],
        "invalid_config"
    );

    fs::write(&local, "[implementation]\nruntime = \"missing-runtime\"\n")
        .expect("unknown runtime override should be written");
    let unknown_runtime = agsv(&root.0, &["config", "validate"]);
    let unknown_runtime = stderr_json(&unknown_runtime);
    assert_eq!(unknown_runtime["error"]["code"], "invalid_config");
    assert!(
        unknown_runtime["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("is not registered"))
    );

    fs::remove_file(&local).expect("local override should be removed");
    fs::write(agent_config(&root.0), "schema_version = 1\n")
        .expect("incomplete tracked config should be written");
    let missing_fields = agsv(&root.0, &["config", "validate"]);
    assert_eq!(
        stderr_json(&missing_fields)["error"]["code"],
        "invalid_config"
    );
}

#[test]
fn legacy_config_gets_layout_defaults_and_one_pane_compatibility() {
    let root = TestDir::new();
    assert!(agsv(&root.0, &["init"]).status.success());
    fs::write(
        agent_config(&root.0),
        r#"schema_version = 1

[workspace]
primary_role = ".agent-supervisor/roles/primary-orchestrator.md"
implementation_role = ".agent-supervisor/roles/implementation-orchestrator.md"

[runtime]
backend = "herdr"
state_directory = ".agent-supervisor/runtime"

[implementation]
runtime = "codex"
model = "gpt-5.6-sol"
reasoning_effort = "max"

[policy]
primary_lease_seconds = 3600
actor_heartbeat_seconds = 300
"#,
    )
    .expect("legacy config should be written");

    let legacy = agsv(&root.0, &["config", "show"]);
    assert!(legacy.status.success());
    let legacy = stdout_json(&legacy);
    assert_eq!(
        legacy["data"]["config"]["session_layout"]["max_panes_per_tab"],
        2
    );
    assert_eq!(
        legacy["data"]["config"]["session_layout"]["place_first_implementation_with_primary"],
        true
    );
    assert_eq!(
        legacy["data"]["config"]["session_layout"]["tab_label_strategy"],
        "sequence"
    );
    assert_eq!(
        legacy["data"]["config"]["session_layout"]["pane_label_template"],
        "{session_label}"
    );
    assert_eq!(
        legacy["data"]["config"]["session_layout"]["split_direction"],
        "right"
    );
    assert_eq!(
        legacy["data"]["config"]["session_layout"]["focus_new_sessions"],
        false
    );

    let local = root.0.join(".agent-supervisor/config.local.toml");
    fs::write(
        &local,
        "[session_layout]\nmax_panes_per_tab = 1\nplace_first_implementation_with_primary = false\npane_label_template = \"{{{session_label}}}\"\n",
    )
    .expect("compatibility override should be written");
    let compatibility = agsv(&root.0, &["config", "show"]);
    assert!(compatibility.status.success());
    let compatibility = stdout_json(&compatibility);
    assert_eq!(
        compatibility["data"]["config"]["session_layout"]["max_panes_per_tab"],
        1
    );
    assert_eq!(
        compatibility["data"]["config"]["session_layout"]["place_first_implementation_with_primary"],
        false
    );
    assert_eq!(
        compatibility["data"]["config"]["session_layout"]["tab_label_strategy"],
        "sequence"
    );
    assert_eq!(
        compatibility["data"]["config"]["session_layout"]["pane_label_template"],
        "{{{session_label}}}"
    );
}

#[test]
fn session_layout_rejects_invalid_combinations_and_templates() {
    let root = TestDir::new();
    assert!(agsv(&root.0, &["init"]).status.success());
    let local = root.0.join(".agent-supervisor/config.local.toml");
    let oversized = format!(
        "[session_layout]\npane_label_template = \"{}\"\n",
        "x".repeat(257)
    );
    let cases = [
        (
            "primary sharing with one pane",
            "[session_layout]\nmax_panes_per_tab = 1\n",
        ),
        ("zero panes", "[session_layout]\nmax_panes_per_tab = 0\n"),
        (
            "too many panes",
            "[session_layout]\nmax_panes_per_tab = 17\n",
        ),
        (
            "unknown tab strategy",
            "[session_layout]\ntab_label_strategy = \"name\"\n",
        ),
        (
            "unknown split direction",
            "[session_layout]\nsplit_direction = \"left\"\n",
        ),
        (
            "empty pane label template",
            "[session_layout]\npane_label_template = \"\"\n",
        ),
        (
            "blank pane label template",
            "[session_layout]\npane_label_template = \"   \"\n",
        ),
        (
            "control character in pane label template",
            "[session_layout]\npane_label_template = \"bad\\nlabel\"\n",
        ),
        (
            "unknown pane label placeholder",
            "[session_layout]\npane_label_template = \"{actor_id}\"\n",
        ),
        (
            "unclosed pane label placeholder",
            "[session_layout]\npane_label_template = \"{session_label\"\n",
        ),
        ("oversized pane label template", oversized.as_str()),
    ];

    for (case, contents) in cases {
        fs::write(&local, contents).expect("invalid override should be written");
        let output = agsv(&root.0, &["config", "validate"]);
        assert!(!output.status.success(), "{case} unexpectedly validated");
        assert_eq!(
            stderr_json(&output)["error"]["code"],
            "invalid_config",
            "{case}"
        );
    }
}

#[cfg(unix)]
#[test]
fn init_rejects_symlinked_managed_paths_without_touching_targets() {
    use std::os::unix::fs::symlink;

    let root = TestDir::new();
    let outside = TestDir::new();
    let target = outside.0.join("outside-ignore");
    fs::write(&target, "outside\n").expect("outside fixture should be written");
    symlink(&target, root.0.join(".gitignore")).expect("symlink should be created");

    let output = agsv(&root.0, &["init"]);
    assert!(!output.status.success());
    assert_eq!(stderr_json(&output)["error"]["code"], "unsafe_path");
    assert_eq!(fs::read_to_string(target).unwrap(), "outside\n");

    let component_root = TestDir::new();
    let outside_agent = outside.0.join("outside-agent");
    fs::create_dir(&outside_agent).expect("outside agent fixture should be created");
    symlink(&outside_agent, component_root.0.join(".agent-supervisor"))
        .expect("component symlink should be created");
    let component_output = agsv(&component_root.0, &["init"]);
    assert_eq!(
        stderr_json(&component_output)["error"]["code"],
        "unsafe_path"
    );
    assert_eq!(fs::read_dir(outside_agent).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn init_and_config_reject_non_regular_or_symlinked_project_artifacts() {
    use std::os::unix::fs::symlink;

    let root = TestDir::new();
    let agent = root.0.join(".agent-supervisor");
    let roles = agent.join("roles");
    fs::create_dir_all(&roles).expect("fixture directories should be created");
    fs::create_dir(roles.join("primary-orchestrator.md"))
        .expect("non-regular role fixture should be created");
    let init = agsv(&root.0, &["init"]);
    assert_eq!(stderr_json(&init)["error"]["code"], "unsafe_path");

    fs::remove_dir(roles.join("primary-orchestrator.md"))
        .expect("directory fixture should be removed");
    assert!(agsv(&root.0, &["init"]).status.success());
    let primary = roles.join("primary-orchestrator.md");
    fs::remove_file(&primary).expect("generated role should be removed");
    symlink("missing-role", &primary).expect("dangling role symlink should be created");
    let validate = agsv(&root.0, &["config", "validate"]);
    assert_eq!(stderr_json(&validate)["error"]["code"], "unsafe_path");

    let state_root = TestDir::new();
    assert!(agsv(&state_root.0, &["init"]).status.success());
    let state = state_root.0.join(".agent-supervisor/runtime");
    fs::remove_dir_all(&state).expect("generated runtime directory should be removed");
    symlink(&root.0, &state).expect("state directory symlink should be created");
    let state_validate = agsv(&state_root.0, &["config", "validate"]);
    assert_eq!(stderr_json(&state_validate)["error"]["code"], "unsafe_path");
}

fn agent_config(workspace: &Path) -> PathBuf {
    workspace.join(".agent-supervisor/config.toml")
}
