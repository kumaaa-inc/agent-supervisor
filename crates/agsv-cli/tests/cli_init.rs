use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use serde_json::Value;

static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

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
    }
}

fn agsv(workspace: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agsv"))
        .arg("--workspace")
        .arg(workspace)
        .arg("--json")
        .args(args)
        .output()
        .expect("agsv should execute")
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
fn daemon_commands_return_a_stable_unavailable_envelope() {
    let root = TestDir::new();
    let output = agsv(&root.0, &["team", "list"]);

    assert_eq!(output.status.code(), Some(69));
    let envelope = stderr_json(&output);
    assert_eq!(envelope["schema_version"], "agsv.cli.v1");
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["command"], "team.list");
    assert_eq!(envelope["error"]["code"], "backend_unavailable");
    assert_eq!(envelope["error"]["details"]["operation"], "team.list");

    let create = agsv(
        &root.0,
        &[
            "team",
            "create",
            "team-a",
            "--operation-id",
            "team-create-a",
        ],
    );
    assert_eq!(
        stderr_json(&create)["error"]["details"]["request"]["operation_id"],
        "team-create-a"
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

    let show = agsv(&root.0, &["config", "show"]);
    assert!(show.status.success());
    assert_eq!(stdout_json(&show)["data"]["source"], "builtin");

    let validate = agsv(&root.0, &["config", "validate"]);
    assert!(validate.status.success());
    assert_eq!(
        stdout_json(&validate)["data"]["effective"]["source"],
        "builtin"
    );

    let status = agsv(&root.0, &["status"]);
    assert_eq!(status.status.code(), Some(69));
    assert_eq!(
        stderr_json(&status)["error"]["details"]["configuration"]["source"],
        "builtin"
    );
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
}

#[test]
fn local_config_overrides_are_typed_merged_and_validated() {
    let root = TestDir::new();
    assert!(agsv(&root.0, &["init"]).status.success());
    let local = root.0.join(".agent-supervisor/config.local.toml");
    fs::write(
        &local,
        "[policy]\nprimary_lease_seconds = 60\nactor_heartbeat_seconds = 15\n",
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

    fs::remove_file(&local).expect("local override should be removed");
    fs::write(agent_config(&root.0), "schema_version = 1\n")
        .expect("incomplete tracked config should be written");
    let missing_fields = agsv(&root.0, &["config", "validate"]);
    assert_eq!(
        stderr_json(&missing_fields)["error"]["code"],
        "invalid_config"
    );
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
