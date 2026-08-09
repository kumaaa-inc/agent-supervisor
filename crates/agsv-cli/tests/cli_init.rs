use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

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
