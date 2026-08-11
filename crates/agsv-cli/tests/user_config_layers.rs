use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    config_home: PathBuf,
    state_home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let serial = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "agsv-user-config-functional-{}-{serial}",
            std::process::id()
        ));
        let root = base.join("workspace");
        let config_home = base.join("config");
        let state_home = base.join("state");
        fs::create_dir_all(&root).expect("workspace fixture should be created");
        fs::create_dir_all(&config_home).expect("config fixture should be created");
        git_init(&root);
        Self {
            root,
            config_home,
            state_home,
        }
    }

    fn write_user_config(&self, contents: &str) {
        fs::write(self.config_home.join("config.toml"), contents)
            .expect("user configuration fixture should be written");
    }

    fn agsv(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_agsv"))
            .arg("--workspace")
            .arg(&self.root)
            .arg("--json")
            .env("AGSV_CONFIG_HOME", &self.config_home)
            .env("AGSV_STATE_HOME", &self.state_home)
            .env("AGSV_SESSION_BACKEND", "fake")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("HERDR_PANE_ID")
            .env_remove("AGSV_ACTOR_ID")
            .env_remove("AGSV_ACTOR_ROLE")
            .env_remove("AGSV_DEV_ALLOW_INSECURE_ACTOR")
            .args(args)
            .output()
            .expect("agsv should execute")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let base = self
            .root
            .parent()
            .expect("fixture workspace must have a parent");
        fs::remove_dir_all(base).expect("fixture should be removed");
    }
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
fn absent_user_config_keeps_zero_config_read_only() {
    let fixture = Fixture::new();

    let output = fixture.agsv(&["config", "show"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let shown = stdout_json(&output);
    assert_eq!(shown["data"]["source"], "builtin");
    assert_eq!(shown["data"]["config_layers"]["user"]["loaded"], false);
    assert_eq!(
        shown["data"]["effective_sources"]["agent_profiles.implementation.model"],
        "builtin"
    );
    assert!(!fixture.root.join(".agent-supervisor").exists());
    assert!(!fixture.state_home.exists());
}

#[test]
fn user_runtime_choices_override_builtins_and_keep_embedded_roles() {
    let fixture = Fixture::new();
    fixture.write_user_config(
        r#"[implementation]
model = "user-compat-model"
reasoning_effort = "high"

[agent_profiles.primary]
model = "user-primary-model"
reasoning_effort = "high"

[agent_profiles.implementation]
model = "user-implementation-model"
reasoning_effort = "medium"

[runtime_adapters]
codex = true
"#,
    );

    let output = fixture.agsv(&["config", "show"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let shown = stdout_json(&output);
    assert_eq!(shown["data"]["source"], "user");
    assert_eq!(shown["data"]["config_layers"]["user"]["loaded"], true);
    assert_eq!(shown["data"]["runtime_adapters"]["codex"], true);
    assert_eq!(
        shown["data"]["profiles"]["agent_profiles"]["primary"]["model"],
        "user-primary-model"
    );
    assert_eq!(
        shown["data"]["profiles"]["agent_profiles"]["implementation"]["model"],
        "user-implementation-model"
    );
    assert_eq!(
        shown["data"]["effective_sources"]["implementation.model"],
        "user"
    );
    assert_eq!(
        shown["data"]["effective_sources"]["agent_profiles.primary.model"],
        "user"
    );
    assert_eq!(
        shown["data"]["effective_sources"]["runtime_adapters.codex"],
        "user"
    );
    assert_eq!(shown["data"]["roles"]["primary"]["source"], "builtin");
    assert_eq!(
        shown["data"]["roles"]["implementation"]["source"],
        "builtin"
    );
    assert!(!fixture.root.join(".agent-supervisor").exists());
}

#[test]
fn tracked_and_local_layers_override_user_values_per_field() {
    let fixture = Fixture::new();
    fixture.write_user_config(
        r#"[agent_profiles.implementation]
model = "user-model"
reasoning_effort = "high"

[runtime_adapters]
codex = true
"#,
    );
    let init = fixture.agsv(&["init"]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    fs::write(
        fixture.root.join(".agent-supervisor/config.local.toml"),
        "[agent_profiles.implementation]\nreasoning_effort = \"medium\"\n",
    )
    .expect("local project override should be written");

    let shown = stdout_json(&fixture.agsv(&["config", "show"]));
    assert_eq!(shown["data"]["source"], "project");
    assert_eq!(
        shown["data"]["profiles"]["agent_profiles"]["implementation"]["model"],
        "gpt-5.6-sol"
    );
    assert_eq!(
        shown["data"]["profiles"]["agent_profiles"]["implementation"]["reasoning_effort"],
        "medium"
    );
    assert_eq!(shown["data"]["runtime_adapters"]["codex"], true);
    assert_eq!(
        shown["data"]["effective_sources"]["agent_profiles.implementation.model"],
        "project_tracked"
    );
    assert_eq!(
        shown["data"]["effective_sources"]["agent_profiles.implementation.reasoning_effort"],
        "project_local"
    );
    assert_eq!(
        shown["data"]["effective_sources"]["runtime_adapters.codex"],
        "user"
    );
}

#[test]
fn partial_project_profile_inherits_same_named_user_machine_fields() {
    let fixture = Fixture::new();
    fixture.write_user_config(
        r#"[agent_profiles.research]
runtime = "codex"
model = "user-research-model"
"#,
    );
    assert!(fixture.agsv(&["init"]).status.success());
    fs::write(
        fixture.root.join(".agent-supervisor/roles/research.md"),
        "Research project role.\n",
    )
    .expect("research role should be written");
    fs::write(
        fixture.root.join(".agent-supervisor/config.toml"),
        r#"schema_version = 1

[workspace]
primary_role = ".agent-supervisor/roles/primary-orchestrator.md"
implementation_role = ".agent-supervisor/roles/implementation-orchestrator.md"
primary_profile = "primary"
default_team_profile = "research"

[runtime]
backend = "herdr"
state_directory = ".agent-supervisor/runtime"

[agent_profiles.research]
role = "research"
capabilities = ["implementation_execution"]
role_file = ".agent-supervisor/roles/research.md"

[team_profiles.research]
actor_profile = "research"
desired_instances = 1
assignment_policy = "first_healthy"

[policy]
primary_lease_seconds = 3600
actor_heartbeat_seconds = 300
"#,
    )
    .expect("partial tracked profile should be written");
    fs::write(
        fixture.root.join(".agent-supervisor/config.local.toml"),
        "[agent_profiles.research]\nreasoning_effort = \"high\"\n",
    )
    .expect("local machine-field completion should be written");

    let output = fixture.agsv(&["config", "show"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let shown = stdout_json(&output);
    let research = &shown["data"]["profiles"]["agent_profiles"]["research"];
    assert_eq!(research["role"], "research");
    assert_eq!(research["runtime"], "codex");
    assert_eq!(research["model"], "user-research-model");
    assert_eq!(research["reasoning_effort"], "high");
    assert_eq!(
        shown["data"]["effective_sources"]["agent_profiles.research.role"],
        "project_tracked"
    );
    assert_eq!(
        shown["data"]["effective_sources"]["agent_profiles.research.model"],
        "user"
    );
    assert_eq!(
        shown["data"]["effective_sources"]["agent_profiles.research.reasoning_effort"],
        "project_local"
    );
}

#[test]
fn legacy_project_synthesis_preserves_omitted_user_profile_fields() {
    let fixture = Fixture::new();
    fixture.write_user_config(
        r#"[implementation]
model = "user-shared-model"
"#,
    );
    assert!(fixture.agsv(&["init"]).status.success());
    fs::write(
        fixture.root.join(".agent-supervisor/config.toml"),
        r#"schema_version = 1

[workspace]
primary_role = ".agent-supervisor/roles/primary-orchestrator.md"
implementation_role = ".agent-supervisor/roles/implementation-orchestrator.md"

[runtime]
backend = "herdr"
state_directory = ".agent-supervisor/runtime"

[implementation]
reasoning_effort = "low"

[policy]
primary_lease_seconds = 3600
actor_heartbeat_seconds = 300
"#,
    )
    .expect("partial legacy tracked configuration should be written");

    let output = fixture.agsv(&["config", "show"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let shown = stdout_json(&output);
    let primary = &shown["data"]["profiles"]["agent_profiles"]["primary"];
    let implementation = &shown["data"]["profiles"]["agent_profiles"]["implementation"];
    assert_eq!(primary["model"], "user-shared-model");
    assert_eq!(implementation["model"], "user-shared-model");
    assert_eq!(primary["reasoning_effort"], "low");
    assert_eq!(implementation["reasoning_effort"], "low");
    assert_eq!(
        shown["data"]["effective_sources"]["agent_profiles.primary.model"],
        "user"
    );
    assert_eq!(
        shown["data"]["effective_sources"]["agent_profiles.implementation.model"],
        "user"
    );
    assert_eq!(
        shown["data"]["effective_sources"]["agent_profiles.primary.reasoning_effort"],
        "project_tracked"
    );
}

#[test]
fn tracked_project_inherits_embedded_roles_by_field_provenance() {
    let fixture = Fixture::new();
    let agent_dir = fixture.root.join(".agent-supervisor");
    fs::create_dir(&agent_dir).expect("project config directory should be created");
    fs::write(
        agent_dir.join("config.toml"),
        r#"schema_version = 1

[workspace]

[runtime]

[agent_profiles.implementation]
model = "tracked-model"

[policy]
"#,
    )
    .expect("partial tracked configuration should be written");

    let output = fixture.agsv(&["config", "show"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let shown = stdout_json(&output);
    assert_eq!(shown["data"]["source"], "project");
    assert_eq!(shown["data"]["roles"]["primary"]["source"], "builtin");
    assert_eq!(
        shown["data"]["roles"]["implementation"]["source"],
        "builtin"
    );
    assert_eq!(
        shown["data"]["effective_sources"]["agent_profiles.implementation.role_file"],
        "builtin"
    );
    assert!(!agent_dir.join("roles").exists());
}

#[test]
fn user_layer_rejects_project_decisions_and_disabled_runtime_selection() {
    let fixture = Fixture::new();
    fixture.write_user_config(
        r#"[workspace]
primary_role = ".agent-supervisor/roles/other.md"

[agent_profiles.implementation]
role_file = ".agent-supervisor/roles/other.md"

[team_profiles.implementation]
assignment_policy = "least_wip"
"#,
    );

    let forbidden = stderr_json(&fixture.agsv(&["config", "validate"]));
    assert_eq!(forbidden["error"]["code"], "invalid_config");
    assert_eq!(forbidden["error"]["details"]["layer"], "user");
    let fields = forbidden["error"]["details"]["forbidden_fields"]
        .as_array()
        .expect("forbidden fields should be listed");
    assert!(fields.iter().any(|field| field == "workspace"));
    assert!(
        fields
            .iter()
            .any(|field| field == "agent_profiles.implementation.role_file")
    );
    assert!(fields.iter().any(|field| field == "team_profiles"));

    fixture.write_user_config("[runtime_adapters]\ncodex = false\n");
    let disabled = stderr_json(&fixture.agsv(&["config", "validate"]));
    assert_eq!(disabled["error"]["code"], "invalid_config");
    assert_eq!(
        disabled["error"]["details"]["availability_field"],
        "runtime_adapters.codex"
    );
    assert_eq!(disabled["error"]["details"]["available"], false);
}
