use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::cli::ConfigCommand;
use crate::output::{CliError, CommandResult, Success};
use crate::secure_fs::{SecureDir, SecureWorkspace};

pub(crate) const CONFIG_TEMPLATE: &str = include_str!("../../../templates/config.toml");
pub(crate) const PRIMARY_ROLE_TEMPLATE: &str =
    include_str!("../../../templates/roles/primary-orchestrator.md");
pub(crate) const IMPLEMENTATION_ROLE_TEMPLATE: &str =
    include_str!("../../../templates/roles/implementation-orchestrator.md");
const BUILTIN_STATE_SENTINEL: &str = "@user-state";
const USER_CONFIG_FILE: &str = "config.toml";
const DEFAULT_PRIMARY_PROFILE: &str = "primary";
const DEFAULT_TEAM_PROFILE: &str = "implementation";
pub(crate) const HUMAN_FACING_PRIMARY_CAPABILITY: &str = "human_facing_primary";

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConfigSource {
    Builtin,
    User,
    Project,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConfigLayer {
    Builtin,
    User,
    ProjectTracked,
    ProjectLocal,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectConfig {
    schema_version: u32,
    workspace: WorkspaceConfig,
    runtime: RuntimeConfig,
    #[serde(default)]
    implementation: ImplementationConfig,
    #[serde(default)]
    agent_profiles: BTreeMap<String, AgentProfileConfig>,
    #[serde(default)]
    team_profiles: BTreeMap<String, TeamProfileConfig>,
    #[serde(default)]
    runtime_adapters: BTreeMap<String, bool>,
    #[serde(default)]
    session_layout: SessionLayoutConfig,
    #[serde(default)]
    review: ReviewConfig,
    policy: PolicyConfig,
}

// A tracked file keeps the established required top-level project sections,
// while values inside those sections participate in field-granular layering.
// The final ProjectConfig is validated only after every layer is merged.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrackedProjectConfig {
    schema_version: u32,
    workspace: WorkspaceOverride,
    runtime: RuntimeOverride,
    #[serde(default)]
    implementation: ImplementationOverride,
    #[serde(default)]
    agent_profiles: BTreeMap<String, AgentProfileOverride>,
    #[serde(default)]
    team_profiles: BTreeMap<String, TeamProfileOverride>,
    #[serde(default)]
    runtime_adapters: BTreeMap<String, bool>,
    #[serde(default)]
    session_layout: SessionLayoutOverride,
    #[serde(default)]
    review: ReviewOverride,
    policy: PolicyOverride,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceConfig {
    primary_role: PathBuf,
    implementation_role: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    primary_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_team_profile: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeConfig {
    backend: String,
    state_directory: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ImplementationConfig {
    runtime: String,
    model: String,
    reasoning_effort: String,
}

impl Default for ImplementationConfig {
    fn default() -> Self {
        Self {
            runtime: "codex".to_owned(),
            model: "gpt-5.6-sol".to_owned(),
            reasoning_effort: "xhigh".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentProfileConfig {
    role: String,
    #[serde(default)]
    capabilities: BTreeSet<String>,
    #[serde(default)]
    launch: AgentLaunchMode,
    #[serde(alias = "provider")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reasoning_effort: Option<String>,
    role_file: PathBuf,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AgentLaunchMode {
    Bound,
    #[default]
    Runtime,
}

impl AgentLaunchMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Runtime => "runtime",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TeamProfileConfig {
    actor_profile: String,
    desired_instances: u32,
    assignment_policy: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum TabLabelStrategy {
    Sequence,
}

impl TabLabelStrategy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Sequence => "sequence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SplitDirection {
    Right,
    Down,
}

impl SplitDirection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Right => "right",
            Self::Down => "down",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionLayoutConfig {
    max_panes_per_tab: u16,
    place_first_implementation_with_primary: bool,
    tab_label_strategy: TabLabelStrategy,
    pane_label_template: String,
    split_direction: SplitDirection,
    focus_new_sessions: bool,
}

impl Default for SessionLayoutConfig {
    fn default() -> Self {
        Self {
            max_panes_per_tab: 2,
            place_first_implementation_with_primary: true,
            tab_label_strategy: TabLabelStrategy::Sequence,
            pane_label_template: "{session_label}".to_owned(),
            split_direction: SplitDirection::Right,
            focus_new_sessions: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyConfig {
    primary_lease_seconds: u32,
    actor_heartbeat_seconds: u32,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ConfigOverride {
    schema_version: Option<u32>,
    workspace: Option<WorkspaceOverride>,
    runtime: Option<RuntimeOverride>,
    implementation: Option<ImplementationOverride>,
    agent_profiles: BTreeMap<String, AgentProfileOverride>,
    team_profiles: BTreeMap<String, TeamProfileOverride>,
    runtime_adapters: BTreeMap<String, bool>,
    session_layout: Option<SessionLayoutOverride>,
    review: Option<ReviewOverride>,
    policy: Option<PolicyOverride>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReviewConfig {
    #[serde(default)]
    checks: Vec<ReviewCheckConfig>,
    #[serde(default)]
    tool_versions: Vec<ReviewToolVersionConfig>,
    #[serde(default)]
    optional_binaries: BTreeSet<String>,
    #[serde(default)]
    environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReviewCheckConfig {
    id: String,
    argv: Vec<String>,
    #[serde(default)]
    expected_exit_code: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cwd: Option<PathBuf>,
    #[serde(default = "default_review_timeout_seconds")]
    timeout_seconds: u32,
    #[serde(default)]
    required_absent_binaries: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReviewToolVersionConfig {
    id: String,
    argv: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct WorkspaceOverride {
    primary_role: Option<PathBuf>,
    implementation_role: Option<PathBuf>,
    primary_profile: Option<String>,
    default_team_profile: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuntimeOverride {
    backend: Option<String>,
    state_directory: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ImplementationOverride {
    runtime: Option<String>,
    model: Option<String>,
    reasoning_effort: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AgentProfileOverride {
    role: Option<String>,
    capabilities: Option<BTreeSet<String>>,
    launch: Option<AgentLaunchMode>,
    #[serde(alias = "provider")]
    runtime: Option<String>,
    model: Option<String>,
    reasoning_effort: Option<String>,
    role_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TeamProfileOverride {
    actor_profile: Option<String>,
    desired_instances: Option<u32>,
    assignment_policy: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SessionLayoutOverride {
    max_panes_per_tab: Option<u16>,
    place_first_implementation_with_primary: Option<bool>,
    tab_label_strategy: Option<TabLabelStrategy>,
    pane_label_template: Option<String>,
    split_direction: Option<SplitDirection>,
    focus_new_sessions: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PolicyOverride {
    primary_lease_seconds: Option<u32>,
    actor_heartbeat_seconds: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ReviewOverride {
    checks: Option<Vec<ReviewCheckConfig>>,
    tool_versions: Option<Vec<ReviewToolVersionConfig>>,
    optional_binaries: Option<BTreeSet<String>>,
    environment: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct UserConfig {
    implementation: Option<ImplementationOverride>,
    agent_profiles: BTreeMap<String, UserAgentProfileOverride>,
    runtime_adapters: BTreeMap<String, bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct UserAgentProfileOverride {
    #[serde(alias = "provider")]
    runtime: Option<String>,
    model: Option<String>,
    reasoning_effort: Option<String>,
}

impl From<UserConfig> for ConfigOverride {
    fn from(user: UserConfig) -> Self {
        Self {
            implementation: user.implementation,
            agent_profiles: user
                .agent_profiles
                .into_iter()
                .map(|(name, profile)| {
                    (
                        name,
                        AgentProfileOverride {
                            runtime: profile.runtime,
                            model: profile.model,
                            reasoning_effort: profile.reasoning_effort,
                            ..AgentProfileOverride::default()
                        },
                    )
                })
                .collect(),
            runtime_adapters: user.runtime_adapters,
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedAgentProfile {
    pub(crate) name: String,
    pub(crate) role: String,
    pub(crate) capabilities: BTreeSet<String>,
    launch: AgentLaunchMode,
    pub(crate) runtime: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) reasoning_effort: Option<String>,
    pub(crate) role_file: PathBuf,
    pub(crate) instructions: String,
    pub(crate) role_source: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ResolvedTeamProfile {
    pub(crate) name: String,
    pub(crate) actor_profile: String,
    pub(crate) desired_instances: u32,
    pub(crate) assignment_policy: String,
}

pub(crate) struct LoadedConfig {
    source: ConfigSource,
    config: ProjectConfig,
    effective_sources: BTreeMap<String, ConfigLayer>,
    agent_profiles: BTreeMap<String, ResolvedAgentProfile>,
    team_profiles: BTreeMap<String, ResolvedTeamProfile>,
    primary_profile_name: String,
    default_team_profile_name: String,
    persist_profile_snapshots: bool,
    user_config_path: Option<PathBuf>,
    loaded_layers: BTreeSet<ConfigLayer>,
}

impl LoadedConfig {
    pub(crate) const fn source_name(&self) -> &'static str {
        match self.source {
            ConfigSource::Builtin => "builtin",
            ConfigSource::User => "user",
            ConfigSource::Project => "project",
        }
    }

    pub(crate) fn runtime_adapter_availability(&self) -> &BTreeMap<String, bool> {
        &self.config.runtime_adapters
    }

    pub(crate) fn agent_profiles(&self) -> &BTreeMap<String, ResolvedAgentProfile> {
        &self.agent_profiles
    }

    pub(crate) fn team_profiles(&self) -> &BTreeMap<String, ResolvedTeamProfile> {
        &self.team_profiles
    }

    pub(crate) const fn persist_profile_snapshots(&self) -> bool {
        self.persist_profile_snapshots
    }

    pub(crate) fn primary_profile(&self) -> &ResolvedAgentProfile {
        self.agent_profiles
            .get(&self.primary_profile_name)
            .expect("validated configuration must contain the selected Primary profile")
    }

    pub(crate) fn default_team_profile(&self) -> &ResolvedTeamProfile {
        self.team_profiles
            .get(&self.default_team_profile_name)
            .expect("validated configuration must contain the selected default team profile")
    }

    pub(crate) fn scope_runtime_reporting(&self, operation: &str, data: &mut Value) {
        let Some(object) = data.as_object_mut() else {
            return;
        };
        match operation {
            "doctor" | "status" => {
                let primary = self.primary_profile();
                let team = self.default_team_profile();
                let implementation = self
                    .agent_profiles()
                    .get(&team.actor_profile)
                    .expect("validated team profile must reference an actor profile");
                object.insert(
                    "primary_launch".to_owned(),
                    scoped_profile_launch("selected_primary_profile", primary),
                );
                object.insert(
                    "default_team_launch".to_owned(),
                    scoped_team_launch(team, implementation),
                );
                if operation == "doctor" {
                    label_default_team_compatibility_aliases(object, team, implementation);
                }
            }
            "context" => label_context_launch(object),
            _ => {}
        }
    }

    pub(crate) fn summary(&self, root: &Path) -> Result<Value, CliError> {
        let state_directory = self.resolved_state_directory(root)?;
        let roles = self
            .agent_profiles()
            .iter()
            .map(|(name, profile)| {
                (
                    name,
                    json!({
                        "source": profile.role_source,
                        "path": profile.role_file,
                        "bytes": profile.instructions.len(),
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let agent_profiles = self
            .agent_profiles()
            .iter()
            .map(|(name, profile)| {
                (
                    name,
                    json!({
                        "name": profile.name,
                        "role": profile.role,
                        "capabilities": profile.capabilities,
                        "launch": profile_launch_summary(profile),
                        "role_file": profile.role_file,
                        "role_source": profile.role_source,
                        "role_bytes": profile.instructions.len(),
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        Ok(json!({
            "source": self.source,
            "config_layers": {
                "builtin": { "loaded": true, "path": "<builtin config>" },
                "user": {
                    "loaded": self.loaded_layers.contains(&ConfigLayer::User),
                    "path": self.user_config_path,
                },
                "project_tracked": {
                    "loaded": self.loaded_layers.contains(&ConfigLayer::ProjectTracked),
                    "path": ".agent-supervisor/config.toml",
                },
                "project_local": {
                    "loaded": self.loaded_layers.contains(&ConfigLayer::ProjectLocal),
                    "path": ".agent-supervisor/config.local.toml",
                },
            },
            "effective_sources": self.effective_sources,
            "local_override": self.loaded_layers.contains(&ConfigLayer::ProjectLocal),
            "resolved_state_path": state_directory,
            "runtime_adapters": self.runtime_adapter_availability(),
            "config": self.config,
            "roles": roles,
            "profiles": {
                "persist_snapshots": self.persist_profile_snapshots(),
                "selected_primary": self.primary_profile_name,
                "selected_default_team": self.default_team_profile_name,
                "agent_profiles": agent_profiles,
                "team_profiles": self.team_profiles(),
            },
        }))
    }

    pub(crate) fn control_settings(
        &self,
        root: &Path,
    ) -> Result<agsv_control::ControlSettings, CliError> {
        let agent_profiles = self
            .agent_profiles()
            .iter()
            .map(|(name, profile)| (name.clone(), control_actor_profile(profile)))
            .collect();
        let team_profiles = self
            .team_profiles()
            .iter()
            .map(|(name, profile)| {
                (
                    name.clone(),
                    agsv_control::TeamProfileSettings {
                        name: profile.name.clone(),
                        actor_profile: profile.actor_profile.clone(),
                        desired_instances: profile.desired_instances,
                        assignment_policy: profile.assignment_policy.clone(),
                    },
                )
            })
            .collect();
        Ok(agsv_control::ControlSettings {
            workspace: root.to_path_buf(),
            state_directory: self.resolved_state_directory(root)?,
            config_source: self.source_name().to_owned(),
            backend: self.config.runtime.backend.clone(),
            persist_profile_snapshots: self.persist_profile_snapshots(),
            primary_profile: self.primary_profile().name.clone(),
            default_team_profile: self.default_team_profile().name.clone(),
            agent_profiles,
            team_profiles,
            runtime_adapter_availability: self.runtime_adapter_availability().clone(),
            max_panes_per_tab: self.config.session_layout.max_panes_per_tab,
            place_first_implementation_with_primary: self
                .config
                .session_layout
                .place_first_implementation_with_primary,
            tab_label_strategy: self
                .config
                .session_layout
                .tab_label_strategy
                .as_str()
                .to_owned(),
            pane_label_template: self.config.session_layout.pane_label_template.clone(),
            split_direction: self
                .config
                .session_layout
                .split_direction
                .as_str()
                .to_owned(),
            focus_new_sessions: self.config.session_layout.focus_new_sessions,
            primary_lease_seconds: self.config.policy.primary_lease_seconds,
            actor_heartbeat_seconds: self.config.policy.actor_heartbeat_seconds,
            review: agsv_control::ReviewSettings {
                checks: self
                    .config
                    .review
                    .checks
                    .iter()
                    .map(|check| agsv_control::ReviewCheckSettings {
                        id: check.id.clone(),
                        argv: check.argv.clone(),
                        expected_exit_code: check.expected_exit_code,
                        relative_cwd: check.cwd.clone(),
                        timeout_seconds: check.timeout_seconds,
                        required_absent_binaries: check.required_absent_binaries.clone(),
                    })
                    .collect(),
                tool_versions: self
                    .config
                    .review
                    .tool_versions
                    .iter()
                    .map(|tool| agsv_control::ReviewToolVersionSettings {
                        id: tool.id.clone(),
                        argv: tool.argv.clone(),
                    })
                    .collect(),
                optional_binaries: self.config.review.optional_binaries.clone(),
                environment: self.config.review.environment.clone(),
            },
        })
    }

    fn resolved_state_directory(&self, root: &Path) -> Result<PathBuf, CliError> {
        let identity = agsv_control::WorkspaceIdentity::for_configuration(root)
            .map_err(CliError::from_control)?;
        if self.config.runtime.state_directory == Path::new(BUILTIN_STATE_SENTINEL) {
            agsv_control::default_state_directory(&identity).map_err(CliError::from_control)
        } else {
            Ok(identity
                .repository_root()
                .join(&self.config.runtime.state_directory))
        }
    }
}

fn scoped_profile_launch(scope: &str, profile: &ResolvedAgentProfile) -> Value {
    let mut launch = profile_launch_summary(profile);
    let object = launch
        .as_object_mut()
        .expect("profile launch summary must be an object");
    object.insert("scope".to_owned(), json!(scope));
    object.insert("profile".to_owned(), json!(profile.name));
    launch
}

fn scoped_team_launch(team: &ResolvedTeamProfile, profile: &ResolvedAgentProfile) -> Value {
    let mut launch = scoped_profile_launch("selected_default_team_actor_profile", profile);
    launch
        .as_object_mut()
        .expect("profile launch summary must be an object")
        .insert("team_profile".to_owned(), json!(team.name));
    launch
}

fn label_default_team_compatibility_aliases(
    data: &mut serde_json::Map<String, Value>,
    team: &ResolvedTeamProfile,
    profile: &ResolvedAgentProfile,
) {
    for field in ["runtime", "launch"] {
        let Some(object) = data.get_mut(field).and_then(Value::as_object_mut) else {
            continue;
        };
        object.insert(
            "scope".to_owned(),
            json!("selected_default_team_actor_profile"),
        );
        object.insert("team_profile".to_owned(), json!(team.name));
        object.insert("actor_profile".to_owned(), json!(profile.name));
    }
}

fn label_context_launch(data: &mut serde_json::Map<String, Value>) {
    let actor_launch = {
        let Some(profile) = data.get_mut("profile").and_then(Value::as_object_mut) else {
            return;
        };
        let Some(profile_name) = profile
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return;
        };
        let Some(launch) = profile.get_mut("launch").and_then(Value::as_object_mut) else {
            return;
        };
        launch.insert("scope".to_owned(), json!("authenticated_actor_profile"));
        launch.insert("profile".to_owned(), json!(profile_name));
        Value::Object(launch.clone())
    };
    data.insert("actor_launch".to_owned(), actor_launch);
}

fn control_actor_profile(profile: &ResolvedAgentProfile) -> agsv_control::ActorProfileSettings {
    let launch = match profile.launch {
        AgentLaunchMode::Bound => agsv_control::ActorLaunchSettings::Bound,
        AgentLaunchMode::Runtime => agsv_control::ActorLaunchSettings::Runtime {
            runtime: profile
                .runtime
                .clone()
                .expect("validated runtime profile must select an adapter"),
            model: profile
                .model
                .clone()
                .expect("validated runtime profile must select a model"),
            reasoning_effort: profile
                .reasoning_effort
                .clone()
                .expect("validated runtime profile must select reasoning effort"),
        },
    };
    agsv_control::ActorProfileSettings {
        name: profile.name.clone(),
        role: profile.role.clone(),
        capabilities: profile.capabilities.clone(),
        launch,
        role_file: profile.role_file.clone(),
        role_instructions: profile.instructions.clone(),
        role_source: profile.role_source.clone(),
    }
}

pub(crate) fn execute(root: &Path, command: &ConfigCommand) -> CommandResult {
    let loaded = load(root)?;
    match command {
        ConfigCommand::Show => show(root, &loaded),
        ConfigCommand::Validate => validate(root, &loaded),
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn load(root: &Path) -> Result<LoadedConfig, CliError> {
    let workspace = SecureWorkspace::open(root)?;
    let agent_dir = workspace.root().open_dir_optional(".agent-supervisor")?;
    let user_config_path = user_config_path()?;
    let user = read_user_config(user_config_path.as_deref())?;
    let tracked = read_optional(agent_dir.as_ref(), "config.toml")?;
    let local = read_optional(agent_dir.as_ref(), "config.local.toml")?;

    let mut config = parse_toml::<ProjectConfig>(Path::new("<builtin config>"), CONFIG_TEMPLATE)?;
    config.runtime.state_directory = PathBuf::from(BUILTIN_STATE_SENTINEL);
    let mut effective_sources = config_sources(&config, ConfigLayer::Builtin);

    let user_override = user.is_some();
    let mut pending_profiles = BTreeMap::new();
    let mut project_profile_declarations = BTreeSet::new();
    if let Some((path, contents)) = user.as_ref() {
        let mut overrides = parse_user_config(path, contents)?;
        pending_profiles = defer_unknown_user_profiles(&config, &mut overrides);
        for (name, profile) in &pending_profiles {
            record_agent_profile_sources(
                name,
                profile,
                false,
                ConfigLayer::User,
                &mut effective_sources,
            );
        }
        apply_user_override(&mut config, overrides, &mut effective_sources)?;
    }

    let tracked_config = tracked.is_some();
    let profile_tables_declared = if let Some((path, contents)) = tracked.as_ref() {
        let _ = parse_toml::<TrackedProjectConfig>(path, contents)?;
        profile_tables_declared(path, contents)?
    } else {
        true
    };
    let legacy_profiles = tracked_config && !profile_tables_declared;
    let bridge_legacy_overrides = !tracked_config || legacy_profiles;
    if let Some((path, contents)) = tracked.as_ref() {
        let mut overrides = parse_toml::<ConfigOverride>(path, contents)?;
        if legacy_profiles {
            apply_legacy_tracked_override(&mut config, overrides, &mut effective_sources)?;
        } else {
            queue_new_agent_profile_layers(
                &config,
                &mut overrides,
                &mut pending_profiles,
                &mut project_profile_declarations,
                ConfigLayer::ProjectTracked,
                &mut effective_sources,
            );
            apply_layer_override(
                &mut config,
                overrides,
                false,
                ConfigLayer::ProjectTracked,
                &mut effective_sources,
            )?;
        }
    }

    let source = if tracked_config {
        ConfigSource::Project
    } else if user_override {
        ConfigSource::User
    } else {
        ConfigSource::Builtin
    };

    let mut persist_profile_snapshots = tracked_config && !legacy_profiles;
    let mut state_override = false;
    if let Some((path, contents)) = local.as_ref() {
        let mut overrides = parse_toml::<ConfigOverride>(path, contents)?;
        persist_profile_snapshots |=
            !overrides.agent_profiles.is_empty() || !overrides.team_profiles.is_empty();
        state_override = overrides
            .runtime
            .as_ref()
            .is_some_and(|value| value.state_directory.is_some());
        queue_new_agent_profile_layers(
            &config,
            &mut overrides,
            &mut pending_profiles,
            &mut project_profile_declarations,
            ConfigLayer::ProjectLocal,
            &mut effective_sources,
        );
        apply_layer_override(
            &mut config,
            overrides,
            bridge_legacy_overrides,
            ConfigLayer::ProjectLocal,
            &mut effective_sources,
        )?;
    }

    finalize_pending_profiles(
        &mut config,
        pending_profiles,
        &project_profile_declarations,
        user_config_path.as_deref(),
    )?;
    remove_bound_profile_launch_sources(&config, &mut effective_sources);

    validate_semantics(&config)?;
    if matches!(source, ConfigSource::Project) || state_override {
        workspace.check_directory_relative(&config.runtime.state_directory)?;
    }

    let agent_profiles = load_agent_profiles(&workspace, &config, &effective_sources)?;
    let team_profiles = config
        .team_profiles
        .iter()
        .map(|(name, profile)| {
            (
                name.clone(),
                ResolvedTeamProfile {
                    name: name.clone(),
                    actor_profile: profile.actor_profile.clone(),
                    desired_instances: profile.desired_instances,
                    assignment_policy: profile.assignment_policy.clone(),
                },
            )
        })
        .collect();
    let primary_profile_name = selected_primary_profile_name(&config).to_owned();
    let default_team_profile_name = selected_default_team_profile_name(&config).to_owned();
    let loaded_layers = [
        Some(ConfigLayer::Builtin),
        user_override.then_some(ConfigLayer::User),
        tracked_config.then_some(ConfigLayer::ProjectTracked),
        local.is_some().then_some(ConfigLayer::ProjectLocal),
    ]
    .into_iter()
    .flatten()
    .collect();
    Ok(LoadedConfig {
        source,
        config,
        effective_sources,
        agent_profiles,
        team_profiles,
        primary_profile_name,
        default_team_profile_name,
        persist_profile_snapshots,
        user_config_path,
        loaded_layers,
    })
}

fn show(root: &Path, loaded: &LoadedConfig) -> CommandResult {
    let effective = toml::to_string_pretty(&loaded.config).map_err(|error| {
        CliError::invalid_config(
            format!("could not render effective configuration: {error}"),
            json!({ "workspace": root }),
        )
    })?;
    let summary = loaded.summary(root)?;
    Ok(Success {
        human: effective,
        data: summary,
    })
}

fn validate(root: &Path, loaded: &LoadedConfig) -> Result<Success, CliError> {
    let summary = loaded.summary(root)?;
    Ok(Success {
        human: format!("configuration is valid for {}", root.display()),
        data: json!({
            "valid": true,
            "source": loaded.source_name(),
            "effective": summary,
        }),
    })
}

fn user_config_path() -> Result<Option<PathBuf>, CliError> {
    let directory = if let Some(path) = std::env::var_os("AGSV_CONFIG_HOME") {
        PathBuf::from(path)
    } else if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(path).join("agent-supervisor")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("agent-supervisor")
    } else {
        return Ok(None);
    };
    if !directory.is_absolute() {
        return Err(CliError::unsafe_path(
            "AGSV user configuration home must be an absolute path",
            json!({ "path": directory }),
        ));
    }
    Ok(Some(directory.join(USER_CONFIG_FILE)))
}

fn read_user_config(path: Option<&Path>) -> Result<Option<(PathBuf, String)>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let parent = path
        .parent()
        .expect("an absolute user configuration path must have a parent");
    match fs::metadata(parent) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CliError::io(
                "inspect user configuration directory",
                parent,
                &error,
            ));
        }
    }
    let directory = SecureWorkspace::open(parent)?;
    let Some(mut file) = directory.root().open_regular_optional(USER_CONFIG_FILE)? else {
        return Ok(None);
    };
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|error| CliError::io("read user configuration", path, &error))?;
    Ok(Some((path.to_path_buf(), contents)))
}

fn parse_user_config(path: &Path, contents: &str) -> Result<ConfigOverride, CliError> {
    let document = parse_toml::<toml::Value>(path, contents)?;
    let forbidden_fields = user_config_forbidden_fields(&document);
    if !forbidden_fields.is_empty() {
        return Err(CliError::invalid_config(
            format!(
                "user configuration may set only implementation and agent-profile runtime/model/reasoning_effort values plus runtime_adapters availability; project-owned fields are not allowed: {}",
                forbidden_fields.join(", ")
            ),
            json!({
                "path": path,
                "layer": "user",
                "forbidden_fields": forbidden_fields,
                "allowed_fields": [
                    "implementation.runtime",
                    "implementation.model",
                    "implementation.reasoning_effort",
                    "agent_profiles.<name>.runtime",
                    "agent_profiles.<name>.model",
                    "agent_profiles.<name>.reasoning_effort",
                    "runtime_adapters.<runtime>",
                ],
            }),
        ));
    }
    parse_toml::<UserConfig>(path, contents).map(Into::into)
}

fn user_config_forbidden_fields(document: &toml::Value) -> Vec<String> {
    let Some(root) = document.as_table() else {
        return Vec::new();
    };
    let mut forbidden = root
        .keys()
        .filter(|field| {
            !matches!(
                field.as_str(),
                "implementation" | "agent_profiles" | "runtime_adapters"
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    if let Some(implementation) = root.get("implementation").and_then(toml::Value::as_table) {
        forbidden.extend(
            implementation
                .keys()
                .filter(|field| !matches!(field.as_str(), "runtime" | "model" | "reasoning_effort"))
                .map(|field| format!("implementation.{field}")),
        );
    }
    if let Some(agent_profiles) = root.get("agent_profiles").and_then(toml::Value::as_table) {
        for (name, profile) in agent_profiles {
            let Some(profile) = profile.as_table() else {
                continue;
            };
            forbidden.extend(
                profile
                    .keys()
                    .filter(|field| {
                        !matches!(
                            field.as_str(),
                            "runtime" | "provider" | "model" | "reasoning_effort"
                        )
                    })
                    .map(|field| format!("agent_profiles.{name}.{field}")),
            );
        }
    }
    forbidden.sort();
    forbidden
}

fn read_optional(
    agent_dir: Option<&SecureDir>,
    name: &str,
) -> Result<Option<(PathBuf, String)>, CliError> {
    let Some(agent_dir) = agent_dir else {
        return Ok(None);
    };
    let Some(mut file) = agent_dir.open_regular_optional(name)? else {
        return Ok(None);
    };
    let path = PathBuf::from(".agent-supervisor").join(name);
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|error| CliError::io("read", &path, &error))?;
    Ok(Some((path, contents)))
}

fn parse_toml<T>(path: &Path, contents: &str) -> Result<T, CliError>
where
    T: for<'de> Deserialize<'de>,
{
    toml::from_str(contents).map_err(|error| {
        CliError::invalid_config(
            format!("invalid configuration in {}: {error}", path.display()),
            json!({ "path": path, "parse_error": error.to_string() }),
        )
    })
}

fn profile_tables_declared(path: &Path, contents: &str) -> Result<bool, CliError> {
    let document = parse_toml::<toml::Value>(path, contents)?;
    Ok(document.get("agent_profiles").is_some() || document.get("team_profiles").is_some())
}

fn config_sources(config: &ProjectConfig, layer: ConfigLayer) -> BTreeMap<String, ConfigLayer> {
    let mut sources = BTreeMap::new();
    for field in [
        "schema_version",
        "workspace.primary_role",
        "workspace.implementation_role",
        "runtime.backend",
        "runtime.state_directory",
        "implementation.runtime",
        "implementation.model",
        "implementation.reasoning_effort",
        "session_layout.max_panes_per_tab",
        "session_layout.place_first_implementation_with_primary",
        "session_layout.tab_label_strategy",
        "session_layout.pane_label_template",
        "session_layout.split_direction",
        "session_layout.focus_new_sessions",
        "policy.primary_lease_seconds",
        "policy.actor_heartbeat_seconds",
    ] {
        sources.insert(field.to_owned(), layer);
    }
    if config.workspace.primary_profile.is_some() {
        sources.insert("workspace.primary_profile".to_owned(), layer);
    }
    if config.workspace.default_team_profile.is_some() {
        sources.insert("workspace.default_team_profile".to_owned(), layer);
    }
    for name in config.agent_profiles.keys() {
        for field in [
            "role",
            "capabilities",
            "launch",
            "runtime",
            "model",
            "reasoning_effort",
            "role_file",
        ] {
            sources.insert(format!("agent_profiles.{name}.{field}"), layer);
        }
    }
    for name in config.team_profiles.keys() {
        for field in ["actor_profile", "desired_instances", "assignment_policy"] {
            sources.insert(format!("team_profiles.{name}.{field}"), layer);
        }
    }
    for name in config.runtime_adapters.keys() {
        sources.insert(format!("runtime_adapters.{name}"), layer);
    }
    record_review_config_sources(&mut sources, &config.review, layer);
    sources
}

fn record_review_config_sources(
    sources: &mut BTreeMap<String, ConfigLayer>,
    review: &ReviewConfig,
    layer: ConfigLayer,
) {
    for field in [
        "review.checks",
        "review.tool_versions",
        "review.optional_binaries",
        "review.environment",
    ] {
        sources.insert(field.to_owned(), layer);
    }
    for check in &review.checks {
        for field in [
            "argv",
            "expected_exit_code",
            "timeout_seconds",
            "required_absent_binaries",
        ] {
            sources.insert(format!("review.checks.{}.{field}", check.id), layer);
        }
        if check.cwd.is_some() {
            sources.insert(format!("review.checks.{}.cwd", check.id), layer);
        }
    }
    for tool in &review.tool_versions {
        sources.insert(format!("review.tool_versions.{}.argv", tool.id), layer);
    }
    for key in review.environment.keys() {
        sources.insert(format!("review.environment.{key}"), layer);
    }
}

fn defer_unknown_user_profiles(
    config: &ProjectConfig,
    overrides: &mut ConfigOverride,
) -> BTreeMap<String, AgentProfileOverride> {
    let profiles = std::mem::take(&mut overrides.agent_profiles);
    let (known, deferred) = profiles
        .into_iter()
        .partition(|(name, _)| config.agent_profiles.contains_key(name));
    overrides.agent_profiles = known;
    deferred
}

fn queue_new_agent_profile_layers(
    config: &ProjectConfig,
    overrides: &mut ConfigOverride,
    pending_profiles: &mut BTreeMap<String, AgentProfileOverride>,
    project_profile_declarations: &mut BTreeSet<String>,
    layer: ConfigLayer,
    sources: &mut BTreeMap<String, ConfigLayer>,
) {
    let new_profiles = overrides
        .agent_profiles
        .keys()
        .filter(|name| !config.agent_profiles.contains_key(*name))
        .cloned()
        .collect::<Vec<_>>();
    for name in new_profiles {
        let higher = overrides
            .agent_profiles
            .remove(&name)
            .expect("profile name came from the same map");
        let lower = pending_profiles.remove(&name).unwrap_or_default();
        let first_project_declaration = project_profile_declarations.insert(name.clone());
        let supplies_default_capabilities = first_project_declaration
            && lower.capabilities.is_none()
            && higher.capabilities.is_none();
        let merged = merge_agent_profile_overrides(lower.clone(), higher.clone());
        record_agent_profile_sources(
            &name,
            &higher,
            supplies_default_capabilities,
            layer,
            sources,
        );
        pending_profiles.insert(name, merged);
    }
}

fn finalize_pending_profiles(
    config: &mut ProjectConfig,
    pending_profiles: BTreeMap<String, AgentProfileOverride>,
    project_profile_declarations: &BTreeSet<String>,
    user_config_path: Option<&Path>,
) -> Result<(), CliError> {
    let unknown = pending_profiles
        .keys()
        .filter(|name| !project_profile_declarations.contains(*name))
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(unknown_user_profiles(user_config_path, unknown.into_iter()));
    }
    for (name, profile) in pending_profiles {
        apply_agent_profile_override(config, name, profile)?;
    }
    Ok(())
}

fn merge_agent_profile_overrides(
    mut lower: AgentProfileOverride,
    higher: AgentProfileOverride,
) -> AgentProfileOverride {
    if higher.role.is_some() {
        lower.role = higher.role;
    }
    if higher.capabilities.is_some() {
        lower.capabilities = higher.capabilities;
    }
    if higher.launch.is_some() {
        lower.launch = higher.launch;
    }
    if higher.runtime.is_some() {
        lower.runtime = higher.runtime;
    }
    if higher.model.is_some() {
        lower.model = higher.model;
    }
    if higher.reasoning_effort.is_some() {
        lower.reasoning_effort = higher.reasoning_effort;
    }
    if higher.role_file.is_some() {
        lower.role_file = higher.role_file;
    }
    lower
}

fn apply_legacy_tracked_override(
    config: &mut ProjectConfig,
    overrides: ConfigOverride,
    sources: &mut BTreeMap<String, ConfigLayer>,
) -> Result<(), CliError> {
    apply_layer_override(
        config,
        overrides,
        true,
        ConfigLayer::ProjectTracked,
        sources,
    )
}

fn apply_user_override(
    config: &mut ProjectConfig,
    overrides: ConfigOverride,
    sources: &mut BTreeMap<String, ConfigLayer>,
) -> Result<(), CliError> {
    apply_layer_override(config, overrides, true, ConfigLayer::User, sources)
}

fn unknown_user_profiles<'a>(
    path: Option<&Path>,
    profiles: impl Iterator<Item = &'a String>,
) -> CliError {
    let profiles = profiles.cloned().collect::<Vec<_>>();
    CliError::invalid_config(
        format!(
            "user configuration references agent profiles that no project layer defines: {}",
            profiles.join(", ")
        ),
        json!({
            "path": path,
            "layer": "user",
            "unknown_agent_profiles": profiles,
        }),
    )
}

fn remove_bound_profile_launch_sources(
    config: &ProjectConfig,
    sources: &mut BTreeMap<String, ConfigLayer>,
) {
    for (name, profile) in &config.agent_profiles {
        if profile.launch != AgentLaunchMode::Bound {
            continue;
        }
        for field in ["runtime", "model", "reasoning_effort"] {
            sources.remove(&format!("agent_profiles.{name}.{field}"));
        }
    }
}

fn apply_layer_override(
    config: &mut ProjectConfig,
    overrides: ConfigOverride,
    bridge_legacy_overrides: bool,
    layer: ConfigLayer,
    sources: &mut BTreeMap<String, ConfigLayer>,
) -> Result<(), CliError> {
    record_override_sources(config, &overrides, bridge_legacy_overrides, layer, sources);
    apply_override(config, overrides, bridge_legacy_overrides)
}

#[allow(clippy::too_many_lines)]
fn record_override_sources(
    config: &ProjectConfig,
    overrides: &ConfigOverride,
    bridge_legacy_overrides: bool,
    layer: ConfigLayer,
    sources: &mut BTreeMap<String, ConfigLayer>,
) {
    if let Some(review) = &overrides.review {
        record_review_override_sources(review, layer, sources);
    }
    {
        let mut mark = |field: String| {
            sources.insert(field, layer);
        };
        if overrides.schema_version.is_some() {
            mark("schema_version".to_owned());
        }
        if let Some(workspace) = &overrides.workspace {
            if workspace.primary_role.is_some() {
                mark("workspace.primary_role".to_owned());
                if bridge_legacy_overrides {
                    mark(format!(
                        "agent_profiles.{DEFAULT_PRIMARY_PROFILE}.role_file"
                    ));
                }
            }
            if workspace.implementation_role.is_some() {
                mark("workspace.implementation_role".to_owned());
                if bridge_legacy_overrides {
                    mark(format!("agent_profiles.{DEFAULT_TEAM_PROFILE}.role_file"));
                }
            }
            if workspace.primary_profile.is_some() {
                mark("workspace.primary_profile".to_owned());
            }
            if workspace.default_team_profile.is_some() {
                mark("workspace.default_team_profile".to_owned());
            }
        }
        if let Some(runtime) = &overrides.runtime {
            if runtime.backend.is_some() {
                mark("runtime.backend".to_owned());
            }
            if runtime.state_directory.is_some() {
                mark("runtime.state_directory".to_owned());
            }
        }
        if let Some(implementation) = &overrides.implementation {
            for (field, present) in [
                ("runtime", implementation.runtime.is_some()),
                ("model", implementation.model.is_some()),
                (
                    "reasoning_effort",
                    implementation.reasoning_effort.is_some(),
                ),
            ] {
                if present {
                    mark(format!("implementation.{field}"));
                    if bridge_legacy_overrides {
                        mark(format!("agent_profiles.{DEFAULT_TEAM_PROFILE}.{field}"));
                    }
                }
            }
        }
    }
    for (name, profile) in &overrides.agent_profiles {
        let new_profile = !config.agent_profiles.contains_key(name);
        record_agent_profile_sources(name, profile, new_profile, layer, sources);
    }
    {
        let mut mark = |field: String| {
            sources.insert(field, layer);
        };
        for (name, profile) in &overrides.team_profiles {
            for (field, present) in [
                ("actor_profile", profile.actor_profile.is_some()),
                ("desired_instances", profile.desired_instances.is_some()),
                ("assignment_policy", profile.assignment_policy.is_some()),
            ] {
                if present {
                    mark(format!("team_profiles.{name}.{field}"));
                }
            }
        }
        for name in overrides.runtime_adapters.keys() {
            mark(format!("runtime_adapters.{name}"));
        }
        if let Some(layout) = &overrides.session_layout {
            for (field, present) in [
                ("max_panes_per_tab", layout.max_panes_per_tab.is_some()),
                (
                    "place_first_implementation_with_primary",
                    layout.place_first_implementation_with_primary.is_some(),
                ),
                ("tab_label_strategy", layout.tab_label_strategy.is_some()),
                ("pane_label_template", layout.pane_label_template.is_some()),
                ("split_direction", layout.split_direction.is_some()),
                ("focus_new_sessions", layout.focus_new_sessions.is_some()),
            ] {
                if present {
                    mark(format!("session_layout.{field}"));
                }
            }
        }
        if let Some(policy) = &overrides.policy {
            if policy.primary_lease_seconds.is_some() {
                mark("policy.primary_lease_seconds".to_owned());
            }
            if policy.actor_heartbeat_seconds.is_some() {
                mark("policy.actor_heartbeat_seconds".to_owned());
            }
        }
    }
}

fn record_review_override_sources(
    review: &ReviewOverride,
    layer: ConfigLayer,
    sources: &mut BTreeMap<String, ConfigLayer>,
) {
    if let Some(checks) = &review.checks {
        sources.retain(|field, _| !field.starts_with("review.checks."));
        sources.insert("review.checks".to_owned(), layer);
        for check in checks {
            for field in [
                "argv",
                "expected_exit_code",
                "timeout_seconds",
                "required_absent_binaries",
            ] {
                sources.insert(format!("review.checks.{}.{field}", check.id), layer);
            }
            if check.cwd.is_some() {
                sources.insert(format!("review.checks.{}.cwd", check.id), layer);
            }
        }
    }
    if let Some(tool_versions) = &review.tool_versions {
        sources.retain(|field, _| !field.starts_with("review.tool_versions."));
        sources.insert("review.tool_versions".to_owned(), layer);
        for tool in tool_versions {
            sources.insert(format!("review.tool_versions.{}.argv", tool.id), layer);
        }
    }
    if review.optional_binaries.is_some() {
        sources.insert("review.optional_binaries".to_owned(), layer);
    }
    if let Some(environment) = &review.environment {
        sources.retain(|field, _| !field.starts_with("review.environment."));
        sources.insert("review.environment".to_owned(), layer);
        for key in environment.keys() {
            sources.insert(format!("review.environment.{key}"), layer);
        }
    }
}

fn record_agent_profile_sources(
    name: &str,
    profile: &AgentProfileOverride,
    new_profile: bool,
    layer: ConfigLayer,
    sources: &mut BTreeMap<String, ConfigLayer>,
) {
    for (field, present) in [
        ("role", profile.role.is_some()),
        (
            "capabilities",
            profile.capabilities.is_some() || new_profile,
        ),
        ("launch", profile.launch.is_some() || new_profile),
        ("runtime", profile.runtime.is_some()),
        ("model", profile.model.is_some()),
        ("reasoning_effort", profile.reasoning_effort.is_some()),
        ("role_file", profile.role_file.is_some()),
    ] {
        if present {
            sources.insert(format!("agent_profiles.{name}.{field}"), layer);
        }
    }
}

#[allow(clippy::too_many_lines)]
fn apply_override(
    config: &mut ProjectConfig,
    overrides: ConfigOverride,
    bridge_legacy_overrides: bool,
) -> Result<(), CliError> {
    let ConfigOverride {
        schema_version,
        workspace,
        runtime,
        implementation,
        agent_profiles,
        team_profiles,
        runtime_adapters,
        session_layout,
        review,
        policy,
    } = overrides;

    if let Some(schema_version) = schema_version {
        config.schema_version = schema_version;
    }
    if let Some(workspace) = workspace {
        if let Some(primary_role) = workspace.primary_role {
            if bridge_legacy_overrides {
                config
                    .agent_profiles
                    .get_mut(DEFAULT_PRIMARY_PROFILE)
                    .expect("legacy-compatible Primary profile must exist")
                    .role_file
                    .clone_from(&primary_role);
            }
            config.workspace.primary_role = primary_role;
        }
        if let Some(implementation_role) = workspace.implementation_role {
            if bridge_legacy_overrides {
                config
                    .agent_profiles
                    .get_mut(DEFAULT_TEAM_PROFILE)
                    .expect("legacy-compatible implementation profile must exist")
                    .role_file
                    .clone_from(&implementation_role);
            }
            config.workspace.implementation_role = implementation_role;
        }
        if let Some(primary_profile) = workspace.primary_profile {
            config.workspace.primary_profile = Some(primary_profile);
        }
        if let Some(default_team_profile) = workspace.default_team_profile {
            config.workspace.default_team_profile = Some(default_team_profile);
        }
    }
    if let Some(runtime) = runtime {
        if let Some(backend) = runtime.backend {
            config.runtime.backend = backend;
        }
        if let Some(state_directory) = runtime.state_directory {
            config.runtime.state_directory = state_directory;
        }
    }
    if let Some(implementation) = implementation {
        if let Some(runtime) = implementation.runtime {
            if bridge_legacy_overrides {
                config
                    .agent_profiles
                    .get_mut(DEFAULT_TEAM_PROFILE)
                    .expect("legacy-compatible implementation profile must exist")
                    .runtime
                    .replace(runtime.clone());
            }
            config.implementation.runtime = runtime;
        }
        if let Some(model) = implementation.model {
            if bridge_legacy_overrides {
                config
                    .agent_profiles
                    .get_mut(DEFAULT_TEAM_PROFILE)
                    .expect("legacy-compatible implementation profile must exist")
                    .model
                    .replace(model.clone());
            }
            config.implementation.model = model;
        }
        if let Some(reasoning_effort) = implementation.reasoning_effort {
            if bridge_legacy_overrides {
                config
                    .agent_profiles
                    .get_mut(DEFAULT_TEAM_PROFILE)
                    .expect("legacy-compatible implementation profile must exist")
                    .reasoning_effort
                    .replace(reasoning_effort.clone());
            }
            config.implementation.reasoning_effort = reasoning_effort;
        }
    }
    for (name, profile_override) in agent_profiles {
        apply_agent_profile_override(config, name, profile_override)?;
    }
    for (name, profile_override) in team_profiles {
        apply_team_profile_override(config, name, profile_override)?;
    }
    for (name, available) in runtime_adapters {
        config.runtime_adapters.insert(name, available);
    }
    if let Some(session_layout) = session_layout {
        if let Some(max_panes_per_tab) = session_layout.max_panes_per_tab {
            config.session_layout.max_panes_per_tab = max_panes_per_tab;
        }
        if let Some(place_first_implementation_with_primary) =
            session_layout.place_first_implementation_with_primary
        {
            config
                .session_layout
                .place_first_implementation_with_primary = place_first_implementation_with_primary;
        }
        if let Some(tab_label_strategy) = session_layout.tab_label_strategy {
            config.session_layout.tab_label_strategy = tab_label_strategy;
        }
        if let Some(pane_label_template) = session_layout.pane_label_template {
            config.session_layout.pane_label_template = pane_label_template;
        }
        if let Some(split_direction) = session_layout.split_direction {
            config.session_layout.split_direction = split_direction;
        }
        if let Some(focus_new_sessions) = session_layout.focus_new_sessions {
            config.session_layout.focus_new_sessions = focus_new_sessions;
        }
    }
    if let Some(review) = review {
        if let Some(checks) = review.checks {
            config.review.checks = checks;
        }
        if let Some(tool_versions) = review.tool_versions {
            config.review.tool_versions = tool_versions;
        }
        if let Some(optional_binaries) = review.optional_binaries {
            config.review.optional_binaries = optional_binaries;
        }
        if let Some(environment) = review.environment {
            config.review.environment = environment;
        }
    }
    if let Some(policy) = policy {
        if let Some(primary_lease_seconds) = policy.primary_lease_seconds {
            config.policy.primary_lease_seconds = primary_lease_seconds;
        }
        if let Some(actor_heartbeat_seconds) = policy.actor_heartbeat_seconds {
            config.policy.actor_heartbeat_seconds = actor_heartbeat_seconds;
        }
    }
    Ok(())
}

fn apply_agent_profile_override(
    config: &mut ProjectConfig,
    name: String,
    profile_override: AgentProfileOverride,
) -> Result<(), CliError> {
    if let Some(profile) = config.agent_profiles.get_mut(&name) {
        if let Some(role) = profile_override.role {
            profile.role = role;
        }
        if let Some(capabilities) = profile_override.capabilities {
            profile.capabilities = capabilities;
        }
        if let Some(launch) = profile_override.launch {
            profile.launch = launch;
            if launch == AgentLaunchMode::Bound {
                profile.runtime = None;
                profile.model = None;
                profile.reasoning_effort = None;
            }
        }
        if let Some(runtime) = profile_override.runtime {
            if profile.launch == AgentLaunchMode::Runtime {
                profile.runtime = Some(runtime);
            }
        }
        if let Some(model) = profile_override.model {
            if profile.launch == AgentLaunchMode::Runtime {
                profile.model = Some(model);
            }
        }
        if let Some(reasoning_effort) = profile_override.reasoning_effort {
            if profile.launch == AgentLaunchMode::Runtime {
                profile.reasoning_effort = Some(reasoning_effort);
            }
        }
        if let Some(role_file) = profile_override.role_file {
            profile.role_file = role_file;
        }
        return Ok(());
    }

    let AgentProfileOverride {
        role,
        capabilities,
        launch,
        runtime,
        model,
        reasoning_effort,
        role_file,
    } = profile_override;
    let launch = launch.unwrap_or_else(|| {
        if capabilities
            .as_ref()
            .is_some_and(|values| values.contains(HUMAN_FACING_PRIMARY_CAPABILITY))
        {
            AgentLaunchMode::Bound
        } else {
            AgentLaunchMode::Runtime
        }
    });
    let mut missing = [("role", role.is_none()), ("role_file", role_file.is_none())]
        .into_iter()
        .filter_map(|(field, absent)| absent.then_some(field))
        .collect::<Vec<_>>();
    if launch == AgentLaunchMode::Runtime {
        missing.extend(
            [
                ("runtime", runtime.is_none()),
                ("model", model.is_none()),
                ("reasoning_effort", reasoning_effort.is_none()),
            ]
            .into_iter()
            .filter_map(|(field, absent)| absent.then_some(field)),
        );
    }
    if !missing.is_empty() {
        return Err(CliError::invalid_config(
            format!(
                "layered configuration for new agent profile `{name}` is missing required fields: {}",
                missing.join(", ")
            ),
            json!({ "profile": name, "missing_fields": missing }),
        ));
    }
    config.agent_profiles.insert(
        name,
        AgentProfileConfig {
            role: role.expect("checked above"),
            capabilities: capabilities.unwrap_or_default(),
            launch,
            runtime: (launch == AgentLaunchMode::Runtime)
                .then_some(runtime)
                .flatten(),
            model: (launch == AgentLaunchMode::Runtime)
                .then_some(model)
                .flatten(),
            reasoning_effort: (launch == AgentLaunchMode::Runtime)
                .then_some(reasoning_effort)
                .flatten(),
            role_file: role_file.expect("checked above"),
        },
    );
    Ok(())
}

fn apply_team_profile_override(
    config: &mut ProjectConfig,
    name: String,
    profile_override: TeamProfileOverride,
) -> Result<(), CliError> {
    if let Some(profile) = config.team_profiles.get_mut(&name) {
        if let Some(actor_profile) = profile_override.actor_profile {
            profile.actor_profile = actor_profile;
        }
        if let Some(desired_instances) = profile_override.desired_instances {
            profile.desired_instances = desired_instances;
        }
        if let Some(assignment_policy) = profile_override.assignment_policy {
            profile.assignment_policy = assignment_policy;
        }
        return Ok(());
    }

    let TeamProfileOverride {
        actor_profile,
        desired_instances,
        assignment_policy,
    } = profile_override;
    let missing = [
        ("actor_profile", actor_profile.is_none()),
        ("desired_instances", desired_instances.is_none()),
        ("assignment_policy", assignment_policy.is_none()),
    ]
    .into_iter()
    .filter_map(|(field, absent)| absent.then_some(field))
    .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(CliError::invalid_config(
            format!(
                "local override for new team profile `{name}` is missing required fields: {}",
                missing.join(", ")
            ),
            json!({ "profile": name, "missing_fields": missing }),
        ));
    }
    config.team_profiles.insert(
        name,
        TeamProfileConfig {
            actor_profile: actor_profile.expect("checked above"),
            desired_instances: desired_instances.expect("checked above"),
            assignment_policy: assignment_policy.expect("checked above"),
        },
    );
    Ok(())
}

fn validate_semantics(config: &ProjectConfig) -> Result<(), CliError> {
    validate_runtime_adapters(config)?;
    validate_legacy_semantics(config)?;
    validate_agent_profiles(config)?;
    validate_team_profiles(config)?;
    validate_review_config(&config.review)?;
    validate_primary_profile_selection(config)?;
    validate_default_team_profile_selection(config)
}

fn default_review_timeout_seconds() -> u32 {
    3_600
}

fn validate_legacy_semantics(config: &ProjectConfig) -> Result<(), CliError> {
    if config.schema_version != 1 {
        return Err(CliError::invalid_config(
            "config schema_version must be 1",
            json!({ "schema_version": config.schema_version }),
        ));
    }
    validate_relative_path("workspace.primary_role", &config.workspace.primary_role)?;
    validate_relative_path(
        "workspace.implementation_role",
        &config.workspace.implementation_role,
    )?;
    validate_relative_path("runtime.state_directory", &config.runtime.state_directory)?;
    if config.runtime.backend.trim().is_empty() {
        return Err(CliError::invalid_config(
            "runtime.backend must be a non-empty registered backend identifier",
            json!({ "backend": config.runtime.backend }),
        ));
    }
    validate_range(
        "policy.primary_lease_seconds",
        config.policy.primary_lease_seconds,
        1,
        86_400,
    )?;
    validate_range(
        "policy.actor_heartbeat_seconds",
        config.policy.actor_heartbeat_seconds,
        1,
        3_600,
    )?;
    if config.policy.actor_heartbeat_seconds >= config.policy.primary_lease_seconds {
        return Err(CliError::invalid_config(
            "policy.actor_heartbeat_seconds must be less than policy.primary_lease_seconds",
            json!({
                "primary_lease_seconds": config.policy.primary_lease_seconds,
                "actor_heartbeat_seconds": config.policy.actor_heartbeat_seconds,
            }),
        ));
    }
    validate_runtime_selection(
        config,
        "implementation.runtime",
        &config.implementation.runtime,
    )?;
    validate_text_field("implementation.model", &config.implementation.model, 256)?;
    validate_text_field(
        "implementation.reasoning_effort",
        &config.implementation.reasoning_effort,
        128,
    )
}

fn validate_agent_profiles(config: &ProjectConfig) -> Result<(), CliError> {
    if config.agent_profiles.is_empty() {
        return Err(CliError::invalid_config(
            "agent_profiles must define at least one actor profile",
            json!({ "field": "agent_profiles" }),
        ));
    }
    for (name, profile) in &config.agent_profiles {
        validate_token(&format!("agent_profiles.{name} name"), name, 128)?;
        validate_text_field(&format!("agent_profiles.{name}.role"), &profile.role, 128)?;
        if profile.capabilities.len() > agsv_control::MAX_PROFILE_CAPABILITIES {
            return Err(CliError::invalid_config(
                format!(
                    "agent_profiles.{name}.capabilities must contain at most {} entries",
                    agsv_control::MAX_PROFILE_CAPABILITIES
                ),
                json!({
                    "field": format!("agent_profiles.{name}.capabilities"),
                    "value": profile.capabilities.len(),
                    "maximum": agsv_control::MAX_PROFILE_CAPABILITIES,
                }),
            ));
        }
        for capability in &profile.capabilities {
            validate_token(
                &format!("agent_profiles.{name}.capabilities"),
                capability,
                128,
            )?;
        }
        match profile.launch {
            AgentLaunchMode::Bound => {
                if profile.runtime.is_some()
                    || profile.model.is_some()
                    || profile.reasoning_effort.is_some()
                {
                    return Err(CliError::invalid_config(
                        format!(
                            "agent_profiles.{name} is bound and cannot declare runtime launch fields"
                        ),
                        json!({
                            "field": format!("agent_profiles.{name}.launch"),
                            "launch": profile.launch.as_str(),
                            "forbidden_fields": ["runtime", "model", "reasoning_effort"],
                        }),
                    ));
                }
            }
            AgentLaunchMode::Runtime => {
                let runtime =
                    required_profile_launch_field(name, "runtime", profile.runtime.as_deref())?;
                let model = required_profile_launch_field(name, "model", profile.model.as_deref())?;
                let reasoning_effort = required_profile_launch_field(
                    name,
                    "reasoning_effort",
                    profile.reasoning_effort.as_deref(),
                )?;
                validate_runtime_selection(
                    config,
                    &format!("agent_profiles.{name}.runtime"),
                    runtime,
                )?;
                validate_text_field(&format!("agent_profiles.{name}.model"), model, 256)?;
                validate_text_field(
                    &format!("agent_profiles.{name}.reasoning_effort"),
                    reasoning_effort,
                    128,
                )?;
            }
        }
        validate_relative_path(
            &format!("agent_profiles.{name}.role_file"),
            &profile.role_file,
        )?;
    }
    Ok(())
}

fn required_profile_launch_field<'a>(
    profile: &str,
    field: &str,
    value: Option<&'a str>,
) -> Result<&'a str, CliError> {
    value.ok_or_else(|| {
        CliError::invalid_config(
            format!("agent_profiles.{profile}.{field} is required for runtime launch"),
            json!({
                "field": format!("agent_profiles.{profile}.{field}"),
                "launch": "runtime",
            }),
        )
    })
}

fn validate_runtime_adapters(config: &ProjectConfig) -> Result<(), CliError> {
    for runtime in config.runtime_adapters.keys() {
        validate_token(&format!("runtime_adapters.{runtime}"), runtime, 128)?;
        validate_runtime_field(&format!("runtime_adapters.{runtime}"), runtime)?;
    }
    Ok(())
}

fn validate_team_profiles(config: &ProjectConfig) -> Result<(), CliError> {
    if config.team_profiles.is_empty() {
        return Err(CliError::invalid_config(
            "team_profiles must define at least one persistent team profile",
            json!({ "field": "team_profiles" }),
        ));
    }
    for (name, profile) in &config.team_profiles {
        validate_token(&format!("team_profiles.{name} name"), name, 128)?;
        validate_token(
            &format!("team_profiles.{name}.actor_profile"),
            &profile.actor_profile,
            128,
        )?;
        let actor_profile = config
            .agent_profiles
            .get(&profile.actor_profile)
            .ok_or_else(|| {
                CliError::invalid_config(
                    format!(
                        "team_profiles.{name}.actor_profile references unknown agent profile `{}`",
                        profile.actor_profile
                    ),
                    json!({
                        "field": format!("team_profiles.{name}.actor_profile"),
                        "actor_profile": profile.actor_profile,
                        "available_agent_profiles": config.agent_profiles.keys().collect::<Vec<_>>(),
                    }),
                )
            })?;
        if actor_profile.launch != AgentLaunchMode::Runtime {
            return Err(CliError::invalid_config(
                format!(
                    "team_profiles.{name}.actor_profile `{}` must be runtime-launched",
                    profile.actor_profile
                ),
                json!({
                    "field": format!("team_profiles.{name}.actor_profile"),
                    "team_profile": name,
                    "actor_profile": profile.actor_profile,
                    "launch": actor_profile.launch.as_str(),
                    "required_launch": "runtime",
                    "reason": "team actors are created through a runtime adapter and cannot use a bound caller session",
                }),
            ));
        }
        if profile.desired_instances > 1_024 {
            return Err(CliError::invalid_config(
                format!("team_profiles.{name}.desired_instances must be at most 1024"),
                json!({
                    "field": format!("team_profiles.{name}.desired_instances"),
                    "value": profile.desired_instances,
                    "maximum": 1_024,
                }),
            ));
        }
        validate_token(
            &format!("team_profiles.{name}.assignment_policy"),
            &profile.assignment_policy,
            128,
        )?;
        if !agsv_control::SUPPORTED_ASSIGNMENT_POLICIES
            .contains(&profile.assignment_policy.as_str())
        {
            return Err(CliError::invalid_config(
                format!(
                    "team_profiles.{name}.assignment_policy `{}` is not supported",
                    profile.assignment_policy
                ),
                json!({
                    "field": format!("team_profiles.{name}.assignment_policy"),
                    "assignment_policy": profile.assignment_policy,
                    "available_assignment_policies": agsv_control::SUPPORTED_ASSIGNMENT_POLICIES,
                }),
            ));
        }
    }
    Ok(())
}

// Keep the cross-field suite, probe, binary, and environment constraints in a
// single exhaustive validator so no partially valid review plan can escape.
#[allow(clippy::too_many_lines)]
fn validate_review_config(review: &ReviewConfig) -> Result<(), CliError> {
    const MAX_ITEMS: usize = 64;
    if review.checks.len() > MAX_ITEMS
        || review.tool_versions.len() > MAX_ITEMS
        || review.optional_binaries.len() > MAX_ITEMS
        || review.environment.len() > MAX_ITEMS
    {
        return Err(CliError::invalid_config(
            "review configuration collections may contain at most 64 entries each",
            json!({
                "checks": review.checks.len(),
                "tool_versions": review.tool_versions.len(),
                "optional_binaries": review.optional_binaries.len(),
                "environment": review.environment.len(),
                "maximum": MAX_ITEMS,
            }),
        ));
    }

    let mut check_ids = BTreeSet::new();
    for check in &review.checks {
        validate_review_id("review.checks.id", &check.id)?;
        if !check_ids.insert(&check.id) {
            return Err(CliError::invalid_config(
                format!("review check id `{}` is declared more than once", check.id),
                json!({ "field": "review.checks.id", "id": check.id }),
            ));
        }
        validate_review_argv(&format!("review.checks.{}.argv", check.id), &check.argv)?;
        if !(0..=255).contains(&check.expected_exit_code) {
            return Err(CliError::invalid_config(
                format!(
                    "review.checks.{}.expected_exit_code must be between 0 and 255",
                    check.id
                ),
                json!({
                    "field": format!("review.checks.{}.expected_exit_code", check.id),
                    "value": check.expected_exit_code,
                }),
            ));
        }
        if let Some(cwd) = &check.cwd {
            validate_relative_path(&format!("review.checks.{}.cwd", check.id), cwd)?;
        }
        validate_range(
            &format!("review.checks.{}.timeout_seconds", check.id),
            check.timeout_seconds,
            1,
            86_400,
        )?;
        for binary in &check.required_absent_binaries {
            validate_review_id(
                &format!("review.checks.{}.required_absent_binaries", check.id),
                binary,
            )?;
            if !review.optional_binaries.contains(binary) {
                return Err(CliError::invalid_config(
                    format!(
                        "review check `{}` requires undeclared optional binary `{binary}` to be absent",
                        check.id
                    ),
                    json!({
                        "field": format!("review.checks.{}.required_absent_binaries", check.id),
                        "binary": binary,
                        "optional_binaries": review.optional_binaries,
                    }),
                ));
            }
            if check.argv[0] == *binary
                || review
                    .tool_versions
                    .iter()
                    .any(|probe| probe.argv[0] == *binary)
            {
                return Err(CliError::invalid_config(
                    format!(
                        "review check `{}` cannot require its own check or version-probe executable `{binary}` to be absent",
                        check.id
                    ),
                    json!({
                        "field": format!("review.checks.{}.required_absent_binaries", check.id),
                        "binary": binary,
                    }),
                ));
            }
        }
    }

    let mut tool_ids = BTreeSet::new();
    for tool in &review.tool_versions {
        validate_review_id("review.tool_versions.id", &tool.id)?;
        if !tool_ids.insert(&tool.id) {
            return Err(CliError::invalid_config(
                format!("review tool id `{}` is declared more than once", tool.id),
                json!({ "field": "review.tool_versions.id", "id": tool.id }),
            ));
        }
        validate_review_argv(
            &format!("review.tool_versions.{}.argv", tool.id),
            &tool.argv,
        )?;
    }
    if !review.checks.is_empty() && review.tool_versions.is_empty() {
        return Err(CliError::invalid_config(
            "a non-empty review suite must declare at least one tool version probe",
            json!({ "field": "review.tool_versions" }),
        ));
    }
    let probed_programs = review
        .tool_versions
        .iter()
        .map(|tool| tool.argv[0].as_str())
        .collect::<BTreeSet<_>>();
    for check in &review.checks {
        if !probed_programs.contains(check.argv[0].as_str()) {
            return Err(CliError::invalid_config(
                format!(
                    "review check `{}` executes `{}` without a matching tool version probe",
                    check.id, check.argv[0]
                ),
                json!({
                    "field": format!("review.checks.{}.argv", check.id),
                    "program": check.argv[0],
                }),
            ));
        }
    }
    for binary in &review.optional_binaries {
        validate_review_id("review.optional_binaries", binary)?;
    }
    for (key, value) in &review.environment {
        agsv_control::ReviewSettings::validate_environment_entry(key, value).map_err(|error| {
            CliError::invalid_config(
                error.message,
                json!({
                    "field": format!("review.environment.{key}"),
                    "key": key,
                    "protocol_error": error.details,
                }),
            )
        })?;
        if value.len() > 4_096 || value.contains('\0') {
            return Err(CliError::invalid_config(
                format!(
                    "review.environment value for `{key}` must be at most 4096 bytes and contain no NUL"
                ),
                json!({ "field": format!("review.environment.{key}"), "length_bytes": value.len() }),
            ));
        }
        if value.contains("{inherit}") && value != "{inherit}" {
            return Err(CliError::invalid_config(
                format!(
                    "review.environment value for `{key}` must use `{{inherit}}` as the entire value"
                ),
                json!({ "field": format!("review.environment.{key}") }),
            ));
        }
    }
    Ok(())
}

fn validate_review_id(field: &str, value: &str) -> Result<(), CliError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(CliError::invalid_config(
            format!(
                "{field} must use 1-128 portable binary-name characters and not start with `-`"
            ),
            json!({ "field": field, "value": value }),
        ))
    }
}

fn validate_review_argv(field: &str, argv: &[String]) -> Result<(), CliError> {
    if argv.is_empty() || argv.len() > 128 {
        return Err(CliError::invalid_config(
            format!("{field} must contain between 1 and 128 arguments"),
            json!({ "field": field, "argument_count": argv.len() }),
        ));
    }
    validate_review_id(&format!("{field}[0]"), &argv[0])?;
    for (index, argument) in argv.iter().enumerate().skip(1) {
        if argument.len() > 4_096 || argument.chars().any(char::is_control) {
            return Err(CliError::invalid_config(
                format!(
                    "{field}[{index}] must be at most 4096 bytes and contain no control characters"
                ),
                json!({ "field": field, "index": index, "length_bytes": argument.len() }),
            ));
        }
    }
    Ok(())
}

fn validate_primary_profile_selection(config: &ProjectConfig) -> Result<(), CliError> {
    let primary_profile_name = selected_primary_profile_name(config);
    validate_token("workspace.primary_profile", primary_profile_name, 128)?;
    let primary_profile = config
        .agent_profiles
        .get(primary_profile_name)
        .ok_or_else(|| {
            CliError::invalid_config(
                format!(
                    "workspace.primary_profile references unknown agent profile `{primary_profile_name}`"
                ),
                json!({
                    "field": "workspace.primary_profile",
                    "primary_profile": primary_profile_name,
                    "available_agent_profiles": config.agent_profiles.keys().collect::<Vec<_>>(),
                }),
            )
        })?;
    if !primary_profile
        .capabilities
        .contains(HUMAN_FACING_PRIMARY_CAPABILITY)
    {
        return Err(CliError::invalid_config(
            format!(
                "workspace.primary_profile `{primary_profile_name}` must declare capability `{HUMAN_FACING_PRIMARY_CAPABILITY}`"
            ),
            json!({
                "field": "workspace.primary_profile",
                "primary_profile": primary_profile_name,
                "required_capability": HUMAN_FACING_PRIMARY_CAPABILITY,
                "capabilities": primary_profile.capabilities,
            }),
        ));
    }
    if primary_profile.launch != AgentLaunchMode::Bound {
        return Err(CliError::invalid_config(
            format!(
                "workspace.primary_profile `{primary_profile_name}` must use bound launch mode"
            ),
            json!({
                "field": format!("agent_profiles.{primary_profile_name}.launch"),
                "primary_profile": primary_profile_name,
                "launch": primary_profile.launch.as_str(),
                "required_launch": "bound",
                "reason": "the human-facing Primary is bound to its caller session and is not runtime-launched",
            }),
        ));
    }
    validate_range(
        "session_layout.max_panes_per_tab",
        u32::from(config.session_layout.max_panes_per_tab),
        1,
        16,
    )?;
    if config.session_layout.max_panes_per_tab == 1
        && config
            .session_layout
            .place_first_implementation_with_primary
    {
        return Err(CliError::invalid_config(
            "session_layout.place_first_implementation_with_primary requires max_panes_per_tab of at least 2",
            json!({
                "max_panes_per_tab": config.session_layout.max_panes_per_tab,
                "place_first_implementation_with_primary": true,
            }),
        ));
    }
    validate_pane_label_template(&config.session_layout.pane_label_template)?;
    Ok(())
}

fn validate_default_team_profile_selection(config: &ProjectConfig) -> Result<(), CliError> {
    let default_team_profile_name = selected_default_team_profile_name(config);
    validate_token(
        "workspace.default_team_profile",
        default_team_profile_name,
        128,
    )?;
    if !config.team_profiles.contains_key(default_team_profile_name) {
        return Err(CliError::invalid_config(
            format!(
                "workspace.default_team_profile references unknown team profile `{default_team_profile_name}`"
            ),
            json!({
                "field": "workspace.default_team_profile",
                "default_team_profile": default_team_profile_name,
                "available_team_profiles": config.team_profiles.keys().collect::<Vec<_>>(),
            }),
        ));
    }
    Ok(())
}

fn selected_primary_profile_name(config: &ProjectConfig) -> &str {
    config
        .workspace
        .primary_profile
        .as_deref()
        .unwrap_or(DEFAULT_PRIMARY_PROFILE)
}

fn selected_default_team_profile_name(config: &ProjectConfig) -> &str {
    config
        .workspace
        .default_team_profile
        .as_deref()
        .unwrap_or(DEFAULT_TEAM_PROFILE)
}

fn validate_runtime_field(field: &str, runtime: &str) -> Result<(), CliError> {
    if runtime.trim().is_empty() {
        return Err(CliError::invalid_config(
            format!("{field} must be non-empty"),
            json!({ "field": field, "runtime": runtime }),
        ));
    }
    agsv_control::validate_runtime(runtime).map_err(|error| {
        let message = format!("invalid {field}: {error}");
        CliError::invalid_config(
            message,
            json!({
                "field": field,
                "runtime": runtime,
                "adapter_error_code": error.code,
                "adapter_details": error.details,
            }),
        )
    })
}

fn validate_runtime_selection(
    config: &ProjectConfig,
    field: &str,
    runtime: &str,
) -> Result<(), CliError> {
    validate_runtime_field(field, runtime)?;
    if config.runtime_adapters.get(runtime) == Some(&false) {
        return Err(CliError::invalid_config(
            format!(
                "{field} selects runtime adapter `{runtime}`, but runtime_adapters.{runtime} is false"
            ),
            json!({
                "field": field,
                "runtime": runtime,
                "availability_field": format!("runtime_adapters.{runtime}"),
                "available": false,
            }),
        ));
    }
    Ok(())
}

fn validate_text_field(field: &str, value: &str, maximum: usize) -> Result<(), CliError> {
    let valid = !value.trim().is_empty()
        && value.trim() == value
        && value.len() <= maximum
        && !value.chars().any(char::is_control);
    if valid {
        Ok(())
    } else {
        Err(CliError::invalid_config(
            format!(
                "{field} must be non-empty, contain no surrounding whitespace or control characters, and be at most {maximum} bytes"
            ),
            json!({ "field": field, "value": value, "maximum_bytes": maximum }),
        ))
    }
}

fn validate_token(field: &str, value: &str, maximum: usize) -> Result<(), CliError> {
    validate_text_field(field, value, maximum)?;
    let portable = value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
    });
    if portable {
        Ok(())
    } else {
        Err(CliError::invalid_config(
            format!("{field} must use ASCII letters, digits, or - _ . : / @"),
            json!({
                "field": field,
                "value": value,
                "allowed_pattern": "^[A-Za-z0-9_.:/@-]+$",
            }),
        ))
    }
}

fn validate_pane_label_template(template: &str) -> Result<(), CliError> {
    if template.trim().is_empty() || template.len() > 256 || template.chars().any(char::is_control)
    {
        return Err(CliError::invalid_config(
            "session_layout.pane_label_template must be non-empty, at most 256 bytes, and contain no control characters",
            json!({
                "field": "session_layout.pane_label_template",
                "length_bytes": template.len(),
            }),
        ));
    }

    let mut characters = template.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        match character {
            '{' if characters.peek().is_some_and(|(_, next)| *next == '{') => {
                characters.next();
            }
            '}' if characters.peek().is_some_and(|(_, next)| *next == '}') => {
                characters.next();
            }
            '{' => {
                let remaining = &template[index + character.len_utf8()..];
                let Some(end) = remaining.find('}') else {
                    return Err(invalid_pane_label_placeholder(template));
                };
                let placeholder = &remaining[..end];
                if !matches!(
                    placeholder,
                    "session_label" | "team_purpose" | "active_request_title"
                ) {
                    return Err(invalid_pane_label_placeholder(template));
                }
                for _ in 0..=end {
                    characters.next();
                }
            }
            '}' => return Err(invalid_pane_label_placeholder(template)),
            _ => {}
        }
    }
    Ok(())
}

fn invalid_pane_label_placeholder(template: &str) -> CliError {
    CliError::invalid_config(
        "session_layout.pane_label_template supports only {session_label}, {team_purpose}, and {active_request_title}",
        json!({
            "field": "session_layout.pane_label_template",
            "template": template,
        }),
    )
}

fn validate_relative_path(field: &str, path: &Path) -> Result<(), CliError> {
    let valid = !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)));
    if valid {
        Ok(())
    } else {
        Err(CliError::invalid_config(
            format!("{field} must be workspace-relative and contain no `.` or `..`"),
            json!({ "field": field, "path": path }),
        ))
    }
}

fn validate_range(field: &str, value: u32, minimum: u32, maximum: u32) -> Result<(), CliError> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(CliError::invalid_config(
            format!("{field} must be between {minimum} and {maximum}"),
            json!({ "field": field, "value": value, "minimum": minimum, "maximum": maximum }),
        ))
    }
}

fn load_agent_profiles(
    workspace: &SecureWorkspace,
    config: &ProjectConfig,
    effective_sources: &BTreeMap<String, ConfigLayer>,
) -> Result<BTreeMap<String, ResolvedAgentProfile>, CliError> {
    config
        .agent_profiles
        .iter()
        .map(|(name, profile)| {
            let role_file_source = effective_sources
                .get(&format!("agent_profiles.{name}.role_file"))
                .copied();
            let embedded = role_file_source == Some(ConfigLayer::Builtin)
                && matches!(
                    name.as_str(),
                    DEFAULT_PRIMARY_PROFILE | DEFAULT_TEAM_PROFILE
                );
            let (instructions, role_source) = if embedded && name == DEFAULT_PRIMARY_PROFILE {
                (PRIMARY_ROLE_TEMPLATE.to_owned(), "builtin".to_owned())
            } else if embedded {
                (
                    IMPLEMENTATION_ROLE_TEMPLATE.to_owned(),
                    "builtin".to_owned(),
                )
            } else {
                read_role(workspace, &profile.role_file)?
            };
            Ok((
                name.clone(),
                ResolvedAgentProfile {
                    name: name.clone(),
                    role: profile.role.clone(),
                    capabilities: profile.capabilities.clone(),
                    launch: profile.launch,
                    runtime: profile.runtime.clone(),
                    model: profile.model.clone(),
                    reasoning_effort: profile.reasoning_effort.clone(),
                    role_file: profile.role_file.clone(),
                    instructions,
                    role_source,
                },
            ))
        })
        .collect()
}

fn profile_launch_summary(profile: &ResolvedAgentProfile) -> Value {
    match profile.launch {
        AgentLaunchMode::Bound => json!({
            "applicable": false,
            "mode": "bound",
        }),
        AgentLaunchMode::Runtime => json!({
            "applicable": true,
            "mode": "runtime",
            "runtime": profile.runtime,
            "model": profile.model,
            "reasoning_effort": profile.reasoning_effort,
        }),
    }
}

fn read_role(workspace: &SecureWorkspace, relative: &Path) -> Result<(String, String), CliError> {
    let mut file = workspace.open_regular_relative(relative)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|error| CliError::io("read role", &workspace.display().join(relative), &error))?;
    Ok((contents, relative.display().to_string()))
}
