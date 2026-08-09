use std::collections::{BTreeMap, BTreeSet};
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
const DEFAULT_PRIMARY_PROFILE: &str = "primary";
const DEFAULT_TEAM_PROFILE: &str = "implementation";
pub(crate) const HUMAN_FACING_PRIMARY_CAPABILITY: &str = "human_facing_primary";
pub(crate) const IMPLEMENTATION_EXECUTION_CAPABILITY: &str = "implementation_execution";

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConfigSource {
    Builtin,
    Project,
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
    session_layout: SessionLayoutConfig,
    policy: PolicyConfig,
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
            reasoning_effort: "max".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentProfileConfig {
    role: String,
    #[serde(default)]
    capabilities: BTreeSet<String>,
    #[serde(alias = "provider")]
    runtime: String,
    model: String,
    reasoning_effort: String,
    role_file: PathBuf,
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

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ConfigOverride {
    schema_version: Option<u32>,
    workspace: Option<WorkspaceOverride>,
    runtime: Option<RuntimeOverride>,
    implementation: Option<ImplementationOverride>,
    agent_profiles: BTreeMap<String, AgentProfileOverride>,
    team_profiles: BTreeMap<String, TeamProfileOverride>,
    session_layout: Option<SessionLayoutOverride>,
    policy: Option<PolicyOverride>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct WorkspaceOverride {
    primary_role: Option<PathBuf>,
    implementation_role: Option<PathBuf>,
    primary_profile: Option<String>,
    default_team_profile: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuntimeOverride {
    backend: Option<String>,
    state_directory: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ImplementationOverride {
    runtime: Option<String>,
    model: Option<String>,
    reasoning_effort: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AgentProfileOverride {
    role: Option<String>,
    capabilities: Option<BTreeSet<String>>,
    #[serde(alias = "provider")]
    runtime: Option<String>,
    model: Option<String>,
    reasoning_effort: Option<String>,
    role_file: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TeamProfileOverride {
    actor_profile: Option<String>,
    desired_instances: Option<u32>,
    assignment_policy: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SessionLayoutOverride {
    max_panes_per_tab: Option<u16>,
    place_first_implementation_with_primary: Option<bool>,
    tab_label_strategy: Option<TabLabelStrategy>,
    pane_label_template: Option<String>,
    split_direction: Option<SplitDirection>,
    focus_new_sessions: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PolicyOverride {
    primary_lease_seconds: Option<u32>,
    actor_heartbeat_seconds: Option<u32>,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedAgentProfile {
    pub(crate) name: String,
    pub(crate) role: String,
    pub(crate) capabilities: BTreeSet<String>,
    pub(crate) runtime: String,
    pub(crate) model: String,
    pub(crate) reasoning_effort: String,
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
    agent_profiles: BTreeMap<String, ResolvedAgentProfile>,
    team_profiles: BTreeMap<String, ResolvedTeamProfile>,
    primary_profile_name: String,
    default_team_profile_name: String,
    persist_profile_snapshots: bool,
    local_override: bool,
}

impl LoadedConfig {
    pub(crate) const fn source_name(&self) -> &'static str {
        match self.source {
            ConfigSource::Builtin => "builtin",
            ConfigSource::Project => "project",
        }
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
                        "runtime": profile.runtime,
                        "model": profile.model,
                        "reasoning_effort": profile.reasoning_effort,
                        "role_file": profile.role_file,
                        "role_source": profile.role_source,
                        "role_bytes": profile.instructions.len(),
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        Ok(json!({
            "source": self.source,
            "local_override": self.local_override,
            "resolved_state_path": state_directory,
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
            .map(|(name, profile)| {
                (
                    name.clone(),
                    agsv_control::ActorProfileSettings {
                        name: profile.name.clone(),
                        role: profile.role.clone(),
                        capabilities: profile.capabilities.clone(),
                        runtime: profile.runtime.clone(),
                        model: profile.model.clone(),
                        reasoning_effort: profile.reasoning_effort.clone(),
                        role_file: profile.role_file.clone(),
                        role_instructions: profile.instructions.clone(),
                        role_source: profile.role_source.clone(),
                    },
                )
            })
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

pub(crate) fn execute(root: &Path, command: &ConfigCommand) -> CommandResult {
    let loaded = load(root)?;
    match command {
        ConfigCommand::Show => show(root, &loaded),
        ConfigCommand::Validate => validate(root, &loaded),
    }
}

pub(crate) fn load(root: &Path) -> Result<LoadedConfig, CliError> {
    let workspace = SecureWorkspace::open(root)?;
    let agent_dir = workspace.root().open_dir_optional(".agent-supervisor")?;
    let tracked = read_optional(agent_dir.as_ref(), "config.toml")?;
    let local = read_optional(agent_dir.as_ref(), "config.local.toml")?;

    let (mut config, source, profile_tables_declared) = if let Some((path, contents)) = tracked {
        let profile_tables_declared = profile_tables_declared(&path, &contents)?;
        (
            parse_toml::<ProjectConfig>(&path, &contents)?,
            ConfigSource::Project,
            profile_tables_declared,
        )
    } else {
        let mut defaults =
            parse_toml::<ProjectConfig>(Path::new("<builtin config>"), CONFIG_TEMPLATE)?;
        defaults.runtime.state_directory = PathBuf::from(BUILTIN_STATE_SENTINEL);
        (defaults, ConfigSource::Builtin, true)
    };

    let legacy_profiles = !profile_tables_declared;
    if legacy_profiles {
        synthesize_legacy_profiles(&mut config);
    }
    let bridge_legacy_overrides = legacy_profiles || matches!(source, ConfigSource::Builtin);

    let mut persist_profile_snapshots = matches!(source, ConfigSource::Project) && !legacy_profiles;
    let mut role_overrides = BTreeSet::new();
    let mut state_override = false;
    if let Some((path, contents)) = local.as_ref() {
        let overrides = parse_toml::<ConfigOverride>(path, contents)?;
        persist_profile_snapshots |=
            !overrides.agent_profiles.is_empty() || !overrides.team_profiles.is_empty();
        if bridge_legacy_overrides {
            if overrides
                .workspace
                .as_ref()
                .is_some_and(|value| value.primary_role.is_some())
            {
                role_overrides.insert(DEFAULT_PRIMARY_PROFILE.to_owned());
            }
            if overrides
                .workspace
                .as_ref()
                .is_some_and(|value| value.implementation_role.is_some())
            {
                role_overrides.insert(DEFAULT_TEAM_PROFILE.to_owned());
            }
        }
        role_overrides.extend(
            overrides
                .agent_profiles
                .iter()
                .filter(|(_, profile)| profile.role_file.is_some())
                .map(|(name, _)| name.clone()),
        );
        state_override = overrides
            .runtime
            .as_ref()
            .is_some_and(|value| value.state_directory.is_some());
        apply_override(&mut config, overrides, bridge_legacy_overrides)?;
    }

    validate_semantics(&config)?;
    if !matches!(source, ConfigSource::Builtin) || state_override {
        workspace.check_directory_relative(&config.runtime.state_directory)?;
    }

    let agent_profiles = load_agent_profiles(&workspace, &config, source, &role_overrides)?;
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
    Ok(LoadedConfig {
        source,
        config,
        agent_profiles,
        team_profiles,
        primary_profile_name,
        default_team_profile_name,
        persist_profile_snapshots,
        local_override: local.is_some(),
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
        session_layout,
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
                    .clone_from(&runtime);
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
                    .clone_from(&model);
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
                    .clone_from(&reasoning_effort);
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
        if let Some(runtime) = profile_override.runtime {
            profile.runtime = runtime;
        }
        if let Some(model) = profile_override.model {
            profile.model = model;
        }
        if let Some(reasoning_effort) = profile_override.reasoning_effort {
            profile.reasoning_effort = reasoning_effort;
        }
        if let Some(role_file) = profile_override.role_file {
            profile.role_file = role_file;
        }
        return Ok(());
    }

    let AgentProfileOverride {
        role,
        capabilities,
        runtime,
        model,
        reasoning_effort,
        role_file,
    } = profile_override;
    let missing = [
        ("role", role.is_none()),
        ("runtime", runtime.is_none()),
        ("model", model.is_none()),
        ("reasoning_effort", reasoning_effort.is_none()),
        ("role_file", role_file.is_none()),
    ]
    .into_iter()
    .filter_map(|(field, absent)| absent.then_some(field))
    .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(CliError::invalid_config(
            format!(
                "local override for new agent profile `{name}` is missing required fields: {}",
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
            runtime: runtime.expect("checked above"),
            model: model.expect("checked above"),
            reasoning_effort: reasoning_effort.expect("checked above"),
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

fn synthesize_legacy_profiles(config: &mut ProjectConfig) {
    let runtime = config.implementation.runtime.clone();
    let model = config.implementation.model.clone();
    let reasoning_effort = config.implementation.reasoning_effort.clone();
    config.agent_profiles.insert(
        DEFAULT_PRIMARY_PROFILE.to_owned(),
        AgentProfileConfig {
            role: "primary".to_owned(),
            capabilities: BTreeSet::from([HUMAN_FACING_PRIMARY_CAPABILITY.to_owned()]),
            runtime: runtime.clone(),
            model: model.clone(),
            reasoning_effort: reasoning_effort.clone(),
            role_file: config.workspace.primary_role.clone(),
        },
    );
    config.agent_profiles.insert(
        DEFAULT_TEAM_PROFILE.to_owned(),
        AgentProfileConfig {
            role: "implementation".to_owned(),
            capabilities: BTreeSet::from([IMPLEMENTATION_EXECUTION_CAPABILITY.to_owned()]),
            runtime,
            model,
            reasoning_effort,
            role_file: config.workspace.implementation_role.clone(),
        },
    );
    config.team_profiles.insert(
        DEFAULT_TEAM_PROFILE.to_owned(),
        TeamProfileConfig {
            actor_profile: DEFAULT_TEAM_PROFILE.to_owned(),
            desired_instances: 1,
            assignment_policy: "first_healthy".to_owned(),
        },
    );
}

fn validate_semantics(config: &ProjectConfig) -> Result<(), CliError> {
    validate_legacy_semantics(config)?;
    validate_agent_profiles(config)?;
    validate_team_profiles(config)?;
    validate_primary_profile_selection(config)?;
    validate_default_team_profile_selection(config)
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
    validate_runtime_field("implementation.runtime", &config.implementation.runtime)?;
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
        validate_runtime_field(&format!("agent_profiles.{name}.runtime"), &profile.runtime)?;
        validate_text_field(&format!("agent_profiles.{name}.model"), &profile.model, 256)?;
        validate_text_field(
            &format!("agent_profiles.{name}.reasoning_effort"),
            &profile.reasoning_effort,
            128,
        )?;
        validate_relative_path(
            &format!("agent_profiles.{name}.role_file"),
            &profile.role_file,
        )?;
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
        if !config.agent_profiles.contains_key(&profile.actor_profile) {
            return Err(CliError::invalid_config(
                format!(
                    "team_profiles.{name}.actor_profile references unknown agent profile `{}`",
                    profile.actor_profile
                ),
                json!({
                    "field": format!("team_profiles.{name}.actor_profile"),
                    "actor_profile": profile.actor_profile,
                    "available_agent_profiles": config.agent_profiles.keys().collect::<Vec<_>>(),
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
    source: ConfigSource,
    role_overrides: &BTreeSet<String>,
) -> Result<BTreeMap<String, ResolvedAgentProfile>, CliError> {
    config
        .agent_profiles
        .iter()
        .map(|(name, profile)| {
            let embedded = matches!(source, ConfigSource::Builtin)
                && !role_overrides.contains(name)
                && ((name == DEFAULT_PRIMARY_PROFILE
                    && profile.role_file == config.workspace.primary_role)
                    || (name == DEFAULT_TEAM_PROFILE
                        && profile.role_file == config.workspace.implementation_role));
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

fn read_role(workspace: &SecureWorkspace, relative: &Path) -> Result<(String, String), CliError> {
    let mut file = workspace.open_regular_relative(relative)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|error| CliError::io("read role", &workspace.display().join(relative), &error))?;
    Ok((contents, relative.display().to_string()))
}
