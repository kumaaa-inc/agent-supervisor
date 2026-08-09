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

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConfigSource {
    Builtin,
    Project,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectConfig {
    schema_version: u32,
    workspace: WorkspaceConfig,
    runtime: RuntimeConfig,
    #[serde(default)]
    implementation: ImplementationConfig,
    policy: PolicyConfig,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceConfig {
    primary_role: PathBuf,
    implementation_role: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeBackend {
    Herdr,
    Fake,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeConfig {
    backend: RuntimeBackend,
    state_directory: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
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
    policy: Option<PolicyOverride>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct WorkspaceOverride {
    primary_role: Option<PathBuf>,
    implementation_role: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuntimeOverride {
    backend: Option<RuntimeBackend>,
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
struct PolicyOverride {
    primary_lease_seconds: Option<u32>,
    actor_heartbeat_seconds: Option<u32>,
}

struct RoleInstructions {
    primary: String,
    implementation: String,
    primary_source: String,
    implementation_source: String,
}

pub(crate) struct LoadedConfig {
    source: ConfigSource,
    config: ProjectConfig,
    roles: RoleInstructions,
    local_override: bool,
}

impl LoadedConfig {
    pub(crate) const fn source_name(&self) -> &'static str {
        match self.source {
            ConfigSource::Builtin => "builtin",
            ConfigSource::Project => "project",
        }
    }

    pub(crate) fn primary_role(&self) -> &str {
        &self.roles.primary
    }

    pub(crate) fn implementation_role(&self) -> &str {
        &self.roles.implementation
    }

    pub(crate) fn summary(&self, root: &Path) -> Result<Value, CliError> {
        let state_directory = self.resolved_state_directory(root)?;
        Ok(json!({
            "source": self.source,
            "local_override": self.local_override,
            "resolved_state_path": state_directory,
            "config": self.config,
            "roles": {
                "primary": {
                    "source": self.roles.primary_source,
                    "bytes": self.primary_role().len(),
                },
                "implementation": {
                    "source": self.roles.implementation_source,
                    "bytes": self.implementation_role().len(),
                },
            },
        }))
    }

    pub(crate) fn control_settings(
        &self,
        root: &Path,
    ) -> Result<agsv_control::ControlSettings, CliError> {
        let backend = match self.config.runtime.backend {
            RuntimeBackend::Herdr => agsv_control::BackendKind::Herdr,
            RuntimeBackend::Fake => agsv_control::BackendKind::Fake,
        };
        Ok(agsv_control::ControlSettings {
            workspace: root.to_path_buf(),
            state_directory: self.resolved_state_directory(root)?,
            config_source: self.source_name().to_owned(),
            primary_role: self.primary_role().to_owned(),
            implementation_role: self.implementation_role().to_owned(),
            backend,
            model: self.config.implementation.model.clone(),
            reasoning_effort: self.config.implementation.reasoning_effort.clone(),
        })
    }

    fn resolved_state_directory(&self, root: &Path) -> Result<PathBuf, CliError> {
        let identity = agsv_control::WorkspaceIdentity::for_configuration(root)
            .map_err(CliError::from_control)?;
        if self.config.runtime.state_directory == Path::new(BUILTIN_STATE_SENTINEL) {
            agsv_control::default_state_directory(&identity).map_err(CliError::from_control)
        } else {
            Ok(identity.root().join(&self.config.runtime.state_directory))
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

    let (mut config, source) = if let Some((path, contents)) = tracked {
        (
            parse_toml::<ProjectConfig>(&path, &contents)?,
            ConfigSource::Project,
        )
    } else {
        let mut defaults =
            parse_toml::<ProjectConfig>(Path::new("<builtin config>"), CONFIG_TEMPLATE)?;
        defaults.runtime.state_directory = PathBuf::from(BUILTIN_STATE_SENTINEL);
        (defaults, ConfigSource::Builtin)
    };

    let mut role_override = (false, false);
    let mut state_override = false;
    if let Some((path, contents)) = local.as_ref() {
        let overrides = parse_toml::<ConfigOverride>(path, contents)?;
        role_override = (
            overrides
                .workspace
                .as_ref()
                .is_some_and(|value| value.primary_role.is_some()),
            overrides
                .workspace
                .as_ref()
                .is_some_and(|value| value.implementation_role.is_some()),
        );
        state_override = overrides
            .runtime
            .as_ref()
            .is_some_and(|value| value.state_directory.is_some());
        apply_override(&mut config, overrides);
    }

    validate_semantics(&config)?;
    if !matches!(source, ConfigSource::Builtin) || state_override {
        workspace.check_directory_relative(&config.runtime.state_directory)?;
    }

    let roles = load_roles(&workspace, &config, source, role_override)?;
    Ok(LoadedConfig {
        source,
        config,
        roles,
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

fn apply_override(config: &mut ProjectConfig, overrides: ConfigOverride) {
    if let Some(schema_version) = overrides.schema_version {
        config.schema_version = schema_version;
    }
    if let Some(workspace) = overrides.workspace {
        if let Some(primary_role) = workspace.primary_role {
            config.workspace.primary_role = primary_role;
        }
        if let Some(implementation_role) = workspace.implementation_role {
            config.workspace.implementation_role = implementation_role;
        }
    }
    if let Some(runtime) = overrides.runtime {
        if let Some(backend) = runtime.backend {
            config.runtime.backend = backend;
        }
        if let Some(state_directory) = runtime.state_directory {
            config.runtime.state_directory = state_directory;
        }
    }
    if let Some(implementation) = overrides.implementation {
        if let Some(runtime) = implementation.runtime {
            config.implementation.runtime = runtime;
        }
        if let Some(model) = implementation.model {
            config.implementation.model = model;
        }
        if let Some(reasoning_effort) = implementation.reasoning_effort {
            config.implementation.reasoning_effort = reasoning_effort;
        }
    }
    if let Some(policy) = overrides.policy {
        if let Some(primary_lease_seconds) = policy.primary_lease_seconds {
            config.policy.primary_lease_seconds = primary_lease_seconds;
        }
        if let Some(actor_heartbeat_seconds) = policy.actor_heartbeat_seconds {
            config.policy.actor_heartbeat_seconds = actor_heartbeat_seconds;
        }
    }
}

fn validate_semantics(config: &ProjectConfig) -> Result<(), CliError> {
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
    if config.implementation.runtime != "codex" {
        return Err(CliError::invalid_config(
            "implementation.runtime must be `codex` in v0.1",
            json!({ "runtime": config.implementation.runtime }),
        ));
    }
    if config.implementation.model.trim().is_empty()
        || config.implementation.reasoning_effort.trim().is_empty()
    {
        return Err(CliError::invalid_config(
            "implementation model and reasoning_effort must be non-empty",
            json!({}),
        ));
    }
    Ok(())
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

fn load_roles(
    workspace: &SecureWorkspace,
    config: &ProjectConfig,
    source: ConfigSource,
    role_override: (bool, bool),
) -> Result<RoleInstructions, CliError> {
    let (primary, primary_source) = if matches!(source, ConfigSource::Builtin) && !role_override.0 {
        (PRIMARY_ROLE_TEMPLATE.to_owned(), "builtin".to_owned())
    } else {
        read_role(workspace, &config.workspace.primary_role)?
    };
    let (implementation, implementation_source) =
        if matches!(source, ConfigSource::Builtin) && !role_override.1 {
            (
                IMPLEMENTATION_ROLE_TEMPLATE.to_owned(),
                "builtin".to_owned(),
            )
        } else {
            read_role(workspace, &config.workspace.implementation_role)?
        };
    Ok(RoleInstructions {
        primary,
        implementation,
        primary_source,
        implementation_source,
    })
}

fn read_role(workspace: &SecureWorkspace, relative: &Path) -> Result<(String, String), CliError> {
    let mut file = workspace.open_regular_relative(relative)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|error| CliError::io("read role", &workspace.display().join(relative), &error))?;
    Ok((contents, relative.display().to_string()))
}
