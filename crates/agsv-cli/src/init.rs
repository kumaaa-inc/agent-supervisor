use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use serde_json::json;

use crate::cli::ConfigCommand;
use crate::output::{CliError, CommandResult, Success};

const CONFIG_TEMPLATE: &str = include_str!("../../../templates/config.toml");
const PRIMARY_ROLE_TEMPLATE: &str =
    include_str!("../../../templates/roles/primary-orchestrator.md");
const IMPLEMENTATION_ROLE_TEMPLATE: &str =
    include_str!("../../../templates/roles/implementation-orchestrator.md");
const LOCAL_IGNORE: &str = ".agent-supervisor/config.local.toml";
const RUNTIME_IGNORE: &str = ".agent-supervisor/runtime/";

struct ProjectFile {
    relative_path: &'static str,
    contents: &'static str,
}

const PROJECT_FILES: &[ProjectFile] = &[
    ProjectFile {
        relative_path: ".agent-supervisor/config.toml",
        contents: CONFIG_TEMPLATE,
    },
    ProjectFile {
        relative_path: ".agent-supervisor/roles/primary-orchestrator.md",
        contents: PRIMARY_ROLE_TEMPLATE,
    },
    ProjectFile {
        relative_path: ".agent-supervisor/roles/implementation-orchestrator.md",
        contents: IMPLEMENTATION_ROLE_TEMPLATE,
    },
];

pub(crate) fn initialize(root: &Path) -> CommandResult {
    ensure_workspace(root)?;

    let roles_dir = root.join(".agent-supervisor/roles");
    fs::create_dir_all(&roles_dir)
        .map_err(|error| CliError::io("create directory", &roles_dir, &error))?;

    let mut created = Vec::new();
    let mut preserved = Vec::new();
    for project_file in PROJECT_FILES {
        let path = root.join(project_file.relative_path);
        if write_if_missing(&path, project_file.contents)? {
            created.push(project_file.relative_path);
        } else {
            preserved.push(project_file.relative_path);
        }
    }

    let ignore_added = append_ignore_entries(root)?;
    let changed = !created.is_empty() || !ignore_added.is_empty();
    let human = if changed {
        format!(
            "initialized Agent Supervisor in {} (created {}, preserved {}, added {} ignore entries)",
            root.display(),
            created.len(),
            preserved.len(),
            ignore_added.len()
        )
    } else {
        format!(
            "Agent Supervisor is already initialized in {}; project-owned files were preserved",
            root.display()
        )
    };

    Ok(Success {
        human,
        data: json!({
            "workspace": root,
            "changed": changed,
            "created": created,
            "preserved": preserved,
            "ignore_entries_added": ignore_added,
        }),
    })
}

pub(crate) fn config(root: &Path, command: &ConfigCommand) -> CommandResult {
    match command {
        ConfigCommand::Show => show_config(root),
        ConfigCommand::Validate => validate_config(root),
    }
}

fn ensure_workspace(root: &Path) -> Result<(), CliError> {
    match fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(CliError::invalid_config(
            format!("workspace path is not a directory: {}", root.display()),
            json!({ "workspace": root }),
        )),
        Err(error) => Err(CliError::io("inspect workspace", root, &error)),
    }
}

fn write_if_missing(path: &Path, contents: &str) -> Result<bool, CliError> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(contents.as_bytes())
                .map_err(|error| CliError::io("write", path, &error))?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(CliError::io("create", path, &error)),
    }
}

fn append_ignore_entries(root: &Path) -> Result<Vec<&'static str>, CliError> {
    let path = root.join(".gitignore");
    let existing = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(CliError::io("read", &path, &error)),
    };
    let entries = [LOCAL_IGNORE, RUNTIME_IGNORE];
    let missing = entries
        .into_iter()
        .filter(|entry| {
            !existing
                .lines()
                .any(|line| line.trim_end_matches('\r') == *entry)
        })
        .collect::<Vec<_>>();

    if missing.is_empty() {
        return Ok(missing);
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| CliError::io("open for append", &path, &error))?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(file).map_err(|error| CliError::io("append", &path, &error))?;
    }
    for entry in &missing {
        writeln!(file, "{entry}").map_err(|error| CliError::io("append", &path, &error))?;
    }
    Ok(missing)
}

fn show_config(root: &Path) -> CommandResult {
    let tracked_path = root.join(".agent-supervisor/config.toml");
    let tracked_source = read_config(&tracked_path)?;
    let tracked = parse_config(&tracked_path, &tracked_source)?;
    let local_path = root.join(".agent-supervisor/config.local.toml");
    let local = match fs::read_to_string(&local_path) {
        Ok(source) => Some((source.clone(), parse_config(&local_path, &source)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(CliError::io("read", &local_path, &error)),
    };

    let human = local.as_ref().map_or_else(
        || tracked_source.clone(),
        |(source, _)| format!("{tracked_source}\n# config.local.toml\n{source}"),
    );
    let local_data = local.map(|(_, value)| {
        json!({
            "path": local_path,
            "config": value,
        })
    });

    Ok(Success {
        human,
        data: json!({
            "tracked": {
                "path": tracked_path,
                "config": tracked,
            },
            "local": local_data,
        }),
    })
}

fn validate_config(root: &Path) -> CommandResult {
    let tracked_path = root.join(".agent-supervisor/config.toml");
    let tracked_source = read_config(&tracked_path)?;
    let tracked = parse_config(&tracked_path, &tracked_source)?;

    let schema_version = tracked
        .get("schema_version")
        .and_then(toml::Value::as_integer);
    if schema_version != Some(1) {
        return Err(CliError::invalid_config(
            "config schema_version must be 1",
            json!({ "path": tracked_path, "schema_version": schema_version }),
        ));
    }

    let primary_role = config_role_path(&tracked, "primary_role")?;
    let implementation_role = config_role_path(&tracked, "implementation_role")?;
    let role_paths = [primary_role, implementation_role].map(|relative| root.join(relative));
    for path in &role_paths {
        if !path.is_file() {
            return Err(CliError::invalid_config(
                format!("configured role file does not exist: {}", path.display()),
                json!({ "path": path }),
            ));
        }
    }

    let local_path = root.join(".agent-supervisor/config.local.toml");
    let local_validated = match fs::read_to_string(&local_path) {
        Ok(source) => {
            parse_config(&local_path, &source)?;
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(CliError::io("read", &local_path, &error)),
    };

    Ok(Success {
        human: format!("configuration is valid: {}", tracked_path.display()),
        data: json!({
            "valid": true,
            "schema_version": 1,
            "tracked": tracked_path,
            "local_validated": local_validated,
            "roles": role_paths,
        }),
    })
}

fn read_config(path: &Path) -> Result<String, CliError> {
    fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CliError::invalid_config(
                format!("configuration is not initialized: {}", path.display()),
                json!({ "path": path }),
            )
        } else {
            CliError::io("read", path, &error)
        }
    })
}

fn parse_config(path: &Path, source: &str) -> Result<toml::Value, CliError> {
    toml::from_str(source).map_err(|error| {
        CliError::invalid_config(
            format!("invalid TOML in {}: {error}", path.display()),
            json!({ "path": path, "parse_error": error.to_string() }),
        )
    })
}

fn config_role_path<'a>(config: &'a toml::Value, key: &str) -> Result<&'a str, CliError> {
    config
        .get("workspace")
        .and_then(|workspace| workspace.get(key))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            CliError::invalid_config(
                format!("config workspace.{key} must be a path string"),
                json!({ "key": format!("workspace.{key}") }),
            )
        })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let serial = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("agsv-init-unit-{}-{serial}", std::process::id()));
            fs::create_dir(&path).expect("test directory should be created");
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("test directory should be removed");
        }
    }

    #[test]
    fn second_init_preserves_project_files() {
        let root = TestDir::new();
        let first = initialize(&root.0).expect("first init should succeed");
        assert_eq!(first.data["created"].as_array().map(Vec::len), Some(3));

        let role_path = root
            .0
            .join(".agent-supervisor/roles/primary-orchestrator.md");
        fs::write(&role_path, "project-owned role\n").expect("role should be editable");
        let second = initialize(&root.0).expect("second init should succeed");

        assert_eq!(
            fs::read_to_string(role_path).unwrap(),
            "project-owned role\n"
        );
        assert_eq!(second.data["changed"], false);
        assert_eq!(second.data["preserved"].as_array().map(Vec::len), Some(3));
    }

    #[test]
    fn ignore_entries_are_appended_once_and_keep_existing_content() {
        let root = TestDir::new();
        let ignore = root.0.join(".gitignore");
        fs::write(&ignore, "target").expect("fixture should be written");

        initialize(&root.0).expect("init should succeed");
        initialize(&root.0).expect("repeat init should succeed");

        assert_eq!(
            fs::read_to_string(ignore).unwrap(),
            "target\n.agent-supervisor/config.local.toml\n.agent-supervisor/runtime/\n"
        );
    }
}
