use std::path::Path;

use serde_json::json;

use crate::config::{CONFIG_TEMPLATE, IMPLEMENTATION_ROLE_TEMPLATE, PRIMARY_ROLE_TEMPLATE};
use crate::output::{CommandResult, Success};
use crate::secure_fs::{SecureDir, SecureWorkspace};

const LOCAL_IGNORE: &str = ".agent-supervisor/config.local.toml";
const RUNTIME_IGNORE: &str = ".agent-supervisor/runtime/";

struct ProjectFile {
    relative_path: &'static str,
    file_name: &'static str,
    contents: &'static str,
    parent: ProjectFileParent,
}

enum ProjectFileParent {
    Agent,
    Roles,
}

const PROJECT_FILES: &[ProjectFile] = &[
    ProjectFile {
        relative_path: ".agent-supervisor/config.toml",
        file_name: "config.toml",
        contents: CONFIG_TEMPLATE,
        parent: ProjectFileParent::Agent,
    },
    ProjectFile {
        relative_path: ".agent-supervisor/roles/primary-orchestrator.md",
        file_name: "primary-orchestrator.md",
        contents: PRIMARY_ROLE_TEMPLATE,
        parent: ProjectFileParent::Roles,
    },
    ProjectFile {
        relative_path: ".agent-supervisor/roles/implementation-orchestrator.md",
        file_name: "implementation-orchestrator.md",
        contents: IMPLEMENTATION_ROLE_TEMPLATE,
        parent: ProjectFileParent::Roles,
    },
];

pub(crate) fn initialize(root: &Path) -> CommandResult {
    let workspace = SecureWorkspace::open(root)?;
    let agent_dir = workspace.root().ensure_dir(".agent-supervisor")?;
    let roles_dir = agent_dir.ensure_dir("roles")?;
    let runtime_dir = agent_dir.ensure_dir("runtime")?;
    let _lock = runtime_dir.lock_file("init.lock")?;

    let mut created = Vec::new();
    let mut preserved = Vec::new();
    for project_file in PROJECT_FILES {
        let parent = match project_file.parent {
            ProjectFileParent::Agent => &agent_dir,
            ProjectFileParent::Roles => &roles_dir,
        };
        if write_project_file(parent, project_file)? {
            created.push(project_file.relative_path);
        } else {
            preserved.push(project_file.relative_path);
        }
    }

    let ignore_added = workspace
        .root()
        .update_ignore(".gitignore", &[LOCAL_IGNORE, RUNTIME_IGNORE])?;
    let changed = !created.is_empty() || !ignore_added.is_empty();
    let human = if changed {
        format!(
            "initialized Agent Supervisor in {} (created {}, preserved {}, added {} ignore entries)",
            workspace.display().display(),
            created.len(),
            preserved.len(),
            ignore_added.len()
        )
    } else {
        format!(
            "Agent Supervisor is already initialized in {}; project-owned files were preserved",
            workspace.display().display()
        )
    };

    Ok(Success {
        human,
        data: json!({
            "workspace": workspace.display(),
            "changed": changed,
            "created": created,
            "preserved": preserved,
            "ignore_entries_added": ignore_added,
        }),
    })
}

fn write_project_file(
    parent: &SecureDir,
    project_file: &ProjectFile,
) -> Result<bool, crate::output::CliError> {
    parent.create_regular_if_missing(project_file.file_name, project_file.contents)
}
