use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use agsv_protocol::WorkspaceId;
use sha2::{Digest, Sha256};

use crate::ControlError;

/// Canonical repository identity used to scope durable state.
#[derive(Clone, Debug)]
pub struct WorkspaceIdentity {
    root: PathBuf,
    git_common_dir: PathBuf,
    workspace_id: WorkspaceId,
    hash: String,
}

impl WorkspaceIdentity {
    /// Discovers a canonical Git workspace and its shared common directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is not a readable Git workspace.
    pub fn discover(path: &Path) -> Result<Self, ControlError> {
        let supplied = fs::canonicalize(path)
            .map_err(|error| ControlError::io("canonicalize workspace", path, &error))?;
        let root = git_path(&supplied, &["rev-parse", "--show-toplevel"])?;
        let root = fs::canonicalize(&root)
            .map_err(|error| ControlError::io("canonicalize Git workspace", &root, &error))?;
        let common = git_path(&root, &["rev-parse", "--git-common-dir"])?;
        let common = if common.is_absolute() {
            common
        } else {
            root.join(common)
        };
        let git_common_dir = fs::canonicalize(&common).map_err(|error| {
            ControlError::io("canonicalize Git common directory", &common, &error)
        })?;
        let mut hasher = Sha256::new();
        hasher.update(root.as_os_str().as_encoded_bytes());
        hasher.update([0]);
        hasher.update(git_common_dir.as_os_str().as_encoded_bytes());
        let hash = hex_bytes(&hasher.finalize());
        let workspace_id =
            WorkspaceId::new(format!("ws-{}", &hash[..24])).map_err(ControlError::protocol)?;
        Ok(Self {
            root,
            git_common_dir,
            workspace_id,
            hash,
        })
    }

    /// Builds a deterministic read-only configuration identity for a directory
    /// that may not have been initialized as a Git repository yet.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be canonicalized.
    pub fn for_configuration(path: &Path) -> Result<Self, ControlError> {
        if let Ok(identity) = Self::discover(path) {
            return Ok(identity);
        }
        let root = fs::canonicalize(path)
            .map_err(|error| ControlError::io("canonicalize workspace", path, &error))?;
        let mut hasher = Sha256::new();
        hasher.update(root.as_os_str().as_encoded_bytes());
        hasher.update([0]);
        hasher.update(root.as_os_str().as_encoded_bytes());
        let hash = hex_bytes(&hasher.finalize());
        let workspace_id =
            WorkspaceId::new(format!("ws-{}", &hash[..24])).map_err(ControlError::protocol)?;
        Ok(Self {
            root: root.clone(),
            git_common_dir: root,
            workspace_id,
            hash,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn git_common_dir(&self) -> &Path {
        &self.git_common_dir
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }
}

pub(crate) fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    hex_bytes(&Sha256::digest(bytes.as_ref()))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Resolves the OS user-state location without creating it.
///
/// # Errors
///
/// Returns an error when no supported user-state base is available or an
/// explicit override is not absolute.
pub fn default_state_directory(identity: &WorkspaceIdentity) -> Result<PathBuf, ControlError> {
    let base = if let Some(path) = std::env::var_os("AGSV_STATE_HOME") {
        PathBuf::from(path)
    } else if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(path).join("agent-supervisor")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("agent-supervisor")
    } else {
        return Err(ControlError::new(
            "state_directory_unavailable",
            "could not resolve an OS user state directory; set AGSV_STATE_HOME",
        ));
    };
    if !base.is_absolute() {
        return Err(
            ControlError::new("unsafe_path", "AGSV state home must be an absolute path")
                .with_details(serde_json::json!({ "path": base })),
        );
    }
    Ok(base.join("workspaces").join(identity.hash()))
}

fn git_path(root: &Path, args: &[&str]) -> Result<PathBuf, ControlError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| ControlError::io("run git", root, &error))?;
    if !output.status.success() {
        return Err(ControlError::new(
            "not_a_git_workspace",
            format!(
                "Git workspace discovery failed for {}: {}",
                root.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if value.is_empty() {
        return Err(ControlError::new(
            "invalid_git_output",
            "Git workspace discovery returned an empty path",
        ));
    }
    Ok(PathBuf::from(value))
}
