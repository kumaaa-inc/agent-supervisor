use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static GIT_COMPARISON_CALLS: Cell<u64> = const { Cell::new(0) };
}

#[derive(Clone, Debug)]
pub(crate) struct BaseStalenessContext {
    git: PathBuf,
    repository: PathBuf,
    observed_at_ms: u64,
    target: TargetObservation,
}

#[derive(Clone, Debug)]
enum TargetObservation {
    Available {
        source: &'static str,
        branch: String,
        full_ref: String,
        head_sha: String,
        committed_at_ms: u64,
    },
    Unavailable {
        state: &'static str,
        source: &'static str,
        branch: Option<String>,
        reason: &'static str,
        detail: Option<String>,
    },
}

impl BaseStalenessContext {
    pub(crate) fn observe(
        git: &Path,
        repository: &Path,
        configured_branch: Option<&str>,
        observed_at_ms: u64,
    ) -> Self {
        let target = observe_target(git, repository, configured_branch);
        Self {
            git: git.to_path_buf(),
            repository: repository.to_path_buf(),
            observed_at_ms,
            target,
        }
    }

    pub(crate) fn target_report(&self) -> Value {
        match &self.target {
            TargetObservation::Available {
                source,
                branch,
                full_ref,
                head_sha,
                committed_at_ms,
            } => json!({
                "state": "available",
                "source": source,
                "branch": branch,
                "ref": full_ref,
                "head_sha": head_sha,
                "committed_at_ms": committed_at_ms,
                "observed_at_ms": self.observed_at_ms,
            }),
            TargetObservation::Unavailable {
                state,
                source,
                branch,
                reason,
                detail,
            } => json!({
                "state": state,
                "source": source,
                "branch": branch,
                "reason": reason,
                "detail": detail,
                "observed_at_ms": self.observed_at_ms,
            }),
        }
    }

    pub(crate) fn request_report(&self, base_sha: &str, candidate_sha: Option<&str>) -> Value {
        let TargetObservation::Available {
            head_sha,
            committed_at_ms: target_committed_at_ms,
            ..
        } = &self.target
        else {
            return json!({
                "state": "unavailable",
                "declared_base_sha": base_sha,
                "commits_behind": Value::Null,
                "behind_since_ms": Value::Null,
                "behind_for_ms": Value::Null,
                "overlap": candidate_unavailable_or_not_compared(candidate_sha, "comparison_target_unavailable"),
            });
        };

        let base_committed_at_ms = match commit_time_ms(&self.git, &self.repository, base_sha) {
            Ok(value) => value,
            Err(detail) => {
                return unavailable_report(
                    base_sha,
                    candidate_sha,
                    "declared_base_unavailable",
                    &detail,
                );
            }
        };
        if base_sha == head_sha {
            return json!({
                "state": "current",
                "declared_base_sha": base_sha,
                "base_committed_at_ms": base_committed_at_ms,
                "target_head_sha": head_sha,
                "target_committed_at_ms": target_committed_at_ms,
                "commits_behind": 0,
                "behind_since_ms": Value::Null,
                "behind_for_ms": 0,
                "duration_basis": "oldest_intervening_commit_timestamp",
                "overlap": overlap_report(
                    &self.git,
                    &self.repository,
                    base_sha,
                    head_sha,
                    candidate_sha,
                ),
            });
        }

        match is_ancestor(&self.git, &self.repository, base_sha, head_sha) {
            Ok(true) => self.behind_report(
                base_sha,
                head_sha,
                base_committed_at_ms,
                *target_committed_at_ms,
                candidate_sha,
            ),
            Ok(false) => match is_ancestor(&self.git, &self.repository, head_sha, base_sha) {
                Ok(true) => json!({
                    "state": "base_ahead",
                    "declared_base_sha": base_sha,
                    "base_committed_at_ms": base_committed_at_ms,
                    "target_head_sha": head_sha,
                    "target_committed_at_ms": target_committed_at_ms,
                    "commits_behind": Value::Null,
                    "behind_since_ms": Value::Null,
                    "behind_for_ms": Value::Null,
                    "overlap": candidate_unavailable_or_not_compared(candidate_sha, "declared_base_not_behind_target"),
                }),
                Ok(false) => json!({
                    "state": "diverged",
                    "declared_base_sha": base_sha,
                    "base_committed_at_ms": base_committed_at_ms,
                    "target_head_sha": head_sha,
                    "target_committed_at_ms": target_committed_at_ms,
                    "commits_behind": Value::Null,
                    "behind_since_ms": Value::Null,
                    "behind_for_ms": Value::Null,
                    "overlap": candidate_unavailable_or_not_compared(candidate_sha, "declared_base_diverged_from_target"),
                }),
                Err(detail) => {
                    unavailable_report(base_sha, candidate_sha, "relationship_unavailable", &detail)
                }
            },
            Err(detail) => {
                unavailable_report(base_sha, candidate_sha, "relationship_unavailable", &detail)
            }
        }
    }

    fn behind_report(
        &self,
        base_sha: &str,
        head_sha: &str,
        base_committed_at_ms: u64,
        target_committed_at_ms: u64,
        candidate_sha: Option<&str>,
    ) -> Value {
        let count = match rev_list_count(&self.git, &self.repository, base_sha, head_sha) {
            Ok(value) => value,
            Err(detail) => {
                return unavailable_report(
                    base_sha,
                    candidate_sha,
                    "behind_count_unavailable",
                    &detail,
                );
            }
        };
        let behind_since_ms =
            match oldest_intervening_commit_ms(&self.git, &self.repository, base_sha, head_sha) {
                Ok(value) => value,
                Err(detail) => {
                    return unavailable_report(
                        base_sha,
                        candidate_sha,
                        "behind_duration_unavailable",
                        &detail,
                    );
                }
            };
        let (behind_for_ms, duration_state) = match self.observed_at_ms.checked_sub(behind_since_ms)
        {
            Some(duration) => (Some(duration), "available"),
            None => (None, "commit_time_in_future"),
        };
        json!({
            "state": "behind",
            "declared_base_sha": base_sha,
            "base_committed_at_ms": base_committed_at_ms,
            "target_head_sha": head_sha,
            "target_committed_at_ms": target_committed_at_ms,
            "commits_behind": count,
            "behind_since_ms": behind_since_ms,
            "behind_for_ms": behind_for_ms,
            "duration_state": duration_state,
            "duration_basis": "oldest_intervening_commit_timestamp",
            "overlap": overlap_report(
                &self.git,
                &self.repository,
                base_sha,
                head_sha,
                candidate_sha,
            ),
        })
    }
}

fn observe_target(
    git: &Path,
    repository: &Path,
    configured_branch: Option<&str>,
) -> TargetObservation {
    let (source, branch, configured) = if let Some(branch) = configured_branch {
        ("configured", branch.to_owned(), true)
    } else {
        match git_stdout(
            git,
            repository,
            ["symbolic-ref", "--quiet", "--short", "HEAD"],
        ) {
            Ok(branch) if !branch.is_empty() => ("workspace_primary_branch", branch, false),
            Ok(_) => {
                return TargetObservation::Unavailable {
                    state: "not_configured",
                    source: "workspace_primary_branch",
                    branch: None,
                    reason: "primary_worktree_has_no_attached_branch",
                    detail: None,
                };
            }
            Err(detail) => {
                return TargetObservation::Unavailable {
                    state: "not_configured",
                    source: "workspace_primary_branch",
                    branch: None,
                    reason: "primary_worktree_has_no_attached_branch",
                    detail: Some(detail),
                };
            }
        }
    };
    let full_ref = format!("refs/heads/{branch}");
    let revision = format!("{full_ref}^{{commit}}");
    let head_sha = match git_stdout(
        git,
        repository,
        [
            "rev-parse",
            "--verify",
            "--end-of-options",
            revision.as_str(),
        ],
    ) {
        Ok(value) => value,
        Err(detail) => {
            if !configured {
                return TargetObservation::Unavailable {
                    state: "not_configured",
                    source,
                    branch: None,
                    reason: "primary_worktree_branch_is_unborn",
                    detail: Some(detail),
                };
            }
            return TargetObservation::Unavailable {
                state: "unavailable",
                source,
                branch: Some(branch),
                reason: "integration_branch_unresolved",
                detail: Some(detail),
            };
        }
    };
    let committed_at_ms = match commit_time_ms(git, repository, &head_sha) {
        Ok(value) => value,
        Err(detail) => {
            return TargetObservation::Unavailable {
                state: "unavailable",
                source,
                branch: Some(branch),
                reason: "integration_branch_commit_unavailable",
                detail: Some(detail),
            };
        }
    };
    TargetObservation::Available {
        source,
        branch,
        full_ref,
        head_sha,
        committed_at_ms,
    }
}

fn unavailable_report(
    base_sha: &str,
    candidate_sha: Option<&str>,
    reason: &'static str,
    detail: &str,
) -> Value {
    json!({
        "state": "unavailable",
        "reason": reason,
        "detail": detail,
        "declared_base_sha": base_sha,
        "commits_behind": Value::Null,
        "behind_since_ms": Value::Null,
        "behind_for_ms": Value::Null,
        "overlap": candidate_unavailable_or_not_compared(candidate_sha, reason),
    })
}

fn candidate_unavailable_or_not_compared(candidate_sha: Option<&str>, reason: &str) -> Value {
    match candidate_sha {
        None => json!({
            "state": "candidate_not_available",
            "reason": "request_has_no_candidate",
        }),
        Some(candidate_sha) => json!({
            "state": "not_comparable",
            "candidate_sha": candidate_sha,
            "reason": reason,
        }),
    }
}

fn overlap_report(
    git: &Path,
    repository: &Path,
    base_sha: &str,
    target_sha: &str,
    candidate_sha: Option<&str>,
) -> Value {
    let Some(candidate_sha) = candidate_sha else {
        return candidate_unavailable_or_not_compared(None, "request_has_no_candidate");
    };
    match is_ancestor(git, repository, base_sha, candidate_sha) {
        Ok(true) => {}
        Ok(false) => {
            return candidate_unavailable_or_not_compared(
                Some(candidate_sha),
                "candidate_not_descended_from_declared_base",
            );
        }
        Err(detail) => {
            return json!({
                "state": "not_comparable",
                "candidate_sha": candidate_sha,
                "reason": "candidate_relationship_unavailable",
                "detail": detail,
            });
        }
    }
    let candidate_paths =
        match candidate_touched_paths(git, repository, base_sha, candidate_sha, target_sha) {
            Ok(paths) => paths,
            Err(detail) => {
                return json!({
                    "state": "not_comparable",
                    "candidate_sha": candidate_sha,
                    "reason": "candidate_paths_unavailable",
                    "detail": detail,
                });
            }
        };
    let intervening_paths = match touched_paths(git, repository, base_sha, target_sha) {
        Ok(paths) => paths,
        Err(detail) => {
            return json!({
                "state": "not_comparable",
                "candidate_sha": candidate_sha,
                "reason": "intervening_paths_unavailable",
                "detail": detail,
            });
        }
    };
    let paths = candidate_paths
        .intersection(&intervening_paths)
        .cloned()
        .collect::<Vec<_>>();
    json!({
        "state": "comparable",
        "candidate_sha": candidate_sha,
        "touches_same_files": !paths.is_empty(),
        "shared_path_count": paths.len(),
        "shared_paths": paths,
        "path_basis": "candidate_exclusive_and_integration_commits_since_declared_base",
    })
}

fn is_ancestor(
    git: &Path,
    repository: &Path,
    ancestor: &str,
    descendant: &str,
) -> Result<bool, String> {
    let output = git_output(
        git,
        repository,
        ["merge-base", "--is-ancestor", ancestor, descendant],
    )?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(git_failure_detail(&output)),
    }
}

fn commit_time_ms(git: &Path, repository: &Path, sha: &str) -> Result<u64, String> {
    parse_seconds_ms(&git_stdout(
        git,
        repository,
        ["show", "-s", "--format=%ct", sha],
    )?)
}

fn rev_list_count(
    git: &Path,
    repository: &Path,
    base_sha: &str,
    target_sha: &str,
) -> Result<u64, String> {
    let range = format!("{base_sha}..{target_sha}");
    git_stdout(git, repository, ["rev-list", "--count", range.as_str()])?
        .parse::<u64>()
        .map_err(|error| format!("Git returned an invalid commit count: {error}"))
}

fn oldest_intervening_commit_ms(
    git: &Path,
    repository: &Path,
    base_sha: &str,
    target_sha: &str,
) -> Result<u64, String> {
    let range = format!("{base_sha}..{target_sha}");
    let output = git_stdout(git, repository, ["log", "--format=%ct", range.as_str()])?;
    output
        .lines()
        .map(parse_seconds_ms)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .min()
        .ok_or_else(|| "Git returned no intervening commit timestamps".to_owned())
}

fn parse_seconds_ms(value: &str) -> Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("Git returned an invalid commit timestamp: {error}"))
        .and_then(|seconds| {
            seconds.checked_mul(1_000).ok_or_else(|| {
                "Git commit timestamp overflows milliseconds since the Unix epoch".to_owned()
            })
        })
}

fn candidate_touched_paths(
    git: &Path,
    repository: &Path,
    base_sha: &str,
    candidate_sha: &str,
    target_sha: &str,
) -> Result<BTreeSet<String>, String> {
    let base_exclusion = format!("^{base_sha}");
    let target_exclusion = format!("^{target_sha}");
    touched_paths_from_revisions(
        git,
        repository,
        [
            candidate_sha,
            base_exclusion.as_str(),
            target_exclusion.as_str(),
        ],
        "--diff-merges=remerge",
    )
}

fn touched_paths(
    git: &Path,
    repository: &Path,
    base_sha: &str,
    target_sha: &str,
) -> Result<BTreeSet<String>, String> {
    let range = format!("{base_sha}..{target_sha}");
    touched_paths_from_revisions(git, repository, [range.as_str()], "-m")
}

fn touched_paths_from_revisions<I, S>(
    git: &Path,
    repository: &Path,
    revisions: I,
    merge_mode: &str,
) -> Result<BTreeSet<String>, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = vec![
        "log".into(),
        merge_mode.into(),
        "--no-renames".into(),
        "--no-ext-diff".into(),
        "--format=".into(),
        "--name-only".into(),
        "-z".into(),
    ];
    command.extend(
        revisions
            .into_iter()
            .map(|revision| revision.as_ref().to_owned()),
    );
    command.push("--".into());
    let output = git_output(git, repository, command)?;
    if !output.status.success() {
        return Err(git_failure_detail(&output));
    }
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| {
            String::from_utf8(path.to_vec())
                .map_err(|error| format!("Git returned a non-UTF-8 touched path: {error}"))
        })
        .collect()
}

fn git_stdout<I, S>(git: &Path, repository: &Path, args: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = git_output(git, repository, args)?;
    if !output.status.success() {
        return Err(git_failure_detail(&output));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("Git returned non-UTF-8 output: {error}"))
}

fn git_output<I, S>(git: &Path, repository: &Path, args: I) -> Result<Output, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    #[cfg(test)]
    GIT_COMPARISON_CALLS.set(GIT_COMPARISON_CALLS.get() + 1);
    let mut command = Command::new(git);
    command
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LC_ALL", "C")
        .arg("-C")
        .arg(repository)
        .args(args);
    command.output().map_err(|error| error.to_string())
}

fn git_failure_detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if stderr.is_empty() {
        format!("Git exited with {}", output.status)
    } else {
        stderr
    }
}

#[cfg(test)]
pub(crate) fn reset_git_comparison_count() {
    GIT_COMPARISON_CALLS.set(0);
}

#[cfg(test)]
pub(crate) fn git_comparison_count() -> u64 {
    GIT_COMPARISON_CALLS.get()
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use super::BaseStalenessContext;

    const PATHLESS_CHILD: &str = "AGSV_BASE_STALENESS_PATHLESS_CHILD";
    const PINNED_GIT: &str = "AGSV_BASE_STALENESS_PINNED_GIT";

    #[test]
    fn unborn_primary_branch_is_plainly_not_configured() {
        let temporary = tempfile::tempdir().unwrap();
        let git = crate::review::resolve_git_executable().unwrap();
        run_git(&git, temporary.path(), &["init", "-q"]);
        let context = BaseStalenessContext::observe(&git, temporary.path(), None, 1);
        let target = context.target_report();
        assert_eq!(target["state"], "not_configured");
        assert_eq!(target["reason"], "primary_worktree_branch_is_unborn");
        assert!(target["branch"].is_null());

        let metadata = fs::metadata(temporary.path().join(".git")).unwrap();
        assert!(metadata.is_dir());
    }

    #[test]
    fn reporting_uses_injected_git_with_no_ambient_path() {
        if let Some(git) = env::var_os(PINNED_GIT) {
            assert!(env::var_os("PATH").is_none());
            exercise_pathless_reporting(Path::new(&git));
            return;
        }

        let git = crate::review::resolve_git_executable().unwrap();
        let status = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "base_staleness::tests::reporting_uses_injected_git_with_no_ambient_path",
                "--nocapture",
            ])
            .env_clear()
            .env(PATHLESS_CHILD, "1")
            .env(PINNED_GIT, &git)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn missing_injected_git_does_not_fall_back_to_ambient_path() {
        let temporary = tempfile::tempdir().unwrap();
        let git = crate::review::resolve_git_executable().unwrap();
        initialize_repository(&git, temporary.path());
        let missing = temporary.path().join("missing-pinned-git");

        let context = BaseStalenessContext::observe(&missing, temporary.path(), None, 1);
        let target = context.target_report();
        assert_eq!(target["state"], "not_configured");
        assert_eq!(target["reason"], "primary_worktree_has_no_attached_branch");
        assert!(
            target["detail"]
                .as_str()
                .is_some_and(|detail| !detail.is_empty())
        );
    }

    fn exercise_pathless_reporting(git: &Path) {
        assert_eq!(
            env::var_os(PATHLESS_CHILD).as_deref(),
            Some(std::ffi::OsStr::new("1"))
        );
        let temporary = tempfile::tempdir().unwrap();
        initialize_repository(git, temporary.path());
        let context = BaseStalenessContext::observe(git, temporary.path(), None, 1);
        let target = context.target_report();
        assert_eq!(target["state"], "available");
        let head = target["head_sha"].as_str().unwrap();
        let request = context.request_report(head, None);
        assert_eq!(request["state"], "current");
        assert_eq!(request["commits_behind"], 0);
    }

    fn initialize_repository(git: &Path, root: &Path) {
        run_git(git, root, &["init", "-q"]);
        run_git(git, root, &["config", "user.email", "test@example.com"]);
        run_git(git, root, &["config", "user.name", "AGSV Test"]);
        fs::write(root.join("base.txt"), "base\n").unwrap();
        run_git(git, root, &["add", "base.txt"]);
        run_git(git, root, &["commit", "-q", "-m", "base"]);
    }

    fn run_git(git: &Path, root: &Path, args: &[&str]) {
        let output = neutral_git_command(git, root).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn neutral_git_command(git: &Path, root: &Path) -> Command {
        let mut command = Command::new(git);
        command
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C")
            .arg("-C")
            .arg(root);
        command
    }
}
