use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agsv_protocol::{
    GitSha, PayloadDigest, PolicyRevision, ReviewBinaryId, ReviewBinaryObservation,
    ReviewBinaryPresence, ReviewCheck, ReviewCheckId, ReviewCheckOutcome, ReviewCheckResult,
    ReviewCheckTermination, ReviewEnvironmentId, ReviewEnvironmentKey, ReviewEnvironmentRecord,
    ReviewExecutionVariant, ReviewOutputArtifact, ReviewPlan, ReviewPlanIdentity,
    ReviewProcessContainment, ReviewSession, ReviewSessionId, ReviewToolId, ReviewToolVersion,
    ReviewToolVersionProbe, ReviewTreeIdentity, TimestampMillis, Validate,
};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::ControlError;
use crate::engine::ReviewSettings;
use crate::identity::sha256_hex;

const REVIEW_DIRECTORY: &str = "reviews";
const CHECKOUT_DIRECTORY: &str = "source";
const ARTIFACT_DIRECTORY: &str = "artifacts";
const TEMP_DIRECTORY: &str = "tmp";
const EMPTY_GIT_TEMPLATE_DIRECTORY: &str = "empty-git-template";
const EMPTY_GIT_HOOKS_DIRECTORY: &str = "empty-git-hooks";
const PATH_PROFILES_DIRECTORY: &str = "path-profiles";
const MAX_REVIEW_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_REVIEW_ATTEMPT_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
static DETECTED_SANDBOX: OnceLock<Option<SandboxKind>> = OnceLock::new();

pub(crate) struct ReviewExecutionEvidence {
    pub path_digest: PayloadDigest,
    pub environment: ReviewEnvironmentRecord,
    pub result: ReviewCheckResult,
}

#[derive(Clone, Copy)]
enum SandboxKind {
    None,
    #[cfg(target_os = "macos")]
    MacOs,
    #[cfg(target_os = "linux")]
    Bubblewrap,
}

impl SandboxKind {
    const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            #[cfg(target_os = "macos")]
            Self::MacOs => "macos_sandbox_exec",
            #[cfg(target_os = "linux")]
            Self::Bubblewrap => "linux_bubblewrap_pid_namespace",
        }
    }

    const fn process_containment(self) -> ReviewProcessContainment {
        match self {
            Self::None => ReviewProcessContainment::None,
            #[cfg(target_os = "macos")]
            Self::MacOs => ReviewProcessContainment::ProcessGroupOnly,
            #[cfg(target_os = "linux")]
            Self::Bubblewrap => ReviewProcessContainment::PidNamespaceParentDeath,
        }
    }
}

pub(crate) struct ReviewAttemptBudget {
    remaining: Arc<AtomicU64>,
}

impl ReviewAttemptBudget {
    pub(crate) fn new() -> Self {
        Self {
            remaining: Arc::new(AtomicU64::new(MAX_REVIEW_ATTEMPT_ARTIFACT_BYTES)),
        }
    }
}

struct CapturedProcess {
    exit_code: Option<i32>,
    stdout: ReviewOutputArtifact,
    stderr: ReviewOutputArtifact,
    started_at: TimestampMillis,
    finished_at: TimestampMillis,
    termination: ReviewCheckTermination,
    process_tree_may_outlive: bool,
}

struct CapturedStream {
    artifact: ReviewOutputArtifact,
    incomplete: bool,
}

#[derive(Clone)]
struct OutputCaptureControl {
    attempt_budget: Arc<AtomicU64>,
    output_limited: Arc<AtomicBool>,
    capture_done: Arc<AtomicBool>,
    may_be_incomplete: bool,
}

struct CapturedToolVersions {
    versions: Vec<ReviewToolVersion>,
    resolved: BTreeMap<String, (PathBuf, PayloadDigest)>,
}

pub(crate) struct ReviewRunner {
    repository: PathBuf,
    root: PathBuf,
    settings: ReviewSettings,
    git: PathBuf,
    sandbox: Option<SandboxKind>,
}

impl ReviewRunner {
    pub(crate) fn new(
        repository: &Path,
        state_directory: &Path,
        settings: ReviewSettings,
    ) -> Result<Self, ControlError> {
        let repository = fs::canonicalize(repository).map_err(|error| {
            ControlError::io("canonicalize review repository", repository, &error)
        })?;
        let state_directory = fs::canonicalize(state_directory).map_err(|error| {
            ControlError::io(
                "canonicalize review state directory",
                state_directory,
                &error,
            )
        })?;
        let git = resolve_executable("git", &controller_path()?)?;
        let sandbox = detect_sandbox();
        Ok(Self {
            repository,
            root: state_directory.join(REVIEW_DIRECTORY),
            settings,
            git,
            sandbox,
        })
    }

    pub(crate) fn configured(&self) -> bool {
        !self.settings.checks.is_empty()
    }

    pub(crate) fn sandbox_name(&self) -> &'static str {
        self.sandbox.unwrap_or(SandboxKind::None).name()
    }

    pub(crate) fn sandbox_enforced(&self) -> bool {
        self.sandbox.is_some()
    }

    pub(crate) fn process_containment(&self) -> ReviewProcessContainment {
        self.sandbox_kind().process_containment()
    }

    pub(crate) fn verify_artifact(
        &self,
        source: &str,
        path: &Path,
        expected_digest: &PayloadDigest,
        expected_byte_count: u64,
    ) -> Result<(), ControlError> {
        let relative = path.strip_prefix(&self.root).map_err(|_| {
            ControlError::new(
                "review_artifact_path_invalid",
                "review evidence reference is outside controller-owned artifact storage",
            )
            .with_details(json!({ "source": source, "path": path }))
        })?;
        reject_symlink(&self.root)?;
        let mut inspected = self.root.clone();
        for component in relative.components() {
            let Component::Normal(segment) = component else {
                return Err(ControlError::new(
                    "review_artifact_path_invalid",
                    "review evidence reference is not a normalized relative path",
                )
                .with_details(json!({ "source": source, "path": path })));
            };
            inspected.push(segment);
            reject_symlink(&inspected)?;
        }
        let metadata = fs::metadata(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ControlError::new(
                    "review_artifact_missing",
                    "durable review evidence references a missing output artifact",
                )
                .with_details(json!({ "source": source, "path": path }))
            } else {
                ControlError::io("inspect review evidence artifact", path, &error)
            }
        })?;
        if !metadata.is_file() {
            return Err(ControlError::new(
                "review_artifact_path_invalid",
                "durable review evidence reference is not a regular file",
            )
            .with_details(json!({ "source": source, "path": path })));
        }
        let actual_digest = digest_file(path)?;
        if metadata.len() != expected_byte_count || actual_digest != *expected_digest {
            return Err(ControlError::new(
                "review_artifact_integrity_mismatch",
                "durable review output artifact differs from its recorded byte count or digest",
            )
            .with_details(json!({
                "source": source,
                "path": path,
                "expected_byte_count": expected_byte_count,
                "actual_byte_count": metadata.len(),
                "expected_digest": expected_digest,
                "actual_digest": actual_digest,
            })));
        }
        Ok(())
    }

    pub(crate) fn plan(&self, policy_revision: PolicyRevision) -> Result<ReviewPlan, ControlError> {
        if !self.configured() {
            return Err(ControlError::new(
                "review_suite_unconfigured",
                "the active configuration has no control-plane review checks",
            )
            .with_hint("declare review.checks and review.tool_versions in project configuration"));
        }
        let checks = self
            .settings
            .checks
            .iter()
            .map(|check| {
                let relative_cwd = check
                    .relative_cwd
                    .as_ref()
                    .map(|path| {
                        path.to_str().map(str::to_owned).ok_or_else(|| {
                            ControlError::new(
                                "invalid_review_configuration",
                                "review check cwd must be valid UTF-8",
                            )
                        })
                    })
                    .transpose()?;
                Ok(ReviewCheck {
                    check_id: ReviewCheckId::new(check.id.clone())
                        .map_err(ControlError::protocol)?,
                    argv: check.argv.clone(),
                    relative_cwd,
                    timeout_seconds: check.timeout_seconds,
                    expected_exit_code: check.expected_exit_code,
                    required_absent_binaries: check
                        .required_absent_binaries
                        .iter()
                        .cloned()
                        .map(ReviewBinaryId::new)
                        .collect::<Result<_, _>>()
                        .map_err(ControlError::protocol)?,
                })
            })
            .collect::<Result<Vec<_>, ControlError>>()?;
        let tool_version_probes = self
            .settings
            .tool_versions
            .iter()
            .map(|probe| {
                Ok(ReviewToolVersionProbe {
                    tool_id: ReviewToolId::new(probe.id.clone()).map_err(ControlError::protocol)?,
                    argv: probe.argv.clone(),
                })
            })
            .collect::<Result<Vec<_>, ControlError>>()?;
        let declared_environment = self
            .settings
            .environment
            .iter()
            .map(|(key, value)| {
                Ok((
                    ReviewEnvironmentKey::new(key.clone()).map_err(ControlError::protocol)?,
                    value.clone(),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, ControlError>>()?;
        let optional_binaries = self
            .settings
            .optional_binaries
            .iter()
            .cloned()
            .map(ReviewBinaryId::new)
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(ControlError::protocol)?;
        let declared_environment_digest = digest_json(&declared_environment)?;
        let config_digest = digest_json(&json!({
            "checks": checks,
            "tool_version_probes": tool_version_probes,
            "declared_environment": declared_environment,
            "optional_binaries": optional_binaries,
        }))?;
        let plan = ReviewPlan {
            identity: ReviewPlanIdentity {
                policy_revision,
                config_digest,
            },
            checks,
            tool_version_probes,
            declared_environment,
            declared_environment_digest,
            optional_binaries,
        };
        plan.validate().map_err(ControlError::protocol)?;
        Ok(plan)
    }

    pub(crate) fn resolve_tree(
        &self,
        candidate: &GitSha,
    ) -> Result<ReviewTreeIdentity, ControlError> {
        let commit = self.git_text(
            &self.repository,
            &["rev-parse", &format!("{}^{{commit}}", candidate.as_str())],
            "resolve review candidate commit",
        )?;
        if commit != candidate.as_str() {
            return Err(ControlError::new(
                "candidate_mismatch",
                "review candidate did not resolve to the exact requested commit",
            )
            .with_details(json!({ "candidate_sha": candidate, "resolved_commit": commit })));
        }
        let tree = self.git_text(
            &self.repository,
            &["rev-parse", &format!("{}^{{tree}}", candidate.as_str())],
            "resolve review candidate tree",
        )?;
        Ok(ReviewTreeIdentity {
            candidate_sha: candidate.clone(),
            tree_sha: GitSha::new(tree).map_err(ControlError::protocol)?,
        })
    }

    pub(crate) fn checkout_path(&self, session_id: &ReviewSessionId) -> PathBuf {
        self.root.join(session_id.as_str()).join(CHECKOUT_DIRECTORY)
    }

    pub(crate) fn artifacts_path(&self, session_id: &ReviewSessionId) -> PathBuf {
        self.root.join(session_id.as_str()).join(ARTIFACT_DIRECTORY)
    }

    pub(crate) fn temp_path(&self, session_id: &ReviewSessionId) -> PathBuf {
        self.root.join(session_id.as_str()).join(TEMP_DIRECTORY)
    }

    pub(crate) fn prepare_checkout(&self, session: &ReviewSession) -> Result<(), ControlError> {
        session.validate().map_err(ControlError::protocol)?;
        let expected = self.checkout_path(&session.session_id);
        if Path::new(&session.checkout_path) != expected {
            return Err(ControlError::new(
                "review_checkout_identity_mismatch",
                "durable checkout path does not match the controller-owned session path",
            )
            .with_details(json!({
                "session_id": session.session_id,
                "stored_path": session.checkout_path,
                "expected_path": expected,
            })));
        }
        ensure_secure_directory(&self.root)?;
        ensure_secure_directory(&self.root.join(EMPTY_GIT_TEMPLATE_DIRECTORY))?;
        let session_root = self.root.join(session.session_id.as_str());
        ensure_secure_directory(&session_root)?;
        for name in [
            ARTIFACT_DIRECTORY,
            TEMP_DIRECTORY,
            EMPTY_GIT_TEMPLATE_DIRECTORY,
            EMPTY_GIT_HOOKS_DIRECTORY,
        ] {
            ensure_secure_directory(&session_root.join(name))?;
        }

        if expected.exists() {
            if self.verify_checkout(session).is_ok() {
                return Ok(());
            }
            let mut preserved = None;
            for sequence in 1..=32_u8 {
                let candidate = session_root.join(format!("source.invalid-{sequence}"));
                if !candidate.exists() {
                    preserved = Some(candidate);
                    break;
                }
            }
            let preserved = preserved.ok_or_else(|| {
                ControlError::new(
                    "review_checkout_recovery_exhausted",
                    "too many invalid checkout remnants exist for this review session",
                )
            })?;
            fs::rename(&expected, &preserved).map_err(|error| {
                ControlError::io("preserve invalid review checkout", &expected, &error)
            })?;
            fsync_directory(&session_root)?;
        }
        reject_symlink(&expected)?;
        self.materialize_exact_checkout(session, &expected)?;
        ensure_standalone_objects(&expected)?;
        make_tree_read_only(&expected)?;
        self.verify_checkout(session)?;
        fsync_directory(&expected)?;
        fsync_directory(&session_root)
    }

    fn materialize_exact_checkout(
        &self,
        session: &ReviewSession,
        expected: &Path,
    ) -> Result<(), ControlError> {
        let initialized = self
            .neutral_git_command()
            .args(["init", "-q"])
            .arg("--")
            .arg(expected)
            .output()
            .map_err(|error| {
                ControlError::io("initialize isolated review checkout", expected, &error)
            })?;
        require_success(
            initialized,
            "review_checkout_failed",
            "initialize isolated review checkout",
        )?;
        let mut pack = self
            .neutral_git_command()
            .arg("-C")
            .arg(&self.repository)
            .args(["pack-objects", "--stdout", "--revs"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                ControlError::io("read exact review object graph", &self.repository, &error)
            })?;
        let mut pack_input = pack.stdin.take().ok_or_else(|| {
            ControlError::new(
                "review_checkout_failed",
                "Git pack input pipe is unavailable",
            )
        })?;
        writeln!(pack_input, "{}", session.tree.candidate_sha.as_str()).map_err(|error| {
            ControlError::io("select exact review object graph", &self.repository, &error)
        })?;
        drop(pack_input);
        let pack_output = pack.stdout.take().ok_or_else(|| {
            ControlError::new(
                "review_checkout_failed",
                "Git pack output pipe is unavailable",
            )
        })?;
        let indexed = self
            .neutral_git_command()
            .arg("-C")
            .arg(expected)
            .args(["index-pack", "--stdin", "--fix-thin"])
            .stdin(Stdio::from(pack_output))
            .output()
            .map_err(|error| {
                ControlError::io("index isolated review object graph", expected, &error)
            })?;
        let packed = pack.wait_with_output().map_err(|error| {
            ControlError::io("finish exact review object graph", &self.repository, &error)
        })?;
        require_success(
            packed,
            "review_checkout_failed",
            "read exact review object graph",
        )?;
        require_success(
            indexed,
            "review_checkout_failed",
            "index isolated review object graph",
        )?;
        let checkout = self
            .neutral_git_command()
            .arg("-C")
            .arg(expected)
            .args([
                "-c",
                "core.hooksPath=../empty-git-hooks",
                "checkout",
                "--detach",
            ])
            .arg(session.tree.candidate_sha.as_str())
            .output()
            .map_err(|error| {
                ControlError::io("checkout exact review candidate", expected, &error)
            })?;
        require_success(
            checkout,
            "review_checkout_failed",
            "checkout exact review candidate",
        )?;
        Ok(())
    }

    pub(crate) fn verify_checkout(&self, session: &ReviewSession) -> Result<(), ControlError> {
        let checkout = self.checkout_path(&session.session_id);
        reject_symlink(&checkout)?;
        if !checkout.is_dir() {
            return Err(ControlError::new(
                "review_checkout_missing",
                "the durable review checkout is missing",
            )
            .with_details(json!({ "session_id": session.session_id, "path": checkout })));
        }
        let commit = self.git_text(
            &checkout,
            &["rev-parse", "HEAD^{commit}"],
            "verify review checkout commit",
        )?;
        let tree = self.git_text(
            &checkout,
            &["rev-parse", "HEAD^{tree}"],
            "verify review checkout tree",
        )?;
        if commit != session.tree.candidate_sha.as_str() || tree != session.tree.tree_sha.as_str() {
            return Err(ControlError::new(
                "review_checkout_identity_mismatch",
                "review checkout no longer matches its durable commit and tree identity",
            )
            .with_details(json!({
                "session_id": session.session_id,
                "expected_candidate_sha": session.tree.candidate_sha,
                "actual_candidate_sha": commit,
                "expected_tree_sha": session.tree.tree_sha,
                "actual_tree_sha": tree,
            })));
        }
        let status = self
            .neutral_git_command()
            .env("GIT_OPTIONAL_LOCKS", "0")
            .arg("-C")
            .arg(&checkout)
            .args(["status", "--porcelain=v1", "--untracked-files=all"])
            .output()
            .map_err(|error| ControlError::io("verify clean review checkout", &checkout, &error))?;
        require_success(
            status.clone(),
            "review_checkout_invalid",
            "verify clean review checkout",
        )?;
        if !status.stdout.is_empty() {
            return Err(ControlError::new(
                "review_checkout_dirty",
                "review checkout contains tracked or untracked changes",
            )
            .with_details(json!({
                "session_id": session.session_id,
                "status_sha256": sha256_hex(&status.stdout),
            })));
        }
        ensure_standalone_objects(&checkout)?;
        ensure_tree_read_only(&checkout)
    }

    // This is the security boundary that derives, executes, and correlates one
    // complete check and its environment evidence; keeping it contiguous makes
    // the executable-identity and post-execution checkout checks reviewable.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_check(
        &self,
        session: &ReviewSession,
        attempt_sequence: u64,
        check: &ReviewCheck,
        variant: ReviewExecutionVariant,
        budget: &ReviewAttemptBudget,
        fail_after_child_spawn: bool,
    ) -> Result<ReviewExecutionEvidence, ControlError> {
        self.verify_checkout(session)?;
        let sandbox = self.sandbox_kind();
        let absent = match variant {
            ReviewExecutionVariant::Normal => BTreeSet::new(),
            ReviewExecutionVariant::RequiredAbsent => {
                if check.required_absent_binaries.is_empty() {
                    return Err(ControlError::new(
                        "invalid_review_execution",
                        "required-absent execution requires at least one declared binary",
                    ));
                }
                check.required_absent_binaries.clone()
            }
        };
        let path = if absent.is_empty() {
            validated_path()?
        } else {
            self.sanitized_path(&session.session_id, &absent)?
        };
        let path_digest =
            PayloadDigest::new(sha256_hex(path.as_bytes())).map_err(ControlError::protocol)?;
        for binary in &absent {
            if resolve_executable_optional(binary.as_str(), &path)?.is_some() {
                return Err(ControlError::new(
                    "review_absent_binary_present",
                    format!("binary `{binary}` still resolves in the required-absent PATH profile"),
                ));
            }
        }
        let session_root = self.root.join(session.session_id.as_str());
        let checkout = self.checkout_path(&session.session_id);
        let artifacts = self.artifacts_path(&session.session_id);
        let temp = self.temp_path(&session.session_id);
        let cwd = resolve_review_cwd(&checkout, check.relative_cwd.as_deref())?;
        let variant_name = execution_variant_name(variant);
        let result_root = artifacts
            .join(format!("attempt-{attempt_sequence}"))
            .join(check.check_id.as_str())
            .join(variant_name);
        ensure_directory_tree(&result_root)?;
        ensure_directory_tree(&temp)?;
        let (environment, declared_values_digest) = self.expanded_environment(session, &path)?;

        let CapturedToolVersions {
            versions: tool_versions,
            resolved: resolved_tools,
        } = self.capture_tool_versions(
            session,
            check,
            sandbox,
            &path,
            &environment,
            &cwd,
            &result_root,
            budget,
        )?;
        let check_program = &check.argv[0];
        let executable = resolve_executable(check_program, &path)?;
        let executable_digest = digest_file(&executable)?;
        let pinned = resolved_tools.get(check_program).ok_or_else(|| {
            ControlError::new(
                "review_tool_version_missing",
                format!(
                    "check executable `{check_program}` has no matching captured version probe"
                ),
            )
        })?;
        if pinned.0 != executable || pinned.1 != executable_digest {
            return Err(ControlError::new(
                "review_executable_changed",
                "review executable identity changed after its version probe",
            )
            .with_details(json!({
                "program": check_program,
                "resolved_executable": executable,
            })));
        }

        let binary_observations = session
            .plan
            .optional_binaries
            .union(&check.required_absent_binaries)
            .map(|binary| binary_observation(binary, &path))
            .collect::<Result<Vec<_>, ControlError>>()?;
        let execution_environment = execution_environment(
            variant,
            sandbox,
            &cwd,
            &path_digest,
            &declared_values_digest,
        )?;
        let execution_environment_digest = digest_json(&execution_environment)?;
        let environment_id = ReviewEnvironmentId::new(stable_review_id(
            "review-env",
            &format!(
                "{}:{attempt_sequence}:{}:{variant_name}:{}",
                session.session_id,
                check.check_id,
                execution_environment_digest.as_str()
            ),
        ))
        .map_err(ControlError::protocol)?;
        let recorded_at = TimestampMillis(current_time_ms()?);
        let environment_record = ReviewEnvironmentRecord {
            environment_id: environment_id.clone(),
            workspace_id: session.workspace_id.clone(),
            session_id: session.session_id.clone(),
            request_id: session.request_id.clone(),
            candidate_sha: session.tree.candidate_sha.clone(),
            attempt_sequence,
            plan: session.plan.identity.clone(),
            check_id: check.check_id.clone(),
            variant,
            process_containment: sandbox.process_containment(),
            recorded_at,
            declared_environment_digest: session.plan.declared_environment_digest.clone(),
            execution_environment,
            execution_environment_digest,
            tool_versions,
            binary_observations,
            required_absent_binaries: absent,
        };
        environment_record
            .validate()
            .map_err(ControlError::protocol)?;

        let stdout_path = result_root.join("stdout.bin");
        let stderr_path = result_root.join("stderr.bin");
        let captured = self.run_controlled(
            sandbox,
            &executable,
            &check.argv[1..],
            &cwd,
            &session_root,
            &artifacts,
            &temp,
            &path,
            &environment,
            &stdout_path,
            &stderr_path,
            check.timeout_seconds,
            budget,
            fail_after_child_spawn,
        )?;
        if digest_file(&executable)? != executable_digest {
            return Err(ControlError::new(
                "review_executable_changed",
                "review executable identity changed during check execution",
            ));
        }
        let outcome = match (captured.termination, captured.exit_code) {
            (ReviewCheckTermination::Exited, Some(actual))
                if actual == check.expected_exit_code =>
            {
                ReviewCheckOutcome::Passed
            }
            (ReviewCheckTermination::Exited, Some(_)) => ReviewCheckOutcome::Failed,
            _ => ReviewCheckOutcome::ExecutionError,
        };
        let result = ReviewCheckResult {
            workspace_id: session.workspace_id.clone(),
            session_id: session.session_id.clone(),
            request_id: session.request_id.clone(),
            candidate_sha: session.tree.candidate_sha.clone(),
            attempt_sequence,
            plan: session.plan.identity.clone(),
            check_id: check.check_id.clone(),
            variant,
            environment_id,
            outcome,
            expected_exit_code: check.expected_exit_code,
            actual_exit_code: captured.exit_code,
            termination: captured.termination,
            process_tree_may_outlive: captured.process_tree_may_outlive,
            stdout: captured.stdout,
            stderr: captured.stderr,
            started_at: captured.started_at,
            finished_at: captured.finished_at,
        };
        session
            .validate_execution_pair(&result, &environment_record)
            .map_err(ControlError::protocol)?;
        self.verify_checkout(session)?;
        Ok(ReviewExecutionEvidence {
            path_digest,
            environment: environment_record,
            result,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn capture_tool_versions(
        &self,
        session: &ReviewSession,
        check: &ReviewCheck,
        sandbox: SandboxKind,
        path: &str,
        environment: &BTreeMap<String, String>,
        cwd: &Path,
        result_root: &Path,
        budget: &ReviewAttemptBudget,
    ) -> Result<CapturedToolVersions, ControlError> {
        let mut versions = Vec::new();
        let mut resolved = BTreeMap::new();
        let session_root = self.root.join(session.session_id.as_str());
        let artifacts = self.artifacts_path(&session.session_id);
        let temp = self.temp_path(&session.session_id);
        for probe in &session.plan.tool_version_probes {
            let executable = resolve_executable(&probe.argv[0], path)?;
            let executable_digest = digest_file(&executable)?;
            let probe_root = result_root.join("tools").join(probe.tool_id.as_str());
            ensure_directory_tree(&probe_root)?;
            let stdout_path = probe_root.join("stdout.bin");
            let stderr_path = probe_root.join("stderr.bin");
            let captured = self.run_controlled(
                sandbox,
                &executable,
                &probe.argv[1..],
                cwd,
                &session_root,
                &artifacts,
                &temp,
                path,
                environment,
                &stdout_path,
                &stderr_path,
                check.timeout_seconds,
                budget,
                false,
            )?;
            if captured.termination != ReviewCheckTermination::Exited {
                return Err(ControlError::new(
                    "review_tool_probe_failed",
                    format!(
                        "tool version probe `{}` did not exit with complete output",
                        probe.tool_id
                    ),
                ));
            }
            let exit_code = captured.exit_code.ok_or_else(|| {
                ControlError::new(
                    "review_tool_probe_failed",
                    format!(
                        "tool version probe `{}` did not exit normally",
                        probe.tool_id
                    ),
                )
            })?;
            if exit_code != 0 {
                return Err(ControlError::new(
                    "review_tool_probe_failed",
                    format!(
                        "tool version probe `{}` exited with status {exit_code}",
                        probe.tool_id
                    ),
                ));
            }
            let version = version_text(&stdout_path, &stderr_path)?;
            let after_digest = digest_file(&executable)?;
            if after_digest != executable_digest {
                return Err(ControlError::new(
                    "review_executable_changed",
                    format!(
                        "tool executable for `{}` changed during its version probe",
                        probe.tool_id
                    ),
                ));
            }
            versions.push(ReviewToolVersion {
                tool_id: probe.tool_id.clone(),
                resolved_executable: executable.to_string_lossy().into_owned(),
                executable_digest: executable_digest.clone(),
                probe_exit_code: exit_code,
                version,
                stdout: captured.stdout,
                stderr: captured.stderr,
            });
            resolved.insert(probe.argv[0].clone(), (executable, executable_digest));
        }
        if !resolved.contains_key(&check.argv[0]) {
            return Err(ControlError::new(
                "review_tool_version_missing",
                format!(
                    "check `{}` has no matching tool version probe",
                    check.check_id
                ),
            ));
        }
        Ok(CapturedToolVersions { versions, resolved })
    }

    // Keep process creation, bounded capture, termination classification, and
    // fsync ordering together so the execution evidence boundary is auditable.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn run_controlled(
        &self,
        sandbox: SandboxKind,
        executable: &Path,
        arguments: &[String],
        cwd: &Path,
        session_root: &Path,
        artifacts: &Path,
        temp: &Path,
        path: &str,
        environment: &BTreeMap<String, String>,
        stdout_path: &Path,
        stderr_path: &Path,
        timeout_seconds: u32,
        budget: &ReviewAttemptBudget,
        fail_after_child_spawn: bool,
    ) -> Result<CapturedProcess, ControlError> {
        let stdout = create_output_file(stdout_path)?;
        let stderr = create_output_file(stderr_path)?;
        let mut command = Self::sandbox_command(
            sandbox,
            executable,
            arguments,
            cwd,
            session_root,
            artifacts,
            temp,
        )?;
        command
            .env_clear()
            .env("PATH", path)
            .env("TMPDIR", temp)
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null_device())
            .env(
                "GIT_TEMPLATE_DIR",
                self.root.join(EMPTY_GIT_TEMPLATE_DIRECTORY),
            )
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .envs(environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(target_os = "macos")]
        if Path::new("/Applications/Xcode.app/Contents/Developer").is_dir() {
            command.env(
                "DEVELOPER_DIR",
                "/Applications/Xcode.app/Contents/Developer",
            );
        }
        command.process_group(0);
        let started_at = TimestampMillis(current_time_ms()?);
        let started = Instant::now();
        let mut child = command
            .spawn()
            .map_err(|error| ControlError::io("spawn sandboxed review command", cwd, &error))?;
        let child_stdout = child.stdout.take().ok_or_else(|| {
            ControlError::new(
                "review_output_unavailable",
                "sandboxed review stdout pipe is unavailable",
            )
        })?;
        let child_stderr = child.stderr.take().ok_or_else(|| {
            ControlError::new(
                "review_output_unavailable",
                "sandboxed review stderr pipe is unavailable",
            )
        })?;
        set_nonblocking(&child_stdout, stdout_path)?;
        set_nonblocking(&child_stderr, stderr_path)?;
        let output_limited = Arc::new(AtomicBool::new(false));
        let capture_done = Arc::new(AtomicBool::new(false));
        let capture_control = OutputCaptureControl {
            attempt_budget: Arc::clone(&budget.remaining),
            output_limited: Arc::clone(&output_limited),
            capture_done: Arc::clone(&capture_done),
            may_be_incomplete: sandbox.process_containment()
                != ReviewProcessContainment::PidNamespaceParentDeath,
        };
        let stdout_capture = capture_output_thread(
            child_stdout,
            stdout,
            session_root,
            stdout_path,
            capture_control.clone(),
        );
        let stderr_capture = capture_output_thread(
            child_stderr,
            stderr,
            session_root,
            stderr_path,
            capture_control,
        );
        if fail_after_child_spawn {
            terminate_review_process(&mut child, cwd, sandbox)?;
            capture_done.store(true, Ordering::Release);
            let _ = finish_output_capture(stdout_capture, stdout_path)?;
            let _ = finish_output_capture(stderr_capture, stderr_path)?;
            return Err(ControlError::new(
                "injected_crash",
                "injected crash after sandboxed review child spawn",
            ));
        }
        let timeout = Duration::from_secs(u64::from(timeout_seconds));
        let (status, timed_out) = loop {
            if let Some(status) = child.try_wait().map_err(|error| {
                ControlError::io("wait for sandboxed review command", cwd, &error)
            })? {
                terminate_remaining_process_group(child.id(), sandbox, cwd)?;
                break (status, false);
            }
            if output_limited.load(Ordering::Acquire) {
                let status = terminate_review_process(&mut child, cwd, sandbox)?;
                break (status, false);
            }
            if started.elapsed() >= timeout {
                let status = terminate_review_process(&mut child, cwd, sandbox)?;
                break (status, true);
            }
            thread::sleep(Duration::from_millis(20));
        };
        capture_done.store(true, Ordering::Release);
        let stdout = finish_output_capture(stdout_capture, stdout_path)?;
        let stderr = finish_output_capture(stderr_capture, stderr_path)?;
        let output_limited = stdout.artifact.truncated || stderr.artifact.truncated;
        let output_capture_incomplete = stdout.incomplete || stderr.incomplete;
        let finished_at = TimestampMillis(current_time_ms()?);
        let (termination, exit_code) = if timed_out {
            (ReviewCheckTermination::TimedOut, None)
        } else if output_limited {
            (ReviewCheckTermination::OutputLimitExceeded, None)
        } else if output_capture_incomplete {
            (
                ReviewCheckTermination::OutputCaptureIncomplete,
                status.code(),
            )
        } else if let Some(exit_code) = status.code() {
            (ReviewCheckTermination::Exited, Some(exit_code))
        } else {
            (ReviewCheckTermination::Signaled, None)
        };
        let process_tree_may_outlive = (timed_out || output_limited || output_capture_incomplete)
            && sandbox.process_containment() != ReviewProcessContainment::PidNamespaceParentDeath;
        Ok(CapturedProcess {
            exit_code,
            stdout: stdout.artifact,
            stderr: stderr.artifact,
            started_at,
            finished_at,
            termination,
            process_tree_may_outlive,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn sandbox_command(
        sandbox: SandboxKind,
        executable: &Path,
        arguments: &[String],
        cwd: &Path,
        session_root: &Path,
        artifacts: &Path,
        temp: &Path,
    ) -> Result<Command, ControlError> {
        match sandbox {
            SandboxKind::None => {
                let mut command = Command::new(executable);
                command.args(arguments).current_dir(cwd);
                Ok(command)
            }
            #[cfg(target_os = "macos")]
            SandboxKind::MacOs => {
                let profile_path = session_root.join("write-sandbox.sb");
                let profile = format!(
                    "(version 1)\n(allow default)\n(deny file-write*)\n(allow file-write* (literal \"/dev/null\") (subpath \"{}\") (subpath \"{}\"))\n",
                    sandbox_escape(artifacts),
                    sandbox_escape(temp),
                );
                fs::write(&profile_path, profile).map_err(|error| {
                    ControlError::io("write review sandbox profile", &profile_path, &error)
                })?;
                File::open(&profile_path)
                    .and_then(|file| file.sync_all())
                    .map_err(|error| {
                        ControlError::io("sync review sandbox profile", &profile_path, &error)
                    })?;
                let mut command = Command::new("/usr/bin/sandbox-exec");
                command
                    .args(["-f"])
                    .arg(profile_path)
                    .arg("--")
                    .arg(executable)
                    .args(arguments)
                    .current_dir(cwd);
                Ok(command)
            }
            #[cfg(target_os = "linux")]
            SandboxKind::Bubblewrap => {
                let bubblewrap = resolve_executable("bwrap", &validated_path()?)?;
                let mut command = Command::new(bubblewrap);
                command
                    .args([
                        "--die-with-parent",
                        "--new-session",
                        "--unshare-pid",
                        "--ro-bind",
                        "/",
                        "/",
                    ])
                    .args(["--proc", "/proc"])
                    .args(["--dev-bind", "/dev", "/dev"])
                    .args(["--bind"])
                    .arg(artifacts)
                    .arg(artifacts)
                    .args(["--bind"])
                    .arg(temp)
                    .arg(temp)
                    .args(["--chdir"])
                    .arg(cwd)
                    .arg("--")
                    .arg(executable)
                    .args(arguments)
                    .current_dir(cwd);
                Ok(command)
            }
        }
    }

    fn sandbox_kind(&self) -> SandboxKind {
        self.sandbox.unwrap_or(SandboxKind::None)
    }

    fn sanitized_path(
        &self,
        session_id: &ReviewSessionId,
        absent: &BTreeSet<ReviewBinaryId>,
    ) -> Result<String, ControlError> {
        let original = validated_path()?;
        let key = absent
            .iter()
            .map(ReviewBinaryId::as_str)
            .collect::<Vec<_>>()
            .join("\0");
        let root = self
            .root
            .join(session_id.as_str())
            .join(PATH_PROFILES_DIRECTORY)
            .join(&sha256_hex(key.as_bytes())[..24]);
        ensure_directory_tree(&root)?;
        let mut profile = Vec::new();
        for (index, directory) in std::env::split_paths(&original).enumerate() {
            let shadow = root.join(format!("{index:04}"));
            ensure_secure_directory(&shadow)?;
            let entries = match fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(ControlError::io(
                        "read review PATH component",
                        &directory,
                        &error,
                    ));
                }
            };
            for entry in entries {
                let entry = entry.map_err(|error| {
                    ControlError::io("read review PATH entry", &directory, &error)
                })?;
                let name = entry.file_name();
                let name_text = name.to_string_lossy();
                if absent.iter().any(|binary| binary.as_str() == name_text) {
                    continue;
                }
                let Ok(metadata) = fs::metadata(entry.path()) else {
                    continue;
                };
                if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
                    continue;
                }
                let target = fs::canonicalize(entry.path()).map_err(|error| {
                    ControlError::io("canonicalize review PATH entry", &entry.path(), &error)
                })?;
                let link = shadow.join(&name);
                match fs::symlink_metadata(&link) {
                    Ok(existing) if existing.file_type().is_symlink() => {
                        if fs::read_link(&link).map_err(|error| {
                            ControlError::io("read review PATH link", &link, &error)
                        })? != target
                        {
                            return Err(ControlError::new(
                                "review_path_profile_conflict",
                                "existing sanitized PATH entry points to another executable",
                            ));
                        }
                    }
                    Ok(_) => {
                        return Err(ControlError::new(
                            "review_path_profile_conflict",
                            "existing sanitized PATH entry is not a symbolic link",
                        ));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        std::os::unix::fs::symlink(&target, &link).map_err(|error| {
                            ControlError::io("create sanitized PATH entry", &link, &error)
                        })?;
                    }
                    Err(error) => {
                        return Err(ControlError::io(
                            "inspect sanitized PATH entry",
                            &link,
                            &error,
                        ));
                    }
                }
            }
            profile.push(shadow);
        }
        std::env::join_paths(profile)
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(|error| {
                ControlError::new(
                    "invalid_review_environment",
                    format!("could not construct sanitized PATH: {error}"),
                )
            })
    }

    fn expanded_environment(
        &self,
        session: &ReviewSession,
        path: &str,
    ) -> Result<(BTreeMap<String, String>, PayloadDigest), ControlError> {
        let checkout = self.checkout_path(&session.session_id);
        let artifacts = self.artifacts_path(&session.session_id);
        let temp = self.temp_path(&session.session_id);
        let mut declared = session
            .plan
            .declared_environment
            .iter()
            .map(|(key, value)| {
                let value = if value == "{inherit}" {
                    std::env::var(key.as_str()).map_err(|_| {
                        ControlError::new(
                            "review_environment_unavailable",
                            format!("declared inherited environment `{key}` is unavailable"),
                        )
                    })?
                } else {
                    value
                        .replace("{checkout}", &checkout.to_string_lossy())
                        .replace("{artifacts}", &artifacts.to_string_lossy())
                        .replace("{temp}", &temp.to_string_lossy())
                };
                Ok((key.to_string(), value))
            })
            .collect::<Result<BTreeMap<_, _>, ControlError>>()?;
        let declared_values_digest = digest_json(&declared)?;
        declared.insert("PATH".to_owned(), path.to_owned());
        Ok((declared, declared_values_digest))
    }

    fn git_text(
        &self,
        directory: &Path,
        args: &[&str],
        action: &str,
    ) -> Result<String, ControlError> {
        let output = self
            .neutral_git_command()
            .arg("-C")
            .arg(directory)
            .args(args)
            .output()
            .map_err(|error| ControlError::io(action, directory, &error))?;
        let output = require_success(output, "git_error", action)?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    fn neutral_git_command(&self) -> Command {
        let mut command = Command::new(&self.git);
        self.neutralize_git_environment(&mut command);
        command
    }

    fn neutralize_git_environment(&self, command: &mut Command) {
        command
            // Git honors repository and object-database overrides from the
            // ambient environment before many command-line repository
            // selectors. Start from an empty environment so a controller
            // invocation can never redirect the supposedly private checkout
            // into another repository or object store.
            .env_clear()
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_NAMESPACE")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null_device())
            .env(
                "GIT_TEMPLATE_DIR",
                self.root.join(EMPTY_GIT_TEMPLATE_DIRECTORY),
            )
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C");
    }
}

fn validated_path() -> Result<String, ControlError> {
    // The controller builds the child PATH from absolute normalized host
    // components only. Empty, relative, tilde, and parent-traversal entries are
    // rejected from the child profile rather than inherited implicitly.
    controller_path()
}

fn detect_sandbox() -> Option<SandboxKind> {
    *DETECTED_SANDBOX.get_or_init(detect_sandbox_uncached)
}

fn detect_sandbox_uncached() -> Option<SandboxKind> {
    #[cfg(target_os = "macos")]
    {
        let available = Path::new("/usr/bin/sandbox-exec").is_file()
            && Path::new("/usr/bin/true").is_file()
            && Command::new("/usr/bin/sandbox-exec")
                .args(["-p", "(version 1)(allow default)", "--", "/usr/bin/true"])
                .env_clear()
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
        return available.then_some(SandboxKind::MacOs);
    }
    #[cfg(target_os = "linux")]
    {
        let path = controller_path().ok()?;
        let bubblewrap = resolve_executable_optional("bwrap", &path).ok()??;
        let available = Command::new(bubblewrap)
            .args([
                "--die-with-parent",
                "--new-session",
                "--unshare-pid",
                "--ro-bind",
                "/",
                "/",
                "--proc",
                "/proc",
                "--",
                "/bin/true",
            ])
            .env_clear()
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        return available.then_some(SandboxKind::Bubblewrap);
    }
    #[allow(unreachable_code)]
    None
}

fn controller_path() -> Result<String, ControlError> {
    let value = std::env::var("PATH").map_err(|_| {
        ControlError::new(
            "invalid_review_environment",
            "control-plane Git discovery requires PATH",
        )
    })?;
    let components = std::env::split_paths(&value)
        .filter(|component| {
            component.is_absolute()
                && !component
                    .components()
                    .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        })
        .collect::<Vec<_>>();
    if components.is_empty() {
        return Err(ControlError::new(
            "invalid_review_environment",
            "control-plane Git discovery found no absolute PATH components",
        ));
    }
    std::env::join_paths(components)
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|error| {
            ControlError::new(
                "invalid_review_environment",
                format!("could not construct control-plane Git PATH: {error}"),
            )
        })
}

fn resolve_executable_optional(program: &str, path: &str) -> Result<Option<PathBuf>, ControlError> {
    match resolve_executable(program, path) {
        Ok(executable) => Ok(Some(executable)),
        Err(error) if error.code == "review_executable_unavailable" => Ok(None),
        Err(error) => Err(error),
    }
}

fn resolve_review_cwd(checkout: &Path, relative: Option<&str>) -> Result<PathBuf, ControlError> {
    let mut resolved = checkout.to_path_buf();
    if let Some(relative) = relative {
        let relative = Path::new(relative);
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::Prefix(_)
                        | Component::RootDir
                        | Component::CurDir
                        | Component::ParentDir
                )
            })
        {
            return Err(ControlError::new(
                "unsafe_review_path",
                "review check cwd must be a normalized relative path",
            ));
        }
        for component in relative.components() {
            resolved.push(component.as_os_str());
            let metadata = fs::symlink_metadata(&resolved)
                .map_err(|error| ControlError::io("inspect review check cwd", &resolved, &error))?;
            if metadata.file_type().is_symlink() {
                return Err(ControlError::new(
                    "unsafe_review_path",
                    "review check cwd may not traverse symbolic links",
                )
                .with_details(json!({ "path": resolved })));
            }
        }
    }
    if !resolved.is_dir() {
        return Err(ControlError::new(
            "unsafe_review_path",
            "review check cwd is not a directory in the exact checkout",
        )
        .with_details(json!({ "path": resolved })));
    }
    let canonical_checkout = fs::canonicalize(checkout)
        .map_err(|error| ControlError::io("canonicalize review checkout", checkout, &error))?;
    let canonical_cwd = fs::canonicalize(&resolved)
        .map_err(|error| ControlError::io("canonicalize review check cwd", &resolved, &error))?;
    if !canonical_cwd.starts_with(&canonical_checkout) {
        return Err(ControlError::new(
            "unsafe_review_path",
            "review check cwd escapes the exact checkout",
        ));
    }
    Ok(canonical_cwd)
}

const fn execution_variant_name(variant: ReviewExecutionVariant) -> &'static str {
    match variant {
        ReviewExecutionVariant::Normal => "normal",
        ReviewExecutionVariant::RequiredAbsent => "required-absent",
    }
}

fn ensure_directory_tree(path: &Path) -> Result<(), ControlError> {
    if path.exists() {
        return ensure_secure_directory(path);
    }
    let parent = path
        .parent()
        .ok_or_else(|| ControlError::new("unsafe_review_path", "review directory has no parent"))?;
    ensure_directory_tree(parent)?;
    ensure_secure_directory(path)
}

fn digest_file(path: &Path) -> Result<PayloadDigest, ControlError> {
    let mut file = File::open(path)
        .map_err(|error| ControlError::io("open review evidence file", path, &error))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| ControlError::io("read review evidence file", path, &error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    PayloadDigest::new(encoded).map_err(ControlError::protocol)
}

fn binary_observation(
    binary: &ReviewBinaryId,
    path: &str,
) -> Result<ReviewBinaryObservation, ControlError> {
    match resolve_executable_optional(binary.as_str(), path)? {
        Some(executable) => Ok(ReviewBinaryObservation {
            binary_id: binary.clone(),
            presence: ReviewBinaryPresence::Present,
            resolved_executable: Some(executable.to_string_lossy().into_owned()),
            executable_digest: Some(digest_file(&executable)?),
        }),
        None => Ok(ReviewBinaryObservation {
            binary_id: binary.clone(),
            presence: ReviewBinaryPresence::Absent,
            resolved_executable: None,
            executable_digest: None,
        }),
    }
}

fn execution_environment(
    variant: ReviewExecutionVariant,
    sandbox: SandboxKind,
    cwd: &Path,
    path_digest: &PayloadDigest,
    declared_values_digest: &PayloadDigest,
) -> Result<BTreeMap<ReviewEnvironmentKey, String>, ControlError> {
    let cwd_identity = sha256_hex(cwd.as_os_str().as_encoded_bytes());
    let mut values = BTreeMap::new();
    for (key, value) in [
        ("os", std::env::consts::OS.to_owned()),
        ("arch", std::env::consts::ARCH.to_owned()),
        ("agsv_version", env!("CARGO_PKG_VERSION").to_owned()),
        ("cwd_identity", cwd_identity),
        ("path_digest", path_digest.as_str().to_owned()),
        (
            "declared_values_digest",
            declared_values_digest.as_str().to_owned(),
        ),
        (
            "path_profile",
            format!("{}:{}", sandbox.name(), execution_variant_name(variant)),
        ),
        ("lang", "C.UTF-8".to_owned()),
        ("lc_all", "C.UTF-8".to_owned()),
    ] {
        values.insert(
            ReviewEnvironmentKey::new(key.to_owned()).map_err(ControlError::protocol)?,
            value,
        );
    }
    Ok(values)
}

fn stable_review_id(prefix: &str, identity: &str) -> String {
    format!("{prefix}-{}", &sha256_hex(identity.as_bytes())[..32])
}

fn current_time_ms() -> Result<u64, ControlError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ControlError::new("clock_error", error.to_string()))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| ControlError::new("clock_error", "current time exceeds u64 milliseconds"))
}

fn version_text(stdout_path: &Path, stderr_path: &Path) -> Result<String, ControlError> {
    let stdout = fs::read(stdout_path)
        .map_err(|error| ControlError::io("read tool-version stdout", stdout_path, &error))?;
    let stderr = fs::read(stderr_path)
        .map_err(|error| ControlError::io("read tool-version stderr", stderr_path, &error))?;
    let raw = if stdout.is_empty() { &stderr } else { &stdout };
    let normalized = String::from_utf8_lossy(raw)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() {
        return Err(ControlError::new(
            "review_tool_probe_failed",
            "tool version probe produced no version text",
        ));
    }
    Ok(normalized.chars().take(1024).collect())
}

fn create_output_file(path: &Path) -> Result<File, ControlError> {
    let parent = path.parent().ok_or_else(|| {
        ControlError::new(
            "unsafe_review_path",
            "review output has no parent directory",
        )
    })?;
    ensure_directory_tree(parent)?;
    reject_symlink(path)?;
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| ControlError::io("create review output", path, &error))
}

fn set_nonblocking(file: &impl AsFd, path: &Path) -> Result<(), ControlError> {
    let flags = fcntl(file, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(|error| {
            ControlError::io(
                "inspect review output pipe",
                path,
                &std::io::Error::from_raw_os_error(error as i32),
            )
        })?;
    fcntl(file, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).map_err(|error| {
        ControlError::io(
            "make review output pipe nonblocking",
            path,
            &std::io::Error::from_raw_os_error(error as i32),
        )
    })?;
    Ok(())
}

fn capture_output_thread<R: Read + Send + 'static>(
    reader: R,
    output: File,
    session_root: &Path,
    output_path: &Path,
    control: OutputCaptureControl,
) -> thread::JoinHandle<Result<CapturedStream, ControlError>> {
    let session_root = session_root.to_path_buf();
    let output_path = output_path.to_path_buf();
    thread::spawn(move || {
        capture_bounded_output(reader, output, &session_root, &output_path, &control)
    })
}

fn capture_bounded_output(
    mut reader: impl Read,
    mut output: File,
    session_root: &Path,
    output_path: &Path,
    control: &OutputCaptureControl,
) -> Result<CapturedStream, ControlError> {
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut persisted = 0_u64;
    let mut truncated = false;
    let mut incomplete = false;
    let mut reads_after_command_finished = 0_u8;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if control.capture_done.load(Ordering::Acquire) && control.may_be_incomplete {
                    incomplete = true;
                    break;
                }
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(error) => {
                return Err(ControlError::io(
                    "capture review output",
                    output_path,
                    &error,
                ));
            }
        };
        if read == 0 {
            break;
        }
        let local_remaining = MAX_REVIEW_OUTPUT_BYTES.saturating_sub(persisted);
        let locally_allowed = usize::try_from(local_remaining.min(read as u64))
            .expect("bounded review output slice fits usize");
        let allowed = reserve_attempt_artifact_bytes(&control.attempt_budget, locally_allowed);
        if allowed > 0 {
            output
                .write_all(&buffer[..allowed])
                .map_err(|error| ControlError::io("persist review output", output_path, &error))?;
            persisted = persisted.saturating_add(allowed as u64);
        }
        if allowed < read {
            truncated = true;
            control.output_limited.store(true, Ordering::Release);
        }
        if truncated {
            break;
        }
        if control.capture_done.load(Ordering::Acquire) && control.may_be_incomplete {
            reads_after_command_finished = reads_after_command_finished.saturating_add(1);
            if reads_after_command_finished >= 16 {
                let mut probe = [0_u8; 1];
                match reader.read(&mut probe) {
                    Ok(0) => {}
                    Ok(_) => {
                        incomplete = true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        incomplete = true;
                    }
                    Err(error) => {
                        return Err(ControlError::io(
                            "finish review output capture",
                            output_path,
                            &error,
                        ));
                    }
                }
                break;
            }
        }
    }
    output
        .sync_all()
        .map_err(|error| ControlError::io("sync review output", output_path, &error))?;
    Ok(CapturedStream {
        artifact: output_artifact(session_root, output_path, truncated)?,
        incomplete,
    })
}

fn reserve_attempt_artifact_bytes(remaining: &AtomicU64, requested: usize) -> usize {
    let requested = requested as u64;
    let mut available = remaining.load(Ordering::Acquire);
    loop {
        let reserved = available.min(requested);
        match remaining.compare_exchange_weak(
            available,
            available - reserved,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return usize::try_from(reserved)
                    .expect("reserved review output bytes originated from usize");
            }
            Err(actual) => available = actual,
        }
    }
}

fn finish_output_capture(
    capture: thread::JoinHandle<Result<CapturedStream, ControlError>>,
    output_path: &Path,
) -> Result<CapturedStream, ControlError> {
    capture.join().map_err(|_| {
        ControlError::new(
            "review_output_capture_failed",
            "review output capture worker terminated unexpectedly",
        )
        .with_details(json!({ "path": output_path }))
    })?
}

fn output_artifact(
    session_root: &Path,
    output_path: &Path,
    truncated: bool,
) -> Result<ReviewOutputArtifact, ControlError> {
    let relative = output_path.strip_prefix(session_root).map_err(|_| {
        ControlError::new(
            "unsafe_review_path",
            "review output is outside its control-owned session directory",
        )
    })?;
    let metadata = fs::metadata(output_path)
        .map_err(|error| ControlError::io("inspect review output", output_path, &error))?;
    Ok(ReviewOutputArtifact {
        digest: digest_file(output_path)?,
        byte_count: metadata.len(),
        reference: Some(relative.to_string_lossy().into_owned()),
        truncated,
    })
}

fn sandbox_escape(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn terminate_review_process(
    child: &mut std::process::Child,
    cwd: &Path,
    sandbox: SandboxKind,
) -> Result<std::process::ExitStatus, ControlError> {
    #[cfg(not(target_os = "linux"))]
    let _ = sandbox;
    #[cfg(target_os = "linux")]
    if matches!(sandbox, SandboxKind::Bubblewrap) {
        // The bubblewrap monitor is PID 1 of a private PID namespace. Killing
        // and reaping it makes the kernel terminate every process in that
        // namespace, including descendants that called setsid or double-forked.
        child
            .kill()
            .map_err(|error| ControlError::io("terminate contained review command", cwd, &error))?;
        return child
            .wait()
            .map_err(|error| ControlError::io("reap contained review command", cwd, &error));
    }
    let group = format!("-{}", child.id());
    let killed = Command::new("/bin/kill")
        .args(["-KILL", group.as_str()])
        .status()
        .map_err(|error| ControlError::io("terminate review process group", cwd, &error))?;
    if !killed.success() {
        child
            .kill()
            .map_err(|error| ControlError::io("terminate sandboxed review command", cwd, &error))?;
    }
    child
        .wait()
        .map_err(|error| ControlError::io("reap sandboxed review command", cwd, &error))
}

fn terminate_remaining_process_group(
    child_id: u32,
    sandbox: SandboxKind,
    cwd: &Path,
) -> Result<(), ControlError> {
    if sandbox.process_containment() == ReviewProcessContainment::PidNamespaceParentDeath {
        return Ok(());
    }
    let group = format!("-{child_id}");
    let status = Command::new("/bin/kill")
        .args(["-KILL", group.as_str()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| ControlError::io("clean up review process group", cwd, &error))?;
    // No process in the original group is the common case after an ordinary
    // single-process exit. A non-success status is therefore not an error; the
    // recorded containment class still states that detached descendants may
    // be outside this cleanup boundary.
    let _ = status;
    Ok(())
}

pub(crate) fn resolve_executable(program: &str, path: &str) -> Result<PathBuf, ControlError> {
    if program.is_empty()
        || program.contains('/')
        || program.contains('\\')
        || program.starts_with('-')
    {
        return Err(ControlError::new(
            "invalid_review_configuration",
            "review executable names must be portable PATH entries",
        ));
    }
    for directory in std::env::split_paths(path) {
        let candidate = directory.join(program);
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            return fs::canonicalize(&candidate).map_err(|error| {
                ControlError::io("canonicalize review executable", &candidate, &error)
            });
        }
    }
    Err(ControlError::new(
        "review_executable_unavailable",
        format!("review executable `{program}` is not present in the controlled PATH"),
    ))
}

fn ensure_secure_directory(path: &Path) -> Result<(), ControlError> {
    if path.exists() {
        reject_symlink(path)?;
        if !path.is_dir() {
            return Err(ControlError::new(
                "unsafe_review_path",
                "review-managed path exists and is not a directory",
            )
            .with_details(json!({ "path": path })));
        }
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|error| ControlError::io("create review directory", path, &error))?;
    reject_symlink(path)
}

fn reject_symlink(path: &Path) -> Result<(), ControlError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ControlError::new(
            "unsafe_review_path",
            "review-managed paths may not be symbolic links",
        )
        .with_details(json!({ "path": path }))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ControlError::io("inspect review path", path, &error)),
    }
}

fn make_tree_read_only(path: &Path) -> Result<(), ControlError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| ControlError::io("inspect review checkout", path, &error))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)
            .map_err(|error| ControlError::io("read review checkout", path, &error))?
        {
            let entry = entry
                .map_err(|error| ControlError::io("read review checkout entry", path, &error))?;
            make_tree_read_only(&entry.path())?;
        }
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(permissions.mode() & !0o222);
    fs::set_permissions(path, permissions)
        .map_err(|error| ControlError::io("make review checkout read-only", path, &error))
}

fn ensure_tree_read_only(path: &Path) -> Result<(), ControlError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| ControlError::io("inspect review checkout permissions", path, &error))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.permissions().mode() & 0o222 != 0 {
        return Err(ControlError::new(
            "review_checkout_writable",
            "review checkout contains a path with owner, group, or other write permission",
        )
        .with_details(json!({ "path": path, "mode": metadata.permissions().mode() & 0o7777 })));
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)
            .map_err(|error| ControlError::io("read review checkout", path, &error))?
        {
            let entry = entry
                .map_err(|error| ControlError::io("read review checkout entry", path, &error))?;
            ensure_tree_read_only(&entry.path())?;
        }
    }
    Ok(())
}

fn ensure_standalone_objects(checkout: &Path) -> Result<(), ControlError> {
    let git_directory = checkout.join(".git");
    let git_metadata = fs::symlink_metadata(&git_directory).map_err(|error| {
        ControlError::io("inspect isolated Git directory", &git_directory, &error)
    })?;
    if git_metadata.file_type().is_symlink() || !git_metadata.is_dir() {
        return Err(ControlError::new(
            "review_checkout_not_isolated",
            "review checkout Git metadata must be a private directory",
        )
        .with_details(json!({ "path": git_directory })));
    }
    let objects = git_directory.join("objects");
    let metadata = fs::symlink_metadata(&objects).map_err(|error| {
        ControlError::io("inspect isolated Git object database", &objects, &error)
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ControlError::new(
            "review_checkout_invalid",
            "isolated review checkout has no private Git object database",
        ));
    }
    let alternates = objects.join("info").join("alternates");
    match fs::symlink_metadata(&alternates) {
        Ok(_) => {
            return Err(ControlError::new(
                "review_checkout_not_isolated",
                "review checkout must not use a Git alternates object database",
            )
            .with_details(json!({ "path": alternates })));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(ControlError::io(
                "inspect isolated Git alternates",
                &alternates,
                &error,
            ));
        }
    }
    ensure_no_hardlinked_files(&objects)
}

fn ensure_no_hardlinked_files(path: &Path) -> Result<(), ControlError> {
    for entry in fs::read_dir(path)
        .map_err(|error| ControlError::io("inspect isolated Git objects", path, &error))?
    {
        let entry =
            entry.map_err(|error| ControlError::io("inspect isolated Git object", path, &error))?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            ControlError::io("inspect isolated Git object", &entry.path(), &error)
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ControlError::new(
                "review_checkout_not_isolated",
                "review checkout object database contains a symbolic link",
            )
            .with_details(json!({ "path": entry.path() })));
        }
        if metadata.is_dir() {
            ensure_no_hardlinked_files(&entry.path())?;
        } else if metadata.is_file() && metadata.nlink() > 1 {
            return Err(ControlError::new(
                "review_checkout_not_isolated",
                "review checkout contains a hard-linked Git object",
            )
            .with_details(json!({ "path": entry.path(), "link_count": metadata.nlink() })));
        }
    }
    Ok(())
}

fn fsync_directory(path: &Path) -> Result<(), ControlError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| ControlError::io("sync review directory", path, &error))
}

fn require_success(
    output: Output,
    code: &'static str,
    action: &str,
) -> Result<Output, ControlError> {
    if output.status.success() {
        Ok(output)
    } else {
        Err(ControlError::new(
            code,
            format!(
                "{action} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        )
        .with_details(json!({
            "exit_code": output.status.code(),
            "stdout_sha256": sha256_hex(&output.stdout),
            "stderr_sha256": sha256_hex(&output.stderr),
        })))
    }
}

fn digest_json(value: &impl serde::Serialize) -> Result<PayloadDigest, ControlError> {
    let bytes = serde_json::to_vec(value).map_err(ControlError::database)?;
    PayloadDigest::new(sha256_hex(bytes)).map_err(ControlError::protocol)
}

const fn null_device() -> &'static str {
    "/dev/null"
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64};

    use super::{
        MAX_REVIEW_OUTPUT_BYTES, OutputCaptureControl, ReviewRunner, capture_bounded_output,
        create_output_file,
    };
    use crate::engine::ReviewSettings;

    #[test]
    fn neutral_git_command_explicitly_removes_repository_overrides() {
        let runner = ReviewRunner {
            repository: "/repository".into(),
            root: "/state/reviews".into(),
            settings: ReviewSettings::default(),
            git: "/usr/bin/git".into(),
            sandbox: None,
        };
        let mut command = std::process::Command::new("/usr/bin/git");
        for key in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
        ] {
            command.env(key, "/hostile/override");
        }
        runner.neutralize_git_environment(&mut command);
        let environment = command
            .get_envs()
            .map(|(key, value)| (key.to_owned(), value.map(ToOwned::to_owned)))
            .collect::<BTreeMap<_, _>>();
        for key in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
        ] {
            assert!(!environment.contains_key(std::ffi::OsStr::new(key)));
        }
    }

    #[test]
    fn bounded_capture_persists_an_exact_prefix_and_marks_truncation() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("stdout.bin");
        let output = create_output_file(&path).unwrap();
        let input = vec![b'x'; usize::try_from(MAX_REVIEW_OUTPUT_BYTES).unwrap() + 17];
        let limited = Arc::new(AtomicBool::new(false));
        let control = OutputCaptureControl {
            attempt_budget: Arc::new(AtomicU64::new(MAX_REVIEW_OUTPUT_BYTES * 2)),
            output_limited: Arc::clone(&limited),
            capture_done: Arc::new(AtomicBool::new(false)),
            may_be_incomplete: true,
        };
        let artifact = capture_bounded_output(
            Cursor::new(input),
            output,
            temporary.path(),
            &path,
            &control,
        )
        .unwrap();
        assert_eq!(artifact.artifact.byte_count, MAX_REVIEW_OUTPUT_BYTES);
        assert!(artifact.artifact.truncated);
        assert!(!artifact.incomplete);
        assert!(limited.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(
            std::fs::metadata(path).unwrap().len(),
            MAX_REVIEW_OUTPUT_BYTES
        );

        let budget_path = temporary.path().join("budget.bin");
        let control = OutputCaptureControl {
            attempt_budget: Arc::new(AtomicU64::new(17)),
            output_limited: Arc::new(AtomicBool::new(false)),
            capture_done: Arc::new(AtomicBool::new(false)),
            may_be_incomplete: true,
        };
        let artifact = capture_bounded_output(
            Cursor::new(vec![b'y'; 100]),
            create_output_file(&budget_path).unwrap(),
            temporary.path(),
            &budget_path,
            &control,
        )
        .unwrap();
        assert_eq!(artifact.artifact.byte_count, 17);
        assert!(artifact.artifact.truncated);
        assert!(!artifact.incomplete);
    }
}
