# Agent Supervisor

Agent Supervisor (`agsv`) is a local, durable control plane that connects a human-facing Primary Orchestrator with one or more Implementation Orchestrators. It provides typed messages, team isolation, acknowledgements, leases, fencing epochs, recovery, and replaceable session/runtime adapters while leaving native subagent execution to Claude Code and Codex.

The v0.2 release targets macOS with Herdr, Claude Code, and Codex. See [the
architecture](docs/architecture.md), [v0.1 scope](docs/v0.1.md), and the
[v0.2 configuration, scheduling, and recovery model](docs/v0.2.md).

AGSV authorizes the human-facing Primary and Implementation teams through
durable capabilities, not provider names. Runtime adapters, session backends,
and caller identity are replaceable boundaries, while the protocol state
remains provider-neutral.

Messages are durably delivered before AGSV wakes their target. Herdr wake-up is
bidirectional: Primary commands wake managed Implementation sessions, and
Implementation progress, questions, blockers, QA, and candidate reports wake
the manually bootstrapped Primary pane. A transient wake failure is surfaced
so retrying the same operation ID redelivers the notification without applying
the protocol transition twice.

Linked Git worktrees resolve one shared workspace and state store from their
Git common directory while retaining worktree-local configuration and Git
evidence paths. Session lifecycle backends and provider-neutral runtimes are
selected from independent compile-time registries, while caller identity is
resolved through a separate boundary. The Herdr identity adapter turns the
current pane into an opaque, hashed durable binding to an actor generation;
lifecycle handles are routing state, not authentication proof. Privileged
commands and mailbox access authenticate that binding rather than trusting
caller-supplied actor names. This boundary prevents accidental cross-pane
impersonation; processes with equivalent access to the same Unix account
remain outside the threat model.

An authenticated actor can declare its own generation stopped with `agsv actor
shutdown --operation-id ID`. AGSV atomically records the stopped actor, stopped
session, audit event, and replay result before asking the persisted session
backend to stop the pane. That binding is then terminal for mutations, while
read-only inspection remains available. `context --bootstrap` advances to a
fresh fenced generation. Primary shutdown releases the Primary lease but does
not deactivate the independent workspace controller; run `agsv stop --force`
first when both should become quiescent.

Runtime adapters and session lifecycle backends are deliberately independent.
An actor profile selects the runtime, model, and reasoning effort; the
workspace selects the default lifecycle backend, while each durable session
records the backend and runtime that own it. Recovery dispatches through those
persisted identifiers and fails closed on a mismatch. `agsv doctor`, `agsv
status`, and `agsv events` expose the effective runtime, backend, caller
identity, profile/capability, and assignment-policy context.

Both built-in profiles use `gpt-5.6-sol`. The Primary keeps `max` reasoning
effort, while v0.2 changes the Implementation default from `max` to `xhigh`.
Schema-version-1 configuration and profile-less v0.1 state remain compatible;
current stores use the fresh-create schema-10 union. Sub-floor databases are
preserved byte-for-byte rather than converted in place.

The CLI embeds the local controller in each invocation. `agsv start`
durably activates the workspace; validated protocol state, acknowledgements,
and append-only events survive later CLI processes in a WAL-mode SQLite store.
Without `.agent-supervisor/config.toml`, configuration and roles are built in
and mutable state is written only to an OS user-state directory.

Opening a sub-floor store refuses while an older controller is active or any
recorded session has activity inside the 24-hour maximum lease horizon accepted
by released configuration. Expired session rows still require an explicit,
exact-state confirmation: the refusal reports a SHA-256 blocker digest, and
`agsv state preserve-subfloor --confirm-blocker-digest DIGEST --operation-id ID`
re-reads that state and requires every persisted backend handle to report
`missing` or `stopped` twice before preserving it. The first fresh schema-10
store then records the preservation mode, source digest, blocker and admission
proof digests, expired rows, backend observations, and operation ID in its
durable event history. A live or unknown backend observation, a recent or
future heartbeat, and an active controller cannot be overridden.
The admission receipt verifies every preserved main, WAL, and SHM digest before
fresh initialization; copy the preservation directory before inspecting it
with an older SQLite client.

## Install

### CLI

Install the latest macOS release (Apple Silicon or Intel) with the generated
shell installer:

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/kumaaa-inc/agent-supervisor/releases/latest/download/agsv-cli-installer.sh | sh
```

Alternatively, build and install the `agsv` binary from a local checkout with
the stable Rust toolchain:

```bash
cargo install --path crates/agsv-cli --locked --force
```

`--force` also refreshes an existing installation when the source changed
without a version bump. Verify the installed binary with `agsv --version`.

### Agent Skill

The provider-neutral `agsv` Skill teaches the CLI and durable protocol. AGSV
itself supplies the authenticated Primary or Implementation role at bootstrap;
the Skill does not assign a role based on whether the runtime is Claude Code or
Codex.

Install the Skill globally for both agents so the Primary session and
AGSV-launched Implementation sessions in linked worktrees can discover it:

```bash
npx skills add kumaaa-inc/agent-supervisor \
  --skill agsv \
  --global \
  --agent claude-code \
  --agent codex \
  --yes
```

Verify or update the global installation with:

```bash
npx skills ls --global --agent claude-code --agent codex
npx skills update agsv --global --yes
```

While developing from a local checkout, install the same Skill without waiting
for a GitHub push:

```bash
npx skills add . \
  --skill agsv \
  --global \
  --agent claude-code \
  --agent codex \
  --yes
```

Start new Claude Code and Codex sessions after installing or updating the
Skill. Its source lives in `skills/agsv` and follows the
[skills.sh repository layout](https://www.skills.sh/docs).

## License

Agent Supervisor is licensed under the [MIT License](LICENSE).

## Zero-config quick start

`agsv init` is optional. From a Herdr-managed Primary pane in any Git
repository, the built-in configuration and role instructions can be used
directly:

```bash
agsv --json config validate
agsv --json start
agsv --json context --bootstrap
agsv --json doctor
```

These commands do not create `.agent-supervisor/` or write configuration into
the repository. The JSON response reports the user-scoped `state_path`; AGSV
keys it by the repository's Git common directory so linked worktrees share the
same mailbox and control state. Ordinary Git worktree creation and session
launching still require their normal permissions.

A Primary may attach a concise, display-only purpose when creating a team and
update it later without changing any team, actor, session, lease, or fencing
identity:

```bash
agsv --json team create v02-core \
  --purpose "runtime adapter boundary" \
  --operation-id create-v02-core
agsv --json team update team-v02-core \
  --purpose "session labels and layout" \
  --operation-id update-v02-core-purpose
```

With the default Herdr layout, the first Implementation shares the Primary's
tab, later Implementations fill two panes per AGSV-managed tab, and new tabs
receive collision-free positive-integer labels. Creation is explicitly targeted
at the Herdr workspace containing the bound Primary pane, independent of which
workspace is focused. Backends without label or tab/pane capabilities continue
to work and report those presentation features as unsupported.

Run `agsv init` only when the project wants to commit and customize the default
policy or role files. Initialization is idempotent and does not silently
overwrite project-owned role changes.

Initialized configuration also materializes persistent actor and team
profiles. Roles are project-defined descriptions; open-ended capabilities grant
control-plane privileges. The built-in profiles preserve the v0.1 Primary and
Implementation role, capability, and workflow semantics, while additional
roles can be introduced without a protocol enum change. Inspect the resolved
profile selection and metadata with `agsv --json config show`,
`agsv --json status`, or `agsv --json doctor`.

Team profiles persist `desired_instances` and `assignment_policy`. Team create,
resume, and reconcile converge persistent actor instances on the desired count.
Choose a non-default profile with `agsv --json team create NAME --profile
PROFILE --operation-id OPERATION_ID`; the selected profile is persisted and
reported by team show, status, and audit events.
Request creation supports `first_healthy` and deterministic `least_wip`
selection; status and doctor expose the effective policy and actor WIP state.
For profile-less v0.1 teams, `team create --orchestrators` remains the durable
compatibility count. Explicit team profiles use their persisted
`desired_instances` value as the authoritative count.

`team list` and `team show` include each team's last attributed durable work
activity, exact nonterminal-request count, and an on-demand observation of its
recorded working directory and current Git HEAD. A recorded path that is
absent or whose present Git/session identity no longer matches durable state is
reported as a fact rather than repaired. `actor list`, `actor show`, and team
details include each exact actor generation's age anchor and completed
assignment count. `doctor.teams_without_nonterminal_work` carries the same
timestamps and inactivity duration without an age threshold or closure
recommendation; team reuse and closure remain project-role judgement.
`status.observability_integrity` reports whether the hot checkpoint matches
the durable projection manifest. `doctor.observability_integrity` additionally
streams the attributed fact chain and reports any integrity failure as
diagnostic evidence without making status or doctor unavailable.

Projects can declare a tool-neutral verification suite in `[review]`. After a
candidate is ready, the Primary can create a durable exact-tree session, run
the suite through the control plane, and read the resulting environment and
output-digest evidence by session or candidate SHA:

```bash
agsv --json review begin \
  --request request-123 \
  --candidate-sha 0123456789abcdef0123456789abcdef01234567 \
  --operation-id review-begin-123
agsv --json review verify \
  --session review-123 \
  --operation-id review-verify-123
agsv --json review show \
  --candidate-sha 0123456789abcdef0123456789abcdef01234567
```

Checks use argv arrays passed directly to the selected executable without an
AGSV-added shell; a project may intentionally select an interpreter. Checks may
require a second PATH profile in which exact optional-binary names do not
resolve. That fact does not attest that the host lacks the binary or that an
alias or absolute path is unreachable. Each stream is captured away from the
child-writable build-output directory, stores at most 1 MiB, and records whether
its content-addressed prefix was truncated; one attempt has a 64 MiB artifact
budget. Verification records the host's actual
process-containment class: Linux bubblewrap uses a parent-death PID namespace,
macOS sandbox-exec enforces source writes but only controls the direct process
group, and an unsupported host records no containment. Timeout, output-limit,
and incomplete-capture evidence therefore records when detached descendants
may have survived. An open pipe abandoned after the parent terminates is
reported separately from cap truncation. `status` and `doctor` report these
boundaries and any recovery-required sessions.

Configured literal `[review.environment]` values are frozen into the durable
plan and must not contain secrets. Use an exact `{inherit}` value for a secret
or other ambient value: the child receives it, while durable records contain
only the sentinel and a digest of the expanded declared environment. Passing
records are readable evidence in this release; they do not yet gate
`decision submit`.

During rejected-candidate rework, a scoped progress message moves the request
from `changes_requested` to `in_progress`; a later scoped blocker can move
active rework to `blocked`. Both retain the rejected candidate and decision as
the replaceable baseline. Only the assigned current-epoch actor may replace it
with a different immutable SHA; stale actors and retries with changed content
remain fenced.

## Development

The workspace follows the stable Rust channel. New dependencies are selected
with `cargo add`, `Cargo.lock` is committed, and Dependabot watches both Cargo
and GitHub Actions dependencies.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

Release maintainers should follow [the release runbook](docs/releasing.md).
