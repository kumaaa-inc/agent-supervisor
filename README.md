# Agent Supervisor

Agent Supervisor (`agsv`) is a local, durable control plane that connects a human-facing Primary Orchestrator with one or more Implementation Orchestrators. It provides typed messages, team isolation, acknowledgements, leases, fencing epochs, recovery, and replaceable session/runtime adapters while leaving native subagent execution to Claude Code and Codex.

The initial release targets macOS with Herdr, Claude Code, and Codex. See [the
architecture](docs/architecture.md), [v0.1 scope](docs/v0.1.md), and the
[v0.2 configuration and recovery model](docs/v0.2.md).

The v0.1 workflow keeps one human-facing Claude Code Primary and allows it to
coordinate multiple Codex implementation teams through a replaceable session
backend (Herdr first). AGSV persists the protocol state independently of either
provider.

Messages are durably delivered before AGSV wakes their target. Herdr wake-up is
bidirectional: Primary commands wake managed Implementation sessions, and
Implementation progress, questions, blockers, QA, and candidate reports wake
the manually bootstrapped Primary pane. A transient wake failure is surfaced
so retrying the same operation ID redelivers the notification without applying
the protocol transition twice.

Linked Git worktrees resolve one shared workspace and state store from their
Git common directory while retaining worktree-local configuration and Git
evidence paths. Session lifecycle backends are selected from a compile-time
registry, while caller identity is resolved through a separate boundary. The
Herdr identity adapter turns the current pane into an opaque, hashed durable
binding to an actor generation; lifecycle handles are routing state, not
authentication proof. Privileged commands and mailbox access authenticate that
binding rather than trusting caller-supplied actor names. This boundary
prevents accidental cross-pane impersonation; processes with equivalent access
to the same Unix account remain outside the threat model.

Runtime adapters and session lifecycle backends are deliberately independent.
An actor profile selects the runtime, model, and reasoning effort; the
workspace selects the default lifecycle backend, while each durable session
records the backend and runtime that own it. Recovery dispatches through those
persisted identifiers and fails closed on a mismatch. `agsv doctor`, `agsv
status`, and `agsv events` expose the effective runtime, backend, caller
identity, profile/capability, and assignment-policy context.

The v0.1 CLI embeds the local controller in each invocation. `agsv start`
durably activates the workspace; validated protocol state, acknowledgements,
and append-only events survive later CLI processes in a WAL-mode SQLite store.
Without `.agent-supervisor/config.toml`, configuration and roles are built in
and mutable state is written only to an OS user-state directory.

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
Implementation behavior, while additional roles can be introduced without a
protocol enum change. Use `agsv --json config show`, `agsv --json status`, or
`agsv --json doctor` to inspect the resolved profile selection and metadata.

Team profiles persist `desired_instances` and `assignment_policy`. Team create,
resume, and reconcile converge persistent actor instances on the desired count.
Request creation supports `first_healthy` and deterministic `least_wip`
selection; status and doctor expose the effective policy and actor WIP state.
For profile-less v0.1 teams, `team create --orchestrators` remains the durable
compatibility count. Explicit team profiles use their persisted
`desired_instances` value as the authoritative count.

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
