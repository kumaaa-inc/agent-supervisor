# Agent Supervisor

Agent Supervisor (`agsv`) is a local, durable control plane that connects a human-facing Primary Orchestrator with one or more Implementation Orchestrators. It provides typed messages, team isolation, acknowledgements, leases, fencing epochs, recovery, and replaceable session/runtime adapters while leaving native subagent execution to Claude Code and Codex.

The initial release targets macOS with Herdr, Claude Code, and Codex. See [the architecture](docs/architecture.md) and [v0.1 scope](docs/v0.1.md).

The v0.1 workflow keeps one human-facing Claude Code Primary and allows it to
coordinate multiple Codex implementation teams through a replaceable session
backend (Herdr first). AGSV persists the protocol state independently of either
provider.

Linked Git worktrees resolve one shared workspace and state store from their
Git common directory while retaining worktree-local configuration and Git
evidence paths. Herdr panes are durably bound to actor generations, so
privileged commands and mailbox access authenticate the current pane rather
than trusting caller-supplied actor names. This boundary prevents accidental
cross-pane impersonation; processes with equivalent access to the same Unix
account remain outside the threat model.

The v0.1 CLI embeds the local controller in each invocation. `agsv start`
durably activates the workspace; validated protocol state, acknowledgements,
and append-only events survive later CLI processes in a WAL-mode SQLite store.
Without `.agent-supervisor/config.toml`, configuration and roles are built in
and mutable state is written only to an OS user-state directory.

## Zero-config quick start

`agsv init` is optional. From any Git repository, the built-in configuration
and role instructions can be used directly:

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

Run `agsv init` only when the project wants to commit and customize the default
policy or role files. Initialization is idempotent and does not silently
overwrite project-owned role changes.

## Development

The workspace follows the stable Rust channel. New dependencies are selected
with `cargo add`, `Cargo.lock` is committed, and Dependabot watches both Cargo
and GitHub Actions dependencies.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```
