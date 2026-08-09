# Agent Supervisor

Agent Supervisor (`agsv`) is a local, durable control plane that connects a human-facing Primary Orchestrator with one or more Implementation Orchestrators. It provides typed messages, team isolation, acknowledgements, leases, fencing epochs, recovery, and replaceable session/runtime adapters while leaving native subagent execution to Claude Code and Codex.

The initial release targets macOS with Herdr, Claude Code, and Codex. See [the architecture](docs/architecture.md) and [v0.1 scope](docs/v0.1.md).

The v0.1 workflow keeps one human-facing Claude Code Primary and allows it to
coordinate multiple Codex implementation teams through a replaceable session
backend (Herdr first). AGSV persists the protocol state independently of either
provider.

## Development

The workspace follows the stable Rust channel. New dependencies are selected
with `cargo add`, `Cargo.lock` is committed, and Dependabot watches both Cargo
and GitHub Actions dependencies.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```
