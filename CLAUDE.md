# Agent Supervisor development rules

Read `docs/architecture.md` and `docs/v0.1.md` before implementation.

## Product boundary

- AGSV is a durable protocol and control plane between top-level orchestrators.
- AGSV may launch, resume, observe, and message top-level orchestrators through adapters.
- AGSV must not implement provider-native subagent scheduling, coding, review reasoning, or QA reasoning.
- One active human-facing Primary owns intent and approval for a workspace. Multiple Implementation Orchestrators may operate concurrently in isolated teams.
- Project-specific behavior belongs in generated role files, not in protocol invariants.
- Keep zero-config operation first-class: absence of `.agent-supervisor/` must use embedded defaults and user-scoped state without writing to the repository. `agsv init` only materializes customization files.

## Engineering rules

- Rust protocol types are the source of truth. Generate and commit external JSON Schemas from them.
- Keep the core independent of Herdr, Claude Code, Codex, and GitHub.
- Make state transitions explicit, validated, idempotent, and covered by tests.
- Treat Git SHAs and external references as evidence. Do not trust agent prose as proof.
- Never edit generated schema files by hand.
- Do not add automatic push or merge behavior in v0.1. Emit exact-SHA integration authorization only.
- Add third-party Rust dependencies with `cargo add` so the current latest compatible stable release is selected. Commit `Cargo.lock` and avoid speculative dependencies.
- Keep GitHub Actions on current stable major releases and pin the Rust toolchain to the stable channel.
- Preserve existing user changes and avoid destructive Git commands.

## Team ownership in this repository

For the Primary. Name a team for the area of the system it owns, never for the release or the task that prompted it. Release-named teams (`team-v03-retention` and its siblings) guaranteed a fresh set every cycle and left directories nobody closed; that accumulation came from naming, not from count.

| Team | Owns |
|---|---|
| `control-plane` | `agsv-control` — engine, store, review verification, schema admission |
| `protocol-core` | `agsv-protocol` and `agsv-core` — types, schemas, supervisor invariants, fencing |
| `surface` | `agsv-cli`, `agsv-runtime`, `agsv-session`, `templates/`, `docs/` |

Three, because a team serializes on its single working directory and three concurrent streams has been sufficient. Nearly every change touches `agsv-control`, so `control-plane` is the busy one and this split buys less parallelism than it appears to; if it becomes the bottleneck, add a second team against the same area rather than inventing a release-named one.

Reuse these across releases. Replace a stale actor rather than the team that owns its warm working directory, and close a team only when the area itself is gone.

## Required checks

Run these before handing off a change:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```
