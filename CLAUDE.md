# Agent Supervisor development rules

Read `docs/architecture.md` and `docs/v0.1.md` before implementation.

## Product boundary

- AGSV is a durable protocol and control plane between top-level orchestrators.
- AGSV may launch, resume, observe, and message top-level orchestrators through adapters.
- AGSV must not implement provider-native subagent scheduling, coding, review reasoning, or QA reasoning.
- One active human-facing Primary owns intent and approval for a workspace. Multiple Implementation Orchestrators may operate concurrently in isolated teams.
- Project-specific behavior belongs in generated role files, not in protocol invariants.

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

## Required checks

Run these before handing off a change:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```
