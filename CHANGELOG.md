# Changelog

All notable changes to Agent Supervisor are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-10

### Added

- Add a compile-time, provider-neutral runtime registry. Actor profiles now
  select a runtime, model, reasoning effort, capabilities, and role
  instructions while keeping provider-native launch and resume syntax inside
  the runtime adapter.
- Separate session lifecycle backends from caller identity. Every durable
  Implementation session records its runtime and backend owner, while an opaque
  hashed caller binding authenticates the current actor generation independently
  of the lifecycle handle.
- Add persistent actor and team profiles with arbitrary descriptive roles and
  explicit `human_facing_primary` and `implementation_execution` capabilities.
  Roles no longer imply control-plane authority.
- Add durable team purpose, backend-neutral session labels, and configurable
  layout hints. The default Herdr layout places the first Implementation beside
  the Primary and packs later panes under collision-free positive-integer tabs.
- Add `desired_instances` reconciliation and the deterministic `first_healthy`
  and `least_wip` assignment policies. Team create, resume, and explicit
  reconciliation now converge missing, paused, stale, and surplus instances.
- Extend `doctor`, `status`, and `events` with redacted runtime, backend,
  caller-identity, profile, capability, assignment-policy, and instance-health
  context.

### Changed

- Keep schema-version-1 configuration and profile-less v0.1 state compatible,
  including zero-config operation without repository writes. Explicit profiles
  become authoritative once materialized, and control databases migrate in
  place to schema version 5.
- Generate the protocol and domain JSON schemas from Rust while retaining the
  v0.1 wire contract for compatible clients.
- Change the built-in Implementation Orchestrator reasoning effort from `max`
  to `xhigh` while retaining the `gpt-5.6-sol` model. The built-in Primary
  Orchestrator remains on `gpt-5.6-sol` with `max` effort.

### Fixed

- Fix rejected-candidate rework so a scoped progress message moves the request
  back to `in_progress`; a later scoped blocker can move active rework to
  `blocked`. Both retain the rejected candidate and decision as a replaceable
  baseline; only the assigned current-epoch actor may complete with a different
  immutable SHA. ([#8](https://github.com/kumaaa-inc/agent-supervisor/issues/8))
- Pin legacy sessions without a runtime owner to Codex only after validation,
  then recover existing sessions through their persisted runtime and backend
  instead of a changed registry default.
- Make desired-instance reconciliation, surplus cleanup, and multi-actor
  replacement crash-safe and idempotent across process restarts, stale
  operation claims, partial launches, backend cleanup failures, and repeated
  create or resume commands.
- Validate Primary and team worktree ownership before any session side effect,
  retain surplus actors with nonterminal work, and fence stale generations so
  replacement cannot revive or clobber an actor's peers.
- Create Implementation panes in the Herdr workspace containing the
  authenticated Primary pane instead of whichever Herdr workspace the user has
  focused. ([#5](https://github.com/kumaaa-inc/agent-supervisor/issues/5))
- Harden migration fixtures, long session-label uniqueness, deterministic tab
  allocation, and team membership checks for conflict notices.

### Security

- Fail closed when runtime, lifecycle-backend, caller-identity, profile, or
  worktree ownership does not match durable state; debug caller identity remains
  limited to the deterministic fake backend with explicit insecure opt-in.
- Fence concurrent actor replacement with exact actor-generation compare-and-
  swap checks and durable replacement intent, preventing stale launches or
  completions from taking ownership after an epoch change.

## [0.1.1] - 2026-08-09

### Fixed

- Wake the bound Primary Herdr pane when an Implementation Orchestrator sends
  progress, questions, blockers, QA results, or candidate evidence.
- Surface Primary wake failures so retrying the same operation ID reattempts
  notification without duplicating the durable protocol transition.

### Changed

- Register the Primary pane as a durable notification endpoint during context
  bootstrap and authenticated commands.
- Teach the provider-neutral AGSV Skill and generated Primary role to process
  the authenticated inbox when AGSV wakes the pane.

## [0.1.0] - 2026-08-09

### Added

- Durable local control plane for one human-facing Primary Orchestrator and
  multiple concurrent Implementation Orchestrators.
- Typed, acknowledged coordination messages for requests, reviews, decisions,
  run control, QA, dependencies, conflicts, consultations, and handoffs.
- Isolated implementation teams backed by Git worktrees and Herdr sessions,
  with crash-safe launch and replacement recovery.
- Zero-config operation with embedded defaults and user-scoped SQLite state;
  `agsv init` remains available for project-owned customization.
- Provider-neutral `agsv` Skill installable for both Claude Code and Codex.
- macOS release binaries, checksums, shell installer, and GitHub artifact
  attestations.

### Security

- Pane-bound actor identity, expiring leases, fencing epochs, exact-SHA review
  decisions, idempotent operations, and causal snapshot validation.
- Private user-state permissions and worktree-aware workspace isolation.

<!-- generated by git-cliff -->
