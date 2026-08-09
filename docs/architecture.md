# Architecture

## Boundary

AGSV is the workspace-level protocol between top-level orchestrators. It does not manage their provider-native subagents.

```text
Human
  <-> Primary Orchestrator (Claude Code, active x1)
        <-> AGSV control plane and durable mailbox
              <-> Team X / Implementation Orchestrator (Codex)
              <-> Team Y / Implementation Orchestrator (Codex)
```

The Primary may use native Claude subagents for design and fresh review. Each Implementation Orchestrator may use native Codex subagents for implementation, fixes, and QA.

## Runtime topology

- In v0.1, CLI invocations use an embedded local controller over a fenced,
  compare-and-swap SQLite snapshot. The durable `start` marker is truthful and
  does not claim that a background socket daemon exists.
- A future daemon may own the same mutable state behind a local transport
  without changing the protocol aggregate.
- A workspace has one active Primary lease and any number of teams.
- A team has one or more Implementation Orchestrators.
- Herdr is one replaceable session backend. It should normally show the Primary in the user's control tab and each additional team in its own tab.
- Runtime and provider adapters must not leak provider-specific identifiers into core domain types.

## Durable protocol

Every envelope carries stable workspace, team, actor, run, request, policy revision, and fencing identifiers as applicable. Required behavior includes:

- durable delivery with explicit acknowledgement;
- at-least-once adapter wake-up for Implementation targets, with failures
  surfaced so the same operation ID can retry the durable delivery safely;
- idempotent commands and duplicate suppression;
- actor presence and heartbeat;
- one active Primary lease with a fencing epoch;
- one active request assignment with an assignment epoch;
- rejection of stale actor, policy, executor, and assignment epochs;
- immutable candidate SHA references;
- append-only audit events;
- recovery by reconciling persisted state with Git and the active session backend.

Initial typed messages include implementation requests, progress, blockers, candidate readiness, review decisions, fix requests, QA results, integration authorization, cancellation, consultation, dependency/conflict notices, and two-phase ownership handoff.

## Enforcement levels

- Core-enforced: authorization, state transitions, message identity, deduplication, leases, epochs, immutable candidate references.
- Launch-enforced: top-level runtime, model, effort, working directory, and supported sandbox settings.
- Provider-enforced when available: native tool restrictions and session metadata.
- Instructed/observed: provider-native subagent topology, freshness, model selection, and read-only behavior when the provider cannot expose enforcement.

`agsv doctor` must make these levels visible rather than claiming prompt instructions are hard guarantees.

## Configuration and state

AGSV is zero-config by default. When tracked project configuration is absent it
uses embedded default configuration and roles without writing to the repository.
Mutable state for that mode lives in a user state directory keyed by a stable
workspace identity derived from the canonical repository and Git common-dir.
All linked worktrees use the same Git common-directory identity and therefore
the same workspace ID and state store. The current worktree remains distinct
for tracked configuration lookup and command-local Git evidence.

`agsv init` is optional: it materializes the embedded defaults when a project
wants versioned, editable policy and role instructions. Tracked project
configuration then lives under `.agent-supervisor/`; machine-specific overrides
and repository-local runtime state remain ignored.

```text
.agent-supervisor/
  config.toml
  config.local.toml       # ignored
  roles/
    primary-orchestrator.md
    implementation-orchestrator.md
  runtime/                # ignored
```

Protocol and state types are defined in Rust. JSON Schemas are generated from those types and committed for external consumers. SQLite in WAL mode is the initial concurrent local state store; large evidence artifacts remain files referenced by digest.

Herdr-launched actor generations and a manually bootstrapped Primary are bound
durably to hashed pane identities. Privileged commands authenticate the current
binding, renew its configured lease, and fence expired actors; caller-supplied
actor names are assertions only. The state directory and database use owner-only
permissions. This protects against accidental and cross-pane impersonation, not
against a process with equivalent access to the same Unix account.
Implementation actors become stale only after three configured heartbeat
intervals are missed, allowing normal coding work between control-plane calls;
the Primary uses its explicit lease duration.
Environment-selected actor identity exists only for debug builds using the fake
backend with the explicit `AGSV_DEV_ALLOW_INSECURE_ACTOR=1` switch; live and
release backends do not accept it.

## Integration

AGSV v0.1 does not push or merge code. The Primary may issue integration authorization for an exact accepted candidate. Provider-native agents or project tooling perform PR and merge operations. Project conventions such as GitHub closing keywords belong in generated role instructions.
