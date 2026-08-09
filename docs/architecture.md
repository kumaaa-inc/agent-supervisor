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

Top-level provider syntax lives behind the `AgentRuntime` adapter boundary in
`agsv-runtime`. The control plane selects an adapter by runtime identifier from
a compile-time registry, supplies model, reasoning-effort, prompt, and session
context as structured values, and passes the resulting invocation to the
selected `SessionBackend`. Codex is the built-in default. Adding another
runtime changes the adapter registry, not `agsv-core`, `agsv-protocol`, or
provider-neutral control flow.

## Durable protocol

Every envelope carries stable workspace, team, actor, run, request, policy revision, and fencing identifiers as applicable. Required behavior includes:

- durable delivery with explicit acknowledgement;
- at-least-once adapter wake-up for both Primary and Implementation targets,
  with failures surfaced so the same operation ID can retry the durable
  delivery safely;
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

Actor and team profiles are the persistent configuration boundary for
top-level orchestration. An actor profile selects a descriptive project role,
an open set of capabilities, a runtime/model/effort tuple, and a role file. A
team profile selects its actor profile plus a desired instance count and an
assignment policy. The built-in `primary` and `implementation` profiles preserve
the v0.1 behavior; structurally v0.1 configuration is synthesized into the same
effective profiles without writing files or changing its persisted JSON shape.

Role names do not authorize operations. `human_facing_primary` permits holding
the single active Primary lease and exercising Primary operations;
`implementation_execution` permits request assignment and Implementation
operations. Capability strings remain open so projects can add responsibilities
such as research, review, or breakage testing without adding protocol role enum
variants. Newly configured actors and teams persist immutable profile snapshots
so authorization and causal-history checks do not change when configuration is
edited; changing identity-bearing role or capability metadata requires a new
logical actor or team. Profile-less records retain the exact v0.1 `primary` and
`implementation` compatibility mapping, including after a project materializes
the explicit default profiles.

Runtime, model, reasoning effort, and role instructions remain control/runtime
configuration and never enter the provider-neutral domain snapshot. Conversely,
capabilities and team intent are durable domain metadata. The controller
reconciles `desired_instances` during team creation, resume, and explicit
reconciliation. Request creation applies the persisted `first_healthy` or
`least_wip` policy; least-WIP derives its deterministic state from durable
nonterminal assignments and uses the team's persisted actor order for ties.
Assignment policy identifiers remain open protocol data, while effective
configuration rejects identifiers that the current controller cannot execute.
Reconciliation reuses healthy sessions and fences only the stale logical actor
being replaced. Surplus actors are stopped only after desired capacity is
healthy and their WIP is zero, so convergence never strands an active
assignment merely to satisfy an instance count.

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
