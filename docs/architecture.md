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
- Session lifecycle backends are selected by identifier from a compile-time
  registry. Herdr remains the zero-config default; deterministic fixtures and
  future backends use the same launch, checkpoint, resume, status, notify,
  stop, and reconciliation boundary.
- Caller identity is a separate adapter boundary. A lifecycle handle is opaque
  routing state and is never, by itself, proof of the invoking actor.
- Team purpose and effective session labels are descriptive presentation
  metadata. They never participate in team or actor identity, authorization,
  leases, assignment fences, or session ownership.
- Session layout policy is backend-neutral. A capable backend may place a new
  session beside an existing session, create managed tabs, and update display
  labels; an incapable backend ignores those hints and reports the unsupported
  capabilities without making orchestration fail.
- The Herdr backend resolves the workspace containing the bound Primary pane
  and targets creation there explicitly. It never relies on the user's focused
  workspace or moves a launched pane, because a move changes its opaque handle.
- Runtime and provider adapters must not leak provider-specific identifiers into core domain types.

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

The zero-config session layout is equivalent to:

```toml
[session_layout]
max_panes_per_tab = 2
place_first_implementation_with_primary = true
tab_label_strategy = "sequence"
pane_label_template = "{session_label}"
split_direction = "right"
focus_new_sessions = false
```

The Primary occupies the first slot, so the first Implementation is placed
beside it. The second Implementation starts the next AGSV-managed tab, the third
fills that tab, and the pattern repeats. Managed tab labels use the next
available positive integer without renaming or colliding with an existing tab.
Setting `max_panes_per_tab = 1` and
`place_first_implementation_with_primary = false` preserves the v0.1
one-Implementation-per-tab layout. Label templates accept `{session_label}`,
`{team_purpose}`, and `{active_request_title}`; expansion and backend label
updates remain presentation-only.

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

The Herdr caller-identity backend reads the current pane context and emits an
opaque binding key. The actor-binding index stores only its hash and binds it
durably to one actor generation; an opaque lifecycle routing token may also be
persisted separately as backend-owned session state. Privileged commands
resolve the hashed binding, renew its configured lease, and fence expired
actors; caller-supplied actor names are assertions only. Session lifecycle
adapters do not resolve caller identity, and the control plane does not read
Herdr environment variables or binding names directly. The state directory and
database use owner-only permissions. This protects against accidental and
cross-pane impersonation, not against a process with equivalent access to the
same Unix account. Display labels and team purpose are untrusted descriptive
text and are never accepted as caller identity or session ownership evidence.
Implementation actors become stale only after three configured heartbeat
intervals are missed, allowing normal coding work between control-plane calls;
the Primary uses its explicit lease duration.
Environment-selected actor identity exists only for debug builds when the
selected deterministic fixture backend explicitly permits it and
`AGSV_DEV_ALLOW_INSECURE_ACTOR=1` is set; live and release backends do not
accept it. `agsv doctor` reports lifecycle-backend readiness and caller-identity
readiness independently.

## Integration

AGSV v0.1 does not push or merge code. The Primary may issue integration authorization for an exact accepted candidate. Provider-native agents or project tooling perform PR and merge operations. Project conventions such as GitHub closing keywords belong in generated role instructions.
