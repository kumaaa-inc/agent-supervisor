# Architecture

## Boundary

AGSV is the workspace-level protocol between top-level orchestrators. It does not manage their provider-native subagents.

```text
Human
  <-> Primary Orchestrator (configured runtime, active x1)
        <-> AGSV control plane and durable mailbox
              <-> Team X / Implementation Orchestrator (configured runtime)
              <-> Team Y / Implementation Orchestrator (configured runtime)
```

The Primary may use provider-native subagents for design and fresh review. Each
Implementation Orchestrator may use provider-native subagents for
implementation, fixes, and QA.

## Runtime topology

- CLI invocations use an embedded local controller over a fenced,
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

Top-level provider syntax lives behind the `AgentRuntime` adapter boundary in
`agsv-runtime`. The control plane selects an adapter by runtime identifier from
a compile-time registry, supplies model, reasoning-effort, prompt, and session
context as structured values, and passes the resulting invocation to the
selected `SessionBackend`. Codex is the built-in default; Pi is also compiled
and selectable as `pi`. Adding another runtime changes the adapter registry,
not `agsv-core`, `agsv-protocol`, or provider-neutral control flow.

The Pi adapter translates `RuntimeConfig.model` plus an optional reasoning
effort into Pi's model-pattern syntax, using the effort as a `:<thinking>`
suffix. It supplies AGSV role and bootstrap instructions only through
`--append-system-prompt` so durable protocol rules remain system-level, then
uses a separate fixed kickoff after the session is ready to start Pi's first
turn. Exact recovery uses Pi's `--session` identifier. Pi reports no native
sandbox or command-approval enforcement; diagnostics and capability output
remain explicit about that boundary.

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

Configuration resolves at field granularity in this order: embedded defaults,
user configuration, tracked `.agent-supervisor/config.toml`, then project-local
`.agent-supervisor/config.local.toml`. The user file is `config.toml` under
`AGSV_CONFIG_HOME` when set, otherwise under
`$XDG_CONFIG_HOME/agent-supervisor`, or on the supported macOS default at
`~/Library/Application Support/agent-supervisor`. Reading this layer never
creates the directory or writes to the repository. `agsv config show` reports
the loaded layers and a dotted field-to-layer map for every effective value.

The user layer deliberately accepts only `runtime`, `model`, and
`reasoning_effort` under `[implementation]` or an
`[agent_profiles.<name>]` that a built-in or project layer defines, plus a
provider-neutral availability map:

```toml
[runtime_adapters]
codex = true
pi = false
```

`false` disables selecting that compiled adapter; `true` permits it but does
not claim that its executable is installed, which remains runtime diagnostics'
responsibility. Role paths, roles,
capabilities, team profiles, desired counts, assignment policy, session layout,
leases, state paths, and other project decisions are rejected in the user file.

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

State schema admission never converts an older store. A strictly quiescent
sub-floor database is moved intact to a versioned preservation directory. If
it still contains nonterminal session rows, admission derives a blocker digest
from the stored controller marker, session identities and timestamps, actor
heartbeats, source schema, and a fixed 24-hour safety horizon. That horizon is
the maximum Primary lease accepted by released configuration, not a new
configurable upgrade policy. Expired rows remain refused until an operator uses
the dedicated `state preserve-subfloor` command with that exact digest; an
active controller, recent or future activity, and unknown liveness evidence
are non-overridable. The command probes each opaque handle through the backend
recorded beside that session, and both observations must be `missing` or
`stopped`; present, malformed, unavailable, or failed observations refuse. It
then re-reads a coherent SQLite snapshot and repeats the backend proof
immediately before the move. A fully written and fsynced temporary marker is
published without clobber, drives resumable preservation, and is atomically
promoted to the admission receipt only after independently copied files match
the captured source digests and the source paths are removed. This keeps an
older open file descriptor from mutating the preserved inode. Fresh
initialization appends one idempotent `state.schema_admitted` event before
consuming the receipt. Receipt replay verifies the complete main, WAL, and SHM
set against those digests, so operators copy the preservation directory before
opening it with an older SQLite client. Refusals inspect a private raw copy and
verify the source bytes before and after capture, leaving the original bytes
and directory entries unchanged. None of this path runs for a current store's
ordinary load or mutation.

## Review execution

Review sessions are explicit control-plane records, separate from the hot domain
snapshot. `review begin` accepts only the request's current candidate commit,
resolves its exact tree, freezes the trusted configured plan, and materializes a
detached checkout with a private, non-hard-linked Git object database under the
user-scoped state directory. The checkout is reusable for the session. Its
commit, tree, cleanliness, object isolation, and controller-owned path are
rechecked before and after verification. Git configuration, templates, hooks,
and interactive behavior are neutralized during materialization.

Project checks and tool-version probes are structured argument arrays that the
control plane passes directly to the selected executable without adding a
shell. A project may deliberately select an interpreter; its arguments remain
the project's explicit declaration. The control plane resolves and hashes each
executable, runs the version probe and check against that same path, and rejects
an identity change. When supported, an OS write sandbox keeps the exact source
tree read-only while only child build-output and temporary directories are
writable. The environment record states the actual process-containment
class rather than turning platform support into an implicit claim: Linux
bubblewrap uses a parent-death PID namespace, macOS sandbox-exec protects
source writes but only terminates the direct process group, and unsupported
hosts record no containment. Timeout, forced output-limit termination, and
incomplete output capture explicitly state when a detached descendant may
have survived. Incomplete post-parent capture is recorded separately from cap
truncation. A future policy tier may require full containment; R4 records
evidence without gating decisions.

A required-absent variant constructs a controlled PATH and proves that each
declared executable name does not resolve from that PATH before launch. This is
not evidence that the host lacks the binary or that an alias or absolute path
is unreachable. Each stdout/stderr stream is captured in an anonymous
controller-owned file, capped at a 1 MiB content-addressed prefix, and published
to controller-only evidence storage only after its digest is computed;
truncation is recorded and the aggregate attempt budget is 64 MiB.

Each attempt appends correlated environment and check-result records keyed to
the session, request, candidate, frozen plan, check, variant, and attempt
sequence. Raw stdout and stderr stay in controller-only evidence files
referenced by byte count and SHA-256 digest; the child-writable `{artifacts}`
directory is reserved for build outputs and never stores execution evidence.
The environment record contains an allowlist
of OS/architecture, AGSV version, checkout identity, PATH-profile digest,
locale, executable identities and versions, a digest of the actual expanded
declared child environment, and declared optional-binary observations.
Configured literal environment values are frozen into the public durable plan;
operators must use exact `{inherit}` sentinels for secrets/ambient values, whose
expanded bytes are never serialized. Durable running and terminal facts plus
recovery states make retries and crash reconciliation explicit.
These tables and artifacts are read only by review commands and explicit
diagnostics, never by ordinary domain load or mutation.

`status` and `doctor` distinguish configured checks, exact-tree enforcement,
the active OS sandbox, environment evidence, and recovery-required sessions.
Review records are evidence only in this release: acceptance decisions are not
yet gated on a passing verification record.

Actor and team profiles are the persistent configuration boundary for
top-level orchestration. An actor profile selects a descriptive project role,
an open set of capabilities, a runtime/model/effort tuple, and a role file. A
team profile selects its actor profile plus a desired instance count and an
assignment policy. The built-in `primary` and `implementation` profiles preserve
the v0.1 role, capability, and workflow semantics; structurally v0.1
configuration is synthesized into the same effective profiles without writing
files or changing its persisted JSON shape.

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
reconciliation. `agsv team create --profile <team-profile>` selects a
configured profile; without the flag, `workspace.default_team_profile` remains
authoritative. The selected profile snapshot is immutable for that logical
team and appears in team show, status, and the `team.created` audit event.
Recreating a team with a different profile is rejected instead of silently
changing its runtime or assignment behavior. Request creation applies the
persisted `first_healthy` or `least_wip` policy; least-WIP derives its
deterministic state from durable
nonterminal assignments and uses the team's persisted actor order for ties.
Assignment policy identifiers remain open protocol data, while effective
configuration rejects identifiers that the current controller cannot execute.
Reconciliation reuses healthy sessions and fences only the stale logical actor
being replaced. Surplus actors are stopped only after desired capacity is
healthy and their WIP is zero, so convergence never strands an active
assignment merely to satisfy an instance count.

Team and actor observability projections remain outside the hot domain
snapshot. The store transaction consumes a bounded core delta to advance a
team's last explicit work-activity timestamp and exact nonterminal-request
count, anchor a new actor generation, and credit a request that transitions to
completed. Heartbeats, automatic expiry, reconciliation-only actor
housekeeping, and diagnostic reads do not advance team work activity. This
keeps ordinary load and mutation independent of retained history and avoids
deriving counters by scanning archives. Each projection update also advances a
canonical append-only fact chain, an atomic one-row manifest, and a compact
checkpoint in the domain snapshot. Ordinary load compares only the checkpoint
and manifest; a mismatch records an immutable incident but does not make
status or doctor unavailable. Doctor alone streams and binds the complete fact
chain to the projections. Filesystem and Git inspection occurs only on
explicit reporting and reconciliation paths: it reports a recorded path as
absent, or a present path as inconsistent with durable worktree/session
identity, without implicit repair. Doctor exposes
`teams_without_nonterminal_work` with exact timestamps and inactivity
duration; it embeds neither a recency threshold nor a closure recommendation.

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
An authenticated actor may instead declare its exact generation stopped. The
store commits the actor transition, its persisted session status, the audit
event, and the idempotent result in one transaction before any persisted
session-backend stop. The old caller binding remains readable but cannot
authorize another mutation or heartbeat; only explicit bootstrap may advance
it to a fresh actor epoch. A Primary declaration releases and fences the
Primary lease without changing the workspace controller marker, so stopping
the controller remains a separate explicit operation.
Environment-selected actor identity exists only for debug builds when the
selected deterministic fixture backend explicitly permits it and
`AGSV_DEV_ALLOW_INSECURE_ACTOR=1` is set; live and release backends do not
accept it. `agsv doctor` reports lifecycle-backend readiness and caller-identity
readiness independently.

## Integration

AGSV does not push or merge code. The Primary may issue integration
authorization for an exact accepted candidate. Provider-native agents or
project tooling perform PR and merge operations. Project conventions such as
GitHub closing keywords belong in generated role instructions.
