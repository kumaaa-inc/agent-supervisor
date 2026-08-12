---
name: agsv
description: Operate Agent Supervisor (AGSV) as any authenticated top-level orchestrator. Use when a Claude Code, Codex, or other agent needs to start or recover AGSV, discover its durable Primary or Implementation role, create or work in teams, exchange acknowledged messages, handle requests and runs, review or report immutable candidate SHAs, authorize integration, diagnose enforcement, or reconcile workspace state.
---

# Agent Supervisor

Use AGSV as the durable source of orchestrator identity, role, teams, requests, messages, decisions, and acknowledgements. Never infer the current role from the provider: Claude Code, Codex, and future runtimes may serve in either role.

## Enter the authenticated context

Use `agsv` from `PATH` unless a managed launch prompt supplies an absolute AGSV command; in that case, use the supplied command for every invocation in that session.

When the human asks the current session to initialize AGSV, run:

```text
agsv --json config validate
agsv --json start
agsv --json context --bootstrap
```

On a managed launch or recovery, start with `agsv --json context --bootstrap`. Read the returned `actor.role`, `role`, `team`, `assignments`, and `inbox`. Treat the returned role instructions as authoritative for the authenticated actor. Do not self-assign a role, infer one from the provider, or use `--actor` to select another identity.

Use zero-config mode unless the project asks for tracked customization. Run `agsv init` only to materialize project-owned configuration and role files. Never edit `.agent-supervisor/runtime/` or user-scoped control state directly. Linked worktrees discover one workspace through the Git common directory; run commands from the assigned worktree without pointing `--workspace` at the Primary checkout.

## Understand configured boundaries

Treat runtime adapters, session lifecycle backends, and caller identity as
separate boundaries. An actor profile selects its launch mode, capabilities,
and role instructions. Runtime-launched profiles also select runtime, model,
and effort. Bound profiles do not: they attach an existing caller session, so
those launch fields are explicitly not applicable. The workspace selects the
default session backend, while every durable session records the backend and
runtime that own it. Caller identity comes from the authenticated pane binding,
never from a lifecycle handle or a provider name.

The built-in Primary profile is bound to the human-facing pane that bootstraps
it; AGSV does not launch it through a runtime adapter. The built-in
Implementation profile uses `gpt-5.6-sol` with `xhigh` effort. Explicit
runtime-profile values remain authoritative.

Roles are descriptive. Check `profile.capabilities` from `context`: the
`human_facing_primary` capability grants Primary authority and the single
Primary lease, while `implementation_execution` grants request assignment and
Implementation operations. A custom role such as research may intentionally
have neither capability. Do not infer permissions from `actor.role` text.

Team profiles persist `desired_instances` and an assignment policy.
`first_healthy` uses the first healthy desired actor; `least_wip` uses durable
nonterminal assignment counts with stable actor-order tie breaking. Team
creation, resume, and reconciliation converge the desired count. For an
explicit profile, that count is authoritative; `--orchestrators` is retained
for profile-less v0.1 teams.

Team purpose and effective session labels are display-only. Layout-capable
backends may place panes or tabs and update labels according to
`session_layout`; unsupported presentation capabilities never change protocol
success. Herdr launches target the workspace containing the authenticated
Primary pane, not whichever workspace is focused. Use these commands to inspect
the effective configuration and durable owners:

```text
agsv --json config show
agsv --json doctor
agsv --json status
agsv --json events
agsv --json team show <team>
agsv --json reconcile
```

When a project asks to customize these boundaries, run `agsv init` first and
edit the tracked configuration rather than runtime state. Add an actor profile
with an explicit role, capability set, registered runtime ID, model, effort,
and role file; add a team profile that references it and sets desired count and
policy. In a config with explicit profile tables, edit those profile fields;
the parallel `[implementation]` and `workspace.*_role` fields remain v0.1
compatibility inputs and do not override explicit profiles. A new runtime or
session backend also requires a code implementation in
its adapter crate and registration in the corresponding compiled registry.
Keep provider-native syntax inside the runtime adapter, keep opaque lifecycle
handles inside the session backend, and then run `config validate` and `doctor`.

## Preserve protocol guarantees

- Use `--json` for machine-readable operations.
- Supply a stable `--operation-id` for every mutation and acknowledgement. Reuse the same ID when retrying the same logical operation.
- Read only the authenticated inbox with `message inbox`; acknowledge handled deliveries with `message ack`.
- Treat full 40- or 64-hex Git object IDs as immutable candidate evidence.
- Trust executable checks, Git evidence, and exact SHAs rather than agent prose.
- Do not push or merge merely because a candidate or review exists. Follow exact-SHA integration authorization and the project's contribution workflow.
- Run `agsv --json context` during long work to renew the authenticated actor heartbeat and refresh durable assignments.
- To leave a managed generation, run `agsv --json actor shutdown --operation-id <stable-id>`. The declaration durably stops the actor and session before the backend stop. Its binding remains read-only; use `context --bootstrap` for a fresh fenced generation. A Primary should run `stop --force` first only when the independent workspace controller must also become inactive.

## Follow the returned role

### Primary

Only when authenticated context shows `human_facing_primary` capability and the
actor holds the active Primary lease, act as the sole human-facing
orchestrator. Preserve intent, create isolated teams, delegate implementation,
monitor durable state, run fresh candidate review, submit decisions, and
authorize integration. AGSV wakes the bound Primary pane when an Implementation
Orchestrator sends a durable message; read and acknowledge the authenticated
inbox on that turn. Do not bypass Implementation teams by editing their code.

```text
agsv --json team create <name> --purpose <display-purpose> --operation-id <stable-id>
agsv --json team update <team> --purpose <display-purpose> --operation-id <stable-id>
agsv --json request create --team <team> --title <title> --body <scope-and-acceptance-criteria> --operation-id <stable-id>
agsv --json team list
agsv --json request list
agsv --json actor list
agsv --json events
```

When an Implementation actor reports a candidate, verify the exact SHA and evidence in an isolated read-only checkout. Submit the result with:

```text
agsv --json decision submit --request <request> --candidate-sha <sha> --decision accepted|rejected --summary <findings> --operation-id <stable-id>
```

On rejection, send a focused fix request and review the new candidate SHA.
During rework, scoped progress moves the request back to `in_progress`; a later
scoped blocker can move active rework to `blocked`. Both retain the rejected
candidate and decision as a replaceable baseline; the assigned current-epoch
actor must complete with a different immutable SHA. Use the same operation ID
only when retrying that same logical completion. Use `team pause|resume`, `run
pause|resume|cancel`, `request cancel`, `actor replace`, and `reconcile` only
when durable state justifies the transition.

### Implementation

Only when authenticated context shows `implementation_execution` capability and
the actor is assigned to an Implementation team, remain inside that team's
working directory and communicate with the Primary through AGSV. A differently
named configured role can follow this workflow when it has the capability; a
role named `implementation` without it cannot. The launch turn is readiness
setup, not permission to invent work: bootstrap, read the inbox once, and if it
is empty report readiness in the current provider turn and stop. Wait for AGSV
to wake the session rather than sleeping or polling.

Before editing, confirm the authenticated assignment:

```text
agsv --json context
agsv --json message inbox
agsv --json request claim <request> --operation-id <stable-id>
```

Use provider-native subagents for implementation, fixes, internal review, and QA as directed by the injected role. Preserve project-owned changes, commit the result, and report the immutable candidate with concrete verification evidence:

```text
agsv --json request complete <request> --candidate-sha <sha> --evidence <summary> --operation-id <stable-id>
```

If blocked, record an actionable reason with `request block`. Respond to a
rejected review with a new commit; never mutate the reviewed candidate. During
rework, scoped progress moves the request to `in_progress`; a later scoped
blocker can move active rework to `blocked`. Neither clears the rejected
candidate or decision. `request complete` must carry the different new SHA,
and its operation ID is reused only for an exact retry. Do not contact the human
directly or perform Primary-only decisions.

## Exchange durable messages

Use typed messages and scoped identifiers rather than encoding protocol identity only in prose:

```text
agsv --json message inbox
agsv --json message ack <message-id> --operation-id <stable-id>
agsv --json message send --to <actor-or-team> --kind <kind> --body <body> --team <team> --request <request> --operation-id <stable-id>
```

For derived routes, omit `--to`; when supplied it is only an assertion. Supported coordination includes consultation request/response, dependency and conflict notices, two-phase handoff, progress, blockers, fix requests, QA results, and integration completion. Ask the human only through the Primary when intent, authority, or a consequential choice is missing.
