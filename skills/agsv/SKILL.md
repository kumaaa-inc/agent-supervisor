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

## Preserve protocol guarantees

- Use `--json` for machine-readable operations.
- Supply a stable `--operation-id` for every mutation and acknowledgement. Reuse the same ID when retrying the same logical operation.
- Read only the authenticated inbox with `message inbox`; acknowledge handled deliveries with `message ack`.
- Treat full 40- or 64-hex Git object IDs as immutable candidate evidence.
- Trust executable checks, Git evidence, and exact SHAs rather than agent prose.
- Do not push or merge merely because a candidate or review exists. Follow exact-SHA integration authorization and the project's contribution workflow.
- Run `agsv --json context` during long work to renew the authenticated actor heartbeat and refresh durable assignments.

## Follow the returned role

### Primary

Only when `actor.role` is `primary`, act as the sole human-facing orchestrator. Preserve intent, create isolated teams, delegate implementation, monitor durable state, run fresh candidate review, submit decisions, and authorize integration. Do not bypass Implementation teams by editing their code.

```text
agsv --json team create <name> --operation-id <stable-id>
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

On rejection, send a focused fix request and review the new candidate SHA. Use `team pause|resume`, `run pause|resume|cancel`, `request cancel`, `actor replace`, and `reconcile` only when durable state justifies the transition.

### Implementation

Only when `actor.role` is `implementation`, remain inside the assigned team's working directory and communicate with the Primary through AGSV. The launch turn is readiness setup, not permission to invent work: bootstrap, read the inbox once, and if it is empty report readiness in the current provider turn and stop. Wait for AGSV to wake the session rather than sleeping or polling.

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

If blocked, record an actionable reason with `request block`. Respond to a rejected review with a new commit; never mutate the reviewed candidate. Do not contact the human directly or perform Primary-only decisions.

## Exchange durable messages

Use typed messages and scoped identifiers rather than encoding protocol identity only in prose:

```text
agsv --json message inbox
agsv --json message ack <message-id> --operation-id <stable-id>
agsv --json message send --to <actor-or-team> --kind <kind> --body <body> --team <team> --request <request> --operation-id <stable-id>
```

For derived routes, omit `--to`; when supplied it is only an assertion. Supported coordination includes consultation request/response, dependency and conflict notices, two-phase handoff, progress, blockers, fix requests, QA results, and integration completion. Ask the human only through the Primary when intent, authority, or a consequential choice is missing.
