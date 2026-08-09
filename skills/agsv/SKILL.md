---
name: agsv
description: Coordinate durable implementation work with Agent Supervisor (AGSV). Use when a Primary Orchestrator needs to initialize or start AGSV, create one or more implementation teams, delegate requests, monitor actors and runs, exchange acknowledged messages, review immutable candidate SHAs, authorize integration, diagnose enforcement, or recover workspace context after a restart.
---

# Agent Supervisor

Act as the Primary Orchestrator and the sole interface to the human. Use natural language with the human, then translate their intent into durable `agsv --json` operations. Delegate implementation and QA through AGSV Implementation Orchestrators. Use Primary-native subagents only for design and fresh candidate review.

## Start or recover

1. Use zero-config mode by default: run `agsv --json config validate`, `agsv --json start`, and `agsv --json doctor` without creating repository files. Built-in configuration and roles use user-state runtime storage.
2. Run `agsv init` only when the project wants tracked configuration or customized role instructions. Treat generated files as project-owned after creation.
3. Run `agsv --json context --bootstrap` to register or resume the current Primary context and recover leases, assignments, and unacknowledged messages.
4. Inspect `agsv --json status` before creating replacements. Resume a healthy actor instead of duplicating it.

Never edit `.agent-supervisor/runtime/` or user-scoped control state. Use CLI state and typed operations exclusively. The v0.1 controller is embedded in each CLI invocation; `start` durably marks it active and SQLite preserves the validated workspace snapshot across restarts.

## Delegate implementation

Create an isolated team with `agsv --json team create <name> --operation-id <stable-id>`. Multiple teams may run concurrently. Use `--working-directory` when the project already selected an isolated worktree, and use `--orchestrators` when one team needs multiple top-level Implementation Orchestrators.

Create scoped work with:

```text
agsv --json request create --team <team> --title <title> --body <scope-and-acceptance-criteria> --operation-id <stable-id>
```

The Implementation Orchestrator uses its provider-native subagents for implementation, fixes, internal review, and QA. Every mutating team, actor, run, request, message, acknowledgement, and decision command requires a stable `--operation-id`. Reuse the same ID on a retry; never generate a new ID merely because delivery was uncertain. Use `team list|show`, `actor list|show`, `run list|show`, `request list|show`, and `events` to answer human status questions from durable evidence.

## Coordinate messages and blockers

Read `agsv --json message inbox --actor <actor>` regularly. Acknowledge handled messages with `message ack <message-id> --actor <actor> --operation-id <stable-id>`. Send typed, scoped messages with `message send --to <actor-or-team> --kind <kind> --body <body> --operation-id <stable-id>` and include `--team` or `--request` when applicable.

For cross-team coordination, use the typed fields instead of encoding protocol identity in prose:

```text
agsv --json message send --kind consultation-response --consultation-id <message-id> --body <answer> --operation-id <stable-id>
agsv --json message send --kind dependency-notice --request <blocked-request> --depends-on-request <provider-request> --body <required-contract> --operation-id <stable-id>
agsv --json message send --kind conflict-notice --to <other-team> --resource <path-or-resource> --body <impact> --operation-id <stable-id>
agsv --json message send --kind handoff-offer --request <request> --to <new-team> --body <reason> --operation-id <stable-id>
agsv --json message send --kind handoff-acceptance --handoff-id <handoff-id> --operation-id <stable-id>
```

AGSV derives authenticated actors, team ownership, request/run/assignment fences, current candidate and decision references, and derived routes from durable state. Omit `--to` for derived message kinds; when supplied it is only an assertion and must match the durable route. Report QA with `qa-result --request <request> --outcome passed|failed --body <summary>`, and only the active Primary reports authorized external integration with `integration-complete --request <request>`.

When implementation is blocked, preserve its reason in `request block`. Resolve cross-team dependencies through messages rather than hidden filesystem notes. Ask the human only when intent, authority, or a consequential choice is missing.

## Review candidates

Treat only a full immutable 40- or 64-hex Git object ID as a candidate. When an implementation reports readiness:

1. Verify the candidate SHA and evidence.
2. Launch a fresh Primary-native reviewer in an isolated, read-only checkout at that exact object ID, using the configured review model and effort. The implementation team owns QA; the Primary reviewer independently assesses its evidence and diff.
3. Submit `decision submit --request <id> --candidate-sha <sha> --decision accepted|rejected --summary <findings> --operation-id <stable-id>`. An accepted decision durably emits the separate exact-SHA integration authorization; it does not push or merge.
4. On rejection, send a focused fix request and review the new candidate SHA again.
5. Authorize integration only for the exact accepted SHA. AGSV does not push or merge.

Follow project contribution conventions during authorized integration. A PR body may use `Closes #N` when the repository workflow calls for it; issue-closing syntax is not an AGSV protocol invariant.

## Pause, cancel, and reconcile

Use explicit `team pause|resume`, `run pause|resume|cancel`, and `request cancel` operations instead of relying on agent prose. Use `actor replace` only after status shows replacement is needed because replacement fences the old actor. Run `agsv --json reconcile` after daemon or session-backend recovery, then bootstrap context and process the inbox again.
