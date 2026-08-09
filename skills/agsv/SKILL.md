---
name: agsv
description: Coordinate durable implementation work with Agent Supervisor (AGSV). Use when a Primary Orchestrator needs to initialize or start AGSV, create one or more implementation teams, delegate requests, monitor actors and runs, exchange acknowledged messages, review immutable candidate SHAs, authorize integration, diagnose enforcement, or recover workspace context after a restart.
---

# Agent Supervisor

Act as the Primary Orchestrator and the sole interface to the human. Use natural language with the human, then translate their intent into durable `agsv --json` operations. Let provider-native subagents perform implementation, fresh review, and QA; AGSV coordinates top-level orchestrators and does not replace native subagent systems.

## Start or recover

1. Run `agsv init` once when `.agent-supervisor/config.toml` is absent. Treat generated role files as project-owned after creation.
2. Run `agsv --json config validate`, `agsv --json start`, and `agsv --json doctor`.
3. Run `agsv --json context --bootstrap` to register or resume the current Primary context and recover leases, assignments, and unacknowledged messages.
4. Inspect `agsv --json status` before creating replacements. Resume a healthy actor instead of duplicating it.

Never edit `.agent-supervisor/runtime/` or other daemon state. Use CLI state and typed operations exclusively. Report an unavailable backend honestly rather than simulating successful coordination.

## Delegate implementation

Create an isolated team with `agsv --json team create <name>`. Multiple teams may run concurrently. Use `--working-directory` when the project already selected an isolated worktree, and use `--orchestrators` when one team needs multiple top-level Implementation Orchestrators.

Create scoped work with:

```text
agsv --json request create --team <team> --title <title> --body <scope-and-acceptance-criteria> --idempotency-key <stable-key>
```

Keep implementation, review, and QA inside provider-native subagents. Use `team list|show`, `actor list|show`, `run list|show`, `request list|show`, and `events` to answer human status questions from durable evidence.

## Coordinate messages and blockers

Read `agsv --json message inbox --actor <actor>` regularly. Acknowledge handled messages with `message ack <message-id> --actor <actor>`. Send typed, scoped messages with `message send --to <actor-or-team> --kind <kind> --body <body>` and include `--team` or `--request` when applicable.

When implementation is blocked, preserve its reason in `request block`. Resolve cross-team dependencies through messages rather than hidden filesystem notes. Ask the human only when intent, authority, or a consequential choice is missing.

## Review candidates

Treat only a full immutable Git SHA as a candidate. When an implementation reports readiness:

1. Verify the candidate SHA and evidence.
2. Run a fresh provider-native review and QA against that exact SHA.
3. Submit `decision submit --request <id> --candidate-sha <sha> --decision accepted|rejected --summary <findings>`.
4. On rejection, send a focused fix request and review the new candidate SHA again.
5. Authorize integration only for the exact accepted SHA. AGSV does not push or merge.

Follow project contribution conventions during authorized integration. A PR body may use `Closes #N` when the repository workflow calls for it; issue-closing syntax is not an AGSV protocol invariant.

## Pause, cancel, and reconcile

Use explicit `team pause|resume`, `run pause|resume|cancel`, and `request cancel` operations instead of relying on agent prose. Use `actor replace` only after status shows replacement is needed because replacement fences the old actor. Run `agsv --json reconcile` after daemon or session-backend recovery, then bootstrap context and process the inbox again.
