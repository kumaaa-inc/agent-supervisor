# Agent Supervisor

Agent Supervisor (`agsv`) is a local, durable control plane that connects a human-facing Primary Orchestrator with one or more Implementation Orchestrators. It provides typed messages, team isolation, acknowledgements, leases, fencing epochs, recovery, and replaceable session/runtime adapters while leaving native subagent execution to Claude Code and Codex.

The initial release targets macOS with Herdr, Claude Code, and Codex. See [the architecture](docs/architecture.md) and [v0.1 scope](docs/v0.1.md).

