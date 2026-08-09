use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(
    name = "agsv",
    version,
    about = "Durable control plane for top-level agent orchestrators",
    color = clap::ColorChoice::Never
)]
pub(crate) struct Cli {
    /// Emit a stable machine-readable JSON envelope.
    #[arg(long, global = true)]
    pub(crate) json: bool,

    /// Repository workspace containing .agent-supervisor.
    #[arg(long, global = true, default_value = ".", value_name = "PATH")]
    pub(crate) workspace: PathBuf,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Initialize tracked project configuration and role instructions.
    Init,
    /// Start the workspace daemon.
    Start(StartArgs),
    /// Stop the workspace daemon.
    Stop(StopArgs),
    /// Show daemon and workspace status.
    Status,
    /// Diagnose configured enforcement and runtime capabilities.
    Doctor,
    /// Attach to an orchestrator session.
    Attach(AttachArgs),
    /// Read the append-only workspace event stream.
    Events(EventsArgs),
    /// Manage implementation teams.
    #[command(subcommand)]
    Team(TeamCommand),
    /// Manage top-level orchestrator actors.
    #[command(subcommand)]
    Actor(ActorCommand),
    /// Manage durable execution runs.
    #[command(subcommand)]
    Run(RunCommand),
    /// Manage implementation requests.
    #[command(subcommand)]
    Request(RequestCommand),
    /// Exchange durable mailbox messages.
    #[command(subcommand)]
    Message(MessageCommand),
    /// Submit review decisions for immutable candidates.
    #[command(subcommand)]
    Decision(DecisionCommand),
    /// Retrieve durable context for an orchestrator.
    Context(ContextArgs),
    /// Reconcile durable state with Git and the session backend.
    Reconcile,
    /// Inspect tracked workspace configuration.
    #[command(subcommand)]
    Config(ConfigCommand),
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct StartArgs {
    /// Keep the daemon attached to this terminal.
    #[arg(long)]
    foreground: bool,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct StopArgs {
    /// Stop even when actors still hold healthy leases.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct AttachArgs {
    /// Actor to attach to. Defaults to the active Primary.
    #[arg(long)]
    actor: Option<String>,
    /// Team whose active implementation actor should be attached.
    #[arg(long, conflicts_with = "actor")]
    team: Option<String>,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct EventsArgs {
    /// Continue streaming new events.
    #[arg(long)]
    follow: bool,
    /// Maximum historical events to return before following.
    #[arg(long, default_value_t = 100)]
    limit: u32,
}

#[derive(Debug, Subcommand)]
pub(crate) enum TeamCommand {
    /// Create and launch an isolated implementation team.
    Create(TeamCreateArgs),
    /// List teams in the workspace.
    List,
    /// Show a team and its active actors and work.
    Show(IdArgs),
    /// Pause assignment and execution for a team.
    Pause(IdArgs),
    /// Resume a paused team.
    Resume(IdArgs),
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct TeamCreateArgs {
    /// Stable human-readable team name.
    name: String,
    /// Isolated worktree or working directory for the team.
    #[arg(long)]
    working_directory: Option<PathBuf>,
    /// Number of implementation orchestrators to launch.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..))]
    orchestrators: u16,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ActorCommand {
    /// List registered top-level orchestrators.
    List(ActorListArgs),
    /// Show actor identity, presence, and lease state.
    Show(IdArgs),
    /// Stop an actor through its runtime adapter.
    Stop(ReasonedIdArgs),
    /// Fence and replace an unhealthy or stale actor.
    Replace(ReasonedIdArgs),
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct ActorListArgs {
    /// Limit results to one team.
    #[arg(long)]
    team: Option<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RunCommand {
    /// Create a durable execution run for a team.
    Create(RunCreateArgs),
    /// List runs, optionally scoped to one team.
    List(TeamFilterArgs),
    /// Show a run and its fencing epochs.
    Show(IdArgs),
    /// Pause a run.
    Pause(IdArgs),
    /// Resume a paused run.
    Resume(IdArgs),
    /// Cancel a run.
    Cancel(ReasonedIdArgs),
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct RunCreateArgs {
    /// Team that owns the run.
    #[arg(long)]
    team: String,
    /// Optional implementation request to assign initially.
    #[arg(long)]
    request: Option<String>,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct TeamFilterArgs {
    /// Limit results to one team.
    #[arg(long)]
    team: Option<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RequestCommand {
    /// Create a durable implementation request.
    Create(RequestCreateArgs),
    /// List requests, optionally scoped to one team.
    List(RequestListArgs),
    /// Show a request, assignment, and candidate history.
    Show(IdArgs),
    /// Claim a request for an implementation actor.
    Claim(RequestClaimArgs),
    /// Mark a claimed request blocked.
    Block(RequestBlockArgs),
    /// Complete a request with an immutable candidate SHA.
    Complete(RequestCompleteArgs),
    /// Cancel a request.
    Cancel(ReasonedIdArgs),
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct RequestCreateArgs {
    /// Team that should implement the request.
    #[arg(long)]
    team: String,
    /// Short request title.
    #[arg(long)]
    title: String,
    /// Detailed scope and acceptance criteria.
    #[arg(long)]
    body: Option<String>,
    /// Caller-supplied idempotency key.
    #[arg(long)]
    idempotency_key: Option<String>,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct RequestListArgs {
    /// Limit results to one team.
    #[arg(long)]
    team: Option<String>,
    /// Limit results to a lifecycle state.
    #[arg(long)]
    state: Option<String>,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct RequestClaimArgs {
    /// Request identifier.
    id: String,
    /// Implementation actor claiming the request.
    #[arg(long)]
    actor: String,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct RequestBlockArgs {
    /// Request identifier.
    id: String,
    /// Actionable reason that work cannot proceed.
    #[arg(long)]
    reason: String,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct RequestCompleteArgs {
    /// Request identifier.
    id: String,
    /// Full immutable Git commit SHA for review.
    #[arg(long, value_parser = validate_sha)]
    candidate_sha: String,
    /// Summary of verification evidence.
    #[arg(long)]
    evidence: Option<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum MessageCommand {
    /// Send a typed durable message.
    Send(MessageSendArgs),
    /// Read an actor's durable inbox.
    Inbox(MessageInboxArgs),
    /// Acknowledge a delivered message.
    Ack(MessageAckArgs),
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct MessageSendArgs {
    /// Destination actor or team identifier.
    #[arg(long)]
    to: String,
    /// Protocol message kind.
    #[arg(long)]
    kind: String,
    /// Message content.
    #[arg(long)]
    body: String,
    /// Related team, when applicable.
    #[arg(long)]
    team: Option<String>,
    /// Related request, when applicable.
    #[arg(long)]
    request: Option<String>,
    /// Caller-supplied idempotency key.
    #[arg(long)]
    idempotency_key: Option<String>,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct MessageInboxArgs {
    /// Actor whose inbox should be read.
    #[arg(long)]
    actor: String,
    /// Include already acknowledged messages.
    #[arg(long)]
    include_acked: bool,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct MessageAckArgs {
    /// Message identifier.
    id: String,
    /// Actor acknowledging delivery.
    #[arg(long)]
    actor: Option<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum DecisionCommand {
    /// Accept or reject an immutable candidate after fresh review.
    Submit(DecisionSubmitArgs),
}

#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Decision {
    Accepted,
    Rejected,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct DecisionSubmitArgs {
    /// Reviewed request identifier.
    #[arg(long)]
    request: String,
    /// Full immutable Git commit SHA that was reviewed.
    #[arg(long, value_parser = validate_sha)]
    candidate_sha: String,
    /// Review outcome.
    #[arg(long)]
    decision: Decision,
    /// Review findings or acceptance rationale.
    #[arg(long)]
    summary: Option<String>,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct ContextArgs {
    /// Include identity, leases, assignments, and unacknowledged mailbox state.
    #[arg(long)]
    bootstrap: bool,
    /// Actor receiving the context. Defaults to the active Primary.
    #[arg(long)]
    actor: Option<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ConfigCommand {
    /// Show the effective tracked and local configuration inputs.
    Show,
    /// Validate configuration and referenced role files.
    Validate,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct IdArgs {
    /// Domain object identifier.
    id: String,
}

#[derive(Debug, Args, Serialize)]
pub(crate) struct ReasonedIdArgs {
    /// Domain object identifier.
    id: String,
    /// Audit reason for the operation.
    #[arg(long)]
    reason: Option<String>,
}

impl Command {
    pub(crate) fn operation_name(&self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Start(_) => "start",
            Self::Stop(_) => "stop",
            Self::Status => "status",
            Self::Doctor => "doctor",
            Self::Attach(_) => "attach",
            Self::Events(_) => "events",
            Self::Team(command) => command.backend_request().0,
            Self::Actor(command) => command.backend_request().0,
            Self::Run(command) => command.backend_request().0,
            Self::Request(command) => command.backend_request().0,
            Self::Message(command) => command.backend_request().0,
            Self::Decision(command) => command.backend_request().0,
            Self::Context(_) => "context",
            Self::Reconcile => "reconcile",
            Self::Config(command) => command.operation_name(),
        }
    }

    pub(crate) fn backend_request(&self) -> (&'static str, Value) {
        match self {
            Self::Start(args) => ("start", to_value(args)),
            Self::Stop(args) => ("stop", to_value(args)),
            Self::Status => ("status", json!({})),
            Self::Doctor => ("doctor", json!({})),
            Self::Attach(args) => ("attach", to_value(args)),
            Self::Events(args) => ("events", to_value(args)),
            Self::Team(command) => command.backend_request(),
            Self::Actor(command) => command.backend_request(),
            Self::Run(command) => command.backend_request(),
            Self::Request(command) => command.backend_request(),
            Self::Message(command) => command.backend_request(),
            Self::Decision(command) => command.backend_request(),
            Self::Context(args) => ("context", to_value(args)),
            Self::Reconcile => ("reconcile", json!({})),
            Self::Init | Self::Config(_) => unreachable!("local commands do not reach the backend"),
        }
    }
}

macro_rules! command_impl {
    ($type:ty, $prefix:literal, { $($variant:ident $(($binding:ident))? => $name:literal),+ $(,)? }) => {
        impl $type {
            pub(crate) fn backend_request(&self) -> (&'static str, Value) {
                match self {
                    $(Self::$variant $(($binding))? => (
                        concat!($prefix, ".", $name),
                        command_impl!(@value $($binding)?)
                    )),+
                }
            }
        }
    };
    (@value $binding:ident) => { to_value($binding) };
    (@value) => { json!({}) };
}

// Keep operation names explicit and stable even if display text changes.
command_impl!(TeamCommand, "team", {
    Create(args) => "create",
    List => "list",
    Show(args) => "show",
    Pause(args) => "pause",
    Resume(args) => "resume",
});
command_impl!(ActorCommand, "actor", {
    List(args) => "list",
    Show(args) => "show",
    Stop(args) => "stop",
    Replace(args) => "replace",
});
command_impl!(RunCommand, "run", {
    Create(args) => "create",
    List(args) => "list",
    Show(args) => "show",
    Pause(args) => "pause",
    Resume(args) => "resume",
    Cancel(args) => "cancel",
});
command_impl!(RequestCommand, "request", {
    Create(args) => "create",
    List(args) => "list",
    Show(args) => "show",
    Claim(args) => "claim",
    Block(args) => "block",
    Complete(args) => "complete",
    Cancel(args) => "cancel",
});
command_impl!(MessageCommand, "message", {
    Send(args) => "send",
    Inbox(args) => "inbox",
    Ack(args) => "ack",
});
command_impl!(DecisionCommand, "decision", {
    Submit(args) => "submit",
});

impl ConfigCommand {
    pub(crate) const fn operation_name(&self) -> &'static str {
        match self {
            Self::Show => "config.show",
            Self::Validate => "config.validate",
        }
    }
}

fn to_value(value: &impl Serialize) -> Value {
    serde_json::to_value(value).expect("CLI argument structs are serializable")
}

fn validate_sha(value: &str) -> Result<String, String> {
    let is_full_hex_sha = value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if is_full_hex_sha {
        Ok(value.to_ascii_lowercase())
    } else {
        Err("must be a full 40-character hexadecimal Git SHA".to_owned())
    }
}
