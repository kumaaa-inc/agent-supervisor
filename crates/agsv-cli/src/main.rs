mod cli;
mod init;
mod output;

use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Parser, error::ErrorKind};
use cli::{Cli, Command};
use output::{CliError, CommandResult, ErrorEnvelope};

fn main() -> ExitCode {
    let args = std::env::args_os().collect::<Vec<_>>();
    let json_requested = args.iter().any(|arg| arg == "--json");

    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            return report_parse_error(&error, json_requested);
        }
    };

    let command_name = cli.command.operation_name();
    let result = execute(&cli);
    report(command_name, cli.json, result)
}

fn execute(cli: &Cli) -> CommandResult {
    match &cli.command {
        Command::Init => init::initialize(&cli.workspace),
        Command::Config(command) => init::config(&cli.workspace, command),
        command => {
            let (operation, request) = command.backend_request();
            Err(CliError::backend_unavailable(operation, &request))
        }
    }
}

fn report(command: &str, json: bool, result: CommandResult) -> ExitCode {
    match result {
        Ok(success) => {
            if json {
                println!(
                    "{}",
                    output::success_json(command, success.data)
                        .expect("success envelopes contain serializable values")
                );
            } else {
                println!("{}", success.human);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            if json {
                eprintln!(
                    "{}",
                    output::error_json(command, &error)
                        .expect("error envelopes contain serializable values")
                );
            } else {
                eprintln!("error [{}]: {}", error.code, error.message);
                if let Some(hint) = &error.hint {
                    eprintln!("hint: {hint}");
                }
            }
            ExitCode::from(error.exit_code)
        }
    }
}

fn report_parse_error(error: &clap::Error, json: bool) -> ExitCode {
    if json {
        let envelope = ErrorEnvelope::usage(error.to_string());
        eprintln!(
            "{}",
            serde_json::to_string(&envelope).expect("usage error envelope is serializable")
        );
    } else {
        let mut stderr = io::stderr().lock();
        let _ = stderr.write_all(error.to_string().as_bytes());
    }
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn complete_documented_command_tree_parses() {
        let commands: &[&[&str]] = &[
            &["agsv", "init"],
            &["agsv", "start"],
            &["agsv", "stop"],
            &["agsv", "status"],
            &["agsv", "doctor"],
            &["agsv", "attach"],
            &["agsv", "events"],
            &["agsv", "team", "create", "team-a"],
            &["agsv", "team", "list"],
            &["agsv", "team", "show", "team-a"],
            &["agsv", "team", "pause", "team-a"],
            &["agsv", "team", "resume", "team-a"],
            &["agsv", "actor", "list"],
            &["agsv", "actor", "show", "actor-a"],
            &["agsv", "actor", "stop", "actor-a"],
            &["agsv", "actor", "replace", "actor-a"],
            &["agsv", "run", "create", "--team", "team-a"],
            &["agsv", "run", "list"],
            &["agsv", "run", "show", "run-a"],
            &["agsv", "run", "pause", "run-a"],
            &["agsv", "run", "resume", "run-a"],
            &["agsv", "run", "cancel", "run-a"],
            &[
                "agsv", "request", "create", "--team", "team-a", "--title", "work",
            ],
            &["agsv", "request", "list"],
            &["agsv", "request", "show", "request-a"],
            &[
                "agsv",
                "request",
                "claim",
                "request-a",
                "--actor",
                "actor-a",
            ],
            &[
                "agsv",
                "request",
                "block",
                "request-a",
                "--reason",
                "waiting",
            ],
            &[
                "agsv",
                "request",
                "complete",
                "request-a",
                "--candidate-sha",
                "0123456789abcdef0123456789abcdef01234567",
            ],
            &["agsv", "request", "cancel", "request-a"],
            &[
                "agsv", "message", "send", "--to", "actor-a", "--kind", "progress", "--body",
                "working",
            ],
            &["agsv", "message", "inbox", "--actor", "actor-a"],
            &["agsv", "message", "ack", "message-a"],
            &[
                "agsv",
                "decision",
                "submit",
                "--request",
                "request-a",
                "--candidate-sha",
                "0123456789abcdef0123456789abcdef01234567",
                "--decision",
                "accepted",
            ],
            &["agsv", "context", "--bootstrap"],
            &["agsv", "reconcile"],
            &["agsv", "config", "show"],
            &["agsv", "config", "validate"],
        ];

        for args in commands {
            assert!(
                Cli::try_parse_from(*args).is_ok(),
                "failed to parse {args:?}"
            );
        }
    }

    #[test]
    fn json_is_global() {
        let cli = Cli::try_parse_from(["agsv", "team", "list", "--json"])
            .expect("global flag should parse after a subcommand");
        assert!(cli.json);
    }

    #[test]
    fn os_string_json_detection_is_exact() {
        let args = [OsString::from("agsv"), OsString::from("--json")];
        assert!(args.iter().any(|arg| arg == "--json"));
    }
}
