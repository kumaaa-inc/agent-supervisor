mod cli;
mod config;
mod init;
mod output;
mod secure_fs;

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
        Command::Config(command) => config::execute(&cli.workspace, command),
        command => {
            let loaded = config::load(&cli.workspace)?;
            let (operation, request) = command.backend_request();
            let configuration = loaded.summary();
            Err(CliError::backend_unavailable(
                operation,
                &request,
                &configuration,
            ))
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

    const DOCUMENTED_COMMANDS: &[&[&str]] = &[
        &["agsv", "init"],
        &["agsv", "start"],
        &["agsv", "stop"],
        &["agsv", "status"],
        &["agsv", "doctor"],
        &["agsv", "attach"],
        &["agsv", "events"],
        &[
            "agsv",
            "team",
            "create",
            "team-a",
            "--operation-id",
            "team-create-a",
        ],
        &["agsv", "team", "list"],
        &["agsv", "team", "show", "team-a"],
        &["agsv", "team", "pause", "team-a"],
        &["agsv", "team", "resume", "team-a"],
        &["agsv", "actor", "list"],
        &["agsv", "actor", "show", "actor-a"],
        &["agsv", "actor", "stop", "actor-a"],
        &["agsv", "actor", "replace", "actor-a"],
        &[
            "agsv",
            "run",
            "create",
            "--team",
            "team-a",
            "--operation-id",
            "run-create-a",
        ],
        &["agsv", "run", "list"],
        &["agsv", "run", "show", "run-a"],
        &["agsv", "run", "pause", "run-a"],
        &["agsv", "run", "resume", "run-a"],
        &["agsv", "run", "cancel", "run-a"],
        &[
            "agsv",
            "request",
            "create",
            "--team",
            "team-a",
            "--title",
            "work",
            "--operation-id",
            "request-create-a",
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
            "agsv",
            "message",
            "send",
            "--to",
            "actor-a",
            "--kind",
            "progress",
            "--body",
            "working",
            "--operation-id",
            "message-send-a",
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

    #[test]
    fn complete_documented_command_tree_parses() {
        for args in DOCUMENTED_COMMANDS {
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

    #[test]
    fn accepts_sha1_and_sha256_object_ids() {
        let sha1 = "0123456789abcdef0123456789abcdef01234567";
        let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(cli::validate_sha(sha1).as_deref(), Ok(sha1));
        assert_eq!(cli::validate_sha(sha256).as_deref(), Ok(sha256));

        for args in [
            vec![
                "agsv",
                "request",
                "complete",
                "request-a",
                "--candidate-sha",
                sha256,
            ],
            vec![
                "agsv",
                "decision",
                "submit",
                "--request",
                "request-a",
                "--candidate-sha",
                sha256,
                "--decision",
                "accepted",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
    }

    #[test]
    fn create_and_send_commands_require_operation_ids() {
        let commands: &[&[&str]] = &[
            &["agsv", "team", "create", "team-a"],
            &["agsv", "run", "create", "--team", "team-a"],
            &[
                "agsv", "request", "create", "--team", "team-a", "--title", "work",
            ],
            &[
                "agsv", "message", "send", "--to", "actor-a", "--kind", "progress", "--body",
                "working",
            ],
        ];

        for args in commands {
            assert!(
                Cli::try_parse_from(*args).is_err(),
                "operation ID unexpectedly optional for {args:?}"
            );
        }
        assert!(
            Cli::try_parse_from(["agsv", "team", "create", "team-a", "--operation-id", " ",])
                .is_err()
        );
    }
}
