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
            let settings = loaded.control_settings(&cli.workspace)?;
            let control =
                agsv_control::ControlPlane::open(settings).map_err(CliError::from_control)?;
            let data = control
                .execute(operation, &request)
                .map_err(CliError::from_control)?;
            Ok(output::Success {
                human: serde_json::to_string_pretty(&data)
                    .expect("control-plane results are serializable"),
                data,
            })
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
            "--purpose",
            "runtime adapter boundary",
            "--operation-id",
            "team-create-a",
        ],
        &[
            "agsv",
            "team",
            "create",
            "team-adopted",
            "--working-directory",
            "/tmp/team-adopted",
            "--adopt-working-directory",
            "--operation-id",
            "team-create-adopted",
        ],
        &[
            "agsv",
            "team",
            "close",
            "team-a",
            "--operation-id",
            "team-close-a",
        ],
        &[
            "agsv",
            "team",
            "close",
            "team-b",
            "--when-idle",
            "--operation-id",
            "team-close-when-idle-b",
        ],
        &[
            "agsv",
            "team",
            "update",
            "team-team-a",
            "--purpose",
            "session labels and layout",
            "--operation-id",
            "team-update-a",
        ],
        &["agsv", "team", "list"],
        &["agsv", "team", "show", "team-a"],
        &[
            "agsv",
            "team",
            "pause",
            "team-a",
            "--operation-id",
            "team-pause-a",
        ],
        &[
            "agsv",
            "team",
            "resume",
            "team-a",
            "--operation-id",
            "team-resume-a",
        ],
        &["agsv", "actor", "list"],
        &["agsv", "actor", "show", "actor-a"],
        &[
            "agsv",
            "actor",
            "stop",
            "actor-a",
            "--operation-id",
            "actor-stop-a",
        ],
        &[
            "agsv",
            "actor",
            "replace",
            "actor-a",
            "--operation-id",
            "actor-replace-a",
        ],
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
        &[
            "agsv",
            "run",
            "pause",
            "run-a",
            "--operation-id",
            "run-pause-a",
        ],
        &[
            "agsv",
            "run",
            "resume",
            "run-a",
            "--operation-id",
            "run-resume-a",
        ],
        &[
            "agsv",
            "run",
            "cancel",
            "run-a",
            "--operation-id",
            "run-cancel-a",
        ],
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
            "--operation-id",
            "request-claim-a",
        ],
        &[
            "agsv",
            "request",
            "block",
            "request-a",
            "--reason",
            "waiting",
            "--operation-id",
            "request-block-a",
        ],
        &[
            "agsv",
            "request",
            "complete",
            "request-a",
            "--candidate-sha",
            "0123456789abcdef0123456789abcdef01234567",
            "--operation-id",
            "request-complete-a",
        ],
        &[
            "agsv",
            "request",
            "cancel",
            "request-a",
            "--operation-id",
            "request-cancel-a",
        ],
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
        &["agsv", "message", "inbox"],
        &[
            "agsv",
            "message",
            "ack",
            "message-a",
            "--operation-id",
            "message-ack-a",
        ],
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
            "--close-team",
            "--operation-id",
            "decision-a",
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
                "--operation-id",
                "candidate-sha256",
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
                "--operation-id",
                "decision-sha256",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
    }

    #[test]
    fn create_and_send_commands_require_operation_ids() {
        let commands: &[&[&str]] = &[
            &["agsv", "team", "create", "team-a"],
            &[
                "agsv",
                "team",
                "update",
                "team-team-a",
                "--purpose",
                "new purpose",
            ],
            &["agsv", "team", "close", "team-team-a"],
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
        assert!(
            Cli::try_parse_from([
                "agsv",
                "team",
                "update",
                "team-team-a",
                "--operation-id",
                "team-update-a",
            ])
            .is_err()
        );
    }

    #[test]
    fn team_purpose_commands_use_stable_backend_operations() {
        let create = Cli::try_parse_from([
            "agsv",
            "team",
            "create",
            "v02-core",
            "--purpose",
            "runtime adapter boundary",
            "--operation-id",
            "team-create-v02-core",
        ])
        .expect("team create with purpose should parse");
        let (operation, request) = create.command.backend_request();
        assert_eq!(operation, "team.create");
        assert_eq!(request["purpose"], "runtime adapter boundary");

        let update = Cli::try_parse_from([
            "agsv",
            "team",
            "update",
            "team-v02-core",
            "--purpose",
            "session labels and layout",
            "--operation-id",
            "team-update-v02-core",
        ])
        .expect("team update should parse");
        let (operation, request) = update.command.backend_request();
        assert_eq!(operation, "team.update");
        assert_eq!(request["id"], "team-v02-core");
        assert_eq!(request["purpose"], "session labels and layout");
        assert_eq!(request["operation_id"], "team-update-v02-core");
    }

    #[test]
    fn team_lifecycle_flags_use_stable_backend_requests() {
        let adopted = Cli::try_parse_from([
            "agsv",
            "team",
            "create",
            "adopted",
            "--working-directory",
            "/tmp/adopted",
            "--adopt-working-directory",
            "--operation-id",
            "team-create-adopted",
        ])
        .expect("team create should accept explicit working-directory adoption");
        let (operation, request) = adopted.command.backend_request();
        assert_eq!(operation, "team.create");
        assert_eq!(request["working_directory"], "/tmp/adopted");
        assert_eq!(request["adopt_working_directory"], true);

        assert!(
            Cli::try_parse_from([
                "agsv",
                "team",
                "create",
                "invalid-adoption",
                "--adopt-working-directory",
                "--operation-id",
                "team-create-invalid-adoption",
            ])
            .is_err(),
            "adoption must require an explicit working directory"
        );

        let close = Cli::try_parse_from([
            "agsv",
            "team",
            "close",
            "team-adopted",
            "--when-idle",
            "--operation-id",
            "team-close-adopted",
        ])
        .expect("team close should parse");
        let (operation, request) = close.command.backend_request();
        assert_eq!(operation, "team.close");
        assert_eq!(request["id"], "team-adopted");
        assert_eq!(request["when_idle"], true);
        assert_eq!(request["operation_id"], "team-close-adopted");
    }

    #[test]
    fn accepted_decision_close_team_flag_serializes_for_the_engine() {
        let decision = Cli::try_parse_from([
            "agsv",
            "decision",
            "submit",
            "--request",
            "request-a",
            "--candidate-sha",
            "0123456789abcdef0123456789abcdef01234567",
            "--decision",
            "accepted",
            "--close-team",
            "--operation-id",
            "decision-close-team-a",
        ])
        .expect("accepted decision should accept --close-team");
        let (operation, request) = decision.command.backend_request();
        assert_eq!(operation, "decision.submit");
        assert_eq!(request["close_team"], true);
    }
}
