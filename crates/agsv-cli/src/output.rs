use serde::Serialize;
use serde_json::{Value, json};

pub(crate) const ENVELOPE_SCHEMA: &str = "agsv.cli.v1";

pub(crate) type CommandResult = Result<Success, CliError>;

pub(crate) struct Success {
    pub(crate) human: String,
    pub(crate) data: Value,
}

#[derive(Debug)]
pub(crate) struct CliError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) hint: Option<String>,
    pub(crate) details: Value,
    pub(crate) exit_code: u8,
}

#[derive(Serialize)]
pub(crate) struct ErrorEnvelope {
    schema_version: &'static str,
    ok: bool,
    command: String,
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
    details: Value,
}

#[derive(Serialize)]
struct SuccessEnvelope {
    schema_version: &'static str,
    ok: bool,
    command: String,
    data: Value,
}

impl CliError {
    pub(crate) fn io(action: &'static str, path: &std::path::Path, error: &std::io::Error) -> Self {
        Self {
            code: "io_error",
            message: format!("could not {action} {}: {error}", path.display()),
            hint: None,
            details: json!({ "action": action, "path": path }),
            exit_code: 1,
        }
    }

    pub(crate) fn invalid_config(message: impl Into<String>, details: Value) -> Self {
        Self {
            code: "invalid_config",
            message: message.into(),
            hint: Some(
                "inspect `agsv config show` and correct the tracked or local override values"
                    .to_owned(),
            ),
            details,
            exit_code: 1,
        }
    }

    pub(crate) fn unsafe_path(message: impl Into<String>, details: Value) -> Self {
        Self {
            code: "unsafe_path",
            message: message.into(),
            hint: Some("replace symlinks and special files with workspace-owned directories or regular files".to_owned()),
            details,
            exit_code: 1,
        }
    }

    pub(crate) fn backend_unavailable(
        operation: &'static str,
        request: &Value,
        configuration: &Value,
    ) -> Self {
        Self {
            code: "backend_unavailable",
            message: format!("the daemon client is not integrated for `{operation}` yet"),
            hint: Some(
                "runtime-backed commands become available when the daemon adapter is connected"
                    .to_owned(),
            ),
            details: json!({
                "operation": operation,
                "request": request,
                "configuration": configuration,
                "retryable": false,
            }),
            exit_code: 69,
        }
    }
}

impl ErrorEnvelope {
    pub(crate) fn usage(message: String) -> Self {
        Self {
            schema_version: ENVELOPE_SCHEMA,
            ok: false,
            command: "cli".to_owned(),
            error: ErrorBody {
                code: "usage_error",
                message,
                hint: Some("run `agsv --help` for the command tree".to_owned()),
                details: json!({}),
            },
        }
    }

    fn from_error(command: &str, error: &CliError) -> Self {
        Self {
            schema_version: ENVELOPE_SCHEMA,
            ok: false,
            command: command.to_owned(),
            error: ErrorBody {
                code: error.code,
                message: error.message.clone(),
                hint: error.hint.clone(),
                details: error.details.clone(),
            },
        }
    }
}

pub(crate) fn success_json(command: &str, data: Value) -> serde_json::Result<String> {
    serde_json::to_string(&SuccessEnvelope {
        schema_version: ENVELOPE_SCHEMA,
        ok: true,
        command: command.to_owned(),
        data,
    })
}

pub(crate) fn error_json(command: &str, error: &CliError) -> serde_json::Result<String> {
    serde_json::to_string(&ErrorEnvelope::from_error(command, error))
}
