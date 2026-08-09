use agsv_core::Supervisor;
use agsv_protocol::{ActorId, ActorRef, ActorRole};

use crate::ControlError;

const COMPONENT_LIMIT: usize = 48;
const LABEL_LIMIT: usize = 96;
const LABEL_BYTE_LIMIT: usize = 256;

pub(crate) struct LabelContext<'a> {
    pub(crate) session_label: &'a str,
    pub(crate) team_purpose: &'a str,
    pub(crate) active_request_title: &'a str,
}

pub(crate) fn session_label(
    supervisor: &Supervisor,
    actor_id: &ActorId,
    team_purpose: &str,
) -> Result<String, ControlError> {
    let actor = supervisor
        .actor(actor_id)
        .ok_or_else(|| ControlError::not_found("actor", actor_id.as_str()))?;
    if actor.role == ActorRole::Primary {
        return Ok("agsv:primary".to_owned());
    }
    let team_id = actor
        .team_id
        .as_ref()
        .ok_or_else(|| ControlError::invalid_request("Implementation actor has no owning team"))?;
    let team = supervisor
        .team(team_id)
        .ok_or_else(|| ControlError::not_found("team", team_id.as_str()))?;
    let ordinal = team
        .actors
        .iter()
        .position(|candidate| candidate == actor_id)
        .ok_or_else(|| {
            ControlError::invalid_request("Implementation actor is absent from its owning team")
        })?
        + 1;
    let team_name = team_id
        .as_str()
        .strip_prefix("team-")
        .unwrap_or(team_id.as_str());
    let mut label = if ordinal == 1 {
        format!("agsv:{team_name}")
    } else {
        format!("agsv:{team_name}:{ordinal}")
    };
    let purpose = clean_component(team_purpose, COMPONENT_LIMIT);
    if !purpose.is_empty() {
        label.push_str(" · ");
        label.push_str(&purpose);
    }
    Ok(truncate(&label, LABEL_LIMIT))
}

pub(crate) fn active_request_title(supervisor: &Supervisor, actor: &ActorRef) -> String {
    let titles = supervisor
        .snapshot()
        .requests
        .into_iter()
        .filter(|request| !request.status.is_terminal())
        .filter(|request| {
            request
                .assignment
                .as_ref()
                .is_some_and(|assignment| assignment.actor == *actor)
        })
        .map(|request| request.specification.title)
        .collect::<Vec<_>>();
    match titles.as_slice() {
        [] => String::new(),
        [title] => clean_component(title, COMPONENT_LIMIT),
        many => format!("{} active requests", many.len()),
    }
}

pub(crate) fn render_label_template(
    template: &str,
    context: &LabelContext<'_>,
) -> Result<String, ControlError> {
    let mut output = String::new();
    let mut chars = template.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        match character {
            '{' if chars.peek().is_some_and(|(_, next)| *next == '{') => {
                chars.next();
                output.push('{');
            }
            '}' if chars.peek().is_some_and(|(_, next)| *next == '}') => {
                chars.next();
                output.push('}');
            }
            '{' => {
                let remaining = &template[index + character.len_utf8()..];
                let end = remaining.find('}').ok_or_else(invalid_template)?;
                let placeholder = &remaining[..end];
                let value = match placeholder {
                    "session_label" => context.session_label,
                    "team_purpose" => context.team_purpose,
                    "active_request_title" => context.active_request_title,
                    _ => return Err(invalid_template()),
                };
                output.push_str(value);
                for _ in 0..=end {
                    chars.next();
                }
            }
            '}' => return Err(invalid_template()),
            value => output.push(value),
        }
    }
    let output = clean_component(&output, LABEL_LIMIT);
    if output.is_empty() {
        Ok(clean_component(context.session_label, LABEL_LIMIT))
    } else {
        Ok(output)
    }
}

fn invalid_template() -> ControlError {
    ControlError::new(
        "invalid_session_label_template",
        "pane label template contains an unknown or unbalanced placeholder",
    )
}

fn clean_component(value: &str, limit: usize) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let compact = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate(&compact, limit)
}

fn truncate(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit && value.len() <= LABEL_BYTE_LIMIT {
        return value.to_owned();
    }
    let keep = limit.saturating_sub(1);
    let byte_budget = LABEL_BYTE_LIMIT.saturating_sub('…'.len_utf8());
    let mut truncated = String::new();
    for character in value.chars().take(keep) {
        if truncated.len() + character.len_utf8() > byte_budget {
            break;
        }
        truncated.push(character);
    }
    truncated.push('…');
    truncated
}

#[cfg(test)]
mod tests {
    use agsv_core::Supervisor;
    use agsv_protocol::{ActorId, PolicyRevision, TeamId, WorkspaceId};

    use super::{LabelContext, render_label_template, session_label};

    #[test]
    fn labels_use_team_order_and_purpose_without_changing_actor_identity() {
        let mut supervisor = Supervisor::new(
            WorkspaceId::new("workspace-labels").unwrap(),
            PolicyRevision::INITIAL,
        );
        let team_id = TeamId::new("team-v02-core").unwrap();
        supervisor.create_team(team_id.clone()).unwrap();
        let first_id = ActorId::new("implementation-logical-a").unwrap();
        let second_id = ActorId::new("implementation-logical-b").unwrap();
        let first = supervisor
            .register_implementation(&team_id, first_id.clone())
            .unwrap();
        let second = supervisor
            .register_implementation(&team_id, second_id.clone())
            .unwrap();
        let before = supervisor.snapshot();

        assert_eq!(
            session_label(&supervisor, &first_id, "runtime adapters").unwrap(),
            "agsv:v02-core · runtime adapters"
        );
        assert_eq!(
            session_label(&supervisor, &second_id, "").unwrap(),
            "agsv:v02-core:2"
        );
        assert_eq!(first.actor_epoch, second.actor_epoch);
        assert_eq!(supervisor.snapshot(), before);
    }

    #[test]
    fn template_supports_all_placeholders_and_literal_braces() {
        let rendered = render_label_template(
            "{{{session_label}}} {team_purpose} {active_request_title}",
            &LabelContext {
                session_label: "agsv:alpha",
                team_purpose: "purpose",
                active_request_title: "request",
            },
        )
        .unwrap();
        assert_eq!(rendered, "{agsv:alpha} purpose request");
        assert_eq!(
            render_label_template(
                "{active_request_title}",
                &LabelContext {
                    session_label: "agsv:alpha",
                    team_purpose: "",
                    active_request_title: "",
                }
            )
            .unwrap(),
            "agsv:alpha"
        );
        let unicode = render_label_template(
            "{active_request_title}",
            &LabelContext {
                session_label: "agsv:alpha",
                team_purpose: "",
                active_request_title: &"🦀".repeat(200),
            },
        )
        .unwrap();
        assert!(unicode.len() <= 256);
        assert!(unicode.ends_with('…'));
        assert!(
            render_label_template(
                "{unknown}",
                &LabelContext {
                    session_label: "x",
                    team_purpose: "",
                    active_request_title: "",
                }
            )
            .is_err()
        );
    }
}
