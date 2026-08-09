use std::fmt;

use agsv_protocol::ActorRef;
use agsv_session::SessionHandle;
use serde_json::{Value, json};

const HERDR_IDENTITY_BACKEND: &str = "herdr";
const HERDR_SESSION_BACKEND: &str = "herdr";
const HERDR_BINDING_KIND: &str = "herdr_pane";
const INSECURE_DEBUG_IDENTITY_BACKEND: &str = "insecure_debug";

/// Opaque caller evidence resolved once for one control-plane invocation.
///
/// Session lifecycle handles are not authentication credentials. A bound
/// context must still resolve through the durable actor-binding store and its
/// actor-generation fence before the caller is authenticated.
pub(crate) enum CallerContext {
    BoundSession(BoundSessionIdentity),
    InsecureDebug(InsecureActorIdentity),
    Unavailable(UnavailableIdentity),
}

impl fmt::Debug for CallerContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundSession(identity) => formatter
                .debug_struct("BoundSession")
                .field("identity_backend", &identity.identity_backend)
                .field("binding", &identity.binding)
                .field("managed_environment", &identity.managed_environment)
                .finish(),
            Self::InsecureDebug(identity) => formatter
                .debug_struct("InsecureDebug")
                .field("actor_present", &identity.actor_id.is_some())
                .field("role_present", &identity.role.is_some())
                .finish(),
            Self::Unavailable(identity) => formatter
                .debug_struct("Unavailable")
                .field("identity_backend", &identity.identity_backend)
                .field("required", &identity.required)
                .field("managed_environment", &identity.managed_environment)
                .finish(),
        }
    }
}

pub(crate) struct CallerBinding {
    kind: &'static str,
    value: String,
}

impl CallerBinding {
    pub(crate) const fn kind(&self) -> &'static str {
        self.kind
    }

    pub(crate) fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for CallerBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallerBinding")
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Redacted bridge from authenticated caller evidence to a compatible
/// lifecycle notification route.
pub(crate) struct PrimaryNotificationEndpoint<'a> {
    compatible_backend: &'static str,
    route: &'a str,
}

impl PrimaryNotificationEndpoint<'_> {
    pub(crate) fn handle_for(&self, session_backend: &str) -> Option<SessionHandle> {
        (session_backend == self.compatible_backend).then(|| SessionHandle {
            backend: self.compatible_backend.to_owned(),
            external_id: self.route.to_owned(),
            resume_token: Some(self.route.to_owned()),
        })
    }
}

impl fmt::Debug for PrimaryNotificationEndpoint<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrimaryNotificationEndpoint")
            .field("compatible_backend", &self.compatible_backend)
            .field("route", &"<redacted>")
            .finish()
    }
}

pub(crate) struct InsecureActorIdentity {
    actor_id: Option<String>,
    role: Option<String>,
}

impl InsecureActorIdentity {
    pub(crate) fn actor_id(&self) -> Option<&str> {
        self.actor_id.as_deref()
    }

    pub(crate) fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }
}

pub(crate) struct BoundSessionIdentity {
    identity_backend: &'static str,
    binding: CallerBinding,
    managed_environment: bool,
}

pub(crate) struct UnavailableIdentity {
    identity_backend: &'static str,
    required: bool,
    managed_environment: bool,
}

#[derive(Default)]
struct CallerEnvironment {
    managed_environment: bool,
    pane_id: Option<String>,
    insecure_switch: bool,
    actor_id: Option<String>,
    actor_role: Option<String>,
}

impl CallerEnvironment {
    fn capture() -> Self {
        Self {
            managed_environment: std::env::var("HERDR_ENV").as_deref() == Ok("1"),
            pane_id: std::env::var("HERDR_PANE_ID")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            insecure_switch: std::env::var("AGSV_DEV_ALLOW_INSECURE_ACTOR").as_deref() == Ok("1"),
            actor_id: std::env::var("AGSV_ACTOR_ID").ok(),
            actor_role: std::env::var("AGSV_ACTOR_ROLE").ok(),
        }
    }
}

/// Boundary implemented by concrete sources of invocation caller identity.
trait CallerIdentityBackend {
    fn name(&self) -> &'static str;
    fn capture(&self, environment: &CallerEnvironment) -> CallerContext;
}

struct HerdrCallerIdentityBackend;

impl CallerIdentityBackend for HerdrCallerIdentityBackend {
    fn name(&self) -> &'static str {
        HERDR_IDENTITY_BACKEND
    }

    fn capture(&self, environment: &CallerEnvironment) -> CallerContext {
        match environment.pane_id.as_ref() {
            Some(pane_id) => CallerContext::BoundSession(BoundSessionIdentity {
                identity_backend: self.name(),
                binding: CallerBinding {
                    kind: HERDR_BINDING_KIND,
                    value: pane_id.clone(),
                },
                managed_environment: environment.managed_environment,
            }),
            None => CallerContext::Unavailable(UnavailableIdentity {
                identity_backend: self.name(),
                required: true,
                managed_environment: environment.managed_environment,
            }),
        }
    }
}

struct InsecureDebugCallerIdentityBackend;

impl CallerIdentityBackend for InsecureDebugCallerIdentityBackend {
    fn name(&self) -> &'static str {
        INSECURE_DEBUG_IDENTITY_BACKEND
    }

    fn capture(&self, environment: &CallerEnvironment) -> CallerContext {
        CallerContext::InsecureDebug(InsecureActorIdentity {
            actor_id: environment.actor_id.clone(),
            role: environment.actor_role.clone(),
        })
    }
}

/// Resolves concrete caller evidence while keeping it independent from session
/// lifecycle dispatch.
pub(crate) struct CallerIdentityDriver {
    lifecycle_backend: String,
    context: CallerContext,
}

impl CallerIdentityDriver {
    pub(crate) fn from_environment(
        lifecycle_backend: &str,
        lifecycle_permits_insecure: bool,
    ) -> Self {
        let environment = CallerEnvironment::capture();
        Self::from_snapshot(
            lifecycle_backend,
            lifecycle_permits_insecure,
            cfg!(debug_assertions),
            &environment,
        )
    }

    fn from_snapshot(
        lifecycle_backend: &str,
        lifecycle_permits_insecure: bool,
        debug_build: bool,
        environment: &CallerEnvironment,
    ) -> Self {
        let context = if debug_build && lifecycle_permits_insecure && environment.insecure_switch {
            InsecureDebugCallerIdentityBackend.capture(environment)
        } else if environment.pane_id.is_some() {
            HerdrCallerIdentityBackend.capture(environment)
        } else if lifecycle_permits_insecure {
            CallerContext::Unavailable(UnavailableIdentity {
                identity_backend: INSECURE_DEBUG_IDENTITY_BACKEND,
                required: false,
                managed_environment: environment.managed_environment,
            })
        } else {
            HerdrCallerIdentityBackend.capture(environment)
        };
        Self {
            lifecycle_backend: lifecycle_backend.to_owned(),
            context,
        }
    }

    pub(crate) const fn context(&self) -> &CallerContext {
        &self.context
    }

    pub(crate) fn binding_for_launched_session(
        backend: &str,
        resume_token: Option<&str>,
    ) -> Option<CallerBinding> {
        (backend == HERDR_SESSION_BACKEND)
            .then_some(resume_token)
            .flatten()
            .filter(|value| !value.is_empty())
            .map(|value| CallerBinding {
                kind: HERDR_BINDING_KIND,
                value: value.to_owned(),
            })
    }

    pub(crate) fn diagnostics(
        &self,
        binding_actor: Option<&ActorRef>,
        binding_ready: bool,
    ) -> Value {
        match &self.context {
            CallerContext::BoundSession(identity) => json!({
                "identity_backend": identity.identity_backend,
                "session_backend": self.lifecycle_backend,
                "required": true,
                "ready": identity.managed_environment && binding_ready,
                "herdr_environment": identity.managed_environment,
                "pane_present": true,
                "binding_ready": binding_ready,
                "actor": binding_actor,
                "insecure_debug_enabled": false,
            }),
            CallerContext::InsecureDebug(identity) => json!({
                "identity_backend": INSECURE_DEBUG_IDENTITY_BACKEND,
                "session_backend": self.lifecycle_backend,
                "required": false,
                "ready": true,
                "reason": "deterministic fixture identity is enabled explicitly for this debug build",
                "actor_present": identity.actor_id.is_some(),
                "insecure_debug_enabled": true,
            }),
            CallerContext::Unavailable(identity) => json!({
                "identity_backend": identity.identity_backend,
                "session_backend": self.lifecycle_backend,
                "required": identity.required,
                "ready": !identity.required,
                "reason": (!identity.required).then_some("deterministic fixture backend does not require a live caller session"),
                "herdr_environment": identity.managed_environment,
                "pane_present": false,
                "binding_ready": false,
                "insecure_debug_enabled": false,
            }),
        }
    }

    pub(crate) const fn threat_model() -> &'static str {
        "Caller identity backends bind opaque invocation evidence to fenced actor generations. The Herdr backend prevents accidental or cross-pane impersonation; processes with the same Unix account and permission to inspect that account's environment or state are outside this boundary."
    }

    pub(crate) const fn insecure_debug_selected(&self) -> bool {
        matches!(self.context, CallerContext::InsecureDebug(_))
    }
}

impl CallerContext {
    pub(crate) const fn binding(&self) -> Option<&CallerBinding> {
        match self {
            Self::BoundSession(identity) => Some(&identity.binding),
            Self::InsecureDebug(_) | Self::Unavailable(_) => None,
        }
    }

    pub(crate) const fn insecure_actor(&self) -> Option<&InsecureActorIdentity> {
        match self {
            Self::InsecureDebug(identity) => Some(identity),
            Self::BoundSession(_) | Self::Unavailable(_) => None,
        }
    }

    pub(crate) fn primary_notification_endpoint(&self) -> Option<PrimaryNotificationEndpoint<'_>> {
        let identity = match self {
            Self::BoundSession(identity) if identity.identity_backend == HERDR_IDENTITY_BACKEND => {
                identity
            }
            Self::BoundSession(_) | Self::InsecureDebug(_) | Self::Unavailable(_) => return None,
        };
        Some(PrimaryNotificationEndpoint {
            compatible_backend: HERDR_SESSION_BACKEND,
            route: identity.binding.value(),
        })
    }

    pub(crate) fn matches_persisted_session(
        &self,
        backend: &str,
        resume_token: Option<&str>,
    ) -> bool {
        let Some(binding) = self.binding() else {
            return false;
        };
        backend == HERDR_SESSION_BACKEND && resume_token == Some(binding.value())
    }
}

#[cfg(test)]
mod tests {
    use super::{CallerEnvironment, CallerIdentityDriver};

    fn environment() -> CallerEnvironment {
        CallerEnvironment {
            managed_environment: true,
            pane_id: Some("secret-pane-id".to_owned()),
            insecure_switch: false,
            actor_id: None,
            actor_role: None,
        }
    }

    #[test]
    fn bound_identity_is_opaque_and_redacted() {
        let environment = environment();
        let driver = CallerIdentityDriver::from_snapshot("herdr", false, true, &environment);
        let binding = driver.context().binding().unwrap();
        assert_eq!(binding.kind(), "herdr_pane");
        assert_eq!(binding.value(), "secret-pane-id");
        assert!(!format!("{:?}", driver.context()).contains("secret-pane-id"));
        assert!(
            driver
                .context()
                .matches_persisted_session("herdr", Some("secret-pane-id"))
        );
        assert!(
            !driver
                .context()
                .matches_persisted_session("fake", Some("secret-pane-id"))
        );
        let endpoint = driver.context().primary_notification_endpoint().unwrap();
        assert!(!format!("{endpoint:?}").contains("secret-pane-id"));
        let notification = endpoint.handle_for("herdr").unwrap();
        assert_eq!(notification.backend, "herdr");
        assert_eq!(notification.external_id, "secret-pane-id");
        assert_eq!(notification.resume_token.as_deref(), Some("secret-pane-id"));
        assert!(endpoint.handle_for("fake").is_none());
    }

    #[test]
    fn insecure_identity_requires_every_gate_and_takes_precedence() {
        let mut selected = environment();
        selected.insecure_switch = true;
        selected.actor_id = Some("primary-debug".to_owned());
        selected.actor_role = Some("primary".to_owned());
        let driver = CallerIdentityDriver::from_snapshot("fake", true, true, &selected);
        let insecure = driver.context().insecure_actor().unwrap();
        assert_eq!(insecure.actor_id(), Some("primary-debug"));
        assert_eq!(insecure.role(), Some("primary"));
        assert!(driver.context().binding().is_none());

        for (permitted, debug_build, switch) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            let mut rejected = environment();
            rejected.insecure_switch = switch;
            rejected.actor_id = Some("primary-debug".to_owned());
            let driver =
                CallerIdentityDriver::from_snapshot("fake", permitted, debug_build, &rejected);
            assert!(driver.context().insecure_actor().is_none());
            assert!(driver.context().binding().is_some());
        }
    }

    #[test]
    fn selected_insecure_identity_does_not_fall_back_when_actor_is_missing() {
        let mut selected = environment();
        selected.insecure_switch = true;
        let driver = CallerIdentityDriver::from_snapshot("fake", true, true, &selected);
        let insecure = driver.context().insecure_actor().unwrap();
        assert_eq!(insecure.actor_id(), None);
        assert!(driver.context().binding().is_none());
    }

    #[test]
    fn fixture_doctor_remains_ready_without_an_actor_credential() {
        let environment = CallerEnvironment::default();
        let driver = CallerIdentityDriver::from_snapshot("fake", true, true, &environment);
        let diagnostics = driver.diagnostics(None, false);
        assert_eq!(diagnostics["required"], false);
        assert_eq!(diagnostics["ready"], true);
        assert_eq!(diagnostics["identity_backend"], "insecure_debug");
    }

    #[test]
    fn herdr_doctor_requires_environment_and_a_durable_binding() {
        let environment = environment();
        let driver = CallerIdentityDriver::from_snapshot("herdr", false, true, &environment);
        let unbound = driver.diagnostics(None, false);
        assert_eq!(unbound["ready"], false);
        let bound = driver.diagnostics(None, true);
        assert_eq!(bound["ready"], true);

        let environment = CallerEnvironment::default();
        let missing = CallerIdentityDriver::from_snapshot("herdr", false, true, &environment);
        assert_eq!(missing.diagnostics(None, false)["pane_present"], false);
        assert_eq!(missing.diagnostics(None, false)["ready"], false);
    }
}
