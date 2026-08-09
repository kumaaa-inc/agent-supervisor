use std::collections::HashMap;
use std::sync::Mutex;

use crate::{
    LaunchRequest, ResumeRequest, SessionBackend, SessionError, SessionHandle, SessionSnapshot,
    SessionStatus, types::reject_foreign_handle,
};

/// Deterministic observations retained by [`FakeSessionBackend`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FakeEvent {
    Launched {
        actor_id: String,
        session_id: String,
    },
    Resumed {
        actor_id: String,
        session_id: String,
    },
    Message {
        session_id: String,
        body: String,
    },
    Stopped {
        session_id: String,
    },
}

#[derive(Clone)]
struct FakeSession {
    handle: SessionHandle,
    status: SessionStatus,
}

#[derive(Default)]
struct FakeState {
    next_id: u64,
    sessions: HashMap<String, FakeSession>,
    launches: HashMap<String, SessionHandle>,
    events: Vec<FakeEvent>,
}

/// An in-memory backend with stable IDs and idempotent launches.
#[derive(Default)]
pub struct FakeSessionBackend {
    state: Mutex<FakeState>,
}

impl FakeSessionBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_status(
        &self,
        handle: &SessionHandle,
        status: SessionStatus,
    ) -> Result<(), SessionError> {
        let mut state = self.state.lock().map_err(|_| SessionError::Poisoned)?;
        let session = state
            .sessions
            .get_mut(&handle.external_id)
            .ok_or_else(|| SessionError::NotFound(handle.external_id.clone()))?;
        session.status = status;
        Ok(())
    }

    pub fn events(&self) -> Result<Vec<FakeEvent>, SessionError> {
        let state = self.state.lock().map_err(|_| SessionError::Poisoned)?;
        Ok(state.events.clone())
    }
}

impl SessionBackend for FakeSessionBackend {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn launch(&self, request: &LaunchRequest) -> Result<SessionHandle, SessionError> {
        let mut state = self.state.lock().map_err(|_| SessionError::Poisoned)?;
        if let Some(handle) = state.launches.get(&request.idempotency_key) {
            return Ok(handle.clone());
        }

        state.next_id += 1;
        let handle = SessionHandle {
            backend: self.name().to_owned(),
            external_id: format!("fake-{}", state.next_id),
            resume_token: Some(format!("resume-{}", state.next_id)),
        };
        state.sessions.insert(
            handle.external_id.clone(),
            FakeSession {
                handle: handle.clone(),
                status: SessionStatus::Idle,
            },
        );
        state
            .launches
            .insert(request.idempotency_key.clone(), handle.clone());
        state.events.push(FakeEvent::Launched {
            actor_id: request.actor_id.clone(),
            session_id: handle.external_id.clone(),
        });
        Ok(handle)
    }

    fn resume(&self, request: &ResumeRequest) -> Result<SessionHandle, SessionError> {
        reject_foreign_handle(self.name(), &request.handle)?;
        let mut state = self.state.lock().map_err(|_| SessionError::Poisoned)?;
        let session = state
            .sessions
            .get_mut(&request.handle.external_id)
            .ok_or_else(|| SessionError::NotFound(request.handle.external_id.clone()))?;
        session.status = SessionStatus::Idle;
        let handle = session.handle.clone();
        state.events.push(FakeEvent::Resumed {
            actor_id: request.actor_id.clone(),
            session_id: handle.external_id.clone(),
        });
        Ok(handle)
    }

    fn status(&self, handle: &SessionHandle) -> Result<SessionSnapshot, SessionError> {
        reject_foreign_handle(self.name(), handle)?;
        let state = self.state.lock().map_err(|_| SessionError::Poisoned)?;
        let session = state
            .sessions
            .get(&handle.external_id)
            .ok_or_else(|| SessionError::NotFound(handle.external_id.clone()))?;
        Ok(SessionSnapshot {
            handle: session.handle.clone(),
            status: session.status.clone(),
            detail: None,
        })
    }

    fn send_message(&self, handle: &SessionHandle, message: &str) -> Result<(), SessionError> {
        reject_foreign_handle(self.name(), handle)?;
        let mut state = self.state.lock().map_err(|_| SessionError::Poisoned)?;
        if !state.sessions.contains_key(&handle.external_id) {
            return Err(SessionError::NotFound(handle.external_id.clone()));
        }
        state.events.push(FakeEvent::Message {
            session_id: handle.external_id.clone(),
            body: message.to_owned(),
        });
        Ok(())
    }

    fn stop(&self, handle: &SessionHandle) -> Result<(), SessionError> {
        reject_foreign_handle(self.name(), handle)?;
        let mut state = self.state.lock().map_err(|_| SessionError::Poisoned)?;
        let session = state
            .sessions
            .get_mut(&handle.external_id)
            .ok_or_else(|| SessionError::NotFound(handle.external_id.clone()))?;
        session.status = SessionStatus::Stopped { exit_code: None };
        state.events.push(FakeEvent::Stopped {
            session_id: handle.external_id.clone(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn launch_request(key: &str) -> LaunchRequest {
        LaunchRequest {
            actor_id: "actor-1".into(),
            session_name: "worker-one".into(),
            runtime: "codex".into(),
            working_directory: PathBuf::from("/workspace"),
            idempotency_key: key.into(),
            native_args: Vec::new(),
            initial_prompt: None,
            resume_token: None,
        }
    }

    #[test]
    fn duplicate_launch_is_idempotent() {
        let backend = FakeSessionBackend::new();
        let first = backend.launch(&launch_request("launch-1")).unwrap();
        let second = backend.launch(&launch_request("launch-1")).unwrap();

        assert_eq!(first, second);
        assert_eq!(backend.events().unwrap().len(), 1);
    }

    #[test]
    fn foreign_handle_is_rejected() {
        let backend = FakeSessionBackend::new();
        let error = backend
            .status(&SessionHandle {
                backend: "another-backend".into(),
                external_id: "session".into(),
                resume_token: None,
            })
            .unwrap_err();
        assert!(matches!(error, SessionError::ForeignHandle { .. }));
    }
}
