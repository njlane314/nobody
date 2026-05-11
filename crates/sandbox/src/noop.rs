use crate::{PreparedSandbox, PreparedSandboxBackend, Sandbox, SandboxSpec, SandboxStatus};
use anyhow::{Context, Result};
use std::process::{Child, Command};

pub struct NoopSandbox {
    reason: String,
}

impl NoopSandbox {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl Default for NoopSandbox {
    fn default() -> Self {
        Self::new("filesystem sandbox backend is noop; filesystem policy is diagnostic only")
    }
}

impl Sandbox for NoopSandbox {
    fn prepare(&self, _spec: &SandboxSpec) -> Result<PreparedSandbox> {
        Ok(Box::new(PreparedNoopSandbox {
            reason: self.reason.clone(),
        }))
    }
}

struct PreparedNoopSandbox {
    reason: String,
}

impl PreparedSandboxBackend for PreparedNoopSandbox {
    fn status(&self) -> SandboxStatus {
        SandboxStatus {
            backend: "noop".into(),
            enforced: false,
            warning: Some(self.reason.clone()),
        }
    }

    fn spawn(&self, command: &mut Command) -> Result<Child> {
        command.spawn().context("failed to spawn command")
    }
}
