use crate::{
    NetworkSandboxPlan, PreparedSandbox, PreparedSandboxBackend, Sandbox, SandboxSpec,
    SandboxStatus,
};
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
    fn prepare(&self, spec: &SandboxSpec) -> Result<PreparedSandbox> {
        let mut warning = self.reason.clone();
        if let NetworkSandboxPlan::DenyAll | NetworkSandboxPlan::Diagnostic { .. } =
            spec.network.plan()
        {
            warning.push_str("; network policy is diagnostic on this platform");
        }

        Ok(Box::new(PreparedNoopSandbox {
            warning,
            network_mode: spec.network.mode_label().into(),
        }))
    }
}

struct PreparedNoopSandbox {
    warning: String,
    network_mode: String,
}

impl PreparedSandboxBackend for PreparedNoopSandbox {
    fn status(&self) -> SandboxStatus {
        SandboxStatus {
            backend: "noop".into(),
            enforced: false,
            filesystem_enforced: false,
            network_enforced: false,
            network_mode: self.network_mode.clone(),
            warning: Some(self.warning.clone()),
        }
    }

    fn spawn(&self, command: &mut Command) -> Result<Child> {
        command.spawn().context("failed to spawn command")
    }
}
