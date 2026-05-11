use anyhow::{Context, Result, bail};
use nobody_policy::{Action, Decision, Policy};
use nobody_sandbox::{Sandbox, SandboxSpec, platform_default_sandbox};
use nobody_trace::{DecisionSummary, TraceWriter};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

pub struct Runtime {
    policy: Policy,
    trace: TraceWriter,
    sandbox: Box<dyn Sandbox>,
}

pub struct RunSpec {
    pub command: Vec<String>,
    pub policy_path: PathBuf,
}

pub struct RunResult {
    pub code: Option<i32>,
    pub success: bool,
}

struct PreparedEnv {
    clear: bool,
    values: BTreeMap<String, String>,
    allowed_names: Vec<String>,
    denied_names: Vec<String>,
}

impl Runtime {
    pub fn new(policy: Policy, trace_path: PathBuf) -> Result<Self> {
        Self::with_sandbox(policy, trace_path, platform_default_sandbox())
    }

    pub fn with_sandbox(
        policy: Policy,
        trace_path: PathBuf,
        sandbox: Box<dyn Sandbox>,
    ) -> Result<Self> {
        Ok(Self {
            policy,
            trace: TraceWriter::open(&trace_path)?,
            sandbox,
        })
    }

    pub fn run(&mut self, spec: RunSpec) -> Result<RunResult> {
        let program = spec
            .command
            .first()
            .context("missing command to run")?
            .clone();
        let argv = spec.command[1..].to_vec();

        self.trace.event(
            "run.created",
            None,
            json!({
                "command": spec.command,
            }),
        )?;

        self.trace.event(
            "policy.loaded",
            None,
            json!({
                "path": spec.policy_path,
                "trace_path": self.policy.trace_path(),
            }),
        )?;

        let process_decision = self.policy.evaluator().evaluate(Action::ExecuteProcess {
            program: program.clone(),
            argv: argv.clone(),
        });
        let process_summary = DecisionSummary::from_policy_decision(&process_decision);
        let process_event_kind = process_summary.event_kind("process.exec");
        self.trace.event(
            &process_event_kind,
            Some(process_summary.clone()),
            json!({
                "program": program,
                "argv": argv,
            }),
        )?;

        match process_decision {
            Decision::Allow { .. } => {}
            Decision::Deny { reason } => {
                self.complete_failed_run("process_denied", &reason.message)?;
                bail!("process denied by policy: {}", reason.message);
            }
            Decision::Ask { request } => {
                self.complete_failed_run("approval_required", &request.reason.message)?;
                bail!(
                    "process requires approval but approval gates are not implemented: {}",
                    request.reason.message
                );
            }
        }

        let env = self.prepare_env();
        self.trace.event(
            "env.filtered",
            None,
            json!({
                "clear": env.clear,
                "allowed_count": env.allowed_names.len(),
                "denied_count": env.denied_names.len(),
                "allowed": env.allowed_names,
                "denied": env.denied_names,
            }),
        )?;

        let mut command = Command::new(&program);
        command.args(&argv);

        if env.clear {
            command.env_clear();
            command.envs(&env.values);
        } else {
            for name in &env.denied_names {
                command.env_remove(name);
            }
        }

        let sandbox_spec = SandboxSpec::from_policy_parts(
            std::env::current_dir().context("failed to resolve current directory")?,
            &self.policy.fs.read,
            &self.policy.fs.write,
            &self.policy.fs.deny,
            self.policy.net.mode.clone(),
            &self.policy.net.allow,
            &self.policy.net.deny,
        );
        let prepared_sandbox = match self.sandbox.prepare(&sandbox_spec) {
            Ok(prepared) => prepared,
            Err(error) => {
                let message = error.to_string();
                self.trace.event(
                    "sandbox.prepare.failed",
                    None,
                    json!({
                        "error": message,
                    }),
                )?;
                self.complete_failed_run("sandbox_prepare_failed", &message)?;
                return Err(error).context("failed to prepare sandbox");
            }
        };
        let sandbox_status = prepared_sandbox.status();

        if let Some(warning) = &sandbox_status.warning {
            eprintln!("nobody: WARNING: {warning}");
        }

        self.trace.event(
            "sandbox.prepared",
            None,
            json!({
                "backend": sandbox_status.backend,
                "enforced": sandbox_status.enforced,
                "filesystem_enforced": sandbox_status.filesystem_enforced,
                "network_enforced": sandbox_status.network_enforced,
                "network_mode": sandbox_status.network_mode,
                "warning": sandbox_status.warning,
            }),
        )?;

        let mut child = match prepared_sandbox.spawn(&mut command) {
            Ok(child) => child,
            Err(error) => {
                let message = error.to_string();
                self.trace.event(
                    "process.start.failed",
                    None,
                    json!({
                        "program": program,
                        "error": message,
                    }),
                )?;
                self.complete_failed_run("process_start_failed", &message)?;
                return Err(error).with_context(|| format!("failed to start command: {program}"));
            }
        };

        self.trace.event(
            "process.started",
            None,
            json!({
                "program": program,
                "pid": child.id(),
            }),
        )?;

        let status = match child.wait() {
            Ok(status) => status,
            Err(error) => {
                let message = error.to_string();
                self.trace.event(
                    "process.wait.failed",
                    None,
                    json!({
                        "program": program,
                        "error": message,
                    }),
                )?;
                self.complete_failed_run("process_wait_failed", &message)?;
                return Err(error)
                    .with_context(|| format!("failed to wait for command: {program}"));
            }
        };

        self.trace.event(
            "process.exited",
            None,
            json!({
                "program": program,
                "code": status.code(),
                "success": status.success(),
            }),
        )?;

        self.trace.event(
            "run.completed",
            None,
            json!({
                "code": status.code(),
                "success": status.success(),
            }),
        )?;

        Ok(RunResult {
            code: status.code(),
            success: status.success(),
        })
    }

    fn complete_failed_run(&mut self, reason: &str, error: &str) -> Result<()> {
        self.trace.event(
            "run.completed",
            None,
            json!({
                "code": null,
                "success": false,
                "reason": reason,
                "error": error,
            }),
        )
    }

    fn prepare_env(&self) -> PreparedEnv {
        let mut values = BTreeMap::new();
        let mut allowed_names = Vec::new();
        let mut denied_names = Vec::new();
        let evaluator = self.policy.evaluator();

        for (name, value) in std::env::vars() {
            let decision = evaluator.evaluate(Action::ReadEnv { name: name.clone() });

            if decision.is_allow() {
                values.insert(name.clone(), value);
                allowed_names.push(name);
            } else {
                denied_names.push(name);
            }
        }

        PreparedEnv {
            clear: self.policy.env.clear,
            values,
            allowed_names,
            denied_names,
        }
    }
}
