use anyhow::{Context, Result, bail};
use nobody_policy::{Action, Decision, Policy};
use nobody_trace::{DecisionSummary, TraceWriter};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;

pub struct ProxySpec {
    pub server: String,
    pub policy_path: PathBuf,
    pub command: Vec<String>,
}

struct PreparedEnv {
    clear: bool,
    values: BTreeMap<String, String>,
    allowed_names: Vec<String>,
    denied_names: Vec<String>,
}

pub fn proxy(spec: ProxySpec) -> Result<()> {
    let policy = Policy::load(&spec.policy_path)?;
    let trace_path = policy.trace_path();
    let mut trace = TraceWriter::open(&trace_path)?;
    let program = spec
        .command
        .first()
        .context("missing MCP server command")?
        .clone();
    let argv = spec.command[1..].to_vec();

    trace.event(
        "mcp.proxy.created",
        None,
        json!({
            "server": spec.server,
            "command": spec.command,
            "policy_path": spec.policy_path,
            "trace_path": trace_path,
        }),
    )?;

    let process_decision = policy.evaluator().evaluate(Action::ExecuteProcess {
        program: program.clone(),
        argv: argv.clone(),
    });
    let process_summary = DecisionSummary::from_policy_decision(&process_decision);
    trace.event(
        &process_summary.event_kind("process.exec"),
        Some(process_summary),
        json!({
            "program": program,
            "argv": argv,
        }),
    )?;

    match process_decision {
        Decision::Allow { .. } => {}
        Decision::Deny { reason } => {
            let message = reason.message.clone();
            trace.event(
                "mcp.proxy.exited",
                None,
                json!({
                    "server": spec.server,
                    "code": null,
                    "success": false,
                    "reason": "process_denied",
                    "error": message,
                }),
            )?;
            bail!("MCP server process denied by policy: {}", reason.message);
        }
        Decision::Ask { request } => {
            let message = request.reason.message.clone();
            trace.event(
                "mcp.proxy.exited",
                None,
                json!({
                    "server": spec.server,
                    "code": null,
                    "success": false,
                    "reason": "approval_required",
                    "error": message,
                }),
            )?;
            bail!(
                "MCP server process requires approval but approval gates are not implemented: {}",
                request.reason.message
            );
        }
    }

    let env = prepare_env(&policy);
    trace.event(
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
    command
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if env.clear {
        command.env_clear();
        command.envs(&env.values);
    } else {
        for name in &env.denied_names {
            command.env_remove(name);
        }
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let message = error.to_string();
            trace.event(
                "mcp.proxy.exited",
                None,
                json!({
                    "server": spec.server,
                    "code": null,
                    "success": false,
                    "reason": "process_start_failed",
                    "error": message,
                }),
            )?;
            return Err(error).with_context(|| format!("failed to spawn MCP server: {program}"));
        }
    };

    trace.event(
        "mcp.proxy.started",
        None,
        json!({
            "server": spec.server,
            "program": program,
            "pid": child.id(),
        }),
    )?;

    let child_stdout = child
        .stdout
        .take()
        .context("failed to capture MCP server stdout")?;
    let child_stderr = child
        .stderr
        .take()
        .context("failed to capture MCP server stderr")?;
    let mut child_stdin = child
        .stdin
        .take()
        .context("failed to capture MCP server stdin")?;

    let stdout_thread = thread::spawn(move || copy_lines(child_stdout, io::stdout()));
    let stderr_thread = thread::spawn(move || copy_lines(child_stderr, io::stderr()));

    let stdin = io::stdin();
    let mut stdout = BufWriter::new(io::stdout());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            writeln!(child_stdin)?;
            child_stdin.flush()?;
            continue;
        }

        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            trace.event(
                "mcp.message.invalid",
                None,
                json!({
                    "server": spec.server,
                }),
            )?;
            writeln!(child_stdin, "{line}")?;
            child_stdin.flush()?;
            continue;
        };

        if let Some(tool) = tool_call_name(&message) {
            let decision = policy.evaluator().evaluate(Action::CallMcpTool {
                server: spec.server.clone(),
                tool: tool.to_owned(),
            });
            let summary = DecisionSummary::from_policy_decision(&decision);
            trace.event(
                &summary.event_kind("mcp.tool"),
                Some(summary),
                json!({
                    "server": spec.server,
                    "tool": tool,
                    "id": message.get("id").cloned().unwrap_or(Value::Null),
                }),
            )?;

            match decision {
                Decision::Allow { .. } => {
                    writeln!(child_stdin, "{line}")?;
                    child_stdin.flush()?;
                }
                Decision::Deny { reason } => {
                    write_error_response(&mut stdout, &message, -32001, &reason.message)?;
                }
                Decision::Ask { request } => {
                    write_error_response(
                        &mut stdout,
                        &message,
                        -32002,
                        &format!(
                            "MCP tool requires approval but approval gates are not implemented: {}",
                            request.reason.message
                        ),
                    )?;
                }
            }
        } else {
            writeln!(child_stdin, "{line}")?;
            child_stdin.flush()?;
        }
    }

    drop(child_stdin);
    let status = child
        .wait()
        .with_context(|| format!("failed to wait for MCP server: {program}"))?;
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();

    trace.event(
        "mcp.proxy.exited",
        None,
        json!({
            "server": spec.server,
            "code": status.code(),
            "success": status.success(),
        }),
    )?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}

fn prepare_env(policy: &Policy) -> PreparedEnv {
    let mut values = BTreeMap::new();
    let mut allowed_names = Vec::new();
    let mut denied_names = Vec::new();
    let evaluator = policy.evaluator();

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
        clear: policy.env.clear,
        values,
        allowed_names,
        denied_names,
    }
}

fn tool_call_name(message: &Value) -> Option<&str> {
    if message.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }

    message
        .get("params")
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str)
}

fn write_error_response(
    out: &mut impl Write,
    request: &Value,
    code: i64,
    message: &str,
) -> Result<()> {
    let Some(id) = request.get("id") else {
        return Ok(());
    };
    let response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        },
    });
    serde_json::to_writer(&mut *out, &response)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn copy_lines<R, W>(reader: R, writer: W) -> io::Result<()>
where
    R: io::Read,
    W: io::Write,
{
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        writer.write_all(line.as_bytes())?;
        writer.flush()?;
    }

    Ok(())
}
